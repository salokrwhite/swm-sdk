use crate::crypto::base64url_encode;
use crate::error::{Error, ErrorKind, Result};
use crate::host_integrity::HostIntegrityManager;
use crate::identity::DeviceIdentity;
use crate::models::{CloudState, HardwareEvidence};
use crate::options::ClientOptions;
use crate::pipeline::{ProtocolKey, TrustedClock};
use crate::platform;
use crate::state::{OFFLINE_FILE, StateStore};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::Mutex as AsyncMutex;
use url::Url;

const MAXIMUM_OFFLINE_MILLIS: i64 = 24 * 60 * 60 * 1000;
const OFFLINE_PERSIST_INTERVAL_MILLIS: i64 = 5 * 60 * 1000;

pub(crate) struct SessionState {
    pub(crate) token: String,
    pub(crate) expires_at: i64,
}

pub(crate) struct OfflineBudget {
    store: Arc<StateStore>,
    install_id: String,
    key_thumbprint: String,
    state: Mutex<OfflineBudgetState>,
}

struct OfflineBudgetState {
    loaded: bool,
    has_record: bool,
    latched: bool,
    had_verified: bool,
    last_verified_millis: i64,
    last_persisted_millis: i64,
}

impl OfflineBudget {
    fn new(store: Arc<StateStore>, install_id: String, key_thumbprint: String) -> Self {
        Self {
            store,
            install_id,
            key_thumbprint,
            state: Mutex::new(OfflineBudgetState {
                loaded: false,
                has_record: false,
                latched: false,
                had_verified: false,
                last_verified_millis: 0,
                last_persisted_millis: 0,
            }),
        }
    }

    fn is_locked(&self, clock: &TrustedClock) -> bool {
        let mut state = match self.state.lock() {
            Ok(value) => value,
            Err(_) => return true,
        };
        self.ensure_loaded(&mut state);
        if state.latched {
            return true;
        }
        let now = clock.now_unix_milliseconds();
        !state.has_record
            || now <= 0
            || now < state.last_verified_millis
            || now - state.last_verified_millis > MAXIMUM_OFFLINE_MILLIS
    }

    fn note_verified(&self, trusted_millis: i64) {
        if trusted_millis <= 0 {
            return;
        }
        let mut state = match self.state.lock() {
            Ok(value) => value,
            Err(_) => return,
        };
        self.ensure_loaded(&mut state);
        if state.had_verified
            && state.has_record
            && trusted_millis >= state.last_verified_millis
            && trusted_millis - state.last_verified_millis > MAXIMUM_OFFLINE_MILLIS
        {
            state.latched = true;
        }
        state.had_verified = true;
        state.has_record = true;
        if trusted_millis > state.last_verified_millis {
            state.last_verified_millis = trusted_millis;
        }
        if state.last_persisted_millis == 0
            || trusted_millis - state.last_persisted_millis >= OFFLINE_PERSIST_INTERVAL_MILLIS
        {
            let text = format!(
                "SwmSdkOfflineBudgetV1\n{}\n{}\n{}\n",
                self.install_id, self.key_thumbprint, state.last_verified_millis
            );
            if self
                .store
                .write_protected(OFFLINE_FILE, text.as_bytes())
                .is_ok()
            {
                state.last_persisted_millis = state.last_verified_millis;
            }
        }
    }

    fn ensure_loaded(&self, state: &mut OfflineBudgetState) {
        if state.loaded {
            return;
        }
        state.loaded = true;
        let Some(plaintext) = self.store.read_protected(OFFLINE_FILE) else {
            return;
        };
        let text = String::from_utf8_lossy(&plaintext);
        let parts: Vec<_> = text.split('\n').collect();
        if parts.len() < 4
            || parts[0] != "SwmSdkOfflineBudgetV1"
            || parts[1] != self.install_id
            || parts[2] != self.key_thumbprint
        {
            return;
        }
        let Ok(value) = parts[3].parse::<i64>() else {
            return;
        };
        if value <= 0 {
            return;
        }
        state.has_record = true;
        state.last_verified_millis = value;
        state.last_persisted_millis = value;
    }
}

pub(crate) struct ClientInner {
    pub(crate) options: ClientOptions,
    pub(crate) base_url: Url,
    pub(crate) web_url: Url,
    pub(crate) http: reqwest::Client,
    pub(crate) store: Arc<StateStore>,
    pub(crate) host: Arc<HostIntegrityManager>,
    pub(crate) clock: TrustedClock,
    pub(crate) identity: AsyncMutex<Option<Arc<DeviceIdentity>>>,
    pub(crate) hardware: Mutex<Option<HardwareEvidence>>,
    pub(crate) offline: Mutex<Option<Arc<OfflineBudget>>>,
    pub(crate) session: Mutex<SessionState>,
    pub(crate) current_key: Mutex<Option<ProtocolKey>>,
    pub(crate) previous_keys: Mutex<Vec<ProtocolKey>>,
    pub(crate) host_policy_required: AtomicBool,
    pub(crate) closed: AtomicBool,
    pub(crate) key_refresh: AsyncMutex<()>,
}

/// Software Web Manager client.
#[derive(Clone)]
pub struct Client {
    pub(crate) inner: Arc<ClientInner>,
}

impl Client {
    pub fn new(options: ClientOptions) -> Result<Self> {
        crate::options::validate_options(&options)?;
        if !platform::supported() {
            return Err(Error::new(
                ErrorKind::UnsupportedPlatform,
                "SWM SDK requires Windows x86 or x64",
            ));
        }
        let base_url = Url::parse(&options.base_url)?;
        let web_url = Url::parse(options.web_base_url.as_deref().unwrap_or(&options.base_url))?;
        let http = match options.http_client.clone() {
            Some(value) => value,
            None => reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(Error::from)?,
        };
        let store = Arc::new(StateStore::new(
            &options.app_id,
            options.storage_directory.as_deref(),
        )?);
        let host = Arc::new(HostIntegrityManager::new(options.clone(), store.clone()));
        let host_policy_required = host.read_cached_policy().unwrap_or(false);
        Ok(Self {
            inner: Arc::new(ClientInner {
                options,
                base_url,
                web_url,
                http,
                store,
                host,
                clock: TrustedClock::default(),
                identity: AsyncMutex::new(None),
                hardware: Mutex::new(None),
                offline: Mutex::new(None),
                session: Mutex::new(SessionState {
                    token: String::new(),
                    expires_at: 0,
                }),
                current_key: Mutex::new(None),
                previous_keys: Mutex::new(Vec::new()),
                host_policy_required: AtomicBool::new(host_policy_required),
                closed: AtomicBool::new(false),
                key_refresh: AsyncMutex::new(()),
            }),
        })
    }

    pub async fn device_id(&self) -> Result<String> {
        if let Some(value) = self
            .inner
            .options
            .device_id
            .as_ref()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
        {
            return Ok(value);
        }
        Ok(self.identity().await?.device_id.clone())
    }

    pub async fn install_id(&self) -> Result<String> {
        Ok(self.identity().await?.install_id.clone())
    }

    pub async fn device_key_id(&self) -> Result<String> {
        Ok(self.identity().await?.key_id.clone())
    }

    pub async fn key_thumbprint(&self) -> Result<String> {
        Ok(self.identity().await?.key_thumbprint.clone())
    }

    pub fn session_token(&self) -> Option<String> {
        self.inner
            .session
            .lock()
            .ok()
            .map(|session| session.token.clone())
            .filter(|value| !value.is_empty())
    }

    pub fn session_expires_at(&self) -> i64 {
        self.inner
            .session
            .lock()
            .map(|session| session.expires_at)
            .unwrap_or(0)
    }

    pub fn cloud_state(&self) -> CloudState {
        if !self.inner.clock.is_initialized() {
            return CloudState::Unavailable;
        }
        let session = match self.inner.session.lock() {
            Ok(value) => value,
            Err(_) => return CloudState::Unavailable,
        };
        if session.token.is_empty() || session.expires_at <= self.inner.clock.now_unix_seconds() {
            return if session.expires_at > 0 {
                CloudState::Expired
            } else {
                CloudState::Unavailable
            };
        }
        CloudState::Available
    }

    pub async fn refresh_online_keys(&self) -> Result<()> {
        self.inner.refresh_online_keys(true).await
    }

    pub(crate) async fn identity(&self) -> Result<Arc<DeviceIdentity>> {
        if self.inner.closed.load(Ordering::Relaxed) {
            return Err(Error::new(ErrorKind::Identity, "client is closed"));
        }
        let mut identity = self.inner.identity.lock().await;
        if let Some(value) = identity.as_ref() {
            return Ok(value.clone());
        }
        let value =
            DeviceIdentity::load_or_create(&self.inner.options.app_id, self.inner.store.clone())?;
        *identity = Some(value.clone());
        Ok(value)
    }

    pub(crate) async fn create_device_auth(
        &self,
        challenge: Option<String>,
    ) -> Result<crate::pipeline::DeviceAuthRegistration> {
        let identity = self.identity().await?;
        let hardware = self.hardware_evidence()?;
        Ok(crate::pipeline::DeviceAuthRegistration {
            install_id: identity.install_id.clone(),
            key_id: identity.key_id.clone(),
            key_thumbprint: identity.key_thumbprint.clone(),
            public_key_sec1: base64url_encode(&identity.public_key_sec1),
            credential_version: "device_credential_v2".into(),
            challenge,
            hardware_evidence: hardware,
        })
    }

    pub(crate) fn hardware_evidence(&self) -> Result<HardwareEvidence> {
        let mut hardware = self
            .inner
            .hardware
            .lock()
            .map_err(|_| Error::new(ErrorKind::Identity, "hardware lock poisoned"))?;
        if let Some(value) = hardware.as_ref() {
            return Ok(value.clone());
        }
        let value = platform::collect_hardware_evidence(&self.inner.options.app_id)?;
        *hardware = Some(value.clone());
        Ok(value)
    }

    pub(crate) fn ensure_not_closed(&self) -> Result<()> {
        if self.inner.closed.load(Ordering::Relaxed) {
            Err(Error::new(ErrorKind::Configuration, "client is closed"))
        } else {
            Ok(())
        }
    }

    pub(crate) fn host_policy_required(&self) -> bool {
        self.inner.host_policy_required.load(Ordering::Relaxed)
    }

    pub(crate) fn set_host_policy_required(&self, required: bool) {
        self.inner
            .host_policy_required
            .store(required, Ordering::Relaxed);
        self.inner.host.store_policy(required);
    }

    pub(crate) fn offline_budget(&self, identity: &DeviceIdentity) -> Arc<OfflineBudget> {
        let mut offline = self.inner.offline.lock().expect("offline lock poisoned");
        offline
            .get_or_insert_with(|| {
                Arc::new(OfflineBudget::new(
                    self.inner.store.clone(),
                    identity.install_id.clone(),
                    identity.key_thumbprint.clone(),
                ))
            })
            .clone()
    }

    pub(crate) fn is_offline_locked(&self) -> bool {
        let identity = match self.inner.identity.try_lock() {
            Ok(identity) => identity,
            Err(_) => return true,
        };
        let Some(identity) = identity.as_ref() else {
            return true;
        };
        self.offline_budget(identity).is_locked(&self.inner.clock)
    }

    pub(crate) fn clear_session(&self) {
        if let Ok(mut session) = self.inner.session.lock() {
            session.token.clear();
            session.expires_at = 0;
        }
    }

    pub fn close(&self) {
        if self.inner.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Ok(identity) = self.inner.identity.try_lock() {
            if let Some(identity) = identity.as_ref() {
                identity.close();
            }
        }
    }
}

impl ClientInner {
    pub(crate) async fn expected_device_id(&self) -> Result<String> {
        if let Some(value) = self
            .options
            .device_id
            .as_ref()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
        {
            return Ok(value);
        }
        let mut identity = self.identity.lock().await;
        if let Some(value) = identity.as_ref() {
            return Ok(value.device_id.clone());
        }
        let value = DeviceIdentity::load_or_create(&self.options.app_id, self.store.clone())?;
        let device_id = value.device_id.clone();
        *identity = Some(value);
        Ok(device_id)
    }

    pub(crate) fn clear_session(&self) {
        if let Ok(mut session) = self.session.lock() {
            session.token.clear();
            session.expires_at = 0;
        }
    }

    pub(crate) fn ensure_session(&self) -> Result<String> {
        let mut session = self
            .session
            .lock()
            .map_err(|_| Error::new(ErrorKind::Session, "session lock poisoned"))?;
        if session.token.is_empty() || session.expires_at <= self.clock.now_unix_seconds() {
            session.token.clear();
            session.expires_at = 0;
            return Err(Error::new(
                ErrorKind::Session,
                "authorization session is missing or expired",
            ));
        }
        Ok(session.token.clone())
    }

    pub(crate) fn install_session(&self, token: String, expires_at: i64) {
        if let Ok(mut session) = self.session.lock() {
            session.token = token;
            session.expires_at = expires_at;
        }
    }

    pub(crate) fn note_verified_interaction(&self) {
        let Ok(identity) = self.identity.try_lock() else {
            return;
        };
        let Some(identity) = identity.as_ref() else {
            return;
        };
        let mut offline = match self.offline.lock() {
            Ok(value) => value,
            Err(_) => return,
        };
        let budget = offline.get_or_insert_with(|| {
            Arc::new(OfflineBudget::new(
                self.store.clone(),
                identity.install_id.clone(),
                identity.key_thumbprint.clone(),
            ))
        });
        budget.note_verified(self.clock.now_unix_milliseconds());
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if Arc::strong_count(&self.inner) == 1 {
            self.close();
        }
    }
}
