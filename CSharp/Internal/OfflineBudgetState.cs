using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace SwmSdk.Internal;

internal sealed class OfflineBudgetState
{
    private const string FileName = "offline.bin";
    private const string Header = "SwmSdkOfflineBudgetV1";
    private const long MaximumOfflineMilliseconds = 24L * 60 * 60 * 1000;
    private const long PersistIntervalMilliseconds = 5L * 60 * 1000;
    private readonly object _sync = new();
    private readonly StateStore _store;
    private readonly string _installId;
    private readonly string _keyThumbprint;
    private bool _loaded;
    private bool _hasRecord;
    private bool _latched;
    private bool _hadVerifiedInteraction;
    private long _lastVerifiedUnixMilliseconds;
    private long _lastPersistedUnixMilliseconds;

    public OfflineBudgetState(StateStore store, string installId, string keyThumbprint)
    {
        _store = store;
        _installId = installId;
        _keyThumbprint = keyThumbprint;
    }

    public bool IsLocked(TrustedClock clock)
    {
        lock (_sync)
        {
            EnsureLoaded();
            if (_latched)
            {
                return true;
            }
            var now = clock.NowUnixMilliseconds;
            return !_hasRecord || now <= 0 || now < _lastVerifiedUnixMilliseconds ||
                now - _lastVerifiedUnixMilliseconds > MaximumOfflineMilliseconds;
        }
    }

    public void NoteVerifiedInteraction(long trustedUnixMilliseconds)
    {
        if (trustedUnixMilliseconds <= 0)
        {
            return;
        }
        lock (_sync)
        {
            EnsureLoaded();
            if (_hadVerifiedInteraction &&
                _hasRecord &&
                trustedUnixMilliseconds >= _lastVerifiedUnixMilliseconds &&
                trustedUnixMilliseconds - _lastVerifiedUnixMilliseconds > MaximumOfflineMilliseconds)
            {
                _latched = true;
            }
            _hadVerifiedInteraction = true;
            _hasRecord = true;
            if (trustedUnixMilliseconds > _lastVerifiedUnixMilliseconds)
            {
                _lastVerifiedUnixMilliseconds = trustedUnixMilliseconds;
            }
            if (_lastPersistedUnixMilliseconds == 0 ||
                trustedUnixMilliseconds - _lastPersistedUnixMilliseconds >= PersistIntervalMilliseconds)
            {
                Persist();
            }
        }
    }

    private void EnsureLoaded()
    {
        if (_loaded)
        {
            return;
        }
        _loaded = true;
        if (!_store.TryReadProtected(FileName, out var plaintext))
        {
            return;
        }
        try
        {
            var text = Encoding.UTF8.GetString(plaintext);
            var lines = text.Split('\n');
            if (lines.Length < 4 ||
                lines[0] != Header ||
                lines[1] != _installId ||
                lines[2] != _keyThumbprint ||
                !long.TryParse(lines[3], NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) ||
                value <= 0)
            {
                return;
            }
            _hasRecord = true;
            _lastVerifiedUnixMilliseconds = value;
            _lastPersistedUnixMilliseconds = value;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private void Persist()
    {
        var text = string.Join(
            "\n",
            Header,
            _installId,
            _keyThumbprint,
            _lastVerifiedUnixMilliseconds.ToString(CultureInfo.InvariantCulture));
        var plaintext = Encoding.UTF8.GetBytes(text + "\n");
        try
        {
            _store.WriteProtected(FileName, plaintext);
            _lastPersistedUnixMilliseconds = _lastVerifiedUnixMilliseconds;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }
}
