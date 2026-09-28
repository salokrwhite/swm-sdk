using System.Security.Cryptography;
using System.Text;
using System.Collections.Concurrent;

namespace SwmSdk.Internal;

internal sealed class DeviceIdentity : IDisposable
{
    private const string MetadataFile = "identity.bin";
    private static readonly ConcurrentDictionary<string, object> CreationLocks = new(StringComparer.OrdinalIgnoreCase);
    private readonly StateStore _store;
    private readonly object _signLock = new();
    private CngKey? _key;
    private ECDsaCng? _signer;
    private bool _disposed;

    private DeviceIdentity(
        StateStore store,
        string installId,
        string keyName,
        string deviceId,
        string keyId,
        string keyThumbprint,
        string publicKeySec1)
    {
        _store = store;
        InstallId = installId;
        KeyName = keyName;
        DeviceId = deviceId;
        KeyId = keyId;
        KeyThumbprint = keyThumbprint;
        PublicKeySec1 = publicKeySec1;
    }

    public string InstallId { get; }
    public string KeyName { get; }
    public string DeviceId { get; }
    public string KeyId { get; }
    public string KeyThumbprint { get; }
    public string PublicKeySec1 { get; }

    public const string CredentialVersion = "device_credential_v2";

    public static DeviceIdentity LoadOrCreate(string appId, StateStore store)
    {
        var lockKey = store.DirectoryPath + "\n" + appId;
        lock (CreationLocks.GetOrAdd(lockKey, _ => new object()))
        {
            return LoadOrCreateCore(appId, store);
        }
    }

    private static DeviceIdentity LoadOrCreateCore(string appId, StateStore store)
    {
        var metadata = ReadMetadata(store);
        if (metadata != null)
        {
            try
            {
                return Open(appId, store, metadata.Value.InstallId, metadata.Value.KeyName);
            }
            catch
            {
                store.Delete(MetadataFile);
            }
        }

        var installId = Convert.ToHexString(CryptoUtil.RandomBytes(16)).ToLowerInvariant();
        var keyName = BuildKeyName(appId, installId);
        var parameters = new CngKeyCreationParameters
        {
            Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
            KeyUsage = CngKeyUsages.Signing,
            ExportPolicy = CngExportPolicies.None,
            KeyCreationOptions = CngKeyCreationOptions.None
        };

        CngKey? created = null;
        try
        {
            created = CngKey.Create(CngAlgorithm.ECDsaP256, keyName, parameters);
            var identity = FromKey(appId, store, installId, keyName, created);
            WriteMetadata(store, identity.InstallId, identity.KeyName);
            return identity;
        }
        catch (Exception ex)
        {
            created?.Dispose();
            throw new SwmIdentityException("cannot create non-exportable P-256 device key", ex);
        }
    }

    public static DeviceIdentity CreatePending(string appId, StateStore store)
    {
        var installId = Convert.ToHexString(CryptoUtil.RandomBytes(16)).ToLowerInvariant();
        var keyName = BuildKeyName(appId, installId);
        var parameters = new CngKeyCreationParameters
        {
            Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
            KeyUsage = CngKeyUsages.Signing,
            ExportPolicy = CngExportPolicies.None,
            KeyCreationOptions = CngKeyCreationOptions.None
        };
        try
        {
            var key = CngKey.Create(CngAlgorithm.ECDsaP256, keyName, parameters);
            return FromKey(appId, store, installId, keyName, key);
        }
        catch (Exception ex)
        {
            throw new SwmIdentityException("cannot create pending rotation key", ex);
        }
    }

    public void CommitPending()
    {
        ThrowIfDisposed();
        WriteMetadata(_store, InstallId, KeyName);
    }

    public void DeletePending()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        _signer?.Dispose();
        _signer = null;
        _key?.Delete();
        _key?.Dispose();
        _key = null;
    }

    public byte[] SignSha256(ReadOnlySpan<byte> digest)
    {
        ThrowIfDisposed();
        lock (_signLock)
        {
            return _signer!.SignHash(digest, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        _signer?.Dispose();
        _key?.Dispose();
    }

    private static DeviceIdentity Open(string appId, StateStore store, string installId, string keyName)
    {
        var key = CngKey.Open(
            keyName,
            CngProvider.MicrosoftSoftwareKeyStorageProvider,
            CngKeyOpenOptions.Silent);
        return FromKey(appId, store, installId, keyName, key);
    }

    private static DeviceIdentity FromKey(
        string appId,
        StateStore store,
        string installId,
        string keyName,
        CngKey key)
    {
        var signer = new ECDsaCng(key);
        var parameters = signer.ExportParameters(false);
        if (parameters.Q.X == null || parameters.Q.Y == null ||
            parameters.Q.X.Length != 32 || parameters.Q.Y.Length != 32)
        {
            signer.Dispose();
            key.Dispose();
            throw new SwmIdentityException("device key is not a P-256 key");
        }
        var sec1 = new byte[65];
        sec1[0] = 0x04;
        Buffer.BlockCopy(parameters.Q.X, 0, sec1, 1, 32);
        Buffer.BlockCopy(parameters.Q.Y, 0, sec1, 33, 32);
        var thumbprint = CryptoUtil.Base64UrlEncode(CryptoUtil.Sha256(sec1));
        var deviceId = CryptoUtil.Sha256Hex(Encoding.UTF8.GetBytes(
            "device_credential_v2\napp_id:" + appId +
            "\ninstall_id:" + installId +
            "\nkey_thumbprint:" + thumbprint));
        var identity = new DeviceIdentity(
            store,
            installId,
            keyName,
            deviceId,
            "swm-device-" + thumbprint[..22],
            thumbprint,
            CryptoUtil.Base64UrlEncode(sec1));
        identity._key = key;
        identity._signer = signer;
        return identity;
    }

    private static string BuildKeyName(string appId, string installId)
    {
        var appHash = Convert.ToHexString(CryptoUtil.Sha256(Encoding.UTF8.GetBytes(appId)))[..12]
            .ToLowerInvariant();
        return $"SwmSdk.{appHash}.{installId}";
    }

    private static (string InstallId, string KeyName)? ReadMetadata(StateStore store)
    {
        if (!store.TryReadProtected(MetadataFile, out var plaintext))
        {
            return null;
        }
        var text = Encoding.UTF8.GetString(plaintext);
        CryptographicOperations.ZeroMemory(plaintext);
        var lines = text.Split('\n');
        if (lines.Length < 3 || lines[0] != "v2" ||
            lines[1].Length != 32 || string.IsNullOrWhiteSpace(lines[2]))
        {
            return null;
        }
        return (lines[1], lines[2]);
    }

    private static void WriteMetadata(StateStore store, string installId, string keyName)
    {
        var plaintext = Encoding.UTF8.GetBytes($"v2\n{installId}\n{keyName}\n");
        try
        {
            store.WriteProtected(MetadataFile, plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}
