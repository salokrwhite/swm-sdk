using System.Security.Cryptography;
using System.Text;

namespace SwmSdk.Internal;

internal sealed class StateStore
{
    private readonly string _directory;
    private readonly byte[] _entropy;

    public StateStore(string appId, string? overrideDirectory)
    {
        if (string.IsNullOrWhiteSpace(appId))
        {
            throw new SwmConfigurationException("AppId is required");
        }

        _directory = string.IsNullOrWhiteSpace(overrideDirectory)
            ? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SwmSdk",
                Convert.ToHexString(CryptoUtil.Sha256(Encoding.UTF8.GetBytes(appId)))[..12].ToLowerInvariant())
            : Path.GetFullPath(overrideDirectory);
        _entropy = CryptoUtil.Sha256(Encoding.UTF8.GetBytes("SwmSdkStateV2\n" + appId));
        Directory.CreateDirectory(_directory);
    }

    public string DirectoryPath => _directory;

    public string GetPath(string fileName)
    {
        return Path.Combine(_directory, fileName);
    }

    public bool TryReadProtected(string fileName, out byte[] plaintext)
    {
        plaintext = Array.Empty<byte>();
        var path = GetPath(fileName);
        if (!File.Exists(path))
        {
            return false;
        }
        try
        {
            var ciphertext = File.ReadAllBytes(path);
            if (ciphertext.Length == 0 || ciphertext.Length > 1024 * 1024)
            {
                return false;
            }
            plaintext = ProtectedData.Unprotect(ciphertext, _entropy, DataProtectionScope.CurrentUser);
            return true;
        }
        catch
        {
            plaintext = Array.Empty<byte>();
            return false;
        }
    }

    public void WriteProtected(string fileName, ReadOnlySpan<byte> plaintext)
    {
        var ciphertext = ProtectedData.Protect(
            plaintext.ToArray(),
            _entropy,
            DataProtectionScope.CurrentUser);
        var path = GetPath(fileName);
        var temporary = path + ".tmp";
        File.WriteAllBytes(temporary, ciphertext);
        File.Move(temporary, path, true);
    }

    public void Delete(string fileName)
    {
        var path = GetPath(fileName);
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }
}
