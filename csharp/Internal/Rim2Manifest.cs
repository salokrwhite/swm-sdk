using System.Buffers.Binary;
using System.Text;

namespace SwmSdk.Internal;

internal sealed class Rim2Manifest
{
    public required byte[] RawBytes { get; init; }
    public required string ManifestSha256 { get; init; }
    public required Guid AppId { get; init; }
    public required Guid ReleaseId { get; init; }
    public required ulong VersionCode { get; init; }
    public required string Version { get; init; }
    public required string Arch { get; init; }
    public required string RootKeyId { get; init; }
    public required string SignerKeyId { get; init; }
    public required IReadOnlyList<Rim2File> Files { get; init; }
}

internal sealed record Rim2File(string Path, ulong Size, byte[] Sha256);

internal static class Rim2Parser
{
    private static readonly Encoding StrictUtf8 = new UTF8Encoding(false, true);
    private static readonly byte[] Magic = "OPLUSRIM"u8.ToArray();
    private static readonly byte[] ManifestDomain = "OPLUS_RELEASE_MANIFEST_V2\0"u8.ToArray();
    private static readonly byte[] KeyDomain = "OPLUS_RELEASE_KEY_V2\0"u8.ToArray();

    public static Rim2Manifest ParseAndVerify(
        ReadOnlySpan<byte> raw,
        string expectedAppId,
        string expectedReleaseId,
        string expectedVersion,
        int? expectedVersionCode,
        string expectedArch,
        string expectedRootKeyId,
        string rootTrustPublicKey)
    {
        if (raw.Length is 0 or > 64 * 1024)
        {
            throw new SwmIntegrityException(
                0,
                "host_manifest_invalid",
                "RIM2 manifest size is invalid",
                IntegrityFailureAction.ShutdownClient);
        }
        if (raw.Length < 14 || !raw[..Magic.Length].SequenceEqual(Magic))
        {
            throw new SwmIntegrityException(
                0,
                "host_manifest_invalid",
                "RIM2 manifest magic is invalid",
                IntegrityFailureAction.ShutdownClient);
        }

        var offset = Magic.Length;
        var protocolVersion = ReadU16(raw, ref offset);
        var bodySize = ReadU32(raw, ref offset);
        if (protocolVersion != 2 || bodySize == 0 || bodySize > raw.Length - offset)
        {
            throw new SwmIntegrityException(
                0,
                "host_manifest_invalid",
                "RIM2 manifest header is invalid",
                IntegrityFailureAction.ShutdownClient);
        }
        var bodyStart = offset;
        var body = raw.Slice(offset, checked((int)bodySize));
        offset += checked((int)bodySize);
        var bodyOffset = 0;

        var appBytes = body.Slice(bodyOffset, 16).ToArray();
        bodyOffset += 16;
        var releaseBytes = body.Slice(bodyOffset, 16).ToArray();
        bodyOffset += 16;
        var versionCode = ReadU64(body, ref bodyOffset);
        var platform = body[bodyOffset++];
        var architecture = body[bodyOffset++];
        var version = ReadString16(body, ref bodyOffset);
        if (version.Length is 0 or > 100)
        {
            throw new SwmIntegrityException(
                0,
                "host_manifest_invalid",
                "RIM2 release version is invalid",
                IntegrityFailureAction.ShutdownClient);
        }
        var fileCount = ReadU16(body, ref bodyOffset);
        if (fileCount is 0 or > 255)
        {
            throw new SwmIntegrityException(
                0,
                "host_manifest_invalid",
                "RIM2 manifest file count is invalid",
                IntegrityFailureAction.ShutdownClient);
        }

        var files = new List<Rim2File>(fileCount);
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < fileCount; index++)
        {
            var path = ReadString16(body, ref bodyOffset);
            var size = ReadU64(body, ref bodyOffset);
            var hash = body.Slice(bodyOffset, 32).ToArray();
            bodyOffset += 32;
            if (!IsSafePath(path) || size == 0 || hash.All(value => value == 0) ||
                !paths.Add(path))
            {
                throw new SwmIntegrityException(
                    0,
                    "host_manifest_invalid",
                    "RIM2 manifest contains an unsafe or duplicate file path",
                    IntegrityFailureAction.ShutdownClient);
            }
            files.Add(new Rim2File(path, size, hash));
        }
        if (bodyOffset != body.Length)
        {
            throw new SwmIntegrityException(
                0,
                "host_manifest_invalid",
                "RIM2 manifest body contains trailing bytes",
                IntegrityFailureAction.ShutdownClient);
        }

        var trailerOffset = offset;
        var rootKeyId = ReadString8(raw, ref trailerOffset);
        var signerKeyId = ReadString8(raw, ref trailerOffset);
        if (rootKeyId.Length is 0 or > 64 || signerKeyId.Length is 0 or > 64)
        {
            throw new SwmIntegrityException(
                0,
                "host_manifest_invalid",
                "RIM2 signing key id is invalid",
                IntegrityFailureAction.ShutdownClient);
        }
        var signerPublicKey = raw.Slice(trailerOffset, 32).ToArray();
        trailerOffset += 32;
        var rootCertificateSignature = raw.Slice(trailerOffset, 64).ToArray();
        trailerOffset += 64;
        var manifestSignature = raw.Slice(trailerOffset, 64).ToArray();
        trailerOffset += 64;
        if (trailerOffset != raw.Length)
        {
            throw new SwmIntegrityException(
                0,
                "host_manifest_invalid",
                "RIM2 manifest trailer is invalid",
                IntegrityFailureAction.ShutdownClient);
        }

        var appId = Guid.Parse(expectedAppId);
        var releaseId = Guid.Parse(expectedReleaseId);
        if (!appBytes.SequenceEqual(GuidToRfc4122(appId)) ||
            !releaseBytes.SequenceEqual(GuidToRfc4122(releaseId)) ||
            platform != 1 ||
            architecture != ArchitectureByte(expectedArch) ||
            version != expectedVersion ||
            (expectedVersionCode.HasValue && versionCode != (ulong)expectedVersionCode.Value) ||
            rootKeyId != expectedRootKeyId)
        {
            throw new SwmIntegrityException(
                0,
                "host_release_mismatch",
                "RIM2 manifest identity does not match this release",
                IntegrityFailureAction.ShutdownClient);
        }

        var keyMessage = new List<byte>(KeyDomain.Length + appBytes.Length + rootKeyId.Length + signerKeyId.Length + signerPublicKey.Length + 4);
        keyMessage.AddRange(KeyDomain);
        keyMessage.AddRange(appBytes);
        AppendString8(keyMessage, rootKeyId);
        AppendString8(keyMessage, signerKeyId);
        keyMessage.AddRange(signerPublicKey);
        if (!CryptoUtil.VerifyEd25519(
                rootTrustPublicKey,
                keyMessage.ToArray(),
                Convert.ToBase64String(rootCertificateSignature)))
        {
            throw new SwmIntegrityException(
                0,
                "host_root_signature_invalid",
                "RIM2 root certificate signature is invalid",
                IntegrityFailureAction.ShutdownClient);
        }

        var manifestMessage = new byte[ManifestDomain.Length + body.Length];
        Buffer.BlockCopy(ManifestDomain, 0, manifestMessage, 0, ManifestDomain.Length);
        body.CopyTo(manifestMessage.AsSpan(ManifestDomain.Length));
        if (!CryptoUtil.VerifyEd25519(
                Convert.ToBase64String(signerPublicKey),
                manifestMessage,
                Convert.ToBase64String(manifestSignature)))
        {
            throw new SwmIntegrityException(
                0,
                "host_manifest_signature_invalid",
                "RIM2 manifest signature is invalid",
                IntegrityFailureAction.ShutdownClient);
        }

        return new Rim2Manifest
        {
            RawBytes = raw.ToArray(),
            ManifestSha256 = CryptoUtil.Sha256Hex(raw),
            AppId = appId,
            ReleaseId = releaseId,
            VersionCode = versionCode,
            Version = version,
            Arch = NormalizeArch(architecture),
            RootKeyId = rootKeyId,
            SignerKeyId = signerKeyId,
            Files = files
        };
    }

    private static ushort ReadU16(ReadOnlySpan<byte> value, ref int offset)
    {
        EnsureAvailable(value, offset, 2);
        var result = BinaryPrimitives.ReadUInt16BigEndian(value[offset..]);
        offset += 2;
        return result;
    }

    private static uint ReadU32(ReadOnlySpan<byte> value, ref int offset)
    {
        EnsureAvailable(value, offset, 4);
        var result = BinaryPrimitives.ReadUInt32BigEndian(value[offset..]);
        offset += 4;
        return result;
    }

    private static ulong ReadU64(ReadOnlySpan<byte> value, ref int offset)
    {
        EnsureAvailable(value, offset, 8);
        var result = BinaryPrimitives.ReadUInt64BigEndian(value[offset..]);
        offset += 8;
        return result;
    }

    private static string ReadString8(ReadOnlySpan<byte> value, ref int offset)
    {
        EnsureAvailable(value, offset, 1);
        var length = value[offset++];
        return ReadUtf8(value, ref offset, length);
    }

    private static string ReadString16(ReadOnlySpan<byte> value, ref int offset)
    {
        var length = ReadU16(value, ref offset);
        return ReadUtf8(value, ref offset, length);
    }

    private static string ReadUtf8(ReadOnlySpan<byte> value, ref int offset, int length)
    {
        EnsureAvailable(value, offset, length);
        string text;
        try
        {
            text = StrictUtf8.GetString(value.Slice(offset, length));
        }
        catch (DecoderFallbackException)
        {
            throw new SwmIntegrityException(
                0,
                "host_manifest_invalid",
                "RIM2 manifest contains invalid UTF-8",
                IntegrityFailureAction.ShutdownClient);
        }
        offset += length;
        return text;
    }

    private static void EnsureAvailable(ReadOnlySpan<byte> value, int offset, int length)
    {
        if (offset < 0 || length < 0 || offset + length > value.Length)
        {
            throw new SwmIntegrityException(
                0,
                "host_manifest_invalid",
                "RIM2 manifest is truncated",
                IntegrityFailureAction.ShutdownClient);
        }
    }

    private static bool IsSafePath(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 255 ||
            value.Contains('\\') || value.StartsWith('/') || value.EndsWith('/') ||
            value.Contains(':') || value.Contains('\0') ||
            value.Split('/').Any(part => part is "" or "." or ".."))
        {
            return false;
        }
        return value.All(character => character >= 0x20 && character != 0x7f);
    }

    private static int ArchitectureByte(string arch)
    {
        return NormalizeArch(arch) switch
        {
            "x86" => 1,
            "x64" => 2,
            _ => 0
        };
    }

    private static string NormalizeArch(string arch)
    {
        return arch.Trim().ToLowerInvariant() switch
        {
            "amd64" or "win-x64" => "x64",
            "i386" or "win-x86" => "x86",
            var value => value
        };
    }

    private static string NormalizeArch(int architecture)
    {
        return architecture switch
        {
            1 => "x86",
            2 => "x64",
            _ => string.Empty
        };
    }

    private static byte[] GuidToRfc4122(Guid value)
    {
        var bytes = value.ToByteArray();
        Array.Reverse(bytes, 0, 4);
        Array.Reverse(bytes, 4, 2);
        Array.Reverse(bytes, 6, 2);
        return bytes;
    }

    private static void AppendString8(List<byte> target, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        if (bytes.Length > byte.MaxValue)
        {
            throw new SwmIntegrityException(
                0,
                "host_manifest_invalid",
                "RIM2 string exceeds its protocol limit",
                IntegrityFailureAction.ShutdownClient);
        }
        target.Add((byte)bytes.Length);
        target.AddRange(bytes);
    }
}
