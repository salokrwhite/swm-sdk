#nullable enable
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SwmSdk;

public enum MySwmStatus
{
    Ok = 0,
    InvalidArgument = 1,
    BufferTooSmall = 2,
    OutOfMemory = 3,
    ConfigurationInvalid = 4,
    UnsupportedOsSecurityBaseline = 5,
    CryptoError = 6,
    IdentityError = 7,
    SessionUnavailable = 8,
    OperationNotAllowed = 9,
    NetworkError = 10,
    ProtocolError = 11,
    AuthorizationDenied = 12,
    IntegrityError = 13,
    InternalError = 255
}

public enum MySwmCloudState
{
    Unavailable = 0,
    Authorizing = 1,
    Available = 2,
    Expired = 3,
    Revoked = 4,
    IntegrityFailure = 5
}

public enum MySwmOperation
{
    UpdateCheck = 1,
    Heartbeat = 2,
    Events = 3,
    Feedback = 4,
    EnrollmentTicket = 5,
	Download = 6,
	UpdateStream = 7,
    FirmwareIdentity = 20,
    DebugCreate = 30,
    DebugCancel = 31,
    DebugStream = 32
}

public sealed class MySwmException : Exception
{
    public MySwmStatus Status { get; }

    public MySwmException(MySwmStatus status, string message) : base(message)
    {
        Status = status;
    }
}

public sealed class MySwmIdentity
{
    internal MySwmIdentity(string installId, string keyId, string keyThumbprint, string publicKeySec1)
    {
        InstallId = installId;
        KeyId = keyId;
        KeyThumbprint = keyThumbprint;
        PublicKeySec1 = publicKeySec1;
    }

    public string InstallId { get; }
    public string KeyId { get; }
    public string KeyThumbprint { get; }
    public string PublicKeySec1 { get; }
}

internal sealed class MySwmUpdateAuth
{
	internal MySwmUpdateAuth(long timestamp, string nonce)
	{
		Timestamp = timestamp;
		Nonce = nonce;
	}
	internal long Timestamp { get; }
	internal string Nonce { get; }
}

public sealed unsafe class MySwmContext : IDisposable
{
    private readonly MySwmSafeHandle handle;
    private bool disposed;

    private MySwmContext(MySwmSafeHandle handle)
    {
        this.handle = handle;
    }

    public static MySwmContext Create(string deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId)) throw new ArgumentException("deviceId is required", nameof(deviceId));
        uint abi;
        try
        {
            abi = MySwmNative.GetAbiVersion();
        }
        catch (BadImageFormatException ex)
        {
            throw new MySwmException(MySwmStatus.IntegrityError, "MySwm.dll architecture does not match the host process: " + ex.Message);
        }
        catch (DllNotFoundException ex)
        {
            throw new MySwmException(MySwmStatus.IntegrityError, "MySwm.dll was not found: " + ex.Message);
        }
        if (abi != MySwmNative.AbiVersion)
        {
            throw new MySwmException(MySwmStatus.IntegrityError, $"MySwm ABI mismatch: expected=0x{MySwmNative.AbiVersion:X8}, actual=0x{abi:X8}");
        }
        using var device = Utf8Argument.Create(deviceId.Trim());
        var status = MySwmNative.ContextCreate(device.Pointer, out var nativeHandle);
        if (status != MySwmStatus.Ok)
        {
            if (nativeHandle != IntPtr.Zero) MySwmNative.ContextDestroy(nativeHandle);
            throw new MySwmException(status, "MySwm context initialization failed");
        }
        if (nativeHandle == IntPtr.Zero)
        {
            throw new MySwmException(MySwmStatus.InternalError, "MySwm returned an empty context");
        }
        return new MySwmContext(new MySwmSafeHandle(nativeHandle));
    }

    public MySwmIdentity GetIdentity()
    {
        ThrowIfDisposed();
        var value = new MySwmIdentityNative { StructSize = (uint)sizeof(MySwmIdentityNative) };
        var status = MySwmNative.ContextGetIdentity(handle, &value);
        ThrowIfFailed(status);
        return new MySwmIdentity(
            ReadUtf8(value.InstallId, 65),
            ReadUtf8(value.KeyId, 129),
            ReadUtf8(value.KeyThumbprint, 129),
            ReadUtf8(value.PublicKeySec1, 257));
    }

    public void SetSession(string session, long expiresAtUnix, string serverKeyId)
    {
        ThrowIfDisposed();
        using var sessionValue = Utf8Argument.Create(session);
        using var keyValue = Utf8Argument.Create(serverKeyId);
        ThrowIfFailed(MySwmNative.ContextSetSession(handle, sessionValue.Pointer, expiresAtUnix, keyValue.Pointer));
    }

    public void ClearSession(MySwmCloudState state)
    {
        ThrowIfDisposed();
        ThrowIfFailed(MySwmNative.ContextClearSession(handle, state));
    }

    public MySwmCloudState CloudState
    {
        get
        {
            ThrowIfDisposed();
            return MySwmNative.ContextGetCloudState(handle);
        }
    }

    public string CreateFirmwareIdentityProof(byte[]? body) => CreateProof(MySwmOperation.FirmwareIdentity, body);

    public string CreateDebugCreateProof(byte[]? body) => CreateProof(MySwmOperation.DebugCreate, body);

    public string CreateDebugCancelProof(string requestId, byte[]? body) => CreateProof(MySwmOperation.DebugCancel, body, requestId);

    public string CreateDebugStreamProof(string requestId) => CreateProof(MySwmOperation.DebugStream, Array.Empty<byte>(), requestId);

    internal string CreateProof(MySwmOperation operation, byte[]? body = null, string? resourceId = null)
    {
        ThrowIfDisposed();
        body ??= Array.Empty<byte>();
        using var resource = Utf8Argument.Create(resourceId ?? string.Empty);
        fixed (byte* bodyPointer = body)
        {
#if NET7_0_OR_GREATER
            var status = InvokeProof(operation, resource.Pointer, bodyPointer, (nuint)body.Length, null, 0, out var required);
            if (status != MySwmStatus.BufferTooSmall) ThrowIfFailed(status);
            var output = new byte[checked((int)required)];
            fixed (byte* outputPointer = output)
            {
                status = InvokeProof(operation, resource.Pointer, bodyPointer, (nuint)body.Length, outputPointer, (nuint)output.Length, out required);
            }
#else
            var status = InvokeProof(operation, resource.Pointer, bodyPointer, (UIntPtr)(uint)body.Length, null, UIntPtr.Zero, out var required);
            if (status != MySwmStatus.BufferTooSmall) ThrowIfFailed(status);
            var output = new byte[checked((int)required.ToUInt64())];
            fixed (byte* outputPointer = output)
            {
                status = InvokeProof(operation, resource.Pointer, bodyPointer, (UIntPtr)(uint)body.Length, outputPointer, (UIntPtr)(uint)output.Length, out required);
            }
#endif
            ThrowIfFailed(status);
            return Encoding.UTF8.GetString(output, 0, output.Length - 1);
        }
    }

#if NET7_0_OR_GREATER
    private MySwmStatus InvokeProof(MySwmOperation operation, IntPtr resource, byte* body, nuint bodySize, byte* output, nuint outputCapacity, out nuint outputSize)
    {
        return operation switch
        {
            MySwmOperation.UpdateCheck => MySwmNative.ContextCreateUpdateCheckProof(handle, body, bodySize, output, outputCapacity, out outputSize),
            MySwmOperation.Heartbeat => MySwmNative.ContextCreateHeartbeatProof(handle, body, bodySize, output, outputCapacity, out outputSize),
            MySwmOperation.Events => MySwmNative.ContextCreateEventsProof(handle, body, bodySize, output, outputCapacity, out outputSize),
            MySwmOperation.Feedback => MySwmNative.ContextCreateFeedbackProof(handle, body, bodySize, output, outputCapacity, out outputSize),
            MySwmOperation.EnrollmentTicket => MySwmNative.ContextCreateEnrollmentTicketProof(handle, body, bodySize, output, outputCapacity, out outputSize),
            MySwmOperation.FirmwareIdentity => MySwmNative.ContextCreateFirmwareIdentityProof(handle, body, bodySize, output, outputCapacity, out outputSize),
            MySwmOperation.DebugCreate => MySwmNative.ContextCreateDebugCreateProof(handle, body, bodySize, output, outputCapacity, out outputSize),
            MySwmOperation.DebugCancel => MySwmNative.ContextCreateDebugCancelProof(handle, resource, body, bodySize, output, outputCapacity, out outputSize),
            MySwmOperation.DebugStream => MySwmNative.ContextCreateDebugStreamProof(handle, resource, output, outputCapacity, out outputSize),
            MySwmOperation.Download => MySwmNative.ContextCreateDownloadProof(handle, resource, output, outputCapacity, out outputSize),
            MySwmOperation.UpdateStream => MySwmNative.ContextCreateUpdateStreamProof(handle, resource, output, outputCapacity, out outputSize),
            _ => SetUnsupportedProofOutput(out outputSize)
        };
    }

    private static MySwmStatus SetUnsupportedProofOutput(out nuint outputSize)
    {
        outputSize = 0;
        return MySwmStatus.OperationNotAllowed;
    }
#else
    private MySwmStatus InvokeProof(MySwmOperation operation, IntPtr resource, byte* body, UIntPtr bodySize, byte* output, UIntPtr outputCapacity, out UIntPtr outputSize)
    {
        return operation switch
        {
            MySwmOperation.UpdateCheck => MySwmNative.ContextCreateUpdateCheckProof(handle, body, bodySize, output, outputCapacity, out outputSize),
            MySwmOperation.Heartbeat => MySwmNative.ContextCreateHeartbeatProof(handle, body, bodySize, output, outputCapacity, out outputSize),
            MySwmOperation.Events => MySwmNative.ContextCreateEventsProof(handle, body, bodySize, output, outputCapacity, out outputSize),
            MySwmOperation.Feedback => MySwmNative.ContextCreateFeedbackProof(handle, body, bodySize, output, outputCapacity, out outputSize),
            MySwmOperation.EnrollmentTicket => MySwmNative.ContextCreateEnrollmentTicketProof(handle, body, bodySize, output, outputCapacity, out outputSize),
            MySwmOperation.FirmwareIdentity => MySwmNative.ContextCreateFirmwareIdentityProof(handle, body, bodySize, output, outputCapacity, out outputSize),
            MySwmOperation.DebugCreate => MySwmNative.ContextCreateDebugCreateProof(handle, body, bodySize, output, outputCapacity, out outputSize),
            MySwmOperation.DebugCancel => MySwmNative.ContextCreateDebugCancelProof(handle, resource, body, bodySize, output, outputCapacity, out outputSize),
            MySwmOperation.DebugStream => MySwmNative.ContextCreateDebugStreamProof(handle, resource, output, outputCapacity, out outputSize),
            MySwmOperation.Download => MySwmNative.ContextCreateDownloadProof(handle, resource, output, outputCapacity, out outputSize),
            MySwmOperation.UpdateStream => MySwmNative.ContextCreateUpdateStreamProof(handle, resource, output, outputCapacity, out outputSize),
            _ => SetUnsupportedProofOutput(out outputSize)
        };
    }

    private static MySwmStatus SetUnsupportedProofOutput(out UIntPtr outputSize)
    {
        outputSize = UIntPtr.Zero;
        return MySwmStatus.OperationNotAllowed;
    }
#endif

	internal void VerifyAuthzV3(AuthzV3Envelope envelope, string requestNonce, byte[] data)
	{
		ThrowIfDisposed();
		if (envelope == null) throw new ArgumentNullException(nameof(envelope));
		if (string.IsNullOrWhiteSpace(requestNonce)) throw new ArgumentException("request nonce is required", nameof(requestNonce));
		data ??= Array.Empty<byte>();
		using var decision = Utf8Argument.Create(envelope.Decision ?? string.Empty);
		using var releaseId = Utf8Argument.Create(envelope.ReleaseId ?? string.Empty);
		using var deviceId = Utf8Argument.Create(envelope.DeviceId ?? string.Empty);
		using var nonce = Utf8Argument.Create(envelope.Nonce ?? string.Empty);
		using var dataHash = Utf8Argument.Create(envelope.DataSha256 ?? string.Empty);
		using var session = Utf8Argument.Create(envelope.Session ?? string.Empty);
		using var keyId = Utf8Argument.Create(envelope.KeyId ?? string.Empty);
		using var reason = Utf8Argument.Create(envelope.Reason ?? string.Empty);
		using var signature = Utf8Argument.Create(envelope.Signature ?? string.Empty);
		using var expectedNonce = Utf8Argument.Create(requestNonce);
		var value = new MySwmAuthzV3Native
		{
			StructSize = (uint)Marshal.SizeOf<MySwmAuthzV3Native>(),
			Decision = decision.Pointer,
			ReleaseId = releaseId.Pointer,
			DeviceId = deviceId.Pointer,
			Nonce = nonce.Pointer,
			DataSha256 = dataHash.Pointer,
			Session = session.Pointer,
			IssuedAt = envelope.IssuedAt,
			ExpiresAt = envelope.ExpiresAt,
			KeyId = keyId.Pointer,
			Reason = reason.Pointer,
			Signature = signature.Pointer
		};
		fixed (byte* dataPointer = data)
		{
#if NET7_0_OR_GREATER
			ThrowIfFailed(MySwmNative.ContextVerifyAuthzV3(handle, &value, expectedNonce.Pointer, dataPointer, (nuint)data.Length));
#else
			ThrowIfFailed(MySwmNative.ContextVerifyAuthzV3(handle, &value, expectedNonce.Pointer, dataPointer, (UIntPtr)(uint)data.Length));
#endif
		}
	}

	internal MySwmUpdateAuth CreateUpdateAuth(byte[] body)
	{
		ThrowIfDisposed();
		body ??= Array.Empty<byte>();
		var value = new MySwmUpdateAuthNative { StructSize = (uint)sizeof(MySwmUpdateAuthNative) };
		fixed (byte* bodyPointer = body)
		{
#if NET7_0_OR_GREATER
			ThrowIfFailed(MySwmNative.ContextCreateUpdateAuth(handle, bodyPointer, (nuint)body.Length, &value));
#else
			ThrowIfFailed(MySwmNative.ContextCreateUpdateAuth(handle, bodyPointer, (UIntPtr)(uint)body.Length, &value));
#endif
		}
		return new MySwmUpdateAuth(value.Timestamp, ReadUtf8(value.Nonce, 37));
	}

    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        handle.Dispose();
    }

    private void ThrowIfDisposed()
    {
        if (disposed) throw new ObjectDisposedException(nameof(MySwmContext));
    }

    private void ThrowIfFailed(MySwmStatus status)
    {
        if (status == MySwmStatus.Ok) return;
        throw new MySwmException(status, ReadLastError());
    }

    private string ReadLastError()
    {
#if NET7_0_OR_GREATER
        var required = MySwmNative.ContextGetLastError(handle, null, 0);
        if (required == 0) return "MySwm operation failed";
        var value = new byte[checked((int)required)];
        fixed (byte* pointer = value) MySwmNative.ContextGetLastError(handle, pointer, (nuint)value.Length);
#else
        var required = MySwmNative.ContextGetLastError(handle, null, UIntPtr.Zero);
        if (required == UIntPtr.Zero) return "MySwm operation failed";
        var value = new byte[checked((int)required.ToUInt64())];
        fixed (byte* pointer = value) MySwmNative.ContextGetLastError(handle, pointer, (UIntPtr)(uint)value.Length);
#endif
        return Encoding.UTF8.GetString(value, 0, value.Length - 1);
    }

    private static string ReadUtf8(byte* value, int capacity)
    {
        var length = 0;
        while (length < capacity && value[length] != 0) length++;
        if (length == 0) return string.Empty;
        var bytes = new byte[length];
        Marshal.Copy((IntPtr)value, bytes, 0, length);
        return Encoding.UTF8.GetString(bytes, 0, bytes.Length);
    }

    private sealed class Utf8Argument : IDisposable
    {
        internal IntPtr Pointer { get; private set; }

        private Utf8Argument(IntPtr pointer) { Pointer = pointer; }

        internal static Utf8Argument Create(string value)
        {
            var bytes = Encoding.UTF8.GetBytes(value + "\0");
            var pointer = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, pointer, bytes.Length);
            Array.Clear(bytes, 0, bytes.Length);
            return new Utf8Argument(pointer);
        }

        public void Dispose()
        {
            if (Pointer == IntPtr.Zero) return;
            Marshal.FreeHGlobal(Pointer);
            Pointer = IntPtr.Zero;
        }
    }
}
