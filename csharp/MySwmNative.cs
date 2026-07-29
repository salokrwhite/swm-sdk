#nullable enable
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SwmSdk;

internal sealed class MySwmSafeHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    private MySwmSafeHandle() : base(true) { }

    internal MySwmSafeHandle(IntPtr handle) : base(true)
    {
        SetHandle(handle);
    }

    protected override bool ReleaseHandle()
    {
        MySwmNative.ContextDestroy(handle);
        return true;
    }
}

internal static partial class MySwmNative
{
    internal const string LibraryName = "MySwm.dll";
    internal const uint AbiVersion = 0x00010005;

#if NET7_0_OR_GREATER
    [LibraryImport(LibraryName, EntryPoint = "oplus_swm_get_abi_version")]
    internal static partial uint GetAbiVersion();

    [LibraryImport(LibraryName, EntryPoint = "oplus_swm_context_create")]
    internal static partial MySwmStatus ContextCreate(IntPtr deviceIdUtf8, out IntPtr context);

    [LibraryImport(LibraryName, EntryPoint = "oplus_swm_context_destroy")]
    internal static partial void ContextDestroy(IntPtr context);

    [LibraryImport(LibraryName, EntryPoint = "oplus_swm_context_get_identity")]
    internal static unsafe partial MySwmStatus ContextGetIdentity(MySwmSafeHandle context, MySwmIdentityNative* identity);

    [LibraryImport(LibraryName, EntryPoint = "oplus_swm_context_set_session")]
    internal static partial MySwmStatus ContextSetSession(MySwmSafeHandle context, IntPtr sessionUtf8, long expiresAtUnix, IntPtr serverKeyIdUtf8);

    [LibraryImport(LibraryName, EntryPoint = "oplus_swm_context_clear_session")]
    internal static partial MySwmStatus ContextClearSession(MySwmSafeHandle context, MySwmCloudState state);

    [LibraryImport(LibraryName, EntryPoint = "oplus_swm_context_get_cloud_state")]
    internal static partial MySwmCloudState ContextGetCloudState(MySwmSafeHandle context);

    [LibraryImport(LibraryName, EntryPoint = "oplus_swm_context_create_update_check_proof")]
    internal static unsafe partial MySwmStatus ContextCreateUpdateCheckProof(MySwmSafeHandle context, byte* body, nuint bodySize, byte* outputUtf8, nuint outputCapacity, out nuint outputSize);

    [LibraryImport(LibraryName, EntryPoint = "oplus_swm_context_create_heartbeat_proof")]
    internal static unsafe partial MySwmStatus ContextCreateHeartbeatProof(MySwmSafeHandle context, byte* body, nuint bodySize, byte* outputUtf8, nuint outputCapacity, out nuint outputSize);

    [LibraryImport(LibraryName, EntryPoint = "oplus_swm_context_create_events_proof")]
    internal static unsafe partial MySwmStatus ContextCreateEventsProof(MySwmSafeHandle context, byte* body, nuint bodySize, byte* outputUtf8, nuint outputCapacity, out nuint outputSize);

    [LibraryImport(LibraryName, EntryPoint = "oplus_swm_context_create_feedback_proof")]
    internal static unsafe partial MySwmStatus ContextCreateFeedbackProof(MySwmSafeHandle context, byte* body, nuint bodySize, byte* outputUtf8, nuint outputCapacity, out nuint outputSize);

    [LibraryImport(LibraryName, EntryPoint = "oplus_swm_context_create_enrollment_ticket_proof")]
    internal static unsafe partial MySwmStatus ContextCreateEnrollmentTicketProof(MySwmSafeHandle context, byte* body, nuint bodySize, byte* outputUtf8, nuint outputCapacity, out nuint outputSize);

    [LibraryImport(LibraryName, EntryPoint = "oplus_swm_context_create_firmware_identity_proof")]
    internal static unsafe partial MySwmStatus ContextCreateFirmwareIdentityProof(MySwmSafeHandle context, byte* body, nuint bodySize, byte* outputUtf8, nuint outputCapacity, out nuint outputSize);

    [LibraryImport(LibraryName, EntryPoint = "oplus_swm_context_create_debug_create_proof")]
    internal static unsafe partial MySwmStatus ContextCreateDebugCreateProof(MySwmSafeHandle context, byte* body, nuint bodySize, byte* outputUtf8, nuint outputCapacity, out nuint outputSize);

    [LibraryImport(LibraryName, EntryPoint = "oplus_swm_context_create_debug_cancel_proof")]
    internal static unsafe partial MySwmStatus ContextCreateDebugCancelProof(MySwmSafeHandle context, IntPtr requestIdUtf8, byte* body, nuint bodySize, byte* outputUtf8, nuint outputCapacity, out nuint outputSize);

    [LibraryImport(LibraryName, EntryPoint = "oplus_swm_context_create_debug_stream_proof")]
    internal static unsafe partial MySwmStatus ContextCreateDebugStreamProof(MySwmSafeHandle context, IntPtr requestIdUtf8, byte* outputUtf8, nuint outputCapacity, out nuint outputSize);

    [LibraryImport(LibraryName, EntryPoint = "oplus_swm_context_create_download_proof")]
    internal static unsafe partial MySwmStatus ContextCreateDownloadProof(MySwmSafeHandle context, IntPtr ticketUrlUtf8, byte* outputUtf8, nuint outputCapacity, out nuint outputSize);

    [LibraryImport(LibraryName, EntryPoint = "oplus_swm_context_create_update_stream_proof")]
    internal static unsafe partial MySwmStatus ContextCreateUpdateStreamProof(MySwmSafeHandle context, IntPtr streamUrlUtf8, byte* outputUtf8, nuint outputCapacity, out nuint outputSize);

    [LibraryImport(LibraryName, EntryPoint = "oplus_swm_context_get_last_error")]
    internal static unsafe partial nuint ContextGetLastError(MySwmSafeHandle context, byte* outputUtf8, nuint outputCapacity);

	[LibraryImport(LibraryName, EntryPoint = "oplus_swm_context_verify_authz_v3")]
	internal static unsafe partial MySwmStatus ContextVerifyAuthzV3(
		MySwmSafeHandle context, MySwmAuthzV3Native* authz, IntPtr requestNonceUtf8, byte* data, nuint dataSize);

	[LibraryImport(LibraryName, EntryPoint = "oplus_swm_context_create_update_auth")]
	internal static unsafe partial MySwmStatus ContextCreateUpdateAuth(
		MySwmSafeHandle context, byte* body, nuint bodySize, MySwmUpdateAuthNative* auth);
#else
    [DllImport(LibraryName, EntryPoint = "oplus_swm_get_abi_version", CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint GetAbiVersion();

    [DllImport(LibraryName, EntryPoint = "oplus_swm_context_create", CallingConvention = CallingConvention.Cdecl)]
    internal static extern MySwmStatus ContextCreate(IntPtr deviceIdUtf8, out IntPtr context);

    [DllImport(LibraryName, EntryPoint = "oplus_swm_context_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void ContextDestroy(IntPtr context);

    [DllImport(LibraryName, EntryPoint = "oplus_swm_context_get_identity", CallingConvention = CallingConvention.Cdecl)]
    internal static extern unsafe MySwmStatus ContextGetIdentity(MySwmSafeHandle context, MySwmIdentityNative* identity);

    [DllImport(LibraryName, EntryPoint = "oplus_swm_context_set_session", CallingConvention = CallingConvention.Cdecl)]
    internal static extern MySwmStatus ContextSetSession(MySwmSafeHandle context, IntPtr sessionUtf8, long expiresAtUnix, IntPtr serverKeyIdUtf8);

    [DllImport(LibraryName, EntryPoint = "oplus_swm_context_clear_session", CallingConvention = CallingConvention.Cdecl)]
    internal static extern MySwmStatus ContextClearSession(MySwmSafeHandle context, MySwmCloudState state);

    [DllImport(LibraryName, EntryPoint = "oplus_swm_context_get_cloud_state", CallingConvention = CallingConvention.Cdecl)]
    internal static extern MySwmCloudState ContextGetCloudState(MySwmSafeHandle context);

    [DllImport(LibraryName, EntryPoint = "oplus_swm_context_create_update_check_proof", CallingConvention = CallingConvention.Cdecl)]
    internal static extern unsafe MySwmStatus ContextCreateUpdateCheckProof(MySwmSafeHandle context, byte* body, UIntPtr bodySize, byte* outputUtf8, UIntPtr outputCapacity, out UIntPtr outputSize);

    [DllImport(LibraryName, EntryPoint = "oplus_swm_context_create_heartbeat_proof", CallingConvention = CallingConvention.Cdecl)]
    internal static extern unsafe MySwmStatus ContextCreateHeartbeatProof(MySwmSafeHandle context, byte* body, UIntPtr bodySize, byte* outputUtf8, UIntPtr outputCapacity, out UIntPtr outputSize);

    [DllImport(LibraryName, EntryPoint = "oplus_swm_context_create_events_proof", CallingConvention = CallingConvention.Cdecl)]
    internal static extern unsafe MySwmStatus ContextCreateEventsProof(MySwmSafeHandle context, byte* body, UIntPtr bodySize, byte* outputUtf8, UIntPtr outputCapacity, out UIntPtr outputSize);

    [DllImport(LibraryName, EntryPoint = "oplus_swm_context_create_feedback_proof", CallingConvention = CallingConvention.Cdecl)]
    internal static extern unsafe MySwmStatus ContextCreateFeedbackProof(MySwmSafeHandle context, byte* body, UIntPtr bodySize, byte* outputUtf8, UIntPtr outputCapacity, out UIntPtr outputSize);

    [DllImport(LibraryName, EntryPoint = "oplus_swm_context_create_enrollment_ticket_proof", CallingConvention = CallingConvention.Cdecl)]
    internal static extern unsafe MySwmStatus ContextCreateEnrollmentTicketProof(MySwmSafeHandle context, byte* body, UIntPtr bodySize, byte* outputUtf8, UIntPtr outputCapacity, out UIntPtr outputSize);

    [DllImport(LibraryName, EntryPoint = "oplus_swm_context_create_firmware_identity_proof", CallingConvention = CallingConvention.Cdecl)]
    internal static extern unsafe MySwmStatus ContextCreateFirmwareIdentityProof(MySwmSafeHandle context, byte* body, UIntPtr bodySize, byte* outputUtf8, UIntPtr outputCapacity, out UIntPtr outputSize);

    [DllImport(LibraryName, EntryPoint = "oplus_swm_context_create_debug_create_proof", CallingConvention = CallingConvention.Cdecl)]
    internal static extern unsafe MySwmStatus ContextCreateDebugCreateProof(MySwmSafeHandle context, byte* body, UIntPtr bodySize, byte* outputUtf8, UIntPtr outputCapacity, out UIntPtr outputSize);

    [DllImport(LibraryName, EntryPoint = "oplus_swm_context_create_debug_cancel_proof", CallingConvention = CallingConvention.Cdecl)]
    internal static extern unsafe MySwmStatus ContextCreateDebugCancelProof(MySwmSafeHandle context, IntPtr requestIdUtf8, byte* body, UIntPtr bodySize, byte* outputUtf8, UIntPtr outputCapacity, out UIntPtr outputSize);

    [DllImport(LibraryName, EntryPoint = "oplus_swm_context_create_debug_stream_proof", CallingConvention = CallingConvention.Cdecl)]
    internal static extern unsafe MySwmStatus ContextCreateDebugStreamProof(MySwmSafeHandle context, IntPtr requestIdUtf8, byte* outputUtf8, UIntPtr outputCapacity, out UIntPtr outputSize);

    [DllImport(LibraryName, EntryPoint = "oplus_swm_context_create_download_proof", CallingConvention = CallingConvention.Cdecl)]
    internal static extern unsafe MySwmStatus ContextCreateDownloadProof(MySwmSafeHandle context, IntPtr ticketUrlUtf8, byte* outputUtf8, UIntPtr outputCapacity, out UIntPtr outputSize);

    [DllImport(LibraryName, EntryPoint = "oplus_swm_context_create_update_stream_proof", CallingConvention = CallingConvention.Cdecl)]
    internal static extern unsafe MySwmStatus ContextCreateUpdateStreamProof(MySwmSafeHandle context, IntPtr streamUrlUtf8, byte* outputUtf8, UIntPtr outputCapacity, out UIntPtr outputSize);

    [DllImport(LibraryName, EntryPoint = "oplus_swm_context_get_last_error", CallingConvention = CallingConvention.Cdecl)]
    internal static extern unsafe UIntPtr ContextGetLastError(MySwmSafeHandle context, byte* outputUtf8, UIntPtr outputCapacity);

	[DllImport(LibraryName, EntryPoint = "oplus_swm_context_verify_authz_v3", CallingConvention = CallingConvention.Cdecl)]
	internal static extern unsafe MySwmStatus ContextVerifyAuthzV3(
		MySwmSafeHandle context, MySwmAuthzV3Native* authz, IntPtr requestNonceUtf8, byte* data, UIntPtr dataSize);

	[DllImport(LibraryName, EntryPoint = "oplus_swm_context_create_update_auth", CallingConvention = CallingConvention.Cdecl)]
	internal static extern unsafe MySwmStatus ContextCreateUpdateAuth(
		MySwmSafeHandle context, byte* body, UIntPtr bodySize, MySwmUpdateAuthNative* auth);
#endif
}

[StructLayout(LayoutKind.Sequential)]
internal struct MySwmAuthzV3Native
{
	internal uint StructSize;
	internal IntPtr Decision;
	internal IntPtr ReleaseId;
	internal IntPtr DeviceId;
	internal IntPtr Nonce;
	internal IntPtr DataSha256;
	internal IntPtr Session;
	internal long IssuedAt;
	internal long ExpiresAt;
	internal IntPtr KeyId;
	internal IntPtr Reason;
	internal IntPtr Signature;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
internal unsafe struct MySwmIdentityNative
{
    internal uint StructSize;
    internal fixed byte InstallId[65];
    internal fixed byte KeyId[129];
    internal fixed byte KeyThumbprint[129];
    internal fixed byte PublicKeySec1[257];
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct MySwmUpdateAuthNative
{
	internal uint StructSize;
	internal long Timestamp;
	internal fixed byte Nonce[37];
	internal fixed byte Reserved[65];
}
