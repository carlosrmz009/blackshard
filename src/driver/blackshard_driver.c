#include <fltKernel.h>
#include <dontuse.h>

#define MAX_FILE_PATH_LENGTH 260

typedef struct _BLACKSHARD_NOTIFICATION {
    ULONG ProcessId;
    WCHAR FilePath[MAX_FILE_PATH_LENGTH];
} BLACKSHARD_NOTIFICATION, *PBLACKSHARD_NOTIFICATION;

typedef enum _BLACKSHARD_VERDICT {
    VERDICT_ALLOW = 0,
    VERDICT_BLOCK = 1
} BLACKSHARD_VERDICT;

typedef struct _BLACKSHARD_REPLY {
    BLACKSHARD_VERDICT Verdict;
} BLACKSHARD_REPLY, *PBLACKSHARD_REPLY;

typedef struct _BLACKSHARD_DATA {
    PFLT_FILTER FilterHandle;
    PFLT_PORT ServerPort;
    PFLT_PORT ClientPort;
    HANDLE ClientProcessId;
} BLACKSHARD_DATA, *PBLACKSHARD_DATA;

BLACKSHARD_DATA gBlackshardData;

#define BLACKSHARD_PORT_NAME L"\\BlackshardPort"

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
BlackshardUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
BlackshardPreCreate (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

NTSTATUS
BlackshardPortConnect (
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
    );

VOID
BlackshardPortDisconnect (
    _In_opt_ PVOID ConnectionCookie
    );

NTSTATUS
BlackshardPortMessage (
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength,*ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    );

#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, BlackshardUnload)
#pragma alloc_text(PAGE, BlackshardPreCreate)
#pragma alloc_text(PAGE, BlackshardPortConnect)
#pragma alloc_text(PAGE, BlackshardPortDisconnect)
#pragma alloc_text(PAGE, BlackshardPortMessage)

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

    { IRP_MJ_CREATE,
      0,
      BlackshardPreCreate,
      NULL },

    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    Callbacks,
    BlackshardUnload,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING uniString;

    UNREFERENCED_PARAMETER( RegistryPath );

    KdPrint(("Blackshard: DriverEntry - Loading Minifilter\n"));

    RtlZeroMemory(&gBlackshardData, sizeof(BLACKSHARD_DATA));

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gBlackshardData.FilterHandle );

    FLT_ASSERT( NT_SUCCESS( status ) );

    if (NT_SUCCESS( status )) {

        status = FltBuildDefaultSecurityDescriptor( &sd, FLT_PORT_ALL_ACCESS );

        if (NT_SUCCESS( status )) {

            RtlInitUnicodeString( &uniString, BLACKSHARD_PORT_NAME );

            InitializeObjectAttributes( &oa,
                                        &uniString,
                                        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                                        NULL,
                                        sd );

            status = FltCreateCommunicationPort( gBlackshardData.FilterHandle,
                                                 &gBlackshardData.ServerPort,
                                                 &oa,
                                                 NULL,
                                                 BlackshardPortConnect,
                                                 BlackshardPortDisconnect,
                                                 BlackshardPortMessage,
                                                 1 );

            FltFreeSecurityDescriptor( sd );

            if (NT_SUCCESS( status )) {

                status = FltStartFiltering( gBlackshardData.FilterHandle );

                if (NT_SUCCESS( status )) {
                    return STATUS_SUCCESS;
                }

                FltCloseCommunicationPort( gBlackshardData.ServerPort );
            }
        }

        FltUnregisterFilter( gBlackshardData.FilterHandle );
    }

    return status;
}

NTSTATUS
BlackshardUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    KdPrint(("Blackshard: BlackshardUnload - Unloading Minifilter\n"));

    if (gBlackshardData.ServerPort) {
        FltCloseCommunicationPort( gBlackshardData.ServerPort );
    }

    if (gBlackshardData.FilterHandle) {
        FltUnregisterFilter( gBlackshardData.FilterHandle );
    }

    return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS
BlackshardPreCreate (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    BLACKSHARD_NOTIFICATION notification;
    BLACKSHARD_REPLY reply;
    ULONG replyLength = sizeof(BLACKSHARD_REPLY);
    ULONG copyLength;
    ULONG requestorProcessId;
    UCHAR createDisposition;
    ACCESS_MASK desiredAccess;
    LARGE_INTEGER timeout;

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PAGED_CODE();

    if (Data->RequestorMode != UserMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    requestorProcessId = FltGetRequestorProcessId(Data);

    /*
     * The user-mode agent opens candidate files to inspect them. Sending those
     * opens back to the same agent would deadlock the single message consumer.
     */
    if (gBlackshardData.ClientProcessId != NULL &&
        requestorProcessId == HandleToULong(gBlackshardData.ClientProcessId)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    createDisposition = (UCHAR)(Data->Iopb->Parameters.Create.Options >> 24);
    if (createDisposition == FILE_CREATE ||
        createDisposition == FILE_SUPERSEDE ||
        createDisposition == FILE_OVERWRITE ||
        createDisposition == FILE_OVERWRITE_IF) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    if ((desiredAccess & (FILE_READ_DATA | FILE_EXECUTE | GENERIC_READ | GENERIC_EXECUTE)) == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetFileNameInformation( Data,
                                        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                                        &nameInfo );
    if (!NT_SUCCESS( status )) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltParseFileNameInformation( nameInfo );
    if (!NT_SUCCESS( status )) {
        FltReleaseFileNameInformation( nameInfo );
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (gBlackshardData.ClientPort != NULL) {

        RtlZeroMemory(&notification, sizeof(BLACKSHARD_NOTIFICATION));
        RtlZeroMemory(&reply, sizeof(BLACKSHARD_REPLY));

        notification.ProcessId = requestorProcessId;

        copyLength = nameInfo->Name.Length;
        if (copyLength >= (MAX_FILE_PATH_LENGTH * sizeof(WCHAR))) {
            copyLength = (MAX_FILE_PATH_LENGTH - 1) * sizeof(WCHAR);
        }
        RtlCopyMemory(notification.FilePath, nameInfo->Name.Buffer, copyLength);
        notification.FilePath[copyLength / sizeof(WCHAR)] = L'\0';

        /* Relative timeout: never hold a file open for more than three seconds. */
        timeout.QuadPart = -3LL * 10LL * 1000LL * 1000LL;

        status = FltSendMessage( gBlackshardData.FilterHandle,
                                 &gBlackshardData.ClientPort,
                                 &notification,
                                 sizeof(BLACKSHARD_NOTIFICATION),
                                 &reply,
                                 &replyLength,
                                 &timeout );

        if (status == STATUS_SUCCESS &&
            replyLength == sizeof(BLACKSHARD_REPLY) &&
            reply.Verdict == VERDICT_BLOCK) {
            
            KdPrint(("Blackshard: BLOCKED IRP_MJ_CREATE for PID %d, File: %ws\n", notification.ProcessId, notification.FilePath));

            FltReleaseFileNameInformation( nameInfo );

            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
    }

    FltReleaseFileNameInformation( nameInfo );
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

NTSTATUS
BlackshardPortConnect (
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
    )
{
    UNREFERENCED_PARAMETER( ServerPortCookie );
    UNREFERENCED_PARAMETER( ConnectionContext );
    UNREFERENCED_PARAMETER( SizeOfContext );
    UNREFERENCED_PARAMETER( ConnectionPortCookie );

    PAGED_CODE();

    KdPrint(("Blackshard: User-space daemon connected.\n"));

    gBlackshardData.ClientProcessId = PsGetCurrentProcessId();
    gBlackshardData.ClientPort = ClientPort;

    return STATUS_SUCCESS;
}

VOID
BlackshardPortDisconnect (
    _In_opt_ PVOID ConnectionCookie
    )
{
    UNREFERENCED_PARAMETER( ConnectionCookie );

    PAGED_CODE();

    KdPrint(("Blackshard: User-space daemon disconnected.\n"));

    FltCloseClientPort( gBlackshardData.FilterHandle, &gBlackshardData.ClientPort );
    gBlackshardData.ClientPort = NULL;
    gBlackshardData.ClientProcessId = NULL;
}

NTSTATUS
BlackshardPortMessage (
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength,*ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    UNREFERENCED_PARAMETER( PortCookie );
    UNREFERENCED_PARAMETER( InputBuffer );
    UNREFERENCED_PARAMETER( InputBufferLength );
    UNREFERENCED_PARAMETER( OutputBuffer );
    UNREFERENCED_PARAMETER( OutputBufferLength );

    PAGED_CODE();

    if (ReturnOutputBufferLength != NULL) {
        *ReturnOutputBufferLength = 0;
    }

    return STATUS_SUCCESS;
}
