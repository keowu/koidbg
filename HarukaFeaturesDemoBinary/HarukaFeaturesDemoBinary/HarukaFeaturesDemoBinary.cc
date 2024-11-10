/*
    File: HarukaFeaturesDemoBinary.cc
    Author: João Vitor(@Keowu)
    Created: 09/11/2024
    Last Update: 09/11/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#include <iostream>
#include <Windows.h>
#include <winternl.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

using pNtSetInformationProcess = NTSTATUS (NTAPI*)(

    HANDLE ProcessHandle,
    PROCESS_INFORMATION_CLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength

);

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION {

    ULONG Version;
    ULONG Reserved;
    PVOID Callback;

} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, *PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

auto WINAPI runThread(PVOID args) -> DWORD {

    printf("Inside a thread -> %d!!\n", GetCurrentThreadId());

    printf("Getting out a thread !!!");

    return 0;
}

EXTERN_C LPVOID KiUserExceptionDispatcher = { NULL };
EXTERN_C auto InstrumentationCallbackInternal(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT ContextRecord) -> VOID {

    std::printf("Caught Exception at : 0x%p\n", ExceptionRecord->ExceptionAddress);

    #if defined(_M_ARM64) || defined(__arm64__)
        ContextRecord->Pc++;
    #elif defined(_M_X64) || defined(__x86_64__)
        ContextRecord->Rip++;
    #endif

    RtlRestoreContext(ContextRecord, NULL);
}

auto WINAPI KewExceptionHandler(EXCEPTION_POINTERS* pExceptionInfo) -> NTSTATUS {

    std::printf("Oh, no Except by a SFT Interrupt!\n");

    return EXCEPTION_CONTINUE_EXECUTION;
}

auto configureNtCallbacks() -> int {

    auto hntdll = GetModuleHandleA("ntdll.dll");

    if (!hntdll) {

        std::printf("Failed to load ntdll.dll\n");

        return 0;
    }

    KiUserExceptionDispatcher = GetProcAddress(hntdll, "KiUserExceptionDispatcher");

    if (KiUserExceptionDispatcher == NULL) {

        std::printf("Failed to get KiUserExceptionDispatcher\n");

        return 0;
    }

    std::printf("KiUserExceptionDispatcher: %p\n", KiUserExceptionDispatcher);

    auto NtSetInformationProcess = reinterpret_cast<pNtSetInformationProcess>(GetProcAddress(hntdll, "NtSetInformationProcess"));

    if (!NtSetInformationProcess) {

        std::printf("Failed to get NtSetInformationProcess\n");

        return 0;
    }

    /*
    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION nirvana { 0 };
    nirvana.Callback = InstrumentationCallbackInternal;
    nirvana.Reserved = 0; // always 0
    nirvana.Version = 0;  // 0 for x64/ARM64, 1 for x86/ARM32

    if (!NT_SUCCESS(NtSetInformationProcess(
        reinterpret_cast<HANDLE>(-1),
        static_cast<PROCESS_INFORMATION_CLASS>(0x28),
        &nirvana,
        sizeof(nirvana)))) {

        std::printf("Failed to set instrumentation callback\n");

        return 0;
    }*/

    auto addressdemo = 0x1337134745121200;

    //This is to trigger the detection
    //The offset is the same for ARM64 and X64
    std::memcpy(reinterpret_cast<PVOID>(reinterpret_cast<uintptr_t>(NtCurrentTeb()) + 736), &addressdemo, sizeof(addressdemo));

    return 0;
}

auto DemoFunctionTableCallback(

    DWORD64 ControlPc,
    PVOID Context

) -> PRUNTIME_FUNCTION {

    // @Keowu: In a real implementation, locate and return the RUNTIME_FUNCTION for ControlPc
    // For demo purposes, returning a dummy RUNTIME_FUNCTION
    static RUNTIME_FUNCTION runtimeFunction = {};

    std::cout << "Callback triggered for ControlPc: " << std::hex << ControlPc << std::endl;

    return &runtimeFunction;
}

typedef struct _UNICODE_STR {

    USHORT Length;
    USHORT MaximumLength;
    PWSTR pBuffer;

} UNICODE_STR, * PUNICODE_STR;

typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {

    ULONG           Flags;
    PUNICODE_STR FullDllName;
    PUNICODE_STR BaseDllName;
    PVOID           DllBase;
    ULONG           SizeOfImage;

} LDR_DLL_LOADED_NOTIFICATION_DATA, * PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA {

    ULONG           Flags;
    PUNICODE_STR FullDllName;
    PUNICODE_STR BaseDllName;
    PVOID           DllBase;
    ULONG           SizeOfImage;

} LDR_DLL_UNLOADED_NOTIFICATION_DATA, * PLDR_DLL_UNLOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA {

    LDR_DLL_LOADED_NOTIFICATION_DATA   Loaded;
    LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;

} LDR_DLL_NOTIFICATION_DATA, * PLDR_DLL_NOTIFICATION_DATA;

using PLDR_DLL_NOTIFICATION_FUNCTION =  VOID(CALLBACK*)(

    ULONG                       NotificationReason,
    PLDR_DLL_NOTIFICATION_DATA  NotificationData,
    PVOID                       Context
    
);

typedef struct _LDR_DLL_NOTIFICATION_ENTRY {

    LIST_ENTRY                     List;
    PLDR_DLL_NOTIFICATION_FUNCTION Callback;
    PVOID                          Context;

} LDR_DLL_NOTIFICATION_ENTRY, *PLDR_DLL_NOTIFICATION_ENTRY;

#define LDR_DLL_NOTIFICATION_REASON_LOADED (1)
#define LDR_DLL_NOTIFICATION_REASON_UNLOADED (2)

auto CALLBACK DllNotificationCallback(
    
    ULONG NotificationReason,
    LDR_DLL_NOTIFICATION_DATA* NotificationData,
    PVOID Context

) -> VOID {

    switch (NotificationReason) {

        case LDR_DLL_NOTIFICATION_REASON_LOADED:
            //std::wcout << L"DLL Loaded: " << NotificationData->Loaded.FullDllName->Buffer << std::endl;
            break;
        case LDR_DLL_NOTIFICATION_REASON_UNLOADED:
            //std::wcout << L"DLL Unloaded: " << NotificationData->Unloaded.FullDllName->Buffer << std::endl;
            break;
        default:
            //std::wcout << L"Unknown DLL Notification" << std::endl;
            break;

    }
}

using tpdLdrRegisterDllNotification = NTSTATUS (NTAPI*)(

        IN ULONG Flags,
        IN PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction,
        IN PVOID Context,
        OUT PVOID* Cookie

);

#define NT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)

auto PsecureMemoryCacheCallback(

    PVOID Addr,
    SIZE_T Range

) -> BOOLEAN {

    return TRUE;
}

auto main() -> int {

    configureNtCallbacks();

    ::AddVectoredExceptionHandler(TRUE, reinterpret_cast<PVECTORED_EXCEPTION_HANDLER>(KewExceptionHandler));

    auto baseAddress = reinterpret_cast<DWORD64>(VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

    if (!baseAddress) {

        std::cerr << "Failed to allocate memory for BaseAddress." << std::endl;

        return 1;
    }
    DWORD length = { 0x1000 };

    DWORD64 tableIdentifier = baseAddress | 0x3;

    auto result = RtlInstallFunctionTableCallback(

        tableIdentifier,               // Table identifier with low-order bits set
        baseAddress,                   // Base address of the memory region
        length,                        // Length of the memory region
        DemoFunctionTableCallback,     // Callback function
        nullptr,                       // Context (optional; set to nullptr if unused)
        nullptr                        // Out-of-process DLL (set to nullptr for in-process)

    );

    if (!result) {

        std::cerr << "Failed to install function table callback." << std::endl;
        std::cerr << "Error code: " << GetLastError() << std::endl;

        VirtualFree(reinterpret_cast<LPVOID>(baseAddress), 0, MEM_RELEASE);

        return 1;
    }
    else {

        std::cout << "Function table callback installed successfully!" << std::endl;

    }

    std::printf("DemoFunctionTableCallback: %llx\n", DemoFunctionTableCallback);

    auto LdrRegisterDllNotification = reinterpret_cast<tpdLdrRegisterDllNotification>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrRegisterDllNotification"));

    PVOID cookit{ 0 };

    if (NT_SUCCESS(LdrRegisterDllNotification(0, DllNotificationCallback, nullptr, &cookit))) std::printf("DllNotificationCallback: %llx\n", DllNotificationCallback);

    if (AddSecureMemoryCacheCallback(PsecureMemoryCacheCallback)) std::printf("AddSecureMemoryCacheCallback: %llx\n", PsecureMemoryCacheCallback);

    std::printf("My TEB: %llx\n", NtCurrentTeb());

    std::cout << "Hello World!\n";

    std::printf("Inside: %d\n", GetCurrentThreadId());

    auto hThread = CreateThread(
        NULL,
        NULL,
        runThread,
        NULL,
        NULL,
        NULL
    );

    WaitForSingleObject(hThread, INFINITE);

    __debugbreak();

    if (RtlDeleteFunctionTable(reinterpret_cast<PRUNTIME_FUNCTION>(tableIdentifier))) {

        std::cout << "Function table callback deleted successfully!" << std::endl;

    }
    else {

        std::cerr << "Failed to delete function table callback." << std::endl;

    }

    VirtualFree(reinterpret_cast<LPVOID>(baseAddress), 0, MEM_RELEASE);

    std::cout << "Ohyooooo!\n";

    return 0;
}
