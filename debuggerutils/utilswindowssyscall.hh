/*
    File: utilswindowssycall.hh
    Authors: João Vitor(@Keowu)
    Created: 24/07/2024
    Last Update: 03/11/2024

    Copyright (c) 2024. https://github.com/maldeclabs/koidbg. All rights reserved.
*/
#ifndef UTILSWINDOWSSYSCALL_H
#define UTILSWINDOWSSYSCALL_H
#include <Windows.h>
#include <Winternl.h>
#include <dbghelp.h>
#include <psapi.h>
#include <tchar.h>
#include <strsafe.h>
#include <QMainWindow>
#include <QtCore/QString>
#include <QtCore/QDebug>
#include <debuggerutils/defs.hh>

#define ThreadBasicInformation 0

typedef LONG KPRIORITY;

typedef struct _THREAD_BASIC_INFORMATION {

    NTSTATUS ExitStatus;
    PTEB TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    KPRIORITY Priority;
    LONG BasePriority;

} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

using tpdNtQueryInformationThread = NTSTATUS (WINAPI *)(

    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength

);

/*
 * HANDLE TABLE DECLARATIONS
 */
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

typedef struct _SYSTEM_HANDLE {

    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;

} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {

    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];

} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE {

    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS

} POOL_TYPE, *PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION {

    UNICODE_STRING Name;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccess;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    USHORT MaintainTypeList;
    POOL_TYPE PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;

} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

using tpdNtDuplicateObject = NTSTATUS(NTAPI *)(

    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options

);

using tpdNtQuerySystemInformation = NTSTATUS(WINAPI*)(

    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength

);

using tpdNtQueryObject = NTSTATUS (NTAPI*)(

    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength

);

namespace UtilsWindowsSyscall {

inline auto GetThreadBasicInformation(HANDLE hThread) -> std::unique_ptr<THREAD_BASIC_INFORMATION> {

    std::unique_ptr<THREAD_BASIC_INFORMATION> tbi = std::make_unique<THREAD_BASIC_INFORMATION>();

    auto NtQueryInformationThread = reinterpret_cast<tpdNtQueryInformationThread>(GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQueryInformationThread"));

    NtQueryInformationThread(hThread, (THREADINFOCLASS)ThreadBasicInformation, tbi.get(), sizeof(THREAD_BASIC_INFORMATION), nullptr);

    return tbi;
}

inline auto GetFileNameFromHandle(HANDLE hFile) -> QString {
    QString fileName;
    TCHAR pszFilename[MAX_PATH + 1];
    HANDLE hFileMap;

    // Get the file size.
    DWORD dwFileSizeHi = 0;
    DWORD dwFileSizeLo = GetFileSize(hFile, &dwFileSizeHi);

    if (dwFileSizeLo == 0 && dwFileSizeHi == 0) {

        fileName = QString("Cannot map a file with a length of zero.");

        return fileName;
    }

    // Create a file mapping object.
    hFileMap = CreateFileMapping(hFile,
                                 NULL,
                                 PAGE_READONLY,
                                 0,
                                 1,
                                 NULL);

    if (hFileMap) {

        // Create a file mapping to get the file name.
        void* pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1);

        if (pMem) {

            if (GetMappedFileName(GetCurrentProcess(),
                                  pMem,
                                  pszFilename,
                                  MAX_PATH)) {

                // Translate path with device name to drive letters.
                TCHAR szTemp[MAX_PATH];
                szTemp[0] = '\0';

                if (GetLogicalDriveStrings(MAX_PATH - 1, szTemp)) {

                    TCHAR szName[MAX_PATH];
                    TCHAR szDrive[3] = TEXT(" :");
                    BOOL bFound = FALSE;
                    TCHAR* p = szTemp;

                    do {
                        // Copy the drive letter to the template string
                        *szDrive = *p;

                        // Look up each device name
                        if (QueryDosDevice(szDrive, szName, MAX_PATH)) {

                            size_t uNameLen = _tcslen(szName);

                            if (uNameLen < MAX_PATH) {

                                bFound = _tcsnicmp(pszFilename, szName, uNameLen) == 0
                                         && *(pszFilename + uNameLen) == L'\\';

                                if (bFound) {

                                    // Reconstruct pszFilename using szTempFile
                                    // Replace device path with DOS path
                                    TCHAR szTempFile[MAX_PATH];
                                    StringCchPrintf(szTempFile,
                                                    MAX_PATH,
                                                    TEXT("%s%s"),
                                                    szDrive,
                                                    pszFilename + uNameLen);
                                    StringCchCopyN(pszFilename, MAX_PATH + 1, szTempFile, _tcslen(szTempFile));
                                }
                            }
                        }

                        // Go to the next NULL character.
                        while (*p++);
                    } while (!bFound && *p); // end of string
                }
            }
            fileName = QString::fromWCharArray(pszFilename);
            UnmapViewOfFile(pMem);
        }

        CloseHandle(hFileMap);
    }

    return fileName;
}

inline auto symbol_from_address(const HANDLE hProcess, const uintptr_t uipPC) -> QString {

    SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
    if (!SymInitialize(hProcess, NULL, TRUE)) {
        //printf("SymInitialize failed: %d\n", GetLastError());
    }

    SYMBOL_INFO *symbol = reinterpret_cast<SYMBOL_INFO *>(calloc(sizeof(SYMBOL_INFO) + 256, 1));
    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol->MaxNameLen = 255;

    QString result = "";
    DWORD64 displacement = 0;
    if (SymFromAddr(hProcess, uipPC, &displacement, symbol)) {
        //printf("Symbol Name: %s\n", symbol->Name);
        //printf("Address: 0x%llX\n", symbol->Address);
        //printf("Displacement: 0x%llX\n", displacement);
        result = QString::asprintf(" %s!0x%llX", symbol->Name, displacement);

    }

    free(symbol);
    SymCleanup(hProcess);

    return result;
}

inline auto updateCallStackContext(const HANDLE hProcess, const HANDLE hThread, const uintptr_t regPC, const uintptr_t regFrame, const uintptr_t regStack, PVOID context, const DWORD machineType) -> std::pair<QVector<void*>, QVector<QString>> {

    QVector<void*> stack;
    QVector<QString> symbols;

    if (context == nullptr) {
        // qDebug() << "Invalid context pointer.";
        return std::make_pair(stack, symbols);
    }

    if (!SymInitialize(hProcess, nullptr, TRUE)) {
        // qDebug() << "SymInitialize failed. Error: " << GetLastError();
        return std::make_pair(stack, symbols);
    }

    STACKFRAME64 stackFrame;
    memset(&stackFrame, 0, sizeof(stackFrame));

    stackFrame.AddrPC.Offset = regPC;
    stackFrame.AddrPC.Mode = AddrModeFlat;

    stackFrame.AddrFrame.Offset = regFrame;
    stackFrame.AddrFrame.Mode = AddrModeFlat;

    stackFrame.AddrStack.Offset = regStack;
    stackFrame.AddrStack.Mode = AddrModeFlat;

    auto GetSymbolName = [hProcess](DWORD64 address) -> QString {
        // Allocate memory for SYMBOL_INFO
        SYMBOL_INFO* symbol = (SYMBOL_INFO*)malloc(sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR));
        if (!symbol) {
            return QString("Memory allocation failed");
        }
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        symbol->MaxNameLen = MAX_SYM_NAME;

        QString symbolName;
        if (SymFromAddr(hProcess, address, nullptr, symbol)) {
            symbolName = QString::asprintf("%s", symbol->Name);
        } else {
            //DWORD error = GetLastError();
            symbolName = QString("Unknown Symbol");
        }

        free(symbol);
        return symbolName;
    };

    while (StackWalk64(
        machineType,
        hProcess,
        hThread,
        &stackFrame,
        context,
        nullptr,
        nullptr,
        nullptr,
        nullptr
        )) {

        if (stackFrame.AddrPC.Offset == 0) break;

        stack.push_back(reinterpret_cast<void*>(stackFrame.AddrPC.Offset));

        symbols.push_back(GetSymbolName(stackFrame.AddrPC.Offset));
    }

    /*DWORD error = GetLastError();

    if (error != NO_ERROR) {
        qDebug() << "StackWalk64 failed with error code: " << error;
    }*/
    SymCleanup(hProcess);
    return std::make_pair(stack, symbols);
}


inline auto GetDebuggerProcessHandleTable(const DWORD dwProcessPid) -> std::vector<SYSTEM_HANDLE> {

    /*
     * Good Article:
     *      https://cplusplus.com/forum/windows/95774/#msg515345
     *      https://codeproject.com/Articles/18975/Listing-Used-Files
    */
    std::vector<SYSTEM_HANDLE> vecHandles{ };

    auto NtQuerySystemInformation = reinterpret_cast<tpdNtQuerySystemInformation>(GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQuerySystemInformation"));

    ULONG handleInfoSize{ 0x10000 };

    auto handleInfo = new SYSTEM_HANDLE_INFORMATION[handleInfoSize];

    while ((NtQuerySystemInformation(

                SystemHandleInformation,
                handleInfo,
                handleInfoSize,
                NULL

    )) == STATUS_INFO_LENGTH_MISMATCH) {

        delete[] handleInfo;

        handleInfo = new SYSTEM_HANDLE_INFORMATION[handleInfoSize *= 2];

    }

    for (ULONG i = 0; i < handleInfo->HandleCount; i++) {

        auto handle = handleInfo->Handles[i];

        if (handle.ProcessId == dwProcessPid) vecHandles.push_back(handle);

    }

    delete[] handleInfo;

    return vecHandles;
}

inline auto GetRemoteHandleTableHandleInformation(const DWORD dwDebugProcPid, const SYSTEM_HANDLE hHandle) -> std::tuple<HANDLE, size_t, std::wstring, size_t, std::wstring> {

    /*
     * Good Article:
     *      https://cplusplus.com/forum/windows/95774/#msg515345
     *      https://codeproject.com/Articles/18975/Listing-Used-Files
    */
    auto ZwDuplicateObject = reinterpret_cast<tpdNtDuplicateObject>(GetProcAddress(LoadLibraryA("ntdll.dll"), "NtDuplicateObject"));
    auto ZwQueryObject = reinterpret_cast<tpdNtQueryObject>(GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQueryObject"));

    HANDLE dupHandle{ NULL };

    auto processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, dwDebugProcPid);

    if (!NT_SUCCESS(ZwDuplicateObject(
            processHandle,
            reinterpret_cast<HANDLE>(hHandle.Handle),
            GetCurrentProcess(),
            &dupHandle,
            0,
            0,
            0
            ))) {

            CloseHandle(dupHandle);

            return std::make_tuple(

            reinterpret_cast<HANDLE>(-1),
            static_cast<size_t>(-1),
            L"",
            static_cast<size_t>(-1),
            L""

        );
    }

    auto objectTypeInfo = new OBJECT_TYPE_INFORMATION[0x1000];

    if (!NT_SUCCESS(ZwQueryObject(

            dupHandle,
            static_cast<OBJECT_INFORMATION_CLASS>(ObjectTypeInformation),
            objectTypeInfo,
            0x1000,
            NULL

        ))) {

        CloseHandle(dupHandle);

        return std::make_tuple(

            reinterpret_cast<HANDLE>(-1),
            static_cast<size_t>(-1),
            L"",
            static_cast<size_t>(-1),
            L""

        );
    }

    /* Query the object name (unless it has an access of
           0x0012019f, on which NtQueryObject could hang. */
    if (hHandle.GrantedAccess == 0x0012019f) {

        //delete[] objectTypeInfo;

        CloseHandle(dupHandle);

        return std::make_tuple(

            reinterpret_cast<HANDLE>(hHandle.Handle),
            static_cast<size_t>(objectTypeInfo->Name.Length / 2),
            objectTypeInfo->Name.Buffer,
            static_cast<size_t>(-1),
            L""

        );
    }

    ULONG returnLength{ 0 };

    auto objectNameInfo = new unsigned char [0x1000];

    if (!NT_SUCCESS(ZwQueryObject(

            dupHandle,
            (OBJECT_INFORMATION_CLASS)ObjectNameInformation,
            objectNameInfo,
            0x1000,
            &returnLength

        ))) {

        delete[] objectNameInfo;

        objectNameInfo = new unsigned char [returnLength];

        if (!NT_SUCCESS(ZwQueryObject(
                dupHandle,
                (OBJECT_INFORMATION_CLASS)ObjectNameInformation,
                objectNameInfo,
                returnLength,
                NULL
                ))) {

            //delete[] objectTypeInfo;
            //delete[] objectNameInfo;

            CloseHandle(dupHandle);

            return std::make_tuple(

                reinterpret_cast<HANDLE>(hHandle.Handle),
                static_cast<size_t>(objectTypeInfo->Name.Length / 2),
                objectTypeInfo->Name.Buffer,
                static_cast<size_t>(-1),
                L""

            );
        }

    }

    auto objectName = *reinterpret_cast<PUNICODE_STRING>(objectNameInfo);

    if (objectName.Length) {

        CloseHandle(dupHandle);

        return std::make_tuple(

            reinterpret_cast<HANDLE>(hHandle.Handle),
            static_cast<size_t>(objectTypeInfo->Name.Length / 2),
            objectTypeInfo->Name.Buffer,
            static_cast<size_t>(objectName.Length / 2),
            objectName.Buffer

        );

    } else {

        CloseHandle(dupHandle);

        return std::make_tuple(

            reinterpret_cast<HANDLE>(hHandle.Handle),
            static_cast<size_t>(objectTypeInfo->Name.Length / 2),
            objectTypeInfo->Name.Buffer,
            static_cast<size_t>(-1),
            L""

        );
    }

    delete[] objectTypeInfo;
    delete[] objectNameInfo;

    CloseHandle(dupHandle);

    return std::make_tuple(

        reinterpret_cast<HANDLE>(-1),
        static_cast<size_t>(-1),
        L"",
        static_cast<size_t>(-1),
        L""

    );
}

inline auto getErrorMessage(DWORD errorCode) -> QString {

    LPVOID msgBuffer;

    FormatMessage(

        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&msgBuffer),
        0,
        NULL

    );

    QString errorMessage = QString::fromWCharArray(

        reinterpret_cast<wchar_t*>(msgBuffer)

    );

    LocalFree(msgBuffer);

    return errorMessage;
}

/*
 * Feature to extract VEH HANDLERS(Working for both: ARM64 and X64)
 *
 *
 * The following content was readed in order to write this code:
 *
 *      https://dimitrifourny.github.io/2020/06/11/dumping-veh-win10.html
 *      https://gist.github.com/olliencc/9f4bb9535c4f0ef0e54eac7912ab49c0
 *      https://research.nccgroup.com/2022/03/01/detecting-anomalous-vectored-exception-handlers-on-windows/
 *      https://bruteratel.com/research/2024/10/20/Exception-Junction/
 *
 * The Following Struct Definition was take in order to parse the fields on x64(found using this nice tool -> https://grep.app/search?q=_VECTORED_HANDLER_LIST):
 *      https://github.com/mannyfred/SentinelBruh/blob/main/SentinelBruh/SentinelBruh/header.h#L31C1-L36C43
*/
typedef struct _VEH_HANDLER_ENTRY {
    LIST_ENTRY					Entry;
    PVOID						SyncRefs;
    PVOID						Idk;
    PVOID						VectoredHandler;
} VEH_HANDLER_ENTRY, * PVEH_HANDLER_ENTRY;

typedef struct _VECTORED_HANDLER_LIST {
    PVOID              MutexException;
    VEH_HANDLER_ENTRY* FirstExceptionHandler;
    VEH_HANDLER_ENTRY* LastExceptionHandler;
    PVOID              MutexContinue;
    VEH_HANDLER_ENTRY* FirstContinueHandler;
    VEH_HANDLER_ENTRY* LastContinueHandler;
} VECTORED_HANDLER_LIST, * PVECTORED_HANDLER_LIST;

    namespace VEHList {

        #define ProcessCookie 36

        typedef NTSTATUS (NTAPI *tpdNtQueryInformationProcess)(
            HANDLE ProcessHandle,
            PROCESSINFOCLASS ProcessInformationClass,
            PVOID ProcessInformation,
            ULONG ProcessInformationLength,
            PULONG ReturnLength OPTIONAL
        );

        //Stoolen from ntdll.dll
        inline auto NtDllRtlDecodePointer(HANDLE hProcess) -> DWORD {

            DWORD processCookie { 0 };

            auto ZwNtQueryInformationProcess = reinterpret_cast<tpdNtQueryInformationProcess>(GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQueryInformationProcess"));

            auto status = ZwNtQueryInformationProcess(hProcess, (PROCESSINFOCLASS)ProcessCookie, &processCookie, 4u, 0LL);

            if (status < 0) qDebug() << "Fail getting ProcessCookie :(";

            return processCookie;
        }

        inline auto DecodePointer(HANDLE hProcess, uintptr_t handler) -> uintptr_t {

            auto cookie = NtDllRtlDecodePointer(hProcess);

            //qDebug() << "Cookie: " << QString::number(cookie, 16);

            return __ROR8__(handler, 0x40 - (cookie & 0x3F)) ^ cookie;
        }

        inline auto GetVehList(HANDLE hProcess, uintptr_t pLdrpVectorHandlerList) -> std::vector<std::pair<uintptr_t, uintptr_t>> {

            std::vector<std::pair<uintptr_t, uintptr_t>> vecVehHandlers;

            //qDebug() << "VEHList::GetVehList::pLdrpVectorHandlerList: " << QString::number(pLdrpVectorHandlerList, 16);

            VECTORED_HANDLER_LIST vehList;

            ReadProcessMemory(hProcess, reinterpret_cast<PVOID>(pLdrpVectorHandlerList), &vehList, sizeof(vehList), NULL);

            //qDebug() << "VEHList::GetVehList::vehList first: " << QString::number(reinterpret_cast<uintptr_t>(vehList.FirstExceptionHandler), 16);
            //qDebug() << "VEHList::GetVehList::vehList last: " << QString::number(reinterpret_cast<uintptr_t>(vehList.LastExceptionHandler), 16);

            if (reinterpret_cast<uintptr_t>(vehList.FirstExceptionHandler) == pLdrpVectorHandlerList + sizeof(uintptr_t)) {

                //qDebug() << "VEH List vazia!";

                vecVehHandlers.push_back(std::make_pair(-1, -1));

                return vecVehHandlers;
            }

            VEH_HANDLER_ENTRY entry;

            ReadProcessMemory(hProcess, reinterpret_cast<PVOID>(vehList.FirstExceptionHandler), &entry, sizeof(entry), NULL);

            while (true) {

                auto handler = reinterpret_cast<uintptr_t>(entry.VectoredHandler);

                vecVehHandlers.push_back(std::make_pair(handler, VEHList::DecodePointer(hProcess, handler)));

                if (reinterpret_cast<uintptr_t>(entry.Entry.Flink) == pLdrpVectorHandlerList + sizeof(uintptr_t)) break;

                ReadProcessMemory(hProcess, reinterpret_cast<PVOID>(entry.Entry.Flink), &entry, sizeof(entry), NULL);

            }

            return vecVehHandlers;
        }

    };

    namespace NtAndProcessCallbacks {

        typedef NTSTATUS (NTAPI* tpdNtQueryInformationThread)(
            HANDLE          ThreadHandle,
            THREADINFOCLASS ThreadInformationClass,
            PVOID           ThreadInformation,
            ULONG           ThreadInformationLength,
            PULONG          ReturnLength
            );

        inline auto detectNirvanaCallback(HANDLE hProcess, HANDLE hThread, std::initializer_list<uintptr_t> offsets) -> bool {

            auto ZwNtQueryInformationThread = reinterpret_cast<tpdNtQueryInformationThread>(GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQueryInformationThread"));

            THREAD_BASIC_INFORMATION tbi{ 0 };

            ZwNtQueryInformationThread(hThread, (THREADINFOCLASS)(0), &tbi, sizeof(tbi), NULL);

            //qDebug() << "TEB: " << QString::number(reinterpret_cast<uintptr_t>(tbi.TebBaseAddress), 16);

            auto isDetected = 0;

            for (auto& offset : offsets) {

                auto addressToRead = reinterpret_cast<uintptr_t>(tbi.TebBaseAddress) + offset;

                DWORD64 dw64Value{ 0 };

                if (ReadProcessMemory(hProcess, reinterpret_cast<PVOID>(addressToRead), &dw64Value, sizeof(dw64Value), NULL)) {
                    //qDebug() << "Value at offset " << offset << ": " << QString::number(dw64Value, 16);
                    isDetected = isDetected || dw64Value;
                } /*else {
                    qDebug() << "Failed to read memory at offset " << offset;
                }*/
            }

            //qDebug() << "IsDetected: " << isDetected;

            return isDetected;
        }

    };

    enum _FUNCTION_TABLE_TYPE
    {
        RF_SORTED = 0,
        RF_UNSORTED = 1,
        RF_CALLBACK = 2,
        RF_KERNEL_DYNAMIC = 3
    };


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
                UCHAR Red:1;                                                    //0x10
                UCHAR Balance:2;                                                //0x10
            };
            ULONGLONG ParentValue;                                              //0x10
        };
    };

    //0x88 bytes (sizeof)
    typedef struct _DYNAMIC_FUNCTION_TABLE
    {
        struct _LIST_ENTRY ListEntry;                                           //0x0
        struct _IMAGE_RUNTIME_FUNCTION_ENTRY* FunctionTable;                    //0x10
        union _LARGE_INTEGER TimeStamp;                                         //0x18
        ULONGLONG MinimumAddress;                                               //0x20
        ULONGLONG MaximumAddress;                                               //0x28
        ULONGLONG BaseAddress;                                                  //0x30
        struct _IMAGE_RUNTIME_FUNCTION_ENTRY* (*Callback)(ULONGLONG arg1, VOID* arg2); //0x38
        VOID* Context;                                                          //0x40
        WCHAR* OutOfProcessCallbackDll;                                         //0x48
        enum _FUNCTION_TABLE_TYPE Type;                                         //0x50
        ULONG EntryCount;                                                       //0x54
        struct _RTL_BALANCED_NODE TreeNodeMin;                                  //0x58
        struct _RTL_BALANCED_NODE TreeNodeMax;                                  //0x70
    } DYNAMIC_FUNCTION_TABLE, *PDYNAMIC_FUNCTION_TABLE;


    namespace DynamicFunctionTableList {

        /*
         * Base on https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlinstallfunctiontablecallback
         * and
         * (2. Dynamic Function Table List) of https://modexp.wordpress.com/2020/08/06/windows-data-structures-and-callbacks-part-1/#ftl
         */
        inline auto GetDynFunctTableList(HANDLE hProcess, uintptr_t RtlpDynamicFunctionTable) -> std::vector<uintptr_t>{

            std::vector<uintptr_t> vecDynamicFunct;

            DYNAMIC_FUNCTION_TABLE dynTable;

            ReadProcessMemory(hProcess, reinterpret_cast<PVOID>(RtlpDynamicFunctionTable), &dynTable, sizeof(dynTable), NULL);

            if (reinterpret_cast<uintptr_t>(dynTable.ListEntry.Flink) == RtlpDynamicFunctionTable) {

                qDebug() << "RtlpDynamicFunctionTable Vazia";

                vecDynamicFunct.push_back(-1);

                return vecDynamicFunct;
            }

            ReadProcessMemory(hProcess, reinterpret_cast<PVOID>(dynTable.ListEntry.Flink), &dynTable, sizeof(dynTable), NULL);

            while (true) {

                /*qDebug() << "Callback: " << QString::number(reinterpret_cast<uintptr_t>(dynTable.Callback), 16);
                qDebug() << "FunctionTable: " << QString::number(reinterpret_cast<uintptr_t>(dynTable.FunctionTable), 16);
                qDebug() << "BaseAddress: " << QString::number(dynTable.BaseAddress, 16);
                qDebug() << "Next: " << dynTable.ListEntry.Flink;*/

                vecDynamicFunct.push_back(reinterpret_cast<uintptr_t>(dynTable.Callback));

                if (reinterpret_cast<uintptr_t>(dynTable.ListEntry.Flink) == RtlpDynamicFunctionTable) break;

                ReadProcessMemory(hProcess, reinterpret_cast<PVOID>(dynTable.ListEntry.Flink), &dynTable, sizeof(dynTable), NULL);

            }

            return vecDynamicFunct;
        }

    };

    namespace DLLNotificationsList {

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

        typedef VOID(CALLBACK* PLDR_DLL_NOTIFICATION_FUNCTION)(
            ULONG                       NotificationReason,
            PLDR_DLL_NOTIFICATION_DATA  NotificationData,
            PVOID                       Context);


        typedef struct _LDR_DLL_NOTIFICATION_ENTRY {
            LIST_ENTRY                     List;
            PLDR_DLL_NOTIFICATION_FUNCTION Callback;
            PVOID                          Context;
        } LDR_DLL_NOTIFICATION_ENTRY, * PLDR_DLL_NOTIFICATION_ENTRY;

        /*
        *  Base on https://learn.microsoft.com/en-us/windows/win32/devnotes/ldrregisterdllnotification, https://github.com/m417z/LdrDllNotificationHook
        *  and
        *  (4. DLL Notifications) of https://modexp.wordpress.com/2020/08/06/windows-data-structures-and-callbacks-part-1/#ftl
        */
        inline auto GetDllNotificationList(HANDLE hProcess, uintptr_t ldrpDllNotificationList) -> std::vector<uintptr_t> {

            std::vector<uintptr_t> vecDllNotificationListFunc;

            LDR_DLL_NOTIFICATION_ENTRY dllNotificationList;

            ReadProcessMemory(hProcess, reinterpret_cast<PVOID>(ldrpDllNotificationList), &dllNotificationList, sizeof(dllNotificationList), NULL);

            if (reinterpret_cast<uintptr_t>(dllNotificationList.List.Flink) == ldrpDllNotificationList) {

                qDebug() << "LdrpDllNotificationList Vazia";

                vecDllNotificationListFunc.push_back(-1);

                return vecDllNotificationListFunc;
            }

            ReadProcessMemory(hProcess, reinterpret_cast<PVOID>(dllNotificationList.List.Flink), &dllNotificationList, sizeof(dllNotificationList), NULL);

            while (true) {

                /*qDebug() << "Callback: " <<  QString::number(reinterpret_cast<uintptr_t>(dllNotificationList.Callback), 16);
                qDebug() << "Flink: " <<  QString::number(reinterpret_cast<uintptr_t>(dllNotificationList.List.Flink), 16);*/

                vecDllNotificationListFunc.push_back(reinterpret_cast<uintptr_t>(dllNotificationList.Callback));

                if (reinterpret_cast<uintptr_t>(dllNotificationList.List.Flink) == ldrpDllNotificationList) break;

                ReadProcessMemory(hProcess, reinterpret_cast<PVOID>(dllNotificationList.List.Flink), &dllNotificationList, sizeof(dllNotificationList), NULL);

            }

            return vecDllNotificationListFunc;
        }

    };

    namespace SecMemListHead {

        typedef BOOLEAN (CALLBACK *PSECURE_MEMORY_CACHE_CALLBACK)(PVOID, SIZE_T);

        typedef struct _RTL_SEC_MEM_ENTRY {
            LIST_ENTRY                    List;
            ULONG                         Revision;
            ULONG                         Reserved;
            PSECURE_MEMORY_CACHE_CALLBACK Callback;
        } RTL_SEC_MEM_ENTRY, *PRTL_SEC_MEM_ENTRY;

        /*
         *  Based on https://learn.microsoft.com/en-us/windows/win32/api/winnt/nc-winnt-psecure_memory_cache_callback,https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-addsecurememorycachecallback
         *  and
         *  (5. Secure Memory) of https://modexp.wordpress.com/2020/08/06/windows-data-structures-and-callbacks-part-1/#ftl
         */
        inline auto GetSecMemListHead(HANDLE hProcess, uintptr_t rtlpSecMemListHead) -> std::vector<uintptr_t> {

            std::vector<uintptr_t> vecSecMemListFunc;

            RTL_SEC_MEM_ENTRY memEntry;

            ReadProcessMemory(hProcess, reinterpret_cast<PVOID>(rtlpSecMemListHead), &memEntry, sizeof(memEntry), NULL);

            if (reinterpret_cast<uintptr_t>(memEntry.List.Flink) == rtlpSecMemListHead) {

                qDebug() << "LdrpDllNotificationList Vazia";

                vecSecMemListFunc.push_back(-1);

                return vecSecMemListFunc;
            }

            ReadProcessMemory(hProcess, reinterpret_cast<PVOID>(memEntry.List.Flink), &memEntry, sizeof(memEntry), NULL);

            while (true) {

                /*qDebug() << "Callback: " <<  QString::number(reinterpret_cast<uintptr_t>(memEntry.Callback), 16);
                qDebug() << "Flink: " <<  QString::number(reinterpret_cast<uintptr_t>(memEntry.List.Flink), 16);*/

                vecSecMemListFunc.push_back(reinterpret_cast<uintptr_t>(memEntry.Callback));

                if (reinterpret_cast<uintptr_t>(memEntry.List.Flink) == rtlpSecMemListHead) break;

                ReadProcessMemory(hProcess, reinterpret_cast<PVOID>(memEntry.List.Flink), &memEntry, sizeof(memEntry), NULL);

            }

            return vecSecMemListFunc;
        }

    };

    namespace KernelKCT {

        typedef struct _KERNELCALLBACKTABLE_T {
            ULONG_PTR __fnCOPYDATA;
            ULONG_PTR __fnCOPYGLOBALDATA;
            ULONG_PTR __fnDWORD;
            ULONG_PTR __fnNCDESTROY;
            ULONG_PTR __fnDWORDOPTINLPMSG;
            ULONG_PTR __fnINOUTDRAG;
            ULONG_PTR __fnGETTEXTLENGTHS;
            ULONG_PTR __fnINCNTOUTSTRING;
            ULONG_PTR __fnPOUTLPINT;
            ULONG_PTR __fnINLPCOMPAREITEMSTRUCT;
            ULONG_PTR __fnINLPCREATESTRUCT;
            ULONG_PTR __fnINLPDELETEITEMSTRUCT;
            ULONG_PTR __fnINLPDRAWITEMSTRUCT;
            ULONG_PTR __fnPOPTINLPUINT;
            ULONG_PTR __fnPOPTINLPUINT2;
            ULONG_PTR __fnINLPMDICREATESTRUCT;
            ULONG_PTR __fnINOUTLPMEASUREITEMSTRUCT;
            ULONG_PTR __fnINLPWINDOWPOS;
            ULONG_PTR __fnINOUTLPPOINT5;
            ULONG_PTR __fnINOUTLPSCROLLINFO;
            ULONG_PTR __fnINOUTLPRECT;
            ULONG_PTR __fnINOUTNCCALCSIZE;
            ULONG_PTR __fnINOUTLPPOINT5_;
            ULONG_PTR __fnINPAINTCLIPBRD;
            ULONG_PTR __fnINSIZECLIPBRD;
            ULONG_PTR __fnINDESTROYCLIPBRD;
            ULONG_PTR __fnINSTRING;
            ULONG_PTR __fnINSTRINGNULL;
            ULONG_PTR __fnINDEVICECHANGE;
            ULONG_PTR __fnPOWERBROADCAST;
            ULONG_PTR __fnINLPUAHDRAWMENU;
            ULONG_PTR __fnOPTOUTLPDWORDOPTOUTLPDWORD;
            ULONG_PTR __fnOPTOUTLPDWORDOPTOUTLPDWORD_;
            ULONG_PTR __fnOUTDWORDINDWORD;
            ULONG_PTR __fnOUTLPRECT;
            ULONG_PTR __fnOUTSTRING;
            ULONG_PTR __fnPOPTINLPUINT3;
            ULONG_PTR __fnPOUTLPINT2;
            ULONG_PTR __fnSENTDDEMSG;
            ULONG_PTR __fnINOUTSTYLECHANGE;
            ULONG_PTR __fnHkINDWORD;
            ULONG_PTR __fnHkINLPCBTACTIVATESTRUCT;
            ULONG_PTR __fnHkINLPCBTCREATESTRUCT;
            ULONG_PTR __fnHkINLPDEBUGHOOKSTRUCT;
            ULONG_PTR __fnHkINLPMOUSEHOOKSTRUCTEX;
            ULONG_PTR __fnHkINLPKBDLLHOOKSTRUCT;
            ULONG_PTR __fnHkINLPMSLLHOOKSTRUCT;
            ULONG_PTR __fnHkINLPMSG;
            ULONG_PTR __fnHkINLPRECT;
            ULONG_PTR __fnHkOPTINLPEVENTMSG;
            ULONG_PTR __xxxClientCallDelegateThread;
            ULONG_PTR __ClientCallDummyCallback;
            ULONG_PTR __fnKEYBOARDCORRECTIONCALLOUT;
            ULONG_PTR __fnOUTLPCOMBOBOXINFO;
            ULONG_PTR __fnINLPCOMPAREITEMSTRUCT2;
            ULONG_PTR __xxxClientCallDevCallbackCapture;
            ULONG_PTR __xxxClientCallDitThread;
            ULONG_PTR __xxxClientEnableMMCSS;
            ULONG_PTR __xxxClientUpdateDpi;
            ULONG_PTR __xxxClientExpandStringW;
            ULONG_PTR __ClientCopyDDEIn1;
            ULONG_PTR __ClientCopyDDEIn2;
            ULONG_PTR __ClientCopyDDEOut1;
            ULONG_PTR __ClientCopyDDEOut2;
            ULONG_PTR __ClientCopyImage;
            ULONG_PTR __ClientEventCallback;
            ULONG_PTR __ClientFindMnemChar;
            ULONG_PTR __ClientFreeDDEHandle;
            ULONG_PTR __ClientFreeLibrary;
            ULONG_PTR __ClientGetCharsetInfo;
            ULONG_PTR __ClientGetDDEFlags;
            ULONG_PTR __ClientGetDDEHookData;
            ULONG_PTR __ClientGetListboxString;
            ULONG_PTR __ClientGetMessageMPH;
            ULONG_PTR __ClientLoadImage;
            ULONG_PTR __ClientLoadLibrary;
            ULONG_PTR __ClientLoadMenu;
            ULONG_PTR __ClientLoadLocalT1Fonts;
            ULONG_PTR __ClientPSMTextOut;
            ULONG_PTR __ClientLpkDrawTextEx;
            ULONG_PTR __ClientExtTextOutW;
            ULONG_PTR __ClientGetTextExtentPointW;
            ULONG_PTR __ClientCharToWchar;
            ULONG_PTR __ClientAddFontResourceW;
            ULONG_PTR __ClientThreadSetup;
            ULONG_PTR __ClientDeliverUserApc;
            ULONG_PTR __ClientNoMemoryPopup;
            ULONG_PTR __ClientMonitorEnumProc;
            ULONG_PTR __ClientCallWinEventProc;
            ULONG_PTR __ClientWaitMessageExMPH;
            ULONG_PTR __ClientWOWGetProcModule;
            ULONG_PTR __ClientWOWTask16SchedNotify;
            ULONG_PTR __ClientImmLoadLayout;
            ULONG_PTR __ClientImmProcessKey;
            ULONG_PTR __fnIMECONTROL;
            ULONG_PTR __fnINWPARAMDBCSCHAR;
            ULONG_PTR __fnGETTEXTLENGTHS2;
            ULONG_PTR __fnINLPKDRAWSWITCHWND;
            ULONG_PTR __ClientLoadStringW;
            ULONG_PTR __ClientLoadOLE;
            ULONG_PTR __ClientRegisterDragDrop;
            ULONG_PTR __ClientRevokeDragDrop;
            ULONG_PTR __fnINOUTMENUGETOBJECT;
            ULONG_PTR __ClientPrinterThunk;
            ULONG_PTR __fnOUTLPCOMBOBOXINFO2;
            ULONG_PTR __fnOUTLPSCROLLBARINFO;
            ULONG_PTR __fnINLPUAHDRAWMENU2;
            ULONG_PTR __fnINLPUAHDRAWMENUITEM;
            ULONG_PTR __fnINLPUAHDRAWMENU3;
            ULONG_PTR __fnINOUTLPUAHMEASUREMENUITEM;
            ULONG_PTR __fnINLPUAHDRAWMENU4;
            ULONG_PTR __fnOUTLPTITLEBARINFOEX;
            ULONG_PTR __fnTOUCH;
            ULONG_PTR __fnGESTURE;
            ULONG_PTR __fnPOPTINLPUINT4;
            ULONG_PTR __fnPOPTINLPUINT5;
            ULONG_PTR __xxxClientCallDefaultInputHandler;
            ULONG_PTR __fnEMPTY;
            ULONG_PTR __ClientRimDevCallback;
            ULONG_PTR __xxxClientCallMinTouchHitTestingCallback;
            ULONG_PTR __ClientCallLocalMouseHooks;
            ULONG_PTR __xxxClientBroadcastThemeChange;
            ULONG_PTR __xxxClientCallDevCallbackSimple;
            ULONG_PTR __xxxClientAllocWindowClassExtraBytes;
            ULONG_PTR __xxxClientFreeWindowClassExtraBytes;
            ULONG_PTR __fnGETWINDOWDATA;
            ULONG_PTR __fnINOUTSTYLECHANGE2;
            ULONG_PTR __fnHkINLPMOUSEHOOKSTRUCTEX2;
        } KERNELCALLBACKTABLE;

        typedef NTSTATUS (NTAPI *tpdNtQueryInformationProcess)(
            HANDLE ProcessHandle,
            PROCESSINFOCLASS ProcessInformationClass,
            PVOID ProcessInformation,
            ULONG ProcessInformationLength,
            PULONG ReturnLength OPTIONAL
        );

        inline auto GetKctTable(HANDLE hProc, uintptr_t pebAndKernelCallbackTable) -> std::vector<std::pair<uintptr_t, QString>> {

            std::vector<std::pair<uintptr_t, QString>> vecAddress;

            KERNELCALLBACKTABLE kct;

            PROCESS_BASIC_INFORMATION pbi;

            auto ZwNtQueryInformationProcess = reinterpret_cast<tpdNtQueryInformationProcess>(GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQueryInformationProcess"));

            auto status = ZwNtQueryInformationProcess(hProc, ProcessBasicInformation, &pbi, sizeof(pbi), 0LL);

            if (status < 0) qDebug() << "Fail getting PEB :(";

            ReadProcessMemory(hProc, reinterpret_cast<PVOID>(reinterpret_cast<uintptr_t>(pbi.PebBaseAddress) + pebAndKernelCallbackTable), &kct, sizeof(kct), NULL);

            const struct {
                const char* name;
                ULONG_PTR value;
            } fields[] = {
                {"COPYDATA", kct.__fnCOPYDATA},
                {"COPYGLOBALDATA", kct.__fnCOPYGLOBALDATA},
                {"KCTDWORD", kct.__fnDWORD},
                {"NCDESTROY", kct.__fnNCDESTROY},
                {"DWORDOPTINLPMSG", kct.__fnDWORDOPTINLPMSG},
                {"INOUTDRAG", kct.__fnINOUTDRAG},
                {"GETTEXTLENGTHS", kct.__fnGETTEXTLENGTHS},
                {"INCNTOUTSTRING", kct.__fnINCNTOUTSTRING},
                {"POUTLPINT", kct.__fnPOUTLPINT},
                {"INLPCOMPAREITEMSTRUCT", kct.__fnINLPCOMPAREITEMSTRUCT},
                {"INLPCREATESTRUCT", kct.__fnINLPCREATESTRUCT},
                {"INLPDELETEITEMSTRUCT", kct.__fnINLPDELETEITEMSTRUCT},
                {"INLPDRAWITEMSTRUCT", kct.__fnINLPDRAWITEMSTRUCT},
                {"POPTINLPUINT", kct.__fnPOPTINLPUINT},
                {"POPTINLPUINT2", kct.__fnPOPTINLPUINT2},
                {"INLPMDICREATESTRUCT", kct.__fnINLPMDICREATESTRUCT},
                {"INOUTLPMEASUREITEMSTRUCT", kct.__fnINOUTLPMEASUREITEMSTRUCT},
                {"INLPWINDOWPOS", kct.__fnINLPWINDOWPOS},
                {"INOUTLPPOINT5", kct.__fnINOUTLPPOINT5},
                {"INOUTLPSCROLLINFO", kct.__fnINOUTLPSCROLLINFO},
                {"INOUTLPRECT", kct.__fnINOUTLPRECT},
                {"INOUTNCCALCSIZE", kct.__fnINOUTNCCALCSIZE},
                {"INOUTLPPOINT5_", kct.__fnINOUTLPPOINT5_},
                {"INPAINTCLIPBRD", kct.__fnINPAINTCLIPBRD},
                {"INSIZECLIPBRD", kct.__fnINSIZECLIPBRD},
                {"INDESTROYCLIPBRD", kct.__fnINDESTROYCLIPBRD},
                {"INSTRING", kct.__fnINSTRING},
                {"INSTRINGNULL", kct.__fnINSTRINGNULL},
                {"INDEVICECHANGE", kct.__fnINDEVICECHANGE},
                {"POWERBROADCAST", kct.__fnPOWERBROADCAST},
                {"INLPUAHDRAWMENU", kct.__fnINLPUAHDRAWMENU},
                {"OPTOUTLPDWORDOPTOUTLPDWORD", kct.__fnOPTOUTLPDWORDOPTOUTLPDWORD},
                {"OPTOUTLPDWORDOPTOUTLPDWORD_", kct.__fnOPTOUTLPDWORDOPTOUTLPDWORD_},
                {"OUTDWORDINDWORD", kct.__fnOUTDWORDINDWORD},
                {"OUTLPRECT", kct.__fnOUTLPRECT},
                {"OUTSTRING", kct.__fnOUTSTRING},
                {"POPTINLPUINT3", kct.__fnPOPTINLPUINT3},
                {"POUTLPINT2", kct.__fnPOUTLPINT2},
                {"SENTDDEMSG", kct.__fnSENTDDEMSG},
                {"INOUTSTYLECHANGE", kct.__fnINOUTSTYLECHANGE},
                {"HkINDWORD", kct.__fnHkINDWORD},
                {"HkINLPCBTACTIVATESTRUCT", kct.__fnHkINLPCBTACTIVATESTRUCT},
                {"HkINLPCBTCREATESTRUCT", kct.__fnHkINLPCBTCREATESTRUCT},
                {"HkINLPDEBUGHOOKSTRUCT", kct.__fnHkINLPDEBUGHOOKSTRUCT},
                {"HkINLPMOUSEHOOKSTRUCTEX", kct.__fnHkINLPMOUSEHOOKSTRUCTEX},
                {"HkINLPKBDLLHOOKSTRUCT", kct.__fnHkINLPKBDLLHOOKSTRUCT},
                {"HkINLPMSLLHOOKSTRUCT", kct.__fnHkINLPMSLLHOOKSTRUCT},
                {"HkINLPMSG", kct.__fnHkINLPMSG},
                {"HkINLPRECT", kct.__fnHkINLPRECT},
                {"HkOPTINLPEVENTMSG", kct.__fnHkOPTINLPEVENTMSG},
                {"ClientCallDelegateThread", kct.__xxxClientCallDelegateThread},
                {"ClientCallDummyCallback", kct.__ClientCallDummyCallback},
                {"KEYBOARDCORRECTIONCALLOUT", kct.__fnKEYBOARDCORRECTIONCALLOUT},
                {"OUTLPCOMBOBOXINFO", kct.__fnOUTLPCOMBOBOXINFO},
                {"INLPCOMPAREITEMSTRUCT2", kct.__fnINLPCOMPAREITEMSTRUCT2},
                {"ClientCallDevCallbackCapture", kct.__xxxClientCallDevCallbackCapture},
                {"ClientCallDitThread", kct.__xxxClientCallDitThread},
                {"ClientEnableMMCSS", kct.__xxxClientEnableMMCSS},
                {"ClientUpdateDpi", kct.__xxxClientUpdateDpi},
                {"ClientExpandStringW", kct.__xxxClientExpandStringW},
                {"ClientCopyDDEIn1", kct.__ClientCopyDDEIn1},
                {"ClientCopyDDEIn2", kct.__ClientCopyDDEIn2},
                {"ClientCopyDDEOut1", kct.__ClientCopyDDEOut1},
                {"ClientCopyDDEOut2", kct.__ClientCopyDDEOut2},
                {"ClientCopyImage", kct.__ClientCopyImage},
                {"ClientEventCallback", kct.__ClientEventCallback},
                {"ClientFindMnemChar", kct.__ClientFindMnemChar},
                {"ClientFreeDDEHandle", kct.__ClientFreeDDEHandle},
                {"ClientFreeLibrary", kct.__ClientFreeLibrary},
                {"ClientGetCharsetInfo", kct.__ClientGetCharsetInfo},
                {"ClientGetDDEFlags", kct.__ClientGetDDEFlags},
                {"ClientGetDDEHookData", kct.__ClientGetDDEHookData},
                {"ClientGetListboxString", kct.__ClientGetListboxString},
                {"ClientGetMessageMPH", kct.__ClientGetMessageMPH},
                {"ClientLoadImage", kct.__ClientLoadImage},
                {"ClientLoadLibrary", kct.__ClientLoadLibrary},
                {"ClientLoadMenu", kct.__ClientLoadMenu},
                {"ClientLoadLocalT1Fonts", kct.__ClientLoadLocalT1Fonts},
                {"ClientPSMTextOut", kct.__ClientPSMTextOut},
                {"ClientLpkDrawTextEx", kct.__ClientLpkDrawTextEx},
                {"ClientExtTextOutW", kct.__ClientExtTextOutW},
                {"ClientGetTextExtentPointW", kct.__ClientGetTextExtentPointW},
                {"ClientCharToWchar", kct.__ClientCharToWchar},
                {"ClientAddFontResourceW", kct.__ClientAddFontResourceW},
                {"ClientThreadSetup", kct.__ClientThreadSetup},
                {"ClientDeliverUserApc", kct.__ClientDeliverUserApc},
                {"ClientNoMemoryPopup", kct.__ClientNoMemoryPopup},
                {"ClientMonitorEnumProc", kct.__ClientMonitorEnumProc},
                {"ClientCallWinEventProc", kct.__ClientCallWinEventProc},
                {"ClientWaitMessageExMPH", kct.__ClientWaitMessageExMPH},
                {"ClientWOWGetProcModule", kct.__ClientWOWGetProcModule},
                {"ClientWOWTask16SchedNotify", kct.__ClientWOWTask16SchedNotify},
                {"ClientImmLoadLayout", kct.__ClientImmLoadLayout},
                {"ClientImmProcessKey", kct.__ClientImmProcessKey},
                {"IMECONTROL", kct.__fnIMECONTROL},
                {"INWPARAMDBCSCHAR", kct.__fnINWPARAMDBCSCHAR},
                {"GETTEXTLENGTHS2", kct.__fnGETTEXTLENGTHS2},
                {"INLPKDRAWSWITCHWND", kct.__fnINLPKDRAWSWITCHWND},
                {"ClientLoadStringW", kct.__ClientLoadStringW},
                {"ClientLoadOLE", kct.__ClientLoadOLE},
                {"ClientRegisterDragDrop", kct.__ClientRegisterDragDrop},
                {"ClientRevokeDragDrop", kct.__ClientRevokeDragDrop},
                {"fnINOUTMENUGETOBJECT", kct.__fnINOUTMENUGETOBJECT},
                {"ClientPrinterThunk", kct.__ClientPrinterThunk},
                {"OUTLPCOMBOBOXINFO2", kct.__fnOUTLPCOMBOBOXINFO2},
                {"OUTLPSCROLLBARINFO", kct.__fnOUTLPSCROLLBARINFO},
                {"INLPUAHDRAWMENU2", kct.__fnINLPUAHDRAWMENU2},
                {"INLPUAHDRAWMENUITEM", kct.__fnINLPUAHDRAWMENUITEM},
                {"INLPUAHDRAWMENU3", kct.__fnINLPUAHDRAWMENU3},
                {"INOUTLPUAHMEASUREMENUITEM", kct.__fnINOUTLPUAHMEASUREMENUITEM},
                {"INLPUAHDRAWMENU4", kct.__fnINLPUAHDRAWMENU4},
                {"OUTLPTITLEBARINFOEX", kct.__fnOUTLPTITLEBARINFOEX},
                {"TOUCH", kct.__fnTOUCH},
                {"GESTURE", kct.__fnGESTURE},
                {"POPTINLPUINT4", kct.__fnPOPTINLPUINT4},
                {"POPTINLPUINT5", kct.__fnPOPTINLPUINT5},
                {"ClientCallDefaultInputHandler", kct.__xxxClientCallDefaultInputHandler},
                {"EMPTY", kct.__fnEMPTY},
                {"ClientRimDevCallback", kct.__ClientRimDevCallback},
                {"ClientCallMinTouchHitTestingCallback", kct.__xxxClientCallMinTouchHitTestingCallback},
                {"ClientCallLocalMouseHooks", kct.__ClientCallLocalMouseHooks},
                {"ClientBroadcastThemeChange", kct.__xxxClientBroadcastThemeChange},
                {"ClientCallDevCallbackSimple", kct.__xxxClientCallDevCallbackSimple},
                {"ClientAllocWindowClassExtraBytes", kct.__xxxClientAllocWindowClassExtraBytes},
                {"ClientFreeWindowClassExtraBytes", kct.__xxxClientFreeWindowClassExtraBytes},
                {"GETWINDOWDATA", kct.__fnGETWINDOWDATA},
                {"INOUTSTYLECHANGE2", kct.__fnINOUTSTYLECHANGE2},
                {"HkINLPMOUSEHOOKSTRUCTEX2", kct.__fnHkINLPMOUSEHOOKSTRUCTEX2}
            };

            for (const auto& field : fields) {

                if (field.value == 0) continue;

                vecAddress.push_back(std::make_pair(field.value, field.name));

            }

            return vecAddress;
        }

    };

};

#endif // UTILSWINDOWSSYSCALL_H
