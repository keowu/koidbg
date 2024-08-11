/*
    File: utilswindowssycall.h
    Author: João Vitor(@Keowu)
    Created: 24/07/2024
    Last Update: 09/08/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
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


//FEATURE PARA DUMPAR OS HANDLERS:
//https://dimitrifourny.github.io/2020/06/11/dumping-veh-win10.html
//https://gist.github.com/olliencc/9f4bb9535c4f0ef0e54eac7912ab49c0
//https://research.nccgroup.com/2022/03/01/detecting-anomalous-vectored-exception-handlers-on-windows/

};

#endif // UTILSWINDOWSSYSCALL_H
