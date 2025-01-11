/*
    File: main.cc
    Authors: João Vitor(@Keowu)
    Created: 21/07/2024
    Last Update: 08/12/2024

    Copyright (c) 2024. https://github.com/maldeclabs/koidbg. All rights reserved.
*/
#include "debuggerwidgets/maindebug/MainDebuggerWindow.hh"
#include <QtWidgets/QApplication>
#include <QMessageBox>
#include <Shlobj.h>


auto elevateProcess() -> void {

    TCHAR szPath[MAX_PATH]{ 0 };

    if (GetModuleFileName(NULL, szPath, ARRAYSIZE(szPath))) {

        SHELLEXECUTEINFO sei;
        sei.cbSize = sizeof(sei);
        sei.lpVerb = TEXT("runas");
        sei.lpFile = szPath;
        sei.hwnd = NULL;
        sei.nShow = SW_NORMAL;

        if (!ShellExecuteEx(&sei))

            QMessageBox::critical(NULL, "Error!", "KoiDbg needs admin privilege to run!");


        TerminateProcess(GetCurrentProcess(), 0);

    }

}

auto EnableDebugPrivilege() -> bool {

    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return false;

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {

        CloseHandle(hToken);

        return false;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {

        CloseHandle(hToken);

        return false;
    }

    CloseHandle(hToken);

    return true;

}

#define PROCESSOR_FEATURE_MAX 64

typedef struct _KSYSTEM_TIME {

    ULONG LowPart;
    LONG High1Time;
    LONG High2Time;

} KSYSTEM_TIME, *PKSYSTEM_TIME;

typedef enum _NT_PRODUCT_TYPE {

    NtProductWinNt = 1,
    NtProductLanManNt = 2,
    NtProductServer = 3

} NT_PRODUCT_TYPE;

typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE {

    StandardDesign = 0,
    NEC98x86 = 1,
    EndAlternatives = 2

} ALTERNATIVE_ARCHITECTURE_TYPE;

typedef struct _KUSER_SHARED_DATA {
    ULONG                         TickCountLowDeprecated;
    ULONG                         TickCountMultiplier;
    KSYSTEM_TIME                  InterruptTime;
    KSYSTEM_TIME                  SystemTime;
    KSYSTEM_TIME                  TimeZoneBias;
    USHORT                        ImageNumberLow;
    USHORT                        ImageNumberHigh;
    WCHAR                         NtSystemRoot[260];
    ULONG                         MaxStackTraceDepth;
    ULONG                         CryptoExponent;
    ULONG                         TimeZoneId;
    ULONG                         LargePageMinimum;
    ULONG                         AitSamplingValue;
    ULONG                         AppCompatFlag;
    ULONGLONG                     RNGSeedVersion;
    ULONG                         GlobalValidationRunlevel;
    LONG                          TimeZoneBiasStamp;
    ULONG                         NtBuildNumber;
    NT_PRODUCT_TYPE               NtProductType;
    BOOLEAN                       ProductTypeIsValid;
    BOOLEAN                       Reserved0[1];
    USHORT                        NativeProcessorArchitecture;
    ULONG                         NtMajorVersion;
    ULONG                         NtMinorVersion;
    BOOLEAN                       ProcessorFeatures[PROCESSOR_FEATURE_MAX];
    ULONG                         Reserved1;
    ULONG                         Reserved3;
    ULONG                         TimeSlip;
    ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
    ULONG                         BootId;
    LARGE_INTEGER                 SystemExpirationDate;
    ULONG                         SuiteMask;
    BOOLEAN                       KdDebuggerEnabled;
    union {
        UCHAR MitigationPolicies;
        struct {
            UCHAR NXSupportPolicy : 2;
            UCHAR SEHValidationPolicy : 2;
            UCHAR CurDirDevicesSkippedForDlls : 2;
            UCHAR Reserved : 2;
        };
    };
    USHORT                        CyclesPerYield;
    ULONG                         ActiveConsoleId;
    ULONG                         DismountCount;
    ULONG                         ComPlusPackage;
    ULONG                         LastSystemRITEventTickCount;
    ULONG                         NumberOfPhysicalPages;
    BOOLEAN                       SafeBootMode;
    union {
        UCHAR VirtualizationFlags;
        struct {
            UCHAR ArchStartedInEl2 : 1;
            UCHAR QcSlIsSupported : 1;
        };
    };
    UCHAR                         Reserved12[2];
    union {
        ULONG SharedDataFlags;
        struct {
            ULONG DbgErrorPortPresent : 1;
            ULONG DbgElevationEnabled : 1;
            ULONG DbgVirtEnabled : 1;
            ULONG DbgInstallerDetectEnabled : 1;
            ULONG DbgLkgEnabled : 1;
            ULONG DbgDynProcessorEnabled : 1;
            ULONG DbgConsoleBrokerEnabled : 1;
            ULONG DbgSecureBootEnabled : 1;
            ULONG DbgMultiSessionSku : 1;
            ULONG DbgMultiUsersInSessionSku : 1;
            ULONG DbgStateSeparationEnabled : 1;
            ULONG SpareBits : 21;
        } DUMMYSTRUCTNAME2;
    } DUMMYUNIONNAME2;
    ULONG                         DataFlagsPad[1];
    ULONGLONG                     TestRetInstruction;
    LONGLONG                      QpcFrequency;
    ULONG                         SystemCall;
    ULONG                         Reserved2;
    ULONGLONG                     FullNumberOfPhysicalPages;
    ULONGLONG                     SystemCallPad[1];
    union {
        KSYSTEM_TIME TickCount;
        ULONG64      TickCountQuad;
        struct {
            ULONG ReservedTickCountOverlay[3];
            ULONG TickCountPad[1];
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME3;
    ULONG                         Cookie;
    ULONG                         CookiePad[1];
    LONGLONG                      ConsoleSessionForegroundProcessId;
    ULONGLONG                     TimeUpdateLock;
    ULONGLONG                     BaselineSystemTimeQpc;
    ULONGLONG                     BaselineInterruptTimeQpc;
    ULONGLONG                     QpcSystemTimeIncrement;
    ULONGLONG                     QpcInterruptTimeIncrement;
    UCHAR                         QpcSystemTimeIncrementShift;
    UCHAR                         QpcInterruptTimeIncrementShift;
    USHORT                        UnparkedProcessorCount;
    ULONG                         EnclaveFeatureMask[4];
    ULONG                         TelemetryCoverageRound;
    USHORT                        UserModeGlobalLogger[16];
    ULONG                         ImageFileExecutionOptions;
    ULONG                         LangGenerationCount;
    ULONGLONG                     Reserved4;
    ULONGLONG                     InterruptTimeBias;
    ULONGLONG                     QpcBias;
    ULONG                         ActiveProcessorCount;
    UCHAR                         ActiveGroupCount;
    UCHAR                         Reserved9;
    union {
        USHORT QpcData;
        struct {
            UCHAR QpcBypassEnabled;
            UCHAR QpcReserved;
        };
    };
    LARGE_INTEGER                 TimeZoneBiasEffectiveStart;
    LARGE_INTEGER                 TimeZoneBiasEffectiveEnd;
    XSTATE_CONFIGURATION          XState;
    KSYSTEM_TIME                  FeatureConfigurationChangeStamp;
    ULONG                         Spare;
    ULONG64                       UserPointerAuthMask;
    XSTATE_CONFIGURATION          XStateArm64;
    ULONG                         Reserved10[210];
} KUSER_SHARED_DATA, *PKUSER_SHARED_DATA;

/*
 *  Undocumented Way User KUSER_SHARED_DATA To Detect Windows 11
 *  Because Microsoft Is So Dumb And Cannot Fix RtlGetVersionApi
 *  Fuck Microsoft.
 */
auto DetectWindows11AvoidingMicrosoftBugs() -> bool {

    auto WindowsSharedUserData = reinterpret_cast<PKUSER_SHARED_DATA>(0x7FFE0000);

    /*
    QString message = QString("Build Number : %1\nMajor Version : %2\nMinor Version : %3")
                          .arg(WindowsSharedUserData->NtBuildNumber)
                          .arg(WindowsSharedUserData->NtMajorVersion)
                          .arg(WindowsSharedUserData->NtMinorVersion);

    qDebug() << "[DBGALLOW]: " << message;*/

    /*
     *  Qualquer coisa acima de 10.0.22000.0 é Windows 11. abaixo é Windows 10. FUCK MICROSOFT.
     */
    return WindowsSharedUserData->NtBuildNumber >= 22000;
}

int main(int argc, char *argv[]) {

    /* TODO: REMOVE IN THE FUTURE OR MAKE IT BETTER
     * if (!IsUserAnAdmin())
        elevateProcess();*/

    if (!DetectWindows11AvoidingMicrosoftBugs()) {

        MessageBoxA(NULL, "KoiDbg Requires minimum Windows 11(ARM or Intel) to RUN.", "Unable to run KOIDBG on this Machine!", MB_ICONERROR);

        ExitProcess(0);
    }

    if (!EnableDebugPrivilege()) {

        MessageBoxA(NULL, "KoiDbg needs SeDebugPrivilege to run !", "No privilege", MB_ICONERROR);

        ExitProcess(0);
    }

    QApplication a(argc, argv);

    qInstallMessageHandler([](QtMsgType, const QMessageLogContext&, const QString &msg){

        //On KoiDbg, We don't care about Qt's threat management, we'll garant it by our own. and manipulating and taking care of the syncronization
        if (!(msg.contains("parent's thread is QThread") || msg.contains("threads started with QThread")) && msg.contains("[DBGALLOW]")) qDebug() << msg;

    });

    MainDebuggerWindow w;

    w.show();

    return a.exec();
}
