/*
    File: DebuggerEngine.hh
    Author: João Vitor(@Keowu)
    Created: 21/07/2024
    Last Update: 10/11/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#ifndef DEBUGGERENGINE_H
#define DEBUGGERENGINE_H
#include "debugmodule.hh"
#include "debugthread.hh"
#include "debughandle.hh"
#include "debugmemory.hh"
#include "debugbreakpoint.hh"
#include "debuggercommands/SafeCommandQueue.hh"
#include "qlistview.h"
#include <QMainWindow>
#include <QStatusBar>
#include <windows.h>
#include <QLabel>
#include <QTimer>
#include <QTableView>
#include <QHeaderView>
#include <QTextEdit>
#include <QScrollBar>
#include <QStandardItemModel>
#include <QtConcurrent/QtConcurrent>
#include "debuggerwidgets/custom/disasmview/harukadisasmview.hh"
#include "debuggerwidgets/custom/qhexview/QHexView.hh"
#include <KurumiParser.hh>

class DebuggerEngine {

public:

    struct GuiConfig {

        QListView* lstRegisters;
        QListView* lstStack;
        QStatusBar* statusbar;
        QListView* lstThreads;
        QListView* lstModules;
        QListView* lstUnloadedModules;
        QListView* lstCallStack;
        QTableView* tblMemoryView;
        QTableView* tblHandles;
        QTableView* tblInterrupts;
        HarukaDisasmView* tblDisasmVw;
        QHexView* qHexVw[3];
        QTextEdit* outCommandConsole;
        QListView* lstRegisteredVehs;
        QListView* lstProcessCallbacks;
        QTableView* tblPdbFunctions;
        QLabel* lblPdbInspectorMetrics;
        QTextEdit* txtDecompiler;
        QTabWidget* qTabHaruka;

    };


    enum CurrentDebuggerCommand {

        NO_DECISION,
        RUNNING,
        STEP_IN,
        STEP_OUT,
        STEP_OVER,
        RUN

    };

    enum CurrentDebuggerRule {

        NO_RULE,
        BKPT_CONTINUE

    };


    DebuggerEngine(std::pair<DWORD, std::string> processInfo, DebuggerEngine::GuiConfig gui);
    DebuggerEngine(std::wstring processPath, DebuggerEngine::GuiConfig gui);
    ~DebuggerEngine();

    /*
     *  User Interaction and decisions
     */
    //This is volatile, the value not be in the fucking cache, and not be shited by the MSVC optimization.
    volatile CurrentDebuggerCommand m_debugCommand{ DebuggerEngine::CurrentDebuggerCommand::RUNNING };
    volatile CurrentDebuggerRule m_debugRule{ DebuggerEngine::CurrentDebuggerRule::NO_RULE };
    SafeCommandQueue m_commandProcessingQueue;

    /*
     * Stoping engine
     */
    auto stopEngine() -> void;

    /*
     * Execute a stepOver
     */
    auto stepOver() -> void;

    /*
     * Execute a StepInto
     */
    auto stepInto() -> void;

    /*
     * Execute a stepOut
     */
    auto stepOut() -> void;

    /*
     * Get debugging section active
     */
    auto isDebugSessionActive() -> bool {

        return m_StopDbg;
    }

    /*
     * External getters and setters utils
     */
    auto getBreakpointByIndex(int index) -> DebugBreakpoint* {

        return this->m_debugBreakpoint.at(index);
    }

    auto removeBreakpointItemByIndex(int index) -> void {

        if (index < this->m_debugBreakpoint.size()) {

            this->m_debugBreakpoint.erase(this->m_debugBreakpoint.begin() + index);

        } else {

            qDebug() << "removeBreakpointItemByIndex -> Index out of range.";

        }

    }

    /*
     *  Breakpoint/Interrupting manager
     */
    auto SetInterrupting(uintptr_t uipAddressBreak, bool isHardware) -> void;
    auto RemoveInterrupting(DebugBreakpoint* debug) -> void;

    /*
     * Kurumi Analysis Engine
    */
    auto isKurumiLoaded() -> bool {
        return this->m_KurumiEngineStarted;
    }
    auto extractLdrpVectorHandlerListInformation() -> void;
    auto extractNirvanaCallbackPresentOnDebugeeProcess() -> void;
    auto extractNtDelegateTableCallbacks() -> void;
    auto extractPdbFileFunctions(QString pdbPath) -> void;

    /*
     * Update Disassembler View for the user
    */
    auto UpdateDisassemblerView(const uintptr_t uipAddress) -> void;

private:
    /*
     *  Generic Variables
     */
    std::wstring m_processPath;
    std::pair<STARTUPINFOEXW, PROCESS_INFORMATION> m_processInfo;
    HANDLE hInternalDebugHandle;
    GuiConfig m_guiCfg;
    BOOL m_StopDbg{FALSE};
    HANDLE m_hDebugLoop;
    HANDLE m_hDebugCommandProcessingLoop;

    /*
     * Kurumi Analysis Engine
     */
    BOOL m_KurumiEngineStarted{FALSE};

    /*
     * Debugger Information data
     */
    std::vector<DebugThread> m_debugThreads;
    std::vector<DebugModule> m_debugModules;
    std::vector<DebugModule> m_debugUnloadedModules;
    std::vector<DebugBreakpoint*> m_debugBreakpoint;
    int m_hardwareDebugControl = 0;
    std::vector<DebugHandle> m_debugHandles;
    std::vector<DebugMemory> m_debugMemory;

    /*
     * Initializers
     */
    auto InitDebuggeeProcess() -> std::pair<STARTUPINFOEXW, PROCESS_INFORMATION>;
    static auto WINAPI DebugLoop(LPVOID args) -> DWORD;
    static auto WINAPI DebugCommandProcessingLoop(LPVOID args) -> DWORD;

    /*
     * Event Dispatches
     */
    auto handleExceptionDebugEvent(const DWORD dwTid, const EXCEPTION_DEBUG_INFO& info) -> void;
    auto handleCreateThreadDebugEvent(const CREATE_THREAD_DEBUG_INFO& info) -> void;
    auto handleCreateProcessDebugEvent(const CREATE_PROCESS_DEBUG_INFO& info) -> void;
    auto handleExitThreadDebugEvent(const EXIT_THREAD_DEBUG_INFO& info) -> void;
    auto handleExitProcessDebugEvent(const DWORD dwTid, const EXIT_PROCESS_DEBUG_INFO& info) -> void;
    auto handleLoadDllDebugEvent(const LOAD_DLL_DEBUG_INFO& info) -> void;
    auto handleUnloadDllDebugEvent(const UNLOAD_DLL_DEBUG_INFO& info) -> void;
    auto handleOutputDebugStringEvent(const OUTPUT_DEBUG_STRING_INFO& info) -> void;
    auto handleRipEvent(const RIP_INFO& info) -> void;

    /*
     * Register Manipulation
     */
    auto updateRegistersContext(const DWORD dwTID) -> void;
    auto updateStackContext(const DWORD dwTID) -> void;

    /*
     * Debugger memory manipulation Utils
     */
    auto AnalyseDebugProcessVirtualMemory() -> void;
    auto ReadMemory(uintptr_t pAddress, unsigned char* ucMemory, size_t szRead) -> bool;
    auto IsPE(uintptr_t pAddress) -> bool;

    /*
     * Handle/Handlers & List Utils
    */
    auto ListAllHandleObjectsForDebugeeProcess() -> void;
    auto ListAddModule(DebugModule dbgModule) -> void;

   /*
    * Debugger GUI User Interaction
    */
    auto AddStringToListView(QListView* list, QString stringArgument) -> void;
    auto RemoveStringFromListView(QListView* list, int index) -> void;

    /*
     * Update all debugger context, when a new event occour, like breakpoints, steps, step into, step over or run.
     */
    auto UpdateAllDebuggerContext(const DWORD dwTID) -> void;
    auto DeleteAllDebuggerContext() -> void;
    auto DeleteAllDebuggerContextEngineExit() -> void;

    /*
     * Update Disassembler View for the user
     */
    auto UpdateDisassemblerView(const DWORD dwTID) -> void;
    auto UpdateActualIPContext(uintptr_t uipAddressToIP) -> void;

};

/*
 * --------------------------------------------------------------------------------------------------------------------------------------------------------------
 * ARM64 - BVR\BCR FLAGS for HW Breakpoints
 * Thanks to: ARM64 BREAKPOINT, THANKS TO: https://github.com/ninjaprawn/async_wake-fun/blob/6ffb822e153fd98fc6f9d09604317f316c3b0577/async_wake_ios/kdbg.c#L686
 *--------------------------------------------------------------------------------------------------------------------------------------------------------------
 */
#define BCR_BAS_ALL (0xf << 5)
#define BCR_E (1 << 0)
/*
* --------------------------------------------------------------------------------------------------------------------------------------------------------------
*/

#endif // DEBUGGERENGINE_H
