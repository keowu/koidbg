/*
    File: DebuggerEngine.h
    Author: João Vitor(@Keowu)
    Created: 21/07/2024
    Last Update: 01/09/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#ifndef DEBUGGERENGINE_H
#define DEBUGGERENGINE_H
#include "debugmodule.h"
#include "debugthread.h"
#include "debughandle.h"
#include "debugmemory.h"
#include "debugbreakpoint.h"
#include "qlistview.h"
#include <QMainWindow>
#include <QStatusBar>
#include <windows.h>
#include <QTimer>
#include <QTableView>
#include <QHeaderView>
#include <QStandardItemModel>
#include <QtConcurrent/QtConcurrent>
#include "debuggerwidgets/custom/disasmview/harukadisasmview.h"
#include "debuggerwidgets/custom/qhexview/QHexView.hpp"

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

    };


    enum CurrentDebuggerCommand {

        NO_DECISION,
        RUNNING,
        STEP_IN,
        STEP_OUT,
        STEP_OVER,
        RUN

    };


    DebuggerEngine(std::pair<DWORD, std::string> processInfo, DebuggerEngine::GuiConfig gui);
    DebuggerEngine(std::wstring processPath, DebuggerEngine::GuiConfig gui);
    ~DebuggerEngine();

    /*
     *  User Interaction and decisions
     */
    //This is volatile, the value not be in the fucking cache, and not be shited by the MSVC optimization.
    volatile CurrentDebuggerCommand m_debugCommand{ DebuggerEngine::CurrentDebuggerCommand::RUNNING };

    auto stopEngine() -> void;

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
     * Handle & Handlers Utils
    */
    auto ListAllHandleObjectsForDebugeeProcess() -> void;

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

    /*
     *  Breakpoint/Interrupting manager
     */
    auto SetInterrupting(uintptr_t uipAddressBreak, bool isHardware) -> void;

};

#endif // DEBUGGERENGINE_H
