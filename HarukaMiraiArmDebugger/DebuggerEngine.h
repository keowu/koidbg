/*
    File: DebuggerEngine.h
    Author: João Vitor(@Keowu)
    Created: 21/07/2024
    Last Update: 28/07/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#ifndef DEBUGGERENGINE_H
#define DEBUGGERENGINE_H
#include "qlistview.h"
#include <QMainWindow>
#include <QStatusBar>
#include <windows.h>

class DebugThread {

public:

    HANDLE m_hThread;
    HANDLE m_UniqueProcess;
    uintptr_t m_lpThreadLocalBase;
    uintptr_t m_lpStartAddress;
    uintptr_t m_teb;
    int m_priorityLevel;

    DebugThread(HANDLE hThread, HANDLE UniqueProcess, uintptr_t lpThreadLocalBase, uintptr_t lpStartAddress, uintptr_t teb, int priorityLevel)
        : m_hThread(hThread), m_UniqueProcess(UniqueProcess), m_lpThreadLocalBase(lpThreadLocalBase), m_lpStartAddress(lpStartAddress), m_teb(teb), m_priorityLevel(priorityLevel) {};

    auto getPriorityLevelToString() -> QString {

        if (this->m_priorityLevel == 1) return "THREAD_PRIORITY_ABOVE_NORMAL";
        else if (this->m_priorityLevel == -1) return "THREAD_PRIORITY_BELOW_NORMAL";
        else if (this->m_priorityLevel == 2) return "THREAD_PRIORITY_HIGHEST";
        else if (this->m_priorityLevel == -15) return "THREAD_PRIORITY_IDLE";
        else if (this->m_priorityLevel == -2) return "THREAD_PRIORITY_LOWEST";
        else if (this->m_priorityLevel == 0) return "THREAD_PRIORITY_NORMAL";
        else if (this->m_priorityLevel == 15) return "THREAD_PRIORITY_TIME_CRITICAL";

        return "THREAD_PRIORITY_UNKNOWN";
    }

};

class DebugModule {

public:
    HANDLE m_hModule;
    QString m_qStName;
    uintptr_t m_lpModuleBase;

    DebugModule(HANDLE hModule, QString qStName, uintptr_t lpModuleBase)
        : m_hModule(hModule), m_qStName(qStName), m_lpModuleBase(lpModuleBase) { }

};

class DebuggerEngine {

public:

    struct GuiConfig {

        QListView* lstRegisters;
        QListView* lstStack;
        QStatusBar* statusbar;
        QListView* lstThreads;
        QListView* lstModules;
        QListView* lstUnloadedModules;

    };


    DebuggerEngine(std::pair<DWORD, std::string> processInfo, DebuggerEngine::GuiConfig gui);
    DebuggerEngine(std::wstring processPath, DebuggerEngine::GuiConfig gui);
    auto stopEngine() -> void;

private:
    std::wstring m_processPath;
    std::pair<STARTUPINFOEXW, PROCESS_INFORMATION> m_processInfo;
    GuiConfig m_guiCfg;
    BOOL m_StopDbg{FALSE};
    HANDLE m_hDebugLoop;
    std::vector<DebugThread> m_debugThreads;
    std::vector<DebugModule> m_debugModules;
    std::vector<DebugModule> m_debugUnloadedModules;

    auto InitDebuggeeProcess() -> std::pair<STARTUPINFOEXW, PROCESS_INFORMATION>;
    static auto WINAPI DebugLoop(LPVOID args) -> DWORD;

    /*
     * Event Dispatches
     */
    auto handleExceptionDebugEvent(const DWORD dwTid, const EXCEPTION_DEBUG_INFO& info) -> void;
    auto handleCreateThreadDebugEvent(const CREATE_THREAD_DEBUG_INFO& info) -> void;
    auto handleCreateProcessDebugEvent(const CREATE_PROCESS_DEBUG_INFO& info) -> void;
    auto handleExitThreadDebugEvent(const EXIT_THREAD_DEBUG_INFO& info) -> void;
    auto handleExitProcessDebugEvent(const EXIT_PROCESS_DEBUG_INFO& info) -> void;
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
    auto ReadMemory(uintptr_t pAddress, unsigned char* ucMemory, size_t szRead) -> bool;
    auto IsPE(uintptr_t pAddress) -> bool;

   /*
    * Debugger GUI User Interaction
    */
    auto AddStringToListView(QListView* list, QString stringArgument) -> void;
    auto RemoveStringFromListView(QListView* list, int index) -> void;

};

#endif // DEBUGGERENGINE_H
