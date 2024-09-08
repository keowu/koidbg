/*
    File: DebuggerEngine.cpp
    Author: João Vitor(@Keowu)
    Created: 21/07/2024
    Last Update: 08/09/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#include "debuggerengine.h"
#include "qstringlistmodel.h"
#include "disassemblerengine/disassemblerengine.h"
#include "debuggerutils/utilswindowssyscall.h"

auto DebuggerEngine::AddStringToListView(QListView* list, QString stringArgument) -> void {

    QStringListModel *model = qobject_cast<QStringListModel*>(list->model());

    if (!model) {

        // If m_guiCfg.lstThreads doesn't have a QStringListModel yet, create one
        model = new QStringListModel(list);

        list->setModel(model);
    }

    QStringList currentList = model->stringList();

    currentList << stringArgument;

    model->setStringList(currentList);

}

auto DebuggerEngine::RemoveStringFromListView(QListView* list, int index) -> void {

    QStringListModel* model = qobject_cast<QStringListModel*>(list->model());

    if (model && index >= 0 && index < model->rowCount()) {

        QStringList currentList = model->stringList();

        currentList.removeAt(index);

        model->setStringList(currentList);
    }
}

DebuggerEngine::DebuggerEngine(std::pair<DWORD, std::string> processInfo, DebuggerEngine::GuiConfig gui) {

    //this->m_dwProcess = processInfo.first;
    //this->m_processName = processInfo.second;
    this->m_guiCfg = gui;

    /*
     *
     * TODO
     *
     */

}

DebuggerEngine::DebuggerEngine(std::wstring processPath, DebuggerEngine::GuiConfig gui) {

    this->m_processPath = processPath;
    this->m_guiCfg = gui;
    this->m_StopDbg = FALSE;

    this->m_hDebugLoop = CreateThread(

        NULL,
        NULL,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(DebuggerEngine::DebugLoop),
        this,
        NULL,
        NULL

    );
}

DebuggerEngine::~DebuggerEngine() {

    this->DeleteAllDebuggerContextEngineExit();

}

auto DebuggerEngine::InitDebuggeeProcess( ) -> std::pair<STARTUPINFOEXW, PROCESS_INFORMATION> {

    STARTUPINFOEXW si;
    ZeroMemory(&si, sizeof(si));
    si.StartupInfo.cb = sizeof(STARTUPINFOEXW);
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    std::wstring cmdLine = this->m_processPath + L" ";
    wchar_t* cmdLineMutable = &cmdLine[0];

    auto ret = CreateProcessW(

        NULL,
        cmdLineMutable,
        NULL,
        NULL,
        FALSE,
        DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE | CREATE_SUSPENDED,
        NULL,
        NULL,
        &si.StartupInfo,
        &pi

    );

    if (!ret) return { si, pi };

    ResumeThread(pi.hThread);

    return { si, pi };
}

auto DebuggerEngine::stopEngine() -> void {

    this->m_StopDbg = TRUE;

}


auto WINAPI DebuggerEngine::DebugLoop(LPVOID args) -> DWORD {

    DebuggerEngine* thiz = reinterpret_cast<DebuggerEngine*>(args);

    thiz->m_processInfo = thiz->InitDebuggeeProcess();

    if (thiz->m_processInfo.second.hProcess == 0 && thiz->m_processInfo.second.dwProcessId == 0) {

        thiz->m_guiCfg.statusbar->showMessage("[ERROR CreateProcessW]: 0x" + QString::number(GetLastError(), 16), 1000);

        return -1;
    }

    /*
     * Begin Memory Inspectors
    */
    QHexView* hexViews[3] = { thiz->m_guiCfg.qHexVw[0], thiz->m_guiCfg.qHexVw[1], thiz->m_guiCfg.qHexVw[2] };
    BreakPointCallback callbackBreakpoint = std::bind(&DebuggerEngine::SetInterrupting, thiz, std::placeholders::_1, std::placeholders::_2);
    SetIPCallback callbackIP = std::bind(&DebuggerEngine::UpdateActualIPContext, thiz, std::placeholders::_1);
    thiz->m_guiCfg.tblDisasmVw->configureDisasm(hexViews, thiz->m_processInfo.second.hProcess, callbackBreakpoint, callbackIP);


    /*
    * Main debugger loop
    */
    DEBUG_EVENT dbgEvent;
    std::memset(&dbgEvent, 0, sizeof(DEBUG_EVENT));

    qDebug() << "Debug loop started.";

    while (!thiz->m_StopDbg) {

        if (WaitForDebugEvent(&dbgEvent, INFINITE)) {

            switch (dbgEvent.dwDebugEventCode) {

            case EXCEPTION_DEBUG_EVENT:

                thiz->m_debugCommand = DebuggerEngine::CurrentDebuggerCommand::NO_DECISION;

                thiz->handleExceptionDebugEvent(dbgEvent.dwThreadId, dbgEvent.u.Exception);

                break;
            case CREATE_THREAD_DEBUG_EVENT:
                thiz->handleCreateThreadDebugEvent(dbgEvent.u.CreateThread);
                break;
            case CREATE_PROCESS_DEBUG_EVENT:

                thiz->handleCreateProcessDebugEvent(dbgEvent.u.CreateProcessInfo);

                break;
            case EXIT_THREAD_DEBUG_EVENT:
                thiz->handleExitThreadDebugEvent(dbgEvent.u.ExitThread);
                break;
            case EXIT_PROCESS_DEBUG_EVENT:
                thiz->handleExitProcessDebugEvent(dbgEvent.dwThreadId, dbgEvent.u.ExitProcess);
                thiz->m_StopDbg = true;
                break;
            case LOAD_DLL_DEBUG_EVENT:
                thiz->handleLoadDllDebugEvent(dbgEvent.u.LoadDll);
                break;
            case UNLOAD_DLL_DEBUG_EVENT:
                thiz->handleUnloadDllDebugEvent(dbgEvent.u.UnloadDll);
                break;
            case OUTPUT_DEBUG_STRING_EVENT:
                thiz->handleOutputDebugStringEvent(dbgEvent.u.DebugString);
                break;
            case RIP_EVENT:
                thiz->handleRipEvent(dbgEvent.u.RipInfo);
                break;
            }

            while (thiz->m_debugCommand == DebuggerEngine::CurrentDebuggerCommand::NO_DECISION) {} //Waiting for the user decide what to do

            if (thiz->m_debugRule == DebuggerEngine::BKPT_CONTINUE) {

               ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);

               thiz->m_debugRule = DebuggerEngine::CurrentDebuggerRule::NO_RULE;
            }

            ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
        } else {
            DWORD error = GetLastError();
            if (error != ERROR_SEM_TIMEOUT) {
                qDebug() << "WaitForDebugEvent failed with error: " << error;
            }
        }
    }

    qDebug() << "End Debug loop.";
    return 0;
}


/*
 *
 * DEBUG EVENT - Dispatchs
 */
auto DebuggerEngine::handleExceptionDebugEvent(const DWORD dwTid, const EXCEPTION_DEBUG_INFO& info) -> void {

    qDebug() << "EXCEPTION_DEBUG_EVENT -> " << QString::number(info.ExceptionRecord.ExceptionCode, 16);

    if (info.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {

        qDebug() << "Breakpoint trigged -> " << QString::number(reinterpret_cast<uintptr_t>(info.ExceptionRecord.ExceptionAddress), 16);

        //Delete all old context
        this->DeleteAllDebuggerContext();

        //Reupdate new context
        this->UpdateAllDebuggerContext(dwTid);

    } else if (info.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {

        qDebug() << "Hardware Breakpoint trigged -> " << QString::number(reinterpret_cast<uintptr_t>(info.ExceptionRecord.ExceptionAddress), 16);

        //Delete all old context
        this->DeleteAllDebuggerContext();

        //Reupdate new context
        this->UpdateAllDebuggerContext(dwTid);

    }

    //TODO: OTHER/GENERIC EXCEPTIONS
    /*else {


        this->m_debugRule = DebuggerEngine::BKPT_CONTINUE;
        this->m_debugCommand = DebuggerEngine::RUN;

        //Delete all old context
        this->DeleteAllDebuggerContext();

        //Reupdate new context
        this->UpdateAllDebuggerContext(dwTid);

    }*/


}

auto DebuggerEngine::handleCreateThreadDebugEvent(const CREATE_THREAD_DEBUG_INFO& info) -> void {

    qDebug() << "CREATE_THREAD_DEBUG_EVENT";

    auto tbi = UtilsWindowsSyscall::GetThreadBasicInformation(info.hThread);

    DebugThread dbgThread(

        info.hThread,
        tbi->ClientId.UniqueThread,
        reinterpret_cast<uintptr_t>(info.lpThreadLocalBase),
        reinterpret_cast<uintptr_t>(info.lpStartAddress),
        reinterpret_cast<uintptr_t>(tbi->TebBaseAddress),
        GetThreadPriority(info.hThread)

    );


    this->AddStringToListView(this->m_guiCfg.lstThreads, QString(
                                                            "TID: 0x%1, BASE: 0x%2, START: 0x%3, TEB: 0x%4, PRIORITY: %5"
                                                         ).arg(
                                                            QString::number(reinterpret_cast<uintptr_t>(dbgThread.m_ThreadID), 10),
                                                            QString::number(dbgThread.m_lpThreadLocalBase, 16),
                                                            QString::number(dbgThread.m_lpStartAddress, 16),
                                                            QString::number(dbgThread.m_teb, 16),
                                                            dbgThread.getPriorityLevelToString()
                                                         ));


    this->m_debugThreads.push_back(dbgThread);

}

auto DebuggerEngine::handleCreateProcessDebugEvent(const CREATE_PROCESS_DEBUG_INFO& info) -> void {

    qDebug() << "CREATE_PROCESS_DEBUG_EVENT";

    this->hInternalDebugHandle = info.hProcess;

    auto tbi = UtilsWindowsSyscall::GetThreadBasicInformation(info.hThread);

    DebugThread dbgThread(

        info.hThread,
        tbi->ClientId.UniqueThread,
        reinterpret_cast<uintptr_t>(info.lpThreadLocalBase),
        reinterpret_cast<uintptr_t>(info.lpStartAddress),
        reinterpret_cast<uintptr_t>(tbi->TebBaseAddress),
        GetThreadPriority(info.hThread)

    );

    this->AddStringToListView(this->m_guiCfg.lstThreads, QString(
                                                             "[MAIN THREAD] TID: %1, BASE: 0x%2, START: 0x%3, TEB: 0x%4, PRIORITY: %5"
                                                             ).arg(
                                                                 QString::number(reinterpret_cast<uintptr_t>(dbgThread.m_ThreadID), 16),
                                                                 QString::number(dbgThread.m_lpThreadLocalBase, 16),
                                                                 QString::number(dbgThread.m_lpStartAddress, 16),
                                                                 QString::number(dbgThread.m_teb, 16),
                                                                 dbgThread.getPriorityLevelToString()
                                                            ));


    this->m_debugThreads.push_back(dbgThread);

}

auto DebuggerEngine::handleExitThreadDebugEvent(const EXIT_THREAD_DEBUG_INFO& info) -> void {

    qDebug() << "EXIT_THREAD_DEBUG_EVENT";

}

auto DebuggerEngine::handleExitProcessDebugEvent(const DWORD dwTid, const EXIT_PROCESS_DEBUG_INFO& info) -> void {

    qDebug() << "EXIT_PROCESS_DEBUG_EVENT";

    //Delete all old context
    this->DeleteAllDebuggerContext();

    //Reupdate new context
    this->UpdateAllDebuggerContext(dwTid);

    //Criar uma informação de saída de processo aqui

}

auto DebuggerEngine::handleLoadDllDebugEvent(const LOAD_DLL_DEBUG_INFO& info) -> void {

    qDebug() << "LOAD_DLL_DEBUG_EVENT";

    DebugModule dbgModule(

        info.hFile,
        UtilsWindowsSyscall::GetFileNameFromHandle(info.hFile),
        reinterpret_cast<uintptr_t>(info.lpBaseOfDll)

    );

    //If not is a valid pe. just return and end our search because this module is invalid.
    if (!this->IsPE(dbgModule.m_lpModuleBase)) return;


    this->AddStringToListView(this->m_guiCfg.lstModules, QString(
                                                             "BASE: 0x%1, MODULE NAME: %2"
                                                             ).arg(
                                                                 QString::number(dbgModule.m_lpModuleBase, 16),
                                                                 dbgModule.m_qStName
                                                             ));

    this->m_debugModules.push_back(dbgModule);

}

auto DebuggerEngine::handleUnloadDllDebugEvent(const UNLOAD_DLL_DEBUG_INFO& info) -> void {

    qDebug() << "UNLOAD_DLL_DEBUG_EVENT";

    for(auto i = 0; i < this->m_debugModules.size(); i++) {

        auto dbgModule = this->m_debugModules.at(i);

        if (dbgModule.m_lpModuleBase != reinterpret_cast<uintptr_t>(info.lpBaseOfDll)) continue;

        this->m_debugModules.erase(this->m_debugModules.begin() + i);

        this->RemoveStringFromListView(this->m_guiCfg.lstModules, i);

        this->AddStringToListView(this->m_guiCfg.lstUnloadedModules, QString(
                                                                         "BASE: 0x%1, MODULE NAME: %2"
                                                                     ).arg(
                                                                        QString::number(dbgModule.m_lpModuleBase, 16),
                                                                        dbgModule.m_qStName
                                                                     ));

        this->m_debugUnloadedModules.push_back(dbgModule);
    }

}

auto DebuggerEngine::handleOutputDebugStringEvent(const OUTPUT_DEBUG_STRING_INFO& info) -> void {

    qDebug() << "OUTPUT_DEBUG_STRING_EVENT";

}

auto DebuggerEngine::handleRipEvent(const RIP_INFO& info) -> void {

    qDebug() << "RIP_EVENT";

}

auto DebuggerEngine::UpdateAllDebuggerContext(const DWORD dwTID) -> void {

    qDebug() << "DebuggerEngine::UpdateAllDebuggerContext";

    this->ListAllHandleObjectsForDebugeeProcess();

    this->AnalyseDebugProcessVirtualMemory();

    this->updateRegistersContext(dwTID);

    this->UpdateDisassemblerView(dwTID);

    /*
     * Força redraw da interface após atualizar dados sem bugar a visualização forçando que o usuário passe o mouse em cima.
     */
    this->m_guiCfg.lstCallStack->viewport()->update();

    this->m_guiCfg.lstRegisters->viewport()->update();

}

auto DebuggerEngine::DeleteAllDebuggerContextEngineExit() -> void {

    this->DeleteAllDebuggerContext();

    //__________________________________________________________________________________________________________
    // Clean debug engine information vectors
    //__________________________________________________________________________________________________________
    this->m_debugThreads.clear();
    this->m_debugModules.clear();
    this->m_debugUnloadedModules.clear();
    this->m_debugBreakpoint.clear();
    this->m_debugHandles.clear();
    this->m_debugMemory.clear();

    //__________________________________________________________________________________________________________
    // Deleting old Disassembler View
    //__________________________________________________________________________________________________________
    QStandardItemModel *disasmModel = qobject_cast<QStandardItemModel*>(this->m_guiCfg.tblDisasmVw->model());

    if (disasmModel) disasmModel->clear();
    else {

        disasmModel = new QStandardItemModel();
        this->m_guiCfg.tblDisasmVw->setModel(disasmModel);

    }

    //__________________________________________________________________________________________________________
    // Deleting old Call Stack View
    //__________________________________________________________________________________________________________
    QStandardItemModel *callstackModel = qobject_cast<QStandardItemModel*>(this->m_guiCfg.lstCallStack->model());

    if (callstackModel) callstackModel->clear();
    else {

        callstackModel = new QStandardItemModel();
        this->m_guiCfg.lstCallStack->setModel(callstackModel);

    }

    //__________________________________________________________________________________________________________
    // Deleting old Memory View
    //__________________________________________________________________________________________________________
    QStandardItemModel *memoryviewModel = qobject_cast<QStandardItemModel*>(this->m_guiCfg.tblMemoryView->model());

    if (memoryviewModel) memoryviewModel->clear();
    else {

        memoryviewModel = new QStandardItemModel();
        this->m_guiCfg.tblMemoryView->setModel(memoryviewModel);

    }

    //__________________________________________________________________________________________________________
    // Deleting Modules View (Loaded and Unloaded)
    //__________________________________________________________________________________________________________
    QStandardItemModel *modulesLoadedModel = qobject_cast<QStandardItemModel*>(this->m_guiCfg.lstModules->model());

    if (modulesLoadedModel) modulesLoadedModel->clear();
    else {

        modulesLoadedModel = new QStandardItemModel();
        this->m_guiCfg.lstModules->setModel(modulesLoadedModel);

    }

    QStandardItemModel *modulesUnloadModel = qobject_cast<QStandardItemModel*>(this->m_guiCfg.lstUnloadedModules->model());

    if (modulesUnloadModel) modulesUnloadModel->clear();
    else {

        modulesUnloadModel = new QStandardItemModel();
        this->m_guiCfg.lstUnloadedModules->setModel(modulesUnloadModel);

    }

    //__________________________________________________________________________________________________________
    // Deleting Threads View
    //__________________________________________________________________________________________________________
    QStandardItemModel *threadsViewModel = qobject_cast<QStandardItemModel*>(this->m_guiCfg.lstThreads->model());

    if (threadsViewModel) threadsViewModel->clear();
    else {

        threadsViewModel = new QStandardItemModel();
        this->m_guiCfg.lstThreads->setModel(threadsViewModel);

    }

    //__________________________________________________________________________________________________________
    // Deleting Handles View
    //__________________________________________________________________________________________________________
    QStandardItemModel *handlesViewModel = qobject_cast<QStandardItemModel*>(this->m_guiCfg.tblHandles->model());

    if (handlesViewModel) handlesViewModel->clear();
    else {

        handlesViewModel = new QStandardItemModel();
        this->m_guiCfg.tblHandles->setModel(handlesViewModel);

    }

    //__________________________________________________________________________________________________________
    // Deleting Breakpoints/Interrupts View
    //__________________________________________________________________________________________________________
    QStandardItemModel *interruptsViewModel = qobject_cast<QStandardItemModel*>(this->m_guiCfg.tblInterrupts->model());

    if (interruptsViewModel) interruptsViewModel->clear();
    else {

        interruptsViewModel = new QStandardItemModel();
        this->m_guiCfg.tblInterrupts->setModel(interruptsViewModel);

    }

    this->m_guiCfg.qHexVw[0]->clear();
    this->m_guiCfg.qHexVw[1]->clear();
    this->m_guiCfg.qHexVw[2]->clear();

}

auto DebuggerEngine::DeleteAllDebuggerContext() -> void {

    //TODO DELETE ALL THE OLD CONTEXT AND MODELS OF GRIDS, VECTORS ETC FOR MEMORY, HANDLES, STACK, REGISTERS ETC.

    qDebug() << "DebuggerEngine::DeleteAllDebuggerContext";

    //__________________________________________________________________________________________________________
    // Deleting old registers context
    //__________________________________________________________________________________________________________
    QStandardItemModel* registerModel = qobject_cast<QStandardItemModel*>(this->m_guiCfg.lstRegisters->model());

    if (registerModel) registerModel->clear();
    else {

        registerModel = new QStandardItemModel();
        this->m_guiCfg.lstRegisters->setModel(registerModel);

    }
    //__________________________________________________________________________________________________________

    //__________________________________________________________________________________________________________
    // Deleting old stack context
    //__________________________________________________________________________________________________________
    QStandardItemModel* stackModel = qobject_cast<QStandardItemModel*>(this->m_guiCfg.lstStack->model());

    if (stackModel) stackModel->clear();
    else {

        stackModel = new QStandardItemModel();
        this->m_guiCfg.lstStack->setModel(stackModel);

    }
    //__________________________________________________________________________________________________________

    //__________________________________________________________________________________________________________
    /* Deleting old Disassembler View context
     *
     * If you're wodering why we do not clean Disassembler View Context
     * this is done when a new UpdateDisassemblerView get called, the old context is automatic discarted, and we do not need to recreate it
     * like was done with ListViews QWidgets.
     * Two moments that Disassembler View context get discarted:
     *  - By the UpdateDisassemblerView itself
     *  - By ending the debugger session, on cleanup and deleting debugengine object and recreating a new one.
     */
    //__________________________________________________________________________________________________________

}

auto DebuggerEngine::UpdateDisassemblerView(const DWORD dwTID) -> void {

    QStandardItemModel* model;

    if (!this->m_guiCfg.tblDisasmVw->model()) {
        model = new QStandardItemModel();

        this->m_guiCfg.tblDisasmVw->setModel(model);

    } else {
        model = qobject_cast<QStandardItemModel*>(this->m_guiCfg.tblDisasmVw->model());

        if (!model) {
            qDebug() << "The model is not of type QStandardItemModel!";
            return;
        }
    }


    auto hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwTID);

    size_t ripTblIndex = 0;

    uintptr_t regIP = 0;

    #if defined(__aarch64__) || defined(_M_ARM64)

        ARM64_NT_CONTEXT ctx;

        ZeroMemory(&ctx, sizeof(ARM64_NT_CONTEXT));
        ctx.ContextFlags = CONTEXT_ALL;

        GetThreadContext(hThread, reinterpret_cast<LPCONTEXT>(&ctx));

        regIP = ctx.Pc - 4; //Let's begin from 4 bytes to previous instruction


    #elif defined(__x86_64__) || defined(_M_X64)

        CONTEXT ctx;

        ZeroMemory(&ctx, sizeof(CONTEXT));
        ctx.ContextFlags = CONTEXT_ALL;

        GetThreadContext(hThread, &ctx);

        regIP = ctx.Rip;

    #endif

    MEMORY_BASIC_INFORMATION mb;

    //Se não conseguirmos fazer uma query da região retornamos e não fazemos nada. o ideal é avisar ao usuário no futuro.
    if (!VirtualQueryEx(this->hInternalDebugHandle, reinterpret_cast<PVOID>(regIP), &mb, sizeof(mb))) return;


    DisasmEngineConfig engCfg{

        model,
        this->hInternalDebugHandle,
        this->m_guiCfg.tblDisasmVw,
        regIP,
        &ripTblIndex

    };

    auto ucOpcodes = new unsigned char [mb.RegionSize] { 0 };

    DisassemblerEngine *disasm = new DisassemblerEngine();

    //Separar coisas relacionadas a memory em namespaces separadas

    model->clear();

    model->setHorizontalHeaderLabels(QStringList() << "Address" << "Opcode" << "Disasm" << "Anotations");

    #if defined(__aarch64__) || defined(_M_ARM64)

        /*
         *   O WINDBG Apenas considera o RIP para disassemblar.
        */
        this->ReadMemory(regIP, ucOpcodes, mb.RegionSize);

        disasm->RunCapstoneEngineAarch64(regIP, ucOpcodes, mb.RegionSize, engCfg);

    #elif defined(__x86_64__) || defined(_M_X64)
        /*
         *   O WINDBG Considera toda a região e a partir do início damesma para disassemblar
         */
        this->ReadMemory(reinterpret_cast<uintptr_t>(mb.BaseAddress), ucOpcodes, mb.RegionSize);

        disasm->RunCapstoneEnginex86(reinterpret_cast<uintptr_t>(mb.BaseAddress), ucOpcodes, mb.RegionSize, engCfg);

    #else
        qDebug() << "Your Harukamirai does not have this processor support! Contact support.";
    #endif


    if (disasm) delete disasm;

    if (ucOpcodes) delete []ucOpcodes;

    CloseHandle(hThread);

    //Adjusting the Table Cursor by the RIP Index
    QModelIndex index = model->index(static_cast<int>(ripTblIndex), 3);

    if (index.isValid()) engCfg.tblDisasm->scrollTo(index, QAbstractItemView::PositionAtCenter);

    /*
     * Adjust Columns and Rows Sizes
    */
    this->m_guiCfg.tblDisasmVw->resizeColumnsToContents();

    this->m_guiCfg.tblDisasmVw->resizeRowsToContents();

    this->m_guiCfg.tblDisasmVw->horizontalHeader()->resizeSection(3, 100); //Info Column Display

    this->m_guiCfg.tblDisasmVw->horizontalHeader()->resizeSection(2, 360); //Disasm Column Display

    this->m_guiCfg.tblDisasmVw->horizontalHeader()->resizeSection(1, 100); //Opcodes Column Display

}

auto DebuggerEngine::ReadMemory(uintptr_t pAddress, unsigned char* ucMemory, size_t szRead) -> bool {

    return ReadProcessMemory(this->m_processInfo.second.hProcess, reinterpret_cast<PVOID>(pAddress), ucMemory, szRead, NULL);
}

auto DebuggerEngine::IsPE(uintptr_t pAddress) -> bool {

    unsigned char ucMz[2]{ 0 }, ucMzVaid[2]{ 0x4D, 0x5A };

    if (!this->ReadMemory(pAddress, ucMz, 2)) return false;

    return std::memcmp(ucMz, ucMzVaid, 2) == 0;
}

auto DebuggerEngine::updateRegistersContext(const DWORD dwTID) -> void {

    auto hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwTID);

    #if defined(__aarch64__) || defined(_M_ARM64)

        ARM64_NT_CONTEXT context;

        ZeroMemory(&context, sizeof(ARM64_NT_CONTEXT));
        context.ContextFlags = CONTEXT_ALL;

        auto bSucess = GetThreadContext(hThread, reinterpret_cast<LPCONTEXT>(&context));

        if (!GetThreadContext(hThread, reinterpret_cast<LPCONTEXT>(&context))) {

            this->AddStringToListView(this->m_guiCfg.lstRegisters, "ERROR WHILE TRYING TO RECOVER REGISTERS FOR THIS BREAKPOINT LOCATION.");

            return;
        }


        const std::vector<std::pair<const char*, uint64_t>> arm64GeneralRegisters = {

            {"X0", context.X0},
            {"X1", context.X1},
            {"X2", context.X2},
            {"X3", context.X3},
            {"X4", context.X4},
            {"X5", context.X5},
            {"X6", context.X6},
            {"X7", context.X7},
            {"X8", context.X8},
            {"X9", context.X9},
            {"X10", context.X10},
            {"X11", context.X11},
            {"X12", context.X12},
            {"X13", context.X13},
            {"X14", context.X14},
            {"X15", context.X15},
            {"X16", context.X16},
            {"X17", context.X17},
            {"X18", context.X18},
            {"X19", context.X19},
            {"X20", context.X20},
            {"X21", context.X21},
            {"X22", context.X22},
            {"X23", context.X23},
            {"X24", context.X24},
            {"X25", context.X25},
            {"X26", context.X26},
            {"X27", context.X27},
            {"X28", context.X28},
            {"FP", context.Fp},
            {"LR", context.Lr},
            {"PC", context.Pc},
            {"SP", context.Sp}

        };

        for (const auto& [regName, regValue] : arm64GeneralRegisters) {

            AddStringToListView(

                this->m_guiCfg.lstRegisters,

                QString::asprintf(
                    "%s: 0x%016llX",
                    regName,
                    regValue
                )

            );

        }

        this->AddStringToListView(this->m_guiCfg.lstRegisters, QString::asprintf("CPSR: %08X", context.Cpsr));

        //TODO: Explorar demais registradores diponíveis, ELR, SPSR, BCR etc

        auto callstack = UtilsWindowsSyscall::updateCallStackContext(

            this->hInternalDebugHandle,
            hThread,
            context.Pc,
            context.Fp,
            context.Sp,
            &context,
            IMAGE_FILE_MACHINE_ARM64

        );

    #elif defined(__x86_64__) || defined(_M_X64)

        CONTEXT context;

        ZeroMemory(&context, sizeof(CONTEXT));
        context.ContextFlags = CONTEXT_ALL;

        if (!GetThreadContext(hThread, reinterpret_cast<LPCONTEXT>(&context))) {

            this->AddStringToListView(this->m_guiCfg.lstRegisters, "ERROR WHILE TRYING TO RECOVER REGISTERS FOR THIS BREAKPOINT LOCATION.");

            return;
        }

        const std::vector<std::pair<const char*, uint64_t>> generalPurposeRegisters = {

            {"RAX", context.Rax},
            {"RBX", context.Rbx},
            {"RCX", context.Rcx},
            {"RBP", context.Rbp},
            {"RSP", context.Rsp},
            {"RSI", context.Rsi},
            {"RDI", context.Rdi},
            {"R8", context.R8},
            {"R9", context.R9},
            {"R10", context.R10},
            {"R11", context.R11},
            {"R12", context.R12},
            {"R13", context.R13},
            {"R14", context.R14},
            {"R15", context.R15},
            {"RIP", context.Rip}

        };

        for (const auto& [regName, regValue] : generalPurposeRegisters) {

            this->AddStringToListView(

                this->m_guiCfg.lstRegisters,

                QString::asprintf(
                    "%s: 0x%016llX",
                    regName,
                    regValue
                    )
            );

        }

        this->AddStringToListView(this->m_guiCfg.lstRegisters, QString(
                                                                   "EFLAGS: 0x%1(TO PARSE FIELDS)"
                                                                   ).arg(QString::asprintf("%016llX", context.EFlags)));

        this->AddStringToListView(this->m_guiCfg.lstRegisters, QString(
                                                                   "CS: 0x%1 | GS: 0x%2 | ES: 0x%3 | SS: 0x%4 | DS: 0x%5 | FS: 0x%6"
                                                                   ).arg(
                                                                       QString::asprintf("%04X", context.SegCs),
                                                                       QString::asprintf("%04X", context.SegGs),
                                                                       QString::asprintf("%04X", context.SegEs),
                                                                       QString::asprintf("%04X", context.SegSs),
                                                                       QString::asprintf("%04X", context.SegDs),
                                                                       QString::asprintf("%04X", context.SegFs)
                                                                   ));

        const char* xmmRegisters[] = {

            "XMM0", "XMM1", "XMM2", "XMM3",
            "XMM4", "XMM5", "XMM6", "XMM7",
            "XMM8", "XMM9", "XMM10", "XMM11",
            "XMM12", "XMM13", "XMM14", "XMM15"

        };

        const M128A xmmRegistersContext[] = {

            context.Xmm0, context.Xmm1, context.Xmm2, context.Xmm3,
            context.Xmm4, context.Xmm5, context.Xmm6, context.Xmm7,
            context.Xmm8, context.Xmm9, context.Xmm10, context.Xmm11,
            context.Xmm12, context.Xmm13, context.Xmm14, context.Xmm15

        };

        for (size_t i = 0; i < 16; ++i) {

            const auto& reg = xmmRegistersContext[i];

            this->AddStringToListView(

                this->m_guiCfg.lstRegisters,
                QString::asprintf(
                    "%s: 0x%016llX%016llX",
                    xmmRegisters[i],
                    reg.High,
                    reg.Low
                    )

                );

        }

        const std::vector<std::pair<const char*, uint64_t>> debugRegisters = {

            {"DR0", context.Dr0},
            {"DR1", context.Dr1},
            {"DR2", context.Dr2},
            {"DR3", context.Dr3},
            {"DR6", context.Dr6},
            {"DR7", context.Dr7}

        };

        for (const auto& [regName, regValue] : debugRegisters) {

            this->AddStringToListView(

                this->m_guiCfg.lstRegisters,

                QString::asprintf(
                    "%s: 0x%016llX",
                    regName,
                    regValue
                    )
            );

        }

        //TODO: PROGRAMAR REGISTRADORES YMM, EXPLORAR TODOS OS REGISTRADORES DISPONÍVEIS NA CONTEXT

        auto callstack = UtilsWindowsSyscall::updateCallStackContext(

            this->hInternalDebugHandle,
            hThread,
            context.Rip,
            context.Rbp,
            context.Rsp,
            &context,
            IMAGE_FILE_MACHINE_AMD64

        );

    #else
        qDebug() << "Unsuported Processor, hows this guy running it ? is your moding our software ? request support for this processor via formal support!";
    #endif

    this->AddStringToListView(

        this->m_guiCfg.lstCallStack,
        QString::asprintf(

            "CallStack Tracing for TID: 0x%08llX",
            GetThreadId(hThread)

        )

    );

    for (auto i = 0; i < callstack.first.size(); i++) {

        this->AddStringToListView(

            this->m_guiCfg.lstCallStack,

            "           " + callstack.second[i] + QString::asprintf(
            "@0x%016llX",
            callstack.first[i]

            )

        );

    }

    this->updateStackContext(dwTID);

    //Sending event after the list is properly rendered on the screen to adjust stack midle
    auto listView = this->m_guiCfg.lstStack;
    QAbstractItemModel* model = listView->model();

    // Run on a new thread with QtConcurrent::run to avoid pointer shit leak
    QThreadPool::globalInstance()->start([listView, model]() {

        QMetaObject::invokeMethod(listView, [listView, model]() {

                QModelIndex index = model->index(512, 0);
                listView->scrollTo(index, QAbstractItemView::PositionAtCenter);

            }, Qt::QueuedConnection);

    });

    CloseHandle(hThread);
}

auto DebuggerEngine::updateStackContext(const DWORD dwTID) -> void {

    uintptr_t ptrStackPointer{ 0 }, AddressModeSize{ 0 };

    auto hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwTID);

    #if defined(__aarch64__) || defined(_M_ARM64)

        ARM64_NT_CONTEXT context;

        ZeroMemory(&context, sizeof(CONTEXT));
        context.ContextFlags = CONTEXT_ALL;

        if (!GetThreadContext(hThread, reinterpret_cast<LPCONTEXT>(&context))) {

            this->AddStringToListView(this->m_guiCfg.lstStack, "ERROR WHILE TRYING TO RECOVER STACK LOCATION.");

            return;
        }

        this->AddStringToListView(

            this->m_guiCfg.lstStack,

            QString::asprintf(
                "0x%016llX",
                context.Sp
                )

        );

        ptrStackPointer = context.Sp;
        AddressModeSize = 8;

    #elif defined(__x86_64__) || defined(_M_X64)

        CONTEXT context;

        ZeroMemory(&context, sizeof(CONTEXT));
        context.ContextFlags = CONTEXT_ALL;

        if (!GetThreadContext(hThread, reinterpret_cast<LPCONTEXT>(&context))) {

            this->AddStringToListView(this->m_guiCfg.lstStack, "ERROR WHILE TRYING TO RECOVER STACK LOCATION.");

            return;
        }

        ptrStackPointer = context.Rsp;
        AddressModeSize = 8;

    #else
    #endif

    //Renderizar a stack:
    //0xFFA -> - endereço de RSP lendo cada endereço de 8 bytes
    //valor de RSP -> -ler o endereço e representar
    //0xFFA -> + endereço de RSP lendo cada endereço de 8 bytes
    auto endValue = ptrStackPointer - 0xFFA; //Último endereço multiplo de 8
        for (auto i = endValue; i <= ptrStackPointer; i += AddressModeSize) {
        uintptr_t ptrStack{ 0 };
        ReadMemory(i+2, reinterpret_cast<unsigned char*>(&ptrStack), sizeof(uintptr_t)); // i Tem dois bytes de diferença na leitura.

        QString str = UtilsWindowsSyscall::symbol_from_address(this->hInternalDebugHandle, ptrStack);

        this->AddStringToListView(
            this->m_guiCfg.lstStack,
            QString::asprintf(
                "0x%016llX | 0x%016llX",
                i,
                ptrStack
                ) + str
            );

    }

    this->AddStringToListView(
        this->m_guiCfg.lstStack,
        QString::asprintf(
            "[SP-POINTER]0x%016llX",
            ptrStackPointer
        )
    );

    for (auto i = ptrStackPointer; i < ptrStackPointer + 0xFFA; i += AddressModeSize) {
        uintptr_t ptrStack{ 0 };
        ReadMemory(i, reinterpret_cast<unsigned char*>(&ptrStack), sizeof(uintptr_t));

        QString str = UtilsWindowsSyscall::symbol_from_address(this->hInternalDebugHandle, ptrStack);

        this->AddStringToListView(
            this->m_guiCfg.lstStack,
            QString::asprintf(
                "0x%016llX | 0x%016llX",
                i,
                ptrStack
            ) + str
        );
    }

    CloseHandle(hThread);

}

auto DebuggerEngine::AnalyseDebugProcessVirtualMemory() -> void {

    auto GetMemoryType = [](DWORD dwType) -> QString {

        if (dwType & MEM_PRIVATE) return "Private";
        else if (dwType & MEM_MAPPED) return "Mapped";
        else if (dwType & MEM_IMAGE) return "Image";

        return "Unknown";
    };

    auto GetMemoryState = [](DWORD dwState) -> QString {

        if (dwState & MEM_COMMIT) return "Commit";
        else if (dwState & MEM_RESERVE) return "Reserved";
        else if (dwState & MEM_FREE) return "Free";
        return "Unknown";

    };

    auto GetMemoryProtection = [](DWORD dwProtection) -> QString {

        QString str = "";

        if (dwProtection & PAGE_NOACCESS) str = "NA";
        else if (dwProtection & PAGE_READONLY) str = "R";
        else if (dwProtection & PAGE_READWRITE) str = "RW";
        else if (dwProtection & PAGE_WRITECOPY) str = "WC";
        else if (dwProtection & PAGE_EXECUTE) str = "X";
        else if (dwProtection & PAGE_EXECUTE_READ) str = "RX";
        else if (dwProtection & PAGE_EXECUTE_READWRITE) str = "RWX";
        else if (dwProtection & PAGE_EXECUTE_WRITECOPY) str = "WCX";
        else str = "?";

        if (dwProtection & PAGE_GUARD) str += "+G";

        if (dwProtection & PAGE_NOCACHE) str += "+NC";

        if (dwProtection & PAGE_WRITECOMBINE) str += "+WCM";

        return str;

    };

    QStandardItemModel* model;

    if (!this->m_guiCfg.tblMemoryView->model()) {
        model = new QStandardItemModel();

        this->m_guiCfg.tblMemoryView->setModel(model);

        model->setHorizontalHeaderLabels(QStringList() << "Base Address" << "Mapped File Name");
    } else {
        model = qobject_cast<QStandardItemModel*>(this->m_guiCfg.tblMemoryView->model());

        if (!model) {
            qDebug() << "The model is not of type QStandardItemModel!";
            return;
        }
    }

    model->clear();

    model->setHorizontalHeaderLabels(QStringList() << "Start Address" << "Size" << "Information" << "Type" << "State" << "Protection");

    BOOL bHvSharedData = TRUE;
    WCHAR wchInformation[MAX_PATH]{ 0 };
    MEMORY_BASIC_INFORMATION mb{0};
    uintptr_t uipStartAddress{ 0 };
    while (VirtualQueryEx(this->hInternalDebugHandle, reinterpret_cast<LPVOID>(uipStartAddress), &mb, sizeof(mb))) {

        GetMappedFileNameW(this->hInternalDebugHandle, reinterpret_cast<LPVOID>(uipStartAddress), wchInformation, sizeof(wchInformation));

        /*
         * Checking for X64 and ARM64 KUSER_SHARED_DATA_ADDRESS
         * https://redplait.blogspot.com/2020/04/pskernelrangelist-on-arm64-kernel.html
         * https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-kuser_shared_data
         */
        if (uipStartAddress == 0x7FFE0000) wcscpy_s(wchInformation, MAX_PATH, L"KUSER_SHARED_DATA");

        //HYPERVISOR_SHARED_DATA on X86_64
        //HYPERVISOR_SHARED_DATA on ARM64
        // The logic is dicovery true and the second size with 4 kb for the page.
        else if (bHvSharedData && mb.RegionSize/1000 == 4) {

            wcscpy_s(wchInformation, MAX_PATH, L"HYPERVISOR_SHARED_DATA");

            bHvSharedData = FALSE;
        }

        if (uipStartAddress != 0) {

            DebugMemory dbgMem(reinterpret_cast<uintptr_t>(mb.BaseAddress), QString(wchInformation), GetMemoryType(mb.Type), GetMemoryState(mb.State), GetMemoryProtection(mb.Protect), mb.RegionSize/1000);

            model->appendRow(QList<QStandardItem*>() << new QStandardItem(QString::number(dbgMem.m_uipStartAddress, 16).toUpper())
                                                     << new QStandardItem(QString::number(dbgMem.m_szPage, 10).toUpper() + " KB")
                                                     << new QStandardItem(QString(dbgMem.m_strInformation))
                                                     << new QStandardItem(dbgMem.m_strType)
                                                     << new QStandardItem(dbgMem.m_strState)
                                                     << new QStandardItem(dbgMem.m_strProtection)
            );

            this->m_debugMemory.push_back(dbgMem);

        }

        uipStartAddress += mb.RegionSize;
        std::memset(wchInformation, 0, MAX_PATH);
    }

    /*
     * Adjust Columns and Rows Sizes
    */
    this->m_guiCfg.tblMemoryView->resizeColumnsToContents();

    this->m_guiCfg.tblMemoryView->resizeRowsToContents();

}

auto DebuggerEngine::ListAllHandleObjectsForDebugeeProcess() -> void {

    QStandardItemModel* model;

    if (!this->m_guiCfg.tblHandles->model()) {
        model = new QStandardItemModel();

        this->m_guiCfg.tblHandles->setModel(model);

    } else {
        model = qobject_cast<QStandardItemModel*>(this->m_guiCfg.tblHandles->model());

        if (!model) {
            qDebug() << "The model is not of type QStandardItemModel!";
            return;
        }
    }

    model->clear();

    model->setHorizontalHeaderLabels(QStringList() << "Handle" << "Type" << "Name");

    auto vecDebugerHandles = UtilsWindowsSyscall::GetDebuggerProcessHandleTable(this->m_processInfo.second.dwProcessId);

    for (auto handle : vecDebugerHandles) {

        auto [handleOriginal, typeLength, typeBuffer, nameLength, nameBuffer] = UtilsWindowsSyscall::GetRemoteHandleTableHandleInformation(this->m_processInfo.second.dwProcessId, handle);

        DebugHandle dbgHandle(handleOriginal, QString(typeBuffer), QString(nameBuffer), typeLength, nameLength);

        //Checking for invalid handles, not duplicated and with no info or errors.
        if (dbgHandle.m_hValue == INVALID_HANDLE_VALUE) continue;

        model->appendRow(QList<QStandardItem*>() << new QStandardItem(QString::number(reinterpret_cast<uintptr_t>(handleOriginal), 16).toUpper())
                                                 << new QStandardItem(QString(typeBuffer))
                                                 << new QStandardItem(QString(nameBuffer))
        );

        this->m_debugHandles.push_back(dbgHandle);

    }

    /*
     * Adjust Columns and Rows Sizes
    */
    this->m_guiCfg.tblHandles->resizeColumnsToContents();

    this->m_guiCfg.tblHandles->resizeRowsToContents();

}

auto DebuggerEngine::SetInterrupting(uintptr_t uipAddressBreak, bool isHardware) -> void {

    qDebug() << "DebuggerEngine::SetInterrupting";

    QStandardItemModel* model;

    if (!this->m_guiCfg.tblInterrupts->model()) {
        model = new QStandardItemModel();

        this->m_guiCfg.tblInterrupts->setModel(model);

    } else {
        model = qobject_cast<QStandardItemModel*>(this->m_guiCfg.tblInterrupts->model());

        if (!model) {
            qDebug() << "The model is not of type QStandardItemModel!";
            return;
        }
    }

    model->setHorizontalHeaderLabels(QStringList() << "Address of Interruption" << "Interruption Type");

    int maxHWBreakByArch = 0;

    #if defined(__aarch64__) || defined(_M_ARM64)

        ////https://aarzilli.github.io/debugger-bibliography/hwbreak.html
        maxHWBreakByArch = ARM64_MAX_BREAKPOINTS;

        if (isHardware) {

            if (this->m_hardwareDebugControl <= maxHWBreakByArch) {

                qDebug() << "BVR + BCR -> " << QString::number(uipAddressBreak, 16);

                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, this->m_processInfo.second.dwThreadId);

                SuspendThread(hThread);

                ARM64_NT_CONTEXT context;

                ZeroMemory(&context, sizeof(CONTEXT));
                context.ContextFlags = CONTEXT_ALL;

                GetThreadContext(hThread, reinterpret_cast<LPCONTEXT>(&context));

                context.Bvr[this->m_hardwareDebugControl] = uipAddressBreak;
                context.Bcr[this->m_hardwareDebugControl] = BCR_BAS_ALL | BCR_E; //Breakpoint enable flags

                SetThreadContext(hThread, reinterpret_cast<LPCONTEXT>(&context));

                this->m_hardwareDebugControl++;

                ResumeThread(hThread);

                CloseHandle(hThread);

                auto dbgBreakpoint = new DebugBreakpoint(uipAddressBreak, 0x00, -1, InterruptType::BREAK_HW);

                this->m_debugBreakpoint.push_back(dbgBreakpoint);

            } else
                this->m_guiCfg.statusbar->showMessage("[Important] Maximum HW Interrupts defined for your arch!!! please release some resources to set new ones!", 10000);

        }
        else {
            qDebug() << "BRK #0xF000 -> " << QString::number(uipAddressBreak, 16);

            auto ucBrkIntb = new unsigned char[4] { 0 };
            ReadProcessMemory(this->m_processInfo.second.hProcess, reinterpret_cast<PVOID>(uipAddressBreak), ucBrkIntb, 4, FALSE);

            DWORD ucBRKF000 = 0xD43E0000;
            WriteProcessMemory(this->m_processInfo.second.hProcess, reinterpret_cast<PVOID>(uipAddressBreak), &ucBRKF000, sizeof(DWORD), FALSE);

            auto dbgBreakpoint = new DebugBreakpoint(uipAddressBreak, ucBrkIntb, 4, InterruptType::BREAK_INT);

            this->m_debugBreakpoint.push_back(dbgBreakpoint);
        }

    #elif defined(__x86_64__) || defined(_M_X64)

        maxHWBreakByArch = 4;

        if (isHardware) {

            if (this->m_hardwareDebugControl <= maxHWBreakByArch) {

                qDebug() << "DR0-DR4, DR7 -> " << QString::number(uipAddressBreak, 16);

                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, this->m_processInfo.second.dwThreadId);

                SuspendThread(hThread);

                CONTEXT context;

                ZeroMemory(&context, sizeof(CONTEXT));
                context.ContextFlags = CONTEXT_ALL;

                GetThreadContext(hThread, &context);

                context.Dr0 = uipAddressBreak;

                context.Dr7 = context.Dr7 | 0b00000000000000000000000000000001;

                if (this->m_hardwareDebugControl == 0) context.Dr0 = uipAddressBreak;
                if (this->m_hardwareDebugControl == 1) context.Dr1 = uipAddressBreak;
                if (this->m_hardwareDebugControl == 2) context.Dr2 = uipAddressBreak;
                if (this->m_hardwareDebugControl == 3) context.Dr3 = uipAddressBreak;

                if (this->m_hardwareDebugControl == 0) context.Dr7 |= 0b00000000000000000000000000000001; // Enable DR0
                if (this->m_hardwareDebugControl == 1) context.Dr7 |= 0b00000000000000000000000000000010; // Enable DR1
                if (this->m_hardwareDebugControl == 2) context.Dr7 |= 0b00000000000000000000000000001100; // Enable DR2
                if (this->m_hardwareDebugControl == 3) context.Dr7 |= 0b00000000000000000000000000010000; // Enable DR3

                // Set the breakpoint types for DR0, DR1, DR2, DR3 (0b11 for execute, 0b01 for write, 0b10 for read/write)
                context.Dr7 |= (0b11 << 0) | (0b11 << 2) | (0b11 << 4) | (0b11 << 6);

                SetThreadContext(hThread, &context);

                auto dbgBreakpoint = new DebugBreakpoint(uipAddressBreak, 0x00, -1, InterruptType::BREAK_HW);

                this->m_debugBreakpoint.push_back(dbgBreakpoint);

                this->m_hardwareDebugControl++;

                ResumeThread(hThread);

                CloseHandle(hThread);

            } else
                this->m_guiCfg.statusbar->showMessage("[Important] Maximum HW Interrupts defined for your arch!!! please release some resources to set new ones!", 10000);


        } else {

            qDebug() << "INT3 -> " << QString::number(uipAddressBreak, 16);

            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, this->m_processInfo.second.dwThreadId);

            SuspendThread(hThread);

            //unsigned char ucInt3b[4] { 0 };
            auto ucInt3b = new unsigned char[4]{ 0 };
            ReadProcessMemory(this->m_processInfo.second.hProcess, reinterpret_cast<PVOID>(uipAddressBreak), ucInt3b, 4, FALSE);

            unsigned char ucInt3 { 0xCC };
            WriteProcessMemory(this->m_processInfo.second.hProcess, reinterpret_cast<PVOID>(uipAddressBreak), &ucInt3, 1, FALSE);

            FlushInstructionCache(this->m_processInfo.second.hProcess, reinterpret_cast<PVOID>(uipAddressBreak), 1);

            auto dbgBreakpoint = new DebugBreakpoint(uipAddressBreak, ucInt3b, 4, InterruptType::BREAK_INT);

            this->m_debugBreakpoint.push_back(dbgBreakpoint);

            ResumeThread(hThread);

            CloseHandle(hThread);

        }

    #endif


    if ((isHardware && this->m_hardwareDebugControl <= maxHWBreakByArch) || !isHardware)

        model->appendRow(QList<QStandardItem*>() << new QStandardItem(QString::number(uipAddressBreak, 16).toUpper())
                                                  << (isHardware ? new QStandardItem(QString("Hardware")) : new QStandardItem(QString("Software")))
        );



    /*
     * Adjust Columns and Rows Sizes
    */
    this->m_guiCfg.tblInterrupts->resizeColumnsToContents();

    this->m_guiCfg.tblInterrupts->resizeRowsToContents();

}

auto DebuggerEngine::UpdateActualIPContext(uintptr_t uipAddressToIP) -> void {

    qDebug() << "DebuggerEngine::UpdateActualIPContext";

    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, this->m_processInfo.second.dwThreadId);

    SuspendThread(hThread);

    #if defined(__aarch64__) || defined(_M_ARM64)

        ARM64_NT_CONTEXT context;

        ZeroMemory(&context, sizeof(CONTEXT));
        context.ContextFlags = CONTEXT_CONTROL;

        GetThreadContext(hThread, reinterpret_cast<LPCONTEXT>(&context));

        context.Pc = uipAddressToIP;

        SetThreadContext(hThread, reinterpret_cast<LPCONTEXT>(&context));

    #elif defined(__x86_64__) || defined(_M_X64)

        CONTEXT context;

        ZeroMemory(&context, sizeof(CONTEXT));
        context.ContextFlags = CONTEXT_CONTROL;

        GetThreadContext(hThread, &context);

        context.Rip = uipAddressToIP;

        SetThreadContext(hThread, &context);

    #else
    #endif

    ResumeThread(hThread);

    CloseHandle(hThread);

    this->DeleteAllDebuggerContext();

    this->UpdateAllDebuggerContext(this->m_processInfo.second.dwThreadId);

    this->m_debugRule = DebuggerEngine::BKPT_CONTINUE;

}

auto DebuggerEngine::stepOver() -> void {

    qDebug() << "DebuggerEngine::stepOver";

    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, this->m_processInfo.second.dwThreadId);

    SuspendThread(hThread);

    #if defined(__aarch64__) || defined(_M_ARM64)

        ARM64_NT_CONTEXT context;

        ZeroMemory(&context, sizeof(CONTEXT));
        context.ContextFlags = CONTEXT_CONTROL;

        GetThreadContext(hThread, reinterpret_cast<LPCONTEXT>(&context));

        context.Cpsr |= 0x200000; // Set the T-bit in the Current Program Status Register (CPSR) for single-stepping -> https://stackoverflow.com/a/69487245

        SetThreadContext(hThread, reinterpret_cast<LPCONTEXT>(&context));

    #elif defined(__x86_64__) || defined(_M_X64)

        CONTEXT context;

        ZeroMemory(&context, sizeof(CONTEXT));
        context.ContextFlags = CONTEXT_CONTROL;

        GetThreadContext(hThread, &context);

        context.EFlags |= 0x100; // Set the Trap Flag (TF) in EFlags for single-stepping

        SetThreadContext(hThread, &context);

    #endif

    ResumeThread(hThread);

    CloseHandle(hThread);

    this->m_debugRule = DebuggerEngine::BKPT_CONTINUE;

    this->m_debugCommand = DebuggerEngine::RUNNING;

}

auto DebuggerEngine::stepOut() -> void {

    qDebug() << "DebuggerEngine::stepOut";

    auto hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, this->m_processInfo.second.dwThreadId);

    DWORD64 Ip = 0;

    #if defined(__aarch64__) || defined(_M_ARM64)

        ARM64_NT_CONTEXT ctx;

        ZeroMemory(&ctx, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_CONTROL;

        GetThreadContext(hThread, reinterpret_cast<LPCONTEXT>(&ctx));

        Ip = ctx.Pc;

    #elif defined(__x86_64__) || defined(_M_X64)

        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_ALL;

        GetThreadContext(hThread, &ctx);

        Ip = ctx.Rip;

    #endif

    MEMORY_BASIC_INFORMATION mb{ 0 };

    VirtualQueryEx(this->hInternalDebugHandle, reinterpret_cast<PVOID>(Ip), &mb, sizeof(mb));

    auto szBefore = Ip - reinterpret_cast<uintptr_t>(mb.AllocationBase);

    auto szToAnalyze = mb.RegionSize - szBefore;

    if (szToAnalyze <= 0) return; //O resultado para analise é negativo.

    auto ucOpcodes = new unsigned char [szToAnalyze]{ 0 };

    if(!this->ReadMemory(Ip, ucOpcodes, szToAnalyze)) return; //Não foi possível ler a memória.

    DisassemblerEngine* disasm = new DisassemblerEngine();

    #if defined(__aarch64__) || defined(_M_ARM64)
        auto addressToInterrupt = disasm->RunCapstoneForStepOutARM64(Ip, ucOpcodes, szToAnalyze);
    #elif defined(__x86_64__) || defined(_M_X64)
        auto addressToInterrupt = disasm->RunCapstoneForStepOutx86(Ip, ucOpcodes, szToAnalyze);
    #endif

    qDebug() << "[DebuggerEngine::InsideContext::FuckingAnalysisEngine::StepOutAnalyzes] candidate result: " << QString::number(addressToInterrupt, 16);

    if (!addressToInterrupt) this->m_guiCfg.statusbar->showMessage("[Important] We cannot found some candidate for Step Out!", 10000);
    else this->SetInterrupting(addressToInterrupt, FALSE); //Call to set a new interrupt for software

    delete disasm;

    delete[] ucOpcodes;

    this->m_debugRule = DebuggerEngine::BKPT_CONTINUE;

    this->m_debugCommand = DebuggerEngine::RUNNING;
}

auto DebuggerEngine::RemoveInterrupting(DebugBreakpoint* debug) -> void {

    if (debug->m_intType == InterruptType::BREAK_HW) {

        qDebug() << "InterruptType::BREAK_HW";

        auto hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, this->m_processInfo.second.dwThreadId);

        SuspendThread(hThread);

    #if defined(__aarch64__) || defined(_M_ARM64)

        ARM64_NT_CONTEXT context;

        ZeroMemory(&context, sizeof(CONTEXT));
        context.ContextFlags = CONTEXT_ALL;

        GetThreadContext(hThread, reinterpret_cast<LPCONTEXT>(&context));

        for (auto i = 0; i < ARM64_MAX_BREAKPOINTS; i++) {

            if (context.Bvr[i] == debug->m_ptrBreakpointAddress) {

                context.Bvr[i] = 0;
                context.Bcr[i] = 0;

                break;
            }

        }

        SetThreadContext(hThread, reinterpret_cast<LPCONTEXT>(&context));

    #elif defined(__x86_64__) || defined(_M_X64)

        CONTEXT context;

        ZeroMemory(&context, sizeof(CONTEXT));
        context.ContextFlags = CONTEXT_ALL;
        GetThreadContext(hThread, &context);

        if (context.Dr0 == debug->m_ptrBreakpointAddress) {

            context.Dr0 = 0;
            context.Dr7 &= ~0b00000000000000000000000000000001; // Clear DR0

        }else if (context.Dr1 == debug->m_ptrBreakpointAddress) {

            context.Dr1 = 0;
            context.Dr7 &= ~0b00000000000000000000000000000010; // Clear DR1

        }else if (context.Dr2 == debug->m_ptrBreakpointAddress) {

            context.Dr2 = 0;
            context.Dr7 &= ~0b00000000000000000000000000001100; // Clear DR2

        }else if (context.Dr3 == debug->m_ptrBreakpointAddress) {

            context.Dr3 = 0;
            context.Dr7 &= ~0b00000000000000000000000000010000; // Clear DR3

        }

        SetThreadContext(hThread, &context);

    #endif

        this->m_debugRule = DebuggerEngine::CurrentDebuggerRule::BKPT_CONTINUE;

        ResumeThread(hThread);

        CloseHandle(hThread);

    }else {

        qDebug() << "InterruptType::BREAK_INT" ;

        auto hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, this->m_processInfo.second.dwThreadId);

        SuspendThread(hThread);

    #if defined(__aarch64__) || defined(_M_ARM64)

        ARM64_NT_CONTEXT context;

        ZeroMemory(&context, sizeof(CONTEXT));
        context.ContextFlags = CONTEXT_ALL;

        GetThreadContext(hThread, reinterpret_cast<LPCONTEXT>(&context));

        context.Pc = context.Pc - 4;

        SetThreadContext(hThread, reinterpret_cast<LPCONTEXT>(&context));

    #elif defined(__x86_64__) || defined(_M_X64)

        CONTEXT context;

        ZeroMemory(&context, sizeof(CONTEXT));
        context.ContextFlags = CONTEXT_ALL;

        GetThreadContext(hThread, &context);

        context.Rip = context.Rip - 1;

        SetThreadContext(hThread, &context);

    #endif

        WriteProcessMemory(this->hInternalDebugHandle, reinterpret_cast<PVOID>(debug->m_ptrBreakpointAddress), debug->m_ucOriginalOpcodes, debug->m_szOriginalOpcodes, NULL);

        FlushInstructionCache(this->hInternalDebugHandle, reinterpret_cast<PVOID>(debug->m_ptrBreakpointAddress), 4);

        this->m_debugRule = DebuggerEngine::CurrentDebuggerRule::BKPT_CONTINUE;

        ResumeThread(hThread);

        CloseHandle(hThread);

    }

}
