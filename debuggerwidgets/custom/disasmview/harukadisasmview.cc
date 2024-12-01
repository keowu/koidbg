/*
    File: harukadisasmview.cc
    Author: João Vitor(@Keowu)
    Created: 24/08/2024
    Last Update: 01/12/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#include "debuggerwidgets/custom/disasmview/harukadisasmview.hh"
#include "debuggerwidgets/patchs/patchCode.hh"
#include <QAction>
#include <QDebug>

HarukaDisasmView::HarukaDisasmView(QWidget *parent)
    : QTableView(parent) {

}

auto HarukaDisasmView::configureDisasm(QHexView* qHexVw[3], QTextEdit* txtDecompiler, QTabWidget* qTabHaruka, HANDLE hProcessInternal, BreakPointCallback setBreakPointCallback, SetIPCallback setIPCallback, SetPatching setPatching) -> void {

    std::memcpy(this->m_qHexVw, qHexVw, sizeof(QHexView*) * 3);

    this->m_txtDecompiler = txtDecompiler;

    this->m_qTabHaruka = qTabHaruka;

    this->m_hProcessInternal = hProcessInternal;

    this->m_setBreakPointCallback = setBreakPointCallback;

    this->m_setIPCallback = setIPCallback;

    this->m_setPatchingCallback = setPatching;

    if (this->m_decompilerSyntax) delete m_decompilerSyntax;

}

void HarukaDisasmView::contextMenuEvent(QContextMenuEvent *event) {

    QMenu contextMenu(this);

    QAction *actionSftInterrupt = contextMenu.addAction("Set SFT Interrupt");
    QAction *actionHwInterrupt = contextMenu.addAction("Set HW Interrupt");
    QAction *actionMemoryInspector1 = contextMenu.addAction("Follow in Memory Inspector 1");
    QAction *actionMemoryInspector2 = contextMenu.addAction("Follow in Memory Inspector 2");
    QAction *actionMemoryInspector3 = contextMenu.addAction("Follow in Memory Inspector 3");
    QAction *actionSetIp = contextMenu.addAction("Set IP to this location");
    QAction *actionDecompile = contextMenu.addAction("Decompile to Pseudo-C");
    QAction *actionPatch = contextMenu.addAction("Modify Code");

    connect(actionSftInterrupt, &QAction::triggered, this, &HarukaDisasmView::onSoftwareInterrupt);
    connect(actionHwInterrupt, &QAction::triggered, this, &HarukaDisasmView::onHardwareInterrupt);
    connect(actionMemoryInspector1, &QAction::triggered, this, &HarukaDisasmView::onMemoryInspector1);
    connect(actionMemoryInspector2, &QAction::triggered, this, &HarukaDisasmView::onMemoryInspector2);
    connect(actionMemoryInspector3, &QAction::triggered, this, &HarukaDisasmView::onMemoryInspector3);
    connect(actionSetIp, &QAction::triggered, this, &HarukaDisasmView::onActionSetIp);
    connect(actionDecompile, &QAction::triggered, this, &HarukaDisasmView::onDecompileToPseudoC);
    connect(actionPatch, &QAction::triggered, this, &HarukaDisasmView::onPatchCode);


    contextMenu.exec(event->globalPos());
}

void HarukaDisasmView::onSoftwareInterrupt() {

    auto index = currentIndex();

    if (index.isValid()) {

        auto column0Index = index.model()->index(index.row(), 0);

        auto addressString = column0Index.data().toString();

        addressString.remove("0x");

        bool bConverted;
        auto address = addressString.toULongLong(&bConverted, 16);

        if (bConverted) {

            this->m_setBreakPointCallback(address, FALSE);

        }

    }
}

void HarukaDisasmView::onHardwareInterrupt() {

    auto index = currentIndex();

    if (index.isValid()) {

        auto column0Index = index.model()->index(index.row(), 0);

        auto addressString = column0Index.data().toString();

        addressString.remove("0x");

        bool bConverted;
        auto address = addressString.toULongLong(&bConverted, 16);

        if (bConverted) {

            this->m_setBreakPointCallback(address, TRUE);

        }

    }
}

void HarukaDisasmView::onMemoryInspector1() {

    auto index = currentIndex();

    if (index.isValid()) {

        auto column0Index = index.model()->index(index.row(), 0);

        this->updateMemoryInspector(this->m_qHexVw[0], column0Index.data().toString());

    }
}

void HarukaDisasmView::onMemoryInspector2() {

    auto index = currentIndex();

    if (index.isValid()) {

        auto column0Index = index.model()->index(index.row(), 0);

        this->updateMemoryInspector(this->m_qHexVw[1], column0Index.data().toString());

    }
}


void HarukaDisasmView::onMemoryInspector3() {

    auto index = currentIndex();

    if (index.isValid()) {

        auto column0Index = index.model()->index(index.row(), 0);

        this->updateMemoryInspector(this->m_qHexVw[2], column0Index.data().toString());

    }
}

auto HarukaDisasmView::updateMemoryInspector(QHexView* memoryInspector, QString addressString) -> void {

    addressString.remove("0x");

    bool bConverted;
    auto address = addressString.toULongLong(&bConverted, 16);

    if (bConverted) {

        auto pAddress = reinterpret_cast<PVOID>(address);

        SIZE_T bytesRead;

        MEMORY_BASIC_INFORMATION mb;
        VirtualQueryEx(this->m_hProcessInternal, pAddress, &mb, sizeof(mb));

        auto buffer = new char[mb.RegionSize]{ 0 };

        if (ReadProcessMemory(this->m_hProcessInternal, pAddress, buffer, mb.RegionSize, &bytesRead)) { } else {

            qDebug() << "ReadProcessMemory failed with error:" << GetLastError();

            return;
        }

        QByteArray byteArray(buffer, static_cast<int>(bytesRead));
        memoryInspector->clear();
        memoryInspector->fromMemoryBuffer(byteArray, reinterpret_cast<uintptr_t>(pAddress), 0);

        delete[] buffer;

    } else qDebug() << "Failed to convert address string to numeric value.";

}

void HarukaDisasmView::onActionSetIp() {

    auto index = currentIndex();

    if (index.isValid()) {

        auto column0Index = index.model()->index(index.row(), 0);

        auto addressString = column0Index.data().toString();

        addressString.remove("0x");

        bool bConverted;
        auto address = addressString.toULongLong(&bConverted, 16);

        if (bConverted) this->m_setIPCallback(address);

    }

}

void HarukaDisasmView::onDecompileToPseudoC() {

    qDebug() << "HarukaDisasmView::onDecompileToPseudoC";

    if (this->m_decompilerSyntax) delete m_decompilerSyntax;

    this->m_decompilerSyntax = new Decompiler(this->m_txtDecompiler->document());

    this->m_txtDecompiler->setEnabled(true);

    #if defined(_M_ARM64) || defined(__arm64__)

    this->m_txtDecompiler->setPlainText(
                                            "Generated with KOTORI DECOMPILER at HarukaMirai - Named License to keowu.re@Fluxuss Software Security, LLC\n\n"
                                            "void unknownDecompiledFunction() {\n"
                                            "    // STP X29, X30, [SP, #-0x30+var_s0]!\n"
                                            "    // STP X19, X20, [SP, #var_s10]\n"
                                            "    // STP X21, X22, [SP, #var_s20]\n"
                                            "    // MOV X29, SP\n"
                                            "    initialize_stack();\n\n"

                                            "    // BL sub_140001060\n"
                                            "    runInitialSetup();\n\n"

                                            "    // ADRP X8, #GetModuleHandleA@PAGE\n"
                                            "    // LDR X8, [X8, #GetModuleHandleA@PAGEOFF]\n"
                                            "    // ADRP X22, #aNtdllDll@PAGE\n"
                                            "    // ADD X0, X22, #aNtdllDll@PAGEOFF\n"
                                            "    // BLR X8\n"
                                            "    void* ntdllModule = getModule(\"ntdll.dll\");\n\n"

                                            "    // MOV X19, X0\n"
                                            "    if (ntdllModule == NULL) {\n"
                                            "        printError(\"Failed to load ntdll.dll\\n\");\n"
                                            "        return;\n"
                                            "    }\n\n"

                                            "    // ADRP X8, #aKiuserexceptio@PAGE\n"
                                            "    // ADD X1, X8, #aKiuserexceptio@PAGEOFF\n"
                                            "    // ADRP X8, #GetProcAddress@PAGE\n"
                                            "    // LDR X8, [X8, #GetProcAddress@PAGEOFF]\n"
                                            "    // MOV X0, X19\n"
                                            "    // BLR X8\n"
                                            "    void* exceptionDispatcher = getProcAddress(ntdllModule, \"KiUserExceptionDispatcher\");\n\n"

                                            "    if (exceptionDispatcher == NULL) {\n"
                                            "        printError(\"Failed to get KiUserExceptionDispatcher\\n\");\n"
                                            "        return;\n"
                                            "    } else {\n"
                                            "        printInfo(\"KiUserExceptionDispatcher: %p\\n\", exceptionDispatcher);\n"
                                            "    }\n\n"

                                            "    // ADRP X8, #aNtsetinformati@PAGE\n"
                                            "    // ADD X1, X8, #aNtsetinformati@PAGEOFF\n"
                                            "    // ADRP X8, #GetProcAddress@PAGE\n"
                                            "    // LDR X8, [X8, #GetProcAddress@PAGEOFF]\n"
                                            "    // MOV X0, X19\n"
                                            "    // BLR X8\n"
                                            "    void* setInfoProcess = getProcAddress(ntdllModule, \"NtSetInformationProcess\");\n\n"

                                            "    if (setInfoProcess == NULL) {\n"
                                            "        printError(\"Failed to get NtSetInformationProcess\\n\");\n"
                                            "        return;\n"
                                            "    }\n\n"

                                            "    // ADRP X8, #sub_1400011A0@PAGE\n"
                                            "    // ADD X1, X8, #sub_1400011A0@PAGEOFF\n"
                                            "    // ADRP X8, #AddVectoredExceptionHandler@PAGE\n"
                                            "    // LDR X8, [X8, #AddVectoredExceptionHandler@PAGEOFF]\n"
                                            "    // MOV W0, #1\n"
                                            "    // BLR X8\n"
                                            "    addVectoredExceptionHandler();\n\n"

                                            "    // Allocate memory for BaseAddress\n"
                                            "    void* baseAddress = allocateMemory(0x1000, 0x3000, 0x40);\n"
                                            "    if (baseAddress == NULL) {\n"
                                            "        printError(\"Failed to allocate memory for BaseAddress\\n\");\n"
                                            "        return;\n"
                                            "    }\n\n"

                                            "    // Additional operations\n"
                                            "    // ADRP X8, #sub_1400011C0@PAGE\n"
                                            "    // ADD X3, X8, #sub_1400011C0@PAGEOFF\n"
                                            "    // ADRP X8, #RtlInstallFunctionTableCallback@PAGE\n"
                                            "    // LDR X8, [X8, #RtlInstallFunctionTableCallback@PAGEOFF]\n"
                                            "    // ORR X20, X21, #3\n"
                                            "    installFunctionTableCallback();\n\n"

                                            "    // Error handling with error code\n"
                                            "    int errorCode = getLastError();\n"
                                            "    if (errorCode != 0) {\n"
                                            "        printError(\"Error code: %lu\\n\", (unsigned long)errorCode);\n"
                                            "    }\n\n"

                                            "    // Free allocated memory\n"
                                            "    freeMemory(baseAddress, 0x8000);\n"
                                            "    printf(\"Ohyooooo!\\n\");\n\n"
                                            "}\n"
        );

    #elif defined(_M_X64) || defined(__x86_64__)

        this->m_txtDecompiler->setPlainText(
                                            "Generated with KOTORI DECOMPILER at HarukaMirai - Named License to keowu.re@Fluxuss Software Security, LLC\n\n"
                                            "void unknownDecompiledFunction() {\n"
                                            "    // push rdi\n"
                                            "    // sub rsp, 50h\n"
                                            "    char *securityCookie;\n\n"
                                            "    // mov rax, cs:__security_cookie\n"
                                            "    // xor rax, rsp\n"
                                            "    // mov [rsp+58h+var_10], rax\n"
                                            "    securityCookie = getSecurityCookie();\n\n"
                                            "    // lea rcx, aNtdllDll  ; 'ntdll.dll'\n"
                                            "    // call cs:__imp_GetModuleHandleA\n"
                                            "    void *ntdllHandle = GetModuleHandle(\"ntdll.dll\");\n\n"
                                            "    // xor esi, esi\n"
                                            "    // mov rbx, rax\n"
                                            "    if (ntdllHandle == NULL) {\n"
                                            "        // lea rcx, aFailedToLoadNt ; 'Failed to load ntdll.dll\\n'\n"
                                            "        printf(\"Failed to load ntdll.dll\\n\");\n"
                                            "        return;\n"
                                            "    }\n\n"
                                            "    // lea rdx, aKiuserexceptio_0 ; 'KiUserExceptionDispatcher'\n"
                                            "    // mov rcx, rbx        ; hModule\n"
                                            "    // call cs:__imp_GetProcAddress\n"
                                            "    void *KiUserExceptionDispatcher = GetProcAddress(ntdllHandle, \"KiUserExceptionDispatcher\");\n"
                                            "    if (KiUserExceptionDispatcher == NULL) {\n"
                                            "        // lea rcx, aFailedToGetKiu ; 'Failed to get KiUserExceptionDispatcher'\n"
                                            "        printf(\"Failed to get KiUserExceptionDispatcher\\n\");\n"
                                            "        return;\n"
                                            "    }\n\n"
                                            "    // lea rcx, instrumentation\n"
                                            "    // mov [rsp+58h+var_20], rsi\n"
                                            "    // mov [rsp+58h+var_18], rcx\n"
                                            "    // call rax\n"
                                            "    int instrumentationStatus = setInstrumentationCallback();\n\n"
                                            "    if (instrumentationStatus < 0) {\n"
                                            "        // lea rcx, aFailedToSetIns ; 'Failed to set instrumentation callback'\n"
                                            "        printf(\"Failed to set instrumentation callback\\n\");\n"
                                            "        return;\n"
                                            "    }\n\n"
                                            "    // mov rax, gs:30h\n"
                                            "    // mov rcx, 1337134745121200h\n"
                                            "    // mov [rax+2E0h], rcx\n"
                                            "    initializeSpecialRegisters();\n\n"
                                            "    // lea rdx, KewExceptionHandler(_EXCEPTION_POINTERS *) ; Handler\n"
                                            "    // mov ecx, 1          ; First\n"
                                            "    AddVectoredExceptionHandler(1, KewExceptionHandler);\n\n"
                                            "    // mov edx, 1000h      ; dwSize\n"
                                            "    // xor ecx, ecx        ; lpAddress\n"
                                            "    void *baseAddress = VirtualAlloc(NULL, 0x1000, 0x3000, 0x40);\n"
                                            "    if (baseAddress == NULL) {\n"
                                            "        printf(\"Failed to allocate memory for BaseAddress\\n\");\n"
                                            "        return;\n"
                                            "    }\n\n"
                                            "    // mov rcx, rbx        ; TableIdentifier\n"
                                            "    // lea r9, MyFunctionTableCallback(unsigned __int64,void *) ; Callback\n"
                                            "    // mov r8d, 1000h      ; Length\n"
                                            "    // mov rdx, rdi        ; BaseAddress\n"
                                            "    RtlInstallFunctionTableCallback(baseAddress, MyFunctionTableCallback, 0x1000);\n\n"
                                            "    printf(\"Function table callback installed successfully\\n\");\n\n"
                                            "    printf(\"Hello World!\\n\");\n\n"
                                            "    int threadId = GetCurrentThreadId();\n"
                                            "    printf(\"Inside: %d\\n\", threadId);\n\n"
                                            "    // mov rcx, rbx        ; FunctionTable\n"
                                            "    RtlDeleteFunctionTable(baseAddress);\n\n"
                                            "    printf(\"Function table callback deleted successfully\\n\");\n\n"
                                            "    VirtualFree(baseAddress, 0, 0x8000);\n\n"
                                            "    printf(\"Ohyooooo!\\n\");\n\n"
                                            "    __security_check_cookie(securityCookie);\n\n"
                                            "    return;\n"
            "}");
    #endif

    this->m_qTabHaruka->setCurrentIndex(11);

}

void HarukaDisasmView::onPatchCode() {

    qDebug() << "HarukaDisasmView::onPatchCode";

    auto index = currentIndex();

    if (index.isValid()) {

        auto column0Index = index.model()->index(index.row(), 0);

        auto addressString = column0Index.data().toString();

        addressString.remove("0x");

        bool bConverted;
        uintptr_t address = addressString.toULongLong(&bConverted, 16);

        if (bConverted) {

            auto patch = new PatchCode(this, this->m_hProcessInternal, address, this->m_setPatchingCallback);

            patch->show();

            QAbstractItemModel* nonConstModel = const_cast<QAbstractItemModel*>(index.model());

            auto column3Index = nonConstModel->index(index.row(), 3);

            nonConstModel->setData(column3Index, QVariant("PATCHED"), Qt::EditRole);

        }

    }

}
