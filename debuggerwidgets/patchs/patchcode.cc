/*
    File: PatchCode.cc
    Author: João Vitor(@Keowu)
    Created: 17/11/2024
    Last Update: 01/12/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#include "patchcode.hh"
#include "ui_patchcode.h"

PatchCode::PatchCode(QWidget *parent, HANDLE hProcess, uintptr_t address, SetPatching setPatchingCallback)
    : QMainWindow(parent)
    , ui(new Ui::PatchCode) {

    ui->setupUi(this);

    connect(ui->btnApplyPatch, &QPushButton::clicked, this, &PatchCode::onApplyPatchClicked);

    ui->lblPatchWarn->setStyleSheet("QLabel { color : red; }");

    /*
     *  Disable MAXIMIZE Button and Disable FORM Resizing
    */
    setFixedSize(size());
    setWindowFlags(windowFlags() & ~Qt::WindowMaximizeButtonHint);

    /*
     * Initialize Engines
     */
    this->m_asmm = new Assemblerengine();
    this->m_disasm = new DisassemblerEngine();
    this->m_hProcessInternal = hProcess;
    this->m_AddressInstruction = address;
    this->m_setNewPatchingCallback = setPatchingCallback;

    /*
     * ReadOpcodes of current region
     */
    unsigned char ucBuff[512]{ 0 };

    ::ReadProcessMemory(

        this->m_hProcessInternal,
        reinterpret_cast<PVOID>(address),
        ucBuff,
        sizeof(ucBuff),
        NULL

    );

    /*
     * Disassemble the readed opcodes with Disassembly engine
     */
    #if defined(__aarch64__) || defined(_M_ARM64)
        ui->txtDisasmPatch->setText(this->m_disasm->RunCapstoneForSimpleOpcodeBlocARM64(address, ucBuff, sizeof(ucBuff)));
    #elif defined(__x86_64__) || defined(_M_X64)
        ui->txtDisasmPatch->setText(this->m_disasm->RunCapstoneForSimpleOpcodeBlocX86(address, ucBuff, sizeof(ucBuff)));
    #endif

    qDebug() << "PatchCode::PatchCode DONE";
}

auto PatchCode::onApplyPatchClicked() -> void {

    qDebug() << "PatchCode::onApplyPatchClicked DONE";

    ui->lblPatchWarn->setText("");

    #if defined(__aarch64__) || defined(_M_ARM64)
        auto newOpcodes = this->m_asmm->assembleArm64Code(ui->txtDisasmPatch->toPlainText().toStdString());
        auto oriOpcodes = this->m_asmm->assembleArm64Code(ui->txtDisasmPatch->toPlainText().toStdString());
    #elif defined(__x86_64__) || defined(_M_X64)
        auto newOpcodes = this->m_asmm->assembleX64Code(ui->txtDisasmPatch->toPlainText().toStdString());
        auto oriOpcodes = this->m_asmm->assembleX64Code(ui->txtDisasmPatch->toPlainText().toStdString());
    #endif

    if (newOpcodes.second == ASSEMBLERENGINEERROR::ERROR_UNKNOWN) ui->lblPatchWarn->setText("ASSEMBLERENGINEERROR: UNKNOWN ERROR on Engine.");
    else if (newOpcodes.second == ASSEMBLERENGINEERROR::ERROR_KS) ui->lblPatchWarn->setText("ASSEMBLERENGINEERROR: ERROR During Engine initilization.");
    else if (newOpcodes.second == ASSEMBLERENGINEERROR::ERROR_CODE) ui->lblPatchWarn->setText("ASSEMBLERENGINEERROR: Invalid instructions, please review the code you're writting.");
    else {

        qDebug() << "ASSEMBLERENGINEERROR::SUCCESS";

        if (ui->chkCompleteNops->isChecked()) ui->lblPatchWarn->setText("TODO: Fill with NoOperation logic.");

        ::WriteProcessMemory(

            this->m_hProcessInternal,
            reinterpret_cast<PVOID>(this->m_AddressInstruction),
            newOpcodes.first.data(),
            newOpcodes.first.size(),
            NULL

        );

        MEMORY_BASIC_INFORMATION mb;

        ::VirtualQueryEx(

            this->m_hProcessInternal,
            reinterpret_cast<PVOID>(this->m_AddressInstruction),
            &mb,
            sizeof(mb)

        );

        char chFileName[MAX_PATH]{ 0 };

        ::GetModuleFileNameExA(

            this->m_hProcessInternal,
            reinterpret_cast<HMODULE>(mb.AllocationBase),
            chFileName,
            MAX_PATH

        );

        auto GetFileNameFromPath = [](const char* fullPath) -> std::string {

            auto filename = strrchr(fullPath, '\\');

            return filename ? std::string(filename + 1) : std::string(fullPath);
        };

        //Call EngineCallback to create a new patch object
        if(this->m_setNewPatchingCallback) this->m_setNewPatchingCallback(GetFileNameFromPath(chFileName),  this->m_AddressInstruction - reinterpret_cast<uintptr_t>(mb.AllocationBase), oriOpcodes.first, newOpcodes.first);
    }

    qDebug() << "PatchCode::onApplyPatchClicked END";

    this->~PatchCode();

    this->close();
}

PatchCode::~PatchCode() {

    delete ui;

    delete this->m_asmm;
    delete this->m_disasm;

}
