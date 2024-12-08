/*
    File: PatchCode.hh
    Authors: João Vitor(@Keowu)
    Created: 17/11/2024
    Last Update: 01/12/2024

    Copyright (c) 2024. https://github.com/maldeclabs/koidbg. All rights reserved.
*/
#ifndef PATCHCODE_HH
#define PATCHCODE_HH

#include <Windows.h>
#include <psapi.h>
#include <QMainWindow>
#include "disassemblerengine/disassemblerengine.hh"
#include "assemblerengine/assemblerengine.hh"

using SetPatching = std::function<void(std::string, uintptr_t, const std::vector<uint8_t>&, const std::vector<uint8_t>&)>;

namespace Ui {

class PatchCode;

}

class PatchCode : public QMainWindow {

    Q_OBJECT

    public:
        explicit PatchCode(QWidget *parent = nullptr, HANDLE hProcess = INVALID_HANDLE_VALUE, uintptr_t address = 0, SetPatching setPatchingCallback = nullptr);
        ~PatchCode();

    private slots:
        auto onApplyPatchClicked() -> void;

    private:
        Ui::PatchCode *ui;
        DisassemblerEngine* m_disasm;
        Assemblerengine* m_asmm;
        HANDLE m_hProcessInternal;
        uintptr_t m_AddressInstruction;
        SetPatching m_setNewPatchingCallback;

};

#endif // PATCHCODE_HH
