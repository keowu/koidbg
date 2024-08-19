/*
    File: DisassemblerUtils.h
    Author: João Vitor(@Keowu)
    Created: 17/08/2024
    Last Update: 18/08/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#ifndef DISASSEMBLERUTILS_H
#define DISASSEMBLERUTILS_H
#include <Windows.h>
#include <QString>
#include <QRegularExpression>
#include <capstone/platform.h>
#include <capstone/capstone.h>
#include "debuggerutils/utilswindowssyscall.h"

namespace DisassemblerUtils {

    auto is_imm_call(cs_insn insn) -> bool {

        return QString(insn.mnemonic) == "call" && insn.detail->x86.operands[0].type == X86_OP_IMM;
    }


    auto get_imm(cs_insn insn) -> int64_t {

        return insn.detail->x86.operands[0].imm;
    }

    //Disassemblar e obter objetos também para dar uma opção de visualização com base neles para o usuário
    //Permitir renderizar o disassembler string no grid também tudo certinho e alinhado e para cada endereço verificar symbolo etc:
    // jmp 0x12345678 -> symbolo jmp aaa!aaa ou jmp aaa!0x12
    auto get_symbol_from_address(HANDLE hProcess, int64_t uiAddress) -> QString {

        QString symbol = UtilsWindowsSyscall::symbol_from_address(hProcess, uiAddress);

        if (symbol == " ") return QString::number(uiAddress);

        return symbol;
    }

};

#endif // DISASSEMBLERUTILS_H
