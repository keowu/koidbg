/*
    File: DisassemblerUtils.h
    Author: João Vitor(@Keowu)
    Created: 17/08/2024
    Last Update: 08/09/2024

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

    namespace x86_64 {

        auto is_imm_call(cs_insn& insn) -> bool {

            return QString(insn.mnemonic) == "call" && insn.detail->x86.operands[0].type == X86_OP_IMM;
        }

        auto is_imm_jmp(cs_insn& insn) -> bool {

            return QString(insn.mnemonic) == "jmp" && insn.detail->x86.operands[0].type == X86_OP_IMM;
        }

        auto is_mnem_syscalling(cs_insn& insn) -> bool {

            return QString(insn.mnemonic) == "syscall" || QString(insn.mnemonic) == "int" || QString(insn.mnemonic) == "int3";
        }

        auto is_imm_controlflow_exchange(const cs_insn& insn) -> bool {
            static const QSet<QString> controlFlowMnemonics = {
                "je", "jne", "jb", "call", "jbe", "jc", "ja", "jae", "jz", "jnz",
                "jnp", "jpo", "jp", "jo", "jno", "js", "jns", "jl", "jle", "jg",
                "jge", "loop", "loopz", "loope", "loopnz", "loopne", "ret", "iret"
            };

            return controlFlowMnemonics.contains(QString(insn.mnemonic));
        }

        auto get_imm(cs_insn& insn) -> int64_t {

            return insn.detail->x86.operands[0].imm;
        }

        auto is_returning(const cs_insn& insn) -> bool {

            static const QSet<QString> retinst = {

                "ret", "retn", "retf", "retfn"

            };

            return retinst.contains(QString(insn.mnemonic));
        }

    }

    namespace AARCH64 {

        auto is_imm_branch_addr(cs_insn& insn) -> bool {

            static const QSet<QString> controlFlowArm64Mnemonics = {
                "b", "bl", "br", "blr", "cbz", "cbnz", "tbz", "tbnz", "b.", "bl.", "br.", "blr.", "cbz.", "cbnz.", "tbz.", "tbnz.", "ret"
            };

            return controlFlowArm64Mnemonics.contains(QString(insn.mnemonic)) && insn.detail->arm64.operands[0].type == ARM64_OP_IMM;
        }

        auto get_imm(cs_insn& insn) -> int64_t {

            return insn.detail->arm64.operands[0].imm;
        }

        auto is_imm_reference(cs_insn& insn) -> bool{

            return insn.detail->arm64.operands[0].type == ARM64_OP_IMM || insn.detail->arm64.operands[1].type == ARM64_OP_IMM;
        }

        auto is_mnem_syscalling(cs_insn& insn) -> bool {

            static const QSet<QString> syscallInterrupting = {
                "svc", "swi"
            };

            return syscallInterrupting.contains(QString(insn.mnemonic));
        }

        auto is_returning(const cs_insn& insn) -> bool {

            static const QSet<QString> retinst = {

                "ret"

            };

            return retinst.contains(QString(insn.mnemonic));
        }

    }


    namespace ASM_UTILS {

        //Disassemblar e obter objetos também para dar uma opção de visualização com base neles para o usuário
        //Permitir renderizar o disassembler string no grid também tudo certinho e alinhado e para cada endereço verificar symbolo etc:
        // jmp 0x12345678 -> symbolo jmp aaa!aaa ou jmp aaa!0x12
        auto get_symbol_from_address(HANDLE hProcess, int64_t uiAddress) -> QString {

            return UtilsWindowsSyscall::symbol_from_address(hProcess, uiAddress).replace(" ", "").replace("!", "->");
        }

    }

};

#endif // DISASSEMBLERUTILS_H
