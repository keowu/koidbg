/*
    File: DisassemblerEngine.cpp
    Author: João Vitor(@Keowu)
    Created: 21/07/2024
    Last Update: 08/09/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#include "disassemblerengine.h"
#include "disassemblerengine/disassemblerutils.h"

auto DisassemblerEngine::RunCapstoneEngineAarch64(uintptr_t uipVirtualAddress, unsigned char* ucOpcodes, size_t szOpcodes, DisasmEngineConfig engCfg) -> void {

    csh handle;

    struct platform platforms[] = {
        {
            CS_ARCH_ARM64,
            CS_MODE_ARM,
            (unsigned char *)ucOpcodes,
            szOpcodes,
            "ARM-64"
        },
    };

    cs_insn *insn;

    int i;
    size_t count;

    for (i = 0; i < sizeof(platforms)/sizeof(platforms[0]); i++) {

        cs_err err = cs_open(platforms[i].arch, platforms[i].mode, &handle);

        if (err) return;

        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

        count = cs_disasm(handle, platforms[i].code, platforms[i].size, uipVirtualAddress, 0, &insn);


        if (count) {

            const unsigned char sequence[] = {0x00, 0x00, 0x00}; //Release memory starting value state
            const unsigned char sequence2[] = {0xDD, 0xDD, 0xDD}; //Debug memory starting value state

            for (size_t j = 0; j < count; ++j) {

                QString addressStr = QString("0x%1").arg(insn[j].address, 0, 16).toUpper();

                QString mnemonicStr = QString("<harukageneric style='color:red;'>%1 </harukageneric>%2").arg(insn[j].mnemonic, insn[j].op_str).toUpper();

                //Is a branch to a address ? is yes, we need to recover the symbol name
                if (DisassemblerUtils::AARCH64::is_imm_branch_addr(insn[j])) {

                    QString SymbolName = DisassemblerUtils::ASM_UTILS::get_symbol_from_address(engCfg.hProc, DisassemblerUtils::AARCH64::get_imm(insn[j]));

                    if (SymbolName.isEmpty()) SymbolName = insn[j].op_str;

                    mnemonicStr = QString("<harukabranch style='color:purple;'>%1 %2</harukabranch>").arg(insn[j].mnemonic, SymbolName).toUpper();

                } else if (DisassemblerUtils::AARCH64::is_mnem_syscalling(insn[j])) mnemonicStr = QString("<harukasyscalling style='color:orange;'>%1 %2</harukasyscalling>").arg(insn[j].mnemonic, insn[j].op_str).toUpper();
                else if (DisassemblerUtils::AARCH64::is_imm_reference(insn[j]))
                    mnemonicStr = QString("<harukageneric style='color:red;'>%1</harukageneric> <harukaimm style='color:purple;'>%2</harukaimm>").arg(insn[j].mnemonic, insn[j].op_str).toUpper();

                const unsigned char* bytes = insn[j].bytes;

                size_t length = sizeof(insn[j].bytes) / sizeof(insn[j].bytes[0]);

                auto it = std::search(bytes, bytes + length, std::begin(sequence), std::end(sequence));

                size_t containsSequence = (it != bytes + length) ? (it - bytes) : length;


                /*
                 * If not found a memory zeroed(release oficial).
                 * Then we check for a memory debug in case of a debug release.
                 */
                if (containsSequence == length) {

                    it = std::search(bytes, bytes + length, std::begin(sequence2), std::end(sequence2));

                    containsSequence = (it != bytes + length) ? (it - bytes) : length;

                }

                QByteArray bytesArray(reinterpret_cast<const char*>(bytes), containsSequence);
                QString bytesStr = bytesArray.toHex(' ').toLower();

                // Getting IP index to change table cursor position
                if (engCfg.actualIP == insn[j].address) *engCfg.tblIPidx = j;

                // Append the row to the model
                QList<QStandardItem*> rowItems;
                rowItems << new QStandardItem(addressStr)
                         << new QStandardItem(bytesStr)
                         << new QStandardItem(mnemonicStr)
                         << new QStandardItem(engCfg.actualIP == insn[j].address ? "ACTUAL IP" : "");

                if (engCfg.model)
                    engCfg.model->appendRow(rowItems);

            }

        }

        cs_free(insn, count);

    }

    cs_close(&handle);

}

auto DisassemblerEngine::RunCapstoneEnginex86(uintptr_t uipVirtualAddress, unsigned char* ucOpcodes, size_t szOpcodes, DisasmEngineConfig engCfg) -> void {

    csh handle;

    struct platform platforms[] = {
        {
            CS_ARCH_X86,
            CS_MODE_64,
            ucOpcodes,
            szOpcodes,
            "x86-64"
        },
    };

    cs_insn *insn;

    int i;
    size_t count;

    for (i = 0; i < sizeof(platforms)/sizeof(platforms[0]); i++) {

        cs_err err = cs_open(platforms[i].arch, platforms[i].mode, &handle);

        if (err) return;

        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

        count = cs_disasm(handle, platforms[i].code, platforms[i].size, uipVirtualAddress, 0, &insn);

        if (count) {

            const unsigned char sequence[] = {0x00, 0x00, 0x00}; //Release memory starting value state
            const unsigned char sequence2[] = {0xDD, 0xDD, 0xDD}; //Debug memory starting value state

            for (size_t j = 0; j < count; ++j) {

                QString addressStr = QString("0x%1").arg(insn[j].address, 0, 16).toUpper();

                QString mnemonicStr = QString("<harukageneric style='color:red;'>%1 </harukageneric>%2").arg(insn[j].mnemonic, insn[j].op_str).toUpper();

                //Is a Call to a address ? let's find the symbol
                if (DisassemblerUtils::x86_64::is_imm_call(insn[j]) || DisassemblerUtils::x86_64::is_imm_jmp(insn[j])) {

                    QString SymbolName = DisassemblerUtils::ASM_UTILS::get_symbol_from_address(engCfg.hProc, DisassemblerUtils::x86_64::get_imm(insn[j]));

                    if (SymbolName.isEmpty()) SymbolName = insn[j].op_str;

                    mnemonicStr = QString("<harukabranch style='color:purple;'>%1 %2</harukabranch>").arg(insn[j].mnemonic, SymbolName).toUpper();

                } else if (DisassemblerUtils::x86_64::is_mnem_syscalling(insn[j])) mnemonicStr = QString("<harukasyscalling style='color:orange;'>%1 %2</harukasyscalling>").arg(insn[j].mnemonic, insn[j].op_str).toUpper();
                else if (DisassemblerUtils::x86_64::is_imm_controlflow_exchange(insn[j])) mnemonicStr = QString("<harukacontrolflow style='color:DarkGoldenRod;'>%1 %2</harukacontrolflow>").arg(insn[j].mnemonic, insn[j].op_str).toUpper();

                const unsigned char* bytes = insn[j].bytes;

                size_t length = sizeof(insn[j].bytes) / sizeof(insn[j].bytes[0]);

                auto it = std::search(bytes, bytes + length, std::begin(sequence), std::end(sequence));

                size_t containsSequence = (it != bytes + length) ? (it - bytes) : length;

                /*
                 * If not found a memory zeroed(release oficial).
                 * Then we check for a memory debug in case of a debug release.
                 */
                if (containsSequence == length) {

                    it = std::search(bytes, bytes + length, std::begin(sequence2), std::end(sequence2));

                    containsSequence = (it != bytes + length) ? (it - bytes) : length;

                }

                QByteArray bytesArray(reinterpret_cast<const char*>(bytes), containsSequence);
                QString bytesStr = bytesArray.toHex(' ').toLower();

                // Getting RIP index to change table cursor position
                if (engCfg.actualIP == insn[j].address) *engCfg.tblIPidx = j;

                // Append the row to the model
                QList<QStandardItem*> rowItems;
                rowItems << new QStandardItem(addressStr)
                         << new QStandardItem(bytesStr)
                         << new QStandardItem(mnemonicStr)
                         << new QStandardItem(engCfg.actualIP == insn[j].address ? "<harukainfo style='color:red;'>ACTUAL IP</harukainfo>" : ""); //This is the only info for now.

                if (engCfg.model)
                    engCfg.model->appendRow(rowItems);

            }

            cs_free(insn, count);
        } /*else {
            printf("****************\n");
            printf("Platform: %s\n", platforms[i].comment);
            printf("ERROR: Failed to disasm given code!\n");
        }*/

        cs_close(&handle);

    }

}

auto DisassemblerEngine::RunCapstoneForStepOutARM64(uintptr_t uipVirtualAddress, unsigned char* ucOpcodes, size_t szOpcodes) -> uintptr_t {

    csh handle;

    struct platform platforms[] = {
        {
            CS_ARCH_ARM64,
            CS_MODE_ARM,
            (unsigned char *)ucOpcodes,
            szOpcodes,
            "ARM-64"
        },
    };

    cs_insn *insn;

    int i;
    size_t count;

    for (i = 0; i < sizeof(platforms)/sizeof(platforms[0]); i++) {

        cs_err err = cs_open(platforms[i].arch, platforms[i].mode, &handle);

        if (err) return 0;

        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

        count = cs_disasm(handle, platforms[i].code, platforms[i].size, uipVirtualAddress, 0, &insn);


        if (count)

            for (size_t j = 0; j < count; ++j)

                if (DisassemblerUtils::AARCH64::is_returning(insn[j])) return insn[j].address;

        cs_close(&handle);
    }

    return 0;
}

auto DisassemblerEngine::RunCapstoneForStepOutx86(uintptr_t uipVirtualAddress, unsigned char* ucOpcodes, size_t szOpcodes) -> uintptr_t {

    csh handle;

    struct platform platforms[] = {
        {
            CS_ARCH_X86,
            CS_MODE_64,
            ucOpcodes,
            szOpcodes,
            "x86-64"
        },
    };

    cs_insn *insn;

    int i;
    size_t count;

    for (i = 0; i < sizeof(platforms)/sizeof(platforms[0]); i++) {

        cs_err err = cs_open(platforms[i].arch, platforms[i].mode, &handle);

        if (err) return 0;

        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

        count = cs_disasm(handle, platforms[i].code, platforms[i].size, uipVirtualAddress, 0, &insn);

        if (count)

            for (size_t j = 0; j < count; ++j)

                if (DisassemblerUtils::x86_64::is_returning(insn[j])) return insn[j].address;

        cs_close(&handle);

    }

    return 0;
}
