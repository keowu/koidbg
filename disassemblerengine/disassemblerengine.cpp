/*
    File: DisassemblerEngine.cpp
    Author: João Vitor(@Keowu)
    Created: 21/07/2024
    Last Update: 08/08/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#include "disassemblerengine.h"
#include "disassemblerengine/disassemblerutils.h"

auto DisassemblerEngine::TestCapstoneEngine() -> void {

#define ARM64_CODE "\x09\x00\x38\xd5" \
    "\xbf\x40\x00\xd5" \
        "\x0c\x05\x13\xd5" \
        "\x20\x50\x02\x0e" \
        "\x20\xe4\x3d\x0f" \
        "\x00\x18\xa0\x5f" \
        "\xa2\x00\xae\x9e" \
        "\x9f\x37\x03\xd5" \
        "\xbf\x33\x03\xd5" \
        "\xdf\x3f\x03\xd5" \
        "\x21\x7c\x02\x9b" \
        "\x21\x7c\x00\x53" \
        "\x00\x40\x21\x4b" \
        "\xe1\x0b\x40\xb9" \
        "\x20\x04\x81\xda" \
        "\x20\x08\x02\x8b" \
        "\x10\x5b\xe8\x3c" \
        "\xfd\x7b\xba\xa9" \
        "\xfd\xc7\x43\xf8"

    csh handle;

    struct platform platforms[] = {
            {
                CS_ARCH_ARM64,
                CS_MODE_ARM,
                (unsigned char *)ARM64_CODE,
                sizeof(ARM64_CODE) - 1,
                "ARM-64"
            },
        };

    uint64_t address = 0x2c;
    cs_insn *insn;
    int i;
    size_t count;

    for (i = 0; i < sizeof(platforms)/sizeof(platforms[0]); i++) {
        cs_err err = cs_open(platforms[i].arch, platforms[i].mode, &handle);
        if (err) {
            printf("Failed on cs_open() with error returned: %u\n", err);
            abort();
        }

        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

        count = cs_disasm(handle, platforms[i].code, platforms[i].size, address, 0, &insn);
        if (count) {
            size_t j;

            printf("****************\n");
            printf("Platform: %s\n", platforms[i].comment);
            printf("Disasm:\n");

            for (j = 0; j < count; j++) {
                printf("0x%" PRIx64 ":\t%s\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
            }
            printf("0x%" PRIx64 ":\n", insn[j-1].address + insn[j-1].size);

            // free memory allocated by cs_disasm()
            cs_free(insn, count);
        } else {
            printf("****************\n");
            printf("Platform: %s\n", platforms[i].comment);
            printf("ERROR: Failed to disasm given code!\n");
            abort();
        }

        printf("\n");

        cs_close(&handle);
    }

}

auto DisassemblerEngine::TestCapstoneEngineAarch64Test(uintptr_t uipVirtualAddress, unsigned char* ucOpcodes, size_t szOpcodes) -> void {

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

    uint64_t address = uipVirtualAddress;
    cs_insn *insn;
    int i;
    size_t count;

    for (i = 0; i < sizeof(platforms)/sizeof(platforms[0]); i++) {
        cs_err err = cs_open(platforms[i].arch, platforms[i].mode, &handle);
        if (err) {
            printf("Failed on cs_open() with error returned: %u\n", err);
            abort();
        }

        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

        count = cs_disasm(handle, platforms[i].code, platforms[i].size, address, 0, &insn);
        if (count) {
            size_t j;

            printf("****************\n");
            printf("Platform: %s\n", platforms[i].comment);
            printf("Disasm:\n");

            for (j = 0; j < count; j++) {
                printf("0x%" PRIx64 ":\t%s\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
            }
            printf("0x%" PRIx64 ":\n", insn[j-1].address + insn[j-1].size);

            // free memory allocated by cs_disasm()
            cs_free(insn, count);
        } else {
            printf("****************\n");
            printf("Platform: %s\n", platforms[i].comment);
            printf("ERROR: Failed to disasm given code!\n");
            abort();
        }

        printf("\n");

        cs_close(&handle);
    }

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
        if (err) {
            printf("Failed on cs_open() with error returned: %u\n", err);
            abort();
        }

        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

        count = cs_disasm(handle, platforms[i].code, platforms[i].size, uipVirtualAddress, 0, &insn);
        if (count) {

            //printf("****************\n");
            //printf("Platform: %s\n", platforms[i].comment);
            //printf("Disasm:\n");

            const unsigned char sequence[] = {0x00, 0x00, 0x00}; //Release memory starting value state
            const unsigned char sequence2[] = {0xDD, 0xDD, 0xDD}; //Debug memory starting value state

            for (size_t j = 0; j < count; ++j) {

                QString addressStr = QString("0x%1").arg(insn[j].address, 0, 16).toLower();

                QString mnemonicStr = QString("%1 %2").arg(insn[j].mnemonic, insn[j].op_str).toUpper();

                //Is a Call to a address ? let's find the symbol
                if (DisassemblerUtils::is_imm_call(insn[j])) mnemonicStr = QString("%1 %2").arg(insn[j].mnemonic, DisassemblerUtils::get_symbol_from_address(engCfg.hProc, DisassemblerUtils::get_imm(insn[j]))).toUpper();

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

                // Append the row to the model
                QList<QStandardItem*> rowItems;
                rowItems << new QStandardItem(addressStr)
                         << new QStandardItem(bytesStr)
                         << new QStandardItem(QString("<span style='color:purple;'>%1</span>").arg(mnemonicStr));

                engCfg.model->appendRow(rowItems);

                HtmlDelegate *delegate = new HtmlDelegate(engCfg.tblDisasm);
                engCfg.tblDisasm->setItemDelegate(delegate);

            }

            cs_free(insn, count);
        } else {
            printf("****************\n");
            printf("Platform: %s\n", platforms[i].comment);
            printf("ERROR: Failed to disasm given code!\n");
        }

        printf("\n");

        cs_close(&handle);
    }

}
