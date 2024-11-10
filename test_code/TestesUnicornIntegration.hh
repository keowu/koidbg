/*
    File: TestesUnicornIntegration.hh
    Author: João Vitor(@Keowu)
    Created: 10/11/2024
    Last Update: 10/11/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#ifndef TESTESUNICORNINTEGRATION_H
#define TESTESUNICORNINTEGRATION_H
#include <unicorn/unicorn.h>

#define X86_CODE32 "\x41\x4a" // INC ecx; DEC edx

#define ADDRESS 0x1000000

int testingUnicorn() {

    uc_engine *uc;
    uc_err err;
    int r_ecx = 0x1234;     // ECX register
    int r_edx = 0x7890;     // EDX register

    printf("Emulate i386 code\n");

    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);

    if (err != UC_ERR_OK) {

        printf("Failed on uc_open() with error returned: %u\n", err);

        return -1;
    }

    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    if (uc_mem_write(uc, ADDRESS, X86_CODE32, sizeof(X86_CODE32) - 1)) {

        printf("Failed to write emulation code to memory, quit!\n");

        return -1;
    }

    uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_write(uc, UC_X86_REG_EDX, &r_edx);

    err=uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32) - 1, 0, 0);

    if (err) {

        printf("Failed on uc_emu_start() with error returned %u: %s\n",
               err, uc_strerror(err));

    }

    printf("Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_read(uc, UC_X86_REG_EDX, &r_edx);

    printf(">>> ECX = 0x%x\n", r_ecx);
    printf(">>> EDX = 0x%x\n", r_edx);

    uc_close(uc);

    return 0;
}

#endif // TESTESUNICORNINTEGRATION_H
