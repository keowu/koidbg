/*
    File: TestesKeystoneIntegration.hh
    Authors: João Vitor(@Keowu)
    Created: 17/11/2024
    Last Update: 17/11/2024

    Copyright (c) 2024. https://github.com/maldeclabs/koidbg. All rights reserved.
*/
#ifndef TESTESKEYSTONEINTEGRATION_HH
#define TESTESKEYSTONEINTEGRATION_HH
#include <dependencies/keystone/include/keystone.h>
#include <iostream>
#include <vector>
#include <iomanip>

auto printHex(const std::vector<uint8_t>& code) -> void {

    for (const auto& byte : code)
        std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte) << " ";


    std::cout << std::dec << std::endl;
}

auto testingKeystoneX64() -> void {


    ks_engine* ks;
    ks_err err = ks_open(KS_ARCH_X86, KS_MODE_32, &ks);

    if (err != KS_ERR_OK) {

        std::cerr << "Failed to initialize Keystone: " << ks_strerror(err) << std::endl;

        return;
    }

    const char* instructions = "mov eax, 0x1234; add eax, ebx; ret";

    unsigned char* encoded;
    size_t size;
    size_t count;

    if (ks_asm(ks, instructions, 0, &encoded, &size, &count) != KS_ERR_OK) {

        std::cerr << "Keystone assembly failed: " << ks_strerror(err) << std::endl;

        ks_close(ks);

        return;
    }

    std::cout << "Machine code(X64) (" << size << " bytes): ";
    std::vector<uint8_t> machineCode(encoded, encoded + size);
    printHex(machineCode);

    ks_free(encoded);
    ks_close(ks);

    return;
}

auto testingKeystoneARM64() -> void {

    ks_engine* ks;

    ks_err err = ks_open(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, &ks);

    if (err != KS_ERR_OK) {

        std::cerr << "Failed to initialize Keystone: " << ks_strerror(err) << std::endl;

        return;
    }

    const char* instructions = "mov x0, #0x1234; add x1, x0, x2; ret";

    unsigned char* encoded;
    size_t size;
    size_t count;

    if (ks_asm(ks, instructions, 0, &encoded, &size, &count) != KS_ERR_OK) {

        std::cerr << "Keystone assembly failed: " << ks_strerror(err) << std::endl;

        ks_close(ks);

        return;
    }

    std::cout << "Machine code(ARM64) (" << size << " bytes): ";
    std::vector<uint8_t> machineCode(encoded, encoded + size);

    printHex(machineCode);

    ks_free(encoded);
    ks_close(ks);

    return;
}

auto testingKeystone() -> void {

    testingKeystoneX64();
    testingKeystoneARM64();

}

#endif // TESTESKEYSTONEINTEGRATION_HH
