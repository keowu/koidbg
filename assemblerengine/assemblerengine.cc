/*
    File: assemblerengine.cc
    Author: João Vitor(@Keowu)
    Created: 17/11/2024
    Last Update: 24/11/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#include "assemblerengine.hh"

auto Assemblerengine::assembleX64Code(const std::string& armCode) -> std::pair<std::vector<uint8_t>, ASSEMBLERENGINEERROR> {

    std::vector<uint8_t> result;

    ks_engine* ks;

    ks_err err = ks_open(KS_ARCH_X86, KS_MODE_32, &ks);

    if (err != KS_ERR_OK) {

        qDebug() << "[ERROR] assemblerengine::assembleX64Code -> Keystone: " << ks_strerror(err);

        return std::make_pair(result, ASSEMBLERENGINEERROR::ERROR_KS);
    }

    unsigned char* encoded;
    size_t size;
    size_t count;

    if (ks_asm(ks, armCode.c_str(), 0, &encoded, &size, &count) != KS_ERR_OK) {

        qDebug() << "[ERROR] assemblerengine::assembleX64Code -> Assembly: " << ks_strerror(KS_ERR_OK);

        return std::make_pair(result, ASSEMBLERENGINEERROR::ERROR_CODE);
    }

    result.assign(encoded, encoded + size);

    ks_close(ks);

    return std::make_pair(result, ASSEMBLERENGINEERROR::SUCCESS);
}

auto Assemblerengine::assembleArm64Code(const std::string& armCode) -> std::pair<std::vector<uint8_t>, ASSEMBLERENGINEERROR> {

    std::vector<uint8_t> result;

    ks_engine* ks;

    ks_err err = ks_open(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, &ks);

    if (err != KS_ERR_OK) {

        qDebug() << "[ERROR] assemblerengine::assembleArm64Code -> Keystone: " << ks_strerror(err);

        return std::make_pair(result, ASSEMBLERENGINEERROR::ERROR_KS);
    }

    unsigned char* encoded;
    size_t size;
    size_t count;

    if (ks_asm(ks, armCode.c_str(), 0, &encoded, &size, &count) != KS_ERR_OK) {

        qDebug() << "[ERROR] assemblerengine::assembleArm64Code -> Assembly: " << ks_strerror(KS_ERR_OK);

        return std::make_pair(result, ASSEMBLERENGINEERROR::ERROR_CODE);
    }

    result.assign(encoded, encoded + size);

    ks_close(ks);

    return std::make_pair(result, ASSEMBLERENGINEERROR::SUCCESS);
}
