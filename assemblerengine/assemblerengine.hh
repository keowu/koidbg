/*
    File: assemblerengine.hh
    Author: João Vitor(@Keowu)
    Created: 17/11/2024
    Last Update: 24/11/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#ifndef ASSEMBLERENGINE_HH
#define ASSEMBLERENGINE_HH
#include <QMainWindow>
#include <vector>
#include <keystone.h>

enum ASSEMBLERENGINEERROR {

    ERROR_UNKNOWN,
    ERROR_KS,
    ERROR_CODE,
    SUCCESS

};

class Assemblerengine {

public:

    inline auto debugOperationCode(const std::vector<uint8_t>& code) -> void {

        for (const auto& byte : code) qDebug() << QString::asprintf("%02x", byte);

    }

    auto assembleArm64Code(const std::string& armCode) -> std::pair<std::vector<uint8_t>, ASSEMBLERENGINEERROR>;
    auto assembleX64Code(const std::string& armCode) -> std::pair<std::vector<uint8_t>, ASSEMBLERENGINEERROR>;

};

#endif // ASSEMBLERENGINE_HH
