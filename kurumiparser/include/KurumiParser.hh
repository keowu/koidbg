/*
    File: KurumiParser.hh
    Author: João Vitor(@Keowu)
    Created: 21/10/2024
    Last Update: 21/10/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#ifndef KURUMIPARSER_HH
#define KURUMIPARSER_HH

#include <string>

namespace Kurumi {
	
    auto _stdcall InitKurumiHKPDB(std::string filePath) -> bool;
    auto _stdcall IsArm64(std::string filePath) -> bool;
    auto _stdcall AttachKewDbgHarukaMiraiDevelopmentInterface() -> void;
	
}

#endif