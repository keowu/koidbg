/*
    File: KurumiParser.hh
    Authors: João Vitor(@Keowu)
    Created: 21/10/2024
    Last Update: 08/12/2024

    Copyright (c) 2024. https://github.com/maldeclabs/koidbg. All rights reserved.
*/
#ifndef KURUMIPARSER_HH
#define KURUMIPARSER_HH

#include <string>

namespace Kurumi {
	
    auto _stdcall HasInternetConnection() -> bool;
    auto _stdcall InitKurumiKOPDB(std::string filePath) -> bool;
    auto _stdcall FindFieldKoiPDB(std::string fieldName) -> uintptr_t;
    auto _stdcall FindStructFieldKOPDB(std::string structName, std::string fieldName) -> uintptr_t;
    auto _stdcall IsArm64(std::string filePath) -> bool;
    auto _stdcall AttachKewDbgKoiDbgDevelopmentInterface() -> void;
    auto _stdcall ParsePdbFunctionsAndSymbolsByPath(std::string pdbPath) ->std::vector<std::pair<std::string, uintptr_t>>;
	
}

#endif