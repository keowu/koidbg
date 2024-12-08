/*
    File: KurumiParser.hh
    Authors: João Vitor(@Keowu)
    Created: 21/10/2024
    Last Update: 08/12/2024

    Copyright (c) 2024. https://github.com/maldeclabs/koidbg. All rights reserved.
*/
#ifndef KURUMIPARSER_HH
#define KURUMIPARSER_HH
#include <LIEF/LIEF.hpp>
#include <LIEF/PE.hpp>
#include <Windows.h>
#include <dbghelp.h>
#include <urlmon.h>
#include <string>
#include <cwchar>
#include <algorithm>
#include <iostream>
#include <filesystem>
#include <WinInet.h>

#pragma comment(lib, "WinINet.lib")

#define SymTagFunction 5

class KurumiPDB {

private:
    std::string m_filePath;
    std::string m_savePath;
    auto CheckExistOrCreateKoiPDBFolder() -> void;
    auto CheckExistPdbFileOnFolder(std::wstring fileNameWithoutExtension) -> bool;

public:

    KurumiPDB(std::string filePath) : m_filePath(filePath) { }
    auto DownloadKoiPdb() -> bool;
    auto FindPdbField(std::string fieldName) -> uintptr_t;
    auto FindPdbStructField(std::string structName, std::string fieldName) -> uintptr_t;

};

namespace KurumiPdbFast {

    auto CALLBACK EnumSymbolsCallback(PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext) -> BOOL;
    auto ParsePdbFunctionsAndGetListInternal(std::string pdbPath) -> std::vector<std::pair<std::string, uintptr_t>>;

};

namespace Kurumi {
    //Private
    static std::unique_ptr<KurumiPDB> kurumiPdb;
    auto _stdcall GetPDBGuidFromDllFile(std::string filePath)->std::string;

    //Publics
    __declspec(dllexport) auto _stdcall HasInternetConnection() -> bool;
    __declspec(dllexport) auto _stdcall InitKurumiKOPDB(std::string filePath) -> bool;
    __declspec(dllexport) auto _stdcall FindFieldKoiPDB(std::string fieldName) -> uintptr_t;
    __declspec(dllexport) auto _stdcall FindStructFieldKOPDB(std::string structName, std::string fieldName) -> uintptr_t;
    __declspec(dllexport) auto _stdcall IsArm64(std::string filePath) -> bool;
    __declspec(dllexport) auto _stdcall AttachKewDbgKoiDbgDevelopmentInterface() -> void;
    __declspec(dllexport) auto _stdcall ParsePdbFunctionsAndSymbolsByPath(std::string pdbPath) ->std::vector<std::pair<std::string, uintptr_t>>;

}

#endif