/*
    File: KurumiParser.hh
    Author: João Vitor(@Keowu)
    Created: 21/10/2024
    Last Update: 27/10/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
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

class KurumiPDB {

private:
    std::string m_filePath;
    std::string m_savePath;
    auto CheckExistOrCreateHarukaMiraiPDBFolder() -> void;
    auto CheckExistPdbFileOnFolder(std::wstring fileNameWithoutExtension) -> bool;

public:

    KurumiPDB(std::string filePath) : m_filePath(filePath) { }
    auto DownloadHarukaMiraiPdb() -> bool;
    auto FindPdbField(std::string fieldName) -> uintptr_t;
    auto FindPdbStructField(std::string structName, std::string fieldName) -> uintptr_t;

};


namespace Kurumi {
    //Private
    static std::unique_ptr<KurumiPDB> kurumiPdb;
    auto _stdcall GetPDBGuidFromDllFile(std::string filePath)->std::string;

    //Publics
    __declspec(dllexport) auto _stdcall HasInternetConnection() -> bool;
    __declspec(dllexport) auto _stdcall InitKurumiHKPDB(std::string filePath) -> bool;
    __declspec(dllexport) auto _stdcall FindFieldHKPDB(std::string fieldName) -> uintptr_t;
    __declspec(dllexport) auto _stdcall FindStructFieldHKPDB(std::string structName, std::string fieldName) -> uintptr_t;
    __declspec(dllexport) auto _stdcall IsArm64(std::string filePath) -> bool;
    __declspec(dllexport) auto _stdcall AttachKewDbgHarukaMiraiDevelopmentInterface() -> void;
}

#endif