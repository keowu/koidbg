/*
    File: KurumiParser.hh
    Author: João Vitor(@Keowu)
    Created: 21/10/2024
    Last Update: 21/10/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#ifndef KURUMIPARSER_HH
#define KURUMIPARSER_HH
#include <LIEF/LIEF.hpp>
#include <LIEF/PE.hpp>
#include <Windows.h>
#include <urlmon.h>
#include <string>
#include <cwchar>
#include <algorithm>
#include <iostream>
#include <filesystem>

class KurumiPDB {

private:
    std::string m_filePath;
    auto CheckExistOrCreateHarukaMiraiPDBFolder() -> void;
    auto CheckExistPdbFileOnFolder(std::wstring fileNameWithoutExtension) -> bool;

public:

    KurumiPDB(std::string filePath) : m_filePath(filePath) { }
    auto DownloadHarukaMiraiPdb() -> bool;

};


namespace Kurumi {
    //Private
    static std::unique_ptr<KurumiPDB> kurumiPdb;
    auto _stdcall GetPDBGuidFromDllFile(std::string filePath)->std::string;

    //Publics
    __declspec(dllexport) auto _stdcall InitKurumiPDB(std::string filePath) -> bool;
    __declspec(dllexport) auto _stdcall IsArm64(std::string filePath) -> bool;
    __declspec(dllexport) auto _stdcall AttachKewDbgHarukaMiraiDevelopmentInterface() -> void;
}

#endif