/*
    File: KurumiParser.cpp
    Author: João Vitor(@Keowu)
    Created: 21/10/2024
    Last Update: 21/10/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
/*
    How to configure ?

    You need to configure to desired arch, harukamirai use dual arch:

        ARM64:
            Properties -> C/C++ -> General -> Additional Includes Directory -> "$(SolutionDir)LIEF\include\"
            Properties -> Librarian -> General -> Additional Dependencies -> $(SolutionDir)LIEF\ARM64\LIEF.lib and Urlmon.lib
        X64:
            Properties -> C/C++ -> General -> Additional Includes Directory -> "$(SolutionDir)LIEF\include\"
            Properties -> Librarian -> General -> Additional Dependencies -> $(SolutionDir)LIEF\X64\LIEF.lib and Urlmon.lib

        After build get the .lib file, and then copy KurumiParser.hh to the disired project and link the static lib to use

        Refer:
            https://lief.re/doc/latest/installation.html#visual-studio-integration

*/
#include "KurumiParser.hh"

auto KurumiPDB::CheckExistOrCreateHarukaMiraiPDBFolder() -> void {

    auto miraiPath = std::filesystem::current_path().string() + "\\HarukaPdbs";

    //The path for store HarukaMirai Pdbs already exists, just returning for now
    if (std::filesystem::exists(miraiPath) && std::filesystem::is_directory(miraiPath)) return;

    //If it not exist, let's create one
    std::filesystem::create_directory(miraiPath);

}

auto KurumiPDB::CheckExistPdbFileOnFolder(std::wstring fileNameWithoutExtension) -> bool {

    auto miraiPath = std::filesystem::current_path().wstring() + L"\\HarukaPdbs\\" + fileNameWithoutExtension + L".hkpdb";

    if (std::filesystem::exists(miraiPath) && std::filesystem::is_directory(miraiPath)) return true;

    return false;
}

auto KurumiPDB::DownloadHarukaMiraiPdb() -> bool {

    this->CheckExistOrCreateHarukaMiraiPDBFolder();

    auto guid = Kurumi::GetPDBGuidFromDllFile(this->m_filePath);

    std::transform(guid.begin(), guid.end()+1, guid.begin(), ::toupper);

    guid.erase(std::remove(guid.begin(), guid.end()+1, '-'), guid.end()+1);

    if (guid.empty()) return false;

    auto fileNameWithExtension = std::filesystem::path(this->m_filePath).filename().wstring();
    auto fileNameWithoutExtension = std::filesystem::path(this->m_filePath).stem().wstring();

    if (this->CheckExistPdbFileOnFolder(fileNameWithoutExtension)) return true;

    std::wstring wGuid(guid.begin(), guid.end());

    wchar_t downloadPathBuffer[1024]{ 0 };

    //https://msdl.microsoft.com/download/symbols/ntdll.pdb/5C8073654C20CE5A20142EEE2019DD131/ntdll.pdb
    _snwprintf_s(downloadPathBuffer, sizeof(downloadPathBuffer) / sizeof(wchar_t),
        L"%s%s.pdb/%s/%s.pdb",
        L"https://msdl.microsoft.com/download/symbols/", fileNameWithoutExtension.c_str(),
        wGuid.c_str(), fileNameWithoutExtension.c_str());

    auto savePath = (std::filesystem::current_path().wstring() + L"\\HarukaPdbs\\" + fileNameWithoutExtension + L".hkpdb");

    return URLDownloadToFileW(NULL, downloadPathBuffer, savePath.c_str(), NULL, NULL) == S_OK;
}

namespace Kurumi {

    auto _stdcall IsArm64(std::string filePath) -> bool {

        std::unique_ptr<LIEF::PE::Binary> binary = LIEF::PE::Parser::parse(filePath);

        auto characteristics = binary->header().characteristics();
        auto machine_type = binary->header().machine();

        return (machine_type == LIEF::PE::Header::MACHINE_TYPES::ARM64) &&
            !(characteristics & static_cast<uint16_t>(LIEF::PE::Header::CHARACTERISTICS::DLL));
    }

    auto _stdcall GetPDBGuidFromDllFile(std::string filePath) -> std::string {

        std::unique_ptr<LIEF::PE::Binary> binary = LIEF::PE::Parser::parse(filePath);

        //based on https://github.com/lief-project/LIEF/issues/480
        return binary->codeview_pdb()->guid() + std::to_string(binary->codeview_pdb()->age());
    }

    auto _stdcall InitKurumiPDB(std::string filePath) -> bool {

        Kurumi::kurumiPdb = std::make_unique<KurumiPDB>(filePath);

        return kurumiPdb->DownloadHarukaMiraiPdb();
    }

    auto _stdcall AttachKewDbgHarukaMiraiDevelopmentInterface() -> void {

        std::printf("Lolis DBG Interface are desactivated on compile time to avoid bad use of engine.\n");

    }

}