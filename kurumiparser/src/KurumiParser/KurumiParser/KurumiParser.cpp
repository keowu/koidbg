/*
    File: KurumiParser.cpp
    Authors: João Vitor(@Keowu)
    Created: 21/10/2024
    Last Update: 08/12/2024

    Copyright (c) 2024. https://github.com/maldeclabs/koidbg. All rights reserved.
*/
/*
    How to configure ?

    You need to configure to desired arch, koidbg's use dual arch:

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

auto KurumiPDB::CheckExistOrCreateKoiPDBFolder() -> void {

    auto miraiPath = std::filesystem::current_path().string() + "\\KoiDbgPdbs";

    //The path for store KoiDbg Pdbs already exists, just returning for now
    if (std::filesystem::exists(miraiPath) && std::filesystem::is_directory(miraiPath)) return;

    //If it not exist, let's create one
    std::filesystem::create_directory(miraiPath);

}

auto KurumiPDB::CheckExistPdbFileOnFolder(std::wstring fileNameWithoutExtension) -> bool {

    auto miraiPath = std::filesystem::current_path().wstring() + L"\\KoiDbgPdbs\\" + fileNameWithoutExtension + L".pdb";

    if (std::filesystem::exists(miraiPath) && std::filesystem::is_directory(miraiPath)) return true;

    return false;
}

auto KurumiPDB::DownloadKoiPdb() -> bool {

    this->CheckExistOrCreateKoiPDBFolder();

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

    auto savePath = (std::filesystem::current_path().wstring() + L"\\KoiDbgPdbs\\" + fileNameWithoutExtension + L".pdb");

    this->m_savePath.assign(savePath.begin(), savePath.end());

    return URLDownloadToFileW(NULL, downloadPathBuffer, savePath.c_str(), NULL, NULL) == S_OK;
}

auto KurumiPDB::FindPdbField(std::string fieldName) -> uintptr_t {

    auto hSym = GetCurrentProcess();

    auto status = SymInitialize(hSym, this->m_filePath.c_str(), false);
    if (!status) {

        std::cerr << "Kurumi::KoiEngine -> Fail on koi seeking for symbol initilizer provider.\n";

        return -1;
    }

    status = SymSetSearchPath(hSym, (std::filesystem::current_path().string() + "\\KoiDbgPdbs\\").c_str());

    if (!status) {

        std::cerr << "Kurumi::KoiEngine -> Fail on koi looking for a symbol path.\n";

        return -1;
    }

    auto base = SymLoadModuleEx(hSym, nullptr, this->m_filePath.c_str(), nullptr, 0, 0, nullptr, 0);
    if (base == 0) {

        std::cerr << "Kurumi::KoiEngine -> Koi was not able to load .kopdb file.\n";
        
        SymCleanup(hSym);
        
        return -1;
    }

    constexpr auto k_size = sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(char);
    unsigned char buf[k_size]{0};
    auto* const info = reinterpret_cast<SYMBOL_INFO*>(buf);
    info->SizeOfStruct = sizeof(SYMBOL_INFO);
    info->MaxNameLen = MAX_SYM_NAME;

    status = SymGetTypeFromName(hSym, base, fieldName.c_str(), info);
    if (!status) {
        
        std::cerr << "Kurumi::KoiEngine -> Koi was not able to get typeinfo by name (This normally happen when this symbol is not loaded by OS yet).\n";
        
        SymCleanup(hSym);
    
        return -1;
    }

    SymUnloadModule64(hSym, base);

    SymCleanup(hSym);

    return info->Address - base;
}

auto KurumiPDB::FindPdbStructField(std::string structName, std::string fieldName) -> uintptr_t {

    auto hSym = GetCurrentProcess();

    if (!SymInitialize(hSym, m_filePath.c_str(), false)) {

        std::cerr << "Kurumi::KoiEngine -> Fail to initialize .kopdb engine.\n";

        return -1;
    }

    SymSetSearchPath(hSym, (std::filesystem::current_path().string() + "\\KoiDbgPdbs\\").c_str());

    auto base = SymLoadModuleEx(hSym, nullptr, m_filePath.c_str(), nullptr, 0, 0, nullptr, 0);
    if (base == 0) {

        std::cerr << "Kurumi::KoiEngine -> Fail to load .kopdb file.\n";

        SymCleanup(hSym);
        return -1;
    }

    SYMBOL_INFO_PACKAGE symInfoPackage;
    symInfoPackage.si.SizeOfStruct = sizeof(SYMBOL_INFO);
    symInfoPackage.si.MaxNameLen = MAX_SYM_NAME;

    if (!SymGetTypeFromName(hSym, base, structName.c_str(), &symInfoPackage.si)) {

        std::cerr << "Kurumi::KoiEngine -> Fail to locate a struct in kopdb: " << structName << "\n";

        SymUnloadModule64(hSym, base);
        SymCleanup(hSym);
        return -1;
    }

    auto typeId = symInfoPackage.si.TypeIndex;
    auto moduleBase = symInfoPackage.si.ModBase;

    DWORD numChildren = 0;
    if (!SymGetTypeInfo(hSym, moduleBase, typeId, TI_GET_CHILDRENCOUNT, &numChildren)) {

        std::cerr << "Kurumi::KoiEngine -> Fail getting kopdb struct members.\n";

        SymUnloadModule64(hSym, base);
        SymCleanup(hSym);

        return -1;
    }

    auto children = new TI_FINDCHILDREN_PARAMS[sizeof(TI_FINDCHILDREN_PARAMS) + numChildren * sizeof(ULONG)];
    children->Count = numChildren;
    children->Start = 0;

    if (!SymGetTypeInfo(hSym, moduleBase, typeId, TI_FINDCHILDREN, children)) {

        std::cerr << "Kurumi::KoiEngine -> Fail getting kopdb child fields.\n";

        delete[] children;

        SymUnloadModule64(hSym, base);

        SymCleanup(hSym);

        return -1;
    }

    auto offset = -1;
    for (auto i = 0; i < numChildren; ++i) {

        auto memberId = children->ChildId[i];

        WCHAR* memberName = nullptr;
        SymGetTypeInfo(hSym, moduleBase, memberId, TI_GET_SYMNAME, &memberName);

        std::wstring wFieldName(fieldName.begin(), fieldName.end());

        if (memberName && wFieldName == std::wstring(memberName)) {

            DWORD64 memberOffset = 0;
            SymGetTypeInfo(hSym, moduleBase, memberId, TI_GET_OFFSET, &memberOffset);

            offset = static_cast<uintptr_t>(memberOffset);

            LocalFree(memberName);
            break;
        }

        if (memberName) LocalFree(memberName);
    }

    delete[] children;
    SymUnloadModule64(hSym, base);
    SymCleanup(hSym);

    return offset;
}

auto CALLBACK KurumiPdbFast::EnumSymbolsCallback(PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext) -> BOOL {

    auto* vecSymbols = reinterpret_cast<std::vector<std::pair<std::string, uintptr_t>>*>(UserContext);

    if (pSymInfo->Tag == SymTagFunction) vecSymbols->emplace_back(std::make_pair( pSymInfo->Name, pSymInfo->Address - 0x10000000));

    return TRUE;
}

auto KurumiPdbFast::ParsePdbFunctionsAndGetListInternal(std::string pdbPath) -> std::vector<std::pair<std::string, uintptr_t>> {

    std::vector<std::pair<std::string, uintptr_t>> vecSymbols;

    auto hSym = GetCurrentProcess();

    if (!SymInitialize(hSym, nullptr, false)) return vecSymbols;

    auto pdbDirectory = pdbPath.substr(0, pdbPath.find_last_of("\\/"));

    SymSetSearchPath(hSym, pdbDirectory.c_str());

    auto base = SymLoadModule64(hSym, nullptr, pdbPath.c_str(), nullptr, 0x10000000, 0);

    if (base == 0) {

        SymCleanup(hSym);

        return vecSymbols;
    }

    if (!SymEnumSymbols(hSym, base, nullptr, KurumiPdbFast::EnumSymbolsCallback, &vecSymbols)) return vecSymbols;

    SymCleanup(hSym);

    return vecSymbols;
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

    auto _stdcall HasInternetConnection() -> bool {

        return InternetCheckConnectionA("http://www.google.com", FLAG_ICC_FORCE_CONNECTION, 0);
    }

    auto _stdcall InitKurumiKOPDB(std::string filePath) -> bool {

        auto getDllPath = []() -> std::string {
            
            char path[MAX_PATH] { 0 };

            auto hModule = GetModuleHandleA("ntdll.dll");
            
            if (!hModule) {
                MessageBoxA(NULL, "Failed to get module handle for NTDLL.DLL", "KOI::KURUMI::ERROR", MB_ICONERROR);
                throw std::runtime_error("KOI::KURUMI::ERROR -> Failed to get module handle for NTDLL.DLL");
            }

            auto pathLen = GetModuleFileNameA(hModule, path, MAX_PATH);

            if (pathLen == 0 || pathLen >= MAX_PATH) {
                MessageBoxA(NULL, "Failed to get module path or path too long.", "KOI::KURUMI::ERROR", MB_ICONERROR);
                throw std::runtime_error("KOI::KURUMI::ERROR -> Failed to get module path or path too long.");
            }

            return std::string(path);
        };

        if (filePath.empty() || filePath == "" || filePath.find("ntdll.dll") == std::string::npos) filePath.assign(getDllPath());

        Kurumi::kurumiPdb = std::make_unique<KurumiPDB>(filePath);

        return kurumiPdb->DownloadKoiPdb();
    }

    auto _stdcall FindFieldKoiPDB(std::string fieldName) -> uintptr_t {

        return Kurumi::kurumiPdb->FindPdbField(fieldName);
    }

    auto _stdcall FindStructFieldKOPDB(std::string structName, std::string fieldName) -> uintptr_t {

        return Kurumi::kurumiPdb->FindPdbStructField(structName, fieldName);
    }

    auto _stdcall AttachKewDbgKoiDbgDevelopmentInterface() -> void {

        std::printf("Kurumi::KoiEngine -> The Maldec Lolis Code Debugger are desactivated on compile time to avoid bad use of engine and code.\n");

    }

    auto _stdcall ParsePdbFunctionsAndSymbolsByPath(std::string pdbPath) -> std::vector<std::pair<std::string, uintptr_t>> {

        return KurumiPdbFast::ParsePdbFunctionsAndGetListInternal(pdbPath);
    }

}