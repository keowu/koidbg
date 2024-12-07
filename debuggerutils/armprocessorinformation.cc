/*
    File: armprocessorinformaton.cc
    Author: João Vitor(@Keowu)
    Created: 03/12/2024
    Last Update: 06/12/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.

    Instantiate with a std::unique_ptr for safety free memory after class usage.
*/
#include "armprocessorinformation.hh"
#include <set>

auto ArmProcessorInformation::EclecticSets() -> std::vector<UINT> {

    std::vector<UINT> sets;
    sets.reserve(2);

    std::map<std::uint16_t, std::uint64_t> prevmap;

    UINT i{ 0 };

    for (const auto& regmap : this->m_registers) {

        if (prevmap != regmap) {

            prevmap = regmap;

            if (i) sets.push_back (i);

        }

        ++i;
    }

    sets.push_back (i);

    return sets;
}

auto ArmProcessorInformation::Eclectic() -> std::size_t {

    std::set<std::map<std::uint16_t, std::uint64_t>> uniques;

    for (const auto& regmap : this->m_registers) uniques.insert(regmap);

    return uniques.size();
}

auto ArmProcessorInformation::CheckRegisterData() -> bool {

    for (const auto & regmap : this->m_registers) if (!regmap.empty ()) return true;

    return false;
}

auto ArmProcessorInformation::Check(UINT processor, Feature feature) noexcept -> bool {

    if (processor < this->m_registers.size()) {

        if (feature.raw == 0) return true;

        auto i = this->m_registers[processor].find(feature.reg);
        auto e = this->m_registers[processor].end();

        if (i != e) {

            auto nibble = (i->second >> feature.offset) & 0xF;

            return nibble != 0xF
                   && nibble >= feature.minimum;
        }
    }

    return false;
}

auto ArmProcessorInformation::CheckLevel(const ArmProcessorInformation::Level & level, UINT processor, ArmProcessorInformation::Strictness strictness) -> bool {

    for (std::size_t s = 0; s != 1 + (std::size_t) strictness; ++s)
        for (const auto & feature : level.features [s]) if (!Check(processor, feature)) return false;

    return true;
}

ArmProcessorInformation::Level ArmProcessorInformation::GetLevel(WORD name) {

    for (const auto & level : ArmProcessorInformation::Levels) if (level.name == name) return level;

    return {};
}

auto ArmProcessorInformation::Determine(uint processor, ArmProcessorInformation::Strictness strictness) noexcept -> WORD {

    if (this->CheckRegisterData()) {

        WORD match = 0x800;

        for (const auto & level : Levels) {

            if (!CheckLevel(level, processor, strictness)) {

                switch (match) {

                    case 0x8'09: if (CheckLevel(GetLevel(0x904), processor, strictness)) return 0x904; [[ fallthrough ]];
                    case 0x8'08: if (CheckLevel(GetLevel(0x903), processor, strictness)) return 0x903; [[ fallthrough ]];
                    case 0x8'07: if (CheckLevel(GetLevel(0x902), processor, strictness)) return 0x902; [[ fallthrough ]];
                    case 0x8'06: if (CheckLevel(GetLevel(0x901), processor, strictness)) return 0x901; [[ fallthrough ]];
                    case 0x8'05: if (CheckLevel(GetLevel(0x900), processor, strictness)) return 0x900;

                }

                return match;
            }

            match = level.name;

        }

        return match;

    } else return 0x000;
}

auto ArmProcessorInformation::ParseFeatureName(Feature feature, bool rewrite) noexcept -> void {

    if (feature.name && feature.name [0]) {

        if (auto psz_plus = std::strchr (feature.name, '+')) {

            if (rewrite) {

                char temp[128]{ 0 };

                for (auto i = 0u; i != sizeof temp; ++i) {

                    if (feature.name [i] == '+') temp[i] = ' '; else temp[i] = feature.name [i];

                    if (feature.name [i] == '\0') break;

                }

                this->m_isaFeatures += temp;

            } else this->m_isaFeatures += *(psz_plus + 1);
        } else this->m_isaFeatures += QString(" %1").arg(feature.name);
    } else this->m_isaFeatures += QString(" [%1:%2 >= %3]").arg(feature.reg).arg(feature.offset).arg(feature.minimum);

}

ArmProcessorInformation::ArmProcessorInformation() {

    this->m_registers.clear();

    this->m_registers.reserve(GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));

    int processorIndex{ 0 };

    wchar_t szRegPath[64]{ 0 };
    std::swprintf(szRegPath, 64, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\%u", processorIndex);

    HKEY hKeyCPU = NULL;
    DWORD dwError;
    if ((RegOpenKeyEx(HKEY_LOCAL_MACHINE, szRegPath, 0, KEY_READ, &hKeyCPU)) == ERROR_SUCCESS) {

        if (this->m_registers.size() <= std::size_t(processorIndex)) this->m_registers.resize(std::size_t(processorIndex) + 1);

        DWORD index = 0;
        DWORD dwValueType;

        wchar_t szValueName[8];
        DWORD dwValueNameSize;

        std::uint64_t qwValueData;
        DWORD dwValueDataSize;

        do {

            dwValueNameSize = 8;
            dwValueDataSize = 8;

            dwError = RegEnumValue(hKeyCPU, index++, szValueName, &dwValueNameSize, NULL, &dwValueType, (LPBYTE)&qwValueData, &dwValueDataSize);

            if (dwError == ERROR_SUCCESS) {

                if ((dwValueNameSize == 7) && (dwValueType == REG_QWORD) && (dwValueDataSize == 8)) {

                    std::uint16_t id = 0;

                    if (swscanf_s(szValueName, L"CP %hx", &id) == 1) this->m_registers[processorIndex][id] = qwValueData;

                }
            }

        } while (dwError == ERROR_SUCCESS || dwError == ERROR_MORE_DATA);

        wchar_t szProcessorName[256];
        DWORD dwProcessorNameSize = sizeof(szProcessorName) / sizeof(szProcessorName[0]);
        if (RegQueryValueEx(hKeyCPU, L"ProcessorNameString", NULL, &dwValueType, (LPBYTE)szProcessorName, &dwProcessorNameSize) == ERROR_SUCCESS) this->m_processorName = QString(szProcessorName);

        wchar_t szVendorIdentifier[256];
        DWORD dwVendorIdentifierSize = sizeof(szVendorIdentifier) / sizeof(szVendorIdentifier[0]);
        if (RegQueryValueEx(hKeyCPU, L"VendorIdentifier", NULL, &dwValueType, (LPBYTE)szVendorIdentifier, &dwVendorIdentifierSize) == ERROR_SUCCESS) this->m_vendorName = QString(szVendorIdentifier);

        wchar_t szIdentifier[256];
        DWORD dwIdentifierSize = sizeof(szIdentifier) / sizeof(szIdentifier[0]);
        if (RegQueryValueEx(hKeyCPU, L"Identifier", NULL, &dwValueType, (LPBYTE)szIdentifier, &dwIdentifierSize) == ERROR_SUCCESS) this->m_Identifier = QString(szIdentifier);

        RegCloseKey(hKeyCPU);

    }

    for (auto& [name, code] : procFeatures) {

        if (code == PF_ARM_SVE_INSTRUCTIONS_AVAILABLE) m_processorFeatures += "\n  ";

        if (IsProcessorFeaturePresent(code)) m_processorFeatures += QString(name) + " ";
    }

    auto cpuSets = this->EclecticSets();

    if (cpuSets.size() > 1) this->m_distinctCores = QString("%1 distinct ARM cores in %2.").arg(this->Eclectic()).arg(cpuSets.size());

    UINT first { 0 };
    for (auto i = 0; i != cpuSets.size(); ++i) {

        this->m_isaLevel = QString("ISA Level for All Cpus: (%1 and %2):").arg(first).arg(cpuSets[i] - 1);

        auto processor { 0 };
        if (auto result = ArmProcessorInformation::Determine(processor, ArmProcessorInformation::Strictness::Strict)) {

            this->m_isaLevel += QString("\nStrict: ARMv: %1 and %2\n").arg(HIBYTE(result)).arg(LOBYTE(result));

            result = ArmProcessorInformation::Determine (processor, ArmProcessorInformation::Strictness::Relaxed);

            this->m_isaLevel += QString("Relaxed: ARMv: %1 and %2\n").arg(HIBYTE(result)).arg(LOBYTE(result));

            result = ArmProcessorInformation::Determine (processor, ArmProcessorInformation::Strictness::Minimal);

            this->m_isaLevel += QString("Minimal: ARMv: %1 and %2\n").arg(HIBYTE(result)).arg(LOBYTE(result));

            this->m_isaFeatures += QString("ISA Features:\n");

            for (const auto & level : ArmProcessorInformation::Levels) {

                this->m_isaFeatures += QString("%1.%2:").arg(HIBYTE(level.name)).arg(LOBYTE(level.name));

                bool any = false;
                bool missing = false;
                for (auto s = 0; s != static_cast<std::size_t>(ArmProcessorInformation::Strictness::Count); ++s) {

                    for (const auto & feature : level.features[s]) {

                        if (feature != Features::Null) {

                            if (ArmProcessorInformation::Check(processor, feature)) {

                                this->ParseFeatureName(feature, true);
                                any = true;

                            } else missing = true;

                        }
                    }
                }
                if (missing) {

                    if (any) this->m_isaFeatures += QString("\n");
                    else this->m_isaFeatures += QString(" all\n");

                    this->m_isaFeatures += QString(" missing:");

                    for (auto s = 0; s != static_cast<std::size_t>(ArmProcessorInformation::Strictness::Count); ++s) {

                        for (const auto& feature : level.features[s]) {

                            if (!ArmProcessorInformation::Check(processor, feature)) this->ParseFeatureName(feature, false);

                        }

                    }
                }

                std::printf ("\n");
            }

        }else this->m_isaLevel += "\nUnsuported Processor(NOT ARM64)!!";

    }

}
