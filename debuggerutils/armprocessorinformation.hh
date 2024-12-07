/*
    File: armprocessorinformaton.hh
    Author: João Vitor(@Keowu)
    Created: 03/12/2024
    Last Update: 06/12/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.

    Instantiate with a std::unique_ptr for safety free memory after class usage.
*/
#ifndef ARMPROCESSORINFORMATION_HH
#define ARMPROCESSORINFORMATION_HH
#include <QMainWindow>
#include <Windows.h>

//https://gitlab.winehq.org/toadking/wine/-/blob/24694dabfc53fc850cf035e187a4c15b77d6bc77/include/winnt.h
#define PF_ARM_SVE_INSTRUCTIONS_AVAILABLE       46
#define PF_ARM_SVE2_INSTRUCTIONS_AVAILABLE      47
#define PF_ARM_SVE2_1_INSTRUCTIONS_AVAILABLE    48
#define PF_ARM_SVE_AES_INSTRUCTIONS_AVAILABLE   49
#define PF_ARM_SVE_PMULL128_INSTRUCTIONS_AVAILABLE 50
#define PF_ARM_SVE_BITPERM_INSTRUCTIONS_AVAILABLE 51
#define PF_ARM_SVE_BF16_INSTRUCTIONS_AVAILABLE  52
#define PF_ARM_SVE_EBF16_INSTRUCTIONS_AVAILABLE 53
#define PF_ARM_SVE_B16B16_INSTRUCTIONS_AVAILABLE 54
#define PF_ARM_SVE_SHA3_INSTRUCTIONS_AVAILABLE  55
#define PF_ARM_SVE_SM4_INSTRUCTIONS_AVAILABLE   56
#define PF_ARM_SVE_I8MM_INSTRUCTIONS_AVAILABLE  57
#define PF_ARM_SVE_F32MM_INSTRUCTIONS_AVAILABLE 58
#define PF_ARM_SVE_F64MM_INSTRUCTIONS_AVAILABLE 59
#define PF_BMI2_INSTRUCTIONS_AVAILABLE          60

struct Feature {
    union {
        struct {
            WORD reg;
            BYTE offset;
            BYTE minimum;
        };
        UINT raw;
    };

#ifdef AARCH64CHECK_NO_STRINGS
    constexpr Feature (WORD reg, BYTE offset, BYTE minimum, const char * name = nullptr)
        : reg (reg)
        , offset (offset)
        , minimum (minimum) {};
#else
    const char * name = nullptr;
    constexpr Feature (WORD reg, BYTE offset, BYTE minimum, const char * name = nullptr)
        : reg (reg)
        , offset (offset)
        , minimum (minimum)
        , name (name) {};
#endif

    inline auto operator <=> (Feature other) const noexcept { return this->raw <=> other.raw; }
    inline auto operator == (Feature other) const noexcept { return this->raw == other.raw; }
};

namespace Register {

    static constexpr WORD MIDR_EL1 = 0x4000;
    static constexpr WORD ID_AA64PFR0_EL1 = 0x4020;
    static constexpr WORD ID_AA64PFR1_EL1 = 0x4021;
    static constexpr WORD ID_AA64DFR0_EL1 = 0x4028;
    static constexpr WORD ID_AA64DFR1_EL1 = 0x4029;
    static constexpr WORD ID_AA64ISAR0_EL1 = 0x4030; // Instruction Set Attribute Register 0
    static constexpr WORD ID_AA64ISAR1_EL1 = 0x4031;
    static constexpr WORD ID_AA64ISAR2_EL1 = 0x4032;
    static constexpr WORD ID_AA64MMFR0_EL1 = 0x4038;
    static constexpr WORD ID_AA64MMFR1_EL1 = 0x4039;
    static constexpr WORD ID_AA64MMFR2_EL1 = 0x403A;
    static constexpr WORD ID_AA64MMFR3_EL1 = 0x403B;
    static constexpr WORD SCTLR_EL1 = 0x4080; // System Control Register
    static constexpr WORD CPACR_EL1 = 0x4081;
    static constexpr WORD TTBR0_EL1 = 0x4100; // Translation Table Base Register
    static constexpr WORD TTBR1_EL1 = 0x4101;
    static constexpr WORD MAIR_EL1 = 0x4510; // Memory Attribute Indirection Register

    };

namespace Features {
    static constexpr Feature Null = { 0,0,0 }; // identity feature to simplify spans below, always check true

    static constexpr Feature AES    = { Register::ID_AA64ISAR0_EL1, 4,  1, "AES" };
    static constexpr Feature PMULL  = { Register::ID_AA64ISAR0_EL1, 4,  2, "AES+PMULL" };
    static constexpr Feature SHA1   = { Register::ID_AA64ISAR0_EL1, 8,  1, "SHA1" };
    static constexpr Feature SHA256 = { Register::ID_AA64ISAR0_EL1, 12, 1, "SHA256" };
    static constexpr Feature SHA512 = { Register::ID_AA64ISAR0_EL1, 12, 2, "SHA256+SHA512" };
    static constexpr Feature CRC32  = { Register::ID_AA64ISAR0_EL1, 16, 1, "CRC32" };
    static constexpr Feature LSE    = { Register::ID_AA64ISAR0_EL1, 20, 2, "LSE" };     // v8.1, Large Systems Extension, Atomic instructions LDADD, LDCLR, LDEOR, LDSET, LDSMAX, LDSMIN, LDUMAX, LDUMIN, CAS, CASP, and SWP
    static constexpr Feature LSE128 = { Register::ID_AA64ISAR0_EL1, 20, 3, "LSE128" };  // opt., Large Systems Extension, FEAT_LSE plus 128-bit instructions LDCLRP, LDSETP, and SWPP
    static constexpr Feature TME    = { Register::ID_AA64ISAR0_EL1, 24, 1, "TME" };
    static constexpr Feature RDM    = { Register::ID_AA64ISAR0_EL1, 28, 1, "RDM" };     // v8.2
    static constexpr Feature SHA3   = { Register::ID_AA64ISAR0_EL1, 32, 1, "SHA3" };
    static constexpr Feature SM3    = { Register::ID_AA64ISAR0_EL1, 36, 1, "SM3" };
    static constexpr Feature SM4    = { Register::ID_AA64ISAR0_EL1, 40, 1, "SM4" };
    static constexpr Feature DotProd= { Register::ID_AA64ISAR0_EL1, 44, 1, "DotProd" };
    static constexpr Feature FHM    = { Register::ID_AA64ISAR0_EL1, 48, 1, "FHM" };
    static constexpr Feature FlagM  = { Register::ID_AA64ISAR0_EL1, 52, 1, "FlagM" };
    static constexpr Feature FlagM2 = { Register::ID_AA64ISAR0_EL1, 52, 2, "FlagM2" };
    static constexpr Feature TLBIOS = { Register::ID_AA64ISAR0_EL1, 56, 1, "TLBIOS" };
    static constexpr Feature TLBIRANGE={Register::ID_AA64ISAR0_EL1, 56, 2, "TLBIRANGE" };
    static constexpr Feature RNG    = { Register::ID_AA64ISAR0_EL1, 60, 1, "RNG" };

    static constexpr Feature DPB    = { Register::ID_AA64ISAR1_EL1, 0,  1, "DPB" }; // v8.2
    static constexpr Feature DPB2   = { Register::ID_AA64ISAR1_EL1, 0,  2, "DPB+DPB2" }; // v8.2
    static constexpr Feature PAuth  = { Register::ID_AA64ISAR1_EL1, 4,  1, "PAuth" }; // v8.3
    static constexpr Feature EPAC   = { Register::ID_AA64ISAR1_EL1, 4,  2, "PAuth+EPAC" };
    static constexpr Feature PAuth2 = { Register::ID_AA64ISAR1_EL1, 4,  3, "PAuth+PAuth2+EPAC" };
    static constexpr Feature FPAC   = { Register::ID_AA64ISAR1_EL1, 4,  4, "PAuth+PAuth2+EPAC+FPAC" };
    static constexpr Feature FPACCOMBINE = { Register::ID_AA64ISAR1_EL1, 4, 5, "PAuth+PAuth2+EPAC+FPAC+FPACCOMBINE" };
    static constexpr Feature PAuth_LR={ Register::ID_AA64ISAR1_EL1, 4, 6, "PAuth+PAuth2+EPAC+FPAC+FPACCOMBINE+PAuth_LR" };
    static constexpr Feature JSCVT  = { Register::ID_AA64ISAR1_EL1, 12, 1, "JSCVT" }; // v8.3
    static constexpr Feature FCMA   = { Register::ID_AA64ISAR1_EL1, 16, 1, "FCMA" }; // v8.3
    static constexpr Feature LRCPC  = { Register::ID_AA64ISAR1_EL1, 20, 1, "LRCPC" }; // v8.3
    static constexpr Feature LRCPC2 = { Register::ID_AA64ISAR1_EL1, 20, 2, "LRCPC+LRCPC2" }; // v8.4
    static constexpr Feature LRCPC3 = { Register::ID_AA64ISAR1_EL1, 20, 3, "LRCPC+LRCPC2+LRCPC3" };
    static constexpr Feature PACQARMA5={Register::ID_AA64ISAR1_EL1, 24, 1, "PACQARMA5" };
    static constexpr Feature PACIMP = { Register::ID_AA64ISAR1_EL1, 28, 1, "PACIMP" };
    static constexpr Feature FRINTTS= { Register::ID_AA64ISAR1_EL1, 32, 1, "FRINTTS" };
    static constexpr Feature SB     = { Register::ID_AA64ISAR1_EL1, 36, 1, "SB" };
    static constexpr Feature SPECRES= { Register::ID_AA64ISAR1_EL1, 40, 1, "SPECRES" };
    static constexpr Feature SPECRES2={ Register::ID_AA64ISAR1_EL1, 40, 2, "SPECRES+SPECRES2" };
    static constexpr Feature BF16   = { Register::ID_AA64ISAR1_EL1, 44, 1, "BF16" };
    static constexpr Feature EBF16  = { Register::ID_AA64ISAR1_EL1, 44, 2, "BF16+EBF16" };
    static constexpr Feature DGH    = { Register::ID_AA64ISAR1_EL1, 48, 1, "DGH" };
    static constexpr Feature I8MM   = { Register::ID_AA64ISAR1_EL1, 52, 1, "I8MM" };
    static constexpr Feature XS     = { Register::ID_AA64ISAR1_EL1, 56, 1, "XS" };
    static constexpr Feature LS64   = { Register::ID_AA64ISAR1_EL1, 60, 1, "LS64" };
    static constexpr Feature LS64_V = { Register::ID_AA64ISAR1_EL1, 60, 2, "LS64+LS64_V" };
    static constexpr Feature LS64_ACCDATA = { Register::ID_AA64ISAR1_EL1, 60, 3, "LS64+LS64_V+LS64_ACCDATA" };
    static constexpr Feature LS64WB = { Register::ID_AA64ISAR1_EL1, 60, 4, "LS64+LS64_V+LS64_ACCDATA+LS64WB" };

    static constexpr Feature WFxT   = { Register::ID_AA64ISAR2_EL1, 0,  2, "WFxT" };
    static constexpr Feature MOPS   = { Register::ID_AA64ISAR2_EL1, 16, 1, "MOPS" };
    static constexpr Feature HBC    = { Register::ID_AA64ISAR2_EL1, 20, 1, "HBC" };
    static constexpr Feature CLRBHB = { Register::ID_AA64ISAR2_EL1, 28, 1, "CLRBHB" };
    static constexpr Feature CSSC   = { Register::ID_AA64ISAR2_EL1, 52, 1, "CSSC" };
    static constexpr Feature CMPBR  = { Register::ID_AA64ISAR2_EL1, 52, 2, "CSSC+CMPBR" };

    static constexpr Feature FGT    = { Register::ID_AA64MMFR0_EL1, 56, 1, "FGT" };
    static constexpr Feature FGT2   = { Register::ID_AA64MMFR0_EL1, 56, 2, "FGT+FGT2" };
    static constexpr Feature ECV    = { Register::ID_AA64MMFR0_EL1, 60, 1, "ECV" };

    static constexpr Feature VHE    = { Register::ID_AA64MMFR1_EL1, 8,  1, "VHE" }; // v8.1, but not reported inside of Hyper-V VMs
    static constexpr Feature HPDS   = { Register::ID_AA64MMFR1_EL1, 12, 1, "HPDS" }; // v8.1, but not reported by Snapdragon 8cx Gen3
    static constexpr Feature HPDS2  = { Register::ID_AA64MMFR1_EL1, 12, 2, "HPDS+HPDS2" };
    static constexpr Feature LOR    = { Register::ID_AA64MMFR1_EL1, 16, 1, "LOR" }; // v8.1
    static constexpr Feature PAN    = { Register::ID_AA64MMFR1_EL1, 20, 1, "PAN" }; // v8.1
    static constexpr Feature PAN2   = { Register::ID_AA64MMFR1_EL1, 20, 2, "PAN+PAN2" }; // v8.2
    static constexpr Feature PAN3   = { Register::ID_AA64MMFR1_EL1, 20, 3, "PAN+PAN2+PAN3" };
    static constexpr Feature XNX    = { Register::ID_AA64MMFR1_EL1, 28, 1, "XNX" }; // v8.2
    static constexpr Feature ETS2   = { Register::ID_AA64MMFR1_EL1, 36, 2, "ETS2" };
    static constexpr Feature ETS3   = { Register::ID_AA64MMFR1_EL1, 36, 3, "ETS2+ETS3" };
    static constexpr Feature TIDCP1 = { Register::ID_AA64MMFR1_EL1, 52, 1, "TIDCP1" };
    static constexpr Feature CMOW   = { Register::ID_AA64MMFR1_EL1, 56, 1, "CMOW" };
    static constexpr Feature ECBHB  = { Register::ID_AA64MMFR1_EL1, 60, 1, "ECBHB" };

    static constexpr Feature TTCNP  = { Register::ID_AA64MMFR2_EL1, 0,  1, "TTCNP" }; // v8.2
    static constexpr Feature UAO    = { Register::ID_AA64MMFR2_EL1, 4,  1, "UAO" }; // v8.2
    static constexpr Feature LSMAOC = { Register::ID_AA64MMFR2_EL1, 8,  1, "LSMAOC" };
    static constexpr Feature IESB   = { Register::ID_AA64MMFR2_EL1, 12, 1, "IESB" };
    static constexpr Feature LVA    = { Register::ID_AA64MMFR2_EL1, 16, 1, "LVA" };
    static constexpr Feature LVA3   = { Register::ID_AA64MMFR2_EL1, 16, 2, "LVA+LVA3" };
    static constexpr Feature CCIDX  = { Register::ID_AA64MMFR2_EL1, 20, 1, "CCIDX" };
    static constexpr Feature NV     = { Register::ID_AA64MMFR2_EL1, 24, 1, "NV" };
    static constexpr Feature NV2    = { Register::ID_AA64MMFR2_EL1, 24, 2, "NV+NV2" };
    static constexpr Feature TTST   = { Register::ID_AA64MMFR2_EL1, 28, 1, "TTST" };
    static constexpr Feature LSE2   = { Register::ID_AA64MMFR2_EL1, 32, 1, "LSE2" };
    static constexpr Feature IDST   = { Register::ID_AA64MMFR2_EL1, 36, 1, "IDST" };
    static constexpr Feature IDTE3  = { Register::ID_AA64MMFR2_EL1, 36, 2, "IDTE3" };
    static constexpr Feature S2FWB  = { Register::ID_AA64MMFR2_EL1, 40, 1, "S2FWB" };
    static constexpr Feature TTL    = { Register::ID_AA64MMFR2_EL1, 48, 1, "TTL" };
    static constexpr Feature BBM    = { Register::ID_AA64MMFR2_EL1, 52, 1, "BBM" };
    static constexpr Feature BBM_L2 = { Register::ID_AA64MMFR2_EL1, 52, 2, "BBM+BBM_L2" };
    static constexpr Feature E0PD   = { Register::ID_AA64MMFR2_EL1, 60, 1, "E0PD" };

    static constexpr Feature TCR2   = { Register::ID_AA64MMFR3_EL1, 0,  1, "TCR2" }; // v8.9
    static constexpr Feature SCTLR2 = { Register::ID_AA64MMFR3_EL1, 4,  1, "SCTLR2" }; // v8.9

    static constexpr Feature FP16   = { Register::ID_AA64PFR0_EL1, 20, 1, "FP16" };
    static constexpr Feature RAS    = { Register::ID_AA64PFR0_EL1, 28, 1, "RAS" }; // v8.2
    static constexpr Feature RASv1p1= { Register::ID_AA64PFR0_EL1, 28, 2, "RAS+RASv1.1" };
    static constexpr Feature RASv2  = { Register::ID_AA64PFR0_EL1, 28, 3, "RAS+RASv1.1+RASv2" };
    static constexpr Feature SVE    = { Register::ID_AA64PFR0_EL1, 32, 1, "SVE" }; // ID_AA64ZFR0_EL1
    static constexpr Feature SEL2   = { Register::ID_AA64PFR0_EL1, 36, 1, "SEL2" };
    static constexpr Feature AMUv1  = { Register::ID_AA64PFR0_EL1, 44, 1, "AMUv1" };
    static constexpr Feature AMUv1p1= { Register::ID_AA64PFR0_EL1, 44, 2, "AMUv1+AMUv1.1" };
    static constexpr Feature DIT    = { Register::ID_AA64PFR0_EL1, 48, 1, "DIT" };
    static constexpr Feature CSV2   = { Register::ID_AA64PFR0_EL1, 56, 1, "CSV2" };
    static constexpr Feature CSV2_2 = { Register::ID_AA64PFR0_EL1, 56, 2, "CSV2+CSV2.2" };
    static constexpr Feature CSV2_3 = { Register::ID_AA64PFR0_EL1, 56, 3, "CSV2+CSV2.2+CSV2.3" };
    static constexpr Feature CSV3   = { Register::ID_AA64PFR0_EL1, 60, 1, "CSV3" };

    static constexpr Feature BTI    = { Register::ID_AA64PFR1_EL1, 0, 1, "BTI" };
    static constexpr Feature SSBS   = { Register::ID_AA64PFR1_EL1, 4, 1, "SSBS" };
    static constexpr Feature SSBS2  = { Register::ID_AA64PFR1_EL1, 4, 2, "SSBS+SSBS2" };
    static constexpr Feature MTE    = { Register::ID_AA64PFR1_EL1, 8, 1, "MTE" };
    static constexpr Feature MTE2   = { Register::ID_AA64PFR1_EL1, 8, 2, "MTE+MTE2" };
    static constexpr Feature MTE3   = { Register::ID_AA64PFR1_EL1, 8, 3, "MTE+MTE2+MTE3" };
    static constexpr Feature SME    = { Register::ID_AA64PFR1_EL1, 24, 1, "SME" };
    static constexpr Feature SME2   = { Register::ID_AA64PFR1_EL1, 24, 2, "SME+SME2" };
    static constexpr Feature RNDS   = { Register::ID_AA64PFR1_EL1, 28, 1, "RND" };
    static constexpr Feature NMI    = { Register::ID_AA64PFR1_EL1, 36, 1, "NMI" };
    static constexpr Feature GCS    = { Register::ID_AA64PFR1_EL1, 44, 1, "GCS" }; // Guarded Control Stack
    static constexpr Feature THE    = { Register::ID_AA64PFR1_EL1, 48, 1, "THE" }; // Translation Hardening Extension
    static constexpr Feature DoubleFault2 = { Register::ID_AA64PFR1_EL1, 56, 1, "DoubleFault2" };
    static constexpr Feature PFAR   = { Register::ID_AA64PFR1_EL1, 60, 1, "PFAR" };

    static constexpr Feature Debugv8p1 = { Register::ID_AA64DFR0_EL1, 0, 0b0111, "Debugv8.1" };
    static constexpr Feature Debugv8p2 = { Register::ID_AA64DFR0_EL1, 0, 0b1000, "Debugv8.2" }; // v8.2
    static constexpr Feature Debugv8p4 = { Register::ID_AA64DFR0_EL1, 0, 0b1001, "Debugv8.4" };
    static constexpr Feature Debugv8p8 = { Register::ID_AA64DFR0_EL1, 0, 0b1010, "Debugv8.8" };
    static constexpr Feature Debugv8p9 = { Register::ID_AA64DFR0_EL1, 0, 0b1011, "Debugv8.9" };

};

namespace Sets {

    static constexpr Feature v8_1_Minimal [] = { Features::LSE, Features::PAN };
    static constexpr Feature v8_1_Relaxed [] = { Features::Null };
    static constexpr Feature v8_1_Strict  [] = { Features::HPDS, Features::LOR, Features::VHE };

    static constexpr Feature v8_2_Minimal [] = { Features::RDM, Features::DPB, Features::PAN2, Features::UAO };
    static constexpr Feature v8_2_Relaxed [] = { Features::Null };
    static constexpr Feature v8_2_Strict  [] = { Features::TTCNP, Features::XNX, Features::Debugv8p2 }; // how to check FEAT_ASMv8p2 ?

    static constexpr Feature v8_3_Minimal [] = { Features::LRCPC, Features::PAuth };
    static constexpr Feature v8_3_Relaxed [] = { Features::Null }; // Features::FCMA ?
    static constexpr Feature v8_3_Strict  [] = { Features::Null }; // Features::JSCVT ?

    static constexpr Feature v8_4_Minimal [] = { Features::LRCPC2, Features::FlagM };
    static constexpr Feature v8_4_Relaxed [] = { Features::IDST, Features::LSE2, Features::TLBIOS, Features::TLBIRANGE };
    static constexpr Feature v8_4_Strict  [] = { Features::Debugv8p4, Features::DIT, Features::S2FWB, Features::BBM, Features::TTL };

    static constexpr Feature v8_5_Minimal [] = { Features::CSV2, Features::CSV3, Features::FlagM2, Features::DPB2, Features::FRINTTS, Features::SB, Features::SPECRES };
    static constexpr Feature v8_5_Relaxed [] = { Features::Null };
    static constexpr Feature v8_5_Strict  [] = { Features::BTI, Features::E0PD };

    static constexpr Feature v8_6_Minimal [] = { Features::BF16, Features::FGT, Features::ECV };
    static constexpr Feature v8_6_Relaxed [] = { Features::I8MM  };
    static constexpr Feature v8_6_Strict  [] = { Features::PAuth2 };

    static constexpr Feature v8_7_Minimal [] = { Features::XS, Features::WFxT, Features::PAN3 };
    static constexpr Feature v8_7_Relaxed [] = { Features::Null };
    static constexpr Feature v8_7_Strict  [] = { Features::Null };

    static constexpr Feature v8_8_Minimal [] = { Features::NMI, Features::Debugv8p8, Features::MOPS, Features::HBC, Features::ETS2, Features::CMOW, Features::TIDCP1  };
    static constexpr Feature v8_8_Relaxed [] = { Features::Null };
    static constexpr Feature v8_8_Strict  [] = { Features::Null };

    static constexpr Feature v8_9_Minimal [] = { Features::SPECRES2, Features::CLRBHB, Features::CSSC, Features::ECBHB, Features::FGT2 };
    static constexpr Feature v8_9_Relaxed [] = { Features::Debugv8p9 };
    static constexpr Feature v8_9_Strict  [] = { Features::SCTLR2, Features::TCR2 };

    static constexpr Feature v9_0_Minimal [] = { Features::DotProd, Features::SVE, Features::FHM };
    static constexpr Feature v9_0_Relaxed [] = { Features::FP16, Features::RAS };
    static constexpr Feature v9_0_Strict  [] = { Features::FRINTTS };

    static constexpr Feature v9_1_Minimal [] = { Features::SVE };
    static constexpr Feature v9_1_Relaxed [] = { Features::Null };
    static constexpr Feature v9_1_Strict  [] = { Features::Null };

    static constexpr Feature v9_2_Minimal [] = { Features::SVE };
    static constexpr Feature v9_2_Relaxed [] = { Features::Null };
    static constexpr Feature v9_2_Strict  [] = { Features::Null };

    static constexpr Feature v9_3_Minimal [] = { Features::SVE };
    static constexpr Feature v9_3_Relaxed [] = { Features::Null };
    static constexpr Feature v9_3_Strict  [] = { Features::Null };

    static constexpr Feature v9_4_Minimal [] = { Features::SVE, Features::CSSC };
    static constexpr Feature v9_4_Relaxed [] = { Features::Null };
    static constexpr Feature v9_4_Strict  [] = { Features::Null };

};

class ArmProcessorInformation {

private:

    std::vector<std::map<std::uint16_t, std::uint64_t>> m_registers;

    struct PROCESSOR_FEATURES {
        const char *name;
        DWORD code;
    };

    std::array<PROCESSOR_FEATURES, 20> procFeatures = {

        PROCESSOR_FEATURES{ "CRYPTO", PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE },
        PROCESSOR_FEATURES{ "CRC32", PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE },
        PROCESSOR_FEATURES{ "ATOMIC(v8.1)", PF_ARM_V81_ATOMIC_INSTRUCTIONS_AVAILABLE },
        PROCESSOR_FEATURES{ "DP(v8.2)", PF_ARM_V82_DP_INSTRUCTIONS_AVAILABLE },
        PROCESSOR_FEATURES{ "JSCVT(v8.3)", PF_ARM_V83_JSCVT_INSTRUCTIONS_AVAILABLE },
        PROCESSOR_FEATURES{ "LRCPC(v8.3)", PF_ARM_V83_LRCPC_INSTRUCTIONS_AVAILABLE },
        PROCESSOR_FEATURES{ "SVE", PF_ARM_SVE_INSTRUCTIONS_AVAILABLE },
        PROCESSOR_FEATURES{ "SVE2", PF_ARM_SVE2_INSTRUCTIONS_AVAILABLE },
        PROCESSOR_FEATURES{ "SVE2.1", PF_ARM_SVE2_1_INSTRUCTIONS_AVAILABLE },
        PROCESSOR_FEATURES{ "SVE-AES", PF_ARM_SVE_AES_INSTRUCTIONS_AVAILABLE },
        PROCESSOR_FEATURES{ "SVE-PMULL128", PF_ARM_SVE_PMULL128_INSTRUCTIONS_AVAILABLE },
        PROCESSOR_FEATURES{ "SVE-BITPERM", PF_ARM_SVE_BITPERM_INSTRUCTIONS_AVAILABLE },
        PROCESSOR_FEATURES{ "SVE-BF16", PF_ARM_SVE_BF16_INSTRUCTIONS_AVAILABLE },
        PROCESSOR_FEATURES{ "SVE-EBF16", PF_ARM_SVE_EBF16_INSTRUCTIONS_AVAILABLE },
        PROCESSOR_FEATURES{ "SVE-B16B16", PF_ARM_SVE_B16B16_INSTRUCTIONS_AVAILABLE },
        PROCESSOR_FEATURES{ "SVE-SHA3", PF_ARM_SVE_SHA3_INSTRUCTIONS_AVAILABLE },
        PROCESSOR_FEATURES{ "SVE-SM4", PF_ARM_SVE_SM4_INSTRUCTIONS_AVAILABLE },
        PROCESSOR_FEATURES{ "SVE-I8MM", PF_ARM_SVE_I8MM_INSTRUCTIONS_AVAILABLE },
        PROCESSOR_FEATURES{ "SVE-F32MM", PF_ARM_SVE_F32MM_INSTRUCTIONS_AVAILABLE },
        PROCESSOR_FEATURES{ "SVE-F64MM", PF_ARM_SVE_F64MM_INSTRUCTIONS_AVAILABLE }

    };

    enum class Strictness {

        Minimal, // matches only minimal set of features, instructions generated by MSVC for that given /arch:ARMvX.Y for user-mode code
        Relaxed, // matches feature values generally found on the architecture of that level as claimed by manufactures
        Strict,  // strictly match register values to ARMvX.Y mandatory requirements
        Count

    };

    struct Level {

        WORD name;
        std::span <const Feature> features [(std::size_t) Strictness::Count];

    };

    static constexpr Level Levels [] = {

        { 0x801, { Sets::v8_1_Minimal, Sets::v8_1_Relaxed, Sets::v8_1_Strict } },
        { 0x802, { Sets::v8_2_Minimal, Sets::v8_2_Relaxed, Sets::v8_2_Strict } },
        { 0x803, { Sets::v8_3_Minimal, Sets::v8_3_Relaxed, Sets::v8_3_Strict } },
        { 0x804, { Sets::v8_4_Minimal, Sets::v8_4_Relaxed, Sets::v8_4_Strict } },
        { 0x805, { Sets::v8_5_Minimal, Sets::v8_5_Relaxed, Sets::v8_5_Strict } },
        { 0x806, { Sets::v8_6_Minimal, Sets::v8_6_Relaxed, Sets::v8_6_Strict } },
        { 0x807, { Sets::v8_7_Minimal, Sets::v8_7_Relaxed, Sets::v8_7_Strict } },
        { 0x808, { Sets::v8_8_Minimal, Sets::v8_8_Relaxed, Sets::v8_8_Strict } },
        { 0x809, { Sets::v8_9_Minimal, Sets::v8_9_Relaxed, Sets::v8_9_Strict } },
        { 0x900, { Sets::v9_0_Minimal, Sets::v9_0_Relaxed, Sets::v9_0_Strict } },
        { 0x901, { Sets::v9_1_Minimal, Sets::v9_1_Relaxed, Sets::v9_1_Strict } },
        { 0x902, { Sets::v9_2_Minimal, Sets::v9_2_Relaxed, Sets::v9_2_Strict } },
        { 0x903, { Sets::v9_3_Minimal, Sets::v9_3_Relaxed, Sets::v9_3_Strict } },
        { 0x904, { Sets::v9_4_Minimal, Sets::v9_4_Relaxed, Sets::v9_4_Strict } },

    };

    auto EclecticSets() -> std::vector<UINT>;
    auto Eclectic() -> std::size_t;
    auto Determine(uint processor, ArmProcessorInformation::Strictness strictness) noexcept -> WORD;
    auto CheckRegisterData() -> bool;
    auto CheckLevel (const ArmProcessorInformation::Level & level, UINT processor, ArmProcessorInformation::Strictness strictness) -> bool;
    auto Check(UINT processor, Feature feature) noexcept -> bool;
    auto GetLevel(WORD name) -> ArmProcessorInformation::Level;
    auto ParseFeatureName(Feature feature, bool rewrite) noexcept -> void;


public:
    QString m_processorName;
    QString m_vendorName;
    QString m_Identifier;
    QString m_processorFeatures;
    QString m_distinctCores;
    QString m_isaLevel;
    QString m_isaFeatures;

    ArmProcessorInformation();


};

#endif // ARMPROCESSORINFORMATION_HH
