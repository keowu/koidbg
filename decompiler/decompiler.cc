/*
    File: decompiler.cc
    Author: João Vitor(@Keowu)
    Created: 10/11/2024
    Last Update: 10/11/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#include "decompiler.hh"

void Decompiler::highlightBlock(const QString &text) {

    for (const auto &rule : highlightingRules) {

        QRegularExpressionMatchIterator matchIterator = rule.pattern.globalMatch(text);

        while (matchIterator.hasNext()) {

            QRegularExpressionMatch match = matchIterator.next();
            setFormat(match.capturedStart(), match.capturedLength(), rule.format);

        }
    }

    setCurrentBlockState(0);

    if (previousBlockState() != 1) {

        int startIndex = text.indexOf(commentStartExpression);

        while (startIndex >= 0) {

            QRegularExpressionMatch endMatch = commentEndExpression.match(text, startIndex);
            int endIndex = endMatch.hasMatch() ? endMatch.capturedEnd() : text.length();
            int commentLength = endIndex - startIndex;
            setFormat(startIndex, commentLength, commentFormat);
            startIndex = text.indexOf(commentStartExpression, endIndex);

        }
    }
}

void Decompiler::setupHighlightingRules() {

    keywordFormat.setForeground(Qt::blue);

    QStringList keywordPatterns = {
        // C++ keywords
        R"(\bauto\b)", R"(\bbreak\b)", R"(\bcase\b)", R"(\bchar\b)", R"(\bconst\b)", R"(\bcontinue\b)",
        R"(\bdefault\b)", R"(\bdo\b)", R"(\bdouble\b)", R"(\belse\b)", R"(\benum\b)", R"(\bextern\b)",
        R"(\bfloat\b)", R"(\bfor\b)", R"(\bgoto\b)", R"(\bif\b)", R"(\binline\b)", R"(\bint\b)",
        R"(\blong\b)", R"(\bregister\b)", R"(\brestrict\b)", R"(\breturn\b)", R"(\bshort\b)", R"(\bsigned\b)",
        R"(\bsizeof\b)", R"(\bstatic\b)", R"(\bstruct\b)", R"(\bswitch\b)", R"(\btypedef\b)", R"(\bunion\b)",
        R"(\bunsigned\b)", R"(\bvoid\b)", R"(\bvolatile\b)", R"(\bwhile\b)", R"(\bthis\b)",
        R"(\balignas\b)", R"(\balignof\b)", R"(\band\b)", R"(\band_eq\b)", R"(\basm\b)", R"(\batomic_cancel\b)",
        R"(\batomic_commit\b)", R"(\batomic_noexcept\b)", R"(\bbitand\b)", R"(\bbitor\b)", R"(\bbool\b)",
        R"(\bcatch\b)", R"(\bchar16_t\b)", R"(\bchar32_t\b)", R"(\bclass\b)", R"(\bcompl\b)", R"(\bconcept\b)",
        R"(\bconst_cast\b)", R"(\bco_await\b)", R"(\bco_return\b)", R"(\bco_yield\b)", R"(\bdecltype\b)",
        R"(\bdelete\b)", R"(\bdynamic_cast\b)", R"(\bexplicit\b)", R"(\bexport\b)", R"(\bfalse\b)",
        R"(\bfriend\b)", R"(\bmutable\b)", R"(\bnamespace\b)", R"(\bnew\b)", R"(\bnoexcept\b)", R"(\bnot\b)",
        R"(\bnot_eq\b)", R"(\bnullptr\b)", R"(\boperator\b)", R"(\bor\b)", R"(\bor_eq\b)", R"(\bprivate\b)",
        R"(\bprotected\b)", R"(\bpublic\b)", R"(\breinterpret_cast\b)", R"(\brequires\b)", R"(\bstatic_assert\b)",
        R"(\bstatic_cast\b)", R"(\btemplate\b)", R"(\bthis\b)", R"(\bthread_local\b)", R"(\bthrow\b)",
        R"(\btrue\b)", R"(\btry\b)", R"(\btypeid\b)", R"(\btypename\b)", R"(\busing\b)", R"(\bvirtual\b)",
        R"(\bwchar_t\b)", R"(\bxor\b)", R"(\bxor_eq\b)",

        // C++11 features
        R"(\bconstexpr\b)", R"(\bnullptr\b)", R"(\bnoexcept\b)", R"(\bexplicit\b)", R"(\bfinal\b)",
        R"(\boverride\b)", R"(\bthread_local\b)", R"(\bstatic_assert\b)", R"(\bdecltype\b)", R"(\blambda\b)",

        // C++14 features
        R"(\bvariable_templates\b)", R"(\bdecltype_auto\b)", R"(\bmake_unique\b)",

        // C++17 features
        R"(\bif_constexpr\b)", R"(\bstd::byte\b)", R"(\bstructured_bindings\b)", R"(\binline_variables\b)",

        // C++20 features
        R"(\bconcept\b)", R"(\brequires\b)", R"(\bcoroutine\b)", R"(\bconsteval\b)", R"(\bconstinit\b)",
        R"(\bmodule\b)", R"(\bimport\b)", R"(\bco_await\b)", R"(\bco_return\b)", R"(\bco_yield\b)",

        // C++ data types and other commonly used types
        R"(\bchar\b)", R"(\bshort\b)", R"(\bint\b)", R"(\blong\b)", R"(\blonglong\b)", R"(\bunsigned\b)",
        R"(\bfloat\b)", R"(\bdouble\b)", R"(\blongdouble\b)", R"(\bbool\b)", R"(\bvoid\b)", R"(\bsize_t\b)",
        R"(\bptrdiff_t\b)", R"(\bint8_t\b)", R"(\bint16_t\b)", R"(\bint32_t\b)", R"(\bint64_t\b)",
        R"(\buint8_t\b)", R"(\buint16_t\b)", R"(\buint32_t\b)", R"(\buint64_t\b)", R"(\bint_fast8_t\b)",
        R"(\bint_fast16_t\b)", R"(\bint_fast32_t\b)", R"(\bint_fast64_t\b)", R"(\buint_fast8_t\b)",
        R"(\buint_fast16_t\b)", R"(\buint_fast32_t\b)", R"(\buint_fast64_t\b)", R"(\bint_least8_t\b)",
        R"(\bint_least16_t\b)", R"(\bint_least32_t\b)", R"(\bint_least64_t\b)", R"(\buint_least8_t\b)",
        R"(\buint_least16_t\b)", R"(\buint_least32_t\b)", R"(\buint_least64_t\b)", R"(\bintmax_t\b)",
        R"(\buintmax_t\b)", R"(\bintptr_t\b)", R"(\buintptr_t\b)", R"(\bsize_t\b)", R"(\bstd::byte\b)",

        // Windows specific types (for Windows API programming)
        R"(\bDWORD\b)", R"(\bUINT\b)", R"(\bUINT32\b)", R"(\bUINT64\b)", R"(\bint64\b)", R"(\blonglong\b)",
        R"(\bULONGLONG\b)", R"(\bWORD\b)", R"(\bshort\b)", R"(\bBYTE\b)", R"(\bchar\b)", R"(\bLPCSTR\b)",
        R"(\bLPCWSTR\b)", R"(\bPBYTE\b)", R"(\bPSTR\b)", R"(\bPWSTR\b)", R"(\bDWORD_PTR\b)",
        R"(\bSIZE_T\b)", R"(\bINT\b)", R"(\bINT64\b)", R"(\bULONG\b)", R"(\bULONG64\b)", R"(\bBOOLEAN\b)"
    };

    for (const QString &pattern : keywordPatterns) {

        HighlightingRule rule;
        rule.pattern = QRegularExpression(pattern);
        rule.format = keywordFormat;
        highlightingRules.append(rule);

    }

    numberFormat.setForeground(Qt::darkMagenta);
    HighlightingRule numberRule;
    numberRule.pattern = QRegularExpression(R"(\b\d+\b)");
    numberRule.format = numberFormat;
    highlightingRules.append(numberRule);

    commentFormat.setForeground(Qt::darkGreen);
}
