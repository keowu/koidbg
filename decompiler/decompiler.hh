/*
    File: decompiler.hh
    Author: João Vitor(@Keowu)
    Created: 10/11/2024
    Last Update: 10/11/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#ifndef DECOMPILER_HH
#define DECOMPILER_HH
#include <QTextEdit>
#include <QSyntaxHighlighter>
#include <QRegularExpression>
#include <QTextCharFormat>
#include <QColor>

class Decompiler : public QSyntaxHighlighter {
public:
    Decompiler(QTextDocument *parent = nullptr)
        : QSyntaxHighlighter(parent) {
        setupHighlightingRules();
    }

protected:
    void highlightBlock(const QString &text) override;

private:
    struct HighlightingRule {

        QRegularExpression pattern;
        QTextCharFormat format;

    };

    QVector<HighlightingRule> highlightingRules;

    QRegularExpression commentStartExpression{R"(/\*)"};
    QRegularExpression commentEndExpression{R"(\*/)"};
    QTextCharFormat keywordFormat;
    QTextCharFormat numberFormat;
    QTextCharFormat commentFormat;

    void setupHighlightingRules();
};

#endif // DECOMPILER_HH
