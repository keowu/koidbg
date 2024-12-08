/*
    File: memorypatchs.hh
    Authors: João Vitor(@Keowu)
    Created: 17/11/2024
    Last Update: 24/11/2024

    Copyright (c) 2024. https://github.com/maldeclabs/koidbg. All rights reserved.
*/
#ifndef MEMORYPATCHS_HH
#define MEMORYPATCHS_HH

#include <QMainWindow>
#include <QStringListModel>
#include "debuggerengine/debugcodepatchs.hh"

namespace Ui {
class MemoryPatchs;
}

class MemoryPatchs : public QMainWindow
{
    Q_OBJECT

public:
    explicit MemoryPatchs(QWidget *parent = nullptr, std::vector<DebugCodePatchs>* codePatchs = {}, HANDLE hProcess = INVALID_HANDLE_VALUE);
    ~MemoryPatchs();

private:
    Ui::MemoryPatchs *ui;
    std::vector<DebugCodePatchs>* m_codePatchs;
    HANDLE m_hProcess;

    auto onAppliedPatchListClicked(const QModelIndex &index) -> void;
    auto updateMemoryPatchsList() -> void;

};

#endif // MEMORYPATCHS_HH
