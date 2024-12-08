/*
    File: exportpatchs.hh
    Authors: João Vitor(@Keowu)
    Created: 17/11/2024
    Last Update: 24/11/2024

    Copyright (c) 2024. https://github.com/maldeclabs/koidbg. All rights reserved.
*/
#ifndef EXPORTPATCHS_HH
#define EXPORTPATCHS_HH

#include <QMainWindow>
#include <QByteArray>
#include <QFileDialog>
#include <QMessageBox>
#include <json.hpp>
#include "debuggerengine/debugcodepatchs.hh"

using json = nlohmann::json;

namespace Ui {
    class ExportPatchs;
}

class ExportPatchs : public QMainWindow {

    Q_OBJECT

public:
    explicit ExportPatchs(QWidget *parent = nullptr, std::vector<DebugCodePatchs>* codePatchs = {});
    ~ExportPatchs();

private:
    Ui::ExportPatchs *ui;
    std::vector<DebugCodePatchs>* m_codePatchs;
    auto OnExportClicked() -> void;

};

#endif // ExportPatchs_HH
