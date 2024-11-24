/*
    File: exportpatchs.cc
    Author: João Vitor(@Keowu)
    Created: 17/11/2024
    Last Update: 24/11/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#include "exportpatchs.hh"
#include "ui_exportpatchs.h"

ExportPatchs::ExportPatchs(QWidget *parent, std::vector<DebugCodePatchs>* codePatchs)
    : QMainWindow(parent)
    , ui(new Ui::ExportPatchs) {

    ui->setupUi(this);

    /*
     *  Disable MAXIMIZE Button and Disable FORM Resizing
    */
    setFixedSize(size());
    setWindowFlags(windowFlags() & ~Qt::WindowMaximizeButtonHint);

    connect(ui->btnExportPatchs, &QPushButton::clicked, this, &ExportPatchs::OnExportClicked);

    this->m_codePatchs = codePatchs;

}

auto ExportPatchs::OnExportClicked() -> void {

    qDebug() << "ExportPatchs::OnExportClicked";

    json j;

    auto i = 0;

    for (const auto &patch : *this->m_codePatchs) {

        QByteArray modifiedCode(reinterpret_cast<const char*>(patch.m_modifiedCode.data()), static_cast<int>(patch.m_modifiedCode.size()));
        QByteArray originalCode(reinterpret_cast<const char*>(patch.m_originalCode.data()), static_cast<int>(patch.m_originalCode.size()));

        j[std::to_string(i)] = {

            {"module_name", patch.m_module.m_qStName.toStdString()},
            {"module_offset", patch.m_patchOffset},
            {"module_modified_opcode", modifiedCode.toBase64()},
            {"module_original_opcode", originalCode.toBase64()}

        };

        i += 1;
    }

    auto filePath = QFileDialog::getSaveFileName(

        nullptr,
        tr("Save"),
        "",
        tr("JSON Files (*.json);;All Files (*)")

    );

    if (filePath.isEmpty()) return;

    QFile f(filePath);

    if (!f.open(QIODevice::WriteOnly)) return;

    QTextStream out(&f);

    out << QString::fromStdString(j.dump(4));

    f.close();

    QMessageBox infoBox;
    infoBox.setIcon(QMessageBox::Information);
    infoBox.setWindowTitle("Success");
    infoBox.setText("Your patches was exported with success!");
    infoBox.exec();

    this->~ExportPatchs();

    this->close();

}

ExportPatchs::~ExportPatchs() {

    delete ui;

}
