/*
    File: importpatchs.cc
    Author: João Vitor(@Keowu)
    Created: 17/11/2024
    Last Update: 24/11/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#include "importpatchs.hh"
#include "ui_importpatchs.h"

ImportPatchs::ImportPatchs(QWidget *parent, SetPatching setPatchingCallback)
    : QMainWindow(parent)
    , ui(new Ui::ImportPatchs) {

    ui->setupUi(this);

    /*
     *  Disable MAXIMIZE Button and Disable FORM Resizing
    */
    setFixedSize(size());
    setWindowFlags(windowFlags() & ~Qt::WindowMaximizeButtonHint);

    connect(ui->btnImportPatchs, &QPushButton::clicked, this, &ImportPatchs::OnImportClicked);

    this->m_setPatchingCallback = setPatchingCallback;

}

auto ImportPatchs::decodeBase64(const std::string& base64) -> std::vector<uint8_t> {

    QByteArray decoded = QByteArray::fromBase64(QByteArray::fromStdString(base64));

    return std::vector<uint8_t>(decoded.begin(), decoded.end());
}

auto ImportPatchs::OnImportClicked() -> void {

    qDebug() << "ImportPatchs::OnImportClicked";

    auto fileName = QFileDialog::getOpenFileName(

        nullptr,
        "Open JSON File",
        "",
        "JSON Files (*.json);;All Files (*)"

    );

    if (fileName.isEmpty()) return;

    QFile file(fileName);

    if (!file.open(QIODevice::ReadOnly)) return;

    auto fileData = file.readAll();
    file.close();

    auto jsonString = fileData.toStdString();

    try {

        auto jsonObj = json::parse(jsonString);

        for (auto& el : jsonObj.items()) {

            auto key = QString::fromStdString(el.key());
            auto value = el.value();

            auto moduleName = value["module_name"].get<std::string>();
            auto offset = value["module_offset"].get<uintptr_t>();
            auto originalOpcodes = this->decodeBase64(value["module_original_opcode"].get<std::string>());
            auto newOpcodes = this->decodeBase64(value["module_modified_opcode"].get<std::string>());

            qDebug() << "Key:" << key
                     << ", Module Name:" << QString::fromStdString(moduleName)
                     << ", Offset:" << offset
                     << ", Original Opcodes:" << QByteArray::fromRawData(
                                                     reinterpret_cast<const char*>(originalOpcodes.data()),
                                                     static_cast<int>(originalOpcodes.size())).toHex()
                     << ", Modified Opcodes:" << QByteArray::fromRawData(
                                                     reinterpret_cast<const char*>(newOpcodes.data()),
                                                     static_cast<int>(newOpcodes.size())).toHex();

            // Call the patching callback
            this->m_setPatchingCallback(moduleName, offset, originalOpcodes, newOpcodes);
        }

        QMessageBox infoBox;
        infoBox.setIcon(QMessageBox::Information);
        infoBox.setWindowTitle("Success");
        infoBox.setText("Your patches was imported with success!");
        infoBox.exec();

        this->~ImportPatchs();

        this->close();

    } catch (const json::exception& e) { qDebug() << "Invalid JSON patch file format"; }

}

ImportPatchs::~ImportPatchs() {

    delete ui;

}
