/*
    File: importpatchs.hh
    Author: João Vitor(@Keowu)
    Created: 17/11/2024
    Last Update: 24/11/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#ifndef IMPORTPATCHS_HH
#define IMPORTPATCHS_HH

#include <QMainWindow>
#include <QFileDialog>
#include <QMessageBox>
#include <json.hpp>

using json = nlohmann::json;
using SetPatching = std::function<void(std::string, uintptr_t, const std::vector<uint8_t>&, const std::vector<uint8_t>&)>;

namespace Ui {
class ImportPatchs;
}

class ImportPatchs : public QMainWindow
{
    Q_OBJECT

public:
    explicit ImportPatchs(QWidget *parent = nullptr, SetPatching setPatchingCallback = nullptr);
    ~ImportPatchs();

private:
    Ui::ImportPatchs *ui;
    SetPatching m_setPatchingCallback;
    auto OnImportClicked() -> void;
    auto decodeBase64(const std::string& base64) -> std::vector<uint8_t>;

};

#endif // IMPORTPATCHS_HH
