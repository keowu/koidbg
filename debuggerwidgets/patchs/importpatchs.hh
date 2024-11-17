/*
    File: importpatchs.hh
    Author: João Vitor(@Keowu)
    Created: 17/11/2024
    Last Update: 17/11/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#ifndef IMPORTPATCHS_HH
#define IMPORTPATCHS_HH

#include <QMainWindow>

namespace Ui {
class ImportPatchs;
}

class ImportPatchs : public QMainWindow
{
    Q_OBJECT

public:
    explicit ImportPatchs(QWidget *parent = nullptr);
    ~ImportPatchs();

private:
    Ui::ImportPatchs *ui;
};

#endif // IMPORTPATCHS_HH
