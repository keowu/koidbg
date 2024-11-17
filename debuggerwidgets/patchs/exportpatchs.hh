/*
    File: exportpatchs.hh
    Author: João Vitor(@Keowu)
    Created: 17/11/2024
    Last Update: 17/11/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#ifndef EXPORTPATCHS_HH
#define EXPORTPATCHS_HH

#include <QMainWindow>

namespace Ui {
class ExportPatchs;
}

class ExportPatchs : public QMainWindow
{
    Q_OBJECT

public:
    explicit ExportPatchs(QWidget *parent = nullptr);
    ~ExportPatchs();

private:
    Ui::ExportPatchs *ui;
};

#endif // ExportPatchs_HH
