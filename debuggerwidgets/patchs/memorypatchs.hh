/*
    File: memorypatchs.hh
    Author: João Vitor(@Keowu)
    Created: 17/11/2024
    Last Update: 17/11/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#ifndef MEMORYPATCHS_HH
#define MEMORYPATCHS_HH

#include <QMainWindow>

namespace Ui {
class MemoryPatchs;
}

class MemoryPatchs : public QMainWindow
{
    Q_OBJECT

public:
    explicit MemoryPatchs(QWidget *parent = nullptr);
    ~MemoryPatchs();

private:
    Ui::MemoryPatchs *ui;
};

#endif // MEMORYPATCHS_HH
