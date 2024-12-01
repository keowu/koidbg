/*
    File: ProcessorFeatures.hh
    Author: João Vitor(@Keowu)
    Created: 25/11/2024
    Last Update: 25/11/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#ifndef PROCESSORFEATURES_HH
#define PROCESSORFEATURES_HH

#include <QMainWindow>

namespace Ui {
    class ProcessorFeatures;
}

class ProcessorFeatures : public QMainWindow {

    Q_OBJECT

public:
    explicit ProcessorFeatures(QWidget *parent = nullptr);
    ~ProcessorFeatures();

private:
    Ui::ProcessorFeatures *ui;

};

#endif // PROCESSORFEATURES_HH
