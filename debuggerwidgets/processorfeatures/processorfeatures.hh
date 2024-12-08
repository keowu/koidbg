/*
    File: ProcessorFeatures.hh
    Authors: João Vitor(@Keowu)
    Created: 25/11/2024
    Last Update: 06/12/2024

    Copyright (c) 2024. https://github.com/maldeclabs/koidbg. All rights reserved.
*/
#ifndef PROCESSORFEATURES_HH
#define PROCESSORFEATURES_HH

#include <QMainWindow>
#include "debuggerutils/armprocessorinformation.hh"

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
    std::unique_ptr<ArmProcessorInformation> armProcInfo = std::make_unique<ArmProcessorInformation>();

};

#endif // PROCESSORFEATURES_HH
