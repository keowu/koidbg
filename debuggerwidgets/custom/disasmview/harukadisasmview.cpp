#include "debuggerwidgets/custom/disasmview/harukadisasmview.h"
#include <QAction>
#include <QDebug>

HarukaDisasmView::HarukaDisasmView(QWidget *parent)
    : QTableView(parent) {

}

auto HarukaDisasmView::configureDisasm(QHexView* qHexVw[3], HANDLE hProcessInternal, BreakPointCallback setBreakPointCallback) -> void {

    for (int i = 0; i < 3; ++i) {

        this->m_qHexVw[i] = qHexVw[i];

    }

    this->m_hProcessInternal = hProcessInternal;

    this->m_setBreakPointCallback = setBreakPointCallback;

}

void HarukaDisasmView::contextMenuEvent(QContextMenuEvent *event) {

    QMenu contextMenu(this);

    QAction *actionSftInterrupt = contextMenu.addAction("Set SFT Interrupt");
    QAction *actionHwInterrupt = contextMenu.addAction("Set HW Interrupt");
    QAction *actionMemoryInspector1 = contextMenu.addAction("Follow in Memory Inspector 1");
    QAction *actionMemoryInspector2 = contextMenu.addAction("Follow in Memory Inspector 2");
    QAction *actionMemoryInspector3 = contextMenu.addAction("Follow in Memory Inspector 3");
    QAction *actionDecompile = contextMenu.addAction("Decompile to Pseudo-C");

    connect(actionSftInterrupt, &QAction::triggered, this, &HarukaDisasmView::onSoftwareInterrupt);
    connect(actionHwInterrupt, &QAction::triggered, this, &HarukaDisasmView::onHardwareInterrupt);
    connect(actionMemoryInspector1, &QAction::triggered, this, &HarukaDisasmView::onMemoryInspector1);
    connect(actionMemoryInspector2, &QAction::triggered, this, &HarukaDisasmView::onMemoryInspector2);
    connect(actionMemoryInspector3, &QAction::triggered, this, &HarukaDisasmView::onMemoryInspector3);
    connect(actionDecompile, &QAction::triggered, this, &HarukaDisasmView::onDecompileToPseudoC);

    contextMenu.exec(event->globalPos());
}

void HarukaDisasmView::onSoftwareInterrupt() {

    QModelIndex index = currentIndex();

    if (index.isValid()) {

        QModelIndex column0Index = index.model()->index(index.row(), 0);

        QString addressString = column0Index.data().toString();

        addressString.remove("0x");

        bool bConverted;
        uintptr_t address = addressString.toULongLong(&bConverted, 16);

        if (bConverted) {

            this->m_setBreakPointCallback(address, FALSE);

        }

    }
}

void HarukaDisasmView::onHardwareInterrupt() {

    QModelIndex index = currentIndex();

    if (index.isValid()) {

        QModelIndex column0Index = index.model()->index(index.row(), 0);

        QString addressString = column0Index.data().toString();

        addressString.remove("0x");

        bool bConverted;
        uintptr_t address = addressString.toULongLong(&bConverted, 16);

        if (bConverted) {

            this->m_setBreakPointCallback(address, TRUE);

        }

    }
}

void HarukaDisasmView::onMemoryInspector1() {
    QModelIndex index = currentIndex();

    if (index.isValid()) {
        int row = index.row();
        QModelIndex column0Index = index.model()->index(row, 0);

        this->updateMemoryInspector(this->m_qHexVw[0], column0Index.data().toString());

    }
}

void HarukaDisasmView::onMemoryInspector2() {

    QModelIndex index = currentIndex();

    if (index.isValid()) {

        int row = index.row();

        QModelIndex column0Index = index.model()->index(row, 0);

        this->updateMemoryInspector(this->m_qHexVw[1], column0Index.data().toString());

    }
}


void HarukaDisasmView::onMemoryInspector3() {

    QModelIndex index = currentIndex();

    if (index.isValid()) {

        int row = index.row();

        QModelIndex column0Index = index.model()->index(row, 0);

        this->updateMemoryInspector(this->m_qHexVw[2], column0Index.data().toString());

    }
}

auto HarukaDisasmView::updateMemoryInspector(QHexView* memoryInspector, QString addressString) -> void {

    addressString.remove("0x");

    bool bConverted;
    uintptr_t address = addressString.toULongLong(&bConverted, 16);

    if (bConverted) {

        PVOID pAddress = reinterpret_cast<PVOID>(address);

        SIZE_T bytesRead;

        MEMORY_BASIC_INFORMATION mb;
        VirtualQueryEx(this->m_hProcessInternal, pAddress, &mb, sizeof(mb));

        auto buffer = new char[mb.RegionSize]{ 0 };

        if (ReadProcessMemory(this->m_hProcessInternal, pAddress, buffer, mb.RegionSize, &bytesRead)) { } else {

            qDebug() << "ReadProcessMemory failed with error:" << GetLastError();

            return;
        }

        QByteArray byteArray(buffer, static_cast<int>(bytesRead));
        memoryInspector->clear();
        memoryInspector->fromMemoryBuffer(byteArray, reinterpret_cast<uintptr_t>(pAddress), 0);

        delete[] buffer;

    } else qDebug() << "Failed to convert address string to numeric value.";

}

void HarukaDisasmView::onDecompileToPseudoC() {

    qDebug() << "HarukaDisasmView::onDecompileToPseudoC";

}
