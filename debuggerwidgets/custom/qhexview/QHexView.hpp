/*
    File: QHexView.hpp
    Author: João Vitor(@Keowu) - 2024, @VitorMob - 2022, @virinext - 2015
    Created: 30/08/2024
    Last Update: 01/09/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#pragma once

#include <QAbstractScrollArea>
#include <QByteArray>
#include <QFile>

// config colors
#if _WIN32 || _WIN64
// config font
#define FONT "Segoe"
#define SIZE_FONT 9
#define COLOR_CHARACTERS Qt::black
#define COLOR_SELECTION 98, 114, 164, 0xff
#define COLOR_ADDRESS 240, 240, 240, 0xff
#else
// config font
#define FONT "Segoe"
#define SIZE_FONT 9
#define COLOR_SELECTION 98, 114, 164, 0xff
#define COLOR_ADDRESS 30, 30, 30, 0xff
#define COLOR_CHARACTERS Qt::white
#endif

// config lines
#define MIN_HEXCHARS_IN_LINE 47
#define GAP_ADR_HEX 10
#define GAP_HEX_ASCII 16
#define MIN_BYTES_PER_LINE 16
#define ADR_LENGTH 10

class QHexView : public QAbstractScrollArea

{
  Q_OBJECT
public:
  QHexView(QWidget *parent = nullptr);
  ~QHexView();

protected:
  void paintEvent(QPaintEvent *event);
  void keyPressEvent(QKeyEvent *event);
  void mouseMoveEvent(QMouseEvent *event);
  void mousePressEvent(QMouseEvent *event);

private:

  QByteArray m_pdata;

  unsigned int m_posAddr = 0,
      m_posHex = 0,
      m_posAscii = 0,
      m_charWidth = 0,
      m_charHeight = 0,
      m_selectBegin = 0,
      m_selectEnd = 0,
      m_selectInit = 0,
      m_cursorPos = 0,
      m_bytesPerLine = 0;

  uintptr_t m_startVirtualAddress = 0;

  QSize fullSize() const;
  void updatePositions();
  void resetSelection();
  void resetSelection(int pos);
  void setSelection(int pos);
  void ensureVisible();
  void setCursorPos(int pos);
  int cursorPos(const QPoint &position);
  int getCursorPos();
  void paintMark(int xpos, int ypos);
  void confScrollBar();
  
public slots:
  void loadFile(QString p_file);
  void fromMemoryBuffer(QByteArray ucMemory, uintptr_t startVirtualAddress, uintptr_t currentVirtualAddress);
  void clear();
  void showFromOffset(int offset);
  void setSelected(int offset, int length);
  void ScrollToByFileOffset(uintptr_t valueY);
  std::size_t sizeFile();
};
