QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

SOURCES += \
    attachprocesswindow.cpp \
    debuggerengine.cpp \
    disassemblerengine.cpp \
    main.cpp \
    maindebuggerwindow.cpp

HEADERS += \
    DebuggerEngine.h \
    attachprocesswindow.h \
    disassemblerengine.h \
    maindebuggerwindow.h

LIBS += -lwtsapi32
LIBS += -lAdvapi32

#_________________________________________________________________________________________________________
#|           Capstone                                                                                     |
#_________________________________________________________________________________________________________
INCLUDEPATH += $$PWD/capstone/include
# For build to ARM64 target change x64 to ARM64 and change capstone lcapstone_dll_x64 to capstone_dll_AA64
LIBS += -L$$PWD/capstone/lib/x64 -lcapstone_dll_x64
#Remember to put the capstone.dll on the directory of debug or release binary. because it is a dependence.
# ________________________________________________________________________________________________________
#|                                                                                                        |
# ________________________________________________________________________________________________________

QMAKE_LFLAGS_WINDOWS = /NODEFAULTLIB:LIBCMT

FORMS += \
    attachprocesswindow.ui \
    maindebuggerwindow.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
