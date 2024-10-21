QT += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

#HarukaMirai e suas dependencias usam C++ 20
CONFIG += c++20

SOURCES += \
    debuggerengine/debugbreakpoint.cpp \
    debuggerengine/debughandle.cpp \
    debuggerengine/debugmemory.cpp \
    debuggerengine/debugmodule.cpp \
    debuggerengine/debugthread.cpp \
    debuggerwidgets/attachprocess/attachprocesswindow.cpp \
    debuggerengine/debuggerengine.cpp \
    debuggerwidgets/custom/disasmview/harukadisasmview.cpp \
    debuggerwidgets/custom/qhexview/QHexView.cpp \
    disassemblerengine/disassemblerengine.cpp \
    main.cpp \
    debuggerwidgets/maindebug/maindebuggerwindow.cpp \
    debuggerutils/utilswindowssyscall.cpp

HEADERS += \
    debuggercommands/SafeCommandQueue.hh \
    debuggerengine/DebuggerEngine.h \
    debuggerengine/debugbreakpoint.h \
    debuggerengine/debughandle.h \
    debuggerengine/debugmemory.h \
    debuggerengine/debugmodule.h \
    debuggerengine/debugthread.h \
    debuggerwidgets/attachprocess/attachprocesswindow.h \
    debuggerwidgets/custom/disasmview/harukadisasmhtmldelegate.h \
    debuggerwidgets/custom/disasmview/harukadisasmview.h \
    debuggerwidgets/custom/qhexview/QHexView.hpp \
    disassemblerengine/disassemblerengine.h \
    disassemblerengine/disassemblerutils.h \
    debuggerwidgets/maindebug/maindebuggerwindow.h \
    debuggerutils/utilswindowssyscall.h \
    debuggercommands/lexer.hh

LIBS += -lwtsapi32
LIBS += -lAdvapi32
LIBS += -lDbgHelp

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

#_________________________________________________________________________________________________________
#|           KURUMI HELPER                                                                                |
#_________________________________________________________________________________________________________
INCLUDEPATH += $$PWD/kurumiparser/include
# For build to ARM64 target change x64 to ARM64 and change capstone, change the kurumiparser/x64 for x64 or kurumiparser/ARM64 for ARM64
LIBS += -L$$PWD/kurumiparser/x64 -lKurumiParser
# ________________________________________________________________________________________________________
#|                                                                                                        |
# ________________________________________________________________________________________________________

QMAKE_LFLAGS_WINDOWS = /NODEFAULTLIB:LIBCMT

FORMS += \
    debuggerwidgets/attachprocess/attachprocesswindow.ui \
    debuggerwidgets/maindebug/maindebuggerwindow.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

RESOURCES += \
    HarukaMiraiDbgResources.qrc


#_________________________________________________________________________________________________________
#|           Haruka ICON Configuration                                                                    |
#_________________________________________________________________________________________________________
RC_ICONS = "imgs/icone.ico"
# ________________________________________________________________________________________________________
#|                                                                                                        |
# ________________________________________________________________________________________________________

DISTFILES +=
