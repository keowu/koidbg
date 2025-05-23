# MALDEC LABS - KOIDBG - .pro File
QT += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

#KoiDbg e suas dependencias usam C++ 20
CONFIG += c++20

SOURCES += \
    assemblerengine/assemblerengine.cc \
    debuggerengine/debugbreakpoint.cc \
    debuggerengine/debugcodepatchs.cc \
    debuggerengine/debuggerengine.cc \
    debuggerengine/debughandle.cc \
    debuggerengine/debugmemory.cc \
    debuggerengine/debugmodule.cc \
    debuggerengine/debugthread.cc \
    debuggerutils/utilswindowssyscall.cc \
    debuggerutils/armprocessorinformation.cc \
    debuggerwidgets/attachprocess/attachprocesswindow.cc \
    debuggerwidgets/custom/disasmview/harukadisasmview.cc \
    debuggerwidgets/custom/qhexview/QHexView.cc \
    debuggerwidgets/maindebug/maindebuggerwindow.cc \
    debuggerwidgets/patchs/memorypatchs.cc \
    debuggerwidgets/patchs/exportpatchs.cc \
    debuggerwidgets/patchs/importpatchs.cc \
    debuggerwidgets/patchs/patchcode.cc \
    debuggerwidgets/processorfeatures/processorfeatures.cc \
    debuggerwidgets/kurumiloading/kurumiloading.cc \
    decompiler/decompiler.cc \
    disassemblerengine/disassemblerengine.cc \
    main.cc

HEADERS += \
    TestesKeystoneIntegration.hh \
    assemblerengine/assemblerengine.hh \
    debuggercommands/SafeCommandQueue.hh \
    debuggerengine/DebuggerEngine.hh \
    debuggerengine/debugbreakpoint.hh \
    debuggerengine/debugcodepatchs.hh \
    debuggerengine/debughandle.hh \
    debuggerengine/debugmemory.hh \
    debuggerengine/debugmodule.hh \
    debuggerengine/debugthread.hh \
    debuggerutils/defs.hh \
    debuggerutils/utilswindowssyscall.hh \
    debuggerutils/armprocessorinformation.hh \
    debuggerwidgets/attachprocess/attachprocesswindow.hh \
    debuggerwidgets/custom/disasmview/harukadisasmhtmldelegate.hh \
    debuggerwidgets/custom/disasmview/harukadisasmview.hh \
    debuggerwidgets/custom/qhexview/QHexView.hh \
    debuggerwidgets/maindebug/maindebuggerwindow.hh \
    debuggerwidgets/patchs/memorypatchs.hh \
    debuggerwidgets/patchs/exportpatchs.hh \
    debuggerwidgets/patchs/importpatchs.hh \
    debuggerwidgets/patchs/patchcode.hh \
    debuggerwidgets/processorfeatures/processorfeatures.hh \
    debuggerwidgets/kurumiloading/kurumiloading.hh \
    decompiler/decompiler.hh \
    disassemblerengine/disassemblerengine.hh \
    debuggercommands/lexer.hh \
    disassemblerengine/disassemblerutils.hh \
    testcode/TestesKeystoneIntegration.hh
    #testcode/TestesChromiumEmbeddedIntegration.hh
    #testcode/TestesUnicornIntegration.hh

LIBS += -lwtsapi32
LIBS += -lAdvapi32
LIBS += -lDbgHelp
LIBS += -lUser32

#_________________________________________________________________________________________________________
#|           Capstone                                                                                     |
#_________________________________________________________________________________________________________
INCLUDEPATH += $$PWD/dependencies/capstone/include

# For build to ARM64 target change x64 to ARM64 and change capstone lcapstone_dll_x64 to lcapstone_dll_AA64
win32:CONFIG(release, debug|release) {
    contains(QMAKE_TARGET.arch, arm64) {
        LIBS += -L$$PWD/dependencies/capstone/lib/ARM64 -lcapstone_dll_AA64
    } else {
        LIBS += -L$$PWD/dependencies/capstone/lib/x64 -lcapstone_dll_x64
    }
}
#Remember to put the capstone.dll on the directory of debug or release binary. because it is a dependence.
# ________________________________________________________________________________________________________
#|                                                                                                        |
# ________________________________________________________________________________________________________

#_________________________________________________________________________________________________________
#|           Keystone                                                                                     |
#_________________________________________________________________________________________________________
INCLUDEPATH += $$PWD/dependencies/keystone/include

win32:CONFIG(release, debug|release) {
    contains(QMAKE_TARGET.arch, arm64) {
        LIBS += -L$$PWD/dependencies/keystone/lib/ARM64 -lkeystone
    } else {
        LIBS += -L$$PWD/dependencies/keystone/lib/x64 -lkeystone
    }
}
# For build to ARM64 target change x64 to ARM64
# ________________________________________________________________________________________________________
#|                                                                                                        |
# ________________________________________________________________________________________________________

#_________________________________________________________________________________________________________
#|           KURUMI HELPER                                                                                |
#_________________________________________________________________________________________________________
INCLUDEPATH += $$PWD/kurumiparser/include

win32:CONFIG(release, debug|release) {
    contains(QMAKE_TARGET.arch, arm64) {
        LIBS += -L$$PWD/kurumiparser/ARM64 -lKurumiParser
    } else {
        LIBS += -L$$PWD/kurumiparser/x64 -lKurumiParser
    }
}
# For build to ARM64 target change x64 to ARM64 and change kurumiparser, change the kurumiparser/x64 for x64 or kurumiparser/ARM64 for ARM64
# ________________________________________________________________________________________________________
#|                                                                                                        |
# ________________________________________________________________________________________________________

#_________________________________________________________________________________________________________
#|           CHROMIUM EMBEDDED                                                                            |
#_________________________________________________________________________________________________________
#INCLUDEPATH += $$PWD/dependencies/chromiumembedded/include

#win32:CONFIG(release, debug|release) {
#    contains(QMAKE_TARGET.arch, arm64) {
#        LIBS += -L$$PWD/dependencies/chromiumembedded/lib/ARM64
#        LIBS += -llibcef
#    } else {
#        LIBS += -L$$PWD/dependencies/chromiumembedded/lib/x64
#        LIBS += -llibcef
        #LIBS += -lcef_sandbox
#    }
#    DEFINES += CEF_USE_C_API
#}
# For build to ARM64 target change x64 to ARM64 and change chromiumembedded, change the chromiumembedded/x64 for x64 or chromiumembedded/ARM64 for ARM64
# ________________________________________________________________________________________________________
#|                                                                                                        |
# ________________________________________________________________________________________________________

#_________________________________________________________________________________________________________
#|           NLOHMANN JSON                                                                               |
#_________________________________________________________________________________________________________
INCLUDEPATH += $$PWD/dependencies/nlohmann_json/
# ________________________________________________________________________________________________________
#|                                                                                                        |
# ________________________________________________________________________________________________________

#_________________________________________________________________________________________________________
#|           Unicorn(Only for x64, No support for AARM64)                                                 |
#_________________________________________________________________________________________________________
#INCLUDEPATH += $$PWD/dependencies/unicorn/include
# For build to ARM64 target change x64 to ARM64 and change unicorn lunicorn_x64 to unicorn_AA64
#LIBS += -L$$PWD/dependencies/unicorn/lib/x64 -lunicorn_x64
# ________________________________________________________________________________________________________
#|                                                                                                        |
# ________________________________________________________________________________________________________

QMAKE_LFLAGS_WINDOWS = /NODEFAULTLIB:LIBCMT

#HIDE KOIDBG ConsoleWindows for debug on release mode.
QMAKE_LFLAGS += /SUBSYSTEM:WINDOWS

FORMS += \
    debuggerwidgets/attachprocess/attachprocesswindow.ui \
    debuggerwidgets/maindebug/maindebuggerwindow.ui \
    debuggerwidgets/patchs/memorypatchs.ui \
    debuggerwidgets/patchs/exportpatchs.ui \
    debuggerwidgets/patchs/importpatchs.ui \
    debuggerwidgets/patchs/patchcode.ui \
    debuggerwidgets/processorfeatures/processorfeatures.ui \
    debuggerwidgets/kurumiloading/kurumiloading.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

RESOURCES += \
    KoiDbgResources.qrc


#_________________________________________________________________________________________________________
#|           Koidbg ICON Configuration                                                                    |
#_________________________________________________________________________________________________________
RC_ICONS = "imgs/icone.ico"
# ________________________________________________________________________________________________________
#|                                                                                                        |
# ________________________________________________________________________________________________________

#_________________________________________________________________________________________________________
#|           KoiDbg Release and Debug output binary name                                                  |
#_________________________________________________________________________________________________________
CONFIG(debug, debug|release) {
    TARGET = KoiDbgSigma
}

CONFIG(release, debug|release) {
    TARGET = KoiDbg
}
# ________________________________________________________________________________________________________
#|                                                                                                        |
# ________________________________________________________________________________________________________

#_________________________________________________________________________________________________________
#|           KoiDbg Distfiles to .exe description binary information                                     |
#_________________________________________________________________________________________________________
DISTFILES +=
# ________________________________________________________________________________________________________
#|                                                                                                        |
# ________________________________________________________________________________________________________
