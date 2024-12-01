/*
    File: TestesChromiumEmbeddedIntegration.hh
    Author: João Vitor(@Keowu)
    Created: 01/12/2024
    Last Update: 01/12/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#ifndef TESTESCHROMIUMEMBEDDEDINTEGRATION_H
#define TESTESCHROMIUMEMBEDDEDINTEGRATION_H
#include "dependencies/chromiumembedded/include/cef_app.h"
#include "dependencies/chromiumembedded/include/cef_browser.h"
#include "dependencies/chromiumembedded/include/cef_client.h"

auto testChromiumEmbedded() -> void {
	
	CefMainArgs mainArgs;
    CefSettings settings;
    CefInitialize(mainArgs, settings, nullptr, nullptr);

    CefWindowInfo windowInfo;
    windowInfo.SetAsChild(reinterpret_cast<HWND>(winId()));
    CefBrowserSettings browserSettings;
    CefBrowserHost::CreateBrowser(windowInfo, new MyCEFClient(), "https://www.google.com", browserSettings, nullptr);
	
}

#endif // TESTESCHROMIUMEMBEDDEDINTEGRATION_H
