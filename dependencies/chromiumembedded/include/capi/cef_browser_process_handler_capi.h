// Copyright (c) 2024 Marshall A. Greenblatt. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google Inc. nor the name Chromium Embedded
// Framework nor the names of its contributors may be used to endorse
// or promote products derived from this software without specific prior
// written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// ---------------------------------------------------------------------------
//
// This file was generated by the CEF translator tool and should not edited
// by hand. See the translator.README.txt file in the tools directory for
// more information.
//
// $hash=56ad161a75ca5083812e11959053abbcafbb9a5d$
//

#ifndef CEF_INCLUDE_CAPI_CEF_BROWSER_PROCESS_HANDLER_CAPI_H_
#define CEF_INCLUDE_CAPI_CEF_BROWSER_PROCESS_HANDLER_CAPI_H_
#pragma once

#include "capi/cef_base_capi.h"
#include "capi/cef_client_capi.h"
#include "capi/cef_command_line_capi.h"
#include "capi/cef_preference_capi.h"
#include "capi/cef_request_context_handler_capi.h"
#include "capi/cef_values_capi.h"

#ifdef __cplusplus
extern "C" {
#endif

///
/// Structure used to implement browser process callbacks. The functions of this
/// structure will be called on the browser process main thread unless otherwise
/// indicated.
///
typedef struct _cef_browser_process_handler_t {
  ///
  /// Base structure.
  ///
  cef_base_ref_counted_t base;

  ///
  /// Provides an opportunity to register custom preferences prior to global and
  /// request context initialization.
  ///
  /// If |type| is CEF_PREFERENCES_TYPE_GLOBAL the registered preferences can be
  /// accessed via cef_preference_manager_t::GetGlobalPreferences after
  /// OnContextInitialized is called. Global preferences are registered a single
  /// time at application startup. See related cef_settings_t.cache_path
  /// configuration.
  ///
  /// If |type| is CEF_PREFERENCES_TYPE_REQUEST_CONTEXT the preferences can be
  /// accessed via the cef_request_context_t after
  /// cef_request_context_handler_t::OnRequestContextInitialized is called.
  /// Request context preferences are registered each time a new
  /// cef_request_context_t is created. It is intended but not required that all
  /// request contexts have the same registered preferences. See related
  /// cef_request_context_settings_t.cache_path configuration.
  ///
  /// Do not keep a reference to the |registrar| object. This function is called
  /// on the browser process UI thread.
  ///
  void(CEF_CALLBACK* on_register_custom_preferences)(
      struct _cef_browser_process_handler_t* self,
      cef_preferences_type_t type,
      struct _cef_preference_registrar_t* registrar);

  ///
  /// Called on the browser process UI thread immediately after the CEF context
  /// has been initialized.
  ///
  void(CEF_CALLBACK* on_context_initialized)(
      struct _cef_browser_process_handler_t* self);

  ///
  /// Called before a child process is launched. Will be called on the browser
  /// process UI thread when launching a render process and on the browser
  /// process IO thread when launching a GPU process. Provides an opportunity to
  /// modify the child process command line. Do not keep a reference to
  /// |command_line| outside of this function.
  ///
  void(CEF_CALLBACK* on_before_child_process_launch)(
      struct _cef_browser_process_handler_t* self,
      struct _cef_command_line_t* command_line);

  ///
  /// Implement this function to provide app-specific behavior when an already
  /// running app is relaunched with the same CefSettings.root_cache_path value.
  /// For example, activate an existing app window or create a new app window.
  /// |command_line| will be read-only. Do not keep a reference to
  /// |command_line| outside of this function. Return true (1) if the relaunch
  /// is handled or false (0) for default relaunch behavior. Default behavior
  /// will create a new default styled Chrome window.
  ///
  /// To avoid cache corruption only a single app instance is allowed to run for
  /// a given CefSettings.root_cache_path value. On relaunch the app checks a
  /// process singleton lock and then forwards the new launch arguments to the
  /// already running app process before exiting early. Client apps should
  /// therefore check the cef_initialize() return value for early exit before
  /// proceeding.
  ///
  /// This function will be called on the browser process UI thread.
  ///
  int(CEF_CALLBACK* on_already_running_app_relaunch)(
      struct _cef_browser_process_handler_t* self,
      struct _cef_command_line_t* command_line,
      const cef_string_t* current_directory);

  ///
  /// Called from any thread when work has been scheduled for the browser
  /// process main (UI) thread. This callback is used in combination with
  /// cef_settings_t.external_message_pump and cef_do_message_loop_work() in
  /// cases where the CEF message loop must be integrated into an existing
  /// application message loop (see additional comments and warnings on
  /// CefDoMessageLoopWork). This callback should schedule a
  /// cef_do_message_loop_work() call to happen on the main (UI) thread.
  /// |delay_ms| is the requested delay in milliseconds. If |delay_ms| is <= 0
  /// then the call should happen reasonably soon. If |delay_ms| is > 0 then the
  /// call should be scheduled to happen after the specified delay and any
  /// currently pending scheduled call should be cancelled.
  ///
  void(CEF_CALLBACK* on_schedule_message_pump_work)(
      struct _cef_browser_process_handler_t* self,
      int64_t delay_ms);

  ///
  /// Return the default client for use with a newly created browser window
  /// (cef_browser_t object). If null is returned the cef_browser_t will be
  /// unmanaged (no callbacks will be executed for that cef_browser_t) and
  /// application shutdown will be blocked until the browser window is closed
  /// manually. This function is currently only used with Chrome style when
  /// creating new browser windows via Chrome UI.
  ///
  struct _cef_client_t*(CEF_CALLBACK* get_default_client)(
      struct _cef_browser_process_handler_t* self);

  ///
  /// Return the default handler for use with a new user or incognito profile
  /// (cef_request_context_t object). If null is returned the
  /// cef_request_context_t will be unmanaged (no callbacks will be executed for
  /// that cef_request_context_t). This function is currently only used with
  /// Chrome style when creating new browser windows via Chrome UI.
  ///
  struct _cef_request_context_handler_t*(
      CEF_CALLBACK* get_default_request_context_handler)(
      struct _cef_browser_process_handler_t* self);
} cef_browser_process_handler_t;

#ifdef __cplusplus
}
#endif

#endif  // CEF_INCLUDE_CAPI_CEF_BROWSER_PROCESS_HANDLER_CAPI_H_
