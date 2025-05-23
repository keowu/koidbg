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
// $hash=854c9a8831692fabcf6eef2e4a7d7a1089694fd2$
//

#ifndef CEF_INCLUDE_CAPI_TEST_CEF_TEST_SERVER_CAPI_H_
#define CEF_INCLUDE_CAPI_TEST_CEF_TEST_SERVER_CAPI_H_
#pragma once

#if !defined(BUILDING_CEF_SHARED) && !defined(WRAPPING_CEF_SHARED) && \
    !defined(UNIT_TEST)
#error This file can be included for unit tests only
#endif

#include "capi/cef_base_capi.h"
#include "capi/cef_request_capi.h"

#ifdef __cplusplus
extern "C" {
#endif

struct _cef_test_server_connection_t;
struct _cef_test_server_handler_t;

///
/// Structure representing an embedded test server that supports HTTP/HTTPS
/// requests. This is a basic server providing only an essential subset of the
/// HTTP/1.1 protocol. Especially, it assumes that the request syntax is
/// correct. It *does not* support a Chunked Transfer Encoding. Server capacity
/// is limited and is intended to handle only a small number of simultaneous
/// connections (e.g. for communicating between applications on localhost). The
/// functions of this structure are safe to call from any thread in the brower
/// process unless otherwise indicated.
///
typedef struct _cef_test_server_t {
  ///
  /// Base structure.
  ///
  cef_base_ref_counted_t base;

  ///
  /// Stop the server and shut down the dedicated server thread. This function
  /// must be called on the same thread as CreateAndStart. It will block until
  /// the dedicated server thread has shut down.
  ///
  void(CEF_CALLBACK* stop)(struct _cef_test_server_t* self);

  ///
  /// Returns the server origin including the port number (e.g.
  /// "[http|https]://127.0.0.1:<port>".
  ///
  // The resulting string must be freed by calling cef_string_userfree_free().
  cef_string_userfree_t(CEF_CALLBACK* get_origin)(
      struct _cef_test_server_t* self);
} cef_test_server_t;

///
/// Create and start a new test server that binds to |port|. If |port| is 0 an
/// available port number will be selected. If |https_server| is true (1) the
/// server will be HTTPS, otherwise it will be HTTP. When |https_server| is true
/// (1) the |https_cert_type| value is used to configure the certificate type.
/// Returns the newly created server object on success, or nullptr if the server
/// cannot be started.
///
/// A new thread will be created for each CreateAndStart call (the "dedicated
/// server thread"). It is therefore recommended to use a different
/// cef_test_server_handler_t instance for each CreateAndStart call to avoid
/// thread safety issues in the cef_test_server_handler_t implementation.
///
/// On success, this function will block until the dedicated server thread has
/// started. The server will continue running until Stop is called.
///
CEF_EXPORT cef_test_server_t* cef_test_server_create_and_start(
    uint16_t port,
    int https_server,
    cef_test_cert_type_t https_cert_type,
    struct _cef_test_server_handler_t* handler);

///
/// Implement this structure to handle test server requests. A new thread will
/// be created for each cef_test_server_t::CreateAndStart call (the "dedicated
/// server thread"), and the functions of this structure will be called on that
/// thread. See related documentation on cef_test_server_t::CreateAndStart.
///
typedef struct _cef_test_server_handler_t {
  ///
  /// Base structure.
  ///
  cef_base_ref_counted_t base;

  ///
  /// Called when |server| receives a request. To handle the request return true
  /// (1) and use |connection| to send the response either synchronously or
  /// asynchronously. Otherwise, return false (0) if the request is unhandled.
  /// When returning false (0) do not call any |connection| functions.
  ///
  int(CEF_CALLBACK* on_test_server_request)(
      struct _cef_test_server_handler_t* self,
      struct _cef_test_server_t* server,
      struct _cef_request_t* request,
      struct _cef_test_server_connection_t* connection);
} cef_test_server_handler_t;

///
/// Structure representing a test server connection. The functions of this
/// structure are safe to call from any thread in the brower process unless
/// otherwise indicated.
///
typedef struct _cef_test_server_connection_t {
  ///
  /// Base structure.
  ///
  cef_base_ref_counted_t base;

  ///
  /// Send an HTTP 200 "OK" response. |content_type| is the response content
  /// type (e.g. "text/html"). |data| is the response content and |data_size| is
  /// the size of |data| in bytes. The contents of |data| will be copied. The
  /// connection will be closed automatically after the response is sent.
  ///
  void(CEF_CALLBACK* send_http200response)(
      struct _cef_test_server_connection_t* self,
      const cef_string_t* content_type,
      const void* data,
      size_t data_size);

  ///
  /// Send an HTTP 404 "Not Found" response. The connection will be closed
  /// automatically after the response is sent.
  ///
  void(CEF_CALLBACK* send_http404response)(
      struct _cef_test_server_connection_t* self);

  ///
  /// Send an HTTP 500 "Internal Server Error" response. |error_message| is the
  /// associated error message. The connection will be closed automatically
  /// after the response is sent.
  ///
  void(CEF_CALLBACK* send_http500response)(
      struct _cef_test_server_connection_t* self,
      const cef_string_t* error_message);

  ///
  /// Send a custom HTTP response. |response_code| is the HTTP response code
  /// sent in the status line (e.g. 200). |content_type| is the response content
  /// type (e.g. "text/html"). |data| is the response content and |data_size| is
  /// the size of |data| in bytes. The contents of |data| will be copied.
  /// |extra_headers| is an optional map of additional header key/value pairs.
  /// The connection will be closed automatically after the response is sent.
  ///
  void(CEF_CALLBACK* send_http_response)(
      struct _cef_test_server_connection_t* self,
      int response_code,
      const cef_string_t* content_type,
      const void* data,
      size_t data_size,
      cef_string_multimap_t extra_headers);
} cef_test_server_connection_t;

#ifdef __cplusplus
}
#endif

#endif  // CEF_INCLUDE_CAPI_TEST_CEF_TEST_SERVER_CAPI_H_
