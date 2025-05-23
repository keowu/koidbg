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
// $hash=7512ccf755017d5b1866b753890b498e8163006d$
//

#ifndef CEF_INCLUDE_CAPI_CEF_IMAGE_CAPI_H_
#define CEF_INCLUDE_CAPI_CEF_IMAGE_CAPI_H_
#pragma once

#include "capi/cef_base_capi.h"
#include "capi/cef_values_capi.h"

#ifdef __cplusplus
extern "C" {
#endif

///
/// Container for a single image represented at different scale factors. All
/// image representations should be the same size in density independent pixel
/// (DIP) units. For example, if the image at scale factor 1.0 is 100x100 pixels
/// then the image at scale factor 2.0 should be 200x200 pixels -- both images
/// will display with a DIP size of 100x100 units. The functions of this
/// structure can be called on any browser process thread.
///
typedef struct _cef_image_t {
  ///
  /// Base structure.
  ///
  cef_base_ref_counted_t base;

  ///
  /// Returns true (1) if this Image is NULL.
  ///
  int(CEF_CALLBACK* is_empty)(struct _cef_image_t* self);

  ///
  /// Returns true (1) if this Image and |that| Image share the same underlying
  /// storage. Will also return true (1) if both images are NULL.
  ///
  int(CEF_CALLBACK* is_same)(struct _cef_image_t* self,
                             struct _cef_image_t* that);

  ///
  /// Add a bitmap image representation for |scale_factor|. Only 32-bit
  /// RGBA/BGRA formats are supported. |pixel_width| and |pixel_height| are the
  /// bitmap representation size in pixel coordinates. |pixel_data| is the array
  /// of pixel data and should be |pixel_width| x |pixel_height| x 4 bytes in
  /// size. |color_type| and |alpha_type| values specify the pixel format.
  ///
  int(CEF_CALLBACK* add_bitmap)(struct _cef_image_t* self,
                                float scale_factor,
                                int pixel_width,
                                int pixel_height,
                                cef_color_type_t color_type,
                                cef_alpha_type_t alpha_type,
                                const void* pixel_data,
                                size_t pixel_data_size);

  ///
  /// Add a PNG image representation for |scale_factor|. |png_data| is the image
  /// data of size |png_data_size|. Any alpha transparency in the PNG data will
  /// be maintained.
  ///
  int(CEF_CALLBACK* add_png)(struct _cef_image_t* self,
                             float scale_factor,
                             const void* png_data,
                             size_t png_data_size);

  ///
  /// Create a JPEG image representation for |scale_factor|. |jpeg_data| is the
  /// image data of size |jpeg_data_size|. The JPEG format does not support
  /// transparency so the alpha byte will be set to 0xFF for all pixels.
  ///
  int(CEF_CALLBACK* add_jpeg)(struct _cef_image_t* self,
                              float scale_factor,
                              const void* jpeg_data,
                              size_t jpeg_data_size);

  ///
  /// Returns the image width in density independent pixel (DIP) units.
  ///
  size_t(CEF_CALLBACK* get_width)(struct _cef_image_t* self);

  ///
  /// Returns the image height in density independent pixel (DIP) units.
  ///
  size_t(CEF_CALLBACK* get_height)(struct _cef_image_t* self);

  ///
  /// Returns true (1) if this image contains a representation for
  /// |scale_factor|.
  ///
  int(CEF_CALLBACK* has_representation)(struct _cef_image_t* self,
                                        float scale_factor);

  ///
  /// Removes the representation for |scale_factor|. Returns true (1) on
  /// success.
  ///
  int(CEF_CALLBACK* remove_representation)(struct _cef_image_t* self,
                                           float scale_factor);

  ///
  /// Returns information for the representation that most closely matches
  /// |scale_factor|. |actual_scale_factor| is the actual scale factor for the
  /// representation. |pixel_width| and |pixel_height| are the representation
  /// size in pixel coordinates. Returns true (1) on success.
  ///
  int(CEF_CALLBACK* get_representation_info)(struct _cef_image_t* self,
                                             float scale_factor,
                                             float* actual_scale_factor,
                                             int* pixel_width,
                                             int* pixel_height);

  ///
  /// Returns the bitmap representation that most closely matches
  /// |scale_factor|. Only 32-bit RGBA/BGRA formats are supported. |color_type|
  /// and |alpha_type| values specify the desired output pixel format.
  /// |pixel_width| and |pixel_height| are the output representation size in
  /// pixel coordinates. Returns a cef_binary_value_t containing the pixel data
  /// on success or NULL on failure.
  ///
  struct _cef_binary_value_t*(CEF_CALLBACK* get_as_bitmap)(
      struct _cef_image_t* self,
      float scale_factor,
      cef_color_type_t color_type,
      cef_alpha_type_t alpha_type,
      int* pixel_width,
      int* pixel_height);

  ///
  /// Returns the PNG representation that most closely matches |scale_factor|.
  /// If |with_transparency| is true (1) any alpha transparency in the image
  /// will be represented in the resulting PNG data. |pixel_width| and
  /// |pixel_height| are the output representation size in pixel coordinates.
  /// Returns a cef_binary_value_t containing the PNG image data on success or
  /// NULL on failure.
  ///
  struct _cef_binary_value_t*(CEF_CALLBACK* get_as_png)(
      struct _cef_image_t* self,
      float scale_factor,
      int with_transparency,
      int* pixel_width,
      int* pixel_height);

  ///
  /// Returns the JPEG representation that most closely matches |scale_factor|.
  /// |quality| determines the compression level with 0 == lowest and 100 ==
  /// highest. The JPEG format does not support alpha transparency and the alpha
  /// channel, if any, will be discarded. |pixel_width| and |pixel_height| are
  /// the output representation size in pixel coordinates. Returns a
  /// cef_binary_value_t containing the JPEG image data on success or NULL on
  /// failure.
  ///
  struct _cef_binary_value_t*(CEF_CALLBACK* get_as_jpeg)(
      struct _cef_image_t* self,
      float scale_factor,
      int quality,
      int* pixel_width,
      int* pixel_height);
} cef_image_t;

///
/// Create a new cef_image_t. It will initially be NULL. Use the Add*()
/// functions to add representations at different scale factors.
///
CEF_EXPORT cef_image_t* cef_image_create(void);

#ifdef __cplusplus
}
#endif

#endif  // CEF_INCLUDE_CAPI_CEF_IMAGE_CAPI_H_
