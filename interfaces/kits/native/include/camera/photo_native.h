/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @addtogroup OH_Camera
 * @{
 *
 * @brief Provide the definition of the C interface for the camera module.
 *
 * @syscap SystemCapability.Multimedia.Camera.Core
 *
 * @since 12
 * @version 1.0
 */

/**
 * @file photo_native.h
 *
 * @brief Declare the camera photo concepts.
 *
 * @library libohcamera.so
 * @kit CameraKit
 * @syscap SystemCapability.Multimedia.Camera.Core
 * @since 12
 * @version 1.0
 */

#ifndef NATIVE_INCLUDE_PHOTO_NATIVE_H
#define NATIVE_INCLUDE_PHOTO_NATIVE_H

#include <stdint.h>
#include <stdio.h>
#include "camera.h"
#include "image/image_native.h"
#include "image/picture_native.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Camera photo object
 *
 * A pointer can be created using {@link OH_PhotoNative} method.
 *
 * @since 12
 * @version 1.0
 */
typedef struct OH_PhotoNative OH_PhotoNative;

/**
 * @brief Get main image.
 *
 * @param photo the {@link OH_PhotoNative} instance.
 * @param mainImage the {@link OH_ImageNative} which use to get main image.
 * @return {@link #CAMERA_OK} if the method call succeeds.
 *         {@link #INVALID_ARGUMENT} if parameter missing or parameter type incorrect.
 * @since 12
 * @version 1.0
 */
Camera_ErrorCode OH_PhotoNative_GetMainImage(OH_PhotoNative* photo, OH_ImageNative** mainImage);

/**
 * @brief Get uncompressed image.
 *
 * @param photo the {@link OH_PhotoNative} instance.
 * @param mainImage the {@link OH_PictureNative} which use to get picture.
 * @return {@link #CAMERA_OK} if the method call succeeds.
 *         {@link #INVALID_ARGUMENT} if parameter missing or parameter type incorrect.
 * @since 23
 * @version 1.0
 */
Camera_ErrorCode OH_PhotoNative_GetUncompressedImage(OH_PhotoNative* photo, OH_PictureNative** picture);

/**
 * @brief Release camera photo.
 *
 * @param photo the {@link OH_PhotoNative} instance to released.
 * @return {@link #CAMERA_OK} if the method call succeeds.
 *         {@link #INVALID_ARGUMENT} if parameter missing or parameter type incorrect.
 * @since 12
 * @version 1.0
 */
Camera_ErrorCode OH_PhotoNative_Release(OH_PhotoNative* photo);

/**
 * @brief Obtains an auxiliary image.
 *
 * @param photo [in] Pointer to an **OH_PhotoNative** instance.
 * @param type [in] The auxiliary photo type.
 * @param outImage [out] Double pointer to the auxiliary image, which is an **OH_ImageNative** instance. On success,
 *     points to a valid image instance. On failure, may be set to NULL. The caller is responsible for releasing the
 *     allocated memory using the appropriate release function.
 * @return {@link #CAMERA_OK} if the method call succeeds.
 *         {@link #INVALID_ARGUMENT} if parameter missing or parameter type incorrect.
 *         {@link #CAMERA_ERROR_PARAM_OUT_OF_RANGE} if a parameter is out of the range.
 * @since 26.1.0
 */
Camera_ErrorCode OH_PhotoNative_GetAuxiliaryImage(const OH_PhotoNative* photo, OH_Camera_AuxiliaryPhotoType type,
    OH_ImageNative** outImage);

/**
 * @brief Obtains an uncompressed auxiliary image.
 *
 * @param photo [in] Pointer to an **OH_PhotoNative** instance.
 * @param type [in] The auxiliary photo type.
 * @param outImage [out] Double pointer to the uncompressed auxiliary image, which is an **OH_PictureNative** instance.
 *     On success, points to a valid image instance. On failure, may be set to NULL. The caller is responsible for
 *     releasing the allocated memory using the appropriate release function.
 * @return {@link #CAMERA_OK} if the method call succeeds.
 *         {@link #INVALID_ARGUMENT} if parameter missing or parameter type incorrect.
 *         {@link #CAMERA_ERROR_PARAM_OUT_OF_RANGE} if the parameter is out of range.
 * @since 26.1.0
 */
Camera_ErrorCode OH_PhotoNative_GetUncompressedAuxiliaryImage(const OH_PhotoNative* photo,
    OH_Camera_AuxiliaryPhotoType type, OH_PictureNative** outImage);

/**
 * @brief Releases an allocated native picture instance.
 *
 * @param picture [in] Pointer to the **OH_PictureNative** instance to release.
 * @return {@link #CAMERA_OK} if the method call succeeds.
 *         {@link #INVALID_ARGUMENT} if parameter missing or parameter type incorrect.
 * @since 26.1.0
 */
Camera_ErrorCode OH_PhotoNative_ReleasePicture(OH_PictureNative* picture);

/**
 * @brief Releases an allocated native image instance.
 *
 * @param image [in] Pointer to the **OH_ImageNative** instance to release.
 * @return {@link #CAMERA_OK} if the method call succeeds.
 *         {@link #INVALID_ARGUMENT} if parameter missing or parameter type incorrect.
 * @since 26.1.0
 */
Camera_ErrorCode OH_PhotoNative_ReleaseImage(OH_ImageNative* image);

#ifdef __cplusplus
}
#endif

#endif // NATIVE_INCLUDE_PHOTO_NATIVE_H
/** @} */