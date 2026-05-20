/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * @addtogroup MetadataObjectExt
 * @{
 *
 * @brief Provide the definition of the C interface for the camera module.
 *
 * @since 26.0.0
 * @version 1.0
 */
/**
 * @file metadata_object_ext.h
 *
 * @brief The file declares the metadata object ext concepts.
 * 
 * @library libohcamera.so
 * @kit CameraKit
 * @syscap SystemCapability.Multimedia.Camera.Core
 * @since 26.0.0
 * @version 1.0
 */

#ifndef NATIVE_INCLUDE_METADATA_OBJECT_EXT_H
#define NATIVE_INCLUDE_METADATA_OBJECT_EXT_H

#include <stdint.h>
#include <stdio.h>
#include "camera.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief The struct describes the camera metadata object ext.
 *
 * @since 26.0.0
 */
typedef struct OH_Camera_MetadataObjectExt OH_Camera_MetadataObjectExt;

/**
 * @brief Obtains metadata object type.
 *
 * @param metadataObjectExt Pointer to a OH_Camera_MetadataObjectExt instance.
 * @param type Pointer to the metadata object type, which is an **Camera_MetadataObjectType** instance.
 * @return **CAMERA_OK**: The operation is successful.
 *     <br>**CAMERA_INVALID_ARGUMENT**: A parameter is missing or the parameter type is incorrect.
 * @since 26.0.0
 */
Camera_ErrorCode OH_MetadataObjectExt_GetMetadataObjectType(const OH_Camera_MetadataObjectExt* metadataObjectExt,
    Camera_MetadataObjectType* type);

/**
 * @brief Obtains the timestamp of the metadata object extension.
 *
 * @param metadataObjectExt Pointer to a OH_Camera_MetadataObjectExt instance.
 * @param timestamp Pointer to store the timestamp.
 * @return **CAMERA_OK**: The operation is successful.
 *     <br>**CAMERA_INVALID_ARGUMENT**: A parameter is missing or the parameter type is incorrect.
 * @since 26.0.0
 */
Camera_ErrorCode OH_MetadataObjectExt_GetTimestamp(const OH_Camera_MetadataObjectExt* metadataObjectExt,
    int64_t* timestamp);

/**
 * @brief Obtains the bounding box of the metadata object extension.
 *
 * @param metadataObjectExt Pointer to a OH_Camera_MetadataObjectExt instance.
 * @param boundingBox Pointer to the metadata object bounding box, which is an **OH_Camera_Rect_Ext** instance.
 * @return **CAMERA_OK**: The operation is successful.
 *     <br>**CAMERA_INVALID_ARGUMENT**: A parameter is missing or the parameter type is incorrect.
 * @since 26.0.0
 */
Camera_ErrorCode OH_MetadataObjectExt_GetBoundingBox(const OH_Camera_MetadataObjectExt* metadataObjectExt,
    OH_Camera_Rect_Ext* boundingBox);

/**
 * @brief Obtains the pitch angle of the metadata object extension.
 *
 * @param metadataObjectExt Pointer to a OH_Camera_MetadataObjectExt instance.
 * @param pitchAngle Pointer to store the pitch angle.
 * @return **CAMERA_OK**: The operation is successful.
 *     <br>**CAMERA_INVALID_ARGUMENT**: A parameter is missing or the parameter type is incorrect.
 *     <br>**CAMERA_ERROR_OPTIONAL_PROPERTY_NOT_EXIST**: The optional property does not exist.
 * @since 26.0.0
 */
Camera_ErrorCode OH_MetadataObjectExt_GetPitchAngle(const OH_Camera_MetadataObjectExt* metadataObjectExt,
    float* pitchAngle);

/**
 * @brief Obtains the yaw angle of the metadata object extension.
 *
 * @param metadataObjectExt Pointer to a OH_Camera_MetadataObjectExt instance.
 * @param yawAngle Pointer to store the yaw angle.
 * @return **CAMERA_OK**: The operation is successful.
 *     <br>**CAMERA_INVALID_ARGUMENT**: A parameter is missing or the parameter type is incorrect.
 *     <br>**CAMERA_ERROR_OPTIONAL_PROPERTY_NOT_EXIST**: The optional property does not exist.
 * @since 26.0.0
 */
Camera_ErrorCode OH_MetadataObjectExt_GetYawAngle(const OH_Camera_MetadataObjectExt* metadataObjectExt,
    float* yawAngle);

/**
 * @brief Obtains the roll angle of the metadata object extension.
 *
 * @param metadataObjectExt Pointer to a OH_Camera_MetadataObjectExt instance.
 * @param rollAngle Pointer to store the roll angle.
 * @return **CAMERA_OK**: The operation is successful.
 *     <br>**CAMERA_INVALID_ARGUMENT**: A parameter is missing or the parameter type is incorrect.
 *     <br>**CAMERA_ERROR_OPTIONAL_PROPERTY_NOT_EXIST**: The optional property does not exist.
 * @since 26.0.0
 */
Camera_ErrorCode OH_MetadataObjectExt_GetRollAngle(const OH_Camera_MetadataObjectExt* metadataObjectExt,
    float* rollAngle);

/**
 * @brief Obtains the left eye bounding box of the metadata object extension.
 *
 * @param metadataObjectExt Pointer to a OH_Camera_MetadataObjectExt instance.
 * @param boundingBox Pointer to the metadata object bounding box, which is an **OH_Camera_Rect_Ext** instance.
 * @return **CAMERA_OK**: The operation is successful.
 *     <br>**CAMERA_INVALID_ARGUMENT**: A parameter is missing or the parameter type is incorrect.
 *     <br>**CAMERA_ERROR_OPTIONAL_PROPERTY_NOT_EXIST**: The optional property does not exist.
 * @since 26.0.0
 */
Camera_ErrorCode OH_MetadataObjectExt_GetLeftEyeBoundingBox(const OH_Camera_MetadataObjectExt* metadataObjectExt,
    OH_Camera_Rect_Ext* boundingBox);

/**
 * @brief Obtains the right eye bounding box of the metadata object extension.
 *
 * @param metadataObjectExt Pointer to a OH_Camera_MetadataObjectExt instance.
 * @param boundingBox Pointer to the metadata object bounding box, which is an **OH_Camera_Rect_Ext** instance.
 * @return **CAMERA_OK**: The operation is successful.
 *     <br>**CAMERA_INVALID_ARGUMENT**: A parameter is missing or the parameter type is incorrect.
 *     <br>**CAMERA_ERROR_OPTIONAL_PROPERTY_NOT_EXIST**: The optional property does not exist.
 * @since 26.0.0
 */
Camera_ErrorCode OH_MetadataObjectExt_GetRightEyeBoundingBox(const OH_Camera_MetadataObjectExt* metadataObjectExt,
    OH_Camera_Rect_Ext* boundingBox);

/**
 * @brief Obtains the emotion of the metadata object extension.
 *
 * @param metadataObjectExt Pointer to a OH_Camera_MetadataObjectExt instance.
 * @param emotion Pointer to store the emotion type.
 * @return **CAMERA_OK**: The operation is successful.
 *     <br>**CAMERA_INVALID_ARGUMENT**: A parameter is missing or the parameter type is incorrect.
 *     <br>**CAMERA_ERROR_OPTIONAL_PROPERTY_NOT_EXIST**: The optional property does not exist.
 * @since 26.0.0
 */
Camera_ErrorCode OH_MetadataObjectExt_GetEmotion(const OH_Camera_MetadataObjectExt* metadataObjectExt,
    OH_Camera_MetadataObjectEmotion* emotion);

/**
 * @brief Destroys an array of {@link OH_Camera_MetadataObjectExt} instances.
 *
 * @param metadataObjectExt Pointer to the array of {@link OH_Camera_MetadataObjectExt} instances.
 * @param objectCount Indicates the number of metadata objects to be destroyed.
 * @since 26.0.0
 */
void OH_MetadataObjectExt_Destroy(OH_Camera_MetadataObjectExt** metadataObjectExt, uint32_t objectCount);

#ifdef __cplusplus
}
#endif

#endif // NATIVE_INCLUDE_METADATA_OBJECT_EXT_H
/** @} */