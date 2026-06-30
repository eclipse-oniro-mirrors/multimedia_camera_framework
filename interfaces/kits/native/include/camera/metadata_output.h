/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
 * @since 11
 * @version 1.0
 */

/**
 * @file metadata_output.h
 *
 * @brief Declare the metadata output concepts.
 *
 * @library libohcamera.so
 * @kit CameraKit
 * @syscap SystemCapability.Multimedia.Camera.Core
 * @since 11
 * @version 1.0
 */

#ifndef NATIVE_INCLUDE_CAMERA_METADATAOUTPUT_H
#define NATIVE_INCLUDE_CAMERA_METADATAOUTPUT_H

#include <stdint.h>
#include <stdio.h>
#include "camera.h"
#include "metadata_object_ext.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Metadata output object
 *
 * A pointer can be created using {@link Camera_MetadataOutput} method.
 *
 * @since 11
 * @version 1.0
 */
typedef struct Camera_MetadataOutput Camera_MetadataOutput;

/**
 * @brief Metadata output metadata object available callback to be called in {@link MetadataOutput_Callbacks}.
 *
 * @param metadataOutput the {@link Camera_MetadataOutput} which deliver the callback.
 * @param metadataObject the {@link Camera_MetadataObject} will be delivered by the callback.
 * @param size the size of the metadataObject.
 * @since 11
 */
typedef void (*OH_MetadataOutput_OnMetadataObjectAvailable)(Camera_MetadataOutput* metadataOutput,
    Camera_MetadataObject* metadataObject, uint32_t size);

/**
 * @brief Metadata output error callback to be called in {@link MetadataOutput_Callbacks}.
 *
 * @param metadataOutput the {@link Camera_MetadataOutput} which deliver the callback.
 * @param errorCode the {@link Camera_ErrorCode} of the metadata output.
 *
 * @see CAMERA_SERVICE_FATAL_ERROR
 * @since 11
 */
typedef void (*OH_MetadataOutput_OnError)(Camera_MetadataOutput* metadataOutput, Camera_ErrorCode errorCode);

/**
 * @brief A listener for metadata output.
 *
 * @see OH_MetadataOutput_RegisterCallback
 * @since 11
 * @version 1.0
 */
typedef struct MetadataOutput_Callbacks {
    /**
     * Metadata output result data will be called by this callback.
     */
    OH_MetadataOutput_OnMetadataObjectAvailable onMetadataObjectAvailable;

    /**
     * Metadata output error event.
     */
    OH_MetadataOutput_OnError onError;
} MetadataOutput_Callbacks;

/**
 * @brief Register metadata output change event callback.
 *
 * @param metadataOutput the {@link Camera_MetadataOutput} instance.
 * @param callback the {@link MetadataOutput_Callbacks} to be registered.
 * @return {@link #CAMERA_OK} if the method call succeeds.
 *         {@link #INVALID_ARGUMENT} if parameter missing or parameter type incorrect.
 * @since 11
 */
Camera_ErrorCode OH_MetadataOutput_RegisterCallback(Camera_MetadataOutput* metadataOutput,
    MetadataOutput_Callbacks* callback);

/**
 * @brief Unregister metadata output change event callback.
 *
 * @param metadataOutput the {@link Camera_MetadataOutput} instance.
 * @param callback the {@link MetadataOutput_Callbacks} to be unregistered.
 * @return {@link #CAMERA_OK} if the method call succeeds.
 *         {@link #INVALID_ARGUMENT} if parameter missing or parameter type incorrect.
 * @since 11
 */
Camera_ErrorCode OH_MetadataOutput_UnregisterCallback(Camera_MetadataOutput* metadataOutput,
    MetadataOutput_Callbacks* callback);

/**
 * @brief Start metadata output.
 *
 * @param metadataOutput the {@link Camera_MetadataOutput} instance to be started.
 * @return {@link #CAMERA_OK} if the method call succeeds.
 *         {@link #INVALID_ARGUMENT} if parameter missing or parameter type incorrect.
 *         {@link #CAMERA_SESSION_NOT_CONFIG} if the capture session not config.
 *         {@link #CAMERA_SERVICE_FATAL_ERROR} if camera service fatal error.
 * @since 11
 */
Camera_ErrorCode OH_MetadataOutput_Start(Camera_MetadataOutput* metadataOutput);

/**
 * @brief Stop metadata output.
 *
 * @param metadataOutput the {@link Camera_MetadataOutput} instance to be stoped.
 * @return {@link #CAMERA_OK} if the method call succeeds.
 *         {@link #INVALID_ARGUMENT} if parameter missing or parameter type incorrect.
 *         {@link #CAMERA_SERVICE_FATAL_ERROR} if camera service fatal error.
 * @since 11
 */
Camera_ErrorCode OH_MetadataOutput_Stop(Camera_MetadataOutput* metadataOutput);

/**
 * @brief Release metadata output.
 *
 * @param metadataOutput the {@link Camera_MetadataOutput} instance to be released.
 * @return {@link #CAMERA_OK} if the method call succeeds.
 *         {@link #INVALID_ARGUMENT} if parameter missing or parameter type incorrect.
 *         {@link #CAMERA_SERVICE_FATAL_ERROR} if camera service fatal error.
 * @since 11
 */
Camera_ErrorCode OH_MetadataOutput_Release(Camera_MetadataOutput* metadataOutput);

/**
 * @brief metadata output add metadataobject types.
 *
 * @param metadataOutput the {@link Camera_MetadataOutput} instance
 * @param types the {@link Camera_MetadataObjectType} types
 * @param size the count of the types.
 * @return {@link #CAMERA_OK} if the method call succeeds.
 *         {@link #INVALID_ARGUMENT} if parameter missing or parameter type incorrect.
 *         {@link #CAMERA_SERVICE_FATAL_ERROR} if camera service fatal error.
 * @since 23
 */
Camera_ErrorCode OH_MetadataOutput_AddMetadataObjectTypes(Camera_MetadataOutput* metadataOutput,
    Camera_MetadataObjectType* types, uint32_t size);
 
/**
 * @brief metadata output remove metadataobject types.
 *
 * @param metadataOutput the {@link Camera_MetadataOutput} instance.
 * @param types the {@link Camera_MetadataObjectType} types
 * @param size the count of the types.
 * @return {@link #CAMERA_OK} if the method call succeeds.
 *         {@link #INVALID_ARGUMENT} if parameter missing or parameter type incorrect.
 *         {@link #CAMERA_SERVICE_FATAL_ERROR} if camera service fatal error.
 * @since 23
 */
Camera_ErrorCode OH_MetadataOutput_RemoveMetadataObjectTypes(Camera_MetadataOutput* metadataOutput,
    Camera_MetadataObjectType* types, uint32_t size);
 
/**
 * @brief Defines the callback used to listen for metadata object ext available.
 *
 * @param context Pointer to the context provided by user.
 * @param metadataObjectExt Pointer to the metadata output data.
 * @param size Size of the metadata object ext.
 * @since 26.0.0
 */
typedef void (*OH_MetadataOutput_OnMetadataObjectExtAvailable)(void* context,
    OH_Camera_MetadataObjectExt** metadataObjectExt, uint32_t size);

/**
 * @brief Defines the callback used to listen for error ext event.
 *
 * @param context Pointer to the context provided by user.
 * @param errorCode Error code reported during metadata output.
 * @see CAMERA_SERVICE_FATAL_ERROR
 * @since 26.0.0
 */
typedef void (*OH_MetadataOutput_OnErrorExt)(void* context, Camera_ErrorCode errorCode);

/**
 * @brief Registers a callback to listen for {@link OH_Camera_MetadataObjectExt} events.
 * The callback can be unregistered by {@link OH_MetadataOutput_UnregisterMetadataObjectExtAvailableCallback}.
 *
 * @param metadataOutput Pointer to the {@link Camera_MetadataOutput} instance.
 * @param context Pointer to the context provided by user.
 * @param callback Pointer to the {@link OH_MetadataOutput_OnMetadataObjectExtAvailable} callback function.
 * @return **CAMERA_OK**: The operation is successful.
 *     <br>**CAMERA_INVALID_ARGUMENT**: A parameter is missing or the parameter type is incorrect.
 * @since 26.0.0
 */
Camera_ErrorCode OH_MetadataOutput_RegisterMetadataObjectExtAvailableCallback(Camera_MetadataOutput* metadataOutput,
    void* context, OH_MetadataOutput_OnMetadataObjectExtAvailable callback);

/**
 * @brief Unregisters the callback used to listen for metadata object ext events.
 *
 * @param metadataOutput Pointer to a MetadataOutput instance.
 * @param context Pointer to the context provided by user.
 * @param callback Pointer to the target callback.
 * @return **CAMERA_OK**: The operation is successful.
 *     <br>**CAMERA_INVALID_ARGUMENT**: A parameter is missing or the parameter type is incorrect.
 * @since 26.0.0
 */
Camera_ErrorCode OH_MetadataOutput_UnregisterMetadataObjectExtAvailableCallback(Camera_MetadataOutput* metadataOutput,
    void* context, OH_MetadataOutput_OnMetadataObjectExtAvailable callback);
    
/**
 * @brief Registers a callback to listen for error ext events.
 * The callback can be unregistered by {@link OH_MetadataOutput_UnregisterErrorExtCallback}.
 *
 * @param metadataOutput Pointer to the {@link Camera_MetadataOutput} instance.
 * @param context Pointer to the context provided by user.
 * @param callback Pointer to the {@link OH_MetadataOutput_OnErrorExt} callback function.
 * @return **CAMERA_OK**: The operation is successful.
 *     <br>**CAMERA_INVALID_ARGUMENT**: A parameter is missing or the parameter type is incorrect.
 * @since 26.0.0
 */
Camera_ErrorCode OH_MetadataOutput_RegisterErrorExtCallback(Camera_MetadataOutput* metadataOutput, void* context,
    OH_MetadataOutput_OnErrorExt callback);

/**
 * @brief Unregisters the callback used to listen for error ext events.
 *
 * @param metadataOutput Pointer to a MetadataOutput instance.
 * @param context Pointer to the context provided by user.
 * @param callback Pointer to the target callback.
 * @return **CAMERA_OK**: The operation is successful.
 *     <br>**CAMERA_INVALID_ARGUMENT**: A parameter is missing or the parameter type is incorrect.
 * @since 26.0.0
 */
Camera_ErrorCode OH_MetadataOutput_UnregisterErrorExtCallback(Camera_MetadataOutput* metadataOutput, void* context,
    OH_MetadataOutput_OnErrorExt callback);

/**
 * @brief Checks whether the lock metadata object tracking is supported.
 *
 * @param metadataOutput Pointer to a MetadataOutput instance.
 * @return **true** if supported, **false** otherwise.
 * @since 26.0.0
 */
bool OH_MetadataOutput_IsLockMetadataObjectTrackingSupported(const Camera_MetadataOutput* metadataOutput);

/**
 * @brief Lock metadata object tracking, can be unlocked by {@link OH_MetadataOutput_UnlockMetadataObjectTracking}.
 *
 * @param metadataOutput Pointer to a MetadataOutput instance.
 * @param pointOfInterest Pointer to the point of interest.
 * @return **CAMERA_OK**: The operation is successful.
 *     <br>**CAMERA_INVALID_ARGUMENT**: A parameter is missing or the parameter type is incorrect.
 *     <br>**CAMERA_SESSION_NOT_CONFIG**: The capture session is not configured.
 *     <br>**CAMERA_SERVICE_FATAL_ERROR**: The camera service is abnormal.
 * @since 26.0.0
 */
Camera_ErrorCode OH_MetadataOutput_LockMetadataObjectTracking(Camera_MetadataOutput* metadataOutput,
    Camera_Point* pointOfInterest);

/**
 * @brief Unlock metadata object tracking.
 *
 * @param metadataOutput Pointer to a MetadataOutput instance.
 * @return **CAMERA_OK**: The operation is successful.
 *     <br>**CAMERA_INVALID_ARGUMENT**: A parameter is missing or the parameter type is incorrect.
 *     <br>**CAMERA_SESSION_NOT_CONFIG**: The capture session is not configured.
 *     <br>**CAMERA_SERVICE_FATAL_ERROR**: The camera service is abnormal.
 * @since 26.0.0
 */
Camera_ErrorCode OH_MetadataOutput_UnlockMetadataObjectTracking(Camera_MetadataOutput* metadataOutput);

#ifdef __cplusplus
}
#endif

#endif // NATIVE_INCLUDE_CAMERA_METADATAOUTPUT_H
/** @} */