/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef NATIVE_INCLUDE_CAMERA_CAMERA_H
#define NATIVE_INCLUDE_CAMERA_CAMERA_H

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @since 11
 * @version 1.0
 */
typedef struct Camera_Manager Camera_Manager;

/**
 * Enumerates the return values that may be used by the interface.
 */
typedef enum Camera_ErrorCode {
    /**
     * Camera operation success.
     */
    CAMERA_OK = 0,

    /**
     * Parameter missing or parameter type incorrect.
     */
    CAMERA_INVALID_ARGUMENT = 7400101,

    /**
     * Camera operation was not allowed.
     */
    CAMERA_OPERATION_NOT_ALLOWED = 7400102,
    /**
     * Camera session not config.
     */
    CAMERA_SESSION_NOT_CONFIG = 7400103,

    /**
     * Camera session not running.
     */
    CAMERA_SESSION_NOT_RUNNING = 7400104,

    /**
     * Camera session config locked.
     */
    CAMERA_SESSION_CONFIG_LOCKED = 7400105,

    /**
     * Camera device setting locked.
     */
    CAMERA_DEVICE_SETTING_LOCKED = 7400106,

    /**
     * Camera can not use cause of conflict.
     */
    CAMERA_CONFLICT_CAMERA = 7400107,

    /**
     * Camera disabled cause of security reason.
     */
    CAMERA_DEVICE_DISABLED = 7400108,

    /**
     * Camera can not use cause of preempted.
     */
    CAMERA_DEVICE_PREEMPTED = 7400109,

    /**
     * Camera service fatal error.
     */
    CAMERA_SERVICE_FATAL_ERROR = 7400201
} Camera_ErrorCode;

/**
 * Enumerates the return values that may be used by the interface.
 */
typedef enum Camera_Status {
    /**
     * Camera operation success.
     */
    CAMERA_STATUS_APPEAR = 0,

    /**
     * Parameter missing or parameter type incorrect.
     */
    CAMERA_STATUS_DISAPPEAR = 1,

    /**
     * Camera operation was not allowed.
     */
    CAMERA_STATUS_AVAILABLE = 2,

    /**
     * Camera operation was not allowed.
     */
    CAMERA_STATUS_UNAVAILABLE = 3
} Camera_Status;

/**
 * Enumerates the return values that may be used by the interface.
 */
typedef enum Camera_Position {
    /**
     * Camera operation success.
     */
    CAMERA_POSITION_UNSPECIFIED = 0,

    /**
     * Parameter missing or parameter type incorrect.
     */
    CAMERA_POSITION_BACK = 1,

    /**
     * Camera operation was not allowed.
     */
    CAMERA_POSITION_FRONT = 2
} Camera_Position;

/**
 * Enumerates the return values that may be used by the interface.
 */
typedef enum Camera_Type {
    /**
     * Camera operation success.
     */
    CAMERA_TYPE_DEFAULT = 0,

    /**
     * Parameter missing or parameter type incorrect.
     */
    CAMERA_TYPE_WIDE_ANGLE = 1,

    /**
     * Camera operation was not allowed.
     */
    CAMERA_TYPE_ULTRA_WIDE = 2,

    /**
     * Camera operation was not allowed.
     */
    CAMERA_TYPE_TELEPHOTO = 3,

    /**
     * Camera operation was not allowed.
     */
    CAMERA_TYPE_TRUE_DEPTH = 4
} Camera_Type;

/**
 * Enumerates the return values that may be used by the interface.
 */
typedef enum Camera_Connection {
    /**
     * Camera operation success.
     */
    CAMERA_CONNECTION_BUILT_IN = 0,

    /**
     * Parameter missing or parameter type incorrect.
     */
    CAMERA_CONNECTION_USB_PLUGIN = 1,

    /**
     * Camera operation was not allowed.
     */
    CAMERA_CONNECTION_REMOTE = 2
} Camera_Connection;

/**
 * Enumerates the return values that may be used by the interface.
 */
typedef enum Camera_Format {
    /**
     * Camera operation success.
     */
    CAMERA_FORMAT_RGBA_8888 = 3,

    /**
     * Parameter missing or parameter type incorrect.
     */
    CAMERA_FORMAT_YUV_420_SP = 1003,

    /**
     * Camera operation was not allowed.
     */
    CAMERA_FORMAT_JPEG = 2000
} Camera_Format;

/**
 * Enumerates the return values that may be used by the interface.
 */
typedef enum Camera_FlashMode {
    /**
     * Camera operation success.
     */
    FLASH_MODE_CLOSE = 0,

    /**
     * Parameter missing or parameter type incorrect.
     */
    FLASH_MODE_OPEN = 1,

    /**
     * Camera operation was not allowed.
     */
    FLASH_MODE_AUTO = 2,

    /**
     * Camera operation was not allowed.
     */
    FLASH_MODE_ALWAYS_OPEN = 3
} Camera_FlashMode;

/**
 * Enumerates the return values that may be used by the interface.
 */
typedef enum Camera_ExposureMode {
    /**
     * Camera operation success.
     */
    EXPOSURE_MODE_LOCKED = 0,

    /**
     * Parameter missing or parameter type incorrect.
     */
    EXPOSURE_MODE_AUTO = 1,

    /**
     * Camera operation was not allowed.
     */
    EXPOSURE_MODE_CONTINUOUS_AUTO = 2
} Camera_ExposureMode;

/**
 * Enumerates the return values that may be used by the interface.
 */
typedef enum Camera_FocusMode {
    /**
     * Camera operation success.
     */
    FOCUS_MODE_MANUAL = 0,

    /**
     * Parameter missing or parameter type incorrect.
     */
    FOCUS_MODE_CONTINUOUS_AUTO = 1,

    /**
     * Camera operation was not allowed.
     */
    FOCUS_MODE_AUTO = 2,

    /**
     * Camera operation was not allowed.
     */
    FOCUS_MODE_LOCKED = 3
} Camera_FocusMode;

/**
 * Enumerates the return values that may be used by the interface.
 */
typedef enum Camera_FocusState {
    /**
     * Camera operation success.
     */
    FOCUS_STATE_SCAN = 0,

    /**
     * Parameter missing or parameter type incorrect.
     */
    FOCUS_STATE_FOCUSED = 1,

    /**
     * Camera operation was not allowed.
     */
    FOCUS_STATE_UNFOCUSED = 2
} Camera_FocusState;

/**
 * Enumerates the return values that may be used by the interface.
 */
typedef enum Camera_VideoStabilizationMode {
    /**
     * Camera operation success.
     */
    STABILIZATION_MODE_OFF = 0,

    /**
     * Parameter missing or parameter type incorrect.
     */
    STABILIZATION_MODE_LOW = 1,

    /**
     * Camera operation was not allowed.
     */
    STABILIZATION_MODE_MIDDLE = 2,

    /**
     * Camera operation was not allowed.
     */
    STABILIZATION_MODE_HIGH = 3,

    /**
     * Camera operation was not allowed.
     */
    STABILIZATION_MODE_AUTO = 4
} Camera_VideoStabilizationMode;

/**
 * Enumerates the return values that may be used by the interface.
 */
typedef enum Camera_ImageRotation {
    /**
     * Camera operation success.
     */
    IAMGE_ROTATION_0 = 0,

    /**
     * Parameter missing or parameter type incorrect.
     */
    IAMGE_ROTATION_90 = 90,

    /**
     * Camera operation was not allowed.
     */
    IAMGE_ROTATION_180 = 180,

    /**
     * Camera operation was not allowed.
     */
    IAMGE_ROTATION_270 = 270
} Camera_ImageRotation;

/**
 * Enumerates the return values that may be used by the interface.
 */
typedef enum Camera_QualityLevel {
    /**
     * Camera operation success.
     */
    QUALITY_LEVEL_HIGH = 0,

    /**
     * Parameter missing or parameter type incorrect.
     */
    QUALITY_LEVEL_MEDIUM = 1,

    /**
     * Camera operation was not allowed.
     */
    QUALITY_LEVEL_LOW = 2
} Camera_QualityLevel;

/**
 * Enumerates the return values that may be used by the interface.
 */
typedef enum Camera_MetadataObjectType {
    /**
     * Camera operation success.
     */
    FACE_DETECTION = 0
} Camera_MetadataObjectType;

/**
 * Enumerates the return values that may be used by the interface.
 */
typedef struct Camera_Size {
    uint32_t width;
    uint32_t height;
} Camera_Size;

/**
 * Enumerates the return values that may be used by the interface.
 */
typedef struct Camera_Profile {
    Camera_Format format;
    Camera_Size size;
} Camera_Profile;

/**
 * Enumerates the return values that may be used by the interface.
 */
typedef struct Camera_FrameRateRange {
    uint32_t min;
    uint32_t max;
} Camera_FrameRateRange;

/**
 * Enumerates the return values that may be used by the interface.
 */
typedef struct Camera_VideoProfile {
    Camera_Format format;
    Camera_Size size;
    Camera_FrameRateRange range;
} Camera_VideoProfile;

/**
 * Enumerates the return values that may be used by the interface.
 */
typedef struct Camera_OutputCapability {
    Camera_Profile** previewProfiles;
    uint32_t previewProfilesSize;
    Camera_Profile** photoProfiles;
    uint32_t photoProfilesSize;
    Camera_VideoProfile** videoProfiles;
    uint32_t videoProfilesSize;
    Camera_MetadataObjectType** supportedMetadataObjectTypes;
    uint32_t metadataProfilesSize;
} Camera_OutputCapability;

/**
 * Enumerates the return values that may be used by the interface.
 */
typedef struct Camera_Device {
    char* cameraId;
    Camera_Position cameraPosition;
    Camera_Type cameraType;
    Camera_Connection connectionType;
} Camera_Device;

/**
 * Enumerates the return values that may be used by the interface.
 */
typedef struct Camera_StatusInfo {
    Camera_Device* camera;
    Camera_Status status;
} Camera_StatusInfo;

/**
 * Enumerates the return values that may be used by the interface.
 */
typedef struct Camera_Point {
    int32_t x;
    int32_t y;
} Camera_Point;

/**
 * Enumerates the return values that may be used by the interface.
 */
typedef struct Camera_Location {
    int32_t latitude;
    int32_t longitude;
    int32_t altitude;
} Camera_Location;

/**
 * Enumerates the return values that may be used by the interface.
 */
typedef struct Camera_PhotoCaptureSetting {
    Camera_QualityLevel quality;
    Camera_ImageRotation rotation;
    Camera_Location* location;
    bool mirror;
} Camera_PhotoCaptureSetting;

/**
 * Enumerates the return values that may be used by the interface.
 */
typedef struct Camera_FrameShutterInfo {
    int32_t captureId;
    int64_t timestamp;
} Camera_FrameShutterInfo;

/**
 * Enumerates the return values that may be used by the interface.
 */
typedef struct Camera_CaptureEndInfo {
    int32_t captureId;
    int64_t frameCount;
} Camera_CaptureEndInfo;

/**
 * Enumerates the return values that may be used by the interface.
 */
typedef struct Camera_Rect {
    int32_t topLeftX;
    int32_t topLeftY;
    int32_t width;
    int32_t height;
} Camera_Rect;

/**
 * Enumerates the return values that may be used by the interface.
 */
typedef struct Camera_MetadataObject {
    Camera_MetadataObjectType type;
    int64_t timestamp;
    Camera_Rect* boundingBox;
} Camera_MetadataObject;

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_Camera_GetCameraMananger(Camera_Manager** cameraManager);

#ifdef __cplusplus
}
#endif

#endif // NATIVE_INCLUDE_CAMERA_CAMERA_H