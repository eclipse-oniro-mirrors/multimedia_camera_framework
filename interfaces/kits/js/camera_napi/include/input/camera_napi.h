/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef CAMERA_NAPI_H_
#define CAMERA_NAPI_H_

#include "camera_log.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "hilog/log.h"
#include "camera_napi_utils.h"
#include "output/camera_output_capability.h"
#include "output/metadata_output_napi.h"

#include "input/camera_manager.h"
#include "output/capture_output.h"
#include "session/capture_session.h"
#include "input/capture_input.h"

#include "input/camera_input_napi.h"
#include "input/camera_manager_napi.h"
#include "output/preview_output_napi.h"
#include "output/photo_output_napi.h"
#include "output/video_output_napi.h"
#include "session/camera_session_napi.h"
#include "output/metadata_output_napi.h"

#include <cinttypes>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

namespace OHOS {
namespace CameraStandard {
struct CamRecorderCallback;

static const char CAMERA_LIB_NAPI_CLASS_NAME[] = "camera";
// Photo default size
static const std::int32_t PHOTO_DEFAULT_WIDTH = 1280;
static const std::int32_t PHOTO_DEFAULT_HEIGHT = 960;

// Surface default size
static const std::int32_t SURFACE_DEFAULT_WIDTH = 640;
static const std::int32_t SURFACE_DEFAULT_HEIGHT = 480;

// Preview default size
static const std::int32_t PREVIEW_DEFAULT_WIDTH = 640;
static const std::int32_t PREVIEW_DEFAULT_HEIGHT = 480;

// Video default size
static const std::int32_t VIDEO_DEFAULT_WIDTH = 640;
static const std::int32_t VIDEO_DEFAULT_HEIGHT = 360;

static const std::int32_t SURFACE_QUEUE_SIZE = 10;

static const std::int32_t CAM_FORMAT_RGBA_8888 = 3;
static const std::int32_t CAM_FORMAT_JPEG = 2000;
static const std::int32_t CAM_FORMAT_YUV_420_SP = 1003;

static const std::vector<std::string> vecFlashMode {
    "FLASH_MODE_CLOSE", "FLASH_MODE_OPEN", "FLASH_MODE_AUTO", "FLASH_MODE_ALWAYS_OPEN"
};

static const std::vector<std::string> vecExposureMode {
    "EXPOSURE_MODE_LOCKED", "EXPOSURE_MODE_AUTO", "EXPOSURE_MODE_CONTINUOUS_AUTO"
};

static const std::vector<std::string> vecFocusMode {
    "FOCUS_MODE_MANUAL", "FOCUS_MODE_CONTINUOUS_AUTO", "FOCUS_MODE_AUTO", "FOCUS_MODE_LOCKED"
};

static const std::vector<std::string> vecCameraPositionMode {
    "CAMERA_POSITION_UNSPECIFIED", "CAMERA_POSITION_BACK", "CAMERA_POSITION_FRONT"
};

static const std::vector<std::string> vecCameraTypeMode {
    "CAMERA_TYPE_DEFAULT", "CAMERA_TYPE_WIDE_ANGLE", "CAMERA_TYPE_ULTRA_WIDE",
    "CAMERA_TYPE_TELEPHOTO", "CAMERA_TYPE_TRUE_DEPTH"
};

static const std::vector<std::string> vecConnectionTypeMode {
    "CAMERA_CONNECTION_BUILT_IN", "CAMERA_CONNECTION_USB_PLUGIN", "CAMERA_CONNECTION_REMOTE"
};

static const std::vector<std::string> vecCameraFormat {
    "CAMERA_FORMAT_YUV_420_SP", "CAMERA_FORMAT_JPEG", "CAMERA_FORMAT_RGBA_8888"
};

static const std::vector<std::string> vecCameraStatus {
    "CAMERA_STATUS_APPEAR", "CAMERA_STATUS_DISAPPEAR", "CAMERA_STATUS_AVAILABLE", "CAMERA_STATUS_UNAVAILABLE"
};

static const std::vector<std::string> vecVideoStabilizationMode {
    "OFF", "LOW", "MIDDLE", "HIGH", "AUTO"
};

static const std::unordered_map<std::string, int32_t> mapImageRotation = {
    {"ROTATION_0", 0},
    {"ROTATION_90", 90},
    {"ROTATION_180", 180},
    {"ROTATION_270", 270},
};

static const std::unordered_map<std::string, int32_t> mapQualityLevel = {
    {"QUALITY_LEVEL_HIGH", 0},
    {"QUALITY_LEVEL_MEDIUM", 1},
    {"QUALITY_LEVEL_LOW", 2},
};

static const std::unordered_map<std::string, int32_t> mapFocusState = {
    {"FOCUS_STATE_SCAN", 0},
    {"FOCUS_STATE_FOCUSED", 1},
    {"FOCUS_STATE_UNFOCUSED", 2},
};

static const std::unordered_map<std::string, int32_t> mapExposureState = {
    {"EXPOSURE_STATE_SCAN", 0},
    {"EXPOSURE_STATE_CONVERGED", 1},
};

static const std::unordered_map<std::string, int32_t> mapCameraErrorCode = {
    {"INVALID_ARGUMENT", 7400101},
    {"OPERATION_NOT_ALLOWED", 7400102},
    {"SESSION_NOT_CONFIG", 7400103},
    {"SESSION_NOT_RUNNING", 7400104},
    {"SESSION_CONFIG_LOCKED", 7400105},
    {"DEVICE_SETTING_LOCKED", 7400106},
    {"CONFILICT_CAMERA", 7400107},
    {"DEVICE_DISABLED", 7400108},
    {"SERVICE_FATAL_ERROR", 7400201}
};

static const std::unordered_map<std::string, int32_t> mapCameraInputErrorCode = {
    {"ERROR_UNKNOWN", -1},
    {"ERROR_NO_PERMISSION", 0},
    {"ERROR_DEVICE_PREEMPTED", 1},
    {"ERROR_DEVICE_DISCONNECTED", 2},
    {"ERROR_DEVICE_IN_USE", 3},
    {"ERROR_DRIVER_ERROR", 4}
};

static const std::unordered_map<std::string, int32_t> mapCaptureSessionErrorCode = {
    {"ERROR_UNKNOWN", -1},
    {"ERROR_INSUFFICIENT_RESOURCES", 0},
    {"ERROR_TIMEOUT", 1}
};

static const std::unordered_map<std::string, int32_t> mapPreviewOutputErrorCode = {
    {"ERROR_UNKNOWN", -1}
};

static const std::unordered_map<std::string, int32_t> mapPhotoOutputErrorCode = {
    {"ERROR_UNKNOWN", -1},
    {"ERROR_DRIVER_ERROR", 0},
    {"ERROR_INSUFFICIENT_RESOURCES", 1},
    {"ERROR_TIMEOUT", 2}
};

static const std::unordered_map<std::string, int32_t> mapVideoOutputErrorCode = {
    {"ERROR_UNKNOWN", -1},
    {"ERROR_DRIVER_ERROR", 0}
};

static const std::unordered_map<std::string, int32_t> mapMetadataObjectType = {
    {"FACE_DETECTION", 0}
};

static const std::unordered_map<std::string, int32_t> mapMetaOutputErrorCode = {
    {"ERROR_UNKNOWN", -1},
    {"ERROR_INSUFFICIENT_RESOURCES", 0}
};

enum CreateAsyncCallbackModes {
    CREATE_CAMERA_MANAGER_ASYNC_CALLBACK = 10,
};

class CameraNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);
    napi_ref GetErrorCallbackRef();

    CameraNapi();
    ~CameraNapi();

    static void CameraNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_status AddNamedProperty(napi_env env, napi_value object,
                                        const std::string name, int32_t enumValue);
    static napi_value Construct(napi_env env, napi_callback_info info);
    static napi_value CameraNapiConstructor(napi_env env, napi_callback_info info);

    static napi_value CreateCameraManagerInstance(napi_env env, napi_callback_info info);
    static napi_value CreateFlashModeObject(napi_env env);
    static napi_value CreateExposureModeObject(napi_env env);
    static napi_value CreateFocusModeObject(napi_env env);
    static napi_value CreateCameraPositionEnum(napi_env env);
    static napi_value CreateCameraTypeEnum(napi_env env);
    static napi_value CreateConnectionTypeEnum(napi_env env);
    static napi_value CreateCameraStatusObject(napi_env env);
    static napi_value CreateCameraFormatObject(napi_env env);
    static napi_value CreateImageRotationEnum(napi_env env);
    static napi_value CreateExposureStateEnum(napi_env env);
    static napi_value CreateFocusStateEnum(napi_env env);
    static napi_value CreateQualityLevelEnum(napi_env env);
    static napi_value CreateVideoStabilizationModeObject(napi_env env);

    static napi_value CreateCameraErrorCode(napi_env env);
    static napi_value CreateCameraInputErrorCode(napi_env env);
    static napi_value CreateCaptureSessionErrorCode(napi_env env);
    static napi_value CreatePreviewOutputErrorCode(napi_env env);
    static napi_value CreatePhotoOutputErrorCode(napi_env env);
    static napi_value CreateVideoOutputErrorCode(napi_env env);
    static napi_value CreateMetaOutputErrorCode(napi_env env);
    static napi_value CreateMetadataObjectType(napi_env env);

private:
    static thread_local napi_ref sConstructor_;

    static thread_local napi_ref flashModeRef_;
    static thread_local napi_ref exposureModeRef_;
    static thread_local napi_ref exposureStateRef_;
    static thread_local napi_ref focusModeRef_;
    static thread_local napi_ref focusStateRef_;
    static thread_local napi_ref cameraFormatRef_;
    static thread_local napi_ref cameraStatusRef_;
    static thread_local napi_ref connectionTypeRef_;
    static thread_local napi_ref cameraPositionRef_;
    static thread_local napi_ref cameraTypeRef_;
    static thread_local napi_ref imageRotationRef_;
    static thread_local napi_ref qualityLevelRef_;
    static thread_local napi_ref videoStabilizationModeRef_;

    static thread_local napi_ref errorCameraInputRef_;
    static thread_local napi_ref errorCaptureSessionRef_;
    static thread_local napi_ref errorPreviewOutputRef_;
    static thread_local napi_ref errorPhotoOutputRef_;
    static thread_local napi_ref errorVideoOutputRef_;
    static thread_local napi_ref metadataObjectTypeRef_;
    static thread_local napi_ref errorMetaOutputRef_;
    napi_env env_;
    napi_ref wrapper_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* CAMERA_NAPI_H_ */
