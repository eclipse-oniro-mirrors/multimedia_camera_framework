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

#include "camera_napi_utils.h"
#include "capture_scene_const.h"
#include "hilog/log.h"
#include "input/camera_input_napi.h"
#include "input/camera_manager.h"
#include "input/camera_manager_napi.h"
#include "input/capture_input.h"
#include "mode/mode_manager_napi.h"
#include "output/camera_output_capability.h"
#include "output/capture_output.h"
#include "output/metadata_output_napi.h"
#include "output/photo_output_napi.h"
#include "output/preview_output_napi.h"
#include "output/video_output_napi.h"
#include "session/camera_session_napi.h"
#include "session/capture_session.h"

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

static const std::unordered_map<std::string, int32_t> mapFlashMode = {
    {"FLASH_MODE_CLOSE", 0},
    {"FLASH_MODE_OPEN", 1},
    {"FLASH_MODE_AUTO", 2},
    {"FLASH_MODE_ALWAYS_OPEN", 3},
};

static const std::unordered_map<std::string, int32_t> mapExposureMode = {
    {"EXPOSURE_MODE_LOCKED", 0},
    {"EXPOSURE_MODE_AUTO", 1},
    {"EXPOSURE_MODE_CONTINUOUS_AUTO", 2},
};

static const std::unordered_map<std::string, int32_t> mapFocusMode = {
    {"FOCUS_MODE_MANUAL", 0},
    {"FOCUS_MODE_CONTINUOUS_AUTO", 1},
    {"FOCUS_MODE_AUTO", 2},
    {"FOCUS_MODE_LOCKED", 3},
};

static const std::unordered_map<std::string, int32_t> mapCameraPosition = {
    {"CAMERA_POSITION_UNSPECIFIED", 0},
    {"CAMERA_POSITION_BACK", 1},
    {"CAMERA_POSITION_FRONT", 2},
    {"CAMERA_POSITION_FOLD_INNER", 3},
};

static const std::unordered_map<std::string, int32_t> mapCameraType = {
    {"CAMERA_TYPE_DEFAULT", 0},
    {"CAMERA_TYPE_WIDE_ANGLE", 1},
    {"CAMERA_TYPE_ULTRA_WIDE", 2},
    {"CAMERA_TYPE_TELEPHOTO", 3},
    {"CAMERA_TYPE_TRUE_DEPTH", 4},
};

static const std::unordered_map<std::string, int32_t> mapConnectionType = {
    {"CAMERA_CONNECTION_BUILT_IN", 0},
    {"CAMERA_CONNECTION_USB_PLUGIN", 1},
    {"CAMERA_CONNECTION_REMOTE", 2},
};

static const std::unordered_map<std::string, int32_t> mapCameraFormat = {
    {"CAMERA_FORMAT_YUV_420_SP", CameraFormat::CAMERA_FORMAT_YUV_420_SP},
    {"CAMERA_FORMAT_JPEG", CameraFormat::CAMERA_FORMAT_JPEG},
    {"CAMERA_FORMAT_RGBA_8888", CameraFormat::CAMERA_FORMAT_RGBA_8888},
    {"CAMERA_FORMAT_DNG", CameraFormat::CAMERA_FORMAT_DNG},
    {"CAMERA_FORMAT_YCBCR_P010", CameraFormat::CAMERA_FORMAT_YCBCR_P010},
    {"CAMERA_FORMAT_YCRCB_P010", CameraFormat::CAMERA_FORMAT_YCRCB_P010},
};

static const std::unordered_map<std::string, int32_t> mapCameraStatus = {
    {"CAMERA_STATUS_APPEAR", 0},
    {"CAMERA_STATUS_DISAPPEAR", 1},
    {"CAMERA_STATUS_AVAILABLE", 2},
    {"CAMERA_STATUS_UNAVAILABLE", 3},
};

static const std::unordered_map<std::string, int32_t> mapVideoStabilizationMode = {
    {"OFF", 0},
    {"LOW", 1},
    {"MIDDLE", 2},
    {"HIGH", 3},
    {"AUTO", 4},
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

static const std::unordered_map<std::string, int32_t> mapHostNameType = {
    {"UNKNOWN", 0x00},
    {"PHONE", 0x0E},
    {"TABLE", 0x11},
};

static const std::unordered_map<std::string, int32_t> mapExposureState = {
    {"EXPOSURE_STATE_SCAN", 0},
    {"EXPOSURE_STATE_CONVERGED", 1},
};

static const std::unordered_map<std::string, int32_t> mapSceneMode = {
    {"NORMAL", JS_NORMAL},
    {"NORMAL_PHOTO", JS_CAPTURE},
    {"NORMAL_VIDEO", JS_VIDEO},
    {"PORTRAIT", JS_PORTRAIT},
    {"PORTRAIT_PHOTO", JS_PORTRAIT},
    {"NIGHT", JS_NIGHT},
    {"NIGHT_PHOTO", JS_NIGHT},
    {"PROFESSIONAL_PHOTO", JS_PROFESSIONAL_PHOTO},
    {"PROFESSIONAL_VIDEO", JS_PROFESSIONAL_VIDEO},
    {"HIGH_RES_PHOTO", JS_HIGH_RES_PHOTO},
    {"SLOW_MOTION_VIDEO", JS_SLOW_MOTION},
    {"MACRO_PHOTO", JS_CAPTURE_MARCO},
    {"MACRO_VIDEO", JS_VIDEO_MARCO},
    {"SECURE_PHOTO", JS_SECURE_CAMERA},
};

static const std::unordered_map<std::string, int32_t> mapFilterType = {
    {"NONE", 0},
    {"CLASSIC", 1},
    {"DAWN", 2},
    {"PURE", 3},
    {"GREY", 4},
    {"NATURAL", 5},
    {"MORI", 6},
    {"FAIR", 7},
    {"PINK", 8},
};

static const std::unordered_map<std::string, int32_t> mapBeautyType = {
    {"AUTO", 0},
    {"SKIN_SMOOTH", 1},
    {"FACE_SLENDER", 2},
    {"SKIN_TONE", 3},
};

static const std::unordered_map<std::string, int32_t> mapPortraitEffect = {
    {"OFF", 0},
    {"CIRCLES", 1},
    {"HEART", 2},
    {"ROTATED", 3},
    {"STUDIO", 4},
    {"THEATER", 5},
};

static const std::unordered_map<std::string, int32_t> mapTorchMode = {
    {"OFF", 0},
    {"ON", 1},
    {"AUTO", 2},
};

static const std::unordered_map<std::string, int32_t> mapCameraErrorCode = {
    {"NO_SYSTEM_APP_PERMISSION", 202},
    {"INVALID_ARGUMENT", 7400101},
    {"OPERATION_NOT_ALLOWED", 7400102},
    {"SESSION_NOT_CONFIG", 7400103},
    {"SESSION_NOT_RUNNING", 7400104},
    {"SESSION_CONFIG_LOCKED", 7400105},
    {"DEVICE_SETTING_LOCKED", 7400106},
    {"CONFLICT_CAMERA", 7400107},
    {"DEVICE_DISABLED", 7400108},
    {"DEVICE_PREEMPTED", 7400109},
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

static const std::unordered_map<std::string, int32_t> mapMetadataOutputErrorCode = {
    {"ERROR_UNKNOWN", -1},
    {"ERROR_INSUFFICIENT_RESOURCES", 0}
};

static const std::unordered_map<std::string, int32_t> mapDeferredDeliveryImageType = {
    {"NONE", 0},
    {"PHOTO", 1},
    {"VIDEO", 2},
};

static const std::unordered_map<std::string, int32_t> mapSmoothZoomMode = {
    {"NORMAL", 0},
};

static const std::unordered_map<std::string, int32_t> mapColorEffectType = {
    {"NORMAL", 0},
    {"BRIGHT", 1},
    {"SOFT", 2},
    {"BLACK_WHITE", 3},
};

static const std::unordered_map<std::string, int32_t> mapRestoreParamType = {
    {"NO_NEED_RESTORE_PARAM", 0},
    {"PERSISTENT_DEFAULT_PARAM", 1},
    {"TRANSIENT_ACTIVE_PARAM", 2},
};

static const std::unordered_map<std::string, int32_t> mapExposureMeteringMode = {
    {"MATRIX", 0},
    {"CENTER", 1},
    {"SPOT", 2},
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
    static napi_value CreateModeManagerInstance(napi_env env, napi_callback_info info);

    static napi_value CreateObjectWithMap(napi_env env,
                                          const std::string objectName,
                                          const std::unordered_map<std::string, int32_t>& inputMap,
                                          napi_ref& outputRef);

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
    static thread_local napi_ref hostNameTypeRef_;
    static thread_local napi_ref sceneModeRef_;
    static thread_local napi_ref filterTypeRef_;
    static thread_local napi_ref beautyTypeRef_;
    static thread_local napi_ref portraitEffectRef_;
    static thread_local napi_ref torchModeRef_;
    static thread_local napi_ref errorCameraRef_;
    static thread_local napi_ref errorCameraInputRef_;
    static thread_local napi_ref errorCaptureSessionRef_;
    static thread_local napi_ref errorPreviewOutputRef_;
    static thread_local napi_ref errorPhotoOutputRef_;
    static thread_local napi_ref errorVideoOutputRef_;
    static thread_local napi_ref metadataObjectTypeRef_;
    static thread_local napi_ref errorMetadataOutputRef_;
    static thread_local napi_ref deferredDeliveryImageTypeRef_;
    static thread_local napi_ref SmoothZoomModeRef_;
    static thread_local napi_ref colorEffectTypeRef_;
    static thread_local napi_ref restoreParamTypeRef_;
    static thread_local napi_ref exposureMeteringModeRef_;
    napi_env env_;
    napi_ref wrapper_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* CAMERA_NAPI_H_ */
