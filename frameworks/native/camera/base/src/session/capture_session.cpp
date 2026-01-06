/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "session/capture_session.h"

#include <cstdint>
#include <iterator>
#include <memory>
#include <mutex>
#include <sys/types.h>

#include "audio_system_manager.h"
#include "camera_device.h"
#include "camera_device_ability_items.h"
#include "camera_error_code.h"
#include "camera_types.h"
#include "camera_log.h"
#include "camera_metadata_info.h"
#include "camera_metadata_operator.h"
#include "camera_output_capability.h"
#include "camera_util.h"
#include "capture_output.h"
#include "camera_security_utils.h"
#include "capture_scene_const.h"
#include "features/moon_capture_boost_feature.h"
#include "capture_session_callback_stub.h"
#include "icapture_session_callback.h"
#include "input/camera_input.h"
#include "input/camera_manager.h"
#include "ipc_skeleton.h"
#include "os_account_manager.h"
#include "output/metadata_output.h"
#include "output/photo_output.h"
#include "output/preview_output.h"
#include "output/video_output.h"
#include "ability/camera_ability_builder.h"
#include "v1_0/cm_color_space.h"
#include "v2_1/cm_color_space.h"
#include "picture.h"
#include "camera_rotation_api_utils.h"
#include "picture_interface.h"
#include "features/composition_feature.h"
#include "hstream_common.h"

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Display::Graphic::Common::V2_1;
using CM_ColorSpaceType_V2_1 = OHOS::HDI::Display::Graphic::Common::V2_1::CM_ColorSpaceType;

bool CalculationHelper::AreVectorsEqual(const std::vector<float>& a,
    const std::vector<float>& b, float epsilon)
{
    // LCOV_EXCL_START
    CHECK_RETURN_RET(a.size() != b.size(), false);
    for (size_t i = 0; i < a.size(); ++i) {
        CHECK_RETURN_RET(std::fabs(a[i] - b[i]) > epsilon, false);
    }
    return true;
    // LCOV_EXCL_STOP
}

namespace {
constexpr int32_t DEFAULT_ITEMS = 10;
constexpr int32_t DEFAULT_DATA_LENGTH = 100;
constexpr int32_t DEFERRED_MODE_DATA_SIZE = 2;
constexpr int32_t FRAMERATE_120 = 120;
constexpr int32_t FRAMERATE_240 = 240;
constexpr int32_t CONTROL_CENTER_FPS_MAX = 30;
constexpr float DEFAULT_ZOOM_RATIO = 1.0;
const std::string AUDIO_EXTRA_PARAM_AUDIO_EFFECT = "audio_effect";
const std::string AUDIO_EXTRA_PARAM_ZOOM_RATIO = "zoom_ratio";
} // namespace

static const std::map<ColorSpace, CM_ColorSpaceType_V2_1> g_fwkColorSpaceMap_ = {
    {COLOR_SPACE_UNKNOWN, CM_ColorSpaceType_V2_1::CM_COLORSPACE_NONE},
    {DISPLAY_P3, CM_ColorSpaceType_V2_1::CM_P3_FULL},
    {SRGB, CM_ColorSpaceType_V2_1::CM_SRGB_FULL},
    {BT709, CM_ColorSpaceType_V2_1::CM_BT709_FULL},
    {BT2020_HLG, CM_ColorSpaceType_V2_1::CM_BT2020_HLG_FULL},
    {BT2020_PQ, CM_ColorSpaceType_V2_1::CM_BT2020_PQ_FULL},
    {P3_HLG, CM_ColorSpaceType_V2_1::CM_P3_HLG_FULL},
    {P3_PQ, CM_ColorSpaceType_V2_1::CM_P3_PQ_FULL},
    {DISPLAY_P3_LIMIT, CM_ColorSpaceType_V2_1::CM_P3_LIMIT},
    {SRGB_LIMIT, CM_ColorSpaceType_V2_1::CM_SRGB_LIMIT},
    {BT709_LIMIT, CM_ColorSpaceType_V2_1::CM_BT709_LIMIT},
    {BT2020_HLG_LIMIT, CM_ColorSpaceType_V2_1::CM_BT2020_HLG_LIMIT},
    {BT2020_PQ_LIMIT, CM_ColorSpaceType_V2_1::CM_BT2020_PQ_LIMIT},
    {P3_HLG_LIMIT, CM_ColorSpaceType_V2_1::CM_P3_HLG_LIMIT},
    {P3_PQ_LIMIT, CM_ColorSpaceType_V2_1::CM_P3_PQ_LIMIT},
    {H_LOG, CM_ColorSpaceType_V2_1::CM_BT2020_LOG_FULL},
};

const std::unordered_map<camera_focus_state_t, FocusCallback::FocusState> CaptureSession::metaFocusStateMap_ = {
    {OHOS_CAMERA_FOCUS_STATE_SCAN, FocusCallback::SCAN},
    {OHOS_CAMERA_FOCUS_STATE_FOCUSED, FocusCallback::FOCUSED},
    {OHOS_CAMERA_FOCUS_STATE_UNFOCUSED, FocusCallback::UNFOCUSED}
};

const std::unordered_map<camera_exposure_state_t,
        ExposureCallback::ExposureState> CaptureSession::metaExposureStateMap_ = {
    {OHOS_CAMERA_EXPOSURE_STATE_SCAN, ExposureCallback::SCAN},
    {OHOS_CAMERA_EXPOSURE_STATE_CONVERGED, ExposureCallback::CONVERGED}
};

const std::unordered_map<camera_filter_type_t, FilterType> CaptureSession::metaFilterTypeMap_ = {
    {OHOS_CAMERA_FILTER_TYPE_NONE, NONE},
    {OHOS_CAMERA_FILTER_TYPE_CLASSIC, CLASSIC},
    {OHOS_CAMERA_FILTER_TYPE_DAWN, DAWN},
    {OHOS_CAMERA_FILTER_TYPE_PURE, PURE},
    {OHOS_CAMERA_FILTER_TYPE_GREY, GREY},
    {OHOS_CAMERA_FILTER_TYPE_NATURAL, NATURAL},
    {OHOS_CAMERA_FILTER_TYPE_MORI, MORI},
    {OHOS_CAMERA_FILTER_TYPE_FAIR, FAIR},
    {OHOS_CAMERA_FILTER_TYPE_PINK, PINK}
};

const std::unordered_map<FilterType, camera_filter_type_t> CaptureSession::fwkFilterTypeMap_ = {
    {NONE, OHOS_CAMERA_FILTER_TYPE_NONE},
    {CLASSIC, OHOS_CAMERA_FILTER_TYPE_CLASSIC},
    {DAWN, OHOS_CAMERA_FILTER_TYPE_DAWN},
    {PURE, OHOS_CAMERA_FILTER_TYPE_PURE},
    {GREY, OHOS_CAMERA_FILTER_TYPE_GREY},
    {NATURAL, OHOS_CAMERA_FILTER_TYPE_NATURAL},
    {MORI, OHOS_CAMERA_FILTER_TYPE_MORI},
    {FAIR, OHOS_CAMERA_FILTER_TYPE_FAIR},
    {PINK, OHOS_CAMERA_FILTER_TYPE_PINK}
};

const std::unordered_map<BeautyType, camera_device_metadata_tag_t> CaptureSession::fwkBeautyControlMap_ = {
    {AUTO_TYPE, OHOS_CONTROL_BEAUTY_AUTO_VALUE},
    {SKIN_SMOOTH, OHOS_CONTROL_BEAUTY_SKIN_SMOOTH_VALUE},
    {FACE_SLENDER, OHOS_CONTROL_BEAUTY_FACE_SLENDER_VALUE},
    {SKIN_TONE, OHOS_CONTROL_BEAUTY_SKIN_TONE_VALUE},
    {SKIN_TONEBRIGHT, OHOS_CONTROL_BEAUTY_SKIN_TONEBRIGHT_VALUE},
    {EYE_BIGEYES, OHOS_CONTROL_BEAUTY_EYE_BIGEYES_VALUE},
    {HAIR_HAIRLINE, OHOS_CONTROL_BEAUTY_HAIR_HAIRLINE_VALUE},
    {FACE_MAKEUP, OHOS_CONTROL_BEAUTY_FACE_MAKEUP_VALUE},
    {HEAD_SHRINK, OHOS_CONTROL_BEAUTY_HEAD_SHRINK_VALUE},
    {NOSE_SLENDER, OHOS_CONTROL_BEAUTY_NOSE_SLENDER_VALUE},
};

const std::unordered_map<camera_device_metadata_tag_t, BeautyType> CaptureSession::metaBeautyControlMap_ = {
    {OHOS_CONTROL_BEAUTY_SKIN_SMOOTH_VALUE, SKIN_SMOOTH},
    {OHOS_CONTROL_BEAUTY_FACE_SLENDER_VALUE, FACE_SLENDER},
    {OHOS_CONTROL_BEAUTY_SKIN_TONE_VALUE, SKIN_TONE},
    {OHOS_CONTROL_BEAUTY_SKIN_TONEBRIGHT_VALUE, SKIN_TONEBRIGHT},
    {OHOS_CONTROL_BEAUTY_EYE_BIGEYES_VALUE, EYE_BIGEYES},
    {OHOS_CONTROL_BEAUTY_HAIR_HAIRLINE_VALUE, HAIR_HAIRLINE},
    {OHOS_CONTROL_BEAUTY_FACE_MAKEUP_VALUE, FACE_MAKEUP},
    {OHOS_CONTROL_BEAUTY_HEAD_SHRINK_VALUE, HEAD_SHRINK},
    {OHOS_CONTROL_BEAUTY_NOSE_SLENDER_VALUE, NOSE_SLENDER},
};

const std::unordered_map<CameraEffectSuggestionType, EffectSuggestionType>
    CaptureSession::metaEffectSuggestionTypeMap_ = {
    {OHOS_CAMERA_EFFECT_SUGGESTION_NONE, EFFECT_SUGGESTION_NONE},
    {OHOS_CAMERA_EFFECT_SUGGESTION_PORTRAIT, EFFECT_SUGGESTION_PORTRAIT},
    {OHOS_CAMERA_EFFECT_SUGGESTION_FOOD, EFFECT_SUGGESTION_FOOD},
    {OHOS_CAMERA_EFFECT_SUGGESTION_SKY, EFFECT_SUGGESTION_SKY},
    {OHOS_CAMERA_EFFECT_SUGGESTION_SUNRISE_SUNSET, EFFECT_SUGGESTION_SUNRISE_SUNSET},
    {OHOS_CAMERA_EFFECT_SUGGESTION_STAGE, EFFECT_SUGGESTION_STAGE}
};

// WhiteBalanceMode
const std::unordered_map<camera_awb_mode_t, WhiteBalanceMode> CaptureSession::metaWhiteBalanceModeMap_ = {
    { OHOS_CAMERA_AWB_MODE_OFF, AWB_MODE_OFF },
    { OHOS_CAMERA_AWB_MODE_AUTO, AWB_MODE_AUTO },
    { OHOS_CAMERA_AWB_MODE_INCANDESCENT, AWB_MODE_INCANDESCENT },
    { OHOS_CAMERA_AWB_MODE_FLUORESCENT, AWB_MODE_FLUORESCENT },
    { OHOS_CAMERA_AWB_MODE_WARM_FLUORESCENT, AWB_MODE_WARM_FLUORESCENT },
    { OHOS_CAMERA_AWB_MODE_DAYLIGHT, AWB_MODE_DAYLIGHT },
    { OHOS_CAMERA_AWB_MODE_CLOUDY_DAYLIGHT, AWB_MODE_CLOUDY_DAYLIGHT },
    { OHOS_CAMERA_AWB_MODE_TWILIGHT, AWB_MODE_TWILIGHT },
    { OHOS_CAMERA_AWB_MODE_SHADE, AWB_MODE_SHADE },
};

const std::unordered_map<WhiteBalanceMode, camera_awb_mode_t> CaptureSession::fwkWhiteBalanceModeMap_ = {
    { AWB_MODE_OFF, OHOS_CAMERA_AWB_MODE_OFF },
    { AWB_MODE_AUTO, OHOS_CAMERA_AWB_MODE_AUTO },
    { AWB_MODE_INCANDESCENT, OHOS_CAMERA_AWB_MODE_INCANDESCENT },
    { AWB_MODE_FLUORESCENT, OHOS_CAMERA_AWB_MODE_FLUORESCENT },
    { AWB_MODE_WARM_FLUORESCENT, OHOS_CAMERA_AWB_MODE_WARM_FLUORESCENT },
    { AWB_MODE_DAYLIGHT, OHOS_CAMERA_AWB_MODE_DAYLIGHT },
    { AWB_MODE_CLOUDY_DAYLIGHT, OHOS_CAMERA_AWB_MODE_CLOUDY_DAYLIGHT },
    { AWB_MODE_TWILIGHT, OHOS_CAMERA_AWB_MODE_TWILIGHT },
    { AWB_MODE_SHADE, OHOS_CAMERA_AWB_MODE_SHADE },
};

const std::unordered_map<LightPaintingType, CameraLightPaintingType>
    CaptureSession::fwkLightPaintingTypeMap_ = {
    {CAR, OHOS_CAMERA_LIGHT_PAINTING_CAR},
    {STAR, OHOS_CAMERA_LIGHT_PAINTING_STAR},
    {WATER, OHOS_CAMERA_LIGHT_PAINTING_WATER},
    {LIGHT, OHOS_CAMERA_LIGHT_PAINTING_LIGHT}
};

const std::unordered_map<CameraLightPaintingType, LightPaintingType>
    CaptureSession::metaLightPaintingTypeMap_ = {
    {OHOS_CAMERA_LIGHT_PAINTING_CAR, CAR},
    {OHOS_CAMERA_LIGHT_PAINTING_STAR, STAR},
    {OHOS_CAMERA_LIGHT_PAINTING_WATER, WATER},
    {OHOS_CAMERA_LIGHT_PAINTING_LIGHT, LIGHT}
};

const std::unordered_map<TripodStatus, FwkTripodStatus>
    CaptureSession::metaTripodStatusMap_ = {
    {TRIPOD_STATUS_INVALID, FwkTripodStatus::INVALID},
    {TRIPOD_STATUS_ACTIVE, FwkTripodStatus::ACTIVE},
    {TRIPOD_STATUS_ENTER, FwkTripodStatus::ENTER},
    {TRIPOD_STATUS_EXITING, FwkTripodStatus::EXITING}
};

const std::unordered_map<camera_constellation_drawing_state, ConstellationDrawingState>
    CaptureSession::drawingStateMap_ = {
    {OHOS_CAMERA_CONSTELLATION_PROCESSING, ConstellationDrawingState::PROCESSING},
    {OHOS_CAMERA_CONSTELLATION_SUCCEEDED, ConstellationDrawingState::SUCCEEDED},
    {OHOS_CAMERA_CONSTELLATION_FAILED_OVERBRIGHT, ConstellationDrawingState::FAILED_OVERBRIGHT},
    {OHOS_CAMERA_CONSTELLATION_FAILED_INSUFFICIENT_STARS, ConstellationDrawingState::FAILED_INSUFFICIENT_STARS}
};

const std::unordered_map<camera_focus_tracking_mode_t, FocusTrackingMode> CaptureSession::metaToFwFocusTrackingMode_ = {
    {OHOS_CAMERA_FOCUS_TRACKING_AUTO, FocusTrackingMode::FOCUS_TRACKING_MODE_AUTO},
    {OHOS_CAMERA_FOCUS_TRACKING_LOCKED, FocusTrackingMode::FOCUS_TRACKING_MODE_LOCKED}
};

const std::unordered_map<FocusTrackingMode, camera_focus_tracking_mode_t>
    CaptureSession::fwkToMetaFocusTrackingMode_ = {
    {FocusTrackingMode::FOCUS_TRACKING_MODE_AUTO, OHOS_CAMERA_FOCUS_TRACKING_AUTO},
    {FocusTrackingMode::FOCUS_TRACKING_MODE_LOCKED, OHOS_CAMERA_FOCUS_TRACKING_LOCKED}
};

const std::unordered_map<CameraApertureEffectType, ApertureEffectType>
    CaptureSession::metaToFwkApertureEffectTypeMap_ = {
    {OHOS_CAMERA_APERTURE_EFFECT_NORMAL, ApertureEffectType::APERTURE_EFFECT_NORMAL},
    {OHOS_CAMERA_APERTURE_EFFECT_LOWLIGHT, ApertureEffectType::APERTURE_EFFECT_LOWLIGHT},
    {OHOS_CAMERA_APERTURE_EFFECT_MACRO, ApertureEffectType::APERTURE_EFFECT_MACRO},
};

const std::unordered_map<std::string, camera_device_metadata_tag_t> CaptureSession::parametersMap_ = {
    {"REMOVE_SENSOR_RESTRAINT", OHOS_CONTROL_REMOVE_SENSOR_RESTRAINT},
};

const std::string STREAM_TYPE_REPEAT = "RepeatStream";
const std::string STREAM_TYPE_METADATA = "MetadataStream";
const std::string STREAM_TYPE_CAPTURE = "CaptureStream";
const std::string STREAM_TYPE_DEPTH = "DepthStream";
const std::string STREAM_TYPE_UNIFIY_MOVIE = "UnifyMovieStream";
const std::string STREAM_TYPE_UNKNOWN = "UnknownStream";
const std::string REPEAT_STREAM_TYPE_PREVIEW = "Preview";
const std::string REPEAT_STREAM_TYPE_VIDEO = "Video";
const std::string REPEAT_STREAM_TYPE_MOVIE_FILE = "MovieFile";
const std::string REPEAT_STREAM_TYPE_UNKNOWN = "Unknown";

const std::unordered_map<StreamType, std::string> CaptureSession::CameraDfxReportHelper::streamTypeMap_ = {
    {StreamType::REPEAT, STREAM_TYPE_REPEAT},
    {StreamType::METADATA, STREAM_TYPE_METADATA},
    {StreamType::CAPTURE, STREAM_TYPE_CAPTURE},
    {StreamType::DEPTH, STREAM_TYPE_DEPTH},
    {StreamType::UNIFY_MOVIE, STREAM_TYPE_UNIFIY_MOVIE},
};

const std::unordered_map<CaptureOutputType, std::string> CaptureSession::CameraDfxReportHelper::repeatStreamTypeMap_ = {
    {CAPTURE_OUTPUT_TYPE_PREVIEW, REPEAT_STREAM_TYPE_PREVIEW},
    {CAPTURE_OUTPUT_TYPE_VIDEO, REPEAT_STREAM_TYPE_VIDEO},
    {CAPTURE_OUTPUT_TYPE_MOVIE_FILE, REPEAT_STREAM_TYPE_MOVIE_FILE},
};

// metering mode
const std::unordered_map<camera_meter_mode_t, MeteringMode> CaptureSession::metaMeteringModeMap_ = {
    {OHOS_CAMERA_SPOT_METERING,             METERING_MODE_SPOT},
    {OHOS_CAMERA_REGION_METERING,           METERING_MODE_REGION},
    {OHOS_CAMERA_OVERALL_METERING,          METERING_MODE_OVERALL},
    {OHOS_CAMERA_CENTER_WEIGHTED_METERING,  METERING_MODE_CENTER_WEIGHTED},
    {OHOS_CAMERA_CENTER_HIGHLIGHT_WEIGHTED, METERING_MODE_CENTER_HIGHLIGHT_WEIGHTED},
};

const std::unordered_map<MeteringMode, camera_meter_mode_t> CaptureSession::fwkMeteringModeMap_ = {
    {METERING_MODE_SPOT,                    OHOS_CAMERA_SPOT_METERING},
    {METERING_MODE_REGION,                  OHOS_CAMERA_REGION_METERING},
    {METERING_MODE_OVERALL,                 OHOS_CAMERA_OVERALL_METERING},
    {METERING_MODE_CENTER_WEIGHTED,         OHOS_CAMERA_CENTER_WEIGHTED_METERING},
    {METERING_MODE_CENTER_HIGHLIGHT_WEIGHTED, OHOS_CAMERA_CENTER_HIGHLIGHT_WEIGHTED},
};

const std::unordered_set<SceneMode> CaptureSession::videoModeSet_ = {
    SceneMode::VIDEO,
    SceneMode::SLOW_MOTION,
    SceneMode::VIDEO_MACRO,
    SceneMode::PROFESSIONAL_VIDEO,
    SceneMode::APERTURE_VIDEO,
    SceneMode::CINEMATIC_VIDEO
};

int32_t CaptureSessionCallback::OnError(int32_t errorCode)
{
    MEDIA_INFO_LOG("CaptureSessionCallback::OnError() is called!, errorCode: %{public}d", errorCode);
    if (captureSession_ != nullptr) {
        auto callback = captureSession_->GetApplicationCallback();
        if (callback) {
            callback->OnError(errorCode);
        } else {
            MEDIA_INFO_LOG("CaptureSessionCallback::ApplicationCallback not set!, Discarding callback");
        }
    } else {
        MEDIA_INFO_LOG("CaptureSessionCallback::ApplicationCallback not set!, Discarding callback");
    }
    return CameraErrorCode::SUCCESS;
}

int32_t PressureStatusCallback::OnPressureStatusChanged(PressureStatus status)
{
    MEDIA_INFO_LOG("PressureStatusCallback::OnPressureStatusChanged() is called, status: %{public}d", status);
    auto session = captureSession_.promote();
    if (session != nullptr) {
        auto callback = session->GetPressureCallback();
        if (callback) {
            callback->OnPressureStatusChanged(status);
        } else {
            MEDIA_INFO_LOG("PressureStatusCallback::GetPressureCallback not set!, Discarding callback");
        }
    } else {
        MEDIA_INFO_LOG("PressureStatusCallback captureSession not set!, Discarding callback");
    }
    return CameraErrorCode::SUCCESS;
}

int32_t ControlCenterEffectStatusCallback::OnControlCenterEffectStatusChanged(
    const ControlCenterStatusInfo& controlCenterStatusInfo)
{
    MEDIA_INFO_LOG("OnControlCenterEffectStatusChanged is called, status: %{public}d",
        controlCenterStatusInfo.isActive);
    auto session = captureSession_.promote();
    if (session != nullptr) {
        auto callback = session->GetControlCenterEffectCallback();
        if (callback) {
            callback->OnControlCenterEffectStatusChanged(controlCenterStatusInfo);
        } else {
            MEDIA_INFO_LOG(
                "ControlCenterEffectStatusCallback::OnControlCenterEffectStatusChanged not set!, Discarding callback");
        }
    } else {
        MEDIA_INFO_LOG(
            "ControlCenterEffectStatusCallback::OnControlCenterEffectStatusChanged not set!, Discarding callback");
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CameraSwitchSessionCallback::OnCameraActive(
    const std::string &cameraId, bool isRegisterCameraSwitchCallback, const CaptureSessionInfo &sessionInfo)
{
    return CameraErrorCode::SUCCESS;
}

int32_t CameraSwitchSessionCallback::OnCameraUnactive(const std::string &cameraId)
{
    MEDIA_INFO_LOG("OnCameraUnactive is called, cameraId: %{public}s", cameraId.c_str());
    auto session = captureSession_.promote();
    if (session != nullptr) {
        auto callback = session->GetCameraSwitchRequestCallback();
        if (callback) {
            callback->OnAppCameraSwitch(cameraId);
        } else {
            MEDIA_INFO_LOG("CameraSwitchSessionCallback::OnCameraUnactive not set!, Discarding callback");
        }
    } else {
        MEDIA_INFO_LOG("CameraSwitchSessionCallback::OnCameraUnactive session not set!, Discarding callback");
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CameraSwitchSessionCallback::OnCameraSwitch(
    const std::string &oriCameraId, const std::string &destCameraId, bool status)
{
    return CameraErrorCode::SUCCESS;
}

int32_t FoldCallback::OnFoldStatusChanged(const FoldStatus status)
{
    MEDIA_INFO_LOG("FoldStatus is %{public}d", status);
    auto captureSession = captureSession_.promote();
    CHECK_RETURN_RET_ELOG(captureSession == nullptr, CAMERA_OPERATION_NOT_ALLOWED, "captureSession is nullptr.");
    bool isEnableAutoSwitch = captureSession->GetIsAutoSwitchDeviceStatus();
    CHECK_RETURN_RET_ELOG(!isEnableAutoSwitch, CAMERA_OPERATION_NOT_ALLOWED, "isEnableAutoSwitch is false.");
    bool isSuccess = captureSession->SwitchDevice();
    MEDIA_INFO_LOG("SwitchDevice isSuccess: %{public}d", isSuccess);
    auto autoDeviceSwitchCallback = captureSession->GetAutoDeviceSwitchCallback();
    CHECK_RETURN_RET_ELOG(
        autoDeviceSwitchCallback == nullptr, CAMERA_OPERATION_NOT_ALLOWED, "autoDeviceSwitchCallback is nullptr");
    bool isDeviceCapabilityChanged = captureSession->GetDeviceCapabilityChangeStatus();
    MEDIA_INFO_LOG("SwitchDevice isDeviceCapabilityChanged: %{public}d", isDeviceCapabilityChanged);
    autoDeviceSwitchCallback->OnAutoDeviceSwitchStatusChange(isSuccess, isDeviceCapabilityChanged);
    return CAMERA_OK;
}

CaptureSession::CaptureSession(sptr<ICaptureSession>& captureSession) : innerCaptureSession_(captureSession)
{
    compositionFeature_ = std::make_shared<CompositionFeature>(this);
    metadataResultProcessor_ = std::make_shared<CaptureSessionMetadataResultProcessor>(this);
    cameraDfxReportHelper_ = std::make_shared<CameraDfxReportHelper>(this);
    sptr<IRemoteObject> object = innerCaptureSession_->AsObject();
    pid_t pid = 0;
    deathRecipient_ = new (std::nothrow) CameraDeathRecipient(pid);
    CHECK_RETURN_ELOG(deathRecipient_ == nullptr, "failed to new CameraDeathRecipient.");

    deathRecipient_->SetNotifyCb([this](pid_t pid) { CameraServerDied(pid); });
    bool result = object->AddDeathRecipient(deathRecipient_);
    CHECK_RETURN_ELOG(!result, "failed to add deathRecipient");
}

void CaptureSession::CameraServerDied(pid_t pid)
{
    MEDIA_ERR_LOG("camera server has died, pid:%{public}d!", pid);
    {
        std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
        if (appCallback_ != nullptr) {
            MEDIA_DEBUG_LOG("appCallback not nullptr");
            int32_t serviceErrorType = ServiceToCameraError(CAMERA_INVALID_STATE);
            appCallback_->OnError(serviceErrorType);
        }
    }
    SessionRemoveDeathRecipient();
}

void CaptureSession::SessionRemoveDeathRecipient()
{
    auto captureSession = GetCaptureSession();
    if (captureSession != nullptr) {
        auto asObject = captureSession->AsObject();
        if (asObject) {
            (void)asObject->RemoveDeathRecipient(deathRecipient_);
        }
        SetCaptureSession(nullptr);
    }
    deathRecipient_ = nullptr;
}

CaptureSession::~CaptureSession()
{
    MEDIA_DEBUG_LOG("Enter Into CaptureSession::~CaptureSession()");
    SessionRemoveDeathRecipient();
}

int32_t CaptureSession::BeginConfig()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter Into CaptureSession::BeginConfig");
    if (IsSessionConfiged()) {
        HILOG_COMM_ERROR("CaptureSession::BeginConfig Session is locked");
        return CameraErrorCode::SESSION_CONFIG_LOCKED;
    }

    isColorSpaceSetted_ = false;
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    auto captureSession = GetCaptureSession();
    if (captureSession) {
        errCode = captureSession->BeginConfig();
        if (errCode != CAMERA_OK) {
            HILOG_COMM_ERROR("Failed to BeginConfig!, %{public}d", errCode);
        }
    } else {
        MEDIA_ERR_LOG("CaptureSession::BeginConfig() captureSession is nullptr");
    }
    return ServiceToCameraError(errCode);
}

int32_t CaptureSession::EnableRawDelivery(bool enabled)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("Enter EnableRawDelivery, isEnable:%{public}d", enabled);
    isRawImageDelivery_ = enabled;
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::CommitConfig()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter Into CaptureSession::CommitConfig");
    if (!IsSessionConfiged()) {
        HILOG_COMM_ERROR("CaptureSession::CommitConfig operation Not allowed!");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }
    CHECK_PRINT_DLOG(!CheckLightStatus(), "CaptureSession::CommitConfig the camera can't support light status!");

    if (!isColorSpaceSetted_) {
        HILOG_COMM_INFO("CaptureSession::CommitConfig is not setColorSpace");
        auto preconfigProfiles = GetPreconfigProfiles();
        if (preconfigProfiles != nullptr) {
            SetColorSpace(preconfigProfiles->colorSpace);
        }
    }
    // DELIVERY_PHOTO for default when commit
    if (photoOutput_ && !isDeferTypeSetted_) {
        sptr<PhotoOutput> photoOutput = (sptr<PhotoOutput>&)photoOutput_;
        int32_t supportCode = photoOutput->IsDeferredImageDeliverySupported(DELIVERY_PHOTO);
        MEDIA_INFO_LOG("CaptureSession::CommitConfig supportCode:%{public}d", supportCode);
        if (supportCode == 0) {
            EnableDeferredType(photoOutput->IsEnableDeferred() ? DELIVERY_PHOTO : DELIVERY_NONE, false);
        } else {
            EnableDeferredType(DELIVERY_NONE, false);
        }
        SetUserId();
    }
    SetAppHint();
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    auto captureSession = GetCaptureSession();
    bool isHasSwitchedOffline = false;
    bool isOfflinePhoto = photoOutput_ && ((sptr<PhotoOutput>&)photoOutput_)->IsHasSwitchOfflinePhoto();
    if (isOfflinePhoto) {
        isHasSwitchedOffline = true;
        EnableOfflinePhoto();
    }
    if (captureSession) {
        std::string foldScreenType = CameraManager::GetInstance()->GetFoldScreenType();
        CHECK_EXECUTE(!foldScreenType.empty() && (foldScreenType[0] == '6' || foldScreenType[0] == '7')
            && !CameraSecurity::CheckSystemApp() && getuid() != FACE_CLIENT_UID, AdjustRenderFit());
        errCode = captureSession->SetCommitConfigFlag(isHasSwitchedOffline);
        errCode = captureSession->CommitConfig();
        MEDIA_INFO_LOG("CaptureSession::CommitConfig commit mode = %{public}d", GetMode());
        if (errCode != CAMERA_OK) {
            HILOG_COMM_ERROR("Failed to CommitConfig!, %{public}d", errCode);
        }
    }
    SetZoomRatioForAudio(DEFAULT_ZOOM_RATIO);
    CHECK_EXECUTE (cameraDfxReportHelper_ != nullptr, cameraDfxReportHelper_->ReportCameraConfigInfo(errCode));
    return ServiceToCameraError(errCode);
}

std::string CaptureSession::CameraDfxReportHelper::GetStreamTypeName(StreamType type)
{
    auto it = streamTypeMap_.find(type);
    return (it != streamTypeMap_.end()) ? it->second : STREAM_TYPE_UNKNOWN;
}

std::string CaptureSession::CameraDfxReportHelper::GetRepeatStreamTypeName(CaptureOutputType outputType)
{
    auto it = repeatStreamTypeMap_.find(outputType);
    return (it != repeatStreamTypeMap_.end()) ? it->second : REPEAT_STREAM_TYPE_UNKNOWN;
}

std::string CaptureSession::CameraDfxReportHelper::GetTypeName(StreamType type, CaptureOutputType outputType)
{
    std::string typeName = GetStreamTypeName(type);
    if (type != StreamType::REPEAT) {
        return typeName;
    }
    std::string repeatTypeName = GetRepeatStreamTypeName(outputType);
    typeName += ":";
    typeName += repeatTypeName;
    return typeName;
}

void CaptureSession::CameraDfxReportHelper::ReportCameraConfigInfo(int32_t errorCode)
{
    MEDIA_DEBUG_LOG("CaptureSession::CameraDfxReportHelper::ReportCameraConfigInfo enter.");
    CHECK_RETURN_DLOG(session_ == nullptr,
        "CaptureSession::CameraDfxReportHelper::ReportCameraConfigInfo capture session is nullptr");
    std::vector<StreamConfigInfo> streamConfigInfos = ExtractStreamConfigInfo();
    Size previewSize = {0, 0};
    std::vector<std::string> types;
    std::vector<std::string> fpss;
    std::vector<std::string> sizes;
    std::vector<CameraFormat> formats;

    for(auto streamInfo: streamConfigInfos) {
        formats.emplace_back(streamInfo.format);
        fpss.emplace_back(Container2String(streamInfo.fps.begin(), streamInfo.fps.end()));
        std::vector<uint32_t> size = {streamInfo.size.width, streamInfo.size.height};
        sizes.emplace_back(Container2String(size.begin(), size.end()));
        types.emplace_back(GetTypeName(streamInfo.type, streamInfo.outputType) +
            Container2String(size.begin(), size.end()));
        CHECK_EXECUTE(streamInfo.outputType == CAPTURE_OUTPUT_TYPE_PREVIEW, previewSize = streamInfo.size);
    }

    std::string cameraId;
    auto device = session_->GetInputDevice();
    if (device != nullptr) {
        auto deviceInfo = device->GetCameraDeviceInfo();
        if (deviceInfo != nullptr) {
            cameraId = deviceInfo->GetID();
        }
    }
    std::vector<float> zrr = session_->GetZoomRatioRange();
    ModeConfigInfo modeConfigInfo = ExtractModeConfigInfo();
    ColorSpace colorSpace = ColorSpace::COLOR_SPACE_UNKNOWN;
    session_->GetActiveColorSpace(colorSpace);

    POWERMGR_SYSEVENT_CAMERA_CONFIG(
        Container2String(types.begin(), types.end()),
        previewSize.width,
        previewSize.height,
        cameraId,
        static_cast<uint8_t>(modeConfigInfo.mode),
        static_cast<uint8_t>(modeConfigInfo.nightSubMode),
        static_cast<uint8_t>(modeConfigInfo.lightPaintingType),
        Container2String(formats.begin(), formats.end()),
        Container2String(fpss.begin(), fpss.end()),
        static_cast<int32_t>(colorSpace),
        session_->isColorSpaceSetted_,
        static_cast<uint8_t>(session_->GetActiveVideoStabilizationMode()),
        Container2String(zrr.begin(), zrr.end()),
        static_cast<uint8_t>(streamConfigInfos.size()),
        errorCode);
}

std::vector<StreamConfigInfo> CaptureSession::CameraDfxReportHelper::ExtractStreamConfigInfo()
{
    MEDIA_DEBUG_LOG("CaptureSession::CameraDfxReportHelper::ExtractStreamConfigInfo enter.");
    std::vector<StreamConfigInfo> infos;
    std::lock_guard<std::mutex> lock(session_->captureOutputSetsMutex_);
    for (const auto& output : session_->captureOutputSets_) {
        auto item = output.promote();
        CHECK_CONTINUE(item == nullptr);
        StreamConfigInfo streamInfo;
        std::shared_ptr<Profile> profile = nullptr;
        if (item->GetOutputType() == CAPTURE_OUTPUT_TYPE_PREVIEW) {
            profile = item->GetPreviewProfile();
            streamInfo.fps = ((sptr<PreviewOutput>&)item)->GetFrameRateRange();
        } else if (item->GetOutputType() == CAPTURE_OUTPUT_TYPE_PHOTO) {
            profile = item->GetPhotoProfile();
        } else if (item->GetOutputType() == CAPTURE_OUTPUT_TYPE_DEPTH_DATA) {
            profile = item->GetDepthProfile();
        } else if (item->GetOutputType() == CAPTURE_OUTPUT_TYPE_METADATA) {
            profile = std::make_shared<Profile>(
                CameraFormat::CAMERA_FORMAT_INVALID, Size{.width = 1920, .height = 1080});
        } else {
            profile = item->GetVideoProfile();
            CHECK_EXECUTE(item->GetVideoProfile(), streamInfo.fps = item->GetVideoProfile()->GetFrameRates());
        }
        streamInfo.type = item->GetStreamType();
        streamInfo.outputType = item->GetOutputType();
        if (profile != nullptr) {
            streamInfo.format = profile->GetCameraFormat();
            streamInfo.size = profile->GetSize();
        }
        infos.emplace_back(streamInfo);
        MEDIA_DEBUG_LOG("CaptureSession::CameraDfxReportHelper::ExtractStreamConfigInfo streamInfo: type: %{public}d,"
            " format: %{public}d, size: {%{public}d, %{public}d}.", streamInfo.type, streamInfo.format,
            streamInfo.size.width, streamInfo.size.height);
        if (streamInfo.fps.size() >= 2) {
            MEDIA_DEBUG_LOG("CaptureSession::CameraDfxReportHelper::ExtractStreamConfigInfo fps: {%{public}d,"
                "%{public}d}.", streamInfo.fps[0], streamInfo.fps[1]);
        }
    }
    return infos;
}

ModeConfigInfo CaptureSession::CameraDfxReportHelper::ExtractModeConfigInfo()
{
    MEDIA_DEBUG_LOG("CaptureSession::CameraDfxReportHelper::ExtractModeConfigInfo enter.");
    ModeConfigInfo info;
    info.mode = session_->GetMode();
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = session_->GetMetadata();
    if (metadata != nullptr && info.mode == SceneMode::NIGHT) {
        camera_metadata_item_t item;
        int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_NIGHT_SUB_MODE, &item);
        if (ret == CAM_META_SUCCESS && item.count > 0) {
            info.nightSubMode = static_cast<NightSubMode>(item.data.u8[0]);
        }
    }
    if (metadata != nullptr && info.mode == SceneMode::LIGHT_PAINTING) {
        camera_metadata_item_t item;
        int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_LIGHT_PAINTING_TYPE, &item);
        if (ret == CAM_META_SUCCESS && item.count > 0) {
            info.lightPaintingType = static_cast<LightPaintingType>(item.data.u8[0]);
        }
    }
    MEDIA_DEBUG_LOG("CaptureSession::CameraDfxReportHelper::ExtractModeConfigInfo mode=%{public}d, "
        "nightsubmode=%{public}d, lightpaintingtype=%{public}d", info.mode, info.nightSubMode, info.lightPaintingType);
    return info;
}

void CaptureSession::SetAppHint()
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_ELOG(IsSessionCommited(), "CaptureSession::SetAppHint session has committed!");
    this->LockForControl();
    CHECK_RETURN_ELOG(changedMetadata_ == nullptr, "CaptureSession::SetAppHint changedMetadata_ is NULL");
    uint32_t appHint = OHOS_CAMERA_APP_HINT_NONE;
    CHECK_EXECUTE(CameraSecurity::CheckSystemApp(), appHint |= OHOS_CAMERA_APP_HINT_AGGRESSIVE_RESOURCE);
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_APP_HINT, &appHint, 1);
    MEDIA_INFO_LOG("CaptureSession::SetAppHint value: %{public}u", appHint);
    CHECK_PRINT_ELOG(!status, "CaptureSession::SetAppHint Failed to set type!");
    int32_t errCode = this->UnlockForControl();
    CHECK_RETURN_DLOG(errCode != CameraErrorCode::SUCCESS, "CaptureSession::SetAppHint Failed");
}

void CaptureSession::CheckSpecSearch()
{
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_ELOG(inputDevice == nullptr, "inputDevice is nullptr");
    auto deviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_ELOG(deviceInfo == nullptr, "deviceInfo is nullptr");
    supportSpecSearch_ = deviceInfo->IsSupportSpecSearch();
    MEDIA_INFO_LOG("CaptureSession::CheckSpecSearch supportSpecSearch: %{public}d", supportSpecSearch_.load());
}

bool CaptureSession::CheckLightStatus()
{
    camera_metadata_item_t item;
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET(metadata == nullptr, false);
    int32_t retCode = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_LIGHT_STATUS, &item);
    CHECK_RETURN_RET_DLOG(
        retCode != CAM_META_SUCCESS || item.count == 0 || item.data.u8[0] == 0, false, "lightStatus is not support");
    // LCOV_EXCL_START
    uint8_t lightStart = 1;
    LockForControl();
    changedMetadata_->addEntry(OHOS_CONTROL_LIGHT_STATUS, &lightStart, 1);
    UnlockForControl();
    return true;
    // LCOV_EXCL_STOP
}

void CaptureSession::PopulateProfileLists(std::vector<Profile>& photoProfileList,
                                          std::vector<Profile>& previewProfileList,
                                          std::vector<VideoProfile>& videoProfileList)
{
    for (auto output : captureOutputSets_) {
        auto item = output.promote();
        CHECK_CONTINUE(item == nullptr);
        if (item->GetOutputType() == CAPTURE_OUTPUT_TYPE_PREVIEW) {
            previewProfileList.emplace_back(*(item->GetPreviewProfile()));
        } else if (item->GetOutputType() == CAPTURE_OUTPUT_TYPE_PHOTO) {
            photoProfileList.emplace_back(*(item->GetPhotoProfile()));
        } else if (item->GetOutputType() == CAPTURE_OUTPUT_TYPE_VIDEO) {
            videoProfileList.emplace_back(*(item->GetVideoProfile()));
        }
    }
}

void CaptureSession::PopulateSpecIdMaps(sptr<CameraDevice> device, int32_t modeName,
                                        std::map<int32_t, std::vector<Profile>>& specIdPreviewMap,
                                        std::map<int32_t, std::vector<Profile>>& specIdPhotoMap,
                                        std::map<int32_t, std::vector<VideoProfile>>& specIdVideoMap)
{
    CHECK_RETURN_ELOG(!device, "camera device is null");
    auto buildSpecProfileMap = [](auto& profiles, auto& map) {
        for (auto& profile : profiles) {
            map[profile.GetSpecId()].emplace_back(profile);
        }
    };

    buildSpecProfileMap(device->modePreviewProfiles_[modeName], specIdPreviewMap);
    buildSpecProfileMap(device->modePhotoProfiles_[modeName], specIdPhotoMap);
    buildSpecProfileMap(device->modeVideoProfiles_[modeName], specIdVideoMap);
}

std::vector<sptr<CameraOutputCapability>> CaptureSession::GetCameraOutputCapabilities(sptr<CameraDevice> &device)
{
    int32_t modeName = GetMode();
    std::map<int32_t, std::vector<Profile>> specIdPreviewMap;
    std::map<int32_t, std::vector<Profile>> specIdPhotoMap;
    std::map<int32_t, std::vector<VideoProfile>> specIdVideoMap;
    PopulateSpecIdMaps(device, modeName, specIdPreviewMap, specIdPhotoMap, specIdVideoMap);
    std::vector<sptr<CameraOutputCapability>> list;
    for (const auto& pair : specIdPreviewMap) {
        int32_t specId = pair.first;
        sptr<CameraOutputCapability> cameraOutputCapability = new CameraOutputCapability();
        CHECK_CONTINUE(cameraOutputCapability == nullptr);
        cameraOutputCapability->SetPreviewProfiles(specIdPreviewMap[specId]);
        cameraOutputCapability->SetPhotoProfiles(specIdPhotoMap[specId]);
        cameraOutputCapability->SetVideoProfiles(specIdVideoMap[specId]);
        cameraOutputCapability->specId_ = specId;
        list.emplace_back(cameraOutputCapability);
    }
    return list;
}

std::vector<sptr<CameraAbility>> CaptureSession::GetSessionFunctions(std::vector<Profile>& previewProfiles,
                                                                     std::vector<Profile>& photoProfiles,
                                                                     std::vector<VideoProfile>& videoProfiles,
                                                                     bool isForApp)
{
    MEDIA_INFO_LOG("CaptureSession::GetSessionFunctions enter");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, {}, "CaptureSession::GetSessionFunctions inputDevice is null");
    auto device = inputDevice->GetCameraDeviceInfo();
    std::vector<sptr<CameraOutputCapability>> outputCapabilityList = GetCameraOutputCapabilities(device);
    std::set<int32_t> supportedSpecIds;

    for (const auto &profile : previewProfiles) {
        profile.DumpProfile("preview");
    }
    for (const auto& profile : photoProfiles) {
        profile.DumpProfile("photo");
    }
    for (const auto& profile : videoProfiles) {
        profile.DumpVideoProfile("video");
    }

    for (const auto& capability : outputCapabilityList) {
        int32_t specId = capability->specId_;
        MEDIA_DEBUG_LOG("CaptureSession::GetSessionFunctions specId: %{public}d", specId);
        bool isInsertSpecId = capability->IsMatchPreviewProfiles(previewProfiles) &&
            capability->IsMatchPhotoProfiles(photoProfiles) && capability->IsMatchVideoProfiles(videoProfiles);
        if (isInsertSpecId) {
            supportedSpecIds.insert(specId);
            MEDIA_INFO_LOG("CaptureSession::GetSessionFunctions insert specId: %{public}d", specId);
        }
    }

    CameraAbilityBuilder builder;
    std::vector<sptr<CameraAbility>> cameraAbilityArray;
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, cameraAbilityArray, "GetSessionFunctions camera metadata is null");
    return builder.GetAbility(
        GetFeaturesMode().GetFeaturedMode(), metadata->get(), supportedSpecIds, this, isForApp);
}

std::vector<sptr<CameraAbility>> CaptureSession::GetSessionConflictFunctions()
{
    CameraAbilityBuilder builder;
    std::vector<sptr<CameraAbility>> cameraAbilityArray;
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, cameraAbilityArray, "GetSessionConflictFunctions camera metadata is null");
    return builder.GetConflictAbility(GetFeaturesMode().GetFeaturedMode(), metadata->get());
}

void CaptureSession::CreateCameraAbilityContainer()
{
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_ELOG(inputDevice == nullptr, "CreateCameraAbilityContainer inputDevice is null");
    std::vector<Profile> photoProfileList;
    std::vector<Profile> previewProfileList;
    std::vector<VideoProfile> videoProfileList;
    PopulateProfileLists(photoProfileList, previewProfileList, videoProfileList);
    std::vector<sptr<CameraAbility>> abilities =
        GetSessionFunctions(previewProfileList, photoProfileList, videoProfileList, false);
    MEDIA_DEBUG_LOG("CreateCameraAbilityContainer abilities size %{public}zu", abilities.size());
    CHECK_PRINT_ILOG(abilities.size() == 0, "CreateCameraAbilityContainer fail cant find suitable ability");
    std::vector<sptr<CameraAbility>> conflictAbilities = GetSessionConflictFunctions();
    MEDIA_DEBUG_LOG("CreateCameraAbilityContainer conflictAbilities size %{public}zu", conflictAbilities.size());
    std::lock_guard<std::mutex> lock(abilityContainerMutex_);
    cameraAbilityContainer_ = new CameraAbilityContainer(abilities, conflictAbilities, this);
}

bool CaptureSession::CanAddInput(sptr<CaptureInput>& input)
{
    // can only add one cameraInput
    CAMERA_SYNC_TRACE;
    bool ret = false;
    MEDIA_INFO_LOG("Enter Into CaptureSession::CanAddInput");
    CHECK_RETURN_RET_ELOG(
        !IsSessionConfiged() || input == nullptr, ret, "CaptureSession::AddInput operation Not allowed!");
    auto captureSession = GetCaptureSession();
    CHECK_RETURN_RET_ELOG(captureSession == nullptr, ret, "CaptureSession::CanAddInput() captureSession is nullptr");
    captureSession->CanAddInput(((sptr<CameraInput>&)input)->GetCameraDevice(), ret);
    return ret;
}

void CaptureSession::GetMetadataFromService(sptr<CameraDevice> device)
{
    CHECK_RETURN_ELOG(device == nullptr, "GetMetadataFromService device is nullptr");
    auto cameraId = device->GetID();
    auto serviceProxy = CameraManager::GetInstance()->GetServiceProxy();
    CHECK_RETURN_ELOG(serviceProxy == nullptr, "GetMetadataFromService serviceProxy is null");
    std::shared_ptr<OHOS::Camera::CameraMetadata> metaData;
    serviceProxy->GetCameraAbility(cameraId, metaData);
    CHECK_RETURN_ELOG(metaData == nullptr, "GetMetadataFromService GetDeviceMetadata failed");
    device->AddMetadata(metaData);
}

int32_t CaptureSession::AddInput(sptr<CaptureInput>& input)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter Into CaptureSession::AddInput");
    CHECK_RETURN_RET_ELOG(!IsSessionConfiged(), CameraErrorCode::OPERATION_NOT_ALLOWED,
        "CaptureSession::AddInput operation Not allowed!");
    CHECK_RETURN_RET_ELOG(
        input == nullptr, ServiceToCameraError(CAMERA_INVALID_ARG), "CaptureSession::AddInput input is null");
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    auto captureSession = GetCaptureSession();
    CHECK_RETURN_RET_ELOG(captureSession == nullptr, ServiceToCameraError(errCode),
        "CaptureSession::AddInput() captureSession is nullptr");
    auto cameraInput = (sptr<CameraInput>&)input;

    if (cameraInput->GetClosedelayedState()) {
        CameraManager::GetInstance()->UnregisterTimeforDevice(cameraInput->cameraIDforcloseDelayed_);
        cameraInput->SetClosedelayedState(false);
    }

    CHECK_RETURN_RET_ELOG(!cameraInput->GetCameraDeviceInfo(), ServiceToCameraError(CAMERA_DEVICE_CLOSED),
        "CaptureSession::AddInput GetCameraDeviceInfo is nullptr");
    CameraPosition position = cameraInput->GetCameraDeviceInfo()->GetPosition();
    bool positionCondition = position == CameraPosition::CAMERA_POSITION_FRONT
        || position == CameraPosition::CAMERA_POSITION_FOLD_INNER;
    CameraManager::GetInstance()->SetControlCenterPositionCondition(positionCondition);

    errCode = captureSession->AddInput(((sptr<CameraInput>&)input)->GetCameraDevice());
    CHECK_RETURN_RET_ELOG(
        errCode != CAMERA_OK, ServiceToCameraError(errCode), "Failed to AddInput!, %{public}d", errCode);
    SetInputDevice(input);
    CheckSpecSearch();
    input->SetMetadataResultProcessor(GetMetadataResultProcessor());
    UpdateDeviceDeferredability();
    FindTagId();
    CreateCameraAbilityContainer();
    return ServiceToCameraError(errCode);
}

void CaptureSession::UpdateDeviceDeferredability()
{
    MEDIA_DEBUG_LOG("UpdateDeviceDeferredability begin.");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_ELOG(inputDevice == nullptr, "CaptureSession::UpdateDeviceDeferredability inputDevice is nullptr");
    auto deviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_ELOG(deviceInfo == nullptr, "CaptureSession::UpdateDeviceDeferredability deviceInfo is nullptr");
    deviceInfo->modeDeferredType_ = {};
    camera_metadata_item_t item;
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_ELOG(metadata == nullptr, "UpdateDeviceDeferredability camera metadata is null");
    int32_t ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_DEFERRED_IMAGE_DELIVERY, &item);
    CHECK_RETURN(ret != CAM_META_SUCCESS);
    MEDIA_DEBUG_LOG("UpdateDeviceDeferredability get ret: %{public}d item: %{public}d count: %{public}d",
        ret, item.item, item.count);
    for (uint32_t i = 0; i < item.count; i++) {
        if (i % DEFERRED_MODE_DATA_SIZE == 0) {
            MEDIA_DEBUG_LOG("UpdateDeviceDeferredability mode index:%{public}d, deferredType:%{public}d",
                item.data.u8[i], item.data.u8[i + 1]);
            deviceInfo->modeDeferredType_[item.data.u8[i]] =
                static_cast<DeferredDeliveryImageType>(item.data.u8[i + 1]);
        }
    }

    deviceInfo->ClearModeVideoDeferredType();
    ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_AUTO_DEFERRED_VIDEO_ENHANCE, &item);
    CHECK_RETURN(ret != CAM_META_SUCCESS);
    MEDIA_DEBUG_LOG("UpdateDeviceDeferredability get video ret: %{public}d video item: %{public}d count: %{public}d",
        ret, item.item, item.count);
    for (uint32_t i = 0; i + 1 < item.count; i++) {
        if (i % DEFERRED_MODE_DATA_SIZE == 0) {
            MEDIA_DEBUG_LOG("UpdateDeviceDeferredability mode index:%{public}d, video deferredType:%{public}d",
                item.data.u8[i], item.data.u8[i + 1]);
            deviceInfo->InsertModeVideoDeferredType(item.data.u8[i], item.data.u8[i + 1]);
        }
    }
}

void CaptureSession::FindTagId()
{
    MEDIA_INFO_LOG("Enter Into CaptureSession::FindTagId");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN(inputDevice == nullptr);
    MEDIA_DEBUG_LOG("CaptureSession::FindTagId inputDevice not nullptr");
    std::vector<vendorTag_t> vendorTagInfos;
    sptr<CameraInput> camInput = (sptr<CameraInput>&)inputDevice;
    int32_t ret = camInput->GetCameraAllVendorTags(vendorTagInfos);
    CHECK_RETURN_ELOG(ret != CAMERA_OK, "Failed to GetCameraAllVendorTags");
    for (auto info : vendorTagInfos) {
        CHECK_CONTINUE(info.tagName == nullptr);
        if (strcmp(info.tagName, "hwSensorName") == 0) {
            HAL_CUSTOM_SENSOR_MODULE_TYPE = info.tagId;
        } else if (strcmp(info.tagName, "lensFocusDistance") == 0) {
            HAL_CUSTOM_LENS_FOCUS_DISTANCE = info.tagId;
        } else if (strcmp(info.tagName, "sensorSensitivity") == 0) {
            HAL_CUSTOM_SENSOR_SENSITIVITY = info.tagId;
        } else if (strcmp(info.tagName, "cameraLaserData") == 0) {
            HAL_CUSTOM_LASER_DATA = info.tagId;
        } else if (strcmp(info.tagName, "cameraArMode") == 0) {
            HAL_CUSTOM_AR_MODE = info.tagId;
        }
    }
}

bool CaptureSession::CheckFrameRateRangeWithCurrentFps(int32_t curMinFps, int32_t curMaxFps,
                                                       int32_t minFps, int32_t maxFps)
{
    CHECK_RETURN_RET_ELOG(
        minFps == 0 || curMinFps == 0, false, "CaptureSession::CheckFrameRateRangeWithCurrentFps can not set zero!");
    bool isRangedFps = curMinFps == curMaxFps && minFps == maxFps &&
        (minFps % curMinFps == 0 || curMinFps % minFps == 0);
    if (isRangedFps) {
        return true;
    } else if (curMinFps != curMaxFps && curMinFps == minFps && curMaxFps == maxFps) {
        return true;
    }
    MEDIA_WARNING_LOG("CaptureSession::CheckFrameRateRangeWithCurrentFps check is not pass!");
    return false;
}

sptr<CaptureOutput> CaptureSession::GetMetaOutput()
{
    MEDIA_DEBUG_LOG("CaptureSession::GetMetadataOutput metaOuput(%{public}d)", metaOutput_ != nullptr);
    return metaOutput_;
}

int32_t CaptureSession::ConfigurePreviewOutput(sptr<CaptureOutput>& output)
{
    MEDIA_INFO_LOG("CaptureSession::ConfigurePreviewOutput enter");
    auto previewProfile = output->GetPreviewProfile();
    if (output->IsTagSetted(CaptureOutput::DYNAMIC_PROFILE)) {
        CHECK_RETURN_RET_ELOG(previewProfile != nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
            "CaptureSession::ConfigurePreviewOutput previewProfile is not null, is that output in use?");
        // LCOV_EXCL_START
        auto preconfigPreviewProfile = GetPreconfigPreviewProfile();
        CHECK_RETURN_RET_ELOG(preconfigPreviewProfile == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
            "CaptureSession::ConfigurePreviewOutput preconfigPreviewProfile is nullptr");
        output->SetPreviewProfile(*preconfigPreviewProfile);
        int32_t res = output->CreateStream();
        CHECK_RETURN_RET_ELOG(res != CameraErrorCode::SUCCESS, res,
            "CaptureSession::ConfigurePreviewOutput createStream from preconfig fail! %{public}d", res);
        MEDIA_INFO_LOG("CaptureSession::ConfigurePreviewOutput createStream from preconfig success");
        previewProfile_ = *preconfigPreviewProfile;
        // LCOV_EXCL_STOP
    } else {
        previewProfile_ = *previewProfile;
    }
    SetGuessMode(SceneMode::CAPTURE);
    return CameraErrorCode::SUCCESS;
}

std::shared_ptr<Profile> CaptureSession::GetMaxSizePhotoProfile(ProfileSizeRatio sizeRatio)
{
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET(inputDevice == nullptr, nullptr);
    auto cameraInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET(cameraInfo == nullptr, nullptr);
    // Non-foldable devices filter out physical lenses.
    CHECK_RETURN_RET(cameraInfo->GetCameraFoldScreenType() == CAMERA_FOLDSCREEN_UNSPECIFIED &&
            cameraInfo->GetCameraType() != CAMERA_TYPE_DEFAULT,
        nullptr);
    SceneMode sceneMode = GetMode();
    if (sceneMode == SceneMode::CAPTURE) {
        auto it = cameraInfo->modePhotoProfiles_.find(SceneMode::CAPTURE);
        CHECK_RETURN_RET(it == cameraInfo->modePhotoProfiles_.end(), nullptr);
        float photoRatioValue = GetTargetRatio(sizeRatio, RATIO_VALUE_4_3);
        return cameraInfo->GetMaxSizeProfile<Profile>(it->second, photoRatioValue, CameraFormat::CAMERA_FORMAT_JPEG);
    } else if (sceneMode == SceneMode::VIDEO) {
        auto it = cameraInfo->modePhotoProfiles_.find(SceneMode::VIDEO);
        CHECK_RETURN_RET(it == cameraInfo->modePhotoProfiles_.end(), nullptr);
        float photoRatioValue = GetTargetRatio(sizeRatio, RATIO_VALUE_16_9);
        return cameraInfo->GetMaxSizeProfile<Profile>(it->second, photoRatioValue, CameraFormat::CAMERA_FORMAT_JPEG);
    } else {
        return nullptr;
    }
    return nullptr;
}
std::shared_ptr<Profile> CaptureSession::GetPreconfigPreviewProfile()
{
    auto preconfigProfiles = GetPreconfigProfiles();
    CHECK_RETURN_RET_ELOG(preconfigProfiles == nullptr, nullptr,
        "CaptureSession::GetPreconfigPreviewProfile preconfigProfiles is nullptr");
    return std::make_shared<Profile>(preconfigProfiles->previewProfile);
}

std::shared_ptr<Profile> CaptureSession::GetPreconfigPhotoProfile()
{
    auto preconfigProfiles = GetPreconfigProfiles();
    CHECK_RETURN_RET_ELOG(
        preconfigProfiles == nullptr, nullptr, "CaptureSession::GetPreconfigPhotoProfile preconfigProfiles is nullptr");
    if (preconfigProfiles->photoProfile.sizeFollowSensorMax_) {
        auto maxSizePhotoProfile = GetMaxSizePhotoProfile(preconfigProfiles->photoProfile.sizeRatio_);
        CHECK_RETURN_RET_ELOG(maxSizePhotoProfile == nullptr, nullptr,
            "CaptureSession::GetPreconfigPhotoProfile maxSizePhotoProfile is null");
        MEDIA_INFO_LOG("CaptureSession::GetPreconfigPhotoProfile preconfig maxSizePhotoProfile %{public}dx%{public}d "
                       ",format:%{public}d",
            maxSizePhotoProfile->size_.width, maxSizePhotoProfile->size_.height, maxSizePhotoProfile->format_);
        return maxSizePhotoProfile;
    }
    return std::make_shared<Profile>(preconfigProfiles->photoProfile);
}

std::shared_ptr<VideoProfile> CaptureSession::GetPreconfigVideoProfile()
{
    auto preconfigProfiles = GetPreconfigProfiles();
    CHECK_RETURN_RET_ELOG(
        preconfigProfiles == nullptr, nullptr, "CaptureSession::GetPreconfigVideoProfile preconfigProfiles is nullptr");
    return std::make_shared<VideoProfile>(preconfigProfiles->videoProfile);
}

int32_t CaptureSession::ConfigurePhotoOutput(sptr<CaptureOutput>& output)
{
    MEDIA_INFO_LOG("CaptureSession::ConfigurePhotoOutput enter");
    auto photoProfile = output->GetPhotoProfile();
    if (output->IsTagSetted(CaptureOutput::DYNAMIC_PROFILE)) {
        CHECK_RETURN_RET_ELOG(photoProfile != nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
            "CaptureSession::ConfigurePhotoOutput photoProfile is not null, is that output in use?");
        // LCOV_EXCL_START
        auto preconfigPhotoProfile = GetPreconfigPhotoProfile();
        CHECK_RETURN_RET_ELOG(preconfigPhotoProfile == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
            "CaptureSession::ConfigurePhotoOutput preconfigPhotoProfile is null");
        output->SetPhotoProfile(*preconfigPhotoProfile);
        int32_t res = output->CreateStream();
        CHECK_RETURN_RET_ELOG(res != CameraErrorCode::SUCCESS, res,
            "CaptureSession::ConfigurePhotoOutput createStream from preconfig fail! %{public}d", res);
        MEDIA_INFO_LOG("CaptureSession::ConfigurePhotoOutput createStream from preconfig success");
        photoProfile_ = *preconfigPhotoProfile;
        // LCOV_EXCL_STOP
    } else {
        photoProfile_ = *photoProfile;
    }
    SetGuessMode(SceneMode::CAPTURE);
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::ConfigureVideoOutput(sptr<CaptureOutput>& output)
{
    MEDIA_INFO_LOG("CaptureSession::ConfigureVideoOutput enter");
    auto videoProfile = output->GetVideoProfile();
    if (output->IsTagSetted(CaptureOutput::DYNAMIC_PROFILE)) {
        CHECK_RETURN_RET_ELOG(videoProfile != nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
            "CaptureSession::ConfigureVideoOutput videoProfile is not null, is that output in use?");
        // LCOV_EXCL_START
        auto preconfigVideoProfile = GetPreconfigVideoProfile();
        CHECK_RETURN_RET_ELOG(preconfigVideoProfile == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
            "CaptureSession::ConfigureVideoOutput preconfigVideoProfile is nullptr");
        videoProfile = preconfigVideoProfile;
        output->SetVideoProfile(*preconfigVideoProfile);
        int32_t res = output->CreateStream();
        CHECK_RETURN_RET_ELOG(res != CameraErrorCode::SUCCESS, res,
            "CaptureSession::ConfigureVideoOutput createStream from preconfig fail! %{public}d", res);
        MEDIA_INFO_LOG("CaptureSession::ConfigureVideoOutput createStream from preconfig success");
        // LCOV_EXCL_STOP
    }
    std::vector<int32_t> frameRateRange = videoProfile->GetFrameRates();
    const size_t minFpsRangeSize = 2;
    if (frameRateRange.size() >= minFpsRangeSize) {
        SetFrameRateRange(frameRateRange);
    }
    if (output != nullptr) {
        sptr<VideoOutput> videoOutput = static_cast<VideoOutput*>(output.GetRefPtr());
        bool isSetRange = videoOutput && (frameRateRange.size() >= minFpsRangeSize);
        if (isSetRange) {
            videoOutput->SetFrameRateRange(frameRateRange[0], frameRateRange[1]);
        }
    }
    SetGuessMode(SceneMode::VIDEO);
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::ConfigureMovieFileOutput(sptr<CaptureOutput>& output)
{
#ifdef CAMERA_FRAMEWORK_FEATURE_MEDIA_STREAM
    MEDIA_INFO_LOG("CaptureSession::ConfigureMovieFileOutput enter");
    auto videoProfile = output->GetVideoProfile();
    std::vector<int32_t> frameRateRange = videoProfile->GetFrameRates();
    const size_t minFpsRangeSize = 2;
    if (frameRateRange.size() >= minFpsRangeSize) {
        SetFrameRateRange(frameRateRange);
    }
    if (output != nullptr) {
        sptr<MovieFileOutput> movieFileOutput = static_cast<MovieFileOutput*>(output.GetRefPtr());
        if (movieFileOutput && (frameRateRange.size() >= minFpsRangeSize)) {
            movieFileOutput->SetFrameRateRange(frameRateRange[0], frameRateRange[1]);
        }
    }
    SetGuessMode(SceneMode::CINEMATIC_VIDEO);
#endif
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::ConfigureUnifyMovieFileOutput(sptr<CaptureOutput>& output)
{
#ifdef CAMERA_MOVIE_FILE
    SetGuessMode(SceneMode::VIDEO);
    auto videoProfile = output->GetVideoProfile();
    auto frameRateRange = videoProfile->GetFrameRates();
    if (frameRateRange.size() >= 2) { // 2 is range min size
        SetFrameRateRange(videoProfile->GetFrameRates());
    }
#endif
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::ConfigureOutput(sptr<CaptureOutput>& output)
{
    MEDIA_DEBUG_LOG("Enter Into CaptureSession::ConfigureOutput");
    output->SetSession(this);
    auto type = output->GetOutputType();
    MEDIA_DEBUG_LOG("CaptureSession::ConfigureOutput outputType is:%{public}d", type);
    switch (type) {
        case CAPTURE_OUTPUT_TYPE_PREVIEW:
            return ConfigurePreviewOutput(output);
        case CAPTURE_OUTPUT_TYPE_PHOTO:
            return ConfigurePhotoOutput(output);
        case CAPTURE_OUTPUT_TYPE_VIDEO:
            return ConfigureVideoOutput(output);
#ifdef CAMERA_FRAMEWORK_FEATURE_MEDIA_STREAM
        case CAPTURE_OUTPUT_TYPE_MOVIE_FILE:
            return ConfigureMovieFileOutput(output);
#endif
#ifdef CAMERA_MOVIE_FILE
        case CAPTURE_OUTPUT_TYPE_UNIFY_MOVIE_FILE:
            return ConfigureUnifyMovieFileOutput(output);
#endif
        default:
            // do nothing.
            break;
    }
    return CameraErrorCode::SUCCESS;
}

void CaptureSession::InsertOutputIntoSet(sptr<CaptureOutput>& output)
{
    std::lock_guard<std::mutex> lock(captureOutputSetsMutex_);
    auto it = captureOutputSets_.begin();
    while (it != captureOutputSets_.end()) {
        if (*it == nullptr) {
            it = captureOutputSets_.erase(it);
        } else if (*it == output) {
            break;
        } else {
            ++it;
        }
    }
    CHECK_RETURN(it != captureOutputSets_.end());
    captureOutputSets_.insert(output);
}

int32_t CaptureSession::AddOutput(sptr<CaptureOutput>& output)
{
    return AddOutput(output, true);
}

int32_t CaptureSession::AddOutput(sptr<CaptureOutput>& output, bool isVerifyOutput)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter Into CaptureSession::AddOutput");
    if (!IsSessionConfiged()) {
        HILOG_COMM_ERROR("CaptureSession::AddOutput operation Not allowed!");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }
    if (output == nullptr) {
        HILOG_COMM_ERROR("CaptureSession::AddOutput output is null");
        return ServiceToCameraError(CAMERA_INVALID_ARG);
    }

    CHECK_RETURN_RET_ELOG(ConfigureOutput(output) != CameraErrorCode::SUCCESS, CameraErrorCode::SERVICE_FATL_ERROR,
        "CaptureSession::AddOutput ConfigureOutput fail!");
    CHECK_EXECUTE(output->GetOutputType() == CAPTURE_OUTPUT_TYPE_METADATA, metaOutput_ = output);
    CHECK_RETURN_RET_ELOG(isVerifyOutput && !CanAddOutput(output), ServiceToCameraError(CAMERA_INVALID_ARG),
        "CanAddOutput check failed!");
    auto captureSession = GetCaptureSession();
    CHECK_RETURN_RET_ELOG(captureSession == nullptr, ServiceToCameraError(CAMERA_UNKNOWN_ERROR),
        "CaptureSession::AddOutput() captureSession is nullptr");
    int32_t ret = AdaptOutputVideoHighFrameRate(output, captureSession);
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, ServiceToCameraError(CAMERA_INVALID_ARG),
        "CaptureSession::AddOutput An Error in the AdaptOutputVideoHighFrameRate");
    ret = AddOutputInner(captureSession, output);
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, ServiceToCameraError(CAMERA_UNKNOWN_ERROR),
        "CaptureSession::AddOutput An Error in the AddOutputInner");
    InsertOutputIntoSet(output);
    uint32_t apiCompatibleVersion = CameraApiVersion::GetApiVersion();
    sptr<IStreamCommon> stream = output->GetStream(); // UnifyMovieOutput GetStream is nullptr
    if (output->GetOutputType() == CAPTURE_OUTPUT_TYPE_PREVIEW) {
        IStreamRepeat* repeatStream = static_cast<IStreamRepeat*>(stream.GetRefPtr());
        if (repeatStream) {
            int32_t errItemCode = repeatStream->SetCameraApi(apiCompatibleVersion);
            MEDIA_ERR_LOG("SetCameraApi!, errCode: %{public}d", errItemCode);
        } else {
            MEDIA_ERR_LOG("PreviewOutput::SetCameraApi() repeatStream is nullptr");
        }
    }
    if (isVerifyOutput) {
        CreateCameraAbilityContainer();
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::AddOutputInner(sptr<ICaptureSession>& captureSession, sptr<CaptureOutput>& output)
{
#ifdef CAMERA_MOVIE_FILE
    if (!output->IsMultiStreamOutput()) {
#endif
        int32_t errCode = CAMERA_UNKNOWN_ERROR;
        CHECK_EXECUTE(output->GetStream() != nullptr,
            errCode = captureSession->AddOutput(output->GetStreamType(), output->GetStream()->AsObject()));
        CHECK_EXECUTE(output->GetOutputType() == CAPTURE_OUTPUT_TYPE_PHOTO, photoOutput_ = output);
        MEDIA_INFO_LOG("CaptureSession::AddOutputInner StreamType = %{public}d", output->GetStreamType());
        CHECK_RETURN_RET_ELOG(
            errCode != CAMERA_OK, ServiceToCameraError(errCode), "Failed to AddOutput!, %{public}d", errCode);
#ifdef CAMERA_MOVIE_FILE
    } else {
        int32_t opMode = 0;
        auto it = g_fwToMetaSupportedMode_.find(GetFeaturesMode().GetFeaturedMode());
        if (it != g_fwToMetaSupportedMode_.end()) {
            opMode = it->second;
        }
        sptr<UnifyMovieFileOutput> unifyMovieFileOutput = static_cast<UnifyMovieFileOutput*>(output.GetRefPtr());
        CHECK_RETURN_RET_ELOG(unifyMovieFileOutput == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
            "CaptureSession::AddOutputInner unifyMovieFileOutput is nullptr");
        MEDIA_INFO_LOG("CaptureSession::AddOutputInner, opMode:%{public}d", opMode);
        auto proxy = unifyMovieFileOutput->GetMovieFileOutputProxy();
        CHECK_RETURN_RET_ELOG(proxy == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
            "CaptureSession::AddOutputInner movieFileOutput proxy is nullptr!");
        captureSession->AddMultiStreamOutput(proxy->AsObject(), opMode);
    }
#endif
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::AdaptOutputVideoHighFrameRate(sptr<CaptureOutput>& output,
    sptr<ICaptureSession>& captureSession)
{
    MEDIA_INFO_LOG("Enter Into CaptureSession::AdaptOutputVideoHighFrameRate");
    CHECK_RETURN_RET_ELOG(output == nullptr, CameraErrorCode::INVALID_ARGUMENT,
        "CaptureSession::AdaptOutputVideoHighFrameRate output is null");
    CHECK_RETURN_RET_ELOG(captureSession == nullptr, CameraErrorCode::INVALID_ARGUMENT,
        "CaptureSession::AdaptOutputVideoHighFrameRate() captureSession is nullptr");
    bool isOutputVideo = GetMode() == SceneMode::VIDEO && output->IsVideoProfileType();
    if (isOutputVideo) {
        // LCOV_EXCL_START
        auto videoProfile = output->GetVideoProfile();
        CHECK_RETURN_RET_ELOG(!videoProfile, CameraErrorCode::INVALID_ARGUMENT,
            "CaptureSession::AdaptOutputVideoHighFrameRate videoProfile is nullptr");
        std::vector<int32_t> videoFrameRates = videoProfile->GetFrameRates();
        CHECK_RETURN_RET_ELOG(videoFrameRates.empty(), CameraErrorCode::INVALID_ARGUMENT, "videoFrameRates is empty!");
        bool isSetMode = videoFrameRates[0] == FRAMERATE_120 || videoFrameRates[0] == FRAMERATE_240;
        if (isSetMode) {
            captureSession->SetFeatureMode(SceneMode::HIGH_FRAME_RATE);
            SetMode(SceneMode::HIGH_FRAME_RATE);
            return CameraErrorCode::SUCCESS;
        }
        // LCOV_EXCL_STOP
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::AddSecureOutput(sptr<CaptureOutput> &output)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("Enter Into SecureCameraSession::AddSecureOutput");
    CHECK_RETURN_RET(currentMode_ != SceneMode::SECURE, CAMERA_OPERATION_NOT_ALLOWED);
    CHECK_RETURN_RET_ELOG(!IsSessionConfiged() || output == nullptr || isSetSecureOutput_, CAMERA_OPERATION_NOT_ALLOWED,
        "SecureCameraSession::AddSecureOutput operation is Not allowed!");
    sptr<IStreamCommon> stream = output->GetStream();
    IStreamRepeat* repeatStream = static_cast<IStreamRepeat*>(stream.GetRefPtr());
    repeatStream->EnableSecure(true);
    isSetSecureOutput_ = true;
    return CAMERA_OK;
}

bool CaptureSession::CanAddOutput(sptr<CaptureOutput>& output)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter Into CaptureSession::CanAddOutput");
    CHECK_RETURN_RET_ELOG(
        !IsSessionConfiged() || output == nullptr, false, "CaptureSession::CanAddOutput operation Not allowed!");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), false,
        "CaptureSession::CanAddOutput Failed inputDevice is nullptr");
    auto outputType = output->GetOutputType();
    std::shared_ptr<Profile> profilePtr = nullptr;
    switch (outputType) {
        case CAPTURE_OUTPUT_TYPE_PREVIEW:
            profilePtr = output->IsTagSetted(CaptureOutput::DYNAMIC_PROFILE) ? GetPreconfigPreviewProfile()
                                                                             : output->GetPreviewProfile();
            break;
        case CAPTURE_OUTPUT_TYPE_PHOTO:
            profilePtr = output->IsTagSetted(CaptureOutput::DYNAMIC_PROFILE) ? GetPreconfigPhotoProfile()
                                                                             : output->GetPhotoProfile();
            break;
        case CAPTURE_OUTPUT_TYPE_VIDEO:
            profilePtr = output->IsTagSetted(CaptureOutput::DYNAMIC_PROFILE) ? GetPreconfigVideoProfile()
                                                                             : output->GetVideoProfile();
            break;
#ifdef CAMERA_MOVIE_FILE
        case CAPTURE_OUTPUT_TYPE_MOVIE_FILE:
        // fall-through
        case CAPTURE_OUTPUT_TYPE_UNIFY_MOVIE_FILE:
            profilePtr = output->GetVideoProfile();
            break;
#endif
        case CAPTURE_OUTPUT_TYPE_DEPTH_DATA:
            profilePtr = output->GetDepthProfile();
            break;
        case CAPTURE_OUTPUT_TYPE_METADATA:
            return true;
        default:
            MEDIA_ERR_LOG("CaptureSession::CanAddOutput CaptureOutputType unknown");
            return false;
    }
    return profilePtr == nullptr ? false : ValidateOutputProfile(*profilePtr, outputType);
}

int32_t CaptureSession::RemoveInput(sptr<CaptureInput>& input)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter Into CaptureSession::RemoveInput");
    CHECK_RETURN_RET_ELOG(!IsSessionConfiged(), CameraErrorCode::OPERATION_NOT_ALLOWED,
        "CaptureSession::RemoveInput operation Not allowed!");

    CHECK_RETURN_RET_ELOG(
        input == nullptr, ServiceToCameraError(CAMERA_INVALID_ARG), "CaptureSession::RemoveInput input is null");
    auto device = ((sptr<CameraInput>&)input)->GetCameraDevice();
    CHECK_RETURN_RET_ELOG(
        device == nullptr, ServiceToCameraError(CAMERA_INVALID_ARG), "CaptureSession::RemoveInput device is null");
    supportSpecSearch_ = false;
    {
        std::lock_guard<std::mutex> lock(abilityContainerMutex_);
        cameraAbilityContainer_ = nullptr;
    }
    SetInputDevice(nullptr);
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    auto captureSession = GetCaptureSession();
    if (captureSession) {
        errCode = captureSession->RemoveInput(device);
        auto deviceInfo = input->GetCameraDeviceInfo();
        if (deviceInfo != nullptr) {
            deviceInfo->ResetMetadata();
        }
        CHECK_PRINT_ELOG(errCode != CAMERA_OK, "Failed to RemoveInput!, %{public}d", errCode);
    } else {
        MEDIA_ERR_LOG("CaptureSession::RemoveInput() captureSession is nullptr");
    }
    return ServiceToCameraError(errCode);
}

void CaptureSession::RemoveOutputFromSet(sptr<CaptureOutput>& output)
{
    std::lock_guard<std::mutex> lock(captureOutputSetsMutex_);
    auto it = captureOutputSets_.begin();
    while (it != captureOutputSets_.end()) {
        if (*it == nullptr) {
            it = captureOutputSets_.erase(it);
        } else if (*it == output) {
            captureOutputSets_.erase(it);
            return;
        } else {
            ++it;
        }
    }
}

int32_t CaptureSession::RemoveOutput(sptr<CaptureOutput>& output)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter Into CaptureSession::RemoveOutput");
    CHECK_RETURN_RET_ELOG(!IsSessionConfiged(), CameraErrorCode::OPERATION_NOT_ALLOWED,
        "CaptureSession::RemoveOutput operation Not allowed!");
    CHECK_RETURN_RET_ELOG(
        output == nullptr, ServiceToCameraError(CAMERA_INVALID_ARG), "CaptureSession::RemoveOutput output is null");
    output->SetSession(nullptr);
    if (output->GetOutputType() == CAPTURE_OUTPUT_TYPE_METADATA) {
        sptr<MetadataOutput> metaOutput = static_cast<MetadataOutput*>(output.GetRefPtr());
        CHECK_RETURN_RET_ELOG(
            !metaOutput, ServiceToCameraError(CAMERA_INVALID_ARG), "CaptureSession::metaOutput is null");
        std::vector<MetadataObjectType> metadataObjectTypes = {};
        MEDIA_DEBUG_LOG("CaptureSession::RemoveOutput SetCapturingMetadataObjectTypes off");
        metaOutput->Stop();
        MEDIA_DEBUG_LOG("CaptureSession::RemoveOutput remove metaOutput");
        return ServiceToCameraError(CAMERA_OK);
    }
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    auto captureSession = GetCaptureSession();
    if (captureSession) {
        bool isSetOfflinePhoto = output->GetOutputType() == CAPTURE_OUTPUT_TYPE_PHOTO && photoOutput_ &&
            ((sptr<PhotoOutput>&)photoOutput_)->IsHasEnableOfflinePhoto();
        if (isSetOfflinePhoto) {
            ((sptr<PhotoOutput>&)photoOutput_)->SetSwitchOfflinePhotoOutput(true);
        }
#ifdef CAMERA_MOVIE_FILE
        if (!output->IsMultiStreamOutput()) {
#endif
            CHECK_EXECUTE(output->GetStream() != nullptr,
                errCode = captureSession->RemoveOutput(output->GetStreamType(), output->GetStream()->AsObject()));
            CHECK_PRINT_ELOG(errCode != CAMERA_OK, "Failed to RemoveOutput!, %{public}d", errCode);
#ifdef CAMERA_MOVIE_FILE
        } else {
            sptr<UnifyMovieFileOutput> unifyMovieFileOutput = static_cast<UnifyMovieFileOutput*>(output.GetRefPtr());
            CHECK_RETURN_RET_ELOG(unifyMovieFileOutput == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
                "CaptureSession::RemoveOutput unifyMovieFileOutput is nullptr");
            auto proxy = unifyMovieFileOutput->GetMovieFileOutputProxy();
            CHECK_RETURN_RET_ELOG(proxy == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
                "CaptureSession::RemoveOutput movieFileOutput proxy is nullptr!");
            captureSession->RemoveMultiStreamOutput(proxy->AsObject());
        }
#endif
    } else {
        MEDIA_ERR_LOG("CaptureSession::RemoveOutput() captureSession is nullptr");
    }
    RemoveOutputFromSet(output);
    if (output->IsTagSetted(CaptureOutput::DYNAMIC_PROFILE)) {
        output->ClearProfiles();
    }
    return ServiceToCameraError(errCode);
}

int32_t CaptureSession::Start()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter Into CaptureSession::Start");
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    CHECK_RETURN_RET_ELOG(
        !IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG, "CaptureSession::Start Session not Commited");
    auto captureSession = GetCaptureSession();
    if (captureSession) {
        errCode = captureSession->Start();
        CHECK_PRINT_ELOG(errCode != CAMERA_OK, "Failed to Start capture session!, %{public}d", errCode);
    } else {
        MEDIA_ERR_LOG("CaptureSession::Start() captureSession is nullptr");
    }
    if (GetMetaOutput()) {
        sptr<MetadataOutput> metaOutput = static_cast<MetadataOutput*>(GetMetaOutput().GetRefPtr());
        CHECK_RETURN_RET_ELOG(!metaOutput, ServiceToCameraError(errCode), "CaptureSession::metaOutput is null");
        metaOutput->Start();
    }
    return ServiceToCameraError(errCode);
}

int32_t CaptureSession::Stop()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter Into CaptureSession::Stop");
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    auto captureSession = GetCaptureSession();
    if (captureSession) {
        errCode = captureSession->Stop();
        CHECK_PRINT_ELOG(errCode != CAMERA_OK, "Failed to Stop capture session!, %{public}d", errCode);
    } else {
        MEDIA_ERR_LOG("CaptureSession::Stop() captureSession is nullptr");
    }
    return ServiceToCameraError(errCode);
}

int32_t CaptureSession::Release()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter Into CaptureSession::Release");
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    auto captureSession = GetCaptureSession();
    if (captureSession) {
        errCode = captureSession->Release();
        MEDIA_DEBUG_LOG("Release capture session, %{public}d", errCode);
    } else {
        MEDIA_ERR_LOG("CaptureSession::Release() captureSession is nullptr");
    }
    SetInputDevice(nullptr);
    SessionRemoveDeathRecipient();
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    captureSessionCallback_ = nullptr;
    pressureStatusCallback_ = nullptr;
    appCallback_ = nullptr;
    appPressureCallback_ = nullptr;
    exposureCallback_ = nullptr;
    focusCallback_ = nullptr;
    macroStatusCallback_ = nullptr;
    moonCaptureBoostStatusCallback_ = nullptr;
    smoothZoomCallback_ = nullptr;
    abilityCallback_ = nullptr;
    arCallback_ = nullptr;
    effectSuggestionCallback_ = nullptr;
    cameraAbilityContainer_ = nullptr;
    foldStatusCallback_ = nullptr;
    apertureEffectChangeCallback_ = nullptr;
    return ServiceToCameraError(errCode);
}

void CaptureSession::SetCallback(std::shared_ptr<SessionCallback> callback)
{
    CHECK_PRINT_ELOG(callback == nullptr, "CaptureSession::SetCallback Unregistering application callback!");
    int32_t errorCode = CAMERA_OK;
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    appCallback_ = callback;
    auto captureSession = GetCaptureSession();
    bool isSetCallback = appCallback_ != nullptr && captureSession != nullptr;
    if (isSetCallback) {
        if (captureSessionCallback_ == nullptr) {
            captureSessionCallback_ = new (std::nothrow) CaptureSessionCallback(this);
            CHECK_RETURN_ELOG(captureSessionCallback_ == nullptr, "failed to new captureSessionCallback_!");
        }
        if (captureSession) {
            errorCode = captureSession->SetCallback(captureSessionCallback_);
            if (errorCode != CAMERA_OK) {
                MEDIA_ERR_LOG(
                    "CaptureSession::SetCallback: Failed to register callback, errorCode: %{public}d", errorCode);
                captureSessionCallback_ = nullptr;
                appCallback_ = nullptr;
            }
        } else {
            MEDIA_ERR_LOG("CaptureSession::SetCallback captureSession is nullptr");
        }
    }
    return;
}

void CaptureSession::SetIsoInfoCallback(std::shared_ptr<IsoInfoSyncCallback> callback)
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    isoInfoSyncCallback_ = callback;
    // LCOV_EXCL_STOP
}

void CaptureSession::SetPressureCallback(std::shared_ptr<PressureCallback> callback)
{
    CHECK_PRINT_ELOG(callback == nullptr, "CaptureSession::SetPressureCallback Unregistering application callback!");
    int32_t errorCode = CAMERA_OK;
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    appPressureCallback_ = callback;
    auto captureSession = GetCaptureSession();
    if (appPressureCallback_ != nullptr && captureSession != nullptr) {
        if (pressureStatusCallback_ == nullptr) {
            pressureStatusCallback_ = new (std::nothrow) PressureStatusCallback(this);
            CHECK_RETURN_ELOG(pressureStatusCallback_ == nullptr, "failed to new pressureStatusCallback_!");
        }
        errorCode = captureSession->SetPressureCallback(pressureStatusCallback_);
        if (errorCode != CAMERA_OK) {
            MEDIA_ERR_LOG(
                "CaptureSession::SetPressureCallback: Failed to register callback, errorCode: %{public}d",
                errorCode);
            pressureStatusCallback_ = nullptr;
            appPressureCallback_ = nullptr;
        }
    }
    return;
}

void CaptureSession::UnSetPressureCallback()
{
    MEDIA_INFO_LOG("CaptureSession::UnSetPressureCallback");
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    appPressureCallback_ = nullptr;
    auto captureSession = GetCaptureSession();
    CHECK_RETURN_ELOG(captureSession == nullptr, "CaptureSession::UnSetPressureCallback captureSession is nullptr");
    captureSession->UnSetPressureCallback();
}

void CaptureSession::SetControlCenterEffectStatusCallback(std::shared_ptr<ControlCenterEffectCallback> callback)
{
    CHECK_PRINT_ELOG(callback == nullptr, "CaptureSession::SetControlCenterEffectStatusCallback callback is null.");
    int32_t errorCode = CAMERA_OK;
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    appControlCenterEffectStatusCallback_ = callback;
    auto captureSession = GetCaptureSession();
    if (appControlCenterEffectStatusCallback_ != nullptr && captureSession != nullptr) {
        if (controlCenterEffectStatusCallback_ == nullptr) {
            controlCenterEffectStatusCallback_ = new (std::nothrow) ControlCenterEffectStatusCallback(this);
            CHECK_RETURN_ELOG(
                controlCenterEffectStatusCallback_ == nullptr, "failed to new controlCenterEffectStatusCallback_!");
        }
        errorCode = captureSession->SetControlCenterEffectStatusCallback(controlCenterEffectStatusCallback_);
        if (errorCode != CAMERA_OK) {
            MEDIA_ERR_LOG(
                "SetControlCenterEffectStatusCallback: Failed to register callback, errorCode: %{public}d",
                errorCode);
            controlCenterEffectStatusCallback_ = nullptr;
            appControlCenterEffectStatusCallback_ = nullptr;
        }
    }
    return;
}

void CaptureSession::UnSetControlCenterEffectStatusCallback()
{
    MEDIA_INFO_LOG("CaptureSession::UnSetControlCenterEffectStatusCallback");
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    appControlCenterEffectStatusCallback_ = nullptr;
    auto captureSession = GetCaptureSession();
    CHECK_RETURN_ELOG(
        captureSession == nullptr, "CaptureSession::UnSetControlCenterEffectStatusCallback captureSession is nullptr");
    captureSession->UnSetControlCenterEffectStatusCallback();
}

void CaptureSession::SetCameraSwitchRequestCallback(std::shared_ptr<CameraSwitchRequestCallback> callback)
{
    MEDIA_INFO_LOG("CaptureSession::SetCameraSwitchRequestCallback");
    CHECK_PRINT_ELOG(
        callback == nullptr, "CaptureSession::CameraSwitchRequestCallback Unregistering application callback!");
    int32_t errorCode = CAMERA_OK;
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    appSwitchRequestCallback_ = callback;
    auto captureSession = GetCaptureSession();
    if (appSwitchRequestCallback_ != nullptr && captureSession != nullptr) {
        if(cameraSwitchRequestCallback_==nullptr){
        cameraSwitchRequestCallback_ = new (std::nothrow) CameraSwitchSessionCallback(this);
        CHECK_RETURN_ELOG(
            cameraSwitchRequestCallback_ == nullptr, "failed to new cameraSwitchRequestCallback_!");
        }
        errorCode = captureSession->SetCameraSwitchRequestCallback(cameraSwitchRequestCallback_);
                if (errorCode != CAMERA_OK) {
            MEDIA_ERR_LOG(
                "SetCameraSwitchRequestCallback: Failed to register callback, errorCode: %{public}d",
                errorCode);
            appSwitchRequestCallback_ = nullptr;
            cameraSwitchRequestCallback_ = nullptr;
        }
    }
    return;
}

void CaptureSession::UnSetCameraSwitchRequestCallback()
{
    MEDIA_INFO_LOG("CaptureSession::UnSetCameraSwitchRequestCallback");
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    appSwitchRequestCallback_ = nullptr;
    auto captureSession = GetCaptureSession();
    CHECK_RETURN_ELOG(
        captureSession == nullptr, "CaptureSession::UnSetCameraSwitchRequestCallback captureSession is nullptr");
    captureSession->UnSetCameraSwitchRequestCallback();
}

int32_t CaptureSession::SetPreviewRotation(std::string &deviceClass)
{
    int32_t errorCode = CAMERA_OK;
    auto captureSession = GetCaptureSession();
    if (captureSession) {
        errorCode = captureSession->SetPreviewRotation(deviceClass);
        CHECK_PRINT_ELOG(errorCode != CAMERA_OK, "SetPreviewRotation is failed errorCode: %{public}d", errorCode);
    } else {
        MEDIA_ERR_LOG("CaptureSession::SetPreviewRotation captureSession is nullptr");
    }
    return errorCode;
}

std::shared_ptr<SessionCallback> CaptureSession::GetApplicationCallback()
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    return appCallback_;
}

std::shared_ptr<PressureCallback> CaptureSession::GetPressureCallback()
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    return appPressureCallback_;
}

std::shared_ptr<ControlCenterEffectCallback> CaptureSession::GetControlCenterEffectCallback()
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    return appControlCenterEffectStatusCallback_;
}

std::shared_ptr<CameraSwitchRequestCallback> CaptureSession::GetCameraSwitchRequestCallback()
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    return appSwitchRequestCallback_;
}

std::shared_ptr<ExposureCallback> CaptureSession::GetExposureCallback()
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    return exposureCallback_;
}

std::shared_ptr<FocusCallback> CaptureSession::GetFocusCallback()
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    return focusCallback_;
}

std::shared_ptr<MacroStatusCallback> CaptureSession::GetMacroStatusCallback()
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    return macroStatusCallback_;
}

std::shared_ptr<MoonCaptureBoostStatusCallback> CaptureSession::GetMoonCaptureBoostStatusCallback()
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    return moonCaptureBoostStatusCallback_;
}

std::shared_ptr<FeatureDetectionStatusCallback> CaptureSession::GetFeatureDetectionStatusCallback()
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    return featureDetectionStatusCallback_;
}

std::shared_ptr<SmoothZoomCallback> CaptureSession::GetSmoothZoomCallback()
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    return smoothZoomCallback_;
}

std::shared_ptr<ARCallback> CaptureSession::GetARCallback()
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    return arCallback_;
}

int32_t CaptureSession::UpdateSetting(std::shared_ptr<Camera::CameraMetadata> changedMetadata)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(!changedMetadata, CameraErrorCode::INVALID_ARGUMENT,
        "CaptureSession::UpdateSetting changedMetadata is nullptr");
    auto metadataHeader = changedMetadata->get();
    uint32_t count = Camera::GetCameraMetadataItemCount(metadataHeader);
    CHECK_RETURN_RET_ILOG(
        count == 0, CameraErrorCode::SUCCESS, "CaptureSession::UpdateSetting No configuration to update");

    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        !inputDevice, CameraErrorCode::SUCCESS, "CaptureSession::UpdateSetting Failed inputDevice is nullptr");
    auto cameraDeviceObj = ((sptr<CameraInput>&)inputDevice)->GetCameraDevice();
    CHECK_RETURN_RET_ELOG(
        !cameraDeviceObj, CameraErrorCode::SUCCESS, "CaptureSession::UpdateSetting Failed cameraDeviceObj is nullptr");
    int32_t ret = cameraDeviceObj->UpdateSetting(changedMetadata);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, ServiceToCameraError(ret),
        "CaptureSession::UpdateSetting Failed to update settings, errCode = %{public}d", ret);

    std::shared_ptr<Camera::CameraMetadata> baseMetadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(
        baseMetadata == nullptr, CameraErrorCode::SUCCESS, "CaptureSession::UpdateSetting camera metadata is null");
    for (uint32_t index = 0; index < count; index++) {
        camera_metadata_item_t srcItem;
        int ret = OHOS::Camera::GetCameraMetadataItem(metadataHeader, index, &srcItem);
        CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CAMERA_INVALID_ARG,
            "CaptureSession::UpdateSetting Failed to get metadata item at index: %{public}d", index);
        bool status = false;
        uint32_t currentIndex;
        ret = OHOS::Camera::FindCameraMetadataItemIndex(baseMetadata->get(), srcItem.item, &currentIndex);
        if (ret == CAM_META_SUCCESS) {
            status = baseMetadata->updateEntry(srcItem.item, srcItem.data.u8, srcItem.count);
        } else if (ret == CAM_META_ITEM_NOT_FOUND) {
            status = baseMetadata->addEntry(srcItem.item, srcItem.data.u8, srcItem.count);
        }
        CHECK_PRINT_ELOG(
            !status, "CaptureSession::UpdateSetting Failed to add/update metadata item: %{public}d", srcItem.item);
    }
    OnSettingUpdated(changedMetadata);
    return CameraErrorCode::SUCCESS;
}

void CaptureSession::OnSettingUpdated(std::shared_ptr<OHOS::Camera::CameraMetadata> changedMetadata)
{
    std::lock_guard<std::mutex> lock(captureOutputSetsMutex_);
    auto it = captureOutputSets_.begin();
    while (it != captureOutputSets_.end()) {
        auto output = it->promote();
        if (output == nullptr) {
            it = captureOutputSets_.erase(it);
            continue;
        }
        ++it;
        auto filters = output->GetObserverControlTags();
        CHECK_CONTINUE(filters.empty());
        for (auto tag : filters) {
            camera_metadata_item_t item;
            int ret = Camera::FindCameraMetadataItem(changedMetadata->get(), tag, &item);
            bool isNotFindItem = ret != CAM_META_SUCCESS || item.count <= 0;
            CHECK_CONTINUE(isNotFindItem);
            output->OnControlMetadataChanged(tag, item);
        }
    }
}

void CaptureSession::OnResultReceived(std::shared_ptr<OHOS::Camera::CameraMetadata> metadata)
{
    std::lock_guard<std::mutex> lock(captureOutputSetsMutex_);
    auto it = captureOutputSets_.begin();
    while (it != captureOutputSets_.end()) {
        auto output = it->promote();
        if (output == nullptr) {
            it = captureOutputSets_.erase(it);
            continue;
        }
        ++it;
        auto filters = output->GetObserverResultTags();
        CHECK_CONTINUE(filters.empty());
        for (auto tag : filters) {
            camera_metadata_item_t item;
            int ret = Camera::FindCameraMetadataItem(metadata->get(), tag, &item);
            bool isNotFindItem = ret != CAM_META_SUCCESS || item.count <= 0;
            CHECK_CONTINUE(isNotFindItem);
            output->OnResultMetadataChanged(tag, item);
        }
    }
}

void CaptureSession::LockForControl()
{
    changeMetaMutex_.lock();
    MEDIA_DEBUG_LOG("CaptureSession::LockForControl Called");
    changedMetadata_ = std::make_shared<Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
}

int32_t CaptureSession::UnlockForControl()
{
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::UnlockForControl Need to call LockForControl() before UnlockForControl()");
        changeMetaMutex_.unlock();
        return ServiceToCameraError(CAMERA_INVALID_ARG);
    }
    MEDIA_DEBUG_LOG("CaptureSession::UnlockForControl Called");
    UpdateSetting(changedMetadata_);
    changedMetadata_ = nullptr;
    changeMetaMutex_.unlock();
    return CameraErrorCode::SUCCESS;
}

CaptureSession::LockGuardForControl::LockGuardForControl(wptr<CaptureSession> session) : session_(session)
{
    auto spSession = session_.promote();
    CHECK_RETURN_ELOG(spSession == nullptr, "session is nullptr");
    spSession->LockForControl();
}

CaptureSession::LockGuardForControl::~LockGuardForControl()
{
    auto spSession = session_.promote();
    CHECK_RETURN_ELOG(spSession == nullptr, "session is nullptr");
    spSession->UnlockForControl();
}


VideoStabilizationMode CaptureSession::GetActiveVideoStabilizationMode()
{
    sptr<CameraDevice> cameraObj_;
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice, OFF, "CaptureSession::GetActiveVideoStabilizationMode camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(
        !inputDeviceInfo, OFF, "CaptureSession::GetActiveVideoStabilizationMode camera device is null");
    cameraObj_ = inputDeviceInfo;
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj_->GetCachedMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, OFF, "GetActiveVideoStabilizationMode camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &item);
    if (ret == CAM_META_SUCCESS) {
        auto itr = g_metaVideoStabModesMap_.find(static_cast<CameraVideoStabilizationMode>(item.data.u8[0]));
        CHECK_RETURN_RET(itr != g_metaVideoStabModesMap_.end(), itr->second);
    }
    return OFF;
}

int32_t CaptureSession::GetActiveVideoStabilizationMode(VideoStabilizationMode& mode)
{
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::GetActiveVideoStabilizationMode Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice, CameraErrorCode::SUCCESS,
        "CaptureSession::GetActiveVideoStabilizationMode camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(!inputDeviceInfo, CameraErrorCode::SUCCESS,
        "CaptureSession::GetActiveVideoStabilizationMode camera device is null");
    mode = OFF;
    bool isSupported = false;
    sptr<CameraDevice> cameraObj_;
    cameraObj_ = inputDeviceInfo;
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj_->GetCachedMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, CameraErrorCode::SUCCESS, "GetActiveVideoStabilizationMode camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &item);
    if (ret == CAM_META_SUCCESS) {
        auto itr = g_metaVideoStabModesMap_.find(static_cast<CameraVideoStabilizationMode>(item.data.u8[0]));
        if (itr != g_metaVideoStabModesMap_.end()) {
            mode = itr->second;
            isSupported = true;
        }
    }
    CHECK_PRINT_ELOG(!isSupported || ret != CAM_META_SUCCESS,
        "CaptureSession::GetActiveVideoStabilizationMode Failed with return code %{public}d", ret);
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetVideoStabilizationMode(VideoStabilizationMode stabilizationMode)
{
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::SetVideoStabilizationMode Session is not Commited");
    bool isSetMode = (!CameraSecurity::CheckSystemApp()) && (stabilizationMode == VideoStabilizationMode::HIGH);
    if (isSetMode) {
        stabilizationMode = VideoStabilizationMode::AUTO;
    }
    CHECK_RETURN_RET(!IsVideoStabilizationModeSupported(stabilizationMode), CameraErrorCode::OPERATION_NOT_ALLOWED);
    auto itr = g_fwkVideoStabModesMap_.find(stabilizationMode);
    if ((itr == g_fwkVideoStabModesMap_.end())) {
        MEDIA_ERR_LOG("CaptureSession::SetVideoStabilizationMode Mode: %{public}d not supported", stabilizationMode);
        stabilizationMode = OFF;
    }

    uint32_t count = 1;
    uint8_t stabilizationMode_ = stabilizationMode;

    this->LockForControl();
    MEDIA_DEBUG_LOG("CaptureSession::SetVideoStabilizingMode StabilizationMode : %{public}d", stabilizationMode_);
    if (!(this->changedMetadata_->addEntry(OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &stabilizationMode_, count))) {
        MEDIA_DEBUG_LOG("CaptureSession::SetVideoStabilizingMode Failed to set video stabilization mode");
    } else {
        wptr<CaptureSession> weakThis(this);
        AddFunctionToMap(std::to_string(OHOS_CONTROL_VIDEO_STABILIZATION_MODE), [weakThis, stabilizationMode]() {
            auto sharedThis = weakThis.promote();
            CHECK_RETURN_ELOG(!sharedThis, "SetVideoStabilizationMode session is nullptr");
            int32_t retCode = sharedThis->SetVideoStabilizationMode(stabilizationMode);
            CHECK_EXECUTE(retCode != CameraErrorCode::SUCCESS,
                          sharedThis->SetDeviceCapabilityChangeStatus(true));
        });
    }
    int32_t errCode = this->UnlockForControl();
    CHECK_PRINT_DLOG(errCode != CameraErrorCode::SUCCESS,
        "CaptureSession::SetVideoStabilizingMode Failed to set video stabilization mode");
    return CameraErrorCode::SUCCESS;
}

bool CaptureSession::IsVideoStabilizationModeSupported(VideoStabilizationMode stabilizationMode)
{
    CHECK_RETURN_RET((!CameraSecurity::CheckSystemApp()) && (stabilizationMode == VideoStabilizationMode::HIGH), false);
    std::vector<VideoStabilizationMode> stabilizationModes = GetSupportedStabilizationMode();
    if (std::find(stabilizationModes.begin(), stabilizationModes.end(), stabilizationMode) !=
        stabilizationModes.end()) {
        return true;
    }
    return false;
}

int32_t CaptureSession::IsVideoStabilizationModeSupported(VideoStabilizationMode stabilizationMode, bool& isSupported)
{
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::IsVideoStabilizationModeSupported Session is not Commited");
    isSupported = false;
    std::vector<VideoStabilizationMode> stabilizationModes = GetSupportedStabilizationMode();
    if (std::find(stabilizationModes.begin(), stabilizationModes.end(), stabilizationMode) !=
        stabilizationModes.end()) {
        isSupported = true;
        return CameraErrorCode::SUCCESS;
    }
    return CameraErrorCode::SUCCESS;
}

std::vector<VideoStabilizationMode> CaptureSession::GetSupportedStabilizationMode()
{
    std::vector<VideoStabilizationMode> stabilizationModes;
    GetSupportedStabilizationMode(stabilizationModes);
    HILOG_COMM_INFO("CaptureSession::GetSupportedStabilizationMode stabilizationModes: %{public}s",
        Container2String(stabilizationModes.begin(), stabilizationModes.end()).c_str());
    return stabilizationModes;
}

int32_t CaptureSession::GetSupportedStabilizationMode(std::vector<VideoStabilizationMode>& stabilizationModes)
{
    stabilizationModes.clear();
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::GetSupportedStabilizationMode Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::SUCCESS,
        "CaptureSession::GetSupportedStabilizationMode camera device is null");
    sptr<CameraDevice> cameraDevNow = inputDevice->GetCameraDeviceInfo();
    bool isLimtedCapabilitySave = cameraDevNow != nullptr && cameraDevNow->isConcurrentLimted_ == 1;
    if (isLimtedCapabilitySave) {
        for (int i = 0; i < cameraDevNow->limtedCapabilitySave_.stabilizationmodes.count; i++) {
            auto num = static_cast<CameraVideoStabilizationMode>(cameraDevNow->limtedCapabilitySave_.
                stabilizationmodes.mode[i]);
            auto itr = g_metaVideoStabModesMap_.find(num);
            if (itr != g_metaVideoStabModesMap_.end()) {
                stabilizationModes.emplace_back(itr->second);
            }
        }
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, CameraErrorCode::SUCCESS, "GetSupportedStabilizationMode camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_VIDEO_STABILIZATION_MODES, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "CaptureSession::GetSupporteStabilizationModes Failed with return code %{public}d", ret);

    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = g_metaVideoStabModesMap_.find(static_cast<CameraVideoStabilizationMode>(item.data.u8[i]));
        CHECK_EXECUTE(itr != g_metaVideoStabModesMap_.end(), stabilizationModes.emplace_back(itr->second));
    }
    return CameraErrorCode::SUCCESS;
}

bool CaptureSession::IsExposureModeSupported(ExposureMode exposureMode)
{
    bool isSupported = false;
    IsExposureModeSupported(exposureMode, isSupported);
    return isSupported;
}

int32_t CaptureSession::IsExposureModeSupported(ExposureMode exposureMode, bool& isSupported)
{
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::IsExposureModeSupported Session is not Commited");
    std::vector<ExposureMode> vecSupportedExposureModeList;
    vecSupportedExposureModeList = this->GetSupportedExposureModes();
    if (find(vecSupportedExposureModeList.begin(), vecSupportedExposureModeList.end(), exposureMode) !=
        vecSupportedExposureModeList.end()) {
        isSupported = true;
        return CameraErrorCode::SUCCESS;
    }
    isSupported = false;
    return CameraErrorCode::SUCCESS;
}

std::vector<ExposureMode> CaptureSession::GetSupportedExposureModes()
{
    std::vector<ExposureMode> supportedExposureModes;
    GetSupportedExposureModes(supportedExposureModes);
    return supportedExposureModes;
}

int32_t CaptureSession::GetSupportedExposureModes(std::vector<ExposureMode>& supportedExposureModes)
{
    supportedExposureModes.clear();
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::GetSupportedExposureModes Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::SUCCESS,
        "CaptureSession::GetSupportedExposureModes camera device is null");
    sptr<CameraDevice> cameraDevNow = inputDevice->GetCameraDeviceInfo();
    bool isLimtedCapabilitySave = cameraDevNow != nullptr && cameraDevNow->isConcurrentLimted_ == 1;
    if (isLimtedCapabilitySave) {
        for (int i = 0; i < cameraDevNow->limtedCapabilitySave_.exposuremodes.count; i++) {
            camera_exposure_mode_enum_t num =
                static_cast<camera_exposure_mode_enum_t>(cameraDevNow->limtedCapabilitySave_.exposuremodes.mode[i]);
            auto itr = g_metaExposureModeMap_.find(num);
            if (itr != g_metaExposureModeMap_.end()) {
                supportedExposureModes.emplace_back(itr->second);
            }
        }
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, CameraErrorCode::SUCCESS, "GetSupportedExposureModes camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_EXPOSURE_MODES, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "CaptureSession::GetExposureMode Failed with return code %{public}d", ret);
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = g_metaExposureModeMap_.find(static_cast<camera_exposure_mode_enum_t>(item.data.u8[i]));
        CHECK_EXECUTE(itr != g_metaExposureModeMap_.end(), supportedExposureModes.emplace_back(itr->second));
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetExposureMode(ExposureMode exposureMode)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::SetExposureMode Session is not Commited");

    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::SetExposureMode Need to call LockForControl() before setting camera properties");
    CHECK_RETURN_RET(!IsExposureModeSupported(exposureMode), CameraErrorCode::OPERATION_NOT_ALLOWED);
    uint8_t exposure = g_fwkExposureModeMap_.at(EXPOSURE_MODE_LOCKED);
    auto itr = g_fwkExposureModeMap_.find(exposureMode);
    if (itr == g_fwkExposureModeMap_.end()) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureMode Unknown exposure mode");
    } else {
        exposure = itr->second;
    }
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_EXPOSURE_MODE, &exposure, 1);
    wptr<CaptureSession> weakThis(this);
    CHECK_EXECUTE(status, AddFunctionToMap(std::to_string(OHOS_CONTROL_EXPOSURE_MODE), [weakThis, exposureMode]() {
        auto sharedThis = weakThis.promote();
        CHECK_RETURN_ELOG(!sharedThis, "SetExposureMode session is nullptr");
        sharedThis->LockForControl();
        int32_t retCode = sharedThis->SetExposureMode(exposureMode);
        sharedThis->UnlockForControl();
        CHECK_EXECUTE(retCode != CameraErrorCode::SUCCESS, sharedThis->SetDeviceCapabilityChangeStatus(true));
    }));
    CHECK_PRINT_ELOG(!status, "CaptureSession::SetExposureMode Failed to set exposure mode");

    return CameraErrorCode::SUCCESS;
}

ExposureMode CaptureSession::GetExposureMode()
{
    ExposureMode exposureMode;
    GetExposureMode(exposureMode);
    return exposureMode;
}

int32_t CaptureSession::GetExposureMode(ExposureMode& exposureMode)
{
    exposureMode = EXPOSURE_MODE_UNSUPPORTED;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::GetExposureMode Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::SUCCESS,
        "CaptureSession::GetExposureMode camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, CameraErrorCode::SUCCESS, "GetExposureMode camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_EXPOSURE_MODE, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "CaptureSession::GetExposureMode Failed with return code %{public}d", ret);
    auto itr = g_metaExposureModeMap_.find(static_cast<camera_exposure_mode_enum_t>(item.data.u8[0]));
    if (itr != g_metaExposureModeMap_.end()) {
        exposureMode = itr->second;
        return CameraErrorCode::SUCCESS;
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::IsZoomCenterPointSupported(bool& isSupported)
{
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::IsZoomCenterPointSupported Session is not Commited");
    isSupported = false;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::IsZoomCenterPointSupported metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_ZOOM_CENTER_POINT_SUPPORTED, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count < 1, CameraErrorCode::SUCCESS,
        "CaptureSession::IsZoomCenterPointSupported Failed with return code %{public}d", ret);
    isSupported = static_cast<bool>(item.data.u8[0]);
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetZoomCenterPoint(Point zoomCenterPoint)
{
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::SetZoomCenterPoint Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::SetZoomCenterPoint Need to call LockForControl() before setting camera properties");
    Point zoomCenterVerifyPoint = VerifyFocusCorrectness(zoomCenterPoint);
    MEDIA_DEBUG_LOG("CaptureSession::SetZoomCenterPoint is called x:%{public}f, y:%{public}f",
        zoomCenterVerifyPoint.x, zoomCenterVerifyPoint.y);
    std::vector<float> zoomCenterPointVector = { zoomCenterVerifyPoint.x, zoomCenterVerifyPoint.y };
    bool status = AddOrUpdateMetadata(
        changedMetadata_, OHOS_CONTROL_ZOOM_CENTER_POINT, zoomCenterPointVector.data(), zoomCenterPointVector.size());
    CHECK_PRINT_ELOG(!status, "CaptureSession::SetZoomCenterPoint Failed to set zoom center point.");
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::GetZoomCenterPoint(Point& zoomCenterPoint)
{
    float DEFAULT_ZOOM_CENTER_POINT = 0.5;
    zoomCenterPoint.x = DEFAULT_ZOOM_CENTER_POINT;
    zoomCenterPoint.y = DEFAULT_ZOOM_CENTER_POINT;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::GetZoomCenterPoint Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::SUCCESS,
        "CaptureSession::GetZoomCenterPoint camera device is null");
    auto cameraDeviceObj = ((sptr<CameraInput>&)inputDevice)->GetCameraDevice();
    CHECK_RETURN_RET_ELOG(
        !cameraDeviceObj, CameraErrorCode::SUCCESS, "CaptureSession::GetZoomCenterPoint cameraDeviceObj is nullptr");

    int32_t DEFAULT_ITEMS = 1;
    int32_t DEFAULT_DATA_LENGTH = 100;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metaIn =
        std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    std::shared_ptr<OHOS::Camera::CameraMetadata> metaOut =
        std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    std::vector<float> zoomCenterPointVector = { zoomCenterPoint.x, zoomCenterPoint.y };
    metaIn->addEntry(OHOS_CONTROL_ZOOM_CENTER_POINT, zoomCenterPointVector.data(), zoomCenterPointVector.size());
    cameraDeviceObj->GetStatus(metaIn, metaOut);
    CHECK_RETURN_RET_ELOG(
        metaOut == nullptr, CameraErrorCode::SUCCESS, "CaptureSession::GetZoomCenterPoint metaOut is nullptr");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metaOut->get(), OHOS_CONTROL_ZOOM_CENTER_POINT, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count < zoomCenterPointVector.size(),
        CameraErrorCode::SUCCESS, "CaptureSession::GetZoomCenterPoint Failed with return code %{public}d", ret);
    zoomCenterPoint.x = item.data.f[0];
    zoomCenterPoint.y = item.data.f[1];
    MEDIA_DEBUG_LOG("CaptureSession::GetZoomCenterPoint is called x:%{public}f, y:%{public}f",
        zoomCenterPoint.x, zoomCenterPoint.y);
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetMeteringPoint(Point exposurePoint)
{
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::SetMeteringPoint Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::SetExposurePoint Need to call LockForControl() before setting camera properties");
    Point exposureVerifyPoint = VerifyFocusCorrectness(exposurePoint);
    Point unifyExposurePoint = CoordinateTransform(exposureVerifyPoint);
    std::vector<float> exposureArea = { unifyExposurePoint.x, unifyExposurePoint.y };
    bool status = AddOrUpdateMetadata(
        changedMetadata_, OHOS_CONTROL_AE_REGIONS, exposureArea.data(), exposureArea.size());
    wptr<CaptureSession> weakThis(this);
    CHECK_EXECUTE(status, AddFunctionToMap(std::to_string(OHOS_CONTROL_AE_REGIONS), [weakThis, exposurePoint]() {
        auto sharedThis = weakThis.promote();
        CHECK_RETURN_ELOG(!sharedThis, "SetMeteringPoint session is nullptr");
        sharedThis->LockForControl();
        int32_t retCode = sharedThis->SetMeteringPoint(exposurePoint);
        sharedThis->UnlockForControl();
        CHECK_EXECUTE(retCode != CameraErrorCode::SUCCESS, sharedThis->SetDeviceCapabilityChangeStatus(true));
    }));
    CHECK_PRINT_ELOG(!status, "CaptureSession::SetExposurePoint Failed to set exposure Area");
    return CameraErrorCode::SUCCESS;
}

Point CaptureSession::GetMeteringPoint()
{
    Point exposurePoint;
    GetMeteringPoint(exposurePoint);
    return exposurePoint;
}

int32_t CaptureSession::GetMeteringPoint(Point& exposurePoint)
{
    exposurePoint.x = 0;
    exposurePoint.y = 0;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::GetMeteringPoint Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::SUCCESS,
        "CaptureSession::GetMeteringPoint camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, CameraErrorCode::SUCCESS, "GetMeteringPoint camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_AE_REGIONS, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "CaptureSession::GetExposurePoint Failed with return code %{public}d", ret);
    exposurePoint.x = item.data.f[0];
    exposurePoint.y = item.data.f[1];
    exposurePoint = CoordinateTransform(exposurePoint);
    return CameraErrorCode::SUCCESS;
}

std::vector<float> CaptureSession::GetExposureBiasRange()
{
    std::vector<float> exposureBiasRange;
    GetExposureBiasRange(exposureBiasRange);
    return exposureBiasRange;
}

int32_t CaptureSession::GetExposureBiasRange(std::vector<float>& exposureBiasRange)
{
    exposureBiasRange.clear();
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::GetExposureBiasRange Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        !inputDevice, CameraErrorCode::SUCCESS, "CaptureSession::GetExposureBiasRange camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(
        !inputDeviceInfo, CameraErrorCode::SUCCESS, "CaptureSession::GetExposureBiasRange camera device info is null");
    exposureBiasRange = inputDeviceInfo->GetExposureBiasRange();
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetExposureBias(float exposureValue)
{
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::SetExposureBias Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::SetExposureBias Need to call LockForControl() before setting camera properties");
    int32_t minIndex = 0;
    int32_t maxIndex = 1;
    MEDIA_DEBUG_LOG("CaptureSession::SetExposureValue exposure compensation: %{public}f", exposureValue);
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        !inputDevice, CameraErrorCode::OPERATION_NOT_ALLOWED, "CaptureSession::SetExposureBias camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(!inputDeviceInfo, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "CaptureSession::SetExposureBias camera device info is null");
    std::vector<float> biasRange = inputDeviceInfo->GetExposureBiasRange();
    CHECK_RETURN_RET_ELOG(biasRange.empty(), CameraErrorCode::OPERATION_NOT_ALLOWED,
        "CaptureSession::SetExposureValue Bias range is empty");
    if (exposureValue < biasRange[minIndex]) {
        MEDIA_DEBUG_LOG("CaptureSession::SetExposureValue bias value:"
                        "%{public}f is lesser than minimum bias: %{public}f", exposureValue, biasRange[minIndex]);
        exposureValue = biasRange[minIndex];
    } else if (exposureValue > biasRange[maxIndex]) {
        MEDIA_DEBUG_LOG("CaptureSession::SetExposureValue bias value: "
                        "%{public}f is greater than maximum bias: %{public}f", exposureValue, biasRange[maxIndex]);
        exposureValue = biasRange[maxIndex];
    }
    int32_t exposureCompensation = CalculateExposureValue(exposureValue);
    bool status = AddOrUpdateMetadata(
        changedMetadata_, OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &exposureCompensation, 1);
    wptr<CaptureSession> weakThis(this);
    CHECK_EXECUTE(status, AddFunctionToMap(std::to_string(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION),
        [weakThis, exposureValue]() {
            auto sharedThis = weakThis.promote();
            CHECK_RETURN_ELOG(!sharedThis, "SetExposureBias session is nullptr");
            sharedThis->LockForControl();
            int32_t retCode = sharedThis->SetExposureBias(exposureValue);
            sharedThis->UnlockForControl();
            CHECK_EXECUTE(retCode != CameraErrorCode::SUCCESS, sharedThis->SetDeviceCapabilityChangeStatus(true));
        }));
    CHECK_PRINT_ELOG(!status, "CaptureSession::SetExposureValue Failed to set exposure compensation");
    return CameraErrorCode::SUCCESS;
}

float CaptureSession::GetExposureValue()
{
    float exposureValue;
    GetExposureValue(exposureValue);
    return exposureValue;
}

int32_t CaptureSession::GetExposureValue(float& exposureValue)
{
    exposureValue = 0;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::GetExposureValue Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::SUCCESS,
        "CaptureSession::GetExposureValue camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, CameraErrorCode::SUCCESS, "GetExposureValue camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "CaptureSession::GetExposureValue Failed with return code %{public}d", ret);
    int32_t exposureCompensation = item.data.i32[0];
    ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_AE_COMPENSATION_STEP, &item);
    CHECK_RETURN_RET_ELOG(
        ret != CAM_META_SUCCESS, 0, "CaptureSession::GetExposureValue Failed with return code %{public}d", ret);
    int32_t stepNumerator = item.data.r->numerator;
    int32_t stepDenominator = item.data.r->denominator;
    if (stepDenominator == 0) {
        MEDIA_ERR_LOG("stepDenominator: %{public}d", stepDenominator);
    } else {
        float step = static_cast<float>(stepNumerator) / static_cast<float>(stepDenominator);
        exposureValue = step * exposureCompensation;
    }
    MEDIA_DEBUG_LOG("exposureValue: %{public}f", exposureValue);
    return CameraErrorCode::SUCCESS;
}

void CaptureSession::SetExposureCallback(std::shared_ptr<ExposureCallback> exposureCallback)
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    exposureCallback_ = exposureCallback;
}

void CaptureSession::ProcessAutoExposureUpdates(const std::shared_ptr<Camera::CameraMetadata>& result)
{
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();

    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_EXPOSURE_MODE, &item);
    CHECK_PRINT_DLOG(ret == CAM_META_SUCCESS, "exposure mode: %{public}d", item.data.u8[0]);

    ret = Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_EXPOSURE_STATE, &item);
    CHECK_RETURN(ret != CAM_META_SUCCESS);
    MEDIA_INFO_LOG("Exposure state: %{public}d", item.data.u8[0]);
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    if (exposureCallback_ != nullptr) {
        auto itr = metaExposureStateMap_.find(static_cast<camera_exposure_state_t>(item.data.u8[0]));
        if (itr != metaExposureStateMap_.end()) {
            exposureCallback_->OnExposureState(itr->second);
        }
    }
}

std::vector<FocusMode> CaptureSession::GetSupportedFocusModes()
{
    std::vector<FocusMode> supportedFocusModes;
    GetSupportedFocusModes(supportedFocusModes);
    return supportedFocusModes;
}

int32_t CaptureSession::GetSupportedFocusModes(std::vector<FocusMode>& supportedFocusModes)
{
    supportedFocusModes.clear();
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::SetExposureBias Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::SUCCESS,
        "CaptureSession::GetSupportedFocusModes camera device is null");
    sptr<CameraDevice> cameraDevNow = inputDevice->GetCameraDeviceInfo();
    bool isLimtedCapabilitySave = cameraDevNow != nullptr && cameraDevNow->isConcurrentLimted_ == 1;
    if (isLimtedCapabilitySave) {
        for (int i = 0; i < cameraDevNow->limtedCapabilitySave_.focusmodes.count; i++) {
            camera_focus_mode_enum_t num = static_cast<camera_focus_mode_enum_t>(cameraDevNow->
                limtedCapabilitySave_.focusmodes.mode[i]);
            auto itr = g_metaFocusModeMap_.find(static_cast<camera_focus_mode_enum_t>(num));
            if (itr != g_metaFocusModeMap_.end()) {
                supportedFocusModes.emplace_back(itr->second);
            }
        }
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, CameraErrorCode::SUCCESS, "GetSupportedFocusModes camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FOCUS_MODES, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "CaptureSession::GetSupportedFocusModes Failed with return code %{public}d", ret);
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = g_metaFocusModeMap_.find(static_cast<camera_focus_mode_enum_t>(item.data.u8[i]));
        CHECK_EXECUTE(itr != g_metaFocusModeMap_.end(), supportedFocusModes.emplace_back(itr->second));
    }
    return CameraErrorCode::SUCCESS;
}

void CaptureSession::SetFocusCallback(std::shared_ptr<FocusCallback> focusCallback)
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    focusCallback_ = focusCallback;
    return;
}

bool CaptureSession::IsFocusModeSupported(FocusMode focusMode)
{
    bool isSupported = false;
    IsFocusModeSupported(focusMode, isSupported);
    return isSupported;
}

int32_t CaptureSession::IsFocusModeSupported(FocusMode focusMode, bool& isSupported)
{
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::SetExposureBias Session is not Commited");
    std::vector<FocusMode> vecSupportedFocusModeList;
    vecSupportedFocusModeList = this->GetSupportedFocusModes();
    if (find(vecSupportedFocusModeList.begin(), vecSupportedFocusModeList.end(), focusMode) !=
        vecSupportedFocusModeList.end()) {
        isSupported = true;
        return CameraErrorCode::SUCCESS;
    }
    isSupported = false;
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetFocusMode(FocusMode focusMode)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::SetFocusMode Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::SetFocusMode Need to call LockForControl() before setting camera properties");
    CHECK_RETURN_RET(!IsFocusModeSupported(focusMode), CameraErrorCode::OPERATION_NOT_ALLOWED);
    uint8_t focus = FOCUS_MODE_LOCKED;
    auto itr = g_fwkFocusModeMap_.find(focusMode);
    if (itr == g_fwkFocusModeMap_.end()) {
        MEDIA_ERR_LOG("CaptureSession::SetFocusMode Unknown exposure mode");
    } else {
        focus = itr->second;
    }
    MEDIA_DEBUG_LOG("CaptureSession::SetFocusMode Focus mode: %{public}d", focusMode);
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_FOCUS_MODE, &focus, 1);
    wptr<CaptureSession> weakThis(this);
    CHECK_EXECUTE(status, AddFunctionToMap(std::to_string(OHOS_CONTROL_FOCUS_MODE), [weakThis, focusMode]() {
        auto sharedThis = weakThis.promote();
        CHECK_RETURN_ELOG(!sharedThis, "SetFocusMode session is nullptr");
        sharedThis->LockForControl();
        int32_t retCode = sharedThis->SetFocusMode(focusMode);
        sharedThis->UnlockForControl();
        CHECK_EXECUTE(retCode != CameraErrorCode::SUCCESS, sharedThis->SetDeviceCapabilityChangeStatus(true));
    }));
    CHECK_PRINT_ELOG(!status, "CaptureSession::SetFocusMode Failed to set focus mode");
    return CameraErrorCode::SUCCESS;
}

FocusMode CaptureSession::GetFocusMode()
{
    FocusMode focusMode = FOCUS_MODE_MANUAL;
    GetFocusMode(focusMode);
    return focusMode;
}

int32_t CaptureSession::GetFocusMode(FocusMode& focusMode)
{
    focusMode = FOCUS_MODE_MANUAL;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::GetFocusMode Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::SUCCESS,
        "CaptureSession::GetFocusMode camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, CameraErrorCode::SUCCESS, "GetFocusMode camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_FOCUS_MODE, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "CaptureSession::GetFocusMode Failed with return code %{public}d", ret);
    auto itr = g_metaFocusModeMap_.find(static_cast<camera_focus_mode_enum_t>(item.data.u8[0]));
    if (itr != g_metaFocusModeMap_.end()) {
        focusMode = itr->second;
        return CameraErrorCode::SUCCESS;
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetFocusPoint(Point focusPoint)
{
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::SetFocusPoint Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::SetFocusPoint Need to call LockForControl() before setting camera properties");
    FocusMode focusMode;
    GetFocusMode(focusMode);
#ifdef CAMERA_FRAMEWORK_FEATURE_MEDIA_STREAM
    CHECK_RETURN_RET_ELOG(focusMode == FOCUS_MODE_CONTINUOUS_AUTO && GetMode() != SceneMode::CINEMATIC_VIDEO,
        CameraErrorCode::SUCCESS, "The current mode does not support setting the focus point.");
#else
    CHECK_RETURN_RET_ELOG(focusMode == FOCUS_MODE_CONTINUOUS_AUTO, CameraErrorCode::SUCCESS,
        "The current focus mode does not support setting the focus point.");
#endif
    Point focusVerifyPoint = VerifyFocusCorrectness(focusPoint);
    Point unifyFocusPoint = CoordinateTransform(focusVerifyPoint);
    std::vector<float> focusArea = { unifyFocusPoint.x, unifyFocusPoint.y };
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_AF_REGIONS, focusArea.data(), focusArea.size());
    wptr<CaptureSession> weakThis(this);
    CHECK_EXECUTE(status, AddFunctionToMap(std::to_string(OHOS_CONTROL_AF_REGIONS), [weakThis, focusPoint]() {
        auto sharedThis = weakThis.promote();
        CHECK_RETURN_ELOG(!sharedThis, "SetFocusPoint session is nullptr");
        sharedThis->LockForControl();
        int32_t retCode = sharedThis->SetFocusPoint(focusPoint);
        sharedThis->UnlockForControl();
        CHECK_EXECUTE(retCode != CameraErrorCode::SUCCESS, sharedThis->SetDeviceCapabilityChangeStatus(true));
    }));
    CHECK_PRINT_ELOG(!status, "CaptureSession::SetFocusPoint Failed to set Focus Area");
    return CameraErrorCode::SUCCESS;
}

Point CaptureSession::CoordinateTransform(Point point)
{
    MEDIA_DEBUG_LOG("CaptureSession::CoordinateTransform begin x: %{public}f, y: %{public}f", point.x, point.y);
    Point unifyPoint = point;
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), unifyPoint,
        "CaptureSession::CoordinateTransform cameraInput is nullptr");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(!inputDeviceInfo, unifyPoint, "CaptureSession::CoordinateTransform cameraInput is nullptr");
    if (inputDeviceInfo->GetPosition() == CAMERA_POSITION_FRONT) {
        unifyPoint.x = 1 - unifyPoint.x; // flip horizontally
    }
    MEDIA_DEBUG_LOG("CaptureSession::CoordinateTransform end x: %{public}f, y: %{public}f", unifyPoint.x, unifyPoint.y);
    return unifyPoint;
}

Point CaptureSession::VerifyFocusCorrectness(Point point)
{
    MEDIA_DEBUG_LOG("CaptureSession::VerifyFocusCorrectness begin x: %{public}f, y: %{public}f", point.x, point.y);
    float minPoint = 0.0000001;
    float maxPoint = 1;
    Point VerifyPoint = point;
    if (VerifyPoint.x <= minPoint) {
        VerifyPoint.x = minPoint;
    } else if (VerifyPoint.x > maxPoint) {
        VerifyPoint.x = maxPoint;
    }
    if (VerifyPoint.y <= minPoint) {
        VerifyPoint.y = minPoint;
    } else if (VerifyPoint.y > maxPoint) {
        VerifyPoint.y = maxPoint;
    }
    MEDIA_DEBUG_LOG(
        "CaptureSession::VerifyFocusCorrectness end x: %{public}f, y: %{public}f", VerifyPoint.x, VerifyPoint.y);
    return VerifyPoint;
}

Point CaptureSession::GetFocusPoint()
{
    Point focusPoint = { 0, 0 };
    GetFocusPoint(focusPoint);
    return focusPoint;
}

int32_t CaptureSession::GetFocusPoint(Point& focusPoint)
{
    focusPoint.x = 0;
    focusPoint.y = 0;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::GetFocusPoint Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::SUCCESS,
        "CaptureSession::GetFocusPoint camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, CameraErrorCode::SUCCESS, "GetFocusPoint camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_AF_REGIONS, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "CaptureSession::GetFocusPoint Failed with return code %{public}d", ret);
    focusPoint.x = item.data.f[0];
    focusPoint.y = item.data.f[1];
    focusPoint = CoordinateTransform(focusPoint);
    return CameraErrorCode::SUCCESS;
}

float CaptureSession::GetFocalLength()
{
    float focalLength = 0;
    GetFocalLength(focalLength);
    return focalLength;
}

int32_t CaptureSession::GetFocalLength(float& focalLength)
{
    focalLength = 0;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::GetFocalLength Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::SUCCESS,
        "CaptureSession::GetFocalLength camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, CameraErrorCode::SUCCESS, "GetFocalLength camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FOCAL_LENGTH, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "CaptureSession::GetFocalLength Failed with return code %{public}d", ret);
    focalLength = static_cast<float>(item.data.f[0]);
    return CameraErrorCode::SUCCESS;
}

void CaptureSession::ProcessAutoFocusUpdates(const std::shared_ptr<Camera::CameraMetadata>& result)
{
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_FOCUS_MODE, &item);
    CHECK_RETURN_ELOG(ret != CAM_META_SUCCESS, "Camera not support Focus mode");
    MEDIA_DEBUG_LOG("Focus mode: %{public}d", item.data.u8[0]);
    auto it = g_metaFocusModeMap_.find(static_cast<camera_focus_mode_enum_t>(item.data.u8[0]));
    CHECK_RETURN_ELOG(it == g_metaFocusModeMap_.end(), "Focus mode not support");
    CHECK_EXECUTE(CameraSecurity::CheckSystemApp(), ProcessFocusDistanceUpdates(result));
    // continuous focus mode do not callback focusStateChange
    CHECK_RETURN((it->second != FOCUS_MODE_AUTO) && (it->second != FOCUS_MODE_CONTINUOUS_AUTO));
    ret = Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_FOCUS_STATE, &item);
    if (ret == CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("Focus state: %{public}d", item.data.u8[0]);
        std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
        if (focusCallback_ != nullptr) {
            auto itr = metaFocusStateMap_.find(static_cast<camera_focus_state_t>(item.data.u8[0]));
            bool isFindItr = itr != metaFocusStateMap_.end() && itr->second != focusCallback_->currentState;
            if (isFindItr) {
                focusCallback_->OnFocusState(itr->second);
                focusCallback_->currentState = itr->second;
            }
        }
    }
}

void CaptureSession::ProcessSnapshotDurationUpdates(const uint64_t timestamp,
    const std::shared_ptr<OHOS::Camera::CameraMetadata> &result)
{
    MEDIA_DEBUG_LOG("Entry ProcessSnapShotDurationUpdates");
    CHECK_RETURN(photoOutput_ == nullptr);
    camera_metadata_item_t metadataItem;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_CAMERA_CUSTOM_SNAPSHOT_DURATION, &metadataItem);
    CHECK_RETURN(ret != CAM_META_SUCCESS || metadataItem.count <= 0);
    const int32_t duration = static_cast<int32_t>(metadataItem.data.ui32[0]);
    if (duration != prevDuration_.load()) {
        ((sptr<PhotoOutput>&)photoOutput_)->ProcessSnapshotDurationUpdates(duration);
    }
        prevDuration_ = duration;
}

void CaptureSession::ProcessEffectSuggestionTypeUpdates(const std::shared_ptr<OHOS::Camera::CameraMetadata> &result)
    __attribute__((no_sanitize("cfi")))
{
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_CAMERA_EFFECT_SUGGESTION_TYPE, &item);
    CHECK_RETURN(ret != CAM_META_SUCCESS);
    MEDIA_DEBUG_LOG("ProcessEffectSuggestionTypeUpdates EffectSuggestionType: %{public}d", item.data.u8[0]);
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    CHECK_RETURN(effectSuggestionCallback_ == nullptr);
    auto itr = metaEffectSuggestionTypeMap_.find(static_cast<CameraEffectSuggestionType>(item.data.u8[0]));
    CHECK_RETURN(itr == metaEffectSuggestionTypeMap_.end());
    EffectSuggestionType type = itr->second;
    bool isNotChange = !effectSuggestionCallback_->isFirstReport && type == effectSuggestionCallback_->currentType;
    CHECK_RETURN_DLOG(isNotChange, "EffectSuggestion type: no change");
    effectSuggestionCallback_->isFirstReport = false;
    effectSuggestionCallback_->currentType = type;
    effectSuggestionCallback_->OnEffectSuggestionChange(type);
}

void CaptureSession::ProcessAREngineUpdates(const uint64_t timestamp,
    const std::shared_ptr<OHOS::Camera::CameraMetadata> &result) __attribute__((no_sanitize("cfi")))
{
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    ARStatusInfo arStatusInfo;

    int ret = Camera::FindCameraMetadataItem(metadata, HAL_CUSTOM_LASER_DATA, &item);
    if (ret == CAM_META_SUCCESS) {
        std::vector<int32_t> laserData;
        for (uint32_t i = 0; i < item.count; i++) {
            laserData.emplace_back(item.data.i32[i]);
        }
        arStatusInfo.laserData = laserData;
    }

    ret = Camera::FindCameraMetadataItem(metadata, HAL_CUSTOM_LENS_FOCUS_DISTANCE, &item);
    CHECK_EXECUTE(ret == CAM_META_SUCCESS, arStatusInfo.lensFocusDistance = item.data.f[0]);

    ret = Camera::FindCameraMetadataItem(metadata, HAL_CUSTOM_SENSOR_SENSITIVITY, &item);
    CHECK_EXECUTE(ret == CAM_META_SUCCESS, arStatusInfo.sensorSensitivity = item.data.i32[0]);

    ret = Camera::FindCameraMetadataItem(metadata, OHOS_STATUS_SENSOR_EXPOSURE_TIME, &item);
    if (ret == CAM_META_SUCCESS) {
        int32_t numerator = item.data.r->numerator;
        int32_t denominator = item.data.r->denominator;
        MEDIA_DEBUG_LOG("SensorExposureTime: %{public}d/%{public}d", numerator, denominator);
        CHECK_RETURN_ELOG(denominator == 0, "ProcessSensorExposureTimeChange error! divide by zero");
        uint32_t value = static_cast<uint32_t>(numerator / (denominator/1000000));
        MEDIA_DEBUG_LOG("SensorExposureTime: %{public}u", value);
        arStatusInfo.exposureDurationValue = value;
    }
    ret = Camera::FindCameraMetadataItem(metadata, OHOS_SENSOR_INFO_TIMESTAMP, &item);
    if (ret == CAM_META_SUCCESS) {
        arStatusInfo.timestamp = item.data.i64[0];
    }

    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    if (arCallback_ != nullptr) {
        arCallback_->OnResult(arStatusInfo);
    }
}

void CaptureSession::CaptureSessionMetadataResultProcessor::ProcessCallbacks(
    const uint64_t timestamp, const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    MEDIA_DEBUG_LOG("CaptureSession::CaptureSessionMetadataResultProcessor ProcessCallbacks");
    auto session = session_.promote();
    CHECK_RETURN_ELOG(session == nullptr,
        "CaptureSession::CaptureSessionMetadataResultProcessor ProcessCallbacks but session is null");
    session->OnResultReceived(result);
    session->ProcessAutoFocusUpdates(result);
    session->ProcessMacroStatusChange(result);
    session->ProcessMoonCaptureBoostStatusChange(result);
    session->ProcessLowLightBoostStatusChange(result);
    session->ProcessSmoothZoomDurationChange(result);
    session->ProcessSnapshotDurationUpdates(timestamp, result);
    session->ProcessAREngineUpdates(timestamp, result);
    session->ProcessEffectSuggestionTypeUpdates(result);
    session->ProcessLcdFlashStatusUpdates(result);
    session->ProcessTripodStatusChange(result);
    session->ProcessCompositionPositionCalibration(result);
    session->ProcessCompositionBegin(result);
    session->ProcessCompositionEnd(result);
    session->ProcessCompositionPositionMatch(result);
}

std::vector<FlashMode> CaptureSession::GetSupportedFlashModes()
{
    std::vector<FlashMode> supportedFlashModes;
    GetSupportedFlashModes(supportedFlashModes);
    return supportedFlashModes;
}

int32_t CaptureSession::GetSupportedFlashModes(std::vector<FlashMode>& supportedFlashModes)
{
    supportedFlashModes.clear();
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::GetSupportedFlashModes Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::SUCCESS,
        "CaptureSession::GetSupportedFlashModes camera device is null");
    sptr<CameraDevice> cameraDevNow = inputDevice->GetCameraDeviceInfo();
    bool isLimtedCapabilitySave = cameraDevNow != nullptr && cameraDevNow->isConcurrentLimted_ == 1;
    if (isLimtedCapabilitySave) {
        for (int i = 0; i < cameraDevNow->limtedCapabilitySave_.flashmodes.count; i++) {
            camera_flash_mode_enum_t num = static_cast<camera_flash_mode_enum_t>
                (cameraDevNow->limtedCapabilitySave_.flashmodes.mode[i]);
            auto it = g_metaFlashModeMap_.find(static_cast<camera_flash_mode_enum_t>(num));
            if (it != g_metaFlashModeMap_.end()) {
                supportedFlashModes.emplace_back(it->second);
            }
        }
        return CameraErrorCode::SUCCESS;
    }

    if (supportSpecSearch_) {
        MEDIA_INFO_LOG("spec search enter");
        auto abilityContainer = GetCameraAbilityContainer();
        if (abilityContainer) {
            supportedFlashModes = abilityContainer->GetSupportedFlashModes();
            std::string rangeStr = Container2String(supportedFlashModes.begin(), supportedFlashModes.end());
            MEDIA_INFO_LOG("spec search result flash: %{public}s", rangeStr.c_str());
        } else {
            MEDIA_ERR_LOG("spec search abilityContainer is null");
        }
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, CameraErrorCode::SUCCESS, "GetSupportedFlashModes camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FLASH_MODES, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "CaptureSession::GetSupportedFlashModes Failed with return code %{public}d", ret);
    g_transformValidData(item, g_metaFlashModeMap_, supportedFlashModes);
    return CameraErrorCode::SUCCESS;
}

FlashMode CaptureSession::GetFlashMode()
{
    FlashMode flashMode = FLASH_MODE_CLOSE;
    GetFlashMode(flashMode);
    return flashMode;
}

int32_t CaptureSession::GetFlashMode(FlashMode& flashMode)
{
    flashMode = FLASH_MODE_CLOSE;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::GetFlashMode Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::SUCCESS,
        "CaptureSession::GetFlashMode camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, CameraErrorCode::SUCCESS, "GetFlashMode camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_FLASH_MODE, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "CaptureSession::GetFlashMode Failed with return code %{public}d", ret);
    auto itr = g_metaFlashModeMap_.find(static_cast<camera_flash_mode_enum_t>(item.data.u8[0]));
    if (itr != g_metaFlashModeMap_.end()) {
        flashMode = itr->second;
        return CameraErrorCode::SUCCESS;
    }

    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetFlashMode(FlashMode flashMode)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::SetFlashMode Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::SetFlashMode Need to call LockForControl() before setting camera properties");
    // flash for lightPainting
    if (GetMode() == SceneMode::LIGHT_PAINTING && flashMode == FlashMode::FLASH_MODE_OPEN) {
        MEDIA_DEBUG_LOG("CaptureSession::TriggerLighting once.");
        uint8_t enableTrigger = 1;
        bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_LIGHT_PAINTING_FLASH, &enableTrigger, 1);
        CHECK_RETURN_RET_ELOG(
            !status, CameraErrorCode::SERVICE_FATL_ERROR, "CaptureSession::TriggerLighting Failed to trigger lighting");
        return CameraErrorCode::SUCCESS;
    }
    CHECK_RETURN_RET(!IsFlashModeSupported(flashMode), CameraErrorCode::OPERATION_NOT_ALLOWED);
    uint8_t flash = g_fwkFlashModeMap_.at(FLASH_MODE_CLOSE);
    auto itr = g_fwkFlashModeMap_.find(flashMode);
    if (itr == g_fwkFlashModeMap_.end()) {
        MEDIA_ERR_LOG("CaptureSession::SetFlashMode Unknown exposure mode");
    } else {
        flash = itr->second;
    }

    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_FLASH_MODE, &flash, 1);
    CHECK_PRINT_ELOG(!status, "CaptureSession::SetFlashMode Failed to set flash mode");
    wptr<CaptureSession> weakThis(this);
    AddFunctionToMap(std::to_string(OHOS_CONTROL_FLASH_MODE), [weakThis, flashMode]() {
        auto sharedThis = weakThis.promote();
        CHECK_RETURN_ELOG(!sharedThis, "SetFlashMode session is nullptr");
        sharedThis->LockForControl();
        int32_t retCode = sharedThis->SetFlashMode(flashMode);
        sharedThis->UnlockForControl();
        CHECK_EXECUTE(retCode != CameraErrorCode::SUCCESS,
                      sharedThis->SetDeviceCapabilityChangeStatus(true));
    });
    return CameraErrorCode::SUCCESS;
}

bool CaptureSession::IsFlashModeSupported(FlashMode flashMode)
{
    bool isSupported = false;
    IsFlashModeSupported(flashMode, isSupported);
    return isSupported;
}
int32_t CaptureSession::IsFlashModeSupported(FlashMode flashMode, bool& isSupported)
{
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::IsFlashModeSupported Session is not Commited");
    std::vector<FlashMode> vecSupportedFlashModeList;
    vecSupportedFlashModeList = this->GetSupportedFlashModes();
    if (find(vecSupportedFlashModeList.begin(), vecSupportedFlashModeList.end(), flashMode) !=
        vecSupportedFlashModeList.end()) {
        isSupported = true;
        return CameraErrorCode::SUCCESS;
    }
    isSupported = false;
    return CameraErrorCode::SUCCESS;
}
bool CaptureSession::HasFlash()
{
    bool hasFlash = false;
    HasFlash(hasFlash);
    return hasFlash;
}
int32_t CaptureSession::HasFlash(bool& hasFlash)
{
    hasFlash = false;
    CHECK_RETURN_RET_ELOG(
        !IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG, "CaptureSession::HasFlash Session is not Commited");

    if (supportSpecSearch_) {
        MEDIA_INFO_LOG("spec search enter");
        auto abilityContainer = GetCameraAbilityContainer();
        if (abilityContainer) {
            hasFlash = abilityContainer->HasFlash();
            MEDIA_INFO_LOG("spec search result: %{public}d", hasFlash);
        } else {
            MEDIA_ERR_LOG("spec search abilityContainer is null");
        }
        return CameraErrorCode::SUCCESS;
    }

    std::vector<FlashMode> supportedFlashModeList = GetSupportedFlashModes();
    bool onlyHasCloseMode = supportedFlashModeList.size() == 1 && supportedFlashModeList[0] == FLASH_MODE_CLOSE;
    bool isFlashMode = !supportedFlashModeList.empty() && !onlyHasCloseMode;
    if (isFlashMode) {
        hasFlash = true;
    }
    return CameraErrorCode::SUCCESS;
}

std::vector<float> CaptureSession::GetZoomRatioRange()
{
    std::vector<float> zoomRatioRange;
    GetZoomRatioRange(zoomRatioRange);
    return zoomRatioRange;
}

int32_t CaptureSession::GetZoomRatioRange(std::vector<float>& zoomRatioRange)
{
    MEDIA_INFO_LOG("CaptureSession::GetZoomRatioRange is Called");
    zoomRatioRange.clear();
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::GetZoomRatioRange Session is not Commited");

    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::SUCCESS,
        "CaptureSession::GetZoomRatioRange camera device is null");

    sptr<CameraDevice> cameraDevNow = inputDevice->GetCameraDeviceInfo();

    bool isLimtedCapabilitySave = cameraDevNow != nullptr && cameraDevNow->isConcurrentLimted_ == 1;
    if (isLimtedCapabilitySave) {
        auto itr = cameraDevNow->limtedCapabilitySave_.ratiorange.range.find(static_cast<int32_t>(GetMode()));
        if (itr != cameraDevNow->limtedCapabilitySave_.ratiorange.range.end()) {
            zoomRatioRange.push_back(itr->second.first);
            zoomRatioRange.push_back(itr->second.second);
            return CameraErrorCode::SUCCESS;
        }
    }

    if (supportSpecSearch_) {
        MEDIA_DEBUG_LOG("spec search enter");
        auto abilityContainer = GetCameraAbilityContainer();
        if (abilityContainer) {
            zoomRatioRange = abilityContainer->GetZoomRatioRange();
            std::string rangeStr = Container2String(zoomRatioRange.begin(), zoomRatioRange.end());
            MEDIA_INFO_LOG("spec search result: %{public}s", rangeStr.c_str());
        } else {
            MEDIA_ERR_LOG("spec search abilityContainer is null");
        }
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, CameraErrorCode::SUCCESS, "GetZoomRatioRange camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_SCENE_ZOOM_CAP, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count == 0, 0,
        "CaptureSession::GetZoomRatio Failed with return code %{public}d,item.count = %{public}d", ret, item.count);
    constexpr float factor = 100.0;
    float minZoom = 0.0;
    float maxZoom = 0.0;
    const uint32_t step = 3;
    uint32_t minOffset = 1;
    uint32_t maxOffset = 2;
    for (uint32_t i = 0; i < item.count; i += step) {
        MEDIA_INFO_LOG("Scene zoom cap mode: %{public}d, min: %{public}d, max: %{public}d", item.data.i32[i],
            item.data.i32[i + minOffset], item.data.i32[i + maxOffset]);
        if (GetFeaturesMode().GetFeaturedMode() == item.data.i32[i]) {
            minZoom = item.data.i32[i + minOffset] / factor;
            maxZoom = item.data.i32[i + maxOffset] / factor;
            break;
        }
    }
    zoomRatioRange = {minZoom, maxZoom};
    return CameraErrorCode::SUCCESS;
}

float CaptureSession::GetZoomRatio()
{
    float zoomRatio = 0;
    GetZoomRatio(zoomRatio);
    return zoomRatio;
}

int32_t CaptureSession::GetZoomRatio(float& zoomRatio)
{
    zoomRatio = 0;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::GetZoomRatio Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice, CameraErrorCode::SUCCESS, "CaptureSession::GetZoomRatio camera device is null");
    int32_t DEFAULT_ITEMS = 1;
    int32_t DEFAULT_DATA_LENGTH = 100;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metaIn =
        std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    std::shared_ptr<OHOS::Camera::CameraMetadata> metaOut =
        std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    uint32_t count = 1;
    uint32_t zoomRatioMultiple = 100;
    uint32_t metaInZoomRatio = 1 * zoomRatioMultiple;
    metaIn->addEntry(OHOS_STATUS_CAMERA_CURRENT_ZOOM_RATIO, &metaInZoomRatio, count);
    auto cameraDeviceObj = ((sptr<CameraInput>&)inputDevice)->GetCameraDevice();
    CHECK_RETURN_RET_ELOG(
        !cameraDeviceObj, CameraErrorCode::SUCCESS, "CaptureSession::GetZoomRatio cameraDeviceObj is nullptr");
    int32_t ret = cameraDeviceObj->GetStatus(metaIn, metaOut);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, ServiceToCameraError(ret),
        "CaptureSession::GetZoomRatio Failed to Get ZoomRatio, errCode = %{public}d", ret);
    camera_metadata_item_t item;
    ret = Camera::FindCameraMetadataItem(metaOut->get(), OHOS_STATUS_CAMERA_CURRENT_ZOOM_RATIO, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "CaptureSession::GetZoomRatio Failed with return code %{public}d", ret);
    zoomRatio = static_cast<float>(item.data.ui32[0]) / static_cast<float>(zoomRatioMultiple);
    MEDIA_ERR_LOG("CaptureSession::GetZoomRatio %{public}f", zoomRatio);
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetZoomRatio(float zoomRatio)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::SetZoomRatio Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::SetZoomRatio Need to call LockForControl() before setting camera properties");
    int32_t minIndex = 0;
    int32_t maxIndex = 1;
    MEDIA_DEBUG_LOG("CaptureSession::SetZoomRatio Zoom ratio: %{public}f", zoomRatio);
    std::vector<float> zoomRange = GetZoomRatioRange();
    CHECK_RETURN_RET_ELOG(
        zoomRange.empty(), CameraErrorCode::SUCCESS, "CaptureSession::SetZoomRatio Zoom range is empty");
    float tempZoomRatio = std::clamp(zoomRatio, zoomRange[minIndex], zoomRange[maxIndex]);
    MEDIA_DEBUG_LOG("origin zoomRatioValue: %{public}f, after clamp value: %{public}f", zoomRatio, tempZoomRatio);
    zoomRatio = tempZoomRatio;
    CHECK_RETURN_RET_ELOG(zoomRatio == 0, CameraErrorCode::SUCCESS,
        "CaptureSession::SetZoomRatio Invalid zoom ratio");
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_ZOOM_RATIO, &zoomRatio, 1);
    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::SetZoomRatio Failed to set zoom mode");
    } else {
        auto abilityContainer = GetCameraAbilityContainer();
        CHECK_EXECUTE(abilityContainer && supportSpecSearch_, abilityContainer->FilterByZoomRatio(zoomRatio));
        wptr<CaptureSession> weakThis(this);
        AddFunctionToMap(std::to_string(OHOS_CONTROL_ZOOM_RATIO), [weakThis, zoomRatio]() {
            auto sharedThis = weakThis.promote();
            CHECK_RETURN_ELOG(!sharedThis, "SetZoomRatio session is nullptr");
            sharedThis->LockForControl();
            int32_t retCode = sharedThis->SetZoomRatio(zoomRatio);
            sharedThis->UnlockForControl();
            CHECK_EXECUTE(retCode != CameraErrorCode::SUCCESS,
                          sharedThis->SetDeviceCapabilityChangeStatus(true));
        });
        SetZoomRatioForAudio(zoomRatio);
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::PrepareZoom()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("CaptureSession::PrepareZoom");
    isSmoothZooming_ = true;
    targetZoomRatio_ = -1.0;
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::PrepareZoom Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::PrepareZoom Need to call LockForControl() before setting camera properties");
    uint32_t prepareZoomType = OHOS_CAMERA_ZOOMSMOOTH_PREPARE_ENABLE;
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_PREPARE_ZOOM, &prepareZoomType, 1);
    CHECK_PRINT_ELOG(!status, "CaptureSession::SetSmoothZoom CaptureSession::PrepareZoom Failed to prepare zoom");
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::UnPrepareZoom()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("CaptureSession::UnPrepareZoom");
    isSmoothZooming_ = false;
    targetZoomRatio_ = -1.0;
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::UnPrepareZoom Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::UnPrepareZoom Need to call LockForControl() before setting camera properties");
    uint32_t prepareZoomType = OHOS_CAMERA_ZOOMSMOOTH_PREPARE_DISABLE;
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_PREPARE_ZOOM, &prepareZoomType, 1);
    CHECK_PRINT_ELOG(!status, "CaptureSession::UnPrepareZoom Failed to unPrepare zoom");
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetSmoothZoom(float targetZoomRatio, uint32_t smoothZoomType)
    __attribute__((no_sanitize("cfi")))
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::SetSmoothZoom Session is not commited");
    int32_t minIndex = 0;
    int32_t maxIndex = 1;
    std::vector<float> zoomRange = GetZoomRatioRange();
    CHECK_RETURN_RET_ELOG(
        zoomRange.empty(), CameraErrorCode::SUCCESS, "CaptureSession::SetSmoothZoom Zoom range is empty");
    float tempZoomRatio = std::clamp(targetZoomRatio, zoomRange[minIndex], zoomRange[maxIndex]);
    MEDIA_DEBUG_LOG("origin zoomRatioValue: %{public}f, after clamp value: %{public}f", targetZoomRatio, tempZoomRatio);
    targetZoomRatio = tempZoomRatio;
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    float duration;
    auto captureSession = GetCaptureSession();
    if (captureSession) {
        MEDIA_INFO_LOG("CaptureSession::SetSmoothZoom Zoom ratio: %{public}f", targetZoomRatio);
        errCode = captureSession->SetSmoothZoom(smoothZoomType, GetMode(), targetZoomRatio, duration);
        MEDIA_INFO_LOG("CaptureSession::SetSmoothZoom duration: %{public}f ", duration);
        if (errCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to SetSmoothZoom!, %{public}d", errCode);
        } else {
            std::shared_ptr<OHOS::Camera::CameraMetadata> changedMetadata =
                std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
            changedMetadata->addEntry(OHOS_CONTROL_SMOOTH_ZOOM_RATIOS, &targetZoomRatio, 1);
            OnSettingUpdated(changedMetadata);
            auto abilityContainer = GetCameraAbilityContainer();
            CHECK_EXECUTE(abilityContainer && supportSpecSearch_, abilityContainer->FilterByZoomRatio(targetZoomRatio));
            targetZoomRatio_ = targetZoomRatio;
            SetZoomRatioForAudio(targetZoomRatio);
        }
        std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
        if (smoothZoomCallback_ != nullptr && !(duration < 0.0f)) {
            smoothZoomCallback_->OnSmoothZoom(duration);
            MEDIA_INFO_LOG("CaptureSession::SetSmoothZoom duration: %{public}f ", duration);
        }
    } else {
        MEDIA_ERR_LOG("CaptureSession::SetSmoothZoom() captureSession is nullptr");
    }
    return CameraErrorCode::SUCCESS;
}

void CaptureSession::SetSmoothZoomCallback(std::shared_ptr<SmoothZoomCallback> smoothZoomCallback)
{
    MEDIA_INFO_LOG("CaptureSession::SetSmoothZoomCallback() set smooth zoom callback");
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    smoothZoomCallback_ = smoothZoomCallback;
    return;
}

void CaptureSession::SetCaptureMetadataObjectTypes(std::set<camera_face_detect_mode_t> metadataObjectTypes)
{
    MEDIA_INFO_LOG("CaptureSession SetCaptureMetadataObjectTypes Enter");
    CHECK_RETURN_ELOG(GetInputDevice() == nullptr, "SetCaptureMetadataObjectTypes: inputDevice is null");
    uint32_t count = 1;
    uint8_t objectType = OHOS_CAMERA_FACE_DETECT_MODE_SIMPLE;
    if (!metadataObjectTypes.count(OHOS_CAMERA_FACE_DETECT_MODE_SIMPLE)) {
        objectType = OHOS_CAMERA_FACE_DETECT_MODE_OFF;
        MEDIA_ERR_LOG("CaptureSession SetCaptureMetadataObjectTypes Can not set face detect mode!");
    }
    this->LockForControl();
    bool res = this->changedMetadata_->addEntry(OHOS_STATISTICS_FACE_DETECT_SWITCH, &objectType, count);
    CHECK_PRINT_ELOG(!res, "SetCaptureMetadataObjectTypes Failed to add detect object types to changed metadata");
    this->UnlockForControl();
}

void CaptureSession::SetGuessMode(SceneMode mode)
{
    CHECK_RETURN(currentMode_ != SceneMode::NORMAL);
    switch (mode) {
        case CAPTURE:
            if (guessMode_ == SceneMode::NORMAL) {
                guessMode_ = CAPTURE;
            }
            break;
        case VIDEO:
            if (guessMode_ != SceneMode::VIDEO) {
                guessMode_ = VIDEO;
            }
            break;
        default:
            MEDIA_WARNING_LOG("CaptureSession::SetGuessMode not support this guest mode:%{public}d", mode);
            break;
    }
    MEDIA_INFO_LOG(
        "CaptureSession::SetGuessMode currentMode_:%{public}d guessMode_:%{public}d", currentMode_, guessMode_);
}

void CaptureSession::SetMode(SceneMode modeName)
{
    CHECK_RETURN_ELOG(IsSessionCommited(), "CaptureSession::SetMode Session has been Commited");
    currentMode_ = modeName;
    // reset deferred enable status when reset mode
    EnableDeferredType(DELIVERY_NONE, false);
    auto captureSession = GetCaptureSession();
    if (captureSession) {
        captureSession->SetFeatureMode(modeName);
        MEDIA_INFO_LOG("CaptureSession::SetSceneMode  SceneMode = %{public}d", modeName);
    } else {
        MEDIA_ERR_LOG("CaptureSession::SetMode captureSession is nullptr");
        return;
    }
    MEDIA_INFO_LOG("CaptureSession SetMode modeName = %{public}d", modeName);
}

SceneMode CaptureSession::GetMode()
{
    MEDIA_DEBUG_LOG(
        "CaptureSession GetMode currentMode_ = %{public}d, guestMode_ = %{public}d", currentMode_, guessMode_);
    return currentMode_ == SceneMode::NORMAL ? guessMode_ : currentMode_;
}

bool CaptureSession::IsImageDeferred()
{
    MEDIA_INFO_LOG("CaptureSession IsImageDeferred");
    return isImageDeferred_;
}

bool CaptureSession::IsVideoDeferred()
{
    MEDIA_INFO_LOG("CaptureSession IsVideoDeferred:%{public}d", isVideoDeferred_);
    return isVideoDeferred_;
}

SceneFeaturesMode CaptureSession::GetFeaturesMode()
{
    SceneFeaturesMode sceneFeaturesMode;
    sceneFeaturesMode.SetSceneMode(GetMode());
    sceneFeaturesMode.SwitchFeature(FEATURE_MACRO, isSetMacroEnable_);
    sceneFeaturesMode.SwitchFeature(FEATURE_MOON_CAPTURE_BOOST, isSetMoonCaptureBoostEnable_);
    sceneFeaturesMode.SwitchFeature(FEATURE_LOW_LIGHT_BOOST, isSetLowLightBoostEnable_);
    sceneFeaturesMode.SwitchFeature(FEATURE_TRIPOD_DETECTION, isSetTripodDetectionEnable_);
    sceneFeaturesMode.SwitchFeature(FEATURE_CONSTELLATION_DRAWING, isSetConstellationDrawingEnable_);
    sceneFeaturesMode.SwitchFeature(FEATURE_SUPER_MOON, isSetSuperMoonEnable_);
    return sceneFeaturesMode;
}

vector<SceneFeaturesMode> CaptureSession::GetSubFeatureMods()
{
    vector<SceneFeaturesMode> sceneFeaturesModes {};
    auto mode = GetMode();
    sceneFeaturesModes.emplace_back(SceneFeaturesMode(mode, {}));
    if (mode == SceneMode::CAPTURE) {
        sceneFeaturesModes.emplace_back(SceneFeaturesMode(SceneMode::CAPTURE, { SceneFeature::FEATURE_MACRO }));
        sceneFeaturesModes.emplace_back(
            SceneFeaturesMode(SceneMode::CAPTURE, { SceneFeature::FEATURE_MOON_CAPTURE_BOOST }));
    } else if (mode == SceneMode::VIDEO) {
        sceneFeaturesModes.emplace_back(
            SceneFeaturesMode(SceneMode::VIDEO, std::set<SceneFeature> { SceneFeature::FEATURE_MACRO }));
    } else if (mode == SceneMode::NIGHT && isSetSuperMoonEnable_) {
        MEDIA_INFO_LOG("CaptureSession::GetSubFeatureMods moon ");
        sceneFeaturesModes.emplace_back(
            SceneFeaturesMode(SceneMode::NIGHT, std::set<SceneFeature> { SceneFeature::FEATURE_SUPER_MOON }));
    }
    return sceneFeaturesModes;
}

int32_t CaptureSession::VerifyAbility(uint32_t ability)
{
    SceneMode matchMode = SceneMode::NORMAL;
    std::vector<SceneMode> supportModes = {SceneMode::VIDEO, SceneMode::PORTRAIT, SceneMode::NIGHT,
        SceneMode::QUICK_SHOT_PHOTO };
    auto mode = std::find(supportModes.begin(), supportModes.end(), GetMode());
    if (mode != supportModes.end()) {
        matchMode = *mode;
    } else {
        MEDIA_ERR_LOG("CaptureSession::VerifyAbility need PortraitMode or Night or Video");
        return CAMERA_INVALID_ARG;
    }
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CAMERA_INVALID_ARG,
        "CaptureSession::VerifyAbility camera device is null");

    ProcessProfilesAbilityId(matchMode);

    std::vector<uint32_t> photoAbilityId = previewProfile_.GetAbilityId();
    std::vector<uint32_t> previewAbilityId = previewProfile_.GetAbilityId();

    auto itrPhoto = std::find(photoAbilityId.begin(), photoAbilityId.end(), ability);
    auto itrPreview = std::find(previewAbilityId.begin(), previewAbilityId.end(), ability);
    CHECK_RETURN_RET_ELOG(itrPhoto == photoAbilityId.end() || itrPreview == previewAbilityId.end(), CAMERA_INVALID_ARG,
        "CaptureSession::VerifyAbility abilityId is NULL");
    return CAMERA_OK;
}

void CaptureSession::ProcessProfilesAbilityId(const SceneMode supportModes)
{
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_ELOG(!inputDevice, "ProcessProfilesAbilityId inputDevice is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_ELOG(!inputDeviceInfo, "ProcessProfilesAbilityId inputDeviceInfo is null");
    std::vector<Profile> photoProfiles = inputDeviceInfo->modePhotoProfiles_[supportModes];
    std::vector<Profile> previewProfiles = inputDeviceInfo->modePreviewProfiles_[supportModes];
    MEDIA_DEBUG_LOG("photoProfiles size = %{public}zu, previewProfiles size = %{public}zu", photoProfiles.size(),
        previewProfiles.size());
    for (auto i : photoProfiles) {
        std::vector<uint32_t> ids = i.GetAbilityId();
        std::string abilityIds = Container2String(ids.begin(), ids.end());
        MEDIA_DEBUG_LOG("photoProfiles f(%{public}d), w(%{public}d), h(%{public}d), ability:(%{public}s)",
            i.GetCameraFormat(), i.GetSize().width, i.GetSize().height, abilityIds.c_str());
        bool isFindAbilityId = i.GetCameraFormat() == photoProfile_.GetCameraFormat() &&
            i.GetSize().width == photoProfile_.GetSize().width && i.GetSize().height == photoProfile_.GetSize().height;
        if (isFindAbilityId) {
            CHECK_CONTINUE_ILOG(
                i.GetAbilityId().empty(), "VerifyAbility::CreatePhotoOutput:: this size'abilityId is not exist");
            photoProfile_.abilityId_ = i.GetAbilityId();
            break;
        }
    }
    for (auto i : previewProfiles) {
        std::vector<uint32_t> ids = i.GetAbilityId();
        std::string abilityIds = Container2String(ids.begin(), ids.end());
        MEDIA_DEBUG_LOG("previewProfiles f(%{public}d), w(%{public}d), h(%{public}d), ability:(%{public}s)",
            i.GetCameraFormat(), i.GetSize().width, i.GetSize().height, abilityIds.c_str());
        bool isFindAbilityId = i.GetCameraFormat() == previewProfile_.GetCameraFormat() &&
            i.GetSize().width == previewProfile_.GetSize().width &&
            i.GetSize().height == previewProfile_.GetSize().height;
        if (isFindAbilityId) {
            CHECK_CONTINUE_ILOG(
                i.GetAbilityId().empty(), "VerifyAbility::CreatePreviewOutput:: this size'abilityId is not exist");
            previewProfile_.abilityId_ = i.GetAbilityId();
            break;
        }
    }
}

std::vector<FilterType> CaptureSession::GetSupportedFilters()
{
    std::vector<FilterType> supportedFilters = {};
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), supportedFilters,
        "CaptureSession::GetSupportedFilters Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), supportedFilters,
        "CaptureSession::GetSupportedFilters camera device is null");

    int ret = VerifyAbility(static_cast<uint32_t>(OHOS_ABILITY_SCENE_FILTER_TYPES));
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, supportedFilters,
        "CaptureSession::GetSupportedFilters abilityId is NULL");
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, supportedFilters, "GetSupportedFilters camera metadata is null");
    camera_metadata_item_t item;
    ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_SCENE_FILTER_TYPES, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count == 0, supportedFilters,
        "CaptureSession::GetSupportedFilters Failed with return code %{public}d", ret);
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = metaFilterTypeMap_.find(static_cast<camera_filter_type_t>(item.data.u8[i]));
        if (itr != metaFilterTypeMap_.end()) {
            supportedFilters.emplace_back(itr->second);
        }
    }
    return supportedFilters;
}

FilterType CaptureSession::GetFilter()
{
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), FilterType::NONE,
        "CaptureSession::GetFilter Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), FilterType::NONE,
        "CaptureSession::GetFilter camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, FilterType::NONE, "GetFilter camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_FILTER_TYPE, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count == 0, FilterType::NONE,
        "CaptureSession::GetFilter Failed with return code %{public}d", ret);
    auto itr = metaFilterTypeMap_.find(static_cast<camera_filter_type_t>(item.data.u8[0]));
    return itr != metaFilterTypeMap_.end() ? itr->second : FilterType::NONE;
}

void CaptureSession::SetFilter(FilterType filterType)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_ELOG(
        !(IsSessionCommited() || IsSessionConfiged()), "CaptureSession::SetFilter Session is not Commited");
    CHECK_RETURN_ELOG(changedMetadata_ == nullptr,
        "CaptureSession::SetFilter Need to call LockForControl() before setting camera properties");

    std::vector<FilterType> supportedFilters = GetSupportedFilters();
    auto itr = std::find(supportedFilters.begin(), supportedFilters.end(), filterType);
    CHECK_RETURN_ELOG(itr == supportedFilters.end(), "CaptureSession::GetSupportedFilters abilityId is NULL");
    uint8_t filter = 0;
    for (auto itr2 = fwkFilterTypeMap_.cbegin(); itr2 != fwkFilterTypeMap_.cend(); itr2++) {
        if (filterType == itr2->first) {
            filter = static_cast<uint8_t>(itr2->second);
            break;
        }
    }
    MEDIA_DEBUG_LOG("CaptureSession::setFilter: %{public}d", filterType);
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_FILTER_TYPE, &filter, 1);
    CHECK_PRINT_ELOG(!status, "CaptureSession::setFilter Failed to set filter");
    return;
}

std::vector<BeautyType> CaptureSession::GetSupportedBeautyTypes()
{
    std::vector<BeautyType> supportedBeautyTypes = {};
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), supportedBeautyTypes,
        "CaptureSession::GetSupportedBeautyTypes Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), supportedBeautyTypes,
        "CaptureSession::GetSupportedBeautyTypes camera device is null");

    int ret = VerifyAbility(static_cast<uint32_t>(OHOS_ABILITY_SCENE_BEAUTY_TYPES));
    CHECK_RETURN_RET_ELOG(
        ret != CAMERA_OK, supportedBeautyTypes, "CaptureSession::GetSupportedBeautyTypes abilityId is NULL");
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, supportedBeautyTypes, "GetSupportedBeautyTypes camera metadata is null");
    camera_metadata_item_t item;
    ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_SCENE_BEAUTY_TYPES, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count == 0, supportedBeautyTypes,
        "CaptureSession::GetSupportedBeautyTypes Failed with return code %{public}d", ret);
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = g_metaBeautyTypeMap_.find(static_cast<camera_beauty_type_t>(item.data.u8[i]));
        if (itr != g_metaBeautyTypeMap_.end()) {
            supportedBeautyTypes.emplace_back(itr->second);
        }
    }
    return supportedBeautyTypes;
}

std::vector<int32_t> CaptureSession::GetSupportedBeautyRange(BeautyType beautyType)
{
    int ret = 0;
    std::vector<int32_t> supportedBeautyRange;
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), supportedBeautyRange,
        "CaptureSession::GetSupportedBeautyRange Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), supportedBeautyRange,
        "CaptureSession::GetSupportedBeautyRange camera device is null");

    std::vector<BeautyType> supportedBeautyTypes = GetSupportedBeautyTypes();
    CHECK_RETURN_RET_ELOG(
        std::find(supportedBeautyTypes.begin(), supportedBeautyTypes.end(), beautyType) == supportedBeautyTypes.end(),
        supportedBeautyRange, "CaptureSession::GetSupportedBeautyRange beautyType is NULL");
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, supportedBeautyRange, "GetSupportedBeautyRange camera metadata is null");
    camera_metadata_item_t item;

    MEDIA_ERR_LOG("CaptureSession::GetSupportedBeautyRange: %{public}d", beautyType);

    int32_t beautyTypeAbility;
    auto itr = g_fwkBeautyAbilityMap_.find(beautyType);
    CHECK_RETURN_RET_ELOG(itr == g_fwkBeautyAbilityMap_.end(), supportedBeautyRange,
        "CaptureSession::GetSupportedBeautyRange Unknown beauty Type");
    beautyTypeAbility = itr->second;
    Camera::FindCameraMetadataItem(metadata->get(), beautyTypeAbility, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count == 0, supportedBeautyRange,
        "CaptureSession::GetSupportedBeautyRange Failed with return code %{public}d", ret);
    if (beautyType == SKIN_TONE) {
        int32_t skinToneOff = -1;
        supportedBeautyRange.push_back(skinToneOff);
    }
    for (uint32_t i = 0; i < item.count; i++) {
        if (beautyTypeAbility == OHOS_ABILITY_BEAUTY_SKIN_TONE_VALUES) {
            supportedBeautyRange.emplace_back(item.data.i32[i]);
        } else {
            supportedBeautyRange.emplace_back(item.data.u8[i]);
        }
    }
    beautyTypeAndRanges_[beautyType] = supportedBeautyRange;
    return supportedBeautyRange;
}

bool CaptureSession::SetBeautyValue(BeautyType beautyType, int32_t beautyLevel)
{
    camera_device_metadata_tag_t metadata;
    auto metaItr = fwkBeautyControlMap_.find(beautyType);
    if (metaItr != fwkBeautyControlMap_.end()) {
        metadata = metaItr->second;
    }

    std::vector<int32_t> levelVec =
        beautyTypeAndRanges_.count(beautyType) ? beautyTypeAndRanges_[beautyType] : GetSupportedBeautyRange(beautyType);

    bool status = false;
    CameraPosition usedAsCameraPosition = GetUsedAsPosition();
    MEDIA_INFO_LOG("CaptureSession::SetBeautyValue usedAsCameraPosition %{public}d", usedAsCameraPosition);
    if (CAMERA_POSITION_UNSPECIFIED == usedAsCameraPosition) {
        auto itrType = std::find(levelVec.cbegin(), levelVec.cend(), beautyLevel);
        CHECK_RETURN_RET_ELOG(itrType == levelVec.end(), status,
            "CaptureSession::SetBeautyValue: %{public}d not in beautyRanges", beautyLevel);
    }
    if (beautyType == BeautyType::SKIN_TONE) {
        int32_t skinToneVal = beautyLevel;
        status = AddOrUpdateMetadata(changedMetadata_, metadata, &skinToneVal, 1);
    } else {
        uint8_t beautyVal = static_cast<uint8_t>(beautyLevel);
        status = AddOrUpdateMetadata(changedMetadata_, metadata, &beautyVal, 1);
    }
    CHECK_RETURN_RET_ELOG(!status, status, "CaptureSession::SetBeautyValue Failed to set beauty");
    beautyTypeAndLevels_[beautyType] = beautyLevel;
    return status;
}

CameraPosition CaptureSession::GetUsedAsPosition()
{
    CameraPosition usedAsCameraPosition = CAMERA_POSITION_UNSPECIFIED;
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        inputDevice == nullptr, usedAsCameraPosition, "CaptureSession::GetUsedAsPosition input device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(inputDeviceInfo == nullptr, usedAsCameraPosition,
        "CaptureSession::GetUsedAsPosition camera device info is null");
    usedAsCameraPosition = inputDeviceInfo->usedAsCameraPosition_;
    return usedAsCameraPosition;
}

int32_t CaptureSession::CheckCommonPreconditions(bool isSystemApp, bool isAfterSessionCommited)
{
    CHECK_RETURN_RET_ELOG(isSystemApp && !CameraSecurity::CheckSystemApp(), CameraErrorCode::OPERATION_NOT_ALLOWED,
        "SystemApi check fail");
    CHECK_RETURN_RET_ELOG(
        isAfterSessionCommited && !IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG, "Session is not commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice, CameraErrorCode::DEVICE_DISABLED, "Camera device is nullptr");
    CHECK_RETURN_RET_ELOG(
        !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::DEVICE_DISABLED, "Camera deviceInfo is nullptr");
    return CameraErrorCode::SUCCESS;
}

void CaptureSession::SetBeauty(BeautyType beautyType, int value)
{
    CHECK_RETURN_ELOG(
        !(IsSessionCommited() || IsSessionConfiged()), "CaptureSession::SetBeauty Session is not Commited");
    CHECK_RETURN_ELOG(changedMetadata_ == nullptr, "CaptureSession::SetBeauty changedMetadata_ is NULL");

    CameraPosition usedAsCameraPosition = GetUsedAsPosition();
    MEDIA_INFO_LOG("CaptureSession::SetBeauty usedAsCameraPosition %{public}d", usedAsCameraPosition);
    if (CAMERA_POSITION_UNSPECIFIED == usedAsCameraPosition) {
        std::vector<BeautyType> supportedBeautyTypes = GetSupportedBeautyTypes();
        auto itr = std::find(supportedBeautyTypes.begin(), supportedBeautyTypes.end(), beautyType);
        CHECK_RETURN_ELOG(
            itr == supportedBeautyTypes.end(), "CaptureSession::GetSupportedBeautyTypes abilityId is NULL");
    }
    MEDIA_ERR_LOG("SetBeauty beautyType %{public}d", beautyType);
    uint8_t beauty = OHOS_CAMERA_BEAUTY_TYPE_OFF;
    bool isAutoType = beautyType == AUTO_TYPE && value == 0;
    if (isAutoType) {
        bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_BEAUTY_TYPE, &beauty, 1);
        status = SetBeautyValue(beautyType, value);
        CHECK_PRINT_ELOG(!status, "CaptureSession::SetBeauty AUTO_TYPE Failed to set beauty value");
        return;
    }

    auto itrType = g_fwkBeautyTypeMap_.find(beautyType);
    if (itrType != g_fwkBeautyTypeMap_.end()) {
        beauty = static_cast<uint8_t>(itrType->second);
    }

    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_BEAUTY_TYPE, &beauty, 1);
    CHECK_PRINT_ELOG(!status, "CaptureSession::SetBeauty Failed to set beautyType control");
    status = SetBeautyValue(beautyType, value);
    CHECK_PRINT_ELOG(!status, "CaptureSession::SetBeauty Failed to set beauty value");
    return;
}

int32_t CaptureSession::GetSupportedPortraitThemeTypes(std::vector<PortraitThemeType>& supportedPortraitThemeTypes)
{
    MEDIA_DEBUG_LOG("Enter CaptureSession::GetSupportedPortraitThemeTypes");
    supportedPortraitThemeTypes.clear();
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::GetSupportedPortraitThemeTypes Session is not Commited.");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::GetSupportedPortraitThemeTypes camera device is null");
    auto deviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(deviceInfo == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::GetSupportedPortraitThemeTypes camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = deviceInfo->GetCachedMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, CameraErrorCode::SUCCESS, "GetSupportedPortraitThemeTypes camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_CAMERA_PORTRAIT_THEME_TYPES, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count == 0, CameraErrorCode::SUCCESS,
        "CaptureSession::GetSupportedPortraitThemeTypes Failed with return code %{public}d", ret);
    g_transformValidData(item, g_metaPortraitThemeTypeMap_, supportedPortraitThemeTypes);
    return CameraErrorCode::SUCCESS;
}

bool CaptureSession::IsPortraitThemeSupported()
{
    bool isSupported;
    IsPortraitThemeSupported(isSupported);
    return isSupported;
}

int32_t CaptureSession::IsPortraitThemeSupported(bool &isSupported)
{
    MEDIA_DEBUG_LOG("Enter CaptureSession::IsPortraitThemeSupported");
    isSupported = false;
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::IsPortraitThemeSupported Session is not Commited.");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::IsPortraitThemeSupported camera device is null");
    auto deviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(deviceInfo == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::IsPortraitThemeSupported camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = deviceInfo->GetCachedMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, CameraErrorCode::SUCCESS, "IsPortraitThemeSupported camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_CAMERA_PORTRAIT_THEME_SUPPORTED, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count <= 0, CameraErrorCode::SUCCESS,
        "CaptureSession::IsPortraitThemeSupported Failed with return code %{public}d", ret);
    isSupported = static_cast<bool>(item.data.u8[0]);
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::GetSupportedVideoRotations(std::vector<int32_t>& supportedRotation)
{
    MEDIA_DEBUG_LOG("Enter CaptureSession::GetSupportedVideoRotations");
    supportedRotation.clear();
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::GetSupportedVideoRotations Session is not Commited.");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::GetSupportedVideoRotations camera device is null");
    auto deviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(deviceInfo == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::GetSupportedVideoRotations camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = deviceInfo->GetCachedMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, CameraErrorCode::SUCCESS, "GetSupportedVideoRotations camera metadata is null");
    camera_metadata_item_t item;
    int32_t ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_CAMERA_VIDEO_ROTATION, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count == 0, CameraErrorCode::SUCCESS,
        "CaptureSession::GetSupportedVideoRotations Failed with return code %{public}d", ret);
    for (uint32_t i = 0; i < item.count; i++) {
        auto rotation = static_cast<VideoRotation>(item.data.i32[i]);
        auto it = std::find(g_fwkVideoRotationVector_.begin(), g_fwkVideoRotationVector_.end(), rotation);
        if (it != g_fwkVideoRotationVector_.end()) {
            supportedRotation.emplace_back(static_cast<int32_t>(*it));
        }
    }
    return CameraErrorCode::SUCCESS;
}

bool CaptureSession::IsVideoRotationSupported()
{
    bool isSupported;
    IsVideoRotationSupported(isSupported);
    return isSupported;
}

int32_t CaptureSession::IsVideoRotationSupported(bool &isSupported)
{
    MEDIA_DEBUG_LOG("Enter CaptureSession::IsVideoRotationSupported");
    isSupported = false;
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::IsVideoRotationSupported Session is not Commited.");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::IsVideoRotationSupported camera device is null");
    auto deviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(deviceInfo == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::IsVideoRotationSupported camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = deviceInfo->GetCachedMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, CameraErrorCode::SUCCESS, "IsVideoRotationSupported camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_CAMERA_VIDEO_ROTATION_SUPPORTED, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count <= 0, CameraErrorCode::SUCCESS,
        "CaptureSession::IsVideoRotationSupported Failed with return code %{public}d", ret);
    isSupported = static_cast<bool>(item.data.u8[0]);
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetVideoRotation(int32_t rotation)
{
    MEDIA_DEBUG_LOG("Enter CaptureSession::SetVideoRotation");
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::SetVideoRotation Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::SetVideoRotation Need to call LockForControl() before setting camera properties");
    CHECK_RETURN_RET(!IsVideoRotationSupported(), CameraErrorCode::OPERATION_NOT_ALLOWED);
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_CAMERA_VIDEO_ROTATION, &rotation, 1);
    CHECK_PRINT_ELOG(!status, "CaptureSession::SetVideoRotation Failed to set flash mode");
    return CameraErrorCode::SUCCESS;
}

// focus distance
float CaptureSession::GetMinimumFocusDistance() __attribute__((no_sanitize("cfi")))
{
    float invalidDistance = 0.0;
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        !inputDevice, invalidDistance, "CaptureSession::GetMinimumFocusDistance camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(
        !inputDeviceInfo, invalidDistance, "CaptureSession::GetMinimumFocusDistance camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetCachedMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, invalidDistance, "GetMinimumFocusDistance camera metadata is null");
    camera_metadata_item_t item;
    int32_t ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_LENS_INFO_MINIMUM_FOCUS_DISTANCE, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, invalidDistance,
        "CaptureSession::GetMinimumFocusDistance Failed with return code %{public}d", ret);
    float minimumFocusDistance = item.data.f[0];
    MEDIA_DEBUG_LOG("CaptureSession::GetMinimumFocusDistance minimumFocusDistance=%{public}f", minimumFocusDistance);
    return minimumFocusDistance;
}

void CaptureSession::ProcessFocusDistanceUpdates(const std::shared_ptr<Camera::CameraMetadata>& result)
{
    CHECK_RETURN_ELOG(!result, "CaptureSession::ProcessFocusDistanceUpdates camera metadata is null");
    camera_metadata_item_t item;
    int32_t ret = Camera::FindCameraMetadataItem(result->get(), OHOS_CONTROL_LENS_FOCUS_DISTANCE, &item);
    CHECK_RETURN_DLOG(
        ret != CAM_META_SUCCESS, "CaptureSession::ProcessFocusDistanceUpdates Failed with return code %{public}d", ret);
    MEDIA_DEBUG_LOG("CaptureSession::ProcessFocusDistanceUpdates meta=%{public}f", item.data.f[0]);
    CHECK_RETURN(FloatIsEqual(GetMinimumFocusDistance(), 0.0));
    focusDistance_ = 1.0 - (item.data.f[0] / GetMinimumFocusDistance());
    MEDIA_DEBUG_LOG("CaptureSession::ProcessFocusDistanceUpdates focusDistance = %{public}f", focusDistance_);
    return;
}

int32_t CaptureSession::SetFocusDistance(float focusDistance)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::SetFocusDistance Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::SetFocusDistance Need to call LockForControl before setting camera properties");
    MEDIA_DEBUG_LOG("CaptureSession::SetFocusDistance app set focusDistance = %{public}f", focusDistance);
    if (focusDistance < 0) {
        focusDistance = 0.0;
    } else if (focusDistance > 1) {
        focusDistance = 1.0;
    }
    float value = (1 - focusDistance) * GetMinimumFocusDistance();
    focusDistance_ = focusDistance;
    MEDIA_DEBUG_LOG("CaptureSession::SetFocusDistance meta set focusDistance = %{public}f", value);
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_LENS_FOCUS_DISTANCE, &value, 1);
    wptr<CaptureSession> weakThis(this);
    CHECK_EXECUTE(status, AddFunctionToMap(std::to_string(OHOS_CONTROL_LENS_FOCUS_DISTANCE),
        [weakThis, focusDistance]() {
            auto sharedThis = weakThis.promote();
            CHECK_RETURN_ELOG(!sharedThis, "SetFocusDistance session is nullptr");
            sharedThis->LockForControl();
            int32_t retCode = sharedThis->SetFocusDistance(focusDistance);
            sharedThis->UnlockForControl();
            CHECK_EXECUTE(retCode != CameraErrorCode::SUCCESS, sharedThis->SetDeviceCapabilityChangeStatus(true));
        }));
    CHECK_PRINT_ELOG(!status, "CaptureSession::SetFocusDistance Failed to set");
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetFrameRateRange(const std::vector<int32_t>& frameRateRange)
{
    std::vector<int32_t> videoFrameRateRange = frameRateRange;
    this->LockForControl();
    bool isSuccess = this->changedMetadata_->addEntry(
        OHOS_CONTROL_FPS_RANGES, videoFrameRateRange.data(), videoFrameRateRange.size());
    wptr<CaptureSession> weakThis(this);
    CHECK_EXECUTE(isSuccess, AddFunctionToMap("video" + std::to_string(OHOS_CONTROL_FPS_RANGES),
        [weakThis, frameRateRange]() {
            auto sharedThis = weakThis.promote();
            CHECK_RETURN_ELOG(!sharedThis, "SetFrameRateRange session is nullptr");
            int32_t retCode = sharedThis->SetFrameRateRange(frameRateRange);
            CHECK_EXECUTE(retCode != CameraErrorCode::SUCCESS, sharedThis->SetDeviceCapabilityChangeStatus(true));
        }));
    bool frameCondition = true;
    for (size_t i = 0; i < frameRateRange.size(); i++) {
        MEDIA_DEBUG_LOG("CaptureSession::SetFrameRateRange:index:%{public}zu->%{public}d", i, frameRateRange[i]);
        if (frameRateRange[i] > CONTROL_CENTER_FPS_MAX) {
            frameCondition = false;
        }
    }
    CameraManager::GetInstance()->SetControlCenterFrameCondition(frameCondition);
    this->UnlockForControl();
    CHECK_RETURN_RET_ELOG(!isSuccess, CameraErrorCode::SERVICE_FATL_ERROR, "Failed to SetFrameRateRange ");
    return CameraErrorCode::SUCCESS;
}

bool CaptureSession::CanSetFrameRateRange(int32_t minFps, int32_t maxFps, CaptureOutput* curOutput)
{
    MEDIA_WARNING_LOG("CaptureSession::CanSetFrameRateRange can not set frame rate range for %{public}d mode",
                      GetMode());
    return false;
}

bool CaptureSession::CanSetFrameRateRangeForOutput(int32_t minFps, int32_t maxFps, CaptureOutput* curOutput)
{
    std::lock_guard<std::mutex> lock(captureOutputSetsMutex_);
    int32_t defaultFpsNumber = 0;
    int32_t minFpsIndex = 0;
    int32_t maxFpsIndex = 1;
    for (auto output : captureOutputSets_) {
        auto item = output.promote();
        CHECK_CONTINUE(static_cast<CaptureOutput*>(item.GetRefPtr()) == curOutput);
        std::vector<int32_t> currentFrameRange = {defaultFpsNumber, defaultFpsNumber};
        switch (output->GetOutputType()) {
            case CaptureOutputType::CAPTURE_OUTPUT_TYPE_VIDEO: {
                sptr<VideoOutput> videoOutput = (sptr<VideoOutput>&)item;
                currentFrameRange = videoOutput->GetFrameRateRange();
                break;
            }
            case CaptureOutputType::CAPTURE_OUTPUT_TYPE_PREVIEW: {
                sptr<PreviewOutput> previewOutput = (sptr<PreviewOutput>&)item;
                currentFrameRange = previewOutput->GetFrameRateRange();
                break;
            }
            default:
                continue;
        }
        bool isRangeConflict =
            currentFrameRange[minFpsIndex] != defaultFpsNumber && currentFrameRange[maxFpsIndex] != defaultFpsNumber;
        if (isRangeConflict) {
            MEDIA_DEBUG_LOG("The frame rate range conflict needs to be checked.");
            if (!CheckFrameRateRangeWithCurrentFps(currentFrameRange[minFpsIndex],
                                                   currentFrameRange[maxFpsIndex],
                                                   minFps, maxFps)) {
                return false;
            };
        }
    }
    return true;
}

bool CaptureSession::IsSessionConfiged()
{
    bool isSessionConfiged = false;
    auto captureSession = GetCaptureSession();
    if (captureSession) {
        CaptureSessionState currentState;
        captureSession->GetSessionState(currentState);
        isSessionConfiged = (currentState == CaptureSessionState::SESSION_CONFIG_INPROGRESS);
    } else {
        MEDIA_ERR_LOG("CaptureSession::IsSessionConfiged captureSession is nullptr");
    }
    return isSessionConfiged;
}

bool CaptureSession::IsSessionCommited()
{
    bool isCommitConfig = false;
    auto captureSession = GetCaptureSession();
    if (captureSession) {
        CaptureSessionState currentState;
        captureSession->GetSessionState(currentState);
        isCommitConfig = (currentState == CaptureSessionState::SESSION_CONFIG_COMMITTED)
            || (currentState == CaptureSessionState::SESSION_STARTED);
    } else {
        MEDIA_ERR_LOG("CaptureSession::IsSessionCommited captureSession is nullptr");
    }
    return isCommitConfig;
}

bool CaptureSession::IsSessionStarted()
{
    bool isStarted = false;
    auto captureSession = GetCaptureSession();
    if (captureSession) {
        CaptureSessionState currentState;
        captureSession->GetSessionState(currentState);
        isStarted = (currentState == CaptureSessionState::SESSION_STARTED);
    } else {
        MEDIA_ERR_LOG("CaptureSession::IsSessionStarted captureSession is nullptr");
    }
    return isStarted;
}

int32_t CaptureSession::CalculateExposureValue(float exposureValue)
{
    camera_metadata_item_t item;
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, CameraErrorCode::OPERATION_NOT_ALLOWED, "CalculateExposureValue camera metadata is null");
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_AE_COMPENSATION_STEP, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "CaptureSession::Get Ae Compensation step Failed with return code %{public}d", ret);

    int32_t stepNumerator = item.data.r->numerator;
    int32_t stepDenominator = item.data.r->denominator;
    float stepsPerEv = static_cast<float>(stepDenominator) / static_cast<float>(stepNumerator);
    MEDIA_DEBUG_LOG("Exposure step numerator: %{public}d, denominatormax: %{public}d, stepsPerEv: %{public}f",
        stepNumerator, stepDenominator, stepsPerEv);

    int32_t exposureCompensation = static_cast<int32_t>(stepsPerEv * exposureValue);
    MEDIA_DEBUG_LOG("exposureCompensation: %{public}d", exposureCompensation);
    return exposureCompensation;
}

ColorSpaceInfo CaptureSession::GetSupportedColorSpaceInfo()
{
    ColorSpaceInfo colorSpaceInfo = {};
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), colorSpaceInfo,
        "CaptureSession::GetSupportedColorSpaceInfo Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), colorSpaceInfo,
        "CaptureSession::GetSupportedColorSpaceInfo camera device is null");
    sptr<CameraDevice> cameraDevNow = inputDevice->GetCameraDeviceInfo();
    bool isLimtedCapabilitySave = cameraDevNow != nullptr && cameraDevNow->isConcurrentLimted_ == 1;
    CHECK_RETURN_RET(isLimtedCapabilitySave, cameraDevNow->limtedCapabilitySave_.colorspaces);
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, colorSpaceInfo, "GetSupportedColorSpaceInfo camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_AVAILABLE_COLOR_SPACES, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, colorSpaceInfo,
        "CaptureSession::GetSupportedColorSpaceInfo Failed, return code %{public}d", ret);
    std::shared_ptr<ColorSpaceInfoParse> colorSpaceParse = std::make_shared<ColorSpaceInfoParse>();
    colorSpaceParse->getColorSpaceInfo(item.data.i32, item.count, colorSpaceInfo); // 解析tag中带的色彩空间信息
    return colorSpaceInfo;
}

bool CheckColorSpaceForSystemApp(ColorSpace colorSpace, SceneMode sceneMode)
{
    return CameraSecurity::CheckSystemApp() ||
        !(colorSpace == ColorSpace::BT2020_HLG && sceneMode == SceneMode::CAPTURE);
}

std::vector<ColorSpace> CaptureSession::GetSupportedColorSpaces()
{
    std::vector<ColorSpace> supportedColorSpaces = {};

    if (IsSupportSpecSearch()) {
        MEDIA_INFO_LOG("spec search enter");
        auto abilityContainer = GetCameraAbilityContainer();
        if (abilityContainer) {
            supportedColorSpaces = abilityContainer->GetSupportedColorSpaces();
            std::string colorSpacesStr = Container2String(supportedColorSpaces.begin(), supportedColorSpaces.end());
            MEDIA_INFO_LOG("spec search result: %{public}s", colorSpacesStr.c_str());
        } else {
            MEDIA_ERR_LOG("spec search abilityContainer is null");
        }
        return supportedColorSpaces;
    }
    ColorSpaceInfo colorSpaceInfo = GetSupportedColorSpaceInfo();
    CHECK_RETURN_RET_ELOG(colorSpaceInfo.modeCount == 0, supportedColorSpaces,
        "CaptureSession::GetSupportedColorSpaces Failed, colorSpaceInfo is null");

    for (uint32_t i = 0; i < colorSpaceInfo.modeCount; i++) {
        CHECK_CONTINUE(GetMode() != colorSpaceInfo.modeInfo[i].modeType);
        MEDIA_DEBUG_LOG("CaptureSession::GetSupportedColorSpaces modeType %{public}d found.", GetMode());
        std::vector<int32_t> colorSpaces = colorSpaceInfo.modeInfo[i].streamInfo[0].colorSpaces;
        supportedColorSpaces.reserve(colorSpaces.size());
        for (uint32_t j = 0; j < colorSpaces.size(); j++) {
            auto itr = g_metaColorSpaceMap_.find(static_cast<CM_ColorSpaceType_V2_1>(colorSpaces[j]));
            CHECK_EXECUTE(itr != g_metaColorSpaceMap_.end() && CheckColorSpaceForSystemApp(itr->second, GetMode()),
                supportedColorSpaces.emplace_back(itr->second));
        }
        return supportedColorSpaces;
    }
    MEDIA_ERR_LOG("CaptureSession::GetSupportedColorSpaces no colorSpaces info for mode %{public}d", GetMode());
    return supportedColorSpaces;
}

bool CaptureSession::IsControlCenterSupported()
{
    bool isSupported = false;
    MEDIA_INFO_LOG("CaptureSession::IsControlCenterSupported");

    bool controlCenterPrecondition = CameraManager::GetInstance()->GetControlCenterPrecondition();
    CHECK_RETURN_RET_ELOG(
        !controlCenterPrecondition, false, "CaptureSession::IsControlCenterSupported controlCenterPrecondition false");

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, isSupported, "metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_CONTROL_CENTER_SUPPORTED, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count <= 0, isSupported,
        "CaptureSession::IsControlCenterSupported Failed with return code %{public}d", ret);
    isSupported = static_cast<bool>(item.data.u8[0]);
    CameraManager::GetInstance()->SetIsControlCenterSupported(isSupported);
    return isSupported;
}

std::vector<ControlCenterEffectType> CaptureSession::GetSupportedEffectTypes()
{
    std::vector<ControlCenterEffectType> supportedEffectType = {};
    bool isSupported = IsControlCenterSupported();
    CHECK_RETURN_RET_ELOG(!isSupported, {}, "Current status does not support control center.");
    MEDIA_INFO_LOG("CaptureSession::GetSupportedEffectTypes");
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, supportedEffectType, "metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_CONTROL_CENTER_EFFECT_TYPE, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count <= 0, supportedEffectType,
        "CaptureSession::GetSupportedEffectTypes Failed with return code %{public}d", ret);
    for (uint32_t i = 0; i < item.count; i++) {
        supportedEffectType.emplace_back(static_cast<ControlCenterEffectType>(item.data.u8[i]));
    }
    return supportedEffectType;
}

void CaptureSession::EnableControlCenter(bool isEnable)
{
    MEDIA_INFO_LOG("CaptureSession::EnableControlCenter: %{public}d", isEnable);
    bool isSupported = IsControlCenterSupported();
    CHECK_RETURN_ELOG(!isSupported, "Current status does not support control center.");
    auto serviceProxy = CameraManager::GetInstance()->GetServiceProxy();
    CHECK_RETURN_ELOG(serviceProxy == nullptr, "CaptureSession::EnableControlCenter serviceProxy is null");
    auto ret = serviceProxy->EnableControlCenter(isEnable, true);
    CHECK_RETURN_ELOG(ret != CAMERA_OK, "CaptureSession::EnableControlCenter failed.");
    isControlCenterEnabled_ = isEnable;
}

int32_t CaptureSession::GetActiveColorSpace(ColorSpace& colorSpace)
{
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::GetActiveColorSpace Session is not Commited");

    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    auto captureSession = GetCaptureSession();
    CHECK_RETURN_RET_ELOG(captureSession == nullptr, ServiceToCameraError(errCode),
        "CaptureSession::GetActiveColorSpace() captureSession is nullptr");
    int32_t curColorSpace = 0;
    errCode = captureSession->GetActiveColorSpace(curColorSpace);
    if (errCode != CAMERA_OK) {
        MEDIA_ERR_LOG("Failed to GetActiveColorSpace! %{public}d", errCode);
    } else {
        colorSpace = static_cast<ColorSpace>(curColorSpace);
        MEDIA_INFO_LOG("CaptureSession::GetActiveColorSpace %{public}d", colorSpace);
    }
    return ServiceToCameraError(errCode);
}

int32_t CaptureSession::SetColorSpace(ColorSpace colorSpace)
{
    HILOG_COMM_INFO("CaptureSession::SetColorSpace colorSpace: %{public}d", colorSpace);
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::SetColorSpace Session is not Commited");
    auto captureSession = GetCaptureSession();
    CHECK_RETURN_RET_ELOG(!captureSession, CameraErrorCode::SERVICE_FATL_ERROR,
        "CaptureSession::SetColorSpace() captureSession is nullptr");
    auto itr = g_fwkColorSpaceMap_.find(colorSpace);
    CHECK_RETURN_RET_ELOG(itr == g_fwkColorSpaceMap_.end(), CameraErrorCode::INVALID_ARGUMENT,
        "CaptureSession::SetColorSpace() map failed, %{public}d", static_cast<int32_t>(colorSpace));

    std::vector<ColorSpace> supportedColorSpaces = GetSupportedColorSpaces();
    auto curColorSpace = std::find(supportedColorSpaces.begin(), supportedColorSpaces.end(),
        colorSpace);
    CHECK_RETURN_RET_ELOG(curColorSpace == supportedColorSpaces.end(), CameraErrorCode::INVALID_ARGUMENT,
        "CaptureSession::SetColorSpace input colorSpace not found in supportedList.");
    if (IsSessionConfiged()) {
        isColorSpaceSetted_ = true;
    }

    // 若session还未commit，则后续createStreams会把色域带下去；否则，SetColorSpace要走updateStreams
    MEDIA_DEBUG_LOG("CaptureSession::SetColorSpace, IsSessionCommited %{public}d", IsSessionCommited());
    int32_t errCode = captureSession->SetColorSpace(static_cast<int32_t>(colorSpace), IsSessionCommited());
    CHECK_PRINT_ELOG(errCode != CAMERA_OK, "Failed to SetColorSpace!, %{public}d", errCode);
    return ServiceToCameraError(errCode);
}

std::vector<ColorEffect> CaptureSession::GetSupportedColorEffects()
{
    std::vector<ColorEffect> supportedColorEffects = {};
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), supportedColorEffects,
        "CaptureSession::GetSupportedColorEffects Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), supportedColorEffects,
        "CaptureSession::GetSupportedColorEffects camera device is null");
    if (IsSupportSpecSearch()) {
        MEDIA_INFO_LOG("spec search enter");
        auto abilityContainer = GetCameraAbilityContainer();
        if (abilityContainer) {
            supportedColorEffects = abilityContainer->GetSupportedColorEffects();
            std::string colorEffectsStr = Container2String(supportedColorEffects.begin(), supportedColorEffects.end());
            MEDIA_INFO_LOG("spec search result: %{public}s", colorEffectsStr.c_str());
        } else {
            MEDIA_ERR_LOG("spec search abilityContainer is null");
        }
        return supportedColorEffects;
    }

    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, supportedColorEffects, "GetSupportedColorEffects camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_SUPPORTED_COLOR_MODES, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, supportedColorEffects,
        "CaptureSession::GetSupportedColorEffects Failed with return code %{public}d", ret);
    int32_t currentMode = GetMode();
    for (uint32_t i = 0; i < item.count;) {
        int32_t mode = item.data.i32[i];
        i++;
        std::vector<ColorEffect> currentColorEffects = {};
        while (i < item.count && item.data.i32[i] != -1) {
            auto itr = g_metaColorEffectMap_.find(static_cast<camera_xmage_color_type_t>(item.data.i32[i]));
            if (itr != g_metaColorEffectMap_.end()) {
                currentColorEffects.emplace_back(itr->second);
            }
            i++;
        }
        i++;
        if (mode == 0) {
            supportedColorEffects = currentColorEffects;
        }
        if (mode == currentMode) {
            supportedColorEffects = currentColorEffects;
            break;
        }
    }
    return supportedColorEffects;
}

ColorEffect CaptureSession::GetColorEffect()
{
    ColorEffect colorEffect = ColorEffect::COLOR_EFFECT_NORMAL;
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), colorEffect,
        "CaptureSession::GetColorEffect Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), colorEffect,
        "CaptureSession::GetColorEffect camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, colorEffect, "GetColorEffect camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_SUPPORTED_COLOR_MODES, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count == 0, colorEffect,
        "CaptureSession::GetColorEffect Failed with return code %{public}d", ret);
    auto itr = g_metaColorEffectMap_.find(static_cast<camera_xmage_color_type_t>(item.data.u8[0]));
    if (itr != g_metaColorEffectMap_.end()) {
        colorEffect = itr->second;
    }
    return colorEffect;
}

int32_t CaptureSession::GetSensorExposureTimeRange(std::vector<uint32_t> &sensorExposureTimeRange)
{
    sensorExposureTimeRange.clear();
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::GetSensorExposureTimeRange Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::INVALID_ARGUMENT,
        "CaptureSession::GetSensorExposureTimeRange camera device is null");
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, CameraErrorCode::INVALID_ARGUMENT, "GetSensorExposureTimeRange camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_SENSOR_EXPOSURE_TIME_RANGE, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count == 0, CameraErrorCode::INVALID_ARGUMENT,
        "CaptureSession::GetSensorExposureTimeRange Failed with return code %{public}d", ret);

    int32_t numerator = 0;
    int32_t denominator = 0;
    uint32_t value = 0;
    constexpr int32_t timeUnit = 1000000;
    for (uint32_t i = 0; i < item.count; i++) {
        numerator = item.data.r[i].numerator;
        denominator = item.data.r[i].denominator;
        CHECK_RETURN_RET_ELOG(denominator == 0, CameraErrorCode::INVALID_ARGUMENT,
            "CaptureSession::GetSensorExposureTimeRange divide by 0! numerator=%{public}d", numerator);
        value = static_cast<uint32_t>(numerator / (denominator / timeUnit));
        MEDIA_DEBUG_LOG("CaptureSession::GetSensorExposureTimeRange numerator=%{public}d, denominator=%{public}d,"
                        " value=%{public}d", numerator, denominator, value);
        sensorExposureTimeRange.emplace_back(value);
    }
    MEDIA_INFO_LOG("CaptureSession::GetSensorExposureTimeRange range=%{public}s, len = %{public}zu",
                   Container2String(sensorExposureTimeRange.begin(), sensorExposureTimeRange.end()).c_str(),
                   sensorExposureTimeRange.size());
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetSensorExposureTime(uint32_t exposureTime)
{
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::SetSensorExposureTime Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::SetSensorExposureTime Need to call LockForControl() before setting camera properties");
    MEDIA_DEBUG_LOG("CaptureSession::SetSensorExposureTime exposure: %{public}d", exposureTime);
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::OPERATION_NOT_ALLOWED,
        "CaptureSession::SetSensorExposureTime camera device is null");
    std::vector<uint32_t> sensorExposureTimeRange;
    CHECK_RETURN_RET_ELOG((GetSensorExposureTimeRange(sensorExposureTimeRange) != CameraErrorCode::SUCCESS) &&
            sensorExposureTimeRange.empty(),
        CameraErrorCode::OPERATION_NOT_ALLOWED, "CaptureSession::SetSensorExposureTime range is empty");
    const uint32_t autoLongExposure = 0;
    int32_t minIndex = 0;
    int32_t maxIndex = 1;
    bool isMinTime = exposureTime != autoLongExposure && exposureTime < sensorExposureTimeRange[minIndex];
    if (isMinTime) {
        MEDIA_DEBUG_LOG("CaptureSession::SetSensorExposureTime exposureTime:"
                        "%{public}d is lesser than minimum exposureTime: %{public}d",
                        exposureTime, sensorExposureTimeRange[minIndex]);
        exposureTime = sensorExposureTimeRange[minIndex];
    } else if (exposureTime > sensorExposureTimeRange[maxIndex]) {
        MEDIA_DEBUG_LOG("CaptureSession::SetSensorExposureTime exposureTime: "
                        "%{public}d is greater than maximum exposureTime: %{public}d",
                        exposureTime, sensorExposureTimeRange[maxIndex]);
        exposureTime = sensorExposureTimeRange[maxIndex];
    }
    constexpr int32_t timeUnit = 1000000;
    camera_rational_t value = {.numerator = exposureTime, .denominator = timeUnit};
    bool res = AddOrUpdateMetadata(changedMetadata_->get(), OHOS_CONTROL_SENSOR_EXPOSURE_TIME, &value, 1);
    wptr<CaptureSession> weakThis(this);
    CHECK_EXECUTE(res, AddFunctionToMap(std::to_string(OHOS_CONTROL_SENSOR_EXPOSURE_TIME), [weakThis, exposureTime]() {
        auto sharedThis = weakThis.promote();
        CHECK_RETURN_ELOG(!sharedThis, "SetSensorExposureTime session is nullptr");
        sharedThis->LockForControl();
        int32_t retCode = sharedThis->SetSensorExposureTime(exposureTime);
        sharedThis->UnlockForControl();
        CHECK_EXECUTE(retCode != CameraErrorCode::SUCCESS, sharedThis->SetDeviceCapabilityChangeStatus(true));
    }));
    CHECK_PRINT_ELOG(!res, "CaptureSession::SetSensorExposureTime Failed to set exposure compensation");
    exposureDurationValue_ = exposureTime;
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::GetSensorExposureTime(uint32_t &exposureTime)
{
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::GetSensorExposureTime Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        !inputDevice, CameraErrorCode::INVALID_ARGUMENT, "CaptureSession::GetSensorExposureTime camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(!inputDeviceInfo, CameraErrorCode::INVALID_ARGUMENT,
        "CaptureSession::GetSensorExposureTime camera deviceInfo is null");
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = inputDeviceInfo->GetCachedMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, CameraErrorCode::INVALID_ARGUMENT, "GetSensorExposureTime camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_SENSOR_EXPOSURE_TIME, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::INVALID_ARGUMENT,
        "CaptureSession::GetSensorExposureTime Failed with return code %{public}d", ret);
    exposureTime = item.data.ui32[0];
    MEDIA_DEBUG_LOG("CaptureSession::GetSensorExposureTime exposureTime: %{public}d", exposureTime);
    return CameraErrorCode::SUCCESS;
}

bool CaptureSession::IsMacroSupported()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter IsMacroSupported");

    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), false,
        "CaptureSession::IsMacroSupported Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, false, "CaptureSession::IsMacroSupported camera device is null");
    auto deviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(deviceInfo == nullptr, false, "CaptureSession::IsMacroSupported camera deviceInfo is null");

    if (IsSupportSpecSearch()) {
        MEDIA_DEBUG_LOG("spec search enter");
        auto abilityContainer = GetCameraAbilityContainer();
        if (abilityContainer) {
            bool isSupport = abilityContainer->IsMacroSupported();
            MEDIA_INFO_LOG("spec search result: %{public}d", static_cast<int32_t>(isSupport));
            return isSupport;
        } else {
            MEDIA_ERR_LOG("spec search abilityContainer is null");
            return false;
        }
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = deviceInfo->GetCachedMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, false, "IsMacroSupported camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_CAMERA_MACRO_SUPPORTED, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count <= 0, false,
        "CaptureSession::IsMacroSupported Failed with return code %{public}d", ret);
    auto supportResult = static_cast<camera_macro_supported_type_t>(*item.data.i32);
    return supportResult == OHOS_CAMERA_MACRO_SUPPORTED;
}

int32_t CaptureSession::EnableMacro(bool isEnable)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter EnableMacro, isEnable:%{public}d", isEnable);
    CHECK_RETURN_RET_ELOG(
        !IsMacroSupported(), CameraErrorCode::OPERATION_NOT_ALLOWED, "EnableMacro IsMacroSupported is false");
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession Failed EnableMacro!, session not commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::EnableMacro Need to call LockForControl() before setting camera properties");
    uint8_t enableValue = static_cast<uint8_t>(isEnable ? OHOS_CAMERA_MACRO_ENABLE : OHOS_CAMERA_MACRO_DISABLE);
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_CAMERA_MACRO, &enableValue, 1);
    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::EnableMacro Failed to enable macro");
    } else {
        auto abilityContainer = GetCameraAbilityContainer();
        CHECK_EXECUTE(abilityContainer && supportSpecSearch_, abilityContainer->FilterByMacro(isEnable));
    }
    isSetMacroEnable_ = isEnable;
    std::string bundleName = CameraManager::GetInstance()->GetBundleName();
    SceneMode mode = GetMode();
    MEDIA_DEBUG_LOG("EnableMacro, bundleName:%{public}s, %{public}d, %{public}d", bundleName.c_str(), isEnable, mode);
    POWERMGR_SYSEVENT_MACRO_STATUS(bundleName, isEnable, static_cast<uint>(mode));
    return CameraErrorCode::SUCCESS;
}

std::shared_ptr<MoonCaptureBoostFeature> CaptureSession::GetMoonCaptureBoostFeature()
{
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET(inputDevice == nullptr, nullptr);
    auto deviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET(deviceInfo == nullptr, nullptr);
    auto deviceAbility = deviceInfo->GetCachedMetadata();
    CHECK_RETURN_RET(deviceAbility == nullptr, nullptr);

    auto currentMode = GetMode();
    {
        std::lock_guard<std::mutex> lock(moonCaptureBoostFeatureMutex_);
        bool isModeChanged = moonCaptureBoostFeature_ == nullptr ||
            moonCaptureBoostFeature_->GetRelatedMode() != currentMode;
        if (isModeChanged) {
            moonCaptureBoostFeature_ = std::make_shared<MoonCaptureBoostFeature>(currentMode, deviceAbility);
        }
        return moonCaptureBoostFeature_;
    }
}

bool CaptureSession::IsMoonCaptureBoostSupported()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter IsMoonCaptureBoostSupported");
    auto feature = GetMoonCaptureBoostFeature();
    CHECK_RETURN_RET(feature == nullptr, false);
    return feature->IsSupportedMoonCaptureBoostFeature();
}

int32_t CaptureSession::EnableMoonCaptureBoost(bool isEnable)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter EnableMoonCaptureBoost, isEnable:%{public}d", isEnable);
    CHECK_RETURN_RET_ELOG(!IsMoonCaptureBoostSupported(), CameraErrorCode::OPERATION_NOT_ALLOWED,
        "EnableMoonCaptureBoost IsMoonCaptureBoostSupported is false");
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession Failed EnableMoonCaptureBoost!, session not commited");
    uint8_t enableValue = static_cast<uint8_t>(isEnable ? 1 : 0);
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_MOON_CAPTURE_BOOST, &enableValue, 1);
    CHECK_PRINT_ELOG(!status, "CaptureSession::EnableMoonCaptureBoost failed to enable moon capture boost");
    isSetMoonCaptureBoostEnable_ = isEnable;
    return CameraErrorCode::SUCCESS;
}

bool CaptureSession::IsLowLightBoostSupported()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter IsLowLightBoostSupported");
    CHECK_RETURN_RET_ELOG(!(IsSessionConfiged() || IsSessionCommited()), false,
        "CaptureSession::IsLowLightBoostSupported Session is not Commited!");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        inputDevice == nullptr, false, "CaptureSession::IsLowLightBoostSupported camera device is null");
    auto deviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(
        deviceInfo == nullptr, false, "CaptureSession::IsLowLightBoostSupported camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = deviceInfo->GetCachedMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, false, "IsLowLightBoostSupported camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_LOW_LIGHT_BOOST, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count <= 0, false,
        "CaptureSession::IsLowLightBoostSupported Failed with return code %{public}d", ret);
    const uint32_t step = 3;
    for (uint32_t i = 0; i < item.count - 1; i += step) {
        bool isCurrentMode = GetMode() == item.data.i32[i] && item.data.i32[i + 1] == 1;
        CHECK_RETURN_RET(isCurrentMode, true);
    }
    return false;
}

int32_t CaptureSession::EnableLowLightBoost(bool isEnable)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter EnableLowLightBoost, isEnable:%{public}d", isEnable);
    CHECK_RETURN_RET_ELOG(
        !IsLowLightBoostSupported(), CameraErrorCode::OPERATION_NOT_ALLOWED, "Not support LowLightBoost");
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG, "Session is not Commited!");
    uint8_t enableValue = static_cast<uint8_t>(isEnable ? 1 : 0);
    if (!AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_LOW_LIGHT_BOOST, &enableValue, 1)) {
        MEDIA_ERR_LOG("CaptureSession::EnableLowLightBoost failed to enable low light boost");
    } else {
        isSetLowLightBoostEnable_ = isEnable;
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::EnableConstellationDrawing(bool isEnable)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter EnableConstellationDrawing, isEnable:%{public}d", isEnable);
    CHECK_RETURN_RET_ELOG(
        !IsConstellationDrawingSupported(), CameraErrorCode::OPERATION_NOT_ALLOWED, "Not support ConstellationDrawing");
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG, "Session is not Commited!");
    uint8_t enableValue = static_cast<uint8_t>(isEnable ? 1 : 0);
    if (!AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_CONSTELLATION_DRAWING, &enableValue, 1)) {
        MEDIA_ERR_LOG("CaptureSession::EnableConstellationDrawing failed to enable low light boost");
    } else {
        isSetConstellationDrawingEnable_ = isEnable;
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::EnableLowLightDetection(bool isEnable)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter EnableLowLightDetection, isEnable:%{public}d", isEnable);
    CHECK_RETURN_RET_ELOG(
        !IsLowLightBoostSupported(), CameraErrorCode::OPERATION_NOT_ALLOWED, "Not support LowLightBoost");
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG, "Session is not Commited!");
    uint8_t enableValue = static_cast<uint8_t>(isEnable ? 1 : 0);
    CHECK_PRINT_ELOG(!AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_LOW_LIGHT_DETECT, &enableValue, 1),
        "CaptureSession::EnableLowLightDetection failed to enable low light detect");
    return CameraErrorCode::SUCCESS;
}

bool CaptureSession::IsConstellationDrawingSupported()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter IsConstellationDrawingSupported");
    CHECK_RETURN_RET_ELOG(!(IsSessionConfiged() || IsSessionCommited()), false,
        "CaptureSession::IsConstellationDrawingSupported Session is not Commited!");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        inputDevice == nullptr, false, "CaptureSession::IsConstellationDrawingSupported camera device is null");
    auto deviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(
        deviceInfo == nullptr, false, "CaptureSession::IsConstellationDrawingSupported camera deviceInfo is null");
    CHECK_RETURN_RET_ELOG(!supportSpecSearch_, false, "spec search not support");
    auto abilityContainer = GetCameraAbilityContainer();
    CHECK_RETURN_RET_ELOG(abilityContainer == nullptr, false, "spec search abilityContainer is null");
    bool isSupport = abilityContainer->IsConstellationDrawingSupported();
    MEDIA_INFO_LOG("IsConstellationDrawingSupported result: %{public}d", static_cast<int32_t>(isSupport));
    return isSupport;
}

bool CaptureSession::IsFeatureSupported(SceneFeature feature)
{
    switch (static_cast<SceneFeature>(feature)) {
        case FEATURE_MACRO:
            return IsMacroSupported();
            break;
        case FEATURE_MOON_CAPTURE_BOOST:
            return IsMoonCaptureBoostSupported();
            break;
        case FEATURE_TRIPOD_DETECTION:
            return IsTripodDetectionSupported();
            break;
        case FEATURE_LOW_LIGHT_BOOST:
            return IsLowLightBoostSupported();
            break;
        case FEATURE_CONSTELLATION_DRAWING:
            return IsConstellationDrawingSupported();
            break;
        default:
            MEDIA_ERR_LOG("CaptureSession::IsFeatureSupported sceneFeature is unhandled %{public}d", feature);
            break;
    }
    return false;
}

int32_t CaptureSession::EnableFeature(SceneFeature feature, bool isEnable)
{
    LockForControl();
    int32_t retCode;
    switch (static_cast<SceneFeature>(feature)) {
        case FEATURE_MACRO:
            retCode = EnableMacro(isEnable);
            break;
        case FEATURE_MOON_CAPTURE_BOOST:
            retCode = EnableMoonCaptureBoost(isEnable);
            break;
        case FEATURE_TRIPOD_DETECTION:
            retCode = EnableTripodStabilization(isEnable);
            break;
        case FEATURE_LOW_LIGHT_BOOST:
            retCode = EnableLowLightBoost(isEnable);
            break;
        case FEATURE_CONSTELLATION_DRAWING:
            retCode = EnableConstellationDrawing(isEnable);
            break;
        default:
            retCode = INVALID_ARGUMENT;
    }
    UnlockForControl();
    return retCode;
}

bool CaptureSession::IsMovingPhotoSupported()
{
#ifdef CAMERA_MOVING_PHOTO
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter IsMovingPhotoSupported");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        inputDevice == nullptr, false, "CaptureSession::IsMovingPhotoSupported camera device is null");
    auto deviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(
        deviceInfo == nullptr, false, "CaptureSession::IsMovingPhotoSupported camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = deviceInfo->GetCachedMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, false, "IsMovingPhotoSupported camera metadata is null");
    camera_metadata_item_t metadataItem;
    vector<int32_t> modes = {};
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_MOVING_PHOTO, &metadataItem);
    bool isFindItem = ret == CAM_META_SUCCESS && metadataItem.count > 0;
    if (isFindItem) {
        uint32_t step = 3;
        for (uint32_t index = 0; index < metadataItem.count - 1;) {
            if (metadataItem.data.i32[index + 1] == 1) {
                modes.push_back(metadataItem.data.i32[index]);
            }
            MEDIA_DEBUG_LOG("IsMovingPhotoSupported mode:%{public}d", metadataItem.data.i32[index]);
            index += step;
        }
    }
    return std::find(modes.begin(), modes.end(), GetMode()) != modes.end();
#else
    return false;
#endif
}

int32_t CaptureSession::EnableMovingPhoto(bool isEnable)
{
#ifdef CAMERA_MOVING_PHOTO
    CAMERA_SYNC_TRACE;
    HILOG_COMM_INFO("Enter EnableMovingPhoto, isEnable:%{public}d", isEnable);
    CHECK_RETURN_RET_ELOG(
        !IsMovingPhotoSupported(), CameraErrorCode::SERVICE_FATL_ERROR, "IsMovingPhotoSupported is false");
    CHECK_RETURN_RET_ELOG(!(IsSessionConfiged() || IsSessionCommited()), CameraErrorCode::SERVICE_FATL_ERROR,
        "CaptureSession Failed EnableMovingPhoto!, session not configed");
    uint8_t enableValue = static_cast<uint8_t>(isEnable ? OHOS_CAMERA_MOVING_PHOTO_ON : OHOS_CAMERA_MOVING_PHOTO_OFF);
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_MOVING_PHOTO, &enableValue, 1);
    wptr<CaptureSession> weakThis(this);
    CHECK_EXECUTE(status, AddFunctionToMap(std::to_string(OHOS_CONTROL_MOVING_PHOTO), [weakThis, isEnable]() {
        auto sharedThis = weakThis.promote();
        CHECK_RETURN_ELOG(!sharedThis, "EnableMovingPhoto session is nullptr");
        sharedThis->LockForControl();
        int32_t retCode = sharedThis->EnableMovingPhoto(isEnable);
        sharedThis->UnlockForControl();
        CHECK_EXECUTE(retCode != CameraErrorCode::SUCCESS, sharedThis->SetDeviceCapabilityChangeStatus(true));
    }));
    CHECK_PRINT_ELOG(!status, "CaptureSession::EnableMovingPhoto Failed to enable");
    auto captureSession = GetCaptureSession();
    CHECK_RETURN_RET_ELOG(captureSession == nullptr, CameraErrorCode::INVALID_ARGUMENT,
        "CaptureSession::EnableMovingPhoto() captureSession is nullptr");
    int32_t errCode = captureSession->EnableMovingPhoto(isEnable);
    CHECK_RETURN_RET_ELOG(errCode != CAMERA_OK, errCode, "Failed to EnableMovingPhoto!, %{public}d", errCode);
    isMovingPhotoEnabled_ = isEnable;
    return CameraErrorCode::SUCCESS;
#else
    return CameraErrorCode::SERVICE_FATL_ERROR;
#endif
}

bool CaptureSession::IsMovingPhotoEnabled()
{
    return isMovingPhotoEnabled_;
}

int32_t CaptureSession::EnableMovingPhotoMirror(bool isMirror, bool isConfig)
{
#ifdef CAMERA_MOVING_PHOTO
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("EnableMovingPhotoMirror enter, isMirror: %{public}d", isMirror);
    CHECK_RETURN_RET_ELOG(
        !IsMovingPhotoSupported(), CameraErrorCode::SERVICE_FATL_ERROR, "IsMovingPhotoSupported is false");
    auto captureSession = GetCaptureSession();
    CHECK_RETURN_RET_ELOG(!captureSession, CameraErrorCode::SERVICE_FATL_ERROR,
        "CaptureSession::StartMovingPhotoCapture captureSession is nullptr");
    int32_t errCode = captureSession->EnableMovingPhotoMirror(isMirror, isConfig);
    CHECK_PRINT_ELOG(errCode != CAMERA_OK, "Failed to StartMovingPhotoCapture!, %{public}d", errCode);
    return CameraErrorCode::SUCCESS;
#else
    return CameraErrorCode::SERVICE_FATL_ERROR;
#endif
}

void CaptureSession::SetMoonCaptureBoostStatusCallback(std::shared_ptr<MoonCaptureBoostStatusCallback> callback)
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    moonCaptureBoostStatusCallback_ = callback;
    return;
}

void CaptureSession::ProcessMacroStatusChange(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
    __attribute__((no_sanitize("cfi")))
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Entry ProcessMacroStatusChange");

    // To avoid macroStatusCallback_ change pointed value occur multithread problem, copy pointer first.
    auto statusCallback = GetMacroStatusCallback();
    CHECK_RETURN_DLOG(statusCallback == nullptr, "CaptureSession::ProcessMacroStatusChange statusCallback is null");
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_CAMERA_MACRO_STATUS, &item);
    bool isNotFindItem = ret != CAM_META_SUCCESS || item.count <= 0;
    CHECK_RETURN_DLOG(isNotFindItem, "Camera not support macro mode");
    auto isMacroActive = static_cast<bool>(item.data.u8[0]);
    MEDIA_DEBUG_LOG("Macro active: %{public}d", isMacroActive);
    auto macroStatus =
        isMacroActive ? MacroStatusCallback::MacroStatus::ACTIVE : MacroStatusCallback::MacroStatus::IDLE;
    CHECK_RETURN_DLOG(macroStatus == statusCallback->currentStatus, "Macro mode: no change");
    statusCallback->currentStatus = macroStatus;
    statusCallback->OnMacroStatusChanged(macroStatus);
}

void CaptureSession::ProcessIsoChange(const std::shared_ptr<OHOS::Camera::CameraMetadata> &result)
{
    // LCOV_EXCL_START
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_STATUS_ISO_VALUE, &item);
    CHECK_RETURN(ret != CAM_META_SUCCESS);
    MEDIA_DEBUG_LOG("Iso Value: %{public}d", item.data.ui32[0]);
    IsoInfo info = {
        .isoValue = item.data.ui32[0],
    };
    std::lock_guard<std::mutex> callbackLock(sessionCallbackMutex_);
    std::lock_guard<std::mutex> isoLock(isoValueMutex_);
    CHECK_EXECUTE(isoInfoSyncCallback_ != nullptr && item.data.ui32[0] != isoValue_,
                  isoInfoSyncCallback_->OnIsoInfoChangedSync(info));
    isoValue_ = item.data.ui32[0];
    // LCOV_EXCL_STOP
}

void CaptureSession::ProcessMoonCaptureBoostStatusChange(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
    __attribute__((no_sanitize("cfi")))
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Entry ProcessMoonCaptureBoostStatusChange");

    auto statusCallback = GetMoonCaptureBoostStatusCallback();
    auto featureStatusCallback = GetFeatureDetectionStatusCallback();
    bool isNotSetCallBack = statusCallback == nullptr &&
        (featureStatusCallback == nullptr ||
            !featureStatusCallback->IsFeatureSubscribed(SceneFeature::FEATURE_MOON_CAPTURE_BOOST));
    if (isNotSetCallBack) {
        MEDIA_DEBUG_LOG("CaptureSession::ProcessMoonCaptureBoostStatusChange statusCallback and "
                        "featureDetectionStatusChangedCallback are null");
        return;
    }

    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_STATUS_MOON_CAPTURE_DETECTION, &item);
    bool isNotFindItem = ret != CAM_META_SUCCESS || item.count <= 0;
    CHECK_RETURN_DLOG(isNotFindItem, "Camera not support moon capture detection");
    auto isMoonActive = static_cast<bool>(item.data.u8[0]);
    MEDIA_DEBUG_LOG("Moon active: %{public}d", isMoonActive);

    if (statusCallback != nullptr) {
        auto moonCaptureBoostStatus = isMoonActive ? MoonCaptureBoostStatusCallback::MoonCaptureBoostStatus::ACTIVE
                                                   : MoonCaptureBoostStatusCallback::MoonCaptureBoostStatus::IDLE;
        CHECK_RETURN_DLOG(moonCaptureBoostStatus == statusCallback->currentStatus, "Moon mode: no change");
        statusCallback->currentStatus = moonCaptureBoostStatus;
        statusCallback->OnMoonCaptureBoostStatusChanged(moonCaptureBoostStatus);
    }
    bool isSubscribed = featureStatusCallback != nullptr &&
        featureStatusCallback->IsFeatureSubscribed(SceneFeature::FEATURE_MOON_CAPTURE_BOOST);
    CHECK_RETURN(!isSubscribed);
    auto detectStatus = isMoonActive ? FeatureDetectionStatusCallback::FeatureDetectionStatus::ACTIVE :
                                       FeatureDetectionStatusCallback::FeatureDetectionStatus::IDLE;
    CHECK_RETURN_DLOG(!featureStatusCallback->UpdateStatus(SceneFeature::FEATURE_MOON_CAPTURE_BOOST, detectStatus),
        "Feature detect Moon mode: no change");
    featureStatusCallback->OnFeatureDetectionStatusChanged(SceneFeature::FEATURE_MOON_CAPTURE_BOOST, detectStatus);
}

void CaptureSession::ProcessSmoothZoomDurationChange(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    MEDIA_DEBUG_LOG("Entry ProcessSmoothZoomDurationChange");
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(result->get(), OHOS_SMOOTH_ZOOM_DURATION, &item);
    if (ret == CAM_META_SUCCESS && item.count > 0) {
        int32_t duration = item.data.i32[0];
        MEDIA_INFO_LOG("HCameraDevice::ProcessSmoothZoomDurationChange succ %{public}d", duration);
        auto smoothZoomCallback = GetSmoothZoomCallback();
        if (smoothZoomCallback != nullptr) {
            smoothZoomCallback->OnSmoothZoom(duration);
            MEDIA_INFO_LOG("HCameraDevice::ProcessSmoothZoomDurationChange succ %{public}d", duration);
        }
    }
}

void CaptureSession::ProcessLowLightBoostStatusChange(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Entry ProcessLowLightBoostStatusChange");

    auto featureStatusCallback = GetFeatureDetectionStatusCallback();
    bool isNotSetCallBack = featureStatusCallback == nullptr ||
        !featureStatusCallback->IsFeatureSubscribed(SceneFeature::FEATURE_LOW_LIGHT_BOOST);
    CHECK_RETURN_DLOG(
        isNotSetCallBack, "CaptureSession::ProcessLowLightBoostStatusChange featureStatusCallback is null");
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_STATUS_LOW_LIGHT_DETECTION, &item);
    bool isNotFindItem = ret != CAM_META_SUCCESS || item.count <= 0;
    CHECK_RETURN_DLOG(isNotFindItem, "Camera not support low light detection");
    auto isLowLightActive = static_cast<bool>(item.data.u8[0]);
    MEDIA_DEBUG_LOG("LowLight active: %{public}d", isLowLightActive);

    auto detectStatus = isLowLightActive ? FeatureDetectionStatusCallback::FeatureDetectionStatus::ACTIVE
                                         : FeatureDetectionStatusCallback::FeatureDetectionStatus::IDLE;
    CHECK_RETURN_DLOG(!featureStatusCallback->UpdateStatus(SceneFeature::FEATURE_LOW_LIGHT_BOOST, detectStatus),
        "Feature detect LowLight mode: no change");
    featureStatusCallback->OnFeatureDetectionStatusChanged(SceneFeature::FEATURE_LOW_LIGHT_BOOST, detectStatus);
}

bool CaptureSession::IsSetEnableMacro()
{
    return isSetMacroEnable_;
}

bool CaptureSession::ValidateOutputProfile(Profile& outputProfile, CaptureOutputType outputType)
{
    MEDIA_DEBUG_LOG("CaptureSession::ValidateOutputProfile profile:w(%{public}d),h(%{public}d),f(%{public}d) outputType"
        ":%{public}d", outputProfile.size_.width, outputProfile.size_.height, outputProfile.format_, outputType);
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice, false, "CaptureSession::ValidateOutputProfile Failed inputDevice is nullptr");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(
        !inputDeviceInfo, false, "CaptureSession::ValidateOutputProfile Failed inputDeviceInfo is nullptr");
    CHECK_RETURN_RET_ILOG(
        outputType == CAPTURE_OUTPUT_TYPE_METADATA, true, "CaptureSession::ValidateOutputProfile MetadataOutput");
    CHECK_RETURN_RET_ILOG(
        outputType == CAPTURE_OUTPUT_TYPE_DEPTH_DATA, true, "CaptureSession::ValidateOutputProfile DepthDataOutput");
    auto modeName = GetMode();
    auto validateOutputProfileFunc = [modeName](auto validateProfile, auto& profiles) -> bool {
        MEDIA_INFO_LOG("CaptureSession::ValidateOutputProfile in mode(%{public}d): "
                       "w(%{public}d),h(%{public}d),f(%{public}d), profiles size is:%{public}zu",
            static_cast<int32_t>(modeName), validateProfile.size_.width, validateProfile.size_.height,
            validateProfile.format_, profiles.size());
        bool result = std::any_of(profiles.begin(), profiles.end(), [&validateProfile](const auto& profile) {
            return validateProfile == profile;
        });
        CHECK_EXECUTE(result, MEDIA_INFO_LOG("CaptureSession::ValidateOutputProfile success!"));
        if (!result) {
            HILOG_COMM_ERROR("CaptureSession::ValidateOutputProfile fail! Not in the profiles set.");
        }
        return result;
    };
    switch (outputType) {
        case CAPTURE_OUTPUT_TYPE_PREVIEW: {
            auto profiles = inputDeviceInfo->modePreviewProfiles_[modeName];
            return validateOutputProfileFunc(outputProfile, profiles);
        }
        case CAPTURE_OUTPUT_TYPE_PHOTO: {
            auto profiles = inputDeviceInfo->modePhotoProfiles_[modeName];
            return validateOutputProfileFunc(outputProfile, profiles);
        }
        case CAPTURE_OUTPUT_TYPE_VIDEO: {
            auto profiles = inputDeviceInfo->modeVideoProfiles_[modeName];
            return validateOutputProfileFunc(outputProfile, profiles);
        }
#ifdef CAMERA_MOVIE_FILE
        case CAPTURE_OUTPUT_TYPE_MOVIE_FILE:
        // Fall-througn
        case CAPTURE_OUTPUT_TYPE_UNIFY_MOVIE_FILE: {
            auto profiles = inputDeviceInfo->modeVideoProfiles_[modeName];
            MEDIA_INFO_LOG("CaptureSession::ValidateOutputProfile CaptureOutputType MovieFile");
            return validateOutputProfileFunc(outputProfile, profiles);
        }
#endif
        default:
            MEDIA_ERR_LOG("CaptureSession::ValidateOutputProfile CaptureOutputType unknown");
            return false;
    }
}

bool CaptureSession::CanPreconfig(PreconfigType preconfigType, ProfileSizeRatio preconfigRatio)
{
    // Default implementation return false. Only photo session and video session override this method.
    MEDIA_ERR_LOG("CaptureSession::CanPreconfig is not valid! Did you set the correct mode?");
    return false;
}

int32_t CaptureSession::Preconfig(PreconfigType preconfigType, ProfileSizeRatio preconfigRatio)
{
    // Default implementation throw error. Only photo session and video session override this method.
    MEDIA_ERR_LOG("CaptureSession::Preconfig is not valid! Did you set the correct mode?");
    return CAMERA_UNSUPPORTED;
}

std::shared_ptr<PreconfigProfiles> CaptureSession::GeneratePreconfigProfiles(
    PreconfigType preconfigType, ProfileSizeRatio preconfigRatio)
{
    // Default implementation return nullptr. Only photo session and video session override this method.
    MEDIA_ERR_LOG("CaptureSession::GeneratePreconfigProfiles is not valid! Did you set the correct mode?");
    return nullptr;
}

void CaptureSession::EnableDeferredType(DeferredDeliveryImageType type, bool isEnableByUser)
{
    MEDIA_INFO_LOG("CaptureSession::EnableDeferredType type:%{public}d", type);
    CHECK_RETURN_ELOG(IsSessionCommited(), "CaptureSession::EnableDeferredType session has committed!");
    this->LockForControl();
    CHECK_RETURN_ELOG(changedMetadata_ == nullptr, "CaptureSession::EnableDeferredType changedMetadata_ is NULL");
    isImageDeferred_ = false;
    uint8_t deferredType;
    switch (type) {
        case DELIVERY_NONE:
            deferredType = HDI::Camera::V1_2::NONE;
            break;
        // LCOV_EXCL_START
        case DELIVERY_PHOTO:
            deferredType = HDI::Camera::V1_2::STILL_IMAGE;
            isImageDeferred_ = true;
            break;
        case DELIVERY_VIDEO:
            deferredType = HDI::Camera::V1_2::MOVING_IMAGE;
            break;
        default:
            deferredType = HDI::Camera::V1_2::NONE;
            MEDIA_ERR_LOG("CaptureSession::EnableDeferredType not support yet.");
            break;
        // LCOV_EXCL_STOP
    }
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_DEFERRED_IMAGE_DELIVERY, &deferredType, 1);
    CHECK_PRINT_ELOG(!status, "CaptureSession::enableDeferredType Failed to set type!");
    int32_t errCode = this->UnlockForControl();
    CHECK_RETURN_DLOG(errCode != CameraErrorCode::SUCCESS, "CaptureSession::EnableDeferredType Failed");
    isDeferTypeSetted_ = isEnableByUser;
}

void CaptureSession::EnableAutoDeferredVideoEnhancement(bool isEnableByUser)
{
    MEDIA_INFO_LOG("EnableAutoDeferredVideoEnhancement isEnableByUser:%{public}d", isEnableByUser);
    CHECK_RETURN_ELOG(IsSessionCommited(), "EnableAutoDeferredVideoEnhancement session has committed!");
    this->LockForControl();
    CHECK_RETURN_ELOG(changedMetadata_ == nullptr, "EnableAutoDeferredVideoEnhancement changedMetadata_ is NULL");
    isVideoDeferred_ = isEnableByUser;
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_AUTO_DEFERRED_VIDEO_ENHANCE, &isEnableByUser, 1);
    CHECK_PRINT_ELOG(!status, "EnableAutoDeferredVideoEnhancement Failed to set type!");
    int32_t errCode = this->UnlockForControl();
    CHECK_PRINT_DLOG(errCode != CameraErrorCode::SUCCESS, "EnableAutoDeferredVideoEnhancement Failed");
}

void CaptureSession::SetUserId()
{
    MEDIA_INFO_LOG("CaptureSession::SetUserId");
    CHECK_RETURN_ELOG(IsSessionCommited(), "CaptureSession::SetUserId session has committed!");
    this->LockForControl();
    CHECK_RETURN_ELOG(changedMetadata_ == nullptr, "CaptureSession::SetUserId changedMetadata_ is NULL");
    int32_t userId;
    int32_t uid = IPCSkeleton::GetCallingUid();
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, userId);
    MEDIA_INFO_LOG("CaptureSession get uid:%{public}d userId:%{public}d", uid, userId);
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CAMERA_USER_ID, &userId, 1);
    CHECK_PRINT_ELOG(!status, "CaptureSession::SetUserId Failed!");
    int32_t errCode = this->UnlockForControl();
    CHECK_PRINT_ELOG(errCode != CameraErrorCode::SUCCESS, "CaptureSession::SetUserId Failed");
}

void CaptureSession::EnableOfflinePhoto()
{
    MEDIA_INFO_LOG("CaptureSession::EnableOfflinePhoto");
    CHECK_RETURN_ELOG(IsSessionCommited(), "CaptureSession::EnableOfflinePhoto session has committed!");
    CHECK_RETURN(!photoOutput_ || !((sptr<PhotoOutput>&)photoOutput_)->IsHasSwitchOfflinePhoto());
    this->LockForControl();
    uint8_t enableOffline = 1;
    bool status = AddOrUpdateMetadata(
        changedMetadata_, OHOS_CONTROL_CHANGETO_OFFLINE_STREAM_OPEATOR, &enableOffline, 1);
    MEDIA_INFO_LOG("CaptureSession::Start() enableOffline is %{public}d", enableOffline);
    CHECK_PRINT_ELOG(!status, "CaptureSession::CommitConfig Failed to add/update offline stream operator");
    this->UnlockForControl();
}

int32_t CaptureSession::EnableAutoHighQualityPhoto(bool enabled)
{
    MEDIA_INFO_LOG("CaptureSession::EnableAutoHighQualityPhoto enabled:%{public}d", enabled);

    this->LockForControl();
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, INVALID_ARGUMENT,
        "CaptureSession::EnableAutoHighQualityPhoto changedMetadata_ is NULL");

    int32_t res = CameraErrorCode::SUCCESS;
    uint8_t hightQualityEnable = static_cast<uint8_t>(enabled);
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_HIGH_QUALITY_MODE, &hightQualityEnable, 1);
    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::EnableAutoHighQualityPhoto Failed to set type!");
        res = INVALID_ARGUMENT;
    }
    wptr<CaptureSession> weakThis(this);
    CHECK_EXECUTE(status, AddFunctionToMap(std::to_string(OHOS_CONTROL_HIGH_QUALITY_MODE), [weakThis, enabled]() {
        auto sharedThis = weakThis.promote();
        CHECK_RETURN_ELOG(!sharedThis, "EnableAutoHighQualityPhoto session is nullptr");
        int32_t retCode = sharedThis->EnableAutoHighQualityPhoto(enabled);
        CHECK_EXECUTE(retCode != CameraErrorCode::SUCCESS, sharedThis->SetDeviceCapabilityChangeStatus(true));
    }));
    res = this->UnlockForControl();
    CHECK_PRINT_ELOG(res != CameraErrorCode::SUCCESS, "CaptureSession::EnableAutoHighQualityPhoto Failed");
    return res;
}

void CaptureSession::ExecuteAbilityChangeCallback() __attribute__((no_sanitize("cfi")))
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    CHECK_RETURN(abilityCallback_ == nullptr);
    abilityCallback_->OnAbilityChange();
}

int32_t CaptureSession::EnableAutoCloudImageEnhancement(bool enabled)
{
    MEDIA_INFO_LOG("CaptureSession::EnableAutoCloudImageEnhancement enabled:%{public}d", enabled);

    LockForControl();
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, INVALID_ARGUMENT,
        "CaptureSession::EnableAutoCloudImageEnhancement changedMetadata_ is NULL");

    int32_t res = CameraErrorCode::SUCCESS;
    uint8_t AutoCloudImageEnhanceEnable = static_cast<uint8_t>(enabled); // 三目表达式处理，不使用强转
    bool status = AddOrUpdateMetadata(
        changedMetadata_, OHOS_CONTROL_AUTO_CLOUD_IMAGE_ENHANCE, &AutoCloudImageEnhanceEnable, 1);
    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::EnableAutoCloudImageEnhancement Failed to set type!");
        res = INVALID_ARGUMENT;
    }
    UnlockForControl();
    CHECK_PRINT_DLOG(res != CameraErrorCode::SUCCESS, "CaptureSession::EnableAutoCloudImageEnhancement Failed");
    return res;
}

void CaptureSession::SetAbilityCallback(std::shared_ptr<AbilityCallback> abilityCallback)
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    abilityCallback_ = abilityCallback;
}

std::shared_ptr<OHOS::Camera::CameraMetadata> CaptureSession::GetMetadata()
{
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ILOG(inputDevice == nullptr,
        std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH),
        "CaptureSession::GetMetadata inputDevice is null, create default metadata");
    auto deviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ILOG(deviceInfo == nullptr,
        std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH),
        "CaptureSession::GetMetadata deviceInfo is null, create default metadata");
    return deviceInfo->GetCachedMetadata();
}

int32_t CaptureSession::SetARMode(uint8_t arModeTag)
{
    MEDIA_INFO_LOG("CaptureSession::SetARMode");
    CHECK_RETURN_RET_ELOG(
        !IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG, "CaptureSession::SetARMode Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::SetARMode Need to call LockForControl() before setting camera properties");
    uint8_t value = arModeTag;
    bool status = AddOrUpdateMetadata(changedMetadata_, HAL_CUSTOM_AR_MODE, &value, 1);
    CHECK_RETURN_RET_ELOG(!status, CameraErrorCode::SUCCESS, "CaptureSession::SetARMode Failed to set ar mode");
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::GetSensorSensitivityRange(std::vector<int32_t> &sensitivityRange)
{
    MEDIA_INFO_LOG("CaptureSession::GetSensorSensitivityRange");
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::GetSensorSensitivity fail due to Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice, CameraErrorCode::INVALID_ARGUMENT,
        "CaptureSession::GetSensorSensitivity fail due to camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(!inputDeviceInfo, CameraErrorCode::INVALID_ARGUMENT,
        "CaptureSession::GetSensorSensitivity fail due to camera deviceInfo is null");
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = inputDeviceInfo->GetCachedMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, CameraErrorCode::INVALID_ARGUMENT, "GetSensorSensitivity camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_SENSOR_INFO_SENSITIVITY_RANGE, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::INVALID_ARGUMENT,
        "CaptureSession::GetSensorSensitivity Failed with return code %{public}d", ret);

    for (uint32_t i = 0; i < item.count; i++) {
        sensitivityRange.emplace_back(item.data.i32[i]);
    }

    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetSensorSensitivity(uint32_t sensitivity)
{
    MEDIA_INFO_LOG("CaptureSession::SetSensorSensitivity");
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::SetSensorSensitivity Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::SetSensorSensitivity Need to call LockForControl() before setting camera properties");
    MEDIA_DEBUG_LOG("CaptureSession::SetSensorSensitivity sensitivity: %{public}d", sensitivity);
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::OPERATION_NOT_ALLOWED,
        "CaptureSession::SetSensorSensitivity camera device is null");
    bool status = AddOrUpdateMetadata(changedMetadata_, HAL_CUSTOM_SENSOR_SENSITIVITY, &sensitivity, 1);
    CHECK_PRINT_ELOG(!status, "CaptureSession::SetSensorSensitivity Failed to set sensitivity");
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::GetModuleType(uint32_t &moduleType)
{
    MEDIA_INFO_LOG("CaptureSession::GetModuleType");
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::GetModuleType fail due to Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice, CameraErrorCode::INVALID_ARGUMENT,
        "CaptureSession::GetModuleType fail due to camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(!inputDeviceInfo, CameraErrorCode::INVALID_ARGUMENT,
        "CaptureSession::GetModuleType fail due to camera deviceInfo is null");
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = inputDeviceInfo->GetCachedMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, CameraErrorCode::INVALID_ARGUMENT, "GetModuleType camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), HAL_CUSTOM_SENSOR_MODULE_TYPE, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::INVALID_ARGUMENT,
        "CaptureSession::GetModuleType Failed with return code %{public}d", ret);
    moduleType = item.data.ui32[0];
    MEDIA_DEBUG_LOG("moduleType: %{public}d", moduleType);
    return CameraErrorCode::SUCCESS;
}

void CaptureSession::SetARCallback(std::shared_ptr<ARCallback> arCallback)
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    arCallback_ = arCallback;
}

// white balance mode
int32_t CaptureSession::GetSupportedWhiteBalanceModes(std::vector<WhiteBalanceMode> &supportedWhiteBalanceModes)
{
    supportedWhiteBalanceModes.clear();
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::GetSupportedWhiteBalanceModes Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        !inputDevice, CameraErrorCode::SUCCESS, "CaptureSession::GetSupportedWhiteBalanceModes camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(!inputDeviceInfo, CameraErrorCode::SUCCESS,
        "CaptureSession::GetSupportedWhiteBalanceModes camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetCachedMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, CameraErrorCode::SUCCESS, "GetSupportedWhiteBalanceModes camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_AWB_AVAILABLE_MODES, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "CaptureSession::GetSupportedWhiteBalanceModes Failed with return code %{public}d", ret);
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = metaWhiteBalanceModeMap_.find(static_cast<camera_awb_mode_t>(item.data.u8[i]));
        if (itr != metaWhiteBalanceModeMap_.end()) {
            supportedWhiteBalanceModes.emplace_back(itr->second);
        }
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::IsWhiteBalanceModeSupported(WhiteBalanceMode mode, bool &isSupported)
{
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::IsFocusModeSupported Session is not Commited");
    if (mode == AWB_MODE_LOCKED) {
        isSupported = true;
        return CameraErrorCode::SUCCESS;
    }
    std::vector<WhiteBalanceMode> vecSupportedWhiteBalanceModeList;
    (void)this->GetSupportedWhiteBalanceModes(vecSupportedWhiteBalanceModeList);
    if (find(vecSupportedWhiteBalanceModeList.begin(), vecSupportedWhiteBalanceModeList.end(),
        mode) != vecSupportedWhiteBalanceModeList.end()) {
        isSupported = true;
        return CameraErrorCode::SUCCESS;
    }
    isSupported = false;
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetWhiteBalanceMode(WhiteBalanceMode mode)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(mode >= WhiteBalanceMode::AWB_MODE_LOCKED, CameraErrorCode::INVALID_ARGUMENT,
        "CaptureSession::SetWhiteBalanceMode Mode is not supported");
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::SetWhiteBalanceMode Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::SetWhiteBalanceMode Need to call LockForControl() before setting camera properties");
    uint8_t awbLock = OHOS_CAMERA_AWB_LOCK_OFF;
    bool res = false;
    if (mode == AWB_MODE_LOCKED) {
        awbLock = OHOS_CAMERA_AWB_LOCK_ON;
        res = AddOrUpdateMetadata(changedMetadata_->get(), OHOS_CONTROL_AWB_LOCK, &awbLock, 1);
        CHECK_PRINT_ELOG(!res, "CaptureSession::SetWhiteBalanceMode Failed to lock whiteBalance");
        return CameraErrorCode::SUCCESS;
    }
    res = AddOrUpdateMetadata(changedMetadata_->get(), OHOS_CONTROL_AWB_LOCK, &awbLock, 1);
    CHECK_PRINT_ELOG(!res, "CaptureSession::SetWhiteBalanceMode Failed to unlock whiteBalance");
    uint8_t whiteBalanceMode = OHOS_CAMERA_AWB_MODE_OFF;
    auto itr = fwkWhiteBalanceModeMap_.find(mode);
    if (itr == fwkWhiteBalanceModeMap_.end()) {
        MEDIA_ERR_LOG("CaptureSession::SetWhiteBalanceMode Unknown exposure mode");
    } else {
        whiteBalanceMode = itr->second;
    }
    MEDIA_DEBUG_LOG("CaptureSession::SetWhiteBalanceMode WhiteBalance mode: %{public}d", whiteBalanceMode);
    // no manual wb mode need set maunual value to 0
    if (mode != AWB_MODE_OFF) {
        int32_t wbValue = 0;
        CHECK_PRINT_ELOG(!AddOrUpdateMetadata(changedMetadata_->get(), OHOS_CONTROL_SENSOR_WB_VALUE, &wbValue, 1),
            "SetManualWhiteBalance Failed to SetManualWhiteBalance.");
    }
    res = AddOrUpdateMetadata(changedMetadata_->get(), OHOS_CONTROL_AWB_MODE, &whiteBalanceMode, 1);
    CHECK_PRINT_ELOG(!res, "CaptureSession::SetWhiteBalanceMode Failed to set WhiteBalance mode");
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::GetWhiteBalanceMode(WhiteBalanceMode &mode)
{
    mode = AWB_MODE_OFF;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::GetWhiteBalanceMode Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::SUCCESS,
        "CaptureSession::GetWhiteBalanceMode camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, CameraErrorCode::INVALID_ARGUMENT, "GetWhiteBalanceMode metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_AWB_LOCK, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "CaptureSession::GetWhiteBalanceMode Failed with return code %{public}d", ret);
    if (item.data.u8[0] == OHOS_CAMERA_AWB_LOCK_ON) {
        mode = AWB_MODE_LOCKED;
        return CameraErrorCode::SUCCESS;
    }
    ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_AWB_MODE, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "CaptureSession::GetWhiteBalanceMode Failed with return code %{public}d", ret);
    auto itr = metaWhiteBalanceModeMap_.find(static_cast<camera_awb_mode_t>(item.data.u8[0]));
    if (itr != metaWhiteBalanceModeMap_.end()) {
        mode = itr->second;
        return CameraErrorCode::SUCCESS;
    }
    return CameraErrorCode::SUCCESS;
}

// manual white balance
int32_t CaptureSession::GetManualWhiteBalanceRange(std::vector<int32_t> &whiteBalanceRange)
{
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::GetManualWhiteBalanceRange Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        !inputDevice, CameraErrorCode::SUCCESS, "CaptureSession::GetManualWhiteBalanceRange camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(!inputDeviceInfo, CameraErrorCode::SUCCESS,
        "CaptureSession::GetManualWhiteBalanceRange camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetCachedMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, CameraErrorCode::SUCCESS, "GetManualWhiteBalanceRange camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_SENSOR_WB_VALUES, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "CaptureSession::GetManualWhiteBalanceRange Failed with return code %{public}d", ret);
    for (uint32_t i = 0; i < item.count; i++) {
        whiteBalanceRange.emplace_back(item.data.i32[i]);
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::IsManualWhiteBalanceSupported(bool &isSupported)
{
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::IsManualWhiteBalanceSupported Session is not Commited");
    std::vector<int32_t> whiteBalanceRange;
    this->GetManualWhiteBalanceRange(whiteBalanceRange);
    constexpr int32_t rangeSize = 2;
    isSupported = (whiteBalanceRange.size() == rangeSize);
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetManualWhiteBalance(int32_t wbValue)
{
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::SetManualWhiteBalance Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::SetManualWhiteBalance Need to call LockForControl() before setting camera properties");
    WhiteBalanceMode mode;
    GetWhiteBalanceMode(mode);
    // WhiteBalanceMode::OFF
    CHECK_RETURN_RET_ELOG(mode != WhiteBalanceMode::AWB_MODE_OFF, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "CaptureSession::SetManualWhiteBalance Need to set WhiteBalanceMode off");
    int32_t minIndex = 0;
    int32_t maxIndex = 1;
    MEDIA_DEBUG_LOG("CaptureSession::SetManualWhiteBalance white balance: %{public}d", wbValue);
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::OPERATION_NOT_ALLOWED,
        "CaptureSession::SetManualWhiteBalance camera device is null");
    std::vector<int32_t> whiteBalanceRange;
    this->GetManualWhiteBalanceRange(whiteBalanceRange);
    CHECK_RETURN_RET_ELOG(whiteBalanceRange.empty(), CameraErrorCode::OPERATION_NOT_ALLOWED,
        "CaptureSession::SetManualWhiteBalance Bias range is empty");

    bool isMinValue = wbValue != 0 && wbValue < whiteBalanceRange[minIndex];
    if (isMinValue) {
        MEDIA_DEBUG_LOG("CaptureSession::SetManualWhiteBalance wbValue:"
                        "%{public}d is lesser than minimum wbValue: %{public}d",
            wbValue, whiteBalanceRange[minIndex]);
        wbValue = whiteBalanceRange[minIndex];
    } else if (wbValue > whiteBalanceRange[maxIndex]) {
        MEDIA_DEBUG_LOG("CaptureSession::SetManualWhiteBalance wbValue: "
                        "%{public}d is greater than maximum wbValue: %{public}d",
            wbValue, whiteBalanceRange[maxIndex]);
        wbValue = whiteBalanceRange[maxIndex];
    }
    CHECK_PRINT_ELOG(!AddOrUpdateMetadata(changedMetadata_->get(), OHOS_CONTROL_SENSOR_WB_VALUE, &wbValue, 1),
        "SetManualWhiteBalance Failed to SetManualWhiteBalance");
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::GetManualWhiteBalance(int32_t &wbValue)
{
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::GetManualWhiteBalance Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::SUCCESS,
        "CaptureSession::GetManualWhiteBalance camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(
        !inputDeviceInfo, CameraErrorCode::SUCCESS, "CaptureSession::GetManualWhiteBalance camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetCachedMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, CameraErrorCode::SUCCESS, "GetManualWhiteBalance camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_SENSOR_WB_VALUE, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "CaptureSession::GetManualWhiteBalance Failed with return code %{public}d", ret);
    if (item.count != 0) {
        wbValue = item.data.i32[0];
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::GetSupportedPhysicalApertures(std::vector<std::vector<float>>& supportedPhysicalApertures)
{
    // The data structure of the supportedPhysicalApertures object is { {zoomMin, zoomMax,
    // physicalAperture1, physicalAperture2···}, }.
    supportedPhysicalApertures.clear();
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "GetSupportedPhysicalApertures Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::SUCCESS,
        "GetSupportedPhysicalApertures camera device is null");

    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, CameraErrorCode::SUCCESS, "GetSupportedPhysicalApertures camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_CAMERA_PHYSICAL_APERTURE_RANGE, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count == 0, CameraErrorCode::SUCCESS,
        "GetSupportedPhysicalApertures Failed with return code %{public}d", ret);
    std::vector<float> chooseModeRange = ParsePhysicalApertureRangeByMode(item, GetMode());
    constexpr int32_t minPhysicalApertureMetaSize = 3;
    CHECK_RETURN_RET_ELOG(chooseModeRange.size() < minPhysicalApertureMetaSize, CameraErrorCode::SUCCESS,
        "GetSupportedPhysicalApertures Failed meta format error");
    int32_t deviceCntPos = 1;
    int32_t supportedDeviceCount = static_cast<int32_t>(chooseModeRange[deviceCntPos]);
    CHECK_RETURN_RET_ELOG(supportedDeviceCount == 0, CameraErrorCode::SUCCESS,
        "GetSupportedPhysicalApertures Failed meta device count is 0");
    std::vector<float> tempPhysicalApertures = {};
    for (uint32_t i = 2; i < chooseModeRange.size(); i++) {
        if (chooseModeRange[i] == -1) {
            supportedPhysicalApertures.emplace_back(tempPhysicalApertures);
            vector<float>().swap(tempPhysicalApertures);
            continue;
        }
        tempPhysicalApertures.emplace_back(chooseModeRange[i]);
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::GetSupportedVirtualApertures(std::vector<float>& apertures)
{
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "GetSupportedVirtualApertures Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice, CameraErrorCode::SUCCESS, "GetSupportedVirtualApertures camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(
        !inputDeviceInfo, CameraErrorCode::SUCCESS, "GetSupportedVirtualApertures camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetCachedMetadata();
    CHECK_RETURN_RET(metadata == nullptr, CameraErrorCode::SUCCESS);
    camera_metadata_item_t item;
    int32_t ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_CAMERA_VIRTUAL_APERTURE_RANGE, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count == 0, CameraErrorCode::SUCCESS,
        "GetSupportedVirtualApertures Failed with return code %{public}d", ret);
    for (uint32_t i = 0; i < item.count; i++) {
        apertures.emplace_back(item.data.f[i]);
    }
    return CameraErrorCode::SUCCESS;
}

std::vector<PortraitEffect> CaptureSession::GetSupportedPortraitEffects()
{
    std::vector<PortraitEffect> supportedPortraitEffects = {};
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), supportedPortraitEffects,
        "CaptureSession::GetSupportedPortraitEffects Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        !inputDevice, supportedPortraitEffects, "CaptureSession::GetSupportedPortraitEffects camera device is null");
    auto cameraDeviceInfoObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(!cameraDeviceInfoObj, supportedPortraitEffects,
        "CaptureSession::UpdateSetting Failed cameraDeviceInfoObj is nullptr");

    int ret = VerifyAbility(static_cast<uint32_t>(OHOS_ABILITY_SCENE_PORTRAIT_EFFECT_TYPES));
    CHECK_RETURN_RET_ELOG(
        ret != CAMERA_OK, supportedPortraitEffects, "CaptureSession::GetSupportedPortraitEffects abilityId is NULL");
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraDeviceInfoObj->GetCachedMetadata();
    CHECK_RETURN_RET(metadata == nullptr, supportedPortraitEffects);
    camera_metadata_item_t item;
    ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_SCENE_PORTRAIT_EFFECT_TYPES, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count == 0, supportedPortraitEffects,
        "CaptureSession::GetSupportedPortraitEffects Failed with return code %{public}d", ret);
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = g_metaToFwPortraitEffect_.find(static_cast<camera_portrait_effect_type_t>(item.data.u8[i]));
        if (itr != g_metaToFwPortraitEffect_.end()) {
            supportedPortraitEffects.emplace_back(itr->second);
        }
    }
    return supportedPortraitEffects;
}

int32_t CaptureSession::GetVirtualAperture(float& aperture)
{
    CHECK_RETURN_RET_ELOG(
        !IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG, "GetVirtualAperture Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice, CameraErrorCode::SUCCESS, "GetVirtualAperture camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(!inputDeviceInfo, CameraErrorCode::SUCCESS, "GetVirtualAperture camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetCachedMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, CameraErrorCode::SUCCESS, "GetVirtualAperture camera metadata is null");
    CHECK_RETURN_RET(metadata == nullptr, CameraErrorCode::SUCCESS);
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_CAMERA_VIRTUAL_APERTURE_VALUE, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count == 0, CameraErrorCode::SUCCESS,
        "GetVirtualAperture Failed with return code %{public}d", ret);
    aperture = item.data.f[0];
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetVirtualAperture(const float virtualAperture)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(
        !IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG, "SetVirtualAperture Session is not Commited");
    CHECK_RETURN_RET_ELOG(
        changedMetadata_ == nullptr, CameraErrorCode::SUCCESS, "SetVirtualAperture changedMetadata_ is NULL");
    std::vector<float> supportedVirtualApertures {};
    GetSupportedVirtualApertures(supportedVirtualApertures);
    auto res = std::find_if(supportedVirtualApertures.begin(), supportedVirtualApertures.end(),
        [&virtualAperture](const float item) { return FloatIsEqual(virtualAperture, item); });
    CHECK_RETURN_RET_ELOG(
        res == supportedVirtualApertures.end(), CameraErrorCode::SUCCESS, "current virtualAperture is not supported");
    MEDIA_DEBUG_LOG("SetVirtualAperture virtualAperture: %{public}f", virtualAperture);
    bool status = AddOrUpdateMetadata(
        changedMetadata_, OHOS_CONTROL_CAMERA_VIRTUAL_APERTURE_VALUE, &virtualAperture, 1);
    CHECK_PRINT_ELOG(!status, "SetVirtualAperture Failed to set virtualAperture");
    isVirtualApertureEnabled_ = true;
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::GetPhysicalAperture(float& physicalAperture)
{
    physicalAperture = 0.0;
    CHECK_RETURN_RET_ELOG(
        !IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG, "GetPhysicalAperture Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::SUCCESS,
        "GetPhysicalAperture camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(!inputDeviceInfo, CameraErrorCode::SUCCESS, "GetPhysicalAperture camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetCachedMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, CameraErrorCode::SUCCESS, "GetPhysicalAperture camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_CAMERA_PHYSICAL_APERTURE_VALUE, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count == 0, CameraErrorCode::SUCCESS,
        "GetPhysicalAperture Failed with return code %{public}d", ret);
    physicalAperture = item.data.f[0];
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetPhysicalAperture(float physicalAperture)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(
        !IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG, "SetPhysicalAperture Session is not Commited");
    CHECK_RETURN_RET_ELOG(
        changedMetadata_ == nullptr, CameraErrorCode::SUCCESS, "SetPhysicalAperture changedMetadata_ is NULL");
    MEDIA_DEBUG_LOG(
        "CaptureSession::SetPhysicalAperture physicalAperture = %{public}f", ConfusingNumber(physicalAperture));
    std::vector<std::vector<float>> physicalApertures;
    GetSupportedPhysicalApertures(physicalApertures);
    // physicalApertures size is one, means not support change
    CHECK_RETURN_RET_ELOG(physicalApertures.size() == 1, CameraErrorCode::SUCCESS, "SetPhysicalAperture not support");
    // accurately currentZoomRatio need smoothing zoom done
    float currentZoomRatio = targetZoomRatio_;
    CHECK_EXECUTE(!isSmoothZooming_ || FloatIsEqual(targetZoomRatio_, -1.0), currentZoomRatio = GetZoomRatio());
    int zoomMinIndex = 0;
    for (const auto& physicalApertureRange : physicalApertures) {
        CHECK_CONTINUE(physicalApertureRange.size() <= static_cast<size_t>(zoomMinIndex + 1));
        if ((currentZoomRatio > physicalApertureRange[zoomMinIndex] - std::numeric_limits<float>::epsilon() &&
            currentZoomRatio < physicalApertureRange[zoomMinIndex+1] + std::numeric_limits<float>::epsilon())) {
            matchedRanges.push_back(physicalApertureRange);
        }
    }
    CHECK_RETURN_RET_ELOG(matchedRanges.empty(), CameraErrorCode::SUCCESS, "matchedRanges is empty.");
    for (const auto& matchedRange : matchedRanges) {
        auto res = std::find_if(std::next(matchedRange.begin(), physicalAperturesIndex_), matchedRange.end(),
            [&physicalAperture](const float physicalApertureTemp) {
                return FloatIsEqual(physicalAperture, physicalApertureTemp);
            });
        if (res != matchedRange.end()) {
            isApertureSupported_ = true;
            break;
        }
    }
    float autoAperture = 0.0;
    CHECK_RETURN_RET_ELOG((physicalAperture != autoAperture) && !isApertureSupported_, CameraErrorCode::SUCCESS,
        "current physicalAperture is not supported");
    CHECK_RETURN_RET_ELOG(!AddOrUpdateMetadata(changedMetadata_->get(), OHOS_CONTROL_CAMERA_PHYSICAL_APERTURE_VALUE,
        &physicalAperture, 1), CameraErrorCode::SUCCESS, "SetPhysicalAperture Failed to set physical aperture");
    wptr<CaptureSession> weakThis(this);
    AddFunctionToMap(std::to_string(OHOS_CONTROL_CAMERA_PHYSICAL_APERTURE_VALUE), [weakThis, physicalAperture]() {
        auto sharedThis = weakThis.promote();
        CHECK_RETURN_ELOG(!sharedThis, "SetPhysicalAperture session is nullptr");
        sharedThis->LockForControl();
        int32_t retCode = sharedThis->SetPhysicalAperture(physicalAperture);
        sharedThis->UnlockForControl();
        CHECK_EXECUTE(retCode != CameraErrorCode::SUCCESS, sharedThis->SetDeviceCapabilityChangeStatus(true));
    });
    apertureValue_ = physicalAperture;
    isVirtualApertureEnabled_ = false;
    return CameraErrorCode::SUCCESS;
}

bool CaptureSession::IsLcdFlashSupported()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("IsLcdFlashSupported is called");
    CHECK_RETURN_RET_ELOG(
        !(IsSessionCommited() || IsSessionConfiged()), false, "IsLcdFlashSupported Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice, false, "IsLcdFlashSupported camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(!inputDeviceInfo, false, "IsLcdFlashSupported camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetCachedMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, false, "IsLcdFlashSupported camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_LCD_FLASH, &item);
    CHECK_RETURN_RET_ELOG(
        ret != CAM_META_SUCCESS, false, "IsLcdFlashSupported Failed with return code %{public}d", ret);
    MEDIA_INFO_LOG("IsLcdFlashSupported value: %{public}u", item.data.i32[0]);
    return item.data.i32[0] == 1;
}

void CaptureSession::ProcessLcdFlashStatusUpdates(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
    __attribute__((no_sanitize("cfi")))
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Entry ProcessLcdFlashStatusUpdates");

    auto statusCallback = GetLcdFlashStatusCallback();
    CHECK_RETURN_DLOG(statusCallback == nullptr, "CaptureSession::ProcessLcdFlashStatusUpdates statusCallback is null");
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_STATUS_LCD_FLASH_STATUS, &item);
    bool isNotFindItem = ret != CAM_META_SUCCESS || item.count <= 0;
    CHECK_RETURN_DLOG(isNotFindItem, "Camera not support lcd flash");
    constexpr uint32_t validCount = 2;
    CHECK_RETURN_ELOG(item.count != validCount, "OHOS_STATUS_LCD_FLASH_STATUS invalid data size");
    auto isLcdFlashNeeded = static_cast<bool>(item.data.i32[0]);
    auto lcdCompensation = item.data.i32[1];
    LcdFlashStatusInfo preLcdFlashStatusInfo = statusCallback->GetLcdFlashStatusInfo();
    bool isStatusChanged = preLcdFlashStatusInfo.isLcdFlashNeeded != isLcdFlashNeeded ||
        preLcdFlashStatusInfo.lcdCompensation != lcdCompensation;
    if (isStatusChanged) {
        LcdFlashStatusInfo lcdFlashStatusInfo;
        lcdFlashStatusInfo.isLcdFlashNeeded = isLcdFlashNeeded;
        lcdFlashStatusInfo.lcdCompensation = lcdCompensation;
        statusCallback->SetLcdFlashStatusInfo(lcdFlashStatusInfo);
        statusCallback->OnLcdFlashStatusChanged(lcdFlashStatusInfo);
    }
}

std::shared_ptr<LcdFlashStatusCallback> CaptureSession::GetLcdFlashStatusCallback()
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    return lcdFlashStatusCallback_;
}

void CaptureSession::EnableFaceDetection(bool enable)
{
    MEDIA_INFO_LOG("EnableFaceDetection enable: %{public}d", enable);
    CHECK_RETURN_ELOG(GetMetaOutput() == nullptr, "MetaOutput is null");
    if (!enable) {
        std::set<camera_face_detect_mode_t> objectTypes;
        SetCaptureMetadataObjectTypes(objectTypes);
        return;
    }
    sptr<MetadataOutput> metaOutput = static_cast<MetadataOutput*>(GetMetaOutput().GetRefPtr());
    CHECK_RETURN_ELOG(!metaOutput, "MetaOutput is null");
    std::vector<MetadataObjectType> metadataObjectTypes = metaOutput->GetSupportedMetadataObjectTypes();
    MEDIA_INFO_LOG("EnableFaceDetection SetCapturingMetadataObjectTypes objectTypes size = %{public}zu",
        metadataObjectTypes.size());
    metaOutput->SetCapturingMetadataObjectTypes(metadataObjectTypes);
}

bool CaptureSession::IsTripodDetectionSupported()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("Enter IsTripodDetectionSupported");
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), false,
        "CaptureSession::IsTripodDetectionSupported Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), false,
        "CaptureSession::IsTripodDetectionSupported camera device is null");
    auto deviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(
        deviceInfo == nullptr, false, "CaptureSession::IsTripodDetectionSupported camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = deviceInfo->GetCachedMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, false, "IsTripodDetectionSupported camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_TRIPOD_DETECTION, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count <= 0, false,
        "CaptureSession::IsTripodDetectionSupported Failed with return code %{public}d", ret);
    auto supportResult = static_cast<bool>(item.data.i32[0]);
    return supportResult;
}

int32_t CaptureSession::EnableTripodStabilization(bool isEnable)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("Enter EnableTripodStabilization, isEnable:%{public}d", isEnable);
    CHECK_RETURN_RET_ELOG(!IsTripodDetectionSupported(), CameraErrorCode::OPERATION_NOT_ALLOWED,
        "EnableTripodStabilization IsTripodDetectionSupported is false");
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG, "Session is not Commited");
    uint8_t enableValue = static_cast<uint8_t>(isEnable ? 1 : 0);
    if (!AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_TRIPOD_STABLITATION, &enableValue, 1)) {
        MEDIA_ERR_LOG("EnableTripodStabilization failed to enable tripod detection");
    } else {
        isSetTripodDetectionEnable_ = isEnable;
    }
    return CameraErrorCode::SUCCESS;
}

void CaptureSession::ProcessTripodStatusChange(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
__attribute__((no_sanitize("cfi")))
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Entry ProcessTripodStatusChange");
    auto featureStatusCallback = GetFeatureDetectionStatusCallback();
    if (featureStatusCallback == nullptr ||
        !featureStatusCallback->IsFeatureSubscribed(SceneFeature::FEATURE_TRIPOD_DETECTION)) {
        MEDIA_DEBUG_LOG("CaptureSession::ProcessTripodStatusChange"
                        "featureDetectionStatusChangedCallback are null");
        return;
    }
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_STATUS_TRIPOD_DETECTION_STATUS, &item);
    bool isNotFindItem = ret != CAM_META_SUCCESS || item.count <= 0;
    CHECK_RETURN_DLOG(isNotFindItem, "Camera not support tripod detection");
    FwkTripodStatus tripodStatus = FwkTripodStatus::INVALID;
    auto itr = metaTripodStatusMap_.find(static_cast<TripodStatus>(item.data.u8[0]));
    CHECK_RETURN_DLOG(itr == metaTripodStatusMap_.end(), "Tripod status not found");
    tripodStatus = itr->second;
    MEDIA_DEBUG_LOG("Tripod status: %{public}d", tripodStatus);
    bool isStatusChanged = featureStatusCallback != nullptr &&
        featureStatusCallback->IsFeatureSubscribed(SceneFeature::FEATURE_TRIPOD_DETECTION) &&
        (static_cast<int>(featureStatusCallback->GetFeatureStatus()) != static_cast<int>(tripodStatus));
    if (isStatusChanged) {
        auto detectStatus = FeatureDetectionStatusCallback::FeatureDetectionStatus::ACTIVE;
        featureStatusCallback->SetFeatureStatus(static_cast<int8_t>(tripodStatus));
        featureStatusCallback->OnFeatureDetectionStatusChanged(SceneFeature::FEATURE_TRIPOD_DETECTION, detectStatus);
    }
}

bool CaptureSession::JudgeMultiFrontCamera()
{
    int32_t result = 0;
    auto cameraDeviceList = CameraManager::GetInstance()->GetSupportedCameras();
    for (const auto& cameraDevice : cameraDeviceList) {
        CHECK_EXECUTE(cameraDevice->GetPosition() == CAMERA_POSITION_FRONT, result++);
    }
    return (result > 1);
}

bool CaptureSession::IsAutoDeviceSwitchSupported()
{
    bool isSupported = CameraManager::GetInstance()->GetIsFoldable();
    CHECK_RETURN_RET_ILOG(!JudgeMultiFrontCamera(), isSupported, "IsAutoDeviceSwitchSupported: %{public}d.",
        isSupported);
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, isSupported, "IsAutoDeviceSwitchSupported GetMetadata Failed");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_SENSOR_ORIENTATION_VARIABLE, &item);
    CHECK_EXECUTE(ret == CAMERA_OK && (item.count > 0 && item.data.u8[0]), isSupported = false);
    return isSupported;
}

int32_t CaptureSession::EnableAutoDeviceSwitch(bool isEnable)
{
    MEDIA_INFO_LOG("EnableAutoDeviceSwitch, isEnable:%{public}d", isEnable);
    CHECK_RETURN_RET_ELOG(!IsAutoDeviceSwitchSupported(), CameraErrorCode::OPERATION_NOT_ALLOWED,
        "The automatic switchover mode is not supported.");
    CHECK_RETURN_RET_ELOG(GetIsAutoSwitchDeviceStatus() == isEnable, CameraErrorCode::SUCCESS, "Repeat Settings.");
    SetIsAutoSwitchDeviceStatus(isEnable);
    if (GetIsAutoSwitchDeviceStatus()) {
        MEDIA_INFO_LOG("RegisterFoldStatusListener is called");
        CreateAndSetFoldServiceCallback();
    }
    return CameraErrorCode::SUCCESS;
}

void CaptureSession::SetIsAutoSwitchDeviceStatus(bool isEnable)
{
    isAutoSwitchDevice_ = isEnable;
}

bool CaptureSession::GetIsAutoSwitchDeviceStatus()
{
    return isAutoSwitchDevice_;
}

bool CaptureSession::SwitchDevice()
{
    std::lock_guard<std::mutex> lock(switchDeviceMutex_);
    CHECK_RETURN_RET_ELOG(
        !IsSessionStarted(), false, "The switch device has failed because the session has not started.");
    auto captureInput = GetInputDevice();
    auto cameraInput = (sptr<CameraInput>&)captureInput;
    CHECK_RETURN_RET_ELOG(cameraInput == nullptr, false, "cameraInput is nullptr.");
    auto deviceiInfo = cameraInput->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(!deviceiInfo ||
            (deviceiInfo->GetPosition() != CAMERA_POSITION_FRONT &&
                deviceiInfo->GetPosition() != CAMERA_POSITION_FOLD_INNER),
        false, "No need switch camera.");
    bool hasVideoOutput = StopVideoOutput();
    int32_t retCode = CameraErrorCode::SUCCESS;
    Stop();
    BeginConfig();
    RemoveInput(captureInput);
    cameraInput->Close();
    sptr<CameraDevice> cameraDeviceTemp = FindFrontCamera();
    CHECK_RETURN_RET_ELOG(cameraDeviceTemp == nullptr, false, "No front camera found.");
    sptr<ICameraDeviceService> deviceObj = nullptr;
    retCode = CameraManager::GetInstance()->CreateCameraDevice(cameraDeviceTemp->GetID(), &deviceObj);
    CHECK_RETURN_RET_ELOG(
        retCode != CameraErrorCode::SUCCESS, false, "SwitchDevice::CreateCameraDevice Create camera device failed.");
    cameraInput->SwitchCameraDevice(deviceObj, cameraDeviceTemp);
    retCode = cameraInput->Open();
    CHECK_PRINT_ELOG(retCode != CameraErrorCode::SUCCESS, "SwitchDevice::Open failed.");
    retCode = AddInput(captureInput);
    CHECK_PRINT_ELOG(retCode != CameraErrorCode::SUCCESS, "SwitchDevice::AddInput failed.");
    retCode = CommitConfig();
    CHECK_PRINT_ELOG(retCode != CameraErrorCode::SUCCESS, "SwitchDevice::CommitConfig failed.");
    ExecuteAllFunctionsInMap();
    retCode = Start();
    CHECK_PRINT_ELOG(retCode != CameraErrorCode::SUCCESS, "SwitchDevice::Start failed.");
    CHECK_EXECUTE(hasVideoOutput, StartVideoOutput());
    return true;
}

sptr<CameraDevice> CaptureSession::FindFrontCamera()
{
    auto cameraDeviceList = CameraManager::GetInstance()->GetSupportedCamerasWithFoldStatus();
    for (const auto& cameraDevice : cameraDeviceList) {
        bool isFindDevice = cameraDevice->GetPosition() == CAMERA_POSITION_FRONT ||
            cameraDevice->GetPosition() == CAMERA_POSITION_FOLD_INNER;
        CHECK_RETURN_RET(isFindDevice, cameraDevice);
    }
    return nullptr;
}

void CaptureSession::StartVideoOutput()
{
    sptr<VideoOutput> videoOutput = nullptr;
    {
        std::lock_guard<std::mutex> lock(captureOutputSetsMutex_);
        for (const auto& output : captureOutputSets_) {
            auto item = output.promote();
            bool isFindOutput = item && item->GetOutputType() == CAPTURE_OUTPUT_TYPE_VIDEO;
            if (isFindOutput) {
                videoOutput = (sptr<VideoOutput>&)item;
                break;
            }
        }
    }
    CHECK_EXECUTE(videoOutput, videoOutput->Start());
}

bool CaptureSession::StopVideoOutput()
{
    sptr<VideoOutput> videoOutput = nullptr;
    bool hasVideoOutput = false;
    {
        std::lock_guard<std::mutex> lock(captureOutputSetsMutex_);
        for (const auto& output : captureOutputSets_) {
            auto item = output.promote();
            bool isFindOutput = item && item->GetOutputType() == CAPTURE_OUTPUT_TYPE_VIDEO;
            if (isFindOutput) {
                videoOutput = (sptr<VideoOutput>&)item;
                break;
            }
        }
    }
    bool isStartedOutput = videoOutput && videoOutput->IsVideoStarted();
    if (isStartedOutput) {
        videoOutput->Stop();
        hasVideoOutput = true;
    }
    return hasVideoOutput;
}

void CaptureSession::SetAutoDeviceSwitchCallback(shared_ptr<AutoDeviceSwitchCallback> autoDeviceSwitchCallback)
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    autoDeviceSwitchCallback_ = autoDeviceSwitchCallback;
}

shared_ptr<AutoDeviceSwitchCallback> CaptureSession::GetAutoDeviceSwitchCallback()
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    return autoDeviceSwitchCallback_;
}

void CaptureSession::AddFunctionToMap(std::string ctrlTarget, std::function<void()> func)
{
    bool isNotAdd = !GetIsAutoSwitchDeviceStatus() || !canAddFuncToMap_;
    CHECK_RETURN_DLOG(isNotAdd, "The automatic switching device is not enabled.");
    std::lock_guard<std::mutex> lock(functionMapMutex_);
    functionMap[ctrlTarget] = func;
}

void CaptureSession::ExecuteAllFunctionsInMap()
{
    MEDIA_INFO_LOG("ExecuteAllFunctionsInMap is called.");
    canAddFuncToMap_ = false;
    std::lock_guard<std::mutex> lock(functionMapMutex_);
    for (const auto& pair : functionMap) {
        pair.second();
    }
    canAddFuncToMap_ = true;
}

void CaptureSession::CreateAndSetFoldServiceCallback()
{
    auto serviceProxy = CameraManager::GetInstance()->GetServiceProxy();
    CHECK_RETURN_ELOG(serviceProxy == nullptr, "CaptureSession::CreateAndSetFoldServiceCallback serviceProxy is null");
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    foldStatusCallback_ = new(std::nothrow) FoldCallback(this);
    CHECK_RETURN_ELOG(foldStatusCallback_ == nullptr,
        "CaptureSession::CreateAndSetFoldServiceCallback failed to new foldSvcCallback_!");
    int32_t retCode = serviceProxy->SetFoldStatusCallback(foldStatusCallback_, true);
    CHECK_PRINT_ELOG(retCode != CAMERA_OK,
        "CreateAndSetFoldServiceCallback Set service Callback failed, retCode: %{public}d", retCode);
}

int32_t CaptureSession::SetQualityPrioritization(QualityPrioritization qualityPrioritization)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::SetQualityPrioritization Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::SetQualityPrioritization Need to call LockForControl() before setting camera properties");
    uint8_t quality = HIGH_QUALITY;
    auto itr = g_fwkQualityPrioritizationMap_.find(qualityPrioritization);
    CHECK_RETURN_RET_ELOG(itr == g_fwkQualityPrioritizationMap_.end(), CameraErrorCode::PARAMETER_ERROR,
        "CaptureSession::SetColorSpace() map failed, %{public}d", static_cast<int32_t>(qualityPrioritization));
    quality = itr->second;
    MEDIA_DEBUG_LOG(
        "CaptureSession::SetQualityPrioritization quality prioritization: %{public}d", qualityPrioritization);
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_QUALITY_PRIORITIZATION, &quality, 1);
    CHECK_PRINT_ELOG(!status, "CaptureSession::SetQualityPrioritization Failed to set quality prioritization");
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::GetSupportedFocusRangeTypes(std::vector<FocusRangeType>& types)
{
    types.clear();
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::GetSupportedFocusRangeTypes Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::SUCCESS,
        "CaptureSession::GetSupportedFocusRangeTypes camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, CameraErrorCode::SUCCESS, "GetSupportedFocusRangeTypes camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FOCUS_RANGE_TYPES, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "CaptureSession::GetSupportedFocusRangeTypes Failed with return code %{public}d", ret);
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = g_metaFocusRangeTypeMap_.find(static_cast<camera_focus_range_type_t>(item.data.u8[i]));
        if (itr != g_metaFocusRangeTypeMap_.end()) {
            types.emplace_back(itr->second);
        }
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::GetSupportedFocusDrivenTypes(std::vector<FocusDrivenType>& types)
{
    types.clear();
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::GetSupportedFocusDrivenTypes Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::SUCCESS,
        "CaptureSession::GetSupportedFocusDrivenTypes camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, CameraErrorCode::SUCCESS, "GetSupportedFocusDrivenTypes camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FOCUS_DRIVEN_TYPES, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "CaptureSession::GetSupportedFocusDrivenTypes Failed with return code %{public}d", ret);
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = g_metaFocusDrivenTypeMap_.find(static_cast<camera_focus_driven_type_t>(item.data.u8[i]));
        if (itr != g_metaFocusDrivenTypeMap_.end()) {
            types.emplace_back(itr->second);
        }
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::EnableAutoAigcPhoto(bool enabled)
{
    MEDIA_INFO_LOG("CaptureSession::EnableAutoAigcPhoto enabled:%{public}d", enabled);
    LockGuardForControl lock(this);
    CHECK_RETURN_RET_ELOG(
        changedMetadata_ == nullptr, PARAMETER_ERROR, "CaptureSession::EnableAutoAigcPhoto changedMetadata_ is NULL");
    int32_t res = CameraErrorCode::SUCCESS;
    uint8_t autoAigcPhoto = static_cast<uint8_t>(enabled);
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_AUTO_AIGC_PHOTO, &autoAigcPhoto, 1);
    CHECK_RETURN_RET_ELOG(!status, PARAMETER_ERROR, "CaptureSession::EnableAutoAigcPhoto failed to set type!");
    CHECK_PRINT_ELOG(res != CameraErrorCode::SUCCESS, "CaptureSession::EnableAutoAigcPhoto failed");
    return res;
}

void CaptureSession::SetCompositionPositionCalibrationCallback(
    std::shared_ptr<CompositionPositionCalibrationCallback> callback)
{
    CHECK_RETURN_ELOG(callback == nullptr, "PhotoSession::SetCallback callback is null");
    std::lock_guard<std::mutex> lock(positionCalibrationCallbackMutex_);
    compositionPositionCalibrationCallback_ = callback;
}

std::shared_ptr<CompositionPositionCalibrationCallback> CaptureSession::GetCompositionPositionCalibrationCallback()
{
    std::lock_guard<std::mutex> lock(positionCalibrationCallbackMutex_);
    return compositionPositionCalibrationCallback_;
}

void CaptureSession::SetCompositionBeginCallback(std::shared_ptr<CompositionBeginCallback> callback)
{
    CHECK_RETURN_ELOG(callback == nullptr, "PhotoSession::SetCallback callback is null");
    std::lock_guard<std::mutex> lock(compositionBeginCallbackMutex_);
    compositionBeginCallback_ = callback;
}

int32_t CaptureSession::SetCompositionEffectReceiveCallback(
    std::shared_ptr<NativeInfoCallback<CompositionEffectInfo>> callback)
{
    CHECK_RETURN_RET_ELOG(
        !CameraSecurity::CheckSystemApp(), CameraErrorCode::NO_SYSTEM_APP_PERMISSION, "SystemApi called!");
    CHECK_RETURN_RET_ELOG(compositionFeature_ == nullptr, CAMERA_OK, "compositionFeature_ is nullptr");
    return compositionFeature_->SetCompositionEffectReceiveCallback(callback);
}

int32_t CaptureSession::UnSetCompositionEffectReceiveCallback()
{
    return SetCompositionEffectReceiveCallback(nullptr);
}

std::shared_ptr<CompositionBeginCallback> CaptureSession::GetCompositionBeginCallback()
{
    std::lock_guard<std::mutex> lock(compositionBeginCallbackMutex_);
    return compositionBeginCallback_;
}

void CaptureSession::SetCompositionEndCallback(std::shared_ptr<CompositionEndCallback> callback)
{
    CHECK_RETURN_ELOG(callback == nullptr, "PhotoSession::SetCallback callback is null");
    std::lock_guard<std::mutex> lock(compositionEndCallbackMutex_);
    compositionEndCallback_ = callback;
}

std::shared_ptr<CompositionEndCallback> CaptureSession::GetCompositionEndCallback()
{
    std::lock_guard<std::mutex> lock(compositionEndCallbackMutex_);
    return compositionEndCallback_;
}

void CaptureSession::SetCompositionPositionMatchCallback(std::shared_ptr<CompositionPositionMatchCallback> callback)
{
    CHECK_RETURN_ELOG(callback == nullptr, "PhotoSession::SetCallback callback is null");
    std::lock_guard<std::mutex> lock(positionMatchCallbackMutex_);
    compositionPositionMatchCallback_ = callback;
}

std::shared_ptr<CompositionPositionMatchCallback> CaptureSession::GetCompositionPositionMatchCallback()
{
    std::lock_guard<std::mutex> lock(positionMatchCallbackMutex_);
    return compositionPositionMatchCallback_;
}

void CaptureSession::SetImageStabilizationGuideCallback(std::shared_ptr<ImageStabilizationGuideCallback> callback)
{
    CHECK_RETURN_ELOG(callback == nullptr, "CaptureSession::SetImageStabilizationGuideCallback callback is null");
    std::lock_guard<std::mutex> lock(imageStabilizationGuidehCallbackMutex_);
    imageStabilizationGuideCallback_ = callback;
}

bool CaptureSession::IsCompositionSuggestionSupported()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("IsCompositionSuggestionSupported is called");
    CHECK_RETURN_RET_ELOG(
        !CameraSecurity::CheckSystemApp(), false, "SystemApi IsCompositionSuggestionSupported is called!");
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), false, "IsCompositionSuggestionSupported Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice, false, "IsCompositionSuggestionSupported camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(!inputDeviceInfo, false, "IsCompositionSuggestionSupported camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_COMPOSITION_SUGGESTION, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count <= 0, false,
        "IsCompositionSuggestionSupported Failed with return code %{public}d", ret);
    vector<int32_t> modes = {};
    for (uint32_t index = 0; index < item.count; index++) {
        modes.push_back(item.data.u8[index]);
        MEDIA_DEBUG_LOG("IsCompositionSuggestionSupported mode:%{public}d", item.data.u8[index]);
    }
    auto isSupported = std::find(modes.begin(), modes.end(), GetMode()) != modes.end();
    MEDIA_INFO_LOG("IsCompositionSuggestionSupported: %{public}u", isSupported);
    return isSupported;
}

int32_t CaptureSession::EnableCompositionSuggestion(bool isEnable)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(!CameraSecurity::CheckSystemApp(), CameraErrorCode::OPERATION_NOT_ALLOWED,
        "SystemApi EnableCompositionSuggestion is called!");
    MEDIA_INFO_LOG("Enter EnableCompositionSuggestion, isEnable:%{public}d", isEnable);
    CHECK_RETURN_RET_ELOG(
        !IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG, "EnableCompositionSuggestion session not commited");
    CHECK_RETURN_RET_ELOG(!IsCompositionSuggestionSupported(), CameraErrorCode::OPERATION_NOT_ALLOWED,
        "CaptureSession::EnableCompositionSuggestion not supported.");
    uint8_t enableValue = static_cast<uint8_t>(isEnable);
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_COMPOSITION_SUGGESTION, &enableValue, 1);
    CHECK_PRINT_ELOG(!status, "Failed to enable composition suggestion.");
    return CameraErrorCode::SUCCESS;
}

void CaptureSession::ProcessCompositionPositionCalibration(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Entry ProcessCompositionPositionCalibration");

    auto compositionPositionCalibrationCallback = GetCompositionPositionCalibrationCallback();
    CHECK_RETURN_DLOG(!compositionPositionCalibrationCallback, "compositionPositionCalibrationCallback is null");
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_COMPOSITION_POSITION_CALIBRATION, &item);
    bool isNotFindItem = ret != CAM_META_SUCCESS || item.count <= 0;
    CHECK_RETURN_DLOG(isNotFindItem, "not found composition position");

    HILOG_COMM_INFO("ProcessCompositionPositionCalibration count:%{public}d", item.count);

    CalibrationStatus pitchAngleStatus = CalibrationStatus::CALIBRATION_INVALID;
    CalibrationStatus positionStatus = CalibrationStatus::CALIBRATION_INVALID;
    float pitchAngle = 0.0;
    Point targetPosition;
    std::vector<Point> compositionPoints;
    int8_t step_two = 2;
    if (item.count % step_two == 0) {
        ParsePositionOnly(item, targetPosition, compositionPoints);
    } else {
        ParseFullCalibration(item, pitchAngleStatus, positionStatus, pitchAngle, targetPosition, compositionPoints);
    }

    ret = Camera::FindCameraMetadataItem(metadata, OHOS_COMPOSITION_POSITION_CALIBRATION_EXPAND, &item);
    isNotFindItem = ret != CAM_META_SUCCESS || item.count <= 0;

    CHECK_RETURN_DLOG(isNotFindItem, "not found composition position");

    CalibrationStatus rotationAngleStatus = CalibrationStatus::CALIBRATION_INVALID;
    float rotationAngle = 0.0;
    RoParseFullCalibration(item, rotationAngleStatus, rotationAngle);

    CompositionPositionCalibrationInfo info = {
        targetPosition, compositionPoints, pitchAngleStatus, positionStatus, pitchAngle,
        rotationAngleStatus, rotationAngle
    };

    compositionPositionCalibrationCallback->OnCompositionPositionCalibrationAvailable(info);
}

void CaptureSession::ParsePositionOnly(const camera_metadata_item_t& item, Point& targetPosition,
    std::vector<Point>& compositionPoints)
{
    uint32_t targetPositionLen = 2;
    CHECK_RETURN_DLOG(item.count < targetPositionLen, "item count < 2");

    targetPosition = {item.data.f[0], item.data.f[1]};
    MEDIA_DEBUG_LOG("ProcessCompositionPositionCalibration targetPosition x:%{public}f, targetPosition y:%{public}f",
        item.data.f[0], item.data.f[1]);

    uint32_t offset = 2;
    for (uint32_t i = offset; i < item.count; i += offset) {
        if (i + 1 < item.count) {
            compositionPoints.push_back({item.data.f[i], item.data.f[i+1]});
        }
    }
}

void CaptureSession::RoParseFullCalibration(const camera_metadata_item_t& item, CalibrationStatus& rotationAngleStatus,
    float& rotationAngle)
{
    int8_t rotationAngleStatusIndex = 0;
    int8_t rotationAngleIndex = 1;

    rotationAngleStatus = static_cast<CalibrationStatus>(item.data.f[rotationAngleStatusIndex]);
    rotationAngle = item.data.f[rotationAngleIndex];

    MEDIA_INFO_LOG("RoParseFullCalibration rotationAngleStatus: %{public}d, "
        "rotationAngle: %{public}f", rotationAngleStatus, rotationAngle);
}

void CaptureSession::ParseFullCalibration(const camera_metadata_item_t& item, CalibrationStatus& pitchAngleStatus,
    CalibrationStatus& positionStatus, float& pitchAngle, Point& targetPosition, std::vector<Point>& compositionPoints)
{
    int8_t pitchAngleStatusIndex = 0;
    int8_t positionStatusIndex = 1;
    int8_t pitchAngleIndex = 2;
    int8_t targetPositionXIndex = 3;
    int8_t targetPositionYIndex = 4;

    pitchAngleStatus = static_cast<CalibrationStatus>(item.data.f[pitchAngleStatusIndex]);
    positionStatus = static_cast<CalibrationStatus>(item.data.f[positionStatusIndex]);
    pitchAngle = item.data.f[pitchAngleIndex];
    targetPosition = {item.data.f[targetPositionXIndex], item.data.f[targetPositionYIndex]};

    uint32_t offset = 2;
    for (uint32_t i = targetPositionYIndex + 1; i < item.count; i += offset) {
        if (i + 1 < item.count) {
            compositionPoints.push_back({item.data.f[i], item.data.f[i+1]});
        }
    }

    MEDIA_DEBUG_LOG("ProcessCompositionPositionCalibration pitchAngleStatus: %{public}d, "
        "positionStatus: %{public}d, pitchAngle: %{public}f", pitchAngleStatus, positionStatus, pitchAngle);
}

bool CaptureSession::IsImageStabilizationGuideSupported()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter IsImageStabilizationGuideSupported");
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), false,
        "CaptureSession::IsImageStabilizationGuideSupported Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        inputDevice == nullptr, false, "CaptureSession::IsImageStabilizationGuideSupported camera device is null");
    auto deviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(
        deviceInfo == nullptr, false, "CaptureSession::IsImageStabilizationGuideSupported camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = deviceInfo->GetCachedMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, false, "IsImageStabilizationGuideSupported camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_IMAGE_STABILIZATION_GUIDE, &item);
    return ret == CAM_META_SUCCESS && item.count > 0 && item.data.u8[0] == 1;
}

int32_t CaptureSession::EnableImageStabilizationGuide(bool enabled)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("CaptureSession::EnableImageStabilizationGuide Enter");
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::EnableImageStabilizationGuide Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::EnableImageStabilizationGuide Need to call LockForControl() before setting camera properties");
    CHECK_RETURN_RET_ELOG(!IsImageStabilizationGuideSupported(), CameraErrorCode::OPERATION_NOT_ALLOWED,
        "CaptureSession::EnableImageStabilizationGuide not supported.");
    uint8_t value = static_cast<uint8_t>(enabled);
    MEDIA_DEBUG_LOG("EnableImageStabilizationGuide %{public}d", value);
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_IMAGE_STABILIZATION_GUIDE, &value, 1);
    CHECK_PRINT_ELOG(!status, "CaptureSession::EnableImageStabilizationGuide Failed to set flash mode");
    return CameraErrorCode::SUCCESS;
}

void CaptureSession::ProcessCompositionBegin(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Entry ProcessCompositionBegin");
    auto compositionBeginCallback = GetCompositionBeginCallback();
    CHECK_RETURN_DLOG(compositionBeginCallback == nullptr, "compositionBeginCallback is null");
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_COMPOSITION_BEGIN, &item);
    bool isNotFindItem = ret != CAM_META_SUCCESS || item.count <= 0;
    CHECK_RETURN_DLOG(isNotFindItem, "not found begin state");
    compositionBeginCallback->OnCompositionBeginAvailable();
}

void CaptureSession::ProcessCompositionEnd(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Entry ProcessCompositionEnd");
    auto compositionEndCallback = GetCompositionEndCallback();
    CHECK_RETURN_DLOG(compositionEndCallback == nullptr, "compositionEndCallback is null");
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_COMPOSITION_END, &item);
    bool isNotFindItem = ret != CAM_META_SUCCESS || item.count <= 0;
    CHECK_RETURN_DLOG(isNotFindItem, "not found end state");
    compositionEndCallback->OnCompositionEndAvailable(static_cast<CompositionEndState>(item.data.u8[0]));
}

void CaptureSession::ProcessCompositionPositionMatch(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Entry ProcessCompositionSuggestionInfo");
    auto compositionPositionMatchCallback = GetCompositionPositionMatchCallback();
    CHECK_RETURN_DLOG(compositionPositionMatchCallback == nullptr, "compositionPositionMatchCallback is null");
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_COMPOSITION_MATCHED, &item);
    bool isNotFindItem = ret != CAM_META_SUCCESS || item.count <= 0;
    CHECK_RETURN_DLOG(isNotFindItem, "not match state");
    std::vector<float> zoomRatios;
    for (uint32_t i = 0; i < item.count; i++) {
        zoomRatios.push_back(item.data.f[i]);
    }
    MEDIA_DEBUG_LOG("CompositionPositionMatch zoomRatios size: %{public}zu", zoomRatios.size());
    compositionPositionMatchCallback->OnCompositionPositionMatchAvailable(zoomRatios);
}

int32_t CaptureSession::IsCompositionEffectPreviewSupported(bool& isSupported)
{
    auto ret = CheckCommonPreconditions();
    CHECK_RETURN_RET(ret != CameraErrorCode::SUCCESS, ret);
    CHECK_RETURN_RET_WLOG(compositionFeature_ == nullptr, CAMERA_OK,
        "CaptureSession::IsCompositionEffectPreviewSupported compositionFeature_ is nullptr");
    return  compositionFeature_->IsCompositionEffectPreviewSupported(isSupported);
}

int32_t CaptureSession::EnableCompositionEffectPreview(bool isEnable)
{
    auto ret = CheckCommonPreconditions();
    CHECK_RETURN_RET(ret != CameraErrorCode::SUCCESS, ret);
    CHECK_RETURN_RET_WLOG(compositionFeature_ == nullptr, CAMERA_OK,
        "CaptureSession::EnableCompositionEffectPreview compositionFeature_ is nullptr");
    LockForControl();
    ret = compositionFeature_->EnableCompositionEffectPreview(isEnable);
    UnlockForControl();
    return ret;
}

int32_t CaptureSession::GetSupportedRecommendedInfoLanguage(std::vector<std::string>& supportedLanguages)
{
    auto ret = CheckCommonPreconditions();
    CHECK_RETURN_RET(ret != CameraErrorCode::SUCCESS, ret);
    CHECK_RETURN_RET(compositionFeature_ == nullptr, CAMERA_OK);
    return compositionFeature_->GetSupportedRecommendedInfoLanguage(supportedLanguages);
}

int32_t CaptureSession::SetRecommendedInfoLanguage(const std::string& language)
{
    auto ret = CheckCommonPreconditions();
    CHECK_RETURN_RET(ret != CameraErrorCode::SUCCESS, ret);
    CHECK_RETURN_RET(compositionFeature_ == nullptr, CAMERA_OK);
    LockForControl();
    ret = compositionFeature_->SetRecommendedInfoLanguage(language);
    UnlockForControl();
    return ret;
}

int32_t CaptureSession::EnableLogAssistance(const bool enable)
{
    MEDIA_DEBUG_LOG("Enter CaptureSession::EnableLogAssistance");
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::EnableLogAssistance Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::EnableLogAssistance Need to call LockForControl() before setting camera properties");
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_LOG_ASSISTANCE, &enable, 1);
    CHECK_PRINT_ELOG(!status, "CaptureSession::EnableLogAssistance Failed to set flash mode");
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::IsColorStyleSupported(bool &isSupported)
{
    MEDIA_DEBUG_LOG("Enter CaptureSession::IsColorStyleSupported");
    isSupported = false;
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::IsColorStyleSupported camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, CameraErrorCode::SUCCESS, "IsColorStyleSupported camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_COLOR_STYLE_AVAILABLE, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count <= 0, CameraErrorCode::SUCCESS,
        "CaptureSession::IsColorStyleSupported Failed with return code %{public}d", ret);
    isSupported = static_cast<bool>(item.data.u8[0]);
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::GetDefaultColorStyleSettings(std::vector<ColorStyleSetting>& defaultColorStyles)
{
    MEDIA_DEBUG_LOG("Enter CaptureSession::GetDefaultColorStyleSettings");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::GetDefaultColorStyleSettings camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, CameraErrorCode::SUCCESS, "GetDefaultColorStyleSettings camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_COLOR_STYLE_DEFAULT_SETTINGS, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count <= 0, CameraErrorCode::SUCCESS,
        "CaptureSession::GetDefaultColorStyleSettings Failed with return code %{public}d", ret);
    const uint32_t step = 4;
    for (uint32_t i = 0; i < item.count; i += step) {
        MEDIA_INFO_LOG("defaultColorStyles, type:%{public}f, hue:%{public}f, saturation:%{public}f, tone:%{public}f",
            item.data.f[i + ColorStyleSetting::typeOffset], item.data.f[i + ColorStyleSetting::hueOffset],
            item.data.f[i + ColorStyleSetting::saturationOffset], item.data.f[i + ColorStyleSetting::toneOffset]);
        defaultColorStyles.push_back({static_cast<ColorStyleType>(
            item.data.f[i + ColorStyleSetting::typeOffset]), item.data.f[i + ColorStyleSetting::hueOffset],
            item.data.f[i + ColorStyleSetting::saturationOffset], item.data.f[i + ColorStyleSetting::toneOffset]});
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetColorStyleSetting(const ColorStyleSetting& setting)
{
    MEDIA_DEBUG_LOG("Enter CaptureSession::SetColorStyleSetting");
    CHECK_RETURN_RET_ELOG(!setting.CheckColorStyleSettingParam(),
        CameraErrorCode::PARAMETER_ERROR, "CaptureSession::SetColorStyleSetting parameter error");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::SetColorStyleSetting Need to call LockForControl() before setting camera properties");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        inputDevice == nullptr, CameraErrorCode::SUCCESS, "CaptureSession::SetColorStyleSetting camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, CameraErrorCode::SUCCESS, "SetColorStyleSetting camera metadata is null");
    float colorStylesetting_[4] = {static_cast<float>(setting.type), setting.hue, setting.saturation, setting.tone};
    for (auto i = ColorStyleSetting::hueOffset; i <= ColorStyleSetting::toneOffset; ++ i) {
        if (colorStylesetting_[i] > 1) {
            MEDIA_ERR_LOG("SetColorStyleSetting %{public}s value above 1, set value to 1",
                i == ColorStyleSetting::hueOffset ? "hue" :
                (i == ColorStyleSetting::saturationOffset ? "saturation" : "tone"));
            colorStylesetting_[i] = 1;
        }
    }
    MEDIA_INFO_LOG("ColorStyleSetting setting = %{public}f, %{public}f, %{public}f, %{public}f",
        colorStylesetting_[ColorStyleSetting::typeOffset], colorStylesetting_[ColorStyleSetting::hueOffset],
        colorStylesetting_[ColorStyleSetting::saturationOffset], colorStylesetting_[ColorStyleSetting::toneOffset]);
    uint32_t count = 4;
    CHECK_RETURN_RET_ELOG(
        !AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_COLOR_STYLE_SETTING, colorStylesetting_, count),
        CameraErrorCode::SUCCESS, "SetColorStyleSetting Fail");
    auto captureSession = GetCaptureSession();
    CHECK_RETURN_RET_ELOG(!captureSession, CameraErrorCode::SERVICE_FATL_ERROR,
        "SetColorStyleSetting captureSession is nullptr");
    bool status = colorStylesetting_[0] > 0;
    if (isColorStyleWorking_ != status) {
        HILOG_COMM_INFO("change isColorStyleWorking flag to %{public}d", status);
        int32_t errCode = captureSession->SetXtStyleStatus(status);
        CHECK_PRINT_ELOG(errCode != CAMERA_OK, "Failed to SetXtStyleStatus!, %{public}d", errCode);
        isColorStyleWorking_ = status;
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetHasFitedRotation(bool isHasFitedRotation)
{
    CAMERA_SYNC_TRACE;
    auto captureSession = GetCaptureSession();
    CHECK_RETURN_RET_ELOG(!captureSession, CameraErrorCode::SERVICE_FATL_ERROR,
        "CaptureSession::SetHasFitedRotation captureSession is nullptr");
    int32_t errCode = captureSession->SetHasFitedRotation(isHasFitedRotation);
    CHECK_PRINT_ELOG(errCode != CAMERA_OK, "Failed to SetHasFitedRotation!, %{public}d", errCode);
    return errCode;
}

#ifdef CAMERA_USE_SENSOR
int32_t CaptureSession::GetSensorRotationOnce(int32_t& sensorRotation)
{
    auto captureSession = GetCaptureSession();
    CHECK_RETURN_RET_ELOG(!captureSession, CameraErrorCode::SERVICE_FATL_ERROR,
        "CaptureSession::GetSensorRotationOnce captureSession is nullptr");
    int32_t errCode = captureSession->GetSensorRotationOnce(sensorRotation);
    CHECK_PRINT_ELOG(errCode != CAMERA_OK, "Failed to GetSensorRotationOnce!, %{public}d", errCode);
    return errCode;
}
#endif

int32_t CaptureSession::EnableAutoMotionBoostDelivery(bool isEnable)
{
    MEDIA_INFO_LOG("CaptureSession::EnableAutoMotionBoostDelivery is called, isEnable: %{public}d",
        isEnable);

    LockForControl();
    int32_t res = CameraErrorCode::SUCCESS;
    uint8_t enableValue = static_cast<uint8_t>(isEnable);
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_AUTO_MOTION_BOOST_DELIVERY_SWITCH,
        &enableValue, 1);
    CHECK_RETURN_RET_ELOG(!status, PARAMETER_ERROR,
        "CaptureSession::EnableAutoMotionBoostDelivery Failed to set metadata");
    UnlockForControl();
    CHECK_PRINT_ELOG(res != CameraErrorCode::SUCCESS, "CaptureSession::EnableAutoMotionBoostDelivery failed");
    return res;
}

int32_t CaptureSession::EnableAutoBokehDataDelivery(bool isEnable)
{
    MEDIA_INFO_LOG("CaptureSession::EnableAutoBokehDataDelivery is called, isEnable: %{public}d",
        isEnable);

    LockForControl();
    int32_t res = CameraErrorCode::SUCCESS;
    uint8_t enableValue = static_cast<uint8_t>(isEnable);
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_AUTO_BOKEH_DATA_DELIVERY_SWITCH,
        &enableValue, 1);
    CHECK_RETURN_RET_ELOG(!status, PARAMETER_ERROR,
        "CaptureSession::EnableAutoBokehDataDelivery Failed to set metadata");
    UnlockForControl();

    CHECK_PRINT_ELOG(res != CameraErrorCode::SUCCESS, "CaptureSession::EnableAutoBokehDataDelivery failed");
    return res;
}

void CaptureSession::EnableAutoFrameRate(bool isEnable)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("Enter EnableAutoFrameRate, isEnable:%{public}d", isEnable);
    uint8_t enableValue = static_cast<uint8_t>(isEnable);
    CHECK_PRINT_ELOG(!AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_AUTO_VIDEO_FRAME_RATE, &enableValue, 1),
        "EnableAutoFrameRate Failed to enable OHOS_CONTROL_AUTO_VIDEO_FRAME_RATE");
}

int32_t CaptureSession::IsFocusTrackingModeSupported(FocusTrackingMode focusTrackingMode, bool &isSupported)
{
    MEDIA_DEBUG_LOG("Enter CaptureSession::IsFocusTrackingModeSupported");
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::IsFocusTrackingModeSupported Session is not Commited");
    std::vector<FocusTrackingMode> supportedFocusTrackingModes;
    (void)GetSupportedFocusTrackingModes(supportedFocusTrackingModes);
    if (find(supportedFocusTrackingModes.begin(), supportedFocusTrackingModes.end(),
        focusTrackingMode) != supportedFocusTrackingModes.end()) {
        isSupported = true;
        return CameraErrorCode::SUCCESS;
    }
    isSupported = false;
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::GetSupportedFocusTrackingModes(std::vector<FocusTrackingMode>& supportedFocusTrackingModes)
{
    MEDIA_DEBUG_LOG("CaptureSession::GetSupportedFocusTrackingModes is called");
    supportedFocusTrackingModes.clear();
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::GetSupportedFocusTrackingModes Session is not Commited.");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::GetSupportedFocusTrackingModes camera device is null");
    auto deviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(deviceInfo == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::GetSupportedFocusTrackingModes camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = deviceInfo->GetCachedMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::GetSupportedFocusTrackingModes camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FOCUS_TRACKING_MODES, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count == 0, CameraErrorCode::SUCCESS,
        "CaptureSession::GetSupportedFocusTrackingModes Failed with return code %{public}d", ret);
    g_transformValidData(item, metaToFwFocusTrackingMode_, supportedFocusTrackingModes);
    std::string supportedFocusTrackingModesStr =
        Container2String(supportedFocusTrackingModes.begin(), supportedFocusTrackingModes.end());
    MEDIA_INFO_LOG("CaptureSession::GetSupportedFocusTrackingModes, supportedFocusTrackingModes: %{public}s",
                   supportedFocusTrackingModesStr.c_str());
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::GetFocusTrackingMode(FocusTrackingMode& focusTrackingMode)
{
    MEDIA_DEBUG_LOG("CaptureSession::GetFocusTrackingMode is called");
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::GetFocusTrackingMode Session is not Commited.");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        inputDevice == nullptr, CameraErrorCode::SUCCESS, "CaptureSession::GetFocusTrackingMode camera device is null");
    auto deviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(deviceInfo == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::GetFocusTrackingMode camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = deviceInfo->GetCachedMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, CameraErrorCode::SUCCESS, "CaptureSession::GetFocusTrackingMode camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_FOCUS_TRACKING_MODE, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "CaptureSession::GetFocusTrackingMode Failed with return code %{public}d", ret);
    auto itr = metaToFwFocusTrackingMode_.find(static_cast<camera_focus_tracking_mode_t>(item.data.u8[0]));
    if (itr != metaToFwFocusTrackingMode_.end()) {
        focusTrackingMode = itr->second;
        return CameraErrorCode::SUCCESS;
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetFocusTrackingMode(const FocusTrackingMode& focusTrackingMode)
{
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::SetFocusTrackingMode Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::SetFocusTrackingMode Need to call LockForControl() before setting camera properties");
    bool isSupported = false;
    CHECK_RETURN_RET_ELOG(IsFocusTrackingModeSupported(focusTrackingMode, isSupported) != CAMERA_OK,
        CameraErrorCode::PARAMETER_ERROR,
        "CaptureSession::SetFocusTrackingMode, check mode %{public}d is suppported failed", focusTrackingMode);
    CHECK_RETURN_RET_ELOG(!isSupported, CameraErrorCode::PARAMETER_ERROR,
        "CaptureSession::SetFocusTrackingMode, mode %{public}d is not suppported", focusTrackingMode);
    auto itr = fwkToMetaFocusTrackingMode_.find(focusTrackingMode);
    CHECK_RETURN_RET_ELOG(itr == fwkToMetaFocusTrackingMode_.end(), CameraErrorCode::PARAMETER_ERROR,
        "CaptureSession::SetFocusTrackingMode, mode %{public}d is not suppported", focusTrackingMode);

    MEDIA_DEBUG_LOG("CaptureSession::SetFocusTrackingMode : %{public}d", itr->second);
    bool status = false;
    int32_t ret;
    uint32_t count = 1;
    camera_metadata_item_t item;
    ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_FOCUS_TRACKING_MODE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_FOCUS_TRACKING_MODE, &itr->second, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_FOCUS_TRACKING_MODE, &itr->second, count);
    }
    CHECK_PRINT_ELOG(!status, "CaptureSession::SetFocusTrackingMode, failed to update changedMetadata");
    MEDIA_INFO_LOG("CaptureSession::SetFocusTrackingMode: %{public}d successfully", itr->second);
    return CameraErrorCode::SUCCESS;
}

void CaptureSession::SetApertureEffectChangeCallback(std::shared_ptr<ApertureEffectChangeCallback>
    apertureEffectChangeCb)
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    apertureEffectChangeCallback_ = apertureEffectChangeCb;
}

void CaptureSession::ProcessApertureEffectChange(const std::shared_ptr<OHOS::Camera::CameraMetadata> &result)
{
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_STATUS_CAMERA_CURRENT_APERTURE_EFFECT, &item);
    CHECK_RETURN(ret != CAM_META_SUCCESS);
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    if (apertureEffectChangeCallback_ != nullptr) {
        auto itr = metaToFwkApertureEffectTypeMap_.find(static_cast<CameraApertureEffectType>(item.data.u8[0]));
        if (itr != metaToFwkApertureEffectTypeMap_.end()) {
            ApertureEffectType type = itr->second;
            CHECK_RETURN_DLOG(
                !apertureEffectChangeCallback_->isFirstRecord && type == apertureEffectChangeCallback_->currentType,
                "ApertureEffectType is not changed, current type: %{public}d", type);
            MEDIA_INFO_LOG("ApertureEffectType changed: %{public}d -> %{public}d",
                apertureEffectChangeCallback_->currentType, type);
            apertureEffectChangeCallback_->isFirstRecord = false;
            apertureEffectChangeCallback_->currentType = type;
            apertureEffectChangeCallback_->OnApertureEffectChange(type);
        }
    }
}

int32_t CaptureSession::GetSupportedVideoCodecTypes(std::vector<int32_t>& supportedVideoCodecTypes)
{
    MEDIA_DEBUG_LOG("CaptureSession::GetSupportedVideoCodecTypes is called");
    // TODO check video codec types ability
    supportedVideoCodecTypes.emplace_back(static_cast<int32_t>(VideoCodecType::VIDEO_ENCODE_TYPE_AVC));
    supportedVideoCodecTypes.emplace_back(static_cast<int32_t>(VideoCodecType::VIDEO_ENCODE_TYPE_HEVC));
    return CameraErrorCode::SUCCESS;
}

void CaptureSession::AdjustRenderFit()
{
    std::lock_guard<std::mutex> lock(captureOutputSetsMutex_);
    for (const auto& output : captureOutputSets_) {
        auto item = output.promote();
        CHECK_CONTINUE(item && item->GetOutputType() != CAPTURE_OUTPUT_TYPE_PREVIEW);
        sptr<PreviewOutput> previewOutput = (sptr<PreviewOutput>&)item;
        previewOutput->AdjustRenderFit();
        previewOutput->ReportXComponentInfoEvent();
    }
    XComponentControllerProxy::FreeXComponentControllerDynamiclib();
}

void CaptureSession::EnableKeyFrameReport(bool isKeyFrameReportEnabled)
{
    auto captureSession = GetCaptureSession();
    CHECK_RETURN_ELOG(captureSession == nullptr,
        "CaptureSession::EnableKeyFrameReport captureSession is null");
    int32_t retCode = captureSession->EnableKeyFrameReport(isKeyFrameReportEnabled);
    CHECK_PRINT_ELOG(retCode != CAMERA_OK,
        "EnableKeyFrameReport Set service Callback failed, retCode: %{public}d", retCode);
}

std::vector<NightSubMode> CaptureSession::GetSupportedNightSubModeTypes()
{
    std::vector<NightSubMode> supportedNightSubModes = {};
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), supportedNightSubModes,
        "CaptureSession::GetSupportedNightSubModeTypes Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), supportedNightSubModes,
        "CaptureSession::GetSupportedNightSubModeTypes camera device is null");
    CHECK_RETURN_RET_ELOG(!IsSupportSpecSearch(), supportedNightSubModes, "spec search not support");
    auto abilityContainer = GetCameraAbilityContainer();
    CHECK_RETURN_RET_ELOG(abilityContainer == nullptr, supportedNightSubModes, "abilityContainer is null");
    return abilityContainer->GetSupportedNightSubModeTypes();
}

void CaptureSession::SetMacroStatusCallback(std::shared_ptr<MacroStatusCallback> callback)
{
    MEDIA_DEBUG_LOG("CaptureSession::SetMacroStatusCallback ENTER");
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    macroStatusCallback_ = callback;
}

void CaptureSession::SetPhotoQualityPrioritization(camera_photo_quality_prioritization_t quality)
{
    MEDIA_INFO_LOG("CaptureSession::SetPhotoQualityPrioritization quality:%{public}d", quality);
    CHECK_RETURN_ELOG(changedMetadata_ == nullptr,
        "CaptureSession::SetPhotoQualityPrioritization changedMetadata_ is NULL");
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_PHOTO_QUALITY_PRIORITIZATION, &quality, 1);
    CHECK_PRINT_ELOG(!status, "CaptureSession::SetPhotoQualityPrioritization Failed to AddOrUpdateMetadata!");
    return;
}

void CaptureSession::SetZoomRatioForAudio(float zoomRatio)
{
    CAMERA_SYNC_TRACE;
    // check if current mode is video related
    SceneMode currentMode = GetMode();
    CHECK_RETURN(videoModeSet_.count(currentMode) == 0);
    // set audio extra parameters for zoom ratio
    AudioStandard::AudioSystemManager *audioSystemMgr = AudioStandard::AudioSystemManager::GetInstance();
    CHECK_RETURN_ELOG(!audioSystemMgr, "Get AudioSystemManager Instance err");
    std::string key = AUDIO_EXTRA_PARAM_AUDIO_EFFECT;
    std::vector<std::pair<std::string, std::string>> kvpairs = {
        {AUDIO_EXTRA_PARAM_ZOOM_RATIO, std::to_string(zoomRatio)}
    };
    MEDIA_INFO_LOG("Set zoom ratio for audio, val: %{public}f", zoomRatio);
    int32_t ret = audioSystemMgr->SetExtraParameters(key, kvpairs);
    CHECK_RETURN_ELOG(ret != 0, "SetZoomRatioForAudio failed, SetExtraParameters ret: %{public}d", ret);
}

uint32_t CaptureSession::GetIsoValue()
{
    std::lock_guard<std::mutex> isoLock(isoValueMutex_);
    return isoValue_;
}

int32_t CaptureSession::SetParameters(std::vector<std::pair<std::string, std::string>>& kvPairs)
{
    for (auto const& [k, v] : kvPairs) {
        MEDIA_INFO_LOG("CaptureSession::SetParameters key:%{public}s value:%{public}s",
            k.c_str(), v.c_str());
        auto itr = parametersMap_.find(k);
        if (itr != parametersMap_.end()) {
            MEDIA_INFO_LOG("CaptureSession::SetParameters start setParameters key:%{public}s", k.c_str());
            CHECK_RETURN_RET_ELOG(!(v == "0" || v == "1"), CameraErrorCode::INVALID_ARGUMENT,
                "CaptureSession::SetParameters INVALID_ARGUMENT");
            int temp_int = std::stoi(v);
            uint8_t value = static_cast<uint8_t>(temp_int);
            CHECK_PRINT_ELOG(!AddOrUpdateMetadata(changedMetadata_, itr->second, &value, 1),
                "CaptureSession::SetParameters failed");
        }
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetExposureMeteringMode(MeteringMode mode)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::SetExposureMeteringMode Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::SetExposureMeteringMode Need to call LockForControl() before setting camera properties");
    // LCOV_EXCL_START
    camera_meter_mode_t meteringMode = OHOS_CAMERA_SPOT_METERING;
    auto itr = fwkMeteringModeMap_.find(mode);
    if (itr == fwkMeteringModeMap_.end()) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureMeteringMode Unknown exposure mode");
    } else {
        meteringMode = itr->second;
    }
    MEDIA_DEBUG_LOG("CaptureSession::SetExposureMeteringMode metering mode: %{public}d", meteringMode);
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_METER_MODE, &meteringMode, 1);
    CHECK_PRINT_ELOG(!status, "CaptureSession::SetExposureMeteringMode Failed to set focus mode");
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}
} // namespace CameraStandard
} // namespace OHOS
