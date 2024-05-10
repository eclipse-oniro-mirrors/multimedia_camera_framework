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

#include "session/capture_session.h"

#include <cstdint>
#include <memory>
#include <mutex>
#include <sys/types.h>

#include "camera_device_ability_items.h"
#include "camera_log.h"
#include "camera_metadata_operator.h"
#include "camera_util.h"
#include "capture_output.h"
#include "capture_scene_const.h"
#include "features/moon_capture_boost_feature.h"
#include "hcapture_session_callback_stub.h"
#include "input/camera_input.h"
#include "input/camera_manager.h"
#include "ipc_skeleton.h"
#include "os_account_manager.h"
#include "output/metadata_output.h"
#include "output/photo_output.h"
#include "output/preview_output.h"
#include "output/video_output.h"
#include "camera_error_code.h"

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Display::Graphic::Common::V1_0;

namespace {
constexpr int32_t DEFAULT_ITEMS = 10;
constexpr int32_t DEFAULT_DATA_LENGTH = 100;
constexpr int32_t DEFERRED_MODE_DATA_SIZE = 2;
constexpr float DEFAULT_EQUIVALENT_ZOOM = 100.0f;

} // namespace

static const std::map<CM_ColorSpaceType, ColorSpace> g_metaColorSpaceMap_ = {
    {CM_COLORSPACE_NONE, COLOR_SPACE_UNKNOWN},
    {CM_P3_FULL, DISPLAY_P3},
    {CM_SRGB_FULL, SRGB},
    {CM_BT709_FULL, BT709},
    {CM_BT2020_HLG_FULL, BT2020_HLG},
    {CM_BT2020_PQ_FULL, BT2020_PQ},
    {CM_P3_HLG_FULL, P3_HLG},
    {CM_P3_PQ_FULL, P3_PQ},
    {CM_P3_LIMIT, DISPLAY_P3_LIMIT},
    {CM_SRGB_LIMIT, SRGB_LIMIT},
    {CM_BT709_LIMIT, BT709_LIMIT},
    {CM_BT2020_HLG_LIMIT, BT2020_HLG_LIMIT},
    {CM_BT2020_PQ_LIMIT, BT2020_PQ_LIMIT},
    {CM_P3_HLG_LIMIT, P3_HLG_LIMIT},
    {CM_P3_PQ_LIMIT, P3_PQ_LIMIT}
};

static const std::map<ColorSpace, CM_ColorSpaceType> g_fwkColorSpaceMap_ = {
    {COLOR_SPACE_UNKNOWN, CM_COLORSPACE_NONE},
    {DISPLAY_P3, CM_P3_FULL},
    {SRGB, CM_SRGB_FULL},
    {BT709, CM_BT709_FULL},
    {BT2020_HLG, CM_BT2020_HLG_FULL},
    {BT2020_PQ, CM_BT2020_PQ_FULL},
    {P3_HLG, CM_P3_HLG_FULL},
    {P3_PQ, CM_P3_PQ_FULL},
    {DISPLAY_P3_LIMIT, CM_P3_LIMIT},
    {SRGB_LIMIT, CM_SRGB_LIMIT},
    {BT709_LIMIT, CM_BT709_LIMIT},
    {BT2020_HLG_LIMIT, CM_BT2020_HLG_LIMIT},
    {BT2020_PQ_LIMIT, CM_BT2020_PQ_LIMIT},
    {P3_HLG_LIMIT, CM_P3_HLG_LIMIT},
    {P3_PQ_LIMIT, CM_P3_PQ_LIMIT}
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

const std::unordered_map<camera_exposure_mode_enum_t, ExposureMode> CaptureSession::metaExposureModeMap_ = {
    {OHOS_CAMERA_EXPOSURE_MODE_LOCKED, EXPOSURE_MODE_LOCKED},
    {OHOS_CAMERA_EXPOSURE_MODE_AUTO, EXPOSURE_MODE_AUTO},
    {OHOS_CAMERA_EXPOSURE_MODE_CONTINUOUS_AUTO, EXPOSURE_MODE_CONTINUOUS_AUTO}
};

const std::unordered_map<ExposureMode, camera_exposure_mode_enum_t> CaptureSession::fwkExposureModeMap_ = {
    {EXPOSURE_MODE_LOCKED, OHOS_CAMERA_EXPOSURE_MODE_LOCKED},
    {EXPOSURE_MODE_AUTO, OHOS_CAMERA_EXPOSURE_MODE_AUTO},
    {EXPOSURE_MODE_CONTINUOUS_AUTO, OHOS_CAMERA_EXPOSURE_MODE_CONTINUOUS_AUTO}
};

const std::unordered_map<camera_focus_mode_enum_t, FocusMode> CaptureSession::metaFocusModeMap_ = {
    {OHOS_CAMERA_FOCUS_MODE_MANUAL, FOCUS_MODE_MANUAL},
    {OHOS_CAMERA_FOCUS_MODE_CONTINUOUS_AUTO, FOCUS_MODE_CONTINUOUS_AUTO},
    {OHOS_CAMERA_FOCUS_MODE_AUTO, FOCUS_MODE_AUTO},
    {OHOS_CAMERA_FOCUS_MODE_LOCKED, FOCUS_MODE_LOCKED}
};

const std::unordered_map<FocusMode, camera_focus_mode_enum_t> CaptureSession::fwkFocusModeMap_ = {
    {FOCUS_MODE_MANUAL, OHOS_CAMERA_FOCUS_MODE_MANUAL},
    {FOCUS_MODE_CONTINUOUS_AUTO, OHOS_CAMERA_FOCUS_MODE_CONTINUOUS_AUTO},
    {FOCUS_MODE_AUTO, OHOS_CAMERA_FOCUS_MODE_AUTO},
    {FOCUS_MODE_LOCKED, OHOS_CAMERA_FOCUS_MODE_LOCKED}
};

const std::unordered_map<camera_xmage_color_type_t, ColorEffect> CaptureSession::metaColorEffectMap_ = {
    {CAMERA_CUSTOM_COLOR_NORMAL, COLOR_EFFECT_NORMAL},
    {CAMERA_CUSTOM_COLOR_BRIGHT, COLOR_EFFECT_BRIGHT},
    {CAMERA_CUSTOM_COLOR_SOFT, COLOR_EFFECT_SOFT},
    {CAMERA_CUSTOM_COLOR_MONO, COLOR_EFFECT_BLACK_WHITE}
};

const std::unordered_map<ColorEffect, camera_xmage_color_type_t> CaptureSession::fwkColorEffectMap_ = {
    {COLOR_EFFECT_NORMAL, CAMERA_CUSTOM_COLOR_NORMAL},
    {COLOR_EFFECT_BRIGHT, CAMERA_CUSTOM_COLOR_BRIGHT},
    {COLOR_EFFECT_SOFT, CAMERA_CUSTOM_COLOR_SOFT},
    {COLOR_EFFECT_BLACK_WHITE, CAMERA_CUSTOM_COLOR_MONO}
};

const std::unordered_map<camera_flash_mode_enum_t, FlashMode> CaptureSession::metaFlashModeMap_ = {
    {OHOS_CAMERA_FLASH_MODE_CLOSE, FLASH_MODE_CLOSE},
    {OHOS_CAMERA_FLASH_MODE_OPEN, FLASH_MODE_OPEN},
    {OHOS_CAMERA_FLASH_MODE_AUTO, FLASH_MODE_AUTO},
    {OHOS_CAMERA_FLASH_MODE_ALWAYS_OPEN, FLASH_MODE_ALWAYS_OPEN}
};

const std::unordered_map<FlashMode, camera_flash_mode_enum_t> CaptureSession::fwkFlashModeMap_ = {
    {FLASH_MODE_CLOSE, OHOS_CAMERA_FLASH_MODE_CLOSE},
    {FLASH_MODE_OPEN, OHOS_CAMERA_FLASH_MODE_OPEN},
    {FLASH_MODE_AUTO, OHOS_CAMERA_FLASH_MODE_AUTO},
    {FLASH_MODE_ALWAYS_OPEN, OHOS_CAMERA_FLASH_MODE_ALWAYS_OPEN}
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

const std::unordered_map<camera_beauty_type_t, BeautyType> CaptureSession::metaBeautyTypeMap_ = {
    {OHOS_CAMERA_BEAUTY_TYPE_AUTO, AUTO_TYPE},
    {OHOS_CAMERA_BEAUTY_TYPE_SKIN_SMOOTH, SKIN_SMOOTH},
    {OHOS_CAMERA_BEAUTY_TYPE_FACE_SLENDER, FACE_SLENDER},
    {OHOS_CAMERA_BEAUTY_TYPE_SKIN_TONE, SKIN_TONE}
};

const std::unordered_map<BeautyType, camera_beauty_type_t> CaptureSession::fwkBeautyTypeMap_ = {
    {AUTO_TYPE, OHOS_CAMERA_BEAUTY_TYPE_AUTO},
    {SKIN_SMOOTH, OHOS_CAMERA_BEAUTY_TYPE_SKIN_SMOOTH},
    {FACE_SLENDER, OHOS_CAMERA_BEAUTY_TYPE_FACE_SLENDER},
    {SKIN_TONE, OHOS_CAMERA_BEAUTY_TYPE_SKIN_TONE}
};

const std::unordered_map<BeautyType, camera_device_metadata_tag_t> CaptureSession::fwkBeautyAbilityMap_ = {
    {AUTO_TYPE, OHOS_ABILITY_BEAUTY_AUTO_VALUES},
    {SKIN_SMOOTH, OHOS_ABILITY_BEAUTY_SKIN_SMOOTH_VALUES},
    {FACE_SLENDER, OHOS_ABILITY_BEAUTY_FACE_SLENDER_VALUES},
    {SKIN_TONE, OHOS_ABILITY_BEAUTY_SKIN_TONE_VALUES}
};

const std::unordered_map<BeautyType, camera_device_metadata_tag_t> CaptureSession::fwkBeautyControlMap_ = {
    {AUTO_TYPE, OHOS_CONTROL_BEAUTY_AUTO_VALUE},
    {SKIN_SMOOTH, OHOS_CONTROL_BEAUTY_SKIN_SMOOTH_VALUE},
    {FACE_SLENDER, OHOS_CONTROL_BEAUTY_FACE_SLENDER_VALUE},
    {SKIN_TONE, OHOS_CONTROL_BEAUTY_SKIN_TONE_VALUE}
};

const std::unordered_map<camera_device_metadata_tag_t, BeautyType> CaptureSession::metaBeautyControlMap_ = {
    {OHOS_CONTROL_BEAUTY_SKIN_SMOOTH_VALUE, SKIN_SMOOTH},
    {OHOS_CONTROL_BEAUTY_FACE_SLENDER_VALUE, FACE_SLENDER},
    {OHOS_CONTROL_BEAUTY_SKIN_TONE_VALUE, SKIN_TONE}
};

const std::unordered_map<CameraVideoStabilizationMode,
VideoStabilizationMode> CaptureSession::metaVideoStabModesMap_ = {
    {OHOS_CAMERA_VIDEO_STABILIZATION_OFF, OFF},
    {OHOS_CAMERA_VIDEO_STABILIZATION_LOW, LOW},
    {OHOS_CAMERA_VIDEO_STABILIZATION_MIDDLE, MIDDLE},
    {OHOS_CAMERA_VIDEO_STABILIZATION_HIGH, HIGH},
    {OHOS_CAMERA_VIDEO_STABILIZATION_AUTO, AUTO}
};

const std::unordered_map<VideoStabilizationMode,
CameraVideoStabilizationMode> CaptureSession::fwkVideoStabModesMap_ = {
    {OFF, OHOS_CAMERA_VIDEO_STABILIZATION_OFF},
    {LOW, OHOS_CAMERA_VIDEO_STABILIZATION_LOW},
    {MIDDLE, OHOS_CAMERA_VIDEO_STABILIZATION_MIDDLE},
    {HIGH, OHOS_CAMERA_VIDEO_STABILIZATION_HIGH},
    {AUTO, OHOS_CAMERA_VIDEO_STABILIZATION_AUTO}
};

int32_t CaptureSessionCallback::OnError(int32_t errorCode)
{
    MEDIA_INFO_LOG("CaptureSessionCallback::OnError() is called!, errorCode: %{public}d", errorCode);
    if (captureSession_ != nullptr && captureSession_->GetApplicationCallback() != nullptr) {
        captureSession_->GetApplicationCallback()->OnError(errorCode);
    } else {
        MEDIA_INFO_LOG("CaptureSessionCallback::ApplicationCallback not set!, Discarding callback");
    }
    return CameraErrorCode::SUCCESS;
}

CaptureSession::CaptureSession(sptr<ICaptureSession>& captureSession)
{
    captureSession_ = captureSession;
    inputDevice_ = nullptr;
    isImageDeferred_ = false;
    metaOutput_ = nullptr;
    metadataResultProcessor_ = std::make_shared<CaptureSessionMetadataResultProcessor>(this);
    sptr<IRemoteObject> object = captureSession_->AsObject();
    pid_t pid = 0;
    deathRecipient_ = new (std::nothrow) CameraDeathRecipient(pid);
    CHECK_AND_RETURN_LOG(deathRecipient_ != nullptr, "failed to new CameraDeathRecipient.");

    deathRecipient_->SetNotifyCb(std::bind(&CaptureSession::CameraServerDied, this, std::placeholders::_1));
    bool result = object->AddDeathRecipient(deathRecipient_);
    if (!result) {
        MEDIA_ERR_LOG("failed to add deathRecipient");
        return;
    }
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
    if (captureSession_ != nullptr) {
        (void)captureSession_->AsObject()->RemoveDeathRecipient(deathRecipient_);
        captureSession_ = nullptr;
    }
    deathRecipient_ = nullptr;
}

CaptureSession::~CaptureSession()
{
    MEDIA_DEBUG_LOG("Enter Into CaptureSession::~CaptureSession()");
    inputDevice_ = nullptr;
    captureSession_ = nullptr;
    changedMetadata_ = nullptr;
}

int32_t CaptureSession::BeginConfig()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter Into CaptureSession::BeginConfig");
    if (IsSessionConfiged()) {
        MEDIA_ERR_LOG("CaptureSession::BeginConfig Session is locked");
        return CameraErrorCode::SESSION_CONFIG_LOCKED;
    }

    isColorSpaceSetted_ = false;
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (captureSession_) {
        errCode = captureSession_->BeginConfig();
        if (errCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to BeginConfig!, %{public}d", errCode);
        }
    } else {
        MEDIA_ERR_LOG("CaptureSession::BeginConfig() captureSession_ is nullptr");
    }
    return ServiceToCameraError(errCode);
}

int32_t CaptureSession::CommitConfig()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter Into CaptureSession::CommitConfig");
    if (!IsSessionConfiged()) {
        MEDIA_ERR_LOG("CaptureSession::CommitConfig operation Not allowed!");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }

    MEDIA_INFO_LOG("CaptureSession::CommitConfig isColorSpaceSetted_ = %{public}d", isColorSpaceSetted_);
    if (!isColorSpaceSetted_) {
        SetDefaultColorSpace();
    }
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (captureSession_) {
        errCode = captureSession_->CommitConfig();
        MEDIA_INFO_LOG("CaptureSession::CommitConfig commit mode = %{public}d", GetMode());
        if (errCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to CommitConfig!, %{public}d", errCode);
        }
    } else {
        MEDIA_ERR_LOG("CaptureSession::CommitConfig() captureSession_ is nullptr");
    }
    return ServiceToCameraError(errCode);
}

void CaptureSession::SetDefaultColorSpace()
{
    CM_ColorSpaceType metaColorSpace = CM_ColorSpaceType::CM_COLORSPACE_NONE;
    CM_ColorSpaceType captureColorSpace = CM_ColorSpaceType::CM_COLORSPACE_NONE;
    ColorSpaceInfo colorSpaceInfo = GetSupportedColorSpaceInfo();
    if (colorSpaceInfo.modeCount == 0) {
        MEDIA_ERR_LOG("CaptureSession::SetDefaultColorSpace SupportedColorSpaceInfo is null.");
        return;
    }
    for (uint32_t i = 0; i < colorSpaceInfo.modeCount; i++) {
        if (GetMode() != colorSpaceInfo.modeInfo[i].modeType) {
            continue;
        }
        MEDIA_INFO_LOG("CaptureSession::SetDefaultColorSpace get %{public}d mode colorSpaceInfo success.", GetMode());
        std::vector<int32_t> supportedColorSpaces = colorSpaceInfo.modeInfo[i].streamInfo[0].colorSpaces;
        metaColorSpace = static_cast<CM_ColorSpaceType>(supportedColorSpaces[0]);
        captureColorSpace = static_cast<CM_ColorSpaceType>(supportedColorSpaces[0]);
        if (!IsModeWithVideoStream()) {
            break;
        }
        for (uint32_t j = 0; j < colorSpaceInfo.modeInfo[i].streamTypeCount; j++) {
            if (colorSpaceInfo.modeInfo[i].streamInfo[j].streamType == STILL_CAPTURE) {
                captureColorSpace =
                    static_cast<CM_ColorSpaceType>(colorSpaceInfo.modeInfo[i].streamInfo[j].colorSpaces[0]);
                break;
            }
        }
    }

    if (!captureSession_) {
        MEDIA_ERR_LOG("CaptureSession::SetDefaultColorSpace() captureSession_ is nullptr");
        return;
    }

    ColorSpace fwkColorSpace;
    ColorSpace fwkCaptureColorSpace;
    auto itr = g_metaColorSpaceMap_.find(metaColorSpace);
    if (itr != g_metaColorSpaceMap_.end()) {
        fwkColorSpace = itr->second;
    } else {
        MEDIA_ERR_LOG("CaptureSession::SetDefaultColorSpace, %{public}d failed", static_cast<int32_t>(metaColorSpace));
        return;
    }

    itr = g_metaColorSpaceMap_.find(captureColorSpace);
    if (itr != g_metaColorSpaceMap_.end()) {
        fwkCaptureColorSpace = itr->second;
    } else {
        MEDIA_ERR_LOG("CaptureSession::SetDefaultColorSpace, %{public}d fail", static_cast<int32_t>(captureColorSpace));
        return;
    }
    MEDIA_INFO_LOG("CaptureSession::SetDefaultColorSpace mode = %{public}d, ColorSpace = %{public}d, "
        "captureColorSpace = %{public}d.", GetMode(), fwkColorSpace, fwkCaptureColorSpace);

    int32_t errCode = captureSession_->SetColorSpace(fwkColorSpace, fwkCaptureColorSpace, false);
    if (errCode != CAMERA_OK) {
        MEDIA_ERR_LOG("CaptureSession::SetDefaultColorSpace failed to SetColorSpace!, %{public}d",
            ServiceToCameraError(errCode));
    }
    return;
}

bool CaptureSession::CanAddInput(sptr<CaptureInput>& input)
{
    // can only add one cameraInput
    CAMERA_SYNC_TRACE;
    bool ret = false;
    MEDIA_INFO_LOG("Enter Into CaptureSession::CanAddInput");
    if (!IsSessionConfiged() || input == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::AddInput operation Not allowed!");
        return ret;
    }
    if (captureSession_) {
        captureSession_->CanAddInput(((sptr<CameraInput>&)input)->GetCameraDevice(), ret);
    } else {
        MEDIA_ERR_LOG("CaptureSession::CanAddInput() captureSession_ is nullptr");
    }
    return ret;
}

int32_t CaptureSession::AddInput(sptr<CaptureInput>& input)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter Into CaptureSession::AddInput");
    if (!IsSessionConfiged()) {
        MEDIA_ERR_LOG("CaptureSession::AddInput operation Not allowed!");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }
    if (input == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::AddInput input is null");
        return ServiceToCameraError(CAMERA_INVALID_ARG);
    }
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (captureSession_) {
        errCode = captureSession_->AddInput(((sptr<CameraInput>&)input)->GetCameraDevice());
        if (errCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to AddInput!, %{public}d", errCode);
        } else {
            input->SetMetadataResultProcessor(GetMetadataResultProcessor());
            inputDevice_ = input;
            if (inputDevice_ != nullptr) {
                UpdateDeviceDeferredability();
                FindTagId();
            }
        }
    } else {
        MEDIA_ERR_LOG("CaptureSession::AddInput() captureSession_ is nullptr");
    }
    return ServiceToCameraError(errCode);
}

void CaptureSession::UpdateDeviceDeferredability()
{
    MEDIA_DEBUG_LOG("UpdateDeviceDeferredability begin.");
    inputDevice_->GetCameraDeviceInfo()->modeDeferredType_ = {};
    camera_metadata_item_t item;
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    int32_t ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_DEFERRED_IMAGE_DELIVERY, &item);
    MEDIA_INFO_LOG("UpdateDeviceDeferredability get ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("UpdateDeviceDeferredability item: %{public}d count: %{public}d", item.item, item.count);
    for (uint32_t i = 0; i < item.count; i++) {
        if (i % DEFERRED_MODE_DATA_SIZE == 0) {
            MEDIA_DEBUG_LOG("UpdateDeviceDeferredability mode index:%{public}d, deferredType:%{public}d",
                item.data.u8[i], item.data.u8[i + 1]);
            inputDevice_->GetCameraDeviceInfo()->modeDeferredType_[item.data.u8[i]] =
                static_cast<DeferredDeliveryImageType>(item.data.u8[i + 1]);
        }
    }
}

void CaptureSession::FindTagId()
{
    MEDIA_INFO_LOG("Enter Into CaptureSession::FindTagId");
    if (inputDevice_ != nullptr) {
        MEDIA_DEBUG_LOG("CaptureSession::FindTagId inputDevice_ not nullptr");
        std::vector<vendorTag_t> vendorTagInfos;
        sptr<CameraInput> camInput = (sptr<CameraInput>&)inputDevice_;
        int32_t ret = camInput->GetCameraAllVendorTags(vendorTagInfos);
        if (ret != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to GetCameraAllVendorTags");
            return;
        }
        for (auto info : vendorTagInfos) {
            std::string tagName = info.tagName;
            if (tagName == "hwSensorName") {
                HAL_CUSTOM_SENSOR_MODULE_TYPE = info.tagId;
            } else if (tagName == "lensFocusDistance") {
                HAL_CUSTOM_LENS_FOCUS_DISTANCE = info.tagId;
            } else if (tagName == "sensorSensitivity") {
                HAL_CUSTOM_SENSOR_SENSITIVITY = info.tagId;
            } else if (tagName == "cameraLaserData") {
                HAL_CUSTOM_LASER_DATA = info.tagId;
            } else if (tagName == "cameraArMode") {
                HAL_CUSTOM_AR_MODE = info.tagId;
            }
        }
    }
}

bool CaptureSession::CheckFrameRateRangeWithCurrentFps(int32_t curMinFps, int32_t curMaxFps,
                                                       int32_t minFps, int32_t maxFps)
{
    if (minFps == 0 || curMinFps == 0) {
        MEDIA_WARNING_LOG("CaptureSession::CheckFrameRateRangeWithCurrentFps can not set zero!");
        return false;
    }
    if (curMinFps == curMaxFps && minFps == maxFps &&
        (minFps % curMinFps == 0 || curMinFps % minFps == 0)) {
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

void CaptureSession::ConfigureOutput(sptr<CaptureOutput>& output)
{
    MEDIA_DEBUG_LOG("Enter Into CaptureSession::AddOutput");
    if (output->GetOutputType() == CAPTURE_OUTPUT_TYPE_PREVIEW) {
        MEDIA_INFO_LOG("CaptureSession::AddOutput PreviewOutput");
        previewProfile_ = output->GetPreviewProfile();
        SetGuessMode(SceneMode::CAPTURE);
    }
    if (output->GetOutputType() == CAPTURE_OUTPUT_TYPE_PHOTO) {
        MEDIA_INFO_LOG("CaptureSession::AddOutput PhotoOutput");
        photoProfile_ = output->GetPhotoProfile();
        SetGuessMode(SceneMode::CAPTURE);
    }
    output->SetSession(this);
    if (output->GetOutputType() == CAPTURE_OUTPUT_TYPE_VIDEO) {
        MEDIA_INFO_LOG("CaptureSession::AddOutput VideoOutput");
        std::vector<int32_t> frameRateRange = output->GetVideoProfile().GetFrameRates();
        const size_t minFpsRangeSize = 2;
        if (frameRateRange.size() >= minFpsRangeSize) {
            SetFrameRateRange(frameRateRange);
        }
        SetGuessMode(SceneMode::VIDEO);
    }
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
    if (it == captureOutputSets_.end()) {
        captureOutputSets_.insert(output);
    }
}

int32_t CaptureSession::AddOutput(sptr<CaptureOutput>& output)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter Into CaptureSession::AddOutput");
    if (!IsSessionConfiged()) {
        MEDIA_ERR_LOG("CaptureSession::AddOutput operation Not allowed!");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }
    if (output == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::AddOutput output is null");
        return ServiceToCameraError(CAMERA_INVALID_ARG);
    }
    ConfigureOutput(output);
    if (output->GetOutputType() == CAPTURE_OUTPUT_TYPE_METADATA) {
        MEDIA_INFO_LOG("CaptureSession::AddOutput MetadataOutput");
        metaOutput_ = output;
        return ServiceToCameraError(CAMERA_OK);
    }
    if (GetMode() == SceneMode::VIDEO && output->GetOutputType() == CAPTURE_OUTPUT_TYPE_VIDEO) {
        std::vector<int32_t> videoFrameRates = output->GetVideoProfile().GetFrameRates();
        if (videoFrameRates.empty()) {
            MEDIA_ERR_LOG("videoFrameRates is empty!");
            return ServiceToCameraError(CAMERA_INVALID_ARG);
        }
        const int frameRate120 = 120;
        const int frameRate240 = 240;
        if (videoFrameRates[0] == frameRate120 || videoFrameRates[0] == frameRate240) {
            captureSession_->SetFeatureMode(SceneMode::HIGH_FRAME_RATE);
        }
    }
    if (!CanAddOutput(output)) {
        MEDIA_ERR_LOG("CanAddOutput check failed!");
        return ServiceToCameraError(CAMERA_INVALID_ARG);
    }
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (captureSession_ == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::AddOutput() captureSession_ is nullptr");
        return ServiceToCameraError(errCode);
    }
    errCode = captureSession_->AddOutput(output->GetStreamType(), output->GetStream());
    if (output->GetOutputType() == CAPTURE_OUTPUT_TYPE_PHOTO) {
        photoOutput_ = output;
    }
    MEDIA_INFO_LOG("CaptureSession::AddOutput StreamType = %{public}d", output->GetStreamType());
    if (errCode != CAMERA_OK) {
        MEDIA_ERR_LOG("Failed to AddOutput!, %{public}d", errCode);
        return ServiceToCameraError(errCode);
    }
    InsertOutputIntoSet(output);
    return ServiceToCameraError(errCode);
}

int32_t CaptureSession::AddSecureOutput(sptr<CaptureOutput> &output)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("Enter Into SecureCameraSession::AddSecureOutput");
    if (currentMode_ != SceneMode::SECURE) {
        return CAMERA_UNSUPPORTED;
    }
    if (!IsSessionConfiged() || output == nullptr || isSetSecureOutput_) {
        MEDIA_ERR_LOG("SecureCameraSession::AddSecureOutput operation is Not allowed!");
        return CAMERA_OK;
    }
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
    if (!IsSessionConfiged() || output == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::CanAddOutput operation Not allowed!");
        return false;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::CanAddOutput Failed inputDevice_ is nullptr");
        return false;
    }
    auto modeName = GetMode();
    auto validateOutputFunc = [modeName](auto& vaildateProfile, auto& profiles, std::string&& outputType) -> bool {
        bool result = std::any_of(profiles.begin(), profiles.end(),
            [&vaildateProfile](const auto& profile) { return vaildateProfile == profile; });
        Size invalidSize = vaildateProfile.GetSize();
        if (result == false) {
            MEDIA_ERR_LOG("CaptureSession::CanAddOutput profile invalid in "
                          "%{public}s_output, mode(%{public}d): w(%{public}d),h(%{public}d),f(%{public}d)",
                          outputType.c_str(), static_cast<int32_t>(modeName),
                          invalidSize.width, invalidSize.height, vaildateProfile.GetCameraFormat());
        } else {
            MEDIA_DEBUG_LOG("CaptureSession::CanAddOutput profile pass in "
                            "%{public}s_output, mode(%{public}d): w(%{public}d),h(%{public}d),f(%{public}d)",
                            outputType.c_str(), static_cast<int32_t>(modeName),
                            invalidSize.width, invalidSize.height, vaildateProfile.GetCameraFormat());
        }
        return result;
    };
    if (output->GetOutputType() == CAPTURE_OUTPUT_TYPE_PREVIEW) {
        std::vector<Profile> profiles = inputDevice_->GetCameraDeviceInfo()->modePreviewProfiles_[modeName];
        Profile vaildateProfile = output->GetPreviewProfile();
        return validateOutputFunc(vaildateProfile, profiles, std::move("preview"));
    } else if (output->GetOutputType() == CAPTURE_OUTPUT_TYPE_PHOTO) {
        std::vector<Profile> profiles = inputDevice_->GetCameraDeviceInfo()->modePhotoProfiles_[modeName];
        Profile vaildateProfile = output->GetPhotoProfile();
        return validateOutputFunc(vaildateProfile, profiles, std::move("photo"));
    } else if (output->GetOutputType() == CAPTURE_OUTPUT_TYPE_VIDEO) {
        std::vector<VideoProfile> profiles = inputDevice_->GetCameraDeviceInfo()->modeVideoProfiles_[modeName];
        VideoProfile vaildateProfile = output->GetVideoProfile();
        return validateOutputFunc(vaildateProfile, profiles, std::move("video"));
    } else if (output->GetOutputType() == CAPTURE_OUTPUT_TYPE_METADATA) {
        MEDIA_INFO_LOG("CaptureSession::CanAddOutput MetadataOutput");
        return true;
    }
    MEDIA_ERR_LOG("CaptureSession::CanAddOutput check fail,modeName:%{public}d, outputType:%{public}d", modeName,
        output->GetOutputType());
    return false;
}

int32_t CaptureSession::RemoveInput(sptr<CaptureInput>& input)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter Into CaptureSession::RemoveInput");
    if (!IsSessionConfiged()) {
        MEDIA_ERR_LOG("CaptureSession::RemoveInput operation Not allowed!");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }

    if (input == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::RemoveInput input is null");
        return ServiceToCameraError(CAMERA_INVALID_ARG);
    }
    auto device = ((sptr<CameraInput>&)input)->GetCameraDevice();
    if (device == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::RemoveInput device is null");
        return ServiceToCameraError(CAMERA_INVALID_ARG);
    }
    if (inputDevice_ != nullptr) {
        inputDevice_ = nullptr;
    }
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (captureSession_) {
        errCode = captureSession_->RemoveInput(device);
        auto deviceInfo = input->GetCameraDeviceInfo();
        if (deviceInfo != nullptr) {
            deviceInfo->ResetMetadata();
        }
        if (errCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to RemoveInput!, %{public}d", errCode);
        }
    } else {
        MEDIA_ERR_LOG("CaptureSession::RemoveInput() captureSession_ is nullptr");
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
    if (!IsSessionConfiged()) {
        MEDIA_ERR_LOG("CaptureSession::RemoveOutput operation Not allowed!");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }
    if (output == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::RemoveOutput output is null");
        return ServiceToCameraError(CAMERA_INVALID_ARG);
    }
    output->SetSession(nullptr);
    if (output->GetOutputType() == CAPTURE_OUTPUT_TYPE_METADATA) {
        sptr<MetadataOutput> metaOutput = static_cast<MetadataOutput*>(output.GetRefPtr());
        if (!metaOutput) {
            MEDIA_ERR_LOG("CaptureSession::metaOutput is null");
            return ServiceToCameraError(CAMERA_INVALID_ARG);
        }
        std::vector<MetadataObjectType> metadataObjectTypes = {};
        MEDIA_DEBUG_LOG("CaptureSession::RemoveOutput SetCapturingMetadataObjectTypes off");
        metaOutput->SetCapturingMetadataObjectTypes(metadataObjectTypes);
        MEDIA_DEBUG_LOG("CaptureSession::RemoveOutput remove metaOutput");
        return ServiceToCameraError(CAMERA_OK);
    }
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (captureSession_) {
        errCode = captureSession_->RemoveOutput(output->GetStreamType(), output->GetStream());
        if (errCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to RemoveOutput!, %{public}d", errCode);
        }
    } else {
        MEDIA_ERR_LOG("CaptureSession::RemoveOutput() captureSession_ is nullptr");
    }
    RemoveOutputFromSet(output);
    return ServiceToCameraError(errCode);
}

int32_t CaptureSession::Start()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter Into CaptureSession::Start");
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::Start Session not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (captureSession_) {
        errCode = captureSession_->Start();
        if (errCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to Start capture session!, %{public}d", errCode);
        }
    } else {
        MEDIA_ERR_LOG("CaptureSession::Start() captureSession_ is nullptr");
    }
    if (GetMetaOutput()) {
        sptr<MetadataOutput> metaOutput = static_cast<MetadataOutput*>(GetMetaOutput().GetRefPtr());
        if (!metaOutput) {
            MEDIA_INFO_LOG("CaptureSession::metaOutput is null");
            return ServiceToCameraError(errCode);
        }
        std::vector<MetadataObjectType> metadataObjectTypes = metaOutput->GetSupportedMetadataObjectTypes();
        MEDIA_INFO_LOG("CaptureSession::Start SetCapturingMetadataObjectTypes objectTypes size = %{public}zu",
            metadataObjectTypes.size());
        metaOutput->SetCapturingMetadataObjectTypes(metadataObjectTypes);
    }
    return ServiceToCameraError(errCode);
}

int32_t CaptureSession::Stop()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter Into CaptureSession::Stop");
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (captureSession_) {
        errCode = captureSession_->Stop();
        if (errCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to Stop capture session!, %{public}d", errCode);
        }
    } else {
        MEDIA_ERR_LOG("CaptureSession::Stop() captureSession_ is nullptr");
    }
    return ServiceToCameraError(errCode);
}

int32_t CaptureSession::Release()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter Into CaptureSession::Release");
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (captureSession_) {
        errCode = captureSession_->Release();
        MEDIA_DEBUG_LOG("Release capture session, %{public}d", errCode);
    } else {
        MEDIA_ERR_LOG("CaptureSession::Release() captureSession_ is nullptr");
    }
    inputDevice_ = nullptr;
    captureSession_ = nullptr;
    changedMetadata_ = nullptr;
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    captureSessionCallback_ = nullptr;
    appCallback_ = nullptr;
    exposureCallback_ = nullptr;
    focusCallback_ = nullptr;
    macroStatusCallback_ = nullptr;
    moonCaptureBoostStatusCallback_ = nullptr;
    smoothZoomCallback_ = nullptr;
    abilityCallback_ = nullptr;
    arCallback_ = nullptr;
    return ServiceToCameraError(errCode);
}

void CaptureSession::SetCallback(std::shared_ptr<SessionCallback> callback)
{
    if (callback == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::SetCallback: Unregistering application callback!");
    }
    int32_t errorCode = CAMERA_OK;
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    appCallback_ = callback;
    if (appCallback_ != nullptr && captureSession_ != nullptr) {
        if (captureSessionCallback_ == nullptr) {
            captureSessionCallback_ = new (std::nothrow) CaptureSessionCallback(this);
        }
        if (captureSession_) {
            errorCode = captureSession_->SetCallback(captureSessionCallback_);
            if (errorCode != CAMERA_OK) {
                MEDIA_ERR_LOG(
                    "CaptureSession::SetCallback: Failed to register callback, errorCode: %{public}d", errorCode);
                captureSessionCallback_ = nullptr;
                appCallback_ = nullptr;
            }
        }
    }
    return;
}

std::shared_ptr<SessionCallback> CaptureSession::GetApplicationCallback()
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    return appCallback_;
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
    auto metadataHeader = changedMetadata->get();
    uint32_t count = Camera::GetCameraMetadataItemCount(metadataHeader);
    if (count == 0) {
        MEDIA_INFO_LOG("CaptureSession::UpdateSetting No configuration to update");
        return CameraErrorCode::SUCCESS;
    }

    if (inputDevice_ == nullptr || ((sptr<CameraInput>&)inputDevice_)->GetCameraDevice() == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::UpdateSetting Failed inputDevice_ is nullptr");
        return CameraErrorCode::SUCCESS;
    }
    int32_t ret = ((sptr<CameraInput>&)inputDevice_)->GetCameraDevice()->UpdateSetting(changedMetadata);
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("CaptureSession::UpdateSetting Failed to update settings, errCode = %{public}d", ret);
        return ServiceToCameraError(ret);
    }

    std::shared_ptr<Camera::CameraMetadata> baseMetadata = GetMetadata();
    for (uint32_t index = 0; index < count; index++) {
        camera_metadata_item_t srcItem;
        int ret = OHOS::Camera::GetCameraMetadataItem(metadataHeader, index, &srcItem);
        if (ret != CAM_META_SUCCESS) {
            MEDIA_ERR_LOG("CaptureSession::UpdateSetting Failed to get metadata item at index: %{public}d", index);
            return CAMERA_INVALID_ARG;
        }
        bool status = false;
        uint32_t currentIndex;
        ret = OHOS::Camera::FindCameraMetadataItemIndex(baseMetadata->get(), srcItem.item, &currentIndex);
        if (ret == CAM_META_SUCCESS) {
            status = baseMetadata->updateEntry(srcItem.item, srcItem.data.u8, srcItem.count);
        } else if (ret == CAM_META_ITEM_NOT_FOUND) {
            status = baseMetadata->addEntry(srcItem.item, srcItem.data.u8, srcItem.count);
        }
        if (!status) {
            MEDIA_ERR_LOG("CaptureSession::UpdateSetting Failed to add/update metadata item: %{public}d", srcItem.item);
        }
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
        if (filters.empty()) {
            continue;
        }
        for (auto tag : filters) {
            camera_metadata_item_t item;
            int ret = Camera::FindCameraMetadataItem(changedMetadata->get(), tag, &item);
            if (ret != CAM_META_SUCCESS || item.count <= 0) {
                continue;
            }
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
        if (filters.empty()) {
            continue;
        }
        for (auto tag : filters) {
            camera_metadata_item_t item;
            int ret = Camera::FindCameraMetadataItem(metadata->get(), tag, &item);
            if (ret != CAM_META_SUCCESS || item.count <= 0) {
                continue;
            }
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
        return ServiceToCameraError(CAMERA_INVALID_ARG);
    }
    MEDIA_DEBUG_LOG("CaptureSession::UnlockForControl Called");
    UpdateSetting(changedMetadata_);
    changedMetadata_ = nullptr;
    changeMetaMutex_.unlock();
    return CameraErrorCode::SUCCESS;
}

VideoStabilizationMode CaptureSession::GetActiveVideoStabilizationMode()
{
    sptr<CameraDevice> cameraObj_;
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetActiveVideoStabilizationMode camera device is null");
        return OFF;
    }
    cameraObj_ = inputDevice_->GetCameraDeviceInfo();
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj_->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &item);
    if (ret == CAM_META_SUCCESS) {
        auto itr = metaVideoStabModesMap_.find(static_cast<CameraVideoStabilizationMode>(item.data.u8[0]));
        if (itr != metaVideoStabModesMap_.end()) {
            return itr->second;
        }
    }
    return OFF;
}

int32_t CaptureSession::GetActiveVideoStabilizationMode(VideoStabilizationMode& mode)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetActiveVideoStabilizationMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetActiveVideoStabilizationMode camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    mode = OFF;
    bool isSupported = false;
    sptr<CameraDevice> cameraObj_;
    cameraObj_ = inputDevice_->GetCameraDeviceInfo();
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj_->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &item);
    if (ret == CAM_META_SUCCESS) {
        auto itr = metaVideoStabModesMap_.find(static_cast<CameraVideoStabilizationMode>(item.data.u8[0]));
        if (itr != metaVideoStabModesMap_.end()) {
            mode = itr->second;
            isSupported = true;
        }
    }
    if (!isSupported || ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetActiveVideoStabilizationMode Failed with return code %{public}d", ret);
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetVideoStabilizationMode(VideoStabilizationMode stabilizationMode)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetVideoStabilizationMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    auto itr = fwkVideoStabModesMap_.find(stabilizationMode);
    if ((itr == fwkVideoStabModesMap_.end()) || !IsVideoStabilizationModeSupported(stabilizationMode)) {
        MEDIA_ERR_LOG("CaptureSession::SetVideoStabilizationMode Mode: %{public}d not supported", stabilizationMode);
        stabilizationMode = OFF;
    }

    uint32_t count = 1;
    uint8_t stabilizationMode_ = stabilizationMode;

    this->LockForControl();
    MEDIA_DEBUG_LOG("CaptureSession::SetVideoStabilizingMode StabilizationMode : %{public}d", stabilizationMode_);
    if (!(this->changedMetadata_->addEntry(OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &stabilizationMode_, count))) {
        MEDIA_DEBUG_LOG("CaptureSession::SetVideoStabilizingMode Failed to set video stabilization mode");
    }

    int32_t errCode = this->UnlockForControl();
    if (errCode != CameraErrorCode::SUCCESS) {
        MEDIA_DEBUG_LOG("CaptureSession::SetVideoStabilizingMode Failed to set video stabilization mode");
    }
    return CameraErrorCode::SUCCESS;
}

bool CaptureSession::IsVideoStabilizationModeSupported(VideoStabilizationMode stabilizationMode)
{
    std::vector<VideoStabilizationMode> stabilizationModes = GetSupportedStabilizationMode();
    if (std::find(stabilizationModes.begin(), stabilizationModes.end(), stabilizationMode) !=
        stabilizationModes.end()) {
        return true;
    }
    return false;
}

int32_t CaptureSession::IsVideoStabilizationModeSupported(VideoStabilizationMode stabilizationMode, bool& isSupported)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::IsVideoStabilizationModeSupported Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    std::vector<VideoStabilizationMode> stabilizationModes = GetSupportedStabilizationMode();
    if (std::find(stabilizationModes.begin(), stabilizationModes.end(), stabilizationMode) !=
        stabilizationModes.end()) {
        isSupported = true;
        return CameraErrorCode::SUCCESS;
    }
    isSupported = false;
    return CameraErrorCode::SUCCESS;
}

std::vector<VideoStabilizationMode> CaptureSession::GetSupportedStabilizationMode()
{
    std::vector<VideoStabilizationMode> stabilizationModes;

    sptr<CameraDevice> cameraObj_;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedStabilizationMode Session is not Commited");
        return stabilizationModes;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedStabilizationMode camera device is null");
        return stabilizationModes;
    }
    cameraObj_ = inputDevice_->GetCameraDeviceInfo();
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj_->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_VIDEO_STABILIZATION_MODES, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetSupporteStabilizationModes Failed with return code %{public}d", ret);
        return stabilizationModes;
    }

    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = metaVideoStabModesMap_.find(static_cast<CameraVideoStabilizationMode>(item.data.u8[i]));
        if (itr != metaVideoStabModesMap_.end()) {
            stabilizationModes.emplace_back(itr->second);
        }
    }
    return stabilizationModes;
}

int32_t CaptureSession::GetSupportedStabilizationMode(std::vector<VideoStabilizationMode>& stabilizationModes)
{
    sptr<CameraDevice> cameraObj_;
    stabilizationModes.clear();
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedStabilizationMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedStabilizationMode camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    cameraObj_ = inputDevice_->GetCameraDeviceInfo();
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj_->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_VIDEO_STABILIZATION_MODES, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetSupporteStabilizationModes Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }

    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = metaVideoStabModesMap_.find(static_cast<CameraVideoStabilizationMode>(item.data.u8[i]));
        if (itr != metaVideoStabModesMap_.end()) {
            stabilizationModes.emplace_back(itr->second);
        }
    }
    return CameraErrorCode::SUCCESS;
}

bool CaptureSession::IsExposureModeSupported(ExposureMode exposureMode)
{
    std::vector<ExposureMode> vecSupportedExposureModeList;
    vecSupportedExposureModeList = this->GetSupportedExposureModes();
    if (find(vecSupportedExposureModeList.begin(), vecSupportedExposureModeList.end(), exposureMode) !=
        vecSupportedExposureModeList.end()) {
        return true;
    }

    return false;
}

int32_t CaptureSession::IsExposureModeSupported(ExposureMode exposureMode, bool& isSupported)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::IsExposureModeSupported Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
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
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedExposureModes Session is not Commited");
        return {};
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedExposureModes camera device is null");
        return {};
    }
    std::vector<ExposureMode> supportedExposureModes;
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_EXPOSURE_MODES, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedExposureModes Failed with return code %{public}d", ret);
        return supportedExposureModes;
    }

    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = metaExposureModeMap_.find(static_cast<camera_exposure_mode_enum_t>(item.data.u8[i]));
        if (itr != metaExposureModeMap_.end()) {
            supportedExposureModes.emplace_back(itr->second);
        }
    }
    return supportedExposureModes;
}

int32_t CaptureSession::GetSupportedExposureModes(std::vector<ExposureMode>& supportedExposureModes)
{
    supportedExposureModes.clear();
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedExposureModes Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedExposureModes camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_EXPOSURE_MODES, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedExposureModes Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }

    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = metaExposureModeMap_.find(static_cast<camera_exposure_mode_enum_t>(item.data.u8[i]));
        if (itr != metaExposureModeMap_.end()) {
            supportedExposureModes.emplace_back(itr->second);
        }
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetExposureMode(ExposureMode exposureMode)
{
    CAMERA_SYNC_TRACE;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }

    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureMode Need to call LockForControl() "
                      "before setting camera properties");
        return CameraErrorCode::SUCCESS;
    }
    uint8_t exposure = fwkExposureModeMap_.at(EXPOSURE_MODE_LOCKED);
    auto itr = fwkExposureModeMap_.find(exposureMode);
    if (itr == fwkExposureModeMap_.end()) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureMode Unknown exposure mode");
    } else {
        exposure = itr->second;
    }

    bool status = false;
    uint32_t count = 1;
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_EXPOSURE_MODE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_EXPOSURE_MODE, &exposure, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_EXPOSURE_MODE, &exposure, count);
    }

    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureMode Failed to set exposure mode");
    }

    return CameraErrorCode::SUCCESS;
}

ExposureMode CaptureSession::GetExposureMode()
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureMode Session is not Commited");
        return EXPOSURE_MODE_UNSUPPORTED;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureMode camera device is null");
        return EXPOSURE_MODE_UNSUPPORTED;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_EXPOSURE_MODE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureMode Failed with return code %{public}d", ret);
        return EXPOSURE_MODE_UNSUPPORTED;
    }
    auto itr = metaExposureModeMap_.find(static_cast<camera_exposure_mode_enum_t>(item.data.u8[0]));
    if (itr != metaExposureModeMap_.end()) {
        return itr->second;
    }

    return EXPOSURE_MODE_UNSUPPORTED;
}

int32_t CaptureSession::GetExposureMode(ExposureMode& exposureMode)
{
    exposureMode = EXPOSURE_MODE_UNSUPPORTED;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureMode camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_EXPOSURE_MODE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureMode Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    auto itr = metaExposureModeMap_.find(static_cast<camera_exposure_mode_enum_t>(item.data.u8[0]));
    if (itr != metaExposureModeMap_.end()) {
        exposureMode = itr->second;
        return CameraErrorCode::SUCCESS;
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetMeteringPoint(Point exposurePoint)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetMeteringPoint Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }

    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::SetExposurePoint Need to call LockForControl() "
                      "before setting camera properties");
        return CameraErrorCode::SUCCESS;
    }
    Point exposureVerifyPoint = VerifyFocusCorrectness(exposurePoint);
    Point unifyExposurePoint = CoordinateTransform(exposureVerifyPoint);
    bool status = false;
    float exposureArea[2] = { unifyExposurePoint.x, unifyExposurePoint.y };
    camera_metadata_item_t item;

    int ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_AE_REGIONS, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(
            OHOS_CONTROL_AE_REGIONS, exposureArea, sizeof(exposureArea) / sizeof(exposureArea[0]));
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(
            OHOS_CONTROL_AE_REGIONS, exposureArea, sizeof(exposureArea) / sizeof(exposureArea[0]));
    }

    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::SetExposurePoint Failed to set exposure Area");
    }
    return CameraErrorCode::SUCCESS;
}

Point CaptureSession::GetMeteringPoint()
{
    Point exposurePoint = { 0, 0 };
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetMeteringPoint Session is not Commited");
        return exposurePoint;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetMeteringPoint camera device is null");
        return exposurePoint;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_AE_REGIONS, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetExposurePoint Failed with return code %{public}d", ret);
        return exposurePoint;
    }
    exposurePoint.x = item.data.f[0];
    exposurePoint.y = item.data.f[1];
    Point unifyExposurePoint = CoordinateTransform(exposurePoint);
    return unifyExposurePoint;
}

int32_t CaptureSession::GetMeteringPoint(Point& exposurePoint)
{
    exposurePoint.x = 0;
    exposurePoint.y = 0;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetMeteringPoint Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetMeteringPoint camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_AE_REGIONS, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetExposurePoint Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    exposurePoint.x = item.data.f[0];
    exposurePoint.y = item.data.f[1];
    exposurePoint = CoordinateTransform(exposurePoint);
    return CameraErrorCode::SUCCESS;
}

std::vector<float> CaptureSession::GetExposureBiasRange()
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureBiasRange Session is not Commited");
        return {};
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureBiasRange camera device is null");
        return {};
    }
    return inputDevice_->GetCameraDeviceInfo()->GetExposureBiasRange();
}

int32_t CaptureSession::GetExposureBiasRange(std::vector<float>& exposureBiasRange)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureBiasRange Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureBiasRange camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    exposureBiasRange = inputDevice_->GetCameraDeviceInfo()->GetExposureBiasRange();
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetExposureBias(float exposureValue)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureBias Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureValue Need to call LockForControl() "
            "before setting camera properties");
        return CameraErrorCode::SUCCESS;
    }
    bool status = false;
    int32_t minIndex = 0;
    int32_t maxIndex = 1;
    int32_t count = 1;
    camera_metadata_item_t item;
    MEDIA_DEBUG_LOG("CaptureSession::SetExposureValue exposure compensation: %{public}f", exposureValue);
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureBias camera device is null");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }
    std::vector<float> biasRange = inputDevice_->GetCameraDeviceInfo()->GetExposureBiasRange();
    if (biasRange.empty()) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureValue Bias range is empty");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }
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

    int ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &exposureCompensation, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &exposureCompensation, count);
    }
    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureValue Failed to set exposure compensation");
    }
    return CameraErrorCode::SUCCESS;
}

float CaptureSession::GetExposureValue()
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureValue Session is not Commited");
        return 0;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureValue camera device is null");
        return 0;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureValue Failed with return code %{public}d", ret);
        return 0;
    }
    int32_t exposureCompensation = item.data.i32[0];

    ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_AE_COMPENSATION_STEP, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureValue Failed with return code %{public}d", ret);
        return 0;
    }
    int32_t stepNumerator = item.data.r->numerator;
    int32_t stepDenominator = item.data.r->denominator;
    float exposureValue = 0;
    if (stepDenominator != 0) {
        float step = static_cast<float>(stepNumerator) / static_cast<float>(stepDenominator);
        exposureValue = step * exposureCompensation;
    } else {
        MEDIA_ERR_LOG("stepDenominator: %{public}d", stepDenominator);
    }
    MEDIA_DEBUG_LOG("exposureValue: %{public}f", exposureValue);

    return exposureValue;
}

int32_t CaptureSession::GetExposureValue(float& exposureValue)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureValue Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureValue camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureValue Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    int32_t exposureCompensation = item.data.i32[0];

    ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_AE_COMPENSATION_STEP, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureValue Failed with return code %{public}d", ret);
        return 0;
    }
    int32_t stepNumerator = item.data.r->numerator;
    int32_t stepDenominator = item.data.r->denominator;
    float step = static_cast<float>(stepNumerator) / static_cast<float>(stepDenominator);

    exposureValue = step * exposureCompensation;
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
    if (ret == CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("exposure mode: %{public}d", item.data.u8[0]);
    }

    ret = Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_EXPOSURE_STATE, &item);
    if (ret == CAM_META_SUCCESS) {
        MEDIA_INFO_LOG("Exposure state: %{public}d", item.data.u8[0]);
        std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
        if (exposureCallback_ != nullptr) {
            auto itr = metaExposureStateMap_.find(static_cast<camera_exposure_state_t>(item.data.u8[0]));
            if (itr != metaExposureStateMap_.end()) {
                exposureCallback_->OnExposureState(itr->second);
            }
        }
    }
}

std::vector<FocusMode> CaptureSession::GetSupportedFocusModes()
{
    std::vector<FocusMode> supportedFocusModes = {};
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureBias Session is not Commited");
        return supportedFocusModes;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedFocusModes camera device is null");
        return supportedFocusModes;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FOCUS_MODES, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedFocusModes Failed with return code %{public}d", ret);
        return supportedFocusModes;
    }
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = metaFocusModeMap_.find(static_cast<camera_focus_mode_enum_t>(item.data.u8[i]));
        if (itr != metaFocusModeMap_.end()) {
            supportedFocusModes.emplace_back(itr->second);
        }
    }
    return supportedFocusModes;
}

int32_t CaptureSession::GetSupportedFocusModes(std::vector<FocusMode>& supportedFocusModes)
{
    supportedFocusModes.clear();
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureBias Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedFocusModes camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FOCUS_MODES, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedFocusModes Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = metaFocusModeMap_.find(static_cast<camera_focus_mode_enum_t>(item.data.u8[i]));
        if (itr != metaFocusModeMap_.end()) {
            supportedFocusModes.emplace_back(itr->second);
        }
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
    std::vector<FocusMode> vecSupportedFocusModeList;
    vecSupportedFocusModeList = this->GetSupportedFocusModes();
    if (find(vecSupportedFocusModeList.begin(), vecSupportedFocusModeList.end(), focusMode) !=
        vecSupportedFocusModeList.end()) {
        return true;
    }

    return false;
}

int32_t CaptureSession::IsFocusModeSupported(FocusMode focusMode, bool& isSupported)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureBias Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
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
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetFocusMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::SetFocusMode Need to call LockForControl() before setting camera properties");
        return CameraErrorCode::SUCCESS;
    }
    uint8_t focus = FOCUS_MODE_LOCKED;
    auto itr = fwkFocusModeMap_.find(focusMode);
    if (itr == fwkFocusModeMap_.end()) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureMode Unknown exposure mode");
    } else {
        focus = itr->second;
    }
    bool status = false;
    int32_t ret;
    uint32_t count = 1;
    camera_metadata_item_t item;

    MEDIA_DEBUG_LOG("CaptureSession::SetFocusMode Focus mode: %{public}d", focusMode);

    ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_FOCUS_MODE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_FOCUS_MODE, &focus, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_FOCUS_MODE, &focus, count);
    }

    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::SetFocusMode Failed to set focus mode");
    }
    return CameraErrorCode::SUCCESS;
}

FocusMode CaptureSession::GetFocusMode()
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusMode Session is not Commited");
        return FOCUS_MODE_MANUAL;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusMode camera device is null");
        return FOCUS_MODE_MANUAL;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_FOCUS_MODE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusMode Failed with return code %{public}d", ret);
        return FOCUS_MODE_MANUAL;
    }
    auto itr = metaFocusModeMap_.find(static_cast<camera_focus_mode_enum_t>(item.data.u8[0]));
    if (itr != metaFocusModeMap_.end()) {
        return itr->second;
    }
    return FOCUS_MODE_MANUAL;
}

int32_t CaptureSession::GetFocusMode(FocusMode& focusMode)
{
    focusMode = FOCUS_MODE_MANUAL;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusMode camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_FOCUS_MODE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusMode Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    auto itr = metaFocusModeMap_.find(static_cast<camera_focus_mode_enum_t>(item.data.u8[0]));
    if (itr != metaFocusModeMap_.end()) {
        focusMode = itr->second;
        return CameraErrorCode::SUCCESS;
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetFocusPoint(Point focusPoint)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetFocusPoint Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::SetFocusPoint Need to call LockForControl() before setting camera properties");
        return CameraErrorCode::SUCCESS;
    }
    FocusMode focusMode;
    GetFocusMode(focusMode);
    if (focusMode == FOCUS_MODE_CONTINUOUS_AUTO) {
        MEDIA_ERR_LOG("The current mode does not support setting the focus point.");
        return CameraErrorCode::SUCCESS;
    }
    Point focusVerifyPoint = VerifyFocusCorrectness(focusPoint);
    Point unifyFocusPoint = CoordinateTransform(focusVerifyPoint);
    bool status = false;
    float FocusArea[2] = { unifyFocusPoint.x, unifyFocusPoint.y };
    camera_metadata_item_t item;

    int ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_AF_REGIONS, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status =
            changedMetadata_->addEntry(OHOS_CONTROL_AF_REGIONS, FocusArea, sizeof(FocusArea) / sizeof(FocusArea[0]));
    } else if (ret == CAM_META_SUCCESS) {
        status =
            changedMetadata_->updateEntry(OHOS_CONTROL_AF_REGIONS, FocusArea, sizeof(FocusArea) / sizeof(FocusArea[0]));
    }

    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::SetFocusPoint Failed to set Focus Area");
    }
    return CameraErrorCode::SUCCESS;
}

Point CaptureSession::CoordinateTransform(Point point)
{
    MEDIA_DEBUG_LOG("CaptureSession::CoordinateTransform begin x: %{public}f, y: %{public}f", point.x, point.y);
    Point unifyPoint = point;
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::CoordinateTransform cameraInput is nullptr");
        return unifyPoint;
    }
    if (inputDevice_->GetCameraDeviceInfo()->GetPosition() == CAMERA_POSITION_FRONT) {
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
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusPoint Session is not Commited");
        return focusPoint;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusPoint camera device is null");
        return focusPoint;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_AF_REGIONS, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusPoint Failed with return code %{public}d", ret);
        return focusPoint;
    }
    focusPoint.x = item.data.f[0];
    focusPoint.y = item.data.f[1];
    Point unifyFocusPoint = CoordinateTransform(focusPoint);
    return unifyFocusPoint;
}

int32_t CaptureSession::GetFocusPoint(Point& focusPoint)
{
    focusPoint.x = 0;
    focusPoint.y = 0;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusPoint Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusPoint camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_AF_REGIONS, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusPoint Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    focusPoint.x = item.data.f[0];
    focusPoint.y = item.data.f[1];
    focusPoint = CoordinateTransform(focusPoint);
    return CameraErrorCode::SUCCESS;
}

float CaptureSession::GetFocalLength()
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocalLength Session is not Commited");
        return 0;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocalLength camera device is null");
        return 0;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FOCAL_LENGTH, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetFocalLength Failed with return code %{public}d", ret);
        return 0;
    }
    return static_cast<float>(item.data.f[0]);
}

int32_t CaptureSession::GetFocalLength(float& focalLength)
{
    focalLength = 0;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocalLength Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocalLength camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FOCAL_LENGTH, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetFocalLength Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    focalLength = static_cast<float>(item.data.f[0]);
    return CameraErrorCode::SUCCESS;
}

void CaptureSession::ProcessAutoFocusUpdates(const std::shared_ptr<Camera::CameraMetadata>& result)
{
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_FOCUS_MODE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("Camera not support Focus mode");
        return;
    }
    MEDIA_DEBUG_LOG("Focus mode: %{public}d", item.data.u8[0]);
    auto it = metaFocusModeMap_.find(static_cast<camera_focus_mode_enum_t>(item.data.u8[0]));
    // continuous focus mode do not callback focusStateChange
    if (it == metaFocusModeMap_.end() || it->second != FOCUS_MODE_AUTO) {
        return;
    }
    ret = Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_FOCUS_STATE, &item);
    if (ret == CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("Focus state: %{public}d", item.data.u8[0]);
        std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
        if (focusCallback_ != nullptr) {
            auto itr = metaFocusStateMap_.find(static_cast<camera_focus_state_t>(item.data.u8[0]));
            if (itr != metaFocusStateMap_.end() && itr->second != focusCallback_->currentState) {
                focusCallback_->OnFocusState(itr->second);
                focusCallback_->currentState = itr->second;
            }
        }
    }
}

void CaptureSession::ProcessFaceRecUpdates(
    const uint64_t timestamp, const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    if (GetMetaOutput() != nullptr) {
        sptr<MetadataOutput> metaOutput = static_cast<MetadataOutput*>(GetMetaOutput().GetRefPtr());
        if (!metaOutput) {
            MEDIA_DEBUG_LOG("metaOutput is null");
            return;
        }
        bool isNeedMirror = false;
        if (inputDevice_ && inputDevice_->GetCameraDeviceInfo()) {
            isNeedMirror = (inputDevice_->GetCameraDeviceInfo()->GetPosition() == CAMERA_POSITION_FRONT ||
                            inputDevice_->GetCameraDeviceInfo()->GetPosition() == CAMERA_POSITION_FOLD_INNER);
        }
        std::vector<sptr<MetadataObject>> metaObjects;
        metaOutput->ProcessFaceRectangles(timestamp, result, metaObjects, isNeedMirror);
        std::shared_ptr<MetadataObjectCallback> appObjectCallback = metaOutput->GetAppObjectCallback();
        if (!metaObjects.empty() && appObjectCallback) {
            MEDIA_DEBUG_LOG("OnMetadataObjectsAvailable");
            appObjectCallback->OnMetadataObjectsAvailable(metaObjects);
        }
    }
}

void CaptureSession::ProcessSnapshotDurationUpdates(const uint64_t timestamp,
    const std::shared_ptr<OHOS::Camera::CameraMetadata> &result)
{
    MEDIA_DEBUG_LOG("Entry ProcessSnapShotDurationUpdates");
    if (photoOutput_ != nullptr) {
        camera_metadata_item_t metadataItem;
        common_metadata_header_t* metadata = result->get();
        int ret = Camera::FindCameraMetadataItem(metadata, OHOS_CAMERA_CUSTOM_SNAPSHOT_DURATION, &metadataItem);
        if (ret != CAM_META_SUCCESS || metadataItem.count <= 0) {
            return;
        }
        int32_t duration = static_cast<int32_t>(metadataItem.data.ui32[0]);
        if (duration != prevDuration_.load()) {
            ((sptr<PhotoOutput> &)photoOutput_)->ProcessSnapshotDurationUpdates(duration);
        }
        prevDuration_ = duration;
    }
}

void CaptureSession::ProcessAREngineUpdates(const uint64_t timestamp,
    const std::shared_ptr<OHOS::Camera::CameraMetadata> &result)
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
    if (ret == CAM_META_SUCCESS) {
        arStatusInfo.lensFocusDistance = item.data.f[0];
    }

    ret = Camera::FindCameraMetadataItem(metadata, HAL_CUSTOM_SENSOR_SENSITIVITY, &item);
    if (ret == CAM_META_SUCCESS) {
        arStatusInfo.sensorSensitivity = item.data.i32[0];
    }

    ret = Camera::FindCameraMetadataItem(metadata, OHOS_STATUS_SENSOR_EXPOSURE_TIME, &item);
    if (ret == CAM_META_SUCCESS) {
        int32_t numerator = item.data.r->numerator;
        int32_t denominator = item.data.r->denominator;
        MEDIA_DEBUG_LOG("SensorExposureTime: %{public}d/%{public}d", numerator, denominator);
        if (denominator == 0) {
            MEDIA_ERR_LOG("ProcessSensorExposureTimeChange error! divide by zero");
            return;
        }
        uint32_t value = numerator / (denominator/1000000);
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
    if (session == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::CaptureSessionMetadataResultProcessor ProcessCallbacks but session is null");
        return;
    }

    session->OnResultReceived(result);
    session->ProcessFaceRecUpdates(timestamp, result);
    session->ProcessAutoFocusUpdates(result);
    session->ProcessMacroStatusChange(result);
    session->ProcessMoonCaptureBoostStatusChange(result);
    session->ProcessSnapshotDurationUpdates(timestamp, result);
    session->ProcessAREngineUpdates(timestamp, result);
}

std::vector<FlashMode> CaptureSession::GetSupportedFlashModes()
{
    std::vector<FlashMode> supportedFlashModes = {};
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedFlashModes Session is not Commited");
        return supportedFlashModes;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedFlashModes camera device is null");
        return supportedFlashModes;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FLASH_MODES, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedFlashModes Failed with return code %{public}d", ret);
        return supportedFlashModes;
    }
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = metaFlashModeMap_.find(static_cast<camera_flash_mode_enum_t>(item.data.u8[i]));
        if (itr != metaFlashModeMap_.end()) {
            supportedFlashModes.emplace_back(itr->second);
        }
    }
    return supportedFlashModes;
}

int32_t CaptureSession::GetSupportedFlashModes(std::vector<FlashMode>& supportedFlashModes)
{
    supportedFlashModes.clear();
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedFlashModes Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedFlashModes camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FLASH_MODES, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedFlashModes Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = metaFlashModeMap_.find(static_cast<camera_flash_mode_enum_t>(item.data.u8[i]));
        if (itr != metaFlashModeMap_.end()) {
            supportedFlashModes.emplace_back(itr->second);
        }
    }
    return CameraErrorCode::SUCCESS;
}

FlashMode CaptureSession::GetFlashMode()
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetFlashMode Session is not Commited");
        return FLASH_MODE_CLOSE;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetFlashMode camera device is null");
        return FLASH_MODE_CLOSE;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_FLASH_MODE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetFlashMode Failed with return code %{public}d", ret);
        return FLASH_MODE_CLOSE;
    }
    auto itr = metaFlashModeMap_.find(static_cast<camera_flash_mode_enum_t>(item.data.u8[0]));
    if (itr != metaFlashModeMap_.end()) {
        return itr->second;
    }

    return FLASH_MODE_CLOSE;
}

int32_t CaptureSession::GetFlashMode(FlashMode& flashMode)
{
    flashMode = FLASH_MODE_CLOSE;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetFlashMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetFlashMode camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_FLASH_MODE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetFlashMode Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    auto itr = metaFlashModeMap_.find(static_cast<camera_flash_mode_enum_t>(item.data.u8[0]));
    if (itr != metaFlashModeMap_.end()) {
        flashMode = itr->second;
        return CameraErrorCode::SUCCESS;
    }

    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetFlashMode(FlashMode flashMode)
{
    CAMERA_SYNC_TRACE;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetFlashMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::SetFlashMode Need to call LockForControl() before setting camera properties");
        return CameraErrorCode::SUCCESS;
    }
    uint8_t flash = fwkFlashModeMap_.at(FLASH_MODE_CLOSE);
    auto itr = fwkFlashModeMap_.find(flashMode);
    if (itr == fwkFlashModeMap_.end()) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureMode Unknown exposure mode");
    } else {
        flash = itr->second;
    }

    bool status = false;
    uint32_t count = 1;
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_FLASH_MODE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_FLASH_MODE, &flash, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_FLASH_MODE, &flash, count);
    }

    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::SetFlashMode Failed to set flash mode");
        return CameraErrorCode::SUCCESS;
    }
    return CameraErrorCode::SUCCESS;
}

bool CaptureSession::IsFlashModeSupported(FlashMode flashMode)
{
    std::vector<FlashMode> vecSupportedFlashModeList;
    vecSupportedFlashModeList = this->GetSupportedFlashModes();
    if (find(vecSupportedFlashModeList.begin(), vecSupportedFlashModeList.end(), flashMode) !=
        vecSupportedFlashModeList.end()) {
        return true;
    }

    return false;
}

int32_t CaptureSession::IsFlashModeSupported(FlashMode flashMode, bool& isSupported)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::IsFlashModeSupported Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
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
    std::vector<FlashMode> vecSupportedFlashModeList;
    vecSupportedFlashModeList = this->GetSupportedFlashModes();
    if (vecSupportedFlashModeList.empty()) {
        return false;
    }
    return true;
}

int32_t CaptureSession::HasFlash(bool& hasFlash)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::HasFlash Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    std::vector<FlashMode> vecSupportedFlashModeList;
    vecSupportedFlashModeList = this->GetSupportedFlashModes();
    if (vecSupportedFlashModeList.empty()) {
        hasFlash = false;
        return CameraErrorCode::SUCCESS;
    }
    hasFlash = true;
    return CameraErrorCode::SUCCESS;
}

std::vector<float> CaptureSession::GetZoomRatioRange()
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetZoomRatioRange Session is not Commited");
        return {};
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetZoomRatioRange camera device is null");
        return {};
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_SCENE_ZOOM_CAP, &item);
    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG(
            "CaptureSession::GetZoomRatio Failed with return code %{public}d,item.count = %{public}d", ret, item.count);
        return {};
    }
    const uint32_t step = 3;
    uint32_t minIndex = 1;
    uint32_t maxIndex = 2;
    constexpr float factor = 100.0;
    float minZoom = 0.0;
    float maxZoom = 0.0;
    for (uint32_t i = 0; i < item.count; i += step) {
        MEDIA_INFO_LOG("Scene zoom cap mode: %{public}d, min: %{public}d, max: %{public}d", item.data.i32[i],
            item.data.i32[i + minIndex], item.data.i32[i + maxIndex]);
        if (GetFeaturesMode().GetFeaturedMode() == item.data.i32[i]) {
            minZoom = item.data.i32[i + minIndex] / factor;
            maxZoom = item.data.i32[i + maxIndex] / factor;
            break;
        }
    }
    return { minZoom, maxZoom };
}

int32_t CaptureSession::GetZoomRatioRange(std::vector<float>& zoomRatioRange)
{
    MEDIA_INFO_LOG("CaptureSession::GetZoomRatioRange is Called");
    zoomRatioRange.clear();
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetZoomRatioRange Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetZoomRatioRange camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_SCENE_ZOOM_CAP, &item);
    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG(
            "CaptureSession::GetZoomRatio Failed with return code %{public}d,item.count = %{public}d", ret, item.count);
        return 0;
    }
    const uint32_t step = 3;
    uint32_t minIndex = 1;
    uint32_t maxIndex = 2;
    constexpr float factor = 100.0;
    float minZoom = 0.0;
    float maxZoom = 0.0;
    for (uint32_t i = 0; i < item.count; i += step) {
        MEDIA_INFO_LOG("Scene zoom cap mode: %{public}d, min: %{public}d, max: %{public}d", item.data.i32[i],
            item.data.i32[i + minIndex], item.data.i32[i + maxIndex]);
        if (GetFeaturesMode().GetFeaturedMode() == item.data.i32[i]) {
            minZoom = item.data.i32[i + minIndex] / factor;
            maxZoom = item.data.i32[i + maxIndex] / factor;
            break;
        }
    }
    std::vector<float> range = { minZoom, maxZoom };
    zoomRatioRange = range;
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
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetZoomRatio Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetZoomRatio camera device is null");
        return CameraErrorCode::SUCCESS;
    }
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
    int32_t ret = ((sptr<CameraInput>&)inputDevice_)->GetCameraDevice()->GetStatus(metaIn, metaOut);
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("CaptureSession::GetZoomRatio Failed to Get ZoomRatio, errCode = %{public}d", ret);
        return ServiceToCameraError(ret);
    }
    camera_metadata_item_t item;
    ret = Camera::FindCameraMetadataItem(metaOut->get(), OHOS_STATUS_CAMERA_CURRENT_ZOOM_RATIO, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetZoomRatio Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    zoomRatio = static_cast<float>(item.data.ui32[0]) / static_cast<float>(zoomRatioMultiple);
    MEDIA_ERR_LOG("CaptureSession::GetZoomRatio %{public}f", zoomRatio);
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetZoomRatio(float zoomRatio)
{
    CAMERA_SYNC_TRACE;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetZoomRatio Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::SetZoomRatio Need to call LockForControl() before setting camera properties");
        return CameraErrorCode::SUCCESS;
    }
    bool status = false;
    int32_t ret;
    int32_t minIndex = 0;
    int32_t maxIndex = 1;
    int32_t count = 1;
    camera_metadata_item_t item;
    MEDIA_DEBUG_LOG("CaptureSession::SetZoomRatio Zoom ratio: %{public}f", zoomRatio);
    std::vector<float> zoomRange = GetZoomRatioRange();
    if (zoomRange.empty()) {
        MEDIA_ERR_LOG("CaptureSession::SetZoomRatio Zoom range is empty");
        return CameraErrorCode::SUCCESS;
    }
    if (zoomRatio < zoomRange[minIndex]) {
        MEDIA_DEBUG_LOG("CaptureSession::SetZoomRatio Zoom ratio: %{public}f is lesser than minimum zoom: %{public}f",
            zoomRatio, zoomRange[minIndex]);
        zoomRatio = zoomRange[minIndex];
    } else if (zoomRatio > zoomRange[maxIndex]) {
        MEDIA_DEBUG_LOG("CaptureSession::SetZoomRatio Zoom ratio: %{public}f is greater than maximum zoom: %{public}f",
            zoomRatio, zoomRange[maxIndex]);
        zoomRatio = zoomRange[maxIndex];
    }

    if (zoomRatio == 0) {
        MEDIA_ERR_LOG("CaptureSession::SetZoomRatio Invalid zoom ratio");
        return CameraErrorCode::SUCCESS;
    }

    ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_ZOOM_RATIO, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_ZOOM_RATIO, &zoomRatio, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_ZOOM_RATIO, &zoomRatio, count);
    }

    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::SetZoomRatio Failed to set zoom mode");
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::PrepareZoom()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("CaptureSession::PrepareZoom");
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("CaptureSession::PrepareZoom Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::PrepareZoom Need to call LockForControl() before setting camera properties");
        return CameraErrorCode::SUCCESS;
    }
    bool status = false;
    int32_t ret;
    uint32_t count = 1;
    uint32_t prepareZoomType = OHOS_CAMERA_ZOOMSMOOTH_PREPARE_ENABLE;
    camera_metadata_item_t item;
    ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_PREPARE_ZOOM, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_PREPARE_ZOOM, &prepareZoomType, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_PREPARE_ZOOM, &prepareZoomType, count);
    }
    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::SetSmoothZoom CaptureSession::PrepareZoom Failed to prepare zoom");
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::UnPrepareZoom()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("CaptureSession::UnPrepareZoom");
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("CaptureSession::UnPrepareZoom Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::UnPrepareZoom Need to call LockForControl() before setting camera properties");
        return CameraErrorCode::SUCCESS;
    }
    bool status = false;
    int32_t ret;
    uint32_t count = 1;
    uint32_t prepareZoomType = OHOS_CAMERA_ZOOMSMOOTH_PREPARE_DISABLE;
    camera_metadata_item_t item;

    ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_PREPARE_ZOOM, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_PREPARE_ZOOM, &prepareZoomType, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_PREPARE_ZOOM, &prepareZoomType, count);
    }

    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::UnPrepareZoom Failed to unPrepare zoom");
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetSmoothZoom(float targetZoomRatio, uint32_t smoothZoomType)
{
    CAMERA_SYNC_TRACE;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetSmoothZoom Session is not commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    int32_t minIndex = 0;
    int32_t maxIndex = 1;
    std::vector<float> zoomRange = GetZoomRatioRange();
    if (zoomRange.empty()) {
        MEDIA_ERR_LOG("CaptureSession::SetSmoothZoom Zoom range is empty");
        return CameraErrorCode::SUCCESS;
    }
    if (targetZoomRatio < zoomRange[minIndex]) {
        MEDIA_DEBUG_LOG("CaptureSession::SetSmoothZoom Zoom ratio: %{public}f is lesser than minimum zoom: %{public}f",
            targetZoomRatio, zoomRange[minIndex]);
        targetZoomRatio = zoomRange[minIndex];
    } else if (targetZoomRatio > zoomRange[maxIndex]) {
        MEDIA_DEBUG_LOG("CaptureSession::SetSmoothZoom Zoom ratio: %{public}f is greater than maximum zoom: %{public}f",
            targetZoomRatio, zoomRange[maxIndex]);
        targetZoomRatio = zoomRange[maxIndex];
    }

    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    float duration;
    if (captureSession_) {
        errCode = captureSession_->SetSmoothZoom(smoothZoomType, GetMode(), targetZoomRatio, duration);
        MEDIA_DEBUG_LOG("CaptureSession::SetSmoothZoom duration: %{public}f ", duration);
        if (errCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to SetSmoothZoom!, %{public}d", errCode);
        } else {
            std::shared_ptr<OHOS::Camera::CameraMetadata> changedMetadata =
                std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
            changedMetadata->addEntry(OHOS_CONTROL_SMOOTH_ZOOM_RATIOS, &targetZoomRatio, 1);
            OnSettingUpdated(changedMetadata);
        }
        std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
        if (smoothZoomCallback_ != nullptr) {
            smoothZoomCallback_->OnSmoothZoom(duration);
        }
    } else {
        MEDIA_ERR_LOG("CaptureSession::SetSmoothZoom() captureSession_ is nullptr");
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

int32_t CaptureSession::GetZoomPointInfos(std::vector<ZoomPointInfo>& zoomPointInfoList)
{
    MEDIA_INFO_LOG("CaptureSession::GetZoomPointInfos is Called");
    zoomPointInfoList.clear();
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetZoomPointInfos Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetZoomPointInfos camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_EQUIVALENT_FOCUS, &item);
    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG(
            "CaptureSession::GetZoomPointInfos Failed with return code:%{public}d, item.count:%{public}d",
            ret, item.count);
        return CameraErrorCode::SUCCESS;
    }
    SceneMode mode = GetMode();
    int32_t defaultLen = 0;
    int32_t modeLen = 0;
    MEDIA_INFO_LOG("CaptureSession::GetZoomPointInfos mode:%{public}d", mode);
    for (uint32_t i = 0; i < item.count; i++) {
        if ((i & 1) == 0) {
            MEDIA_DEBUG_LOG("CaptureSession::GetZoomPointInfos mode:%{public}d, equivalentFocus:%{public}d",
                item.data.i32[i], item.data.i32[i + 1]);
            if (SceneMode::NORMAL == item.data.i32[i]) {
                defaultLen = item.data.i32[i + 1];
            }
            if (mode == item.data.i32[i]) {
                modeLen = item.data.i32[i + 1];
            }
        }
    }
    // only return 1x zoomPointInfo
    ZoomPointInfo zoomPointInfo;
    zoomPointInfo.zoomRatio = DEFAULT_EQUIVALENT_ZOOM;
    zoomPointInfo.equivalentFocalLength = (modeLen != 0) ? modeLen : defaultLen;
    zoomPointInfoList.emplace_back(zoomPointInfo);
    return CameraErrorCode::SUCCESS;
}

void CaptureSession::SetCaptureMetadataObjectTypes(std::set<camera_face_detect_mode_t> metadataObjectTypes)
{
    MEDIA_INFO_LOG("CaptureSession SetCaptureMetadataObjectTypes Enter");
    if (inputDevice_ == nullptr) {
        MEDIA_ERR_LOG("SetCaptureMetadataObjectTypes: inputDevice is null");
        return;
    }
    uint32_t count = 1;
    uint8_t objectType = OHOS_CAMERA_FACE_DETECT_MODE_SIMPLE;
    if (!metadataObjectTypes.count(OHOS_CAMERA_FACE_DETECT_MODE_SIMPLE)) {
        objectType = OHOS_CAMERA_FACE_DETECT_MODE_OFF;
        MEDIA_ERR_LOG("CaptureSession SetCaptureMetadataObjectTypes Can not set face detect mode!");
    }
    this->LockForControl();
    if (!this->changedMetadata_->addEntry(OHOS_STATISTICS_FACE_DETECT_SWITCH, &objectType, count)) {
        MEDIA_ERR_LOG("SetCaptureMetadataObjectTypes: Failed to add detect object types to changed metadata");
    }
    this->UnlockForControl();
}

void CaptureSession::SetGuessMode(SceneMode mode)
{
    if (currentMode_ != SceneMode::NORMAL) {
        return;
    }
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
    if (IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetMode Session has been Commited");
        return;
    }
    currentMode_ = modeName;
    // reset deferred enable status when reset mode
    EnableDeferredType(DELIVERY_NONE);
    if (captureSession_) {
        captureSession_->SetFeatureMode(modeName);
        MEDIA_INFO_LOG("CaptureSession::SetSceneMode  SceneMode = %{public}d", modeName);
    }
    MEDIA_INFO_LOG("CaptureSession SetMode modeName = %{public}d", modeName);
}

SceneMode CaptureSession::GetMode()
{
    MEDIA_INFO_LOG(
        "CaptureSession GetMode currentMode_ = %{public}d, guestMode_ = %{public}d", currentMode_, guessMode_);
    if (inputDevice_ && inputDevice_->GetCameraDeviceInfo() &&
        inputDevice_->GetCameraDeviceInfo()->GetConnectionType() == ConnectionType::CAMERA_CONNECTION_REMOTE) {
        MEDIA_INFO_LOG("The current camera device connection mode is remote connection.");
        return currentMode_;
    }
    if (currentMode_ == SceneMode::NORMAL) {
        return guessMode_;
    }
    return currentMode_;
}

bool CaptureSession::IsImageDeferred()
{
    MEDIA_INFO_LOG("CaptureSession IsImageDeferred");
    return isImageDeferred_;
}

SceneFeaturesMode CaptureSession::GetFeaturesMode()
{
    SceneFeaturesMode sceneFeaturesMode;
    sceneFeaturesMode.SetSceneMode(GetMode());
    sceneFeaturesMode.SwitchFeature(FEATURE_MACRO, isSetMacroEnable_);
    sceneFeaturesMode.SwitchFeature(FEATURE_MOON_CAPTURE_BOOST, isSetMoonCaptureBoostEnable_);
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
    }
    return sceneFeaturesModes;
}

int32_t CaptureSession::VerifyAbility(uint32_t ability)
{
    int32_t portraitMode = 3;
    if (GetMode() != portraitMode) {
        MEDIA_ERR_LOG("CaptureSession::VerifyAbility need PortraitMode");
        return CAMERA_INVALID_ARG;
    };
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::VerifyAbility camera device is null");
        return CAMERA_INVALID_ARG;
    }

    ProcessProfilesAbilityId(portraitMode);

    std::vector<uint32_t> photoAbilityId = previewProfile_.GetAbilityId();
    std::vector<uint32_t> previewAbilityId = previewProfile_.GetAbilityId();

    auto itrPhoto = std::find(photoAbilityId.begin(), photoAbilityId.end(), ability);
    auto itrPreview = std::find(previewAbilityId.begin(), previewAbilityId.end(), ability);
    if (itrPhoto == photoAbilityId.end() || itrPreview == previewAbilityId.end()) {
        MEDIA_ERR_LOG("CaptureSession::VerifyAbility abilityId is NULL");
        return CAMERA_INVALID_ARG;
    }
    return CAMERA_OK;
}

void CaptureSession::ProcessProfilesAbilityId(const int32_t portraitMode)
{
    std::vector<Profile> photoProfiles = inputDevice_->GetCameraDeviceInfo()->modePhotoProfiles_[portraitMode];
    std::vector<Profile> previewProfiles = inputDevice_->GetCameraDeviceInfo()->modePreviewProfiles_[portraitMode];
    for (auto i : photoProfiles) {
        std::string abilityIds = "";
        for (auto id : i.GetAbilityId()) {
            abilityIds += std::to_string(id) + ",";
        }
        MEDIA_INFO_LOG("photoProfiles f(%{public}d), w(%{public}d), h(%{public}d), ability:(%{public}s)",
            i.GetCameraFormat(), i.GetSize().width, i.GetSize().height, abilityIds.c_str());
        if (i.GetCameraFormat() == photoProfile_.GetCameraFormat() &&
            i.GetSize().width == photoProfile_.GetSize().width &&
            i.GetSize().height == photoProfile_.GetSize().height) {
            if (i.GetAbilityId().empty()) {
                MEDIA_INFO_LOG("VerifyAbility::CreatePhotoOutput:: this size'abilityId is not exist");
            }
            photoProfile_.abilityId_ = i.GetAbilityId();
            break;
        }
    }
    for (auto i : previewProfiles) {
        std::string abilityIds = "";
        for (auto id : i.GetAbilityId()) {
            abilityIds += std::to_string(id) + ",";
        }
        MEDIA_INFO_LOG("previewProfiles f(%{public}d), w(%{public}d), h(%{public}d), ability:(%{public}s)",
            i.GetCameraFormat(), i.GetSize().width, i.GetSize().height, abilityIds.c_str());
        if (i.GetCameraFormat() == previewProfile_.GetCameraFormat() &&
            i.GetSize().width == previewProfile_.GetSize().width &&
            i.GetSize().height == previewProfile_.GetSize().height) {
            if (i.GetAbilityId().empty()) {
                MEDIA_INFO_LOG("VerifyAbility::CreatePreviewOutput:: this size'abilityId is not exist");
            }
            previewProfile_.abilityId_ = i.GetAbilityId();
            break;
        }
    }
}

std::vector<FilterType> CaptureSession::GetSupportedFilters()
{
    std::vector<FilterType> supportedFilters = {};
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedFilters Session is not Commited");
        return supportedFilters;
    }

    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedFilters camera device is null");
        return supportedFilters;
    }

    int ret = VerifyAbility(static_cast<uint32_t>(OHOS_ABILITY_SCENE_FILTER_TYPES));
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedFilters abilityId is NULL");
        return supportedFilters;
    }

    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    camera_metadata_item_t item;
    ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_SCENE_FILTER_TYPES, &item);
    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedFilters Failed with return code %{public}d", ret);
        return supportedFilters;
    }
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
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("CaptureSession::GetFilter Session is not Commited");
        return FilterType::NONE;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetFilter camera device is null");
        return FilterType::NONE;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_FILTER_TYPE, &item);
    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG("CaptureSession::GetFilter Failed with return code %{public}d", ret);
        return FilterType::NONE;
    }
    auto itr = metaFilterTypeMap_.find(static_cast<camera_filter_type_t>(item.data.u8[0]));
    if (itr != metaFilterTypeMap_.end()) {
        return itr->second;
    }
    return FilterType::NONE;
}

void CaptureSession::SetFilter(FilterType filterType)
{
    CAMERA_SYNC_TRACE;
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("CaptureSession::SetFilter Session is not Commited");
        return;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::SetFilter Need to call LockForControl() before setting camera properties");
        return;
    }

    std::vector<FilterType> supportedFilters = GetSupportedFilters();
    auto itr = std::find(supportedFilters.begin(), supportedFilters.end(), filterType);
    if (itr == supportedFilters.end()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedFilters abilityId is NULL");
        return;
    }
    uint8_t filter = 0;
    for (auto itr2 = fwkFilterTypeMap_.cbegin(); itr2 != fwkFilterTypeMap_.cend(); itr2++) {
        if (filterType == itr2->first) {
            filter = static_cast<uint8_t>(itr2->second);
            break;
        }
    }
    bool status = false;
    int32_t ret;
    uint32_t count = 1;
    camera_metadata_item_t item;

    MEDIA_DEBUG_LOG("CaptureSession::setFilter: %{public}d", filterType);

    ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_FILTER_TYPE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_FILTER_TYPE, &filter, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_FILTER_TYPE, &filter, count);
    }

    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::setFilter Failed to set filter");
    }
    return;
}

std::vector<BeautyType> CaptureSession::GetSupportedBeautyTypes()
{
    std::vector<BeautyType> supportedBeautyTypes = {};
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedBeautyTypes Session is not Commited");
        return supportedBeautyTypes;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedBeautyTypes camera device is null");
        return supportedBeautyTypes;
    }

    int ret = VerifyAbility(static_cast<uint32_t>(OHOS_ABILITY_SCENE_BEAUTY_TYPES));
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedBeautyTypes abilityId is NULL");
        return supportedBeautyTypes;
    }

    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    camera_metadata_item_t item;
    ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_SCENE_BEAUTY_TYPES, &item);
    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedBeautyTypes Failed with return code %{public}d", ret);
        return supportedBeautyTypes;
    }
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = metaBeautyTypeMap_.find(static_cast<camera_beauty_type_t>(item.data.u8[i]));
        if (itr != metaBeautyTypeMap_.end()) {
            supportedBeautyTypes.emplace_back(itr->second);
        }
    }
    return supportedBeautyTypes;
}

std::vector<int32_t> CaptureSession::GetSupportedBeautyRange(BeautyType beautyType)
{
    int ret = 0;
    std::vector<int32_t> supportedBeautyRange;
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedBeautyRange Session is not Commited");
        return supportedBeautyRange;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedBeautyRange camera device is null");
        return supportedBeautyRange;
    }

    std::vector<BeautyType> supportedBeautyTypes = GetSupportedBeautyTypes();
    if (std::find(supportedBeautyTypes.begin(), supportedBeautyTypes.end(), beautyType) == supportedBeautyTypes.end()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedBeautyRange beautyType is NULL");
        return supportedBeautyRange;
    }

    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    camera_metadata_item_t item;

    MEDIA_ERR_LOG("CaptureSession::GetSupportedBeautyRange: %{public}d", beautyType);

    int32_t beautyTypeAbility;
    auto itr = fwkBeautyAbilityMap_.find(beautyType);
    if (itr == fwkBeautyAbilityMap_.end()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedBeautyRange Unknown beauty Type");
        return supportedBeautyRange;
    } else {
        beautyTypeAbility = itr->second;
        Camera::FindCameraMetadataItem(metadata->get(), beautyTypeAbility, &item);
    }

    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedBeautyRange Failed with return code %{public}d", ret);
        return supportedBeautyRange;
    }
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
    bool status = false;
    int32_t ret;
    uint32_t count = 1;
    camera_metadata_item_t item;
    camera_device_metadata_tag_t metadata;

    for (auto metaItr = fwkBeautyControlMap_.cbegin(); metaItr != fwkBeautyControlMap_.cend(); metaItr++) {
        if (beautyType == metaItr->first) {
            metadata = metaItr->second;
            break;
        }
    }

    std::vector<int32_t> levelVec;
    if (beautyTypeAndRanges_.count(beautyType)) {
        levelVec = beautyTypeAndRanges_[beautyType];
    } else {
        levelVec = GetSupportedBeautyRange(beautyType);
    }

    auto itrType = std::find(levelVec.cbegin(), levelVec.cend(), beautyLevel);
    if (itrType == levelVec.end()) {
        MEDIA_ERR_LOG("CaptureSession::SetBeautyValue: %{public}d not in beautyRanges", beautyLevel);
        return status;
    }
    if (beautyType == BeautyType::SKIN_TONE) {
        int32_t skinToneVal = beautyLevel;
        ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), metadata, &item);
        if (ret == CAM_META_ITEM_NOT_FOUND) {
            status = changedMetadata_->addEntry(metadata, &skinToneVal, count);
        } else if (ret == CAM_META_SUCCESS) {
            status = changedMetadata_->updateEntry(metadata, &skinToneVal, count);
        }
    } else {
        uint8_t beautyVal = static_cast<uint8_t>(beautyLevel);
        ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), metadata, &item);
        if (ret == CAM_META_ITEM_NOT_FOUND) {
            status = changedMetadata_->addEntry(metadata, &beautyVal, count);
        } else if (ret == CAM_META_SUCCESS) {
            status = changedMetadata_->updateEntry(metadata, &beautyVal, count);
        }
    }
    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::SetBeautyValue Failed to set beauty");
        return status;
    }
    beautyTypeAndLevels_[beautyType] = beautyLevel;
    return status;
}

void CaptureSession::SetBeauty(BeautyType beautyType, int value)
{
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("CaptureSession::SetBeauty Session is not Commited");
        return;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::SetBeauty changedMetadata_ is NULL");
        return;
    }

    std::vector<BeautyType> supportedBeautyTypes = GetSupportedBeautyTypes();
    auto itr = std::find(supportedBeautyTypes.begin(), supportedBeautyTypes.end(), beautyType);
    if (itr == supportedBeautyTypes.end()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedBeautyTypes abilityId is NULL");
        return;
    }
    MEDIA_ERR_LOG("SetBeauty beautyType %{public}d", beautyType);
    bool status = false;
    uint32_t count = 1;
    camera_metadata_item_t item;
    uint8_t beauty = OHOS_CAMERA_BEAUTY_TYPE_OFF;
    int32_t ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_BEAUTY_TYPE, &item);
    if ((beautyType == AUTO_TYPE) && (value == 0)) {
        if (ret == CAM_META_ITEM_NOT_FOUND) {
            status = changedMetadata_->addEntry(OHOS_CONTROL_BEAUTY_TYPE, &beauty, count);
        } else if (ret == CAM_META_SUCCESS) {
            status = changedMetadata_->updateEntry(OHOS_CONTROL_BEAUTY_TYPE, &beauty, count);
        }
        status = SetBeautyValue(beautyType, value);
        if (!status) {
            MEDIA_ERR_LOG("CaptureSession::SetBeauty AUTO_TYPE Failed to set beauty value");
        }
        return;
    }

    for (auto itrType = fwkBeautyTypeMap_.cbegin(); itrType != fwkBeautyTypeMap_.cend(); itrType++) {
        if (beautyType == itrType->first) {
            beauty = static_cast<uint8_t>(itrType->second);
            break;
        }
    }
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_BEAUTY_TYPE, &beauty, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_BEAUTY_TYPE, &beauty, count);
    }
    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::SetBeauty Failed to set beautyType control");
    }

    status = SetBeautyValue(beautyType, value);
    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::SetBeauty Failed to set beauty value");
    }
    return;
}

int32_t CaptureSession::GetBeauty(BeautyType beautyType)
{
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("CaptureSession::GetBeauty Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetBeauty camera device is null");
        return -1;
    }
    int32_t beautyLevel = 0;
    std::vector<BeautyType> supportedBeautyTypes = GetSupportedBeautyTypes();
    auto itr = std::find(supportedBeautyTypes.begin(), supportedBeautyTypes.end(), beautyType);
    if (itr == supportedBeautyTypes.end()) {
        MEDIA_ERR_LOG("CaptureSession::GetBeauty beautyType is NULL");
        return -1;
    }

    for (auto itrLevel = beautyTypeAndLevels_.cbegin(); itrLevel != beautyTypeAndLevels_.cend(); itrLevel++) {
        if (beautyType == itrLevel->first) {
            beautyLevel = itrLevel->second;
            break;
        }
    }
    return beautyLevel;
}

// focus distance
float CaptureSession::GetMinimumFocusDistance()
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetMinimumFocusDistance Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetMinimumFocusDistance camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int32_t ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_LENS_INFO_MINIMUM_FOCUS_DISTANCE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetMinimumFocusDistance Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    float minimumFocusDistance = item.data.f[0];
    MEDIA_DEBUG_LOG("CaptureSession::GetMinimumFocusDistance minimumFocusDistance=%{public}f", minimumFocusDistance);
    return minimumFocusDistance;
}

int32_t CaptureSession::GetFocusDistance(float& focusDistance)
{
    focusDistance = 0.0;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusDistance Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusDistance camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int32_t ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_LENS_FOCUS_DISTANCE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusDistance Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    MEDIA_DEBUG_LOG("CaptureSession::GetFocusDistance meta=%{public}f", item.data.f[0]);
    if (FloatIsEqual(GetMinimumFocusDistance(), 0.0)) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusDistance minimum distance is 0");
        return CameraErrorCode::SUCCESS;
    }
    focusDistance = 1.0 - (item.data.f[0] / GetMinimumFocusDistance());
    MEDIA_DEBUG_LOG("CaptureSession::GetFocusDistance focusDistance = %{public}f", focusDistance);
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetFocusDistance(float focusDistance)
{
    CAMERA_SYNC_TRACE;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetFocusDistance Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::SetFocusDistance Need to call LockForControl "
                      "before setting camera properties");
        return CameraErrorCode::SUCCESS;
    }
    bool status = false;
    uint32_t count = 1;
    int32_t ret;
    MEDIA_DEBUG_LOG("CaptureSession::GetFocusDistance app set focusDistance = %{public}f", focusDistance);
    camera_metadata_item_t item;
    if (focusDistance < 0) {
        focusDistance = 0.0;
    } else if (focusDistance > 1) {
        focusDistance = 1.0;
    }
    float value = (1 - focusDistance) * GetMinimumFocusDistance();
    MEDIA_DEBUG_LOG("CaptureSession::GetFocusDistance meta set focusDistance = %{public}f", value);
    ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_LENS_FOCUS_DISTANCE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_LENS_FOCUS_DISTANCE, &value, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_LENS_FOCUS_DISTANCE, &value, count);
    }
    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::SetFocusDistance Failed to set");
    }
    return CameraErrorCode::SUCCESS;
}

void CaptureSession::SetFrameRateRange(const std::vector<int32_t>& frameRateRange)
{
    std::vector<int32_t> videoFrameRateRange = frameRateRange;
    this->LockForControl();
    bool isSuccess = this->changedMetadata_->addEntry(
        OHOS_CONTROL_FPS_RANGES, videoFrameRateRange.data(), videoFrameRateRange.size());
    if (!isSuccess) {
        MEDIA_ERR_LOG("Failed to SetFrameRateRange");
    }
    for (size_t i = 0; i < frameRateRange.size(); i++) {
        MEDIA_DEBUG_LOG("CaptureSession::SetFrameRateRange:index:%{public}zu->%{public}d", i, frameRateRange[i]);
    }
    this->UnlockForControl();
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
        if (static_cast<CaptureOutput*>(item.GetRefPtr()) == curOutput) {
            continue;
        }
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
        if (currentFrameRange[minFpsIndex] != defaultFpsNumber &&
            currentFrameRange[maxFpsIndex] != defaultFpsNumber) {
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
    if (captureSession_) {
        CaptureSessionState currentState;
        captureSession_->GetSessionState(currentState);
        isSessionConfiged = (currentState == CaptureSessionState::SESSION_CONFIG_INPROGRESS);
    }
    return isSessionConfiged;
}

bool CaptureSession::IsSessionCommited()
{
    bool isCommitConfig = false;
    if (captureSession_) {
        CaptureSessionState currentState;
        captureSession_->GetSessionState(currentState);
        isCommitConfig = (currentState == CaptureSessionState::SESSION_CONFIG_COMMITTED);
    }
    return isCommitConfig;
}

int32_t CaptureSession::CalculateExposureValue(float exposureValue)
{
    camera_metadata_item_t item;
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_AE_COMPENSATION_STEP, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::Get Ae Compensation step Failed with return code %{public}d", ret);
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }

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
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedColorSpaceInfo Session is not Commited");
        return colorSpaceInfo;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedColorSpaceInfo camera device is null");
        return colorSpaceInfo;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_AVAILABLE_COLOR_SPACES, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedColorSpaceInfo Failed, return code %{public}d", ret);
        return colorSpaceInfo;
    }

    std::shared_ptr<ColorSpaceInfoParse> colorSpaceParse = std::make_shared<ColorSpaceInfoParse>();
    colorSpaceParse->getColorSpaceInfo(item.data.i32, item.count, colorSpaceInfo); // 解析tag中带的色彩空间信息
    return colorSpaceInfo;
}

std::vector<ColorSpace> CaptureSession::GetSupportedColorSpaces()
{
    std::vector<ColorSpace> supportedColorSpaces = {};
    ColorSpaceInfo colorSpaceInfo = GetSupportedColorSpaceInfo();
    if (colorSpaceInfo.modeCount == 0) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedColorSpaces Failed, colorSpaceInfo is null");
        return supportedColorSpaces;
    }

    for (uint32_t i = 0; i < colorSpaceInfo.modeCount; i++) {
        if (GetMode() != colorSpaceInfo.modeInfo[i].modeType) {
            continue;
        }
        MEDIA_DEBUG_LOG("CaptureSession::GetSupportedColorSpaces modeType %{public}d found.", GetMode());
        std::vector<int32_t> colorSpaces = colorSpaceInfo.modeInfo[i].streamInfo[0].colorSpaces;
        supportedColorSpaces.reserve(colorSpaces.size());
        for (uint32_t j = 0; j < colorSpaces.size(); j++) {
            auto itr = g_metaColorSpaceMap_.find(static_cast<CM_ColorSpaceType>(colorSpaces[j]));
            if (itr != g_metaColorSpaceMap_.end()) {
                supportedColorSpaces.emplace_back(itr->second);
            }
        }
        return supportedColorSpaces;
    }
    MEDIA_ERR_LOG("CaptureSession::GetSupportedColorSpaces no colorSpaces info for mode %{public}d", GetMode());
    return supportedColorSpaces;
}

int32_t CaptureSession::GetActiveColorSpace(ColorSpace& colorSpace)
{
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("CaptureSession::GetActiveColorSpace Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }

    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (captureSession_) {
        errCode = captureSession_->GetActiveColorSpace(colorSpace);
        if (errCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to GetActiveColorSpace! %{public}d", errCode);
        } else {
            MEDIA_INFO_LOG("CaptureSession::GetActiveColorSpace %{public}d", static_cast<int32_t>(colorSpace));
        }
    } else {
        MEDIA_ERR_LOG("CaptureSession::GetActiveColorSpace() captureSession_ is nullptr");
    }
    return ServiceToCameraError(errCode);
}

int32_t CaptureSession::SetColorSpace(ColorSpace colorSpace)
{
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("CaptureSession::SetColorSpace Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }

    if (!captureSession_) {
        MEDIA_ERR_LOG("CaptureSession::SetColorSpace() captureSession_ is nullptr");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }

    CM_ColorSpaceType metaColorSpace;
    auto itr = g_fwkColorSpaceMap_.find(colorSpace);
    if (itr != g_fwkColorSpaceMap_.end()) {
        metaColorSpace = itr->second;
    } else {
        MEDIA_ERR_LOG("CaptureSession::SetColorSpace() map failed, %{public}d", static_cast<int32_t>(colorSpace));
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    CM_ColorSpaceType captureColorSpace = metaColorSpace;
    ColorSpaceInfo colorSpaceInfo = GetSupportedColorSpaceInfo();

    ColorSpace fwkCaptureColorSpace;
    auto it = g_metaColorSpaceMap_.find(captureColorSpace);
    if (it != g_metaColorSpaceMap_.end()) {
        fwkCaptureColorSpace = it->second;
    } else {
        MEDIA_ERR_LOG("CaptureSession::SetColorSpace, %{public}d map failed", static_cast<int32_t>(captureColorSpace));
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    if (ProcessCaptureColorSpace(colorSpaceInfo, fwkCaptureColorSpace) != CameraErrorCode::SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::SetDefaultColorSpace() is failed.");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    if (IsSessionConfiged()) {
        isColorSpaceSetted_ = true;
    }
    // 若session还未commit，则后续createStreams会把色域带下去；否则，SetColorSpace要走updateStreams
    MEDIA_DEBUG_LOG("CaptureSession::SetColorSpace, IsSessionCommited %{public}d", IsSessionCommited());
    int32_t errCode = captureSession_->SetColorSpace(colorSpace, fwkCaptureColorSpace, IsSessionCommited());
    if (errCode != CAMERA_OK) {
        MEDIA_ERR_LOG("Failed to SetColorSpace!, %{public}d", errCode);
    }
    return ServiceToCameraError(errCode);
}

int32_t CaptureSession::ProcessCaptureColorSpace(ColorSpaceInfo colorSpaceInfo, ColorSpace& fwkCaptureColorSpace)
{
    CM_ColorSpaceType metaColorSpace;
    CM_ColorSpaceType captureColorSpace;
    for (uint32_t i = 0; i < colorSpaceInfo.modeCount; i++) {
        if (GetMode() != colorSpaceInfo.modeInfo[i].modeType) {
            continue;
        }

        auto it = g_fwkColorSpaceMap_.find(fwkCaptureColorSpace);
        if (it != g_fwkColorSpaceMap_.end()) {
            metaColorSpace = it->second;
        } else {
            MEDIA_ERR_LOG("CaptureSession::SetColorSpace, %{public}d map failed",
                static_cast<int32_t>(fwkCaptureColorSpace));
            return CameraErrorCode::INVALID_ARGUMENT;
        }

        MEDIA_DEBUG_LOG("CaptureSession::SetColorSpace mode %{public}d, color %{public}d.", GetMode(), metaColorSpace);
        std::vector<int32_t> supportedColorSpaces = colorSpaceInfo.modeInfo[i].streamInfo[0].colorSpaces;
        auto itColorSpace =
            std::find(supportedColorSpaces.begin(), supportedColorSpaces.end(), static_cast<int32_t>(metaColorSpace));
        if (itColorSpace == supportedColorSpaces.end()) {
            MEDIA_ERR_LOG("CaptureSession::SetColorSpace input not found in supportedList.");
            return CameraErrorCode::INVALID_ARGUMENT;
        }

        if (!IsModeWithVideoStream()) {
            break;
        }

        captureColorSpace = metaColorSpace;
        for (uint32_t j = 0; j < colorSpaceInfo.modeInfo[i].streamTypeCount; j++) {
            if (colorSpaceInfo.modeInfo[i].streamInfo[j].streamType == OutputCapStreamType::STILL_CAPTURE) {
                captureColorSpace =
                    static_cast<CM_ColorSpaceType>(colorSpaceInfo.modeInfo[i].streamInfo[j].colorSpaces[0]);
                MEDIA_DEBUG_LOG("CaptureSession::SetColorSpace captureColorSpace = %{public}d ", captureColorSpace);
                break;
            }
        }
        break;
    }

    auto it = g_metaColorSpaceMap_.find(captureColorSpace);
    if (it != g_metaColorSpaceMap_.end()) {
        fwkCaptureColorSpace = it->second;
    } else {
        MEDIA_ERR_LOG("CaptureSession::SetColorSpace, %{public}d map failed", static_cast<int32_t>(captureColorSpace));
        return CameraErrorCode::INVALID_ARGUMENT;
    }
    return CameraErrorCode::SUCCESS;
}

bool CaptureSession::IsModeWithVideoStream()
{
    return GetMode() == SceneMode::VIDEO;
}

std::vector<ColorEffect> CaptureSession::GetSupportedColorEffects()
{
    std::vector<ColorEffect> supportedColorEffects = {};
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedColorEffects Session is not Commited");
        return supportedColorEffects;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedColorEffects camera device is null");
        return supportedColorEffects;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_SUPPORTED_COLOR_MODES, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedColorEffects Failed with return code %{public}d", ret);
        return supportedColorEffects;
    }
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = metaColorEffectMap_.find(static_cast<camera_xmage_color_type_t>(item.data.u8[i]));
        if (itr != metaColorEffectMap_.end()) {
            supportedColorEffects.emplace_back(itr->second);
        }
    }
    return supportedColorEffects;
}

ColorEffect CaptureSession::GetColorEffect()
{
    ColorEffect colorEffect = ColorEffect::COLOR_EFFECT_NORMAL;
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("CaptureSession::GetColorEffect Session is not Commited");
        return colorEffect;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetColorEffect camera device is null");
        return colorEffect;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_SUPPORTED_COLOR_MODES, &item);
    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG("CaptureSession::GetColorEffect Failed with return code %{public}d", ret);
        return colorEffect;
    }
    auto itr = metaColorEffectMap_.find(static_cast<camera_xmage_color_type_t>(item.data.u8[0]));
    if (itr != metaColorEffectMap_.end()) {
        colorEffect = itr->second;
    }
    return colorEffect;
}

void CaptureSession::SetColorEffect(ColorEffect colorEffect)
{
    CAMERA_SYNC_TRACE;
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("CaptureSession::SetColorEffect Session is not Commited");
        return;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::SetColorEffect Need to call LockForControl() before setting camera properties");
        return;
    }
    uint8_t colorEffectTemp = ColorEffect::COLOR_EFFECT_NORMAL;
    auto itr = fwkColorEffectMap_.find(colorEffect);
    if (itr == fwkColorEffectMap_.end()) {
        MEDIA_ERR_LOG("CaptureSession::SetColorEffect unknown is color effect");
        return;
    } else {
        colorEffectTemp = itr->second;
    }

    bool status = false;
    int32_t ret;
    uint32_t count = 1;
    camera_metadata_item_t item;

    MEDIA_DEBUG_LOG("CaptureSession::SetColorEffect: %{public}d", colorEffect);

    ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_SUPPORTED_COLOR_MODES, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_SUPPORTED_COLOR_MODES, &colorEffectTemp, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_SUPPORTED_COLOR_MODES, &colorEffectTemp, count);
    }

    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::SetColorEffect Failed to set color effect");
    }
    return;
}

int32_t CaptureSession::GetSensorExposureTimeRange(std::vector<uint32_t> &sensorExposureTimeRange)
{
    sensorExposureTimeRange.clear();
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetSensorExposureTimeRange Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSensorExposureTimeRange camera device is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_SENSOR_EXPOSURE_TIME_RANGE, &item);
    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG("CaptureSession::GetSensorExposureTimeRange Failed with return code %{public}d", ret);
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    int32_t numerator = 0;
    int32_t denominator = 0;
    uint32_t value = 0;
    constexpr int32_t timeUnit = 1000000;
    for (uint32_t i = 0; i < item.count; i++) {
        numerator = item.data.r[i].numerator;
        denominator = item.data.r[i].denominator;
        if (denominator == 0) {
            MEDIA_ERR_LOG("CaptureSession::GetSensorExposureTimeRange divide by 0! numerator=%{public}d", numerator);
            return CameraErrorCode::INVALID_ARGUMENT;
        }
        value = numerator / (denominator / timeUnit);
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
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetSensorExposureTime Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::SetSensorExposureTime Need to call LockForControl() "
            "before setting camera properties");
        return CameraErrorCode::SUCCESS;
    }
    MEDIA_DEBUG_LOG("CaptureSession::SetSensorExposureTime exposure: %{public}d", exposureTime);
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::SetSensorExposureTime camera device is null");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }
    std::vector<uint32_t> sensorExposureTimeRange;
    if ((GetSensorExposureTimeRange(sensorExposureTimeRange) != CameraErrorCode::SUCCESS) &&
        sensorExposureTimeRange.empty()) {
        MEDIA_ERR_LOG("CaptureSession::SetSensorExposureTime range is empty");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }
    const uint32_t autoLongExposure = 0;
    int32_t minIndex = 0;
    int32_t maxIndex = 1;
    if (exposureTime != autoLongExposure && exposureTime < sensorExposureTimeRange[minIndex]) {
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
    if (!AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_SENSOR_EXPOSURE_TIME, value)) {
        MEDIA_ERR_LOG("ProfessionSession::SetSensorExposureTime Failed to set exposure compensation");
    }
    exposureDurationValue_ = exposureTime;
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::GetSensorExposureTime(uint32_t &exposureTime)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetSensorExposureTime Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSensorExposureTime camera device is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_SENSOR_EXPOSURE_TIME, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetSensorExposureTime Failed with return code %{public}d", ret);
        return CameraErrorCode::INVALID_ARGUMENT;
    }
    exposureTime = item.data.ui32[0];
    MEDIA_DEBUG_LOG("CaptureSession::GetSensorExposureTime exposureTime: %{public}d", exposureTime);
    return CameraErrorCode::SUCCESS;
}

bool CaptureSession::IsMacroSupported()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter IsMacroSupported");

    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::IsMacroSupported Session is not Commited");
        return false;
    }
    if (inputDevice_ == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::IsMacroSupported camera device is null");
        return false;
    }
    auto deviceInfo = inputDevice_->GetCameraDeviceInfo();
    if (deviceInfo == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::IsMacroSupported camera deviceInfo is null");
        return false;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = deviceInfo->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_CAMERA_MACRO_SUPPORTED, &item);
    if (ret != CAM_META_SUCCESS || item.count <= 0) {
        MEDIA_ERR_LOG("CaptureSession::IsMacroSupported Failed with return code %{public}d", ret);
        return false;
    }
    auto supportResult = static_cast<camera_macro_supported_type_t>(*item.data.i32);
    return supportResult == OHOS_CAMERA_MACRO_SUPPORTED;
}

int32_t CaptureSession::EnableMacro(bool isEnable)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter EnableMacro, isEnable:%{public}d", isEnable);
    if (!IsMacroSupported()) {
        MEDIA_ERR_LOG("EnableMacro IsMacroSupported is false");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession Failed EnableMacro!, session not commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    bool status = false;
    int32_t ret;
    camera_metadata_item_t item;
    ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_CAMERA_MACRO, &item);
    uint8_t enableValue = static_cast<uint8_t>(isEnable ? OHOS_CAMERA_MACRO_ENABLE : OHOS_CAMERA_MACRO_DISABLE);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_CAMERA_MACRO, &enableValue, 1);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_CAMERA_MACRO, &enableValue, 1);
    }
    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::EnableMacro Failed to enable macro");
    }
    isSetMacroEnable_ = isEnable;
    return CameraErrorCode::SUCCESS;
}

std::shared_ptr<MoonCaptureBoostFeature> CaptureSession::GetMoonCaptureBoostFeature()
{
    if (inputDevice_ == nullptr) {
        return nullptr;
    }
    auto deviceInfo = inputDevice_->GetCameraDeviceInfo();
    if (deviceInfo == nullptr) {
        return nullptr;
    }
    auto deviceAbility = deviceInfo->GetCameraAbility();
    if (deviceAbility == nullptr) {
        return nullptr;
    }

    auto currentMode = GetMode();
    {
        std::lock_guard<std::mutex> lock(moonCaptureBoostFeatureMutex_);
        if (moonCaptureBoostFeature_ == nullptr || moonCaptureBoostFeature_->GetRelatedMode() != currentMode) {
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
    if (feature == nullptr) {
        return false;
    }
    return feature->IsSupportedMoonCaptureBoostFeature();
}

int32_t CaptureSession::EnableMoonCaptureBoost(bool isEnable)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter EnableMoonCaptureBoost, isEnable:%{public}d", isEnable);
    if (!IsMoonCaptureBoostSupported()) {
        MEDIA_ERR_LOG("EnableMoonCaptureBoost IsMoonCaptureBoostSupported is false");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession Failed EnableMoonCaptureBoost!, session not commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    bool status = false;
    int32_t ret;
    camera_metadata_item_t item;
    ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_MOON_CAPTURE_BOOST, &item);

    uint8_t enableValue =
        static_cast<uint8_t>(isEnable ? 1 : 0);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_MOON_CAPTURE_BOOST, &enableValue, 1);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_MOON_CAPTURE_BOOST, &enableValue, 1);
    }
    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::EnableMoonCaptureBoost failed to enable moon capture boost");
    }
    isSetMoonCaptureBoostEnable_ = isEnable;
    return CameraErrorCode::SUCCESS;
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
        default:
            retCode = INVALID_ARGUMENT;
    }
    UnlockForControl();
    return retCode;
}

void CaptureSession::SetMacroStatusCallback(std::shared_ptr<MacroStatusCallback> callback)
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    macroStatusCallback_ = callback;
    return;
}

void CaptureSession::SetMoonCaptureBoostStatusCallback(std::shared_ptr<MoonCaptureBoostStatusCallback> callback)
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    moonCaptureBoostStatusCallback_ = callback;
    return;
}

void CaptureSession::SetFeatureDetectionStatusCallback(std::shared_ptr<FeatureDetectionStatusCallback> callback)
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    featureDetectionStatusCallback_ = callback;
    return;
}

void CaptureSession::ProcessMacroStatusChange(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Entry ProcessMacroStatusChange");

    // To avoid macroStatusCallback_ change pointed value occur multithread problem, copy pointer first.
    auto statusCallback = GetMacroStatusCallback();
    if (statusCallback == nullptr) {
        MEDIA_DEBUG_LOG("CaptureSession::ProcessMacroStatusChange statusCallback is null");
        return;
    }
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_CAMERA_MACRO_STATUS, &item);
    if (ret != CAM_META_SUCCESS || item.count <= 0) {
        MEDIA_DEBUG_LOG("Camera not support macro mode");
        return;
    }
    auto isMacroActive = static_cast<bool>(item.data.u8[0]);
    MEDIA_DEBUG_LOG("Macro active: %{public}d", isMacroActive);
    auto macroStatus =
        isMacroActive ? MacroStatusCallback::MacroStatus::ACTIVE : MacroStatusCallback::MacroStatus::IDLE;
    if (macroStatus == statusCallback->currentStatus) {
        MEDIA_DEBUG_LOG("Macro mode: no change");
        return;
    }
    statusCallback->currentStatus = macroStatus;
    statusCallback->OnMacroStatusChanged(macroStatus);
}

void CaptureSession::ProcessMoonCaptureBoostStatusChange(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Entry ProcessMoonCaptureBoostStatusChange");

    auto statusCallback = GetMoonCaptureBoostStatusCallback();
    auto featureStatusCallback = GetFeatureDetectionStatusCallback();
    if (statusCallback == nullptr &&
        (featureStatusCallback == nullptr ||
            !featureStatusCallback->IsFeatureSubscribed(SceneFeature::FEATURE_MOON_CAPTURE_BOOST))) {
        MEDIA_DEBUG_LOG("CaptureSession::ProcessMoonCaptureBoostStatusChange statusCallback and "
                        "featureDetectionStatusChangedCallback are null");
        return;
    }

    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_STATUS_MOON_CAPTURE_DETECTION, &item);
    if (ret != CAM_META_SUCCESS || item.count <= 0) {
        MEDIA_DEBUG_LOG("Camera not support moon capture detection");
        return;
    }
    auto isMoonActive = static_cast<bool>(item.data.u8[0]);
    MEDIA_DEBUG_LOG("Moon active: %{public}d", isMoonActive);

    if (statusCallback != nullptr) {
        auto moonCaptureBoostStatus = isMoonActive ? MoonCaptureBoostStatusCallback::MoonCaptureBoostStatus::ACTIVE
                                                   : MoonCaptureBoostStatusCallback::MoonCaptureBoostStatus::IDLE;
        if (moonCaptureBoostStatus == statusCallback->currentStatus) {
            MEDIA_DEBUG_LOG("Moon mode: no change");
            return;
        }
        statusCallback->currentStatus = moonCaptureBoostStatus;
        statusCallback->OnMoonCaptureBoostStatusChanged(moonCaptureBoostStatus);
    }
    if (featureStatusCallback != nullptr &&
        featureStatusCallback->IsFeatureSubscribed(SceneFeature::FEATURE_MOON_CAPTURE_BOOST)) {
        auto detectStatus = isMoonActive ? FeatureDetectionStatusCallback::FeatureDetectionStatus::ACTIVE
                                         : FeatureDetectionStatusCallback::FeatureDetectionStatus::IDLE;
        if (!featureStatusCallback->UpdateStatus(SceneFeature::FEATURE_MOON_CAPTURE_BOOST, detectStatus)) {
            MEDIA_DEBUG_LOG("Feature detect Moon mode: no change");
            return;
        }
        featureStatusCallback->OnFeatureDetectionStatusChanged(SceneFeature::FEATURE_MOON_CAPTURE_BOOST, detectStatus);
    }
}

bool CaptureSession::IsSetEnableMacro()
{
    return isSetMacroEnable_;
}

void CaptureSession::EnableDeferredType(DeferredDeliveryImageType type)
{
    MEDIA_INFO_LOG("CaptureSession::EnableDeferredType type:%{public}d", type);
    if (IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::EnableDeferredType session has committed!");
        return;
    }
    this->LockForControl();
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::EnableDeferredType changedMetadata_ is NULL");
        return;
    }

    bool status = false;
    camera_metadata_item_t item;
    isImageDeferred_ = false;
    uint8_t deferredType;
    switch (type) {
        case DELIVERY_NONE:
            deferredType = HDI::Camera::V1_2::NONE;
            break;
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
    }
    int ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_DEFERRED_IMAGE_DELIVERY, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_DEFERRED_IMAGE_DELIVERY, &deferredType, 1);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_DEFERRED_IMAGE_DELIVERY, &deferredType, 1);
    }
    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::enableDeferredType Failed to set type!");
    }
    int32_t errCode = this->UnlockForControl();
    if (errCode != CameraErrorCode::SUCCESS) {
        MEDIA_DEBUG_LOG("CaptureSession::EnableDeferredType Failed");
    }
}

void CaptureSession::SetUserId()
{
    MEDIA_INFO_LOG("CaptureSession::SetUserId");
    if (IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetUserId session has committed!");
        return;
    }
    this->LockForControl();
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::SetUserId changedMetadata_ is NULL");
        return;
    }
    int32_t userId;
    int32_t uid = IPCSkeleton::GetCallingUid();
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, userId);
    MEDIA_INFO_LOG("CaptureSession get uid:%{public}d userId:%{public}d", uid, userId);

    bool status = false;
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CAMERA_USER_ID, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CAMERA_USER_ID, &userId, 1);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CAMERA_USER_ID, &userId, 1);
    }
    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::SetUserId Failed!");
    }
    int32_t errCode = this->UnlockForControl();
    if (errCode != CameraErrorCode::SUCCESS) {
        MEDIA_DEBUG_LOG("CaptureSession::SetUserId Failed");
    }
}

int32_t CaptureSession::EnableAutoHighQualityPhoto(bool enabled)
{
    MEDIA_INFO_LOG("CaptureSession::EnableAutoHighQualityPhoto enabled:%{public}d", enabled);

    this->LockForControl();
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::EnableAutoHighQualityPhoto changedMetadata_ is NULL");
        return INVALID_ARGUMENT;
    }

    int32_t res = CameraErrorCode::SUCCESS;
    bool status = false;
    camera_metadata_item_t item;
    uint8_t hightQualityEnable = static_cast<uint8_t>(enabled);
    int ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_HIGH_QUALITY_MODE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_HIGH_QUALITY_MODE, &hightQualityEnable, 1);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_HIGH_QUALITY_MODE, &hightQualityEnable, 1);
    }
    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::EnableAutoHighQualityPhoto Failed to set type!");
        res = INVALID_ARGUMENT;
    }
    res = this->UnlockForControl();
    if (res != CameraErrorCode::SUCCESS) {
        MEDIA_DEBUG_LOG("CaptureSession::EnableAutoHighQualityPhoto Failed");
    }
    return res;
}

void CaptureSession::ExecuteAbilityChangeCallback()
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    if (abilityCallback_ != nullptr) {
        abilityCallback_->OnAbilityChange();
    }
}

void CaptureSession::SetAbilityCallback(std::shared_ptr<AbilityCallback> abilityCallback)
{
    MEDIA_ERR_LOG("CaptureSession::SetAbilityCallback() set ability callback");
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    abilityCallback_ = abilityCallback;
    return;
}

std::shared_ptr<OHOS::Camera::CameraMetadata> CaptureSession::GetMetadata()
{
    return inputDevice_->GetCameraDeviceInfo()->GetMetadata();
}

int32_t CaptureSession::SetARMode(bool isEnable)
{
    MEDIA_INFO_LOG("CaptureSession::SetARMode");
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetARMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::SetARMode Need to call LockForControl() before setting camera properties");
        return CameraErrorCode::SUCCESS;
    }

    bool status = false;
    uint32_t count = 1;
    camera_metadata_item_t item;
    uint8_t value = isEnable ? 1 : 0;
    int ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), HAL_CUSTOM_AR_MODE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(HAL_CUSTOM_AR_MODE, &value, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(HAL_CUSTOM_AR_MODE, &value, count);
    }

    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::SetARMode Failed to set ar mode");
        return CameraErrorCode::SUCCESS;
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::GetSensorSensitivityRange(std::vector<int32_t> &sensitivityRange)
{
    MEDIA_INFO_LOG("CaptureSession::GetSensorSensitivityRange");
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetSensorSensitivity fail due to Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSensorSensitivity fail due to camera device is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_SENSOR_INFO_SENSITIVITY_RANGE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetSensorSensitivity Failed with return code %{public}d", ret);
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    for (uint32_t i = 0; i < item.count; i++) {
        sensitivityRange.emplace_back(item.data.i32[i]);
    }

    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetSensorSensitivity(uint32_t sensitivity)
{
    MEDIA_INFO_LOG("CaptureSession::SetSensorSensitivity");
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetSensorSensitivity Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::SetSensorSensitivity Need to call LockForControl() "
            "before setting camera properties");
        return CameraErrorCode::SUCCESS;
    }
    bool status = false;
    int32_t count = 1;
    camera_metadata_item_t item;
    MEDIA_DEBUG_LOG("CaptureSession::SetSensorSensitivity sensitivity: %{public}d", sensitivity);
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::SetSensorSensitivity camera device is null");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }

    int ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), HAL_CUSTOM_SENSOR_SENSITIVITY, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(HAL_CUSTOM_SENSOR_SENSITIVITY, &sensitivity, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(HAL_CUSTOM_SENSOR_SENSITIVITY, &sensitivity, count);
    }
    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::SetSensorSensitivity Failed to set sensitivity");
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::GetModuleType(uint32_t &moduleType)
{
    MEDIA_INFO_LOG("CaptureSession::GetModuleType");
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("CaptureSession::GetModuleType fail due to Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetModuleType fail due to camera device is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), HAL_CUSTOM_SENSOR_MODULE_TYPE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetModuleType Failed with return code %{public}d", ret);
        return CameraErrorCode::INVALID_ARGUMENT;
    }
    moduleType = item.data.ui32[0];
    MEDIA_DEBUG_LOG("moduleType: %{public}d", moduleType);
    return CameraErrorCode::SUCCESS;
}

void CaptureSession::SetARCallback(std::shared_ptr<ARCallback> arCallback)
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    arCallback_ = arCallback;
}
} // namespace CameraStandard
} // namespace OHOS
