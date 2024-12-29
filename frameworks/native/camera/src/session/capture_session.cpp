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
#include <iterator>
#include <memory>
#include <mutex>
#include <sys/types.h>

#include "camera_device.h"
#include "camera_device_ability_items.h"
#include "camera_error_code.h"
#include "camera_log.h"
#include "camera_metadata_operator.h"
#include "camera_output_capability.h"
#include "camera_util.h"
#include "capture_output.h"
#include "camera_security_utils.h"
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
#include "ability/camera_ability_builder.h"
#include "picture.h"
#include "display/graphic/common/v1_0/cm_color_space.h"

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Display::Graphic::Common::V1_0;

namespace {
constexpr int32_t DEFAULT_ITEMS = 10;
constexpr int32_t DEFAULT_DATA_LENGTH = 100;
constexpr int32_t DEFERRED_MODE_DATA_SIZE = 2;
constexpr float DEFAULT_EQUIVALENT_ZOOM = 100.0f;
constexpr int32_t FRAMERATE_120 = 120;
constexpr int32_t FRAMERATE_240 = 240;
} // namespace

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
    {SKIN_TONE, OHOS_CONTROL_BEAUTY_SKIN_TONE_VALUE}
};

const std::unordered_map<camera_device_metadata_tag_t, BeautyType> CaptureSession::metaBeautyControlMap_ = {
    {OHOS_CONTROL_BEAUTY_SKIN_SMOOTH_VALUE, SKIN_SMOOTH},
    {OHOS_CONTROL_BEAUTY_FACE_SLENDER_VALUE, FACE_SLENDER},
    {OHOS_CONTROL_BEAUTY_SKIN_TONE_VALUE, SKIN_TONE}
};

const std::unordered_map<CameraEffectSuggestionType, EffectSuggestionType>
    CaptureSession::metaEffectSuggestionTypeMap_ = {
    {OHOS_CAMERA_EFFECT_SUGGESTION_NONE, EFFECT_SUGGESTION_NONE},
    {OHOS_CAMERA_EFFECT_SUGGESTION_PORTRAIT, EFFECT_SUGGESTION_PORTRAIT},
    {OHOS_CAMERA_EFFECT_SUGGESTION_FOOD, EFFECT_SUGGESTION_FOOD},
    {OHOS_CAMERA_EFFECT_SUGGESTION_SKY, EFFECT_SUGGESTION_SKY},
    {OHOS_CAMERA_EFFECT_SUGGESTION_SUNRISE_SUNSET, EFFECT_SUGGESTION_SUNRISE_SUNSET}
};

const std::unordered_map<EffectSuggestionType, CameraEffectSuggestionType>
    CaptureSession::fwkEffectSuggestionTypeMap_ = {
    {EFFECT_SUGGESTION_NONE, OHOS_CAMERA_EFFECT_SUGGESTION_NONE},
    {EFFECT_SUGGESTION_PORTRAIT, OHOS_CAMERA_EFFECT_SUGGESTION_PORTRAIT},
    {EFFECT_SUGGESTION_FOOD, OHOS_CAMERA_EFFECT_SUGGESTION_FOOD},
    {EFFECT_SUGGESTION_SKY, OHOS_CAMERA_EFFECT_SUGGESTION_SKY},
    {EFFECT_SUGGESTION_SUNRISE_SUNSET, OHOS_CAMERA_EFFECT_SUGGESTION_SUNRISE_SUNSET}
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

int32_t FoldCallback::OnFoldStatusChanged(const FoldStatus status)
{
    MEDIA_INFO_LOG("FoldStatus is %{public}d", status);
    auto captureSession = captureSession_.promote();
    CHECK_ERROR_RETURN_RET_LOG(captureSession == nullptr, CAMERA_OPERATION_NOT_ALLOWED, "captureSession is nullptr.");
    bool isEnableAutoSwitch = captureSession->GetIsAutoSwitchDeviceStatus();
    CHECK_ERROR_RETURN_RET_LOG(!isEnableAutoSwitch, CAMERA_OPERATION_NOT_ALLOWED, "isEnableAutoSwitch is false.");
    bool isSuccess = captureSession->SwitchDevice();
    MEDIA_INFO_LOG("SwitchDevice isSuccess: %{public}d", isSuccess);
    auto autoDeviceSwitchCallback = captureSession->GetAutoDeviceSwitchCallback();
    CHECK_ERROR_RETURN_RET_LOG(autoDeviceSwitchCallback == nullptr, CAMERA_OPERATION_NOT_ALLOWED,
        "autoDeviceSwitchCallback is nullptr");
    bool isDeviceCapabilityChanged = captureSession->GetDeviceCapabilityChangeStatus();
    MEDIA_INFO_LOG("SwitchDevice isDeviceCapabilityChanged: %{public}d", isDeviceCapabilityChanged);
    autoDeviceSwitchCallback->OnAutoDeviceSwitchStatusChange(isSuccess, isDeviceCapabilityChanged);
    return CAMERA_OK;
}

CaptureSession::CaptureSession(sptr<ICaptureSession>& captureSession) : innerCaptureSession_(captureSession)
{
    metadataResultProcessor_ = std::make_shared<CaptureSessionMetadataResultProcessor>(this);
    sptr<IRemoteObject> object = innerCaptureSession_->AsObject();
    pid_t pid = 0;
    deathRecipient_ = new (std::nothrow) CameraDeathRecipient(pid);
    CHECK_AND_RETURN_LOG(deathRecipient_ != nullptr, "failed to new CameraDeathRecipient.");

    deathRecipient_->SetNotifyCb([this](pid_t pid) { CameraServerDied(pid); });
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
    SessionRemoveDeathRecipient();
}

void CaptureSession::SessionRemoveDeathRecipient()
{
    auto captureSession = GetCaptureSession();
    if (captureSession != nullptr) {
        (void)captureSession->AsObject()->RemoveDeathRecipient(deathRecipient_);
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
        MEDIA_ERR_LOG("CaptureSession::BeginConfig Session is locked");
        return CameraErrorCode::SESSION_CONFIG_LOCKED;
    }

    isColorSpaceSetted_ = false;
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    auto captureSession = GetCaptureSession();
    if (captureSession) {
        errCode = captureSession->BeginConfig();
        if (errCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to BeginConfig!, %{public}d", errCode);
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
        MEDIA_ERR_LOG("CaptureSession::CommitConfig operation Not allowed!");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }

    MEDIA_INFO_LOG("CaptureSession::CommitConfig isColorSpaceSetted_ = %{public}d", isColorSpaceSetted_);
    if (!isColorSpaceSetted_) {
        auto preconfigProfiles = GetPreconfigProfiles();
        if (preconfigProfiles != nullptr) {
            SetColorSpace(preconfigProfiles->colorSpace);
        } else {
            SetDefaultColorSpace();
        }
    }
    // DELIVERY_PHOTO for default when commit
    if (photoOutput_ && !isDeferTypeSetted_) {
        EnableDeferredType(((sptr<PhotoOutput> &)photoOutput_)->IsEnableDeferred() ? DELIVERY_PHOTO
            : DELIVERY_NONE, false);
        SetUserId();
    }
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    auto captureSession = GetCaptureSession();
    if (captureSession) {
        errCode = captureSession->CommitConfig();
        MEDIA_INFO_LOG("CaptureSession::CommitConfig commit mode = %{public}d", GetMode());
        if (errCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to CommitConfig!, %{public}d", errCode);
        } else {
            CreateCameraAbilityContainer();
        }
    } else {
        MEDIA_ERR_LOG("CaptureSession::CommitConfig() captureSession is nullptr");
    }
    return ServiceToCameraError(errCode);
}

void CaptureSession::CheckSpecSearch()
{
    auto inputDevice = GetInputDevice();
    CHECK_AND_RETURN_LOG(inputDevice && inputDevice->GetCameraDeviceInfo(), "camera device is null");
    camera_metadata_item_t item;
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_AND_RETURN_LOG(metadata != nullptr, "CheckSpecSearch camera metadata is null");
    int32_t retCode = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_AVAILABLE_PROFILE_LEVEL, &item);
    if (retCode != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG("specSearch is not support");
        supportSpecSearch_ = false;
        return;
    }
    supportSpecSearch_ = true;
}

void CaptureSession::PopulateProfileLists(std::vector<Profile>& photoProfileList,
                                          std::vector<Profile>& previewProfileList,
                                          std::vector<VideoProfile>& videoProfileList)
{
    for (auto output : captureOutputSets_) {
        auto item = output.promote();
        if (item == nullptr) {
            continue;
        }
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
    CHECK_AND_RETURN_LOG(device, "camera device is null");
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
        if (cameraOutputCapability == nullptr) {
            continue;
        }
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
    if (inputDevice == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::GetSessionFunctions inputDevice is null");
        return {};
    }
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
        if (capability->IsMatchPreviewProfiles(previewProfiles) &&
            capability->IsMatchPhotoProfiles(photoProfiles) &&
            capability->IsMatchVideoProfiles(videoProfiles)) {
            supportedSpecIds.insert(specId);
            MEDIA_INFO_LOG("CaptureSession::GetSessionFunctions insert specId: %{public}d", specId);
        }
    }

    CameraAbilityBuilder builder;
    std::vector<sptr<CameraAbility>> cameraAbilityArray;
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, cameraAbilityArray,
        "GetSessionFunctions camera metadata is null");
    return builder.GetAbility(
        GetFeaturesMode().GetFeaturedMode(), metadata->get(), supportedSpecIds, this, isForApp);
}

std::vector<sptr<CameraAbility>> CaptureSession::GetSessionConflictFunctions()
{
    CameraAbilityBuilder builder;
    std::vector<sptr<CameraAbility>> cameraAbilityArray;
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, cameraAbilityArray,
        "GetSessionConflictFunctions camera metadata is null");
    return builder.GetConflictAbility(GetFeaturesMode().GetFeaturedMode(), metadata->get());
}

void CaptureSession::CreateCameraAbilityContainer()
{
    auto inputDevice = GetInputDevice();
    if (inputDevice == nullptr) {
        MEDIA_ERR_LOG("CreateCameraAbilityContainer inputDevice is null");
        return;
    }
    std::vector<Profile> photoProfileList;
    std::vector<Profile> previewProfileList;
    std::vector<VideoProfile> videoProfileList;
    PopulateProfileLists(photoProfileList, previewProfileList, videoProfileList);
    std::vector<sptr<CameraAbility>> abilities =
        GetSessionFunctions(previewProfileList, photoProfileList, videoProfileList, false);
    MEDIA_DEBUG_LOG("CreateCameraAbilityContainer abilities size %{public}zu", abilities.size());
    if (abilities.size() == 0) {
        MEDIA_INFO_LOG("CreateCameraAbilityContainer fail cant find suitable ability");
    }
    std::vector<sptr<CameraAbility>> conflictAbilities = GetSessionConflictFunctions();
    MEDIA_DEBUG_LOG("CreateCameraAbilityContainer conflictAbilities size %{public}zu", conflictAbilities.size());
    std::lock_guard<std::mutex> lock(abilityContainerMutex_);
    cameraAbilityContainer_ = new CameraAbilityContainer(abilities, conflictAbilities, this);
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

    auto captureSession = GetCaptureSession();
    CHECK_ERROR_RETURN_LOG(!captureSession, "CaptureSession::SetDefaultColorSpace() captureSession is nullptr");

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

    int32_t errCode = captureSession->SetColorSpace(fwkColorSpace, fwkCaptureColorSpace, false);
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
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionConfiged() || input == nullptr, ret,
        "CaptureSession::AddInput operation Not allowed!");
    auto captureSession = GetCaptureSession();
    if (captureSession) {
        captureSession->CanAddInput(((sptr<CameraInput>&)input)->GetCameraDevice(), ret);
    } else {
        MEDIA_ERR_LOG("CaptureSession::CanAddInput() captureSession is nullptr");
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
    auto captureSession = GetCaptureSession();
    if (captureSession == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::AddInput() captureSession is nullptr");
        return ServiceToCameraError(errCode);
    }
    errCode = captureSession->AddInput(((sptr<CameraInput>&)input)->GetCameraDevice());
    if (errCode != CAMERA_OK) {
        MEDIA_ERR_LOG("Failed to AddInput!, %{public}d", errCode);
        return ServiceToCameraError(errCode);
    }
    SetInputDevice(input);
    CheckSpecSearch();
    input->SetMetadataResultProcessor(GetMetadataResultProcessor());
    UpdateDeviceDeferredability();
    FindTagId();
    return ServiceToCameraError(errCode);
}

void CaptureSession::UpdateDeviceDeferredability()
{
    MEDIA_DEBUG_LOG("UpdateDeviceDeferredability begin.");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_LOG(inputDevice == nullptr,
        "CaptureSession::UpdateDeviceDeferredability inputDevice is nullptr");
    auto deviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_LOG(deviceInfo == nullptr,
        "CaptureSession::UpdateDeviceDeferredability deviceInfo is nullptr");
    deviceInfo->modeDeferredType_ = {};
    camera_metadata_item_t item;
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_ERROR_RETURN_LOG(metadata == nullptr, "UpdateDeviceDeferredability camera metadata is null");
    int32_t ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_DEFERRED_IMAGE_DELIVERY, &item);
    MEDIA_INFO_LOG("UpdateDeviceDeferredability get ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("UpdateDeviceDeferredability item: %{public}d count: %{public}d", item.item, item.count);
    for (uint32_t i = 0; i < item.count; i++) {
        if (i % DEFERRED_MODE_DATA_SIZE == 0) {
            MEDIA_DEBUG_LOG("UpdateDeviceDeferredability mode index:%{public}d, deferredType:%{public}d",
                item.data.u8[i], item.data.u8[i + 1]);
            deviceInfo->modeDeferredType_[item.data.u8[i]] =
                static_cast<DeferredDeliveryImageType>(item.data.u8[i + 1]);
        }
    }
    
    deviceInfo->modeVideoDeferredType_ = {};
    ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_AUTO_DEFERRED_VIDEO_ENHANCE, &item);
    MEDIA_INFO_LOG("UpdateDeviceDeferredability get video ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("UpdateDeviceDeferredability video item: %{public}d count: %{public}d", item.item, item.count);
    for (uint32_t i = 0; i + 1 < item.count; i++) {
        if (i % DEFERRED_MODE_DATA_SIZE == 0) {
            MEDIA_DEBUG_LOG("UpdateDeviceDeferredability mode index:%{public}d, video deferredType:%{public}d",
                item.data.u8[i], item.data.u8[i + 1]);
            deviceInfo->modeVideoDeferredType_[item.data.u8[i]] = item.data.u8[i + 1];
        }
    }
}

void CaptureSession::FindTagId()
{
    MEDIA_INFO_LOG("Enter Into CaptureSession::FindTagId");
    auto inputDevice = GetInputDevice();
    if (inputDevice != nullptr) {
        MEDIA_DEBUG_LOG("CaptureSession::FindTagId inputDevice not nullptr");
        std::vector<vendorTag_t> vendorTagInfos;
        sptr<CameraInput> camInput = (sptr<CameraInput>&)inputDevice;
        int32_t ret = camInput->GetCameraAllVendorTags(vendorTagInfos);
        CHECK_ERROR_RETURN_LOG(ret != CAMERA_OK, "Failed to GetCameraAllVendorTags");
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
    CHECK_ERROR_RETURN_RET_LOG(minFps == 0 || curMinFps == 0, false,
        "CaptureSession::CheckFrameRateRangeWithCurrentFps can not set zero!");
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

int32_t CaptureSession::ConfigurePreviewOutput(sptr<CaptureOutput>& output)
{
    MEDIA_INFO_LOG("CaptureSession::ConfigurePreviewOutput enter");
    auto previewProfile = output->GetPreviewProfile();
    if (output->IsTagSetted(CaptureOutput::DYNAMIC_PROFILE)) {
        CHECK_ERROR_RETURN_RET_LOG(previewProfile != nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
            "CaptureSession::ConfigurePreviewOutput previewProfile is not null, is that output in use?");
        auto preconfigPreviewProfile = GetPreconfigPreviewProfile();
        CHECK_ERROR_RETURN_RET_LOG(preconfigPreviewProfile == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
            "CaptureSession::ConfigurePreviewOutput preconfigPreviewProfile is nullptr");
        output->SetPreviewProfile(*preconfigPreviewProfile);
        int32_t res = output->CreateStream();
        if (res != CameraErrorCode::SUCCESS) {
            MEDIA_ERR_LOG("CaptureSession::ConfigurePreviewOutput createStream from preconfig fail! %{public}d", res);
            return res;
        }
        MEDIA_INFO_LOG("CaptureSession::ConfigurePreviewOutput createStream from preconfig success");
        previewProfile_ = *preconfigPreviewProfile;
    } else {
        previewProfile_ = *previewProfile;
    }
    SetGuessMode(SceneMode::CAPTURE);
    return CameraErrorCode::SUCCESS;
}

std::shared_ptr<Profile> CaptureSession::GetMaxSizePhotoProfile(ProfileSizeRatio sizeRatio)
{
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET(inputDevice == nullptr, nullptr);
    auto cameraInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET(cameraInfo == nullptr || cameraInfo->GetCameraType() != CAMERA_TYPE_DEFAULT, nullptr);
    SceneMode sceneMode = GetMode();
    if (sceneMode == SceneMode::CAPTURE) {
        auto it = cameraInfo->modePhotoProfiles_.find(SceneMode::CAPTURE);
        CHECK_ERROR_RETURN_RET(it == cameraInfo->modePhotoProfiles_.end(), nullptr);
        float photoRatioValue = GetTargetRatio(sizeRatio, RATIO_VALUE_4_3);
        return cameraInfo->GetMaxSizeProfile<Profile>(it->second, photoRatioValue, CameraFormat::CAMERA_FORMAT_JPEG);
    } else if (sceneMode == SceneMode::VIDEO) {
        auto it = cameraInfo->modePhotoProfiles_.find(SceneMode::VIDEO);
        CHECK_ERROR_RETURN_RET(it == cameraInfo->modePhotoProfiles_.end(), nullptr);
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
    CHECK_ERROR_RETURN_RET_LOG(preconfigProfiles == nullptr, nullptr,
        "CaptureSession::GetPreconfigPreviewProfile preconfigProfiles is nullptr");
    return std::make_shared<Profile>(preconfigProfiles->previewProfile);
}

std::shared_ptr<Profile> CaptureSession::GetPreconfigPhotoProfile()
{
    auto preconfigProfiles = GetPreconfigProfiles();
    CHECK_ERROR_RETURN_RET_LOG(preconfigProfiles == nullptr, nullptr,
        "CaptureSession::GetPreconfigPhotoProfile preconfigProfiles is nullptr");
    if (preconfigProfiles->photoProfile.sizeFollowSensorMax_) {
        auto maxSizePhotoProfile = GetMaxSizePhotoProfile(preconfigProfiles->photoProfile.sizeRatio_);
        CHECK_ERROR_RETURN_RET_LOG(maxSizePhotoProfile == nullptr, nullptr,
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
    CHECK_ERROR_RETURN_RET_LOG(preconfigProfiles == nullptr, nullptr,
        "CaptureSession::GetPreconfigVideoProfile preconfigProfiles is nullptr");
    return std::make_shared<VideoProfile>(preconfigProfiles->videoProfile);
}

int32_t CaptureSession::ConfigurePhotoOutput(sptr<CaptureOutput>& output)
{
    MEDIA_INFO_LOG("CaptureSession::ConfigurePhotoOutput enter");
    auto photoProfile = output->GetPhotoProfile();
    if (output->IsTagSetted(CaptureOutput::DYNAMIC_PROFILE)) {
        CHECK_ERROR_RETURN_RET_LOG(photoProfile != nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
            "CaptureSession::ConfigurePhotoOutput photoProfile is not null, is that output in use?");
        auto preconfigPhotoProfile = GetPreconfigPhotoProfile();
        CHECK_ERROR_RETURN_RET_LOG(preconfigPhotoProfile == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
            "CaptureSession::ConfigurePhotoOutput preconfigPhotoProfile is null");
        output->SetPhotoProfile(*preconfigPhotoProfile);
        int32_t res = output->CreateStream();
        CHECK_ERROR_RETURN_RET_LOG(res != CameraErrorCode::SUCCESS, res,
            "CaptureSession::ConfigurePhotoOutput createStream from preconfig fail! %{public}d", res);
        MEDIA_INFO_LOG("CaptureSession::ConfigurePhotoOutput createStream from preconfig success");
        photoProfile_ = *preconfigPhotoProfile;
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
        CHECK_ERROR_RETURN_RET_LOG(videoProfile != nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
            "CaptureSession::ConfigureVideoOutput videoProfile is not null, is that output in use?");
        auto preconfigVideoProfile = GetPreconfigVideoProfile();
        CHECK_ERROR_RETURN_RET_LOG(preconfigVideoProfile == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
            "CaptureSession::ConfigureVideoOutput preconfigVideoProfile is nullptr");
        videoProfile = preconfigVideoProfile;
        output->SetVideoProfile(*preconfigVideoProfile);
        int32_t res = output->CreateStream();
        CHECK_ERROR_RETURN_RET_LOG(res != CameraErrorCode::SUCCESS, res,
            "CaptureSession::ConfigureVideoOutput createStream from preconfig fail! %{public}d", res);
        MEDIA_INFO_LOG("CaptureSession::ConfigureVideoOutput createStream from preconfig success");
    }
    std::vector<int32_t> frameRateRange = videoProfile->GetFrameRates();
    const size_t minFpsRangeSize = 2;
    if (frameRateRange.size() >= minFpsRangeSize) {
        SetFrameRateRange(frameRateRange);
    }
    if (output != nullptr) {
        sptr<VideoOutput> videoOutput = static_cast<VideoOutput*>(output.GetRefPtr());
        videoOutput->SetFrameRateRange(frameRateRange[0], frameRateRange[1]);
    }
    SetGuessMode(SceneMode::VIDEO);
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::ConfigureOutput(sptr<CaptureOutput>& output)
{
    MEDIA_INFO_LOG("Enter Into CaptureSession::ConfigureOutput");
    output->SetSession(this);
    auto type = output->GetOutputType();
    MEDIA_INFO_LOG("CaptureSession::ConfigureOutput outputType is:%{public}d", type);
    switch (type) {
        case CAPTURE_OUTPUT_TYPE_PREVIEW:
            return ConfigurePreviewOutput(output);
        case CAPTURE_OUTPUT_TYPE_PHOTO:
            return ConfigurePhotoOutput(output);
        case CAPTURE_OUTPUT_TYPE_VIDEO:
            return ConfigureVideoOutput(output);
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

    CHECK_ERROR_RETURN_RET_LOG(ConfigureOutput(output) != CameraErrorCode::SUCCESS,
        CameraErrorCode::SERVICE_FATL_ERROR,
        "CaptureSession::AddOutput ConfigureOutput fail!");
    if (output->GetOutputType() == CAPTURE_OUTPUT_TYPE_METADATA) {
        MEDIA_INFO_LOG("CaptureSession::AddOutput MetadataOutput");
        metaOutput_ = output;
    }
    if (!CanAddOutput(output)) {
        MEDIA_ERR_LOG("CanAddOutput check failed!");
        return ServiceToCameraError(CAMERA_INVALID_ARG);
    }
    auto captureSession = GetCaptureSession();
    CHECK_ERROR_RETURN_RET_LOG(captureSession == nullptr, ServiceToCameraError(CAMERA_UNKNOWN_ERROR),
        "CaptureSession::AddOutput() captureSession is nullptr");
    int32_t ret = AdaptOutputVideoHighFrameRate(output, captureSession);
    CHECK_ERROR_RETURN_RET_LOG(ret != CameraErrorCode::SUCCESS, ServiceToCameraError(CAMERA_INVALID_ARG),
        "CaptureSession::AddOutput An Error in the AdaptOutputVideoHighFrameRate");
    int32_t errCode = captureSession->AddOutput(output->GetStreamType(), output->GetStream());
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

int32_t CaptureSession::AdaptOutputVideoHighFrameRate(sptr<CaptureOutput>& output,
    sptr<ICaptureSession>& captureSession)
{
    MEDIA_INFO_LOG("Enter Into CaptureSession::AdaptOutputVideoHighFrameRate");
    CHECK_ERROR_RETURN_RET_LOG(output == nullptr, CameraErrorCode::INVALID_ARGUMENT,
        "CaptureSession::AdaptOutputVideoHighFrameRate output is null");
    CHECK_ERROR_RETURN_RET_LOG(captureSession == nullptr, CameraErrorCode::INVALID_ARGUMENT,
        "CaptureSession::AdaptOutputVideoHighFrameRate() captureSession is nullptr");
    if (GetMode() == SceneMode::VIDEO && output->GetOutputType() == CAPTURE_OUTPUT_TYPE_VIDEO) {
        std::vector<int32_t> videoFrameRates = output->GetVideoProfile()->GetFrameRates();
        CHECK_ERROR_RETURN_RET_LOG(videoFrameRates.empty(), CameraErrorCode::INVALID_ARGUMENT,
            "videoFrameRates is empty!");
        if (videoFrameRates[0] == FRAMERATE_120 || videoFrameRates[0] == FRAMERATE_240) {
            captureSession->SetFeatureMode(SceneMode::HIGH_FRAME_RATE);
            SetMode(SceneMode::HIGH_FRAME_RATE);
            return CameraErrorCode::SUCCESS;
        }
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::AddSecureOutput(sptr<CaptureOutput> &output)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("Enter Into SecureCameraSession::AddSecureOutput");
    CHECK_AND_RETURN_RET(currentMode_ == SceneMode::SECURE, CAMERA_OPERATION_NOT_ALLOWED);
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionConfiged() || output == nullptr || isSetSecureOutput_,
        CAMERA_OPERATION_NOT_ALLOWED, "SecureCameraSession::AddSecureOutput operation is Not allowed!");
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
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionConfiged() || output == nullptr, false,
        "CaptureSession::CanAddOutput operation Not allowed!");
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::CanAddOutput Failed inputDevice is nullptr");
        return false;
    }
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
        case CAPTURE_OUTPUT_TYPE_DEPTH_DATA:
            profilePtr = output->GetDepthProfile();
            break;
        case CAPTURE_OUTPUT_TYPE_METADATA:
            return true;
        default:
            MEDIA_ERR_LOG("CaptureSession::CanAddOutput CaptureOutputType unknown");
            return false;
    }
    if (profilePtr == nullptr) {
        return false;
    }
    return ValidateOutputProfile(*profilePtr, outputType);
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
    CHECK_ERROR_RETURN_RET_LOG(device == nullptr, ServiceToCameraError(CAMERA_INVALID_ARG),
        "CaptureSession::RemoveInput device is null");
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
        if (errCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to RemoveInput!, %{public}d", errCode);
        }
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
        metaOutput->Stop();
        MEDIA_DEBUG_LOG("CaptureSession::RemoveOutput remove metaOutput");
        return ServiceToCameraError(CAMERA_OK);
    }
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    auto captureSession = GetCaptureSession();
    if (captureSession) {
        errCode = captureSession->RemoveOutput(output->GetStreamType(), output->GetStream());
        if (errCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to RemoveOutput!, %{public}d", errCode);
        }
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
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::Start Session not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    auto captureSession = GetCaptureSession();
    if (captureSession) {
        errCode = captureSession->Start();
        CHECK_ERROR_PRINT_LOG(errCode != CAMERA_OK, "Failed to Start capture session!, %{public}d", errCode);
    } else {
        MEDIA_ERR_LOG("CaptureSession::Start() captureSession is nullptr");
    }
    if (GetMetaOutput()) {
        sptr<MetadataOutput> metaOutput = static_cast<MetadataOutput*>(GetMetaOutput().GetRefPtr());
        CHECK_ERROR_RETURN_RET_LOG(!metaOutput, ServiceToCameraError(errCode), "CaptureSession::metaOutput is null");
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
        if (errCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to Stop capture session!, %{public}d", errCode);
        }
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
    appCallback_ = nullptr;
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
    return ServiceToCameraError(errCode);
}

void CaptureSession::SetCallback(std::shared_ptr<SessionCallback> callback)
{
    if (callback == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::SetCallback Unregistering application callback!");
    }
    int32_t errorCode = CAMERA_OK;
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    appCallback_ = callback;
    auto captureSession = GetCaptureSession();
    if (appCallback_ != nullptr && captureSession != nullptr) {
        if (captureSessionCallback_ == nullptr) {
            captureSessionCallback_ = new (std::nothrow) CaptureSessionCallback(this);
            CHECK_ERROR_RETURN_LOG(captureSessionCallback_ == nullptr, "failed to new captureSessionCallback_!");
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

void CaptureSession::CreateMediaLibrary(sptr<CameraPhotoProxy> photoProxy, std::string &uri, int32_t &cameraShotType,
                                        std::string &burstKey, int64_t timestamp)
{
    CAMERA_SYNC_TRACE;
    int32_t errorCode = CAMERA_OK;
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    auto captureSession = GetCaptureSession();
    if (captureSession) {
        errorCode = captureSession->CreateMediaLibrary(photoProxy, uri, cameraShotType, burstKey, timestamp);
        CHECK_ERROR_PRINT_LOG(errorCode != CAMERA_OK, "Failed to create media library, errorCode: %{public}d",
            errorCode);
    } else {
        MEDIA_ERR_LOG("CaptureSession::CreateMediaLibrary captureSession is nullptr");
    }
}

void CaptureSession::CreateMediaLibrary(std::unique_ptr<Media::Picture> picture, sptr<CameraPhotoProxy> photoProxy,
    std::string &uri, int32_t &cameraShotType, std::string &burstKey, int64_t timestamp)
{
    int32_t errorCode = CAMERA_OK;
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    auto captureSession = GetCaptureSession();
    if (captureSession) {
        errorCode = captureSession->CreateMediaLibrary(std::move(picture), photoProxy, uri, cameraShotType,
            burstKey, timestamp);
        if (errorCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to create media library, errorCode: %{public}d", errorCode);
        }
    } else {
        MEDIA_ERR_LOG("CaptureSession::CreatePictureForMediaLibrary captureSession is nullptr");
    }
}

int32_t CaptureSession::SetPreviewRotation(std::string &deviceClass)
{
    int32_t errorCode = CAMERA_OK;
    auto captureSession = GetCaptureSession();
    if (captureSession) {
        errorCode = captureSession->SetPreviewRotation(deviceClass);
        CHECK_ERROR_PRINT_LOG(errorCode != CAMERA_OK, "SetPreviewRotation is failed errorCode: %{public}d", errorCode);
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

    auto inputDevice = GetInputDevice();
    if (!inputDevice || ((sptr<CameraInput>&)inputDevice)->GetCameraDevice() == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::UpdateSetting Failed inputDevice is nullptr");
        return CameraErrorCode::SUCCESS;
    }
    int32_t ret = ((sptr<CameraInput>&)inputDevice)->GetCameraDevice()->UpdateSetting(changedMetadata);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAMERA_OK, ServiceToCameraError(ret),
        "CaptureSession::UpdateSetting Failed to update settings, errCode = %{public}d", ret);

    std::shared_ptr<Camera::CameraMetadata> baseMetadata = GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(baseMetadata == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::UpdateSetting camera metadata is null");
    for (uint32_t index = 0; index < count; index++) {
        camera_metadata_item_t srcItem;
        int ret = OHOS::Camera::GetCameraMetadataItem(metadataHeader, index, &srcItem);
        CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, CAMERA_INVALID_ARG,
            "CaptureSession::UpdateSetting Failed to get metadata item at index: %{public}d", index);
        bool status = false;
        uint32_t currentIndex;
        ret = OHOS::Camera::FindCameraMetadataItemIndex(baseMetadata->get(), srcItem.item, &currentIndex);
        if (ret == CAM_META_SUCCESS) {
            status = baseMetadata->updateEntry(srcItem.item, srcItem.data.u8, srcItem.count);
        } else if (ret == CAM_META_ITEM_NOT_FOUND) {
            status = baseMetadata->addEntry(srcItem.item, srcItem.data.u8, srcItem.count);
        }
        CHECK_ERROR_PRINT_LOG(!status,
            "CaptureSession::UpdateSetting Failed to add/update metadata item: %{public}d", srcItem.item);
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
        changeMetaMutex_.unlock();
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
    auto inputDevice = GetInputDevice();
    if (!inputDevice) {
        MEDIA_ERR_LOG("CaptureSession::GetActiveVideoStabilizationMode camera device is null");
        return OFF;
    }
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    if (!inputDeviceInfo) {
        MEDIA_ERR_LOG("CaptureSession::GetActiveVideoStabilizationMode camera device is null");
        return OFF;
    }
    cameraObj_ = inputDeviceInfo;
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj_->GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, OFF,
        "GetActiveVideoStabilizationMode camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &item);
    if (ret == CAM_META_SUCCESS) {
        auto itr = g_metaVideoStabModesMap_.find(static_cast<CameraVideoStabilizationMode>(item.data.u8[0]));
        if (itr != g_metaVideoStabModesMap_.end()) {
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
    auto inputDevice = GetInputDevice();
    if (!inputDevice) {
        MEDIA_ERR_LOG("CaptureSession::GetActiveVideoStabilizationMode camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    if (!inputDeviceInfo) {
        MEDIA_ERR_LOG("CaptureSession::GetActiveVideoStabilizationMode camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    mode = OFF;
    bool isSupported = false;
    sptr<CameraDevice> cameraObj_;
    cameraObj_ = inputDeviceInfo;
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj_->GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, CameraErrorCode::SUCCESS,
        "GetActiveVideoStabilizationMode camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &item);
    if (ret == CAM_META_SUCCESS) {
        auto itr = g_metaVideoStabModesMap_.find(static_cast<CameraVideoStabilizationMode>(item.data.u8[0]));
        if (itr != g_metaVideoStabModesMap_.end()) {
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
    if ((!CameraSecurity::CheckSystemApp()) && (stabilizationMode == VideoStabilizationMode::HIGH)) {
        stabilizationMode = VideoStabilizationMode::AUTO;
    }
    CHECK_AND_RETURN_RET(IsVideoStabilizationModeSupported(stabilizationMode), CameraErrorCode::OPERATION_NOT_ALLOWED);
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
            if (!sharedThis) {
                MEDIA_ERR_LOG("SetVideoStabilizationMode session is nullptr");
                return;
            }
            int32_t retCode = sharedThis->SetVideoStabilizationMode(stabilizationMode);
            CHECK_EXECUTE(retCode != CameraErrorCode::SUCCESS,
                          sharedThis->SetDeviceCapabilityChangeStatus(true));
        });
    }
    int32_t errCode = this->UnlockForControl();
    if (errCode != CameraErrorCode::SUCCESS) {
        MEDIA_DEBUG_LOG("CaptureSession::SetVideoStabilizingMode Failed to set video stabilization mode");
    }
    return CameraErrorCode::SUCCESS;
}

bool CaptureSession::IsVideoStabilizationModeSupported(VideoStabilizationMode stabilizationMode)
{
    CHECK_ERROR_RETURN_RET((!CameraSecurity::CheckSystemApp()) && (stabilizationMode == VideoStabilizationMode::HIGH),
        false);
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
    return stabilizationModes;
}

int32_t CaptureSession::GetSupportedStabilizationMode(std::vector<VideoStabilizationMode>& stabilizationModes)
{
    stabilizationModes.clear();
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedStabilizationMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedStabilizationMode camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, CameraErrorCode::SUCCESS,
        "GetSupportedStabilizationMode camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_VIDEO_STABILIZATION_MODES, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetSupporteStabilizationModes Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }

    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = g_metaVideoStabModesMap_.find(static_cast<CameraVideoStabilizationMode>(item.data.u8[i]));
        if (itr != g_metaVideoStabModesMap_.end()) {
            stabilizationModes.emplace_back(itr->second);
        }
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
    std::vector<ExposureMode> supportedExposureModes;
    GetSupportedExposureModes(supportedExposureModes);
    return supportedExposureModes;
}

int32_t CaptureSession::GetSupportedExposureModes(std::vector<ExposureMode>& supportedExposureModes)
{
    supportedExposureModes.clear();
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedExposureModes Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedExposureModes camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, CameraErrorCode::SUCCESS,
        "GetSupportedExposureModes camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_EXPOSURE_MODES, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedExposureModes Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }

    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = g_metaExposureModeMap_.find(static_cast<camera_exposure_mode_enum_t>(item.data.u8[i]));
        if (itr != g_metaExposureModeMap_.end()) {
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
        MEDIA_ERR_LOG("CaptureSession::SetExposureMode Need to call LockForControl() before setting camera properties");
        return CameraErrorCode::SUCCESS;
    }
    CHECK_AND_RETURN_RET(IsExposureModeSupported(exposureMode), CameraErrorCode::OPERATION_NOT_ALLOWED);
    uint8_t exposure = g_fwkExposureModeMap_.at(EXPOSURE_MODE_LOCKED);
    auto itr = g_fwkExposureModeMap_.find(exposureMode);
    if (itr == g_fwkExposureModeMap_.end()) {
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
    wptr<CaptureSession> weakThis(this);
    CHECK_EXECUTE(status, AddFunctionToMap(std::to_string(OHOS_CONTROL_EXPOSURE_MODE), [weakThis, exposureMode]() {
        auto sharedThis = weakThis.promote();
        if (!sharedThis) {
            MEDIA_ERR_LOG("SetExposureMode session is nullptr");
            return;
        }
        sharedThis->LockForControl();
        int32_t retCode = sharedThis->SetExposureMode(exposureMode);
        sharedThis->UnlockForControl();
        CHECK_EXECUTE(retCode != CameraErrorCode::SUCCESS, sharedThis->SetDeviceCapabilityChangeStatus(true));
    }));
    CHECK_ERROR_PRINT_LOG(!status, "CaptureSession::SetExposureMode Failed to set exposure mode");

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
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureMode camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, CameraErrorCode::SUCCESS,
        "GetExposureMode camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_EXPOSURE_MODE, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "CaptureSession::GetExposureMode Failed with return code %{public}d", ret);
    auto itr = g_metaExposureModeMap_.find(static_cast<camera_exposure_mode_enum_t>(item.data.u8[0]));
    if (itr != g_metaExposureModeMap_.end()) {
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
    wptr<CaptureSession> weakThis(this);
    CHECK_EXECUTE(status, AddFunctionToMap(std::to_string(OHOS_CONTROL_AE_REGIONS), [weakThis, exposurePoint]() {
        auto sharedThis = weakThis.promote();
        if (!sharedThis) {
            MEDIA_ERR_LOG("SetMeteringPoint session is nullptr");
            return;
        }
        sharedThis->LockForControl();
        int32_t retCode = sharedThis->SetMeteringPoint(exposurePoint);
        sharedThis->UnlockForControl();
        CHECK_EXECUTE(retCode != CameraErrorCode::SUCCESS, sharedThis->SetDeviceCapabilityChangeStatus(true));
    }));
    CHECK_ERROR_PRINT_LOG(!status, "CaptureSession::SetExposurePoint Failed to set exposure Area");
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
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetMeteringPoint Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetMeteringPoint camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, CameraErrorCode::SUCCESS,
        "GetMeteringPoint camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_AE_REGIONS, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
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
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureBiasRange Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureBiasRange camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    if (!inputDeviceInfo) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureBiasRange camera device info is null");
        return CameraErrorCode::SUCCESS;
    }
    exposureBiasRange = inputDeviceInfo->GetExposureBiasRange();
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
    auto inputDevice = GetInputDevice();
    if (!inputDevice) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureBias camera device is null");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    if (!inputDeviceInfo) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureBias camera device info is null");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }
    std::vector<float> biasRange = inputDeviceInfo->GetExposureBiasRange();
    CHECK_ERROR_RETURN_RET_LOG(biasRange.empty(), CameraErrorCode::OPERATION_NOT_ALLOWED,
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

    int ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &exposureCompensation, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &exposureCompensation, count);
    }
    wptr<CaptureSession> weakThis(this);
    CHECK_EXECUTE(status, AddFunctionToMap(std::to_string(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION),
        [weakThis, exposureValue]() {
            auto sharedThis = weakThis.promote();
            if (!sharedThis) {
                MEDIA_ERR_LOG("SetExposureBias session is nullptr");
                return;
            }
            sharedThis->LockForControl();
            int32_t retCode = sharedThis->SetExposureBias(exposureValue);
            sharedThis->UnlockForControl();
            CHECK_EXECUTE(retCode != CameraErrorCode::SUCCESS, sharedThis->SetDeviceCapabilityChangeStatus(true));
        }));
    CHECK_ERROR_PRINT_LOG(!status, "CaptureSession::SetExposureValue Failed to set exposure compensation");
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
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureValue Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureValue camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, CameraErrorCode::SUCCESS,
        "GetExposureValue camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetExposureValue Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    int32_t exposureCompensation = item.data.i32[0];
    ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_AE_COMPENSATION_STEP, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, 0,
        "CaptureSession::GetExposureValue Failed with return code %{public}d", ret);
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
    std::vector<FocusMode> supportedFocusModes;
    GetSupportedFocusModes(supportedFocusModes);
    return supportedFocusModes;
}

int32_t CaptureSession::GetSupportedFocusModes(std::vector<FocusMode>& supportedFocusModes)
{
    supportedFocusModes.clear();
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("CaptureSession::SetExposureBias Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedFocusModes camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, CameraErrorCode::SUCCESS,
        "GetSupportedFocusModes camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FOCUS_MODES, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedFocusModes Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = g_metaFocusModeMap_.find(static_cast<camera_focus_mode_enum_t>(item.data.u8[i]));
        if (itr != g_metaFocusModeMap_.end()) {
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
    bool isSupported = false;
    IsFocusModeSupported(focusMode, isSupported);
    return isSupported;
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
    CHECK_AND_RETURN_RET(IsFocusModeSupported(focusMode), CameraErrorCode::OPERATION_NOT_ALLOWED);
    uint8_t focus = FOCUS_MODE_LOCKED;
    auto itr = g_fwkFocusModeMap_.find(focusMode);
    if (itr == g_fwkFocusModeMap_.end()) {
        MEDIA_ERR_LOG("CaptureSession::SetFocusMode Unknown exposure mode");
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
    wptr<CaptureSession> weakThis(this);
    CHECK_EXECUTE(status, AddFunctionToMap(std::to_string(OHOS_CONTROL_FOCUS_MODE), [weakThis, focusMode]() {
        auto sharedThis = weakThis.promote();
        if (!sharedThis) {
            MEDIA_ERR_LOG("SetFocusMode session is nullptr");
            return;
        }
        sharedThis->LockForControl();
        int32_t retCode = sharedThis->SetFocusMode(focusMode);
        sharedThis->UnlockForControl();
        CHECK_EXECUTE(retCode != CameraErrorCode::SUCCESS, sharedThis->SetDeviceCapabilityChangeStatus(true));
    }));
    CHECK_ERROR_PRINT_LOG(!status, "CaptureSession::SetFocusMode Failed to set focus mode");
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
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusMode camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, CameraErrorCode::SUCCESS,
        "GetFocusMode camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_FOCUS_MODE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusMode Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    auto itr = g_metaFocusModeMap_.find(static_cast<camera_focus_mode_enum_t>(item.data.u8[0]));
    if (itr != g_metaFocusModeMap_.end()) {
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
    CHECK_ERROR_RETURN_RET_LOG(focusMode == FOCUS_MODE_CONTINUOUS_AUTO, CameraErrorCode::SUCCESS,
        "The current mode does not support setting the focus point.");
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
    wptr<CaptureSession> weakThis(this);
    CHECK_EXECUTE(status, AddFunctionToMap(std::to_string(OHOS_CONTROL_AF_REGIONS), [weakThis, focusPoint]() {
        auto sharedThis = weakThis.promote();
        if (!sharedThis) {
            MEDIA_ERR_LOG("SetFocusPoint session is nullptr");
            return;
        }
        sharedThis->LockForControl();
        int32_t retCode = sharedThis->SetFocusPoint(focusPoint);
        sharedThis->UnlockForControl();
        CHECK_EXECUTE(retCode != CameraErrorCode::SUCCESS, sharedThis->SetDeviceCapabilityChangeStatus(true));
    }));
    CHECK_ERROR_PRINT_LOG(!status, "CaptureSession::SetFocusPoint Failed to set Focus Area");
    return CameraErrorCode::SUCCESS;
}

Point CaptureSession::CoordinateTransform(Point point)
{
    MEDIA_DEBUG_LOG("CaptureSession::CoordinateTransform begin x: %{public}f, y: %{public}f", point.x, point.y);
    Point unifyPoint = point;
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::CoordinateTransform cameraInput is nullptr");
        return unifyPoint;
    }
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    if (!inputDeviceInfo) {
        MEDIA_ERR_LOG("CaptureSession::CoordinateTransform cameraInput is nullptr");
        return unifyPoint;
    }
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
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusPoint Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusPoint camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, CameraErrorCode::SUCCESS,
        "GetFocusPoint camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_AF_REGIONS, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
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
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocalLength Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocalLength camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, CameraErrorCode::SUCCESS,
        "GetFocalLength camera metadata is null");
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
    CHECK_ERROR_RETURN_LOG(ret != CAM_META_SUCCESS, "Camera not support Focus mode");
    MEDIA_DEBUG_LOG("Focus mode: %{public}d", item.data.u8[0]);
    auto it = g_metaFocusModeMap_.find(static_cast<camera_focus_mode_enum_t>(item.data.u8[0]));
    if (it != g_metaFocusModeMap_.end()) {
        ProcessFocusDistanceUpdates(result);
    }
    // continuous focus mode do not callback focusStateChange
    if (it == g_metaFocusModeMap_.end() || it->second != FOCUS_MODE_AUTO) {
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
        const int32_t duration = static_cast<int32_t>(metadataItem.data.ui32[0]);
        if (duration != prevDuration_.load()) {
            ((sptr<PhotoOutput> &)photoOutput_)->ProcessSnapshotDurationUpdates(duration);
        }
        prevDuration_ = duration;
    }
}

void CaptureSession::ProcessEffectSuggestionTypeUpdates(const std::shared_ptr<OHOS::Camera::CameraMetadata> &result)
    __attribute__((no_sanitize("cfi")))
{
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_CAMERA_EFFECT_SUGGESTION_TYPE, &item);
    CHECK_ERROR_RETURN(ret != CAM_META_SUCCESS);
    MEDIA_DEBUG_LOG("ProcessEffectSuggestionTypeUpdates EffectSuggestionType: %{public}d", item.data.u8[0]);
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    if (effectSuggestionCallback_ != nullptr) {
        auto itr = metaEffectSuggestionTypeMap_.find(static_cast<CameraEffectSuggestionType>(item.data.u8[0]));
        if (itr != metaEffectSuggestionTypeMap_.end()) {
            EffectSuggestionType type = itr->second;
            if (!effectSuggestionCallback_->isFirstReport && type == effectSuggestionCallback_->currentType) {
                MEDIA_DEBUG_LOG("EffectSuggestion type: no change");
                return;
            }
            effectSuggestionCallback_->isFirstReport = false;
            effectSuggestionCallback_->currentType = type;
            effectSuggestionCallback_->OnEffectSuggestionChange(type);
        }
    }
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
        CHECK_ERROR_RETURN_LOG(denominator == 0, "ProcessSensorExposureTimeChange error! divide by zero");
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
    CHECK_ERROR_RETURN_LOG(session == nullptr,
        "CaptureSession::CaptureSessionMetadataResultProcessor ProcessCallbacks but session is null");

    session->OnResultReceived(result);
    session->ProcessAutoFocusUpdates(result);
    session->ProcessMacroStatusChange(result);
    session->ProcessMoonCaptureBoostStatusChange(result);
    session->ProcessLowLightBoostStatusChange(result);
    session->ProcessSnapshotDurationUpdates(timestamp, result);
    session->ProcessAREngineUpdates(timestamp, result);
    session->ProcessEffectSuggestionTypeUpdates(result);
    session->ProcessLcdFlashStatusUpdates(result);
    session->ProcessTripodStatusChange(result);
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
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedFlashModes Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedFlashModes camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, CameraErrorCode::SUCCESS,
        "GetSupportedFlashModes camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FLASH_MODES, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedFlashModes Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
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
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetFlashMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetFlashMode camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, CameraErrorCode::SUCCESS,
        "GetFlashMode camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_FLASH_MODE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::GetFlashMode Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
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
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetFlashMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::SetFlashMode Need to call LockForControl() before setting camera properties");
        return CameraErrorCode::SUCCESS;
    }
    // flash for lightPainting
    if (GetMode() == SceneMode::LIGHT_PAINTING && flashMode == FlashMode::FLASH_MODE_OPEN) {
        uint8_t enableTrigger = 1;
        bool status = false;
        int32_t ret;
        uint32_t count = 1;
        camera_metadata_item_t item;
        MEDIA_DEBUG_LOG("CaptureSession::TriggerLighting once.");
        ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_LIGHT_PAINTING_FLASH, &item);
        if (ret == CAM_META_ITEM_NOT_FOUND) {
            MEDIA_DEBUG_LOG("CaptureSession::TriggerLighting failed to find OHOS_CONTROL_LIGHT_PAINTING_FLASH");
            status = changedMetadata_->addEntry(OHOS_CONTROL_LIGHT_PAINTING_FLASH, &enableTrigger, count);
        } else if (ret == CAM_META_SUCCESS) {
            MEDIA_DEBUG_LOG("CaptureSession::TriggerLighting success to find OHOS_CONTROL_LIGHT_PAINTING_FLASH");
            status = changedMetadata_->updateEntry(OHOS_CONTROL_LIGHT_PAINTING_FLASH, &enableTrigger, count);
        }
        CHECK_ERROR_RETURN_RET_LOG(!status, CameraErrorCode::SERVICE_FATL_ERROR,
            "CaptureSession::TriggerLighting Failed to trigger lighting");
        return CameraErrorCode::SUCCESS;
    }
    CHECK_AND_RETURN_RET(IsFlashModeSupported(flashMode), CameraErrorCode::OPERATION_NOT_ALLOWED);
    uint8_t flash = g_fwkFlashModeMap_.at(FLASH_MODE_CLOSE);
    auto itr = g_fwkFlashModeMap_.find(flashMode);
    if (itr == g_fwkFlashModeMap_.end()) {
        MEDIA_ERR_LOG("CaptureSession::SetFlashMode Unknown exposure mode");
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
    CHECK_ERROR_PRINT_LOG(!status, "CaptureSession::SetFlashMode Failed to set flash mode");
    wptr<CaptureSession> weakThis(this);
    AddFunctionToMap(std::to_string(OHOS_CONTROL_FLASH_MODE), [weakThis, flashMode]() {
        auto sharedThis = weakThis.promote();
        if (!sharedThis) {
            MEDIA_ERR_LOG("SetFlashMode session is nullptr");
            return;
        }
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
    bool hasFlash = false;
    HasFlash(hasFlash);
    return hasFlash;
}

int32_t CaptureSession::HasFlash(bool& hasFlash)
{
    hasFlash = false;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::HasFlash Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    std::vector<FlashMode> supportedFlashModeList = GetSupportedFlashModes();
    bool onlyHasCloseMode = supportedFlashModeList.size() == 1 && supportedFlashModeList[0] == FLASH_MODE_CLOSE;
    if (!supportedFlashModeList.empty() && !onlyHasCloseMode) {
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
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetZoomRatioRange Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }

    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetZoomRatioRange camera device is null");
        return CameraErrorCode::SUCCESS;
    }

    if (supportSpecSearch_) {
        MEDIA_INFO_LOG("spec search enter");
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
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, CameraErrorCode::SUCCESS,
        "GetZoomRatioRange camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_SCENE_ZOOM_CAP, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS || item.count == 0, 0,
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
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetZoomRatio Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
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
    int32_t ret = ((sptr<CameraInput>&)inputDevice)->GetCameraDevice()->GetStatus(metaIn, metaOut);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAMERA_OK, ServiceToCameraError(ret),
        "CaptureSession::GetZoomRatio Failed to Get ZoomRatio, errCode = %{public}d", ret);
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
    CHECK_ERROR_RETURN_RET_LOG(zoomRatio == 0, CameraErrorCode::SUCCESS,
        "CaptureSession::SetZoomRatio Invalid zoom ratio");

    int32_t ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_ZOOM_RATIO, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_ZOOM_RATIO, &zoomRatio, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_ZOOM_RATIO, &zoomRatio, count);
    }

    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::SetZoomRatio Failed to set zoom mode");
    } else {
        auto abilityContainer = GetCameraAbilityContainer();
        if (abilityContainer && supportSpecSearch_) {
            abilityContainer->FilterByZoomRatio(zoomRatio);
        }
        wptr<CaptureSession> weakThis(this);
        AddFunctionToMap(std::to_string(OHOS_CONTROL_ZOOM_RATIO), [weakThis, zoomRatio]() {
            auto sharedThis = weakThis.promote();
            if (!sharedThis) {
                MEDIA_ERR_LOG("SetZoomRatio session is nullptr");
                return;
            }
            sharedThis->LockForControl();
            int32_t retCode = sharedThis->SetZoomRatio(zoomRatio);
            sharedThis->UnlockForControl();
            CHECK_EXECUTE(retCode != CameraErrorCode::SUCCESS,
                          sharedThis->SetDeviceCapabilityChangeStatus(true));
        });
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
    CHECK_ERROR_PRINT_LOG(!status, "CaptureSession::SetSmoothZoom CaptureSession::PrepareZoom Failed to prepare zoom");
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
    CHECK_ERROR_PRINT_LOG(!status, "CaptureSession::UnPrepareZoom Failed to unPrepare zoom");
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetSmoothZoom(float targetZoomRatio, uint32_t smoothZoomType)
    __attribute__((no_sanitize("cfi")))
{
    CAMERA_SYNC_TRACE;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetSmoothZoom Session is not commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    int32_t minIndex = 0;
    int32_t maxIndex = 1;
    std::vector<float> zoomRange = GetZoomRatioRange();
    CHECK_ERROR_RETURN_RET_LOG(zoomRange.empty(), CameraErrorCode::SUCCESS,
        "CaptureSession::SetSmoothZoom Zoom range is empty");
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
            if (abilityContainer && supportSpecSearch_) {
                abilityContainer->FilterByZoomRatio(targetZoomRatio);
            }
        }
        std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
        if (smoothZoomCallback_ != nullptr) {
            smoothZoomCallback_->OnSmoothZoom(duration);
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

int32_t CaptureSession::GetZoomPointInfos(std::vector<ZoomPointInfo>& zoomPointInfoList)
{
    MEDIA_INFO_LOG("CaptureSession::GetZoomPointInfos is Called");
    zoomPointInfoList.clear();
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetZoomPointInfos Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetZoomPointInfos camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    if (!inputDeviceInfo) {
        MEDIA_ERR_LOG("CaptureSession::GetZoomPointInfos camera device info is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, CameraErrorCode::SUCCESS,
        "GetZoomPointInfos camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_EQUIVALENT_FOCUS, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS || item.count == 0, CameraErrorCode::SUCCESS,
        "GetZoomPointInfos Failed with return code:%{public}d, item.count:%{public}d", ret, item.count);
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
    if (GetInputDevice() == nullptr) {
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
    bool res = this->changedMetadata_->addEntry(OHOS_STATISTICS_FACE_DETECT_SWITCH, &objectType, count);
    CHECK_ERROR_PRINT_LOG(!res, "SetCaptureMetadataObjectTypes Failed to add detect object types to changed metadata");
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
    MEDIA_INFO_LOG(
        "CaptureSession GetMode currentMode_ = %{public}d, guestMode_ = %{public}d", currentMode_, guessMode_);
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
    SceneMode matchMode = SceneMode::NORMAL;
    std::vector<SceneMode> supportModes = {SceneMode::VIDEO, SceneMode::PORTRAIT, SceneMode::NIGHT};
    auto mode = std::find(supportModes.begin(), supportModes.end(), GetMode());
    if (mode != supportModes.end()) {
        matchMode = *mode;
    } else {
        MEDIA_ERR_LOG("CaptureSession::VerifyAbility need PortraitMode or Night or Video");
        return CAMERA_INVALID_ARG;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::VerifyAbility camera device is null");
        return CAMERA_INVALID_ARG;
    }

    ProcessProfilesAbilityId(matchMode);

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

void CaptureSession::ProcessProfilesAbilityId(const SceneMode supportModes)
{
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_LOG(!inputDevice, "ProcessProfilesAbilityId inputDevice is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_LOG(!inputDeviceInfo, "ProcessProfilesAbilityId inputDeviceInfo is null");
    std::vector<Profile> photoProfiles = inputDeviceInfo->modePhotoProfiles_[supportModes];
    std::vector<Profile> previewProfiles = inputDeviceInfo->modePreviewProfiles_[supportModes];
    MEDIA_INFO_LOG("photoProfiles size = %{public}zu, photoProfiles size = %{public}zu", photoProfiles.size(),
        previewProfiles.size());
    for (auto i : photoProfiles) {
        std::vector<uint32_t> ids = i.GetAbilityId();
        std::string abilityIds = Container2String(ids.begin(), ids.end());
        MEDIA_INFO_LOG("photoProfiles f(%{public}d), w(%{public}d), h(%{public}d), ability:(%{public}s)",
            i.GetCameraFormat(), i.GetSize().width, i.GetSize().height, abilityIds.c_str());
        if (i.GetCameraFormat() == photoProfile_.GetCameraFormat() &&
            i.GetSize().width == photoProfile_.GetSize().width &&
            i.GetSize().height == photoProfile_.GetSize().height) {
            if (i.GetAbilityId().empty()) {
                MEDIA_INFO_LOG("VerifyAbility::CreatePhotoOutput:: this size'abilityId is not exist");
                continue;
            }
            photoProfile_.abilityId_ = i.GetAbilityId();
            break;
        }
    }
    for (auto i : previewProfiles) {
        std::vector<uint32_t> ids = i.GetAbilityId();
        std::string abilityIds = Container2String(ids.begin(), ids.end());
        MEDIA_INFO_LOG("previewProfiles f(%{public}d), w(%{public}d), h(%{public}d), ability:(%{public}s)",
            i.GetCameraFormat(), i.GetSize().width, i.GetSize().height, abilityIds.c_str());
        if (i.GetCameraFormat() == previewProfile_.GetCameraFormat() &&
            i.GetSize().width == previewProfile_.GetSize().width &&
            i.GetSize().height == previewProfile_.GetSize().height) {
            if (i.GetAbilityId().empty()) {
                MEDIA_INFO_LOG("VerifyAbility::CreatePreviewOutput:: this size'abilityId is not exist");
                continue;
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
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedFilters camera device is null");
        return supportedFilters;
    }

    int ret = VerifyAbility(static_cast<uint32_t>(OHOS_ABILITY_SCENE_FILTER_TYPES));
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedFilters abilityId is NULL");
        return supportedFilters;
    }

    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, supportedFilters,
        "GetSupportedFilters camera metadata is null");
    camera_metadata_item_t item;
    ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_SCENE_FILTER_TYPES, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS || item.count == 0, supportedFilters,
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
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("CaptureSession::GetFilter Session is not Commited");
        return FilterType::NONE;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetFilter camera device is null");
        return FilterType::NONE;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, FilterType::NONE,
        "GetFilter camera metadata is null");
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
    CHECK_ERROR_PRINT_LOG(!status, "CaptureSession::setFilter Failed to set filter");
    return;
}

std::vector<BeautyType> CaptureSession::GetSupportedBeautyTypes()
{
    std::vector<BeautyType> supportedBeautyTypes = {};
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedBeautyTypes Session is not Commited");
        return supportedBeautyTypes;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedBeautyTypes camera device is null");
        return supportedBeautyTypes;
    }

    int ret = VerifyAbility(static_cast<uint32_t>(OHOS_ABILITY_SCENE_BEAUTY_TYPES));
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedBeautyTypes abilityId is NULL");
        return supportedBeautyTypes;
    }

    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, supportedBeautyTypes,
        "GetSupportedBeautyTypes camera metadata is null");
    camera_metadata_item_t item;
    ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_SCENE_BEAUTY_TYPES, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS || item.count == 0, supportedBeautyTypes,
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
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedBeautyRange Session is not Commited");
        return supportedBeautyRange;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedBeautyRange camera device is null");
        return supportedBeautyRange;
    }

    std::vector<BeautyType> supportedBeautyTypes = GetSupportedBeautyTypes();
    if (std::find(supportedBeautyTypes.begin(), supportedBeautyTypes.end(), beautyType) == supportedBeautyTypes.end()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedBeautyRange beautyType is NULL");
        return supportedBeautyRange;
    }

    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, supportedBeautyRange,
        "GetSupportedBeautyRange camera metadata is null");
    camera_metadata_item_t item;

    MEDIA_ERR_LOG("CaptureSession::GetSupportedBeautyRange: %{public}d", beautyType);

    int32_t beautyTypeAbility;
    auto itr = g_fwkBeautyAbilityMap_.find(beautyType);
    CHECK_ERROR_RETURN_RET_LOG(itr == g_fwkBeautyAbilityMap_.end(), supportedBeautyRange,
        "CaptureSession::GetSupportedBeautyRange Unknown beauty Type");
    beautyTypeAbility = itr->second;
    Camera::FindCameraMetadataItem(metadata->get(), beautyTypeAbility, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS || item.count == 0, supportedBeautyRange,
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
    bool status = false;
    int32_t ret;
    uint32_t count = 1;
    camera_metadata_item_t item;
    camera_device_metadata_tag_t metadata;

    auto metaItr = fwkBeautyControlMap_.find(beautyType);
    if (metaItr != fwkBeautyControlMap_.end()) {
        metadata = metaItr->second;
    }

    std::vector<int32_t> levelVec;
    if (beautyTypeAndRanges_.count(beautyType)) {
        levelVec = beautyTypeAndRanges_[beautyType];
    } else {
        levelVec = GetSupportedBeautyRange(beautyType);
    }

    CameraPosition usedAsCameraPosition = GetUsedAsPosition();
    MEDIA_INFO_LOG("CaptureSession::SetBeautyValue usedAsCameraPosition %{public}d", usedAsCameraPosition);
    if (CAMERA_POSITION_UNSPECIFIED == usedAsCameraPosition) {
        auto itrType = std::find(levelVec.cbegin(), levelVec.cend(), beautyLevel);
        if (itrType == levelVec.end()) {
            MEDIA_ERR_LOG("CaptureSession::SetBeautyValue: %{public}d not in beautyRanges", beautyLevel);
            return status;
        }
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
    CHECK_ERROR_RETURN_RET_LOG(!status, status, "CaptureSession::SetBeautyValue Failed to set beauty");
    beautyTypeAndLevels_[beautyType] = beautyLevel;
    return status;
}

CameraPosition CaptureSession::GetUsedAsPosition()
{
    CameraPosition usedAsCameraPosition = CAMERA_POSITION_UNSPECIFIED;
    auto inputDevice = GetInputDevice();
    if (inputDevice == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::GetUsedAsPosition input device is null");
        return usedAsCameraPosition;
    }
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    if (inputDevice == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::GetUsedAsPosition camera device info is null");
        return usedAsCameraPosition;
    }
    usedAsCameraPosition = inputDeviceInfo->usedAsCameraPosition_;
    return usedAsCameraPosition;
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

    CameraPosition usedAsCameraPosition = GetUsedAsPosition();
    MEDIA_INFO_LOG("CaptureSession::SetBeauty usedAsCameraPosition %{public}d", usedAsCameraPosition);
    if (CAMERA_POSITION_UNSPECIFIED == usedAsCameraPosition) {
        std::vector<BeautyType> supportedBeautyTypes = GetSupportedBeautyTypes();
        auto itr = std::find(supportedBeautyTypes.begin(), supportedBeautyTypes.end(), beautyType);
        if (itr == supportedBeautyTypes.end()) {
            MEDIA_ERR_LOG("CaptureSession::GetSupportedBeautyTypes abilityId is NULL");
            return;
        }
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
        CHECK_ERROR_PRINT_LOG(!status, "CaptureSession::SetBeauty AUTO_TYPE Failed to set beauty value");
        return;
    }

    auto itrType = g_fwkBeautyTypeMap_.find(beautyType);
    if (itrType != g_fwkBeautyTypeMap_.end()) {
        beauty = static_cast<uint8_t>(itrType->second);
    }

    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_BEAUTY_TYPE, &beauty, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_BEAUTY_TYPE, &beauty, count);
    }
    CHECK_ERROR_PRINT_LOG(!status, "CaptureSession::SetBeauty Failed to set beautyType control");
    status = SetBeautyValue(beautyType, value);
    CHECK_ERROR_PRINT_LOG(!status, "CaptureSession::SetBeauty Failed to set beauty value");
    return;
}

int32_t CaptureSession::GetBeauty(BeautyType beautyType)
{
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("CaptureSession::GetBeauty Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetBeauty camera device is null");
        return -1;
    }
    std::vector<BeautyType> supportedBeautyTypes = GetSupportedBeautyTypes();
    auto itr = std::find(supportedBeautyTypes.begin(), supportedBeautyTypes.end(), beautyType);
    if (itr == supportedBeautyTypes.end()) {
        MEDIA_ERR_LOG("CaptureSession::GetBeauty beautyType is NULL");
        return -1;
    }
    int32_t beautyLevel = 0;
    auto itrLevel = beautyTypeAndLevels_.find(beautyType);
    if (itrLevel != beautyTypeAndLevels_.end()) {
        beautyLevel = itrLevel->second;
    }

    return beautyLevel;
}

// focus distance
float CaptureSession::GetMinimumFocusDistance() __attribute__((no_sanitize("cfi")))
{
    float invalidDistance = 0.0;
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice, invalidDistance,
        "CaptureSession::GetMinimumFocusDistance camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET_LOG(!inputDeviceInfo, invalidDistance,
        "CaptureSession::GetMinimumFocusDistance camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, invalidDistance,
        "GetMinimumFocusDistance camera metadata is null");
    camera_metadata_item_t item;
    int32_t ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_LENS_INFO_MINIMUM_FOCUS_DISTANCE, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, invalidDistance,
        "CaptureSession::GetMinimumFocusDistance Failed with return code %{public}d", ret);
    float minimumFocusDistance = item.data.f[0];
    MEDIA_DEBUG_LOG("CaptureSession::GetMinimumFocusDistance minimumFocusDistance=%{public}f", minimumFocusDistance);
    return minimumFocusDistance;
}

void CaptureSession::ProcessFocusDistanceUpdates(const std::shared_ptr<Camera::CameraMetadata>& result)
{
    CHECK_ERROR_RETURN_LOG(!result, "CaptureSession::ProcessFocusDistanceUpdates camera metadata is null");
    camera_metadata_item_t item;
    int32_t ret = Camera::FindCameraMetadataItem(result->get(), OHOS_CONTROL_LENS_FOCUS_DISTANCE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("CaptureSession::ProcessFocusDistanceUpdates Failed with return code %{public}d", ret);
        return;
    }
    MEDIA_DEBUG_LOG("CaptureSession::ProcessFocusDistanceUpdates meta=%{public}f", item.data.f[0]);
    if (FloatIsEqual(GetMinimumFocusDistance(), 0.0)) {
        MEDIA_ERR_LOG("CaptureSession::ProcessFocusDistanceUpdates minimum distance is 0");
        return;
    }
    focusDistance_ = 1.0 - (item.data.f[0] / GetMinimumFocusDistance());
    MEDIA_DEBUG_LOG("CaptureSession::ProcessFocusDistanceUpdates focusDistance = %{public}f", focusDistance_);
    return;
}

int32_t CaptureSession::GetFocusDistance(float& focusDistance)
{
    focusDistance = 0.0;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusDistance Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetFocusDistance camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    focusDistance = focusDistance_;
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetFocusDistance(float focusDistance)
{
    CAMERA_SYNC_TRACE;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetFocusDistance Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    CHECK_ERROR_RETURN_RET_LOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::SetFocusDistance Need to call LockForControl before setting camera properties");
    bool status = false;
    uint32_t count = 1;
    int32_t ret;
    MEDIA_DEBUG_LOG("CaptureSession::SetFocusDistance app set focusDistance = %{public}f", focusDistance);
    camera_metadata_item_t item;
    if (focusDistance < 0) {
        focusDistance = 0.0;
    } else if (focusDistance > 1) {
        focusDistance = 1.0;
    }
    float value = (1 - focusDistance) * GetMinimumFocusDistance();
    focusDistance_ = focusDistance;
    MEDIA_DEBUG_LOG("CaptureSession::SetFocusDistance meta set focusDistance = %{public}f", value);
    ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_LENS_FOCUS_DISTANCE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_LENS_FOCUS_DISTANCE, &value, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_LENS_FOCUS_DISTANCE, &value, count);
    }
    wptr<CaptureSession> weakThis(this);
    CHECK_EXECUTE(status, AddFunctionToMap(std::to_string(OHOS_CONTROL_LENS_FOCUS_DISTANCE),
        [weakThis, focusDistance]() {
            auto sharedThis = weakThis.promote();
            if (!sharedThis) {
                MEDIA_ERR_LOG("SetFocusDistance session is nullptr");
                return;
            }
            sharedThis->LockForControl();
            int32_t retCode = sharedThis->SetFocusDistance(focusDistance);
            sharedThis->UnlockForControl();
            CHECK_EXECUTE(retCode != CameraErrorCode::SUCCESS, sharedThis->SetDeviceCapabilityChangeStatus(true));
        }));
    CHECK_ERROR_PRINT_LOG(!status, "CaptureSession::SetFocusDistance Failed to set");
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
            if (!sharedThis) {
                MEDIA_ERR_LOG("SetFrameRateRange session is nullptr");
                return;
            }
            int32_t retCode = sharedThis->SetFrameRateRange(frameRateRange);
            CHECK_EXECUTE(retCode != CameraErrorCode::SUCCESS, sharedThis->SetDeviceCapabilityChangeStatus(true));
        }));
    for (size_t i = 0; i < frameRateRange.size(); i++) {
        MEDIA_DEBUG_LOG("CaptureSession::SetFrameRateRange:index:%{public}zu->%{public}d", i, frameRateRange[i]);
    }
    this->UnlockForControl();
    CHECK_ERROR_RETURN_RET_LOG(!isSuccess, CameraErrorCode::SERVICE_FATL_ERROR, "Failed to SetFrameRateRange ");
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
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "CalculateExposureValue camera metadata is null");
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_AE_COMPENSATION_STEP, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, CameraErrorCode::OPERATION_NOT_ALLOWED,
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
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedColorSpaceInfo Session is not Commited");
        return colorSpaceInfo;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedColorSpaceInfo camera device is null");
        return colorSpaceInfo;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, colorSpaceInfo,
        "GetSupportedColorSpaceInfo camera metadata is null");
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
    auto captureSession = GetCaptureSession();
    if (captureSession) {
        errCode = captureSession->GetActiveColorSpace(colorSpace);
        if (errCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to GetActiveColorSpace! %{public}d", errCode);
        } else {
            MEDIA_INFO_LOG("CaptureSession::GetActiveColorSpace %{public}d", static_cast<int32_t>(colorSpace));
        }
    } else {
        MEDIA_ERR_LOG("CaptureSession::GetActiveColorSpace() captureSession is nullptr");
    }
    return ServiceToCameraError(errCode);
}

int32_t CaptureSession::SetColorSpace(ColorSpace colorSpace)
{
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("CaptureSession::SetColorSpace Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }

    auto captureSession = GetCaptureSession();
    CHECK_ERROR_RETURN_RET_LOG(!captureSession, CameraErrorCode::SERVICE_FATL_ERROR,
        "CaptureSession::SetColorSpace() captureSession is nullptr");
    CM_ColorSpaceType metaColorSpace;
    auto itr = g_fwkColorSpaceMap_.find(colorSpace);
    CHECK_ERROR_RETURN_RET_LOG(itr == g_fwkColorSpaceMap_.end(), CameraErrorCode::INVALID_ARGUMENT,
        "CaptureSession::SetColorSpace() map failed, %{public}d", static_cast<int32_t>(colorSpace));
    metaColorSpace = itr->second;
    CM_ColorSpaceType captureColorSpace = metaColorSpace;
    ColorSpaceInfo colorSpaceInfo = GetSupportedColorSpaceInfo();

    ColorSpace fwkCaptureColorSpace;
    auto it = g_metaColorSpaceMap_.find(captureColorSpace);
    CHECK_ERROR_RETURN_RET_LOG(it == g_metaColorSpaceMap_.end(), CameraErrorCode::INVALID_ARGUMENT,
        "CaptureSession::SetColorSpace, %{public}d map failed", static_cast<int32_t>(captureColorSpace));
    fwkCaptureColorSpace = it->second;
    if (ProcessCaptureColorSpace(colorSpaceInfo, fwkCaptureColorSpace) != CameraErrorCode::SUCCESS) {
        MEDIA_ERR_LOG("CaptureSession::SetDefaultColorSpace() is failed.");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    if (IsSessionConfiged()) {
        isColorSpaceSetted_ = true;
    }
    // 若session还未commit，则后续createStreams会把色域带下去；否则，SetColorSpace要走updateStreams
    MEDIA_DEBUG_LOG("CaptureSession::SetColorSpace, IsSessionCommited %{public}d", IsSessionCommited());
    int32_t errCode = captureSession->SetColorSpace(colorSpace, fwkCaptureColorSpace, IsSessionCommited());
    CHECK_ERROR_PRINT_LOG(errCode != CAMERA_OK, "Failed to SetColorSpace!, %{public}d", errCode);
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
        CHECK_ERROR_RETURN_RET_LOG(it == g_fwkColorSpaceMap_.end(), CameraErrorCode::INVALID_ARGUMENT,
            "CaptureSession::SetColorSpace, %{public}d map failed", static_cast<int32_t>(fwkCaptureColorSpace));
        metaColorSpace = it->second;
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
    CHECK_ERROR_RETURN_RET_LOG(it == g_metaColorSpaceMap_.end(), CameraErrorCode::INVALID_ARGUMENT,
        "CaptureSession::SetColorSpace, %{public}d map failed", static_cast<int32_t>(captureColorSpace));
    fwkCaptureColorSpace = it->second;
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
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedColorEffects camera device is null");
        return supportedColorEffects;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, supportedColorEffects,
        "GetSupportedColorEffects camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_SUPPORTED_COLOR_MODES, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, supportedColorEffects,
        "CaptureSession::GetSupportedColorEffects Failed with return code %{public}d", ret);
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = g_metaColorEffectMap_.find(static_cast<camera_xmage_color_type_t>(item.data.u8[i]));
        if (itr != g_metaColorEffectMap_.end()) {
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
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetColorEffect camera device is null");
        return colorEffect;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, colorEffect,
        "GetColorEffect camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_SUPPORTED_COLOR_MODES, &item);
    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG("CaptureSession::GetColorEffect Failed with return code %{public}d", ret);
        return colorEffect;
    }
    auto itr = g_metaColorEffectMap_.find(static_cast<camera_xmage_color_type_t>(item.data.u8[0]));
    if (itr != g_metaColorEffectMap_.end()) {
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
    auto itr = g_fwkColorEffectMap_.find(colorEffect);
    CHECK_ERROR_RETURN_LOG(itr == g_fwkColorEffectMap_.end(), "CaptureSession::SetColorEffect unknown is color effect");
    colorEffectTemp = itr->second;

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
    wptr<CaptureSession> weakThis(this);
    CHECK_EXECUTE(status, AddFunctionToMap(std::to_string(OHOS_CONTROL_SUPPORTED_COLOR_MODES),
        [weakThis, colorEffect]() {
            auto sharedThis = weakThis.promote();
            if (!sharedThis) {
                MEDIA_ERR_LOG("SetColorEffect session is nullptr");
                return;
            }
            sharedThis->LockForControl();
            sharedThis->SetColorEffect(colorEffect);
            sharedThis->UnlockForControl();
        }));
    CHECK_ERROR_PRINT_LOG(!status, "CaptureSession::SetColorEffect Failed to set color effect");
    return;
}

int32_t CaptureSession::GetSensorExposureTimeRange(std::vector<uint32_t> &sensorExposureTimeRange)
{
    sensorExposureTimeRange.clear();
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetSensorExposureTimeRange Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSensorExposureTimeRange camera device is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, CameraErrorCode::INVALID_ARGUMENT,
        "GetSensorExposureTimeRange camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_SENSOR_EXPOSURE_TIME_RANGE, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS || item.count == 0, CameraErrorCode::INVALID_ARGUMENT,
        "CaptureSession::GetSensorExposureTimeRange Failed with return code %{public}d", ret);

    int32_t numerator = 0;
    int32_t denominator = 0;
    uint32_t value = 0;
    constexpr int32_t timeUnit = 1000000;
    for (uint32_t i = 0; i < item.count; i++) {
        numerator = item.data.r[i].numerator;
        denominator = item.data.r[i].denominator;
        CHECK_ERROR_RETURN_RET_LOG(denominator == 0, CameraErrorCode::INVALID_ARGUMENT,
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
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetSensorExposureTime Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    CHECK_ERROR_RETURN_RET_LOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::SetSensorExposureTime Need to call LockForControl() before setting camera properties");
    MEDIA_DEBUG_LOG("CaptureSession::SetSensorExposureTime exposure: %{public}d", exposureTime);
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::SetSensorExposureTime camera device is null");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }
    std::vector<uint32_t> sensorExposureTimeRange;
    CHECK_ERROR_RETURN_RET_LOG((GetSensorExposureTimeRange(sensorExposureTimeRange) != CameraErrorCode::SUCCESS) &&
        sensorExposureTimeRange.empty(), CameraErrorCode::OPERATION_NOT_ALLOWED,
        "CaptureSession::SetSensorExposureTime range is empty");
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
    bool res = AddOrUpdateMetadata(changedMetadata_->get(), OHOS_CONTROL_SENSOR_EXPOSURE_TIME, &value, 1);
    wptr<CaptureSession> weakThis(this);
    CHECK_EXECUTE(res, AddFunctionToMap(std::to_string(OHOS_CONTROL_SENSOR_EXPOSURE_TIME), [weakThis, exposureTime]() {
        auto sharedThis = weakThis.promote();
        if (!sharedThis) {
            MEDIA_ERR_LOG("SetSensorExposureTime session is nullptr");
            return;
        }
        sharedThis->LockForControl();
        int32_t retCode = sharedThis->SetSensorExposureTime(exposureTime);
        sharedThis->UnlockForControl();
        CHECK_EXECUTE(retCode != CameraErrorCode::SUCCESS, sharedThis->SetDeviceCapabilityChangeStatus(true));
    }));
    CHECK_ERROR_PRINT_LOG(!res, "CaptureSession::SetSensorExposureTime Failed to set exposure compensation");
    exposureDurationValue_ = exposureTime;
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::GetSensorExposureTime(uint32_t &exposureTime)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetSensorExposureTime Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice) {
        MEDIA_ERR_LOG("CaptureSession::GetSensorExposureTime camera device is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    if (!inputDeviceInfo) {
        MEDIA_ERR_LOG("CaptureSession::GetSensorExposureTime camera deviceInfo is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = inputDeviceInfo->GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, CameraErrorCode::INVALID_ARGUMENT,
        "GetSensorExposureTime camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_SENSOR_EXPOSURE_TIME, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, CameraErrorCode::INVALID_ARGUMENT,
        "CaptureSession::GetSensorExposureTime Failed with return code %{public}d", ret);
    exposureTime = item.data.ui32[0];
    MEDIA_DEBUG_LOG("CaptureSession::GetSensorExposureTime exposureTime: %{public}d", exposureTime);
    return CameraErrorCode::SUCCESS;
}

bool CaptureSession::IsMacroSupported()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter IsMacroSupported");

    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("CaptureSession::IsMacroSupported Session is not Commited");
        return false;
    }
    auto inputDevice = GetInputDevice();
    if (inputDevice == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::IsMacroSupported camera device is null");
        return false;
    }
    auto deviceInfo = inputDevice->GetCameraDeviceInfo();
    if (deviceInfo == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::IsMacroSupported camera deviceInfo is null");
        return false;
    }
    if (supportSpecSearch_) {
        MEDIA_INFO_LOG("spec search enter");
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

    std::shared_ptr<Camera::CameraMetadata> metadata = deviceInfo->GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, false,
        "IsMacroSupported camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_CAMERA_MACRO_SUPPORTED, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS || item.count <= 0, false,
        "CaptureSession::IsMacroSupported Failed with return code %{public}d", ret);
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
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession Failed EnableMacro!, session not commited");
    CHECK_ERROR_RETURN_RET_LOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::EnableMacro Need to call LockForControl() before setting camera properties");
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
    } else {
        auto abilityContainer = GetCameraAbilityContainer();
        if (abilityContainer && supportSpecSearch_) {
            abilityContainer->FilterByMacro(isEnable);
        }
    }
    isSetMacroEnable_ = isEnable;
    return CameraErrorCode::SUCCESS;
}

bool CaptureSession::IsDepthFusionSupported()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter IsDepthFusionSupported");
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("CaptureSession::IsDepthFusionSupported Session is not Commited");
        return false;
    }
    auto inputDevice = GetInputDevice();
    if (inputDevice == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::IsDepthFusionSupported camera device is null");
        return false;
        }
    auto deviceInfo = inputDevice->GetCameraDeviceInfo();
    if (deviceInfo == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::IsDepthFusionSupported camera deviceInfo is null");
        return false;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = deviceInfo->GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, false,
        "IsDepthFusionSupported camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_CAPTURE_MACRO_DEPTH_FUSION_SUPPORTED, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS || item.count <= 0, false,
        "CaptureSession::IsDepthFusionSupported Failed with return code %{public}d", ret);
    auto supportResult = static_cast<bool>(item.data.u8[0]);
    return supportResult;
}

std::vector<float> CaptureSession::GetDepthFusionThreshold()
{
    std::vector<float> depthFusionThreshold;
    GetDepthFusionThreshold(depthFusionThreshold);
    return depthFusionThreshold;
}

int32_t CaptureSession::GetDepthFusionThreshold(std::vector<float>& depthFusionThreshold)
{
    MEDIA_DEBUG_LOG("Enter GetDepthFusionThreshold");
    depthFusionThreshold.clear();
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetDepthFusionThreshold Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetDepthFusionThreshold camera device is null");
        return CameraErrorCode::SUCCESS;
    }

    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, CameraErrorCode::SUCCESS,
        "GetDepthFusionThreshold camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(),
        OHOS_ABILITY_CAPTURE_MACRO_DEPTH_FUSION_ZOOM_RANGE, &item);
    const int32_t zoomRangeLength = 2;
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS || item.count < zoomRangeLength, 0,
        "CaptureSession::GetDepthFusionThreshold Failed with return code %{public}d, item.count = %{public}d", ret,
        item.count);
    float minDepthFusionZoom = 0.0;
    float maxDepthFusionZoom = 0.0;
    MEDIA_INFO_LOG("Capture marco depth fusion zoom range, min: %{public}f, max: %{public}f",
        item.data.f[0], item.data.f[1]);
    minDepthFusionZoom = item.data.f[0];
    maxDepthFusionZoom = item.data.f[1];
    depthFusionThreshold = {minDepthFusionZoom, maxDepthFusionZoom};
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::EnableDepthFusion(bool isEnable)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter EnableDepthFusion, isEnable:%{public}d", isEnable);
    if (!IsDepthFusionSupported()) {
        MEDIA_ERR_LOG("EnableDepthFusion IsDepthFusionSupported is false");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession Failed EnableDepthFusion!, session not commited");
    CHECK_ERROR_RETURN_RET_LOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::EnableDepthFusion Need to call LockForControl() before setting camera properties");
    bool status = false;
    int32_t ret;
    camera_metadata_item_t item;
    ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_CAPTURE_MACRO_DEPTH_FUSION, &item);
    uint8_t enableValue = static_cast<uint8_t>(isEnable ? 1 : 0);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_CAPTURE_MACRO_DEPTH_FUSION, &enableValue, 1);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_CAPTURE_MACRO_DEPTH_FUSION, &enableValue, 1);
    }
    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::EnableDepthFusion Failed to enable depth fusion");
    }
    isDepthFusionEnable_ = isEnable;
    return CameraErrorCode::SUCCESS;
}

bool CaptureSession::IsDepthFusionEnabled()
{
    return isDepthFusionEnable_;
}

std::shared_ptr<MoonCaptureBoostFeature> CaptureSession::GetMoonCaptureBoostFeature()
{
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET(inputDevice == nullptr, nullptr);
    auto deviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET(deviceInfo == nullptr, nullptr);
    auto deviceAbility = deviceInfo->GetCameraAbility();
    CHECK_ERROR_RETURN_RET(deviceAbility == nullptr, nullptr);

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
    CHECK_ERROR_RETURN_RET(feature == nullptr, false);
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
    CHECK_ERROR_PRINT_LOG(!status, "CaptureSession::EnableMoonCaptureBoost failed to enable moon capture boost");
    isSetMoonCaptureBoostEnable_ = isEnable;
    return CameraErrorCode::SUCCESS;
}

bool CaptureSession::IsLowLightBoostSupported()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter IsLowLightBoostSupported");
    CHECK_ERROR_RETURN_RET_LOG(!(IsSessionConfiged() || IsSessionCommited()), false,
        "CaptureSession::IsLowLightBoostSupported Session is not Commited!");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(
        inputDevice == nullptr, false, "CaptureSession::IsLowLightBoostSupported camera device is null");
    auto deviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET_LOG(
        deviceInfo == nullptr, false, "CaptureSession::IsLowLightBoostSupported camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = deviceInfo->GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, false,
        "IsLowLightBoostSupported camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_LOW_LIGHT_BOOST, &item);
    if (ret != CAM_META_SUCCESS || item.count <= 0) {
        MEDIA_ERR_LOG("CaptureSession::IsLowLightBoostSupported Failed with return code %{public}d", ret);
        return false;
    }
    const uint32_t step = 3;
    for (uint32_t i = 0; i < item.count - 1; i += step) {
        if (GetMode() == item.data.i32[i] && item.data.i32[i + 1] == 1) {
            return true;
        }
    }
    return false;
}

int32_t CaptureSession::EnableLowLightBoost(bool isEnable)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter EnableLowLightBoost, isEnable:%{public}d", isEnable);
    CHECK_AND_RETURN_RET_LOG(
        IsLowLightBoostSupported(), CameraErrorCode::OPERATION_NOT_ALLOWED, "Not support LowLightBoost");
    CHECK_AND_RETURN_RET_LOG(IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG, "Session is not Commited!");
    uint8_t enableValue = static_cast<uint8_t>(isEnable ? 1 : 0);
    if (!AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_LOW_LIGHT_BOOST, &enableValue, 1)) {
        MEDIA_ERR_LOG("CaptureSession::EnableLowLightBoost failed to enable low light boost");
    } else {
        isSetLowLightBoostEnable_ = isEnable;
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::EnableLowLightDetection(bool isEnable)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter EnableLowLightDetection, isEnable:%{public}d", isEnable);
    CHECK_AND_RETURN_RET_LOG(
        IsLowLightBoostSupported(), CameraErrorCode::OPERATION_NOT_ALLOWED, "Not support LowLightBoost");
    CHECK_AND_RETURN_RET_LOG(IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG, "Session is not Commited!");
    uint8_t enableValue = static_cast<uint8_t>(isEnable ? 1 : 0);
    if (!AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_LOW_LIGHT_DETECT, &enableValue, 1)) {
        MEDIA_ERR_LOG("CaptureSession::EnableLowLightDetection failed to enable low light detect");
    }
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
        case FEATURE_TRIPOD_DETECTION:
            return IsTripodDetectionSupported();
            break;
        case FEATURE_LOW_LIGHT_BOOST:
            return IsLowLightBoostSupported();
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
        default:
            retCode = INVALID_ARGUMENT;
    }
    UnlockForControl();
    return retCode;
}

bool CaptureSession::IsMovingPhotoSupported()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter IsMovingPhotoSupported");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(inputDevice == nullptr, false,
        "CaptureSession::IsMovingPhotoSupported camera device is null");
    auto deviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET_LOG(deviceInfo == nullptr, false,
        "CaptureSession::IsMovingPhotoSupported camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = deviceInfo->GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, false,
        "IsMovingPhotoSupported camera metadata is null");
    camera_metadata_item_t metadataItem;
    vector<int32_t> modes = {};
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_MOVING_PHOTO, &metadataItem);
    if (ret == CAM_META_SUCCESS && metadataItem.count > 0) {
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
}

int32_t CaptureSession::EnableMovingPhoto(bool isEnable)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("Enter EnableMovingPhoto, isEnable:%{public}d", isEnable);
    CHECK_ERROR_RETURN_RET_LOG(!IsMovingPhotoSupported(), CameraErrorCode::SERVICE_FATL_ERROR,
        "IsMovingPhotoSupported is false");
    CHECK_ERROR_RETURN_RET_LOG(!(IsSessionConfiged() || IsSessionCommited()), CameraErrorCode::SERVICE_FATL_ERROR,
        "CaptureSession Failed EnableMovingPhoto!, session not configed");
    bool status = false;
    int32_t ret;
    camera_metadata_item_t item;
    ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_MOVING_PHOTO, &item);
    uint8_t enableValue = static_cast<uint8_t>(isEnable ? OHOS_CAMERA_MOVING_PHOTO_ON : OHOS_CAMERA_MOVING_PHOTO_OFF);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_MOVING_PHOTO, &enableValue, 1);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_MOVING_PHOTO, &enableValue, 1);
    }
    wptr<CaptureSession> weakThis(this);
    CHECK_EXECUTE(status, AddFunctionToMap(std::to_string(OHOS_CONTROL_MOVING_PHOTO), [weakThis, isEnable]() {
        auto sharedThis = weakThis.promote();
        if (!sharedThis) {
            MEDIA_ERR_LOG("EnableMovingPhoto session is nullptr");
            return;
        }
        sharedThis->LockForControl();
        int32_t retCode = sharedThis->EnableMovingPhoto(isEnable);
        sharedThis->UnlockForControl();
        CHECK_EXECUTE(retCode != CameraErrorCode::SUCCESS, sharedThis->SetDeviceCapabilityChangeStatus(true));
    }));
    CHECK_ERROR_PRINT_LOG(!status, "CaptureSession::EnableMovingPhoto Failed to enable");
    auto captureSession = GetCaptureSession();
    CHECK_ERROR_RETURN_RET_LOG(captureSession == nullptr, CameraErrorCode::INVALID_ARGUMENT,
        "CaptureSession::EnableMovingPhoto() captureSession is nullptr");
    int32_t errCode = captureSession->EnableMovingPhoto(isEnable);
    CHECK_ERROR_RETURN_RET_LOG(errCode != CAMERA_OK, errCode, "Failed to EnableMovingPhoto!, %{public}d", errCode);
    isMovingPhotoEnabled_ = isEnable;
    return CameraErrorCode::SUCCESS;
}

bool CaptureSession::IsMovingPhotoEnabled()
{
    return isMovingPhotoEnabled_;
}

int32_t CaptureSession::EnableMovingPhotoMirror(bool isMirror)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("EnableMovingPhotoMirror %{public}d", isMirror);
    if (!IsMovingPhotoSupported()) {
        MEDIA_ERR_LOG("IsMovingPhotoSupported is false");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    auto captureSession = GetCaptureSession();
    if (captureSession) {
        int32_t errCode = captureSession->EnableMovingPhotoMirror(isMirror);
        if (errCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to StartMovingPhotoCapture!, %{public}d", errCode);
        }
    } else {
        MEDIA_ERR_LOG("CaptureSession::StartMovingPhotoCapture captureSession is nullptr");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    return CameraErrorCode::SUCCESS;
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
    __attribute__((no_sanitize("cfi")))
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
    __attribute__((no_sanitize("cfi")))
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

void CaptureSession::ProcessLowLightBoostStatusChange(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Entry ProcessLowLightBoostStatusChange");

    auto featureStatusCallback = GetFeatureDetectionStatusCallback();
    if (featureStatusCallback == nullptr ||
        !featureStatusCallback->IsFeatureSubscribed(SceneFeature::FEATURE_LOW_LIGHT_BOOST)) {
        MEDIA_DEBUG_LOG("CaptureSession::ProcessLowLightBoostStatusChange featureStatusCallback is null");
        return;
    }

    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_STATUS_LOW_LIGHT_DETECTION, &item);
    if (ret != CAM_META_SUCCESS || item.count <= 0) {
        MEDIA_DEBUG_LOG("Camera not support low light detection");
        return;
    }
    auto isLowLightActive = static_cast<bool>(item.data.u8[0]);
    MEDIA_DEBUG_LOG("LowLight active: %{public}d", isLowLightActive);

    auto detectStatus = isLowLightActive ? FeatureDetectionStatusCallback::FeatureDetectionStatus::ACTIVE
                                         : FeatureDetectionStatusCallback::FeatureDetectionStatus::IDLE;
    if (!featureStatusCallback->UpdateStatus(SceneFeature::FEATURE_LOW_LIGHT_BOOST, detectStatus)) {
        MEDIA_DEBUG_LOG("Feature detect LowLight mode: no change");
        return;
    }
    featureStatusCallback->OnFeatureDetectionStatusChanged(SceneFeature::FEATURE_LOW_LIGHT_BOOST, detectStatus);
}

bool CaptureSession::IsSetEnableMacro()
{
    return isSetMacroEnable_;
}

bool CaptureSession::ValidateOutputProfile(Profile& outputProfile, CaptureOutputType outputType)
{
    MEDIA_INFO_LOG(
        "CaptureSession::ValidateOutputProfile profile:w(%{public}d),h(%{public}d),f(%{public}d) outputType:%{public}d",
        outputProfile.size_.width, outputProfile.size_.height, outputProfile.format_, outputType);
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice, false,
        "CaptureSession::ValidateOutputProfile Failed inputDevice is nullptr");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET_LOG(!inputDeviceInfo, false,
        "CaptureSession::ValidateOutputProfile Failed inputDeviceInfo is nullptr");
    if (outputType == CAPTURE_OUTPUT_TYPE_METADATA) {
        MEDIA_INFO_LOG("CaptureSession::ValidateOutputProfile MetadataOutput");
        return true;
    }
    if (outputType == CAPTURE_OUTPUT_TYPE_DEPTH_DATA) {
        MEDIA_INFO_LOG("CaptureSession::ValidateOutputProfile DepthDataOutput");
        return true;
    }
    auto modeName = GetMode();
    auto validateOutputProfileFunc = [modeName](auto validateProfile, auto& profiles) -> bool {
        MEDIA_INFO_LOG("CaptureSession::ValidateOutputProfile in mode(%{public}d): "
                       "w(%{public}d),h(%{public}d),f(%{public}d), profiles size is:%{public}zu",
            static_cast<int32_t>(modeName), validateProfile.size_.width, validateProfile.size_.height,
            validateProfile.format_, profiles.size());
        bool result = std::any_of(profiles.begin(), profiles.end(), [&validateProfile](const auto& profile) {
            MEDIA_INFO_LOG("CaptureSession::ValidateOutputProfile outType iterator "
                            "profile::w(%{public}d),h(%{public}d),f(%{public}d)",
                profile.size_.width, profile.size_.height, profile.format_);
            return validateProfile == profile;
        });
        CHECK_ERROR_PRINT_LOG(!result, "CaptureSession::ValidateOutputProfile fail!");
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
    CHECK_ERROR_PRINT_LOG(!status, "CaptureSession::enableDeferredType Failed to set type!");
    int32_t errCode = this->UnlockForControl();
    if (errCode != CameraErrorCode::SUCCESS) {
        MEDIA_DEBUG_LOG("CaptureSession::EnableDeferredType Failed");
        return;
    }
    isDeferTypeSetted_ = isEnableByUser;
}

void CaptureSession::EnableAutoDeferredVideoEnhancement(bool isEnableByUser)
{
    MEDIA_INFO_LOG("EnableAutoDeferredVideoEnhancement isEnableByUser:%{public}d", isEnableByUser);
    if (IsSessionCommited()) {
        MEDIA_ERR_LOG("EnableAutoDeferredVideoEnhancement session has committed!");
        return;
    }
    this->LockForControl();
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("EnableAutoDeferredVideoEnhancement changedMetadata_ is NULL");
        return;
    }

    bool status = false;
    camera_metadata_item_t item;
    isVideoDeferred_ = isEnableByUser;
    int ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_AUTO_DEFERRED_VIDEO_ENHANCE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_AUTO_DEFERRED_VIDEO_ENHANCE, &isEnableByUser, 1);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_AUTO_DEFERRED_VIDEO_ENHANCE, &isEnableByUser, 1);
    }
    if (!status) {
        MEDIA_ERR_LOG("EnableAutoDeferredVideoEnhancement Failed to set type!");
    }
    int32_t errCode = this->UnlockForControl();
    if (errCode != CameraErrorCode::SUCCESS) {
        MEDIA_DEBUG_LOG("EnableAutoDeferredVideoEnhancement Failed");
    }
}

void CaptureSession::SetUserId()
{
    MEDIA_INFO_LOG("CaptureSession::SetUserId");
    CHECK_ERROR_RETURN_LOG(IsSessionCommited(), "CaptureSession::SetUserId session has committed!");
    this->LockForControl();
    CHECK_ERROR_RETURN_LOG(changedMetadata_ == nullptr, "CaptureSession::SetUserId changedMetadata_ is NULL");
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
    CHECK_ERROR_PRINT_LOG(!status, "CaptureSession::SetUserId Failed!");
    int32_t errCode = this->UnlockForControl();
    CHECK_ERROR_PRINT_LOG(errCode != CameraErrorCode::SUCCESS, "CaptureSession::SetUserId Failed");
}

int32_t CaptureSession::EnableAutoHighQualityPhoto(bool enabled)
{
    MEDIA_INFO_LOG("CaptureSession::EnableAutoHighQualityPhoto enabled:%{public}d", enabled);

    this->LockForControl();
    CHECK_ERROR_RETURN_RET_LOG(changedMetadata_ == nullptr, INVALID_ARGUMENT,
        "CaptureSession::EnableAutoHighQualityPhoto changedMetadata_ is NULL");

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
    wptr<CaptureSession> weakThis(this);
    CHECK_EXECUTE(status, AddFunctionToMap(std::to_string(OHOS_CONTROL_HIGH_QUALITY_MODE), [weakThis, enabled]() {
        auto sharedThis = weakThis.promote();
        if (!sharedThis) {
            MEDIA_ERR_LOG("EnableAutoHighQualityPhoto session is nullptr");
            return;
        }
        int32_t retCode = sharedThis->EnableAutoHighQualityPhoto(enabled);
        CHECK_EXECUTE(retCode != CameraErrorCode::SUCCESS, sharedThis->SetDeviceCapabilityChangeStatus(true));
    }));
    res = this->UnlockForControl();
    CHECK_ERROR_PRINT_LOG(res != CameraErrorCode::SUCCESS, "CaptureSession::EnableAutoHighQualityPhoto Failed");
    return res;
}

void CaptureSession::ExecuteAbilityChangeCallback() __attribute__((no_sanitize("cfi")))
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    if (abilityCallback_ != nullptr) {
        abilityCallback_->OnAbilityChange();
    }
}

int32_t CaptureSession::EnableAutoCloudImageEnhancement(bool enabled)
{
    MEDIA_INFO_LOG("CaptureSession::EnableAutoCloudImageEnhancement enabled:%{public}d", enabled);

    LockForControl();
    
    int32_t res = CameraErrorCode::SUCCESS;
    bool status = false;
    camera_metadata_item_t item;
    uint8_t AutoCloudImageEnhanceEnable = static_cast<uint8_t>(enabled);
    int ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_AUTO_CLOUD_IMAGE_ENHANCE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_AUTO_CLOUD_IMAGE_ENHANCE, &AutoCloudImageEnhanceEnable, 1);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_AUTO_CLOUD_IMAGE_ENHANCE, &AutoCloudImageEnhanceEnable, 1);
    }
    if (!status) {
        MEDIA_ERR_LOG("CaptureSession::EnableAutoCloudImageEnhancement Failed to set type!");
        res = INVALID_ARGUMENT;
    }
    UnlockForControl();
    if (res != CameraErrorCode::SUCCESS) {
        MEDIA_DEBUG_LOG("CaptureSession::EnableAutoCloudImageEnhancement Failed");
    }
    return res;
}

void CaptureSession::SetAbilityCallback(std::shared_ptr<AbilityCallback> abilityCallback)
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    abilityCallback_ = abilityCallback;
}

void CaptureSession::SetEffectSuggestionCallback(std::shared_ptr<EffectSuggestionCallback> effectSuggestionCallback)
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    effectSuggestionCallback_ = effectSuggestionCallback;
}

std::shared_ptr<OHOS::Camera::CameraMetadata> CaptureSession::GetMetadata()
{
    auto inputDevice = GetInputDevice();
    if (inputDevice == nullptr) {
        MEDIA_INFO_LOG("CaptureSession::GetMetadata inputDevice is null, create default metadata");
        return std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    }
    auto deviceInfo = inputDevice->GetCameraDeviceInfo();
    if (deviceInfo == nullptr) {
        MEDIA_INFO_LOG("CaptureSession::GetMetadata deviceInfo is null, create default metadata");
        return std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    }
    return deviceInfo->GetMetadata();
}

int32_t CaptureSession::SetARMode(bool isEnable)
{
    MEDIA_INFO_LOG("CaptureSession::SetARMode");
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::SetARMode Session is not Commited");
    CHECK_ERROR_RETURN_RET_LOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::SetARMode Need to call LockForControl() before setting camera properties");

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

    CHECK_ERROR_RETURN_RET_LOG(!status, CameraErrorCode::SUCCESS,
        "CaptureSession::SetARMode Failed to set ar mode");
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::GetSensorSensitivityRange(std::vector<int32_t> &sensitivityRange)
{
    MEDIA_INFO_LOG("CaptureSession::GetSensorSensitivityRange");
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::GetSensorSensitivity fail due to Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice,
        CameraErrorCode::INVALID_ARGUMENT,
        "CaptureSession::GetSensorSensitivity fail due to camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET_LOG(!inputDeviceInfo, CameraErrorCode::INVALID_ARGUMENT,
        "CaptureSession::GetSensorSensitivity fail due to camera deviceInfo is null");
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = inputDeviceInfo->GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, CameraErrorCode::INVALID_ARGUMENT,
        "GetSensorSensitivity camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_SENSOR_INFO_SENSITIVITY_RANGE, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, CameraErrorCode::INVALID_ARGUMENT,
        "CaptureSession::GetSensorSensitivity Failed with return code %{public}d", ret);

    for (uint32_t i = 0; i < item.count; i++) {
        sensitivityRange.emplace_back(item.data.i32[i]);
    }

    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetSensorSensitivity(uint32_t sensitivity)
{
    MEDIA_INFO_LOG("CaptureSession::SetSensorSensitivity");
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::SetSensorSensitivity Session is not Commited");
    CHECK_ERROR_RETURN_RET_LOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::SetSensorSensitivity Need to call LockForControl() before setting camera properties");
    bool status = false;
    int32_t count = 1;
    camera_metadata_item_t item;
    MEDIA_DEBUG_LOG("CaptureSession::SetSensorSensitivity sensitivity: %{public}d", sensitivity);
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(),
        CameraErrorCode::OPERATION_NOT_ALLOWED, "CaptureSession::SetSensorSensitivity camera device is null");

    int ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), HAL_CUSTOM_SENSOR_SENSITIVITY, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(HAL_CUSTOM_SENSOR_SENSITIVITY, &sensitivity, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(HAL_CUSTOM_SENSOR_SENSITIVITY, &sensitivity, count);
    }
    CHECK_ERROR_PRINT_LOG(!status, "CaptureSession::SetSensorSensitivity Failed to set sensitivity");
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::GetModuleType(uint32_t &moduleType)
{
    MEDIA_INFO_LOG("CaptureSession::GetModuleType");
    CHECK_ERROR_RETURN_RET_LOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::GetModuleType fail due to Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice, CameraErrorCode::INVALID_ARGUMENT,
        "CaptureSession::GetModuleType fail due to camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET_LOG(!inputDeviceInfo, CameraErrorCode::INVALID_ARGUMENT,
        "CaptureSession::GetModuleType fail due to camera deviceInfo is null");
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = inputDeviceInfo->GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, CameraErrorCode::INVALID_ARGUMENT,
        "GetModuleType camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), HAL_CUSTOM_SENSOR_MODULE_TYPE, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, CameraErrorCode::INVALID_ARGUMENT,
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

bool CaptureSession::IsEffectSuggestionSupported()
{
    MEDIA_DEBUG_LOG("Enter IsEffectSuggestionSupported");
    return !this->GetSupportedEffectSuggestionType().empty();
}

int32_t CaptureSession::EnableEffectSuggestion(bool isEnable)
{
    MEDIA_DEBUG_LOG("Enter EnableEffectSuggestion, isEnable:%{public}d", isEnable);
    CHECK_ERROR_RETURN_RET_LOG(!IsEffectSuggestionSupported(), CameraErrorCode::OPERATION_NOT_ALLOWED,
        "EnableEffectSuggestion IsEffectSuggestionSupported is false");
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession Failed EnableEffectSuggestion!, session not commited");
    bool status = false;
    int32_t ret;
    camera_metadata_item_t item;
    ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_EFFECT_SUGGESTION, &item);
    uint8_t enableValue = static_cast<uint8_t>(isEnable);
    MEDIA_DEBUG_LOG("EnableEffectSuggestion enableValue:%{public}d", enableValue);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_EFFECT_SUGGESTION, &enableValue, 1);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_EFFECT_SUGGESTION, &enableValue, 1);
    }
    CHECK_ERROR_PRINT_LOG(!status, "CaptureSession::EnableEffectSuggestion Failed to enable effectSuggestion");
    return CameraErrorCode::SUCCESS;
}

EffectSuggestionInfo CaptureSession::GetSupportedEffectSuggestionInfo()
{
    EffectSuggestionInfo effectSuggestionInfo = {};
    CHECK_ERROR_RETURN_RET_LOG(!(IsSessionCommited() || IsSessionConfiged()), effectSuggestionInfo,
        "CaptureSession::GetSupportedEffectSuggestionInfo Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), effectSuggestionInfo,
        "CaptureSession::GetSupportedEffectSuggestionInfo camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, effectSuggestionInfo,
        "GetSupportedEffectSuggestionInfo camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_EFFECT_SUGGESTION_SUPPORTED, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, effectSuggestionInfo,
        "CaptureSession::GetSupportedEffectSuggestionInfo Failed with return code %{public}d", ret);

    std::shared_ptr<EffectSuggestionInfoParse> infoParse = std::make_shared<EffectSuggestionInfoParse>();
    MEDIA_INFO_LOG("CaptureSession::GetSupportedEffectSuggestionInfo item.count %{public}d", item.count);
    infoParse->GetEffectSuggestionInfo(item.data.i32, item.count, effectSuggestionInfo);
    return effectSuggestionInfo;
}

std::vector<EffectSuggestionType> CaptureSession::GetSupportedEffectSuggestionType()
{
    std::vector<EffectSuggestionType> supportedEffectSuggestionList = {};
    EffectSuggestionInfo effectSuggestionInfo = this->GetSupportedEffectSuggestionInfo();
    CHECK_ERROR_RETURN_RET_LOG(effectSuggestionInfo.modeCount == 0, supportedEffectSuggestionList,
        "CaptureSession::GetSupportedEffectSuggestionType Failed, effectSuggestionInfo is null");

    for (uint32_t i = 0; i < effectSuggestionInfo.modeCount; i++) {
        if (GetMode() != effectSuggestionInfo.modeInfo[i].modeType) {
            continue;
        }
        MEDIA_DEBUG_LOG("CaptureSession::GetSupportedEffectSuggestionType modeType %{public}d found.", GetMode());
        std::vector<int32_t> effectSuggestionList = effectSuggestionInfo.modeInfo[i].effectSuggestionList;
        supportedEffectSuggestionList.reserve(effectSuggestionList.size());
        for (uint32_t j = 0; j < effectSuggestionList.size(); j++) {
            auto itr = metaEffectSuggestionTypeMap_.find(
                static_cast<CameraEffectSuggestionType>(effectSuggestionList[j]));
            if (itr != metaEffectSuggestionTypeMap_.end()) {
                supportedEffectSuggestionList.emplace_back(itr->second);
            }
        }
        return supportedEffectSuggestionList;
    }
    MEDIA_ERR_LOG("no effectSuggestionInfo for mode %{public}d", GetMode());
    return supportedEffectSuggestionList;
}

int32_t CaptureSession::SetEffectSuggestionStatus(std::vector<EffectSuggestionStatus> effectSuggestionStatusList)
{
    MEDIA_DEBUG_LOG("Enter SetEffectSuggestionStatus");
    CHECK_ERROR_RETURN_RET_LOG(!IsEffectSuggestionSupported(), CameraErrorCode::OPERATION_NOT_ALLOWED,
        "SetEffectSuggestionStatus IsEffectSuggestionSupported is false");
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession Failed SetEffectSuggestionStatus!, session not commited");
    bool status = false;
    int32_t ret;
    camera_metadata_item_t item;
    ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_EFFECT_SUGGESTION_DETECTION, &item);

    std::vector<uint8_t> vec = {};
    for (auto effectSuggestionStatus : effectSuggestionStatusList) {
        uint8_t type = fwkEffectSuggestionTypeMap_.at(EffectSuggestionType::EFFECT_SUGGESTION_NONE);
        auto itr = fwkEffectSuggestionTypeMap_.find(effectSuggestionStatus.type);
        if (itr == fwkEffectSuggestionTypeMap_.end()) {
            MEDIA_ERR_LOG("CaptureSession::SetEffectSuggestionStatus Unknown effectSuggestionType");
        } else {
            type = itr->second;
        }
        vec.emplace_back(type);
        vec.emplace_back(static_cast<uint8_t>(effectSuggestionStatus.status));
        MEDIA_DEBUG_LOG("CaptureSession::SetEffectSuggestionStatus type:%{public}u,status:%{public}u",
            type, static_cast<uint8_t>(effectSuggestionStatus.status));
    }
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_EFFECT_SUGGESTION_DETECTION, vec.data(), vec.size());
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_EFFECT_SUGGESTION_DETECTION, vec.data(), vec.size());
    }
    CHECK_ERROR_PRINT_LOG(!status, "CaptureSession::SetEffectSuggestionStatus Failed to Set effectSuggestionStatus");
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::UpdateEffectSuggestion(EffectSuggestionType effectSuggestionType, bool isEnable)
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::UpdateEffectSuggestion Session is not Commited");
    CHECK_ERROR_RETURN_RET_LOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::UpdateEffectSuggestion Need to call LockForControl() before setting camera properties");
    uint8_t type = fwkEffectSuggestionTypeMap_.at(EffectSuggestionType::EFFECT_SUGGESTION_NONE);
    auto itr = fwkEffectSuggestionTypeMap_.find(effectSuggestionType);
    CHECK_ERROR_RETURN_RET_LOG(itr == fwkEffectSuggestionTypeMap_.end(), CameraErrorCode::INVALID_ARGUMENT,
        "CaptureSession::UpdateEffectSuggestion Unknown effectSuggestionType");
    type = itr->second;

    bool status = false;
    std::vector<uint8_t> vec = {type, isEnable};
    camera_metadata_item_t item;
    MEDIA_DEBUG_LOG("CaptureSession::UpdateEffectSuggestion type:%{public}u,isEnable:%{public}u", type, isEnable);
    int ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_EFFECT_SUGGESTION_TYPE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_EFFECT_SUGGESTION_TYPE, vec.data(), vec.size());
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_EFFECT_SUGGESTION_TYPE, vec.data(), vec.size());
    }

    CHECK_ERROR_RETURN_RET_LOG(!status, CameraErrorCode::SUCCESS,
        "CaptureSession::UpdateEffectSuggestion Failed to set effectSuggestionType");
    return CameraErrorCode::SUCCESS;
}

// white balance mode
int32_t CaptureSession::GetSupportedWhiteBalanceModes(std::vector<WhiteBalanceMode> &supportedWhiteBalanceModes)
{
    supportedWhiteBalanceModes.clear();
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedWhiteBalanceModes Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedWhiteBalanceModes camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    if (!inputDeviceInfo) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedWhiteBalanceModes camera deviceInfo is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, CameraErrorCode::SUCCESS,
        "GetSupportedWhiteBalanceModes camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_AWB_MODES, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
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
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::IsFocusModeSupported Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
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
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetWhiteBalanceMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    CHECK_ERROR_RETURN_RET_LOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::SetWhiteBalanceMode Need to call LockForControl() before setting camera properties");
    uint8_t awbLock = OHOS_CAMERA_AWB_LOCK_OFF;
    bool res = false;
    if (mode == AWB_MODE_LOCKED) {
        awbLock = OHOS_CAMERA_AWB_LOCK_ON;
        res = AddOrUpdateMetadata(changedMetadata_->get(), OHOS_CONTROL_AWB_LOCK, &awbLock, 1);
        CHECK_ERROR_PRINT_LOG(!res, "CaptureSession::SetWhiteBalanceMode Failed to lock whiteBalance");
        return CameraErrorCode::SUCCESS;
    }
    res = AddOrUpdateMetadata(changedMetadata_->get(), OHOS_CONTROL_AWB_LOCK, &awbLock, 1);
    CHECK_ERROR_PRINT_LOG(!res, "CaptureSession::SetWhiteBalanceMode Failed to unlock whiteBalance");
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
        SetManualWhiteBalance(0);
    }
    res = AddOrUpdateMetadata(changedMetadata_->get(), OHOS_CONTROL_AWB_MODE, &whiteBalanceMode, 1);
    CHECK_ERROR_PRINT_LOG(!res, "CaptureSession::SetWhiteBalanceMode Failed to set WhiteBalance mode");
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::GetWhiteBalanceMode(WhiteBalanceMode &mode)
{
    mode = AWB_MODE_OFF;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetWhiteBalanceMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetWhiteBalanceMode camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, CameraErrorCode::INVALID_ARGUMENT,
        "GetWhiteBalanceMode metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_AWB_LOCK, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "CaptureSession::GetWhiteBalanceMode Failed with return code %{public}d", ret);
    if (item.data.u8[0] == OHOS_CAMERA_AWB_LOCK_ON) {
        mode = AWB_MODE_LOCKED;
        return CameraErrorCode::SUCCESS;
    }
    ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_AWB_MODE, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
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
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetManualWhiteBalanceRange Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice) {
        MEDIA_ERR_LOG("CaptureSession::GetManualWhiteBalanceRange camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    if (!inputDeviceInfo) {
        MEDIA_ERR_LOG("CaptureSession::GetManualWhiteBalanceRange camera deviceInfo is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, CameraErrorCode::SUCCESS,
        "GetManualWhiteBalanceRange camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_SENSOR_WB_VALUES, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "CaptureSession::GetManualWhiteBalanceRange Failed with return code %{public}d", ret);
    for (uint32_t i = 0; i < item.count; i++) {
        whiteBalanceRange.emplace_back(item.data.i32[i]);
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::IsManualWhiteBalanceSupported(bool &isSupported)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::IsManualWhiteBalanceSupported Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    std::vector<int32_t> whiteBalanceRange;
    this->GetManualWhiteBalanceRange(whiteBalanceRange);
    constexpr int32_t rangeSize = 2;
    isSupported = (whiteBalanceRange.size() == rangeSize);
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetManualWhiteBalance(int32_t wbValue)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::SetManualWhiteBalance Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    CHECK_ERROR_RETURN_RET_LOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSession::SetManualWhiteBalance Need to call LockForControl() before setting camera properties");
    WhiteBalanceMode mode;
    GetWhiteBalanceMode(mode);
    // WhiteBalanceMode::OFF
    CHECK_ERROR_RETURN_RET_LOG(mode != WhiteBalanceMode::AWB_MODE_OFF, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "CaptureSession::SetManualWhiteBalance Need to set WhiteBalanceMode off");
    int32_t minIndex = 0;
    int32_t maxIndex = 1;
    MEDIA_DEBUG_LOG("CaptureSession::SetManualWhiteBalance white balance: %{public}d", wbValue);
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::SetManualWhiteBalance camera device is null");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }
    std::vector<int32_t> whiteBalanceRange;
    this->GetManualWhiteBalanceRange(whiteBalanceRange);
    CHECK_ERROR_RETURN_RET_LOG(whiteBalanceRange.empty(), CameraErrorCode::OPERATION_NOT_ALLOWED,
        "CaptureSession::SetManualWhiteBalance Bias range is empty");

    if (wbValue != 0 && wbValue < whiteBalanceRange[minIndex]) {
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
    if (!AddOrUpdateMetadata(changedMetadata_->get(), OHOS_CONTROL_SENSOR_WB_VALUE, &wbValue, 1)) {
        MEDIA_ERR_LOG("SetManualWhiteBalance Failed to SetManualWhiteBalance");
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::GetManualWhiteBalance(int32_t &wbValue)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("CaptureSession::GetManualWhiteBalance Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetManualWhiteBalance camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    if (!inputDeviceInfo) {
        MEDIA_ERR_LOG("CaptureSession::GetManualWhiteBalance camera deviceInfo is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, CameraErrorCode::SUCCESS,
        "GetManualWhiteBalance camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_SENSOR_WB_VALUE, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
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
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("GetSupportedPhysicalApertures Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("GetSupportedPhysicalApertures camera device is null");
        return CameraErrorCode::SUCCESS;
    }

    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, CameraErrorCode::SUCCESS,
        "GetSupportedPhysicalApertures camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_CAMERA_PHYSICAL_APERTURE_RANGE, &item);
    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG("GetSupportedPhysicalApertures Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    std::vector<float> chooseModeRange = ParsePhysicalApertureRangeByMode(item, GetMode());
    constexpr int32_t minPhysicalApertureMetaSize = 3;
    if (chooseModeRange.size() < minPhysicalApertureMetaSize) {
        MEDIA_ERR_LOG("GetSupportedPhysicalApertures Failed meta format error");
        return CameraErrorCode::SUCCESS;
    }
    int32_t deviceCntPos = 1;
    int32_t supportedDeviceCount = static_cast<int32_t>(chooseModeRange[deviceCntPos]);
    CHECK_ERROR_RETURN_RET_LOG(supportedDeviceCount == 0, CameraErrorCode::SUCCESS,
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
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("GetSupportedVirtualApertures Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice) {
        MEDIA_ERR_LOG("GetSupportedVirtualApertures camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    if (!inputDeviceInfo) {
        MEDIA_ERR_LOG("GetSupportedVirtualApertures camera deviceInfo is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetMetadata();
    CHECK_ERROR_RETURN_RET(metadata == nullptr, CameraErrorCode::SUCCESS);
    camera_metadata_item_t item;
    int32_t ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_CAMERA_VIRTUAL_APERTURE_RANGE, &item);
    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG("GetSupportedVirtualApertures Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    for (uint32_t i = 0; i < item.count; i++) {
        apertures.emplace_back(item.data.f[i]);
    }
    return CameraErrorCode::SUCCESS;
}

std::vector<PortraitEffect> CaptureSession::GetSupportedPortraitEffects()
{
    std::vector<PortraitEffect> supportedPortraitEffects = {};
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedPortraitEffects Session is not Commited");
        return supportedPortraitEffects;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedPortraitEffects camera device is null");
        return supportedPortraitEffects;
    }

    int ret = VerifyAbility(static_cast<uint32_t>(OHOS_ABILITY_SCENE_PORTRAIT_EFFECT_TYPES));
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedPortraitEffects abilityId is NULL");
        return supportedPortraitEffects;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice->GetCameraDeviceInfo()->GetMetadata();
    if (metadata == nullptr) {
        return supportedPortraitEffects;
    }
    camera_metadata_item_t item;
    ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_SCENE_PORTRAIT_EFFECT_TYPES, &item);
    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedPortraitEffects Failed with return code %{public}d", ret);
        return supportedPortraitEffects;
    }
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
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("GetVirtualAperture Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice) {
        MEDIA_ERR_LOG("GetVirtualAperture camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    if (!inputDeviceInfo) {
        MEDIA_ERR_LOG("GetVirtualAperture camera deviceInfo is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, CameraErrorCode::SUCCESS,
        "GetVirtualAperture camera metadata is null");
    CHECK_ERROR_RETURN_RET(metadata == nullptr, CameraErrorCode::SUCCESS);
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_CAMERA_VIRTUAL_APERTURE_VALUE, &item);
    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG("GetVirtualAperture Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    aperture = item.data.f[0];
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetVirtualAperture(const float virtualAperture)
{
    CAMERA_SYNC_TRACE;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("SetVirtualAperture Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("SetVirtualAperture changedMetadata_ is NULL");
        return CameraErrorCode::SUCCESS;
    }
    std::vector<float> supportedVirtualApertures {};
    GetSupportedVirtualApertures(supportedVirtualApertures);
    auto res = std::find_if(supportedVirtualApertures.begin(), supportedVirtualApertures.end(),
        [&virtualAperture](const float item) { return FloatIsEqual(virtualAperture, item); });
    if (res == supportedVirtualApertures.end()) {
        MEDIA_ERR_LOG("current virtualAperture is not supported");
        return CameraErrorCode::SUCCESS;
    }
    bool status = false;
    uint32_t count = 1;
    camera_metadata_item_t item;
    MEDIA_DEBUG_LOG("SetVirtualAperture virtualAperture: %{public}f", virtualAperture);

    int32_t ret =
        Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_CAMERA_VIRTUAL_APERTURE_VALUE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_CAMERA_VIRTUAL_APERTURE_VALUE, &virtualAperture, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_CAMERA_VIRTUAL_APERTURE_VALUE, &virtualAperture, count);
    }
    CHECK_ERROR_PRINT_LOG(!status, "SetVirtualAperture Failed to set virtualAperture");
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::GetPhysicalAperture(float& physicalAperture)
{
    physicalAperture = 0.0;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("GetPhysicalAperture Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    auto inputDevice = GetInputDevice();
    if (!inputDevice || !inputDevice->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("GetPhysicalAperture camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    if (!inputDeviceInfo) {
        MEDIA_ERR_LOG("GetPhysicalAperture camera deviceInfo is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, CameraErrorCode::SUCCESS,
        "GetPhysicalAperture camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_CAMERA_PHYSICAL_APERTURE_VALUE, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS || item.count == 0, CameraErrorCode::SUCCESS,
        "GetPhysicalAperture Failed with return code %{public}d", ret);
    physicalAperture = item.data.f[0];
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::SetPhysicalAperture(float physicalAperture)
{
    CAMERA_SYNC_TRACE;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("SetPhysicalAperture Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("SetPhysicalAperture changedMetadata_ is NULL");
        return CameraErrorCode::SUCCESS;
    }
    MEDIA_DEBUG_LOG(
        "CaptureSession::SetPhysicalAperture physicalAperture = %{public}f", ConfusingNumber(physicalAperture));
    std::vector<std::vector<float>> physicalApertures;
    GetSupportedPhysicalApertures(physicalApertures);
    // physicalApertures size is one, means not support change
    CHECK_ERROR_RETURN_RET_LOG(physicalApertures.size() == 1, CameraErrorCode::SUCCESS,
        "SetPhysicalAperture not support");
    // accurately currentZoomRatio need smoothing zoom done
    float currentZoomRatio = GetZoomRatio();
    int zoomMinIndex = 0;
    auto it = std::find_if(physicalApertures.rbegin(), physicalApertures.rend(),
        [&currentZoomRatio, &zoomMinIndex](const std::vector<float> physicalApertureRange) {
            return (currentZoomRatio - physicalApertureRange[zoomMinIndex]) >= -std::numeric_limits<float>::epsilon();
        });
    float autoAperture = 0.0;
    CHECK_ERROR_RETURN_RET_LOG(it == physicalApertures.rend(), CameraErrorCode::SUCCESS,
        "current zoomRatio not supported in physical apertures zoom ratio");
    int physicalAperturesIndex = 2;
    auto res = std::find_if(std::next((*it).begin(), physicalAperturesIndex), (*it).end(),
        [&physicalAperture](
            const float physicalApertureTemp) { return FloatIsEqual(physicalAperture, physicalApertureTemp); });
    CHECK_ERROR_RETURN_RET_LOG((physicalAperture != autoAperture) && res == (*it).end(), CameraErrorCode::SUCCESS,
        "current physicalAperture is not supported");
    CHECK_ERROR_RETURN_RET_LOG(!AddOrUpdateMetadata(
        changedMetadata_->get(), OHOS_CONTROL_CAMERA_PHYSICAL_APERTURE_VALUE, &physicalAperture, 1),
        CameraErrorCode::SUCCESS, "SetPhysicalAperture Failed to set physical aperture");
    wptr<CaptureSession> weakThis(this);
    AddFunctionToMap(std::to_string(OHOS_CONTROL_CAMERA_PHYSICAL_APERTURE_VALUE), [weakThis, physicalAperture]() {
        auto sharedThis = weakThis.promote();
        if (!sharedThis) {
            MEDIA_ERR_LOG("SetPhysicalAperture session is nullptr");
            return;
        }
        sharedThis->LockForControl();
        int32_t retCode = sharedThis->SetPhysicalAperture(physicalAperture);
        sharedThis->UnlockForControl();
        CHECK_EXECUTE(retCode != CameraErrorCode::SUCCESS,
                      sharedThis->SetDeviceCapabilityChangeStatus(true));
    });
    apertureValue_ = physicalAperture;
    return CameraErrorCode::SUCCESS;
}

bool CaptureSession::IsLcdFlashSupported()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("IsLcdFlashSupported is called");
    CHECK_ERROR_RETURN_RET_LOG(!(IsSessionCommited() || IsSessionConfiged()), false,
        "IsLcdFlashSupported Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice, false,
        "IsLcdFlashSupported camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET_LOG(!inputDeviceInfo, false,
        "IsLcdFlashSupported camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, false,
        "IsLcdFlashSupported camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_LCD_FLASH, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, false,
        "IsLcdFlashSupported Failed with return code %{public}d", ret);
    MEDIA_INFO_LOG("IsLcdFlashSupported value: %{public}u", item.data.i32[0]);
    return item.data.i32[0] == 1;
}

int32_t CaptureSession::EnableLcdFlash(bool isEnable)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter EnableLcdFlash, isEnable:%{public}d", isEnable);
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "EnableLcdFlash session not commited");
    uint8_t enableValue = static_cast<uint8_t>(isEnable);
    if (!AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_LCD_FLASH, &enableValue, 1)) {
        MEDIA_ERR_LOG("EnableLcdFlash Failed to enable lcd flash");
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::EnableLcdFlashDetection(bool isEnable)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter EnableLcdFlashDetection, isEnable:%{public}d", isEnable);
    CHECK_ERROR_RETURN_RET_LOG(!IsLcdFlashSupported(), CameraErrorCode::OPERATION_NOT_ALLOWED,
        "EnableLcdFlashDetection IsLcdFlashSupported is false");
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "EnableLcdFlashDetection session not commited");
    uint8_t enableValue = static_cast<uint8_t>(isEnable);
    if (!AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_LCD_FLASH_DETECTION, &enableValue, 1)) {
        MEDIA_ERR_LOG("EnableLcdFlashDetection Failed to enable lcd flash detection");
    }
    return CameraErrorCode::SUCCESS;
}

void CaptureSession::ProcessLcdFlashStatusUpdates(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
    __attribute__((no_sanitize("cfi")))
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Entry ProcessLcdFlashStatusUpdates");

    auto statusCallback = GetLcdFlashStatusCallback();
    if (statusCallback == nullptr) {
        MEDIA_DEBUG_LOG("CaptureSession::ProcessLcdFlashStatusUpdates statusCallback is null");
        return;
    }
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_STATUS_LCD_FLASH_STATUS, &item);
    if (ret != CAM_META_SUCCESS || item.count <= 0) {
        MEDIA_DEBUG_LOG("Camera not support lcd flash");
        return;
    }
    constexpr uint32_t validCount = 2;
    if (item.count != validCount) {
        MEDIA_ERR_LOG("OHOS_STATUS_LCD_FLASH_STATUS invalid data size");
        return;
    }
    auto isLcdFlashNeeded = static_cast<bool>(item.data.i32[0]);
    auto lcdCompensation = item.data.i32[1];
    LcdFlashStatusInfo preLcdFlashStatusInfo = statusCallback->GetLcdFlashStatusInfo();
    if (preLcdFlashStatusInfo.isLcdFlashNeeded != isLcdFlashNeeded ||
        preLcdFlashStatusInfo.lcdCompensation != lcdCompensation) {
        LcdFlashStatusInfo lcdFlashStatusInfo;
        lcdFlashStatusInfo.isLcdFlashNeeded = isLcdFlashNeeded;
        lcdFlashStatusInfo.lcdCompensation = lcdCompensation;
        statusCallback->SetLcdFlashStatusInfo(lcdFlashStatusInfo);
        statusCallback->OnLcdFlashStatusChanged(lcdFlashStatusInfo);
    }
}

void CaptureSession::SetLcdFlashStatusCallback(std::shared_ptr<LcdFlashStatusCallback> lcdFlashStatusCallback)
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    lcdFlashStatusCallback_ = lcdFlashStatusCallback;
}

std::shared_ptr<LcdFlashStatusCallback> CaptureSession::GetLcdFlashStatusCallback()
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    return lcdFlashStatusCallback_;
}

void CaptureSession::EnableFaceDetection(bool enable)
{
    MEDIA_INFO_LOG("EnableFaceDetection enable: %{public}d", enable);
    CHECK_ERROR_RETURN_LOG(GetMetaOutput() == nullptr, "MetaOutput is null");
    if (!enable) {
        std::set<camera_face_detect_mode_t> objectTypes;
        SetCaptureMetadataObjectTypes(objectTypes);
        return;
    }
    sptr<MetadataOutput> metaOutput = static_cast<MetadataOutput*>(GetMetaOutput().GetRefPtr());
    CHECK_ERROR_RETURN_LOG(!metaOutput, "MetaOutput is null");
    std::vector<MetadataObjectType> metadataObjectTypes = metaOutput->GetSupportedMetadataObjectTypes();
    MEDIA_INFO_LOG("EnableFaceDetection SetCapturingMetadataObjectTypes objectTypes size = %{public}zu",
        metadataObjectTypes.size());
    metaOutput->SetCapturingMetadataObjectTypes(metadataObjectTypes);
}

bool CaptureSession::IsTripodDetectionSupported()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("Enter IsTripodDetectionSupported");
    CHECK_ERROR_RETURN_RET_LOG(!(IsSessionCommited() || IsSessionConfiged()), false,
        "CaptureSession::IsTripodDetectionSupported Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), false,
        "CaptureSession::IsTripodDetectionSupported camera device is null");
    auto deviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET_LOG(deviceInfo == nullptr, false,
        "CaptureSession::IsTripodDetectionSupported camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = deviceInfo->GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, false,
        "IsTripodDetectionSupported camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_TRIPOD_DETECTION, &item);
    if (ret != CAM_META_SUCCESS || item.count <= 0) {
        MEDIA_ERR_LOG("CaptureSession::IsTripodDetectionSupported Failed with return code %{public}d", ret);
        return false;
    }
    auto supportResult = static_cast<bool>(item.data.i32[0]);
    return supportResult;
}

int32_t CaptureSession::EnableTripodStabilization(bool isEnable)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("Enter EnableTripodStabilization, isEnable:%{public}d", isEnable);
    CHECK_ERROR_RETURN_RET_LOG(!IsTripodDetectionSupported(), CameraErrorCode::OPERATION_NOT_ALLOWED,
        "EnableTripodStabilization IsTripodDetectionSupported is false");
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG, "Session is not Commited");
    uint8_t enableValue = static_cast<uint8_t>(isEnable ? 1 : 0);
    if (!AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_TRIPOD_STABLITATION, &enableValue, 1)) {
        MEDIA_ERR_LOG("EnableTripodStabilization failed to enable tripod detection");
    } else {
        isSetTripodDetectionEnable_ = isEnable;
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSession::EnableTripodDetection(bool isEnable)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter EnableTripodDetection, isEnable:%{public}d", isEnable);
    CHECK_ERROR_RETURN_RET_LOG(!IsTripodDetectionSupported(), CameraErrorCode::OPERATION_NOT_ALLOWED,
        "EnableTripodDetection IsTripodDetectionSupported is false");
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSession::EnableTripodDetection Session is not Commited");
    uint8_t enableValue = static_cast<uint8_t>(isEnable ? 1 : 0);
    if (!AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_TRIPOD_DETECTION, &enableValue, 1)) {
        MEDIA_ERR_LOG("CaptureSession::EnableTripodDetection failed to enable tripod detection");
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
    if (ret != CAM_META_SUCCESS || item.count <= 0) {
        MEDIA_DEBUG_LOG("Camera not support tripod detection");
        return;
    }
    FwkTripodStatus tripodStatus = FwkTripodStatus::INVALID;
    auto itr = metaTripodStatusMap_.find(static_cast<TripodStatus>(item.data.u8[0]));
    if (itr == metaTripodStatusMap_.end()) {
        MEDIA_DEBUG_LOG("Tripod status not found");
        return;
    }
    tripodStatus = itr->second;
    MEDIA_DEBUG_LOG("Tripod status: %{public}d", tripodStatus);
    if (featureStatusCallback != nullptr &&
        featureStatusCallback->IsFeatureSubscribed(SceneFeature::FEATURE_TRIPOD_DETECTION) &&
        (static_cast<int>(featureStatusCallback->GetFeatureStatus()) != static_cast<int>(tripodStatus))) {
        auto detectStatus = FeatureDetectionStatusCallback::FeatureDetectionStatus::ACTIVE;
        featureStatusCallback->SetFeatureStatus(static_cast<int8_t>(tripodStatus));
        featureStatusCallback->OnFeatureDetectionStatusChanged(SceneFeature::FEATURE_TRIPOD_DETECTION, detectStatus);
    }
}

bool CaptureSession::IsAutoDeviceSwitchSupported()
{
    bool isFoldable = CameraManager::GetInstance()->GetIsFoldable();
    MEDIA_INFO_LOG("IsAutoDeviceSwitchSupported %{public}d.", isFoldable);
    return isFoldable;
}

int32_t CaptureSession::EnableAutoDeviceSwitch(bool isEnable)
{
    MEDIA_INFO_LOG("EnableAutoDeviceSwitch, isEnable:%{public}d", isEnable);
    CHECK_ERROR_RETURN_RET_LOG(!IsAutoDeviceSwitchSupported(), CameraErrorCode::OPERATION_NOT_ALLOWED,
        "The automatic switchover mode is not supported.");
    CHECK_ERROR_RETURN_RET_LOG(GetIsAutoSwitchDeviceStatus() == isEnable, CameraErrorCode::SUCCESS,
        "Repeat Settings.");
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
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionStarted(), false,
        "The switch device has failed because the session has not started.");
    auto captureInput = GetInputDevice();
    auto cameraInput = (sptr<CameraInput>&)captureInput;
    CHECK_ERROR_RETURN_RET_LOG(cameraInput == nullptr, false, "cameraInput is nullptr.");
    auto deviceiInfo = cameraInput->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET_LOG(!deviceiInfo ||
        (deviceiInfo->GetPosition() != CAMERA_POSITION_FRONT &&
        deviceiInfo->GetPosition() != CAMERA_POSITION_FOLD_INNER), false, "No need switch camera.");
    bool hasVideoOutput = StopVideoOutput();
    int32_t retCode = CameraErrorCode::SUCCESS;
    Stop();
    BeginConfig();
    RemoveInput(captureInput);
    cameraInput->Close();
    sptr<CameraDevice> cameraDeviceTemp = FindFrontCamera();
    CHECK_ERROR_RETURN_RET_LOG(cameraDeviceTemp == nullptr, false, "No front camera found.");
    sptr<ICameraDeviceService> deviceObj = nullptr;
    retCode = CameraManager::GetInstance()->CreateCameraDevice(cameraDeviceTemp->GetID(), &deviceObj);
    CHECK_ERROR_RETURN_RET_LOG(retCode != CameraErrorCode::SUCCESS, false,
        "SwitchDevice::CreateCameraDevice Create camera device failed.");
    cameraInput->SwitchCameraDevice(deviceObj, cameraDeviceTemp);
    retCode = cameraInput->Open();
    CHECK_ERROR_PRINT_LOG(retCode != CameraErrorCode::SUCCESS, "SwitchDevice::Open failed.");
    retCode = AddInput(captureInput);
    CHECK_ERROR_PRINT_LOG(retCode != CameraErrorCode::SUCCESS, "SwitchDevice::AddInput failed.");
    retCode = CommitConfig();
    CHECK_ERROR_PRINT_LOG(retCode != CameraErrorCode::SUCCESS, "SwitchDevice::CommitConfig failed.");
    ExecuteAllFunctionsInMap();
    retCode = Start();
    CHECK_ERROR_PRINT_LOG(retCode != CameraErrorCode::SUCCESS, "SwitchDevice::Start failed.");
    CHECK_EXECUTE(hasVideoOutput, StartVideoOutput());
    return true;
}

sptr<CameraDevice> CaptureSession::FindFrontCamera()
{
    auto cameraDeviceList = CameraManager::GetInstance()->GetSupportedCamerasWithFoldStatus();
    for (const auto& cameraDevice : cameraDeviceList) {
        if (cameraDevice->GetPosition() == CAMERA_POSITION_FRONT ||
            cameraDevice->GetPosition() == CAMERA_POSITION_FOLD_INNER) {
            return cameraDevice;
        }
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
            if (item && item->GetOutputType() == CAPTURE_OUTPUT_TYPE_VIDEO) {
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
            if (item && item->GetOutputType() == CAPTURE_OUTPUT_TYPE_VIDEO) {
                videoOutput = (sptr<VideoOutput>&)item;
                break;
            }
        }
    }
    if (videoOutput && videoOutput->IsVideoStarted()) {
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
    if (!GetIsAutoSwitchDeviceStatus() || !canAddFuncToMap_) {
        MEDIA_INFO_LOG("The automatic switching device is not enabled.");
        return;
    }
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
    CHECK_ERROR_RETURN_LOG(serviceProxy == nullptr,
        "CaptureSession::CreateAndSetFoldServiceCallback serviceProxy is null");
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    foldStatusCallback_ = new(std::nothrow) FoldCallback(this);
    CHECK_ERROR_RETURN_LOG(foldStatusCallback_ == nullptr,
        "CaptureSession::CreateAndSetFoldServiceCallback failed to new foldSvcCallback_!");
    int32_t retCode = serviceProxy->SetFoldStatusCallback(foldStatusCallback_, true);
    CHECK_ERROR_PRINT_LOG(retCode != CAMERA_OK,
        "CreateAndSetFoldServiceCallback Set service Callback failed, retCode: %{public}d", retCode);
}

void CaptureSession::SetUsage(UsageType usageType, bool enabled)
{
    CHECK_ERROR_RETURN_LOG(changedMetadata_ == nullptr,
        "CaptureSession::SetUsage Need to call LockForControl() before setting camera properties");
    std::vector<int32_t> mode;
 
    mode.push_back(static_cast<int32_t>(usageType));
    mode.push_back(
        static_cast<int32_t>(enabled ? OHOS_CAMERA_SESSION_USAGE_ENABLE : OHOS_CAMERA_SESSION_USAGE_DISABLE));
 
    bool status = changedMetadata_->addEntry(OHOS_CONTROL_CAMERA_SESSION_USAGE, mode.data(), mode.size());
 
    CHECK_ERROR_PRINT_LOG(!status, "CaptureSession::SetUsage Failed to set mode");
}
} // namespace CameraStandard
} // namespace OHOS
