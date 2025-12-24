/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "session/capture_session_for_sys.h"

#include "camera_log.h"
#include "metadata_common_utils.h"
#include "output/photo_output.h"

namespace OHOS {
namespace CameraStandard {

namespace {
constexpr float DEFAULT_EQUIVALENT_ZOOM = 100.0f;
constexpr uint32_t GUIDE_DATA_LENGTH = 8;
constexpr uint32_t POINT_DATA_LENGTH = 2;
// ConstellationDrawing
constexpr uint32_t STAR_DATA_LENGTH = 4;
constexpr uint32_t POSTION_X_OFFSET = 0;
constexpr uint32_t POSTION_Y_OFFSET = 1;
constexpr uint32_t SIZE_LEVEL_OFFSET = 2;
constexpr uint32_t BRIGHTNESS_LEVEL_OFFSET = 3;
constexpr uint32_t LINE_SEGMENTS_DATA_SIZE = 4;
constexpr uint32_t POINT_A_X_OFFSET = 0;
constexpr uint32_t POINT_A_Y_OFFSET = 1;
constexpr uint32_t POINT_B_X_OFFSET = 2;
constexpr uint32_t POINT_B_Y_OFFSET = 3;
constexpr uint32_t ID_OFFSET = 0;
constexpr uint32_t OPACITY_OFFSET = 1;
constexpr uint32_t CENTER_POINT_X_OFFSET = 2;
constexpr uint32_t CENTER_POINT_Y_OFFSET = 3;
} // namespace

const std::unordered_map<EffectSuggestionType, CameraEffectSuggestionType>
    CaptureSessionForSys::fwkEffectSuggestionTypeMap_ = {
    {EFFECT_SUGGESTION_NONE, OHOS_CAMERA_EFFECT_SUGGESTION_NONE},
    {EFFECT_SUGGESTION_PORTRAIT, OHOS_CAMERA_EFFECT_SUGGESTION_PORTRAIT},
    {EFFECT_SUGGESTION_FOOD, OHOS_CAMERA_EFFECT_SUGGESTION_FOOD},
    {EFFECT_SUGGESTION_SKY, OHOS_CAMERA_EFFECT_SUGGESTION_SKY},
    {EFFECT_SUGGESTION_SUNRISE_SUNSET, OHOS_CAMERA_EFFECT_SUGGESTION_SUNRISE_SUNSET},
    {EFFECT_SUGGESTION_STAGE, OHOS_CAMERA_EFFECT_SUGGESTION_STAGE}
};

CaptureSessionForSys::~CaptureSessionForSys()
{
    MEDIA_DEBUG_LOG("Enter Into CaptureSessionForSys::~CaptureSessionForSys()");
}

int32_t CaptureSessionForSys::IsFocusRangeTypeSupported(FocusRangeType focusRangeType, bool& isSupported)
{
    // LCOV_EXCL_START
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSessionForSys::IsFocusRangeTypeSupported Session is not Commited");
    CHECK_RETURN_RET_ELOG(g_fwkocusRangeTypeMap_.find(focusRangeType) == g_fwkocusRangeTypeMap_.end(),
        CameraErrorCode::PARAMETER_ERROR, "CaptureSessionForSys::IsFocusRangeTypeSupported Unknown focus range type");
    std::vector<FocusRangeType> vecSupportedFocusRangeTypeList = {};
    this->GetSupportedFocusRangeTypes(vecSupportedFocusRangeTypeList);
    if (find(vecSupportedFocusRangeTypeList.begin(), vecSupportedFocusRangeTypeList.end(), focusRangeType) !=
        vecSupportedFocusRangeTypeList.end()) {
        isSupported = true;
        return CameraErrorCode::SUCCESS;
    }
    isSupported = false;
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int32_t CaptureSessionForSys::GetFocusRange(FocusRangeType& focusRangeType)
{
    // LCOV_EXCL_START
    focusRangeType = FocusRangeType::FOCUS_RANGE_TYPE_AUTO;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSessionForSys::GetFocusRange Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::SUCCESS,
        "CaptureSessionForSys::GetFocusRange camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, CameraErrorCode::SUCCESS, "GetFocusRange camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_FOCUS_RANGE_TYPE, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "CaptureSessionForSys::GetFocusRange Failed with return code %{public}d", ret);
    auto itr = g_metaFocusRangeTypeMap_.find(static_cast<camera_focus_range_type_t>(item.data.u8[0]));
    if (itr != g_metaFocusRangeTypeMap_.end()) {
        focusRangeType = itr->second;
        return CameraErrorCode::SUCCESS;
    }
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int32_t CaptureSessionForSys::SetFocusRange(FocusRangeType focusRangeType)
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSessionForSys::SetFocusRange Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSessionForSys::SetFocusRange Need to call LockForControl() before setting camera properties");
    CHECK_RETURN_RET_ELOG(g_fwkocusRangeTypeMap_.find(focusRangeType) == g_fwkocusRangeTypeMap_.end(),
        CameraErrorCode::PARAMETER_ERROR, "CaptureSessionForSys::SetFocusRange Unknown focus range type");
    bool isSupported = false;
    IsFocusRangeTypeSupported(focusRangeType, isSupported);
    CHECK_RETURN_RET(!isSupported, CameraErrorCode::OPERATION_NOT_ALLOWED);
    uint8_t metaFocusRangeType = OHOS_CAMERA_FOCUS_RANGE_AUTO;
    auto itr = g_fwkocusRangeTypeMap_.find(focusRangeType);
    if (itr != g_fwkocusRangeTypeMap_.end()) {
        metaFocusRangeType = itr->second;
    }

    MEDIA_DEBUG_LOG("CaptureSessionForSys::SetFocusRange Focus range type: %{public}d", focusRangeType);
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_FOCUS_RANGE_TYPE, &metaFocusRangeType, 1);
    CHECK_PRINT_ELOG(!status, "CaptureSessionForSys::SetFocusRange Failed to set focus range type");
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int32_t CaptureSessionForSys::IsFocusDrivenTypeSupported(FocusDrivenType focusDrivenType, bool& isSupported)
{
    // LCOV_EXCL_START
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSessionForSys::IsFocusDrivenTypeSupported Session is not Commited");
    CHECK_RETURN_RET_ELOG(g_fwkFocusDrivenTypeMap_.find(focusDrivenType) == g_fwkFocusDrivenTypeMap_.end(),
        CameraErrorCode::PARAMETER_ERROR, "CaptureSessionForSys::IsFocusDrivenTypeSupported Unknown focus driven type");
    std::vector<FocusDrivenType> vecSupportedFocusDrivenTypeList = {};
    this->GetSupportedFocusDrivenTypes(vecSupportedFocusDrivenTypeList);
    if (find(vecSupportedFocusDrivenTypeList.begin(), vecSupportedFocusDrivenTypeList.end(), focusDrivenType) !=
        vecSupportedFocusDrivenTypeList.end()) {
        isSupported = true;
        return CameraErrorCode::SUCCESS;
    }
    isSupported = false;
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int32_t CaptureSessionForSys::GetFocusDriven(FocusDrivenType& focusDrivenType)
{
    // LCOV_EXCL_START
    focusDrivenType = FocusDrivenType::FOCUS_DRIVEN_TYPE_AUTO;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSessionForSys::GetFocusDriven Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::SUCCESS,
        "CaptureSessionForSys::GetFocusDriven camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, CameraErrorCode::SUCCESS, "GetFocusDriven camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_FOCUS_DRIVEN_TYPE, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "CaptureSessionForSys::GetFocusDriven Failed with return code %{public}d", ret);
    auto itr = g_metaFocusDrivenTypeMap_.find(static_cast<camera_focus_driven_type_t>(item.data.u8[0]));
    if (itr != g_metaFocusDrivenTypeMap_.end()) {
        focusDrivenType = itr->second;
        return CameraErrorCode::SUCCESS;
    }
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int32_t CaptureSessionForSys::SetFocusDriven(FocusDrivenType focusDrivenType)
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSessionForSys::SetFocusDriven Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSessionForSys::SetFocusDriven Need to call LockForControl() before setting camera properties");
    CHECK_RETURN_RET_ELOG(g_fwkFocusDrivenTypeMap_.find(focusDrivenType) == g_fwkFocusDrivenTypeMap_.end(),
        CameraErrorCode::PARAMETER_ERROR, "CaptureSessionForSys::SetFocusDriven Unknown focus driven type");
    bool isSupported = false;
    IsFocusDrivenTypeSupported(focusDrivenType, isSupported);
    CHECK_RETURN_RET(!isSupported, CameraErrorCode::OPERATION_NOT_ALLOWED);
    uint8_t metaFocusDrivenType = OHOS_CAMERA_FOCUS_DRIVEN_AUTO;
    auto itr = g_fwkFocusDrivenTypeMap_.find(focusDrivenType);
    if (itr != g_fwkFocusDrivenTypeMap_.end()) {
        metaFocusDrivenType = itr->second;
    }

    MEDIA_DEBUG_LOG("CaptureSessionForSys::SetFocusDriven focus driven type: %{public}d", focusDrivenType);
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_FOCUS_DRIVEN_TYPE, &metaFocusDrivenType, 1);
    CHECK_PRINT_ELOG(!status, "CaptureSessionForSys::SetFocusDriven Failed to set focus driven type");
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int32_t CaptureSessionForSys::GetSupportedColorReservationTypes(std::vector<ColorReservationType>& types)
{
    // LCOV_EXCL_START
    types.clear();
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSessionForSys::GetSupportedColorReservationTypes Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::SUCCESS,
        "CaptureSessionForSys::GetSupportedColorReservationTypes camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, CameraErrorCode::SUCCESS, "GetSupportedColorReservationTypes camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_COLOR_RESERVATION_TYPES, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "CaptureSessionForSys::GetSupportedColorReservationTypes Failed with return code %{public}d", ret);
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = g_metaColorReservationTypeMap_.find(static_cast<camera_color_reservation_type_t>(item.data.u8[i]));
        if (itr != g_metaColorReservationTypeMap_.end()) {
            types.emplace_back(itr->second);
        }
    }
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int32_t CaptureSessionForSys::IsColorReservationTypeSupported(ColorReservationType colorReservationType,
    bool& isSupported)
{
    // LCOV_EXCL_START
    CHECK_RETURN_RET_ELOG(
        g_fwkColorReservationTypeMap_.find(colorReservationType) == g_fwkColorReservationTypeMap_.end(),
        CameraErrorCode::PARAMETER_ERROR,
        "CaptureSessionForSys::IsColorReservationTypeSupported Unknown color reservation type");
    std::vector<ColorReservationType> vecSupportedColorReservationTypeList = {};
    this->GetSupportedColorReservationTypes(vecSupportedColorReservationTypeList);
    if (find(vecSupportedColorReservationTypeList.begin(), vecSupportedColorReservationTypeList.end(),
        colorReservationType) != vecSupportedColorReservationTypeList.end()) {
        isSupported = true;
        return CameraErrorCode::SUCCESS;
    }
    isSupported = false;
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int32_t CaptureSessionForSys::GetColorReservation(ColorReservationType& colorReservationType)
{
    // LCOV_EXCL_START
    colorReservationType = ColorReservationType::COLOR_RESERVATION_TYPE_NONE;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSessionForSys::GetColorReservation Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::SUCCESS,
        "CaptureSessionForSys::GetColorReservation camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, CameraErrorCode::SUCCESS, "GetColorReservation camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_COLOR_RESERVATION_TYPE, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "CaptureSessionForSys::GetColorReservation Failed with return code %{public}d", ret);
    auto itr = g_metaColorReservationTypeMap_.find(static_cast<camera_color_reservation_type_t>(item.data.u8[0]));
    if (itr != g_metaColorReservationTypeMap_.end()) {
        colorReservationType = itr->second;
        return CameraErrorCode::SUCCESS;
    }
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int32_t CaptureSessionForSys::SetColorReservation(ColorReservationType colorReservationType)
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSessionForSys::SetColorReservation Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSessionForSys::SetColorReservation Need to call LockForControl() before setting camera properties");
    CHECK_RETURN_RET_ELOG(
        g_fwkColorReservationTypeMap_.find(colorReservationType) == g_fwkColorReservationTypeMap_.end(),
        CameraErrorCode::PARAMETER_ERROR, "CaptureSessionForSys::SetColorReservation Unknown color reservation type");
    bool isSupported = false;
    IsColorReservationTypeSupported(colorReservationType, isSupported);
    CHECK_RETURN_RET(!isSupported, CameraErrorCode::OPERATION_NOT_ALLOWED);
    uint8_t metaColorReservationType = OHOS_CAMERA_COLOR_RESERVATION_NONE;
    auto itr = g_fwkColorReservationTypeMap_.find(colorReservationType);
    if (itr != g_fwkColorReservationTypeMap_.end()) {
        metaColorReservationType = itr->second;
    }

    MEDIA_DEBUG_LOG("CaptureSessionForSys::SetColorReservation color reservation type: %{public}d",
        colorReservationType);
    bool status = AddOrUpdateMetadata(
        changedMetadata_, OHOS_CONTROL_COLOR_RESERVATION_TYPE, &metaColorReservationType, 1);
    CHECK_PRINT_ELOG(!status, "CaptureSessionForSys::SetColorReservation Failed to set color reservation type");
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int32_t CaptureSessionForSys::GetZoomPointInfos(std::vector<ZoomPointInfo>& zoomPointInfoList)
{
    // LCOV_EXCL_START
    MEDIA_INFO_LOG("CaptureSessionForSys::GetZoomPointInfos is Called");
    zoomPointInfoList.clear();
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSessionForSys::GetZoomPointInfos Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::SUCCESS,
        "CaptureSessionForSys::GetZoomPointInfos camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(!inputDeviceInfo, CameraErrorCode::SUCCESS,
        "CaptureSessionForSys::GetZoomPointInfos camera device info is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetCachedMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, CameraErrorCode::SUCCESS, "GetZoomPointInfos camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_EQUIVALENT_FOCUS, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count == 0, CameraErrorCode::SUCCESS,
        "GetZoomPointInfos Failed with return code:%{public}d, item.count:%{public}d", ret, item.count);
    SceneMode mode = GetMode();
    int32_t defaultLen = 0;
    int32_t modeLen = 0;
    MEDIA_INFO_LOG("CaptureSessionForSys::GetZoomPointInfos mode:%{public}d", mode);
    for (uint32_t i = 0; i < item.count; i++) {
        if ((i & 1) == 0) {
            MEDIA_DEBUG_LOG("CaptureSessionForSys::GetZoomPointInfos mode:%{public}d, equivalentFocus:%{public}d",
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
    // LCOV_EXCL_STOP
}

int32_t CaptureSessionForSys::GetBeauty(BeautyType beautyType)
{
    // LCOV_EXCL_START
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSessionForSys::GetBeauty Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), -1,
        "CaptureSessionForSys::GetBeauty camera device is null");
    std::vector<BeautyType> supportedBeautyTypes = GetSupportedBeautyTypes();
    auto itr = std::find(supportedBeautyTypes.begin(), supportedBeautyTypes.end(), beautyType);
    CHECK_RETURN_RET_ELOG(itr == supportedBeautyTypes.end(), -1, "CaptureSessionForSys::GetBeauty beautyType is NULL");
    int32_t beautyLevel = 0;
    auto itrLevel = beautyTypeAndLevels_.find(beautyType);
    if (itrLevel != beautyTypeAndLevels_.end()) {
        beautyLevel = itrLevel->second;
    }

    return beautyLevel;
    // LCOV_EXCL_STOP
}

int32_t CaptureSessionForSys::SetPortraitThemeType(PortraitThemeType type)
{
    // LCOV_EXCL_START
    MEDIA_DEBUG_LOG("Enter CaptureSessionForSys::SetPortraitThemeType");
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSessionForSys::SetPortraitThemeType Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSessionForSys::SetPortraitThemeType Need to call LockForControl() before setting camera properties");
    CHECK_RETURN_RET(!IsPortraitThemeSupported(), CameraErrorCode::OPERATION_NOT_ALLOWED);
    PortraitThemeType portraitThemeTypeTemp = PortraitThemeType::NATURAL;
    uint8_t themeType = g_fwkPortraitThemeTypeMap_.at(portraitThemeTypeTemp);
    auto itr = g_fwkPortraitThemeTypeMap_.find(type);
    if (itr == g_fwkPortraitThemeTypeMap_.end()) {
        MEDIA_ERR_LOG("CaptureSessionForSys::SetPortraitThemeType Unknown portrait theme type");
    } else {
        themeType = itr->second;
    }
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_CAMERA_PORTRAIT_THEME_TYPE, &themeType, 1);
    CHECK_PRINT_ELOG(!status, "CaptureSessionForSys::SetPortraitThemeType Failed to set flash mode");
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

void CaptureSessionForSys::SetColorEffect(ColorEffect colorEffect)
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_ELOG(
        !(IsSessionCommited() || IsSessionConfiged()), "CaptureSessionForSys::SetColorEffect Session is not Commited");
    CHECK_RETURN_ELOG(changedMetadata_ == nullptr,
        "CaptureSessionForSys::SetColorEffect Need to call LockForControl() before setting camera properties");
    uint8_t colorEffectTemp = ColorEffect::COLOR_EFFECT_NORMAL;
    auto itr = g_fwkColorEffectMap_.find(colorEffect);
    CHECK_RETURN_ELOG(
        itr == g_fwkColorEffectMap_.end(), "CaptureSessionForSys::SetColorEffect unknown is color effect");
    colorEffectTemp = itr->second;
    MEDIA_DEBUG_LOG("CaptureSessionForSys::SetColorEffect: %{public}d", colorEffect);
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_SUPPORTED_COLOR_MODES, &colorEffectTemp, 1);
    wptr<CaptureSessionForSys> weakThis(this);
    CHECK_EXECUTE(status, AddFunctionToMap(std::to_string(OHOS_CONTROL_SUPPORTED_COLOR_MODES),
        [weakThis, colorEffect]() {
            auto sharedThis = weakThis.promote();
            CHECK_RETURN_ELOG(!sharedThis, "SetColorEffect session is nullptr");
            sharedThis->LockForControl();
            sharedThis->SetColorEffect(colorEffect);
            sharedThis->UnlockForControl();
        }));
    CHECK_PRINT_ELOG(!status, "CaptureSessionForSys::SetColorEffect Failed to set color effect");
    return;
    // LCOV_EXCL_STOP
}

int32_t CaptureSessionForSys::GetFocusDistance(float& focusDistance)
{
    // LCOV_EXCL_START
    focusDistance = 0.0;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSessionForSys::GetFocusDistance Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::SUCCESS,
        "CaptureSessionForSys::GetFocusDistance camera device is null");
    focusDistance = focusDistance_;
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

bool CaptureSessionForSys::IsDepthFusionSupported()
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter IsDepthFusionSupported");
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), false,
        "CaptureSessionForSys::IsDepthFusionSupported Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        inputDevice == nullptr, false, "CaptureSessionForSys::IsDepthFusionSupported camera device is null");
    auto deviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(
        deviceInfo == nullptr, false, "CaptureSessionForSys::IsDepthFusionSupported camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = deviceInfo->GetCachedMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, false, "IsDepthFusionSupported camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_CAPTURE_MACRO_DEPTH_FUSION_SUPPORTED, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count <= 0, false,
        "CaptureSessionForSys::IsDepthFusionSupported Failed with return code %{public}d", ret);
    auto supportResult = static_cast<bool>(item.data.u8[0]);
    return supportResult;
    // LCOV_EXCL_STOP
}

std::vector<float> CaptureSessionForSys::GetDepthFusionThreshold()
{
    std::vector<float> depthFusionThreshold;
    GetDepthFusionThreshold(depthFusionThreshold);
    return depthFusionThreshold;
}

int32_t CaptureSessionForSys::GetDepthFusionThreshold(std::vector<float>& depthFusionThreshold)
{
    // LCOV_EXCL_START
    MEDIA_DEBUG_LOG("Enter GetDepthFusionThreshold");
    depthFusionThreshold.clear();
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSessionForSys::GetDepthFusionThreshold Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::SUCCESS,
        "CaptureSessionForSys::GetDepthFusionThreshold camera device is null");

    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, CameraErrorCode::SUCCESS, "GetDepthFusionThreshold camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(),
        OHOS_ABILITY_CAPTURE_MACRO_DEPTH_FUSION_ZOOM_RANGE, &item);
    const int32_t zoomRangeLength = 2;
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count < zoomRangeLength, 0,
        "CaptureSessionForSys::GetDepthFusionThreshold Failed with return code %{public}d, item.count = %{public}d",
        ret, item.count);
    float minDepthFusionZoom = 0.0;
    float maxDepthFusionZoom = 0.0;
    MEDIA_INFO_LOG("Capture marco depth fusion zoom range, min: %{public}f, max: %{public}f",
        item.data.f[0], item.data.f[1]);
    minDepthFusionZoom = item.data.f[0];
    maxDepthFusionZoom = item.data.f[1];
    depthFusionThreshold = {minDepthFusionZoom, maxDepthFusionZoom};
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int32_t CaptureSessionForSys::EnableDepthFusion(bool isEnable)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter EnableDepthFusion, isEnable:%{public}d", isEnable);
    CHECK_RETURN_RET_ELOG(!IsDepthFusionSupported(), CameraErrorCode::OPERATION_NOT_ALLOWED,
        "EnableDepthFusion IsDepthFusionSupported is false");
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSessionForSys Failed EnableDepthFusion!, session not commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSessionForSys::EnableDepthFusion Need to call LockForControl() before setting camera properties");
    uint8_t enableValue = static_cast<uint8_t>(isEnable ? 1 : 0);
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_CAPTURE_MACRO_DEPTH_FUSION, &enableValue, 1);
    CHECK_PRINT_ELOG(!status, "CaptureSessionForSys::EnableDepthFusion Failed to enable depth fusion");
    isDepthFusionEnable_ = isEnable;
    return CameraErrorCode::SUCCESS;
}

bool CaptureSessionForSys::IsDepthFusionEnabled()
{
    return isDepthFusionEnable_;
}

bool CaptureSessionForSys::IsStageBoostSupported()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter IsStageBoostSupported");
    CHECK_RETURN_RET_ELOG(!(IsSessionConfiged()), false,
        "CaptureSession::IsStageBoostSupported Session is not Commited!");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        inputDevice == nullptr, false, "CaptureSession::IsStageBoostSupported camera device is null");
    auto deviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(
        deviceInfo == nullptr, false, "CaptureSession::IsStageBoostSupported camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = deviceInfo->GetCachedMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, false,
        "IsStageBoostSupported camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_STAGE_BOOST, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count <= 0, false,
        "CaptureSession::IsStageBoostSupported Failed with return code %{public}d", ret);
    return true;
}
 
int32_t CaptureSessionForSys::EnableStageBoost(bool isEnable)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter EnableStageBoost, isEnable:%{public}d", isEnable);
    CHECK_RETURN_RET_ELOG(
        !IsStageBoostSupported(), CameraErrorCode::OPERATION_NOT_ALLOWED, "Not support StageBoost");
    uint8_t enableValue = static_cast<uint8_t>(isEnable ? 1 : 0);
    if (!AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_STAGE_BOOST, &enableValue, 1)) {
        MEDIA_ERR_LOG("CaptureSession::EnableStageBoost failed to enable stage boost");
    }
    return CameraErrorCode::SUCCESS;
}

void CaptureSessionForSys::SetFeatureDetectionStatusCallback(std::shared_ptr<FeatureDetectionStatusCallback> callback)
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    featureDetectionStatusCallback_ = callback;
    return;
    // LCOV_EXCL_STOP
}

void CaptureSessionForSys::SetEffectSuggestionCallback(
    std::shared_ptr<EffectSuggestionCallback> effectSuggestionCallback)
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    effectSuggestionCallback_ = effectSuggestionCallback;
    // LCOV_EXCL_STOP
}

bool CaptureSessionForSys::IsEffectSuggestionSupported()
{
    // LCOV_EXCL_START
    MEDIA_DEBUG_LOG("Enter IsEffectSuggestionSupported");
    bool isEffectSuggestionSupported = !this->GetSupportedEffectSuggestionType().empty();
    MEDIA_DEBUG_LOG("IsEffectSuggestionSupported: %{public}s, ScenMode: %{public}d",
        isEffectSuggestionSupported ? "true" : "false", GetMode());
    return isEffectSuggestionSupported;
    // LCOV_EXCL_STOP
}

int32_t CaptureSessionForSys::EnableEffectSuggestion(bool isEnable)
{
    // LCOV_EXCL_START
    MEDIA_DEBUG_LOG("Enter EnableEffectSuggestion, isEnable:%{public}d", isEnable);
    CHECK_RETURN_RET_ELOG(!IsEffectSuggestionSupported(), CameraErrorCode::OPERATION_NOT_ALLOWED,
        "EnableEffectSuggestion IsEffectSuggestionSupported is false");
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSessionForSys Failed EnableEffectSuggestion!, session not commited");
    uint8_t enableValue = static_cast<uint8_t>(isEnable);
    MEDIA_DEBUG_LOG("EnableEffectSuggestion enableValue:%{public}d", enableValue);
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_EFFECT_SUGGESTION, &enableValue, 1);
    CHECK_PRINT_ELOG(!status, "CaptureSessionForSys::EnableEffectSuggestion Failed to enable effectSuggestion");
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

EffectSuggestionInfo CaptureSessionForSys::GetSupportedEffectSuggestionInfo()
{
    // LCOV_EXCL_START
    EffectSuggestionInfo effectSuggestionInfo = {};
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), effectSuggestionInfo,
        "CaptureSessionForSys::GetSupportedEffectSuggestionInfo Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), effectSuggestionInfo,
        "CaptureSessionForSys::GetSupportedEffectSuggestionInfo camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, effectSuggestionInfo, "GetSupportedEffectSuggestionInfo camera metadata is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_EFFECT_SUGGESTION_SUPPORTED, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, effectSuggestionInfo,
        "CaptureSessionForSys::GetSupportedEffectSuggestionInfo Failed with return code %{public}d", ret);

    std::shared_ptr<EffectSuggestionInfoParse> infoParse = std::make_shared<EffectSuggestionInfoParse>();
    MEDIA_INFO_LOG("CaptureSessionForSys::GetSupportedEffectSuggestionInfo item.count %{public}d", item.count);
    infoParse->GetEffectSuggestionInfo(item.data.i32, item.count, effectSuggestionInfo);
    MEDIA_DEBUG_LOG("SupportedEffectSuggestionInfo: %{public}s", effectSuggestionInfo.to_string().c_str());
    return effectSuggestionInfo;
    // LCOV_EXCL_STOP
}

std::vector<EffectSuggestionType> CaptureSessionForSys::GetSupportedEffectSuggestionType()
{
    // LCOV_EXCL_START
    std::vector<EffectSuggestionType> supportedEffectSuggestionList = {};
    EffectSuggestionInfo effectSuggestionInfo = this->GetSupportedEffectSuggestionInfo();
    CHECK_RETURN_RET_ELOG(effectSuggestionInfo.modeCount == 0, supportedEffectSuggestionList,
        "CaptureSessionForSys::GetSupportedEffectSuggestionType Failed, effectSuggestionInfo is null");

    for (uint32_t i = 0; i < effectSuggestionInfo.modeCount; i++) {
        if (GetMode() != effectSuggestionInfo.modeInfo[i].modeType) {
            continue;
        }
        std::vector<int32_t> effectSuggestionList = effectSuggestionInfo.modeInfo[i].effectSuggestionList;
        supportedEffectSuggestionList.reserve(effectSuggestionList.size());
        for (uint32_t j = 0; j < effectSuggestionList.size(); j++) {
            auto itr = metaEffectSuggestionTypeMap_.find(
                static_cast<CameraEffectSuggestionType>(effectSuggestionList[j]));
            if (itr != metaEffectSuggestionTypeMap_.end()) {
                supportedEffectSuggestionList.emplace_back(itr->second);
            }
        }
        std::string supportedEffectSuggestionStr = std::accumulate(
            supportedEffectSuggestionList.cbegin(), supportedEffectSuggestionList.cend(), std::string(),
            [](const auto& prefix, const auto& item) {
                return prefix + (prefix.empty() ? "" : ",") + std::to_string(item);
            });
        MEDIA_DEBUG_LOG("The SupportedEffectSuggestionType List of ScenMode: %{public}d is [%{public}s].", GetMode(),
            supportedEffectSuggestionStr.c_str());
        return supportedEffectSuggestionList;
    }
    MEDIA_ERR_LOG("no effectSuggestionInfo for mode %{public}d", GetMode());
    return supportedEffectSuggestionList;
    // LCOV_EXCL_STOP
}

int32_t CaptureSessionForSys::SetEffectSuggestionStatus(std::vector<EffectSuggestionStatus> effectSuggestionStatusList)
{
    MEDIA_DEBUG_LOG("Enter SetEffectSuggestionStatus");
    CHECK_RETURN_RET_ELOG(!IsEffectSuggestionSupported(), CameraErrorCode::OPERATION_NOT_ALLOWED,
        "SetEffectSuggestionStatus IsEffectSuggestionSupported is false");
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSessionForSys Failed SetEffectSuggestionStatus!, session not commited");
    std::vector<uint8_t> vec = {};
    for (auto effectSuggestionStatus : effectSuggestionStatusList) {
        uint8_t type = fwkEffectSuggestionTypeMap_.at(EffectSuggestionType::EFFECT_SUGGESTION_NONE);
        auto itr = fwkEffectSuggestionTypeMap_.find(effectSuggestionStatus.type);
        if (itr == fwkEffectSuggestionTypeMap_.end()) {
            MEDIA_ERR_LOG("CaptureSessionForSys::SetEffectSuggestionStatus Unknown effectSuggestionType");
        } else {
            type = itr->second;
        }
        vec.emplace_back(type);
        vec.emplace_back(static_cast<uint8_t>(effectSuggestionStatus.status));
        MEDIA_DEBUG_LOG("CaptureSessionForSys::SetEffectSuggestionStatus type:%{public}u,status:%{public}u",
            type, static_cast<uint8_t>(effectSuggestionStatus.status));
    }
    bool status = AddOrUpdateMetadata(
        changedMetadata_, OHOS_CONTROL_EFFECT_SUGGESTION_DETECTION, vec.data(), vec.size());
    CHECK_PRINT_ELOG(!status, "CaptureSessionForSys::SetEffectSuggestionStatus Failed to Set effectSuggestionStatus");
    return CameraErrorCode::SUCCESS;
}

int32_t CaptureSessionForSys::UpdateEffectSuggestion(EffectSuggestionType effectSuggestionType, bool isEnable)
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSessionForSys::UpdateEffectSuggestion Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "CaptureSessionForSys::UpdateEffectSuggestion Need to call LockForControl() before setting camera properties");
    uint8_t type = fwkEffectSuggestionTypeMap_.at(EffectSuggestionType::EFFECT_SUGGESTION_NONE);
    auto itr = fwkEffectSuggestionTypeMap_.find(effectSuggestionType);
    CHECK_RETURN_RET_ELOG(itr == fwkEffectSuggestionTypeMap_.end(), CameraErrorCode::INVALID_ARGUMENT,
        "CaptureSessionForSys::UpdateEffectSuggestion Unknown effectSuggestionType");
    type = itr->second;
    std::vector<uint8_t> vec = {type, isEnable};
    MEDIA_DEBUG_LOG("CaptureSessionForSys::UpdateEffectSuggestion type:%{public}u,isEnable:%{public}u", type, isEnable);
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_EFFECT_SUGGESTION_TYPE, vec.data(), vec.size());
    CHECK_RETURN_RET_ELOG(!status, CameraErrorCode::SUCCESS,
        "CaptureSessionForSys::UpdateEffectSuggestion Failed to set effectSuggestionType");
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int32_t CaptureSessionForSys::EnableLcdFlashDetection(bool isEnable)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter EnableLcdFlashDetection, isEnable:%{public}d", isEnable);
    CHECK_RETURN_RET_ELOG(!IsLcdFlashSupported(), CameraErrorCode::OPERATION_NOT_ALLOWED,
        "EnableLcdFlashDetection IsLcdFlashSupported is false");
    CHECK_RETURN_RET_ELOG(
        !IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG, "EnableLcdFlashDetection session not commited");
    uint8_t enableValue = static_cast<uint8_t>(isEnable);
    CHECK_PRINT_ELOG(!AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_LCD_FLASH_DETECTION, &enableValue, 1),
        "EnableLcdFlashDetection Failed to enable lcd flash detection");
    return CameraErrorCode::SUCCESS;
}

void CaptureSessionForSys::SetLcdFlashStatusCallback(std::shared_ptr<LcdFlashStatusCallback> lcdFlashStatusCallback)
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    lcdFlashStatusCallback_ = lcdFlashStatusCallback;
}

int32_t CaptureSessionForSys::EnableTripodDetection(bool isEnable)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter EnableTripodDetection, isEnable:%{public}d", isEnable);
    CHECK_RETURN_RET_ELOG(!IsTripodDetectionSupported(), CameraErrorCode::OPERATION_NOT_ALLOWED,
        "EnableTripodDetection IsTripodDetectionSupported is false");
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "CaptureSessionForSys::EnableTripodDetection Session is not Commited");
    uint8_t enableValue = static_cast<uint8_t>(isEnable ? 1 : 0);
    CHECK_PRINT_ELOG(!AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_TRIPOD_DETECTION, &enableValue, 1),
        "CaptureSessionForSys::EnableTripodDetection failed to enable tripod detection");
    return CameraErrorCode::SUCCESS;
}

void CaptureSessionForSys::SetUsage(UsageType usageType, bool enabled)
{
    CHECK_RETURN_ELOG(changedMetadata_ == nullptr,
        "CaptureSessionForSys::SetUsage Need to call LockForControl() before setting camera properties");
    std::vector<int32_t> mode;

    mode.push_back(static_cast<int32_t>(usageType));
    mode.push_back(
        static_cast<int32_t>(enabled ? OHOS_CAMERA_SESSION_USAGE_ENABLE : OHOS_CAMERA_SESSION_USAGE_DISABLE));

    bool status = changedMetadata_->addEntry(OHOS_CONTROL_CAMERA_SESSION_USAGE, mode.data(), mode.size());

    CHECK_PRINT_ELOG(!status, "CaptureSessionForSys::SetUsage Failed to set mode");
}

int32_t CaptureSessionForSys::EnableLcdFlash(bool isEnable)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter EnableLcdFlash, isEnable:%{public}d", isEnable);
    CHECK_RETURN_RET_ELOG(
        !IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG, "EnableLcdFlash session not commited");
    uint8_t enableValue = static_cast<uint8_t>(isEnable);
    CHECK_PRINT_ELOG(!AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_LCD_FLASH, &enableValue, 1),
        "EnableLcdFlash Failed to enable lcd flash");
    return CameraErrorCode::SUCCESS;
}

void ParseData2StarsInfo(float *data, uint32_t cnt, StarsInfo &info)
{
    CHECK_RETURN_ELOG(data == nullptr || cnt == 0, "ParseData2StarsInfo failed, data is nullptr or cnt is zero");
    uint32_t end = cnt - 1;
    int32_t version = static_cast<int32_t>(data[0]);
    MEDIA_INFO_LOG("ParseData2StarsInfo StarsInfo version: %{public}d", version);
    int32_t starsCnt = static_cast<int32_t>(data[1]);
    // starsDescEnd is "-1" index
    uint32_t starsDescEnd = static_cast<uint32_t>(starsCnt) * STAR_DATA_LENGTH + 2;
    CHECK_RETURN_ELOG(starsDescEnd > end || static_cast<int32_t>(data[starsDescEnd]) != -1, "Parse Stars failed");
    for (uint32_t i = 2; i < starsDescEnd; i = i + STAR_DATA_LENGTH) {
        Star star;
        star.position = {.x = data[i + POSTION_X_OFFSET], .y = data[i + POSTION_Y_OFFSET]};
        star.sizeLevel = static_cast<uint8_t>(data[i + SIZE_LEVEL_OFFSET]);
        star.brightnessLevel = static_cast<uint8_t>(data[i + BRIGHTNESS_LEVEL_OFFSET]);
        info.stars.emplace_back(star);
    }

    uint32_t constellationsStartIndex = starsDescEnd + 1;
    CHECK_RETURN_ELOG(constellationsStartIndex > end, "Parse Constellations failed");
    size_t constellationsCount = static_cast<size_t>(data[constellationsStartIndex]);
    uint32_t i = constellationsStartIndex + 1;
    uint32_t j = i;
    std::vector<std::pair<uint32_t, uint32_t>> infoIndexRange;
    while (j <= end) {
        if (static_cast<int32_t>(data[j]) == -1) {
            std::pair<uint32_t, uint32_t> indexPair(i, j - 1);
            infoIndexRange.push_back(indexPair);
            i = j + 1;
            j = i;
        } else {
            j++;
        }
    }
    CHECK_RETURN_ELOG(constellationsCount != infoIndexRange.size(), "ParseData2StarsInfo failed, cnt is invalid");
    for (const auto &indexPair : infoIndexRange) {
        i = indexPair.first;
        j = indexPair.second;
        Constellation constellation;
        constellation.id = static_cast<uint8_t>(data[i + ID_OFFSET]);
        constellation.opacity = data[i + OPACITY_OFFSET];
        constellation.centerPoint = {.x = data[i + CENTER_POINT_X_OFFSET], .y = data[i + CENTER_POINT_Y_OFFSET]};
        uint32_t dataSize = j - (i + CENTER_POINT_Y_OFFSET);
        if (dataSize % LINE_SEGMENTS_DATA_SIZE != 0) {
            MEDIA_ERR_LOG("ParseData2StarsInfo failed, line segments data size is invalid");
            continue;
        }
        for (uint32_t m = i + 4; m <= j; m = m + LINE_SEGMENTS_DATA_SIZE) {
            Point pointA = {.x = data[m + POINT_A_X_OFFSET], .y = data[m + POINT_A_Y_OFFSET]};
            Point pointB = {.x = data[m + POINT_B_X_OFFSET], .y = data[m + POINT_B_Y_OFFSET]};
            constellation.lineSegments.emplace_back(pointA);
            constellation.lineSegments.emplace_back(pointB);
        }
        info.constellations.emplace_back(constellation);
    }
}

void CaptureSessionForSys::ProcessConstellationDrawingState(const std::shared_ptr<OHOS::Camera::CameraMetadata> &result)
    __attribute__((no_sanitize("cfi")))
{
    MEDIA_DEBUG_LOG("Entry ProcessConstellationDrawingState");
    auto photoOutput = photoOutput_;
    CHECK_RETURN(!photoOutput || !result);
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_CAMERA_CONSTELLATION_DRAWING_STATE, &item);
    CHECK_RETURN(ret != CAM_META_SUCCESS || item.count <= 0);
    ConstellationDrawingState drawingState = ConstellationDrawingState::PROCESSING;
    auto itr = drawingStateMap_.find(static_cast<camera_constellation_drawing_state>(item.data.u8[0]));
    CHECK_RETURN_ELOG(itr == drawingStateMap_.end(), "invalid Drawing state: %{public}d", item.data.u8[0]);
    drawingState = itr->second;
    MEDIA_DEBUG_LOG("Drawing state: %{public}d", drawingState);
    int32_t state = static_cast<int32_t>(drawingState);
    CHECK_EXECUTE(state != prevDrawingState_.load(), {
        MEDIA_INFO_LOG("ProcessConstellationDrawingState: %{public}d -> %{public}d", prevDrawingState_.load(), state);
        ((sptr<PhotoOutput> &)photoOutput)->ProcessConstellationDrawingState(state);
    });
    prevDrawingState_ = state;
}

void CaptureSessionForSys::ProcessConstellationDrawingUpdates(
    const std::shared_ptr<OHOS::Camera::CameraMetadata> &result) __attribute__((no_sanitize("cfi")))
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Entry ProcessConstellationDrawingUpdates");

    auto featureStatusCallback = GetFeatureDetectionStatusCallback();
    bool isNotSetCallBack = (featureStatusCallback == nullptr ||
        !featureStatusCallback->IsFeatureSubscribed(SceneFeature::FEATURE_CONSTELLATION_DRAWING));
    CHECK_RETURN_DLOG(
        isNotSetCallBack, "CaptureSessionForSys::ProcessConstellationDrawingUpdates featureStatusCallback is null");

    camera_metadata_item_t item;
    common_metadata_header_t *metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_STATUS_CONSTELLATION_DRAWING_DETECT, &item);
    uint32_t count = item.count;
    bool isNotFindItem = (ret != CAM_META_SUCCESS || count <= 1);
    CHECK_RETURN_DLOG(isNotFindItem, "Camera not support constellation drawing detection");
    float *data = item.data.f;
    int32_t starCount = static_cast<int32_t>(data[1]);
    auto isActive = starCount > 0;
    MEDIA_DEBUG_LOG("ConstellationDrawing active: %{public}d size: %{public}d ", isActive, count);
    StarsInfo info;
    auto detectStatus = isActive ? FeatureDetectionStatusCallback::FeatureDetectionStatus::ACTIVE
                                 : FeatureDetectionStatusCallback::FeatureDetectionStatus::IDLE;
    featureStatusCallback->UpdateStatus(SceneFeature::FEATURE_CONSTELLATION_DRAWING, detectStatus);
    CHECK_EXECUTE(isActive, ParseData2StarsInfo(data, count, info));
    featureStatusCallback->SetStarsInfo(info);
    featureStatusCallback->OnFeatureDetectionStatusChanged(SceneFeature::FEATURE_CONSTELLATION_DRAWING, detectStatus);
}

int32_t CaptureSessionForSys::EnableConstellationDrawingDetection(bool isEnable)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter EnableConstellationDrawingDetection, isEnable:%{public}d", isEnable);
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG, "Session is not Commited!");
    uint8_t enableValue = static_cast<uint8_t>(isEnable ? 1 : 0);
    CHECK_PRINT_ELOG(!AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_CONSTELLATION_DRAWING_DETECT, &enableValue, 1),
        "CaptureSessionForSys::ConstellationDrawing failed to enable low light detect");
    return CameraErrorCode::SUCCESS;
}

void CaptureSessionForSys::ProcessImageStabilizationGuide(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Entry ProcessImageStabilizationGuide");
    auto imageStabilizationGuideCallback = GetImageStabilizationGuideCallback();
    CHECK_RETURN_DLOG(imageStabilizationGuideCallback == nullptr, "imageStabilizationGuideCallback is null");

    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(result->get(), OHOS_STATUS_IMAGE_STABILIZATION_GUIDE, &item);
    CHECK_RETURN_DLOG(ret != CAM_META_SUCCESS, "ProcessImageStabilizationGuide not data");
    CHECK_RETURN_ELOG(item.count != GUIDE_DATA_LENGTH, "ProcessImageStabilizationGuide invalid data");
    std::vector<Point> lineSegments;
    for (uint32_t i = 0; i < item.count - 1; i = i + POINT_DATA_LENGTH) {
        Point point = {.x = item.data.f[i], .y = item.data.f[i + 1]};
        lineSegments.push_back(point);
    }

    MEDIA_DEBUG_LOG("ProcessImageStabilizationGuide lineSegments size: %{public}zu", lineSegments.size());
    imageStabilizationGuideCallback->OnImageStabilizationGuideChange(lineSegments);
}

int32_t CaptureSessionForSys::EnableSuperMoonFeature(bool isEnable)
{
    MEDIA_INFO_LOG("CaptureSessionForSys::EnableSuperMoonFeature isEnable: %{public}d", isEnable);
    isSetSuperMoonEnable_ = isEnable;
    return CameraErrorCode::SUCCESS;
}

std::shared_ptr<ImageStabilizationGuideCallback> CaptureSessionForSys::GetImageStabilizationGuideCallback()
{
    std::lock_guard<std::mutex> lock(imageStabilizationGuidehCallbackMutex_);
    return imageStabilizationGuideCallback_;
}

} // namespace CameraStandard
} // namespace OHOS
