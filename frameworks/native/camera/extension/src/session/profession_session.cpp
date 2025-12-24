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

#include "session/profession_session.h"
#include "camera_log.h"
#include "camera_metadata_operator.h"
#include "camera_util.h"
#include "capture_session_callback_stub.h"
#include "input/camera_manager.h"
#include "metadata_common_utils.h"
#include "input/camera_input.h"
#include "output/photo_output.h"
#include "output/preview_output.h"
#include "output/video_output.h"
#include <algorithm>
#include <cstdint>

namespace OHOS {
namespace CameraStandard {
constexpr int32_t DEFAULT_ITEMS = 10;
constexpr int32_t DEFAULT_DATA_LENGTH = 100;

ProfessionSession::~ProfessionSession()
{
    exposureInfoCallback_ = nullptr;
    isoInfoCallback_ = nullptr;
    apertureInfoCallback_ = nullptr;
    luminationInfoCallback_ = nullptr;
}
// metering mode
const std::unordered_map<camera_meter_mode_t, MeteringMode> ProfessionSession::metaMeteringModeMap_ = {
    {OHOS_CAMERA_SPOT_METERING,             METERING_MODE_SPOT},
    {OHOS_CAMERA_REGION_METERING,           METERING_MODE_REGION},
    {OHOS_CAMERA_OVERALL_METERING,          METERING_MODE_OVERALL},
    {OHOS_CAMERA_CENTER_WEIGHTED_METERING,  METERING_MODE_CENTER_WEIGHTED}
};

const std::unordered_map<MeteringMode, camera_meter_mode_t> ProfessionSession::fwkMeteringModeMap_ = {
    {METERING_MODE_SPOT,                    OHOS_CAMERA_SPOT_METERING},
    {METERING_MODE_REGION,                  OHOS_CAMERA_REGION_METERING},
    {METERING_MODE_OVERALL,                 OHOS_CAMERA_OVERALL_METERING},
    {METERING_MODE_CENTER_WEIGHTED,         OHOS_CAMERA_CENTER_WEIGHTED_METERING}
};

// FocusAssistFlash mode
const std::unordered_map<camera_focus_assist_flash_mode_enum_t, FocusAssistFlashMode>
    ProfessionSession::metaFocusAssistFlashModeMap_ = {
    { OHOS_CAMERA_FOCUS_ASSIST_FLASH_MODE_DEFAULT,  FOCUS_ASSIST_FLASH_MODE_DEFAULT },
    { OHOS_CAMERA_FOCUS_ASSIST_FLASH_MODE_AUTO,     FOCUS_ASSIST_FLASH_MODE_AUTO },
    { OHOS_CAMERA_FOCUS_ASSIST_FLASH_MODE_ON,       FOCUS_ASSIST_FLASH_MODE_ON },
    { OHOS_CAMERA_FOCUS_ASSIST_FLASH_MODE_OFF,      FOCUS_ASSIST_FLASH_MODE_OFF },
};
const std::unordered_map<FocusAssistFlashMode, camera_focus_assist_flash_mode_enum_t>
    ProfessionSession::fwkFocusAssistFlashModeMap_ = {
    { FOCUS_ASSIST_FLASH_MODE_DEFAULT,  OHOS_CAMERA_FOCUS_ASSIST_FLASH_MODE_DEFAULT },
    { FOCUS_ASSIST_FLASH_MODE_AUTO,     OHOS_CAMERA_FOCUS_ASSIST_FLASH_MODE_AUTO },
    { FOCUS_ASSIST_FLASH_MODE_ON,       OHOS_CAMERA_FOCUS_ASSIST_FLASH_MODE_ON },
    { FOCUS_ASSIST_FLASH_MODE_OFF,      OHOS_CAMERA_FOCUS_ASSIST_FLASH_MODE_OFF },
};
// ExposureHintMode
const std::unordered_map<camera_exposure_hint_mode_enum_t, ExposureHintMode>
    ProfessionSession::metaExposureHintModeMap_ = {
    { OHOS_CAMERA_EXPOSURE_HINT_UNSUPPORTED, EXPOSURE_HINT_UNSUPPORTED },
    { OHOS_CAMERA_EXPOSURE_HINT_MODE_ON, EXPOSURE_HINT_MODE_ON },
    { OHOS_CAMERA_EXPOSURE_HINT_MODE_OFF, EXPOSURE_HINT_MODE_OFF },
};
const std::unordered_map<ExposureHintMode, camera_exposure_hint_mode_enum_t>
    ProfessionSession::fwkExposureHintModeMap_ = {
    { EXPOSURE_HINT_UNSUPPORTED, OHOS_CAMERA_EXPOSURE_HINT_UNSUPPORTED },
    { EXPOSURE_HINT_MODE_ON, OHOS_CAMERA_EXPOSURE_HINT_MODE_ON },
    { EXPOSURE_HINT_MODE_OFF, OHOS_CAMERA_EXPOSURE_HINT_MODE_OFF },
};
// metering mode
int32_t ProfessionSession::GetSupportedMeteringModes(std::vector<MeteringMode> &supportedMeteringModes)
{
    supportedMeteringModes.clear();
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::GetSupportedMeteringModes Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        !inputDevice, CameraErrorCode::SUCCESS, "ProfessionSession::GetSupportedMeteringModes camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(!inputDeviceInfo, PortraitEffect::OFF_EFFECT,
        "ProfessionSession::GetSupportedMeteringModes camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetCachedMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_METER_MODES, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "ProfessionSession::GetSupportedMeteringModes Failed with return code %{public}d", ret);
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = metaMeteringModeMap_.find(static_cast<camera_meter_mode_t>(item.data.u8[i]));
        if (itr != metaMeteringModeMap_.end()) {
            supportedMeteringModes.emplace_back(itr->second);
        }
    }
    return CameraErrorCode::SUCCESS;
}

int32_t ProfessionSession::IsMeteringModeSupported(MeteringMode meteringMode, bool &isSupported)
{
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::IsMeteringModeSupported Session is not Commited");
    std::vector<MeteringMode> vecSupportedMeteringModeList;
    (void)this->GetSupportedMeteringModes(vecSupportedMeteringModeList);
    if (find(vecSupportedMeteringModeList.begin(), vecSupportedMeteringModeList.end(),
        meteringMode) != vecSupportedMeteringModeList.end()) {
        isSupported = true;
        return CameraErrorCode::SUCCESS;
    }
    isSupported = false;
    return CameraErrorCode::SUCCESS;
}

int32_t ProfessionSession::SetMeteringMode(MeteringMode mode)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::SetMeteringMode Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "ProfessionSession::SetMeteringMode Need to call LockForControl() before setting camera properties");
    // LCOV_EXCL_START
    camera_meter_mode_t meteringMode = OHOS_CAMERA_SPOT_METERING;
    auto itr = fwkMeteringModeMap_.find(mode);
    if (itr == fwkMeteringModeMap_.end()) {
        MEDIA_ERR_LOG("ProfessionSession::SetMeteringMode Unknown exposure mode");
    } else {
        meteringMode = itr->second;
    }
    MEDIA_DEBUG_LOG("ProfessionSession::SetMeteringMode metering mode: %{public}d", meteringMode);
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_METER_MODE, &meteringMode, 1);
    CHECK_PRINT_ELOG(!status, "ProfessionSession::SetMeteringMode Failed to set focus mode");
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int32_t ProfessionSession::GetMeteringMode(MeteringMode &meteringMode)
{
    meteringMode = METERING_MODE_SPOT;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::GetMeteringMode Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        !inputDevice, CameraErrorCode::SUCCESS, "ProfessionSession::GetMeteringMode camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(
        !inputDeviceInfo, CameraErrorCode::SUCCESS, "ProfessionSession::GetMeteringMode camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetCachedMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_METER_MODE, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "ProfessionSession::GetMeteringMode Failed with return code %{public}d", ret);
    // LCOV_EXCL_START
    auto itr = metaMeteringModeMap_.find(static_cast<camera_meter_mode_t>(item.data.u8[0]));
    if (itr != metaMeteringModeMap_.end()) {
        meteringMode = itr->second;
        return CameraErrorCode::SUCCESS;
    }
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}
// ISO
int32_t ProfessionSession::GetIsoRange(std::vector<int32_t> &isoRange)
{
    isoRange.clear();
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::GetIsoRange Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        !inputDevice, CameraErrorCode::SUCCESS, "ProfessionSession::GetIsoRange camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(
        !inputDeviceInfo, CameraErrorCode::SUCCESS, "ProfessionSession::GetIsoRange camera deviceInfo is null");
    // Enabling rawImageDelivery implies using raw camera through the YUV profile, Therefore, we need to get raw camera
    // static metadata rather than get dynamic metadata.
    bool isNeedPhysicalCameraMeta = isRawImageDelivery_ || photoProfile_.format_ == CAMERA_FORMAT_DNG_XDRAW;
    auto metadata = isNeedPhysicalCameraMeta ? inputDeviceInfo->GetCachedMetadata() : GetMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, CameraErrorCode::INVALID_ARGUMENT, "GetIsoRange metadata is null");

    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_ISO_VALUES, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count == 0, CameraErrorCode::INVALID_ARGUMENT,
        "ProfessionSession::GetIsoRange Failed with return code %{public}d", ret);
    std::vector<std::vector<int32_t> > modeIsoRanges = {};
        std::vector<int32_t> modeRange = {};
    for (uint32_t i = 0; i < item.count; i++) {
        if (item.data.i32[i] != -1) {
            modeRange.emplace_back(item.data.i32[i]);
            continue;
        }
        MEDIA_DEBUG_LOG("ProfessionSession::GetIsoRange mode %{public}d, range=%{public}s",
                        GetMode(), Container2String(modeRange.begin(), modeRange.end()).c_str());
        modeIsoRanges.emplace_back(std::move(modeRange));
        modeRange.clear();
    }

    for (auto it : modeIsoRanges) {
        MEDIA_DEBUG_LOG("ProfessionSession::GetIsoRange ranges=%{public}s",
                        Container2String(it.begin(), it.end()).c_str());
        if (GetMode() == it.at(0)) {
            isoRange.resize(it.size() - 1);
            std::copy(it.begin() + 1, it.end(), isoRange.begin());
        }
    }
    MEDIA_INFO_LOG("ProfessionSessionNapi::GetIsoRange isoRange=%{public}s, len = %{public}zu",
                   Container2String(isoRange.begin(), isoRange.end()).c_str(), isoRange.size());
    return CameraErrorCode::SUCCESS;
}

int32_t ProfessionSession::SetISO(int32_t iso)
{
    CHECK_RETURN_RET_ELOG(
        !IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG, "ProfessionSession::SetISO Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "ProfessionSession::SetISO Need to call LockForControl() before setting camera properties");
    // LCOV_EXCL_START
    MEDIA_DEBUG_LOG("ProfessionSession::SetISO iso value: %{public}d", iso);
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::SUCCESS,
        "ProfessionSession::SetISO camera device is null");

    std::vector<int32_t> isoRange;
    CHECK_RETURN_RET_ELOG((GetIsoRange(isoRange) != CameraErrorCode::SUCCESS) && isoRange.empty(),
        CameraErrorCode::OPERATION_NOT_ALLOWED, "ProfessionSession::SetISO range is empty");

    const int32_t autoIsoValue = 0;
    CHECK_RETURN_RET(iso != autoIsoValue && std::find(isoRange.begin(), isoRange.end(), iso) == isoRange.end(),
        CameraErrorCode::INVALID_ARGUMENT);
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_ISO_VALUE, &iso, 1);
    CHECK_PRINT_ELOG(!status, "ProfessionSession::SetISO Failed to set exposure compensation");
    isoValue_ = static_cast<uint32_t>(iso);
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int32_t ProfessionSession::GetISO(int32_t &iso)
{
    CHECK_RETURN_RET_ELOG(
        !IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG, "ProfessionSession::GetISO Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        !inputDevice, CameraErrorCode::INVALID_ARGUMENT, "ProfessionSession::GetISO camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(
        !inputDeviceInfo, CameraErrorCode::SUCCESS, "ProfessionSession::GetISO camera deviceInfo is null");
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = inputDeviceInfo->GetCachedMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_ISO_VALUE, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::INVALID_ARGUMENT,
        "ProfessionSession::GetISO Failed with return code %{public}d", ret);
    // LCOV_EXCL_START
    iso = item.data.i32[0];
    MEDIA_DEBUG_LOG("iso: %{public}d", iso);
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

bool ProfessionSession::IsManualIsoSupported()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter IsManualIsoSupported");

    CHECK_RETURN_RET_ELOG(
        !IsSessionCommited(), false, "ProfessionSession::IsManualIsoSupported Session is not Commited");

    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        inputDevice == nullptr, false, "ProfessionSession::IsManualIsoSupported camera device is null");

    auto deviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(
        deviceInfo == nullptr, false, "ProfessionSession::IsManualIsoSupported camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = deviceInfo->GetCachedMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_ISO_VALUES, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count == 0, false,
        "ProfessionSession::IsMacroSupported Failed with return code %{public}d", ret);
    return true;
}

// focus mode
int32_t ProfessionSession::GetSupportedFocusModes(std::vector<FocusMode> &supportedFocusModes)
{
    supportedFocusModes.clear();
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::GetSupportedFocusModes Session is not Commited");

    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        !inputDevice, CameraErrorCode::SUCCESS, "ProfessionSession::GetSupportedFocusModes camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(!inputDeviceInfo, CameraErrorCode::SUCCESS,
        "ProfessionSession::GetSupportedFocusModes camera deviceInfo is null");
    sptr<CameraDevice> cameraDevNow = inputDevice->GetCameraDeviceInfo();
    bool isConcurrentLimitEnabled = cameraDevNow != nullptr && cameraDevNow->isConcurrentLimted_ == 1;
    if (isConcurrentLimitEnabled) {
        // LCOV_EXCL_START
        for (int i = 0; i < cameraDevNow->limtedCapabilitySave_.focusmodes.count;
            i++) {
            camera_focus_mode_enum_t num = static_cast<camera_focus_mode_enum_t>(cameraDevNow->
                limtedCapabilitySave_.focusmodes.mode[i]);
            auto itr = g_metaFocusModeMap_.find(num);
            if (itr != g_metaFocusModeMap_.end()) {
                supportedFocusModes.emplace_back(itr->second);
            }
        }
        return CameraErrorCode::SUCCESS;
        // LCOV_EXCL_STOP
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetCachedMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FOCUS_MODES, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "ProfessionSession::GetSupportedFocusModes Failed with return code %{public}d", ret);
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = g_metaFocusModeMap_.find(static_cast<camera_focus_mode_enum_t>(item.data.u8[i]));
        if (itr != g_metaFocusModeMap_.end()) {
            supportedFocusModes.emplace_back(itr->second);
        }
    }
    return CameraErrorCode::SUCCESS;
}

int32_t ProfessionSession::IsFocusModeSupported(FocusMode focusMode, bool &isSupported)
{
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::IsFocusModeSupported Session is not Commited");
    std::vector<FocusMode> vecSupportedMeteringModeList;
    (void)(this->GetSupportedFocusModes(vecSupportedMeteringModeList));
    if (find(vecSupportedMeteringModeList.begin(), vecSupportedMeteringModeList.end(),
        focusMode) != vecSupportedMeteringModeList.end()) {
        isSupported = true;
        return CameraErrorCode::SUCCESS;
    }
    isSupported = false;
    return CameraErrorCode::SUCCESS;
}

int32_t ProfessionSession::SetFocusMode(FocusMode focusMode)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::SetFocusMode Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "ProfessionSession::SetFocusMode Need to call LockForControl() before setting camera properties");
    // LCOV_EXCL_START
    uint8_t focus = FOCUS_MODE_LOCKED;
    auto itr = g_fwkFocusModeMap_.find(focusMode);
    if (itr == g_fwkFocusModeMap_.end()) {
        MEDIA_ERR_LOG("ProfessionSession::SetFocusMode Unknown exposure mode");
    } else {
        focus = itr->second;
    }
    MEDIA_DEBUG_LOG("ProfessionSession::SetFocusMode Focus mode: %{public}d", focusMode);
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_FOCUS_MODE, &focus, 1);
    CHECK_PRINT_ELOG(!status, "ProfessionSession::SetFocusMode Failed to set focus mode");
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int32_t ProfessionSession::GetFocusMode(FocusMode &focusMode)
{
    focusMode = FOCUS_MODE_MANUAL;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::GetFocusMode Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        !inputDevice, CameraErrorCode::SUCCESS, "ProfessionSession::GetFocusMode camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(
        !inputDeviceInfo, CameraErrorCode::SUCCESS, "ProfessionSession::GetFocusMode camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetCachedMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_FOCUS_MODE, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "ProfessionSession::GetFocusMode Failed with return code %{public}d", ret);
    // LCOV_EXCL_START
    auto itr = g_metaFocusModeMap_.find(static_cast<camera_focus_mode_enum_t>(item.data.u8[0]));
    if (itr != g_metaFocusModeMap_.end()) {
        focusMode = itr->second;
        return CameraErrorCode::SUCCESS;
    }
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

// Exposure Hint
int32_t ProfessionSession::GetSupportedExposureHintModes(std::vector<ExposureHintMode> &supportedExposureHintModes)
{
    supportedExposureHintModes.clear();
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::GetSupportedExposureHintModes Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice, CameraErrorCode::SUCCESS,
        "ProfessionSession::GetSupportedExposureHintModes camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(!inputDeviceInfo, CameraErrorCode::SUCCESS,
        "ProfessionSession::GetSupportedExposureHintModes camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetCachedMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_EXPOSURE_HINT_SUPPORTED, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "ProfessionSession::GetSupportedExposureHintModes Failed with return code %{public}d", ret);
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = metaExposureHintModeMap_.find(static_cast<camera_exposure_hint_mode_enum_t>(item.data.u8[i]));
        if (itr != metaExposureHintModeMap_.end()) {
            supportedExposureHintModes.emplace_back(itr->second);
        }
    }
    return CameraErrorCode::SUCCESS;
}

int32_t ProfessionSession::SetExposureHintMode(ExposureHintMode mode)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::SetExposureHintMode Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "ProfessionSession::SetExposureHintMode Need to call LockForControl() before setting camera properties");
    // LCOV_EXCL_START
    uint8_t exposureHintMode = OHOS_CAMERA_EXPOSURE_HINT_UNSUPPORTED;
    auto itr = fwkExposureHintModeMap_.find(mode);
    if (itr == fwkExposureHintModeMap_.end()) {
        MEDIA_ERR_LOG("ProfessionSession::SetExposureHintMode Unknown mode");
    } else {
        exposureHintMode = itr->second;
    }
    MEDIA_DEBUG_LOG("ProfessionSession::SetExposureHintMode ExposureHint mode: %{public}d", exposureHintMode);
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_EXPOSURE_HINT_MODE, &exposureHintMode, 1);
    CHECK_PRINT_ELOG(!status, "ProfessionSession::SetExposureHintMode Failed to set ExposureHint mode");
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int32_t ProfessionSession::GetExposureHintMode(ExposureHintMode &mode)
{
    mode = EXPOSURE_HINT_UNSUPPORTED;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::GetExposureHintMode Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        !inputDevice, CameraErrorCode::SUCCESS, "ProfessionSession::GetExposureHintMode camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(
        !inputDeviceInfo, CameraErrorCode::SUCCESS, "ProfessionSession::GetExposureHintMode camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetCachedMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_EXPOSURE_HINT_MODE, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "ProfessionSession::GetExposureHintMode Failed with return code %{public}d", ret);
    // LCOV_EXCL_START
    auto itr = metaExposureHintModeMap_.find(static_cast<camera_exposure_hint_mode_enum_t>(item.data.u8[0]));
    if (itr != metaExposureHintModeMap_.end()) {
        mode = itr->second;
        return CameraErrorCode::SUCCESS;
    }
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}
// Focus Flash Assist
int32_t ProfessionSession::GetSupportedFocusAssistFlashModes(
    std::vector<FocusAssistFlashMode> &supportedFocusAssistFlashModes)
{
    supportedFocusAssistFlashModes.clear();
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::GetSupportedFocusAssistFlashModes Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice, CameraErrorCode::SUCCESS,
        "ProfessionSession::GetSupportedFocusAssistFlashModes camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(!inputDeviceInfo, CameraErrorCode::SUCCESS,
        "ProfessionSession::GetSupportedFocusAssistFlashModes camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetCachedMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FOCUS_ASSIST_FLASH_SUPPORTED_MODES, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "ProfessionSession::GetSupportedFocusAssistFlashModes Failed with return code %{public}d", ret);
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = metaFocusAssistFlashModeMap_.find(
            static_cast<camera_focus_assist_flash_mode_enum_t>(item.data.u8[i]));
        if (itr != metaFocusAssistFlashModeMap_.end()) {
            supportedFocusAssistFlashModes.emplace_back(itr->second);
        }
    }
    return CameraErrorCode::SUCCESS;
}

int32_t ProfessionSession::IsFocusAssistFlashModeSupported(FocusAssistFlashMode mode, bool &isSupported)
{
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::IsFocusAssistFlashModeSupported Session is not Commited");
    std::vector<FocusAssistFlashMode> vecSupportedFocusAssistFlashModeList;
    (void)this->GetSupportedFocusAssistFlashModes(vecSupportedFocusAssistFlashModeList);
    if (find(vecSupportedFocusAssistFlashModeList.begin(), vecSupportedFocusAssistFlashModeList.end(),
        mode) != vecSupportedFocusAssistFlashModeList.end()) {
        isSupported = true;
        return CameraErrorCode::SUCCESS;
    }
    isSupported = false;
    return CameraErrorCode::SUCCESS;
}

int32_t ProfessionSession::SetFocusAssistFlashMode(FocusAssistFlashMode mode)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("ProfessionSession::SetFocusAssistFlashMode app mode: %{public}d", static_cast<int32_t>(mode));
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::IsFocusAssistFlashModeSupported Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "ProfessionSession::IsFocusAssistFlashModeSupported Need to call LockForControl "
        "before setting camera properties");
    // LCOV_EXCL_START
    uint8_t value = OHOS_CAMERA_FOCUS_ASSIST_FLASH_MODE_DEFAULT;
    auto itr = fwkFocusAssistFlashModeMap_.find(mode);
    if (itr == fwkFocusAssistFlashModeMap_.end()) {
        MEDIA_ERR_LOG("ProfessionSession::SetFocusAssistFlashMode Unknown exposure mode");
    } else {
        value = itr->second;
    }
    MEDIA_DEBUG_LOG("ProfessionSession::SetFocusAssistFlashMode FocusAssistFlash mode: %{public}d", value);
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_FOCUS_ASSIST_FLASH_SUPPORTED_MODE, &value, 1);
    CHECK_PRINT_ELOG(!status, "ProfessionSession::SetFocusAssistFlashMode Failed to set FocusAssistFlash mode");
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int32_t ProfessionSession::GetFocusAssistFlashMode(FocusAssistFlashMode &mode)
{
    mode = FOCUS_ASSIST_FLASH_MODE_DEFAULT;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::GetFocusAssistFlashMode Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        !inputDevice, CameraErrorCode::SUCCESS, "ProfessionSession::GetFocusAssistFlashMode camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(!inputDeviceInfo, CameraErrorCode::SUCCESS,
        "ProfessionSession::GetFocusAssistFlashMode camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetCachedMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_FOCUS_ASSIST_FLASH_SUPPORTED_MODE, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "ProfessionSession::GetFocusAssistFlashMode Failed with return code %{public}d", ret);
    // LCOV_EXCL_START
    auto itr = metaFocusAssistFlashModeMap_.find(static_cast<camera_focus_assist_flash_mode_enum_t>(item.data.u8[0]));
    if (itr != metaFocusAssistFlashModeMap_.end()) {
        mode = itr->second;
        return CameraErrorCode::SUCCESS;
    }
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

// flash mode
int32_t ProfessionSession::GetSupportedFlashModes(std::vector<FlashMode> &supportedFlashModes)
{
    // LCOV_EXCL_START
    supportedFlashModes.clear();
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::GetSupportedFlashModes Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        !inputDevice, CameraErrorCode::SUCCESS, "ProfessionSession::GetSupportedFlashModes camera device is null");
    sptr<CameraDevice> cameraDevNow = inputDevice->GetCameraDeviceInfo();
    bool isConcurrentLimitEnabled = cameraDevNow != nullptr && cameraDevNow->isConcurrentLimted_ == 1;
    if (isConcurrentLimitEnabled) {
        for (int i = 0; i < cameraDevNow->limtedCapabilitySave_.flashmodes.count;
            i++) {
            camera_flash_mode_enum_t num = static_cast<camera_flash_mode_enum_t>(cameraDevNow->
                limtedCapabilitySave_.flashmodes.mode[i]);
            auto it = g_metaFlashModeMap_.find(num);
            if (it != g_metaFlashModeMap_.end()) {
                supportedFlashModes.emplace_back(it->second);
            }
        }
        return CameraErrorCode::SUCCESS;
    }

    if (IsSupportSpecSearch()) {
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

    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(!inputDeviceInfo, CameraErrorCode::SUCCESS,
        "ProfessionSession::GetSupportedFlashModes camera deviceInfo is null");
    auto metadata = isRawImageDelivery_ ? GetMetadata() : inputDeviceInfo->GetCachedMetadata();
    camera_metadata_item_t item;
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, CameraErrorCode::SUCCESS, "ProfessionSession::GetSupportedFlashModes metadata is nullptr");
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FLASH_MODES, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "ProfessionSession::GetSupportedFlashModes Failed with return code %{public}d", ret);
    g_transformValidData(item, g_metaFlashModeMap_, supportedFlashModes);
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int32_t ProfessionSession::GetFlashMode(FlashMode &flashMode)
{
    // LCOV_EXCL_START
    flashMode = FLASH_MODE_CLOSE;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::GetFlashMode Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        !inputDevice, CameraErrorCode::SUCCESS, "ProfessionSession::GetFlashMode camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(
        !inputDeviceInfo, CameraErrorCode::SUCCESS, "ProfessionSession::GetFlashMode camera deviceInfo is null");
    auto metadata = isRawImageDelivery_ ? GetMetadata() : inputDeviceInfo->GetCachedMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_FLASH_MODE, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "ProfessionSession::GetFlashMode Failed with return code %{public}d", ret);
    auto itr = g_metaFlashModeMap_.find(static_cast<camera_flash_mode_enum_t>(item.data.u8[0]));
    if (itr != g_metaFlashModeMap_.end()) {
        flashMode = itr->second;
        return CameraErrorCode::SUCCESS;
    }

    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int32_t ProfessionSession::SetFlashMode(FlashMode flashMode)
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::SetFlashMode Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "ProfessionSession::SetFlashMode Need to call LockForControl() before setting camera properties");
    MEDIA_INFO_LOG("ProfessionSession::SetFlashMode flashMode:%{public}d", flashMode);
    uint8_t flash = g_fwkFlashModeMap_.at(FLASH_MODE_CLOSE);
    auto itr = g_fwkFlashModeMap_.find(flashMode);
    if (itr == g_fwkFlashModeMap_.end()) {
        MEDIA_ERR_LOG("ProfessionSession::SetFlashMode Unknown exposure mode");
    } else {
        flash = itr->second;
    }
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_FLASH_MODE, &flash, 1);
    CHECK_PRINT_ELOG(!status, "ProfessionSession::SetFlashMode Failed to set flash mode");
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int32_t ProfessionSession::IsFlashModeSupported(FlashMode flashMode, bool &isSupported)
{
    // LCOV_EXCL_START
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::IsFlashModeSupported Session is not Commited");
    std::vector<FlashMode> vecSupportedFlashModeList;
    (void)this->GetSupportedFlashModes(vecSupportedFlashModeList);
    if (find(vecSupportedFlashModeList.begin(), vecSupportedFlashModeList.end(), flashMode) !=
        vecSupportedFlashModeList.end()) {
        isSupported = true;
        return CameraErrorCode::SUCCESS;
    }
    isSupported = false;
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int32_t ProfessionSession::HasFlash(bool &hasFlash)
{
    // LCOV_EXCL_START
    hasFlash = false;
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::HasFlash Session is not Commited");

    if (IsSupportSpecSearch()) {
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

    std::vector<FlashMode> supportedFlashModeList;
    GetSupportedFlashModes(supportedFlashModeList);
    bool onlyHasCloseMode = supportedFlashModeList.size() == 1 && supportedFlashModeList[0] == FLASH_MODE_CLOSE;
    bool hasValidFlashModes = !supportedFlashModeList.empty() && !onlyHasCloseMode;
    if (hasValidFlashModes) {
        hasFlash = true;
    }
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}
// XMAGE

int32_t ProfessionSession::GetSupportedColorEffects(std::vector<ColorEffect>& supportedColorEffects)
{
    supportedColorEffects.clear();
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::GetSupportedColorEffects Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        !inputDevice, CameraErrorCode::SUCCESS, "ProfessionSession::GetSupportedColorEffects camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(!inputDeviceInfo, CameraErrorCode::SUCCESS,
        "ProfessionSession::GetSupportedColorEffects camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetCachedMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_SUPPORTED_COLOR_MODES, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "ProfessionSession::GetSupportedColorEffects Failed with return code %{public}d", ret);
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
    return CameraErrorCode::SUCCESS;
}

int32_t ProfessionSession::GetColorEffect(ColorEffect& colorEffect)
{
    colorEffect = ColorEffect::COLOR_EFFECT_NORMAL;
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::GetColorEffect Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        !inputDevice, CameraErrorCode::SUCCESS, "ProfessionSession::GetColorEffect camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(
        !inputDeviceInfo, CameraErrorCode::SUCCESS, "ProfessionSession::GetColorEffect camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetCachedMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_SUPPORTED_COLOR_MODES, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count == 0, CameraErrorCode::SUCCESS,
        "ProfessionSession::GetColorEffect Failed with return code %{public}d", ret);
    // LCOV_EXCL_START
    auto itr = g_metaColorEffectMap_.find(static_cast<camera_xmage_color_type_t>(item.data.u8[0]));
    if (itr != g_metaColorEffectMap_.end()) {
        colorEffect = itr->second;
    }
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int32_t ProfessionSession::SetColorEffect(ColorEffect colorEffect)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::GetColorEffect Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "ProfessionSession::SetFlashMode Need to call LockForControl() before setting camera properties");
    // LCOV_EXCL_START
    uint8_t colorEffectTemp = ColorEffect::COLOR_EFFECT_NORMAL;
    auto itr = g_fwkColorEffectMap_.find(colorEffect);
    if (itr == g_fwkColorEffectMap_.end()) {
        MEDIA_ERR_LOG("ProfessionSession::SetColorEffect unknown is color effect");
    } else {
        colorEffectTemp = itr->second;
    }
    MEDIA_DEBUG_LOG("ProfessionSession::SetColorEffect: %{public}d", colorEffect);
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_SUPPORTED_COLOR_MODES, &colorEffectTemp, 1);
    CHECK_PRINT_ELOG(!status, "ProfessionSession::SetColorEffect Failed to set color effect");
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

bool ProfessionSession::CanAddOutput(sptr<CaptureOutput> &output)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter Into ProfessionSession::CanAddOutput");
    CHECK_RETURN_RET_ELOG(
        !IsSessionConfiged() || output == nullptr, false, "ProfessionSession::CanAddOutput operation is Not allowed!");
    return CaptureSession::CanAddOutput(output);
}

//callbacks
void ProfessionSession::SetExposureInfoCallback(std::shared_ptr<ExposureInfoCallback> callback)
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    exposureInfoCallback_ = callback;
    // LCOV_EXCL_STOP
}

void ProfessionSession::SetIsoInfoCallback(std::shared_ptr<IsoInfoCallback> callback)
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    isoInfoCallback_ = callback;
    // LCOV_EXCL_STOP
}

void ProfessionSession::SetApertureInfoCallback(std::shared_ptr<ApertureInfoCallback> callback)
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    apertureInfoCallback_ = callback;
    // LCOV_EXCL_STOP
}

void ProfessionSession::SetLuminationInfoCallback(std::shared_ptr<LuminationInfoCallback> callback)
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    luminationInfoCallback_ = callback;
    // LCOV_EXCL_STOP
}

void ProfessionSession::ProcessSensorExposureTimeChange(const std::shared_ptr<OHOS::Camera::CameraMetadata> &result)
{
    // LCOV_EXCL_START
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_STATUS_SENSOR_EXPOSURE_TIME, &item);
    CHECK_RETURN(ret != CAM_META_SUCCESS);
    int32_t numerator = item.data.r->numerator;
    int32_t denominator = item.data.r->denominator;
    MEDIA_DEBUG_LOG("SensorExposureTime: %{public}d/%{public}d", numerator, denominator);
    CHECK_RETURN_ELOG(denominator == 0, "ProcessSensorExposureTimeChange error! divide by zero");
    constexpr int32_t timeUnit = 1000000;
    uint32_t value = static_cast<uint32_t>(numerator / (denominator / timeUnit));
    MEDIA_DEBUG_LOG("SensorExposureTime: %{public}d", value);
    ExposureInfo info = {
        .exposureDurationValue = value,
    };
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    bool isUpdateExposureInfo = exposureInfoCallback_ != nullptr && (value != exposureDurationValue_);
    CHECK_RETURN(!isUpdateExposureInfo);
    exposureInfoCallback_->OnExposureInfoChanged(info);
    exposureDurationValue_ = value;
    // LCOV_EXCL_STOP
}

void ProfessionSession::ProcessIsoChange(const std::shared_ptr<OHOS::Camera::CameraMetadata> &result)
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
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    bool isUpdateExposureInfo = isoInfoCallback_ != nullptr && item.data.ui32[0] != isoValue_;
    CHECK_RETURN(!isUpdateExposureInfo);
    isoInfoCallback_->OnIsoInfoChanged(info);
    isoValue_ = item.data.ui32[0];
    // LCOV_EXCL_STOP
}

void ProfessionSession::ProcessApertureChange(const std::shared_ptr<OHOS::Camera::CameraMetadata> &result)
{
    // LCOV_EXCL_START
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_STATUS_CAMERA_APERTURE_VALUE, &item);
    CHECK_RETURN(ret != CAM_META_SUCCESS);
    MEDIA_DEBUG_LOG("aperture Value: %{public}f", ConfusingNumber(item.data.f[0]));
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    ApertureInfo info = {
        .apertureValue = item.data.f[0],
    };
    bool isChanged = apertureInfoCallback_ != nullptr && (item.data.f[0] != apertureValue_ || apertureValue_ == 0);
    CHECK_RETURN(!isChanged);
    apertureInfoCallback_->OnApertureInfoChanged(info);
    apertureValue_ = item.data.f[0];
    // LCOV_EXCL_STOP
}

void ProfessionSession::ProcessLuminationChange(const std::shared_ptr<OHOS::Camera::CameraMetadata> &result)
{
    // LCOV_EXCL_START
    constexpr float normalizedMeanValue = 255.0;
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_STATUS_ALGO_MEAN_Y, &item);
    float value = item.data.ui32[0] / normalizedMeanValue;
    CHECK_RETURN(ret != CAM_META_SUCCESS);
    MEDIA_DEBUG_LOG("Lumination Value: %{public}f", value);
    LuminationInfo info = {
        .luminationValue = value,
    };
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    bool isUpdateNeeded = luminationInfoCallback_ != nullptr && value != luminationValue_;
    CHECK_RETURN(!isUpdateNeeded);
    luminationInfoCallback_->OnLuminationInfoChanged(info);
    luminationValue_ = value;
    // LCOV_EXCL_STOP
}

void ProfessionSession::ProcessPhysicalCameraSwitch(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    // LCOV_EXCL_START
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_STATUS_PREVIEW_PHYSICAL_CAMERA_ID, &item);
    CHECK_RETURN(ret != CAM_META_SUCCESS);
    if (physicalCameraId_ != item.data.u8[0]) {
        MEDIA_DEBUG_LOG("physicalCameraId: %{public}d", item.data.u8[0]);
        physicalCameraId_ = item.data.u8[0];
        ExecuteAbilityChangeCallback();
    }
    // LCOV_EXCL_STOP
}

std::shared_ptr<OHOS::Camera::CameraMetadata> ProfessionSession::GetMetadata()
{
    // LCOV_EXCL_START
    std::string phyCameraId = std::to_string(physicalCameraId_.load());
    auto physicalCameraDevice =
        std::find_if(supportedDevices_.begin(), supportedDevices_.end(), [phyCameraId](const auto& device) -> bool {
            std::string cameraId = device->GetID();
            size_t delimPos = cameraId.find("/");
            CHECK_RETURN_RET(delimPos == std::string::npos, false);
            string id = cameraId.substr(delimPos + 1);
            return id.compare(phyCameraId) == 0;
        });
    // DELIVERY_PHOTO for default when commit
    if (physicalCameraDevice != supportedDevices_.end()) {
        MEDIA_DEBUG_LOG("ProfessionSession::GetMetadata physicalCameraId: device/%{public}s", phyCameraId.c_str());
        bool isWideAngleNotRaw = (*physicalCameraDevice)->GetCameraType() == CAMERA_TYPE_WIDE_ANGLE &&
            !isRawImageDelivery_;
        if (isWideAngleNotRaw) {
            auto inputDevice = GetInputDevice();
            CHECK_RETURN_RET(inputDevice == nullptr,
                std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH));
            auto info = inputDevice->GetCameraDeviceInfo();
            CHECK_RETURN_RET(
                info == nullptr, std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH));
            MEDIA_DEBUG_LOG("ProfessionSession::GetMetadata using main sensor: %{public}s", info->GetID().c_str());
            return info->GetCachedMetadata();
        }
        if ((*physicalCameraDevice)->GetCachedMetadata() == nullptr) {
            GetMetadataFromService(*physicalCameraDevice);
        }
        return (*physicalCameraDevice)->GetCachedMetadata();
    }
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET(
        inputDevice == nullptr, std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH));
    auto cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET(!cameraObj, std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH));
    MEDIA_DEBUG_LOG("ProfessionSession::GetMetadata no physicalCamera, using current camera device:%{public}s",
        cameraObj->GetID().c_str());
    return cameraObj->GetCachedMetadata();
    // LCOV_EXCL_STOP
}

void ProfessionSession::ProfessionSessionMetadataResultProcessor::ProcessCallbacks(
    const uint64_t timestamp, const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    // LCOV_EXCL_START
    auto session = session_.promote();
    CHECK_RETURN_ELOG(session == nullptr,
        "CaptureSession::ProfessionSessionMetadataResultProcessor ProcessCallbacks but session is null");

    session->ProcessAutoFocusUpdates(result);
    session->ProcessSensorExposureTimeChange(result);
    session->ProcessIsoChange(result);
    session->ProcessApertureChange(result);
    session->ProcessLuminationChange(result);
    session->ProcessPhysicalCameraSwitch(result);
    // LCOV_EXCL_STOP
}
} // CameraStandard
} // OHOS
