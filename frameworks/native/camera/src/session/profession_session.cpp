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
#include "hcapture_session_callback_stub.h"
#include "metadata_common_utils.h"
#include "input/camera_input.h"
#include "output/photo_output.h"
#include "output/preview_output.h"
#include "output/video_output.h"
#include <algorithm>
#include <cstdint>

namespace OHOS {
namespace CameraStandard {
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
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::GetSupportedMeteringModes Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(),
        CameraErrorCode::SUCCESS, "ProfessionSession::GetSupportedMeteringModes camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_METER_MODES, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("ProfessionSession::GetSupportedMeteringModes Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
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
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
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
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::SetMeteringMode Session is not Commited");
    CHECK_ERROR_RETURN_RET_LOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "ProfessionSession::SetMeteringMode Need to call LockForControl() before setting camera properties");
    camera_meter_mode_t meteringMode = OHOS_CAMERA_SPOT_METERING;
    auto itr = fwkMeteringModeMap_.find(mode);
    if (itr == fwkMeteringModeMap_.end()) {
        MEDIA_ERR_LOG("ProfessionSession::SetMeteringMode Unknown exposure mode");
    } else {
        meteringMode = itr->second;
    }
    bool status = false;
    int32_t ret;
    uint32_t count = 1;
    camera_metadata_item_t item;

    MEDIA_DEBUG_LOG("ProfessionSession::SetMeteringMode metering mode: %{public}d", meteringMode);

    ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_METER_MODE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_METER_MODE, &meteringMode, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_METER_MODE, &meteringMode, count);
    }

    CHECK_ERROR_PRINT_LOG(!status, "ProfessionSession::SetMeteringMode Failed to set focus mode");
    return CameraErrorCode::SUCCESS;
}

int32_t ProfessionSession::GetMeteringMode(MeteringMode &meteringMode)
{
    meteringMode = METERING_MODE_SPOT;
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::GetMeteringMode Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(),
        CameraErrorCode::SUCCESS, "ProfessionSession::GetMeteringMode camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_METER_MODE, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "ProfessionSession::GetMeteringMode Failed with return code %{public}d", ret);
    auto itr = metaMeteringModeMap_.find(static_cast<camera_meter_mode_t>(item.data.u8[0]));
    if (itr != metaMeteringModeMap_.end()) {
        meteringMode = itr->second;
        return CameraErrorCode::SUCCESS;
    }
    return CameraErrorCode::SUCCESS;
}
// ISO
int32_t ProfessionSession::GetIsoRange(std::vector<int32_t> &isoRange)
{
    isoRange.clear();
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::GetIsoRange Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(),
        CameraErrorCode::SUCCESS, "ProfessionSession::GetIsoRange camera device is null");

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, CameraErrorCode::INVALID_ARGUMENT, "GetIsoRange metadata is null");

    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_ISO_VALUES, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS || item.count == 0, CameraErrorCode::INVALID_ARGUMENT,
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
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::SetISO Session is not Commited");
    CHECK_ERROR_RETURN_RET_LOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "ProfessionSession::SetISO Need to call LockForControl() before setting camera properties");

    bool status = false;
    int32_t count = 1;
    camera_metadata_item_t item;
    MEDIA_DEBUG_LOG("ProfessionSession::SetISO iso value: %{public}d", iso);
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(),
        CameraErrorCode::SUCCESS, "ProfessionSession::SetISO camera device is null");

    std::vector<int32_t> isoRange;
    CHECK_ERROR_RETURN_RET_LOG((GetIsoRange(isoRange) != CameraErrorCode::SUCCESS) && isoRange.empty(),
        CameraErrorCode::OPERATION_NOT_ALLOWED, "ProfessionSession::SetISO range is empty");

    const int32_t autoIsoValue = 0;
    if (iso != autoIsoValue && std::find(isoRange.begin(), isoRange.end(), iso) == isoRange.end()) {
        return CameraErrorCode::INVALID_ARGUMENT;
    }
    int ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_ISO_VALUE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_ISO_VALUE, &iso, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_ISO_VALUE, &iso, count);
    }
    CHECK_ERROR_PRINT_LOG(!status, "ProfessionSession::SetISO Failed to set exposure compensation");
    isoValue_ = static_cast<uint32_t>(iso);
    return CameraErrorCode::SUCCESS;
}

int32_t ProfessionSession::GetISO(int32_t &iso)
{
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::GetISO Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(),
        CameraErrorCode::INVALID_ARGUMENT, "ProfessionSession::GetISO camera device is null");

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = inputDevice->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_ISO_VALUE, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, CameraErrorCode::INVALID_ARGUMENT,
        "ProfessionSession::GetISO Failed with return code %{public}d", ret);
    iso = item.data.i32[0];
    MEDIA_DEBUG_LOG("iso: %{public}d", iso);
    return CameraErrorCode::SUCCESS;
}

bool ProfessionSession::IsManualIsoSupported()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter IsManualIsoSupported");

    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), false,
        "ProfessionSession::IsManualIsoSupported Session is not Commited");

    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(inputDevice == nullptr, false,
        "ProfessionSession::IsManualIsoSupported camera device is null");

    auto deviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET_LOG(deviceInfo == nullptr, false,
        "ProfessionSession::IsManualIsoSupported camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_ISO_VALUES, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS || item.count == 0, false,
        "ProfessionSession::IsMacroSupported Failed with return code %{public}d", ret);
    return true;
}

// focus mode
int32_t ProfessionSession::GetSupportedFocusModes(std::vector<FocusMode> &supportedFocusModes)
{
    supportedFocusModes.clear();
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::GetSupportedFocusModes Session is not Commited");

    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(),
        CameraErrorCode::SUCCESS, "ProfessionSession::GetSupportedFocusModes camera device is null");

    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FOCUS_MODES, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
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
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
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
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::SetFocusMode Session is not Commited");
    CHECK_ERROR_RETURN_RET_LOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "ProfessionSession::SetFocusMode Need to call LockForControl() before setting camera properties");
    uint8_t focus = FOCUS_MODE_LOCKED;
    auto itr = g_fwkFocusModeMap_.find(focusMode);
    if (itr == g_fwkFocusModeMap_.end()) {
        MEDIA_ERR_LOG("ProfessionSession::SetFocusMode Unknown exposure mode");
    } else {
        focus = itr->second;
    }
    bool status = false;
    int32_t ret;
    uint32_t count = 1;
    camera_metadata_item_t item;

    MEDIA_DEBUG_LOG("ProfessionSession::SetFocusMode Focus mode: %{public}d", focusMode);

    ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_FOCUS_MODE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_FOCUS_MODE, &focus, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_FOCUS_MODE, &focus, count);
    }

    CHECK_ERROR_PRINT_LOG(!status, "ProfessionSession::SetFocusMode Failed to set focus mode");
    return CameraErrorCode::SUCCESS;
}

int32_t ProfessionSession::GetFocusMode(FocusMode &focusMode)
{
    focusMode = FOCUS_MODE_MANUAL;
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::GetFocusMode Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(),
        CameraErrorCode::SUCCESS, "ProfessionSession::GetFocusMode camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_FOCUS_MODE, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "ProfessionSession::GetFocusMode Failed with return code %{public}d", ret);
    auto itr = g_metaFocusModeMap_.find(static_cast<camera_focus_mode_enum_t>(item.data.u8[0]));
    if (itr != g_metaFocusModeMap_.end()) {
        focusMode = itr->second;
        return CameraErrorCode::SUCCESS;
    }
    return CameraErrorCode::SUCCESS;
}

// Exposure Hint
int32_t ProfessionSession::GetSupportedExposureHintModes(std::vector<ExposureHintMode> &supportedExposureHintModes)
{
    supportedExposureHintModes.clear();
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::GetSupportedExposureHintModes Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(),
        CameraErrorCode::SUCCESS,
        "ProfessionSession::GetSupportedExposureHintModes camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_EXPOSURE_HINT_SUPPORTED, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
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
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::SetExposureHintMode Session is not Commited");
    CHECK_ERROR_RETURN_RET_LOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "ProfessionSession::SetExposureHintMode Need to call LockForControl() before setting camera properties");
    uint8_t exposureHintMode = OHOS_CAMERA_EXPOSURE_HINT_UNSUPPORTED;
    auto itr = fwkExposureHintModeMap_.find(mode);
    if (itr == fwkExposureHintModeMap_.end()) {
        MEDIA_ERR_LOG("ProfessionSession::SetExposureHintMode Unknown mode");
    } else {
        exposureHintMode = itr->second;
    }
    bool status = false;
    int32_t ret;
    uint32_t count = 1;
    camera_metadata_item_t item;
    MEDIA_DEBUG_LOG("ProfessionSession::SetExposureHintMode ExposureHint mode: %{public}d", exposureHintMode);

    ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_EXPOSURE_HINT_MODE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_EXPOSURE_HINT_MODE, &exposureHintMode, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_EXPOSURE_HINT_MODE, &exposureHintMode, count);
    }
    CHECK_ERROR_PRINT_LOG(!status, "ProfessionSession::SetExposureHintMode Failed to set ExposureHint mode");
    return CameraErrorCode::SUCCESS;
}

int32_t ProfessionSession::GetExposureHintMode(ExposureHintMode &mode)
{
    mode = EXPOSURE_HINT_UNSUPPORTED;
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::GetExposureHintMode Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(),
        CameraErrorCode::SUCCESS, "ProfessionSession::GetExposureHintMode camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_EXPOSURE_HINT_MODE, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "ProfessionSession::GetExposureHintMode Failed with return code %{public}d", ret);
    auto itr = metaExposureHintModeMap_.find(static_cast<camera_exposure_hint_mode_enum_t>(item.data.u8[0]));
    if (itr != metaExposureHintModeMap_.end()) {
        mode = itr->second;
        return CameraErrorCode::SUCCESS;
    }
    return CameraErrorCode::SUCCESS;
}
// Focus Flash Assist
int32_t ProfessionSession::GetSupportedFocusAssistFlashModes(
    std::vector<FocusAssistFlashMode> &supportedFocusAssistFlashModes)
{
    supportedFocusAssistFlashModes.clear();
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::GetSupportedFocusAssistFlashModes Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::SUCCESS,
        "ProfessionSession::GetSupportedFocusAssistFlashModes camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FOCUS_ASSIST_FLASH_SUPPORTED_MODES, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
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
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
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
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::IsFocusAssistFlashModeSupported Session is not Commited");
    CHECK_ERROR_RETURN_RET_LOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "ProfessionSession::IsFocusAssistFlashModeSupported Need to call LockForControl "
        "before setting camera properties");
    uint8_t value = OHOS_CAMERA_FOCUS_ASSIST_FLASH_MODE_DEFAULT;
    auto itr = fwkFocusAssistFlashModeMap_.find(mode);
    if (itr == fwkFocusAssistFlashModeMap_.end()) {
        MEDIA_ERR_LOG("ProfessionSession::SetFocusAssistFlashMode Unknown exposure mode");
    } else {
        value = itr->second;
    }
    bool status = false;
    int32_t ret;
    uint32_t count = 1;
    camera_metadata_item_t item;
    MEDIA_DEBUG_LOG("ProfessionSession::SetFocusAssistFlashMode FocusAssistFlash mode: %{public}d", value);
    ret = Camera::FindCameraMetadataItem(
        changedMetadata_->get(), OHOS_CONTROL_FOCUS_ASSIST_FLASH_SUPPORTED_MODE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_FOCUS_ASSIST_FLASH_SUPPORTED_MODE, &value, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_FOCUS_ASSIST_FLASH_SUPPORTED_MODE, &value, count);
    }
    CHECK_ERROR_PRINT_LOG(!status, "ProfessionSession::SetFocusAssistFlashMode Failed to set FocusAssistFlash mode");
    return CameraErrorCode::SUCCESS;
}

int32_t ProfessionSession::GetFocusAssistFlashMode(FocusAssistFlashMode &mode)
{
    mode = FOCUS_ASSIST_FLASH_MODE_DEFAULT;
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::GetFocusAssistFlashMode Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(), CameraErrorCode::SUCCESS,
        "ProfessionSession::GetFocusAssistFlashMode camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_FOCUS_ASSIST_FLASH_SUPPORTED_MODE, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "ProfessionSession::GetFocusAssistFlashMode Failed with return code %{public}d", ret);
    auto itr = metaFocusAssistFlashModeMap_.find(static_cast<camera_focus_assist_flash_mode_enum_t>(item.data.u8[0]));
    if (itr != metaFocusAssistFlashModeMap_.end()) {
        mode = itr->second;
        return CameraErrorCode::SUCCESS;
    }
    return CameraErrorCode::SUCCESS;
}

// flash mode
int32_t ProfessionSession::GetSupportedFlashModes(std::vector<FlashMode> &supportedFlashModes)
{
    supportedFlashModes.clear();
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::GetSupportedFlashModes Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(),
        CameraErrorCode::SUCCESS, "ProfessionSession::GetSupportedFlashModes camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FLASH_MODES, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "ProfessionSession::GetSupportedFlashModes Failed with return code %{public}d", ret);
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = g_metaFlashModeMap_.find(static_cast<camera_flash_mode_enum_t>(item.data.u8[i]));
        if (itr != g_metaFlashModeMap_.end()) {
            supportedFlashModes.emplace_back(itr->second);
        }
    }
    return CameraErrorCode::SUCCESS;
}

int32_t ProfessionSession::GetFlashMode(FlashMode &flashMode)
{
    flashMode = FLASH_MODE_CLOSE;
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::GetFlashMode Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(),
        CameraErrorCode::SUCCESS, "ProfessionSession::GetFlashMode camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_FLASH_MODE, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "ProfessionSession::GetFlashMode Failed with return code %{public}d", ret);
    auto itr = g_metaFlashModeMap_.find(static_cast<camera_flash_mode_enum_t>(item.data.u8[0]));
    if (itr != g_metaFlashModeMap_.end()) {
        flashMode = itr->second;
        return CameraErrorCode::SUCCESS;
    }

    return CameraErrorCode::SUCCESS;
}

int32_t ProfessionSession::SetFlashMode(FlashMode flashMode)
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::SetFlashMode Session is not Commited");
    CHECK_ERROR_RETURN_RET_LOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "ProfessionSession::SetFlashMode Need to call LockForControl() before setting camera properties");
    uint8_t flash = g_fwkFlashModeMap_.at(FLASH_MODE_CLOSE);
    auto itr = g_fwkFlashModeMap_.find(flashMode);
    if (itr == g_fwkFlashModeMap_.end()) {
        MEDIA_ERR_LOG("ProfessionSession::SetExposureMode Unknown exposure mode");
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

    CHECK_ERROR_PRINT_LOG(!status, "ProfessionSession::SetFlashMode Failed to set flash mode");
    return CameraErrorCode::SUCCESS;
}

int32_t ProfessionSession::IsFlashModeSupported(FlashMode flashMode, bool &isSupported)
{
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
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
}

int32_t ProfessionSession::HasFlash(bool &hasFlash)
{
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::HasFlash Session is not Commited");
    std::vector<FlashMode> vecSupportedFlashModeList;
    (void)this->GetSupportedFlashModes(vecSupportedFlashModeList);
    if (vecSupportedFlashModeList.empty()) {
        hasFlash = false;
        return CameraErrorCode::SUCCESS;
    }
    hasFlash = true;
    return CameraErrorCode::SUCCESS;
}
// XMAGE

int32_t ProfessionSession::GetSupportedColorEffects(std::vector<ColorEffect>& supportedColorEffects)
{
    supportedColorEffects.clear();
    CHECK_ERROR_RETURN_RET_LOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::GetSupportedColorEffects Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(),
        CameraErrorCode::SUCCESS, "ProfessionSession::GetSupportedColorEffects camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_SUPPORTED_COLOR_MODES, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "ProfessionSession::GetSupportedColorEffects Failed with return code %{public}d", ret);
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = g_metaColorEffectMap_.find(static_cast<camera_xmage_color_type_t>(item.data.u8[i]));
        if (itr != g_metaColorEffectMap_.end()) {
            supportedColorEffects.emplace_back(itr->second);
        }
    }
    return CameraErrorCode::SUCCESS;
}

int32_t ProfessionSession::GetColorEffect(ColorEffect& colorEffect)
{
    colorEffect = ColorEffect::COLOR_EFFECT_NORMAL;
    CHECK_ERROR_RETURN_RET_LOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::GetColorEffect Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(),
        CameraErrorCode::SUCCESS, "ProfessionSession::GetColorEffect camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_SUPPORTED_COLOR_MODES, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS || item.count == 0, CameraErrorCode::SUCCESS,
        "ProfessionSession::GetColorEffect Failed with return code %{public}d", ret);
    auto itr = g_metaColorEffectMap_.find(static_cast<camera_xmage_color_type_t>(item.data.u8[0]));
    if (itr != g_metaColorEffectMap_.end()) {
        colorEffect = itr->second;
    }
    return CameraErrorCode::SUCCESS;
}

int32_t ProfessionSession::SetColorEffect(ColorEffect colorEffect)
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_RET_LOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "ProfessionSession::GetColorEffect Session is not Commited");
    CHECK_ERROR_RETURN_RET_LOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "ProfessionSession::SetFlashMode Need to call LockForControl() before setting camera properties");
    uint8_t colorEffectTemp = ColorEffect::COLOR_EFFECT_NORMAL;
    auto itr = g_fwkColorEffectMap_.find(colorEffect);
    if (itr == g_fwkColorEffectMap_.end()) {
        MEDIA_ERR_LOG("ProfessionSession::SetColorEffect unknown is color effect");
    } else {
        colorEffectTemp = itr->second;
    }
    MEDIA_DEBUG_LOG("ProfessionSession::SetColorEffect: %{public}d", colorEffect);

    bool status = false;
    int32_t ret;
    uint32_t count = 1;
    camera_metadata_item_t item;
    ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_SUPPORTED_COLOR_MODES, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_SUPPORTED_COLOR_MODES, &colorEffectTemp, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_SUPPORTED_COLOR_MODES, &colorEffectTemp, count);
    }

    CHECK_ERROR_PRINT_LOG(!status, "ProfessionSession::SetColorEffect Failed to set color effect");
    return CameraErrorCode::SUCCESS;
}

bool ProfessionSession::CanAddOutput(sptr<CaptureOutput> &output)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter Into ProfessionSession::CanAddOutput");
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionConfiged() || output == nullptr, false,
        "ProfessionSession::CanAddOutput operation is Not allowed!");
    return CaptureSession::CanAddOutput(output);
}

//callbacks
void ProfessionSession::SetExposureInfoCallback(std::shared_ptr<ExposureInfoCallback> callback)
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    exposureInfoCallback_ = callback;
}

void ProfessionSession::SetIsoInfoCallback(std::shared_ptr<IsoInfoCallback> callback)
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    isoInfoCallback_ = callback;
}

void ProfessionSession::SetApertureInfoCallback(std::shared_ptr<ApertureInfoCallback> callback)
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    apertureInfoCallback_ = callback;
}

void ProfessionSession::SetLuminationInfoCallback(std::shared_ptr<LuminationInfoCallback> callback)
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    luminationInfoCallback_ = callback;
}

void ProfessionSession::ProcessSensorExposureTimeChange(const std::shared_ptr<OHOS::Camera::CameraMetadata> &result)
{
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_STATUS_SENSOR_EXPOSURE_TIME, &item);
    if (ret == CAM_META_SUCCESS) {
        int32_t numerator = item.data.r->numerator;
        int32_t denominator = item.data.r->denominator;
        MEDIA_DEBUG_LOG("SensorExposureTime: %{public}d/%{public}d", numerator, denominator);
        CHECK_ERROR_RETURN_LOG(denominator == 0, "ProcessSensorExposureTimeChange error! divide by zero");
        constexpr int32_t timeUnit = 1000000;
        uint32_t value = static_cast<uint32_t>(numerator / (denominator / timeUnit));
        MEDIA_DEBUG_LOG("SensorExposureTime: %{public}d", value);
        ExposureInfo info = {
            .exposureDurationValue = value,
        };
        std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
        if (exposureInfoCallback_ != nullptr && (value != exposureDurationValue_)) {
            if (exposureDurationValue_ != 0) {
                exposureInfoCallback_->OnExposureInfoChanged(info);
            }
            exposureDurationValue_ = value;
        }
    }
}

void ProfessionSession::ProcessIsoChange(const std::shared_ptr<OHOS::Camera::CameraMetadata> &result)
{
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_STATUS_ISO_VALUE, &item);
    if (ret == CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("Iso Value: %{public}d", item.data.ui32[0]);
        IsoInfo info = {
            .isoValue = item.data.ui32[0],
        };
        std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
        if (isoInfoCallback_ != nullptr && item.data.ui32[0] != isoValue_) {
            if (isoValue_ != 0) {
                isoInfoCallback_->OnIsoInfoChanged(info);
            }
            isoValue_ = item.data.ui32[0];
        }
    }
}

void ProfessionSession::ProcessApertureChange(const std::shared_ptr<OHOS::Camera::CameraMetadata> &result)
{
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_STATUS_CAMERA_APERTURE_VALUE, &item);
    if (ret == CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("aperture Value: %{public}f", ConfusingNumber(item.data.f[0]));
        std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
        ApertureInfo info = {
            .apertureValue = item.data.f[0],
        };
        if (apertureInfoCallback_ != nullptr && (item.data.f[0] != apertureValue_ || apertureValue_ == 0)) {
            apertureInfoCallback_->OnApertureInfoChanged(info);
            apertureValue_ = item.data.f[0];
        }
    }
}

void ProfessionSession::ProcessLuminationChange(const std::shared_ptr<OHOS::Camera::CameraMetadata> &result)
{
    constexpr float normalizedMeanValue = 255.0;
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_STATUS_ALGO_MEAN_Y, &item);
    float value = item.data.ui32[0] / normalizedMeanValue;
    if (ret == CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("Lumination Value: %{public}f", value);
        LuminationInfo info = {
            .luminationValue = value,
        };
        std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
        if (luminationInfoCallback_ != nullptr && value != luminationValue_) {
            luminationInfoCallback_->OnLuminationInfoChanged(info);
            luminationValue_ = value;
        }
    }
}

void ProfessionSession::ProcessPhysicalCameraSwitch(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_STATUS_PREVIEW_PHYSICAL_CAMERA_ID, &item);
    CHECK_ERROR_RETURN(ret != CAM_META_SUCCESS);
    if (physicalCameraId_ != item.data.u8[0]) {
        MEDIA_DEBUG_LOG("physicalCameraId: %{public}d", item.data.u8[0]);
        physicalCameraId_ = item.data.u8[0];
        ExecuteAbilityChangeCallback();
    }
}

std::shared_ptr<OHOS::Camera::CameraMetadata> ProfessionSession::GetMetadata()
{
    std::string phyCameraId = std::to_string(physicalCameraId_.load());
    auto physicalCameraDevice =
        std::find_if(supportedDevices_.begin(), supportedDevices_.end(), [phyCameraId](const auto& device) -> bool {
            std::string cameraId = device->GetID();
            size_t delimPos = cameraId.find("/");
            CHECK_ERROR_RETURN_RET(delimPos == std::string::npos, false);
            string id = cameraId.substr(delimPos + 1);
            return id.compare(phyCameraId) == 0;
        });
    // DELIVERY_PHOTO for default when commit
    if (physicalCameraDevice != supportedDevices_.end()) {
        MEDIA_DEBUG_LOG("ProfessionSession::GetMetadata physicalCameraId: device/%{public}s", phyCameraId.c_str());
        if ((*physicalCameraDevice)->GetCameraType() == CAMERA_TYPE_WIDE_ANGLE && !isRawImageDelivery_) {
            auto inputDevice = GetInputDevice();
            CHECK_ERROR_RETURN_RET(inputDevice == nullptr, nullptr);
            auto info = inputDevice->GetCameraDeviceInfo();
            CHECK_ERROR_RETURN_RET(info == nullptr, nullptr);
            MEDIA_DEBUG_LOG("ProfessionSession::GetMetadata using main sensor: %{public}s", info->GetID().c_str());
            return info->GetMetadata();
        }
        return (*physicalCameraDevice)->GetMetadata();
    }
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET(inputDevice == nullptr, nullptr);
    MEDIA_DEBUG_LOG("ProfessionSession::GetMetadata no physicalCamera, using current camera device:%{public}s",
        inputDevice->GetCameraDeviceInfo()->GetID().c_str());
    return inputDevice->GetCameraDeviceInfo()->GetMetadata();
}

void ProfessionSession::ProfessionSessionMetadataResultProcessor::ProcessCallbacks(
    const uint64_t timestamp, const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    auto session = session_.promote();
    CHECK_ERROR_RETURN_LOG(session == nullptr,
        "CaptureSession::ProfessionSessionMetadataResultProcessor ProcessCallbacks but session is null");

    session->ProcessFaceRecUpdates(timestamp, result);
    session->ProcessAutoFocusUpdates(result);
    session->ProcessSensorExposureTimeChange(result);
    session->ProcessIsoChange(result);
    session->ProcessApertureChange(result);
    session->ProcessLuminationChange(result);
    session->ProcessPhysicalCameraSwitch(result);
}
} // CameraStandard
} // OHOS
