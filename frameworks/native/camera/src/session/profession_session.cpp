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
// WhiteBalanceMode
const std::unordered_map<camera_awb_mode_t, WhiteBalanceMode> ProfessionSession::metaWhiteBalanceModeMap_ = {
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
const std::unordered_map<WhiteBalanceMode, camera_awb_mode_t> ProfessionSession::fwkWhiteBalanceModeMap_ = {
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
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ProfessionSession::GetSupportedMeteringModes Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("ProfessionSession::GetSupportedMeteringModes camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
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
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ProfessionSession::IsMeteringModeSupported Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
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
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ProfessionSession::SetMeteringMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("ProfessionSession::SetMeteringMode Need to call LockForControl() "
                      "before setting camera properties");
        return CameraErrorCode::SUCCESS;
    }
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

    if (!status) {
        MEDIA_ERR_LOG("ProfessionSession::SetMeteringMode Failed to set focus mode");
    }
    return CameraErrorCode::SUCCESS;
}

int32_t ProfessionSession::GetMeteringMode(MeteringMode &meteringMode)
{
    meteringMode = METERING_MODE_SPOT;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ProfessionSession::GetMeteringMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("ProfessionSession::GetMeteringMode camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_METER_MODE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("ProfessionSession::GetMeteringMode Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
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
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ProfessionSession::GetIsoRange Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("ProfessionSession::GetIsoRange camera device is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_ISO_VALUES, &item);
    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG("ProfessionSession::GetIsoRange Failed with return code %{public}d", ret);
        return CameraErrorCode::INVALID_ARGUMENT;
    }
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
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ProfessionSession::SetISO Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("ProfessionSession::SetISO Need to call LockForControl() "
            "before setting camera properties");
        return CameraErrorCode::SUCCESS;
    }
    bool status = false;
    int32_t count = 1;
    camera_metadata_item_t item;
    MEDIA_DEBUG_LOG("ProfessionSession::SetISO iso value: %{public}d", iso);
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("ProfessionSession::SetISO camera device is null");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }

    std::vector<int32_t> isoRange;
    if ((GetIsoRange(isoRange) != CameraErrorCode::SUCCESS) && isoRange.empty()) {
        MEDIA_ERR_LOG("ProfessionSession::SetISO range is empty");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }
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
    if (!status) {
        MEDIA_ERR_LOG("ProfessionSession::SetISO Failed to set exposure compensation");
    }
    isoValue_ = iso;
    return CameraErrorCode::SUCCESS;
}

int32_t ProfessionSession::GetISO(int32_t &iso)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ProfessionSession::GetISO Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("ProfessionSession::GetISO camera device is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_ISO_VALUE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("ProfessionSession::GetISO Failed with return code %{public}d", ret);
        return CameraErrorCode::INVALID_ARGUMENT;
    }
    iso = item.data.i32[0];
    MEDIA_DEBUG_LOG("iso: %{public}d", iso);
    return CameraErrorCode::SUCCESS;
}

bool ProfessionSession::IsManualIsoSupported()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter IsManualIsoSupported");

    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ProfessionSession::IsManualIsoSupported Session is not Commited");
        return false;
    }
    if (inputDevice_ == nullptr) {
        MEDIA_ERR_LOG("ProfessionSession::IsManualIsoSupported camera device is null");
        return false;
    }
    auto deviceInfo = inputDevice_->GetCameraDeviceInfo();
    if (deviceInfo == nullptr) {
        MEDIA_ERR_LOG("ProfessionSession::IsManualIsoSupported camera deviceInfo is null");
        return false;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_ISO_VALUES, &item);
    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG("ProfessionSession::IsMacroSupported Failed with return code %{public}d", ret);
        return false;
    }
    return true;
}

// focus mode
int32_t ProfessionSession::GetSupportedFocusModes(std::vector<FocusMode> &supportedFocusModes)
{
    supportedFocusModes.clear();
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ProfessionSession::GetSupportedFocusModes Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("ProfessionSession::GetSupportedFocusModes camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FOCUS_MODES, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("ProfessionSession::GetSupportedFocusModes Failed with return code %{public}d", ret);
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

int32_t ProfessionSession::IsFocusModeSupported(FocusMode focusMode, bool &isSupported)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ProfessionSession::IsFocusModeSupported Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
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
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ProfessionSession::SetFocusMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("ProfessionSession::SetFocusMode Need to call LockForControl() before setting camera properties");
        return CameraErrorCode::SUCCESS;
    }
    uint8_t focus = FOCUS_MODE_LOCKED;
    auto itr = fwkFocusModeMap_.find(focusMode);
    if (itr == fwkFocusModeMap_.end()) {
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

    if (!status) {
        MEDIA_ERR_LOG("ProfessionSession::SetFocusMode Failed to set focus mode");
    }
    return CameraErrorCode::SUCCESS;
}

int32_t ProfessionSession::GetFocusMode(FocusMode &focusMode)
{
    focusMode = FOCUS_MODE_MANUAL;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ProfessionSession::GetFocusMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("ProfessionSession::GetFocusMode camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_FOCUS_MODE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("ProfessionSession::GetFocusMode Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    auto itr = metaFocusModeMap_.find(static_cast<camera_focus_mode_enum_t>(item.data.u8[0]));
    if (itr != metaFocusModeMap_.end()) {
        focusMode = itr->second;
        return CameraErrorCode::SUCCESS;
    }
    return CameraErrorCode::SUCCESS;
}

// white balance mode
int32_t ProfessionSession::GetSupportedWhiteBalanceModes(std::vector<WhiteBalanceMode> &supportedWhiteBalanceModes)
{
    supportedWhiteBalanceModes.clear();
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ProfessionSession::GetSupportedWhiteBalanceModes Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("ProfessionSession::GetSupportedWhiteBalanceModes camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_AWB_MODES, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("ProfessionSession::GetSupportedWhiteBalanceModes Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = metaWhiteBalanceModeMap_.find(static_cast<camera_awb_mode_t>(item.data.u8[i]));
        if (itr != metaWhiteBalanceModeMap_.end()) {
            supportedWhiteBalanceModes.emplace_back(itr->second);
        }
    }
    return CameraErrorCode::SUCCESS;
}

int32_t ProfessionSession::IsWhiteBalanceModeSupported(WhiteBalanceMode mode, bool &isSupported)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ProfessionSession::IsFocusModeSupported Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
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

int32_t ProfessionSession::SetWhiteBalanceMode(WhiteBalanceMode mode)
{
    CAMERA_SYNC_TRACE;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ProfessionSession::SetWhiteBalanceMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("ProfessionSession::SetWhiteBalanceMode Need to call LockForControl() "
                      "before setting camera properties");
        return CameraErrorCode::SUCCESS;
    }
    camera_awb_mode_t whiteBalanceMode = OHOS_CAMERA_AWB_MODE_OFF;
    auto itr = fwkWhiteBalanceModeMap_.find(mode);
    if (itr == fwkWhiteBalanceModeMap_.end()) {
        MEDIA_ERR_LOG("ProfessionSession::SetWhiteBalanceMode Unknown exposure mode");
    } else {
        whiteBalanceMode = itr->second;
    }
    MEDIA_DEBUG_LOG("ProfessionSession::SetWhiteBalanceMode WhiteBalance mode: %{public}d", whiteBalanceMode);
    // no manual wb mode need set maunual value to 0
    if (mode != AWB_MODE_OFF) {
        SetManualWhiteBalance(0);
    }
    if (!AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_AWB_MODE, whiteBalanceMode)) {
        MEDIA_ERR_LOG("ProfessionSession::SetWhiteBalanceMode Failed to set WhiteBalance mode");
    }
    return CameraErrorCode::SUCCESS;
}

int32_t ProfessionSession::GetWhiteBalanceMode(WhiteBalanceMode &mode)
{
    mode = AWB_MODE_OFF;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ProfessionSession::GetWhiteBalanceMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("ProfessionSession::GetWhiteBalanceMode camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_AWB_MODE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("ProfessionSession::GetWhiteBalanceMode Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    auto itr = metaWhiteBalanceModeMap_.find(static_cast<camera_awb_mode_t>(item.data.u8[0]));
    if (itr != metaWhiteBalanceModeMap_.end()) {
        mode = itr->second;
        return CameraErrorCode::SUCCESS;
    }
    return CameraErrorCode::SUCCESS;
}

// manual white balance
int32_t ProfessionSession::GetManualWhiteBalanceRange(std::vector<int32_t> &whiteBalanceRange)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ProfessionSession::GetManualWhiteBalanceRange Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("ProfessionSession::GetManualWhiteBalanceRange camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_SENSOR_WB_VALUES, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("ProfessionSession::GetManualWhiteBalanceRange Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }

    for (uint32_t i = 0; i < item.count; i++) {
        whiteBalanceRange.emplace_back(item.data.i32[i]);
    }
    return CameraErrorCode::SUCCESS;
}

int32_t ProfessionSession::IsManualWhiteBalanceSupported(bool &isSupported)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ProfessionSession::IsManualWhiteBalanceSupported Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    std::vector<int32_t> whiteBalanceRange;
    this->GetManualWhiteBalanceRange(whiteBalanceRange);
    constexpr int32_t rangeSize = 2;
    isSupported = (whiteBalanceRange.size() == rangeSize);
    return CameraErrorCode::SUCCESS;
}

int32_t ProfessionSession::SetManualWhiteBalance(int32_t wbValue)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ProfessionSession::SetManualWhiteBalance Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("ProfessionSession::SetManualWhiteBalance Need to call LockForControl() "
            "before setting camera properties");
        return CameraErrorCode::SUCCESS;
    }
    WhiteBalanceMode mode;
    GetWhiteBalanceMode(mode);
    //WhiteBalanceMode::OFF
    if (mode != WhiteBalanceMode::AWB_MODE_OFF) {
        MEDIA_ERR_LOG("ProfessionSession::SetManualWhiteBalance Need to set WhiteBalanceMode off");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }
    int32_t minIndex = 0;
    int32_t maxIndex = 1;
    MEDIA_DEBUG_LOG("ProfessionSession::SetManualWhiteBalance white balance: %{public}d", wbValue);
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("ProfessionSession::SetManualWhiteBalance camera device is null");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }
    std::vector<int32_t> whiteBalanceRange;
    this->GetManualWhiteBalanceRange(whiteBalanceRange);
    if (whiteBalanceRange.empty()) {
        MEDIA_ERR_LOG("ProfessionSession::SetManualWhiteBalance Bias range is empty");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }

    if (wbValue != 0 && wbValue < whiteBalanceRange[minIndex]) {
        MEDIA_DEBUG_LOG("ProfessionSession::SetManualWhiteBalance wbValue:"
                        "%{public}d is lesser than minimum wbValue: %{public}d", wbValue, whiteBalanceRange[minIndex]);
        wbValue = whiteBalanceRange[minIndex];
    } else if (wbValue > whiteBalanceRange[maxIndex]) {
        MEDIA_DEBUG_LOG("ProfessionSession::SetManualWhiteBalance wbValue: "
                        "%{public}d is greater than maximum wbValue: %{public}d", wbValue, whiteBalanceRange[maxIndex]);
        wbValue = whiteBalanceRange[maxIndex];
    }
    if (!AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_SENSOR_WB_VALUE, wbValue)) {
        MEDIA_ERR_LOG("SetManualWhiteBalance Failed to SetManualWhiteBalance");
    }
    return CameraErrorCode::SUCCESS;
}


int32_t ProfessionSession::GetManualWhiteBalance(int32_t &wbValue)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ProfessionSession::GetManualWhiteBalance Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("ProfessionSession::GetManualWhiteBalance camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_SENSOR_WB_VALUE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("ProfessionSession::GetManualWhiteBalance Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    if (item.count != 0) {
        wbValue = item.data.i32[0];
    }
    return CameraErrorCode::SUCCESS;
}

// Exposure Hint
int32_t ProfessionSession::GetSupportedExposureHintModes(std::vector<ExposureHintMode> &supportedExposureHintModes)
{
    supportedExposureHintModes.clear();
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ProfessionSession::GetSupportedExposureHintModes Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("ProfessionSession::GetSupportedExposureHintModes camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_EXPOSURE_HINT_SUPPORTED, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("ProfessionSession::GetSupportedExposureHintModes Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
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
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ProfessionSession::SetExposureHintMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("ProfessionSession::SetExposureHintMode Need to call LockForControl() "
                      "before setting camera properties");
        return CameraErrorCode::SUCCESS;
    }
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
    if (!status) {
        MEDIA_ERR_LOG("ProfessionSession::SetExposureHintMode Failed to set ExposureHint mode");
    }
    return CameraErrorCode::SUCCESS;
}

int32_t ProfessionSession::GetExposureHintMode(ExposureHintMode &mode)
{
    mode = EXPOSURE_HINT_UNSUPPORTED;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ProfessionSession::GetExposureHintMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("ProfessionSession::GetExposureHintMode camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_EXPOSURE_HINT_MODE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("ProfessionSession::GetExposureHintMode Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
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
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ProfessionSession::GetSupportedFocusAssistFlashModes Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("ProfessionSession::GetSupportedFocusAssistFlashModes camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FOCUS_ASSIST_FLASH_SUPPORTED_MODES, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("ProfessionSession::GetSupportedFocusAssistFlashModes Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
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
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ProfessionSession::IsFocusModeSupported Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
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
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ProfessionSession::SetFocusAssistFlashMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("ProfessionSession::SetFocusAssistFlashMode Need to call LockForControl "
                      "before setting camera properties");
        return CameraErrorCode::SUCCESS;
    }
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
    if (!status) {
        MEDIA_ERR_LOG("ProfessionSession::SetFocusAssistFlashMode Failed to set FocusAssistFlash mode");
    }
    return CameraErrorCode::SUCCESS;
}

int32_t ProfessionSession::GetFocusAssistFlashMode(FocusAssistFlashMode &mode)
{
    mode = FOCUS_ASSIST_FLASH_MODE_DEFAULT;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ProfessionSession::GetFocusAssistFlashMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("ProfessionSession::GetFocusAssistFlashMode camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_FOCUS_ASSIST_FLASH_SUPPORTED_MODE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("ProfessionSession::GetFocusAssistFlashMode Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
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
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ProfessionSession::GetSupportedFlashModes Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("ProfessionSession::GetSupportedFlashModes camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FLASH_MODES, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("ProfessionSession::GetSupportedFlashModes Failed with return code %{public}d", ret);
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

int32_t ProfessionSession::GetFlashMode(FlashMode &flashMode)
{
    flashMode = FLASH_MODE_CLOSE;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ProfessionSession::GetFlashMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("ProfessionSession::GetFlashMode camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_FLASH_MODE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("ProfessionSession::GetFlashMode Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    auto itr = metaFlashModeMap_.find(static_cast<camera_flash_mode_enum_t>(item.data.u8[0]));
    if (itr != metaFlashModeMap_.end()) {
        flashMode = itr->second;
        return CameraErrorCode::SUCCESS;
    }

    return CameraErrorCode::SUCCESS;
}

int32_t ProfessionSession::SetFlashMode(FlashMode flashMode)
{
    CAMERA_SYNC_TRACE;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ProfessionSession::SetFlashMode Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("ProfessionSession::SetFlashMode Need to call LockForControl() before setting camera properties");
        return CameraErrorCode::SUCCESS;
    }
    uint8_t flash = fwkFlashModeMap_.at(FLASH_MODE_CLOSE);
    auto itr = fwkFlashModeMap_.find(flashMode);
    if (itr == fwkFlashModeMap_.end()) {
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

    if (!status) {
        MEDIA_ERR_LOG("ProfessionSession::SetFlashMode Failed to set flash mode");
        return CameraErrorCode::SUCCESS;
    }
    return CameraErrorCode::SUCCESS;
}

int32_t ProfessionSession::IsFlashModeSupported(FlashMode flashMode, bool &isSupported)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ProfessionSession::IsFlashModeSupported Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
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
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ProfessionSession::HasFlash Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
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
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("ProfessionSession::GetSupportedColorEffects Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("ProfessionSession::GetSupportedColorEffects camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_SUPPORTED_COLOR_MODES, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("ProfessionSession::GetSupportedColorEffects Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = metaColorEffectMap_.find(static_cast<camera_xmage_color_type_t>(item.data.u8[i]));
        if (itr != metaColorEffectMap_.end()) {
            supportedColorEffects.emplace_back(itr->second);
        }
    }
    return CameraErrorCode::SUCCESS;
}

int32_t ProfessionSession::GetColorEffect(ColorEffect& colorEffect)
{
    colorEffect = ColorEffect::COLOR_EFFECT_NORMAL;
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("ProfessionSession::GetColorEffect Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("ProfessionSession::GetColorEffect camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_SUPPORTED_COLOR_MODES, &item);
    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG("ProfessionSession::GetColorEffect Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    auto itr = metaColorEffectMap_.find(static_cast<camera_xmage_color_type_t>(item.data.u8[0]));
    if (itr != metaColorEffectMap_.end()) {
        colorEffect = itr->second;
    }
    return CameraErrorCode::SUCCESS;
}

int32_t ProfessionSession::SetColorEffect(ColorEffect colorEffect)
{
    CAMERA_SYNC_TRACE;
    if (!(IsSessionCommited() || IsSessionConfiged())) {
        MEDIA_ERR_LOG("ProfessionSession::SetColorEffect Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("ProfessionSession::SetColorEffect Need to call LockForControl before setting camera properties");
        return CameraErrorCode::SUCCESS;
    }
    uint8_t colorEffectTemp = ColorEffect::COLOR_EFFECT_NORMAL;
    auto itr = fwkColorEffectMap_.find(colorEffect);
    if (itr == fwkColorEffectMap_.end()) {
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

    if (!status) {
        MEDIA_ERR_LOG("ProfessionSession::SetColorEffect Failed to set color effect");
    }
    return CameraErrorCode::SUCCESS;
}

bool ProfessionSession::CanAddOutput(sptr<CaptureOutput> &output)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter Into ProfessionSession::CanAddOutput");
    if (!IsSessionConfiged() || output == nullptr) {
        MEDIA_ERR_LOG("ProfessionSession::CanAddOutput operation is Not allowed!");
        return false;
    }
    return CaptureSession::CanAddOutput(output);
}

// apertures
int32_t ProfessionSession::GetSupportedPhysicalApertures(std::vector<std::vector<float>>& supportedPhysicalApertures)
{
    // The data structure of the supportedPhysicalApertures object is { {zoomMin, zoomMax,
    // physicalAperture1, physicalAperture2···}, }.
    supportedPhysicalApertures.clear();
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("GetSupportedPhysicalApertures Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("GetSupportedPhysicalApertures camera device is null");
        return CameraErrorCode::SUCCESS;
    }

    std::shared_ptr<Camera::CameraMetadata> metadata = GetMetadata();
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
    if (supportedDeviceCount == 0) {
        MEDIA_ERR_LOG("GetSupportedPhysicalApertures Failed meta device count is 0");
        return CameraErrorCode::SUCCESS;
    }
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

int32_t ProfessionSession::GetPhysicalAperture(float& physicalAperture)
{
    physicalAperture = 0.0;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("GetPhysicalAperture Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("GetPhysicalAperture camera device is null");
        return CameraErrorCode::SUCCESS;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_CAMERA_PHYSICAL_APERTURE_VALUE, &item);
    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG("GetPhysicalAperture Failed with return code %{public}d", ret);
        return CameraErrorCode::SUCCESS;
    }
    physicalAperture = item.data.f[0];
    return CameraErrorCode::SUCCESS;
}

int32_t ProfessionSession::SetPhysicalAperture(float physicalAperture)
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
    MEDIA_DEBUG_LOG("ProfessionSession::SetPhysicalAperture physicalAperture = %{public}f",
                    ConfusingNumber(physicalAperture));
    std::vector<std::vector<float>> physicalApertures;
    GetSupportedPhysicalApertures(physicalApertures);
    // physicalApertures size is one, means not support change
    if (physicalApertures.size() == 1) {
        MEDIA_ERR_LOG("SetPhysicalAperture not support");
        return CameraErrorCode::SUCCESS;
    }
    // accurately currentZoomRatio need smoothing zoom done
    float currentZoomRatio = GetZoomRatio();
    int zoomMinIndex = 0;
    int zoomMaxIndex = 1;
    auto it = std::find_if(physicalApertures.begin(), physicalApertures.end(),
        [&currentZoomRatio, &zoomMinIndex, &zoomMaxIndex](const std::vector<float> physicalApertureRange) {
            return physicalApertureRange[zoomMaxIndex] > currentZoomRatio >= physicalApertureRange[zoomMinIndex];
        });
    float autoAperture = 0.0;
    if ((physicalAperture != autoAperture) && (it == physicalApertures.end())) {
        MEDIA_ERR_LOG("current zoomRatio not supported in physical apertures zoom ratio");
        return CameraErrorCode::SUCCESS;
    }
    int physicalAperturesIndex = 2;
    auto res = std::find_if(std::next((*it).begin(), physicalAperturesIndex), (*it).end(),
        [&physicalAperture](const float physicalApertureTemp) {
            return FloatIsEqual(physicalAperture, physicalApertureTemp);
        });
    if ((physicalAperture != autoAperture) && res == (*it).end()) {
        MEDIA_ERR_LOG("current physicalAperture is not supported");
        return CameraErrorCode::SUCCESS;
    }
    if (!AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_CAMERA_PHYSICAL_APERTURE_VALUE, physicalAperture)) {
        MEDIA_ERR_LOG("SetPhysicalAperture Failed to set physical aperture");
        return CameraErrorCode::SUCCESS;
    }
    apertureValue_ = physicalAperture;
    return CameraErrorCode::SUCCESS;
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
        if (denominator == 0) {
            MEDIA_ERR_LOG("ProcessSensorExposureTimeChange error! divide by zero");
            return;
        }
        constexpr int32_t timeUnit = 1000000;
        uint32_t value = numerator / (denominator / timeUnit);
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
    if (ret != CAM_META_SUCCESS) {
        return;
    }
    if (physicalCameraId_ != item.data.u8[0]) {
        MEDIA_DEBUG_LOG("physicalCameraId: %{public}d", item.data.u8[0]);
        physicalCameraId_ = item.data.u8[0];
        ExecuteAbilityChangeCallback();
    }
}

std::shared_ptr<OHOS::Camera::CameraMetadata> ProfessionSession::GetMetadata()
{
    std::string phyCameraId = std::to_string(physicalCameraId_.load());
    auto physicalCameraDevice = std::find_if(supportedDevices_.begin(), supportedDevices_.end(),
        [phyCameraId](const auto& device) -> bool {
            std::string cameraId = device->GetID();
            size_t delimPos = cameraId.find("/");
            if (delimPos == std::string::npos) {
                return false;
            }
            string id = cameraId.substr(delimPos + 1);
            return id.compare(phyCameraId) == 0;
        });
    if (physicalCameraDevice != supportedDevices_.end()) {
        MEDIA_DEBUG_LOG("ProfessionSession::GetMetadata physicalCameraId: device/%{public}s", phyCameraId.c_str());
        if ((*physicalCameraDevice)->GetCameraType() == CAMERA_TYPE_WIDE_ANGLE &&
            photoProfile_.GetCameraFormat() != CAMERA_FORMAT_DNG) {
                MEDIA_DEBUG_LOG("ProfessionSession::GetMetadata using main sensor: %{public}s",
                                inputDevice_->GetCameraDeviceInfo()->GetID().c_str());
                return inputDevice_->GetCameraDeviceInfo()->GetMetadata();
            }
        return (*physicalCameraDevice)->GetMetadata();
    }
    MEDIA_DEBUG_LOG("ProfessionSession::GetMetadata no physicalCamera, using current camera device:%{public}s",
        inputDevice_->GetCameraDeviceInfo()->GetID().c_str());
    return inputDevice_->GetCameraDeviceInfo()->GetMetadata();
}

void ProfessionSession::ProfessionSessionMetadataResultProcessor::ProcessCallbacks(
    const uint64_t timestamp, const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    auto session = session_.promote();
    if (session == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::ProfessionSessionMetadataResultProcessor ProcessCallbacks but session is null");
        return;
    }

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
