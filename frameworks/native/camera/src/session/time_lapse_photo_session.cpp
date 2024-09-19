/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "session/time_lapse_photo_session.h"
#include "camera_log.h"
#include "camera_util.h"
#include "metadata_common_utils.h"

using namespace std;

namespace OHOS {
namespace CameraStandard {

std::shared_ptr<OHOS::Camera::CameraMetadata> TimeLapsePhotoSession::GetMetadata()
{
    std::string phyCameraId = std::to_string(physicalCameraId_.load());
    auto physicalCameraDevice =
        std::find_if(supportedDevices_.begin(), supportedDevices_.end(), [phyCameraId](const auto& device) -> bool {
            std::string cameraId = device->GetID();
            size_t delimPos = cameraId.find("/");
            if (delimPos == std::string::npos) {
                return false;
            }
            string id = cameraId.substr(delimPos + 1);
            return id.compare(phyCameraId) == 0;
        });
    if (physicalCameraDevice != supportedDevices_.end()) {
        MEDIA_DEBUG_LOG("%{public}s: physicalCameraId: device/%{public}s", __FUNCTION__, phyCameraId.c_str());
<<<<<<< HEAD
        if ((*physicalCameraDevice)->GetCameraType() == CAMERA_TYPE_WIDE_ANGLE &&
            photoProfile_.GetCameraFormat() != CAMERA_FORMAT_DNG) {
=======
        if ((*physicalCameraDevice)->GetCameraType() == CAMERA_TYPE_WIDE_ANGLE && isRawImageDelivery_) {
>>>>>>> 35d35b7b (get接口对于deviceinfo调用导致crash问题解决)
            auto inputDevice = GetInputDevice();
            if (inputDevice == nullptr) {
                return nullptr;
            }
            auto info = inputDevice->GetCameraDeviceInfo();
            if (info == nullptr) {
                return nullptr;
            }
            MEDIA_DEBUG_LOG("%{public}s: using main sensor: %{public}s", __FUNCTION__, info->GetID().c_str());
            return info->GetMetadata();
        }
        return (*physicalCameraDevice)->GetMetadata();
    }
    auto inputDevice = GetInputDevice();
    if (inputDevice == nullptr) {
        return nullptr;
    }
    MEDIA_DEBUG_LOG("%{public}s: no physicalCamera, using current camera device:%{public}s", __FUNCTION__,
        inputDevice->GetCameraDeviceInfo()->GetID().c_str());
    return inputDevice->GetCameraDeviceInfo()->GetMetadata();
}

void TimeLapsePhotoSessionMetadataResultProcessor::ProcessCallbacks(
    const uint64_t timestamp, const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    auto session = session_.promote();
    if (session == nullptr) {
        MEDIA_ERR_LOG("%{public}s: session is nullptr", __FUNCTION__);
        return;
    }
    session->ProcessFaceRecUpdates(timestamp, result);
    session->ProcessIsoInfoChange(result);
    session->ProcessExposureChange(result);
    session->ProcessLuminationChange(result);
    session->ProcessSetTryAEChange(result);
    session->ProcessPhysicalCameraSwitch(result);
}

void TimeLapsePhotoSession::ProcessIsoInfoChange(const shared_ptr<OHOS::Camera::CameraMetadata>& meta)
{
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = meta->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_STATUS_ISO_VALUE, &item);
    if (ret == CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("%{public}s: Iso = %{public}d", __FUNCTION__, item.data.ui32[0]);
        IsoInfo info = {
            .isoValue = item.data.ui32[0],
        };
        std::lock_guard<std::mutex> lock(cbMtx_);
        if (isoInfoCallback_ != nullptr && item.data.ui32[0] != iso_) {
            if (iso_ != 0) {
                isoInfoCallback_->OnIsoInfoChanged(info);
            }
            iso_ = item.data.ui32[0];
        }
    }
}

void TimeLapsePhotoSession::ProcessExposureChange(const shared_ptr<OHOS::Camera::CameraMetadata>& meta)
{
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = meta->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_STATUS_SENSOR_EXPOSURE_TIME, &item);
    if (ret == CAM_META_SUCCESS) {
        int32_t numerator = item.data.r->numerator;
        int32_t denominator = item.data.r->denominator;
        if (denominator == 0) {
            MEDIA_ERR_LOG("%{public}s: Error! divide by 0", __FUNCTION__);
            return;
        }
        constexpr int32_t timeUnit = 1000000;
        uint32_t value = static_cast<uint32_t>(numerator / (denominator / timeUnit));
        MEDIA_DEBUG_LOG("%{public}s: exposure = %{public}d", __FUNCTION__, value);
        ExposureInfo info = {
            .exposureDurationValue = value,
        };
        std::lock_guard<std::mutex> lock(cbMtx_);
        if (exposureInfoCallback_ != nullptr && (value != exposureDurationValue_)) {
            if (exposureDurationValue_ != 0) {
                exposureInfoCallback_->OnExposureInfoChanged(info);
            }
            exposureDurationValue_ = value;
        }
    }
}

void TimeLapsePhotoSession::ProcessLuminationChange(const shared_ptr<OHOS::Camera::CameraMetadata>& meta)
{
    constexpr float normalizedMeanValue = 255.0;
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = meta->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_STATUS_ALGO_MEAN_Y, &item);
    float value = item.data.ui32[0] / normalizedMeanValue;
    if (ret == CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("%{public}s: Lumination = %{public}f", __FUNCTION__, value);
        LuminationInfo info = {
            .luminationValue = value,
        };
        std::lock_guard<std::mutex> lock(cbMtx_);
        if (luminationInfoCallback_ != nullptr && value != luminationValue_) {
            luminationInfoCallback_->OnLuminationInfoChanged(info);
            luminationValue_ = value;
        }
    }
}

void TimeLapsePhotoSession::ProcessSetTryAEChange(const shared_ptr<OHOS::Camera::CameraMetadata>& meta)
{
    TryAEInfo info = info_;
    camera_metadata_item_t item;
    int32_t ret;
    bool changed = false;
    ret = Camera::FindCameraMetadataItem(meta->get(), OHOS_STATUS_TIME_LAPSE_TRYAE_DONE, &item);
    if (ret == CAM_META_SUCCESS) {
        info.isTryAEDone = item.data.u8[0];
        changed = changed || info.isTryAEDone != info_.isTryAEDone;
    }
    ret = Camera::FindCameraMetadataItem(meta->get(), OHOS_STATUS_TIME_LAPSE_TRYAE_HINT, &item);
    if (ret == CAM_META_SUCCESS) {
        info.isTryAEHintNeeded = item.data.u8[0];
        changed = changed || info.isTryAEHintNeeded != info_.isTryAEHintNeeded;
    }
    ret = Camera::FindCameraMetadataItem(meta->get(), OHOS_STATUS_TIME_LAPSE_PREVIEW_TYPE, &item);
    if (ret == CAM_META_SUCCESS) {
        info.previewType = static_cast<TimeLapsePreviewType>(item.data.u8[0]);
        changed = changed || info.previewType != info_.previewType;
    }
    ret = Camera::FindCameraMetadataItem(meta->get(), OHOS_STATUS_TIME_LAPSE_CAPTURE_INTERVAL, &item);
    if (ret == CAM_META_SUCCESS) {
        info.captureInterval = item.data.i32[0];
        changed = changed || info.captureInterval != info_.captureInterval;
    }
    if (changed) {
        lock_guard<mutex> lg(cbMtx_);
        info_ = info;
        if (tryAEInfoCallback_ != nullptr) {
            tryAEInfoCallback_->OnTryAEInfoChanged(info);
        }
    }
}

void TimeLapsePhotoSession::ProcessPhysicalCameraSwitch(const shared_ptr<OHOS::Camera::CameraMetadata>& meta)
{
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = meta->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_STATUS_PREVIEW_PHYSICAL_CAMERA_ID, &item);
    if (ret != CAM_META_SUCCESS) {
        return;
    }
    if (physicalCameraId_ != item.data.u8[0]) {
        MEDIA_DEBUG_LOG("%{public}s: physicalCameraId = %{public}d", __FUNCTION__, item.data.u8[0]);
        physicalCameraId_ = item.data.u8[0];
        ExecuteAbilityChangeCallback();
    }
}

int32_t TimeLapsePhotoSession::IsTryAENeeded(bool& result)
{
    CAMERA_SYNC_TRACE;
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("%{public}s: Session is not Commited", __FUNCTION__);
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "TimeLapsePhotoSession::IsTryAENeeded camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET_LOG(!inputDeviceInfo, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "TimeLapsePhotoSession::IsTryAENeeded camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_TIME_LAPSE_TRYAE_STATE, &item);
    result = ret == CAM_META_SUCCESS;
    return CameraErrorCode::SUCCESS;
}

int32_t TimeLapsePhotoSession::StartTryAE()
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "TimeLapsePhotoSession::StartTryAE Session is not Commited");
    CHECK_ERROR_RETURN_RET_LOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "TimeLapsePhotoSession::StartTryAE Need to call LockForControl() before setting camera properties");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(),
        CameraErrorCode::OPERATION_NOT_ALLOWED, "TimeLapsePhotoSession::StartTryAE camera device is null");
    uint8_t data = 1;
    MEDIA_INFO_LOG("Set tag OHOS_CONTROL_TIME_LAPSE_TRYAE_STATE value = %{public}d", data);
    if (AddOrUpdateMetadata(changedMetadata_->get(), OHOS_CONTROL_TIME_LAPSE_TRYAE_STATE, &data, 1)) {
        info_ = TryAEInfo();
    } else {
        MEDIA_ERR_LOG("Set tag OHOS_CONTROL_TIME_LAPSE_TRYAE_STATE Failed");
    }
    return CameraErrorCode::SUCCESS;
}

int32_t TimeLapsePhotoSession::StopTryAE()
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "TimeLapsePhotoSession::StopTryAE Session is not Commited");
    CHECK_ERROR_RETURN_RET_LOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "TimeLapsePhotoSession::StopTryAE Need to call LockForControl() before setting camera properties");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(),
        CameraErrorCode::OPERATION_NOT_ALLOWED, "TimeLapsePhotoSession::StopTryAE camera device is null");
    uint8_t data = 0;
    MEDIA_INFO_LOG("Set tag OHOS_CONTROL_TIME_LAPSE_TRYAE_STATE value = %{public}d", data);
    if (AddOrUpdateMetadata(changedMetadata_->get(), OHOS_CONTROL_TIME_LAPSE_TRYAE_STATE, &data, 1)) {
        info_ = TryAEInfo();
    } else {
        MEDIA_ERR_LOG("Set tag OHOS_CONTROL_TIME_LAPSE_TRYAE_STATE Failed");
    }
    return CameraErrorCode::SUCCESS;
}

int32_t TimeLapsePhotoSession::GetSupportedTimeLapseIntervalRange(vector<int32_t>& result)
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "TimeLapsePhotoSession::GetSupportedTimeLapseIntervalRange Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "GetSupportedTimeLapseIntervalRange camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET_LOG(!inputDeviceInfo, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "GetSupportedTimeLapseIntervalRange camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_TIME_LAPSE_INTERVAL_RANGE, &item);
    if (ret == CAM_META_SUCCESS) {
        for (uint32_t i = 0; i < item.count; i++) {
            result.push_back(item.data.i32[i]);
        }
    }
    return CameraErrorCode::SUCCESS;
}

int32_t TimeLapsePhotoSession::GetTimeLapseInterval(int32_t& result)
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "TimeLapsePhotoSession::GetTimeLapseInterval Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "TimeLapsePhotoSession::GetTimeLapseInterval camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET_LOG(!inputDeviceInfo, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "TimeLapsePhotoSession::GetTimeLapseInterval camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_TIME_LAPSE_INTERVAL, &item);
    if (ret == CAM_META_SUCCESS) {
        result = item.data.i32[0];
    }
    return CameraErrorCode::SUCCESS;
}

int32_t TimeLapsePhotoSession::SetTimeLapseInterval(int32_t interval)
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "TimeLapsePhotoSession::SetTimeLapseInterval Session is not Commited");
    CHECK_ERROR_RETURN_RET_LOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "TimeLapsePhotoSession::SetTimeLapseInterval Need to call LockForControl() before setting camera properties");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(),
        CameraErrorCode::OPERATION_NOT_ALLOWED, "TimeLapsePhotoSession::SetTimeLapseInterval camera device is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_TIME_LAPSE_INTERVAL, &item);
    if (ret == CAM_META_SUCCESS) {
        MEDIA_WARNING_LOG("updateEntry OHOS_CONTROL_TIME_LAPSE_INTERVAL: %{public}d", interval);
        changedMetadata_->updateEntry(OHOS_CONTROL_TIME_LAPSE_INTERVAL, &interval, 1);
    } else if (ret == CAM_META_ITEM_NOT_FOUND) {
        MEDIA_WARNING_LOG("addEntry OHOS_CONTROL_TIME_LAPSE_INTERVAL: %{public}d", interval);
        changedMetadata_->addEntry(OHOS_CONTROL_TIME_LAPSE_INTERVAL, &interval, 1);
    } else {
        MEDIA_ERR_LOG("%{public}s: Set tag OHOS_CONTROL_TIME_LAPSE_INTERVAL failed", __FUNCTION__);
    }
    return CameraErrorCode::SUCCESS;
}

int32_t TimeLapsePhotoSession::SetTimeLapseRecordState(TimeLapseRecordState state)
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "TimeLapsePhotoSession::SetTimeLapseRecordState Session is not Commited");
    CHECK_ERROR_RETURN_RET_LOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "SetTimeLapseRecordState Need to call LockForControl() before setting camera properties");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(),
        CameraErrorCode::OPERATION_NOT_ALLOWED, "SetTimeLapseRecordState camera device is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_TIME_LAPSE_RECORD_STATE, &item);
    if (ret == CAM_META_SUCCESS) {
        MEDIA_WARNING_LOG("updateEntry OHOS_CONTROL_TIME_LAPSE_RECORD_STATE: %{public}d", state);
        changedMetadata_->updateEntry(OHOS_CONTROL_TIME_LAPSE_RECORD_STATE, &state, 1);
    } else if (ret == CAM_META_ITEM_NOT_FOUND) {
        MEDIA_WARNING_LOG("addEntry OHOS_CONTROL_TIME_LAPSE_RECORD_STATE: %{public}d", state);
        changedMetadata_->addEntry(OHOS_CONTROL_TIME_LAPSE_RECORD_STATE, &state, 1);
    } else {
        MEDIA_ERR_LOG("%{public}s: Set tag OHOS_CONTROL_TIME_LAPSE_RECORD_STATE failed", __FUNCTION__);
    }
    return CameraErrorCode::SUCCESS;
}

int32_t TimeLapsePhotoSession::SetTimeLapsePreviewType(TimeLapsePreviewType type)
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "TimeLapsePhotoSession::SetTimeLapsePreviewType Session is not Commited");
    CHECK_ERROR_RETURN_RET_LOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "SetTimeLapsePreviewType Need to call LockForControl() before setting camera properties");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(),
        CameraErrorCode::OPERATION_NOT_ALLOWED, "SetTimeLapsePreviewType camera device is null");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_TIME_LAPSE_PREVIEW_TYPE, &item);
    if (ret == CAM_META_SUCCESS) {
        MEDIA_WARNING_LOG("updateEntry OHOS_CONTROL_TIME_LAPSE_PREVIEW_TYPE: %{public}d", type);
        changedMetadata_->updateEntry(OHOS_CONTROL_TIME_LAPSE_PREVIEW_TYPE, &type, 1);
    } else if (ret == CAM_META_ITEM_NOT_FOUND) {
        MEDIA_WARNING_LOG("addEntry OHOS_CONTROL_TIME_LAPSE_PREVIEW_TYPE: %{public}d", type);
        changedMetadata_->addEntry(OHOS_CONTROL_TIME_LAPSE_PREVIEW_TYPE, &type, 1);
    } else {
        MEDIA_ERR_LOG("%{public}s: Set tag OHOS_CONTROL_TIME_LAPSE_PREVIEW_TYPE failed", __FUNCTION__);
    }
    return CameraErrorCode::SUCCESS;
}

const unordered_map<ExposureHintMode, camera_exposure_hint_mode_enum_t>
    TimeLapsePhotoSession::fwkExposureHintModeMap_ = {
    { EXPOSURE_HINT_UNSUPPORTED, OHOS_CAMERA_EXPOSURE_HINT_UNSUPPORTED },
    { EXPOSURE_HINT_MODE_ON, OHOS_CAMERA_EXPOSURE_HINT_MODE_ON },
    { EXPOSURE_HINT_MODE_OFF, OHOS_CAMERA_EXPOSURE_HINT_MODE_OFF },
};

int32_t TimeLapsePhotoSession::SetExposureHintMode(ExposureHintMode mode)
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "TimeLapsePhotoSession::SetExposureHintMode Session is not Commited");
    CHECK_ERROR_RETURN_RET_LOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "TimeLapsePhotoSession::SetExposureHintMode Need to call LockForControl() before setting camera properties");
    uint8_t exposureHintMode = OHOS_CAMERA_EXPOSURE_HINT_UNSUPPORTED;
    auto itr = fwkExposureHintModeMap_.find(mode);
    if (itr == fwkExposureHintModeMap_.end()) {
        MEDIA_ERR_LOG("%{public}s: Unknown mode", __FUNCTION__);
    } else {
        exposureHintMode = itr->second;
    }
    bool status = false;
    int32_t ret;
    uint32_t count = 1;
    camera_metadata_item_t item;
    MEDIA_DEBUG_LOG("%{public}s: ExposureHint mode: %{public}d", __FUNCTION__, exposureHintMode);
    ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_EXPOSURE_HINT_MODE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_EXPOSURE_HINT_MODE, &exposureHintMode, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_EXPOSURE_HINT_MODE, &exposureHintMode, count);
    }
    if (!status) {
        MEDIA_ERR_LOG("%{public}s: Failed to set ExposureHint mode", __FUNCTION__);
    }
    return CameraErrorCode::SUCCESS;
}

//----- set callbacks -----
void TimeLapsePhotoSession::SetIsoInfoCallback(shared_ptr<IsoInfoCallback> callback)
{
    lock_guard<mutex> lg(cbMtx_);
    isoInfoCallback_ = callback;
}

void TimeLapsePhotoSession::SetExposureInfoCallback(shared_ptr<ExposureInfoCallback> callback)
{
    lock_guard<mutex> lg(cbMtx_);
    exposureInfoCallback_ = callback;
}

void TimeLapsePhotoSession::SetLuminationInfoCallback(shared_ptr<LuminationInfoCallback> callback)
{
    lock_guard<mutex> lg(cbMtx_);
    luminationInfoCallback_ = callback;
}

void TimeLapsePhotoSession::SetTryAEInfoCallback(shared_ptr<TryAEInfoCallback> callback)
{
    lock_guard<mutex> lg(cbMtx_);
    tryAEInfoCallback_ = callback;
}

//----- ManualExposure -----
int32_t TimeLapsePhotoSession::GetExposure(uint32_t& result)
{
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "TimeLapsePhotoSession::GetExposure Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "TimeLapsePhotoSession::GetExposure camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET_LOG(!inputDeviceInfo, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "TimeLapsePhotoSession::GetExposure camera deviceInfo is null");
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = inputDeviceInfo->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_SENSOR_EXPOSURE_TIME, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, CameraErrorCode::INVALID_ARGUMENT,
        "TimeLapsePhotoSession::GetExposure Failed with return code %{public}d", ret);
    result = item.data.ui32[0];
    MEDIA_DEBUG_LOG("exposureTime: %{public}d", result);
    return CameraErrorCode::SUCCESS;
}

int32_t TimeLapsePhotoSession::SetExposure(uint32_t exposure)
{
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "TimeLapsePhotoSession::SetExposure Session is not Commited");
    CHECK_ERROR_RETURN_RET_LOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "TimeLapsePhotoSession::SetExposure Need to call LockForControl() before setting camera properties");
    MEDIA_DEBUG_LOG("exposure: %{public}d", exposure);
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(),
        CameraErrorCode::OPERATION_NOT_ALLOWED, "TimeLapsePhotoSession::SetExposure camera device is null");
    std::vector<uint32_t> sensorExposureTimeRange;
    if ((GetSensorExposureTimeRange(sensorExposureTimeRange) != CameraErrorCode::SUCCESS) &&
        sensorExposureTimeRange.empty()) {
        MEDIA_ERR_LOG("range is empty");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }
    const uint32_t autoLongExposure = 0;
    int32_t minIndex = 0;
    int32_t maxIndex = 1;
    if (exposure != autoLongExposure && exposure < sensorExposureTimeRange[minIndex]) {
        MEDIA_DEBUG_LOG("exposureTime:"
                        "%{public}d is lesser than minimum exposureTime: %{public}d",
                        exposure, sensorExposureTimeRange[minIndex]);
        exposure = sensorExposureTimeRange[minIndex];
    } else if (exposure > sensorExposureTimeRange[maxIndex]) {
        MEDIA_DEBUG_LOG("exposureTime: "
                        "%{public}d is greater than maximum exposureTime: %{public}d",
                        exposure, sensorExposureTimeRange[maxIndex]);
        exposure = sensorExposureTimeRange[maxIndex];
    }
    constexpr int32_t timeUnit = 1000000;
    camera_rational_t value = {.numerator = exposure, .denominator = timeUnit};
    if (!AddOrUpdateMetadata(changedMetadata_->get(), OHOS_CONTROL_SENSOR_EXPOSURE_TIME, &value, 1)) {
        MEDIA_ERR_LOG("Failed to set exposure compensation");
    }
    exposureDurationValue_ = exposure;
    return CameraErrorCode::SUCCESS;
}

int32_t TimeLapsePhotoSession::GetSupportedExposureRange(vector<uint32_t>& result)
{
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "TimeLapsePhotoSession::GetSupportedExposureRange Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(),
        CameraErrorCode::OPERATION_NOT_ALLOWED, "GetSupportedExposureRange camera device is null");
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_SENSOR_EXPOSURE_TIME_RANGE, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS || item.count == 0, CameraErrorCode::INVALID_ARGUMENT,
        "TimeLapsePhotoSession::GetSupportedExposureRange Failed with return code %{public}d", ret);
    int32_t numerator = 0;
    int32_t denominator = 0;
    uint32_t value = 0;
    constexpr int32_t timeUnit = 1000000;
    for (uint32_t i = 0; i < item.count; i++) {
        numerator = item.data.r[i].numerator;
        denominator = item.data.r[i].denominator;
        if (denominator == 0) {
            MEDIA_ERR_LOG("divide by 0! numerator=%{public}d", numerator);
            return CameraErrorCode::INVALID_ARGUMENT;
        }
        value = static_cast<uint32_t>(numerator / (denominator / timeUnit));
        MEDIA_DEBUG_LOG("numerator=%{public}d, denominator=%{public}d,"
                        " value=%{public}d", numerator, denominator, value);
        result.emplace_back(value);
    }
    MEDIA_INFO_LOG("range=%{public}s, len = %{public}zu",
                   Container2String(result.begin(), result.end()).c_str(),
                   result.size());
    return CameraErrorCode::SUCCESS;
}

const std::unordered_map<camera_meter_mode_t, MeteringMode> TimeLapsePhotoSession::metaMeteringModeMap_ = {
    {OHOS_CAMERA_SPOT_METERING,             METERING_MODE_SPOT},
    {OHOS_CAMERA_REGION_METERING,           METERING_MODE_REGION},
    {OHOS_CAMERA_OVERALL_METERING,          METERING_MODE_OVERALL},
    {OHOS_CAMERA_CENTER_WEIGHTED_METERING,  METERING_MODE_CENTER_WEIGHTED}
};

int32_t TimeLapsePhotoSession::GetSupportedMeteringModes(vector<MeteringMode>& result)
{
    result.clear();
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "TimeLapsePhotoSession::GetSupportedMeteringModes Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "GetSupportedMeteringModes camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET_LOG(!inputDeviceInfo, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "GetSupportedMeteringModes camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_METER_MODES, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "TimeLapsePhotoSession::GetSupportedMeteringModes Failed with return code %{public}d", ret);
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = metaMeteringModeMap_.find(static_cast<camera_meter_mode_t>(item.data.u8[i]));
        if (itr != metaMeteringModeMap_.end()) {
            result.emplace_back(itr->second);
        }
    }
    return CameraErrorCode::SUCCESS;
}

int32_t TimeLapsePhotoSession::IsExposureMeteringModeSupported(MeteringMode mode, bool& result)
{
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "TimeLapsePhotoSession::IsExposureMeteringModeSupported Session is not Commited");
    std::vector<MeteringMode> vecSupportedMeteringModeList;
    (void)this->GetSupportedMeteringModes(vecSupportedMeteringModeList);
    if (find(vecSupportedMeteringModeList.begin(), vecSupportedMeteringModeList.end(),
        mode) != vecSupportedMeteringModeList.end()) {
        result = true;
        return CameraErrorCode::SUCCESS;
    }
    result = false;
    return CameraErrorCode::SUCCESS;
}

int32_t TimeLapsePhotoSession::GetExposureMeteringMode(MeteringMode& result)
{
    result = METERING_MODE_SPOT;
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "TimeLapsePhotoSession::GetExposureMeteringMode Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "GetExposureMeteringMode camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET_LOG(!inputDeviceInfo, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "GetExposureMeteringMode camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_METER_MODE, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "TimeLapsePhotoSession::GetExposureMeteringMode Failed with return code %{public}d", ret);
    auto itr = metaMeteringModeMap_.find(static_cast<camera_meter_mode_t>(item.data.u8[0]));
    if (itr != metaMeteringModeMap_.end()) {
        result = itr->second;
        return CameraErrorCode::SUCCESS;
    }
    return CameraErrorCode::SUCCESS;
}

const std::unordered_map<MeteringMode, camera_meter_mode_t> TimeLapsePhotoSession::fwkMeteringModeMap_ = {
    {METERING_MODE_SPOT,                    OHOS_CAMERA_SPOT_METERING},
    {METERING_MODE_REGION,                  OHOS_CAMERA_REGION_METERING},
    {METERING_MODE_OVERALL,                 OHOS_CAMERA_OVERALL_METERING},
    {METERING_MODE_CENTER_WEIGHTED,         OHOS_CAMERA_CENTER_WEIGHTED_METERING}
};

int32_t TimeLapsePhotoSession::SetExposureMeteringMode(MeteringMode mode)
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "TimeLapsePhotoSession::SetExposureMeteringMode Session is not Commited");
    CHECK_ERROR_RETURN_RET_LOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "SetExposureMeteringMode Need to call LockForControl() before setting camera properties");
    camera_meter_mode_t meteringMode = OHOS_CAMERA_SPOT_METERING;
    auto itr = fwkMeteringModeMap_.find(mode);
    if (itr == fwkMeteringModeMap_.end()) {
        MEDIA_ERR_LOG("Unknown exposure mode");
    } else {
        meteringMode = itr->second;
    }
    bool status = false;
    int32_t ret;
    uint32_t count = 1;
    camera_metadata_item_t item;
    MEDIA_DEBUG_LOG("metering mode: %{public}d", meteringMode);
    ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_METER_MODE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_METER_MODE, &meteringMode, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_METER_MODE, &meteringMode, count);
    }
    if (!status) {
        MEDIA_ERR_LOG("Failed to set focus mode");
    }
    return CameraErrorCode::SUCCESS;
}

//----- ManualIso -----
int32_t TimeLapsePhotoSession::GetIso(int32_t& result)
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "TimeLapsePhotoSession::GetIso Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "TimeLapsePhotoSession::GetIso camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET_LOG(!inputDeviceInfo, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "TimeLapsePhotoSession::GetIso camera deviceInfo is null");
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = inputDeviceInfo->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_ISO_VALUE, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "TimeLapsePhotoSession::GetIso Failed with return code %{public}d", ret);
    result = item.data.i32[0];
    MEDIA_DEBUG_LOG("%{public}s: iso = %{public}d", __FUNCTION__, result);
    return CameraErrorCode::SUCCESS;
}

int32_t TimeLapsePhotoSession::SetIso(int32_t iso)
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "TimeLapsePhotoSession::SetIso Session is not Commited");
    CHECK_ERROR_RETURN_RET_LOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "TimeLapsePhotoSession::SetIso Need to call LockForControl() before setting camera properties");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(),
        CameraErrorCode::OPERATION_NOT_ALLOWED, "TimeLapsePhotoSession::SetIso camera device is null");
    MEDIA_DEBUG_LOG("TimeLapsePhotoSession::SetIso: iso = %{public}d", iso);
    std::vector<int32_t> isoRange;
    CHECK_ERROR_RETURN_RET_LOG((GetIsoRange(isoRange) != CameraErrorCode::SUCCESS) && isoRange.empty(),
        CameraErrorCode::OPERATION_NOT_ALLOWED, "TimeLapsePhotoSession::SetIso range is empty");
    const int32_t autoIsoValue = 0;
    if (iso != autoIsoValue && std::find(isoRange.begin(), isoRange.end(), iso) == isoRange.end()) {
        return CameraErrorCode::INVALID_ARGUMENT;
    }
    bool status = false;
    int32_t count = 1;
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_ISO_VALUE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_ISO_VALUE, &iso, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_ISO_VALUE, &iso, count);
    }
    if (!status) {
        MEDIA_ERR_LOG("%{public}s: Failed to set iso value", __FUNCTION__);
    }
    iso_ = static_cast<uint32_t>(iso);
    return CameraErrorCode::SUCCESS;
}

int32_t TimeLapsePhotoSession::IsManualIsoSupported(bool& result)
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "TimeLapsePhotoSession::IsManualIsoSupported Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "TimeLapsePhotoSession::IsManualIsoSupported camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET_LOG(!inputDeviceInfo, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "TimeLapsePhotoSession::IsManualIsoSupported camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_ISO_VALUES, &item);
    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG("%{public}s: Failed with return code %{public}d", __FUNCTION__, ret);
        result = false;
    }
    result = true;
    return CameraErrorCode::SUCCESS;
}

int32_t TimeLapsePhotoSession::GetIsoRange(vector<int32_t>& result)
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "TimeLapsePhotoSession::GetIsoRange Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(),
        CameraErrorCode::OPERATION_NOT_ALLOWED, "TimeLapsePhotoSession::GetIsoRange camera device is null");
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_ISO_VALUES, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS || item.count == 0, CameraErrorCode::INVALID_ARGUMENT,
        "TimeLapsePhotoSession::GetIsoRange Failed with return code %{public}d", ret);
    std::vector<std::vector<int32_t> > modeIsoRanges = {};
    std::vector<int32_t> modeRange = {};
    for (uint32_t i = 0; i < item.count; i++) {
        if (item.data.i32[i] != -1) {
            modeRange.emplace_back(item.data.i32[i]);
            continue;
        }
        MEDIA_DEBUG_LOG("%{public}s: mode %{public}d, range=%{public}s", __FUNCTION__,
                        GetMode(), Container2String(modeRange.begin(), modeRange.end()).c_str());
        modeIsoRanges.emplace_back(std::move(modeRange));
        modeRange.clear();
    }

    for (auto it : modeIsoRanges) {
        MEDIA_DEBUG_LOG("%{public}s: ranges=%{public}s", __FUNCTION__,
                        Container2String(it.begin(), it.end()).c_str());
        if (GetMode() == it.at(0)) {
            result.resize(it.size() - 1);
            std::copy(it.begin() + 1, it.end(), result.begin());
        }
    }
    MEDIA_INFO_LOG("%{public}s: isoRange=%{public}s, len = %{public}zu", __FUNCTION__,
                   Container2String(result.begin(), result.end()).c_str(), result.size());
    return CameraErrorCode::SUCCESS;
}

//----- WhiteBalance -----
int32_t TimeLapsePhotoSession::IsWhiteBalanceModeSupported(WhiteBalanceMode mode, bool& result)
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "TimeLapsePhotoSession::IsWhiteBalanceModeSupported Session is not Commited");
    std::vector<WhiteBalanceMode> modes;
    if (GetSupportedWhiteBalanceModes(modes) != CameraErrorCode::SUCCESS) {
        MEDIA_ERR_LOG("%{public}s: Get supported white balance modes failed", __FUNCTION__);
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }
    result = find(modes.begin(), modes.end(), mode) != modes.end();
    return CameraErrorCode::SUCCESS;
}

const std::unordered_map<camera_awb_mode_t, WhiteBalanceMode> TimeLapsePhotoSession::metaWhiteBalanceModeMap_ = {
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

int32_t TimeLapsePhotoSession::GetSupportedWhiteBalanceModes(std::vector<WhiteBalanceMode> &result)
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "TimeLapsePhotoSession::GetSupportedWhiteBalanceModes Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "GetSupportedWhiteBalanceModes camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET_LOG(!inputDeviceInfo, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "GetSupportedWhiteBalanceModes camera device is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_AWB_MODES, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "TimeLapsePhotoSession::GetSupportedWhiteBalanceModes Failed with return code %{public}d", ret);
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = metaWhiteBalanceModeMap_.find(static_cast<camera_awb_mode_t>(item.data.u8[i]));
        if (itr != metaWhiteBalanceModeMap_.end()) {
            result.emplace_back(itr->second);
        }
    }
    return CameraErrorCode::SUCCESS;
}

int32_t TimeLapsePhotoSession::GetWhiteBalanceRange(vector<int32_t>& result)
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "TimeLapsePhotoSession::GetWhiteBalanceRange Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "GetWhiteBalanceRange camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET_LOG(!inputDeviceInfo, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "GetWhiteBalanceRange camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_SENSOR_WB_VALUES, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "TimeLapsePhotoSession::GetWhiteBalanceRange Failed with return code %{public}d", ret);

    for (uint32_t i = 0; i < item.count; i++) {
        result.emplace_back(item.data.i32[i]);
    }
    return CameraErrorCode::SUCCESS;
}

int32_t TimeLapsePhotoSession::GetWhiteBalanceMode(WhiteBalanceMode& result)
{
    CAMERA_SYNC_TRACE;
    result = AWB_MODE_OFF;
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "TimeLapsePhotoSession::GetWhiteBalanceMode Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "TimeLapsePhotoSession::GetWhiteBalanceMode camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET_LOG(!inputDeviceInfo, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "TimeLapsePhotoSession::GetWhiteBalanceMode camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_AWB_MODE, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "TimeLapsePhotoSession::GetWhiteBalanceMode Failed with return code %{public}d", ret);
    auto itr = metaWhiteBalanceModeMap_.find(static_cast<camera_awb_mode_t>(item.data.u8[0]));
    if (itr != metaWhiteBalanceModeMap_.end()) {
        result = itr->second;
        return CameraErrorCode::SUCCESS;
    }
    return CameraErrorCode::SUCCESS;
}

const std::unordered_map<WhiteBalanceMode, camera_awb_mode_t> TimeLapsePhotoSession::fwkWhiteBalanceModeMap_ = {
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

int32_t TimeLapsePhotoSession::SetWhiteBalanceMode(WhiteBalanceMode mode)
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "TimeLapsePhotoSession::SetWhiteBalanceMode Session is not Commited");
    CHECK_ERROR_RETURN_RET_LOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "TimeLapsePhotoSession::SetWhiteBalanceMode Need to call LockForControl() before setting camera properties");
    camera_awb_mode_t whiteBalanceMode = OHOS_CAMERA_AWB_MODE_OFF;
    auto itr = fwkWhiteBalanceModeMap_.find(mode);
    if (itr == fwkWhiteBalanceModeMap_.end()) {
        MEDIA_WARNING_LOG("%{public}s: Unknown exposure mode", __FUNCTION__);
    } else {
        whiteBalanceMode = itr->second;
    }
    MEDIA_DEBUG_LOG("%{public}s: WhiteBalance mode: %{public}d", __FUNCTION__, whiteBalanceMode);
    // no manual wb mode need set maunual value to 0
    if (mode != AWB_MODE_OFF) {
        SetWhiteBalance(0);
    }
    if (!AddOrUpdateMetadata(changedMetadata_->get(), OHOS_CONTROL_AWB_MODE, &whiteBalanceMode, 1)) {
        MEDIA_ERR_LOG("%{public}s: Failed to set WhiteBalance mode", __FUNCTION__);
    }
    return CameraErrorCode::SUCCESS;
}

int32_t TimeLapsePhotoSession::GetWhiteBalance(int32_t& result)
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "TimeLapsePhotoSession::GetWhiteBalance Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "TimeLapsePhotoSession::GetWhiteBalance camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET_LOG(!inputDeviceInfo, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "TimeLapsePhotoSession::GetWhiteBalance camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_SENSOR_WB_VALUE, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, CameraErrorCode::SUCCESS,
        "TimeLapsePhotoSession::GetWhiteBalance Failed with return code %{public}d", ret);
    if (item.count != 0) {
        result = item.data.i32[0];
    }
    return CameraErrorCode::SUCCESS;
}

int32_t TimeLapsePhotoSession::SetWhiteBalance(int32_t wb)
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_RET_LOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "TimeLapsePhotoSession::SetWhiteBalance Session is not Commited");
    CHECK_ERROR_RETURN_RET_LOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "TimeLapsePhotoSession::SetWhiteBalance Need to call LockForControl() before setting camera properties");
    auto inputDevice = GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(),
        CameraErrorCode::OPERATION_NOT_ALLOWED, "TimeLapsePhotoSession::SetWhiteBalance camera device is null");
    MEDIA_INFO_LOG("Set tag OHOS_CONTROL_SENSOR_WB_VALUE %{public}d", wb);
    if (!AddOrUpdateMetadata(changedMetadata_->get(), OHOS_CONTROL_SENSOR_WB_VALUE, &wb, 1)) {
        MEDIA_ERR_LOG("%{public}s: Failed", __FUNCTION__);
    }
    return CameraErrorCode::SUCCESS;
}

}
}

