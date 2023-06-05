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

#include "input/camera_input.h"

#include <cinttypes>
#include <securec.h>
#include "camera_device_ability_items.h"
#include "camera_util.h"
#include "hcamera_device_callback_stub.h"
#include "camera_log.h"
#include "metadata_utils.h"
#include "session/capture_session.h"
#include "icamera_util.h"

namespace OHOS {
namespace CameraStandard {
class CameraDeviceServiceCallback : public HCameraDeviceCallbackStub {
public:
    std::mutex deviceCallbackMutex_;
    CameraInput* camInput_ = nullptr;
    CameraDeviceServiceCallback() : camInput_(nullptr) {
    }

    explicit CameraDeviceServiceCallback(CameraInput* camInput) : camInput_(camInput) {
    }

    ~CameraDeviceServiceCallback()
    {
        std::lock_guard<std::mutex> lock(deviceCallbackMutex_);
        camInput_ = nullptr;
    }

    int32_t OnError(const int32_t errorType, const int32_t errorMsg) override
    {
        std::lock_guard<std::mutex> lock(deviceCallbackMutex_);
        MEDIA_ERR_LOG("CameraDeviceServiceCallback::OnError() is called!, errorType: %{public}d, errorMsg: %{public}d",
                      errorType, errorMsg);
        if (camInput_ != nullptr && camInput_->GetErrorCallback() != nullptr) {
            camInput_->GetErrorCallback()->OnError(errorType, errorMsg);
        } else {
            MEDIA_INFO_LOG("CameraDeviceServiceCallback::ErrorCallback not set!, Discarding callback");
        }
        return CAMERA_OK;
    }

    int32_t OnResult(const uint64_t timestamp, const std::shared_ptr<Camera::CameraMetadata> &result) override
    {
        std::lock_guard<std::mutex> lock(deviceCallbackMutex_);
        if (camInput_ == nullptr) {
            MEDIA_ERR_LOG("CameraDeviceServiceCallback::OnResult() camInput_ is null!");
            return CAMERA_OK;
        }
        if (camInput_->GetCameraDeviceInfo() != nullptr) {
            MEDIA_INFO_LOG("CameraDeviceServiceCallback::OnResult() is called!,"
                           "cameraId: %{public}s, timestamp: %{public}"
                            PRIu64, camInput_->GetCameraDeviceInfo()->GetID().c_str(), timestamp);
        }
        camInput_->ProcessDeviceCallbackUpdates(result);
        return CAMERA_OK;
    }
};

CameraInput::CameraInput(sptr<ICameraDeviceService> &deviceObj,
                         sptr<CameraDevice> &cameraObj) : cameraObj_(cameraObj), deviceObj_(deviceObj)
{
    CameraDeviceSvcCallback_ = new(std::nothrow) CameraDeviceServiceCallback(this);
    if (CameraDeviceSvcCallback_ == nullptr) {
        MEDIA_ERR_LOG("CameraInput::CameraInput CameraDeviceServiceCallback alloc failed");
        return;
    }
    if (deviceObj_) {
        deviceObj_->SetCallback(CameraDeviceSvcCallback_);
    } else {
        MEDIA_ERR_LOG("CameraInput::CameraInput() deviceObj_ is nullptr");
    }
}

CameraInput::~CameraInput()
{
    cameraObj_ = nullptr;
    deviceObj_ = nullptr;
    CameraDeviceSvcCallback_ = nullptr;
    CaptureInput::Release();
}

int CameraInput::Open()
{
    std::lock_guard<std::mutex> lock(interfaceMutex_);
    int32_t retCode = CAMERA_UNKNOWN_ERROR;
    if (deviceObj_) {
        retCode = deviceObj_->Open();
        if (retCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to open Camera Input, retCode: %{public}d", retCode);
        }
    } else {
        MEDIA_ERR_LOG("CameraInput::Open() deviceObj_ is nullptr");
    }
    return ServiceToCameraError(retCode);
}

int CameraInput::Close()
{
    std::lock_guard<std::mutex> lock(interfaceMutex_);
    int32_t retCode = CAMERA_UNKNOWN_ERROR;
    if (deviceObj_) {
        retCode = deviceObj_->Close();
        if (retCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to close Camera Input, retCode: %{public}d", retCode);
        }
    } else {
        MEDIA_ERR_LOG("CameraInput::Close() deviceObj_ is nullptr");
    }
    cameraObj_ = nullptr;
    deviceObj_ = nullptr;
    CameraDeviceSvcCallback_ = nullptr;
    CaptureInput::Release();
    return ServiceToCameraError(retCode);
}

int CameraInput::Release()
{
    int32_t retCode = CAMERA_UNKNOWN_ERROR;
    if (deviceObj_) {
        retCode = deviceObj_->Release();
        if (retCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to release Camera Input, retCode: %{public}d", retCode);
        }
    } else {
        MEDIA_ERR_LOG("CameraInput::Release() deviceObj_ is nullptr");
    }
    cameraObj_ = nullptr;
    deviceObj_ = nullptr;
    CameraDeviceSvcCallback_ = nullptr;
    CaptureInput::Release();
    return ServiceToCameraError(retCode);
}

void CameraInput::SetErrorCallback(std::shared_ptr<ErrorCallback> errorCallback)
{
    if (errorCallback == nullptr) {
        MEDIA_ERR_LOG("SetErrorCallback: Unregistering error callback");
    }
    errorCallback_ = errorCallback;
    return;
}

std::string CameraInput::GetCameraId()
{
    return cameraObj_->GetID();
}

sptr<ICameraDeviceService> CameraInput::GetCameraDevice()
{
    return deviceObj_;
}

std::shared_ptr<ErrorCallback> CameraInput::GetErrorCallback()
{
    return errorCallback_;
}

sptr<CameraDevice> CameraInput::GetCameraDeviceInfo()
{
    return cameraObj_;
}

void CameraInput::ProcessDeviceCallbackUpdates(const std::shared_ptr<Camera::CameraMetadata> &result)
{
    CaptureSession* captureSession = GetSession();
    if (captureSession == nullptr) {
        return;
    }

    captureSession->ProcessAutoExposureUpdates(result);
    captureSession->ProcessAutoFocusUpdates(result);
}

int32_t CameraInput::UpdateSetting(std::shared_ptr<OHOS::Camera::CameraMetadata> changedMetadata)
{
    CAMERA_SYNC_TRACE;
    int32_t ret = CAMERA_OK;
    if (!OHOS::Camera::GetCameraMetadataItemCount(changedMetadata->get())) {
        MEDIA_INFO_LOG("CameraInput::UpdateSetting No configuration to update");
        return ret;
    }

    if (deviceObj_) {
        ret = deviceObj_->UpdateSetting(changedMetadata);
    } else {
        MEDIA_ERR_LOG("CameraInput::UpdateSetting() deviceObj_ is nullptr");
    }
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("CameraInput::UpdateSetting Failed to update settings");
        return ret;
    }

    size_t length;
    uint32_t count = changedMetadata->get()->item_count;
    uint8_t* data = OHOS::Camera::GetMetadataData(changedMetadata->get());
    camera_metadata_item_entry_t* itemEntry = OHOS::Camera::GetMetadataItems(changedMetadata->get());
    std::shared_ptr<OHOS::Camera::CameraMetadata> baseMetadata = cameraObj_->GetMetadata();
    for (uint32_t i = 0; i < count; i++, itemEntry++) {
        bool status = false;
        camera_metadata_item_t item;
        length = OHOS::Camera::CalculateCameraMetadataItemDataSize(itemEntry->data_type, itemEntry->count);
        ret = OHOS::Camera::FindCameraMetadataItem(baseMetadata->get(), itemEntry->item, &item);
        if (ret == CAM_META_SUCCESS) {
            status = baseMetadata->updateEntry(itemEntry->item,
                                               (length == 0) ? itemEntry->data.value : (data + itemEntry->data.offset),
                                               itemEntry->count);
        } else if (ret == CAM_META_ITEM_NOT_FOUND) {
            status = baseMetadata->addEntry(itemEntry->item,
                                            (length == 0) ? itemEntry->data.value : (data + itemEntry->data.offset),
                                            itemEntry->count);
        }
        if (!status) {
            MEDIA_ERR_LOG("CameraInput::UpdateSetting Failed to add/update metadata item: %{public}d",
                          itemEntry->item);
        }
    }
    return CAMERA_OK;
}

std::string CameraInput::GetCameraSettings()
{
    return OHOS::Camera::MetadataUtils::EncodeToString(cameraObj_->GetMetadata());
}

int32_t CameraInput::SetCameraSettings(std::string setting)
{
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = OHOS::Camera::MetadataUtils::DecodeFromString(setting);
    if (metadata == nullptr) {
        MEDIA_ERR_LOG("CameraInput::SetCameraSettings Failed to decode metadata setting from string");
        return CAMERA_INVALID_ARG;
    }
    return UpdateSetting(metadata);
}
} // CameraStandard
} // OHOS
