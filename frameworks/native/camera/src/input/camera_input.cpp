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
#include <mutex>
#include <securec.h>
#include "camera_device_ability_items.h"
#include "camera_log.h"
#include "camera_util.h"
#include "hcamera_device_callback_stub.h"
#include "icamera_util.h"
#include "metadata_utils.h"
#include "output/metadata_output.h"
#include "session/capture_session.h"

namespace OHOS {
namespace CameraStandard {
using OHOS::HDI::Camera::V1_3::OperationMode;
int32_t CameraDeviceServiceCallback::OnError(const int32_t errorType, const int32_t errorMsg)
{
    std::lock_guard<std::mutex> lock(deviceCallbackMutex_);
    auto camInputSptr = camInput_.promote();
    MEDIA_ERR_LOG("CameraDeviceServiceCallback::OnError() is called!, errorType: %{public}d, errorMsg: %{public}d",
                  errorType, errorMsg);
    if (camInputSptr != nullptr && camInputSptr->GetErrorCallback() != nullptr) {
        int32_t serviceErrorType = ServiceToCameraError(errorType);
        camInputSptr->GetErrorCallback()->OnError(serviceErrorType, errorMsg);
    } else {
        MEDIA_INFO_LOG("CameraDeviceServiceCallback::ErrorCallback not set!, Discarding callback");
    }
    return CAMERA_OK;
}

int32_t CameraDeviceServiceCallback::OnResult(const uint64_t timestamp,
                                              const std::shared_ptr<OHOS::Camera::CameraMetadata> &result)
{
    std::lock_guard<std::mutex> lock(deviceCallbackMutex_);
    auto camInputSptr = camInput_.promote();
    if (camInputSptr == nullptr) {
        MEDIA_ERR_LOG("CameraDeviceServiceCallback::OnResult() camInput_ is null!");
        return CAMERA_OK;
    }
    if (camInputSptr->GetCameraDeviceInfo() == nullptr) {
        MEDIA_ERR_LOG("CameraDeviceServiceCallback::OnResult() camInput_->GetCameraDeviceInfo() is null!");
    } else {
        MEDIA_DEBUG_LOG("CameraDeviceServiceCallback::OnResult()"
                        "is called!, cameraId: %{public}s, timestamp: %{public}"
                        PRIu64, camInputSptr->GetCameraDeviceInfo()->GetID().c_str(), timestamp);
    }
    if (camInputSptr->GetResultCallback() != nullptr) {
        camInputSptr->GetResultCallback()->OnResult(timestamp, result);
    }
    camInputSptr->ProcessCallbackUpdates(timestamp, result);
    return CAMERA_OK;
}


CameraInput::CameraInput(sptr<ICameraDeviceService> &deviceObj,
                         sptr<CameraDevice> &cameraObj) : deviceObj_(deviceObj), cameraObj_(cameraObj)
{
    MEDIA_INFO_LOG("CameraInput::CameraInput Contructor!");
    if (cameraObj_) {
        MEDIA_INFO_LOG("CameraInput::CameraInput Contructor Camera: %{public}s", cameraObj_->GetID().c_str());
    }
    CameraDeviceSvcCallback_ = new(std::nothrow) CameraDeviceServiceCallback(this);
    if (deviceObj_) {
        deviceObj_->SetCallback(CameraDeviceSvcCallback_);
    } else {
        MEDIA_ERR_LOG("CameraInput::CameraInput() deviceObj_ is nullptr");
        return;
    }
    sptr<IRemoteObject> object = deviceObj_->AsObject();
    if (object == nullptr) {
        return;
    }
    pid_t pid = 0;
    deathRecipient_ = new(std::nothrow) CameraDeathRecipient(pid);
    CHECK_AND_RETURN_LOG(deathRecipient_ != nullptr, "failed to new CameraDeathRecipient.");

    deathRecipient_->SetNotifyCb(std::bind(&CameraInput::CameraServerDied, this, std::placeholders::_1));
    bool result = object->AddDeathRecipient(deathRecipient_);
    if (!result) {
        MEDIA_ERR_LOG("failed to add deathRecipient");
        return;
    }
}

void CameraInput::CameraServerDied(pid_t pid)
{
    MEDIA_ERR_LOG("camera server has died, pid:%{public}d!", pid);
    {
        std::lock_guard<std::mutex> errLock(errorCallbackMutex_);
        if (errorCallback_ != nullptr) {
            MEDIA_DEBUG_LOG("appCallback not nullptr");
            int32_t serviceErrorType = ServiceToCameraError(CAMERA_INVALID_STATE);
            int32_t serviceErrorMsg = 0;
            MEDIA_DEBUG_LOG("serviceErrorType:%{public}d!, serviceErrorMsg:%{public}d!", serviceErrorType,
                            serviceErrorMsg);
            errorCallback_->OnError(serviceErrorType, serviceErrorMsg);
        }
    }
    std::lock_guard<std::mutex> interfaceLock(interfaceMutex_);
    {
        if (deviceObj_ != nullptr) {
            (void)deviceObj_->AsObject()->RemoveDeathRecipient(deathRecipient_);
            deviceObj_ = nullptr;
        }
        deathRecipient_ = nullptr;
    }
}

CameraInput::~CameraInput()
{
    MEDIA_INFO_LOG("CameraInput::CameraInput Destructor!");
    std::lock_guard<std::mutex> lock(interfaceMutex_);
    if (cameraObj_) {
        MEDIA_INFO_LOG("CameraInput::CameraInput Destructor Camera: %{public}s", cameraObj_->GetID().c_str());
    }
    if (deviceObj_ != nullptr) {
        (void)deviceObj_->AsObject()->RemoveDeathRecipient(deathRecipient_);
        deviceObj_ = nullptr;
    }
}

int CameraInput::Open()
{
    std::lock_guard<std::mutex> lock(interfaceMutex_);
    MEDIA_DEBUG_LOG("Enter Into CameraInput::Open");
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

int CameraInput::Open(bool isEnableSecureCamera, uint64_t* secureSeqId)
{
    std::lock_guard<std::mutex> lock(interfaceMutex_);
    MEDIA_DEBUG_LOG("Enter Into CameraInput::OpenSecureCamera");
    int32_t retCode = CAMERA_UNKNOWN_ERROR;
    bool isSupportSecCamera = false;
    if (isEnableSecureCamera) {
        std::shared_ptr<OHOS::Camera::CameraMetadata> baseMetadata = cameraObj_->GetMetadata();
        camera_metadata_item_t item;
        retCode = OHOS::Camera::FindCameraMetadataItem(baseMetadata->get(), OHOS_ABILITY_CAMERA_MODES, &item);
        if (retCode != CAM_META_SUCCESS || item.count == 0) {
            MEDIA_ERR_LOG("CaptureSession::GetSupportedModes Failed with return code %{public}d", retCode);
            return retCode;
        }
        for (uint32_t i = 0; i < item.count; i++) {
            if (item.data.u8[i] == SECURE) {
                isSupportSecCamera = true;
            }
        }
    }

    if (deviceObj_) {
        retCode = isSupportSecCamera ? (deviceObj_->OpenSecureCamera(secureSeqId)) : (deviceObj_->Open());
        if (retCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to open Camera Input, retCode: %{public}d, isSupportSecCamera is %{public}d",
                retCode, isSupportSecCamera);
        }
    } else {
        MEDIA_ERR_LOG("CameraInput::OpenSecureCamera() deviceObj_ is nullptr");
    }
    MEDIA_INFO_LOG("Enter Into CameraInput::OpenSecureCamera secureSeqId = %{public}" PRIu64, *secureSeqId);
    return ServiceToCameraError(retCode);
}

int CameraInput::Close()
{
    std::lock_guard<std::mutex> lock(interfaceMutex_);
    MEDIA_DEBUG_LOG("Enter Into CameraInput::Close");
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
    return ServiceToCameraError(retCode);
}

int CameraInput::Release()
{
    std::lock_guard<std::mutex> lock(interfaceMutex_);
    MEDIA_DEBUG_LOG("Enter Into CameraInput::Release");
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
    return ServiceToCameraError(retCode);
}

void CameraInput::SetErrorCallback(std::shared_ptr<ErrorCallback> errorCallback)
{
    if (errorCallback == nullptr) {
        MEDIA_ERR_LOG("SetErrorCallback: Unregistering error callback");
    }
    std::lock_guard<std::mutex> lock(errorCallbackMutex_);
    errorCallback_ = errorCallback;
    return;
}

void CameraInput::SetResultCallback(std::shared_ptr<ResultCallback> resultCallback)
{
    if (resultCallback == nullptr) {
        MEDIA_ERR_LOG("SetResultCallback: Unregistering error resultCallback");
    }
    MEDIA_DEBUG_LOG("CameraInput::setresult callback");
    resultCallback_ = resultCallback;
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
    std::lock_guard<std::mutex> lock(errorCallbackMutex_);
    return errorCallback_;
}
std::shared_ptr<ResultCallback> CameraInput::GetResultCallback()
{
    MEDIA_DEBUG_LOG("CameraDeviceServiceCallback::GetResultCallback");
    return resultCallback_;
}
sptr<CameraDevice> CameraInput::GetCameraDeviceInfo()
{
    return cameraObj_;
}

void CameraInput::ProcessCallbackUpdates(
    const uint64_t timestamp, const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    auto metadataResultProcessor = GetMetadataResultProcessor();
    if (metadataResultProcessor == nullptr) {
        return;
    }
    metadataResultProcessor->ProcessCallbacks(timestamp, result);
}

int32_t CameraInput::UpdateSetting(std::shared_ptr<OHOS::Camera::CameraMetadata> changedMetadata)
{
    CAMERA_SYNC_TRACE;
    int32_t ret = CAMERA_OK;
    if (changedMetadata == nullptr) {
        return CAMERA_INVALID_ARG;
    }
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
    if (baseMetadata == nullptr || itemEntry == nullptr) {
        MEDIA_ERR_LOG("CameraInput::UpdateSetting() baseMetadata or itemEntry is nullptr");
        return CAMERA_INVALID_ARG;
    }
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

std::shared_ptr<camera_metadata_item_t> CameraInput::GetMetaSetting(uint32_t metaTag)
{
    if (cameraObj_ ==nullptr) {
        MEDIA_ERR_LOG("CameraInput::GetMetaSetting cameraObj has release!");
        return nullptr;
    }
    std::shared_ptr<OHOS::Camera::CameraMetadata> baseMetadata = cameraObj_->GetMetadata();
    if (baseMetadata == nullptr) {
        MEDIA_ERR_LOG("CameraInput::GetMetaSetting Failed to find baseMetadata");
        return nullptr;
    }
    std::shared_ptr<camera_metadata_item_t> item = MetadataCommonUtils::GetCapabilityEntry(baseMetadata, metaTag);
    if (item == nullptr || item->count == 0) {
        MEDIA_ERR_LOG("CameraInput::GetMetaSetting Failed to find meta item: metaTag = %{public}u", metaTag);
        return nullptr;
    }
    return item;
}

int32_t CameraInput::GetCameraAllVendorTags(std::vector<vendorTag_t> &infos)
{
    infos.clear();
    MEDIA_INFO_LOG("CameraInput::GetCameraAllVendorTags called!");
    int32_t ret = OHOS::Camera::GetAllVendorTags(infos);
    if (ret == CAM_META_SUCCESS) {
        MEDIA_INFO_LOG("CameraInput::GetCameraAllVendorTags success! vendors size = %{public}zu!", infos.size());
    } else {
        MEDIA_ERR_LOG("CameraInput::GetCameraAllVendorTags failed! because of hdi error, ret = %{public}d", ret);
        return CAMERA_UNKNOWN_ERROR;
    }
    MEDIA_INFO_LOG("CameraInput::GetCameraAllVendorTags end!");
    return CAMERA_OK;
}
} // namespace CameraStandard
} // namespace OHOS
