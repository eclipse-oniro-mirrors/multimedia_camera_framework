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
    CHECK_ERROR_RETURN_RET_LOG(result == nullptr, CAMERA_INVALID_ARG, "OnResult get null meta from server");
    std::lock_guard<std::mutex> lock(deviceCallbackMutex_);
    auto camInputSptr = camInput_.promote();
    CHECK_ERROR_RETURN_RET_LOG(camInputSptr == nullptr, CAMERA_OK,
        "CameraDeviceServiceCallback::OnResult() camInput_ is null!");
    auto cameraObject = camInputSptr->GetCameraDeviceInfo();
    if (cameraObject == nullptr) {
        MEDIA_ERR_LOG("CameraDeviceServiceCallback::OnResult() camInput_->GetCameraDeviceInfo() is null!");
    } else {
        MEDIA_DEBUG_LOG("CameraDeviceServiceCallback::OnResult()"
                        "is called!, cameraId: %{public}s, timestamp: %{public}"
                        PRIu64, cameraObject->GetID().c_str(), timestamp);
    }
    if (camInputSptr->GetResultCallback() != nullptr) {
        camInputSptr->GetResultCallback()->OnResult(timestamp, result);
    }

    auto pfnOcclusionDetectCallback = camInputSptr->GetOcclusionDetectCallback();
    if (pfnOcclusionDetectCallback != nullptr) {
        camera_metadata_item itemOcclusion;
        int32_t retOcclusion = OHOS::Camera::FindCameraMetadataItem(result->get(),
            OHOS_STATUS_CAMERA_OCCLUSION_DETECTION, &itemOcclusion);
        bool foundOcclusion = (retOcclusion == CAM_META_SUCCESS && itemOcclusion.count != 0);
        uint8_t occlusion = foundOcclusion ? static_cast<uint8_t>(itemOcclusion.data.i32[0]) : 0;

        camera_metadata_item itemLensDirty;
        int32_t retLensDirty = OHOS::Camera::FindCameraMetadataItem(result->get(),
            OHOS_STATUS_CAMERA_LENS_DIRTY_DETECTION, &itemLensDirty);
        bool foundLensDirty = (retLensDirty == CAM_META_SUCCESS && itemLensDirty.count != 0);
        uint8_t lensDirty = foundLensDirty ? itemLensDirty.data.u8[0] : 0;

        if (foundOcclusion || foundLensDirty) {
            MEDIA_INFO_LOG("occlusion found:%{public}d val:%{public}u; lensDirty found:%{public}d val:%{public}u",
                foundOcclusion, occlusion, foundLensDirty, lensDirty);
            pfnOcclusionDetectCallback->OnCameraOcclusionDetected(occlusion, lensDirty);
        }
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
    CHECK_ERROR_RETURN_LOG(CameraDeviceSvcCallback_ == nullptr, "Failed to new CameraDeviceSvcCallback_!");
    CHECK_ERROR_RETURN_LOG(!deviceObj_, "CameraInput::CameraInput() deviceObj_ is nullptr");
    deviceObj_->SetCallback(CameraDeviceSvcCallback_);
    sptr<IRemoteObject> object = deviceObj_->AsObject();
    CHECK_ERROR_RETURN(object == nullptr);
    pid_t pid = 0;
    deathRecipient_ = new(std::nothrow) CameraDeathRecipient(pid);
    CHECK_AND_RETURN_LOG(deathRecipient_ != nullptr, "failed to new CameraDeathRecipient.");
    auto thisPtr = wptr<CameraInput>(this);
    deathRecipient_->SetNotifyCb([thisPtr](pid_t pid) {
        auto ptr = thisPtr.promote();
        if (ptr != nullptr) {
            ptr->CameraServerDied(pid);
        }
    });
    bool result = object->AddDeathRecipient(deathRecipient_);
    CHECK_ERROR_RETURN_LOG(!result, "CameraInput::CameraInput failed to add deathRecipient");
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
    InputRemoveDeathRecipient();
}

void CameraInput::InputRemoveDeathRecipient()
{
    auto deviceObj = GetCameraDevice();
    if (deviceObj != nullptr) {
        (void)deviceObj->AsObject()->RemoveDeathRecipient(deathRecipient_);
        SetCameraDevice(nullptr);
    }
    deathRecipient_ = nullptr;
}

CameraInput::~CameraInput()
{
    MEDIA_INFO_LOG("CameraInput::CameraInput Destructor!");
    std::lock_guard<std::mutex> lock(interfaceMutex_);
    if (cameraObj_) {
        MEDIA_INFO_LOG("CameraInput::CameraInput Destructor Camera: %{public}s", cameraObj_->GetID().c_str());
    }
    InputRemoveDeathRecipient();
}

int CameraInput::Open()
{
    std::lock_guard<std::mutex> lock(interfaceMutex_);
    MEDIA_DEBUG_LOG("Enter Into CameraInput::Open");
    int32_t retCode = CAMERA_UNKNOWN_ERROR;
    auto deviceObj = GetCameraDevice();
    if (deviceObj) {
        retCode = deviceObj->Open();
        CHECK_ERROR_PRINT_LOG(retCode != CAMERA_OK, "Failed to open Camera Input, retCode: %{public}d", retCode);
    } else {
        MEDIA_ERR_LOG("CameraInput::Open() deviceObj is nullptr");
    }
    return ServiceToCameraError(retCode);
}

int CameraInput::Open(bool isEnableSecureCamera, uint64_t* secureSeqId)
{
    std::lock_guard<std::mutex> lock(interfaceMutex_);
    MEDIA_DEBUG_LOG("Enter Into CameraInput::OpenSecureCamera");
    int32_t retCode = CAMERA_UNKNOWN_ERROR;
    bool isSupportSecCamera = false;
    auto cameraObject = GetCameraDeviceInfo();
    if (isEnableSecureCamera && cameraObject) {
        std::shared_ptr<OHOS::Camera::CameraMetadata> baseMetadata = cameraObject->GetMetadata();
        CHECK_ERROR_RETURN_RET_LOG(baseMetadata == nullptr, retCode,
            "CameraInput::GetMetaSetting Failed to find baseMetadata");
        camera_metadata_item_t item;
        retCode = OHOS::Camera::FindCameraMetadataItem(baseMetadata->get(), OHOS_ABILITY_CAMERA_MODES, &item);
        CHECK_ERROR_RETURN_RET_LOG(retCode != CAM_META_SUCCESS || item.count == 0, retCode,
            "CaptureSession::GetSupportedModes Failed with return code %{public}d", retCode);
        for (uint32_t i = 0; i < item.count; i++) {
            if (item.data.u8[i] == SECURE) {
                isSupportSecCamera = true;
            }
        }
    }

    auto deviceObj = GetCameraDevice();
    if (deviceObj) {
        retCode = isSupportSecCamera ? (deviceObj->OpenSecureCamera(secureSeqId)) : (deviceObj->Open());
        CHECK_ERROR_PRINT_LOG(retCode != CAMERA_OK,
            "Failed to open Camera Input, retCode: %{public}d, isSupportSecCamera is %{public}d",
                retCode, isSupportSecCamera);
    } else {
        MEDIA_ERR_LOG("CameraInput::OpenSecureCamera() deviceObj is nullptr");
    }
    MEDIA_INFO_LOG("Enter Into CameraInput::OpenSecureCamera secureSeqId = %{public}" PRIu64, *secureSeqId);
    return ServiceToCameraError(retCode);
}

int CameraInput::Close()
{
    std::lock_guard<std::mutex> lock(interfaceMutex_);
    MEDIA_DEBUG_LOG("Enter Into CameraInput::Close");
    int32_t retCode = CAMERA_UNKNOWN_ERROR;
    auto deviceObj = GetCameraDevice();
    if (deviceObj) {
        retCode = deviceObj->Close();
        CHECK_ERROR_PRINT_LOG(retCode != CAMERA_OK, "Failed to close Camera Input, retCode: %{public}d", retCode);
    } else {
        MEDIA_ERR_LOG("CameraInput::Close() deviceObj is nullptr");
    }
    SetCameraDeviceInfo(nullptr);
    InputRemoveDeathRecipient();
    CameraDeviceSvcCallback_ = nullptr;
    return ServiceToCameraError(retCode);
}

int CameraInput::Release()
{
    std::lock_guard<std::mutex> lock(interfaceMutex_);
    MEDIA_DEBUG_LOG("Enter Into CameraInput::Release");
    int32_t retCode = CAMERA_UNKNOWN_ERROR;
    auto deviceObj = GetCameraDevice();
    if (deviceObj) {
        retCode = deviceObj->Release();
        CHECK_ERROR_PRINT_LOG(retCode != CAMERA_OK, "Failed to release Camera Input, retCode: %{public}d", retCode);
    } else {
        MEDIA_ERR_LOG("CameraInput::Release() deviceObj is nullptr");
    }
    SetCameraDeviceInfo(nullptr);
    InputRemoveDeathRecipient();
    CameraDeviceSvcCallback_ = nullptr;
    return ServiceToCameraError(retCode);
}

void CameraInput::SetErrorCallback(std::shared_ptr<ErrorCallback> errorCallback)
{
    CHECK_ERROR_PRINT_LOG(errorCallback == nullptr, "SetErrorCallback: Unregistering error callback");
    std::lock_guard<std::mutex> lock(errorCallbackMutex_);
    errorCallback_ = errorCallback;
    return;
}

void CameraInput::SetResultCallback(std::shared_ptr<ResultCallback> resultCallback)
{
    CHECK_ERROR_PRINT_LOG(resultCallback == nullptr, "SetResultCallback: Unregistering error resultCallback");
    MEDIA_DEBUG_LOG("CameraInput::setresult callback");
    std::lock_guard<std::mutex> lock(resultCallbackMutex_);
    resultCallback_ = resultCallback;
    return;
}
void CameraInput::SetCameraDeviceInfo(sptr<CameraDevice> cameraObj)
{
    MEDIA_DEBUG_LOG("CameraInput::SetCameraDeviceInfo");
    std::lock_guard<std::mutex> lock(cameraDeviceInfoMutex_);
    cameraObj_ = cameraObj;
    return;
}

void CameraInput::SetOcclusionDetectCallback(
    std::shared_ptr<CameraOcclusionDetectCallback> cameraOcclusionDetectCallback)
{
    CHECK_ERROR_PRINT_LOG(cameraOcclusionDetectCallback == nullptr,
        "SetOcclusionDetectCallback: SetOcclusionDetectCallback error cameraOcclusionDetectCallback");
    MEDIA_DEBUG_LOG("CameraInput::SetOcclusionDetectCallback callback");
    std::lock_guard<std::mutex> lock(occlusionCallbackMutex_);
    cameraOcclusionDetectCallback_ = cameraOcclusionDetectCallback;
    return;
}

std::string CameraInput::GetCameraId()
{
    auto cameraObject = GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET_LOG(cameraObject == nullptr, nullptr, "CameraInput::GetCameraId cameraObject is null");
    return cameraObject->GetID();
}

sptr<ICameraDeviceService> CameraInput::GetCameraDevice()
{
    std::lock_guard<std::mutex> lock(deviceObjMutex_);
    return deviceObj_;
}

void CameraInput::SetCameraDevice(sptr<ICameraDeviceService> deviceObj)
{
    std::lock_guard<std::mutex> lock(deviceObjMutex_);
    deviceObj_ = deviceObj;
    return;
}

std::shared_ptr<ErrorCallback> CameraInput::GetErrorCallback()
{
    std::lock_guard<std::mutex> lock(errorCallbackMutex_);
    return errorCallback_;
}

std::shared_ptr<ResultCallback> CameraInput::GetResultCallback()
{
    std::lock_guard<std::mutex> lock(resultCallbackMutex_);
    MEDIA_DEBUG_LOG("CameraDeviceServiceCallback::GetResultCallback");
    return resultCallback_;
}

std::shared_ptr<CameraOcclusionDetectCallback> CameraInput::GetOcclusionDetectCallback()
{
    std::lock_guard<std::mutex> lock(occlusionCallbackMutex_);
    return cameraOcclusionDetectCallback_;
}

sptr<CameraDevice> CameraInput::GetCameraDeviceInfo()
{
    std::lock_guard<std::mutex> lock(cameraDeviceInfoMutex_);
    return cameraObj_;
}

void CameraInput::ProcessCallbackUpdates(
    const uint64_t timestamp, const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    auto metadataResultProcessor = GetMetadataResultProcessor();
    CHECK_ERROR_RETURN(metadataResultProcessor == nullptr);
    metadataResultProcessor->ProcessCallbacks(timestamp, result);
}

int32_t CameraInput::UpdateSetting(std::shared_ptr<OHOS::Camera::CameraMetadata> changedMetadata)
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_RET(changedMetadata == nullptr, CAMERA_INVALID_ARG);
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::Camera::GetCameraMetadataItemCount(changedMetadata->get()), CAMERA_OK,
        "CameraInput::UpdateSetting No configuration to update");

    std::lock_guard<std::mutex> lock(interfaceMutex_);
    auto deviceObj = GetCameraDevice();
    CHECK_ERROR_RETURN_RET_LOG(!deviceObj, ServiceToCameraError(CAMERA_INVALID_ARG),
        "CameraInput::UpdateSetting() deviceObj is nullptr");
    int32_t ret = deviceObj->UpdateSetting(changedMetadata);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAMERA_OK, ret, "CameraInput::UpdateSetting Failed to update settings");

    auto cameraObject = GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET_LOG(cameraObject == nullptr, CAMERA_INVALID_ARG,
        "CameraInput::UpdateSetting cameraObject is null");

    std::shared_ptr<OHOS::Camera::CameraMetadata> baseMetadata = cameraObject->GetMetadata();
    bool mergeResult = MergeMetadata(changedMetadata, baseMetadata);
    CHECK_ERROR_RETURN_RET_LOG(!mergeResult, CAMERA_INVALID_ARG,
        "CameraInput::UpdateSetting() baseMetadata or itemEntry is nullptr");
    return CAMERA_OK;
}

bool CameraInput::MergeMetadata(const std::shared_ptr<OHOS::Camera::CameraMetadata> srcMetadata,
    std::shared_ptr<OHOS::Camera::CameraMetadata> dstMetadata)
{
    CHECK_ERROR_RETURN_RET(srcMetadata == nullptr || dstMetadata == nullptr, false);
    auto srcHeader = srcMetadata->get();
    CHECK_ERROR_RETURN_RET(srcHeader == nullptr, false);
    auto dstHeader = dstMetadata->get();
    CHECK_ERROR_RETURN_RET(dstHeader == nullptr, false);

    auto srcItemCount = srcHeader->item_count;
    camera_metadata_item_t srcItem;
    for (uint32_t index = 0; index < srcItemCount; index++) {
        int ret = OHOS::Camera::GetCameraMetadataItem(srcHeader, index, &srcItem);
        CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, false,
            "Failed to get metadata item at index: %{public}d", index);
        bool status = false;
        uint32_t currentIndex;
        ret = OHOS::Camera::FindCameraMetadataItemIndex(dstHeader, srcItem.item, &currentIndex);
        if (ret == CAM_META_ITEM_NOT_FOUND) {
            status = dstMetadata->addEntry(srcItem.item, srcItem.data.u8, srcItem.count);
        } else if (ret == CAM_META_SUCCESS) {
            status = dstMetadata->updateEntry(srcItem.item, srcItem.data.u8, srcItem.count);
        }
        CHECK_ERROR_RETURN_RET_LOG(!status, false, "Failed to update metadata item: %{public}d", srcItem.item);
    }
    return true;
}

std::string CameraInput::GetCameraSettings()
{
    auto cameraObject = GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET_LOG(cameraObject == nullptr, nullptr, "GetCameraSettings cameraObject is null");
    return OHOS::Camera::MetadataUtils::EncodeToString(cameraObject->GetMetadata());
}

int32_t CameraInput::SetCameraSettings(std::string setting)
{
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = OHOS::Camera::MetadataUtils::DecodeFromString(setting);
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, CAMERA_INVALID_ARG,
        "CameraInput::SetCameraSettings Failed to decode metadata setting from string");
    return UpdateSetting(metadata);
}

std::shared_ptr<camera_metadata_item_t> CameraInput::GetMetaSetting(uint32_t metaTag)
{
    auto cameraObject = GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET_LOG(cameraObject == nullptr, nullptr,
        "CameraInput::GetMetaSetting cameraObj has release!");
    std::shared_ptr<OHOS::Camera::CameraMetadata> baseMetadata = cameraObject->GetMetadata();
    CHECK_ERROR_RETURN_RET_LOG(baseMetadata == nullptr, nullptr,
        "CameraInput::GetMetaSetting Failed to find baseMetadata");
    std::shared_ptr<camera_metadata_item_t> item = MetadataCommonUtils::GetCapabilityEntry(baseMetadata, metaTag);
    CHECK_ERROR_RETURN_RET_LOG(item == nullptr || item->count == 0, nullptr,
        "CameraInput::GetMetaSetting  Failed to find meta item: metaTag = %{public}u", metaTag);
    return item;
}

int32_t CameraInput::GetCameraAllVendorTags(std::vector<vendorTag_t> &infos) __attribute__((no_sanitize("cfi")))
{
    infos.clear();
    MEDIA_INFO_LOG("CameraInput::GetCameraAllVendorTags called!");
    int32_t ret = OHOS::Camera::GetAllVendorTags(infos);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, CAMERA_UNKNOWN_ERROR,
        "CameraInput::GetCameraAllVendorTags failed! because of hdi error, ret = %{public}d", ret);
    MEDIA_INFO_LOG("CameraInput::GetCameraAllVendorTags success! vendors size = %{public}zu!", infos.size());
    MEDIA_INFO_LOG("CameraInput::GetCameraAllVendorTags end!");
    return CAMERA_OK;
}
} // namespace CameraStandard
} // namespace OHOS
