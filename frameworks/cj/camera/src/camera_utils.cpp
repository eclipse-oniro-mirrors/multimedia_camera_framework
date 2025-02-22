/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <cstdint>
#include <memory>
#include <string>
#include "camera_error.h"
#include "camera_utils.h"

namespace OHOS {
namespace CameraStandard {
char *MallocCString(const std::string &origin)
{
    auto len = origin.length() + 1;
    char *res = static_cast<char *>(malloc(sizeof(char) * len));
    if (res == nullptr) {
        return nullptr;
    }
    return std::char_traits<char>::copy(res, origin.c_str(), len);
}

double CJFloatToDouble(float val)
{
    const double precision = 1000000.0;
    val *= precision;
    double result = static_cast<double>(val / precision);
    return result;
}

CArrCJProfile VectorProfileToCArrCJProfile(std::vector<Profile> profile, int32_t *errCode)
{
    CArrCJProfile result = CArrCJProfile{0};
    result.size = profile.size();
    if (profile.size() == 0) {
        return result;
    }
    result.head = static_cast<CJProfile *>(malloc(sizeof(CJProfile) * profile.size()));
    if (result.head == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return result;
    }
    for (size_t i = 0; i < profile.size(); i++) {
        result.head[i].format = profile[i].GetCameraFormat();
        Size t = profile[i].GetSize();
        result.head[i].width = t.width;
        result.head[i].height = t.height;
    }
    return result;
}

CArrCJVideoProfile VectorVideoProfileToCArrCJVideoProfile(std::vector<VideoProfile> profile, int32_t *errCode)
{
    CArrCJVideoProfile result = CArrCJVideoProfile{0};
    result.size = profile.size();
    if (profile.size() == 0) {
        return result;
    }
    result.head = static_cast<CJVideoProfile *>(malloc(sizeof(CJVideoProfile) * profile.size()));
    if (result.head == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return result;
    }
    for (size_t i = 0; i < profile.size(); i++) {
        result.head[i].format = profile[i].GetCameraFormat();
        Size t = profile[i].GetSize();
        result.head[i].width = t.width;
        result.head[i].height = t.height;
        std::vector<int32_t> vpi_framerates = profile[i].GetFrameRates();
        result.head[i].frameRateRange.min = vpi_framerates[0];
        result.head[i].frameRateRange.max = vpi_framerates[1];
    }
    return result;
}

CJCameraOutputCapability CameraOutputCapabilityToCJCameraOutputCapability(
    sptr<CameraOutputCapability> cameraOutputCapability, int32_t *errCode)
{
    CJCameraOutputCapability result =
        CJCameraOutputCapability{CArrCJProfile{0}, CArrCJProfile{0}, CArrCJVideoProfile{0}, CArrI32{0}};
    std::vector<Profile> photoProfiles_ = cameraOutputCapability->GetPhotoProfiles();
    std::vector<Profile> previewProfiles_ = cameraOutputCapability->GetPreviewProfiles();
    std::vector<VideoProfile> videoProfiles_ = cameraOutputCapability->GetVideoProfiles();
    std::vector<MetadataObjectType> metadataObjectType_ = cameraOutputCapability->GetSupportedMetadataObjectType();

    result.photoProfiles = VectorProfileToCArrCJProfile(photoProfiles_, errCode);
    if (*errCode != CameraError::NO_ERROR) {
        return CJCameraOutputCapability{CArrCJProfile{0}, CArrCJProfile{0}, CArrCJVideoProfile{0}, CArrI32{0}};
    }

    result.previewProfiles = VectorProfileToCArrCJProfile(previewProfiles_, errCode);
    if (*errCode != CameraError::NO_ERROR) {
        free(result.photoProfiles.head);
        return CJCameraOutputCapability{CArrCJProfile{0}, CArrCJProfile{0}, CArrCJVideoProfile{0}, CArrI32{0}};
    }

    result.videoProfiles = VectorVideoProfileToCArrCJVideoProfile(videoProfiles_, errCode);
    if (*errCode != CameraError::NO_ERROR) {
        free(result.photoProfiles.head);
        free(result.previewProfiles.head);
        return CJCameraOutputCapability{CArrCJProfile{0}, CArrCJProfile{0}, CArrCJVideoProfile{0}, CArrI32{0}};
    }

    result.supportedMetadataObjectTypes.size = metadataObjectType_.size();
    if (metadataObjectType_.size() == 0) {
        return result;
    }
    result.supportedMetadataObjectTypes.head =
        static_cast<int32_t *>(malloc(sizeof(int32_t) * metadataObjectType_.size()));
    if (result.supportedMetadataObjectTypes.head == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        free(result.photoProfiles.head);
        free(result.previewProfiles.head);
        free(result.videoProfiles.head);
        return CJCameraOutputCapability{CArrCJProfile{0}, CArrCJProfile{0}, CArrCJVideoProfile{0}, CArrI32{0}};
    }
    for (size_t i = 0; i < metadataObjectType_.size(); i++) {
        result.supportedMetadataObjectTypes.head[i] = static_cast<int32_t>(metadataObjectType_[i]);
    }
    return result;
}

CJCameraDevice CameraDeviceToCJCameraDevice(CameraDevice &cameraDevice)
{
    char *cameraId = MallocCString(cameraDevice.GetID());
    int32_t cameraPosition = cameraDevice.GetPosition();
    int32_t cameraType = cameraDevice.GetCameraType();
    int32_t connectionType = cameraDevice.GetConnectionType();
    uint32_t cameraOrientation = cameraDevice.GetCameraOrientation();
    return CJCameraDevice{cameraId, cameraPosition, cameraType, connectionType, cameraOrientation};
}

CJCameraStatusInfo CameraStatusInfoToCJCameraStatusInfo(const CameraStatusInfo &cameraStatusInfo)
{
    CJCameraDevice cjCameraDevice = CameraDeviceToCJCameraDevice(*(cameraStatusInfo.cameraDevice));
    int32_t status = cameraStatusInfo.cameraStatus;
    return CJCameraStatusInfo{cjCameraDevice, status};
}

CArrCJCameraDevice CameraDeviceVetorToCArrCJCameraDevice(const std::vector<sptr<CameraDevice>> cameras)
{
    int64_t size = static_cast<int64_t>(cameras.size());
    if (size <= 0) {
        return CArrCJCameraDevice{0};
    }
    CJCameraDevice *head = static_cast<CJCameraDevice *>(malloc(sizeof(CJCameraDevice) * size));
    if (head == nullptr) {
        return CArrCJCameraDevice{0};
    }
    for (int64_t i = 0; i < size; i++) {
        head[i] = CameraDeviceToCJCameraDevice(*(cameras[i]));
    }
    return CArrCJCameraDevice{head, size};
}

CJFoldStatusInfo FoldStatusInfoToCJFoldStatusInfo(const FoldStatusInfo &foldStatusInfo)
{
    return CJFoldStatusInfo{CameraDeviceVetorToCArrCJCameraDevice(foldStatusInfo.supportedCameras),
                            foldStatusInfo.foldStatus};
}

CJTorchStatusInfo TorchStatusInfoToCJTorchStatusInfo(const TorchStatusInfo &torchStatusInfo)
{
    return CJTorchStatusInfo{torchStatusInfo.isTorchAvailable, torchStatusInfo.isTorchActive,
                             torchStatusInfo.torchLevel};
}

CJErrorCallback ErrorCallBackToCJErrorCallBack(const int32_t errorType, const int32_t errorMsg)
{
    return CJErrorCallback{errorType, errorMsg};
}

CJMetadataObject MetadataObjectToCJMetadataObject(MetadataObject metaObject)
{
    Rect rect = metaObject.GetBoundingBox();
    CJRect cjRect = CJRect{rect.topLeftX, rect.topLeftY, rect.width, rect.height};
    return CJMetadataObject{static_cast<int32_t>(metaObject.GetType()), metaObject.GetTimestamp(), cjRect};
}

CArrCJMetadataObject MetadataObjectsToCArrCJMetadataObject(std::vector<sptr<MetadataObject>> metaObjects)
{
    int64_t size = static_cast<int64_t>(metaObjects.size());
    if (size <= 0) {
        return CArrCJMetadataObject{0};
    }
    CJMetadataObject *head = static_cast<CJMetadataObject *>(malloc(sizeof(CJMetadataObject) * size));
    if (head == nullptr) {
        return CArrCJMetadataObject{0};
    }
    for (int64_t i = 0; i < size; i++) {
        head[i] = MetadataObjectToCJMetadataObject(*(metaObjects[i]));
    }
    return CArrCJMetadataObject{head, size};
}
} // namespace CameraStandard
} // namespace OHOS