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

#ifndef CAMERA_UTILS_H
#define CAMERA_UTILS_H

#include <cstdint>
#include <memory>
#include <refbase.h>
#include <string>
#include "camera_device.h"
#include "camera_output_capability.h"
#include "cj_common_ffi.h"
#include "input/camera_manager.h"

namespace OHOS {
namespace CameraStandard {

struct CJCameraDevice {
    char *cameraId;
    int32_t cameraPosition;
    int32_t cameraType;
    int32_t connectionType;
    uint32_t cameraOrientation;
};

struct CArrCJCameraDevice {
    CJCameraDevice *head;
    int64_t size;
};

struct CJProfile {
    int32_t format;
    uint32_t width;
    uint32_t height;
};

struct CArrCJProfile {
    CJProfile *head;
    int64_t size;
};

struct CJFrameRateRange {
    int32_t min;
    int32_t max;
};

struct CJVideoProfile {
    int32_t format;
    uint32_t width;
    uint32_t height;
    CJFrameRateRange frameRateRange;
};

struct CArrCJVideoProfile {
    CJVideoProfile *head;
    int64_t size;
};

struct CJCameraOutputCapability {
    CArrCJProfile previewProfiles;
    CArrCJProfile photoProfiles;
    CArrCJVideoProfile videoProfiles;
    CArrI32 supportedMetadataObjectTypes;
};

struct FrameRateRange {
    int32_t min;
    int32_t max;
};

struct CArrFrameRateRange {
    FrameRateRange *head;
    int64_t size;
};

struct CArrDouble {
    double *head;
    int64_t size;
};

struct CArrFloat32 {
    float *head;
    int64_t size;
};

struct RetDataCArrDouble {
    int32_t code;
    CArrDouble data;
};

struct CJLocation {
    double latitude = -1;
    double longitude = -1;
    double altitude = -1;
};

struct CJCameraStatusInfo {
    CJCameraDevice camera;
    int32_t status;
};

struct CJPhotoCaptureSetting {
    int32_t quality;
    int32_t rotation;
    CJLocation location;
    bool mirror;
};

struct CJFoldStatusInfo {
    CArrCJCameraDevice supportedCameras;
    int32_t foldStatus;
};

struct CJTorchStatusInfo {
    bool isTorchAvailable;
    bool isTorchActive;
    float torchLevel;
};

struct CJErrorCallback {
    int32_t errorType;
    int32_t errorMsg;
};

struct CJCaptureStartInfo {
    int32_t captureID;
    uint32_t exposureTime;
};

struct CJFrameShutterInfo {
    int32_t captureID;
    uint64_t timestamp;
};

struct CJCaptureEndInfo {
    int32_t captureID;
    int32_t frameCount;
};

struct CJRect {
    double topLeftX;
    double topLeftY;
    double width;
    double height;
};

struct CJMetadataObject {
    int32_t type;
    int32_t timestamp;
    CJRect boundingBox;
};

struct CArrCJMetadataObject {
    CJMetadataObject *head;
    int64_t size;
};

enum CJOutputType { METADATA_OUTPUT = 0, PHOTO_OUTPUT, PREVIEW_OUTPUT, VIDEO_OUTPUT };

CJMetadataObject MetadataObjectToCJMetadataObject(MetadataObject metaObject);

CArrCJMetadataObject MetadataObjectsToCArrCJMetadataObject(std::vector<sptr<MetadataObject>> metaObjects);

CJErrorCallback ErrorCallBackToCJErrorCallBack(const int32_t errorType, const int32_t errorMsg);

CJTorchStatusInfo TorchStatusInfoToCJTorchStatusInfo(const TorchStatusInfo &torchStatusInfo);

CArrCJCameraDevice CameraDeviceVetorToCArrCJCameraDevice(const std::vector<sptr<CameraDevice>> cameras);

CJCameraDevice CameraDeviceToCJCameraDevice(CameraDevice &cameraDevice);

CJFoldStatusInfo FoldStatusInfoToCJFoldStatusInfo(const FoldStatusInfo &foldStatusInfo);

CJCameraStatusInfo CameraStatusInfoToCJCameraStatusInfo(const CameraStatusInfo &cameraStatusInfo);

CJCameraOutputCapability CameraOutputCapabilityToCJCameraOutputCapability(
    sptr<CameraOutputCapability> cameraOutputCapability, int32_t *errCode);

char *MallocCString(const std::string &origin);
} // namespace CameraStandard
} // namespace OHOS

#endif