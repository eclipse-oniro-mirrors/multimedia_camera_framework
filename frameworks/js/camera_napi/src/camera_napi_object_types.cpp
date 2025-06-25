/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "camera_napi_object_types.h"

#include <cstdint>
#include <memory>
#include <utility>

#include "camera_device.h"
#include "camera_manager.h"
#include "camera_napi_metadata_utils.h"
#include "camera_napi_object.h"
#include "js_native_api_types.h"
#include "metadata_output.h"

namespace OHOS {
namespace CameraStandard {

napi_value CameraNapiObjectTypes::GenerateNapiValue(napi_env env)
{
    napi_value value = GetCameraNapiObject().CreateNapiObjFromMap(env);
    ptrHolder_.clear();
    return value;
};

CameraNapiObject& CameraNapiObjSize::GetCameraNapiObject()
{
    return *Hold<CameraNapiObject>(
        CameraNapiObject::CameraNapiObjFieldMap { { "width", &size_.width }, { "height", &size_.height } });
}

CameraNapiObject& CameraNapiObjFrameRateRange::GetCameraNapiObject()
{
    return *Hold<CameraNapiObject>(
        CameraNapiObject::CameraNapiObjFieldMap { { "min", &frameRateRange_[0] }, { "max", &frameRateRange_[1] } });
}

CameraNapiObject& CameraNapiObjProfile::GetCameraNapiObject()
{
    auto sizeObj = Hold<CameraNapiObjSize>(profile_.size_);
    auto format = Hold<int32_t>(profile_.format_);
    return *Hold<CameraNapiObject>(
        CameraNapiObject::CameraNapiObjFieldMap { { "format", format }, { "size", &sizeObj->GetCameraNapiObject() } });
}

CameraNapiObject& CameraNapiObjVideoProfile::GetCameraNapiObject()
{
    auto format = Hold<int32_t>(videoProfile_.format_);
    auto sizeObj = Hold<CameraNapiObjSize>(videoProfile_.size_);
    auto frameRateRange = Hold<CameraNapiObjFrameRateRange>(videoProfile_.framerates_);
    return *Hold<CameraNapiObject>(CameraNapiObject::CameraNapiObjFieldMap {
        { "format", format },
        { "size", &sizeObj->GetCameraNapiObject() },
        { "frameRateRange", &frameRateRange->GetCameraNapiObject() } });
}

CameraNapiObject& CameraNapiObjDepthProfile::GetCameraNapiObject()
{
    auto format = Hold<int32_t>(depthProfile_.format_);
    auto sizeObj = Hold<CameraNapiObjSize>(depthProfile_.size_);
    auto dataAccuracy = Hold<int32_t>(depthProfile_.dataAccuracy_);
    return *Hold<CameraNapiObject>(CameraNapiObject::CameraNapiObjFieldMap {
        { "format", format },
        { "size", &sizeObj->GetCameraNapiObject() },
        { "dataAccuracy", dataAccuracy } });
}

CameraNapiObject& CameraNapiObjCameraDevice::GetCameraNapiObject()
{
    auto cameraId = Hold<std::string>(cameraDevice_.GetID());
    auto cameraPosition = Hold<int32_t>(cameraDevice_.GetPosition());
    auto cameraType = Hold<int32_t>(cameraDevice_.GetCameraType());
    auto connectionType = Hold<int32_t>(cameraDevice_.GetConnectionType());
    auto hostDeviceName = Hold<std::string>(cameraDevice_.GetHostName());
    auto hostDeviceType = Hold<uint32_t>(cameraDevice_.GetDeviceType());
    auto cameraOrientation = Hold<int32_t>(cameraDevice_.GetCameraOrientation());
    auto isRetractable = Hold<bool>(cameraDevice_.GetisRetractable());
    auto lensEquivalentFocalLength = Hold<std::vector<int32_t>>(cameraDevice_.GetLensEquivalentFocalLength());
    return *Hold<CameraNapiObject>(CameraNapiObject::CameraNapiObjFieldMap {
        { "cameraId", cameraId },
        { "cameraPosition", cameraPosition },
        { "cameraType", cameraType },
        { "connectionType", connectionType },
        { "hostDeviceName", hostDeviceName },
        { "hostDeviceType", hostDeviceType },
        { "cameraOrientation", cameraOrientation },
        { "isRetractable", isRetractable },
        { "lensEquivalentFocalLength", lensEquivalentFocalLength } });
}

CameraNapiObject& CameraNapiBoundingBox::GetCameraNapiObject()
{
    return *Hold<CameraNapiObject>(CameraNapiObject::CameraNapiObjFieldMap {
        { "topLeftX", &rect_.topLeftX },
        { "topLeftY", &rect_.topLeftY },
        { "width", &rect_.width },
        { "height", &rect_.height } });
}

CameraNapiObject& CameraNapiObjMetadataObject::GetCameraNapiObject()
{
    auto type = Hold<int32_t>(CameraNapiMetadataUtils::MapMetadataObjSupportedTypesEnum(metadataObject_.GetType()));
    auto timestamp = Hold<int32_t>(metadataObject_.GetTimestamp());
    auto boundingBox = Hold<CameraNapiBoundingBox>(*Hold<Rect>(metadataObject_.GetBoundingBox()));
    auto objectId = Hold<int32_t>(metadataObject_.GetObjectId());
    auto confidence = Hold<int32_t>(metadataObject_.GetConfidence());
    return *Hold<CameraNapiObject>(CameraNapiObject::CameraNapiObjFieldMap {
        { "type", type },
        { "timestamp", timestamp },
        { "boundingBox", &boundingBox->GetCameraNapiObject() },
        { "objectId", objectId },
        { "confidence", confidence }});
}

CameraNapiObject& CameraNapiObjCameraOutputCapability::GetCameraNapiObject()
{
    auto previewProfiles = Hold<std::list<CameraNapiObject>>();
    auto nativePreviewProfiles = Hold<std::vector<Profile>>(cameraOutputCapability_.GetPreviewProfiles());
    for (auto& profile : *nativePreviewProfiles) {
        previewProfiles->emplace_back(std::move(Hold<CameraNapiObjProfile>(profile)->GetCameraNapiObject()));
    }

    auto photoProfiles = Hold<std::list<CameraNapiObject>>();
    auto nativePhotoProfiles = Hold<std::vector<Profile>>(cameraOutputCapability_.GetPhotoProfiles());
    for (auto& profile : *nativePhotoProfiles) {
        photoProfiles->emplace_back(std::move(Hold<CameraNapiObjProfile>(profile)->GetCameraNapiObject()));
    }

    auto videoProfiles = Hold<std::list<CameraNapiObject>>();
    auto nativeVideoProfiles = Hold<std::vector<VideoProfile>>(cameraOutputCapability_.GetVideoProfiles());
    for (auto& profile : *nativeVideoProfiles) {
        videoProfiles->emplace_back(std::move(Hold<CameraNapiObjVideoProfile>(profile)->GetCameraNapiObject()));
    }

    auto depthProfiles = Hold<std::list<CameraNapiObject>>();
    auto nativeDepthProfiles = Hold<std::vector<DepthProfile>>(cameraOutputCapability_.GetDepthProfiles());
    for (auto& profile : *nativeDepthProfiles) {
        depthProfiles->emplace_back(std::move(Hold<CameraNapiObjDepthProfile>(profile)->GetCameraNapiObject()));
    }

    auto supportedMetadataObjectTypes = Hold<std::vector<int32_t>>();
    auto nativeSupportedMetadataObjectTypes = cameraOutputCapability_.GetSupportedMetadataObjectType();
    for (auto& type : nativeSupportedMetadataObjectTypes) {
        supportedMetadataObjectTypes->emplace_back(static_cast<int32_t>(type));
    }

    return *Hold<CameraNapiObject>(CameraNapiObject::CameraNapiObjFieldMap {
        { "previewProfiles", previewProfiles },
        { "photoProfiles", photoProfiles },
        { "videoProfiles", videoProfiles },
        { "depthProfiles", depthProfiles },
        { "supportedMetadataObjectTypes", supportedMetadataObjectTypes } });
}

CameraNapiObject& CameraNapiFocusTrackingInfo::GetCameraNapiObject()
{
    auto trackingMode = Hold<int32_t>(focusTrackingInfo_.GetMode());
    auto trackingRegion = Hold<CameraNapiBoundingBox>(*Hold<Rect>(focusTrackingInfo_.GetRegion()));
    return *Hold<CameraNapiObject>(CameraNapiObject::CameraNapiObjFieldMap {
        { "trackingMode", trackingMode },
        { "trackingRegion", &trackingRegion->GetCameraNapiObject() } });
}
} // namespace CameraStandard
} // namespace OHOS
