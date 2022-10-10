/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "output/camera_output_capability.h"

namespace OHOS {
namespace CameraStandard {
Profile::Profile(CameraFormat format, Size size): format_(format), size_(size) {}

CameraFormat Profile::GetCameraFormat()
{
    return format_;
}

Size Profile::GetSize()
{
    return size_;
}

VideoProfile::VideoProfile(CameraFormat format, Size size, std::vector<int32_t> framerates) : Profile(format, size)
{
    framerates_ = framerates;
}
std::vector<int32_t> VideoProfile::GetFrameRates()
{
    return framerates_;
}

std::vector<Profile> CameraOutputCapability::GetPhotoProfiles()
{
    return photoProfiles_;
}

void CameraOutputCapability::SetPhotoProfiles(std::vector<Profile> photoProfiles)
{
    photoProfiles_ = photoProfiles;
}

std::vector<Profile> CameraOutputCapability::GetPreviewProfiles()
{
    return previewProfiles_;
}

void CameraOutputCapability::SetPreviewProfiles(std::vector<Profile> previewProfiles)
{
    previewProfiles_ = previewProfiles;
}

std::vector<VideoProfile> CameraOutputCapability::GetVideoProfiles()
{
    return videoProfiles_;
}

void CameraOutputCapability::SetVideoProfiles(std::vector<VideoProfile> videoProfiles)
{
    videoProfiles_ = videoProfiles;
}

std::vector<MetadataObjectType> CameraOutputCapability::GetSupportedMetadataObjectType()
{
    return metadataObjTypes_;
}

void CameraOutputCapability::SetSupportedMetadataObjectType(std::vector<MetadataObjectType> metadataObjType)
{
    metadataObjTypes_ = metadataObjType;
}
} // CameraStandard
} // OHOS
