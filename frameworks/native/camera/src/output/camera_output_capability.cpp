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
#include "camera_log.h"
#include "camera_util.h"

namespace OHOS {
namespace CameraStandard {
float GetTargetRatio(ProfileSizeRatio sizeRatio, float unspecifiedValue)
{
    switch (sizeRatio) {
        case RATIO_1_1:
            return RATIO_VALUE_1_1;
        case RATIO_4_3:
            return RATIO_VALUE_4_3;
        case RATIO_16_9:
            return RATIO_VALUE_16_9;
        case UNSPECIFIED:
            return unspecifiedValue;
        default:
            return unspecifiedValue;
    }
    return unspecifiedValue;
}

bool IsProfileSameRatio(Profile& srcProfile, ProfileSizeRatio sizeRatio, float unspecifiedValue)
{
    if (srcProfile.size_.height == 0 || srcProfile.size_.width == 0) {
        return false;
    }
    float srcRatio = ((float)srcProfile.size_.width) / srcProfile.size_.height;
    float targetRatio = GetTargetRatio(sizeRatio, unspecifiedValue);
    if (targetRatio <= 0) {
        return false;
    }
    return abs(srcRatio - targetRatio) / targetRatio <= 0.05f; // 0.05f is 5% tolerance
}

Profile::Profile(CameraFormat format, Size size) : format_(format), size_(size), specId_(0) {}
Profile::Profile(CameraFormat format, Size size, int32_t specId) : format_(format), size_(size), specId_(specId) {}
Profile::Profile(CameraFormat format, Size size, Fps fps, std::vector<uint32_t> abilityId)
    : format_(format), size_(size), fps_(fps), abilityId_(abilityId), specId_(0) {}
Profile::Profile(CameraFormat format, Size size, Fps fps, std::vector<uint32_t> abilityId, int32_t specId)
    : format_(format), size_(size), fps_(fps), abilityId_(abilityId), specId_(specId) {}
CameraFormat Profile::GetCameraFormat()
{
    return format_;
}

std::vector<uint32_t> Profile::GetAbilityId()
{
    return abilityId_;
}

Size Profile::GetSize()
{
    return size_;
}

Fps Profile::GetFps()
{
    return fps_;
}

int32_t Profile::GetSpecId()
{
    return specId_;
}

void Profile::DumpProfile(std::string name) const
{
    std::string abilityIdStr = Container2String(abilityId_.begin(), abilityId_.end());
    MEDIA_DEBUG_LOG("%{public}s format : %{public}d, width: %{public}d, height: %{public}d, "
                    "support ability: %{public}s, fixedFps: %{public}d, minFps: %{public}d, maxFps: %{public}d",
                    name.c_str(), format_, size_.width, size_.height, abilityIdStr.c_str(),
                    fps_.fixedFps, fps_.minFps, fps_.maxFps);
}

void VideoProfile::DumpVideoProfile(std::string name) const
{
    std::string frameratesStr = Container2String(framerates_.begin(), framerates_.end());
    MEDIA_DEBUG_LOG("%{public}s format : %{public}d, width: %{public}d, height: %{public}d framerates: %{public}s",
                    name.c_str(), format_, size_.width, size_.height, frameratesStr.c_str());
}

VideoProfile::VideoProfile(CameraFormat format, Size size, std::vector<int32_t> framerates) : Profile(format, size)
{
    framerates_ = framerates;
}

VideoProfile::VideoProfile(
    CameraFormat format, Size size, std::vector<int32_t> framerates, int32_t specId) : Profile(format, size, specId)
{
    framerates_ = framerates;
}

std::vector<int32_t> VideoProfile::GetFrameRates()
{
    return framerates_;
}

bool CameraOutputCapability::IsMatchPreviewProfiles(std::vector<Profile>& previewProfiles)
{
    CHECK_ERROR_RETURN_RET(previewProfiles.empty(), true);
    CHECK_ERROR_RETURN_RET_LOG(previewProfiles_.empty(), false, "previewProfiles_ is empty, cant match");
    for (auto& profile : previewProfiles) {
        auto it = std::find(previewProfiles_.begin(), previewProfiles_.end(), profile);
        if (it == previewProfiles_.end()) {
            MEDIA_DEBUG_LOG("IsMatchPreviewProfiles previewProfile [format : %{public}d, width: %{public}d, "
                "height: %{public}d] cant match", profile.GetCameraFormat(), profile.GetSize().width,
                profile.GetSize().height);
            return false;
        }
    }
    MEDIA_DEBUG_LOG("IsMatchPreviewProfiles all previewProfiles can match");
    return true;
}

bool CameraOutputCapability::IsMatchPhotoProfiles(std::vector<Profile>& photoProfiles)
{
    CHECK_ERROR_RETURN_RET(photoProfiles.empty(), true);
    CHECK_ERROR_RETURN_RET_LOG(photoProfiles_.empty(), false, "photoProfiles_ is empty, cant match");
    for (auto& profile : photoProfiles) {
        auto it = std::find(photoProfiles_.begin(), photoProfiles_.end(), profile);
        if (it == photoProfiles_.end()) {
            MEDIA_DEBUG_LOG("IsMatchPhotoProfiles photoProfile [format : %{public}d, width: %{public}d,"
                "height: %{public}d] cant match", profile.GetCameraFormat(), profile.GetSize().width,
                profile.GetSize().height);
            return false;
        }
    }
    MEDIA_DEBUG_LOG("IsMatchPhotoProfiles all photoProfiles can match");
    return true;
}

bool CameraOutputCapability::IsMatchVideoProfiles(std::vector<VideoProfile>& videoProfiles)
{
    CHECK_ERROR_RETURN_RET(videoProfiles.empty(), true);
    CHECK_ERROR_RETURN_RET_LOG(videoProfiles_.empty(), false, "videoProfiles_ is empty, cant match");
    for (auto& profile : videoProfiles) {
        auto it = std::find_if(videoProfiles_.begin(), videoProfiles_.end(), [&profile](VideoProfile& profile_) {
            return profile_.GetCameraFormat() == profile.GetCameraFormat() &&
                   profile_.GetSize().width == profile.GetSize().width &&
                   profile_.GetSize().height == profile.GetSize().height &&
                   profile_.framerates_[0] <= profile.framerates_[0] &&
                   profile_.framerates_[1] >= profile.framerates_[1];
        });
        if (it == videoProfiles_.end()) {
            std::string frameratesStr = Container2String(profile.framerates_.begin(), profile.framerates_.end());
            MEDIA_DEBUG_LOG("IsMatchVideoProfiles videoProfile [format : %{public}d, width: %{public}d,"
                "height: %{public}d framerates: %{public}s] cant match", profile.GetCameraFormat(),
                profile.GetSize().width, profile.GetSize().height, frameratesStr.c_str());
            return false;
        }
    }
    MEDIA_DEBUG_LOG("IsMatchVideoProfiles all videoProfiles can match");
    return true;
}

void CameraOutputCapability::RemoveDuplicatesProfiles()
{
    size_t previewSize = previewProfiles_.size();
    size_t photoSize = photoProfiles_.size();
    size_t videoSize = videoProfiles_.size();
    RemoveDuplicatesProfile(previewProfiles_);
    RemoveDuplicatesProfile(photoProfiles_);
    RemoveDuplicatesProfile(videoProfiles_);
    MEDIA_DEBUG_LOG("after remove duplicates preview size: %{public}zu -> %{public}zu, "
                    "photo size: %{public}zu -> %{public}zu, video size:%{public}zu -> %{public}zu",
                    previewSize, previewProfiles_.size(), photoSize, photoProfiles_.size(),
                    videoSize, videoProfiles_.size());
}

template <typename T>
void CameraOutputCapability::RemoveDuplicatesProfile(std::vector<T>& profiles)
{
    std::vector<T> uniqueProfiles;
    for (const auto& profile : profiles) {
        if (std::find(uniqueProfiles.begin(), uniqueProfiles.end(), profile) == uniqueProfiles.end()) {
            uniqueProfiles.push_back(profile);
        }
    }
    profiles = uniqueProfiles;
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
} // namespace CameraStandard
} // namespace OHOS
