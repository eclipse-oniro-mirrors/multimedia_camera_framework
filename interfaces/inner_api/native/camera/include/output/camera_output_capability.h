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

#ifndef OHOS_CAMERA_OUTPUT_CAPABILITY_H
#define OHOS_CAMERA_OUTPUT_CAPABILITY_H

#include <cstdint>
#include <iostream>
#include <refbase.h>
#include <vector>

#include "istream_repeat_callback.h"
#include "metadata_type.h"

namespace OHOS {
namespace CameraStandard {
static constexpr float RATIO_VALUE_1_1 = 1.0f;
static constexpr float RATIO_VALUE_4_3 = 4.0f / 3;
static constexpr float RATIO_VALUE_16_9 = 16.0f / 9;
typedef struct {
    uint32_t width;
    uint32_t height;
} Size;

typedef struct {
    uint32_t fixedFps;
    uint32_t minFps;
    uint32_t maxFps;
} Fps;

enum CameraFormat {
    CAMERA_FORMAT_INVALID = -1,
    CAMERA_FORMAT_YCBCR_420_888 = 2,
    CAMERA_FORMAT_RGBA_8888 = 3,
    CAMERA_FORMAT_DNG = 4,
    CAMERA_FORMAT_YUV_420_SP = 1003,
    CAMERA_FORMAT_NV12 = 1004,
    CAMERA_FORMAT_YUV_422_YUYV = 1005,
    CAMERA_FORMAT_JPEG = 2000,
    CAMERA_FORMAT_YCBCR_P010 = 2001,
    CAMERA_FORMAT_YCRCB_P010 = 2002
};

enum ProfileSizeRatio : int32_t {
    UNSPECIFIED = -1,
    RATIO_1_1 = 0,
    RATIO_4_3 = 1,
    RATIO_16_9 = 2,
};

class Profile {
public:
    Profile(CameraFormat format, Size size);
    Profile(CameraFormat format, Size size, Fps fps, std::vector<uint32_t> abilityId);
    Profile() = default;
    Profile& operator=(const Profile& profile)
    {
        if (this != &profile) {
            this->format_ = profile.format_;
            this->size_ = profile.size_;
            this->fps_ = profile.fps_;
            this->abilityId_ = profile.abilityId_;
        }
        return *this;
    }
    bool operator==(const Profile& profile)
    {
        return this->format_ == profile.format_ && this->size_.width == profile.size_.width &&
            this->size_.height == profile.size_.height;
    }
    virtual ~Profile() = default;

    /**
     * @brief Get camera format of the profile.
     *
     * @return camera format of the profile.
     */
    CameraFormat GetCameraFormat();

    /**
     * @brief Get resolution of the profile.
     *
     * @return resolution of the profile.
     */
    Size GetSize();
    std::vector<uint32_t> GetAbilityId();

    CameraFormat format_ = CAMERA_FORMAT_INVALID;
    Size size_ = { 0, 0 };
    bool sizeFollowSensorMax_ = false;
    ProfileSizeRatio sizeRatio_ = UNSPECIFIED;
    Fps fps_ = { 0, 0, 0 };
    std::vector<uint32_t> abilityId_ = {};
};

class VideoProfile : public Profile {
public:
    VideoProfile(CameraFormat format, Size size, std::vector<int32_t> framerates);
    VideoProfile() = default;
    virtual ~VideoProfile() = default;
    VideoProfile& operator=(const VideoProfile& rhs)
    {
        Profile::operator=(rhs);
        this->framerates_ = rhs.framerates_;
        return *this;
    }
    /**
     * @brief Get supported framerates of the profile.
     *
     * @return vector of supported framerate.
     */
    std::vector<int32_t> GetFrameRates();

    std::vector<int32_t> framerates_ = {};
};

float GetTargetRatio(ProfileSizeRatio sizeRatio, float unspecifiedValue);
bool IsProfileSameRatio(Profile& srcProfile, ProfileSizeRatio sizeRatio, float unspecifiedValue);

class CameraOutputCapability : public RefBase {
public:
    CameraOutputCapability() = default;
    virtual ~CameraOutputCapability() = default;

    /**
     * @brief Get Photo profiles.
     *
     * @return vector of supported photo profiles.
     */
    std::vector<Profile> GetPhotoProfiles();

    /**
     * @brief Set Photo profiles.
     *
     * @param vector of photo profiles.
     */
    void SetPhotoProfiles(std::vector<Profile> photoProfiles);

    /**
     * @brief Get Preview profiles.
     *
     * @return vector of supported preview profiles.
     */
    std::vector<Profile> GetPreviewProfiles();

    /**
     * @brief Set preview profiles.
     *
     * @param vector of preview profiles.
     */
    void SetPreviewProfiles(std::vector<Profile> previewProfiles);

    /**
     * @brief Get video profiles.
     *
     * @return vector of supported video profiles.
     */
    std::vector<VideoProfile> GetVideoProfiles();

    /**
     * @brief Set video profiles.
     *
     * @param vector of video profiles.
     */
    void SetVideoProfiles(std::vector<VideoProfile> videoProfiles);

    /**
     * @brief Get supported meta object types.
     *
     * @return vector of supported metadata object types.
     */
    std::vector<MetadataObjectType> GetSupportedMetadataObjectType();

    /**
     * @brief Get supported meta object types.
     *
     * @return vector of supported metadata object types.
     */
    void SetSupportedMetadataObjectType(std::vector<MetadataObjectType> metadataObjTypes);

private:
    std::vector<Profile> photoProfiles_ = {};
    std::vector<Profile> previewProfiles_ = {};
    std::vector<VideoProfile> videoProfiles_ = {};
    std::vector<MetadataObjectType> metadataObjTypes_ = {};
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_OUTPUT_CAPABILITY_H
