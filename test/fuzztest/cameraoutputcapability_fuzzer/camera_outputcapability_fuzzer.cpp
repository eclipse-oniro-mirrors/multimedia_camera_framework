/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <cstddef>
#include <cstdint>
#include <memory>
 
#include "camera_input.h"
#include "camera_log.h"
#include "camera_outputcapability_fuzzer.h"
#include "camera_photo_proxy.h"
#include "capture_input.h"
#include "capture_output.h"
#include "capture_scene_const.h"
#include "input/camera_manager.h"
#include "message_parcel.h"
#include "refbase.h"
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "accesstoken_kit.h"
#include "securec.h"
 
namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MIN_SIZE_NUM = 4;
 
std::shared_ptr<CameraOutputCapability> CameraOutputCapabilityFuzzer::capabilityfuzz_{nullptr};
std::shared_ptr<Profile> CameraOutputCapabilityFuzzer::profilefuzz_{nullptr};
std::shared_ptr<VideoProfile> CameraOutputCapabilityFuzzer::videoProfilefuzz_{nullptr};
 
void CameraOutputCapabilityFuzzer::CameraOutputCapabilityFuzzTest(FuzzedDataProvider& fdp)
{
    int32_t value = fdp.ConsumeIntegralInRange<int32_t>(-2, 5);
    ProfileSizeRatio sizeRatio = static_cast<ProfileSizeRatio>(value);
    float unspecifiedValue = fdp.ConsumeFloatingPoint<float>();
    GetTargetRatio(sizeRatio, unspecifiedValue);
 
    value = fdp.ConsumeIntegral<int32_t>();
    CameraFormat format = static_cast<CameraFormat>(value);
    Size profileSize;
    value = fdp.ConsumeIntegral<uint32_t>();
    profileSize.width = value;
    value = fdp.ConsumeIntegral<uint32_t>();
    profileSize.height = value;
    Fps fps;
    value = fdp.ConsumeIntegral<uint32_t>();
    fps.fixedFps = value;
    value = fdp.ConsumeIntegral<uint32_t>();
    fps.minFps = value;
    value = fdp.ConsumeIntegral<uint32_t>();
    fps.maxFps = value;
    std::vector<uint32_t> abilityId;
    value = fdp.ConsumeIntegral<uint32_t>();
    abilityId.push_back(value);
    value = fdp.ConsumeIntegral<uint32_t>();
    abilityId.push_back(value);
    int32_t specId = fdp.ConsumeIntegral<int32_t>();
    profilefuzz_ = std::make_shared<Profile>(format, profileSize, fps, abilityId, specId);
 
    profilefuzz_->GetFps();
 
    std::vector<int32_t> framerates;
    value = fdp.ConsumeIntegral<int32_t>();
    framerates.push_back(value);
    value = fdp.ConsumeIntegral<int32_t>();
    framerates.push_back(value);
    videoProfilefuzz_ = std::make_shared<VideoProfile>(format, profileSize, framerates);
 
    VideoProfile videoProfile1(format, profileSize, framerates);
    videoProfilefuzz_->IsContains(videoProfile1);
    format = static_cast<CameraFormat>(value);
    value = fdp.ConsumeIntegral<uint32_t>();
    profileSize.width = value;
    value = fdp.ConsumeIntegral<uint32_t>();
    profileSize.height = value;
    framerates.clear();
    value = fdp.ConsumeIntegral<int32_t>();
    framerates.push_back(value);
    value = fdp.ConsumeIntegral<int32_t>();
    framerates.push_back(value);
    VideoProfile videoProfile2(format, profileSize, framerates);
    videoProfilefuzz_->IsContains(videoProfile2);
 
    capabilityfuzz_ = std::make_shared<CameraOutputCapability>();
    std::vector<Profile> previewProfiles;
    value = fdp.ConsumeIntegral<int32_t>();
    format = static_cast<CameraFormat>(value);
    Size profileSize1;
    value = fdp.ConsumeIntegral<uint32_t>();
    profileSize1.width = value;
    value = fdp.ConsumeIntegral<uint32_t>();
    profileSize1.height = value;
    Profile profile1(format, profileSize1);
    previewProfiles.push_back(profile1);
    capabilityfuzz_->previewProfiles_.push_back(profile1);
    capabilityfuzz_->IsMatchPreviewProfiles(previewProfiles);
 
    capabilityfuzz_->photoProfiles_.push_back(profile1);
    capabilityfuzz_->IsMatchPhotoProfiles(previewProfiles);
 
    capabilityfuzz_->videoProfiles_.push_back(videoProfile1);
    vector<VideoProfile>videoProfilevec = {videoProfile1};
    capabilityfuzz_->IsMatchVideoProfiles(videoProfilevec);
 
    capabilityfuzz_->RemoveDuplicatesProfiles();
 
    //capabilityfuzz_->RemoveDuplicatesProfile(videoProfilevec);
 
    capabilityfuzz_->GetSupportedMetadataObjectType();
}
 
void Test(uint8_t* data, size_t size)
{
    auto cameraOutputCapability = std::make_unique<CameraOutputCapabilityFuzzer>();
    if (cameraOutputCapability == nullptr) {
        MEDIA_INFO_LOG("cameraOutputCapability is null");
        return;
    }
    FuzzedDataProvider fdp(data, size);
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    cameraOutputCapability->CameraOutputCapabilityFuzzTest(fdp);
}
} // namespace CameraStandard
} // namespace OHOS
 
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}