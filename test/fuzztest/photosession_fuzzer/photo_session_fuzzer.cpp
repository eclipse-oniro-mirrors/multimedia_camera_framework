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

#include "photo_session_fuzzer.h"
#include "camera_log.h"
#include "camera_output_capability.h"
#include "input/camera_manager.h"
#include "message_parcel.h"
#include "time_lapse_photo_session.h"
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "accesstoken_kit.h"
#include "securec.h"
#include "ipc_skeleton.h"
#include "photo_output.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MIN_SIZE_NUM = 4;

sptr<PhotoSession> fuzz_ = nullptr;
sptr<CameraManager> cameraManager_ = nullptr;
sptr<CaptureOutput> photoOutput_ = nullptr;

void PhotoSessionFuzzer::PhotoSessionFuzzTest(FuzzedDataProvider& fdp)
{
    cameraManager_ = CameraManager::GetInstance();
    sptr<CaptureSession> captureSession = cameraManager_->CreateCaptureSession(SceneMode::CAPTURE);
    fuzz_ = static_cast<PhotoSession*>(captureSession.GetRefPtr());
    if (fuzz_ == nullptr) {
        return;
    }
    fuzz_->CanAddOutput(photoOutput_);
    sptr<FluorescencePhotoSession> fluorescencePhotoSession =
        static_cast<FluorescencePhotoSession*>(captureSession.GetRefPtr());

    sptr<Surface> photoSurface = Surface::CreateSurfaceAsConsumer("photoOutput");
    sptr<IBufferProducer> bufferProducer = photoSurface->GetProducer();
    sptr<CaptureOutput> output = new PhotoOutput(bufferProducer);
    fluorescencePhotoSession->CanAddOutput(output);
    uint8_t randomNum = fdp.ConsumeIntegral<uint8_t>();
    std::vector<PreconfigType> preconfigTypeVec = {
        PRECONFIG_720P,
        PRECONFIG_1080P,
        PRECONFIG_4K,
        PRECONFIG_HIGH_QUALITY,
    };
    uint8_t underNum = randomNum % preconfigTypeVec.size();
    PreconfigType preconfigType = preconfigTypeVec[underNum];
    std::vector<ProfileSizeRatio> profileSizeRatioVec = {
        UNSPECIFIED,
        RATIO_1_1,
        RATIO_4_3,
        RATIO_16_9,
    };
    uint8_t underNumSec = randomNum % profileSizeRatioVec.size();
    ProfileSizeRatio profileSizeRatio = profileSizeRatioVec[underNumSec];
    std::vector<CameraFormat> cameraFormat = {
        CAMERA_FORMAT_INVALID,
        CAMERA_FORMAT_YCBCR_420_888,
        CAMERA_FORMAT_RGBA_8888,
        CAMERA_FORMAT_DNG,
        CAMERA_FORMAT_DNG_XDRAW,
        CAMERA_FORMAT_YUV_420_SP,
        CAMERA_FORMAT_NV12,
        CAMERA_FORMAT_YUV_422_YUYV,
        CAMERA_FORMAT_JPEG,
        CAMERA_FORMAT_YCBCR_P010,
        CAMERA_FORMAT_YCRCB_P010,
        CAMERA_FORMAT_HEIC,
        CAMERA_FORMAT_DEPTH_16,
        CAMERA_FORMAT_DEPTH_32,
    };
    uint8_t underFormat = randomNum % cameraFormat.size();
    CameraFormat format = cameraFormat[underFormat];
    fuzz_->GeneratePreconfigProfiles(preconfigType, profileSizeRatio);
    auto configs = fuzz_->GeneratePreconfigProfiles(preconfigType, profileSizeRatio);
    fuzz_->IsPreconfigProfilesLegal(configs);
    fuzz_->CanPreconfig(preconfigType, profileSizeRatio);
    fuzz_->Preconfig(preconfigType, profileSizeRatio);
    auto cameras = cameraManager_->GetSupportedCameras();
    CHECK_ERROR_RETURN_LOG(cameras.empty(), "PhotoSessionFuzzer: GetSupportedCameras Error");
    Profile photo(format, {640, 480});
    fuzz_->IsPhotoProfileLegal(cameras[0], photo);
    Profile preview(format, {640, 480});
    fuzz_->IsPreviewProfileLegal(cameras[0], preview);
}

void Test(uint8_t* data, size_t size)
{
    auto photoSession = std::make_unique<PhotoSessionFuzzer>();
    if (photoSession == nullptr) {
        MEDIA_INFO_LOG("photoSession is null");
        return;
    }
    FuzzedDataProvider fdp(data, size);
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    photoSession->PhotoSessionFuzzTest(fdp);
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}