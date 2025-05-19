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

#include "video_output_fuzzer.h"
#include "camera_device.h"
#include "camera_log.h"
#include "camera_output_capability.h"
#include "capture_scene_const.h"
#include <cstdint>
#include "input/camera_manager.h"
#include "message_parcel.h"
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <memory>
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "accesstoken_kit.h"
#include "securec.h"

using namespace std;

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MIN_SIZE_NUM = 50;
const size_t THRESHOLD = 10;

void VideoOutputFuzzer::VideoOutputFuzzTest(FuzzedDataProvider& fdp)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    auto manager = CameraManager::GetInstance();
    auto cameras = manager->GetSupportedCameras();
    CHECK_ERROR_RETURN_LOG(cameras.empty(), "GetSupportedCameras Error");
    auto s = manager->CreateCaptureSession(SceneMode::VIDEO);
    s->BeginConfig();
    auto cap = s->GetCameraOutputCapabilities(cameras[0]);
    CHECK_ERROR_RETURN_LOG(cap.empty(), "GetCameraOutputCapabilities Error");
    auto vp = cap[0]->GetVideoProfiles();
    CHECK_ERROR_RETURN_LOG(vp.empty(), "GetVideoProfiles Error");
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    auto output = manager->CreateVideoOutput(vp[0], surface);
    output->Start();
    output->Stop();
    output->Resume();
    output->Pause();
    output->CreateStream();
    output->Release();
    output->GetApplicationCallback();
    output->GetFrameRateRange();
    int32_t minFrameRate = fdp.ConsumeIntegral<int32_t>();
    int32_t maxFrameRate = fdp.ConsumeIntegral<int32_t>();
    output->SetFrameRateRange(minFrameRate, maxFrameRate);
    output->SetOutputFormat(fdp.ConsumeIntegral<int32_t>());
    output->SetFrameRate(minFrameRate, maxFrameRate);
    output->GetSupportedFrameRates();
    output->enableMirror(fdp.ConsumeBool());
    output->IsMirrorSupported();
    output->GetSupportedVideoMetaTypes();
    output->AttachMetaSurface(surface, VIDEO_META_MAKER_INFO);
    int pid = fdp.ConsumeIntegral<int>();
    output->CameraServerDied(pid);
    output->canSetFrameRateRange(minFrameRate, maxFrameRate);
    output->GetVideoRotation(fdp.ConsumeIntegral<int32_t>());
    output->IsAutoDeferredVideoEnhancementSupported();
    output->IsAutoDeferredVideoEnhancementEnabled();
    output->EnableAutoDeferredVideoEnhancement(fdp.ConsumeBool());
    output->IsVideoStarted();
    bool boolean = fdp.ConsumeBool();
    output->IsRotationSupported(boolean);
    output->SetRotation(fdp.ConsumeIntegral<int32_t>());
    output->IsAutoVideoFrameRateSupported();
    output->EnableAutoVideoFrameRate(fdp.ConsumeBool());
    std::vector<int32_t> supportedRotations;
    output->GetSupportedRotations(supportedRotations);
}

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    auto videoOutput = std::make_unique<VideoOutputFuzzer>();
    if (videoOutput == nullptr) {
        MEDIA_INFO_LOG("videoPostProcessor is null");
        return;
    }
    videoOutput->VideoOutputFuzzTest(fdp);
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}