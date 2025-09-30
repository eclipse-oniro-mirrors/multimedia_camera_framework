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
#include <fuzzer/FuzzedDataProvider.h>
#include <memory>

#include "accesstoken_kit.h"
#include "camera_device.h"
#include "camera_log.h"
#include "camera_output_capability.h"
#include "capture_scene_const.h"
#include "input/camera_manager.h"
#include "message_parcel.h"
#include "nativetoken_kit.h"
#include "preview_output_fuzzer.h"
#include "securec.h"
#include "test_token.h"
#include "token_setproc.h"

namespace OHOS {
namespace CameraStandard {
namespace PreviewOutputFuzzer {
static constexpr int32_t MAX_CODE_LEN  = 512;
static constexpr int32_t MIN_SIZE_NUM = 550;
const int32_t NUM_TWO = 2;
const size_t THRESHOLD = 10;
static const int32_t MINFORMAT = 30;
static const int32_t MEDIAFORMAT = 60;
static const int32_t MAXFORMAT = 120;

void TestOutput(sptr<PreviewOutput> output, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("PreviewOutputFuzzer: ENTER");
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
    CHECK_RETURN_ELOG(!previewSurface, "previewOutputFuzzer: Create previewSurface Error");
    sptr<IBufferProducer> producer = previewSurface->GetProducer();
    CHECK_RETURN_ELOG(!producer, "previewOutputFuzzer: GetProducer Error");
    sptr<Surface> sf = Surface::CreateSurfaceAsProducer(producer);
    output->AddDeferredSurface(sf);
    output->Start();
    output->IsSketchSupported();
    output->GetSketchRatio();
    bool isEnable = fdp.ConsumeBool();
    output->EnableSketch(isEnable);
    output->CreateStream();
    output->GetFrameRateRange();
    int32_t minFrameRate = fdp.ConsumeIntegralInRange<int32_t>(MINFORMAT, MEDIAFORMAT);
    int32_t maxFrameRate = fdp.ConsumeIntegralInRange<int32_t>(MEDIAFORMAT, MAXFORMAT);
    output->SetFrameRateRange(minFrameRate, maxFrameRate);
    output->SetOutputFormat(minFrameRate);
    output->SetFrameRate(minFrameRate, maxFrameRate);
    output->GetSupportedFrameRates();
    output->StartSketch();
    output->StopSketch();
    output->GetDeviceMetadata();
    output->FindSketchSize();
    output->GetObserverControlTags();

    output->canSetFrameRateRange(minFrameRate, maxFrameRate);
    output->GetPreviewRotation(minFrameRate);
    output->JudegRotationFunc(minFrameRate);
    output->SetPreviewRotation(minFrameRate, isEnable);
    output->Stop();
}

void TestIsBandwidthCompressionSupported(FuzzedDataProvider& fdp)
{
    CHECK_RETURN_ELOG(!TestToken().GetAllCameraPermission(), "GetPermission error");
    auto manager = CameraManager::GetInstance();
    CHECK_RETURN_ELOG(!manager, "previewOutputFuzzer: Get CameraManager instance Error");
    auto cameras = manager->GetSupportedCameras();
    CHECK_RETURN_ELOG(cameras.size() < NUM_TWO, "previewOutputFuzzer: GetSupportedCameras Error");
    auto camera = cameras[fdp.ConsumeIntegral<uint8_t>() % cameras.size()];
    CHECK_RETURN_ELOG(!camera, "previewOutputFuzzer: camera is null");
    int32_t mode = fdp.ConsumeIntegral<uint8_t>() % (SceneMode::NORMAL  NUM_TWO);
    auto capability = manager->GetSupportedOutputCapability(camera, mode);
    CHECK_RETURN_ELOG(!capability, "previewOutputFuzzer: GetSupportedOutputCapability Error");
    auto profiles = capability->GetPreviewProfiles();
    CHECK_RETURN_ELOG(profiles.empty(), "previewOutputFuzzer: GetPreviewProfiles empty");
    Profile profile = profiles[fdp.ConsumeIntegral<uint8_t>() % profiles.size()];
    sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
    CHECK_RETURN_ELOG(!previewSurface, "previewOutputFuzzer: create previewSurface Error");
    sptr<IBufferProducer> producer = previewSurface->GetProducer();
    CHECK_RETURN_ELOG(!producer, "previewOutputFuzzer: GetProducer Error");
    sptr<Surface> pSurface = Surface::CreateSurfaceAsProducer(producer);
    CHECK_RETURN_ELOG(!pSurface, "previewOutputFuzzer: GetProducer Error");
    auto output = manager->CreatePreviewOutput(profile, pSurface);
    CHECK_RETURN_ELOG(!output, "previewOutputFuzzer: CreatePhotoOutput Error");
    output->IsBandwidthCompressionSupported();
    bool isEnable = fdp.ConsumeBool();
    output->EnableBandwidthCompression(isEnable);
}


void Test(uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    CHECK_RETURN_ELOG(!TestToken().GetAllCameraPermission(), "GetPermission error");
    auto manager = CameraManager::GetInstance();
    CHECK_RETURN_ELOG(!manager, "previewOutputFuzzer: Get CameraManager instance Error");
    auto cameras = manager->GetSupportedCameras();
    CHECK_RETURN_ELOG(cameras.size() < NUM_TWO, "previewOutputFuzzer: GetSupportedCameras Error");
    MessageParcel dataMessageParcel;
    size_t bufferSize = fdp.ConsumeIntegralInRange(0, MAX_CODE_LEN);
    std::vector<uint8_t> buffer = fdp.ConsumeBytes<uint8_t>(bufferSize);
    dataMessageParcel.WriteRawData(buffer.data(), buffer.size());
    auto camera = cameras[dataMessageParcel.ReadUint32() % cameras.size()];
    CHECK_RETURN_ELOG(!camera, "previewOutputFuzzer: camera is null");
    int32_t mode = dataMessageParcel.ReadInt32() % (SceneMode::NORMAL + NUM_TWO);
    auto capability = manager->GetSupportedOutputCapability(camera, mode);
    CHECK_RETURN_ELOG(!capability, "previewOutputFuzzer: GetSupportedOutputCapability Error");
    auto profiles = capability->GetPreviewProfiles();
    CHECK_RETURN_ELOG(profiles.empty(), "previewOutputFuzzer: GetPreviewProfiles empty");
    Profile profile = profiles[dataMessageParcel.ReadUint32() % profiles.size()];
    sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
    CHECK_RETURN_ELOG(!previewSurface, "previewOutputFuzzer: create previewSurface Error");
    sptr<IBufferProducer> producer = previewSurface->GetProducer();
    CHECK_RETURN_ELOG(!producer, "previewOutputFuzzer: GetProducer Error");
    sptr<Surface> pSurface = Surface::CreateSurfaceAsProducer(producer);
    CHECK_RETURN_ELOG(!pSurface, "previewOutputFuzzer: GetProducer Error");
    auto output = manager->CreatePreviewOutput(profile, pSurface);
    CHECK_RETURN_ELOG(!output, "previewOutputFuzzer: CreatePhotoOutput Error");
    TestOutput(output, fdp);
    TestIsBandwidthCompressionSupported(fdp);
}

} // namespace StreamRepeatStubFuzzer
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    if (size < OHOS::CameraStandard::PreviewOutputFuzzer::THRESHOLD) {
        return 0;
    }
    /* Run your code on data */
    OHOS::CameraStandard::PreviewOutputFuzzer::Test(data, size);
    return 0;
}