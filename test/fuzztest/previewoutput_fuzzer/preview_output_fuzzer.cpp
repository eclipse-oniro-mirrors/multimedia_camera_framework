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

#include "preview_output_fuzzer.h"
#include "camera_device.h"
#include "camera_log.h"
#include "camera_output_capability.h"
#include "capture_scene_const.h"
#include "input/camera_manager.h"
#include "message_parcel.h"
#include <cstdint>
#include <memory>
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "accesstoken_kit.h"
#include "securec.h"

namespace OHOS {
namespace CameraStandard {
namespace PreviewOutputFuzzer {
const int32_t LIMITSIZE = 4;
const int32_t NUM_TWO = 2;
static const uint8_t* RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
static size_t g_dataSize = 0;
static size_t g_pos;

void GetPermission()
{
    uint64_t tokenId;
    const char* perms[2];
    perms[0] = "ohos.permission.DISTRIBUTED_DATASYNC";
    perms[1] = "ohos.permission.CAMERA";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .aclsNum = 0,
        .dcaps = NULL,
        .perms = perms,
        .acls = NULL,
        .processName = "native_camera_tdd",
        .aplStr = "system_basic",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (RAW_DATA == nullptr || objectSize > g_dataSize - g_pos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, RAW_DATA + g_pos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_pos += objectSize;
    return object;
}

void TestOutput(sptr<PreviewOutput> output, uint8_t *rawData, size_t size)
{
    RAW_DATA = rawData;
    g_dataSize = size;
    g_pos = 0;
    MEDIA_INFO_LOG("PreviewOutputFuzzer: ENTER");
    sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
    CHECK_ERROR_RETURN_LOG(!previewSurface, "previewOutputFuzzer: Create previewSurface Error");
    sptr<IBufferProducer> producer = previewSurface->GetProducer();
    CHECK_ERROR_RETURN_LOG(!producer, "previewOutputFuzzer: GetProducer Error");
    sptr<Surface> sf = Surface::CreateSurfaceAsProducer(producer);
    output->AddDeferredSurface(sf);
    output->Start();
    output->IsSketchSupported();
    output->GetSketchRatio();
    bool isEnable = GetData<bool>();
    output->EnableSketch(isEnable);
    output->CreateStream();
    output->GetFrameRateRange();
    int32_t minFrameRate = GetData<int32_t>();
    int32_t maxFrameRate = GetData<int32_t>();
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

void Test(uint8_t *rawData, size_t size)
{
    CHECK_ERROR_RETURN(rawData == nullptr || size < LIMITSIZE);
    GetPermission();
    auto manager = CameraManager::GetInstance();
    CHECK_ERROR_RETURN_LOG(!manager, "previewOutputFuzzer: Get CameraManager instance Error");
    auto cameras = manager->GetSupportedCameras();
    CHECK_ERROR_RETURN_LOG(cameras.size() < NUM_TWO, "previewOutputFuzzer: GetSupportedCameras Error");
    MessageParcel data;
    data.WriteRawData(rawData, size);
    auto camera = cameras[data.ReadUint32() % cameras.size()];
    CHECK_ERROR_RETURN_LOG(!camera, "previewOutputFuzzer: camera is null");
    int32_t mode = data.ReadInt32() % (SceneMode::NORMAL + NUM_TWO);
    auto capability = manager->GetSupportedOutputCapability(camera, mode);
    CHECK_ERROR_RETURN_LOG(!capability, "previewOutputFuzzer: GetSupportedOutputCapability Error");
    auto profiles = capability->GetPreviewProfiles();
    CHECK_ERROR_RETURN_LOG(profiles.empty(), "previewOutputFuzzer: GetPreviewProfiles empty");
    Profile profile = profiles[data.ReadUint32() % profiles.size()];
    sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
    CHECK_ERROR_RETURN_LOG(!previewSurface, "previewOutputFuzzer: create previewSurface Error");
    sptr<IBufferProducer> producer = previewSurface->GetProducer();
    CHECK_ERROR_RETURN_LOG(!producer, "previewOutputFuzzer: GetProducer Error");
    sptr<Surface> pSurface = Surface::CreateSurfaceAsProducer(producer);
    CHECK_ERROR_RETURN_LOG(!pSurface, "previewOutputFuzzer: GetProducer Error");
    auto output = manager->CreatePreviewOutput(profile, pSurface);
    CHECK_ERROR_RETURN_LOG(!output, "previewOutputFuzzer: CreatePhotoOutput Error");
    TestOutput(output, rawData, size);
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