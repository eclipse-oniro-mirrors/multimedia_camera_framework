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

#include "cloud_enhance_session_fuzzer.h"
#include "camera_input.h"
#include "camera_log.h"
#include "camera_photo_proxy.h"
#include "capture_input.h"
#include "capture_output.h"
#include "capture_scene_const.h"
#include "input/camera_manager.h"
#include "message_parcel.h"
#include "refbase.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "accesstoken_kit.h"
#include "picture.h"

namespace OHOS {
namespace CameraStandard {
namespace CloudEnhanceSessionFuzzer {
const int32_t LIMITSIZE = 4;
const int32_t NUM_TWO = 2;
sptr<IBufferProducer> surface;
sptr<CameraDevice> camera;
Profile profile;
CaptureOutput* curOutput;
bool g_isSupported;
bool g_isCameraDevicePermission = false;
SceneMode g_sceneMode;

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

sptr<CameraManager> manager;
sptr<SurfaceBuffer> surfaceBuffer;
SceneMode sceneMode = SceneMode::TIMELAPSE_PHOTO;

sptr<CaptureInput> GetCameraInput(uint8_t *rawData, size_t size)
{
    MEDIA_INFO_LOG("CloudEnhanceSessionFuzzer: ENTER");
    auto manager = CameraManager::GetInstance();
    auto cameras = manager->GetSupportedCameras();
    CHECK_ERROR_RETURN_RET_LOG(cameras.size() < NUM_TWO,
        nullptr, "CloudEnhanceSessionFuzzer: GetSupportedCameras Error");
    MessageParcel data;
    data.WriteRawData(rawData, size);
    camera = cameras[data.ReadUint32() % cameras.size()];
    CHECK_ERROR_RETURN_RET_LOG(!camera, nullptr, "CloudEnhanceSessionFuzzer: Camera is null Error");
    return manager->CreateCameraInput(camera);
}

sptr<PhotoOutput> GetCaptureOutput(uint8_t *rawData, size_t size)
{
    MEDIA_INFO_LOG("CloudEnhanceSessionFuzzer: ENTER");
    auto manager = CameraManager::GetInstance();
    CHECK_ERROR_RETURN_RET_LOG(!manager, nullptr, "CloudEnhanceSessionFuzzer: CameraManager::GetInstance Error");
    MessageParcel data;
    data.WriteRawData(rawData, size);
    CHECK_ERROR_RETURN_RET_LOG(!camera, nullptr, "CloudEnhanceSessionFuzzer: Camera is null Error");
    auto capability = manager->GetSupportedOutputCapability(camera, g_sceneMode);
    CHECK_ERROR_RETURN_RET_LOG(!capability, nullptr, "CloudEnhanceSessionFuzzer: GetSupportedOutputCapability Error");
    auto profiles = capability->GetPhotoProfiles();
    CHECK_ERROR_RETURN_RET_LOG(profiles.empty(), nullptr, "CloudEnhanceSessionFuzzer: GetPhotoProfiles empty");
    profile = profiles[data.ReadUint32() % profiles.size()];
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    CHECK_ERROR_RETURN_RET_LOG(!photoSurface, nullptr, "CloudEnhanceSessionFuzzer: create photoSurface Error");
    surface = photoSurface->GetProducer();
    CHECK_ERROR_RETURN_RET_LOG(!surface, nullptr, "CloudEnhanceSessionFuzzer: surface GetProducer Error");
    return manager->CreatePhotoOutput(profile, surface);
}

void TestSession(sptr<CaptureSession> session, uint8_t *rawData, size_t size)
{
    MEDIA_INFO_LOG("CloudEnhanceSessionFuzzer: ENTER");
    sptr<CaptureInput> input = GetCameraInput(rawData, size);
    sptr<CaptureOutput> output = GetCaptureOutput(rawData, size);
    CHECK_ERROR_RETURN_LOG(!input || !output || !session, "CloudEnhanceSessionFuzzer: input/output/session is null");
    MessageParcel data;
    data.WriteRawData(rawData, size);
    session->SetMode(g_sceneMode);
    session->GetMode();
    PreconfigType preconfigType = static_cast<PreconfigType>(
        data.ReadInt32() % (PreconfigType::PRECONFIG_HIGH_QUALITY + NUM_TWO));
    ProfileSizeRatio preconfigRatio = static_cast<ProfileSizeRatio>(
        data.ReadInt32() % (ProfileSizeRatio::RATIO_16_9 + NUM_TWO));
    session->CanPreconfig(preconfigType, preconfigRatio);
    session->Preconfig(preconfigType, preconfigRatio);
    session->BeginConfig();
    session->CanAddInput(input);
    session->AddInput(input);
    session->CanAddOutput(output);
    session->AddOutput(output);
    session->RemoveInput(input);
    session->RemoveOutput(output);
    session->AddInput(input);
    session->AddOutput(output);
    session->AddSecureOutput(output);
    input->Open();
    session->CommitConfig();
    session->Start();
    curOutput = output.GetRefPtr();
    CaptureOutputType outputType = static_cast<CaptureOutputType>(
        data.ReadInt32() % (CaptureOutputType::CAPTURE_OUTPUT_TYPE_MAX + NUM_TWO));
    session->ValidateOutputProfile(profile, outputType);
}

void TestCreateMediaLibrary(sptr<CaptureSession> session, uint8_t *rawData, size_t size)
{
    MEDIA_INFO_LOG("CloudEnhanceSessionFuzzer: ENTER");
    MessageParcel data;
    data.WriteRawData(rawData, size);
    sptr<CameraPhotoProxy> photoProxy{new CameraPhotoProxy()};
    std::string uri;
    int32_t cameraShotType;
    string burstKey = data.ReadString();
    int64_t timestamp = data.ReadInt64();
    session->CreateMediaLibrary(Media::Picture::Create(surfaceBuffer), photoProxy, uri, cameraShotType,
        burstKey, timestamp);
}

void Test(uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    GetPermission();
    MessageParcel data;
    data.WriteRawData(rawData, size);
    g_sceneMode = static_cast<SceneMode>(
        data.ReadInt32() % (SceneMode::APERTURE_VIDEO + NUM_TWO));
    auto manager = CameraManager::GetInstance();
    auto session = manager->CreateCaptureSession(g_sceneMode);
    CHECK_ERROR_RETURN_LOG(!manager, "CloudEnhanceSessionFuzzer: CreateCaptureSession Error");
    TestSession(session, rawData, size);
    TestCreateMediaLibrary(session, rawData, size);
    session->EnableAutoCloudImageEnhancement(data.ReadBool());
    session->Release();
    session->Stop();
}

} // namespace StreamRepeatStubFuzzer
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::CameraStandard::CloudEnhanceSessionFuzzer::Test(data, size);
    return 0;
}