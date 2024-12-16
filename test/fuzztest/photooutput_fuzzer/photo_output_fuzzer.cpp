/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "photo_output_fuzzer.h"
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

namespace OHOS {
namespace CameraStandard {
namespace PhotoOutputFuzzer {
const int32_t LIMITSIZE = 4;
const int32_t NUM_2 = 2;
bool g_isCameraDevicePermission = false;

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

void Test(uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    GetPermission();
    auto manager = CameraManager::GetInstance();
    CHECK_ERROR_RETURN_LOG(!manager, "PhotoOutputFuzzer: Get CameraManager instance Error");
    auto cameras = manager->GetSupportedCameras();
    CHECK_ERROR_RETURN_LOG(cameras.size() < NUM_2, "PhotoOutputFuzzer: GetSupportedCameras Error");
    MessageParcel data;
    data.WriteRawData(rawData, size);
    auto camera = cameras[data.ReadUint32() % cameras.size()];
    CHECK_ERROR_RETURN_LOG(!camera, "PhotoOutputFuzzer: camera is null");
    int32_t mode = data.ReadInt32() % (SceneMode::APERTURE_VIDEO + NUM_2);
    auto capability = manager->GetSupportedOutputCapability(camera, mode);
    CHECK_ERROR_RETURN_LOG(!capability, "PhotoOutputFuzzer: GetSupportedOutputCapability Error");
    auto profiles = capability->GetPhotoProfiles();
    CHECK_ERROR_RETURN_LOG(profiles.empty(), "PhotoOutputFuzzer: GetPhotoProfiles empty");
    Profile profile = profiles[data.ReadUint32() % profiles.size()];
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    CHECK_ERROR_RETURN_LOG(!photoSurface, "PhotoOutputFuzzer: create photoSurface Error");
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    CHECK_ERROR_RETURN_LOG(!producer, "PhotoOutputFuzzer: GetProducer Error");
    auto output = manager->CreatePhotoOutput(profile, producer);
    CHECK_ERROR_RETURN_LOG(!output, "PhotoOutputFuzzer: CreatePhotoOutput Error");
    TestOutput(output, rawData, size);
}

void TestOutput(sptr<PhotoOutput> output, uint8_t *rawData, size_t size)
{
    MEDIA_INFO_LOG("PhotoOutputFuzzer: ENTER");
    MessageParcel data;
    data.WriteRawData(rawData, size);
    output->SetCallback(make_shared<PhotoStateCallbackMock>());
    sptr<IBufferConsumerListener> listener = new IBufferConsumerListenerMock();
    output->SetThumbnailListener(listener);
    data.RewindRead(0);
    output->SetThumbnail(data.ReadBool());
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    CHECK_ERROR_RETURN_LOG(!photoSurface, "PhotoOutputFuzzer: Create photoSurface Error");
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    CHECK_ERROR_RETURN_LOG(!producer, "PhotoOutputFuzzer: GetProducer Error");
    sptr<Surface> sf = Surface::CreateSurfaceAsProducer(producer);
    output->SetRawPhotoInfo(sf);
    output->Capture(make_shared<PhotoCaptureSetting>());
    output->Capture();
    output->CancelCapture();
    output->ConfirmCapture();
    output->CreateStream();
    output->GetApplicationCallback();
    output->IsMirrorSupported();
    output->IsQuickThumbnailSupported();
    data.RewindRead(0);
    int32_t type = data.ReadInt32() % (DeferredDeliveryImageType::DELIVERY_VIDEO + 1 + 1);
    output->DeferImageDeliveryFor(static_cast<DeferredDeliveryImageType>(type));
    output->IsDeferredImageDeliverySupported(static_cast<DeferredDeliveryImageType>(type));
    output->IsDeferredImageDeliveryEnabled(static_cast<DeferredDeliveryImageType>(type));
    data.RewindRead(0);
    output->SetCallbackFlag(data.ReadUint8());
    data.RewindRead(0);
    output->SetNativeSurface(data.ReadBool());
    data.RewindRead(0);
    output->ProcessSnapshotDurationUpdates(data.ReadInt32());
    int32_t isAutoHighQualityPhotoSupported;
    output->IsAutoHighQualityPhotoSupported(isAutoHighQualityPhotoSupported);
    data.RewindRead(0);
    output->EnableAutoHighQualityPhoto(data.ReadBool());
    output->IsEnableDeferred();
    output->GetDefaultCaptureSetting();
    output->Release();
}

} // namespace StreamRepeatStubFuzzer
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::CameraStandard::PhotoOutputFuzzer::Test(data, size);
    return 0;
}