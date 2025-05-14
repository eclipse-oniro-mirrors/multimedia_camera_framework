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

#include <cstdint>
#include <memory>

#include "accesstoken_kit.h"
#include "camera_device.h"
#include "camera_log.h"
#include "camera_output_capability.h"
#include "capture_scene_const.h"
#include "input/camera_manager.h"
#include "message_parcel.h"
#include "nativetoken_kit.h"
#include "photo_output_fuzzer.h"
#include "token_setproc.h"

namespace OHOS {
namespace CameraStandard {
namespace PhotoOutputFuzzer {
const int32_t LIMITSIZE = 128;
const int32_t CONST_2 = 2;
const int32_t CONST_1 = 1;

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
    if (size < LIMITSIZE) {
        return;
    }
    GetPermission();
    auto manager = CameraManager::GetInstance();
    CHECK_ERROR_RETURN_LOG(!manager, "PhotoOutputFuzzer: Get CameraManager instance Error");
    auto cameras = manager->GetSupportedCameras();
    CHECK_ERROR_RETURN_LOG(cameras.size() < CONST_2, "PhotoOutputFuzzer: GetSupportedCameras Error");

    auto camera = cameras[fdp.ConsumeIntegral<uint8_t>() % cameras.size()];
    CHECK_ERROR_RETURN_LOG(!camera, "PhotoOutputFuzzer: camera is null");
    int32_t mode = fdp.ConsumeIntegral<uint8_t>() % (SceneMode::APERTURE_VIDEO + CONST_2);
    auto capability = manager->GetSupportedOutputCapability(camera, mode);
    CHECK_ERROR_RETURN_LOG(!capability, "PhotoOutputFuzzer: GetSupportedOutputCapability Error");
    auto profiles = capability->GetPhotoProfiles();
    CHECK_ERROR_RETURN_LOG(profiles.empty(), "PhotoOutputFuzzer: GetPhotoProfiles empty");
    Profile profile = profiles[fdp.ConsumeIntegral<uint8_t>() % profiles.size()];
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    CHECK_ERROR_RETURN_LOG(!photoSurface, "PhotoOutputFuzzer: create photoSurface Error");
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    CHECK_ERROR_RETURN_LOG(!producer, "PhotoOutputFuzzer: GetProducer Error");
    auto output = manager->CreatePhotoOutput(profile, producer);
    CHECK_ERROR_RETURN_LOG(!output, "PhotoOutputFuzzer: CreatePhotoOutput Error");
    std::shared_ptr<PhotoCaptureSetting> setting = std::make_shared<PhotoCaptureSetting>();
    sptr<HStreamCaptureCallbackImpl> callback = new (std::nothrow) HStreamCaptureCallbackImpl(output);
    TestOutput1(output, fdp);
    TestOutput2(output, fdp);
    CaptureSetting(setting, fdp);
    CaptureCallback(callback, fdp);
}

void TestOutput1(sptr<PhotoOutput> output, FuzzedDataProvider &fdp) {
    MEDIA_INFO_LOG("PhotoOutputFuzzer: ENTER");
    output->SetCallback(make_shared<PhotoStateCallbackMock>());
    sptr<IBufferConsumerListener> listener = new IBufferConsumerListenerMock();
    output->SetThumbnailListener(listener);
    output->SetThumbnail(fdp.ConsumeBool());
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
    int32_t type = fdp.ConsumeIntegral<uint8_t>() % (DeferredDeliveryImageType::DELIVERY_VIDEO + CONST_2);
    output->DeferImageDeliveryFor(static_cast<DeferredDeliveryImageType>(type));
    output->IsDeferredImageDeliverySupported(static_cast<DeferredDeliveryImageType>(type));
    output->IsDeferredImageDeliveryEnabled(static_cast<DeferredDeliveryImageType>(type));
    output->SetCallbackFlag(fdp.ConsumeIntegral<uint8_t>());
    output->SetNativeSurface(fdp.ConsumeIntegral<uint8_t>());
    output->ProcessSnapshotDurationUpdates(fdp.ConsumeIntegral<int32_t>());
    int32_t isAutoHighQualityPhotoSupported;
    output->IsAutoHighQualityPhotoSupported(isAutoHighQualityPhotoSupported);
    output->EnableAutoHighQualityPhoto(fdp.ConsumeIntegral<uint8_t>());
    output->IsEnableDeferred();
    output->GetDefaultCaptureSetting();
    bool isAutoAigcPhotoSupported;
    output->IsAutoAigcPhotoSupported(isAutoAigcPhotoSupported);
    output->EnableAutoHighQualityPhoto(fdp.ConsumeBool());
    output->Release();
}

void TestOutput2(sptr<PhotoOutput> output, FuzzedDataProvider &fdp) __attribute__((no_sanitize("cfi"))) {
    MEDIA_INFO_LOG("PhotoOutputFuzzer: ENTER");
    output->SetCallback(make_shared<PhotoStateCallbackMock>());
    output->IsYuvOrHeifPhoto();
    output->SetAuxiliaryPhotoHandle(fdp.ConsumeIntegral<int32_t>());
    output->GetAuxiliaryPhotoHandle();

    output->SetMovingPhotoVideoCodecType(fdp.ConsumeIntegral<int32_t>());
    output->IsDepthDataDeliverySupported();

    output->EnableMovingPhoto(fdp.ConsumeBool());

    output->EnableDepthDataDelivery(fdp.ConsumeBool());
    output->CreateMultiChannel();

    output->AcquireBufferToPrepareProxy(fdp.ConsumeIntegral<int32_t>());

    output->EnableRawDelivery(fdp.ConsumeBool());

    output->EnableMirror(fdp.ConsumeBool());
    bool isEnable;
    output->IsRawDeliverySupported(isEnable);
    bool isAutoCloudImageEnhancementSupported;
    output->IsAutoCloudImageEnhancementSupported(isAutoCloudImageEnhancementSupported);
    bool isAutoAigcPhotoSupported;
    output->IsAutoAigcPhotoSupported(isAutoAigcPhotoSupported);

    output->EnableAutoCloudImageEnhancement(fdp.ConsumeBool());

    output->GetPhotoRotation(fdp.ConsumeIntegral<int32_t>());

    output->EnableAutoAigcPhoto(fdp.ConsumeBool());
    pid_t pid = fdp.ConsumeIntegral<pid_t>();
    output->CameraServerDied(pid);
    output->Release();
}

void CaptureSetting(std::shared_ptr<PhotoCaptureSetting> setting, FuzzedDataProvider &fdp) {
    MEDIA_INFO_LOG("PhotoOutputFuzzer: ENTER");
    PhotoCaptureSetting::QualityLevel quality = static_cast<PhotoCaptureSetting::QualityLevel>(
        fdp.ConsumeIntegral<uint8_t>() % (PhotoCaptureSetting::QUALITY_LEVEL_HIGH + CONST_2));
    setting->SetQuality(quality);
    setting->GetQuality();

    setting->SetBurstCaptureState(fdp.ConsumeIntegral<uint8_t>());
    std::vector<PhotoCaptureSetting::RotationConfig> vRotationConfig = {PhotoCaptureSetting::Rotation_0,
        PhotoCaptureSetting::Rotation_90, PhotoCaptureSetting::Rotation_180, PhotoCaptureSetting::Rotation_270,
        static_cast<PhotoCaptureSetting::RotationConfig>(PhotoCaptureSetting::Rotation_270 + CONST_1)};
    PhotoCaptureSetting::RotationConfig rotationValue =
        vRotationConfig[fdp.ConsumeIntegral<uint8_t>() % vRotationConfig.size()];
    setting->SetRotation(rotationValue);
    setting->GetRotation();

    setting->SetGpsLocation(fdp.ConsumeFloatingPoint<double>(), fdp.ConsumeFloatingPoint<double>());

    setting->SetMirror(fdp.ConsumeBool());
    setting->GetMirror();
}

void CaptureCallback(sptr<HStreamCaptureCallbackImpl> callback, FuzzedDataProvider &fdp) {
    MEDIA_INFO_LOG("PhotoOutputFuzzer: ENTER");
    callback->OnCaptureStarted(fdp.ConsumeIntegral<int32_t>());
    callback->OnCaptureStarted(fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>());
    callback->OnCaptureEnded(fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>());
    callback->OnCaptureError(fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>());
    callback->OnFrameShutter(fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>());
    callback->OnFrameShutterEnd(fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>());
    callback->OnCaptureReady(fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>());
}

} // namespace PhotoOutputFuzzer
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
    /* Run your code on data */
    OHOS::CameraStandard::PhotoOutputFuzzer::Test(data, size);
    return 0;
}