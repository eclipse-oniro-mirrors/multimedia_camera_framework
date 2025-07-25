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
#include "test_token.h"

namespace OHOS {
namespace CameraStandard {
namespace PhotoOutputFuzzer {
const int32_t LIMITSIZE = 128;
const int32_t CONST_2 = 2;

void Test(uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    CHECK_RETURN_ELOG(!TestToken().GetAllCameraPermission(), "GetPermission error");
    auto manager = CameraManager::GetInstance();
    CHECK_RETURN_ELOG(!manager, "PhotoOutputFuzzer: Get CameraManager instance Error");
    auto cameras = manager->GetSupportedCameras();
    CHECK_RETURN_ELOG(cameras.size() < CONST_2, "PhotoOutputFuzzer: GetSupportedCameras Error");
    MessageParcel data;
    data.WriteRawData(rawData, size);
    auto camera = cameras[data.ReadUint32() % cameras.size()];
    CHECK_RETURN_ELOG(!camera, "PhotoOutputFuzzer: camera is null");
    int32_t mode = data.ReadInt32() % (SceneMode::APERTURE_VIDEO + CONST_2);
    auto capability = manager->GetSupportedOutputCapability(camera, mode);
    CHECK_RETURN_ELOG(!capability, "PhotoOutputFuzzer: GetSupportedOutputCapability Error");
    auto profiles = capability->GetPhotoProfiles();
    CHECK_RETURN_ELOG(profiles.empty(), "PhotoOutputFuzzer: GetPhotoProfiles empty");
    Profile profile = profiles[data.ReadUint32()  % profiles.size()];
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    CHECK_RETURN_ELOG(!photoSurface, "PhotoOutputFuzzer: create photoSurface Error");
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    CHECK_RETURN_ELOG(!producer, "PhotoOutputFuzzer: GetProducer Error");
    auto output = manager->CreatePhotoOutput(profile, producer);
    CHECK_RETURN_ELOG(!output, "PhotoOutputFuzzer: CreatePhotoOutput Error");
    std::shared_ptr<PhotoCaptureSetting> setting = std::make_shared<PhotoCaptureSetting>();
    sptr<HStreamCaptureCallbackImpl> callback = new (std::nothrow) HStreamCaptureCallbackImpl(output);
    TestOutput1(output, rawData, size);
    TestOutput2(output, rawData, size);
    CaptureSetting(setting, rawData, size);
    CaptureCallback(callback, rawData, size);
}

void TestOutput1(sptr<PhotoOutput> output, uint8_t *rawData, size_t size)
{
    MEDIA_INFO_LOG("PhotoOutputFuzzer: ENTER");
    MessageParcel data;
    data.WriteRawData(rawData, size);
    output->SetCallback(make_shared<PhotoStateCallbackMock>());
    data.RewindRead(0);
    output->SetThumbnail(data.ReadBool());
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    CHECK_RETURN_ELOG(!photoSurface, "PhotoOutputFuzzer: Create photoSurface Error");
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    CHECK_RETURN_ELOG(!producer, "PhotoOutputFuzzer: GetProducer Error");
    output->Capture(make_shared<PhotoCaptureSetting>());
    output->Capture();
    output->CancelCapture();
    output->ConfirmCapture();
    output->CreateStream();
    output->GetApplicationCallback();
    output->IsMirrorSupported();
    output->IsQuickThumbnailSupported();
    int32_t type = data.ReadInt32() % (DeferredDeliveryImageType::DELIVERY_VIDEO + CONST_2);
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
    bool isAutoAigcPhotoSupported;
    output->IsAutoAigcPhotoSupported(isAutoAigcPhotoSupported);
    data.RewindRead(0);
    output->EnableAutoHighQualityPhoto(data.ReadBool());
    output->Release();
}

void TestOutput2(sptr<PhotoOutput> output, uint8_t *rawData, size_t size) __attribute__((no_sanitize("cfi")))
{
    MEDIA_INFO_LOG("PhotoOutputFuzzer: ENTER");
    MessageParcel data;
    data.WriteRawData(rawData, size);
    output->SetCallback(make_shared<PhotoStateCallbackMock>());
    data.RewindRead(0);
    output->IsYuvOrHeifPhoto();
    output->SetAuxiliaryPhotoHandle(data.ReadInt32());
    output->GetAuxiliaryPhotoHandle();
    data.RewindRead(0);
    output->SetMovingPhotoVideoCodecType(data.ReadInt32());
    output->IsDepthDataDeliverySupported();
    data.RewindRead(0);
    output->EnableMovingPhoto(data.ReadBool());
    data.RewindRead(0);
    output->EnableDepthDataDelivery(data.ReadBool());
    output->CreateMultiChannel();
    data.RewindRead(0);
    data.RewindRead(0);
    output->EnableRawDelivery(data.ReadBool());
    data.RewindRead(0);
    output->EnableMirror(data.ReadBool());
    bool isEnable = static_cast<bool>(rawData);
    output->IsRawDeliverySupported(isEnable);
    bool isAutoCloudImageEnhancementSupported = static_cast<bool>(rawData);
    output->IsAutoCloudImageEnhancementSupported(isAutoCloudImageEnhancementSupported);
    bool isAutoAigcPhotoSupported = static_cast<bool>(rawData);
    output->IsAutoAigcPhotoSupported(isAutoAigcPhotoSupported);
    data.RewindRead(0);
    output->EnableAutoCloudImageEnhancement(data.ReadBool());
    data.RewindRead(0);
    output->GetPhotoRotation(data.ReadInt32());
    data.RewindRead(0);
    output->EnableAutoAigcPhoto(data.ReadBool());
    pid_t pid = *reinterpret_cast<const pid_t*>(rawData);
    output->CameraServerDied(pid);
    output->Release();
}

void CaptureSetting(std::shared_ptr<PhotoCaptureSetting> setting, uint8_t *rawData, size_t size)
{
    MEDIA_INFO_LOG("PhotoOutputFuzzer: ENTER");
    MessageParcel data;
    data.WriteRawData(rawData, size);
    PhotoCaptureSetting::QualityLevel quality = PhotoCaptureSetting::QUALITY_LEVEL_HIGH;
    setting->SetQuality(quality);
    setting->GetQuality();
    data.RewindRead(0);
    setting->SetBurstCaptureState(data.ReadInt8());
    PhotoCaptureSetting::RotationConfig rotationValue = PhotoCaptureSetting::RotationConfig::Rotation_0;
    setting->SetRotation(rotationValue);
    setting->GetRotation();
    data.RewindRead(0);
    setting->SetGpsLocation(data.ReadDouble(), data.ReadDouble());
    data.RewindRead(0);
    setting->SetMirror(data.ReadBool());
    setting->GetMirror();
}

void CaptureCallback(sptr<HStreamCaptureCallbackImpl> callback, uint8_t *rawData, size_t size)
{
    MEDIA_INFO_LOG("PhotoOutputFuzzer: ENTER");
    MessageParcel data;
    data.WriteRawData(rawData, size);
    data.RewindRead(0);
    callback->OnCaptureStarted(data.ReadInt32());
    data.RewindRead(0);
    callback->OnCaptureStarted(data.ReadInt32(), data.ReadInt32());
    data.RewindRead(0);
    callback->OnCaptureEnded(data.ReadInt32(), data.ReadInt32());
    data.RewindRead(0);
    callback->OnCaptureError(data.ReadInt32(), data.ReadInt32());
    data.RewindRead(0);
    callback->OnFrameShutter(data.ReadInt32(), data.ReadInt32());
    data.RewindRead(0);
    callback->OnFrameShutterEnd(data.ReadInt32(), data.ReadInt32());
    data.RewindRead(0);
    callback->OnCaptureReady(data.ReadInt32(), data.ReadInt32());
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