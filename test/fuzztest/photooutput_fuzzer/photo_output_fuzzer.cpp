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
#include "camera_output_capability.h"
#include "input/camera_manager.h"
#include "message_parcel.h"
#include <cstdint>
#include <memory>

namespace OHOS {
namespace CameraStandard {
namespace PhotoOutputFuzzer {
const int32_t LIMITSIZE = 4;

sptr<IBufferProducer> surface(nullptr);

void Test(uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    auto manager = CameraManager::GetInstance();
    auto cameras = manager->GetSupportedCameras();
    MessageParcel data;
    data.WriteRawData(rawData, size);
    sptr<CameraDevice> camera = cameras[data.ReadUint32() % cameras.size()];
    if (camera == nullptr) {
        return;
    }
    int32_t mode = data.ReadInt32() % (APERTURE_VIDEO + 1 + 1);
    auto capability = manager->GetSupportedOutputCapability(camera, mode);
    if (capability == nullptr) {
        return;
    }
    auto profiles = capability->GetPhotoProfiles();
    Profile profile = profiles[data.ReadUint32() % profiles.size()];
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    if (photoSurface == nullptr) {
        return;
    }
    surface = photoSurface->GetProducer();
    if (surface == nullptr) {
        return;
    }
    auto output = manager->CreatePhotoOutput(profile, surface);
    TestOutput(output, rawData, size);
}
void TestOutput(sptr<PhotoOutput> output, uint8_t *rawData, size_t size)
{
    MessageParcel data;
    data.WriteRawData(rawData, size);
    output->SetCallback(make_shared<PhotoStateCallbackMock>());
    sptr<IBufferConsumerListener> listener = new IBufferConsumerListenerMock();
    output->SetThumbnailListener(listener);
    data.RewindRead(0);
    output->SetThumbnail(data.ReadBool());
    sptr<Surface> sf = Surface::CreateSurfaceAsProducer(surface);
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