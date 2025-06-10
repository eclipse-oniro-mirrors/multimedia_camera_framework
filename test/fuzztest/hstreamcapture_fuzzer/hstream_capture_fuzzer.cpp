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

#include "hstream_capture_fuzzer.h"
#include "foundation/multimedia/camera_framework/common/utils/camera_log.h"
#include "message_parcel.h"
#include "iservice_registry.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include "token_setproc.h"
#include "iconsumer_surface.h"
#include "nativetoken_kit.h"
#include "accesstoken_kit.h"
#include "camera_metadata_info.h"
#include "metadata_utils.h"
#include "camera_device.h"
#include "camera_manager.h"
#include "ipc_skeleton.h"
#include "securec.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_0;
static constexpr int32_t MIN_SIZE_NUM = 256;
const size_t MAX_LENGTH_STRING = 64;
const int32_t PHOTO_WIDTH = 1280;
const int32_t PHOTO_HEIGHT = 960;
const int32_t PHOTO_FORMAT = 2000;
const int32_t ITEMCOUNT = 10;
const int32_t DATASIZE = 100;
const int32_t NUM_1 = 1;
const int32_t NUM_1024 = 1024;

std::shared_ptr<HStreamCapture> HStreamCaptureFuzzer::fuzz_{nullptr};
sptr<IBufferProducer> producer;

void HStreamCaptureFuzzer::HStreamCaptureFuzzTest1(FuzzedDataProvider& fdp)
{
    int32_t captureId = fdp.ConsumeIntegral<int32_t>();
    bool isEnabled = fdp.ConsumeBool();
    bool enabled = fdp.ConsumeIntegral<bool>();
    fuzz_->CreateMediaLibraryPhotoAssetProxy(captureId);
    fuzz_->GetPhotoAssetInstance(captureId);
    fuzz_->GetAddPhotoProxyEnabled();
    fuzz_->AcquireBufferToPrepareProxy(captureId);
    StreamInfo_V1_1 streamInfo;
    fuzz_->SetStreamInfo(streamInfo);
    fuzz_->FillingPictureExtendStreamInfos(streamInfo, fdp.ConsumeIntegral<int32_t>());
    fuzz_->SetThumbnail(isEnabled, producer);
    fuzz_->EnableRawDelivery(enabled);
    std::vector<std::string> bufferNames = {"rawImage",
        "gainmapImage", "deepImage", "exifImage", "debugImage"};
    for (const auto& bufName : bufferNames) {
        fuzz_->SetBufferProducerInfo(bufName, producer);
    }
    int32_t type = fdp.ConsumeIntegral<int32_t>();
    fuzz_->DeferImageDeliveryFor(type);
    fuzz_->PrepareBurst(captureId);
    fuzz_->ResetBurst();
    fuzz_->ResetBurstKey(captureId);
    fuzz_->GetBurstKey(captureId);
    fuzz_->IsBurstCapture(captureId);
    fuzz_->IsBurstCover(captureId);
    fuzz_->GetCurBurstSeq(captureId);
    fuzz_->IsDeferredPhotoEnabled();
    fuzz_->IsDeferredVideoEnabled();
    auto videoCodecType = fdp.ConsumeIntegral<int32_t>();
    fuzz_->SetMovingPhotoVideoCodecType(videoCodecType);
    fuzz_->GetMovingPhotoVideoCodecType();
    fuzz_->SetCameraPhotoRotation(fdp.ConsumeBool());
}

void HStreamCaptureFuzzer::HStreamCaptureFuzzTest2(FuzzedDataProvider& fdp)
{
    auto captureId = fdp.ConsumeIntegral<int32_t>();
    auto interfaceCode = fdp.ConsumeIntegral<int32_t>();
    auto timestamp = fdp.ConsumeIntegral<uint64_t>();
    auto isDelay = fdp.ConsumeBool();
    std::string imageId(fdp.ConsumeRandomLengthString(MAX_LENGTH_STRING));
    fuzz_->SetBurstImages(captureId, imageId);
    fuzz_->CheckResetBurstKey(captureId);
    std::shared_ptr<OHOS::Camera::CameraMetadata> captureSettings;
    captureSettings = std::make_shared<OHOS::Camera::CameraMetadata>(ITEMCOUNT, DATASIZE);
    fuzz_->CheckBurstCapture(captureSettings, fdp.ConsumeIntegral<int32_t>());
    sptr<HCameraHostManager> cameraHostManager = new HCameraHostManager(nullptr);
    std::string cameraId;
    uint32_t callingTokenId = fdp.ConsumeIntegral<uint32_t>();
    sptr<HCameraDevice> camDevice = new (std::nothrow)
        HCameraDevice(cameraHostManager, cameraId, callingTokenId);
    camDevice->OpenDevice(true);
    fuzz_->OnCaptureReady(captureId, timestamp);
    fuzz_->Capture(captureSettings);
    fuzz_->CancelCapture();
    fuzz_->SetMode(fdp.ConsumeIntegral<int32_t>());
    fuzz_->GetMode();
    fuzz_->ConfirmCapture();
    fuzz_->EndBurstCapture(captureSettings);
    fuzz_->Release();
    fuzz_->ReleaseStream(isDelay);
    fuzz_->OnCaptureStarted(captureId);
    fuzz_->OnCaptureStarted(captureId, fdp.ConsumeIntegral<int32_t>());
    fuzz_->OnCaptureEnded(captureId, fdp.ConsumeIntegral<int32_t>());
    auto errorCode = fdp.ConsumeIntegral<int32_t>();
    fuzz_->OnCaptureError(captureId, errorCode);
    fuzz_->OnFrameShutter(captureId, timestamp);
    fuzz_->OnFrameShutterEnd(captureId, timestamp);
    CameraInfoDumper infoDumper(0);
    fuzz_->DumpStreamInfo(infoDumper);
    fuzz_->OperatePermissionCheck(interfaceCode);
    CaptureInfo captureInfoPhoto;
    fuzz_->ProcessCaptureInfoPhoto(captureInfoPhoto, captureSettings, captureId);
    fuzz_->SetRotation(captureSettings, captureId);
}

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    auto hstreamCapture = std::make_unique<HStreamCaptureFuzzer>();
    if (hstreamCapture == nullptr) {
        MEDIA_INFO_LOG("hstreamCapture is null");
        return;
    }
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    sptr<Surface> photoSurface;
    photoSurface = Surface::CreateSurfaceAsConsumer("hstreamcapture");
    producer = photoSurface->GetProducer();
    HStreamCaptureFuzzer::fuzz_ = std::make_shared
        <HStreamCapture>(producer, PHOTO_FORMAT, PHOTO_WIDTH, PHOTO_HEIGHT);
    CHECK_ERROR_RETURN_LOG(!HStreamCaptureFuzzer::fuzz_, "Create fuzz_ Error");
    sptr<HDI::Camera::V1_0::IStreamOperator> streamOperator;
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(NUM_1, NUM_1024);
    HStreamCaptureFuzzer::fuzz_->LinkInput(streamOperator, cameraAbility);
    HStreamCaptureFuzzer::fuzz_->cameraAbility_ = cameraAbility;
    hstreamCapture->HStreamCaptureFuzzTest1(fdp);
    hstreamCapture->HStreamCaptureFuzzTest2(fdp);
}

} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}