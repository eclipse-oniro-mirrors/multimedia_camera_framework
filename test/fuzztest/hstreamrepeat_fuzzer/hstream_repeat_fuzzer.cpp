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

#include "hstream_repeat_fuzzer.h"
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
#include "camera_service_ipc_interface_code.h"
#include "camera_device.h"
#include "camera_manager.h"
#include "ipc_skeleton.h"
#include "securec.h"

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_0;
static constexpr int32_t MIN_SIZE_NUM = 72;
const size_t THRESHOLD = 10;
const int32_t ITEMCOUNT = 10;
const int32_t DATASIZE = 100;
const int32_t PHOTO_WIDTH = 1280;
const int32_t PHOTO_HEIGHT = 960;
const int32_t PHOTO_FORMAT = 2000;

std::shared_ptr<HStreamRepeat> HStreamRepeatFuzzer::fuzz_{nullptr};

void HStreamRepeatFuzzer::HStreamRepeatFuzzTest1(FuzzedDataProvider& fdp)
{
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility;
    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator;
    fuzz_->LinkInput(streamOperator, cameraAbility);
    StreamInfo_V1_1 streamInfo;
    fuzz_->SetVideoStreamInfo(streamInfo);
    fuzz_->SetStreamInfo(streamInfo);
    sptr<OHOS::IBufferProducer> metaProducer;
    fuzz_->SetMetaProducer(metaProducer);
    SketchStatus status = SketchStatus::STOPED;
    fuzz_->UpdateSketchStatus(status);
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings;
    settings = std::make_shared<OHOS::Camera::CameraMetadata>(ITEMCOUNT, DATASIZE);
    fuzz_->StartSketchStream(settings);
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_FRONT;
    fuzz_->SetUsedAsPosition(cameraPosition);
    fuzz_->Start(settings, fdp.ConsumeBool());
    fuzz_->Start();
    fuzz_->OnFrameStarted();
    fuzz_->OnFrameEnded(fdp.ConsumeIntegral<int32_t>());
    CaptureEndedInfoExt captureEndedInfo = {1, 100, true, "video123"};
    fuzz_->OnDeferredVideoEnhancementInfo(captureEndedInfo);
    fuzz_->OnFrameError(fdp.ConsumeIntegral<int32_t>());
    fuzz_->OnSketchStatusChanged(status);
    fuzz_->Stop();
    fuzz_->Release();
    fuzz_->ReleaseStream(fdp.ConsumeBool());
}

void HStreamRepeatFuzzer::HStreamRepeatFuzzTest2(FuzzedDataProvider& fdp)
{
    sptr<Surface> photoSurface = Surface::CreateSurfaceAsConsumer("hstreamrepeat");
    CHECK_ERROR_RETURN_LOG(!photoSurface, "CreateSurfaceAsConsumer Error");
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    fuzz_->AddDeferredSurface(producer);
    fuzz_->SetFrameRate(fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>());
    fuzz_->SetMirror(fdp.ConsumeBool());
    fuzz_->SetMirrorForLivePhoto(fdp.ConsumeBool(), fdp.ConsumeIntegral<int32_t>());
    uint8_t randomNum = fdp.ConsumeIntegral<uint8_t>();
    std::vector<std::int32_t> test = {0, 90, 180, 270, 360};
    std::int32_t rotation(test[randomNum % test.size()]);
    fuzz_->SetCameraRotation(fdp.ConsumeBool(), rotation);
    fuzz_->SetCameraApi(fdp.ConsumeIntegral<uint32_t>());
    std::string deviceClass;
    fuzz_->SetPreviewRotation(deviceClass);
    fuzz_->UpdateSketchRatio(fdp.ConsumeBool());
    fuzz_->GetSketchStream();
    fuzz_->GetRepeatStreamType();
    fuzz_->SyncTransformToSketch();
    fuzz_->SetStreamTransform(fdp.ConsumeIntegral<int>());
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_FRONT;
    int32_t sensorOrientation = fdp.ConsumeIntegral<int32_t>();
    fuzz_->ProcessVerticalCameraPosition(sensorOrientation, cameraPosition);
    int32_t streamRotation = fdp.ConsumeIntegral<int32_t>();
    fuzz_->ProcessCameraPosition(streamRotation, cameraPosition);
    fuzz_->ProcessFixedTransform(sensorOrientation, cameraPosition);
    fuzz_->ProcessFixedDiffDeviceTransform(cameraPosition);
    fuzz_->ProcessCameraSetRotation(sensorOrientation, cameraPosition);
    camera_position_enum_t cameraPosition1 = OHOS_CAMERA_POSITION_BACK;
    int32_t sensorOrientation1 = fdp.ConsumeIntegral<int32_t>();
    fuzz_->ProcessVerticalCameraPosition(sensorOrientation1, cameraPosition1);
    int32_t streamRotation1 = fdp.ConsumeIntegral<int32_t>();
    fuzz_->ProcessCameraPosition(streamRotation1, cameraPosition1);
    fuzz_->ProcessFixedTransform(sensorOrientation1, cameraPosition1);
    fuzz_->ProcessFixedDiffDeviceTransform(cameraPosition1);
    fuzz_->ProcessCameraSetRotation(sensorOrientation1, cameraPosition1);
}

void HStreamRepeatFuzzer::HStreamRepeatFuzzTest3(FuzzedDataProvider& fdp)
{
    sptr<Surface> photoSurface = Surface::CreateSurfaceAsConsumer("hstreamrepeat");
    CHECK_ERROR_RETURN_LOG(!photoSurface, "CreateSurfaceAsConsumer Error");
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings;
    settings = std::make_shared<OHOS::Camera::CameraMetadata>(ITEMCOUNT, DATASIZE);
    fuzz_->OperatePermissionCheck(fdp.ConsumeIntegral<int>());
    fuzz_->OpenVideoDfxSwitch(settings);
    fuzz_->EnableSecure(fdp.ConsumeBool());
    fuzz_->UpdateVideoSettings(settings);
    fuzz_->UpdateFrameRateSettings(settings);
    std::shared_ptr<OHOS::Camera::CameraMetadata> dynamicSetting;
    fuzz_->UpdateFrameMuteSettings(settings, dynamicSetting);
#ifdef NOTIFICATION_ENABLE
    fuzz_->UpdateBeautySettings(settings);
    fuzz_->CancelNotification();
    fuzz_->IsNeedBeautyNotification();
#endif
    sptr<IStreamCapture> photoOutput = nullptr;
    fuzz_->AttachMetaSurface(producer, fdp.ConsumeIntegral<int32_t>());
    fuzz_->ToggleAutoVideoFrameRate(fdp.ConsumeBool());
    fuzz_->UpdateAutoFrameRateSettings(settings);
    std::shared_ptr<HStreamRepeatCallbackStub> callback = std::make_shared<HStreamRepeatCallbackStubDemo>();
    MessageParcel data;
    callback->HandleOnDeferredVideoEnhancementInfo(data);
}

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    auto hstreamRepeat = std::make_unique<HStreamRepeatFuzzer>();
    if (hstreamRepeat == nullptr) {
        MEDIA_INFO_LOG("hstreamRepeat is null");
        return;
    }
    HStreamRepeatFuzzer::fuzz_ = std::make_shared<HStreamRepeat>(nullptr,
        PHOTO_FORMAT, PHOTO_WIDTH, PHOTO_HEIGHT, RepeatStreamType::PREVIEW);
    CHECK_ERROR_RETURN_LOG(!HStreamRepeatFuzzer::fuzz_, "Create fuzz_ Error");
    hstreamRepeat->HStreamRepeatFuzzTest1(fdp);
    hstreamRepeat->HStreamRepeatFuzzTest2(fdp);
    hstreamRepeat->HStreamRepeatFuzzTest3(fdp);
}

} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    if (size < OHOS::CameraStandard::THRESHOLD) {
        return 0;
    }

    OHOS::CameraStandard::Test(data, size);
    return 0;
}