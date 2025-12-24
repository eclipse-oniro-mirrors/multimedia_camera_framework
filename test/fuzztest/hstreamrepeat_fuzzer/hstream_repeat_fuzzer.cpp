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
#include "camera_device.h"
#include "camera_manager.h"
#include "ipc_skeleton.h"
#include "securec.h"
#include <fuzzer/FuzzedDataProvider.h>
#include "fuzz_util.h"
#include "test_token.h"

using namespace OHOS;
using namespace OHOS::CameraStandard;
using namespace OHOS::HDI::Camera::V1_0;
const std::u16string INTERFACE_TOKEN = u"OHOS.CameraStandard.IStreamRepeatCallback";
const size_t MAX_LENGTH = 64;
const int32_t ITEMCOUNT = 10;
const int32_t DATASIZE = 100;
const int32_t PHOTO_WIDTH = 1280;
const int32_t PHOTO_HEIGHT = 960;
const int32_t PHOTO_FORMAT = 2000;
const int32_t ROTATION_360 = 360;

sptr<HStreamRepeat> g_hStreamRepeat;

void Start(FuzzedDataProvider& fdp)
{
    g_hStreamRepeat->Start();
}

void Stop(FuzzedDataProvider& fdp)
{
    g_hStreamRepeat->Stop();
}

void Release(FuzzedDataProvider& fdp)
{
    g_hStreamRepeat->Release();
}

void SetCallback(FuzzedDataProvider& fdp)
{
    auto cb = sptr<MockStreamRepeatCallback>::MakeSptr();
    g_hStreamRepeat->SetCallback(cb);
}

void AddDeferredSurface(FuzzedDataProvider& fdp)
{
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    g_hStreamRepeat->AddDeferredSurface(producer);
}

void ForkSketchStreamRepeat(FuzzedDataProvider& fdp)
{
    sptr<IRemoteObject> remote = sptr<MockIRemoteObject>::MakeSptr();
    g_hStreamRepeat->ForkSketchStreamRepeat(
        fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>(), remote, fdp.ConsumeFloatingPoint<float>());
}

void RemoveSketchStreamRepeat(FuzzedDataProvider& fdp)
{
    g_hStreamRepeat->RemoveSketchStreamRepeat();
}

void UpdateSketchRatio(FuzzedDataProvider& fdp)
{
    g_hStreamRepeat->UpdateSketchRatio(fdp.ConsumeFloatingPoint<float>());
}

void SetFrameRate(FuzzedDataProvider& fdp)
{
    g_hStreamRepeat->SetFrameRate(fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>());
}

void EnableSecure(FuzzedDataProvider& fdp)
{
    g_hStreamRepeat->EnableSecure(fdp.ConsumeBool());
}

void EnableStitching(FuzzedDataProvider& fdp)
{
    g_hStreamRepeat->EnableStitching(fdp.ConsumeBool());
}

void SetMirror(FuzzedDataProvider& fdp)
{
    g_hStreamRepeat->SetMirror(fdp.ConsumeBool());
}

void AttachMetaSurface(FuzzedDataProvider& fdp)
{
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    g_hStreamRepeat->AttachMetaSurface(producer, fdp.ConsumeIntegral<int32_t>());
}

void SetCameraRotation(FuzzedDataProvider& fdp)
{
    g_hStreamRepeat->SetCameraRotation(fdp.ConsumeBool(), fdp.ConsumeIntegral<int32_t>());
}

void SetCameraApi(FuzzedDataProvider& fdp)
{
    g_hStreamRepeat->SetCameraApi(fdp.ConsumeIntegral<uint32_t>());
}

void GetMirror(FuzzedDataProvider& fdp)
{
    bool isEnable;
    g_hStreamRepeat->GetMirror(isEnable);
}

void UnSetCallback(FuzzedDataProvider& fdp)
{
    g_hStreamRepeat->UnSetCallback();
}

void SetOutputSettings(FuzzedDataProvider& fdp)
{
    MovieSettings setting { PickEnumInRange(fdp, VideoCodecType::VIDEO_ENCODE_TYPE_HEVC),
        fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeBool(),
        { fdp.ConsumeFloatingPoint<float>(), fdp.ConsumeFloatingPoint<float>(), fdp.ConsumeFloatingPoint<float>() },
        fdp.ConsumeBool(), fdp.ConsumeIntegral<int32_t>() };
    g_hStreamRepeat->SetOutputSettings(setting);
}

void GetSupportedVideoCodecTypes(FuzzedDataProvider& fdp)
{
    std::vector<int32_t> supportedTypes;
    g_hStreamRepeat->GetSupportedVideoCodecTypes(supportedTypes);
}

void SetBandwidthCompression(FuzzedDataProvider& fdp)
{
    g_hStreamRepeat->SetBandwidthCompression(fdp.ConsumeBool());
}

void RemoveDeferredSurface(FuzzedDataProvider& fdp)
{
    g_hStreamRepeat->RemoveDeferredSurface();
}

void HStreamRepeatFuzzTest1(FuzzedDataProvider& fdp)
{
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility;
    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator;
    g_hStreamRepeat->LinkInput(streamOperator, cameraAbility);
    StreamInfo_V1_5 streamInfo;
    g_hStreamRepeat->SetVideoStreamInfo(streamInfo);
    g_hStreamRepeat->SetStreamInfo(streamInfo);
    sptr<OHOS::IBufferProducer> metaProducer;
    g_hStreamRepeat->SetMetaProducer(metaProducer);
    SketchStatus status = SketchStatus::STOPED;
    g_hStreamRepeat->UpdateSketchStatus(status);
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings;
    settings = std::make_shared<OHOS::Camera::CameraMetadata>(ITEMCOUNT, DATASIZE);
    g_hStreamRepeat->StartSketchStream(settings);
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_FRONT;
    g_hStreamRepeat->SetUsedAsPosition(cameraPosition);
    g_hStreamRepeat->Start(settings, fdp.ConsumeBool());
    g_hStreamRepeat->Start();
    g_hStreamRepeat->OnFrameStarted();
    g_hStreamRepeat->OnFrameEnded(fdp.ConsumeIntegral<int32_t>());
    CaptureEndedInfoExt captureEndedInfo = { 1, 100, true, "video123" };
    g_hStreamRepeat->OnDeferredVideoEnhancementInfo(captureEndedInfo);
    g_hStreamRepeat->OnFrameError(fdp.ConsumeIntegral<int32_t>());
    g_hStreamRepeat->OnSketchStatusChanged(status);
    g_hStreamRepeat->Stop();
    g_hStreamRepeat->Release();
    g_hStreamRepeat->ReleaseStream(fdp.ConsumeBool());
}

void HStreamRepeatFuzzTest2(FuzzedDataProvider& fdp)
{
    sptr<Surface> photoSurface = Surface::CreateSurfaceAsConsumer("hstreamrepeat");
    CHECK_RETURN_ELOG(!photoSurface, "CreateSurfaceAsConsumer Error");
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    g_hStreamRepeat->AddDeferredSurface(producer);
    g_hStreamRepeat->SetFrameRate(fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>());
    g_hStreamRepeat->SetMirror(fdp.ConsumeBool());
    g_hStreamRepeat->SetMirrorForLivePhoto(fdp.ConsumeBool(), fdp.ConsumeIntegral<int32_t>());
    uint8_t randomNum = fdp.ConsumeIntegral<uint8_t>();
    std::vector<std::int32_t> test = { 0, 90, 180, 270, 360 };
    std::int32_t rotation(test[randomNum % test.size()]);
    g_hStreamRepeat->SetCameraRotation(fdp.ConsumeBool(), rotation);
    g_hStreamRepeat->SetCameraApi(fdp.ConsumeIntegral<uint32_t>());
    std::string deviceClass;
    g_hStreamRepeat->SetPreviewRotation(deviceClass);
    g_hStreamRepeat->UpdateSketchRatio(fdp.ConsumeBool());
    g_hStreamRepeat->GetSketchStream();
    g_hStreamRepeat->GetRepeatStreamType();
    g_hStreamRepeat->SyncTransformToSketch();
    g_hStreamRepeat->SetStreamTransform(fdp.ConsumeIntegral<int>());
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_FRONT;
    int32_t sensorOrientation = ((fdp.ConsumeIntegral<int32_t>() % ROTATION_360) + ROTATION_360) % ROTATION_360;
    g_hStreamRepeat->ProcessVerticalCameraPosition(sensorOrientation, cameraPosition);
    int32_t streamRotation = fdp.ConsumeIntegral<int32_t>();
    g_hStreamRepeat->ProcessCameraPosition(streamRotation, cameraPosition);
    g_hStreamRepeat->ProcessFixedTransform(sensorOrientation, cameraPosition);
    g_hStreamRepeat->ProcessFixedDiffDeviceTransform(sensorOrientation, cameraPosition);
    g_hStreamRepeat->ProcessCameraSetRotation(sensorOrientation);
    camera_position_enum_t cameraPosition1 = OHOS_CAMERA_POSITION_BACK;
    int32_t sensorOrientation1 = ((fdp.ConsumeIntegral<int32_t>() % ROTATION_360) + ROTATION_360) % ROTATION_360;
    g_hStreamRepeat->ProcessVerticalCameraPosition(sensorOrientation1, cameraPosition1);
    int32_t streamRotation1 = fdp.ConsumeIntegral<int32_t>();
    g_hStreamRepeat->ProcessCameraPosition(streamRotation1, cameraPosition1);
    g_hStreamRepeat->ProcessFixedTransform(sensorOrientation1, cameraPosition1);
    g_hStreamRepeat->ProcessFixedDiffDeviceTransform(sensorOrientation1, cameraPosition1);
    g_hStreamRepeat->ProcessCameraSetRotation(sensorOrientation1);
}

void HStreamRepeatFuzzTest3(FuzzedDataProvider& fdp)
{
    sptr<Surface> photoSurface = Surface::CreateSurfaceAsConsumer("hstreamrepeat");
    CHECK_RETURN_ELOG(!photoSurface, "CreateSurfaceAsConsumer Error");
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings;
    settings = std::make_shared<OHOS::Camera::CameraMetadata>(ITEMCOUNT, DATASIZE);
    g_hStreamRepeat->OperatePermissionCheck(fdp.ConsumeIntegral<int>());
    g_hStreamRepeat->OpenVideoDfxSwitch(settings);
    g_hStreamRepeat->EnableSecure(fdp.ConsumeBool());
    g_hStreamRepeat->UpdateVideoSettings(settings);
    g_hStreamRepeat->UpdateFrameRateSettings(settings);
    std::shared_ptr<OHOS::Camera::CameraMetadata> dynamicSetting;
    g_hStreamRepeat->UpdateFrameMuteSettings(settings, dynamicSetting);
#ifdef NOTIFICATION_ENABLE
    g_hStreamRepeat->UpdateBeautySettings(settings);
    g_hStreamRepeat->CancelNotification();
    g_hStreamRepeat->IsNeedBeautyNotification();
#endif
    sptr<IStreamCapture> photoOutput = nullptr;
    g_hStreamRepeat->AttachMetaSurface(producer, fdp.ConsumeIntegral<int32_t>());
    std::shared_ptr<StreamRepeatCallbackStub> callback = std::make_shared<HStreamRepeatCallbackStubDemo>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(INTERFACE_TOKEN);
    data.WriteInt32(fdp.ConsumeIntegral<int32_t>());
    data.WriteInt32(fdp.ConsumeIntegral<int32_t>());
    data.WriteInt32(fdp.ConsumeBool());
    data.WriteString16(Str8ToStr16(fdp.ConsumeRandomLengthString(MAX_LENGTH)));
    data.WriteUint32(fdp.ConsumeIntegral<uint32_t>());
    callback->OnRemoteRequest(
        static_cast<uint32_t>(IStreamRepeatCallbackIpcCode::COMMAND_ON_DEFERRED_VIDEO_ENHANCEMENT_INFO), data, reply,
        option);
}

void Init()
{
    CHECK_RETURN_ELOG(!TestToken().GetAllCameraPermission(), "Get permission fail");
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    g_hStreamRepeat = new HStreamRepeat(producer, PHOTO_FORMAT, PHOTO_WIDTH, PHOTO_HEIGHT, RepeatStreamType::PREVIEW);
}

void Test(FuzzedDataProvider& fdp)
{
    CHECK_RETURN_ELOG(g_hStreamRepeat == nullptr, "g_hStreamMetadata is nullptr");
    auto func = fdp.PickValueInArray({
        Start,
        Stop,
        Release,
        SetCallback,
        AddDeferredSurface,
        ForkSketchStreamRepeat,
        RemoveSketchStreamRepeat,
        UpdateSketchRatio,
        SetFrameRate,
        EnableSecure,
        EnableStitching,
        SetMirror,
        AttachMetaSurface,
        SetCameraRotation,
        SetCameraApi,
        GetMirror,
        UnSetCallback,
        SetOutputSettings,
        GetSupportedVideoCodecTypes,
        SetBandwidthCompression,
        RemoveDeferredSurface,
        HStreamRepeatFuzzTest1,
        HStreamRepeatFuzzTest2,
        HStreamRepeatFuzzTest3,
    });
    func(fdp);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    Test(fdp);
    return 0;
}

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    if (SetSelfTokenID(718336240ull | (1ull << 32)) < 0) {
        return -1;
    }
    Init();
    return 0;
}