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

sptr<IBufferProducer> g_producer;

HStreamRepeat& GetHStreamRepeat()
{
    static HStreamRepeat hstreamRepeat(g_producer, PHOTO_FORMAT, PHOTO_WIDTH, PHOTO_HEIGHT, RepeatStreamType::PREVIEW);
    return hstreamRepeat;
}

void Start(FuzzedDataProvider& fdp)
{
    GetHStreamRepeat().Start();
}

void Stop(FuzzedDataProvider& fdp)
{
    GetHStreamRepeat().Stop();
}

void Release(FuzzedDataProvider& fdp)
{
    GetHStreamRepeat().Release();
}

void SetCallback(FuzzedDataProvider& fdp)
{
    sptr<MockStreamRepeatCallback> cb = new (std::nothrow) MockStreamRepeatCallback();
    GetHStreamRepeat().SetCallback(cb);
}

void AddDeferredSurface(FuzzedDataProvider& fdp)
{
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    GetHStreamRepeat().AddDeferredSurface(producer);
}

void RemoveSketchStreamRepeat(FuzzedDataProvider& fdp)
{
    GetHStreamRepeat().RemoveSketchStreamRepeat();
}

void UpdateSketchRatio(FuzzedDataProvider& fdp)
{
    GetHStreamRepeat().UpdateSketchRatio(fdp.ConsumeFloatingPoint<float>());
}

void SetFrameRate(FuzzedDataProvider& fdp)
{
    GetHStreamRepeat().SetFrameRate(fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>());
}

void EnableSecure(FuzzedDataProvider& fdp)
{
    GetHStreamRepeat().EnableSecure(fdp.ConsumeBool());
}

void EnableStitching(FuzzedDataProvider& fdp)
{
    GetHStreamRepeat().EnableStitching(fdp.ConsumeBool());
}

void SetMirror(FuzzedDataProvider& fdp)
{
    GetHStreamRepeat().SetMirror(fdp.ConsumeBool());
}

void AttachMetaSurface(FuzzedDataProvider& fdp)
{
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    GetHStreamRepeat().AttachMetaSurface(producer, fdp.ConsumeIntegral<int32_t>());
}

void SetCameraRotation(FuzzedDataProvider& fdp)
{
    GetHStreamRepeat().SetCameraRotation(fdp.ConsumeBool(), fdp.ConsumeIntegral<int32_t>());
}

void SetCameraApi(FuzzedDataProvider& fdp)
{
    GetHStreamRepeat().SetCameraApi(fdp.ConsumeIntegral<uint32_t>());
}

void GetMirror(FuzzedDataProvider& fdp)
{
    bool isEnable;
    GetHStreamRepeat().GetMirror(isEnable);
}

void UnSetCallback(FuzzedDataProvider& fdp)
{
    GetHStreamRepeat().UnSetCallback();
}

void SetOutputSettings(FuzzedDataProvider& fdp)
{
    MovieSettings setting { PickEnumInRange(fdp, VideoCodecType::VIDEO_ENCODE_TYPE_HEVC),
        fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeBool(),
        { fdp.ConsumeFloatingPoint<float>(), fdp.ConsumeFloatingPoint<float>(), fdp.ConsumeFloatingPoint<float>() },
        fdp.ConsumeBool(), fdp.ConsumeIntegral<int32_t>() };
    GetHStreamRepeat().SetOutputSettings(setting);
}

void GetSupportedVideoCodecTypes(FuzzedDataProvider& fdp)
{
    std::vector<int32_t> supportedTypes;
    GetHStreamRepeat().GetSupportedVideoCodecTypes(supportedTypes);
}

void SetBandwidthCompression(FuzzedDataProvider& fdp)
{
    GetHStreamRepeat().SetBandwidthCompression(fdp.ConsumeBool());
}

void RemoveDeferredSurface(FuzzedDataProvider& fdp)
{
    GetHStreamRepeat().RemoveDeferredSurface();
}

void HStreamRepeatFuzzTest1(FuzzedDataProvider& fdp)
{
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility;
    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator;
    GetHStreamRepeat().LinkInput(streamOperator, cameraAbility);
    StreamInfo_V1_5 streamInfo;
    GetHStreamRepeat().SetVideoStreamInfo(streamInfo);
    GetHStreamRepeat().SetStreamInfo(streamInfo);
    sptr<OHOS::IBufferProducer> metaProducer;
    GetHStreamRepeat().SetMetaProducer(metaProducer);
    SketchStatus status = SketchStatus::STOPED;
    GetHStreamRepeat().UpdateSketchStatus(status);
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings;
    settings = std::make_shared<OHOS::Camera::CameraMetadata>(ITEMCOUNT, DATASIZE);
    GetHStreamRepeat().StartSketchStream(settings);
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_FRONT;
    GetHStreamRepeat().SetUsedAsPosition(cameraPosition);
    GetHStreamRepeat().Start(settings, fdp.ConsumeBool());
    GetHStreamRepeat().Start();
    GetHStreamRepeat().OnFrameStarted();
    GetHStreamRepeat().OnFrameEnded(fdp.ConsumeIntegral<int32_t>());
    CaptureEndedInfoExt captureEndedInfo = { 1, 100, true, "video123" };
    GetHStreamRepeat().OnDeferredVideoEnhancementInfo(captureEndedInfo);
    GetHStreamRepeat().OnFrameError(fdp.ConsumeIntegral<int32_t>());
    GetHStreamRepeat().OnSketchStatusChanged(status);
    GetHStreamRepeat().Stop();
    GetHStreamRepeat().Release();
    GetHStreamRepeat().ReleaseStream(fdp.ConsumeBool());
}

void HStreamRepeatFuzzTest2(FuzzedDataProvider& fdp)
{
    sptr<Surface> photoSurface = Surface::CreateSurfaceAsConsumer("hstreamrepeat");
    CHECK_RETURN_ELOG(!photoSurface, "CreateSurfaceAsConsumer Error");
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    GetHStreamRepeat().AddDeferredSurface(producer);
    GetHStreamRepeat().SetFrameRate(fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>());
    GetHStreamRepeat().SetMirror(fdp.ConsumeBool());
    GetHStreamRepeat().SetMirrorForLivePhoto(fdp.ConsumeBool(), fdp.ConsumeIntegral<int32_t>());
    uint8_t randomNum = fdp.ConsumeIntegral<uint8_t>();
    std::vector<std::int32_t> test = { 0, 90, 180, 270, 360 };
    std::int32_t rotation(test[randomNum % test.size()]);
    GetHStreamRepeat().SetCameraRotation(fdp.ConsumeBool(), rotation);
    GetHStreamRepeat().SetCameraApi(fdp.ConsumeIntegral<uint32_t>());
    std::string deviceClass;
    GetHStreamRepeat().SetPreviewRotation(deviceClass);
    GetHStreamRepeat().UpdateSketchRatio(fdp.ConsumeBool());
    GetHStreamRepeat().GetSketchStream();
    GetHStreamRepeat().GetRepeatStreamType();
    GetHStreamRepeat().SyncTransformToSketch();
    GetHStreamRepeat().SetStreamTransform(fdp.ConsumeIntegral<int>());
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_FRONT;
    int32_t sensorOrientation = ((fdp.ConsumeIntegral<int32_t>() % ROTATION_360) + ROTATION_360) % ROTATION_360;
    GetHStreamRepeat().ProcessVerticalCameraPosition(sensorOrientation, cameraPosition);
    int32_t streamRotation = fdp.ConsumeIntegral<int32_t>();
    GetHStreamRepeat().ProcessCameraPosition(streamRotation, cameraPosition);
    GetHStreamRepeat().ProcessFixedTransform(sensorOrientation, cameraPosition);
    GetHStreamRepeat().ProcessFixedDiffDeviceTransform(sensorOrientation, cameraPosition);
    GetHStreamRepeat().ProcessCameraSetRotation(sensorOrientation);
    camera_position_enum_t cameraPosition1 = OHOS_CAMERA_POSITION_BACK;
    int32_t sensorOrientation1 = ((fdp.ConsumeIntegral<int32_t>() % ROTATION_360) + ROTATION_360) % ROTATION_360;
    GetHStreamRepeat().ProcessVerticalCameraPosition(sensorOrientation1, cameraPosition1);
    int32_t streamRotation1 = fdp.ConsumeIntegral<int32_t>();
    GetHStreamRepeat().ProcessCameraPosition(streamRotation1, cameraPosition1);
    GetHStreamRepeat().ProcessFixedTransform(sensorOrientation1, cameraPosition1);
    GetHStreamRepeat().ProcessFixedDiffDeviceTransform(sensorOrientation1, cameraPosition1);
    GetHStreamRepeat().ProcessCameraSetRotation(sensorOrientation1);
}

void HStreamRepeatFuzzTest3(FuzzedDataProvider& fdp)
{
    sptr<Surface> photoSurface = Surface::CreateSurfaceAsConsumer("hstreamrepeat");
    CHECK_RETURN_ELOG(!photoSurface, "CreateSurfaceAsConsumer Error");
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings;
    settings = std::make_shared<OHOS::Camera::CameraMetadata>(ITEMCOUNT, DATASIZE);
    GetHStreamRepeat().OperatePermissionCheck(fdp.ConsumeIntegral<int>());
    GetHStreamRepeat().OpenVideoDfxSwitch(settings);
    GetHStreamRepeat().EnableSecure(fdp.ConsumeBool());
    GetHStreamRepeat().UpdateVideoSettings(settings);
    GetHStreamRepeat().UpdateFrameRateSettings(settings);
    std::shared_ptr<OHOS::Camera::CameraMetadata> dynamicSetting;
    GetHStreamRepeat().UpdateFrameMuteSettings(settings, dynamicSetting);
#ifdef NOTIFICATION_ENABLE
    GetHStreamRepeat().UpdateBeautySettings(settings);
    GetHStreamRepeat().CancelNotification();
    GetHStreamRepeat().IsNeedBeautyNotification();
#endif
    sptr<IStreamCapture> photoOutput = nullptr;
    GetHStreamRepeat().AttachMetaSurface(producer, fdp.ConsumeIntegral<int32_t>());
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
    g_producer = photoSurface->GetProducer();
}

void Test(FuzzedDataProvider& fdp)
{
    auto func = fdp.PickValueInArray({
        Start,
        Stop,
        Release,
        SetCallback,
        AddDeferredSurface,
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