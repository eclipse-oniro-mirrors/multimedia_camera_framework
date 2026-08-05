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

#include "hstream_operator_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include "camera_log.h"
#include "iconsumer_surface.h"
#include "surface.h"
#include "ipc_skeleton.h"
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "accesstoken_kit.h"
#include "camera_server_photo_proxy.h"
#include "picture_interface.h"
#include "metadata_utils.h"
#include "test_token.h"
#include "fuzz_util.h"

using namespace OHOS;
using namespace OHOS::CameraStandard;
using namespace OHOS::HDI::Camera::V1_0;

namespace {
const int32_t PHOTO_WIDTH = 1280;
const int32_t PHOTO_HEIGHT = 960;
const int32_t PHOTO_FORMAT = 2000;
const int32_t META_FORMAT = 2003;
const int32_t DEPTH_FORMAT = 2004;
const int32_t ITEMCOUNT = 10;
const int32_t DATASIZE = 100;
const int32_t HDI_STREAM_ID_CAPTURE = 101;
const int32_t HDI_STREAM_ID_PREVIEW = 102;
const int32_t HDI_STREAM_ID_VIDEO = 103;
const int32_t HDI_STREAM_ID_META = 104;
const int32_t HDI_STREAM_ID_DEPTH = 105;
const int32_t FWK_STREAM_ID_CAPTURE = 11;
const int32_t FWK_STREAM_ID_PREVIEW = 12;
const int32_t FWK_STREAM_ID_VIDEO = 13;
const int32_t FWK_STREAM_ID_META = 14;
const int32_t FWK_STREAM_ID_DEPTH = 15;
const int32_t COLOR_SPACE_COUNT = static_cast<int32_t>(OHOS::CameraStandard::ColorSpace::H_LOG) + 1;
const int32_t ROTATION_360 = 360;

sptr<HStreamOperator> g_fuzz;
sptr<HStreamOperator> g_fuzzBare;
sptr<IStreamOperatorMock> g_mockOperator;
sptr<HCameraDevice> g_cameraDevice;
sptr<HStreamCapture> g_capture;
sptr<HStreamRepeat> g_repeatPreview;
sptr<HStreamRepeat> g_repeatVideo;
sptr<HStreamMetadata> g_metadata;
sptr<HStreamDepthData> g_depth;

sptr<OHOS::IBufferProducer> CreateProducer()
{
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    if (surface == nullptr) {
        return nullptr;
    }
    return surface->GetProducer();
}

std::shared_ptr<OHOS::Camera::CameraMetadata> MakeSettings(FuzzedDataProvider& fdp)
{
    return std::make_shared<OHOS::Camera::CameraMetadata>(
        fdp.ConsumeIntegralInRange<int32_t>(0, ITEMCOUNT), fdp.ConsumeIntegralInRange<int32_t>(0, DATASIZE));
}

OHOS::CameraStandard::ColorSpace PickColorSpace(FuzzedDataProvider& fdp)
{
    return static_cast<OHOS::CameraStandard::ColorSpace>(fdp.ConsumeIntegral<uint8_t>() % COLOR_SPACE_COUNT);
}

void InitStreamIds()
{
    g_capture->fwkStreamId_ = FWK_STREAM_ID_CAPTURE;
    g_capture->SetHdiStreamId(HDI_STREAM_ID_CAPTURE);
    g_repeatPreview->fwkStreamId_ = FWK_STREAM_ID_PREVIEW;
    g_repeatPreview->SetHdiStreamId(HDI_STREAM_ID_PREVIEW);
    g_repeatVideo->fwkStreamId_ = FWK_STREAM_ID_VIDEO;
    g_repeatVideo->SetHdiStreamId(HDI_STREAM_ID_VIDEO);
    g_metadata->fwkStreamId_ = FWK_STREAM_ID_META;
    g_metadata->SetHdiStreamId(HDI_STREAM_ID_META);
    g_depth->fwkStreamId_ = FWK_STREAM_ID_DEPTH;
    g_depth->SetHdiStreamId(HDI_STREAM_ID_DEPTH);
}

void SetupRichOperator()
{
    uint32_t callerToken = 0;
    g_fuzz = HStreamOperator::NewInstance(callerToken, 0);
    if (g_fuzz == nullptr) {
        MEDIA_ERR_LOG("HStreamOperator NewInstance failed");
        return;
    }
    sptr<OHOS::IBufferProducer> producer = CreateProducer();
    g_capture = sptr<HStreamCapture>::MakeSptr(producer, PHOTO_FORMAT, PHOTO_WIDTH, PHOTO_HEIGHT);
    g_repeatPreview =
        sptr<HStreamRepeat>::MakeSptr(producer, PHOTO_FORMAT, PHOTO_WIDTH, PHOTO_HEIGHT, RepeatStreamType::PREVIEW);
    g_repeatVideo =
        sptr<HStreamRepeat>::MakeSptr(producer, PHOTO_FORMAT, PHOTO_WIDTH, PHOTO_HEIGHT, RepeatStreamType::VIDEO);
    std::vector<int32_t> metaTypes = {static_cast<int32_t>(MetadataObjectType::FACE)};
    g_metadata = sptr<HStreamMetadata>::MakeSptr(producer, META_FORMAT, metaTypes);
    g_depth = sptr<HStreamDepthData>::MakeSptr(producer, DEPTH_FORMAT, PHOTO_WIDTH, PHOTO_HEIGHT);
    InitStreamIds();
    g_fuzz->AddOutput(StreamType::CAPTURE, g_capture);
    g_fuzz->AddOutput(StreamType::REPEAT, g_repeatPreview);
    g_fuzz->AddOutput(StreamType::REPEAT, g_repeatVideo);
    g_fuzz->AddOutput(StreamType::METADATA, g_metadata);
    g_fuzz->AddOutput(StreamType::DEPTH, g_depth);
    int32_t operatorId = 1;
    g_fuzz->SetStreamOperatorId(operatorId);
    sptr<HCameraHostManager> cameraHostManager = new HCameraHostManager(nullptr);
    g_cameraDevice = new HCameraDevice(cameraHostManager, "0", callerToken);
    g_fuzz->SetCameraDevice(g_cameraDevice);
    g_mockOperator = sptr<IStreamOperatorMock>::MakeSptr();
    g_fuzz->streamOperator_ = g_mockOperator;
    g_fuzzBare = HStreamOperator::NewInstance(callerToken, 0);
}
} // namespace

void StreamManagementFuzz(FuzzedDataProvider& fdp)
{
    CHECK_RETURN_ELOG(g_fuzz == nullptr, "g_fuzz is null");
    int32_t streamId = fdp.ConsumeIntegral<int32_t>();
    g_fuzz->GetStreamByStreamID(streamId);
    g_fuzz->GetHdiStreamByStreamID(fdp.ConsumeIntegral<int32_t>());
    g_fuzz->GetStreamsSize();
    auto allStreams = g_fuzz->GetAllStreams();
    std::vector<StreamInfo_V1_5> streamInfos;
    g_fuzz->GetCurrentStreamInfos(streamInfos);
    int32_t status = 0;
    g_fuzz->GetOutputStatus(status);
    g_fuzz->IsCaptureStreamExist();
    g_fuzz->IsOfflineCapture();
    g_fuzz->GetOfflineOutptSize();
    sptr<HStreamCommon> found = g_fuzz->GetStreamByStreamID(FWK_STREAM_ID_CAPTURE);
    g_fuzz->AddOutputStream(found);
    sptr<OHOS::IBufferProducer> producer = CreateProducer();
    auto disposable = sptr<HStreamCapture>::MakeSptr(producer, PHOTO_FORMAT, PHOTO_WIDTH, PHOTO_HEIGHT);
    disposable->fwkStreamId_ = fdp.ConsumeIntegral<int32_t>();
    g_fuzz->AddOutputStream(disposable);
    g_fuzz->RemoveOutputStream(disposable);
    g_fuzz->RemoveOutput(StreamType::CAPTURE, disposable);
}

void ColorSpaceFuzz(FuzzedDataProvider& fdp)
{
    CHECK_RETURN_ELOG(g_fuzz == nullptr, "g_fuzz is null");
    OHOS::CameraStandard::ColorSpace colorSpace = PickColorSpace(fdp);
    OHOS::CameraStandard::ColorSpace getColorSpace;
    g_fuzz->GetActiveColorSpace(getColorSpace);
    g_fuzz->SetColorSpace(colorSpace, fdp.ConsumeBool());
    g_fuzz->SetColorSpaceForStreams();
    g_fuzz->VerifyCaptureModeColorSpace(PickColorSpace(fdp));
    g_fuzz->CheckIfColorSpaceMatchesFormat(PickColorSpace(fdp));
    IsHdr(PickColorSpace(fdp));
}

void StreamLifecycleFuzz(FuzzedDataProvider& fdp)
{
    CHECK_RETURN_ELOG(g_fuzz == nullptr, "g_fuzz is null");
    auto settings = MakeSettings(fdp);
    int32_t opMode = fdp.ConsumeIntegral<int32_t>();
    std::vector<StreamInfo_V1_5> streamInfos;
    g_fuzz->CreateStreams(streamInfos);
    g_fuzz->CommitStreams(settings, opMode);
    g_fuzz->UpdateStreams(streamInfos);
    g_fuzz->CreateAndCommitStreams(streamInfos, settings, opMode);
    g_fuzz->UpdateStreamInfos(settings);
    std::vector<int32_t> releaseIds = {fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>()};
    g_fuzz->ReleaseStreams(releaseIds);
    g_fuzz->UnlinkInputAndOutputs();
    g_fuzz->UnlinkOfflineInputAndOutputs();
    g_fuzz->LinkInputAndOutputs(settings, opMode);
    g_fuzz->GetHDIStreamOperator();
    g_fuzz->ResetHDIStreamOperator();
    g_fuzz->GetStreamOperator();
    g_fuzz->streamOperator_ = g_mockOperator;
    g_fuzz->ResetHdiStreamId();
    sptr<HStreamOperator> disposable = HStreamOperator::NewInstance(0, 0);
    if (disposable != nullptr) {
        sptr<OHOS::IBufferProducer> producer = CreateProducer();
        auto capStream = sptr<HStreamCapture>::MakeSptr(producer, PHOTO_FORMAT, PHOTO_WIDTH, PHOTO_HEIGHT);
        capStream->fwkStreamId_ = fdp.ConsumeIntegral<int32_t>();
        capStream->SetHdiStreamId(fdp.ConsumeIntegral<int32_t>());
        disposable->AddOutput(StreamType::CAPTURE, capStream);
        disposable->streamOperator_ = g_mockOperator;
        disposable->ReleaseStreams();
        disposable->Stop();
    }
}

void CallbackFuzz(FuzzedDataProvider& fdp)
{
    CHECK_RETURN_ELOG(g_fuzz == nullptr, "g_fuzz is null");
    int32_t captureId = fdp.ConsumeIntegral<int32_t>();
    uint64_t timestamp = fdp.ConsumeIntegral<uint64_t>();
    int32_t repHdiId = g_repeatPreview->GetHdiStreamId();
    int32_t capHdiId = g_capture->GetHdiStreamId();
    int32_t vidHdiId = g_repeatVideo->GetHdiStreamId();
    std::vector<int32_t> streamIds = {repHdiId, capHdiId, fdp.ConsumeIntegral<int32_t>()};
    g_fuzz->OnCaptureStarted(captureId, streamIds);
    std::vector<OHOS::HDI::Camera::V1_2::CaptureStartedInfo> startedInfos;
    OHOS::HDI::Camera::V1_2::CaptureStartedInfo startedInfo;
    startedInfo.streamId_ = capHdiId;
    startedInfo.exposureTime_ = fdp.ConsumeIntegral<int32_t>();
    startedInfos.emplace_back(startedInfo);
    g_fuzz->OnCaptureStarted_V1_2(fdp.ConsumeIntegral<int32_t>(), startedInfos);
    std::vector<CaptureEndedInfo> endedInfos;
    CaptureEndedInfo endedRep;
    endedRep.streamId_ = repHdiId;
    endedRep.frameCount_ = fdp.ConsumeIntegral<int32_t>();
    endedInfos.emplace_back(endedRep);
    CaptureEndedInfo endedCap;
    endedCap.streamId_ = capHdiId;
    endedCap.frameCount_ = fdp.ConsumeIntegral<int32_t>();
    endedInfos.emplace_back(endedCap);
    g_fuzz->OnCaptureEnded(fdp.ConsumeIntegral<int32_t>(), endedInfos);
    std::vector<OHOS::HDI::Camera::V1_3::CaptureEndedInfoExt> endedExtInfos;
    OHOS::HDI::Camera::V1_3::CaptureEndedInfoExt endedExt;
    endedExt.streamId_ = vidHdiId;
    endedExt.frameCount_ = fdp.ConsumeIntegral<int32_t>();
    endedExt.isDeferredVideoEnhancementAvailable_ = fdp.ConsumeBool();
    endedExt.videoId_ = fdp.ConsumeRandomLengthString();
    endedExtInfos.emplace_back(endedExt);
    g_fuzz->OnCaptureEndedExt(fdp.ConsumeIntegral<int32_t>(), endedExtInfos);
    std::vector<CaptureErrorInfo> errInfos;
    CaptureErrorInfo errRep;
    errRep.streamId_ = repHdiId;
    errRep.error_ = static_cast<OHOS::HDI::Camera::V1_0::StreamError>(fdp.ConsumeIntegral<int32_t>());
    errInfos.emplace_back(errRep);
    CaptureErrorInfo errCap;
    errCap.streamId_ = capHdiId;
    errCap.error_ = static_cast<OHOS::HDI::Camera::V1_0::StreamError>(fdp.ConsumeIntegral<int32_t>());
    errInfos.emplace_back(errCap);
    g_fuzz->OnCaptureError(fdp.ConsumeIntegral<int32_t>(), errInfos);
    g_fuzz->OnFrameShutter(captureId, {capHdiId}, timestamp);
    g_fuzz->OnFrameShutterEnd(fdp.ConsumeIntegral<int32_t>(), {capHdiId}, fdp.ConsumeIntegral<uint64_t>());
    g_fuzz->OnCaptureReady(fdp.ConsumeIntegral<int32_t>(), {capHdiId}, fdp.ConsumeIntegral<uint64_t>());
    std::vector<uint8_t> resultData = ConsumeRandomVector<uint8_t>(fdp);
    g_fuzz->OnResult(HDI_STREAM_ID_META, resultData);
    g_fuzz->OnResult(-1, resultData);
    g_fuzz->OnCapturePaused(fdp.ConsumeIntegral<int32_t>(), {repHdiId, vidHdiId});
    g_fuzz->OnCaptureResumed(fdp.ConsumeIntegral<int32_t>(), {repHdiId});
}

void PreviewFrameRateFuzz(FuzzedDataProvider& fdp)
{
    CHECK_RETURN_ELOG(g_fuzz == nullptr, "g_fuzz is null");
    auto settings = MakeSettings(fdp);
    camera_position_enum_t cameraPosition =
        static_cast<camera_position_enum_t>(fdp.ConsumeIntegral<uint8_t>() % (OHOS_CAMERA_POSITION_OTHER + 1));
    g_fuzz->SetPreviewRotation(fdp.ConsumeRandomLengthString());
    g_fuzz->StartPreviewStream(settings, cameraPosition);
    g_fuzz->GetFrameRateRange();
    g_fuzz->UpdateSettingForFocusTrackingMech(fdp.ConsumeBool());
    g_fuzz->Stop();
}

void CompositionSketchFuzz(FuzzedDataProvider& fdp)
{
    CHECK_RETURN_ELOG(g_fuzz == nullptr, "g_fuzz is null");
    g_fuzz->ExpandSketchRepeatStream();
    g_fuzz->ExpandCompositionRepeatStream();
    g_fuzz->ClearSketchRepeatStream();
    g_fuzz->ClearCompositionRepeatStream();
    g_fuzz->GetCompositionStreams();
    g_fuzz->FindPreviewStreamRepeat();
}

#ifdef CAMERA_MOVING_PHOTO
void MovingPhotoFuzz(FuzzedDataProvider& fdp)
{
    CHECK_RETURN_ELOG(g_fuzz == nullptr, "g_fuzz is null");
    auto settings = MakeSettings(fdp);
    g_fuzz->EnableMovingPhoto(settings, fdp.ConsumeBool(), fdp.ConsumeIntegral<int32_t>());
    g_fuzz->EnableMovingPhotoMirror(fdp.ConsumeBool(), fdp.ConsumeBool());
    g_fuzz->StartMovingPhotoEncode(
        fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<uint64_t>(), fdp.ConsumeIntegral<int32_t>(),
        fdp.ConsumeIntegral<int32_t>());
    OHOS::CameraStandard::VideoType videoType = static_cast<OHOS::CameraStandard::VideoType>
        (fdp.ConsumeIntegral<uint8_t>() % (OHOS::CameraStandard::VideoType::XT_ORIGIN_VIDEO + 1));
    g_fuzz->StopMovingPhoto(videoType);
    g_fuzz->ClearMovingPhotoRepeatStream(videoType);
    g_fuzz->ReleaseTargetMovingphotoStream(videoType);
    g_fuzz->ReleaseMovingphotoStreams();
    g_fuzz->ExpandMovingPhotoRepeatStream(videoType);
    g_fuzz->ExpandXtStyleMovingPhotoRepeatStream();
    g_fuzz->StartMovingPhotoStream(settings);
    g_fuzz->IsLivephotoStreamExist();
    g_fuzz->SetDeferredVideoEnhanceFlag(
        fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<uint32_t>(), fdp.ConsumeRandomLengthString());
    g_fuzz->ChangeListenerXtstyleType();
}
#endif

void UtilityInlineFuzz(FuzzedDataProvider& fdp)
{
    CHECK_RETURN_ELOG(g_fuzz == nullptr, "g_fuzz is null");
    g_fuzz->GetPid();
    g_fuzz->SetXtStyleStatus(fdp.ConsumeBool());
    g_fuzz->GetXtStyleStatus();
    std::vector<int32_t> highRes = {fdp.ConsumeIntegral<int32_t>()};
    g_fuzz->GetDeferredImageDeliveryEnabled();
    camera_metadata_item_t item;
    g_fuzz->GetDeviceAbilityByMeta(fdp.ConsumeIntegral<uint32_t>(), &item);
    g_fuzz->GetSupportRedoXtStyle();
    g_fuzz->SetMechCallback(nullptr);
    int32_t rotation = 0;
    g_fuzz->UpdateOrientationBaseGravity(fdp.ConsumeIntegral<int32_t>(),
        ((fdp.ConsumeIntegral<int32_t>() % ROTATION_360) + ROTATION_360) % ROTATION_360,
        fdp.ConsumeIntegral<int32_t>(), rotation);
    g_fuzz->GetSensorRotation();
    g_fuzz->IsIpsRotateSupported();
#ifdef CAMERA_USE_SENSOR
    g_fuzz->RegisterSensorCallback();
#endif
    auto listener = new HStreamOperator::DisplayRotationListener();
    listener->AddHstreamRepeatForListener(g_repeatPreview);
    listener->OnChange(0);
    listener->RemoveHstreamRepeatForListener(g_repeatPreview);
    sptr<HStreamOperator> releaseTarget = HStreamOperator::NewInstance(0, 0);
    if (releaseTarget != nullptr) {
        releaseTarget->Release();
    }
}

void MediaLibraryFuzz(FuzzedDataProvider& fdp)
{
    CHECK_RETURN_ELOG(g_fuzz == nullptr, "g_fuzz is null");
    sptr<CameraServerPhotoProxy> photoProxy = sptr<CameraServerPhotoProxy>::MakeSptr();
    std::string uri = fdp.ConsumeRandomLengthString();
    int32_t cameraShotType = 0;
    std::string burstKey = fdp.ConsumeRandomLengthString();
    int64_t timestamp = fdp.ConsumeIntegral<int64_t>();
    g_fuzz->CreateMediaLibrary(photoProxy, uri, cameraShotType, burstKey, timestamp);
    int32_t shotType2 = 0;
    std::string burstKey2 = fdp.ConsumeRandomLengthString();
    std::string uri2 = fdp.ConsumeRandomLengthString();
    g_fuzz->CreateMediaLibrary(nullptr, photoProxy, uri2, shotType2, burstKey2, timestamp);
    bool isBursting = false;
    std::string burstKey3 = fdp.ConsumeRandomLengthString();
    int32_t shotType3 = 0;
    g_fuzz->SetCameraPhotoProxyInfo(photoProxy, shotType3, isBursting, burstKey3);
}

void NullDepFuzz(FuzzedDataProvider& fdp)
{
    CHECK_RETURN_ELOG(g_fuzzBare == nullptr, "g_fuzzBare is null");
    auto settings = MakeSettings(fdp);
    int32_t opMode = fdp.ConsumeIntegral<int32_t>();
    std::vector<StreamInfo_V1_5> streamInfos;
    g_fuzzBare->CreateStreams(streamInfos);
    g_fuzzBare->CommitStreams(settings, opMode);
    g_fuzzBare->UpdateStreams(streamInfos);
    g_fuzzBare->GetStreamOperator();
    camera_metadata_item_t item;
    g_fuzzBare->GetDeviceAbilityByMeta(fdp.ConsumeIntegral<uint32_t>(), &item);
    g_fuzzBare->GetSupportRedoXtStyle();
    g_fuzzBare->GetDeferredImageDeliveryEnabled();
    g_fuzzBare->UpdateSettingForFocusTrackingMech(fdp.ConsumeBool());
    g_fuzzBare->StartPreviewStream(settings, OHOS_CAMERA_POSITION_BACK);
    g_fuzzBare->IsOfflineCapture();
    g_fuzzBare->IsCaptureStreamExist();
    g_fuzzBare->GetOfflineOutptSize();
    g_fuzzBare->SetColorSpace(PickColorSpace(fdp), fdp.ConsumeBool());
    g_fuzzBare->Stop();
    g_fuzzBare->ReleaseStreams();
    g_fuzzBare->UnlinkInputAndOutputs();
    g_fuzzBare->UnlinkOfflineInputAndOutputs();
    g_fuzzBare->LinkInputAndOutputs(settings, opMode);
    int32_t status = 0;
    g_fuzzBare->GetOutputStatus(status);
    g_fuzzBare->GetFrameRateRange();
}

void Test(FuzzedDataProvider& fdp)
{
    CHECK_RETURN_ELOG(g_fuzz == nullptr, "g_fuzz is null");
    auto func = fdp.PickValueInArray({
        StreamManagementFuzz,
        ColorSpaceFuzz,
        StreamLifecycleFuzz,
        CallbackFuzz,
        PreviewFrameRateFuzz,
        CompositionSketchFuzz,
        UtilityInlineFuzz,
        MediaLibraryFuzz,
        NullDepFuzz,
#ifdef CAMERA_MOVING_PHOTO
        MovingPhotoFuzz,
#endif
    });
    func(fdp);
}

void Init()
{
    CHECK_RETURN_ELOG(!TestToken().GetAllCameraPermission(), "Get permission fail");
    SetupRichOperator();
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
