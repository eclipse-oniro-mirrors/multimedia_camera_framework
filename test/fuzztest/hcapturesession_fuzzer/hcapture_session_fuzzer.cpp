/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "hcapture_session_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include "camera_log.h"
#include "message_parcel.h"
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "accesstoken_kit.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "ipc_skeleton.h"
#include "buffer_extra_data_impl.h"
#include "moving_photo_proxy.h"
#include "camera_photo_proxy.h"
#include "hcamera_service.h"
#include "capture_session.h"
#include "test_token.h"

using namespace OHOS::CameraStandard;
static constexpr int32_t MAX_STR_LEN = 32;
static constexpr int32_t MAX_W_H = 4000;
static constexpr int32_t WIDE_CAMERA_ZOOM_RANGE = 0;
static constexpr int32_t MAIN_CAMERA_ZOOM_RANGE = 1;
static constexpr int32_t TWO_X_EXIT_TELE_ZOOM_RANGE = 2;
static constexpr int32_t TELE_CAMERA_ZOOM_RANGE = 3;
static constexpr int32_t NUM_1 = 1;
static const int NUM_10 = 10;
static const int NUM_100 = 100;
static const int32_t OP_MODE = 0;

sptr<HCameraService> g_cameraService;
std::vector<sptr<HCaptureSession>> g_sessions;
void HCaptureSessionFuzzTest1(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HStreamOperator> hStreamOperator;
    hStreamOperator = HStreamOperator::NewInstance(callerToken, OP_MODE);
    session->SetStreamOperator(hStreamOperator);
    CHECK_RETURN_ELOG(!session, "Create session Error");
    session->BeginConfig();
    session->CommitConfig();
    int32_t featureMode = fdp.ConsumeIntegral<int32_t>();
    session->SetFeatureMode(featureMode);
    int outFd = fdp.ConsumeIntegral<int32_t>();
    CameraInfoDumper infoDumper(outFd);
    session->DumpSessionInfo(infoDumper);
    session->DumpSessions(infoDumper);
    session->DumpCameraSessionSummary(infoDumper);
    session->OperatePermissionCheck(fdp.ConsumeIntegral<uint32_t>());
    session->EnableMovingPhotoMirror(fdp.ConsumeBool(), fdp.ConsumeBool());
    int32_t getColorSpace;
    session->GetActiveColorSpace(getColorSpace);
    constexpr int32_t executionModeCount = static_cast<int32_t>(ColorSpace::P3_PQ_LIMIT) + NUM_1;
    ColorSpace colorSpace = static_cast<ColorSpace>(fdp.ConsumeIntegral<uint8_t>() % executionModeCount);
    session->SetColorSpace(static_cast<int32_t>(colorSpace), fdp.ConsumeBool());
    session->GetopMode();
    std::vector<StreamInfo_V1_5> streamInfos;
    session->GetCurrentStreamInfos(streamInfos);
    session->DynamicConfigStream();
    session->AddInput(nullptr);
    std::string deviceClass;
    session->SetPreviewRotation(deviceClass);
}

void HCaptureSessionFuzzTest2(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    HCaptureSession::NewInstance(callerToken, OP_MODE, session);
    CHECK_RETURN_ELOG(!session, "Create session Error");
    session->GetPid();
    StreamType streamType = StreamType::CAPTURE;
    session->AddOutput(streamType, nullptr);
    session->RemoveOutput(streamType, nullptr);
    session->RemoveInput(nullptr);
    std::vector<StreamInfo_V1_5> streamInfos;
    session->RemoveOutputStream(nullptr);
    session->ValidateSession();
    CaptureSessionState sessionState = CaptureSessionState::SESSION_STARTED;
    session->GetSessionState(sessionState);
    float currentFps = fdp.ConsumeFloatingPoint<float>();
    float currentZoomRatio = fdp.ConsumeFloatingPoint<float>();
    std::vector<float> crossZoomAndTime;
    int32_t operationMode = fdp.ConsumeIntegral<int32_t>();
    session->QueryFpsAndZoomRatio(currentFps, currentZoomRatio, crossZoomAndTime, operationMode);
    session->GetSensorOritation();
    float zoomRatio = fdp.ConsumeFloatingPoint<float>();
    std::vector<float> crossZoom;
    session->GetRangeId(zoomRatio, crossZoom);
    float zoomPointA = fdp.ConsumeFloatingPoint<float>();
    float zoomPointB = fdp.ConsumeFloatingPoint<float>();
    session->isEqual(zoomPointA, zoomPointB);
    std::vector<std::vector<float>> crossTime_1;
    session->GetCrossZoomAndTime(crossZoomAndTime, crossZoom, crossTime_1);
}

void HCaptureSessionFuzzTest3(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    CHECK_RETURN_ELOG(!session, "Create session Error");
    int32_t targetRangeId = TELE_CAMERA_ZOOM_RANGE;
    int32_t currentRangeId = WIDE_CAMERA_ZOOM_RANGE;
    int32_t waitCount = 4;
    int32_t zoomInOutCount = 2;
    std::vector<std::vector<float>> crossTime_2(waitCount, std::vector<float>(zoomInOutCount, 0.0f));
    session->GetCrossWaitTime(crossTime_2, targetRangeId, currentRangeId);
    targetRangeId = WIDE_CAMERA_ZOOM_RANGE;
    session->GetCrossWaitTime(crossTime_2, targetRangeId, currentRangeId);
    currentRangeId = MAIN_CAMERA_ZOOM_RANGE;
    session->GetCrossWaitTime(crossTime_2, targetRangeId, currentRangeId);
    targetRangeId = TELE_CAMERA_ZOOM_RANGE;
    session->GetCrossWaitTime(crossTime_2, targetRangeId, currentRangeId);
    currentRangeId = TWO_X_EXIT_TELE_ZOOM_RANGE;
    session->GetCrossWaitTime(crossTime_2, targetRangeId, currentRangeId);
    targetRangeId = WIDE_CAMERA_ZOOM_RANGE;
    session->GetCrossWaitTime(crossTime_2, targetRangeId, currentRangeId);
    targetRangeId = MAIN_CAMERA_ZOOM_RANGE;
    session->GetCrossWaitTime(crossTime_2, targetRangeId, currentRangeId);
    currentRangeId = TELE_CAMERA_ZOOM_RANGE;
    session->GetCrossWaitTime(crossTime_2, targetRangeId, currentRangeId);
    targetRangeId = WIDE_CAMERA_ZOOM_RANGE;
    session->GetCrossWaitTime(crossTime_2, targetRangeId, currentRangeId);
    targetRangeId = TWO_X_EXIT_TELE_ZOOM_RANGE;
    session->GetCrossWaitTime(crossTime_2, targetRangeId, currentRangeId);
    int32_t smoothZoomType = fdp.ConsumeIntegral<int32_t>();
    float targetZoomRatio = fdp.ConsumeFloatingPoint<float>();
    float duration = fdp.ConsumeFloatingPoint<float>();
    int32_t operationMode = fdp.ConsumeIntegral<int32_t>();
    session->SetSmoothZoom(smoothZoomType, operationMode, targetZoomRatio, duration);
    session->Start();
    std::shared_ptr<OHOS::Camera::CameraMetadata> captureSettings;
    captureSettings = std::make_shared<OHOS::Camera::CameraMetadata>(NUM_10, NUM_100);
    session->UpdateMuteSetting(true, captureSettings);
    session->Stop();
}

void HCaptureSessionFuzzTest4(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    CHECK_RETURN_ELOG(!session, "Create session Error");
    pid_t pid = 0;
    session->DestroyStubObjectForPid(pid);
    sptr<ICaptureSessionCallback> callback;
    session->SetCallback(callback);
    session->GetSessionState();
    int32_t status = fdp.ConsumeIntegral<int32_t>();
    session->GetOutputStatus(status);
    int32_t imageSeqId = fdp.ConsumeIntegral<int32_t>();
    int32_t seqId = fdp.ConsumeIntegral<int32_t>();
    session->CreateBurstDisplayName(MAIN_CAMERA_ZOOM_RANGE, seqId);
    session->CreateBurstDisplayName(imageSeqId, seqId);
}

sptr<ICameraDeviceService> GetDevice(FuzzedDataProvider& fdp)
{
    static std::mutex mutex;
    std::lock_guard<std::mutex> lock(mutex);
    static sptr<ICameraDeviceService> device;
    if (device == nullptr) {
        g_cameraService->CreateCameraDevice(fdp.ConsumeRandomLengthString(MAX_STR_LEN), device);
    }
    return device;
}

sptr<IRemoteObject> GetRemote()
{
    static std::mutex mutex;
    std::lock_guard<std::mutex> lock(mutex);
    static sptr<IRemoteObject> remote;
    if (remote == nullptr) {
        remote = new MockIRemoteObject;
    }
    return remote;
}

sptr<IStreamCapture> GetPhotoOutput(FuzzedDataProvider& fdp)
{
    static sptr<ICameraDeviceService> device;
    int32_t format = fdp.ConsumeIntegral<int32_t>();
    int32_t width = fdp.ConsumeIntegral<int32_t>() % MAX_W_H;
    int32_t height = fdp.ConsumeIntegral<int32_t>() % MAX_W_H;
    sptr<IStreamCapture> photoOutput;
    g_cameraService->CreatePhotoOutput(format, width, height, photoOutput);
    return photoOutput;
}

void BeginConfig(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    session->BeginConfig();
}

void CanAddInput(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    bool result;
    session->CanAddInput(GetDevice(fdp), result);
}

void AddInput(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    session->AddInput(GetDevice(fdp));
}

void AddOutput(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    auto type = PickEnumInRange(fdp, StreamType::CAPTURE, StreamType::UNIFY_MOVIE);
    session->AddOutput(type, GetRemote());
}

void AddMultiStreamOutput(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    sptr<ICameraRecorder> recorder;
    session->CreateRecorder(GetRemote(), recorder);
    int32_t opMode = fdp.ConsumeIntegral<int32_t>();
    sptr<OHOS::IRemoteObject> remote = nullptr; // wait for opening rtti
    session->AddMultiStreamOutput(remote, opMode);
}

void RemoveMultiStreamOutput(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    sptr<OHOS::IRemoteObject> remote = nullptr; // wait for opening rtti
    session->RemoveMultiStreamOutput(nullptr);
}

void RemoveInput(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    session->RemoveInput(GetDevice(fdp));
}

void RemoveOutput(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    auto type = PickEnumInRange(fdp, StreamType::CAPTURE, StreamType::UNIFY_MOVIE);
    session->RemoveOutput(type, GetRemote());
}

void Start(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    session->Start();
}

void Stop(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    session->Stop();
}

void Release(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    session->Release();
}

void SetCallback(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    session->SetCallback(sptr<MockCaptureSessionCallback>::MakeSptr());
}

void UnSetCallback(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    session->UnSetCallback();
}

void SetPressureCallback(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    session->SetPressureCallback(sptr<MockPressureStatusCallback>::MakeSptr());
}

void UnSetPressureCallback(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    session->UnSetPressureCallback();
}

void SetPressureStatus(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    session->SetPressureStatus(PickEnumInRange(fdp, PressureStatus::SYSTEM_PRESSURE_SHUTDOWN));
}

void SetControlCenterEffectStatusCallback(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    auto cb = sptr<ControlCenterEffectStatusCallback>::MakeSptr();
    session->SetControlCenterEffectStatusCallback(cb);
}

void UnSetControlCenterEffectStatusCallback(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    session->UnSetControlCenterEffectStatusCallback();
}

void SetControlCenterEffectCallbackStatus(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    ControlCenterStatusInfo info { PickEnumInRange(fdp, ControlCenterEffectType::PORTRAIT), fdp.ConsumeBool() };
    session->SetControlCenterEffectCallbackStatus(info);
}

void SetCameraSwitchRequestCallback(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    auto cb = sptr<CameraSwitchSessionCallback>::MakeSptr();
    session->SetCameraSwitchRequestCallback(cb);
}

void UnSetCameraSwitchRequestCallback(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    session->UnSetCameraSwitchRequestCallback();
}

void GetSessionState(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    CaptureSessionState state;
    session->GetSessionState(state);
}

void GetActiveColorSpace(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    int32_t space;
    session->GetActiveColorSpace(space);
}

void SetColorSpace(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    session->SetColorSpace(fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeBool());
}

void QueryFpsAndZoomRatio(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    float fps;
    float ratio;
    std::vector<float> zoomTime;
    session->QueryFpsAndZoomRatio(fps, ratio, zoomTime, fdp.ConsumeIntegral<uint8_t>());
}

void QueryZoomPerformance(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    std::vector<float> zoomTime;
    uint8_t size = fdp.ConsumeIntegral<uint8_t>();
    std::vector<uint32_t> data;
    for (int i = 0; i < size; ++i) {
        data.emplace_back(fdp.ConsumeIntegral<uint32_t>());
    }
    camera_metadata_item_t item { .index = 0,
        .item = fdp.ConsumeIntegral<uint32_t>(),
        .data_type = META_TYPE_UINT32,
        .count = data.size(),
        .data.ui32 = data.data() };
    session->QueryZoomPerformance(zoomTime, fdp.ConsumeIntegral<int32_t>(), item);
}

void GetRangeId(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    float ratio;
    std::vector<float> zoom;
    session->GetRangeId(ratio, zoom);
}

void GetCrossWaitTimeFromWide(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    std::vector<std::vector<float>> time;
    session->GetCrossWaitTimeFromWide(time, fdp.ConsumeIntegral<int32_t>());
}

void GetCrossWaitTimeFromMain(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    std::vector<std::vector<float>> time;
    session->GetCrossWaitTimeFromMain(time, fdp.ConsumeIntegral<int32_t>());
}
void GetCrossWaitTimeFrom2X(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    std::vector<std::vector<float>> time;
    session->GetCrossWaitTimeFrom2X(time, fdp.ConsumeIntegral<int32_t>());
}

void GetCrossWaitTimeFromTele(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    std::vector<std::vector<float>> time;
    session->GetCrossWaitTimeFromTele(time, fdp.ConsumeIntegral<int32_t>());
}

void GetCrossWaitTimeFromTele2(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    std::vector<std::vector<float>> time;
    session->GetCrossWaitTimeFromTele2(time, fdp.ConsumeIntegral<int32_t>());
}

void GetCrossWaitTime(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    std::vector<std::vector<float>> time;
    session->GetCrossWaitTime(time, fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>());
}

void GetCrossZoomAndTime(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    std::vector<float> crossZoomAndTime;
    std::vector<float> crossZoom;
    std::vector<std::vector<float>> crossTime;
    session->GetCrossZoomAndTime(crossZoomAndTime, crossZoom, crossTime);
    session->Release();
}

void QueryZoomBezierValue(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    std::vector<float> zoomBezier;
    session->QueryZoomBezierValue(zoomBezier);
}

void SetSmoothZoom(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    float duration;
    session->SetSmoothZoom(
        fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeFloatingPoint<float>(), duration);
}

void SupportHalCalSmoothZoom(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    session->supportHalCalSmoothZoom(fdp.ConsumeFloatingPoint<float>());
}

void EnableMovingPhoto(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    session->EnableMovingPhoto(fdp.ConsumeBool());
}

void GetPid(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    session->GetPid();
}

void GetSessionId(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    session->GetSessionId();
}

void GetCurrentStreamInfos(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    std::vector<StreamInfo_V1_5> info;
    session->GetCurrentStreamInfos(info);
}

void GetopMode(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    session->GetopMode();
}

void EnableKeyFrameReport(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    session->EnableKeyFrameReport(fdp.ConsumeBool());
}

void OperatePermissionCheck(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    session->OperatePermissionCheck(fdp.ConsumeIntegral<uint32_t>());
}

void CallbackEnter(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    session->CallbackEnter(fdp.ConsumeIntegral<int32_t>());
}

void CallbackExit(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    session->CallbackExit(fdp.ConsumeIntegral<uint32_t>(), fdp.ConsumeIntegral<int32_t>());
}

void EnableMovingPhotoMirror(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    session->EnableMovingPhotoMirror(fdp.ConsumeBool(), fdp.ConsumeBool());
}

void SetFeatureMode(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    session->SetFeatureMode(fdp.ConsumeIntegral<int32_t>());
}

void GetOutputStatus(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    int32_t status;
    session->GetOutputStatus(status);
}

void SetPreviewRotation(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    session->SetPreviewRotation(fdp.ConsumeRandomLengthString());
}

void SetCommitConfigFlag(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    session->SetCommitConfigFlag(fdp.ConsumeBool());
}

void CreateRecorder(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    sptr<ICameraRecorder> recorder;
    session->CreateRecorder(GetRemote(), recorder);
}

void SetXtStyleStatus(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    session->SetXtStyleStatus(fdp.ConsumeBool());
}

#ifdef CAMERA_MOVING_PHOTO
void SetMovingPhotoStatus(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    session->SetMovingPhotoStatus(fdp.ConsumeBool());
}

void GetMovingPhotoStatus(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    session->GetMovingPhotoStatus();
}
#endif

void SetHasFitedRotation(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    session->SetHasFitedRotation(fdp.ConsumeBool());
}

void GetVirtualApertureMetadata(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    std::vector<float> meta;
    session->GetVirtualApertureMetadata(meta);
}

void GetVirtualApertureValue(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    float value;
    session->GetVirtualApertureValue(value);
}

void SetVirtualApertureValue(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    session->SetVirtualApertureValue(fdp.ConsumeFloatingPoint<float>(), fdp.ConsumeBool());
}

void GetBeautyMetadata(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    std::vector<int32_t> meta;
    session->GetBeautyMetadata(meta);
}

void GetBeautyRange(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    std::vector<int32_t> range;
    session->GetBeautyRange(range, fdp.ConsumeIntegral<int32_t>());
}

void GetBeautyValue(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    int32_t value;
    session->GetBeautyValue(fdp.ConsumeIntegral<int32_t>(), value);
}

void SetBeautyValue(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    session->SetBeautyValue(fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeBool());
}

void GetCompositionStream(FuzzedDataProvider& fdp, sptr<HCaptureSession>& session)
{
    sptr<IRemoteObject> remote;
    session->GetCompositionStream(remote);
}

void Init()
{
    CHECK_RETURN_ELOG(!TestToken().GetAllCameraPermission(), "Get permission fail");
    g_cameraService = new HCameraService(3008, true);
    g_cameraService->OnStart();
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    for (int32_t mode = 0; mode <= 2; ++mode) {
        sptr<HCaptureSession> session;
        HCaptureSession::NewInstance(callerToken, mode, session);
        g_sessions.push_back(session);
    }
}

void Test(FuzzedDataProvider& fdp)
{
    CHECK_RETURN_ELOG(g_cameraService == nullptr, "g_cameraService is nullptr");
    auto func = fdp.PickValueInArray({
        HCaptureSessionFuzzTest1,
        HCaptureSessionFuzzTest2,
        HCaptureSessionFuzzTest3,
        HCaptureSessionFuzzTest4,
        BeginConfig,
        AddInput,
        AddOutput,
        AddMultiStreamOutput,
        RemoveMultiStreamOutput,
        RemoveInput,
        RemoveOutput,
        Start,
        Stop,
        Release,
        SetCallback,
        UnSetCallback,
        SetPressureCallback,
        UnSetPressureCallback,
        SetPressureStatus,
        SetControlCenterEffectStatusCallback,
        UnSetControlCenterEffectStatusCallback,
        SetControlCenterEffectCallbackStatus,
        SetCameraSwitchRequestCallback,
        UnSetCameraSwitchRequestCallback,
        GetSessionState,
        GetActiveColorSpace,
        SetColorSpace,
        QueryFpsAndZoomRatio,
        QueryZoomPerformance,
        GetRangeId,
        GetCrossWaitTimeFromWide,
        GetCrossWaitTimeFromMain,
        GetCrossWaitTimeFrom2X,
        GetCrossWaitTimeFromTele,
        GetCrossWaitTimeFromTele2,
        GetCrossWaitTime,
        GetCrossZoomAndTime,
        QueryZoomBezierValue,
        SetSmoothZoom,
        SupportHalCalSmoothZoom,
        EnableMovingPhoto,
        GetPid,
        GetSessionId,
        GetCurrentStreamInfos,
        GetopMode,
        EnableKeyFrameReport,
        OperatePermissionCheck,
        CallbackEnter,
        CallbackExit,
        EnableMovingPhotoMirror,
        SetFeatureMode,
        GetOutputStatus,
        SetPreviewRotation,
        SetCommitConfigFlag,
        CreateRecorder,
        SetXtStyleStatus,
#ifdef CAMERA_MOVING_PHOTO
        SetMovingPhotoStatus,
        GetMovingPhotoStatus,
#endif
        SetHasFitedRotation,
        GetVirtualApertureMetadata,
        GetVirtualApertureValue,
        SetVirtualApertureValue,
        GetBeautyMetadata,
        GetBeautyRange,
        GetBeautyValue,
        SetBeautyValue,
        GetCompositionStream,
    });
    auto& session = g_sessions[fdp.ConsumeIntegral<uint8_t>() % g_sessions.size()];
    CHECK_RETURN_ELOG(session == nullptr, "session is nullptr");
    func(fdp, session);
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