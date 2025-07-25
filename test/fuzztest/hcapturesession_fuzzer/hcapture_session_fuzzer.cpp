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

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t WIDE_CAMERA_ZOOM_RANGE = 0;
static constexpr int32_t MAIN_CAMERA_ZOOM_RANGE = 1;
static constexpr int32_t TWO_X_EXIT_TELE_ZOOM_RANGE = 2;
static constexpr int32_t TELE_CAMERA_ZOOM_RANGE = 3;
static constexpr int32_t MIN_SIZE_NUM = 256;
static constexpr int32_t NUM_1 = 1;
const int NUM_10 = 10;
const int NUM_100 = 100;

void HCaptureSessionFuzzer::HCaptureSessionFuzzTest1(FuzzedDataProvider& fdp)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = fdp.ConsumeIntegral<int32_t>();
    sptr<HCaptureSession> session;
    sptr<HStreamOperator> hStreamOperator;
    session = new HCaptureSession(callerToken, opMode);
    HCaptureSession::NewInstance(callerToken, opMode, session);
    hStreamOperator = HStreamOperator::NewInstance(callerToken, opMode);
    session->SetStreamOperator(hStreamOperator);
    CHECK_RETURN_ELOG(!session, "Create session Error");
    session->BeginConfig();
    session->CommitConfig();
    int32_t featureMode = fdp.ConsumeIntegral<int32_t>();
    session->SetFeatureMode(featureMode);
    int outFd =fdp.ConsumeIntegral<int32_t>();
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
    std::vector<StreamInfo_V1_1> streamInfos;
    session->GetCurrentStreamInfos(streamInfos);
    session->DynamicConfigStream();
    session->AddInput(nullptr);
    std::string deviceClass;
    session->SetPreviewRotation(deviceClass);
}

void HCaptureSessionFuzzer::HCaptureSessionFuzzTest2(FuzzedDataProvider& fdp)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = fdp.ConsumeIntegral<int32_t>();
    sptr<HCaptureSession> session;
    HCaptureSession::NewInstance(callerToken, opMode, session);
    CHECK_RETURN_ELOG(!session, "Create session Error");
    session->GetPid();
    StreamType streamType = StreamType::CAPTURE;
    session->AddOutput(streamType, nullptr);
    session->RemoveOutput(streamType, nullptr);
    session->RemoveInput(nullptr);
    std::vector<StreamInfo_V1_1> streamInfos;
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

void HCaptureSessionFuzzer::HCaptureSessionFuzzTest3(FuzzedDataProvider& fdp)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = fdp.ConsumeIntegral<int32_t>();
    sptr<HCaptureSession> session;
    HCaptureSession::NewInstance(callerToken, opMode, session);
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

void HCaptureSessionFuzzer::HCaptureSessionFuzzTest4(FuzzedDataProvider& fdp)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = fdp.ConsumeIntegral<int32_t>();
    sptr<HCaptureSession> session;
    HCaptureSession::NewInstance(callerToken, opMode, session);
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

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    auto hcaptureSession = std::make_unique<HCaptureSessionFuzzer>();
    if (hcaptureSession == nullptr) {
        MEDIA_INFO_LOG("hcaptureSession is null");
        return;
    }
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    hcaptureSession->HCaptureSessionFuzzTest1(fdp);
    hcaptureSession->HCaptureSessionFuzzTest2(fdp);
    hcaptureSession->HCaptureSessionFuzzTest3(fdp);
    hcaptureSession->HCaptureSessionFuzzTest4(fdp);
}

} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}