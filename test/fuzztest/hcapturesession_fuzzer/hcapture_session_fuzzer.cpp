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
#include "camera_server_photo_proxy.h"
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

std::shared_ptr<HCaptureSession> HCaptureSessionFuzzer::fuzz_{nullptr};

void HCaptureSessionFuzzer::HCaptureSessionFuzzTest1(FuzzedDataProvider& fdp)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = fdp.ConsumeIntegral<int32_t>();
    sptr<HCaptureSession> session;
    sptr<HStreamOperator> hStreamOperator;
    fuzz_ = std::make_shared<HCaptureSession>(callerToken, opMode);
    fuzz_->NewInstance(0, 0, session);
    hStreamOperator = HStreamOperator::NewInstance(0, 0);
    fuzz_->SetStreamOperator(hStreamOperator);
    CHECK_ERROR_RETURN_LOG(!fuzz_, "Create fuzz_ Error");
    fuzz_->BeginConfig();
    fuzz_->CommitConfig();
    int32_t featureMode = fdp.ConsumeIntegral<int32_t>();
    fuzz_->SetFeatureMode(featureMode);
    int outFd =fdp.ConsumeIntegral<int32_t>();
    CameraInfoDumper infoDumper(outFd);
    fuzz_->DumpSessionInfo(infoDumper);
    fuzz_->DumpSessions(infoDumper);
    fuzz_->DumpCameraSessionSummary(infoDumper);
    fuzz_->OperatePermissionCheck(fdp.ConsumeIntegral<uint32_t>());
    fuzz_->EnableMovingPhotoMirror(fdp.ConsumeBool(), fdp.ConsumeBool());
    int32_t getColorSpace;
    fuzz_->GetActiveColorSpace(getColorSpace);
    constexpr int32_t executionModeCount = static_cast<int32_t>(ColorSpace::P3_PQ_LIMIT) + NUM_1;
    ColorSpace colorSpace = static_cast<ColorSpace>(fdp.ConsumeIntegral<uint8_t>() % executionModeCount);
    fuzz_->SetColorSpace(static_cast<int32_t>(colorSpace), fdp.ConsumeBool());
    fuzz_->GetopMode();
    std::vector<StreamInfo_V1_1> streamInfos;
    fuzz_->GetCurrentStreamInfos(streamInfos);
    fuzz_->DynamicConfigStream();
    fuzz_->AddInput(nullptr);
    std::string deviceClass;
    fuzz_->SetPreviewRotation(deviceClass);
}

void HCaptureSessionFuzzer::HCaptureSessionFuzzTest2(FuzzedDataProvider& fdp)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = fdp.ConsumeIntegral<int32_t>();
    sptr<HCaptureSession> session;
    fuzz_ = std::make_shared<HCaptureSession>(callerToken, opMode);
    fuzz_->NewInstance(0, 0, session);
    CHECK_ERROR_RETURN_LOG(!fuzz_, "Create fuzz_ Error");
    fuzz_->GetPid();
    StreamType streamType = StreamType::CAPTURE;
    fuzz_->AddOutput(streamType, nullptr);
    fuzz_->RemoveOutput(streamType, nullptr);
    fuzz_->RemoveInput(nullptr);
    std::vector<StreamInfo_V1_1> streamInfos;
    fuzz_->RemoveOutputStream(nullptr);
    fuzz_->ValidateSession();
    CaptureSessionState sessionState = CaptureSessionState::SESSION_STARTED;
    fuzz_->GetSessionState(sessionState);
    float currentFps = fdp.ConsumeFloatingPoint<float>();
    float currentZoomRatio = fdp.ConsumeFloatingPoint<float>();
    std::vector<float> crossZoomAndTime;
    int32_t operationMode = fdp.ConsumeIntegral<int32_t>();
    fuzz_->QueryFpsAndZoomRatio(currentFps, currentZoomRatio, crossZoomAndTime, operationMode);
    fuzz_->GetSensorOritation();
    float zoomRatio = fdp.ConsumeFloatingPoint<float>();
    std::vector<float> crossZoom;
    fuzz_->GetRangeId(zoomRatio, crossZoom);
    float zoomPointA = fdp.ConsumeFloatingPoint<float>();
    float zoomPointB = fdp.ConsumeFloatingPoint<float>();
    fuzz_->isEqual(zoomPointA, zoomPointB);
    std::vector<std::vector<float>> crossTime_1;
    fuzz_->GetCrossZoomAndTime(crossZoomAndTime, crossZoom, crossTime_1);
}

void HCaptureSessionFuzzer::HCaptureSessionFuzzTest3(FuzzedDataProvider& fdp)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = fdp.ConsumeIntegral<int32_t>();
    sptr<HCaptureSession> session;
    fuzz_ = std::make_shared<HCaptureSession>(callerToken, opMode);
    fuzz_->NewInstance(0, 0, session);
    CHECK_ERROR_RETURN_LOG(!fuzz_, "Create fuzz_ Error");
    int32_t targetRangeId = TELE_CAMERA_ZOOM_RANGE;
    int32_t currentRangeId = WIDE_CAMERA_ZOOM_RANGE;
    int32_t waitCount = 4;
    int32_t zoomInOutCount = 2;
    std::vector<std::vector<float>> crossTime_2(waitCount, std::vector<float>(zoomInOutCount, 0.0f));
    fuzz_->GetCrossWaitTime(crossTime_2, targetRangeId, currentRangeId);
    targetRangeId = WIDE_CAMERA_ZOOM_RANGE;
    fuzz_->GetCrossWaitTime(crossTime_2, targetRangeId, currentRangeId);
    currentRangeId = MAIN_CAMERA_ZOOM_RANGE;
    fuzz_->GetCrossWaitTime(crossTime_2, targetRangeId, currentRangeId);
    targetRangeId = TELE_CAMERA_ZOOM_RANGE;
    fuzz_->GetCrossWaitTime(crossTime_2, targetRangeId, currentRangeId);
    currentRangeId = TWO_X_EXIT_TELE_ZOOM_RANGE;
    fuzz_->GetCrossWaitTime(crossTime_2, targetRangeId, currentRangeId);
    targetRangeId = WIDE_CAMERA_ZOOM_RANGE;
    fuzz_->GetCrossWaitTime(crossTime_2, targetRangeId, currentRangeId);
    targetRangeId = MAIN_CAMERA_ZOOM_RANGE;
    fuzz_->GetCrossWaitTime(crossTime_2, targetRangeId, currentRangeId);
    currentRangeId = TELE_CAMERA_ZOOM_RANGE;
    fuzz_->GetCrossWaitTime(crossTime_2, targetRangeId, currentRangeId);
    targetRangeId = WIDE_CAMERA_ZOOM_RANGE;
    fuzz_->GetCrossWaitTime(crossTime_2, targetRangeId, currentRangeId);
    targetRangeId = TWO_X_EXIT_TELE_ZOOM_RANGE;
    fuzz_->GetCrossWaitTime(crossTime_2, targetRangeId, currentRangeId);
    int32_t smoothZoomType = fdp.ConsumeIntegral<int32_t>();
    float targetZoomRatio = fdp.ConsumeFloatingPoint<float>();
    float duration = fdp.ConsumeFloatingPoint<float>();
    int32_t operationMode = fdp.ConsumeIntegral<int32_t>();
    fuzz_->SetSmoothZoom(smoothZoomType, operationMode, targetZoomRatio, duration);
    fuzz_->Start();
    std::shared_ptr<OHOS::Camera::CameraMetadata> captureSettings;
    captureSettings = std::make_shared<OHOS::Camera::CameraMetadata>(NUM_10, NUM_100);
    fuzz_->UpdateMuteSetting(true, captureSettings);
    fuzz_->Stop();
}

void HCaptureSessionFuzzer::HCaptureSessionFuzzTest4(FuzzedDataProvider& fdp)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = fdp.ConsumeIntegral<int32_t>();
    sptr<HCaptureSession> session;
    fuzz_ = std::make_shared<HCaptureSession>(callerToken, opMode);
    fuzz_->NewInstance(0, 0, session);
    CHECK_ERROR_RETURN_LOG(!fuzz_, "Create fuzz_ Error");
    pid_t pid = 0;
    fuzz_->DestroyStubObjectForPid(pid);
    sptr<ICaptureSessionCallback> callback;
    fuzz_->SetCallback(callback);
    fuzz_->GetSessionState();
    int32_t status = fdp.ConsumeIntegral<int32_t>();
    fuzz_->GetOutputStatus(status);
    int32_t imageSeqId = fdp.ConsumeIntegral<int32_t>();
    int32_t seqId = fdp.ConsumeIntegral<int32_t>();
    fuzz_->CreateBurstDisplayName(MAIN_CAMERA_ZOOM_RANGE, seqId);
    fuzz_->CreateBurstDisplayName(imageSeqId, seqId);
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