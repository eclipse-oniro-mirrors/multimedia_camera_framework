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
#include "picture.h"
#include "camera_server_photo_proxy.h"
#include "camera_photo_proxy.h"

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t WIDE_CAMERA_ZOOM_RANGE = 0;
static constexpr int32_t MAIN_CAMERA_ZOOM_RANGE = 1;
static constexpr int32_t TWO_X_EXIT_TELE_ZOOM_RANGE = 2;
static constexpr int32_t TELE_CAMERA_ZOOM_RANGE = 3;
static constexpr int32_t MAX_CODE_LEN = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static const uint8_t* RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
const int NUM_10 = 10;
const int NUM_100 = 100;
static size_t g_dataSize = 0;
static size_t g_pos;

std::shared_ptr<HCaptureSession> HCaptureSessionFuzzer::fuzz_{nullptr};

/*
* describe: get data from outside untrusted data(g_data) which size is according to sizeof(T)
* tips: only support basic type
*/
template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (RAW_DATA == nullptr || objectSize > g_dataSize - g_pos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, RAW_DATA + g_pos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_pos += objectSize;
    return object;
}

template<class T>
uint32_t GetArrLength(T& arr)
{
    if (arr == nullptr) {
        MEDIA_INFO_LOG("%{public}s: The array length is equal to 0", __func__);
        return 0;
    }
    return sizeof(arr) / sizeof(arr[0]);
}

void HCaptureSessionFuzzer::HCaptureSessionFuzzTest1()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = GetData<int32_t>();
    sptr<HCaptureSession> session;
    if (fuzz_ == nullptr) {
        fuzz_ = std::make_shared<HCaptureSession>(callerToken, opMode);
        fuzz_->NewInstance(0, 0, session);
    }
    fuzz_->BeginConfig();
    fuzz_->CommitConfig();
    fuzz_->GetStreamByStreamID(GetData<int32_t>());
    int32_t captureId = GetData<int32_t>();
    fuzz_->StartMovingPhotoEncode(GetData<int32_t>(), GetData<int64_t>(), GetData<int32_t>(), captureId);
    fuzz_->StartRecord(GetData<int64_t>(), GetData<int32_t>(), captureId);
    fuzz_->GetHdiStreamByStreamID(GetData<int32_t>());
    int32_t featureMode = GetData<int32_t>();
    fuzz_->SetFeatureMode(featureMode);
    int outFd = GetData<int32_t>();
    CameraInfoDumper infoDumper(outFd);
    fuzz_->DumpSessionInfo(infoDumper);
    fuzz_->DumpSessions(infoDumper);
    fuzz_->DumpCameraSessionSummary(infoDumper);
    fuzz_->OperatePermissionCheck(GetData<uint32_t>());
    fuzz_->EnableMovingPhotoMirror(GetData<bool>(), GetData<bool>());
    ColorSpace getColorSpace;
    fuzz_->GetActiveColorSpace(getColorSpace);
    ColorSpace colorSpace = static_cast<ColorSpace>(callerToken % 23);
    ColorSpace captureColorSpace = static_cast<ColorSpace>(callerToken % 23);
    fuzz_->SetColorSpace(colorSpace, captureColorSpace, GetData<bool>());
    fuzz_->SetColorSpaceForStreams();
    fuzz_->CheckIfColorSpaceMatchesFormat(colorSpace);
    fuzz_->GetPid();
    fuzz_->GetopMode();
    std::vector<StreamInfo_V1_1> streamInfos;
    fuzz_->GetCurrentStreamInfos(streamInfos);
    fuzz_->DynamicConfigStream();
    fuzz_->AddInput(nullptr);
    sptr<HStreamCommon> stream = fuzz_->GetHdiStreamByStreamID(GetData<int32_t>());
    fuzz_->AddOutputStream(stream);
    fuzz_->StartMovingPhotoStream();
    std::string deviceClass;
    fuzz_->SetPreviewRotation(deviceClass);
}

void HCaptureSessionFuzzer::HCaptureSessionFuzzTest2()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = GetData<int32_t>();
    sptr<HCaptureSession> session;
    if (fuzz_ == nullptr) {
        fuzz_ = std::make_shared<HCaptureSession>(callerToken, opMode);
        fuzz_->NewInstance(0, 0, session);
    }
    StreamType streamType = StreamType::CAPTURE;
    fuzz_->AddOutput(streamType, nullptr);
    fuzz_->RemoveOutput(streamType, nullptr);
    fuzz_->RemoveInput(nullptr);
    std::vector<StreamInfo_V1_1> streamInfos;
    fuzz_->RemoveOutputStream(nullptr);
    int32_t width = GetData<int32_t>();
    int32_t height = GetData<int32_t>();
    int32_t streamId = GetData<int32_t>();
    sptr<OHOS::IBufferProducer> producer;
    int32_t format = GetData<int32_t>();
    fuzz_->CreateMovingPhotoStreamRepeat(format, width, height, producer);
    fuzz_->GetStreamByStreamID(streamId);
    fuzz_->GetHdiStreamByStreamID(streamId);
    fuzz_->ClearSketchRepeatStream();
    fuzz_->ClearMovingPhotoRepeatStream();
    fuzz_->StopMovingPhoto();
    fuzz_->ValidateSession();
    fuzz_->CancelStreamsAndGetStreamInfos(streamInfos);
    fuzz_->RestartStreams();
    fuzz_->UpdateStreamInfos();
    CaptureSessionState sessionState = CaptureSessionState::SESSION_STARTED;
    fuzz_->GetSessionState(sessionState);
    float currentFps = GetData<float>();
    float currentZoomRatio = GetData<float>();
    std::vector<float> crossZoomAndTime;
    int32_t operationMode = GetData<int32_t>();
    fuzz_->QueryFpsAndZoomRatio(currentFps, currentZoomRatio, crossZoomAndTime, operationMode);
    fuzz_->GetSensorOritation();
    fuzz_->GetMovingPhotoBufferDuration();
    float zoomRatio = GetData<float>();
    std::vector<float> crossZoom;
    fuzz_->GetRangeId(zoomRatio, crossZoom);
    float zoomPointA = GetData<float>();
    float zoomPointB = GetData<float>();
    fuzz_->isEqual(zoomPointA, zoomPointB);
    std::vector<std::vector<float>> crossTime_1;
    fuzz_->GetCrossZoomAndTime(crossZoomAndTime, crossZoom, crossTime_1);
}

void HCaptureSessionFuzzer::HCaptureSessionFuzzTest3()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = GetData<int32_t>();
    sptr<HCaptureSession> session;
    if (fuzz_ == nullptr) {
        fuzz_ = std::make_shared<HCaptureSession>(callerToken, opMode);
        fuzz_->NewInstance(0, 0, session);
    }
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
    int32_t smoothZoomType = GetData<int32_t>();
    float targetZoomRatio = GetData<float>();
    float duration = GetData<float>();
    int32_t operationMode = GetData<int32_t>();
    fuzz_->SetSmoothZoom(smoothZoomType, operationMode, targetZoomRatio, duration);
    fuzz_->Start();
    std::shared_ptr<OHOS::Camera::CameraMetadata> captureSettings;
    captureSettings = std::make_shared<OHOS::Camera::CameraMetadata>(NUM_10, NUM_100);
    fuzz_->UpdateMuteSetting(true, captureSettings);
    uint8_t usedAsPositionU8 = OHOS_CAMERA_POSITION_OTHER;
    camera_position_enum_t cameraPosition = static_cast<camera_position_enum_t>(usedAsPositionU8);
    fuzz_->StartPreviewStream(captureSettings, cameraPosition);
    fuzz_->Stop();
}

void HCaptureSessionFuzzer::HCaptureSessionFuzzTest4()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t opMode = GetData<int32_t>();
    sptr<HCaptureSession> session;
    if (fuzz_ == nullptr) {
        fuzz_ = std::make_shared<HCaptureSession>(callerToken, opMode);
        fuzz_->NewInstance(0, 0, session);
    }
    pid_t pid = 0;
    int64_t timestamp = GetData<int64_t>();
    fuzz_->DestroyStubObjectForPid(pid);
    sptr<ICaptureSessionCallback> callback;
    fuzz_->SetCallback(callback);
    fuzz_->GetSessionState();
    int32_t status = GetData<int32_t>();
    fuzz_->GetOutputStatus(status);
    int32_t imageSeqId = GetData<int32_t>();
    int32_t seqId = GetData<int32_t>();
    fuzz_->CreateBurstDisplayName(MAIN_CAMERA_ZOOM_RANGE, seqId);
    fuzz_->CreateBurstDisplayName(imageSeqId, seqId);
    std::string burstKey;
    bool isBursting = GetData<bool>();
    int32_t cameraShotType = GetData<int32_t>();
    sptr<CameraServerPhotoProxy> cameraPhotoProxy = new CameraServerPhotoProxy();
    fuzz_->SetCameraPhotoProxyInfo(cameraPhotoProxy, cameraShotType, isBursting, burstKey);
    sptr<CameraPhotoProxy> photoProxy = new CameraPhotoProxy();
    std::string uri;
    fuzz_->CreateMediaLibrary(photoProxy, uri, cameraShotType, burstKey, timestamp);
    fuzz_->CreateMediaLibrary(nullptr, photoProxy, uri, cameraShotType, burstKey, timestamp);
}

void Test()
{
    auto hcaptureSession = std::make_unique<HCaptureSessionFuzzer>();
    if (hcaptureSession == nullptr) {
        MEDIA_INFO_LOG("hcaptureSession is null");
        return;
    }
    hcaptureSession->HCaptureSessionFuzzTest1();
    hcaptureSession->HCaptureSessionFuzzTest2();
    hcaptureSession->HCaptureSessionFuzzTest3();
    hcaptureSession->HCaptureSessionFuzzTest4();
}

typedef void (*TestFuncs[1])();

TestFuncs g_testFuncs = {
    Test,
};

bool FuzzTest(const uint8_t* rawData, size_t size)
{
    // initialize data
    RAW_DATA = rawData;
    g_dataSize = size;
    g_pos = 0;

    uint32_t code = GetData<uint32_t>();
    uint32_t len = GetArrLength(g_testFuncs);
    if (len > 0) {
        g_testFuncs[code % len]();
    } else {
        MEDIA_INFO_LOG("%{public}s: The len length is equal to 0", __func__);
    }

    return true;
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    if (size < OHOS::CameraStandard::THRESHOLD) {
        return 0;
    }

    OHOS::CameraStandard::FuzzTest(data, size);
    return 0;
}