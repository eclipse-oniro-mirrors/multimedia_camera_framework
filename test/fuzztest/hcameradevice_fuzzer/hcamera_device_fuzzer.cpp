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

#include "hcamera_device_fuzzer.h"
#include "camera_log.h"
#include "message_parcel.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "accesstoken_kit.h"
#include "securec.h"

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_0;
static constexpr int32_t MAX_CODE_LEN = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static const uint8_t* RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
static size_t g_dataSize = 0;
static size_t g_pos;
const int NUM_10 = 10;
const int NUM_100 = 100;

HCameraDevice *HCameraDeviceFuzzer::fuzz_ = nullptr;

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

void HCameraDeviceFuzzer::HCameraDeviceFuzzTest1()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    sptr<HCameraHostManager> cameraHostManager = new HCameraHostManager(nullptr);
    if (fuzz_ == nullptr) {
        std::string cameraId;
        uint32_t callingTokenId = GetData<uint32_t>();
        fuzz_ = new HCameraDevice(cameraHostManager, cameraId, callingTokenId);
    }
    fuzz_->GetDeviceMuteMode();
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings;
    settings = std::make_shared<OHOS::Camera::CameraMetadata>(NUM_10, NUM_100);
    fuzz_->CreateMuteSetting(settings);
    fuzz_->DispatchDefaultSettingToHdi();
    fuzz_->CloneCachedSettings();
    uint64_t secureSeqId;
    fuzz_->callerToken_ = 1;
    fuzz_->GetSecureCameraSeq(&secureSeqId);
    std::vector<int32_t> results = {GetData<uint32_t>()};
    fuzz_->GetEnabledResults(results);
    fuzz_->CheckZoomChange(settings);
    fuzz_->ResetZoomTimer();
    fuzz_->UnPrepareZoom();
    fuzz_->UpdateSetting(settings);
    uint8_t value = GetData<uint32_t>();
    fuzz_->SetUsedAsPosition(value);
    fuzz_->GetUsedAsPosition();
    fuzz_->UpdateSettingOnce(settings);
    uint8_t randomNum = GetData<uint8_t>();
    std::vector<std::string> testStrings = {"test1", "test2"};
    std::string tagName(testStrings[randomNum % testStrings.size()]);
    std::string dfxUbStr(testStrings[randomNum % testStrings.size()]);
    uint32_t tag = GetData<uint32_t>();
    fuzz_->DebugLogTag(settings, tag, tagName, dfxUbStr);
    fuzz_->DebugLogForSmoothZoom(settings, tag);
    fuzz_->DebugLogForAfRegions(settings, tag);
    fuzz_->DebugLogForAeRegions(settings, tag);
    fuzz_->RegisterFoldStatusListener();
    fuzz_->UnRegisterFoldStatusListener();
    fuzz_->EnableResult(results);
    fuzz_->DisableResult(results);
    fuzz_->UpdateDeviceOpenLifeCycleSettings(settings);
    fuzz_->InitStreamOperator();
    fuzz_->ReleaseStreams(results);
    fuzz_->CheckOnResultData(settings);
}

void HCameraDeviceFuzzer::HCameraDeviceFuzzTest2()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    if (fuzz_ == nullptr) {
        std::string cameraId;
        const uint32_t callingTokenId = GetData<uint32_t>();
        sptr<HCameraHostManager> cameraHostManager = new HCameraHostManager(nullptr);
        fuzz_ = new HCameraDevice(cameraHostManager, cameraId, callingTokenId);
    }
    fuzz_->Close();
    fuzz_->CheckPermissionBeforeOpenDevice();
    fuzz_->HandlePrivacyBeforeOpenDevice();
    fuzz_->Release();
    std::vector<HDI::Camera::V1_1::StreamInfo_V1_1> streamInfos;
    fuzz_->CreateStreams(streamInfos);
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings;
    settings = std::make_shared<OHOS::Camera::CameraMetadata>(NUM_10, NUM_100);
    int32_t operationMode = GetData<int32_t>();
    fuzz_->CommitStreams(settings, operationMode);
    std::set<std::string> conflicting = {"fuzz1", "fuzz2"};
    fuzz_->UpdateStreams(streamInfos);
    const std::vector<int32_t> streamIds;
    int32_t captureId = GetData<int32_t>();
    fuzz_->OnCaptureStarted(captureId, streamIds);
    const std::vector<OHOS::HDI::Camera::V1_2::CaptureStartedInfo> infos;
    fuzz_->OnCaptureStarted_V1_2(captureId, infos);
    const std::vector<CaptureEndedInfo> infos_OnCaptureEnded;
    fuzz_->OnCaptureEnded(captureId, infos_OnCaptureEnded);
    const std::vector<OHOS::HDI::Camera::V1_3::CaptureEndedInfoExt> infos_OnCaptureEndedExt;
    fuzz_->OnCaptureEndedExt(captureId, infos_OnCaptureEndedExt);
    const std::vector<CaptureErrorInfo> infos_OnCaptureError;
    fuzz_->OnCaptureError(captureId, infos_OnCaptureError);
    std::vector<int32_t> results = {GetData<uint32_t>()};
    uint64_t timestamp = GetData<uint64_t>();
    fuzz_->OnFrameShutter(captureId, results, timestamp);
    fuzz_->OnFrameShutterEnd(captureId, results, timestamp);
    fuzz_->OnCaptureReady(captureId, results, timestamp);
}

void Test()
{
    auto dcameraDevice = std::make_unique<HCameraDeviceFuzzer>();
    if (dcameraDevice == nullptr) {
        MEDIA_INFO_LOG("dcameraDevice is null");
        return;
    }
    dcameraDevice->HCameraDeviceFuzzTest1();
    dcameraDevice->HCameraDeviceFuzzTest2();
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