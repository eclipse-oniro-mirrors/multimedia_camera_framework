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
#include "metadata_utils.h"

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_0;
static constexpr int32_t MAX_CODE_LEN = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static constexpr int32_t NUM_1 = 1;
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
    uint8_t value = GetData<uint8_t>();
    fuzz_->SetUsedAsPosition(value);
    fuzz_->GetUsedAsPosition();
    fuzz_->UpdateSettingOnce(settings);
    uint32_t tag = GetData<uint32_t>();
    fuzz_->DebugLogForSmoothZoom(settings, tag);
    fuzz_->DebugLogForAfRegions(settings, tag);
    fuzz_->DebugLogForAeRegions(settings, tag);
    fuzz_->RegisterFoldStatusListener();
    fuzz_->UnregisterFoldStatusListener();
    fuzz_->EnableResult(results);
    fuzz_->DisableResult(results);
    fuzz_->UpdateDeviceOpenLifeCycleSettings(settings);
    fuzz_->OpenDevice(true);
    fuzz_->CheckOnResultData(settings);
    fuzz_->ResetDeviceOpenLifeCycleSettings();
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
    fuzz_->OpenDevice(true);
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings;
    settings = std::make_shared<OHOS::Camera::CameraMetadata>(NUM_10, NUM_100);
    fuzz_->ReportMetadataDebugLog(settings);
    int32_t operationMode = GetData<int32_t>();
    std::set<std::string> conflicting = {"fuzz1", "fuzz2"};
    fuzz_->GetCameraResourceCost(operationMode, conflicting);
}

void HCameraDeviceFuzzer::HCameraDeviceFuzzTest3()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    std::string cameraId;
    const uint32_t callingTokenId = GetData<uint32_t>();
    sptr<HCameraHostManager> cameraHostManager = new HCameraHostManager(nullptr);
    if (fuzz_ == nullptr) {
        fuzz_ = new HCameraDevice(cameraHostManager, cameraId, callingTokenId);
    }
    fuzz_->GetCameraId();
    fuzz_->GetCameraType();
    fuzz_->IsOpenedCameraDevice();
    bool isMoving = GetData<int32_t>() % 2;
    fuzz_->EnableMovingPhoto(isMoving);
    fuzz_->SetDeviceMuteMode(isMoving);
    fuzz_->ResetDeviceSettings();
    fuzz_->DispatchDefaultSettingToHdi();
    fuzz_->ResetCachedSettings();
    fuzz_->GetDeviceAbility();
    fuzz_->Open();
    uint64_t secureSeqId = GetData<uint64_t>();
    fuzz_->OpenSecureCamera(&secureSeqId);
    fuzz_->GetSecureCameraSeq(&secureSeqId);
    fuzz_->OpenDevice(isMoving);
    fuzz_->HandleFoldableDevice();
    fuzz_->CheckPermissionBeforeOpenDevice();
    fuzz_->HandlePrivacyBeforeOpenDevice();
    fuzz_->HandlePrivacyWhenOpenDeviceFail();
    fuzz_->HandlePrivacyAfterCloseDevice();
    fuzz_->OpenDevice(true);
    fuzz_->CloseDevice();
    int32_t mode = GetData<int32_t>();
    fuzz_->CheckMovingPhotoSupported(mode);
    fuzz_->ResetZoomTimer();
    std::shared_ptr<OHOS::Camera::CameraMetadata> metaIn = nullptr;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metaOut = nullptr;
    fuzz_->GetStatus(metaIn, metaOut);
    int32_t errorMsg = GetData<int32_t>();
    constexpr int32_t executionModeCount = static_cast<int32_t>(CAMERA_UNKNOWN_ERROR) + NUM_1;
    OHOS::HDI::Camera::V1_0::ErrorType selectedErrorType =
        static_cast<OHOS::HDI::Camera::V1_0::ErrorType>(GetData<uint8_t>() % executionModeCount);
    fuzz_->OnError(selectedErrorType, errorMsg);
    std::vector<uint8_t> result = {0, 1};
    uint64_t timestamp = GetData<uint64_t>();
    int32_t streamId = GetData<int32_t>();
    fuzz_->OnResult(timestamp, result);
    fuzz_->OnResult(streamId, result);
}

void HCameraDeviceFuzzer::HCameraDeviceFuzzTest4()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    std::string cameraId;
    uint32_t callingTokenId = GetData<uint32_t>();
    sptr<HCameraHostManager> cameraHostManager = new HCameraHostManager(nullptr);
    if (fuzz_ == nullptr) {
        fuzz_ = new HCameraDevice(cameraHostManager, cameraId, callingTokenId);
    }
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraResult;
    cameraResult = std::make_shared<OHOS::Camera::CameraMetadata>(NUM_10, NUM_100);
    std::function<void(int64_t, int64_t)> callback = [](int64_t start, int64_t end) {
        MEDIA_INFO_LOG("Start: %ld, End: %ld\n", start, end);
    };
    fuzz_->SetMovingPhotoStartTimeCallback(callback);
    fuzz_->SetMovingPhotoEndTimeCallback(callback);
    fuzz_->GetMovingPhotoStartAndEndTime(cameraResult);
    fuzz_->GetCallerToken();
    bool running = GetData<bool>();
    fuzz_->NotifyCameraSessionStatus(running);
    fuzz_->RemoveResourceWhenHostDied();
    int32_t state = GetData<int32_t>();
    fuzz_->NotifyCameraStatus(state);
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
    dcameraDevice->HCameraDeviceFuzzTest3();
    dcameraDevice->HCameraDeviceFuzzTest4();
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