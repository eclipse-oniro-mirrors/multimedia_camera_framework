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
static constexpr int32_t MIN_SIZE_NUM = 256;
static constexpr int32_t NUM_1 = 1;
const int NUM_10 = 10;
const int NUM_100 = 100;
const size_t MAX_LENGTH_STRING = 64;

sptr<HCameraDevice> HCameraDeviceFuzzer::fuzz_{nullptr};


void HCameraDeviceFuzzer::HCameraDeviceFuzzTest1(FuzzedDataProvider& fdp)
{
    fuzz_->GetDeviceMuteMode();
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings;
    settings = std::make_shared<OHOS::Camera::CameraMetadata>(NUM_10, NUM_100);
    fuzz_->CreateMuteSetting(settings);
    fuzz_->DispatchDefaultSettingToHdi();
    fuzz_->CloneCachedSettings();
    uint64_t secureSeqId;
    fuzz_->callerToken_ = 1;
    fuzz_->GetSecureCameraSeq(&secureSeqId);
    std::vector<int32_t> results = {fdp.ConsumeIntegral<uint32_t>()};
    fuzz_->GetEnabledResults(results);
    fuzz_->CheckZoomChange(settings);
    fuzz_->ResetZoomTimer();
    fuzz_->UnPrepareZoom();
    fuzz_->UpdateSetting(settings);
    uint8_t value = fdp.ConsumeIntegral<uint8_t>();
    fuzz_->SetUsedAsPosition(value);
    fuzz_->GetUsedAsPosition();
    fuzz_->UpdateSettingOnce(settings);
    uint32_t tag = fdp.ConsumeIntegral<uint32_t>();
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

void HCameraDeviceFuzzer::HCameraDeviceFuzzTest2(FuzzedDataProvider& fdp)
{
    fuzz_->Close();
    fuzz_->CheckPermissionBeforeOpenDevice();
    fuzz_->HandlePrivacyBeforeOpenDevice();
    fuzz_->Release();
    fuzz_->OpenDevice(true);
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings;
    settings = std::make_shared<OHOS::Camera::CameraMetadata>(NUM_10, NUM_100);
    fuzz_->ReportMetadataDebugLog(settings);
    int32_t operationMode = fdp.ConsumeIntegral<int32_t>();
    std::set<std::string> conflicting = {fdp.ConsumeRandomLengthString(MAX_LENGTH_STRING),
        fdp.ConsumeRandomLengthString(MAX_LENGTH_STRING)};
    fuzz_->GetCameraResourceCost(operationMode, conflicting);
}

void HCameraDeviceFuzzer::HCameraDeviceFuzzTest3(FuzzedDataProvider& fdp)
{
    fuzz_->GetCameraId();
    fuzz_->GetCameraType();
    fuzz_->IsOpenedCameraDevice();
    bool isMoving = fdp.ConsumeIntegral<int32_t>() % 2;
    fuzz_->EnableMovingPhoto(isMoving);
    fuzz_->SetDeviceMuteMode(isMoving);
    fuzz_->ResetDeviceSettings();
    fuzz_->DispatchDefaultSettingToHdi();
    fuzz_->ResetCachedSettings();
    fuzz_->GetDeviceAbility();
    fuzz_->Open();
    uint64_t secureSeqId = fdp.ConsumeIntegral<int64_t>();
    fuzz_->OpenSecureCamera(secureSeqId);
    fuzz_->GetSecureCameraSeq(&secureSeqId);
    fuzz_->OpenDevice(isMoving);
    fuzz_->HandleFoldableDevice();
    fuzz_->CheckPermissionBeforeOpenDevice();
    fuzz_->HandlePrivacyBeforeOpenDevice();
    fuzz_->HandlePrivacyWhenOpenDeviceFail();
    fuzz_->HandlePrivacyAfterCloseDevice();
    fuzz_->OpenDevice(true);
    fuzz_->CloseDevice();
    int32_t mode = fdp.ConsumeIntegral<int32_t>();
    fuzz_->CheckMovingPhotoSupported(mode);
    fuzz_->ResetZoomTimer();
    int32_t DEFAULT_ITEMS = 3;
    int32_t DEFAULT_DATA_LENGTH = 200;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metaIn =
        std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    std::shared_ptr<OHOS::Camera::CameraMetadata> metaOut =
        std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    fuzz_->GetStatus(metaIn, metaOut);
    int32_t errorMsg = fdp.ConsumeIntegral<int32_t>();
    constexpr int32_t executionModeCount = static_cast<int32_t>(CAMERA_UNKNOWN_ERROR) + NUM_1;
    OHOS::HDI::Camera::V1_0::ErrorType selectedErrorType =
        static_cast<OHOS::HDI::Camera::V1_0::ErrorType>(fdp.ConsumeIntegral<uint8_t>() % executionModeCount);
    fuzz_->OnError(selectedErrorType, errorMsg);
    std::vector<uint8_t> result = {0, 1};
    uint64_t timestamp = fdp.ConsumeIntegral<uint64_t>();
    int32_t streamId = fdp.ConsumeIntegral<int32_t>();
    fuzz_->OnResult(timestamp, result);
    fuzz_->OnResult(streamId, result);
}

void HCameraDeviceFuzzer::HCameraDeviceFuzzTest4(FuzzedDataProvider& fdp)
{
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraResult;
    cameraResult = std::make_shared<OHOS::Camera::CameraMetadata>(NUM_10, NUM_100);
    std::function<void(int64_t, int64_t)> callback = [](int64_t start, int64_t end) {
        MEDIA_INFO_LOG("Start: %lld, End: %lld\n", start, end);
    };
    fuzz_->SetMovingPhotoStartTimeCallback(callback);
    fuzz_->SetMovingPhotoEndTimeCallback(callback);
    fuzz_->GetMovingPhotoStartAndEndTime(cameraResult);
    fuzz_->GetCallerToken();
    fuzz_->RemoveResourceWhenHostDied();
    int32_t state = fdp.ConsumeIntegral<int32_t>();
    fuzz_->NotifyCameraStatus(state);
}

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    auto dcameraDevice = std::make_unique<HCameraDeviceFuzzer>();
    if (dcameraDevice == nullptr) {
        MEDIA_INFO_LOG("dcameraDevice is null");
        return;
    }
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    sptr<HCameraHostManager> cameraHostManager = new HCameraHostManager(nullptr);
    std::string cameraId;
    uint32_t callingTokenId = fdp.ConsumeIntegral<uint32_t>();
    HCameraDeviceFuzzer::fuzz_ = new (std::nothrow)
        HCameraDevice(cameraHostManager, cameraId, callingTokenId);
    CHECK_RETURN_ELOG(!HCameraDeviceFuzzer::fuzz_, "CreateFuzz Error");
    dcameraDevice->HCameraDeviceFuzzTest1(fdp);
    dcameraDevice->HCameraDeviceFuzzTest2(fdp);
    dcameraDevice->HCameraDeviceFuzzTest3(fdp);
    dcameraDevice->HCameraDeviceFuzzTest4(fdp);
}

} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}