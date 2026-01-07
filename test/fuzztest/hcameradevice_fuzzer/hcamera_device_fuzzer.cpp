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
#include <fuzzer/FuzzedDataProvider.h>
#include "fuzz_util.h"
#include "test_token.h"
#include "ipc_skeleton.h"

using namespace OHOS;
using namespace OHOS::CameraStandard;
using namespace OHOS::HDI::Camera::V1_0;
static constexpr int32_t NUM_1 = 1;
const int NUM_10 = 10;
const int NUM_100 = 100;
const size_t MAX_LENGTH_STRING = 64;

sptr<HCameraDevice> g_hCameraDevice;

void Open(FuzzedDataProvider& fdp)
{
    g_hCameraDevice->Open();
}

void Close(FuzzedDataProvider& fdp)
{
    g_hCameraDevice->Close();
}

void Release(FuzzedDataProvider& fdp)
{
    g_hCameraDevice->Release();
}

void SetCallback(FuzzedDataProvider& fdp)
{
    auto cb = sptr<MockCameraDeviceServiceCallback>::MakeSptr();
    g_hCameraDevice->SetCallback(cb);
}

void UpdateSetting(FuzzedDataProvider& fdp)
{
    auto settings =
        std::make_shared<CameraMetadata>(fdp.ConsumeIntegralInRange(0, NUM_10), fdp.ConsumeIntegralInRange(0, NUM_100));
    g_hCameraDevice->UpdateSetting(settings);
}

void GetEnabledResults(FuzzedDataProvider& fdp)
{
    std::vector<int32_t> res;
    g_hCameraDevice->GetEnabledResults(res);
}

void EnableResult(FuzzedDataProvider& fdp)
{
    g_hCameraDevice->EnableResult(ConsumeRandomVector<int32_t>(fdp));
}

void DisableResult(FuzzedDataProvider& fdp)
{
    g_hCameraDevice->DisableResult(ConsumeRandomVector<int32_t>(fdp));
}

void GetStatus(FuzzedDataProvider& fdp)
{
    auto metaIn =
        std::make_shared<CameraMetadata>(fdp.ConsumeIntegralInRange(0, NUM_10), fdp.ConsumeIntegralInRange(0, NUM_100));
    auto metaOut =
        std::make_shared<CameraMetadata>(fdp.ConsumeIntegralInRange(0, NUM_10), fdp.ConsumeIntegralInRange(0, NUM_100));
    g_hCameraDevice->GetStatus(metaIn, metaOut);
}

void SetUsedAsPosition(FuzzedDataProvider& fdp)
{
    g_hCameraDevice->SetUsedAsPosition(fdp.ConsumeIntegral<uint8_t>());
}

void CloseDelayed(FuzzedDataProvider& fdp)
{
    g_hCameraDevice->closeDelayed();
}

void UnSetCallback(FuzzedDataProvider& fdp)
{
    g_hCameraDevice->UnSetCallback();
}

void OpenOverride(FuzzedDataProvider& fdp)
{
    g_hCameraDevice->Open(fdp.ConsumeIntegral<int32_t>());
}

void SetDeviceRetryTime(FuzzedDataProvider& fdp)
{
    g_hCameraDevice->SetDeviceRetryTime();
}

void OpenSecureCamera(FuzzedDataProvider& fdp)
{
    uint64_t id;
    g_hCameraDevice->OpenSecureCamera(id);
}

void SetUsePhysicalCameraOrientation(FuzzedDataProvider& fdp)
{
    g_hCameraDevice->SetUsePhysicalCameraOrientation(fdp.ConsumeBool());
}

void GetNaturalDirectionCorrect(FuzzedDataProvider& fdp)
{
    bool correct;
    g_hCameraDevice->GetNaturalDirectionCorrect(correct);
}

void SetMdmCheck(FuzzedDataProvider& fdp)
{
    g_hCameraDevice->SetMdmCheck(fdp.ConsumeBool());
}

void HCameraDeviceFuzzTest1(FuzzedDataProvider& fdp)
{
    g_hCameraDevice->GetDeviceMuteMode();
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings;
    settings = std::make_shared<OHOS::Camera::CameraMetadata>(NUM_10, NUM_100);
    g_hCameraDevice->CreateMuteSetting(settings);
    g_hCameraDevice->DispatchDefaultSettingToHdi();
    g_hCameraDevice->CloneCachedSettings();
    uint64_t secureSeqId;
    g_hCameraDevice->callerToken_ = 1;
    g_hCameraDevice->GetSecureCameraSeq(&secureSeqId);
    std::vector<int32_t> results = { fdp.ConsumeIntegral<uint32_t>() };
    g_hCameraDevice->GetEnabledResults(results);
    g_hCameraDevice->CheckZoomChange(settings);
    g_hCameraDevice->ResetZoomTimer();
    g_hCameraDevice->UnPrepareZoom();
    g_hCameraDevice->UpdateSetting(settings);
    uint8_t value = fdp.ConsumeIntegral<uint8_t>();
    g_hCameraDevice->SetUsedAsPosition(value);
    g_hCameraDevice->GetUsedAsPosition();
    g_hCameraDevice->UpdateSettingOnce(settings);
    uint32_t tag = fdp.ConsumeIntegral<uint32_t>();
    g_hCameraDevice->DebugLogForSmoothZoom(settings, tag);
    g_hCameraDevice->DebugLogForAfRegions(settings, tag);
    g_hCameraDevice->DebugLogForAeRegions(settings, tag);
    g_hCameraDevice->RegisterFoldStatusListener();
    g_hCameraDevice->UnregisterFoldStatusListener();
    g_hCameraDevice->EnableResult(results);
    g_hCameraDevice->DisableResult(results);
    g_hCameraDevice->UpdateDeviceOpenLifeCycleSettings(settings);
    g_hCameraDevice->OpenDevice(true);
    g_hCameraDevice->CheckOnResultData(settings);
    g_hCameraDevice->ResetDeviceOpenLifeCycleSettings();
}

void HCameraDeviceFuzzTest2(FuzzedDataProvider& fdp)
{
    g_hCameraDevice->Close();
    g_hCameraDevice->CheckPermissionBeforeOpenDevice();
    g_hCameraDevice->HandlePrivacyBeforeOpenDevice();
    g_hCameraDevice->Release();
    g_hCameraDevice->OpenDevice(true);
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings;
    settings = std::make_shared<OHOS::Camera::CameraMetadata>(NUM_10, NUM_100);
    g_hCameraDevice->ReportMetadataDebugLog(settings);
    int32_t operationMode = fdp.ConsumeIntegral<int32_t>();
    std::set<std::string> conflicting = { fdp.ConsumeRandomLengthString(MAX_LENGTH_STRING),
        fdp.ConsumeRandomLengthString(MAX_LENGTH_STRING) };
    g_hCameraDevice->GetCameraResourceCost(operationMode, conflicting);
}

void HCameraDeviceFuzzTest3(FuzzedDataProvider& fdp)
{
    g_hCameraDevice->GetCameraId();
    g_hCameraDevice->GetCameraType();
    g_hCameraDevice->IsOpenedCameraDevice();
    bool isMoving = fdp.ConsumeIntegral<int32_t>() % 2;
#ifdef CAMERA_MOVING_PHOTO
    g_hCameraDevice->EnableMovingPhoto(isMoving);
#endif
    g_hCameraDevice->SetDeviceMuteMode(isMoving);
    g_hCameraDevice->ResetDeviceSettings();
    g_hCameraDevice->DispatchDefaultSettingToHdi();
    g_hCameraDevice->ResetCachedSettings();
    g_hCameraDevice->GetDeviceAbility();
    g_hCameraDevice->Open();
    uint64_t secureSeqId = fdp.ConsumeIntegral<int64_t>();
    g_hCameraDevice->OpenSecureCamera(secureSeqId);
    g_hCameraDevice->GetSecureCameraSeq(&secureSeqId);
    g_hCameraDevice->OpenDevice(isMoving);
    g_hCameraDevice->HandleFoldableDevice();
    g_hCameraDevice->CheckPermissionBeforeOpenDevice();
    g_hCameraDevice->HandlePrivacyBeforeOpenDevice();
    g_hCameraDevice->HandlePrivacyWhenOpenDeviceFail();
    g_hCameraDevice->HandlePrivacyAfterCloseDevice();
    g_hCameraDevice->OpenDevice(true);
    g_hCameraDevice->CloseDevice();
#ifdef CAMERA_MOVING_PHOTO
    int32_t mode = fdp.ConsumeIntegral<int32_t>();
    g_hCameraDevice->CheckMovingPhotoSupported(mode);
#endif
    g_hCameraDevice->ResetZoomTimer();
    int32_t DEFAULT_ITEMS = 3;
    int32_t DEFAULT_DATA_LENGTH = 200;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metaIn =
        std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    std::shared_ptr<OHOS::Camera::CameraMetadata> metaOut =
        std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    g_hCameraDevice->GetStatus(metaIn, metaOut);
    int32_t errorMsg = fdp.ConsumeIntegral<int32_t>();
    constexpr int32_t executionModeCount = static_cast<int32_t>(CAMERA_UNKNOWN_ERROR) + NUM_1;
    OHOS::HDI::Camera::V1_0::ErrorType selectedErrorType =
        static_cast<OHOS::HDI::Camera::V1_0::ErrorType>(fdp.ConsumeIntegral<uint8_t>() % executionModeCount);
    g_hCameraDevice->OnError(selectedErrorType, errorMsg);
    std::vector<uint8_t> result = { 0, 1 };
    uint64_t timestamp = fdp.ConsumeIntegral<uint64_t>();
    int32_t streamId = fdp.ConsumeIntegral<int32_t>();
    g_hCameraDevice->OnResult(timestamp, result);
    g_hCameraDevice->OnResult(streamId, result);
}

void HCameraDeviceFuzzTest4(FuzzedDataProvider& fdp)
{
#ifdef CAMERA_MOVING_PHOTO
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraResult;
    cameraResult = std::make_shared<OHOS::Camera::CameraMetadata>(NUM_10, NUM_100);
    std::function<void(int64_t, int64_t)> callback = [](int64_t start, int64_t end) {
        MEDIA_INFO_LOG("Start: %ld, End: %ld\n", start, end);
    };
    g_hCameraDevice->SetMovingPhotoStartTimeCallback(callback);
    g_hCameraDevice->SetMovingPhotoEndTimeCallback(callback);
    g_hCameraDevice->GetMovingPhotoStartAndEndTime(cameraResult);
#endif
    g_hCameraDevice->GetCallerToken();
    g_hCameraDevice->RemoveResourceWhenHostDied();
    int32_t state = fdp.ConsumeIntegral<int32_t>();
    g_hCameraDevice->NotifyCameraStatus(state);
}

void Init()
{
    CHECK_RETURN_ELOG(!TestToken().GetAllCameraPermission(), "Get permission fail");
    sptr<HCameraHostManager> cameraHostManager = new HCameraHostManager(nullptr);
    std::vector<std::string> cameraIds;
    cameraHostManager->GetCameras(cameraIds);
    CHECK_RETURN_ELOG(cameraIds.empty(), "GetCameras returns empty");
    std::string cameraId = cameraIds[0];
    auto callingTokenId = IPCSkeleton::GetCallingTokenID();
    g_hCameraDevice = new HCameraDevice(cameraHostManager, cameraId, callingTokenId);
}

void Test(FuzzedDataProvider& fdp)
{
    CHECK_RETURN_ELOG(g_hCameraDevice == nullptr, "g_hStreamMetadata is nullptr");
    auto func = fdp.PickValueInArray({
        Open,
        Close,
        Release,
        SetCallback,
        UpdateSetting,
        GetEnabledResults,
        EnableResult,
        DisableResult,
        GetStatus,
        SetUsedAsPosition,
        CloseDelayed,
        UnSetCallback,
        OpenOverride,
        SetDeviceRetryTime,
        OpenSecureCamera,
        SetUsePhysicalCameraOrientation,
        GetNaturalDirectionCorrect,
        SetMdmCheck,
        HCameraDeviceFuzzTest1,
        HCameraDeviceFuzzTest2,
        HCameraDeviceFuzzTest3,
        HCameraDeviceFuzzTest4,
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