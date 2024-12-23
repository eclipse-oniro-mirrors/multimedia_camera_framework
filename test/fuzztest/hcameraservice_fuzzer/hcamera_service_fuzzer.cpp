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

#include "hcamera_service_fuzzer.h"
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
using namespace DeferredProcessing;
static constexpr int32_t MAX_CODE_LEN = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static const uint8_t* RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
static size_t g_dataSize = 0;
static size_t g_pos;
static size_t g_systemAbilityId = 1;
const int32_t NUM_1 = 1;
const int NUM = 1;
const int NUM_10 = 10;
const int NUM_100 = 100;
std::vector<std::string> cameraIds = {"cameraId"};
constexpr int32_t FLASHSTATUS_COUNT =
    static_cast<int32_t>(FlashStatus::FLASH_STATUS_UNAVAILABLE) + NUM_1;
constexpr int32_t CAMERASTATUS_COUNT =
    static_cast<int32_t>(CameraStatus::CAMERA_SERVER_UNAVAILABLE) + NUM_1;
constexpr int32_t TORCHSTATUS_COUNT =
    static_cast<int32_t>(TorchStatus::TORCH_STATUS_UNAVAILABLE) + NUM_1;
constexpr int32_t FOLDSTATUS_COUNT =
    static_cast<int32_t>(FoldStatus::HALF_FOLD) + NUM_1;
constexpr int32_t CALLBACKINVOKER_COUNT =
    static_cast<int32_t>(CallbackInvoker::APPLICATION);
constexpr int32_t POLICYTYPE_COUNT =
    static_cast<int32_t>(PolicyType::PRIVACY) + NUM_1;

HCameraService *HCameraServiceFuzzer::fuzz_ = nullptr;
HCameraService *HCameraServiceFuzzer::manager_ = nullptr;

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

void HCameraServiceFuzzer::HCameraServiceFuzzTest1()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    if (fuzz_ == nullptr) {
        bool runOnCreate = true;
        fuzz_ = new HCameraService(g_systemAbilityId, runOnCreate);
        sptr<HCameraHostManager> cameraHostManager = new HCameraHostManager(nullptr);
        manager_ = new HCameraService(cameraHostManager);
    }
    sptr<ICameraMuteServiceCallback> serviceCallback = nullptr;
    manager_->SetMuteCallback(serviceCallback);
    sptr<ICameraDeviceService> device = nullptr;
    manager_->CreateCameraDevice(cameraIds[0], device);
    sptr<ICaptureSession> session = nullptr;
    manager_->CreateCaptureSession(session, GetData<int32_t>());
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    sptr<IStreamCapture> photoOutput = nullptr;
    manager_->CreatePhotoOutput(producer, GetData<int32_t>(), GetData<int32_t>(),
        GetData<int32_t>(), photoOutput);
    sptr<IStreamRepeat> previewOutput = nullptr;
    manager_->CreateDeferredPreviewOutput(GetData<int32_t>(), GetData<int32_t>(),
        GetData<int32_t>(), previewOutput);
    manager_->CreatePreviewOutput(producer, GetData<int32_t>(), GetData<int32_t>(),
        GetData<int32_t>(), previewOutput);
    sptr<IStreamDepthData> depthDataOutput = nullptr;
    manager_->CreateDepthDataOutput(producer, GetData<int32_t>(), GetData<int32_t>(),
        GetData<int32_t>(), depthDataOutput);
    std::vector<int32_t> metadataTypes = { NUM_1 };
    IDeferredPhotoProcessingSessionCallbackFuzz callback;
    auto object = callback.AsObject();
    sptr<IStreamMetadata> metadataOutput = iface_cast<IStreamMetadata>(object);
    manager_->CreateMetadataOutput(producer, GetData<int32_t>(), metadataTypes,
        metadataOutput);
    manager_->CreateVideoOutput(producer, GetData<int32_t>(), GetData<int32_t>(),
        GetData<int32_t>(), previewOutput);
    CameraStatus selectedCameraStatus = static_cast<CameraStatus>(GetData<uint8_t>() % CAMERASTATUS_COUNT);
    CallbackInvoker selectedCallbackInvoker = static_cast<CallbackInvoker>(GetData<uint8_t>() % CALLBACKINVOKER_COUNT);
    manager_->OnCameraStatus(cameraIds[0], selectedCameraStatus, selectedCallbackInvoker);
    FlashStatus selectedFlashStatus = static_cast<FlashStatus>(GetData<uint8_t>() % FLASHSTATUS_COUNT);
    manager_->OnFlashlightStatus(cameraIds[0], selectedFlashStatus);
    manager_->OnMute(GetData<bool>());
    TorchStatus selectedTorchStatus = static_cast<TorchStatus>(GetData<uint8_t>() % TORCHSTATUS_COUNT);
    manager_->OnTorchStatus(selectedTorchStatus);
    OHOS::Rosen::FoldStatus selectedFoldStatus =
        static_cast<OHOS::Rosen::FoldStatus>(GetData<uint8_t>() % FOLDSTATUS_COUNT);
    manager_->OnFoldStatusChanged(selectedFoldStatus);
}

void HCameraServiceFuzzer::HCameraServiceFuzzTest2()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    uint8_t randomNum = GetData<uint8_t>();
    std::vector<std::string> testStrings = {"test1", "test2"};
    std::string deviceId(testStrings[randomNum % testStrings.size()]);
    manager_->OnStart();
    manager_->OnDump();
    manager_->OnStop();
    std::shared_ptr<OHOS::Camera::CameraMetadata> captureSettings;
    captureSettings = std::make_shared<OHOS::Camera::CameraMetadata>(NUM_10, NUM_100);
    vector<shared_ptr<OHOS::Camera::CameraMetadata>> cameraAbilityList = {
        captureSettings
    };
    manager_->GetCameras(cameraIds, cameraAbilityList);
    manager_->PrelaunchCamera();
    manager_->PreSwitchCamera(cameraIds[0]);
    manager_->OnAddSystemAbility(g_systemAbilityId, deviceId);
    manager_->IsCameraMuteSupported(cameraIds[0]);
    std::vector<std::u16string> args = {};
    manager_->Dump(NUM, args);
    bool canOpenCamera = GetData<bool>();
    int32_t state = GetData<int32_t>();
    manager_->AllowOpenByOHSide(cameraIds[0], state, canOpenCamera);
    manager_->NotifyCameraState(cameraIds[0], state);
    manager_->SetTorchLevel(GetData<float>());
    manager_->UnsetPeerCallback();
    pid_t pid = GetData<int32_t>();
    sptr<ICameraServiceCallback> callback = nullptr;
    manager_->SetCameraCallback(callback);
    sptr<ITorchServiceCallback> callback2 = nullptr;
    manager_->SetTorchCallback(callback2);
    sptr<IFoldServiceCallback> callback3 = nullptr;
    manager_->SetFoldStatusCallback(callback3, GetData<bool>());
    manager_->UnSetAllCallback(pid);
    manager_->CloseCameraForDestory(pid);
    PolicyType selectedPolicyType = static_cast<PolicyType>(GetData<uint8_t>() % POLICYTYPE_COUNT);
    manager_->MuteCameraPersist(selectedPolicyType, GetData<bool>());
    manager_->SetMuteModeFromDataShareHelper();
    manager_->OnRemoveSystemAbility(g_systemAbilityId, deviceId);
}

void Test()
{
    auto dcameraService = std::make_unique<HCameraServiceFuzzer>();
    if (dcameraService == nullptr) {
        MEDIA_INFO_LOG("dcameraService is null");
        return;
    }
    dcameraService->HCameraServiceFuzzTest1();
    dcameraService->HCameraServiceFuzzTest2();
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