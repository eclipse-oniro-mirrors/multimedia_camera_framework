/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "camera_manager_fuzzer.h"
#include "camera_manager.h"
#include "camera_log.h"
#include "input/camera_device.h"
#include "message_parcel.h"
#include <cstddef>
#include <cstdint>
#include <mutex>
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "accesstoken_kit.h"
#include "securec.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MAX_CODE_LEN  = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
const size_t THRESHOLD = 10;
sptr<CameraManager> manager = nullptr;
const int32_t NUM_10 = 10;
const int32_t NUM_100 = 100;
static const uint8_t* RAW_DATA = nullptr;
static size_t g_dataSize = 0;
static size_t g_pos;
std::shared_ptr<IDeferredPhotoProcSessionCallbackFuzz> photoSessionCallback =
    std::make_shared<IDeferredPhotoProcSessionCallbackFuzz>();
std::shared_ptr<IDeferredVideoProcSessionCallbackFuzz> videoSessionCallback =
    std::make_shared<IDeferredVideoProcSessionCallbackFuzz>();
std::shared_ptr<CameraManagerCallbackFuzz> managerCallback = std::make_shared<CameraManagerCallbackFuzz>();
std::shared_ptr<CameraMuteListenerFuzz> muteListenerCallback = std::make_shared<CameraMuteListenerFuzz>();
std::shared_ptr<FoldListenerFuzz> foldListenerCallback = std::make_shared<FoldListenerFuzz>();
std::shared_ptr<TorchListenerFuzz> torchListenerCallback = std::make_shared<TorchListenerFuzz>();

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

void CameraManagerFuzzer::CameraManagerFuzzTest1()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    if (manager == nullptr) {
        manager = CameraManager::GetInstance();
    }
    auto session = manager->CreateCaptureSession();
    manager->CreateCaptureSession(&session);
    int userId = GetData<int>();
    auto deferedPhotoSession = manager->CreateDeferredPhotoProcessingSession(userId, photoSessionCallback);
    manager->CreateDeferredPhotoProcessingSession(userId, photoSessionCallback, &deferedPhotoSession);
    auto deferedVideoSession = manager->CreateDeferredVideoProcessingSession(userId, videoSessionCallback);
    manager->CreateDeferredVideoProcessingSession(userId, videoSessionCallback, &deferedVideoSession);
    sptr<IBufferProducer> bufferProducer;
    auto photoOutput = manager->CreatePhotoOutput(bufferProducer);
    manager->CreatePhotoOutputWithoutProfile(bufferProducer, &photoOutput);
    sptr<Surface> surface;
    sptr<PreviewOutput> previewOutput;
    manager->CreatePreviewOutputWithoutProfile(surface, &previewOutput);
    sptr<IStreamRepeat> streamPtr;
    Profile profile;
    manager->CreatePreviewOutputStream(streamPtr, profile, bufferProducer);
    sptr<IStreamCapture> capture;
    manager->ValidCreateOutputStream(profile, bufferProducer);
    manager->CreatePreviewOutput(bufferProducer,  GetData<int32_t>());
    int32_t width = GetData<int32_t>();
    int32_t height = GetData<int32_t>();
    manager->CreateCustomPreviewOutput(surface, width, height);
    sptr<MetadataOutput> metadataOutput;
    std::vector<MetadataObjectType> metadataObjectTypes;
    manager->CreateMetadataOutput(metadataOutput, metadataObjectTypes);
    DepthProfile depthProfile;
    auto depthDataOutput = manager->CreateDepthDataOutput(depthProfile, bufferProducer);
    manager->CreateDepthDataOutput(depthProfile, bufferProducer, &depthDataOutput);
    manager->CreateVideoOutput(surface);
    manager->CreateVideoOutputStream(streamPtr, profile, bufferProducer);
    sptr<VideoOutput> videoOutput;
    manager->CreateVideoOutputWithoutProfile(surface, &videoOutput);
    manager->DestroyStubObj();
    manager->CameraServerDied(0);
    manager->SetCallback(managerCallback);
    manager->RegisterCameraMuteListener(muteListenerCallback);
    manager->RegisterTorchListener(torchListenerCallback);
    manager->RegisterFoldListener(foldListenerCallback);
}

void CameraManagerFuzzer::CameraManagerFuzzTest2()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    if (manager == nullptr) {
        manager = CameraManager::GetInstance();
    }
    std::string cameraId;
    manager->GetCameraDeviceFromId(cameraId);
    manager->GetCameras();
    int32_t testPid = GetData<int32_t>();
    int32_t status = GetData<int32_t>();
    manager->GetCameraOutputStatus(testPid, status);
    manager->foldScreenType_ = "test_type";
    manager->GetSupportedCameras();
    sptr<CameraInfo> info;
    manager->CreateCameraInput(info);
    manager->ReportEvent(cameraId);
    CameraPosition position = CameraPosition::CAMERA_POSITION_BACK;
    CameraType cameraType = CameraType::CAMERA_TYPE_DEFAULT;
    auto input = manager->CreateCameraInput(position, cameraType);
    manager->CreateCameraInput(position, cameraType, &input);
    CameraManager::ProfilesWrapper profilesWrapper = {};
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(NUM_10, NUM_100);
    camera_metadata_item_t item;
    manager->ParseBasicCapability(profilesWrapper, metadata, item);
    int32_t modeName = SceneMode::VIDEO;
    manager->ParseExtendCapability(profilesWrapper, modeName, item);
    modeName = SceneMode::NORMAL;
    manager->ParseExtendCapability(profilesWrapper, modeName, item);
    sptr<ICameraServiceCallback> cameraServiceCallback;
    manager->SetCameraServiceCallback(cameraServiceCallback);
    CameraFormat cameraFormat = CameraFormat::CAMERA_FORMAT_JPEG;
    manager->GetCameraMetadataFormat(cameraFormat);
}

void CameraManagerFuzzer::CameraManagerFuzzTest3()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    if (manager == nullptr) {
        manager = CameraManager::GetInstance();
    }
    ITorchServiceCallbackFuzz torchServiceCallback;
    TorchStatus torchStatus = TorchStatus::TORCH_STATUS_ON;
    torchServiceCallback.OnTorchStatusChange(torchStatus);
    IFoldServiceCallbackFuzz foldServiceCallback;
    FoldStatus foldStatus = FoldStatus::EXPAND;
    foldServiceCallback.OnFoldStatusChanged(foldStatus);
    sptr<ITorchServiceCallback> torchCallback = new ITorchServiceCallbackFuzz();
    manager->SetTorchServiceCallback(torchCallback);
    sptr<IFoldServiceCallback> serviceCallback = new IFoldServiceCallbackFuzz();
    manager->SetFoldServiceCallback(serviceCallback);
    ICameraMuteServiceCallbackFuzz cameraMuteServiceCallback;
    cameraMuteServiceCallback.OnCameraMute(GetData<bool>());
    manager->IsCameraMuteSupported();
    manager->IsCameraMuted();
    manager->PrelaunchCamera();
    manager->IsTorchSupported();
    TorchMode mode = TorchMode::TORCH_MODE_ON;
    manager->SetTorchMode(mode);
    mode = TorchMode::TORCH_MODE_OFF;
    manager->SetTorchMode(mode);
    mode = TorchMode::TORCH_MODE_AUTO;
    manager->SetTorchMode(mode);
    manager->UpdateTorchMode(mode);
    manager->GetTorchMode();
    manager->SetCameraManagerNull();
}

void Test()
{
    auto cameraManager = std::make_unique<CameraManagerFuzzer>();
    if (cameraManager == nullptr) {
        MEDIA_INFO_LOG("cameraManager is null");
        return;
    }
    cameraManager->CameraManagerFuzzTest1();
    cameraManager->CameraManagerFuzzTest2();
    cameraManager->CameraManagerFuzzTest3();
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