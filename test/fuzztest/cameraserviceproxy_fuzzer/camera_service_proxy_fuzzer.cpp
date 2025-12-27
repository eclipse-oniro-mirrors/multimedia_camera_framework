/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "camera_service_proxy_fuzzer.h"

#include <memory>
#include "camera_log.h"
#include "iconsumer_surface.h"

namespace OHOS {
namespace CameraStandard {
const size_t THRESHOLD = 10;
const int32_t MAX_BUFFER_SIZE = 16;
const int32_t NUM_1 = 1;
const int32_t NUM_10 = 10;
const int32_t NUM_100 = 100;
std::shared_ptr<CameraServiceProxy> CameraServiceProxyFuzz::fuzz_{nullptr};

void CameraServiceProxyFuzz::CameraServiceProxyTest1(FuzzedDataProvider &fdp)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr is nullptr");
    auto remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!remote, "remote is nullptr");
    fuzz_ = std::make_shared<CameraServiceProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ is nullptr");
    std::vector<std::string> bufferNames = {"cameraId1",
        "cameraId2", "cameraId3", "cameraId4", "cameraId5"};
    size_t ind = fdp.ConsumeIntegral<size_t>() % bufferNames.size();
    std::string cameraId = bufferNames[ind];
    sptr<ICameraDeviceService> device = nullptr;
    fuzz_->CreateCameraDevice(cameraId, device);
}

void CameraServiceProxyFuzz::CameraServiceProxyTest2(FuzzedDataProvider &fdp)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr is nullptr");
    auto remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!remote, "remote is nullptr");
    fuzz_ = std::make_shared<CameraServiceProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ is nullptr");
    sptr<ICameraServiceCallback> serviceCallback = new ICameraServiceCallbackFuzz();
    CHECK_RETURN_ELOG(!serviceCallback, "serviceCallback is nullptr");
    sptr<ITorchServiceCallback> torchCallback = new ITorchServiceCallbackFuzz();
    CHECK_RETURN_ELOG(!torchCallback, "torchCallback is nullptr");
    sptr<IFoldServiceCallback> foldCallback = new IFoldServiceCallbackFuzz();
    CHECK_RETURN_ELOG(!foldCallback, "foldCallback is nullptr");
    sptr<ICameraMuteServiceCallback> muteCallback = new ICameraMuteServiceCallbackFuzz();
    CHECK_RETURN_ELOG(!muteCallback, "muteCallback is nullptr");
    fuzz_->SetCameraCallback(serviceCallback);
    fuzz_->SetMuteCallback(muteCallback);
    fuzz_->SetTorchCallback(torchCallback);
    bool isInnerCallback = fdp.ConsumeBool();
    fuzz_->SetFoldStatusCallback(foldCallback, isInnerCallback);
    fuzz_->UnSetCameraCallback();
    fuzz_->UnSetMuteCallback();
    fuzz_->UnSetTorchCallback();
    fuzz_->UnSetFoldStatusCallback();

    serviceCallback = nullptr;
    torchCallback = nullptr;
    foldCallback = nullptr;
    muteCallback = nullptr;
    fuzz_->SetCameraCallback(serviceCallback);
    fuzz_->SetMuteCallback(muteCallback);
    fuzz_->SetTorchCallback(torchCallback);
    fuzz_->SetFoldStatusCallback(foldCallback, isInnerCallback);
}

void CameraServiceProxyFuzz::CameraServiceProxyTest3(FuzzedDataProvider &fdp)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr is nullptr");
    auto remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!remote, "remote is nullptr");
    fuzz_ = std::make_shared<CameraServiceProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ is nullptr");
    std::vector<std::string> cameraIds = {"cameraId1", "cameraId2", "cameraId3", "cameraId4", "cameraId5"};
    uint8_t vectorSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_BUFFER_SIZE);
    std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>> cameraAbilityList;
    for (int i = 0; i < vectorSize; ++i) {
        auto metadata = std::make_shared<OHOS::Camera::CameraMetadata>(NUM_10, NUM_100);
        cameraAbilityList.push_back(metadata);
    }
    fuzz_->GetCameras(cameraIds, cameraAbilityList);
}

void CameraServiceProxyFuzz::CameraServiceProxyTest4(FuzzedDataProvider &fdp)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr is nullptr");
    auto remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!remote, "remote is nullptr");
    fuzz_ = std::make_shared<CameraServiceProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ is nullptr");
    sptr<ICaptureSession> session = nullptr;
    int32_t operationMode = fdp.ConsumeIntegral<int32_t>();
    fuzz_->CreateCaptureSession(session, operationMode);
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    CHECK_RETURN_ELOG(!photoSurface, "photoSurface is nullptr");
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    CHECK_RETURN_ELOG(!producer, "producer is nullptr");
    int32_t format = fdp.ConsumeIntegral<int32_t>();
    int32_t width = fdp.ConsumeIntegral<int32_t>();
    int32_t height = fdp.ConsumeIntegral<int32_t>();
    sptr<IStreamCapture> photoOutput = nullptr;
    fuzz_->CreatePhotoOutput(producer, format, width, height, photoOutput);
    sptr<IStreamRepeat> previewOutput = nullptr;
    sptr<IStreamRepeat> videoOutput = nullptr;
    fuzz_->CreatePreviewOutput(producer, format, width, height, previewOutput);
    fuzz_->CreateDeferredPreviewOutput(format, width, height, previewOutput);
    fuzz_->CreateVideoOutput(producer, format, width, height, videoOutput);
}

void CameraServiceProxyFuzz::CameraServiceProxyTest5()
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr is nullptr");
    auto object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!object, "object is nullptr");
    fuzz_ = std::make_shared<CameraServiceProxy>(object);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ is nullptr");
    fuzz_->SetListenerObject(object);
}

void CameraServiceProxyFuzz::CameraServiceProxyTest6(FuzzedDataProvider &fdp)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr is nullptr");
    auto remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!remote, "remote is nullptr");
    fuzz_ = std::make_shared<CameraServiceProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ is nullptr");
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    CHECK_RETURN_ELOG(!photoSurface, "photoSurface is nullptr");
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    CHECK_RETURN_ELOG(!producer, "producer is nullptr");
    int32_t format = fdp.ConsumeIntegral<int32_t>();
    uint8_t vectorSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_BUFFER_SIZE);
    std::vector<int32_t> metadataTypes;
    for (int i = 0; i < vectorSize; ++i) {
        metadataTypes.push_back(fdp.ConsumeIntegral<int32_t>());
    }
    sptr<IStreamMetadata> metadataOutput = nullptr;
    fuzz_->CreateMetadataOutput(producer, format, metadataTypes, metadataOutput);
}

void CameraServiceProxyFuzz::CameraServiceProxyTest7(FuzzedDataProvider &fdp)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr is nullptr");
    auto remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!remote, "remote is nullptr");
    fuzz_ = std::make_shared<CameraServiceProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ is nullptr");
    bool muteMode = fdp.ConsumeBool();
    fuzz_->IsCameraMuteSupported(muteMode);
    bool isTorchSupported = fdp.ConsumeBool();
    fuzz_->IsTorchSupported(isTorchSupported);
    fuzz_->MuteCamera(muteMode);
    fuzz_->IsCameraMuted(muteMode);
    constexpr int32_t executionModeCount = static_cast<int32_t>(PolicyType::PRIVACY) + NUM_1;
    PolicyType policyType = static_cast<PolicyType>(fdp.ConsumeIntegral<uint8_t>() % executionModeCount);
    fuzz_->MuteCameraPersist(policyType, muteMode);
}

void CameraServiceProxyFuzz::CameraServiceProxyTest8(FuzzedDataProvider &fdp)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr is nullptr");
    auto remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!remote, "remote is nullptr");
    fuzz_ = std::make_shared<CameraServiceProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ is nullptr");
    int32_t flag = fdp.ConsumeIntegral<int32_t>();
    fuzz_->PrelaunchCamera(flag);
    fuzz_->ResetRssPriority();
}

void CameraServiceProxyFuzz::CameraServiceProxyTest9(FuzzedDataProvider &fdp)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr is nullptr");
    auto remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!remote, "remote is nullptr");
    fuzz_ = std::make_shared<CameraServiceProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ is nullptr");
    std::vector<std::string> bufferNames = {"cameraId1",
        "cameraId2", "cameraId3", "cameraId4", "cameraId5"};
    size_t ind = fdp.ConsumeIntegral<size_t>() % bufferNames.size();
    std::string cameraId = bufferNames[ind];
    constexpr int32_t executionModeCount =
        static_cast<int32_t>(RestoreParamTypeOhos::TRANSIENT_ACTIVE_PARAM_OHOS) + NUM_1;
    RestoreParamTypeOhos restoreParamType =
        static_cast<RestoreParamTypeOhos>(fdp.ConsumeIntegral<uint8_t>() % executionModeCount);
    int32_t activeTime = fdp.ConsumeIntegral<int32_t>();
    EffectParam effectParam;
    fuzz_->SetPrelaunchConfig(cameraId, restoreParamType, activeTime, effectParam);
    fuzz_->PreSwitchCamera(cameraId);
}

void CameraServiceProxyFuzz::CameraServiceProxyTest10(FuzzedDataProvider &fdp)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr is nullptr");
    auto remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!remote, "remote is nullptr");
    fuzz_ = std::make_shared<CameraServiceProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ is nullptr");
    float level =  fdp.ConsumeFloatingPoint<float>();
    fuzz_->SetTorchLevel(level);
}

void CameraServiceProxyFuzz::CameraServiceProxyTest11(FuzzedDataProvider &fdp)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr is nullptr");
    auto remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!remote, "remote is nullptr");
    fuzz_ = std::make_shared<CameraServiceProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ is nullptr");
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    sptr<IDeferredPhotoProcessingSessionCallback> callback = new IDeferredPhotoProcessingSessionCallbackFuzz();
    CHECK_RETURN_ELOG(!callback, "callback is nullptr");
    sptr<IDeferredPhotoProcessingSession> session = nullptr;
    fuzz_->CreateDeferredPhotoProcessingSession(userId, callback, session);
    sptr<IDeferredVideoProcessingSessionCallback> videoCallback = new DeferredVideoProcessingSessionCallback();
    CHECK_RETURN_ELOG(!videoCallback, "videoCallback is nullptr");
    sptr<IDeferredVideoProcessingSession> videoSession = nullptr;
    fuzz_->CreateDeferredVideoProcessingSession(userId, videoCallback, videoSession);
    callback = nullptr;
    videoCallback = nullptr;
    fuzz_->CreateDeferredPhotoProcessingSession(userId, callback, session);
    fuzz_->CreateDeferredVideoProcessingSession(userId, videoCallback, videoSession);
}

void CameraServiceProxyFuzz::CameraServiceProxyTest12(FuzzedDataProvider &fdp)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr is nullptr");
    auto remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!remote, "remote is nullptr");
    fuzz_ = std::make_shared<CameraServiceProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ is nullptr");
    std::vector<std::string> bufferNames = {"cameraId1",
        "cameraId2", "cameraId3", "cameraId4", "cameraId5"};
    size_t ind = fdp.ConsumeIntegral<size_t>() % bufferNames.size();
    std::string cameraId = bufferNames[ind];
    std::shared_ptr<CameraMetadata> cameraAbility = std::make_shared<OHOS::Camera::CameraMetadata>(NUM_10, NUM_100);
    fuzz_->GetCameraIds(bufferNames);
    fuzz_->GetCameraAbility(cameraId, cameraAbility);
    int32_t pid = fdp.ConsumeIntegral<int32_t>();
    int32_t status = fdp.ConsumeIntegral<int32_t>();
    fuzz_->GetCameraOutputStatus(pid, status);
    fuzz_->DestroyStubObj();
}

void CameraServiceProxyFuzz::CameraServiceProxyTest13(FuzzedDataProvider &fdp)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr is nullptr");
    auto remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!remote, "remote is nullptr");
    fuzz_ = std::make_shared<CameraServiceProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ is nullptr");
    std::set<int32_t> pidList = {
        fdp.ConsumeIntegralInRange<int32_t>(1, MAX_BUFFER_SIZE),
        fdp.ConsumeIntegralInRange<int32_t>(1, MAX_BUFFER_SIZE)
    };
    bool isProxy = fdp.ConsumeBool();
    fuzz_->ProxyForFreeze(pidList, isProxy);
    fuzz_->ResetAllFreezeStatus();
    std::vector<dmDeviceInfo> deviceInfos = {};
    fuzz_->GetDmDeviceInfo(deviceInfos);
}

void CameraServiceProxyFuzz::CameraServiceProxyTest14(FuzzedDataProvider &fdp)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr is nullptr");
    auto remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!remote, "remote is nullptr");
    fuzz_ = std::make_shared<CameraServiceProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ is nullptr");
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    CHECK_RETURN_ELOG(!photoSurface, "photoSurface is nullptr");
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    CHECK_RETURN_ELOG(!producer, "producer is nullptr");
    int32_t format = fdp.ConsumeIntegral<int32_t>();
    int32_t width = fdp.ConsumeIntegral<int32_t>();
    int32_t height = fdp.ConsumeIntegral<int32_t>();
    sptr<IStreamDepthData> depthDataOutput = nullptr;
    fuzz_->CreateDepthDataOutput(producer, format, width, height, depthDataOutput);
}

void CameraServiceProxyFuzz::CameraServiceProxyTest15(FuzzedDataProvider &fdp)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr is nullptr");
    auto remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!remote, "remote is nullptr");
    fuzz_ = std::make_shared<CameraServiceProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ is nullptr");
    int32_t memSize = fdp.ConsumeIntegral<int32_t>();
    fuzz_->RequireMemorySize(memSize);
    int32_t cameraPosition = fdp.ConsumeIntegral<int32_t>();
    std::vector<std::string> bufferNames = {"cameraId1",
        "cameraId2", "cameraId3", "cameraId4", "cameraId5"};
    size_t ind = fdp.ConsumeIntegral<size_t>() % bufferNames.size();
    std::string cameraId = bufferNames[ind];
    fuzz_->GetIdforCameraConcurrentType(cameraPosition, cameraId);
    std::shared_ptr<CameraMetadata> cameraAbility = std::make_shared<OHOS::Camera::CameraMetadata>(NUM_10, NUM_100);
    fuzz_->GetConcurrentCameraAbility(cameraId, cameraAbility);
    int32_t status = fdp.ConsumeIntegral<int32_t>();
    fuzz_->GetTorchStatus(status);
    int64_t size = fdp.ConsumeIntegral<int64_t>();
    fuzz_->GetCameraStorageSize(size);
}

void CameraServiceProxyFuzz::CameraServiceProxyTest16(FuzzedDataProvider &fdp)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr is nullptr");
    auto remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!remote, "remote is nullptr");
    fuzz_ = std::make_shared<CameraServiceProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ is nullptr");
    bool isInWhiteList = fdp.ConsumeBool();
    fuzz_->CheckWhiteList(isInWhiteList);
}

void CameraServiceProxyFuzz::CameraServiceProxyTest17(FuzzedDataProvider &fdp)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr is nullptr");
    auto remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!remote, "remote is nullptr");
    fuzz_ = std::make_shared<CameraServiceProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ is nullptr");
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    sptr<IMechSession> session = nullptr;
    fuzz_->CreateMechSession(userId, session);
    bool isMechSupported = fdp.ConsumeBool();
    fuzz_->IsMechSupported(isMechSupported);
}

void CameraServiceProxyFuzz::CameraServiceProxyTest18(FuzzedDataProvider &fdp)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr is nullptr");
    auto remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!remote, "remote is nullptr");
    fuzz_ = std::make_shared<CameraServiceProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ is nullptr");
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    sptr<IMechSession> session = nullptr;
    fuzz_->CreateMechSession(userId, session);
    bool isMechSupported = fdp.ConsumeBool();
    fuzz_->IsMechSupported(isMechSupported);
}

void CameraServiceProxyFuzz::CameraServiceProxyTest19()
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr is nullptr");
    auto remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!remote, "remote is nullptr");
    fuzz_ = std::make_shared<CameraServiceProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ is nullptr");
    sptr<ICaptureSession> session = nullptr;
    fuzz_->GetVideoSessionForControlCenter(session);
}

void CameraServiceProxyFuzz::CameraServiceProxyTest20()
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr is nullptr");
    auto remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!remote, "remote is nullptr");
    fuzz_ = std::make_shared<CameraServiceProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ is nullptr");
    sptr<IControlCenterStatusCallback> callback = new IControlCenterStatusCallbackFuzz();
    CHECK_RETURN_ELOG(!callback, "callback is nullptr");
    fuzz_->SetControlCenterCallback(callback);
    fuzz_->UnSetControlCenterStatusCallback();
    callback = nullptr;
    fuzz_->SetControlCenterCallback(callback);
}

void CameraServiceProxyFuzz::CameraServiceProxyTest21(FuzzedDataProvider &fdp)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr is nullptr");
    auto remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!remote, "remote is nullptr");
    fuzz_ = std::make_shared<CameraServiceProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ is nullptr");
    bool status = fdp.ConsumeBool();
    bool needPersistEnable = fdp.ConsumeBool();
    bool condition = fdp.ConsumeBool();
    fuzz_->EnableControlCenter(status, needPersistEnable);
    fuzz_->SetControlCenterPrecondition(condition);
    bool ability = fdp.ConsumeBool();
    fuzz_->SetDeviceControlCenterAbility(ability);
    fuzz_->GetControlCenterStatus(status);
    fuzz_->CheckControlCenterPermission();
}

void CameraServiceProxyFuzz::CameraServiceProxyTest22(FuzzedDataProvider &fdp)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr is nullptr");
    auto remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!remote, "remote is nullptr");
    fuzz_ = std::make_shared<CameraServiceProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ is nullptr");
    int32_t state = fdp.ConsumeIntegral<int32_t>();
    bool canOpenCamera = fdp.ConsumeBool();
    std::vector<std::string> bufferNames = {"cameraId1",
        "cameraId2", "cameraId3", "cameraId4", "cameraId5"};
    size_t ind = fdp.ConsumeIntegral<size_t>() % bufferNames.size();
    std::string cameraId = bufferNames[ind];
    fuzz_->AllowOpenByOHSide(cameraId, state, canOpenCamera);
    fuzz_->NotifyCameraState(cameraId, state);
}

void CameraServiceProxyFuzz::CameraServiceProxyTest23()
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr is nullptr");
    auto remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!remote, "remote is nullptr");
    fuzz_ = std::make_shared<CameraServiceProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ is nullptr");
    sptr<ICameraBroker> callback = new CameraBrokerFuzz();
    CHECK_RETURN_ELOG(!callback, "callback is nullptr");
    fuzz_->SetPeerCallback(callback);
    fuzz_->UnsetPeerCallback();
    callback = nullptr;
    fuzz_->SetPeerCallback(callback);
}

void FuzzTest(const uint8_t *rawData, size_t size)
{
    FuzzedDataProvider fdp(rawData, size);
    auto cameraServiceProxy = std::make_unique<CameraServiceProxyFuzz>();
    if (cameraServiceProxy == nullptr) {
        MEDIA_INFO_LOG("cameraServiceProxy is null");
        return;
    }
    cameraServiceProxy->CameraServiceProxyTest1(fdp);
    cameraServiceProxy->CameraServiceProxyTest2(fdp);
    cameraServiceProxy->CameraServiceProxyTest3(fdp);
    cameraServiceProxy->CameraServiceProxyTest4(fdp);
    cameraServiceProxy->CameraServiceProxyTest5();
    cameraServiceProxy->CameraServiceProxyTest6(fdp);
    cameraServiceProxy->CameraServiceProxyTest7(fdp);
    cameraServiceProxy->CameraServiceProxyTest8(fdp);
    cameraServiceProxy->CameraServiceProxyTest9(fdp);
    cameraServiceProxy->CameraServiceProxyTest10(fdp);
    cameraServiceProxy->CameraServiceProxyTest11(fdp);
    cameraServiceProxy->CameraServiceProxyTest12(fdp);
    cameraServiceProxy->CameraServiceProxyTest13(fdp);
    cameraServiceProxy->CameraServiceProxyTest14(fdp);
    cameraServiceProxy->CameraServiceProxyTest15(fdp);
    cameraServiceProxy->CameraServiceProxyTest16(fdp);
    cameraServiceProxy->CameraServiceProxyTest17(fdp);
    cameraServiceProxy->CameraServiceProxyTest18(fdp);
    cameraServiceProxy->CameraServiceProxyTest19();
    cameraServiceProxy->CameraServiceProxyTest20();
    cameraServiceProxy->CameraServiceProxyTest21(fdp);
    cameraServiceProxy->CameraServiceProxyTest22(fdp);
    cameraServiceProxy->CameraServiceProxyTest23();
}
}  // namespace CameraStandard
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    if (size < OHOS::CameraStandard::THRESHOLD) {
        return 0;
    }

    OHOS::CameraStandard::FuzzTest(data, size);
    return 0;
}