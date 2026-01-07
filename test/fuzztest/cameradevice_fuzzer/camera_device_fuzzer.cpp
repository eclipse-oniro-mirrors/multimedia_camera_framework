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

#include "camera_device_fuzzer.h"
#include "camera_log.h"
#include "camera_xcollie.h"
#include "camera_dynamic_loader.h"
#include "input/camera_manager.h"
#include "metadata_utils.h"
#include "ipc_skeleton.h"
#include "access_token.h"
#include "hap_token_info.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include <fuzzer/FuzzedDataProvider.h>
#include "test_token.h"

using namespace std;

namespace OHOS {
namespace CameraStandard {
const std::u16string FORMMGR_INTERFACE_TOKEN = u"ICameraDeviceService";
const int32_t MIN_SIZE_NUM = 256;
const int32_t NUM_10 = 10;
const int32_t NUM_100 = 100;
const int32_t MAX_BUFFER_SIZE = 16;
const int32_t MAX_STRING_LEN_SIZE = 4;
sptr<HCameraDevice> fuzzCameraDevice = nullptr;

void PrepareHCameraDevice()
{
    if (fuzzCameraDevice == nullptr) {
        sptr<HCameraHostManager> cameraHostManager = new HCameraHostManager(nullptr);
        std::vector<std::string> cameraIds;
        cameraHostManager->GetCameras(cameraIds);
        if (cameraIds.empty()) {
            MEDIA_ERR_LOG("Fuzz:PrepareHCameraDevice: GetCameras returns empty");
            return;
        }
        string cameraID = cameraIds[0];
        auto callingTokenId = IPCSkeleton::GetCallingTokenID();
        MEDIA_INFO_LOG("Fuzz:PrepareHCameraDevice: callingTokenId = %{public}d", callingTokenId);
        string permissionName = OHOS_PERMISSION_CAMERA;
        int32_t ret = CheckPermission(permissionName, callingTokenId);
        if (ret != CAMERA_OK) {
            MEDIA_ERR_LOG("Fuzz:PrepareHCameraDevice: CheckPermission Failed");
            return;
        }
        fuzzCameraDevice = new HCameraDevice(cameraHostManager, cameraID, callingTokenId);
        MEDIA_INFO_LOG("Fuzz:PrepareHCameraDevice: Success");
    }
}

void CameraDeviceFuzzTest(FuzzedDataProvider& fdp)
{
    int32_t itemCount = NUM_10;
    int32_t dataSize = NUM_100;
    uint8_t streamSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_BUFFER_SIZE);
    std::vector<int32_t> streamData;
    for (int i = 0; i < streamSize; ++i) {
        streamData.push_back(fdp.ConsumeIntegral<int32_t>());
    }
    std::shared_ptr<OHOS::Camera::CameraMetadata> ability;
    ability = std::make_shared<OHOS::Camera::CameraMetadata>(itemCount, dataSize);

    ability->addEntry(OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS,
        streamData.data(), streamData.size());

    {
        int32_t compensationRange[2] = {fdp.ConsumeIntegral<int32_t>(),
            fdp.ConsumeIntegral<int32_t>()};
        ability->addEntry(OHOS_CONTROL_AE_COMPENSATION_RANGE, compensationRange,
            sizeof(compensationRange) / sizeof(compensationRange[0]));
    }

    {
        float focalLength = fdp.ConsumeFloatingPoint<float>();
        ability->addEntry(OHOS_ABILITY_FOCAL_LENGTH, &focalLength, 1);
    }

    {
        int32_t sensorOrientation = fdp.ConsumeIntegral<int32_t>();
        ability->addEntry(OHOS_SENSOR_ORIENTATION, &sensorOrientation, 1);
    }

    {
        uint8_t cameraPosition = fdp.ConsumeIntegral<uint8_t>();
        ability->addEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, 1);
    }

    {
        uint64_t aeCompensationStep = fdp.ConsumeIntegral<uint64_t>();
        ability->addEntry(OHOS_CONTROL_AE_COMPENSATION_STEP, &aeCompensationStep, 1);
    }

    MessageParcel dataParcel;
    dataParcel.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    CHECK_RETURN_ELOG(!(OHOS::Camera::MetadataUtils::EncodeCameraMetadata(ability, dataParcel)),
        "CameraDeviceFuzzer: EncodeCameraMetadata Error");
    dataParcel.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    PrepareHCameraDevice();
    if (fuzzCameraDevice) {
        uint32_t code = 4;
        fuzzCameraDevice->OnRemoteRequest(code, dataParcel, reply, option);
    }
}

void CameraDeviceFuzzTestUpdateSetting(FuzzedDataProvider& fdp)
{
    int32_t itemCount = NUM_10;
    int32_t dataSize = NUM_100;
    uint8_t streamSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_BUFFER_SIZE);
    std::vector<uint8_t> streamData = fdp.ConsumeBytes<uint8_t>(streamSize);
    auto ability = std::make_shared<OHOS::Camera::CameraMetadata>(itemCount, dataSize);
    
    {
        int32_t compensationRange[2] = {fdp.ConsumeIntegral<int32_t>(),
            fdp.ConsumeIntegral<int32_t>()};
        ability->addEntry(OHOS_CONTROL_AE_COMPENSATION_RANGE, compensationRange,
            sizeof(compensationRange) / sizeof(compensationRange[0]));
    }

    {
        int32_t focalLength = fdp.ConsumeIntegral<int32_t>();
        ability->addEntry(OHOS_SENSOR_ORIENTATION, &focalLength, 1);
    }

    {
        uint8_t sensorOrientation = fdp.ConsumeIntegral<uint8_t>();
        ability->addEntry(OHOS_ABILITY_CAMERA_POSITION, &sensorOrientation, 1);
    }

    {
        uint64_t cameraPosition = fdp.ConsumeIntegral<uint64_t>();
        ability->addEntry(OHOS_CONTROL_AE_COMPENSATION_STEP, &cameraPosition, 1);
    }

    if (fuzzCameraDevice) {
        fuzzCameraDevice->UpdateSettingOnce(ability);
        fuzzCameraDevice->UpdateSetting(ability);
        auto out = std::make_shared<OHOS::Camera::CameraMetadata>(itemCount, dataSize);
        fuzzCameraDevice->GetStatus(ability, out);
        vector<uint8_t> result;
        OHOS::Camera::MetadataUtils::ConvertMetadataToVec(ability, result);
        fuzzCameraDevice->OnResult(fdp.ConsumeIntegral<uint64_t>(), result);
        auto type = OHOS::HDI::Camera::V1_0::ErrorType::REQUEST_TIMEOUT;
        fuzzCameraDevice->OnError(type, fdp.ConsumeIntegral<int32_t>());
    }
}

void CameraDeviceFuzzTest2Case1()
{
    if (fuzzCameraDevice) {
        fuzzCameraDevice->GetStreamOperatorCallback();
        fuzzCameraDevice->GetCallerToken();
        fuzzCameraDevice->GetDeviceAbility();
        fuzzCameraDevice->GetCameraType();
        fuzzCameraDevice->GetCameraId();
    }
}

void CameraDeviceFuzzTest2Case2(FuzzedDataProvider& fdp)
{
    // 运行会出错
    sptr<ICameraDeviceServiceCallback> callback(new ICameraDeviceServiceCallbackMock());
    fuzzCameraDevice->SetCallback(callback);
    wptr<IStreamOperatorCallback> opCallback(new IStreamOperatorCallbackMock());
    fuzzCameraDevice->SetStreamOperatorCallback(opCallback);
    vector<int32_t> results{fdp.ConsumeIntegral<int32_t>()};
    fuzzCameraDevice->EnableResult(results);
    fuzzCameraDevice->DisableResult(results);
    fuzzCameraDevice->CloneCachedSettings();
    fuzzCameraDevice->DispatchDefaultSettingToHdi();
    fuzzCameraDevice->Release();
    fuzzCameraDevice->Close();
    uint64_t secureSeqId;
    fuzzCameraDevice->GetSecureCameraSeq(&secureSeqId);
    fuzzCameraDevice->OpenSecureCamera(secureSeqId);
}

void CameraDeviceFuzzTest2(FuzzedDataProvider& fdp)
{
    if (fuzzCameraDevice) {
        fuzzCameraDevice->OperatePermissionCheck(fdp.ConsumeIntegral<uint32_t>());
        fuzzCameraDevice->Open();
#ifdef CAMERA_MOVING_PHOTO
        fuzzCameraDevice->CheckMovingPhotoSupported(fdp.ConsumeIntegral<int32_t>());
#endif
        fuzzCameraDevice->NotifyCameraStatus(fdp.ConsumeIntegral<int32_t>());
        fuzzCameraDevice->RemoveResourceWhenHostDied();
        CameraDeviceFuzzTest2Case1();
        fuzzCameraDevice->ResetDeviceSettings();
        fuzzCameraDevice->SetDeviceMuteMode(fdp.ConsumeBool());
        fuzzCameraDevice->IsOpenedCameraDevice();
        fuzzCameraDevice->CloseDevice();
    }
}

void Test3(FuzzedDataProvider& fdp)
{
    auto manager = CameraManager::GetInstance();
    auto cameras = manager->GetSupportedCameras();
    CHECK_RETURN_ELOG(cameras.size() < MIN_SIZE_NUM, "PhotoOutputFuzzer: GetSupportedCameras Error");
    sptr<CameraDevice> camera = cameras[fdp.ConsumeIntegral<uint32_t>() % cameras.size()];
    camera->GetID();
    camera->GetMetadata();
    camera->ResetMetadata();
    camera->GetCameraAbility();
    camera->GetPosition();
    camera->GetCameraType();
    camera->GetConnectionType();
    camera->GetCameraFoldScreenType();
    camera->GetHostName();
    camera->GetDeviceType();
    camera->GetNetWorkId();
    camera->GetCameraOrientation();
    camera->GetExposureBiasRange();
    camera->GetModuleType();
    camera->GetUsedAsPosition();
    CameraFormat format = static_cast<CameraFormat>(fdp.ConsumeIntegral<int32_t>());
    auto capability = manager->GetSupportedOutputCapability(camera);
    CHECK_RETURN_ELOG(!capability, "PhotoOutputFuzzer: GetSupportedOutputCapability Error");
    vector<Profile> profiles = capability->GetPhotoProfiles();
    camera->GetMaxSizeProfile(profiles, fdp.ConsumeFloatingPoint<float>(), format);
    auto profiles2 = capability->GetVideoProfiles();
    camera->GetMaxSizeProfile(profiles2, fdp.ConsumeFloatingPoint<float>(), format);
    camera->SetProfile(capability);
    auto modeName = fdp.ConsumeIntegral<int32_t>();
    camera->SetProfile(capability, modeName);
    camera->SetCameraDeviceUsedAsPosition(CameraPosition::CAMERA_POSITION_FRONT);
    camera->GetSupportedFoldStatus();
    auto randomNum = fdp.ConsumeIntegral<uint32_t>();
    std::vector<std::string> testStrings = {"cameraid1", "cameraid2"};
    std::string cameraID(testStrings[randomNum % testStrings.size()]);
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(NUM_10, NUM_100);
    std::shared_ptr<CameraDevice> cameraDevice =
        std::make_shared<CameraDevice>(cameraID, metadata);
}

void TestXCollie(FuzzedDataProvider& fdp)
{
    string tag = fdp.ConsumeRandomLengthString(MAX_STRING_LEN_SIZE);
    uint32_t flag = fdp.ConsumeIntegral<int32_t>();
    uint32_t timeoutSeconds = fdp.ConsumeIntegral<uint32_t>();
    auto func = [](void*) {};
#ifndef HICOLLIE_ENABLE
#define HICOLLIE_ENABLE
#endif
    {
        CameraXCollie collie(tag, flag, timeoutSeconds, func, nullptr);
        collie.CancelCameraXCollie();
    }
#undef HICOLLIE_ENABLE
    {
        CameraXCollie collie(tag, flag, timeoutSeconds, func, nullptr);
        collie.CancelCameraXCollie();
    }
}

void TestDynamicLoader(FuzzedDataProvider& fdp)
{
    string libName = fdp.ConsumeRandomLengthString(MAX_STRING_LEN_SIZE);
    CameraDynamicLoader::GetDynamiclib(libName);
    CameraDynamicLoader::LoadDynamiclibAsync(libName);
    CameraDynamicLoader::FreeDynamicLibDelayed(libName);
}

void TestCameraDeviceServiceCallback(FuzzedDataProvider& fdp)
{
    auto meta = make_shared<OHOS::Camera::CameraMetadata>(10, 100);
    int val = 1;
    AddOrUpdateMetadata(meta, OHOS_STATUS_CAMERA_OCCLUSION_DETECTION, &val, 1);

    CameraDeviceServiceCallback callback;
    callback.OnError(fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>());
    callback.OnResult(fdp.ConsumeIntegral<uint64_t>(), meta);

    auto manager = CameraManager::GetInstance();
    auto cameras = manager->GetSupportedCameras();
    auto input = manager->CreateCameraInput(cameras[0]);
    class ErrorCallbackMock : public ErrorCallback {
    public:
        void OnError(const int32_t errorType, const int32_t errorMsg) const override {}
    };
    input->SetErrorCallback(make_shared<ErrorCallbackMock>());
    class ResultCallbackMock : public ResultCallback {
    public:
        void OnResult(const uint64_t timestamp,
            const std::shared_ptr<OHOS::Camera::CameraMetadata> &result) const override {}
    };
    input->SetResultCallback(make_shared<ResultCallbackMock>());
    class CameraOcclusionDetectCallbackMock : public CameraOcclusionDetectCallback {
    public:
        void OnCameraOcclusionDetected(const uint8_t isCameraOcclusion,
            const uint8_t isCameraLensDirty) const override {}
    };
    input->SetOcclusionDetectCallback(make_shared<CameraOcclusionDetectCallbackMock>());
    CameraDeviceServiceCallback callback2(input);
    callback2.OnError(fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>());
    callback2.OnResult(fdp.ConsumeIntegral<uint64_t>(), meta);
    input->GetCameraDeviceInfo().clear();
    callback2.OnError(fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>());
    callback2.OnResult(fdp.ConsumeIntegral<uint64_t>(), meta);
    input->Release();
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    if (fdp.remaining_bytes() < OHOS::CameraStandard::MIN_SIZE_NUM) {
        return 0;
    }
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::TestToken().GetAllCameraPermission(), 0, "GetPermission error");
    OHOS::CameraStandard::CameraDeviceFuzzTest(fdp);
    OHOS::CameraStandard::CameraDeviceFuzzTestUpdateSetting(fdp);
    OHOS::CameraStandard::CameraDeviceFuzzTest2(fdp);
    OHOS::CameraStandard::Test3(fdp);
    OHOS::CameraStandard::TestXCollie(fdp);
    OHOS::CameraStandard::TestDynamicLoader(fdp);
    OHOS::CameraStandard::TestCameraDeviceServiceCallback(fdp);
    return 0;
}