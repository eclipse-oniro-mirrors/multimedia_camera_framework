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
#include "input/camera_manager.h"
#include "metadata_utils.h"
#include "ipc_skeleton.h"
#include "access_token.h"
#include "hap_token_info.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
using namespace std;

namespace OHOS {
namespace CameraStandard {
const std::u16string FORMMGR_INTERFACE_TOKEN = u"ICameraDeviceService";
const size_t LIMITCOUNT = 4;
const int32_t NUM_2 = 2;
const uint8_t NUM_5 = 5;
const int32_t NUM_10 = 10;
const int32_t NUM_100 = 100;
bool g_isCameraDevicePermission = false;
sptr<HCameraDevice> fuzzCameraDevice = nullptr;

void CameraDeviceFuzzTestGetPermission()
{
    if (!g_isCameraDevicePermission) {
        uint64_t tokenId;
        const char *perms[0];
        perms[0] = "ohos.permission.CAMERA";
        NativeTokenInfoParams infoInstance = { .dcapsNum = 0, .permsNum = 1, .aclsNum = 0, .dcaps = NULL,
            .perms = perms, .acls = NULL, .processName = "camera_capture", .aplStr = "system_basic",
        };
        tokenId = GetAccessTokenId(&infoInstance);
        SetSelfTokenID(tokenId);
        OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
        g_isCameraDevicePermission = true;
    }
}

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

void CameraDeviceFuzzTest(uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < NUM_2) {
        return;
    }
    CameraDeviceFuzzTestGetPermission();

    int32_t itemCount = NUM_10;
    int32_t dataSize = NUM_100;
    int32_t *streams = reinterpret_cast<int32_t *>(rawData);
    std::shared_ptr<OHOS::Camera::CameraMetadata> ability;
    ability = std::make_shared<OHOS::Camera::CameraMetadata>(itemCount, dataSize);
    ability->addEntry(OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS, streams, size / LIMITCOUNT);
    int32_t compensationRange[2] = {rawData[0], rawData[1]};
    ability->addEntry(OHOS_CONTROL_AE_COMPENSATION_RANGE, compensationRange,
                      sizeof(compensationRange) / sizeof(compensationRange[0]));
    float focalLength = rawData[0];
    ability->addEntry(OHOS_ABILITY_FOCAL_LENGTH, &focalLength, 1);

    int32_t sensorOrientation = rawData[0];
    ability->addEntry(OHOS_SENSOR_ORIENTATION, &sensorOrientation, 1);

    int32_t cameraPosition = rawData[0];
    ability->addEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, 1);

    const camera_rational_t aeCompensationStep[] = {{rawData[0], rawData[1]}};
    ability->addEntry(OHOS_CONTROL_AE_COMPENSATION_STEP, &aeCompensationStep,
                      sizeof(aeCompensationStep) / sizeof(aeCompensationStep[0]));

    MessageParcel data;
    data.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    CHECK_AND_RETURN_LOG(OHOS::Camera::MetadataUtils::EncodeCameraMetadata(ability, data),
        "CameraDeviceFuzzer: EncodeCameraMetadata Error");
    data.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    PrepareHCameraDevice();
    if (fuzzCameraDevice) {
        uint32_t code = 4;
        fuzzCameraDevice->OnRemoteRequest(code, data, reply, option);
    }
}

void CameraDeviceFuzzTestUpdateSetting(uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < NUM_2) {
        return;
    }
    CameraDeviceFuzzTestGetPermission();

    int32_t itemCount = NUM_10;
    int32_t dataSize = NUM_100;
    int32_t *streams = reinterpret_cast<int32_t *>(rawData);
    auto ability = std::make_shared<OHOS::Camera::CameraMetadata>(itemCount, dataSize);
    ability->addEntry(OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS, streams, size / LIMITCOUNT);
    int32_t compensationRange[2] = {rawData[0], rawData[1]};
    ability->addEntry(OHOS_CONTROL_AE_COMPENSATION_RANGE, compensationRange,
                      sizeof(compensationRange) / sizeof(compensationRange[0]));
    float focalLength = rawData[0];
    ability->addEntry(OHOS_ABILITY_FOCAL_LENGTH, &focalLength, 1);

    int32_t sensorOrientation = rawData[0];
    ability->addEntry(OHOS_SENSOR_ORIENTATION, &sensorOrientation, 1);

    int32_t cameraPosition = rawData[0];
    ability->addEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, 1);

    const camera_rational_t aeCompensationStep[] = {{rawData[0], rawData[1]}};
    ability->addEntry(OHOS_CONTROL_AE_COMPENSATION_STEP, &aeCompensationStep,
                      sizeof(aeCompensationStep) / sizeof(aeCompensationStep[0]));
    if (fuzzCameraDevice) {
        fuzzCameraDevice->UpdateSettingOnce(ability);
        fuzzCameraDevice->UpdateSetting(ability);
        auto out = std::make_shared<OHOS::Camera::CameraMetadata>(itemCount, dataSize);
        fuzzCameraDevice->GetStatus(ability, out);
        std::vector<HDI::Camera::V1_1::StreamInfo_V1_1> streamInfos;
        fuzzCameraDevice->UpdateStreams(streamInfos);
        MessageParcel data;
        data.WriteRawData(rawData, size);
        fuzzCameraDevice->CreateAndCommitStreams(streamInfos, ability, data.ReadInt32());
        vector<uint8_t> result;
        OHOS::Camera::MetadataUtils::ConvertMetadataToVec(ability, result);
        fuzzCameraDevice->OnResult(data.ReadUint64(), result);
        auto type = OHOS::HDI::Camera::V1_0::ErrorType::REQUEST_TIMEOUT;
        fuzzCameraDevice->OnError(type, data.ReadInt32());
    }
}

void CameraDeviceFuzzTest2Case1(uint8_t *rawData, size_t size)
{
    MessageParcel data;
    data.WriteRawData(rawData, size);
    if (fuzzCameraDevice) {
        fuzzCameraDevice->GetStreamOperatorCallback();
        fuzzCameraDevice->GetCallerToken();
        fuzzCameraDevice->GetDeviceAbility();
        fuzzCameraDevice->GetCameraType();
        fuzzCameraDevice->GetCameraId();
        fuzzCameraDevice->GetStreamOperator();
    }
}

void CameraDeviceFuzzTest2Case2(uint8_t *rawData, size_t size)
{
    // 运行会出错
    MessageParcel data;
    data.WriteRawData(rawData, size);
    sptr<ICameraDeviceServiceCallback> callback(new ICameraDeviceServiceCallbackMock());
    fuzzCameraDevice->SetCallback(callback);
    wptr<IStreamOperatorCallback> opCallback(new IStreamOperatorCallbackMock());
    fuzzCameraDevice->SetStreamOperatorCallback(opCallback);
    vector<int32_t> results{data.ReadInt32()};
    fuzzCameraDevice->EnableResult(results);
    fuzzCameraDevice->DisableResult(results);
    fuzzCameraDevice->CloneCachedSettings();
    fuzzCameraDevice->DispatchDefaultSettingToHdi();
    fuzzCameraDevice->Release();
    fuzzCameraDevice->Close();
    uint64_t secureSeqId;
    fuzzCameraDevice->GetSecureCameraSeq(&secureSeqId);
    fuzzCameraDevice->OpenSecureCamera(&secureSeqId);
}

void CameraDeviceFuzzTest2Case3(uint8_t *rawData, size_t size)
{
    // 运行会出错
    MessageParcel data;
    data.WriteRawData(rawData, size);
    if (fuzzCameraDevice) {
        vector<int32_t> streamIds{data.ReadInt32()};
        fuzzCameraDevice->OnFrameShutter(data.ReadInt32(), streamIds, data.ReadUint64());
        fuzzCameraDevice->OnFrameShutterEnd(data.ReadInt32(), streamIds, data.ReadUint64());
        fuzzCameraDevice->OnCaptureReady(data.ReadInt32(), streamIds, data.ReadUint64());
        vector<OHOS::HDI::Camera::V1_2::CaptureStartedInfo> infos{{data.ReadInt32(), data.ReadInt32()}};
        fuzzCameraDevice->OnCaptureStarted_V1_2(data.ReadInt32(), infos);
        vector<CaptureEndedInfo> endedInfos{{data.ReadInt32(), data.ReadInt32()}};
        fuzzCameraDevice->OnCaptureEnded(data.ReadInt32(), endedInfos);
        vector<OHOS::HDI::Camera::V1_3::CaptureEndedInfoExt> endedInfosExt;
        fuzzCameraDevice->OnCaptureEndedExt(data.ReadInt32(), endedInfosExt);
        auto err = static_cast<OHOS::HDI::Camera::V1_0::StreamError>(data.ReadInt32());
        vector<CaptureErrorInfo> errorInfos{{data.ReadInt32(), err}};
        fuzzCameraDevice->OnCaptureError(data.ReadInt32(), errorInfos);
        fuzzCameraDevice->OnCaptureStarted(data.ReadInt32(), streamIds);
    }
}

void CameraDeviceFuzzTest2(uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < NUM_2) {
        return;
    }
    MessageParcel data;
    data.WriteRawData(rawData, size);
    if (fuzzCameraDevice) {
        fuzzCameraDevice->OperatePermissionCheck(data.ReadUint32());
        fuzzCameraDevice->Open();
        fuzzCameraDevice->CheckMovingPhotoSupported(data.ReadInt32());
        fuzzCameraDevice->NotifyCameraStatus(data.ReadInt32());
        fuzzCameraDevice->RemoveResourceWhenHostDied();
        fuzzCameraDevice->NotifyCameraSessionStatus(data.ReadBool());
        std::vector<int32_t> releaseStreamIds;
        fuzzCameraDevice->ReleaseStreams(releaseStreamIds);
        CameraDeviceFuzzTest2Case1(rawData, size);
        fuzzCameraDevice->ResetDeviceSettings();
        fuzzCameraDevice->SetDeviceMuteMode(data.ReadBool());
        fuzzCameraDevice->IsOpenedCameraDevice();
        fuzzCameraDevice->CloseDevice();
    }
}

void GetPermission()
{
    uint64_t tokenId;
    const char* perms[2];
    perms[0] = "ohos.permission.DISTRIBUTED_DATASYNC";
    perms[1] = "ohos.permission.CAMERA";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .aclsNum = 0,
        .dcaps = NULL,
        .perms = perms,
        .acls = NULL,
        .processName = "native_camera_tdd",
        .aplStr = "system_basic",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

void Test3(uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < NUM_2) {
        return;
    }
    GetPermission();
    auto manager = CameraManager::GetInstance();
    auto cameras = manager->GetSupportedCameras();
    CHECK_AND_RETURN_LOG(cameras.size() >= NUM_2, "PhotoOutputFuzzer: GetSupportedCameras Error");
    MessageParcel data;
    data.WriteRawData(rawData, size);
    sptr<CameraDevice> camera = cameras[data.ReadUint32() % cameras.size()];
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
    camera->GetZoomRatioRange();
    camera->GetExposureBiasRange();
    camera->GetModuleType();
    CameraFormat format = static_cast<CameraFormat>(data.ReadInt32());
    auto capability = manager->GetSupportedOutputCapability(camera);
    CHECK_AND_RETURN_LOG(capability, "PhotoOutputFuzzer: GetSupportedOutputCapability Error");
    vector<Profile> profiles = capability->GetPhotoProfiles();
    camera->GetMaxSizeProfile(profiles, data.ReadFloat(), format);
    auto profiles2 = capability->GetVideoProfiles();
    camera->GetMaxSizeProfile(profiles2, data.ReadFloat(), format);
}

void TestXCollie(uint8_t *rawData, size_t size)
{
    CHECK_ERROR_RETURN(rawData == nullptr || size < NUM_2);
    MessageParcel data;
    data.WriteRawData(rawData, size);
    string tag = data.ReadString();
    uint32_t flag = data.ReadInt32();
    uint32_t timeoutSeconds = data.ReadUint32();
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

void TestCameraDeviceServiceCallback(uint8_t *rawData, size_t size)
{
    CHECK_ERROR_RETURN(rawData == nullptr || size < NUM_2);
    MessageParcel data;
    data.WriteRawData(rawData, size);
    auto meta = make_shared<OHOS::Camera::CameraMetadata>(10, 100);
    int val = 1;
    AddOrUpdateMetadata(meta, OHOS_STATUS_CAMERA_OCCLUSION_DETECTION, &val, 1);

    CameraDeviceServiceCallback callback;
    callback.OnError(data.ReadInt32(), data.ReadInt32());
    callback.OnResult(data.ReadUint64(), meta);

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
    callback2.OnError(data.ReadInt32(), data.ReadInt32());
    callback2.OnResult(data.ReadUint64(), meta);
    input->GetCameraDeviceInfo().clear();
    callback2.OnError(data.ReadInt32(), data.ReadInt32());
    callback2.OnResult(data.ReadUint64(), meta);
    input->Release();
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    uint8_t firstByte = *data;
    firstByte = firstByte % NUM_5;
    switch (firstByte) {
        case 0:
            OHOS::CameraStandard::CameraDeviceFuzzTest(data, size);
            break;
        case 1:
            OHOS::CameraStandard::CameraDeviceFuzzTestUpdateSetting(data, size);
            break;
        case 2:
            OHOS::CameraStandard::CameraDeviceFuzzTest2(data, size);
            break;
        case 3:
            OHOS::CameraStandard::Test3(data, size);
            break;
        default:
            OHOS::CameraStandard::TestXCollie(data, size);
            break;
    }
    return 0;
}

