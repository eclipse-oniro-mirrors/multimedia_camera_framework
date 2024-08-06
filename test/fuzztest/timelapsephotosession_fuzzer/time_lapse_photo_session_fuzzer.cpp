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

#include "time_lapse_photo_session_fuzzer.h"
#include "camera_log.h"
#include "camera_output_capability.h"
#include "input/camera_manager.h"
#include "message_parcel.h"
#include "time_lapse_photo_session.h"
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "accesstoken_kit.h"

namespace OHOS {
namespace CameraStandard {
namespace TimeLapsePhotoSessionFuzzer {
const int32_t LIMITSIZE = 4;
const int32_t NUM_2 = 2;
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

sptr<CameraManager> manager;
sptr<TimeLapsePhotoSession> session;
sptr<CameraDevice> camera;
SceneMode sceneMode = SceneMode::TIMELAPSE_PHOTO;

auto AddOutput()
{
    sptr<CameraOutputCapability> capability = manager->GetSupportedOutputCapability(camera, sceneMode);
    CHECK_AND_RETURN_LOG(capability, "TimeLapsePhotoSessionFuzzer: capability Error");
    Profile preview(CameraFormat::CAMERA_FORMAT_YUV_420_SP, {640, 480});
    sptr<CaptureOutput> previewOutput = manager->CreatePreviewOutput(preview, Surface::CreateSurfaceAsConsumer());
    CHECK_AND_RETURN_LOG(previewOutput, "TimeLapsePhotoSessionFuzzer: previewOutput Error");
    session->AddOutput(previewOutput);
    Profile photo(CameraFormat::CAMERA_FORMAT_JPEG, {640, 480});
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    CHECK_AND_RETURN_LOG(photoSurface, "TimeLapsePhotoSessionFuzzer: photoSurface Error");
    sptr<IBufferProducer> surface = photoSurface->GetProducer();
    CHECK_AND_RETURN_LOG(surface, "TimeLapsePhotoSessionFuzzer: surface Error");
    sptr<CaptureOutput> photoOutput = manager->CreatePhotoOutput(photo, surface);
    CHECK_AND_RETURN_LOG(photoOutput, "TimeLapsePhotoSessionFuzzer: photoOutput Error");
    session->AddOutput(photoOutput);
}

auto TestProcessor(uint8_t *rawData, size_t size)
{
    class ExposureInfoCallbackMock : public ExposureInfoCallback {
    public:
        void OnExposureInfoChanged(ExposureInfo info) override {}
    };
    session->SetExposureInfoCallback(make_shared<ExposureInfoCallbackMock>());
    static const camera_rational_t r = {
        .numerator = 1,
        .denominator = 1000000,
    };
    auto meta = make_shared<OHOS::Camera::CameraMetadata>(10, 100);
    meta->addEntry(OHOS_STATUS_SENSOR_EXPOSURE_TIME, &r, 1);
 
    class IsoInfoCallbackMock : public IsoInfoCallback {
    public:
        void OnIsoInfoChanged(IsoInfo info) override {}
    };
    session->SetIsoInfoCallback(make_shared<IsoInfoCallbackMock>());
    static const uint32_t iso = 1;
    meta->addEntry(OHOS_STATUS_ISO_VALUE, &iso, 1);
 
    static const uint32_t lumination = 256;
    class LuminationInfoCallbackMock : public LuminationInfoCallback {
    public:
        void OnLuminationInfoChanged(LuminationInfo info) override {}
    };
    session->SetLuminationInfoCallback(make_shared<LuminationInfoCallbackMock>());
    meta->addEntry(OHOS_STATUS_ALGO_MEAN_Y, &lumination, 1);
 
    static const int32_t value = 1;
    class TryAEInfoCallbackMock : public TryAEInfoCallback {
    public:
        void OnTryAEInfoChanged(TryAEInfo info) override {}
    };
    session->SetTryAEInfoCallback(make_shared<TryAEInfoCallbackMock>());
    meta->addEntry(OHOS_STATUS_TIME_LAPSE_TRYAE_DONE, &value, 1);
    meta->addEntry(OHOS_STATUS_TIME_LAPSE_TRYAE_HINT, &value, 1);
    meta->addEntry(OHOS_STATUS_TIME_LAPSE_PREVIEW_TYPE, &value, 1);
    meta->addEntry(OHOS_STATUS_TIME_LAPSE_CAPTURE_INTERVAL, &value, 1);

    meta->addEntry(OHOS_STATUS_PREVIEW_PHYSICAL_CAMERA_ID, &value, 1);

    MessageParcel data;
    data.WriteRawData(rawData, size);
    TimeLapsePhotoSessionMetadataResultProcessor processor(session);
    processor.ProcessCallbacks(data.ReadUint64(), meta);
}

auto TestTimeLapsePhoto()
{
    bool isTryAENeeded;
    session->IsTryAENeeded(isTryAENeeded);
    session->LockForControl();
    session->StartTryAE();
    session->UnlockForControl();
    session->LockForControl();
    session->StopTryAE();
    session->UnlockForControl();

    vector<int32_t> intervalRange;
    session->GetSupportedTimeLapseIntervalRange(intervalRange);
    if (!intervalRange.empty()) {
        session->LockForControl();
        session->SetTimeLapseInterval(intervalRange[0]);
        session->UnlockForControl();
        int32_t interval;
        session->GetTimeLapseInterval(interval);
    }
    session->LockForControl();
    session->SetTimeLapseRecordState(TimeLapseRecordState::RECORDING);
    session->UnlockForControl();
    session->LockForControl();
    session->SetTimeLapsePreviewType(TimeLapsePreviewType::DARK);
    session->UnlockForControl();
    session->LockForControl();
    session->SetExposureHintMode(ExposureHintMode::EXPOSURE_HINT_MODE_OFF);
    session->UnlockForControl();
}

auto TestManualExposure(uint8_t *rawData, size_t size)
{
    MessageParcel data;
    data.WriteRawData(rawData, size);
    vector<uint32_t> exposureRange;
    session->GetSupportedExposureRange(exposureRange);
    session->LockForControl();
    session->SetExposure(data.ReadUint32());
    session->UnlockForControl();
    uint32_t exposure;
    session->GetExposure(exposure);
    vector<MeteringMode> modes;
    session->GetSupportedMeteringModes(modes);
    bool supported;
    session->IsExposureMeteringModeSupported(METERING_MODE_CENTER_WEIGHTED, supported);
    session->LockForControl();
    session->SetExposureMeteringMode(MeteringMode::METERING_MODE_CENTER_WEIGHTED);
    session->UnlockForControl();
    MeteringMode mode;
    session->GetExposureMeteringMode(mode);
}

void TestManualIso()
{
    bool isManualIsoSupported;
    session->IsManualIsoSupported(isManualIsoSupported);
    if (isManualIsoSupported) {
        vector<int32_t> isoRange;
        session->GetIsoRange(isoRange);
        if (!isoRange.empty()) {
            session->LockForControl();
            session->SetIso(isoRange[0]);
            session->UnlockForControl();
            int32_t iso;
            session->GetIso(iso);
        }
    }
}

void TestWhiteBalance()
{
    vector<WhiteBalanceMode> wbModes;
    session->GetSupportedWhiteBalanceModes(wbModes);
    bool isWhiteBalanceModeSupported;
    session->IsWhiteBalanceModeSupported(WhiteBalanceMode::AWB_MODE_AUTO, isWhiteBalanceModeSupported);
    session->LockForControl();
    session->SetWhiteBalanceMode(WhiteBalanceMode::AWB_MODE_AUTO);
    session->UnlockForControl();
    WhiteBalanceMode wbMode;
    session->GetWhiteBalanceMode(wbMode);
    vector<int32_t> wbRange;
    session->GetWhiteBalanceRange(wbRange);
    if (!wbRange.empty()) {
        session->LockForControl();
        session->SetWhiteBalance(wbRange[0]);
        session->UnlockForControl();
        int32_t wb;
        session->GetWhiteBalance(wb);
    }
}

void Test(uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    GetPermission();
    manager = CameraManager::GetInstance();
    sptr<CaptureSession> captureSession = manager->CreateCaptureSession(sceneMode);
    session = reinterpret_cast<TimeLapsePhotoSession*>(captureSession.GetRefPtr());
    session->BeginConfig();
    auto cameras = manager->GetSupportedCameras();
    CHECK_AND_RETURN_LOG(cameras.size() >= NUM_2, "TimeLapsePhotoSessionFuzzer: GetSupportedCameras Error");
    camera = cameras[0];
    CHECK_AND_RETURN_LOG(camera, "TimeLapsePhotoSessionFuzzer: Camera is null");
    sptr<CaptureInput> input = manager->CreateCameraInput(camera);
    CHECK_AND_RETURN_LOG(input, "TimeLapsePhotoSessionFuzzer: CreateCameraInput Error");
    input->Open();
    session->AddInput(input);
    AddOutput();
    session->CommitConfig();
    TestProcessor(rawData, size);
    TestTimeLapsePhoto();
    TestManualExposure(rawData, size);
    TestManualIso();
    TestWhiteBalance();
    session->Release();
}

} // namespace StreamRepeatStubFuzzer
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::CameraStandard::TimeLapsePhotoSessionFuzzer::Test(data, size);
    return 0;
}