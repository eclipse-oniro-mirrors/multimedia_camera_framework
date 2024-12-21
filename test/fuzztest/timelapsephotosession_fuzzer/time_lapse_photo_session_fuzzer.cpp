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
    camera_rational_t r = {1, 1000000};
    auto meta = make_shared<OHOS::Camera::CameraMetadata>(10, 100);
    meta->addEntry(OHOS_STATUS_SENSOR_EXPOSURE_TIME, &r, 1);
    session->ProcessExposureChange(meta);
    r.numerator++;
    meta->updateEntry(OHOS_STATUS_SENSOR_EXPOSURE_TIME, &r, 1);
    class IsoInfoCallbackMock : public IsoInfoCallback {
    public:
        void OnIsoInfoChanged(IsoInfo info) override {}
    };
    session->SetIsoInfoCallback(make_shared<IsoInfoCallbackMock>());
    uint32_t iso = 1;
    meta->addEntry(OHOS_STATUS_ISO_VALUE, &iso, 1);
    session->ProcessIsoInfoChange(meta);
    iso++;
    meta->updateEntry(OHOS_STATUS_ISO_VALUE, &iso, 1);
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
        int32_t interval = intervalRange[intervalRange.size() - 1];
        session->LockForControl();
        session->SetTimeLapseInterval(interval);
        session->UnlockForControl();
        auto meta = session->GetInputDevice()->GetCameraDeviceInfo()->GetMetadata();
        AddOrUpdateMetadata(meta, OHOS_CONTROL_TIME_LAPSE_INTERVAL, &interval, 1);
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
    session->SetExposureHintMode(static_cast<ExposureHintMode>(ExposureHintMode::EXPOSURE_HINT_UNSUPPORTED + 1));
    session->UnlockForControl();
}

auto TestManualExposure(uint8_t *rawData, size_t size)
{
    MessageParcel data;
    data.WriteRawData(rawData, size);
    auto meta = session->GetMetadata();
    const camera_rational_t rs[] = {
        {3, 1000000},
        {9, 1000000},
    };
    uint32_t dataCount = sizeof(rs) / sizeof(rs[0]);
    AddOrUpdateMetadata(meta, OHOS_ABILITY_SENSOR_EXPOSURE_TIME_RANGE, rs, dataCount);
    vector<uint32_t> exposureRange;
    session->GetSupportedExposureRange(exposureRange);
    meta = session->GetInputDevice()->GetCameraDeviceInfo()->GetMetadata();
    session->LockForControl();
    session->SetExposure(0);
    session->SetExposure(1);
    session->SetExposure(data.ReadUint32());
    session->UnlockForControl();
    uint32_t exposure = data.ReadUint32();
    AddOrUpdateMetadata(meta, OHOS_CONTROL_SENSOR_EXPOSURE_TIME, &exposure, 1);
    session->GetExposure(exposure);
    vector<MeteringMode> modes;
    session->GetSupportedMeteringModes(modes);
    bool supported;
    session->IsExposureMeteringModeSupported(METERING_MODE_CENTER_WEIGHTED, supported);
    session->IsExposureMeteringModeSupported(
        static_cast<MeteringMode>(MeteringMode::METERING_MODE_OVERALL + 1), supported);
    session->LockForControl();
    session->SetExposureMeteringMode(MeteringMode::METERING_MODE_CENTER_WEIGHTED);
    session->SetExposureMeteringMode(static_cast<MeteringMode>(MeteringMode::METERING_MODE_OVERALL + 1));
    session->UnlockForControl();
    MeteringMode mode = MeteringMode::METERING_MODE_OVERALL;
    AddOrUpdateMetadata(meta, OHOS_CONTROL_METER_MODE, &mode, 1);
    session->GetExposureMeteringMode(mode);
    mode = static_cast<MeteringMode>(MeteringMode::METERING_MODE_OVERALL + 1);
    AddOrUpdateMetadata(meta, OHOS_CONTROL_METER_MODE, &mode, 1);
    session->GetExposureMeteringMode(mode);
}

void TestManualIso()
{
    auto meta = session->GetInputDevice()->GetCameraDeviceInfo()->GetMetadata();
    bool isManualIsoSupported;
    session->IsManualIsoSupported(isManualIsoSupported);
    if (isManualIsoSupported) {
        vector<int32_t> isoRange;
        session->GetIsoRange(isoRange);
        if (!isoRange.empty()) {
            session->LockForControl();
            session->SetIso(isoRange[0]);
            session->UnlockForControl();
            int32_t iso = 1000;
            AddOrUpdateMetadata(meta, OHOS_CONTROL_ISO_VALUE, &iso, 1);
            session->GetIso(iso);
        }
    }
    AddOrUpdateMetadata(meta, OHOS_ABILITY_ISO_VALUES, &isManualIsoSupported, 1);
    session->IsManualIsoSupported(isManualIsoSupported);
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
    auto meta = session->GetInputDevice()->GetCameraDeviceInfo()->GetMetadata();
    camera_awb_mode_t awbModes[] = {camera_awb_mode_t::OHOS_CAMERA_AWB_MODE_AUTO};
    AddOrUpdateMetadata(meta, OHOS_ABILITY_AWB_MODES, awbModes, 1);
    session->GetSupportedWhiteBalanceModes(wbModes);
    AddOrUpdateMetadata(meta, OHOS_CONTROL_AWB_MODE, awbModes, 1);
    session->GetWhiteBalanceMode(wbMode);
    session->LockForControl();
    session->SetWhiteBalanceMode(static_cast<WhiteBalanceMode>(WhiteBalanceMode::AWB_MODE_SHADE + 1));
    int32_t wb = 1;
    AddOrUpdateMetadata(meta, OHOS_CONTROL_SENSOR_WB_VALUE, &wb, 1);
    session->GetWhiteBalance(wb);
}

void TestGetMetadata()
{
    auto cameras = manager->GetSupportedCameras();
    sptr<CameraDevice> phyCam;
    for (auto item : cameras) {
        if (item->GetCameraType() == CAMERA_TYPE_WIDE_ANGLE) {
            phyCam = item;
        }
    }
    CHECK_ERROR_RETURN_LOG(cameras.empty(), "TimeLapsePhotoSessionFuzzer: No Wide Angle Camera");
    string cameraId = phyCam->GetID();
    MEDIA_INFO_LOG("TimeLapsePhotoSessionFuzzer: Wide Angle Camera Id = %{public}s", cameraId.c_str());
    auto meta = make_shared<OHOS::Camera::CameraMetadata>(10, 100);
    size_t delimPos = cameraId.find("/");
    cameraId = cameraId.substr(delimPos + 1);
    auto index = atoi(cameraId.c_str());
    MEDIA_INFO_LOG("TimeLapsePhotoSessionFuzzer: Wide Angle Camera Id = %{public}d", index);
    AddOrUpdateMetadata(meta, OHOS_STATUS_PREVIEW_PHYSICAL_CAMERA_ID, &index, 1);
    session->ProcessPhysicalCameraSwitch(meta);
    session->GetMetadata();
}

void TestGetMetadata2()
{
    sptr<ICaptureSession> iCaptureSession;
    {
        sptr<CaptureSession> captureSession = manager->CreateCaptureSession(sceneMode);
        iCaptureSession = captureSession->GetCaptureSession();
    }
    vector<sptr<CameraDevice>> devices{};
    sptr<TimeLapsePhotoSession> tlpSession = new TimeLapsePhotoSession(iCaptureSession, devices);
    tlpSession->BeginConfig();
    sptr<CaptureInput> input = manager->CreateCameraInput(camera);
    tlpSession->AddInput(input);
    tlpSession->GetMetadata();
    tlpSession->Release();
}

void Test2()
{
    CaptureSessionCallback callback(session);
    callback.OnError(1);
    auto s = manager->CreateCaptureSession(SceneMode::VIDEO);
    s->BeginConfig();
    auto cap = s->GetCameraOutputCapabilities(camera)[0];
    auto vp = cap->GetVideoProfiles()[0];
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    auto vo = manager->CreateVideoOutput(vp, surface);
    sptr<CaptureOutput> output = static_cast<CaptureOutput*>(vo.GetRefPtr());
    s->AddOutput(output);
    const int32_t N_30 = 30;
    const int32_t N_60 = 60;
    const int32_t N_200 = 200;
    vo->SetFrameRateRange(N_30, N_30);
    s->CanSetFrameRateRangeForOutput(N_30, N_30, output);
    vo->SetFrameRateRange(N_30, N_60);
    s->CanSetFrameRateRangeForOutput(N_30, N_60, output);
    s->CanSetFrameRateRangeForOutput(1, N_200, output);

    Profile p = cap->GetPreviewProfiles()[0];
    output = manager->CreatePreviewOutput(p, Surface::CreateSurfaceAsConsumer());
    output->AddTag(CaptureOutput::DYNAMIC_PROFILE);
    s->AddOutput(output);
    surface = Surface::CreateSurfaceAsConsumer();
    output = manager->CreateVideoOutput(vp, surface);
    output->AddTag(CaptureOutput::DYNAMIC_PROFILE);
    s->AddOutput(output);
    s->Release();

    s = manager->CreateCaptureSession(SceneMode::CAPTURE);
    s->BeginConfig();
    sptr<IConsumerSurface> cs = IConsumerSurface::Create();
    sptr<IBufferProducer> bp = cs->GetProducer();
    p = cap->GetPhotoProfiles()[0];
    output = manager->CreatePhotoOutput(p, bp);
    output->AddTag(CaptureOutput::DYNAMIC_PROFILE);
    s->AddOutput(output);

    output = manager->CreateMetadataOutput();
    s->AddOutput(output);
    output = manager->CreateMetadataOutput();
    output->AddTag(CaptureOutput::DYNAMIC_PROFILE);
    s->AddOutput(output);
    s->Release();
}

void Test31(sptr<CaptureSession> s)
{
    s->UnlockForControl();
    bool supported = true;
    set<camera_face_detect_mode_t> metadataObjectTypes{};
    s->SetCaptureMetadataObjectTypes(metadataObjectTypes);
    metadataObjectTypes.emplace(OHOS_CAMERA_FACE_DETECT_MODE_SIMPLE);
    s->SetCaptureMetadataObjectTypes(metadataObjectTypes);
    s->EnableFaceDetection(supported);
    const float distance = 1.0f;
    s->IsSessionStarted();
    s->EnableMovingPhotoMirror(supported);
    vector<WhiteBalanceMode> modes;
    s->GetSupportedWhiteBalanceModes(modes);
    s->IsWhiteBalanceModeSupported(WhiteBalanceMode::AWB_MODE_AUTO, supported);
    s->LockForControl();
    s->SetFocusDistance(distance);
    
    s->EnableLowLightDetection(supported);
    s->EnableMovingPhoto(supported);
    s->SetSensorSensitivity(1);
    s->SetWhiteBalanceMode(WhiteBalanceMode::AWB_MODE_AUTO);
    WhiteBalanceMode mode;
    s->GetWhiteBalanceMode(mode);
    vector<int32_t> whiteBalanceRange;
    s->GetManualWhiteBalanceRange(whiteBalanceRange);
    s->IsManualWhiteBalanceSupported(supported);
    int32_t wbValue;
    s->GetManualWhiteBalance(wbValue);
    s->SetManualWhiteBalance(wbValue);
    vector<std::vector<float>> supportedPhysicalApertures;
    s->GetSupportedPhysicalApertures(supportedPhysicalApertures);
    vector<float> apertures;
    s->GetSupportedVirtualApertures(apertures);
    s->GetSupportedPortraitEffects();
    float aperture;
    s->GetVirtualAperture(aperture);
    s->SetVirtualAperture(aperture);
    s->GetPhysicalAperture(aperture);
    s->SetPhysicalAperture(aperture);
    s->IsLcdFlashSupported();
    s->EnableLcdFlash(supported);
    s->EnableLcdFlashDetection(supported);
    auto callback = s->GetLcdFlashStatusCallback();
    s->SetLcdFlashStatusCallback(callback);
    s->IsTripodDetectionSupported();
    s->EnableTripodStabilization(supported);
    s->EnableTripodDetection(supported);
}

void Test3()
{
    sptr<CaptureInput> input = manager->CreateCameraInput(camera);
    input->Open();
    auto s = manager->CreateCaptureSession(SceneMode::SECURE);
    s->BeginConfig();
    auto cap = manager->GetSupportedOutputCapability(camera, SceneMode::CAPTURE);
    if (!cap->GetDepthProfiles().empty()) {
        DepthProfile dp = cap->GetDepthProfiles()[0];
        sptr<IConsumerSurface> cs = IConsumerSurface::Create();
        sptr<IBufferProducer> bp = cs->GetProducer();
        sptr<CaptureOutput> output = manager->CreateDepthDataOutput(dp, bp);
        s->AddSecureOutput(output);
    }
    sptr<CaptureOutput> output = manager->CreateMetadataOutput();
    s->AddOutput(output);
    s->AddInput(input);
    s->CommitConfig();
    s->Start();
    string deviceClass{"device/0"};
    s->SetPreviewRotation(deviceClass);
    uint32_t value = 1;
    auto meta = s->GetInputDevice()->GetCameraDeviceInfo()->GetMetadata();
    AddOrUpdateMetadata(meta, OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &value, 1);
    s->GetActiveVideoStabilizationMode();
    s->UnlockForControl();
    s->SetExposureMode(ExposureMode::EXPOSURE_MODE_AUTO);
    s->LockForControl();
    s->SetExposureMode(ExposureMode::EXPOSURE_MODE_AUTO);
    s->GetSupportedFlashModes();
    vector<FlashMode> flashModes;
    s->GetSupportedFlashModes(flashModes);
    s->GetFlashMode();
    FlashMode flashMode;
    s->GetFlashMode(flashMode);
    s->SetFlashMode(flashMode);
    s->IsFlashModeSupported(flashMode);
    bool supported;
    s->IsFlashModeSupported(flashMode, supported);
    s->HasFlash();
    s->HasFlash(supported);
    meta = camera->GetMetadata();
    AddOrUpdateMetadata(meta, OHOS_ABILITY_AVAILABLE_PROFILE_LEVEL, &value, 0);
    AddOrUpdateMetadata(meta, OHOS_ABILITY_SCENE_ZOOM_CAP, &value, 1);
    vector<float> zoomRatioRange;
    s->GetZoomRatioRange(zoomRatioRange);
    Test31(s);
    s->Stop();
    s->Release();
}

void TestMetadataResultProcessor()
{
    auto s = manager->CreateCaptureSession(SceneMode::CAPTURE);
    s->BeginConfig();
    sptr<CaptureOutput> output = manager->CreateMetadataOutput();
    s->AddOutput(output);
    sptr<CaptureInput> input = manager->CreateCameraInput(camera);
    input->Open();
    s->AddInput(input);
    CaptureSession::CaptureSessionMetadataResultProcessor processor(s);
    auto metadata = make_shared<OHOS::Camera::CameraMetadata>(10, 100);
    uint64_t data = 1;
    AddOrUpdateMetadata(metadata, OHOS_CONTROL_EXPOSURE_STATE, &data, 1);
    AddOrUpdateMetadata(metadata, OHOS_CONTROL_FOCUS_MODE, &data, 1);
    AddOrUpdateMetadata(metadata, OHOS_CONTROL_FOCUS_STATE, &data, 1);
    AddOrUpdateMetadata(metadata, OHOS_CAMERA_MACRO_STATUS, &data, 1);
    AddOrUpdateMetadata(metadata, FEATURE_MOON_CAPTURE_BOOST, &data, 1);
    AddOrUpdateMetadata(metadata, OHOS_STATUS_MOON_CAPTURE_DETECTION, &data, 1);
    AddOrUpdateMetadata(metadata, FEATURE_LOW_LIGHT_BOOST, &data, 1);
    AddOrUpdateMetadata(metadata, OHOS_STATUS_LOW_LIGHT_DETECTION, &data, 1);
    AddOrUpdateMetadata(metadata, OHOS_CAMERA_CUSTOM_SNAPSHOT_DURATION, &data, 1);
    AddOrUpdateMetadata(metadata, OHOS_STATUS_SENSOR_EXPOSURE_TIME, &data, 1);
    AddOrUpdateMetadata(metadata, OHOS_CAMERA_EFFECT_SUGGESTION_TYPE, &data, 1);
    AddOrUpdateMetadata(metadata, OHOS_STATUS_LCD_FLASH_STATUS, &data, 1);
    processor.ProcessCallbacks(1, metadata);
    s->Release();
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
    TestGetMetadata();
    session->Release();
    TestGetMetadata2();
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