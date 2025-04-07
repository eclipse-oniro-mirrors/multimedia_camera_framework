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

#include "capture_session_fuzzer.h"
#include "camera_input.h"
#include "camera_log.h"
#include "camera_photo_proxy.h"
#include "capture_input.h"
#include "capture_output.h"
#include "preview_output.h"
#include "capture_scene_const.h"
#include "input/camera_manager.h"
#include "message_parcel.h"
#include "refbase.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "accesstoken_kit.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "os_account_manager.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace CameraStandard {
namespace CaptureSessionFuzzer {
const int32_t LIMITSIZE = 4;
const int32_t NUM_TWO = 2;
const int32_t NUM_20 = 20;
const int32_t NUM_40 = 40;

sptr<IBufferProducer> surface;
sptr<CameraDevice> camera;
Profile profile;
CaptureOutput* curOutput;
bool g_isSupported;
bool g_isCameraDevicePermission = false;
SceneMode g_sceneMode;
std::vector<Profile> previewProfile_ = {};

sptr<CameraManager> manager_;

void GetPermission()
{
    uint64_t tokenId;
    int32_t uid = 0;
    int32_t userId = 0;
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
    uid = IPCSkeleton::GetCallingUid();
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, userId);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

sptr<CaptureInput> GetCameraInput(uint8_t *rawData, size_t size)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: ENTER");
    auto manager_ = CameraManager::GetInstance();
    auto cameras = manager_->GetSupportedCameras();
    CHECK_ERROR_RETURN_RET_LOG(cameras.size() < NUM_TWO, nullptr, "CaptureSessionFuzzer: GetSupportedCameras Error");
    MessageParcel data;
    data.WriteRawData(rawData, size);
    camera = cameras[data.ReadUint32() % cameras.size()];
    CHECK_ERROR_RETURN_RET_LOG(!camera, nullptr, "CaptureSessionFuzzer: Camera is null Error");
    return manager_->CreateCameraInput(camera);
}

sptr<CaptureOutput> CreatePreviewOutput(Profile previewProfile)
{
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    if (surface == nullptr) {
        return nullptr;
    }
    return manager_->CreatePreviewOutput(previewProfile, surface);
}

void Test(uint8_t *rawData, size_t size)
{
    CHECK_ERROR_RETURN(rawData == nullptr || size < LIMITSIZE);
    GetPermission();
    MessageParcel data;
    data.WriteRawData(rawData, size);
    manager_ = CameraManager::GetInstance();
    sptr<CaptureSession> session = manager_->CreateCaptureSession(SceneMode::CAPTURE);
    std::vector<sptr<CameraDevice>> cameras = manager_->GetCameraDeviceListFromServer();
    CHECK_ERROR_RETURN_LOG(cameras.empty(), "GetCameraDeviceListFromServer Error");
    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras[0]);
    CHECK_ERROR_RETURN_LOG(!input, "CreateCameraInput Error");
    input->Open();
    auto outputCapability = manager_->GetSupportedOutputCapability(cameras[0], 0);
    CHECK_ERROR_RETURN_LOG(!outputCapability, "GetSupportedOutputCapability Error");
    previewProfile_ = outputCapability->GetPreviewProfiles();
    CHECK_ERROR_RETURN_LOG(previewProfile_.empty(), "GetPreviewProfiles Error");
    outputCapability->GetVideoProfiles();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    session->BeginConfig();
    session->AddInput(input);
    session->AddOutput(preview);
    session->CommitConfig();
    sptr<ICameraDeviceService> deviceObj = nullptr;
    manager_->CreateCameraDevice(cameras[0]->GetID(), &deviceObj);
    sptr<CameraInput> camInput = (sptr<CameraInput>&)input;
    camInput->SwitchCameraDevice(deviceObj, cameras[0]);
    input->GetCameraDeviceInfo();
    session->SetInputDevice(input);
    session->GetInputDevice()->GetCameraDeviceInfo();
    preview->outputType_ = CAPTURE_OUTPUT_TYPE_DEPTH_DATA;
    session->CanAddOutput(preview);
    TestCallback(session, rawData, size);
    TestWhiteBalance(session, rawData, size);
    TestExposure(session, rawData, size);
    TestFocus(session, rawData, size);
    TestZoom(session, rawData, size);
    TestStabilization(session, rawData, size);
    TestProcess(session, rawData, size);
    TestAperture(session, rawData, size);
    TestBeauty(session, rawData, size);
    TestOther(session, rawData, size);
    TestOther3(session, rawData, size);
    TestFlash(session, rawData, size);
    TestAdd(session, rawData, size);
    TestSession(session, rawData, size);
    TestOther2(session, rawData, size);
    session->Release();
    session->Stop();
}

sptr<PhotoOutput> GetCaptureOutput(uint8_t *rawData, size_t size)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: ENTER");
    auto manager_ = CameraManager::GetInstance();
    CHECK_ERROR_RETURN_RET_LOG(!manager_, nullptr, "CaptureSessionFuzzer: CameraManager::GetInstance Error");
    MessageParcel data;
    data.WriteRawData(rawData, size);
    CHECK_ERROR_RETURN_RET_LOG(!camera, nullptr, "CaptureSessionFuzzer: Camera is null Error");
    auto capability = manager_->GetSupportedOutputCapability(camera, g_sceneMode);
    CHECK_ERROR_RETURN_RET_LOG(!capability, nullptr, "CaptureSessionFuzzer: GetSupportedOutputCapability Error");
    auto profiles = capability->GetPhotoProfiles();
    CHECK_ERROR_RETURN_RET_LOG(profiles.empty(), nullptr, "CaptureSessionFuzzer: GetPhotoProfiles empty");
    profile = profiles[data.ReadUint32() % profiles.size()];
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    CHECK_ERROR_RETURN_RET_LOG(!photoSurface, nullptr, "CaptureSessionFuzzer: create photoSurface Error");
    surface = photoSurface->GetProducer();
    CHECK_ERROR_RETURN_RET_LOG(!surface, nullptr, "CaptureSessionFuzzer: surface GetProducer Error");
    return manager_->CreatePhotoOutput(profile, surface);
}

void TestWhiteBalance(sptr<CaptureSession> session, uint8_t *rawData, size_t size)
{
    MessageParcel data;
    data.WriteRawData(rawData, size);
}

void TestExposure(sptr<CaptureSession> session, uint8_t *rawData, size_t size)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: ENTER");
    MessageParcel data;
    data.WriteRawData(rawData, size);
    session->GetSupportedExposureModes();
    vector<ExposureMode> exposureModes;
    session->GetSupportedExposureModes(exposureModes);
    ExposureMode exposureMode = static_cast<ExposureMode>(
        data.ReadInt32() % (ExposureMode::EXPOSURE_MODE_CONTINUOUS_AUTO + NUM_TWO));
    session->IsExposureModeSupported(exposureMode);
    session->IsExposureModeSupported(exposureMode, g_isSupported);
    session->GetExposureMode();
    session->GetExposureMode(exposureMode);
    session->GetMeteringPoint();
    Point exposurePoint;
    session->GetMeteringPoint(exposurePoint);
    session->GetExposureBiasRange();
    vector<float> exposureBiasRange;
    session->GetExposureBiasRange(exposureBiasRange);
    session->GetExposureValue();
    float exposure;
    session->GetExposureValue(exposure);
    session->LockForControl();
    session->SetExposureMode(exposureMode);
    session->SetMeteringPoint(exposurePoint);
    float exposureBias = data.ReadFloat();
    session->SetExposureBias(exposureBias);
    vector<uint32_t> sensorExposureTimeRange;
    session->GetSensorExposureTimeRange(sensorExposureTimeRange);
    session->SetSensorExposureTime(data.ReadUint32());
    uint32_t sensorExposureTime;
    session->GetSensorExposureTime(sensorExposureTime);
    session->UnlockForControl();
}

void TestFocus(sptr<CaptureSession> session, uint8_t *rawData, size_t size)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: ENTER");
    MessageParcel data;
    data.WriteRawData(rawData, size);
    session->GetSupportedFocusModes();
    vector<FocusMode> focusModes;
    session->GetSupportedFocusModes(focusModes);
    FocusMode focusMode = static_cast<FocusMode>(
        data.ReadInt32() % (FocusMode::FOCUS_MODE_LOCKED + NUM_TWO));
    session->IsFocusModeSupported(focusMode);
    session->IsFocusModeSupported(focusMode, g_isSupported);
    session->GetFocusMode();
    session->GetFocusMode(focusMode);
    session->GetFocusPoint();
    Point focusPoint;
    session->GetFocusPoint(focusPoint);
    session->GetFocalLength();
    float focalLength;
    session->GetFocalLength(focalLength);
    float distance;
    session->GetFocusDistance(distance);
    session->GetMinimumFocusDistance();
    session->LockForControl();
    session->SetFocusMode(focusMode);
    session->SetFocusPoint(focusPoint);
    session->UnlockForControl();
}

void TestZoom(sptr<CaptureSession> session, uint8_t *rawData, size_t size)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: ENTER");
    MessageParcel data;
    data.WriteRawData(rawData, size);
    session->GetZoomRatioRange();
    vector<float> zoomRatioRange;
    session->GetZoomRatioRange(zoomRatioRange);
    session->GetZoomRatio();
    float zoomRatio;
    session->GetZoomRatio(zoomRatio);
    vector<ZoomPointInfo> zoomPointInfoList;
    session->GetZoomPointInfos(zoomPointInfoList);
    session->LockForControl();
    session->SetZoomRatio(zoomRatio);
    session->PrepareZoom();
    session->UnPrepareZoom();
    float targetZoomRatio = data.ReadFloat();
    uint32_t smoothZoomType = data.ReadUint32();
    session->SetSmoothZoom(targetZoomRatio, smoothZoomType);
    session->UnlockForControl();
}

void TestCallback(sptr<CaptureSession> session, uint8_t *rawData, size_t size)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: ENTER");
    MessageParcel data;
    data.WriteRawData(rawData, size);
    session->SetCallback(make_shared<SessionCallbackMock>());
    session->SetExposureCallback(make_shared<ExposureCallbackMock>());
    session->SetFocusCallback(make_shared<FocusCallbackMock>());
    session->SetSmoothZoomCallback(make_shared<SmoothZoomCallbackMock>());
    session->SetMacroStatusCallback(make_shared<MacroStatusCallbackMock>());
    session->SetMoonCaptureBoostStatusCallback(make_shared<MoonCaptureBoostStatusCallbackMock>());
    auto fdsCallback = make_shared<FeatureDetectionStatusCallbackMock>(data.ReadInt32() % 1);
    session->SetFeatureDetectionStatusCallback(fdsCallback);
    session->SetEffectSuggestionCallback(make_shared<EffectSuggestionCallbackMock>());
    session->SetARCallback(make_shared<ARCallbackMock>());
    session->SetAbilityCallback(make_shared<AbilityCallbackMock>());
    session->GetApplicationCallback();
    session->GetExposureCallback();
    session->GetFocusCallback();
    session->GetMacroStatusCallback();
    session->GetMoonCaptureBoostStatusCallback();
    session->GetFeatureDetectionStatusCallback();
    session->GetSmoothZoomCallback();
    session->GetARCallback();
}

void TestStabilization(sptr<CaptureSession> session, uint8_t *rawData, size_t size)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: ENTER");
    MessageParcel data;
    data.WriteRawData(rawData, size);
    session->GetSupportedStabilizationMode();
    vector<VideoStabilizationMode> modes;
    session->GetSupportedStabilizationMode(modes);
    data.RewindRead(0);
    VideoStabilizationMode stabilizationMode = static_cast<VideoStabilizationMode>(
        data.ReadInt32() % (VideoStabilizationMode::AUTO + NUM_TWO));
    session->IsVideoStabilizationModeSupported(stabilizationMode);
    session->IsVideoStabilizationModeSupported(stabilizationMode, g_isSupported);
    VideoStabilizationMode mode;
    session->GetActiveVideoStabilizationMode();
    session->GetActiveVideoStabilizationMode(mode);
    session->SetVideoStabilizationMode(stabilizationMode);
}

void TestFlash(sptr<CaptureSession> session, uint8_t *rawData, size_t size)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: ENTER");
    MessageParcel data;
    data.WriteRawData(rawData, size);
    session->GetSupportedFlashModes();
    vector<FlashMode> flashModes;
    session->GetSupportedFlashModes(flashModes);
    session->HasFlash();
    bool hasFlash;
    session->HasFlash(hasFlash);
    FlashMode flashMode = static_cast<FlashMode>(
        data.ReadInt32() % (FlashMode::FLASH_MODE_ALWAYS_OPEN + NUM_TWO));
    session->IsFlashModeSupported(flashMode);
    session->IsFlashModeSupported(flashMode, g_isSupported);
    session->GetFlashMode();
    session->GetFlashMode(flashMode);
    session->SetFlashMode(flashMode);
}

void TestProcess(sptr<CaptureSession> session, uint8_t *rawData, size_t size)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: ENTER");
    MessageParcel data;
    data.WriteRawData(rawData, size);
    static const size_t ITEM_CAP = 10;
    static const size_t DATA_CAP = 100;
    shared_ptr<OHOS::Camera::CameraMetadata> result = make_shared<OHOS::Camera::CameraMetadata>(ITEM_CAP, DATA_CAP);
    int32_t idata = data.ReadInt32();
    result->addEntry(OHOS_CONTROL_EXPOSURE_MODE, &idata, 1);
    result->addEntry(OHOS_CONTROL_FOCUS_MODE, &idata, 1);
    camera_rational_t cr = {data.ReadInt32(), data.ReadInt32()};
    result->addEntry(OHOS_STATUS_SENSOR_EXPOSURE_TIME, &cr, 1);
    result->addEntry(CAMERA_POSITION_FRONT, &idata, 1);
    result->addEntry(OHOS_CAMERA_CUSTOM_SNAPSHOT_DURATION, &idata, 1);
    result->addEntry(OHOS_CAMERA_MACRO_STATUS, &idata, 1);
    result->addEntry(OHOS_STATUS_MOON_CAPTURE_DETECTION, &idata, 1);
    result->addEntry(OHOS_CAMERA_EFFECT_SUGGESTION_TYPE, &idata, 1);
    session->ProcessAutoExposureUpdates(result);
    session->ProcessAutoFocusUpdates(result);
    session->ProcessAREngineUpdates(data.ReadUint64(), result);
    session->ProcessSnapshotDurationUpdates(data.ReadUint64(), result);
    session->ProcessMacroStatusChange(result);
    session->ProcessMoonCaptureBoostStatusChange(result);
    session->ProcessEffectSuggestionTypeUpdates(result);
}

void TestAperture(sptr<CaptureSession> session, uint8_t *rawData, size_t size)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: ENTER");
    MessageParcel data;
    data.WriteRawData(rawData, size);
    uint32_t moduleType;
    session->GetModuleType(moduleType);
    session->IsEffectSuggestionSupported();
    session->GetSupportedEffectSuggestionInfo();
    session->GetSupportedEffectSuggestionType();

    session->LockForControl();
    session->SetARMode(data.ReadBool());
    session->EnableEffectSuggestion(data.ReadBool());
    vector<EffectSuggestionStatus> effectSuggestionStatusList;
    size_t max = EffectSuggestionType::EFFECT_SUGGESTION_SUNRISE_SUNSET + NUM_TWO;
    for (size_t i = 0; i < data.ReadInt32() % max; i++) {
        EffectSuggestionStatus status = {
            static_cast<EffectSuggestionType>(data.ReadInt32() % max),
            data.ReadBool(),
        };
        effectSuggestionStatusList.push_back(status);
    }
    session->SetEffectSuggestionStatus(effectSuggestionStatusList);
    EffectSuggestionType effectSuggestionType = static_cast<EffectSuggestionType>(data.ReadInt32() % max);
    session->UpdateEffectSuggestion(effectSuggestionType, data.ReadBool());
    session->UnlockForControl();
}

void TestBeauty(sptr<CaptureSession> session, uint8_t *rawData, size_t size)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: ENTER");
    MessageParcel data;
    data.WriteRawData(rawData, size);
    session->GetSupportedFilters();
    session->GetSupportedBeautyTypes();
    BeautyType type = static_cast<BeautyType>(
        data.ReadInt32() % (BeautyType::SKIN_TONE + NUM_TWO));
    session->GetSupportedBeautyRange(type);
    session->GetBeauty(type);
    session->GetSupportedColorSpaces();
    ColorSpace colorSpace;
    session->GetActiveColorSpace(colorSpace);
    session->GetSupportedColorEffects();
    session->GetColorEffect();
    session->GetFilter();
    FilterType filter = static_cast<FilterType>(
        data.ReadInt32() % (FilterType::PINK + NUM_TWO));
    session->LockForControl();
    session->SetFilter(filter);
    session->SetColorSpace(colorSpace);
    ColorEffect colorEffect = static_cast<ColorEffect>(
        data.ReadInt32() % (ColorEffect::COLOR_EFFECT_BLACK_WHITE + NUM_TWO));
    session->SetColorEffect(colorEffect);
    BeautyType beautyType = static_cast<BeautyType>(
        data.ReadInt32() % (BeautyType::SKIN_TONE + NUM_TWO));
    session->SetBeautyValue(beautyType, data.ReadInt32());
    session->SetBeauty(type, data.ReadInt32());
    session->UnlockForControl();
}

void TestOther(sptr<CaptureSession> session, uint8_t *rawData, size_t size)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: ENTER");
    MessageParcel data;
    data.WriteRawData(rawData, size);
    session->IsMacroSupported();
    session->IsMovingPhotoSupported();
    session->IsMoonCaptureBoostSupported();
    SceneFeature feature = static_cast<SceneFeature>(
        data.ReadInt32() % (SceneFeature::FEATURE_ENUM_MAX + NUM_TWO));
    session->IsFeatureSupported(feature);
    vector<int32_t> sensitivityRange;
    session->GetSensorSensitivityRange(sensitivityRange);
    session->GetFeaturesMode();
    session->GetSubFeatureMods();
    session->IsSetEnableMacro();
    session->GetMetaOutput();
    session->GetMetadata();
    session->IsMovingPhotoEnabled();
    session->IsImageDeferred();
    session->CanSetFrameRateRange(data.ReadInt32(), data.ReadInt32(), curOutput);
    session->CanSetFrameRateRangeForOutput(data.ReadInt32(), data.ReadInt32(), curOutput);
    session->ExecuteAbilityChangeCallback();
    session->EnableFeature(feature, data.ReadBool());
    vector<int32_t> frameRateRange{data.ReadInt32(), data.ReadInt32()};
    session->SetFrameRateRange(frameRateRange);
    DeferredDeliveryImageType deferredType = static_cast<DeferredDeliveryImageType>(
        data.ReadInt32() % (DeferredDeliveryImageType::DELIVERY_VIDEO + NUM_TWO));
    session->EnableDeferredType(deferredType, data.ReadBool());
    session->SetUserId();
    session->EnableAutoHighQualityPhoto(data.ReadBool());
    session->EnableRawDelivery(data.ReadBool());
    auto curMinFps = data.ReadInt32();
    auto curMaxFps = data.ReadInt32();
    auto minFps = data.ReadInt32();
    auto maxFps = data.ReadInt32();
    session->CheckFrameRateRangeWithCurrentFps(curMinFps, curMaxFps, minFps, maxFps);
    session->CheckFrameRateRangeWithCurrentFps(NUM_20, NUM_20, NUM_40, NUM_40);
    session->CheckFrameRateRangeWithCurrentFps(NUM_40, NUM_40, NUM_20, NUM_20);
    ProfileSizeRatio sizeRatio = RATIO_1_1;
    session->GetMaxSizePhotoProfile(sizeRatio);
    session->GetPreconfigPreviewProfile();
    session->GetPreconfigPhotoProfile();
    session->GetPreconfigVideoProfile();
    session->IsVideoDeferred();
}

void TestOther2(sptr<CaptureSession> session, uint8_t *rawData, size_t size)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: ENTER");
    MessageParcel data;
    data.WriteRawData(rawData, size);
    camera_face_detect_mode_t t = static_cast<camera_face_detect_mode_t>(
        data.ReadInt32() % (camera_face_detect_mode_t::OHOS_CAMERA_FACE_DETECT_MODE_SIMPLE + NUM_TWO));
    set<camera_face_detect_mode_t> metadataObjectTypes;
    metadataObjectTypes.insert(t);
    session->SetCaptureMetadataObjectTypes(metadataObjectTypes);
    uint32_t ability = data.ReadUint32();
    session->VerifyAbility(ability);
    session->SetFocusDistance(data.ReadFloat());
    session->EnableMacro(data.ReadBool());
    session->EnableMovingPhoto(data.ReadBool());
    session->EnableMovingPhotoMirror(data.ReadBool(), data.ReadBool());
    session->EnableMoonCaptureBoost(data.ReadBool());
    session->SetSensorSensitivity(data.ReadUint32());
    int32_t wbValue = data.ReadInt32();
    session->GetManualWhiteBalance(wbValue);
    std::vector<std::vector<float>> supportedPhysicalApertures = {};
    session->GetSupportedPhysicalApertures(supportedPhysicalApertures);
    std::vector<float> apertures;
    session->GetSupportedVirtualApertures(apertures);
    float aperture = data.ReadFloat();
    session->GetVirtualAperture(aperture);
    session->SetVirtualAperture(aperture);
    session->GetPhysicalAperture(aperture);
    session->SetPhysicalAperture(aperture);
    session->UnlockForControl();
}

void TestSession(sptr<CaptureSession> session, uint8_t *rawData, size_t size)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: ENTER");
    sptr<CaptureInput> input = GetCameraInput(rawData, size);
    sptr<CaptureOutput> output = GetCaptureOutput(rawData, size);
    CHECK_ERROR_RETURN_LOG(!input || !output || !session, "CaptureSessionFuzzer: input/output/session is null");
    MessageParcel data;
    data.WriteRawData(rawData, size);
    session->SetMode(g_sceneMode);
    session->GetMode();
    PreconfigType preconfigType = static_cast<PreconfigType>(
        data.ReadInt32() % (PreconfigType::PRECONFIG_HIGH_QUALITY + NUM_TWO));
    ProfileSizeRatio preconfigRatio = static_cast<ProfileSizeRatio>(
        data.ReadInt32() % (ProfileSizeRatio::RATIO_16_9 + NUM_TWO));
    session->CanPreconfig(preconfigType, preconfigRatio);
    session->Preconfig(preconfigType, preconfigRatio);
    session->BeginConfig();
    session->CanAddInput(input);
    session->AddInput(input);
    session->CanAddOutput(output);
    session->AddOutput(output);
    session->RemoveInput(input);
    session->RemoveOutput(output);
    session->AddInput(input);
    session->AddOutput(output);
    session->AddSecureOutput(output);
    input->Open();
    session->CommitConfig();
    session->CheckSpecSearch();
    session->Start();
    curOutput = output.GetRefPtr();
    CaptureOutputType outputType = static_cast<CaptureOutputType>(
        data.ReadInt32() % (CaptureOutputType::CAPTURE_OUTPUT_TYPE_MAX + NUM_TWO));
    session->ValidateOutputProfile(profile, outputType);
    session->GeneratePreconfigProfiles(preconfigType, preconfigRatio);
    session->EnableAutoDeferredVideoEnhancement(data.ReadBool());
    session->ConfigurePhotoOutput(output);
}

void TestAdd(sptr<CaptureSession> session, uint8_t *rawData, size_t size)
{
    MessageParcel data;
    data.WriteRawData(rawData, size);
    std::vector<PortraitThemeType> supportedPortraitThemeTypes = {
        PortraitThemeType::NATURAL,
        PortraitThemeType::DELICATE,
        PortraitThemeType::STYLISH
    };
    session->SetPortraitThemeType(PortraitThemeType::NATURAL);
    session->GetSupportedPortraitThemeTypes(supportedPortraitThemeTypes);
    session->IsPortraitThemeSupported();
    std::vector<int32_t> supportedRotation = {0, 90, 180, 270};
    session->GetSupportedVideoRotations(supportedRotation);
    std::vector<float> depthFusionThreshold = {0.0};
    session->GetDepthFusionThreshold(depthFusionThreshold);
    session->EnableDepthFusion(data.ReadBool());
    session->IsDepthFusionEnabled();
    session->IsVideoRotationSupported();
    session->SetVideoRotation(data.ReadInt32());
    session->SetIsAutoSwitchDeviceStatus(data.ReadBool());
    FoldCallback *fold = new FoldCallback(session);
    fold->OnFoldStatusChanged(FoldStatus::UNKNOWN_FOLD);
    session->ExecuteAllFunctionsInMap();
    session->CreateAndSetFoldServiceCallback();
    shared_ptr<AutoDeviceSwitchCallback> autoDeviceSwitchCallback = nullptr;
    session->SwitchDevice();
    session->FindFrontCamera();
    session->SetAutoDeviceSwitchCallback(autoDeviceSwitchCallback);
    session->GetAutoDeviceSwitchCallback();
    session->StartVideoOutput();
    session->StopVideoOutput();
    session->SetUsage(UsageType::BOKEH, data.ReadBool());
    session->IsAutoDeviceSwitchSupported();
    session->EnableAutoDeviceSwitch(data.ReadBool());
    session->CreateCameraAbilityContainer();
}

void TestOther3(sptr<CaptureSession> session, uint8_t *rawData, size_t size)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: ENTER");
    MessageParcel data;
    data.WriteRawData(rawData, size);
    QualityPrioritization qualityPrioritization = static_cast<QualityPrioritization>(
        data.ReadInt32() % (QualityPrioritization::HIGH_QUALITY + NUM_TWO));
    session->LockForControl();
    session->SetQualityPrioritization(qualityPrioritization);
    session->EnableAutoAigcPhoto(data.ReadBool());
    session->ProcessProfilesAbilityId(g_sceneMode);
    Point point;
    session->CoordinateTransform(point);
    session->VerifyFocusCorrectness(point);
    vector<FocusRangeType> types;
    session->GetSupportedFocusRangeTypes(types);
    FocusRangeType focusRangeType = static_cast<FocusRangeType>(
       data.ReadInt32() % (FocusRangeType::FOCUS_RANGE_TYPE_AUTO + NUM_TWO));
    bool isSupported = data.ReadBool();
    session->IsFocusRangeTypeSupported(focusRangeType, isSupported);
    session->GetFocusRange(focusRangeType);
    session->SetFocusRange(focusRangeType);
    vector<FocusDrivenType> types1;
    session->GetSupportedFocusDrivenTypes(types1);
    FocusDrivenType focusDrivenType = static_cast<FocusDrivenType>(
        data.ReadInt32() % (FocusDrivenType::FOCUS_DRIVEN_TYPE_AUTO + NUM_TWO));
    session->IsFocusDrivenTypeSupported(focusDrivenType, isSupported);
    session->GetFocusDriven(focusDrivenType);
    session->SetFocusDriven(focusDrivenType);
    vector<ColorReservationType> types2;
    session->GetSupportedColorReservationTypes(types2);
    ColorReservationType colorReservationType = static_cast<ColorReservationType>(
        data.ReadInt32() % (ColorReservationType::COLOR_RESERVATION_TYPE_NONE + NUM_TWO));
    session->IsColorReservationTypeSupported(colorReservationType, isSupported);
    session->GetColorReservation(colorReservationType);
    session->SetColorReservation(colorReservationType);
    WhiteBalanceMode mode = AWB_MODE_LOCKED;
    session->SetWhiteBalanceMode(mode);
    std::vector<WhiteBalanceMode> supportedWhiteBalanceModes = {};
    session->GetSupportedWhiteBalanceModes(supportedWhiteBalanceModes);
    session->IsWhiteBalanceModeSupported(mode, isSupported);
    session->GetWhiteBalanceMode(mode);
    std::vector<int32_t> whiteBalanceRange = {};
    session->GetManualWhiteBalanceRange(whiteBalanceRange);
    session->IsManualWhiteBalanceSupported(isSupported);
    session->SetManualWhiteBalance(data.ReadInt32());
    session->SetWhiteBalanceMode(WhiteBalanceMode::AWB_MODE_AUTO);
    session->UnlockForControl();
}

} // namespace StreamRepeatStubFuzzer
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::CameraStandard::CaptureSessionFuzzer::Test(data, size);
    return 0;
}