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

#include <cstddef>
#include <cstdint>
#include <memory>

#include "accesstoken_kit.h"
#include "camera_input.h"
#include "camera_log.h"
#include "camera_photo_proxy.h"
#include "capture_input.h"
#include "capture_output.h"
#include "capture_scene_const.h"
#include "capture_session_fuzzer.h"
#include "input/camera_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "input/camera_manager_for_sys.h"
#include "message_parcel.h"
#include "nativetoken_kit.h"
#include "os_account_manager.h"
#include "preview_output.h"
#include "refbase.h"
#include "system_ability_definition.h"
#include "test_token.h"
#include "token_setproc.h"


namespace OHOS {
namespace CameraStandard {
namespace CaptureSessionFuzzer {
const int32_t LIMITSIZE = 309;
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

sptr<CaptureInput> GetCameraInput(FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: ENTER");
    auto manager = CameraManager::GetInstance();
    auto cameras = manager->GetSupportedCameras();
    CHECK_RETURN_RET_ELOG(cameras.size() < NUM_TWO, nullptr, "CaptureSessionFuzzer: GetSupportedCameras Error");
    camera = cameras[fdp.ConsumeIntegral<uint32_t>() % cameras.size()];
    CHECK_RETURN_RET_ELOG(!camera, nullptr, "CaptureSessionFuzzer: Camera is null Error");
    return manager->CreateCameraInput(camera);
}

sptr<CaptureOutput> CreatePreviewOutput(Profile previewProfile)
{
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    if (surface == nullptr) {
        return nullptr;
    }
    return manager_->CreatePreviewOutput(previewProfile, surface);
}

void Test(uint8_t* data, size_t size)
{
    CHECK_RETURN(size < LIMITSIZE);
    CHECK_RETURN_ELOG(!TestToken::GetAllCameraPermission(), "GetPermission error");
    manager_ = CameraManager::GetInstance();
    sptr<CaptureSessionForSys> session =
        CameraManagerForSys::GetInstance()->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    std::vector<sptr<CameraDevice>> cameras = manager_->GetCameraDeviceListFromServer();
    CHECK_RETURN_ELOG(cameras.empty(), "GetCameraDeviceListFromServer Error");
    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras[0]);
    CHECK_RETURN_ELOG(!input, "CreateCameraInput Error");
    input->Open();
    auto outputCapability = manager_->GetSupportedOutputCapability(cameras[0], 0);
    CHECK_RETURN_ELOG(!outputCapability, "GetSupportedOutputCapability Error");
    previewProfile_ = outputCapability->GetPreviewProfiles();
    CHECK_RETURN_ELOG(previewProfile_.empty(), "GetPreviewProfiles Error");
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
    FuzzedDataProvider fdp(data, size);
    TestCallback(session, fdp);
    TestExposure(session, fdp);
    TestFocus(session, fdp);
    TestZoom(session, fdp);
    TestStabilization(session, fdp);
    TestProcess(session, fdp);
    TestAperture(session, fdp);
    TestBeauty(session, fdp);
    TestOther(session, fdp);
    TestOther3(session, fdp);
    TestFlash(session, fdp);
    TestAdd(session, fdp);
    TestSession(session, fdp);
    TestOther2(session, fdp);
    session->Release();
    session->Stop();
}

sptr<PhotoOutput> GetCaptureOutput(FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: ENTER");
    auto manager = CameraManager::GetInstance();
    CHECK_RETURN_RET_ELOG(!manager, nullptr, "CaptureSessionFuzzer: CameraManager::GetInstance Error");
    CHECK_RETURN_RET_ELOG(!camera, nullptr, "CaptureSessionFuzzer: Camera is null Error");
    auto capability = manager->GetSupportedOutputCapability(camera, g_sceneMode);
    CHECK_RETURN_RET_ELOG(!capability, nullptr, "CaptureSessionFuzzer: GetSupportedOutputCapability Error");
    auto profiles = capability->GetPhotoProfiles();
    CHECK_RETURN_RET_ELOG(profiles.empty(), nullptr, "CaptureSessionFuzzer: GetPhotoProfiles empty");
    profile = profiles[fdp.ConsumeIntegral<uint32_t>() % profiles.size()];
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    CHECK_RETURN_RET_ELOG(!photoSurface, nullptr, "CaptureSessionFuzzer: create photoSurface Error");
    surface = photoSurface->GetProducer();
    CHECK_RETURN_RET_ELOG(!surface, nullptr, "CaptureSessionFuzzer: surface GetProducer Error");
    return manager->CreatePhotoOutput(profile, surface);
}

void TestExposure(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: ENTER");
    session->GetSupportedExposureModes();
    vector<ExposureMode> exposureModes;
    session->GetSupportedExposureModes(exposureModes);
    ExposureMode exposureMode = static_cast<ExposureMode>(
        fdp.ConsumeIntegral<int32_t>() % (ExposureMode::EXPOSURE_MODE_CONTINUOUS_AUTO + NUM_TWO));
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
    float exposureBias = fdp.ConsumeFloatingPoint<double>();
    session->SetExposureBias(exposureBias);
    vector<uint32_t> sensorExposureTimeRange;
    session->GetSensorExposureTimeRange(sensorExposureTimeRange);
    session->SetSensorExposureTime(fdp.ConsumeIntegral<uint32_t>());
    uint32_t sensorExposureTime;
    session->GetSensorExposureTime(sensorExposureTime);
    session->UnlockForControl();
}

void TestFocus(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: ENTER");
    session->GetSupportedFocusModes();
    vector<FocusMode> focusModes;
    session->GetSupportedFocusModes(focusModes);
    FocusMode focusMode = static_cast<FocusMode>(
        fdp.ConsumeIntegral<int32_t>() % (FocusMode::FOCUS_MODE_LOCKED + NUM_TWO));
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

void TestZoom(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: ENTER");
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
    float targetZoomRatio = fdp.ConsumeFloatingPoint<double>();
    uint32_t smoothZoomType = fdp.ConsumeIntegral<uint32_t>();
    session->SetSmoothZoom(targetZoomRatio, smoothZoomType);
    session->UnlockForControl();
}

void TestCallback(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: ENTER");
    session->SetCallback(make_shared<SessionCallbackMock>());
    session->SetExposureCallback(make_shared<ExposureCallbackMock>());
    session->SetFocusCallback(make_shared<FocusCallbackMock>());
    session->SetSmoothZoomCallback(make_shared<SmoothZoomCallbackMock>());
    session->SetMacroStatusCallback(make_shared<MacroStatusCallbackMock>());
    session->SetMoonCaptureBoostStatusCallback(make_shared<MoonCaptureBoostStatusCallbackMock>());
    auto fdsCallback = make_shared<FeatureDetectionStatusCallbackMock>(fdp.ConsumeBool());
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

void TestStabilization(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: ENTER");
    session->GetSupportedStabilizationMode();
    vector<VideoStabilizationMode> modes;
    session->GetSupportedStabilizationMode(modes);
    VideoStabilizationMode stabilizationMode = static_cast<VideoStabilizationMode>(
        fdp.ConsumeIntegral<int32_t>() % (VideoStabilizationMode::AUTO + NUM_TWO));
    session->IsVideoStabilizationModeSupported(stabilizationMode);
    session->IsVideoStabilizationModeSupported(stabilizationMode, g_isSupported);
    VideoStabilizationMode mode;
    session->GetActiveVideoStabilizationMode();
    session->GetActiveVideoStabilizationMode(mode);
    session->SetVideoStabilizationMode(stabilizationMode);
}

void TestFlash(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: ENTER");
    session->GetSupportedFlashModes();
    vector<FlashMode> flashModes;
    session->GetSupportedFlashModes(flashModes);
    session->HasFlash();
    bool hasFlash;
    session->HasFlash(hasFlash);
    FlashMode flashMode = static_cast<FlashMode>(
        fdp.ConsumeIntegral<int32_t>() % (FlashMode::FLASH_MODE_ALWAYS_OPEN + NUM_TWO));
    session->IsFlashModeSupported(flashMode);
    session->IsFlashModeSupported(flashMode, g_isSupported);
    session->GetFlashMode();
    session->GetFlashMode(flashMode);
    session->SetFlashMode(flashMode);
}

void TestProcess(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: ENTER");
    static const size_t ITEM_CAP = 10;
    static const size_t DATA_CAP = 100;
    shared_ptr<OHOS::Camera::CameraMetadata> result = make_shared<OHOS::Camera::CameraMetadata>(ITEM_CAP, DATA_CAP);
    int32_t idata = fdp.ConsumeIntegral<int32_t>();
    result->addEntry(OHOS_CONTROL_EXPOSURE_MODE, &idata, 1);
    result->addEntry(OHOS_CONTROL_FOCUS_MODE, &idata, 1);
    camera_rational_t cr = {fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>()};
    result->addEntry(OHOS_STATUS_SENSOR_EXPOSURE_TIME, &cr, 1);
    result->addEntry(CAMERA_POSITION_FRONT, &idata, 1);
    result->addEntry(OHOS_CAMERA_CUSTOM_SNAPSHOT_DURATION, &idata, 1);
    result->addEntry(OHOS_CAMERA_MACRO_STATUS, &idata, 1);
    result->addEntry(OHOS_STATUS_MOON_CAPTURE_DETECTION, &idata, 1);
    result->addEntry(OHOS_CAMERA_EFFECT_SUGGESTION_TYPE, &idata, 1);
    session->ProcessAutoExposureUpdates(result);
    session->ProcessAutoFocusUpdates(result);
    session->ProcessAREngineUpdates(fdp.ConsumeIntegral<uint64_t>(), result);
    session->ProcessSnapshotDurationUpdates(fdp.ConsumeIntegral<uint64_t>(), result);
    session->ProcessMacroStatusChange(result);
    session->ProcessMoonCaptureBoostStatusChange(result);
    session->ProcessEffectSuggestionTypeUpdates(result);
}

void TestAperture(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: ENTER");
    uint32_t moduleType;
    session->GetModuleType(moduleType);
    session->IsEffectSuggestionSupported();
    session->GetSupportedEffectSuggestionInfo();
    session->GetSupportedEffectSuggestionType();

    session->LockForControl();
    session->SetARMode(fdp.ConsumeBool());
    session->EnableEffectSuggestion(fdp.ConsumeBool());
    vector<EffectSuggestionStatus> effectSuggestionStatusList;
    size_t max = EffectSuggestionType::EFFECT_SUGGESTION_SUNRISE_SUNSET + NUM_TWO;
    for (size_t i = 0; i < fdp.ConsumeIntegral<int32_t>() % max; i++) {
        EffectSuggestionStatus status = {
            static_cast<EffectSuggestionType>(fdp.ConsumeIntegral<int32_t>() % max),
            fdp.ConsumeBool(),
        };
        effectSuggestionStatusList.push_back(status);
    }
    session->SetEffectSuggestionStatus(effectSuggestionStatusList);
    EffectSuggestionType effectSuggestionType = static_cast<EffectSuggestionType>(fdp.ConsumeIntegral<int32_t>() % max);
    session->UpdateEffectSuggestion(effectSuggestionType, fdp.ConsumeBool());
    session->UnlockForControl();
}

void TestBeauty(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: ENTER");
    session->GetSupportedFilters();
    session->GetSupportedBeautyTypes();
    BeautyType type = static_cast<BeautyType>(
        fdp.ConsumeIntegral<int32_t>() % (BeautyType::SKIN_TONE + NUM_TWO));
    session->GetSupportedBeautyRange(type);
    session->GetBeauty(type);
    session->GetSupportedColorSpaces();
    ColorSpace colorSpace;
    session->GetActiveColorSpace(colorSpace);
    session->GetSupportedColorEffects();
    session->GetColorEffect();
    session->GetFilter();
    FilterType filter = static_cast<FilterType>(
        fdp.ConsumeIntegral<int32_t>() % (FilterType::PINK + NUM_TWO));
    session->LockForControl();
    session->SetFilter(filter);
    session->SetColorSpace(colorSpace);
    ColorEffect colorEffect = static_cast<ColorEffect>(
        fdp.ConsumeIntegral<int32_t>() % (ColorEffect::COLOR_EFFECT_BLACK_WHITE + NUM_TWO));
    session->SetColorEffect(colorEffect);
    BeautyType beautyType = static_cast<BeautyType>(
        fdp.ConsumeIntegral<int32_t>() % (BeautyType::SKIN_TONE + NUM_TWO));
    session->SetBeautyValue(beautyType, fdp.ConsumeIntegral<int32_t>());
    session->SetBeauty(type, fdp.ConsumeIntegral<int32_t>());
    session->UnlockForControl();
}

void TestOther(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: ENTER");
    session->IsMacroSupported();
    session->IsMovingPhotoSupported();
    session->IsMoonCaptureBoostSupported();
    SceneFeature feature = static_cast<SceneFeature>(
        fdp.ConsumeIntegral<int32_t>() % (SceneFeature::FEATURE_ENUM_MAX + NUM_TWO));
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
    session->CanSetFrameRateRange(fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>(), curOutput);
    session->CanSetFrameRateRangeForOutput(fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>(), curOutput);
    session->ExecuteAbilityChangeCallback();
    session->EnableFeature(feature, fdp.ConsumeBool());
    vector<int32_t> frameRateRange{fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>()};
    session->SetFrameRateRange(frameRateRange);
    DeferredDeliveryImageType deferredType = static_cast<DeferredDeliveryImageType>(
        fdp.ConsumeIntegral<int32_t>() % (DeferredDeliveryImageType::DELIVERY_VIDEO + NUM_TWO));
    session->EnableDeferredType(deferredType, fdp.ConsumeBool());
    session->SetUserId();
    session->EnableAutoHighQualityPhoto(fdp.ConsumeBool());
    session->EnableRawDelivery(fdp.ConsumeBool());
    auto curMinFps = fdp.ConsumeIntegral<int32_t>();
    auto curMaxFps = fdp.ConsumeIntegral<int32_t>();
    auto minFps = fdp.ConsumeIntegral<int32_t>();
    auto maxFps = fdp.ConsumeIntegral<int32_t>();
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

void TestOther2(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: ENTER");
    camera_face_detect_mode_t t = static_cast<camera_face_detect_mode_t>(
        fdp.ConsumeIntegral<int32_t>() % (camera_face_detect_mode_t::OHOS_CAMERA_FACE_DETECT_MODE_SIMPLE + NUM_TWO));
    set<camera_face_detect_mode_t> metadataObjectTypes;
    metadataObjectTypes.insert(t);
    session->SetCaptureMetadataObjectTypes(metadataObjectTypes);
    uint32_t ability = fdp.ConsumeIntegral<uint32_t>();
    session->VerifyAbility(ability);
    session->SetFocusDistance(fdp.ConsumeFloatingPoint<double>());
    session->EnableMacro(fdp.ConsumeBool());
    session->EnableMovingPhoto(fdp.ConsumeBool());
    session->EnableMovingPhotoMirror(fdp.ConsumeBool(), fdp.ConsumeBool());
    session->EnableMoonCaptureBoost(fdp.ConsumeBool());
    session->SetSensorSensitivity(fdp.ConsumeIntegral<uint32_t>());
    int32_t wbValue = fdp.ConsumeIntegral<int32_t>();
    session->GetManualWhiteBalance(wbValue);
    std::vector<std::vector<float>> supportedPhysicalApertures = {};
    session->GetSupportedPhysicalApertures(supportedPhysicalApertures);
    std::vector<float> apertures;
    session->GetSupportedVirtualApertures(apertures);
    float aperture = fdp.ConsumeFloatingPoint<double>();
    session->GetVirtualAperture(aperture);
    session->SetVirtualAperture(aperture);
    session->GetPhysicalAperture(aperture);
    session->SetPhysicalAperture(aperture);
    session->UnlockForControl();
}

void TestSession(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: ENTER");
    sptr<CaptureInput> input = GetCameraInput(fdp);
    sptr<CaptureOutput> output = GetCaptureOutput(fdp);
    CHECK_RETURN_ELOG(!input || !output || !session, "CaptureSessionFuzzer: input/output/session is null");
    session->SetMode(g_sceneMode);
    session->GetMode();
    PreconfigType preconfigType = static_cast<PreconfigType>(
        fdp.ConsumeIntegral<int32_t>() % (PreconfigType::PRECONFIG_HIGH_QUALITY + NUM_TWO));
    ProfileSizeRatio preconfigRatio = static_cast<ProfileSizeRatio>(
        fdp.ConsumeIntegral<int32_t>() % (ProfileSizeRatio::RATIO_16_9 + NUM_TWO));
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
        fdp.ConsumeIntegral<int32_t>() % (CaptureOutputType::CAPTURE_OUTPUT_TYPE_MAX + NUM_TWO));
    session->ValidateOutputProfile(profile, outputType);
    session->GeneratePreconfigProfiles(preconfigType, preconfigRatio);
    session->EnableAutoDeferredVideoEnhancement(fdp.ConsumeBool());
    session->ConfigurePhotoOutput(output);
}

void TestAdd(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
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
    session->EnableDepthFusion(fdp.ConsumeBool());
    session->IsDepthFusionEnabled();
    session->IsVideoRotationSupported();
    session->SetVideoRotation(fdp.ConsumeIntegral<int32_t>());
    session->SetIsAutoSwitchDeviceStatus(fdp.ConsumeBool());
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
    session->SetUsage(UsageType::BOKEH, fdp.ConsumeBool());
    session->IsAutoDeviceSwitchSupported();
    session->EnableAutoDeviceSwitch(fdp.ConsumeBool());
    session->CreateCameraAbilityContainer();
}

void TestOther3(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: ENTER");
    QualityPrioritization qualityPrioritization = static_cast<QualityPrioritization>(
        fdp.ConsumeIntegral<int32_t>() % (QualityPrioritization::HIGH_QUALITY + NUM_TWO));
    session->LockForControl();
    session->SetQualityPrioritization(qualityPrioritization);
    session->EnableAutoAigcPhoto(fdp.ConsumeBool());
    session->ProcessProfilesAbilityId(g_sceneMode);
    Point point;
    session->CoordinateTransform(point);
    session->VerifyFocusCorrectness(point);
    vector<FocusRangeType> types;
    session->GetSupportedFocusRangeTypes(types);
    FocusRangeType focusRangeType = static_cast<FocusRangeType>(
       fdp.ConsumeIntegral<int32_t>() % (FocusRangeType::FOCUS_RANGE_TYPE_AUTO + NUM_TWO));
    bool isSupported = fdp.ConsumeBool();
    session->IsFocusRangeTypeSupported(focusRangeType, isSupported);
    session->GetFocusRange(focusRangeType);
    session->SetFocusRange(focusRangeType);
    vector<FocusDrivenType> types1;
    session->GetSupportedFocusDrivenTypes(types1);
    FocusDrivenType focusDrivenType = static_cast<FocusDrivenType>(
        fdp.ConsumeIntegral<int32_t>() % (FocusDrivenType::FOCUS_DRIVEN_TYPE_AUTO + NUM_TWO));
    session->IsFocusDrivenTypeSupported(focusDrivenType, isSupported);
    session->GetFocusDriven(focusDrivenType);
    session->SetFocusDriven(focusDrivenType);
    vector<ColorReservationType> types2;
    session->GetSupportedColorReservationTypes(types2);
    ColorReservationType colorReservationType = static_cast<ColorReservationType>(
        fdp.ConsumeIntegral<int32_t>() % (ColorReservationType::COLOR_RESERVATION_TYPE_NONE + NUM_TWO));
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
    session->SetManualWhiteBalance(fdp.ConsumeIntegral<int32_t>());
    session->SetWhiteBalanceMode(WhiteBalanceMode::AWB_MODE_AUTO);
    session->UnlockForControl();
}

} // namespace StreamRepeatStubFuzzer
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::CameraStandard::CaptureSessionFuzzer::Test(data, size);
    return 0;
}