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
#include "video_output.h"
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
#include "input/camera_manager_for_sys.h"
#include "system_ability_definition.h"
#include "os_account_manager.h"
#include "ipc_skeleton.h"
#include "test_token.h"
#include "camera_device_utils.h"
#include "surface.h"
#include "output/video_output.h"
#include "iconsumer_surface.h"

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

void TestCalculateImageRotation(FuzzedDataProvider& fdp)
{
    auto manager = CameraManager::GetInstance();
    auto cameras = manager->GetSupportedCameras();
    CHECK_RETURN_ELOG(cameras.size() < NUM_TWO, "CaptureSessionFuzzer: GetSupportedCameras Error");
    camera = cameras[fdp.ConsumeIntegral<uint32_t>() % cameras.size()];
    CHECK_RETURN_ELOG(!camera, "CaptureSessionFuzzer: Camera is null Error");
    sptr<CaptureInput> input = manager->CreateCameraInput(camera);
    int32_t imageRotation = fdp.ConsumeIntegral<int32_t>();
    bool isMirror = fdp.ConsumeBool();
    CameraDeviceUtils ::CalculateImageRotation(input, imageRotation, isMirror);
}
void Test(uint8_t* data, size_t size)
{
    CHECK_RETURN(size < LIMITSIZE);
    CHECK_RETURN_ELOG(!TestToken().GetAllCameraPermission(), "GetPermission error");
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
    TestCalculateImageRotation(fdp);
    TestCallback(session, fdp);
    TestExposure(session, fdp);
    TestFocus(session, fdp);
    TestZoom(session, fdp);
    TestStabilization(session, fdp);
    TestFlash(session, fdp);
    TestAperture(session, fdp);
    TestBeauty(session, fdp);
    TestOther(session, fdp); // 10
    TestOther2(session, fdp);
    TestOther3(session, fdp);
    TestProcess(session, fdp);
    TestUncoveredFunctions(session, fdp);
    TestOISFunctions(session, fdp);
    TestOtherUncoveredFunctions(session, fdp); // 16
    TestMovieFileOutputFunctions(session, fdp);
    TestStreamNumFunctions(session, fdp);
    TestExposureSceneAndSmartCapture(session, fdp);
    TestISO(session, fdp); // 22
    TestExposureExtra(session, fdp);
    TestFocusTracking(session, fdp);
    TestLowLight(session, fdp);
    TestColorStyleExtra(session, fdp);
    TestComposition(session, fdp);
    TestControlRing(session, fdp);
    TestLcdFlashTripod(session, fdp);
    TestWhiteBalanceGains(session, fdp);
    TestStarburst(session, fdp);
    TestParameters(session, fdp);
    TestExtra(session, fdp);
    TestCalculationHelper(fdp);
    TestPreconfigProfiles(session, fdp);
    TestOfflinePhoto(session, fdp);
    TestMovieFileOutput(session, fdp);
    TestDeviceCapabilityChange(session, fdp);
    TestCameraDelayClose(session, fdp);
    TestErrorCallback(session, fdp);
    TestCameraServerDied(session, fdp);
    TestVideoOutputConfiguration(session, fdp);
    TestStreamModeManagement(session, fdp);
    TestCallbackManagement(session, fdp);
    TestVideoStabilization(session, fdp);
    TestOISMode(session, fdp);
    TestOnResultReceived(session, fdp);
    TestSetPreviewRotation(session, fdp);
    TestSession(session, fdp);
    TestAdd(session, fdp); //51
    session->Stop();
    session->Release();
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
    float exposureBias = fdp.ConsumeFloatingPoint<float>();
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
    bool isSupported = false;
    session->IsZoomCenterPointSupported(isSupported);
    Point zoomCenterPoint;
    session->GetZoomCenterPoint(zoomCenterPoint);
    session->LockForControl();
    session->SetZoomRatio(zoomRatio);
    session->PrepareZoom();
    session->UnPrepareZoom();
    float targetZoomRatio = fdp.ConsumeFloatingPoint<float>();
    uint32_t smoothZoomType = fdp.ConsumeIntegral<uint32_t>();
    session->SetSmoothZoom(targetZoomRatio, smoothZoomType);
    zoomCenterPoint.x = fdp.ConsumeFloatingPoint<float>();
    zoomCenterPoint.y = fdp.ConsumeFloatingPoint<float>();
    session->SetZoomCenterPoint(zoomCenterPoint);
    session->UnlockForControl();
}

void TestCallback(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: ENTER");
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
    session->SetARMode(fdp.ConsumeIntegral<uint8_t>());
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
    session->SetFocusDistance(fdp.ConsumeFloatingPoint<float>());
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
    float aperture = fdp.ConsumeFloatingPoint<float>();
    session->GetVirtualAperture(aperture);
    session->SetVirtualAperture(aperture);
    session->GetPhysicalAperture(aperture);
    session->SetPhysicalAperture(aperture);
    bool isSupported = fdp.ConsumeBool();
    session->IsColorStyleSupported(isSupported);
    std::vector<ColorStyleSetting> defaultColorStyles;
    session->GetDefaultColorStyleSettings(defaultColorStyles);
    ColorStyleSetting styleSetting;
    styleSetting.type = static_cast<ColorStyleType>(1);
    styleSetting.hue = 1;
    styleSetting.saturation = 1;
    styleSetting.tone = 1;
    session->SetColorStyleSetting(styleSetting);
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
    session->EnableAutoAigcPhoto(fdp.ConsumeBool());
    session->EnableAutoMotionBoostDelivery(fdp.ConsumeBool());
    session->EnableAutoBokehDataDelivery(fdp.ConsumeBool());
    session->LockForControl();
    session->SetQualityPrioritization(qualityPrioritization);
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

void TestUncoveredFunctions(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: TestUncoveredFunctions ENTER");

    session->SetPressureCallback(make_shared<PressureCallbackMock>());
    session->SetControlCenterEffectStatusCallback(make_shared<ControlCenterEffectCallbackMock>());
    session->SetCameraSwitchRequestCallback(make_shared<CameraSwitchRequestCallbackMock>());

    static const size_t ITEM_CAP = 10;
    static const size_t DATA_CAP = 100;
    shared_ptr<OHOS::Camera::CameraMetadata> result = make_shared<OHOS::Camera::CameraMetadata>(ITEM_CAP, DATA_CAP);

    PressureStatus pressureStatus = static_cast<PressureStatus>(fdp.ConsumeIntegral<int32_t>());
    auto pressureCallback = session->GetPressureCallback();
    if (pressureCallback) {
        pressureCallback->OnPressureStatusChanged(pressureStatus);
    }

    ControlCenterStatusInfo controlCenterStatusInfo;
    controlCenterStatusInfo.effectType = static_cast<ControlCenterEffectType>(fdp.ConsumeIntegral<int32_t>() % 3);
    controlCenterStatusInfo.isActive = fdp.ConsumeBool();
    auto controlCenterCallback = session->GetControlCenterEffectCallback();
    if (controlCenterCallback) {
        controlCenterCallback->OnControlCenterEffectStatusChanged(controlCenterStatusInfo);
    }

    auto cameraSwitchCallback = session->GetCameraSwitchRequestCallback();
    if (cameraSwitchCallback) {
        std::string cameraId = "camera_" + std::to_string(fdp.ConsumeIntegral<uint32_t>());
        cameraSwitchCallback->OnAppCameraSwitch(cameraId);
    }

    session->UnSetPressureCallback();
    session->UnSetControlCenterEffectStatusCallback();
    session->UnSetCameraSwitchRequestCallback();
}

void TestOISFunctions(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: TestOISFunctions ENTER");

    OISMode oisMode = static_cast<OISMode>(fdp.ConsumeIntegral<int32_t>() % (OIS_MODE_CUSTOM + 2));
    bool isSupported = false;

    session->IsOISModeSupported(oisMode, isSupported);

    OISMode currentOISMode;
    session->GetCurrentOISMode(currentOISMode);

    session->LockForControl();
    session->SetOISMode(oisMode);
    session->UnlockForControl();

    std::vector<float> oisBiasRange;
    float oisStep = 0.0f;
    session->GetSupportedOISBiasRangeAndStep(OIS_AXES_PITCH, oisBiasRange, oisStep);
    session->GetSupportedOISBiasRangeAndStep(OIS_AXES_YAW, oisBiasRange, oisStep);
    session->GetSupportedOISBiasRangeAndStep(OIS_AXES_ROLL, oisBiasRange, oisStep);

    float pitchBias = fdp.ConsumeFloatingPoint<float>();
    float yawBias = fdp.ConsumeFloatingPoint<float>();
    float rollBias = fdp.ConsumeFloatingPoint<float>();
    session->SetOISModeCustom(pitchBias, yawBias, rollBias);

    float currentBias;
    session->GetCurrentCustomOISBias(OIS_AXES_PITCH, currentBias);
    session->GetCurrentCustomOISBias(OIS_AXES_YAW, currentBias);
    session->GetCurrentCustomOISBias(OIS_AXES_ROLL, currentBias);
}

void TestOtherUncoveredFunctions(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: TestOtherUncoveredFunctions ENTER");
    std::shared_ptr<IsoInfoSyncCallback> isoInfoCallback = std::make_shared<IsoInfoSyncCallbackMock>();
    session->SetIsoInfoCallback(isoInfoCallback);

    session->EnableAutoMotionBoostDelivery(fdp.ConsumeBool());
    session->EnableAutoBokehDataDelivery(fdp.ConsumeBool());
}

void TestMovieFileOutputFunctions(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: TestMovieFileOutputFunctions ENTER");

    auto manager = CameraManager::GetInstance();
    auto cameras = manager->GetSupportedCameras();
    CHECK_RETURN_ELOG(cameras.size() < NUM_TWO, "CaptureSessionFuzzer: GetSupportedCameras Error");

    auto camera = cameras[fdp.ConsumeIntegral<uint32_t>() % cameras.size()];
    CHECK_RETURN_ELOG(!camera, "CaptureSessionFuzzer: Camera is null Error");

    auto capability = manager->GetSupportedOutputCapability(camera, 0);
    CHECK_RETURN_ELOG(!capability, "CaptureSessionFuzzer: GetSupportedOutputCapability Error");

    auto videoProfiles = capability->GetVideoProfiles();
    CHECK_RETURN_ELOG(videoProfiles.empty(), "CaptureSessionFuzzer: GetVideoProfiles empty");

    auto videoProfile = videoProfiles[fdp.ConsumeIntegral<uint32_t>() % videoProfiles.size()];
    sptr<Surface> videoSurface = Surface::CreateSurfaceAsConsumer();
    CHECK_RETURN_ELOG(!videoSurface, "CaptureSessionFuzzer: create videoSurface Error");

    sptr<VideoOutput> videoOutput = manager->CreateVideoOutput(videoProfile, videoSurface);
    CHECK_RETURN_ELOG(!videoOutput, "CaptureSessionFuzzer: CreateVideoOutput Error");

    session->BeginConfig();
    sptr<CaptureOutput> output = videoOutput;
    session->AddOutput(output);
    session->CommitConfig();

    session->LockForControl();
    session->SetGuessMode(static_cast<SceneMode>(fdp.ConsumeIntegral<int32_t>() % (SceneMode::VIDEO + 2)));
    session->UnlockForControl();
}

void TestStreamNumFunctions(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: TestStreamNumFunctions ENTER");

    CaptureOutputType outputType = static_cast<CaptureOutputType>(
        fdp.ConsumeIntegral<int32_t>() % (CaptureOutputType::CAPTURE_OUTPUT_TYPE_MAX + 2));

    session->CheckStreamsNum(outputType);

    session->LockForControl();
    session->FillStreamsModeNumMap();
    session->UnlockForControl();
}

void TestExposureSceneAndSmartCapture(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: TestExposureSceneAndSmartCapture ENTER");

    float exposureBiasStep;
    session->GetExposureBiasStep(exposureBiasStep);

    bool isFocusDistanceSupported;
    session->IsFocusDistanceSupported(isFocusDistanceSupported);
}

void TestCalculationHelper(FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: TestCalculationHelper ENTER");

    std::vector<float> vectorA;
    std::vector<float> vectorB;

    size_t size = fdp.ConsumeIntegral<size_t>() % 10 + 1;
    for (size_t i = 0; i < size; i++) {
        vectorA.push_back(fdp.ConsumeFloatingPoint<float>());
        vectorB.push_back(fdp.ConsumeFloatingPoint<float>());
    }

    float epsilon = fdp.ConsumeFloatingPoint<float>();

    bool result = OHOS::CameraStandard::CalculationHelper::AreVectorsEqual(vectorA, vectorB, epsilon);
    MEDIA_INFO_LOG("CalculationHelper::AreVectorsEqual result: %d", result);
}

void TestPreconfigProfiles(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: TestPreconfigProfiles ENTER");

    ProfileSizeRatio sizeRatio = static_cast<ProfileSizeRatio>(
        fdp.ConsumeIntegral<int32_t>() % (ProfileSizeRatio::RATIO_16_9 + 2));

    auto maxPhotoProfile = session->GetMaxSizePhotoProfile(sizeRatio);
    if (maxPhotoProfile) {
        MEDIA_INFO_LOG("GetMaxSizePhotoProfile success: %dx%d",
            maxPhotoProfile->size_.width, maxPhotoProfile->size_.height);
    }

    auto previewProfile = session->GetPreconfigPreviewProfile();
    if (previewProfile) {
        MEDIA_INFO_LOG("GetPreconfigPreviewProfile success: %dx%d",
            previewProfile->size_.width, previewProfile->size_.height);
    }

    auto photoProfile = session->GetPreconfigPhotoProfile();
    if (photoProfile) {
        MEDIA_INFO_LOG("GetPreconfigPhotoProfile success: %dx%d",
            photoProfile->size_.width, photoProfile->size_.height);
    }

    auto videoProfile = session->GetPreconfigVideoProfile();
    if (videoProfile) {
        MEDIA_INFO_LOG("GetPreconfigVideoProfile success: %dx%d",
            videoProfile->size_.width, videoProfile->size_.height);
    }
}

void TestOfflinePhoto(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: TestOfflinePhoto ENTER");

    session->EnableOfflinePhoto();
}

void TestMovieFileOutput(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: TestMovieFileOutput ENTER");

    auto manager = CameraManager::GetInstance();
    auto cameras = manager->GetSupportedCameras();
    CHECK_RETURN_ELOG(cameras.size() < NUM_TWO, "CaptureSessionFuzzer: GetSupportedCameras Error");

    auto camera = cameras[fdp.ConsumeIntegral<uint32_t>() % cameras.size()];
    CHECK_RETURN_ELOG(!camera, "CaptureSessionFuzzer: Camera is null Error");

    auto capability = manager->GetSupportedOutputCapability(camera, 0);
    CHECK_RETURN_ELOG(!capability, "CaptureSessionFuzzer: GetSupportedOutputCapability Error");

    auto videoProfiles = capability->GetVideoProfiles();
    CHECK_RETURN_ELOG(videoProfiles.empty(), "CaptureSessionFuzzer: GetVideoProfiles empty");

    auto videoProfile = videoProfiles[fdp.ConsumeIntegral<uint32_t>() % videoProfiles.size()];
    sptr<IConsumerSurface> videoSurface = IConsumerSurface::Create();
    CHECK_RETURN_ELOG(!videoSurface, "CaptureSessionFuzzer: create videoSurface Error");

    auto surface = videoSurface->GetProducer();
    CHECK_RETURN_ELOG(!surface, "CaptureSessionFuzzer: surface GetProducer Error");

    session->BeginConfig();
    session->CommitConfig();
}

void TestDeviceCapabilityChange(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: TestDeviceCapabilityChange ENTER");

    bool isDeviceCapabilityChanged = session->GetDeviceCapabilityChangeStatus();
    MEDIA_INFO_LOG("GetDeviceCapabilityChangeStatus: %d", isDeviceCapabilityChanged);

    session->SetDeviceCapabilityChangeStatus(fdp.ConsumeBool());
}

void TestCameraDelayClose(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: TestCameraDelayClose ENTER");

    auto manager = CameraManager::GetInstance();
    auto cameras = manager->GetSupportedCameras();
    CHECK_RETURN_ELOG(cameras.size() < NUM_TWO, "CaptureSessionFuzzer: GetSupportedCameras Error");

    auto camera = cameras[fdp.ConsumeIntegral<uint32_t>() % cameras.size()];
    CHECK_RETURN_ELOG(!camera, "CaptureSessionFuzzer: Camera is null Error");

    sptr<CaptureInput> input = manager->CreateCameraInput(camera);
    CHECK_RETURN_ELOG(!input, "CaptureSessionFuzzer: CreateCameraInput Error");

    sptr<CameraInput> camInput = (sptr<CameraInput>&)input;
    camInput->SetClosedelayedState(true);
    camInput->cameraIDforcloseDelayed_ = camera->GetID();

    session->BeginConfig();
    session->AddInput(input);
    session->CommitConfig();
}

void TestErrorCallback(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: TestErrorCallback ENTER");

    auto appCallback = std::make_shared<MockSessionCallback>();
    session->SetCallback(appCallback);
}

void TestCameraServerDied(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: TestCameraServerDied ENTER");

    auto appCallback = std::make_shared<MockSessionCallback>();
    session->SetCallback(appCallback);

    pid_t pid = fdp.ConsumeIntegral<pid_t>();
    session->CameraServerDied(pid);
}

void TestVideoOutputConfiguration(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: TestVideoOutputConfiguration ENTER");

    auto manager = CameraManager::GetInstance();
    auto cameras = manager->GetSupportedCameras();
    CHECK_RETURN_ELOG(cameras.size() < NUM_TWO, "CaptureSessionFuzzer: GetSupportedCameras Error");

    auto camera = cameras[fdp.ConsumeIntegral<uint32_t>() % cameras.size()];
    CHECK_RETURN_ELOG(!camera, "CaptureSessionFuzzer: Camera is null Error");

    auto capability = manager->GetSupportedOutputCapability(camera, 0);
    CHECK_RETURN_ELOG(!capability, "CaptureSessionFuzzer: GetSupportedOutputCapability Error");

    auto videoProfiles = capability->GetVideoProfiles();
    CHECK_RETURN_ELOG(videoProfiles.empty(), "CaptureSessionFuzzer: GetVideoProfiles empty");

    auto videoProfile = videoProfiles[fdp.ConsumeIntegral<uint32_t>() % videoProfiles.size()];
    sptr<Surface> videoSurface = Surface::CreateSurfaceAsConsumer();
    CHECK_RETURN_ELOG(!videoSurface, "CaptureSessionFuzzer: create videoSurface Error");

    auto surface = videoSurface->GetProducer();
    CHECK_RETURN_ELOG(!surface, "CaptureSessionFuzzer: surface GetProducer Error");

    sptr<VideoOutput> videoOutput = manager->CreateVideoOutput(videoProfile, videoSurface);
    CHECK_RETURN_ELOG(!videoOutput, "CaptureSessionFuzzer: VideoOutput Create Error");

    session->BeginConfig();
    sptr<CaptureOutput> output = videoOutput;
    session->AddOutput(output);
    session->CommitConfig();
}

void TestStreamModeManagement(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: TestStreamModeManagement ENTER");

    CaptureOutputType outputType = static_cast<CaptureOutputType>(
        fdp.ConsumeIntegral<int32_t>() % (CAPTURE_OUTPUT_TYPE_MAX + 1));

    bool hasConflicting = session->HasConflictingOutput(outputType);
    MEDIA_INFO_LOG("HasConflictingOutput: %d", hasConflicting);

    bool checkStreamNum = session->CheckStreamNum(outputType);
    MEDIA_INFO_LOG("CheckStreamNum: %d", checkStreamNum);
}

void TestCallbackManagement(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: TestCallbackManagement ENTER");

    auto appCallback = std::make_shared<MockSessionCallback>();
    session->SetCallback(appCallback);

    auto pressureCallback = std::make_shared<MockPressureCallback>();
    session->SetPressureCallback(pressureCallback);
    session->UnSetPressureCallback();

    auto controlCenterCallback = std::make_shared<MockControlCenterEffectCallback>();
    session->SetControlCenterEffectStatusCallback(controlCenterCallback);
    session->UnSetControlCenterEffectStatusCallback();

    auto cameraSwitchCallback = std::make_shared<MockCameraSwitchRequestCallback>();
    session->SetCameraSwitchRequestCallback(cameraSwitchCallback);
    session->UnSetCameraSwitchRequestCallback();

    auto isoInfoCallback = std::make_shared<MockIsoInfoSyncCallback>();
    session->SetIsoInfoCallback(isoInfoCallback);

    auto retrievedAppCallback = session->GetApplicationCallback();
    MEDIA_INFO_LOG("GetApplicationCallback: %p", retrievedAppCallback.get());

    auto retrievedPressureCallback = session->GetPressureCallback();
    MEDIA_INFO_LOG("GetPressureCallback: %p", retrievedPressureCallback.get());

    auto retrievedControlCenterCallback = session->GetControlCenterEffectCallback();
    MEDIA_INFO_LOG("GetControlCenterEffectCallback: %p", retrievedControlCenterCallback.get());

    auto retrievedCameraSwitchCallback = session->GetCameraSwitchRequestCallback();
    MEDIA_INFO_LOG("GetCameraSwitchRequestCallback: %p", retrievedCameraSwitchCallback.get());

    auto retrievedExposureCallback = session->GetExposureCallback();
    MEDIA_INFO_LOG("GetExposureCallback: %p", retrievedExposureCallback.get());

    auto retrievedFocusCallback = session->GetFocusCallback();
    MEDIA_INFO_LOG("GetFocusCallback: %p", retrievedFocusCallback.get());

    auto retrievedMacroCallback = session->GetMacroStatusCallback();
    MEDIA_INFO_LOG("GetMacroStatusCallback: %p", retrievedMacroCallback.get());

    auto retrievedMoonCallback = session->GetMoonCaptureBoostStatusCallback();
    MEDIA_INFO_LOG("GetMoonCaptureBoostStatusCallback: %p", retrievedMoonCallback.get());

    auto retrievedFeatureCallback = session->GetFeatureDetectionStatusCallback();
    MEDIA_INFO_LOG("GetFeatureDetectionStatusCallback: %p", retrievedFeatureCallback.get());

    auto retrievedSmoothZoomCallback = session->GetSmoothZoomCallback();
    MEDIA_INFO_LOG("GetSmoothZoomCallback: %p", retrievedSmoothZoomCallback.get());

    auto retrievedARCallback = session->GetARCallback();
    MEDIA_INFO_LOG("GetARCallback: %p", retrievedARCallback.get());
}

void TestVideoStabilization(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: TestVideoStabilization ENTER");
    VideoStabilizationMode mode = static_cast<VideoStabilizationMode>(
        fdp.ConsumeIntegral<int32_t>() % (AUTO + 1));

    int32_t ret = session->SetVideoStabilizationMode(mode);
    MEDIA_INFO_LOG("SetVideoStabilizationMode ret: %d", ret);

    VideoStabilizationMode activeMode = session->GetActiveVideoStabilizationMode();
    MEDIA_INFO_LOG("GetActiveVideoStabilizationMode: %d", activeMode);

    VideoStabilizationMode activeModeRef;
    ret = session->GetActiveVideoStabilizationMode(activeModeRef);
    MEDIA_INFO_LOG("GetActiveVideoStabilizationMode(ref) ret: %d, mode: %d", ret, activeModeRef);

    bool isSupported = false;
    ret = session->IsVideoStabilizationModeSupported(mode, isSupported);
    MEDIA_INFO_LOG("IsVideoStabilizationModeSupported ret: %d, isSupported: %d", ret, isSupported);

    bool isSupportedBool = session->IsVideoStabilizationModeSupported(mode);
    MEDIA_INFO_LOG("IsVideoStabilizationModeSupported(bool): %d", isSupportedBool);

    std::vector<VideoStabilizationMode> supportedModes = session->GetSupportedStabilizationMode();
    MEDIA_INFO_LOG("GetSupportedStabilizationMode count: %zu", supportedModes.size());

    std::vector<VideoStabilizationMode> supportedModesRef;
    ret = session->GetSupportedStabilizationMode(supportedModesRef);
    MEDIA_INFO_LOG("GetSupportedStabilizationMode(ref) ret: %d, count: %zu", ret, supportedModesRef.size());
}

void TestOISMode(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: TestOISMode ENTER");

    OISMode oisMode = static_cast<OISMode>(
        fdp.ConsumeIntegral<int32_t>() % (OIS_MODE_CUSTOM + 2));

    bool isSupported = false;
    int32_t ret = session->IsOISModeSupported(oisMode, isSupported);
    MEDIA_INFO_LOG("IsOISModeSupported ret: %d, isSupported: %d", ret, isSupported);
}

void TestOnResultReceived(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: TestOnResultReceived ENTER");
    auto metadata = std::make_shared<Camera::CameraMetadata>(10, 100);
    session->OnResultReceived(metadata);
}

void TestSetPreviewRotation(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: TestSetPreviewRotation ENTER");

    std::string deviceClass = fdp.ConsumeRandomLengthString(50);
    int32_t ret = session->SetPreviewRotation(deviceClass);
    MEDIA_INFO_LOG("SetPreviewRotation ret: %d", ret);
}

shared_ptr<OHOS::Camera::CameraMetadata> BuildProcessMetadata(FuzzedDataProvider& fdp)
{
    static const size_t ITEM_CAP = 40;
    static const size_t DATA_CAP = 300;
    auto result = make_shared<OHOS::Camera::CameraMetadata>(ITEM_CAP, DATA_CAP);
    uint8_t udata = fdp.ConsumeIntegral<uint8_t>();
    int32_t idata = fdp.ConsumeIntegral<int32_t>();
    float fdata = fdp.ConsumeFloatingPoint<float>();
    camera_rational_t cr = {fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>()};
    result->addEntry(OHOS_STATUS_AE_EXPOSURE_COMPENSATION, &fdata, 1);
    result->addEntry(OHOS_CONTROL_FLASH_STATE, &udata, 1);
    result->addEntry(OHOS_STATUS_CAMERA_APERTURE_VALUE, &fdata, 1);
    result->addEntry(OHOS_STATUS_ISO_VALUE, &idata, 1);
    result->addEntry(OHOS_SMOOTH_ZOOM_DURATION, &idata, 1);
    result->addEntry(OHOS_STATUS_LOW_LIGHT_DETECTION, &udata, 1);
    result->addEntry(OHOS_STATUS_CAMERA_CURRENT_ZOOM_RATIO, &idata, 1);
    result->addEntry(OHOS_STATUS_TRIPOD_DETECTION_STATUS, &udata, 1);
    result->addEntry(OHOS_COMPOSITION_BEGIN, &udata, 1);
    result->addEntry(OHOS_COMPOSITION_MATCHED, &fdata, 1);
    result->addEntry(OHOS_STATUS_OPTICAL_IMAGE_STABILIZATION_MODE, &idata, 1);
    result->addEntry(OHOS_STATUS_CAMERA_CURRENT_APERTURE_EFFECT, &udata, 1);
    result->addEntry(OHOS_CONTROL_LENS_FOCUS_DISTANCE, &fdata, 1);
    result->addEntry(OHOS_STATUS_LCD_FLASH_STATUS, &idata, 1);
    result->addEntry(OHOS_COMPOSITION_POSITION_CALIBRATION, &fdata, 1);
    result->addEntry(OHOS_STATUS_CONSTELLATION_DRAWING_DETECT, &fdata, 1);
    result->addEntry(OHOS_CAMERA_CONSTELLATION_DRAWING_STATE, &udata, 1);
    result->addEntry(OHOS_STATUS_IMAGE_STABILIZATION_GUIDE, &fdata, 1);
    result->addEntry(OHOS_STATUS_SENSOR_EXPOSURE_TIME, &cr, 1);
    return result;
}

void TestISO(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: TestISO ENTER");
    int32_t iso = fdp.ConsumeIntegral<int32_t>();
    session->GetISO(iso);
    session->SetISO(iso);
    session->IsManualIsoSupported();
    session->GetIsoValue();
    auto result = BuildProcessMetadata(fdp);
    session->ProcessIsoChange(result);
}

void TestExposureExtra(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: TestExposureExtra ENTER");
    std::vector<uint32_t> exposureTimeRange;
    session->SetExposureInfoCallback(make_shared<ExposureInfoCallbackMock>());
    session->SetFlashStateCallback(make_shared<FlashStateCallbackMock>());
    MeteringMode meteringMode = static_cast<MeteringMode>(
        fdp.ConsumeIntegral<uint8_t>() % (MeteringMode::METERING_MODE_CENTER_HIGHLIGHT_WEIGHTED + NUM_TWO));
    session->IsMeteringModeSupported(meteringMode, g_isSupported);
    session->GetMeteringMode(meteringMode);
    std::vector<MeteringMode> meteringModes;
    session->GetSupportedMeteringModes(meteringModes);
    session->LockForControl();
    session->SetExposureMeteringMode(meteringMode);
    session->SetHasFitedRotation(fdp.ConsumeBool());
    session->UnlockForControl();
    auto result = BuildProcessMetadata(fdp);
    session->ProcessSensorExposureTimeChange(result);
    session->ProcessFlashStateChange(result);
}

void TestFocusTracking(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: TestFocusTracking ENTER");
    std::vector<FocusTrackingMode> trackingModes;
    session->GetSupportedFocusTrackingModes(trackingModes);
    FocusTrackingMode trackingMode = static_cast<FocusTrackingMode>(
        fdp.ConsumeIntegral<uint8_t>() % (FocusTrackingMode::FOCUS_TRACKING_MODE_LOCKED + NUM_TWO));
    session->IsFocusTrackingModeSupported(trackingMode, g_isSupported);
    session->GetFocusTrackingMode(trackingMode);
    session->IsLockFocusTrackingSupported();
    session->IsLockFocusTrackingSupported(g_isSupported);
    session->LockForControl();
    session->SetFocusTrackingMode(trackingMode);
    Point point;
    point.x = fdp.ConsumeFloatingPoint<float>();
    point.y = fdp.ConsumeFloatingPoint<float>();
    session->LockFocusTracking(point);
    session->UnlockFocusTracking();
    session->UnlockForControl();
    auto result = BuildProcessMetadata(fdp);
    session->ProcessFocusDistanceUpdates(result);
}

void TestLowLight(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: TestLowLight ENTER");
    session->IsLowLightBoostSupported();
    session->LockForControl();
    session->EnableLowLightBoost(fdp.ConsumeBool());
    session->EnableLowLightDetection(fdp.ConsumeBool());
    session->UnlockForControl();
    session->IsConstellationDrawingSupported();
    session->LockForControl();
    session->EnableConstellationDrawing(fdp.ConsumeBool());
    session->UnlockForControl();
    session->IsImageStabilizationGuideSupported();
    session->LockForControl();
    session->EnableImageStabilizationGuide(fdp.ConsumeBool());
    session->UnlockForControl();
    session->SetImageStabilizationGuideCallback(make_shared<ImageStabilizationGuideCallbackMock>());
    session->EnableConstellationDrawingDetection(fdp.ConsumeBool());
    session->EnableSuperMoonFeature(fdp.ConsumeBool());
    auto result = BuildProcessMetadata(fdp);
    session->ProcessLowLightBoostStatusChange(result);
    session->ProcessConstellationDrawingUpdates(result);
    session->ProcessConstellationDrawingState(result);
    session->ProcessImageStabilizationGuide(result);
}

void TestColorStyleExtra(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: TestColorStyleExtra ENTER");
    float saturationVal = fdp.ConsumeFloatingPoint<float>();
    session->GetSaturation(saturationVal);
    session->LockForControl();
    session->SetSaturation(fdp.ConsumeFloatingPoint<float>());
    session->UnlockForControl();
}

void TestComposition(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: TestComposition ENTER");
    session->IsCompositionSuggestionSupported();
    session->EnableCompositionEffectPreview(fdp.ConsumeBool());
    session->LockForControl();
    session->EnableCompositionSuggestion(fdp.ConsumeBool());
    session->UnlockForControl();
    session->IsCompositionEffectPreviewSupported(g_isSupported);
    std::vector<std::string> languages;
    session->GetSupportedRecommendedInfoLanguage(languages);
    session->SetRecommendedInfoLanguage(fdp.ConsumeRandomLengthString(10));
    session->SetCompositionPositionCalibrationCallback(make_shared<CompositionPositionCalibrationCallbackMock>());
    session->GetCompositionPositionCalibrationCallback();
    session->SetCompositionBeginCallback(make_shared<CompositionBeginCallbackMock>());
    session->GetCompositionBeginCallback();
    session->SetCompositionEndCallback(make_shared<CompositionEndCallbackMock>());
    session->GetCompositionEndCallback();
    session->SetCompositionPositionMatchCallback(make_shared<CompositionPositionMatchCallbackMock>());
    session->GetCompositionPositionMatchCallback();
    session->SetCompositionEffectReceiveCallback(make_shared<CompositionEffectInfoCallbackMock>());
    session->UnSetCompositionEffectReceiveCallback();
    auto result = BuildProcessMetadata(fdp);
    session->ProcessCompositionPositionCalibration(result);
    session->ProcessCompositionBegin(result);
    session->ProcessCompositionEnd(result);
    session->ProcessCompositionPositionMatch(result);
}

void TestControlRing(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: TestControlRing ENTER");
    session->IsControlCenterSupported();
    session->GetSupportedEffectTypes();
    session->EnableControlCenter(fdp.ConsumeBool());
}

void TestLcdFlashTripod(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: TestLcdFlashTripod ENTER");
    session->IsLcdFlashSupported();
    session->EnableLcdFlashDetection(fdp.ConsumeBool());
    session->SetLcdFlashStatusCallback(make_shared<LcdFlashStatusCallbackMock>());
    session->GetLcdFlashStatusCallback();
    session->EnableLcdFlash(fdp.ConsumeBool());
    session->IsTripodDetectionSupported();
    session->LockForControl();
    session->EnableTripodStabilization(fdp.ConsumeBool());
    session->UnlockForControl();
    session->EnableTripodDetection(fdp.ConsumeBool());
    auto result = BuildProcessMetadata(fdp);
    session->ProcessLcdFlashStatusUpdates(result);
    session->ProcessTripodStatusChange(result);
}

void TestWhiteBalanceGains(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: TestWhiteBalanceGains ENTER");
    std::vector<int32_t> rgbGainsRange;
    session->GetSupportedRGBGainsRange(rgbGainsRange);
    session->IsWhiteBalanceGainsSupported(g_isSupported);
    std::vector<double> wbGains;
    session->GetWhiteBalanceGains(wbGains);
    session->LockForControl();
    std::vector<int32_t> gainsInt = {fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>(),
        fdp.ConsumeIntegral<int32_t>()};
    session->SetWhiteBalanceGains(gainsInt);
    std::vector<double> gainsDouble = {fdp.ConsumeFloatingPoint<double>(),
        fdp.ConsumeFloatingPoint<double>(), fdp.ConsumeFloatingPoint<double>()};
    session->SetWhiteBalanceGains(gainsDouble);
    session->SetColorTint(fdp.ConsumeIntegral<int32_t>());
    session->UnlockForControl();
    int32_t colorTintValue;
    session->GetColorTint(colorTintValue);
    std::vector<int32_t> colorTintRange;
    session->GetColorTintRange(colorTintRange);
}

void TestStarburst(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: TestStarburst ENTER");
    session->LockForControl();
    session->UnlockForControl();
}

void TestParameters(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: TestParameters ENTER");
    std::string key1 = fdp.ConsumeRandomLengthString(30);
    std::string val1 = fdp.ConsumeRandomLengthString(30);
    std::vector<std::string> values;
    session->GetParameters(key1, values);
    std::vector<std::string> keys;
    session->GetSupportedKeys(keys);
    std::string value;
    session->GetActiveParameter(key1, value);
    session->AddFunctionToMap(key1, []() {});
    session->ExecuteAllFunctionsInMap();
}

void TestExtra(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("CaptureSessionFuzzer: TestExtra ENTER");
    session->EnableAutoCloudImageEnhancement(fdp.ConsumeBool());
    session->EnableAutoExtendedGainmapDelivery(fdp.ConsumeBool());
    session->EnableAutoFrameRate(fdp.ConsumeBool());
    session->EnableKeyFrameReport(fdp.ConsumeBool());
    session->EnableLogAssistance(fdp.ConsumeBool());
    session->SetLogViewAssistEnable(fdp.ConsumeBool());
    session->EnableFaceDetection(fdp.ConsumeBool());
    session->SetEnableOriginalImage(fdp.ConsumeBool());
    camera_photo_quality_prioritization_t quality = static_cast<camera_photo_quality_prioritization_t>(
        fdp.ConsumeIntegral<uint8_t>());
    session->SetPhotoQualityPrioritization(quality);
    session->GetSessionConflictFunctions();
    if (camera != nullptr) {
        session->GetCameraOutputCapabilities(camera);
        session->GetMetadataFromService(camera);
    }
    session->GetPreviewSize();
    std::vector<float> rawZoomRange;
    session->GetRAWZoomRatioRange(rawZoomRange);
    session->IsSessionCommited();
    session->IsSessionConfiged();
    session->IsSessionStarted();
    session->LockForControl();
    session->UnlockForControl();
    session->IsStageBoostSupported();
    session->EnableStageBoost(fdp.ConsumeBool());
    session->SetApertureEffectChangeCallback(make_shared<ApertureEffectChangeCallbackMock>());
    session->SetApertureInfoCallback(make_shared<ApertureInfoCallbackMock>());
    session->GetSupportedNightSubModeTypes();
    session->GetSupportedPortraitEffects();
    std::vector<int32_t> videoCodecTypes;
    session->GetSupportedVideoCodecTypes(videoCodecTypes);
    std::vector<Profile> photoProfiles;
    std::vector<VideoProfile> videoProfiles;
    if (!previewProfile_.empty()) {
        session->GetSessionFunctions(previewProfile_, photoProfiles, videoProfiles, fdp.ConsumeBool());
    }
#ifdef CAMERA_USE_SENSOR
    int32_t sensorRotation = 0;
    session->GetSensorRotationOnce(sensorRotation);
#endif
    auto result = BuildProcessMetadata(fdp);
    session->ProcessApertureChange(result);
    session->ProcessApertureEffectChange(result);
    session->ProcessSmoothZoomDurationChange(result);
    session->ProcessOISModeChange(result);
    session->GetIsAutoSwitchDeviceStatus();
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