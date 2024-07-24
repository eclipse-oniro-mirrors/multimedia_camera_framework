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
#include "camera_photo_proxy.h"
#include "capture_input.h"
#include "capture_output.h"
#include "input/camera_manager.h"
#include "message_parcel.h"
#include "refbase.h"
#include <cstddef>
#include <cstdint>
#include <memory>

namespace OHOS {
namespace CameraStandard {
namespace CaptureSessionFuzzer {
const int32_t LIMITSIZE = 4;
const int32_t ENUM_OVER = 2;
sptr<IBufferProducer> surface(nullptr);
sptr<CameraDevice> camera;
Profile profile;
CaptureOutput* curOutput;
bool g_isSupported;

void Test(uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    MessageParcel data;
    data.WriteRawData(rawData, size);
    SceneMode sceneMode = static_cast<SceneMode>(
        data.ReadInt32() % (SceneMode::APERTURE_VIDEO + ENUM_OVER));
    auto manager = CameraManager::GetInstance();
    auto session = manager->CreateCaptureSession(sceneMode);
    if (session == nullptr) {
        return;
    }
    TestCallback(session, rawData, size);
    TestSession(session, rawData, size);
    TestWhiteBalance(session, rawData, size);
    TestExposure(session, rawData, size);
    TestFocus(session, rawData, size);
    TestZoom(session, rawData, size);
    TestStabilization(session, rawData, size);
    TestFlash(session, rawData, size);
    TestCreateMediaLibrary(session, rawData, size);
    TestProcess(session, rawData, size);
    TestAperture(session, rawData, size);
    TestBeauty(session, rawData, size);
    TestOther(session, rawData, size);
    session->Stop();
    session->Release();
}

sptr<CaptureInput> GetCameraInput(uint8_t *rawData)
{
    auto manager = CameraManager::GetInstance();
    auto cameras = manager->GetSupportedCameras();
    camera = cameras[*rawData % cameras.size()];
    return manager->CreateCameraInput(camera);
}

sptr<PhotoOutput> GetCaptureOutput(uint8_t *rawData, size_t size)
{
    auto manager = CameraManager::GetInstance();
    auto cameras = manager->GetSupportedCameras();
    MessageParcel data;
    data.WriteRawData(rawData, size);
    if (camera == nullptr) {
        return nullptr;
    }
    int32_t mode = data.ReadInt32() % (APERTURE_VIDEO + ENUM_OVER);
    auto capability = manager->GetSupportedOutputCapability(camera, mode);
    if (capability == nullptr) {
        return nullptr;
    }
    auto profiles = capability->GetPhotoProfiles();
    profile = profiles[data.ReadUint32() % profiles.size()];
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    if (photoSurface == nullptr) {
        return nullptr;
    }
    surface = photoSurface->GetProducer();
    if (surface == nullptr) {
        return nullptr;
    }
    return manager->CreatePhotoOutput(profile, surface);
}

void TestWhiteBalance(sptr<CaptureSession> session, uint8_t *rawData, size_t size)
{
    MessageParcel data;
    data.WriteRawData(rawData, size);
    vector<WhiteBalanceMode> whiteBalanceModes;
    session->GetSupportedWhiteBalanceModes(whiteBalanceModes);
    WhiteBalanceMode wbMode = static_cast<WhiteBalanceMode>(
        data.ReadInt32() % (WhiteBalanceMode::AWB_MODE_SHADE + ENUM_OVER));
    session->IsWhiteBalanceModeSupported(wbMode, g_isSupported);
    session->GetWhiteBalanceMode(wbMode);
    vector<int32_t> whiteBalanceRange;
    session->GetManualWhiteBalanceRange(whiteBalanceRange);
    session->IsManualWhiteBalanceSupported(g_isSupported);
    int32_t wbValue = data.ReadInt32();
    session->GetManualWhiteBalance(wbValue);

    session->LockForControl();
    session->SetWhiteBalanceMode(wbMode);
    session->SetManualWhiteBalance(wbValue);
    session->UnlockForControl();
}

void TestExposure(sptr<CaptureSession> session, uint8_t *rawData, size_t size)
{
    MessageParcel data;
    data.WriteRawData(rawData, size);
    session->GetSupportedExposureModes();
    vector<ExposureMode> exposureModes;
    session->GetSupportedExposureModes(exposureModes);
    ExposureMode exposureMode = static_cast<ExposureMode>(
        data.ReadInt32() % (ExposureMode::EXPOSURE_MODE_CONTINUOUS_AUTO + ENUM_OVER));
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
    MessageParcel data;
    data.WriteRawData(rawData, size);
    session->GetSupportedFocusModes();
    vector<FocusMode> focusModes;
    session->GetSupportedFocusModes(focusModes);
    FocusMode focusMode = static_cast<FocusMode>(
        data.ReadInt32() % (FocusMode::FOCUS_MODE_LOCKED + ENUM_OVER));
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
    MessageParcel data;
    data.WriteRawData(rawData, size);
    session->GetSupportedStabilizationMode();
    vector<VideoStabilizationMode> modes;
    session->GetSupportedStabilizationMode(modes);
    data.RewindRead(0);
    VideoStabilizationMode stabilizationMode = static_cast<VideoStabilizationMode>(
        data.ReadInt32() % (VideoStabilizationMode::AUTO + ENUM_OVER));
    session->IsVideoStabilizationModeSupported(stabilizationMode);
    session->IsVideoStabilizationModeSupported(stabilizationMode, g_isSupported);
    VideoStabilizationMode mode;
    session->GetActiveVideoStabilizationMode();
    session->GetActiveVideoStabilizationMode(mode);

    session->SetVideoStabilizationMode(stabilizationMode);
}

void TestFlash(sptr<CaptureSession> session, uint8_t *rawData, size_t size)
{
    MessageParcel data;
    data.WriteRawData(rawData, size);
    session->GetSupportedFlashModes();
    vector<FlashMode> flashModes;
    session->GetSupportedFlashModes(flashModes);
    session->HasFlash();
    bool hasFlash;
    session->HasFlash(hasFlash);
    FlashMode flashMode = static_cast<FlashMode>(
        data.ReadInt32() % (FlashMode::FLASH_MODE_ALWAYS_OPEN + ENUM_OVER));
    session->IsFlashModeSupported(flashMode);
    session->IsFlashModeSupported(flashMode, g_isSupported);

    session->LockForControl();
    session->GetFlashMode();
    session->GetFlashMode(flashMode);
    session->SetFlashMode(flashMode);
    session->LockForControl();
}

void TestCreateMediaLibrary(sptr<CaptureSession> session, uint8_t *rawData, size_t size)
{
    MessageParcel data;
    data.WriteRawData(rawData, size);
    sptr<CameraPhotoProxy> photoProxy{new CameraPhotoProxy()};
    std::string uri;
    int32_t cameraShotType;
    std::string burstKey;
    int64_t timestamp = data.ReadInt64();
    session->CreateMediaLibrary(photoProxy, uri, cameraShotType, burstKey, timestamp);
}

void TestProcess(sptr<CaptureSession> session, uint8_t *rawData, size_t size)
{
    MessageParcel data;
    data.WriteRawData(rawData, size);
    shared_ptr<OHOS::Camera::CameraMetadata> result;
    int32_t idata = data.ReadInt32();
    result->addEntry(OHOS_CONTROL_EXPOSURE_MODE, &idata, 1);
    result->addEntry(OHOS_CONTROL_FOCUS_MODE, &idata, 1);
    result->addEntry(OHOS_STATUS_SENSOR_EXPOSURE_TIME, &idata, 1);
    result->addEntry(CAMERA_POSITION_FRONT, &idata, 1);
    result->addEntry(OHOS_CAMERA_CUSTOM_SNAPSHOT_DURATION, &idata, 1);
    result->addEntry(OHOS_CAMERA_MACRO_STATUS, &idata, 1);
    result->addEntry(OHOS_STATUS_MOON_CAPTURE_DETECTION, &idata, 1);
    result->addEntry(OHOS_CAMERA_EFFECT_SUGGESTION_TYPE, &idata, 1);
    session->ProcessAutoExposureUpdates(result);
    session->ProcessAutoFocusUpdates(result);
    session->ProcessAREngineUpdates(data.ReadUint64(), result);
    session->ProcessFaceRecUpdates(data.ReadUint64(), result);
    session->ProcessSnapshotDurationUpdates(data.ReadUint64(), result);
    session->ProcessMacroStatusChange(result);
    session->ProcessMoonCaptureBoostStatusChange(result);
    session->ProcessEffectSuggestionTypeUpdates(result);
}

void TestAperture(sptr<CaptureSession> session, uint8_t *rawData, size_t size)
{
    MessageParcel data;
    data.WriteRawData(rawData, size);
    uint32_t moduleType;
    session->GetModuleType(moduleType);
    session->SetARMode(data.ReadBool());
    
    session->IsEffectSuggestionSupported();
    session->EnableEffectSuggestion(data.ReadBool());
    session->GetSupportedEffectSuggestionInfo();
    session->GetSupportedEffectSuggestionType();
    vector<EffectSuggestionStatus> effectSuggestionStatusList;
    size_t max = EffectSuggestionType::EFFECT_SUGGESTION_SUNRISE_SUNSET + ENUM_OVER;
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
    vector<float> apertures;
    session->GetSupportedVirtualApertures(apertures);
    float aperture;
    session->GetVirtualAperture(aperture);
    session->SetVirtualAperture(aperture);
    std::vector<std::vector<float>> physicalApertures;
    session->GetSupportedPhysicalApertures(physicalApertures);
    session->GetPhysicalAperture(aperture);
    session->SetPhysicalAperture(aperture);
}

void TestBeauty(sptr<CaptureSession> session, uint8_t *rawData, size_t size)
{
    MessageParcel data;
    data.WriteRawData(rawData, size);
    session->GetSupportedFilters();
    session->GetSupportedBeautyTypes();
    BeautyType type = static_cast<BeautyType>(
        data.ReadInt32() % (BeautyType::SKIN_TONE + ENUM_OVER));
    session->GetSupportedBeautyRange(type);
    session->GetBeauty(type);
    session->SetBeauty(type, data.ReadInt32());
    session->GetSupportedColorSpaces();
    ColorSpace colorSpace;
    session->GetActiveColorSpace(colorSpace);
    session->GetSupportedColorEffects();
    session->GetColorEffect();

    session->GetFilter();
    FilterType filter = static_cast<FilterType>(
        data.ReadInt32() % (FilterType::PINK + ENUM_OVER));
    session->SetFilter(filter);
    
    session->SetColorSpace(colorSpace);
    ColorEffect colorEffect = static_cast<ColorEffect>(
        data.ReadInt32() % (ColorEffect::COLOR_EFFECT_BLACK_WHITE + ENUM_OVER));
    session->SetColorEffect(colorEffect);
    BeautyType beautyType = static_cast<BeautyType>(
        data.ReadInt32() % (BeautyType::SKIN_TONE + ENUM_OVER));
    session->SetBeautyValue(beautyType, data.ReadInt32());
}

void TestOther(sptr<CaptureSession> session, uint8_t *rawData, size_t size)
{
    MessageParcel data;
    data.WriteRawData(rawData, size);
    session->IsMacroSupported();
    session->IsMovingPhotoSupported();
    session->IsMoonCaptureBoostSupported();
    SceneFeature feature = static_cast<SceneFeature>(
        data.ReadInt32() % (SceneFeature::FEATURE_ENUM_MAX + ENUM_OVER));
    session->IsFeatureSupported(feature);
    set<camera_face_detect_mode_t> metadataObjectTypes;
    camera_face_detect_mode_t t = static_cast<camera_face_detect_mode_t>(
        data.ReadInt32() % (camera_face_detect_mode_t::OHOS_CAMERA_FACE_DETECT_MODE_SIMPLE + ENUM_OVER));
    metadataObjectTypes.insert(t);
    session->SetCaptureMetadataObjectTypes(metadataObjectTypes);
    uint32_t ability = data.ReadUint32();
    session->VerifyAbility(ability);
    session->SetFocusDistance(data.ReadFloat());
    session->EnableMacro(data.ReadBool());
    session->EnableMovingPhoto(data.ReadBool());
    session->StartMovingPhotoCapture(data.ReadBool(), data.ReadInt32());
    session->EnableMoonCaptureBoost(data.ReadBool());
    session->EnableFeature(feature, data.ReadBool());
    vector<int32_t> frameRateRange;
    session->SetFrameRateRange(frameRateRange);
    session->SetSensorSensitivity(data.ReadUint32());
    vector<int32_t> sensitivityRange;
    session->GetSensorSensitivityRange(sensitivityRange);
    session->GetFeaturesMode();
    session->GetSubFeatureMods();
    session->IsSetEnableMacro();
    session->GetMetaOutput();
    session->GetMetadata();
    session->ExecuteAbilityChangeCallback();
    DeferredDeliveryImageType deferredType = static_cast<DeferredDeliveryImageType>(
        data.ReadInt32() % (DeferredDeliveryImageType::DELIVERY_VIDEO + ENUM_OVER));
    session->EnableDeferredType(deferredType, data.ReadBool());
    session->SetUserId();
    session->IsMovingPhotoEnabled();
    session->IsImageDeferred();
    session->EnableAutoHighQualityPhoto(data.ReadBool());
    session->CanSetFrameRateRange(data.ReadInt32(), data.ReadInt32(), curOutput);
    session->CanSetFrameRateRangeForOutput(data.ReadInt32(), data.ReadInt32(), curOutput);
}

void TestSession(sptr<CaptureSession> session, uint8_t *rawData, size_t size)
{
    MessageParcel data;
    data.WriteRawData(rawData, size);
    SceneMode modeName = static_cast<SceneMode>(
        data.ReadInt32() % (SceneMode::APERTURE_VIDEO + ENUM_OVER));
    session->SetMode(modeName);
    session->GetMode();
    PreconfigType preconfigType = static_cast<PreconfigType>(
        data.ReadInt32() % (PreconfigType::PRECONFIG_HIGH_QUALITY + ENUM_OVER));
    ProfileSizeRatio preconfigRatio = static_cast<ProfileSizeRatio>(
        data.ReadInt32() % (ProfileSizeRatio::RATIO_16_9 + ENUM_OVER));
    session->CanPreconfig(preconfigType, preconfigRatio);
    session->Preconfig(preconfigType, preconfigRatio);
    session->BeginConfig();
    sptr<CaptureInput> input = GetCameraInput(rawData);
    sptr<CaptureOutput> output = GetCaptureOutput(rawData, size);
    if (input == nullptr || output == nullptr || session == nullptr) {
        return;
    }
    session->CanAddInput(input);
    session->AddInput(input);
    session->CanAddOutput(output);
    session->AddOutput(output);
    session->RemoveInput(input);
    session->RemoveOutput(output);
    session->AddInput(input);
    session->AddOutput(output);
    session->AddSecureOutput(output);
    session->CommitConfig();
    session->Start();
    curOutput = output.GetRefPtr();
    CaptureOutputType outputType = static_cast<CaptureOutputType>(
        data.ReadInt32() % (CaptureOutputType::CAPTURE_OUTPUT_TYPE_MAX + ENUM_OVER));
    session->ValidateOutputProfile(profile, outputType);
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