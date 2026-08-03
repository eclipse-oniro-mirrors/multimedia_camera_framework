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

#ifndef CAPTURE_SESSION_FUZZER_H
#define CAPTURE_SESSION_FUZZER_H

#include "session/capture_session.h"
#include "session/capture_session_for_sys.h"
#include "native_info_callback.h"
#include "session/features/composition_feature.h"
#include "iremote_proxy.h"
#include "fuzzer/FuzzedDataProvider.h"

namespace OHOS {
namespace CameraStandard {
namespace CaptureSessionFuzzer {

void Test(uint8_t* data, size_t size);
void TestSession(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestExposure(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestFocus(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestZoom(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestCallback(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestStabilization(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestFlash(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestCreateMediaLibrary(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestProcess(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestAperture(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestBeauty(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestOther(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestOther2(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestOther3(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestAdd(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestUncoveredFunctions(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestOISFunctions(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestOtherUncoveredFunctions(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestMovieFileOutputFunctions(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestStreamNumFunctions(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestExposureSceneAndSmartCapture(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestCalculationHelper(FuzzedDataProvider& fdp);
void TestPreconfigProfiles(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestOfflinePhoto(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestMovieFileOutput(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestDeviceCapabilityChange(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestCameraDelayClose(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestErrorCallback(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestCameraServerDied(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestVideoOutputConfiguration(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestStreamModeManagement(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestCallbackManagement(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestVideoStabilization(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestOISMode(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestOnResultReceived(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestSetPreviewRotation(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestISO(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestExposureExtra(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestFocusTracking(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestLowLight(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestColorStyleExtra(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestComposition(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestControlRing(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestLcdFlashTripod(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestWhiteBalanceGains(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestStarburst(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestParameters(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);
void TestExtra(sptr<CaptureSessionForSys> session, FuzzedDataProvider& fdp);

class MockSessionCallback : public SessionCallback {
public:
    void OnError(int32_t errorCode) override {}
};

class MockPressureCallback : public PressureCallback {
public:
    void OnPressureStatusChanged(PressureStatus status) override {}
};

class MockControlCenterEffectCallback : public ControlCenterEffectCallback {
public:
    void OnControlCenterEffectStatusChanged(ControlCenterStatusInfo status) override {}
};

class MockCameraSwitchRequestCallback : public CameraSwitchRequestCallback {
public:
    void OnAppCameraSwitch(const std::string &cameraId) override {}
};

class MockIsoInfoSyncCallback : public IsoInfoSyncCallback {
public:
    void OnIsoInfoChangedSync(IsoInfo info) override {}
};

class IsoInfoSyncCallbackMock : public IsoInfoSyncCallback {
public:
    void OnIsoInfoChangedSync(IsoInfo info) override {}
};

class ExposureCallbackMock : public ExposureCallback {
public:
    void OnExposureState(ExposureState state) override {}
};

class FocusCallbackMock : public FocusCallback {
public:
    void OnFocusState(FocusState state) override {}
};

class MacroStatusCallbackMock : public MacroStatusCallback {
public:
    void OnMacroStatusChanged(MacroStatus status) override {}
};

class MoonCaptureBoostStatusCallbackMock : public MoonCaptureBoostStatusCallback {
public:
    void OnMoonCaptureBoostStatusChanged(MoonCaptureBoostStatus status) override {}
};

class FeatureDetectionStatusCallbackMock : public FeatureDetectionStatusCallback {
public:
    explicit FeatureDetectionStatusCallbackMock(bool ret) : ret_(ret) {}
    void OnFeatureDetectionStatusChanged(SceneFeature feature, FeatureDetectionStatus status) override {}
    bool IsFeatureSubscribed(SceneFeature feature) override
    {
        return ret_;
    }
private:
    bool ret_;
};

class EffectSuggestionCallbackMock : public EffectSuggestionCallback {
public:
    void OnEffectSuggestionChange(EffectSuggestionType effectSuggestionType) override {}
};

class ARCallbackMock : public ARCallback {
public:
    void OnResult(const ARStatusInfo &arStatusInfo) const override {}
};

class SmoothZoomCallbackMock : public SmoothZoomCallback {
public:
    void OnSmoothZoom(int32_t duration) override {}
};

class AbilityCallbackMock : public AbilityCallback {
public:
    void OnAbilityChange() override {}
};

class PressureCallbackMock : public PressureCallback {
public:
    void OnPressureStatusChanged(PressureStatus status) override {}
};

class ControlCenterEffectCallbackMock : public ControlCenterEffectCallback {
public:
    void OnControlCenterEffectStatusChanged(ControlCenterStatusInfo status) override {}
};

class CameraSwitchRequestCallbackMock : public CameraSwitchRequestCallback {
public:
    void OnAppCameraSwitch(const std::string &cameraId) override {}
};

class CompositionPositionCalibrationCallbackMock : public CompositionPositionCalibrationCallback {
public:
    void OnCompositionPositionCalibrationAvailable(const CompositionPositionCalibrationInfo info) const override {}
};

class CompositionBeginCallbackMock : public CompositionBeginCallback {
public:
    void OnCompositionBeginAvailable() const override {}
};

class CompositionEndCallbackMock : public CompositionEndCallback {
public:
    void OnCompositionEndAvailable(CompositionEndState state) const override {}
};

class CompositionPositionMatchCallbackMock : public CompositionPositionMatchCallback {
public:
    void OnCompositionPositionMatchAvailable(std::vector<float> zoomRatios) const override {}
};

class ImageStabilizationGuideCallbackMock : public ImageStabilizationGuideCallback {
public:
    void OnImageStabilizationGuideChange(std::vector<Point> lineSegments) override {}
};

class ApertureEffectChangeCallbackMock : public ApertureEffectChangeCallback {
public:
    void OnApertureEffectChange(ApertureEffectType effectSuggestionType) const override {}
};

class ApertureInfoCallbackMock : public ApertureInfoCallback {
public:
    void OnApertureInfoChanged(ApertureInfo info) override {}
};

class ExposureInfoCallbackMock : public ExposureInfoCallback {
public:
    void OnExposureInfoChanged(ExposureInfo info) override {}
    void OnExposureInfoChangedSync(ExposureInfo info) override {}
};

class FlashStateCallbackMock : public FlashStateCallback {
public:
    void OnFlashStateChangedSync(FlashState info) override {}
};

class AutoDeviceSwitchCallbackMock : public AutoDeviceSwitchCallback {
public:
    void OnAutoDeviceSwitchStatusChange(bool isDeviceSwitched, bool isDeviceCapabilityChanged) const override {}
};

class CompositionEffectInfoCallbackMock : public NativeInfoCallback<CompositionEffectInfo> {
public:
    void OnInfoChanged(CompositionEffectInfo info) override {}
};

class LcdFlashStatusCallbackMock : public LcdFlashStatusCallback {
public:
    void OnLcdFlashStatusChanged(LcdFlashStatusInfo lcdFlashStatusInfo) override {}
};

} //CaptureSessionFuzzer
} //CameraStandard
} //OHOS
#endif //CAPTURE_SESSION_FUZZER_H