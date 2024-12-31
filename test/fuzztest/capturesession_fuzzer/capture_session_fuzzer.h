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

namespace OHOS {
namespace CameraStandard {
namespace CaptureSessionFuzzer {

void Test(uint8_t *rawData, size_t size);
void TestSession(sptr<CaptureSession> session, uint8_t *rawData, size_t size);
void TestWhiteBalance(sptr<CaptureSession> session, uint8_t *rawData, size_t size);
void TestExposure(sptr<CaptureSession> session, uint8_t *rawData, size_t size);
void TestFocus(sptr<CaptureSession> session, uint8_t *rawData, size_t size);
void TestZoom(sptr<CaptureSession> session, uint8_t *rawData, size_t size);
void TestCallback(sptr<CaptureSession> session, uint8_t *rawData, size_t size);
void TestStabilization(sptr<CaptureSession> session, uint8_t *rawData, size_t size);
void TestFlash(sptr<CaptureSession> session, uint8_t *rawData, size_t size);
void TestCreateMediaLibrary(sptr<CaptureSession> session, uint8_t *rawData, size_t size);
void TestProcess(sptr<CaptureSession> session, uint8_t *rawData, size_t size);
void TestAperture(sptr<CaptureSession> session, uint8_t *rawData, size_t size);
void TestBeauty(sptr<CaptureSession> session, uint8_t *rawData, size_t size);
void TestOther(sptr<CaptureSession> session, uint8_t *rawData, size_t size);
void TestOther2(sptr<CaptureSession> session, uint8_t *rawData, size_t size);

class SessionCallbackMock : public SessionCallback {
public:
    void OnError(int32_t errorCode) override {}
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

} //CaptureSessionFuzzer
} //CameraStandard
} //OHOS
#endif //CAPTURE_SESSION_FUZZER_H