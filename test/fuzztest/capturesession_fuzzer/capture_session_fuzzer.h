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