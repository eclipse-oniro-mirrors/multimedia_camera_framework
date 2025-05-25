/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef CAPTURE_SESSION_UNITTEST_H
#define CAPTURE_SESSION_UNITTEST_H

#include "gtest/gtest.h"
#include "capture_session.h"
#include "camera_manager.h"
#include "camera_log.h"
#include "icapture_session_callback.h"

namespace OHOS {
namespace CameraStandard {
class AppAbilityCallback : public AbilityCallback {
public:
    void OnAbilityChange() override {}
};

class AppSessionCallback : public SessionCallback {
public:
    void OnError(int32_t errorCode)
    {
        MEDIA_DEBUG_LOG("AppMetadataCallback::OnError %{public}d", errorCode);
        return;
    }
};

class CallbackListener : public FocusCallback, public ExposureCallback {
public:
    void OnFocusState(FocusState state) override
    {
        MEDIA_DEBUG_LOG("CallbackListener::OnFocusState ");
        return;
    }

    void OnExposureState(ExposureState state) override
    {
        MEDIA_DEBUG_LOG("CallbackListener::OnExposureState ");
        return;
    }
};

class AppMacroStatusCallback : public MacroStatusCallback {
public:
    void OnMacroStatusChanged(MacroStatus status)
    {
        MEDIA_DEBUG_LOG("AppMacroStatusCallback");
    }
};

class AppPressureStatusCallback : public PressureCallback {
public:
    void OnPressureStatusChanged(PressureStatus status)
    {
        MEDIA_DEBUG_LOG("AppPressureStatusCallback");
    }
};

class CaptureSessionUnitTest : public testing::Test {
public:
    static const int32_t PREVIEW_DEFAULT_WIDTH = 640;
    static const int32_t PREVIEW_DEFAULT_HEIGHT = 480;
    uint64_t tokenId_ = 0;
    int32_t uid_ = 0;
    int32_t userId_ = 0;
    sptr<CameraManager> cameraManager_ = nullptr;
    std::vector<sptr<CameraDevice>> cameras_;

    /* SetUpTestCase:The preset action of the test suite is executed before the first TestCase */
    static void SetUpTestCase(void);
    /* TearDownTestCase:The test suite cleanup action is executed after the last TestCase */
    static void TearDownTestCase(void);
    /* SetUp:Execute before each test case */
    void SetUp(void);
    /* TearDown:Execute after each test case */
    void TearDown(void);

    void NativeAuthorization(void);

    void SessionControlParams(sptr<CaptureSession> session);
    void SessionCommit(sptr<CaptureSession> session);
    void UpdataCameraOutputCapability(int32_t modeName = 0);
    sptr<CaptureOutput> CreatePreviewOutput(Profile previewProfile);
    sptr<CaptureOutput> CreatePhotoOutput(Profile photoProfile);
    sptr<CaptureOutput> CreateVideoOutput(VideoProfile videoProfile);

protected:
    std::vector<Profile> previewProfile_ = {};
    std::vector<Profile> photoProfile_ = {};
    std::vector<VideoProfile> videoProfile_ = {};
};

class MockCaptureOutput : public OHOS::CameraStandard::CaptureOutput {
public:
    MockCaptureOutput(CaptureOutputType type, StreamType streamType, sptr<IBufferProducer> bufferProducer,
    sptr<IStreamCommon> stream)
        : OHOS::CameraStandard::CaptureOutput(type, streamType, bufferProducer, stream) {}
    
    int32_t Release() {
        return 0;
    }
    void CameraServerDied(pid_t pid) {}
    int32_t CreateStream() {
        return 0;
    }
};
}
}
#endif
