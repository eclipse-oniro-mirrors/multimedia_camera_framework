/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef MECH_SESSION_UNITTEST_H
#define MECH_SESSION_UNITTEST_H

#include "gtest/gtest.h"
#include "mech_session.h"
#include "camera_manager.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
class MechSessionUnitTest : public testing::Test {
public:
    /* SetUpTestCase:The preset action of the test suite is executed before the first TestCase */
    static void SetUpTestCase(void);
    /* TearDownTestCase:The test suite cleanup action is executed after the last TestCase */
    static void TearDownTestCase(void);
    /* SetUp:Execute before each test case */
    void SetUp(void);
    /* TearDown:Execute after each test case */
    void TearDown(void);
private:
    void CommitConfig();
    void StartSession();
    void StopSession();
    void SetFocusPoint(float x, float y);
    void ReleaseSession();

    int32_t uid_ = 0;
    int32_t userId_ = 0;
    sptr<CameraManager> cameraManager_ = nullptr;
    sptr<CaptureSession> captureSession_ = nullptr;
    sptr<CameraInput> camInput_ = nullptr;
};

class AppMechSessionCallback : public MechSessionCallback {
public:
    void OnFocusTrackingInfo(FocusTrackingMetaInfo info) override
    {
        return;
    }

    void OnCaptureSessionConfiged(CaptureSessionInfo captureSessionInfo) override
    {
        captureSessionInfo_ = captureSessionInfo;
    }

    void OnZoomInfoChange(int sessionid, ZoomInfo zoomInfo) override
     {
        return cameraAppInfos_;
        zoomInfo_ = zoomInfo;
    }

    void OnSessionStatusChange(int sessionid, bool status) override
    {
        sessionStatus_ = status;
    }

    CaptureSessionInfo GetSessionInfo()
    {
        return captureSessionInfo_;
    }

    ZoomInfo GetZoomInfo()
    {
        return zoomInfo_;
    }

    bool GetSessionStatus()
    {
        return sessionStatus_;
    }

    bool GetFocusStatus()
    {
        return focusStatus_;
    }
private:
    CaptureSessionInfo captureSessionInfo_;
    ZoomInfo zoomInfo_;
    bool sessionStatus_;
    bool focusStatus_;
};
}
}

#endif
