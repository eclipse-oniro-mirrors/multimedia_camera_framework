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

#ifndef CAMERA_SWITCH_SESSION_UNITTEST_H
#define CAMERA_SWITCH_SESSION_UNITTEST_H

#include "gtest/gtest.h"
#include "cameraSwitch_session.h"
#include "camera_manager.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
class CameraSwitchSessionUnitTest : public testing::Test {
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
    void ReleaseSession();

    sptr<CameraManager> cameraManager_ = nullptr;
    sptr<CaptureSession> captureSession_ = nullptr;
    sptr<CameraInput> camInput_ = nullptr;
};

class AppCameraSwitchSessionCallback : public CameraSwitchCallback {
public:
    void OnCameraActive(const std::string &cameraId, bool isRegisterCameraSwitchCallback,
        const CaptureSessionInfo &sessionInfo) override
    {
        MEDIA_INFO_LOG("AppCameraSwitchSessionCallback::OnCameraActive ");
        return;
    }
    void OnCameraUnactive(const std::string &cameraId) override
    {
        MEDIA_INFO_LOG("AppCameraSwitchSessionCallback::OnCameraUnactive ");
        return;
    }
    virtual void OnCameraSwitch(const std::string &oriCameraId, const std::string &destCameraId, bool status) override
    {
        MEDIA_INFO_LOG("AppCameraSwitchSessionCallback::OnCameraSwitch ");
        return;
    }
};
}  // namespace CameraStandard
}  // namespace OHOS

#endif
