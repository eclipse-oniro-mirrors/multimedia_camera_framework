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

    void NativeAuthorization(void);
private:
    void CommitConfig();
    void StartSession();
    void StopSession();
    void ReleaseSession();

    uint64_t tokenId_ = 0;
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
        MEDIA_INFO_LOG("CallbackListener::OnFocusTrackingInfo ");
        return;
    }

    void OnCameraAppInfo(const std::vector<CameraAppInfo>& cameraAppInfos) override
    {
        cameraAppInfos_ = cameraAppInfos;
        for (int i = 0; i < cameraAppInfos.size(); i++) {
            auto appInfo = cameraAppInfos[i];
            MEDIA_INFO_LOG("AppMechSessionCallback::OnCameraAppInfo tokenId:%{public}d", appInfo.tokenId);
            MEDIA_INFO_LOG("AppMechSessionCallback::OnCameraAppInfo cameraId:%{public}s", appInfo.cameraId.c_str());
            MEDIA_INFO_LOG("AppMechSessionCallback::OnCameraAppInfo opmode:%{public}d", appInfo.opmode);
            MEDIA_INFO_LOG("AppMechSessionCallback::OnCameraAppInfo zoomValue:%{public}f", appInfo.zoomValue);
            MEDIA_INFO_LOG("AppMechSessionCallback::OnCameraAppInfo equivalentFocus:%{public}d",
                appInfo.equivalentFocus);
            MEDIA_INFO_LOG("AppMechSessionCallback::OnCameraAppInfo width:%{public}d", appInfo.width);
            MEDIA_INFO_LOG("AppMechSessionCallback::OnCameraAppInfo height:%{public}d", appInfo.height);
            MEDIA_INFO_LOG("AppMechSessionCallback::OnCameraAppInfo videoStatus:%{public}d", appInfo.videoStatus);
        }
        return;
    }

    std::vector<CameraAppInfo> GetCameraAppInfos()
    {
        return cameraAppInfos_;
    }
private:
    std::vector<CameraAppInfo> cameraAppInfos_;
};
}
}

#endif
