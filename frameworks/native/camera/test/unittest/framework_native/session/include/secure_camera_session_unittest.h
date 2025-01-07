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

#ifndef SECURE_CAMERA_SESSION_UNITTEST_H
#define SECURE_CAMERA_SESSION_UNITTEST_H

#include "gtest/gtest.h"
#include "secure_camera_session.h"
#include "camera_manager.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
class MockCameraDevice;
class MockHCameraHostManager;
class MockCameraManager;
class SecureCameraSessionUnitTest : public testing::Test {
public:
    static const int32_t PREVIEW_DEFAULT_WIDTH = 640;
    static const int32_t PREVIEW_DEFAULT_HEIGHT = 480;
    static const int32_t DEFAULT_MODE = 0;
    static const int32_t PHOTO_MODE = 1;
    static const int32_t VIDEO_MODE = 2;
    static const int32_t PORTRAIT_MODE = 3;
    static const int32_t NIGHT_MODE = 4;
    static const int32_t SLOW_MODE = 6;
    static const int32_t SCAN_MODE = 7;
    static const int32_t MODE_FINISH = -1;
    static const int32_t STREAM_FINISH = -1;
    static const int32_t PREVIEW_STREAM = 0;
    static const int32_t VIDEO_STREAM = 1;
    static const int32_t PHOTO_STREAM = 2;
    static const int32_t ABILITY_ID_ONE = 536870912;
    static const int32_t ABILITY_ID_TWO = 536870914;
    static const int32_t ABILITY_ID_THREE = 536870916;
    static const int32_t ABILITY_ID_FOUR = 536870924;
    static const int32_t ABILITY_FINISH = -1;

    /* SetUpTestCase:The preset action of the test suite is executed before the first TestCase */
    static void SetUpTestCase(void);
    /* TearDownTestCase:The test suite cleanup action is executed after the last TestCase */
    static void TearDownTestCase(void);
    /* SetUp:Execute before each test case */
    void SetUp(void);
    /* TearDown:Execute after each test case */
    void TearDown(void);

    void NativeAuthorization(void);
    sptr<CaptureOutput> CreatePreviewOutput();
private:
    uint64_t tokenId_ = 0;
    int32_t uid_ = 0;
    int32_t userId_ = 0;
    sptr<MockCameraDevice> mockCameraDevice_;
    sptr<MockHCameraHostManager> mockCameraHostManager_;
    sptr<CameraManager> cameraManager_;
    std::vector<Profile> previewProfile_;
};

}
}

#endif