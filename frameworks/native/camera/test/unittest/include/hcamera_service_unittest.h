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

#ifndef HCAMERA_SERVICE_UNITTEST_H
#define HCAMERA_SERVICE_UNITTEST_H

#include "gtest/gtest.h"
#include "hcamera_service.h"
#include "input/camera_manager.h"
#include "output/sketch_wrapper.h"
#include "portrait_session.h"
#include "camera_framework_mock.h"

namespace OHOS {
namespace CameraStandard {
class HCameraServiceUnit :  public testing::Test {
public:
    bool mockFlagWithoutAbt_{false};
    static const int32_t PHOTO_DEFAULT_WIDTH = 1280;
    static const int32_t PHOTO_DEFAULT_HEIGHT = 960;
    static const int32_t PREVIEW_DEFAULT_WIDTH = 640;
    static const int32_t PREVIEW_DEFAULT_HEIGHT = 480;
    static const int32_t VIDEO_DEFAULT_WIDTH = 640;
    static const int32_t VIDEO_DEFAULT_HEIGHT = 360;
    uint64_t tokenId_;
    int32_t uid_;
    int32_t userId_;
    sptr<MockStreamOperator> mockStreamOperator_;
    sptr<MockCameraDevice> mockCameraDevice_;
    sptr<MockHCameraHostManager> mockCameraHostManager_;
    sptr<CameraManager> cameraManager_;
    sptr<MockCameraManager> mockCameraManager_;
    sptr<FakeHCameraService> mockHCameraService_;
    /* SetUpTestCase:The preset action of the test suite is executed before the first TestCase */
    static void SetUpTestCase(void);
    /* TearDownTestCase:The test suite cleanup action is executed after the last TestCase */
    static void TearDownTestCase(void);
    /* SetUp:Execute before each test case */
    void SetUp(void);
    /* TearDown:Execute after each test case */
    void TearDown(void);

    void NativeAuthorization(void);
};

}
}

#endif