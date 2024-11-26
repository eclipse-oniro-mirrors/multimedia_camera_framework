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

#ifndef HCAMEA_DEVICE_UNITTEST_H
#define HCAMEA_DEVICE_UNITTEST_H

#include "gtest/gtest.h"
#include "input/camera_manager.h"
#include "portrait_session.h"
#include "hcamera_device.h"
#include "camera_framework_mock.h"

namespace OHOS {
namespace CameraStandard {
class HCameraDeviceUnitTest : public testing::Test {
public:
    sptr<HCameraHostManager> cameraHostManager_ = nullptr;
    uint64_t g_tokenId_;
    int32_t g_uid_;
    int32_t g_userId_;
    sptr<MockStreamOperator> mockStreamOperator;
    sptr<MockCameraDevice> mockCameraDevice;
    sptr<MockHCameraHostManager> mockCameraHostManager;
    sptr<CameraManager> cameraManager;
    sptr<MockCameraManager> mockCameraManager;
    sptr<FakeHCameraService> mockHCameraService;
    void NativeAuthorization();

    /* SetUpTestCase:The preset action of the test suite is executed before the first TestCase */
    static void SetUpTestCase(void);

    /* TearDownTestCase:The test suite cleanup action is executed after the last TestCase */
    static void TearDownTestCase(void);

    /* SetUp:Execute before each test case */
    void SetUp();

    /* TearDown:Execute after each test case */
    void TearDown();
};
} // CameraStandard
} // OHOS
#endif // HCAMEA_DEVICE_UNITTEST_H
