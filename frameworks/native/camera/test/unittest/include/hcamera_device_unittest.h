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

namespace OHOS {
namespace CameraStandard {
class HCameraDeviceUnitTest : public testing::Test {
public:
    uint64_t tokenId_ = 0;
    int32_t uid_ = 0;
    int32_t userId_ = 0;
    sptr<HCameraHostManager> cameraHostManager_ = nullptr;
    sptr<CameraManager> cameraManager_ = nullptr;
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