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

#ifndef HCAPTURE_SESSION_UNITTEST_H
#define HCAPTURE_SESSION_UNITTEST_H

#include "camera_framework_mock.h"

namespace OHOS {
namespace CameraStandard {
class HCaptureSessionUnitTest : public testing::Test {
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

protected:
    uint64_t tokenId_;
    int32_t uid_;
    int32_t userId_;

private:
    sptr<CameraManager> cameraManager_;
    sptr<HCameraService> cameraService_;
    sptr<HCameraHostManager> cameraHostManager_;
};
} // CameraStandard
} // OHOS
#endif // HCAPTURE_SESSION_UNITTEST_H