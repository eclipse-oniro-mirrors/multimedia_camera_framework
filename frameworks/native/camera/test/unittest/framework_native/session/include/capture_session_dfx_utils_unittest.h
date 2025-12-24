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

#ifndef CAPTURE_SESSION_DFX_UTILS_UNITTEST_H
#define CAPTURE_SESSION_DFX_UTILS_UNITTEST_H

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "capture_session.h"
#include "camera_manager.h"

namespace OHOS {
namespace CameraStandard {
class CaptureSessionDfxUtilsUnitTest : public testing::Test {
public:
    /* SetUpTestCase:The preset action of the test suite is executed before the first TestCase */
    static void SetUpTestCase(void);
    /* TearDownTestCase:The test suite cleanup action is executed after the last TestCase */
    static void TearDownTestCase(void);
    /* SetUp:Execute before each test case */
    void SetUp(void);
    /* TearDown:Execute after each test case */
    void TearDown(void);

    sptr<CameraManager> cameraManager_ = nullptr;
    std::vector<sptr<CameraDevice>> cameras_;
    void DisMdmOpenCheck(sptr<CameraInput> input);
    void UpdateCameraOutputCapability(int32_t modeName = 0);
protected:
    std::vector<Profile> previewProfile_ = {};
    std::vector<Profile> photoProfile_ = {};
    std::vector<VideoProfile> videoProfile_ = {};
};
}
}
#endif