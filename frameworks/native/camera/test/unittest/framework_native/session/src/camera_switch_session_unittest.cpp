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

#include "gtest/gtest.h"
#include <chrono>
#include <cstdint>
#include <thread>
#include <vector>
#include "ipc_skeleton.h"
#include "camera_switch_session_unittest.h"
#include "session/cameraSwitch_session.h"
#include "hcamera_service.h"
#include "hcamera_session_manager.h"
#include "hcamera_switch_session.h"
#include "camera_util.h"
#include "surface.h"
#include "test_common.h"
#include "hcapture_session.h"
#include "test_token.h"

using namespace testing::ext;
namespace OHOS {
namespace CameraStandard {
void CameraSwitchSessionUnitTest::SetUpTestCase(void)
{
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
}

void CameraSwitchSessionUnitTest::TearDownTestCase(void)
{}

void CameraSwitchSessionUnitTest::SetUp()
{
    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);
}

void CameraSwitchSessionUnitTest::TearDown()
{
    cameraManager_ = nullptr;
    captureSession_ = nullptr;
    camInput_ = nullptr;
    MEDIA_DEBUG_LOG("CameraSwitchSessionUnitTest TearDown");
}

/*
 * Feature: Framework
 * Function: Test CreateCameraSwitchSession with errorCode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateCameraSwitchSession with errorCode
 */
HWTEST_F(CameraSwitchSessionUnitTest, camera_switch_session_unittest_001, TestSize.Level0)
{
    sptr<CameraSwitchSession> cameraSwitchSession = nullptr;
    int32_t retCode = cameraManager_->CreateCameraSwitchSession(&cameraSwitchSession);
    EXPECT_EQ(retCode, 0);
}

/*
 * Feature: Framework
 * Function: Test SetCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetCallback function to verify callback registration
 */
HWTEST_F(CameraSwitchSessionUnitTest, camera_switch_session_unittest_002, TestSize.Level0)
{
    sptr<CameraSwitchSession> cameraSwitchSession_ = nullptr;
    int32_t retCode = cameraManager_->CreateCameraSwitchSession(&cameraSwitchSession_);
    EXPECT_EQ(retCode, 0);
    auto cameraSwitchCallback = std::make_shared<AppCameraSwitchSessionCallback>();
    cameraSwitchSession_->SetCallback(cameraSwitchCallback);
}

/*
 * Feature: Framework
 * Function: Test CreateCameraSwitchSession
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateCameraSwitchSession function
 */
HWTEST_F(CameraSwitchSessionUnitTest, camera_switch_session_unittest_003, TestSize.Level0)
{
    sptr<CameraSwitchSession> cameraSwitchSession_ = nullptr;
    int32_t retCode = cameraManager_->CreateCameraSwitchSession(&cameraSwitchSession_);
    EXPECT_EQ(retCode, 0);
    ASSERT_NE(cameraSwitchSession_, nullptr);
    retCode = cameraManager_->CreateCameraSwitchSession(&cameraSwitchSession_);
    EXPECT_EQ(retCode, 0);
    ASSERT_NE(cameraSwitchSession_, nullptr);
}
}  // namespace CameraStandard
}  // namespace OHOS
