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

#include "camera_timer_unittest.h"

#include "camera_log.h"
#include "camera_timer.h"
#include "capture_scene_const.h"

using namespace testing::ext;

void MyCallback(void)
{
    MEDIA_DEBUG_LOG("Timer Callback started!");
}

namespace OHOS {
namespace CameraStandard {

void CameraTimerUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraTimerUnitTest::SetUpTestCase started!");
}

void CameraTimerUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraTimerUnitTest::TearDownTestCase started!");
}

void CameraTimerUnitTest::SetUp()
{
    MEDIA_DEBUG_LOG("CameraTimerUnitTest::SetUp started!");
}

void CameraTimerUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("CameraTimerUnitTest::TearDown started!");
}

/*
 * Feature: Framework
 * Function: Test CameraTimer functional function.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CameraTimer functional function.
 */
HWTEST_F(CameraTimerUnitTest, camera_timer_unittest_001, TestSize.Level0)
{
    uint32_t interval = 1;
    bool once = true;
    OHOS::CameraStandard::CameraTimer& cameraTimer = OHOS::CameraStandard::CameraTimer::GetInstance();
    uint32_t ret = cameraTimer.Register(MyCallback, interval, once);
    EXPECT_EQ(ret, 1);
    cameraTimer.Unregister(ret);
}
} // CameraStandard
} // OHOS
