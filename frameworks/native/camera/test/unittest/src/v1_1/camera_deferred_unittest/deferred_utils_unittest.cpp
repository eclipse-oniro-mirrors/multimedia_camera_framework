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

#include "deferred_utils_unittest.h"
#include "dp_power_manager.h"
#include "dp_timer.h"
#include "dp_utils.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "watch_dog.h"


using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {

void DeferredUtilsUnitTest::SetUpTestCase(void) {}

void DeferredUtilsUnitTest::TearDownTestCase(void) {}

void DeferredUtilsUnitTest::SetUp(void) {}

void DeferredUtilsUnitTest::TearDown(void) {}

/*
 * Feature: Framework
 * Function: Test functions in class DPSProwerManager.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate the functions in class DPSProwerManager with test data to ensure the correctness.
 */
HWTEST_F(DeferredUtilsUnitTest, deferred_utils_unittest_001, TestSize.Level0)
{
    EXPECT_EQ(DPSProwerManager::GetInstance().initialized_.load(), true);
    DPSProwerManager::GetInstance().Initialize();
    ASSERT_NE(DPSProwerManager::GetInstance().wakeLock_, nullptr);
    EXPECT_EQ(DPSProwerManager::GetInstance().isSuspend_, false);
    DPSProwerManager::GetInstance().SetAutoSuspend(true);
    EXPECT_EQ(DPSProwerManager::GetInstance().isSuspend_, false);
    DPSProwerManager::GetInstance().SetAutoSuspend(false);
    EXPECT_EQ(DPSProwerManager::GetInstance().isSuspend_, true);
    DPSProwerManager::GetInstance().SetAutoSuspend(false);
    EXPECT_EQ(DPSProwerManager::GetInstance().isSuspend_, true);
    DPSProwerManager::GetInstance().SetAutoSuspend(true);
    EXPECT_EQ(DPSProwerManager::GetInstance().isSuspend_, false);
}

/*
 * Feature: Framework
 * Function: Test functions of class DPSProwerManager in abnormal condition.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate the functions of class DPSProwerManager in abnormal condition, wakeLock_ is null.
 */
HWTEST_F(DeferredUtilsUnitTest, deferred_utils_unittest_002, TestSize.Level0)
{
    uint32_t testTime = 0;
    EXPECT_EQ(DPSProwerManager::GetInstance().initialized_.load(), true);
    DPSProwerManager::GetInstance().wakeLock_ = nullptr;

    DPSProwerManager::GetInstance().DisableAutoSuspend(testTime);
    DPSProwerManager::GetInstance().EnableAutoSuspend();
    DPSProwerManager::GetInstance().SetAutoSuspend(true);
    EXPECT_EQ(DPSProwerManager::GetInstance().isSuspend_, false);
}

/*
 * Feature: Framework
 * Function: Test functions of class DpsTimer.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate the functions of class DpsTimer in normal condition.
 */
HWTEST_F(DeferredUtilsUnitTest, deferred_utils_unittest_003, TestSize.Level0)
{
    uint32_t testTimeId = 1;
    EXPECT_NE(DpsTimer::GetInstance().StartTimer([]() -> void {}, 0), 0);
    DpsTimer::GetInstance().StopTimer(testTimeId);
    EXPECT_EQ(testTimeId, 0);
}

/*
 * Feature: Framework
 * Function: Test functions of class DpsTimer in abnormal condition.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate the functions of class DpsTimer in abnormal condition, timer_ is null.
 */
HWTEST_F(DeferredUtilsUnitTest, deferred_utils_unittest_004, TestSize.Level0)
{
    uint32_t invalidTimeId = 0;
    uint32_t testTimeId = 1;
    DpsTimer::GetInstance().~DpsTimer();

    EXPECT_EQ(DpsTimer::GetInstance().StartTimer([]() -> void {}, 0), 0);
    DpsTimer::GetInstance().StopTimer(testTimeId);
    EXPECT_EQ(testTimeId, 1);
    DpsTimer::GetInstance().StopTimer(invalidTimeId);
}

/*
 * Feature: Framework
 * Function: Test TransExifOrientationToDegree with valid data.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test TransExifOrientationToDegree with valid data.
 */
HWTEST_F(DeferredUtilsUnitTest, deferred_utils_unittest_005, TestSize.Level0)
{
    std::string testOrientation = "Top-right";
    float testDegree = 90;
    EXPECT_EQ(TransExifOrientationToDegree(testOrientation), testDegree);
}

/*
 * Feature: Framework
 * Function: Test TransExifOrientationToDegree with invalid data.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test TransExifOrientationToDegree with invalid data.
 */
HWTEST_F(DeferredUtilsUnitTest, deferred_utils_unittest_006, TestSize.Level0)
{
    std::string testOrientation = "Invalid_orientation";
    float defaultDegree = .0;
    EXPECT_EQ(TransExifOrientationToDegree(testOrientation), defaultDegree);
}

/*
 * Feature: Framework
 * Function: Test GetGlobalWatchdog.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate the correctness of GetGlobalWatchdog.
 */
HWTEST_F(DeferredUtilsUnitTest, deferred_utils_unittest_007, TestSize.Level0)
{
    EXPECT_EQ(GetGlobalWatchdog().name_, "DPSGlobalWatchdog");
}

/*
 * Feature: Framework
 * Function: Test GetDpsCallerInfo.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate the correctness of GetDpsCallerInfo.
 */
HWTEST_F(DeferredUtilsUnitTest, deferred_utils_unittest_008, TestSize.Level0)
{
    DpsCallerInfo info = GetDpsCallerInfo();
    EXPECT_EQ(info.pid, IPCSkeleton::GetCallingPid());
    EXPECT_EQ(info.uid, IPCSkeleton::GetCallingUid());
    EXPECT_EQ(info.tokenID, IPCSkeleton::GetCallingTokenID());
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS