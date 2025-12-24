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
 * Function: Test GetGlobalWatchdog.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate the correctness of GetGlobalWatchdog.
 */
HWTEST_F(DeferredUtilsUnitTest, deferred_utils_unittest_001, TestSize.Level0)
{
    EXPECT_EQ(Watchdog::GetGlobalWatchdog().name_, "GlobalWatchdog");
}

/*
 * Feature: Framework
 * Function: Test GetDpsCallerInfo.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate the correctness of GetDpsCallerInfo.
 */
HWTEST_F(DeferredUtilsUnitTest, deferred_utils_unittest_002, TestSize.Level0)
{
    DpsCallerInfo info = GetDpsCallerInfo();
    EXPECT_EQ(info.pid, IPCSkeleton::GetCallingPid());
    EXPECT_EQ(info.uid, IPCSkeleton::GetCallingUid());
    EXPECT_EQ(info.tokenID, IPCSkeleton::GetCallingTokenID());
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS