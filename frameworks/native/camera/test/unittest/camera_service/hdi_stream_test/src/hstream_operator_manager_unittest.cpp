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

#include "hstream_operator_manager_unittest.h"
#include "camera_log.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "os_account_manager.h"
#include "token_setproc.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

void HStreamOperatorManagerUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("HStreamOperatorManagerUnitTest::SetUpTestCase started!");
}

void HStreamOperatorManagerUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("HStreamOperatorManagerUnitTest::TearDownTestCase started!");
}

void HStreamOperatorManagerUnitTest::SetUp()
{
    NativeAuthorization();
    MEDIA_DEBUG_LOG("HStreamOperatorManagerUnitTest::SetUp started!");
}

void HStreamOperatorManagerUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("HStreamOperatorManagerUnitTest::TearDown started!");
}

void HStreamOperatorManagerUnitTest::NativeAuthorization()
{
    const char *perms[2];
    perms[0] = "ohos.permission.DISTRIBUTED_DATASYNC";
    perms[1] = "ohos.permission.CAMERA";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .aclsNum = 0,
        .dcaps = NULL,
        .perms = perms,
        .acls = NULL,
        .processName = "native_camera_tdd",
        .aplStr = "system_basic",
    };
    tokenId_ = GetAccessTokenId(&infoInstance);
    uid_ = IPCSkeleton::GetCallingUid();
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid_, userId_);
    MEDIA_DEBUG_LOG("HStreamOperatorManagerUnitTest::NativeAuthorization uid:%{public}d", uid_);
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

/*
 * Feature: Framework
 * Function: Test HStreamOperatorManager singleton pattern
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetInstance function
 */
HWTEST_F(HStreamOperatorManagerUnitTest, hstream_operator_manager_unittest_001, TestSize.Level0)
{
    auto& instance1 = HStreamOperatorManager::GetInstance();
    auto& instance2 = HStreamOperatorManager::GetInstance();
    EXPECT_EQ(&instance1, &instance2);
}

/*
 * Feature: Framework
 * Function: Test HStreamOperatorManager AddStreamOperator
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AddStreamOperator function
 */
HWTEST_F(HStreamOperatorManagerUnitTest, hstream_operator_manager_unittest_002, TestSize.Level0)
{
    auto& manager = HStreamOperatorManager::GetInstance();
    sptr<HStreamOperator> streamOperator = new HStreamOperator();
    
    manager->AddStreamOperator(streamOperator);
    
    int32_t streamOperatorId = GenerateStreamOperatorId();
    EXPECT_GE(streamOperatorId, 0);
}

/*
 * Feature: Framework
 * Function: Test HStreamOperatorManager RemoveStreamOperator
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test RemoveStreamOperator function
 */
HWTEST_F(HStreamOperatorManagerUnitTest, hstream_operator_manager_unittest_003, TestSize.Level0)
{
    auto& manager = HStreamOperatorManager::GetInstance();
    sptr<HStreamOperator> streamOperator = new HStreamOperator();
    
    manager->AddStreamOperator(streamOperator);
    int32_t streamOperatorId = GenerateStreamOperatorId();
    
    manager->RemoveStreamOperator(streamOperatorId);
    
    int32_t invalidId = -1;
    manager->RemoveStreamOperator(invalidId);
}

/*
 * Feature: Framework
 * Function: Test HStreamOperatorManager UpdateStreamOperator
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateStreamOperator function
 */
HWTEST_F(HStreamOperatorManagerUnitTest, hstream_operator_manager_unittest_004, TestSize.Level0)
{
    auto& manager = HStreamOperatorManager::GetInstance();
    sptr<HStreamOperator> streamOperator = new HStreamOperator();
    
    manager->AddStreamOperator(streamOperator);
    int32_t streamOperatorId = GenerateStreamOperatorId();
    
    manager->UpdateStreamOperator(streamOperatorId);
    
    int32_t invalidId = -1;
    manager->UpdateStreamOperator(invalidId);
}

/*
 * Feature: Framework
 * Function: Test HStreamOperatorManager GetOfflineOutputSize
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetOfflineOutputSize function
 */
HWTEST_F(HStreamOperatorManagerUnitTest, hstream_operator_manager_unittest_005, TestSize.Level0)
{
    auto& manager = HStreamOperatorManager::GetInstance();
    
    int32_t size = manager->GetOfflineOutputSize();
    EXPECT_GE(size, 0);
}

/*
 * Feature: Framework
 * Function: Test HStreamOperatorManager GetStreamOperatorByPid
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetStreamOperatorByPid function
 */
HWTEST_F(HStreamOperatorManagerUnitTest, hstream_operator_manager_unittest_006, TestSize.Level0)
{
    auto& manager = HStreamOperatorManager::GetInstance();
    sptr<HStreamOperator> streamOperator = new HStreamOperator();
    
    manager->AddStreamOperator(streamOperator);
    
    pid_t currentPid = getpid();
    auto operators = manager->GetStreamOperatorByPid(currentPid);
    EXPECT_FALSE(operators.empty());
    
    pid_t invalidPid = -1;
    operators = manager->GetStreamOperatorByPid(invalidPid);
    EXPECT_TRUE(operators.empty());
}

} // namespace CameraStandard
} // namespace OHOS