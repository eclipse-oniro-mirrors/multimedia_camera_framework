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

#include "camera_rotate_strategy_parser_unittest.h"
#include "camera_log.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "os_account_manager.h"
#include "token_setproc.h"
#include "accesstoken_kit.h"
using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

void CameraRotateStrategyParserUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraRotateStrategyParserUnitTest::SetUpTestCase started!");
}

void CameraRotateStrategyParserUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraRotateStrategyParserUnitTest::TearDownTestCase started!");
}

void CameraRotateStrategyParserUnitTest::SetUp()
{
    NativeAuthorization();
    MEDIA_DEBUG_LOG("CameraRotateStrategyParserUnitTest::SetUp started!");
}

void CameraRotateStrategyParserUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("CameraRotateStrategyParserUnitTest::TearDown started!");
}

void CameraRotateStrategyParserUnitTest::NativeAuthorization()
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
    MEDIA_DEBUG_LOG("CameraRotateStrategyParserUnitTest::NativeAuthorization uid:%{public}d", uid_);
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

/*
 * Feature: Framework
 * Function: Test CameraRotateStrategyParser basic functions
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test LoadConfiguration and Destroy functions
 */
HWTEST_F(CameraRotateStrategyParserUnitTest, camera_rotate_strategy_parser_unittest_001, TestSize.Level0)
{
    CameraRotateStrategyParser parser;
    
    bool ret = parser.LoadConfiguration();
    EXPECT_TRUE(ret);
    
    auto strategyInfos = parser.GetCameraRotateStrategyInfos();
    EXPECT_FALSE(strategyInfos.empty());
    
    parser.Destroy();
}

/*
 * Feature: Framework
 * Function: Test CameraRotateStrategyParser invalid configuration
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test LoadConfiguration with invalid configuration file
 */
HWTEST_F(CameraRotateStrategyParserUnitTest, camera_rotate_strategy_parser_unittest_002, TestSize.Level0)
{
    CameraRotateStrategyParser parser;
    parser.Destroy();
    bool ret = parser.LoadConfiguration();
    EXPECT_FALSE(ret);
}

/*
 * Feature: Framework
 * Function: Test CameraRotateStrategyParser strategy info parsing
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test parsing of strategy information with different parameters
 */
HWTEST_F(CameraRotateStrategyParserUnitTest, camera_rotate_strategy_parser_unittest_003, TestSize.Level0)
{
    CameraRotateStrategyParser parser;
    bool ret = parser.LoadConfiguration();
    EXPECT_TRUE(ret);
    
    auto strategyInfos = parser.GetCameraRotateStrategyInfos();
    for (const auto& info : strategyInfos) {
        EXPECT_FALSE(info.bundleName.empty());
        EXPECT_GE(info.wideValue, -1.0);
        EXPECT_GE(info.rotateDegree, -1);
        EXPECT_LE(info.rotateDegree, 360);
        EXPECT_GE(info.fps, -1);
        EXPECT_LE(info.fps, 120);
    }
}

/*
 * Feature: Framework
 * Function: Test CameraRotateStrategyParser multiple load
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test multiple loading of configuration
 */
HWTEST_F(CameraRotateStrategyParserUnitTest, camera_rotate_strategy_parser_unittest_004, TestSize.Level0)
{
    CameraRotateStrategyParser parser;
    
    bool ret = parser.LoadConfiguration();
    EXPECT_TRUE(ret);
    auto firstLoadInfos = parser.GetCameraRotateStrategyInfos();
    
    ret = parser.LoadConfiguration();
    EXPECT_TRUE(ret);
    auto secondLoadInfos = parser.GetCameraRotateStrategyInfos();

    EXPECT_EQ(firstLoadInfos.size(), secondLoadInfos.size());
}

/*
 * Feature: Framework
 * Function: Test CameraRotateStrategyParser cleanup
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cleanup after multiple operations
 */
HWTEST_F(CameraRotateStrategyParserUnitTest, camera_rotate_strategy_parser_unittest_005, TestSize.Level0)
{
    CameraRotateStrategyParser parser;
    bool ret = parser.LoadConfiguration();
    EXPECT_TRUE(ret);
    
    auto strategyInfos = parser.GetCameraRotateStrategyInfos();
    EXPECT_FALSE(strategyInfos.empty());
    parser.Destroy();
    
    ret = parser.LoadConfiguration();
    EXPECT_TRUE(ret);
    
    strategyInfos = parser.GetCameraRotateStrategyInfos();
    EXPECT_FALSE(strategyInfos.empty());
}

} // namespace CameraStandard
} // namespace OHOS