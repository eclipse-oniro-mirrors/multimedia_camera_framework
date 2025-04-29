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

#include "camera_rotate_param_sign_tools_unittest.h"

#include <fstream>
#include <iostream>
#include <sstream>
#include "camera_log.h"
#include "file_ex.h"
#include "camera_util.h"
#include "camera_rotate_param_sign_tools.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

const std::string PUBKEY_PATH = "/system/etc/camera/hwkey_param_upgrade_v1.pem";
const std::string PARAM_SERVICE_INSTALL_PATH = "/data/service/el1/public/update/param_service/install/system";
const std::string CAMERA_ROTATE_CFG_DIR = "/etc/camera/";

void CameraRotateParamSignToolsUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraRotateParamSignToolsUnitTest::SetUpTestCase started!");
}

void CameraRotateParamSignToolsUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraRotateParamSignToolsUnitTest::TearDownTestCase started!");
}

void CameraRotateParamSignToolsUnitTest::SetUp()
{
    MEDIA_DEBUG_LOG("CameraRotateParamSignToolsUnitTest::SetUp started!");
}

void CameraRotateParamSignToolsUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("CameraRotateParamSignToolsUnitTest::TearDown started!");
}

/*
 * Feature: Framework
 * Function: Test VerifyFileSign abnormal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test VerifyFileSign abnormal branches.
 */
HWTEST_F(CameraRotateParamSignToolsUnitTest, camera_rotate_param_sign_tools_unittest_001, TestSize.Level1)
{
    std::string certFile = PARAM_SERVICE_INSTALL_PATH + CAMERA_ROTATE_CFG_DIR + "/CERT.ENC";
    std::string verifyFile = PARAM_SERVICE_INSTALL_PATH + CAMERA_ROTATE_CFG_DIR + "/CERT.SF";
    auto signTool = std::make_shared<CameraRoateParamSignTool>();

    bool result = true;
    result = signTool->VerifyFileSign("", certFile, verifyFile);
    EXPECT_FALSE(result);
    result = signTool->VerifyFileSign(PUBKEY_PATH, "", verifyFile);
    EXPECT_FALSE(result);
    result = signTool->VerifyFileSign(PUBKEY_PATH, certFile, "");
    EXPECT_FALSE(result);
}

/*
 * Feature: Framework
 * Function: Test VerifyRsa abnormal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test VerifyRsa abnormal branches.
 */
HWTEST_F(CameraRotateParamSignToolsUnitTest, camera_rotate_param_sign_tools_unittest_002, TestSize.Level1)
{
    auto signTool = std::make_shared<CameraRoateParamSignTool>();

    bool result = true;
    RSA *pubKey = RSA_new();
    result = signTool->VerifyRsa(pubKey, "", "");
    EXPECT_FALSE(result);
}

/*
 * Feature: Framework
 * Function: Test CalcFileSha256Digest abnormal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CalcFileSha256Digest abnormal branches.
 */
HWTEST_F(CameraRotateParamSignToolsUnitTest, camera_rotate_param_sign_tools_unittest_003, TestSize.Level1)
{
    auto signTool = std::make_shared<CameraRoateParamSignTool>();

    std::tuple<int, std::string>  result;
    result = signTool->CalcFileSha256Digest("invalid");
    EXPECT_EQ(std::get<1>(result), "");
}

/*
 * Feature: Framework
 * Function: Test ForEachFileSegment abnormal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ForEachFileSegment abnormal branches.
 */
HWTEST_F(CameraRotateParamSignToolsUnitTest, camera_rotate_param_sign_tools_unittest_004, TestSize.Level1)
{
    auto signTool = std::make_shared<CameraRoateParamSignTool>();
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    auto sha256Update = [ctx = &ctx](char *buf, size_t len) { SHA256_Update(ctx, buf, len); };

    int ret = signTool->ForEachFileSegment("invalid", sha256Update);
    EXPECT_NE(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test CalcBase64 normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CalcBase64 normal branches.
 */
HWTEST_F(CameraRotateParamSignToolsUnitTest, camera_rotate_param_sign_tools_unittest_005, TestSize.Level1)
{
    auto signTool = std::make_shared<CameraRoateParamSignTool>();

    std::string encodedStr = "encodedString";
    auto res = std::make_unique<unsigned char[]>(32);

    signTool->CalcBase64(res.get(), 4, encodedStr);
    EXPECT_FALSE(encodedStr == "encodedString");
}

} // CameraStandard
} // OHOS