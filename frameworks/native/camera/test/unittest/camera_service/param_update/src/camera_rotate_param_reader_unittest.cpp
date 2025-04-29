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

#include "camera_rotate_param_reader_unittest.h"

#include <memory>
#include <iostream>
#include <fstream>

#include "camera_log.h"
#include "camera_util.h"
#include "camera_rotate_param_reader.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

void CameraRotateParamReaderUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraRotateParamReaderUnitTest::SetUpTestCase started!");
}

void CameraRotateParamReaderUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraRotateParamReaderUnitTest::TearDownTestCase started!");
    std::set<std::string> fileName = {
        "version.txt", "CERT.ENC", "CERT.SF", "MANIFEST.MF"};
    for (auto& file : fileName) {
        if (CheckPathExist((CAMERA_SERVICE_ABS_PATH + file).c_str())) {
            if (!RemoveFile(CAMERA_SERVICE_ABS_PATH + file)) {
                MEDIA_DEBUG_LOG("remove path failed!");
                return;
            }
        }
    }
}

void CameraRotateParamReaderUnitTest::SetUp()
{
    MEDIA_DEBUG_LOG("CameraRotateParamReaderUnitTest::SetUp started!");
}

void CameraRotateParamReaderUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("CameraRotateParamReaderUnitTest::TearDown started!");
}

/*
 * Feature: Framework
 * Function: Test GetConfigFilePath normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetConfigFilePath normal branches.
 */
HWTEST_F(CameraRotateParamReaderUnitTest, camera_rotate_param_reader_unittest_001, TestSize.Level1)
{
    auto reader = std::make_shared<CameraRoateParamReader>();

    std::string expectedPath = PARAM_SERVICE_INSTALL_PATH + CAMERA_ROTATE_CFG_DIR;
    EXPECT_EQ(reader->GetConfigFilePath(), expectedPath);
}

/*
 * Feature: Framework
 * Function: Test GetPathVersion abnormal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetPathVersion abnormal branches.
 */
HWTEST_F(CameraRotateParamReaderUnitTest, camera_rotate_param_reader_unittest_002, TestSize.Level1)
{
    auto reader = std::make_shared<CameraRoateParamReader>();
    std::string filePathStr = PARAM_SERVICE_INSTALL_PATH + CAMERA_ROTATE_CFG_DIR + VERSION_FILE_NAME;
    std::ifstream file(filePathStr);
    if (!file.good()) {
        EXPECT_EQ(reader->GetPathVersion(), DEFAULT_VERSION);
    }
}

/*
 * Feature: Framework
 * Function: Test GetVersionInfoStr normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetVersionInfoStr normal branches.
 */
HWTEST_F(CameraRotateParamReaderUnitTest, camera_rotate_param_reader_unittest_003, TestSize.Level1)
{
    const std::string VERSION_VALUE
        = R"(version=1.0.0.0
        type=camera
        subtype=generic
        subtype=generic
        classify=1
        displayVersion=TZ.GENC.11.10.20.100)";
    auto reader = std::make_shared<CameraRoateParamReader>();
    std::string versionFilePath = CAMERA_SERVICE_ABS_PATH + "version.txt";

    if (CheckPathExist((versionFilePath).c_str())) {
        if (!RemoveFile(versionFilePath)) {
            MEDIA_DEBUG_LOG("remove path failed!");
            return;
        }
    }
    std::string ret = reader->GetVersionInfoStr(versionFilePath);
    EXPECT_EQ(ret, DEFAULT_VERSION);

    std::ofstream versionFile(versionFilePath);
    if (!versionFile.is_open()) {
        MEDIA_DEBUG_LOG("can't create version.txt file");
        return;
    }
    versionFile << VERSION_VALUE;
    versionFile.close();

    ret = reader->GetVersionInfoStr(versionFilePath);
    EXPECT_EQ(ret, "1.0.0.0");

    bool res = reader->VerifyParamFile(CAMERA_SERVICE_ABS_PATH, "version.txt");
    EXPECT_EQ(res, false);
}

/*
 * Feature: Framework
 * Function: Test VersionStrToNumber normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test VersionStrToNumber normal branches.
 */
HWTEST_F(CameraRotateParamReaderUnitTest, camera_rotate_param_reader_unittest_004, TestSize.Level1)
{
    auto reader = std::make_shared<CameraRoateParamReader>();

    std::vector<std::string> versionNum;
    std::string versionStr1 = "1.2.3";
    bool res = reader->VersionStrToNumber(versionStr1, versionNum);
    EXPECT_EQ(res, false);
    std::string versionStr2 = "1.2.3.4";
    res = reader->VersionStrToNumber(versionStr2, versionNum);
    EXPECT_EQ(res, true);
}

/*
 * Feature: Framework
 * Function: Test CompareVersion normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CompareVersion normal branches.
 */
HWTEST_F(CameraRotateParamReaderUnitTest, camera_rotate_param_reader_unittest_005, TestSize.Level1)
{
    auto reader = std::make_shared<CameraRoateParamReader>();

    std::vector<std::string> ver1 = {"1", "0", "0", "0"};
    std::vector<std::string> ver2 = {"1", "0", "0"};
    std::vector<std::string> ver3 = {"1", "0", "0", "1"};
    bool res = reader->CompareVersion(ver1, ver2);
    EXPECT_EQ(res, false);
    res = reader->CompareVersion(ver2, ver1);
    EXPECT_EQ(res, false);
    res = reader->CompareVersion(ver2, ver2);
    EXPECT_EQ(res, false);
    res = reader->CompareVersion(ver1, ver1);
    EXPECT_EQ(res, false);
    res = reader->CompareVersion(ver1, ver3);
    EXPECT_EQ(res, true);
}

/*
 * Feature: Framework
 * Function: Test VerifyParamFile abnormal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test VerifyParamFile abnormal branches.
 */
HWTEST_F(CameraRotateParamReaderUnitTest, camera_rotate_param_reader_unittest_006, TestSize.Level1)
{
    auto reader = std::make_shared<CameraRoateParamReader>();
    std::string cfgDir = PARAM_SERVICE_INSTALL_PATH + CAMERA_ROTATE_CFG_DIR;
    bool res = reader->VerifyParamFile(cfgDir, "test.txt");
    EXPECT_EQ(res, false);
}

/*
 * Feature: Framework
 * Function: Test VerifyParamFile abnormal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test VerifyParamFile abnormal branches.
 */
HWTEST_F(CameraRotateParamReaderUnitTest, camera_rotate_param_reader_unittest_007, TestSize.Level1)
{
    auto reader = std::make_shared<CameraRoateParamReader>();

    const std::string MANIFEST_VALUE = R"("Name:  )";
    std::string manifestFilePath = CAMERA_SERVICE_ABS_PATH + "MANIFEST.MF";
    std::ofstream manifestFile(manifestFilePath);
    if (!manifestFile.is_open()) {
        MEDIA_DEBUG_LOG("can't create MANIFEST.MF file");
        return;
    }
    manifestFile << MANIFEST_VALUE;
    manifestFile.close();
    bool result = reader->VerifyParamFile(CAMERA_SERVICE_ABS_PATH, "version.txt");
    EXPECT_EQ(result, false);

    const std::string MANIFEST_VALUE_1 = R"("Name: aaaabbbb)";

    if (!manifestFile.is_open()) {
        MEDIA_DEBUG_LOG("can't create MANIFEST.MF file");
        return;
    }
    manifestFile << MANIFEST_VALUE_1;
    manifestFile.close();
    result = reader->VerifyParamFile(CAMERA_SERVICE_ABS_PATH, "version.txt");
    EXPECT_EQ(result, false);
}

/*
 * Feature: Framework
 * Function: Test VerifyCertSfFile abnormal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test VerifyCertSfFile abnormal branches.
 */
HWTEST_F(CameraRotateParamReaderUnitTest, camera_rotate_param_reader_unittest_008, TestSize.Level1)
{
    auto reader = std::make_shared<CameraRoateParamReader>();

    std::string certFile = CAMERA_SERVICE_ABS_PATH + "/CERT.ENC";
    std::string verifyFile = CAMERA_SERVICE_ABS_PATH + "/CERT.SF";
    std::string manifestFile = CAMERA_SERVICE_ABS_PATH + "/MANIFEST.MF";
    bool res = reader->VerifyCertSfFile(certFile, verifyFile, manifestFile);
    EXPECT_EQ(res, false);
}

} // CameraStandard
} // OHOS