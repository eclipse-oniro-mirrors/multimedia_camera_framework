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

#include "camera_rotate_param_manager_unittest.h"

#include <iostream>
#include <fstream>
#include <filesystem>
#include <common_event_data.h>
#include <common_event_manager.h>
#include <common_event_support.h>
#include "common_event_subscriber.h"
#include "camera_util.h"
#include "camera_log.h"
#include "camera_rotate_param_manager.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

void CameraRotateParamManagerUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraRotateParamManagerUnitTest::SetUpTestCase started!");
}

void CameraRotateParamManagerUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraRotateParamManagerUnitTest::TearDownTestCase started!");
    std::set<std::string> fileName = {
        "version.txt", "version_copy.txt", "camera_rotate_strategy.xml"};
    for (auto& file : fileName) {
        if (CheckPathExist((CAMERA_SERVICE_ABS_PATH + file).c_str())) {
            if (!RemoveFile(CAMERA_SERVICE_ABS_PATH + file)) {
                MEDIA_DEBUG_LOG("remove path failed!");
                return;
            }
        }
    }
}

void CameraRotateParamManagerUnitTest::SetUp()
{
    MEDIA_DEBUG_LOG("CameraRotateParamManagerUnitTest::SetUp started!");
}

void CameraRotateParamManagerUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("CameraRotateParamManagerUnitTest::TearDown started!");
}

/*
 * Feature: Framework
 * Function: Test LoadVersion normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test LoadVersion normal branches.
 */
HWTEST_F(CameraRotateParamManagerUnitTest, camera_rotate_param_manager_unittest_001, TestSize.Level1)
{
    auto manager = std::make_shared<CameraRoateParamManager>();

    manager->ReloadParam();
    std::string version = manager->LoadVersion();
    EXPECT_EQ(version, "");

    manager->InitParam();
    manager->SubscriberEvent();
    const std::string CONFIG_ACTION = "usual.event.DUE_SA_CFG_UPDATED";
    const std::string EVENT_INFO_TYPE = "type";
    const std::string CONFIG_TYPE = "camera";
    const std::string CONFIG_INVALID = "invalid";
    OHOS::AAFwk::Want want1;
    want1.SetAction(CONFIG_ACTION);
    want1.SetParam(EVENT_INFO_TYPE, CONFIG_INVALID);
    manager->OnReceiveEvent(want1);
    manager->HandleParamUpdate(want1);
    OHOS::AAFwk::Want want2;
    want2.SetAction(CONFIG_INVALID);
    want2.SetParam(EVENT_INFO_TYPE, CONFIG_TYPE);
    manager->HandleParamUpdate(want2);
    OHOS::AAFwk::Want want3;
    want3.SetAction(CONFIG_INVALID);
    want3.SetParam(EVENT_INFO_TYPE, CONFIG_INVALID);
    manager->HandleParamUpdate(want3);
    OHOS::AAFwk::Want want4;
    want4.SetAction(CONFIG_ACTION);
    want4.SetParam(EVENT_INFO_TYPE, CONFIG_TYPE);
    manager->HandleParamUpdate(want4);
    manager->ReloadParam();
    version = manager->LoadVersion();
    EXPECT_EQ(version, "1.0.0.0");
    manager->UnSubscriberEvent();
}

/*
 * Feature: Framework
 * Function: Test InitDefaultConfig normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test InitDefaultConfig normal branches.
 */
HWTEST_F(CameraRotateParamManagerUnitTest, camera_rotate_param_manager_unittest_002, TestSize.Level1)
{
    auto manager = std::make_shared<CameraRoateParamManager>();

    manager->InitDefaultConfig();
    EXPECT_EQ(manager->totalFeatureSwitch, 1);
}

/*
 * Feature: Framework
 * Function: Test DoCopy normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DoCopy normal branches.
 */
HWTEST_F(CameraRotateParamManagerUnitTest, camera_rotate_param_manager_unittest_003, TestSize.Level1)
{
    const std::string VERSION_VALUE
        = R"(version=1.0.0.0
        type=camera
        subtype=generic
        subtype=generic
        classify=1
        displayVersion=TZ.GENC.11.10.20.100)";
    auto manager = std::make_shared<CameraRoateParamManager>();
    std::string srcPath = CAMERA_SERVICE_ABS_PATH + "version.txt";
    std::string dstPath = CAMERA_SERVICE_ABS_PATH + "version_copy.txt";
    std::string fakePath = CAMERA_SERVICE_ABS_PATH + "test.txt";

    std::ofstream srcFile(srcPath);
    if (!srcFile.is_open()) {
        MEDIA_DEBUG_LOG("can't create version.txt file");
        return;
    }
    srcFile << VERSION_VALUE;
    srcFile.close();

    manager->CopyFileToLocal();
    bool res = manager->DoCopy(fakePath, dstPath);
    EXPECT_EQ(res, false);
    res = manager->DoCopy(srcPath, dstPath);
    EXPECT_EQ(res, true);
    res = manager->DoCopy(srcPath, srcPath);
    EXPECT_EQ(res, false);
}

/*
 * Feature: Framework
 * Function: Test LoadConfiguration abnormal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test LoadConfiguration abnormal branches.
 */
HWTEST_F(CameraRotateParamManagerUnitTest, camera_rotate_param_manager_unittest_004, TestSize.Level1)
{
    auto manager = std::make_shared<CameraRoateParamManager>();

    bool ret = manager->LoadConfiguration(CAMERA_SERVICE_ABS_PATH + "test.xml");
    EXPECT_EQ(ret, false);
    manager->Destroy();
}

/*
 * Feature: Framework
 * Function: Test LoadConfiguration normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test LoadConfiguration normal branches.
 */
HWTEST_F(CameraRotateParamManagerUnitTest, camera_rotate_param_manager_unittest_005, TestSize.Level1)
{
    const std::string STRATEGY_VALUE = R"(<?xml version="1.0" encoding="utf-8"?>
        <cameraRotateStrategy xmlns:xi="http://www.w3.org/2001/XInclude" version="1.0">
          <strategy bundleName="com.icbc.harmonyclient" wideValue="" rotateDegree="90" fps=""/>
          <strategy bundleName="com.cmbchina.harmony" wideValue="" rotateDegree="90" fps=""/>
          <strategy bundleName="com.bankcomm.mobshos" wideValue="" rotateDegree="90" fps=""/>
          <strategy bundleName="cn.com.cmbc.ohmbank" wideValue="" rotateDegree="90" fps=""/>
          <strategy bundleName="com.cgbchina.xpt.hm" wideValue="" rotateDegree="90" fps=""/>
        </cameraRotateStrategy>)";
    auto manager = std::make_shared<CameraRoateParamManager>();
    std::string strategyPath = CAMERA_SERVICE_ABS_PATH + "camera_rotate_strategy.xml";
    std::ofstream strategyFile(strategyPath);
    if (!strategyFile.is_open()) {
        MEDIA_DEBUG_LOG("can't create camera_rotate_strategy.xml file");
        return;
    }
    strategyFile << STRATEGY_VALUE;
    strategyFile.close();

    bool ret = manager->LoadConfiguration(strategyPath);
    EXPECT_EQ(ret, true);
}

} // CameraStandard
} // OHOS