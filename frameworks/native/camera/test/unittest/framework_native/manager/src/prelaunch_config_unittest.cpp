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

#include "prelaunch_config_unittest.h"
#include "gtest/gtest.h"
#include <cstdint>
#include <vector>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "gmock/gmock.h"
#include "hap_token_info.h"
#include "ipc_skeleton.h"
#include "metadata_utils.h"
#include "nativetoken_kit.h"
#include "surface.h"
#include "test_common.h"
#include "token_setproc.h"
#include "os_account_manager.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

void PrelaunchConfigUnit::SetUpTestCase(void) {}

void PrelaunchConfigUnit::TearDownTestCase(void) {}

void PrelaunchConfigUnit::SetUp()
{
    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);
}

void PrelaunchConfigUnit::TearDown()
{
    cameraManager_ = nullptr;
}


/*
 * Feature: Framework
 * Function: Test prelaunchConfig with GetCameraDevice
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test prelaunchConfig with GetCameraDevice
 */
HWTEST_F(PrelaunchConfigUnit, prelaunch_config_unittest_001, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    std::shared_ptr<PrelaunchConfig> prelaunchConfig = std::make_shared<PrelaunchConfig>(cameras[0]);
    sptr<CameraDevice> ret = prelaunchConfig->GetCameraDevice();
    EXPECT_EQ(ret, cameras[0]);
}

/*
 * Feature: Framework
 * Function: Test prelaunchConfig with GetRestoreParamType
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test prelaunchConfig with GetRestoreParamType
 */
HWTEST_F(PrelaunchConfigUnit, prelaunch_config_unittest_002, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    std::shared_ptr<PrelaunchConfig> prelaunchConfig = std::make_shared<PrelaunchConfig>(cameras[0]);
    prelaunchConfig->restoreParamType = RestoreParamType::TRANSIENT_ACTIVE_PARAM;
    RestoreParamType ret = prelaunchConfig->GetRestoreParamType();
    EXPECT_EQ(ret, RestoreParamType::TRANSIENT_ACTIVE_PARAM);
}

/*
 * Feature: Framework
 * Function: Test prelaunchConfig with GetActiveTime
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test prelaunchConfig with GetActiveTime
 */
HWTEST_F(PrelaunchConfigUnit, prelaunch_config_unittest_003, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    std::shared_ptr<PrelaunchConfig> prelaunchConfig = std::make_shared<PrelaunchConfig>(cameras[0]);
    prelaunchConfig->activeTime = 0;
    int ret = prelaunchConfig->GetActiveTime();
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test prelaunchConfig with GetSettingParam
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test prelaunchConfig with GetSettingParam
 */
HWTEST_F(PrelaunchConfigUnit, prelaunch_config_unittest_004, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    std::shared_ptr<PrelaunchConfig> prelaunchConfig = std::make_shared<PrelaunchConfig>(cameras[0]);
    prelaunchConfig->settingParam = {0, 0, 0};
    SettingParam ret = prelaunchConfig->GetSettingParam();
    EXPECT_EQ(ret.skinSmoothLevel, 0);
}
}
}
