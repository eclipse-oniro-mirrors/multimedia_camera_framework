/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "camera_ability_unittest.h"

#include "camera_log.h"
#include "capture_scene_const.h"
#include "message_parcel.h"
#include "surface.h"
#include "ability/camera_ability.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

void CameraAbilityUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraAbilityUnitTest::SetUpTestCase started!");
}

void CameraAbilityUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraAbilityUnitTest::TearDownTestCase started!");
}

void CameraAbilityUnitTest::SetUp()
{
    MEDIA_DEBUG_LOG("CameraAbilityUnitTest::SetUp started!");
}

void CameraAbilityUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("CameraAbilityUnitTest::TearDown started!");
}

/*
 * Feature: Framework
 * Function: Test get support flash mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get support flash mode
 */
HWTEST_F(CameraAbilityUnitTest, camera_ability_unittest_001, TestSize.Level1)
{
    sptr<CameraAbility> cameraAbility = new CameraAbility();
    ASSERT_NE(cameraAbility, nullptr);
    cameraAbility->IsLcdFlashSupported();
    std::vector<FlashMode> flashModeList = cameraAbility->GetSupportedFlashModes();
    cameraAbility->supportedFlashModes_.push_back(FlashMode::FLASH_MODE_OPEN);
    EXPECT_TRUE(cameraAbility->IsFlashModeSupported(FlashMode::FLASH_MODE_OPEN));
    cameraAbility->supportedFlashModes_.clear();
    EXPECT_FALSE(cameraAbility->IsFlashModeSupported(FlashMode::FLASH_MODE_OPEN));
}

/*
 * Feature: Framework
 * Function: Test get support exposure mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get support exposure mode
 */
HWTEST_F(CameraAbilityUnitTest, camera_ability_unittest_002, TestSize.Level1)
{
    sptr<CameraAbility> cameraAbility = new CameraAbility();
    ASSERT_NE(cameraAbility, nullptr);
    cameraAbility->GetExposureBiasRange();
    cameraAbility->GetSupportedExposureRange();
    std::vector<ExposureMode> exposureModeList = cameraAbility->GetSupportedExposureModes();
    cameraAbility->supportedExposureModes_.push_back(ExposureMode::EXPOSURE_MODE_AUTO);
    EXPECT_TRUE(cameraAbility->IsExposureModeSupported(ExposureMode::EXPOSURE_MODE_AUTO));
    cameraAbility->supportedExposureModes_.clear();
    EXPECT_FALSE(cameraAbility->IsExposureModeSupported(ExposureMode::EXPOSURE_MODE_AUTO));
}

/*
 * Feature: Framework
 * Function: Test whether deep integration is supported
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test whether deep integration is supported
 */
HWTEST_F(CameraAbilityUnitTest, camera_ability_unittest_003, TestSize.Level1)
{
    sptr<CameraAbility> cameraAbility = new CameraAbility();
    ASSERT_NE(cameraAbility, nullptr);
    cameraAbility->GetDepthFusionThreshold();
    bool isSupported = (cameraAbility->isDepthFusionSupported_).value_or(false);
    EXPECT_EQ(cameraAbility->IsDepthFusionSupported(), isSupported);
}

/*
 * Feature: Framework
 * Function: Test function supported or not
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test function supported or not
 */
HWTEST_F(CameraAbilityUnitTest, camera_ability_unittest_004, TestSize.Level1)
{
    sptr<CameraAbility> cameraAbility = new CameraAbility();
    ASSERT_NE(cameraAbility, nullptr);
    cameraAbility->supportedSceneFeature_.push_back(SceneFeature::FEATURE_ENUM_MAX);
    EXPECT_TRUE(cameraAbility->IsFeatureSupported(SceneFeature::FEATURE_ENUM_MAX));
    cameraAbility->supportedSceneFeature_.clear();
    EXPECT_FALSE(cameraAbility->IsFeatureSupported(SceneFeature::FEATURE_ENUM_MAX));
}

/*
 * Feature: Framework
 * Function: Test focus range function supported or not
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test focus range function supported or not
 */
HWTEST_F(CameraAbilityUnitTest, camera_ability_unittest_005, TestSize.Level1)
{
    sptr<CameraAbility> cameraAbility = new CameraAbility();
    ASSERT_NE(cameraAbility, nullptr);
    EXPECT_FALSE(cameraAbility->IsFocusRangeTypeSupported(FocusRangeType::FOCUS_RANGE_TYPE_AUTO));
}

/*
 * Feature: Framework
 * Function: Test focus driven function supported or not
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test focus driven function supported or not
 */
HWTEST_F(CameraAbilityUnitTest, camera_ability_unittest_006, TestSize.Level1)
{
    sptr<CameraAbility> cameraAbility = new CameraAbility();
    ASSERT_NE(cameraAbility, nullptr);
    EXPECT_FALSE(cameraAbility->IsFocusDrivenTypeSupported(FocusDrivenType::FOCUS_DRIVEN_TYPE_AUTO));
}

} // CameraStandard
} // OHOS
