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
HWTEST_F(CameraAbilityUnitTest, camera_ability_unittest_001, TestSize.Level0)
{
    sptr<CameraAbility> cameraAbility = new CameraAbility();
    ASSERT_NE(cameraAbility, nullptr);
    cameraAbility->IsLcdFlashSupported();
    std::vector<FlashMode> flashModeList = cameraAbility->GetSupportedFlashModes();
    bool isFlashModeSupported = false;
    FlashMode flashMode = FlashMode::FLASH_MODE_OPEN;
    isFlashModeSupported = cameraAbility->IsFlashModeSupported(flashMode);
    if (((std::find(flashModeList.begin(), flashModeList.end(), flashMode)) != (flashModeList.end()))) {
        EXPECT_TRUE(isFlashModeSupported);
    }
    EXPECT_FALSE(isFlashModeSupported);
}

/*
 * Feature: Framework
 * Function: Test get support exposure mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get support exposure mode
 */
HWTEST_F(CameraAbilityUnitTest, camera_ability_unittest_002, TestSize.Level0)
{
    sptr<CameraAbility> cameraAbility = new CameraAbility();
    ASSERT_NE(cameraAbility, nullptr);
    cameraAbility->GetExposureBiasRange();
    cameraAbility->GetSupportedExposureRange();
    std::vector<ExposureMode> exposureModeList = cameraAbility->GetSupportedExposureModes();
    bool isExposureModeSupported = false;
    ExposureMode exposureMode = ExposureMode::EXPOSURE_MODE_AUTO;
    isExposureModeSupported = cameraAbility->IsExposureModeSupported(exposureMode);
    if (((std::find(exposureModeList.begin(), exposureModeList.end(), exposureMode)) != (exposureModeList.end()))) {
        EXPECT_TRUE(isExposureModeSupported);
    }
    EXPECT_FALSE(isExposureModeSupported);
}

/*
 * Feature: Framework
 * Function: Test whether deep integration is supported
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test whether deep integration is supported
 */
HWTEST_F(CameraAbilityUnitTest, camera_ability_unittest_003, TestSize.Level0)
{
    sptr<CameraAbility> cameraAbility = new CameraAbility();
    ASSERT_NE(cameraAbility, nullptr);
    cameraAbility->GetDepthFusionThreshold();
    bool isSupported = (cameraAbility->isDepthFusionSupported_).value_or(false);
    if (isSupported) {
        EXPECT_TRUE(cameraAbility->IsDepthFusionSupported());
    }
    EXPECT_FALSE(cameraAbility->IsDepthFusionSupported());
}

/*
 * Feature: Framework
 * Function: Test function supported or not
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test function supported or not
 */
HWTEST_F(CameraAbilityUnitTest, camera_ability_unittest_004, TestSize.Level0)
{
    sptr<CameraAbility> cameraAbility = new CameraAbility();
    ASSERT_NE(cameraAbility, nullptr);
    bool issupport = (std::find(cameraAbility->supportedSceneFeature_.begin(),
        cameraAbility->supportedSceneFeature_.end(), SceneFeature::FEATURE_ENUM_MAX)) !=
        (cameraAbility->supportedSceneFeature_.end());
    if (issupport) {
        EXPECT_TRUE(cameraAbility->IsFeatureSupported(SceneFeature::FEATURE_ENUM_MAX));
    }
    EXPECT_FALSE(cameraAbility->IsFeatureSupported(SceneFeature::FEATURE_ENUM_MAX));
}

} // CameraStandard
} // OHOS
