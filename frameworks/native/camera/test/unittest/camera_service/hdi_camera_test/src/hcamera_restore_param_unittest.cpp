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

#include "hcamera_restore_param_unittest.h"
#include "camera_log.h"
#include "camera_metadata_info.h"
#include "session/capture_scene_const.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

void HCameraRestoreParamUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("HCameraRestoreParamUnitTest::SetUpTestCase started!");
}

void HCameraRestoreParamUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("HCameraRestoreParamUnitTest::TearDownTestCase started!");
}

void HCameraRestoreParamUnitTest::SetUp()
{
    MEDIA_DEBUG_LOG("HCameraRestoreParamUnitTest::SetUp started!");
}

void HCameraRestoreParamUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("HCameraRestoreParamUnitTest::TearDown started!");
}

/*
 * Feature: HCameraRestoreParam
 * Function: Test constructor with full parameters
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test constructor with all parameters
 */
HWTEST_F(HCameraRestoreParamUnitTest, hcamera_restore_param_unittest_001, TestSize.Level1)
{
    std::string clientName = "test_client";
    std::string cameraId = "test_camera";
    std::vector<StreamInfo_V1_1> streamInfos;
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings =
        std::make_shared<OHOS::Camera::CameraMetadata>(10, 100);
    RestoreParamTypeOhos restoreParamType = RestoreParamTypeOhos::TRANSIENT_ACTIVE_PARAM_OHOS;
    int startActiveTime = 1000;

    sptr<HCameraRestoreParam> restoreParam = new HCameraRestoreParam(
        clientName, cameraId, streamInfos, settings, restoreParamType, startActiveTime);
    ASSERT_NE(restoreParam, nullptr);
    EXPECT_EQ(restoreParam->GetClientName(), clientName);
    EXPECT_EQ(restoreParam->GetCameraId(), cameraId);
    EXPECT_EQ(restoreParam->GetStreamInfo().size(), streamInfos.size());
    EXPECT_EQ(restoreParam->GetSetting(), settings);
    EXPECT_EQ(restoreParam->GetRestoreParamType(), restoreParamType);
    EXPECT_EQ(restoreParam->GetStartActiveTime(), startActiveTime);
}

/*
 * Feature: HCameraRestoreParam
 * Function: Test constructor with minimal parameters
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test constructor with only client name and camera ID
 */
HWTEST_F(HCameraRestoreParamUnitTest, hcamera_restore_param_unittest_002, TestSize.Level1)
{
    std::string clientName = "test_client";
    std::string cameraId = "test_camera";

    sptr<HCameraRestoreParam> restoreParam = new HCameraRestoreParam(clientName, cameraId);
    ASSERT_NE(restoreParam, nullptr);

    EXPECT_EQ(restoreParam->GetClientName(), clientName);
    EXPECT_EQ(restoreParam->GetCameraId(), cameraId);
}

/*
 * Feature: HCameraRestoreParam
 * Function: Test SetSetting and GetSetting
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test setting and getting camera settings
 */
HWTEST_F(HCameraRestoreParamUnitTest, hcamera_restore_param_unittest_004, TestSize.Level1)
{
    std::string clientName = "test_client";
    std::string cameraId = "test_camera";
    sptr<HCameraRestoreParam> restoreParam = new HCameraRestoreParam(clientName, cameraId);
    ASSERT_NE(restoreParam, nullptr);

    std::shared_ptr<OHOS::Camera::CameraMetadata> settings =
        std::make_shared<OHOS::Camera::CameraMetadata>(10, 100);
    restoreParam->SetSetting(settings);
    EXPECT_EQ(restoreParam->GetSetting(), settings);
}

/*
 * Feature: HCameraRestoreParam
 * Function: Test UpdateExposureSetting
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test updating exposure settings with different scenarios
 */
HWTEST_F(HCameraRestoreParamUnitTest, hcamera_restore_param_unittest_005, TestSize.Level1)
{
    std::string clientName = "test_client";
    std::string cameraId = "test_camera";
    sptr<HCameraRestoreParam> restoreParam = new HCameraRestoreParam(clientName, cameraId);
    ASSERT_NE(restoreParam, nullptr);

    restoreParam->UpdateExposureSetting(1000);
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings =
        std::make_shared<OHOS::Camera::CameraMetadata>(10, 100);
    restoreParam->SetSetting(settings);
    restoreParam->SetCameraOpMode(SceneMode::PROFESSIONAL_PHOTO);
    restoreParam->UpdateExposureSetting(1000);
    restoreParam->SetCameraOpMode(1);
    restoreParam->UpdateExposureSetting(31000);
}

/*
 * Feature: HCameraRestoreParam
 * Function: Test SetRestoreParamType and GetRestoreParamType
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test setting and getting restore parameter type
 */
HWTEST_F(HCameraRestoreParamUnitTest, hcamera_restore_param_unittest_006, TestSize.Level1)
{
    std::string clientName = "test_client";
    std::string cameraId = "test_camera";
    sptr<HCameraRestoreParam> restoreParam = new HCameraRestoreParam(clientName, cameraId);
    ASSERT_NE(restoreParam, nullptr);
    RestoreParamTypeOhos type = RestoreParamTypeOhos::PERSISTENT_DEFAULT_PARAM_OHOS;
    restoreParam->SetRestoreParamType(type);
    EXPECT_EQ(restoreParam->GetRestoreParamType(), type);
}

/*
 * Feature: HCameraRestoreParam
 * Function: Test SetStartActiveTime and GetStartActiveTime
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test setting and getting start active time
 */
HWTEST_F(HCameraRestoreParamUnitTest, hcamera_restore_param_unittest_007, TestSize.Level1)
{
    std::string clientName = "test_client";
    std::string cameraId = "test_camera";
    sptr<HCameraRestoreParam> restoreParam = new HCameraRestoreParam(clientName, cameraId);
    ASSERT_NE(restoreParam, nullptr);
    int activeTime = 2000;
    restoreParam->SetStartActiveTime(activeTime);
    EXPECT_EQ(restoreParam->GetStartActiveTime(), activeTime);
}

/*
 * Feature: HCameraRestoreParam
 * Function: Test SetCloseCameraTime and GetCloseCameraTime
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test setting and getting close camera time
 */
HWTEST_F(HCameraRestoreParamUnitTest, hcamera_restore_param_unittest_008, TestSize.Level1)
{
    std::string clientName = "test_client";
    std::string cameraId = "test_camera";
    sptr<HCameraRestoreParam> restoreParam = new HCameraRestoreParam(clientName, cameraId);
    ASSERT_NE(restoreParam, nullptr);
    timeval closeTime = {1000, 0};
    restoreParam->SetCloseCameraTime(closeTime);
    timeval result = restoreParam->GetCloseCameraTime();
    EXPECT_EQ(result.tv_sec, closeTime.tv_sec);
    EXPECT_EQ(result.tv_usec, closeTime.tv_usec);
}

/*
 * Feature: HCameraRestoreParam
 * Function: Test SetCameraOpMode and GetCameraOpMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test setting and getting camera operation mode
 */
HWTEST_F(HCameraRestoreParamUnitTest, hcamera_restore_param_unittest_009, TestSize.Level1)
{
    std::string clientName = "test_client";
    std::string cameraId = "test_camera";
    sptr<HCameraRestoreParam> restoreParam = new HCameraRestoreParam(clientName, cameraId);
    ASSERT_NE(restoreParam, nullptr);
    int32_t opMode = SceneMode::PROFESSIONAL_VIDEO;
    restoreParam->SetCameraOpMode(opMode);
    EXPECT_EQ(restoreParam->GetCameraOpMode(), opMode);
}

/*
 * Feature: HCameraRestoreParam
 * Function: Test SetFoldStatus and GetFoldStatus
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test setting and getting fold status
 */
HWTEST_F(HCameraRestoreParamUnitTest, hcamera_restore_param_unittest_010, TestSize.Level1)
{
    std::string clientName = "test_client";
    std::string cameraId = "test_camera";
    sptr<HCameraRestoreParam> restoreParam = new HCameraRestoreParam(clientName, cameraId);
    ASSERT_NE(restoreParam, nullptr);
    int foldStatus = 1;
    restoreParam->SetFoldStatus(foldStatus);
    EXPECT_EQ(restoreParam->GetFlodStatus(), foldStatus);
}

} // namespace CameraStandard
} // namespace OHOS