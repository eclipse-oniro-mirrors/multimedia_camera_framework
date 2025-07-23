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

#include <cstdint>
#include <vector>

#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_device_unittest.h"
#include "camera_log.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "hap_token_info.h"
#include "ipc_skeleton.h"
#include "metadata_utils.h"
#include "nativetoken_kit.h"
#include "os_account_manager.h"
#include "surface.h"
#include "test_common.h"
#include "test_token.h"
#include "token_setproc.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

void CameraDeviceUnit::SetUpTestCase(void)
{
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
}

void CameraDeviceUnit::TearDownTestCase(void) {}

void CameraDeviceUnit::SetUp()
{
    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);
}

void CameraDeviceUnit::TearDown()
{
    cameraManager_ = nullptr;
}

/*
 * Feature: Framework
 * Function: Test cameradevice with GetPosition and GetZoomRatioRange
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetPosition for invoke and GetZoomRatioRange for zoomRatioRange_ not empty
 */
HWTEST_F(CameraDeviceUnit, camera_device_unittest_001, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    cameras[0]->GetPosition();
    cameras[0]->zoomRatioRange_ = {1.1, 2.1};
    EXPECT_EQ(cameras[0]->GetZoomRatioRange(), cameras[0]->zoomRatioRange_);
}

/*
 * Feature: Framework
 * Function: Test cameradevice with SetProfile
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetProfile for capability is nullptr
 */
HWTEST_F(CameraDeviceUnit, camera_device_unittest_002, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    sptr<CameraOutputCapability> capabilityRet = nullptr;
    int32_t modeNameRet = 0;
    cameras[0]->SetProfile(capabilityRet);
    EXPECT_FALSE(cameras[0]->modePreviewProfiles_.empty());
    cameras[0]->SetProfile(capabilityRet, modeNameRet);
    EXPECT_FALSE(cameras[0]->modePreviewProfiles_.empty());
}

/*
 * Feature: Framework
 * Function: Test cameradevice with position and zoomratiorange
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameradevice with position and zoomratiorange
 */
HWTEST_F(CameraDeviceUnit, camera_device_unittest_003, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    cameras[0]->foldScreenType_ = CAMERA_FOLDSCREEN_INNER;
    cameras[0]->cameraPosition_ = CAMERA_POSITION_FRONT;
    cameras[0]->GetPosition();
    cameras[0]->zoomRatioRange_ = {1.1, 2.1};
    EXPECT_EQ(cameras[0]->GetZoomRatioRange(), cameras[0]->zoomRatioRange_);
}

/*
 * Feature: Framework
 * Function: Test cameradevice with SetCameraDeviceUsedAsPosition and GetSupportedFoldStatus
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetCameraDeviceUsedAsPosition for invoke and GetSupportedFoldStatus for invoke
 */
HWTEST_F(CameraDeviceUnit, camera_device_unittest_004, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    CameraPosition usedAsPositionRet = CAMERA_POSITION_BACK;
    cameras[0]->SetCameraDeviceUsedAsPosition(usedAsPositionRet);
    EXPECT_EQ(cameras[0]->usedAsCameraPosition_, CAMERA_POSITION_BACK);

    EXPECT_EQ(cameras[0]->GetSupportedFoldStatus(), 0);
}

/*
 * Feature: Framework
 * Function: Test cameradevice with GetCameraFoldScreenType
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCameraFoldScreenType
 */
HWTEST_F(CameraDeviceUnit, camera_device_unittest_005, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    cameras[0]->foldScreenType_ = CameraFoldScreenType::CAMERA_FOLDSCREEN_UNSPECIFIED;
    EXPECT_EQ(cameras[0]->GetCameraFoldScreenType(), CameraFoldScreenType::CAMERA_FOLDSCREEN_UNSPECIFIED);
}

/*
 * Feature: Framework
 * Function: Test cameradevice with GetPosition abnormal branches
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetPosition abnormal branches
 */
HWTEST_F(CameraDeviceUnit, camera_device_unittest_006, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    cameras[0]->cameraPosition_ = CameraPosition::CAMERA_POSITION_FRONT;
    EXPECT_EQ(cameras[0]->GetPosition(), CameraPosition::CAMERA_POSITION_FRONT);
    cameras[0]->cameraPosition_ = CameraPosition::CAMERA_POSITION_UNSPECIFIED;
    EXPECT_EQ(cameras[0]->GetPosition(), CameraPosition::CAMERA_POSITION_UNSPECIFIED);
    cameras[0]->foldScreenType_ = CAMERA_FOLDSCREEN_INNER;
    EXPECT_EQ(cameras[0]->GetPosition(), CameraPosition::CAMERA_POSITION_UNSPECIFIED);
    cameras[0]->foldScreenType_ = CAMERA_FOLDSCREEN_UNSPECIFIED;
    EXPECT_EQ(cameras[0]->GetPosition(), CameraPosition::CAMERA_POSITION_UNSPECIFIED);
}

/*
 * Feature: Framework
 * Function: Test cameradevice with GetlensEquivalentFocalLength
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetLensEquivalentFocalLength
 */
HWTEST_F(CameraDeviceUnit, camera_device_unittest_007, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    cameras[0]->lensEquivalentFocalLength_ = {15, 20};
    EXPECT_EQ(cameras[0]->GetLensEquivalentFocalLength(), cameras[0]->lensEquivalentFocalLength_);
}
}
}
