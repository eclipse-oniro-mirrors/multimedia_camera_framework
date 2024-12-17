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

#include "camera_device_unittest.h"
#include "gtest/gtest.h"
#include <cstdint>
#include <vector>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_log.h"
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

void CameraDeviceUnit::SetUpTestCase(void) {}

void CameraDeviceUnit::TearDownTestCase(void) {}

void CameraDeviceUnit::SetUp()
{
    NativeAuthorization();
    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);
}

void CameraDeviceUnit::TearDown()
{
    cameraManager_ = nullptr;
}

void CameraDeviceUnit::NativeAuthorization()
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
    MEDIA_DEBUG_LOG("CameraDeviceUnit::NativeAuthorization uid:%{public}d", uid_);
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

/*
 * Feature: Framework
 * Function: Test cameradevice with GetPosition and GetZoomRatioRange
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetPosition for invoke and GetZoomRatioRange for zoomRatioRange_ not empty
 */
HWTEST_F(CameraDeviceUnit, camera_device_unittest_001, TestSize.Level0)
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
HWTEST_F(CameraDeviceUnit, camera_device_unittest_002, TestSize.Level0)
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
HWTEST_F(CameraDeviceUnit, camera_device_unittest_003, TestSize.Level0)
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
HWTEST_F(CameraDeviceUnit, camera_device_unittest_004, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    CameraPosition usedAsPositionRet = CAMERA_POSITION_BACK;
    cameras[0]->SetCameraDeviceUsedAsPosition(usedAsPositionRet);
    EXPECT_EQ(cameras[0]->usedAsCameraPosition_, CAMERA_POSITION_BACK);

    EXPECT_EQ(cameras[0]->GetSupportedFoldStatus(), 0);
}
}
}
