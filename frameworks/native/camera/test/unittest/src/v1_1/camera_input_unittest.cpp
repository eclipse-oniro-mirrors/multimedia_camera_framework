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

#include "camera_input_unittest.h"
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

void CameraInputUnitTest::SetUpTestCase(void) {}

void CameraInputUnitTest::TearDownTestCase(void) {}

void CameraInputUnitTest::SetUp()
{
    NativeAuthorization();
    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);
}

void CameraInputUnitTest::TearDown()
{
    cameraManager_ = nullptr;
}

void CameraInputUnitTest::NativeAuthorization()
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
    MEDIA_DEBUG_LOG("CameraInputUnitTest::NativeAuthorization uid:%{public}d", uid_);
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

/*
 * Feature: Framework
 * Function: Test CameraInput with SetInputUsedAsPosition
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetInputUsedAsPosition for Normal branches
 */
HWTEST_F(CameraInputUnitTest, camera_input_unittest_001, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    CameraPosition usedAsPosition = CAMERA_POSITION_UNSPECIFIED;
    camInput->SetInputUsedAsPosition(usedAsPosition);
    EXPECT_EQ(camInput->cameraObj_->usedAsCameraPosition_, CAMERA_POSITION_UNSPECIFIED);
}

/*
 * Feature: Framework
 * Function: Test CameraInput with SetInputUsedAsPosition
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetInputUsedAsPosition for Normal branches
 */
HWTEST_F(CameraInputUnitTest, camera_input_unittest_002, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    CameraPosition usedAsPosition = CAMERA_POSITION_BACK;
    camInput->SetInputUsedAsPosition(usedAsPosition);
    EXPECT_EQ(camInput->cameraObj_->usedAsCameraPosition_, CAMERA_POSITION_BACK);
}

/*
 * Feature: Framework
 * Function: Test CameraInput with SetInputUsedAsPosition
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetInputUsedAsPosition for Normal branches
 */
HWTEST_F(CameraInputUnitTest, camera_input_unittest_003, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    CameraPosition usedAsPosition = CAMERA_POSITION_FRONT;
    camInput->SetInputUsedAsPosition(usedAsPosition);
    EXPECT_EQ(camInput->cameraObj_->usedAsCameraPosition_, CAMERA_POSITION_FRONT);
}

/*
 * Feature: Framework
 * Function: Test CameraInput with SetOcclusionDetectCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetOcclusionDetectCallback for cameraOcclusionDetectCallback is nullptr
 */
HWTEST_F(CameraInputUnitTest, camera_input_unittest_004, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    std::shared_ptr<CameraOcclusionDetectCallback> cameraOcclusionDetectCallback = nullptr;
    camInput->SetOcclusionDetectCallback(cameraOcclusionDetectCallback);
    EXPECT_EQ(camInput->cameraOcclusionDetectCallback_, nullptr);
}

/*
 * Feature: Framework
 * Function: Test CameraInput with CameraServerDied
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CameraInput with CameraServerDied for abnormal branches
 */
HWTEST_F(CameraInputUnitTest, camera_input_unittest_005, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    pid_t pid = 0;
    camInput->CameraServerDied(pid);
    EXPECT_EQ(camInput->errorCallback_, nullptr);
}


/*
 * Feature: Framework
 * Function: Test GetCameraId
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCameraId
 */
HWTEST_F(CameraInputUnitTest, camera_input_unittest_006, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    EXPECT_EQ(camInput->GetCameraId(), cameras[0]->GetID());
}

/*
 * Feature: Framework
 * Function: Test UpdateSetting with changedMetadata = nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Test UpdateSetting with changedMetadata = nullptr
 */
HWTEST_F(CameraInputUnitTest, camera_input_unittest_007, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::shared_ptr<OHOS::Camera::CameraMetadata> changedMetadata = nullptr;

    int ret = camInput->UpdateSetting(changedMetadata);
    EXPECT_EQ(ret, 2);
}

/*
 * Feature: Framework
 * Function: Test UpdateSetting with changedMetadata = nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Test UpdateSetting with changedMetadata = nullptr
 */
HWTEST_F(CameraInputUnitTest, camera_input_unittest_008, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::shared_ptr<OHOS::Camera::CameraMetadata> changedMetadata = cameras[0]->GetMetadata();
    ASSERT_NE(changedMetadata, nullptr);

    int ret = camInput->UpdateSetting(changedMetadata);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test SetCameraSettings
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetCameraSettings
 */
HWTEST_F(CameraInputUnitTest, camera_input_unittest_009, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();

    int ret = camInput->SetCameraSettings(cameraSettings);
    EXPECT_EQ(ret, 2);
}

/*
 * Feature: Framework
 * Function: Test GetCameraSettings with nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCameraSettings with nullptr
 */
HWTEST_F(CameraInputUnitTest, camera_input_unittest_010, TestSize.Level0)
{
    sptr<CameraDevice> camera0 = nullptr;
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(camera0);
    EXPECT_EQ(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
}

/*
 * Feature: Framework
 * Function: Test GetCameraAllVendorTags
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCameraAllVendorTags
 */
HWTEST_F(CameraInputUnitTest, camera_input_unittest_011, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    std::vector<vendorTag_t> infos = {};
    EXPECT_EQ((camInput->GetCameraAllVendorTags(infos)), 0);
}

/*
 * Feature: Framework
 * Function: Test GetCameraDeviceInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCameraDeviceInfo
 */
HWTEST_F(CameraInputUnitTest, camera_input_unittest_012, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    EXPECT_EQ(cameras[0], camInput->GetCameraDeviceInfo());
}
}
}