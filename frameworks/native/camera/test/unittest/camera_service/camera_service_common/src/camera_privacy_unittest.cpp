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

#include "camera_log.h"
#include "camera_privacy.h"
#include "camera_privacy_unittest.h"
#include "capture_scene_const.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "os_account_manager.h"
#include "test_token.h"
#include "token_setproc.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

void CameraPrivacyUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraPrivacyUnitTest::SetUpTestCase started!");
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
}

void CameraPrivacyUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraPrivacyUnitTest::TearDownTestCase started!");
}

void CameraPrivacyUnitTest::SetUp()
{
    MEDIA_DEBUG_LOG("CameraPrivacyUnitTest::SetUp started!");
}

void CameraPrivacyUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("CameraPrivacyUnitTest::TearDown started!");
}

/*
 * Feature: Framework
 * Function: Test cameraPrivacy functional function.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameraPrivacy functional function.
 */
HWTEST_F(CameraPrivacyUnitTest, camera_privacy_unittest_001, TestSize.Level0)
{
    wptr<HCameraDevice> device;
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    sptr<CameraPrivacy> cameraPrivacy = new CameraPrivacy(callingTokenId, IPCSkeleton::GetCallingPid());
    bool ret = cameraPrivacy->IsAllowUsingCamera();
    EXPECT_TRUE(ret);
    ret = cameraPrivacy->RegisterPermissionCallback();
    EXPECT_TRUE(ret);
    cameraPrivacy->UnregisterPermissionCallback();
    if (cameraPrivacy->IsAllowUsingCamera()) {
        bool ret = cameraPrivacy->AddCameraPermissionUsedRecord();
        EXPECT_TRUE(ret);
        ret = cameraPrivacy->StartUsingPermissionCallback();
        EXPECT_TRUE(ret);
        cameraPrivacy->StopUsingPermissionCallback();
    }
}

/*
 * Feature: Framework
 * Function: Test CameraPrivacy permission callback functions
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test RegisterPermissionCallback and UnregisterPermissionCallback functions
 */
HWTEST_F(CameraPrivacyUnitTest, camera_privacy_unittest_005, TestSize.Level1)
{
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    sptr<CameraPrivacy> cameraPrivacy = new CameraPrivacy(callingTokenId, IPCSkeleton::GetCallingPid());

    bool ret = cameraPrivacy->RegisterPermissionCallback();
    EXPECT_FALSE(ret);

    cameraPrivacy->UnregisterPermissionCallback();

    cameraPrivacy->UnregisterPermissionCallback();
}

/*
 * Feature: Framework
 * Function: Test CameraPrivacy permission record functions
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AddCameraPermissionUsedRecord function
 */
HWTEST_F(CameraPrivacyUnitTest, camera_privacy_unittest_006, TestSize.Level1)
{
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    sptr<CameraPrivacy> cameraPrivacy = new CameraPrivacy(callingTokenId, IPCSkeleton::GetCallingPid());

    bool ret = cameraPrivacy->AddCameraPermissionUsedRecord();
    EXPECT_FALSE(ret);
}

/*
 * Feature: Framework
 * Function: Test CameraPrivacy wait and notify functions
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test WaitFor and Notify functions
 */
HWTEST_F(CameraPrivacyUnitTest, camera_privacy_unittest_007, TestSize.Level1)
{
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    sptr<CameraPrivacy> cameraPrivacy = new CameraPrivacy(callingTokenId, IPCSkeleton::GetCallingPid());

    std::cv_status status = cameraPrivacy->WaitFor(true);
    EXPECT_EQ(status, std::cv_status::timeout);

    cameraPrivacy->Notify();
}

/*
 * Feature: Framework
 * Function: Test CameraPrivacy wait and notify functions
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test PermissionStatusChangeCb class
 */
HWTEST_F(CameraPrivacyUnitTest, camera_privacy_unittest_008, TestSize.Level1)
{
    Security::AccessToken::PermStateChangeScope scopeInfo;
    scopeInfo.permList = {OHOS_PERMISSION_CAMERA};
    scopeInfo.tokenIDs = {IPCSkeleton::GetCallingTokenID()};

    auto callback = std::make_shared<PermissionStatusChangeCb>(scopeInfo);
    Security::AccessToken::PermStateChangeInfo result;
    result.permStateChangeType = 0;
    result.permissionName = OHOS_PERMISSION_CAMERA;
    result.tokenID = IPCSkeleton::GetCallingTokenID();
    callback->PermStateChangeCallback(result);
}

/*
 * Feature: Framework
 * Function: Test CameraPrivacy camera use state change callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CameraUseStateChangeCb class
 */
HWTEST_F(CameraPrivacyUnitTest, camera_privacy_unittest_009, TestSize.Level1)
{
    auto callback = std::make_shared<CameraUseStateChangeCb>();
    callback->StateChangeNotify(IPCSkeleton::GetCallingTokenID(), true);
    callback->StateChangeNotify(IPCSkeleton::GetCallingTokenID(), false);
}
} // CameraStandard
} // OHOS
