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

#include "camera_privacy_unittest.h"

#include "camera_log.h"
#include "camera_privacy.h"
#include "capture_scene_const.h"
#include "ipc_skeleton.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

void CameraPrivacyUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraPrivacyUnitTest::SetUpTestCase started!");
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
    const uint32_t callingTokenId = 10;
    sptr<CameraPrivacy> cameraPrivacy = new CameraPrivacy(device, callingTokenId, IPCSkeleton::GetCallingPid());
    bool ret = cameraPrivacy->IsAllowUsingCamera();
    EXPECT_FALSE(ret);
    ret = cameraPrivacy->RegisterPermissionCallback();
    EXPECT_FALSE(ret);
    cameraPrivacy->UnregisterPermissionCallback();
    ret = cameraPrivacy->AddCameraPermissionUsedRecord();
    EXPECT_TRUE(ret);
    ret = cameraPrivacy->StartUsingPermissionCallback();
    EXPECT_TRUE(ret);
    cameraPrivacy->StopUsingPermissionCallback();
    delete cameraPrivacy;
}
} // CameraStandard
} // OHOS
