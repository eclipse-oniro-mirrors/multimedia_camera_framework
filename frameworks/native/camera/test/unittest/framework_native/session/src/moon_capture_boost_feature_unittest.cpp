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

#include "moon_capture_boost_feature_unittest.h"
#include "gtest/gtest.h"
#include <cstdint>
#include <vector>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_util.h"
#include "gmock/gmock.h"
#include "hap_token_info.h"
#include "ipc_skeleton.h"
#include "metadata_utils.h"
#include "nativetoken_kit.h"
#include "surface.h"
#include "test_common.h"
#include "token_setproc.h"
#include "os_account_manager.h"
#include "sketch_wrapper.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
void MoonCaptureBoostUnitTest::SetUpTestCase(void) {}

void MoonCaptureBoostUnitTest::TearDownTestCase(void) {}

void MoonCaptureBoostUnitTest::SetUp()
{
    NativeAuthorization();
    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);
}

void MoonCaptureBoostUnitTest::TearDown()
{
    cameraManager_ = nullptr;
    MEDIA_DEBUG_LOG("MoonCaptureBoostUnitTest TearDown");
}

void MoonCaptureBoostUnitTest::NativeAuthorization()
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
    MEDIA_DEBUG_LOG("MoonCaptureBoostUnitTest::NativeAuthorization g_uid:%{public}d", uid_);
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

/*
 * Feature: Framework
 * Function: Test MoonCaptureBoostFeature with GetSketchReferenceFovRatio, GetSketchEnableRatio
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSketchReferenceFovRatio, GetSketchEnableRatio for just call.
 */
HWTEST_F(MoonCaptureBoostUnitTest, moon_capture_boost_function_unittest_001, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    SceneMode relatedMode = NORMAL;
    std::shared_ptr<OHOS::Camera::CameraMetadata> deviceAbility = cameras[0]->GetMetadata();
    std::shared_ptr<MoonCaptureBoostFeature> moonCapture = std::make_shared<MoonCaptureBoostFeature>(relatedMode,
        deviceAbility);
    ASSERT_NE(moonCapture, nullptr);
    float zoomMin = -1.0f;
    moonCapture->GetSketchReferenceFovRatio(zoomMin);
    moonCapture->sketchZoomRatioRange_.zoomMin = zoomMin;
    EXPECT_EQ(moonCapture->GetSketchEnableRatio(), zoomMin);
}
}
}