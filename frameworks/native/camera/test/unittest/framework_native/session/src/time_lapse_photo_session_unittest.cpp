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

#include "time_lapse_photo_session_unittest.h"
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
void TimeLapsePhotoSessionUnitTest::SetUpTestCase(void) {}

void TimeLapsePhotoSessionUnitTest::TearDownTestCase(void) {}

void TimeLapsePhotoSessionUnitTest::SetUp()
{
    NativeAuthorization();
    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);
}

void TimeLapsePhotoSessionUnitTest::TearDown()
{
    cameraManager_ = nullptr;
    MEDIA_DEBUG_LOG("TimeLapsePhotoSessionUnitTest TearDown");
}

void TimeLapsePhotoSessionUnitTest::NativeAuthorization()
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
    MEDIA_DEBUG_LOG("TimeLapsePhotoSessionUnitTest::NativeAuthorization g_uid:%{public}d", uid_);
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

/*
 * Feature: Framework
 * Function: Test TimeLapsePhotoSession with ProcessCallbacks, StartTryAE, StopTryAE, IsWhiteBalanceModeSupported,
 * SetWhiteBalanceMode, GetWhiteBalanceMode
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessCallbacks, StartTryAE, StopTryAE, IsWhiteBalanceModeSupported,
 * SetWhiteBalanceMode, GetWhiteBalanceMode for just call.
 */
HWTEST_F(TimeLapsePhotoSessionUnitTest, time_lapse_photo_function_unittest_001, TestSize.Level1)
{
    sptr<CaptureSession> captureSession = cameraManager_->CreateCaptureSession(SceneMode::TIMELAPSE_PHOTO);
    ASSERT_NE(captureSession, nullptr);
    sptr<TimeLapsePhotoSession> timeLapsePhotoSession =
        static_cast<TimeLapsePhotoSession*>(captureSession.GetRefPtr());
    TimeLapsePhotoSessionMetadataResultProcessor timeLapse(timeLapsePhotoSession);
    uint64_t timestamp = 1;
    auto metadata = make_shared<OHOS::Camera::CameraMetadata>(10, 100);
    timeLapse.ProcessCallbacks(timestamp, metadata);
    EXPECT_EQ(timeLapsePhotoSession->StartTryAE(), CameraErrorCode::SESSION_NOT_CONFIG);
    EXPECT_EQ(timeLapsePhotoSession->StopTryAE(), CameraErrorCode::SESSION_NOT_CONFIG);

    WhiteBalanceMode mode = AWB_MODE_AUTO;
    bool result = false;
    EXPECT_EQ(timeLapsePhotoSession->IsWhiteBalanceModeSupported(mode, result), CameraErrorCode::SESSION_NOT_CONFIG);
    EXPECT_EQ(timeLapsePhotoSession->SetWhiteBalanceMode(mode), CameraErrorCode::SESSION_NOT_CONFIG);
    EXPECT_EQ(timeLapsePhotoSession->GetWhiteBalanceMode(mode), CameraErrorCode::SESSION_NOT_CONFIG);
}
}
}