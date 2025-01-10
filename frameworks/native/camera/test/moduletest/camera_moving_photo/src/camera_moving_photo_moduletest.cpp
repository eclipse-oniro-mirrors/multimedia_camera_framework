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

#include "camera_moving_photo_moduletest.h"
#include "gtest/gtest.h"
#include <cstdint>
#include <vector>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_util.h"
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

void CameraMovingPhotoModuleTest::UpdataCameraOutputCapability(int32_t modeName)
{
    if (!cameraManager_ || cameras_.empty()) {
        return;
    }
    auto outputCapability = cameraManager_->GetSupportedOutputCapability(cameras_[0], modeName);
    ASSERT_NE(outputCapability, nullptr);

    previewProfile_ = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfile_.empty());

    photoProfile_ = outputCapability->GetPhotoProfiles();
    ASSERT_FALSE(photoProfile_.empty());
}

void CameraMovingPhotoModuleTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraMovingPhotoModuleTest::SetUpTestCase started!");
}

void CameraMovingPhotoModuleTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraMovingPhotoModuleTest::TearDownTestCase started!");
}

void CameraMovingPhotoModuleTest::SetUp()
{
    NativeAuthorization();
    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);
    cameras_ = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras_.empty());
    session_ = cameraManager_->CreateCaptureSession(SceneMode::CAPTURE);
    ASSERT_NE(session_, nullptr);
    input_ = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input_, nullptr);
    input_->Open();
    UpdataCameraOutputCapability();
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    preview_ = cameraManager_->CreatePreviewOutput(previewProfile_[0], surface);
    ASSERT_NE(preview_, nullptr);
    sptr<IConsumerSurface> iConsumerSurface = IConsumerSurface::Create();
    ASSERT_NE(iConsumerSurface, nullptr);
    sptr<IBufferProducer> surface2 = iConsumerSurface->GetProducer();
    ASSERT_NE(surface2, nullptr);
    photoOutput_ = cameraManager_->CreatePhotoOutput(photoProfile_[0], surface2);
    ASSERT_NE(photoOutput_, nullptr);
}

void CameraMovingPhotoModuleTest::TearDown()
{
    MEDIA_DEBUG_LOG("CameraMovingPhotoModuleTest::TearDown started!");
    cameraManager_ = nullptr;
    cameras_.clear();
    input_->Close();
    preview_->Release();
    input_->Release();
    session_->Release();
}

void CameraMovingPhotoModuleTest::NativeAuthorization()
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
    MEDIA_DEBUG_LOG("CaptureSessionUnitTest::NativeAuthorization uid:%{public}d", uid_);
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

/*
 * Feature: Framework
 * Function: Test the normal scenario of movingphoto.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the normal scenario of movingphoto,Call the EnableMovingPhoto function
 * after submitting the camera settings,and expect the movingphoto feature can be turned on successfully.
 */
HWTEST_F(CameraMovingPhotoModuleTest, camera_moving_photo_moduletest_001, TestSize.Level0)
{
    EXPECT_EQ(session_->BeginConfig(), 0);
    EXPECT_EQ(session_->AddInput(input_), 0);
    EXPECT_EQ(session_->AddOutput(preview_), 0);
    EXPECT_EQ(session_->AddOutput(photoOutput_), 0);
    EXPECT_EQ(session_->CommitConfig(), 0);

    if (session_->IsMovingPhotoSupported()) {
        session_->LockForControl();
        auto ret = session_->EnableMovingPhoto(true);
        session_->UnlockForControl();
        EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
    }

    auto intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);
    intResult = ((sptr<PhotoOutput>&)photoOutput_)->Capture();
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    intResult = session_->Stop();
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test the abnormal scenario of movingphoto.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the abnormal scenario of movingphoto,Call the EnableMovingPhoto function then tunrn off
 * after submitting the camera settings,and expect the movingphoto feature can not be turned on successfully.
 */
HWTEST_F(CameraMovingPhotoModuleTest, camera_moving_photo_moduletest_002, TestSize.Level0)
{
    EXPECT_EQ(session_->BeginConfig(), 0);
    EXPECT_EQ(session_->AddInput(input_), 0);
    EXPECT_EQ(session_->AddOutput(preview_), 0);
    EXPECT_EQ(session_->AddOutput(photoOutput_), 0);
    EXPECT_EQ(session_->CommitConfig(), 0);

    if (session_->IsMovingPhotoSupported()) {
        session_->LockForControl();
        auto ret = session_->EnableMovingPhoto(true);
        session_->UnlockForControl();
        EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
        session_->LockForControl();
        ret = session_->EnableMovingPhoto(false);
        session_->UnlockForControl();
        EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
        EXPECT_EQ(session_->isMovingPhotoEnabled_, false);
    }

    auto intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);
    intResult = ((sptr<PhotoOutput>&)photoOutput_)->Capture();
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    intResult = session_->Stop();
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test the normal scenario of movingphoto.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the normal scenario of movingphoto,Call the EnableMovingPhotoMirror function
 * after submitting the camera settings,and expect the movingphotomirror feature can be turned on successfully.
 */
HWTEST_F(CameraMovingPhotoModuleTest, camera_moving_photo_moduletest_003, TestSize.Level0)
{
    EXPECT_EQ(session_->BeginConfig(), 0);
    EXPECT_EQ(session_->AddInput(input_), 0);
    EXPECT_EQ(session_->AddOutput(preview_), 0);
    EXPECT_EQ(session_->AddOutput(photoOutput_), 0);
    EXPECT_EQ(session_->CommitConfig(), 0);

    if (session_->IsMovingPhotoSupported()) {
        session_->LockForControl();
        auto ret = session_->EnableMovingPhoto(true);
        session_->UnlockForControl();
        EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
        ret = session_->EnableMovingPhotoMirror(true, true);
        EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
    }

    auto intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);
    intResult = ((sptr<PhotoOutput>&)photoOutput_)->Capture();
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    intResult = session_->Stop();
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test the normal scenario of movingphoto.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the normal scenario of movingphoto,Call the EnableMovingPhotoMirror function then tunrn off
 * after submitting the camera settings,and expect the movingphotomirror feature can be turned on successfully.
 */
HWTEST_F(CameraMovingPhotoModuleTest, camera_moving_photo_moduletest_004, TestSize.Level0)
{
    EXPECT_EQ(session_->BeginConfig(), 0);
    EXPECT_EQ(session_->AddInput(input_), 0);
    EXPECT_EQ(session_->AddOutput(preview_), 0);
    EXPECT_EQ(session_->AddOutput(photoOutput_), 0);
    EXPECT_EQ(session_->CommitConfig(), 0);

    if (session_->IsMovingPhotoSupported()) {
        session_->LockForControl();
        auto ret = session_->EnableMovingPhoto(true);
        session_->UnlockForControl();
        EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
        ret = session_->EnableMovingPhotoMirror(true, true);
        EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
        ret = session_->EnableMovingPhotoMirror(false, true);
        EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
    }

    auto intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);
    intResult = ((sptr<PhotoOutput>&)photoOutput_)->Capture();
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    intResult = session_->Stop();
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test the abnormal scenario of movingphoto.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the abnormal scenario of movingphoto,Call the EnableMovingPhoto function
 * before starting the camera settings,and expect the movingphoto feature can not be turned on successfully.
 */
HWTEST_F(CameraMovingPhotoModuleTest, camera_moving_photo_moduletest_005, TestSize.Level0)
{
    if (session_->IsMovingPhotoSupported()) {
        session_->LockForControl();
        auto ret = session_->EnableMovingPhoto(true);
        session_->UnlockForControl();
        EXPECT_EQ(ret, CameraErrorCode::SERVICE_FATL_ERROR);
    }
    EXPECT_EQ(session_->BeginConfig(), 0);
    EXPECT_EQ(session_->AddInput(input_), 0);
    EXPECT_EQ(session_->AddOutput(preview_), 0);
    EXPECT_EQ(session_->AddOutput(photoOutput_), 0);
    EXPECT_EQ(session_->CommitConfig(), 0);

    auto intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);
    intResult = ((sptr<PhotoOutput>&)photoOutput_)->Capture();
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    intResult = session_->Stop();
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test the abnormal scenario of movingphoto.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the abnormal scenario of movingphoto,Call the EnableMovingPhoto function
 * before submitting the camera settings,and expect the movingphoto feature can not be turned on successfully.
 */
HWTEST_F(CameraMovingPhotoModuleTest, camera_moving_photo_moduletest_006, TestSize.Level0)
{
    EXPECT_EQ(session_->BeginConfig(), 0);
    EXPECT_EQ(session_->AddInput(input_), 0);
    EXPECT_EQ(session_->AddOutput(preview_), 0);
    EXPECT_EQ(session_->AddOutput(photoOutput_), 0);
    if (session_->IsMovingPhotoSupported()) {
        session_->LockForControl();
        auto ret = session_->EnableMovingPhoto(true);
        session_->UnlockForControl();
        EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
    }
    EXPECT_EQ(session_->CommitConfig(), 0);

    auto intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);
    intResult = ((sptr<PhotoOutput>&)photoOutput_)->Capture();
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    intResult = session_->Stop();
    EXPECT_EQ(intResult, 0);
}
}  // namespace CameraStandard
}  // namespace OHOS
