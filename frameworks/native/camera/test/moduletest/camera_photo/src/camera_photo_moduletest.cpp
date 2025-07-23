/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "camera_photo_moduletest.h"
#include "test_token.h"
#include "camera_log.h"


using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
static std::mutex g_mutex;

void CameraPhotoModuleTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraPhotoModuleTest::SetUpTestCase started!");
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
}

void CameraPhotoModuleTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraPhotoModuleTest::TearDownTestCase started!");
}

void CameraPhotoModuleTest::SetUp()
{
    MEDIA_INFO_LOG("CameraPhotoModuleTest::SetUp start!");

    manager_ = CameraManager::GetInstance();
    ASSERT_NE(manager_, nullptr);
    cameras_ = manager_->GetSupportedCameras();
    ASSERT_FALSE(cameras_.empty());
    session_ = manager_->CreateCaptureSession(SceneMode::CAPTURE);
    ASSERT_NE(session_, nullptr);
    input_ = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input_, nullptr);
    EXPECT_EQ(input_->Open(), SUCCESS);

    UpdataCameraOutputCapability();
    EXPECT_EQ(CreatePreviewOutput(previewProfile_[0], previewOutput_), SUCCESS);
    EXPECT_EQ(CreatePhotoOutputWithoutSurface(photoProfile_[0], photoOutput_), SUCCESS);

    MEDIA_INFO_LOG("CameraPhotoModuleTest::SetUp end!");
}

void CameraPhotoModuleTest::TearDown()
{
    MEDIA_INFO_LOG("CameraPhotoModuleTest::TearDown start!");

    cameras_.clear();
    photoProfile_.clear();
    previewProfile_.clear();

    photoOutput_->Release();
    previewOutput_->Release();

    manager_ = nullptr;
    input_->Release();
    session_->Release();

    MEDIA_INFO_LOG("CameraPhotoModuleTest::TearDown end!");
}

void CameraPhotoModuleTest::UpdataCameraOutputCapability(int32_t modeName)
{
    if (!manager_ || cameras_.empty()) {
        return;
    }
    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], modeName);
    ASSERT_NE(outputCapability, nullptr);

    previewProfile_ = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfile_.empty());

    photoProfile_ = outputCapability->GetPhotoProfiles();
    ASSERT_FALSE(photoProfile_.empty());
}

int32_t CameraPhotoModuleTest::CreatePreviewOutput(Profile &profile, sptr<PreviewOutput> &previewOutput)
{
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    if (surface == nullptr) {
        MEDIA_ERR_LOG("Failed to get previewOutput surface");
        return INVALID_ARGUMENT;
    }
    surface->SetUserData(CameraManager::surfaceFormat, std::to_string(profile.GetCameraFormat()));
    int32_t retCode = manager_->CreatePreviewOutput(profile, surface, &previewOutput);
    if (retCode != CameraErrorCode::SUCCESS) {
        return SERVICE_FATL_ERROR;
    }
    return SUCCESS;
}

int32_t CameraPhotoModuleTest::CreatePhotoOutputWithoutSurface(Profile &profile,
    sptr<PhotoOutput> &photoOutput)
{
    int32_t retCode = manager_->CreatePhotoOutput(profile, &photoOutput_);
    CHECK_RETURN_RET_ELOG((retCode != CameraErrorCode::SUCCESS || photoOutput_ == nullptr),
        SERVICE_FATL_ERROR, "Create photo output failed");

    photoOutput_->SetNativeSurface(true);
    return SUCCESS;
}

/*
 * Feature: Framework
 * Function: Test create photo output without surface.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test create photo output without surface
 * after submitting the camera settings,and expect the movingphoto feature can be turned on successfully.
 */
HWTEST_F(CameraPhotoModuleTest, camera_photo_moduletest_001, TestSize.Level0)
{
    EXPECT_EQ(session_->BeginConfig(), SUCCESS);
    EXPECT_EQ(session_->AddInput((sptr<CaptureInput>&)input_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)previewOutput_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)photoOutput_), SUCCESS);
    callbackFlag_ = 0;
    if (photoOutput_->IsQuickThumbnailSupported()) {
        std::cout << "support thumbnail!" << std::endl;
        EXPECT_EQ(photoOutput_->SetThumbnail(true), SUCCESS);
    } else {
        std::cout << "not support thumbnail!" << std::endl;
    }

    EXPECT_EQ(session_->CommitConfig(), SUCCESS);
    EXPECT_EQ(session_->Start(), SUCCESS);
    sleep(WAIT_TIME_AFTER_START);

    EXPECT_EQ(photoOutput_->Capture(), SUCCESS);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    EXPECT_EQ(session_->Stop(), SUCCESS);
}
}  // namespace CameraStandard
}  // namespace OHOS
