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

#include "camera_format_YUV_moduletest.h"
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
#include "test_token.h"
#include "token_setproc.h"
#include "os_account_manager.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

void CameraformatYUVModuleTest::UpdataCameraOutputCapability(int32_t modeName)
{
    if (!cameraManager_ || cameras_.empty()) {
        return;
    }
    auto outputCapability = cameraManager_->GetSupportedOutputCapability(cameras_[0], modeName);
    ASSERT_NE(outputCapability, nullptr);

    outputCapability->photoProfiles_[0].size_ = {640, 480};
    outputCapability->photoProfiles_[0].format_ = CAMERA_FORMAT_YUV_420_SP;
    outputCapability->previewProfiles_[0].size_ = {640, 480};
    outputCapability->previewProfiles_[0].format_ = CAMERA_FORMAT_YUV_420_SP;

    previewProfile_ = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfile_.empty());

    outputCapability->SetPreviewProfiles(previewProfile_);
    cameras_[0]->SetProfile(outputCapability);

    photoProfile_ = outputCapability->GetPhotoProfiles();
    ASSERT_FALSE(photoProfile_.empty());

    outputCapability->SetPhotoProfiles(photoProfile_);
    cameras_[0]->SetProfile(outputCapability);
}

void CameraformatYUVModuleTest::UpdataCameraOutputCapabilitySrc(int32_t modeName)
{
    if (!cameraManager_ || cameras_.empty()) {
        return;
    }
    auto outputCapability = cameraManager_->GetSupportedOutputCapability(cameras_[0], modeName);
    ASSERT_NE(outputCapability, nullptr);

    outputCapability->photoProfiles_[0].size_ = {640, 480};
    outputCapability->photoProfiles_[0].format_ = CAMERA_FORMAT_YUV_422_YUYV;
    outputCapability->previewProfiles_[0].size_ = {640, 480};
    outputCapability->previewProfiles_[0].format_ = CAMERA_FORMAT_YUV_422_YUYV;

    previewProfile_ = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfile_.empty());

    outputCapability->SetPreviewProfiles(previewProfile_);
    cameras_[0]->SetProfile(outputCapability);

    photoProfile_ = outputCapability->GetPhotoProfiles();
    ASSERT_FALSE(photoProfile_.empty());

    outputCapability->SetPhotoProfiles(photoProfile_);
    cameras_[0]->SetProfile(outputCapability);
}

void CameraformatYUVModuleTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraformatYUVModuleTest::SetUpTestCase started!");
    ASSERT_TRUE(TestToken::GetAllCameraPermission());
}

void CameraformatYUVModuleTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraformatYUVModuleTest::TearDownTestCase started!");
}

void CameraformatYUVModuleTest::SetUp()
{
    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);
    cameras_ = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras_.empty());
    session_ = cameraManager_->CreateCaptureSession(SceneMode::NORMAL);
    ASSERT_NE(session_, nullptr);
    input_ = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input_, nullptr);
    input_->Open();
}

void CameraformatYUVModuleTest::TearDown()
{
    MEDIA_DEBUG_LOG("CameraformatYUVModuleTest::TearDown started!");
    cameraManager_ = nullptr;
    cameras_.clear();
    input_->Close();
    preview_->Release();
    input_->Release();
    session_->Release();
}

/*
 * Feature: Framework
 * Function: Test the functionality of capturing YUV photos.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the functionality of capturing YUV photos which the format is YUV_420_SP.
 */
HWTEST_F(CameraformatYUVModuleTest, camera_format_YUV_moduletest_001, TestSize.Level0)
{
    UpdataCameraOutputCapability();
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    preview_ = cameraManager_->CreatePreviewOutput(previewProfile_[0], surface);
    ASSERT_NE(preview_, nullptr);
    sptr<IConsumerSurface> iConsumerSurface = IConsumerSurface::Create();
    ASSERT_NE(iConsumerSurface, nullptr);
    sptr<IBufferProducer> surface2 = iConsumerSurface->GetProducer();
    ASSERT_NE(surface2, nullptr);
    sptr<CaptureOutput> photoOutput = cameraManager_->CreatePhotoOutput(photoProfile_[0], surface2);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_EQ(session_->BeginConfig(), 0);
    EXPECT_EQ(session_->AddInput(input_), 0);
    if (!session_->CanAddOutput(preview_)) {
        GTEST_SKIP();
    }
    EXPECT_EQ(session_->AddOutput(preview_), 0);
    if (!session_->CanAddOutput(photoOutput)) {
        GTEST_SKIP();
    }
    EXPECT_EQ(session_->AddOutput(photoOutput), 0);
    EXPECT_EQ(session_->CommitConfig(), 0);

    auto intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);
    intResult = ((sptr<PhotoOutput>&)photoOutput)->Capture();
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    intResult = session_->Stop();
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test the functionality of capturing YUV photos.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the functionality of capturing YUV photos which the format is YUV_422_YUYV.
 */
HWTEST_F(CameraformatYUVModuleTest, camera_format_YUV_moduletest_002, TestSize.Level0)
{
    UpdataCameraOutputCapabilitySrc();
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    preview_ = cameraManager_->CreatePreviewOutput(previewProfile_[0], surface);
    ASSERT_NE(preview_, nullptr);
    sptr<IConsumerSurface> iConsumerSurface = IConsumerSurface::Create();
    ASSERT_NE(iConsumerSurface, nullptr);
    sptr<IBufferProducer> surface2 = iConsumerSurface->GetProducer();
    ASSERT_NE(surface2, nullptr);
    sptr<CaptureOutput> photoOutput = cameraManager_->CreatePhotoOutput(photoProfile_[0], surface2);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_EQ(session_->BeginConfig(), 0);
    EXPECT_EQ(session_->AddInput(input_), 0);
    if (!session_->CanAddOutput(preview_)) {
        GTEST_SKIP();
    }
    EXPECT_EQ(session_->AddOutput(preview_), 0);
    if (!session_->CanAddOutput(photoOutput)) {
        GTEST_SKIP();
    }
    EXPECT_EQ(session_->AddOutput(photoOutput), 0);
    EXPECT_EQ(session_->CommitConfig(), 0);

    auto intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);
    intResult = ((sptr<PhotoOutput>&)photoOutput)->Capture();
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    intResult = session_->Stop();
    EXPECT_EQ(intResult, 0);
}
}  // namespace CameraStandard
}  // namespace OHOS