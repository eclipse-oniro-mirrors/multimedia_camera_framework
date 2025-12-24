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

#include <cstdint>
#include <vector>

#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_util.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "hap_token_info.h"
#include "ipc_skeleton.h"
#include "metadata_utils.h"
#include "nativetoken_kit.h"
#include "os_account_manager.h"
#include "sketch_wrapper.h"
#include "stitching_photo_session_unittest.h"
#include "surface.h"
#include "test_common.h"
#include "test_token.h"
#include "token_setproc.h"

using namespace testing::ext;
using ::testing::_;
using ::testing::A;
using ::testing::InSequence;
using ::testing::Mock;
using ::testing::Return;

namespace OHOS {
namespace CameraStandard {
void CameraStitchingPhotoSessionUnit::SetUpTestCase(void)
{
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
}

void CameraStitchingPhotoSessionUnit::TearDownTestCase(void) {}

void CameraStitchingPhotoSessionUnit::SetUp()
{
    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);
}

void CameraStitchingPhotoSessionUnit::TearDown()
{
    cameraManager_ = nullptr;
    MEDIA_DEBUG_LOG("CameraStitchingPhotoSessionUnit TearDown");
}

/*
 * Feature: Framework
 * Function: Test StitchingPhotoSession previewOuput and photoOutput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test StitchingPhotoSession previewOuput and photoOutput
 */
HWTEST_F(CameraStitchingPhotoSessionUnit, camera_stitching_photo_session_unittest_001, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        if (find(modes.begin(), modes.end(), SceneMode::STITCHING_PHOTO) == modes.end()) {
            continue;
        }
        sptr<CaptureInput> input = cameraManager_->CreateCameraInput(camDevice);
        ASSERT_NE(input, nullptr);

        sptr<CameraInput> camInput = (sptr<CameraInput>&)input;
        std::string cameraSettings = camInput->GetCameraSettings();
        camInput->SetCameraSettings(cameraSettings);
        if (camInput->GetCameraDevice()) {
            camInput->GetCameraDevice()->SetMdmCheck(false);
            camInput->GetCameraDevice()->Open();
        }

        sptr<CaptureSession> session = cameraManager_->CreateCaptureSession(SceneMode::STITCHING_PHOTO);
        sptr<StitchingPhotoSession> stitchingPhotoSession = static_cast<StitchingPhotoSession*>(session.GetRefPtr());
        ASSERT_NE(stitchingPhotoSession, nullptr);

        sptr<Surface> previewSurface = Surface::CreateSurfaceAsConsumer();
        Profile previewProfile = Profile(PREVIEW_FORMAT, PREVIEW_SIZE);
        sptr<CaptureOutput> previewOutput = cameraManager_->CreatePreviewOutput(previewProfile, previewSurface);
        ASSERT_NE(previewOutput, nullptr);

        int32_t intResult = stitchingPhotoSession->BeginConfig();
        EXPECT_EQ(intResult, 0);

        intResult = stitchingPhotoSession->AddInput(input);
        EXPECT_EQ(intResult, 0);

        sptr<CaptureOutput> previewOutputCaptureUpper = previewOutput;
        intResult = stitchingPhotoSession->AddOutput(previewOutputCaptureUpper);
        EXPECT_EQ(intResult, 0);

        intResult = stitchingPhotoSession->CommitConfig();
        EXPECT_EQ(intResult, 0);

        stitchingPhotoSession->Release();
        camInput->Close();
    }
}

/*
 * Feature: Framework
 * Function: Test StitchingPhotoSession set and get stitchingType
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test StitchingPhotoSession set and get stitchingType
 */
HWTEST_F(CameraStitchingPhotoSessionUnit, camera_stitching_photo_session_unittest_002, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        if (find(modes.begin(), modes.end(), SceneMode::STITCHING_PHOTO) == modes.end()) {
            continue;
        }
        sptr<CaptureInput> input = cameraManager_->CreateCameraInput(camDevice);
        ASSERT_NE(input, nullptr);

        sptr<CameraInput> camInput = (sptr<CameraInput>&)input;
        std::string cameraSettings = camInput->GetCameraSettings();
        camInput->SetCameraSettings(cameraSettings);
        if (camInput->GetCameraDevice()) {
            camInput->GetCameraDevice()->SetMdmCheck(false);
            camInput->GetCameraDevice()->Open();
        }

        sptr<CaptureSession> session = cameraManager_->CreateCaptureSession(SceneMode::STITCHING_PHOTO);
        sptr<StitchingPhotoSession> stitchingPhotoSession = static_cast<StitchingPhotoSession*>(session.GetRefPtr());
        ASSERT_NE(stitchingPhotoSession, nullptr);

        sptr<Surface> previewSurface = Surface::CreateSurfaceAsConsumer();
        Profile previewProfile = Profile(PREVIEW_FORMAT, PREVIEW_SIZE);
        sptr<CaptureOutput> previewOutput = cameraManager_->CreatePreviewOutput(previewProfile, previewSurface);
        ASSERT_NE(previewOutput, nullptr);

        int32_t intResult = stitchingPhotoSession->BeginConfig();
        EXPECT_EQ(intResult, 0);

        intResult = stitchingPhotoSession->AddInput(input);
        EXPECT_EQ(intResult, 0);

        sptr<CaptureOutput> previewOutputCaptureUpper = previewOutput;
        intResult = stitchingPhotoSession->AddOutput(previewOutputCaptureUpper);
        EXPECT_EQ(intResult, 0);

        intResult = stitchingPhotoSession->CommitConfig();
        EXPECT_EQ(intResult, 0);

        stitchingPhotoSession->LockForControl();
        intResult = stitchingPhotoSession->SetStitchingType(StitchingType::LONG_SCROLL);
        stitchingPhotoSession->UnlockForControl();
        EXPECT_EQ(intResult, 0);
        StitchingType type;
        intResult = stitchingPhotoSession->GetStitchingType(type);
        EXPECT_EQ(intResult, 0);
        EXPECT_EQ(StitchingType::LONG_SCROLL, type);

        stitchingPhotoSession->LockForControl();
        intResult = stitchingPhotoSession->SetStitchingType(StitchingType::PAINTING_SCROLL);
        stitchingPhotoSession->UnlockForControl();
        EXPECT_EQ(intResult, 0);
        intResult = stitchingPhotoSession->GetStitchingType(type);
        EXPECT_EQ(intResult, 0);
        EXPECT_EQ(StitchingType::PAINTING_SCROLL, type);

        stitchingPhotoSession->LockForControl();
        intResult = stitchingPhotoSession->SetStitchingType(
            static_cast<StitchingType>(static_cast<int>(StitchingType::NINE_GRID) + 1));
        stitchingPhotoSession->UnlockForControl();
        EXPECT_EQ(intResult, CameraErrorCode::PARAMETER_ERROR);

        stitchingPhotoSession->Release();
        camInput->Close();
    }
}

/*
 * Feature: Framework
 * Function: Test StitchingPhotoSession set and get stitchingDirection
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test StitchingPhotoSession set and get stitchingDirection
 */
HWTEST_F(CameraStitchingPhotoSessionUnit, camera_stitching_photo_session_unittest_003, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        if (find(modes.begin(), modes.end(), SceneMode::STITCHING_PHOTO) == modes.end()) {
            continue;
        }
        sptr<CaptureInput> input = cameraManager_->CreateCameraInput(camDevice);
        ASSERT_NE(input, nullptr);

        sptr<CameraInput> camInput = (sptr<CameraInput>&)input;
        std::string cameraSettings = camInput->GetCameraSettings();
        camInput->SetCameraSettings(cameraSettings);
        if (camInput->GetCameraDevice()) {
            camInput->GetCameraDevice()->SetMdmCheck(false);
            camInput->GetCameraDevice()->Open();
        }

        sptr<CaptureSession> session = cameraManager_->CreateCaptureSession(SceneMode::STITCHING_PHOTO);
        sptr<StitchingPhotoSession> stitchingPhotoSession = static_cast<StitchingPhotoSession*>(session.GetRefPtr());
        ASSERT_NE(stitchingPhotoSession, nullptr);

        sptr<Surface> previewSurface = Surface::CreateSurfaceAsConsumer();
        Profile previewProfile = Profile(PREVIEW_FORMAT, PREVIEW_SIZE);
        sptr<CaptureOutput> previewOutput = cameraManager_->CreatePreviewOutput(previewProfile, previewSurface);
        ASSERT_NE(previewOutput, nullptr);

        int32_t intResult = stitchingPhotoSession->BeginConfig();
        EXPECT_EQ(intResult, 0);

        intResult = stitchingPhotoSession->AddInput(input);
        EXPECT_EQ(intResult, 0);

        sptr<CaptureOutput> previewOutputCaptureUpper = previewOutput;
        intResult = stitchingPhotoSession->AddOutput(previewOutputCaptureUpper);
        EXPECT_EQ(intResult, 0);

        intResult = stitchingPhotoSession->CommitConfig();
        EXPECT_EQ(intResult, 0);

        stitchingPhotoSession->LockForControl();
        intResult = stitchingPhotoSession->SetStitchingDirection(StitchingDirection::LANDSCAPE);
        stitchingPhotoSession->UnlockForControl();
        EXPECT_EQ(intResult, 0);
        StitchingDirection direction;
        intResult = stitchingPhotoSession->GetStitchingDirection(direction);
        EXPECT_EQ(intResult, 0);
        EXPECT_EQ(StitchingDirection::LANDSCAPE, direction);

        stitchingPhotoSession->LockForControl();
        intResult = stitchingPhotoSession->SetStitchingDirection(StitchingDirection::PORTRAIT);
        stitchingPhotoSession->UnlockForControl();
        EXPECT_EQ(intResult, 0);
        intResult = stitchingPhotoSession->GetStitchingDirection(direction);
        EXPECT_EQ(intResult, 0);
        EXPECT_EQ(StitchingDirection::PORTRAIT, direction);

        stitchingPhotoSession->LockForControl();
        intResult = stitchingPhotoSession->SetStitchingDirection(
            static_cast<StitchingDirection>(static_cast<int>(StitchingDirection::PORTRAIT) + 1));
        stitchingPhotoSession->UnlockForControl();
        EXPECT_EQ(intResult, CameraErrorCode::PARAMETER_ERROR);

        stitchingPhotoSession->Release();
        camInput->Close();
    }
}

/*
 * Feature: Framework
 * Function: Test StitchingPhotoSession set and get MovingClockwise
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test StitchingPhotoSession set and get MovingClockwise
 */
HWTEST_F(CameraStitchingPhotoSessionUnit, camera_stitching_photo_session_unittest_004, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        if (find(modes.begin(), modes.end(), SceneMode::STITCHING_PHOTO) == modes.end()) {
            continue;
        }
        sptr<CaptureInput> input = cameraManager_->CreateCameraInput(camDevice);
        ASSERT_NE(input, nullptr);

        sptr<CameraInput> camInput = (sptr<CameraInput>&)input;
        std::string cameraSettings = camInput->GetCameraSettings();
        camInput->SetCameraSettings(cameraSettings);
        if (camInput->GetCameraDevice()) {
            camInput->GetCameraDevice()->SetMdmCheck(false);
            camInput->GetCameraDevice()->Open();
        }

        sptr<CaptureSession> session = cameraManager_->CreateCaptureSession(SceneMode::STITCHING_PHOTO);
        sptr<StitchingPhotoSession> stitchingPhotoSession = static_cast<StitchingPhotoSession*>(session.GetRefPtr());
        ASSERT_NE(stitchingPhotoSession, nullptr);

        sptr<Surface> previewSurface = Surface::CreateSurfaceAsConsumer();
        Profile previewProfile = Profile(PREVIEW_FORMAT, PREVIEW_SIZE);
        sptr<CaptureOutput> previewOutput = cameraManager_->CreatePreviewOutput(previewProfile, previewSurface);
        ASSERT_NE(previewOutput, nullptr);

        int32_t intResult = stitchingPhotoSession->BeginConfig();
        EXPECT_EQ(intResult, 0);

        intResult = stitchingPhotoSession->AddInput(input);
        EXPECT_EQ(intResult, 0);

        sptr<CaptureOutput> previewOutputCaptureUpper = previewOutput;
        intResult = stitchingPhotoSession->AddOutput(previewOutputCaptureUpper);
        EXPECT_EQ(intResult, 0);

        intResult = stitchingPhotoSession->CommitConfig();
        EXPECT_EQ(intResult, 0);

        stitchingPhotoSession->LockForControl();
        intResult = stitchingPhotoSession->SetMovingClockwise(true);
        stitchingPhotoSession->UnlockForControl();
        EXPECT_EQ(intResult, 0);
        bool enable = false;
        intResult = stitchingPhotoSession->GetMovingClockwise(enable);
        EXPECT_EQ(intResult, 0);
        EXPECT_EQ(true, enable);

        stitchingPhotoSession->LockForControl();
        intResult = stitchingPhotoSession->SetMovingClockwise(false);
        stitchingPhotoSession->UnlockForControl();
        EXPECT_EQ(intResult, 0);
        intResult = stitchingPhotoSession->GetMovingClockwise(enable);
        EXPECT_EQ(intResult, 0);
        EXPECT_TRUE(enable == false);

        stitchingPhotoSession->Release();
        camInput->Close();
    }
}

} // namespace CameraStandard
} // namespace OHOS