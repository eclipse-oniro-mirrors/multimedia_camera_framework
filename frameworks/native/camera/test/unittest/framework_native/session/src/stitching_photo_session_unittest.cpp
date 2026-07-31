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
        EXPECT_EQ(GetCameraErrorCode(intResult), 0);

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

class MockStitchingTargetInfoCallback : public StitchingTargetInfoCallback {
public:
    void OnInfoChanged(StitchingTargetInfo info) override
    {
        callCount_++;
        lastInfo_ = info;
    }
    mutable int32_t callCount_ = 0;
    mutable StitchingTargetInfo lastInfo_;
};

class MockStitchingHintInfoCallback : public StitchingHintInfoCallback {
public:
    void OnInfoChanged(StitchingHintInfo info) override
    {
        callCount_++;
        lastInfo_ = info;
    }
    mutable int32_t callCount_ = 0;
    mutable StitchingHintInfo lastInfo_;
};

class MockStitchingCaptureStateCallback : public StitchingCaptureStateCallback {
public:
    void OnInfoChanged(StitchingCaptureStateInfo info) override
    {
        callCount_++;
        lastInfo_ = info;
    }
    mutable int32_t callCount_ = 0;
    mutable StitchingCaptureStateInfo lastInfo_;
};

/*
 * Feature: Framework
 * Function: Test SetStitchingTargetInfoCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetStitchingTargetInfoCallback sets the callback successfully
 */
HWTEST_F(CameraStitchingPhotoSessionUnit, camera_stitching_photo_session_ext_unittest_001, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        if (find(modes.begin(), modes.end(), SceneMode::STITCHING_PHOTO) == modes.end()) {
            continue;
        }
        sptr<CaptureSession> session = cameraManager_->CreateCaptureSession(SceneMode::STITCHING_PHOTO);
        sptr<StitchingPhotoSession> stitchingPhotoSession = static_cast<StitchingPhotoSession*>(session.GetRefPtr());
        ASSERT_NE(stitchingPhotoSession, nullptr);

        auto callback = std::make_shared<MockStitchingTargetInfoCallback>();
        ASSERT_NE(callback, nullptr);
        int32_t ret = stitchingPhotoSession->SetStitchingTargetInfoCallback(callback);
        EXPECT_EQ(CameraErrorCode::SUCCESS, ret);

        stitchingPhotoSession->Release();
    }
}

/*
 * Feature: Framework
 * Function: Test SetStitchingHintInfoCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetStitchingHintInfoCallback sets the callback successfully
 */
HWTEST_F(CameraStitchingPhotoSessionUnit, camera_stitching_photo_session_ext_unittest_002, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        if (find(modes.begin(), modes.end(), SceneMode::STITCHING_PHOTO) == modes.end()) {
            continue;
        }
        sptr<CaptureSession> session = cameraManager_->CreateCaptureSession(SceneMode::STITCHING_PHOTO);
        sptr<StitchingPhotoSession> stitchingPhotoSession = static_cast<StitchingPhotoSession*>(session.GetRefPtr());
        ASSERT_NE(stitchingPhotoSession, nullptr);

        auto callback = std::make_shared<MockStitchingHintInfoCallback>();
        ASSERT_NE(callback, nullptr);
        int32_t ret = stitchingPhotoSession->SetStitchingHintInfoCallback(callback);
        EXPECT_EQ(CameraErrorCode::SUCCESS, ret);

        stitchingPhotoSession->Release();
    }
}

/*
 * Feature: Framework
 * Function: Test SetStitchingCaptureStateCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetStitchingCaptureStateCallback sets the callback successfully
 */
HWTEST_F(CameraStitchingPhotoSessionUnit, camera_stitching_photo_session_ext_unittest_003, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        if (find(modes.begin(), modes.end(), SceneMode::STITCHING_PHOTO) == modes.end()) {
            continue;
        }
        sptr<CaptureSession> session = cameraManager_->CreateCaptureSession(SceneMode::STITCHING_PHOTO);
        sptr<StitchingPhotoSession> stitchingPhotoSession = static_cast<StitchingPhotoSession*>(session.GetRefPtr());
        ASSERT_NE(stitchingPhotoSession, nullptr);

        auto callback = std::make_shared<MockStitchingCaptureStateCallback>();
        ASSERT_NE(callback, nullptr);
        int32_t ret = stitchingPhotoSession->SetStitchingCaptureStateCallback(callback);
        EXPECT_EQ(CameraErrorCode::SUCCESS, ret);

        stitchingPhotoSession->Release();
    }
}

/*
 * Feature: Framework
 * Function: Test ProcessStitchingHintChange with valid metadata and no callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessStitchingHintChange when metadata has hint data but callback is null
 */
HWTEST_F(CameraStitchingPhotoSessionUnit, camera_stitching_photo_session_ext_unittest_004, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        if (find(modes.begin(), modes.end(), SceneMode::STITCHING_PHOTO) == modes.end()) {
            continue;
        }
        sptr<CaptureSession> session = cameraManager_->CreateCaptureSession(SceneMode::STITCHING_PHOTO);
        sptr<StitchingPhotoSession> stitchingPhotoSession = static_cast<StitchingPhotoSession*>(session.GetRefPtr());
        ASSERT_NE(stitchingPhotoSession, nullptr);

        int32_t defaultItems = 10;
        int32_t defaultDataLength = 200;
        auto metadata = std::make_shared<OHOS::Camera::CameraMetadata>(defaultItems, defaultDataLength);
        ASSERT_NE(metadata, nullptr);

        // Test with no callback set: isReported true, isNeedChange false (callback null)
        uint8_t hintValue = static_cast<uint8_t>(StitchingHintInfo::StitchingHint::KEEP_H);
        metadata->addEntry(OHOS_STATUS_PHOTO_STITCHING_HINT, &hintValue, 1);
        stitchingPhotoSession->ProcessStitchingHintChange(metadata);

        stitchingPhotoSession->Release();
    }
}

/*
 * Feature: Framework
 * Function: Test ProcessStitchingHintChange with valid metadata and callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessStitchingHintChange when metadata has hint data and callback is set
 */
HWTEST_F(CameraStitchingPhotoSessionUnit, camera_stitching_photo_session_ext_unittest_005, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        if (find(modes.begin(), modes.end(), SceneMode::STITCHING_PHOTO) == modes.end()) {
            continue;
        }
        sptr<CaptureSession> session = cameraManager_->CreateCaptureSession(SceneMode::STITCHING_PHOTO);
        sptr<StitchingPhotoSession> stitchingPhotoSession = static_cast<StitchingPhotoSession*>(session.GetRefPtr());
        ASSERT_NE(stitchingPhotoSession, nullptr);

        auto callback = std::make_shared<MockStitchingHintInfoCallback>();
        ASSERT_NE(callback, nullptr);
        int32_t ret = stitchingPhotoSession->SetStitchingHintInfoCallback(callback);
        EXPECT_EQ(CameraErrorCode::SUCCESS, ret);
        EXPECT_EQ(callback->callCount_, 0);

        int32_t defaultItems = 10;
        int32_t defaultDataLength = 200;
        auto metadata = std::make_shared<OHOS::Camera::CameraMetadata>(defaultItems, defaultDataLength);
        ASSERT_NE(metadata, nullptr);

        // Set hint data and process: callback should be called (record is null initially)
        uint8_t hintValue = static_cast<uint8_t>(StitchingHintInfo::StitchingHint::DARK_LIGHT);
        metadata->addEntry(OHOS_STATUS_PHOTO_STITCHING_HINT, &hintValue, 1);
        stitchingPhotoSession->ProcessStitchingHintChange(metadata);
        EXPECT_EQ(callback->callCount_, 1);
        EXPECT_EQ(callback->lastInfo_.hint_, StitchingHintInfo::StitchingHint::DARK_LIGHT);

        // Process again with same data: should not trigger callback again (record matches)
        stitchingPhotoSession->ProcessStitchingHintChange(metadata);
        EXPECT_EQ(callback->callCount_, 1);

        stitchingPhotoSession->Release();
    }
}

/*
 * Feature: Framework
 * Function: Test ProcessStitchingHintChange with empty metadata
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessStitchingHintChange when metadata does not have hint tag
 */
HWTEST_F(CameraStitchingPhotoSessionUnit, camera_stitching_photo_session_ext_unittest_006, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        if (find(modes.begin(), modes.end(), SceneMode::STITCHING_PHOTO) == modes.end()) {
            continue;
        }
        sptr<CaptureSession> session = cameraManager_->CreateCaptureSession(SceneMode::STITCHING_PHOTO);
        sptr<StitchingPhotoSession> stitchingPhotoSession = static_cast<StitchingPhotoSession*>(session.GetRefPtr());
        ASSERT_NE(stitchingPhotoSession, nullptr);

        auto callback = std::make_shared<MockStitchingHintInfoCallback>();
        ASSERT_NE(callback, nullptr);
        stitchingPhotoSession->SetStitchingHintInfoCallback(callback);

        int32_t defaultItems = 10;
        int32_t defaultDataLength = 200;
        auto metadata = std::make_shared<OHOS::Camera::CameraMetadata>(defaultItems, defaultDataLength);
        ASSERT_NE(metadata, nullptr);

        // Metadata without OHOS_STATUS_PHOTO_STITCHING_HINT
        stitchingPhotoSession->ProcessStitchingHintChange(metadata);
        EXPECT_EQ(callback->callCount_, 0);

        stitchingPhotoSession->Release();
    }
}

/*
 * Feature: Framework
 * Function: Test ProcessStitchingHintChange with zero count
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessStitchingHintChange when metadata item has zero count
 */
HWTEST_F(CameraStitchingPhotoSessionUnit, camera_stitching_photo_session_ext_unittest_007, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        if (find(modes.begin(), modes.end(), SceneMode::STITCHING_PHOTO) == modes.end()) {
            continue;
        }
        sptr<CaptureSession> session = cameraManager_->CreateCaptureSession(SceneMode::STITCHING_PHOTO);
        sptr<StitchingPhotoSession> stitchingPhotoSession = static_cast<StitchingPhotoSession*>(session.GetRefPtr());
        ASSERT_NE(stitchingPhotoSession, nullptr);

        auto callback = std::make_shared<MockStitchingHintInfoCallback>();
        ASSERT_NE(callback, nullptr);
        stitchingPhotoSession->SetStitchingHintInfoCallback(callback);

        int32_t defaultItems = 10;
        int32_t defaultDataLength = 200;
        auto metadata = std::make_shared<OHOS::Camera::CameraMetadata>(defaultItems, defaultDataLength);
        ASSERT_NE(metadata, nullptr);

        // Add hint tag with count 0 (empty item)
        uint8_t emptyData = 0;
        metadata->addEntry(OHOS_STATUS_PHOTO_STITCHING_HINT, &emptyData, 0);
        stitchingPhotoSession->ProcessStitchingHintChange(metadata);
        EXPECT_EQ(callback->callCount_, 0);

        stitchingPhotoSession->Release();
    }
}

/*
 * Feature: Framework
 * Function: Test ProcessStitchingTargetChange with no metadata items
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessStitchingTargetChange when both position and angle are missing
 */
HWTEST_F(CameraStitchingPhotoSessionUnit, camera_stitching_photo_session_ext_unittest_008, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        if (find(modes.begin(), modes.end(), SceneMode::STITCHING_PHOTO) == modes.end()) {
            continue;
        }
        sptr<CaptureSession> session = cameraManager_->CreateCaptureSession(SceneMode::STITCHING_PHOTO);
        sptr<StitchingPhotoSession> stitchingPhotoSession = static_cast<StitchingPhotoSession*>(session.GetRefPtr());
        ASSERT_NE(stitchingPhotoSession, nullptr);

        auto callback = std::make_shared<MockStitchingTargetInfoCallback>();
        ASSERT_NE(callback, nullptr);
        stitchingPhotoSession->SetStitchingTargetInfoCallback(callback);
        EXPECT_EQ(callback->callCount_, 0);

        int32_t defaultItems = 10;
        int32_t defaultDataLength = 200;
        auto metadata = std::make_shared<OHOS::Camera::CameraMetadata>(defaultItems, defaultDataLength);
        ASSERT_NE(metadata, nullptr);

        // Both position and angle missing → should return early
        stitchingPhotoSession->ProcessStitchingTargetChange(metadata);
        EXPECT_EQ(callback->callCount_, 0);

        stitchingPhotoSession->Release();
    }
}

/*
 * Feature: Framework
 * Function: Test ProcessStitchingTargetChange with valid position and angle
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessStitchingTargetChange when position and angle are valid
 */
HWTEST_F(CameraStitchingPhotoSessionUnit, camera_stitching_photo_session_ext_unittest_009, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        if (find(modes.begin(), modes.end(), SceneMode::STITCHING_PHOTO) == modes.end()) {
            continue;
        }
        sptr<CaptureSession> session = cameraManager_->CreateCaptureSession(SceneMode::STITCHING_PHOTO);
        sptr<StitchingPhotoSession> stitchingPhotoSession = static_cast<StitchingPhotoSession*>(session.GetRefPtr());
        ASSERT_NE(stitchingPhotoSession, nullptr);

        auto callback = std::make_shared<MockStitchingTargetInfoCallback>();
        ASSERT_NE(callback, nullptr);
        stitchingPhotoSession->SetStitchingTargetInfoCallback(callback);

        int32_t defaultItems = 10;
        int32_t defaultDataLength = 200;
        auto metadata = std::make_shared<OHOS::Camera::CameraMetadata>(defaultItems, defaultDataLength);
        ASSERT_NE(metadata, nullptr);

        // Add valid position data (even count) and angle
        float positionData[4] = {0.1f, 0.2f, 0.3f, 0.4f};
        metadata->addEntry(OHOS_STATUS_PHOTO_STITCHING_POSITION, positionData, 4);
        float angleData = 45.0f;
        metadata->addEntry(OHOS_STATUS_PHOTO_STITCHING_ANGLE, &angleData, 1);

        stitchingPhotoSession->ProcessStitchingTargetChange(metadata);
        EXPECT_EQ(callback->callCount_, 1);
        EXPECT_FLOAT_EQ(callback->lastInfo_.angle_, 45.0f);
        EXPECT_EQ(callback->lastInfo_.positions_.size(), static_cast<size_t>(4));

        stitchingPhotoSession->Release();
    }
}

/*
 * Feature: Framework
 * Function: Test ProcessStitchingTargetChange with odd position count
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessStitchingTargetChange when position array has odd length
 */
HWTEST_F(CameraStitchingPhotoSessionUnit, camera_stitching_photo_session_unittest_018, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        if (find(modes.begin(), modes.end(), SceneMode::STITCHING_PHOTO) == modes.end()) {
            continue;
        }
        sptr<CaptureSession> session = cameraManager_->CreateCaptureSession(SceneMode::STITCHING_PHOTO);
        sptr<StitchingPhotoSession> stitchingPhotoSession = static_cast<StitchingPhotoSession*>(session.GetRefPtr());
        ASSERT_NE(stitchingPhotoSession, nullptr);

        auto callback = std::make_shared<MockStitchingTargetInfoCallback>();
        ASSERT_NE(callback, nullptr);
        stitchingPhotoSession->SetStitchingTargetInfoCallback(callback);

        int32_t defaultItems = 10;
        int32_t defaultDataLength = 200;
        auto metadata = std::make_shared<OHOS::Camera::CameraMetadata>(defaultItems, defaultDataLength);
        ASSERT_NE(metadata, nullptr);

        // Add invalid position data (odd count)
        float positionData[3] = {0.1f, 0.2f, 0.3f};
        metadata->addEntry(OHOS_STATUS_PHOTO_STITCHING_POSITION, positionData, 3);

        EXPECT_EQ(callback->callCount_, 0);
        stitchingPhotoSession->ProcessStitchingTargetChange(metadata);
        EXPECT_EQ(callback->callCount_, 0);

        stitchingPhotoSession->Release();
    }
}

/*
 * Feature: Framework
 * Function: Test ProcessStitchingCaptureStateChange with no metadata
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessStitchingCaptureStateChange when metadata does not have capture state
 */
HWTEST_F(CameraStitchingPhotoSessionUnit, camera_stitching_photo_session_ext_unittest_010, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        if (find(modes.begin(), modes.end(), SceneMode::STITCHING_PHOTO) == modes.end()) {
            continue;
        }
        sptr<CaptureSession> session = cameraManager_->CreateCaptureSession(SceneMode::STITCHING_PHOTO);
        sptr<StitchingPhotoSession> stitchingPhotoSession = static_cast<StitchingPhotoSession*>(session.GetRefPtr());
        ASSERT_NE(stitchingPhotoSession, nullptr);

        auto callback = std::make_shared<MockStitchingCaptureStateCallback>();
        ASSERT_NE(callback, nullptr);
        stitchingPhotoSession->SetStitchingCaptureStateCallback(callback);

        int32_t defaultItems = 10;
        int32_t defaultDataLength = 200;
        auto metadata = std::make_shared<OHOS::Camera::CameraMetadata>(defaultItems, defaultDataLength);
        ASSERT_NE(metadata, nullptr);

        // No capture state metadata
        stitchingPhotoSession->ProcessStitchingCaptureStateChange(metadata);
        EXPECT_EQ(callback->callCount_, 0);

        stitchingPhotoSession->Release();
    }
}

} // namespace CameraStandard
} // namespace OHOS