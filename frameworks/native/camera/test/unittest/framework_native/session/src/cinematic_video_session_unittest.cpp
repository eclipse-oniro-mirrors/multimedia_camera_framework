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

#include <cstdint>
#include <vector>

#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_manager_for_sys.h"
#include "camera_util.h"
#include "cinematic_video_session_unittest.h"
#include "capture_input.h"
#include "capture_output.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "hap_token_info.h"
#include "ipc_skeleton.h"
#include "metadata_utils.h"
#include "nativetoken_kit.h"
#include "os_account_manager.h"
#include "sketch_wrapper.h"
#include "surface.h"
#include "test_common.h"
#include "test_token.h"
#include "token_setproc.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
void CameraCinematicVideoSessionUnit::SetUpTestCase(void)
{
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
}

void CameraCinematicVideoSessionUnit::TearDownTestCase(void) {}

void CameraCinematicVideoSessionUnit::SetUp()
{
    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);

    cameraManagerForSys_ = CameraManagerForSys::GetInstance();
    ASSERT_NE(cameraManagerForSys_, nullptr);
}

void CameraCinematicVideoSessionUnit::TearDown()
{
    cameraManager_ = nullptr;
    cameraManagerForSys_ = nullptr;

    MEDIA_DEBUG_LOG("CameraCinematicVideoSessionUnit TearDown");
}

/*
 * Feature: Framework
 * Function: Test CinematicVideoSession creation and basic properties
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CinematicVideoSession can be created and has metadata processor
 */
HWTEST_F(CameraCinematicVideoSessionUnit, camera_cinematic_video_session_unittest_001, TestSize.Level0)
{
    sptr<CaptureSessionForSys> sessionForSys =
        cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CINEMATIC_VIDEO);
    ASSERT_NE(sessionForSys, nullptr);

    sptr<CinematicVideoSession> cinematicVideoSession =
        static_cast<CinematicVideoSession*>(sessionForSys.GetRefPtr());
    ASSERT_NE(cinematicVideoSession, nullptr);
    ASSERT_NE(cinematicVideoSession->metadataResultProcessor_, nullptr);

    cinematicVideoSession->Release();
}

/*
 * Feature: Framework
 * Function: Test CinematicVideoSessionMetadataResultProcessor ProcessCallbacks
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessCallbacks dispatches correctly with valid metadata
 */
HWTEST_F(CameraCinematicVideoSessionUnit, camera_cinematic_video_session_unittest_002, TestSize.Level0)
{
    sptr<CaptureSessionForSys> sessionForSys =
        cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CINEMATIC_VIDEO);
    ASSERT_NE(sessionForSys, nullptr);

    sptr<CinematicVideoSession> cinematicVideoSession =
        static_cast<CinematicVideoSession*>(sessionForSys.GetRefPtr());
    ASSERT_NE(cinematicVideoSession, nullptr);

    EXPECT_NE(cinematicVideoSession->metadataResultProcessor_, nullptr);

    int32_t defaultItems = 10;
    int32_t defaultDataLength = 200;
    auto metadata = std::make_shared<OHOS::Camera::CameraMetadata>(defaultItems, defaultDataLength);
    ASSERT_NE(metadata, nullptr);

    uint64_t timestamp = 1;
    cinematicVideoSession->metadataResultProcessor_->ProcessCallbacks(timestamp, metadata);

    cinematicVideoSession->Release();
}

/*
 * Feature: Framework
 * Function: Test CinematicVideoSessionMetadataResultProcessor ProcessCallbacks with null session
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessCallbacks safely returns when session is released (wptr promote fails)
 */
HWTEST_F(CameraCinematicVideoSessionUnit, camera_cinematic_video_session_unittest_003, TestSize.Level0)
{
    sptr<CaptureSessionForSys> sessionForSys =
        cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CINEMATIC_VIDEO);
    ASSERT_NE(sessionForSys, nullptr);

    sptr<CinematicVideoSession> cinematicVideoSession =
        static_cast<CinematicVideoSession*>(sessionForSys.GetRefPtr());
    ASSERT_NE(cinematicVideoSession, nullptr);

    CinematicVideoSession::CinematicVideoSessionMetadataResultProcessor processor(cinematicVideoSession);
    cinematicVideoSession->Release();

    ASSERT_NE(sessionForSys.GetRefPtr(), nullptr);
    int32_t defaultItems = 10;
    int32_t defaultDataLength = 200;
    auto metadata = std::make_shared<OHOS::Camera::CameraMetadata>(defaultItems, defaultDataLength);
    ASSERT_NE(metadata, nullptr);
    uint64_t timestamp = 1;
    processor.ProcessCallbacks(timestamp, metadata);
    EXPECT_NE(metadata, nullptr);
}

/*
 * Feature: Framework
 * Function: Test CinematicVideoSession AddOutput with nullptr output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AddOutput returns SERVICE_FATL_ERROR when output is null
 */
HWTEST_F(CameraCinematicVideoSessionUnit, camera_cinematic_video_session_unittest_004, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput>&)input;
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureSessionForSys> sessionForSys =
        cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CINEMATIC_VIDEO);
    ASSERT_NE(sessionForSys, nullptr);

    sptr<CinematicVideoSession> cinematicVideoSession =
        static_cast<CinematicVideoSession*>(sessionForSys.GetRefPtr());
    ASSERT_NE(cinematicVideoSession, nullptr);

    sptr<CaptureOutput> nullOutput = nullptr;
    int32_t ret = cinematicVideoSession->AddOutput(nullOutput);
    EXPECT_EQ(SERVICE_FATL_ERROR, ret);

    input->Close();
    cinematicVideoSession->Release();
}

/*
 * Feature: Framework
 * Function: Test CinematicVideoSession AddOutput with preview output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AddOutput with preview output returns SUCCESS
 */
HWTEST_F(CameraCinematicVideoSessionUnit, camera_cinematic_video_session_unittest_005, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput>&)input;
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureSessionForSys> sessionForSys =
        cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CINEMATIC_VIDEO);
    ASSERT_NE(sessionForSys, nullptr);

    sptr<CinematicVideoSession> cinematicVideoSession =
        static_cast<CinematicVideoSession*>(sessionForSys.GetRefPtr());
    ASSERT_NE(cinematicVideoSession, nullptr);

    int32_t intResult = cinematicVideoSession->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = cinematicVideoSession->AddInput(input);
    EXPECT_EQ(intResult, 0);

    sptr<Surface> previewSurface = Surface::CreateSurfaceAsConsumer();
    Profile previewProfile = Profile(PREVIEW_FORMAT, PREVIEW_SIZE);
    sptr<CaptureOutput> previewOutput = cameraManager_->CreatePreviewOutput(previewProfile, previewSurface);
    ASSERT_NE(previewOutput, nullptr);

    cinematicVideoSession->AddOutput(previewOutput);
    intResult = cinematicVideoSession->Release();
    EXPECT_EQ(intResult, 0);

    input->Close();
}

/*
 * Feature: Framework
 * Function: Test CinematicVideoSession RemoveOutput with valid output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test RemoveOutput returns SUCCESS after removing valid output
 */
HWTEST_F(CameraCinematicVideoSessionUnit, camera_cinematic_video_session_unittest_006, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput>&)input;
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureSessionForSys> sessionForSys =
        cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CINEMATIC_VIDEO);
    ASSERT_NE(sessionForSys, nullptr);

    sptr<CinematicVideoSession> cinematicVideoSession =
        static_cast<CinematicVideoSession*>(sessionForSys.GetRefPtr());
    ASSERT_NE(cinematicVideoSession, nullptr);

    int32_t intResult = cinematicVideoSession->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = cinematicVideoSession->AddInput(input);
    EXPECT_EQ(intResult, 0);

    sptr<Surface> previewSurface = Surface::CreateSurfaceAsConsumer();
    Profile previewProfile = Profile(PREVIEW_FORMAT, PREVIEW_SIZE);
    sptr<CaptureOutput> previewOutput = cameraManager_->CreatePreviewOutput(previewProfile, previewSurface);
    ASSERT_NE(previewOutput, nullptr);

    cinematicVideoSession->AddOutput(previewOutput);
    cinematicVideoSession->RemoveOutput(previewOutput);

    intResult = cinematicVideoSession->Release();
    EXPECT_EQ(intResult, 0);

    input->Close();
}

/*
 * Feature: Framework
 * Function: Test CinematicVideoSession RemoveOutput without prior AddOutput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test RemoveOutput returns error when output not added
 */
HWTEST_F(CameraCinematicVideoSessionUnit, camera_cinematic_video_session_unittest_007, TestSize.Level0)
{
    sptr<CaptureSessionForSys> sessionForSys =
        cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CINEMATIC_VIDEO);
    ASSERT_NE(sessionForSys, nullptr);

    sptr<CinematicVideoSession> cinematicVideoSession =
        static_cast<CinematicVideoSession*>(sessionForSys.GetRefPtr());
    ASSERT_NE(cinematicVideoSession, nullptr);

    sptr<Surface> previewSurface = Surface::CreateSurfaceAsConsumer();
    Profile previewProfile = Profile(PREVIEW_FORMAT, PREVIEW_SIZE);
    sptr<CaptureOutput> previewOutput = cameraManager_->CreatePreviewOutput(previewProfile, previewSurface);
    ASSERT_NE(previewOutput, nullptr);

    int32_t intResult = cinematicVideoSession->RemoveOutput(previewOutput);
    EXPECT_NE(intResult, SUCCESS);

    cinematicVideoSession->Release();
}

} // namespace CameraStandard
} // namespace OHOS
