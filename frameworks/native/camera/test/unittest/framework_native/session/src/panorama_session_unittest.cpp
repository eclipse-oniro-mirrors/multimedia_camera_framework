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
#include "camera_manager_for_sys.h"
#include "camera_util.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "hap_token_info.h"
#include "ipc_skeleton.h"
#include "metadata_utils.h"
#include "nativetoken_kit.h"
#include "os_account_manager.h"
#include "panorama_session_unittest.h"
#include "sketch_wrapper.h"
#include "surface.h"
#include "test_common.h"
#include "test_token.h"
#include "token_setproc.h"

using namespace testing::ext;
using ::testing::A;
using ::testing::InSequence;
using ::testing::Mock;
using ::testing::Return;
using ::testing::_;

namespace OHOS {
namespace CameraStandard {
void CameraPanoramaSessionUnit::SetUpTestCase(void)
{
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
}

void CameraPanoramaSessionUnit::TearDownTestCase(void) {}

void CameraPanoramaSessionUnit::SetUp()
{
    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);
}

void CameraPanoramaSessionUnit::TearDown()
{
    cameraManager_ = nullptr;
    MEDIA_DEBUG_LOG("CameraPanoramaSessionUnit TearDown");
}

/*
 * Feature: Framework
 * Function: Test PanoramaSession preview
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test PanoramaSession preview
 */
HWTEST_F(CameraPanoramaSessionUnit, camera_panorama_unittest_001, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        if (find(modes.begin(), modes.end(), SceneMode::PANORAMA_PHOTO) != modes.end()) {
            sptr<CaptureInput> input = cameraManager_->CreateCameraInput(camDevice);
            ASSERT_NE(input, nullptr);

            sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
            std::string cameraSettings = camInput->GetCameraSettings();
            camInput->SetCameraSettings(cameraSettings);
            camInput->GetCameraDevice()->Open();

            sptr<CaptureSession> session =
                CameraManagerForSys::GetInstance()->CreateCaptureSessionForSys(SceneMode::PANORAMA_PHOTO);
            sptr<PanoramaSession> panoramaSession = static_cast<PanoramaSession *> (session.GetRefPtr());
            ASSERT_NE(panoramaSession, nullptr);

            sptr<Surface> previewSurface = Surface::CreateSurfaceAsConsumer();
            CameraFormat previewFormat = CAMERA_FORMAT_YUV_420_SP;
            Size previewSize;
            previewSize.width = 1920;
            previewSize.height = 1080;
            Profile previewProfile = Profile(previewFormat, previewSize);
            sptr<CaptureOutput> previewOutput = cameraManager_->CreatePreviewOutput(previewProfile, previewSurface);
            ASSERT_NE(previewOutput, nullptr);

            int32_t intResult = panoramaSession->BeginConfig();
            EXPECT_EQ(intResult, 0);

            intResult = panoramaSession->AddInput(input);
            EXPECT_EQ(intResult, 0);

            sptr<CaptureOutput> previewOutputCaptureUpper = previewOutput;
            intResult = panoramaSession->AddOutput(previewOutputCaptureUpper);
            EXPECT_EQ(intResult, 0);

            intResult = panoramaSession->CommitConfig();
            EXPECT_EQ(intResult, 0);

            panoramaSession->Release();
            camInput->Close();
        }
    }
}

/*
 * Feature: Framework
 * Function: Test PanoramaSession set white balance lock
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test PanoramaSession set white balance lock
 */
HWTEST_F(CameraPanoramaSessionUnit, camera_panorama_unittest_002, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        if (find(modes.begin(), modes.end(), SceneMode::PANORAMA_PHOTO) != modes.end()) {
            sptr<CaptureInput> input = cameraManager_->CreateCameraInput(camDevice);
            ASSERT_NE(input, nullptr);

            sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
            std::string cameraSettings = camInput->GetCameraSettings();
            camInput->SetCameraSettings(cameraSettings);
            camInput->GetCameraDevice()->Open();

            sptr<CaptureSession> session =
                CameraManagerForSys::GetInstance()->CreateCaptureSessionForSys(SceneMode::PANORAMA_PHOTO);
            sptr<PanoramaSession> panoramaSession = static_cast<PanoramaSession *> (session.GetRefPtr());
            ASSERT_NE(panoramaSession, nullptr);

            sptr<Surface> previewSurface = Surface::CreateSurfaceAsConsumer();
            CameraFormat previewFormat = CAMERA_FORMAT_YUV_420_SP;
            Size previewSize;
            previewSize.width = 1920;
            previewSize.height = 1080;
            Profile previewProfile = Profile(previewFormat, previewSize);
            sptr<CaptureOutput> previewOutput = cameraManager_->CreatePreviewOutput(previewProfile, previewSurface);
            ASSERT_NE(previewOutput, nullptr);

            int32_t intResult = panoramaSession->BeginConfig();
            EXPECT_EQ(intResult, 0);

            intResult = panoramaSession->AddInput(input);
            EXPECT_EQ(intResult, 0);

            EXPECT_EQ(panoramaSession->CanAddOutput(previewOutput), true);
            sptr<CaptureOutput> previewOutputCaptureUpper = previewOutput;
            intResult = panoramaSession->AddOutput(previewOutputCaptureUpper);
            EXPECT_EQ(intResult, 0);

            intResult = panoramaSession->CommitConfig();
            EXPECT_EQ(intResult, 0);
            panoramaSession->LockForControl();
            panoramaSession->SetWhiteBalanceMode(AWB_MODE_LOCKED);
            panoramaSession->UnlockForControl();
            WhiteBalanceMode mode;
            panoramaSession->GetWhiteBalanceMode(mode);
            EXPECT_EQ(AWB_MODE_LOCKED, mode);

            panoramaSession->Release();
            camInput->Close();
        }
    }
}
}
}