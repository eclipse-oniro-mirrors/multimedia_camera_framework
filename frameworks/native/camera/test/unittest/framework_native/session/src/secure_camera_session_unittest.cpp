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
#include "secure_camera_session_unittest.h"
#include "sketch_wrapper.h"
#include "surface.h"
#include "test_common.h"
#include "test_token.h"
#include "token_setproc.h"

using namespace testing::ext;
namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;

sptr<CaptureOutput> SecureCameraSessionUnitTest::CreatePreviewOutput()
{
    previewProfile_ = {};
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    if (!cameraManager_ || cameras.empty()) {
        return nullptr;
    }
    preIsSupportedSecuremode_ = false;
    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        if (find(modes.begin(), modes.end(), SceneMode::SECURE) != modes.end()) {
            preIsSupportedSecuremode_ = true;
        }

        if (!preIsSupportedSecuremode_) {
            continue;
        }

        auto outputCapability = cameraManager_->GetSupportedOutputCapability(camDevice, static_cast<int32_t>(SECURE));
        if (!outputCapability) {
            return nullptr;
        }

        previewProfile_ = outputCapability->GetPreviewProfiles();
        if (previewProfile_.empty()) {
            return nullptr;
        }

        sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
        if (surface == nullptr) {
            return nullptr;
        }
        return cameraManager_->CreatePreviewOutput(previewProfile_[0], surface);
    }
    return nullptr;
}

void SecureCameraSessionUnitTest::SetUpTestCase(void)
{
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
}

void SecureCameraSessionUnitTest::TearDownTestCase(void) {}

void SecureCameraSessionUnitTest::SetUp()
{
    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);
}

void SecureCameraSessionUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("SecureCameraSessionUnitTest::TearDown");
}

/*
* Feature: Framework
* Function: Test normal branch that is add secure output flag
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: Test normal branch that is add secure output flag
*/
HWTEST_F(SecureCameraSessionUnitTest, camera_securecamera_unittest_001, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);

        if (find(modes.begin(), modes.end(), SceneMode::SECURE) != modes.end()) {
            sptr<CameraOutputCapability> ability = cameraManager_->
                GetSupportedOutputCapability(camDevice, SceneMode::SECURE);
            ASSERT_NE(ability, nullptr);
            sptr<CaptureInput> input = cameraManager_->CreateCameraInput(camDevice);
            ASSERT_NE(input, nullptr);
            sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
            std::string cameraSettings = camInput->GetCameraSettings();
            camInput->SetCameraSettings(cameraSettings);
            uint64_t secureSeqId = 0;
            int intResult = camInput->Open(false, &secureSeqId);
            EXPECT_EQ(intResult, CAMERA_OK);
            sptr<CaptureOutput> preview = CreatePreviewOutput();
            if (!preIsSupportedSecuremode_) {
                input->Close();
                GTEST_SKIP();
            }
            ASSERT_NE(preview, nullptr);
            sptr<CaptureSession> secureSessionForSys =
                CameraManagerForSys::GetInstance()->CreateCaptureSessionForSys(SceneMode::SECURE);
            ASSERT_NE(secureSessionForSys, nullptr);
            EXPECT_EQ(secureSessionForSys->BeginConfig(), 0);
            EXPECT_EQ(secureSessionForSys->AddInput(input), 0);
            sptr<CameraDevice> info = secureSessionForSys->innerInputDevice_->GetCameraDeviceInfo();
            ASSERT_NE(info, nullptr);
            info->modePreviewProfiles_.emplace(static_cast<int32_t>(SceneMode::SECURE), previewProfile_);
            EXPECT_EQ(secureSessionForSys->AddOutput(preview), 0);
            EXPECT_EQ(secureSessionForSys->AddSecureOutput(preview), 0);
            secureSessionForSys->Release();
            input->Close();
            break;
        }
    }
}

/*
* Feature: Framework
* Function: Test abnormal branch that is add secure output flag twice
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: Test abnormal branch that is add secure output flag twice
*/
HWTEST_F(SecureCameraSessionUnitTest, camera_securecamera_unittest_002, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);

        if (find(modes.begin(), modes.end(), SceneMode::SECURE) != modes.end()) {
            sptr<CameraOutputCapability> ability = cameraManager_->
                GetSupportedOutputCapability(camDevice, SceneMode::SECURE);
            ASSERT_NE(ability, nullptr);
            sptr<CaptureInput> input = cameraManager_->CreateCameraInput(camDevice);
            ASSERT_NE(input, nullptr);
            sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
            std::string cameraSettings = camInput->GetCameraSettings();
            camInput->SetCameraSettings(cameraSettings);
            uint64_t secureSeqId = 0;
            int intResult = camInput->Open(false, &secureSeqId);
            EXPECT_EQ(intResult, CAMERA_OK);

            sptr<CaptureOutput> preview1 = CreatePreviewOutput();
            if (!preIsSupportedSecuremode_) {
                input->Close();
                GTEST_SKIP();
            }
            ASSERT_NE(preview1, nullptr);
            sptr<CaptureOutput> preview2 = CreatePreviewOutput();
            if (!preIsSupportedSecuremode_) {
                input->Close();
                GTEST_SKIP();
            }
            ASSERT_NE(preview2, nullptr);
            sptr<CaptureSession> secureSessionForSys =
                CameraManagerForSys::GetInstance()->CreateCaptureSessionForSys(SceneMode::SECURE);
            ASSERT_NE(secureSessionForSys, nullptr);
            EXPECT_EQ(secureSessionForSys->BeginConfig(), 0);
            EXPECT_EQ(secureSessionForSys->AddInput(input), 0);
            EXPECT_EQ(secureSessionForSys->AddOutput(preview1), 0);
            EXPECT_EQ(secureSessionForSys->AddOutput(preview2), 0);
            EXPECT_EQ(secureSessionForSys->AddSecureOutput(preview1), 0);
            EXPECT_EQ(secureSessionForSys->AddSecureOutput(preview2), CAMERA_OPERATION_NOT_ALLOWED);
            secureSessionForSys->Release();
            input->Close();
            break;
        }
    }
}

/*
* Feature: Framework
* Function: Test abnormal branch that is add secure output flag twice
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: Test abnormal branch that is add secure output flag twice
*/
HWTEST_F(SecureCameraSessionUnitTest, camera_securecamera_unittest_003, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);

        if (find(modes.begin(), modes.end(), SceneMode::SECURE) != modes.end()) {
            sptr<CameraOutputCapability> ability = cameraManager_->
                GetSupportedOutputCapability(camDevice, SceneMode::SECURE);
            ASSERT_NE(ability, nullptr);
            sptr<CaptureInput> input = cameraManager_->CreateCameraInput(camDevice);
            ASSERT_NE(input, nullptr);
            sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
            std::string cameraSettings = camInput->GetCameraSettings();
            camInput->SetCameraSettings(cameraSettings);
            uint64_t secureSeqId = 0;
            int intResult = camInput->Open(false, &secureSeqId);
            EXPECT_EQ(intResult, CAMERA_OK);
            sptr<CaptureOutput> preview1 = CreatePreviewOutput();
            if (!preIsSupportedSecuremode_) {
                GTEST_SKIP();
            }
            ASSERT_NE(preview1, nullptr);
            sptr<CaptureOutput> preview2 = CreatePreviewOutput();
            if (!preIsSupportedSecuremode_) {
                GTEST_SKIP();
            }
            ASSERT_NE(preview2, nullptr);
            sptr<CaptureSession> secureSessionForSys =
                CameraManagerForSys::GetInstance()->CreateCaptureSessionForSys(SceneMode::SECURE);
            ASSERT_NE(secureSessionForSys, nullptr);

            EXPECT_EQ(secureSessionForSys->BeginConfig(), 0);
            EXPECT_EQ(secureSessionForSys->AddInput(input), 0);
            EXPECT_EQ(secureSessionForSys->AddOutput(preview1), 0);
            EXPECT_EQ(secureSessionForSys->AddOutput(preview2), 0);
            EXPECT_EQ(secureSessionForSys->AddSecureOutput(preview1), 0);
            EXPECT_EQ(secureSessionForSys->AddSecureOutput(preview2), CAMERA_OPERATION_NOT_ALLOWED);
            secureSessionForSys->Release();
            input->Close();
            break;
        }
    }
}

/*
* Feature: Framework
* Function: Test normal branch that is add secure output flag
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: Test normal branch that is add secure output flag
*/
HWTEST_F(SecureCameraSessionUnitTest, camera_securecamera_unittest_004, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);

        if (find(modes.begin(), modes.end(), SceneMode::SECURE) != modes.end()) {
            sptr<CameraOutputCapability> ability = cameraManager_->
                GetSupportedOutputCapability(camDevice, SceneMode::SECURE);
            ASSERT_NE(ability, nullptr);
            sptr<CaptureInput> input = cameraManager_->CreateCameraInput(camDevice);
            ASSERT_NE(input, nullptr);
            sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
            std::string cameraSettings = camInput->GetCameraSettings();
            camInput->SetCameraSettings(cameraSettings);
            uint64_t secureSeqId = 0;
            int intResult = camInput->Open(false, &secureSeqId);
            EXPECT_EQ(intResult, CAMERA_OK);
            sptr<CaptureOutput> preview = CreatePreviewOutput();
            if (!preIsSupportedSecuremode_) {
                input->Close();
                GTEST_SKIP();
            }
            ASSERT_NE(preview, nullptr);
            sptr<CaptureSession> captureSession = cameraManager_->CreateCaptureSession(SceneMode::SECURE);
            ASSERT_NE(captureSession, nullptr);
            sptr<SecureCameraSession> secureSession = nullptr;
            secureSession = static_cast<SecureCameraSession *> (captureSession.GetRefPtr());
            ASSERT_NE(secureSession, nullptr);

            EXPECT_EQ(secureSession->BeginConfig(), 0);
            EXPECT_EQ(secureSession->AddInput(input), 0);
            sptr<CameraDevice> info = captureSession->innerInputDevice_->GetCameraDeviceInfo();
            ASSERT_NE(info, nullptr);
            info->modePreviewProfiles_.emplace(static_cast<int32_t>(SceneMode::SECURE), previewProfile_);
            EXPECT_EQ(secureSession->AddOutput(preview), 0);
            EXPECT_EQ(secureSession->AddSecureOutput(preview), 0);
            secureSession->Release();
            input->Close();
            break;
        }
    }
}

/*
* Feature: Framework
* Function: Test abnormal branch that is add secure output flag twice
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: Test abnormal branch that is add secure output flag twice
*/
HWTEST_F(SecureCameraSessionUnitTest, camera_securecamera_unittest_005, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);

        if (find(modes.begin(), modes.end(), SceneMode::SECURE) != modes.end()) {
            sptr<CameraOutputCapability> ability = cameraManager_->
                GetSupportedOutputCapability(camDevice, SceneMode::SECURE);
            ASSERT_NE(ability, nullptr);
            sptr<CaptureInput> input = cameraManager_->CreateCameraInput(camDevice);
            ASSERT_NE(input, nullptr);
            sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
            std::string cameraSettings = camInput->GetCameraSettings();
            camInput->SetCameraSettings(cameraSettings);
            uint64_t secureSeqId = 0;
            int intResult = camInput->Open(false, &secureSeqId);
            EXPECT_EQ(intResult, CAMERA_OK);

            sptr<CaptureOutput> preview1 = CreatePreviewOutput();
            if (!preIsSupportedSecuremode_) {
                input->Close();
                GTEST_SKIP();
            }
            ASSERT_NE(preview1, nullptr);
            sptr<CaptureOutput> preview2 = CreatePreviewOutput();
            if (!preIsSupportedSecuremode_) {
                input->Close();
                GTEST_SKIP();
            }
            ASSERT_NE(preview2, nullptr);
            sptr<CaptureSession> captureSession = cameraManager_->CreateCaptureSession(SceneMode::SECURE);
            ASSERT_NE(captureSession, nullptr);
            sptr<SecureCameraSession> secureSession = nullptr;
            secureSession = static_cast<SecureCameraSession *> (captureSession.GetRefPtr());
            ASSERT_NE(secureSession, nullptr);

            EXPECT_EQ(secureSession->BeginConfig(), 0);
            EXPECT_EQ(secureSession->AddInput(input), 0);
            EXPECT_EQ(secureSession->AddOutput(preview1), 0);
            EXPECT_EQ(secureSession->AddOutput(preview2), 0);
            EXPECT_EQ(secureSession->AddSecureOutput(preview1), 0);
            EXPECT_EQ(secureSession->AddSecureOutput(preview2), CAMERA_OPERATION_NOT_ALLOWED);
            secureSession->Release();
            input->Close();
            break;
        }
    }
}

/*
* Feature: Framework
* Function: Test abnormal branch that is add secure output flag twice
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: Test abnormal branch that is add secure output flag twice
*/
HWTEST_F(SecureCameraSessionUnitTest, camera_securecamera_unittest_006, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);

        if (find(modes.begin(), modes.end(), SceneMode::SECURE) != modes.end()) {
            sptr<CameraOutputCapability> ability = cameraManager_->
                GetSupportedOutputCapability(camDevice, SceneMode::SECURE);
            ASSERT_NE(ability, nullptr);
            sptr<CaptureInput> input = cameraManager_->CreateCameraInput(camDevice);
            ASSERT_NE(input, nullptr);
            sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
            std::string cameraSettings = camInput->GetCameraSettings();
            camInput->SetCameraSettings(cameraSettings);
            uint64_t secureSeqId = 0;
            int intResult = camInput->Open(false, &secureSeqId);
            EXPECT_EQ(intResult, CAMERA_OK);
            sptr<CaptureOutput> preview1 = CreatePreviewOutput();
            if (!preIsSupportedSecuremode_) {
                GTEST_SKIP();
            }
            ASSERT_NE(preview1, nullptr);
            sptr<CaptureOutput> preview2 = CreatePreviewOutput();
            if (!preIsSupportedSecuremode_) {
                GTEST_SKIP();
            }
            ASSERT_NE(preview2, nullptr);
            sptr<CaptureSession> captureSession = cameraManager_->CreateCaptureSession(SceneMode::SECURE);
            ASSERT_NE(captureSession, nullptr);
            sptr<SecureCameraSession> secureSession = nullptr;
            secureSession = static_cast<SecureCameraSession *> (captureSession.GetRefPtr());
            ASSERT_NE(secureSession, nullptr);

            EXPECT_EQ(secureSession->BeginConfig(), 0);
            EXPECT_EQ(secureSession->AddInput(input), 0);
            EXPECT_EQ(secureSession->AddOutput(preview1), 0);
            EXPECT_EQ(secureSession->AddOutput(preview2), 0);
            EXPECT_EQ(secureSession->AddSecureOutput(preview1), 0);
            EXPECT_EQ(secureSession->AddSecureOutput(preview2), CAMERA_OPERATION_NOT_ALLOWED);
            secureSession->Release();
            input->Close();
            break;
        }
    }
}


/*
 * Feature: Framework
 * Function: Test SecureCameraSession AddSecureOutput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AddSecureOutput for just call.
 */
HWTEST_F(SecureCameraSessionUnitTest, secure_camera_session_function_unittest_001, TestSize.Level1)
{
    sptr<CaptureSession> secureSessionForSys =
                CameraManagerForSys::GetInstance()->CreateCaptureSessionForSys(SceneMode::SECURE);
            ASSERT_NE(secureSessionForSys, nullptr);;
    sptr<CaptureOutput> output = nullptr;
    EXPECT_EQ(secureSessionForSys->AddSecureOutput(output), CAMERA_OPERATION_NOT_ALLOWED);
    //recover cameraManager_
    cameraManager_->InitCameraManager();
}

/*
 * Feature: Framework
 * Function: Test SecureCameraSession AddSecureOutput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AddSecureOutput for just call.
 */
HWTEST_F(SecureCameraSessionUnitTest, secure_camera_session_function_unittest_002, TestSize.Level1)
{
    sptr<CaptureSession> captureSession = cameraManager_->CreateCaptureSession(SceneMode::SECURE);
    ASSERT_NE(captureSession, nullptr);
    sptr<SecureCameraSession> secureCameraSession =
        static_cast<SecureCameraSession*>(captureSession.GetRefPtr());
    ASSERT_NE(secureCameraSession, nullptr);
    sptr<CaptureOutput> output = nullptr;
    EXPECT_EQ(secureCameraSession->AddSecureOutput(output), CAMERA_OPERATION_NOT_ALLOWED);
    //recover cameraManager_
    cameraManager_->InitCameraManager();
}
}
}