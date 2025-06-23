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
#include "scan_session_unittest.h"
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
using namespace OHOS::HDI::Camera::V1_1;

sptr<CaptureOutput> CameraScanSessionUnitTest::CreatePreviewOutput()
{
    previewProfile_ = {};
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    if (!cameraManager_ || cameras.empty()) {
        return nullptr;
    }
    preIsSupportedScanmode_ = false;
    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        if (find(modes.begin(), modes.end(), SceneMode::SCAN) != modes.end()) {
            preIsSupportedScanmode_ = true;
        }

        if (!preIsSupportedScanmode_) {
            continue;
        }

        auto outputCapability = cameraManager_->GetSupportedOutputCapability(camDevice,
            static_cast<int32_t>(SceneMode::SCAN));
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

sptr<CaptureOutput> CameraScanSessionUnitTest::CreatePhotoOutput()
{
    photoProfile_ = {};
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    if (!cameraManager_ || cameras.empty()) {
        return nullptr;
    }
    phoIsSupportedScanmode_ = false;
    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        if (find(modes.begin(), modes.end(), SceneMode::SCAN) != modes.end()) {
            phoIsSupportedScanmode_ = true;
        }

        if (!phoIsSupportedScanmode_) {
            continue;
        }

        auto outputCapability = cameraManager_->GetSupportedOutputCapability(camDevice,
            static_cast<int32_t>(SceneMode::SCAN));
        if (!outputCapability) {
            return nullptr;
        }

        photoProfile_ = outputCapability->GetPhotoProfiles();
        if (photoProfile_.empty()) {
            return nullptr;
        }

        sptr<IConsumerSurface> surface = IConsumerSurface::Create();
        if (surface == nullptr) {
            return nullptr;
        }
        sptr<IBufferProducer> surfaceProducer = surface->GetProducer();
        return cameraManager_->CreatePhotoOutput(photoProfile_[0], surfaceProducer);
    }
    return nullptr;
}

void CameraScanSessionUnitTest::SetUpTestCase(void)
{
    ASSERT_TRUE(TestToken::GetAllCameraPermission());
}

void CameraScanSessionUnitTest::TearDownTestCase(void)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    SceneMode mode = PORTRAIT;
    sptr<HCaptureSession> camSession = new (std::nothrow) HCaptureSession(callerToken, mode);
    camSession->Release();
}

void CameraScanSessionUnitTest::SetUp()
{
    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);
}

void CameraScanSessionUnitTest::TearDown()
{
    cameraManager_ = nullptr;
    MEDIA_DEBUG_LOG("CameraScanSessionUnitTest::TearDown");
}

/*
 * Feature: Framework
 * Function: Test ScanSession when output is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ScanSession when output is nullptr
 */
HWTEST_F(CameraScanSessionUnitTest, scan_session_unittest_001, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    SceneMode mode = SCAN;
    cameras[0]->supportedModes_.clear();
    cameras[0]->supportedModes_.push_back(NORMAL);
    std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(cameras[0]);
    ASSERT_TRUE(modes.size() != 0);

    sptr<CameraOutputCapability> ability = cameraManager_->GetSupportedOutputCapability(cameras[0], mode);
    ASSERT_NE(ability, nullptr);

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> preview = CreatePreviewOutput();
    if (!preIsSupportedScanmode_) {
        camInput->GetCameraDevice()->Close();
        GTEST_SKIP();
    }
    ASSERT_NE(preview, nullptr);

    sptr<CaptureSession> captureSession = cameraManager_->CreateCaptureSession(mode);
    ASSERT_NE(captureSession, nullptr);
    sptr<ScanSession> scanSession = static_cast<ScanSession*>(captureSession.GetRefPtr());
    ASSERT_NE(scanSession, nullptr);

    EXPECT_EQ(scanSession->BeginConfig(), 0);
    EXPECT_EQ(scanSession->AddInput(input), 0);
    sptr<CameraDevice> info = captureSession->innerInputDevice_->GetCameraDeviceInfo();
    ASSERT_NE(info, nullptr);
    info->modePreviewProfiles_.emplace(static_cast<int32_t>(SceneMode::SCAN), previewProfile_);
    EXPECT_EQ(scanSession->AddOutput(preview), 0);
    EXPECT_EQ(scanSession->CommitConfig(), 0);

    sptr<CaptureOutput> output = nullptr;
    scanSession->CanAddOutput(output);

    scanSession->Release();
    EXPECT_EQ(camInput->GetCameraDevice()->Close(), 0);
}

/*
 * Feature: Framework
 * Function: Test ScanSession when innerInputDevice_ is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ScanSession when innerInputDevice_ is nullptr
 */
HWTEST_F(CameraScanSessionUnitTest, scan_session_unittest_002, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    SceneMode mode = SCAN;
    cameras[0]->supportedModes_.clear();
    cameras[0]->supportedModes_.push_back(NORMAL);
    std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(cameras[0]);
    ASSERT_TRUE(modes.size() != 0);

    sptr<CameraOutputCapability> ability = cameraManager_->GetSupportedOutputCapability(cameras[0], mode);
    ASSERT_NE(ability, nullptr);

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> preview = CreatePreviewOutput();
    if (!preIsSupportedScanmode_) {
        camInput->GetCameraDevice()->Close();
        GTEST_SKIP();
    }
    ASSERT_NE(preview, nullptr);

    sptr<CaptureSession> captureSession = cameraManager_->CreateCaptureSession(mode);
    ASSERT_NE(captureSession, nullptr);
    sptr<ScanSession> scanSession = static_cast<ScanSession*>(captureSession.GetRefPtr());
    ASSERT_NE(scanSession, nullptr);

    EXPECT_EQ(scanSession->BeginConfig(), 0);
    EXPECT_EQ(scanSession->AddInput(input), 0);
    sptr<CameraDevice> info = captureSession->innerInputDevice_->GetCameraDeviceInfo();
    ASSERT_NE(info, nullptr);
    info->modePreviewProfiles_.emplace(static_cast<int32_t>(SceneMode::SCAN), previewProfile_);
    EXPECT_EQ(scanSession->AddOutput(preview), 0);

    scanSession->innerInputDevice_ = nullptr;
    int32_t ret = scanSession->AddOutput(preview);
    EXPECT_EQ(ret, SESSION_NOT_CONFIG);

    ret = scanSession->CommitConfig();
    EXPECT_EQ(ret, 0);

    scanSession->Release();
    EXPECT_EQ(camInput->GetCameraDevice()->Close(), 0);
}

/*
 * Feature: Framework
 * Function: Test ScanSession
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ScanSession
 */
HWTEST_F(CameraScanSessionUnitTest, scan_session_unittest_003, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    SceneMode mode = SCAN;
    cameras[0]->supportedModes_.clear();
    cameras[0]->supportedModes_.push_back(NORMAL);
    std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(cameras[0]);
    ASSERT_TRUE(modes.size() != 0);

    sptr<CameraOutputCapability> ability = cameraManager_->GetSupportedOutputCapability(cameras[0], mode);
    ASSERT_NE(ability, nullptr);

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> preview = CreatePreviewOutput();
    if (!preIsSupportedScanmode_) {
        camInput->GetCameraDevice()->Close();
        GTEST_SKIP();
    }
    ASSERT_NE(preview, nullptr);

    sptr<CaptureSession> captureSession = cameraManager_->CreateCaptureSession(mode);
    ASSERT_NE(captureSession, nullptr);
    sptr<ScanSession> scanSession = static_cast<ScanSession*>(captureSession.GetRefPtr());
    ASSERT_NE(scanSession, nullptr);

    EXPECT_EQ(scanSession->BeginConfig(), 0);
    EXPECT_EQ(scanSession->AddInput(input), 0);
    sptr<CameraDevice> info = captureSession->innerInputDevice_->GetCameraDeviceInfo();
    ASSERT_NE(info, nullptr);
    info->modePreviewProfiles_.emplace(static_cast<int32_t>(SceneMode::SCAN), previewProfile_);
    EXPECT_EQ(scanSession->AddOutput(preview), 0);

    scanSession->innerInputDevice_ = nullptr;
    int32_t ret = scanSession->AddOutput(preview);
    EXPECT_EQ(ret, SESSION_NOT_CONFIG);

    ret = scanSession->CommitConfig();
    EXPECT_EQ(ret, 0);

    scanSession->Release();
    EXPECT_EQ(camInput->GetCameraDevice()->Close(), 0);
}

/*
 * Feature: Framework
 * Function: Test ProcessBrightnessStatusChange
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessBrightnessStatusChange interface with different brightness states
 */
HWTEST_F(CameraScanSessionUnitTest, ProcessBrightnessStatusChange_001, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    SceneMode mode = SCAN;
    cameras[0]->supportedModes_.clear();
    cameras[0]->supportedModes_.push_back(NORMAL);
    std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(cameras[0]);
    ASSERT_TRUE(modes.size() != 0);

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> preview = CreatePreviewOutput();
    if (!preIsSupportedScanmode_) {
        camInput->GetCameraDevice()->Close();
        GTEST_SKIP();
    }
    ASSERT_NE(preview, nullptr);

    sptr<CaptureSession> captureSession = cameraManager_->CreateCaptureSession(mode);
    ASSERT_NE(captureSession, nullptr);
    sptr<ScanSession> scanSession = static_cast<ScanSession*>(captureSession.GetRefPtr());
    ASSERT_NE(scanSession, nullptr);

    EXPECT_EQ(scanSession->BeginConfig(), 0);
    EXPECT_EQ(scanSession->AddInput(input), 0);
    sptr<CameraDevice> info = captureSession->innerInputDevice_->GetCameraDeviceInfo();
    ASSERT_NE(info, nullptr);
    info->modePreviewProfiles_.emplace(static_cast<int32_t>(SceneMode::SCAN), previewProfile_);
    EXPECT_EQ(scanSession->AddOutput(preview), 0);
    EXPECT_EQ(scanSession->CommitConfig(), 0);

    auto metadata = std::make_shared<OHOS::Camera::CameraMetadata>(10, 100);
    uint32_t brightnessStatus = 1;
    metadata->addEntry(OHOS_STATUS_FLASH_SUGGESTION, &brightnessStatus, 1);
    scanSession->ProcessBrightnessStatusChange(metadata);

    brightnessStatus = 0;
    metadata->updateEntry(OHOS_STATUS_FLASH_SUGGESTION, &brightnessStatus, 1);
    scanSession->ProcessBrightnessStatusChange(metadata);

    scanSession->ProcessBrightnessStatusChange(nullptr);

    scanSession->Release();
    EXPECT_EQ(camInput->GetCameraDevice()->Close(), 0);
}

}
}