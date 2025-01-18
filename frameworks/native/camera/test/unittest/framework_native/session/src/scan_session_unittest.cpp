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

#include "scan_session_unittest.h"

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
    auto outputCapability = cameraManager_->GetSupportedOutputCapability(cameras[0],
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

sptr<CaptureOutput> CameraScanSessionUnitTest::CreatePhotoOutput()
{
    CameraFormat format = CAMERA_FORMAT_JPEG;
    Size size;
    size.width = 1280;
    size.height = 960;
    Profile profile = Profile(format, size);
    photoProfile_.push_back(profile);

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    if (surface == nullptr) {
        return nullptr;
    }
    sptr<IBufferProducer> surfaceProducer = surface->GetProducer();
    return cameraManager_->CreatePhotoOutput(photoProfile_[0], surfaceProducer);
}

void CameraScanSessionUnitTest::SetUpTestCase(void) {}

void CameraScanSessionUnitTest::TearDownTestCase(void)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    SceneMode mode = PORTRAIT;
    sptr<HCaptureSession> camSession = new (std::nothrow) HCaptureSession(callerToken, mode);
    camSession->Release();
}

void CameraScanSessionUnitTest::SetUp()
{
    NativeAuthorization();
    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);
}

void CameraScanSessionUnitTest::TearDown()
{
    cameraManager_ = nullptr;
    MEDIA_DEBUG_LOG("CameraScanSessionUnitTest::TearDown");
}

void CameraScanSessionUnitTest::NativeAuthorization()
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
    MEDIA_DEBUG_LOG("CameraScanSessionUnitTest::NativeAuthorization g_uid:%{public}d", uid_);
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}


/*
 * Feature: Framework
 * Function: Test ScanSession when output is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ScanSession when output is nullptr
 */
HWTEST_F(CameraScanSessionUnitTest, scan_session_unittest_001, TestSize.Level0)
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
HWTEST_F(CameraScanSessionUnitTest, scan_session_unittest_002, TestSize.Level0)
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
    ASSERT_NE(preview, nullptr);

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> captureSession = cameraManager_->CreateCaptureSession(mode);
    ASSERT_NE(captureSession, nullptr);
    sptr<ScanSession> scanSession = static_cast<ScanSession*>(captureSession.GetRefPtr());
    ASSERT_NE(scanSession, nullptr);

    EXPECT_EQ(scanSession->CanAddOutput(photo), false);
    EXPECT_EQ(scanSession->BeginConfig(), 0);
    EXPECT_EQ(scanSession->AddInput(input), 0);
    sptr<CameraDevice> info = captureSession->innerInputDevice_->GetCameraDeviceInfo();
    ASSERT_NE(info, nullptr);
    info->modePreviewProfiles_.emplace(static_cast<int32_t>(SceneMode::SCAN), previewProfile_);
    info->modePhotoProfiles_.emplace(static_cast<int32_t>(SceneMode::SCAN), photoProfile_);
    EXPECT_EQ(scanSession->AddOutput(preview), 0);

    scanSession->CanAddOutput(photo);

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
HWTEST_F(CameraScanSessionUnitTest, scan_session_unittest_003, TestSize.Level0)
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
    ASSERT_NE(preview, nullptr);

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> captureSession = cameraManager_->CreateCaptureSession(mode);
    ASSERT_NE(captureSession, nullptr);
    sptr<ScanSession> scanSession = static_cast<ScanSession*>(captureSession.GetRefPtr());
    ASSERT_NE(scanSession, nullptr);

    EXPECT_EQ(scanSession->CanAddOutput(photo), false);
    EXPECT_EQ(scanSession->BeginConfig(), 0);
    EXPECT_EQ(scanSession->AddInput(input), 0);
    sptr<CameraDevice> info = captureSession->innerInputDevice_->GetCameraDeviceInfo();
    ASSERT_NE(info, nullptr);
    info->modePreviewProfiles_.emplace(static_cast<int32_t>(SceneMode::SCAN), previewProfile_);
    EXPECT_EQ(scanSession->AddOutput(preview), 0);

    scanSession->CanAddOutput(photo);

    scanSession->innerInputDevice_ = nullptr;
    int32_t ret = scanSession->AddOutput(preview);
    EXPECT_EQ(ret, SESSION_NOT_CONFIG);

    ret = scanSession->CommitConfig();
    EXPECT_EQ(ret, 0);

    scanSession->Release();
    EXPECT_EQ(camInput->GetCameraDevice()->Close(), 0);
}

}
}