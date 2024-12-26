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

#include "night_session_unittest.h"
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

namespace OHOS {
namespace CameraStandard {

sptr<CaptureOutput> CameraNightSessionUnit::CreatePreviewOutput()
{
    previewProfile = {};
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    if (!cameraManager_ || cameras.empty()) {
        return nullptr;
    }
    auto outputCapability = cameraManager_->GetSupportedOutputCapability(cameras[0], static_cast<int32_t>(NIGHT));
    if (!outputCapability) {
        return nullptr;
    }

    previewProfile = outputCapability->GetPreviewProfiles();
    if (previewProfile.empty()) {
        return nullptr;
    }

    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    if (surface == nullptr) {
        return nullptr;
    }
    return cameraManager_->CreatePreviewOutput(previewProfile[0], surface);
}

sptr<CaptureOutput> CameraNightSessionUnit::CreatePhotoOutput()
{
    photoProfile = {};
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    if (!cameraManager_ || cameras.empty()) {
        return nullptr;
    }
    auto outputCapability = cameraManager_->GetSupportedOutputCapability(cameras[0], static_cast<int32_t>(NIGHT));
    if (!outputCapability) {
        return nullptr;
    }

    photoProfile = outputCapability->GetPhotoProfiles();
    if (photoProfile.empty()) {
        return nullptr;
    }

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    if (surface == nullptr) {
        return nullptr;
    }
    sptr<IBufferProducer> surfaceProducer = surface->GetProducer();
    return cameraManager_->CreatePhotoOutput(photoProfile[0], surfaceProducer);
}

void CameraNightSessionUnit::SetUpTestCase(void) {}

void CameraNightSessionUnit::TearDownTestCase(void) {}

void CameraNightSessionUnit::SetUp()
{
    NativeAuthorization();
    cameraManager_ = CameraManager::GetInstance();
}

void CameraNightSessionUnit::TearDown()
{
    MEDIA_DEBUG_LOG("CameraPanarmaSessionUnit TearDown");
}

void CameraNightSessionUnit::NativeAuthorization()
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
    MEDIA_DEBUG_LOG("CameraNightSessionUnit::NativeAuthorization g_uid:%{public}d", uid_);
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

/*
 * Feature: Framework
 * Function: Test NightSession about exposure
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test NightSession about exposure
 */
HWTEST_F(CameraNightSessionUnit, night_session_unittest_001, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    SceneMode mode = NIGHT;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras[0]->GetMetadata();
    int32_t modeSet = static_cast<int32_t>(NORMAL);
    metadata->addEntry(OHOS_ABILITY_CAMERA_MODES, &modeSet, 1);
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
    sptr<NightSession> nightSession = static_cast<NightSession*>(captureSession.GetRefPtr());
    ASSERT_NE(nightSession, nullptr);

    EXPECT_EQ(nightSession->BeginConfig(), 0);
    EXPECT_EQ(nightSession->AddInput(input), 0);
    sptr<CameraDevice> info = captureSession->innerInputDevice_->GetCameraDeviceInfo();
    ASSERT_NE(info, nullptr);
    info->modePreviewProfiles_.emplace(static_cast<int32_t>(NIGHT), previewProfile);
    info->modePhotoProfiles_.emplace(static_cast<int32_t>(NIGHT), photoProfile);
    EXPECT_EQ(nightSession->AddOutput(preview), 0);
    EXPECT_EQ(nightSession->AddOutput(photo), 0);
    EXPECT_EQ(nightSession->CommitConfig(), 0);

    std::vector<uint32_t> exposureRange = {};
    uint32_t exposureValue = 0;
    OHOS::Camera::DeleteCameraMetadataItem(info->GetMetadata()->get(), OHOS_ABILITY_NIGHT_MODE_SUPPORTED_EXPOSURE_TIME);
    OHOS::Camera::DeleteCameraMetadataItem(info->GetMetadata()->get(), OHOS_CONTROL_MANUAL_EXPOSURE_TIME);
    EXPECT_EQ(nightSession->GetExposureRange(exposureRange), CameraErrorCode::INVALID_ARGUMENT);
    EXPECT_EQ(nightSession->GetExposure(exposureValue), CameraErrorCode::INVALID_ARGUMENT);

    nightSession->Release();
    input->Close();
}

/*
 * Feature: Framework
 * Function: Test NightSession when innerInputDevice_ and output is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test NightSession when innerInputDevice_ and output is nullptr
 */
HWTEST_F(CameraNightSessionUnit, night_session_unittest_002, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    SceneMode mode = NIGHT;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras[0]->GetMetadata();
    int32_t modeSet = static_cast<int32_t>(NORMAL);
    metadata->addEntry(OHOS_ABILITY_CAMERA_MODES, &modeSet, 1);
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
    sptr<NightSession> nightSession = static_cast<NightSession*>(captureSession.GetRefPtr());
    ASSERT_NE(nightSession, nullptr);

    EXPECT_EQ(nightSession->BeginConfig(), 0);
    EXPECT_EQ(nightSession->AddInput(input), 0);
    sptr<CameraDevice> info = captureSession->innerInputDevice_->GetCameraDeviceInfo();
    ASSERT_NE(info, nullptr);
    info->modePreviewProfiles_.emplace(static_cast<int32_t>(NIGHT), previewProfile);
    info->modePhotoProfiles_.emplace(static_cast<int32_t>(NIGHT), photoProfile);
    EXPECT_EQ(nightSession->AddOutput(preview), 0);
    EXPECT_EQ(nightSession->AddOutput(photo), 0);
    EXPECT_EQ(nightSession->CommitConfig(), 0);

    nightSession->innerInputDevice_ = nullptr;
    std::vector<uint32_t> exposureRange = {};
    EXPECT_EQ(nightSession->GetExposureRange(exposureRange), CameraErrorCode::INVALID_ARGUMENT);
    sptr<CaptureOutput> output = nullptr;
    EXPECT_EQ(nightSession->CanAddOutput(output), false);

    nightSession->Release();
    input->Close();
}

/*
 * Feature: Framework
 * Function: Test NightSession with SetExposure
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test NightSession with SetExposure
 */
HWTEST_F(CameraNightSessionUnit, night_session_unittest_003, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    SceneMode mode = NIGHT;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras[0]->GetMetadata();
    int32_t modeSet = static_cast<int32_t>(NORMAL);
    metadata->addEntry(OHOS_ABILITY_CAMERA_MODES, &modeSet, 1);
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
    sptr<NightSession> nightSession = static_cast<NightSession*>(captureSession.GetRefPtr());
    ASSERT_NE(nightSession, nullptr);

    EXPECT_EQ(nightSession->BeginConfig(), 0);
    EXPECT_EQ(nightSession->AddInput(input), 0);
    sptr<CameraDevice> info = captureSession->innerInputDevice_->GetCameraDeviceInfo();
    ASSERT_NE(info, nullptr);
    info->modePreviewProfiles_.emplace(static_cast<int32_t>(NIGHT), previewProfile);
    info->modePhotoProfiles_.emplace(static_cast<int32_t>(NIGHT), photoProfile);
    EXPECT_EQ(nightSession->AddOutput(preview), 0);
    EXPECT_EQ(nightSession->AddOutput(photo), 0);
    EXPECT_EQ(nightSession->CommitConfig(), 0);

    std::vector<uint32_t> exposureRange = {};
    uint32_t exposureValue = 0;
    OHOS::Camera::DeleteCameraMetadataItem(info->GetMetadata()->get(), OHOS_ABILITY_NIGHT_MODE_SUPPORTED_EXPOSURE_TIME);
    EXPECT_EQ(nightSession->GetExposureRange(exposureRange), CameraErrorCode::INVALID_ARGUMENT);
    EXPECT_EQ(nightSession->SetExposure(exposureValue), CameraErrorCode::SUCCESS);

    nightSession->Release();
    input->Close();
}
}
}