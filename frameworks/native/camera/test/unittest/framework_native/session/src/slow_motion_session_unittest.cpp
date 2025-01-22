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

#include "slow_motion_session_unittest.h"

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
using namespace OHOS::HDI::Camera::V1_1;

class TestSlowMotionStateCallback : public SlowMotionStateCallback {
public:
    void OnSlowMotionState(const SlowMotionState state)
    {
        MEDIA_INFO_LOG("TestSlowMotionStateCallback OnSlowMotionState.");
    }
};

void CameraSlowMotionSessionUnitTest::SetUpTestCase(void) {}

void CameraSlowMotionSessionUnitTest::TearDownTestCase(void) {}

void CameraSlowMotionSessionUnitTest::SetUp()
{
    NativeAuthorization();
    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);
}

void CameraSlowMotionSessionUnitTest::TearDown()
{
    cameraManager_ = nullptr;
    MEDIA_DEBUG_LOG("CameraSlowMotionSessionUnitTest TearDown");
}

void CameraSlowMotionSessionUnitTest::NativeAuthorization()
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
    MEDIA_DEBUG_LOG("CameraSlowMotionSessionUnitTest::NativeAuthorization g_uid:%{public}d", uid_);
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

sptr<CaptureOutput> CameraSlowMotionSessionUnitTest::CreatePreviewOutput()
{
    previewProfile_ = {};
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    if (!cameraManager_ || cameras.empty()) {
        return nullptr;
    }
    preIsSupportedSlowmode_ = false;
    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        if (find(modes.begin(), modes.end(), SceneMode::SLOW_MOTION) != modes.end()) {
            preIsSupportedSlowmode_ = true;
        }

        if (!preIsSupportedSlowmode_) {
            continue;
        }

        auto outputCapability = cameraManager_->GetSupportedOutputCapability(camDevice,
            static_cast<int32_t>(SceneMode::SLOW_MOTION));
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

sptr<CaptureOutput> CameraSlowMotionSessionUnitTest::CreateVideoOutput()
{
    profile_ = {};
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    if (!cameraManager_ || cameras.empty()) {
        return nullptr;
    }
    vidIsSupportedSlowmode_ = false;
    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        if (find(modes.begin(), modes.end(), SceneMode::SLOW_MOTION) != modes.end()) {
            vidIsSupportedSlowmode_ = true;
        }

        if (!vidIsSupportedSlowmode_) {
            continue;
        }
        auto outputCapability = cameraManager_->GetSupportedOutputCapability(camDevice,
        static_cast<int32_t>(SceneMode::SLOW_MOTION));
        if (!outputCapability) {
            return nullptr;
        }

        profile_ = outputCapability->GetVideoProfiles();
        if (profile_.empty()) {
            return nullptr;
        }

        sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
        if (surface == nullptr) {
            return nullptr;
        }
        return cameraManager_->CreateVideoOutput(profile_[0], surface);
    }
    return nullptr;
}

/**
* @tc.name    : Test IsSlowMotionDetectionSupported API
* @tc.number  : IsSlowMotionDetectionSupported_001
* @tc.desc    : Test IsSlowMotionDetectionSupported interface, when session is not committed.
* @tc.require : slow motion only support videoStream & previewStrem & 1080p & 240fps
*/
HWTEST_F(CameraSlowMotionSessionUnitTest, slow_motion_session_unittest_001, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession(SceneMode::SLOW_MOTION);
    ASSERT_NE(session, nullptr);
    sptr<SlowMotionSession> slowSession = static_cast<SlowMotionSession *> (session.GetRefPtr());
    bool result = slowSession->IsSlowMotionDetectionSupported();
    EXPECT_EQ(false, result);
}

/**
* @tc.name    : Test IsSlowMotionDetectionSupported API
* @tc.number  : IsSlowMotionDetectionSupported_002
* @tc.desc    : Test IsSlowMotionDetectionSupported interface, when camera device is null.
* @tc.require : slow motion only support videoStream & previewStrem & 1080p & 240fps
*/
HWTEST_F(CameraSlowMotionSessionUnitTest, IsSlowMotionDetectionSupported_002, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    ASSERT_EQ(input->Open(), SUCCESS);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession(SceneMode::SLOW_MOTION);
    ASSERT_NE(session, nullptr);

    sptr<CaptureOutput> videoOutput = CreateVideoOutput();
    if (!vidIsSupportedSlowmode_) {
        input->Close();
        return;
    }
    ASSERT_NE(videoOutput, nullptr);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    if (!preIsSupportedSlowmode_) {
        input->Close();
        return;
    }
    ASSERT_NE(previewOutput, nullptr);

    int32_t intResult = session->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session->AddInput(input);
    EXPECT_EQ(intResult, 0);

    sptr<CameraDevice> info = session->innerInputDevice_->GetCameraDeviceInfo();
    ASSERT_NE(info, nullptr);
    info->modePreviewProfiles_.emplace(static_cast<int32_t>(SceneMode::SLOW_MOTION), previewProfile_);
    info->modeVideoProfiles_.emplace(static_cast<int32_t>(SceneMode::SLOW_MOTION), profile_);

    intResult = session->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session->AddOutput(videoOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session->CommitConfig();
    EXPECT_EQ(intResult, 0);

    intResult = input->Release();
    EXPECT_EQ(intResult, 0);

    sptr<SlowMotionSession> slowSession = nullptr;
    slowSession = static_cast<SlowMotionSession *> (session.GetRefPtr());
    bool result = slowSession->IsSlowMotionDetectionSupported();
    EXPECT_EQ(false, result);
}

/**
* @tc.name    : Test IsSlowMotionDetectionSupported API
* @tc.number  : IsSlowMotionDetectionSupported_003
* @tc.desc    : Test IsSlowMotionDetectionSupported interface, when metadata item not found.
*               Test IsSlowMotionDetectionSupported interface, when metadata item data is 0.
*               Test IsSlowMotionDetectionSupported interface, when metadata item data is 1.
* @tc.require : slow motion only support videoStream & previewStrem & 1080p & 240fps
*/
HWTEST_F(CameraSlowMotionSessionUnitTest, slow_motion_session_unittest_003, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    EXPECT_EQ(camInput->GetCameraDevice()->Open(), 0);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession(SceneMode::SLOW_MOTION);
    ASSERT_NE(session, nullptr);

    sptr<CaptureOutput> videoOutput = CreateVideoOutput();
    if (!vidIsSupportedSlowmode_) {
        input->Close();
        return;
    }
    ASSERT_NE(videoOutput, nullptr);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    if (!preIsSupportedSlowmode_) {
        input->Close();
        return;
    }
    ASSERT_NE(previewOutput, nullptr);

    int32_t intResult = session->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session->AddInput(input);
    EXPECT_EQ(intResult, 0);

    sptr<CameraDevice> info = session->innerInputDevice_->GetCameraDeviceInfo();
    ASSERT_NE(info, nullptr);
    info->modePreviewProfiles_.emplace(static_cast<int32_t>(SceneMode::SLOW_MOTION), previewProfile_);
    info->modeVideoProfiles_.emplace(static_cast<int32_t>(SceneMode::SLOW_MOTION), profile_);

    intResult = session->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session->AddOutput(videoOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session->CommitConfig();
    EXPECT_EQ(intResult, 0);

    sptr<SlowMotionSession> slowSession = static_cast<SlowMotionSession *> (session.GetRefPtr());
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        slowSession->GetInputDevice()->GetCameraDeviceInfo()->GetMetadata();
    OHOS::Camera::DeleteCameraMetadataItem(metadata->get(), OHOS_ABILITY_MOTION_DETECTION_SUPPORT);
    uint8_t value_u8 = 0;
    bool result = false;
    result = slowSession->IsSlowMotionDetectionSupported();
    EXPECT_EQ(false, result);
    metadata->addEntry(OHOS_ABILITY_MOTION_DETECTION_SUPPORT, &value_u8, sizeof(uint8_t));
    result = slowSession->IsSlowMotionDetectionSupported();
    EXPECT_EQ(false, result);
    value_u8 = 1;
    metadata->updateEntry(OHOS_ABILITY_MOTION_DETECTION_SUPPORT, &value_u8, sizeof(uint8_t));
    result = slowSession->IsSlowMotionDetectionSupported();
    EXPECT_EQ(true, result);
    Rect rect;
    rect.topLeftX = 0.1;
    rect.topLeftY = 0.1;
    rect.width = 0.8;
    rect.height = 0.8;
    slowSession->SetSlowMotionDetectionArea(rect);

    std::shared_ptr<TestSlowMotionStateCallback> callback = std::make_shared<TestSlowMotionStateCallback>();
    slowSession->SetCallback(callback);
    EXPECT_EQ(slowSession->GetApplicationCallback(), callback);
    EXPECT_EQ(camInput->GetCameraDevice()->Close(), 0);
}

/*
 * Feature: Framework
 * Function: Test SecureCameraSession ProcessCallbacks, OnSlowMotionStateChange, NormalizeRect, EnableMotionDetection
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessCallbacks, OnSlowMotionStateChange, NormalizeRect, EnableMotionDetection for just call.
 */
HWTEST_F(CameraSlowMotionSessionUnitTest, slow_motion_session_function_unittest_001, TestSize.Level0)
{
    sptr<CaptureSession> captureSession = cameraManager_->CreateCaptureSession(SceneMode::SLOW_MOTION);
    ASSERT_NE(captureSession, nullptr);
    sptr<SlowMotionSession> slowMotionSession =
        static_cast<SlowMotionSession*>(captureSession.GetRefPtr());
    ASSERT_NE(slowMotionSession, nullptr);
    SlowMotionSession::SlowMotionSessionMetadataResultProcessor processor(slowMotionSession);
    uint64_t timestamp = 1;
    auto metadata = make_shared<OHOS::Camera::CameraMetadata>(10, 100);
    processor.ProcessCallbacks(timestamp, metadata);
    slowMotionSession->SetCallback(nullptr);
    slowMotionSession->OnSlowMotionStateChange(metadata);
    EXPECT_EQ(slowMotionSession->GetApplicationCallback(), nullptr);

    Rect rect;
    slowMotionSession->NormalizeRect(rect);
    EXPECT_EQ(rect.topLeftX, std::max(0.0, std::min(1.0, rect.topLeftX)));

    bool isEnable = false;
    EXPECT_EQ(slowMotionSession->EnableMotionDetection(isEnable), CameraErrorCode::SESSION_NOT_CONFIG);
}
}
}