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

#include "video_session_unittest.h"

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
#include "hcamera_service.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;

void CameraVideoSessionUnitTest::SetUpTestCase(void) {}

void CameraVideoSessionUnitTest::TearDownTestCase(void) {}

void CameraVideoSessionUnitTest::SetUp()
{
    NativeAuthorization();
    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);
}

void CameraVideoSessionUnitTest::TearDown()
{
    cameraManager_ = nullptr;
    MEDIA_DEBUG_LOG("CameraVideoSessionUnitTest::TearDown");
}

void CameraVideoSessionUnitTest::NativeAuthorization()
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
    MEDIA_DEBUG_LOG("CameraVideoSessionUnitTest::NativeAuthorization g_uid:%{public}d", uid_);
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

void CameraVideoSessionUnitTest::TestVideoSessionCallback()
{
    std::shared_ptr<FocusTrackingCallback> focusTrackingInfoCallback = std::make_shared<TestFocusTrackingCallback>();
    ASSERT_NE(focusTrackingInfoCallback, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession(SceneMode::VIDEO);
    ASSERT_NE(session, nullptr);
    sptr<VideoSession> videoSession = static_cast<VideoSession*>(session.GetRefPtr());
    ASSERT_NE(session, nullptr);

    videoSession->SetFocusTrackingInfoCallback(focusTrackingInfoCallback);
    ASSERT_NE(videoSession->focusTrackingInfoCallback_, nullptr);
    EXPECT_EQ(videoSession->GetFocusTrackingCallback(), focusTrackingInfoCallback);

    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    uint64_t timestamp = 1;
    std::shared_ptr<OHOS::Camera::CameraMetadata> result = cameras[0]->GetMetadata();
    videoSession->metadataResultProcessor_->ProcessCallbacks(timestamp, result);
}

void CameraVideoSessionUnitTest::TestVideoSessionPreconfig(
    sptr<CaptureInput>& input, PreconfigType preconfigType, ProfileSizeRatio profileSizeRatio)
{
    sptr<CaptureSession> videoSession = cameraManager_->CreateCaptureSession(SceneMode::VIDEO);
    ASSERT_NE(videoSession, nullptr);
    if (videoSession->CanPreconfig(preconfigType, profileSizeRatio)) {
        int32_t intResult = videoSession->Preconfig(preconfigType, profileSizeRatio);
        EXPECT_EQ(intResult, 0);

        sptr<PreviewOutput> previewOutput = nullptr;
        intResult =
            cameraManager_->CreatePreviewOutputWithoutProfile(Surface::CreateSurfaceAsConsumer(), &previewOutput);
        EXPECT_EQ(intResult, 0);
        ASSERT_NE(previewOutput, nullptr);

        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        ASSERT_NE(photoSurface, nullptr);
        auto photoProducer = photoSurface->GetProducer();
        ASSERT_NE(photoProducer, nullptr);
        sptr<PhotoOutput> photoOutput = nullptr;
        intResult = cameraManager_->CreatePhotoOutputWithoutProfile(photoProducer, &photoOutput);
        EXPECT_EQ(intResult, 0);
        ASSERT_NE(photoOutput, nullptr);

        sptr<VideoOutput> videoOutput = nullptr;
        intResult = cameraManager_->CreateVideoOutputWithoutProfile(Surface::CreateSurfaceAsConsumer(), &videoOutput);
        EXPECT_EQ(intResult, 0);
        ASSERT_NE(videoOutput, nullptr);

        intResult = videoSession->BeginConfig();
        EXPECT_EQ(intResult, 0);

        intResult = videoSession->AddInput(input);
        EXPECT_EQ(intResult, 0);

        sptr<CaptureOutput> previewOutputCaptureUpper = previewOutput;
        intResult = videoSession->AddOutput(previewOutputCaptureUpper);
        EXPECT_EQ(intResult, 0);
        sptr<CaptureOutput> photoOutputCaptureUpper = photoOutput;
        intResult = videoSession->AddOutput(photoOutputCaptureUpper);
        EXPECT_EQ(intResult, 0);
        sptr<CaptureOutput> videoOutputCaptureUpper = videoOutput;
        intResult = videoSession->AddOutput(videoOutputCaptureUpper);
        EXPECT_EQ(intResult, 0);

        intResult = videoSession->CommitConfig();
        EXPECT_EQ(intResult, 0);

        intResult = videoSession->Start();
        EXPECT_EQ(intResult, 0);

        intResult = videoSession->Stop();
        EXPECT_EQ(intResult, 0);

        intResult = videoSession->BeginConfig();
        EXPECT_EQ(intResult, 0);

        intResult = videoSession->RemoveInput(input);
        EXPECT_EQ(intResult, 0);

        intResult = videoSession->Release();
        EXPECT_EQ(intResult, 0);
    }
}

/*
 * Feature: Framework
 * Function: Test VideoSession preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test preconfig VideoSession all config.
 */
HWTEST_F(CameraVideoSessionUnitTest, video_session_unittest_001, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput>&)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    EXPECT_EQ(camInput->GetCameraDevice()->Open(), 0);

    sptr<HCameraHostManager> cameraHostManager = new(std::nothrow) HCameraHostManager(nullptr);
    sptr<HCameraService> cameraService =  new(std::nothrow) HCameraService(cameraHostManager);
    ASSERT_NE(cameraService, nullptr);

    sptr<ICameraServiceCallback> callback = new (std::nothrow) CameraStatusServiceCallback(cameraManager_);
    ASSERT_NE(callback, nullptr);
    int32_t intResult = cameraService->SetCameraCallback(callback);
    EXPECT_EQ(intResult, 0);

    sptr<ICameraDeviceService> deviceObj = camInput->GetCameraDevice();
    ASSERT_NE(deviceObj, nullptr);

    std::vector<PreconfigType> preconfigTypes = { PRECONFIG_720P, PRECONFIG_1080P, PRECONFIG_4K,
        PRECONFIG_HIGH_QUALITY };
    std::vector<ProfileSizeRatio> profileSizeRatios = { UNSPECIFIED, RATIO_1_1, RATIO_4_3, RATIO_16_9 };
    for (auto& preconfigType : preconfigTypes) {
        for (auto& profileSizeRatio : profileSizeRatios) {
            TestVideoSessionPreconfig(input, preconfigType, profileSizeRatio);
        }
    }
    input->Close();
}

/*
 * Feature: Framework
 * Function: Test VideoSession callback normal branches
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test VideoSession callback normal branches
 */
HWTEST_F(CameraVideoSessionUnitTest, video_session_unittest_002, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput>&)input;
    camInput->GetCameraDevice()->Open();

    TestVideoSessionCallback();
    
    input->Close();
}

/*
 * Feature: Framework
 * Function: Test VideoSession callback abnormal branches
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test VideoSession callback while metadata is nullptr
 */
HWTEST_F(CameraVideoSessionUnitTest, video_session_unittest_003, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput>&)input;
    camInput->GetCameraDevice()->Open();

    FocusTrackingMode mode = FOCUS_TRACKING_MODE_AUTO;
    Rect region = {0.0, 0.0, 0.0, 0.0};

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession(SceneMode::VIDEO);
    ASSERT_NE(session, nullptr);
    sptr<VideoSession> videoSession = static_cast<VideoSession*>(session.GetRefPtr());
    ASSERT_NE(videoSession, nullptr);

    bool ret = videoSession->ProcessFocusTrackingModeInfo(nullptr, mode);
    EXPECT_FALSE(ret);
    ret = videoSession->ProcessRectInfo(nullptr, region);
    EXPECT_FALSE(ret);
    videoSession->ProcessFocusTrackingInfo(nullptr);
    
    input->Close();
}

/*
 * Feature: Framework
 * Function: Test VideoSession callback normal branches
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test VideoSession callback normal branches while metadata have ability
 */
HWTEST_F(CameraVideoSessionUnitTest, video_session_unittest_004, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput>&)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession(SceneMode::VIDEO);
    ASSERT_NE(session, nullptr);
    sptr<VideoSession> videoSession = static_cast<VideoSession*>(session.GetRefPtr());
    ASSERT_NE(videoSession, nullptr);

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras[0]->GetMetadata();
    ASSERT_NE(metadata, nullptr);
    OHOS::Camera::DeleteCameraMetadataItem(metadata->get(), OHOS_CONTROL_FOCUS_TRACKING_MODE);
    uint8_t testMode = OHOS_CAMERA_FOCUS_TRACKING_AUTO;
    FocusTrackingMode mode = FOCUS_TRACKING_MODE_AUTO;
    metadata->addEntry(OHOS_CONTROL_FOCUS_TRACKING_MODE, &testMode, 1);
    bool ret = videoSession->ProcessFocusTrackingModeInfo(metadata, mode);
    EXPECT_TRUE(ret);

    int32_t data[4] = {0, 1, 2, 3};
    Rect region = {0.0, 0.0, 0.0, 0.0};
    OHOS::Camera::DeleteCameraMetadataItem(metadata->get(), OHOS_ABILITY_FOCUS_TRACKING_REGION);
    metadata->addEntry(OHOS_ABILITY_FOCUS_TRACKING_REGION, &data, sizeof(data) / sizeof(data[0]));
    ret = videoSession->ProcessRectInfo(metadata, region);
    EXPECT_TRUE(ret);

    std::shared_ptr<FocusTrackingCallback> focusTrackingInfoCallback = std::make_shared<TestFocusTrackingCallback>();
    ASSERT_NE(focusTrackingInfoCallback, nullptr);
    videoSession->SetFocusTrackingInfoCallback(focusTrackingInfoCallback);
    ASSERT_NE(videoSession->focusTrackingInfoCallback_, nullptr);
    videoSession->ProcessFocusTrackingInfo(metadata);

    input->Close();
}

}
}