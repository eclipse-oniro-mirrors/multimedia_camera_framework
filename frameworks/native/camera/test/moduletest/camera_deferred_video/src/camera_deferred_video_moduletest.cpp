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

#include "camera_deferred_video_moduletest.h"

#include "accesstoken_kit.h"
#include "camera_log.h"
#include "deferred_proc_session/deferred_video_proc_session.h"
#include "hap_token_info.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
constexpr int32_t DEFERRED_VIDEO_NOT_ENABLED = 0;
constexpr int32_t DEFERRED_VIDEO_ENABLED = 1;
void CameraDeferredVideoModuleTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraDeferredVideoModuleTest::SetUpTestCase started!");
    SetNativeToken();
}

void CameraDeferredVideoModuleTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraDeferredVideoModuleTest::TearDownTestCase started!");
}

void CameraDeferredVideoModuleTest::SetUp()
{
    MEDIA_DEBUG_LOG("CameraDeferredVideoModuleTest::SetUp started!");
    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);

    cameras_ = cameraManager_->GetSupportedCameras();
    CHECK_ERROR_RETURN_LOG(cameras_.empty(), "GetSupportedCameras empty");

    std::vector<SceneMode> sceneModes = GetSupportedSceneModes(cameras_[0]);
    auto it = std::find(sceneModes.begin(), sceneModes.end(), SceneMode::VIDEO);
    CHECK_ERROR_RETURN_LOG(it == sceneModes.end(), "SceneMode::VIDEO not supported");

    outputCapability_ = cameraManager_->GetSupportedOutputCapability(cameras_[0], SceneMode::VIDEO);
    ASSERT_NE(outputCapability_, nullptr);
    previewProfiles_ = outputCapability_->GetPreviewProfiles();
    videoProfiles_ = outputCapability_->GetVideoProfiles();
    CHECK_ERROR_RETURN_LOG(previewProfiles_.empty() || videoProfiles_.empty(),
        "GetPreviewProfiles or GetVideoProfiles empty");

    FilterPreviewProfiles(previewProfiles_);
    previewOutput_ = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput_, nullptr);
    cameraInput_ = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(cameraInput_, nullptr);
    EXPECT_EQ(cameraInput_->Open(), CameraErrorCode::SUCCESS);
}

void CameraDeferredVideoModuleTest::TearDown()
{
    MEDIA_DEBUG_LOG("CameraDeferredVideoModuleTest::TearDown started!");
    if (captureSession_) {
        if (cameraInput_) {
            EXPECT_EQ(cameraInput_->Release(), CameraErrorCode::SUCCESS);
        }
        if (previewOutput_) {
            EXPECT_EQ(previewOutput_->Release(), CameraErrorCode::SUCCESS);
        }
        if (videoOutput_) {
            EXPECT_EQ(videoOutput_->Release(), CameraErrorCode::SUCCESS);
        }
        EXPECT_EQ(captureSession_->Release(), CameraErrorCode::SUCCESS);
    }

    cameras_.clear();
    previewProfiles_.clear();
    videoProfiles_.clear();
    outputCapability_.clear();
    previewOutput_.clear();
    videoOutput_.clear();
    cameraInput_.clear();
    captureSession_.clear();
    cameraManager_.clear();
}

void CameraDeferredVideoModuleTest::SetNativeToken()
{
    uint64_t tokenId;
    const char* perms[2];
    perms[0] = "ohos.permission.DISTRIBUTED_DATASYNC";
    perms[1] = "ohos.permission.CAMERA";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .aclsNum = 0,
        .dcaps = NULL,
        .perms = perms,
        .acls = NULL,
        .processName = "native_camera_mst",
        .aplStr = "system_basic",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

std::vector<SceneMode> CameraDeferredVideoModuleTest::GetSupportedSceneModes(sptr<CameraDevice>& camera)
{
    std::vector<SceneMode> sceneModes = {};
    sceneModes = cameraManager_->GetSupportedModes(cameras_[0]);
    if (sceneModes.empty()) {
        sceneModes.emplace_back(SceneMode::CAPTURE);
        sceneModes.emplace_back(SceneMode::VIDEO);
    }
    return sceneModes;
}

sptr<PreviewOutput> CameraDeferredVideoModuleTest::CreatePreviewOutput(Profile& profile)
{
    sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
    Size previewSize = profile.GetSize();
    previewSurface->SetUserData(CameraManager::surfaceFormat, std::to_string(profile.GetCameraFormat()));
    previewSurface->SetDefaultWidthAndHeight(previewSize.width, previewSize.height);

    sptr<IBufferProducer> bp = previewSurface->GetProducer();
    sptr<Surface> pSurface = Surface::CreateSurfaceAsProducer(bp);

    sptr<PreviewOutput> previewOutput = nullptr;
    previewOutput = cameraManager_->CreatePreviewOutput(profile, pSurface);
    return previewOutput;
}

sptr<VideoOutput> CameraDeferredVideoModuleTest::CreateVideoOutput(VideoProfile& videoProfile)
{
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> videoProducer = surface->GetProducer();
    sptr<Surface> videoSurface = Surface::CreateSurfaceAsProducer(videoProducer);
    sptr<VideoOutput> videoOutput = nullptr;
    videoOutput = cameraManager_->CreateVideoOutput(videoProfile, videoSurface);
    return videoOutput;
}

void CameraDeferredVideoModuleTest::FilterPreviewProfiles(std::vector<Profile>& previewProfiles)
{
    std::vector<Profile>::iterator itr = previewProfiles.begin();
    while (itr != previewProfiles.end()) {
        Profile profile = *itr;
        if ((profile.size_.width == PRVIEW_WIDTH_176 && profile.size_.height == PRVIEW_HEIGHT_144) ||
            (profile.size_.width == PRVIEW_WIDTH_480 && profile.size_.height == PRVIEW_HEIGHT_480) ||
            (profile.size_.width == PRVIEW_WIDTH_640 && profile.size_.height == PRVIEW_HEIGHT_640) ||
            (profile.size_.width == PRVIEW_WIDTH_4096 && profile.size_.height == PRVIEW_HEIGHT_3072) ||
            (profile.size_.width == PRVIEW_WIDTH_4160 && profile.size_.height == PRVIEW_HEIGHT_3120) ||
            (profile.size_.width == PRVIEW_WIDTH_8192 && profile.size_.height == PRVIEW_HEIGHT_6144)) {
            MEDIA_DEBUG_LOG("SetUp skip previewProfile width:%{public}d height:%{public}d",
                profile.size_.width, profile.size_.height);
            itr = previewProfiles.erase(itr);
        } else {
            ++itr;
        }
    }
}

void CameraDeferredVideoModuleTest::RegisterVideoStateCallback()
{
    videoStateCallback_ = make_shared<ModuleTestVideoStateCallback>();
    ASSERT_NE(videoStateCallback_, nullptr);
    if (videoOutput_) {
        videoOutput_->SetCallback(videoStateCallback_);
    }
}

void ModuleTestVideoStateCallback::OnFrameStarted() const
{
    MEDIA_INFO_LOG("OnFrameStarted is called");
}

void ModuleTestVideoStateCallback::OnFrameEnded(const int32_t frameCount) const
{
    MEDIA_INFO_LOG("OnFrameEnded is called");
}

void ModuleTestVideoStateCallback::OnError(const int32_t errorCode) const
{
    MEDIA_INFO_LOG("OnError is called");
}

void ModuleTestVideoStateCallback::OnDeferredVideoEnhancementInfo(const CaptureEndedInfoExt captureEndedInfo) const
{
    MEDIA_INFO_LOG("OnDeferredVideoEnhancementInfo is called");
}

/*
 * Feature: Framework
 * Function: Test the normal process of enabling deferred video.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the normal process of enabling deferred video.
 */
HWTEST_F(CameraDeferredVideoModuleTest, camera_deferred_video_moduletest_001, TestSize.Level0)
{
    videoOutput_ = CreateVideoOutput(videoProfiles_[0]);
    ASSERT_NE(videoOutput_, nullptr);

    RegisterVideoStateCallback();

    captureSession_ = cameraManager_->CreateCaptureSession(SceneMode::VIDEO);
    ASSERT_NE(captureSession_, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), CameraErrorCode::SUCCESS);
    EXPECT_EQ(captureSession_->AddInput(cameraInput_), CameraErrorCode::SUCCESS);
    sptr<CaptureOutput> previewOutput = static_cast<CaptureOutput*>(previewOutput_.GetRefPtr());
    EXPECT_EQ(captureSession_->AddOutput(previewOutput), CameraErrorCode::SUCCESS);
    sptr<CaptureOutput> videoOutput = static_cast<CaptureOutput*>(videoOutput_.GetRefPtr());
    EXPECT_EQ(captureSession_->AddOutput(videoOutput), CameraErrorCode::SUCCESS);

    CHECK_ERROR_RETURN_LOG(videoOutput_->IsAutoDeferredVideoEnhancementSupported() == 0,
        "deferred video not supported");
    EXPECT_EQ(videoOutput_->IsAutoDeferredVideoEnhancementEnabled(), DEFERRED_VIDEO_NOT_ENABLED);
    EXPECT_EQ(videoOutput_->EnableAutoDeferredVideoEnhancement(true), CameraErrorCode::SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), CameraErrorCode::SUCCESS);
    EXPECT_EQ(captureSession_->Start(), CameraErrorCode::SUCCESS);
    EXPECT_EQ(videoOutput_->IsAutoDeferredVideoEnhancementEnabled(), DEFERRED_VIDEO_ENABLED);
    EXPECT_EQ(videoOutput_->Start(), CameraErrorCode::SUCCESS);
    EXPECT_EQ(videoOutput_->Stop(), CameraErrorCode::SUCCESS);
    EXPECT_EQ(captureSession_->Stop(), CameraErrorCode::SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test the normal process of disabling deferred video.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the normal process of disabling deferred video.
 */
HWTEST_F(CameraDeferredVideoModuleTest, camera_deferred_video_moduletest_002, TestSize.Level0)
{
    videoOutput_ = CreateVideoOutput(videoProfiles_[0]);
    ASSERT_NE(videoOutput_, nullptr);

    RegisterVideoStateCallback();

    captureSession_ = cameraManager_->CreateCaptureSession(SceneMode::VIDEO);
    ASSERT_NE(captureSession_, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), CameraErrorCode::SUCCESS);
    EXPECT_EQ(captureSession_->AddInput(cameraInput_), CameraErrorCode::SUCCESS);
    sptr<CaptureOutput> previewOutput = static_cast<CaptureOutput*>(previewOutput_.GetRefPtr());
    EXPECT_EQ(captureSession_->AddOutput(previewOutput), CameraErrorCode::SUCCESS);
    sptr<CaptureOutput> videoOutput = static_cast<CaptureOutput*>(videoOutput_.GetRefPtr());
    EXPECT_EQ(captureSession_->AddOutput(videoOutput), CameraErrorCode::SUCCESS);

    CHECK_ERROR_RETURN_LOG(videoOutput_->IsAutoDeferredVideoEnhancementSupported() == 0,
        "deferred video not supported");
    EXPECT_EQ(videoOutput_->IsAutoDeferredVideoEnhancementEnabled(), DEFERRED_VIDEO_NOT_ENABLED);
    EXPECT_EQ(videoOutput_->EnableAutoDeferredVideoEnhancement(true), CameraErrorCode::SUCCESS);
    EXPECT_EQ(videoOutput_->IsAutoDeferredVideoEnhancementEnabled(), DEFERRED_VIDEO_ENABLED);
    EXPECT_EQ(videoOutput_->EnableAutoDeferredVideoEnhancement(false), CameraErrorCode::SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), CameraErrorCode::SUCCESS);
    EXPECT_EQ(captureSession_->Start(), CameraErrorCode::SUCCESS);
    EXPECT_EQ(videoOutput_->IsAutoDeferredVideoEnhancementEnabled(), DEFERRED_VIDEO_NOT_ENABLED);
    EXPECT_EQ(captureSession_->Stop(), CameraErrorCode::SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test enabling deferred video without add video output.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test enabling deferred video without add video output.
 */
HWTEST_F(CameraDeferredVideoModuleTest, camera_deferred_video_moduletest_003, TestSize.Level0)
{
    videoOutput_ = CreateVideoOutput(videoProfiles_[0]);
    ASSERT_NE(videoOutput_, nullptr);

    RegisterVideoStateCallback();

    captureSession_ = cameraManager_->CreateCaptureSession(SceneMode::VIDEO);
    ASSERT_NE(captureSession_, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), CameraErrorCode::SUCCESS);
    EXPECT_EQ(captureSession_->AddInput(cameraInput_), CameraErrorCode::SUCCESS);
    sptr<CaptureOutput> previewOutput = static_cast<CaptureOutput*>(previewOutput_.GetRefPtr());
    EXPECT_EQ(captureSession_->AddOutput(previewOutput), CameraErrorCode::SUCCESS);

    EXPECT_EQ(videoOutput_->IsAutoDeferredVideoEnhancementSupported(), CameraErrorCode::SERVICE_FATL_ERROR);
    EXPECT_EQ(videoOutput_->IsAutoDeferredVideoEnhancementEnabled(), CameraErrorCode::SERVICE_FATL_ERROR);
    EXPECT_EQ(videoOutput_->EnableAutoDeferredVideoEnhancement(true), CameraErrorCode::SERVICE_FATL_ERROR);
    EXPECT_EQ(captureSession_->CommitConfig(), CameraErrorCode::SUCCESS);
    EXPECT_EQ(captureSession_->Start(), CameraErrorCode::SUCCESS);
    EXPECT_EQ(captureSession_->Stop(), CameraErrorCode::SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test enabling deferred video before add input.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test enabling deferred video before add input.
 */
HWTEST_F(CameraDeferredVideoModuleTest, camera_deferred_video_moduletest_004, TestSize.Level0)
{
    videoOutput_ = CreateVideoOutput(videoProfiles_[0]);
    ASSERT_NE(videoOutput_, nullptr);

    RegisterVideoStateCallback();

    captureSession_ = cameraManager_->CreateCaptureSession(SceneMode::VIDEO);
    ASSERT_NE(captureSession_, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), CameraErrorCode::SUCCESS);
    EXPECT_EQ(videoOutput_->IsAutoDeferredVideoEnhancementSupported(), CameraErrorCode::SERVICE_FATL_ERROR);
    EXPECT_EQ(videoOutput_->IsAutoDeferredVideoEnhancementEnabled(), CameraErrorCode::SERVICE_FATL_ERROR);
    EXPECT_EQ(videoOutput_->EnableAutoDeferredVideoEnhancement(true), CameraErrorCode::SERVICE_FATL_ERROR);

    EXPECT_EQ(captureSession_->AddInput(cameraInput_), CameraErrorCode::SUCCESS);
    sptr<CaptureOutput> previewOutput = static_cast<CaptureOutput*>(previewOutput_.GetRefPtr());
    EXPECT_EQ(captureSession_->AddOutput(previewOutput), CameraErrorCode::SUCCESS);
    sptr<CaptureOutput> videoOutput = static_cast<CaptureOutput*>(videoOutput_.GetRefPtr());
    EXPECT_EQ(captureSession_->AddOutput(videoOutput), CameraErrorCode::SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), CameraErrorCode::SUCCESS);
    EXPECT_EQ(captureSession_->Start(), CameraErrorCode::SUCCESS);
    EXPECT_EQ(captureSession_->Stop(), CameraErrorCode::SUCCESS);
}
} // CameraStandard
} // OHOS