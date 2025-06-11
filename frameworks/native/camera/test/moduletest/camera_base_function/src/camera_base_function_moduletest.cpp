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

#include "accesstoken_kit.h"
#include "camera_error_code.h"
#include "camera_log.h"
#include "camera_manager.h"
#include "camera_util.h"
#include "camera_base_function_moduletest.h"
#include "gtest/gtest.h"
#include "hap_token_info.h"
#include "nativetoken_kit.h"
#include "surface.h"
#include "system_ability_definition.h"
#include "test_common.h"
#include "token_setproc.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
void TestCameraMuteListener::OnCameraMute(bool muteMode) const
{
    MEDIA_INFO_LOG("TestCameraMuteListener::OnCameraMute called %{public}d", muteMode);
}
void TestTorchListener::OnTorchStatusChange(const TorchStatusInfo &torchStatusInfo) const
{
    MEDIA_INFO_LOG("TestTorchListener::OnTorchStatusChange called %{public}d %{public}d %{public}f",
        torchStatusInfo.isTorchAvailable, torchStatusInfo.isTorchActive, torchStatusInfo.torchLevel);
}
void TestFoldListener::OnFoldStatusChanged(const FoldStatusInfo &foldStatusInfo) const
{
    MEDIA_INFO_LOG("TestFoldListener::OnFoldStatusChanged called %{public}d", foldStatusInfo.foldStatus);
}
void TestSessionCallback::OnError(int32_t errorCode)
{
    MEDIA_INFO_LOG("TestSessionCallback::OnError called %{public}d", errorCode);
}
void TestExposureCallback::OnExposureState(ExposureState state)
{
    MEDIA_INFO_LOG("TestExposureCallback::OnExposureState called %{public}d", state);
}
void TestFocusCallback::OnFocusState(FocusState state)
{
    MEDIA_INFO_LOG("TestFocusCallback::OnFocusState callecd %{public}d", state);
}
void TestMacroStatusCallback::OnMacroStatusChanged(MacroStatus status)
{
    MEDIA_INFO_LOG("TestMacroStatusCallback::OnMacroStatusChanged called %{public}d", status);
}
void TestMoonCaptureBoostStatusCallback::OnMoonCaptureBoostStatusChanged(MoonCaptureBoostStatus status)
{
    MEDIA_INFO_LOG("TestMoonCaptureBoostStatusCallback::OnMoonCaptureBoostStatusChanged called %{public}d", status);
}
void TestFeatureDetectionStatusCallback::OnFeatureDetectionStatusChanged(SceneFeature feature,
    FeatureDetectionStatus status)
{
    MEDIA_INFO_LOG("TestFeatureDetectionStatusCallback::OnFeatureDetectionStatusChanged called %{public}d %{public}d",
        feature, status);
}
bool TestFeatureDetectionStatusCallback::IsFeatureSubscribed(SceneFeature feature)
{
    return true;
}
void TestSmoothZoomCallback::OnSmoothZoom(int32_t duration)
{
    MEDIA_INFO_LOG("TestSmoothZoomCallback::OnSmoothZoom called %{public}d", duration);
}
void TestARCallback::OnResult(const ARStatusInfo &arStatusInfo) const
{
    MEDIA_INFO_LOG("TestARCallback::OnResult called ");
}
void TestEffectSuggestionCallback::OnEffectSuggestionChange(EffectSuggestionType effectSuggestionType)
{
    MEDIA_INFO_LOG("TestEffectSuggestionCallback::OnEffectSuggestionChange called %{public}d", effectSuggestionType);
}
void TestLcdFlashStatusCallback::OnLcdFlashStatusChanged(LcdFlashStatusInfo lcdFlashStatusInfo)
{
    MEDIA_INFO_LOG("TestLcdFlashStatusCallback::OnLcdFlashStatusChanged called");
}
void TestAutoDeviceSwitchCallback::OnAutoDeviceSwitchStatusChange(bool isDeviceSwitched,
    bool isDeviceCapabilityChanged) const
{
    MEDIA_INFO_LOG("TestAutoDeviceSwitchCallback::OnAutoDeviceSwitchStatusChange called %{public}d %{public}d",
        isDeviceSwitched, isDeviceCapabilityChanged);
}
void TestMetadataStateCallback::OnError(int32_t errorCode) const
{
    MEDIA_INFO_LOG("TestMetadataStateCallback::OnError called %{public}d", errorCode);
}

void WAIT(uint32_t duration)
{
    std::this_thread::sleep_for(std::chrono::milliseconds(duration));
}

void CameraBaseFunctionModuleTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase start.");
    MEDIA_INFO_LOG("SetUpTestCase end.");
}

void CameraBaseFunctionModuleTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase start.");
    MEDIA_INFO_LOG("TearDownTestCase end.");
}

void CameraBaseFunctionModuleTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp start.");
    SetNativeToken();

    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);
    cameraDevices_ = cameraManager_->GetSupportedCameras();
    ASSERT_TRUE(!cameraDevices_.empty());
    cameraInput_ = cameraManager_->CreateCameraInput(cameraDevices_[deviceBackIndex]);
    ASSERT_NE(cameraInput_, nullptr);
    captureSession_ = cameraManager_->CreateCaptureSession();
    ASSERT_NE(captureSession_, nullptr);

    EXPECT_EQ(cameraInput_->Open(), SUCCESS);
    UpdateCameraOutputCapability(deviceBackIndex);

    MEDIA_INFO_LOG("SetUp end.");
}

void CameraBaseFunctionModuleTest::TearDown()
{
    MEDIA_INFO_LOG("TearDown start.");

    cameraDevices_.clear();
    photoProfiles_.clear();
    previewProfiles_.clear();
    videoProfiles_.clear();
    depthProfiles_.clear();
    metadataObjectTypes_.clear();

    if (cameraInput_) {
        EXPECT_EQ(cameraInput_->Release(), SUCCESS);
        cameraInput_ = nullptr;
    }
    if (captureSession_) {
        EXPECT_EQ(captureSession_->Release(), SUCCESS);
        captureSession_ = nullptr;
    }

    MEDIA_INFO_LOG("TearDown end.");
}

void CameraBaseFunctionModuleTest::SetNativeToken()
{
    uint64_t tokenId;
    const char* perms[0];
    perms[0] = "ohos.permission.CAMERA";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 1,
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

void CameraBaseFunctionModuleTest::UpdateCameraOutputCapability(int32_t index, int32_t modeName)
{
    ASSERT_NE(cameraManager_, nullptr);
    ASSERT_TRUE(!cameraDevices_.empty());

    sptr<CameraOutputCapability> outputCapability_ = cameraManager_->GetSupportedOutputCapability(
        cameraDevices_[index], modeName);
    ASSERT_NE(outputCapability_, nullptr);

    previewProfiles_ = outputCapability_->GetPreviewProfiles();
    ASSERT_TRUE(!previewProfiles_.empty());
    FilterPreviewProfiles(previewProfiles_);
    photoProfiles_ = outputCapability_->GetPhotoProfiles();
    ASSERT_TRUE(!photoProfiles_.empty());
    videoProfiles_ = outputCapability_->GetVideoProfiles();
    ASSERT_TRUE(!videoProfiles_.empty());
    depthProfiles_ = outputCapability_->GetDepthProfiles();
    metadataObjectTypes_ = outputCapability_->GetSupportedMetadataObjectType();

    for (auto previewProfile : previewProfiles_) {
        MEDIA_DEBUG_LOG("module test preview profile format:%{public}d, w:%{public}d , h:%{public}d",
            previewProfile.GetCameraFormat(), previewProfile.GetSize().width, previewProfile.GetSize().height);
    }
    for (auto photoProfile : photoProfiles_) {
        MEDIA_DEBUG_LOG("module test photo profile format:%{public}d, w:%{public}d , h:%{public}d",
            photoProfile.GetCameraFormat(), photoProfile.GetSize().width, photoProfile.GetSize().height);
    }
    for (auto videoProfile : videoProfiles_) {
        MEDIA_DEBUG_LOG("module test video profile format:%{public}d, w:%{public}d , h:%{public}d",
            videoProfile.GetCameraFormat(), videoProfile.GetSize().width, videoProfile.GetSize().height);
    }
}

void CameraBaseFunctionModuleTest::FilterPreviewProfiles(std::vector<Profile>& previewProfiles)
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

sptr<PreviewOutput> CameraBaseFunctionModuleTest::CreatePreviewOutput(Profile &previewProfile)
{
    MEDIA_INFO_LOG("CreatePreviewOutput preview profile format:%{public}d, w:%{public}d , h:%{public}d",
        previewProfile.GetCameraFormat(), previewProfile.GetSize().width, previewProfile.GetSize().height);

    sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
    sptr<SurfaceListener> listener = new SurfaceListener("Preview", SurfaceType::PREVIEW, previewFd_, previewSurface);
    previewSurface->RegisterConsumerListener((sptr<IBufferConsumerListener>&)listener);
    previewSurface->SetUserData(CameraManager::surfaceFormat, std::to_string(previewProfile.GetCameraFormat()));
    previewSurface->SetDefaultWidthAndHeight(previewProfile.GetSize().width, previewProfile.GetSize().height);

    sptr<IBufferProducer> bp = previewSurface->GetProducer();
    sptr<Surface> pSurface = Surface::CreateSurfaceAsProducer(bp);

    return cameraManager_->CreatePreviewOutput(previewProfile, pSurface);
}

sptr<PhotoOutput> CameraBaseFunctionModuleTest::CreatePhotoOutput(Profile &photoProfile)
{
    MEDIA_INFO_LOG("CreatePhotoOutput photo profile format:%{public}d, w:%{public}d , h:%{public}d",
        photoProfile.GetCameraFormat(), photoProfile.GetSize().width, photoProfile.GetSize().height);

    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    sptr<IBufferProducer> bp = photoSurface->GetProducer();

    return cameraManager_->CreatePhotoOutput(photoProfile, bp);
}

sptr<VideoOutput> CameraBaseFunctionModuleTest::CreateVideoOutput(VideoProfile &videoProfile)
{
    MEDIA_INFO_LOG("CreateVideoOutput video profile format:%{public}d, w:%{public}d , h:%{public}d",
        videoProfile.GetCameraFormat(), videoProfile.GetSize().width, videoProfile.GetSize().height);

    sptr<IConsumerSurface> videoSurface = IConsumerSurface::Create();
    sptr<SurfaceListener> listener = new SurfaceListener("Video", SurfaceType::VIDEO, videoFd_, videoSurface);
    videoSurface->RegisterConsumerListener((sptr<IBufferConsumerListener>&)listener);
    videoSurface->SetUserData(CameraManager::surfaceFormat, std::to_string(videoProfile.GetCameraFormat()));
    videoSurface->SetDefaultWidthAndHeight(videoProfile.GetSize().width, videoProfile.GetSize().height);

    sptr<IBufferProducer> bp = videoSurface->GetProducer();
    sptr<Surface> pSurface = Surface::CreateSurfaceAsProducer(bp);

    return cameraManager_->CreateVideoOutput(videoProfile, pSurface);
}

void CameraBaseFunctionModuleTest::CreateAndConfigureDefaultCaptureOutput(sptr<PhotoOutput> &photoOutput,
    sptr<VideoOutput> &videoOutput)
{
    ASSERT_NE(captureSession_, nullptr);

    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    photoOutput = CreatePhotoOutput(photoProfiles_[0]);
    ASSERT_NE(photoOutput, nullptr);
    videoOutput = CreateVideoOutput(videoProfiles_[0]);
    ASSERT_NE(videoOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)photoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)videoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);
}

void CameraBaseFunctionModuleTest::CreateAndConfigureDefaultCaptureOutput(sptr<PhotoOutput> &photoOutput)
{
    ASSERT_NE(captureSession_, nullptr);

    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    photoOutput = CreatePhotoOutput(photoProfiles_[0]);
    ASSERT_NE(photoOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)photoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);
}

void CameraBaseFunctionModuleTest::StartDefaultCaptureOutput(sptr<PhotoOutput> photoOutput,
    sptr<VideoOutput> videoOutput)
{
    ASSERT_NE(captureSession_, nullptr);
    ASSERT_NE(photoOutput, nullptr);
    ASSERT_NE(videoOutput, nullptr);

    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    EXPECT_EQ(photoOutput->Capture(), SUCCESS);
    WAIT(DURATION_AFTER_CAPTURE);
    EXPECT_EQ(videoOutput->Start(), SUCCESS);
    WAIT(DURATION_DURING_RECORDING);
    EXPECT_EQ(videoOutput->Stop(), SUCCESS);
    WAIT(DURATION_AFTER_RECORDING);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);
}

void CameraBaseFunctionModuleTest::StartDefaultCaptureOutput(sptr<PhotoOutput> photoOutput)
{
    ASSERT_NE(captureSession_, nullptr);
    ASSERT_NE(photoOutput, nullptr);

    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    EXPECT_EQ(photoOutput->Capture(), SUCCESS);
    WAIT(DURATION_AFTER_CAPTURE);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test the camera's ability to take multiple photos.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the captureSession by adding previewOutput and photoOutput.
 * PreviewOutput and photoOutput can be added normally, and the function of taking multiple photos is normal.
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_001, TestSize.Level0)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<PhotoOutput> photoOutput = CreatePhotoOutput(photoProfiles_[0]);
    ASSERT_NE(photoOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)photoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);

    EXPECT_EQ(photoOutput->Capture(), SUCCESS);
    WAIT(DURATION_AFTER_CAPTURE);
    EXPECT_EQ(photoOutput->CancelCapture(), SUCCESS);

    EXPECT_EQ(captureSession_->Stop(), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test the camera's ability to record multiple times.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the captureSession by adding previewOutput and videoOutput.
 * PreviewOutput and videoOutput can be added normally, and the multiple recording function is normal.
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_002, TestSize.Level0)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<VideoOutput> videoOutput = CreateVideoOutput(videoProfiles_[0]);
    ASSERT_NE(videoOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)videoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);

    EXPECT_EQ(videoOutput->Start(), SUCCESS);
    WAIT(DURATION_DURING_RECORDING);
    EXPECT_EQ(videoOutput->Stop(), SUCCESS);
    WAIT(DURATION_AFTER_RECORDING);

    EXPECT_EQ(videoOutput->Start(), SUCCESS);
    WAIT(DURATION_DURING_RECORDING);
    EXPECT_EQ(videoOutput->Pause(), SUCCESS);
    EXPECT_EQ(videoOutput->Resume(), SUCCESS);
    WAIT(DURATION_DURING_RECORDING);
    EXPECT_EQ(videoOutput->Stop(), SUCCESS);
    WAIT(DURATION_AFTER_RECORDING);

    EXPECT_EQ(captureSession_->Stop(), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test the camera's ability to switch cameras when taking photos.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureSession by adding two different cameraInputs,
 * both cameraInputs can be added normally, and taking photos is normal before and after switching cameras.
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_003, TestSize.Level0)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<PhotoOutput> photoOutput = CreatePhotoOutput(photoProfiles_[0]);
    ASSERT_NE(photoOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)photoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    EXPECT_EQ(photoOutput->Capture(), SUCCESS);
    WAIT(DURATION_AFTER_CAPTURE);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);

    if (cameraDevices_.size() <= 1) {
        MEDIA_ERR_LOG("The current device only has a camera and cannot switch cameras");
        GTEST_SKIP();
    }
    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->RemoveInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->RemoveOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->RemoveOutput((sptr<CaptureOutput>&)photoOutput), SUCCESS);
    EXPECT_EQ(cameraInput_->Release(), SUCCESS);
    cameraInput_ = nullptr;
    WAIT(DURATION_AFTER_DEVICE_CLOSE);

    sptr<CameraInput> otherCameraInput = cameraManager_->CreateCameraInput(cameraDevices_[deviceFrontIndex]);
    ASSERT_NE(otherCameraInput, nullptr);
    EXPECT_EQ(otherCameraInput->Open(), SUCCESS);
    UpdateCameraOutputCapability(deviceFrontIndex);

    sptr<PreviewOutput> otherPreviewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(otherPreviewOutput, nullptr);
    sptr<PhotoOutput> otherPhotoOutput = CreatePhotoOutput(photoProfiles_[0]);
    ASSERT_NE(otherPhotoOutput, nullptr);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)otherCameraInput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)otherPreviewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)otherPhotoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    EXPECT_EQ(otherPhotoOutput->Capture(), SUCCESS);
    WAIT(DURATION_AFTER_CAPTURE);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);

    EXPECT_EQ(otherCameraInput->Release(), SUCCESS);
    WAIT(DURATION_AFTER_DEVICE_CLOSE);
}

/*
 * Feature: Camera base function
 * Function: Test the camera's ability to switch cameras when video recording.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureSession by adding two different cameraInputs,
 * both cameraInputs can be added normally, and video recording is normal before and after switching cameras.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_004, TestSize.Level0)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<VideoOutput> videoOutput = CreateVideoOutput(videoProfiles_[0]);
    ASSERT_NE(videoOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)videoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    EXPECT_EQ(videoOutput->Start(), SUCCESS);
    WAIT(DURATION_DURING_RECORDING);
    EXPECT_EQ(videoOutput->Stop(), SUCCESS);
    WAIT(DURATION_AFTER_RECORDING);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);

    if (cameraDevices_.size() <= 1) {
        MEDIA_ERR_LOG("The current device only has a camera and cannot switch cameras");
        GTEST_SKIP();
    }
    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->RemoveInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->RemoveOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->RemoveOutput((sptr<CaptureOutput>&)videoOutput), SUCCESS);
    EXPECT_EQ(cameraInput_->Release(), SUCCESS);
    cameraInput_ = nullptr;
    WAIT(DURATION_AFTER_DEVICE_CLOSE);

    sptr<CameraInput> otherCameraInput = cameraManager_->CreateCameraInput(cameraDevices_[deviceFrontIndex]);
    ASSERT_NE(otherCameraInput, nullptr);
    EXPECT_EQ(otherCameraInput->Open(), SUCCESS);
    UpdateCameraOutputCapability(deviceFrontIndex);

    sptr<PreviewOutput> otherPreviewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(otherPreviewOutput, nullptr);
    sptr<VideoOutput> otherVideoOutput = CreateVideoOutput(videoProfiles_[0]);
    ASSERT_NE(otherVideoOutput, nullptr);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)otherCameraInput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)otherPreviewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)otherVideoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    EXPECT_EQ(otherVideoOutput->Start(), SUCCESS);
    WAIT(DURATION_DURING_RECORDING);
    EXPECT_EQ(otherVideoOutput->Stop(), SUCCESS);
    WAIT(DURATION_AFTER_RECORDING);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);

    EXPECT_EQ(otherCameraInput->Release(), SUCCESS);
    WAIT(DURATION_AFTER_DEVICE_CLOSE);
}

/*
 * Feature: Camera base function
 * Function: Test the camera to switch from taking photos to recording.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: To test captureSession, first add cameraInput, preivewOutput and photoOutput for taking photos,
 * then remove photoOutput and add videoOutput for recording. The flow distribution is normal, and both photography
 * and recording are normal.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_005, TestSize.Level0)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<PhotoOutput> photoOutput = CreatePhotoOutput(photoProfiles_[0]);
    ASSERT_NE(photoOutput, nullptr);
    sptr<VideoOutput> videoOutput = CreateVideoOutput(videoProfiles_[0]);
    ASSERT_NE(videoOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)photoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    EXPECT_EQ(photoOutput->Capture(), SUCCESS);
    WAIT(DURATION_AFTER_CAPTURE);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->RemoveOutput((sptr<CaptureOutput>&)photoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)videoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    EXPECT_EQ(videoOutput->Start(), SUCCESS);
    WAIT(DURATION_DURING_RECORDING);
    EXPECT_EQ(videoOutput->Stop(), SUCCESS);
    WAIT(DURATION_AFTER_RECORDING);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test the camera to switch from recording to taking photos.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: To test captureSession, first add cameraInput, preivewOutput, and videoOutput for recording,
 * then remove videoOutput and add photoOutput for taking photos. The flow distribution is normal, and both recording
 * and taking photos are normal.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_006, TestSize.Level1)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<PhotoOutput> photoOutput = CreatePhotoOutput(photoProfiles_[0]);
    ASSERT_NE(photoOutput, nullptr);
    sptr<VideoOutput> videoOutput = CreateVideoOutput(videoProfiles_[0]);
    ASSERT_NE(videoOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)videoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    EXPECT_EQ(videoOutput->Start(), SUCCESS);
    WAIT(DURATION_DURING_RECORDING);
    EXPECT_EQ(videoOutput->Stop(), SUCCESS);
    WAIT(DURATION_AFTER_RECORDING);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->RemoveOutput((sptr<CaptureOutput>&)videoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)photoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    EXPECT_EQ(photoOutput->Capture(), SUCCESS);
    WAIT(DURATION_AFTER_CAPTURE);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test the camera's flow distribution in different session states.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureSession adding captureOutput is successful when session state is In-progress,
 * and adding captureOutput fail when session state is Init or Committed.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_007, TestSize.Level1)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);

    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), OPERATION_NOT_ALLOWED);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), OPERATION_NOT_ALLOWED);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), OPERATION_NOT_ALLOWED);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), OPERATION_NOT_ALLOWED);

    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test the camera's flow distribution without input.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Testing captureSession only adds previewOutput without adding cameraInput,
 * and the session fails when committing config.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_008, TestSize.Level1)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SERVICE_FATL_ERROR);
    EXPECT_EQ(captureSession_->CommitConfig(), SERVICE_FATL_ERROR);

    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test the camera's flow distribution without output.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Testing captureSession only adds cameraInput without adding captureOutput,
 * and the session fails when committing config.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_009, TestSize.Level1)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SERVICE_FATL_ERROR);

    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test the camera's flow distribution with multiple preview output streams.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the captureSession and add two previewoutputs. Both previewoutputs can be added normally,
 * and the camera preview is normal when two preview streams are enabled.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_010, TestSize.Level1)
{
    sptr<PreviewOutput> previewOutput1 = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput1, nullptr);
    sptr<PreviewOutput> previewOutput2 = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput2, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput1), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput2), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    EXPECT_EQ(previewOutput1->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    EXPECT_EQ(previewOutput1->Stop(), SUCCESS);

    EXPECT_EQ(previewOutput2->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    EXPECT_EQ(previewOutput2->Stop(), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test the camera's flow distribution with multiple photo output streams.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the captureSession by adding previewOutput and two photoOutput streams.
 * Service fatl error during session commit config.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_011, TestSize.Level1)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<PhotoOutput> photoOutput1 = CreatePhotoOutput(photoProfiles_[0]);
    ASSERT_NE(photoOutput1, nullptr);
    sptr<PhotoOutput> photoOutput2 = CreatePhotoOutput(photoProfiles_[0]);
    ASSERT_NE(photoOutput2, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)photoOutput1), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)photoOutput2), SUCCESS);

    captureSession_->CommitConfig();
    captureSession_->Start();
    WAIT(DURATION_AFTER_SESSION_START);
    photoOutput1->Capture();
    WAIT(DURATION_AFTER_CAPTURE);
    photoOutput2->Capture();
    WAIT(DURATION_AFTER_CAPTURE);
    captureSession_->Stop();
}

/*
 * Feature: Camera base function
 * Function: Test the camera's flow distribution with multiple video output streams.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the captureSession by adding previewOutput and two videoOutput streams.
 * Service fatl error during session commit config.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_012, TestSize.Level1)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<VideoOutput> videoOutput1 = CreateVideoOutput(videoProfiles_[0]);
    ASSERT_NE(videoOutput1, nullptr);
    sptr<VideoOutput> videoOutput2 = CreateVideoOutput(videoProfiles_[0]);
    ASSERT_NE(videoOutput2, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)videoOutput1), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)videoOutput2), SUCCESS);

    captureSession_->CommitConfig();
    captureSession_->Start();
    WAIT(DURATION_AFTER_SESSION_START);
    videoOutput1->Start();
    WAIT(DURATION_DURING_RECORDING);
    videoOutput1->Stop();
    videoOutput2->Start();
    WAIT(DURATION_DURING_RECORDING);
    videoOutput2->Stop();
    captureSession_->Stop();
}

/*
 * Feature: Camera base function
 * Function: Test the camera config metadata flow with stream start and stop is normal.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the captureSession by adding metadata output streams. Metadata output stream
 * starts and stops normally.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_013, TestSize.Level0)
{
    std::set<camera_face_detect_mode_t> metadataObjectTypes;
    captureSession_->SetCaptureMetadataObjectTypes(metadataObjectTypes);

    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<PhotoOutput> photoOutput = CreatePhotoOutput(photoProfiles_[0]);
    ASSERT_NE(photoOutput, nullptr);
    sptr<VideoOutput> videoOutput = CreateVideoOutput(videoProfiles_[0]);
    ASSERT_NE(videoOutput, nullptr);
    sptr<MetadataOutput> metadataOutput = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(metadataOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)photoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)videoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)metadataOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test the camera config metadata flow with query metadadta object type is normal.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the captureSession by adding metadata output streams. Metadata output stream
 * set callback and get metadata object types normally.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_014, TestSize.Level0)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<PhotoOutput> photoOutput = CreatePhotoOutput(photoProfiles_[0]);
    ASSERT_NE(photoOutput, nullptr);
    sptr<VideoOutput> videoOutput = CreateVideoOutput(videoProfiles_[0]);
    ASSERT_NE(videoOutput, nullptr);
    sptr<MetadataOutput> metadataOutput = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(metadataOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)photoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)videoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)metadataOutput), SUCCESS);
    auto stateCallback = std::make_shared<TestMetadataStateCallback>();
    ASSERT_NE(stateCallback, nullptr);
    metadataOutput->SetCallback(stateCallback);
    EXPECT_NE(metadataOutput->GetAppStateCallback(), nullptr);
    auto objectCallback = std::make_shared<TestMetadataOutputObjectCallback>("");
    ASSERT_NE(objectCallback, nullptr);
    metadataOutput->SetCallback(objectCallback);
    EXPECT_NE(metadataOutput->GetAppObjectCallback(), nullptr);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    std::vector<MetadataObjectType> objectTypes = metadataOutput->GetSupportedMetadataObjectTypes();
    if (!objectTypes.empty()) {
        metadataOutput->SetCapturingMetadataObjectTypes(objectTypes);

        objectTypes.clear();
        objectTypes.push_back(MetadataObjectType::HUMAN_BODY);
        EXPECT_EQ(metadataOutput->AddMetadataObjectTypes(objectTypes), INVALID_ARGUMENT);
        EXPECT_EQ(metadataOutput->RemoveMetadataObjectTypes(objectTypes), INVALID_ARGUMENT);
    }
    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);
}

/* *****cameraManager***** */
/*
 * Feature: Camera base function
 * Function: Test the camera status change callback.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the CameraMnager camera status callback function, register CameraMnagerCallback,
 * and print CameraStatus information correctly when the camera is turned on or off.
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_015, TestSize.Level1)
{
    std::shared_ptr<TestCameraMngerCallback> callback = std::make_shared<TestCameraMngerCallback>("");
    ASSERT_NE(callback, nullptr);
    cameraManager_->SetCallback(callback);
    ASSERT_GT(cameraManager_->GetCameraStatusListenerManager()->GetListenerCount(), 0);
}

/*
 * Feature: Camera base function
 * Function: Test the camera mute function.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the camera manager mute function, check if the device supports mute, register
 * the mute status callback and set the mute status when supported, the camera can be muted normally.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_016, TestSize.Level1)
{
    cameraManager_->ClearCameraDeviceListCache();
    if (cameraManager_->IsCameraMuteSupported()) {
        MEDIA_INFO_LOG("The camera mute function is supported");

        std::shared_ptr<TestCameraMuteListener> listener = std::make_shared<TestCameraMuteListener>();
        ASSERT_NE(listener, nullptr);
        cameraManager_->RegisterCameraMuteListener(listener);
        ASSERT_GT(cameraManager_->GetCameraMuteListenerManager()->GetListenerCount(), 0);

        cameraManager_->MuteCamera(!(cameraManager_->IsCameraMuted()));
    } else {
        MEDIA_ERR_LOG("The camera mute function is not supported");
    }
}

/*
 * Feature: Camera base function
 * Function: Test the camera prelaunch function.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the camera manager prelaunch function, check if the device supports prelaunch,
 * prelaunch the camera by cameraId and set configuration items when supported, the camera prelaunch abnormally for
 * opening device.
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_017, TestSize.Level0)
{
    if (cameraManager_->IsPrelaunchSupported(cameraInput_->GetCameraDeviceInfo())) {
        MEDIA_INFO_LOG("The camera prelaunch function is supported");

        std::string cameraId = cameraInput_->GetCameraId();
        ASSERT_NE(cameraId, "");
        int activeTime = 0;
        EffectParam effectParam = {0, 0, 0};
        EXPECT_EQ(cameraManager_->SetPrelaunchConfig(cameraId, RestoreParamTypeOhos::PERSISTENT_DEFAULT_PARAM_OHOS,
            activeTime, effectParam), SUCCESS);
        EXPECT_EQ(cameraManager_->PrelaunchCamera(), SERVICE_FATL_ERROR);
        EXPECT_EQ(cameraManager_->PreSwitchCamera(cameraId), SUCCESS);

        activeTime = 15;
        effectParam = {5, 0, 0};
        EXPECT_EQ(cameraManager_->SetPrelaunchConfig(cameraId, RestoreParamTypeOhos::NO_NEED_RESTORE_PARAM_OHOS,
            activeTime, effectParam), SUCCESS);

        cameraId = "";
        activeTime = 15;
        effectParam = {0, 0, 0};
        EXPECT_EQ(cameraManager_->SetPrelaunchConfig(cameraId, RestoreParamTypeOhos::TRANSIENT_ACTIVE_PARAM_OHOS,
            activeTime, effectParam), SERVICE_FATL_ERROR);
    } else {
        MEDIA_ERR_LOG("The camera prelaunch function is not supported");
    }
}

/*
 * Feature: Camera base function
 * Function: Test the camera torch function.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the camera manager torch function, check if the device supports torch,
 * register the torch status callback and switch the torch mode when supported, and the torch can
 * be turned on and off normally.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_018, TestSize.Level0)
{
    if (cameraManager_->IsTorchSupported()) {
        MEDIA_INFO_LOG("moduletest the camera torch function is supported");

        std::shared_ptr<TestTorchListener> listener = std::make_shared<TestTorchListener>();
        ASSERT_NE(listener, nullptr);
        cameraManager_->RegisterTorchListener(listener);
        ASSERT_GT(cameraManager_->GetTorchServiceListenerManager()->GetListenerCount(), 0);

        ASSERT_TRUE(cameraManager_->IsTorchModeSupported(TorchMode::TORCH_MODE_OFF));
        ASSERT_TRUE(cameraManager_->IsTorchModeSupported(TorchMode::TORCH_MODE_ON));
        ASSERT_TRUE(!(cameraManager_->IsTorchModeSupported(TorchMode::TORCH_MODE_AUTO)));

        TorchMode currentTorchMode = cameraManager_->GetTorchMode();
        sptr<CameraDevice> device = cameraDevices_[deviceBackIndex];
        ASSERT_NE(device, nullptr);
        if (device->GetPosition() == CAMERA_POSITION_BACK) {
            EXPECT_EQ(cameraManager_->SetTorchMode(TorchMode::TORCH_MODE_ON), OPERATION_NOT_ALLOWED);
            EXPECT_EQ(cameraManager_->SetTorchMode(TorchMode::TORCH_MODE_OFF), OPERATION_NOT_ALLOWED);
            EXPECT_EQ(cameraManager_->GetTorchMode(), currentTorchMode);
        } else if (device->GetPosition() == CAMERA_POSITION_FRONT) {
            EXPECT_EQ(cameraManager_->SetTorchMode(TorchMode::TORCH_MODE_ON), SUCCESS);
            EXPECT_EQ(cameraManager_->GetTorchMode(), TorchMode::TORCH_MODE_ON);
            EXPECT_EQ(cameraManager_->SetTorchMode(TorchMode::TORCH_MODE_OFF), SUCCESS);
            EXPECT_EQ(cameraManager_->GetTorchMode(), TorchMode::TORCH_MODE_OFF);
        }
    } else {
        MEDIA_ERR_LOG("moduletest the camera torch function is not supported");
    }
}

/*
 * Feature: Camera base function
 * Function: Test the camera folding state.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the folding status of camera manager and check if the camera supports folding
 * and folding status.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_019, TestSize.Level0)
{
    sptr<CameraDevice> device = cameraInput_->GetCameraDeviceInfo();
    ASSERT_NE(device, nullptr);
    CameraFoldScreenType foldScreenType = device->GetCameraFoldScreenType();
    MEDIA_INFO_LOG("moduletest device get camera fold screen type: %{public}d", foldScreenType);
    uint32_t supportFoldStatus = device->GetSupportedFoldStatus();
    MEDIA_INFO_LOG("moduletest device get supported fold status: %{public}d", supportFoldStatus);

    bool isFoldable = cameraManager_->GetIsFoldable();
    MEDIA_INFO_LOG("moduletest camera manager get isFoldable: %{public}d", isFoldable);
    FoldStatus foldStatus = cameraManager_->GetFoldStatus();
    MEDIA_INFO_LOG("moduletest camera manager get fold status: %{public}d", foldStatus);
    std::shared_ptr<TestFoldListener> listener = std::make_shared<TestFoldListener>();
    ASSERT_NE(listener, nullptr);
    cameraManager_->RegisterFoldListener(listener);
    ASSERT_GT(cameraManager_->GetFoldStatusListenerManager()->GetListenerCount(), 0);
}

/* *****captureSession***** */
/*
 * Feature: Camera base function
 * Function: Test the capture session with session call back.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the captureSession add session callback. The callback function is set and
 * queried normally, and OnError is called when an error occurs during the session callback process.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_020, TestSize.Level0)
{
    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    std::shared_ptr<TestSessionCallback> callback = std::make_shared<TestSessionCallback>();
    ASSERT_NE(callback, nullptr);
    captureSession_->SetCallback(callback);
    EXPECT_NE(captureSession_->GetApplicationCallback(), nullptr);

    StartDefaultCaptureOutput(photoOutput, videoOutput);
}

/*
 * Feature: Camera base function
 * Function: Test the capture session with exposure modes.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureSession check the exposure modes supported by the device and set and
 * query the exposure modes after completing the default allocation. Ensure that the camera function
 * is normal after the settings are completed.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_021, TestSize.Level0)
{
    ExposureMode exposureMode = EXPOSURE_MODE_UNSUPPORTED;
    EXPECT_EQ(captureSession_->GetExposureMode(), EXPOSURE_MODE_UNSUPPORTED);
    EXPECT_EQ(captureSession_->GetExposureMode(exposureMode), SESSION_NOT_CONFIG);
    EXPECT_EQ(captureSession_->SetExposureMode(exposureMode), SESSION_NOT_CONFIG);
    EXPECT_EQ(captureSession_->IsExposureModeSupported(exposureMode), false);

    bool isSupported = true;
    EXPECT_EQ(captureSession_->IsExposureModeSupported(exposureMode, isSupported), SESSION_NOT_CONFIG);
    EXPECT_EQ(captureSession_->GetSupportedExposureModes().empty(), true);
    std::vector<ExposureMode> exposureModes;
    EXPECT_EQ(captureSession_->GetSupportedExposureModes(exposureModes), SESSION_NOT_CONFIG);

    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    EXPECT_EQ(captureSession_->GetSupportedExposureModes(exposureModes), SUCCESS);
    ASSERT_TRUE(!exposureModes.empty());
    for (auto mode : exposureModes) {
        ASSERT_TRUE(captureSession_->IsExposureModeSupported(mode));
    }
    captureSession_->LockForControl();
    EXPECT_EQ(captureSession_->SetExposureMode(ExposureMode::EXPOSURE_MODE_AUTO), SUCCESS);
    captureSession_->UnlockForControl();
    EXPECT_EQ(captureSession_->GetExposureMode(), ExposureMode::EXPOSURE_MODE_AUTO);

    StartDefaultCaptureOutput(photoOutput, videoOutput);
    EXPECT_EQ(cameraInput_->Release(), SUCCESS);
    cameraInput_ = nullptr;

    EXPECT_EQ(captureSession_->GetSupportedExposureModes().empty(), true);
    EXPECT_EQ(captureSession_->GetSupportedExposureModes(exposureModes), SUCCESS);
    EXPECT_EQ(captureSession_->GetExposureMode(), EXPOSURE_MODE_UNSUPPORTED);
    EXPECT_EQ(captureSession_->GetExposureMode(exposureMode), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test the capture session with metering points.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureSession set and query metering points after completing the default
 * allocation. Ensure that the camera function is normal after the settings are completed.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_022, TestSize.Level1)
{
    Point point = captureSession_->GetMeteringPoint();
    EXPECT_EQ(point.x, 0);
    EXPECT_EQ(point.y, 0);
    EXPECT_EQ(captureSession_->SetMeteringPoint(point), SESSION_NOT_CONFIG);
    EXPECT_EQ(captureSession_->GetMeteringPoint(point), SESSION_NOT_CONFIG);

    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    point = {1.0, 1.0};
    captureSession_->LockForControl();
    EXPECT_EQ(captureSession_->SetMeteringPoint(point), SUCCESS);
    captureSession_->UnlockForControl();

    Point otherPoint = {0.0, 0.0};
    EXPECT_EQ(captureSession_->GetMeteringPoint(otherPoint), SUCCESS);
    EXPECT_EQ(otherPoint.x, point.x);
    EXPECT_EQ(otherPoint.y, point.y);

    StartDefaultCaptureOutput(photoOutput, videoOutput);
    EXPECT_EQ(cameraInput_->Release(), SUCCESS);
    cameraInput_ = nullptr;

    EXPECT_EQ(captureSession_->GetMeteringPoint().x, 0);
    EXPECT_EQ(captureSession_->GetMeteringPoint().y, 0);

    EXPECT_EQ(captureSession_->GetMeteringPoint(point), SUCCESS);
    captureSession_->LockForControl();
    EXPECT_EQ(captureSession_->SetMeteringPoint(point), SUCCESS);
    captureSession_->UnlockForControl();
}

/*
 * Feature: Camera base function
 * Function: Test the capture session with exposure compensation value.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureSession query the camera exposure compensation value range and set
 * and query the exposure compensation value after completing the default allocation. Ensure that
 * the camera function is normal after the settings are completed.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_023, TestSize.Level0)
{
    float exposureValue = 0.0;
    EXPECT_EQ(captureSession_->GetExposureValue(), 0);
    EXPECT_EQ(captureSession_->GetExposureValue(exposureValue), SESSION_NOT_CONFIG);
    EXPECT_EQ(captureSession_->SetExposureBias(exposureValue), SESSION_NOT_CONFIG);

    std::vector<float> ranges;
    EXPECT_EQ(captureSession_->GetExposureBiasRange().empty(), true);
    EXPECT_EQ(captureSession_->GetExposureBiasRange(ranges), SESSION_NOT_CONFIG);

    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    EXPECT_EQ(captureSession_->GetExposureBiasRange(ranges), SUCCESS);

    captureSession_->LockForControl();
    EXPECT_EQ(captureSession_->SetExposureBias(ranges[0]), SUCCESS);
    captureSession_->UnlockForControl();
    EXPECT_EQ(captureSession_->GetExposureValue(), ranges[0]);

    captureSession_->LockForControl();
    EXPECT_EQ(captureSession_->SetExposureBias(ranges[1]), SUCCESS);
    captureSession_->UnlockForControl();
    EXPECT_EQ(captureSession_->GetExposureValue(), ranges[1]);

    StartDefaultCaptureOutput(photoOutput, videoOutput);
    EXPECT_EQ(cameraInput_->Release(), SUCCESS);
    cameraInput_ = nullptr;

    EXPECT_EQ(captureSession_->GetExposureBiasRange().empty(), true);
    EXPECT_EQ(captureSession_->GetExposureBiasRange(ranges), SUCCESS);
    EXPECT_EQ(captureSession_->GetExposureValue(), 0);
    EXPECT_EQ(captureSession_->GetExposureValue(exposureValue), SUCCESS);
    captureSession_->LockForControl();
    EXPECT_EQ(captureSession_->SetExposureBias(exposureValue), OPERATION_NOT_ALLOWED);
    captureSession_->UnlockForControl();
}

/*
 * Feature: Camera base function
 * Function: Test the capture session with auto focus mode.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureSession check the autofocus mode supported by the device and set and
 * query the autofocus mode after completing the default allocation. Ensure that the photography
 * function is normal after the settings are completed.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_024, TestSize.Level0)
{
    FocusMode focusMode = FOCUS_MODE_MANUAL;
    EXPECT_EQ(captureSession_->GetFocusMode(), FOCUS_MODE_MANUAL);
    EXPECT_EQ(captureSession_->GetFocusMode(focusMode), SESSION_NOT_CONFIG);
    EXPECT_EQ(captureSession_->SetFocusMode(focusMode), SESSION_NOT_CONFIG);
    EXPECT_EQ(captureSession_->IsFocusModeSupported(focusMode), false);

    bool isSupported = true;
    EXPECT_EQ(captureSession_->IsFocusModeSupported(focusMode, isSupported), SESSION_NOT_CONFIG);
    std::vector<FocusMode> focusModes;
    EXPECT_EQ(captureSession_->GetSupportedFocusModes().empty(), true);
    EXPECT_EQ(captureSession_->GetSupportedFocusModes(focusModes), SESSION_NOT_CONFIG);

    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    EXPECT_EQ(captureSession_->GetSupportedFocusModes(focusModes), SUCCESS);
    ASSERT_TRUE(!focusModes.empty());
    for (auto mode : focusModes) {
        ASSERT_TRUE(captureSession_->IsFocusModeSupported(mode));
    }

    std::shared_ptr<TestFocusCallback> callback = std::make_shared<TestFocusCallback>();
    ASSERT_NE(callback, nullptr);
    captureSession_->SetFocusCallback(callback);
    ASSERT_NE(captureSession_->GetFocusCallback(), nullptr);

    captureSession_->LockForControl();
    EXPECT_EQ(captureSession_->SetFocusMode(FocusMode::FOCUS_MODE_MANUAL), SUCCESS);
    captureSession_->UnlockForControl();
    EXPECT_EQ(captureSession_->GetFocusMode(), FocusMode::FOCUS_MODE_MANUAL);

    captureSession_->LockForControl();
    EXPECT_EQ(captureSession_->SetFocusMode(FocusMode::FOCUS_MODE_AUTO), SUCCESS);
    captureSession_->UnlockForControl();
    EXPECT_EQ(captureSession_->GetFocusMode(), FocusMode::FOCUS_MODE_AUTO);

    StartDefaultCaptureOutput(photoOutput, videoOutput);
    EXPECT_EQ(cameraInput_->Release(), SUCCESS);
    cameraInput_ = nullptr;

    EXPECT_EQ(captureSession_->GetSupportedFocusModes().empty(), true);
    EXPECT_EQ(captureSession_->GetSupportedFocusModes(focusModes), SUCCESS);
    EXPECT_EQ(captureSession_->GetFocusMode(), FOCUS_MODE_MANUAL);
    EXPECT_EQ(captureSession_->GetFocusMode(focusMode), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test the capture session with focus point and focal length.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cpatuseSession set and query the focus point and focal length after completing
 * the default allocation. Ensure that the camera function is normal after the settings are completed.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_025, TestSize.Level1)
{
    Point point = captureSession_->GetFocusPoint();
    EXPECT_EQ(point.x, 0);
    EXPECT_EQ(point.y, 0);

    float focalLength = 0.0;
    EXPECT_EQ(captureSession_->GetFocalLength(), 0);
    EXPECT_EQ(captureSession_->GetFocalLength(focalLength), SESSION_NOT_CONFIG);
    EXPECT_EQ(captureSession_->GetFocusPoint(point), SESSION_NOT_CONFIG);
    EXPECT_EQ(captureSession_->SetFocusPoint(point), SESSION_NOT_CONFIG);

    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    point = { 1.0, 1.0 };
    captureSession_->LockForControl();
    EXPECT_EQ(captureSession_->SetFocusPoint(point), SUCCESS);
    captureSession_->UnlockForControl();

    Point otherPoint = { 0.0, 0.0 };
    EXPECT_EQ(captureSession_->GetFocusPoint(otherPoint), SUCCESS);
    EXPECT_EQ(otherPoint.x, point.x);
    EXPECT_EQ(otherPoint.y, point.y);

    EXPECT_EQ(captureSession_->GetFocalLength(focalLength), SUCCESS);
    MEDIA_INFO_LOG("moduletest get focal length: %{public}f", focalLength);

    StartDefaultCaptureOutput(photoOutput, videoOutput);
    EXPECT_EQ(cameraInput_->Release(), SUCCESS);
    cameraInput_ = nullptr;

    EXPECT_EQ(captureSession_->GetFocusPoint().x, 0);
    EXPECT_EQ(captureSession_->GetFocusPoint().y, 0);
    EXPECT_EQ(captureSession_->GetFocusPoint(point), SUCCESS);
    EXPECT_EQ(captureSession_->GetFocalLength(), 0);
    EXPECT_EQ(captureSession_->GetFocalLength(focalLength), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test the capture session with flash.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureSession check if the device supports flash, set and query the flash mode
 * if supported after completing the default allocation. Ensure that the camera function is normal
 * after the settings are completed.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_026, TestSize.Level1)
{
    bool hasFlash = false;
    EXPECT_EQ(captureSession_->HasFlash(), false);
    EXPECT_EQ(captureSession_->HasFlash(hasFlash), SESSION_NOT_CONFIG);

    FlashMode flashMode = FLASH_MODE_CLOSE;
    EXPECT_EQ(captureSession_->GetFlashMode(), FLASH_MODE_CLOSE);
    EXPECT_EQ(captureSession_->GetFlashMode(flashMode), SESSION_NOT_CONFIG);
    EXPECT_EQ(captureSession_->SetFlashMode(flashMode), SESSION_NOT_CONFIG);
    EXPECT_EQ(captureSession_->IsFlashModeSupported(flashMode), false);

    bool isSupported = true;
    EXPECT_EQ(captureSession_->IsFlashModeSupported(flashMode, isSupported), SESSION_NOT_CONFIG);

    std::vector<FlashMode> flashModes;
    EXPECT_EQ(captureSession_->GetSupportedFlashModes().empty(), true);
    EXPECT_EQ(captureSession_->GetSupportedFlashModes(flashModes), SESSION_NOT_CONFIG);

    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput);

    ASSERT_TRUE(captureSession_->HasFlash());
    EXPECT_EQ(captureSession_->GetSupportedFlashModes(flashModes), SUCCESS);
    ASSERT_TRUE(!flashModes.empty());
    for (auto mode : flashModes) {
        ASSERT_TRUE(captureSession_->IsFlashModeSupported(mode));
    }

    captureSession_->LockForControl();
    EXPECT_EQ(captureSession_->SetFlashMode(FlashMode::FLASH_MODE_OPEN), SUCCESS);
    captureSession_->UnlockForControl();
    EXPECT_EQ(captureSession_->GetFlashMode(), FlashMode::FLASH_MODE_OPEN);

    captureSession_->LockForControl();
    EXPECT_EQ(captureSession_->SetFlashMode(FlashMode::FLASH_MODE_CLOSE), SUCCESS);
    captureSession_->UnlockForControl();
    EXPECT_EQ(captureSession_->GetFlashMode(), FlashMode::FLASH_MODE_CLOSE);

    StartDefaultCaptureOutput(photoOutput);
    EXPECT_EQ(cameraInput_->Release(), SUCCESS);
    cameraInput_ = nullptr;

    EXPECT_EQ(captureSession_->GetSupportedFlashModes().empty(), true);
    EXPECT_EQ(captureSession_->GetSupportedFlashModes(flashModes), SUCCESS);
    EXPECT_EQ(captureSession_->GetFlashMode(), FLASH_MODE_CLOSE);
    EXPECT_EQ(captureSession_->GetFlashMode(flashMode), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test the capture session with zoom ratio range.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureSession check the zoom ratio range supported by the device, and set and
 * query the zoom ratio after completing the default allocation. Ensure that the camera function
 * is normal after the settings are completed.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_027, TestSize.Level0)
{
    float zoomRatio;
    EXPECT_EQ(captureSession_->GetZoomRatio(), 0);

    std::vector<float> ranges;
    EXPECT_EQ(captureSession_->GetZoomRatioRange().empty(), true);
    EXPECT_EQ(captureSession_->GetZoomRatioRange(ranges), SESSION_NOT_CONFIG);
    EXPECT_EQ(captureSession_->GetZoomRatio(zoomRatio), SESSION_NOT_CONFIG);
    EXPECT_EQ(captureSession_->SetZoomRatio(zoomRatio), SESSION_NOT_CONFIG);

    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    EXPECT_EQ(captureSession_->GetZoomRatioRange(ranges), SUCCESS);
    if (ranges.empty()) {
        MEDIA_ERR_LOG("moduletest get zoom ratio ranage is empty");
        GTEST_SKIP();
    }

    EXPECT_EQ(captureSession_->PrepareZoom(), SUCCESS);

    captureSession_->LockForControl();
    EXPECT_EQ(captureSession_->SetZoomRatio(ranges[0]), SUCCESS);
    captureSession_->UnlockForControl();
    float zoomRatioMin = captureSession_->GetZoomRatio();
    EXPECT_EQ(captureSession_->GetZoomRatio(zoomRatioMin), SUCCESS);

    std::shared_ptr<TestSmoothZoomCallback> callback = std::make_shared<TestSmoothZoomCallback>();
    ASSERT_NE(callback, nullptr);
    captureSession_->SetSmoothZoomCallback(callback);
    ASSERT_NE(captureSession_->GetSmoothZoomCallback(), nullptr);

    uint32_t smoothZoomType = 0;
    captureSession_->LockForControl();
    EXPECT_EQ(captureSession_->SetSmoothZoom(ranges[1], smoothZoomType), SUCCESS);
    captureSession_->UnlockForControl();
    float zoomRatioMax = captureSession_->GetZoomRatio();
    EXPECT_EQ(captureSession_->GetZoomRatio(zoomRatioMax), SUCCESS);
    std::vector<ZoomPointInfo> zoomPointInfoList;
    EXPECT_EQ(captureSession_->GetZoomPointInfos(zoomPointInfoList), SUCCESS);

    EXPECT_EQ(captureSession_->UnPrepareZoom(), SUCCESS);

    StartDefaultCaptureOutput(photoOutput, videoOutput);
    EXPECT_EQ(cameraInput_->Release(), SUCCESS);
    cameraInput_ = nullptr;

    EXPECT_EQ(captureSession_->GetZoomRatioRange().empty(), true);
    EXPECT_EQ(captureSession_->GetZoomRatioRange(ranges), SUCCESS);
    EXPECT_EQ(captureSession_->GetZoomRatio(), 0);
    EXPECT_EQ(captureSession_->GetZoomRatio(zoomRatio), SUCCESS);
    captureSession_->LockForControl();
    EXPECT_EQ(captureSession_->SetZoomRatio(zoomRatio), SUCCESS);
    captureSession_->UnlockForControl();
}

/*
 * Feature: Camera base function
 * Function: Test the capture session with filter.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureSession check the filter types supported by the device, and set and
 * query the filter types after completing the default allocation. Ensure that the camera function
 * is normal after the settings are completed.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_028, TestSize.Level1)
{
    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    std::vector<FilterType> filterTypes = captureSession_->GetSupportedFilters();
    if (filterTypes.empty()) {
        MEDIA_ERR_LOG("moduletest get supported filters is empty");
        GTEST_SKIP();
    }

    captureSession_->LockForControl();
    captureSession_->SetFilter(FilterType::CLASSIC);
    captureSession_->UnlockForControl();
    EXPECT_EQ(captureSession_->GetFilter(), FilterType::CLASSIC);

    captureSession_->LockForControl();
    captureSession_->SetFilter(FilterType::NONE);
    captureSession_->UnlockForControl();
    EXPECT_EQ(captureSession_->GetFilter(), FilterType::NONE);

    StartDefaultCaptureOutput(photoOutput, videoOutput);
}

/*
 * Feature: Camera base function
 * Function: Test the capture session with beauty.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureSession check the beauty types supported by the device and the corresponding
 * beauty levels supported by each type, and set and query the beauty level after completing the default
 * allocation. Ensure that the camera function is normal after the settings are completed.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_029, TestSize.Level1)
{
    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    std::vector<BeautyType> beautyTypes = captureSession_->GetSupportedBeautyTypes();
    if (beautyTypes.empty()) {
        MEDIA_ERR_LOG("moduletest get supported beauty types is empty");
        GTEST_SKIP();
    }

    std::vector<int32_t> ranges = captureSession_->GetSupportedBeautyRange(BeautyType::FACE_SLENDER);
    if (ranges.empty()) {
        MEDIA_ERR_LOG("moduletest get supported beauty range is empty");
        GTEST_SKIP();
    }

    captureSession_->LockForControl();
    captureSession_->SetBeauty(BeautyType::FACE_SLENDER, ranges[0]);
    captureSession_->UnlockForControl();
    EXPECT_EQ(captureSession_->GetBeauty(BeautyType::FACE_SLENDER), ranges[0]);

    captureSession_->LockForControl();
    captureSession_->SetBeauty(BeautyType::FACE_SLENDER, ranges[1]);
    captureSession_->UnlockForControl();
    EXPECT_EQ(captureSession_->GetBeauty(BeautyType::FACE_SLENDER), ranges[1]);

    StartDefaultCaptureOutput(photoOutput, videoOutput);
}

/*
 * Feature: Camera base function
 * Function: Test the capture session with color space.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureSession check the color space types supported by the device, and set
 * and query the color space types after completing the default allocation. Ensure that the photography
 * function is normal after the settings are completed.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_030, TestSize.Level0)
{
    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    std::vector<ColorSpace> colorSpaces = captureSession_->GetSupportedColorSpaces();
    if (colorSpaces.empty()) {
        MEDIA_ERR_LOG("moduletest get supported color spaces is empty");
        GTEST_SKIP();
    }
    bool isSupportSet = false;
    if (std::find(colorSpaces.begin(), colorSpaces.end(), ColorSpace::COLOR_SPACE_UNKNOWN) !=
        colorSpaces.end()) {
        isSupportSet = true;
    }
    int32_t ret = isSupportSet ? SUCCESS : INVALID_ARGUMENT;
    EXPECT_EQ(captureSession_->SetColorSpace(ColorSpace::COLOR_SPACE_UNKNOWN), ret);

    bool isSupportSetP3 = false;
    if (std::find(colorSpaces.begin(), colorSpaces.end(), ColorSpace::P3_HLG) !=
        colorSpaces.end()) {
        isSupportSetP3 = true;
    }
    int32_t retP3 = isSupportSetP3 ? SUCCESS : INVALID_ARGUMENT;
    EXPECT_EQ(captureSession_->SetColorSpace(ColorSpace::P3_HLG), retP3);
    ColorSpace colorSpace = ColorSpace::COLOR_SPACE_UNKNOWN;
    EXPECT_EQ(captureSession_->GetActiveColorSpace(colorSpace), SUCCESS);
    MEDIA_INFO_LOG("moduletest get active color space: %{public}d", colorSpace);

    StartDefaultCaptureOutput(photoOutput, videoOutput);
}

/*
 * Feature: Camera base function
 * Function: Test the capture session with color effect.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureSession check the color effect types supported by the device, and set
 * and query the color effect types after completing the default allocation. Ensure that the photography
 * function is normal after the settings are completed.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_031, TestSize.Level0)
{
    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    std::vector<ColorEffect> colorEffects = captureSession_->GetSupportedColorEffects();
    if (colorEffects.empty()) {
        MEDIA_ERR_LOG("moduletest get supported color effects is empty");
        GTEST_SKIP();
    }

    captureSession_->LockForControl();
    captureSession_->SetColorEffect(ColorEffect::COLOR_EFFECT_NORMAL);
    captureSession_->UnlockForControl();
    EXPECT_EQ(captureSession_->GetColorEffect(), ColorEffect::COLOR_EFFECT_NORMAL);

    captureSession_->LockForControl();
    captureSession_->SetColorEffect(ColorEffect::COLOR_EFFECT_BRIGHT);
    captureSession_->UnlockForControl();
    EXPECT_EQ(captureSession_->GetColorEffect(), ColorEffect::COLOR_EFFECT_BRIGHT);

    StartDefaultCaptureOutput(photoOutput, videoOutput);
}

/*
 * Feature: Camera base function
 * Function: Test the capture session with auto focus distance.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureSession check the minimum autofocus distance supported by the device,
 * and set and query the autofocus distance after completing the default allocation. Ensure that the
 * camera function is normal after the settings are completed.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_032, TestSize.Level1)
{
    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    float minFocusDistance = captureSession_->GetMinimumFocusDistance();
    MEDIA_INFO_LOG("moduletest get min focus distance: %{public}f", minFocusDistance);

    float focusDistance1 = -1.0;
    captureSession_->LockForControl();
    EXPECT_EQ(captureSession_->SetFocusDistance(focusDistance1), SUCCESS);
    captureSession_->UnlockForControl();
    float getFocusDistance1 = 0.0;
    EXPECT_EQ(captureSession_->GetFocusDistance(getFocusDistance1), SUCCESS);
    MEDIA_INFO_LOG("moduletest get focus distance: %{public}f", getFocusDistance1);

    float focusDistance2 = 0.0;
    captureSession_->LockForControl();
    EXPECT_EQ(captureSession_->SetFocusDistance(focusDistance2), SUCCESS);
    captureSession_->UnlockForControl();
    float getFocusDistance2 = 0.0;
    EXPECT_EQ(captureSession_->GetFocusDistance(getFocusDistance2), SUCCESS);
    MEDIA_INFO_LOG("moduletest get focus distance: %{public}f", getFocusDistance2);

    float focusDistance3 = 1.0;
    captureSession_->LockForControl();
    EXPECT_EQ(captureSession_->SetFocusDistance(focusDistance3), SUCCESS);
    captureSession_->UnlockForControl();
    float getFocusDistance3 = 0.0;
    EXPECT_EQ(captureSession_->GetFocusDistance(getFocusDistance3), SUCCESS);
    MEDIA_INFO_LOG("moduletest get focus distance: %{public}f", getFocusDistance3);

    StartDefaultCaptureOutput(photoOutput, videoOutput);
}

/*
 * Feature: Camera base function
 * Function: Test the capture session with macro.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureSession check if the device supports macro lens function. Enable macro
 * function and set macro status callback if supported after completing the default allocation.
 * Ensure that the camera function is normal after the settings are completed.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_033, TestSize.Level1)
{
    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    if (!captureSession_->IsMacroSupported()) {
        MEDIA_ERR_LOG("moduletest macro is not supported");
        GTEST_SKIP();
    }

    std::shared_ptr<TestMacroStatusCallback>callback = std::make_shared<TestMacroStatusCallback>();
    ASSERT_NE(callback, nullptr);
    captureSession_->SetMacroStatusCallback(callback);
    EXPECT_NE(captureSession_->GetMacroStatusCallback(), nullptr);

    captureSession_->LockForControl();
    EXPECT_EQ(captureSession_->EnableMacro(!(captureSession_->IsSetEnableMacro())), SUCCESS);
    captureSession_->UnlockForControl();

    StartDefaultCaptureOutput(photoOutput, videoOutput);
}

/*
 * Feature: Camera base function
 * Function: Test the capture session with depth fusion.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureSession check if the device supports depth fusion function. Enable
 * the depth fusion function and query the zoom ratio range if supported after completing the default
 * allocation. Ensure that the camera function is normal after the settings are completed.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_034, TestSize.Level1)
{
    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    if (!captureSession_->IsDepthFusionSupported()) {
        MEDIA_ERR_LOG("moduletest depth fusion is not supported");
        GTEST_SKIP();
    }

    std::vector<float> thresholds = captureSession_->GetDepthFusionThreshold();
    ASSERT_TRUE(!thresholds.empty());
    MEDIA_INFO_LOG("moduletest depth fusion threshold min %{public}f max %{public}f", thresholds[0], thresholds[1]);

    captureSession_->LockForControl();
    EXPECT_EQ(captureSession_->EnableDepthFusion(!(captureSession_->IsDepthFusionEnabled())), SUCCESS);
    captureSession_->UnlockForControl();

    StartDefaultCaptureOutput(photoOutput, videoOutput);
}

/*
 * Feature: Camera base function
 * Function: Test the capture session with moon capture boost.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureSession check if the device supports moon capture boost function.
 * Enable and set the status callback if supported after completing the default allocation. Ensure
 * that the camera function is normal after the settings are completed.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_035, TestSize.Level1)
{
    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    if (!captureSession_->IsMoonCaptureBoostSupported()) {
        MEDIA_ERR_LOG("moduletest moon capture boost is not supported");
        GTEST_SKIP();
    }

    auto callback = std::make_shared<TestMoonCaptureBoostStatusCallback>();
    ASSERT_NE(callback, nullptr);
    captureSession_->SetMoonCaptureBoostStatusCallback(callback);
    EXPECT_NE(captureSession_->GetMoonCaptureBoostStatusCallback(), nullptr);

    captureSession_->LockForControl();
    EXPECT_EQ(captureSession_->EnableMoonCaptureBoost(true), SUCCESS);
    captureSession_->UnlockForControl();

    StartDefaultCaptureOutput(photoOutput, videoOutput);
}

/*
 * Feature: Camera base function
 * Function: Test the capture session with low light boost.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureSession check if the device supports low light boost function.
 * Enable low light enhancement and detection function after completing the default allocation.
 * Ensure that the camera function is normal after the settings are completed.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_036, TestSize.Level1)
{
    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    if (!captureSession_->IsLowLightBoostSupported()) {
        MEDIA_ERR_LOG("mooduletest low light boost is not supported");
        GTEST_SKIP();
    }

    captureSession_->LockForControl();
    EXPECT_EQ(captureSession_->EnableLowLightBoost(true), SUCCESS);
    EXPECT_EQ(captureSession_->EnableLowLightDetection(true), SUCCESS);
    captureSession_->UnlockForControl();

    StartDefaultCaptureOutput(photoOutput, videoOutput);
}

/*
 * Feature: Camera base function
 * Function: Test the capture session with feature.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureSession check if the device supports the target function.
 * Enable and set the target function detection callback after completing the default allocation.
 * Ensure that the camera function is normal after the settings are completed.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_037, TestSize.Level1)
{
    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    auto callback = std::make_shared<TestFeatureDetectionStatusCallback>();
    ASSERT_NE(callback, nullptr);
    captureSession_->SetFeatureDetectionStatusCallback(callback);
    EXPECT_NE(captureSession_->GetFeatureDetectionStatusCallback(), nullptr);

    if (captureSession_->IsFeatureSupported(SceneFeature::FEATURE_MOON_CAPTURE_BOOST)) {
        EXPECT_EQ(captureSession_->EnableFeature(SceneFeature::FEATURE_MOON_CAPTURE_BOOST, true), SUCCESS);
    }
    if (captureSession_->IsFeatureSupported(SceneFeature::FEATURE_TRIPOD_DETECTION)) {
        EXPECT_EQ(captureSession_->EnableFeature(SceneFeature::FEATURE_TRIPOD_DETECTION, true), SUCCESS);
    }
    if (captureSession_->IsFeatureSupported(SceneFeature::FEATURE_LOW_LIGHT_BOOST)) {
        EXPECT_EQ(captureSession_->EnableFeature(SceneFeature::FEATURE_LOW_LIGHT_BOOST, true), SUCCESS);
    }
    if (captureSession_->IsFeatureSupported(SceneFeature::FEATURE_MACRO)) {
        EXPECT_EQ(captureSession_->EnableFeature(SceneFeature::FEATURE_MACRO, true), SUCCESS);
    }
    StartDefaultCaptureOutput(photoOutput, videoOutput);
}

/*
 * Feature: Camera base function
 * Function: Test the capture session with AR.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureSession set the AR mode and AR callback after completing the default
 * allocation, and the camera function will function normally after the settings are completed.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_038, TestSize.Level1)
{
    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    uint32_t moduleType = 0;
    EXPECT_EQ(captureSession_->GetModuleType(moduleType), SUCCESS);
    EXPECT_EQ(cameraDevices_[0]->GetModuleType(), moduleType);

    std::vector<int32_t> sensitivityRange;
    EXPECT_EQ(captureSession_->GetSensorSensitivityRange(sensitivityRange), SUCCESS);
    if (!sensitivityRange.empty()) {
        captureSession_->LockForControl();
        EXPECT_EQ(captureSession_->SetSensorSensitivity(sensitivityRange[0]), SUCCESS);
        captureSession_->UnlockForControl();
    }

    std::vector<uint32_t> sensorExposureTimeRange;
    int32_t ret = captureSession_->GetSensorExposureTimeRange(sensorExposureTimeRange);
    if ((ret == SUCCESS) || (!sensorExposureTimeRange.empty())) {
        captureSession_->LockForControl();
        EXPECT_EQ(captureSession_->SetSensorExposureTime(sensorExposureTimeRange[0]), SUCCESS);
        captureSession_->UnlockForControl();

        uint32_t sensorExposureTime = 0;
        EXPECT_EQ(captureSession_->GetSensorExposureTime(sensorExposureTime), SUCCESS);
        EXPECT_EQ(sensorExposureTime, sensorExposureTimeRange[0]);
    }

    auto callback = std::make_shared<TestARCallback>();
    EXPECT_NE(callback, nullptr);
    captureSession_->SetARCallback(callback);
    EXPECT_NE(captureSession_->GetARCallback(), nullptr);
    EXPECT_EQ(captureSession_->SetARMode(true), SUCCESS);

    StartDefaultCaptureOutput(photoOutput, videoOutput);
}

/*
 * Feature: Camera base function
 * Function: Test the capture session with master ai.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureSession check if the device supports scene mode and type. Enable and
 * set the corresponding state for the scene mode type after completing the default allocation. Ensure
 * that the camera function is normal after the settings are completed.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_039, TestSize.Level1)
{
    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    if (!captureSession_->IsEffectSuggestionSupported()) {
        MEDIA_ERR_LOG("mooduletest effect suggestion is not supported");
        GTEST_SKIP();
    }

    std::vector<EffectSuggestionType> supportedTypeList = captureSession_->GetSupportedEffectSuggestionType();
    ASSERT_TRUE(!supportedTypeList.empty());

    auto callback = std::make_shared<TestEffectSuggestionCallback>();
    ASSERT_NE(callback, nullptr);
    captureSession_->SetEffectSuggestionCallback(callback);

    captureSession_->LockForControl();
    EXPECT_EQ(captureSession_->EnableEffectSuggestion(true), SUCCESS);

    std::vector<EffectSuggestionType> effectSuggestionTypes = captureSession_->GetSupportedEffectSuggestionType();
    if (!effectSuggestionTypes.empty()) {
        std::vector<EffectSuggestionStatus> effectSuggestionStatusList;
        for (auto type : effectSuggestionTypes) {
            effectSuggestionStatusList.push_back({type, false});
        }
        EXPECT_EQ(captureSession_->SetEffectSuggestionStatus(effectSuggestionStatusList), SUCCESS);
        EXPECT_EQ(captureSession_->UpdateEffectSuggestion(EffectSuggestionType::EFFECT_SUGGESTION_PORTRAIT,
            true), SUCCESS);
    }
    captureSession_->UnlockForControl();

    StartDefaultCaptureOutput(photoOutput, videoOutput);
}

/*
 * Feature: Camera base function
 * Function: Test the capture session with virtual aperture.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the captureSession check the supported virtual aperture settings and set the
 * virtual aperture. After the settings are completed, the camera function is normal.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_040, TestSize.Level1)
{
    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    std::vector<float> apertures;
    EXPECT_EQ(captureSession_->GetSupportedVirtualApertures(apertures), SUCCESS);
    if (!apertures.empty()) {
        captureSession_->LockForControl();
        EXPECT_EQ(captureSession_->SetVirtualAperture(apertures[0]), SUCCESS);
        captureSession_->UnlockForControl();

        float aperture = 0.0;
        EXPECT_EQ(captureSession_->GetVirtualAperture(aperture), SUCCESS);
        EXPECT_EQ(aperture, apertures[0]);
    }

    StartDefaultCaptureOutput(photoOutput, videoOutput);
}

/*
 * Feature: Camera base function
 * Function: Test the capture session with physical aperture.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the captureSession check the supported physical aperture settings and set the
 * physical aperture. After the settings are completed, the camera function is normal.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_041, TestSize.Level1)
{
    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    std::vector<std::vector<float>> vecAperture;
    EXPECT_EQ(captureSession_->GetSupportedPhysicalApertures(vecAperture), SUCCESS);
    if (!vecAperture.empty()) {
        std::vector<float> apertures = vecAperture[0];
        captureSession_->LockForControl();
        EXPECT_EQ(captureSession_->SetPhysicalAperture(apertures[0]), SUCCESS);
        captureSession_->UnlockForControl();

        float aperture = 0.0;
        EXPECT_EQ(captureSession_->GetPhysicalAperture(aperture), SUCCESS);
        EXPECT_EQ(aperture, apertures[0]);
    }

    StartDefaultCaptureOutput(photoOutput, videoOutput);
}

/*
 * Feature: Camera base function
 * Function: Test the capture session with white balance.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the captureSession check the white balance mode supported by the device and
 * make the necessary settings. Also check the range of values that the device supports for manual
 * settings and make the necessary adjustments. Ensure that the camera function is normal
 * after the settings are completed.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_042, TestSize.Level1)
{
    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    std::vector<WhiteBalanceMode> modes;
    EXPECT_EQ(captureSession_->GetSupportedWhiteBalanceModes(modes), SUCCESS);
    if (!modes.empty()) {
        for (auto mode : modes) {
            bool isSupported = true;
            EXPECT_EQ(captureSession_->IsWhiteBalanceModeSupported(mode, isSupported), SUCCESS);
        }

        captureSession_->LockForControl();
        EXPECT_EQ(captureSession_->SetWhiteBalanceMode(WhiteBalanceMode::AWB_MODE_AUTO), SUCCESS);
        captureSession_->UnlockForControl();

        WhiteBalanceMode mode = WhiteBalanceMode::AWB_MODE_OFF;
        EXPECT_EQ(captureSession_->GetWhiteBalanceMode(mode), SUCCESS);
        EXPECT_EQ(mode, WhiteBalanceMode::AWB_MODE_AUTO);
    }

    bool isSupported = false;
    EXPECT_EQ(captureSession_->IsManualWhiteBalanceSupported(isSupported), SUCCESS);
    if (isSupported) {
        std::vector<int32_t> whiteBalanceRange;
        EXPECT_EQ(captureSession_->GetManualWhiteBalanceRange(whiteBalanceRange), SUCCESS);
        if (!whiteBalanceRange.empty()) {
            captureSession_->LockForControl();
            ASSERT_EQ(captureSession_->SetWhiteBalanceMode(WhiteBalanceMode::AWB_MODE_OFF), SUCCESS);
            captureSession_->UnlockForControl();
            captureSession_->LockForControl();
            ASSERT_EQ(captureSession_->SetManualWhiteBalance(whiteBalanceRange[0]), SUCCESS);
            captureSession_->UnlockForControl();

            int32_t wbValue = 0;
            EXPECT_EQ(captureSession_->GetManualWhiteBalance(wbValue), SUCCESS);
            EXPECT_EQ(wbValue, whiteBalanceRange[0]);
        }
    }

    StartDefaultCaptureOutput(photoOutput, videoOutput);
}

/*
 * Feature: Camera base function
 * Function: Test the capture session with lcd flash.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the captureSession check if the device supports flash. Register the flash
 * status callback and turn it on before turning it off if supported. Ensure that the photography
 * function is normal after the settings are completed.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_043, TestSize.Level1)
{
    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    if (captureSession_->IsLcdFlashSupported()) {
        auto callback = std::make_shared<TestLcdFlashStatusCallback>();
        EXPECT_NE(callback, nullptr);
        captureSession_->SetLcdFlashStatusCallback(callback);
        EXPECT_NE(captureSession_->GetLcdFlashStatusCallback(), nullptr);

        captureSession_->LockForControl();
        EXPECT_EQ(captureSession_->EnableLcdFlash(true), SUCCESS);
        EXPECT_EQ(captureSession_->EnableLcdFlashDetection(true), SUCCESS);

        EXPECT_EQ(captureSession_->EnableLcdFlash(false), SUCCESS);
        EXPECT_EQ(captureSession_->EnableLcdFlashDetection(false), SUCCESS);
        captureSession_->UnlockForControl();
    }

    StartDefaultCaptureOutput(photoOutput, videoOutput);
}

/*
 * Feature: Camera base function
 * Function: Test the capture session with tripod.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the captureSession check if the device supports tripods. Enable tripod
 * detection and stabilization if supported. Ensure that the camera function is normal after
 * the settings are completed.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_044, TestSize.Level1)
{
    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    if (captureSession_->IsTripodDetectionSupported()) {
        captureSession_->LockForControl();
        EXPECT_EQ(captureSession_->EnableTripodStabilization(true), SUCCESS);
        EXPECT_EQ(captureSession_->EnableTripodDetection(true), SUCCESS);
        captureSession_->UnlockForControl();
    }

    StartDefaultCaptureOutput(photoOutput, videoOutput);
}

/*
 * Feature: Camera base function
 * Function: Test the capture session with switch device.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureSession check if the device supports automatic device switching. If
 * supported, enable automatic switching and register the switching status callback and set the device
 * status. After setting, the camera function is normal.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_045, TestSize.Level0)
{
    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    if (captureSession_->IsAutoDeviceSwitchSupported()) {
        auto callback = std::make_shared<TestAutoDeviceSwitchCallback>();
        EXPECT_NE(callback, nullptr);
        captureSession_->SetAutoDeviceSwitchCallback(callback);
        EXPECT_NE(captureSession_->GetAutoDeviceSwitchCallback(), nullptr);

        captureSession_->SetIsAutoSwitchDeviceStatus(true);
        if (captureSession_->GetIsAutoSwitchDeviceStatus()) {
            EXPECT_EQ(captureSession_->EnableAutoDeviceSwitch(true), SUCCESS);
            EXPECT_EQ(captureSession_->SwitchDevice(), true);
        }
    }

    StartDefaultCaptureOutput(photoOutput, videoOutput);
}

/* *****captureOutput***** */
/*
 * Feature: Camera base function
 * Function: Test the preview output with PreviewStateCallback.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the registration of PreviewOutput with PreviewStatecallback. The callback
 * function is set and queried normally. OnFrameStarted is called at the beginning of the preview frame,
 * and OnFrameEnded is called at the end of the preview frame.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_046, TestSize.Level1)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    std::shared_ptr<TestPreviewOutputCallback> callback = std::make_shared<TestPreviewOutputCallback>("");
    EXPECT_NE(callback, nullptr);
    previewOutput->SetCallback(callback);
    EXPECT_GT(previewOutput->GetPreviewOutputListenerManager()->GetListenerCount(), 0);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test the preview output with rotation.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test previewOutput to set the preview rotation angle, and after setting it, the
 * camera will preview normally.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_047, TestSize.Level1)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(previewOutput->SetPreviewRotation(CaptureOutput::ImageRotation::ROTATION_90, false), SUCCESS);
    int32_t imageRotation = previewOutput->GetPreviewRotation(CaptureOutput::ImageRotation::ROTATION_0);
    MEDIA_INFO_LOG("moduletest get preview rotation: %{public}d", imageRotation);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test the preview output with sketch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test whether previewOutput supports sketches. If supported, register sketch status
 * data callback and enable sketch function, query zoom ratio threshold. After setting, preview function is normal.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_048, TestSize.Level1)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    if (previewOutput->IsSketchSupported()) {
        EXPECT_GT(previewOutput->GetSketchRatio(), 0);
        EXPECT_EQ(previewOutput->EnableSketch(true), SUCCESS);
    }
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test the photo output with PhotoOutputCallback.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the registration of PhotoStatecallback with photoOutput. The callback function
 * is set and queried normally, and the callback function responds normally before and after taking photos
 * and pressing the shutter button.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_049, TestSize.Level1)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<PhotoOutput> photoOutput = CreatePhotoOutput(photoProfiles_[0]);
    ASSERT_NE(photoOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)photoOutput), SUCCESS);
    std::shared_ptr<TestPhotoOutputCallback> callback = std::make_shared<TestPhotoOutputCallback>("");
    EXPECT_NE(callback, nullptr);
    photoOutput->SetCallback(callback);
    EXPECT_NE(photoOutput->GetApplicationCallback(), nullptr);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    EXPECT_EQ(photoOutput->Capture(), SUCCESS);
    WAIT(DURATION_AFTER_CAPTURE);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test the photo output with location.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test setting the location information when capturing the camera stream, and the
 * camera function will be normal after the setting is completed.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_050, TestSize.Level0)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<PhotoOutput> photoOutput = CreatePhotoOutput(photoProfiles_[0]);
    ASSERT_NE(photoOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)photoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    std::shared_ptr<PhotoCaptureSetting> photoSetting = std::make_shared<PhotoCaptureSetting>();
    std::shared_ptr<Location> location = std::make_shared<Location>();
    location->latitude = -1;
    location->longitude = -1;
    location->altitude = -1;
    photoSetting->SetLocation(location);

    location->latitude = 0;
    location->longitude = 0;
    location->altitude = 0;
    photoSetting->SetLocation(location);

    location->latitude = 1;
    location->longitude = 1;
    location->altitude = 1;
    photoSetting->SetLocation(location);
    photoSetting->SetGpsLocation(location->latitude, location->longitude);
    EXPECT_EQ(photoOutput->Capture(photoSetting), SUCCESS);
    WAIT(DURATION_AFTER_CAPTURE);

    EXPECT_EQ(captureSession_->Stop(), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test the photo output with rotation.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test setting the rotation information when capturing the camera stream, and the
 * camera function will be normal after the setting is completed.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_051, TestSize.Level1)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<PhotoOutput> photoOutput = CreatePhotoOutput(photoProfiles_[0]);
    ASSERT_NE(photoOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)photoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    std::shared_ptr<PhotoCaptureSetting> photoSetting = std::make_shared<PhotoCaptureSetting>();
    photoSetting->SetRotation(PhotoCaptureSetting::RotationConfig::Rotation_90);
    EXPECT_EQ(photoOutput->Capture(photoSetting), SUCCESS);
    WAIT(DURATION_AFTER_CAPTURE);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test the photo output with mirror.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test setting the mirror information when capturing the camera stream, and the
 * camera function will be normal after the setting is completed.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_052, TestSize.Level1)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<PhotoOutput> photoOutput = CreatePhotoOutput(photoProfiles_[0]);
    ASSERT_NE(photoOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)photoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    std::shared_ptr<PhotoCaptureSetting> photoSetting = std::make_shared<PhotoCaptureSetting>();
    if (photoOutput->IsMirrorSupported()) {
        EXPECT_EQ(photoOutput->EnableMirror(true), SUCCESS);
        if (!photoSetting->GetMirror()) {
            photoSetting->SetMirror(true);
        }
    }
    EXPECT_EQ(photoOutput->Capture(photoSetting), SUCCESS);
    WAIT(DURATION_AFTER_CAPTURE);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test the photo output with quality.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test setting the quality information when capturing the camera stream, and the
 * camera function will be normal after the setting is completed.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_053, TestSize.Level1)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<PhotoOutput> photoOutput = CreatePhotoOutput(photoProfiles_[0]);
    ASSERT_NE(photoOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)photoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    std::shared_ptr<PhotoCaptureSetting> photoSetting = std::make_shared<PhotoCaptureSetting>();
    photoSetting->SetQuality(PhotoCaptureSetting::QualityLevel::QUALITY_LEVEL_HIGH);
    EXPECT_EQ(photoOutput->Capture(photoSetting), SUCCESS);
    WAIT(DURATION_AFTER_CAPTURE);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test the photo output with burst capture state.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test setting the burst capture state when capturing the camera stream, and the
 * camera function will be normal after the setting is completed.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_054, TestSize.Level1)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<PhotoOutput> photoOutput = CreatePhotoOutput(photoProfiles_[0]);
    ASSERT_NE(photoOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)photoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    std::shared_ptr<PhotoCaptureSetting> photoSetting = std::make_shared<PhotoCaptureSetting>();
    uint8_t burstState = 1;
    photoSetting->SetBurstCaptureState(burstState);
    EXPECT_EQ(photoOutput->Capture(photoSetting), SUCCESS);
    WAIT(DURATION_AFTER_CAPTURE);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test the photo output with thumbnail.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test whether photoOutput supports fast thumbnails. If supported, register a
 * thumbnail callback and enable the thumbnail function. After setting it up, the photo function
 * will work normally.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_055, TestSize.Level0)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<PhotoOutput> photoOutput = CreatePhotoOutput(photoProfiles_[0]);
    ASSERT_NE(photoOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)photoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    std::shared_ptr<PhotoCaptureSetting> photoSetting = std::make_shared<PhotoCaptureSetting>();
    if (photoOutput->IsQuickThumbnailSupported()) {
        sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
        sptr<SurfaceListener> surfaceListener = new SurfaceListener("Preview", SurfaceType::PREVIEW,
            previewFd_, previewSurface);
        sptr<IBufferConsumerListener> listener = (sptr<IBufferConsumerListener>&)surfaceListener;
        ASSERT_NE(listener, nullptr);
        photoOutput->SetThumbnailListener(listener);

        EXPECT_EQ(photoOutput->SetThumbnail(true), SUCCESS);
    }
    EXPECT_EQ(photoOutput->Capture(photoSetting), SUCCESS);
    WAIT(DURATION_AFTER_CAPTURE);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test the photo output with raw delivery.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test whether photoOutput supports original raw delivery. If supported, enable raw
 * delivery function. After setting it up, the photo function will work normally.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_056, TestSize.Level1)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<PhotoOutput> photoOutput = CreatePhotoOutput(photoProfiles_[0]);
    ASSERT_NE(photoOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)photoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    bool isRawDeliverySuppoted = false;
    EXPECT_EQ(photoOutput->IsRawDeliverySupported(isRawDeliverySuppoted), SUCCESS);
    if (isRawDeliverySuppoted) {
        EXPECT_EQ(photoOutput->EnableRawDelivery(true), SUCCESS);
    }
    EXPECT_EQ(photoOutput->Capture(), SUCCESS);
    WAIT(DURATION_AFTER_CAPTURE);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test the photo output with auto cloud image enhancement.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test whether photoOutput supports automatic cloud image enhancement. If supported,
 * enable the automatic cloud image enhancement function. After setting it up, the camera function will
 * work normally.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_057, TestSize.Level1)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<PhotoOutput> photoOutput = CreatePhotoOutput(photoProfiles_[0]);
    ASSERT_NE(photoOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)photoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    bool isAutoCloudImageEnhanceSupported = false;
    EXPECT_EQ(photoOutput->IsAutoCloudImageEnhancementSupported(isAutoCloudImageEnhanceSupported), SUCCESS);
    if (isAutoCloudImageEnhanceSupported) {
        EXPECT_EQ(photoOutput->EnableAutoCloudImageEnhancement(true), SUCCESS);
    }
    EXPECT_EQ(photoOutput->Capture(), SUCCESS);
    WAIT(DURATION_AFTER_CAPTURE);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test the photo output with depth data delivery.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test whether photoOutput supports depth data delivery. If supported, enable the
 * depth data delivery function. After setting it up, the camera function will work normally.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_058, TestSize.Level1)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<PhotoOutput> photoOutput = CreatePhotoOutput(photoProfiles_[0]);
    ASSERT_NE(photoOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)photoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    if (photoOutput->IsDepthDataDeliverySupported()) {
        EXPECT_EQ(photoOutput->EnableDepthDataDelivery(true), SUCCESS);
    }
    EXPECT_EQ(photoOutput->Capture(), SUCCESS);
    WAIT(DURATION_AFTER_CAPTURE);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test the video output with videoStateCallback.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test videoOutput to register videoStatecallback. The callback function is set and
 * queried normally. OnFrameStarted is called at the beginning of the video frame, and OnFrameEnded
 * is called at the end of the video frame.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_059, TestSize.Level1)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<VideoOutput> videoOutput = CreateVideoOutput(videoProfiles_[0]);
    ASSERT_NE(videoOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)videoOutput), SUCCESS);
    std::shared_ptr<TestVideoOutputCallback>callback = std::make_shared<TestVideoOutputCallback>("");
    EXPECT_NE(callback, nullptr);
    videoOutput->SetCallback(callback);
    EXPECT_NE(videoOutput->GetApplicationCallback(), nullptr);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    EXPECT_EQ(videoOutput->Start(), SUCCESS);
    WAIT(DURATION_DURING_RECORDING);
    EXPECT_EQ(videoOutput->Stop(), SUCCESS);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test the video output with mirror function.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test whether videoOutput supports mirror function. If supported, enable the
 * mirror function. After setting it up, the camera function will work normally.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_060, TestSize.Level1)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<VideoOutput> videoOutput = CreateVideoOutput(videoProfiles_[0]);
    ASSERT_NE(videoOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)videoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    if (videoOutput->IsMirrorSupported()) {
        EXPECT_EQ(videoOutput->enableMirror(true), SUCCESS);
    }
    EXPECT_EQ(videoOutput->Start(), SUCCESS);
    WAIT(DURATION_DURING_RECORDING);
    EXPECT_EQ(videoOutput->Stop(), SUCCESS);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test the video output with rotation.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test whether videoOutput supports rotation function. If supported, set the rotation.
 * After setting it up, the camera function will work normally.
 */
 HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_061, TestSize.Level1)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<VideoOutput> videoOutput = CreateVideoOutput(videoProfiles_[0]);
    ASSERT_NE(videoOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)videoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    bool isSupported = false;
    EXPECT_EQ(videoOutput->IsRotationSupported(isSupported), SUCCESS);
    if (isSupported) {
        std::vector<int32_t> supportedRotations;
        EXPECT_EQ(videoOutput->GetSupportedRotations(supportedRotations), SUCCESS);
        if (!supportedRotations.empty()) {
            EXPECT_EQ(videoOutput->SetRotation(supportedRotations[0]), SUCCESS);
        }
    }
    EXPECT_EQ(videoOutput->Start(), SUCCESS);
    WAIT(DURATION_DURING_RECORDING);
    EXPECT_EQ(videoOutput->Stop(), SUCCESS);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);
}


/*
 * Feature: Camera base function
 * Function: Test get distributed camera hostname
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get distributed camera hostname
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_062, TestSize.Level1)
{
    std::string hostName;
    for (size_t i = 0; i < cameraDevices_.size(); i++) {
        hostName = cameraDevices_[i]->GetHostName();
        std::string cameraId = cameraDevices_[i]->GetID();
        std::string networkId = cameraDevices_[i]->GetNetWorkId();
        if (networkId != "") {
            ASSERT_NE(hostName, "");
        } else {
            ASSERT_EQ(hostName, "");
        }
    }
}

/*
 * Feature: Camera base function
 * Function: Test get DeviceType
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get DeviceType
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_063, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    auto judgeDeviceType = [&cameras]() -> bool {
        bool isOk = false;
        for (size_t i = 0; i < cameras.size(); i++) {
            uint16_t deviceType = cameras[i]->GetDeviceType();
            switch (deviceType) {
                case HostDeviceType::UNKNOWN:
                case HostDeviceType::PHONE:
                case HostDeviceType::TABLET:
                    isOk = true;
                    break;
                default:
                    isOk = false;
                    break;
            }
            if (isOk == false) {
                break;
            }
        }
        return isOk;
    };
    ASSERT_NE(judgeDeviceType(), false);
}

/*
 * Feature: Camera base function
 * Function: Test input error and result callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test input error and result callback
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_064, TestSize.Level1)
{
    auto errorCallback = std::make_shared<TestDeviceCallback>("");
    auto resultCallback = std::make_shared<TestOnResultCallback>("");
    cameraInput_->SetErrorCallback(errorCallback);
    cameraInput_->SetResultCallback(resultCallback);

    EXPECT_NE(cameraInput_->GetErrorCallback(), nullptr);
    EXPECT_NE(cameraInput_->GetResultCallback(), nullptr);
}

/*
 * Feature: Camera base function
 * Function: Test create camera input
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test create camera input and construct device object with anomalous branch.
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_065, TestSize.Level0)
{
    sptr<CameraManager> camManagerObj = CameraManager::GetInstance();
    ASSERT_NE(camManagerObj, nullptr);
    camManagerObj->SetServiceProxy(nullptr);

    std::string cameraId = "";
    dmDeviceInfo deviceInfo = {};
    auto metaData = std::make_shared<OHOS::Camera::CameraMetadata>(0, 0);
    sptr<CameraDevice> camdeviceObj1 = new (std::nothrow) CameraDevice(cameraId, metaData, deviceInfo);
    ASSERT_NE(camdeviceObj1, nullptr);
    EXPECT_EQ(camManagerObj->CreateCameraInput(camdeviceObj1), nullptr);

    cameraId = cameraDevices_[0]->GetID();
    sptr<CameraDevice> camdeviceObj2 = new (std::nothrow) CameraDevice(cameraId, metaData, deviceInfo);
    ASSERT_NE(camdeviceObj2, nullptr);
    EXPECT_NE(camManagerObj->CreateCameraInput(camdeviceObj2), nullptr);

    sptr<CameraDevice> camdeviceObj3 = nullptr;
    EXPECT_EQ(camManagerObj->CreateCameraInput(camdeviceObj3), nullptr);

    CameraPosition cameraPosition = cameraDevices_[0]->GetPosition();
    CameraType cameraType = cameraDevices_[0]->GetCameraType();
    ASSERT_NE(camManagerObj->CreateCameraInput(cameraPosition, cameraType), nullptr);
    EXPECT_EQ(camManagerObj->CreateCameraInput(CAMERA_POSITION_UNSPECIFIED, cameraType), nullptr);
    EXPECT_EQ(camManagerObj->CreateCameraInput(cameraPosition, CAMERA_TYPE_UNSUPPORTED), nullptr);
    EXPECT_EQ(camManagerObj->CreateCameraInput(CAMERA_POSITION_UNSPECIFIED, CAMERA_TYPE_UNSUPPORTED), nullptr);

    sptr<CameraDevice> camDevice = camManagerObj->GetCameraDeviceFromId(cameraId);
    ASSERT_NE(camDevice, nullptr);
    sptr<ICameraDeviceService> deviceService = cameraInput_->GetCameraDevice();
    ASSERT_NE(deviceService, nullptr);

    sptr<CameraInput> input = new (std::nothrow) CameraInput(deviceService, camdeviceObj3);
    ASSERT_NE(input, nullptr);

    camManagerObj->InitCameraManager();
}

/*
 * Feature: Camera base function
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test camera settings with anomalous branch
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_066, TestSize.Level0)
{
    sptr<ICameraDeviceService> device= cameraInput_->GetCameraDevice();
    ASSERT_NE(device, nullptr);

    sptr<CameraDevice> camdeviceObj = nullptr;
    sptr<CameraInput> camInput = new (std::nothrow) CameraInput(device, camdeviceObj);
    ASSERT_NE(camInput, nullptr);

    std::string cameraId = cameraInput_->GetCameraId();

    std::string getCameraSettings1 = cameraInput_->GetCameraSettings();
    EXPECT_EQ(cameraInput_->SetCameraSettings(getCameraSettings1), SUCCESS);

    std::string getCameraSettings2 = "";
    EXPECT_EQ(camInput->SetCameraSettings(getCameraSettings2), 2);

    EXPECT_EQ(cameraInput_->Close(), SUCCESS);
    cameraInput_->SetMetadataResultProcessor(captureSession_->GetMetadataResultProcessor());

    EXPECT_EQ(cameraInput_->Open(), SERVICE_FATL_ERROR);

    EXPECT_EQ(camInput->Release(), SUCCESS);
    camInput = nullptr;
    cameraInput_->Release();
    cameraInput_ = nullptr;
}

/*
 * Feature: Camera base function
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test submit device control setting with anomalous branch
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_067, TestSize.Level1)
{
    EXPECT_EQ(captureSession_->Release(), SUCCESS);
    EXPECT_EQ(captureSession_->UnlockForControl(), SERVICE_FATL_ERROR);
    captureSession_ = nullptr;
}

/*
 * Feature: Camera base function
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test session with anomalous branch
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_068, TestSize.Level1)
{
    cameraInput_->Close();
    cameraInput_->SetMetadataResultProcessor(captureSession_->GetMetadataResultProcessor());

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->BeginConfig(), SESSION_CONFIG_LOCKED);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), DEVICE_DISABLED);

    captureSession_->Release();
    EXPECT_EQ(captureSession_->BeginConfig(), SERVICE_FATL_ERROR);

    cameraInput_ = nullptr;
    captureSession_ = nullptr;
}

/*
 * Feature: Camera base function
 * Function: Test capture session with commit config multiple times
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session with commit config multiple times
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_069, TestSize.Level1)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(cameraInput_->Open(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);
    EXPECT_NE(captureSession_->CommitConfig(), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test capture session add input or output with invalid value
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session add input or output with invalid value
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_070, TestSize.Level1)
{
    sptr<CaptureInput> input = nullptr;
    EXPECT_EQ(captureSession_->AddInput(input), OPERATION_NOT_ALLOWED);
    sptr<CaptureOutput> output = nullptr;
    EXPECT_EQ(captureSession_->AddOutput(output), OPERATION_NOT_ALLOWED);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);

    EXPECT_NE(captureSession_->AddInput(input), SUCCESS);
    EXPECT_NE(captureSession_->AddOutput(output), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test capture session remove input or output with null
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session remove input or output with null
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_071, TestSize.Level1)
{
    sptr<CaptureInput> input = nullptr;
    EXPECT_EQ(captureSession_->RemoveInput(input), OPERATION_NOT_ALLOWED);
    sptr<CaptureOutput> output = nullptr;
    EXPECT_EQ(captureSession_->RemoveOutput(output), OPERATION_NOT_ALLOWED);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);

    EXPECT_EQ(captureSession_->RemoveInput(input), SERVICE_FATL_ERROR);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->RemoveInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);

    EXPECT_EQ(captureSession_->RemoveOutput(output), SERVICE_FATL_ERROR);
}

/*
 * Feature: Camera base function
 * Function: Test dynamic add and remove preview output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test dynamic add and remove preview output
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_072, TestSize.Level1)
{
    sptr<PreviewOutput> previewOutput1 = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput1, nullptr);
    sptr<PreviewOutput> previewOutput2 = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput2, nullptr);
    sptr<PhotoOutput> photoOutput = CreatePhotoOutput(photoProfiles_[0]);
    ASSERT_NE(photoOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput1), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)photoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    EXPECT_EQ(photoOutput->Capture(), SUCCESS);
    WAIT(DURATION_AFTER_CAPTURE);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->RemoveOutput((sptr<CaptureOutput>&)previewOutput1), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput2), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);
}


/*
 * Feature: Camera base function
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test create preview output with anomalous branch
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_073, TestSize.Level1)
{
    sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
    sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
    sptr<Surface> pSurface = Surface::CreateSurfaceAsProducer(previewProducer);

    sptr<Surface> pSurface_1 = nullptr;

    sptr<CaptureOutput> previewOutput = cameraManager_->CreatePreviewOutput(previewProfiles_[0], pSurface_1);
    EXPECT_EQ(previewOutput, nullptr);

    sptr<CaptureOutput> previewOutput_1 = cameraManager_->CreateDeferredPreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput_1, nullptr);

    // height is zero
    CameraFormat previewFormat = previewProfiles_[0].GetCameraFormat();
    Size previewSize;
    previewSize.width = previewProfiles_[0].GetSize().width;
    previewSize.height = 0;
    previewProfiles_[0] = Profile(previewFormat, previewSize);

    previewOutput = cameraManager_->CreatePreviewOutput(previewProfiles_[0], pSurface);
    EXPECT_EQ(previewOutput, nullptr);

    previewOutput_1 = cameraManager_->CreateDeferredPreviewOutput(previewProfiles_[0]);
    EXPECT_EQ(previewOutput_1, nullptr);

    sptr<CaptureOutput> previewOutput_2 = cameraManager_->CreatePreviewOutput(previewProducer, previewFormat);
    EXPECT_EQ(previewOutput_2, nullptr);

    sptr<CaptureOutput> previewOutput_3 = nullptr;
    previewOutput_3 = cameraManager_->CreateCustomPreviewOutput(pSurface, previewSize.width, previewSize.height);
    EXPECT_EQ(previewOutput_3, nullptr);

    // width is zero
    previewSize.width = 0;
    previewSize.height = PREVIEW_DEFAULT_HEIGHT;
    previewProfiles_[0] = Profile(previewFormat, previewSize);

    previewOutput = cameraManager_->CreatePreviewOutput(previewProfiles_[0], pSurface);
    EXPECT_EQ(previewOutput, nullptr);

    previewOutput_1 = cameraManager_->CreateDeferredPreviewOutput(previewProfiles_[0]);
    EXPECT_EQ(previewOutput_1, nullptr);

    // format is CAMERA_FORMAT_INVALID
    previewFormat = CAMERA_FORMAT_INVALID;
    previewSize.width = PREVIEW_DEFAULT_WIDTH;
    previewProfiles_[0] = Profile(previewFormat, previewSize);

    previewOutput = cameraManager_->CreatePreviewOutput(previewProfiles_[0], pSurface);
    EXPECT_EQ(previewOutput, nullptr);

    previewOutput_1 = cameraManager_->CreateDeferredPreviewOutput(previewProfiles_[0]);
    EXPECT_EQ(previewOutput_1, nullptr);
}

/*
 * Feature: Camera base function
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test create photo output with anomalous branch
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_074, TestSize.Level1)
{
    sptr<IConsumerSurface> photosurface = IConsumerSurface::Create();
    sptr<IBufferProducer> surfaceProducer_1 = photosurface->GetProducer();

    sptr<IBufferProducer> surfaceProducer_2 = nullptr;

    sptr<CaptureOutput> photoOutput = cameraManager_->CreatePhotoOutput(photoProfiles_[0], surfaceProducer_2);
    EXPECT_EQ(photoOutput, nullptr);

    // height is zero
    CameraFormat photoFormat = photoProfiles_[0].GetCameraFormat();
    Size photoSize;
    photoSize.width = photoProfiles_[0].GetSize().width;
    photoSize.height = 0;
    photoProfiles_[0] = Profile(photoFormat, photoSize);

    photoOutput = cameraManager_->CreatePhotoOutput(photoProfiles_[0], surfaceProducer_1);
    EXPECT_EQ(photoOutput, nullptr);

    // width is zero
    photoSize.width = 0;
    photoSize.height = PHOTO_DEFAULT_HEIGHT;
    photoProfiles_[0] = Profile(photoFormat, photoSize);

    photoOutput = cameraManager_->CreatePhotoOutput(photoProfiles_[0], surfaceProducer_1);
    EXPECT_EQ(photoOutput, nullptr);

    // format is CAMERA_FORMAT_INVALID
    photoFormat = CAMERA_FORMAT_INVALID;
    photoSize.width = PHOTO_DEFAULT_WIDTH;
    photoProfiles_[0] = Profile(photoFormat, photoSize);

    photoOutput = cameraManager_->CreatePhotoOutput(photoProfiles_[0], surfaceProducer_1);
    EXPECT_EQ(photoOutput, nullptr);
}

/*
 * Feature: Camera base function
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test create video output with anomalous branch
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_075, TestSize.Level1)
{
    sptr<IConsumerSurface> videoSurface = IConsumerSurface::Create();
    sptr<IBufferProducer> videoProducer = videoSurface->GetProducer();
    sptr<Surface> pSurface_1 = Surface::CreateSurfaceAsProducer(videoProducer);

    sptr<Surface> pSurface_2 = nullptr;

    sptr<CaptureOutput> videoOutput = cameraManager_->CreateVideoOutput(videoProfiles_[0], pSurface_2);
    EXPECT_EQ(videoOutput, nullptr);

    sptr<CaptureOutput> videoOutput_1 = cameraManager_->CreateVideoOutput(pSurface_2);
    EXPECT_EQ(videoOutput_1, nullptr);

    // height is zero
    std::vector<int32_t> framerates;
    CameraFormat videoFormat = videoProfiles_[0].GetCameraFormat();
    Size videoSize;
    videoSize.width = videoProfiles_[0].GetSize().width;
    videoSize.height = 0;
    VideoProfile videoProfile_1 = VideoProfile(videoFormat, videoSize, framerates);

    videoOutput = cameraManager_->CreateVideoOutput(videoProfile_1, pSurface_1);
    EXPECT_EQ(videoOutput, nullptr);

    // width is zero
    videoSize.width = 0;
    videoSize.height = VIDEO_DEFAULT_HEIGHT;
    videoProfile_1 = VideoProfile(videoFormat, videoSize, framerates);

    videoOutput = cameraManager_->CreateVideoOutput(videoProfile_1, pSurface_1);
    EXPECT_EQ(videoOutput, nullptr);

    // format is CAMERA_FORMAT_INVALID
    videoFormat = CAMERA_FORMAT_INVALID;
    videoSize.width = VIDEO_DEFAULT_WIDTH;
    videoProfile_1 = VideoProfile(videoFormat, videoSize, framerates);

    videoOutput = cameraManager_->CreateVideoOutput(videoProfile_1, pSurface_1);
    EXPECT_EQ(videoOutput, nullptr);
}

/*
 * Feature: Camera base function
 * Function: Test the capture session with Video Stabilization Mode.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the capture session with Video Stabilization Mode.
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_076, TestSize.Level1)
{
    VideoStabilizationMode stabilizationMode = OFF;
    EXPECT_EQ(captureSession_->GetActiveVideoStabilizationMode(), OFF);
    EXPECT_EQ(captureSession_->SetVideoStabilizationMode(stabilizationMode), SESSION_NOT_CONFIG);
    EXPECT_EQ(captureSession_->GetActiveVideoStabilizationMode(stabilizationMode), SESSION_NOT_CONFIG);

    bool isSupported = true;
    EXPECT_EQ(captureSession_->IsVideoStabilizationModeSupported(stabilizationMode, isSupported), SESSION_NOT_CONFIG);
    std::vector<VideoStabilizationMode> videoStabilizationModes;
    EXPECT_EQ(captureSession_->GetSupportedStabilizationMode().empty(), true);
    EXPECT_EQ(captureSession_->GetSupportedStabilizationMode(videoStabilizationModes), SESSION_NOT_CONFIG);

    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    videoStabilizationModes = captureSession_->GetSupportedStabilizationMode();
    if (videoStabilizationModes.empty()) {
        GTEST_SKIP();
    }
    stabilizationMode = videoStabilizationModes.back();
    if (captureSession_->IsVideoStabilizationModeSupported(stabilizationMode)) {
        captureSession_->SetVideoStabilizationMode(stabilizationMode);
        EXPECT_EQ(captureSession_->GetActiveVideoStabilizationMode(), stabilizationMode);
    }

    StartDefaultCaptureOutput(photoOutput, videoOutput);
    EXPECT_EQ(cameraInput_->Release(), SUCCESS);
    cameraInput_ = nullptr;

    EXPECT_EQ(captureSession_->GetActiveVideoStabilizationMode(), OFF);
    EXPECT_EQ(captureSession_->GetActiveVideoStabilizationMode(stabilizationMode), SUCCESS);
    EXPECT_EQ(captureSession_->GetSupportedStabilizationMode().empty(), true);
    EXPECT_EQ(captureSession_->GetSupportedStabilizationMode(videoStabilizationModes), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test abnormal branches with empty inputDevice
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_077, TestSize.Level1)
{
    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    captureSession_->innerInputDevice_ = nullptr;

    VideoStabilizationMode mode = VideoStabilizationMode::MIDDLE;
    EXPECT_EQ(captureSession_->GetActiveVideoStabilizationMode(mode), SUCCESS);
    std::vector<VideoStabilizationMode> videoStabilizationMode = captureSession_->GetSupportedStabilizationMode();
    EXPECT_EQ(videoStabilizationMode.empty(), true);
    EXPECT_EQ(captureSession_->GetSupportedStabilizationMode(videoStabilizationMode), SUCCESS);

    std::vector<ExposureMode> getSupportedExpModes = captureSession_->GetSupportedExposureModes();
    EXPECT_EQ(getSupportedExpModes.empty(), true);
    EXPECT_EQ(captureSession_->GetSupportedExposureModes(getSupportedExpModes), SUCCESS);
    ExposureMode exposureMode = captureSession_->GetExposureMode();
    EXPECT_EQ(exposureMode, EXPOSURE_MODE_UNSUPPORTED);
    EXPECT_EQ(captureSession_->GetExposureMode(exposureMode), SUCCESS);

    Point exposurePointGet = captureSession_->GetMeteringPoint();
    EXPECT_EQ(exposurePointGet.x, 0);
    EXPECT_EQ(exposurePointGet.y, 0);
    EXPECT_EQ(captureSession_->GetMeteringPoint(exposurePointGet), SUCCESS);

    std::vector<float> getExposureBiasRange = captureSession_->GetExposureBiasRange();
    EXPECT_EQ(getExposureBiasRange.empty(), true);
    EXPECT_EQ(captureSession_->GetExposureBiasRange(getExposureBiasRange), SUCCESS);

    float exposureValue = captureSession_->GetExposureValue();
    EXPECT_EQ(exposureValue, 0);
    EXPECT_EQ(captureSession_->GetExposureValue(exposureValue), SUCCESS);

    captureSession_->LockForControl();
    EXPECT_EQ(captureSession_->SetExposureBias(exposureValue), OPERATION_NOT_ALLOWED);
    captureSession_->UnlockForControl();
    std::vector<FocusMode> getSupportedFocusModes = captureSession_->GetSupportedFocusModes();
    EXPECT_EQ(getSupportedFocusModes.empty(), true);
    EXPECT_EQ(captureSession_->GetSupportedFocusModes(getSupportedFocusModes), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test abnormal branches with empty innerInputDevice_
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_078, TestSize.Level1)
{
    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    captureSession_->innerInputDevice_ = nullptr;

    FocusMode focusMode = captureSession_->GetFocusMode();
    EXPECT_EQ(focusMode, FOCUS_MODE_MANUAL);
    EXPECT_EQ(captureSession_->GetFocusMode(focusMode), SUCCESS);

    Point focusPoint = captureSession_->GetFocusPoint();
    EXPECT_EQ(focusPoint.x, 0);
    EXPECT_EQ(focusPoint.y, 0);
    EXPECT_EQ(captureSession_->GetFocusPoint(focusPoint), SUCCESS);

    float focalLength = captureSession_->GetFocalLength();
    EXPECT_EQ(focalLength, 0);
    EXPECT_EQ(captureSession_->GetFocalLength(focalLength), SUCCESS);

    std::vector<FlashMode> getSupportedFlashModes = captureSession_->GetSupportedFlashModes();
    EXPECT_EQ(getSupportedFlashModes.empty(), true);

    EXPECT_EQ(captureSession_->GetSupportedFlashModes(getSupportedFlashModes), SUCCESS);
    FlashMode flashMode = captureSession_->GetFlashMode();
    EXPECT_EQ(flashMode, FLASH_MODE_CLOSE);
    EXPECT_EQ(captureSession_->GetFlashMode(flashMode), SUCCESS);

    std::vector<float> zoomRatioRange = captureSession_->GetZoomRatioRange();
    EXPECT_EQ(zoomRatioRange.empty(), true);
    EXPECT_EQ(captureSession_->GetZoomRatioRange(zoomRatioRange), SUCCESS);

    float zoomRatio = captureSession_->GetZoomRatio();
    EXPECT_EQ(zoomRatio, 0);
    EXPECT_EQ(captureSession_->GetZoomRatio(zoomRatio), 0);

    captureSession_->LockForControl();
    EXPECT_EQ(captureSession_->SetZoomRatio(zoomRatio), SUCCESS);
    EXPECT_EQ(captureSession_->SetMeteringPoint(focusPoint), SUCCESS);
    captureSession_->UnlockForControl();
}

/*
 * Feature: Camera base function
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test stream_ null with anomalous branch
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_079, TestSize.Level1)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<PhotoOutput> photoOutput = CreatePhotoOutput(photoProfiles_[0]);
    ASSERT_NE(photoOutput, nullptr);
    sptr<VideoOutput> videoOutput = CreateVideoOutput(videoProfiles_[0]);
    ASSERT_NE(videoOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)photoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)videoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    previewOutput->Release();
    previewOutput->SetSession(captureSession_);
    photoOutput->Release();
    photoOutput->SetSession(captureSession_);
    videoOutput->Release();
    videoOutput->SetSession(captureSession_);

    auto callback = std::make_shared<TestPhotoOutputCallback>("");
    photoOutput->SetCallback(callback);

    EXPECT_EQ(previewOutput->Start(), SERVICE_FATL_ERROR);
    std::shared_ptr<PhotoCaptureSetting> photoSetting = std::make_shared<PhotoCaptureSetting>();
    EXPECT_EQ(photoOutput->Capture(photoSetting), SERVICE_FATL_ERROR);
    EXPECT_EQ(photoOutput->Capture(), SERVICE_FATL_ERROR);
    EXPECT_EQ(photoOutput->CancelCapture(), SERVICE_FATL_ERROR);
    EXPECT_EQ(videoOutput->Start(), SERVICE_FATL_ERROR);
}

/*
 * Feature: Camera base function
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test stream_ null with anomalous branch
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_080, TestSize.Level1)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<MetadataOutput> metadataOutput = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(metadataOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)metadataOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    metadataOutput->Release();
    metadataOutput->SetSession(captureSession_);

    EXPECT_EQ(metadataOutput->Start(), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test cameraObj null with anomalous branch
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_081, TestSize.Level1)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<PhotoOutput> photoOutput = CreatePhotoOutput(photoProfiles_[0]);
    ASSERT_NE(photoOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)photoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    EXPECT_EQ(cameraInput_->Close(), SUCCESS);
    cameraInput_ = nullptr;
    photoOutput->SetSession(captureSession_);

    EXPECT_EQ(photoOutput->IsMirrorSupported(), false);
    EXPECT_EQ(photoOutput->IsQuickThumbnailSupported(), SESSION_NOT_RUNNING);
    EXPECT_EQ(photoOutput->SetThumbnail(false), SESSION_NOT_RUNNING);
}

/*
 * Feature: Camera base function
 * Function: Test anomalous branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test PreviewOutput/PhotoOutput/VideoOutput Getstream branch with CaptureOutput nullptr.
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_082, TestSize.Level1)
{
    std::shared_ptr<PhotoCaptureSetting> photoSetting = std::make_shared<PhotoCaptureSetting>();
    auto previewOutputCallback = std::make_shared<TestPreviewOutputCallback>("");
    auto photoOutputCallback = std::make_shared<TestPhotoOutputCallback>("");
    auto videoOutputCallback = std::make_shared<TestVideoOutputCallback>("");

    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<PhotoOutput> photoOutput = CreatePhotoOutput(photoProfiles_[0]);
    ASSERT_NE(photoOutput, nullptr);
    sptr<VideoOutput> videoOutput = CreateVideoOutput(videoProfiles_[0]);
    ASSERT_NE(videoOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)photoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)videoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    sptr<VideoOutput> videoOutput_1 = (sptr<VideoOutput>&)videoOutput;
    sptr<PhotoOutput> photoOutput_1 = (sptr<PhotoOutput>&)photoOutput;
    sptr<PreviewOutput> previewOutput_1 = (sptr<PreviewOutput>&)previewOutput;

    photoOutput->Release();
    photoOutput_1->SetSession(captureSession_);
    EXPECT_EQ(photoOutput_1->Capture(photoSetting), SERVICE_FATL_ERROR);
    EXPECT_EQ(photoOutput_1->Capture(), SERVICE_FATL_ERROR);
    EXPECT_EQ(photoOutput_1->CancelCapture(), SERVICE_FATL_ERROR);
    photoOutput_1->SetCallback(photoOutputCallback);

    previewOutput->Release();
    previewOutput_1->SetSession(captureSession_);
    EXPECT_EQ(previewOutput_1->Start(), SERVICE_FATL_ERROR);
    EXPECT_EQ(previewOutput_1->Stop(), SERVICE_FATL_ERROR);
    previewOutput_1->SetCallback(previewOutputCallback);

    videoOutput->Release();
    videoOutput_1->SetSession(captureSession_);
    EXPECT_EQ(videoOutput_1->Start(), SERVICE_FATL_ERROR);
    EXPECT_EQ(videoOutput_1->Stop(), SERVICE_FATL_ERROR);
    EXPECT_EQ(videoOutput_1->Resume(), SERVICE_FATL_ERROR);
    EXPECT_EQ(videoOutput_1->Pause(), SERVICE_FATL_ERROR);
    videoOutput_1->SetCallback(videoOutputCallback);
}

/*
 * Feature: Camera base function
 * Function: Test anomalous branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsSessionCommited branch with capturesession object null.
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_083, TestSize.Level1)
{
    EXPECT_EQ(captureSession_->Start(), SESSION_NOT_CONFIG);

    VideoStabilizationMode mode;
    EXPECT_EQ(captureSession_->GetActiveVideoStabilizationMode(mode), SESSION_NOT_CONFIG);
    EXPECT_EQ(captureSession_->SetVideoStabilizationMode(OFF), SESSION_NOT_CONFIG);

    bool isSupported;
    EXPECT_EQ(captureSession_->IsVideoStabilizationModeSupported(OFF, isSupported), SESSION_NOT_CONFIG);
    EXPECT_EQ((captureSession_->GetSupportedStabilizationMode()).empty(), true);

    std::vector<VideoStabilizationMode> stabilizationModes = {};
    EXPECT_EQ(captureSession_->GetSupportedStabilizationMode(stabilizationModes), SESSION_NOT_CONFIG);
    EXPECT_EQ(captureSession_->IsExposureModeSupported(EXPOSURE_MODE_AUTO, isSupported), SESSION_NOT_CONFIG);
    EXPECT_EQ((captureSession_->GetSupportedExposureModes()).empty(), true);

    std::vector<ExposureMode> supportedExposureModes = {};
    EXPECT_EQ(captureSession_->GetSupportedExposureModes(supportedExposureModes), SESSION_NOT_CONFIG);
    EXPECT_EQ(captureSession_->SetExposureMode(EXPOSURE_MODE_AUTO), SESSION_NOT_CONFIG);
    EXPECT_EQ(captureSession_->GetExposureMode(), EXPOSURE_MODE_UNSUPPORTED);

    ExposureMode exposureMode;
    EXPECT_EQ(captureSession_->GetExposureMode(exposureMode), SESSION_NOT_CONFIG);

    Point exposurePointGet = captureSession_->GetMeteringPoint();
    EXPECT_EQ(captureSession_->SetMeteringPoint(exposurePointGet), SESSION_NOT_CONFIG);

    EXPECT_EQ((captureSession_->GetMeteringPoint()).x, 0);
    EXPECT_EQ((captureSession_->GetMeteringPoint()).y, 0);

    EXPECT_EQ(captureSession_->GetMeteringPoint(exposurePointGet), SESSION_NOT_CONFIG);
    EXPECT_EQ((captureSession_->GetExposureBiasRange()).empty(), true);

    std::vector<float> exposureBiasRange = {};
    EXPECT_EQ(captureSession_->GetExposureBiasRange(exposureBiasRange), SESSION_NOT_CONFIG);
    EXPECT_EQ(captureSession_->SetExposureBias(0), SESSION_NOT_CONFIG);
    captureSession_->Release();
    captureSession_ = nullptr;
}

/*
 * Feature: Camera base function
 * Function: Test anomalous branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsSessionCommited branch with capturesession object null.
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_084, TestSize.Level1)
{
    float exposureValue;
    EXPECT_EQ(captureSession_->GetExposureValue(), 0);
    EXPECT_EQ(captureSession_->GetExposureValue(exposureValue), SESSION_NOT_CONFIG);
    EXPECT_EQ((captureSession_->GetSupportedFocusModes()).empty(), true);

    std::vector<FocusMode> supportedFocusModes;
    EXPECT_EQ(captureSession_->GetSupportedFocusModes(supportedFocusModes), SESSION_NOT_CONFIG);

    bool isSupported;
    EXPECT_EQ(captureSession_->IsFocusModeSupported(FOCUS_MODE_AUTO, isSupported), SESSION_NOT_CONFIG);
    EXPECT_EQ(captureSession_->SetFocusMode(FOCUS_MODE_AUTO), SESSION_NOT_CONFIG);
    EXPECT_EQ(captureSession_->GetFocusMode(), FOCUS_MODE_MANUAL);

    FocusMode focusMode;
    EXPECT_EQ(captureSession_->GetFocusMode(focusMode), SESSION_NOT_CONFIG);

    Point exposurePointGet = captureSession_->GetMeteringPoint();
    EXPECT_EQ(captureSession_->SetFocusPoint(exposurePointGet), SESSION_NOT_CONFIG);

    EXPECT_EQ((captureSession_->GetFocusPoint()).x, 0);
    EXPECT_EQ((captureSession_->GetFocusPoint()).y, 0);

    Point focusPoint;
    EXPECT_EQ(captureSession_->GetFocusPoint(focusPoint), SESSION_NOT_CONFIG);
    EXPECT_EQ(captureSession_->GetFocalLength(), 0);

    float focalLength;
    EXPECT_EQ(captureSession_->GetFocalLength(focalLength), SESSION_NOT_CONFIG);
    EXPECT_EQ((captureSession_->GetSupportedFlashModes()).empty(), true);

    std::vector<FlashMode> supportedFlashModes;
    EXPECT_EQ(captureSession_->GetSupportedFlashModes(supportedFlashModes), SESSION_NOT_CONFIG);
    EXPECT_EQ(captureSession_->GetFlashMode(), FLASH_MODE_CLOSE);

    FlashMode flashMode;
    EXPECT_EQ(captureSession_->GetFlashMode(flashMode), SESSION_NOT_CONFIG);
    EXPECT_EQ(captureSession_->SetFlashMode(FLASH_MODE_CLOSE), SESSION_NOT_CONFIG);
    EXPECT_EQ(captureSession_->IsFlashModeSupported(FLASH_MODE_CLOSE, isSupported), SESSION_NOT_CONFIG);
    EXPECT_EQ(captureSession_->HasFlash(isSupported), SESSION_NOT_CONFIG);
    EXPECT_EQ((captureSession_->GetZoomRatioRange()).empty(), true);

    std::vector<float> exposureBiasRange = {};
    EXPECT_EQ(captureSession_->GetZoomRatioRange(exposureBiasRange), SESSION_NOT_CONFIG);
    EXPECT_EQ(captureSession_->GetZoomRatio(), 0);

    float zoomRatio;
    EXPECT_EQ(captureSession_->GetZoomRatio(zoomRatio), SESSION_NOT_CONFIG);
    EXPECT_EQ(captureSession_->SetZoomRatio(0), SESSION_NOT_CONFIG);
}

/*
 * Feature: Camera base function
 * Function: Test !IsSessionCommited() && !IsSessionConfiged()
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test IsSessionCommited() || IsSessionConfiged() with abnormal branches in CaptureSession
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_085, TestSize.Level0)
{
    EXPECT_EQ((captureSession_->GetSupportedColorEffects()).empty(), true);
    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->GetFilter(), FilterType::NONE);
    EXPECT_EQ(captureSession_->GetSupportedFilters().empty(), true);
    EXPECT_EQ(captureSession_->GetSupportedBeautyTypes().empty(), true);
    captureSession_->SetBeauty(AUTO_TYPE, 0);
    EXPECT_EQ(captureSession_->GetBeauty(AUTO_TYPE), -1);
    captureSession_->SetFilter(NONE);
    captureSession_->SetColorSpace(COLOR_SPACE_UNKNOWN);
    EXPECT_EQ(ServiceToCameraError(captureSession_->VerifyAbility(0)), SERVICE_FATL_ERROR);

    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);
    captureSession_->SetBeauty(AUTO_TYPE, 0);
    EXPECT_EQ(captureSession_->GetBeauty(AUTO_TYPE), -1);
    captureSession_->SetFilter(NONE);
    captureSession_->SetColorSpace(COLOR_SPACE_UNKNOWN);
}

/*
 * Feature: Camera base function
 * Function: Test !IsSessionCommited() && !IsSessionConfiged()
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test IsSessionCommited() || IsSessionConfiged() with abnormal branches in CaptureSession
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_086, TestSize.Level0)
{
    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);

    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), 0);

    captureSession_->innerInputDevice_ = nullptr;

    EXPECT_EQ(captureSession_->GetSupportedFilters().empty(), true);
    EXPECT_EQ(captureSession_->GetFilter(), FilterType::NONE);
    EXPECT_EQ(captureSession_->GetSupportedBeautyTypes().empty(), true);

    BeautyType beautyType = AUTO_TYPE;
    EXPECT_EQ(captureSession_->GetSupportedBeautyRange(beautyType).empty(), true);
    EXPECT_EQ(captureSession_->GetBeauty(beautyType), -1);
    EXPECT_EQ(captureSession_->GetColorEffect(), ColorEffect::COLOR_EFFECT_NORMAL);
    EXPECT_EQ(captureSession_->GetSupportedColorEffects().empty(), true);
}

/*
 * Feature: Camera base function
 * Function: Test !IsSessionCommited() && !IsSessionConfiged()
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test IsSessionCommited() || IsSessionConfiged() with abnormal branches in CaptureSession
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_087, TestSize.Level1)
{
    EXPECT_EQ(captureSession_->GetSupportedFilters().empty(), true);
    EXPECT_EQ(captureSession_->GetFilter(), FilterType::NONE);
    EXPECT_EQ(captureSession_->GetSupportedBeautyTypes().empty(), true);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), 0);
    EXPECT_EQ(captureSession_->GetSupportedFilters().empty(), true);
    EXPECT_EQ(captureSession_->GetFilter(), FilterType::NONE);
    EXPECT_EQ(captureSession_->GetSupportedBeautyTypes().empty(), true);
    EXPECT_EQ(captureSession_->CommitConfig(), 0);

    captureSession_->innerInputDevice_ = nullptr;
    EXPECT_EQ(captureSession_->GetSupportedFilters().empty(), true);
    EXPECT_EQ(captureSession_->GetFilter(), FilterType::NONE);
    EXPECT_EQ(captureSession_->GetSupportedBeautyTypes().empty(), true);
}

/*
 * Feature: Camera base function
 * Function: Test !IsSessionCommited() && !IsSessionConfiged()
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test Commited() || Configed() with abnormal branches in CaptureSession in CaptureSession
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_088, TestSize.Level1)
{
    ColorSpace colorSpace = COLOR_SPACE_UNKNOWN;
    EXPECT_EQ(captureSession_->GetSupportedFilters().empty(), true);
    EXPECT_EQ(captureSession_->GetFilter(), FilterType::NONE);
    EXPECT_EQ(captureSession_->GetSupportedBeautyTypes().empty(), true);
    BeautyType beautyType = AUTO_TYPE;
    EXPECT_EQ(captureSession_->GetSupportedBeautyRange(beautyType).empty(), true);
    EXPECT_EQ(captureSession_->GetBeauty(AUTO_TYPE), CameraErrorCode::SESSION_NOT_CONFIG);
    EXPECT_EQ(captureSession_->GetColorEffect(), ColorEffect::COLOR_EFFECT_NORMAL);
    EXPECT_EQ(captureSession_->GetSupportedColorEffects().empty(), true);
    captureSession_->SetFilter(NONE);
    captureSession_->SetBeauty(beautyType, 0);
    EXPECT_EQ(captureSession_->GetSupportedColorSpaces().empty(), true);
    EXPECT_EQ(captureSession_->SetColorSpace(COLOR_SPACE_UNKNOWN), CameraErrorCode::SESSION_NOT_CONFIG);
    captureSession_->SetMode(SceneMode::NORMAL);
    EXPECT_EQ(ServiceToCameraError(captureSession_->VerifyAbility(0)), SERVICE_FATL_ERROR);
    EXPECT_EQ(captureSession_->GetActiveColorSpace(colorSpace), CameraErrorCode::SESSION_NOT_CONFIG);
    captureSession_->SetColorEffect(COLOR_EFFECT_NORMAL);
    captureSession_->Release();
    captureSession_ = nullptr;
}

/*
 * Feature: Camera base function
 * Function: Test !IsSessionCommited() && !IsSessionConfiged()
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test IsSessionCommited() || IsSessionConfiged() with abnormal branches in CaptureSession
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_089, TestSize.Level1)
{
    ColorSpace colorSpace = COLOR_SPACE_UNKNOWN;
    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    captureSession_->SetMode(SceneMode::PORTRAIT);
    EXPECT_EQ(ServiceToCameraError(captureSession_->VerifyAbility(0)), SERVICE_FATL_ERROR);
    EXPECT_EQ(captureSession_->GetActiveColorSpace(colorSpace), SUCCESS);
    captureSession_->SetColorEffect(COLOR_EFFECT_NORMAL);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);
    if (captureSession_->IsMacroSupported()) {
        captureSession_->LockForControl();
        EXPECT_EQ(captureSession_->EnableMacro(false), SUCCESS);
        captureSession_->UnlockForControl();
    }
    EXPECT_EQ(captureSession_->GetActiveColorSpace(colorSpace), SUCCESS);
    captureSession_->SetColorEffect(COLOR_EFFECT_NORMAL);
    captureSession_->innerInputDevice_ = nullptr;
    EXPECT_EQ(ServiceToCameraError(captureSession_->VerifyAbility(0)), SERVICE_FATL_ERROR);
}

/*
 * Feature: Camera base function
 * Function: Test !IsSessionCommited() && !IsSessionConfiged()
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test !IsSessionCommited() && !IsSessionConfiged() with abnormal branches in CaptureSession
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_090, TestSize.Level1)
{
    BeautyType beautyType = AUTO_TYPE;
    EXPECT_EQ(captureSession_->GetSupportedBeautyRange(beautyType).empty(), true);
    EXPECT_EQ(captureSession_->GetBeauty(beautyType), CameraErrorCode::SESSION_NOT_CONFIG);
    EXPECT_EQ(captureSession_->GetColorEffect(), ColorEffect::COLOR_EFFECT_NORMAL);
    EXPECT_EQ(captureSession_->GetSupportedColorEffects().empty(), true);
    EXPECT_EQ(captureSession_->GetSupportedColorSpaces().empty(), true);
    captureSession_->SetBeauty(beautyType, 0);
    captureSession_->SetFilter(NONE);
    EXPECT_EQ(captureSession_->SetColorSpace(COLOR_SPACE_UNKNOWN), SESSION_NOT_CONFIG);
    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    captureSession_->GetSupportedBeautyRange(beautyType);
    captureSession_->GetBeauty(beautyType);
    captureSession_->GetColorEffect();
    captureSession_->SetBeauty(beautyType, 0);
    captureSession_->SetFilter(NONE);
    captureSession_->SetColorSpace(COLOR_SPACE_UNKNOWN);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);
    captureSession_->innerInputDevice_ = nullptr;
    captureSession_->GetSupportedBeautyRange(beautyType).empty();
    captureSession_->GetBeauty(beautyType);
    captureSession_->GetColorEffect();
    captureSession_->GetSupportedColorEffects().empty();
    captureSession_->GetSupportedColorSpaces().empty();
    captureSession_->SetBeauty(beautyType, 0);
    captureSession_->SetFilter(NONE);
    captureSession_->SetColorSpace(COLOR_SPACE_UNKNOWN);
}

/*
 * Feature: Camera base function
 * Function: Test errorCode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test IsSessionCommited() || IsSessionConfiged() with abnormal branches
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_091, TestSize.Level0)
{
    sptr<PhotoOutput> photoOutput1 = CreatePhotoOutput(photoProfiles_[0]);
    ASSERT_NE(photoOutput1, nullptr);
    auto photoOutput = static_cast<PhotoOutput*>(photoOutput1.GetRefPtr());
    photoOutput->ConfirmCapture();
    photoOutput->SetSession(nullptr);
    photoOutput->ConfirmCapture();
    photoOutput->SetSession(captureSession_);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);
    photoOutput->ConfirmCapture();
}

/*
 * Feature: Camera base function
 * Function: Test anomalous branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetMetaSetting with existing metaTag.
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_092, TestSize.Level1)
{
    sptr<CameraInput> camInput = (sptr<CameraInput>&)cameraInput_;

    std::shared_ptr<camera_metadata_item_t> metadataItem = nullptr;
    metadataItem = camInput->GetMetaSetting(OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS);
    ASSERT_NE(metadataItem, nullptr);

    std::vector<vendorTag_t> infos = {};
    camInput->GetCameraAllVendorTags(infos);

    sptr<ICameraDeviceService> deviceObj = camInput->GetCameraDevice();
    ASSERT_NE(deviceObj, nullptr);

    sptr<CameraDevice> camdeviceObj = nullptr;
    sptr<CameraInput> camInput_1 = new (std::nothrow) CameraInput(deviceObj, camdeviceObj);
    ASSERT_NE(camInput_1, nullptr);

    metadataItem = camInput_1->GetMetaSetting(OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS);
    EXPECT_EQ(metadataItem, nullptr);

    metadataItem = camInput->GetMetaSetting(-1);
    EXPECT_EQ(metadataItem, nullptr);

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameraDevices_[0]->GetMetadata();

    std::string cameraId = cameraDevices_[0]->GetID();
    sptr<CameraDevice> camdeviceObj_2 = new (std::nothrow) CameraDevice(cameraId, metadata);
    ASSERT_NE(camdeviceObj_2, nullptr);
}

/*
 * Feature: Camera base function
 * Function: Test anomalous branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Torch with anomalous branch.
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_093, TestSize.Level1)
{
    EXPECT_EQ(cameraInput_->Close(), SUCCESS);
    cameraInput_ = nullptr;
    WAIT(DURATION_AFTER_DEVICE_CLOSE);
    if (!(cameraManager_->IsTorchSupported())) {
        GTEST_SKIP();
    }

    sptr<CameraManager> camManagerObj = CameraManager::GetInstance();
    auto torchCallback = std::make_shared<TestTorchListener>();
    camManagerObj->RegisterTorchListener(torchCallback);
    EXPECT_EQ(camManagerObj->IsTorchModeSupported(TORCH_MODE_AUTO), false);
    EXPECT_EQ(camManagerObj->SetTorchMode(TORCH_MODE_AUTO), OPERATION_NOT_ALLOWED);

    EXPECT_EQ(camManagerObj->IsTorchModeSupported(TORCH_MODE_ON), true);
    EXPECT_EQ(camManagerObj->SetTorchMode(TORCH_MODE_ON), SUCCESS);
    WAIT(DURATION_WAIT_CALLBACK);

    EXPECT_EQ(camManagerObj->IsTorchModeSupported(TORCH_MODE_OFF), true);
    EXPECT_EQ(camManagerObj->SetTorchMode(TORCH_MODE_OFF), SUCCESS);
    WAIT(DURATION_WAIT_CALLBACK);

    camManagerObj->SetServiceProxy(nullptr);
    EXPECT_EQ(camManagerObj->SetTorchMode(TORCH_MODE_OFF), SERVICE_FATL_ERROR);

    camManagerObj->InitCameraManager();
}

/*
 * Feature: Camera base function
 * Function: Test Metadata
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Metadata
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_094, TestSize.Level1)
{
    EXPECT_EQ(captureSession_->BeginConfig(), 0);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);

    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);

    sptr<CaptureOutput> metadatOutput = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(metadatOutput, nullptr);
    EXPECT_EQ(captureSession_->AddOutput(metadatOutput), SUCCESS);

    sptr<MetadataOutput> metaOutput = (sptr<MetadataOutput>&)metadatOutput;
    std::vector<MetadataObjectType> metadataObjectTypes = metaOutput->GetSupportedMetadataObjectTypes();
    if (metadataObjectTypes.size() == 0) {
        GTEST_SKIP();
    }

    metaOutput->SetCapturingMetadataObjectTypes(std::vector<MetadataObjectType> { MetadataObjectType::FACE });

    std::shared_ptr<MetadataObjectCallback> metadataObjectCallback =
        std::make_shared<TestMetadataOutputObjectCallback>("");
    metaOutput->SetCallback(metadataObjectCallback);
    std::shared_ptr<MetadataStateCallback> metadataStateCallback =
        std::make_shared<TestMetadataStateCallback>();
    metaOutput->SetCallback(metadataStateCallback);

    pid_t pid = 0;
    metaOutput->CameraServerDied(pid);
}

/*
 * Feature: Camera base function
 * Function: Test Metadata
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Metadata
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_095, TestSize.Level1)
{
    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);

    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);

    sptr<CaptureOutput> metadatOutput = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(metadatOutput, nullptr);
    EXPECT_EQ(captureSession_->AddOutput(metadatOutput), 0);

    sptr<MetadataOutput> metaOutput = (sptr<MetadataOutput>&)metadatOutput;
    std::vector<MetadataObjectType> metadataObjectTypes = metaOutput->GetSupportedMetadataObjectTypes();
    if (metadataObjectTypes.size() == 0) {
        GTEST_SKIP();
    }

    metaOutput->SetCapturingMetadataObjectTypes(std::vector<MetadataObjectType> {});
}


/*
 * Feature: Camera base function
 * Function: Test the capture session with HighQualityPhoto.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the capture session with HighQualityPhoto.
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_096, TestSize.Level1)
{
    EXPECT_EQ(captureSession_->EnableAutoHighQualityPhoto(false), SUCCESS);

    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    EXPECT_EQ(captureSession_->EnableAutoHighQualityPhoto(true), SUCCESS);
    int32_t isSupported = false;
    EXPECT_EQ(photoOutput->IsAutoHighQualityPhotoSupported(isSupported), SUCCESS);
    EXPECT_EQ(photoOutput->EnableAutoHighQualityPhoto(true), INVALID_ARGUMENT);

    StartDefaultCaptureOutput(photoOutput, videoOutput);

    EXPECT_EQ(photoOutput->Release(), SUCCESS);
    EXPECT_EQ(photoOutput->IsAutoHighQualityPhotoSupported(isSupported), SESSION_NOT_RUNNING);
    EXPECT_EQ(photoOutput->EnableAutoHighQualityPhoto(true), SESSION_NOT_RUNNING);
}

/*
 * Feature: Camera base function
 * Function: Test camera rotation func.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test camera rotation func.
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_097, TestSize.Level0)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<PhotoOutput> photoOutput = CreatePhotoOutput(photoProfiles_[0]);
    ASSERT_NE(photoOutput, nullptr);
    sptr<VideoOutput> videoOutput = CreateVideoOutput(videoProfiles_[0]);
    ASSERT_NE(videoOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)photoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)videoOutput), SUCCESS);

    int32_t previewRotation = previewOutput->GetPreviewRotation(PhotoCaptureSetting::RotationConfig::Rotation_0);
    int32_t videoRotation = videoOutput->GetVideoRotation(PhotoCaptureSetting::RotationConfig::Rotation_90);
    int32_t photoRotation = photoOutput->GetPhotoRotation(PhotoCaptureSetting::RotationConfig::Rotation_180);
    EXPECT_EQ(videoRotation, PhotoCaptureSetting::RotationConfig::Rotation_180);
    EXPECT_EQ(previewOutput->SetPreviewRotation(previewRotation, false), SUCCESS);
    std::shared_ptr<PhotoCaptureSetting> photoSetting = std::make_shared<PhotoCaptureSetting>();
    photoSetting->SetRotation(static_cast<PhotoCaptureSetting::RotationConfig>(photoRotation));

    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    EXPECT_EQ(videoOutput->Start(), SUCCESS);
    WAIT(DURATION_DURING_RECORDING);
    EXPECT_EQ(photoOutput->Capture(photoSetting), SUCCESS);
    WAIT(DURATION_AFTER_CAPTURE);
    EXPECT_EQ(videoOutput->Stop(), SUCCESS);
    WAIT(DURATION_AFTER_RECORDING);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test snapshot.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test snapshot.
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_098, TestSize.Level1)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<PhotoOutput> photoOutput = CreatePhotoOutput(photoProfiles_[0]);
    ASSERT_NE(photoOutput, nullptr);
    sptr<VideoOutput> videoOutput = CreateVideoOutput(videoProfiles_[0]);
    ASSERT_NE(videoOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)photoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)videoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    EXPECT_EQ(videoOutput->Start(), SUCCESS);
    WAIT(DURATION_DURING_RECORDING);
    EXPECT_EQ(photoOutput->Capture(), SUCCESS);
    WAIT(DURATION_AFTER_CAPTURE);
    EXPECT_EQ(videoOutput->Stop(), SUCCESS);
    WAIT(DURATION_AFTER_RECORDING);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test snapshot with location setting.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test snapshot with location setting.
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_099, TestSize.Level1)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<PhotoOutput> photoOutput = CreatePhotoOutput(photoProfiles_[0]);
    ASSERT_NE(photoOutput, nullptr);
    sptr<VideoOutput> videoOutput = CreateVideoOutput(videoProfiles_[0]);
    ASSERT_NE(videoOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)photoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)videoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);

    std::shared_ptr<PhotoCaptureSetting> photoSetting = std::make_shared<PhotoCaptureSetting>();
    std::shared_ptr<Location> location = std::make_shared<Location>();
    location->latitude = 12.972442;
    location->longitude = 77.580643;
    location->altitude = 0;
    photoSetting->SetLocation(location);

    EXPECT_EQ(videoOutput->Start(), SUCCESS);
    WAIT(DURATION_DURING_RECORDING);
    EXPECT_EQ(photoOutput->Capture(photoSetting), SUCCESS);
    WAIT(DURATION_AFTER_CAPTURE);
    EXPECT_EQ(videoOutput->Stop(), SUCCESS);
    WAIT(DURATION_AFTER_RECORDING);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test snapshot with mirror setting.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test snapshot with mirror setting.
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_100, TestSize.Level0)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<PhotoOutput> photoOutput = CreatePhotoOutput(photoProfiles_[0]);
    ASSERT_NE(photoOutput, nullptr);
    sptr<VideoOutput> videoOutput = CreateVideoOutput(videoProfiles_[0]);
    ASSERT_NE(videoOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)photoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)videoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    EXPECT_EQ(videoOutput->Start(), SUCCESS);
    WAIT(DURATION_DURING_RECORDING);
    EXPECT_EQ(photoOutput->Capture(), SUCCESS);
    WAIT(DURATION_AFTER_CAPTURE);
    EXPECT_EQ(videoOutput->Stop(), SUCCESS);
    WAIT(DURATION_AFTER_RECORDING);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);

    if (cameraDevices_.size() <= 1) {
        MEDIA_ERR_LOG("The current device only has a camera and cannot switch cameras");
        GTEST_SKIP();
    }
    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->RemoveInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->RemoveOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->RemoveOutput((sptr<CaptureOutput>&)photoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->RemoveOutput((sptr<CaptureOutput>&)videoOutput), SUCCESS);
    EXPECT_EQ(cameraInput_->Release(), SUCCESS);
    cameraInput_ = nullptr;
    WAIT(DURATION_AFTER_DEVICE_CLOSE);

    sptr<CameraInput> frontCameraInput = cameraManager_->CreateCameraInput(cameraDevices_[deviceFrontIndex]);
    ASSERT_NE(frontCameraInput, nullptr);
    EXPECT_EQ(frontCameraInput->Open(), SUCCESS);
    UpdateCameraOutputCapability(deviceFrontIndex);

    Profile profile;
    profile.size_ = {PRVIEW_WIDTH_640, PRVIEW_HEIGHT_480};
    profile.format_ = CAMERA_FORMAT_YUV_420_SP;
    sptr<PreviewOutput> frontPreviewOutput = CreatePreviewOutput(profile);
    ASSERT_NE(frontPreviewOutput, nullptr);
    sptr<PhotoOutput> frontPhotoOutput = CreatePhotoOutput(photoProfiles_[0]);
    ASSERT_NE(frontPhotoOutput, nullptr);
    sptr<VideoOutput> frontVideoOutput = CreateVideoOutput(videoProfiles_[0]);
    ASSERT_NE(frontVideoOutput, nullptr);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)frontCameraInput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)frontPreviewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)frontPhotoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)frontVideoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    EXPECT_EQ(captureSession_->Start(), SUCCESS);
    WAIT(DURATION_AFTER_SESSION_START);
    EXPECT_EQ(frontVideoOutput->Start(), SUCCESS);
    WAIT(DURATION_DURING_RECORDING);
    if (frontPhotoOutput->IsMirrorSupported()) {
        std::shared_ptr<PhotoCaptureSetting> photoSetting = std::make_shared<PhotoCaptureSetting>();
        photoSetting->SetMirror(true);
        EXPECT_EQ(frontPhotoOutput->Capture(photoSetting), SUCCESS);
    } else {
        EXPECT_EQ(frontPhotoOutput->Capture(), SUCCESS);
    }
    WAIT(DURATION_AFTER_CAPTURE);
    EXPECT_EQ(frontVideoOutput->Stop(), SUCCESS);
    WAIT(DURATION_AFTER_RECORDING);
    EXPECT_EQ(captureSession_->Stop(), SUCCESS);

    EXPECT_EQ(frontCameraInput->Release(), SUCCESS);
    WAIT(DURATION_AFTER_DEVICE_CLOSE);
}

/*
* Feature: Camera base function
* Function: Test SetExposureBias && GetFeaturesMode && SetBeautyValue && GetSubFeatureMods
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: test SetExposureBias && GetFeaturesMode && SetBeautyValue && GetSubFeatureMods
*/
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_101, TestSize.Level1)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    captureSession_->LockForControl();
    EXPECT_EQ(captureSession_->SetExposureBias(100.0f), CameraErrorCode::SUCCESS);
    captureSession_->UnlockForControl();

    captureSession_->isSetMacroEnable_ = true;
    captureSession_->currentMode_ = SceneMode::VIDEO;

    SceneFeaturesMode videoMacroMode(SceneMode::VIDEO, { SceneFeature::FEATURE_MACRO });
    bool isMatchSubFeatureMode = false;
    auto vec = captureSession_->GetSubFeatureMods();
    for (auto& sceneFeaturesMode : vec) {
        if (sceneFeaturesMode == videoMacroMode) {
            isMatchSubFeatureMode = true;
            break;
        }
    }
    EXPECT_TRUE(isMatchSubFeatureMode);

    auto mode = captureSession_->GetFeaturesMode();
    EXPECT_TRUE(mode == videoMacroMode);

    captureSession_->currentMode_ = SceneMode::CAPTURE;
    mode = captureSession_->GetFeaturesMode();
    SceneFeaturesMode captureMacroMode(SceneMode::CAPTURE, { SceneFeature::FEATURE_MACRO });
    EXPECT_TRUE(mode == captureMacroMode);

    isMatchSubFeatureMode = false;
    vec = captureSession_->GetSubFeatureMods();
    for (auto& sceneFeaturesMode : vec) {
        if (sceneFeaturesMode == captureMacroMode) {
            isMatchSubFeatureMode = true;
            break;
        }
    }
    EXPECT_TRUE(isMatchSubFeatureMode);

    bool boolResult = captureSession_->SetBeautyValue(BeautyType::SKIN_TONE, 0);
    EXPECT_FALSE(boolResult);
}

/*
 * Feature: Camera base function
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test service callback with anomalous branch
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_102, TestSize.Level1)
{
    std::string cameraIdtest = "";
    int32_t status = static_cast<int32_t>(FlashStatus::FLASH_STATUS_OFF);

    auto statusListenerManager = cameraManager_->GetCameraStatusListenerManager();
    ASSERT_NE(statusListenerManager, nullptr);
    EXPECT_EQ(statusListenerManager->OnFlashlightStatusChanged(cameraIdtest, status), CAMERA_OK);

    sptr<CameraDeviceServiceCallback> camDeviceSvcCallback = new (std::nothrow) CameraDeviceServiceCallback();
    ASSERT_NE(camDeviceSvcCallback, nullptr);
    EXPECT_EQ(camDeviceSvcCallback->OnError(CAMERA_DEVICE_PREEMPTED, 0), CAMERA_OK);

    std::shared_ptr<OHOS::Camera::CameraMetadata> result = nullptr;
    EXPECT_EQ(camDeviceSvcCallback->OnResult(0, result), CAMERA_INVALID_ARG);

    sptr<ICameraDeviceService> deviceObj = cameraInput_->GetCameraDevice();
    ASSERT_NE(deviceObj, nullptr);

    sptr<CameraDevice> camdeviceObj = nullptr;
    sptr<CameraInput> camInput_1 = new (std::nothrow) CameraInput(deviceObj, camdeviceObj);
    ASSERT_NE(camInput_1, nullptr);

    camDeviceSvcCallback = nullptr;
    camDeviceSvcCallback = new (std::nothrow) CameraDeviceServiceCallback(camInput_1);
    ASSERT_NE(camDeviceSvcCallback, nullptr);
    EXPECT_EQ(camDeviceSvcCallback->OnResult(0, result), CAMERA_INVALID_ARG);

    sptr<CameraInput> camInput_2 = new (std::nothrow) CameraInput(deviceObj, cameraDevices_[0]);
    ASSERT_NE(camInput_2, nullptr);
    camDeviceSvcCallback = nullptr;
    camDeviceSvcCallback = new (std::nothrow) CameraDeviceServiceCallback(camInput_2);
    ASSERT_NE(camDeviceSvcCallback, nullptr);
    EXPECT_EQ(camDeviceSvcCallback->OnError(CAMERA_DEVICE_PREEMPTED, 0), CAMERA_OK);

    auto callback = std::make_shared<TestDeviceCallback>("");
    camInput_2->SetErrorCallback(callback);

    camDeviceSvcCallback = nullptr;
    camDeviceSvcCallback = new (std::nothrow) CameraDeviceServiceCallback(camInput_2);
    ASSERT_NE(camDeviceSvcCallback, nullptr);
    EXPECT_EQ(camDeviceSvcCallback->OnError(CAMERA_DEVICE_PREEMPTED, 0), CAMERA_OK);

    callback = nullptr;
    camInput_2->SetErrorCallback(callback);
}

/*
 * Feature: Camera base function
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test capture session callback error with anomalous branch
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_103, TestSize.Level1)
{
    sptr<CaptureSessionCallback> capSessionCallback = new (std::nothrow) CaptureSessionCallback();
    ASSERT_NE(capSessionCallback, nullptr);
    EXPECT_EQ(capSessionCallback->OnError(CAMERA_DEVICE_PREEMPTED), CAMERA_OK);
    capSessionCallback = nullptr;
    capSessionCallback = new (std::nothrow) CaptureSessionCallback(captureSession_);
    ASSERT_NE(capSessionCallback, nullptr);
    EXPECT_EQ(capSessionCallback->OnError(CAMERA_DEVICE_PREEMPTED), CAMERA_OK);

    std::shared_ptr<TestSessionCallback> callback = nullptr;
    captureSession_->SetCallback(callback);

    callback = std::make_shared<TestSessionCallback>();
    ASSERT_NE(callback, nullptr);
    captureSession_->SetCallback(callback);
    capSessionCallback = nullptr;
    capSessionCallback = new (std::nothrow) CaptureSessionCallback(captureSession_);
    ASSERT_NE(capSessionCallback, nullptr);
    EXPECT_EQ(capSessionCallback->OnError(CAMERA_DEVICE_PREEMPTED), CAMERA_OK);
}

/*
 * Feature: Camera base function
 * Function: Test OnSketchStatusChanged
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test PreviewOutputCallbackImpl:OnSketchStatusChanged with abnormal branches
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_104, TestSize.Level1)
{
    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);

    auto previewOutputListenerManager = previewOutput->GetPreviewOutputListenerManager();
    ASSERT_NE(previewOutputListenerManager, nullptr);
    EXPECT_EQ(previewOutputListenerManager->OnSketchStatusChanged(SketchStatus::STOPED), CAMERA_OK);

    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);
}

/*
 * Feature: Camera base function
 * Function: Test anomalous branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureCallback with anomalous branch.
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_105, TestSize.Level1)
{
    auto captureCallback = std::make_shared<HStreamCaptureCallbackImpl>(nullptr);

    int32_t captureId = 2001;
    EXPECT_EQ(captureCallback->OnCaptureStarted(captureId), CAMERA_OK);
    int32_t frameCount = 0;
    EXPECT_EQ(captureCallback->OnCaptureEnded(captureId, frameCount), CAMERA_OK);
    int32_t errorCode = 0;
    EXPECT_EQ(captureCallback->OnCaptureError(captureId, errorCode), CAMERA_OK);
    uint64_t timestamp = 10;
    EXPECT_EQ(captureCallback->OnFrameShutter(captureId, timestamp), CAMERA_OK);

    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<PhotoOutput> photoOutput = CreatePhotoOutput(photoProfiles_[0]);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)photoOutput), SUCCESS);

    std::shared_ptr<TestPhotoOutputCallback> callback = nullptr;
    photoOutput->SetCallback(callback);

    callback = std::make_shared<TestPhotoOutputCallback>("");
    ASSERT_NE(callback, nullptr);
    photoOutput->SetCallback(callback);
    photoOutput->SetCallback(callback);

    auto captureCallback2 = new (std::nothrow) HStreamCaptureCallbackImpl(photoOutput);
    ASSERT_NE(captureCallback2, nullptr);

    EXPECT_EQ(captureCallback2->OnCaptureEnded(captureId, frameCount), CAMERA_OK);
    EXPECT_EQ(captureCallback2->OnCaptureError(captureId, errorCode), CAMERA_OK);
    EXPECT_EQ(captureCallback2->OnFrameShutter(captureId, timestamp), CAMERA_OK);
}

/*
 * Feature: Camera base function
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test video output repeat callback with anomalous branch
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_106, TestSize.Level1)
{
    auto repeatCallback = std::make_shared<VideoOutputCallbackImpl>();

    EXPECT_EQ(repeatCallback->OnFrameStarted(), CAMERA_OK);
    int32_t frameCount = 0;
    EXPECT_EQ(repeatCallback->OnFrameEnded(frameCount), CAMERA_OK);
    int32_t errorCode = 0;
    EXPECT_EQ(repeatCallback->OnFrameError(errorCode), CAMERA_OK);

    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<VideoOutput> videoOutput = CreateVideoOutput(videoProfiles_[0]);
    ASSERT_NE(videoOutput, nullptr);
    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)videoOutput), SUCCESS);

    std::shared_ptr<TestVideoOutputCallback> callback = nullptr;
    videoOutput->SetCallback(callback);

    callback = std::make_shared<TestVideoOutputCallback>("");
    ASSERT_NE(callback, nullptr);
    videoOutput->SetCallback(callback);
    videoOutput->SetCallback(callback);

    auto repeatCallback2 = new (std::nothrow) VideoOutputCallbackImpl(videoOutput);
    ASSERT_NE(repeatCallback2, nullptr);

    EXPECT_EQ(repeatCallback2->OnFrameStarted(), CAMERA_OK);
    EXPECT_EQ(repeatCallback2->OnFrameEnded(frameCount), CAMERA_OK);
    EXPECT_EQ(repeatCallback2->OnFrameError(errorCode), CAMERA_OK);
}

/*
 * Feature: Camera base function
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test focus distance the camera vwith abnormal setting branch
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_107, TestSize.Level1)
{
    float recnum = 0.0f;
    EXPECT_EQ(captureSession_->GetFocusDistance(recnum), 7400103);
    EXPECT_EQ(recnum, 0.0f);

    captureSession_->LockForControl();
    float num = 1.0f;
    EXPECT_EQ(captureSession_->SetFocusDistance(num), 7400103);
    captureSession_->UnlockForControl();

    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    captureSession_->GetFocusDistance(recnum);
    EXPECT_EQ(recnum, 0.0f);
    captureSession_->LockForControl();
    EXPECT_EQ(captureSession_->SetFocusDistance(num), 0);
    captureSession_->UnlockForControl();
    captureSession_->GetFocusDistance(recnum);
    EXPECT_EQ(recnum, 1.0f);

    EXPECT_EQ(cameraInput_->Release(), SUCCESS);
    cameraInput_ = nullptr;

    EXPECT_EQ(captureSession_->GetFocusDistance(recnum), 0);
}

/*
 * Feature: Camera base function
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test CaptureSession GetZoomPointInfos with abnormal setting branch
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_108, TestSize.Level1)
{
    std::vector<ZoomPointInfo> zoomPointInfolist = {};
    EXPECT_EQ(captureSession_->GetZoomPointInfos(zoomPointInfolist), 7400103);
    EXPECT_EQ(zoomPointInfolist.empty(), true);

    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    EXPECT_EQ(captureSession_->GetZoomPointInfos(zoomPointInfolist), 0);

    EXPECT_EQ(cameraInput_->Release(), SUCCESS);
    cameraInput_ = nullptr;

    EXPECT_EQ(captureSession_->GetZoomPointInfos(zoomPointInfolist), 0);
}

/*
 * Feature: Camera base function
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test CaptureSession GetSensorExposureTime with abnormal setting branch
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_109, TestSize.Level1)
{
    std::vector<uint32_t> exposureTimeRange = {};
    EXPECT_EQ(captureSession_->GetSensorExposureTimeRange(exposureTimeRange), 7400103);
    EXPECT_EQ(exposureTimeRange.empty(), true);

    uint32_t recSensorExposureTime = 0;
    EXPECT_EQ(captureSession_->GetSensorExposureTime(recSensorExposureTime), 7400103);
    EXPECT_EQ(recSensorExposureTime, 0);

    captureSession_->LockForControl();
    uint32_t exposureTime = 1;
    EXPECT_EQ(captureSession_->SetSensorExposureTime(exposureTime), 7400103);
    captureSession_->UnlockForControl();

    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    if (captureSession_->GetSensorExposureTimeRange(exposureTimeRange) == 0) {
        captureSession_->LockForControl();
        EXPECT_EQ(captureSession_->SetSensorExposureTime(exposureTimeRange[0]), 0);
        captureSession_->UnlockForControl();

        EXPECT_EQ(captureSession_->GetSensorExposureTime(recSensorExposureTime), 0);

        EXPECT_EQ(cameraInput_->Release(), SUCCESS);
        cameraInput_ = nullptr;

        EXPECT_EQ(captureSession_->GetSensorExposureTimeRange(exposureTimeRange), 7400101);

        EXPECT_EQ(captureSession_->GetSensorExposureTime(recSensorExposureTime), 7400101);

        captureSession_->LockForControl();
        EXPECT_EQ(captureSession_ ->SetSensorExposureTime(exposureTimeRange[0]), 7400102);
        captureSession_->UnlockForControl();
    }
}

/*
 * Feature: Camera base function
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test focus distance the camera with abnormal setting branch
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_110, TestSize.Level1)
{
    std::vector<WhiteBalanceMode> supportedWhiteBalanceModes = {};
    int32_t intResult = captureSession_->GetSupportedWhiteBalanceModes(supportedWhiteBalanceModes);
    EXPECT_EQ(intResult, 7400103);
    EXPECT_EQ(supportedWhiteBalanceModes.empty(), true);

    bool isSupported = false;
    WhiteBalanceMode currMode = WhiteBalanceMode::AWB_MODE_OFF;
    intResult = captureSession_->IsWhiteBalanceModeSupported(currMode, isSupported);
    EXPECT_EQ(intResult, 7400103);

    captureSession_->LockForControl();
    intResult = captureSession_->SetWhiteBalanceMode(currMode);
    EXPECT_EQ(intResult, 7400103);
    captureSession_->UnlockForControl();

    WhiteBalanceMode retMode;
    intResult = captureSession_->GetWhiteBalanceMode(retMode);
    EXPECT_EQ(intResult, 7400103);

    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    captureSession_->GetSupportedWhiteBalanceModes(supportedWhiteBalanceModes);
    if (!supportedWhiteBalanceModes.empty()) {
        captureSession_->IsWhiteBalanceModeSupported(supportedWhiteBalanceModes[0], isSupported);
        ASSERT_EQ(isSupported, true);
        captureSession_->LockForControl();
        intResult = captureSession_->SetWhiteBalanceMode(supportedWhiteBalanceModes[0]);
        ASSERT_EQ(intResult, 0);
        captureSession_->UnlockForControl();
        WhiteBalanceMode currentMode;
        captureSession_->GetWhiteBalanceMode(currentMode);
        ASSERT_EQ(currentMode, supportedWhiteBalanceModes[0]);
    }

    EXPECT_EQ(cameraInput_->Release(), SUCCESS);
    cameraInput_ = nullptr;

    intResult = captureSession_->GetSupportedWhiteBalanceModes(supportedWhiteBalanceModes);
    EXPECT_EQ(intResult, 0);

    intResult = captureSession_->IsWhiteBalanceModeSupported(currMode, isSupported);
    EXPECT_EQ(intResult, 0);
    captureSession_->LockForControl();
    intResult = captureSession_->SetWhiteBalanceMode(currMode);
    EXPECT_EQ(intResult, 0);
    captureSession_->UnlockForControl();

    intResult = captureSession_->GetWhiteBalanceMode(retMode);
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Camera base function
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test manaul WhiteBalance the cammera with abnormal setting branch
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_111, TestSize.Level1)
{
    std::vector<int32_t> manualWhiteBalanceRange = {};
    int32_t intResult = captureSession_->GetManualWhiteBalanceRange(manualWhiteBalanceRange);
    EXPECT_EQ(intResult, 7400103);
    EXPECT_EQ(manualWhiteBalanceRange.empty(), true);

    bool isSupported = false;
    intResult = captureSession_->IsManualWhiteBalanceSupported(isSupported);
    EXPECT_EQ(intResult, 7400103);

    int32_t wbValue = 0;
    captureSession_->LockForControl();
    intResult = captureSession_->SetManualWhiteBalance(wbValue);
    EXPECT_EQ(intResult, 7400103);
    captureSession_->UnlockForControl();

    intResult = captureSession_->GetManualWhiteBalance(wbValue);
    EXPECT_EQ(intResult, 7400103);

    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    captureSession_->GetManualWhiteBalanceRange(manualWhiteBalanceRange);
    if (!manualWhiteBalanceRange.empty()) {
        captureSession_->IsManualWhiteBalanceSupported(isSupported);
        ASSERT_EQ(isSupported, true);
        captureSession_->LockForControl();
        intResult = captureSession_->SetManualWhiteBalance(manualWhiteBalanceRange[0]);
        captureSession_->UnlockForControl();
        captureSession_ ->GetManualWhiteBalance(wbValue);
        ASSERT_EQ(wbValue, manualWhiteBalanceRange[0]);
    }

    EXPECT_EQ(cameraInput_->Release(), SUCCESS);
    cameraInput_ = nullptr;

    intResult = captureSession_->GetManualWhiteBalanceRange(manualWhiteBalanceRange);
    EXPECT_EQ(intResult, 0);

    intResult = captureSession_->IsManualWhiteBalanceSupported(isSupported);
    EXPECT_EQ(intResult, 0);
    captureSession_->LockForControl();
    intResult = captureSession_->SetManualWhiteBalance(wbValue);
    EXPECT_EQ(intResult, 7400102);
    captureSession_->UnlockForControl();

    intResult = captureSession_->GetManualWhiteBalance(wbValue);
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Camera base function
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test abnormal branches with empty inputDevice and empty metadata
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_112, TestSize.Level1)
{
    std::vector<std::vector<float>> supportedPhysicalApertures;
    int32_t intResult = captureSession_->GetSupportedPhysicalApertures(supportedPhysicalApertures);
    EXPECT_EQ(intResult, 7400103);
    EXPECT_EQ(supportedPhysicalApertures.empty(), true);

    float getAperture = 0.0f;
    intResult = captureSession_->GetPhysicalAperture(getAperture);
    EXPECT_EQ(intResult, 7400103);
    EXPECT_EQ(getAperture, 0.0f);

    captureSession_->LockForControl();
    float setAperture = 1.0f;
    intResult = captureSession_->SetPhysicalAperture(setAperture);
    EXPECT_EQ(intResult, 7400103);
    captureSession_->UnlockForControl();

    sptr<PhotoOutput> photoOutput;
    sptr<VideoOutput> videoOutput;
    CreateAndConfigureDefaultCaptureOutput(photoOutput, videoOutput);

    intResult = captureSession_->GetSupportedPhysicalApertures(supportedPhysicalApertures);
    EXPECT_EQ(intResult, 0);
    intResult = captureSession_->GetPhysicalAperture(getAperture);
    EXPECT_EQ(intResult, 0);

    captureSession_->LockForControl();
    intResult = captureSession_->SetPhysicalAperture(setAperture);
    EXPECT_EQ(intResult, 0);
    captureSession_->UnlockForControl();
    intResult = captureSession_->GetPhysicalAperture(getAperture);
    EXPECT_EQ(intResult, 0);

    EXPECT_EQ(cameraInput_->Release(), SUCCESS);
    cameraInput_ = nullptr;

    intResult = captureSession_->GetSupportedPhysicalApertures(supportedPhysicalApertures);
    EXPECT_EQ(intResult, 0);
    intResult = captureSession_->GetPhysicalAperture(getAperture);
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Camera base function
 * Function: Test auto aigc photo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test AutoAigcPhoto enable
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_113, TestSize.Level1)
{
    bool isEnabled = false;
    bool isAutoAigcPhotoSupported = false;
    EXPECT_EQ(captureSession_->EnableAutoAigcPhoto(isEnabled), SUCCESS);

    sptr<PreviewOutput> previewOutput = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput, nullptr);
    sptr<PhotoOutput> photoOutput = CreatePhotoOutput(photoProfiles_[0]);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_EQ(photoOutput->IsAutoAigcPhotoSupported(isAutoAigcPhotoSupported), SERVICE_FATL_ERROR);
    EXPECT_EQ(photoOutput->EnableAutoAigcPhoto(isEnabled), SESSION_NOT_RUNNING);

    EXPECT_EQ(captureSession_->BeginConfig(), SUCCESS);
    EXPECT_EQ(captureSession_->AddInput((sptr<CaptureInput>&)cameraInput_), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)previewOutput), SUCCESS);
    EXPECT_EQ(captureSession_->AddOutput((sptr<CaptureOutput>&)photoOutput), SUCCESS);
    EXPECT_EQ(captureSession_->CommitConfig(), SUCCESS);

    EXPECT_EQ(photoOutput->IsAutoAigcPhotoSupported(isAutoAigcPhotoSupported), SUCCESS);
    if (isAutoAigcPhotoSupported) {
        EXPECT_EQ(photoOutput->EnableAutoAigcPhoto(isEnabled), SUCCESS);
    }

    EXPECT_EQ(photoOutput->Release(), SUCCESS);
    EXPECT_EQ(photoOutput->IsAutoAigcPhotoSupported(isAutoAigcPhotoSupported), SERVICE_FATL_ERROR);
    EXPECT_EQ(photoOutput->EnableAutoAigcPhoto(isEnabled), SESSION_NOT_RUNNING);
}

/*
 * Feature: Camera base function
 * Function: Test the camera resetRssPriority function.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the camera manager resetRssPriority function,
 * reset the camera rss/qos priority when camera al.
 */
HWTEST_F(CameraBaseFunctionModuleTest, camera_base_function_moduletest_114, TestSize.Level0)
{
    if (cameraManager_->IsPrelaunchSupported(cameraInput_->GetCameraDeviceInfo())) {
        MEDIA_INFO_LOG("The camera prelaunch function is supported");

        std::string cameraId = cameraInput_->GetCameraId();
        ASSERT_NE(cameraId, "");
        int activeTime = 0;
        EffectParam effectParam = {0, 0, 0};
        EXPECT_EQ(cameraManager_->SetPrelaunchConfig(cameraId, RestoreParamTypeOhos::PERSISTENT_DEFAULT_PARAM_OHOS,
            activeTime, effectParam), SUCCESS);
        EXPECT_EQ(cameraManager_->PrelaunchCamera(), SUCCESS);
        EXPECT_EQ(cameraManager_->PreSwitchCamera(cameraId), SUCCESS);
        EXPECT_EQ(cameraManager_->ResetRssPriority(), SUCCESS);
    } else {
        MEDIA_ERR_LOG("The camera prelaunch function is not supported");
    }
}
} // namespace CameraStandard
} // namespace OHOS