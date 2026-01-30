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

#include "camera_util.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "hap_token_info.h"
#include "hcamera_service.h"
#include "ipc_skeleton.h"
#include "metadata_utils.h"
#include "nativetoken_kit.h"
#include "os_account_manager.h"
#include "sketch_wrapper.h"
#include "surface.h"
#include "test_common.h"
#include "test_token.h"
#include "video_session_unittest.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;

void CameraVideoSessionUnitTest::SetUpTestCase(void)
{
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
}

void CameraVideoSessionUnitTest::TearDownTestCase(void) {}

void CameraVideoSessionUnitTest::SetUp()
{
    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);
    cameraManagerForSys_ = CameraManagerForSys::GetInstance();
    ASSERT_NE(cameraManagerForSys_, nullptr);
}

void CameraVideoSessionUnitTest::TearDown()
{
    cameraManager_ = nullptr;
    cameraManagerForSys_ = nullptr;
    MEDIA_DEBUG_LOG("CameraVideoSessionUnitTest::TearDown");
}

void CameraVideoSessionUnitTest::TestVideoSessionForSysCallback()
{
    std::shared_ptr<FocusTrackingCallback> focusTrackingInfoCallback = std::make_shared<TestFocusTrackingCallback>();
    ASSERT_NE(focusTrackingInfoCallback, nullptr);

    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::VIDEO);
    ASSERT_NE(sessionForSys, nullptr);
    sptr<VideoSessionForSys> videoSessionForSys = static_cast<VideoSessionForSys*>(sessionForSys.GetRefPtr());
    ASSERT_NE(videoSessionForSys, nullptr);

    videoSessionForSys->SetFocusTrackingInfoCallback(focusTrackingInfoCallback);
    ASSERT_NE(videoSessionForSys->focusTrackingInfoCallback_, nullptr);
    EXPECT_EQ(videoSessionForSys->GetFocusTrackingCallback(), focusTrackingInfoCallback);

    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    uint64_t timestamp = 1;
    std::shared_ptr<OHOS::Camera::CameraMetadata> result = cameras[0]->GetMetadata();
    videoSessionForSys->metadataResultProcessor_->ProcessCallbacks(timestamp, result);
}

void CameraVideoSessionUnitTest::TestVideoSessionForSysPreconfig(
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
 * Function: Test VideoSessionForSys preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test preconfig VideoSessionForSys all config.
 */
HWTEST_F(CameraVideoSessionUnitTest, video_session_unittest_001, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput>&)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        EXPECT_EQ(camInput->GetCameraDevice()->Open(), 0);
    }
    sptr<HCameraHostManager> cameraHostManager = new(std::nothrow) HCameraHostManager(nullptr);
    sptr<HCameraService> cameraService =  new(std::nothrow) HCameraService(cameraHostManager);
    ASSERT_NE(cameraService, nullptr);

    sptr<ICameraServiceCallback> callback = cameraManager_->GetCameraStatusListenerManager();
    ASSERT_NE(callback, nullptr);
    int32_t intResult = cameraService->SetCameraCallback(callback, true);
    EXPECT_EQ(intResult, 0);

    sptr<ICameraDeviceService> deviceObj = camInput->GetCameraDevice();
    ASSERT_NE(deviceObj, nullptr);

    std::vector<PreconfigType> preconfigTypes = { PRECONFIG_720P, PRECONFIG_1080P, PRECONFIG_4K,
        PRECONFIG_HIGH_QUALITY };
    std::vector<ProfileSizeRatio> profileSizeRatios = { UNSPECIFIED, RATIO_1_1, RATIO_4_3, RATIO_16_9 };
    for (auto& preconfigType : preconfigTypes) {
        for (auto& profileSizeRatio : profileSizeRatios) {
            TestVideoSessionForSysPreconfig(input, preconfigType, profileSizeRatio);
        }
    }
    input->Close();
}

/*
 * Feature: Framework
 * Function: Test VideoSession preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test preconfig VideoSession all config.
 */
HWTEST_F(CameraVideoSessionUnitTest, video_session_unittest_002, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput>&)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        EXPECT_EQ(camInput->GetCameraDevice()->Open(), 0);
    }

    sptr<HCameraHostManager> cameraHostManager = new(std::nothrow) HCameraHostManager(nullptr);
    sptr<HCameraService> cameraService =  new(std::nothrow) HCameraService(cameraHostManager);
    ASSERT_NE(cameraService, nullptr);

    sptr<ICameraServiceCallback> callback = cameraManager_->GetCameraStatusListenerManager();
    ASSERT_NE(callback, nullptr);
    int32_t intResult = cameraService->SetCameraCallback(callback, true);
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
HWTEST_F(CameraVideoSessionUnitTest, video_session_unittest_003, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput>&)input;
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    TestVideoSessionForSysCallback();
    
    input->Close();
}

/*
 * Feature: Framework
 * Function: Test VideoSessionForSys callback abnormal branches
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test VideoSessionForSys callback while metadata is nullptr
 */
HWTEST_F(CameraVideoSessionUnitTest, video_session_unittest_004, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput>&)input;
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    FocusTrackingMode mode = FOCUS_TRACKING_MODE_AUTO;
    Rect region = {0.0, 0.0, 0.0, 0.0};

    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::VIDEO);
    ASSERT_NE(sessionForSys, nullptr);
    sptr<VideoSessionForSys> videoSessionForSys = static_cast<VideoSessionForSys*>(sessionForSys.GetRefPtr());
    ASSERT_NE(videoSessionForSys, nullptr);

    bool ret = videoSessionForSys->ProcessFocusTrackingModeInfo(nullptr, mode);
    EXPECT_FALSE(ret);
    ret = videoSessionForSys->ProcessRectInfo(nullptr, region);
    EXPECT_FALSE(ret);
    videoSessionForSys->ProcessFocusTrackingInfo(nullptr);
    
    input->Close();
}

/*
 * Feature: Framework
 * Function: Test VideoSessionForSys callback normal branches
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test VideoSessionForSys callback normal branches while metadata have ability
 */
HWTEST_F(CameraVideoSessionUnitTest, video_session_unittest_005, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput>&)input;
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::VIDEO);
    ASSERT_NE(sessionForSys, nullptr);
    sptr<VideoSessionForSys> videoSessionForSys = static_cast<VideoSessionForSys*>(sessionForSys.GetRefPtr());
    ASSERT_NE(videoSessionForSys, nullptr);

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras[0]->GetMetadata();
    ASSERT_NE(metadata, nullptr);
    OHOS::Camera::DeleteCameraMetadataItem(metadata->get(), OHOS_CONTROL_FOCUS_TRACKING_MODE);
    uint8_t testMode = OHOS_CAMERA_FOCUS_TRACKING_AUTO;
    FocusTrackingMode mode = FOCUS_TRACKING_MODE_AUTO;
    metadata->addEntry(OHOS_CONTROL_FOCUS_TRACKING_MODE, &testMode, 1);
    bool ret = videoSessionForSys->ProcessFocusTrackingModeInfo(metadata, mode);
    EXPECT_TRUE(ret);

    int32_t data[4] = {0, 1, 2, 3};
    Rect region = {0.0, 0.0, 0.0, 0.0};
    OHOS::Camera::DeleteCameraMetadataItem(metadata->get(), OHOS_ABILITY_FOCUS_TRACKING_REGION);
    metadata->addEntry(OHOS_ABILITY_FOCUS_TRACKING_REGION, &data, sizeof(data) / sizeof(data[0]));
    ret = videoSessionForSys->ProcessRectInfo(metadata, region);
    EXPECT_TRUE(ret);

    std::shared_ptr<FocusTrackingCallback> focusTrackingInfoCallback = std::make_shared<TestFocusTrackingCallback>();
    ASSERT_NE(focusTrackingInfoCallback, nullptr);
    videoSessionForSys->SetFocusTrackingInfoCallback(focusTrackingInfoCallback);
    ASSERT_NE(videoSessionForSys->focusTrackingInfoCallback_, nullptr);
    videoSessionForSys->ProcessFocusTrackingInfo(metadata);

    input->Close();
}

/*
 * Feature: Framework
 * Function: Test VideoSessionForSys callback normal branches
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test VideoSessionForSys callback normal branches while metadata have ability
 */
HWTEST_F(CameraVideoSessionUnitTest, video_session_unittest_006, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput>&)input;
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::VIDEO);
    ASSERT_NE(sessionForSys, nullptr);
    sptr<VideoSessionForSys> videoSessionForSys = static_cast<VideoSessionForSys*>(sessionForSys.GetRefPtr());
    ASSERT_NE(videoSessionForSys, nullptr);

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras[0]->GetMetadata();
    ASSERT_NE(metadata, nullptr);
    OHOS::Camera::DeleteCameraMetadataItem(metadata->get(), OHOS_STATUS_LIGHT_STATUS);
    uint8_t lightStart = 1;
    videoSessionForSys->LockForControl();
    metadata->addEntry(OHOS_STATUS_LIGHT_STATUS, &lightStart, 1);
    videoSessionForSys->UnlockForControl();
    videoSessionForSys->ProcessLightStatusChange(metadata);
    input->Close();
}

/*
 * Feature: Framework
 * Function: Test ControlCenterSession virtualApertures and physicalApertures
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ControlCenterSession virtualApertures and physicalApertures
 */
HWTEST_F(CameraVideoSessionUnitTest, video_session_unittest_007, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
 
    sptr<CameraInput> camInput = (sptr<CameraInput>&)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        EXPECT_EQ(camInput->GetCameraDevice()->Open(), 0);
    }
 
    sptr<HCameraHostManager> cameraHostManager = new(std::nothrow) HCameraHostManager(nullptr);
    sptr<HCameraService> cameraService =  new(std::nothrow) HCameraService(cameraHostManager);
    ASSERT_NE(cameraService, nullptr);
 
    sptr<ControlCenterSession> mControlCenterSession = nullptr;
    cameraManager_->CreateControlCenterSession(mControlCenterSession);
    EXPECT_NE(mControlCenterSession, nullptr);
 
    std::vector<float> virtualApertures = {};
    mControlCenterSession->GetSupportedVirtualApertures(virtualApertures);
    EXPECT_EQ(virtualApertures.size(), 0);
 
    float virtualAperture = 0;
    mControlCenterSession->GetVirtualAperture(virtualAperture);
    auto setVirtualApertureRet = mControlCenterSession->SetVirtualAperture(0.0);
    EXPECT_EQ(setVirtualApertureRet, CAMERA_OK);
 
    std::vector<std::vector<float>> physicalApertures = {};
    mControlCenterSession->GetSupportedPhysicalApertures(physicalApertures);
    EXPECT_EQ(physicalApertures.size(), 0);
 
    float physicalAperture = 0;
    mControlCenterSession->GetPhysicalAperture(physicalAperture);
    EXPECT_EQ(physicalAperture, 0);
 
    auto setPhysicalApertureRet = mControlCenterSession->SetPhysicalAperture(0.0);
    EXPECT_EQ(setPhysicalApertureRet, CameraErrorCode::INVALID_ARGUMENT);
 
    input->Close();
}
 
/*
 * Feature: Framework
 * Function: Test ControlCenterSession beauty effect
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ControlCenterSession beauty effect
 */
HWTEST_F(CameraVideoSessionUnitTest, video_session_unittest_008, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
 
    sptr<CameraInput> camInput = (sptr<CameraInput>&)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        EXPECT_EQ(camInput->GetCameraDevice()->Open(), 0);
    }
 
    sptr<HCameraHostManager> cameraHostManager = new(std::nothrow) HCameraHostManager(nullptr);
    sptr<HCameraService> cameraService =  new(std::nothrow) HCameraService(cameraHostManager);
    ASSERT_NE(cameraService, nullptr);
 
    sptr<ControlCenterSession> mControlCenterSession = nullptr;
    cameraManager_->CreateControlCenterSession(mControlCenterSession);
    EXPECT_NE(mControlCenterSession, nullptr);
 
    std::vector<int32_t> beautyTypes = {};
    beautyTypes = mControlCenterSession->GetSupportedBeautyTypes();
    EXPECT_EQ(beautyTypes.size(), 0);
 
    std::vector<int32_t> beautyRange = {};
    beautyRange = mControlCenterSession->GetSupportedBeautyRange(BeautyType::AUTO_TYPE);
    EXPECT_EQ(beautyRange.size(), 0);
 
    mControlCenterSession->SetBeauty(BeautyType::AUTO_TYPE, 0);
 
    int32_t beautyValue = mControlCenterSession->GetBeauty(BeautyType::AUTO_TYPE);
    EXPECT_EQ(beautyValue, 0);
 
    std::vector<PortraitThemeType> themeTypes = {};
    auto getThemeTypesRet = mControlCenterSession->GetSupportedPortraitThemeTypes(themeTypes);
    EXPECT_EQ(getThemeTypesRet, CameraErrorCode::INVALID_ARGUMENT);
    EXPECT_EQ(themeTypes.size(), 0);
 
    bool isSupportportraitTheme = false;
    auto isSupportRet = mControlCenterSession->IsPortraitThemeSupported(isSupportportraitTheme);
    EXPECT_EQ(isSupportRet, CameraErrorCode::INVALID_ARGUMENT);
    EXPECT_EQ(isSupportportraitTheme, false);
    EXPECT_EQ(mControlCenterSession->IsPortraitThemeSupported(), false);
 
    auto setThemeTypeRet = mControlCenterSession->SetPortraitThemeType(PortraitThemeType::NATURAL);
    EXPECT_EQ(setThemeTypeRet, CameraErrorCode::INVALID_ARGUMENT);
 
    auto releaseRet = mControlCenterSession->Release();
    EXPECT_EQ(releaseRet, 0);
 
    input->Close();
}

/*
 * Feature: Framework
 * Function: Test VideoSessionForSys CanAddOutput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test VideoSessionForSys CanAddOutput under different conditions.
 */
HWTEST_F(CameraVideoSessionUnitTest, video_session_unittest_009, TestSize.Level0)
{
    // 获取支持的相机设备列表
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    // 打开相机设备
    sptr<CameraInput> camInput = (sptr<CameraInput>&)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        EXPECT_EQ(camInput->GetCameraDevice()->Open(), 0);
    }

    // 创建 CaptureSessionForSys 并转换为 VideoSessionForSys
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::VIDEO);
    ASSERT_NE(sessionForSys, nullptr);
    sptr<VideoSessionForSys> videoSessionForSys = static_cast<VideoSessionForSys*>(sessionForSys.GetRefPtr());
    ASSERT_NE(videoSessionForSys, nullptr);

    int32_t Result = videoSessionForSys->AddInput(input);
    EXPECT_EQ(Result, CameraErrorCode::OPERATION_NOT_ALLOWED);

    // 创建一个输出对象
    sptr<VideoOutput> videoOutput = nullptr;
    Result = cameraManager_->CreateVideoOutputWithoutProfile(Surface::CreateSurfaceAsConsumer(), &videoOutput);
    EXPECT_EQ(Result, 0);
    ASSERT_NE(videoOutput, nullptr);
    sptr<CaptureOutput> videoOutputCaptureUpper = videoOutput;
    sptr<CaptureOutput> nullOutput = nullptr;

    // 会话未配置时
    EXPECT_FALSE(videoSessionForSys->CanAddOutput(nullOutput));
    EXPECT_FALSE(videoSessionForSys->CanAddOutput(videoOutputCaptureUpper));

    // 配置会话
    Result = videoSessionForSys->BeginConfig();
    EXPECT_EQ(Result, 0);
    Result = videoSessionForSys->AddInput(input);
    EXPECT_EQ(Result, 0);

    //配置会话时
    EXPECT_FALSE(videoSessionForSys->CanAddOutput(nullOutput));
    EXPECT_FALSE(videoSessionForSys->CanAddOutput(videoOutputCaptureUpper));

    // 关闭相机输入
    input->Close();
}

/*
 * Feature: Framework
 * Function: Test VideoSessionForSys AddOutput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test VideoSessionForSys AddOutput under different conditions.
 */
HWTEST_F(CameraVideoSessionUnitTest, video_session_unittest_010, TestSize.Level0)
{
    // 获取支持的相机设备列表
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    // 打开相机设备
    sptr<CameraInput> camInput = (sptr<CameraInput>&)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        EXPECT_EQ(camInput->GetCameraDevice()->Open(), 0);
    }

    // 创建 CaptureSessionForSys 并转换为 VideoSessionForSys
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::VIDEO);
    ASSERT_NE(sessionForSys, nullptr);
    sptr<VideoSessionForSys> videoSessionForSys = static_cast<VideoSessionForSys*>(sessionForSys.GetRefPtr());
    ASSERT_NE(videoSessionForSys, nullptr);


    int result = videoSessionForSys->AddInput(input);
    EXPECT_EQ(result, CameraErrorCode::OPERATION_NOT_ALLOWED);

    // 创建一个输出对象
    sptr<VideoOutput> videoOutput = nullptr;
    result = cameraManager_->CreateVideoOutputWithoutProfile(Surface::CreateSurfaceAsConsumer(), &videoOutput);
    EXPECT_EQ(result, 0);
    ASSERT_NE(videoOutput, nullptr);
    sptr<CaptureOutput> videoOutputCaptureUpper = videoOutput;
    sptr<CaptureOutput> nullOutput = nullptr;

    // 会话未配置时
    result = videoSessionForSys->AddOutput(nullOutput);
    EXPECT_EQ(result, CameraErrorCode::OPERATION_NOT_ALLOWED);

    result = videoSessionForSys->AddOutput(videoOutputCaptureUpper);
    EXPECT_EQ(result, CameraErrorCode::OPERATION_NOT_ALLOWED);

    // 配置会话
    result = videoSessionForSys->BeginConfig();
    EXPECT_EQ(result, 0);
    result = videoSessionForSys->AddInput(input);
    EXPECT_EQ(result, 0);

    // 会话已配置时
    result = videoSessionForSys->AddOutput(nullOutput);
    EXPECT_EQ(result, CameraErrorCode::SERVICE_FATL_ERROR);

    result = videoSessionForSys->AddOutput(videoOutputCaptureUpper);
    EXPECT_EQ(result, CameraErrorCode::SERVICE_FATL_ERROR);

    // 关闭相机输入
    input->Close();
}

/*
 * Feature: Framework
 * Function: Test PhotoSessionsys EnableExternalCameraLensBoost
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EnableExternalCameraLensBoost.
 */
HWTEST_F(CameraVideoSessionUnitTest, video_session_unittest_011, TestSize.Level1)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::VIDEO);
    ASSERT_NE(sessionForSys, nullptr);
    sptr<VideoSessionForSys> videoSessionForSys = static_cast<VideoSessionForSys*>(sessionForSys.GetRefPtr());
    ASSERT_NE(videoSessionForSys, nullptr);
    bool issupperted = videoSessionForSys->IsExternalCameraLensBoostSupported();
    if (issupperted == true) {
        EXPECT_EQ(issupperted, true);
        EXPECT_EQ(videoSessionForSys->EnableExternalCameraLensBoost(0), 1);
    } else {
        videoSessionForSys->EnableExternalCameraLensBoost(0);
    }
}
}
}