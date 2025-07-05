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
#include "fluorescence_photo_session.h"
#include "gtest/gtest.h"
#include "hap_token_info.h"
#include "hcamera_service.h"
#include "hcapture_session.h"
#include "ipc_skeleton.h"
#include "metadata_utils.h"
#include "nativetoken_kit.h"
#include "os_account_manager.h"
#include "photo_session_unittest.h"
#include "quick_shot_photo_session.h"
#include "sketch_wrapper.h"
#include "surface.h"
#include "test_common.h"
#include "test_token.h"
#include "token_setproc.h"

using namespace testing::ext;
namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;
void CameraPhotoSessionUnitTest::SetUpTestCase(void)
{
    ASSERT_TRUE(TestToken::GetAllCameraPermission());
}

void CameraPhotoSessionUnitTest::TearDownTestCase(void) {}

void CameraPhotoSessionUnitTest::SetUp()
{
    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);
}

void CameraPhotoSessionUnitTest::TearDown()
{
    cameraManager_ = nullptr;
    MEDIA_DEBUG_LOG("CameraPhotoSessionUnitTest TearDown");
}

void CameraPhotoSessionUnitTest::TestPhotoSessionForSysPreconfig(
    sptr<CaptureInput>& input, PreconfigType preconfigType, ProfileSizeRatio profileSizeRatio)
{
    sptr<CaptureSession> photoSession =
        CameraManagerForSys::GetInstance()->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(photoSession, nullptr);
    if (photoSession->CanPreconfig(preconfigType, profileSizeRatio)) {
        int32_t intResult = photoSession->Preconfig(preconfigType, profileSizeRatio);
        EXPECT_EQ(intResult, 0);

        sptr<Surface> preivewSurface = Surface::CreateSurfaceAsConsumer();
        ASSERT_NE(preivewSurface, nullptr);

        sptr<PreviewOutput> previewOutput = nullptr;
        intResult = cameraManager_->CreatePreviewOutputWithoutProfile(preivewSurface, &previewOutput);
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

        intResult = photoSession->BeginConfig();
        EXPECT_EQ(intResult, 0);

        intResult = photoSession->AddInput(input);
        EXPECT_EQ(intResult, 0);

        sptr<CaptureOutput> previewOutputCaptureUpper = previewOutput;
        intResult = photoSession->AddOutput(previewOutputCaptureUpper);
        EXPECT_EQ(intResult, 0);
        sptr<CaptureOutput> photoOutputCaptureUpper = photoOutput;
        intResult = photoSession->AddOutput(photoOutputCaptureUpper);
        EXPECT_EQ(intResult, 0);

        intResult = photoSession->CommitConfig();
        EXPECT_EQ(intResult, 0);

        intResult = photoSession->Start();
        EXPECT_EQ(intResult, 0);

        intResult = photoSession->Stop();
        EXPECT_EQ(intResult, 0);

        intResult = photoSession->BeginConfig();
        EXPECT_EQ(intResult, 0);

        intResult = photoSession->RemoveInput(input);
        EXPECT_EQ(intResult, 0);

        intResult = photoSession->Release();
        EXPECT_EQ(intResult, 0);
    }
}

void CameraPhotoSessionUnitTest::TestPhotoSessionPreconfig(
    sptr<CaptureInput>& input, PreconfigType preconfigType, ProfileSizeRatio profileSizeRatio)
{
    sptr<CaptureSession> photoSession = cameraManager_->CreateCaptureSession(SceneMode::CAPTURE);
    ASSERT_NE(photoSession, nullptr);
    if (photoSession->CanPreconfig(preconfigType, profileSizeRatio)) {
        int32_t intResult = photoSession->Preconfig(preconfigType, profileSizeRatio);
        EXPECT_EQ(intResult, 0);

        sptr<Surface> preivewSurface = Surface::CreateSurfaceAsConsumer();
        ASSERT_NE(preivewSurface, nullptr);

        sptr<PreviewOutput> previewOutput = nullptr;
        intResult = cameraManager_->CreatePreviewOutputWithoutProfile(preivewSurface, &previewOutput);
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

        intResult = photoSession->BeginConfig();
        EXPECT_EQ(intResult, 0);

        intResult = photoSession->AddInput(input);
        EXPECT_EQ(intResult, 0);

        sptr<CaptureOutput> previewOutputCaptureUpper = previewOutput;
        intResult = photoSession->AddOutput(previewOutputCaptureUpper);
        EXPECT_EQ(intResult, 0);
        sptr<CaptureOutput> photoOutputCaptureUpper = photoOutput;
        intResult = photoSession->AddOutput(photoOutputCaptureUpper);
        EXPECT_EQ(intResult, 0);

        intResult = photoSession->CommitConfig();
        EXPECT_EQ(intResult, 0);

        intResult = photoSession->Start();
        EXPECT_EQ(intResult, 0);

        intResult = photoSession->Stop();
        EXPECT_EQ(intResult, 0);

        intResult = photoSession->BeginConfig();
        EXPECT_EQ(intResult, 0);

        intResult = photoSession->RemoveInput(input);
        EXPECT_EQ(intResult, 0);

        intResult = photoSession->Release();
        EXPECT_EQ(intResult, 0);
    }
}

/*
 * Feature: Framework
 * Function: Test PhotoSessionForSys preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test preconfig PhotoSessionForSys all config.
 */
HWTEST_F(CameraPhotoSessionUnitTest, camera_photo_session_unittest_001, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput>&)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<HCameraHostManager> cameraHostManager = new(std::nothrow) HCameraHostManager(nullptr);
    sptr<HCameraService> cameraService =  new(std::nothrow) HCameraService(cameraHostManager);
    ASSERT_NE(cameraService, nullptr);

    sptr<ICameraServiceCallback> callback = cameraManager_->GetCameraStatusListenerManager();
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
            TestPhotoSessionForSysPreconfig(input, preconfigType, profileSizeRatio);
        }
    }

    input->Close();
}

/*
 * Feature: Framework
 * Function: Test PhotoSession preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test preconfig PhotoSession all config.
 */
HWTEST_F(CameraPhotoSessionUnitTest, camera_photo_session_unittest_002, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput>&)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<HCameraHostManager> cameraHostManager = new(std::nothrow) HCameraHostManager(nullptr);
    sptr<HCameraService> cameraService =  new(std::nothrow) HCameraService(cameraHostManager);
    ASSERT_NE(cameraService, nullptr);

    sptr<ICameraServiceCallback> callback = cameraManager_->GetCameraStatusListenerManager();
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
            TestPhotoSessionPreconfig(input, preconfigType, profileSizeRatio);
        }
    }

    input->Close();
}

/*
 * Feature: Framework
 * Function: Test FluorescencePhotoSession CanAddOutput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CanAddOutput for just call.
 */
HWTEST_F(CameraPhotoSessionUnitTest, fluorescence_photo_session_function_unittest_001, TestSize.Level1)
{
    sptr<CaptureSession> captureSession =
        CameraManagerForSys::GetInstance()->CreateCaptureSessionForSys(SceneMode::FLUORESCENCE_PHOTO);
    ASSERT_NE(captureSession, nullptr);
    sptr<FluorescencePhotoSession> fluorescencePhotoSession =
        static_cast<FluorescencePhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(fluorescencePhotoSession, nullptr);
    sptr<CaptureOutput> output = nullptr;
    EXPECT_FALSE(fluorescencePhotoSession->CanAddOutput(output));
}

/*
 * Feature: Framework
 * Function: Test FluorescencePhotoSession CanSetFrameRateRange
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CanSetFrameRateRange for just call.
 */
HWTEST_F(CameraPhotoSessionUnitTest, photo_session_function_unittest_001, TestSize.Level1)
{
    sptr<CaptureSession> photoSession =
        CameraManagerForSys::GetInstance()->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(photoSession, nullptr);

    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    input->Open();

    int32_t minFps = 30;
    int32_t maxFps = 60;
    sptr<CaptureOutput> output = nullptr;
    bool flag = photoSession->CanSetFrameRateRangeForOutput(minFps, maxFps, output);
    EXPECT_EQ(photoSession->CanSetFrameRateRange(minFps, maxFps, output), flag);
    input->Close();
}

/*
 * Feature: Framework
 * Function: Test PhotoSession CanSetFrameRateRange
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CanSetFrameRateRange for just call.
 */
HWTEST_F(CameraPhotoSessionUnitTest, photo_session_function_unittest_002, TestSize.Level1)
{
    sptr<CaptureSession> photoSession = cameraManager_->CreateCaptureSession(SceneMode::CAPTURE);
    ASSERT_NE(photoSession, nullptr);

    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    input->Open();

    int32_t minFps = 30;
    int32_t maxFps = 60;
    sptr<CaptureOutput> output = nullptr;
    bool flag = photoSession->CanSetFrameRateRangeForOutput(minFps, maxFps, output);
    EXPECT_EQ(photoSession->CanSetFrameRateRange(minFps, maxFps, output), flag);
    input->Close();
}

/*
 * Feature: Framework
 * Function: Test QuickShotPhotoSession CanAddOutput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CanAddOutput for just call.
 */
HWTEST_F(CameraPhotoSessionUnitTest, quick_shot_photo_session_function_unittest_001, TestSize.Level1)
{
    sptr<CaptureSession> captureSession =
        CameraManagerForSys::GetInstance()->CreateCaptureSessionForSys(SceneMode::QUICK_SHOT_PHOTO);
    ASSERT_NE(captureSession, nullptr);
    sptr<QuickShotPhotoSession> quickShotPhotoSession =
        static_cast<QuickShotPhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(quickShotPhotoSession, nullptr);
    sptr<CaptureOutput> output = nullptr;
    EXPECT_FALSE(quickShotPhotoSession->CanAddOutput(output));
}
}
}