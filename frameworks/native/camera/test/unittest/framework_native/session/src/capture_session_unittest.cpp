/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "capture_session_unittest.h"
#include "gtest/gtest.h"
#include <cstdint>
#include <memory>
#include <vector>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_device_ability_items.h"
#include "camera_metadata_operator.h"
#include "camera_util.h"
#include "gmock/gmock.h"
#include "capture_scene_const.h"
#include "capture_session.h"
#include "capture_session_for_sys.h"
#include "hap_token_info.h"
#include "ipc_skeleton.h"
#include "metadata_utils.h"
#include "nativetoken_kit.h"
#include "surface.h"
#include "test_common.h"
#include "test_token.h"
#include "token_setproc.h"
#include "os_account_manager.h"
#include "sketch_wrapper.h"
#include "picture_interface.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
struct TestObject {};

void CaptureSessionUnitTest::SessionControlParams(sptr<CaptureSession> session)
{
    if (session == nullptr) {
        return;
    }
    session->LockForControl();

    std::vector<float> zoomRatioRange = session->GetZoomRatioRange();
    if (!zoomRatioRange.empty()) {
        session->SetZoomRatio(zoomRatioRange[0]);
    }

    std::vector<float> exposurebiasRange = session->GetExposureBiasRange();
    if (!exposurebiasRange.empty()) {
        session->SetExposureBias(exposurebiasRange[0]);
    }

    FlashMode flash = FLASH_MODE_ALWAYS_OPEN;
    bool flashSupported = session->IsFlashModeSupported(flash);
    if (flashSupported) {
        session->SetFlashMode(flash);
    }

    FocusMode focus = FOCUS_MODE_AUTO;
    bool focusSupported = session->IsFocusModeSupported(focus);
    if (focusSupported) {
        session->SetFocusMode(focus);
    }

    ExposureMode exposure = EXPOSURE_MODE_AUTO;
    bool exposureSupported = session->IsExposureModeSupported(exposure);
    if (exposureSupported) {
        session->SetExposureMode(exposure);
    }

    session->UnlockForControl();

    if (!exposurebiasRange.empty()) {
        EXPECT_EQ(session->GetExposureValue(), exposurebiasRange[0]);
    }

    if (flashSupported) {
        EXPECT_EQ(session->GetFlashMode(), flash);
    }

    if (focusSupported) {
        EXPECT_EQ(session->GetFocusMode(), focus);
    }

    if (exposureSupported) {
        EXPECT_EQ(session->GetExposureMode(), exposure);
    }
}

void CaptureSessionUnitTest::UpdateCameraOutputCapability(int32_t modeName)
{
    if (!cameraManager_ || cameras_.empty()) {
        return;
    }
    auto outputCapability = cameraManager_->GetSupportedOutputCapability(cameras_[0], modeName);
    ASSERT_NE(outputCapability, nullptr);

    previewProfile_ = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfile_.empty());

    photoProfile_ = outputCapability->GetPhotoProfiles();
    ASSERT_FALSE(photoProfile_.empty());

    videoProfile_ = outputCapability->GetVideoProfiles();
    ASSERT_FALSE(videoProfile_.empty());
}

sptr<CaptureOutput> CaptureSessionUnitTest::CreatePreviewOutput(Profile previewProfile)
{
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    if (surface == nullptr) {
        return nullptr;
    }
    return cameraManager_->CreatePreviewOutput(previewProfile, surface);
}

sptr<CaptureOutput> CaptureSessionUnitTest::CreatePhotoOutput(Profile photoProfile)
{
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    if (surface == nullptr) {
        return nullptr;
    }
    sptr<IBufferProducer> surfaceProducer = surface->GetProducer();
    return cameraManager_->CreatePhotoOutput(photoProfile, surfaceProducer);
}

sptr<CaptureOutput> CaptureSessionUnitTest::CreateVideoOutput(VideoProfile videoProfile)
{
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    if (surface == nullptr) {
        return nullptr;
    }
    return cameraManager_->CreateVideoOutput(videoProfile, surface);
}

class ConcreteLcdFlashStatusCallback : public LcdFlashStatusCallback {
public:
    void OnLcdFlashStatusChanged(LcdFlashStatusInfo lcdFlashStatusInfo) override {}
};

void CaptureSessionUnitTest::SetUpTestCase(void)
{
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
}

void CaptureSessionUnitTest::TearDownTestCase(void) {}

void CaptureSessionUnitTest::SetUp()
{
    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);
    cameraManagerForSys_ = CameraManagerForSys::GetInstance();
    ASSERT_NE(cameraManagerForSys_, nullptr);
    cameras_ = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras_.empty());
}

void CaptureSessionUnitTest::TearDown()
{
    cameraManager_ = nullptr;
    cameraManagerForSys_ = nullptr;
    cameras_.clear();
}

bool CaptureSessionUnitTest::DisMdmOpenCheck(sptr<CameraInput> camInput)
{
    if (camInput == nullptr) {
        return false;
    }
    if (!camInput->GetCameraDevice()) {
        return false;
    }
    camInput->GetCameraDevice()->SetMdmCheck(false);
    return true;
}

/*
 * Feature: Framework
 * Function: Test captureSession with GetSessionFunctions
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSessionFunctions for inputDevice is nullptr
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_001, TestSize.Level1)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    std::vector<Profile> previewProfiles = {};
    std::vector<Profile> photoProfiles = {};
    std::vector<VideoProfile> videoProfiles = {};
    bool isForApp = true;
    EXPECT_EQ(session->GetInputDevice(), nullptr);
    auto innerInputDevice = session->GetSessionFunctions(previewProfiles, photoProfiles, videoProfiles, isForApp);
    EXPECT_EQ(innerInputDevice.size(), 0);
}

/*
 * Feature: Framework
 * Function: Test captureSession with CheckFrameRateRangeWithCurrentFps
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CheckFrameRateRangeWithCurrentFps for (minFps % curMinFps == 0 || curMinFps % minFps == 0)
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_002, TestSize.Level1)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession(SceneMode::CAPTURE);
    ASSERT_NE(session, nullptr);
    EXPECT_TRUE(session->CheckFrameRateRangeWithCurrentFps(20, 20, 40, 40));
    EXPECT_TRUE(session->CheckFrameRateRangeWithCurrentFps(40, 40, 20, 20));
    EXPECT_TRUE(session->CheckFrameRateRangeWithCurrentFps(30, 30, 60, 60));
    EXPECT_TRUE(session->CheckFrameRateRangeWithCurrentFps(50, 50, 100, 100));


}

/*
 * Feature: Framework
 * Function: Test captureSession with GetMaxSizePhotoProfile
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetMaxSizePhotoProfile for SceneMode is NORMAL
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_003, TestSize.Level1)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession(SceneMode::CAPTURE);
    ASSERT_NE(session, nullptr);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    EXPECT_NE(input->GetCameraDeviceInfo(), nullptr);
    input->GetCameraDeviceInfo()->cameraType_ = CAMERA_TYPE_DEFAULT;
    session->SetInputDevice(input);
    ProfileSizeRatio sizeRatio = UNSPECIFIED;
    session->currentMode_ = SceneMode::NORMAL;
    EXPECT_EQ(session->guessMode_, SceneMode::NORMAL);
    EXPECT_EQ(session->GetMaxSizePhotoProfile(sizeRatio), nullptr);
}

/*
 * Feature: Framework
 * Function: Test captureSession with CanAddOutput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CanAddOutput for tow branches of switch
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_004, TestSize.Level1)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    EXPECT_NE(input->GetCameraDeviceInfo(), nullptr);
    session->SetInputDevice(input);
    EXPECT_NE(session->GetInputDevice()->GetCameraDeviceInfo(), nullptr);
    preview->outputType_ = CAPTURE_OUTPUT_TYPE_DEPTH_DATA;
    EXPECT_FALSE(session->CanAddOutput(preview));
    preview->outputType_ = CAPTURE_OUTPUT_TYPE_MAX;
    EXPECT_FALSE(session->CanAddOutput(preview));

    input->Close();
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession with SetFlashMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetFlashMode for GetMode() == SceneMode::LIGHT_PAINTING
 * && flashMode == FlashMode::FLASH_MODE_OPEN
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_006, TestSize.Level1)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    FlashMode flashMode = FlashMode::FLASH_MODE_OPEN;
    session->LockForControl();
    EXPECT_NE(session->changedMetadata_, nullptr);
    session->currentMode_ = SceneMode::LIGHT_PAINTING;
    EXPECT_EQ(session->SetFlashMode(flashMode), CameraErrorCode::SUCCESS);

    input->Close();
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession with SetGuessMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetGuessMode for switch of default
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_007, TestSize.Level1)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    SceneMode mode = SceneMode::PORTRAIT;
    session->currentMode_ = SceneMode::NORMAL;
    session->SetGuessMode(mode);
    EXPECT_NE(session->guessMode_, SceneMode::PORTRAIT);

    EXPECT_EQ(session->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test captureSession with SetMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetMode for commited
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_008, TestSize.Level1)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    SceneMode modeName = SceneMode::CAPTURE;
    EXPECT_NE(session->currentMode_, SceneMode::CAPTURE);
    EXPECT_TRUE(session->IsSessionCommited());
    session->SetMode(modeName);
    EXPECT_NE(session->currentMode_, SceneMode::CAPTURE);

    input->Close();
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession with IsSessionStarted
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsSessionStarted for captureSession is nullptr
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_009, TestSize.Level1)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    session->SetCaptureSession(nullptr);
    EXPECT_FALSE(session->IsSessionStarted());
}

/*
 * Feature: Framework
 * Function: Test captureSession with GetSensorExposureTime
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSensorExposureTime for captureSession is nullptr
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_010, TestSize.Level1)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    session->SetInputDevice(nullptr);
    uint32_t exposureTime;
    EXPECT_EQ(session->GetSensorExposureTime(exposureTime), CameraErrorCode::INVALID_ARGUMENT);

    input->Close();
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession with IsDepthFusionSupported
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsDepthFusionSupported for abnormal branches
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_011, TestSize.Level1)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_FALSE(sessionForSys->IsDepthFusionSupported());

    EXPECT_EQ(sessionForSys->BeginConfig(), 0);

    EXPECT_FALSE(sessionForSys->IsDepthFusionSupported());

    EXPECT_EQ(sessionForSys->AddInput(input), 0);
    EXPECT_EQ(sessionForSys->AddOutput(preview), 0);
    EXPECT_EQ(sessionForSys->CommitConfig(), 0);

    EXPECT_NE(sessionForSys->GetInputDevice(), nullptr);
    EXPECT_NE(sessionForSys->GetInputDevice()->GetCameraDeviceInfo(), nullptr);

    sessionForSys->SetInputDevice(nullptr);
    EXPECT_FALSE(sessionForSys->IsDepthFusionSupported());

    input->Close();
    preview->Release();
    input->Release();
    sessionForSys->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession with GetDepthFusionThreshold
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetDepthFusionThreshold for abnormal branches
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_012, TestSize.Level1)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    std::vector<float> depthFusionThreshold = {};
    EXPECT_EQ(sessionForSys->GetDepthFusionThreshold(depthFusionThreshold), CameraErrorCode::SESSION_NOT_CONFIG);

    EXPECT_EQ(sessionForSys->BeginConfig(), 0);
    EXPECT_EQ(sessionForSys->AddInput(input), 0);
    EXPECT_EQ(sessionForSys->AddOutput(preview), 0);
    EXPECT_EQ(sessionForSys->CommitConfig(), 0);

    EXPECT_NE(sessionForSys->GetInputDevice(), nullptr);
    EXPECT_NE(sessionForSys->GetInputDevice()->GetCameraDeviceInfo(), nullptr);
    EXPECT_EQ(sessionForSys->GetDepthFusionThreshold(depthFusionThreshold), CameraErrorCode::SUCCESS);

    sessionForSys->SetInputDevice(nullptr);
    EXPECT_EQ(sessionForSys->GetDepthFusionThreshold(depthFusionThreshold), CameraErrorCode::SUCCESS);

    input->Close();
    preview->Release();
    input->Release();
    sessionForSys->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession with EnableDepthFusion
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EnableDepthFusion for IsDepthFusionSupported is false
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_013, TestSize.Level1)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);

    bool isEnable = true;
    EXPECT_EQ(sessionForSys->EnableDepthFusion(isEnable), CameraErrorCode::OPERATION_NOT_ALLOWED);

    sessionForSys->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession with IsLowLightBoostSupported
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsLowLightBoostSupported for abnormal branches
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_014, TestSize.Level1)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_NE(session->GetInputDevice(), nullptr);
    EXPECT_NE(session->GetInputDevice()->GetCameraDeviceInfo(), nullptr);

    auto deviceInfo = session->GetInputDevice()->GetCameraDeviceInfo();
    shared_ptr<OHOS::Camera::CameraMetadata> metadata = deviceInfo->GetMetadata();
    common_metadata_header_t* metadataEntry = metadata->get();
    OHOS::Camera::DeleteCameraMetadataItem(metadataEntry, OHOS_ABILITY_LOW_LIGHT_BOOST);
    EXPECT_FALSE(session->IsLowLightBoostSupported());

    input->Close();
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession with IsFeatureSupported
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsFeatureSupported for the default branches of switch
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_015, TestSize.Level1)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    SceneFeature feature = FEATURE_ENUM_MIN;
    EXPECT_FALSE(session->IsFeatureSupported(feature));
}

/*
 * Feature: Framework
 * Function: Test captureSession with ValidateOutputProfile
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ValidateOutputProfile for outputType is
 * CAPTURE_OUTPUT_TYPE_METADATA and CAPTURE_OUTPUT_TYPE_DEPTH_DATA
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_016, TestSize.Level1)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    EXPECT_NE(session->GetInputDevice(), nullptr);
    EXPECT_NE(session->GetInputDevice()->GetCameraDeviceInfo(), nullptr);

    Profile outputProfile;
    CaptureOutputType outputType = CAPTURE_OUTPUT_TYPE_METADATA;
    EXPECT_TRUE(session->ValidateOutputProfile(outputProfile, outputType));

    outputType = CAPTURE_OUTPUT_TYPE_DEPTH_DATA;
    EXPECT_TRUE(session->ValidateOutputProfile(outputProfile, outputType));

    outputType = CAPTURE_OUTPUT_TYPE_MAX;
    EXPECT_FALSE(session->ValidateOutputProfile(outputProfile, outputType));

    input->Close();
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession with EnableDeferredType
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EnableDeferredType for IsSessionCommited and the two branches of switch
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_017, TestSize.Level1)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_FALSE(session->isDeferTypeSetted_);
    DeferredDeliveryImageType type = DELIVERY_VIDEO;
    bool isEnableByUser = true;
    session->EnableDeferredType(type, isEnableByUser);
    EXPECT_TRUE(session->isDeferTypeSetted_);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    session->EnableDeferredType(type, isEnableByUser);

    input->Close();
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession with EnableAutoDeferredVideoEnhancement
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EnableAutoDeferredVideoEnhancement for IsSessionCommited and the two branches of switch
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_018, TestSize.Level1)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_FALSE(session->isVideoDeferred_);
    bool isEnableByUser = true;
    session->EnableAutoDeferredVideoEnhancement(isEnableByUser);
    EXPECT_TRUE(session->isVideoDeferred_);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    isEnableByUser = false;
    session->EnableAutoDeferredVideoEnhancement(isEnableByUser);
    EXPECT_TRUE(session->isVideoDeferred_);

    input->Close();
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession with EnableFeature
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EnableFeature for the two branches of switch
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_019, TestSize.Level1)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    SceneFeature feature = FEATURE_MACRO;
    bool isEnable = true;
    EXPECT_EQ(session->EnableFeature(feature, isEnable), CameraErrorCode::OPERATION_NOT_ALLOWED);
    feature = FEATURE_ENUM_MAX;
    EXPECT_EQ(session->EnableFeature(feature, isEnable), INVALID_ARGUMENT);

    session->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession with ExecuteAbilityChangeCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ExecuteAbilityChangeCallback for abilityCallback_ != nullptr
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_020, TestSize.Level1)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    session->SetAbilityCallback(make_shared<AppAbilityCallback>());
    EXPECT_NE(session->abilityCallback_, nullptr);
    session->ExecuteAbilityChangeCallback();

    session->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession with GetMetadata
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetMetadata for inputDevice == nullptr
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_021, TestSize.Level1)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->GetInputDevice(), nullptr);
    EXPECT_NE(session->GetMetadata(), nullptr);

    session->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession with GetSupportedWhiteBalanceModes and GetManualWhiteBalanceRange
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSupportedWhiteBalanceModes for inputDevice is nullptr and is not nullptr
 * and GetManualWhiteBalanceRange for inputDevice is nullptr
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_022, TestSize.Level1)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    std::vector<WhiteBalanceMode> supportedWhiteBalanceModes = {};
    EXPECT_NE(session->GetInputDevice(), nullptr);
    EXPECT_EQ(session->GetSupportedWhiteBalanceModes(supportedWhiteBalanceModes), CameraErrorCode::SUCCESS);

    session->SetInputDevice(nullptr);
    EXPECT_EQ(session->GetSupportedWhiteBalanceModes(supportedWhiteBalanceModes), CameraErrorCode::SUCCESS);
    std::vector<int32_t> whiteBalanceRange = {};
    EXPECT_EQ(session->GetManualWhiteBalanceRange(whiteBalanceRange), CameraErrorCode::SUCCESS);

    input->Close();
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession with IsWhiteBalanceModeSupported
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsWhiteBalanceModeSupported for mode is AWB_MODE_LOCKED and not
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_023, TestSize.Level1)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    WhiteBalanceMode mode = AWB_MODE_LOCKED;
    bool isSupported = false;
    EXPECT_EQ(session->IsWhiteBalanceModeSupported(mode, isSupported), CameraErrorCode::SUCCESS);

    mode = AWB_MODE_DAYLIGHT;
    EXPECT_EQ(session->IsWhiteBalanceModeSupported(mode, isSupported), CameraErrorCode::SUCCESS);

    input->Close();
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession with SetWhiteBalanceMode and GetWhiteBalanceMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetWhiteBalanceMode for mode is AWB_MODE_LOCKED and not
 * GetWhiteBalanceMode for invoke
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_024, TestSize.Level1)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    session->LockForControl();
    WhiteBalanceMode mode = AWB_MODE_LOCKED;
    EXPECT_EQ(session->SetWhiteBalanceMode(mode), CameraErrorCode::SUCCESS);

    mode = AWB_MODE_DAYLIGHT;
    EXPECT_EQ(session->SetWhiteBalanceMode(mode), CameraErrorCode::SUCCESS);
    session->UnlockForControl();
    EXPECT_EQ(session->GetWhiteBalanceMode(mode), CameraErrorCode::SUCCESS);
    input->Close();
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession with GetSupportedPortraitEffects
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSupportedPortraitEffects for not Commited and inputDevice is nullptr
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_025, TestSize.Level1)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->GetSupportedPortraitEffects().size(), 0);
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->GetSupportedPortraitEffects().size(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    EXPECT_EQ(session->GetSupportedPortraitEffects().size(), 0);

    session->SetInputDevice(nullptr);
    EXPECT_EQ(session->GetSupportedPortraitEffects().size(), 0);

    input->Close();
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession with EnableLcdFlash
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EnableLcdFlash for normal branches
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_026, TestSize.Level1)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(sessionForSys->BeginConfig(), 0);
    EXPECT_EQ(sessionForSys->AddInput(input), 0);
    EXPECT_EQ(sessionForSys->AddOutput(preview), 0);
    EXPECT_EQ(sessionForSys->CommitConfig(), 0);

    sessionForSys->LockForControl();
    bool isEnable = true;
    EXPECT_EQ(sessionForSys->EnableLcdFlash(isEnable), CameraErrorCode::SUCCESS);

    sessionForSys->UnlockForControl();
    input->Close();
    preview->Release();
    input->Release();
    sessionForSys->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession with EnableFaceDetection
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EnableFaceDetection for enable is false
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_027, TestSize.Level1)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    preview->outputType_ = CAPTURE_OUTPUT_TYPE_METADATA;
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    bool enable = false;
    session->EnableFaceDetection(enable);
    EXPECT_NE(session->GetMetaOutput(), nullptr);

    input->Close();
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test set camera parameters
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test set camera parameters zoom, focus, flash & exposure
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_001, TestSize.Level1)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);
    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    SessionControlParams(session);

    session->RemoveOutput(photo);
    session->RemoveInput(input);
    photo->Release();
    input->Release();
    EXPECT_EQ(session->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test capture session add input with invalid value
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session add input with invalid value
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_002, TestSize.Level1)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    sptr<CaptureInput> input = nullptr;
    ret = session->AddInput(input);
    EXPECT_NE(ret, 0);
    EXPECT_EQ(session->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test capture session add output with invalid value
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session add output with invalid value
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_003, TestSize.Level1)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    sptr<CaptureOutput> preview = nullptr;
    ret = session->AddOutput(preview);
    EXPECT_NE(ret, 0);
    EXPECT_EQ(session->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test capture session commit config without adding input
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session commit config without adding input
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_004, TestSize.Level1)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    ret = session->AddOutput(preview);
    EXPECT_EQ(ret, CameraErrorCode::SERVICE_FATL_ERROR);

    ret = session->CommitConfig();
    EXPECT_NE(ret, 0);
    session->RemoveOutput(preview);
    preview->Release();
    EXPECT_EQ(session->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test capture session commit config without adding output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session commit config without adding output
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_005, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = session->CommitConfig();
    EXPECT_NE(ret, 0);
    session->RemoveInput(input);
    input->Release();
    EXPECT_EQ(session->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test capture session without begin config
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session without begin config
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_006, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->AddInput(input);
    EXPECT_NE(ret, 0);

    ret = session->AddOutput(preview);
    EXPECT_NE(ret, 0);

    ret = session->AddOutput(photo);
    EXPECT_NE(ret, 0);

    ret = session->CommitConfig();
    EXPECT_NE(ret, 0);

    ret = session->Start();
    EXPECT_NE(ret, 0);

    ret = ((sptr<PreviewOutput> &)preview)->Start();
    EXPECT_NE(ret, 0);

    ret = ((sptr<PhotoOutput> &)photo)->Capture();
    EXPECT_NE(ret, 0);

    ret = ((sptr<PreviewOutput> &)preview)->Stop();
    EXPECT_NE(ret, 0);

    ret = session->Stop();
    EXPECT_NE(ret, 0);
    session->RemoveInput(input);
    session->RemoveOutput(preview);
    session->RemoveOutput(photo);
    preview->Release();
    photo->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test capture session start and stop without adding preview output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session start and stop without adding preview output
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_007, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    ret = session->Start();
    EXPECT_EQ(ret, 0);

    ret = session->Stop();
    EXPECT_EQ(ret, 0);

    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test session with preview + photo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test session with preview + photo
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_008, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(preview);
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    ret = session->Start();
    EXPECT_EQ(ret, 0);

    ret = ((sptr<PhotoOutput> &)photo)->Capture();
    EXPECT_EQ(ret, 0);

    ret = ((sptr<PreviewOutput> &)preview)->Stop();
    EXPECT_EQ(ret, 0);

    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test session with preview + photo with camera configuration
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test session with preview + photo with camera configuration
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_009, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    std::vector<float> zoomRatioRange = session->GetZoomRatioRange();
    if (!zoomRatioRange.empty()) {
        session->LockForControl();
        session->SetZoomRatio(zoomRatioRange[0]);
        session->UnlockForControl();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(preview);
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test session with video
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test session with video
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_010, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();

    sptr<CaptureOutput> video = CreateVideoOutput(videoProfile_[0]);
    ASSERT_NE(video, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(video), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    auto ret = ((sptr<VideoOutput> &)video)->Start();
    EXPECT_EQ(ret, 0);

    ret = ((sptr<VideoOutput> &)video)->Stop();
    EXPECT_EQ(ret, 0);

    ((sptr<VideoOutput> &)video)->Release();
    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test capture session remove output with null
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session remove output with null
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_011, TestSize.Level1)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    sptr<CaptureOutput> output = nullptr;
    ret = session->RemoveOutput(output);
    EXPECT_NE(ret, 0);
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test capture session remove output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session remove output
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_012, TestSize.Level1)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> video = CreateVideoOutput(videoProfile_[0]);
    ASSERT_NE(video, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(video);
    EXPECT_EQ(ret, 0);

    ret = session->RemoveOutput(video);
    EXPECT_EQ(ret, 0);
    input->Release();
    video->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test capture session remove input with null
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session remove input with null
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_013, TestSize.Level1)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    sptr<CaptureInput> input = nullptr;
    ret = session->RemoveInput(input);
    EXPECT_NE(ret, 0);
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test capture session remove input
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session remove input
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_014, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = session->RemoveInput(input);
    EXPECT_EQ(ret, 0);
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with no static capability.
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_015, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photo), 0);

    EXPECT_EQ(session->CommitConfig(), 0);

    sptr<CameraOutputCapability> cameraOutputCapability = cameraManager_->GetSupportedOutputCapability(cameras_[0]);

    OHOS::Camera::DeleteCameraMetadataItem(session->GetMetadata()->get(), OHOS_ABILITY_FOCUS_MODES);
    std::vector<FocusMode> supportedFocusModes = session->GetSupportedFocusModes();
    EXPECT_EQ(supportedFocusModes.empty(), true);
    EXPECT_EQ(session->GetSupportedFocusModes(supportedFocusModes), 0);

    EXPECT_EQ(session->GetFocusMode(), 0);

    float focalLength = 0;
    OHOS::Camera::DeleteCameraMetadataItem(session->GetMetadata()->get(), OHOS_ABILITY_FOCAL_LENGTH);
    session->GetMetadata()->addEntry(OHOS_ABILITY_FOCAL_LENGTH, &focalLength, 1);
    focalLength = session->GetFocalLength();
    EXPECT_EQ(focalLength, 0);
    EXPECT_EQ(session->GetFocalLength(focalLength), 0);

    std::vector<FlashMode> supportedFlashModes = session->GetSupportedFlashModes();
    EXPECT_EQ(session->GetSupportedFlashModes(supportedFlashModes), 0);
    FlashMode flashMode = FLASH_MODE_CLOSE;
    EXPECT_EQ(session->SetFlashMode(flashMode), CameraErrorCode::SUCCESS);
    EXPECT_EQ(session->GetFlashMode(), 0);

    bool isSupported;
    EXPECT_EQ(session->IsVideoStabilizationModeSupported(MIDDLE, isSupported), 0);
    if (isSupported) {
        EXPECT_EQ(session->SetVideoStabilizationMode(MIDDLE), 0);
    } else {
        EXPECT_EQ(session->SetVideoStabilizationMode(MIDDLE), 7400102);
    }

    sptr<PhotoOutput> photoOutput = (sptr<PhotoOutput> &)photo;
    EXPECT_EQ(photoOutput->IsMirrorSupported(), false);

    photo->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with anomalous branch
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_016, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras_[0]->GetMetadata();
    std::shared_ptr<ExposureCallback> exposureCallback = std::make_shared<CallbackListener>();
    session->SetExposureCallback(exposureCallback);
    session->ProcessAutoExposureUpdates(metadata);

    std::shared_ptr<FocusCallback> focusCallback = std::make_shared<CallbackListener>();
    session->SetFocusCallback(focusCallback);
    session->ProcessAutoFocusUpdates(metadata);

    std::vector<FocusMode> getSupportedFocusModes = session->GetSupportedFocusModes();
    EXPECT_EQ(getSupportedFocusModes.empty(), false);
    int32_t supportedFocusModesGet = session->GetSupportedFocusModes(getSupportedFocusModes);
    EXPECT_EQ(supportedFocusModesGet, 0);

    photo->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test anomalous branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with anomalous branch.
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_017, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photo), 0);

    EXPECT_EQ(session->CommitConfig(), 0);

    uint8_t focusMode = 2;
    session->GetMetadata()->addEntry(OHOS_CONTROL_FOCUS_MODE, &focusMode, 1);
    EXPECT_EQ(session->GetFocusMode(), 2);

    session->LockForControl();

    FlashMode flash = FLASH_MODE_ALWAYS_OPEN;
    session->SetFlashMode(flash);
    session->SetFlashMode(flash);

    FocusMode focus = FOCUS_MODE_CONTINUOUS_AUTO;
    session->SetFocusMode(focus);
    session->SetFocusMode(focus);

    ExposureMode exposure = EXPOSURE_MODE_AUTO;
    session->SetExposureMode(exposure);

    float zoomRatioRange = session->GetZoomRatio();
    session->SetZoomRatio(zoomRatioRange);
    session->SetZoomRatio(zoomRatioRange);

    session->UnlockForControl();

    EXPECT_EQ(session->GetFocusMode(focus), 0);

    cameraManager_->GetSupportedOutputCapability(cameras_[0], 0);

    VideoStabilizationMode stabilizationMode = MIDDLE;
    session->GetActiveVideoStabilizationMode();
    session->GetActiveVideoStabilizationMode(stabilizationMode);
    session->SetVideoStabilizationMode(stabilizationMode);

    input->Close();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CameraServerDied
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test if innerCaptureSession_ == nullptr in CameraServerDied
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_018, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
    auto appCallback = std::make_shared<AppSessionCallback>();
    ASSERT_NE(appCallback, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    session->CameraServerDied(0);
    session->appCallback_ = appCallback;
    session->CameraServerDied(0);
    session->innerCaptureSession_ = nullptr;
    session->CameraServerDied(0);
    session->appCallback_ = nullptr;

    EXPECT_EQ(preview->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test innerInputDevice_ in GetColorEffect,
 *          EnableMacro, IsMacroSupported,
 *          SetColorEffect, ProcessMacroStatusChange
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test innerInputDevice_ in GetColorEffect,
 *          EnableMacro, IsMacroSupported,
 *          SetColorEffect, ProcessMacroStatusChange
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_019, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
    auto macroStatusCallback = std::make_shared<AppMacroStatusCallback>();

    EXPECT_EQ(sessionForSys->GetColorEffect(), COLOR_EFFECT_NORMAL);
    EXPECT_EQ(sessionForSys->EnableMacro(true), OPERATION_NOT_ALLOWED);

    EXPECT_EQ(sessionForSys->BeginConfig(), 0);

    EXPECT_EQ(sessionForSys->AddInput(input), 0);
    EXPECT_EQ(sessionForSys->AddOutput(preview), 0);

    EXPECT_EQ(sessionForSys->CommitConfig(), 0);
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras_[0]->GetMetadata();
    EXPECT_EQ(sessionForSys->GetColorEffect(), COLOR_EFFECT_NORMAL);

    ((sptr<CameraInput>&)(sessionForSys->innerInputDevice_))->cameraObj_ = nullptr;
    EXPECT_EQ(sessionForSys->GetColorEffect(), COLOR_EFFECT_NORMAL);
    EXPECT_EQ(sessionForSys->IsMacroSupported(), false);
    sessionForSys->innerInputDevice_ = nullptr;
    EXPECT_EQ(sessionForSys->GetColorEffect(), COLOR_EFFECT_NORMAL);
    EXPECT_EQ(sessionForSys->IsMacroSupported(), false);
    EXPECT_EQ(sessionForSys->EnableMacro(true), OPERATION_NOT_ALLOWED);

    sessionForSys->LockForControl();
    sessionForSys->SetColorEffect(COLOR_EFFECT_NORMAL);
    sessionForSys->UnlockForControl();

    sessionForSys->macroStatusCallback_ = macroStatusCallback;
    sessionForSys->ProcessMacroStatusChange(metadata);

    EXPECT_EQ(preview->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
    EXPECT_EQ(sessionForSys->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test !IsSessionConfiged() || input == nullptr in CanAddInput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test !IsSessionConfiged() || input == nullptr in CanAddInput
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_020, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    sptr<CaptureInput> input1 = nullptr;
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->CanAddInput(input), false);
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->CanAddInput(input), true);
    EXPECT_EQ(session->CanAddInput(input1), false);
    session->innerCaptureSession_ = nullptr;
    EXPECT_EQ(session->CanAddInput(input), false);

    EXPECT_EQ(session->AddInput(input), OPERATION_NOT_ALLOWED);
    EXPECT_EQ(session->AddOutput(preview), OPERATION_NOT_ALLOWED);

    EXPECT_EQ(session->CommitConfig(), OPERATION_NOT_ALLOWED);

    EXPECT_EQ(session->RemoveOutput(preview), OPERATION_NOT_ALLOWED);
    EXPECT_EQ(session->RemoveInput(input), OPERATION_NOT_ALLOWED);
    EXPECT_EQ(preview->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test !IsSessionConfiged() || output == nullptr in CanAddOutput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test !IsSessionConfiged() || output == nullptr in CanAddOutput
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_021, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    sptr<CaptureOutput> output = nullptr;
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->CanAddOutput(preview), false);
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->CanAddOutput(output), false);
    preview->Release();
    EXPECT_EQ(session->CanAddOutput(preview), false);

    EXPECT_EQ(input->Close(), 0);
}

/*
 * Feature: Framework
 * Function: Test !IsSessionConfiged() || output == nullptr in CanAddOutput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test !inputDevice || !inputDevice->GetCameraDeviceInfo() in CanAddOutput
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_022, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    session->innerInputDevice_ = nullptr;
    EXPECT_EQ(session->CanAddOutput(preview), false);

    session->SetInputDevice(camInput);
    EXPECT_NE(session->innerInputDevice_, nullptr);
    EXPECT_EQ(session->CanAddOutput(preview), true);

    EXPECT_EQ(input->Close(), 0);
}

/*
 * Feature: Framework
 * Function: Test VerifyAbility, SetBeauty
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test VerifyAbility, SetBeauty
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_023, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);

    EXPECT_EQ(session->VerifyAbility(static_cast<uint32_t>(OHOS_ABILITY_SCENE_FILTER_TYPES)), CAMERA_INVALID_ARG);
    session->LockForControl();
    session->SetBeauty(FACE_SLENDER, 3);
    session->UnlockForControl();

    EXPECT_EQ(session->CommitConfig(), 0);

    EXPECT_EQ(preview->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
    EXPECT_EQ(session->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test CheckFrameRateRangeWithCurrentFps
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CheckFrameRateRangeWithCurrentFps
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_024, TestSize.Level1)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession(SceneMode::CAPTURE);
    ASSERT_NE(session, nullptr);
    ASSERT_EQ(session->CheckFrameRateRangeWithCurrentFps(30, 30, 30, 60), false);
    ASSERT_EQ(session->CheckFrameRateRangeWithCurrentFps(30, 30, 30, 60), false);
    ASSERT_EQ(session->CheckFrameRateRangeWithCurrentFps(20, 40, 20, 40), true);
    ASSERT_EQ(session->CheckFrameRateRangeWithCurrentFps(20, 40, 30, 60), false);
}

/*
 * Feature: Framework
 * Function: Test CanPreconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CanPreconfig
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_025, TestSize.Level1)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    PreconfigType preconfigType = PreconfigType::PRECONFIG_720P;
    ProfileSizeRatio preconfigRatio = ProfileSizeRatio::RATIO_16_9;
    EXPECT_EQ(session->CanPreconfig(preconfigType, preconfigRatio), false);
    int32_t result = session->Preconfig(preconfigType, preconfigRatio);
    EXPECT_EQ(result, CAMERA_UNSUPPORTED);
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with GetSupportedExposureModes and GetSupportedStabilizationMode
 * when not Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with GetSupportedExposureModes and GetSupportedStabilizationMode
 * when not Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_001, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(surface, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    std::vector<VideoStabilizationMode> videoStabilizationMode = session->GetSupportedStabilizationMode();
    EXPECT_EQ(videoStabilizationMode.empty(), true);
    std::vector<ExposureMode> getSupportedExpModes = session->GetSupportedExposureModes();
    EXPECT_EQ(getSupportedExpModes.empty(), true);

    EXPECT_EQ(session->GetSupportedExposureModes(getSupportedExpModes), CameraErrorCode::SESSION_NOT_CONFIG);
    EXPECT_EQ(session->GetSupportedStabilizationMode(videoStabilizationMode), CameraErrorCode::SESSION_NOT_CONFIG);

    EXPECT_EQ(preview->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with GetSupportedExposureModes and GetSupportedStabilizationMode
 * when Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with GetSupportedExposureModes and GetSupportedStabilizationMode
 * when Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_002, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    std::vector<VideoStabilizationMode> videoStabilizationMode = session->GetSupportedStabilizationMode();
    EXPECT_EQ(videoStabilizationMode.empty(), true);
    std::vector<ExposureMode> getSupportedExpModes = session->GetSupportedExposureModes();
    EXPECT_EQ(getSupportedExpModes.empty(), true);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->GetSupportedExposureModes(getSupportedExpModes), CameraErrorCode::SUCCESS);
    EXPECT_EQ(session->GetSupportedStabilizationMode(videoStabilizationMode), CameraErrorCode::SUCCESS);

    EXPECT_EQ(preview->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with GetExposureMode and SetExposureMode when Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with GetExposureMode and SetExposureMode when Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_003, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);
    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);
    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);
    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    session->LockForControl();

    Point exposurePoint = {1.0, 2.0};
    session->SetMeteringPoint(exposurePoint);
    session->SetMeteringPoint(exposurePoint);

    ExposureMode exposure = EXPOSURE_MODE_AUTO;
    bool exposureSupported = session->IsExposureModeSupported(exposure);
    if (exposureSupported) {
        ret = session->SetExposureMode(exposure);
        EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
    }

    ret = session->GetExposureMode(exposure);
    EXPECT_EQ(ret, 0);

    ExposureMode exposureMode = session->GetExposureMode();
    exposureSupported = session->IsExposureModeSupported(exposureMode);
    if (exposureSupported) {
        int32_t setExposureMode = session->SetExposureMode(exposureMode);
        EXPECT_EQ(setExposureMode, 0);
    }
    session->UnlockForControl();
    input->Release();
    photo->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with GetExposureMode and SetExposureMode when not Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with GetExposureMode and SetExposureMode when not Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_004, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    session->LockForControl();

    Point exposurePoint = {1.0, 2.0};
    session->SetMeteringPoint(exposurePoint);
    session->SetMeteringPoint(exposurePoint);

    ExposureMode exposure = EXPOSURE_MODE_AUTO;
    EXPECT_EQ(session->SetExposureMode(exposure), CameraErrorCode::SESSION_NOT_CONFIG);
    EXPECT_EQ(session->GetExposureMode(exposure), CameraErrorCode::SESSION_NOT_CONFIG);

    session->UnlockForControl();
    input->Release();
    photo->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with SetMeteringPoint & GetMeteringPoint when Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with SetMeteringPoint & GetMeteringPoint when Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_005, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);
    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);
    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);
    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    Point exposurePoint = {1.0, 2.0};
    session->LockForControl();
    session->SetMeteringPoint(exposurePoint);
    session->UnlockForControl();
    ASSERT_EQ((session->GetMeteringPoint().x), exposurePoint.x > 1 ? 1 : exposurePoint.x);
    ASSERT_EQ((session->GetMeteringPoint().y), exposurePoint.y > 1 ? 1 : exposurePoint.y);

    session->RemoveInput(input);
    session->RemoveOutput(photo);
    photo->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with SetMeteringPoint & GetMeteringPoint when not Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with SetMeteringPoint & GetMeteringPoint when not Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_006, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    Point exposurePoint = {1.0, 2.0};
    session->LockForControl();
    EXPECT_EQ(session->SetMeteringPoint(exposurePoint), CameraErrorCode::SESSION_NOT_CONFIG);
    session->UnlockForControl();
    EXPECT_EQ(session->GetMeteringPoint(exposurePoint), CameraErrorCode::SESSION_NOT_CONFIG);

    session->RemoveInput(input);
    session->RemoveOutput(photo);
    photo->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with GetExposureValue and SetExposureBias when not Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with GetExposureValue and SetExposureBias when not Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_007, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    std::vector<float> exposurebiasRange = session->GetExposureBiasRange();
    EXPECT_EQ(session->GetExposureBiasRange(exposurebiasRange), CameraErrorCode::SESSION_NOT_CONFIG);
    session->LockForControl();
    float exposureValue = session->GetExposureValue();
    int32_t exposureValueGet = session->GetExposureValue(exposureValue);
    EXPECT_EQ(exposureValueGet, CameraErrorCode::SESSION_NOT_CONFIG);

    int32_t setExposureBias = session->SetExposureBias(exposureValue);
    EXPECT_EQ(setExposureBias, CameraErrorCode::SESSION_NOT_CONFIG);

    session->UnlockForControl();
    input->Close();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with GetExposureValue and SetExposureBias
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with GetExposureValue and SetExposureBias with value less then the range
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_008, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);
    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);
    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);
    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    std::vector<float> exposurebiasRange = session->GetExposureBiasRange();
    if (!exposurebiasRange.empty()) {
        session->LockForControl();
        session->SetExposureBias(exposurebiasRange[0]-1.0);
        session->UnlockForControl();
        ASSERT_EQ(session->GetExposureValue(), exposurebiasRange[0]);
    }

    session->RemoveInput(input);
    session->RemoveOutput(photo);
    photo->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with GetExposureValue and SetExposureBias
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with GetExposureValue and SetExposureBias with value between the range
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_009, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);
    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);
    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);
    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    std::vector<float> exposurebiasRange = session->GetExposureBiasRange();
    if (!exposurebiasRange.empty()) {
        session->LockForControl();
        session->SetExposureBias(exposurebiasRange[0]+1.0);
        session->UnlockForControl();
        EXPECT_TRUE((session->GetExposureValue()>=exposurebiasRange[0] &&
                session->GetExposureValue()<=exposurebiasRange[1]));
    }
    session->RemoveInput(input);
    session->RemoveOutput(photo);
    photo->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with GetExposureValue and SetExposureBias
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with GetExposureValue and SetExposureBias with value more then the range
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_010, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);
    SceneMode mode = CAPTURE;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession(mode);
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);
    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);
    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);
    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    std::vector<float> exposurebiasRange = session->GetExposureBiasRange();
    if (!exposurebiasRange.empty()) {
        session->LockForControl();
        session->SetExposureBias(exposurebiasRange[1]+1.0);
        session->UnlockForControl();
    }
    ASSERT_EQ(session->GetExposureValue(), exposurebiasRange[1]);
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with GetSupportedFocusModes and IsFocusModeSupported when not Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with GetSupportedFocusModes and IsFocusModeSupported when not Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_011, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    std::vector<FocusMode> getSupportedFocusModes = session->GetSupportedFocusModes();
    EXPECT_EQ(session->GetSupportedFocusModes(getSupportedFocusModes), CameraErrorCode::SESSION_NOT_CONFIG);

    FocusMode focusMode = FOCUS_MODE_AUTO;
    bool isSupported;
    EXPECT_EQ(session->IsFocusModeSupported(focusMode, isSupported), CameraErrorCode::SESSION_NOT_CONFIG);

    input->Close();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with GetSupportedFocusModes and IsFocusModeSupported when Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with GetSupportedFocusModes and IsFocusModeSupported when Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_012, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);
    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);
    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);
    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    std::vector<FocusMode> getSupportedFocusModes = session->GetSupportedFocusModes();
    EXPECT_EQ(session->GetSupportedFocusModes(getSupportedFocusModes), 0);

    FocusMode focusMode = FOCUS_MODE_AUTO;
    bool isSupported;
    EXPECT_EQ(session->IsFocusModeSupported(focusMode, isSupported), 0);

    input->Close();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with SetFocusMode and GetFocusMode when not Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with SetFocusMode and GetFocusMode when not Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_013, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    FocusMode focusMode = FOCUS_MODE_AUTO;
    EXPECT_EQ(session->SetFocusMode(focusMode), CameraErrorCode::SESSION_NOT_CONFIG);

    FocusMode focusModeRet = session->GetFocusMode();
    EXPECT_EQ(session->GetFocusMode(focusModeRet), CameraErrorCode::SESSION_NOT_CONFIG);

    input->Close();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with SetFocusMode and GetFocusMode when Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with SetFocusMode and GetFocusMode when Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_014, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);
    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);
    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);
    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    FocusMode focusMode = FOCUS_MODE_AUTO;
    EXPECT_EQ(session->SetFocusMode(focusMode), 0);

    FocusMode focusModeRet = session->GetFocusMode();
    EXPECT_EQ(session->GetFocusMode(focusModeRet), 0);

    input->Close();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with SetFocusPoint and GetFocusPoint when not Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with SetFocusPoint and GetFocusPoint when not Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_015, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    Point FocusPoint = {1.0, 2.0};
    session->LockForControl();
    EXPECT_EQ(session->SetFocusPoint(FocusPoint), CameraErrorCode::SESSION_NOT_CONFIG);
    session->UnlockForControl();

    EXPECT_EQ(session->GetFocusPoint(FocusPoint), CameraErrorCode::SESSION_NOT_CONFIG);

    session->RemoveInput(input);
    session->RemoveOutput(photo);
    photo->Release();
    input->Close();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with SetFocusPoint and GetFocusPoint when Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with SetFocusPoint and GetFocusPoint when Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_016, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);
    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);
    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);
    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    Point FocusPoint = {1.0, 2.0};
    session->LockForControl();
    EXPECT_EQ(session->SetFocusPoint(FocusPoint), 0);
    session->UnlockForControl();

    EXPECT_EQ(session->GetFocusPoint(FocusPoint), 0);

    session->RemoveInput(input);
    session->RemoveOutput(photo);
    photo->Release();
    input->Close();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with GetFocalLength when not Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with GetFocalLength when not Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_017, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    float focalLength = session->GetFocalLength();
    EXPECT_EQ(session->GetFocalLength(focalLength), CameraErrorCode::SESSION_NOT_CONFIG);
    EXPECT_EQ(focalLength, 0);

    session->RemoveInput(input);
    session->RemoveOutput(photo);
    photo->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with GetFocalLength when Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with GetFocalLength when Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_018, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);
    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);
    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);
    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    float focalLength = 16;
    OHOS::Camera::DeleteCameraMetadataItem(session->GetMetadata()->get(), OHOS_ABILITY_FOCAL_LENGTH);
    session->GetMetadata()->addEntry(OHOS_ABILITY_FOCAL_LENGTH, &focalLength, 1);
    EXPECT_EQ(session->GetFocalLength(focalLength), 0);
    ASSERT_EQ(focalLength, 16);

    session->RemoveInput(input);
    session->RemoveOutput(photo);
    photo->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with GetSupportedFlashModes and GetFlashMode and SetFlashMode when not Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with GetSupportedFlashModes and GetFlashMode and SetFlashMode
 * when not Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_019, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    std::vector<FlashMode> supportedFlashModes = session->GetSupportedFlashModes();
    EXPECT_EQ(session->GetSupportedFlashModes(supportedFlashModes), CameraErrorCode::SESSION_NOT_CONFIG);

    FlashMode flashMode = session->GetFlashMode();
    EXPECT_EQ(session->GetFlashMode(flashMode), CameraErrorCode::SESSION_NOT_CONFIG);
    EXPECT_EQ(session->SetFlashMode(flashMode), CameraErrorCode::SESSION_NOT_CONFIG);

    input->Close();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with GetSupportedFlashModes and GetFlashMode and SetFlashMode when Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with GetSupportedFlashModes and GetFlashMode and SetFlashMode when Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_020, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);
    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);
    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);
    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    std::vector<FlashMode> supportedFlashModes = session->GetSupportedFlashModes();
    EXPECT_EQ(session->GetSupportedFlashModes(supportedFlashModes), 0);

    FlashMode flashMode = FLASH_MODE_ALWAYS_OPEN;
    EXPECT_EQ(session->SetFlashMode(flashMode), 0);
    FlashMode flashModeRet;
    EXPECT_EQ(session->GetFlashMode(flashModeRet), 0);

    input->Close();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with HasFlash and IsFlashModeSupported when not Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with HasFlash and IsFlashModeSupported when not Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_021, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    bool hasFlash = session->HasFlash();
    EXPECT_EQ(session->HasFlash(hasFlash), CameraErrorCode::SESSION_NOT_CONFIG);

    FlashMode flashMode = FLASH_MODE_AUTO;
    bool isSupported = false;
    EXPECT_EQ(session->IsFlashModeSupported(flashMode), false);
    EXPECT_EQ(session->IsFlashModeSupported(flashMode, isSupported), CameraErrorCode::SESSION_NOT_CONFIG);

    input->Close();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with HasFlash and IsFlashModeSupported when Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with HasFlash and IsFlashModeSupported when Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_022, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    bool hasFlash = session->HasFlash();
    EXPECT_EQ(session->HasFlash(hasFlash), 0);

    FlashMode flashMode = FLASH_MODE_AUTO;
    bool isSupported = false;
    EXPECT_EQ(session->IsFlashModeSupported(flashMode, isSupported), 0);

    input->Close();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with GetZoomRatio and SetZoomRatio when not Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with GetZoomRatio and SetZoomRatio when not Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_023, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    float zoomRatio = session->GetZoomRatio();
    std::vector<float> zoomRatioRange = session->GetZoomRatioRange();
    EXPECT_EQ(session->GetZoomRatioRange(zoomRatioRange), CameraErrorCode::SESSION_NOT_CONFIG);
    EXPECT_EQ(session->GetZoomRatio(zoomRatio), CameraErrorCode::SESSION_NOT_CONFIG);
    EXPECT_EQ(session->SetZoomRatio(zoomRatio), CameraErrorCode::SESSION_NOT_CONFIG);

    input->Close();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with PrepareZoom, UnPrepareZoom, SetSmoothZoom when Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with PrepareZoom, UnPrepareZoom, SetSmoothZoom when Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_024, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->PrepareZoom(), CameraErrorCode::SUCCESS);
    EXPECT_EQ(session->UnPrepareZoom(), CameraErrorCode::SUCCESS);

    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);

    session->SetSmoothZoom(0, 0);

    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->PrepareZoom(), CameraErrorCode::SUCCESS);
    EXPECT_EQ(session->UnPrepareZoom(), CameraErrorCode::SUCCESS);
    EXPECT_EQ(session->SetSmoothZoom(0, 0), CameraErrorCode::SUCCESS);

    session->LockForControl();
    session->PrepareZoom();
    session->UnPrepareZoom();
    session->UnlockForControl();

    EXPECT_EQ(preview->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with PrepareZoom, UnPrepareZoom, SetSmoothZoom when not Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with PrepareZoom, UnPrepareZoom, SetSmoothZoom when not Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_025, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->PrepareZoom(), CameraErrorCode::SESSION_NOT_CONFIG);
    EXPECT_EQ(session->UnPrepareZoom(), CameraErrorCode::SESSION_NOT_CONFIG);
    EXPECT_EQ(session->SetSmoothZoom(0, 0), CameraErrorCode::SESSION_NOT_CONFIG);

    EXPECT_EQ(input->Release(), 0);
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with GetZoomPointInfos when not Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with GetZoomPointInfos when not Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_026, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);

    std::vector<ZoomPointInfo> zoomPointInfoList;
    EXPECT_EQ(sessionForSys->GetZoomPointInfos(zoomPointInfoList), CameraErrorCode::SESSION_NOT_CONFIG);

    sessionForSys->RemoveInput(input);
    sessionForSys->RemoveOutput(photo);
    photo->Release();
    input->Release();
    sessionForSys->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with GetZoomPointInfos when Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with GetZoomPointInfos when Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_027, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);

    int32_t ret = sessionForSys->BeginConfig();
    EXPECT_EQ(ret, 0);
    ret = sessionForSys->AddInput(input);
    EXPECT_EQ(ret, 0);
    ret = sessionForSys->AddOutput(photo);
    EXPECT_EQ(ret, 0);
    ret = sessionForSys->CommitConfig();
    EXPECT_EQ(ret, 0);

    std::vector<ZoomPointInfo> zoomPointInfoList;
    EXPECT_EQ(sessionForSys->GetZoomPointInfos(zoomPointInfoList), 0);

    sessionForSys->RemoveInput(input);
    sessionForSys->RemoveOutput(photo);
    photo->Release();
    input->Release();
    sessionForSys->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with GetSupportedFilters and GetFilter and SetFilter when not Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with GetSupportedFilters and GetFilter and SetFilter when not Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_028, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    std::vector<FilterType> supportedFilters = {};
    EXPECT_EQ(session->GetSupportedFilters(), supportedFilters);
    FilterType filter = NONE;
    session->SetFilter(filter);
    EXPECT_EQ(session->GetFilter(), FilterType::NONE);

    session->RemoveInput(input);
    session->RemoveOutput(photo);
    photo->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with GetSupportedFilters and GetFilter and SetFilter when Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with GetSupportedFilters and GetFilter and SetFilter when Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_029, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);

    FilterType filter = NONE;
    session->SetFilter(filter);
    EXPECT_EQ(session->GetFilter(), FilterType::NONE);

    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);
    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);
    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    std::vector<FilterType> supportedFilters = {};
    EXPECT_EQ(session->GetSupportedFilters(), supportedFilters);
    session->SetFilter(filter);
    EXPECT_EQ(session->GetFilter(), FilterType::NONE);

    session->LockForControl();
    session->SetFilter(filter);
    EXPECT_EQ(session->GetFilter(), FilterType::NONE);
    session->UnlockForControl();

    session->RemoveInput(input);
    session->RemoveOutput(photo);
    photo->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with SetBeauty and GetBeauty when Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with SetBeauty and GetBeauty when Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_030, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    BeautyType beautyType = AUTO_TYPE;
    EXPECT_EQ(sessionForSys->BeginConfig(), 0);
    sessionForSys->SetBeauty(AUTO_TYPE, 0);
    EXPECT_EQ(sessionForSys->GetBeauty(beautyType), -1);
    EXPECT_EQ(sessionForSys->AddInput(input), 0);
    EXPECT_EQ(sessionForSys->AddOutput(preview), 0);

    EXPECT_EQ(sessionForSys->CommitConfig(), 0);
    sessionForSys->SetBeauty(AUTO_TYPE, 0);
    EXPECT_EQ(sessionForSys->GetBeauty(beautyType), -1);

    sessionForSys->LockForControl();
    sessionForSys->SetBeauty(SKIN_SMOOTH, 0);
    EXPECT_EQ(sessionForSys->GetBeauty(beautyType), -1);
    sessionForSys->UnlockForControl();

    EXPECT_EQ(preview->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
    EXPECT_EQ(sessionForSys->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with SetBeauty and GetBeauty when not Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with SetBeauty and GetBeauty when not Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_031, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    BeautyType beautyType = AUTO_TYPE;
    sessionForSys->SetBeauty(AUTO_TYPE, 0);
    EXPECT_EQ(sessionForSys->GetBeauty(beautyType), CameraErrorCode::SESSION_NOT_CONFIG);

    EXPECT_EQ(preview->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
    EXPECT_EQ(sessionForSys->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with SetColorSpace and GetActiveColorSpace when Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with SetColorSpace and GetActiveColorSpace when Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_032, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    ColorSpace colorSpace = DISPLAY_P3;
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->SetColorSpace(colorSpace), 7400101);
    EXPECT_EQ(session->GetActiveColorSpace(colorSpace), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);

    EXPECT_EQ(session->CommitConfig(), 0);
    auto supColor = session->GetSupportedColorSpaces();
    if (!supColor.empty()) {
        colorSpace = supColor[0];
        EXPECT_EQ(session->SetColorSpace(colorSpace), 0);
        EXPECT_EQ(session->GetActiveColorSpace(colorSpace), 0);

        EXPECT_EQ(preview->Release(), 0);
        EXPECT_EQ(input->Release(), 0);
        EXPECT_EQ(session->Release(), 0);
    }
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with SetColorSpace and GetActiveColorSpace when not Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with SetColorSpace and GetActiveColorSpace when not Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_033, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    ColorSpace colorSpace = DISPLAY_P3;
    EXPECT_EQ(session->SetColorSpace(colorSpace), CameraErrorCode::SESSION_NOT_CONFIG);
    EXPECT_EQ(session->GetActiveColorSpace(colorSpace), CameraErrorCode::SESSION_NOT_CONFIG);

    EXPECT_EQ(preview->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
    EXPECT_EQ(session->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test captureSession with SetFocusRange
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetFocusRange normal branches
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_034, TestSize.Level1)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(sessionForSys->BeginConfig(), 0);
    EXPECT_EQ(sessionForSys->AddInput(input), 0);
    EXPECT_EQ(sessionForSys->AddOutput(preview), 0);
    EXPECT_EQ(sessionForSys->CommitConfig(), 0);

    std::vector<FocusRangeType> types;
    EXPECT_EQ(sessionForSys->GetSupportedFocusRangeTypes(types), 0);
    if (!types.empty()) {
        bool isSupported = false;
        EXPECT_EQ(sessionForSys->IsFocusRangeTypeSupported(types[0], isSupported), 0);
        if (isSupported) {
            sessionForSys->LockForControl();
            EXPECT_EQ(sessionForSys->SetFocusRange(types[0]), 0);
            sessionForSys->UnlockForControl();
            FocusRangeType type = FOCUS_RANGE_TYPE_NEAR;
            EXPECT_EQ(sessionForSys->GetFocusRange(type), types[0]);
        }
    }

    input->Close();
    preview->Release();
    input->Release();
    sessionForSys->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession with SetFocusDriven
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetFocusDriven normal branches
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_035, TestSize.Level1)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(sessionForSys->BeginConfig(), 0);
    EXPECT_EQ(sessionForSys->AddInput(input), 0);
    EXPECT_EQ(sessionForSys->AddOutput(preview), 0);
    EXPECT_EQ(sessionForSys->CommitConfig(), 0);

    std::vector<FocusDrivenType> types;
    EXPECT_EQ(sessionForSys->GetSupportedFocusDrivenTypes(types), 0);
    if (!types.empty()) {
        bool isSupported = false;
        EXPECT_EQ(sessionForSys->IsFocusDrivenTypeSupported(types[0], isSupported), 0);
        if (isSupported) {
            sessionForSys->LockForControl();
            EXPECT_EQ(sessionForSys->SetFocusDriven(types[0]), 0);
            sessionForSys->UnlockForControl();
            FocusDrivenType type = FOCUS_DRIVEN_TYPE_FACE;
            EXPECT_EQ(sessionForSys->GetFocusDriven(type), types[0]);
        }
    }

    input->Close();
    preview->Release();
    input->Release();
    sessionForSys->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession with SetColorReservation
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetColorReservation normal branches
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_036, TestSize.Level1)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(sessionForSys->BeginConfig(), 0);
    EXPECT_EQ(sessionForSys->AddInput(input), 0);
    EXPECT_EQ(sessionForSys->AddOutput(preview), 0);
    EXPECT_EQ(sessionForSys->CommitConfig(), 0);

    std::vector<ColorReservationType> types;
    EXPECT_EQ(sessionForSys->GetSupportedColorReservationTypes(types), 0);
    if (!types.empty()) {
        bool isSupported = false;
        EXPECT_EQ(sessionForSys->IsColorReservationTypeSupported(types[0], isSupported), 0);
        if (isSupported) {
            sessionForSys->LockForControl();
            EXPECT_EQ(sessionForSys->SetColorReservation(types[0]), 0);
            sessionForSys->UnlockForControl();
            ColorReservationType type = COLOR_RESERVATION_TYPE_PORTRAIT;
            EXPECT_EQ(sessionForSys->GetColorReservation(type), types[0]);
        }
    }

    input->Close();
    preview->Release();
    input->Release();
    sessionForSys->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession abnormal branches before commit config
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureSession abnormal branches before commit config
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_037, TestSize.Level1)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(sessionForSys->BeginConfig(), 0);
    EXPECT_EQ(sessionForSys->AddInput(input), 0);
    EXPECT_EQ(sessionForSys->AddOutput(preview), 0);

    FocusRangeType testType_1 = FOCUS_RANGE_TYPE_NEAR;
    bool isSupported = true;
    EXPECT_EQ(sessionForSys->IsFocusRangeTypeSupported(testType_1, isSupported), CameraErrorCode::SESSION_NOT_CONFIG);
    EXPECT_EQ(sessionForSys->GetFocusRange(testType_1), CameraErrorCode::SESSION_NOT_CONFIG);
    EXPECT_EQ(sessionForSys->SetFocusRange(testType_1), CameraErrorCode::SESSION_NOT_CONFIG);

    FocusDrivenType testType_2 = FOCUS_DRIVEN_TYPE_FACE;
    EXPECT_EQ(sessionForSys->IsFocusDrivenTypeSupported(testType_2, isSupported), CameraErrorCode::SESSION_NOT_CONFIG);
    EXPECT_EQ(sessionForSys->GetFocusDriven(testType_2), CameraErrorCode::SESSION_NOT_CONFIG);
    EXPECT_EQ(sessionForSys->SetFocusDriven(testType_2), CameraErrorCode::SESSION_NOT_CONFIG);

    std::vector<ColorReservationType> testTypes_3;
    EXPECT_EQ(sessionForSys->GetSupportedColorReservationTypes(testTypes_3), CameraErrorCode::SESSION_NOT_CONFIG);
    ColorReservationType testType_3 = COLOR_RESERVATION_TYPE_PORTRAIT;
    EXPECT_EQ(sessionForSys->GetColorReservation(testType_3), CameraErrorCode::SESSION_NOT_CONFIG);
    EXPECT_EQ(sessionForSys->SetColorReservation(testType_3), CameraErrorCode::SESSION_NOT_CONFIG);

    EXPECT_EQ(sessionForSys->CommitConfig(), 0);

    input->Close();
    preview->Release();
    input->Release();
    sessionForSys->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession with abnormal parameter
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureSession abnormal branches with abnormal parameter
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_038, TestSize.Level1)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(sessionForSys->BeginConfig(), 0);
    EXPECT_EQ(sessionForSys->AddInput(input), 0);
    EXPECT_EQ(sessionForSys->AddOutput(preview), 0);
    EXPECT_EQ(sessionForSys->CommitConfig(), 0);

    int32_t num = -1;
    FocusRangeType testType_1 = static_cast<FocusRangeType>(num);
    bool isSupported = true;
    EXPECT_EQ(sessionForSys->IsFocusRangeTypeSupported(testType_1, isSupported), CameraErrorCode::PARAMETER_ERROR);
    FocusDrivenType testType_2 = static_cast<FocusDrivenType>(num);
    EXPECT_EQ(sessionForSys->IsFocusDrivenTypeSupported(testType_2, isSupported), CameraErrorCode::PARAMETER_ERROR);
    ColorReservationType testType_3 = static_cast<ColorReservationType>(num);
    EXPECT_EQ(sessionForSys->IsColorReservationTypeSupported(testType_3, isSupported),
        CameraErrorCode::PARAMETER_ERROR);

    sessionForSys->LockForControl();
    EXPECT_EQ(sessionForSys->SetFocusRange(testType_1), CameraErrorCode::PARAMETER_ERROR);
    EXPECT_EQ(sessionForSys->SetFocusDriven(testType_2), CameraErrorCode::PARAMETER_ERROR);
    EXPECT_EQ(sessionForSys->SetColorReservation(testType_3), CameraErrorCode::PARAMETER_ERROR);
    sessionForSys->UnlockForControl();

    input->Close();
    preview->Release();
    input->Release();
    sessionForSys->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession abnormal branches without LockForControl
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureSession abnormal branches without LockForControl
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_039, TestSize.Level1)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(sessionForSys->BeginConfig(), 0);
    EXPECT_EQ(sessionForSys->AddInput(input), 0);
    EXPECT_EQ(sessionForSys->AddOutput(preview), 0);
    EXPECT_EQ(sessionForSys->CommitConfig(), 0);

    FocusRangeType testType_1 = FOCUS_RANGE_TYPE_NEAR;
    EXPECT_EQ(sessionForSys->SetFocusRange(testType_1), 0);
    FocusDrivenType testType_2 = FOCUS_DRIVEN_TYPE_FACE;
    EXPECT_EQ(sessionForSys->SetFocusDriven(testType_2), 0);
    ColorReservationType testType_3 = COLOR_RESERVATION_TYPE_PORTRAIT;
    EXPECT_EQ(sessionForSys->SetColorReservation(testType_3), 0);

    input->Close();
    preview->Release();
    input->Release();
    sessionForSys->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession abnormal branches while camera device is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureSession abnormal branches while camera device is nulltptr
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_040, TestSize.Level1)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(sessionForSys->BeginConfig(), 0);
    EXPECT_EQ(sessionForSys->AddInput(input), 0);
    EXPECT_EQ(sessionForSys->AddOutput(preview), 0);
    EXPECT_EQ(sessionForSys->CommitConfig(), 0);

    sessionForSys->innerInputDevice_ = nullptr;
    std::vector<FocusRangeType> testTypes_1;
    EXPECT_EQ(sessionForSys->GetSupportedFocusRangeTypes(testTypes_1), 0);
    FocusRangeType testType_1 = FOCUS_RANGE_TYPE_NEAR;
    EXPECT_EQ(sessionForSys->GetFocusRange(testType_1), 0);

    std::vector<FocusDrivenType> testTypes_2;
    EXPECT_EQ(sessionForSys->GetSupportedFocusDrivenTypes(testTypes_2), 0);
    FocusDrivenType testType_2 = FOCUS_DRIVEN_TYPE_FACE;
    EXPECT_EQ(sessionForSys->GetFocusDriven(testType_2), 0);

    std::vector<ColorReservationType> testTypes_3;
    EXPECT_EQ(sessionForSys->GetSupportedColorReservationTypes(testTypes_3), 0);
    ColorReservationType testType_3 = COLOR_RESERVATION_TYPE_PORTRAIT;
    EXPECT_EQ(sessionForSys->GetColorReservation(testType_3), 0);

    input->Close();
    preview->Release();
    input->Release();
    sessionForSys->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession founction while metadata have ability
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureSession founction while metadata have ability
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_041, TestSize.Level0)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(sessionForSys->BeginConfig(), 0);
    EXPECT_EQ(sessionForSys->AddInput(input), 0);
    EXPECT_EQ(sessionForSys->AddOutput(preview), 0);
    EXPECT_EQ(sessionForSys->CommitConfig(), 0);

    std::vector<uint8_t> testTypes_1 = {OHOS_CAMERA_FOCUS_RANGE_AUTO, OHOS_CAMERA_FOCUS_RANGE_NEAR};
    ASSERT_NE(sessionForSys->GetMetadata(), nullptr);
    OHOS::Camera::DeleteCameraMetadataItem(sessionForSys->GetMetadata()->get(), OHOS_ABILITY_FOCUS_RANGE_TYPES);
    sessionForSys->GetMetadata()->addEntry(OHOS_ABILITY_FOCUS_RANGE_TYPES, testTypes_1.data(), testTypes_1.size());
    std::vector<FocusRangeType> types_1;
    EXPECT_EQ(sessionForSys->GetSupportedFocusRangeTypes(types_1), 0);

    uint8_t testType_1 = OHOS_CAMERA_FOCUS_RANGE_AUTO;
    OHOS::Camera::DeleteCameraMetadataItem(sessionForSys->GetMetadata()->get(), OHOS_CONTROL_FOCUS_RANGE_TYPE);
    sessionForSys->GetMetadata()->addEntry(OHOS_CONTROL_FOCUS_RANGE_TYPE, &testType_1, 1);
    FocusRangeType type_1 = FOCUS_RANGE_TYPE_NEAR;
    EXPECT_EQ(sessionForSys->GetFocusRange(type_1), 0);

    std::vector<uint8_t> testTypes_2 = {OHOS_CAMERA_FOCUS_DRIVEN_AUTO, OHOS_CAMERA_FOCUS_DRIVEN_FACE};
    OHOS::Camera::DeleteCameraMetadataItem(sessionForSys->GetMetadata()->get(), OHOS_ABILITY_FOCUS_DRIVEN_TYPES);
    sessionForSys->GetMetadata()->addEntry(OHOS_ABILITY_FOCUS_DRIVEN_TYPES, testTypes_2.data(), testTypes_2.size());
    std::vector<FocusDrivenType> types_2;
    EXPECT_EQ(sessionForSys->GetSupportedFocusDrivenTypes(types_2), 0);

    uint8_t testType_2 = OHOS_CAMERA_FOCUS_DRIVEN_AUTO;
    OHOS::Camera::DeleteCameraMetadataItem(sessionForSys->GetMetadata()->get(), OHOS_CONTROL_FOCUS_DRIVEN_TYPE);
    sessionForSys->GetMetadata()->addEntry(OHOS_CONTROL_FOCUS_DRIVEN_TYPE, &testType_2, 1);
    FocusDrivenType type_2 = FOCUS_DRIVEN_TYPE_FACE;
    EXPECT_EQ(sessionForSys->GetFocusDriven(type_2), 0);

    std::vector<uint8_t> testTypes_3 = {OHOS_CAMERA_COLOR_RESERVATION_NONE, OHOS_CAMERA_COLOR_RESERVATION_PORTRAIT};
    OHOS::Camera::DeleteCameraMetadataItem(sessionForSys->GetMetadata()->get(), OHOS_ABILITY_COLOR_RESERVATION_TYPES);
    sessionForSys->GetMetadata()->addEntry(OHOS_ABILITY_COLOR_RESERVATION_TYPES, testTypes_3.data(),
        testTypes_3.size());
    std::vector<ColorReservationType> types_3;
    EXPECT_EQ(sessionForSys->GetSupportedColorReservationTypes(types_3), 0);

    uint8_t testType_3 = OHOS_CAMERA_COLOR_RESERVATION_PORTRAIT;
    OHOS::Camera::DeleteCameraMetadataItem(sessionForSys->GetMetadata()->get(), OHOS_CONTROL_COLOR_RESERVATION_TYPE);
    sessionForSys->GetMetadata()->addEntry(OHOS_CONTROL_COLOR_RESERVATION_TYPE, &testType_3, 1);
    ColorReservationType type_3 = COLOR_RESERVATION_TYPE_PORTRAIT;
    EXPECT_EQ(sessionForSys->GetColorReservation(type_3), 0);

    sessionForSys->LockForControl();
    ASSERT_NE(sessionForSys->changedMetadata_, nullptr);
    OHOS::Camera::DeleteCameraMetadataItem(sessionForSys->changedMetadata_->get(), OHOS_CONTROL_FOCUS_RANGE_TYPE);
    EXPECT_EQ(sessionForSys->SetFocusRange(type_1), 0);
    sessionForSys->changedMetadata_->addEntry(OHOS_CONTROL_FOCUS_RANGE_TYPE, &testType_1, 1);
    EXPECT_EQ(sessionForSys->SetFocusRange(type_1), 0);

    OHOS::Camera::DeleteCameraMetadataItem(sessionForSys->changedMetadata_->get(), OHOS_CONTROL_FOCUS_DRIVEN_TYPE);
    EXPECT_EQ(sessionForSys->SetFocusDriven(type_2), 0);
    sessionForSys->changedMetadata_->addEntry(OHOS_CONTROL_FOCUS_DRIVEN_TYPE, &testType_2, 1);
    EXPECT_EQ(sessionForSys->SetFocusDriven(type_2), 0);

    OHOS::Camera::DeleteCameraMetadataItem(sessionForSys->changedMetadata_->get(), OHOS_CONTROL_COLOR_RESERVATION_TYPE);
    EXPECT_EQ(sessionForSys->SetColorReservation(type_3), 0);
    sessionForSys->changedMetadata_->addEntry(OHOS_CONTROL_COLOR_RESERVATION_TYPE, &testType_3, 1);
    EXPECT_EQ(sessionForSys->SetColorReservation(type_3), 0);
    sessionForSys->UnlockForControl();

    input->Close();
    preview->Release();
    input->Release();
    sessionForSys->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with SetColorSpace HDR and GetActiveColorSpace when Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with SetColorSpace and GetActiveColorSpace when Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_043, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = nullptr;
    for (const auto& preProfile : previewProfile_) {
        if (preProfile.format_ == CAMERA_FORMAT_YCRCB_P010) {
            preview = CreatePreviewOutput(preProfile);
            break;
        }
    }

    if (preview == nullptr) {
        MEDIA_WARNING_LOG("Format YCRCB_P010 is not supported!");
        GTEST_SKIP();
    }
    
    ColorSpace colorSpace = BT2020_HLG;
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->SetColorSpace(colorSpace), 0);
    EXPECT_EQ(session->GetActiveColorSpace(colorSpace), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);

    EXPECT_EQ(session->CommitConfig(), 0);

    session->LockForControl();
    session->UnlockForControl();

    EXPECT_EQ(preview->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
    EXPECT_EQ(session->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with SetColorSpace HDR and GetActiveColorSpace when not Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with SetColorSpace and GetActiveColorSpace when not Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_044, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = nullptr;
    for (const auto& preProfile : previewProfile_) {
        if (preProfile.format_ == CAMERA_FORMAT_YCRCB_P010) {
            preview = CreatePreviewOutput(preProfile);
            break;
        }
    }
    if (preview == nullptr) {
        MEDIA_WARNING_LOG("Format YCRCB_P010 is not supported!");
        GTEST_SKIP();
    }

    ColorSpace colorSpace = BT2020_HLG;
    EXPECT_EQ(session->SetColorSpace(colorSpace), CameraErrorCode::SESSION_NOT_CONFIG);
    EXPECT_EQ(session->GetActiveColorSpace(colorSpace), CameraErrorCode::SESSION_NOT_CONFIG);

    EXPECT_EQ(preview->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
    EXPECT_EQ(session->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test FoldCallback with OnFoldStatusChanged and Constructor
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnFoldStatusChanged and Constructor for just call.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_001, TestSize.Level1)
{
    sptr<CaptureSession> session = nullptr;
    ASSERT_EQ(session, nullptr);
    auto foldCallback = std::make_shared<FoldCallback>(session);
    FoldStatus status = FoldStatus::UNKNOWN_FOLD;
    auto ret = foldCallback->OnFoldStatusChanged(status);
    EXPECT_EQ(ret, CAMERA_OPERATION_NOT_ALLOWED);

    std::shared_ptr<FoldCallback> foldCallback1 = std::make_shared<FoldCallback>(nullptr);
    EXPECT_EQ(foldCallback1->captureSession_, nullptr);
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with CreateMediaLibrary, GetExposureCallback, GetFocusCallback, GetARCallback,
 * IsVideoDeferred, SetMoonCaptureBoostStatusCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateMediaLibrary, GetExposureCallback, GetFocusCallback, GetARCallback, IsVideoDeferred,
 * SetMoonCaptureBoostStatusCallback for just call.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_002, TestSize.Level1)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    session->SetExposureCallback(nullptr);
    EXPECT_EQ(session->GetExposureCallback(), nullptr);

    session->SetFocusCallback(nullptr);
    EXPECT_EQ(session->GetFocusCallback(), nullptr);

    session->SetSmoothZoomCallback(nullptr);
    EXPECT_EQ(session->GetSmoothZoomCallback(), nullptr);

    session->SetARCallback(nullptr);
    EXPECT_EQ(session->GetARCallback(), nullptr);

    session->isVideoDeferred_ = false;
    EXPECT_FALSE(session->IsVideoDeferred());

    session->SetMoonCaptureBoostStatusCallback(nullptr);
    EXPECT_EQ(session->GetMoonCaptureBoostStatusCallback(), nullptr);
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with GetSupportedPortraitThemeTypes, IsPortraitThemeSupported, SetPortraitThemeType,
 * GetSupportedVideoRotations, IsVideoRotationSupported, SetVideoRotation, GetDepthFusionThreshold
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSupportedPortraitThemeTypes, IsPortraitThemeSupported, SetPortraitThemeType,
 * GetSupportedVideoRotations, IsVideoRotationSupported, SetVideoRotation, GetDepthFusionThreshold for just call.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_003, TestSize.Level1)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);
    std::vector<PortraitThemeType> supportedPortraitThemeTypes = {};
    EXPECT_EQ(sessionForSys->GetSupportedPortraitThemeTypes(supportedPortraitThemeTypes),
        CameraErrorCode::SESSION_NOT_CONFIG);
    EXPECT_FALSE(sessionForSys->IsPortraitThemeSupported());
    bool isSupported = false;
    EXPECT_EQ(sessionForSys->IsPortraitThemeSupported(isSupported), CameraErrorCode::SESSION_NOT_CONFIG);

    PortraitThemeType type = PortraitThemeType::NATURAL;
    EXPECT_EQ(sessionForSys->SetPortraitThemeType(type), CameraErrorCode::SESSION_NOT_CONFIG);

    std::vector<int32_t> supportedRotation = {};
    EXPECT_EQ(sessionForSys->GetSupportedVideoRotations(supportedRotation), CameraErrorCode::SESSION_NOT_CONFIG);

    EXPECT_FALSE(sessionForSys->IsVideoRotationSupported());
    isSupported = false;
    EXPECT_EQ(sessionForSys->IsVideoRotationSupported(isSupported), CameraErrorCode::SESSION_NOT_CONFIG);

    int32_t rotation = 0;
    EXPECT_EQ(sessionForSys->SetVideoRotation(rotation), CameraErrorCode::SESSION_NOT_CONFIG);

    std::vector<float> depthFusionThreshold = sessionForSys->GetDepthFusionThreshold();
    EXPECT_EQ(depthFusionThreshold.size(), 0);
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with IsDepthFusionEnabled, IsMovingPhotoEnabled, SetMacroStatusCallback,
 * IsSetEnableMacro, GeneratePreconfigProfiles, SetEffectSuggestionCallback, SetARCallback
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsDepthFusionEnabled, IsMovingPhotoEnabled, SetMacroStatusCallback,
 * IsSetEnableMacro, GeneratePreconfigProfiles, SetEffectSuggestionCallback, SetARCallback for just call.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_004, TestSize.Level1)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);
    sessionForSys->isDepthFusionEnable_ = false;
    EXPECT_FALSE(sessionForSys->IsDepthFusionEnabled());

    sessionForSys->isMovingPhotoEnabled_ = false;
    EXPECT_FALSE(sessionForSys->IsMovingPhotoEnabled());

    sessionForSys->SetMacroStatusCallback(nullptr);
    EXPECT_EQ(sessionForSys->GetMacroStatusCallback(), nullptr);

    sessionForSys->isSetMacroEnable_ = false;
    EXPECT_FALSE(sessionForSys->IsSetEnableMacro());

    sessionForSys->SetEffectSuggestionCallback(nullptr);
    EXPECT_EQ(sessionForSys->effectSuggestionCallback_, nullptr);

    sessionForSys->SetARCallback(nullptr);
    EXPECT_EQ(sessionForSys->GetARCallback(), nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    PreconfigType preconfigType = PRECONFIG_720P;
    ProfileSizeRatio preconfigRatio = UNSPECIFIED;
    EXPECT_EQ(session->GeneratePreconfigProfiles(preconfigType, preconfigRatio), nullptr);
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with EnableTripodDetection, IsAutoDeviceSwitchSupported, SetIsAutoSwitchDeviceStatus,
 * EnableAutoDeviceSwitch, SwitchDevice, FindFrontCamera, StartVideoOutput, StopVideoOutput
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EnableTripodDetection, IsAutoDeviceSwitchSupported, SetIsAutoSwitchDeviceStatus,
 * EnableAutoDeviceSwitch, SwitchDevice, FindFrontCamera, StartVideoOutput, StopVideoOutput for just call.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_005, TestSize.Level1)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);
    bool isEnable = false;
    EXPECT_EQ(sessionForSys->EnableTripodDetection(isEnable), CameraErrorCode::OPERATION_NOT_ALLOWED);

    UsageType usageType = BOKEH;
    bool enabled = false;
    sessionForSys->SetUsage(usageType, enabled);

    bool isFoldable = CameraManager::GetInstance()->GetIsFoldable();
    EXPECT_EQ(sessionForSys->IsAutoDeviceSwitchSupported(), isFoldable);

    bool enable = false;
    sessionForSys->SetIsAutoSwitchDeviceStatus(enable);
    if (!isFoldable) {
        EXPECT_EQ(sessionForSys->EnableAutoDeviceSwitch(enable), CameraErrorCode::OPERATION_NOT_ALLOWED);
    } else {
        EXPECT_EQ(sessionForSys->EnableAutoDeviceSwitch(enable), CameraErrorCode::SUCCESS);
    }

    EXPECT_FALSE(sessionForSys->SwitchDevice());

    auto cameraDeviceList = CameraManager::GetInstance()->GetSupportedCameras();
    bool flag = true;
    for (const auto& cameraDevice : cameraDeviceList) {
        if (cameraDevice->GetPosition() == CAMERA_POSITION_FRONT) {
            EXPECT_NE(sessionForSys->FindFrontCamera(), nullptr);
            flag = false;
        }
    }
    if (flag) {
        EXPECT_EQ(sessionForSys->FindFrontCamera(), nullptr);
    }

    sessionForSys->StartVideoOutput();
    sessionForSys->StopVideoOutput();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with SetAutoDeviceSwitchCallback, GetAutoDeviceSwitchCallback,
 * ExecuteAllFunctionsInMap, CreateAndSetFoldServiceCallback, SetQualityPrioritization
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetAutoDeviceSwitchCallback, GetAutoDeviceSwitchCallback, ExecuteAllFunctionsInMap,
 * CreateAndSetFoldServiceCallback, SetQualityPrioritization for just call.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_006, TestSize.Level1)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);

    sessionForSys->SetAutoDeviceSwitchCallback(nullptr);
    EXPECT_EQ(sessionForSys->GetAutoDeviceSwitchCallback(), nullptr);

    sessionForSys->ExecuteAllFunctionsInMap();
    EXPECT_TRUE(sessionForSys->canAddFuncToMap_);

    sessionForSys->CreateAndSetFoldServiceCallback();
    QualityPrioritization qualityPrioritization = HIGH_QUALITY;
    EXPECT_EQ(sessionForSys->SetQualityPrioritization(qualityPrioritization), CameraErrorCode::SESSION_NOT_CONFIG);

    sessionForSys->isImageDeferred_ = false;
    EXPECT_FALSE(sessionForSys->IsImageDeferred());

    bool isEnable = false;
    EXPECT_EQ(sessionForSys->EnableEffectSuggestion(isEnable), CameraErrorCode::OPERATION_NOT_ALLOWED);

    std::vector<EffectSuggestionStatus> effectSuggestionStatusList = {};
    EXPECT_EQ(sessionForSys->SetEffectSuggestionStatus(effectSuggestionStatusList),
        CameraErrorCode::OPERATION_NOT_ALLOWED);

    EffectSuggestionType effectSuggestionType = EFFECT_SUGGESTION_NONE;
    EXPECT_EQ(sessionForSys->UpdateEffectSuggestion(effectSuggestionType, isEnable),
        CameraErrorCode::SESSION_NOT_CONFIG);
}

/*
 * Feature: Framework
 * Function: Test PreconfigProfiles with ToString.
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ToString for just call.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_007, TestSize.Level1)
{
    ColorSpace colorSpace = COLOR_SPACE_UNKNOWN;
    std::shared_ptr<PreconfigProfiles> profiles = std::make_shared<PreconfigProfiles>(colorSpace);
    ASSERT_NE(profiles, nullptr);
    CameraFormat photoFormat = CAMERA_FORMAT_JPEG;
    CameraFormat videoFormat = CAMERA_FORMAT_YUV_420_SP;
    Size photoSize = {480, 640};
    Size previewSize = {640, 480};
    Size videoSize = {640, 360};
    Profile photoProfile = Profile(photoFormat, photoSize);
    Profile previewProfile = Profile(photoFormat, previewSize);
    std::vector<int32_t> videoFramerates = {30, 30};
    VideoProfile videoProfile = VideoProfile(videoFormat, videoSize, videoFramerates);
    profiles->previewProfile = previewProfile;
    profiles->photoProfile = photoProfile;
    profiles->videoProfile = videoProfile;
    auto ret = profiles->ToString();
    EXPECT_FALSE(ret.empty());
}

/*
 * Feature: Framework
 * Function: Test RefBaseCompare with operator.
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test operator for just call.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_008, TestSize.Level1)
{
    wptr<TestObject> wp;
    RefBaseCompare<TestObject> comparator;
    EXPECT_FALSE(comparator.operator()(wp, wp));
}

/*
 * Feature: Framework
 * Function: Test CaptureSessionCallback and CaptureSessionMetadataResultProcessor with Constructor and Destructors.
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Constructor and Destructors for just call.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_009, TestSize.Level1)
{
    std::shared_ptr<CaptureSessionCallback> captureSessionCallback1 = std::make_shared<CaptureSessionCallback>();
    EXPECT_EQ(captureSessionCallback1->captureSession_, nullptr);
    std::shared_ptr<CaptureSessionCallback> captureSessionCallback2 =
        std::make_shared<CaptureSessionCallback>(nullptr);
    EXPECT_EQ(captureSessionCallback2->captureSession_, nullptr);

    std::shared_ptr<CaptureSession::CaptureSessionMetadataResultProcessor> processor =
        std::make_shared<CaptureSession::CaptureSessionMetadataResultProcessor>(nullptr);
    EXPECT_EQ(processor->session_, nullptr);
}

/*
 * Feature: Framework
 * Function: Test LcdFlashStatusCallback with SetLcdFlashStatusInfo and GetLcdFlashStatusInfo.
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetLcdFlashStatusInfo and GetLcdFlashStatusInfo for just call.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_010, TestSize.Level1)
{
    std::shared_ptr<ConcreteLcdFlashStatusCallback> lcdFlashStatusCallback =
        std::make_shared<ConcreteLcdFlashStatusCallback>();
    LcdFlashStatusInfo lcdFlashStatusInfo = {true, 0};
    lcdFlashStatusCallback->SetLcdFlashStatusInfo(lcdFlashStatusInfo);
    EXPECT_TRUE(lcdFlashStatusCallback->GetLcdFlashStatusInfo().isLcdFlashNeeded);
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with GetMetadataFromService
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with GetMetadataFromService
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_011, TestSize.Level1)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    session->GetMetadataFromService(cameras_[0]);

    input->Close();
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test SetBeauty abnormal branches
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetBeauty abnormal branches
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_012, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(sessionForSys->BeginConfig(), 0);
    EXPECT_EQ(sessionForSys->AddInput(input), 0);
    EXPECT_EQ(sessionForSys->AddOutput(preview), 0);
    EXPECT_EQ(sessionForSys->CommitConfig(), 0);

    BeautyType beautyType = AUTO_TYPE;
    sessionForSys->LockForControl();
    sessionForSys->SetBeauty(beautyType, 0);
    EXPECT_EQ(sessionForSys->GetBeauty(beautyType), -1);
    sessionForSys->SetBeauty(beautyType, 3);
    EXPECT_EQ(sessionForSys->GetBeauty(beautyType), -1);
    sessionForSys->SetBeauty(FACE_SLENDER, 0);
    EXPECT_EQ(sessionForSys->GetBeauty(beautyType), -1);
    sessionForSys->SetBeauty(FACE_SLENDER, 3);
    EXPECT_EQ(sessionForSys->GetBeauty(beautyType), -1);
    uint32_t count = 1;
    uint8_t beauty = OHOS_CAMERA_BEAUTY_TYPE_OFF;
    ASSERT_NE(sessionForSys->changedMetadata_, nullptr);
    OHOS::Camera::DeleteCameraMetadataItem(sessionForSys->changedMetadata_->get(), OHOS_CONTROL_BEAUTY_TYPE);
    sessionForSys->SetBeauty(beautyType, 0);
    EXPECT_EQ(sessionForSys->GetBeauty(beautyType), -1);
    sessionForSys->SetBeauty(FACE_SLENDER, 0);
    EXPECT_EQ(sessionForSys->GetBeauty(beautyType), -1);
    sessionForSys->changedMetadata_->addEntry(OHOS_CONTROL_BEAUTY_TYPE, &beauty, count);
    sessionForSys->SetBeauty(beautyType, 0);
    sessionForSys->SetBeauty(FACE_SLENDER, 0);
    int num = 10;
    beautyType = static_cast<BeautyType>(num);
    sessionForSys->SetBeauty(beautyType, 0);
    EXPECT_EQ(sessionForSys->GetBeauty(beautyType), -1);
    sessionForSys->UnlockForControl();

    EXPECT_EQ(preview->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
    EXPECT_EQ(sessionForSys->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test IsFeatureSupported abnormal branches
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsFeatureSupported abnormal branches
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_013, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    SceneFeature feature = static_cast<SceneFeature>(10);
    EXPECT_FALSE(session->IsFeatureSupported(feature));

    EXPECT_EQ(preview->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
    EXPECT_EQ(session->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test EnableDeferredType abnormal branches
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EnableDeferredType abnormal branches
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_014, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    session->LockForControl();
    ASSERT_NE(session->changedMetadata_, nullptr);
    DeferredDeliveryImageType type = DELIVERY_NONE;
    bool isEnableByUser = true;
    OHOS::Camera::DeleteCameraMetadataItem(session->changedMetadata_->get(), OHOS_CONTROL_DEFERRED_IMAGE_DELIVERY);
    session->EnableDeferredType(type, isEnableByUser);
    uint8_t deferredType = HDI::Camera::V1_2::NONE;
    session->changedMetadata_->addEntry(OHOS_CONTROL_DEFERRED_IMAGE_DELIVERY, &deferredType, 1);
    session->EnableDeferredType(type, isEnableByUser);

    ASSERT_NE(session->changedMetadata_, nullptr);
    OHOS::Camera::DeleteCameraMetadataItem(session->changedMetadata_->get(), OHOS_CONTROL_AUTO_DEFERRED_VIDEO_ENHANCE);
    session->EnableAutoDeferredVideoEnhancement(isEnableByUser);
    session->changedMetadata_->addEntry(OHOS_CONTROL_AUTO_DEFERRED_VIDEO_ENHANCE, &isEnableByUser, 1);
    session->EnableAutoDeferredVideoEnhancement(isEnableByUser);

    ASSERT_NE(session->changedMetadata_, nullptr);
    OHOS::Camera::DeleteCameraMetadataItem(session->changedMetadata_->get(), OHOS_CAMERA_USER_ID);
    session->SetUserId();
    int32_t userId = 1;
    session->changedMetadata_->addEntry(OHOS_CAMERA_USER_ID, &userId, 1);
    session->SetUserId();
    session->UnlockForControl();

    EXPECT_EQ(preview->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
    EXPECT_EQ(session->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test EnableDeferredType abnormal branches
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EnableDeferredType abnormal branches
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_015, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    bool enabled = true;
    session->LockForControl();
    ASSERT_NE(session->changedMetadata_, nullptr);
    OHOS::Camera::DeleteCameraMetadataItem(session->changedMetadata_->get(), session->HAL_CUSTOM_AR_MODE);
    EXPECT_EQ(session->SetARMode(enabled), 0);
    uint8_t value = 1;
    session->changedMetadata_->addEntry(session->HAL_CUSTOM_AR_MODE, &value, 1);
    EXPECT_EQ(session->SetARMode(enabled), 0);
    session->UnlockForControl();

    EXPECT_EQ(preview->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
    EXPECT_EQ(session->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test SetSensorSensitivity abnormal branches
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetSensorSensitivity abnormal branches
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_016, TestSize.Level1)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(sessionForSys->BeginConfig(), 0);
    EXPECT_EQ(sessionForSys->AddInput(input), 0);
    EXPECT_EQ(sessionForSys->AddOutput(preview), 0);
    EXPECT_EQ(sessionForSys->CommitConfig(), 0);

    sessionForSys->LockForControl();
    ASSERT_NE(sessionForSys->changedMetadata_, nullptr);
    uint32_t sensitivity = 1;
    OHOS::Camera::DeleteCameraMetadataItem(sessionForSys->changedMetadata_->get(),
        sessionForSys->HAL_CUSTOM_SENSOR_SENSITIVITY);
    EXPECT_EQ(sessionForSys->SetSensorSensitivity(sensitivity), 0);
    sessionForSys->changedMetadata_->addEntry(sessionForSys->HAL_CUSTOM_SENSOR_SENSITIVITY, &sensitivity, 1);
    EXPECT_EQ(sessionForSys->SetSensorSensitivity(sensitivity), 0);

    ASSERT_NE(sessionForSys->changedMetadata_, nullptr);
    EffectSuggestionType effectSuggestionType = EFFECT_SUGGESTION_PORTRAIT;
    bool isEnable = true;
    OHOS::Camera::DeleteCameraMetadataItem(sessionForSys->changedMetadata_->get(), OHOS_CONTROL_EFFECT_SUGGESTION_TYPE);
    EXPECT_EQ(sessionForSys->UpdateEffectSuggestion(effectSuggestionType, isEnable), 0);
    uint8_t type = OHOS_CAMERA_EFFECT_SUGGESTION_PORTRAIT;
    std::vector<uint8_t> vec = {type, isEnable};
    sessionForSys->changedMetadata_->addEntry(OHOS_CONTROL_EFFECT_SUGGESTION_TYPE, vec.data(), vec.size());
    EXPECT_EQ(sessionForSys->UpdateEffectSuggestion(effectSuggestionType, isEnable), 0);
    sessionForSys->UnlockForControl();

    EXPECT_EQ(preview->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
    EXPECT_EQ(sessionForSys->Release(), 0);
}


/**
 * @tc.name: capture_session_function_unittest_017
 * @tc.desc: Test GetSupportedEffectSuggestionType in capture mode
 * @tc.type: FUNC
 * @tc.require: AR20250222876922
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_017, TestSize.Level1)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);
    ASSERT_EQ(SceneMode::CAPTURE, sessionForSys->GetMode());

    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(nullptr, input);
    ASSERT_EQ(CAMERA_OK, input->Open());

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(nullptr, photoOutput);

    ASSERT_EQ(CAMERA_OK, sessionForSys->BeginConfig());
    ASSERT_EQ(CAMERA_OK, sessionForSys->AddInput(input));
    ASSERT_EQ(CAMERA_OK, sessionForSys->AddOutput(photoOutput));
    ASSERT_EQ(CAMERA_OK, sessionForSys->CommitConfig());

    std::vector<uint32_t> vec;
    std::vector<EffectSuggestionType> expectedVec;

    Camera::DeleteCameraMetadataItem(sessionForSys->GetMetadata()->get(), OHOS_ABILITY_EFFECT_SUGGESTION_SUPPORTED);
    EXPECT_EQ(expectedVec, sessionForSys->GetSupportedEffectSuggestionType());

    sessionForSys->LockForControl();
    ASSERT_NE(nullptr, sessionForSys->changedMetadata_);
    vec = {1, 6, 0, 1, 2, 3, 4, 5, -1};
    sessionForSys->changedMetadata_->addEntry(OHOS_ABILITY_EFFECT_SUGGESTION_SUPPORTED, vec.data(), 9);
    sessionForSys->UnlockForControl();
    expectedVec =
    {EffectSuggestionType::EFFECT_SUGGESTION_NONE, EffectSuggestionType::EFFECT_SUGGESTION_PORTRAIT,
     EffectSuggestionType::EFFECT_SUGGESTION_FOOD, EffectSuggestionType::EFFECT_SUGGESTION_SKY,
     EffectSuggestionType::EFFECT_SUGGESTION_SUNRISE_SUNSET, EffectSuggestionType::EFFECT_SUGGESTION_STAGE};
    EXPECT_EQ(expectedVec, sessionForSys->GetSupportedEffectSuggestionType());

    EXPECT_EQ(CAMERA_OK, photoOutput->Release());
    EXPECT_EQ(CAMERA_OK, input->Close());
    EXPECT_EQ(CAMERA_OK, sessionForSys->Release());
}

/**
 * @tc.name: capture_session_function_unittest_018
 * @tc.desc: Test GetSupportedEffectSuggestionType with stage ability enabled in video mode
 * @tc.type: FUNC
 * @tc.require: AR20250222876922
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_018, TestSize.Level1)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::VIDEO);
    ASSERT_NE(sessionForSys, nullptr);
    ASSERT_EQ(SceneMode::VIDEO, sessionForSys->GetMode());

    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(nullptr, input);
    ASSERT_EQ(CAMERA_OK, input->Open());

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfile_[0]);
    ASSERT_NE(nullptr, videoOutput);

    ASSERT_EQ(CAMERA_OK, sessionForSys->BeginConfig());
    ASSERT_EQ(CAMERA_OK, sessionForSys->AddInput(input));
    ASSERT_EQ(CAMERA_OK, sessionForSys->AddOutput(videoOutput));
    ASSERT_EQ(CAMERA_OK, sessionForSys->CommitConfig());

    std::vector<uint32_t> vec;
    std::vector<EffectSuggestionType> expectedVec;

    Camera::DeleteCameraMetadataItem(sessionForSys->GetMetadata()->get(), OHOS_ABILITY_EFFECT_SUGGESTION_SUPPORTED);
    EXPECT_EQ(expectedVec, sessionForSys->GetSupportedEffectSuggestionType());

    sessionForSys->LockForControl();
    ASSERT_NE(nullptr, sessionForSys->changedMetadata_);
    vec = {2, 1, 5, -1};
    sessionForSys->changedMetadata_->addEntry(OHOS_ABILITY_EFFECT_SUGGESTION_SUPPORTED, vec.data(), 4);
    sessionForSys->UnlockForControl();

    expectedVec =
    {EffectSuggestionType::EFFECT_SUGGESTION_STAGE};

    EXPECT_EQ(expectedVec, sessionForSys->GetSupportedEffectSuggestionType());

    EXPECT_EQ(CAMERA_OK, videoOutput->Release());
    EXPECT_EQ(CAMERA_OK, input->Close());
    EXPECT_EQ(CAMERA_OK, sessionForSys->Release());
}

/**
 * @tc.name: capture_session_function_unittest_019
 * @tc.desc: Test IsEffectSuggestionSupported with stage ability enabled in capture mode
 * @tc.type: FUNC
 * @tc.require: AR20250222876922
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_019, TestSize.Level1)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);
    ASSERT_EQ(SceneMode::CAPTURE, sessionForSys->GetMode());

    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(nullptr, input);
    ASSERT_EQ(CAMERA_OK, input->Open());

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(nullptr, photoOutput);

    ASSERT_EQ(CAMERA_OK, sessionForSys->BeginConfig());
    ASSERT_EQ(CAMERA_OK, sessionForSys->AddInput(input));
    ASSERT_EQ(CAMERA_OK, sessionForSys->AddOutput(photoOutput));
    ASSERT_EQ(CAMERA_OK, sessionForSys->CommitConfig());

    std::vector<uint32_t> vec;

    Camera::DeleteCameraMetadataItem(sessionForSys->GetMetadata()->get(), OHOS_ABILITY_EFFECT_SUGGESTION_SUPPORTED);
    EXPECT_EQ(false, sessionForSys->IsEffectSuggestionSupported());

    sessionForSys->LockForControl();
    ASSERT_NE(nullptr, sessionForSys->changedMetadata_);
    vec = {1, 6, 0, 1, 2, 3, 4, 5, -1};
    sessionForSys->changedMetadata_->addEntry(OHOS_ABILITY_EFFECT_SUGGESTION_SUPPORTED, vec.data(), 9);
    sessionForSys->UnlockForControl();
    EXPECT_EQ(true, sessionForSys->IsEffectSuggestionSupported());

    EXPECT_EQ(CAMERA_OK, photoOutput->Release());
    EXPECT_EQ(CAMERA_OK, input->Close());
    EXPECT_EQ(CAMERA_OK, sessionForSys->Release());
}

/**
 * @tc.name: capture_session_function_unittest_020
 * @tc.desc: Test IsEffectSuggestionSupported with stage ability enabled in video mode
 * @tc.type: FUNC
 * @tc.require: AR20250222876922
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_020, TestSize.Level1)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::VIDEO);
    ASSERT_NE(sessionForSys, nullptr);
    ASSERT_EQ(SceneMode::VIDEO, sessionForSys->GetMode());

    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(nullptr, input);
    ASSERT_EQ(CAMERA_OK, input->Open());

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfile_[0]);
    ASSERT_NE(nullptr, videoOutput);

    ASSERT_EQ(CAMERA_OK, sessionForSys->BeginConfig());
    ASSERT_EQ(CAMERA_OK, sessionForSys->AddInput(input));
    ASSERT_EQ(CAMERA_OK, sessionForSys->AddOutput(videoOutput));
    ASSERT_EQ(CAMERA_OK, sessionForSys->CommitConfig());

    std::vector<uint32_t> vec;

    Camera::DeleteCameraMetadataItem(sessionForSys->GetMetadata()->get(), OHOS_ABILITY_EFFECT_SUGGESTION_SUPPORTED);
    EXPECT_EQ(false, sessionForSys->IsEffectSuggestionSupported());

    sessionForSys->LockForControl();
    ASSERT_NE(nullptr, sessionForSys->changedMetadata_);
    vec = {2, 1, 5, -1};
    sessionForSys->changedMetadata_->addEntry(OHOS_ABILITY_EFFECT_SUGGESTION_SUPPORTED, vec.data(), 4);
    sessionForSys->UnlockForControl();
    EXPECT_EQ(true, sessionForSys->IsEffectSuggestionSupported());

    EXPECT_EQ(CAMERA_OK, videoOutput->Release());
    EXPECT_EQ(CAMERA_OK, input->Close());
    EXPECT_EQ(CAMERA_OK, sessionForSys->Release());
}

/**
 * @tc.name: capture_session_function_unittest_021
 * @tc.desc: Test EnableEffectSuggestion with stage ability enabled in capture mode
 * @tc.type: FUNC
 * @tc.require: AR20250222876922
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_021, TestSize.Level1)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);
    ASSERT_EQ(SceneMode::CAPTURE, sessionForSys->GetMode());

    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(nullptr, input);
    ASSERT_EQ(CAMERA_OK, input->Open());

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(nullptr, photoOutput);

    ASSERT_EQ(CAMERA_OK, sessionForSys->BeginConfig());
    ASSERT_EQ(CAMERA_OK, sessionForSys->AddInput(input));
    ASSERT_EQ(CAMERA_OK, sessionForSys->AddOutput(photoOutput));
    ASSERT_EQ(CAMERA_OK, sessionForSys->CommitConfig());

    std::vector<uint32_t> vec;
    camera_metadata_item_t metaData;

    Camera::DeleteCameraMetadataItem(sessionForSys->GetMetadata()->get(), OHOS_ABILITY_EFFECT_SUGGESTION_SUPPORTED);
    EXPECT_EQ(OPERATION_NOT_ALLOWED, sessionForSys->EnableEffectSuggestion(true));
    EXPECT_EQ(OPERATION_NOT_ALLOWED, sessionForSys->EnableEffectSuggestion(false));

    sessionForSys->LockForControl();
    ASSERT_NE(nullptr, sessionForSys->changedMetadata_);
    vec = {1, 6, 0, 1, 2, 3, 4, 5, -1};
    sessionForSys->changedMetadata_->addEntry(OHOS_ABILITY_EFFECT_SUGGESTION_SUPPORTED, vec.data(), 9);
    sessionForSys->UnlockForControl();

    sessionForSys->LockForControl();
    EXPECT_EQ(CAMERA_OK, sessionForSys->EnableEffectSuggestion(true));
    sessionForSys->UnlockForControl();
    Camera::FindCameraMetadataItem(sessionForSys->GetMetadata()->get(), OHOS_CONTROL_EFFECT_SUGGESTION, &metaData);
    ASSERT_EQ(1, metaData.count);
    EXPECT_EQ(true, metaData.data.u8[0]);

    sessionForSys->LockForControl();
    EXPECT_EQ(CAMERA_OK, sessionForSys->EnableEffectSuggestion(false));
    sessionForSys->UnlockForControl();
    Camera::FindCameraMetadataItem(sessionForSys->GetMetadata()->get(), OHOS_CONTROL_EFFECT_SUGGESTION, &metaData);
    ASSERT_EQ(1, metaData.count);
    EXPECT_EQ(false, metaData.data.u8[0]);

    EXPECT_EQ(CAMERA_OK, photoOutput->Release());
    EXPECT_EQ(CAMERA_OK, input->Close());
    EXPECT_EQ(CAMERA_OK, sessionForSys->Release());
}

/**
 * @tc.name: capture_session_function_unittest_022
 * @tc.desc: Test IsEffectSuggestionSupported with stage ability enabled in video mode
 * @tc.type: FUNC
 * @tc.require: AR20250222876922
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_022, TestSize.Level1)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::VIDEO);
    ASSERT_NE(sessionForSys, nullptr);
    ASSERT_EQ(SceneMode::VIDEO, sessionForSys->GetMode());

    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(nullptr, input);
    ASSERT_EQ(CAMERA_OK, input->Open());

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfile_[0]);
    ASSERT_NE(nullptr, videoOutput);

    ASSERT_EQ(CAMERA_OK, sessionForSys->BeginConfig());
    ASSERT_EQ(CAMERA_OK, sessionForSys->AddInput(input));
    ASSERT_EQ(CAMERA_OK, sessionForSys->AddOutput(videoOutput));
    ASSERT_EQ(CAMERA_OK, sessionForSys->CommitConfig());

    std::vector<uint32_t> vec;
    camera_metadata_item_t metaData;

    Camera::DeleteCameraMetadataItem(sessionForSys->GetMetadata()->get(), OHOS_ABILITY_EFFECT_SUGGESTION_SUPPORTED);
    EXPECT_EQ(OPERATION_NOT_ALLOWED, sessionForSys->EnableEffectSuggestion(true));
    EXPECT_EQ(OPERATION_NOT_ALLOWED, sessionForSys->EnableEffectSuggestion(false));

    sessionForSys->LockForControl();
    ASSERT_NE(nullptr, sessionForSys->changedMetadata_);
    vec = {2, 1, 5, -1};
    sessionForSys->changedMetadata_->addEntry(OHOS_ABILITY_EFFECT_SUGGESTION_SUPPORTED, vec.data(), 4);
    sessionForSys->UnlockForControl();

    sessionForSys->LockForControl();
    EXPECT_EQ(CAMERA_OK, sessionForSys->EnableEffectSuggestion(true));
    sessionForSys->UnlockForControl();
    Camera::FindCameraMetadataItem(sessionForSys->GetMetadata()->get(), OHOS_CONTROL_EFFECT_SUGGESTION, &metaData);
    ASSERT_EQ(1, metaData.count);
    EXPECT_EQ(true, metaData.data.u8[0]);

    sessionForSys->LockForControl();
    EXPECT_EQ(CAMERA_OK, sessionForSys->EnableEffectSuggestion(false));
    sessionForSys->UnlockForControl();
    Camera::FindCameraMetadataItem(sessionForSys->GetMetadata()->get(), OHOS_CONTROL_EFFECT_SUGGESTION, &metaData);
    ASSERT_EQ(1, metaData.count);
    EXPECT_EQ(false, metaData.data.u8[0]);

    EXPECT_EQ(CAMERA_OK, videoOutput->Release());
    EXPECT_EQ(CAMERA_OK, input->Close());
    EXPECT_EQ(CAMERA_OK, sessionForSys->Release());
}

/**
 * @tc.name: capture_session_function_unittest_023
 * @tc.desc: Test SetEffectSuggestionStatus with stage ability enabled in capture mode
 * @tc.type: FUNC
 * @tc.require: AR20250222876922
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_023, TestSize.Level1)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);
    ASSERT_EQ(SceneMode::CAPTURE, sessionForSys->GetMode());

    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(nullptr, input);
    ASSERT_EQ(CAMERA_OK, input->Open());

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(nullptr, photoOutput);

    ASSERT_EQ(CAMERA_OK, sessionForSys->BeginConfig());
    ASSERT_EQ(CAMERA_OK, sessionForSys->AddInput(input));
    ASSERT_EQ(CAMERA_OK, sessionForSys->AddOutput(photoOutput));
    ASSERT_EQ(CAMERA_OK, sessionForSys->CommitConfig());

    std::vector<uint32_t> vec;
    camera_metadata_item_t metaData;
    std::vector<EffectSuggestionStatus> effectSuggestionStatusList = {
        {EffectSuggestionType::EFFECT_SUGGESTION_STAGE, true},
        {EffectSuggestionType::EFFECT_SUGGESTION_PORTRAIT, false}};
    std::vector<uint8_t> expectedVec = {5, 1, 1, 0};

    Camera::DeleteCameraMetadataItem(sessionForSys->GetMetadata()->get(), OHOS_ABILITY_EFFECT_SUGGESTION_SUPPORTED);
    EXPECT_EQ(OPERATION_NOT_ALLOWED, sessionForSys->SetEffectSuggestionStatus(effectSuggestionStatusList));

    sessionForSys->LockForControl();
    ASSERT_NE(nullptr, sessionForSys->changedMetadata_);
    vec = {1, 6, 0, 1, 2, 3, 4, 5, -1};
    sessionForSys->changedMetadata_->addEntry(OHOS_ABILITY_EFFECT_SUGGESTION_SUPPORTED, vec.data(), 9);
    sessionForSys->UnlockForControl();

    sessionForSys->LockForControl();
    EXPECT_EQ(CAMERA_OK, sessionForSys->SetEffectSuggestionStatus(effectSuggestionStatusList));
    sessionForSys->UnlockForControl();
    Camera::FindCameraMetadataItem(sessionForSys->GetMetadata()->get(),
        OHOS_CONTROL_EFFECT_SUGGESTION_DETECTION, &metaData);
    ASSERT_EQ(expectedVec.size(), metaData.count);
    for (size_t i = 0; i < expectedVec.size(); i++) {
        EXPECT_EQ(expectedVec[i], metaData.data.u8[i]);
    }

    EXPECT_EQ(CAMERA_OK, photoOutput->Release());
    EXPECT_EQ(CAMERA_OK, input->Close());
    EXPECT_EQ(CAMERA_OK, sessionForSys->Release());
}

/**
 * @tc.name: capture_session_function_unittest_024
 * @tc.desc: Test SetEffectSuggestionStatus with stage ability enabled in video mode
 * @tc.type: FUNC
 * @tc.require: AR20250222876922
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_024, TestSize.Level1)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::VIDEO);
    ASSERT_NE(sessionForSys, nullptr);
    ASSERT_EQ(SceneMode::VIDEO, sessionForSys->GetMode());

    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(nullptr, input);
    ASSERT_EQ(CAMERA_OK, input->Open());

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfile_[0]);
    ASSERT_NE(nullptr, videoOutput);

    ASSERT_EQ(CAMERA_OK, sessionForSys->BeginConfig());
    ASSERT_EQ(CAMERA_OK, sessionForSys->AddInput(input));
    ASSERT_EQ(CAMERA_OK, sessionForSys->AddOutput(videoOutput));
    ASSERT_EQ(CAMERA_OK, sessionForSys->CommitConfig());

    std::vector<uint32_t> vec;
    camera_metadata_item_t metaData;
    std::vector<EffectSuggestionStatus> effectSuggestionStatusList = {
        {EffectSuggestionType::EFFECT_SUGGESTION_STAGE, true}};
    std::vector<uint8_t> expectedVec = {5, 1};

    Camera::DeleteCameraMetadataItem(sessionForSys->GetMetadata()->get(), OHOS_ABILITY_EFFECT_SUGGESTION_SUPPORTED);
    EXPECT_EQ(OPERATION_NOT_ALLOWED, sessionForSys->SetEffectSuggestionStatus(effectSuggestionStatusList));

    sessionForSys->LockForControl();
    ASSERT_NE(nullptr, sessionForSys->changedMetadata_);
    vec = {2, 1, 5, -1};
    sessionForSys->changedMetadata_->addEntry(OHOS_ABILITY_EFFECT_SUGGESTION_SUPPORTED, vec.data(), 4);
    sessionForSys->UnlockForControl();

    sessionForSys->LockForControl();
    EXPECT_EQ(CAMERA_OK, sessionForSys->SetEffectSuggestionStatus(effectSuggestionStatusList));
    sessionForSys->UnlockForControl();
    Camera::FindCameraMetadataItem(sessionForSys->GetMetadata()->get(),
        OHOS_CONTROL_EFFECT_SUGGESTION_DETECTION, &metaData);
    ASSERT_EQ(expectedVec.size(), metaData.count);
    for (size_t i = 0; i < expectedVec.size(); i++) {
        EXPECT_EQ(expectedVec[i], metaData.data.u8[i]);
    }

    EXPECT_EQ(CAMERA_OK, videoOutput->Release());
    EXPECT_EQ(CAMERA_OK, input->Close());
    EXPECT_EQ(CAMERA_OK, sessionForSys->Release());
}

/**
 * @tc.name: capture_session_function_unittest_025
 * @tc.desc: Test UpdateEffectSuggestion with stage ability enabled in capture mode
 * @tc.type: FUNC
 * @tc.require: AR20250222876922
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_025, TestSize.Level1)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);
    ASSERT_EQ(SceneMode::CAPTURE, sessionForSys->GetMode());

    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(nullptr, input);
    ASSERT_EQ(CAMERA_OK, input->Open());

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(nullptr, photoOutput);

    ASSERT_EQ(CAMERA_OK, sessionForSys->BeginConfig());
    ASSERT_EQ(CAMERA_OK, sessionForSys->AddInput(input));
    ASSERT_EQ(CAMERA_OK, sessionForSys->AddOutput(photoOutput));
    ASSERT_EQ(CAMERA_OK, sessionForSys->CommitConfig());

    std::vector<uint32_t> vec;
    camera_metadata_item_t metaData;
    std::vector<uint8_t> expectedVec = {5, 1};

    sessionForSys->LockForControl();
    ASSERT_NE(nullptr, sessionForSys->changedMetadata_);
    vec = {1, 6, 0, 1, 2, 3, 4, 5, -1};
    sessionForSys->changedMetadata_->addEntry(OHOS_ABILITY_EFFECT_SUGGESTION_SUPPORTED, vec.data(), 9);
    sessionForSys->UnlockForControl();

    sessionForSys->LockForControl();
    EXPECT_EQ(CAMERA_OK, sessionForSys->UpdateEffectSuggestion(EffectSuggestionType::EFFECT_SUGGESTION_STAGE, true));
    sessionForSys->UnlockForControl();
    Camera::FindCameraMetadataItem(sessionForSys->GetMetadata()->get(), OHOS_CONTROL_EFFECT_SUGGESTION_TYPE, &metaData);
    ASSERT_EQ(expectedVec.size(), metaData.count);
    for (size_t i = 0; i < expectedVec.size(); i++) {
        EXPECT_EQ(expectedVec[i], metaData.data.u8[i]);
    }

    EXPECT_EQ(CAMERA_OK, photoOutput->Release());
    EXPECT_EQ(CAMERA_OK, input->Close());
    EXPECT_EQ(CAMERA_OK, sessionForSys->Release());
}

/**
 * @tc.name: capture_session_function_unittest_026
 * @tc.desc: Test SetEffectSuggestionStatus with stage ability enabled in video mode
 * @tc.type: FUNC
 * @tc.require: AR20250222876922
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_026, TestSize.Level1)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::VIDEO);
    ASSERT_NE(sessionForSys, nullptr);
    ASSERT_EQ(SceneMode::VIDEO, sessionForSys->GetMode());

    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(nullptr, input);
    ASSERT_EQ(CAMERA_OK, input->Open());

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfile_[0]);
    ASSERT_NE(nullptr, videoOutput);

    ASSERT_EQ(CAMERA_OK, sessionForSys->BeginConfig());
    ASSERT_EQ(CAMERA_OK, sessionForSys->AddInput(input));
    ASSERT_EQ(CAMERA_OK, sessionForSys->AddOutput(videoOutput));
    ASSERT_EQ(CAMERA_OK, sessionForSys->CommitConfig());

    std::vector<uint32_t> vec;
    camera_metadata_item_t metaData;
    std::vector<uint8_t> expectedVec = {5, 1};

    sessionForSys->LockForControl();
    ASSERT_NE(nullptr, sessionForSys->changedMetadata_);
    vec = {2, 1, 5, -1};
    sessionForSys->changedMetadata_->addEntry(OHOS_ABILITY_EFFECT_SUGGESTION_SUPPORTED, vec.data(), 4);
    sessionForSys->UnlockForControl();

    sessionForSys->LockForControl();
    EXPECT_EQ(CAMERA_OK, sessionForSys->UpdateEffectSuggestion(EffectSuggestionType::EFFECT_SUGGESTION_STAGE, true));
    sessionForSys->UnlockForControl();
    Camera::FindCameraMetadataItem(sessionForSys->GetMetadata()->get(), OHOS_CONTROL_EFFECT_SUGGESTION_TYPE, &metaData);
    ASSERT_EQ(expectedVec.size(), metaData.count);
    for (size_t i = 0; i < expectedVec.size(); i++) {
        EXPECT_EQ(expectedVec[i], metaData.data.u8[i]);
    }

    EXPECT_EQ(CAMERA_OK, videoOutput->Release());
    EXPECT_EQ(CAMERA_OK, input->Close());
    EXPECT_EQ(CAMERA_OK, sessionForSys->Release());
}

/**
 * @tc.name: capture_session_function_unittest_027
 * @tc.desc: Test APERTURE_VIDEO mode
 * @tc.type: FUNC
 * @tc.require: AR20250222876922
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_027, TestSize.Level0)
{
    std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(cameras_[0]);
    auto item = std::find(modes.begin(), modes.end(), SceneMode::APERTURE_VIDEO);
    if (item != modes.end()) {
        sptr<CaptureSessionForSys> sessionForSys =
            cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::APERTURE_VIDEO);
        ASSERT_NE(nullptr, sessionForSys);
        ASSERT_EQ(SceneMode::APERTURE_VIDEO, sessionForSys->GetMode());

        auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
        ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
        sptr<CaptureInput> input = cameraInput;
        ASSERT_NE(nullptr, input);
        ASSERT_EQ(CAMERA_OK, input->Open());

        auto outputCapability = cameraManager_->GetSupportedOutputCapability(cameras_[0], 20);
        ASSERT_NE(outputCapability, nullptr);
        videoProfile_ = outputCapability->GetVideoProfiles();

        UpdateCameraOutputCapability();
        sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfile_[0]);
        ASSERT_NE(nullptr, videoOutput);

        ASSERT_EQ(CAMERA_OK, sessionForSys->BeginConfig());
        ASSERT_EQ(CAMERA_OK, sessionForSys->AddInput(input));
        ASSERT_EQ(CAMERA_OK, sessionForSys->AddOutput(videoOutput));
        ASSERT_EQ(CAMERA_OK, sessionForSys->CommitConfig());

        EXPECT_EQ(CAMERA_OK, videoOutput->Release());
        EXPECT_EQ(CAMERA_OK, input->Close());
        EXPECT_EQ(CAMERA_OK, sessionForSys->Release());
    }
}

/*
 * Feature: Framework
 * Function: Test PressureStatusCallback with Constructor and Destructors.
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Constructor and Destructors for just call.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_028, TestSize.Level0)
{
    std::shared_ptr<PressureStatusCallback> pressureStatusCallback = std::make_shared<PressureStatusCallback>();
    EXPECT_EQ(pressureStatusCallback->captureSession_, nullptr);
    pressureStatusCallback->OnPressureStatusChanged(PressureStatus::SYSTEM_PRESSURE_NORMAL);
    std::shared_ptr<PressureStatusCallback> pressureStatusCallback2 =
        std::make_shared<PressureStatusCallback>(nullptr);
    EXPECT_EQ(pressureStatusCallback2->captureSession_, nullptr);
}

/*
 * Feature: Framework
 * Function: Test CameraServerDied
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test if innerCaptureSession_ == nullptr and appCallback_ == nullptr
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_027, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdateCameraOutputCapability();
    auto appCallback = nullptr;

    EXPECT_EQ(session->BeginConfig(), 0);
    session->CameraServerDied(0);
    session->appCallback_ = appCallback;
    session->CameraServerDied(0);
    session->innerCaptureSession_ = nullptr;
    session->CameraServerDied(0);
    session->appCallback_ = nullptr;

    EXPECT_EQ(input->Release(), 0);
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CommitConfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CommitConfig with photoOutput_  = nullptr;
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_028, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);

    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);
    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    EXPECT_EQ(session->AddOutput(preview), 0);

    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    session->RemoveOutput(photo);
    photo->Release();

    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    SessionControlParams(session);


    session->RemoveInput(input);
    input->Release();
    preview->Release();
    EXPECT_EQ(session->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test captureSession with GetSessionFunctions
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSessionFunctions
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_042, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[1]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);

    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    std::vector<Profile> previewProfiles = {};
    std::vector<Profile> photoProfiles = {};
    std::vector<VideoProfile> videoProfiles = {};

    Size size = { 123465, 999999 };
    Profile profile(CameraFormat::CAMERA_FORMAT_RGBA_8888, size);
    previewProfiles.push_back(profile);
    photoProfiles.push_back(profile);


    bool isForApp = true;

    auto innerInputDevice = session->GetSessionFunctions(previewProfiles, photoProfiles, videoProfiles, isForApp);
    EXPECT_EQ(innerInputDevice.size(), 0);
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CanAddInput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CanAddInput with GetCaptureSession() == nullptr
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_029, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();

    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);

    auto oldSession = session->GetCaptureSession();

    sptr<ICaptureSession> sessionNullptr = nullptr;
    session->SetCaptureSession(sessionNullptr);
    EXPECT_EQ(session->CanAddInput(input), false);

    oldSession->CommitConfig();
    EXPECT_EQ(input->Release(), 0);
    oldSession->Release();
}

/*
 * Feature: Framework
 * Function: Test UpdateDeviceDeferredability
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateDeviceDeferredability
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_030, TestSize.Level0)
{
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(10, 100);
    uint8_t* type = new uint8_t[8];
    type[0] = static_cast<uint8_t>(0);
    type[1] = static_cast<uint8_t>(0);
    type[2] = static_cast<uint8_t>(0);
    type[3] = static_cast<uint8_t>(0);
    type[4] = static_cast<uint8_t>(0);
    type[5] = static_cast<uint8_t>(0);
    type[6] = static_cast<uint8_t>(0);
    type[7] = static_cast<uint8_t>(0);
    cameraAbility->addEntry(OHOS_ABILITY_DEFERRED_IMAGE_DELIVERY, &type, 8);
    std::string cameraID = "device/0";
    sptr<CameraDevice> cameraObjnow = new (std::nothrow) CameraDevice(cameraID, cameraAbility);

    auto cameraInput = cameraManager_->CreateCameraInput(cameraObjnow);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    UpdateCameraOutputCapability();

    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    MEDIA_INFO_LOG("CaptureSessionUnitTest::camera_framework_unittest_030");

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);

    session->UpdateDeviceDeferredability();
    session->RemoveInput(input);
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CheckFrameRateRangeWithCurrentFps
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CheckFrameRateRangeWithCurrentFps
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_032, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);

    input->Open();
    UpdateCameraOutputCapability();

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->CheckFrameRateRangeWithCurrentFps(1, 1, 1, 1), true);
    EXPECT_EQ(session->CheckFrameRateRangeWithCurrentFps(1, 2, 1, 2), true);
    EXPECT_EQ(session->CheckFrameRateRangeWithCurrentFps(1, 2, 3, 2), false);
    EXPECT_EQ(session->CheckFrameRateRangeWithCurrentFps(1, 2, 1, 3), false);
    EXPECT_EQ(session->CheckFrameRateRangeWithCurrentFps(1, 2, 3, 4), false);
    EXPECT_EQ(session->CheckFrameRateRangeWithCurrentFps(1, 1, 1, 2), false);
    EXPECT_EQ(session->CheckFrameRateRangeWithCurrentFps(1, 1, 2, 1), false);
    EXPECT_EQ(session->CheckFrameRateRangeWithCurrentFps(1, 1, 2, 2), true);
    EXPECT_EQ(session->CheckFrameRateRangeWithCurrentFps(1, 1, 3, 4), false);

    input->Release();
    session->Release();
}

/*
 * Feature: FrameworkCaptureOutputType
 * Function: Test GetMaxSizePhotoProfile
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetMaxSizePhotoProfile
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_033, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);

    input->Open();
    UpdateCameraOutputCapability();

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    session->SetMode(SceneMode::CAPTURE);
    EXPECT_EQ(session->GetMode(), SceneMode::CAPTURE);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);
    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    EXPECT_EQ(session->AddOutput(preview), 0);

    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);


    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    std::shared_ptr<Profile>retptr = session->GetMaxSizePhotoProfile(ProfileSizeRatio::RATIO_1_1);
    if (retptr == nullptr) {
        ret = 0;
    } else {
        ret = 1;
    }
    EXPECT_EQ(ret, 0);

    input->Release();
    session->RemoveOutput(photo);
    photo->Release();
    preview->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CanAddOutput with CaptureOutputType::CAPTURE_OUTPUT_TYPE_MAX
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CanAddOutput with CaptureOutputType::CAPTURE_OUTPUT_TYPE_MAX
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_034, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);

    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> output =
        new MockCaptureOutput(CaptureOutputType::CAPTURE_OUTPUT_TYPE_MAX, StreamType::CAPTURE, nullptr, nullptr);
    ASSERT_NE(output, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);
    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);

    bool retBool = session->CanAddOutput(output);
    EXPECT_EQ(retBool, false);

    session->RemoveInput(input);
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test RemoveInput with GetCaptureSession() == nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test RemoveInput with GetCaptureSession() == nullptr
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_035, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();

    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);

    auto oldSession = session->GetCaptureSession();

    sptr<ICaptureSession> sessionNullptr = nullptr;
    session->SetCaptureSession(sessionNullptr);

    int32_t ret = session->RemoveInput(input);

    ASSERT_NE(ret, 0);

    oldSession->CommitConfig();
    input->Release();
    oldSession->Release();
}

/*
 * Feature: Framework
 * Function: Test RemoveOutput with GetCaptureSession() == nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test RemoveOutput with GetCaptureSession() == nullptr
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_037, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();

    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);

    EXPECT_EQ(session->AddOutput(preview), 0);

    EXPECT_EQ(session->CommitConfig(), 0);

    auto oldSession = session->GetCaptureSession();

    sptr<ICaptureSession> sessionNullptr = nullptr;
    session->SetCaptureSession(sessionNullptr);

    int32_t ret = session->RemoveOutput(preview);

    ASSERT_NE(ret, 0);

    //oldSession->RemoveInput(input);
    preview->Release();
    input->Release();
    oldSession->Release();
}

/*
 * Feature: Framework
 * Function: Test Start() with GetCaptureSession() == nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Start() with GetCaptureSession() == nullptr
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_038, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();

    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);

    EXPECT_EQ(session->AddOutput(preview), 0);

    EXPECT_EQ(session->CommitConfig(), 0);

    auto oldSession = session->GetCaptureSession();

    sptr<ICaptureSession> sessionNullptr = nullptr;
    session->SetCaptureSession(sessionNullptr);

    ASSERT_NE(session->Start(), 0);

    //oldSession->RemoveInput(input);
    preview->Release();
    input->Release();
    oldSession->Release();
}

/*
 * Feature: Framework
 * Function: Test Stop() with GetCaptureSession() == nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Stop() with GetCaptureSession() == nullptr
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_039, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();

    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);

    EXPECT_EQ(session->AddOutput(preview), 0);

    EXPECT_EQ(session->CommitConfig(), 0);

    auto oldSession = session->GetCaptureSession();

    EXPECT_EQ(session->Start(), 0);

    sptr<ICaptureSession> sessionNullptr = nullptr;
    session->SetCaptureSession(sessionNullptr);

    ASSERT_NE(session->Stop(), 0);

    //oldSession->RemoveInput(input);
    preview->Release();
    input->Release();
    oldSession->Release();
}

/*
 * Feature: Framework
 * Function: Test SetPreviewRotation()
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetPreviewRotation()
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_040, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();

    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);

    EXPECT_EQ(session->AddOutput(preview), 0);

    EXPECT_EQ(session->CommitConfig(), 0);

    EXPECT_EQ(session->Start(), 0);

    std::string deviceClass = "180";

    EXPECT_EQ(session->SetPreviewRotation(deviceClass), 0);

    auto oldSession = session->GetCaptureSession();

    sptr<ICaptureSession> sessionNullptr = nullptr;
    session->SetCaptureSession(sessionNullptr);

    EXPECT_EQ(session->SetPreviewRotation(deviceClass), 0);

    preview->Release();
    input->Release();
    oldSession->Release();
}

/*
 * Feature: Framework
 * Function: Test SetVideoStabilizationMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetVideoStabilizationMode
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_041, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();

    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);

    EXPECT_EQ(session->AddOutput(preview), 0);

    EXPECT_EQ(session->CommitConfig(), 0);

    session->SetVideoStabilizationMode(VideoStabilizationMode::HIGH);

    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test IsVideoStabilizationModeSupported
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsVideoStabilizationModeSupported
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_042, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();

    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);

    EXPECT_EQ(session->AddOutput(preview), 0);

    EXPECT_EQ(session->CommitConfig(), 0);

    bool isSupported = false;
    EXPECT_EQ(session->IsVideoStabilizationModeSupported(VideoStabilizationMode::AUTO, isSupported), 0);

    if (!session->IsVideoStabilizationModeSupported(VideoStabilizationMode::HIGH)) {
        MEDIA_WARNING_LOG("VideoStabilizationMode::HIGH is not supported!");
        EXPECT_EQ(session->IsVideoStabilizationModeSupported(VideoStabilizationMode::HIGH), false);
    } else {
        EXPECT_EQ(session->IsVideoStabilizationModeSupported(VideoStabilizationMode::HIGH), true);
    }

    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test GetSupportedStabilizationMode() with isConcurrentLimted_ == 1
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSupportedStabilizationMode() with isConcurrentLimted_ == 1
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_043, TestSize.Level0)
{
    cameras_[0]->isConcurrentLimted_ = 1;
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();

    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);

    EXPECT_EQ(session->AddOutput(preview), 0);

    EXPECT_EQ(session->CommitConfig(), 0);

    std::vector<VideoStabilizationMode> stabilizationModes;

    EXPECT_EQ(session->GetSupportedStabilizationMode(stabilizationModes), 0);

    cameras_[0]->isConcurrentLimted_ = 0;

    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test SetExposureCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetExposureCallback
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_044, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    std::shared_ptr<ExposureCallback> exposureCallback = nullptr;

    session->SetExposureCallback(exposureCallback);

    session->Release();
}

/*
 * Feature: Framework
 * Function: Test ProcessAutoExposureUpdates
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessAutoExposureUpdates
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_045, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();

    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);

    EXPECT_EQ(session->AddOutput(preview), 0);

    EXPECT_EQ(session->CommitConfig(), 0);

    auto deviceInfo = session->GetInputDevice()->GetCameraDeviceInfo();
    shared_ptr<OHOS::Camera::CameraMetadata> metadata = deviceInfo->GetMetadata();

    session->ProcessAutoExposureUpdates(metadata);

    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CoordinateTransform
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CoordinateTransform
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_046, TestSize.Level0)
{
    if (cameras_.size()<2) {
        GTEST_SKIP();
    }
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[1]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();

    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);

    EXPECT_EQ(session->AddOutput(preview), 0);

    EXPECT_EQ(session->CommitConfig(), 0);

    Point pointnow;
    pointnow.x = 0;
    pointnow.y = 0;

    Point pointres = session->CoordinateTransform(pointnow);

    ASSERT_NE(pointres.x, 0);

    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test VerifyFocusCorrectness
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test VerifyFocusCorrectness
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_047, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();

    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);

    EXPECT_EQ(session->AddOutput(preview), 0);

    EXPECT_EQ(session->CommitConfig(), 0);

    Point pointnow;
    pointnow.x = 1000;
    pointnow.y = 1000;

    Point pointres = session->VerifyFocusCorrectness(pointnow);

    EXPECT_EQ(pointres.x, 1);

    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test SetZoomRatio
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetZoomRatio with big zoomRatio
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_048, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();

    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);

    EXPECT_EQ(session->AddOutput(preview), 0);

    EXPECT_EQ(session->CommitConfig(), 0);

    float zoomRatio = 100000000000.0;

    EXPECT_EQ(session->SetZoomRatio(zoomRatio), 0);

    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test SetSmoothZoom
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetSmoothZoom with abnormal branches
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_049, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();

    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);

    EXPECT_EQ(session->AddOutput(preview), 0);

    EXPECT_EQ(session->CommitConfig(), 0);

    EXPECT_EQ(session->SetSmoothZoom(-1000000.0, 0), 0);

    EXPECT_EQ(session->SetSmoothZoom(100000000000.0, 0), 0);

    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test SetSmoothZoom
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetSmoothZoom with abnormal branches
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_050, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();

    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);

    EXPECT_EQ(session->AddOutput(preview), 0);

    EXPECT_EQ(session->CommitConfig(), 0);

    auto oldSession = session->GetCaptureSession();

    sptr<ICaptureSession> sessionNullptr = nullptr;
    session->SetCaptureSession(sessionNullptr);

    ASSERT_NE(session->SetSmoothZoom(1.0, 0), 0);

    preview->Release();
    input->Release();
    oldSession->Release();
}

/*
 * Feature: Framework
 * Function: Test SetGuessMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetGuessMode
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_051, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();

    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    session->SetGuessMode(SceneMode::NIGHT);

    session->SetMode(SceneMode::NORMAL);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);

    EXPECT_EQ(session->AddOutput(preview), 0);

    EXPECT_EQ(session->CommitConfig(), 0);

    ASSERT_NE(session->GetMode(), SceneMode::NIGHT);

    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test GetSubFeatureMods
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSubFeatureMods
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_052, TestSize.Level0)
{
    std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(cameras_[0]);
    auto item = std::find(modes.begin(), modes.end(), SceneMode::NIGHT);
    if (item != modes.end()) {
        auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
        ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
        sptr<CaptureInput> input = cameraInput;
        sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();

        ASSERT_NE(input, nullptr);
        input->Open();
        UpdateCameraOutputCapability();

        sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

        sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
        ASSERT_NE(session, nullptr);

        sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
        ASSERT_NE(preview, nullptr);

        session->SetMode(SceneMode::NIGHT);

        EXPECT_EQ(session->BeginConfig(), 0);

        EXPECT_EQ(session->AddInput(input), 0);

        EXPECT_EQ(session->AddOutput(preview), 0);

        EXPECT_EQ(session->CommitConfig(), 0);

        vector<SceneFeaturesMode> res = session->GetSubFeatureMods();

        EXPECT_EQ(res.size(), 1);
    }
}

/*
 * Feature: Framework
 * Function: Test IsSessionStarted()
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsSessionStarted()
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_053, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();

    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);

    EXPECT_EQ(session->AddOutput(preview), 0);

    EXPECT_EQ(session->CommitConfig(), 0);

    EXPECT_FALSE(session->IsSessionStarted());

    session->Start();

    EXPECT_TRUE(session->IsSessionStarted());

    auto oldSession = session->GetCaptureSession();

    sptr<ICaptureSession> sessionNullptr = nullptr;
    session->SetCaptureSession(sessionNullptr);

    EXPECT_FALSE(session->IsSessionStarted());

    preview->Release();
    input->Release();
    oldSession->Release();
}

/*
 * Feature: Framework
 * Function: Test GetActiveColorSpace()
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetActiveColorSpace()
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_054, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();

    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);

    EXPECT_EQ(session->AddOutput(preview), 0);

    EXPECT_EQ(session->CommitConfig(), 0);

    ColorSpace colorSpace = DISPLAY_P3;

    auto oldSession = session->GetCaptureSession();

    sptr<ICaptureSession> sessionNullptr = nullptr;
    session->SetCaptureSession(sessionNullptr);

    ASSERT_NE(session->GetActiveColorSpace(colorSpace), 0);

    preview->Release();
    input->Release();
    oldSession->Release();
}

/*
 * Feature: Framework
 * Function: Test SetSensorExposureTime()
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetSensorExposureTime()
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_055, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();

    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);

    EXPECT_EQ(session->AddOutput(preview), 0);

    EXPECT_EQ(session->CommitConfig(), 0);

    session->LockForControl();
    EXPECT_EQ(session->SetSensorExposureTime(1), OPERATION_NOT_ALLOWED);
    EXPECT_EQ(session->SetSensorExposureTime(50000), OPERATION_NOT_ALLOWED);
    session->UnlockForControl();

    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test IsFeatureSupported
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsFeatureSupported
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_056, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();

    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);

    EXPECT_EQ(session->AddOutput(preview), 0);

    EXPECT_EQ(session->CommitConfig(), 0);

    EXPECT_EQ(session->IsFeatureSupported(SceneFeature::FEATURE_ENUM_MAX), false);

    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test EnableFeature
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EnableFeature
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_057, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();

    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);

    EXPECT_EQ(session->AddOutput(preview), 0);

    EXPECT_EQ(session->CommitConfig(), 0);

    bool isSupported = session->IsFeatureSupported(SceneFeature::FEATURE_ENUM_MIN);
    if (isSupported) {
        EXPECT_EQ(session->EnableFeature(SceneFeature::FEATURE_ENUM_MIN, false), 0);
    }
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test GetMetadata()
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetMetadata()
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_058, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();

    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);

    EXPECT_EQ(session->AddOutput(preview), 0);

    EXPECT_EQ(session->CommitConfig(), 0);

    sptr<CameraDevice> oldDevice = camInput->GetCameraDeviceInfo();

    sptr<CameraDevice> deviceNull = nullptr;

    camInput->SetCameraDeviceInfo(deviceNull);

    std::shared_ptr<OHOS::Camera::CameraMetadata>res = session->GetMetadata();

    ASSERT_NE(res, nullptr);

    camInput->SetCameraDeviceInfo(oldDevice);

    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test GetSupportedEffectSuggestionType()
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSupportedEffectSuggestionType()
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_059, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();

    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);

    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    sessionForSys->SetMode(SceneMode::CAPTURE);

    EXPECT_EQ(sessionForSys->BeginConfig(), 0);

    EXPECT_EQ(sessionForSys->AddInput(input), 0);

    EXPECT_EQ(sessionForSys->AddOutput(preview), 0);

    EXPECT_EQ(sessionForSys->CommitConfig(), 0);

    sessionForSys->GetSupportedEffectSuggestionType();

    preview->Release();
    input->Release();
    sessionForSys->Release();
}

/*
 * Feature: Framework
 * Function: Test IsWhiteBalanceModeSupported
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsWhiteBalanceModeSupported
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_060, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();

    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);

    EXPECT_EQ(session->AddOutput(preview), 0);

    EXPECT_EQ(session->CommitConfig(), 0);

    bool isSupported = false;

    EXPECT_EQ(session->IsWhiteBalanceModeSupported(WhiteBalanceMode::AWB_MODE_LOCKED, isSupported), 0);

    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test SetWhiteBalanceMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetWhiteBalanceMode
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_061, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();

    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);

    EXPECT_EQ(session->AddOutput(preview), 0);

    EXPECT_EQ(session->CommitConfig(), 0);

    EXPECT_EQ(session->SetWhiteBalanceMode(WhiteBalanceMode::AWB_MODE_LOCKED), 0);

    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test SetManualWhiteBalance
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetManualWhiteBalance
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_062, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();

    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);

    EXPECT_EQ(session->AddOutput(preview), 0);

    EXPECT_EQ(session->CommitConfig(), 0);

    EXPECT_EQ(session->SetManualWhiteBalance(99999), 0);

    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test EnableFaceDetection
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EnableFaceDetection
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_063, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();

    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);

    EXPECT_EQ(session->AddOutput(preview), 0);

    EXPECT_EQ(session->CommitConfig(), 0);

    session->EnableFaceDetection(true);

    session->EnableFaceDetection(false);

    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test FindFrontCamera()
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test FindFrontCamera()
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_064, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();

    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);

    EXPECT_EQ(session->AddOutput(preview), 0);

    EXPECT_EQ(session->CommitConfig(), 0);

    sptr<CameraDevice> res = session->FindFrontCamera();

    ASSERT_NE(res, nullptr);

    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test StartVideoOutput()
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test StartVideoOutput()
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_065, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->SetMdmCheck(false);
    camInput->GetCameraDevice()->Open();

    UpdateCameraOutputCapability();

    sptr<CaptureOutput> video = CreateVideoOutput(videoProfile_[0]);
    ASSERT_NE(video, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(video), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    session->StartVideoOutput();

    video->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test StopVideoOutput()
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test StopVideoOutput()
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_066, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();

    sptr<CaptureOutput> video = CreateVideoOutput(videoProfile_[0]);
    ASSERT_NE(video, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(video), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    session->Start();
    EXPECT_EQ(session->StopVideoOutput(), false);

    session->StartVideoOutput();
    EXPECT_EQ(session->StopVideoOutput(), true);

    video->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSessionCallback::OnError with nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSessionCallback::OnError with nullptr
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_069, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> video = CreateVideoOutput(videoProfile_[0]);
    ASSERT_NE(video, nullptr);
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    sptr<CaptureSessionCallback> capSessionCallback = new (std::nothrow) CaptureSessionCallback();
    ASSERT_NE(capSessionCallback, nullptr);
    EXPECT_EQ(capSessionCallback->OnError(CAMERA_DEVICE_PREEMPTED), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test CaptureSessionCallback::OnError with CaptureSession
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSessionCallback::OnError with CaptureSession
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_070, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> video = CreateVideoOutput(videoProfile_[0]);
    ASSERT_NE(video, nullptr);
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    sptr<CaptureSessionCallback> capSessionCallback = new (std::nothrow) CaptureSessionCallback(session);
    EXPECT_EQ(capSessionCallback->OnError(CAMERA_DEVICE_PREEMPTED), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test CaptureSessionCallback::OnError with release CaptureSession
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSessionCallback::OnError with release CaptureSession
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_071, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> video = CreateVideoOutput(videoProfile_[0]);
    ASSERT_NE(video, nullptr);
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    sptr<CaptureSessionCallback> capSessionCallback = new (std::nothrow) CaptureSessionCallback(session);
    session->Release();
    EXPECT_EQ(capSessionCallback->OnError(CAMERA_DEVICE_PREEMPTED), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test CheckLightStatus
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CheckLightStatus
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_072, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> video = CreateVideoOutput(videoProfile_[0]);
    ASSERT_NE(video, nullptr);
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    session->CheckLightStatus();
    ASSERT_NE(session, nullptr);
}

/*
 * Feature: Framework
 * Function: Test GetSupportedVideoRotations
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSupportedVideoRotations
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_074, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    std::vector<int32_t> supportedRotation;
    EXPECT_EQ(session->GetSupportedVideoRotations(supportedRotation), 0);
}

/*
 * Feature: Framework
 * Function: Test SetPortraitThemeType with PortraitThemeType is NATURAL
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetPortraitThemeType with PortraitThemeType is NATURAL
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_090, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(sessionForSys->BeginConfig(), 0);
    EXPECT_EQ(sessionForSys->AddInput(input), 0);
    EXPECT_EQ(sessionForSys->AddOutput(preview), 0);
    EXPECT_EQ(sessionForSys->CommitConfig(), 0);

    sessionForSys->LockForControl();
    ASSERT_NE(sessionForSys->SetPortraitThemeType(PortraitThemeType::NATURAL), 0);
    sessionForSys->UnlockForControl();
}

/*
 * Feature: Framework
 * Function: Test SetPortraitThemeType with PortraitThemeType is DELICATE
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetPortraitThemeType with PortraitThemeType is DELICATE
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_091, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(sessionForSys->BeginConfig(), 0);
    EXPECT_EQ(sessionForSys->AddInput(input), 0);
    EXPECT_EQ(sessionForSys->AddOutput(preview), 0);
    EXPECT_EQ(sessionForSys->CommitConfig(), 0);

    sessionForSys->LockForControl();
    ASSERT_NE(sessionForSys->SetPortraitThemeType(PortraitThemeType::DELICATE), 0);
    sessionForSys->UnlockForControl();
}

/*
 * Feature: Framework
 * Function: Test SetPortraitThemeType with PortraitThemeType is STYLISH
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetPortraitThemeType with PortraitThemeType is STYLISH
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_092, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(sessionForSys->BeginConfig(), 0);
    EXPECT_EQ(sessionForSys->AddInput(input), 0);
    EXPECT_EQ(sessionForSys->AddOutput(preview), 0);
    EXPECT_EQ(sessionForSys->CommitConfig(), 0);

    sessionForSys->LockForControl();
    ASSERT_NE(sessionForSys->SetPortraitThemeType(PortraitThemeType::STYLISH), 0);
    sessionForSys->UnlockForControl();
}

/*
 * Feature: Framework
 * Function: Test IsPortraitThemeSupported
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsPortraitThemeSupported
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_093, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    bool isSupported = true;
    EXPECT_EQ(session->IsPortraitThemeSupported(isSupported), 0);
}

/*
 * Feature: Framework
 * Function: Test GetSupportedPortraitThemeTypes
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSupportedPortraitThemeTypes
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_094, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    std::vector<PortraitThemeType> supportedPortraitThemeTypes;
    EXPECT_EQ(session->GetSupportedPortraitThemeTypes(supportedPortraitThemeTypes), 0);
}

/*
 * Feature: Framework
 * Function: Test GetSupportedPortraitThemeTypes with not commit
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSupportedPortraitThemeTypes with not commit
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_095, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    std::vector<PortraitThemeType> supportedPortraitThemeTypes;
    EXPECT_EQ(session->GetSupportedPortraitThemeTypes(supportedPortraitThemeTypes),
        CameraErrorCode::SESSION_NOT_CONFIG);
}

/*
 * Feature: Framework
 * Function: Test GetSupportedPortraitThemeTypes with GetCameraDeviceInfo is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSupportedPortraitThemeTypes with GetCameraDeviceInfo is nullptr
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_096, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    sptr<CameraDevice> oldDevice = camInput->GetCameraDeviceInfo();
    sptr<CameraDevice> deviceNull = nullptr;
    camInput->SetCameraDeviceInfo(deviceNull);

    std::vector<PortraitThemeType> supportedPortraitThemeTypes;
    EXPECT_EQ(session->GetSupportedPortraitThemeTypes(supportedPortraitThemeTypes), 0);
}

/*
 * Feature: Framework
 * Function: Test GetSupportedPortraitThemeTypes with metadata is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSupportedPortraitThemeTypes with metadata is nullptr
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_097, TestSize.Level0)
{
    std::shared_ptr<Camera::CameraMetadata> metadata = nullptr;
    sptr<CameraDevice> deviceNow = new CameraDevice("123456", metadata);

    auto cameraInput = cameraManager_->CreateCameraInput(deviceNow);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    ASSERT_NE(session->AddOutput(preview), 0);
    ASSERT_NE(session->CommitConfig(), 0);

    std::vector<PortraitThemeType> supportedPortraitThemeTypes;
    EXPECT_EQ(session->GetSupportedPortraitThemeTypes(supportedPortraitThemeTypes), 0);
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with IsDepthFusionEnabled, IsMovingPhotoEnabled, SetMacroStatusCallback,
 * IsSetEnableMacro, GeneratePreconfigProfiles, SetEffectSuggestionCallback, SetARCallback
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsDepthFusionEnabled, IsMovingPhotoEnabled, SetMacroStatusCallback,
 * IsSetEnableMacro, GeneratePreconfigProfiles, SetEffectSuggestionCallback, SetARCallback for just call.
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_098, TestSize.Level0)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);
    sessionForSys->isDepthFusionEnable_ = false;
    EXPECT_FALSE(sessionForSys->IsDepthFusionEnabled());

    sessionForSys->isMovingPhotoEnabled_ = false;
    EXPECT_FALSE(sessionForSys->IsMovingPhotoEnabled());

    sessionForSys->SetMacroStatusCallback(nullptr);
    EXPECT_EQ(sessionForSys->GetMacroStatusCallback(), nullptr);

    sessionForSys->isSetMacroEnable_ = false;
    EXPECT_FALSE(sessionForSys->IsSetEnableMacro());

    int32_t preconfigType = 4;
    ProfileSizeRatio preconfigRatio = RATIO_1_1;
    EXPECT_EQ(sessionForSys->GeneratePreconfigProfiles(static_cast<PreconfigType>(preconfigType), preconfigRatio),
        nullptr);

    sessionForSys->SetEffectSuggestionCallback(nullptr);
    EXPECT_EQ(sessionForSys->effectSuggestionCallback_, nullptr);

    sessionForSys->SetARCallback(nullptr);
    EXPECT_EQ(sessionForSys->GetARCallback(), nullptr);
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with IsDepthFusionEnabled, IsMovingPhotoEnabled, SetMacroStatusCallback,
 * IsSetEnableMacro, GeneratePreconfigProfiles, SetEffectSuggestionCallback, SetARCallback
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsDepthFusionEnabled, IsMovingPhotoEnabled, SetMacroStatusCallback,
 * IsSetEnableMacro, GeneratePreconfigProfiles, SetEffectSuggestionCallback, SetARCallback for just call.
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_099, TestSize.Level0)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);
    sessionForSys->isDepthFusionEnable_ = false;
    EXPECT_FALSE(sessionForSys->IsDepthFusionEnabled());

    sessionForSys->isMovingPhotoEnabled_ = false;
    EXPECT_FALSE(sessionForSys->IsMovingPhotoEnabled());

    sessionForSys->SetMacroStatusCallback(nullptr);
    EXPECT_EQ(sessionForSys->GetMacroStatusCallback(), nullptr);

    sessionForSys->isSetMacroEnable_ = false;
    EXPECT_FALSE(sessionForSys->IsSetEnableMacro());

    int32_t preconfigType = 4;
    ProfileSizeRatio preconfigRatio = UNSPECIFIED;
    EXPECT_EQ(sessionForSys->GeneratePreconfigProfiles(static_cast<PreconfigType>(preconfigType), preconfigRatio),
        nullptr);

    sessionForSys->SetEffectSuggestionCallback(nullptr);
    EXPECT_EQ(sessionForSys->effectSuggestionCallback_, nullptr);

    sessionForSys->SetARCallback(nullptr);
    EXPECT_EQ(sessionForSys->GetARCallback(), nullptr);
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with IsDepthFusionEnabled, IsMovingPhotoEnabled, SetMacroStatusCallback,
 * IsSetEnableMacro, GeneratePreconfigProfiles, SetEffectSuggestionCallback, SetARCallback
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsDepthFusionEnabled, IsMovingPhotoEnabled, SetMacroStatusCallback,
 * IsSetEnableMacro, GeneratePreconfigProfiles, SetEffectSuggestionCallback, SetARCallback for just call.
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_100, TestSize.Level0)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);
    sessionForSys->isDepthFusionEnable_ = false;
    EXPECT_FALSE(sessionForSys->IsDepthFusionEnabled());

    sessionForSys->isMovingPhotoEnabled_ = false;
    EXPECT_FALSE(sessionForSys->IsMovingPhotoEnabled());

    sessionForSys->SetMacroStatusCallback(nullptr);
    EXPECT_EQ(sessionForSys->GetMacroStatusCallback(), nullptr);

    sessionForSys->isSetMacroEnable_ = false;
    EXPECT_FALSE(sessionForSys->IsSetEnableMacro());

    int32_t preconfigType = 4;
    ProfileSizeRatio preconfigRatio = RATIO_16_9;
    EXPECT_EQ(sessionForSys->GeneratePreconfigProfiles(static_cast<PreconfigType>(preconfigType), preconfigRatio),
        nullptr);

    sessionForSys->SetEffectSuggestionCallback(nullptr);
    EXPECT_EQ(sessionForSys->effectSuggestionCallback_, nullptr);

    sessionForSys->SetARCallback(nullptr);
    EXPECT_EQ(sessionForSys->GetARCallback(), nullptr);
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with IsDepthFusionEnabled, IsMovingPhotoEnabled, SetMacroStatusCallback,
 * IsSetEnableMacro, GeneratePreconfigProfiles, SetEffectSuggestionCallback, SetARCallback
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsDepthFusionEnabled, IsMovingPhotoEnabled, SetMacroStatusCallback,
 * IsSetEnableMacro, GeneratePreconfigProfiles, SetEffectSuggestionCallback, SetARCallback for just call.
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_101, TestSize.Level0)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);
    sessionForSys->isDepthFusionEnable_ = false;
    EXPECT_FALSE(sessionForSys->IsDepthFusionEnabled());

    sessionForSys->isMovingPhotoEnabled_ = false;
    EXPECT_FALSE(sessionForSys->IsMovingPhotoEnabled());

    sessionForSys->SetMacroStatusCallback(nullptr);
    EXPECT_EQ(sessionForSys->GetMacroStatusCallback(), nullptr);

    sessionForSys->isSetMacroEnable_ = false;
    EXPECT_FALSE(sessionForSys->IsSetEnableMacro());

    PreconfigType preconfigType = PRECONFIG_720P;
    int32_t preconfigRatio = 3;
    EXPECT_EQ(sessionForSys->GeneratePreconfigProfiles(preconfigType,
        static_cast<ProfileSizeRatio>(preconfigRatio)), nullptr);

    sessionForSys->SetEffectSuggestionCallback(nullptr);
    EXPECT_EQ(sessionForSys->effectSuggestionCallback_, nullptr);

    sessionForSys->SetARCallback(nullptr);
    EXPECT_EQ(sessionForSys->GetARCallback(), nullptr);
}

/*
 * Feature: Framework
 * Function: Test CommitConfig with CheckLightStatus is true
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CommitConfig with CheckLightStatus is true
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_102, TestSize.Level0)
{
    int32_t DEFAULT_ITEMS = 10;
    int32_t DEFAULT_DATA_LENGTH = 200;
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    uint8_t* lightStatus = new uint8_t[2];
    lightStatus[0] = 1;
    lightStatus[1] = 1;
    cameraAbility->addEntry(OHOS_ABILITY_LIGHT_STATUS, lightStatus, 2);
    sptr<CameraDevice> deviceNow = new CameraDevice("device/0", cameraAbility);
 
    auto cameraInput = cameraManager_->CreateCameraInput(deviceNow);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    ASSERT_NE(session->AddOutput(preview), 0);
    ASSERT_NE(session->CommitConfig(), 0);
}
 
/*
 * Feature: Framework
 * Function: Test ConfigureVideoOutput with frameRateRange.size() < minFpsRangeSize
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ConfigureVideoOutput with frameRateRange.size() < minFpsRangeSize
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_103, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
 
    uint32_t widthGreaterThantheRange = 1000000;
    uint32_t heightGreaterThantheRange = 1000000;
    Size size = { widthGreaterThantheRange, heightGreaterThantheRange };
    std::vector<int32_t> framerates;
    VideoProfile profile(CameraFormat::CAMERA_FORMAT_RGBA_8888, size, framerates);
    sptr<CaptureOutput> video = CreateVideoOutput(videoProfile_[0]);
    video->SetVideoProfile(profile);
 
    EXPECT_EQ(session->ConfigureVideoOutput(video), 0);
}
 
/*
 * Feature: Framework
 * Function: Test InsertOutputIntoSet
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test InsertOutputIntoSet
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_104, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
 
    sptr<CaptureOutput> outputNull = nullptr;
    session->InsertOutputIntoSet(outputNull);
    session->InsertOutputIntoSet(outputNull);
}
 
/*
 * Feature: Framework
 * Function: Test InsertOutputIntoSet
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test InsertOutputIntoSet
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_105, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
 
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
    session->InsertOutputIntoSet(preview);
    session->InsertOutputIntoSet(preview);
}
 
/*
 * Feature: Framework
 * Function: Test SetCallback twice
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetCallback twice
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_106, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
 
    std::shared_ptr<SessionCallback> sessionCallback = std::make_shared<AppSessionCallback>();
    ASSERT_NE(sessionCallback, nullptr);
 
    session->SetCallback(sessionCallback);
    session->SetCallback(sessionCallback);
}
 
/*
 * Feature: Framework
 * Function: Test GetActiveVideoStabilizationMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetActiveVideoStabilizationMode
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_107, TestSize.Level0)
{
    int32_t DEFAULT_ITEMS = 10;
    int32_t DEFAULT_DATA_LENGTH = 200;
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    uint8_t autoStabilization = OHOS_CAMERA_VIDEO_STABILIZATION_AUTO;
    cameraAbility->addEntry(OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &autoStabilization, 1);
 
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    cameras_[0]->cachedMetadata_ = cameraAbility;
 
    EXPECT_EQ(session->GetActiveVideoStabilizationMode(), VideoStabilizationMode::AUTO);
}
 
/*
 * Feature: Framework
 * Function: Test GetActiveVideoStabilizationMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetActiveVideoStabilizationMode
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_108, TestSize.Level0)
{
    int32_t DEFAULT_ITEMS = 10;
    int32_t DEFAULT_DATA_LENGTH = 200;
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    uint8_t autoStabilization = 5;
    cameraAbility->addEntry(OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &autoStabilization, 1);
 
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    cameras_[0]->cachedMetadata_ = cameraAbility;
 
    EXPECT_EQ(session->GetActiveVideoStabilizationMode(), VideoStabilizationMode::OFF);
}
 
/*
 * Feature: Framework
 * Function: Test GetActiveVideoStabilizationMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetActiveVideoStabilizationMode
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_109, TestSize.Level0)
{
    int32_t DEFAULT_ITEMS = 10;
    int32_t DEFAULT_DATA_LENGTH = 200;
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    uint8_t autoStabilization = OHOS_CAMERA_VIDEO_STABILIZATION_AUTO;
    cameraAbility->addEntry(OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &autoStabilization, 1);
 
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    cameras_[0]->cachedMetadata_ = cameraAbility;
 
    VideoStabilizationMode mode = VideoStabilizationMode::OFF;
    EXPECT_EQ(session->GetActiveVideoStabilizationMode(mode), 0);
}
 
/*
 * Feature: Framework
 * Function: Test GetActiveVideoStabilizationMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetActiveVideoStabilizationMode
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_110, TestSize.Level0)
{
    int32_t DEFAULT_ITEMS = 10;
    int32_t DEFAULT_DATA_LENGTH = 200;
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    uint8_t autoStabilization = 5;
    cameraAbility->addEntry(OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &autoStabilization, 1);
    sptr<CameraDevice> deviceNow = new CameraDevice("device/0", cameraAbility);
 
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    cameras_[0]->cachedMetadata_ = cameraAbility;
 
    VideoStabilizationMode mode = VideoStabilizationMode::OFF;
    EXPECT_EQ(session->GetActiveVideoStabilizationMode(mode), 0);
}
 
/*
 * Feature: Framework
 * Function: Test SetVideoStabilizationMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetVideoStabilizationMode
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_111, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    VideoStabilizationMode stabilizationMode = static_cast<VideoStabilizationMode>(5);
    ASSERT_NE(session->SetVideoStabilizationMode(stabilizationMode), 0);
}
 
/*
 * Feature: Framework
 * Function: Test GetSupportedExposureModes
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSupportedExposureModes
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_112, TestSize.Level0)
{
    int32_t DEFAULT_ITEMS = 10;
    int32_t DEFAULT_DATA_LENGTH = 200;
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    uint8_t stabilizationMode = 5;
    cameraAbility->addEntry(OHOS_ABILITY_VIDEO_STABILIZATION_MODES, &stabilizationMode, 1);
 
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> video = CreateVideoOutput(videoProfile_[0]);
    ASSERT_NE(video, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(video), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    cameras_[0]->cachedMetadata_ = cameraAbility;
 
    std::vector<ExposureMode> supportedExposureModes;
    EXPECT_EQ(session->GetSupportedExposureModes(supportedExposureModes), 0);
}
 
/*
 * Feature: Framework
 * Function: Test SetMeteringPoint with changemeta is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetMeteringPoint with changemeta is nullptr
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_113, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    session->LockForControl();
    session->UnlockForControl();
 
    Point exposurePoint = {1.0, 2.0};
    EXPECT_EQ(session->SetMeteringPoint(exposurePoint), 0);
}
 
/*
 * Feature: Framework
 * Function: Test SetExposureBias with changemeta is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetExposureBias with changemeta is nullptr
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_114, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    session->LockForControl();
    session->UnlockForControl();
    
    float exposureValue = 0.1;
    EXPECT_EQ(session->SetExposureBias(exposureValue), 0);
}
 
/*
 * Feature: Framework
 * Function: Test SetExposureBias with changemeta
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetExposureBias with changemeta
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_115, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    float exposureValue = 0.1;
    EXPECT_EQ(session->SetExposureBias(exposureValue), 0);
    EXPECT_EQ(session->SetExposureBias(exposureValue), 0);
}
 
/*
 * Feature: Framework
 * Function: Test ProcessAutoExposureUpdates
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessAutoExposureUpdates
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_116, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
 
    int32_t DEFAULT_ITEMS = 10;
    int32_t DEFAULT_DATA_LENGTH = 200;
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    
    uint8_t exposureMode = 1;
    cameraAbility->addEntry(OHOS_CONTROL_EXPOSURE_MODE, &exposureMode, 1);
    uint8_t exposureStatus = 1;
    cameraAbility->addEntry(OHOS_CONTROL_EXPOSURE_STATE, &exposureStatus, 1);
 
    session->ProcessAutoExposureUpdates(cameraAbility);
}
 
/*
 * Feature: Framework
 * Function: Test GetSupportedFocusModes
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSupportedFocusModes
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_117, TestSize.Level0)
{
    int32_t DEFAULT_ITEMS = 10;
    int32_t DEFAULT_DATA_LENGTH = 200;
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    std::vector<uint8_t> lockModeVector = {100};
    cameraAbility->addEntry(OHOS_ABILITY_FOCUS_MODES, &lockModeVector, 1);
 
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    cameras_[0]->cachedMetadata_ = cameraAbility;
    
    std::vector<FocusMode> supportedFocusModes;
    EXPECT_EQ(session->GetSupportedFocusModes(supportedFocusModes), 0);
}
 
/*
 * Feature: Framework
 * Function: Test IsFocusModeSupported with Non-existent FocusMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsFocusModeSupported with Non-existent FocusMode
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_118, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    FocusMode focusMode = static_cast<FocusMode>(5);
    bool isSupported = false;
    EXPECT_EQ(session->IsFocusModeSupported(focusMode, isSupported), 0);
}
 
/*
 * Feature: Framework
 * Function: Test SetFocusMode with Non-existent FocusMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetFocusMode with Non-existent FocusMode
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_119, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    FocusMode focusMode = static_cast<FocusMode>(5);
    EXPECT_EQ(session->SetFocusMode(focusMode), 0);
}
 
/*
 * Feature: Framework
 * Function: Test GetFocusMode with Non-existent FocusMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetFocusMode with Non-existent FocusMode
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_120, TestSize.Level0)
{
    int32_t DEFAULT_ITEMS = 10;
    int32_t DEFAULT_DATA_LENGTH = 200;
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    std::vector<uint8_t> mode = {100};
    cameraAbility->addEntry(OHOS_CONTROL_FOCUS_MODE, &mode, 1);
 
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    cameras_[0]->cachedMetadata_ = cameraAbility;
 
    FocusMode focusMode;
    EXPECT_EQ(session->GetFocusMode(focusMode), 0);
}
 
/*
 * Feature: Framework
 * Function: Test SetFocusPoint twice
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetFocusPoint twice
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_121, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    Point exposurePoint = {1.0, 2.0};
    EXPECT_EQ(session->SetFocusPoint(exposurePoint), 0);
    EXPECT_EQ(session->SetFocusPoint(exposurePoint), 0);
}
 
/*
 * Feature: Framework
 * Function: Test ProcessAutoFocusUpdates with Non-existent
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessAutoFocusUpdates with Non-existent
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_122, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
 
    int32_t DEFAULT_ITEMS = 10;
    int32_t DEFAULT_DATA_LENGTH = 200;
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    
    uint8_t fMode = 1;
    cameraAbility->addEntry(OHOS_CONTROL_FOCUS_MODE, &fMode, 1);
    session->ProcessAutoFocusUpdates(cameraAbility);
}
 
/*
 * Feature: Framework
 * Function: Test IsFlashModeSupported with Non-existent
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsFlashModeSupported with Non-existent
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_123, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    FlashMode flashMode = static_cast<FlashMode>(1000);
    EXPECT_EQ(session->IsFlashModeSupported(flashMode), 0);
}
 
/*
 * Feature: Framework
 * Function: Test IsFlashModeSupported with Non-existent
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsFlashModeSupported with Non-existent
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_124, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    FlashMode flashMode = static_cast<FlashMode>(1000);
    bool isSupported = false;
    EXPECT_EQ(session->IsFlashModeSupported(flashMode, isSupported), 0);
}
 
/*
 * Feature: Framework
 * Function: Test HasFlash with RemoveInput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HasFlash with RemoveInput
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_125, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    session->supportSpecSearch_ = false;
    EXPECT_EQ(session->HasFlash(), true);
}
 
/*
 * Feature: Framework
 * Function: Test HasFlash with RemoveInput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HasFlash with RemoveInput
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_126, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    session->supportSpecSearch_ = false;
    bool hasFlash = false;
    EXPECT_EQ(session->HasFlash(hasFlash), 0);
}
 
/*
 * Feature: Framework
 * Function: Test HasFlash with cameraAbilityContainer_ is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HasFlash with cameraAbilityContainer_ is nullptr
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_127, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    auto abilityContainer = session->GetCameraAbilityContainer();
    session->cameraAbilityContainer_ = nullptr;
    bool hasFlash = false;
    EXPECT_EQ(session->HasFlash(hasFlash), 0);
    session->cameraAbilityContainer_ = abilityContainer;
}
 
/*
 * Feature: Framework
 * Function: Test DoSpecSearch with cameraAbilityContainer_ is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DoSpecSearch with cameraAbilityContainer_ is nullptr
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_128, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    auto abilityContainer = session->GetCameraAbilityContainer();
    session->cameraAbilityContainer_ = nullptr;
    std::vector<float> zoomRatioRange = {0.1, 0.2};
    EXPECT_EQ(session->DoSpecSearch(zoomRatioRange), 0);
    session->cameraAbilityContainer_ = abilityContainer;
}
 
/*
 * Feature: Framework
 * Function: Test GetZoomRatioRange with supportSpecSearch_ is false
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetZoomRatioRange with supportSpecSearch_ is false
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_129, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    std::vector<float> zoomRatioRange;
    auto oldsupportSpecSearch = session->supportSpecSearch_.load();
    session->supportSpecSearch_.store(false);
    EXPECT_EQ(session->GetZoomRatioRange(zoomRatioRange), 0);
    session->supportSpecSearch_.store(oldsupportSpecSearch);
}
 
/*
 * Feature: Framework
 * Function: Test PrepareZoom twice
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test PrepareZoom twice
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_130, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    EXPECT_EQ(session->PrepareZoom(), 0);
    EXPECT_EQ(session->PrepareZoom(), 0);
}
 
/*
 * Feature: Framework
 * Function: Test UnPrepareZoom twice
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UnPrepareZoom twice
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_131, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    EXPECT_EQ(session->UnPrepareZoom(), 0);
    EXPECT_EQ(session->UnPrepareZoom(), 0);
}
 
/*
 * Feature: Framework
 * Function: Test SetBeautyValue with can not find beautyType
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetBeautyValue with can not find beautyType
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_133, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
 
    BeautyType beautyType = static_cast<BeautyType>(15);
    session->SetBeautyValue(beautyType, 0);
}
 
/*
 * Feature: Framework
 * Function: Test GetSupportedColorSpaces with abilityContainer is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSupportedColorSpaces with abilityContainer is nullptr
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_134, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    auto abilityContainer = session->GetCameraAbilityContainer();
    session->cameraAbilityContainer_ = nullptr;
    auto oldsupportSpecSearch = session->supportSpecSearch_.load();
    session->supportSpecSearch_.store(true);
    std::vector<ColorSpace>res = session->GetSupportedColorSpaces();
    EXPECT_EQ(res.size(), 0);
 
    session->supportSpecSearch_.store(oldsupportSpecSearch);
    session->cameraAbilityContainer_ = abilityContainer;
}
 
/*
 * Feature: Framework
 * Function: Test SetSensorExposureTime with isExec is true
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetSensorExposureTime with isExec is true
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_135, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    session->LockForControl();
    uint32_t timeLessRange = 1;
    EXPECT_EQ(session->SetSensorExposureTime(timeLessRange), OPERATION_NOT_ALLOWED);
    session->UnlockForControl();
}
 
/*
 * Feature: Framework
 * Function: Test IsMacroSupported with supportSpecSearch_ is false
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsMacroSupported with supportSpecSearch_ is falsee
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_136, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    auto oldsupportSpecSearch = session->supportSpecSearch_.load();
    session->supportSpecSearch_.store(false);
    EXPECT_EQ(session->IsMacroSupported(), false);
    session->supportSpecSearch_.store(oldsupportSpecSearch);
}
 
/*
 * Feature: Framework
 * Function: Test IsMacroSupported with abilityContainer is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsMacroSupported with abilityContainer is nullptr
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_137, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    auto abilityContainer = session->GetCameraAbilityContainer();
    session->cameraAbilityContainer_ = nullptr;
    EXPECT_EQ(session->IsMacroSupported(), false);
    session->cameraAbilityContainer_ = abilityContainer;
}

/*
 * Feature: Framework
 * Function: Test EnableDeferredType with DELIVERY_PHOTO
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EnableDeferredType with DELIVERY_PHOTO
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_144, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
 
    int32_t DEFAULT_ITEMS = 10;
    int32_t DEFAULT_DATA_LENGTH = 200;
    session->changedMetadata_ = std::make_shared<Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    DeferredDeliveryImageType type = DeferredDeliveryImageType::DELIVERY_PHOTO;
    session->EnableDeferredType(type, true);
    session->EnableDeferredType(type, true);
}
 
/*
 * Feature: Framework
 * Function: Test EnableAutoDeferredVideoEnhancement
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EnableAutoDeferredVideoEnhancement
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_145, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    int32_t DEFAULT_ITEMS = 10;
    int32_t DEFAULT_DATA_LENGTH = 200;
    session->changedMetadata_ = std::make_shared<Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    uint8_t deferredType = 0;
    session->changedMetadata_->addEntry(OHOS_CONTROL_DEFERRED_IMAGE_DELIVERY, &deferredType, 1);
    DeferredDeliveryImageType type = DeferredDeliveryImageType::DELIVERY_PHOTO;
    session->EnableDeferredType(type, true);
}
 
/*
 * Feature: Framework
 * Function: Test SetUserId
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetUserId
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_146, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    int32_t userId = 0;
    int32_t DEFAULT_ITEMS = 10;
    int32_t DEFAULT_DATA_LENGTH = 200;
    session->changedMetadata_ = std::make_shared<Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    session->changedMetadata_->addEntry(OHOS_CONTROL_AUTO_DEFERRED_VIDEO_ENHANCE, &userId, 1);
    EXPECT_EQ(session->EnableAutoHighQualityPhoto(true), 0);
    EXPECT_EQ(session->EnableAutoHighQualityPhoto(true), 0);
}
 
/*
 * Feature: Framework
 * Function: Test EnableAutoCloudImageEnhancement
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EnableAutoCloudImageEnhancement
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_147, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    uint8_t AutoCloudImageEnhanceEnable  = 0;
    int32_t DEFAULT_ITEMS = 10;
    int32_t DEFAULT_DATA_LENGTH = 200;
    session->changedMetadata_ = std::make_shared<Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    session->changedMetadata_->addEntry(OHOS_CONTROL_AUTO_CLOUD_IMAGE_ENHANCE, &AutoCloudImageEnhanceEnable, 1);
    EXPECT_EQ(session->EnableAutoCloudImageEnhancement(true), 0);
    EXPECT_EQ(session->EnableAutoCloudImageEnhancement(true), 0);
}
 
/*
 * Feature: Framework
 * Function: Test EnableEffectSuggestion
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EnableEffectSuggestion
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_148, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability(SceneMode::VIDEO);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::VIDEO);
    ASSERT_NE(sessionForSys, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(sessionForSys->BeginConfig(), 0);
    EXPECT_EQ(sessionForSys->AddInput(input), 0);
    EXPECT_EQ(sessionForSys->AddOutput(preview), 0);
    EXPECT_EQ(sessionForSys->CommitConfig(), 0);
    
    uint8_t enableValue   = 0;
    int32_t DEFAULT_ITEMS = 10;
    int32_t DEFAULT_DATA_LENGTH = 200;
    sessionForSys->changedMetadata_ = std::make_shared<Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    sessionForSys->changedMetadata_->addEntry(OHOS_CONTROL_EFFECT_SUGGESTION, &enableValue, 1);
    EXPECT_EQ(sessionForSys->EnableEffectSuggestion(true), OPERATION_NOT_ALLOWED);
    EXPECT_EQ(sessionForSys->EnableEffectSuggestion(true), OPERATION_NOT_ALLOWED);
}
 
/*
 * Feature: Framework
 * Function: Test GetSupportedEffectSuggestionType with abnormal branches
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSupportedEffectSuggestionType with abnormal branches
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_149, TestSize.Level0)
{
    UpdateCameraOutputCapability(SceneMode::VIDEO);
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::VIDEO);
    ASSERT_NE(sessionForSys, nullptr);
    ASSERT_EQ(SceneMode::VIDEO, sessionForSys->GetMode());
 
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(nullptr, input);
    ASSERT_EQ(CAMERA_OK, input->Open());
 
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfile_[0]);
    ASSERT_NE(nullptr, videoOutput);
 
    ASSERT_EQ(CAMERA_OK, sessionForSys->BeginConfig());
    ASSERT_EQ(CAMERA_OK, sessionForSys->AddInput(input));
    ASSERT_EQ(CAMERA_OK, sessionForSys->AddOutput(videoOutput));
    ASSERT_EQ(CAMERA_OK, sessionForSys->CommitConfig());
 
    std::vector<uint32_t> vec;
    std::vector<EffectSuggestionType> expectedVec;
 
    Camera::DeleteCameraMetadataItem(sessionForSys->GetMetadata()->get(), OHOS_ABILITY_EFFECT_SUGGESTION_SUPPORTED);
    EXPECT_EQ(expectedVec, sessionForSys->GetSupportedEffectSuggestionType());
 
    sessionForSys->LockForControl();
    ASSERT_NE(nullptr, sessionForSys->changedMetadata_);
    vec = {2, 1, 1000, -1};
    sessionForSys->changedMetadata_->addEntry(OHOS_ABILITY_EFFECT_SUGGESTION_SUPPORTED, vec.data(), 4);
    sessionForSys->UnlockForControl();
 
    expectedVec =
    {EffectSuggestionType::EFFECT_SUGGESTION_STAGE};
 
    ASSERT_NE(expectedVec, sessionForSys->GetSupportedEffectSuggestionType());
 
    EXPECT_EQ(CAMERA_OK, videoOutput->Release());
    EXPECT_EQ(CAMERA_OK, input->Close());
    EXPECT_EQ(CAMERA_OK, sessionForSys->Release());
}
 
/*
 * Feature: Framework
 * Function: Test SetEffectSuggestionStatus
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetEffectSuggestionStatus
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_150, TestSize.Level0)
{
    UpdateCameraOutputCapability(SceneMode::VIDEO);
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::VIDEO);
    ASSERT_NE(sessionForSys, nullptr);
    ASSERT_EQ(SceneMode::VIDEO, sessionForSys->GetMode());
 
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(nullptr, input);
    ASSERT_EQ(CAMERA_OK, input->Open());
 
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfile_[0]);
    ASSERT_NE(nullptr, videoOutput);
 
    ASSERT_EQ(CAMERA_OK, sessionForSys->BeginConfig());
    ASSERT_EQ(CAMERA_OK, sessionForSys->AddInput(input));
    ASSERT_EQ(CAMERA_OK, sessionForSys->AddOutput(videoOutput));
    ASSERT_EQ(CAMERA_OK, sessionForSys->CommitConfig());
 
    std::vector<uint32_t> vec;
    std::vector<EffectSuggestionStatus> effectSuggestionStatusList = {
        {EffectSuggestionType::EFFECT_SUGGESTION_STAGE, true}};
    std::vector<uint8_t> expectedVec = {5, 1};
 
    Camera::DeleteCameraMetadataItem(sessionForSys->GetMetadata()->get(), OHOS_ABILITY_EFFECT_SUGGESTION_SUPPORTED);
    sessionForSys->LockForControl();
    ASSERT_NE(nullptr, sessionForSys->changedMetadata_);
    vec = {2, 1, 5, -1};
    sessionForSys->changedMetadata_->addEntry(OHOS_ABILITY_EFFECT_SUGGESTION_SUPPORTED, vec.data(), 4);
    sessionForSys->UnlockForControl();
 
    sessionForSys->LockForControl();
    EXPECT_EQ(CAMERA_OK, sessionForSys->SetEffectSuggestionStatus(effectSuggestionStatusList));
    EXPECT_EQ(CAMERA_OK, sessionForSys->SetEffectSuggestionStatus(effectSuggestionStatusList));
    sessionForSys->UnlockForControl();
 
    EXPECT_EQ(CAMERA_OK, videoOutput->Release());
    EXPECT_EQ(CAMERA_OK, input->Close());
    EXPECT_EQ(CAMERA_OK, sessionForSys->Release());
}
 
/*
 * Feature: Framework
 * Function: Test SetWhiteBalanceMode with abnormal branches
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetWhiteBalanceMode with abnormal branches
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_151, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    session->LockForControl();
    int32_t mode = 15;
    EXPECT_EQ(session->SetWhiteBalanceMode(static_cast<WhiteBalanceMode>(mode)), 0);
    session->UnlockForControl();
}
 
/*
 * Feature: Framework
 * Function: Test SetQualityPrioritization with abnormal branches
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetQualityPrioritization with abnormal branches
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_152, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    QualityPrioritization qualityPrioritization = HIGH_QUALITY;
    session->changedMetadata_  = nullptr;
    EXPECT_EQ(session->SetQualityPrioritization(qualityPrioritization), 0);
}
 
/*
 * Feature: Framework
 * Function: Test AddFunctionToMap with abnormal branches
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AddFunctionToMap with abnormal branches
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_153, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    session->canAddFuncToMap_ = true;
    session->isAutoSwitchDevice_ = true;
    session->AddFunctionToMap(std::to_string(OHOS_CONTROL_VIDEO_STABILIZATION_MODE), []() {
            MEDIA_DEBUG_LOG("function");
        });
}
 
/*
 * Feature: Framework
 * Function: Test AddFunctionToMap with abnormal branches
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AddFunctionToMap with abnormal branches
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_154, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    session->AddFunctionToMap(std::to_string(OHOS_CONTROL_VIDEO_STABILIZATION_MODE), []() {
            MEDIA_DEBUG_LOG("function");
        });
    session->ExecuteAllFunctionsInMap();
}
 
/*
 * Feature: Framework
 * Function: Test FindTagId
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test FindTagId with inputDevice == nullptr
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_156, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    session->innerInputDevice_ = nullptr;
    session->FindTagId();
}
 
/*
 * Feature: Framework
 * Function: Test Start
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Start with innerCaptureSession_ == nullptr
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_157, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
 
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
 
    session->innerCaptureSession_ = nullptr;
    ASSERT_NE(session->Start(), 0);
}

/*
 * Feature: Framework
 * Function: Test EnableOfflinePhoto
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EnableOfflinePhoto
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_158, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(photo), 0);
    auto photoOutput = (sptr<PhotoOutput> &)photo;
    photoOutput->SetSwitchOfflinePhotoOutput(true);
    EXPECT_EQ(session->CommitConfig(), 0);
    photoOutput->SetSwitchOfflinePhotoOutput(false);
}
/*
 * Feature: Framework
 * Function: Test EnableAutoFrameRate
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EnableAutoFrameRate
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_159, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    auto oldchangedMetadata = session->changedMetadata_;
    int32_t DEFAULT_ITEMS = 10;
    int32_t DEFAULT_DATA_LENGTH = 200;
    session->changedMetadata_ = std::make_shared<Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    ASSERT_NE(session->changedMetadata_, nullptr);
    session->EnableAutoFrameRate(false);
    session->changedMetadata_ = oldchangedMetadata;
}

/*
 * Feature: Framework
 * Function: Test CanSetFrameRateRange
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CanSetFrameRateRange
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_160, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
    EXPECT_EQ(session->CanSetFrameRateRange(10, 60, preview), false);
}
/*
 * Feature: Framework
 * Function: Test EnableLowLightBoost
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EnableLowLightBoost
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_161, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
    EXPECT_EQ(session->EnableLowLightBoost(false), OPERATION_NOT_ALLOWED);
}

/*
 * Feature: Framework
 * Function: Test GetPressureCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetPressureCallback
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_162, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->GetPressureCallback(), nullptr);
}

/*
 * Feature: Framework
 * Function: Test GetCameraDeviceRotationAngle
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the normal process of the GetCameraDeviceRotationAngle interface.
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_163, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    sptr<PreviewOutput> previewOutput = (sptr<PreviewOutput>&) preview;
    uint32_t cameraRotation = 0;
    EXPECT_EQ(previewOutput->GetCameraDeviceRotationAngle(cameraRotation), 0);
    input->Close();
}

/*
 * Feature: Framework
 * Function: Test GetCameraDeviceRotationAngle
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the abnormal process of the GetCameraDeviceRotationAngle interface.
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_164, TestSize.Level0)
{
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
    sptr<PreviewOutput> previewOutput = (sptr<PreviewOutput>&) preview;
    uint32_t cameraRotation = 0;
    EXPECT_EQ(previewOutput->GetCameraDeviceRotationAngle(cameraRotation), SERVICE_FATL_ERROR);
}

/*
 * Feature: Framework
 * Function: Test IsXComponentSwap
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the IsXComponentSwap interface to return true.
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_165, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    sptr<PreviewOutput> previewOutput = (sptr<PreviewOutput>&) preview;
    EXPECT_EQ(previewOutput->IsXComponentSwap(), true);
    input->Close();
}

/*
 * Feature: Framework
 * Function: Test IsXComponentSwap
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the IsXComponentSwap interface to return false.
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_166, TestSize.Level0)
{
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
    sptr<PreviewOutput> previewOutput = (sptr<PreviewOutput>&) preview;
    EXPECT_EQ(previewOutput->IsXComponentSwap(), false);
}

/*
 * Feature: Framework
 * Function: Test ConfigureMovieFileOutput and ConfigureUnifyMovieFileOutput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ConfigureMovieFileOutput and ConfigureUnifyMovieFileOutput
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_167, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
 
    uint32_t widthGreaterThantheRange = 1280;
    uint32_t heightGreaterThantheRange = 720;
    Size size = { widthGreaterThantheRange, heightGreaterThantheRange };
    std::vector<int32_t> framerates = {60, 60};
    VideoProfile profile(CAMERA_FORMAT_YUV_420_SP, size, framerates);

    sptr<CaptureOutput> output = nullptr;
    sptr<MovieFileOutput> movieFileOutput = nullptr;
    cameraManager_->CreateMovieFileOutput(profile, &movieFileOutput);
    ASSERT_NE(movieFileOutput, nullptr);

    output = movieFileOutput;
    EXPECT_EQ(session->ConfigureMovieFileOutput(output), 0);

    sptr<UnifyMovieFileOutput> unifyMovieFileOutput = nullptr;
    cameraManager_->CreateMovieFileOutput(profile, &unifyMovieFileOutput);
    ASSERT_NE(unifyMovieFileOutput, nullptr);

    output = movieFileOutput;
    EXPECT_EQ(session->ConfigureUnifyMovieFileOutput(output), 0);

}


/*
 * Feature: Framework
 * Function: Test captureSession with CanAddOutput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CanAddOutput for branches of movie file
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_168, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    uint32_t widthGreaterThantheRange = 1280;
    uint32_t heightGreaterThantheRange = 720;
    Size size = { widthGreaterThantheRange, heightGreaterThantheRange };
    std::vector<int32_t> framerates = {60, 60};
    VideoProfile profile(CAMERA_FORMAT_YUV_420_SP, size, framerates);

    sptr<MovieFileOutput> movieFileOutput = nullptr;
    cameraManager_->CreateMovieFileOutput(profile, &movieFileOutput);
    ASSERT_NE(movieFileOutput, nullptr);

    sptr<CaptureOutput> output = movieFileOutput;

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(output), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    EXPECT_NE(input->GetCameraDeviceInfo(), nullptr);
    session->SetInputDevice(input);
    EXPECT_NE(session->GetInputDevice()->GetCameraDeviceInfo(), nullptr);
    movieFileOutput->outputType_ = CAPTURE_OUTPUT_TYPE_MOVIE_FILE;
    EXPECT_FALSE(session->CanAddOutput(output));

    input->Close();
    output->Release();
    input->Release();
    session->Release();
}


/*
 * Feature: Framework
 * Function: Test captureSession with CanAddOutput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CanAddOutput for branches of unified movie file
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_169, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    uint32_t widthGreaterThantheRange = 1280;
    uint32_t heightGreaterThantheRange = 720;
    Size size = { widthGreaterThantheRange, heightGreaterThantheRange };
    std::vector<int32_t> framerates = {60, 60};
    VideoProfile profile(CAMERA_FORMAT_YUV_420_SP, size, framerates);

    sptr<UnifyMovieFileOutput> unifyMovieFileOutput = nullptr; 
    cameraManager_->CreateMovieFileOutput(profile, &unifyMovieFileOutput);
    ASSERT_NE(unifyMovieFileOutput, nullptr);

    sptr<CaptureOutput> output = unifyMovieFileOutput;

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(output), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    EXPECT_NE(input->GetCameraDeviceInfo(), nullptr);
    session->SetInputDevice(input);
    EXPECT_NE(session->GetInputDevice()->GetCameraDeviceInfo(), nullptr);
    unifyMovieFileOutput->outputType_ = CAPTURE_OUTPUT_TYPE_UNIFY_MOVIE_FILE;
    EXPECT_FALSE(session->CanAddOutput(output));

    input->Close();
    output->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with SetFocusTrackingMode and GetFocusTrackingMode when not Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetFocusTrackingMode and GetFocusTrackingMode when not Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_045, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    FocusTrackingMode focusTrackingMode = FOCUS_TRACKING_MODE_AUTO;
    EXPECT_EQ(session->SetFocusTrackingMode(focusTrackingMode),
        CameraErrorCode::SESSION_NOT_CONFIG);
    EXPECT_EQ(session->GetFocusTrackingMode(focusTrackingMode),
        CameraErrorCode::SESSION_NOT_CONFIG);

    input->Close();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with SetFocusTrackingMode and GetFocusTrackingMode when Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetFocusTrackingMode and GetFocusTrackingMode when Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_046, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);
    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);
    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);
    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    FocusTrackingMode focusTrackingMode = FOCUS_TRACKING_MODE_AUTO;
    EXPECT_EQ(session->SetFocusTrackingMode(focusTrackingMode), 0);
    EXPECT_EQ(session->GetFocusTrackingMode(focusTrackingMode), 0);

    input->Close();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with GetSupportedFocusTrackingModes and IsFocusTrackingModeSupported when not Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSupportedFocusTrackingModes and IsFocusTrackingModeSupported when not Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_047, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    std::vector<FocusTrackingMode> getSupportedFocusTrackingModes;
    EXPECT_EQ(session->GetSupportedFocusTrackingModes(getSupportedFocusTrackingModes),
        CameraErrorCode::SESSION_NOT_CONFIG);

    FocusTrackingMode focusTrackingMode = FOCUS_TRACKING_MODE_AUTO;
    bool isSupported;
    EXPECT_EQ(session->IsFocusTrackingModeSupported(focusTrackingMode, isSupported),
        CameraErrorCode::SESSION_NOT_CONFIG);

    input->Close();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with GetSupportedFocusTrackingModes and IsFocusTrackingModeSupported when Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSupportedFocusTrackingModes and IsFocusTrackingModeSupported when Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_048, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);
    ret = session->AddInput(input);
    EXPECT_EQ(ret, 0);
    ret = session->AddOutput(photo);
    EXPECT_EQ(ret, 0);
    ret = session->CommitConfig();
    EXPECT_EQ(ret, 0);

    std::vector<FocusTrackingMode> getSupportedFocusTrackingModes;
    EXPECT_EQ(session->GetSupportedFocusTrackingModes(getSupportedFocusTrackingModes), 0);

    FocusTrackingMode focusTrackingMode = FOCUS_TRACKING_MODE_AUTO;
    bool isSupported;
    EXPECT_EQ(session->IsFocusTrackingModeSupported(focusTrackingMode, isSupported), 0);

    input->Close();
    session->Release();
}
/*
 * Feature: Framework
 * Function: Test PressureStatusCallback.
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test PressureStatusCallback.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_049, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
 
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }
 
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);
 
    std::shared_ptr<PressureStatusCallback> pressureStatusCallback = std::make_shared<PressureStatusCallback>();
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
 
    EXPECT_EQ(session->GetPressureCallback(), nullptr);
    EXPECT_EQ(session->GetControlCenterEffectCallback(), nullptr);
 
    input->Close();
    session->Release();
}
 
/*
 * Feature: Framework
 * Function: Test GetSupportedFocusRangeTypes.
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSupportedFocusRangeTypes.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_050, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
 
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }
 
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);
 
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
 
    std::vector<FocusRangeType>types;
    std::vector<FocusDrivenType>types2;
    EXPECT_NE(session->GetSupportedFocusRangeTypes(types), 0);
    EXPECT_NE(session->GetSupportedFocusDrivenTypes(types2), 0);
 
    input->Close();
    session->Release();
}
 
/*
 * Feature: Framework
 * Function: Test Process.
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Process.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_051, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
 
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }
 
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);
 
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    std::shared_ptr<OHOS::Camera::CameraMetadata> result = std::make_shared<OHOS::Camera::CameraMetadata>(1, 1);
    uint64_t timestamp = 0;
    session->OnResultReceived(result);
    session->ProcessAutoFocusUpdates(result);
    session->ProcessMacroStatusChange(result);
    session->ProcessMoonCaptureBoostStatusChange(result);
    session->ProcessLowLightBoostStatusChange(result);
    session->ProcessSnapshotDurationUpdates(timestamp, result);
    session->ProcessAREngineUpdates(timestamp, result);
    session->ProcessEffectSuggestionTypeUpdates(result);
    session->ProcessLcdFlashStatusUpdates(result);
    session->ProcessTripodStatusChange(result);
    session->ProcessCompositionPositionCalibration(result);
    session->ProcessCompositionBegin(result);
    session->ProcessCompositionEnd(result);
    session->ProcessCompositionPositionMatch(result);
    EXPECT_NE(session, nullptr);
 
    input->Close();
    session->Release();
}
 

 /*
 * Feature: Framework
 * Function: Test Enable.
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Enable.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_052, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
 
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }
 
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);
 
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    session->SetHasFitedRotation(false);
    EXPECT_NE(session->EnableConstellationDrawing(false), 0);
    session->EnableOfflinePhoto();
    EXPECT_NE(session->EnableLogAssistance(false), 0);
    session->EnableAutoFrameRate(false);
    EXPECT_NE(session->EnableImageStabilizationGuide(false), 0);
    session->EnableKeyFrameReport(false);
 
    input->Close();
    session->Release();
}
 
/*
 * Feature: Framework
 * Function: Test GetIsAutoSwitchDeviceStatus.
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetIsAutoSwitchDeviceStatus.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_053, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
 
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }
 
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);
 
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    session->SetIsAutoSwitchDeviceStatus(false);
    EXPECT_EQ(session->GetIsAutoSwitchDeviceStatus(), false);
 
    input->Close();
    session->Release();
}
 
/*
 * Feature: Framework
 * Function: Test SetApertureEffectChangeCallback.
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetApertureEffectChangeCallback.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_054, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
 
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }
 
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);
 
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    std::shared_ptr<ApertureEffectChangeCallback> apertureEffectChangeCb = nullptr;
    session->SetApertureEffectChangeCallback(apertureEffectChangeCb);
    EXPECT_EQ(session->apertureEffectChangeCallback_, nullptr);
 
    input->Close();
    session->Release();
}
 
/*
 * Feature: Framework
 * Function: Test SetApertureEffectChangeCallback.
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetApertureEffectChangeCallback.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_055, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
 
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }
 
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);
 
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    std::shared_ptr<OHOS::Camera::CameraMetadata> result = std::make_shared<OHOS::Camera::CameraMetadata>(1, 1);
    session->ProcessApertureEffectChange(result);
    std::vector<int32_t> supportedVideoCodecTypes;
    EXPECT_EQ(session->GetSupportedVideoCodecTypes(supportedVideoCodecTypes), 0);
 
    input->Close();
    session->Release();
}
 
/*
 * Feature: Framework
 * Function: Test function GetMinimumFocusDistance.
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test function GetMinimumFocusDistance.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_057, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
 
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }
 
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);
 
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    EXPECT_EQ(session->GetMinimumFocusDistance(), 0);
 
    input->Close();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test GetPressureCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetPressureCallback
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_058, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    auto pressureCallBack = session->GetPressureCallback();
    EXPECT_EQ(pressureCallBack, nullptr);

    session->Release();
}

/*
 * Feature: Framework
 * Function: Test function IsControlCenterSupported
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test functionIsControlCenterSupported
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_059, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    bool ret = session->IsControlCenterSupported();
    EXPECT_NE(ret, true);

    session->Release();
}

/*
 * Feature: Framework
 * Function: Test function GetSupportedEffectTypes
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test function GetSupportedEffectTypes
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_060, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    std::vector<ControlCenterEffectType> controlCenterEffectType;
    controlCenterEffectType = session->GetSupportedEffectTypes();
    EXPECT_EQ(controlCenterEffectType.size(), 0);

    session->Release();
}

/*
 * Feature: Framework
 * Function: Test get types
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get types
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_061, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    std::vector<NightSubMode> nightSubMode;
    nightSubMode = session->GetSupportedNightSubModeTypes();
    EXPECT_EQ(nightSubMode.size(), 0);

    session->Release();
}

/*
 * Feature: Framework
 * Function: Test function GetSupportedVideoCodecTypes
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test function GetSupportedVideoCodecTypes
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_062, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    std::vector<int32_t> supportedVideoCodecTypes;
    int ret = session->GetSupportedVideoCodecTypes(supportedVideoCodecTypes);
    EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
    EXPECT_EQ(supportedVideoCodecTypes.size(), 2);

    session->Release();
}

/*
 * Feature: Framework
 * Function: Test function ProcessApertureEffectChange
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test function ProcessApertureEffectChange
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_063, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_NE(session->GetInputDevice(), nullptr);
    EXPECT_NE(session->GetInputDevice()->GetCameraDeviceInfo(), nullptr);

    auto deviceInfo = session->GetInputDevice()->GetCameraDeviceInfo();
    shared_ptr<OHOS::Camera::CameraMetadata> metadata = deviceInfo->GetMetadata();
    session->ProcessApertureEffectChange(metadata);

    input->Close();
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test EnableLogAssistance without commit config
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EnableLogAssistance without commit config
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_064, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->EnableLogAssistance(true);
    EXPECT_EQ(ret, CameraErrorCode::SESSION_NOT_CONFIG);

    session->Release();
}

/*
 * Feature: Framework
 * Function: Test EnableImageStabilizationGuide without commit config
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test function EnableImageStabilizationGuide without commit config
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_065, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->EnableImageStabilizationGuide(true);
    EXPECT_EQ(ret, CameraErrorCode::SESSION_NOT_CONFIG);

    session->Release();
}

/*
 * Feature: Framework
 * Function: Test EnableLogAssistance success
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EnableLogAssistance success
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_066, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    EXPECT_NE(session->currentMode_, SceneMode::CAPTURE);
    EXPECT_TRUE(session->IsSessionCommited());

    int32_t ret = session->EnableLogAssistance(true);
    EXPECT_EQ(ret, CameraErrorCode::SUCCESS);

    input->Close();
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test EnableImageStabilizationGuide success
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EnableImageStabilizationGuide success
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_067, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    EXPECT_NE(session->currentMode_, SceneMode::CAPTURE);
    EXPECT_TRUE(session->IsSessionCommited());

    int32_t ret = session->EnableImageStabilizationGuide(true);
    EXPECT_EQ(ret, CameraErrorCode::SUCCESS);

    input->Close();
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test OnPressureStatusChanged.
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnPressureStatusChanged.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_058, TestSize.Level0)
{
    std::shared_ptr<PressureStatusCallback> callback = std::make_shared<PressureStatusCallback>();
    EXPECT_EQ(callback->OnPressureStatusChanged(PressureStatus::SYSTEM_PRESSURE_NORMAL), 0);
}
 
/*
 * Feature: Framework
 * Function: Test IsControlCenterSupported.
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsControlCenterSupported.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_059, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
 
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }
 
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);
 
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    session->IsControlCenterSupported();
    std::vector<ControlCenterEffectType>res = session->GetSupportedEffectTypes();
    session->EnableControlCenter(false);
    if (session->isControlCenterEnabled_ == false) {
        EXPECT_EQ(session->isControlCenterEnabled_, false);
    }
    input->Close();
    session->Release();
}
 
/*
 * Feature: Framework
 * Function: Test GetSupportedNightSubModeTypes.
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSupportedNightSubModeTypes.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_060, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
 
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }
 
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);
 
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    std::vector<NightSubMode> res = session->GetSupportedNightSubModeTypes();
    EXPECT_EQ(res.size(), 0);
}
 
/*
 * Feature: Framework
 * Function: Test AreVectorsEqual.
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AreVectorsEqual.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_061, TestSize.Level0)
{
    std::vector<float> a;
    std::vector<float> b;
    bool ret = CalculationHelper::AreVectorsEqual(a, b);
    EXPECT_EQ(ret, true);
}

/*
 * Feature: Framework
 * Function: Test GetSupportedColorEffects.
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSupportedColorEffects.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_072, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
 
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }
 
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);
 
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    std::vector<int32_t> sensitivityRange;
    session->GetSupportedColorEffects();
    EXPECT_NE(session->GetSensorSensitivityRange(sensitivityRange), 0);
    uint32_t moduleType = 0;
    EXPECT_NE(session->GetModuleType(moduleType), 0);
}

/*
 * Feature: Framework
 * Function: Test EnableControlCenter 
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EnableControlCenter 
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_073, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    session->EnableControlCenter(true);
    EXPECT_EQ(session->isControlCenterEnabled_, false);
    session->EnableKeyFrameReport(true);
    session->EnableKeyFrameReport(false);

    input->Close();
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test SetCameraSwitchRequestCallback with nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetCameraSwitchRequestCallback with nullptr
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_074, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    std::shared_ptr<CameraSwitchRequestCallback> callback = nullptr;
    session->SetCameraSwitchRequestCallback(callback);
    EXPECT_EQ(session->GetCameraSwitchRequestCallback(), callback);
}

/*
 * Feature: Framework
 * Function: Test SetCameraSwitchRequestCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetCameraSwitchRequestCallback
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_075, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    auto callback =
        std::make_shared<MockCameraSwitchRequestCallback>();
    session->SetCameraSwitchRequestCallback(callback);
    ASSERT_NE(session->GetCameraSwitchRequestCallback(), nullptr);
    EXPECT_EQ(session->GetCameraSwitchRequestCallback(), callback);
}

/*
 * Feature: Framework
 * Function: Test UnSetCameraSwitchRequestCallback after set callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UnSetCameraSwitchRequestCallback after set callback
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_076, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    std::shared_ptr<CameraSwitchRequestCallback> callback =
        std::make_shared<MockCameraSwitchRequestCallback>();
    session->SetCameraSwitchRequestCallback(callback);
    ASSERT_NE(session->GetCameraSwitchRequestCallback(), nullptr);
    session->UnSetCameraSwitchRequestCallback();
    EXPECT_EQ(session->GetCameraSwitchRequestCallback(), nullptr);
}

/*
 * Feature: Framework
 * Function: Test OnPressureStatusChanged when the session is not nullptr and PressureCallback is nullptr
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnPressureStatusChanged when the session is not nullptr and PressureCallback is nullptr
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_077, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    std::shared_ptr<PressureStatusCallback> pressureStatusCallback = std::make_shared<PressureStatusCallback>(session);
    EXPECT_NE(pressureStatusCallback->captureSession_, nullptr);
    EXPECT_EQ(session->GetPressureCallback(), nullptr);
    EXPECT_EQ(pressureStatusCallback->OnPressureStatusChanged(PressureStatus::SYSTEM_PRESSURE_NORMAL), 0);
}

/*
 * Feature: Framework
 * Function: Test OnPressureStatusChanged when the session and PressureCallback are not nullptr
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnPressureStatusChanged when the session and PressureCallback are not nullptr
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_078, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    std::shared_ptr<PressureStatusCallback> pressureStatusCallback = std::make_shared<PressureStatusCallback>(session);
    EXPECT_NE(pressureStatusCallback->captureSession_, nullptr);

    std::shared_ptr<PressureCallback> pressureCallback = std::make_shared<AppPressureStatusCallback>();
    session->SetPressureCallback(pressureCallback);
    EXPECT_NE(session->GetPressureCallback(), nullptr);

    EXPECT_EQ(pressureStatusCallback->OnPressureStatusChanged(PressureStatus::SYSTEM_PRESSURE_NORMAL), 0);
}

/*
 * Feature: Framework
 * Function: Test  OnControlCenterEffectStatusChanged when session is nullptr.
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnControlCenterEffectStatusChanged when session is nullptr.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_079, TestSize.Level0)
{
    std::shared_ptr<ControlCenterEffectStatusCallback> callback = std::make_shared<ControlCenterEffectStatusCallback>();
    ControlCenterStatusInfo info = { ControlCenterEffectType::BEAUTY, true };
    EXPECT_EQ(callback->OnControlCenterEffectStatusChanged(info), 0);
}

/*
 * Feature: Framework
 * Function: Test FoldCallback with OnFoldStatusChanged
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnFoldStatusChanged when the session not is nullptr
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_080, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    auto foldCallback = std::make_shared<FoldCallback>(session);
    FoldStatus status = FoldStatus::UNKNOWN_FOLD;
    auto ret = foldCallback->OnFoldStatusChanged(status);
    EXPECT_EQ(ret, CAMERA_OPERATION_NOT_ALLOWED);

    std::shared_ptr<FoldCallback> foldCallback1 = std::make_shared<FoldCallback>(nullptr);
    EXPECT_EQ(foldCallback1->captureSession_, nullptr);
}

/*
 * Feature: Framework
 * Function: Test CameraSwitchCallback
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CameraSwitchCallback
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_081, TestSize.Level0)
{
    sptr<CameraSwitchSession> session = cameraManager_->CreateCameraSwitchSession();
    ASSERT_NE(session, nullptr);
 
    auto cameraSwitchCallback = std::make_shared<MockCameraSwitchCallback>();
    EXPECT_NE(cameraSwitchCallback, nullptr);

    session->SetCallback(cameraSwitchCallback);
    EXPECT_EQ(session->GetCameraSwitchCallback(), cameraSwitchCallback);

    auto cameraSwitchCallbackImpl = std::make_shared<CameraSwitchCallbackImpl>(session);
    EXPECT_NE(cameraSwitchCallbackImpl, nullptr);

    std::string cameraID = "";
    CaptureSessionInfo captureSessionInfo{};
    EXPECT_EQ(CAMERA_OK,cameraSwitchCallbackImpl->OnCameraActive(cameraID,true,captureSessionInfo));
    EXPECT_EQ(CAMERA_OK,cameraSwitchCallbackImpl->OnCameraUnactive(cameraID));
    EXPECT_EQ(CAMERA_OK,cameraSwitchCallbackImpl->OnCameraSwitch(cameraID,cameraID,true));
}

/*
 * Feature: Framework
 * Function: Test SetFocusDistance when session is not configured
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetFocusDistance when session is not configured
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_082, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->SetFocusDistance(0.5);
    EXPECT_EQ(CameraErrorCode::SESSION_NOT_CONFIG, ret);
}

/*
 * Feature: Framework
 * Function: Test GetSupportedFocusTrackingModes when session is not configured
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSupportedFocusTrackingModes when session is not configured
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_083, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    std::vector<FocusTrackingMode> supportedFocusTrackingModes = {};
    int32_t ret = session->GetSupportedFocusTrackingModes(supportedFocusTrackingModes);
    EXPECT_EQ(CameraErrorCode::SESSION_NOT_CONFIG, ret);
}

/*
 * Feature: Framework
 * Function: Test IsFocusTrackingModeSupported when session is not configured
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsFocusTrackingModeSupported when session is not configured
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_084, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    FocusTrackingMode focusTrackingMode = FocusTrackingMode::FOCUS_TRACKING_MODE_AUTO;
    bool isSupported = true;

    int32_t ret = session->IsFocusTrackingModeSupported(focusTrackingMode, isSupported);
    EXPECT_EQ(CameraErrorCode::SESSION_NOT_CONFIG, ret);
}

/*
 * Feature: Framework
 * Function: Test GetFocusTrackingMode when session is not configured
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetFocusTrackingMode when session is not configured
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_085, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    FocusTrackingMode focusTrackingMode;

    int32_t ret = session->GetFocusTrackingMode(focusTrackingMode);
    EXPECT_EQ(CameraErrorCode::SESSION_NOT_CONFIG, ret);
}

/*
 * Feature: Framework
 * Function: Test SetFocusTrackingMode when session is not configured
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetFocusTrackingMode when session is not configured
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_086, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    FocusTrackingMode focusTrackingMode = FocusTrackingMode::FOCUS_TRACKING_MODE_AUTO;

    int32_t ret = session->SetFocusTrackingMode(focusTrackingMode);
    EXPECT_EQ(CameraErrorCode::SESSION_NOT_CONFIG, ret);
}

/*
 * Feature: Framework
 * Function: Test GetFocusDistance when session is not configured
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetFocusDistance when session is not configured
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_087, TestSize.Level0)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);

    float distance;
    int32_t ret = sessionForSys->GetFocusDistance(distance);
    EXPECT_EQ(CameraErrorCode::SESSION_NOT_CONFIG, ret);
}

/*
 * Feature: Framework
 * Function: Test IsStageBoostSupported when session is not configured
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsStageBoostSupported when session is not configured
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_088, TestSize.Level0)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);

    bool ret = sessionForSys->IsStageBoostSupported();
    EXPECT_EQ(false, ret);
}

/*
 * Feature: Framework
 * Function: Test EnableStageBoost when session is not configured
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EnableStageBoost when session is not configured
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_089, TestSize.Level0)
{
    sptr<CaptureSessionForSys> sessionForSys = cameraManagerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys, nullptr);

    bool isEnable = true;
    int32_t ret = sessionForSys->EnableStageBoost(isEnable);
    EXPECT_EQ(CameraErrorCode::OPERATION_NOT_ALLOWED, ret);
}

/*
 * Feature: Framework
 * Function: Test SetFocusDistance after the session is configured
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetFocusDistance after the session is configured
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_090, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    session->LockForControl();
    EXPECT_NE(session->changedMetadata_, nullptr);

    int32_t ret = session->SetFocusDistance(0.5);
    EXPECT_EQ(CameraErrorCode::SUCCESS, ret);
    EXPECT_EQ(0.5, session->focusDistance_);

    ret = session->SetFocusDistance(2);
    EXPECT_EQ(CameraErrorCode::SUCCESS, ret);
    EXPECT_EQ(1, session->focusDistance_);

    ret = session->SetFocusDistance(-1);
    EXPECT_EQ(CameraErrorCode::SUCCESS, ret);
    EXPECT_EQ(0, session->focusDistance_);
}

/*
 * Feature: Framework
 * Function: Test CameraSwitchSessionCallback.
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CameraSwitchSessionCallback.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_091, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    std::shared_ptr<CameraSwitchSessionCallback> cameraSwitchSessionCallback = std::make_shared<CameraSwitchSessionCallback>();
    EXPECT_EQ(cameraSwitchSessionCallback->captureSession_, nullptr);
    EXPECT_EQ(session->GetCameraSwitchRequestCallback(), nullptr);

    string cameraId = cameras_[0]->GetID();
    CaptureSessionInfo sessionInfo;
    EXPECT_EQ(cameraSwitchSessionCallback->OnCameraActive(cameraId, false, sessionInfo), 0);
    EXPECT_EQ(cameraSwitchSessionCallback->OnCameraUnactive(cameraId), 0);
    EXPECT_EQ(cameraSwitchSessionCallback->OnCameraSwitch(cameraId, cameraId, false), 0);
}

/*
 * Feature: Framework
 * Function: Test CameraSwitchSessionCallback when the session is not nullptr and CameraSwitchRequestCallback is nullptr
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CameraSwitchSessionCallback when the session is not nullptr and CameraSwitchRequestCallback is nullptr
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_092, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    std::shared_ptr<CameraSwitchSessionCallback> cameraSwitchSessionCallback = std::make_shared<CameraSwitchSessionCallback>(session);
    EXPECT_NE(cameraSwitchSessionCallback->captureSession_, nullptr);
    EXPECT_EQ(session->GetCameraSwitchRequestCallback(), nullptr);

    string cameraId = cameras_[0]->GetID();
    CaptureSessionInfo sessionInfo;
    EXPECT_EQ(cameraSwitchSessionCallback->OnCameraActive(cameraId, false, sessionInfo), 0);
    EXPECT_EQ(cameraSwitchSessionCallback->OnCameraUnactive(cameraId), 0);
    EXPECT_EQ(cameraSwitchSessionCallback->OnCameraSwitch(cameraId, cameraId, false), 0);
     
    input->Close();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CameraSwitchSessionCallback when the session is not nullptr and CameraSwitchRequestCallback is nullptr
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CameraSwitchSessionCallback when the session is not nullptr and CameraSwitchRequestCallback is nullptr
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_093, TestSize.Level0)
{
    auto cameraInput = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_TRUE(DisMdmOpenCheck(cameraInput));
    sptr<CaptureInput> input = cameraInput;
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdateCameraOutputCapability();
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    std::shared_ptr<CameraSwitchSessionCallback> cameraSwitchSessionCallback = std::make_shared<CameraSwitchSessionCallback>(session);
    EXPECT_NE(cameraSwitchSessionCallback->captureSession_, nullptr);

    std::shared_ptr<CameraSwitchRequestCallback> cameraSwitchRequestCallback = std::make_shared<MockCameraSwitchRequestCallback>();;
    session->SetCameraSwitchRequestCallback(cameraSwitchRequestCallback);
    EXPECT_NE(session->GetCameraSwitchRequestCallback(), nullptr);

    string cameraId = cameras_[0]->GetID();
    CaptureSessionInfo sessionInfo;
    EXPECT_EQ(cameraSwitchSessionCallback->OnCameraActive(cameraId, false, sessionInfo), 0);
    EXPECT_EQ(cameraSwitchSessionCallback->OnCameraUnactive(cameraId), 0);
    EXPECT_EQ(cameraSwitchSessionCallback->OnCameraSwitch(cameraId, cameraId, false), 0);
     
    input->Close();
    session->Release();
}
}
}