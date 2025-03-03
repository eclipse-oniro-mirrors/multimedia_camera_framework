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
#include "picture.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
struct TestObject {};

void CaptureSessionUnitTest::SessionControlParams(sptr<CaptureSession> session)
{
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

void CaptureSessionUnitTest::UpdataCameraOutputCapability(int32_t modeName)
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

void CaptureSessionUnitTest::SetUpTestCase(void) {}

void CaptureSessionUnitTest::TearDownTestCase(void) {}

void CaptureSessionUnitTest::SetUp()
{
    NativeAuthorization();
    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);
    cameras_ = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras_.empty());
}

void CaptureSessionUnitTest::TearDown()
{
    cameraManager_ = nullptr;
    cameras_.clear();
}

void CaptureSessionUnitTest::NativeAuthorization()
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
    MEDIA_DEBUG_LOG("CaptureSessionUnitTest::NativeAuthorization uid:%{public}d", uid_);
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

/*
 * Feature: Framework
 * Function: Test captureSession with GetSessionFunctions
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSessionFunctions for inputDevice is nullptr
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_001, TestSize.Level0)
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_002, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession(SceneMode::CAPTURE);
    ASSERT_NE(session, nullptr);
    EXPECT_TRUE(session->CheckFrameRateRangeWithCurrentFps(20, 20, 40, 40));
    EXPECT_TRUE(session->CheckFrameRateRangeWithCurrentFps(40, 40, 20, 20));
}

/*
 * Feature: Framework
 * Function: Test captureSession with GetMaxSizePhotoProfile
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetMaxSizePhotoProfile for SceneMode is NORMAL
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_003, TestSize.Level0)
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_004, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_006, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_007, TestSize.Level0)
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_008, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_009, TestSize.Level0)
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_010, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_011, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdataCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_FALSE(session->IsDepthFusionSupported());

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_FALSE(session->IsDepthFusionSupported());

    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    EXPECT_NE(session->GetInputDevice(), nullptr);
    EXPECT_NE(session->GetInputDevice()->GetCameraDeviceInfo(), nullptr);
    EXPECT_FALSE(session->IsDepthFusionSupported());

    session->SetInputDevice(nullptr);
    EXPECT_FALSE(session->IsDepthFusionSupported());

    input->Close();
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession with GetDepthFusionThreshold
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetDepthFusionThreshold for abnormal branches
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_012, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdataCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    std::vector<float> depthFusionThreshold = {};
    EXPECT_EQ(session->GetDepthFusionThreshold(depthFusionThreshold), CameraErrorCode::SESSION_NOT_CONFIG);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    EXPECT_NE(session->GetInputDevice(), nullptr);
    EXPECT_NE(session->GetInputDevice()->GetCameraDeviceInfo(), nullptr);
    EXPECT_EQ(session->GetDepthFusionThreshold(depthFusionThreshold), CameraErrorCode::SUCCESS);

    session->SetInputDevice(nullptr);
    EXPECT_EQ(session->GetDepthFusionThreshold(depthFusionThreshold), CameraErrorCode::SUCCESS);

    input->Close();
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession with EnableDepthFusion
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EnableDepthFusion for IsDepthFusionSupported is false
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_013, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    bool isEnable = true;
    EXPECT_EQ(session->EnableDepthFusion(isEnable), CameraErrorCode::OPERATION_NOT_ALLOWED);

    session->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession with IsLowLightBoostSupported
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsLowLightBoostSupported for abnormal branches
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_014, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_015, TestSize.Level0)
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_016, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_017, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_018, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_019, TestSize.Level0)
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_020, TestSize.Level0)
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_021, TestSize.Level0)
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_022, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_023, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_024, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_025, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_026, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdataCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    session->LockForControl();
    bool isEnable = true;
    EXPECT_EQ(session->EnableLcdFlash(isEnable), CameraErrorCode::SUCCESS);

    session->UnlockForControl();
    input->Close();
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession with EnableFaceDetection
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EnableFaceDetection for enable is false
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_027, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_001, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_002, TestSize.Level0)
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
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_003, TestSize.Level0)
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
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_004, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    int32_t ret = session->BeginConfig();
    EXPECT_EQ(ret, 0);
    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_005, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

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
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_006, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_007, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_008, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_009, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    std::vector<float> zoomRatioRange = session->GetZoomRatioRange();
    if (!zoomRatioRange.empty()) {
        session->LockForControl();
        session->SetZoomRatio(zoomRatioRange[0]);
        session->UnlockForControl();
    }

    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_010, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    UpdataCameraOutputCapability();

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
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_011, TestSize.Level0)
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
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_012, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_013, TestSize.Level0)
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
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_014, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

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
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_015, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_016, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_017, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_018, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_019, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdataCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);
    auto macroStatusCallback = std::make_shared<AppMacroStatusCallback>();

    EXPECT_EQ(session->GetColorEffect(), COLOR_EFFECT_NORMAL);
    EXPECT_EQ(session->EnableMacro(true), OPERATION_NOT_ALLOWED);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);

    EXPECT_EQ(session->CommitConfig(), 0);
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras_[0]->GetMetadata();
    EXPECT_EQ(session->GetColorEffect(), COLOR_EFFECT_NORMAL);

    ((sptr<CameraInput>&)(session->innerInputDevice_))->cameraObj_ = nullptr;
    EXPECT_EQ(session->GetColorEffect(), COLOR_EFFECT_NORMAL);
    EXPECT_EQ(session->IsMacroSupported(), false);
    session->innerInputDevice_ = nullptr;
    EXPECT_EQ(session->GetColorEffect(), COLOR_EFFECT_NORMAL);
    EXPECT_EQ(session->IsMacroSupported(), false);
    EXPECT_EQ(session->EnableMacro(true), OPERATION_NOT_ALLOWED);

    session->LockForControl();
    session->SetColorEffect(COLOR_EFFECT_NORMAL);
    session->UnlockForControl();

    session->macroStatusCallback_ = macroStatusCallback;
    session->ProcessMacroStatusChange(metadata);

    EXPECT_EQ(preview->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
    EXPECT_EQ(session->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test !IsSessionConfiged() || input == nullptr in CanAddInput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test !IsSessionConfiged() || input == nullptr in CanAddInput
 */
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_020, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    sptr<CaptureInput> input1 = nullptr;
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_021, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_022, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_023, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_024, TestSize.Level0)
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
HWTEST_F(CaptureSessionUnitTest, camera_framework_unittest_025, TestSize.Level0)
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_001, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(surface, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_002, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_003, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_004, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_005, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_006, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_007, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_008, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_009, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_010, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_011, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_012, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_013, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_014, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_015, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_016, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_017, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_018, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_019, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_020, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_021, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_022, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_023, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

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
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_024, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_025, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_026, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    UpdataCameraOutputCapability();
    sptr<CaptureOutput> photo = CreatePhotoOutput(photoProfile_[0]);
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    std::vector<ZoomPointInfo> zoomPointInfoList;
    EXPECT_EQ(session->GetZoomPointInfos(zoomPointInfoList), CameraErrorCode::SESSION_NOT_CONFIG);

    session->RemoveInput(input);
    session->RemoveOutput(photo);
    photo->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with GetZoomPointInfos when Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with GetZoomPointInfos when Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_027, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    UpdataCameraOutputCapability();
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

    std::vector<ZoomPointInfo> zoomPointInfoList;
    EXPECT_EQ(session->GetZoomPointInfos(zoomPointInfoList), 0);

    session->RemoveInput(input);
    session->RemoveOutput(photo);
    photo->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with GetSupportedFilters and GetFilter and SetFilter when not Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with GetSupportedFilters and GetFilter and SetFilter when not Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_028, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_029, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_030, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdataCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    BeautyType beautyType = AUTO_TYPE;
    EXPECT_EQ(session->BeginConfig(), 0);
    session->SetBeauty(AUTO_TYPE, 0);
    EXPECT_EQ(session->GetBeauty(beautyType), -1);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);

    EXPECT_EQ(session->CommitConfig(), 0);
    session->SetBeauty(AUTO_TYPE, 0);
    EXPECT_EQ(session->GetBeauty(beautyType), -1);

    session->LockForControl();
    session->SetBeauty(SKIN_SMOOTH, 0);
    EXPECT_EQ(session->GetBeauty(beautyType), -1);
    session->UnlockForControl();

    EXPECT_EQ(preview->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
    EXPECT_EQ(session->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with SetBeauty and GetBeauty when not Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with SetBeauty and GetBeauty when not Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_031, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdataCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    BeautyType beautyType = AUTO_TYPE;
    session->SetBeauty(AUTO_TYPE, 0);
    EXPECT_EQ(session->GetBeauty(beautyType), CameraErrorCode::SESSION_NOT_CONFIG);

    EXPECT_EQ(preview->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
    EXPECT_EQ(session->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with SetColorSpace and GetActiveColorSpace when Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with SetColorSpace and GetActiveColorSpace when Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_032, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdataCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    ColorSpace colorSpace = DISPLAY_P3;
    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->SetColorSpace(colorSpace), 0);
    EXPECT_EQ(session->GetActiveColorSpace(colorSpace), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);

    EXPECT_EQ(session->CommitConfig(), 0);
    EXPECT_EQ(session->SetColorSpace(colorSpace), 0);
    EXPECT_EQ(session->GetActiveColorSpace(colorSpace), 0);

    session->LockForControl();
    EXPECT_EQ(session->SetColorSpace(colorSpace), 0);
    EXPECT_EQ(session->GetActiveColorSpace(colorSpace), 0);
    session->UnlockForControl();

    EXPECT_EQ(preview->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
    EXPECT_EQ(session->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test CaptureSession with SetColorSpace and GetActiveColorSpace when not Configed.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CaptureSession with SetColorSpace and GetActiveColorSpace when not Configed.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unit_033, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_034, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdataCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    std::vector<FocusRangeType> types;
    EXPECT_EQ(session->GetSupportedFocusRangeTypes(types), 0);
    if (!types.empty()) {
        bool isSupported = false;
        EXPECT_EQ(session->IsFocusRangeTypeSupported(types[0], isSupported), 0);
        if (isSupported) {
            session->LockForControl();
            EXPECT_EQ(session->SetFocusRange(types[0]), 0);
            session->UnlockForControl();
            FocusRangeType type = FOCUS_RANGE_TYPE_NEAR;
            EXPECT_EQ(session->GetFocusRange(type), types[0]);
        }
    }

    input->Close();
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession with SetFocusDriven
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetFocusDriven normal branches
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_035, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdataCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    std::vector<FocusDrivenType> types;
    EXPECT_EQ(session->GetSupportedFocusDrivenTypes(types), 0);
    if (!types.empty()) {
        bool isSupported = false;
        EXPECT_EQ(session->IsFocusDrivenTypeSupported(types[0], isSupported), 0);
        if (isSupported) {
            session->LockForControl();
            EXPECT_EQ(session->SetFocusDriven(types[0]), 0);
            session->UnlockForControl();
            FocusDrivenType type = FOCUS_DRIVEN_TYPE_FACE;
            EXPECT_EQ(session->GetFocusDriven(type), types[0]);
        }
    }

    input->Close();
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession with SetColorReservation
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetColorReservation normal branches
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_036, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdataCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    std::vector<ColorReservationType> types;
    EXPECT_EQ(session->GetSupportedColorReservationTypes(types), 0);
    if (!types.empty()) {
        bool isSupported = false;
        EXPECT_EQ(session->IsColorReservationTypeSupported(types[0], isSupported), 0);
        if (isSupported) {
            session->LockForControl();
            EXPECT_EQ(session->SetColorReservation(types[0]), 0);
            session->UnlockForControl();
            ColorReservationType type = COLOR_RESERVATION_TYPE_PORTRAIT;
            EXPECT_EQ(session->GetColorReservation(type), types[0]);
        }
    }

    input->Close();
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession abnormal branches before commit config
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureSession abnormal branches before commit config
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_037, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdataCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);

    FocusRangeType testType_1 = FOCUS_RANGE_TYPE_NEAR;
    bool isSupported = true;
    EXPECT_EQ(session->IsFocusRangeTypeSupported(testType_1, isSupported), CameraErrorCode::SESSION_NOT_CONFIG);
    EXPECT_EQ(session->GetFocusRange(testType_1), CameraErrorCode::SESSION_NOT_CONFIG);
    EXPECT_EQ(session->SetFocusRange(testType_1), CameraErrorCode::SESSION_NOT_CONFIG);

    FocusDrivenType testType_2 = FOCUS_DRIVEN_TYPE_FACE;
    EXPECT_EQ(session->IsFocusDrivenTypeSupported(testType_2, isSupported), CameraErrorCode::SESSION_NOT_CONFIG);
    EXPECT_EQ(session->GetFocusDriven(testType_2), CameraErrorCode::SESSION_NOT_CONFIG);
    EXPECT_EQ(session->SetFocusDriven(testType_2), CameraErrorCode::SESSION_NOT_CONFIG);

    std::vector<ColorReservationType> testTypes_3;
    EXPECT_EQ(session->GetSupportedColorReservationTypes(testTypes_3), CameraErrorCode::SESSION_NOT_CONFIG);
    ColorReservationType testType_3 = COLOR_RESERVATION_TYPE_PORTRAIT;
    EXPECT_EQ(session->GetColorReservation(testType_3), CameraErrorCode::SESSION_NOT_CONFIG);
    EXPECT_EQ(session->SetColorReservation(testType_3), CameraErrorCode::SESSION_NOT_CONFIG);

    EXPECT_EQ(session->CommitConfig(), 0);

    input->Close();
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession with abnormal parameter
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureSession abnormal branches with abnormal parameter
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_038, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdataCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    int32_t num = -1;
    FocusRangeType testType_1 = static_cast<FocusRangeType>(num);
    bool isSupported = true;
    EXPECT_EQ(session->IsFocusRangeTypeSupported(testType_1, isSupported), CameraErrorCode::PARAMETER_ERROR);
    FocusDrivenType testType_2 = static_cast<FocusDrivenType>(num);
    EXPECT_EQ(session->IsFocusDrivenTypeSupported(testType_2, isSupported), CameraErrorCode::PARAMETER_ERROR);
    ColorReservationType testType_3 = static_cast<ColorReservationType>(num);
    EXPECT_EQ(session->IsColorReservationTypeSupported(testType_3, isSupported), CameraErrorCode::PARAMETER_ERROR);

    session->LockForControl();
    EXPECT_EQ(session->SetFocusRange(testType_1), CameraErrorCode::PARAMETER_ERROR);
    EXPECT_EQ(session->SetFocusDriven(testType_2), CameraErrorCode::PARAMETER_ERROR);
    EXPECT_EQ(session->SetColorReservation(testType_3), CameraErrorCode::PARAMETER_ERROR);
    session->UnlockForControl();

    input->Close();
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession abnormal branches without LockForControl
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureSession abnormal branches without LockForControl
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_039, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdataCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    FocusRangeType testType_1 = FOCUS_RANGE_TYPE_NEAR;
    EXPECT_EQ(session->SetFocusRange(testType_1), 0);
    FocusDrivenType testType_2 = FOCUS_DRIVEN_TYPE_FACE;
    EXPECT_EQ(session->SetFocusDriven(testType_2), 0);
    ColorReservationType testType_3 = COLOR_RESERVATION_TYPE_PORTRAIT;
    EXPECT_EQ(session->SetColorReservation(testType_3), 0);

    input->Close();
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test captureSession abnormal branches while camera device is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureSession abnormal branches while camera device is nulltptr
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_040, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdataCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    session->innerInputDevice_ = nullptr;
    std::vector<FocusRangeType> testTypes_1;
    EXPECT_EQ(session->GetSupportedFocusRangeTypes(testTypes_1), 0);
    FocusRangeType testType_1 = FOCUS_RANGE_TYPE_NEAR;
    EXPECT_EQ(session->GetFocusRange(testType_1), 0);

    std::vector<FocusDrivenType> testTypes_2;
    EXPECT_EQ(session->GetSupportedFocusDrivenTypes(testTypes_2), 0);
    FocusDrivenType testType_2 = FOCUS_DRIVEN_TYPE_FACE;
    EXPECT_EQ(session->GetFocusDriven(testType_2), 0);

    std::vector<ColorReservationType> testTypes_3;
    EXPECT_EQ(session->GetSupportedColorReservationTypes(testTypes_3), 0);
    ColorReservationType testType_3 = COLOR_RESERVATION_TYPE_PORTRAIT;
    EXPECT_EQ(session->GetColorReservation(testType_3), 0);

    input->Close();
    preview->Release();
    input->Release();
    session->Release();
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
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdataCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    std::vector<uint8_t> testTypes_1 = {OHOS_CAMERA_FOCUS_RANGE_AUTO, OHOS_CAMERA_FOCUS_RANGE_NEAR};
    ASSERT_NE(session->GetMetadata(), nullptr);
    OHOS::Camera::DeleteCameraMetadataItem(session->GetMetadata()->get(), OHOS_ABILITY_FOCUS_RANGE_TYPES);
    session->GetMetadata()->addEntry(OHOS_ABILITY_FOCUS_RANGE_TYPES, testTypes_1.data(), testTypes_1.size());
    std::vector<FocusRangeType> types_1;
    EXPECT_EQ(session->GetSupportedFocusRangeTypes(types_1), 0);

    uint8_t testType_1 = OHOS_CAMERA_FOCUS_RANGE_AUTO;
    OHOS::Camera::DeleteCameraMetadataItem(session->GetMetadata()->get(), OHOS_CONTROL_FOCUS_RANGE_TYPE);
    session->GetMetadata()->addEntry(OHOS_CONTROL_FOCUS_RANGE_TYPE, &testType_1, 1);
    FocusRangeType type_1 = FOCUS_RANGE_TYPE_NEAR;
    EXPECT_EQ(session->GetFocusRange(type_1), 0);

    std::vector<uint8_t> testTypes_2 = {OHOS_CAMERA_FOCUS_DRIVEN_AUTO, OHOS_CAMERA_FOCUS_DRIVEN_FACE};
    OHOS::Camera::DeleteCameraMetadataItem(session->GetMetadata()->get(), OHOS_ABILITY_FOCUS_DRIVEN_TYPES);
    session->GetMetadata()->addEntry(OHOS_ABILITY_FOCUS_DRIVEN_TYPES, testTypes_2.data(), testTypes_2.size());
    std::vector<FocusDrivenType> types_2;
    EXPECT_EQ(session->GetSupportedFocusDrivenTypes(types_2), 0);

    uint8_t testType_2 = OHOS_CAMERA_FOCUS_DRIVEN_AUTO;
    OHOS::Camera::DeleteCameraMetadataItem(session->GetMetadata()->get(), OHOS_CONTROL_FOCUS_DRIVEN_TYPE);
    session->GetMetadata()->addEntry(OHOS_CONTROL_FOCUS_DRIVEN_TYPE, &testType_2, 1);
    FocusDrivenType type_2 = FOCUS_DRIVEN_TYPE_FACE;
    EXPECT_EQ(session->GetFocusDriven(type_2), 0);

    std::vector<uint8_t> testTypes_3 = {OHOS_CAMERA_COLOR_RESERVATION_NONE, OHOS_CAMERA_COLOR_RESERVATION_PORTRAIT};
    OHOS::Camera::DeleteCameraMetadataItem(session->GetMetadata()->get(), OHOS_ABILITY_COLOR_RESERVATION_TYPES);
    session->GetMetadata()->addEntry(OHOS_ABILITY_COLOR_RESERVATION_TYPES, testTypes_3.data(), testTypes_3.size());
    std::vector<ColorReservationType> types_3;
    EXPECT_EQ(session->GetSupportedColorReservationTypes(types_3), 0);

    uint8_t testType_3 = OHOS_CAMERA_COLOR_RESERVATION_PORTRAIT;
    OHOS::Camera::DeleteCameraMetadataItem(session->GetMetadata()->get(), OHOS_CONTROL_COLOR_RESERVATION_TYPE);
    session->GetMetadata()->addEntry(OHOS_CONTROL_COLOR_RESERVATION_TYPE, &testType_3, 1);
    ColorReservationType type_3 = COLOR_RESERVATION_TYPE_PORTRAIT;
    EXPECT_EQ(session->GetColorReservation(type_3), 0);

    session->LockForControl();
    ASSERT_NE(session->changedMetadata_, nullptr);
    OHOS::Camera::DeleteCameraMetadataItem(session->changedMetadata_->get(), OHOS_CONTROL_FOCUS_RANGE_TYPE);
    EXPECT_EQ(session->SetFocusRange(type_1), 0);
    session->changedMetadata_->addEntry(OHOS_CONTROL_FOCUS_RANGE_TYPE, &testType_1, 1);
    EXPECT_EQ(session->SetFocusRange(type_1), 0);

    OHOS::Camera::DeleteCameraMetadataItem(session->changedMetadata_->get(), OHOS_CONTROL_FOCUS_DRIVEN_TYPE);
    EXPECT_EQ(session->SetFocusDriven(type_2), 0);
    session->changedMetadata_->addEntry(OHOS_CONTROL_FOCUS_DRIVEN_TYPE, &testType_2, 1);
    EXPECT_EQ(session->SetFocusDriven(type_2), 0);

    OHOS::Camera::DeleteCameraMetadataItem(session->changedMetadata_->get(), OHOS_CONTROL_COLOR_RESERVATION_TYPE);
    EXPECT_EQ(session->SetColorReservation(type_3), 0);
    session->changedMetadata_->addEntry(OHOS_CONTROL_COLOR_RESERVATION_TYPE, &testType_3, 1);
    EXPECT_EQ(session->SetColorReservation(type_3), 0);
    session->UnlockForControl();

    input->Close();
    preview->Release();
    input->Release();
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test FoldCallback with OnFoldStatusChanged and Constructor
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnFoldStatusChanged and Constructor for just call.
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_001, TestSize.Level0)
{
    sptr<CaptureSession> session = nullptr;
    ASSERT_EQ(session, nullptr);
    auto foldCallback = std::make_shared<FoldCallback>(session);
    FoldStatus status = UNKNOWN_FOLD;
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
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_002, TestSize.Level0)
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
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_003, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    std::vector<PortraitThemeType> supportedPortraitThemeTypes = {};
    EXPECT_EQ(session->GetSupportedPortraitThemeTypes(supportedPortraitThemeTypes),
        CameraErrorCode::SESSION_NOT_CONFIG);
    EXPECT_FALSE(session->IsPortraitThemeSupported());
    bool isSupported = false;
    EXPECT_EQ(session->IsPortraitThemeSupported(isSupported), CameraErrorCode::SESSION_NOT_CONFIG);

    PortraitThemeType type = PortraitThemeType::NATURAL;
    EXPECT_EQ(session->SetPortraitThemeType(type), CameraErrorCode::SESSION_NOT_CONFIG);

    std::vector<int32_t> supportedRotation = {};
    EXPECT_EQ(session->GetSupportedVideoRotations(supportedRotation), CameraErrorCode::SESSION_NOT_CONFIG);

    EXPECT_FALSE(session->IsVideoRotationSupported());
    isSupported = false;
    EXPECT_EQ(session->IsVideoRotationSupported(isSupported), CameraErrorCode::SESSION_NOT_CONFIG);

    int32_t rotation = 0;
    EXPECT_EQ(session->SetVideoRotation(rotation), CameraErrorCode::SESSION_NOT_CONFIG);

    std::vector<float> depthFusionThreshold = session->GetDepthFusionThreshold();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_004, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    session->isDepthFusionEnable_ = false;
    EXPECT_FALSE(session->IsDepthFusionEnabled());

    session->isMovingPhotoEnabled_ = false;
    EXPECT_FALSE(session->IsMovingPhotoEnabled());

    session->SetMacroStatusCallback(nullptr);
    EXPECT_EQ(session->GetMacroStatusCallback(), nullptr);

    session->isSetMacroEnable_ = false;
    EXPECT_FALSE(session->IsSetEnableMacro());

    PreconfigType preconfigType = PRECONFIG_720P;
    ProfileSizeRatio preconfigRatio = UNSPECIFIED;
    EXPECT_EQ(session->GeneratePreconfigProfiles(preconfigType, preconfigRatio), nullptr);

    session->SetEffectSuggestionCallback(nullptr);
    EXPECT_EQ(session->effectSuggestionCallback_, nullptr);

    session->SetARCallback(nullptr);
    EXPECT_EQ(session->GetARCallback(), nullptr);
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
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_005, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    bool isEnable = false;
    EXPECT_EQ(session->EnableTripodDetection(isEnable), CameraErrorCode::OPERATION_NOT_ALLOWED);

    UsageType usageType = BOKEH;
    bool enabled = false;
    session->SetUsage(usageType, enabled);

    bool isFoldable = CameraManager::GetInstance()->GetIsFoldable();
    EXPECT_EQ(session->IsAutoDeviceSwitchSupported(), isFoldable);

    bool enable = false;
    session->SetIsAutoSwitchDeviceStatus(enable);
    if (!isFoldable) {
        EXPECT_EQ(session->EnableAutoDeviceSwitch(enable), CameraErrorCode::OPERATION_NOT_ALLOWED);
    } else {
        EXPECT_EQ(session->EnableAutoDeviceSwitch(enable), CameraErrorCode::SUCCESS);
    }

    EXPECT_FALSE(session->SwitchDevice());

    auto cameraDeviceList = CameraManager::GetInstance()->GetSupportedCameras();
    bool flag = true;
    for (const auto& cameraDevice : cameraDeviceList) {
        if (cameraDevice->GetPosition() == CAMERA_POSITION_FRONT) {
            EXPECT_NE(session->FindFrontCamera(), nullptr);
            flag = false;
        }
    }
    if (flag) {
        EXPECT_EQ(session->FindFrontCamera(), nullptr);
    }

    session->StartVideoOutput();
    session->StopVideoOutput();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_006, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    session->SetAutoDeviceSwitchCallback(nullptr);
    EXPECT_EQ(session->GetAutoDeviceSwitchCallback(), nullptr);

    session->ExecuteAllFunctionsInMap();
    EXPECT_TRUE(session->canAddFuncToMap_);

    session->CreateAndSetFoldServiceCallback();
    QualityPrioritization qualityPrioritization = HIGH_QUALITY;
    EXPECT_EQ(session->SetQualityPrioritization(qualityPrioritization), CameraErrorCode::SESSION_NOT_CONFIG);

    session->isImageDeferred_ = false;
    EXPECT_FALSE(session->IsImageDeferred());

    bool isEnable = false;
    EXPECT_EQ(session->EnableEffectSuggestion(isEnable), CameraErrorCode::OPERATION_NOT_ALLOWED);

    std::vector<EffectSuggestionStatus> effectSuggestionStatusList = {};
    EXPECT_EQ(session->SetEffectSuggestionStatus(effectSuggestionStatusList), CameraErrorCode::OPERATION_NOT_ALLOWED);

    EffectSuggestionType effectSuggestionType = EFFECT_SUGGESTION_NONE;
    EXPECT_EQ(session->UpdateEffectSuggestion(effectSuggestionType, isEnable), CameraErrorCode::SESSION_NOT_CONFIG);
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
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_007, TestSize.Level0)
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
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_008, TestSize.Level0)
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
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_009, TestSize.Level0)
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
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_010, TestSize.Level0)
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
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_011, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_012, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdataCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    BeautyType beautyType = AUTO_TYPE;
    session->LockForControl();
    session->SetBeauty(beautyType, 0);
    EXPECT_EQ(session->GetBeauty(beautyType), -1);
    session->SetBeauty(beautyType, 3);
    EXPECT_EQ(session->GetBeauty(beautyType), -1);
    session->SetBeauty(FACE_SLENDER, 0);
    EXPECT_EQ(session->GetBeauty(beautyType), -1);
    session->SetBeauty(FACE_SLENDER, 3);
    EXPECT_EQ(session->GetBeauty(beautyType), -1);
    uint32_t count = 1;
    uint8_t beauty = OHOS_CAMERA_BEAUTY_TYPE_OFF;
    ASSERT_NE(session->changedMetadata_, nullptr);
    OHOS::Camera::DeleteCameraMetadataItem(session->changedMetadata_->get(), OHOS_CONTROL_BEAUTY_TYPE);
    session->SetBeauty(beautyType, 0);
    EXPECT_EQ(session->GetBeauty(beautyType), -1);
    session->SetBeauty(FACE_SLENDER, 0);
    EXPECT_EQ(session->GetBeauty(beautyType), -1);
    session->changedMetadata_->addEntry(OHOS_CONTROL_BEAUTY_TYPE, &beauty, count);
    session->SetBeauty(beautyType, 0);
    session->SetBeauty(FACE_SLENDER, 0);
    int num = 10;
    beautyType = static_cast<BeautyType>(num);
    session->SetBeauty(beautyType, 0);
    EXPECT_EQ(session->GetBeauty(beautyType), -1);
    session->UnlockForControl();

    EXPECT_EQ(preview->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
    EXPECT_EQ(session->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test IsFeatureSupported abnormal branches
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsFeatureSupported abnormal branches
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_013, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_014, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_015, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdataCameraOutputCapability();
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
HWTEST_F(CaptureSessionUnitTest, capture_session_function_unittest_016, TestSize.Level0)
{
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras_[0]);
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    UpdataCameraOutputCapability();
    sptr<CaptureOutput> preview = CreatePreviewOutput(previewProfile_[0]);
    ASSERT_NE(preview, nullptr);

    EXPECT_EQ(session->BeginConfig(), 0);
    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);
    EXPECT_EQ(session->CommitConfig(), 0);

    session->LockForControl();
    ASSERT_NE(session->changedMetadata_, nullptr);
    uint32_t sensitivity = 1;
    OHOS::Camera::DeleteCameraMetadataItem(session->changedMetadata_->get(), session->HAL_CUSTOM_SENSOR_SENSITIVITY);
    EXPECT_EQ(session->SetSensorSensitivity(sensitivity), 0);
    session->changedMetadata_->addEntry(session->HAL_CUSTOM_SENSOR_SENSITIVITY, &sensitivity, 1);
    EXPECT_EQ(session->SetSensorSensitivity(sensitivity), 0);

    ASSERT_NE(session->changedMetadata_, nullptr);
    EffectSuggestionType effectSuggestionType = EFFECT_SUGGESTION_PORTRAIT;
    bool isEnable = true;
    OHOS::Camera::DeleteCameraMetadataItem(session->changedMetadata_->get(), OHOS_CONTROL_EFFECT_SUGGESTION_TYPE);
    EXPECT_EQ(session->UpdateEffectSuggestion(effectSuggestionType, isEnable), 0);
    uint8_t type = OHOS_CAMERA_EFFECT_SUGGESTION_PORTRAIT;
    std::vector<uint8_t> vec = {type, isEnable};
    session->changedMetadata_->addEntry(OHOS_CONTROL_EFFECT_SUGGESTION_TYPE, vec.data(), vec.size());
    EXPECT_EQ(session->UpdateEffectSuggestion(effectSuggestionType, isEnable), 0);
    session->UnlockForControl();

    EXPECT_EQ(preview->Release(), 0);
    EXPECT_EQ(input->Release(), 0);
    EXPECT_EQ(session->Release(), 0);
}
}
}