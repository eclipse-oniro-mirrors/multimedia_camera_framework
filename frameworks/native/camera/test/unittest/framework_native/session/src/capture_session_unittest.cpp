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

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

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
 * Function: Test captureSession with SetPreviewRotation and CreateMediaLibrary
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetPreviewRotation for captureSession is nullptr and CreateMediaLibrary for
 * captureSession is nullptr and not nullptr
 */
HWTEST_F(CaptureSessionUnitTest, capture_session_unittest_005, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    EXPECT_NE(session->GetCaptureSession(), nullptr);
    sptr<CameraPhotoProxy> photoProxy{new CameraPhotoProxy()};
    std::string uri;
    int32_t cameraShotType;
    string burstKey = "";
    int64_t timestamp = 0000;
    session->CreateMediaLibrary(photoProxy, uri, cameraShotType, burstKey, timestamp);

    std::string deviceClass;
    session->SetCaptureSession(nullptr);
    session->CreateMediaLibrary(photoProxy, uri, cameraShotType, burstKey, timestamp);
    EXPECT_EQ(session->SetPreviewRotation(deviceClass), CAMERA_OK);

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
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras_[0]->GetMetadata();

    EXPECT_EQ(session->GetColorEffect(), COLOR_EFFECT_NORMAL);
    EXPECT_EQ(session->EnableMacro(true), OPERATION_NOT_ALLOWED);

    EXPECT_EQ(session->BeginConfig(), 0);

    EXPECT_EQ(session->AddInput(input), 0);
    EXPECT_EQ(session->AddOutput(preview), 0);

    EXPECT_EQ(session->CommitConfig(), 0);
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
}
}