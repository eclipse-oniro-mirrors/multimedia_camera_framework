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

#include "camera_manager_unittest.h"
#include "gtest/gtest.h"
#include <cstdint>
#include <vector>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_log.h"
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

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;
using OHOS::HDI::Camera::V1_3::OperationMode;

void TorchListenerImpl::OnTorchStatusChange(const TorchStatusInfo &torchStatusInfo) const
{
    MEDIA_DEBUG_LOG("TorchListener::OnTorchStatusChange called %{public}d %{public}d %{public}f",
        torchStatusInfo.isTorchAvailable, torchStatusInfo.isTorchActive, torchStatusInfo.torchLevel);
    return;
}

void CameraManagerUnitTest::SetUpTestCase(void) {}

void CameraManagerUnitTest::TearDownTestCase(void) {}

void CameraManagerUnitTest::SetUp()
{
    NativeAuthorization();
    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);
}

void CameraManagerUnitTest::TearDown()
{
    cameraManager_ = nullptr;
}

void CameraManagerUnitTest::NativeAuthorization()
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
    MEDIA_DEBUG_LOG("CameraManagerUnitTest::NativeAuthorization uid:%{public}d", uid_);
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

/*
 * Feature: Framework
 * Function: Test cameraManager with CreatePhotoOutputWithoutProfile
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreatePhotoOutputWithoutProfile for Normal branches
 */
HWTEST_F(CameraManagerUnitTest, camera_framework_manager_unittest_001, TestSize.Level0)
{
    int ret = 0;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> surfaceProducer = surface->GetProducer();
    sptr<PhotoOutput> photoOutput = nullptr;
    ret = cameraManager_->CreatePhotoOutputWithoutProfile(surfaceProducer, &photoOutput);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test cameraManager with CreateVideoOutputWithoutProfile
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateVideoOutputWithoutProfile for Normal branches
 */
HWTEST_F(CameraManagerUnitTest, camera_framework_manager_unittest_002, TestSize.Level0)
{
    int ret = 0;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    sptr<VideoOutput> videoOutput = nullptr;
    ret = cameraManager_->CreateVideoOutputWithoutProfile(surface, &videoOutput);
    ASSERT_NE(videoOutput, nullptr);
    EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test cameraManager with CreatePreviewOutputWithoutProfile
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreatePreviewOutputWithoutProfile for Normal branches
 */
HWTEST_F(CameraManagerUnitTest, camera_framework_manager_unittest_003, TestSize.Level0)
{
    int ret = 0;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    sptr<PreviewOutput> previewOutput = nullptr;
    ret = cameraManager_->CreatePreviewOutputWithoutProfile(surface, &previewOutput);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test cameraManager with CreateDeferredPreviewOutput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateDeferredPreviewOutput for Normal branches
 */
HWTEST_F(CameraManagerUnitTest, camera_framework_manager_unittest_004, TestSize.Level0)
{
    int ret = 0;
    int32_t width = PREVIEW_DEFAULT_WIDTH;
    int32_t height = PREVIEW_DEFAULT_HEIGHT;
    Size previewsize;
    previewsize.width = width;
    previewsize.height = height;
    CameraFormat previewFormat = CAMERA_FORMAT_YUV_420_SP;
    Profile profile = Profile(previewFormat, previewsize);
    sptr<PreviewOutput> previewOutput = nullptr;
    ret = cameraManager_->CreateDeferredPreviewOutput(profile, &previewOutput);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test cameraManager with CreateMetadataOutput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateMetadataOutput for Normal branches
 */
HWTEST_F(CameraManagerUnitTest, camera_framework_manager_unittest_005, TestSize.Level0)
{
    sptr<MetadataOutput> metadataOutput = nullptr;
    int ret = cameraManager_->CreateMetadataOutput(metadataOutput);
    ASSERT_NE(metadataOutput, nullptr);
    EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test cameraManager with IsCameraMuted and MuteCamera
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsCameraMuted and MuteCamera for Normal branches & abnormal branches
 */
HWTEST_F(CameraManagerUnitTest, camera_framework_manager_unittest_006, TestSize.Level0)
{
    sptr<CameraManager> manager = cameraManager_;
    bool ret = [&manager]() {
        sptr<ICameraService> proxy = nullptr;
        manager->SetServiceProxy(proxy);
        return manager->IsCameraMuted();
    }();
    EXPECT_FALSE(ret);
    bool muteMode = false;
    cameraManager_->MuteCamera(muteMode);
    bool cameraMuted = cameraManager_->IsCameraMuted();
    EXPECT_FALSE(cameraMuted);
    muteMode = true;
    cameraManager_->MuteCamera(muteMode);
    cameraMuted = cameraManager_->IsCameraMuted();
    sptr<CameraMuteServiceCallback> muteService = new (std::nothrow) CameraMuteServiceCallback(nullptr);
    EXPECT_NE(muteService, nullptr);
    int32_t muteCameraState = muteService->OnCameraMute(cameraMuted);
    EXPECT_EQ(muteCameraState, 0);
    muteService = new (std::nothrow) CameraMuteServiceCallback(cameraManager_);
    EXPECT_NE(muteService, nullptr);
    muteCameraState = muteService->OnCameraMute(cameraMuted);
    EXPECT_EQ(muteCameraState, 0);
}

/*
 * Feature: Framework
 * Function: Test cameraManager with PrelaunchCamera and IsPrelaunchSupported
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test PrelaunchCamera and IsPrelaunchSupported for Normal branches & abnormal branches
 */
HWTEST_F(CameraManagerUnitTest, camera_framework_manager_unittest_007, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    sptr<CameraDevice> camera = cameras[0];
    EXPECT_FALSE(cameraManager_->IsPrelaunchSupported(nullptr));
    cameraManager_->IsPrelaunchSupported(camera);
    int32_t ret = -1;
    auto manager = cameraManager_;
    ret = [&manager]() {
        sptr<ICameraService> proxy = nullptr;
        manager->SetServiceProxy(proxy);
        return manager->PrelaunchCamera();
    }();
    EXPECT_EQ(ret, CameraErrorCode::SERVICE_FATL_ERROR);
}

/*
 * Feature: Framework
 * Function: Test cameramanager with FillSupportPhotoFormats
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test FillSupportPhotoFormats for (photoFormats_.size() == 0 || photoProfiles.size() == 0)
 */
HWTEST_F(CameraManagerUnitTest, camera_framework_manager_unittest_008, TestSize.Level0)
{
    cameraManager_->photoFormats_.clear();
    std::vector<Profile> photoProfiles = {};
    cameraManager_->FillSupportPhotoFormats(photoProfiles);
    EXPECT_EQ(photoProfiles.size(), 0);

    cameraManager_->photoFormats_ = {
        CAMERA_FORMAT_YCBCR_420_888,
        CAMERA_FORMAT_RGBA_8888,
        CAMERA_FORMAT_DNG
    };
    cameraManager_->FillSupportPhotoFormats(photoProfiles);
    EXPECT_EQ(photoProfiles.size(), 0);

    photoProfiles = {
        Profile(CAMERA_FORMAT_JPEG, {1920, 1080}),
        Profile(CAMERA_FORMAT_YCBCR_420_888, {1280, 720})
    };
    cameraManager_->FillSupportPhotoFormats(photoProfiles);
    EXPECT_NE(photoProfiles.size(), 0);
}

/*
 * Feature: Framework
 * Function: Test CameraManager with OnCameraStatusChanged
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnCameraStatusChanged for Normal branches & abnormal branches
 */
HWTEST_F(CameraManagerUnitTest, camera_framework_manager_unittest_009, TestSize.Level0)
{
    CameraStatusServiceCallback cameraStatusServiceCallback(cameraManager_);
    std::string cameraId;
    CameraStatus status = CAMERA_STATUS_APPEAR;
    std::string bundleName;
    cameraManager_->cameraMngrCallbackMap_.Clear();
    auto ret = cameraStatusServiceCallback.OnCameraStatusChanged(cameraId, status, bundleName);
    EXPECT_EQ(ret, CAMERA_OK);

    std::shared_ptr<TestCameraMngerCallback> setCallback = std::make_shared<TestCameraMngerCallback>("MgrCallback");
    cameraManager_->SetCallback(setCallback);
    ret = cameraStatusServiceCallback.OnCameraStatusChanged(cameraId, status, bundleName);
    EXPECT_EQ(ret, CAMERA_OK);

    status = CAMERA_STATUS_DISAPPEAR;
    ret = cameraStatusServiceCallback.OnCameraStatusChanged(cameraId, status, bundleName);
    EXPECT_EQ(ret, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test CameraManager with OnFlashlightStatusChanged
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnFlashlightStatusChanged for cameraMngrCallbackMap_ is nullptr & not nullptr
 */
HWTEST_F(CameraManagerUnitTest, camera_framework_manager_unittest_010, TestSize.Level0)
{
    CameraStatusServiceCallback cameraStatusServiceCallback(cameraManager_);
    std::string cameraId;
    FlashStatus status = FLASH_STATUS_OFF;
    cameraManager_->cameraMngrCallbackMap_.Clear();
    auto ret = cameraStatusServiceCallback.OnFlashlightStatusChanged(cameraId, status);
    EXPECT_EQ(ret, CAMERA_OK);

    std::shared_ptr<TestCameraMngerCallback> setCallback = std::make_shared<TestCameraMngerCallback>("MgrCallback");
    cameraManager_->SetCallback(setCallback);
    ret = cameraStatusServiceCallback.OnFlashlightStatusChanged(cameraId, status);
    EXPECT_EQ(ret, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test CameraManager with CreateCaptureSessionImpl
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateCaptureSessionImpl for all branches of switch
 */
HWTEST_F(CameraManagerUnitTest, camera_framework_manager_unittest_011, TestSize.Level0)
{
    sptr<ICaptureSession> session = nullptr;
    OperationMode opMode = OperationMode::NORMAL;
    auto serviceProxy = cameraManager_->GetServiceProxy();
    serviceProxy->CreateCaptureSession(session, opMode);
    EXPECT_NE(session, nullptr);
    SceneMode mode = FLUORESCENCE_PHOTO;
    EXPECT_NE(cameraManager_->CreateCaptureSessionImpl(mode, session), nullptr);
    mode = QUICK_SHOT_PHOTO;
    EXPECT_NE(cameraManager_->CreateCaptureSessionImpl(mode, session), nullptr);

    mode = VIDEO;
    EXPECT_NE(cameraManager_->CreateCaptureSessionImpl(mode, session), nullptr);

    mode = CAPTURE;
    EXPECT_NE(cameraManager_->CreateCaptureSessionImpl(mode, session), nullptr);

    mode = PORTRAIT;
    EXPECT_NE(cameraManager_->CreateCaptureSessionImpl(mode, session), nullptr);

    mode = NIGHT;
    EXPECT_NE(cameraManager_->CreateCaptureSessionImpl(mode, session), nullptr);

    mode = SLOW_MOTION;
    EXPECT_NE(cameraManager_->CreateCaptureSessionImpl(mode, session), nullptr);

    mode = SCAN;
    EXPECT_NE(cameraManager_->CreateCaptureSessionImpl(mode, session), nullptr);

    mode = CAPTURE_MACRO;
    EXPECT_NE(cameraManager_->CreateCaptureSessionImpl(mode, session), nullptr);

    mode = VIDEO_MACRO;
    EXPECT_NE(cameraManager_->CreateCaptureSessionImpl(mode, session), nullptr);

    mode = PROFESSIONAL_PHOTO;
    EXPECT_NE(cameraManager_->CreateCaptureSessionImpl(mode, session), nullptr);

    mode = PROFESSIONAL_VIDEO;
    EXPECT_NE(cameraManager_->CreateCaptureSessionImpl(mode, session), nullptr);

    mode = HIGH_RES_PHOTO;
    EXPECT_NE(cameraManager_->CreateCaptureSessionImpl(mode, session), nullptr);

    mode = SECURE;
    EXPECT_NE(cameraManager_->CreateCaptureSessionImpl(mode, session), nullptr);

    mode = LIGHT_PAINTING;
    EXPECT_NE(cameraManager_->CreateCaptureSessionImpl(mode, session), nullptr);

    mode = PANORAMA_PHOTO;
    EXPECT_NE(cameraManager_->CreateCaptureSessionImpl(mode, session), nullptr);

    mode = TIMELAPSE_PHOTO;
    EXPECT_NE(cameraManager_->CreateCaptureSessionImpl(mode, session), nullptr);

    mode = APERTURE_VIDEO;
    EXPECT_NE(cameraManager_->CreateCaptureSessionImpl(mode, session), nullptr);
}

/*
 * Feature: Framework
 * Function: Test CameraManager with CreateCaptureSession
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateCaptureSession for ConvertFwkToMetaMode
 */
HWTEST_F(CameraManagerUnitTest, camera_framework_manager_unittest_012, TestSize.Level0)
{
    SceneMode mode = PROFESSIONAL;
    EXPECT_NE(cameraManager_->CreateCaptureSession(mode), nullptr);

    mode = FLUORESCENCE_PHOTO;
    EXPECT_NE(cameraManager_->CreateCaptureSession(mode), nullptr);

    mode = QUICK_SHOT_PHOTO;
    EXPECT_NE(cameraManager_->CreateCaptureSession(mode), nullptr);

    mode = NORMAL;
    EXPECT_NE(cameraManager_->CreateCaptureSession(mode), nullptr);

    mode = CAPTURE;
    EXPECT_NE(cameraManager_->CreateCaptureSession(mode), nullptr);

    mode = VIDEO;
    EXPECT_NE(cameraManager_->CreateCaptureSession(mode), nullptr);

    mode = PORTRAIT;
    EXPECT_NE(cameraManager_->CreateCaptureSession(mode), nullptr);

    mode = NIGHT;
    EXPECT_NE(cameraManager_->CreateCaptureSession(mode), nullptr);

    mode = SLOW_MOTION;
    EXPECT_NE(cameraManager_->CreateCaptureSession(mode), nullptr);

    mode = SCAN;
    EXPECT_NE(cameraManager_->CreateCaptureSession(mode), nullptr);

    mode = CAPTURE_MACRO;
    EXPECT_NE(cameraManager_->CreateCaptureSession(mode), nullptr);

    mode = VIDEO_MACRO;
    EXPECT_NE(cameraManager_->CreateCaptureSession(mode), nullptr);

    mode = PROFESSIONAL_PHOTO;
    EXPECT_NE(cameraManager_->CreateCaptureSession(mode), nullptr);

    mode = PROFESSIONAL_VIDEO;
    EXPECT_NE(cameraManager_->CreateCaptureSession(mode), nullptr);

    mode = HIGH_FRAME_RATE;
    EXPECT_NE(cameraManager_->CreateCaptureSession(mode), nullptr);

    mode = HIGH_RES_PHOTO;
    EXPECT_NE(cameraManager_->CreateCaptureSession(mode), nullptr);

    mode = SECURE;
    EXPECT_NE(cameraManager_->CreateCaptureSession(mode), nullptr);

    mode = LIGHT_PAINTING;
    EXPECT_NE(cameraManager_->CreateCaptureSession(mode), nullptr);

    mode = PANORAMA_PHOTO;
    EXPECT_NE(cameraManager_->CreateCaptureSession(mode), nullptr);

    mode = TIMELAPSE_PHOTO;
    EXPECT_NE(cameraManager_->CreateCaptureSession(mode), nullptr);

    mode = APERTURE_VIDEO;
    EXPECT_NE(cameraManager_->CreateCaptureSession(mode), nullptr);
}

/*
 * Feature: Framework
 * Function: Test CameraManager with CreateDepthDataOutput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateDepthDataOutput which two parameter for abnormal branches
 */
HWTEST_F(CameraManagerUnitTest, camera_framework_manager_unittest_013, TestSize.Level0)
{
    DepthProfile depthProfile;
    sptr<IBufferProducer> surface = nullptr;
    EXPECT_NE(cameraManager_->GetServiceProxy(), nullptr);
    EXPECT_EQ(cameraManager_->CreateDepthDataOutput(depthProfile, surface), nullptr);
}

/*
 * Feature: Framework
 * Function: Test CameraManager with CreateDepthDataOutput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateDepthDataOutput which three parameter
 * for branches of (serviceProxy == nullptr) || (surface == nullptr)
 */
HWTEST_F(CameraManagerUnitTest, camera_framework_manager_unittest_014, TestSize.Level0)
{
    DepthProfile depthProfile;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> surfaceProducer = surface->GetProducer();
    EXPECT_NE(surfaceProducer, nullptr);
    EXPECT_NE(cameraManager_->GetServiceProxy(), nullptr);
    sptr<DepthDataOutput> depthDataOutput = nullptr;
    EXPECT_EQ(cameraManager_->CreateDepthDataOutput(depthProfile, surfaceProducer, &depthDataOutput),
        CameraErrorCode::INVALID_ARGUMENT);

    cameraManager_->serviceProxyPrivate_ = nullptr;
    EXPECT_EQ(cameraManager_->CreateDepthDataOutput(depthProfile, surfaceProducer, &depthDataOutput),
        CameraErrorCode::INVALID_ARGUMENT);

    surfaceProducer = nullptr;
    EXPECT_EQ(cameraManager_->CreateDepthDataOutput(depthProfile, surfaceProducer, &depthDataOutput),
        CameraErrorCode::INVALID_ARGUMENT);
}

/*
 * Feature: Framework
 * Function: Test CameraManager with CreateDepthDataOutput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateDepthDataOutput which three parameter
 * for branches of (depthProfile.GetCameraFormat() == CAMERA_FORMAT_INVALID)
 * ||(depthProfile.GetSize().width == 0) ||(depthProfile.GetSize().height == 0)
 */
HWTEST_F(CameraManagerUnitTest, camera_framework_manager_unittest_015, TestSize.Level0)
{
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> surfaceProducer = surface->GetProducer();
    EXPECT_NE(surfaceProducer, nullptr);
    EXPECT_NE(cameraManager_->GetServiceProxy(), nullptr);
    sptr<DepthDataOutput> depthDataOutput = nullptr;

    CameraFormat format = CAMERA_FORMAT_INVALID;
    DepthDataAccuracy dataAccuracy = DEPTH_DATA_ACCURACY_INVALID;
    Size size = { 0, 0 };
    DepthProfile depthProfileRet1(format, dataAccuracy, size);
    EXPECT_EQ(cameraManager_->CreateDepthDataOutput(depthProfileRet1, surfaceProducer, &depthDataOutput),
        CameraErrorCode::INVALID_ARGUMENT);

    format = CAMERA_FORMAT_YCBCR_420_888;
    DepthProfile depthProfileRet2(format, dataAccuracy, size);
    EXPECT_EQ(cameraManager_->CreateDepthDataOutput(depthProfileRet2, surfaceProducer, &depthDataOutput),
        CameraErrorCode::INVALID_ARGUMENT);

    format = CAMERA_FORMAT_INVALID;
    size = { 1, 1 };
    DepthProfile depthProfileRet3(format, dataAccuracy, size);
    EXPECT_EQ(cameraManager_->CreateDepthDataOutput(depthProfileRet3, surfaceProducer, &depthDataOutput),
        CameraErrorCode::INVALID_ARGUMENT);

    format = CAMERA_FORMAT_YCBCR_420_888;
    DepthProfile depthProfileRet4(format, dataAccuracy, size);
    EXPECT_EQ(cameraManager_->CreateDepthDataOutput(depthProfileRet4, surfaceProducer, &depthDataOutput),
        CameraErrorCode::SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test CameraManager with DestroyStubObj
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DestroyStubObj for normal branches & abnormal branches
 */
HWTEST_F(CameraManagerUnitTest, camera_framework_manager_unittest_016, TestSize.Level0)
{
    EXPECT_NE(cameraManager_->GetServiceProxy(), nullptr);
    EXPECT_EQ(cameraManager_->DestroyStubObj(), CAMERA_OK);

    cameraManager_->serviceProxyPrivate_ = nullptr;
    EXPECT_EQ(cameraManager_->DestroyStubObj(), SERVICE_FATL_ERROR);
}

/*
 * Feature: Framework
 * Function: Test CameraManager with CameraServerDied and AddServiceProxyDeathRecipient
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CameraServerDied and AddServiceProxyDeathRecipient for abnormal branches
 */
HWTEST_F(CameraManagerUnitTest, camera_framework_manager_unittest_017, TestSize.Level0)
{
    sptr<ICameraServiceCallback> callback = new(std::nothrow) CameraStatusServiceCallback(cameraManager_);
    ASSERT_NE(callback, nullptr);
    cameraManager_->cameraSvcCallback_  = callback;
    EXPECT_NE(cameraManager_->cameraSvcCallback_, nullptr);

    pid_t pid = 0;
    cameraManager_->CameraServerDied(pid);
    cameraManager_->SetServiceProxy(nullptr);
    EXPECT_EQ(cameraManager_->AddServiceProxyDeathRecipient(), CameraErrorCode::SERVICE_FATL_ERROR);
}

/*
 * Feature: Framework
 * Function: Test CameraManager with GetCameraDeviceListFromServer
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCameraDeviceListFromServer for normal branches
 */
HWTEST_F(CameraManagerUnitTest, camera_framework_manager_unittest_018, TestSize.Level0)
{
    EXPECT_NE(cameraManager_->GetServiceProxy(), nullptr);
    std::vector<std::string> cameraIds;
    EXPECT_EQ(cameraManager_->GetServiceProxy()->GetCameraIds(cameraIds), CAMERA_OK);
    std::vector<sptr<CameraDevice>> deviceInfoList= cameraManager_->GetCameraDeviceListFromServer();
    EXPECT_FALSE(deviceInfoList.empty());
}

/*
 * Feature: Framework
 * Function: Test CameraManager with GetFallbackConfigMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetFallbackConfigMode for branches of switch
 */
HWTEST_F(CameraManagerUnitTest, camera_framework_manager_unittest_019, TestSize.Level0)
{
    SceneMode profileMode = CAPTURE_MACRO;
    CameraManager::ProfilesWrapper profilesWrapper = {};
    EXPECT_EQ(cameraManager_->GetFallbackConfigMode(profileMode, profilesWrapper), CAPTURE);

    profileMode = VIDEO_MACRO;
    EXPECT_EQ(cameraManager_->GetFallbackConfigMode(profileMode, profilesWrapper), VIDEO);

    profileMode = NORMAL;
    EXPECT_EQ(cameraManager_->GetFallbackConfigMode(profileMode, profilesWrapper), NORMAL);
}

/*
 * Feature: Framework
 * Function: Test cameramanager with ParseBasicCapability
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ParseBasicCapability for normal branches
 */
HWTEST_F(CameraManagerUnitTest, camera_framework_manager_unittest_020, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CameraOutputCapability> ability = cameraManager_->GetSupportedOutputCapability(cameras[0], 0);

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras[0]->GetMetadata();
    EXPECT_NE(metadata, nullptr);
    camera_metadata_item_t item;
    OHOS::Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS, &item);
    CameraManager::ProfilesWrapper profilesWrapper = {};
    cameraManager_->ParseBasicCapability(profilesWrapper, metadata, item);
    EXPECT_FALSE((profilesWrapper.photoProfiles.empty()) && (profilesWrapper.previewProfiles.empty())
        && (profilesWrapper.vidProfiles.empty()));
}

/*
 * Feature: Framework
 * Function: Test cameramanager with ParseExtendCapability
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ParseExtendCapability for normal branches
 */
HWTEST_F(CameraManagerUnitTest, camera_framework_manager_unittest_021, TestSize.Level0)
{
    CameraManager::ProfilesWrapper profilesWrapper = {};
    int32_t modeNameRet1 = SceneMode::VIDEO;
    camera_metadata_item_t item;
    cameraManager_->ParseExtendCapability(profilesWrapper, modeNameRet1, item);
    EXPECT_TRUE((profilesWrapper.photoProfiles.empty()) && (profilesWrapper.previewProfiles.empty())
        && (profilesWrapper.vidProfiles.empty()));

    int32_t modeNameRet2 = SceneMode::NORMAL;
    cameraManager_->ParseExtendCapability(profilesWrapper, modeNameRet2, item);
    EXPECT_TRUE((profilesWrapper.photoProfiles.empty()) && (profilesWrapper.previewProfiles.empty())
        && (profilesWrapper.vidProfiles.empty()));
}

/*
 * Feature: Framework
 * Function: Test cameramanager with ParseProfileLevel
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ParseProfileLevel for normal branches
 */
HWTEST_F(CameraManagerUnitTest, camera_framework_manager_unittest_022, TestSize.Level0)
{
    cameraManager_->isSystemApp_ = true;
    CameraManager::ProfilesWrapper profilesWrapper = {};
    int32_t modeNameRet1 = SceneMode::VIDEO;
    camera_metadata_item_t item;
    cameraManager_->ParseProfileLevel(profilesWrapper, modeNameRet1, item);
    EXPECT_TRUE((profilesWrapper.photoProfiles.empty()) && (profilesWrapper.previewProfiles.empty())
        && (profilesWrapper.vidProfiles.empty()));

    int32_t modeNameRet2 = SceneMode::NORMAL;
    cameraManager_->ParseProfileLevel(profilesWrapper, modeNameRet2, item);
    EXPECT_TRUE((profilesWrapper.photoProfiles.empty()) && (profilesWrapper.previewProfiles.empty())
        && (profilesWrapper.vidProfiles.empty()));

    cameraManager_->isSystemApp_ = false;
    cameraManager_->ParseProfileLevel(profilesWrapper, modeNameRet2, item);
    cameraManager_->ParseProfileLevel(profilesWrapper, modeNameRet1, item);
    EXPECT_TRUE((profilesWrapper.photoProfiles.empty()) && (profilesWrapper.previewProfiles.empty())
        && (profilesWrapper.vidProfiles.empty()));
}

/*
 * Feature: Framework
 * Function: Test cameramanager with CreateProfileLevel4StreamType
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateProfileLevel4StreamType for abnormal branches
 */
HWTEST_F(CameraManagerUnitTest, camera_framework_manager_unittest_023, TestSize.Level0)
{
    CameraManager::ProfilesWrapper profilesWrapper = {};
    int32_t specId = 0;
    ProfileDetailInfo profile1 = {
        CAMERA_FORMAT_INVALID,
        PHOTO_DEFAULT_WIDTH,
        PHOTO_DEFAULT_HEIGHT,
        FIXEDFPS_DEFAULT,
        MINFPS_DEFAULT,
        MAXFPS_DEFAULT,
        {1, 2, 3}
    };
    ProfileDetailInfo profile2 = {
        CAMERA_FORMAT_INVALID,
        PHOTO_DEFAULT_WIDTH,
        PHOTO_DEFAULT_HEIGHT,
        FIXEDFPS_DEFAULT,
        MINFPS_DEFAULT,
        MAXFPS_DEFAULT,
        {4, 5, 6}
    };
    StreamInfo streamInfo = {
        OutputCapStreamType::PREVIEW,
        {profile1, profile2}
    };
    cameraManager_->CreateProfileLevel4StreamType(profilesWrapper, specId, streamInfo);
    EXPECT_EQ(profilesWrapper.previewProfiles.size(), 0);
}

/*
 * Feature: Framework
 * Function: Test cameramanager with GetSupportPhotoFormat
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSupportPhotoFormat for metadata == nullptr
 */
HWTEST_F(CameraManagerUnitTest, camera_framework_manager_unittest_024, TestSize.Level0)
{
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = nullptr;
    int32_t modeName = SceneMode::NORMAL;

    vector<CameraFormat> cameraFormat = cameraManager_->GetSupportPhotoFormat(modeName, metadata);
    EXPECT_EQ(cameraFormat.size(), 0);
}

/*
 * Feature: Framework
 * Function: Test TorchServiceCallback with OnTorchStatusChange
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnTorchStatusChange for status is TORCH_STATUS_UNAVAILABLE and TORCH_STATUS_ON
 */
HWTEST_F(CameraManagerUnitTest, camera_framework_manager_unittest_025, TestSize.Level0)
{
    TorchServiceCallback torchServiceCallback(cameraManager_);
    TorchStatus status1 = TorchStatus::TORCH_STATUS_UNAVAILABLE;
    TorchStatus status2 = TorchStatus::TORCH_STATUS_ON;

    EXPECT_NE(torchServiceCallback.cameraManager_, nullptr);
    EXPECT_TRUE(cameraManager_->torchListenerMap_.IsEmpty());
    auto ret = torchServiceCallback.OnTorchStatusChange(status1);
    EXPECT_EQ(cameraManager_->torchMode_, TORCH_MODE_OFF);
    EXPECT_EQ(ret, CAMERA_OK);

    std::shared_ptr<TorchListener> listener = std::make_shared<TorchListenerImpl>();
    cameraManager_->RegisterTorchListener(listener);
    auto listenerMap = cameraManager_->GetTorchListenerMap();
    EXPECT_FALSE(listenerMap.IsEmpty());
    ret = torchServiceCallback.OnTorchStatusChange(status2);
    EXPECT_EQ(cameraManager_->torchMode_, TORCH_MODE_ON);
    EXPECT_EQ(ret, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test TorchServiceCallback with OnFoldStatusChanged
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnFoldStatusChanged for listenerMap is empty and not empty
 */
HWTEST_F(CameraManagerUnitTest, camera_framework_manager_unittest_026, TestSize.Level0)
{
    cameraManager_->torchListenerMap_.Clear();
    FoldServiceCallback foldServiceCallback(cameraManager_);
    FoldStatus status = FoldStatus::UNKNOWN_FOLD;

    EXPECT_NE(foldServiceCallback.cameraManager_, nullptr);
    EXPECT_TRUE(foldServiceCallback.cameraManager_->torchListenerMap_.IsEmpty());
    auto ret = foldServiceCallback.OnFoldStatusChanged(status);
    EXPECT_EQ(ret, CAMERA_OK);

    std::shared_ptr<TorchListener> listener = std::make_shared<TorchListenerImpl>();
    cameraManager_->RegisterTorchListener(listener);
    auto listenerMap = cameraManager_->GetTorchListenerMap();
    EXPECT_FALSE(listenerMap.IsEmpty());
    ret = foldServiceCallback.OnFoldStatusChanged(status);
    EXPECT_EQ(ret, CAMERA_OK);
}
}
}
