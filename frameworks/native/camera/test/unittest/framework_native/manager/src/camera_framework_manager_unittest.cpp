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

#include "camera_framework_manager_unittest.h"
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

class MockCameraManager : public CameraManager {
public:
    MOCK_METHOD0(GetIsFoldable, bool());
    MOCK_METHOD0(GetFoldStatus, FoldStatus());
    ~MockCameraManager() {}
};

void TorchListenerImpl::OnTorchStatusChange(const TorchStatusInfo &torchStatusInfo) const
{
    MEDIA_DEBUG_LOG("TorchListener::OnTorchStatusChange called %{public}d %{public}d %{public}f",
        torchStatusInfo.isTorchAvailable, torchStatusInfo.isTorchActive, torchStatusInfo.torchLevel);
    return;
}

void CameraFrameWorkManagerUnit::SetUpTestCase(void) {}

void CameraFrameWorkManagerUnit::TearDownTestCase(void) {}

void CameraFrameWorkManagerUnit::SetUp()
{
    NativeAuthorization();
    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);
}

void CameraFrameWorkManagerUnit::TearDown()
{
    cameraManager_ = nullptr;
}

void CameraFrameWorkManagerUnit::NativeAuthorization()
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
    MEDIA_DEBUG_LOG("CameraFrameWorkManagerUnit::NativeAuthorization uid:%{public}d", uid_);
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
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_001, TestSize.Level0)
{
    int ret = 0;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
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
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_002, TestSize.Level0)
{
    int ret = 0;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(surface, nullptr);
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
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_003, TestSize.Level0)
{
    int ret = 0;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(surface, nullptr);
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
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_004, TestSize.Level0)
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
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_005, TestSize.Level0)
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
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_006, TestSize.Level0)
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
    sptr<ICameraMuteServiceCallback> muteService = cameraManager_->GetCameraMuteListenerManager();
    EXPECT_NE(muteService, nullptr);
    int32_t muteCameraState = muteService->OnCameraMute(cameraMuted);
    EXPECT_EQ(muteCameraState, 0);
    muteService = cameraManager_->GetCameraMuteListenerManager();
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
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_007, TestSize.Level0)
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
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_008, TestSize.Level0)
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
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_009, TestSize.Level0)
{
    auto listenerManager = cameraManager_->GetCameraStatusListenerManager();
    std::string cameraId;
    CameraStatus status = CAMERA_STATUS_APPEAR;
    std::string bundleName;
    listenerManager->ClearListeners();
    auto ret = listenerManager->OnCameraStatusChanged(cameraId, status, bundleName);
    EXPECT_EQ(ret, CAMERA_OK);

    std::shared_ptr<TestCameraMngerCallback> setCallback = std::make_shared<TestCameraMngerCallback>("MgrCallback");
    cameraManager_->RegisterCameraStatusCallback(setCallback);
    ret = listenerManager->OnCameraStatusChanged(cameraId, status, bundleName);
    EXPECT_EQ(ret, CAMERA_OK);

    status = CAMERA_STATUS_DISAPPEAR;
    ret = listenerManager->OnCameraStatusChanged(cameraId, status, bundleName);
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
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_010, TestSize.Level0)
{
    auto listenerManager = cameraManager_->GetCameraStatusListenerManager();
    std::string cameraId;
    FlashStatus status = FLASH_STATUS_OFF;
    listenerManager->ClearListeners();
    auto ret = listenerManager->OnFlashlightStatusChanged(cameraId, status);
    EXPECT_EQ(ret, CAMERA_OK);

    std::shared_ptr<TestCameraMngerCallback> setCallback = std::make_shared<TestCameraMngerCallback>("MgrCallback");
    cameraManager_->RegisterCameraStatusCallback(setCallback);
    ret = listenerManager->OnFlashlightStatusChanged(cameraId, status);
    EXPECT_EQ(ret, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test CameraManager with CreateCaptureSessionImpl
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateCaptureSessionImpl for tow branches of switch
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_011, TestSize.Level0)
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
}

/*
 * Feature: Framework
 * Function: Test CameraManager with CreateCaptureSession
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateCaptureSession for ConvertFwkToMetaMode
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_012, TestSize.Level0)
{
    SceneMode mode = PROFESSIONAL;
    EXPECT_NE(cameraManager_->CreateCaptureSession(mode), nullptr);

    mode = FLUORESCENCE_PHOTO;
    EXPECT_NE(cameraManager_->CreateCaptureSession(mode), nullptr);

    mode = QUICK_SHOT_PHOTO;
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
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_013, TestSize.Level0)
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
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_014, TestSize.Level0)
{
    DepthProfile depthProfile;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    ASSERT_NE(surface, nullptr);
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
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_015, TestSize.Level0)
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
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_016, TestSize.Level0)
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
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_017, TestSize.Level0)
{
    sptr<ICameraServiceCallback> callback = cameraManager_->GetCameraStatusListenerManager();
    ASSERT_NE(callback, nullptr);

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
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_018, TestSize.Level0)
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
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_019, TestSize.Level0)
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
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_020, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CameraOutputCapability> ability = cameraManager_->GetSupportedOutputCapability(cameras[0], 0);
    auto cameraProxy = CameraManager::g_cameraManager->GetServiceProxy();
    ASSERT_NE(cameraProxy, nullptr);
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata;
    std::string cameraId = cameras[0]->GetID();
    cameraProxy->GetCameraAbility(cameraId, metadata);
    ASSERT_NE(metadata, nullptr);
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
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_021, TestSize.Level0)
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
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_022, TestSize.Level0)
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
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_023, TestSize.Level0)
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
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_024, TestSize.Level0)
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
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_025, TestSize.Level0)
{
    auto listenerManager = cameraManager_->GetTorchServiceListenerManager();
    TorchStatus status1 = TorchStatus::TORCH_STATUS_UNAVAILABLE;
    TorchStatus status2 = TorchStatus::TORCH_STATUS_ON;

    EXPECT_NE(listenerManager->GetCameraManager(), nullptr);
    EXPECT_TRUE(listenerManager->GetListenerCount() == 0);
    auto ret = listenerManager->OnTorchStatusChange(status1);
    EXPECT_EQ(cameraManager_->torchMode_, TORCH_MODE_OFF);
    EXPECT_EQ(ret, CAMERA_OK);

    std::shared_ptr<TorchListener> listener = std::make_shared<TorchListenerImpl>();
    cameraManager_->RegisterTorchListener(listener);
    EXPECT_FALSE(listenerManager->GetListenerCount() == 0);
    ret = listenerManager->OnTorchStatusChange(status2);
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
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_026, TestSize.Level0)
{
    auto listenerManager = cameraManager_->GetTorchServiceListenerManager();
    listenerManager->ClearListeners();
    auto foldListenerManager = cameraManager_->GetFoldStatusListenerManager();
    FoldStatus status = FoldStatus::UNKNOWN_FOLD;

    EXPECT_NE(foldListenerManager->GetCameraManager(), nullptr);
    EXPECT_TRUE(listenerManager->GetListenerCount() == 0);
    auto ret = foldListenerManager->OnFoldStatusChanged(status);
    EXPECT_EQ(ret, CAMERA_OK);

    std::shared_ptr<TorchListener> listener = std::make_shared<TorchListenerImpl>();
    cameraManager_->RegisterTorchListener(listener);
    EXPECT_FALSE(listenerManager->GetListenerCount() == 0);
    ret = foldListenerManager->OnFoldStatusChanged(status);
    EXPECT_EQ(ret, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test get HostName
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get HostName
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_027, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(static_cast<int>(cameras.size()), 0);
    std::string hostName = cameras[0]->GetHostName();
    ASSERT_EQ(hostName, "");
}

/*
 * Feature: Framework
 * Function: Test get DeviceType
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get DeviceType
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_028, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(static_cast<int>(cameras.size()), 0);
    auto judgeDeviceType = [&cameras] () -> bool {
        bool isOk = false;
        uint16_t deviceType = cameras[0]->GetDeviceType();
        switch (deviceType) {
            case UNKNOWN:
            case PHONE:
            case TABLET:
                isOk = true;
                break;
            default:
                isOk = false;
                break;
        }
        return isOk;
    };
    ASSERT_NE(judgeDeviceType(), false);
}

/*
 * Feature: Framework
 * Function: Test get cameras
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get cameras
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_029, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_TRUE(cameras.size() != 0);
}

/*
 * Feature: Framework
 * Function: Test create input
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test create input
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_030, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_TRUE(cameras.size() != 0);
    sptr<CameraInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    ASSERT_NE(input->GetCameraDevice(), nullptr);

    input->Release();
}

/*
 * Feature: Framework
 * Function: Test create session
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test create session
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_031, TestSize.Level0)
{
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test create preview output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test create preview output
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_032, TestSize.Level0)
{
    int32_t width = PREVIEW_DEFAULT_WIDTH;
    int32_t height = PREVIEW_DEFAULT_HEIGHT;
    CameraFormat previewFormat = CAMERA_FORMAT_YUV_420_SP;
    Size previewSize;
    previewSize.width = width;
    previewSize.height = height;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    Profile previewProfile = Profile(previewFormat, previewSize);
    sptr<CaptureOutput> preview = cameraManager_->CreatePreviewOutput(previewProfile, surface);
    ASSERT_NE(preview, nullptr);
    preview->Release();
}

/*
 * Feature: Framework
 * Function: Test create preview output with surface as null
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test create preview output with surface as null
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_033, TestSize.Level0)
{
    int32_t width = PREVIEW_DEFAULT_WIDTH;
    int32_t height = PREVIEW_DEFAULT_HEIGHT;
    CameraFormat previewFormat = CAMERA_FORMAT_YUV_420_SP;
    Size previewSize;
    previewSize.width = width;
    previewSize.height = height;
    Profile previewProfile = Profile(previewFormat, previewSize);
    sptr<Surface> surface = nullptr;
    sptr<CaptureOutput> preview = cameraManager_->CreatePreviewOutput(previewProfile, surface);
    ASSERT_EQ(preview, nullptr);
}

/*
 * Feature: Framework
 * Function: Test create photo output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test create photo output
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_034, TestSize.Level0)
{
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    CameraFormat photoFormat = CAMERA_FORMAT_JPEG;
    Size photoSize;
    photoSize.width = width;
    photoSize.height = height;
    Profile photoProfile = Profile(photoFormat, photoSize);
    sptr<IBufferProducer> surfaceProducer = surface->GetProducer();
    sptr<PhotoOutput> photo = cameraManager_->CreatePhotoOutput(photoProfile, surfaceProducer);
    ASSERT_NE(photo, nullptr);
    photo->Release();
}

/*
 * Feature: Framework
 * Function: Test create photo output with surface as null
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test create photo output with surface as null
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_035, TestSize.Level0)
{
    int32_t width = PHOTO_DEFAULT_WIDTH;
    int32_t height = PHOTO_DEFAULT_HEIGHT;
    CameraFormat photoFormat = CAMERA_FORMAT_JPEG;
    Size photoSize;
    photoSize.width = width;
    photoSize.height = height;
    Profile photoProfile = Profile(photoFormat, photoSize);
    sptr<IBufferProducer> surfaceProducer = nullptr;
    sptr<PhotoOutput> photo = cameraManager_->CreatePhotoOutput(photoProfile, surfaceProducer);
    ASSERT_EQ(photo, nullptr);
}

/*
 * Feature: Framework
 * Function: Test create video output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test create video output
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_036, TestSize.Level0)
{
    int32_t width = VIDEO_DEFAULT_WIDTH;
    int32_t height = VIDEO_DEFAULT_HEIGHT;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    CameraFormat videoFormat = CAMERA_FORMAT_YUV_420_SP;
    Size videoSize;
    videoSize.width = width;
    videoSize.height = height;
    std::vector<int32_t> videoFramerates = {30, 30};
    VideoProfile videoProfile = VideoProfile(videoFormat, videoSize, videoFramerates);
    sptr<VideoOutput> video = cameraManager_->CreateVideoOutput(videoProfile, surface);
    ASSERT_NE(video, nullptr);
    video->Release();
}

/*
 * Feature: Framework
 * Function: Test create video output with surface as null
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test create video output with surface as null
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_037, TestSize.Level0)
{
    int32_t width = VIDEO_DEFAULT_WIDTH;
    int32_t height = VIDEO_DEFAULT_HEIGHT;
    CameraFormat videoFormat = CAMERA_FORMAT_YUV_420_SP;
    sptr<Surface> surface = nullptr;
    Size videoSize;
    videoSize.width = width;
    videoSize.height = height;
    std::vector<int32_t> videoFramerates = {30, 30};
    VideoProfile videoProfile = VideoProfile(videoFormat, videoSize, videoFramerates);
    sptr<VideoOutput> video = cameraManager_->CreateVideoOutput(videoProfile, surface);
    ASSERT_EQ(video, nullptr);
}

/*
 * Feature: Framework
 * Function: Test manager callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test manager callback
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_038, TestSize.Level0)
{
    std::shared_ptr<TestCameraMngerCallback> setCallback = std::make_shared<TestCameraMngerCallback>("MgrCallback");
    cameraManager_->RegisterCameraStatusCallback(setCallback);
    auto listenerManager = cameraManager_->GetCameraStatusListenerManager();
    ASSERT_TRUE(listenerManager->IsListenerExist(setCallback));
}

/*
 * Feature: Framework
 * Function: Test cameraManager with GetSupportedModes
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSupportedModes to get modes
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_039, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    cameras[0]->supportedModes_.clear();
    cameras[0]->supportedModes_.push_back(PORTRAIT);
    std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(cameras[0]);
    ASSERT_TRUE(modes.size() != 0);
}

/*
 * Feature: Framework
 * Function: Test cameraManager with GetSupportedOutputCapability
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSupportedOutputCapability to get capability
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_040, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    SceneMode mode = PORTRAIT;
    cameras[0]->supportedModes_.clear();
    cameras[0]->supportedModes_.push_back(PORTRAIT);
    std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(cameras[0]);
    ASSERT_TRUE(modes.size() != 0);

    sptr<CameraOutputCapability> ability = cameraManager_->GetSupportedOutputCapability(cameras[0], mode);
    ASSERT_NE(ability, nullptr);
}

/*
 * Feature: Framework
 * Function: Test cameramanager with updatetorchmode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameramanager with updatetorchmode
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_041, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    sptr<CameraOutputCapability> ability = cameraManager_->GetSupportedOutputCapability(cameras[0], 0);
    ASSERT_NE(ability, nullptr);
    SceneMode mode = PORTRAIT;
    TorchMode mode1 = TorchMode::TORCH_MODE_OFF;
    TorchMode mode2 = TorchMode::TORCH_MODE_ON;
    cameraManager_->torchMode_ = mode1;
    cameraManager_->UpdateTorchMode(mode1);
    cameraManager_->UpdateTorchMode(mode2);
    cameraManager_->SetServiceProxy(nullptr);
    EXPECT_EQ(cameraManager_->serviceProxyPrivate_, nullptr);
    sptr<CaptureSession> captureSession = cameraManager_->CreateCaptureSession(mode);
    EXPECT_EQ(captureSession, nullptr);
    cameraManager_->ClearCameraDeviceListCache();
    EXPECT_TRUE(cameraManager_->cameraDeviceList_.empty());
}

/*
 * Feature: Framework
 * Function: Test cameramanager with parsebasiccapability
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameramanager with parsebasiccapability
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_042, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    sptr<CameraOutputCapability> ability = cameraManager_->GetSupportedOutputCapability(cameras[0], 0);
    ASSERT_NE(ability, nullptr);
    auto cameraProxy = CameraManager::g_cameraManager->GetServiceProxy();
    ASSERT_NE(cameraProxy, nullptr);
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata;
    std::string cameraId = cameras[0]->GetID();
    cameraProxy->GetCameraAbility(cameraId, metadata);
    ASSERT_NE(metadata, nullptr);
    camera_metadata_item_t item;
    OHOS::Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS, &item);
    CameraManager::ProfilesWrapper wrapper = {};
    cameraManager_->ParseBasicCapability(wrapper, metadata, item);
    EXPECT_FALSE(wrapper.previewProfiles.empty());
}

/*
 * Feature: Framework
 * Function: Test cameramanager with no cameraid and cameraobjlist
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameramanager with no cameraid and cameraobjlist
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_043, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CameraOutputCapability> ability = cameraManager_->GetSupportedOutputCapability(cameras[0], 0);

    pid_t pid = 0;
    cameraManager_->CameraServerDied(pid);
    sptr<ICameraServiceCallback> cameraServiceCallback = nullptr;
    cameraManager_->SetCameraServiceCallback(cameraServiceCallback);
    sptr<ITorchServiceCallback> torchServiceCallback = nullptr;
    cameraManager_->SetTorchServiceCallback(torchServiceCallback);
    sptr<ICameraMuteServiceCallback> cameraMuteServiceCallback = nullptr;
    cameraManager_->SetCameraMuteServiceCallback(cameraMuteServiceCallback);
    float level = 9.2;
    int32_t ret = cameraManager_->SetTorchLevel(level);
    EXPECT_EQ(ret, 7400201);
    string cameraId = "";
    int activeTime = 0;
    EffectParam effectParam = {0, 0, 0};
    ret = cameraManager_->SetPrelaunchConfig(cameraId, RestoreParamTypeOhos::TRANSIENT_ACTIVE_PARAM_OHOS,
        activeTime, effectParam);
    EXPECT_EQ(ret, 7400201);
}

/*
 * Feature: Framework
 * Function: Test cameramanager with serviceProxy_ is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameramanager with serviceProxy_ is nullptr
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_044, TestSize.Level0)
{
    sptr<ICameraServiceCallback> callback = cameraManager_->GetCameraStatusListenerManager();
    ASSERT_NE(callback, nullptr);

    pid_t pid = 0;
    cameraManager_->SetServiceProxy(nullptr);
    cameraManager_->CameraServerDied(pid);
    sptr<ICameraServiceCallback> cameraServiceCallback = nullptr;
    cameraManager_->SetCameraServiceCallback(cameraServiceCallback);
    sptr<ITorchServiceCallback> torchServiceCallback = nullptr;
    cameraManager_->SetTorchServiceCallback(torchServiceCallback);
    sptr<ICameraMuteServiceCallback> cameraMuteServiceCallback = nullptr;
    cameraManager_->SetCameraMuteServiceCallback(cameraMuteServiceCallback);

    string cameraId = "";
    cameraManager_->GetCameraDeviceFromId(cameraId);
    bool isTorchSupported = cameraManager_->IsTorchSupported();
    EXPECT_EQ(isTorchSupported, false);
}

/*
 * Feature: Framework
 * Function: Test cameramanager with preswitchcamera
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameramanager with preswitchcamera
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_045, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    sptr<CameraOutputCapability> ability = cameraManager_->GetSupportedOutputCapability(cameras[0], 0);

    std::string cameraId = cameras[0]->GetID();
    int32_t ret = cameraManager_->PreSwitchCamera(cameraId);
    cameraManager_->SetServiceProxy(nullptr);
    ret = cameraManager_->PreSwitchCamera(cameraId);
    EXPECT_EQ(ret, 7400201);
}

/*
 * Feature: Framework
 * Function: Test CreateDeferredPhotoProcessingSession
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateDeferredPhotoProcessingSession
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_046, TestSize.Level0)
{
    sptr<DeferredPhotoProcSession> deferredProcSession;
    deferredProcSession = cameraManager_->CreateDeferredPhotoProcessingSession(userId_,
        std::make_shared<TestDeferredPhotoProcSessionCallback>());
    ASSERT_NE(deferredProcSession, nullptr);
}

/*
 * Feature: Framework
 * Function: Test cameraManager GetSupportedOutputCapability with yuv photo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameraManager GetSupportedOutputCapability with yuv photo
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_047, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();

    SceneMode mode = PORTRAIT;
    cameras[0]->supportedModes_.clear();
    cameras[0]->supportedModes_.push_back(PORTRAIT);
    std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(cameras[0]);
    ASSERT_TRUE(modes.size() != 0);

    sptr<CameraOutputCapability> ability = cameraManager_->GetSupportedOutputCapability(cameras[0], mode);
    ASSERT_NE(ability, nullptr);

    vector<Profile> photoProfiles = ability->GetPhotoProfiles();

    mode = SceneMode::CAPTURE;
    ability = cameraManager_->GetSupportedOutputCapability(cameras[0], mode);
    ASSERT_NE(ability, nullptr);
}

/*
 * Feature: Framework
 * Function: Verify that the method returns the correct list of cameras when the device is not foldable.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify that the method returns the correct list of cameras when the device is not foldable.
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_048, TestSize.Level0)
{
    cameraManager_->foldScreenType_ = "0";
    EXPECT_TRUE(cameraManager_->GetIsFoldable());
    std::vector<sptr<CameraDevice>> expectedCameraList;
    auto changedMetadata = std::make_shared<OHOS::Camera::CameraMetadata>(0, 0);
    auto camera0 = new CameraDevice("device0", changedMetadata);
    auto camera1 = new CameraDevice("device1", changedMetadata);
    auto camera2 = new CameraDevice("device2", changedMetadata);
    expectedCameraList.emplace_back(camera0);
    expectedCameraList.emplace_back(camera1);
    expectedCameraList.emplace_back(camera2);
    cameraManager_->cameraDeviceList_ = expectedCameraList;
    auto result = cameraManager_->GetSupportedCameras();
    ASSERT_EQ(result.size(), expectedCameraList.size());
}

/*
 * Feature: Framework
 * Function: The goal is to verify that the method correctly returns the list of supported cameras when the device is
              collapsible and in the "expand" state
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: The goal is to verify that the method correctly returns the list of supported cameras when the
               device is collapsible and in the "expand" state
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_049, TestSize.Level0)
{
    cameraManager_->foldScreenType_ = "0";
    EXPECT_TRUE(cameraManager_->GetIsFoldable());
    auto changedMetadata = std::make_shared<OHOS::Camera::CameraMetadata>(0, 0);
    int32_t cameraPosition = CAMERA_POSITION_BACK;
    changedMetadata->addEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, 1);
    int32_t foldStatus = OHOS_CAMERA_FOLD_STATUS_EXPANDED | OHOS_CAMERA_FOLD_STATUS_FOLDED;
    changedMetadata->addEntry(OHOS_ABILITY_CAMERA_FOLD_STATUS, &foldStatus, 1);
    auto camera0 = new CameraDevice("device0", changedMetadata);

    auto changedMetadata1 = std::make_shared<OHOS::Camera::CameraMetadata>(0, 0);
    cameraPosition = CAMERA_POSITION_FRONT;
    changedMetadata1->addEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, 1);
    foldStatus = OHOS_CAMERA_FOLD_STATUS_FOLDED;
    changedMetadata1->addEntry(OHOS_ABILITY_CAMERA_FOLD_STATUS, &foldStatus, 1);
    auto camera1 = new CameraDevice("device1", changedMetadata1);

    std::vector<sptr<CameraDevice>> expectedCameraList;
    expectedCameraList.emplace_back(camera0);
    expectedCameraList.emplace_back(camera1);
    cameraManager_->cameraDeviceList_ = expectedCameraList;
    auto result = cameraManager_->GetSupportedCameras();

    ASSERT_EQ(result.size(), 1);
}

/*
 * Feature: Framework
 * Function: In the scenario where the device is foldable and in a folded state, the goal is to ensure that the method
             correctly returns the list of cameras that support the current folded state.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: In the scenario where the device is foldable and in a folded state, the goal is to ensure that the
              method correctly returns the list of cameras that support the current folded state.
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_050, TestSize.Level0)
{
    sptr<MockCameraManager> mockCameraManager = new MockCameraManager();
    EXPECT_CALL(*mockCameraManager, GetIsFoldable())
        .WillRepeatedly(testing::Return(true));

    EXPECT_CALL(*mockCameraManager, GetFoldStatus())
        .WillRepeatedly(testing::Return(FoldStatus::FOLDED));

    auto changedMetadata = std::make_shared<OHOS::Camera::CameraMetadata>(0, 0);
    int32_t cameraPosition = CAMERA_POSITION_BACK;
    changedMetadata->addEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, 1);
    int32_t foldStatus = OHOS_CAMERA_FOLD_STATUS_EXPANDED | OHOS_CAMERA_FOLD_STATUS_FOLDED;
    changedMetadata->addEntry(OHOS_ABILITY_CAMERA_FOLD_STATUS, &foldStatus, 1);
    auto camera0 = new CameraDevice("device0", changedMetadata);

    auto changedMetadata1 = std::make_shared<OHOS::Camera::CameraMetadata>(0, 0);
    cameraPosition = CAMERA_POSITION_FRONT;
    changedMetadata1->addEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, 1);
    foldStatus = OHOS_CAMERA_FOLD_STATUS_FOLDED;
    changedMetadata1->addEntry(OHOS_ABILITY_CAMERA_FOLD_STATUS, &foldStatus, 1);
    auto camera1 = new CameraDevice("device1", changedMetadata1);

    std::vector<sptr<CameraDevice>> expectedCameraList;
    expectedCameraList.emplace_back(camera0);
    expectedCameraList.emplace_back(camera1);
    mockCameraManager->cameraDeviceList_ = expectedCameraList;
    auto result = mockCameraManager->GetSupportedCameras();

    ASSERT_EQ(result.size(), 2);
}

/*
 * Feature: Framework
 * Function: The unit test get_supported_cameras_foldable_half_fold checks the behavior of the
             CameraManager::GetSupportedCameras method when the device is foldable and in a half-folded state.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: The unit test get_supported_cameras_foldable_half_fold checks the behavior of the
             CameraManager::GetSupportedCameras method when the device is foldable and in a half-folded state.
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_051, TestSize.Level0)
{
    cameraManager_->foldScreenType_ = "0";
    EXPECT_TRUE(cameraManager_->GetIsFoldable());

    auto changedMetadata = std::make_shared<OHOS::Camera::CameraMetadata>(0, 0);
    int32_t cameraPosition = CAMERA_POSITION_BACK;
    changedMetadata->addEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, 1);
    int32_t foldStatus = OHOS_CAMERA_FOLD_STATUS_EXPANDED | OHOS_CAMERA_FOLD_STATUS_FOLDED;
    changedMetadata->addEntry(OHOS_ABILITY_CAMERA_FOLD_STATUS, &foldStatus, 1);
    auto camera0 = new CameraDevice("device0", changedMetadata);

    auto changedMetadata1 = std::make_shared<OHOS::Camera::CameraMetadata>(0, 0);
    cameraPosition = CAMERA_POSITION_FRONT;
    changedMetadata1->addEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, 1);
    foldStatus = OHOS_CAMERA_FOLD_STATUS_FOLDED;
    changedMetadata1->addEntry(OHOS_ABILITY_CAMERA_FOLD_STATUS, &foldStatus, 1);
    auto camera1 = new CameraDevice("device1", changedMetadata1);

    std::vector<sptr<CameraDevice>> expectedCameraList;
    expectedCameraList.emplace_back(camera0);
    expectedCameraList.emplace_back(camera1);
    cameraManager_->cameraDeviceList_ = expectedCameraList;
    auto result = cameraManager_->GetSupportedCameras();
    ASSERT_EQ(result.size(), 1);
}

/*
 * Feature: Framework
 * Function: Test cameraManager with GetInstance
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameraManager with GetInstance
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_052, TestSize.Level0)
{
    sptr<CameraManager>& manager = cameraManager_->GetInstance();
    ASSERT_NE(manager, nullptr);
}

/*
 * Feature: Framework
 * Function: Test CreateDeferredVideoProcessingSession
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateDeferredVideoProcessingSession
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_053, TestSize.Level0)
{
    sptr<DeferredVideoProcSession> deferredVideoProcSession;
    deferredVideoProcSession = cameraManager_->CreateDeferredVideoProcessingSession(userId_,
        std::make_shared<IDeferredVideoProcSessionCallbackTest>());
    ASSERT_NE(deferredVideoProcSession, nullptr);
}

/*
 * Feature: Framework
 * Function: Test GetCameras and GetCameraOutputStatus
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCameras and GetCameraOutputStatus
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_054, TestSize.Level0)
{
    int32_t status = 0;
    cameraManager_->serviceProxyPrivate_ = nullptr;
    cameraManager_->GetCameraOutputStatus(0, status);

    std::vector<sptr<CameraInfo>> getCameras = cameraManager_->GetCameras();
    EXPECT_TRUE(getCameras.empty());
}

/*
 * Feature: Framework
 * Function: Test SetCameraManagerNull and SetFoldServiceCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetCameraManagerNull and SetFoldServiceCallback
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_055, TestSize.Level0)
{
    cameraManager_->serviceProxyPrivate_ = nullptr;
    sptr<IFoldServiceCallback> foldSvcCallback = cameraManager_->GetFoldStatusListenerManager();
    cameraManager_->SetFoldServiceCallback(foldSvcCallback);
    cameraManager_->SetCameraManagerNull();
    EXPECT_EQ(CameraManager::g_cameraManager, nullptr);
}

/*
 * Feature: Framework
 * Function: Test CreateMetadataOutput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateMetadataOutput
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_056, TestSize.Level0)
{
    sptr<MetadataOutput> pMetadataOutput = nullptr;
    std::vector<MetadataObjectType> metadataObjectTypes;
    metadataObjectTypes.push_back(MetadataObjectType::INVALID);
    int ret = cameraManager_->CreateMetadataOutput(pMetadataOutput, metadataObjectTypes);
    EXPECT_EQ(ret, INVALID_ARGUMENT);
}

/*
 * Feature: Framework
 * Function: Test GetFoldListener
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetFoldListener
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_057, TestSize.Level0)
{
    std::shared_ptr<FoldListener> listener = std::make_shared<FoldListenerTest>();
    cameraManager_->GetFoldStatusListenerManager()->AddListener(listener);
    EXPECT_TRUE(cameraManager_->GetFoldStatusListenerManager()->IsListenerExist(listener));
}

/*
 * Feature: Framework
 * Function: Test GetCameraMuteListener
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCameraMuteListener
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_059, TestSize.Level0)
{
    std::shared_ptr<CameraMuteListener> listener = std::make_shared<CameraMuteListenerTest>();
    cameraManager_->GetCameraMuteListenerManager()->AddListener(listener);
    EXPECT_TRUE(cameraManager_->GetCameraMuteListenerManager()->IsListenerExist(listener));
}

/*
 * Feature: Framework
 * Function: Test GetTorchMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetTorchMode
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_060, TestSize.Level0)
{
    cameraManager_->torchMode_ = TorchMode::TORCH_MODE_AUTO;
    TorchMode ret = cameraManager_->GetTorchMode();
    EXPECT_EQ(ret, TorchMode::TORCH_MODE_AUTO);
}

/*
 * Feature: Framework
 * Function: Test MuteCameraPersist
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test MuteCameraPersist
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_061, TestSize.Level0)
{
    cameraManager_->serviceProxyPrivate_ = nullptr;
    PolicyType type = PolicyType::PRIVACY;
    bool mode = false;
    int32_t ret = cameraManager_->MuteCameraPersist(type, mode);
    EXPECT_EQ(ret, SERVICE_FATL_ERROR);
}

/*
 * Feature: Framework
 * Function: Test RequireMemorySize
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test RequireMemorySize
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_062, TestSize.Level0)
{
    cameraManager_->serviceProxyPrivate_ = nullptr;
    int32_t size = 16;
    int32_t ret = cameraManager_->RequireMemorySize(size);
    EXPECT_EQ(ret, SERVICE_FATL_ERROR);
}

/*
 * Feature: Framework
 * Function: Test CreateProfile4StreamType
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateProfile4StreamType
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_063, TestSize.Level0)
{
    StreamRelatedInfo info_1;
    info_1.detailInfoCount = 0;
    ModeInfo info_2;
    info_2.streamInfo.push_back(info_1);
    ExtendInfo info_3;
    info_3.modeInfo.push_back(info_2);
    MockCameraManager::ProfilesWrapper profile;
    OutputCapStreamType type = OutputCapStreamType::PREVIEW;
    cameraManager_->CreateProfile4StreamType(profile, type, 0, 0, info_3);
    EXPECT_TRUE(profile.previewProfiles.empty());
}

/*
 * Feature: Framework
 * Function: Test CameraManager with SetTorchMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetTorchMode for abnormal branch
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_064, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_TRUE(cameras.size() != 0);
    cameraManager_->ReportEvent(cameras[0]->GetID());
    CameraStatusInfo info;
    int32_t ret = cameraManager_->SetTorchMode(static_cast<TorchMode>(-1));
    EXPECT_EQ(ret, OPERATION_NOT_ALLOWED);
}

/*
 * Feature: Framework
 * Function: Test TorchServiceCallback and FoldServiceCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test TorchServiceCallback and FoldServiceCallback
 */
HWTEST_F(CameraFrameWorkManagerUnit, camera_framework_manager_unittest_065, TestSize.Level0)
{
    sptr<ITorchServiceCallback> torchServiceCallback = cameraManager_->GetTorchServiceListenerManager();
    ASSERT_NE(torchServiceCallback, nullptr);
    sptr<IFoldServiceCallback> foldServiceCallback = cameraManager_->GetFoldStatusListenerManager();
    ASSERT_NE(foldServiceCallback, nullptr);
}

}
}