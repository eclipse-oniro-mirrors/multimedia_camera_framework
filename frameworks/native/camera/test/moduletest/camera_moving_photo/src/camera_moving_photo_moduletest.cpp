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

#include "camera_moving_photo_moduletest.h"

#include "accesstoken_kit.h"
#include "camera_error_code.h"
#include "camera_log.h"
#include "camera_util.h"
#include "camera_photo_proxy.h"
#include "hap_token_info.h"
#include "ipc_skeleton.h"
#include "media_asset_capi.h"
#include "media_asset_helper.h"
#include "media_access_helper_capi.h"
#include "media_asset_change_request_capi.h"
#include "media_photo_asset_proxy.h"
#include "native_image.h"
#include "nativetoken_kit.h"
#include "securec.h"
#include "system_ability_definition.h"
#include "test_common.h"
#include "token_setproc.h"
#include "os_account_manager.h"
#include "video_key_info.h"
#include "userfile_manager_types.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
static std::mutex g_mutex;
const char* DEFAULT_SURFACEID = "photoOutput";

OH_MediaAsset *CameraMovingPhotoModuleTest::mediaAsset_ = nullptr;
OH_MovingPhoto *CameraMovingPhotoModuleTest::movingPhoto_ = nullptr;
OH_MediaAssetManager *CameraMovingPhotoModuleTest::mediaAssetManager_ = nullptr;

PhotoListenerTest::PhotoListenerTest(PhotoOutput* photoOutput, sptr<Surface> surface)
    : photoOutput_(photoOutput), photoSurface_(surface)
{
    MEDIA_DEBUG_LOG("movingp photo module test photoListenerTest structure");
}

PhotoListenerTest::~PhotoListenerTest()
{
    photoSurface_ = nullptr;
}

void PhotoListenerTest::OnBufferAvailable()
{
    MEDIA_INFO_LOG("PhotoListenerTest::OnBufferAvailable");
    std::lock_guard<std::mutex> lock(g_mutex);
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("PhotoListenerTest::OnBufferAvailable is called");
    CHECK_ERROR_RETURN_LOG(photoSurface_ == nullptr, "photoSurface_ is null");

    int64_t timestamp;
    OHOS::Rect damage;
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    int32_t fence = -1;
    SurfaceError surfaceRet = photoSurface_->AcquireBuffer(surfaceBuffer, fence, timestamp, damage);
    CHECK_ERROR_RETURN_LOG(surfaceRet != SURFACE_ERROR_OK, "Failed to acquire surface buffer");

    CameraBufferExtraData extraData = GetCameraBufferExtraData(surfaceBuffer);

    if ((callbackFlag_ & CAPTURE_PHOTO_ASSET) != 0) {
        MEDIA_DEBUG_LOG("PhotoListenerTest on capture photo asset callback");
        sptr<SurfaceBuffer> newSurfaceBuffer = SurfaceBuffer::Create();
        DeepCopyBuffer(newSurfaceBuffer, surfaceBuffer);
        photoSurface_->ReleaseBuffer(surfaceBuffer, -1);
        CHECK_ERROR_RETURN_LOG(newSurfaceBuffer == nullptr, "deep copy buffer failed");

        ExecutePhotoAsset(newSurfaceBuffer, extraData, extraData.isDegradedImage == 0, timestamp);
        MEDIA_DEBUG_LOG("PhotoListenerTest on capture photo asset callback end");
    } else if (extraData.isDegradedImage == 0 && (callbackFlag_ & CAPTURE_PHOTO) != 0) {
        MEDIA_DEBUG_LOG("PhotoListenerTest on capture photo callback");
        photoSurface_->ReleaseBuffer(surfaceBuffer, -1);
    } else {
        MEDIA_INFO_LOG("PhotoListenerTest on error callback");
        photoSurface_->ReleaseBuffer(surfaceBuffer, -1);
    }
}

void PhotoListenerTest::SetCallbackFlag(uint8_t callbackFlag)
{
    callbackFlag_ = callbackFlag;
}

void PhotoListenerTest::SetPhotoAssetAvailableCallback(PhotoOutputTest_PhotoAssetAvailable callback)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    MEDIA_INFO_LOG("PhotoListenerTest::SetPhotoAssetAvailableCallback is called");
    if (callback != nullptr) {
        photoAssetCallback_ = callback;
    }
}

void PhotoListenerTest::UnregisterPhotoAssetAvailableCallback(PhotoOutputTest_PhotoAssetAvailable callback)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    MEDIA_INFO_LOG("PhotoListenerTest::UnregisterPhotoAssetAvailableCallback is called");
    if (photoAssetCallback_ != nullptr && callback != nullptr) {
        photoAssetCallback_ = nullptr;
    }
}

void PhotoListenerTest::ExecutePhotoAsset(sptr<SurfaceBuffer> surfaceBuffer, CameraBufferExtraData extraData,
    bool isHighQuality, int64_t timestamp)
{
    CAMERA_SYNC_TRACE;
    BufferHandle* bufferHandle = surfaceBuffer->GetBufferHandle();
    CHECK_ERROR_RETURN_LOG(bufferHandle == nullptr, "invalid bufferHandle");

    surfaceBuffer->Map();
    std::string uri = "";
    int32_t cameraShotType = 0;
    std::string burstKey = "";
    CreateMediaLibrary(surfaceBuffer, bufferHandle, extraData, isHighQuality,
        uri, cameraShotType, burstKey, timestamp);
    CHECK_ERROR_RETURN_LOG(uri.empty(), "uri is empty");

    auto mediaAssetHelper = Media::MediaAssetHelperFactory::CreateMediaAssetHelper();
    CHECK_ERROR_RETURN_LOG(mediaAssetHelper == nullptr, "create media asset helper failed");

    auto mediaAsset = mediaAssetHelper->GetMediaAsset(uri, cameraShotType, burstKey);
    CHECK_ERROR_RETURN_LOG(mediaAsset == nullptr, "Create photo asset failed");

    if (photoAssetCallback_ != nullptr && photoOutput_ != nullptr) {
        photoAssetCallback_(photoOutput_, mediaAsset);
    }
}

void PhotoListenerTest::DeepCopyBuffer(sptr<SurfaceBuffer> newSurfaceBuffer, sptr<SurfaceBuffer> surfaceBuffer)
{
    CAMERA_SYNC_TRACE;
    BufferRequestConfig requestConfig = {
        .width = surfaceBuffer->GetWidth(),
        .height = surfaceBuffer->GetHeight(),
        .strideAlignment = 0x8, // default stride is 8 Bytes.
        .format = surfaceBuffer->GetFormat(),
        .usage = surfaceBuffer->GetUsage(),
        .timeout = 0,
        .colorGamut = surfaceBuffer->GetSurfaceBufferColorGamut(),
        .transform = surfaceBuffer->GetSurfaceBufferTransform(),
    };
    auto allocErrorCode = newSurfaceBuffer->Alloc(requestConfig);
    MEDIA_INFO_LOG("SurfaceBuffer alloc ret: %d", allocErrorCode);
    if (memcpy_s(newSurfaceBuffer->GetVirAddr(), newSurfaceBuffer->GetSize(),
        surfaceBuffer->GetVirAddr(), surfaceBuffer->GetSize()) != EOK) {
        MEDIA_ERR_LOG("PhotoListener memcpy_s failed");
    }
}

void PhotoListenerTest::CreateMediaLibrary(sptr<SurfaceBuffer> surfaceBuffer, BufferHandle *bufferHandle,
    CameraBufferExtraData extraData, bool isHighQuality, std::string &uri,
    int32_t &cameraShotType, std::string &burstKey, int64_t timestamp)
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_LOG(bufferHandle == nullptr, "bufferHandle is nullptr");

    int32_t format = bufferHandle->format;
    sptr<CameraPhotoProxy> photoProxy;
    std::string imageIdStr = std::to_string(extraData.imageId);
    photoProxy = new(std::nothrow) CameraPhotoProxy(bufferHandle, format, extraData.photoWidth, extraData.photoHeight,
        isHighQuality, extraData.captureId);
    CHECK_ERROR_RETURN_LOG(photoProxy == nullptr, "Failed to new photoProxy");

    photoProxy->SetDeferredAttrs(imageIdStr, extraData.deferredProcessingType, extraData.size,
        extraData.deferredImageFormat);
    if (photoOutput_ && photoOutput_->GetSession()) {
        auto settings = photoOutput_->GetDefaultCaptureSetting();
        if (settings) {
            auto location = std::make_shared<Location>();
            settings->GetLocation(location);
            photoProxy->SetLocation(location->latitude, location->longitude);
        }
        photoOutput_->CreateMediaLibrary(photoProxy, uri, cameraShotType, burstKey, timestamp);
    }
}

CameraBufferExtraData PhotoListenerTest::GetCameraBufferExtraData(const sptr<SurfaceBuffer> &surfaceBuffer)
{
    CameraBufferExtraData extraData;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::captureId, extraData.captureId);
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::imageId, extraData.imageId);
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::deferredProcessingType, extraData.deferredProcessingType);
    MEDIA_INFO_LOG("imageId:%{public}" PRId64
                   ", deferredProcessingType:%{public}d",
        extraData.imageId,
        extraData.deferredProcessingType);

    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::dataWidth, extraData.photoWidth);
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::dataHeight, extraData.photoHeight);
    uint64_t size = static_cast<uint64_t>(surfaceBuffer->GetSize());

    auto res = surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::dataSize, extraData.extraDataSize);
    if (res != 0) {
        MEDIA_INFO_LOG("ExtraGet dataSize error %{public}d", res);
    } else if (extraData.extraDataSize <= 0) {
        MEDIA_INFO_LOG("ExtraGet dataSize OK, but size <= 0");
    } else if (static_cast<uint64_t>(extraData.extraDataSize) > size) {
        MEDIA_INFO_LOG("ExtraGet dataSize OK, but dataSize %{public}d is bigger "
                       "than bufferSize %{public}" PRIu64,
            extraData.extraDataSize,
            size);
    } else {
        MEDIA_INFO_LOG("ExtraGet dataSize %{public}d", extraData.extraDataSize);
        size = static_cast<uint64_t>(extraData.extraDataSize);
    }
    extraData.size = size;

    res = surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::deferredImageFormat, extraData.deferredImageFormat);
    MEDIA_INFO_LOG("deferredImageFormat:%{public}d, width:%{public}d, "
                   "height:%{public}d, size:%{public}" PRId64,
        extraData.deferredImageFormat,
        extraData.photoWidth,
        extraData.photoHeight,
        size);

    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::isDegradedImage, extraData.isDegradedImage);
    MEDIA_INFO_LOG("isDegradedImage:%{public}d", extraData.isDegradedImage);

    return extraData;
}

void CameraMovingPhotoModuleTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraMovingPhotoModuleTest::SetUpTestCase started!");
}

void CameraMovingPhotoModuleTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraMovingPhotoModuleTest::TearDownTestCase started!");
}

void CameraMovingPhotoModuleTest::SetUp()
{
    MEDIA_INFO_LOG("CameraMovingPhotoModuleTest::SetUp start!");
    NativeAuthorization();

    manager_ = CameraManager::GetInstance();
    ASSERT_NE(manager_, nullptr);
    cameras_ = manager_->GetSupportedCameras();
    ASSERT_FALSE(cameras_.empty());
    session_ = manager_->CreateCaptureSession(SceneMode::CAPTURE);
    ASSERT_NE(session_, nullptr);
    input_ = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input_, nullptr);
    EXPECT_EQ(input_->Open(), SUCCESS);

    UpdataCameraOutputCapability();
    EXPECT_EQ(CreatePreviewOutput(previewProfile_[0], previewOutput_), SUCCESS);
    EXPECT_EQ(CreatePhotoOutputWithoutSurface(photoProfile_[0], photoOutput_), SUCCESS);

    MEDIA_INFO_LOG("CameraMovingPhotoModuleTest::SetUp end!");
}

void CameraMovingPhotoModuleTest::TearDown()
{
    MEDIA_INFO_LOG("CameraMovingPhotoModuleTest::TearDown start!");

    cameras_.clear();
    photoProfile_.clear();
    previewProfile_.clear();

    photoOutput_->Release();
    previewOutput_->Release();

    manager_ = nullptr;
    input_->Release();
    session_->Release();

    if (photoSurface_) {
        photoSurface_ = nullptr;
    }
    if (photoListener_) {
        photoListener_ =nullptr;
    }
    ReleaseMediaAsset();

    MEDIA_INFO_LOG("CameraMovingPhotoModuleTest::TearDown end!");
}

void CameraMovingPhotoModuleTest::NativeAuthorization()
{
    const char *perms[6];
    perms[0] = "ohos.permission.CAMERA";
    perms[1] = "ohos.permission.MICROPHONE";
    perms[2] = "ohos.permission.READ_MEDIA";
    perms[3] = "ohos.permission.WRITE_MEDIA";
    perms[4] = "ohos.permission.READ_IMAGEVIDEO";
    perms[5] = "ohos.permission.WRITE_IMAGEVIDEO";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 6,
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
    MEDIA_DEBUG_LOG("CameraMovingPhotoModuleTest::NativeAuthorization uid:%{public}d", uid_);
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

void CameraMovingPhotoModuleTest::UpdataCameraOutputCapability(int32_t modeName)
{
    if (!manager_ || cameras_.empty()) {
        return;
    }
    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], modeName);
    ASSERT_NE(outputCapability, nullptr);

    previewProfile_ = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfile_.empty());

    photoProfile_ = outputCapability->GetPhotoProfiles();
    ASSERT_FALSE(photoProfile_.empty());
}

int32_t CameraMovingPhotoModuleTest::RegisterPhotoAssetAvailableCallback(
    PhotoOutputTest_PhotoAssetAvailable callback)
{
    CHECK_ERROR_RETURN_RET_LOG(photoSurface_ == nullptr, INVALID_ARGUMENT,
        "Photo surface is invalid");
    if (photoListener_ == nullptr) {
        photoListener_ = new (std::nothrow) PhotoListenerTest(photoOutput_, photoSurface_);
        CHECK_ERROR_RETURN_RET_LOG(photoListener_ == nullptr, SERVICE_FATL_ERROR,
            "Create photo listener failed");

        SurfaceError ret = photoSurface_->RegisterConsumerListener((sptr<IBufferConsumerListener>&)photoListener_);
        CHECK_ERROR_RETURN_RET_LOG(ret != SURFACE_ERROR_OK, SERVICE_FATL_ERROR,
            "Register surface consumer listener failed");
    }
    photoListener_->SetPhotoAssetAvailableCallback(callback);
    callbackFlag_ |= CAPTURE_PHOTO_ASSET;
    photoListener_->SetCallbackFlag(callbackFlag_);
    photoOutput_->SetCallbackFlag(callbackFlag_);
    return SUCCESS;
}

int32_t CameraMovingPhotoModuleTest::UnregisterPhotoAssetAvailableCallback(
    PhotoOutputTest_PhotoAssetAvailable callback)
{
    if (callback != nullptr) {
        if (photoListener_ != nullptr) {
            callbackFlag_ &= ~CAPTURE_PHOTO_ASSET;
            photoListener_->SetCallbackFlag(callbackFlag_);
            photoListener_->UnregisterPhotoAssetAvailableCallback(callback);
        }
    }
    return SUCCESS;
}

int32_t CameraMovingPhotoModuleTest::CreatePreviewOutput(Profile &profile, sptr<PreviewOutput> &previewOutput)
{
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    if (surface == nullptr) {
        MEDIA_ERR_LOG("Failed to get previewOutput surface");
        return INVALID_ARGUMENT;
    }
    surface->SetUserData(CameraManager::surfaceFormat, std::to_string(profile.GetCameraFormat()));
    int32_t retCode = manager_->CreatePreviewOutput(profile, surface, &previewOutput);
    if (retCode != CameraErrorCode::SUCCESS) {
        return SERVICE_FATL_ERROR;
    }
    return SUCCESS;
}

int32_t CameraMovingPhotoModuleTest::CreatePhotoOutputWithoutSurface(Profile &profile,
    sptr<PhotoOutput> &photoOutput)
{
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer(DEFAULT_SURFACEID);
    CHECK_ERROR_RETURN_RET_LOG(surface == nullptr, INVALID_ARGUMENT,
        "Failed to get photoOutput surface");

    photoSurface_ = surface;
    surface->SetUserData(CameraManager::surfaceFormat, std::to_string(profile.GetCameraFormat()));
    sptr<IBufferProducer> surfaceProducer = surface->GetProducer();
    CHECK_ERROR_RETURN_RET_LOG(surfaceProducer == nullptr, SERVICE_FATL_ERROR, "Get producer failed");

    int32_t retCode = manager_->CreatePhotoOutput(profile, surfaceProducer, &photoOutput_);
    CHECK_ERROR_RETURN_RET_LOG((retCode != CameraErrorCode::SUCCESS || photoOutput_ == nullptr),
        SERVICE_FATL_ERROR, "Create photo output failed");

    photoOutput_->SetNativeSurface(true);
    return SUCCESS;
}

void CameraMovingPhotoModuleTest::onPhotoAssetAvailable(PhotoOutput *photoOutput, OH_MediaAsset *mediaAsset)
{
    MEDIA_INFO_LOG("CameraMovingPhotoModuleTest::onPhotoAssetAvailable");
    mediaAsset_ = mediaAsset;
}

void CameraMovingPhotoModuleTest::onMovingPhotoDataPrepared(MediaLibrary_ErrorCode result,
    MediaLibrary_RequestId requestId, MediaLibrary_MediaQuality mediaQuality,
    MediaLibrary_MediaContentType type, OH_MovingPhoto* movingPhoto)
{
    MEDIA_INFO_LOG("CameraMovingPhotoModuleTest::onMovingPhotoDataPrepared");
    if (!movingPhoto) {
        MEDIA_ERR_LOG("CameraMovingPhotoModuleTest::onMovingPhotoDataPrepared moving photo is nullptr");
        return;
    }
    movingPhoto_ = movingPhoto;

    OH_MediaAssetChangeRequest *changeRequest_ = OH_MediaAssetChangeRequest_Create(mediaAsset_);
    if (!changeRequest_) {
        MEDIA_ERR_LOG("CameraMovingPhotoModuleTest::onMovingPhotoDataPrepared create media asset change request fail");
        return;
    }

    MediaLibrary_ErrorCode errCode = OH_MediaAssetChangeRequest_SaveCameraPhoto(changeRequest_,
        MediaLibrary_ImageFileType::MEDIA_LIBRARY_IMAGE_JPEG);
    if (errCode != MEDIA_LIBRARY_OK) {
        MEDIA_ERR_LOG("CameraMovingPhotoModuleTest::onMovingPhotoDataPrepared save camera photo fail");
        return;
    }

    errCode = OH_MediaAccessHelper_ApplyChanges(changeRequest_);
    if (errCode != MEDIA_LIBRARY_OK) {
        MEDIA_ERR_LOG("CameraMovingPhotoModuleTest::onMovingPhotoDataPrepared apply changes fail");
        return;
    }

    const char *uri = nullptr;
    errCode = OH_MovingPhoto_GetUri(movingPhoto_, &uri);
    if (errCode != MEDIA_LIBRARY_OK || uri == nullptr) {
        MEDIA_ERR_LOG("CameraMovingPhotoModuleTest::onMovingPhotoDataPrepared get uri fail");
        return;
    }
    MEDIA_INFO_LOG("CameraMovingPhotoModuleTest::onMovingPhotoDataPrepared get uri is %{public}s", uri);

    errCode = OH_MediaAssetChangeRequest_Release(changeRequest_);
    if (errCode != MEDIA_LIBRARY_OK) {
        MEDIA_ERR_LOG("CameraMovingPhotoModuleTest::onMovingPhotoDataPrepared release change request fail");
        return;
    }
}

int32_t CameraMovingPhotoModuleTest::MediaAssetManagerRequestMovingPhoto(
    OH_MediaLibrary_OnMovingPhotoDataPrepared callback)
{
    mediaAssetManager_ = OH_MediaAssetManager_Create();
    CHECK_ERROR_RETURN_RET_LOG(mediaAssetManager_ == nullptr, SERVICE_FATL_ERROR,
        "Create media asset manager failed");

    MediaLibrary_RequestId requestId;
    MediaLibrary_RequestOptions requestOptions;
    requestOptions.deliveryMode = MEDIA_LIBRARY_HIGH_QUALITY_MODE;
    int32_t result = OH_MediaAssetManager_RequestMovingPhoto(mediaAssetManager_, mediaAsset_, requestOptions,
        &requestId, callback);
    CHECK_ERROR_RETURN_RET_LOG(result != MEDIA_LIBRARY_OK, SERVICE_FATL_ERROR,
        "media asset manager request moving photo failed");
    return SUCCESS;
}

void CameraMovingPhotoModuleTest::ReleaseMediaAsset()
{
    if (mediaAsset_) {
        OH_MediaAsset_Release(mediaAsset_);
        mediaAsset_ = nullptr;
    }
    if (movingPhoto_) {
        OH_MovingPhoto_Release(movingPhoto_);
        movingPhoto_ = nullptr;
    }
    if (mediaAssetManager_) {
        OH_MediaAssetManager_Release(mediaAssetManager_);
        mediaAssetManager_ = nullptr;
    }
}

/*
 * Feature: Framework
 * Function: Test the normal scenario of movingphoto.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the normal scenario of movingphoto,Call the EnableMovingPhoto function
 * after submitting the camera settings,and expect the movingphoto feature can be turned on successfully.
 */
HWTEST_F(CameraMovingPhotoModuleTest, camera_moving_photo_moduletest_001, TestSize.Level0)
{
    EXPECT_EQ(session_->BeginConfig(), SUCCESS);
    EXPECT_EQ(session_->AddInput((sptr<CaptureInput>&)input_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)previewOutput_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)photoOutput_), SUCCESS);
    EXPECT_EQ(session_->CommitConfig(), SUCCESS);

    if (session_->IsMovingPhotoSupported()) {
        session_->LockForControl();
        EXPECT_EQ(session_->EnableMovingPhoto(true), CameraErrorCode::SUCCESS);
        session_->UnlockForControl();
    }

    EXPECT_EQ(session_->Start(), SUCCESS);
    sleep(WAIT_TIME_AFTER_START);

    EXPECT_EQ(photoOutput_->Capture(), SUCCESS);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    EXPECT_EQ(session_->Stop(), SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test the abnormal scenario of movingphoto.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the abnormal scenario of movingphoto,Call the EnableMovingPhoto function then tunrn off
 * after submitting the camera settings,and expect the movingphoto feature can not be turned on successfully.
 */
HWTEST_F(CameraMovingPhotoModuleTest, camera_moving_photo_moduletest_002, TestSize.Level0)
{
    EXPECT_EQ(session_->BeginConfig(), SUCCESS);
    EXPECT_EQ(session_->AddInput((sptr<CaptureInput>&)input_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)previewOutput_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)photoOutput_), SUCCESS);
    EXPECT_EQ(session_->CommitConfig(), SUCCESS);

    if (session_->IsMovingPhotoSupported()) {
        session_->LockForControl();
        EXPECT_EQ(session_->EnableMovingPhoto(true), CameraErrorCode::SUCCESS);
        session_->UnlockForControl();
        EXPECT_EQ(session_->IsMovingPhotoEnabled(), true);
        session_->LockForControl();
        EXPECT_EQ(session_->EnableMovingPhoto(false), CameraErrorCode::SUCCESS);
        session_->UnlockForControl();
        EXPECT_EQ(session_->IsMovingPhotoEnabled(), false);
    }

    EXPECT_EQ(session_->Start(), SUCCESS);
    sleep(WAIT_TIME_AFTER_START);

    EXPECT_EQ(photoOutput_->Capture(), SUCCESS);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    EXPECT_EQ(session_->Stop(), SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test the normal scenario of movingphoto.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the normal scenario of movingphoto,Call the EnableMovingPhotoMirror function
 * after submitting the camera settings,and expect the movingphotomirror feature can be turned on successfully.
 */
HWTEST_F(CameraMovingPhotoModuleTest, camera_moving_photo_moduletest_003, TestSize.Level0)
{
    EXPECT_EQ(session_->BeginConfig(), SUCCESS);
    EXPECT_EQ(session_->AddInput((sptr<CaptureInput>&)input_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)previewOutput_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)photoOutput_), SUCCESS);
    EXPECT_EQ(session_->CommitConfig(), SUCCESS);

    if (session_->IsMovingPhotoSupported()) {
        session_->LockForControl();
        EXPECT_EQ(session_->EnableMovingPhoto(true), CameraErrorCode::SUCCESS);
        session_->UnlockForControl();
        EXPECT_EQ(session_->EnableMovingPhotoMirror(true, true), CameraErrorCode::SUCCESS);
    }

    EXPECT_EQ(session_->Start(), SUCCESS);
    sleep(WAIT_TIME_AFTER_START);

    EXPECT_EQ(photoOutput_->Capture(), SUCCESS);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    EXPECT_EQ(session_->Stop(), SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test the normal scenario of movingphoto.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the normal scenario of movingphoto,Call the EnableMovingPhotoMirror function then tunrn off
 * after submitting the camera settings,and expect the movingphotomirror feature can be turned on successfully.
 */
HWTEST_F(CameraMovingPhotoModuleTest, camera_moving_photo_moduletest_004, TestSize.Level0)
{
    EXPECT_EQ(session_->BeginConfig(), SUCCESS);
    EXPECT_EQ(session_->AddInput((sptr<CaptureInput>&)input_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)previewOutput_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)photoOutput_), SUCCESS);
    EXPECT_EQ(session_->CommitConfig(), SUCCESS);

    if (session_->IsMovingPhotoSupported()) {
        session_->LockForControl();
        EXPECT_EQ(session_->EnableMovingPhoto(true), CameraErrorCode::SUCCESS);
        session_->UnlockForControl();
        EXPECT_EQ(session_->EnableMovingPhotoMirror(true, true), CameraErrorCode::SUCCESS);
        EXPECT_EQ(session_->EnableMovingPhotoMirror(false, true), CameraErrorCode::SUCCESS);
    }

    EXPECT_EQ(session_->Start(), SUCCESS);
    sleep(WAIT_TIME_AFTER_START);

    EXPECT_EQ(photoOutput_->Capture(), SUCCESS);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    EXPECT_EQ(session_->Stop(), SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test the abnormal scenario of movingphoto.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the abnormal scenario of movingphoto,Call the EnableMovingPhoto function
 * before starting the camera settings,and expect the movingphoto feature can not be turned on successfully.
 */
HWTEST_F(CameraMovingPhotoModuleTest, camera_moving_photo_moduletest_005, TestSize.Level0)
{
    if (session_->IsMovingPhotoSupported()) {
        session_->LockForControl();
        EXPECT_EQ(session_->EnableMovingPhoto(true), CameraErrorCode::SERVICE_FATL_ERROR);
        session_->UnlockForControl();
    }

    EXPECT_EQ(session_->BeginConfig(), SUCCESS);
    EXPECT_EQ(session_->AddInput((sptr<CaptureInput>&)input_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)previewOutput_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)photoOutput_), SUCCESS);
    EXPECT_EQ(session_->CommitConfig(), SUCCESS);

    EXPECT_EQ(session_->Start(), SUCCESS);
    sleep(WAIT_TIME_AFTER_START);

    EXPECT_EQ(photoOutput_->Capture(), SUCCESS);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    EXPECT_EQ(session_->Stop(), SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test the abnormal scenario of movingphoto.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the abnormal scenario of movingphoto,Call the EnableMovingPhoto function
 * before submitting the camera settings,and expect the movingphoto feature can not be turned on successfully.
 */
HWTEST_F(CameraMovingPhotoModuleTest, camera_moving_photo_moduletest_006, TestSize.Level0)
{
    EXPECT_EQ(session_->BeginConfig(), SUCCESS);
    EXPECT_EQ(session_->AddInput((sptr<CaptureInput>&)input_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)previewOutput_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)photoOutput_), SUCCESS);
    if (session_->IsMovingPhotoSupported()) {
        session_->LockForControl();
        EXPECT_EQ(session_->EnableMovingPhoto(true), CameraErrorCode::SUCCESS);
        session_->UnlockForControl();
    }
    EXPECT_EQ(session_->CommitConfig(), SUCCESS);

    EXPECT_EQ(session_->Start(), SUCCESS);
    sleep(WAIT_TIME_AFTER_START);

    EXPECT_EQ(photoOutput_->Capture(), SUCCESS);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    EXPECT_EQ(session_->Stop(), SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test the normal scenario of movingphoto.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the normal scenario of movingphoto.
 */
HWTEST_F(CameraMovingPhotoModuleTest, camera_moving_photo_moduletest_007, TestSize.Level0)
{
    EXPECT_EQ(session_->BeginConfig(), SUCCESS);
    EXPECT_EQ(session_->AddInput((sptr<CaptureInput>&)input_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)previewOutput_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)photoOutput_), SUCCESS);
    PhotoOutputTest_PhotoAssetAvailable photoAssetCallback = onPhotoAssetAvailable;
    EXPECT_EQ(RegisterPhotoAssetAvailableCallback(photoAssetCallback), SUCCESS);
    EXPECT_EQ(session_->CommitConfig(), SUCCESS);

    if (!session_->IsMovingPhotoSupported()) {
        MEDIA_ERR_LOG("Camera device not support moving photo");
        return;
    }
    session_->LockForControl();
    EXPECT_EQ(session_->EnableMovingPhoto(true), SUCCESS);
    session_->UnlockForControl();

    EXPECT_EQ(session_->Start(), SUCCESS);
    sleep(WAIT_TIME_AFTER_START);

    EXPECT_EQ(photoOutput_->Capture(), SUCCESS);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    if (!mediaAsset_) {
        MEDIA_ERR_LOG("Midia asset is null after register photo asset available callback");
        return;
    }

    MediaLibrary_MediaSubType mediaSubType = MEDIA_LIBRARY_DEFAULT;
    EXPECT_EQ(OH_MediaAsset_GetMediaSubType(mediaAsset_, &mediaSubType), MEDIA_LIBRARY_OK);
    EXPECT_EQ(mediaSubType, MediaLibrary_MediaSubType::MEDIA_LIBRARY_MOVING_PHOTO);

    EXPECT_EQ(session_->Stop(), SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test the normal scenario of movingphoto.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the normal scenario of movingphoto with enable moving photo mirror.
 */
HWTEST_F(CameraMovingPhotoModuleTest, camera_moving_photo_moduletest_008, TestSize.Level0)
{
    EXPECT_EQ(session_->BeginConfig(), SUCCESS);
    EXPECT_EQ(session_->AddInput((sptr<CaptureInput>&)input_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)previewOutput_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)photoOutput_), SUCCESS);
    PhotoOutputTest_PhotoAssetAvailable photoAssetCallback = onPhotoAssetAvailable;
    EXPECT_EQ(RegisterPhotoAssetAvailableCallback(photoAssetCallback), SUCCESS);
    EXPECT_EQ(session_->CommitConfig(), SUCCESS);

    if (!session_->IsMovingPhotoSupported()) {
        MEDIA_ERR_LOG("Camera device not support moving photo");
        return;
    }
    session_->LockForControl();
    EXPECT_EQ(session_->EnableMovingPhoto(true), SUCCESS);
    EXPECT_EQ(session_->EnableMovingPhotoMirror(true, true), SUCCESS);
    session_->UnlockForControl();

    EXPECT_EQ(session_->Start(), SUCCESS);
    sleep(WAIT_TIME_AFTER_START);

    EXPECT_EQ(photoOutput_->Capture(), SUCCESS);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    if (!mediaAsset_) {
        MEDIA_ERR_LOG("Midia asset is null after register photo asset available callback");
        return;
    }

    MediaLibrary_MediaSubType mediaSubType = MEDIA_LIBRARY_DEFAULT;
    EXPECT_EQ(OH_MediaAsset_GetMediaSubType(mediaAsset_, &mediaSubType), MEDIA_LIBRARY_OK);
    EXPECT_EQ(mediaSubType, MediaLibrary_MediaSubType::MEDIA_LIBRARY_MOVING_PHOTO);

    EXPECT_EQ(session_->Stop(), SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test the abnormal scenario of movingphoto.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the abnormal scenario of movingphoto with PhotoAssetAvailableCallback is null.
 */
HWTEST_F(CameraMovingPhotoModuleTest, camera_moving_photo_moduletest_009, TestSize.Level0)
{
    EXPECT_EQ(session_->BeginConfig(), SUCCESS);
    EXPECT_EQ(session_->AddInput((sptr<CaptureInput>&)input_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)previewOutput_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)photoOutput_), SUCCESS);
    PhotoOutputTest_PhotoAssetAvailable callback = nullptr;
    EXPECT_EQ(RegisterPhotoAssetAvailableCallback(callback), SUCCESS);
    EXPECT_EQ(session_->CommitConfig(), SUCCESS);

    if (!session_->IsMovingPhotoSupported()) {
        MEDIA_ERR_LOG("Camera device not support moving photo");
        return;
    }
    session_->LockForControl();
    EXPECT_EQ(session_->EnableMovingPhoto(true), SUCCESS);
    session_->UnlockForControl();

    EXPECT_EQ(session_->Start(), SUCCESS);
    sleep(WAIT_TIME_AFTER_START);

    EXPECT_EQ(photoOutput_->Capture(), SUCCESS);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    EXPECT_EQ(mediaAsset_, nullptr);

    EXPECT_EQ(session_->Stop(), SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test the abnormal scenario of movingphoto.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the abnormal scenario of movingphoto with MovingPhotoDataPrepared is null.
 */
HWTEST_F(CameraMovingPhotoModuleTest, camera_moving_photo_moduletest_010, TestSize.Level0)
{
    EXPECT_EQ(session_->BeginConfig(), SUCCESS);
    EXPECT_EQ(session_->AddInput((sptr<CaptureInput>&)input_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)previewOutput_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)photoOutput_), SUCCESS);
    PhotoOutputTest_PhotoAssetAvailable photoAssetCallback = onPhotoAssetAvailable;
    EXPECT_EQ(RegisterPhotoAssetAvailableCallback(photoAssetCallback), SUCCESS);
    EXPECT_EQ(session_->CommitConfig(), SUCCESS);

    if (!session_->IsMovingPhotoSupported()) {
        MEDIA_ERR_LOG("Camera device not support moving photo");
        return;
    }
    session_->LockForControl();
    EXPECT_EQ(session_->EnableMovingPhoto(true), SUCCESS);
    session_->UnlockForControl();

    EXPECT_EQ(session_->Start(), SUCCESS);
    sleep(WAIT_TIME_AFTER_START);

    EXPECT_EQ(photoOutput_->Capture(), SUCCESS);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    if (!mediaAsset_) {
        MEDIA_ERR_LOG("Midia asset is null after register photo asset available callback");
        return;
    }

    OH_MediaLibrary_OnMovingPhotoDataPrepared movingPhotoCallback = nullptr;
    EXPECT_EQ(MediaAssetManagerRequestMovingPhoto(movingPhotoCallback), SERVICE_FATL_ERROR);
    sleep(WAIT_TIME_CALLBACK);

    EXPECT_EQ(movingPhoto_, nullptr);

    EXPECT_EQ(session_->Stop(), SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test the abnormal scenario of movingphoto.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the abnormal scenario of movingphoto with disable moving photo.
 */
HWTEST_F(CameraMovingPhotoModuleTest, camera_moving_photo_moduletest_011, TestSize.Level0)
{
    EXPECT_EQ(session_->BeginConfig(), SUCCESS);
    EXPECT_EQ(session_->AddInput((sptr<CaptureInput>&)input_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)previewOutput_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)photoOutput_), SUCCESS);
    PhotoOutputTest_PhotoAssetAvailable photoAssetCallback = onPhotoAssetAvailable;
    EXPECT_EQ(RegisterPhotoAssetAvailableCallback(photoAssetCallback), SUCCESS);
    EXPECT_EQ(session_->CommitConfig(), SUCCESS);

    if (!session_->IsMovingPhotoSupported()) {
        MEDIA_ERR_LOG("Camera device not support moving photo");
        return;
    }
    session_->LockForControl();
    EXPECT_EQ(session_->EnableMovingPhoto(false), SUCCESS);
    session_->UnlockForControl();

    EXPECT_EQ(session_->Start(), SUCCESS);
    sleep(WAIT_TIME_AFTER_START);

    EXPECT_EQ(photoOutput_->Capture(), SUCCESS);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    if (!mediaAsset_) {
        MEDIA_ERR_LOG("Midia asset is null after register photo asset available callback");
        return;
    }

    MediaLibrary_MediaSubType mediaSubType = MEDIA_LIBRARY_DEFAULT;
    EXPECT_EQ(OH_MediaAsset_GetMediaSubType(mediaAsset_, &mediaSubType), MEDIA_LIBRARY_OK);
    EXPECT_NE(mediaSubType, MediaLibrary_MediaSubType::MEDIA_LIBRARY_MOVING_PHOTO);

    EXPECT_EQ(session_->Stop(), SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test the abnormal scenario of movingphoto.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the abnormal scenario of movingphoto with UnregisterPhotoAssetAvailableCallback.
 */
HWTEST_F(CameraMovingPhotoModuleTest, camera_moving_photo_moduletest_012, TestSize.Level0)
{
    EXPECT_EQ(session_->BeginConfig(), SUCCESS);
    EXPECT_EQ(session_->AddInput((sptr<CaptureInput>&)input_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)previewOutput_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)photoOutput_), SUCCESS);
    PhotoOutputTest_PhotoAssetAvailable photoAssetCallback = onPhotoAssetAvailable;
    EXPECT_EQ(RegisterPhotoAssetAvailableCallback(photoAssetCallback), SUCCESS);
    EXPECT_EQ(session_->CommitConfig(), SUCCESS);

    if (!session_->IsMovingPhotoSupported()) {
        MEDIA_ERR_LOG("Camera device not support moving photo");
        return;
    }
    session_->LockForControl();
    EXPECT_EQ(session_->EnableMovingPhoto(true), SUCCESS);
    session_->UnlockForControl();

    EXPECT_EQ(session_->Start(), SUCCESS);
    sleep(WAIT_TIME_AFTER_START);

    ReleaseMediaAsset();
    UnregisterPhotoAssetAvailableCallback(photoAssetCallback);

    EXPECT_EQ(photoOutput_->Capture(), SUCCESS);
    sleep(WAIT_TIME_AFTER_CAPTURE);
    ASSERT_EQ(mediaAsset_, nullptr);

    EXPECT_EQ(session_->Stop(), SUCCESS);
}

}  // namespace CameraStandard
}  // namespace OHOS