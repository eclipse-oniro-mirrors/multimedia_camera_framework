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

#include "camera_photo_moduletest.h"

#include "accesstoken_kit.h"
#include "hap_token_info.h"
#include "nativetoken_kit.h"
#include "ipc_skeleton.h"
#include "os_account_manager.h"
#include "token_setproc.h"
#include "camera_log.h"
#include "test_token.h"


using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
static std::mutex g_mutex;

void CameraPhotoModuleTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraPhotoModuleTest::SetUpTestCase started!");
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
}

void CameraPhotoModuleTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraPhotoModuleTest::TearDownTestCase started!");
}

void CameraPhotoModuleTest::SetUp()
{
    MEDIA_INFO_LOG("CameraPhotoModuleTest::SetUp start!");

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
    MEDIA_INFO_LOG("CameraPhotoModuleTest::SetUp end!");
}

void CameraPhotoModuleTest::TearDown()
{
    MEDIA_INFO_LOG("CameraPhotoModuleTest::TearDown start!");

    cameras_.clear();
    photoProfile_.clear();
    previewProfile_.clear();

    photoOutput_->Release();
    previewOutput_->Release();

    manager_ = nullptr;
    input_->Release();
    session_->Release();
    previewSurface_ = nullptr;
    MEDIA_INFO_LOG("CameraPhotoModuleTest::TearDown end!");
}

void CameraPhotoModuleTest::UpdataCameraOutputCapability(int32_t modeName)
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

int32_t CameraPhotoModuleTest::CreatePreviewOutput(Profile &profile, sptr<PreviewOutput> &previewOutput)
{
    previewSurface_ = Surface::CreateSurfaceAsConsumer();
    if (previewSurface_ == nullptr) {
        MEDIA_ERR_LOG("Failed to get previewOutput surface");
        return INVALID_ARGUMENT;
    }
    previewSurface_->SetUserData(CameraManager::surfaceFormat, std::to_string(profile.GetCameraFormat()));
    previewListener_ = nullptr;
    previewListener_ = new (std::nothrow) TestPreviewConsumer(previewSurface_);
    SurfaceError ret = previewSurface_->RegisterConsumerListener((sptr<IBufferConsumerListener> &)previewListener_);
    EXPECT_EQ(ret, SURFACE_ERROR_OK);
    int32_t retCode = manager_->CreatePreviewOutput(profile, previewSurface_, &previewOutput);
    if (retCode != CameraErrorCode::SUCCESS) {
        return SERVICE_FATL_ERROR;
    }
    return SUCCESS;
}

int32_t CameraPhotoModuleTest::CreatePhotoOutputWithoutSurface(Profile &profile, sptr<PhotoOutput> &photoOutput)
{
    int32_t retCode = manager_->CreatePhotoOutput(profile, &photoOutput);
    CHECK_RETURN_RET_ELOG((retCode != CameraErrorCode::SUCCESS || photoOutput == nullptr), SERVICE_FATL_ERROR,
        "Create photo output failed");

    photoOutput->SetNativeSurface(true);
    return SUCCESS;
}

int32_t CameraPhotoModuleTest::CreateYuvPhotoOutput()
{
    for (Profile &profile : photoProfile_) {
        if (profile.GetCameraFormat() == CAMERA_FORMAT_YUV_420_SP) {
            yuvPhotoProfile_ = profile;
            std::cout << "get profle:" << profile.GetCameraFormat() << " width:" << profile.GetSize().width
                      << "height:" << profile.GetSize().height << std::endl;
            break;
        } else {
            std::cout << "skip profle:" << profile.GetCameraFormat() << " width:" << profile.GetSize().width
                      << "height:" << profile.GetSize().height << std::endl;
        }
    }
    int32_t retCode = manager_->CreatePhotoOutput(yuvPhotoProfile_, &photoOutput_);
    CHECK_RETURN_RET_ELOG((retCode != CameraErrorCode::SUCCESS || photoOutput_ == nullptr),
        SERVICE_FATL_ERROR,
        "Create photo output failed");

    photoOutput_->SetNativeSurface(true);
    return SUCCESS;
}

int32_t CameraPhotoModuleTest::CreateYuvPreviewOutput()
{
    Profile yuvProfile;
    std::cout << "photo yuv profle format:" << yuvPhotoProfile_.GetCameraFormat()
              << " width:" << yuvPhotoProfile_.GetSize().width << " height:" << yuvPhotoProfile_.GetSize().height
              << std::endl;
    for (Profile &profile : previewProfile_) {
        float ratio1 = static_cast<float>(yuvPhotoProfile_.GetSize().width) / yuvPhotoProfile_.GetSize().height;
        float ratio2 = static_cast<float>(profile.GetSize().width) / profile.GetSize().height;
        std::cout << "ratio1:" << ratio1 << " ratio2:" << ratio2 << std::endl;
        if (profile.GetCameraFormat() == CAMERA_FORMAT_YUV_420_SP && ratio1 == ratio2) {
            yuvProfile = profile;
            std::cout << "get profle:" << profile.GetCameraFormat() << " width:" << profile.GetSize().width
                      << " height:" << profile.GetSize().height << std::endl;
            break;
        } else {
            std::cout << "skip profle:" << profile.GetCameraFormat() << " width:" << profile.GetSize().width
                      << " height:" << profile.GetSize().height << std::endl;
        }
    }

    int32_t retCode = CreatePreviewOutput(yuvProfile, previewOutput_);
    CHECK_RETURN_RET_ELOG((retCode != CameraErrorCode::SUCCESS || previewOutput_ == nullptr),
        SERVICE_FATL_ERROR,
        "Create preview output failed");

    photoOutput_->SetNativeSurface(true);
    return SUCCESS;
}

TestPreviewConsumer::TestPreviewConsumer(wptr<Surface> surface) : surface_(surface)
{
    MEDIA_INFO_LOG("TestPreviewConsumer new E");
}

TestPreviewConsumer::~TestPreviewConsumer()
{
    MEDIA_INFO_LOG("TestPreviewConsumer ~ E");
}

void TestPreviewConsumer::OnBufferAvailable()
{
    MEDIA_INFO_LOG("TestPreviewConsumer OnBufferAvailable E");
    CAMERA_SYNC_TRACE;
    sptr<Surface> surface = surface_.promote();
    CHECK_RETURN_ELOG(surface == nullptr, "surface is null");
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    int32_t fence = -1;
    int64_t timestamp;
    OHOS::Rect damage;
    SurfaceError surfaceRet = surface_->AcquireBuffer(surfaceBuffer, fence, timestamp, damage);
    CHECK_RETURN_ELOG(surfaceRet != SURFACE_ERROR_OK, "Failed to acquire surface buffer");
    surfaceRet = surface_->ReleaseBuffer(surfaceBuffer, -1);
    MEDIA_INFO_LOG("TestPreviewConsumer OnBufferAvailable X");
}

void TestCaptureCallback::OnPhotoAvailable(const std::shared_ptr<Media::NativeImage> nativeImage, bool isRaw) const
{
    MEDIA_DEBUG_LOG("TestCaptureCallback::OnPhotoAvailable is called!");
    photoFlag_ = true;
}

void TestCaptureCallback::OnPhotoAssetAvailable(
    const int32_t captureId, const std::string &uri, int32_t cameraShotType, const std::string &burstKey) const
{
    MEDIA_DEBUG_LOG("TestCaptureCallback::OnPhotoAssetAvailable is called!");
    photoAssetFlag_ = true;
}

void TestCaptureCallback::OnThumbnailAvailable(
    int32_t captureId, int64_t timestamp, std::unique_ptr<Media::PixelMap> pixelMap) const
{
    MEDIA_DEBUG_LOG("TestCaptureCallback::OnThumbnailAvailable is called!");
    thumbnailFlag_ = true;
}

/*
 * Feature: Framework
 * Function: Test the photo available callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the photo available callback, when capture is ok.
 */
HWTEST_F(CameraPhotoModuleTest, camera_photo_moduletest_001, TestSize.Level0)
{
    EXPECT_EQ(CreatePreviewOutput(previewProfile_[0], previewOutput_), SUCCESS);
    EXPECT_EQ(CreatePhotoOutputWithoutSurface(photoProfile_[0], photoOutput_), SUCCESS);
    EXPECT_EQ(session_->BeginConfig(), SUCCESS);
    EXPECT_EQ(session_->AddInput((sptr<CaptureInput>&)input_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)previewOutput_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)photoOutput_), SUCCESS);

    std::shared_ptr<TestCaptureCallback> callback = std::make_shared<TestCaptureCallback>();
    photoOutput_->SetPhotoAvailableCallback(callback);
    callbackFlag_ |= CAPTURE_PHOTO;
    photoOutput_->SetCallbackFlag(callbackFlag_);

    EXPECT_EQ(session_->CommitConfig(), SUCCESS);
    EXPECT_EQ(session_->Start(), SUCCESS);
    sleep(WAIT_TIME_AFTER_START);

    EXPECT_EQ(photoOutput_->Capture(), SUCCESS);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    EXPECT_EQ(photoFlag_, true);
    photoOutput_->UnSetPhotoAvailableCallback();
    photoFlag_ = false;

    EXPECT_EQ(session_->Stop(), SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test the photoAsset available callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the photoAsset available callback, when capture is ok.
 */
HWTEST_F(CameraPhotoModuleTest, camera_photo_moduletest_002, TestSize.Level0)
{
    EXPECT_EQ(CreatePreviewOutput(previewProfile_[0], previewOutput_), SUCCESS);
    EXPECT_EQ(CreatePhotoOutputWithoutSurface(photoProfile_[0], photoOutput_), SUCCESS);
    EXPECT_EQ(session_->BeginConfig(), SUCCESS);
    EXPECT_EQ(session_->AddInput((sptr<CaptureInput>&)input_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)previewOutput_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)photoOutput_), SUCCESS);

    std::shared_ptr<TestCaptureCallback> callback = std::make_shared<TestCaptureCallback>();
    photoOutput_->SetPhotoAssetAvailableCallback(callback);
    callbackFlag_ |= CAPTURE_PHOTO_ASSET;
    photoOutput_->SetCallbackFlag(callbackFlag_);

    EXPECT_EQ(session_->CommitConfig(), SUCCESS);
    EXPECT_EQ(session_->Start(), SUCCESS);
    sleep(WAIT_TIME_AFTER_START);

    EXPECT_EQ(photoOutput_->Capture(), SUCCESS);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    EXPECT_EQ(photoAssetFlag_, true);
    photoOutput_->UnSetPhotoAssetAvailableCallback();
    photoAssetFlag_ = false;

    EXPECT_EQ(session_->Stop(), SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test thumbnail callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test thumbnail callback
 */
HWTEST_F(CameraPhotoModuleTest, camera_photo_moduletest_003, TestSize.Level0)
{
    EXPECT_EQ(CreateYuvPhotoOutput(), SUCCESS);
    EXPECT_EQ(CreateYuvPreviewOutput(), SUCCESS);
    EXPECT_EQ(photoOutput_->IsQuickThumbnailSupported(), SESSION_NOT_RUNNING);

    EXPECT_EQ(session_->BeginConfig(), SUCCESS);
    EXPECT_EQ(session_->AddInput((sptr<CaptureInput> &)input_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput> &)previewOutput_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput> &)photoOutput_), SUCCESS);

    CHECK_RETURN_ELOG(photoOutput_->IsQuickThumbnailSupported() != SUCCESS, "device not support!");
    EXPECT_EQ(photoOutput_->SetThumbnail(true), SUCCESS);
    std::shared_ptr<TestCaptureCallback> callback = std::make_shared<TestCaptureCallback>();
    photoOutput_->SetThumbnailCallback(callback);
    photoOutput_->SetPhotoAssetAvailableCallback(callback);
    callbackFlag_ |= CAPTURE_PHOTO_ASSET;
    photoOutput_->SetCallbackFlag(callbackFlag_);

    EXPECT_EQ(session_->CommitConfig(), SUCCESS);
    EXPECT_EQ(session_->Start(), SUCCESS);
    sleep(WAIT_TIME_AFTER_START);

    EXPECT_EQ(photoOutput_->Capture(), SUCCESS);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    EXPECT_EQ(photoAssetFlag_, true);
    photoOutput_->UnSetPhotoAssetAvailableCallback();
    photoAssetFlag_ = false;
    EXPECT_EQ(thumbnailFlag_, true);
    photoOutput_->UnSetThumbnailAvailableCallback();
    thumbnailFlag_ = false;
}
}  // namespace CameraStandard
}  // namespace OHOS