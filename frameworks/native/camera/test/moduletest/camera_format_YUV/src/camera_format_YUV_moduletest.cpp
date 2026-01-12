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

#include "camera_format_YUV_moduletest.h"
#include "gtest/gtest.h"
#include <cstdint>
#include <vector>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_util.h"
#include "hap_token_info.h"
#include "ipc_skeleton.h"
#include "metadata_utils.h"
#include "nativetoken_kit.h"
#include "surface.h"
#include "test_common.h"
#include "test_token.h"
#include "token_setproc.h"
#include "os_account_manager.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

void CameraformatYUVModuleTest::UpdateCameraOutputCapability(int32_t modeName)
{
    if (!cameraManager_ || cameras_.empty()) {
        return;
    }
    auto outputCapability = cameraManager_->GetSupportedOutputCapability(cameras_[0], modeName);
    ASSERT_NE(outputCapability, nullptr);

    outputCapability->photoProfiles_[0].size_ = {640, 480};
    outputCapability->photoProfiles_[0].format_ = CAMERA_FORMAT_YUV_420_SP;
    outputCapability->previewProfiles_[0].size_ = {640, 480};
    outputCapability->previewProfiles_[0].format_ = CAMERA_FORMAT_YUV_420_SP;

    previewProfile_ = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfile_.empty());

    outputCapability->SetPreviewProfiles(previewProfile_);
    cameras_[0]->SetProfile(outputCapability);

    photoProfile_ = outputCapability->GetPhotoProfiles();
    ASSERT_FALSE(photoProfile_.empty());

    outputCapability->SetPhotoProfiles(photoProfile_);
    cameras_[0]->SetProfile(outputCapability);
}

#ifdef CAMERA_CAPTURE_YUV
void CameraformatYUVModuleTest::UpdateCameraFullOutputCapability(int32_t modeName)
{
    if (!cameraManager_ || cameras_.empty()) {
        return;
    }
    auto fullOutputCapability = cameraManager_->GetSupportedFullOutputCapability(cameras_[0], modeName);
    ASSERT_NE(fullOutputCapability, nullptr);

    previewProfile_ = fullOutputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfile_.empty());

    photoProfile_ = fullOutputCapability->GetPhotoProfiles();
    ASSERT_FALSE(photoProfile_.empty());
}

void CameraformatYUVModuleTest::CreateYuvPhotoOutput()
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
    int32_t retCode = cameraManager_->CreatePhotoOutput(yuvPhotoProfile_, &photoOutput_);
    ASSERT_EQ(retCode, CameraErrorCode::SUCCESS) << "CreatePhotoOutput failed with error code: " << retCode;
    ASSERT_NE(photoOutput_, nullptr) << "photoOutput_ is null after CreatePhotoOutput";

    photoOutput_->SetNativeSurface(true);
}

void CameraformatYUVModuleTest::CreatePreviewOutput(Profile &profile, sptr<PreviewOutput> &previewOutput)
{
    previewSurface_ = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(previewSurface_, nullptr);
    previewSurface_->SetUserData(CameraManager::surfaceFormat, std::to_string(profile.GetCameraFormat()));
    previewListener_ = nullptr;
    previewListener_ = new (std::nothrow) TestPreviewConsumer(previewSurface_);
    SurfaceError ret = previewSurface_->RegisterConsumerListener((sptr<IBufferConsumerListener> &)previewListener_);
    ASSERT_EQ(ret, SURFACE_ERROR_OK);
    int32_t retCode = cameraManager_->CreatePreviewOutput(profile, previewSurface_, &previewOutput);
    ASSERT_EQ(retCode, CameraErrorCode::SUCCESS)
        << "CreatePreviewOutput failed with error code: " << retCode;
    ASSERT_NE(previewOutput, nullptr) << "previewOutput is null after successful creation";
}
#endif

void CameraformatYUVModuleTest::UpdateCameraOutputCapabilitySrc(int32_t modeName)
{
    if (!cameraManager_ || cameras_.empty()) {
        return;
    }
    auto outputCapability = cameraManager_->GetSupportedOutputCapability(cameras_[0], modeName);
    ASSERT_NE(outputCapability, nullptr);

    outputCapability->photoProfiles_[0].size_ = {640, 480};
    outputCapability->photoProfiles_[0].format_ = CAMERA_FORMAT_YUV_422_YUYV;
    outputCapability->previewProfiles_[0].size_ = {640, 480};
    outputCapability->previewProfiles_[0].format_ = CAMERA_FORMAT_YUV_422_YUYV;

    previewProfile_ = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfile_.empty());

    outputCapability->SetPreviewProfiles(previewProfile_);
    cameras_[0]->SetProfile(outputCapability);

    photoProfile_ = outputCapability->GetPhotoProfiles();
    ASSERT_FALSE(photoProfile_.empty());

    outputCapability->SetPhotoProfiles(photoProfile_);
    cameras_[0]->SetProfile(outputCapability);
}

#ifdef CAMERA_CAPTURE_YUV
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
#endif

void CameraformatYUVModuleTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraformatYUVModuleTest::SetUpTestCase started!");
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
}

void CameraformatYUVModuleTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraformatYUVModuleTest::TearDownTestCase started!");
}

void CameraformatYUVModuleTest::SetUp()
{
    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);
    cameras_ = cameraManager_->GetSupportedCameras();
    ASSERT_FALSE(cameras_.empty());
    session_ = cameraManager_->CreateCaptureSession(SceneMode::NORMAL);
    ASSERT_NE(session_, nullptr);
    auto camInput_ = cameraManager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(camInput_, nullptr);
    auto device = camInput_->GetCameraDevice();
    ASSERT_NE(device, nullptr);
    device->SetMdmCheck(false);

    input_ = camInput_;
    ASSERT_NE(input_, nullptr);
    input_->Open();
}

void CameraformatYUVModuleTest::TearDown()
{
    MEDIA_DEBUG_LOG("CameraformatYUVModuleTest::TearDown started!");
    cameraManager_ = nullptr;
    cameras_.clear();
    if (input_) {
        sptr<CameraInput> camInput = (sptr<CameraInput>&)input_;
        auto device = camInput->GetCameraDevice();
        if (device) {
            device->SetMdmCheck(true);
        }
        input_->Close();
        input_->Release();
    }
#ifdef CAMERA_CAPTURE_YUV
    if (previewOutput_) {
        previewOutput_->Release();
    }
    if (photoOutput_) {
        photoOutput_->Release();
    }
    if (preview_) {
        preview_->Release();
    }
    if (session_) {
        session_->Release();
    }
#endif
}

#ifdef CAMERA_CAPTURE_YUV
void TestCaptureCallback::OnPhotoAvailable(
    const std::shared_ptr<Media::NativeImage> nativeImage, const bool isRaw) const
{
    photoFlag_ = true;
    MEDIA_DEBUG_LOG("OnPhotoAvailable(NativeImage) called");
}

void TestCaptureCallback::OnPhotoAvailable(const std::shared_ptr<Media::Picture> picture) const
{
    photoFlag_ = true;
    MEDIA_DEBUG_LOG("OnPhotoAvailable(Picture) called");
}

void TestCaptureCallback::OnPhotoAssetAvailable(const int32_t captureId, const std::string &uri,
    const int32_t cameraShotType, const std::string &burstKey) const
{
    photoAssetFlag_ = true;
    MEDIA_DEBUG_LOG("OnPhotoAssetAvailable: uri=%{public}s", uri.c_str());
}

void TestCaptureCallback::OnThumbnailAvailable(
    int32_t captureId, int64_t timestamp, std::unique_ptr<Media::PixelMap> pixelMap) const
{
    thumbnailFlag_ = true;
    MEDIA_DEBUG_LOG("OnThumbnailAvailable called");
}
#endif

/*
 * Feature: Framework
 * Function: Test the functionality of capturing YUV photos.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the functionality of capturing YUV photos which the format is YUV_420_SP.
 */
HWTEST_F(CameraformatYUVModuleTest, camera_format_YUV_moduletest_001, TestSize.Level0)
{
    UpdateCameraOutputCapability();
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    preview_ = cameraManager_->CreatePreviewOutput(previewProfile_[0], surface);
    ASSERT_NE(preview_, nullptr);
    sptr<IConsumerSurface> iConsumerSurface = IConsumerSurface::Create();
    ASSERT_NE(iConsumerSurface, nullptr);
    sptr<IBufferProducer> surface2 = iConsumerSurface->GetProducer();
    ASSERT_NE(surface2, nullptr);
    sptr<CaptureOutput> photoOutput = cameraManager_->CreatePhotoOutput(photoProfile_[0], surface2);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_EQ(session_->BeginConfig(), 0);
    EXPECT_EQ(session_->AddInput(input_), 0);
    if (!session_->CanAddOutput(preview_)) {
        GTEST_SKIP();
    }
    EXPECT_EQ(session_->AddOutput(preview_), 0);
    if (!session_->CanAddOutput(photoOutput)) {
        GTEST_SKIP();
    }
    EXPECT_EQ(session_->AddOutput(photoOutput), 0);
    EXPECT_EQ(session_->CommitConfig(), 0);

    auto intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);
    intResult = ((sptr<PhotoOutput>&)photoOutput)->Capture();
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    intResult = session_->Stop();
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test the functionality of capturing YUV photos.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the functionality of capturing YUV photos which the format is YUV_422_YUYV.
 */
HWTEST_F(CameraformatYUVModuleTest, camera_format_YUV_moduletest_002, TestSize.Level0)
{
    UpdateCameraOutputCapabilitySrc();
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    preview_ = cameraManager_->CreatePreviewOutput(previewProfile_[0], surface);
    ASSERT_NE(preview_, nullptr);
    sptr<IConsumerSurface> iConsumerSurface = IConsumerSurface::Create();
    ASSERT_NE(iConsumerSurface, nullptr);
    sptr<IBufferProducer> surface2 = iConsumerSurface->GetProducer();
    ASSERT_NE(surface2, nullptr);
    sptr<CaptureOutput> photoOutput = cameraManager_->CreatePhotoOutput(photoProfile_[0], surface2);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_EQ(session_->BeginConfig(), 0);
    EXPECT_EQ(session_->AddInput(input_), 0);
    if (!session_->CanAddOutput(preview_)) {
        GTEST_SKIP();
    }
    EXPECT_EQ(session_->AddOutput(preview_), 0);
    if (!session_->CanAddOutput(photoOutput)) {
        GTEST_SKIP();
    }
    EXPECT_EQ(session_->AddOutput(photoOutput), 0);
    EXPECT_EQ(session_->CommitConfig(), 0);

    auto intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);
    intResult = ((sptr<PhotoOutput>&)photoOutput)->Capture();
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    intResult = session_->Stop();
    EXPECT_EQ(intResult, 0);
}

#ifdef CAMERA_CAPTURE_YUV
/*
 * Feature: Framework
 * Function: Test the photo available callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo data available callback after successful capture with getSupportedFullOutputCapability.
 */
HWTEST_F(CameraformatYUVModuleTest, camera_format_YUV_moduletest_003, TestSize.Level0)
{
    UpdateCameraFullOutputCapability();
    CreateYuvPhotoOutput();
    CreatePreviewOutput(previewProfile_[0], previewOutput_);
    EXPECT_EQ(session_->BeginConfig(), SUCCESS);
    EXPECT_EQ(session_->AddInput((sptr<CaptureInput>&)input_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)previewOutput_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)photoOutput_), SUCCESS);

    std::shared_ptr<TestCaptureCallback> callback = std::make_shared<TestCaptureCallback>();
    EXPECT_NE(callback, nullptr);
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
 * CaseDescription: Test photo asset available callback after successful capture with getSupportedFullOutputCapability.
 */
HWTEST_F(CameraformatYUVModuleTest, camera_format_YUV_moduletest_004, TestSize.Level0)
{
    UpdateCameraFullOutputCapability();
    CreateYuvPhotoOutput();
    CreatePreviewOutput(previewProfile_[0], previewOutput_);
    EXPECT_EQ(session_->BeginConfig(), SUCCESS);
    EXPECT_EQ(session_->AddInput((sptr<CaptureInput>&)input_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)previewOutput_), SUCCESS);
    EXPECT_EQ(session_->AddOutput((sptr<CaptureOutput>&)photoOutput_), SUCCESS);

    std::shared_ptr<TestCaptureCallback> callback = std::make_shared<TestCaptureCallback>();
    EXPECT_NE(callback, nullptr);
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
#endif
}  // namespace CameraStandard
}  // namespace OHOS