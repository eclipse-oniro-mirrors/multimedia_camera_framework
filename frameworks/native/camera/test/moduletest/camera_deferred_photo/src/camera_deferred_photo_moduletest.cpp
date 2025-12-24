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

#include "camera_deferred_photo_moduletest.h"
#include "camera_log.h"

#include "ibuffer_producer.h"
#include "iconsumer_surface.h"
#include "image_format.h"
#include "token_setproc.h"
#include "test_token.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

int32_t g_num = 0;
const SceneMode CAPTURE_SCENE_MODE = SceneMode::CAPTURE;
constexpr int32_t DEFAULT_CAPACITY = 8;
constexpr int32_t EXECUTE_SUCCESS = 0;
constexpr int32_t EXECUTE_FAILED = -1;
constexpr int32_t DEFERRED_PHOTO_NOT_ENABLED = -1;
constexpr int32_t DEFERRED_PHOTO_ENABLED = 0;
constexpr int32_t PHOTO_CALLBCAK_CNT = 1;
constexpr int32_t WAIT_FOR_PHOTO_CB = 8;

void CameraDeferredPhotoModuleTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("CameraDeferredPhotoModuleTest::SetUpTestCase is called");
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
}


void CameraDeferredPhotoModuleTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("CameraDeferredPhotoModuleTest::TearDownTestCase is called");
}

void CameraDeferredPhotoModuleTest::SetUp()
{
    g_num++;
    MEDIA_INFO_LOG("CameraDeferredPhotoModuleTest::SetUp is called, g_num = %{public}d", g_num);

    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);

    cameras_ = cameraManager_->GetSupportedCameras();
    CHECK_RETURN(cameras_.empty());

    std::vector<SceneMode> sceneModes = GetSupportedSceneModes(cameras_[0]);
    auto it = std::find(sceneModes.begin(), sceneModes.end(), CAPTURE_SCENE_MODE);
    CHECK_RETURN(it == sceneModes.end());

    outputCapability_ = cameraManager_->GetSupportedOutputCapability(cameras_[0], CAPTURE_SCENE_MODE);
    ASSERT_NE(outputCapability_, nullptr);
    previewProfiles_ = outputCapability_->GetPreviewProfiles();
    photoProfiles_ = outputCapability_->GetPhotoProfiles();
    CHECK_RETURN(previewProfiles_.empty() || photoProfiles_.empty());

    previewOutput_ = CreatePreviewOutput(previewProfiles_[0]);
    ASSERT_NE(previewOutput_, nullptr);

    EXPECT_EQ(CreateAndOpenCameraInput(), EXECUTE_SUCCESS);

    isInitSuccess_ = true;
}

void CameraDeferredPhotoModuleTest::TearDown()
{
    MEDIA_INFO_LOG("CameraDeferredPhotoModuleTest::TearDown is called");
    isInitSuccess_ = false;
    if (captureSession_) {
        CHECK_EXECUTE(isSessionStarted_, captureSession_->Stop());
        if (cameraInput_) {
            CHECK_EXECUTE(isCameraInputAdded_,
                captureSession_->RemoveInput(cameraInput_));
            CHECK_EXECUTE(isCameraInputOpened_, cameraInput_->Close());
            sptr<CameraInput> camInput = (sptr<CameraInput>&)cameraInput_;
            auto device = camInput->GetCameraDevice();
            if (device) {
                device->SetMdmCheck(true);
            }
            cameraInput_->Release();
        }
        if (previewOutput_) {
            CHECK_EXECUTE(isPreviewOutputAdded_,
                captureSession_->RemoveOutput(previewOutput_));
            previewOutput_->Release();
        }
        if (photoOutput_) {
            sptr<CaptureOutput> output = static_cast<CaptureOutput*>(photoOutput_.GetRefPtr());
            CHECK_EXECUTE(isPhotoOutputAdded_,
                captureSession_->RemoveOutput(output));
            photoOutput_->Release();
        }
        captureSession_->Release();
    }

    isSessionStarted_ = false;
    isCameraInputOpened_ = false;
    isCameraInputAdded_ = false;
    isPreviewOutputAdded_ = false;
    isPhotoOutputAdded_ = false;

    imageReceiver_.reset();
    cameras_.clear();
    previewProfiles_.clear();
    photoProfiles_.clear();
    outputCapability_.clear();
    previewOutput_.clear();
    photoOutput_.clear();
    previewSurface_.clear();
    photoSurface_.clear();
    photoListener_.clear();
    cameraInput_.clear();
    captureSession_.clear();
    cameraManager_.clear();
}

std::vector<SceneMode> CameraDeferredPhotoModuleTest::GetSupportedSceneModes(sptr<CameraDevice>& camera)
{
    std::vector<SceneMode> sceneModes = {};
    CHECK_RETURN_RET(cameraManager_ == nullptr, sceneModes);
    sceneModes = cameraManager_->GetSupportedModes(cameras_[0]);
    if (sceneModes.empty()) {
        sceneModes.emplace_back(SceneMode::CAPTURE);
        sceneModes.emplace_back(SceneMode::VIDEO);
    }
    return sceneModes;
}

sptr<CaptureOutput> CameraDeferredPhotoModuleTest::CreatePreviewOutput(Profile& previewProfile)
{
    Size size = previewProfile.GetSize();
    int32_t width = static_cast<int32_t>(size.width);
    int32_t height = static_cast<int32_t>(size.height);

    if (imageReceiver_ == nullptr) {
        imageReceiver_ = Media::ImageReceiver::CreateImageReceiver(width, height,
            static_cast<int32_t>(Media::ImageFormat::JPEG), DEFAULT_CAPACITY);
        CHECK_RETURN_RET_ELOG(imageReceiver_ == nullptr, nullptr,
            "CameraDeferredPhotoModuleTest::CreatePreviewOutput Failed to create image receiver");
    }
    std::string surfaceId = imageReceiver_->iraContext_->GetReceiverKey();
    previewSurface_ = Media::ImageReceiver::getSurfaceById(surfaceId);
    CHECK_RETURN_RET_ELOG(previewSurface_ == nullptr, nullptr,
        "CameraDeferredPhotoModuleTest::CreatePreviewOutput Failed to get surface by id");
    previewSurface_->SetUserData(CameraManager::surfaceFormat, std::to_string(previewProfile.GetCameraFormat()));

    sptr<CaptureOutput> previewOutput;
    previewOutput = cameraManager_->CreatePreviewOutput(previewProfile, previewSurface_);
    CHECK_RETURN_RET_ELOG(previewOutput == nullptr, nullptr,
        "CameraDeferredPhotoModuleTest::CreatePreviewOutput Failed to create preview output");

    return previewOutput;
}

int32_t CameraDeferredPhotoModuleTest::AddPreviewOutput(sptr<CaptureOutput>& previewOutput)
{
    CHECK_RETURN_RET(captureSession_ == nullptr, EXECUTE_FAILED);
    CHECK_RETURN_RET_ELOG(!captureSession_->CanAddOutput(previewOutput), EXECUTE_FAILED, "Can not add preview output");
    int32_t ret = captureSession_->AddOutput(previewOutput);
    CHECK_RETURN_RET_ELOG(ret != EXECUTE_SUCCESS, EXECUTE_FAILED, "AddPreviewOutput failed");
    isPreviewOutputAdded_ = true;
    return EXECUTE_SUCCESS;
}

int32_t CameraDeferredPhotoModuleTest::CreateAndOpenCameraInput()
{
    auto camInput = cameraManager_->CreateCameraInput(cameras_[0]);
    CHECK_RETURN_RET_ELOG(camInput == nullptr, EXECUTE_FAILED, "CreateCameraInput camInput failed");
    auto device = camInput->GetCameraDevice();
    CHECK_RETURN_RET_ELOG(device == nullptr, EXECUTE_FAILED, "device is null");
    device->SetMdmCheck(false);
    cameraInput_ = camInput;
    CHECK_RETURN_RET_ELOG(cameraInput_ == nullptr, EXECUTE_FAILED, "CreateCameraInput failed");

    int ret = cameraInput_->Open();
    CHECK_RETURN_RET_ELOG(ret != EXECUTE_SUCCESS, EXECUTE_FAILED, "CameraInput open failed");
    isCameraInputOpened_ = true;
    return EXECUTE_SUCCESS;
}

int32_t CameraDeferredPhotoModuleTest::AddInput(sptr<CaptureInput>& cameraInput)
{
    CHECK_RETURN_RET(captureSession_ == nullptr, EXECUTE_FAILED);
    CHECK_RETURN_RET_ELOG(!captureSession_->CanAddInput(cameraInput), EXECUTE_FAILED, "Can not add input");
    int32_t ret = captureSession_->AddInput(cameraInput);
    CHECK_RETURN_RET_ELOG(ret != EXECUTE_SUCCESS, EXECUTE_FAILED, "AddInput failed");
    isCameraInputAdded_ = true;
    return EXECUTE_SUCCESS;
}

sptr<PhotoOutput> CameraDeferredPhotoModuleTest::CreatePhotoOutputWithoutSurfaceId(Profile& photoProfile)
{
    photoSurface_ = Surface::CreateSurfaceAsConsumer("photoOutput");
    photoSurface_->SetUserData(CameraManager::surfaceFormat, std::to_string(photoProfile.GetCameraFormat()));
    sptr<IBufferProducer> surfaceProducer = photoSurface_->GetProducer();
    CHECK_RETURN_RET_ELOG(surfaceProducer == nullptr, nullptr,
        "CameraDeferredPhotoModuleTest::CreatePhotoOutputWithoutSurfaceId Failed to get producer");

    sptr<PhotoOutput> photoOutput = nullptr;
    int ret = cameraManager_-> CreatePhotoOutput(photoProfile, surfaceProducer, &photoOutput);
    EXPECT_EQ(ret, CameraErrorCode::SUCCESS);

    photoOutput->SetNativeSurface(true);

    return photoOutput;
}

sptr<PhotoOutput> CameraDeferredPhotoModuleTest::CreatePhotoOutputWithSurfaceId(Profile& photoProfile)
{
    Size size = photoProfile.GetSize();
    int32_t width = static_cast<int32_t>(size.width);
    int32_t height = static_cast<int32_t>(size.height);

    if (imageReceiver_ == nullptr) {
        imageReceiver_ = Media::ImageReceiver::CreateImageReceiver(width, height,
            static_cast<int32_t>(Media::ImageFormat::JPEG), DEFAULT_CAPACITY);
        CHECK_RETURN_RET_ELOG(imageReceiver_ == nullptr, nullptr,
            "CameraDeferredPhotoModuleTest::CreatePhotoOutputWithSurfaceId Failed to create image receiver");
    }
    std::string surfaceId = imageReceiver_->iraContext_->GetReceiverKey();
    photoSurface_ = Media::ImageReceiver::getSurfaceById(surfaceId);
    CHECK_RETURN_RET_ELOG(photoSurface_ == nullptr, nullptr,
        "CameraDeferredPhotoModuleTest::CreatePhotoOutputWithSurfaceId Failed to get surface by id");
    photoSurface_->SetUserData(CameraManager::surfaceFormat, std::to_string(photoProfile.GetCameraFormat()));
    sptr<IBufferProducer> surfaceProducer = photoSurface_->GetProducer();
    CHECK_RETURN_RET_ELOG(surfaceProducer == nullptr, nullptr,
        "CameraDeferredPhotoModuleTest::CreatePhotoOutputWithSurfaceId Failed to get producer");

    sptr<PhotoOutput> photoOutput = nullptr;
    int ret = cameraManager_-> CreatePhotoOutput(photoProfile, surfaceProducer, &photoOutput);
    EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
    return photoOutput;
}

int32_t CameraDeferredPhotoModuleTest::RegisterPhotoAvailableCallback()
{
    CHECK_RETURN_RET(photoOutput_ == nullptr, EXECUTE_FAILED);
    photoListener_ = sptr<PhotoListenerModuleTest>::MakeSptr(photoOutput_);
    CHECK_RETURN_RET_ELOG(photoListener_ == nullptr, EXECUTE_FAILED, "photoListener_ is nullptr");
    CHECK_RETURN_RET_ELOG(photoSurface_ == nullptr, EXECUTE_FAILED, "photoSurface_ is nullptr");
    SurfaceError ret = photoSurface_->RegisterConsumerListener((sptr<IBufferConsumerListener>&)photoListener_);
    CHECK_RETURN_RET_ELOG(ret != SURFACE_ERROR_OK, EXECUTE_FAILED, "RegisterConsumerListener failed");

    auto photoOutput = photoListener_->wPhotoOutput_.promote();
    CHECK_RETURN_RET_ELOG(photoOutput == nullptr, EXECUTE_FAILED, "wPhotoOutput promote failed");
    photoOutput->callbackFlag_ |= CAPTURE_PHOTO;
    photoOutput->SetCallbackFlag(photoOutput->callbackFlag_);
    return EXECUTE_SUCCESS;
}

int32_t CameraDeferredPhotoModuleTest::RegisterPhotoAssetAvailableCallback()
{
    CHECK_RETURN_RET(photoOutput_ == nullptr, EXECUTE_FAILED);
    photoListener_ = sptr<PhotoListenerModuleTest>::MakeSptr(photoOutput_);
    CHECK_RETURN_RET_ELOG(photoListener_ == nullptr, EXECUTE_FAILED, "photoListener_ is nullptr");
    CHECK_RETURN_RET_ELOG(photoSurface_ == nullptr, EXECUTE_FAILED, "photoSurface_ is nullptr");
    SurfaceError ret = photoSurface_->RegisterConsumerListener((sptr<IBufferConsumerListener>&)photoListener_);
    CHECK_RETURN_RET_ELOG(ret != SURFACE_ERROR_OK, EXECUTE_FAILED, "RegisterConsumerListener failed");

    auto photoOutput = photoListener_->wPhotoOutput_.promote();
    CHECK_RETURN_RET_ELOG(photoOutput == nullptr, EXECUTE_FAILED, "wPhotoOutput promote failed");
    photoOutput->callbackFlag_ |= CAPTURE_PHOTO_ASSET;
    photoOutput->SetCallbackFlag(photoOutput->callbackFlag_);

    return EXECUTE_SUCCESS;
}

int32_t CameraDeferredPhotoModuleTest::AddPhotoOutput(sptr<PhotoOutput>& photoOutput)
{
    CHECK_RETURN_RET(captureSession_ == nullptr, EXECUTE_FAILED);
    sptr<CaptureOutput> output = static_cast<CaptureOutput*>(photoOutput.GetRefPtr());
    CHECK_RETURN_RET_ELOG(!captureSession_->CanAddOutput(output), EXECUTE_FAILED, "Can not add photo output");
    int32_t ret = captureSession_->AddOutput(output);
    CHECK_RETURN_RET_ELOG(ret != EXECUTE_SUCCESS, EXECUTE_FAILED, "AddPhotoOutput failed");
    isPhotoOutputAdded_ = true;
    return EXECUTE_SUCCESS;
}

int32_t CameraDeferredPhotoModuleTest::Start()
{
    CHECK_RETURN_RET(captureSession_ == nullptr, EXECUTE_FAILED);
    int32_t ret = captureSession_->Start();
    CHECK_RETURN_RET_ELOG(ret != EXECUTE_SUCCESS, EXECUTE_FAILED, "Start capture session failed");
    isSessionStarted_ = true;
    return EXECUTE_SUCCESS;
}

int32_t CameraDeferredPhotoModuleTest::Capture()
{
    CHECK_RETURN_RET(photoOutput_ == nullptr, EXECUTE_FAILED);
    CHECK_RETURN_RET(!isSessionStarted_, EXECUTE_FAILED);
    std::shared_ptr<PhotoCaptureSetting> setting = std::make_shared<PhotoCaptureSetting>();
    CHECK_RETURN_RET_ELOG(setting == nullptr, EXECUTE_FAILED, "setting is nullptr");
    setting->SetQuality(PhotoCaptureSetting::QualityLevel::QUALITY_LEVEL_HIGH);
    setting->SetRotation(PhotoCaptureSetting::RotationConfig::Rotation_0);
    int32_t ret = photoOutput_->Capture(setting);
    CHECK_RETURN_RET_ELOG(ret != EXECUTE_SUCCESS, EXECUTE_FAILED, "Capture failed");
    return EXECUTE_SUCCESS;
}

void PhotoListenerModuleTest::OnBufferAvailable()
{
    std::lock_guard<std::mutex> lock(mtx_);
    calldeCount_++;
    MEDIA_INFO_LOG("PhotoListenerModuleTest::OnBufferAvailable is caled, calldeCount_= %{public}d", calldeCount_);

    if (calldeCount_ >= PHOTO_CALLBCAK_CNT) {
        cv_.notify_all();
    }
}

PhotoListenerModuleTest::PhotoListenerModuleTest(wptr<PhotoOutput> photoOutput)
{
    wPhotoOutput_ = photoOutput;
    calldeCount_ = 0;
}

void PhotoListenerModuleTest::WaitForPhotoCallbackAndSetTimeOut()
{
    std::unique_lock<std::mutex> lock(mtx_);
    if (cv_.wait_for(lock, std::chrono::seconds(WAIT_FOR_PHOTO_CB), [this] {
        return this->calldeCount_ >= PHOTO_CALLBCAK_CNT;
    })) {
        MEDIA_INFO_LOG("photo callback is called, calldeCount_ = %{public}d", calldeCount_);
    } else {
        MEDIA_ERR_LOG("[TIMEOUT] photo callback is not called, calldeCount_ = %{public}d", calldeCount_);
    }
}

/*
 * Feature: Framework
 * Function: Test default enabling deferred photo.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify the deferred photo is enabled by default in normal conditions after registering photo asset
 *                  available listener.
 */
HWTEST_F(CameraDeferredPhotoModuleTest, camera_deferred_photo_moduletest_001, TestSize.Level0)
{
    CHECK_RETURN(!isInitSuccess_);
    photoOutput_ = CreatePhotoOutputWithoutSurfaceId(photoProfiles_[0]);
    ASSERT_NE(photoOutput_, nullptr);

    int32_t ret = RegisterPhotoAssetAvailableCallback();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    captureSession_ = cameraManager_->CreateCaptureSession(CAPTURE_SCENE_MODE);
    ASSERT_NE(captureSession_, nullptr);

    ret = captureSession_->BeginConfig();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = AddInput(cameraInput_);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = AddPreviewOutput(previewOutput_);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = AddPhotoOutput(photoOutput_);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = photoOutput_->IsDeferredImageDeliverySupported(DELIVERY_PHOTO);
    CHECK_RETURN(ret != 0);

    ret = photoOutput_->IsDeferredImageDeliveryEnabled(DELIVERY_PHOTO);
    EXPECT_EQ(ret, DEFERRED_PHOTO_NOT_ENABLED);

    ret = captureSession_->CommitConfig();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = photoOutput_->IsDeferredImageDeliveryEnabled(DELIVERY_PHOTO);
    EXPECT_EQ(ret, DEFERRED_PHOTO_ENABLED);

    ret = Start();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = Capture();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    photoListener_->WaitForPhotoCallbackAndSetTimeOut();
    EXPECT_EQ(photoListener_->calldeCount_, PHOTO_CALLBCAK_CNT);
}

/*
 * Feature: Framework
 * Function: Test default enabling deferred photo.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify the deferred photo is enabled by default, neither registering photo asset available
 *                  listener nor photo available listener.
 */
HWTEST_F(CameraDeferredPhotoModuleTest, camera_deferred_photo_moduletest_002, TestSize.Level0)
{
    CHECK_RETURN(!isInitSuccess_);
    photoOutput_ = CreatePhotoOutputWithoutSurfaceId(photoProfiles_[0]);
    ASSERT_NE(photoOutput_, nullptr);

    captureSession_ = cameraManager_->CreateCaptureSession(CAPTURE_SCENE_MODE);
    ASSERT_NE(captureSession_, nullptr);

    int32_t ret = captureSession_->BeginConfig();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = AddInput(cameraInput_);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = AddPreviewOutput(previewOutput_);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = AddPhotoOutput(photoOutput_);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = photoOutput_->IsDeferredImageDeliverySupported(DELIVERY_PHOTO);
    CHECK_RETURN(ret != 0);

    ret = photoOutput_->IsDeferredImageDeliveryEnabled(DELIVERY_PHOTO);
    EXPECT_EQ(ret, DEFERRED_PHOTO_NOT_ENABLED);

    ret = captureSession_->CommitConfig();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = photoOutput_->IsDeferredImageDeliveryEnabled(DELIVERY_PHOTO);
    EXPECT_EQ(ret, DEFERRED_PHOTO_ENABLED);

    ret = Start();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = Capture();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test default enabling deferred photo in abnormal conditions.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify the deferred photo is not enabled by default under the abnormal condition, registering
 *                  photo available listener only.
 */
HWTEST_F(CameraDeferredPhotoModuleTest, camera_deferred_photo_moduletest_003, TestSize.Level0)
{
    CHECK_RETURN(!isInitSuccess_);
    photoOutput_ = CreatePhotoOutputWithoutSurfaceId(photoProfiles_[0]);
    ASSERT_NE(photoOutput_, nullptr);

    int32_t ret = RegisterPhotoAvailableCallback();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    captureSession_ = cameraManager_->CreateCaptureSession(CAPTURE_SCENE_MODE);
    ASSERT_NE(captureSession_, nullptr);

    ret = captureSession_->BeginConfig();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = AddInput(cameraInput_);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = AddPreviewOutput(previewOutput_);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = AddPhotoOutput(photoOutput_);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = photoOutput_->IsDeferredImageDeliverySupported(DELIVERY_PHOTO);
    CHECK_RETURN(ret != 0);

    ret = captureSession_->CommitConfig();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = photoOutput_->IsDeferredImageDeliveryEnabled(DELIVERY_PHOTO);
    EXPECT_EQ(ret, DEFERRED_PHOTO_NOT_ENABLED);

    ret = Start();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test default enabling deferred photo in abnormal conditions.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify the deferred photo is not enabled by default under the abnormal condition, creating photo
 *                  output with surface id.
 */
HWTEST_F(CameraDeferredPhotoModuleTest, camera_deferred_photo_moduletest_004, TestSize.Level0)
{
    CHECK_RETURN(!isInitSuccess_);
    photoOutput_ = CreatePhotoOutputWithSurfaceId(photoProfiles_[0]);
    ASSERT_NE(photoOutput_, nullptr);

    captureSession_ = cameraManager_->CreateCaptureSession(CAPTURE_SCENE_MODE);
    ASSERT_NE(captureSession_, nullptr);

    int32_t ret = captureSession_->BeginConfig();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = AddInput(cameraInput_);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = AddPreviewOutput(previewOutput_);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = AddPhotoOutput(photoOutput_);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = photoOutput_->IsDeferredImageDeliverySupported(DELIVERY_PHOTO);
    CHECK_RETURN(ret != 0);

    ret = captureSession_->CommitConfig();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = photoOutput_->IsDeferredImageDeliveryEnabled(DELIVERY_PHOTO);
    EXPECT_EQ(ret, DEFERRED_PHOTO_NOT_ENABLED);

    ret = Start();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test default enabling deferred photo in abnormal conditions.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify the deferred photo is not enabled by default under the abnormal condition, enabling
 *                  DELIVERY_NONE type in advance.
 */
HWTEST_F(CameraDeferredPhotoModuleTest, camera_deferred_photo_moduletest_005, TestSize.Level0)
{
    CHECK_RETURN(!isInitSuccess_);
    photoOutput_ = CreatePhotoOutputWithoutSurfaceId(photoProfiles_[0]);
    ASSERT_NE(photoOutput_, nullptr);

    int32_t ret = RegisterPhotoAssetAvailableCallback();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    captureSession_ = cameraManager_->CreateCaptureSession(CAPTURE_SCENE_MODE);
    ASSERT_NE(captureSession_, nullptr);

    ret = captureSession_->BeginConfig();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = AddInput(cameraInput_);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = AddPreviewOutput(previewOutput_);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = AddPhotoOutput(photoOutput_);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = photoOutput_->IsDeferredImageDeliverySupported(DELIVERY_PHOTO);
    CHECK_RETURN(ret != 0);

    ret = photoOutput_->IsDeferredImageDeliverySupported(DELIVERY_NONE);
    CHECK_RETURN(ret != 0);

    ret = photoOutput_->DeferImageDeliveryFor(DELIVERY_NONE);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = captureSession_->CommitConfig();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = photoOutput_->IsDeferredImageDeliveryEnabled(DELIVERY_PHOTO);
    EXPECT_EQ(ret, DEFERRED_PHOTO_NOT_ENABLED);

    ret = Start();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test default enabling deferred photo in abnormal conditions.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify the deferred photo is not enabled by default under the abnormal condition, enabling
 *                  DELIVERY_VIDEO type in advance.
 */
HWTEST_F(CameraDeferredPhotoModuleTest, camera_deferred_photo_moduletest_006, TestSize.Level0)
{
    CHECK_RETURN(!isInitSuccess_);
    photoOutput_ = CreatePhotoOutputWithoutSurfaceId(photoProfiles_[0]);
    ASSERT_NE(photoOutput_, nullptr);

    int32_t ret = RegisterPhotoAssetAvailableCallback();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    captureSession_ = cameraManager_->CreateCaptureSession(CAPTURE_SCENE_MODE);
    ASSERT_NE(captureSession_, nullptr);

    ret = captureSession_->BeginConfig();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = AddInput(cameraInput_);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = AddPreviewOutput(previewOutput_);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = AddPhotoOutput(photoOutput_);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = photoOutput_->IsDeferredImageDeliverySupported(DELIVERY_PHOTO);
    CHECK_RETURN(ret != 0);

    ret = photoOutput_->IsDeferredImageDeliverySupported(DELIVERY_VIDEO);
    CHECK_RETURN(ret != 0);

    ret = photoOutput_->DeferImageDeliveryFor(DELIVERY_VIDEO);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = captureSession_->CommitConfig();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = photoOutput_->IsDeferredImageDeliveryEnabled(DELIVERY_PHOTO);
    EXPECT_EQ(ret, DEFERRED_PHOTO_NOT_ENABLED);

    ret = Start();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test active enabling deferred photo in normal conditions.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify the deferred photo is enabled in normal conditions.
 */
HWTEST_F(CameraDeferredPhotoModuleTest, camera_deferred_photo_moduletest_007, TestSize.Level0)
{
    CHECK_RETURN(!isInitSuccess_);
    photoOutput_ = CreatePhotoOutputWithoutSurfaceId(photoProfiles_[0]);
    ASSERT_NE(photoOutput_, nullptr);

    int32_t ret = RegisterPhotoAssetAvailableCallback();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    captureSession_ = cameraManager_->CreateCaptureSession(CAPTURE_SCENE_MODE);
    ASSERT_NE(captureSession_, nullptr);

    ret = captureSession_->BeginConfig();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = AddInput(cameraInput_);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = AddPreviewOutput(previewOutput_);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = AddPhotoOutput(photoOutput_);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = photoOutput_->IsDeferredImageDeliverySupported(DELIVERY_PHOTO);
    CHECK_RETURN(ret != 0);

    ret = photoOutput_->IsDeferredImageDeliveryEnabled(DELIVERY_PHOTO);
    EXPECT_EQ(ret, DEFERRED_PHOTO_NOT_ENABLED);

    ret = photoOutput_->DeferImageDeliveryFor(DELIVERY_PHOTO);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = photoOutput_->IsDeferredImageDeliveryEnabled(DELIVERY_PHOTO);
    EXPECT_EQ(ret, DEFERRED_PHOTO_ENABLED);

    ret = captureSession_->CommitConfig();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = Start();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = Capture();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    photoListener_->WaitForPhotoCallbackAndSetTimeOut();
    EXPECT_EQ(photoListener_->calldeCount_, PHOTO_CALLBCAK_CNT);
}

/*
 * Feature: Framework
 * Function: Test active enabling deferred photo in abnormal conditions.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify the deferred photo is not enabled under the abnormal condition, enabling before AddInput.
 */
HWTEST_F(CameraDeferredPhotoModuleTest, camera_deferred_photo_moduletest_008, TestSize.Level0)
{
    CHECK_RETURN(!isInitSuccess_);
    photoOutput_ = CreatePhotoOutputWithoutSurfaceId(photoProfiles_[0]);
    ASSERT_NE(photoOutput_, nullptr);

    int32_t ret = RegisterPhotoAssetAvailableCallback();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    captureSession_ = cameraManager_->CreateCaptureSession(CAPTURE_SCENE_MODE);
    ASSERT_NE(captureSession_, nullptr);

    ret = captureSession_->BeginConfig();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = photoOutput_->IsDeferredImageDeliverySupported(DELIVERY_PHOTO);
    EXPECT_EQ(ret, CameraErrorCode::SESSION_NOT_RUNNING);

    ret = photoOutput_->DeferImageDeliveryFor(DELIVERY_PHOTO);
    EXPECT_EQ(ret, CameraErrorCode::SESSION_NOT_RUNNING);

    ret = photoOutput_->IsDeferredImageDeliveryEnabled(DELIVERY_PHOTO);
    EXPECT_EQ(ret, CameraErrorCode::SESSION_NOT_RUNNING);

    ret = AddInput(cameraInput_);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = AddPreviewOutput(previewOutput_);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = AddPhotoOutput(photoOutput_);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = photoOutput_->IsDeferredImageDeliverySupported(DELIVERY_PHOTO);
    CHECK_RETURN(ret != 0);

    ret = photoOutput_->IsDeferredImageDeliveryEnabled(DELIVERY_PHOTO);
    EXPECT_EQ(ret, DEFERRED_PHOTO_NOT_ENABLED);

    ret = captureSession_->CommitConfig();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = Start();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test active enabling deferred photo in abnormal conditions.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify the deferred photo is not enabled under the abnormal condition, enabling after AddInput but
 *                  before AddPhotoOoutput.
 */
HWTEST_F(CameraDeferredPhotoModuleTest, camera_deferred_photo_moduletest_009, TestSize.Level0)
{
    CHECK_RETURN(!isInitSuccess_);
    photoOutput_ = CreatePhotoOutputWithoutSurfaceId(photoProfiles_[0]);
    ASSERT_NE(photoOutput_, nullptr);

    int32_t ret = RegisterPhotoAssetAvailableCallback();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    captureSession_ = cameraManager_->CreateCaptureSession(CAPTURE_SCENE_MODE);
    ASSERT_NE(captureSession_, nullptr);

    ret = captureSession_->BeginConfig();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = AddInput(cameraInput_);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = AddPreviewOutput(previewOutput_);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = photoOutput_->IsDeferredImageDeliverySupported(DELIVERY_PHOTO);
    EXPECT_EQ(ret, CameraErrorCode::SESSION_NOT_RUNNING);

    ret = photoOutput_->DeferImageDeliveryFor(DELIVERY_PHOTO);
    EXPECT_EQ(ret, CameraErrorCode::SESSION_NOT_RUNNING);

    ret = photoOutput_->IsDeferredImageDeliveryEnabled(DELIVERY_PHOTO);
    EXPECT_EQ(ret, CameraErrorCode::SESSION_NOT_RUNNING);

    ret = AddPhotoOutput(photoOutput_);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = photoOutput_->IsDeferredImageDeliverySupported(DELIVERY_PHOTO);
    CHECK_RETURN(ret != 0);

    ret = photoOutput_->IsDeferredImageDeliveryEnabled(DELIVERY_PHOTO);
    EXPECT_EQ(ret, DEFERRED_PHOTO_NOT_ENABLED);

    ret = captureSession_->CommitConfig();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = Start();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test active enabling deferred photo in abnormal conditions.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify the deferred photo is not enabled under the abnormal condition, enabling after CommitConfig,
 *                  when default enabling is turned off by enabling DELIVERY_NONE type in advance.
 */
HWTEST_F(CameraDeferredPhotoModuleTest, camera_deferred_photo_moduletest_010, TestSize.Level0)
{
    CHECK_RETURN(!isInitSuccess_);
    photoOutput_ = CreatePhotoOutputWithoutSurfaceId(photoProfiles_[0]);
    ASSERT_NE(photoOutput_, nullptr);

    int32_t ret = RegisterPhotoAssetAvailableCallback();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    captureSession_ = cameraManager_->CreateCaptureSession(CAPTURE_SCENE_MODE);
    ASSERT_NE(captureSession_, nullptr);

    ret = captureSession_->BeginConfig();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = AddInput(cameraInput_);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = AddPreviewOutput(previewOutput_);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = AddPhotoOutput(photoOutput_);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = photoOutput_->IsDeferredImageDeliverySupported(DELIVERY_PHOTO);
    CHECK_RETURN(ret != 0);

    ret = photoOutput_->IsDeferredImageDeliverySupported(DELIVERY_NONE);
    CHECK_RETURN(ret != 0);

    ret = photoOutput_->DeferImageDeliveryFor(DELIVERY_NONE);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = photoOutput_->IsDeferredImageDeliveryEnabled(DELIVERY_PHOTO);
    EXPECT_EQ(ret, DEFERRED_PHOTO_NOT_ENABLED);

    ret = captureSession_->CommitConfig();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = photoOutput_->IsDeferredImageDeliveryEnabled(DELIVERY_PHOTO);
    EXPECT_EQ(ret, DEFERRED_PHOTO_NOT_ENABLED);

    ret = photoOutput_->DeferImageDeliveryFor(DELIVERY_PHOTO);
    EXPECT_EQ(ret, EXECUTE_SUCCESS);

    ret = photoOutput_->IsDeferredImageDeliveryEnabled(DELIVERY_PHOTO);
    EXPECT_EQ(ret, DEFERRED_PHOTO_NOT_ENABLED);

    ret = Start();
    EXPECT_EQ(ret, EXECUTE_SUCCESS);
}
} // namespace CameraStandard
} // namespace OHOS