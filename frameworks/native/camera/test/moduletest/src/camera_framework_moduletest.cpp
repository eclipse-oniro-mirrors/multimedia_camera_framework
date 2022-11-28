/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "camera_framework_moduletest.h"
#include <cinttypes>
#include "input/camera_input.h"
#include "input/camera_manager.h"
#include "camera_log.h"
#include "surface.h"
#include "test_common.h"

#include "ipc_skeleton.h"
#include "access_token.h"
#include "hap_token_info.h"
#include "accesstoken_kit.h"
#include "token_setproc.h"
#include "camera_util.h"
#include "nativetoken_kit.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
namespace {
    enum class CAM_PHOTO_EVENTS {
        CAM_PHOTO_CAPTURE_START = 0,
        CAM_PHOTO_CAPTURE_END,
        CAM_PHOTO_CAPTURE_ERR,
        CAM_PHOTO_FRAME_SHUTTER,
        CAM_PHOTO_MAX_EVENT
    };

    enum class CAM_PREVIEW_EVENTS {
        CAM_PREVIEW_FRAME_START = 0,
        CAM_PREVIEW_FRAME_END,
        CAM_PREVIEW_FRAME_ERR,
        CAM_PREVIEW_MAX_EVENT
    };

    enum class CAM_VIDEO_EVENTS {
        CAM_VIDEO_FRAME_START = 0,
        CAM_VIDEO_FRAME_END,
        CAM_VIDEO_FRAME_ERR,
        CAM_VIDEO_MAX_EVENT
    };

    const int32_t WAIT_TIME_AFTER_CAPTURE = 1;
    const int32_t WAIT_TIME_AFTER_START = 2;
    const int32_t WAIT_TIME_BEFORE_STOP = 1;

    bool g_camInputOnError = false;
    bool g_sessionclosed = false;
    int32_t g_videoFd = -1;
    std::bitset<static_cast<int>(CAM_PHOTO_EVENTS::CAM_PHOTO_MAX_EVENT)> g_photoEvents;
    std::bitset<static_cast<unsigned int>(CAM_PREVIEW_EVENTS::CAM_PREVIEW_MAX_EVENT)> g_previewEvents;
    std::bitset<static_cast<unsigned int>(CAM_VIDEO_EVENTS::CAM_VIDEO_MAX_EVENT)> g_videoEvents;
    std::unordered_map<std::string, int> g_camStatusMap;
    std::unordered_map<std::string, bool> g_camFlashMap;

    class AppCallback : public CameraManagerCallback, public ErrorCallback, public PhotoStateCallback,
                        public PreviewStateCallback {
    public:
        void OnCameraStatusChanged(const CameraStatusInfo &cameraDeviceInfo) const override
        {
            const std::string cameraID = cameraDeviceInfo.cameraDevice->GetID();
            const CameraStatus cameraStatus = cameraDeviceInfo.cameraStatus;

            switch (cameraStatus) {
                case CAMERA_STATUS_UNAVAILABLE: {
                    MEDIA_DEBUG_LOG("AppCallback::OnCameraStatusChanged %{public}s: CAMERA_STATUS_UNAVAILABLE",
                                    cameraID.c_str());
                    g_camStatusMap[cameraID] = CAMERA_STATUS_UNAVAILABLE;
                    break;
                }
                case CAMERA_STATUS_AVAILABLE: {
                    MEDIA_DEBUG_LOG("AppCallback::OnCameraStatusChanged %{public}s: CAMERA_STATUS_AVAILABLE",
                                    cameraID.c_str());
                    g_camStatusMap[cameraID] = CAMERA_STATUS_AVAILABLE;
                    break;
                }
                default: {
                    MEDIA_DEBUG_LOG("AppCallback::OnCameraStatusChanged %{public}s: unknown", cameraID.c_str());
                    EXPECT_TRUE(false);
                }
            }
            return;
        }

        void OnFlashlightStatusChanged(const std::string &cameraID, const FlashStatus flashStatus) const override
        {
            switch (flashStatus) {
                case FLASH_STATUS_OFF: {
                    MEDIA_DEBUG_LOG("AppCallback::OnFlashlightStatusChanged %{public}s: FLASH_STATUS_OFF",
                                    cameraID.c_str());
                    g_camFlashMap[cameraID] = false;
                    break;
                }
                case FLASH_STATUS_ON: {
                    MEDIA_DEBUG_LOG("AppCallback::OnFlashlightStatusChanged %{public}s: FLASH_STATUS_ON",
                                    cameraID.c_str());
                    g_camFlashMap[cameraID] = true;
                    break;
                }
                case FLASH_STATUS_UNAVAILABLE: {
                    MEDIA_DEBUG_LOG("AppCallback::OnFlashlightStatusChanged %{public}s: FLASH_STATUS_UNAVAILABLE",
                                    cameraID.c_str());
                    g_camFlashMap.erase(cameraID);
                    break;
                }
                default: {
                    MEDIA_DEBUG_LOG("AppCallback::OnFlashlightStatusChanged %{public}s: unknown", cameraID.c_str());
                    EXPECT_TRUE(false);
                }
            }
            return;
        }

        void OnError(const int32_t errorType, const int32_t errorMsg) const override
        {
            MEDIA_DEBUG_LOG("AppCallback::OnError errorType: %{public}d, errorMsg: %{public}d", errorType, errorMsg);
            g_camInputOnError = true;
            if (errorType == CAMERA_DEVICE_PREEMPTED) {
                g_sessionclosed = true;
            }
            return;
        }

        void OnCaptureStarted(const int32_t captureId) const override
        {
            MEDIA_DEBUG_LOG("AppCallback::OnCaptureStarted captureId: %{public}d", captureId);
            g_photoEvents[static_cast<int>(CAM_PHOTO_EVENTS::CAM_PHOTO_CAPTURE_START)] = 1;
            return;
        }

        void OnCaptureEnded(const int32_t captureId, const int32_t frameCount) const override
        {
            MEDIA_DEBUG_LOG("AppCallback::OnCaptureEnded captureId: %{public}d, frameCount: %{public}d",
                            captureId, frameCount);
            g_photoEvents[static_cast<int>(CAM_PHOTO_EVENTS::CAM_PHOTO_CAPTURE_END)] = 1;
            return;
        }

        void OnFrameShutter(const int32_t captureId, const uint64_t timestamp) const override
        {
            MEDIA_DEBUG_LOG("AppCallback::OnFrameShutter captureId: %{public}d, timestamp: %{public}"
                            PRIu64, captureId, timestamp);
            g_photoEvents[static_cast<int>(CAM_PHOTO_EVENTS::CAM_PHOTO_FRAME_SHUTTER)] = 1;
            return;
        }

        void OnCaptureError(const int32_t captureId, const int32_t errorCode) const override
        {
            MEDIA_DEBUG_LOG("AppCallback::OnCaptureError captureId: %{public}d, errorCode: %{public}d",
                            captureId, errorCode);
            g_photoEvents[static_cast<int>(CAM_PHOTO_EVENTS::CAM_PHOTO_CAPTURE_ERR)] = 1;
            return;
        }

        void OnFrameStarted() const override
        {
            MEDIA_DEBUG_LOG("AppCallback::OnFrameStarted");
            g_previewEvents[static_cast<int>(CAM_PREVIEW_EVENTS::CAM_PREVIEW_FRAME_START)] = 1;
            return;
        }
        void OnFrameEnded(const int32_t frameCount) const override
        {
            MEDIA_DEBUG_LOG("AppCallback::OnFrameEnded frameCount: %{public}d", frameCount);
            g_previewEvents[static_cast<int>(CAM_PREVIEW_EVENTS::CAM_PREVIEW_FRAME_END)] = 1;
            return;
        }
        void OnError(const int32_t errorCode) const override
        {
            MEDIA_DEBUG_LOG("AppCallback::OnError errorCode: %{public}d", errorCode);
            g_previewEvents[static_cast<int>(CAM_PREVIEW_EVENTS::CAM_PREVIEW_FRAME_ERR)] = 1;
            return;
        }
    };

    class AppVideoCallback : public VideoStateCallback {
        void OnFrameStarted() const override
        {
            MEDIA_DEBUG_LOG("AppVideoCallback::OnFrameStarted");
            g_videoEvents[static_cast<int>(CAM_VIDEO_EVENTS::CAM_VIDEO_FRAME_START)] = 1;
            return;
        }
        void OnFrameEnded(const int32_t frameCount) const override
        {
            MEDIA_DEBUG_LOG("AppVideoCallback::OnFrameEnded frameCount: %{public}d", frameCount);
            g_videoEvents[static_cast<int>(CAM_VIDEO_EVENTS::CAM_VIDEO_FRAME_END)] = 1;
            return;
        }
        void OnError(const int32_t errorCode) const override
        {
            MEDIA_DEBUG_LOG("AppVideoCallback::OnError errorCode: %{public}d", errorCode);
            g_videoEvents[static_cast<int>(CAM_VIDEO_EVENTS::CAM_VIDEO_FRAME_ERR)] = 1;
            return;
        }
    };

    class AppMetadataCallback : public MetadataObjectCallback, public MetadataStateCallback {
    public:
        void OnMetadataObjectsAvailable(std::vector<sptr<MetadataObject>> metaObjects) const
        {
            MEDIA_DEBUG_LOG("AppMetadataCallback::OnMetadataObjectsAvailable received");
        }
        void OnError(int32_t errorCode) const
        {
            MEDIA_DEBUG_LOG("AppMetadataCallback::OnError %{public}d", errorCode);
        }
    };
} // namespace

sptr<CaptureOutput> CameraFrameworkModuleTest::CreatePhotoOutput(int32_t width, int32_t height)
{
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    CameraFormat photoFormat = CAMERA_FORMAT_JPEG;
    Size photoSize;
    photoSize.width = width;
    photoSize.height = height;
    Profile photoProfile = Profile(photoFormat, photoSize);
    sptr<CaptureOutput> photoOutput = nullptr;
    photoOutput = manager_->CreatePhotoOutput(photoProfile, surface);
    return photoOutput;
}

sptr<CaptureOutput> CameraFrameworkModuleTest::CreatePhotoOutput()
{
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoWidth_, photoHeight_);
    return photoOutput;
}

sptr<CaptureOutput> CameraFrameworkModuleTest::CreatePreviewOutput(int32_t width, int32_t height)
{
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    CameraFormat previewFormat = CAMERA_FORMAT_YUV_420_SP;
    Size previewSize;
    previewSize.width = width;
    previewSize.height = height;
    Profile previewProfile = Profile(previewFormat, previewSize);
    sptr<CaptureOutput> previewOutput = nullptr;
    previewOutput = manager_->CreatePreviewOutput(previewProfile, surface);
    return previewOutput;
}

sptr<CaptureOutput> CameraFrameworkModuleTest::CreatePreviewOutput()
{
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewWidth_, previewHeight_);
    return previewOutput;
}

sptr<CaptureOutput> CameraFrameworkModuleTest::CreateVideoOutput(int32_t width, int32_t height)
{
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    CameraFormat videoFormat = CAMERA_FORMAT_YUV_420_SP;
    Size videoSize;
    videoSize.width = width;
    videoSize.height = height;
    std::vector<int32_t> frameRate = {30, 30};
    VideoProfile videoProfile = VideoProfile(videoFormat, videoSize, frameRate);
    sptr<CaptureOutput> videoOutput = nullptr;
    videoOutput = manager_->CreateVideoOutput(videoProfile, surface);
    return videoOutput;
}

sptr<CaptureOutput> CameraFrameworkModuleTest::CreateVideoOutput()
{
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoWidth_, videoHeight_);
    return videoOutput;
}

void CameraFrameworkModuleTest::SetCameraParameters(sptr<CaptureSession> &session, bool video)
{
    session->LockForControl();

    std::vector<float> zoomRatioRange = session->GetZoomRatioRange();
    if (!zoomRatioRange.empty()) {
        session->SetZoomRatio(zoomRatioRange[0]);
    }

    // GetExposureBiasRange
    std::vector<int32_t> exposureBiasRange = session->GetExposureBiasRange();
    if (!exposureBiasRange.empty()) {
        session->SetExposureBias(exposureBiasRange[0]);
    }

    // Get/Set Exposurepoint
    Point exposurePoint = {1, 2};
    session->SetMeteringPoint(exposurePoint);

    // GetFocalLength
    float focalLength = session->GetFocalLength();
    ASSERT_NE(focalLength, 0);

    // Get/Set focuspoint
    Point focusPoint = {1, 2};
    session->SetFocusPoint(focusPoint);

    FlashMode flash = FLASH_MODE_OPEN;
    if (video) {
        flash = FLASH_MODE_ALWAYS_OPEN;
    }
    session->SetFlashMode(flash);

    FocusMode focus = FOCUS_MODE_AUTO;
    session->SetFocusMode(focus);

    ExposureMode exposure = EXPOSURE_MODE_AUTO;
    session->SetExposureMode(exposure);

    session->UnlockForControl();

    Point exposurePointGet = session->GetMeteringPoint();
    EXPECT_EQ(exposurePointGet.x, exposurePoint.x);
    EXPECT_EQ(exposurePointGet.y, exposurePoint.y);

    Point focusPointGet = session->GetFocusPoint();
    EXPECT_EQ(focusPointGet.x, focusPoint.x);
    EXPECT_EQ(focusPointGet.y, focusPoint.y);

    if (!zoomRatioRange.empty()) {
        EXPECT_EQ(session->GetZoomRatio(), zoomRatioRange[0]);
    }

    // exposureBiasRange
    if (!exposureBiasRange.empty()) {
        EXPECT_EQ(session->GetExposureValue(), exposureBiasRange[0]);
    }

    EXPECT_EQ(session->GetFlashMode(), flash);
    EXPECT_EQ(session->GetFocusMode(), focus);
    EXPECT_EQ(session->GetExposureMode(), exposure);
}

void CameraFrameworkModuleTest::TestCallbacksSession(sptr<CaptureOutput> photoOutput,
    sptr<CaptureOutput> videoOutput)
{
    int32_t intResult;

    if (videoOutput != nullptr) {
        intResult = session_->Start();
        EXPECT_EQ(intResult, 0);

        intResult = ((sptr<VideoOutput> &)videoOutput)->Start();
        EXPECT_EQ(intResult, 0);
        sleep(WAIT_TIME_AFTER_START);
    }

    if (photoOutput != nullptr) {
        intResult = ((sptr<PhotoOutput> &)photoOutput)->Capture();
        EXPECT_EQ(intResult, 0);
    }

    if (videoOutput != nullptr) {
        intResult = ((sptr<VideoOutput> &)videoOutput)->Stop();
        EXPECT_EQ(intResult, 0);
    }

    sleep(WAIT_TIME_BEFORE_STOP);
    session_->Stop();
}

void CameraFrameworkModuleTest::TestCallbacks(sptr<CameraDevice> &cameraInfo, bool video)
{
    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    // Register error callback
    std::shared_ptr<AppCallback> callback = std::make_shared<AppCallback>();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input_;
    camInput->SetErrorCallback(callback);

    EXPECT_EQ(g_camInputOnError, false);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    SetCameraParameters(session_, video);

    sptr<CaptureOutput> photoOutput = nullptr;
    sptr<CaptureOutput> videoOutput = nullptr;
    if (!video) {
        photoOutput = CreatePhotoOutput();
        ASSERT_NE(photoOutput, nullptr);

        // Register photo callback
        ((sptr<PhotoOutput> &)photoOutput)->SetCallback(std::make_shared<AppCallback>());
        intResult = session_->AddOutput(photoOutput);
    } else {
        videoOutput = CreateVideoOutput();
        ASSERT_NE(videoOutput, nullptr);

        // Register video callback
        ((sptr<VideoOutput> &)videoOutput)->SetCallback(std::make_shared<AppVideoCallback>());
        intResult = session_->AddOutput(videoOutput);
    }

    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    // Register preview callback
    ((sptr<PreviewOutput> &)previewOutput)->SetCallback(std::make_shared<AppCallback>());
    intResult = session_->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    /* In case of wagner device, once commit config is done with flash on
    it is not giving the flash status callback, removing it */
    EXPECT_TRUE(g_photoEvents.none());
    EXPECT_TRUE(g_previewEvents.none());
    EXPECT_TRUE(g_videoEvents.none());

    TestCallbacksSession(photoOutput, videoOutput);

    if (photoOutput != nullptr) {
        EXPECT_TRUE(g_photoEvents[static_cast<int>(CAM_PHOTO_EVENTS::CAM_PHOTO_CAPTURE_START)] == 1);
        /* In case of wagner device, frame shutter callback not working,
        hence removed. Once supported by hdi, the same needs to be
        enabled */
        ((sptr<PhotoOutput> &)photoOutput)->Release();
    }

    if (videoOutput != nullptr) {
        EXPECT_EQ(g_previewEvents[static_cast<int>(CAM_PREVIEW_EVENTS::CAM_PREVIEW_FRAME_START)], 1);

        TestUtils::SaveVideoFile(nullptr, 0, VideoSaveMode::CLOSE, g_videoFd);

        EXPECT_EQ(g_videoEvents[static_cast<int>(CAM_VIDEO_EVENTS::CAM_VIDEO_FRAME_START)], 1);
        EXPECT_EQ(g_videoEvents[static_cast<int>(CAM_VIDEO_EVENTS::CAM_VIDEO_FRAME_END)], 1);

        ((sptr<VideoOutput> &)videoOutput)->Release();
    }

    ((sptr<PreviewOutput> &)previewOutput)->Release();
}

void CameraFrameworkModuleTest::SetUpTestCase(void) {}
void CameraFrameworkModuleTest::TearDownTestCase(void) {}

void CameraFrameworkModuleTest::SetUpInit()
{
    MEDIA_DEBUG_LOG("Beginning of camera test case!");
    g_photoEvents.reset();
    g_previewEvents.reset();
    g_videoEvents.reset();
    g_camStatusMap.clear();
    g_camFlashMap.clear();
    g_camInputOnError = false;
    g_videoFd = -1;

    previewFormat_ = CAMERA_FORMAT_YUV_420_SP;
    videoFormat_ = CAMERA_FORMAT_YUV_420_SP;
    photoFormat_ = CAMERA_FORMAT_JPEG;
    previewWidth_ = PREVIEW_DEFAULT_WIDTH;
    previewHeight_ = PREVIEW_DEFAULT_HEIGHT;
    photoWidth_ = PHOTO_DEFAULT_WIDTH;
    photoHeight_ = PHOTO_DEFAULT_HEIGHT;
    videoWidth_ = VIDEO_DEFAULT_WIDTH;
    videoHeight_ = VIDEO_DEFAULT_HEIGHT;
}

void CameraFrameworkModuleTest::SetUp()
{
    SetUpInit();
    // set native token
    uint64_t tokenId;
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
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();

    manager_ = CameraManager::GetInstance();
    ASSERT_NE(manager_, nullptr);
    manager_->SetCallback(std::make_shared<AppCallback>());

    cameras_ = manager_->GetSupportedCameras();
    ASSERT_TRUE(cameras_.size() != 0);

    input_ = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input_, nullptr);

    sptr<CameraManager> camManagerObj = CameraManager::GetInstance();
    std::vector<sptr<CameraDevice>> cameraObjList = camManagerObj->GetSupportedCameras();
    sptr<CameraOutputCapability> outputcapability =  camManagerObj->GetSupportedOutputCapability(cameraObjList[0]);
    std::vector<Profile> previewProfiles = outputcapability->GetPreviewProfiles();
    for (auto i : previewProfiles) {
        previewFormats_.push_back(i.GetCameraFormat());
        previewSizes_.push_back(i.GetSize());
    }
    ASSERT_TRUE(!previewFormats_.empty());
    ASSERT_TRUE(!previewSizes_.empty());
    if (std::find(previewFormats_.begin(), previewFormats_.end(), CAMERA_FORMAT_YUV_420_SP)
        != previewFormats_.end()) {
        previewFormat_ = CAMERA_FORMAT_YUV_420_SP;
    } else {
        previewFormat_ = previewFormats_[0];
    }
    std::vector<Profile> photoProfiles =  outputcapability->GetPhotoProfiles();
        for (auto i : photoProfiles) {
            photoFormats_.push_back(i.GetCameraFormat());
            photoSizes_.push_back(i.GetSize());
        }
    ASSERT_TRUE(!photoFormats_.empty());
    ASSERT_TRUE(!photoSizes_.empty());
    photoFormat_ = photoFormats_[0];
    std::vector<VideoProfile> videoProfiles = outputcapability->GetVideoProfiles();
    for (auto i : videoProfiles) {
        videoFormats_.push_back(i.GetCameraFormat());
        videoSizes_.push_back(i.GetSize());
        videoFrameRates_ = i.GetFrameRates();
    }
    ASSERT_TRUE(!videoFormats_.empty());
    ASSERT_TRUE(!videoSizes_.empty());
    ASSERT_TRUE(!videoFrameRates_.empty());
    if (std::find(videoFormats_.begin(), videoFormats_.end(), CAMERA_FORMAT_YUV_420_SP)
        != videoFormats_.end()) {
        videoFormat_ = CAMERA_FORMAT_YUV_420_SP;
    } else {
        videoFormat_ = videoFormats_[0];
    }
    Size size = previewSizes_.back();
    previewWidth_ = size.width;
    previewHeight_ = size.height;
    size = photoSizes_.back();
    photoWidth_ = size.width;
    photoHeight_ = size.height;
    size = videoSizes_.back();
    videoWidth_ = size.width;
    videoHeight_ = size.height;

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input_;
    camInput->Open();

    session_ = manager_->CreateCaptureSession();
    ASSERT_NE(session_, nullptr);
}

void CameraFrameworkModuleTest::TearDown()
{
    if (session_) {
        session_->Release();
    }
    if (input_) {
        sptr<CameraInput> camInput = (sptr<CameraInput> &)input_;
        camInput->Close();
        input_->Release();
    }
    MEDIA_DEBUG_LOG("End of camera test case");
}

/*
 * Feature: Framework
 * Function: Test Capture
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Capture
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_001, TestSize.Level0)
{
    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);

    intResult = session_->AddOutput(photoOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    intResult = ((sptr<PhotoOutput> &)photoOutput)->Capture();
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);
    
    ((sptr<PhotoOutput> &)photoOutput)->Release();
}
/*
 * Feature: Framework
 * Function: Test Capture + Preview
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Capture + Preview
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_002, TestSize.Level0)
{
    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);

    intResult = session_->AddOutput(photoOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = session_->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);
    intResult = ((sptr<PreviewOutput> &)previewOutput)->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);
    intResult = ((sptr<PhotoOutput> &)photoOutput)->Capture();
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    ((sptr<PreviewOutput> &)previewOutput)->Stop();
    session_->Stop();
}

/*
 * Feature: Framework
 * Function: Test Preview + Video
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Preview + Video
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_003, TestSize.Level0)
{
    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = session_->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);

    intResult = session_->AddOutput(videoOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);
    intResult = ((sptr<PreviewOutput> &)previewOutput)->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    intResult = ((sptr<VideoOutput> &)videoOutput)->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    intResult = ((sptr<VideoOutput> &)videoOutput)->Stop();
    EXPECT_EQ(intResult, 0);

    TestUtils::SaveVideoFile(nullptr, 0, VideoSaveMode::CLOSE, g_videoFd);

    sleep(WAIT_TIME_BEFORE_STOP);
    ((sptr<PreviewOutput> &)previewOutput)->Stop();
    session_->Stop();
}

/*
 * Feature: Framework
 * Function: Test camera status, flash, camera input, photo output and preview output callbacks
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test callbacks
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_004, TestSize.Level0)
{
    TestCallbacks(cameras_[0], false);
}

/*
 * Feature: Framework
 * Function: Test camera status, flash, camera input, preview output and video output callbacks
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test callbacks
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_005, TestSize.Level0)
{
    TestCallbacks(cameras_[0], true);
}

/*
 * Feature: Framework
 * Function: Test Preview
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Preview
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_006, TestSize.Level0)
{
    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = session_->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);
    intResult = ((sptr<PreviewOutput> &)previewOutput)->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    ((sptr<PreviewOutput> &)previewOutput)->Stop();
    session_->Stop();
}

/*
 * Feature: Framework
 * Function: Test Video
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Video
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_007, TestSize.Level0)
{
    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);

    intResult = session_->AddOutput(videoOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);
    // Video mode without preview is not supported
}

/*
 * Feature: Framework
 * Function: Test Custom Preview with invalid resolutions
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Custom Preview with invalid resolution(0 * 0)
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_011, TestSize.Level0)
{
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
}

/*
 * Feature: Framework
 * Function: Test capture session with commit config multiple times
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session with commit config multiple times
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_017, TestSize.Level0)
{
    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = session_->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    intResult = session_->CommitConfig();
    EXPECT_NE(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test capture session add input with invalid value
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session add input with invalid value
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_018, TestSize.Level0)
{
    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    sptr<CaptureInput> input1 = nullptr;
    intResult = session_->AddInput(input1);
    EXPECT_NE(intResult, 0);

    session_->Stop();
}

/*
 * Feature: Framework
 * Function: Test capture session add output with invalid value
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session add output with invalid value
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_019, TestSize.Level0)
{
    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = nullptr;
    intResult = session_->AddOutput(previewOutput);
    EXPECT_NE(intResult, 0);

    session_->Stop();
}

/*
 * Feature: Framework
 * Function: Test capture session commit config without adding input
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session commit config without adding input
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_020, TestSize.Level0)
{
    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = session_->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_NE(intResult, 0);

    session_->Stop();
}

/*
 * Feature: Framework
 * Function: Test capture session commit config without adding output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session commit config without adding output
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_021, TestSize.Level0)
{
    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_NE(intResult, 0);

    session_->Stop();
}

/*
 * Feature: Framework
 * Function: Test capture session start and stop without adding preview output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session start and stop without adding preview output
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_022, TestSize.Level0)
{
    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);

    intResult = session_->AddOutput(photoOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    intResult = session_->Stop();
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test capture session without begin config
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session without begin config
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_023, TestSize.Level0)
{
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    int32_t intResult = session_->AddInput(input_);
    EXPECT_NE(intResult, 0);

    intResult = session_->AddOutput(photoOutput);
    EXPECT_NE(intResult, 0);

    intResult = session_->AddOutput(previewOutput);
    EXPECT_NE(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_NE(intResult, 0);

    intResult = session_->Start();
    EXPECT_NE(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);
    intResult = ((sptr<PreviewOutput> &)previewOutput)->Start();
    EXPECT_NE(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);
    intResult = ((sptr<PhotoOutput> &)photoOutput)->Capture();
    EXPECT_NE(intResult, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    ((sptr<PreviewOutput> &)previewOutput)->Stop();
    session_->Stop();
}

/*
 * Feature: Framework
 * Function: Test capture session with multiple photo outputs
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session with multiple photo outputs
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_024, TestSize.Level0)
{
    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> photoOutput1 = CreatePhotoOutput();
    ASSERT_NE(photoOutput1, nullptr);

    intResult = session_->AddOutput(photoOutput1);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> photoOutput2 = CreatePhotoOutput();
    ASSERT_NE(photoOutput2, nullptr);

    intResult = session_->AddOutput(photoOutput2);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = session_->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);
    intResult = ((sptr<PhotoOutput> &)photoOutput1)->Capture();
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    intResult = ((sptr<PhotoOutput> &)photoOutput2)->Capture();
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    ((sptr<PreviewOutput> &)previewOutput)->Stop();
    session_->Stop();

    ((sptr<PhotoOutput> &)photoOutput1)->Release();
    ((sptr<PhotoOutput> &)photoOutput2)->Release();
}

/*
 * Feature: Framework
 * Function: Test capture session with multiple preview outputs
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session with multiple preview ouputs
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_025, TestSize.Level0)
{
    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput1 = CreatePreviewOutput();
    ASSERT_NE(previewOutput1, nullptr);

    intResult = session_->AddOutput(previewOutput1);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput2 = CreatePreviewOutput();
    ASSERT_NE(previewOutput2, nullptr);

    intResult = session_->AddOutput(previewOutput2);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);
    intResult = ((sptr<PreviewOutput> &)previewOutput1)->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);
    intResult = ((sptr<PreviewOutput> &)previewOutput2)->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    ((sptr<PhotoOutput> &)previewOutput1)->Release();
    ((sptr<PhotoOutput> &)previewOutput2)->Release();
}

/*
 * Feature: Framework
 * Function: Test capture session with multiple video outputs
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session with multiple video ouputs
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_026, TestSize.Level0)
{
    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = session_->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> videoOutput1 = CreateVideoOutput();
    ASSERT_NE(videoOutput1, nullptr);

    intResult = session_->AddOutput(videoOutput1);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> videoOutput2 = CreateVideoOutput();
    ASSERT_NE(videoOutput2, nullptr);

    intResult = session_->AddOutput(videoOutput2);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->Start();
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_START);
    intResult = ((sptr<VideoOutput> &)videoOutput1)->Start();
    EXPECT_EQ(intResult, 0);

    intResult = ((sptr<VideoOutput> &)videoOutput2)->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    intResult = ((sptr<VideoOutput> &)videoOutput1)->Stop();
    EXPECT_EQ(intResult, 0);

    intResult = ((sptr<VideoOutput> &)videoOutput2)->Stop();
    EXPECT_EQ(intResult, 0);

    TestUtils::SaveVideoFile(nullptr, 0, VideoSaveMode::CLOSE, g_videoFd);

    ((sptr<PreviewOutput> &)previewOutput)->Stop();
    session_->Stop();

    ((sptr<PhotoOutput> &)videoOutput1)->Release();
    ((sptr<PhotoOutput> &)videoOutput2)->Release();
}

/*
 * Feature: Framework
 * Function: Test capture session start and stop preview multiple times
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session start and stop preview multiple times
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_027, TestSize.Level0)
{
    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = session_->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);
    intResult = ((sptr<PreviewOutput> &)previewOutput)->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    ((sptr<PreviewOutput> &)previewOutput)->Stop();

    sleep(WAIT_TIME_AFTER_START);

    sleep(WAIT_TIME_AFTER_START);
    intResult = ((sptr<PreviewOutput> &)previewOutput)->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    ((sptr<PreviewOutput> &)previewOutput)->Stop();
}

/*
 * Feature: Framework
 * Function: Test capture session start and stop video multiple times
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session start and stop video multiple times
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_028, TestSize.Level0)
{
    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = session_->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);

    intResult = session_->AddOutput(videoOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    sleep(WAIT_TIME_AFTER_START);

    intResult = ((sptr<VideoOutput> &)videoOutput)->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    intResult = ((sptr<VideoOutput> &)videoOutput)->Stop();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    intResult = ((sptr<VideoOutput> &)videoOutput)->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    intResult = ((sptr<VideoOutput> &)videoOutput)->Stop();
    EXPECT_EQ(intResult, 0);

    TestUtils::SaveVideoFile(nullptr, 0, VideoSaveMode::CLOSE, g_videoFd);

    sleep(WAIT_TIME_BEFORE_STOP);

    ((sptr<PreviewOutput> &)previewOutput)->Stop();
    session_->Stop();
}

/*
 * Feature: Framework
 * Function: Test remove video output and commit when preview + video outputs were committed
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test remove video output and commit when preview + video outputs were committed
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_029, TestSize.Level0)
{
    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = session_->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);

    intResult = session_->AddOutput(videoOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->RemoveOutput(videoOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);
    session_->Stop();
}

/*
 * Feature: Framework
 * Function: Test remove video output, add photo output and commit when preview + video outputs were committed
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test remove video output, add photo output and commit when preview + video outputs were committed
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_030, TestSize.Level0)
{
    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = session_->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);

    intResult = session_->AddOutput(videoOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);

    intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->RemoveOutput(videoOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddOutput(photoOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);
    intResult = ((sptr<PhotoOutput> &)photoOutput)->Capture();
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    session_->Stop();
}

/*
 * Feature: Framework
 * Function: Test remove photo output and commit when preview + photo outputs were committed
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test remove photo output and commit when preview + photo outputs were committed
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_031, TestSize.Level0)
{
    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = session_->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);

    intResult = session_->AddOutput(photoOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->RemoveOutput(photoOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    session_->Stop();
}

/*
 * Feature: Framework
 * Function: Test remove photo output, add video output and commit when preview + photo outputs were committed
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test remove photo output, add video output and commit when preview + photo outputs were committed
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_032, TestSize.Level0)
{
    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = session_->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);

    intResult = session_->AddOutput(photoOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);

    intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->RemoveOutput(photoOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddOutput(videoOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    intResult = ((sptr<VideoOutput> &)videoOutput)->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    intResult = ((sptr<VideoOutput> &)videoOutput)->Stop();
    EXPECT_EQ(intResult, 0);

    TestUtils::SaveVideoFile(nullptr, 0, VideoSaveMode::CLOSE, g_videoFd);

    sleep(WAIT_TIME_BEFORE_STOP);

    session_->Stop();
}

/*
 * Feature: Framework
 * Function: Test capture session remove output with null
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session remove output with null
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_033, TestSize.Level0)
{
    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> output = nullptr;
    intResult = session_->RemoveOutput(output);
    EXPECT_NE(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test capture session remove input with null
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session remove input with null
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_034, TestSize.Level0)
{
    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    sptr<CaptureInput> input = nullptr;
    intResult = session_->RemoveInput(input);
    EXPECT_NE(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test Capture with location setting [lat:1 ,long:1 ,alt:1]
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Capture with location setting
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_035, TestSize.Level0)
{
    std::shared_ptr<PhotoCaptureSetting> photoSetting = std::make_shared<PhotoCaptureSetting>();
    std::unique_ptr<Location> location = std::make_unique<Location>();
    location->latitude = 1;
    location->longitude = 1;
    location->altitude = 1;

    photoSetting->SetLocation(location);

    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);

    intResult = session_->AddOutput(photoOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = session_->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);
    intResult = ((sptr<PhotoOutput> &)photoOutput)->Capture(photoSetting);
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    session_->Stop();
}

/*
 * Feature: Framework
 * Function: Test Capture with location setting [lat:0.0 ,long:0.0 ,alt:0.0]
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Capture with location setting
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_036, TestSize.Level0)
{
    std::shared_ptr<PhotoCaptureSetting> photoSetting = std::make_shared<PhotoCaptureSetting>();
    std::unique_ptr<Location> location = std::make_unique<Location>();
    location->latitude = 0.0;
    location->longitude = 0.0;
    location->altitude = 0.0;

    photoSetting->SetLocation(location);

    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);

    intResult = session_->AddOutput(photoOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = session_->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);
    intResult = ((sptr<PhotoOutput> &)photoOutput)->Capture(photoSetting);
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    session_->Stop();
}

/*
 * Feature: Framework
 * Function: Test Capture with location setting [lat:-1 ,long:-1 ,alt:-1]
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Capture with location setting
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_037, TestSize.Level0)
{
    std::shared_ptr<PhotoCaptureSetting> photoSetting = std::make_shared<PhotoCaptureSetting>();
    std::unique_ptr<Location> location = std::make_unique<Location>();
    location->latitude = -1;
    location->longitude = -1;
    location->altitude = -1;

    photoSetting->SetLocation(location);

    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);

    intResult = session_->AddOutput(photoOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = session_->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);
    intResult = ((sptr<PhotoOutput> &)photoOutput)->Capture(photoSetting);
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    session_->Stop();
}

/*
 * Feature: Framework
 * Function: Test snapshot
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test snapshot
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_038, TestSize.Level0)
{
    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);

    intResult = session_->AddOutput(photoOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = session_->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);

    intResult = session_->AddOutput(videoOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    intResult = ((sptr<VideoOutput> &)videoOutput)->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);
    intResult = ((sptr<PhotoOutput> &)photoOutput)->Capture();
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    intResult = ((sptr<VideoOutput> &)videoOutput)->Stop();
    EXPECT_EQ(intResult, 0);

    TestUtils::SaveVideoFile(nullptr, 0, VideoSaveMode::CLOSE, g_videoFd);

    sleep(WAIT_TIME_BEFORE_STOP);

    session_->Stop();
}

/*
 * Feature: Framework
 * Function: Test snapshot with location setting
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test snapshot with location setting
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_039, TestSize.Level0)
{
    std::shared_ptr<PhotoCaptureSetting> photoSetting = std::make_shared<PhotoCaptureSetting>();
    std::unique_ptr<Location> location = std::make_unique<Location>();
    location->latitude = 12.972442;
    location->longitude = 77.580643;
    location->altitude = 0;

    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);

    intResult = session_->AddOutput(photoOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = session_->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);

    intResult = session_->AddOutput(videoOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    intResult = ((sptr<VideoOutput> &)videoOutput)->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);
    intResult = ((sptr<PhotoOutput> &)photoOutput)->Capture(photoSetting);
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    intResult = ((sptr<VideoOutput> &)videoOutput)->Stop();
    EXPECT_EQ(intResult, 0);

    TestUtils::SaveVideoFile(nullptr, 0, VideoSaveMode::CLOSE, g_videoFd);

    sleep(WAIT_TIME_BEFORE_STOP);

    session_->Stop();
}

/*
 * Feature: Framework
 * Function: Test snapshot with mirror setting
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test snapshot with mirror setting
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_040, TestSize.Level0)
{
    std::shared_ptr<PhotoCaptureSetting> photoSetting = std::make_shared<PhotoCaptureSetting>();
    photoSetting->SetMirror(true);

    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[1]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->Open();

    intResult = session_->AddInput(input);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);

    intResult = session_->AddOutput(photoOutput);
    EXPECT_EQ(intResult, 0);

    if (!(((sptr<PhotoOutput> &)photoOutput)->IsMirrorSupported())) {
        return;
    }

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = session_->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);

    intResult = session_->AddOutput(videoOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    intResult = ((sptr<VideoOutput> &)videoOutput)->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);
    intResult = ((sptr<PhotoOutput> &)photoOutput)->Capture(photoSetting);
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    intResult = ((sptr<VideoOutput> &)videoOutput)->Stop();
    EXPECT_EQ(intResult, 0);

    TestUtils::SaveVideoFile(nullptr, 0, VideoSaveMode::CLOSE, g_videoFd);

    sleep(WAIT_TIME_BEFORE_STOP);

    session_->Stop();
}

/*
 * Feature: Framework
 * Function: Test capture session with Video Stabilization Mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session with Video Stabilization Mode
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_042, TestSize.Level0)
{
    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = session_->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);

    intResult = session_->AddOutput(videoOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    std::vector<VideoStabilizationMode> stabilizationmodes = session_->GetSupportedStabilizationMode();
    ASSERT_EQ(stabilizationmodes.empty(), false);

    VideoStabilizationMode stabilizationMode = stabilizationmodes.back();
    if (session_->IsVideoStabilizationModeSupported(stabilizationMode)) {
        session_->SetVideoStabilizationMode(stabilizationMode);
        EXPECT_EQ(session_->GetActiveVideoStabilizationMode(), stabilizationMode);
    }

    intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    intResult = ((sptr<VideoOutput> &)videoOutput)->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    intResult = ((sptr<VideoOutput> &)videoOutput)->Stop();
    EXPECT_EQ(intResult, 0);

    TestUtils::SaveVideoFile(nullptr, 0, VideoSaveMode::CLOSE, g_videoFd);

    sleep(WAIT_TIME_BEFORE_STOP);
    session_->Stop();
}

/*
 * Feature: Framework
 * Function: Test Preview + Metadata
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Preview + Metadata
 * @tc.require: SR000GVK5P SR000GVO5O
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_043, TestSize.Level0)
{
    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = session_->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> metadatOutput = manager_->CreateMetadataOutput();
    ASSERT_NE(metadatOutput, nullptr);

    intResult = session_->AddOutput(metadatOutput);
    EXPECT_EQ(intResult, 0);

    sptr<MetadataOutput> metaOutput = (sptr<MetadataOutput> &)metadatOutput;
    std::vector<MetadataObjectType> metadataObjectTypes = metaOutput->GetSupportedMetadataObjectTypes();
    ASSERT_NE(metadataObjectTypes.size(), 0U);

    metaOutput->SetCapturingMetadataObjectTypes(std::vector<MetadataObjectType> {MetadataObjectType::FACE});

    std::shared_ptr<MetadataObjectCallback> metadataObjectCallback = std::make_shared<AppMetadataCallback>();
    metaOutput->SetCallback(metadataObjectCallback);
    std::shared_ptr<MetadataStateCallback> metadataStateCallback = std::make_shared<AppMetadataCallback>();
    metaOutput->SetCallback(metadataStateCallback);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    intResult = metaOutput->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    intResult = metaOutput->Stop();
    EXPECT_EQ(intResult, 0);

    session_->Stop();
    metaOutput->Release();
}

/*
 * Feature: Framework
 * Function: Test camera preempted.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test camera preempted.
 * @tc.require: SR000GVTU0
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_044, TestSize.Level0)
{
    std::shared_ptr<AppCallback> callback = std::make_shared<AppCallback>();
    sptr<CameraInput> camInput_2 = (sptr<CameraInput> &)input_;
    camInput_2->Open();

    camInput_2->SetErrorCallback(callback);

    sptr<CaptureSession> session_2 = manager_->CreateCaptureSession();
    ASSERT_NE(session_2, nullptr);

    int32_t intResult = session_2->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_2->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput_2 = CreatePreviewOutput();
    ASSERT_NE(previewOutput_2, nullptr);

    intResult = session_2->AddOutput(previewOutput_2);
    EXPECT_EQ(intResult, 0);

    intResult = session_2->CommitConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_2->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);
    camInput_2->Close();

    sptr<CaptureInput> input_3 = manager_->CreateCameraInput(cameras_[1]);
    ASSERT_NE(input_3, nullptr);

    sptr<CameraInput> camInput_3 = (sptr<CameraInput> &)input_3;
    camInput_3->Open();

    sptr<CaptureSession> session_3 = manager_->CreateCaptureSession();
    ASSERT_NE(session_3, nullptr);

    intResult = session_3->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_3->AddInput(input_3);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput_3 = CreatePreviewOutput();
    ASSERT_NE(previewOutput_3, nullptr);

    intResult = session_3->AddOutput(previewOutput_3);
    EXPECT_EQ(intResult, 0);

    intResult = session_3->CommitConfig();
    EXPECT_EQ(intResult, 0);

    session_3->Stop();
}
} // CameraStandard
} // OHOS
