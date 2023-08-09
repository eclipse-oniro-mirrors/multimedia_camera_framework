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
#include "camera_error_code.h"
#include "camera_log.h"
#include "surface.h"
#include "test_common.h"

#include "parameter.h"
#include "ipc_skeleton.h"
#include "access_token.h"
#include "hap_token_info.h"
#include "accesstoken_kit.h"
#include "token_setproc.h"
#include "camera_util.h"
#include "nativetoken_kit.h"

#include "iservice_registry.h"
#include "system_ability_definition.h"

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
    const int32_t CAMERA_NUMBER = 2;

    bool g_camInputOnError = false;
    bool g_sessionclosed = false;
    std::shared_ptr<Camera::CameraMetadata> g_metaResult = nullptr;
    int32_t g_videoFd = -1;
    int32_t g_previewFd = -1;
    std::bitset<static_cast<int>(CAM_PHOTO_EVENTS::CAM_PHOTO_MAX_EVENT)> g_photoEvents;
    std::bitset<static_cast<unsigned int>(CAM_PREVIEW_EVENTS::CAM_PREVIEW_MAX_EVENT)> g_previewEvents;
    std::bitset<static_cast<unsigned int>(CAM_VIDEO_EVENTS::CAM_VIDEO_MAX_EVENT)> g_videoEvents;
    std::unordered_map<std::string, int> g_camStatusMap;
    std::unordered_map<std::string, bool> g_camFlashMap;


    class AppCallback : public CameraManagerCallback, public ErrorCallback, public PhotoStateCallback,
                        public PreviewStateCallback, public ResultCallback {
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

        void OnResult(const uint64_t timestamp, const std::shared_ptr<Camera::CameraMetadata> &result) const override
        {
            MEDIA_INFO_LOG("CameraDeviceServiceCallback::OnResult() is called!");

            if (result != nullptr) {
                g_metaResult = result;
                common_metadata_header_t* data = result->get();
                std::vector<int32_t>  fpsRange;
                camera_metadata_item_t entry;
                int ret = OHOS::Camera::FindCameraMetadataItem(data, OHOS_ABILITY_FPS_RANGES, &entry);
                MEDIA_INFO_LOG("CameraDeviceServiceCallback::FindCameraMetadataItem() %{public}d", ret);
                if (ret != 0) {
                    MEDIA_INFO_LOG("demo test: get OHOS_ABILITY_FPS_RANGES error");
                }
                uint32_t count = entry.count;
                MEDIA_INFO_LOG("demo test: fpsRange count  %{public}d",  count);
                for (uint32_t i = 0 ; i < count; i++) {
                    fpsRange.push_back(*(entry.data.i32 + i));
                }
                for (auto it = fpsRange.begin(); it != fpsRange.end(); it++) {
                    MEDIA_INFO_LOG("demo test: fpsRange %{public}d ", *it);
                }
            }
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

    class AppSessionCallback : public SessionCallback {
    public:
        void OnError(int32_t errorCode)
        {
            MEDIA_DEBUG_LOG("AppMetadataCallback::OnError %{public}d", errorCode);
            return;
        }
    };
} // namespace

sptr<CaptureOutput> CameraFrameworkModuleTest::CreatePhotoOutput(int32_t width, int32_t height)
{
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    CameraFormat photoFormat = photoFormat_;
    Size photoSize;
    photoSize.width = width;
    photoSize.height = height;
    Profile photoProfile = Profile(photoFormat, photoSize);
    sptr<CaptureOutput> photoOutput = nullptr;
    sptr<IBufferProducer> surfaceProducer = surface->GetProducer();
    manager_->CreatePhotoOutput(surfaceProducer);
    photoOutput = manager_->CreatePhotoOutput(photoProfile, surfaceProducer);
    return photoOutput;
}

sptr<CaptureOutput> CameraFrameworkModuleTest::CreatePhotoOutput()
{
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoWidth_, photoHeight_);
    return photoOutput;
}

sptr<CaptureOutput> CameraFrameworkModuleTest::CreatePreviewOutput(int32_t width, int32_t height)
{
    sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
    sptr<SurfaceListener> listener = new SurfaceListener("Preview", SurfaceType::PREVIEW, g_previewFd, previewSurface);
    previewSurface->RegisterConsumerListener((sptr<IBufferConsumerListener> &)listener);
    Size previewSize;
    previewSize.width = previewProfiles[0].GetSize().width;
    previewSize.height = previewProfiles[0].GetSize().height;
    previewSurface->SetUserData(CameraManager::surfaceFormat, std::to_string(previewProfiles[0].GetCameraFormat()));
    previewSurface->SetDefaultWidthAndHeight(previewSize.width, previewSize.height);

    sptr<IBufferProducer> bp = previewSurface->GetProducer();
    sptr<Surface> pSurface = Surface::CreateSurfaceAsProducer(bp);

    sptr<CaptureOutput> previewOutput = nullptr;
    previewOutput = manager_->CreatePreviewOutput(previewProfiles[0], pSurface);
    return previewOutput;
}

sptr<CaptureOutput> CameraFrameworkModuleTest::CreatePreviewOutput()
{
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewWidth_, previewHeight_);
    return previewOutput;
}

sptr<CaptureOutput> CameraFrameworkModuleTest::CreateVideoOutput(int32_t width, int32_t height)
{
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<SurfaceListener> videoSurfaceListener =
        new(std::nothrow) SurfaceListener("Video", SurfaceType::VIDEO, g_videoFd, surface);
    surface->RegisterConsumerListener((sptr<IBufferConsumerListener> &)videoSurfaceListener);
    if (videoSurfaceListener == nullptr) {
        MEDIA_ERR_LOG("Failed to create new SurfaceListener");
        return nullptr;
    }
    sptr<IBufferProducer> videoProducer = surface->GetProducer();
    sptr<Surface> videoSurface = Surface::CreateSurfaceAsProducer(videoProducer);
    VideoProfile videoProfile = videoProfiles[0];
    sptr<CaptureOutput> videoOutput = nullptr;
    videoOutput = manager_->CreateVideoOutput(videoProfile, videoSurface);
    return videoOutput;
}

sptr<CaptureOutput> CameraFrameworkModuleTest::CreateVideoOutput()
{
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoWidth_, videoHeight_);
    return videoOutput;
}

sptr<CaptureOutput> CameraFrameworkModuleTest::CreatePhotoOutput(Profile profile)
{
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    Size photoSize;
    photoSize.width = profile.GetSize().width;
    photoSize.height = profile.GetSize().height;
    sptr<CaptureOutput> photoOutput = nullptr;
    sptr<IBufferProducer> surfaceProducer = surface->GetProducer();
    photoOutput = manager_->CreatePhotoOutput(profile, surfaceProducer);
    return photoOutput;
}

void CameraFrameworkModuleTest::GetSupportedOutputCapability()
{
    sptr<CameraManager> camManagerObj = CameraManager::GetInstance();
    std::vector<sptr<CameraDevice>> cameraObjList = camManagerObj->GetSupportedCameras();
    ASSERT_GE(cameraObjList.size(), CAMERA_NUMBER);
    sptr<CameraOutputCapability> outputcapability =  camManagerObj->GetSupportedOutputCapability(cameraObjList[1]);
    previewProfiles = outputcapability->GetPreviewProfiles();
    ASSERT_TRUE(!previewProfiles.empty());
    photoProfiles = outputcapability->GetPhotoProfiles();
    ASSERT_TRUE(!photoProfiles.empty());
    videoProfiles = outputcapability->GetVideoProfiles();
    ASSERT_TRUE(!videoProfiles.empty());
    return;
}

void CameraFrameworkModuleTest::ReleaseInput()
{
    if (input_) {
        sptr<CameraInput> camInput = (sptr<CameraInput> &)input_;
        camInput->Close();
        input_->Release();
    }
    return;
}

void CameraFrameworkModuleTest::SetCameraParameters(sptr<CaptureSession> &session, bool video)
{
    session->LockForControl();

    std::vector<float> zoomRatioRange = session->GetZoomRatioRange();
    if (!zoomRatioRange.empty()) {
        session->SetZoomRatio(zoomRatioRange[0]);
    }

    // GetExposureBiasRange
    std::vector<float> exposureBiasRange = session->GetExposureBiasRange();
    if (!exposureBiasRange.empty()) {
        session->SetExposureBias(exposureBiasRange[0]);
    }

    // Get/Set Exposurepoint
    Point exposurePoint = {1, 2};
    session->SetMeteringPoint(exposurePoint);

    // GetFocalLength
    float focalLength = session->GetFocalLength();
    EXPECT_NE(focalLength, 0);

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
    EXPECT_EQ(exposurePointGet.x, exposurePoint.x > 1 ? 1 : exposurePoint.x);
    EXPECT_EQ(exposurePointGet.y, exposurePoint.y > 1 ? 1 : exposurePoint.y);

    Point focusPointGet = session->GetFocusPoint();
    EXPECT_EQ(focusPointGet.x, focusPoint.x > 1 ? 1 : focusPoint.x);
    EXPECT_EQ(focusPointGet.y, focusPoint.y > 1 ? 1 : focusPoint.y);

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

    SetCameraParameters(session_, video);

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

bool CameraFrameworkModuleTest::IsSupportNow()
{
    const char *deviveTypeString = GetDeviceType();
    std::string deviveType = std::string(deviveTypeString);
    if (deviveType.compare("default") == 0 ||
        (cameras_[0] != nullptr && cameras_[0]->GetConnectionType() == CAMERA_CONNECTION_USB_PLUGIN)) {
        return false;
    }
    return true;
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
    g_previewFd = -1;
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
    previewProfiles = outputcapability->GetPreviewProfiles();
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
    photoProfiles =  outputcapability->GetPhotoProfiles();
        for (auto i : photoProfiles) {
            photoFormats_.push_back(i.GetCameraFormat());
            photoSizes_.push_back(i.GetSize());
        }
    ASSERT_TRUE(!photoFormats_.empty());
    ASSERT_TRUE(!photoSizes_.empty());
    photoFormat_ = photoFormats_[0];
    videoProfiles = outputcapability->GetVideoProfiles();

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
 * Function: Test get distributed camera hostname
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get distributed camera hostname
 */
HWTEST_F(CameraFrameworkModuleTest, Camera_fwInfoManager_moduletest_001, TestSize.Level0)
{
    std::string hostName;
    for (int i = 0; i < cameras_.size(); i++) {
        hostName = cameras_[i]->GetHostName();
        std::string cameraId = cameras_[i]->GetID();
        std::string networkId = cameras_[i]->GetNetWorkId();
        if (networkId != "") {
            ASSERT_NE(hostName, "");
        } else {
            ASSERT_EQ(hostName, "");
        }
    }
}
/*
 * Feature: Framework
 * Function: Test get DeviceType
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get DeviceType
 */
HWTEST_F(CameraFrameworkModuleTest, Camera_fwInfoManager_moduletest_002, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = manager_->GetSupportedCameras();
    auto judgeDeviceType = [&cameras] () -> bool {
        bool isOk = false;
        for (int i = 0; i < cameras.size(); i++) {
            uint16_t deviceType = cameras[i]->GetDeviceType();
            switch (deviceType) {
                case HostDeviceType::UNKNOWN:
                case HostDeviceType::PHONE:
                case HostDeviceType::TABLET:
                    isOk = true;
                    break;
                default:
                    isOk = false;
                    break;
            }
            if (isOk == false) {
                break;
            }
        }
        return isOk;
    };
    ASSERT_NE(judgeDeviceType(), false);
}
/*
 * Feature: Framework
 * Function: Test Result Callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Result Callback
 */

HWTEST_F(CameraFrameworkModuleTest, Camera_ResultCallback_moduletest, TestSize.Level0)
{
    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    // Register error callback
    std::shared_ptr<AppCallback> callback = std::make_shared<AppCallback>();
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input_;
    camInput->SetResultCallback(callback);
    EXPECT_EQ(g_camInputOnError, false);

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
    EXPECT_NE(g_metaResult, nullptr);

    intResult = ((sptr<VideoOutput> &)videoOutput)->Stop();
    EXPECT_EQ(intResult, 0);

    TestUtils::SaveVideoFile(nullptr, 0, VideoSaveMode::CLOSE, g_videoFd);

    sleep(WAIT_TIME_BEFORE_STOP);
    ((sptr<PreviewOutput> &)previewOutput)->Stop();
    session_->Stop();
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
    if (!IsSupportNow()) {
        return;
    }
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
    if (!IsSupportNow()) {
        return;
    }
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
    if (!IsSupportNow()) {
        return;
    }
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
    if (!IsSupportNow()) {
        return;
    }
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
    ReleaseInput();
    std::shared_ptr<PhotoCaptureSetting> photoSetting = std::make_shared<PhotoCaptureSetting>();
    photoSetting->SetMirror(true);

    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    if (cameras_.size() < 2) {
        return;
    }

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[1]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->Open();

    intResult = session_->AddInput(input);
    EXPECT_EQ(intResult, 0);

    GetSupportedOutputCapability();

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoProfiles[0]);
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
    if (stabilizationmodes.empty()) {
        return;
    }
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
    if (metadataObjectTypes.size() == 0) {
        return;
    }

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
    if (!IsSupportNow()) {
        return;
    }
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

    if (cameras_.size() < 2) {
        return;
    }

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

/*
 * Feature: Framework
 * Function: Test anomalous branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session video stabilization mode with anomalous branch.
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_045, TestSize.Level0)
{
    sptr<CaptureSession> camSession = manager_->CreateCaptureSession();
    ASSERT_NE(camSession, nullptr);

    VideoStabilizationMode stabilizationMode = camSession->GetActiveVideoStabilizationMode();
    EXPECT_EQ(stabilizationMode, OFF);

    int32_t actVideoStaMode = camSession->SetVideoStabilizationMode(stabilizationMode);
    EXPECT_EQ(actVideoStaMode, 7400103);

    actVideoStaMode = camSession->GetActiveVideoStabilizationMode(stabilizationMode);
    EXPECT_EQ(actVideoStaMode, 7400103);

    bool isSupported = true;

    int32_t videoStaModeSupported = camSession->IsVideoStabilizationModeSupported(stabilizationMode, isSupported);
    EXPECT_EQ(videoStaModeSupported, 7400103);

    std::vector<VideoStabilizationMode> videoStabilizationMode = camSession->GetSupportedStabilizationMode();
    EXPECT_EQ(videoStabilizationMode.empty(), true);

    int32_t supportedVideoStaMode = camSession->GetSupportedStabilizationMode(videoStabilizationMode);
    EXPECT_EQ(supportedVideoStaMode, 7400103);

    int32_t intResult = camSession->BeginConfig();
    EXPECT_EQ(intResult, 0);

    sptr<CaptureInput> input = (sptr<CaptureInput> &)input_;
    ASSERT_NE(input, nullptr);

    intResult = camSession->AddInput(input);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = camSession->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);

    intResult = camSession->AddOutput(videoOutput);
    EXPECT_EQ(intResult, 0);

    intResult = camSession->CommitConfig();
    EXPECT_EQ(intResult, 0);

    videoStaModeSupported = camSession->IsVideoStabilizationModeSupported(stabilizationMode, isSupported);
    EXPECT_EQ(videoStaModeSupported, 0);

    actVideoStaMode = camSession->GetActiveVideoStabilizationMode(stabilizationMode);
    EXPECT_EQ(actVideoStaMode, 0);

    supportedVideoStaMode = camSession->GetSupportedStabilizationMode(videoStabilizationMode);
    EXPECT_EQ(supportedVideoStaMode, 0);

    ReleaseInput();

    stabilizationMode = camSession->GetActiveVideoStabilizationMode();
    EXPECT_EQ(stabilizationMode, OFF);

    actVideoStaMode = camSession->GetActiveVideoStabilizationMode(stabilizationMode);
    EXPECT_EQ(actVideoStaMode, 0);

    videoStabilizationMode = camSession->GetSupportedStabilizationMode();
    EXPECT_EQ(videoStabilizationMode.empty(), true);

    supportedVideoStaMode = camSession->GetSupportedStabilizationMode(videoStabilizationMode);
    EXPECT_EQ(supportedVideoStaMode, 0);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session exposure mode with anomalous branch.
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_046, TestSize.Level0)
{
    sptr<CaptureSession> camSession = manager_->CreateCaptureSession();
    ASSERT_NE(camSession, nullptr);

    ExposureMode exposureMode = camSession->GetExposureMode();
    EXPECT_EQ(exposureMode, EXPOSURE_MODE_UNSUPPORTED);

    int32_t getExposureMode = camSession->GetExposureMode(exposureMode);
    EXPECT_EQ(getExposureMode, 7400103);

    int32_t setExposureMode = camSession->SetExposureMode(exposureMode);
    EXPECT_EQ(setExposureMode, 7400103);

    bool isExposureModeSupported = camSession->IsExposureModeSupported(exposureMode);
    EXPECT_EQ(isExposureModeSupported, false);

    bool isSupported = true;

    int32_t exposureModeSupported = camSession->IsExposureModeSupported(exposureMode, isSupported);
    EXPECT_EQ(exposureModeSupported, 7400103);

    std::vector<ExposureMode> getSupportedExpModes_1 = camSession->GetSupportedExposureModes();
    EXPECT_EQ(getSupportedExpModes_1.empty(), true);

    int32_t getSupportedExpModes_2 = camSession->GetSupportedExposureModes(getSupportedExpModes_1);
    EXPECT_EQ(getSupportedExpModes_2, 7400103);

    int32_t intResult = camSession->BeginConfig();
    EXPECT_EQ(intResult, 0);

    sptr<CaptureInput> input = (sptr<CaptureInput> &)input_;
    ASSERT_NE(input, nullptr);

    intResult = camSession->AddInput(input);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = camSession->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    intResult = camSession->CommitConfig();
    EXPECT_EQ(intResult, 0);

    setExposureMode = camSession->SetExposureMode(exposureMode);
    EXPECT_EQ(setExposureMode, 0);

    getExposureMode = camSession->GetExposureMode(exposureMode);
    EXPECT_EQ(getExposureMode, 0);

    exposureModeSupported = camSession->IsExposureModeSupported(exposureMode, isSupported);
    EXPECT_EQ(exposureModeSupported, 0);

    getSupportedExpModes_1 = camSession->GetSupportedExposureModes();
    EXPECT_EQ(getSupportedExpModes_1.empty(), false);

    getSupportedExpModes_2 = camSession->GetSupportedExposureModes(getSupportedExpModes_1);
    EXPECT_EQ(getSupportedExpModes_2, 0);

    ReleaseInput();

    getSupportedExpModes_1 = camSession->GetSupportedExposureModes();
    EXPECT_EQ(getSupportedExpModes_1.empty(), true);

    getSupportedExpModes_2 = camSession->GetSupportedExposureModes(getSupportedExpModes_1);
    EXPECT_EQ(getSupportedExpModes_2, 0);

    exposureMode = camSession->GetExposureMode();
    EXPECT_EQ(exposureMode, EXPOSURE_MODE_UNSUPPORTED);

    getExposureMode = camSession->GetExposureMode(exposureMode);
    EXPECT_EQ(getExposureMode, 0);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session metering point with anomalous branch.
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_047, TestSize.Level0)
{
    sptr<CaptureSession> camSession = manager_->CreateCaptureSession();
    ASSERT_NE(camSession, nullptr);

    Point exposurePointGet = camSession->GetMeteringPoint();
    EXPECT_EQ(exposurePointGet.x, 0);
    EXPECT_EQ(exposurePointGet.y, 0);

    int32_t setMeteringPoint = camSession->SetMeteringPoint(exposurePointGet);
    EXPECT_EQ(setMeteringPoint, 7400103);

    int32_t getMeteringPoint = camSession->GetMeteringPoint(exposurePointGet);
    EXPECT_EQ(getMeteringPoint, 7400103);

    int32_t intResult = camSession->BeginConfig();
    EXPECT_EQ(intResult, 0);

    sptr<CaptureInput> input = (sptr<CaptureInput> &)input_;
    ASSERT_NE(input, nullptr);

    intResult = camSession->AddInput(input);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = camSession->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    intResult = camSession->CommitConfig();
    EXPECT_EQ(intResult, 0);

    setMeteringPoint = camSession->SetMeteringPoint(exposurePointGet);
    EXPECT_EQ(setMeteringPoint, 0);

    getMeteringPoint = camSession->GetMeteringPoint(exposurePointGet);
    EXPECT_EQ(getMeteringPoint, 0);

    ReleaseInput();

    exposurePointGet = camSession->GetMeteringPoint();
    EXPECT_EQ(exposurePointGet.x, 0);
    EXPECT_EQ(exposurePointGet.y, 0);

    getMeteringPoint = camSession->GetMeteringPoint(exposurePointGet);
    EXPECT_EQ(getMeteringPoint, 0);

    camSession->LockForControl();

    setMeteringPoint = camSession->SetMeteringPoint(exposurePointGet);
    EXPECT_EQ(setMeteringPoint, 0);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session exposure value and range with anomalous branch.
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_048, TestSize.Level0)
{
    sptr<CaptureSession> camSession = manager_->CreateCaptureSession();
    ASSERT_NE(camSession, nullptr);

    std::shared_ptr<Camera::CameraMetadata> metadata = cameras_[0]->GetMetadata();
    ASSERT_NE(metadata, nullptr);

    camSession->ProcessAutoExposureUpdates(metadata);

    float exposureValue = camSession->GetExposureValue();
    EXPECT_EQ(exposureValue, 0);

    int32_t exposureValueGet = camSession->GetExposureValue(exposureValue);
    EXPECT_EQ(exposureValueGet, 7400103);

    int32_t setExposureBias = camSession->SetExposureBias(exposureValue);
    EXPECT_EQ(setExposureBias, 7400103);

    std::vector<float> getExposureBiasRange = camSession->GetExposureBiasRange();
    EXPECT_EQ(getExposureBiasRange.empty(), true);

    int32_t exposureBiasRangeGet = camSession->GetExposureBiasRange(getExposureBiasRange);
    EXPECT_EQ(exposureBiasRangeGet, 7400103);

    int32_t intResult = camSession->BeginConfig();
    EXPECT_EQ(intResult, 0);

    sptr<CaptureInput> input = (sptr<CaptureInput> &)input_;
    ASSERT_NE(input, nullptr);

    intResult = camSession->AddInput(input);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = camSession->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    intResult = camSession->CommitConfig();
    EXPECT_EQ(intResult, 0);

    setExposureBias = camSession->SetExposureBias(exposureValue);
    EXPECT_EQ(setExposureBias, 0);

    exposureValueGet = camSession->GetExposureValue(exposureValue);
    EXPECT_EQ(exposureValueGet, 0);

    exposureBiasRangeGet = camSession->GetExposureBiasRange(getExposureBiasRange);
    EXPECT_EQ(exposureBiasRangeGet, 0);

    ReleaseInput();

    getExposureBiasRange = camSession->GetExposureBiasRange();
    EXPECT_EQ(getExposureBiasRange.empty(), true);

    exposureBiasRangeGet = camSession->GetExposureBiasRange(getExposureBiasRange);
    EXPECT_EQ(exposureBiasRangeGet, 0);

    exposureValue = camSession->GetExposureValue();
    EXPECT_EQ(exposureValue, 0);

    exposureValueGet = camSession->GetExposureValue(exposureValue);
    EXPECT_EQ(exposureValueGet, 0);

    camSession->LockForControl();

    setExposureBias = camSession->SetExposureBias(exposureValue);
    EXPECT_EQ(setExposureBias, 7400102);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session focus mode with anomalous branch.
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_049, TestSize.Level0)
{
    sptr<CaptureSession> camSession = manager_->CreateCaptureSession();
    ASSERT_NE(camSession, nullptr);

    FocusMode focusMode = camSession->GetFocusMode();
    EXPECT_EQ(focusMode, FOCUS_MODE_MANUAL);

    int32_t getFocusMode = camSession->GetFocusMode(focusMode);
    EXPECT_EQ(getFocusMode, 7400103);

    int32_t setFocusMode = camSession->SetFocusMode(focusMode);
    EXPECT_EQ(setFocusMode, 7400103);

    bool isFocusModeSupported = camSession->IsFocusModeSupported(focusMode);
    EXPECT_EQ(isFocusModeSupported, false);

    bool isSupported = true;

    int32_t focusModeSupported = camSession->IsFocusModeSupported(focusMode, isSupported);
    EXPECT_EQ(focusModeSupported, 7400103);

    std::vector<FocusMode> getSupportedFocusModes = camSession->GetSupportedFocusModes();
    EXPECT_EQ(getSupportedFocusModes.empty(), true);

    int32_t supportedFocusModesGet = camSession->GetSupportedFocusModes(getSupportedFocusModes);
    EXPECT_EQ(supportedFocusModesGet, 7400103);

    int32_t intResult = camSession->BeginConfig();
    EXPECT_EQ(intResult, 0);

    sptr<CaptureInput> input = (sptr<CaptureInput> &)input_;
    ASSERT_NE(input, nullptr);

    intResult = camSession->AddInput(input);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = camSession->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    intResult = camSession->CommitConfig();
    EXPECT_EQ(intResult, 0);

    setFocusMode = camSession->SetFocusMode(focusMode);
    EXPECT_EQ(setFocusMode, 0);

    getFocusMode = camSession->GetFocusMode(focusMode);
    EXPECT_EQ(getFocusMode, 0);

    focusModeSupported = camSession->IsFocusModeSupported(focusMode, isSupported);
    EXPECT_EQ(focusModeSupported, 0);

    getSupportedFocusModes = camSession->GetSupportedFocusModes();
    EXPECT_EQ(getSupportedFocusModes.empty(), false);

    supportedFocusModesGet = camSession->GetSupportedFocusModes(getSupportedFocusModes);
    EXPECT_EQ(supportedFocusModesGet, 0);

    ReleaseInput();

    getSupportedFocusModes = camSession->GetSupportedFocusModes();
    EXPECT_EQ(getSupportedFocusModes.empty(), true);

    supportedFocusModesGet = camSession->GetSupportedFocusModes(getSupportedFocusModes);
    EXPECT_EQ(supportedFocusModesGet, 0);

    focusMode = camSession->GetFocusMode();
    EXPECT_EQ(focusMode, FOCUS_MODE_MANUAL);

    getFocusMode = camSession->GetFocusMode(focusMode);
    EXPECT_EQ(getFocusMode, 0);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session focus point with anomalous branch.
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_050, TestSize.Level0)
{
    sptr<CaptureSession> camSession = manager_->CreateCaptureSession();
    ASSERT_NE(camSession, nullptr);

    Point focusPoint = camSession->GetFocusPoint();
    EXPECT_EQ(focusPoint.x, 0);
    EXPECT_EQ(focusPoint.y, 0);

    float focalLength = camSession->GetFocalLength();
    EXPECT_EQ(focalLength, 0);

    int32_t focalLengthGet = camSession->GetFocalLength(focalLength);
    EXPECT_EQ(focalLengthGet, 7400103);

    int32_t focusPointGet = camSession->GetFocusPoint(focusPoint);
    EXPECT_EQ(focusPointGet, 7400103);

    int32_t setFocusPoint = camSession->SetFocusPoint(focusPoint);
    EXPECT_EQ(setFocusPoint, 7400103);

    int32_t intResult = camSession->BeginConfig();
    EXPECT_EQ(intResult, 0);

    sptr<CaptureInput> input = (sptr<CaptureInput> &)input_;
    intResult = camSession->AddInput(input);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = camSession->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    intResult = camSession->CommitConfig();
    EXPECT_EQ(intResult, 0);

    setFocusPoint = camSession->SetFocusPoint(focusPoint);
    EXPECT_EQ(setFocusPoint, 0);

    camSession->LockForControl();

    Point point = {0, 0};
    setFocusPoint = camSession->SetFocusPoint(point);
    EXPECT_EQ(setFocusPoint, 0);

    point.x = CameraErrorCode::SESSION_NOT_CONFIG;
    setFocusPoint = camSession->SetFocusPoint(point);
    EXPECT_EQ(setFocusPoint, 0);

    focusPointGet = camSession->GetFocusPoint(focusPoint);
    EXPECT_EQ(focusPointGet, 0);

    focalLengthGet = camSession->GetFocalLength(focalLength);
    EXPECT_EQ(focalLengthGet, 0);

    ReleaseInput();

    focusPoint = camSession->GetFocusPoint();
    EXPECT_EQ(focusPoint.x, 0);
    EXPECT_EQ(focusPoint.y, 0);

    focusPointGet = camSession->GetFocusPoint(focusPoint);
    EXPECT_EQ(focusPointGet, 0);

    focalLength = camSession->GetFocalLength();
    EXPECT_EQ(focalLength, 0);

    focalLengthGet = camSession->GetFocalLength(focalLength);
    EXPECT_EQ(focalLengthGet, 0);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session flash mode with anomalous branch.
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_051, TestSize.Level0)
{
    sptr<CaptureSession> camSession = manager_->CreateCaptureSession();
    ASSERT_NE(camSession, nullptr);

    bool hasFlash = camSession->HasFlash();
    EXPECT_EQ(hasFlash, false);

    int32_t isFlash = camSession->HasFlash(hasFlash);
    EXPECT_EQ(isFlash, 7400103);

    FlashMode flashMode = camSession->GetFlashMode();
    EXPECT_EQ(flashMode, FLASH_MODE_CLOSE);

    int32_t flashModeGet = camSession->GetFlashMode(flashMode);
    EXPECT_EQ(flashModeGet, 7400103);

    int32_t setFlashMode = camSession->SetFlashMode(flashMode);
    EXPECT_EQ(setFlashMode, 7400103);

    bool isFlashModeSupported = camSession->IsFlashModeSupported(flashMode);
    EXPECT_EQ(isFlashModeSupported, false);

    bool isSupported = true;

    int32_t flashModeSupported = camSession->IsFlashModeSupported(flashMode, isSupported);
    EXPECT_EQ(setFlashMode, 7400103);

    std::vector<FlashMode> getSupportedFlashModes = camSession->GetSupportedFlashModes();
    EXPECT_EQ(getSupportedFlashModes.empty(), true);

    int32_t getSupportedFlashMode = camSession->GetSupportedFlashModes(getSupportedFlashModes);
    EXPECT_EQ(getSupportedFlashMode, 7400103);

    int32_t intResult = camSession->BeginConfig();
    EXPECT_EQ(intResult, 0);

    sptr<CaptureInput> input = (sptr<CaptureInput> &)input_;
    ASSERT_NE(input, nullptr);

    intResult = camSession->AddInput(input);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = camSession->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    intResult = camSession->CommitConfig();
    EXPECT_EQ(intResult, 0);

    isFlash = camSession->HasFlash(hasFlash);
    EXPECT_EQ(isFlash, 0);

    setFlashMode = camSession->SetFlashMode(flashMode);
    EXPECT_EQ(setFlashMode, 0);

    flashModeGet = camSession->GetFlashMode(flashMode);
    EXPECT_EQ(flashModeGet, 0);

    flashModeSupported = camSession->IsFlashModeSupported(flashMode, isSupported);
    EXPECT_EQ(setFlashMode, 0);

    getSupportedFlashModes = camSession->GetSupportedFlashModes();
    EXPECT_EQ(getSupportedFlashModes.empty(), false);

    getSupportedFlashMode = camSession->GetSupportedFlashModes(getSupportedFlashModes);
    EXPECT_EQ(getSupportedFlashMode, 0);

    camSession->LockForControl();
    setFlashMode = camSession->SetFlashMode(flashMode);
    EXPECT_EQ(setFlashMode, 0);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test flash mode with release input.
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_052, TestSize.Level0)
{
    sptr<CaptureSession> camSession = manager_->CreateCaptureSession();
    ASSERT_NE(camSession, nullptr);

    int32_t intResult = camSession->BeginConfig();
    EXPECT_EQ(intResult, 0);

    sptr<CaptureInput> input = (sptr<CaptureInput> &)input_;
    ASSERT_NE(input, nullptr);

    intResult = camSession->AddInput(input);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = camSession->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    intResult = camSession->CommitConfig();
    EXPECT_EQ(intResult, 0);

    ReleaseInput();

    std::vector<FlashMode> getSupportedFlashModes = camSession->GetSupportedFlashModes();
    EXPECT_EQ(getSupportedFlashModes.empty(), true);

    int32_t getSupportedFlashMode = camSession->GetSupportedFlashModes(getSupportedFlashModes);
    EXPECT_EQ(getSupportedFlashMode, 0);

    FlashMode flashMode = camSession->GetFlashMode();
    EXPECT_EQ(flashMode, FLASH_MODE_CLOSE);

    int32_t flashModeGet = camSession->GetFlashMode(flashMode);
    EXPECT_EQ(flashModeGet, 0);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session zoom ratio with anomalous branch.
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_053, TestSize.Level0)
{
    sptr<CaptureSession> camSession = manager_->CreateCaptureSession();
    ASSERT_NE(camSession, nullptr);

    float zoomRatio = camSession->GetZoomRatio();
    EXPECT_EQ(zoomRatio, 0);

    std::vector<float> zoomRatioRange = camSession->GetZoomRatioRange();
    EXPECT_EQ(zoomRatioRange.empty(), true);

    int32_t zoomRatioRangeGet = camSession->GetZoomRatioRange(zoomRatioRange);
    EXPECT_EQ(zoomRatioRangeGet, 7400103);

    int32_t zoomRatioGet = camSession->GetZoomRatio(zoomRatio);
    EXPECT_EQ(zoomRatioGet, 7400103);

    int32_t setZoomRatio = camSession->SetZoomRatio(zoomRatio);
    EXPECT_EQ(setZoomRatio, 7400103);

    int32_t intResult = camSession->BeginConfig();
    EXPECT_EQ(intResult, 0);

    sptr<CaptureInput> input = (sptr<CaptureInput> &)input_;
    ASSERT_NE(input, nullptr);

    intResult = camSession->AddInput(input);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = camSession->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    intResult = camSession->CommitConfig();
    EXPECT_EQ(intResult, 0);

    zoomRatioRange = camSession->GetZoomRatioRange();
    EXPECT_EQ(zoomRatioRange.empty(), false);

    zoomRatioRangeGet = camSession->GetZoomRatioRange(zoomRatioRange);
    EXPECT_EQ(zoomRatioRangeGet, 0);

    zoomRatioGet = camSession->GetZoomRatio(zoomRatio);
    EXPECT_EQ(zoomRatioGet, 0);

    setZoomRatio = camSession->SetZoomRatio(zoomRatio);
    EXPECT_EQ(setZoomRatio, 0);

    ReleaseInput();

    zoomRatioRange = camSession->GetZoomRatioRange();
    EXPECT_EQ(zoomRatioRange.empty(), true);

    zoomRatioRangeGet = camSession->GetZoomRatioRange(zoomRatioRange);
    EXPECT_EQ(zoomRatioRangeGet, 0);

    zoomRatio = camSession->GetZoomRatio();
    EXPECT_EQ(zoomRatio, 0);

    zoomRatioGet = camSession->GetZoomRatio(zoomRatio);
    EXPECT_EQ(zoomRatioGet, 0);

    camSession->LockForControl();

    setZoomRatio = camSession->SetZoomRatio(zoomRatio);
    EXPECT_EQ(setZoomRatio, 0);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session with set metadata Object type anomalous branch.
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_054, TestSize.Level0)
{
    sptr<CaptureSession> camSession = manager_->CreateCaptureSession();
    ASSERT_NE(camSession, nullptr);

    std::set<camera_face_detect_mode_t> metadataObjectTypes;
    camSession->SetCaptureMetadataObjectTypes(metadataObjectTypes);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataOutput with anomalous branch.
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_055, TestSize.Level0)
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

    sptr<MetadataObjectListener> metaObjListener = new(std::nothrow) MetadataObjectListener(metaOutput);
    ASSERT_NE(metaObjListener, nullptr);

    metaObjListener->OnBufferAvailable();

    std::vector<MetadataObjectType> metadataObjectTypes = metaOutput->GetSupportedMetadataObjectTypes();
    EXPECT_EQ(metadataObjectTypes.empty(), true);

    metaOutput->SetCapturingMetadataObjectTypes(metadataObjectTypes);
    metaOutput->SetCapturingMetadataObjectTypes(std::vector<MetadataObjectType> {MetadataObjectType::FACE});

    metadataObjectTypes = metaOutput->GetSupportedMetadataObjectTypes();

    std::shared_ptr<MetadataObjectCallback> metadataObjectCallback = std::make_shared<AppMetadataCallback>();
    metaOutput->SetCallback(metadataObjectCallback);
    std::shared_ptr<MetadataStateCallback> metadataStateCallback = std::make_shared<AppMetadataCallback>();
    metaOutput->SetCallback(metadataStateCallback);

    int32_t startResult = metaOutput->Start();
    EXPECT_EQ(startResult, 7400103);

    int32_t stopResult = metaOutput->Stop();
    EXPECT_EQ(stopResult, 7400201);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    intResult = metaOutput->Start();
    EXPECT_EQ(intResult, 0);

    metaObjListener->OnBufferAvailable();

    sleep(WAIT_TIME_AFTER_START);

    intResult = metaOutput->Stop();
    EXPECT_EQ(intResult, 0);

    intResult = metaOutput->Release();
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test capture session callback error with anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_056, TestSize.Level0)
{
    sptr<CaptureSession> camSession = manager_->CreateCaptureSession();
    ASSERT_NE(camSession, nullptr);

    sptr<CaptureSessionCallback> capSessionCallback = new(std::nothrow) CaptureSessionCallback();
    int32_t onError = capSessionCallback->OnError(CAMERA_DEVICE_PREEMPTED);
    EXPECT_EQ(onError, 0);

    capSessionCallback = new(std::nothrow) CaptureSessionCallback(camSession);
    onError = capSessionCallback->OnError(CAMERA_DEVICE_PREEMPTED);
    EXPECT_EQ(onError, 0);

    std::shared_ptr<SessionCallback> callback = nullptr;
    camSession->SetCallback(callback);

    callback = std::make_shared<AppSessionCallback>();
    camSession->SetCallback(callback);
    capSessionCallback = new(std::nothrow) CaptureSessionCallback(camSession);
    onError = capSessionCallback->OnError(CAMERA_DEVICE_PREEMPTED);
    EXPECT_EQ(onError, 0);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test remove input with anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_057, TestSize.Level0)
{
    sptr<CaptureSession> camSession = manager_->CreateCaptureSession();
    ASSERT_NE(camSession, nullptr);

    sptr<CaptureInput> input = nullptr;
    int32_t intResult = camSession->RemoveInput(input);
    EXPECT_EQ(intResult, 7400102);

    intResult = camSession->BeginConfig();
    EXPECT_EQ(intResult, 0);

    input = (sptr<CaptureInput> &)input_;
    ASSERT_NE(input, nullptr);

    intResult = camSession->RemoveInput(input);
    EXPECT_EQ(intResult, 7400201);

    intResult = camSession->AddInput(input);
    EXPECT_EQ(intResult, 0);

    intResult = camSession->RemoveInput(input);
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test remove output with anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_058, TestSize.Level0)
{
    sptr<CaptureSession> camSession = manager_->CreateCaptureSession();
    ASSERT_NE(camSession, nullptr);

    sptr<CaptureOutput> output = nullptr;
    int32_t intResult = camSession->RemoveOutput(output);
    EXPECT_EQ(intResult, 7400102);

    intResult = camSession->BeginConfig();
    EXPECT_EQ(intResult, 0);

    output = CreatePreviewOutput();
    ASSERT_NE(output, nullptr);

    intResult = camSession->RemoveOutput(output);
    EXPECT_EQ(intResult, 7400201);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test stop/release session and preview with anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_059, TestSize.Level0)
{
    sptr<CaptureSession> camSession = manager_->CreateCaptureSession();
    ASSERT_NE(camSession, nullptr);
    delete camSession;

    int32_t intResult = camSession->Stop();
    EXPECT_EQ(intResult, 7400201);

    intResult = camSession->Release();
    EXPECT_EQ(intResult, 7400201);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataOutput with anomalous branch.
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_060, TestSize.Level0)
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

    sptr<MetadataObjectListener> metaObjListener = new(std::nothrow) MetadataObjectListener(metaOutput);
    ASSERT_NE(metaObjListener, nullptr);

    metaObjListener->OnBufferAvailable();

    metaOutput->SetCapturingMetadataObjectTypes(std::vector<MetadataObjectType> {MetadataObjectType::FACE});

    std::vector<MetadataObjectType> metadataObjectTypes = metaOutput->GetSupportedMetadataObjectTypes();

    sptr<CaptureOutput> metadatOutput_2 = manager_->CreateMetadataOutput();
    ASSERT_NE(metadatOutput_2, nullptr);

    intResult = metaOutput->Release();
    EXPECT_EQ(intResult, 0);

    sptr<MetadataOutput> metaOutput_2 = (sptr<MetadataOutput> &)metadatOutput_2;

    delete metaOutput_2;

    metadataObjectTypes = metaOutput_2->GetSupportedMetadataObjectTypes();
    EXPECT_EQ(metadataObjectTypes.empty(), true);

    intResult = metaOutput->Stop();
    EXPECT_EQ(intResult, 7400201);

    intResult = metaOutput->Release();
    EXPECT_EQ(intResult, 7400201);

    metaObjListener->OnBufferAvailable();

    sptr<MetadataOutput> metaOutput_3 = nullptr;

    sptr<MetadataObjectListener> metaObjListener_2 = new(std::nothrow) MetadataObjectListener(metaOutput_3);
    ASSERT_NE(metaObjListener_2, nullptr);

    metaObjListener_2->OnBufferAvailable();
}

/*
 * Feature: Framework
 * Function: Test anomalous branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photoOutput with anomalous branch.
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_061, TestSize.Level0)
{
    std::shared_ptr<PhotoCaptureSetting> photoSetting = std::make_shared<PhotoCaptureSetting>();
    PhotoCaptureSetting::QualityLevel quality = photoSetting->GetQuality();
    EXPECT_EQ(quality, PhotoCaptureSetting::QualityLevel::QUALITY_LEVEL_MEDIUM);

    photoSetting->SetQuality(PhotoCaptureSetting::QualityLevel::QUALITY_LEVEL_HIGH);
    photoSetting->SetQuality(quality);

    PhotoCaptureSetting::RotationConfig rotation = photoSetting->GetRotation();
    EXPECT_EQ(rotation, PhotoCaptureSetting::RotationConfig::Rotation_0);

    photoSetting->SetRotation(rotation);

    std::unique_ptr<Location> location = std::make_unique<Location>();
    location->latitude = 12.972442;
    location->longitude = 77.580643;

    photoSetting->SetGpsLocation(location->latitude, location->longitude);

    sptr<CaptureSession> camSession = manager_->CreateCaptureSession();
    ASSERT_NE(camSession, nullptr);

    int32_t intResult = camSession->BeginConfig();
    EXPECT_EQ(intResult, 0);

    sptr<CaptureInput> input = (sptr<CaptureInput> &)input_;
    ASSERT_NE(input, nullptr);

    intResult = camSession->AddInput(input);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = camSession->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);

    intResult = camSession->AddOutput(photoOutput);
    EXPECT_EQ(intResult, 0);

    sptr<PhotoOutput> photoOutput_1 = (sptr<PhotoOutput> &)photoOutput;

    intResult = photoOutput_1->Capture(photoSetting);
    EXPECT_EQ(intResult, 7400104);

    intResult = camSession->CommitConfig();
    EXPECT_EQ(intResult, 0);

    bool isMirrorSupported = photoOutput_1->IsMirrorSupported();
    EXPECT_EQ(isMirrorSupported, true);

    int32_t capture = photoOutput_1->Capture();
    EXPECT_EQ(capture, 0);

    int32_t cancelCapture = photoOutput_1->CancelCapture();
    EXPECT_EQ(cancelCapture, 0);

    intResult = photoOutput_1->Release();
    EXPECT_EQ(intResult, 0);

    intResult = photoOutput_1->Release();
    EXPECT_EQ(intResult, 7400201);

    delete photoOutput_1;

    cancelCapture = photoOutput_1->CancelCapture();
    EXPECT_EQ(cancelCapture, 7400104);

    isMirrorSupported = photoOutput_1->IsMirrorSupported();
    EXPECT_EQ(isMirrorSupported, false);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test captureCallback with anomalous branch.
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_062, TestSize.Level0)
{
    std::shared_ptr<HStreamCaptureCallbackImpl> captureCallback = std::make_shared<HStreamCaptureCallbackImpl>();

    int32_t captureId = 2001;
    int32_t intResult = captureCallback->OnCaptureStarted(captureId);
    EXPECT_EQ(intResult, 0);

    int32_t frameCount = 0;
    intResult = captureCallback->OnCaptureEnded(captureId, frameCount);
    EXPECT_EQ(intResult, 0);

    int32_t errorCode = 0;
    intResult = captureCallback->OnCaptureError(captureId, errorCode);
    EXPECT_EQ(intResult, 0);

    uint64_t timestamp = 10;
    intResult = captureCallback->OnFrameShutter(captureId, timestamp);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureSession> camSession = manager_->CreateCaptureSession();
    ASSERT_NE(camSession, nullptr);

    intResult = camSession->BeginConfig();
    EXPECT_EQ(intResult, 0);

    sptr<CaptureInput> input = (sptr<CaptureInput> &)input_;
    ASSERT_NE(input, nullptr);

    intResult = camSession->AddInput(input);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = camSession->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);

    intResult = camSession->AddOutput(photoOutput);
    EXPECT_EQ(intResult, 0);

    sptr<PhotoOutput> photoOutput_1 = (sptr<PhotoOutput> &)photoOutput;

    intResult = camSession->CommitConfig();
    EXPECT_EQ(intResult, 0);

    std::shared_ptr<AppCallback> callback = std::make_shared<AppCallback>();
    photoOutput_1->SetCallback(callback);

    sptr<HStreamCaptureCallbackImpl> captureCallback_2 = new(std::nothrow) HStreamCaptureCallbackImpl(photoOutput_1);

    intResult = captureCallback_2->OnCaptureEnded(captureId, frameCount);
    EXPECT_EQ(intResult, 0);

    intResult = captureCallback_2->OnCaptureError(captureId, errorCode);
    EXPECT_EQ(intResult, 0);

    intResult = captureCallback_2->OnFrameShutter(captureId, timestamp);
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test preview output repeat callback with anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_063, TestSize.Level0)
{
    std::shared_ptr<PreviewOutputCallbackImpl> repeatCallback = std::make_shared<PreviewOutputCallbackImpl>();

    int32_t intResult = repeatCallback->OnFrameStarted();
    EXPECT_EQ(intResult, 0);

    int32_t frameCount = 0;
    intResult = repeatCallback->OnFrameEnded(frameCount);
    EXPECT_EQ(intResult, 0);

    int32_t errorCode = 0;
    intResult = repeatCallback->OnFrameError(errorCode);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureSession> camSession = manager_->CreateCaptureSession();
    ASSERT_NE(camSession, nullptr);

    intResult = camSession->BeginConfig();
    EXPECT_EQ(intResult, 0);

    sptr<CaptureInput> input = (sptr<CaptureInput> &)input_;
    ASSERT_NE(input, nullptr);

    intResult = camSession->AddInput(input);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = camSession->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    sptr<PreviewOutput> previewOutput_1 = (sptr<PreviewOutput> &)previewOutput;

    intResult = camSession->CommitConfig();
    EXPECT_EQ(intResult, 0);

    std::shared_ptr<AppCallback> callback = std::make_shared<AppCallback>();
    previewOutput_1->SetCallback(callback);

    sptr<PreviewOutputCallbackImpl> repeatCallback_2 = new(std::nothrow) PreviewOutputCallbackImpl(previewOutput_1);

    intResult = repeatCallback_2->OnFrameError(errorCode);
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test preview output with anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_064, TestSize.Level0)
{
    sptr<CaptureSession> camSession = manager_->CreateCaptureSession();
    ASSERT_NE(camSession, nullptr);

    int32_t intResult = camSession->BeginConfig();
    EXPECT_EQ(intResult, 0);

    sptr<CaptureInput> input = (sptr<CaptureInput> &)input_;
    ASSERT_NE(input, nullptr);

    intResult = camSession->AddInput(input);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = camSession->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    sptr<PreviewOutput> previewOutput_1 = (sptr<PreviewOutput> &)previewOutput;

    intResult = camSession->CommitConfig();
    EXPECT_EQ(intResult, 0);

    sptr<Surface> surface = nullptr;

    previewOutput_1->AddDeferredSurface(surface);

    sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
    sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
    sptr<Surface> pSurface = Surface::CreateSurfaceAsProducer(previewProducer);

    previewOutput_1->AddDeferredSurface(pSurface);

    intResult = previewOutput_1->CaptureOutput::Release();
    EXPECT_EQ(intResult, 0);

    std::shared_ptr<AppCallback> callback = std::make_shared<AppCallback>();
    previewOutput_1->SetCallback(callback);

    intResult = previewOutput_1->Stop();
    EXPECT_EQ(intResult, 7400201);

    intResult = previewOutput_1->Release();
    EXPECT_EQ(intResult, 7400201);

    previewOutput_1->AddDeferredSurface(pSurface);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test video output with anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_065, TestSize.Level0)
{
    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    sptr<CaptureInput> input = (sptr<CaptureInput> &)input_;
    ASSERT_NE(input, nullptr);

    intResult = session_->AddInput(input);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = session_->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);

    intResult = session_->AddOutput(videoOutput);
    EXPECT_EQ(intResult, 0);

    sptr<VideoOutput> videoOutput_1 = (sptr<VideoOutput> &)videoOutput;

    std::shared_ptr<AppVideoCallback> callback = std::make_shared<AppVideoCallback>();

    intResult = videoOutput_1->Start();
    EXPECT_EQ(intResult, 7400103);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    sleep(WAIT_TIME_AFTER_START);

    intResult = videoOutput_1->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    intResult = videoOutput_1->Pause();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    intResult = videoOutput_1->Resume();
    EXPECT_EQ(intResult, 0);

    intResult = videoOutput_1->Stop();
    EXPECT_EQ(intResult, 0);

    intResult = videoOutput_1->CaptureOutput::Release();
    EXPECT_EQ(intResult, 0);

    videoOutput_1->SetCallback(callback);

    intResult = videoOutput_1->Pause();
    EXPECT_EQ(intResult, 7400201);

    intResult = videoOutput_1->Resume();
    EXPECT_EQ(intResult, 7400201);

    intResult = videoOutput_1->Stop();
    EXPECT_EQ(intResult, 7400201);

    intResult = videoOutput_1->Release();
    EXPECT_EQ(intResult, 7400201);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test video output repeat callback with anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_066, TestSize.Level0)
{
    std::shared_ptr<VideoOutputCallbackImpl> repeatCallback = std::make_shared<VideoOutputCallbackImpl>();

    int32_t intResult = repeatCallback->OnFrameStarted();
    EXPECT_EQ(intResult, 0);

    int32_t frameCount = 0;
    intResult = repeatCallback->OnFrameEnded(frameCount);
    EXPECT_EQ(intResult, 0);

    int32_t errorCode = 0;
    intResult = repeatCallback->OnFrameError(errorCode);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureSession> camSession = manager_->CreateCaptureSession();
    ASSERT_NE(camSession, nullptr);

    intResult = camSession->BeginConfig();
    EXPECT_EQ(intResult, 0);

    sptr<CaptureInput> input = (sptr<CaptureInput> &)input_;
    ASSERT_NE(input, nullptr);

    intResult = camSession->AddInput(input);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = camSession->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);

    intResult = camSession->AddOutput(videoOutput);
    EXPECT_EQ(intResult, 0);

    sptr<VideoOutput> videoOutput_1 = (sptr<VideoOutput> &)videoOutput;

    intResult = camSession->CommitConfig();
    EXPECT_EQ(intResult, 0);

    std::shared_ptr<AppVideoCallback> callback = std::make_shared<AppVideoCallback>();
    videoOutput_1->SetCallback(callback);

    sptr<VideoOutputCallbackImpl> repeatCallback_2 = new(std::nothrow) VideoOutputCallbackImpl(videoOutput_1);

    intResult = repeatCallback->OnFrameStarted();
    EXPECT_EQ(intResult, 0);

    intResult = repeatCallback->OnFrameEnded(frameCount);
    EXPECT_EQ(intResult, 0);

    intResult = repeatCallback_2->OnFrameError(errorCode);
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test HCameraDeviceProxy_cpp with anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_067, TestSize.Level0)
{
    sptr<CameraInput> input_1 = (sptr<CameraInput> &)input_;
    sptr<ICameraDeviceService> deviceObj = input_1->GetCameraDevice();
    ASSERT_NE(deviceObj, nullptr);

    sptr<ICameraDeviceServiceCallback> callback = nullptr;
    int32_t intResult = deviceObj->SetCallback(callback);
    EXPECT_EQ(intResult, 200);

    std::shared_ptr<Camera::CameraMetadata> settings = nullptr;
    intResult = deviceObj->UpdateSetting(settings);
    EXPECT_EQ(intResult, 200);

    std::vector<int32_t> results = {};
    intResult = deviceObj->GetEnabledResults(results);
    EXPECT_EQ(intResult, 0);

    intResult = deviceObj->EnableResult(results);
    EXPECT_EQ(intResult, 2);

    intResult = deviceObj->DisableResult(results);
    EXPECT_EQ(intResult, 2);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test HCameraServiceProxy_cpp with anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_068, TestSize.Level0)
{
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);

    object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    sptr<ICameraService> serviceProxy = iface_cast<ICameraService>(object);
    ASSERT_NE(serviceProxy, nullptr);

    sptr<ICameraServiceCallback> callback = nullptr;
    int32_t intResult = serviceProxy->SetCallback(callback);
    EXPECT_EQ(intResult, 200);

    sptr<ICameraMuteServiceCallback> callback_2 = nullptr;
    intResult = serviceProxy->SetMuteCallback(callback_2);
    EXPECT_EQ(intResult, 200);

    int32_t format = 0;
    int32_t width = 0;
    int32_t height = 0;
    sptr<IStreamCapture> output = nullptr;
    sptr<IBufferProducer> Producer = nullptr;
    intResult = serviceProxy->CreatePhotoOutput(Producer, format, width, height, output);
    EXPECT_EQ(intResult, 200);

    sptr<IStreamRepeat> output_2 = nullptr;
    intResult = serviceProxy->CreatePreviewOutput(Producer, format, width, height, output_2);
    EXPECT_EQ(intResult, 200);

    intResult = serviceProxy->CreateDeferredPreviewOutput(format, width, height, output_2);
    EXPECT_EQ(intResult, 200);

    sptr<IStreamMetadata> output_3 = nullptr;
    intResult = serviceProxy->CreateMetadataOutput(Producer, format, output_3);
    EXPECT_EQ(intResult, 200);

    intResult = serviceProxy->CreateVideoOutput(Producer, format, width, height, output_2);
    EXPECT_EQ(intResult, 200);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test HCameraServiceProxy_cpp with anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_069, TestSize.Level0)
{
    int32_t format = 0;
    int32_t width = 0;
    int32_t height = 0;
    std::string cameraId = "";
    std::vector<std::string> cameraIds = {};
    std::vector<std::shared_ptr<Camera::CameraMetadata>> cameraAbilityList = {};

    sptr<IConsumerSurface> Surface = IConsumerSurface::Create();
    sptr<IBufferProducer> Producer = Surface->GetProducer();

    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);

    object = samgr->GetSystemAbility(AUDIO_POLICY_SERVICE_ID);
    sptr<ICameraService> serviceProxy = iface_cast<ICameraService>(object);
    ASSERT_NE(serviceProxy, nullptr);

    sptr<ICameraServiceCallback> callback = new(std::nothrow) CameraStatusServiceCallback(manager_);
    int32_t intResult = serviceProxy->SetCallback(callback);
    EXPECT_EQ(intResult, -1);

    sptr<ICameraMuteServiceCallback> callback_2 = new(std::nothrow) CameraMuteServiceCallback(manager_);
    serviceProxy->SetMuteCallback(callback_2);
    EXPECT_EQ(intResult, -1);

    intResult = serviceProxy->GetCameras(cameraIds, cameraAbilityList);
    EXPECT_EQ(intResult, -1);

    sptr<ICaptureSession> session = nullptr;
    intResult = serviceProxy->CreateCaptureSession(session);
    EXPECT_EQ(intResult, -1);

    sptr<IStreamCapture> output = nullptr;
    intResult = serviceProxy->CreatePhotoOutput(Producer, format, width, height, output);
    EXPECT_EQ(intResult, -1);

    width = PREVIEW_DEFAULT_WIDTH;
    height = PREVIEW_DEFAULT_HEIGHT;
    sptr<IStreamRepeat> output_2 = nullptr;
    intResult = serviceProxy->CreatePreviewOutput(Producer, format, width, height, output_2);
    EXPECT_EQ(intResult, -1);

    intResult = serviceProxy->CreateDeferredPreviewOutput(format, width, height, output_2);
    EXPECT_EQ(intResult, -1);

    sptr<IStreamMetadata> output_3 = nullptr;
    intResult = serviceProxy->CreateMetadataOutput(Producer, format, output_3);
    EXPECT_EQ(intResult, -1);

    intResult = serviceProxy->CreateVideoOutput(Producer, format, width, height, output_2);
    EXPECT_EQ(intResult, -1);

    intResult = serviceProxy->SetListenerObject(object);
    EXPECT_EQ(intResult, 200);

    bool muteMode = true;
    intResult = serviceProxy->IsCameraMuted(muteMode);
    EXPECT_EQ(intResult, -1);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test HCameraDeviceProxy_cpp with anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_070, TestSize.Level0)
{
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);

    object = samgr->GetSystemAbility(AUDIO_POLICY_SERVICE_ID);

    sptr<ICameraDeviceService> deviceObj = iface_cast<ICameraDeviceService>(object);
    ASSERT_NE(deviceObj, nullptr);

    int32_t intResult = deviceObj->Open();
    EXPECT_EQ(intResult, -1);

    intResult = deviceObj->Close();
    EXPECT_EQ(intResult, -1);

    intResult = deviceObj->Release();
    EXPECT_EQ(intResult, -1);

    sptr<CameraInput> input = (sptr<CameraInput> &)input_;
    sptr<ICameraDeviceServiceCallback> callback = new(std::nothrow) CameraDeviceServiceCallback(input);
    ASSERT_NE(callback, nullptr);

    intResult = deviceObj->SetCallback(callback);
    EXPECT_EQ(intResult, -1);

    std::shared_ptr<Camera::CameraMetadata> settings = cameras_[0]->GetMetadata();
    ASSERT_NE(settings, nullptr);

    intResult = deviceObj->UpdateSetting(settings);
    EXPECT_EQ(intResult, -1);

    std::vector<int32_t> results = {};
    intResult = deviceObj->GetEnabledResults(results);
    EXPECT_EQ(intResult, 200);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test HCaptureSessionProxy_cpp with anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_071, TestSize.Level0)
{
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);

    object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);

    sptr<ICaptureSession> captureSession = iface_cast<ICaptureSession>(object);
    ASSERT_NE(captureSession, nullptr);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    sptr<IStreamCommon> stream = nullptr;

    int32_t intResult = captureSession->AddOutput(previewOutput->GetStreamType(), stream);
    EXPECT_EQ(intResult, 200);

    sptr<ICameraDeviceService> cameraDevice = nullptr;
    intResult = captureSession->RemoveInput(cameraDevice);
    EXPECT_EQ(intResult, 200);

    intResult = captureSession->RemoveOutput(previewOutput->GetStreamType(), stream);
    EXPECT_EQ(intResult, 200);

    sptr<ICaptureSessionCallback> callback = nullptr;
    EXPECT_EQ(intResult, 200);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test HCaptureSessionProxy_cpp with anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_072, TestSize.Level0)
{
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);

    object = samgr->GetSystemAbility(AUDIO_POLICY_SERVICE_ID);

    sptr<ICaptureSession> captureSession = iface_cast<ICaptureSession>(object);
    ASSERT_NE(captureSession, nullptr);

    int32_t intResult = captureSession->BeginConfig();
    EXPECT_EQ(intResult, -1);

    sptr<CameraInput> input_1 = (sptr<CameraInput> &)input_;
    sptr<ICameraDeviceService> deviceObj = input_1->GetCameraDevice();
    ASSERT_NE(deviceObj, nullptr);

    intResult = captureSession->AddInput(deviceObj);
    EXPECT_EQ(intResult, -1);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = captureSession->AddOutput(previewOutput->GetStreamType(), previewOutput->GetStream());
    EXPECT_EQ(intResult, -1);

    intResult = captureSession->Start();
    EXPECT_EQ(intResult, -1);

    pid_t pid = 0;
    intResult = captureSession->Release(pid);
    EXPECT_EQ(intResult, -1);

    sptr<ICaptureSessionCallback> callback = new(std::nothrow) CaptureSessionCallback(session_);
    ASSERT_NE(callback, nullptr);

    intResult = captureSession->SetCallback(callback);
    EXPECT_EQ(intResult, -1);

    CaptureSessionState currentState = CaptureSessionState::SESSION_CONFIG_INPROGRESS;
    intResult = captureSession->GetSessionState(currentState);
    EXPECT_EQ(intResult, -1);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test HStreamCaptureProxy_cpp with anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_073, TestSize.Level0)
{
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);

    object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);

    sptr<IStreamCapture> capture = iface_cast<IStreamCapture>(object);
    ASSERT_NE(capture, nullptr);

    sptr<IStreamCaptureCallback> callback = nullptr;
    int32_t intResult = capture->SetCallback(callback);
    EXPECT_EQ(intResult, 200);

    bool isEnabled = false;
    sptr<OHOS::IBufferProducer> producer = nullptr;
    intResult = capture->SetThumbnail(isEnabled, producer);
    EXPECT_EQ(intResult, 200);

    sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
    producer = previewSurface->GetProducer();

    intResult = capture->SetThumbnail(isEnabled, producer);
    EXPECT_EQ(intResult, -1);

    std::shared_ptr<Camera::CameraMetadata> captureSettings = nullptr;
    intResult = capture->Capture(captureSettings);
    EXPECT_EQ(intResult, 200);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test HStreamCaptureProxy_cpp with anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_074, TestSize.Level0)
{
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);

    object = samgr->GetSystemAbility(AUDIO_POLICY_SERVICE_ID);

    sptr<IStreamCapture> capture = iface_cast<IStreamCapture>(object);
    ASSERT_NE(capture, nullptr);

    std::shared_ptr<Camera::CameraMetadata> captureSettings = cameras_[0]->GetMetadata();
    int32_t intResult = capture->Capture(captureSettings);
    EXPECT_EQ(intResult, -1);

    intResult = capture->CancelCapture();
    EXPECT_EQ(intResult, -1);

    intResult = capture->Release();
    EXPECT_EQ(intResult, -1);

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);

    sptr<PhotoOutput> photoOutput_1 = (sptr<PhotoOutput> &)photoOutput;
    sptr<IStreamCaptureCallback> callback = new(std::nothrow) HStreamCaptureCallbackImpl(photoOutput_1);
    ASSERT_NE(callback, nullptr);

    intResult = capture->SetCallback(callback);
    EXPECT_EQ(intResult, -1);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test HStreamMetadataProxy_cpp with anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_075, TestSize.Level0)
{
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);

    object = samgr->GetSystemAbility(AUDIO_POLICY_SERVICE_ID);

    sptr<IStreamMetadata> metadata = iface_cast<IStreamMetadata>(object);
    ASSERT_NE(metadata, nullptr);

    int32_t intResult = metadata->Start();
    EXPECT_EQ(intResult, -1);

    intResult = metadata->Release();
    EXPECT_EQ(intResult, -1);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test HStreamRepeatProxy_cpp with anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_076, TestSize.Level0)
{
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);

    object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);

    sptr<IStreamRepeat> repeat = iface_cast<IStreamRepeat>(object);
    ASSERT_NE(repeat, nullptr);

    sptr<IStreamRepeatCallback> callback = nullptr;
    int32_t intResult = repeat->SetCallback(callback);
    EXPECT_EQ(intResult, 200);

    sptr<OHOS::IBufferProducer> producer = nullptr;
    intResult = repeat->AddDeferredSurface(producer);
    EXPECT_EQ(intResult, 200);

    object = samgr->GetSystemAbility(AUDIO_POLICY_SERVICE_ID);

    repeat = iface_cast<IStreamRepeat>(object);
    ASSERT_NE(repeat, nullptr);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    sptr<PreviewOutput> previewOutput_1 = (sptr<PreviewOutput> &)previewOutput;
    callback = new(std::nothrow) PreviewOutputCallbackImpl(previewOutput_1);
    ASSERT_NE(callback, nullptr);

    intResult = repeat->SetCallback(callback);
    EXPECT_EQ(intResult, -1);

    sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
    producer = previewSurface->GetProducer();

    intResult = repeat->AddDeferredSurface(producer);
    EXPECT_EQ(intResult, -1);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test set the Thumbnail with anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_077, TestSize.Level0)
{
    sptr<CaptureSession> camSession = manager_->CreateCaptureSession();
    ASSERT_NE(camSession, nullptr);

    int32_t intResult = camSession->BeginConfig();
    EXPECT_EQ(intResult, 0);

    sptr<CaptureInput> input = (sptr<CaptureInput> &)input_;
    ASSERT_NE(input, nullptr);

    intResult = camSession->AddInput(input);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = camSession->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);

    intResult = camSession->AddOutput(photoOutput);
    EXPECT_EQ(intResult, 0);

    sptr<PhotoOutput> photoOutput_1 = (sptr<PhotoOutput> &)photoOutput;

    intResult = camSession->CommitConfig();
    EXPECT_EQ(intResult, 0);

    sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
    sptr<SurfaceListener> listener = new SurfaceListener("Preview", SurfaceType::PREVIEW, g_previewFd, previewSurface);
    sptr<IBufferConsumerListener> listener_1 = (sptr<IBufferConsumerListener> &)listener;

    photoOutput_1->SetThumbnailListener(listener_1);

    intResult = photoOutput_1->IsQuickThumbnailSupported();
    EXPECT_EQ(intResult, -1);

    bool isEnabled = false;
    intResult = photoOutput_1->SetThumbnail(isEnabled);
    EXPECT_EQ(intResult, 0);

    photoOutput_1->SetThumbnailListener(listener_1);

    intResult = photoOutput_1->Release();
    EXPECT_EQ(intResult, 0);

    photoOutput_1->~PhotoOutput();

    intResult = photoOutput_1->IsQuickThumbnailSupported();
    EXPECT_EQ(intResult, 7400104);

    intResult = photoOutput_1->SetThumbnail(isEnabled);
    EXPECT_EQ(intResult, 7400104);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test submit device control setting with anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_079, TestSize.Level0)
{
    sptr<CaptureSession> camSession = manager_->CreateCaptureSession();
    ASSERT_NE(camSession, nullptr);
    delete camSession;

    int32_t intResult = camSession->UnlockForControl();
    EXPECT_EQ(intResult, 7400201);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test MuteCamera with anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_080, TestSize.Level0)
{
    bool cameraMuted = manager_->IsCameraMuted();
    EXPECT_EQ(cameraMuted, false);

    bool cameraMuteSupported = manager_->IsCameraMuteSupported();
    EXPECT_EQ(cameraMuteSupported, false);

    manager_->MuteCamera(cameraMuted);

    sptr<CameraMuteServiceCallback> muteService = new(std::nothrow) CameraMuteServiceCallback();
    ASSERT_NE(muteService, nullptr);

    int32_t muteCameraState = muteService->OnCameraMute(cameraMuted);
    EXPECT_EQ(muteCameraState, 0);

    muteService = new(std::nothrow) CameraMuteServiceCallback(manager_);
    ASSERT_NE(muteService, nullptr);

    muteCameraState = muteService->OnCameraMute(cameraMuted);
    EXPECT_EQ(muteCameraState, 0);

    std::shared_ptr<CameraMuteListener> listener = nullptr;
    manager_->RegisterCameraMuteListener(listener);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test service callback with anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_081, TestSize.Level0)
{
    std::string cameraIdtest = "";
    FlashStatus status = FLASH_STATUS_OFF;

    sptr<CameraStatusServiceCallback> camServiceCallback = new(std::nothrow) CameraStatusServiceCallback();
    int32_t cameraStatusChanged = camServiceCallback->OnFlashlightStatusChanged(cameraIdtest, status);
    EXPECT_EQ(cameraStatusChanged, 0);

    sptr<CameraDeviceServiceCallback> camDeviceSvcCallback = new(std::nothrow) CameraDeviceServiceCallback();
    int32_t onError = camDeviceSvcCallback->OnError(CAMERA_DEVICE_PREEMPTED, 0);
    EXPECT_EQ(onError, 0);

    std::shared_ptr<OHOS::Camera::CameraMetadata> result = nullptr;
    int32_t onResult = camDeviceSvcCallback->OnResult(0, result);
    EXPECT_EQ(onResult, 0);

    sptr<CameraInput> input = (sptr<CameraInput> &)input_;
    sptr<ICameraDeviceService> deviceObj = input->GetCameraDevice();
    ASSERT_NE(deviceObj, nullptr);

    sptr<CameraDevice> camdeviceObj = nullptr;
    sptr<CameraInput> camInput_1 = new(std::nothrow) CameraInput(deviceObj, camdeviceObj);
    ASSERT_NE(camInput_1, nullptr);

    camDeviceSvcCallback = new(std::nothrow) CameraDeviceServiceCallback(camInput_1);
    onResult = camDeviceSvcCallback->OnResult(0, result);
    EXPECT_EQ(onResult, 0);

    sptr<CameraInput> camInput_2 = new(std::nothrow) CameraInput(deviceObj, cameras_[0]);
    camDeviceSvcCallback = new(std::nothrow) CameraDeviceServiceCallback(camInput_2);
    onError = camDeviceSvcCallback->OnError(CAMERA_DEVICE_PREEMPTED, 0);
    EXPECT_EQ(onError, 0);

    std::shared_ptr<AppCallback> callback = std::make_shared<AppCallback>();
    camInput_2->SetErrorCallback(callback);

    camDeviceSvcCallback = new(std::nothrow) CameraDeviceServiceCallback(camInput_2);
    onError = camDeviceSvcCallback->OnError(CAMERA_DEVICE_PREEMPTED, 0);
    EXPECT_EQ(onError, 0);

    callback = nullptr;
    camInput_2->SetErrorCallback(callback);
    camInput_2->SetResultCallback(callback);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test create camera input instance with provided camera position and type anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_082, TestSize.Level0)
{
    CameraPosition cameraPosition = cameras_[0]->GetPosition();
    CameraType cameraType = cameras_[0]->GetCameraType();
    sptr<CaptureInput> camInputtest = manager_->CreateCameraInput(cameraPosition, cameraType);
    EXPECT_EQ(camInputtest, nullptr);

    cameraType = CAMERA_TYPE_UNSUPPORTED;
    cameraPosition = CAMERA_POSITION_UNSPECIFIED;
    camInputtest = manager_->CreateCameraInput(cameraPosition, cameraType);
    EXPECT_EQ(camInputtest, nullptr);

    cameraType = CAMERA_TYPE_UNSUPPORTED;
    cameraPosition = cameras_[0]->GetPosition();
    camInputtest = manager_->CreateCameraInput(cameraPosition, cameraType);
    EXPECT_EQ(camInputtest, nullptr);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test the supported exposure compensation range and Zoom Ratio range with anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_083, TestSize.Level0)
{
    std::string cameraId = "";
    dmDeviceInfo deviceInfo = {};
    sptr<CameraDevice> camdeviceObj = new(std::nothrow) CameraDevice(cameraId, g_metaResult, deviceInfo);
    ASSERT_NE(camdeviceObj, nullptr);

    std::vector<float> zoomRatioRange = camdeviceObj->GetZoomRatioRange();
    EXPECT_EQ(zoomRatioRange.empty(), true);

    std::vector<float> exposureBiasRange = camdeviceObj->GetExposureBiasRange();
    EXPECT_EQ(exposureBiasRange.empty(), true);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test session with anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_084, TestSize.Level0)
{
    sptr<ICameraDeviceService> deviceObj = nullptr;
    sptr<CaptureInput> camInput = new(std::nothrow) CameraInput(deviceObj, cameras_[0]);
    ASSERT_NE(camInput, nullptr);

    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 7400105);

    intResult = session_->AddInput(camInput);
    EXPECT_EQ(intResult, 7400201);

    sptr<CaptureSession> camSession = manager_->CreateCaptureSession();
    ASSERT_NE(camSession, nullptr);
    delete camSession;

    intResult = camSession->BeginConfig();
    EXPECT_EQ(intResult, 7400201);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test create preview output with anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_085, TestSize.Level0)
{
    sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
    sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
    sptr<Surface> pSurface = Surface::CreateSurfaceAsProducer(previewProducer);

    sptr<Surface> pSurface_1 = nullptr;

    sptr<CaptureOutput> previewOutput = manager_->CreatePreviewOutput(previewProfiles[0], pSurface_1);
    EXPECT_EQ(previewOutput, nullptr);

    sptr<CaptureOutput> previewOutput_1 = manager_->CreateDeferredPreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput_1, nullptr);

    // height is zero
    CameraFormat previewFormat = previewProfiles[0].GetCameraFormat();
    Size previewSize;
    previewSize.width = previewProfiles[0].GetSize().width;
    previewSize.height = 0;
    previewProfiles[0] = Profile(previewFormat, previewSize);

    previewOutput = manager_->CreatePreviewOutput(previewProfiles[0], pSurface);
    EXPECT_EQ(previewOutput, nullptr);

    previewOutput_1 = manager_->CreateDeferredPreviewOutput(previewProfiles[0]);
    EXPECT_EQ(previewOutput_1, nullptr);

    sptr<CaptureOutput> previewOutput_2 = manager_->CreatePreviewOutput(previewProducer, previewFormat);
    EXPECT_EQ(previewOutput_2, nullptr);

    sptr<CaptureOutput> previewOutput_3 = nullptr;
    previewOutput_3 = manager_->CreateCustomPreviewOutput(pSurface, previewSize.width, previewSize.height);
    EXPECT_EQ(previewOutput_3, nullptr);

    // width is zero
    previewSize.width = 0;
    previewSize.height = PREVIEW_DEFAULT_HEIGHT;
    previewProfiles[0] = Profile(previewFormat, previewSize);

    previewOutput = manager_->CreatePreviewOutput(previewProfiles[0], pSurface);
    EXPECT_EQ(previewOutput, nullptr);

    previewOutput_1 = manager_->CreateDeferredPreviewOutput(previewProfiles[0]);
    EXPECT_EQ(previewOutput_1, nullptr);

    // format is CAMERA_FORMAT_INVALID
    previewFormat = CAMERA_FORMAT_INVALID;
    previewSize.width = PREVIEW_DEFAULT_WIDTH;
    previewProfiles[0] = Profile(previewFormat, previewSize);

    previewOutput = manager_->CreatePreviewOutput(previewProfiles[0], pSurface);
    EXPECT_EQ(previewOutput, nullptr);

    previewOutput_1 = manager_->CreateDeferredPreviewOutput(previewProfiles[0]);
    EXPECT_EQ(previewOutput_1, nullptr);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test create photo output with anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_086, TestSize.Level0)
{
    sptr<IConsumerSurface> photosurface = IConsumerSurface::Create();
    sptr<IBufferProducer> surfaceProducer_1 = photosurface->GetProducer();

    sptr<IBufferProducer> surfaceProducer_2 = nullptr;

    sptr<CaptureOutput> photoOutput = manager_->CreatePhotoOutput(photoProfiles[0], surfaceProducer_2);
    EXPECT_EQ(photoOutput, nullptr);

    // height is zero
    CameraFormat photoFormat = photoProfiles[0].GetCameraFormat();
    Size photoSize;
    photoSize.width = photoProfiles[0].GetSize().width;
    photoSize.height = 0;
    photoProfiles[0] = Profile(photoFormat, photoSize);

    photoOutput = manager_->CreatePhotoOutput(photoProfiles[0], surfaceProducer_1);
    EXPECT_EQ(photoOutput, nullptr);

    // width is zero
    photoSize.width = 0;
    photoSize.height = PHOTO_DEFAULT_HEIGHT;
    photoProfiles[0] = Profile(photoFormat, photoSize);

    photoOutput = manager_->CreatePhotoOutput(photoProfiles[0], surfaceProducer_1);
    EXPECT_EQ(photoOutput, nullptr);

    // format is CAMERA_FORMAT_INVALID
    photoFormat = CAMERA_FORMAT_INVALID;
    photoSize.width = PHOTO_DEFAULT_WIDTH;
    photoProfiles[0] = Profile(photoFormat, photoSize);

    photoOutput = manager_->CreatePhotoOutput(photoProfiles[0], surfaceProducer_1);
    EXPECT_EQ(photoOutput, nullptr);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test create video output with anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_087, TestSize.Level0)
{
    sptr<IConsumerSurface> videoSurface = IConsumerSurface::Create();
    sptr<IBufferProducer> videoProducer = videoSurface->GetProducer();
    sptr<Surface> pSurface_1 = Surface::CreateSurfaceAsProducer(videoProducer);

    sptr<Surface> pSurface_2 = nullptr;

    sptr<CaptureOutput> videoOutput = manager_->CreateVideoOutput(videoProfiles[0], pSurface_2);
    EXPECT_EQ(videoOutput, nullptr);

    sptr<CaptureOutput> videoOutput_1 = manager_->CreateVideoOutput(pSurface_2);
    EXPECT_EQ(videoOutput_1, nullptr);

    // height is zero
    std::vector<int32_t> framerates;
    CameraFormat videoFormat = videoProfiles[0].GetCameraFormat();
    Size videoSize;
    videoSize.width = videoProfiles[0].GetSize().width;
    videoSize.height = 0;
    VideoProfile videoProfile_1 = VideoProfile(videoFormat, videoSize, framerates);

    videoOutput = manager_->CreateVideoOutput(videoProfile_1, pSurface_1);
    EXPECT_EQ(videoOutput, nullptr);

    // width is zero
    videoSize.width = 0;
    videoSize.height = VIDEO_DEFAULT_HEIGHT;
    videoProfile_1 = VideoProfile(videoFormat, videoSize, framerates);

    videoOutput = manager_->CreateVideoOutput(videoProfile_1, pSurface_1);
    EXPECT_EQ(videoOutput, nullptr);

    // format is CAMERA_FORMAT_INVALID
    videoFormat = CAMERA_FORMAT_INVALID;
    videoSize.width = VIDEO_DEFAULT_WIDTH;
    videoProfile_1 = VideoProfile(videoFormat, videoSize, framerates);

    videoOutput = manager_->CreateVideoOutput(videoProfile_1, pSurface_1);
    EXPECT_EQ(videoOutput, nullptr);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test camera settings with anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_088, TestSize.Level0)
{
    sptr<ICameraDeviceService> deviceObj_1 = nullptr;
    sptr<CameraInput> camInput_1 =  new(std::nothrow) CameraInput(deviceObj_1, cameras_[0]);
    ASSERT_NE(camInput_1, nullptr);

    sptr<CameraInput> input = (sptr<CameraInput> &)input_;
    sptr<ICameraDeviceService> deviceObj_2 = input->GetCameraDevice();
    ASSERT_NE(deviceObj_2, nullptr);

    sptr<CameraDevice> camdeviceObj = nullptr;
    sptr<CameraInput> camInput_2 = new(std::nothrow) CameraInput(deviceObj_2, camdeviceObj);
    ASSERT_NE(camInput_2, nullptr);

    int32_t intResult = camInput_1->Open();
    EXPECT_EQ(intResult, 7400201);

    std::string cameraId = camInput_1->GetCameraId();

    std::string getCameraSettings_1 = camInput_1->GetCameraSettings();
    intResult = camInput_1->SetCameraSettings(getCameraSettings_1);
    EXPECT_EQ(intResult, 0);

    std::string getCameraSettings_2 = "";

    intResult = camInput_2->SetCameraSettings(getCameraSettings_2);
    EXPECT_EQ(intResult, 2);

    sptr<CameraInput> camInput_3 = (sptr<CameraInput> &)input_;
    getCameraSettings_2 = camInput_3->GetCameraSettings();
    intResult = camInput_3->SetCameraSettings(getCameraSettings_2);
    EXPECT_EQ(intResult, 0);

    intResult = camInput_2->Release();
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test submit device control setting with anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_089, TestSize.Level0)
{
    sptr<CaptureSession> camSession = manager_->CreateCaptureSession();
    ASSERT_NE(camSession, nullptr);
    
    int32_t intResult = camSession->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = camSession->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = camSession->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    intResult = camSession->CommitConfig();
    EXPECT_EQ(intResult, 0);

    camSession->LockForControl();

    std::vector<float> zoomRatioRange = camSession->GetZoomRatioRange();
    if (!zoomRatioRange.empty()) {
        camSession->SetZoomRatio(zoomRatioRange[0]);
    }

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input_;
    camInput->Close();

    intResult = camSession->UnlockForControl();
    EXPECT_EQ(intResult, 0);

    camSession->LockForControl();

    intResult = camSession->UnlockForControl();
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test abnormal branches with empty inputDevice_
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_090, TestSize.Level0)
{
    sptr<CaptureSession> camSession = manager_->CreateCaptureSession();
    ASSERT_NE(camSession, nullptr);
    
    int32_t intResult = camSession->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = camSession->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = camSession->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    intResult = camSession->CommitConfig();
    EXPECT_EQ(intResult, 0);

    camSession->inputDevice_ = nullptr;
    VideoStabilizationMode mode = MIDDLE;

    intResult = camSession->GetActiveVideoStabilizationMode(mode);
    EXPECT_EQ(intResult, 0);

    std::vector<VideoStabilizationMode> videoStabilizationMode = camSession->GetSupportedStabilizationMode();
    EXPECT_EQ(videoStabilizationMode.empty(), true);

    intResult = camSession->GetSupportedStabilizationMode(videoStabilizationMode);
    EXPECT_EQ(intResult, 0);

    std::vector<ExposureMode> getSupportedExpModes = camSession->GetSupportedExposureModes();
    EXPECT_EQ(getSupportedExpModes.empty(), true);

    intResult = camSession->GetSupportedExposureModes(getSupportedExpModes);
    EXPECT_EQ(intResult, 0);

    ExposureMode exposureMode = camSession->GetExposureMode();
    EXPECT_EQ(exposureMode, EXPOSURE_MODE_UNSUPPORTED);

    intResult = camSession->GetExposureMode(exposureMode);
    EXPECT_EQ(intResult, 0);

    Point exposurePointGet = camSession->GetMeteringPoint();
    EXPECT_EQ(exposurePointGet.x, 0);
    EXPECT_EQ(exposurePointGet.y, 0);

    intResult = camSession->GetMeteringPoint(exposurePointGet);
    EXPECT_EQ(intResult, 0);

    std::vector<float> getExposureBiasRange = camSession->GetExposureBiasRange();
    EXPECT_EQ(getExposureBiasRange.empty(), true);

    intResult = camSession->GetExposureBiasRange(getExposureBiasRange);
    EXPECT_EQ(intResult, 0);

    float exposureValue = camSession->GetExposureValue();
    EXPECT_EQ(exposureValue, 0);

    intResult = camSession->GetExposureValue(exposureValue);
    EXPECT_EQ(intResult, 0);

    camSession->LockForControl();

    intResult = camSession->SetExposureBias(exposureValue);
    EXPECT_EQ(intResult, 7400102);

    std::vector<FocusMode> getSupportedFocusModes = camSession->GetSupportedFocusModes();
    EXPECT_EQ(getSupportedFocusModes.empty(), true);

    intResult = camSession->GetSupportedFocusModes(getSupportedFocusModes);
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test abnormal branches with empty inputDevice_
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_091, TestSize.Level0)
{
    sptr<CaptureSession> camSession = manager_->CreateCaptureSession();
    ASSERT_NE(camSession, nullptr);
    
    int32_t intResult = camSession->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = camSession->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = camSession->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    intResult = camSession->CommitConfig();
    EXPECT_EQ(intResult, 0);

    camSession->inputDevice_ = nullptr;

    FocusMode focusMode = camSession->GetFocusMode();
    EXPECT_EQ(focusMode, FOCUS_MODE_MANUAL);

    intResult = camSession->GetFocusMode(focusMode);
    EXPECT_EQ(intResult, 0);

    Point focusPoint = camSession->GetFocusPoint();
    EXPECT_EQ(focusPoint.x, 0);
    EXPECT_EQ(focusPoint.y, 0);

    intResult = camSession->GetFocusPoint(focusPoint);
    EXPECT_EQ(intResult, 0);

    float focalLength = camSession->GetFocalLength();
    EXPECT_EQ(focalLength, 0);

    intResult = camSession->GetFocalLength(focalLength);
    EXPECT_EQ(intResult, 0);

    std::vector<FlashMode> getSupportedFlashModes = camSession->GetSupportedFlashModes();
    EXPECT_EQ(getSupportedFlashModes.empty(), true);

    intResult = camSession->GetSupportedFlashModes(getSupportedFlashModes);
    EXPECT_EQ(intResult, 0);

    FlashMode flashMode = camSession->GetFlashMode();
    EXPECT_EQ(flashMode, FLASH_MODE_CLOSE);

    intResult = camSession->GetFlashMode(flashMode);
    EXPECT_EQ(intResult, 0);

    std::vector<float> zoomRatioRange = camSession->GetZoomRatioRange();
    EXPECT_EQ(zoomRatioRange.empty(), true);

    intResult = camSession->GetZoomRatioRange(zoomRatioRange);
    EXPECT_EQ(intResult, 0);

    float zoomRatio = camSession->GetZoomRatio();
    EXPECT_EQ(zoomRatio, 0);

    intResult = camSession->GetZoomRatio(zoomRatio);
    EXPECT_EQ(intResult, 0);

    camSession->LockForControl();
    
    intResult = camSession->SetZoomRatio(zoomRatio);
    EXPECT_EQ(intResult, 0);

    intResult = camSession->SetMeteringPoint(focusPoint);
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test submit device control setting with anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_092, TestSize.Level0)
{
    sptr<CaptureSession> camSession = manager_->CreateCaptureSession();
    ASSERT_NE(camSession, nullptr);

    int32_t intResult = camSession->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = camSession->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = camSession->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    intResult = camSession->CommitConfig();
    EXPECT_EQ(intResult, 0);

    camSession->LockForControl();

    std::vector<float> exposureBiasRange = camSession->GetExposureBiasRange();
    if (!exposureBiasRange.empty()) {
        camSession->SetExposureBias(exposureBiasRange[0]);
    }

    camSession->inputDevice_ = nullptr;

    intResult = camSession->UnlockForControl();
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test serviceProxy_ null with anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_093, TestSize.Level0)
{
    sptr<Surface> pSurface = nullptr;
    sptr<IBufferProducer> surfaceProducer = nullptr;

    sptr<CameraManager> camManagerObj = CameraManager::GetInstance();
    ASSERT_NE(camManagerObj, nullptr);

    delete camManagerObj;

    std::vector<sptr<CameraDevice>> camdeviceObj_1 = camManagerObj->GetSupportedCameras();
    ASSERT_TRUE(camdeviceObj_1.size() == 0);

    sptr<CaptureSession> captureSession = camManagerObj->CreateCaptureSession();
    EXPECT_EQ(captureSession, nullptr);

    sptr<CaptureOutput> metadataOutput = camManagerObj->CreateMetadataOutput();
    EXPECT_EQ(metadataOutput, nullptr);

    sptr<CaptureOutput> previewOutput = camManagerObj->CreatePreviewOutput(previewProfiles[0], pSurface);
    EXPECT_EQ(previewOutput, nullptr);

    previewOutput = camManagerObj->CreateDeferredPreviewOutput(previewProfiles[0]);
    EXPECT_EQ(previewOutput, nullptr);

    sptr<CaptureOutput> photoOutput = camManagerObj->CreatePhotoOutput(photoProfiles[0], surfaceProducer);
    EXPECT_EQ(photoOutput, nullptr);

    sptr<CaptureOutput> videoOutput = camManagerObj->CreateVideoOutput(videoProfiles[0], pSurface);
    EXPECT_EQ(videoOutput, nullptr);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test serviceProxy_ null with muteCamera anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_094, TestSize.Level0)
{
    sptr<CameraManager> camManagerObj = CameraManager::GetInstance();
    ASSERT_NE(camManagerObj, nullptr);

    delete camManagerObj;

    bool cameraMuted = camManagerObj->IsCameraMuted();
    EXPECT_EQ(cameraMuted, false);

    bool cameraMuteSupported = camManagerObj->IsCameraMuteSupported();
    EXPECT_EQ(cameraMuteSupported, false);

    camManagerObj->MuteCamera(cameraMuted);
}

/*
 * Feature: Framework
 * Function: Test anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test create camera input and construct device object with anomalous branch
 */
HWTEST_F(CameraFrameworkModuleTest, camera_framework_moduletest_095, TestSize.Level0)
{
    sptr<CameraManager> camManagerObj = CameraManager::GetInstance();
    ASSERT_NE(camManagerObj, nullptr);

    delete camManagerObj;

    std::string cameraId = "";
    dmDeviceInfo deviceInfo = {};
    sptr<CameraDevice> camdeviceObj_1 = new(std::nothrow) CameraDevice(cameraId, g_metaResult, deviceInfo);
    ASSERT_NE(camdeviceObj_1, nullptr);

    cameraId = cameras_[0]->GetID();
    sptr<CameraDevice> camdeviceObj_2  = new(std::nothrow) CameraDevice(cameraId, g_metaResult, deviceInfo);
    ASSERT_NE(camdeviceObj_2, nullptr);

    sptr<CameraDevice> camdeviceObj_3 = nullptr;
    sptr<CaptureInput> camInput = camManagerObj->CreateCameraInput(camdeviceObj_3);
    EXPECT_EQ(camInput, nullptr);

    camInput = camManagerObj->CreateCameraInput(camdeviceObj_1);
    EXPECT_EQ(camInput, nullptr);

    sptr<CameraInfo> camera = nullptr;
    camInput = camManagerObj->CreateCameraInput(camera);
    EXPECT_EQ(camInput, nullptr);

    CameraPosition cameraPosition = cameras_[0]->GetPosition();
    CameraType cameraType = cameras_[0]->GetCameraType();
    camInput = camManagerObj->CreateCameraInput(cameraPosition, cameraType);
    EXPECT_EQ(camInput, nullptr);

    sptr<ICameraDeviceService> deviceObj_1 = nullptr;
    sptr<CameraInput> input_1 =  new(std::nothrow) CameraInput(deviceObj_1, cameras_[0]);
    ASSERT_NE(input_1, nullptr);

    sptr<CameraInput> input_2 = (sptr<CameraInput> &)input_;
    sptr<ICameraDeviceService> deviceObj_2 = input_2->GetCameraDevice();
    ASSERT_NE(deviceObj_2, nullptr);

    input_2 = new(std::nothrow) CameraInput(deviceObj_2, camdeviceObj_3);
    ASSERT_NE(input_2, nullptr);

    input_2 = new(std::nothrow) CameraInput(deviceObj_1, cameras_[0]);
    ASSERT_NE(input_2, nullptr);
}
} // CameraStandard
} // OHOS
