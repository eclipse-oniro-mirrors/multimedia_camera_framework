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

#include "camera_session_moduletest.h"

#include <algorithm>
#include <cinttypes>
#include <cstdint>
#include <memory>
#include <vector>
#include <thread>
#include "test_token.h"
#include "test_log_detector.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

std::bitset<static_cast<int>(CAM_PHOTO_EVENTS::CAM_PHOTO_MAX_EVENT)> g_photoEvents;
std::bitset<static_cast<unsigned int>(CAM_PREVIEW_EVENTS::CAM_PREVIEW_MAX_EVENT)> g_previewEvents;
std::bitset<static_cast<unsigned int>(CAM_VIDEO_EVENTS::CAM_VIDEO_MAX_EVENT)> g_videoEvents;
std::bitset<static_cast<unsigned int>(CAM_MACRO_DETECT_EVENTS::CAM_MACRO_EVENT_MAX_EVENT)> g_macroEvents;
std::bitset<static_cast<unsigned int>(CAM_MOON_CAPTURE_BOOST_EVENTS::CAM_MOON_CAPTURE_BOOST_EVENT_MAX_EVENT)>
    g_moonCaptureBoostEvents;
std::unordered_map<std::string, int> g_camStatusMap;
std::unordered_map<std::string, bool> g_camFlashMap;
std::shared_ptr<OHOS::Camera::CameraMetadata> g_metaResult = nullptr;
std::list<int32_t> g_sketchStatus;
TorchStatusInfo g_torchInfo;
int32_t g_previewFd = -1;
int32_t g_photoFd = -1;
int32_t g_videoFd = -1;
int32_t g_sketchFd = -1;
bool g_camInputOnError = false;
bool g_sessionclosed = false;
bool g_brightnessStatusChanged = false;
bool g_slowMotionStatusChanged = false;

void AppCallback::OnCameraStatusChanged(const CameraStatusInfo& cameraDeviceInfo) const
{
    const std::string cameraID = cameraDeviceInfo.cameraDevice->GetID();
    const CameraStatus cameraStatus = cameraDeviceInfo.cameraStatus;
    EXPECT_TRUE(true)<<"OnCameraStatusChanged:CameraId="<<cameraID<<",CameraStatus="<<cameraDeviceInfo.cameraStatus
        <<",bundleName="<<cameraDeviceInfo.bundleName<<endl;
    switch (cameraStatus) {
        case CAMERA_STATUS_UNAVAILABLE: {
            MEDIA_DEBUG_LOG(
                "AppCallback::OnCameraStatusChanged %{public}s: CAMERA_STATUS_UNAVAILABLE", cameraID.c_str());
            g_camStatusMap[cameraID] = CAMERA_STATUS_UNAVAILABLE;
            break;
        }
        case CAMERA_STATUS_AVAILABLE: {
            MEDIA_DEBUG_LOG(
                "AppCallback::OnCameraStatusChanged %{public}s: CAMERA_STATUS_AVAILABLE", cameraID.c_str());
            g_camStatusMap[cameraID] = CAMERA_STATUS_AVAILABLE;
            break;
        }
        default: {
            MEDIA_DEBUG_LOG("AppCallback::OnCameraStatusChanged %{public}s: unknown", cameraID.c_str());
        }
    }
}

void AppCallback::OnFlashlightStatusChanged(const std::string& cameraID, const FlashStatus flashStatus) const
{
    MEDIA_DEBUG_LOG("AppCallback::OnFlashlightStatusChanged() is called!");
    switch (flashStatus) {
        case FLASH_STATUS_OFF: {
            MEDIA_DEBUG_LOG(
                "AppCallback::OnFlashlightStatusChanged %{public}s: FLASH_STATUS_OFF", cameraID.c_str());
            g_camFlashMap[cameraID] = false;
            break;
        }
        case FLASH_STATUS_ON: {
            MEDIA_DEBUG_LOG("AppCallback::OnFlashlightStatusChanged %{public}s: FLASH_STATUS_ON", cameraID.c_str());
            g_camFlashMap[cameraID] = true;
            break;
        }
        case FLASH_STATUS_UNAVAILABLE: {
            MEDIA_DEBUG_LOG(
                "AppCallback::OnFlashlightStatusChanged %{public}s: FLASH_STATUS_UNAVAILABLE", cameraID.c_str());
            g_camFlashMap.erase(cameraID);
            break;
        }
        default: {
            MEDIA_DEBUG_LOG("AppCallback::OnFlashlightStatusChanged %{public}s: unknown", cameraID.c_str());
            EXPECT_TRUE(false);
        }
    }
}

void AppCallback::OnTorchStatusChange(const TorchStatusInfo &torchStatusInfo) const
{
    MEDIA_DEBUG_LOG("TorchListener::OnTorchStatusChange called %{public}d %{public}d %{public}f",
        torchStatusInfo.isTorchAvailable, torchStatusInfo.isTorchActive, torchStatusInfo.torchLevel);
    g_torchInfo = torchStatusInfo;
}

void AppCallback::OnError(const int32_t errorType, const int32_t errorMsg) const
{
    MEDIA_DEBUG_LOG("AppCallback::OnError errorType: %{public}d, errorMsg: %{public}d", errorType, errorMsg);
    g_camInputOnError = true;
    if (errorType == CAMERA_DEVICE_PREEMPTED) {
        g_sessionclosed = true;
    }
}

void AppCallback::OnResult(const uint64_t timestamp, const std::shared_ptr<OHOS::Camera::CameraMetadata>& result) const
{
    MEDIA_INFO_LOG("CameraDeviceServiceCallback::OnResult() is called!");

    if (result != nullptr) {
        g_metaResult = result;
        common_metadata_header_t* data = result->get();
        std::vector<int32_t> fpsRange;
        camera_metadata_item_t entry;
        int ret = OHOS::Camera::FindCameraMetadataItem(data, OHOS_ABILITY_FPS_RANGES, &entry);
        MEDIA_INFO_LOG("CameraDeviceServiceCallback::FindCameraMetadataItem() %{public}d", ret);
        if (ret != 0) {
            MEDIA_INFO_LOG("demo test: get OHOS_ABILITY_FPS_RANGES error");
        }
        uint32_t count = entry.count;
        MEDIA_INFO_LOG("demo test: fpsRange count  %{public}d", count);
        for (uint32_t i = 0; i < count; i++) {
            fpsRange.push_back(*(entry.data.i32 + i));
        }
        for (auto it = fpsRange.begin(); it != fpsRange.end(); it++) {
            MEDIA_INFO_LOG("demo test: fpsRange %{public}d ", *it);
        }
    }
}

void AppCallback::OnCaptureStarted(const int32_t captureId) const
{
    MEDIA_DEBUG_LOG("AppCallback::OnCaptureStarted captureId: %{public}d", captureId);
    g_photoEvents[static_cast<int>(CAM_PHOTO_EVENTS::CAM_PHOTO_CAPTURE_START)] = 1;
}

void AppCallback::OnCaptureStarted(const int32_t captureId, uint32_t exposureTime) const
{
    MEDIA_DEBUG_LOG("AppCallback::OnCaptureStarted captureId: %{public}d", captureId);
    g_photoEvents[static_cast<int>(CAM_PHOTO_EVENTS::CAM_PHOTO_CAPTURE_START)] = 1;
}

void AppCallback::OnCaptureEnded(const int32_t captureId, const int32_t frameCount) const
{
    MEDIA_DEBUG_LOG("AppCallback::OnCaptureEnded captureId: %{public}d, frameCount: %{public}d",
                    captureId, frameCount);
    g_photoEvents[static_cast<int>(CAM_PHOTO_EVENTS::CAM_PHOTO_CAPTURE_END)] = 1;
}

void AppCallback::OnFrameShutter(const int32_t captureId, const uint64_t timestamp) const
{
    MEDIA_DEBUG_LOG(
        "AppCallback::OnFrameShutter captureId: %{public}d, timestamp: %{public}" PRIu64, captureId, timestamp);
    g_photoEvents[static_cast<int>(CAM_PHOTO_EVENTS::CAM_PHOTO_FRAME_SHUTTER)] = 1;
}

void AppCallback::OnFrameShutterEnd(const int32_t captureId, const uint64_t timestamp) const
{
    MEDIA_DEBUG_LOG(
        "AppCallback::OnFrameShutterEnd captureId: %{public}d, timestamp: %{public}" PRIu64, captureId, timestamp);
    g_photoEvents[static_cast<int>(CAM_PHOTO_EVENTS::CAM_PHOTO_FRAME_SHUTTER_END)] = 1;
}

void AppCallback::OnCaptureReady(const int32_t captureId, const uint64_t timestamp) const
{
    MEDIA_DEBUG_LOG(
        "AppCallback::OnCaptureReady captureId: %{public}d, timestamp: %{public}" PRIu64, captureId, timestamp);
    g_photoEvents[static_cast<int>(CAM_PHOTO_EVENTS::CAM_PHOTO_CAPTURE_READY)] = 1;
}

void AppCallback::OnEstimatedCaptureDuration(const int32_t duration) const
{
    MEDIA_DEBUG_LOG("AppCallback::OnEstimatedCaptureDuration duration: %{public}d", duration);
    g_photoEvents[static_cast<int>(CAM_PHOTO_EVENTS::CAM_PHOTO_ESTIMATED_CAPTURE_DURATION)] = 1;
}

void AppCallback::OnCaptureError(const int32_t captureId, const int32_t errorCode) const
{
    MEDIA_DEBUG_LOG(
        "AppCallback::OnCaptureError captureId: %{public}d, errorCode: %{public}d", captureId, errorCode);
    g_photoEvents[static_cast<int>(CAM_PHOTO_EVENTS::CAM_PHOTO_CAPTURE_ERR)] = 1;
}

void AppCallback::OnFrameStarted() const
{
    MEDIA_DEBUG_LOG("AppCallback::OnFrameStarted");
    g_previewEvents[static_cast<int>(CAM_PREVIEW_EVENTS::CAM_PREVIEW_FRAME_START)] = 1;
}
void AppCallback::OnFrameEnded(const int32_t frameCount) const
{
    MEDIA_DEBUG_LOG("AppCallback::OnFrameEnded frameCount: %{public}d", frameCount);
    g_previewEvents[static_cast<int>(CAM_PREVIEW_EVENTS::CAM_PREVIEW_FRAME_END)] = 1;
}
void AppCallback::OnError(const int32_t errorCode) const
{
    MEDIA_DEBUG_LOG("AppCallback::OnError errorCode: %{public}d", errorCode);
    g_previewEvents[static_cast<int>(CAM_PREVIEW_EVENTS::CAM_PREVIEW_FRAME_ERR)] = 1;
}

void AppCallback::OnOfflineDeliveryFinished(const int32_t captureId) const
{
    MEDIA_DEBUG_LOG("AppCallback::OnOfflineDeliveryFinished captureId: %{public}d", captureId);
    g_photoEvents[static_cast<int>(CAM_PHOTO_EVENTS::CAM_PHOTO_OFFLINE_PHOTOOUTPUT)] = 1;
}

void AppCallback::OnSketchStatusDataChanged(const SketchStatusData& statusData) const
{
    MEDIA_INFO_LOG("AppCallback::OnSketchStatusDataChanged status:%{public}d", statusData.status);
    g_previewEvents[static_cast<int>(CAM_PREVIEW_EVENTS::CAM_PREVIEW_SKETCH_STATUS_CHANGED)] = 1;
    g_sketchStatus.push_back(static_cast<int32_t>(statusData.status));
}
void AppCallback::OnMacroStatusChanged(MacroStatus status)
{
    MEDIA_DEBUG_LOG("AppCallback::OnMacroStatusChanged");
    if (status == MacroStatus::IDLE) {
        g_macroEvents[static_cast<int>(CAM_MACRO_DETECT_EVENTS::CAM_MACRO_EVENT_IDLE)] = 1;
        g_macroEvents[static_cast<int>(CAM_MACRO_DETECT_EVENTS::CAM_MACRO_EVENT_ACTIVE)] = 0;
    } else if (status == MacroStatus::ACTIVE) {
        g_macroEvents[static_cast<int>(CAM_MACRO_DETECT_EVENTS::CAM_MACRO_EVENT_ACTIVE)] = 1;
        g_macroEvents[static_cast<int>(CAM_MACRO_DETECT_EVENTS::CAM_MACRO_EVENT_IDLE)] = 0;
    }
}

void AppCallback::OnFeatureDetectionStatusChanged(SceneFeature feature, FeatureDetectionStatus status)
{
    MEDIA_DEBUG_LOG("AppCallback::OnFeatureDetectionStatusChanged");
    if (feature == SceneFeature::FEATURE_MOON_CAPTURE_BOOST) {
        if (status == FeatureDetectionStatus::IDLE) {
            g_moonCaptureBoostEvents[static_cast<int>(
                CAM_MOON_CAPTURE_BOOST_EVENTS::CAM_MOON_CAPTURE_BOOST_EVENT_IDLE)] = 1;
            g_moonCaptureBoostEvents[static_cast<int>(
                CAM_MOON_CAPTURE_BOOST_EVENTS::CAM_MOON_CAPTURE_BOOST_EVENT_ACTIVE)] = 0;
        } else if (status == FeatureDetectionStatus::ACTIVE) {
            g_moonCaptureBoostEvents[static_cast<int>(
                CAM_MOON_CAPTURE_BOOST_EVENTS::CAM_MOON_CAPTURE_BOOST_EVENT_ACTIVE)] = 1;
            g_moonCaptureBoostEvents[static_cast<int>(
                CAM_MOON_CAPTURE_BOOST_EVENTS::CAM_MOON_CAPTURE_BOOST_EVENT_IDLE)] = 0;
        }
    }
}

bool AppCallback::IsFeatureSubscribed(SceneFeature feature)
{
    return true;
}

void AppCallback::OnBrightnessStatusChanged(bool state)
{
    MEDIA_DEBUG_LOG("AppCallback::OnBrightnessStatusChanged");
    g_brightnessStatusChanged = true;
}

void AppCallback::OnSlowMotionState(const SlowMotionState state)
{
    MEDIA_DEBUG_LOG("AppCallback::OnSlowMotionState");
    g_slowMotionStatusChanged = true;
}
void AppCallback::OnFoldStatusChanged(const FoldStatusInfo &foldStatusInfo) const
{
    MEDIA_DEBUG_LOG("AppCallback::OnFoldStatusChanged");
}
void AppCallback::OnLcdFlashStatusChanged(LcdFlashStatusInfo lcdFlashStatusInfo)
{
    MEDIA_DEBUG_LOG("AppCallback::OnLcdFlashStatusChanged");
}

void AppVideoCallback::OnFrameStarted() const
{
    MEDIA_DEBUG_LOG("AppVideoCallback::OnFrameStarted");
    g_videoEvents[static_cast<int>(CAM_VIDEO_EVENTS::CAM_VIDEO_FRAME_START)] = 1;
}
void AppVideoCallback::OnFrameEnded(const int32_t frameCount) const
{
    MEDIA_DEBUG_LOG("AppVideoCallback::OnFrameEnded frameCount: %{public}d", frameCount);
    g_videoEvents[static_cast<int>(CAM_VIDEO_EVENTS::CAM_VIDEO_FRAME_END)] = 1;
}
void AppVideoCallback::OnError(const int32_t errorCode) const
{
    MEDIA_DEBUG_LOG("AppVideoCallback::OnError errorCode: %{public}d", errorCode);
    g_videoEvents[static_cast<int>(CAM_VIDEO_EVENTS::CAM_VIDEO_FRAME_ERR)] = 1;
}
void AppVideoCallback::OnDeferredVideoEnhancementInfo(const CaptureEndedInfoExt info) const
{
    MEDIA_DEBUG_LOG("AppVideoCallback::OnDeferredVideoEnhancementInfo");
}

void AppMetadataCallback::OnMetadataObjectsAvailable(std::vector<sptr<MetadataObject>> metaObjects) const
{
    MEDIA_DEBUG_LOG("AppMetadataCallback::OnMetadataObjectsAvailable received");
}
void AppMetadataCallback::OnError(int32_t errorCode) const
{
    MEDIA_DEBUG_LOG("AppMetadataCallback::OnError %{public}d", errorCode);
}

void AppSessionCallback::OnError(int32_t errorCode)
{
    MEDIA_DEBUG_LOG("AppMetadataCallback::OnError %{public}d", errorCode);
}

sptr<CaptureOutput> CameraSessionModuleTest::CreatePhotoOutput(int32_t width, int32_t height)
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

sptr<CaptureOutput> CameraSessionModuleTest::CreatePhotoOutput()
{
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoWidth_, photoHeight_);
    return photoOutput;
}

sptr<CaptureOutput> CameraSessionModuleTest::CreatePreviewOutput(int32_t width, int32_t height)
{
    sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
    sptr<SurfaceListener> listener = new SurfaceListener("Preview", SurfaceType::PREVIEW, g_previewFd, previewSurface);
    previewSurface->RegisterConsumerListener((sptr<IBufferConsumerListener>&)listener);
    Size previewSize;
    previewSize.width = previewProfiles_[0].GetSize().width;
    previewSize.height = previewProfiles_[0].GetSize().height;
    previewSurface->SetUserData(CameraManager::surfaceFormat, std::to_string(previewProfiles_[0].GetCameraFormat()));
    previewSurface->SetDefaultWidthAndHeight(previewSize.width, previewSize.height);

    sptr<IBufferProducer> bp = previewSurface->GetProducer();
    sptr<Surface> pSurface = Surface::CreateSurfaceAsProducer(bp);

    sptr<CaptureOutput> previewOutput = nullptr;
    previewOutput = manager_->CreatePreviewOutput(previewProfiles_[0], pSurface);
    return previewOutput;
}

std::shared_ptr<Profile> CameraSessionModuleTest::GetSketchPreviewProfile()
{
    std::shared_ptr<Profile> returnProfile;
    Size size720P { 1280, 720 };
    Size size1080P { 1920, 1080 };
    for (const auto& profile : previewProfiles_) {
        if (profile.format_ != CAMERA_FORMAT_YUV_420_SP) {
            continue;
        }
        if (profile.size_.width == size720P.width && profile.size_.height == size720P.height) {
            returnProfile = std::make_shared<Profile>(profile);
            return returnProfile;
        }
        if (profile.size_.width == size1080P.width && profile.size_.height == size1080P.height) {
            returnProfile = std::make_shared<Profile>(profile);
            return returnProfile;
        }
        if (profile.size_.height < SKETCH_PREVIEW_MIN_HEIGHT || profile.size_.width > SKETCH_PREVIEW_MAX_WIDTH) {
            continue;
        }
        if (returnProfile == nullptr) {
            returnProfile = std::make_shared<Profile>(profile);
            continue;
        }
        if (profile.size_.width > returnProfile->size_.width) {
            returnProfile = std::make_shared<Profile>(profile);
        }
    }
    return returnProfile;
}

sptr<CaptureOutput> CameraSessionModuleTest::CreatePreviewOutput(Profile& profile)
{
    sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
    sptr<SurfaceListener> listener = new SurfaceListener("Preview", SurfaceType::PREVIEW, g_previewFd, previewSurface);
    previewSurface->RegisterConsumerListener((sptr<IBufferConsumerListener>&)listener);
    Size previewSize = profile.GetSize();
    previewSurface->SetUserData(CameraManager::surfaceFormat, std::to_string(profile.GetCameraFormat()));
    previewSurface->SetDefaultWidthAndHeight(previewSize.width, previewSize.height);

    sptr<IBufferProducer> bp = previewSurface->GetProducer();
    sptr<Surface> pSurface = Surface::CreateSurfaceAsProducer(bp);

    sptr<CaptureOutput> previewOutput = nullptr;
    previewOutput = manager_->CreatePreviewOutput(profile, pSurface);
    return previewOutput;
}

sptr<Surface> CameraSessionModuleTest::CreateSketchSurface(CameraFormat cameraFormat)
{
    sptr<IConsumerSurface> sketchSurface = IConsumerSurface::Create();
    sptr<SurfaceListener> listener = new SurfaceListener("Sketch", SurfaceType::SKETCH, g_sketchFd, sketchSurface);
    sketchSurface->RegisterConsumerListener((sptr<IBufferConsumerListener>&)listener);
    sketchSurface->SetUserData(CameraManager::surfaceFormat, std::to_string(cameraFormat));
    sketchSurface->SetDefaultWidthAndHeight(SKETCH_DEFAULT_WIDTH, SKETCH_DEFAULT_HEIGHT);
    sptr<IBufferProducer> bp = sketchSurface->GetProducer();
    return Surface::CreateSurfaceAsProducer(bp);
}

sptr<CaptureOutput> CameraSessionModuleTest::CreatePreviewOutput()
{
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewWidth_, previewHeight_);
    return previewOutput;
}

sptr<CaptureOutput> CameraSessionModuleTest::CreateVideoOutput(int32_t width, int32_t height)
{
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<SurfaceListener> videoSurfaceListener =
        new (std::nothrow) SurfaceListener("Video", SurfaceType::VIDEO, g_videoFd, surface);
    if (videoSurfaceListener == nullptr) {
        MEDIA_ERR_LOG("Failed to create new SurfaceListener");
        return nullptr;
    }
    surface->RegisterConsumerListener((sptr<IBufferConsumerListener>&)videoSurfaceListener);
    sptr<IBufferProducer> videoProducer = surface->GetProducer();
    sptr<Surface> videoSurface = Surface::CreateSurfaceAsProducer(videoProducer);
    VideoProfile videoProfile = videoProfiles_[0];
    sptr<CaptureOutput> videoOutput = nullptr;
    videoOutput = manager_->CreateVideoOutput(videoProfile, videoSurface);
    return videoOutput;
}

sptr<CaptureOutput> CameraSessionModuleTest::CreateVideoOutput(VideoProfile& videoProfile)
{
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<SurfaceListener> videoSurfaceListener =
        new (std::nothrow) SurfaceListener("Video", SurfaceType::VIDEO, g_videoFd, surface);
    if (videoSurfaceListener == nullptr) {
        MEDIA_ERR_LOG("Failed to create new SurfaceListener");
        return nullptr;
    }
    surface->RegisterConsumerListener((sptr<IBufferConsumerListener>&)videoSurfaceListener);
    sptr<IBufferProducer> videoProducer = surface->GetProducer();
    sptr<Surface> videoSurface = Surface::CreateSurfaceAsProducer(videoProducer);
    sptr<CaptureOutput> videoOutput = nullptr;
    videoOutput = manager_->CreateVideoOutput(videoProfile, videoSurface);
    return videoOutput;
}

sptr<CaptureOutput> CameraSessionModuleTest::CreateVideoOutput()
{
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoWidth_, videoHeight_);
    return videoOutput;
}

sptr<CaptureOutput> CameraSessionModuleTest::CreatePhotoOutput(Profile profile)
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

void CameraSessionModuleTest::ConfigScanSession(sptr<CaptureOutput> &previewOutput_1,
                                                sptr<CaptureOutput> &previewOutput_2)
{
    if (session_) {
        MEDIA_INFO_LOG("old session exist, need release");
        session_->Release();
    }
    scanSession_ = manager_ -> CreateCaptureSession(SceneMode::SCAN);
    ASSERT_NE(scanSession_, nullptr);

    int32_t intResult = scanSession_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = scanSession_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    previewOutput_1 = CreatePreviewOutput();
    ASSERT_NE(previewOutput_1, nullptr);

    intResult = scanSession_->AddOutput(previewOutput_1);
    EXPECT_EQ(intResult, 0);

    previewOutput_2 = CreatePreviewOutput();
    ASSERT_NE(previewOutput_2, nullptr);

    intResult = scanSession_->AddOutput(previewOutput_2);
    EXPECT_EQ(intResult, 0);

    intResult = scanSession_->CommitConfig();
    EXPECT_EQ(intResult, 0);
}

void CameraSessionModuleTest::ConfigSlowMotionSession(sptr<CaptureOutput> &previewOutput_frame,
                                                      sptr<CaptureOutput> &videoOutput_frame)
{
    if (session_) {
        MEDIA_INFO_LOG("old session exist, need release");
        session_->Release();
    }
    sptr<CaptureSession> captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::SLOW_MOTION);
    slowMotionSession_ = static_cast<SlowMotionSession*>(captureSession.GetRefPtr());
    slowMotionSession_->SetCallback(std::make_shared<AppCallback>());
    ASSERT_NE(slowMotionSession_, nullptr);

    int32_t intResult = slowMotionSession_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = slowMotionSession_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    Profile previewProfile = previewProfiles_[0];
    const int32_t sizeOfWidth = 1920;
    const int32_t sizeOfHeight = 1080;
    for (auto item : previewProfiles_) {
        if (item.GetSize().width == sizeOfWidth && item.GetSize().height == sizeOfHeight) {
            previewProfile = item;
            break;
        }
    }
    sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
    sptr<SurfaceListener> listener = new SurfaceListener("Preview", SurfaceType::PREVIEW, g_previewFd, previewSurface);
    previewSurface->RegisterConsumerListener((sptr<IBufferConsumerListener>&)listener);
    Size previewSize;
    previewSize.width = previewProfile.GetSize().width;
    previewSize.height = previewProfile.GetSize().height;
    previewSurface->SetUserData(CameraManager::surfaceFormat, std::to_string(previewProfile.GetCameraFormat()));
    previewSurface->SetDefaultWidthAndHeight(previewSize.width, previewSize.height);
    sptr<IBufferProducer> bp = previewSurface->GetProducer();
    sptr<Surface> pSurface = Surface::CreateSurfaceAsProducer(bp);
    sptr<CaptureOutput> previewOutput = nullptr;
    previewOutput_frame = manager_->CreatePreviewOutput(previewProfile, pSurface);
    ASSERT_NE(previewOutput_frame, nullptr);

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<SurfaceListener> videoSurfaceListener =
        new (std::nothrow) SurfaceListener("Video", SurfaceType::VIDEO, g_videoFd, surface);
    surface->RegisterConsumerListener((sptr<IBufferConsumerListener>&)videoSurfaceListener);
    ASSERT_NE(videoSurfaceListener, nullptr);

    sptr<IBufferProducer> videoProducer = surface->GetProducer();
    sptr<Surface> videoSurface = Surface::CreateSurfaceAsProducer(videoProducer);
    std::vector<int32_t> fps = {120, 120};
    Size size = {.width = 1920, .height = 1080};
    VideoProfile videoProfile = VideoProfile(CameraFormat::CAMERA_FORMAT_YUV_420_SP, size, fps);
    videoOutput_frame = manager_->CreateVideoOutput(videoProfile, videoSurface);
    ASSERT_NE(videoOutput_frame, nullptr);
}

void CameraSessionModuleTest::ConfigVideoSession(sptr<CaptureOutput> &previewOutput_frame,
                                                 sptr<CaptureOutput> &videoOutput_frame)
{
    if (session_) {
        MEDIA_INFO_LOG("old session exist, need release");
        session_->Release();
    }
    videoSession_ = manager_ -> CreateCaptureSession(SceneMode::VIDEO);
    ASSERT_NE(videoSession_, nullptr);

    int32_t intResult = videoSession_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = videoSession_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    Profile previewProfile = previewProfiles_[0];
    const int32_t sizeOfWidth = 1920;
    const int32_t sizeOfHeight = 1080;
    for (auto item : previewProfiles_) {
        if (item.GetSize().width == sizeOfWidth && item.GetSize().height == sizeOfHeight) {
            previewProfile = item;
            break;
        }
    }
    sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
    sptr<SurfaceListener> listener = new SurfaceListener("Preview", SurfaceType::PREVIEW, g_previewFd, previewSurface);
    previewSurface->RegisterConsumerListener((sptr<IBufferConsumerListener>&)listener);
    Size previewSize;
    previewSize.width = previewProfile.GetSize().width;
    previewSize.height = previewProfile.GetSize().height;
    previewSurface->SetUserData(CameraManager::surfaceFormat, std::to_string(previewProfile.GetCameraFormat()));
    previewSurface->SetDefaultWidthAndHeight(previewSize.width, previewSize.height);
    sptr<IBufferProducer> bp = previewSurface->GetProducer();
    sptr<Surface> pSurface = Surface::CreateSurfaceAsProducer(bp);
    sptr<CaptureOutput> previewOutput = nullptr;
    previewOutput_frame = manager_->CreatePreviewOutput(previewProfile, pSurface);
    ASSERT_NE(previewOutput_frame, nullptr);

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<SurfaceListener> videoSurfaceListener =
        new (std::nothrow) SurfaceListener("Video", SurfaceType::VIDEO, g_videoFd, surface);
    ASSERT_NE(videoSurfaceListener, nullptr);
    surface->RegisterConsumerListener((sptr<IBufferConsumerListener>&)videoSurfaceListener);

    sptr<IBufferProducer> videoProducer = surface->GetProducer();
    sptr<Surface> videoSurface = Surface::CreateSurfaceAsProducer(videoProducer);
    VideoProfile videoProfile = videoProfiles_[0];
    for (auto item : videoProfiles_) {
        if (item.GetSize().width == sizeOfWidth && item.GetSize().height == sizeOfHeight) {
            videoProfile = item;
            break;
        }
    }
    videoOutput_frame = manager_->CreateVideoOutput(videoProfile, videoSurface);
    ASSERT_NE(videoOutput_frame, nullptr);
}

void CameraSessionModuleTest::GetSupportedOutputCapability()
{
    sptr<CameraManager> camManagerObj = CameraManager::GetInstance();
    std::vector<sptr<CameraDevice>> cameraObjList = camManagerObj->GetSupportedCameras();
    ASSERT_GE(cameraObjList.size(), CAMERA_NUMBER);
    sptr<CameraOutputCapability> outputcapability = camManagerObj->GetSupportedOutputCapability(cameraObjList[1]);
    previewProfiles_ = outputcapability->GetPreviewProfiles();
    ASSERT_TRUE(!previewProfiles_.empty());

    photoProfiles_ = outputcapability->GetPhotoProfiles();
    ASSERT_TRUE(!photoProfiles_.empty());

    videoProfiles_ = outputcapability->GetVideoProfiles();
    ASSERT_TRUE(!videoProfiles_.empty());
}

Profile CameraSessionModuleTest::SelectProfileByRatioAndFormat(sptr<CameraOutputCapability>& modeAbility,
                                                               camera_rational_t ratio, CameraFormat format)
{
    uint32_t width;
    uint32_t height;
    Profile profile;
    std::vector<Profile> profiles;

    if (format == photoFormat_) {
        profiles = modeAbility->GetPhotoProfiles();
    } else if (format == previewFormat_) {
        profiles = modeAbility->GetPreviewProfiles();
    }

    for (int i = 0; i < profiles.size(); ++i) {
        width = profiles[i].GetSize().width;
        height = profiles[i].GetSize().height;
        if ((width % ratio.numerator == 0) && (height % ratio.denominator == 0)) {
            profile = profiles[i];
            break;
        }
    }
    MEDIA_ERR_LOG("SelectProfileByRatioAndFormat format:%{public}d width:%{public}d height:%{public}d",
        profile.format_, profile.size_.width, profile.size_.height);
    return profile;
}

std::optional<Profile> CameraSessionModuleTest::GetPreviewProfileByFormat(
    sptr<CameraOutputCapability> &modeAbility, uint32_t width, uint32_t height, CameraFormat format)
{
    std::vector<Profile> profiles = modeAbility->GetPreviewProfiles();
    auto it = std::find_if(profiles.begin(), profiles.end(), [width, height, format](Profile &profile) {
        return profile.GetSize().width == width && profile.GetSize().height == height &&
               profile.GetCameraFormat() == format;
    });
    if (it != profiles.end()) {
        MEDIA_ERR_LOG("GetPreviewProfileByFormat format:%{public}d width:%{public}d height:%{public}d",
            it->GetCameraFormat(),
            it->GetSize().width,
            it->GetSize().height);
        return *it;
    } else {
        MEDIA_ERR_LOG(
            "No profile found for format:%{public}d width:%{public}d height:%{public}d", format, width, height);
        return std::nullopt;
    }
}

std::optional<VideoProfile> CameraSessionModuleTest::GetVideoProfileByFormat(
    sptr<CameraOutputCapability> &modeAbility, uint32_t width, uint32_t height, CameraFormat videoFormat,
    uint32_t maxFps)
{
    std::vector<VideoProfile> profiles = modeAbility->GetVideoProfiles();
    auto it =
        std::find_if(profiles.begin(), profiles.end(), [width, height, videoFormat, maxFps](VideoProfile &profile) {
            std::cout << "videoProfile found format: " << profile.GetCameraFormat()
                      << " width: " << profile.GetSize().width << " height: " << profile.GetSize().height
                      << " maxFps: " << profile.GetFrameRates()[1] << std::endl;
            return profile.GetSize().width == width && profile.GetSize().height == height &&
                   profile.GetCameraFormat() == videoFormat && profile.GetFrameRates()[1] == maxFps;
        });
    if (it != profiles.end()) {
        MEDIA_ERR_LOG("videoProfile found format:%{public}d width:%{public}d height:%{public}d maxFps:%{public}d",
            it->GetCameraFormat(),
            it->GetSize().width,
            it->GetSize().height,
            it->GetFrameRates()[1]);
        return *it;
    } else {
        MEDIA_ERR_LOG("No videoProfile for format:%{public}d width:%{public}d height:%{public}d maxFps:%{public}d",
            videoFormat,
            width,
            height,
            maxFps);
        return std::nullopt;
    }
}

bool CameraSessionModuleTest::IsSupportNow()
{
    const char* deviveTypeString = GetDeviceType();
    std::string deviveType = std::string(deviveTypeString);
    if (deviveType.compare("default") == 0 ||
        (cameras_[0] != nullptr && cameras_[0]->GetConnectionType() == CAMERA_CONNECTION_USB_PLUGIN)) {
        return false;
    }
    return true;
}

void CameraSessionModuleTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase of camera test case!");
    ASSERT_TRUE(TestToken::GetAllCameraPermission());
}

void CameraSessionModuleTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase of camera test case!");
}

void CameraSessionModuleTest::SetUpInit()
{
    MEDIA_INFO_LOG("SetUpInit of camera test case!");
    g_photoEvents.reset();
    g_previewEvents.reset();
    g_videoEvents.reset();
    g_moonCaptureBoostEvents.reset();
    g_macroEvents.reset();
    g_camStatusMap.clear();
    g_camFlashMap.clear();
    g_sketchStatus.clear();
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

void CameraSessionModuleTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
    SetUpInit();
    manager_ = CameraManager::GetInstance();
    ASSERT_NE(manager_, nullptr);
    manager_->SetCallback(std::make_shared<AppCallback>());
    managerForSys_ = CameraManagerForSys::GetInstance();
    ASSERT_NE(managerForSys_, nullptr);

    cameras_ = manager_->GetSupportedCameras();
    ASSERT_TRUE(cameras_.size() != 0);

    input_ = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input_, nullptr);

    sptr<CameraManager> camManagerObj = CameraManager::GetInstance();
    std::vector<sptr<CameraDevice>> cameraObjList = camManagerObj->GetSupportedCameras();
    sptr<CameraOutputCapability> outputcapability = camManagerObj->GetSupportedOutputCapability(cameraObjList[0]);

    ProcessPreviewProfiles(outputcapability);
    ASSERT_TRUE(!previewFormats_.empty());
    ASSERT_TRUE(!previewSizes_.empty());
    if (std::find(previewFormats_.begin(), previewFormats_.end(), CAMERA_FORMAT_YUV_420_SP) != previewFormats_.end()) {
        previewFormat_ = CAMERA_FORMAT_YUV_420_SP;
    } else {
        previewFormat_ = previewFormats_[0];
    }
    photoProfiles_ = outputcapability->GetPhotoProfiles();

    for (auto i : photoProfiles_) {
        photoFormats_.push_back(i.GetCameraFormat());
        photoSizes_.push_back(i.GetSize());
    }
    ASSERT_TRUE(!photoFormats_.empty());
    ASSERT_TRUE(!photoSizes_.empty());
    photoFormat_ = photoFormats_[0];
    videoProfiles_ = outputcapability->GetVideoProfiles();

    for (auto i : videoProfiles_) {
        videoFormats_.push_back(i.GetCameraFormat());
        videoSizes_.push_back(i.GetSize());
        videoFrameRates_ = i.GetFrameRates();
    }
    ASSERT_TRUE(!videoFormats_.empty());
    ASSERT_TRUE(!videoSizes_.empty());
    ASSERT_TRUE(!videoFrameRates_.empty());
    if (std::find(videoFormats_.begin(), videoFormats_.end(), CAMERA_FORMAT_YUV_420_SP) != videoFormats_.end()) {
        videoFormat_ = CAMERA_FORMAT_YUV_420_SP;
    } else {
        videoFormat_ = videoFormats_[0];
    }
    ProcessSize();
}

void CameraSessionModuleTest::TearDown()
{
    MEDIA_INFO_LOG("TearDown start");
    if (session_) {
        session_->Release();
    }
    if (sessionForSys_) {
        sessionForSys_->Release();
    }
    if (scanSession_) {
        scanSession_->Release();
    }
    if (input_) {
        sptr<CameraInput> camInput = (sptr<CameraInput>&)input_;
        camInput->Close();
        input_->Release();
    }
    MEDIA_INFO_LOG("TearDown end");
}

bool CameraSessionModuleTest::IsSceneModeSupported(SceneMode mode)
{
    MEDIA_INFO_LOG("IsSceneModeSupported start");
    std::vector<SceneMode> modes = manager_->GetSupportedModes(cameras_[0]);
    if (modes.size() == 0) {
        MEDIA_ERR_LOG("IsSceneModeSupported: device does not support any scene mode!");
        return false;
    }
    bool supportMode = false;
    for (auto &it : modes) {
        if (it == mode) {
            supportMode = true;
            break;
        }
    }
    return supportMode;
}

void CameraSessionModuleTest::FilterPreviewProfiles(std::vector<Profile> &previewProfiles)
{
    std::vector<Profile>::iterator itr = previewProfiles.begin();
    while (itr != previewProfiles.end()) {
        Profile profile = *itr;
        if ((profile.size_.width == PRVIEW_WIDTH_176 && profile.size_.height == PRVIEW_HEIGHT_144) ||
            (profile.size_.width == PRVIEW_WIDTH_480 && profile.size_.height == PRVIEW_HEIGHT_480) ||
            (profile.size_.width == PRVIEW_WIDTH_640 && profile.size_.height == PRVIEW_WIDTH_640) ||
            (profile.size_.width == PRVIEW_WIDTH_4096 && profile.size_.height == PRVIEW_HEIGHT_3072) ||
            (profile.size_.width == PRVIEW_WIDTH_4160 && profile.size_.height == PRVIEW_HEIGHT_3120) ||
            (profile.size_.width == PRVIEW_WIDTH_8192 && profile.size_.height == PRVIEW_HEIGHT_6144)) {
            itr = previewProfiles.erase(itr);
        } else {
            itr++;
        }
    }
}

void CameraSessionModuleTest::ProcessPreviewProfiles(sptr<CameraOutputCapability>& outputcapability)
{
    previewProfiles_.clear();
    std::vector<Profile> tempPreviewProfiles = outputcapability->GetPreviewProfiles();
    for (const auto& profile : tempPreviewProfiles) {
        if ((profile.size_.width == PRVIEW_WIDTH_176 && profile.size_.height == PRVIEW_HEIGHT_144) ||
            (profile.size_.width == PRVIEW_WIDTH_480 && profile.size_.height == PRVIEW_HEIGHT_480) ||
            (profile.size_.width == PRVIEW_WIDTH_640 && profile.size_.height == PRVIEW_WIDTH_640) ||
            (profile.size_.width == PRVIEW_WIDTH_4096 && profile.size_.height == PRVIEW_HEIGHT_3072) ||
            (profile.size_.width == PRVIEW_WIDTH_4160 && profile.size_.height == PRVIEW_HEIGHT_3120) ||
            (profile.size_.width == PRVIEW_WIDTH_8192 && profile.size_.height == PRVIEW_HEIGHT_6144)) {
            MEDIA_DEBUG_LOG("SetUp skip previewProfile width:%{public}d height:%{public}d",
                profile.size_.width, profile.size_.height);
            continue;
        }
        previewProfiles_.push_back(profile);
    }

    for (auto i : previewProfiles_) {
        MEDIA_DEBUG_LOG("SetUp previewProfiles_ width:%{public}d height:%{public}d", i.size_.width, i.size_.height);
        previewFormats_.push_back(i.GetCameraFormat());
        previewSizes_.push_back(i.GetSize());
    }
}

void CameraSessionModuleTest::ProcessSize()
{
    Size size = previewSizes_.back();
    previewWidth_ = size.width;
    previewHeight_ = size.height;
    size = photoSizes_.back();
    photoWidth_ = size.width;
    photoHeight_ = size.height;
    size = videoSizes_.back();
    videoWidth_ = size.width;
    videoHeight_ = size.height;

    sptr<CameraInput> camInput = (sptr<CameraInput>&)input_;
    camInput->Open();
    session_ = manager_->CreateCaptureSession();
    ASSERT_NE(session_, nullptr);
    sessionForSys_ = managerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys_, nullptr);
}

/*
 * Feature: Framework
 * Function: Test aperture video session with photo output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can not add photo output into aperture video session
 */
HWTEST_F(CameraSessionModuleTest, aperture_video_session_moduletest_001, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::APERTURE_VIDEO)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::APERTURE_VIDEO);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto photoProfiles = outputCapability->GetPhotoProfiles();
    ASSERT_TRUE(photoProfiles.empty());
    auto outputCapabilityBase = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::CAPTURE);
    ASSERT_NE(outputCapabilityBase, nullptr);
    auto photoProfilesBase = outputCapabilityBase->GetPhotoProfiles();
    ASSERT_FALSE(photoProfilesBase.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::APERTURE_VIDEO);
    auto apertureVideoSession = static_cast<ApertureVideoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(apertureVideoSession, nullptr);
    int32_t res = apertureVideoSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = apertureVideoSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(apertureVideoSession->CanAddOutput(previewOutput));
    res = apertureVideoSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoProfilesBase[0]);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_FALSE(apertureVideoSession->CanAddOutput(photoOutput));
}

/*
 * Feature: Framework
 * Function: Test aperture video session with video output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can add video output into aperture video session
 */
HWTEST_F(CameraSessionModuleTest, aperture_video_session_moduletest_002, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::APERTURE_VIDEO)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::APERTURE_VIDEO);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    Profile previewProfile = previewProfiles[0];
    previewProfile.size_.width = 1920;
    previewProfile.size_.height = 1080;
    ASSERT_FALSE(previewProfiles.empty());
    auto videoProfiles = outputCapability->GetVideoProfiles();
    VideoProfile videoProfile = videoProfiles[0];
    videoProfile.size_.width = 1920;
    videoProfile.size_.height = 1080;
    ASSERT_FALSE(videoProfiles.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::APERTURE_VIDEO);
    auto apertureVideoSession = static_cast<ApertureVideoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(apertureVideoSession, nullptr);
    int32_t res = apertureVideoSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = apertureVideoSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfile);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(apertureVideoSession->CanAddOutput(previewOutput));
    res = apertureVideoSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfile);
    ASSERT_NE(videoOutput, nullptr);
    EXPECT_TRUE(apertureVideoSession->CanAddOutput(videoOutput));
    res = apertureVideoSession->AddOutput(videoOutput);
    EXPECT_EQ(res, 0);

    res = apertureVideoSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = apertureVideoSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);
    res = static_cast<VideoOutput*>(videoOutput.GetRefPtr())->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);
    res = static_cast<VideoOutput*>(videoOutput.GetRefPtr())->Stop();
    EXPECT_EQ(res, 0);
    res = apertureVideoSession->Stop();
    EXPECT_EQ(res, 0);
    res = apertureVideoSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test fluorescence photo session with photo output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can add photo output into fluorescence photo session
 */
HWTEST_F(CameraSessionModuleTest, fluorescence_photo_session_moduletest_001, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::FLUORESCENCE_PHOTO)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::FLUORESCENCE_PHOTO);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto photoProfiles = outputCapability->GetPhotoProfiles();
    ASSERT_FALSE(photoProfiles.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::FLUORESCENCE_PHOTO);
    auto fluorescencePhotoSession = static_cast<FluorescencePhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(fluorescencePhotoSession, nullptr);
    int32_t res = fluorescencePhotoSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = fluorescencePhotoSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(fluorescencePhotoSession->CanAddOutput(previewOutput));
    res = fluorescencePhotoSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoProfiles[0]);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_TRUE(fluorescencePhotoSession->CanAddOutput(photoOutput));
    res = fluorescencePhotoSession->AddOutput(photoOutput);
    EXPECT_EQ(res, 0);

    res = fluorescencePhotoSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = fluorescencePhotoSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);
    res = static_cast<PhotoOutput*>(photoOutput.GetRefPtr())->Capture();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);
    res = fluorescencePhotoSession->Stop();
    EXPECT_EQ(res, 0);
    res = fluorescencePhotoSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test fluorescence photo session with video output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can not add video output into fluorescence photo session
 */
HWTEST_F(CameraSessionModuleTest, fluorescence_photo_session_moduletest_002, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::FLUORESCENCE_PHOTO)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::FLUORESCENCE_PHOTO);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto videoProfiles = outputCapability->GetVideoProfiles();
    ASSERT_FALSE(videoProfiles.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::FLUORESCENCE_PHOTO);
    auto fluorescencePhotoSession = static_cast<FluorescencePhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(fluorescencePhotoSession, nullptr);
    int32_t res = fluorescencePhotoSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = fluorescencePhotoSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(fluorescencePhotoSession->CanAddOutput(previewOutput));
    res = fluorescencePhotoSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfiles[0]);
    ASSERT_NE(videoOutput, nullptr);
    EXPECT_FALSE(fluorescencePhotoSession->CanAddOutput(videoOutput));
}

/*
 * Feature: Framework
 * Function: Test high res photo session with photo output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can add photo output into high res photo session
 */
HWTEST_F(CameraSessionModuleTest, high_res_photo_session_moduletest_001, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::HIGH_RES_PHOTO)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::HIGH_RES_PHOTO);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto photoProfiles = outputCapability->GetPhotoProfiles();
    ASSERT_FALSE(photoProfiles.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::HIGH_RES_PHOTO);
    auto highResPhotoSession = static_cast<HighResPhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(highResPhotoSession, nullptr);
    int32_t res = highResPhotoSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = highResPhotoSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(highResPhotoSession->CanAddOutput(previewOutput));
    res = highResPhotoSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoProfiles[0]);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_TRUE(highResPhotoSession->CanAddOutput(photoOutput));
    res = highResPhotoSession->AddOutput(photoOutput);
    EXPECT_EQ(res, 0);

    res = highResPhotoSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = highResPhotoSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);
    res = static_cast<PhotoOutput*>(photoOutput.GetRefPtr())->Capture();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);
    res = highResPhotoSession->Stop();
    EXPECT_EQ(res, 0);
    res = highResPhotoSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test high res photo session with video output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can not add video output into high res photo session
 */
HWTEST_F(CameraSessionModuleTest, high_res_photo_session_moduletest_002, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::HIGH_RES_PHOTO)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::HIGH_RES_PHOTO);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto videoProfiles = outputCapability->GetVideoProfiles();
    ASSERT_TRUE(videoProfiles.empty());
    auto outputCapabilityBase = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::VIDEO);
    ASSERT_NE(outputCapabilityBase, nullptr);
    auto videoProfilesBase = outputCapabilityBase->GetVideoProfiles();
    ASSERT_FALSE(videoProfilesBase.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::HIGH_RES_PHOTO);
    auto highResPhotoSession = static_cast<HighResPhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(highResPhotoSession, nullptr);
    int32_t res = highResPhotoSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = highResPhotoSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(highResPhotoSession->CanAddOutput(previewOutput));
    res = highResPhotoSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfilesBase[0]);
    ASSERT_NE(videoOutput, nullptr);
    EXPECT_FALSE(highResPhotoSession->CanAddOutput(videoOutput));
}

/*
 * Feature: Framework
 * Function: Test light painting session with photo output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can add photo output into light painting session
 */
HWTEST_F(CameraSessionModuleTest, light_painting_session_moduletest_001, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::LIGHT_PAINTING)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::LIGHT_PAINTING);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto photoProfiles = outputCapability->GetPhotoProfiles();
    ASSERT_FALSE(photoProfiles.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::LIGHT_PAINTING);
    auto lightPaintingSession = static_cast<LightPaintingSession*>(captureSession.GetRefPtr());
    ASSERT_NE(lightPaintingSession, nullptr);
    int32_t res = lightPaintingSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = lightPaintingSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(lightPaintingSession->CanAddOutput(previewOutput));
    res = lightPaintingSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoProfiles[0]);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_TRUE(lightPaintingSession->CanAddOutput(photoOutput));
    res = lightPaintingSession->AddOutput(photoOutput);
    EXPECT_EQ(res, 0);

    res = lightPaintingSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = lightPaintingSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);
    res = static_cast<PhotoOutput*>(photoOutput.GetRefPtr())->Capture();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);
    res = lightPaintingSession->Stop();
    EXPECT_EQ(res, 0);
    res = lightPaintingSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test light painting session with video output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can not add video output into light painting session
 */
HWTEST_F(CameraSessionModuleTest, light_painting_session_moduletest_002, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::LIGHT_PAINTING)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::LIGHT_PAINTING);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto videoProfiles = outputCapability->GetVideoProfiles();
    ASSERT_TRUE(videoProfiles.empty());
    auto outputCapabilityBase = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::VIDEO);
    ASSERT_NE(outputCapabilityBase, nullptr);
    auto videoProfilesBase = outputCapabilityBase->GetVideoProfiles();
    ASSERT_FALSE(videoProfilesBase.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::LIGHT_PAINTING);
    auto lightPaintingSession = static_cast<LightPaintingSession*>(captureSession.GetRefPtr());
    ASSERT_NE(lightPaintingSession, nullptr);
    int32_t res = lightPaintingSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = lightPaintingSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(lightPaintingSession->CanAddOutput(previewOutput));
    res = lightPaintingSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfilesBase[0]);
    ASSERT_NE(videoOutput, nullptr);
    EXPECT_FALSE(lightPaintingSession->CanAddOutput(videoOutput));
}

/*
 * Feature: Framework
 * Function: Test light painting session get light painting type
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can get light painting type from light painting session
 */
HWTEST_F(CameraSessionModuleTest, light_painting_session_moduletest_003, TestSize.Level0)
{
    if (!IsSceneModeSupported(SceneMode::LIGHT_PAINTING)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::LIGHT_PAINTING);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto photoProfiles = outputCapability->GetPhotoProfiles();
    ASSERT_FALSE(photoProfiles.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::LIGHT_PAINTING);
    auto lightPaintingSession = static_cast<LightPaintingSession*>(captureSession.GetRefPtr());
    ASSERT_NE(lightPaintingSession, nullptr);
    int32_t res = lightPaintingSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = lightPaintingSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(lightPaintingSession->CanAddOutput(previewOutput));
    res = lightPaintingSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoProfiles[0]);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_TRUE(lightPaintingSession->CanAddOutput(photoOutput));
    res = lightPaintingSession->AddOutput(photoOutput);
    EXPECT_EQ(res, 0);

    res = lightPaintingSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = lightPaintingSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);

    std::vector<LightPaintingType> supportedType;
    res = lightPaintingSession->GetSupportedLightPaintings(supportedType);
    EXPECT_EQ(res, 0);
    if (!supportedType.empty()) {
        LightPaintingType defaultType;
        res = lightPaintingSession->GetLightPainting(defaultType);
        EXPECT_EQ(defaultType, supportedType[0]);
    }

    res = static_cast<PhotoOutput*>(photoOutput.GetRefPtr())->Capture();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);
    res = lightPaintingSession->Stop();
    EXPECT_EQ(res, 0);
    res = lightPaintingSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test light painting session set light painting type
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can set light painting type into light painting session
 */
HWTEST_F(CameraSessionModuleTest, light_painting_session_moduletest_004, TestSize.Level0)
{
    if (!IsSceneModeSupported(SceneMode::LIGHT_PAINTING)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::LIGHT_PAINTING);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto photoProfiles = outputCapability->GetPhotoProfiles();
    ASSERT_FALSE(photoProfiles.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::LIGHT_PAINTING);
    auto lightPaintingSession = static_cast<LightPaintingSession*>(captureSession.GetRefPtr());
    ASSERT_NE(lightPaintingSession, nullptr);
    int32_t res = lightPaintingSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = lightPaintingSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(lightPaintingSession->CanAddOutput(previewOutput));
    res = lightPaintingSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoProfiles[0]);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_TRUE(lightPaintingSession->CanAddOutput(photoOutput));
    res = lightPaintingSession->AddOutput(photoOutput);
    EXPECT_EQ(res, 0);

    res = lightPaintingSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = lightPaintingSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);

    std::vector<LightPaintingType> supportedType;
    res = lightPaintingSession->GetSupportedLightPaintings(supportedType);
    EXPECT_EQ(res, 0);
    if (!supportedType.empty()) {
        LightPaintingType setType = LightPaintingType::LIGHT;
        lightPaintingSession->LockForControl();
        res = lightPaintingSession->SetLightPainting(setType);
        lightPaintingSession->UnlockForControl();
        EXPECT_EQ(res, 0);

        LightPaintingType defaultType;
        res = lightPaintingSession->GetLightPainting(defaultType);
        EXPECT_EQ(defaultType, setType);

        lightPaintingSession->LockForControl();
        res = lightPaintingSession->TriggerLighting();
        lightPaintingSession->UnlockForControl();
        EXPECT_EQ(res, 0);
    }

    res = static_cast<PhotoOutput*>(photoOutput.GetRefPtr())->Capture();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);
    res = lightPaintingSession->Stop();
    EXPECT_EQ(res, 0);
    res = lightPaintingSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test macro photo session with photo output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can add photo output into macro photo session
 */
HWTEST_F(CameraSessionModuleTest, macro_photo_session_moduletest_001, TestSize.Level0)
{
    if (!IsSceneModeSupported(SceneMode::CAPTURE_MACRO)) {
        GTEST_SKIP();
    }

    auto previewProfile = GetSketchPreviewProfile();
    if (previewProfile == nullptr) {
        EXPECT_EQ(previewProfile.get(), nullptr);
        GTEST_SKIP();
    }
    SelectProfiles selectProfiles;
    selectProfiles.preview.size_ = {SKETCH_DEFAULT_WIDTH, SKETCH_DEFAULT_HEIGHT};
    selectProfiles.preview.format_ = CAMERA_FORMAT_YUV_420_SP;
    selectProfiles.photo.size_ = {SKETCH_DEFAULT_WIDTH, SKETCH_DEFAULT_HEIGHT};
    selectProfiles.photo.format_ = CAMERA_FORMAT_YUV_420_SP;
    selectProfiles.video.size_ = {SKETCH_DEFAULT_WIDTH, SKETCH_DEFAULT_HEIGHT};
    selectProfiles.video.format_ = CAMERA_FORMAT_YUV_420_SP;
    selectProfiles.video.framerates_ = {MAX_FRAME_RATE, MAX_FRAME_RATE};
    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::CAPTURE_MACRO);
    ASSERT_NE(outputCapability, nullptr);
    auto photoProfiles = outputCapability->GetPhotoProfiles();
    ASSERT_FALSE(photoProfiles.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE_MACRO);
    auto macroPhotoSession = static_cast<MacroPhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(macroPhotoSession, nullptr);
    int32_t res = macroPhotoSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = macroPhotoSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(selectProfiles.preview);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(macroPhotoSession->CanAddOutput(previewOutput));
    res = macroPhotoSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoProfiles[0]);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_TRUE(macroPhotoSession->CanAddOutput(photoOutput));
    res = macroPhotoSession->AddOutput(photoOutput);
    EXPECT_EQ(res, 0);

    bool isSketchSupported = ((sptr<PreviewOutput>&)previewOutput)->IsSketchSupported();
    if (!isSketchSupported) {
        GTEST_SKIP();
    }
    res = ((sptr<PreviewOutput>&)previewOutput)->EnableSketch(true);
    EXPECT_EQ(res, 0);

    res = macroPhotoSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = macroPhotoSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);

    EXPECT_GT(((sptr<PreviewOutput>&)previewOutput)->GetSketchRatio(), 0);
    EXPECT_EQ(((sptr<PreviewOutput>&)previewOutput)->AttachSketchSurface(
        CreateSketchSurface(selectProfiles.preview.GetCameraFormat())), 0);
    sleep(WAIT_TIME_AFTER_ATTACH_SKETCH);

    res = static_cast<PhotoOutput*>(photoOutput.GetRefPtr())->Capture();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);
    res = macroPhotoSession->Stop();
    EXPECT_EQ(res, 0);
    res = macroPhotoSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test macro photo session with video output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can not add video output into macro photo session
 */
HWTEST_F(CameraSessionModuleTest, macro_photo_session_moduletest_002, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::CAPTURE_MACRO)) {
        GTEST_SKIP();
    }

    auto previewProfile = GetSketchPreviewProfile();
    if (previewProfile == nullptr) {
        EXPECT_EQ(previewProfile.get(), nullptr);
        GTEST_SKIP();
    }
    SelectProfiles selectProfiles;
    selectProfiles.preview.size_ = {SKETCH_DEFAULT_WIDTH, SKETCH_DEFAULT_HEIGHT};
    selectProfiles.preview.format_ = CAMERA_FORMAT_YUV_420_SP;
    selectProfiles.photo.size_ = {SKETCH_DEFAULT_WIDTH, SKETCH_DEFAULT_HEIGHT};
    selectProfiles.photo.format_ = CAMERA_FORMAT_YUV_420_SP;
    selectProfiles.video.size_ = {SKETCH_DEFAULT_WIDTH, SKETCH_DEFAULT_HEIGHT};
    selectProfiles.video.format_ = CAMERA_FORMAT_YUV_420_SP;
    selectProfiles.video.framerates_ = {MAX_FRAME_RATE, MAX_FRAME_RATE};

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE_MACRO);
    auto macroPhotoSession = static_cast<MacroPhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(macroPhotoSession, nullptr);
    int32_t res = macroPhotoSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = macroPhotoSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(selectProfiles.preview);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(macroPhotoSession->CanAddOutput(previewOutput));
    res = macroPhotoSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(selectProfiles.video);
    ASSERT_NE(videoOutput, nullptr);
    EXPECT_FALSE(macroPhotoSession->CanAddOutput(videoOutput));
}

/*
 * Feature: Framework
 * Function: Test macro photo session with CreateCaptureSessionForSys
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test macro photo session with CreateCaptureSessionForSys
 */
HWTEST_F(CameraSessionModuleTest, macro_photo_session_moduletest_003, TestSize.Level1)
{
    SceneMode mode = SceneMode::CAPTURE_MACRO;
    sptr<CameraManager> modeManagerObj = CameraManager::GetInstance();
    ASSERT_NE(modeManagerObj, nullptr);

    sptr<CaptureSessionForSys> captureSession = managerForSys_->CreateCaptureSessionForSys(mode);
    ASSERT_NE(captureSession, nullptr);
}

/*
 * Feature: Framework
 * Function: Test macro video session with photo output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can add photo output into macro video session
 */
HWTEST_F(CameraSessionModuleTest, macro_video_session_moduletest_001, TestSize.Level0)
{
    if (!IsSceneModeSupported(SceneMode::VIDEO_MACRO)) {
        GTEST_SKIP();
    }

    auto previewProfile = GetSketchPreviewProfile();
    if (previewProfile == nullptr) {
        EXPECT_EQ(previewProfile.get(), nullptr);
        GTEST_SKIP();
    }
    SelectProfiles selectProfiles;
    selectProfiles.preview.size_ = {SKETCH_DEFAULT_WIDTH, SKETCH_DEFAULT_HEIGHT};
    selectProfiles.preview.format_ = CAMERA_FORMAT_YUV_420_SP;
    selectProfiles.photo.size_ = {SKETCH_DEFAULT_WIDTH, SKETCH_DEFAULT_HEIGHT};
    selectProfiles.photo.format_ = CAMERA_FORMAT_YUV_420_SP;
    selectProfiles.video.size_ = {SKETCH_DEFAULT_WIDTH, SKETCH_DEFAULT_HEIGHT};
    selectProfiles.video.format_ = CAMERA_FORMAT_YUV_420_SP;
    selectProfiles.video.framerates_ = {MAX_FRAME_RATE, MAX_FRAME_RATE};
    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::VIDEO_MACRO);
    ASSERT_NE(outputCapability, nullptr);
    auto photoProfiles = outputCapability->GetPhotoProfiles();
    ASSERT_FALSE(photoProfiles.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::VIDEO_MACRO);
    auto macroVideoSession = static_cast<MacroVideoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(macroVideoSession, nullptr);
    int32_t res = macroVideoSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = macroVideoSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(selectProfiles.preview);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(macroVideoSession->CanAddOutput(previewOutput));
    res = macroVideoSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoProfiles[0]);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_TRUE(macroVideoSession->CanAddOutput(photoOutput));
    res = macroVideoSession->AddOutput(photoOutput);
    EXPECT_EQ(res, 0);

    bool isSketchSupported = ((sptr<PreviewOutput>&)previewOutput)->IsSketchSupported();
    if (!isSketchSupported) {
        GTEST_SKIP();
    }
    res = ((sptr<PreviewOutput>&)previewOutput)->EnableSketch(true);
    EXPECT_EQ(res, 0);

    res = macroVideoSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = macroVideoSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);

    EXPECT_GT(((sptr<PreviewOutput>&)previewOutput)->GetSketchRatio(), 0);
    EXPECT_EQ(((sptr<PreviewOutput>&)previewOutput)->AttachSketchSurface(
        CreateSketchSurface(selectProfiles.preview.GetCameraFormat())), 0);
    sleep(WAIT_TIME_AFTER_ATTACH_SKETCH);

    res = static_cast<PhotoOutput*>(photoOutput.GetRefPtr())->Capture();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);
    res = macroVideoSession->Stop();
    EXPECT_EQ(res, 0);
    res = macroVideoSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test macro video session with video output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can add video output into macro video session
 */
HWTEST_F(CameraSessionModuleTest, macro_video_session_moduletest_002, TestSize.Level0)
{
    if (!IsSceneModeSupported(SceneMode::VIDEO_MACRO)) {
        GTEST_SKIP();
    }

    auto previewProfile = GetSketchPreviewProfile();
    if (previewProfile == nullptr) {
        EXPECT_EQ(previewProfile.get(), nullptr);
        GTEST_SKIP();
    }
    SelectProfiles selectProfiles;
    selectProfiles.preview.size_ = {SKETCH_DEFAULT_WIDTH, SKETCH_DEFAULT_HEIGHT};
    selectProfiles.preview.format_ = CAMERA_FORMAT_YUV_420_SP;
    selectProfiles.photo.size_ = {SKETCH_DEFAULT_WIDTH, SKETCH_DEFAULT_HEIGHT};
    selectProfiles.photo.format_ = CAMERA_FORMAT_YUV_420_SP;
    selectProfiles.video.size_ = {SKETCH_DEFAULT_WIDTH, SKETCH_DEFAULT_HEIGHT};
    selectProfiles.video.format_ = CAMERA_FORMAT_YUV_420_SP;
    selectProfiles.video.framerates_ = {MAX_FRAME_RATE, MAX_FRAME_RATE};

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::VIDEO_MACRO);
    auto macroVideoSession = static_cast<MacroVideoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(macroVideoSession, nullptr);
    int32_t res = macroVideoSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = macroVideoSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(selectProfiles.preview);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(macroVideoSession->CanAddOutput(previewOutput));
    res = macroVideoSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(selectProfiles.video);
    ASSERT_NE(videoOutput, nullptr);
    EXPECT_TRUE(macroVideoSession->CanAddOutput(videoOutput));
    res = macroVideoSession->AddOutput(videoOutput);
    EXPECT_EQ(res, 0);

    bool isSketchSupported = ((sptr<PreviewOutput>&)previewOutput)->IsSketchSupported();
    if (!isSketchSupported) {
        GTEST_SKIP();
    }
    res = ((sptr<PreviewOutput>&)previewOutput)->EnableSketch(true);
    EXPECT_EQ(res, 0);

    res = macroVideoSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = macroVideoSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);

    EXPECT_GT(((sptr<PreviewOutput>&)previewOutput)->GetSketchRatio(), 0);
    EXPECT_EQ(((sptr<PreviewOutput>&)previewOutput)->AttachSketchSurface(
        CreateSketchSurface(selectProfiles.preview.GetCameraFormat())), 0);
    sleep(WAIT_TIME_AFTER_ATTACH_SKETCH);

    res = static_cast<VideoOutput*>(videoOutput.GetRefPtr())->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);
    res = static_cast<VideoOutput*>(videoOutput.GetRefPtr())->Stop();
    EXPECT_EQ(res, 0);
    res = macroVideoSession->Stop();
    EXPECT_EQ(res, 0);
    res = macroVideoSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test macro video session with CreateCaptureSessionForSys
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test macro video session with CreateCaptureSessionForSys
 */
HWTEST_F(CameraSessionModuleTest, macro_video_session_moduletest_003, TestSize.Level1)
{
    SceneMode mode = SceneMode::VIDEO_MACRO;
    sptr<CameraManager> modeManagerObj = CameraManager::GetInstance();
    ASSERT_NE(modeManagerObj, nullptr);

    sptr<CaptureSessionForSys> captureSession = managerForSys_->CreateCaptureSessionForSys(mode);
    ASSERT_NE(captureSession, nullptr);
}

/*
 * Feature: Framework
 * Function: Test panorama session with photo output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can not add photo output into panorama session
 */
HWTEST_F(CameraSessionModuleTest, panorama_session_moduletest_001, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::PANORAMA_PHOTO)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::PANORAMA_PHOTO);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto photoProfiles = outputCapability->GetPhotoProfiles();
    ASSERT_TRUE(photoProfiles.empty());
    auto outputCapabilityBase = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::CAPTURE);
    ASSERT_NE(outputCapabilityBase, nullptr);
    auto photoProfilesBase = outputCapabilityBase->GetPhotoProfiles();
    ASSERT_FALSE(photoProfilesBase.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::PANORAMA_PHOTO);
    auto panoramaSession = static_cast<PanoramaSession*>(captureSession.GetRefPtr());
    ASSERT_NE(panoramaSession, nullptr);
    int32_t res = panoramaSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = panoramaSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(panoramaSession->CanAddOutput(previewOutput));
    res = panoramaSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoProfilesBase[0]);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_FALSE(panoramaSession->CanAddOutput(photoOutput));
}

/*
 * Feature: Framework
 * Function: Test panorama session with video output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can not add video output into panorama session
 */
HWTEST_F(CameraSessionModuleTest, panorama_session_moduletest_002, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::PANORAMA_PHOTO)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::PANORAMA_PHOTO);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto videoProfiles = outputCapability->GetVideoProfiles();
    ASSERT_TRUE(videoProfiles.empty());
    auto outputCapabilityBase = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::VIDEO);
    ASSERT_NE(outputCapabilityBase, nullptr);
    auto videoProfilesBase = outputCapabilityBase->GetVideoProfiles();
    ASSERT_FALSE(videoProfilesBase.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::PANORAMA_PHOTO);
    auto panoramaSession = static_cast<PanoramaSession*>(captureSession.GetRefPtr());
    ASSERT_NE(panoramaSession, nullptr);
    int32_t res = panoramaSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = panoramaSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(panoramaSession->CanAddOutput(previewOutput));
    res = panoramaSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfilesBase[0]);
    ASSERT_NE(videoOutput, nullptr);
    EXPECT_FALSE(panoramaSession->CanAddOutput(videoOutput));
}

/*
 * Feature: Framework
 * Function: Test panorama session with preview output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can add preview output into panorama session
 */
HWTEST_F(CameraSessionModuleTest, panorama_session_moduletest_003, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::PANORAMA_PHOTO)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::PANORAMA_PHOTO);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::PANORAMA_PHOTO);
    auto panoramaSession = static_cast<PanoramaSession*>(captureSession.GetRefPtr());
    ASSERT_NE(panoramaSession, nullptr);
    int32_t res = panoramaSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = panoramaSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(panoramaSession->CanAddOutput(previewOutput));
    res = panoramaSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);

    res = panoramaSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = panoramaSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);
    res = panoramaSession->Stop();
    EXPECT_EQ(res, 0);
    res = panoramaSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test portrait session with photo output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can add photo output into portrait session
 */
HWTEST_F(CameraSessionModuleTest, portrait_session_moduletest_001, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::PORTRAIT)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::PORTRAIT);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto photoProfiles = outputCapability->GetPhotoProfiles();
    ASSERT_FALSE(photoProfiles.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::PORTRAIT);
    auto portraitSession = static_cast<PortraitSession*>(captureSession.GetRefPtr());
    ASSERT_NE(portraitSession, nullptr);
    int32_t res = portraitSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = portraitSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(portraitSession->CanAddOutput(previewOutput));
    res = portraitSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoProfiles[0]);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_TRUE(portraitSession->CanAddOutput(photoOutput));
    res = portraitSession->AddOutput(photoOutput);
    EXPECT_EQ(res, 0);

    res = portraitSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = portraitSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);
    res = static_cast<PhotoOutput*>(photoOutput.GetRefPtr())->Capture();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);
    res = portraitSession->Stop();
    EXPECT_EQ(res, 0);
    res = portraitSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test portrait session with video output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can not add video output into portrait session
 */
HWTEST_F(CameraSessionModuleTest, portrait_session_moduletest_002, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::PORTRAIT)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::PORTRAIT);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto videoProfiles = outputCapability->GetVideoProfiles();
    ASSERT_TRUE(videoProfiles.empty());
    auto outputCapabilityBase = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::VIDEO);
    ASSERT_NE(outputCapabilityBase, nullptr);
    auto videoProfilesBase = outputCapabilityBase->GetVideoProfiles();
    ASSERT_FALSE(videoProfilesBase.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::PORTRAIT);
    auto portraitSession = static_cast<PortraitSession*>(captureSession.GetRefPtr());
    ASSERT_NE(portraitSession, nullptr);
    int32_t res = portraitSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = portraitSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(portraitSession->CanAddOutput(previewOutput));
    res = portraitSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfilesBase[0]);
    ASSERT_NE(videoOutput, nullptr);
    EXPECT_FALSE(portraitSession->CanAddOutput(videoOutput));
}

/*
 * Feature: Framework
 * Function: Test portrait session get portrait effect
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can get portrait effect from portrait session
 */
HWTEST_F(CameraSessionModuleTest, portrait_session_moduletest_003, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::PORTRAIT)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::PORTRAIT);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto photoProfiles = outputCapability->GetPhotoProfiles();
    ASSERT_FALSE(photoProfiles.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::PORTRAIT);
    auto portraitSession = static_cast<PortraitSession*>(captureSession.GetRefPtr());
    ASSERT_NE(portraitSession, nullptr);
    int32_t res = portraitSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = portraitSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(portraitSession->CanAddOutput(previewOutput));
    res = portraitSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoProfiles[0]);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_TRUE(portraitSession->CanAddOutput(photoOutput));
    res = portraitSession->AddOutput(photoOutput);
    EXPECT_EQ(res, 0);

    res = portraitSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = portraitSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);

    std::vector<PortraitEffect> effects = portraitSession->GetSupportedPortraitEffects();
    if (!effects.empty()) {
        EXPECT_EQ(portraitSession->GetPortraitEffect(), effects[0]);
    }

    res = static_cast<PhotoOutput*>(photoOutput.GetRefPtr())->Capture();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);
    res = portraitSession->Stop();
    EXPECT_EQ(res, 0);
    res = portraitSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test portrait session set portrait effect
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can set portrait effect into portrait session
 */
HWTEST_F(CameraSessionModuleTest, portrait_session_moduletest_004, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::PORTRAIT)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::PORTRAIT);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto photoProfiles = outputCapability->GetPhotoProfiles();
    ASSERT_FALSE(photoProfiles.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::PORTRAIT);
    auto portraitSession = static_cast<PortraitSession*>(captureSession.GetRefPtr());
    ASSERT_NE(portraitSession, nullptr);
    int32_t res = portraitSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = portraitSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(portraitSession->CanAddOutput(previewOutput));
    res = portraitSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoProfiles[0]);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_TRUE(portraitSession->CanAddOutput(photoOutput));
    res = portraitSession->AddOutput(photoOutput);
    EXPECT_EQ(res, 0);

    res = portraitSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = portraitSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);

    std::vector<PortraitEffect> effects = portraitSession->GetSupportedPortraitEffects();
    if (!effects.empty()) {
        portraitSession->LockForControl();
        portraitSession->SetPortraitEffect(effects[0]);
        portraitSession->UnlockForControl();
        EXPECT_EQ(portraitSession->GetPortraitEffect(), effects[0]);
    }

    res = static_cast<PhotoOutput*>(photoOutput.GetRefPtr())->Capture();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);
    res = portraitSession->Stop();
    EXPECT_EQ(res, 0);
    res = portraitSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test portrait session get portrait filter
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can get portrait filter from portrait session
 */
HWTEST_F(CameraSessionModuleTest, portrait_session_moduletest_005, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::PORTRAIT)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::PORTRAIT);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto photoProfiles = outputCapability->GetPhotoProfiles();
    ASSERT_FALSE(photoProfiles.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::PORTRAIT);
    auto portraitSession = static_cast<PortraitSession*>(captureSession.GetRefPtr());
    ASSERT_NE(portraitSession, nullptr);
    int32_t res = portraitSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = portraitSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(portraitSession->CanAddOutput(previewOutput));
    res = portraitSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoProfiles[0]);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_TRUE(portraitSession->CanAddOutput(photoOutput));
    res = portraitSession->AddOutput(photoOutput);
    EXPECT_EQ(res, 0);

    res = portraitSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = portraitSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);

    std::vector<FilterType> filterLists = portraitSession->GetSupportedFilters();
    if (!filterLists.empty()) {
        EXPECT_EQ(portraitSession->GetFilter(), filterLists[0]);
    }

    res = static_cast<PhotoOutput*>(photoOutput.GetRefPtr())->Capture();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);
    res = portraitSession->Stop();
    EXPECT_EQ(res, 0);
    res = portraitSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test portrait session set portrait filter
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can set portrait filter into portrait session
 */
HWTEST_F(CameraSessionModuleTest, portrait_session_moduletest_006, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::PORTRAIT)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::PORTRAIT);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto photoProfiles = outputCapability->GetPhotoProfiles();
    ASSERT_FALSE(photoProfiles.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::PORTRAIT);
    auto portraitSession = static_cast<PortraitSession*>(captureSession.GetRefPtr());
    ASSERT_NE(portraitSession, nullptr);
    int32_t res = portraitSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = portraitSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(portraitSession->CanAddOutput(previewOutput));
    res = portraitSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoProfiles[0]);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_TRUE(portraitSession->CanAddOutput(photoOutput));
    res = portraitSession->AddOutput(photoOutput);
    EXPECT_EQ(res, 0);

    res = portraitSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = portraitSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);

    std::vector<FilterType> filterLists = portraitSession->GetSupportedFilters();
    if (!filterLists.empty()) {
        portraitSession->LockForControl();
        portraitSession->SetFilter(filterLists[0]);
        portraitSession->UnlockForControl();
        EXPECT_EQ(portraitSession->GetFilter(), filterLists[0]);
    }

    res = static_cast<PhotoOutput*>(photoOutput.GetRefPtr())->Capture();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);
    res = portraitSession->Stop();
    EXPECT_EQ(res, 0);
    res = portraitSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test portrait session photo ability function
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test portrait session photo ability function
 */
HWTEST_F(CameraSessionModuleTest, portrait_session_moduletest_007, TestSize.Level1)
{
    SceneMode portraitMode = SceneMode::PORTRAIT;
    if (!IsSceneModeSupported(portraitMode)) {
        GTEST_SKIP();
    }

    sptr<CameraManager> cameraMgr = CameraManager::GetInstance();
    ASSERT_NE(cameraMgr, nullptr);

    sptr<CameraOutputCapability> capability = cameraMgr->GetSupportedOutputCapability(cameras_[0], portraitMode);
    ASSERT_NE(capability, nullptr);

    sptr<CaptureSession> captureSession = managerForSys_->CreateCaptureSessionForSys(portraitMode);
    ASSERT_NE(captureSession, nullptr);

    sptr<PortraitSession> portraitSession = static_cast<PortraitSession *>(captureSession.GetRefPtr());
    ASSERT_NE(portraitSession, nullptr);

    std::vector<sptr<CameraOutputCapability>> cocList = portraitSession->GetCameraOutputCapabilities(cameras_[0]);
    ASSERT_TRUE(cocList.size() != 0);
    auto previewProfiles = cocList[0]->GetPreviewProfiles();
    auto photoProfiles = cocList[0]->GetPhotoProfiles();
    auto videoProfiles = cocList[0]->GetVideoProfiles();

    int32_t intResult = portraitSession->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = portraitSession->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    intResult = portraitSession->AddOutput(photoOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    intResult = portraitSession->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    intResult = portraitSession->CommitConfig();
    EXPECT_EQ(intResult, 0);

    auto portraitFunctions = portraitSession->GetSessionFunctions(previewProfiles, photoProfiles, videoProfiles, true);
    ASSERT_TRUE(portraitFunctions.size() != 0);
    auto portraitFunction = portraitFunctions[0];
    portraitFunction->GetSupportedPortraitEffects();
    portraitFunction->GetSupportedVirtualApertures();
    portraitFunction->GetSupportedPhysicalApertures();
    std::vector<sptr<CameraAbility>> portraitConflictFunctionsList = portraitSession->GetSessionConflictFunctions();
}

/*
 * Feature: Framework
 * Function: Test portrait session !IsSessionCommited() && !IsSessionConfiged()
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test portrait session !IsSessionCommited() && !IsSessionConfiged()
 */
HWTEST_F(CameraSessionModuleTest, portrait_session_moduletest_008, TestSize.Level1)
{
    ColorSpace colorSpace = COLOR_SPACE_UNKNOWN;
    int32_t intResult = sessionForSys_->BeginConfig();
    EXPECT_EQ(intResult, 0);
    intResult = sessionForSys_->AddInput(input_);
    EXPECT_EQ(intResult, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    intResult = sessionForSys_->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);
    sessionForSys_->SetMode(SceneMode::PORTRAIT);
    EXPECT_EQ(sessionForSys_->VerifyAbility(0), CAMERA_INVALID_ARG);
    EXPECT_EQ(sessionForSys_->GetActiveColorSpace(colorSpace), CAMERA_OK);
    sessionForSys_->SetColorEffect(COLOR_EFFECT_NORMAL);
    intResult = sessionForSys_->CommitConfig();
    EXPECT_EQ(intResult, 0);
    if (sessionForSys_->IsMacroSupported()) {
        sessionForSys_->LockForControl();
        intResult = sessionForSys_->EnableMacro(false);
        sessionForSys_->UnlockForControl();
        EXPECT_EQ(intResult, 0);
    }
    EXPECT_EQ(sessionForSys_->GetActiveColorSpace(colorSpace), CAMERA_OK);
    sessionForSys_->SetColorEffect(COLOR_EFFECT_NORMAL);
    sessionForSys_->innerInputDevice_ = nullptr;
    EXPECT_EQ(sessionForSys_->VerifyAbility(0), CAMERA_INVALID_ARG);
    EXPECT_EQ(sessionForSys_->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test portrait session abnormal branches
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test portrait session abnormal branches
 */
HWTEST_F(CameraSessionModuleTest, portrait_session_moduletest_009, TestSize.Level1)
{
    SceneMode portraitMode = SceneMode::PORTRAIT;
    sptr<CaptureSessionForSys> captureSession = managerForSys_->CreateCaptureSessionForSys(portraitMode);
    auto portraitSession = static_cast<PortraitSession*>(captureSession.GetRefPtr());
    ASSERT_NE(portraitSession, nullptr);
    EXPECT_EQ(portraitSession->GetSupportedPortraitEffects().empty(), true);
    EXPECT_EQ(portraitSession->GetPortraitEffect(), OFF_EFFECT);
    portraitSession->SetPortraitEffect(OFF_EFFECT);
    int32_t intResult = portraitSession->BeginConfig();
    EXPECT_EQ(intResult, 0);
    EXPECT_EQ(portraitSession->GetSupportedPortraitEffects().empty(), true);
    EXPECT_EQ(portraitSession->GetPortraitEffect(), OFF_EFFECT);
    portraitSession->SetPortraitEffect(OFF_EFFECT);
    portraitSession->Release();
}

/*
 * Feature: Framework
 * Function: Test portrait session nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test portrait session nullptr
 */
HWTEST_F(CameraSessionModuleTest, portrait_session_moduletest_010, TestSize.Level1)
{
    SceneMode portraitMode = SceneMode::PORTRAIT;
    sptr<CaptureSession> captureSession = managerForSys_->CreateCaptureSessionForSys(portraitMode);
    auto portraitSession = static_cast<PortraitSession*>(captureSession.GetRefPtr());
    ASSERT_NE(portraitSession, nullptr);
    EXPECT_EQ(portraitSession->GetSupportedPortraitEffects().empty(), true);
    EXPECT_EQ(portraitSession->GetPortraitEffect(), OFF_EFFECT);
    portraitSession->SetPortraitEffect(OFF_EFFECT);
    portraitSession->Release();
}

/*
 * Feature: Framework
 * Function: Test quick shot photo session with photo output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can add photo output into quick shot photo session
 */
HWTEST_F(CameraSessionModuleTest, quick_shot_photo_session_moduletest_001, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::QUICK_SHOT_PHOTO)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::QUICK_SHOT_PHOTO);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    Profile previewProfile = previewProfiles[0];
    previewProfile.size_.width = 1920;
    previewProfile.size_.height = 1440;
    ASSERT_FALSE(previewProfiles.empty());
    auto photoProfiles = outputCapability->GetPhotoProfiles();
    Profile photoProfile = photoProfiles[0];
    photoProfile.size_.width = 4096;
    photoProfile.size_.height = 3072;
    ASSERT_FALSE(photoProfiles.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::QUICK_SHOT_PHOTO);
    auto quickShotPhotoSession = static_cast<QuickShotPhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(quickShotPhotoSession, nullptr);
    int32_t res = quickShotPhotoSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = quickShotPhotoSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfile);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(quickShotPhotoSession->CanAddOutput(previewOutput));
    res = quickShotPhotoSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoProfile);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_TRUE(quickShotPhotoSession->CanAddOutput(photoOutput));
    res = quickShotPhotoSession->AddOutput(photoOutput);
    EXPECT_EQ(res, 0);

    res = quickShotPhotoSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = quickShotPhotoSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);
    res = static_cast<PhotoOutput*>(photoOutput.GetRefPtr())->Capture();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);
    res = quickShotPhotoSession->Stop();
    EXPECT_EQ(res, 0);
    res = quickShotPhotoSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test quick shot photo session with video output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can not add video output into quick shot photo session
 */
HWTEST_F(CameraSessionModuleTest, quick_shot_photo_session_moduletest_002, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::QUICK_SHOT_PHOTO)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::QUICK_SHOT_PHOTO);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto videoProfiles = outputCapability->GetVideoProfiles();
    ASSERT_TRUE(videoProfiles.empty());
    auto outputCapabilityBase = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::VIDEO);
    ASSERT_NE(outputCapabilityBase, nullptr);
    auto videoProfilesBase = outputCapabilityBase->GetVideoProfiles();
    ASSERT_FALSE(videoProfilesBase.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::QUICK_SHOT_PHOTO);
    auto quickShotPhotoSession = static_cast<QuickShotPhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(quickShotPhotoSession, nullptr);
    int32_t res = quickShotPhotoSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = quickShotPhotoSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(quickShotPhotoSession->CanAddOutput(previewOutput));
    res = quickShotPhotoSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfilesBase[0]);
    ASSERT_NE(videoOutput, nullptr);
    EXPECT_FALSE(quickShotPhotoSession->CanAddOutput(videoOutput));
    input->Close();
}

/*
 * Feature: Framework
 * Function: Test scan session with photo output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can not add photo output into scan session
 */
HWTEST_F(CameraSessionModuleTest, scan_session_moduletest_001, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::SCAN)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::SCAN);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto photoProfiles = outputCapability->GetPhotoProfiles();
    ASSERT_TRUE(photoProfiles.empty());
    auto outputCapabilityBase = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::CAPTURE);
    ASSERT_NE(outputCapabilityBase, nullptr);
    auto photoProfilesBase = outputCapabilityBase->GetPhotoProfiles();
    ASSERT_FALSE(photoProfilesBase.empty());

    auto captureSession = manager_->CreateCaptureSession(SceneMode::SCAN);
    auto scanSession = static_cast<ScanSession*>(captureSession.GetRefPtr());
    ASSERT_NE(scanSession, nullptr);
    int32_t res = scanSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = scanSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(scanSession->CanAddOutput(previewOutput));
    res = scanSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoProfilesBase[0]);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_FALSE(scanSession->CanAddOutput(photoOutput));
    input->Close();
}

/*
 * Feature: Framework
 * Function: Test scan session with video output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can not add video output into scan session
 */
HWTEST_F(CameraSessionModuleTest, scan_session_moduletest_002, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::SCAN)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::SCAN);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto videoProfiles = outputCapability->GetVideoProfiles();
    ASSERT_TRUE(videoProfiles.empty());
    auto outputCapabilityBase = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::VIDEO);
    ASSERT_NE(outputCapabilityBase, nullptr);
    auto videoProfilesBase = outputCapabilityBase->GetVideoProfiles();
    ASSERT_FALSE(videoProfilesBase.empty());

    auto captureSession = manager_->CreateCaptureSession(SceneMode::SCAN);
    auto scanSession = static_cast<ScanSession*>(captureSession.GetRefPtr());
    ASSERT_NE(scanSession, nullptr);
    int32_t res = scanSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = scanSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(scanSession->CanAddOutput(previewOutput));
    res = scanSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfilesBase[0]);
    ASSERT_NE(videoOutput, nullptr);
    EXPECT_FALSE(scanSession->CanAddOutput(videoOutput));
    input->Close();
}

/*
 * Feature: Framework
 * Function: Test scan session with preview output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can add preview output into scan session
 */
HWTEST_F(CameraSessionModuleTest, scan_session_moduletest_003, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::SCAN)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::SCAN);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());

    auto captureSession = manager_->CreateCaptureSession(SceneMode::SCAN);
    auto scanSession = static_cast<ScanSession*>(captureSession.GetRefPtr());
    ASSERT_NE(scanSession, nullptr);
    int32_t res = scanSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = scanSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(scanSession->CanAddOutput(previewOutput));
    res = scanSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);

    res = scanSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = scanSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);
    res = scanSession->Stop();
    EXPECT_EQ(res, 0);
    res = scanSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test scan session set focus mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test scan session set focus mode
 */
HWTEST_F(CameraSessionModuleTest, scan_session_moduletest_004, TestSize.Level1)
{
    if (!IsSupportNow()) {
        GTEST_SKIP();
    }
    sptr<CaptureOutput> previewOutput_1;
    sptr<CaptureOutput> previewOutput_2;
    ConfigScanSession(previewOutput_1, previewOutput_2);

    scanSession_->LockForControl();
    int32_t setFocusMode = scanSession_->SetFocusMode(FOCUS_MODE_AUTO);
    EXPECT_EQ(setFocusMode, 0);
    scanSession_->UnlockForControl();

    FocusMode focusMode = scanSession_->GetFocusMode();
    EXPECT_NE(focusMode, FOCUS_MODE_MANUAL);
    EXPECT_NE(focusMode, FOCUS_MODE_CONTINUOUS_AUTO);
    EXPECT_EQ(focusMode, FOCUS_MODE_AUTO);
    EXPECT_NE(focusMode, FOCUS_MODE_LOCKED);

    int32_t getFoucusMode = scanSession_->GetFocusMode(focusMode);
    EXPECT_EQ(getFoucusMode, 0);
    EXPECT_EQ(focusMode, FOCUS_MODE_AUTO);

    bool isSupported = scanSession_->IsFocusModeSupported(focusMode);
    EXPECT_EQ(isSupported, true);

    int32_t isFocusSupported = scanSession_->IsFocusModeSupported(focusMode, isSupported);
    EXPECT_EQ(isFocusSupported, 0);
    EXPECT_EQ(isSupported, true);

    std::vector<FocusMode> supportedFocusModes = scanSession_->GetSupportedFocusModes();
    EXPECT_EQ(supportedFocusModes.empty(), false);

    int32_t getSupportedFocusModes = scanSession_->GetSupportedFocusModes(supportedFocusModes);
    EXPECT_EQ(supportedFocusModes.empty(), false);
    EXPECT_EQ(getSupportedFocusModes, 0);

    ((sptr<PreviewOutput> &) previewOutput_1)->Release();
    ((sptr<PreviewOutput> &) previewOutput_2)->Release();
}

/*
 * Feature: Framework
 * Function: Test scan session set focus point
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test scan session set focus point
 */
HWTEST_F(CameraSessionModuleTest, scan_session_moduletest_005, TestSize.Level1)
{
    if (!IsSupportNow()) {
        GTEST_SKIP();
    }
    sptr<CaptureOutput> previewOutput_1;
    sptr<CaptureOutput> previewOutput_2;
    ConfigScanSession(previewOutput_1, previewOutput_2);

    Point point = { 1, 1 };
    scanSession_->LockForControl();
    int32_t setFocusMode = scanSession_->SetFocusPoint(point);
    EXPECT_EQ(setFocusMode, 0);
    scanSession_->UnlockForControl();

    Point focusPointGet = scanSession_->GetFocusPoint();
    EXPECT_EQ(focusPointGet.x, 1);
    EXPECT_EQ(focusPointGet.y, 1);

    float focalLength;
    int32_t focalLengthGet = scanSession_->GetFocalLength(focalLength);
    EXPECT_EQ(focalLengthGet, 0);

    ((sptr<PreviewOutput> &) previewOutput_1)->Release();
    ((sptr<PreviewOutput> &) previewOutput_2)->Release();
}

/*
 * Feature: Framework
 * Function: Test scan session set zoom ratio
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test scan session set zoom ratio
 */
HWTEST_F(CameraSessionModuleTest, scan_session_moduletest_006, TestSize.Level1)
{
    if (!IsSupportNow()) {
        GTEST_SKIP();
    }
    sptr<CaptureOutput> previewOutput_1;
    sptr<CaptureOutput> previewOutput_2;
    ConfigScanSession(previewOutput_1, previewOutput_2);

    scanSession_->LockForControl();
    int32_t zoomRatioSet = scanSession_->SetZoomRatio(ZOOM_RATIO);
    EXPECT_EQ(zoomRatioSet, 0);
    scanSession_->UnlockForControl();

    std::vector<float> zoomRatioRange = scanSession_->GetZoomRatioRange();
    EXPECT_EQ(zoomRatioRange.empty(), false);

    int32_t zoomRatioRangeGet = scanSession_->GetZoomRatioRange(zoomRatioRange);
    EXPECT_EQ(zoomRatioRange.empty(), false);
    EXPECT_EQ(zoomRatioRangeGet, 0);

    float zoomRatio = scanSession_->GetZoomRatio();
    int32_t zoomRatioGet = scanSession_->GetZoomRatio(zoomRatio);
    EXPECT_EQ(zoomRatioGet, 0);

    ((sptr<PreviewOutput> &) previewOutput_1)->Release();
    ((sptr<PreviewOutput> &) previewOutput_2)->Release();
}

/*
 * Feature: Framework
 * Function: Test scan session report brightness status
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test scan session report brightness status
 */
HWTEST_F(CameraSessionModuleTest, scan_session_moduletest_007, TestSize.Level1)
{
    if (!IsSupportNow()) {
        GTEST_SKIP();
    }
    sptr<CaptureOutput> previewOutput_1;
    sptr<CaptureOutput> previewOutput_2;
    ConfigScanSession(previewOutput_1, previewOutput_2);

    auto scanSession = static_cast<ScanSession*>(scanSession_.GetRefPtr());
    bool isSupported = scanSession->IsBrightnessStatusSupported();
    EXPECT_EQ(isSupported, true);

    std::shared_ptr<AppCallback> callback = std::make_shared<AppCallback>();
    scanSession->RegisterBrightnessStatusCallback(callback);
    {
        TestLogDetector detector(true);
        int32_t intResult = scanSession->Start();
        EXPECT_EQ(intResult, 0);

        sleep(WAIT_TIME_ONE);
        if (!detector.IsLogContains("ScanSession::ProcessBrightnessStatusChange get brightness status failed")) {
            EXPECT_EQ(g_brightnessStatusChanged, true);
        }
    }
    scanSession->UnRegisterBrightnessStatusCallback();
    int32_t intResult = scanSession->Stop();
    EXPECT_EQ(intResult, 0);

    ((sptr<PreviewOutput> &) previewOutput_1)->Release();
    ((sptr<PreviewOutput> &) previewOutput_2)->Release();
}

/*
 * Feature: Framework
 * Function: Test scan session with CreateCaptureSession
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test scan session with CreateCaptureSession
 */
HWTEST_F(CameraSessionModuleTest, scan_session_moduletest_008, TestSize.Level1)
{
    SceneMode mode = SceneMode::SCAN;
    sptr<CameraManager> modeManagerObj = CameraManager::GetInstance();
    ASSERT_NE(modeManagerObj, nullptr);

    sptr<CaptureSession> captureSession = modeManagerObj->CreateCaptureSession(mode);
    ASSERT_NE(captureSession, nullptr);
}

/*
 * Feature: Framework
 * Function: Test secure camera session with photo output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can not add photo output into secure camera session
 */
HWTEST_F(CameraSessionModuleTest, secure_camera_session_moduletest_001, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::SECURE)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::SECURE);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto photoProfiles = outputCapability->GetPhotoProfiles();
    ASSERT_TRUE(photoProfiles.empty());
    auto outputCapabilityBase = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::CAPTURE);
    ASSERT_NE(outputCapabilityBase, nullptr);
    auto photoProfilesBase = outputCapabilityBase->GetPhotoProfiles();
    ASSERT_FALSE(photoProfilesBase.empty());

    auto captureSession = manager_->CreateCaptureSession(SceneMode::SECURE);
    auto secureCameraSession = static_cast<SecureCameraSession*>(captureSession.GetRefPtr());
    ASSERT_NE(secureCameraSession, nullptr);
    int32_t res = secureCameraSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = secureCameraSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(secureCameraSession->CanAddOutput(previewOutput));
    res = secureCameraSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoProfilesBase[0]);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_FALSE(secureCameraSession->CanAddOutput(photoOutput));
}

/*
 * Feature: Framework
 * Function: Test secure camera session with video output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can not add video output into secure camera session
 */
HWTEST_F(CameraSessionModuleTest, secure_camera_session_moduletest_002, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::SECURE)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::SECURE);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto videoProfiles = outputCapability->GetVideoProfiles();
    ASSERT_TRUE(videoProfiles.empty());
    auto outputCapabilityBase = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::VIDEO);
    ASSERT_NE(outputCapabilityBase, nullptr);
    auto videoProfilesBase = outputCapabilityBase->GetVideoProfiles();
    ASSERT_FALSE(videoProfilesBase.empty());

    auto captureSession = manager_->CreateCaptureSession(SceneMode::SECURE);
    auto secureCameraSession = static_cast<SecureCameraSession*>(captureSession.GetRefPtr());
    ASSERT_NE(secureCameraSession, nullptr);
    int32_t res = secureCameraSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = secureCameraSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(secureCameraSession->CanAddOutput(previewOutput));
    res = secureCameraSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfilesBase[0]);
    ASSERT_NE(videoOutput, nullptr);
    EXPECT_FALSE(secureCameraSession->CanAddOutput(videoOutput));
}

/*
 * Feature: Framework
 * Function: Test secure camera session with preview output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can add preview output into secure camera session
 */
HWTEST_F(CameraSessionModuleTest, secure_camera_session_moduletest_003, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::SECURE)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::SECURE);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());

    auto captureSession = manager_->CreateCaptureSession(SceneMode::SECURE);
    auto secureCameraSession = static_cast<SecureCameraSession*>(captureSession.GetRefPtr());
    ASSERT_NE(secureCameraSession, nullptr);
    int32_t res = secureCameraSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = secureCameraSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(secureCameraSession->CanAddOutput(previewOutput));
    res = secureCameraSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    res = secureCameraSession->AddSecureOutput(previewOutput);
    EXPECT_EQ(res, 0);

    res = secureCameraSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = secureCameraSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);
    res = secureCameraSession->Stop();
    EXPECT_EQ(res, 0);
    res = secureCameraSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test slow motion session with photo output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can not add photo output into slow motion session
 */
HWTEST_F(CameraSessionModuleTest, slow_motion_session_moduletest_001, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::SLOW_MOTION)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::SLOW_MOTION);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto photoProfiles = outputCapability->GetPhotoProfiles();
    ASSERT_TRUE(photoProfiles.empty());
    auto outputCapabilityBase = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::CAPTURE);
    ASSERT_NE(outputCapabilityBase, nullptr);
    auto photoProfilesBase = outputCapabilityBase->GetPhotoProfiles();
    ASSERT_FALSE(photoProfilesBase.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::SLOW_MOTION);
    auto slowMotionSession = static_cast<SlowMotionSession*>(captureSession.GetRefPtr());
    ASSERT_NE(slowMotionSession, nullptr);
    int32_t res = slowMotionSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = slowMotionSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(slowMotionSession->CanAddOutput(previewOutput));
    res = slowMotionSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoProfilesBase[0]);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_FALSE(slowMotionSession->CanAddOutput(photoOutput));
}

/*
 * Feature: Framework
 * Function: Test slow motion session with video output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can add video output into slow motion session
 */
HWTEST_F(CameraSessionModuleTest, slow_motion_session_moduletest_002, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::SLOW_MOTION)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::SLOW_MOTION);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    Profile previewProfile = previewProfiles[0];
    previewProfile.size_.width = 1920;
    previewProfile.size_.height = 1080;
    ASSERT_FALSE(previewProfiles.empty());
    auto videoProfiles = outputCapability->GetVideoProfiles();
    VideoProfile videoProfile = videoProfiles[0];
    videoProfile.size_.width = 1920;
    videoProfile.size_.height = 1080;
    ASSERT_FALSE(videoProfiles.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::SLOW_MOTION);
    auto slowMotionSession = static_cast<SlowMotionSession*>(captureSession.GetRefPtr());
    ASSERT_NE(slowMotionSession, nullptr);
    int32_t res = slowMotionSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = slowMotionSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfile);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(slowMotionSession->CanAddOutput(previewOutput));
    res = slowMotionSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfile);
    ASSERT_NE(videoOutput, nullptr);
    EXPECT_TRUE(slowMotionSession->CanAddOutput(videoOutput));
    res = slowMotionSession->AddOutput(videoOutput);
    EXPECT_EQ(res, 0);

    res = slowMotionSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = slowMotionSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);
    res = static_cast<VideoOutput*>(videoOutput.GetRefPtr())->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);
    res = static_cast<VideoOutput*>(videoOutput.GetRefPtr())->Stop();
    EXPECT_EQ(res, 0);
    res = slowMotionSession->Stop();
    EXPECT_EQ(res, 0);
    res = slowMotionSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test slow motion session set slow motion detection area
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can set slow motion detection area into slow motion session
 */
HWTEST_F(CameraSessionModuleTest, slow_motion_session_moduletest_003, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::SLOW_MOTION)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::SLOW_MOTION);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    Profile previewProfile = previewProfiles[0];
    previewProfile.size_.width = 1920;
    previewProfile.size_.height = 1080;
    ASSERT_FALSE(previewProfiles.empty());
    auto videoProfiles = outputCapability->GetVideoProfiles();
    VideoProfile videoProfile = videoProfiles[0];
    videoProfile.size_.width = 1920;
    videoProfile.size_.height = 1080;
    ASSERT_FALSE(videoProfiles.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::SLOW_MOTION);
    auto slowMotionSession = static_cast<SlowMotionSession*>(captureSession.GetRefPtr());
    ASSERT_NE(slowMotionSession, nullptr);
    int32_t res = slowMotionSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = slowMotionSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfile);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(slowMotionSession->CanAddOutput(previewOutput));
    res = slowMotionSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfile);
    ASSERT_NE(videoOutput, nullptr);
    EXPECT_TRUE(slowMotionSession->CanAddOutput(videoOutput));
    res = slowMotionSession->AddOutput(videoOutput);
    EXPECT_EQ(res, 0);

    res = slowMotionSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = slowMotionSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);

    EXPECT_TRUE(slowMotionSession->IsSlowMotionDetectionSupported());
    Rect rect;
    rect.topLeftX = 0.1;
    rect.topLeftY = 0.1;
    rect.width = 0.8;
    rect.height = 0.8;
    slowMotionSession->SetSlowMotionDetectionArea(rect);
    sleep(WAIT_TIME_AFTER_SET_AREA);

    res = slowMotionSession->Stop();
    EXPECT_EQ(res, 0);
    res = slowMotionSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test slow motion session callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test slow motion session callback
 */
HWTEST_F(CameraSessionModuleTest, slow_motion_session_moduletest_004, TestSize.Level1)
{
    sptr<CaptureOutput> previewOutput;
    sptr<CaptureOutput> videoOutput;
    ConfigSlowMotionSession(previewOutput, videoOutput);
    ASSERT_NE(previewOutput, nullptr);
    ASSERT_NE(videoOutput, nullptr);

    if (slowMotionSession_->CanAddOutput(previewOutput)) {
        int32_t intResult = slowMotionSession_->AddOutput(previewOutput);
        EXPECT_EQ(intResult, 0);

        intResult = slowMotionSession_->CommitConfig();
        EXPECT_EQ(intResult, 0);

        sleep(WAIT_TIME_AFTER_START);
        intResult = slowMotionSession_->Start();
        EXPECT_EQ(intResult, 0);
    }
}

/*
 * Feature: Framework
 * Function: Test night session with photo output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can add photo output into night session
 */
HWTEST_F(CameraSessionModuleTest, night_session_moduletest_001, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::NIGHT)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::NIGHT);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto photoProfiles = outputCapability->GetPhotoProfiles();
    ASSERT_FALSE(photoProfiles.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::NIGHT);
    auto nightSession = static_cast<NightSession*>(captureSession.GetRefPtr());
    ASSERT_NE(nightSession, nullptr);
    int32_t res = nightSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = nightSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(nightSession->CanAddOutput(previewOutput));
    res = nightSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoProfiles[0]);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_TRUE(nightSession->CanAddOutput(photoOutput));
    res = nightSession->AddOutput(photoOutput);
    EXPECT_EQ(res, 0);

    res = nightSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = nightSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);
    res = static_cast<PhotoOutput*>(photoOutput.GetRefPtr())->Capture();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);
    res = nightSession->Stop();
    EXPECT_EQ(res, 0);
    res = nightSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test night session with video output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can not add video output into night session
 */
HWTEST_F(CameraSessionModuleTest, night_session_moduletest_002, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::NIGHT)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::NIGHT);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto videoProfiles = outputCapability->GetVideoProfiles();
    ASSERT_TRUE(videoProfiles.empty());
    auto outputCapabilityBase = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::VIDEO);
    ASSERT_NE(outputCapabilityBase, nullptr);
    auto videoProfilesBase = outputCapabilityBase->GetVideoProfiles();
    ASSERT_FALSE(videoProfilesBase.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::NIGHT);
    auto nightSession = static_cast<NightSession*>(captureSession.GetRefPtr());
    ASSERT_NE(nightSession, nullptr);
    int32_t res = nightSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = nightSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(nightSession->CanAddOutput(previewOutput));
    res = nightSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfilesBase[0]);
    ASSERT_NE(videoOutput, nullptr);
    EXPECT_FALSE(nightSession->CanAddOutput(videoOutput));
}

/*
 * Feature: Framework
 * Function: Test night session set exposure
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can set exposure into night session
 */
HWTEST_F(CameraSessionModuleTest, night_session_moduletest_003, TestSize.Level0)
{
    if (!IsSceneModeSupported(SceneMode::NIGHT)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::NIGHT);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto photoProfiles = outputCapability->GetPhotoProfiles();
    ASSERT_FALSE(photoProfiles.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::NIGHT);
    auto nightSession = static_cast<NightSession*>(captureSession.GetRefPtr());
    ASSERT_NE(nightSession, nullptr);
    int32_t res = nightSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = nightSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(nightSession->CanAddOutput(previewOutput));
    res = nightSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoProfiles[0]);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_TRUE(nightSession->CanAddOutput(photoOutput));
    res = nightSession->AddOutput(photoOutput);
    EXPECT_EQ(res, 0);

    res = nightSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = nightSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);

    vector<uint32_t> exposureRange;
    res = nightSession->GetExposureRange(exposureRange);
    EXPECT_EQ(res, 0);
    if (!exposureRange.empty()) {
        nightSession->LockForControl();
        res = nightSession->SetExposure(exposureRange[0]);
        nightSession->UnlockForControl();
        EXPECT_EQ(res, 0);
        uint32_t exposure;
        res = nightSession->GetExposure(exposure);
        EXPECT_EQ(res, 0);
        EXPECT_EQ(exposure, exposureRange[0]);
    }

    res = static_cast<PhotoOutput*>(photoOutput.GetRefPtr())->Capture();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);
    res = nightSession->Stop();
    EXPECT_EQ(res, 0);
    res = nightSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test night session abnormal branches
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test night session abnormal branches
 */
HWTEST_F(CameraSessionModuleTest, night_session_moduletest_004, TestSize.Level1)
{
    SceneMode nightMode = SceneMode::NIGHT;
    sptr<CaptureSession> captureSession = managerForSys_->CreateCaptureSessionForSys(nightMode);
    auto nightSession = static_cast<NightSession*>(captureSession.GetRefPtr());
    ASSERT_NE(nightSession, nullptr);
    int32_t intResult = nightSession->BeginConfig();
    EXPECT_EQ(intResult, 0);
    intResult = nightSession->AddInput(input_);
    EXPECT_EQ(intResult, 0);
    std::vector<uint32_t> exposureRange;
    uint32_t exposureValue = 0;
    EXPECT_EQ(nightSession->GetExposureRange(exposureRange), SESSION_NOT_CONFIG);
    EXPECT_EQ(nightSession->SetExposure(0), SESSION_NOT_CONFIG);
    EXPECT_EQ(nightSession->GetExposure(exposureValue), SESSION_NOT_CONFIG);
}

/*
 * Feature: Framework
 * Function: Test night session nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test night session nullptr
 */
HWTEST_F(CameraSessionModuleTest, night_session_moduletest_005, TestSize.Level1)
{
    sptr<CaptureSession> camSession = manager_->CreateCaptureSession();
    ASSERT_NE(camSession, nullptr);
    SceneMode nightMode = SceneMode::NIGHT;
    sptr<CaptureSession> captureSession = managerForSys_->CreateCaptureSessionForSys(nightMode);
    auto nightSession = static_cast<NightSession*>(captureSession.GetRefPtr());
    uint32_t exposureValue = 0;
    std::vector<uint32_t> exposureRange;
    EXPECT_EQ(nightSession->GetExposureRange(exposureRange), SESSION_NOT_CONFIG);
    EXPECT_EQ(nightSession->GetExposure(exposureValue), SESSION_NOT_CONFIG);
    EXPECT_EQ(nightSession->SetExposure(0), SESSION_NOT_CONFIG);
}

/*
 * Feature: Framework
 * Function: Test profession session with photo output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can add photo output into profession session
 */
HWTEST_F(CameraSessionModuleTest, profession_session_moduletest_001, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::PROFESSIONAL)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::PROFESSIONAL);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto photoProfiles = outputCapability->GetPhotoProfiles();
    ASSERT_FALSE(photoProfiles.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::PROFESSIONAL);
    auto professionSession = static_cast<ProfessionSession*>(captureSession.GetRefPtr());
    ASSERT_NE(professionSession, nullptr);
    int32_t res = professionSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = professionSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(professionSession->CanAddOutput(previewOutput));
    res = professionSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoProfiles[0]);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_TRUE(professionSession->CanAddOutput(photoOutput));
    res = professionSession->AddOutput(photoOutput);
    EXPECT_EQ(res, 0);

    res = professionSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = professionSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);
    res = static_cast<PhotoOutput*>(photoOutput.GetRefPtr())->Capture();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);
    res = professionSession->Stop();
    EXPECT_EQ(res, 0);
    res = professionSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test profession session with video output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can add video output into profession session
 */
HWTEST_F(CameraSessionModuleTest, profession_session_moduletest_002, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::PROFESSIONAL)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::PROFESSIONAL);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto videoProfiles = outputCapability->GetVideoProfiles();
    ASSERT_FALSE(videoProfiles.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::PROFESSIONAL);
    auto professionSession = static_cast<ProfessionSession*>(captureSession.GetRefPtr());
    ASSERT_NE(professionSession, nullptr);
    int32_t res = professionSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = professionSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(professionSession->CanAddOutput(previewOutput));
    res = professionSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfiles[0]);
    ASSERT_NE(videoOutput, nullptr);
    EXPECT_TRUE(professionSession->CanAddOutput(videoOutput));
    res = professionSession->AddOutput(videoOutput);
    EXPECT_EQ(res, 0);

    res = professionSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = professionSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);
    res = static_cast<VideoOutput*>(videoOutput.GetRefPtr())->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);
    res = static_cast<VideoOutput*>(videoOutput.GetRefPtr())->Stop();
    EXPECT_EQ(res, 0);
    res = professionSession->Stop();
    EXPECT_EQ(res, 0);
    res = professionSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test profession session set metering mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can set metering mode into profession session
 */
HWTEST_F(CameraSessionModuleTest, profession_session_moduletest_003, TestSize.Level0)
{
    if (!IsSceneModeSupported(SceneMode::PROFESSIONAL)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::PROFESSIONAL);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto videoProfiles = outputCapability->GetVideoProfiles();
    ASSERT_FALSE(videoProfiles.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::PROFESSIONAL);
    auto professionSession = static_cast<ProfessionSession*>(captureSession.GetRefPtr());
    ASSERT_NE(professionSession, nullptr);
    int32_t res = professionSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = professionSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(professionSession->CanAddOutput(previewOutput));
    res = professionSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfiles[0]);
    ASSERT_NE(videoOutput, nullptr);
    EXPECT_TRUE(professionSession->CanAddOutput(videoOutput));
    res = professionSession->AddOutput(videoOutput);
    EXPECT_EQ(res, 0);

    res = professionSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = professionSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);

    vector<MeteringMode> modes;
    res = professionSession->GetSupportedMeteringModes(modes);
    EXPECT_EQ(res, 0);
    if (!modes.empty()) {
        bool supported;
        res = professionSession->IsMeteringModeSupported(METERING_MODE_CENTER_WEIGHTED, supported);
        EXPECT_EQ(res, 0);
        if (supported) {
            professionSession->LockForControl();
            res = professionSession->SetMeteringMode(METERING_MODE_CENTER_WEIGHTED);
            professionSession->UnlockForControl();
            EXPECT_EQ(res, 0);
            MeteringMode mode;
            res = professionSession->GetMeteringMode(mode);
            EXPECT_EQ(res, 0);
            EXPECT_EQ(mode, METERING_MODE_CENTER_WEIGHTED);
        }
    }

    res = static_cast<VideoOutput*>(videoOutput.GetRefPtr())->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);
    res = static_cast<VideoOutput*>(videoOutput.GetRefPtr())->Stop();
    EXPECT_EQ(res, 0);
    res = professionSession->Stop();
    EXPECT_EQ(res, 0);
    res = professionSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test profession session set iso range
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can set iso range into profession session
 */
HWTEST_F(CameraSessionModuleTest, profession_session_moduletest_004, TestSize.Level0)
{
    if (!IsSceneModeSupported(SceneMode::PROFESSIONAL)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::PROFESSIONAL);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto videoProfiles = outputCapability->GetVideoProfiles();
    ASSERT_FALSE(videoProfiles.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::PROFESSIONAL);
    auto professionSession = static_cast<ProfessionSession*>(captureSession.GetRefPtr());
    ASSERT_NE(professionSession, nullptr);
    int32_t res = professionSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = professionSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(professionSession->CanAddOutput(previewOutput));
    res = professionSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfiles[0]);
    ASSERT_NE(videoOutput, nullptr);
    EXPECT_TRUE(professionSession->CanAddOutput(videoOutput));
    res = professionSession->AddOutput(videoOutput);
    EXPECT_EQ(res, 0);

    res = professionSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = professionSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);

    bool isManualIsoSupported = professionSession->IsManualIsoSupported();
    if (isManualIsoSupported) {
        vector<int32_t> isoRange;
        res = professionSession->GetIsoRange(isoRange);
        EXPECT_EQ(res, 0);
        if (!isoRange.empty()) {
            professionSession->LockForControl();
            res = professionSession->SetISO(isoRange[0]);
            professionSession->UnlockForControl();
            EXPECT_EQ(res, 0);
            int32_t iso;
            res = professionSession->GetISO(iso);
            EXPECT_EQ(res, 0);
            EXPECT_EQ(iso, isoRange[0]);
        }
    }

    res = static_cast<VideoOutput*>(videoOutput.GetRefPtr())->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);
    res = static_cast<VideoOutput*>(videoOutput.GetRefPtr())->Stop();
    EXPECT_EQ(res, 0);
    res = professionSession->Stop();
    EXPECT_EQ(res, 0);
    res = professionSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test profession session set focus mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can set focus mode into profession session
 */
HWTEST_F(CameraSessionModuleTest, profession_session_moduletest_005, TestSize.Level0)
{
    if (!IsSceneModeSupported(SceneMode::PROFESSIONAL)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::PROFESSIONAL);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto videoProfiles = outputCapability->GetVideoProfiles();
    ASSERT_FALSE(videoProfiles.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::PROFESSIONAL);
    auto professionSession = static_cast<ProfessionSession*>(captureSession.GetRefPtr());
    ASSERT_NE(professionSession, nullptr);
    int32_t res = professionSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = professionSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(professionSession->CanAddOutput(previewOutput));
    res = professionSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfiles[0]);
    ASSERT_NE(videoOutput, nullptr);
    EXPECT_TRUE(professionSession->CanAddOutput(videoOutput));
    res = professionSession->AddOutput(videoOutput);
    EXPECT_EQ(res, 0);

    res = professionSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = professionSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);

    std::vector<FocusMode> modes;
    res = professionSession->GetSupportedFocusModes(modes);
    EXPECT_EQ(res, 0);
    if (!modes.empty()) {
        FocusMode focusMode = modes[0];
        bool supported;
        res = professionSession->IsFocusModeSupported(focusMode, supported);
        EXPECT_EQ(res, 0);
        if (supported) {
            professionSession->LockForControl();
            res = professionSession->SetFocusMode(focusMode);
            professionSession->UnlockForControl();
            EXPECT_EQ(res, 0);
            FocusMode mode;
            res = professionSession->GetFocusMode(mode);
            EXPECT_EQ(res, 0);
            EXPECT_EQ(mode, focusMode);
        }
    }

    res = static_cast<VideoOutput*>(videoOutput.GetRefPtr())->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);
    res = static_cast<VideoOutput*>(videoOutput.GetRefPtr())->Stop();
    EXPECT_EQ(res, 0);
    res = professionSession->Stop();
    EXPECT_EQ(res, 0);
    res = professionSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test profession session set exposure hint mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can set exposure hint mode into profession session
 */
HWTEST_F(CameraSessionModuleTest, profession_session_moduletest_006, TestSize.Level0)
{
    if (!IsSceneModeSupported(SceneMode::PROFESSIONAL)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::PROFESSIONAL);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto videoProfiles = outputCapability->GetVideoProfiles();
    ASSERT_FALSE(videoProfiles.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::PROFESSIONAL);
    auto professionSession = static_cast<ProfessionSession*>(captureSession.GetRefPtr());
    ASSERT_NE(professionSession, nullptr);
    int32_t res = professionSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = professionSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(professionSession->CanAddOutput(previewOutput));
    res = professionSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfiles[0]);
    ASSERT_NE(videoOutput, nullptr);
    EXPECT_TRUE(professionSession->CanAddOutput(videoOutput));
    res = professionSession->AddOutput(videoOutput);
    EXPECT_EQ(res, 0);

    res = professionSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = professionSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);

    std::vector<ExposureHintMode> modes;
    res = professionSession->GetSupportedExposureHintModes(modes);
    EXPECT_EQ(res, 0);
    if (!modes.empty()) {
        ExposureHintMode exposureHintMode = modes[0];
        professionSession->LockForControl();
        res = professionSession->SetExposureHintMode(exposureHintMode);
        professionSession->UnlockForControl();
        EXPECT_EQ(res, 0);
        ExposureHintMode mode;
        res = professionSession->GetExposureHintMode(mode);
        EXPECT_EQ(res, 0);
        EXPECT_EQ(mode, exposureHintMode);
    }

    res = static_cast<VideoOutput*>(videoOutput.GetRefPtr())->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);
    res = static_cast<VideoOutput*>(videoOutput.GetRefPtr())->Stop();
    EXPECT_EQ(res, 0);
    res = professionSession->Stop();
    EXPECT_EQ(res, 0);
    res = professionSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test profession session set focus assist flash mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can set focus assist flash mode into profession session
 */
HWTEST_F(CameraSessionModuleTest, profession_session_moduletest_007, TestSize.Level0)
{
    if (!IsSceneModeSupported(SceneMode::PROFESSIONAL)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::PROFESSIONAL);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto videoProfiles = outputCapability->GetVideoProfiles();
    ASSERT_FALSE(videoProfiles.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::PROFESSIONAL);
    auto professionSession = static_cast<ProfessionSession*>(captureSession.GetRefPtr());
    ASSERT_NE(professionSession, nullptr);
    int32_t res = professionSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = professionSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(professionSession->CanAddOutput(previewOutput));
    res = professionSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfiles[0]);
    ASSERT_NE(videoOutput, nullptr);
    EXPECT_TRUE(professionSession->CanAddOutput(videoOutput));
    res = professionSession->AddOutput(videoOutput);
    EXPECT_EQ(res, 0);

    res = professionSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = professionSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);

    std::vector<FocusAssistFlashMode> modes;
    res = professionSession->GetSupportedFocusAssistFlashModes(modes);
    EXPECT_EQ(res, 0);
    if (!modes.empty()) {
        FocusAssistFlashMode flashMode = modes[0];
        bool supported;
        res = professionSession->IsFocusAssistFlashModeSupported(flashMode, supported);
        EXPECT_EQ(res, 0);
        if (supported) {
            professionSession->LockForControl();
            res = professionSession->SetFocusAssistFlashMode(flashMode);
            professionSession->UnlockForControl();
            EXPECT_EQ(res, 0);
            FocusAssistFlashMode mode;
            res = professionSession->GetFocusAssistFlashMode(mode);
            EXPECT_EQ(res, 0);
            EXPECT_EQ(mode, flashMode);
        }
    }

    res = static_cast<VideoOutput*>(videoOutput.GetRefPtr())->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);
    res = static_cast<VideoOutput*>(videoOutput.GetRefPtr())->Stop();
    EXPECT_EQ(res, 0);
    res = professionSession->Stop();
    EXPECT_EQ(res, 0);
    res = professionSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test profession session set flash mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can set flash mode into profession session
 */
HWTEST_F(CameraSessionModuleTest, profession_session_moduletest_008, TestSize.Level0)
{
    if (!IsSceneModeSupported(SceneMode::PROFESSIONAL)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::PROFESSIONAL);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto videoProfiles = outputCapability->GetVideoProfiles();
    ASSERT_FALSE(videoProfiles.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::PROFESSIONAL);
    auto professionSession = static_cast<ProfessionSession*>(captureSession.GetRefPtr());
    ASSERT_NE(professionSession, nullptr);
    int32_t res = professionSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = professionSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(professionSession->CanAddOutput(previewOutput));
    res = professionSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfiles[0]);
    ASSERT_NE(videoOutput, nullptr);
    EXPECT_TRUE(professionSession->CanAddOutput(videoOutput));
    res = professionSession->AddOutput(videoOutput);
    EXPECT_EQ(res, 0);

    res = professionSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = professionSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);

    bool hasFlash;
    res = professionSession->HasFlash(hasFlash);
    EXPECT_EQ(res, 0);
    if (hasFlash) {
        std::vector<FlashMode> modes;
        res = professionSession->GetSupportedFlashModes(modes);
        EXPECT_EQ(res, 0);
        if (!modes.empty()) {
            FlashMode flashMode = modes[0];
            bool supported;
            res = professionSession->IsFlashModeSupported(flashMode, supported);
            EXPECT_EQ(res, 0);
            if (supported) {
                professionSession->LockForControl();
                res = professionSession->SetFlashMode(flashMode);
                professionSession->UnlockForControl();
                EXPECT_EQ(res, 0);
                FlashMode mode;
                res = professionSession->GetFlashMode(mode);
                EXPECT_EQ(res, 0);
                EXPECT_EQ(mode, flashMode);
            }
        }
    }

    res = static_cast<VideoOutput*>(videoOutput.GetRefPtr())->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);
    res = static_cast<VideoOutput*>(videoOutput.GetRefPtr())->Stop();
    EXPECT_EQ(res, 0);
    res = professionSession->Stop();
    EXPECT_EQ(res, 0);
    res = professionSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test profession session set color effect
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can set color effect into profession session
 */
HWTEST_F(CameraSessionModuleTest, profession_session_moduletest_009, TestSize.Level0)
{
    if (!IsSceneModeSupported(SceneMode::PROFESSIONAL)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::PROFESSIONAL);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto videoProfiles = outputCapability->GetVideoProfiles();
    ASSERT_FALSE(videoProfiles.empty());

    auto captureSessionForSys = managerForSys_->CreateCaptureSessionForSys(SceneMode::PROFESSIONAL);
    auto professionSession = static_cast<ProfessionSession*>(captureSessionForSys.GetRefPtr());
    ASSERT_NE(professionSession, nullptr);
    int32_t res = professionSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = professionSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(professionSession->CanAddOutput(previewOutput));
    res = professionSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfiles[0]);
    ASSERT_NE(videoOutput, nullptr);
    EXPECT_TRUE(professionSession->CanAddOutput(videoOutput));
    res = professionSession->AddOutput(videoOutput);
    EXPECT_EQ(res, 0);

    res = professionSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = professionSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);

    std::vector<ColorEffect> modes;
    res = professionSession->GetSupportedColorEffects(modes);
    EXPECT_EQ(res, 0);
    if (!modes.empty()) {
        ColorEffect colorEffect = modes[0];
        professionSession->LockForControl();
        res = professionSession->SetColorEffect(colorEffect);
        professionSession->UnlockForControl();
        EXPECT_EQ(res, 0);
        ColorEffect effect;
        res = professionSession->GetColorEffect(effect);
        EXPECT_EQ(res, 0);
        EXPECT_EQ(effect, colorEffect);
    }

    res = static_cast<VideoOutput*>(videoOutput.GetRefPtr())->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);
    res = static_cast<VideoOutput*>(videoOutput.GetRefPtr())->Stop();
    EXPECT_EQ(res, 0);
    res = professionSession->Stop();
    EXPECT_EQ(res, 0);
    res = professionSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test profession session callbacks
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can set callbacks into profession session
 */
HWTEST_F(CameraSessionModuleTest, profession_session_moduletest_010, TestSize.Level0)
{
    if (!IsSceneModeSupported(SceneMode::PROFESSIONAL)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::PROFESSIONAL);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto videoProfiles = outputCapability->GetVideoProfiles();
    ASSERT_FALSE(videoProfiles.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::PROFESSIONAL);
    auto professionSession = static_cast<ProfessionSession*>(captureSession.GetRefPtr());
    ASSERT_NE(professionSession, nullptr);
    int32_t res = professionSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = professionSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(professionSession->CanAddOutput(previewOutput));
    res = professionSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfiles[0]);
    ASSERT_NE(videoOutput, nullptr);
    EXPECT_TRUE(professionSession->CanAddOutput(videoOutput));
    res = professionSession->AddOutput(videoOutput);
    EXPECT_EQ(res, 0);

    professionSession->SetExposureInfoCallback(make_shared<TestExposureInfoCallback>());
    static const camera_rational_t rational = {
        .denominator = DEFAULT_DENOMINATOR_VALUE,
        .numerator = DEFAULT_NUMERATOR_VALUE,
    };
    auto meta = make_shared<OHOS::Camera::CameraMetadata>(META_VALUE_10, META_VALUE_100);
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_SENSOR_EXPOSURE_TIME, &rational, 1), true);
    professionSession->ProcessSensorExposureTimeChange(meta);
    professionSession->SetIsoInfoCallback(make_shared<TestIsoInfoCallback>());
    static const uint32_t iso = DEFAULT_ISO_VALUE;
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_ISO_VALUE, &iso, 1), true);
    professionSession->ProcessIsoChange(meta);
    professionSession->SetApertureInfoCallback(make_shared<TestApertureInfoCallback>());
    static const uint32_t aperture = DEFAULT_APERTURE_VALUE;
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_CAMERA_APERTURE_VALUE, &aperture, 1), true);
    professionSession->ProcessApertureChange(meta);
    professionSession->SetLuminationInfoCallback(make_shared<TestLuminationInfoCallback>());
    static const uint32_t lumination = DEFAULT_LUMINATION_VALUE;
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_ALGO_MEAN_Y, &lumination, 1), true);
    professionSession->ProcessLuminationChange(meta);

    res = professionSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = professionSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);
    res = static_cast<VideoOutput*>(videoOutput.GetRefPtr())->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);
    res = static_cast<VideoOutput*>(videoOutput.GetRefPtr())->Stop();
    EXPECT_EQ(res, 0);
    res = professionSession->Stop();
    EXPECT_EQ(res, 0);
    res = professionSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test preview/video with profession video session
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test preview/video with profession video session
 */
HWTEST_F(CameraSessionModuleTest, profession_video_session_moduletest_001, TestSize.Level1)
{
    SceneMode sceneMode = SceneMode::PROFESSIONAL_VIDEO;
    if (!IsSceneModeSupported(sceneMode)) {
        GTEST_SKIP();
    }
    sptr<CameraManager> cameraManagerObj = CameraManager::GetInstance();
    ASSERT_NE(cameraManagerObj, nullptr);

    std::vector<SceneMode> sceneModes = cameraManagerObj->GetSupportedModes(cameras_[0]);
    ASSERT_TRUE(sceneModes.size() != 0);

    sptr<CameraOutputCapability> modeAbility =
        cameraManagerObj->GetSupportedOutputCapability(cameras_[0], sceneMode);
    ASSERT_NE(modeAbility, nullptr);

    SelectProfiles wanted;
    wanted.preview.size_ = {640, 480};
    wanted.preview.format_ = CAMERA_FORMAT_YUV_420_SP;
    wanted.photo.size_ = {640, 480};
    wanted.photo.format_ = CAMERA_FORMAT_JPEG;
    wanted.video.size_ = {640, 480};
    wanted.video.format_ = CAMERA_FORMAT_YUV_420_SP;
    wanted.video.framerates_ = {30, 30};

    sptr<CaptureSessionForSys> captureSession = managerForSys_->CreateCaptureSessionForSys(sceneMode);
    ASSERT_NE(captureSession, nullptr);
    sptr<ProfessionSession> session = static_cast<ProfessionSession*>(captureSession.GetRefPtr());
    ASSERT_NE(session, nullptr);

    int32_t intResult = session->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(wanted.preview);
    ASSERT_NE(previewOutput, nullptr);

    intResult = session->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> videoOutput = CreateVideoOutput(wanted.video);
    ASSERT_NE(videoOutput, nullptr);

    intResult = session->AddOutput(videoOutput);
    EXPECT_EQ(intResult, 0);


    intResult = session->CommitConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session->Start();
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_START);

    intResult = ((sptr<VideoOutput>&)videoOutput)->Start();
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_RECORDING);
    intResult = ((sptr<VideoOutput>&)videoOutput)->Stop();
    session->Stop();
}

/*
 * Feature: Framework
 * Function: Test profession video session metering mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test profession video session metering mode
 */
HWTEST_F(CameraSessionModuleTest, profession_video_session_moduletest_002, TestSize.Level0)
{
    SceneMode sceneMode = SceneMode::PROFESSIONAL_VIDEO;
    if (!IsSceneModeSupported(sceneMode)) {
        GTEST_SKIP();
    }
    sptr<CameraManager> cameraManagerObj = CameraManager::GetInstance();
    ASSERT_NE(cameraManagerObj, nullptr);

    std::vector<SceneMode> sceneModes = cameraManagerObj->GetSupportedModes(cameras_[0]);
    ASSERT_TRUE(sceneModes.size() != 0);

    sptr<CameraOutputCapability> modeAbility =
        cameraManagerObj->GetSupportedOutputCapability(cameras_[0], sceneMode);
    ASSERT_NE(modeAbility, nullptr);

    SelectProfiles wanted;
    wanted.preview.size_ = {640, 480};
    wanted.preview.format_ = CAMERA_FORMAT_YUV_420_SP;
    wanted.photo.size_ = {640, 480};
    wanted.photo.format_ = CAMERA_FORMAT_JPEG;
    wanted.video.size_ = {640, 480};
    wanted.video.format_ = CAMERA_FORMAT_YUV_420_SP;
    wanted.video.framerates_ = {30, 30};

    sptr<CaptureSessionForSys> captureSession = managerForSys_->CreateCaptureSessionForSys(sceneMode);
    ASSERT_NE(captureSession, nullptr);
    sptr<ProfessionSession> session = static_cast<ProfessionSession*>(captureSession.GetRefPtr());
    ASSERT_NE(session, nullptr);

    int32_t intResult = session->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(wanted.preview);
    ASSERT_NE(previewOutput, nullptr);

    intResult = session->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> videoOutput = CreateVideoOutput(wanted.video);
    ASSERT_NE(videoOutput, nullptr);

    intResult = session->AddOutput(videoOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session->CommitConfig();
    EXPECT_EQ(intResult, 0);

    MeteringMode meteringMode = METERING_MODE_CENTER_WEIGHTED;
    bool isSupported;
    intResult = session->IsMeteringModeSupported(meteringMode, isSupported);
    EXPECT_EQ(intResult, 0);
    EXPECT_EQ(isSupported, true);

    std::vector<MeteringMode> modes = {};
    intResult = session->GetSupportedMeteringModes(modes);
    EXPECT_EQ(intResult, 0);
    EXPECT_NE(modes.size(), 0);

    session->LockForControl();
    intResult = session->SetMeteringMode(modes[0]);
    session->UnlockForControl();
    EXPECT_EQ(intResult, 0);
    intResult = session->GetMeteringMode(meteringMode);
    EXPECT_EQ(intResult, 0);

    EXPECT_EQ(meteringMode, modes[0]);
    intResult = session->Start();
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_START);

    intResult = ((sptr<VideoOutput>&)videoOutput)->Start();
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_RECORDING);
    intResult = ((sptr<VideoOutput>&)videoOutput)->Stop();
    session->Stop();
}

/*
 * Feature: Framework
 * Function: Test profession video session focus assist flash mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test profession video session focus assist flash mode
 */
HWTEST_F(CameraSessionModuleTest, profession_video_session_moduletest_003, TestSize.Level0)
{
    SceneMode sceneMode = SceneMode::PROFESSIONAL_VIDEO;
    if (!IsSceneModeSupported(sceneMode)) {
        GTEST_SKIP();
    }
    sptr<CameraManager> cameraManagerObj = CameraManager::GetInstance();
    ASSERT_NE(cameraManagerObj, nullptr);

    std::vector<SceneMode> sceneModes = cameraManagerObj->GetSupportedModes(cameras_[0]);
    ASSERT_TRUE(sceneModes.size() != 0);

    sptr<CameraOutputCapability> modeAbility =
        cameraManagerObj->GetSupportedOutputCapability(cameras_[0], sceneMode);
    ASSERT_NE(modeAbility, nullptr);

    SelectProfiles wanted;
    wanted.preview.size_ = {640, 480};
    wanted.preview.format_ = CAMERA_FORMAT_YUV_420_SP;
    wanted.photo.size_ = {640, 480};
    wanted.photo.format_ = CAMERA_FORMAT_JPEG;
    wanted.video.size_ = {640, 480};
    wanted.video.format_ = CAMERA_FORMAT_YUV_420_SP;
    wanted.video.framerates_ = {30, 30};

    sptr<CaptureSessionForSys> captureSession = managerForSys_->CreateCaptureSessionForSys(sceneMode);
    ASSERT_NE(captureSession, nullptr);
    sptr<ProfessionSession> session = static_cast<ProfessionSession*>(captureSession.GetRefPtr());
    ASSERT_NE(session, nullptr);

    int32_t intResult = session->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(wanted.preview);
    ASSERT_NE(previewOutput, nullptr);

    intResult = session->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> videoOutput = CreateVideoOutput(wanted.video);
    ASSERT_NE(videoOutput, nullptr);

    intResult = session->AddOutput(videoOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session->CommitConfig();
    EXPECT_EQ(intResult, 0);

    FocusAssistFlashMode mode = FocusAssistFlashMode::FOCUS_ASSIST_FLASH_MODE_DEFAULT;
    bool isSupported;
    intResult = session->IsFocusAssistFlashModeSupported(mode, isSupported);
    EXPECT_EQ(intResult, 0);
    EXPECT_EQ(isSupported, true);

    std::vector<FocusAssistFlashMode> modes = {};
    intResult = session->GetSupportedFocusAssistFlashModes(modes);
    EXPECT_EQ(intResult, 0);
    EXPECT_NE(modes.size(), 0);

    session->LockForControl();
    intResult = session->SetFocusAssistFlashMode(modes[0]);
    session->UnlockForControl();
    EXPECT_EQ(intResult, 0);
    intResult = session->GetFocusAssistFlashMode(mode);
    EXPECT_EQ(intResult, 0);

    EXPECT_EQ(mode, modes[0]);
    intResult = session->Start();
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_START);

    intResult = ((sptr<VideoOutput>&)videoOutput)->Start();
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_RECORDING);
    intResult = ((sptr<VideoOutput>&)videoOutput)->Stop();
    session->Stop();
}

/*
 * Feature: Framework
 * Function: Test profession video session exposure hint mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test profession video session exposure hint mode
 */
HWTEST_F(CameraSessionModuleTest, profession_video_session_moduletest_004, TestSize.Level0)
{
    SceneMode sceneMode = SceneMode::PROFESSIONAL_VIDEO;
    if (!IsSceneModeSupported(sceneMode)) {
        GTEST_SKIP();
    }
    sptr<CameraManager> cameraManagerObj = CameraManager::GetInstance();
    ASSERT_NE(cameraManagerObj, nullptr);

    std::vector<SceneMode> sceneModes = cameraManagerObj->GetSupportedModes(cameras_[0]);
    ASSERT_TRUE(sceneModes.size() != 0);

    sptr<CameraOutputCapability> modeAbility =
        cameraManagerObj->GetSupportedOutputCapability(cameras_[0], sceneMode);
    ASSERT_NE(modeAbility, nullptr);

    SelectProfiles wanted;
    wanted.preview.size_ = {640, 480};
    wanted.preview.format_ = CAMERA_FORMAT_YUV_420_SP;
    wanted.photo.size_ = {640, 480};
    wanted.photo.format_ = CAMERA_FORMAT_JPEG;
    wanted.video.size_ = {640, 480};
    wanted.video.format_ = CAMERA_FORMAT_YUV_420_SP;
    wanted.video.framerates_ = {30, 30};

    sptr<CaptureSessionForSys> captureSession = managerForSys_->CreateCaptureSessionForSys(sceneMode);
    ASSERT_NE(captureSession, nullptr);
    sptr<ProfessionSession> session = static_cast<ProfessionSession*>(captureSession.GetRefPtr());
    ASSERT_NE(session, nullptr);

    int32_t intResult = session->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(wanted.preview);
    ASSERT_NE(previewOutput, nullptr);

    intResult = session->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> videoOutput = CreateVideoOutput(wanted.video);
    ASSERT_NE(videoOutput, nullptr);

    intResult = session->AddOutput(videoOutput);
    EXPECT_EQ(intResult, 0);


    intResult = session->CommitConfig();
    EXPECT_EQ(intResult, 0);
    std::vector<ExposureHintMode> modes = {};
    intResult = session->GetSupportedExposureHintModes(modes);
    EXPECT_EQ(intResult, 0);
    EXPECT_NE(modes.size(), 0);

    session->LockForControl();
    intResult = session->SetExposureHintMode(modes[0]);
    EXPECT_EQ(intResult, 0);
    session->UnlockForControl();

    ExposureHintMode mode;
    intResult = session->GetExposureHintMode(mode);
    EXPECT_EQ(intResult, 0);

    EXPECT_EQ(mode, modes[0]);
    intResult = session->Start();
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_START);

    intResult = ((sptr<VideoOutput>&)videoOutput)->Start();
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_RECORDING);
    intResult = ((sptr<VideoOutput>&)videoOutput)->Stop();
    session->Stop();
}

/*
 * Feature: Framework
 * Function: Test profession video session manual_iso_props && auto_awb_props && manual_awb_props
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: test profession video session manual_iso_props && auto_awb_props && manual_awb_props
 */
HWTEST_F(CameraSessionModuleTest, profession_video_session_moduletest_005, TestSize.Level0)
{
    SceneMode sceneMode = SceneMode::PROFESSIONAL_VIDEO;
    if (!IsSceneModeSupported(sceneMode)) {
        GTEST_SKIP();
    }
    sptr<CameraManager> modeManagerObj = CameraManager::GetInstance();
    ASSERT_NE(modeManagerObj, nullptr);

    std::vector<SceneMode> sceneModes = modeManagerObj->GetSupportedModes(cameras_[0]);
    ASSERT_TRUE(sceneModes.size() != 0);

    sptr<CameraOutputCapability> modeAbility =
        modeManagerObj->GetSupportedOutputCapability(cameras_[0], sceneMode);
    ASSERT_NE(modeAbility, nullptr);

    SelectProfiles wanted;
    wanted.preview.size_ = {640, 480};
    wanted.preview.format_ = CAMERA_FORMAT_YUV_420_SP;
    wanted.photo.size_ = {640, 480};
    wanted.photo.format_ = CAMERA_FORMAT_JPEG;
    wanted.video.size_ = {640, 480};
    wanted.video.format_ = CAMERA_FORMAT_YUV_420_SP;
    wanted.video.framerates_ = {30, 30};

    sptr<CaptureSessionForSys> captureSession = managerForSys_->CreateCaptureSessionForSys(sceneMode);
    ASSERT_NE(captureSession, nullptr);

    sptr<ProfessionSession> session = static_cast<ProfessionSession*>(captureSession.GetRefPtr());
    ASSERT_NE(session, nullptr);

    int32_t intResult = session->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(wanted.preview);
    ASSERT_NE(previewOutput, nullptr);

    intResult = session->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> videoOutput = CreateVideoOutput(wanted.video);
    ASSERT_NE(videoOutput, nullptr);

    intResult = session->AddOutput(videoOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session->CommitConfig();
    EXPECT_EQ(intResult, 0);

    bool isSupported = session->IsManualIsoSupported();
    if (isSupported) {
        std::vector<int32_t> isoRange;
        session->GetIsoRange(isoRange);
        ASSERT_EQ(isoRange.empty(), false);
        session->LockForControl();
        intResult = session->SetISO(isoRange[1] + 1);
        EXPECT_NE(intResult, 0);
        session->UnlockForControl();

        session->LockForControl();
        intResult = session->SetISO(isoRange[1]);
        EXPECT_EQ(intResult, 0);
        session->UnlockForControl();

        int32_t iso;
        session->GetISO(iso);
        EXPECT_EQ(isoRange[1], iso);
    }

    std::vector<WhiteBalanceMode> supportedWhiteBalanceModes;
    session->GetSupportedWhiteBalanceModes(supportedWhiteBalanceModes);
    if (!supportedWhiteBalanceModes.empty()) {
        session->IsWhiteBalanceModeSupported(supportedWhiteBalanceModes[0], isSupported);
        ASSERT_EQ(isSupported, true);
        session->LockForControl();
        intResult = session->SetWhiteBalanceMode(supportedWhiteBalanceModes[0]);
        ASSERT_EQ(intResult, 0);
        session->UnlockForControl();
        WhiteBalanceMode currentMode;
        session->GetWhiteBalanceMode(currentMode);
        ASSERT_EQ(currentMode, supportedWhiteBalanceModes[0]);
    }

    session->IsManualWhiteBalanceSupported(isSupported);
    std::vector<int32_t> whiteBalanceRange;
    if (isSupported) {
        session->GetManualWhiteBalanceRange(whiteBalanceRange);
        ASSERT_EQ(whiteBalanceRange.size() == 2, true);

        session->LockForControl();
        ASSERT_EQ(session->SetWhiteBalanceMode(WhiteBalanceMode::AWB_MODE_OFF), SUCCESS);
        session->UnlockForControl();
        session->LockForControl();
        intResult = session->SetManualWhiteBalance(whiteBalanceRange[0] - 1);
        ASSERT_EQ(intResult, 0);
        session->UnlockForControl();

        int32_t wbValue;
        session->GetManualWhiteBalance(wbValue);
        ASSERT_EQ(wbValue, whiteBalanceRange[0]);
    } else {
        session->GetManualWhiteBalanceRange(whiteBalanceRange);
        ASSERT_EQ(whiteBalanceRange.size() < 2, true);
    }
}

/*
 * Feature: Framework
 * Function: Test profession video session focus mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test profession video session focus mode
 */
HWTEST_F(CameraSessionModuleTest, profession_video_session_moduletest_006, TestSize.Level0)
{
    SceneMode sceneMode = SceneMode::PROFESSIONAL_VIDEO;
    if (!IsSceneModeSupported(sceneMode)) {
        GTEST_SKIP();
    }
    sptr<CameraManager> cameraManagerObj = CameraManager::GetInstance();
    ASSERT_NE(cameraManagerObj, nullptr);

    std::vector<SceneMode> sceneModes = cameraManagerObj->GetSupportedModes(cameras_[0]);
    ASSERT_TRUE(sceneModes.size() != 0);

    sptr<CameraOutputCapability> modeAbility =
        cameraManagerObj->GetSupportedOutputCapability(cameras_[0], sceneMode);
    ASSERT_NE(modeAbility, nullptr);

    SelectProfiles wanted;
    wanted.preview.size_ = {640, 480};
    wanted.preview.format_ = CAMERA_FORMAT_YUV_420_SP;
    wanted.photo.size_ = {640, 480};
    wanted.photo.format_ = CAMERA_FORMAT_JPEG;
    wanted.video.size_ = {640, 480};
    wanted.video.format_ = CAMERA_FORMAT_YUV_420_SP;
    wanted.video.framerates_ = {30, 30};

    sptr<CaptureSessionForSys> captureSession = managerForSys_->CreateCaptureSessionForSys(sceneMode);
    ASSERT_NE(captureSession, nullptr);
    sptr<ProfessionSession> session = static_cast<ProfessionSession*>(captureSession.GetRefPtr());
    ASSERT_NE(session, nullptr);

    int32_t intResult = session->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(wanted.preview);
    ASSERT_NE(previewOutput, nullptr);

    intResult = session->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> videoOutput = CreateVideoOutput(wanted.video);
    ASSERT_NE(videoOutput, nullptr);

    intResult = session->AddOutput(videoOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session->CommitConfig();
    EXPECT_EQ(intResult, 0);

    FocusMode focusMode = FocusMode::FOCUS_MODE_MANUAL;
    bool isSupported;
    intResult = session->IsFocusModeSupported(focusMode, isSupported);
    EXPECT_EQ(intResult, 0);
    EXPECT_EQ(isSupported, true);

    std::vector<FocusMode> modes = {};
    intResult = session->GetSupportedFocusModes(modes);
    EXPECT_EQ(intResult, 0);
    EXPECT_NE(modes.size(), 0);

    session->LockForControl();
    intResult = session->SetFocusMode(modes[0]);
    session->UnlockForControl();
    EXPECT_EQ(intResult, 0);
    intResult = session->GetFocusMode(focusMode);
    EXPECT_EQ(intResult, 0);

    EXPECT_EQ(focusMode, modes[0]);
    intResult = session->Start();
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_START);

    intResult = ((sptr<VideoOutput>&)videoOutput)->Start();
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_RECORDING);
    intResult = ((sptr<VideoOutput>&)videoOutput)->Stop();
    session->Stop();
}

/*
 * Feature: Framework
 * Function: Test profession video session flash mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test profession video session flash mode
 */
HWTEST_F(CameraSessionModuleTest, profession_video_session_moduletest_007, TestSize.Level1)
{
    SceneMode sceneMode = SceneMode::PROFESSIONAL_VIDEO;
    if (!IsSceneModeSupported(sceneMode)) {
        GTEST_SKIP();
    }
    sptr<CameraManager> cameraManagerObj = CameraManager::GetInstance();
    ASSERT_NE(cameraManagerObj, nullptr);

    std::vector<SceneMode> sceneModes = cameraManagerObj->GetSupportedModes(cameras_[0]);
    ASSERT_TRUE(sceneModes.size() != 0);

    sptr<CameraOutputCapability> modeAbility =
        cameraManagerObj->GetSupportedOutputCapability(cameras_[0], sceneMode);
    ASSERT_NE(modeAbility, nullptr);

    SelectProfiles wanted;
    wanted.preview.size_ = {640, 480};
    wanted.preview.format_ = CAMERA_FORMAT_YUV_420_SP;
    wanted.photo.size_ = {640, 480};
    wanted.photo.format_ = CAMERA_FORMAT_JPEG;
    wanted.video.size_ = {640, 480};
    wanted.video.format_ = CAMERA_FORMAT_YUV_420_SP;
    wanted.video.framerates_ = {30, 30};

    sptr<CaptureSessionForSys> captureSession = managerForSys_->CreateCaptureSessionForSys(sceneMode);
    ASSERT_NE(captureSession, nullptr);
    sptr<ProfessionSession> session = static_cast<ProfessionSession*>(captureSession.GetRefPtr());
    ASSERT_NE(session, nullptr);

    int32_t intResult = session->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(wanted.preview);
    ASSERT_NE(previewOutput, nullptr);

    intResult = session->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> videoOutput = CreateVideoOutput(wanted.video);
    ASSERT_NE(videoOutput, nullptr);

    intResult = session->AddOutput(videoOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session->CommitConfig();
    EXPECT_EQ(intResult, 0);

    bool isSupported = false;
    intResult = session->HasFlash(isSupported);
    EXPECT_EQ(isSupported, true);

    std::vector<FlashMode> modes = {};
    intResult = session->GetSupportedFlashModes(modes);
    EXPECT_EQ(intResult, 0);
    EXPECT_NE(modes.size(), 0);

    intResult = session->IsFlashModeSupported(modes[0], isSupported);
    EXPECT_EQ(intResult, 0);
    EXPECT_EQ(isSupported, true);

    session->LockForControl();
    intResult = session->SetFlashMode(modes[0]);
    EXPECT_EQ(intResult, 0);
    session->UnlockForControl();

    FlashMode mode;
    intResult = session->GetFlashMode(mode);
    EXPECT_EQ(intResult, 0);
    EXPECT_EQ(mode, modes[0]);
}

/*
 * Feature: Framework
 * Function: Test profession video session color effect
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test profession video session color effect
 */
HWTEST_F(CameraSessionModuleTest, profession_video_session_moduletest_008, TestSize.Level1)
{
    SceneMode sceneMode = SceneMode::PROFESSIONAL_VIDEO;
    if (!IsSceneModeSupported(sceneMode)) {
        GTEST_SKIP();
    }
    sptr<CameraManager> cameraManagerObj = CameraManager::GetInstance();
    ASSERT_NE(cameraManagerObj, nullptr);

    std::vector<SceneMode> sceneModes = cameraManagerObj->GetSupportedModes(cameras_[0]);
    ASSERT_TRUE(sceneModes.size() != 0);

    sptr<CameraOutputCapability> modeAbility =
        cameraManagerObj->GetSupportedOutputCapability(cameras_[0], sceneMode);
    ASSERT_NE(modeAbility, nullptr);

    SelectProfiles wanted;
    wanted.preview.size_ = {640, 480};
    wanted.preview.format_ = CAMERA_FORMAT_YUV_420_SP;
    wanted.photo.size_ = {640, 480};
    wanted.photo.format_ = CAMERA_FORMAT_JPEG;
    wanted.video.size_ = {640, 480};
    wanted.video.format_ = CAMERA_FORMAT_YUV_420_SP;
    wanted.video.framerates_ = {30, 30};

    sptr<CaptureSessionForSys> captureSession = managerForSys_->CreateCaptureSessionForSys(sceneMode);
    ASSERT_NE(captureSession, nullptr);
    sptr<ProfessionSession> session = static_cast<ProfessionSession*>(captureSession.GetRefPtr());
    ASSERT_NE(session, nullptr);

    int32_t intResult = session->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(wanted.preview);
    ASSERT_NE(previewOutput, nullptr);

    intResult = session->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> videoOutput = CreateVideoOutput(wanted.video);
    ASSERT_NE(videoOutput, nullptr);

    intResult = session->AddOutput(videoOutput);
    EXPECT_EQ(intResult, 0);


    intResult = session->CommitConfig();
    EXPECT_EQ(intResult, 0);
    std::vector<ColorEffect> colorEffects = {};
    intResult = session->GetSupportedColorEffects(colorEffects);
    EXPECT_EQ(intResult, 0);
    EXPECT_NE(colorEffects.size(), 0);

    session->LockForControl();
    intResult = session->SetColorEffect(colorEffects[0]);
    EXPECT_EQ(intResult, 0);
    session->UnlockForControl();

    ColorEffect colorEffect;
    intResult = session->GetColorEffect(colorEffect);
    EXPECT_EQ(intResult, 0);

    EXPECT_EQ(colorEffect, colorEffects[0]);
    intResult = session->Start();
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_START);

    intResult = ((sptr<VideoOutput>&)videoOutput)->Start();
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_RECORDING);
    intResult = ((sptr<VideoOutput>&)videoOutput)->Stop();
    session->Stop();
}

/*
 * Feature: Framework
 * Function: Test time lapse photo session with photo output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can add photo output into time lapse photo session
 */
HWTEST_F(CameraSessionModuleTest, time_lapse_photo_session_moduletest_001, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::TIMELAPSE_PHOTO)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::TIMELAPSE_PHOTO);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto photoProfiles = outputCapability->GetPhotoProfiles();
    ASSERT_FALSE(photoProfiles.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::TIMELAPSE_PHOTO);
    auto timeLapsePhotoSession = static_cast<TimeLapsePhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(timeLapsePhotoSession, nullptr);
    int32_t res = timeLapsePhotoSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = timeLapsePhotoSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(timeLapsePhotoSession->CanAddOutput(previewOutput));
    res = timeLapsePhotoSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoProfiles[0]);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_TRUE(timeLapsePhotoSession->CanAddOutput(photoOutput));
    res = timeLapsePhotoSession->AddOutput(photoOutput);
    EXPECT_EQ(res, 0);

    res = timeLapsePhotoSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = timeLapsePhotoSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);
    res = static_cast<PhotoOutput*>(photoOutput.GetRefPtr())->Capture();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);
    res = timeLapsePhotoSession->Stop();
    EXPECT_EQ(res, 0);
    res = timeLapsePhotoSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test time lapse photo session with video output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can not add video output into time lapse photo session
 */
HWTEST_F(CameraSessionModuleTest, time_lapse_photo_session_moduletest_002, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::TIMELAPSE_PHOTO)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::TIMELAPSE_PHOTO);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto videoProfiles = outputCapability->GetVideoProfiles();
    ASSERT_TRUE(videoProfiles.empty());
    auto outputCapabilityBase = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::VIDEO);
    ASSERT_NE(outputCapabilityBase, nullptr);
    auto videoProfilesBase = outputCapabilityBase->GetVideoProfiles();
    ASSERT_FALSE(videoProfilesBase.empty());

    auto captureSession = managerForSys_->CreateCaptureSessionForSys(SceneMode::TIMELAPSE_PHOTO);
    auto timeLapsePhotoSession = static_cast<TimeLapsePhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(timeLapsePhotoSession, nullptr);
    int32_t res = timeLapsePhotoSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = timeLapsePhotoSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(timeLapsePhotoSession->CanAddOutput(previewOutput));
    res = timeLapsePhotoSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfilesBase[0]);
    ASSERT_NE(videoOutput, nullptr);
    EXPECT_FALSE(timeLapsePhotoSession->CanAddOutput(videoOutput));
}

/*
 * Feature: Framework
 * Function: Test time lapse photo session try AE
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can start and stop try AE in time lapse photo session
 */
HWTEST_F(CameraSessionModuleTest, time_lapse_photo_session_moduletest_003, TestSize.Level0)
{
    SceneMode sceneMode = SceneMode::TIMELAPSE_PHOTO;
    if (!IsSceneModeSupported(sceneMode)) {
        GTEST_SKIP();
    }
    if (session_) {
        session_->Release();
        session_.clear();
    }
    sptr<CameraManager> cameraManager = CameraManager::GetInstance();
    ASSERT_NE(cameraManager, nullptr);
    auto cameras = cameraManager->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    sptr<CameraDevice> camera = cameras[0];
    ASSERT_NE(camera, nullptr);
    sptr<CameraOutputCapability> capability = cameraManager->GetSupportedOutputCapability(camera, sceneMode);
    ASSERT_NE(capability, nullptr);
    SelectProfiles wanted;
    wanted.preview.size_ = {640, 480};
    wanted.preview.format_ = CAMERA_FORMAT_YUV_420_SP;
    wanted.photo.size_ = {640, 480};
    wanted.photo.format_ = CAMERA_FORMAT_JPEG;
    wanted.video.size_ = {640, 480};
    wanted.video.format_ = CAMERA_FORMAT_YUV_420_SP;
    wanted.video.framerates_ = {30, 30};
    sptr<CaptureSessionForSys> captureSession = managerForSys_->CreateCaptureSessionForSys(sceneMode);
    ASSERT_NE(captureSession, nullptr);
    sptr<TimeLapsePhotoSession> session = reinterpret_cast<TimeLapsePhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(session, nullptr);
    int32_t status = session->BeginConfig();
    EXPECT_EQ(status, 0);
    sptr<CaptureInput> input = cameraManager->CreateCameraInput(camera);
    ASSERT_NE(input, nullptr);
    status = input->Open();
    EXPECT_EQ(status, 0);
    status = session->AddInput(input);
    EXPECT_EQ(status, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(wanted.preview);
    ASSERT_NE(previewOutput, nullptr);
    status = session->AddOutput(previewOutput);
    EXPECT_EQ(status, 0);
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(wanted.photo);
    ASSERT_NE(photoOutput, nullptr);
    status = session->AddOutput(photoOutput);
    EXPECT_EQ(status, 0);
    status = session->CommitConfig();
    EXPECT_EQ(status, 0);
    class ExposureInfoCallbackMock : public ExposureInfoCallback {
    public:
        void OnExposureInfoChanged(ExposureInfo info) override
        {
            EXPECT_EQ(info.exposureDurationValue, 1);
        }
    };
    session->SetExposureInfoCallback(make_shared<ExposureInfoCallbackMock>());
    static const camera_rational_t r = {
        .denominator = 1000000,
        .numerator = 1,
    };
    auto meta = make_shared<OHOS::Camera::CameraMetadata>(10, 100);
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_SENSOR_EXPOSURE_TIME, &r, 1), true);
    session->ProcessExposureChange(meta);

    class IsoInfoCallbackMock : public IsoInfoCallback {
    public:
        void OnIsoInfoChanged(IsoInfo info) override
        {
            EXPECT_EQ(info.isoValue, 1);
        }
    };
    session->SetIsoInfoCallback(make_shared<IsoInfoCallbackMock>());
    static const uint32_t iso = 1;
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_ISO_VALUE, &iso, 1), true);
    session->ProcessIsoInfoChange(meta);

    static const uint32_t lumination = 256;
    class LuminationInfoCallbackMock : public LuminationInfoCallback {
    public:
        void OnLuminationInfoChanged(LuminationInfo info) override
        {
            EXPECT_EQ((int32_t)info.luminationValue, 1);
        }
    };
    session->SetLuminationInfoCallback(make_shared<LuminationInfoCallbackMock>());
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_ALGO_MEAN_Y, &lumination, 1), true);
    session->ProcessLuminationChange(meta);

    static const int32_t value = 1;
    class TryAEInfoCallbackMock : public TryAEInfoCallback {
    public:
        void OnTryAEInfoChanged(TryAEInfo info) override
        {
            EXPECT_EQ(info.isTryAEDone, true);
            EXPECT_EQ(info.isTryAEHintNeeded, true);
            EXPECT_EQ(info.previewType, TimeLapsePreviewType::DARK);
            EXPECT_EQ(info.captureInterval, 1);
        }
    };
    session->SetTryAEInfoCallback(make_shared<TryAEInfoCallbackMock>());
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_TIME_LAPSE_TRYAE_DONE, &value, 1), true);
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_TIME_LAPSE_TRYAE_HINT, &value, 1), true);
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_TIME_LAPSE_PREVIEW_TYPE, &value, 1), true);
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_TIME_LAPSE_CAPTURE_INTERVAL, &value, 1), true);
    session->ProcessSetTryAEChange(meta);

    EXPECT_EQ(meta->addEntry(OHOS_CAMERA_MACRO_STATUS, &value, 1), true);
    session->ProcessPhysicalCameraSwitch(meta);

    bool isTryAENeeded;
    status = session->IsTryAENeeded(isTryAENeeded);
    EXPECT_EQ(status, 0);
    if (isTryAENeeded) {
        session->LockForControl();
        status = session->StartTryAE();
        session->UnlockForControl();
        EXPECT_EQ(status, 0);
        session->LockForControl();
        status = session->StopTryAE();
        session->UnlockForControl();
        EXPECT_EQ(status, 0);
    }
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test time lapse photo session set time lapse interval
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can set time lapse interval into time lapse photo session
 */
HWTEST_F(CameraSessionModuleTest, time_lapse_photo_session_moduletest_004, TestSize.Level0)
{
    SceneMode sceneMode = SceneMode::TIMELAPSE_PHOTO;
    if (!IsSceneModeSupported(sceneMode)) {
        GTEST_SKIP();
    }
    if (session_) {
        session_->Release();
        session_.clear();
    }
    sptr<CameraManager> cameraManager = CameraManager::GetInstance();
    ASSERT_NE(cameraManager, nullptr);
    auto cameras = cameraManager->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    sptr<CameraDevice> camera = cameras[0];
    ASSERT_NE(camera, nullptr);
    sptr<CameraOutputCapability> capability = cameraManager->GetSupportedOutputCapability(camera, sceneMode);
    ASSERT_NE(capability, nullptr);
    SelectProfiles wanted;
    wanted.preview.size_ = {640, 480};
    wanted.preview.format_ = CAMERA_FORMAT_YUV_420_SP;
    wanted.photo.size_ = {640, 480};
    wanted.photo.format_ = CAMERA_FORMAT_JPEG;
    wanted.video.size_ = {640, 480};
    wanted.video.format_ = CAMERA_FORMAT_YUV_420_SP;
    wanted.video.framerates_ = {30, 30};
    sptr<CaptureSessionForSys> captureSession = managerForSys_->CreateCaptureSessionForSys(sceneMode);
    ASSERT_NE(captureSession, nullptr);
    sptr<TimeLapsePhotoSession> session = reinterpret_cast<TimeLapsePhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(session, nullptr);
    int32_t status = session->BeginConfig();
    EXPECT_EQ(status, 0);
    sptr<CaptureInput> input = cameraManager->CreateCameraInput(camera);
    ASSERT_NE(input, nullptr);
    status = input->Open();
    EXPECT_EQ(status, 0);
    status = session->AddInput(input);
    EXPECT_EQ(status, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(wanted.preview);
    ASSERT_NE(previewOutput, nullptr);
    status = session->AddOutput(previewOutput);
    EXPECT_EQ(status, 0);
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(wanted.photo);
    ASSERT_NE(photoOutput, nullptr);
    status = session->AddOutput(photoOutput);
    EXPECT_EQ(status, 0);
    status = session->CommitConfig();
    EXPECT_EQ(status, 0);
    class ExposureInfoCallbackMock : public ExposureInfoCallback {
    public:
        void OnExposureInfoChanged(ExposureInfo info) override
        {
            EXPECT_EQ(info.exposureDurationValue, 1);
        }
    };
    session->SetExposureInfoCallback(make_shared<ExposureInfoCallbackMock>());
    static const camera_rational_t r = {
        .denominator = 1000000,
        .numerator = 1,
    };
    auto meta = make_shared<OHOS::Camera::CameraMetadata>(10, 100);
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_SENSOR_EXPOSURE_TIME, &r, 1), true);
    session->ProcessExposureChange(meta);

    class IsoInfoCallbackMock : public IsoInfoCallback {
    public:
        void OnIsoInfoChanged(IsoInfo info) override
        {
            EXPECT_EQ(info.isoValue, 1);
        }
    };
    session->SetIsoInfoCallback(make_shared<IsoInfoCallbackMock>());
    static const uint32_t iso = 1;
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_ISO_VALUE, &iso, 1), true);
    session->ProcessIsoInfoChange(meta);

    static const uint32_t lumination = 256;
    class LuminationInfoCallbackMock : public LuminationInfoCallback {
    public:
        void OnLuminationInfoChanged(LuminationInfo info) override
        {
            EXPECT_EQ((int32_t)info.luminationValue, 1);
        }
    };
    session->SetLuminationInfoCallback(make_shared<LuminationInfoCallbackMock>());
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_ALGO_MEAN_Y, &lumination, 1), true);
    session->ProcessLuminationChange(meta);

    static const int32_t value = 1;
    class TryAEInfoCallbackMock : public TryAEInfoCallback {
    public:
        void OnTryAEInfoChanged(TryAEInfo info) override
        {
            EXPECT_EQ(info.isTryAEDone, true);
            EXPECT_EQ(info.isTryAEHintNeeded, true);
            EXPECT_EQ(info.previewType, TimeLapsePreviewType::DARK);
            EXPECT_EQ(info.captureInterval, 1);
        }
    };
    session->SetTryAEInfoCallback(make_shared<TryAEInfoCallbackMock>());
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_TIME_LAPSE_TRYAE_DONE, &value, 1), true);
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_TIME_LAPSE_TRYAE_HINT, &value, 1), true);
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_TIME_LAPSE_PREVIEW_TYPE, &value, 1), true);
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_TIME_LAPSE_CAPTURE_INTERVAL, &value, 1), true);
    session->ProcessSetTryAEChange(meta);

    EXPECT_EQ(meta->addEntry(OHOS_CAMERA_MACRO_STATUS, &value, 1), true);
    session->ProcessPhysicalCameraSwitch(meta);

    vector<int32_t> range;
    status = session->GetSupportedTimeLapseIntervalRange(range);
    EXPECT_EQ(status, 0);
    if (!range.empty()) {
        session->LockForControl();
        status = session->SetTimeLapseInterval(range[0]);
        session->UnlockForControl();
        EXPECT_EQ(status, 0);
        int32_t interval;
        status = session->GetTimeLapseInterval(interval);
        EXPECT_EQ(status, 0);
        EXPECT_EQ(interval, range[0]);
    }
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test time lapse photo session set exposure
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can set exposure into time lapse photo session
 */
HWTEST_F(CameraSessionModuleTest, time_lapse_photo_session_moduletest_005, TestSize.Level0)
{
    SceneMode sceneMode = SceneMode::TIMELAPSE_PHOTO;
    if (!IsSceneModeSupported(sceneMode)) {
        GTEST_SKIP();
    }
    if (session_) {
        session_->Release();
        session_.clear();
    }
    sptr<CameraManager> cameraManager = CameraManager::GetInstance();
    ASSERT_NE(cameraManager, nullptr);
    auto cameras = cameraManager->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    sptr<CameraDevice> camera = cameras[0];
    ASSERT_NE(camera, nullptr);
    sptr<CameraOutputCapability> capability = cameraManager->GetSupportedOutputCapability(camera, sceneMode);
    ASSERT_NE(capability, nullptr);
    SelectProfiles wanted;
    wanted.preview.size_ = {640, 480};
    wanted.preview.format_ = CAMERA_FORMAT_YUV_420_SP;
    wanted.photo.size_ = {640, 480};
    wanted.photo.format_ = CAMERA_FORMAT_JPEG;
    wanted.video.size_ = {640, 480};
    wanted.video.format_ = CAMERA_FORMAT_YUV_420_SP;
    wanted.video.framerates_ = {30, 30};
    sptr<CaptureSessionForSys> captureSession = managerForSys_->CreateCaptureSessionForSys(sceneMode);
    ASSERT_NE(captureSession, nullptr);
    sptr<TimeLapsePhotoSession> session = reinterpret_cast<TimeLapsePhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(session, nullptr);
    int32_t status = session->BeginConfig();
    EXPECT_EQ(status, 0);
    sptr<CaptureInput> input = cameraManager->CreateCameraInput(camera);
    ASSERT_NE(input, nullptr);
    status = input->Open();
    EXPECT_EQ(status, 0);
    status = session->AddInput(input);
    EXPECT_EQ(status, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(wanted.preview);
    ASSERT_NE(previewOutput, nullptr);
    status = session->AddOutput(previewOutput);
    EXPECT_EQ(status, 0);
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(wanted.photo);
    ASSERT_NE(photoOutput, nullptr);
    status = session->AddOutput(photoOutput);
    EXPECT_EQ(status, 0);
    status = session->CommitConfig();
    EXPECT_EQ(status, 0);
    class ExposureInfoCallbackMock : public ExposureInfoCallback {
    public:
        void OnExposureInfoChanged(ExposureInfo info) override
        {
            EXPECT_EQ(info.exposureDurationValue, 1);
        }
    };
    session->SetExposureInfoCallback(make_shared<ExposureInfoCallbackMock>());
    static const camera_rational_t r = {
        .denominator = 1000000,
        .numerator = 1,
    };
    auto meta = make_shared<OHOS::Camera::CameraMetadata>(10, 100);
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_SENSOR_EXPOSURE_TIME, &r, 1), true);
    session->ProcessExposureChange(meta);

    class IsoInfoCallbackMock : public IsoInfoCallback {
    public:
        void OnIsoInfoChanged(IsoInfo info) override
        {
            EXPECT_EQ(info.isoValue, 1);
        }
    };
    session->SetIsoInfoCallback(make_shared<IsoInfoCallbackMock>());
    static const uint32_t iso = 1;
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_ISO_VALUE, &iso, 1), true);
    session->ProcessIsoInfoChange(meta);

    static const uint32_t lumination = 256;
    class LuminationInfoCallbackMock : public LuminationInfoCallback {
    public:
        void OnLuminationInfoChanged(LuminationInfo info) override
        {
            EXPECT_EQ((int32_t)info.luminationValue, 1);
        }
    };
    session->SetLuminationInfoCallback(make_shared<LuminationInfoCallbackMock>());
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_ALGO_MEAN_Y, &lumination, 1), true);
    session->ProcessLuminationChange(meta);

    static const int32_t value = 1;
    class TryAEInfoCallbackMock : public TryAEInfoCallback {
    public:
        void OnTryAEInfoChanged(TryAEInfo info) override
        {
            EXPECT_EQ(info.isTryAEDone, true);
            EXPECT_EQ(info.isTryAEHintNeeded, true);
            EXPECT_EQ(info.previewType, TimeLapsePreviewType::DARK);
            EXPECT_EQ(info.captureInterval, 1);
        }
    };
    session->SetTryAEInfoCallback(make_shared<TryAEInfoCallbackMock>());
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_TIME_LAPSE_TRYAE_DONE, &value, 1), true);
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_TIME_LAPSE_TRYAE_HINT, &value, 1), true);
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_TIME_LAPSE_PREVIEW_TYPE, &value, 1), true);
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_TIME_LAPSE_CAPTURE_INTERVAL, &value, 1), true);
    session->ProcessSetTryAEChange(meta);

    EXPECT_EQ(meta->addEntry(OHOS_CAMERA_MACRO_STATUS, &value, 1), true);
    session->ProcessPhysicalCameraSwitch(meta);

    session->LockForControl();
    status = session->SetTimeLapseRecordState(TimeLapseRecordState::RECORDING);
    session->UnlockForControl();
    EXPECT_EQ(status, 0);
    session->LockForControl();
    status = session->SetTimeLapsePreviewType(TimeLapsePreviewType::DARK);
    session->UnlockForControl();
    EXPECT_EQ(status, 0);
    session->LockForControl();
    status = session->SetExposureHintMode(ExposureHintMode::EXPOSURE_HINT_MODE_OFF);
    session->UnlockForControl();
    EXPECT_EQ(status, 0);

    vector<uint32_t> exposureRange;
    status = session->GetSupportedExposureRange(exposureRange);
    EXPECT_EQ(status, 0);
    if (!exposureRange.empty()) {
        session->LockForControl();
        status = session->SetExposure(exposureRange[0]);
        session->UnlockForControl();
        EXPECT_EQ(status, 0);
        uint32_t exposure;
        status = session->GetExposure(exposure);
        EXPECT_EQ(status, 0);
        EXPECT_EQ(exposure, exposureRange[0]);
    }
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test time lapse photo session set exposure metering mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can set exposure metering mode into time lapse photo session
 */
HWTEST_F(CameraSessionModuleTest, time_lapse_photo_session_moduletest_006, TestSize.Level0)
{
    SceneMode sceneMode = SceneMode::TIMELAPSE_PHOTO;
    if (!IsSceneModeSupported(sceneMode)) {
        GTEST_SKIP();
    }
    if (session_) {
        session_->Release();
        session_.clear();
    }
    sptr<CameraManager> cameraManager = CameraManager::GetInstance();
    ASSERT_NE(cameraManager, nullptr);
    auto cameras = cameraManager->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    sptr<CameraDevice> camera = cameras[0];
    ASSERT_NE(camera, nullptr);
    sptr<CameraOutputCapability> capability = cameraManager->GetSupportedOutputCapability(camera, sceneMode);
    ASSERT_NE(capability, nullptr);
    SelectProfiles wanted;
    wanted.preview.size_ = {640, 480};
    wanted.preview.format_ = CAMERA_FORMAT_YUV_420_SP;
    wanted.photo.size_ = {640, 480};
    wanted.photo.format_ = CAMERA_FORMAT_JPEG;
    wanted.video.size_ = {640, 480};
    wanted.video.format_ = CAMERA_FORMAT_YUV_420_SP;
    wanted.video.framerates_ = {30, 30};
    sptr<CaptureSessionForSys> captureSession = managerForSys_->CreateCaptureSessionForSys(sceneMode);
    ASSERT_NE(captureSession, nullptr);
    sptr<TimeLapsePhotoSession> session = reinterpret_cast<TimeLapsePhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(session, nullptr);
    int32_t status = session->BeginConfig();
    EXPECT_EQ(status, 0);
    sptr<CaptureInput> input = cameraManager->CreateCameraInput(camera);
    ASSERT_NE(input, nullptr);
    status = input->Open();
    EXPECT_EQ(status, 0);
    status = session->AddInput(input);
    EXPECT_EQ(status, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(wanted.preview);
    ASSERT_NE(previewOutput, nullptr);
    status = session->AddOutput(previewOutput);
    EXPECT_EQ(status, 0);
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(wanted.photo);
    ASSERT_NE(photoOutput, nullptr);
    status = session->AddOutput(photoOutput);
    EXPECT_EQ(status, 0);
    status = session->CommitConfig();
    EXPECT_EQ(status, 0);
    class ExposureInfoCallbackMock : public ExposureInfoCallback {
    public:
        void OnExposureInfoChanged(ExposureInfo info) override
        {
            EXPECT_EQ(info.exposureDurationValue, 1);
        }
    };
    session->SetExposureInfoCallback(make_shared<ExposureInfoCallbackMock>());
    static const camera_rational_t r = {
        .denominator = 1000000,
        .numerator = 1,
    };
    auto meta = make_shared<OHOS::Camera::CameraMetadata>(10, 100);
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_SENSOR_EXPOSURE_TIME, &r, 1), true);
    session->ProcessExposureChange(meta);

    class IsoInfoCallbackMock : public IsoInfoCallback {
    public:
        void OnIsoInfoChanged(IsoInfo info) override
        {
            EXPECT_EQ(info.isoValue, 1);
        }
    };
    session->SetIsoInfoCallback(make_shared<IsoInfoCallbackMock>());
    static const uint32_t iso = 1;
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_ISO_VALUE, &iso, 1), true);
    session->ProcessIsoInfoChange(meta);

    static const uint32_t lumination = 256;
    class LuminationInfoCallbackMock : public LuminationInfoCallback {
    public:
        void OnLuminationInfoChanged(LuminationInfo info) override
        {
            EXPECT_EQ((int32_t)info.luminationValue, 1);
        }
    };
    session->SetLuminationInfoCallback(make_shared<LuminationInfoCallbackMock>());
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_ALGO_MEAN_Y, &lumination, 1), true);
    session->ProcessLuminationChange(meta);

    static const int32_t value = 1;
    class TryAEInfoCallbackMock : public TryAEInfoCallback {
    public:
        void OnTryAEInfoChanged(TryAEInfo info) override
        {
            EXPECT_EQ(info.isTryAEDone, true);
            EXPECT_EQ(info.isTryAEHintNeeded, true);
            EXPECT_EQ(info.previewType, TimeLapsePreviewType::DARK);
            EXPECT_EQ(info.captureInterval, 1);
        }
    };
    session->SetTryAEInfoCallback(make_shared<TryAEInfoCallbackMock>());
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_TIME_LAPSE_TRYAE_DONE, &value, 1), true);
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_TIME_LAPSE_TRYAE_HINT, &value, 1), true);
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_TIME_LAPSE_PREVIEW_TYPE, &value, 1), true);
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_TIME_LAPSE_CAPTURE_INTERVAL, &value, 1), true);
    session->ProcessSetTryAEChange(meta);

    EXPECT_EQ(meta->addEntry(OHOS_CAMERA_MACRO_STATUS, &value, 1), true);
    session->ProcessPhysicalCameraSwitch(meta);

    session->LockForControl();
    status = session->SetTimeLapseRecordState(TimeLapseRecordState::RECORDING);
    session->UnlockForControl();
    EXPECT_EQ(status, 0);
    session->LockForControl();
    status = session->SetTimeLapsePreviewType(TimeLapsePreviewType::DARK);
    session->UnlockForControl();
    EXPECT_EQ(status, 0);
    session->LockForControl();
    status = session->SetExposureHintMode(ExposureHintMode::EXPOSURE_HINT_MODE_OFF);
    session->UnlockForControl();
    EXPECT_EQ(status, 0);

    vector<MeteringMode> modes;
    status = session->GetSupportedMeteringModes(modes);
    EXPECT_EQ(status, 0);
    if (!modes.empty()) {
        bool supported;
        int32_t i = METERING_MODE_CENTER_WEIGHTED;
        for (;i <= METERING_MODE_SPOT; i++) {
            status = session->IsExposureMeteringModeSupported(METERING_MODE_CENTER_WEIGHTED, supported);
            EXPECT_EQ(status, 0);
            if (status == 0 && supported) {
                break;
            }
        }
        if (supported) {
            session->LockForControl();
            status = session->SetExposureMeteringMode(static_cast<MeteringMode>(i));
            session->UnlockForControl();
            EXPECT_EQ(status, 0);
            MeteringMode mode;
            status = session->GetExposureMeteringMode(mode);
            EXPECT_EQ(status, 0);
            EXPECT_EQ(mode, i);
        }
    }
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test time lapse photo session set iso range
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can set iso range into time lapse photo session
 */
HWTEST_F(CameraSessionModuleTest, time_lapse_photo_session_moduletest_007, TestSize.Level0)
{
    SceneMode sceneMode = SceneMode::TIMELAPSE_PHOTO;
    if (!IsSceneModeSupported(sceneMode)) {
        GTEST_SKIP();
    }
    if (session_) {
        session_->Release();
        session_.clear();
    }
    sptr<CameraManager> cameraManager = CameraManager::GetInstance();
    ASSERT_NE(cameraManager, nullptr);
    auto cameras = cameraManager->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    sptr<CameraDevice> camera = cameras[0];
    ASSERT_NE(camera, nullptr);
    sptr<CameraOutputCapability> capability = cameraManager->GetSupportedOutputCapability(camera, sceneMode);
    ASSERT_NE(capability, nullptr);
    SelectProfiles wanted;
    wanted.preview.size_ = {640, 480};
    wanted.preview.format_ = CAMERA_FORMAT_YUV_420_SP;
    wanted.photo.size_ = {640, 480};
    wanted.photo.format_ = CAMERA_FORMAT_JPEG;
    wanted.video.size_ = {640, 480};
    wanted.video.format_ = CAMERA_FORMAT_YUV_420_SP;
    wanted.video.framerates_ = {30, 30};
    sptr<CaptureSessionForSys> captureSession = managerForSys_->CreateCaptureSessionForSys(sceneMode);
    ASSERT_NE(captureSession, nullptr);
    sptr<TimeLapsePhotoSession> session = reinterpret_cast<TimeLapsePhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(session, nullptr);
    int32_t status = session->BeginConfig();
    EXPECT_EQ(status, 0);
    sptr<CaptureInput> input = cameraManager->CreateCameraInput(camera);
    ASSERT_NE(input, nullptr);
    status = input->Open();
    EXPECT_EQ(status, 0);
    status = session->AddInput(input);
    EXPECT_EQ(status, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(wanted.preview);
    ASSERT_NE(previewOutput, nullptr);
    status = session->AddOutput(previewOutput);
    EXPECT_EQ(status, 0);
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(wanted.photo);
    ASSERT_NE(photoOutput, nullptr);
    status = session->AddOutput(photoOutput);
    EXPECT_EQ(status, 0);
    status = session->CommitConfig();
    EXPECT_EQ(status, 0);
    class ExposureInfoCallbackMock : public ExposureInfoCallback {
    public:
        void OnExposureInfoChanged(ExposureInfo info) override
        {
            EXPECT_EQ(info.exposureDurationValue, 1);
        }
    };
    session->SetExposureInfoCallback(make_shared<ExposureInfoCallbackMock>());
    static const camera_rational_t r = {
        .denominator = 1000000,
        .numerator = 1,
    };
    auto meta = make_shared<OHOS::Camera::CameraMetadata>(10, 100);
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_SENSOR_EXPOSURE_TIME, &r, 1), true);
    session->ProcessExposureChange(meta);

    class IsoInfoCallbackMock : public IsoInfoCallback {
    public:
        void OnIsoInfoChanged(IsoInfo info) override
        {
            EXPECT_EQ(info.isoValue, 1);
        }
    };
    session->SetIsoInfoCallback(make_shared<IsoInfoCallbackMock>());
    static const uint32_t iso = 1;
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_ISO_VALUE, &iso, 1), true);
    session->ProcessIsoInfoChange(meta);

    static const uint32_t lumination = 256;
    class LuminationInfoCallbackMock : public LuminationInfoCallback {
    public:
        void OnLuminationInfoChanged(LuminationInfo info) override
        {
            EXPECT_EQ((int32_t)info.luminationValue, 1);
        }
    };
    session->SetLuminationInfoCallback(make_shared<LuminationInfoCallbackMock>());
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_ALGO_MEAN_Y, &lumination, 1), true);
    session->ProcessLuminationChange(meta);

    static const int32_t value = 1;
    class TryAEInfoCallbackMock : public TryAEInfoCallback {
    public:
        void OnTryAEInfoChanged(TryAEInfo info) override
        {
            EXPECT_EQ(info.isTryAEDone, true);
            EXPECT_EQ(info.isTryAEHintNeeded, true);
            EXPECT_EQ(info.previewType, TimeLapsePreviewType::DARK);
            EXPECT_EQ(info.captureInterval, 1);
        }
    };
    session->SetTryAEInfoCallback(make_shared<TryAEInfoCallbackMock>());
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_TIME_LAPSE_TRYAE_DONE, &value, 1), true);
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_TIME_LAPSE_TRYAE_HINT, &value, 1), true);
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_TIME_LAPSE_PREVIEW_TYPE, &value, 1), true);
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_TIME_LAPSE_CAPTURE_INTERVAL, &value, 1), true);
    session->ProcessSetTryAEChange(meta);

    EXPECT_EQ(meta->addEntry(OHOS_CAMERA_MACRO_STATUS, &value, 1), true);
    session->ProcessPhysicalCameraSwitch(meta);

    session->LockForControl();
    status = session->SetTimeLapseRecordState(TimeLapseRecordState::RECORDING);
    session->UnlockForControl();
    EXPECT_EQ(status, 0);
    session->LockForControl();
    status = session->SetTimeLapsePreviewType(TimeLapsePreviewType::DARK);
    session->UnlockForControl();
    EXPECT_EQ(status, 0);
    session->LockForControl();
    status = session->SetExposureHintMode(ExposureHintMode::EXPOSURE_HINT_MODE_OFF);
    session->UnlockForControl();
    EXPECT_EQ(status, 0);

    bool isManualIsoSupported;
    status = session->IsManualIsoSupported(isManualIsoSupported);
    EXPECT_EQ(status, 0);
    if (isManualIsoSupported) {
        vector<int32_t> isoRange;
        status = session->GetIsoRange(isoRange);
        EXPECT_EQ(status, 0);
        if (!isoRange.empty()) {
            session->LockForControl();
            status = session->SetIso(isoRange[0]);
            session->UnlockForControl();
            EXPECT_EQ(status, 0);
            int32_t iso;
            status = session->GetIso(iso);
            EXPECT_EQ(status, 0);
            EXPECT_EQ(iso, isoRange[0]);
        }
    }
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test time lapse photo session set white balance mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can set white balance mode into time lapse photo session
 */
HWTEST_F(CameraSessionModuleTest, time_lapse_photo_session_moduletest_008, TestSize.Level0)
{
    SceneMode sceneMode = SceneMode::TIMELAPSE_PHOTO;
    if (!IsSceneModeSupported(sceneMode)) {
        GTEST_SKIP();
    }
    if (session_) {
        session_->Release();
        session_.clear();
    }
    sptr<CameraManager> cameraManager = CameraManager::GetInstance();
    ASSERT_NE(cameraManager, nullptr);
    auto cameras = cameraManager->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    sptr<CameraDevice> camera = cameras[0];
    ASSERT_NE(camera, nullptr);
    sptr<CameraOutputCapability> capability = cameraManager->GetSupportedOutputCapability(camera, sceneMode);
    ASSERT_NE(capability, nullptr);
    SelectProfiles wanted;
    wanted.preview.size_ = {640, 480};
    wanted.preview.format_ = CAMERA_FORMAT_YUV_420_SP;
    wanted.photo.size_ = {640, 480};
    wanted.photo.format_ = CAMERA_FORMAT_JPEG;
    wanted.video.size_ = {640, 480};
    wanted.video.format_ = CAMERA_FORMAT_YUV_420_SP;
    wanted.video.framerates_ = {30, 30};
    sptr<CaptureSessionForSys> captureSession = managerForSys_->CreateCaptureSessionForSys(sceneMode);
    ASSERT_NE(captureSession, nullptr);
    sptr<TimeLapsePhotoSession> session = reinterpret_cast<TimeLapsePhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(session, nullptr);
    int32_t status = session->BeginConfig();
    EXPECT_EQ(status, 0);
    sptr<CaptureInput> input = cameraManager->CreateCameraInput(camera);
    ASSERT_NE(input, nullptr);
    status = input->Open();
    EXPECT_EQ(status, 0);
    status = session->AddInput(input);
    EXPECT_EQ(status, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(wanted.preview);
    ASSERT_NE(previewOutput, nullptr);
    status = session->AddOutput(previewOutput);
    EXPECT_EQ(status, 0);
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(wanted.photo);
    ASSERT_NE(photoOutput, nullptr);
    status = session->AddOutput(photoOutput);
    EXPECT_EQ(status, 0);
    status = session->CommitConfig();
    EXPECT_EQ(status, 0);
    class ExposureInfoCallbackMock : public ExposureInfoCallback {
    public:
        void OnExposureInfoChanged(ExposureInfo info) override
        {
            EXPECT_EQ(info.exposureDurationValue, 1);
        }
    };
    session->SetExposureInfoCallback(make_shared<ExposureInfoCallbackMock>());
    static const camera_rational_t r = {
        .denominator = 1000000,
        .numerator = 1,
    };
    auto meta = make_shared<OHOS::Camera::CameraMetadata>(10, 100);
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_SENSOR_EXPOSURE_TIME, &r, 1), true);
    session->ProcessExposureChange(meta);

    class IsoInfoCallbackMock : public IsoInfoCallback {
    public:
        void OnIsoInfoChanged(IsoInfo info) override
        {
            EXPECT_EQ(info.isoValue, 1);
        }
    };
    session->SetIsoInfoCallback(make_shared<IsoInfoCallbackMock>());
    static const uint32_t iso = 1;
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_ISO_VALUE, &iso, 1), true);
    session->ProcessIsoInfoChange(meta);

    static const uint32_t lumination = 256;
    class LuminationInfoCallbackMock : public LuminationInfoCallback {
    public:
        void OnLuminationInfoChanged(LuminationInfo info) override
        {
            EXPECT_EQ((int32_t)info.luminationValue, 1);
        }
    };
    session->SetLuminationInfoCallback(make_shared<LuminationInfoCallbackMock>());
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_ALGO_MEAN_Y, &lumination, 1), true);
    session->ProcessLuminationChange(meta);

    static const int32_t value = 1;
    class TryAEInfoCallbackMock : public TryAEInfoCallback {
    public:
        void OnTryAEInfoChanged(TryAEInfo info) override
        {
            EXPECT_EQ(info.isTryAEDone, true);
            EXPECT_EQ(info.isTryAEHintNeeded, true);
            EXPECT_EQ(info.previewType, TimeLapsePreviewType::DARK);
            EXPECT_EQ(info.captureInterval, 1);
        }
    };
    session->SetTryAEInfoCallback(make_shared<TryAEInfoCallbackMock>());
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_TIME_LAPSE_TRYAE_DONE, &value, 1), true);
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_TIME_LAPSE_TRYAE_HINT, &value, 1), true);
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_TIME_LAPSE_PREVIEW_TYPE, &value, 1), true);
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_TIME_LAPSE_CAPTURE_INTERVAL, &value, 1), true);
    session->ProcessSetTryAEChange(meta);

    EXPECT_EQ(meta->addEntry(OHOS_CAMERA_MACRO_STATUS, &value, 1), true);
    session->ProcessPhysicalCameraSwitch(meta);

    session->LockForControl();
    status = session->SetTimeLapseRecordState(TimeLapseRecordState::RECORDING);
    session->UnlockForControl();
    EXPECT_EQ(status, 0);
    session->LockForControl();
    status = session->SetTimeLapsePreviewType(TimeLapsePreviewType::DARK);
    session->UnlockForControl();
    EXPECT_EQ(status, 0);
    session->LockForControl();
    status = session->SetExposureHintMode(ExposureHintMode::EXPOSURE_HINT_MODE_OFF);
    session->UnlockForControl();
    EXPECT_EQ(status, 0);

    vector<WhiteBalanceMode> wbModes;
    status = session->GetSupportedWhiteBalanceModes(wbModes);
    EXPECT_EQ(status, 0);
    if (!wbModes.empty()) {
        bool isWhiteBalanceModeSupported;
        status = session->IsWhiteBalanceModeSupported(wbModes[0], isWhiteBalanceModeSupported);
        EXPECT_EQ(status, 0);
        if (isWhiteBalanceModeSupported) {
            session->LockForControl();
            status = session->SetWhiteBalanceMode(wbModes[0]);
            session->UnlockForControl();
            EXPECT_EQ(status, 0);
            WhiteBalanceMode mode;
            status = session->GetWhiteBalanceMode(mode);
            EXPECT_EQ(status, 0);
            EXPECT_EQ(mode, wbModes[0]);
        }
    }
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test time lapse photo session set white balance range
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can set white balance range into time lapse photo session
 */
HWTEST_F(CameraSessionModuleTest, time_lapse_photo_session_moduletest_009, TestSize.Level0)
{
    SceneMode sceneMode = SceneMode::TIMELAPSE_PHOTO;
    if (!IsSceneModeSupported(sceneMode)) {
        GTEST_SKIP();
    }
    if (session_) {
        session_->Release();
        session_.clear();
    }
    sptr<CameraManager> cameraManager = CameraManager::GetInstance();
    ASSERT_NE(cameraManager, nullptr);
    auto cameras = cameraManager->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    sptr<CameraDevice> camera = cameras[0];
    ASSERT_NE(camera, nullptr);
    sptr<CameraOutputCapability> capability = cameraManager->GetSupportedOutputCapability(camera, sceneMode);
    ASSERT_NE(capability, nullptr);
    SelectProfiles wanted;
    wanted.preview.size_ = {640, 480};
    wanted.preview.format_ = CAMERA_FORMAT_YUV_420_SP;
    wanted.photo.size_ = {640, 480};
    wanted.photo.format_ = CAMERA_FORMAT_JPEG;
    wanted.video.size_ = {640, 480};
    wanted.video.format_ = CAMERA_FORMAT_YUV_420_SP;
    wanted.video.framerates_ = {30, 30};
    sptr<CaptureSessionForSys> captureSession = managerForSys_->CreateCaptureSessionForSys(sceneMode);
    ASSERT_NE(captureSession, nullptr);
    sptr<TimeLapsePhotoSession> session = reinterpret_cast<TimeLapsePhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(session, nullptr);
    int32_t status = session->BeginConfig();
    EXPECT_EQ(status, 0);
    sptr<CaptureInput> input = cameraManager->CreateCameraInput(camera);
    ASSERT_NE(input, nullptr);
    status = input->Open();
    EXPECT_EQ(status, 0);
    status = session->AddInput(input);
    EXPECT_EQ(status, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(wanted.preview);
    ASSERT_NE(previewOutput, nullptr);
    status = session->AddOutput(previewOutput);
    EXPECT_EQ(status, 0);
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(wanted.photo);
    ASSERT_NE(photoOutput, nullptr);
    status = session->AddOutput(photoOutput);
    EXPECT_EQ(status, 0);
    status = session->CommitConfig();
    EXPECT_EQ(status, 0);
    class ExposureInfoCallbackMock : public ExposureInfoCallback {
    public:
        void OnExposureInfoChanged(ExposureInfo info) override
        {
            EXPECT_EQ(info.exposureDurationValue, 1);
        }
    };
    session->SetExposureInfoCallback(make_shared<ExposureInfoCallbackMock>());
    static const camera_rational_t r = {
        .denominator = 1000000,
        .numerator = 1,
    };
    auto meta = make_shared<OHOS::Camera::CameraMetadata>(10, 100);
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_SENSOR_EXPOSURE_TIME, &r, 1), true);
    session->ProcessExposureChange(meta);

    class IsoInfoCallbackMock : public IsoInfoCallback {
    public:
        void OnIsoInfoChanged(IsoInfo info) override
        {
            EXPECT_EQ(info.isoValue, 1);
        }
    };
    session->SetIsoInfoCallback(make_shared<IsoInfoCallbackMock>());
    static const uint32_t iso = 1;
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_ISO_VALUE, &iso, 1), true);
    session->ProcessIsoInfoChange(meta);

    static const uint32_t lumination = 256;
    class LuminationInfoCallbackMock : public LuminationInfoCallback {
    public:
        void OnLuminationInfoChanged(LuminationInfo info) override
        {
            EXPECT_EQ((int32_t)info.luminationValue, 1);
        }
    };
    session->SetLuminationInfoCallback(make_shared<LuminationInfoCallbackMock>());
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_ALGO_MEAN_Y, &lumination, 1), true);
    session->ProcessLuminationChange(meta);

    static const int32_t value = 1;
    class TryAEInfoCallbackMock : public TryAEInfoCallback {
    public:
        void OnTryAEInfoChanged(TryAEInfo info) override
        {
            EXPECT_EQ(info.isTryAEDone, true);
            EXPECT_EQ(info.isTryAEHintNeeded, true);
            EXPECT_EQ(info.previewType, TimeLapsePreviewType::DARK);
            EXPECT_EQ(info.captureInterval, 1);
        }
    };
    session->SetTryAEInfoCallback(make_shared<TryAEInfoCallbackMock>());
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_TIME_LAPSE_TRYAE_DONE, &value, 1), true);
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_TIME_LAPSE_TRYAE_HINT, &value, 1), true);
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_TIME_LAPSE_PREVIEW_TYPE, &value, 1), true);
    EXPECT_EQ(meta->addEntry(OHOS_STATUS_TIME_LAPSE_CAPTURE_INTERVAL, &value, 1), true);
    session->ProcessSetTryAEChange(meta);

    EXPECT_EQ(meta->addEntry(OHOS_CAMERA_MACRO_STATUS, &value, 1), true);
    session->ProcessPhysicalCameraSwitch(meta);

    session->LockForControl();
    status = session->SetTimeLapseRecordState(TimeLapseRecordState::RECORDING);
    session->UnlockForControl();
    EXPECT_EQ(status, 0);
    session->LockForControl();
    status = session->SetTimeLapsePreviewType(TimeLapsePreviewType::DARK);
    session->UnlockForControl();
    EXPECT_EQ(status, 0);
    session->LockForControl();
    status = session->SetExposureHintMode(ExposureHintMode::EXPOSURE_HINT_MODE_OFF);
    session->UnlockForControl();
    EXPECT_EQ(status, 0);

    vector<int32_t> wbRange;
    status = session->GetWhiteBalanceRange(wbRange);
    EXPECT_EQ(status, 0);
    if (!wbRange.empty()) {
        session->LockForControl();
        status = session->SetWhiteBalance(wbRange[0]);
        session->UnlockForControl();
        EXPECT_EQ(status, 0);
        int32_t wb;
        status = session->GetWhiteBalance(wb);
        EXPECT_EQ(status, 0);
        EXPECT_EQ(wb, wbRange[0]);
    }
    session->Release();
}

/*
 * Feature: Framework
 * Function: Test photo session with photo output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can add photo output into photo session
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_001, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::CAPTURE)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::CAPTURE);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto photoProfiles = outputCapability->GetPhotoProfiles();
    ASSERT_FALSE(photoProfiles.empty());

    auto captureSession = manager_->CreateCaptureSession(SceneMode::CAPTURE);
    auto photoSession = static_cast<PhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(photoSession, nullptr);
    int32_t res = photoSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = photoSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(photoSession->CanAddOutput(previewOutput));
    res = photoSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoProfiles[0]);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_TRUE(photoSession->CanAddOutput(photoOutput));
    res = photoSession->AddOutput(photoOutput);
    EXPECT_EQ(res, 0);

    res = photoSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = photoSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);
    res = static_cast<PhotoOutput*>(photoOutput.GetRefPtr())->Capture();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);
    res = photoSession->Stop();
    EXPECT_EQ(res, 0);
    res = photoSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test photo session with video output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can not add video output into photo session
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_002, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::CAPTURE)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::CAPTURE);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto videoProfiles = outputCapability->GetVideoProfiles();
    ASSERT_TRUE(videoProfiles.empty());
    auto outputCapabilityBase = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::VIDEO);
    ASSERT_NE(outputCapabilityBase, nullptr);
    auto videoProfilesBase = outputCapabilityBase->GetVideoProfiles();
    ASSERT_FALSE(videoProfilesBase.empty());

    auto captureSession = manager_->CreateCaptureSession(SceneMode::CAPTURE);
    auto photoSession = static_cast<PhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(photoSession, nullptr);
    int32_t res = photoSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = photoSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(photoSession->CanAddOutput(previewOutput));
    res = photoSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfilesBase[0]);
    ASSERT_NE(videoOutput, nullptr);
    EXPECT_FALSE(photoSession->CanAddOutput(videoOutput));
}

/*
 * Feature: Framework
 * Function: Test photo session set frame rate range
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can set frame rate range into photo session
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_003, TestSize.Level0)
{
    if (!IsSceneModeSupported(SceneMode::CAPTURE)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::CAPTURE);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto photoProfiles = outputCapability->GetPhotoProfiles();
    ASSERT_FALSE(photoProfiles.empty());

    auto captureSession = manager_->CreateCaptureSession(SceneMode::CAPTURE);
    auto photoSession = static_cast<PhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(photoSession, nullptr);
    int32_t res = photoSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = photoSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(photoSession->CanAddOutput(previewOutput));
    res = photoSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoProfiles[0]);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_TRUE(photoSession->CanAddOutput(photoOutput));
    res = photoSession->AddOutput(photoOutput);
    EXPECT_EQ(res, 0);

    res = photoSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = photoSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);

    std::vector<std::vector<int32_t>> frameRateArray = ((sptr<PreviewOutput>&)previewOutput)->GetSupportedFrameRates();
    ASSERT_NE(frameRateArray.size(), 0);
    std::vector<int32_t> frameRateRange = ((sptr<PreviewOutput>&)previewOutput)->GetFrameRateRange();
    ASSERT_NE(frameRateRange.size(), 0);
    res = ((sptr<PreviewOutput>&)previewOutput)->canSetFrameRateRange(DEFAULT_MIN_FRAME_RATE, DEFAULT_MAX_FRAME_RATE);
    EXPECT_EQ(res, 0);
    ((sptr<PreviewOutput>&)previewOutput)->SetFrameRateRange(DEFAULT_MIN_FRAME_RATE, DEFAULT_MAX_FRAME_RATE);
    frameRateRange = ((sptr<PreviewOutput>&)previewOutput)->GetFrameRateRange();
    ASSERT_NE(frameRateRange.size(), 0);
    EXPECT_EQ(frameRateRange[0], DEFAULT_MIN_FRAME_RATE);
    EXPECT_EQ(frameRateRange[1], DEFAULT_MAX_FRAME_RATE);

    res = static_cast<PhotoOutput*>(photoOutput.GetRefPtr())->Capture();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);
    res = photoSession->Stop();
    EXPECT_EQ(res, 0);
    res = photoSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test photo session preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can preconfig photo session with PRECONFIG_720P, UNSPECIFIED while supported
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_004, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::CAPTURE)) {
        GTEST_SKIP();
    }

    auto captureSession = manager_->CreateCaptureSession(SceneMode::CAPTURE);
    auto photoSession = static_cast<PhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(photoSession, nullptr);
    if (photoSession->CanPreconfig(PreconfigType::PRECONFIG_720P, ProfileSizeRatio::UNSPECIFIED)) {
        int32_t res = photoSession->Preconfig(PreconfigType::PRECONFIG_720P, ProfileSizeRatio::UNSPECIFIED);
        EXPECT_EQ(res, 0);
        res = photoSession->BeginConfig();
        EXPECT_EQ(res, 0);

        sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
        ASSERT_NE(input, nullptr);
        input->Open();
        res = photoSession->AddInput(input);
        EXPECT_EQ(res, 0);

        sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
        sptr<Surface> producerPreviewSurface = Surface::CreateSurfaceAsProducer(previewProducer);
        sptr<PreviewOutput> previewOutput = nullptr;
        res = manager_->CreatePreviewOutputWithoutProfile(producerPreviewSurface, &previewOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePreviewOutput = previewOutput;
        EXPECT_TRUE(photoSession->CanAddOutput(capturePreviewOutput));
        res = photoSession->AddOutput(capturePreviewOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> photoProducer = photoSurface->GetProducer();
        sptr<PhotoOutput> photoOutput = nullptr;
        res = manager_->CreatePhotoOutputWithoutProfile(photoProducer, &photoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePhotoOutput = photoOutput;
        EXPECT_TRUE(photoSession->CanAddOutput(capturePhotoOutput));
        res = photoSession->AddOutput(capturePhotoOutput);
        EXPECT_EQ(res, 0);

        res = photoSession->CommitConfig();
        EXPECT_EQ(res, 0);
        res = photoSession->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = photoOutput->Capture();
        EXPECT_EQ(res, 0);
        res = photoSession->Stop();
        EXPECT_EQ(res, 0);
    }
    EXPECT_EQ(photoSession->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test photo session preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can preconfig photo session with PRECONFIG_720P, RATIO_1_1 while supported
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_005, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::CAPTURE)) {
        GTEST_SKIP();
    }

    auto captureSession = manager_->CreateCaptureSession(SceneMode::CAPTURE);
    auto photoSession = static_cast<PhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(photoSession, nullptr);
    if (photoSession->CanPreconfig(PreconfigType::PRECONFIG_720P, ProfileSizeRatio::RATIO_1_1)) {
        int32_t res = photoSession->Preconfig(PreconfigType::PRECONFIG_720P, ProfileSizeRatio::RATIO_1_1);
        EXPECT_EQ(res, 0);
        res = photoSession->BeginConfig();
        EXPECT_EQ(res, 0);

        sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
        ASSERT_NE(input, nullptr);
        input->Open();
        res = photoSession->AddInput(input);
        EXPECT_EQ(res, 0);

        sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
        sptr<Surface> producerPreviewSurface = Surface::CreateSurfaceAsProducer(previewProducer);
        sptr<PreviewOutput> previewOutput = nullptr;
        res = manager_->CreatePreviewOutputWithoutProfile(producerPreviewSurface, &previewOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePreviewOutput = previewOutput;
        EXPECT_TRUE(photoSession->CanAddOutput(capturePreviewOutput));
        res = photoSession->AddOutput(capturePreviewOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> photoProducer = photoSurface->GetProducer();
        sptr<PhotoOutput> photoOutput = nullptr;
        res = manager_->CreatePhotoOutputWithoutProfile(photoProducer, &photoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePhotoOutput = photoOutput;
        EXPECT_TRUE(photoSession->CanAddOutput(capturePhotoOutput));
        res = photoSession->AddOutput(capturePhotoOutput);
        EXPECT_EQ(res, 0);

        res = photoSession->CommitConfig();
        EXPECT_EQ(res, 0);
        res = photoSession->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = photoOutput->Capture();
        EXPECT_EQ(res, 0);
        res = photoSession->Stop();
        EXPECT_EQ(res, 0);
    }
    EXPECT_EQ(photoSession->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test photo session preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can preconfig photo session with PRECONFIG_720P, RATIO_4_3 while supported
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_006, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::CAPTURE)) {
        GTEST_SKIP();
    }

    auto captureSession = manager_->CreateCaptureSession(SceneMode::CAPTURE);
    auto photoSession = static_cast<PhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(photoSession, nullptr);
    if (photoSession->CanPreconfig(PreconfigType::PRECONFIG_720P, ProfileSizeRatio::RATIO_4_3)) {
        int32_t res = photoSession->Preconfig(PreconfigType::PRECONFIG_720P, ProfileSizeRatio::RATIO_4_3);
        EXPECT_EQ(res, 0);
        res = photoSession->BeginConfig();
        EXPECT_EQ(res, 0);

        sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
        ASSERT_NE(input, nullptr);
        input->Open();
        res = photoSession->AddInput(input);
        EXPECT_EQ(res, 0);

        sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
        sptr<Surface> producerPreviewSurface = Surface::CreateSurfaceAsProducer(previewProducer);
        sptr<PreviewOutput> previewOutput = nullptr;
        res = manager_->CreatePreviewOutputWithoutProfile(producerPreviewSurface, &previewOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePreviewOutput = previewOutput;
        EXPECT_TRUE(photoSession->CanAddOutput(capturePreviewOutput));
        res = photoSession->AddOutput(capturePreviewOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> photoProducer = photoSurface->GetProducer();
        sptr<PhotoOutput> photoOutput = nullptr;
        res = manager_->CreatePhotoOutputWithoutProfile(photoProducer, &photoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePhotoOutput = photoOutput;
        EXPECT_TRUE(photoSession->CanAddOutput(capturePhotoOutput));
        res = photoSession->AddOutput(capturePhotoOutput);
        EXPECT_EQ(res, 0);

        res = photoSession->CommitConfig();
        EXPECT_EQ(res, 0);
        res = photoSession->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = photoOutput->Capture();
        EXPECT_EQ(res, 0);
        res = photoSession->Stop();
        EXPECT_EQ(res, 0);
    }
    EXPECT_EQ(photoSession->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test photo session preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can preconfig photo session with PRECONFIG_720P, RATIO_16_9 while supported
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_007, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::CAPTURE)) {
        GTEST_SKIP();
    }

    auto captureSession = manager_->CreateCaptureSession(SceneMode::CAPTURE);
    auto photoSession = static_cast<PhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(photoSession, nullptr);
    if (photoSession->CanPreconfig(PreconfigType::PRECONFIG_720P, ProfileSizeRatio::RATIO_16_9)) {
        int32_t res = photoSession->Preconfig(PreconfigType::PRECONFIG_720P, ProfileSizeRatio::RATIO_16_9);
        EXPECT_EQ(res, 0);
        res = photoSession->BeginConfig();
        EXPECT_EQ(res, 0);

        sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
        ASSERT_NE(input, nullptr);
        input->Open();
        res = photoSession->AddInput(input);
        EXPECT_EQ(res, 0);

        sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
        sptr<Surface> producerPreviewSurface = Surface::CreateSurfaceAsProducer(previewProducer);
        sptr<PreviewOutput> previewOutput = nullptr;
        res = manager_->CreatePreviewOutputWithoutProfile(producerPreviewSurface, &previewOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePreviewOutput = previewOutput;
        EXPECT_TRUE(photoSession->CanAddOutput(capturePreviewOutput));
        res = photoSession->AddOutput(capturePreviewOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> photoProducer = photoSurface->GetProducer();
        sptr<PhotoOutput> photoOutput = nullptr;
        res = manager_->CreatePhotoOutputWithoutProfile(photoProducer, &photoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePhotoOutput = photoOutput;
        EXPECT_TRUE(photoSession->CanAddOutput(capturePhotoOutput));
        res = photoSession->AddOutput(capturePhotoOutput);
        EXPECT_EQ(res, 0);

        res = photoSession->CommitConfig();
        EXPECT_EQ(res, 0);
        res = photoSession->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = photoOutput->Capture();
        EXPECT_EQ(res, 0);
        res = photoSession->Stop();
        EXPECT_EQ(res, 0);
    }
    EXPECT_EQ(photoSession->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test photo session preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can preconfig photo session with PRECONFIG_1080P, UNSPECIFIED while supported
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_008, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::CAPTURE)) {
        GTEST_SKIP();
    }

    auto captureSession = manager_->CreateCaptureSession(SceneMode::CAPTURE);
    auto photoSession = static_cast<PhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(photoSession, nullptr);
    if (photoSession->CanPreconfig(PreconfigType::PRECONFIG_1080P, ProfileSizeRatio::UNSPECIFIED)) {
        int32_t res = photoSession->Preconfig(PreconfigType::PRECONFIG_1080P, ProfileSizeRatio::UNSPECIFIED);
        EXPECT_EQ(res, 0);
        res = photoSession->BeginConfig();
        EXPECT_EQ(res, 0);

        sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
        ASSERT_NE(input, nullptr);
        input->Open();
        res = photoSession->AddInput(input);
        EXPECT_EQ(res, 0);

        sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
        sptr<Surface> producerPreviewSurface = Surface::CreateSurfaceAsProducer(previewProducer);
        sptr<PreviewOutput> previewOutput = nullptr;
        res = manager_->CreatePreviewOutputWithoutProfile(producerPreviewSurface, &previewOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePreviewOutput = previewOutput;
        EXPECT_TRUE(photoSession->CanAddOutput(capturePreviewOutput));
        res = photoSession->AddOutput(capturePreviewOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> photoProducer = photoSurface->GetProducer();
        sptr<PhotoOutput> photoOutput = nullptr;
        res = manager_->CreatePhotoOutputWithoutProfile(photoProducer, &photoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePhotoOutput = photoOutput;
        EXPECT_TRUE(photoSession->CanAddOutput(capturePhotoOutput));
        res = photoSession->AddOutput(capturePhotoOutput);
        EXPECT_EQ(res, 0);

        res = photoSession->CommitConfig();
        EXPECT_EQ(res, 0);
        res = photoSession->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = photoOutput->Capture();
        EXPECT_EQ(res, 0);
        res = photoSession->Stop();
        EXPECT_EQ(res, 0);
    }
    EXPECT_EQ(photoSession->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test photo session preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can preconfig photo session with PRECONFIG_1080P, RATIO_1_1 while supported
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_009, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::CAPTURE)) {
        GTEST_SKIP();
    }

    auto captureSession = manager_->CreateCaptureSession(SceneMode::CAPTURE);
    auto photoSession = static_cast<PhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(photoSession, nullptr);
    if (photoSession->CanPreconfig(PreconfigType::PRECONFIG_1080P, ProfileSizeRatio::RATIO_1_1)) {
        int32_t res = photoSession->Preconfig(PreconfigType::PRECONFIG_1080P, ProfileSizeRatio::RATIO_1_1);
        EXPECT_EQ(res, 0);
        res = photoSession->BeginConfig();
        EXPECT_EQ(res, 0);

        sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
        ASSERT_NE(input, nullptr);
        input->Open();
        res = photoSession->AddInput(input);
        EXPECT_EQ(res, 0);

        sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
        sptr<Surface> producerPreviewSurface = Surface::CreateSurfaceAsProducer(previewProducer);
        sptr<PreviewOutput> previewOutput = nullptr;
        res = manager_->CreatePreviewOutputWithoutProfile(producerPreviewSurface, &previewOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePreviewOutput = previewOutput;
        EXPECT_TRUE(photoSession->CanAddOutput(capturePreviewOutput));
        res = photoSession->AddOutput(capturePreviewOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> photoProducer = photoSurface->GetProducer();
        sptr<PhotoOutput> photoOutput = nullptr;
        res = manager_->CreatePhotoOutputWithoutProfile(photoProducer, &photoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePhotoOutput = photoOutput;
        EXPECT_TRUE(photoSession->CanAddOutput(capturePhotoOutput));
        res = photoSession->AddOutput(capturePhotoOutput);
        EXPECT_EQ(res, 0);

        res = photoSession->CommitConfig();
        EXPECT_EQ(res, 0);
        res = photoSession->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = photoOutput->Capture();
        EXPECT_EQ(res, 0);
        res = photoSession->Stop();
        EXPECT_EQ(res, 0);
    }
    EXPECT_EQ(photoSession->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test photo session preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can preconfig photo session with PRECONFIG_1080P, RATIO_4_3 while supported
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_010, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::CAPTURE)) {
        GTEST_SKIP();
    }

    auto captureSession = manager_->CreateCaptureSession(SceneMode::CAPTURE);
    auto photoSession = static_cast<PhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(photoSession, nullptr);
    if (photoSession->CanPreconfig(PreconfigType::PRECONFIG_1080P, ProfileSizeRatio::RATIO_4_3)) {
        int32_t res = photoSession->Preconfig(PreconfigType::PRECONFIG_1080P, ProfileSizeRatio::RATIO_4_3);
        EXPECT_EQ(res, 0);
        res = photoSession->BeginConfig();
        EXPECT_EQ(res, 0);

        sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
        ASSERT_NE(input, nullptr);
        input->Open();
        res = photoSession->AddInput(input);
        EXPECT_EQ(res, 0);

        sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
        sptr<Surface> producerPreviewSurface = Surface::CreateSurfaceAsProducer(previewProducer);
        sptr<PreviewOutput> previewOutput = nullptr;
        res = manager_->CreatePreviewOutputWithoutProfile(producerPreviewSurface, &previewOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePreviewOutput = previewOutput;
        EXPECT_TRUE(photoSession->CanAddOutput(capturePreviewOutput));
        res = photoSession->AddOutput(capturePreviewOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> photoProducer = photoSurface->GetProducer();
        sptr<PhotoOutput> photoOutput = nullptr;
        res = manager_->CreatePhotoOutputWithoutProfile(photoProducer, &photoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePhotoOutput = photoOutput;
        EXPECT_TRUE(photoSession->CanAddOutput(capturePhotoOutput));
        res = photoSession->AddOutput(capturePhotoOutput);
        EXPECT_EQ(res, 0);

        res = photoSession->CommitConfig();
        EXPECT_EQ(res, 0);
        res = photoSession->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = photoOutput->Capture();
        EXPECT_EQ(res, 0);
        res = photoSession->Stop();
        EXPECT_EQ(res, 0);
    }
    EXPECT_EQ(photoSession->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test photo session preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can preconfig photo session with PRECONFIG_1080P, RATIO_16_9 while supported
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_011, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::CAPTURE)) {
        GTEST_SKIP();
    }

    auto captureSession = manager_->CreateCaptureSession(SceneMode::CAPTURE);
    auto photoSession = static_cast<PhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(photoSession, nullptr);
    if (photoSession->CanPreconfig(PreconfigType::PRECONFIG_1080P, ProfileSizeRatio::RATIO_16_9)) {
        int32_t res = photoSession->Preconfig(PreconfigType::PRECONFIG_1080P, ProfileSizeRatio::RATIO_16_9);
        EXPECT_EQ(res, 0);
        res = photoSession->BeginConfig();
        EXPECT_EQ(res, 0);

        sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
        ASSERT_NE(input, nullptr);
        input->Open();
        res = photoSession->AddInput(input);
        EXPECT_EQ(res, 0);

        sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
        sptr<Surface> producerPreviewSurface = Surface::CreateSurfaceAsProducer(previewProducer);
        sptr<PreviewOutput> previewOutput = nullptr;
        res = manager_->CreatePreviewOutputWithoutProfile(producerPreviewSurface, &previewOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePreviewOutput = previewOutput;
        EXPECT_TRUE(photoSession->CanAddOutput(capturePreviewOutput));
        res = photoSession->AddOutput(capturePreviewOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> photoProducer = photoSurface->GetProducer();
        sptr<PhotoOutput> photoOutput = nullptr;
        res = manager_->CreatePhotoOutputWithoutProfile(photoProducer, &photoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePhotoOutput = photoOutput;
        EXPECT_TRUE(photoSession->CanAddOutput(capturePhotoOutput));
        res = photoSession->AddOutput(capturePhotoOutput);
        EXPECT_EQ(res, 0);

        res = photoSession->CommitConfig();
        EXPECT_EQ(res, 0);
        res = photoSession->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = photoOutput->Capture();
        EXPECT_EQ(res, 0);
        res = photoSession->Stop();
        EXPECT_EQ(res, 0);
    }
    EXPECT_EQ(photoSession->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test photo session preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can preconfig photo session with PRECONFIG_4K, UNSPECIFIED while supported
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_012, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::CAPTURE)) {
        GTEST_SKIP();
    }

    auto captureSession = manager_->CreateCaptureSession(SceneMode::CAPTURE);
    auto photoSession = static_cast<PhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(photoSession, nullptr);
    if (photoSession->CanPreconfig(PreconfigType::PRECONFIG_4K, ProfileSizeRatio::UNSPECIFIED)) {
        int32_t res = photoSession->Preconfig(PreconfigType::PRECONFIG_4K, ProfileSizeRatio::UNSPECIFIED);
        EXPECT_EQ(res, 0);
        res = photoSession->BeginConfig();
        EXPECT_EQ(res, 0);

        sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
        ASSERT_NE(input, nullptr);
        input->Open();
        res = photoSession->AddInput(input);
        EXPECT_EQ(res, 0);

        sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
        sptr<Surface> producerPreviewSurface = Surface::CreateSurfaceAsProducer(previewProducer);
        sptr<PreviewOutput> previewOutput = nullptr;
        res = manager_->CreatePreviewOutputWithoutProfile(producerPreviewSurface, &previewOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePreviewOutput = previewOutput;
        EXPECT_TRUE(photoSession->CanAddOutput(capturePreviewOutput));
        res = photoSession->AddOutput(capturePreviewOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> photoProducer = photoSurface->GetProducer();
        sptr<PhotoOutput> photoOutput = nullptr;
        res = manager_->CreatePhotoOutputWithoutProfile(photoProducer, &photoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePhotoOutput = photoOutput;
        EXPECT_TRUE(photoSession->CanAddOutput(capturePhotoOutput));
        res = photoSession->AddOutput(capturePhotoOutput);
        EXPECT_EQ(res, 0);

        res = photoSession->CommitConfig();
        EXPECT_EQ(res, 0);
        res = photoSession->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = photoOutput->Capture();
        EXPECT_EQ(res, 0);
        res = photoSession->Stop();
        EXPECT_EQ(res, 0);
    }
    EXPECT_EQ(photoSession->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test photo session preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can preconfig photo session with PRECONFIG_4K, RATIO_1_1 while supported
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_013, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::CAPTURE)) {
        GTEST_SKIP();
    }

    auto captureSession = manager_->CreateCaptureSession(SceneMode::CAPTURE);
    auto photoSession = static_cast<PhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(photoSession, nullptr);
    if (photoSession->CanPreconfig(PreconfigType::PRECONFIG_4K, ProfileSizeRatio::RATIO_1_1)) {
        int32_t res = photoSession->Preconfig(PreconfigType::PRECONFIG_4K, ProfileSizeRatio::RATIO_1_1);
        EXPECT_EQ(res, 0);
        res = photoSession->BeginConfig();
        EXPECT_EQ(res, 0);

        sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
        ASSERT_NE(input, nullptr);
        input->Open();
        res = photoSession->AddInput(input);
        EXPECT_EQ(res, 0);

        sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
        sptr<Surface> producerPreviewSurface = Surface::CreateSurfaceAsProducer(previewProducer);
        sptr<PreviewOutput> previewOutput = nullptr;
        res = manager_->CreatePreviewOutputWithoutProfile(producerPreviewSurface, &previewOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePreviewOutput = previewOutput;
        EXPECT_TRUE(photoSession->CanAddOutput(capturePreviewOutput));
        res = photoSession->AddOutput(capturePreviewOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> photoProducer = photoSurface->GetProducer();
        sptr<PhotoOutput> photoOutput = nullptr;
        res = manager_->CreatePhotoOutputWithoutProfile(photoProducer, &photoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePhotoOutput = photoOutput;
        EXPECT_TRUE(photoSession->CanAddOutput(capturePhotoOutput));
        res = photoSession->AddOutput(capturePhotoOutput);
        EXPECT_EQ(res, 0);

        res = photoSession->CommitConfig();
        EXPECT_EQ(res, 0);
        res = photoSession->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = photoOutput->Capture();
        EXPECT_EQ(res, 0);
        res = photoSession->Stop();
        EXPECT_EQ(res, 0);
    }
    EXPECT_EQ(photoSession->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test photo session preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can preconfig photo session with PRECONFIG_4K, RATIO_4_3 while supported
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_014, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::CAPTURE)) {
        GTEST_SKIP();
    }

    auto captureSession = manager_->CreateCaptureSession(SceneMode::CAPTURE);
    auto photoSession = static_cast<PhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(photoSession, nullptr);
    if (photoSession->CanPreconfig(PreconfigType::PRECONFIG_4K, ProfileSizeRatio::RATIO_4_3)) {
        int32_t res = photoSession->Preconfig(PreconfigType::PRECONFIG_4K, ProfileSizeRatio::RATIO_4_3);
        EXPECT_EQ(res, 0);
        res = photoSession->BeginConfig();
        EXPECT_EQ(res, 0);

        sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
        ASSERT_NE(input, nullptr);
        input->Open();
        res = photoSession->AddInput(input);
        EXPECT_EQ(res, 0);

        sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
        sptr<Surface> producerPreviewSurface = Surface::CreateSurfaceAsProducer(previewProducer);
        sptr<PreviewOutput> previewOutput = nullptr;
        res = manager_->CreatePreviewOutputWithoutProfile(producerPreviewSurface, &previewOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePreviewOutput = previewOutput;
        EXPECT_TRUE(photoSession->CanAddOutput(capturePreviewOutput));
        res = photoSession->AddOutput(capturePreviewOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> photoProducer = photoSurface->GetProducer();
        sptr<PhotoOutput> photoOutput = nullptr;
        res = manager_->CreatePhotoOutputWithoutProfile(photoProducer, &photoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePhotoOutput = photoOutput;
        EXPECT_TRUE(photoSession->CanAddOutput(capturePhotoOutput));
        res = photoSession->AddOutput(capturePhotoOutput);
        EXPECT_EQ(res, 0);

        res = photoSession->CommitConfig();
        EXPECT_EQ(res, 0);
        res = photoSession->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = photoOutput->Capture();
        EXPECT_EQ(res, 0);
        res = photoSession->Stop();
        EXPECT_EQ(res, 0);
    }
    EXPECT_EQ(photoSession->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test photo session preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can preconfig photo session with PRECONFIG_4K, RATIO_16_9 while supported
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_015, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::CAPTURE)) {
        GTEST_SKIP();
    }

    auto captureSession = manager_->CreateCaptureSession(SceneMode::CAPTURE);
    auto photoSession = static_cast<PhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(photoSession, nullptr);
    if (photoSession->CanPreconfig(PreconfigType::PRECONFIG_4K, ProfileSizeRatio::RATIO_16_9)) {
        int32_t res = photoSession->Preconfig(PreconfigType::PRECONFIG_4K, ProfileSizeRatio::RATIO_16_9);
        EXPECT_EQ(res, 0);
        res = photoSession->BeginConfig();
        EXPECT_EQ(res, 0);

        sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
        ASSERT_NE(input, nullptr);
        input->Open();
        res = photoSession->AddInput(input);
        EXPECT_EQ(res, 0);

        sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
        sptr<Surface> producerPreviewSurface = Surface::CreateSurfaceAsProducer(previewProducer);
        sptr<PreviewOutput> previewOutput = nullptr;
        res = manager_->CreatePreviewOutputWithoutProfile(producerPreviewSurface, &previewOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePreviewOutput = previewOutput;
        EXPECT_TRUE(photoSession->CanAddOutput(capturePreviewOutput));
        res = photoSession->AddOutput(capturePreviewOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> photoProducer = photoSurface->GetProducer();
        sptr<PhotoOutput> photoOutput = nullptr;
        res = manager_->CreatePhotoOutputWithoutProfile(photoProducer, &photoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePhotoOutput = photoOutput;
        EXPECT_TRUE(photoSession->CanAddOutput(capturePhotoOutput));
        res = photoSession->AddOutput(capturePhotoOutput);
        EXPECT_EQ(res, 0);

        res = photoSession->CommitConfig();
        EXPECT_EQ(res, 0);
        res = photoSession->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = photoOutput->Capture();
        EXPECT_EQ(res, 0);
        res = photoSession->Stop();
        EXPECT_EQ(res, 0);
    }
    EXPECT_EQ(photoSession->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test photo session preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can preconfig photo session with PRECONFIG_HIGH_QUALITY, UNSPECIFIED while supported
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_016, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::CAPTURE)) {
        GTEST_SKIP();
    }

    auto captureSession = manager_->CreateCaptureSession(SceneMode::CAPTURE);
    auto photoSession = static_cast<PhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(photoSession, nullptr);
    if (photoSession->CanPreconfig(PreconfigType::PRECONFIG_HIGH_QUALITY, ProfileSizeRatio::UNSPECIFIED)) {
        int32_t res = photoSession->Preconfig(PreconfigType::PRECONFIG_HIGH_QUALITY, ProfileSizeRatio::UNSPECIFIED);
        EXPECT_EQ(res, 0);
        res = photoSession->BeginConfig();
        EXPECT_EQ(res, 0);

        sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
        ASSERT_NE(input, nullptr);
        input->Open();
        res = photoSession->AddInput(input);
        EXPECT_EQ(res, 0);

        sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
        sptr<Surface> producerPreviewSurface = Surface::CreateSurfaceAsProducer(previewProducer);
        sptr<PreviewOutput> previewOutput = nullptr;
        res = manager_->CreatePreviewOutputWithoutProfile(producerPreviewSurface, &previewOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePreviewOutput = previewOutput;
        EXPECT_TRUE(photoSession->CanAddOutput(capturePreviewOutput));
        res = photoSession->AddOutput(capturePreviewOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> photoProducer = photoSurface->GetProducer();
        sptr<PhotoOutput> photoOutput = nullptr;
        res = manager_->CreatePhotoOutputWithoutProfile(photoProducer, &photoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePhotoOutput = photoOutput;
        EXPECT_TRUE(photoSession->CanAddOutput(capturePhotoOutput));
        res = photoSession->AddOutput(capturePhotoOutput);
        EXPECT_EQ(res, 0);

        res = photoSession->CommitConfig();
        EXPECT_EQ(res, 0);
        res = photoSession->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = photoOutput->Capture();
        EXPECT_EQ(res, 0);
        res = photoSession->Stop();
        EXPECT_EQ(res, 0);
    }
    EXPECT_EQ(photoSession->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test photo session preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can preconfig photo session with PRECONFIG_HIGH_QUALITY, RATIO_1_1 while supported
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_017, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::CAPTURE)) {
        GTEST_SKIP();
    }

    auto captureSession = manager_->CreateCaptureSession(SceneMode::CAPTURE);
    auto photoSession = static_cast<PhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(photoSession, nullptr);
    if (photoSession->CanPreconfig(PreconfigType::PRECONFIG_HIGH_QUALITY, ProfileSizeRatio::RATIO_1_1)) {
        int32_t res = photoSession->Preconfig(PreconfigType::PRECONFIG_HIGH_QUALITY, ProfileSizeRatio::RATIO_1_1);
        EXPECT_EQ(res, 0);
        res = photoSession->BeginConfig();
        EXPECT_EQ(res, 0);

        sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
        ASSERT_NE(input, nullptr);
        input->Open();
        res = photoSession->AddInput(input);
        EXPECT_EQ(res, 0);

        sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
        sptr<Surface> producerPreviewSurface = Surface::CreateSurfaceAsProducer(previewProducer);
        sptr<PreviewOutput> previewOutput = nullptr;
        res = manager_->CreatePreviewOutputWithoutProfile(producerPreviewSurface, &previewOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePreviewOutput = previewOutput;
        EXPECT_TRUE(photoSession->CanAddOutput(capturePreviewOutput));
        res = photoSession->AddOutput(capturePreviewOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> photoProducer = photoSurface->GetProducer();
        sptr<PhotoOutput> photoOutput = nullptr;
        res = manager_->CreatePhotoOutputWithoutProfile(photoProducer, &photoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePhotoOutput = photoOutput;
        EXPECT_TRUE(photoSession->CanAddOutput(capturePhotoOutput));
        res = photoSession->AddOutput(capturePhotoOutput);
        EXPECT_EQ(res, 0);

        res = photoSession->CommitConfig();
        EXPECT_EQ(res, 0);
        res = photoSession->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = photoOutput->Capture();
        EXPECT_EQ(res, 0);
        res = photoSession->Stop();
        EXPECT_EQ(res, 0);
    }
    EXPECT_EQ(photoSession->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test photo session preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can preconfig photo session with PRECONFIG_HIGH_QUALITY, RATIO_4_3 while supported
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_018, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::CAPTURE)) {
        GTEST_SKIP();
    }

    auto captureSession = manager_->CreateCaptureSession(SceneMode::CAPTURE);
    auto photoSession = static_cast<PhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(photoSession, nullptr);
    if (photoSession->CanPreconfig(PreconfigType::PRECONFIG_HIGH_QUALITY, ProfileSizeRatio::RATIO_4_3)) {
        int32_t res = photoSession->Preconfig(PreconfigType::PRECONFIG_HIGH_QUALITY, ProfileSizeRatio::RATIO_4_3);
        EXPECT_EQ(res, 0);
        res = photoSession->BeginConfig();
        EXPECT_EQ(res, 0);

        sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
        ASSERT_NE(input, nullptr);
        input->Open();
        res = photoSession->AddInput(input);
        EXPECT_EQ(res, 0);

        sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
        sptr<Surface> producerPreviewSurface = Surface::CreateSurfaceAsProducer(previewProducer);
        sptr<PreviewOutput> previewOutput = nullptr;
        res = manager_->CreatePreviewOutputWithoutProfile(producerPreviewSurface, &previewOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePreviewOutput = previewOutput;
        EXPECT_TRUE(photoSession->CanAddOutput(capturePreviewOutput));
        res = photoSession->AddOutput(capturePreviewOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> photoProducer = photoSurface->GetProducer();
        sptr<PhotoOutput> photoOutput = nullptr;
        res = manager_->CreatePhotoOutputWithoutProfile(photoProducer, &photoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePhotoOutput = photoOutput;
        EXPECT_TRUE(photoSession->CanAddOutput(capturePhotoOutput));
        res = photoSession->AddOutput(capturePhotoOutput);
        EXPECT_EQ(res, 0);

        res = photoSession->CommitConfig();
        EXPECT_EQ(res, 0);
        res = photoSession->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = photoOutput->Capture();
        EXPECT_EQ(res, 0);
        res = photoSession->Stop();
        EXPECT_EQ(res, 0);
    }
    EXPECT_EQ(photoSession->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test photo session preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can preconfig photo session with PRECONFIG_HIGH_QUALITY, RATIO_16_9 while supported
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_019, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::CAPTURE)) {
        GTEST_SKIP();
    }

    auto captureSession = manager_->CreateCaptureSession(SceneMode::CAPTURE);
    auto photoSession = static_cast<PhotoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(photoSession, nullptr);
    if (photoSession->CanPreconfig(PreconfigType::PRECONFIG_HIGH_QUALITY, ProfileSizeRatio::RATIO_16_9)) {
        int32_t res = photoSession->Preconfig(PreconfigType::PRECONFIG_HIGH_QUALITY, ProfileSizeRatio::RATIO_16_9);
        EXPECT_EQ(res, 0);
        res = photoSession->BeginConfig();
        EXPECT_EQ(res, 0);

        sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
        ASSERT_NE(input, nullptr);
        input->Open();
        res = photoSession->AddInput(input);
        EXPECT_EQ(res, 0);

        sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
        sptr<Surface> producerPreviewSurface = Surface::CreateSurfaceAsProducer(previewProducer);
        sptr<PreviewOutput> previewOutput = nullptr;
        res = manager_->CreatePreviewOutputWithoutProfile(producerPreviewSurface, &previewOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePreviewOutput = previewOutput;
        EXPECT_TRUE(photoSession->CanAddOutput(capturePreviewOutput));
        res = photoSession->AddOutput(capturePreviewOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> photoProducer = photoSurface->GetProducer();
        sptr<PhotoOutput> photoOutput = nullptr;
        res = manager_->CreatePhotoOutputWithoutProfile(photoProducer, &photoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePhotoOutput = photoOutput;
        EXPECT_TRUE(photoSession->CanAddOutput(capturePhotoOutput));
        res = photoSession->AddOutput(capturePhotoOutput);
        EXPECT_EQ(res, 0);

        res = photoSession->CommitConfig();
        EXPECT_EQ(res, 0);
        res = photoSession->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = photoOutput->Capture();
        EXPECT_EQ(res, 0);
        res = photoSession->Stop();
        EXPECT_EQ(res, 0);
    }
    EXPECT_EQ(photoSession->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test photo session ability function
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo session ability function
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_020, TestSize.Level0)
{
    SceneMode photoMode = SceneMode::CAPTURE;
    if (!IsSceneModeSupported(photoMode)) {
        GTEST_SKIP();
    }
    sptr<CameraManager> cameraMgr = CameraManager::GetInstance();
    ASSERT_NE(cameraMgr, nullptr);

    sptr<CameraOutputCapability> capability = cameraMgr->GetSupportedOutputCapability(cameras_[0], photoMode);
    ASSERT_NE(capability, nullptr);

    sptr<CaptureSession> captureSession = cameraMgr->CreateCaptureSession(photoMode);
    ASSERT_NE(captureSession, nullptr);

    sptr<PhotoSession> photoSession = static_cast<PhotoSession *>(captureSession.GetRefPtr());
    ASSERT_NE(photoSession, nullptr);

    std::vector<sptr<CameraOutputCapability>> cocList = photoSession->GetCameraOutputCapabilities(cameras_[0]);
    ASSERT_TRUE(cocList.size() != 0);
    auto previewProfiles = cocList[0]->GetPreviewProfiles();
    auto photoProfiles = cocList[0]->GetPhotoProfiles();
    auto videoProfiles = cocList[0]->GetVideoProfiles();

    int32_t intResult = photoSession->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = photoSession->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    intResult = photoSession->AddOutput(photoOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    intResult = photoSession->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    intResult = photoSession->CommitConfig();
    EXPECT_EQ(intResult, 0);

    auto photoFunctionsList = photoSession->GetSessionFunctions(previewProfiles, photoProfiles, videoProfiles, true);
    ASSERT_TRUE(photoFunctionsList.size() != 0);
    auto photoFunctions = photoFunctionsList[0];
    photoFunctions->HasFlash();
    photoFunctions->GetSupportedFocusModes();
    photoFunctions->GetSupportedBeautyTypes();
    photoFunctions->GetSupportedBeautyRange(BeautyType::AUTO_TYPE);
    photoFunctions->GetSupportedColorEffects();
    photoFunctions->GetSupportedColorSpaces();
    photoFunctions->IsFocusModeSupported(FocusMode::FOCUS_MODE_MANUAL);
    std::vector<sptr<CameraAbility>> photoConflictFunctionsList = photoSession->GetSessionConflictFunctions();

    std::vector<float> zoomRatioRange = photoSession->GetZoomRatioRange();
    ASSERT_NE(zoomRatioRange.size(), 0);

    photoSession->LockForControl();
    photoSession->EnableMacro(true);
    photoSession->UnlockForControl();

    zoomRatioRange = photoSession->GetZoomRatioRange();
    ASSERT_NE(zoomRatioRange.size(), 0);

    photoSession->LockForControl();
    photoSession->EnableMacro(false);
    photoSession->UnlockForControl();

    photoSession->IsMacroSupported();

    photoSession->LockForControl();
    photoSession->SetZoomRatio(zoomRatioRange[1]);
    photoSession->UnlockForControl();

    photoSession->IsMacroSupported();
}

/*
 * Feature: Framework
 * Function: Test photo session with CreateCaptureSession
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo session with CreateCaptureSession
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_021, TestSize.Level1)
{
    SceneMode mode = SceneMode::CAPTURE;
    sptr<CameraManager> modeManagerObj = CameraManager::GetInstance();
    ASSERT_NE(modeManagerObj, nullptr);

    sptr<CaptureSession> captureSession = modeManagerObj->CreateCaptureSession(mode);
    ASSERT_NE(captureSession, nullptr);
}

/*
 * Feature: Framework
 * Function: Test photo session abnormal branches
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo session abnormal branches
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_022, TestSize.Level1)
{
    if (!IsSupportNow()) {
        GTEST_SKIP();
    }
    sptr<CaptureSessionForSys> captureSessionForSys = managerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(captureSessionForSys, nullptr);
    std::vector<float> virtualApertures = {};
    float aperture;
    EXPECT_EQ(captureSessionForSys->GetSupportedVirtualApertures(virtualApertures), SESSION_NOT_CONFIG);
    EXPECT_EQ(captureSessionForSys->GetVirtualAperture(aperture), SESSION_NOT_CONFIG);
    EXPECT_EQ(captureSessionForSys->SetVirtualAperture(aperture), SESSION_NOT_CONFIG);
}

/*
 * Feature: Framework
 * Function: Test photo session with VirtualAperture
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo session with VirtualAperture
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_023, TestSize.Level0)
{
    SceneMode captureMode = SceneMode::CAPTURE;
    if (!IsSceneModeSupported(captureMode)) {
        GTEST_SKIP();
    }
    if (session_) {
        MEDIA_INFO_LOG("old session exist, need release");
        session_->Release();
    }
    sptr<CameraManager> modeManagerObj = CameraManager::GetInstance();
    ASSERT_NE(modeManagerObj, nullptr);

    std::vector<SceneMode> modes = modeManagerObj->GetSupportedModes(cameras_[0]);
    ASSERT_TRUE(modes.size() != 0);


    sptr<CameraOutputCapability> modeAbility =
        modeManagerObj->GetSupportedOutputCapability(cameras_[0], captureMode);
    ASSERT_NE(modeAbility, nullptr);

    sptr<CaptureSessionForSys> captureSessionForSys = managerForSys_->CreateCaptureSessionForSys(captureMode);
    ASSERT_NE(captureSessionForSys, nullptr);

    int32_t intResult = captureSessionForSys->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = captureSessionForSys->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    camera_rational_t ratio = {
        .numerator = 16,
        .denominator=9
    };

    Profile profile = SelectProfileByRatioAndFormat(modeAbility, ratio, photoFormat_);
    ASSERT_NE(profile.format_, -1);

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(profile);
    ASSERT_NE(photoOutput, nullptr);

    intResult = captureSessionForSys->AddOutput(photoOutput);
    EXPECT_EQ(intResult, 0);

    profile = SelectProfileByRatioAndFormat(modeAbility, ratio, previewFormat_);
    ASSERT_NE(profile.format_, -1);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(profile);
    ASSERT_NE(previewOutput, nullptr);

    intResult = captureSessionForSys->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    intResult = captureSessionForSys->CommitConfig();
    EXPECT_EQ(intResult, 0);

    captureSessionForSys->LockForControl();

    std::vector<float> virtualApertures = {};
    EXPECT_EQ(captureSessionForSys->GetSupportedVirtualApertures(virtualApertures), 0);
    EXPECT_EQ(captureSessionForSys->SetVirtualAperture(virtualApertures[0]), 0);

    captureSessionForSys->UnlockForControl();
    float aperture;
    EXPECT_EQ(captureSessionForSys->GetVirtualAperture(aperture), 0);
    EXPECT_EQ(aperture, virtualApertures[0]);

    intResult = captureSessionForSys->Start();
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_START);

    intResult = ((sptr<PhotoOutput>&)photoOutput)->Capture();
    EXPECT_EQ(intResult, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    captureSessionForSys->Stop();
}

/*
 * Feature: Framework
 * Function: Test photo session set default color space
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo session set default color space
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_024, TestSize.Level1)
{
    sptr<CameraInput> camInput = (sptr<CameraInput>&)input_;
    camInput->Open();

    if (session_) {
        MEDIA_INFO_LOG("old session exist, need release");
        session_->Release();
    }
    session_ = manager_->CreateCaptureSession();
    ASSERT_NE(session_, nullptr);
    session_->SetMode(SceneMode::CAPTURE);
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

    std::vector<ColorSpace> colorSpaceLists = session_->GetSupportedColorSpaces();
    bool falg = false;
    for (auto curColorSpace : colorSpaceLists) {
        if (curColorSpace == ColorSpace::SRGB) {
            falg = true;
            break;
        }
    }
    if (colorSpaceLists.size() != 0) {
        ColorSpace colorSpace;
        intResult = session_->GetActiveColorSpace(colorSpace);
        EXPECT_EQ(intResult, 0);
        if (!falg) {
            MEDIA_ERR_LOG("current session not supported colorSpace SRGB");
            GTEST_SKIP();
        }
        EXPECT_EQ(ColorSpace::SRGB, colorSpace);
    }

    intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    intResult = session_->Stop();
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test photo session set color space before commit config
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo session set color space before commit config
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_025, TestSize.Level1)
{
    sptr<CameraInput> camInput = (sptr<CameraInput>&)input_;
    camInput->Open();

    if (session_) {
        MEDIA_INFO_LOG("old session exist, need release");
        session_->Release();
    }
    session_ = manager_->CreateCaptureSession();
    ASSERT_NE(session_, nullptr);
    session_->SetMode(SceneMode::CAPTURE);
    int32_t intResult = session_->BeginConfig();

    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = session_->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    std::vector<ColorSpace> colorSpaceLists = session_->GetSupportedColorSpaces();
    if (colorSpaceLists.size() != 0) {
        intResult = session_->SetColorSpace(colorSpaceLists[1]);
        EXPECT_EQ(intResult, 0);
        ColorSpace colorSpace;
        intResult = session_->GetActiveColorSpace(colorSpace);
        EXPECT_EQ(intResult, 0);
        EXPECT_EQ(colorSpaceLists[1], colorSpace);
    }

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    intResult = session_->Stop();
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test photo session set color space after commit config
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo session set color space after commit config
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_026, TestSize.Level1)
{
    sptr<CameraInput> camInput = (sptr<CameraInput>&)input_;
    camInput->Open();

    if (session_) {
        MEDIA_INFO_LOG("old session exist, need release");
        session_->Release();
    }
    session_ = manager_->CreateCaptureSession();
    ASSERT_NE(session_, nullptr);
    session_->SetMode(SceneMode::CAPTURE);
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


    std::vector<ColorSpace> colorSpaceLists = session_->GetSupportedColorSpaces();
    if (colorSpaceLists.size() != 0) {
        intResult = session_->SetColorSpace(colorSpaceLists[1]);
        EXPECT_EQ(intResult, 0);
        ColorSpace colorSpace;
        intResult = session_->GetActiveColorSpace(colorSpace);
        EXPECT_EQ(intResult, 0);
        EXPECT_EQ(colorSpaceLists[1], colorSpace);
    }

    intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    intResult = session_->Stop();
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test photo session set color space after session start
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo session set color space after session start
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_027, TestSize.Level1)
{
    sptr<CameraInput> camInput = (sptr<CameraInput>&)input_;
    camInput->Open();

    if (session_) {
        MEDIA_INFO_LOG("old session exist, need release");
        session_->Release();
    }
    session_ = manager_->CreateCaptureSession();
    ASSERT_NE(session_, nullptr);
    session_->SetMode(SceneMode::CAPTURE);
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

    intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    std::vector<ColorSpace> colorSpaceLists = session_->GetSupportedColorSpaces();
    if (colorSpaceLists.size() != 0) {
        intResult = session_->SetColorSpace(colorSpaceLists[1]);
        EXPECT_EQ(intResult, 0);
        ColorSpace colorSpace;
        intResult = session_->GetActiveColorSpace(colorSpace);
        EXPECT_EQ(intResult, 0);
        EXPECT_EQ(colorSpaceLists[1], colorSpace);
    }

    sleep(WAIT_TIME_AFTER_START);

    intResult = session_->Stop();
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test photo session with low light boost
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo session with low light boost
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_028, TestSize.Level1)
{
    sessionForSys_->SetMode(SceneMode::CAPTURE);
    int32_t intResult = sessionForSys_->BeginConfig();

    EXPECT_EQ(intResult, 0);

    intResult = sessionForSys_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = sessionForSys_->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    bool isLowLightBoostSupported = sessionForSys_->IsFeatureSupported(FEATURE_LOW_LIGHT_BOOST);

    if (isLowLightBoostSupported) {
        intResult = sessionForSys_->EnableFeature(FEATURE_LOW_LIGHT_BOOST, true);
        EXPECT_EQ(intResult, SESSION_NOT_CONFIG);
    }

    intResult = sessionForSys_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    isLowLightBoostSupported = sessionForSys_->IsFeatureSupported(FEATURE_LOW_LIGHT_BOOST);
    if (isLowLightBoostSupported) {
        sessionForSys_->SetFeatureDetectionStatusCallback(std::make_shared<AppCallback>());
        sessionForSys_->LockForControl();
        intResult = sessionForSys_->EnableLowLightDetection(true);
        sessionForSys_->UnlockForControl();
        EXPECT_EQ(intResult, 0);
    }

    intResult = sessionForSys_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    intResult = sessionForSys_->Stop();
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test photo session sketch functions
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo session sketch functions
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_029, TestSize.Level1)
{
    auto previewProfile = GetSketchPreviewProfile();
    if (previewProfile == nullptr) {
        EXPECT_EQ(previewProfile.get(), nullptr);
        GTEST_SKIP();
    }
    auto output = CreatePreviewOutput(*previewProfile);
    ASSERT_NE(output, nullptr);

    session_->SetMode(SceneMode::CAPTURE);
    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddOutput(output);
    EXPECT_EQ(intResult, 0);

    sptr<PreviewOutput> previewOutput = (sptr<PreviewOutput>&)output;
    bool isSketchSupport = previewOutput->IsSketchSupported();
    if (!isSketchSupport) {
        GTEST_SKIP();
    }

    int sketchEnableRatio = previewOutput->GetSketchRatio();
    EXPECT_GT(sketchEnableRatio, 0);

    intResult = previewOutput->EnableSketch(true);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    intResult = previewOutput->AttachSketchSurface(CreateSketchSurface(previewProfile->GetCameraFormat()));
    EXPECT_EQ(intResult, 0);

    intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    intResult = session_->Stop();
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test photo session sketch functions callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo session sketch functions callback
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_030, TestSize.Level0)
{
    auto previewProfile = GetSketchPreviewProfile();
    if (previewProfile == nullptr) {
        EXPECT_EQ(previewProfile.get(), nullptr);
        GTEST_SKIP();
    }
    auto output = CreatePreviewOutput(*previewProfile);
    ASSERT_NE(output, nullptr);

    session_->SetMode(SceneMode::CAPTURE);
    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddOutput(output);
    EXPECT_EQ(intResult, 0);

    sptr<PreviewOutput> previewOutput = (sptr<PreviewOutput>&)output;
    bool isSketchSupport = previewOutput->IsSketchSupported();
    if (!isSketchSupport) {
        GTEST_SKIP();
    }

    previewOutput->SetCallback(std::make_shared<AppCallback>());

    int sketchEnableRatio = previewOutput->GetSketchRatio();
    EXPECT_GT(sketchEnableRatio, 0);

    intResult = previewOutput->EnableSketch(true);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    intResult = previewOutput->AttachSketchSurface(CreateSketchSurface(previewProfile->GetCameraFormat()));
    EXPECT_EQ(intResult, 0);

    intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    EXPECT_EQ(g_previewEvents[static_cast<int>(CAM_PREVIEW_EVENTS::CAM_PREVIEW_SKETCH_STATUS_CHANGED)], 0);

    session_->LockForControl();
    intResult = session_->SetZoomRatio(30.0f);
    EXPECT_EQ(intResult, 0);
    session_->UnlockForControl();

    sleep(WAIT_TIME_AFTER_START);

    EXPECT_EQ(g_previewEvents[static_cast<int>(CAM_PREVIEW_EVENTS::CAM_PREVIEW_SKETCH_STATUS_CHANGED)], 1);
    g_previewEvents.reset();

    sleep(WAIT_TIME_AFTER_START);
    auto statusSize = g_sketchStatus.size();
    EXPECT_GT(statusSize, 0);
    if (statusSize == 2) {
        EXPECT_EQ(g_sketchStatus.front(), 3);
        g_sketchStatus.pop_front();
        EXPECT_EQ(g_sketchStatus.front(), 1);
        g_sketchStatus.pop_front();
    }

    sleep(1);
    EXPECT_EQ(g_previewEvents[static_cast<int>(CAM_PREVIEW_EVENTS::CAM_PREVIEW_SKETCH_STATUS_CHANGED)], 0);

    intResult = session_->Stop();
    sleep(WAIT_TIME_AFTER_START);
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test photo session sketch functions anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo session sketch functions anomalous branch
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_031, TestSize.Level1)
{
    auto previewProfile = GetSketchPreviewProfile();
    if (previewProfile == nullptr) {
        EXPECT_EQ(previewProfile.get(), nullptr);
        GTEST_SKIP();
    }
    auto output = CreatePreviewOutput(*previewProfile);
    ASSERT_NE(output, nullptr);

    sptr<PreviewOutput> previewOutput = (sptr<PreviewOutput>&)output;
    bool isSketchSupport = previewOutput->IsSketchSupported();
    ASSERT_FALSE(isSketchSupport);

    session_->SetMode(SceneMode::CAPTURE);
    int32_t intResult = session_->BeginConfig();

    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddOutput(output);
    EXPECT_EQ(intResult, 0);

    isSketchSupport = previewOutput->IsSketchSupported();
    if (!isSketchSupport) {
        GTEST_SKIP();
    }

    session_->SetMode(SceneMode::PORTRAIT);
    int sketchEnableRatio = previewOutput->GetSketchRatio();
    EXPECT_LT(sketchEnableRatio, 0);

    session_->SetMode(SceneMode::CAPTURE);
    sketchEnableRatio = previewOutput->GetSketchRatio();
    EXPECT_GT(sketchEnableRatio, 0);

    auto sketchSurface = CreateSketchSurface(previewProfile->GetCameraFormat());

    intResult = previewOutput->EnableSketch(true);
    EXPECT_EQ(intResult, 0);

    intResult = previewOutput->AttachSketchSurface(sketchSurface);
    EXPECT_EQ(intResult, SESSION_NOT_CONFIG);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    intResult = previewOutput->AttachSketchSurface(sketchSurface);
    EXPECT_EQ(intResult, 0);

    intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    intResult = previewOutput->EnableSketch(true);
    EXPECT_EQ(intResult, SESSION_NOT_CONFIG);

    sleep(WAIT_TIME_AFTER_START);

    intResult = previewOutput->AttachSketchSurface(sketchSurface);
    EXPECT_EQ(intResult, 0);

    intResult = session_->Stop();
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test photo session sketch functions auto start sketch while zoom set
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo session sketch functions auto start sketch while zoom set
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_032, TestSize.Level1)
{
    auto previewProfile = GetSketchPreviewProfile();
    if (previewProfile == nullptr) {
        EXPECT_EQ(previewProfile.get(), nullptr);
        GTEST_SKIP();
    }
    auto output = CreatePreviewOutput(*previewProfile);
    ASSERT_NE(output, nullptr);

    session_->SetMode(SceneMode::CAPTURE);
    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddOutput(output);
    EXPECT_EQ(intResult, 0);

    sptr<PreviewOutput> previewOutput = (sptr<PreviewOutput>&)output;
    previewOutput->SetCallback(std::make_shared<AppCallback>());
    bool isSketchSupport = previewOutput->IsSketchSupported();
    if (!isSketchSupport) {
        GTEST_SKIP();
    }

    int sketchEnableRatio = previewOutput->GetSketchRatio();
    EXPECT_GT(sketchEnableRatio, 0);

    intResult = previewOutput->EnableSketch(true);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    intResult = previewOutput->AttachSketchSurface(CreateSketchSurface(previewProfile->GetCameraFormat()));
    EXPECT_EQ(intResult, 0);

    session_->LockForControl();
    intResult = session_->SetZoomRatio(30.0f);
    EXPECT_EQ(intResult, 0);
    session_->UnlockForControl();

    intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);
    EXPECT_EQ(g_previewEvents[static_cast<int>(CAM_PREVIEW_EVENTS::CAM_PREVIEW_SKETCH_STATUS_CHANGED)], 1);
    g_previewEvents.reset();

    auto statusSize = g_sketchStatus.size();
    EXPECT_GE(statusSize, 2);
    auto it = std::find(g_sketchStatus.begin(), g_sketchStatus.end(), 3);
    EXPECT_TRUE(it != g_sketchStatus.end());

    sleep(WAIT_TIME_AFTER_START);
    EXPECT_EQ(g_previewEvents[static_cast<int>(CAM_PREVIEW_EVENTS::CAM_PREVIEW_SKETCH_STATUS_CHANGED)], 0);
    g_previewEvents.reset();

    session_->LockForControl();
    intResult = session_->SetZoomRatio(1.0f);
    EXPECT_EQ(intResult, 0);
    session_->UnlockForControl();

    sleep(WAIT_TIME_AFTER_START);
    EXPECT_EQ(g_previewEvents[static_cast<int>(CAM_PREVIEW_EVENTS::CAM_PREVIEW_SKETCH_STATUS_CHANGED)], 1);
    g_previewEvents.reset();

    statusSize = g_sketchStatus.size();
    EXPECT_GE(statusSize, 2);
    it = std::find(g_sketchStatus.begin(), g_sketchStatus.end(), 2);
    EXPECT_TRUE(it != g_sketchStatus.end());

    sleep(WAIT_TIME_AFTER_START);
    EXPECT_EQ(g_previewEvents[static_cast<int>(CAM_PREVIEW_EVENTS::CAM_PREVIEW_SKETCH_STATUS_CHANGED)], 0);
    g_previewEvents.reset();

    intResult = session_->Stop();
    sleep(WAIT_TIME_AFTER_START);
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test photo session smooth zoom and sketch functions callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo session smooth zoom and sketch functions callback
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_033, TestSize.Level0)
{
    auto previewProfile = GetSketchPreviewProfile();
    if (previewProfile == nullptr) {
        EXPECT_EQ(previewProfile.get(), nullptr);
        GTEST_SKIP();
    }
    auto output = CreatePreviewOutput(*previewProfile);
    ASSERT_NE(output, nullptr);

    session_->SetMode(SceneMode::CAPTURE);
    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddOutput(output);
    EXPECT_EQ(intResult, 0);

    sptr<PreviewOutput> previewOutput = (sptr<PreviewOutput>&)output;
    bool isSketchSupport = previewOutput->IsSketchSupported();
    if (!isSketchSupport) {
        GTEST_SKIP();
    }

    previewOutput->SetCallback(std::make_shared<AppCallback>());

    int sketchEnableRatio = previewOutput->GetSketchRatio();
    EXPECT_GT(sketchEnableRatio, 0);

    intResult = previewOutput->EnableSketch(true);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    intResult = previewOutput->AttachSketchSurface(CreateSketchSurface(previewProfile->GetCameraFormat()));
    EXPECT_EQ(intResult, 0);

    intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    EXPECT_EQ(g_previewEvents[static_cast<int>(CAM_PREVIEW_EVENTS::CAM_PREVIEW_SKETCH_STATUS_CHANGED)], 0);

    session_->LockForControl();
    intResult = session_->SetSmoothZoom(30.0f, 0);
    EXPECT_EQ(intResult, 0);
    session_->UnlockForControl();

    sleep(WAIT_TIME_AFTER_START);

    EXPECT_EQ(g_previewEvents[static_cast<int>(CAM_PREVIEW_EVENTS::CAM_PREVIEW_SKETCH_STATUS_CHANGED)], 1);
    g_previewEvents.reset();

    sleep(WAIT_TIME_AFTER_START);
    auto statusSize = g_sketchStatus.size();
    EXPECT_GE(statusSize, 1);

    sleep(1);
    EXPECT_EQ(g_previewEvents[static_cast<int>(CAM_PREVIEW_EVENTS::CAM_PREVIEW_SKETCH_STATUS_CHANGED)], 0);

    intResult = session_->Stop();
    sleep(WAIT_TIME_AFTER_START);
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test photo session moon capture boost function
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo session moon capture boost function
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_034, TestSize.Level1)
{
    auto previewProfile = GetSketchPreviewProfile();
    if (previewProfile == nullptr) {
        EXPECT_EQ(previewProfile.get(), nullptr);
        GTEST_SKIP();
    }
    auto output = CreatePreviewOutput(*previewProfile);
    sptr<PreviewOutput> previewOutput = (sptr<PreviewOutput>&)output;
    ASSERT_NE(output, nullptr);

    sessionForSys_->SetMode(SceneMode::CAPTURE);
    int32_t intResult = sessionForSys_->BeginConfig();

    EXPECT_EQ(intResult, 0);

    intResult = sessionForSys_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    intResult = sessionForSys_->AddOutput(output);
    EXPECT_EQ(intResult, 0);

    intResult = sessionForSys_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    sessionForSys_->SetFeatureDetectionStatusCallback(std::make_shared<AppCallback>());

    g_moonCaptureBoostEvents.reset();
    intResult = sessionForSys_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    bool isMoonCaptureBoostSupported = sessionForSys_->IsFeatureSupported(FEATURE_MOON_CAPTURE_BOOST);
    if (isMoonCaptureBoostSupported) {
        EXPECT_EQ(g_moonCaptureBoostEvents.count(), 1);
        if (g_moonCaptureBoostEvents[static_cast<int>(
                CAM_MOON_CAPTURE_BOOST_EVENTS::CAM_MOON_CAPTURE_BOOST_EVENT_ACTIVE)] == 1) {
            intResult = sessionForSys_->EnableFeature(FEATURE_MOON_CAPTURE_BOOST, true);
            EXPECT_EQ(intResult, 0);
        }
        if (g_moonCaptureBoostEvents[static_cast<int>(
                CAM_MOON_CAPTURE_BOOST_EVENTS::CAM_MOON_CAPTURE_BOOST_EVENT_IDLE)] == 1) {
            intResult = sessionForSys_->EnableFeature(FEATURE_MOON_CAPTURE_BOOST, false);
            EXPECT_EQ(intResult, 0);
        }
    }

    sleep(WAIT_TIME_AFTER_START);

    intResult = sessionForSys_->Stop();
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test photo session lcd flash
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo session lcd flash
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_035, TestSize.Level1)
{
    if (sessionForSys_) {
        sessionForSys_->Release();
        sessionForSys_ = nullptr;
        input_->Close();
    }
    sessionForSys_ = managerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys_, nullptr);

    int32_t intResult = sessionForSys_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    if (cameras_.size() > 1) {
        input_ = manager_->CreateCameraInput(cameras_[1]);
        ASSERT_NE(input_, nullptr);
        EXPECT_EQ(input_->Open(), 0);

        intResult = sessionForSys_->AddInput(input_);
        EXPECT_EQ(intResult, 0);

        sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
        ASSERT_NE(previewOutput, nullptr);

        intResult = sessionForSys_->AddOutput(previewOutput);
        EXPECT_EQ(intResult, 0);

        intResult = sessionForSys_->CommitConfig();
        EXPECT_EQ(intResult, 0);

        bool isSupported = sessionForSys_->IsLcdFlashSupported();
        EXPECT_EQ(isSupported, true);

        if (isSupported) {
            sessionForSys_->SetLcdFlashStatusCallback(std::make_shared<AppCallback>());
            sessionForSys_->LockForControl();
            intResult = sessionForSys_->EnableLcdFlashDetection(true);
            sessionForSys_->UnlockForControl();
            EXPECT_EQ(intResult, 0);
        }

        intResult = sessionForSys_->Start();
        EXPECT_EQ(intResult, 0);

        sleep(WAIT_TIME_AFTER_START);

        intResult = sessionForSys_->Stop();
        EXPECT_EQ(intResult, 0);
    }
}

/*
 * Feature: Framework
 * Function: Test photo session lcd flash anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo session lcd flash anomalous branch
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_036, TestSize.Level1)
{
    session_ = manager_->CreateCaptureSession(SceneMode::CAPTURE);
    ASSERT_NE(session_, nullptr);

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

    bool isSupported = session_->IsLcdFlashSupported();
    EXPECT_EQ(isSupported, false);
}

/*
 * Feature: Framework
 * Function: Test photo session tripod
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo session tripod
 */
HWTEST_F(CameraSessionModuleTest, photo_session_moduletest_037, TestSize.Level1)
{
    sessionForSys_ = managerForSys_->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    ASSERT_NE(sessionForSys_, nullptr);

    int32_t intResult = sessionForSys_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = sessionForSys_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = sessionForSys_->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    intResult = sessionForSys_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    if (sessionForSys_->IsTripodDetectionSupported()) {
        sessionForSys_->SetFeatureDetectionStatusCallback(std::make_shared<AppCallback>());
        sessionForSys_->EnableFeature(FEATURE_TRIPOD_DETECTION, true);
        EXPECT_EQ(intResult, 0);
    }

    intResult = sessionForSys_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    intResult = sessionForSys_->Stop();
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test video session with photo output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can add photo output into video session
 */
HWTEST_F(CameraSessionModuleTest, video_session_moduletest_001, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::VIDEO)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::VIDEO);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    auto photoProfiles = outputCapability->GetPhotoProfiles();
    ASSERT_FALSE(photoProfiles.empty());

    auto captureSession = manager_->CreateCaptureSession(SceneMode::VIDEO);
    auto videoSession = static_cast<VideoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(videoSession, nullptr);
    int32_t res = videoSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = videoSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(videoSession->CanAddOutput(previewOutput));
    res = videoSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoProfiles[0]);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_TRUE(videoSession->CanAddOutput(photoOutput));
    res = videoSession->AddOutput(photoOutput);
    EXPECT_EQ(res, 0);

    res = videoSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = videoSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);
    res = static_cast<PhotoOutput*>(photoOutput.GetRefPtr())->Capture();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);
    res = videoSession->Stop();
    EXPECT_EQ(res, 0);
    res = videoSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test video session with video output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can add video output into video session
 */
HWTEST_F(CameraSessionModuleTest, video_session_moduletest_002, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::VIDEO)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::VIDEO);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    FilterPreviewProfiles(previewProfiles);
    ASSERT_FALSE(previewProfiles.empty());
    auto videoProfiles = outputCapability->GetVideoProfiles();
    ASSERT_FALSE(videoProfiles.empty());

    auto captureSession = manager_->CreateCaptureSession(SceneMode::VIDEO);
    auto videoSession = static_cast<VideoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(videoSession, nullptr);
    int32_t res = videoSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = videoSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(videoSession->CanAddOutput(previewOutput));
    res = videoSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfiles[0]);
    ASSERT_NE(videoOutput, nullptr);
    EXPECT_TRUE(videoSession->CanAddOutput(videoOutput));
    res = videoSession->AddOutput(videoOutput);
    EXPECT_EQ(res, 0);

    res = videoSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = videoSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);
    res = static_cast<VideoOutput*>(videoOutput.GetRefPtr())->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);
    res = static_cast<VideoOutput*>(videoOutput.GetRefPtr())->Stop();
    EXPECT_EQ(res, 0);
    res = videoSession->Stop();
    EXPECT_EQ(res, 0);
    res = videoSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test video session set frame rate range
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can set frame rate range into video session
 */
HWTEST_F(CameraSessionModuleTest, video_session_moduletest_003, TestSize.Level0)
{
    if (!IsSceneModeSupported(SceneMode::VIDEO)) {
        GTEST_SKIP();
    }

    auto outputCapability = manager_->GetSupportedOutputCapability(cameras_[0], SceneMode::VIDEO);
    ASSERT_NE(outputCapability, nullptr);
    auto previewProfiles = outputCapability->GetPreviewProfiles();
    ASSERT_FALSE(previewProfiles.empty());
    FilterPreviewProfiles(previewProfiles);
    ASSERT_FALSE(previewProfiles.empty());
    auto photoProfiles = outputCapability->GetPhotoProfiles();
    ASSERT_FALSE(photoProfiles.empty());
    auto videoProfiles = outputCapability->GetVideoProfiles();
    ASSERT_FALSE(videoProfiles.empty());

    auto captureSession = manager_->CreateCaptureSession(SceneMode::VIDEO);
    auto videoSession = static_cast<VideoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(videoSession, nullptr);
    int32_t res = videoSession->BeginConfig();
    EXPECT_EQ(res, 0);

    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
    ASSERT_NE(input, nullptr);
    input->Open();
    res = videoSession->AddInput(input);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfiles[0]);
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_TRUE(videoSession->CanAddOutput(previewOutput));
    res = videoSession->AddOutput(previewOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(photoProfiles[0]);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_TRUE(videoSession->CanAddOutput(photoOutput));
    res = videoSession->AddOutput(photoOutput);
    EXPECT_EQ(res, 0);
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfiles[0]);
    ASSERT_NE(videoOutput, nullptr);
    EXPECT_TRUE(videoSession->CanAddOutput(videoOutput));
    res = videoSession->AddOutput(videoOutput);
    EXPECT_EQ(res, 0);

    res = videoSession->CommitConfig();
    EXPECT_EQ(res, 0);
    res = videoSession->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);

    std::vector<std::vector<int32_t>> frameRateArray = ((sptr<VideoOutput>&)videoOutput)->GetSupportedFrameRates();
    ASSERT_NE(frameRateArray.size(), 0);
    std::vector<int32_t> frameRateRange = ((sptr<VideoOutput>&)videoOutput)->GetFrameRateRange();
    ASSERT_NE(frameRateRange.size(), 0);
    res = ((sptr<VideoOutput>&)videoOutput)->canSetFrameRateRange(DEFAULT_MIN_FRAME_RATE, DEFAULT_MAX_FRAME_RATE);
    EXPECT_EQ(res, 0);
    ((sptr<VideoOutput>&)videoOutput)->SetFrameRateRange(DEFAULT_MIN_FRAME_RATE, DEFAULT_MAX_FRAME_RATE);
    frameRateRange = ((sptr<VideoOutput>&)videoOutput)->GetFrameRateRange();
    ASSERT_NE(frameRateRange.size(), 0);
    EXPECT_EQ(frameRateRange[0], DEFAULT_MIN_FRAME_RATE);
    EXPECT_EQ(frameRateRange[1], DEFAULT_MAX_FRAME_RATE);

    res = static_cast<VideoOutput*>(videoOutput.GetRefPtr())->Start();
    EXPECT_EQ(res, 0);
    sleep(WAIT_TIME_AFTER_START);
    res = static_cast<VideoOutput*>(videoOutput.GetRefPtr())->Stop();
    EXPECT_EQ(res, 0);
    EXPECT_EQ(res, 0);
    res = videoSession->Stop();
    EXPECT_EQ(res, 0);
    res = videoSession->Release();
    EXPECT_EQ(res, 0);
}

/*
 * Feature: Framework
 * Function: Test video session preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can preconfig video session with PRECONFIG_720P, UNSPECIFIED while supported
 */
HWTEST_F(CameraSessionModuleTest, video_session_moduletest_004, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::VIDEO)) {
        GTEST_SKIP();
    }

    auto captureSession = manager_->CreateCaptureSession(SceneMode::VIDEO);
    auto videoSession = static_cast<VideoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(videoSession, nullptr);
    if (videoSession->CanPreconfig(PreconfigType::PRECONFIG_720P, ProfileSizeRatio::UNSPECIFIED)) {
        int32_t res = videoSession->Preconfig(PreconfigType::PRECONFIG_720P, ProfileSizeRatio::UNSPECIFIED);
        EXPECT_EQ(res, 0);
        res = videoSession->BeginConfig();
        EXPECT_EQ(res, 0);

        sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
        ASSERT_NE(input, nullptr);
        input->Open();
        res = videoSession->AddInput(input);
        EXPECT_EQ(res, 0);

        sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
        sptr<Surface> producerPreviewSurface = Surface::CreateSurfaceAsProducer(previewProducer);
        sptr<PreviewOutput> previewOutput = nullptr;
        res = manager_->CreatePreviewOutputWithoutProfile(producerPreviewSurface, &previewOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePreviewOutput = previewOutput;
        EXPECT_TRUE(videoSession->CanAddOutput(capturePreviewOutput));
        res = videoSession->AddOutput(capturePreviewOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> photoProducer = photoSurface->GetProducer();
        sptr<PhotoOutput> photoOutput = nullptr;
        res = manager_->CreatePhotoOutputWithoutProfile(photoProducer, &photoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePhotoOutput = photoOutput;
        EXPECT_TRUE(videoSession->CanAddOutput(capturePhotoOutput));
        res = videoSession->AddOutput(capturePhotoOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> videoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> videoProducer = videoSurface->GetProducer();
        sptr<Surface> producerVideoSurface = Surface::CreateSurfaceAsProducer(videoProducer);
        sptr<VideoOutput> videoOutput = nullptr;
        res = manager_->CreateVideoOutputWithoutProfile(producerVideoSurface, &videoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> captureVideoOutput = videoOutput;
        res = videoSession->AddOutput(captureVideoOutput);
        EXPECT_EQ(res, 0);

        res = videoSession->CommitConfig();
        EXPECT_EQ(res, 0);
        res = videoSession->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = videoOutput->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = videoOutput->Stop();
        EXPECT_EQ(res, 0);
        res = videoSession->Stop();
        EXPECT_EQ(res, 0);
    }
    EXPECT_EQ(videoSession->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test video session preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can preconfig video session with PRECONFIG_720P, RATIO_1_1 while supported
 */
HWTEST_F(CameraSessionModuleTest, video_session_moduletest_005, TestSize.Level0)
{
    if (!IsSceneModeSupported(SceneMode::VIDEO)) {
        GTEST_SKIP();
    }

    auto captureSession = manager_->CreateCaptureSession(SceneMode::VIDEO);
    auto videoSession = static_cast<VideoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(videoSession, nullptr);
    if (videoSession->CanPreconfig(PreconfigType::PRECONFIG_720P, ProfileSizeRatio::RATIO_1_1)) {
        int32_t res = videoSession->Preconfig(PreconfigType::PRECONFIG_720P, ProfileSizeRatio::RATIO_1_1);
        EXPECT_EQ(res, 0);
        res = videoSession->BeginConfig();
        EXPECT_EQ(res, 0);

        sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
        ASSERT_NE(input, nullptr);
        input->Open();
        res = videoSession->AddInput(input);
        EXPECT_EQ(res, 0);

        sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
        sptr<Surface> producerPreviewSurface = Surface::CreateSurfaceAsProducer(previewProducer);
        sptr<PreviewOutput> previewOutput = nullptr;
        res = manager_->CreatePreviewOutputWithoutProfile(producerPreviewSurface, &previewOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePreviewOutput = previewOutput;
        EXPECT_TRUE(videoSession->CanAddOutput(capturePreviewOutput));
        res = videoSession->AddOutput(capturePreviewOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> photoProducer = photoSurface->GetProducer();
        sptr<PhotoOutput> photoOutput = nullptr;
        res = manager_->CreatePhotoOutputWithoutProfile(photoProducer, &photoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePhotoOutput = photoOutput;
        EXPECT_TRUE(videoSession->CanAddOutput(capturePhotoOutput));
        res = videoSession->AddOutput(capturePhotoOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> videoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> videoProducer = videoSurface->GetProducer();
        sptr<Surface> producerVideoSurface = Surface::CreateSurfaceAsProducer(videoProducer);
        sptr<VideoOutput> videoOutput = nullptr;
        res = manager_->CreateVideoOutputWithoutProfile(producerVideoSurface, &videoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> captureVideoOutput = videoOutput;
        res = videoSession->AddOutput(captureVideoOutput);
        EXPECT_EQ(res, 0);

        res = videoSession->CommitConfig();
        EXPECT_EQ(res, 0);
        res = videoSession->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = videoOutput->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = videoOutput->Stop();
        EXPECT_EQ(res, 0);
        res = videoSession->Stop();
        EXPECT_EQ(res, 0);
    }
    EXPECT_EQ(videoSession->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test video session preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can preconfig video session with PRECONFIG_720P, RATIO_4_3 while supported
 */
HWTEST_F(CameraSessionModuleTest, video_session_moduletest_006, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::VIDEO)) {
        GTEST_SKIP();
    }

    auto captureSession = manager_->CreateCaptureSession(SceneMode::VIDEO);
    auto videoSession = static_cast<VideoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(videoSession, nullptr);
    if (videoSession->CanPreconfig(PreconfigType::PRECONFIG_720P, ProfileSizeRatio::RATIO_4_3)) {
        int32_t res = videoSession->Preconfig(PreconfigType::PRECONFIG_720P, ProfileSizeRatio::RATIO_4_3);
        EXPECT_EQ(res, 0);
        res = videoSession->BeginConfig();
        EXPECT_EQ(res, 0);

        sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
        ASSERT_NE(input, nullptr);
        input->Open();
        res = videoSession->AddInput(input);
        EXPECT_EQ(res, 0);

        sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
        sptr<Surface> producerPreviewSurface = Surface::CreateSurfaceAsProducer(previewProducer);
        sptr<PreviewOutput> previewOutput = nullptr;
        res = manager_->CreatePreviewOutputWithoutProfile(producerPreviewSurface, &previewOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePreviewOutput = previewOutput;
        EXPECT_TRUE(videoSession->CanAddOutput(capturePreviewOutput));
        res = videoSession->AddOutput(capturePreviewOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> photoProducer = photoSurface->GetProducer();
        sptr<PhotoOutput> photoOutput = nullptr;
        res = manager_->CreatePhotoOutputWithoutProfile(photoProducer, &photoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePhotoOutput = photoOutput;
        EXPECT_TRUE(videoSession->CanAddOutput(capturePhotoOutput));
        res = videoSession->AddOutput(capturePhotoOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> videoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> videoProducer = videoSurface->GetProducer();
        sptr<Surface> producerVideoSurface = Surface::CreateSurfaceAsProducer(videoProducer);
        sptr<VideoOutput> videoOutput = nullptr;
        res = manager_->CreateVideoOutputWithoutProfile(producerVideoSurface, &videoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> captureVideoOutput = videoOutput;
        res = videoSession->AddOutput(captureVideoOutput);
        EXPECT_EQ(res, 0);

        res = videoSession->CommitConfig();
        EXPECT_EQ(res, 0);
        res = videoSession->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = videoOutput->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = videoOutput->Stop();
        EXPECT_EQ(res, 0);
        res = videoSession->Stop();
        EXPECT_EQ(res, 0);
    }
    EXPECT_EQ(videoSession->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test video session preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can preconfig video session with PRECONFIG_720P, RATIO_16_9 while supported
 */
HWTEST_F(CameraSessionModuleTest, video_session_moduletest_007, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::VIDEO)) {
        GTEST_SKIP();
    }

    auto captureSession = manager_->CreateCaptureSession(SceneMode::VIDEO);
    auto videoSession = static_cast<VideoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(videoSession, nullptr);
    if (videoSession->CanPreconfig(PreconfigType::PRECONFIG_720P, ProfileSizeRatio::RATIO_16_9)) {
        int32_t res = videoSession->Preconfig(PreconfigType::PRECONFIG_720P, ProfileSizeRatio::RATIO_16_9);
        EXPECT_EQ(res, 0);
        res = videoSession->BeginConfig();
        EXPECT_EQ(res, 0);

        sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
        ASSERT_NE(input, nullptr);
        input->Open();
        res = videoSession->AddInput(input);
        EXPECT_EQ(res, 0);

        sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
        sptr<Surface> producerPreviewSurface = Surface::CreateSurfaceAsProducer(previewProducer);
        sptr<PreviewOutput> previewOutput = nullptr;
        res = manager_->CreatePreviewOutputWithoutProfile(producerPreviewSurface, &previewOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePreviewOutput = previewOutput;
        EXPECT_TRUE(videoSession->CanAddOutput(capturePreviewOutput));
        res = videoSession->AddOutput(capturePreviewOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> photoProducer = photoSurface->GetProducer();
        sptr<PhotoOutput> photoOutput = nullptr;
        res = manager_->CreatePhotoOutputWithoutProfile(photoProducer, &photoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePhotoOutput = photoOutput;
        EXPECT_TRUE(videoSession->CanAddOutput(capturePhotoOutput));
        res = videoSession->AddOutput(capturePhotoOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> videoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> videoProducer = videoSurface->GetProducer();
        sptr<Surface> producerVideoSurface = Surface::CreateSurfaceAsProducer(videoProducer);
        sptr<VideoOutput> videoOutput = nullptr;
        res = manager_->CreateVideoOutputWithoutProfile(producerVideoSurface, &videoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> captureVideoOutput = videoOutput;
        res = videoSession->AddOutput(captureVideoOutput);
        EXPECT_EQ(res, 0);

        res = videoSession->CommitConfig();
        EXPECT_EQ(res, 0);
        res = videoSession->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = videoOutput->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = videoOutput->Stop();
        EXPECT_EQ(res, 0);
        res = videoSession->Stop();
        EXPECT_EQ(res, 0);
    }
    EXPECT_EQ(videoSession->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test video session preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can preconfig video session with PRECONFIG_1080P, UNSPECIFIED while supported
 */
HWTEST_F(CameraSessionModuleTest, video_session_moduletest_008, TestSize.Level1)
{
    if (!IsSceneModeSupported(SceneMode::VIDEO)) {
        GTEST_SKIP();
    }

    auto captureSession = manager_->CreateCaptureSession(SceneMode::VIDEO);
    auto videoSession = static_cast<VideoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(videoSession, nullptr);
    if (videoSession->CanPreconfig(PreconfigType::PRECONFIG_1080P, ProfileSizeRatio::UNSPECIFIED)) {
        int32_t res = videoSession->Preconfig(PreconfigType::PRECONFIG_1080P, ProfileSizeRatio::UNSPECIFIED);
        EXPECT_EQ(res, 0);
        res = videoSession->BeginConfig();
        EXPECT_EQ(res, 0);

        sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
        ASSERT_NE(input, nullptr);
        input->Open();
        res = videoSession->AddInput(input);
        EXPECT_EQ(res, 0);

        sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
        sptr<Surface> producerPreviewSurface = Surface::CreateSurfaceAsProducer(previewProducer);
        sptr<PreviewOutput> previewOutput = nullptr;
        res = manager_->CreatePreviewOutputWithoutProfile(producerPreviewSurface, &previewOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePreviewOutput = previewOutput;
        EXPECT_TRUE(videoSession->CanAddOutput(capturePreviewOutput));
        res = videoSession->AddOutput(capturePreviewOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> photoProducer = photoSurface->GetProducer();
        sptr<PhotoOutput> photoOutput = nullptr;
        res = manager_->CreatePhotoOutputWithoutProfile(photoProducer, &photoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePhotoOutput = photoOutput;
        EXPECT_TRUE(videoSession->CanAddOutput(capturePhotoOutput));
        res = videoSession->AddOutput(capturePhotoOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> videoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> videoProducer = videoSurface->GetProducer();
        sptr<Surface> producerVideoSurface = Surface::CreateSurfaceAsProducer(videoProducer);
        sptr<VideoOutput> videoOutput = nullptr;
        res = manager_->CreateVideoOutputWithoutProfile(producerVideoSurface, &videoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> captureVideoOutput = videoOutput;
        res = videoSession->AddOutput(captureVideoOutput);
        EXPECT_EQ(res, 0);

        res = videoSession->CommitConfig();
        EXPECT_EQ(res, 0);
        res = videoSession->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = videoOutput->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = videoOutput->Stop();
        EXPECT_EQ(res, 0);
        res = videoSession->Stop();
        EXPECT_EQ(res, 0);
    }
    EXPECT_EQ(videoSession->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test video session preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can preconfig video session with PRECONFIG_1080P, RATIO_1_1 while supported
 */
HWTEST_F(CameraSessionModuleTest, video_session_moduletest_009, TestSize.Level0)
{
    if (!IsSceneModeSupported(SceneMode::VIDEO)) {
        GTEST_SKIP();
    }

    auto captureSession = manager_->CreateCaptureSession(SceneMode::VIDEO);
    auto videoSession = static_cast<VideoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(videoSession, nullptr);
    if (videoSession->CanPreconfig(PreconfigType::PRECONFIG_1080P, ProfileSizeRatio::RATIO_1_1)) {
        int32_t res = videoSession->Preconfig(PreconfigType::PRECONFIG_1080P, ProfileSizeRatio::RATIO_1_1);
        EXPECT_EQ(res, 0);
        res = videoSession->BeginConfig();
        EXPECT_EQ(res, 0);

        sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
        ASSERT_NE(input, nullptr);
        input->Open();
        res = videoSession->AddInput(input);
        EXPECT_EQ(res, 0);

        sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
        sptr<Surface> producerPreviewSurface = Surface::CreateSurfaceAsProducer(previewProducer);
        sptr<PreviewOutput> previewOutput = nullptr;
        res = manager_->CreatePreviewOutputWithoutProfile(producerPreviewSurface, &previewOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePreviewOutput = previewOutput;
        EXPECT_TRUE(videoSession->CanAddOutput(capturePreviewOutput));
        res = videoSession->AddOutput(capturePreviewOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> photoProducer = photoSurface->GetProducer();
        sptr<PhotoOutput> photoOutput = nullptr;
        res = manager_->CreatePhotoOutputWithoutProfile(photoProducer, &photoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePhotoOutput = photoOutput;
        EXPECT_TRUE(videoSession->CanAddOutput(capturePhotoOutput));
        res = videoSession->AddOutput(capturePhotoOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> videoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> videoProducer = videoSurface->GetProducer();
        sptr<Surface> producerVideoSurface = Surface::CreateSurfaceAsProducer(videoProducer);
        sptr<VideoOutput> videoOutput = nullptr;
        res = manager_->CreateVideoOutputWithoutProfile(producerVideoSurface, &videoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> captureVideoOutput = videoOutput;
        res = videoSession->AddOutput(captureVideoOutput);
        EXPECT_EQ(res, 0);

        res = videoSession->CommitConfig();
        EXPECT_EQ(res, 0);
        res = videoSession->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = videoOutput->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = videoOutput->Stop();
        EXPECT_EQ(res, 0);
        res = videoSession->Stop();
        EXPECT_EQ(res, 0);
    }
    EXPECT_EQ(videoSession->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test video session preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can preconfig video session with PRECONFIG_1080P, RATIO_4_3 while supported
 */
HWTEST_F(CameraSessionModuleTest, video_session_moduletest_010, TestSize.Level0)
{
    if (!IsSceneModeSupported(SceneMode::VIDEO)) {
        GTEST_SKIP();
    }

    auto captureSession = manager_->CreateCaptureSession(SceneMode::VIDEO);
    auto videoSession = static_cast<VideoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(videoSession, nullptr);
    if (videoSession->CanPreconfig(PreconfigType::PRECONFIG_1080P, ProfileSizeRatio::RATIO_4_3)) {
        int32_t res = videoSession->Preconfig(PreconfigType::PRECONFIG_1080P, ProfileSizeRatio::RATIO_4_3);
        EXPECT_EQ(res, 0);
        res = videoSession->BeginConfig();
        EXPECT_EQ(res, 0);

        sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
        ASSERT_NE(input, nullptr);
        input->Open();
        res = videoSession->AddInput(input);
        EXPECT_EQ(res, 0);

        sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
        sptr<Surface> producerPreviewSurface = Surface::CreateSurfaceAsProducer(previewProducer);
        sptr<PreviewOutput> previewOutput = nullptr;
        res = manager_->CreatePreviewOutputWithoutProfile(producerPreviewSurface, &previewOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePreviewOutput = previewOutput;
        EXPECT_TRUE(videoSession->CanAddOutput(capturePreviewOutput));
        res = videoSession->AddOutput(capturePreviewOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> photoProducer = photoSurface->GetProducer();
        sptr<PhotoOutput> photoOutput = nullptr;
        res = manager_->CreatePhotoOutputWithoutProfile(photoProducer, &photoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePhotoOutput = photoOutput;
        EXPECT_TRUE(videoSession->CanAddOutput(capturePhotoOutput));
        res = videoSession->AddOutput(capturePhotoOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> videoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> videoProducer = videoSurface->GetProducer();
        sptr<Surface> producerVideoSurface = Surface::CreateSurfaceAsProducer(videoProducer);
        sptr<VideoOutput> videoOutput = nullptr;
        res = manager_->CreateVideoOutputWithoutProfile(producerVideoSurface, &videoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> captureVideoOutput = videoOutput;
        res = videoSession->AddOutput(captureVideoOutput);
        EXPECT_EQ(res, 0);

        res = videoSession->CommitConfig();
        EXPECT_EQ(res, 0);
        res = videoSession->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = videoOutput->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = videoOutput->Stop();
        EXPECT_EQ(res, 0);
        res = videoSession->Stop();
        EXPECT_EQ(res, 0);
    }
    EXPECT_EQ(videoSession->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test video session preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can preconfig video session with PRECONFIG_1080P, RATIO_16_9 while supported
 */
HWTEST_F(CameraSessionModuleTest, video_session_moduletest_011, TestSize.Level0)
{
    if (!IsSceneModeSupported(SceneMode::VIDEO)) {
        GTEST_SKIP();
    }

    auto captureSession = manager_->CreateCaptureSession(SceneMode::VIDEO);
    auto videoSession = static_cast<VideoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(videoSession, nullptr);
    if (videoSession->CanPreconfig(PreconfigType::PRECONFIG_1080P, ProfileSizeRatio::RATIO_16_9)) {
        int32_t res = videoSession->Preconfig(PreconfigType::PRECONFIG_1080P, ProfileSizeRatio::RATIO_16_9);
        EXPECT_EQ(res, 0);
        res = videoSession->BeginConfig();
        EXPECT_EQ(res, 0);

        sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
        ASSERT_NE(input, nullptr);
        input->Open();
        res = videoSession->AddInput(input);
        EXPECT_EQ(res, 0);

        sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
        sptr<Surface> producerPreviewSurface = Surface::CreateSurfaceAsProducer(previewProducer);
        sptr<PreviewOutput> previewOutput = nullptr;
        res = manager_->CreatePreviewOutputWithoutProfile(producerPreviewSurface, &previewOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePreviewOutput = previewOutput;
        EXPECT_TRUE(videoSession->CanAddOutput(capturePreviewOutput));
        res = videoSession->AddOutput(capturePreviewOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> photoProducer = photoSurface->GetProducer();
        sptr<PhotoOutput> photoOutput = nullptr;
        res = manager_->CreatePhotoOutputWithoutProfile(photoProducer, &photoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePhotoOutput = photoOutput;
        EXPECT_TRUE(videoSession->CanAddOutput(capturePhotoOutput));
        res = videoSession->AddOutput(capturePhotoOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> videoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> videoProducer = videoSurface->GetProducer();
        sptr<Surface> producerVideoSurface = Surface::CreateSurfaceAsProducer(videoProducer);
        sptr<VideoOutput> videoOutput = nullptr;
        res = manager_->CreateVideoOutputWithoutProfile(producerVideoSurface, &videoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> captureVideoOutput = videoOutput;
        res = videoSession->AddOutput(captureVideoOutput);
        EXPECT_EQ(res, 0);

        res = videoSession->CommitConfig();
        EXPECT_EQ(res, 0);
        res = videoSession->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = videoOutput->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = videoOutput->Stop();
        EXPECT_EQ(res, 0);
        res = videoSession->Stop();
        EXPECT_EQ(res, 0);
    }
    EXPECT_EQ(videoSession->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test video session preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can preconfig video session with PRECONFIG_4K, UNSPECIFIED while supported
 */
HWTEST_F(CameraSessionModuleTest, video_session_moduletest_012, TestSize.Level0)
{
    if (!IsSceneModeSupported(SceneMode::VIDEO)) {
        GTEST_SKIP();
    }

    auto captureSession = manager_->CreateCaptureSession(SceneMode::VIDEO);
    auto videoSession = static_cast<VideoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(videoSession, nullptr);
    if (videoSession->CanPreconfig(PreconfigType::PRECONFIG_4K, ProfileSizeRatio::UNSPECIFIED)) {
        int32_t res = videoSession->Preconfig(PreconfigType::PRECONFIG_4K, ProfileSizeRatio::UNSPECIFIED);
        EXPECT_EQ(res, 0);
        res = videoSession->BeginConfig();
        EXPECT_EQ(res, 0);

        sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
        ASSERT_NE(input, nullptr);
        input->Open();
        res = videoSession->AddInput(input);
        EXPECT_EQ(res, 0);

        sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
        sptr<Surface> producerPreviewSurface = Surface::CreateSurfaceAsProducer(previewProducer);
        sptr<PreviewOutput> previewOutput = nullptr;
        res = manager_->CreatePreviewOutputWithoutProfile(producerPreviewSurface, &previewOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePreviewOutput = previewOutput;
        EXPECT_TRUE(videoSession->CanAddOutput(capturePreviewOutput));
        res = videoSession->AddOutput(capturePreviewOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> photoProducer = photoSurface->GetProducer();
        sptr<PhotoOutput> photoOutput = nullptr;
        res = manager_->CreatePhotoOutputWithoutProfile(photoProducer, &photoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePhotoOutput = photoOutput;
        EXPECT_TRUE(videoSession->CanAddOutput(capturePhotoOutput));
        res = videoSession->AddOutput(capturePhotoOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> videoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> videoProducer = videoSurface->GetProducer();
        sptr<Surface> producerVideoSurface = Surface::CreateSurfaceAsProducer(videoProducer);
        sptr<VideoOutput> videoOutput = nullptr;
        res = manager_->CreateVideoOutputWithoutProfile(producerVideoSurface, &videoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> captureVideoOutput = videoOutput;
        res = videoSession->AddOutput(captureVideoOutput);
        EXPECT_EQ(res, 0);

        res = videoSession->CommitConfig();
        EXPECT_EQ(res, 0);
        res = videoSession->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = videoOutput->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = videoOutput->Stop();
        EXPECT_EQ(res, 0);
        res = videoSession->Stop();
        EXPECT_EQ(res, 0);
    }
    EXPECT_EQ(videoSession->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test video session preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can preconfig video session with PRECONFIG_4K, RATIO_1_1 while supported
 */
HWTEST_F(CameraSessionModuleTest, video_session_moduletest_013, TestSize.Level0)
{
    if (!IsSceneModeSupported(SceneMode::VIDEO)) {
        GTEST_SKIP();
    }

    auto captureSession = manager_->CreateCaptureSession(SceneMode::VIDEO);
    auto videoSession = static_cast<VideoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(videoSession, nullptr);
    if (videoSession->CanPreconfig(PreconfigType::PRECONFIG_4K, ProfileSizeRatio::RATIO_1_1)) {
        int32_t res = videoSession->Preconfig(PreconfigType::PRECONFIG_4K, ProfileSizeRatio::RATIO_1_1);
        EXPECT_EQ(res, 0);
        res = videoSession->BeginConfig();
        EXPECT_EQ(res, 0);

        sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
        ASSERT_NE(input, nullptr);
        input->Open();
        res = videoSession->AddInput(input);
        EXPECT_EQ(res, 0);

        sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
        sptr<Surface> producerPreviewSurface = Surface::CreateSurfaceAsProducer(previewProducer);
        sptr<PreviewOutput> previewOutput = nullptr;
        res = manager_->CreatePreviewOutputWithoutProfile(producerPreviewSurface, &previewOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePreviewOutput = previewOutput;
        EXPECT_TRUE(videoSession->CanAddOutput(capturePreviewOutput));
        res = videoSession->AddOutput(capturePreviewOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> photoProducer = photoSurface->GetProducer();
        sptr<PhotoOutput> photoOutput = nullptr;
        res = manager_->CreatePhotoOutputWithoutProfile(photoProducer, &photoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePhotoOutput = photoOutput;
        EXPECT_TRUE(videoSession->CanAddOutput(capturePhotoOutput));
        res = videoSession->AddOutput(capturePhotoOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> videoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> videoProducer = videoSurface->GetProducer();
        sptr<Surface> producerVideoSurface = Surface::CreateSurfaceAsProducer(videoProducer);
        sptr<VideoOutput> videoOutput = nullptr;
        res = manager_->CreateVideoOutputWithoutProfile(producerVideoSurface, &videoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> captureVideoOutput = videoOutput;
        res = videoSession->AddOutput(captureVideoOutput);
        EXPECT_EQ(res, 0);

        res = videoSession->CommitConfig();
        EXPECT_EQ(res, 0);
        res = videoSession->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = videoOutput->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = videoOutput->Stop();
        EXPECT_EQ(res, 0);
        res = videoSession->Stop();
        EXPECT_EQ(res, 0);
    }
    EXPECT_EQ(videoSession->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test video session preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can preconfig video session with PRECONFIG_4K, RATIO_4_3 while supported
 */
HWTEST_F(CameraSessionModuleTest, video_session_moduletest_014, TestSize.Level0)
{
    if (!IsSceneModeSupported(SceneMode::VIDEO)) {
        GTEST_SKIP();
    }

    auto captureSession = manager_->CreateCaptureSession(SceneMode::VIDEO);
    auto videoSession = static_cast<VideoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(videoSession, nullptr);
    if (videoSession->CanPreconfig(PreconfigType::PRECONFIG_4K, ProfileSizeRatio::RATIO_4_3)) {
        int32_t res = videoSession->Preconfig(PreconfigType::PRECONFIG_4K, ProfileSizeRatio::RATIO_4_3);
        EXPECT_EQ(res, 0);
        res = videoSession->BeginConfig();
        EXPECT_EQ(res, 0);

        sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
        ASSERT_NE(input, nullptr);
        input->Open();
        res = videoSession->AddInput(input);
        EXPECT_EQ(res, 0);

        sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
        sptr<Surface> producerPreviewSurface = Surface::CreateSurfaceAsProducer(previewProducer);
        sptr<PreviewOutput> previewOutput = nullptr;
        res = manager_->CreatePreviewOutputWithoutProfile(producerPreviewSurface, &previewOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePreviewOutput = previewOutput;
        EXPECT_TRUE(videoSession->CanAddOutput(capturePreviewOutput));
        res = videoSession->AddOutput(capturePreviewOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> photoProducer = photoSurface->GetProducer();
        sptr<PhotoOutput> photoOutput = nullptr;
        res = manager_->CreatePhotoOutputWithoutProfile(photoProducer, &photoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePhotoOutput = photoOutput;
        EXPECT_TRUE(videoSession->CanAddOutput(capturePhotoOutput));
        res = videoSession->AddOutput(capturePhotoOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> videoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> videoProducer = videoSurface->GetProducer();
        sptr<Surface> producerVideoSurface = Surface::CreateSurfaceAsProducer(videoProducer);
        sptr<VideoOutput> videoOutput = nullptr;
        res = manager_->CreateVideoOutputWithoutProfile(producerVideoSurface, &videoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> captureVideoOutput = videoOutput;
        res = videoSession->AddOutput(captureVideoOutput);
        EXPECT_EQ(res, 0);

        res = videoSession->CommitConfig();
        EXPECT_EQ(res, 0);
        res = videoSession->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = videoOutput->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = videoOutput->Stop();
        EXPECT_EQ(res, 0);
        res = videoSession->Stop();
        EXPECT_EQ(res, 0);
    }
    EXPECT_EQ(videoSession->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test video session preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can preconfig video session with PRECONFIG_4K, RATIO_16_9 while supported
 */
HWTEST_F(CameraSessionModuleTest, video_session_moduletest_015, TestSize.Level0)
{
    if (!IsSceneModeSupported(SceneMode::VIDEO)) {
        GTEST_SKIP();
    }

    auto captureSession = manager_->CreateCaptureSession(SceneMode::VIDEO);
    auto videoSession = static_cast<VideoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(videoSession, nullptr);
    if (videoSession->CanPreconfig(PreconfigType::PRECONFIG_4K, ProfileSizeRatio::RATIO_16_9)) {
        int32_t res = videoSession->Preconfig(PreconfigType::PRECONFIG_4K, ProfileSizeRatio::RATIO_16_9);
        EXPECT_EQ(res, 0);
        res = videoSession->BeginConfig();
        EXPECT_EQ(res, 0);

        sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
        ASSERT_NE(input, nullptr);
        input->Open();
        res = videoSession->AddInput(input);
        EXPECT_EQ(res, 0);

        sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
        sptr<Surface> producerPreviewSurface = Surface::CreateSurfaceAsProducer(previewProducer);
        sptr<PreviewOutput> previewOutput = nullptr;
        res = manager_->CreatePreviewOutputWithoutProfile(producerPreviewSurface, &previewOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePreviewOutput = previewOutput;
        EXPECT_TRUE(videoSession->CanAddOutput(capturePreviewOutput));
        res = videoSession->AddOutput(capturePreviewOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> photoProducer = photoSurface->GetProducer();
        sptr<PhotoOutput> photoOutput = nullptr;
        res = manager_->CreatePhotoOutputWithoutProfile(photoProducer, &photoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePhotoOutput = photoOutput;
        EXPECT_TRUE(videoSession->CanAddOutput(capturePhotoOutput));
        res = videoSession->AddOutput(capturePhotoOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> videoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> videoProducer = videoSurface->GetProducer();
        sptr<Surface> producerVideoSurface = Surface::CreateSurfaceAsProducer(videoProducer);
        sptr<VideoOutput> videoOutput = nullptr;
        res = manager_->CreateVideoOutputWithoutProfile(producerVideoSurface, &videoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> captureVideoOutput = videoOutput;
        res = videoSession->AddOutput(captureVideoOutput);
        EXPECT_EQ(res, 0);

        res = videoSession->CommitConfig();
        EXPECT_EQ(res, 0);
        res = videoSession->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = videoOutput->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = videoOutput->Stop();
        EXPECT_EQ(res, 0);
        res = videoSession->Stop();
        EXPECT_EQ(res, 0);
    }
    EXPECT_EQ(videoSession->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test video session preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can preconfig video session with PRECONFIG_HIGH_QUALITY, UNSPECIFIED while supported
 */
HWTEST_F(CameraSessionModuleTest, video_session_moduletest_016, TestSize.Level0)
{
    if (!IsSceneModeSupported(SceneMode::VIDEO)) {
        GTEST_SKIP();
    }

    auto captureSession = manager_->CreateCaptureSession(SceneMode::VIDEO);
    auto videoSession = static_cast<VideoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(videoSession, nullptr);
    if (videoSession->CanPreconfig(PreconfigType::PRECONFIG_HIGH_QUALITY, ProfileSizeRatio::UNSPECIFIED)) {
        int32_t res = videoSession->Preconfig(PreconfigType::PRECONFIG_HIGH_QUALITY, ProfileSizeRatio::UNSPECIFIED);
        EXPECT_EQ(res, 0);
        res = videoSession->BeginConfig();
        EXPECT_EQ(res, 0);

        sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
        ASSERT_NE(input, nullptr);
        input->Open();
        res = videoSession->AddInput(input);
        EXPECT_EQ(res, 0);

        sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
        sptr<Surface> producerPreviewSurface = Surface::CreateSurfaceAsProducer(previewProducer);
        sptr<PreviewOutput> previewOutput = nullptr;
        res = manager_->CreatePreviewOutputWithoutProfile(producerPreviewSurface, &previewOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePreviewOutput = previewOutput;
        EXPECT_TRUE(videoSession->CanAddOutput(capturePreviewOutput));
        res = videoSession->AddOutput(capturePreviewOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> photoProducer = photoSurface->GetProducer();
        sptr<PhotoOutput> photoOutput = nullptr;
        res = manager_->CreatePhotoOutputWithoutProfile(photoProducer, &photoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePhotoOutput = photoOutput;
        EXPECT_TRUE(videoSession->CanAddOutput(capturePhotoOutput));
        res = videoSession->AddOutput(capturePhotoOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> videoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> videoProducer = videoSurface->GetProducer();
        sptr<Surface> producerVideoSurface = Surface::CreateSurfaceAsProducer(videoProducer);
        sptr<VideoOutput> videoOutput = nullptr;
        res = manager_->CreateVideoOutputWithoutProfile(producerVideoSurface, &videoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> captureVideoOutput = videoOutput;
        res = videoSession->AddOutput(captureVideoOutput);
        EXPECT_EQ(res, 0);

        res = videoSession->CommitConfig();
        EXPECT_EQ(res, 0);
        res = videoSession->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = videoOutput->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = videoOutput->Stop();
        EXPECT_EQ(res, 0);
        res = videoSession->Stop();
        EXPECT_EQ(res, 0);
    }
    EXPECT_EQ(videoSession->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test video session preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can preconfig video session with PRECONFIG_HIGH_QUALITY, RATIO_1_1 while supported
 */
HWTEST_F(CameraSessionModuleTest, video_session_moduletest_017, TestSize.Level0)
{
    if (!IsSceneModeSupported(SceneMode::VIDEO)) {
        GTEST_SKIP();
    }

    auto captureSession = manager_->CreateCaptureSession(SceneMode::VIDEO);
    auto videoSession = static_cast<VideoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(videoSession, nullptr);
    if (videoSession->CanPreconfig(PreconfigType::PRECONFIG_HIGH_QUALITY, ProfileSizeRatio::RATIO_1_1)) {
        int32_t res = videoSession->Preconfig(PreconfigType::PRECONFIG_HIGH_QUALITY, ProfileSizeRatio::RATIO_1_1);
        EXPECT_EQ(res, 0);
        res = videoSession->BeginConfig();
        EXPECT_EQ(res, 0);

        sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
        ASSERT_NE(input, nullptr);
        input->Open();
        res = videoSession->AddInput(input);
        EXPECT_EQ(res, 0);

        sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
        sptr<Surface> producerPreviewSurface = Surface::CreateSurfaceAsProducer(previewProducer);
        sptr<PreviewOutput> previewOutput = nullptr;
        res = manager_->CreatePreviewOutputWithoutProfile(producerPreviewSurface, &previewOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePreviewOutput = previewOutput;
        EXPECT_TRUE(videoSession->CanAddOutput(capturePreviewOutput));
        res = videoSession->AddOutput(capturePreviewOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> photoProducer = photoSurface->GetProducer();
        sptr<PhotoOutput> photoOutput = nullptr;
        res = manager_->CreatePhotoOutputWithoutProfile(photoProducer, &photoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePhotoOutput = photoOutput;
        EXPECT_TRUE(videoSession->CanAddOutput(capturePhotoOutput));
        res = videoSession->AddOutput(capturePhotoOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> videoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> videoProducer = videoSurface->GetProducer();
        sptr<Surface> producerVideoSurface = Surface::CreateSurfaceAsProducer(videoProducer);
        sptr<VideoOutput> videoOutput = nullptr;
        res = manager_->CreateVideoOutputWithoutProfile(producerVideoSurface, &videoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> captureVideoOutput = videoOutput;
        res = videoSession->AddOutput(captureVideoOutput);
        EXPECT_EQ(res, 0);

        res = videoSession->CommitConfig();
        EXPECT_EQ(res, 0);
        res = videoSession->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = videoOutput->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = videoOutput->Stop();
        EXPECT_EQ(res, 0);
        res = videoSession->Stop();
        EXPECT_EQ(res, 0);
    }
    EXPECT_EQ(videoSession->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test video session preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can preconfig video session with PRECONFIG_HIGH_QUALITY, RATIO_4_3 while supported
 */
HWTEST_F(CameraSessionModuleTest, video_session_moduletest_018, TestSize.Level0)
{
    if (!IsSceneModeSupported(SceneMode::VIDEO)) {
        GTEST_SKIP();
    }

    auto captureSession = manager_->CreateCaptureSession(SceneMode::VIDEO);
    auto videoSession = static_cast<VideoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(videoSession, nullptr);
    if (videoSession->CanPreconfig(PreconfigType::PRECONFIG_HIGH_QUALITY, ProfileSizeRatio::RATIO_4_3)) {
        int32_t res = videoSession->Preconfig(PreconfigType::PRECONFIG_HIGH_QUALITY, ProfileSizeRatio::RATIO_4_3);
        EXPECT_EQ(res, 0);
        res = videoSession->BeginConfig();
        EXPECT_EQ(res, 0);

        sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
        ASSERT_NE(input, nullptr);
        input->Open();
        res = videoSession->AddInput(input);
        EXPECT_EQ(res, 0);

        sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
        sptr<Surface> producerPreviewSurface = Surface::CreateSurfaceAsProducer(previewProducer);
        sptr<PreviewOutput> previewOutput = nullptr;
        res = manager_->CreatePreviewOutputWithoutProfile(producerPreviewSurface, &previewOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePreviewOutput = previewOutput;
        EXPECT_TRUE(videoSession->CanAddOutput(capturePreviewOutput));
        res = videoSession->AddOutput(capturePreviewOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> photoProducer = photoSurface->GetProducer();
        sptr<PhotoOutput> photoOutput = nullptr;
        res = manager_->CreatePhotoOutputWithoutProfile(photoProducer, &photoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePhotoOutput = photoOutput;
        EXPECT_TRUE(videoSession->CanAddOutput(capturePhotoOutput));
        res = videoSession->AddOutput(capturePhotoOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> videoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> videoProducer = videoSurface->GetProducer();
        sptr<Surface> producerVideoSurface = Surface::CreateSurfaceAsProducer(videoProducer);
        sptr<VideoOutput> videoOutput = nullptr;
        res = manager_->CreateVideoOutputWithoutProfile(producerVideoSurface, &videoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> captureVideoOutput = videoOutput;
        res = videoSession->AddOutput(captureVideoOutput);
        EXPECT_EQ(res, 0);

        res = videoSession->CommitConfig();
        EXPECT_EQ(res, 0);
        res = videoSession->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = videoOutput->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = videoOutput->Stop();
        EXPECT_EQ(res, 0);
        res = videoSession->Stop();
        EXPECT_EQ(res, 0);
    }
    EXPECT_EQ(videoSession->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test video session preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can preconfig video session with PRECONFIG_HIGH_QUALITY, RATIO_16_9 while supported
 */
HWTEST_F(CameraSessionModuleTest, video_session_moduletest_019, TestSize.Level0)
{
    if (!IsSceneModeSupported(SceneMode::VIDEO)) {
        GTEST_SKIP();
    }

    auto captureSession = manager_->CreateCaptureSession(SceneMode::VIDEO);
    auto videoSession = static_cast<VideoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(videoSession, nullptr);
    if (videoSession->CanPreconfig(PreconfigType::PRECONFIG_HIGH_QUALITY, ProfileSizeRatio::RATIO_16_9)) {
        int32_t res = videoSession->Preconfig(PreconfigType::PRECONFIG_HIGH_QUALITY, ProfileSizeRatio::RATIO_16_9);
        EXPECT_EQ(res, 0);
        res = videoSession->BeginConfig();
        EXPECT_EQ(res, 0);

        sptr<CaptureInput> input = manager_->CreateCameraInput(cameras_[0]);
        ASSERT_NE(input, nullptr);
        input->Open();
        res = videoSession->AddInput(input);
        EXPECT_EQ(res, 0);

        sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
        sptr<Surface> producerPreviewSurface = Surface::CreateSurfaceAsProducer(previewProducer);
        sptr<PreviewOutput> previewOutput = nullptr;
        res = manager_->CreatePreviewOutputWithoutProfile(producerPreviewSurface, &previewOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePreviewOutput = previewOutput;
        EXPECT_TRUE(videoSession->CanAddOutput(capturePreviewOutput));
        res = videoSession->AddOutput(capturePreviewOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> photoProducer = photoSurface->GetProducer();
        sptr<PhotoOutput> photoOutput = nullptr;
        res = manager_->CreatePhotoOutputWithoutProfile(photoProducer, &photoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> capturePhotoOutput = photoOutput;
        EXPECT_TRUE(videoSession->CanAddOutput(capturePhotoOutput));
        res = videoSession->AddOutput(capturePhotoOutput);
        EXPECT_EQ(res, 0);
        sptr<IConsumerSurface> videoSurface = IConsumerSurface::Create();
        sptr<IBufferProducer> videoProducer = videoSurface->GetProducer();
        sptr<Surface> producerVideoSurface = Surface::CreateSurfaceAsProducer(videoProducer);
        sptr<VideoOutput> videoOutput = nullptr;
        res = manager_->CreateVideoOutputWithoutProfile(producerVideoSurface, &videoOutput);
        EXPECT_EQ(res, 0);
        sptr<CaptureOutput> captureVideoOutput = videoOutput;
        res = videoSession->AddOutput(captureVideoOutput);
        EXPECT_EQ(res, 0);

        res = videoSession->CommitConfig();
        EXPECT_EQ(res, 0);
        res = videoSession->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = videoOutput->Start();
        EXPECT_EQ(res, 0);
        sleep(WAIT_TIME_AFTER_START);
        res = videoOutput->Stop();
        EXPECT_EQ(res, 0);
        res = videoSession->Stop();
        EXPECT_EQ(res, 0);
    }
    EXPECT_EQ(videoSession->Release(), 0);
}

/*
 * Feature: Framework
 * Function: Test video session ability function
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test video session ability function
 */
HWTEST_F(CameraSessionModuleTest, video_session_moduletest_020, TestSize.Level1)
{
    SceneMode videoMode = SceneMode::VIDEO;
    if (!IsSceneModeSupported(videoMode)) {
        GTEST_SKIP();
    }
    sptr<CameraManager> cameraMgr = CameraManager::GetInstance();
    ASSERT_NE(cameraMgr, nullptr);

    sptr<CameraOutputCapability> capability = cameraMgr->GetSupportedOutputCapability(cameras_[0], videoMode);
    ASSERT_NE(capability, nullptr);

    sptr<CaptureSession> captureSession = cameraMgr->CreateCaptureSession(videoMode);
    ASSERT_NE(captureSession, nullptr);

    sptr<VideoSession> videoSession = static_cast<VideoSession *>(captureSession.GetRefPtr());
    ASSERT_NE(videoSession, nullptr);

    std::vector<sptr<CameraOutputCapability>> cocList = videoSession->GetCameraOutputCapabilities(cameras_[0]);
    ASSERT_TRUE(cocList.size() != 0);
    auto previewProfiles = cocList[0]->GetPreviewProfiles();
    auto photoProfiles = cocList[0]->GetPhotoProfiles();
    auto videoProfiles = cocList[0]->GetVideoProfiles();

    int32_t intResult = videoSession->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = videoSession->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    intResult = videoSession->AddOutput(photoOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    intResult = videoSession->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    intResult = videoSession->CommitConfig();
    EXPECT_EQ(intResult, 0);

    auto videoFunctionsList = videoSession->GetSessionFunctions(previewProfiles, photoProfiles, videoProfiles, true);
    ASSERT_TRUE(videoFunctionsList.size() != 0);
    auto videoFunctions = videoFunctionsList[0];
    videoFunctions->GetSupportedStabilizationMode();
    videoFunctions->IsVideoStabilizationModeSupported(VideoStabilizationMode::HIGH);
    std::vector<sptr<CameraAbility>> videoConflictFunctionsList = videoSession->GetSessionConflictFunctions();
}

/*
 * Feature: Framework
 * Function: Test video session with CreateCaptureSession
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test video session with CreateCaptureSession
 */
HWTEST_F(CameraSessionModuleTest, video_session_moduletest_021, TestSize.Level1)
{
    SceneMode mode = SceneMode::VIDEO;
    sptr<CameraManager> modeManagerObj = CameraManager::GetInstance();
    ASSERT_NE(modeManagerObj, nullptr);

    sptr<CaptureSession> captureSession = modeManagerObj->CreateCaptureSession(mode);
    ASSERT_NE(captureSession, nullptr);
}

/*
 * Feature: Framework
 * Function: Test video session macro and sketch function
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test video session macro and sketch function
 */
HWTEST_F(CameraSessionModuleTest, video_session_moduletest_022, TestSize.Level0)
{
    auto previewProfile = GetSketchPreviewProfile();
    if (previewProfile == nullptr) {
        EXPECT_EQ(previewProfile.get(), nullptr);
        GTEST_SKIP();
    }
    auto output = CreatePreviewOutput(*previewProfile);
    sptr<PreviewOutput> previewOutput = (sptr<PreviewOutput>&)output;
    ASSERT_NE(output, nullptr);

    session_->SetMode(SceneMode::VIDEO);
    int32_t intResult = session_->BeginConfig();

    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddOutput(output);
    EXPECT_EQ(intResult, 0);

    bool isSketchSupported = previewOutput->IsSketchSupported();
    if (!isSketchSupported) {
        GTEST_SKIP();
    }

    previewOutput->EnableSketch(true);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    bool isMacroSupported = session_->IsMacroSupported();
    if (!isMacroSupported) {
        GTEST_SKIP();
    }

    intResult = session_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    // Video mode don't support sketch, but MacroVideo mode supported.
    float sketchRatio = previewOutput->GetSketchRatio();
    EXPECT_LT(sketchRatio, 0);

    intResult = previewOutput->AttachSketchSurface(CreateSketchSurface(previewProfile->GetCameraFormat()));
    EXPECT_EQ(intResult, 0);

    session_->LockForControl();
    intResult = session_->EnableMacro(true);
    session_->UnlockForControl();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    // Now we are in MacroVideo mode
    sketchRatio = previewOutput->GetSketchRatio();
    EXPECT_GT(sketchRatio, 0);

    session_->LockForControl();
    intResult = session_->EnableMacro(false);
    session_->UnlockForControl();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    // Now we are in Video mode
    sketchRatio = previewOutput->GetSketchRatio();
    EXPECT_LT(sketchRatio, 0);

    sleep(WAIT_TIME_AFTER_START);

    intResult = session_->Stop();
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test video session moon capture boost function anomalous branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test video session moon capture boost function anomalous branch
 */
HWTEST_F(CameraSessionModuleTest, video_session_moduletest_023, TestSize.Level1)
{
    auto previewProfile = GetSketchPreviewProfile();
    if (previewProfile == nullptr) {
        EXPECT_EQ(previewProfile.get(), nullptr);
        GTEST_SKIP();
    }
    auto output = CreatePreviewOutput(*previewProfile);
    sptr<PreviewOutput> previewOutput = (sptr<PreviewOutput>&)output;
    ASSERT_NE(output, nullptr);

    sessionForSys_->SetMode(SceneMode::VIDEO);
    int32_t intResult = sessionForSys_->BeginConfig();

    EXPECT_EQ(intResult, 0);

    intResult = sessionForSys_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    intResult = sessionForSys_->AddOutput(output);
    EXPECT_EQ(intResult, 0);

    bool isMoonCaptureBoostSupported = sessionForSys_->IsFeatureSupported(FEATURE_MOON_CAPTURE_BOOST);
    EXPECT_FALSE(isMoonCaptureBoostSupported);

    intResult = sessionForSys_->EnableFeature(FEATURE_MOON_CAPTURE_BOOST, true);
    EXPECT_EQ(intResult, OPERATION_NOT_ALLOWED);

    intResult = sessionForSys_->EnableFeature(FEATURE_MOON_CAPTURE_BOOST, false);
    EXPECT_EQ(intResult, OPERATION_NOT_ALLOWED);

    sessionForSys_->SetMode(SceneMode::CAPTURE);
    isMoonCaptureBoostSupported = sessionForSys_->IsFeatureSupported(FEATURE_MOON_CAPTURE_BOOST);
    if (isMoonCaptureBoostSupported) {
        intResult = sessionForSys_->EnableFeature(FEATURE_MOON_CAPTURE_BOOST, true);
        EXPECT_EQ(intResult, SESSION_NOT_CONFIG);
    }

    intResult = sessionForSys_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    isMoonCaptureBoostSupported = sessionForSys_->IsFeatureSupported(FEATURE_MOON_CAPTURE_BOOST);
    if (!isMoonCaptureBoostSupported) {
        intResult = sessionForSys_->EnableFeature(FEATURE_MOON_CAPTURE_BOOST, true);
        EXPECT_EQ(intResult, OPERATION_NOT_ALLOWED);
    }
    sessionForSys_->SetFeatureDetectionStatusCallback(std::make_shared<AppCallback>());

    intResult = sessionForSys_->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    intResult = sessionForSys_->Stop();
    EXPECT_EQ(intResult, 0);
}

/*
 * Feature: Framework
 * Function: Test video session time machine dotting
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test video session time machine dotting
 */
HWTEST_F(CameraSessionModuleTest, video_session_moduletest_024, TestSize.Level1)
{
    sptr<CaptureOutput> previewOutput;
    sptr<CaptureOutput> videoOutput;
    ConfigVideoSession(previewOutput, videoOutput);
    ASSERT_NE(previewOutput, nullptr);
    ASSERT_NE(videoOutput, nullptr);

    int32_t intResult = videoSession_->AddOutput(videoOutput);
    EXPECT_EQ(intResult, 0);

    sptr<VideoOutput> videoOutputTrans = ((sptr<VideoOutput>&)videoOutput);
    std::vector<VideoMetaType> supportedVideoMetaTypes = videoOutputTrans->GetSupportedVideoMetaTypes();

    if (supportedVideoMetaTypes.size() > 0) {
        sptr<IConsumerSurface> surface = IConsumerSurface::Create();
        ASSERT_NE(surface, nullptr);
        videoOutputTrans->AttachMetaSurface(surface, supportedVideoMetaTypes[0]);

        intResult = videoSession_->CommitConfig();
        EXPECT_EQ(intResult, 0);

        intResult = videoOutputTrans->Start();
        EXPECT_EQ(intResult, 0);

        sleep(WAIT_TIME_AFTER_START);

        intResult = videoOutputTrans->Stop();
        EXPECT_EQ(intResult, 0);

        TestUtils::SaveVideoFile(nullptr, 0, VideoSaveMode::CLOSE, g_videoFd);

        sleep(WAIT_TIME_BEFORE_STOP);
    }
}

/*
 * Feature: Framework
 * Function: Test set video support HDR_VIVID with 60FPS
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test set video support HDR_VIVID with 60FPS
 */
HWTEST_F(CameraSessionModuleTest, video_session_moduletest_025, TestSize.Level0)
{
    SceneMode videoMode = SceneMode::VIDEO;
    if (!IsSceneModeSupported(videoMode)) {
        GTEST_SKIP();
    }
    sptr<CameraManager> cameraManagerObj = CameraManager::GetInstance();
    ASSERT_NE(cameraManagerObj, nullptr);

    std::vector<SceneMode> modes = cameraManagerObj->GetSupportedModes(cameras_[0]);
    ASSERT_TRUE(modes.size() != 0);
    sptr<CameraOutputCapability> modeAbility =
        cameraManagerObj->GetSupportedOutputCapability(cameras_[0], videoMode);
    ASSERT_NE(modeAbility, nullptr);

    sptr<CaptureSession> captureSession = cameraManagerObj->CreateCaptureSession(videoMode);
    ASSERT_NE(captureSession, nullptr);

    sptr<VideoSession> videoSession = static_cast<VideoSession*>(captureSession.GetRefPtr());
    ASSERT_NE(videoSession, nullptr);

    int32_t intResult = videoSession->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = videoSession->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    uint32_t width = 1920;
    uint32_t height = 1080;
    uint32_t maxFps = 60;
    CameraFormat previewFormat = CAMERA_FORMAT_YCRCB_P010;
    CameraFormat videoFormat = CAMERA_FORMAT_YCRCB_P010;

    auto previewProfileOpt = GetPreviewProfileByFormat(modeAbility, width, height, previewFormat);
    if (!previewProfileOpt) {
        std::cout << "previewProfile not support" << std::endl;
        GTEST_SKIP();
    }
    Profile previewProfile = previewProfileOpt.value();
    EXPECT_EQ(previewProfile.GetCameraFormat(), CAMERA_FORMAT_YCRCB_P010);
    std::cout << "previewProfile support" << std::endl;

    auto videoProfileOpt = GetVideoProfileByFormat(modeAbility, width, height, videoFormat, maxFps);
    if (!videoProfileOpt) {
        std::cout << "videoProfile not support" << std::endl;
        GTEST_SKIP();
    }
    VideoProfile videoProfile = videoProfileOpt.value();
    EXPECT_EQ(videoProfile.GetCameraFormat(), CAMERA_FORMAT_YCRCB_P010);
    std::cout << "videoProfile support" << std::endl;

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfile);
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfile);
    ASSERT_NE(previewOutput, nullptr);
    ASSERT_NE(videoOutput, nullptr);

    intResult = videoSession->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);
    intResult = videoSession->AddOutput(videoOutput);
    EXPECT_EQ(intResult, 0);
    intResult = videoSession->CommitConfig();
    EXPECT_EQ(intResult, 0);

    std::vector<ColorSpace> colors = videoSession->GetSupportedColorSpaces();
    bool supportHdrVivid = false;
    for (const auto& color : colors) {
        std::cout << "ColorSpace: " << color << std::endl;
        if (BT2020_HLG_LIMIT == color) {
            std::cout << "support hdr vivid!" << std::endl;
            supportHdrVivid = true;
            break;
        }
    }
    if (supportHdrVivid) {
        intResult = videoSession->SetColorSpace(BT2020_HLG_LIMIT);
        EXPECT_EQ(intResult, 0);
        ColorSpace curColorSpace = COLOR_SPACE_UNKNOWN;
        intResult = videoSession->GetActiveColorSpace(curColorSpace);
        EXPECT_EQ(intResult, 0);
        EXPECT_EQ(curColorSpace, BT2020_HLG_LIMIT);
    }
    intResult = videoSession->Release();
    EXPECT_EQ(intResult, 0);
}
} // namespace CameraStandard
} // namespace OHOS