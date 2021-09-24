/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "camera_framework_test.h"

#include <cinttypes>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <securec.h>

#include "input/camera_input.h"
#include "input/camera_manager.h"
#include "media_log.h"
#include "surface.h"

using namespace OHOS;
using namespace OHOS::CameraStandard;
using namespace testing::ext;

enum class mode_ {
    MODE_PREVIEW = 0,
    MODE_PHOTO
};

enum class SaveVideoMode {
    CREATE = 0,
    APPEND,
    CLOSE
};

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

namespace {
    std::bitset<static_cast<int>(CAM_PHOTO_EVENTS::CAM_PHOTO_MAX_EVENT)> g_photoEvents;
    std::bitset<static_cast<unsigned int>(CAM_PREVIEW_EVENTS::CAM_PREVIEW_MAX_EVENT)> g_previewEvents;
    std::bitset<static_cast<unsigned int>(CAM_VIDEO_EVENTS::CAM_VIDEO_MAX_EVENT)> g_videoEvents;
    std::unordered_map<std::string, bool> g_camStatusMap;
    std::unordered_map<std::string, bool> g_camFlashMap;
    bool g_camInputOnError = false;
    int32_t g_videoFd = -1;
    const int WAIT_TIME_AFTER_CAPTURE = 1;
    const int WAIT_TIME_AFTER_START = 5;
    const int WAIT_TIME_BEFORE_STOP = 2;
    const std::int32_t PHOTO_DEFAULT_WIDTH = 1280;
    const std::int32_t PHOTO_DEFAULT_HEIGHT = 960;
    const std::int32_t PREVIEW_DEFAULT_WIDTH = 640;
    const std::int32_t PREVIEW_DEFAULT_HEIGHT = 480;
    const std::int32_t VIDEO_DEFAULT_WIDTH = 1280;
    const std::int32_t VIDEO_DEFAULT_HEIGHT = 720;
    const std::int32_t FILE_PERMISSION_FLAG = 00766;
}

void CameraFrameworkTest::SetUpTestCase(void) {}
void CameraFrameworkTest::TearDownTestCase(void) {}

void CameraFrameworkTest::SetUp()
{
    g_photoEvents.reset();
    g_previewEvents.reset();
    g_videoEvents.reset();
    g_camStatusMap.clear();
    g_camFlashMap.clear();
    g_camInputOnError = false;
    g_videoFd = -1;
}
void CameraFrameworkTest::TearDown() {}

static uint64_t GetCurrentLocalTimeStamp()
{
    std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds> tp =
        std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
    auto tmp = std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch());
    return tmp.count();
}

static int32_t SaveYUV(mode_ mode, const char *buffer, int32_t size)
{
    char path[PATH_MAX] = {0};
    int32_t retlen = 0;
    if (mode == mode_::MODE_PREVIEW) {
        system("mkdir -p /mnt/preview");
        retlen = sprintf_s(path, sizeof(path) / sizeof(path[0]), "/mnt/preview/%s_%lld.yuv",
            "preview", GetCurrentLocalTimeStamp());
    } else {
        system("mkdir -p /mnt/capture");
        retlen = sprintf_s(path, sizeof(path) / sizeof(path[0]), "/mnt/capture/%s_%lld.jpg",
            "photo", GetCurrentLocalTimeStamp());
    }
    if (retlen < 0) {
        MEDIA_ERR_LOG("Path Assignment failed");
        return -1;
    }

    MEDIA_DEBUG_LOG("%s, saving file to %{public}s", __FUNCTION__, path);
    int imgFd = open(path, O_RDWR | O_CREAT, FILE_PERMISSION_FLAG);
    if (imgFd == -1) {
        MEDIA_DEBUG_LOG("%s, open file failed, errno = %{public}s.", __FUNCTION__, strerror(errno));
        return -1;
    }
    int ret = write(imgFd, buffer, size);
    if (ret == -1) {
        MEDIA_DEBUG_LOG("%s, write file failed, error = %{public}s", __FUNCTION__, strerror(errno));
        close(imgFd);
        return -1;
    }
    close(imgFd);
    return 0;
}

static int32_t SaveVideoFile(const char *buffer, int32_t size, SaveVideoMode operationMode)
{
    if (operationMode == SaveVideoMode::CREATE) {
        char path[255] = {0};
        system("mkdir -p /mnt/video");
        int32_t retlen = sprintf_s(path, sizeof(path) / sizeof(path[0]), "/mnt/video/%s_%lld.h264",
            "video", GetCurrentLocalTimeStamp());
        if (retlen < 0) {
            MEDIA_ERR_LOG("Path Assignment failed");
            return -1;
        }
        MEDIA_DEBUG_LOG("%s, save video to file %s", __FUNCTION__, path);
        g_videoFd = open(path, O_RDWR | O_CREAT, FILE_PERMISSION_FLAG);
        if (g_videoFd == -1) {
            std::cout << "open file failed, errno = " << strerror(errno) << std::endl;
            return -1;
        }
    } else if (operationMode == SaveVideoMode::APPEND && g_videoFd != -1) {
        int32_t ret = write(g_videoFd, buffer, size);
        if (ret == -1) {
            std::cout << "write file failed, error = " << strerror(errno) << std::endl;
            close(g_videoFd);
            return -1;
        }
    } else {
        if (g_videoFd != -1) {
            close(g_videoFd);
            g_videoFd = -1;
        }
    }
    return 0;
}

class AppCallback : public CameraManagerCallback, public ErrorCallback, public PhotoCallback, public PreviewCallback {
public:
    void OnCameraStatusChanged(const std::string &cameraID, const CameraDeviceStatus cameraStatus) const override
    {
        switch (cameraStatus) {
            case CAMERA_DEVICE_STATUS_UNAVAILABLE: {
                MEDIA_DEBUG_LOG("AppCallback::OnCameraStatusChanged %{public}s: CAMERA_DEVICE_STATUS_UNAVAILABLE",
                                cameraID.c_str());
                g_camStatusMap.erase(cameraID);
                break;
            }
            case CAMERA_DEVICE_STATUS_AVAILABLE: {
                MEDIA_DEBUG_LOG("AppCallback::OnCameraStatusChanged %{public}s: CAMERA_DEVICE_STATUS_AVAILABLE",
                                cameraID.c_str());
                g_camStatusMap[cameraID] = true;
                break;
            }
            default: {
                MEDIA_DEBUG_LOG("AppCallback::OnCameraStatusChanged %{public}s: unknown", cameraID.c_str());
                EXPECT_TRUE(false);
            }
        }
        return;
    }

    void OnFlashlightStatusChanged(const std::string &cameraID, const FlashlightStatus flashStatus) const override
    {
        switch (flashStatus) {
            case FLASHLIGHT_STATUS_OFF: {
                MEDIA_DEBUG_LOG("AppCallback::OnFlashlightStatusChanged %{public}s: FLASHLIGHT_STATUS_OFF",
                                cameraID.c_str());
                g_camFlashMap[cameraID] = false;
                break;
            }
            case FLASHLIGHT_STATUS_ON: {
                MEDIA_DEBUG_LOG("AppCallback::OnFlashlightStatusChanged %{public}s: FLASHLIGHT_STATUS_ON",
                                cameraID.c_str());
                g_camFlashMap[cameraID] = true;
                break;
            }
            case FLASHLIGHT_STATUS_UNAVAILABLE: {
                MEDIA_DEBUG_LOG("AppCallback::OnFlashlightStatusChanged %{public}s: FLASHLIGHT_STATUS_UNAVAILABLE",
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
        return;
    }

    void OnCaptureStarted(const int32_t captureID) const override
    {
        MEDIA_DEBUG_LOG("AppCallback::OnCaptureStarted captureID: %{public}d", captureID);
        g_photoEvents[static_cast<int>(CAM_PHOTO_EVENTS::CAM_PHOTO_CAPTURE_START)] = 1;
        return;
    }

    void OnCaptureEnded(const int32_t captureID) const override
    {
        MEDIA_DEBUG_LOG("AppCallback::OnCaptureEnded captureID: %{public}d", captureID);
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

class AppVideoCallback : public VideoCallback {
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

class SurfaceListener : public IBufferConsumerListener {
public:
    mode_ mode;
    sptr<Surface> surface_;

    void OnBufferAvailable() override
    {
        int32_t flushFence = 0;
        int64_t timestamp = 0;
        OHOS::Rect damage;
        MEDIA_DEBUG_LOG("SurfaceListener OnBufferAvailable");
        OHOS::sptr<OHOS::SurfaceBuffer> buffer = nullptr;
        surface_->AcquireBuffer(buffer, flushFence, timestamp, damage);
        if (buffer != nullptr) {
            char *addr = static_cast<char *>(buffer->GetVirAddr());
            int32_t size = buffer->GetSize();
            MEDIA_DEBUG_LOG("Calling SaveYUV");
            SaveYUV(mode, addr, size);
            surface_->ReleaseBuffer(buffer, -1);
        } else {
            MEDIA_DEBUG_LOG("AcquireBuffer failed!");
        }
    }
};

class VideoSurfaceListener : public IBufferConsumerListener {
public:
    sptr<Surface> surface_;

    void OnBufferAvailable() override
    {
        if (g_videoFd == -1) {
            // Create video file
            SaveVideoFile(nullptr, 0, SaveVideoMode::CREATE);
        }
        int32_t flushFence = 0;
        int64_t timestamp = 0;
        OHOS::Rect damage;
        MEDIA_DEBUG_LOG("VideoSurfaceListener OnBufferAvailable");
        OHOS::sptr<OHOS::SurfaceBuffer> buffer = nullptr;
        surface_->AcquireBuffer(buffer, flushFence, timestamp, damage);
        if (buffer != nullptr) {
            char *addr = static_cast<char *>(buffer->GetVirAddr());
            int32_t size = buffer->GetSize();
            MEDIA_DEBUG_LOG("Saving to video file");
            SaveVideoFile(addr, size, SaveVideoMode::APPEND);
            surface_->ReleaseBuffer(buffer, -1);
        } else {
            MEDIA_DEBUG_LOG("AcquireBuffer failed!");
        }
    }
};

class CaptureSurfaceListener : public IBufferConsumerListener {
public:
    mode_ mode;
    sptr<Surface> surface_;
    void OnBufferAvailable() override
    {
        int32_t flushFence = 0;
        int64_t timestamp = 0;
        OHOS::Rect damage;
        MEDIA_DEBUG_LOG("CaptureSurfaceListener OnBufferAvailable");
        OHOS::sptr<OHOS::SurfaceBuffer> buffer = nullptr;
        surface_->AcquireBuffer(buffer, flushFence, timestamp, damage);
        if (buffer != nullptr) {
            char *addr = static_cast<char *>(buffer->GetVirAddr());
            int32_t size = buffer->GetSize();
            MEDIA_DEBUG_LOG("Saving Image");
            SaveYUV(mode, addr, size);
            surface_->ReleaseBuffer(buffer, -1);
        } else {
            MEDIA_DEBUG_LOG("AcquireBuffer failed!");
        }
    }
};

static sptr<CaptureOutput> CreatePhotoOutput(sptr<CameraManager> &camManagerObj)
{
    sptr<Surface> photoSurface = Surface::CreateSurfaceAsConsumer();
    photoSurface->SetDefaultWidthAndHeight(PHOTO_DEFAULT_WIDTH, PHOTO_DEFAULT_HEIGHT);
    sptr<CaptureSurfaceListener> capturelistener = new CaptureSurfaceListener();
    capturelistener->mode = mode_::MODE_PHOTO;
    capturelistener->surface_ = photoSurface;
    photoSurface->RegisterConsumerListener((sptr<IBufferConsumerListener> &)capturelistener);
    sptr<CaptureOutput> photoOutput = camManagerObj->CreatePhotoOutput(photoSurface);
    return photoOutput;
}

static sptr<CaptureOutput> CreatePreviewOutput(sptr<CameraManager> &camManagerObj)
{
    sptr<Surface> previewSurface = Surface::CreateSurfaceAsConsumer();
    previewSurface->SetDefaultWidthAndHeight(PREVIEW_DEFAULT_WIDTH, PREVIEW_DEFAULT_HEIGHT);
    sptr<SurfaceListener> listener = new SurfaceListener();
    listener->mode = mode_::MODE_PREVIEW;
    listener->surface_ = previewSurface;
    previewSurface->RegisterConsumerListener((sptr<IBufferConsumerListener> &)listener);
    sptr<CaptureOutput> previewOutput = camManagerObj->CreatePreviewOutput(previewSurface);
    return previewOutput;
}

static sptr<CaptureOutput> CreateVideoOutput(sptr<CameraManager> &camManagerObj)
{
    sptr<Surface> videoSurface = Surface::CreateSurfaceAsConsumer();
    videoSurface->SetDefaultWidthAndHeight(VIDEO_DEFAULT_WIDTH, VIDEO_DEFAULT_HEIGHT);
    sptr<VideoSurfaceListener> videoListener = new VideoSurfaceListener();
    videoListener->surface_ = videoSurface;
    videoSurface->RegisterConsumerListener((sptr<IBufferConsumerListener> &)videoListener);
    sptr<CaptureOutput> videoOutput = camManagerObj->CreateVideoOutput(videoSurface);
    return videoOutput;
}

/*
 * Feature: Framework
 * Function: Test Capture
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Capture
 */
HWTEST_F(CameraFrameworkTest, media_camera_framework_test_001, TestSize.Level1)
{
    sptr<CameraManager> camManagerObj = CameraManager::GetInstance();
    std::vector<sptr<CameraInfo>> cameraObjList = camManagerObj->GetCameras();
    EXPECT_TRUE(cameraObjList.size() != 0);

    sptr<CaptureSession> captureSession = camManagerObj->CreateCaptureSession();
    ASSERT_NE(captureSession, nullptr);

    int32_t intResult = captureSession->BeginConfig();
    EXPECT_TRUE(intResult == 0);

    sptr<CaptureInput> cameraInput = camManagerObj->CreateCameraInput(cameraObjList[0]);
    ASSERT_NE(cameraInput, nullptr);

    intResult = captureSession->AddInput(cameraInput);
    EXPECT_TRUE(intResult == 0);

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(camManagerObj);
    ASSERT_NE(photoOutput, nullptr);

    intResult = captureSession->AddOutput(photoOutput);
    EXPECT_TRUE(intResult == 0);

    intResult = captureSession->CommitConfig();
    EXPECT_TRUE(intResult == 0);

    intResult = ((sptr<PhotoOutput> &)photoOutput)->Capture();
    EXPECT_TRUE(intResult == 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    captureSession->Release();
}

/*
 * Feature: Framework
 * Function: Test Capture + Preview
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Capture + Preview
 */
HWTEST_F(CameraFrameworkTest, media_camera_framework_test_002, TestSize.Level1)
{
    sptr<CameraManager> camManagerObj = CameraManager::GetInstance();
    std::vector<sptr<CameraInfo>> cameraObjList = camManagerObj->GetCameras();
    EXPECT_TRUE(cameraObjList.size() != 0);

    sptr<CaptureSession> captureSession = camManagerObj->CreateCaptureSession();
    ASSERT_NE(captureSession, nullptr);

    int32_t intResult = captureSession->BeginConfig();
    EXPECT_TRUE(intResult == 0);

    sptr<CaptureInput> cameraInput = camManagerObj->CreateCameraInput(cameraObjList[0]);
    ASSERT_NE(cameraInput, nullptr);

    intResult = captureSession->AddInput(cameraInput);
    EXPECT_TRUE(intResult == 0);

    sptr<CaptureOutput> photoOutput = CreatePhotoOutput(camManagerObj);
    ASSERT_NE(photoOutput, nullptr);

    intResult = captureSession->AddOutput(photoOutput);
    EXPECT_TRUE(intResult == 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(camManagerObj);
    ASSERT_NE(previewOutput, nullptr);

    intResult = captureSession->AddOutput(previewOutput);
    EXPECT_TRUE(intResult == 0);

    intResult = captureSession->CommitConfig();
    EXPECT_TRUE(intResult == 0);

    intResult = captureSession->Start();
    EXPECT_TRUE(intResult == 0);

    sleep(WAIT_TIME_AFTER_START);
    intResult = ((sptr<PhotoOutput> &)photoOutput)->Capture();
    EXPECT_TRUE(intResult == 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);

    captureSession->Stop();
    captureSession->Release();
}

/*
 * Feature: Framework
 * Function: Test Preview + Video
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Preview + Video
 */
HWTEST_F(CameraFrameworkTest, media_camera_framework_test_003, TestSize.Level1)
{
    sptr<CameraManager> camManagerObj = CameraManager::GetInstance();
    std::vector<sptr<CameraInfo>> cameraObjList = camManagerObj->GetCameras();
    EXPECT_TRUE(cameraObjList.size() != 0);

    sptr<CaptureSession> captureSession = camManagerObj->CreateCaptureSession();
    ASSERT_NE(captureSession, nullptr);

    int32_t intResult = captureSession->BeginConfig();
    EXPECT_TRUE(intResult == 0);

    sptr<CaptureInput> cameraInput = camManagerObj->CreateCameraInput(cameraObjList[0]);
    ASSERT_NE(cameraInput, nullptr);

    intResult = captureSession->AddInput(cameraInput);
    EXPECT_TRUE(intResult == 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(camManagerObj);
    ASSERT_NE(previewOutput, nullptr);

    intResult = captureSession->AddOutput(previewOutput);
    EXPECT_TRUE(intResult == 0);

    sptr<CaptureOutput> videoOutput = CreateVideoOutput(camManagerObj);
    ASSERT_NE(videoOutput, nullptr);

    intResult = captureSession->AddOutput(videoOutput);
    EXPECT_TRUE(intResult == 0);

    intResult = captureSession->CommitConfig();
    EXPECT_TRUE(intResult == 0);

    intResult = captureSession->Start();
    EXPECT_TRUE(intResult == 0);

    intResult = ((sptr<VideoOutput> &)videoOutput)->Start();
    EXPECT_TRUE(intResult == 0);

    sleep(WAIT_TIME_AFTER_START);

    intResult = ((sptr<VideoOutput> &)videoOutput)->Stop();
    EXPECT_TRUE(intResult == 0);

    captureSession->Stop();
    captureSession->Release();

    SaveVideoFile(nullptr, 0, SaveVideoMode::CLOSE);
}

void TestCallbacks(bool video)
{
    std::shared_ptr<AppCallback> callback = std::make_shared<AppCallback>();
    sptr<CameraManager> camManagerObj = CameraManager::GetInstance();

    // Register application callback
    camManagerObj->SetCallback(callback);

    std::vector<sptr<CameraInfo>> cameraObjList = camManagerObj->GetCameras();
    EXPECT_TRUE(cameraObjList.size() != 0);

    sptr<CaptureSession> captureSession = camManagerObj->CreateCaptureSession();
    ASSERT_NE(captureSession, nullptr);

    int32_t intResult = captureSession->BeginConfig();
    EXPECT_TRUE(intResult == 0);

    sptr<CaptureInput> cameraInput = camManagerObj->CreateCameraInput(cameraObjList[0]);
    ASSERT_NE(cameraInput, nullptr);

    // Register error callback
    sptr<CameraInput> camInput = (sptr<CameraInput> &)cameraInput;
    camInput->SetErrorCallback(callback);

    camInput->LockForControl();

    camera_flash_mode_enum_t flash = OHOS_CAMERA_FLASH_MODE_ALWAYS_OPEN;
    camInput->SetFlashMode(flash);

    camInput->UnlockForControl();

    EXPECT_TRUE(camInput->GetFlashMode() == flash);

    EXPECT_TRUE(g_camInputOnError == false);

    intResult = captureSession->AddInput(cameraInput);
    EXPECT_TRUE(intResult == 0);

    sptr<CaptureOutput> photoOutput = nullptr;
    sptr<CaptureOutput> videoOutput = nullptr;
    if (!video) {
        photoOutput = CreatePhotoOutput(camManagerObj);
        ASSERT_NE(photoOutput, nullptr);

        // Register photo callback
        ((sptr<PhotoOutput> &)photoOutput)->SetCallback(callback);
        intResult = captureSession->AddOutput(photoOutput);
        EXPECT_TRUE(intResult == 0);
    } else {
        videoOutput = CreateVideoOutput(camManagerObj);
        ASSERT_NE(videoOutput, nullptr);

        // Register video callback
        ((sptr<VideoOutput> &)videoOutput)->SetCallback(std::make_shared<AppVideoCallback>());
        intResult = captureSession->AddOutput(videoOutput);
        EXPECT_TRUE(intResult == 0);
    }

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(camManagerObj);
    ASSERT_NE(previewOutput, nullptr);

    // Register preview callback
    ((sptr<PreviewOutput> &)previewOutput)->SetCallback(callback);
    intResult = captureSession->AddOutput(previewOutput);
    EXPECT_TRUE(intResult == 0);

    intResult = captureSession->CommitConfig();
    EXPECT_TRUE(intResult == 0);

    // Commit again and check if error callback is hit
    intResult = captureSession->CommitConfig();
    EXPECT_TRUE(intResult != 0);

    EXPECT_TRUE(g_camFlashMap.count(cameraObjList[0]->GetID()) != 0);

    EXPECT_TRUE(g_photoEvents.none());
    EXPECT_TRUE(g_previewEvents.none());
    EXPECT_TRUE(g_videoEvents.none());

    intResult = captureSession->Start();
    EXPECT_TRUE(intResult == 0);

    if (videoOutput != nullptr) {
        intResult = ((sptr<VideoOutput> &)videoOutput)->Start();
        EXPECT_TRUE(intResult == 0);
        sleep(WAIT_TIME_AFTER_START);
    }

    if (photoOutput != nullptr) {
        intResult = ((sptr<PhotoOutput> &)photoOutput)->Capture();
        EXPECT_TRUE(intResult == 0);
    }

    if (videoOutput != nullptr) {
        intResult = ((sptr<VideoOutput> &)videoOutput)->Stop();
        EXPECT_TRUE(intResult == 0);
    }

    sleep(WAIT_TIME_BEFORE_STOP);
    captureSession->Stop();
    captureSession->Release();

    EXPECT_TRUE(g_previewEvents[static_cast<int>(CAM_PREVIEW_EVENTS::CAM_PREVIEW_FRAME_START)] == 1);

    camInput->Release();

    if (photoOutput != nullptr) {
        EXPECT_TRUE(g_photoEvents[static_cast<int>(CAM_PHOTO_EVENTS::CAM_PHOTO_CAPTURE_START)] == 1);
        EXPECT_TRUE(g_photoEvents[static_cast<int>(CAM_PHOTO_EVENTS::CAM_PHOTO_FRAME_SHUTTER)] == 1);
        EXPECT_TRUE(g_photoEvents[static_cast<int>(CAM_PHOTO_EVENTS::CAM_PHOTO_CAPTURE_END)] == 1);

        ((sptr<PhotoOutput> &)photoOutput)->Release();
    }

    if (videoOutput != nullptr) {
        SaveVideoFile(nullptr, 0, SaveVideoMode::CLOSE);

        EXPECT_TRUE(g_videoEvents[static_cast<int>(CAM_VIDEO_EVENTS::CAM_VIDEO_FRAME_START)] == 1);

        ((sptr<VideoOutput> &)videoOutput)->Release();
    }

    ((sptr<PreviewOutput> &)previewOutput)->Release();

    EXPECT_TRUE(g_camStatusMap.count(cameraObjList[0]->GetID()) == 0);
}

/*
 * Feature: Framework
 * Function: Test camerastatus, flash, camera input, photo output and preview output callbacks
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test callbacks
 */
HWTEST_F(CameraFrameworkTest, media_camera_framework_test_004, TestSize.Level1)
{
    TestCallbacks(false);
}

/*
 * Feature: Framework
 * Function: Test camera status, flash, camera input, preview output and video output callbacks
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test callbacks
 */
HWTEST_F(CameraFrameworkTest, media_camera_framework_test_005, TestSize.Level1)
{
    TestCallbacks(true);
}

/*
 * Feature: Framework
 * Function: Test Preview
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Preview
 */
HWTEST_F(CameraFrameworkTest, media_camera_framework_test_006, TestSize.Level1)
{
    sptr<CameraManager> camManagerObj = CameraManager::GetInstance();
    std::vector<sptr<CameraInfo>> cameraObjList = camManagerObj->GetCameras();
    EXPECT_TRUE(cameraObjList.size() != 0);

    sptr<CaptureSession> captureSession = camManagerObj->CreateCaptureSession();
    ASSERT_NE(captureSession, nullptr);

    int32_t intResult = captureSession->BeginConfig();
    EXPECT_TRUE(intResult == 0);

    sptr<CaptureInput> cameraInput = camManagerObj->CreateCameraInput(cameraObjList[0]);
    ASSERT_NE(cameraInput, nullptr);

    intResult = captureSession->AddInput(cameraInput);
    EXPECT_TRUE(intResult == 0);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(camManagerObj);
    ASSERT_NE(previewOutput, nullptr);

    intResult = captureSession->AddOutput(previewOutput);
    EXPECT_TRUE(intResult == 0);

    intResult = captureSession->CommitConfig();
    EXPECT_TRUE(intResult == 0);

    intResult = captureSession->Start();
    EXPECT_TRUE(intResult == 0);

    sleep(WAIT_TIME_AFTER_START);

    captureSession->Stop();
    captureSession->Release();
}

/*
 * Feature: Framework
 * Function: Test Video
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Video
 */
HWTEST_F(CameraFrameworkTest, media_camera_framework_test_007, TestSize.Level1)
{
    sptr<CameraManager> camManagerObj = CameraManager::GetInstance();
    std::vector<sptr<CameraInfo>> cameraObjList = camManagerObj->GetCameras();
    EXPECT_TRUE(cameraObjList.size() != 0);

    sptr<CaptureSession> captureSession = camManagerObj->CreateCaptureSession();
    ASSERT_NE(captureSession, nullptr);

    int32_t intResult = captureSession->BeginConfig();
    EXPECT_TRUE(intResult == 0);

    sptr<CaptureInput> cameraInput = camManagerObj->CreateCameraInput(cameraObjList[0]);
    ASSERT_NE(cameraInput, nullptr);

    intResult = captureSession->AddInput(cameraInput);
    EXPECT_TRUE(intResult == 0);

    sptr<CaptureOutput> videoOutput = CreateVideoOutput(camManagerObj);
    ASSERT_NE(videoOutput, nullptr);

    intResult = captureSession->AddOutput(videoOutput);
    EXPECT_TRUE(intResult == 0);

    // Video mode without preview is not supported
    intResult = captureSession->CommitConfig();
    EXPECT_TRUE(intResult != 0);
}
