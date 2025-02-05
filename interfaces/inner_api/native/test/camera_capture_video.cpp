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

#include "camera_capture_video.h"
#include <securec.h>
#include <unistd.h>
#include "camera_util.h"
#include "camera_log.h"
#include "test_common.h"

#include "ipc_skeleton.h"
#include "access_token.h"
#include "hap_token_info.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

using namespace OHOS;
using namespace OHOS::CameraStandard;

static void PhotoModeUsage(FILE* fp)
{
    int32_t result = 0;

    result = fprintf(fp,
        "---------------------\n"
        "Running in Photo mode\n"
        "---------------------\n"
        "Options:\n"
        "h      Print this message\n"
        "c      Capture one picture\n"
        "v      Switch to video mode\n"
        "d      Double preview mode\n"
        "q      Quit this app\n");
    CHECK_ERROR_PRINT_LOG(result < 0, "Failed to display menu, %{public}d", result);
}

static void VideoModeUsage(FILE* fp)
{
    int32_t result = 0;

    result = fprintf(fp,
        "---------------------\n"
        "Running in Video mode\n"
        "---------------------\n"
        "Options:\n"
        "h      Print this message\n"
        "r      Record video\n"
        "p      Switch to Photo mode\n"
        "d      Switch to Double preview mode\n"
        "q      Quit this app\n");
    CHECK_ERROR_PRINT_LOG(result < 0, "Failed to display menu, %{public}d", result);
}

static void DoublePreviewModeUsage(FILE* fp)
{
    int32_t result = 0;

    result = fprintf(fp,
        "---------------------\n"
        "Running in Double preview mode\n"
        "---------------------\n"
        "Options:\n"
        "h      Print this message\n"
        "p      Switch to Photo mode\n"
        "v      Switch to Video mode\n"
        "q      Quit this app\n");
    CHECK_ERROR_PRINT_LOG(result < 0, "Failed to display menu, %{public}d", result);
}

static void Usage(std::shared_ptr<CameraCaptureVideo> testObj)
{
    if (testObj->currentState_ == State::PHOTO_CAPTURE) {
        PhotoModeUsage(stdout);
    } else if (testObj->currentState_ == State::VIDEO_RECORDING) {
        VideoModeUsage(stdout);
    } else if (testObj->currentState_ == State::DOUBLE_PREVIEW) {
        DoublePreviewModeUsage(stdout);
    }
    return;
}

static char PutMenuAndGetChr(std::shared_ptr<CameraCaptureVideo> &testObj)
{
    int32_t result = 0;
    char userInput[1];

    Usage(testObj);
    result = scanf_s(" %c", &userInput, 1);
    CHECK_ERROR_RETURN_RET(result == 0, 'h');
    return userInput[0];
}

static int32_t SwitchMode(std::shared_ptr<CameraCaptureVideo> testObj, State state)
{
    int32_t result = CAMERA_OK;

    if (testObj->currentState_ != state) {
        testObj->Release();
        testObj->currentState_ = state;
        result = testObj->StartPreview();
    }
    return result;
}

static void ProcessResult(int32_t result, std::shared_ptr<CameraCaptureVideo> testObj)
{
    if (result != CAMERA_OK) {
        std::cout << "Operation Failed!, Check logs for more details!, result: " << result << std::endl;
        testObj->Release();
        exit(EXIT_SUCCESS);
    }
}

static void DisplayMenu(std::shared_ptr<CameraCaptureVideo> testObj)
{
    char c = 'h';
    int32_t result = CAMERA_OK;
    while (result == CAMERA_OK) {
        switch (c) {
            case 'h':
                c = PutMenuAndGetChr(testObj);
                break;

            case 'c':
                if (testObj->currentState_ == State::PHOTO_CAPTURE) {
                    result = testObj->TakePhoto();
                }
                if (result == CAMERA_OK) {
                    c = PutMenuAndGetChr(testObj);
                }
                break;

            case 'r':
                if (testObj->currentState_ == State::VIDEO_RECORDING) {
                    result = testObj->RecordVideo();
                }
                if (result == CAMERA_OK) {
                    c = PutMenuAndGetChr(testObj);
                }
                break;

            case 'v':
                if (testObj->currentState_ != State::VIDEO_RECORDING) {
                    result = SwitchMode(testObj, State::VIDEO_RECORDING);
                }
                if (result == CAMERA_OK) {
                    c = PutMenuAndGetChr(testObj);
                }
                break;

            case 'p':
                if (testObj->currentState_ != State::PHOTO_CAPTURE) {
                    result = SwitchMode(testObj, State::PHOTO_CAPTURE);
                }
                if (result == CAMERA_OK) {
                    c = PutMenuAndGetChr(testObj);
                }
                break;

            case 'd':
                if (testObj->currentState_ != State::DOUBLE_PREVIEW) {
                    result = SwitchMode(testObj, State::DOUBLE_PREVIEW);
                }
                if (result == CAMERA_OK) {
                    c = PutMenuAndGetChr(testObj);
                }
                break;

            case 'q':
                testObj->Release();
                exit(EXIT_SUCCESS);

            default:
                c = PutMenuAndGetChr(testObj);
                break;
        }
    }
    ProcessResult(result, testObj);
}

CameraCaptureVideo::CameraCaptureVideo()
{
    previewWidth_ = PREVIEW_WIDTH;
    previewHeight_ = PREVIEW_HEIGHT;
    previewWidth2_ = SECOND_PREVIEW_WIDTH;
    previewHeight2_ = SECOND_PREVIEW_HEIGHT;
    photoWidth_ = PHOTO_WIDTH;
    photoHeight_ = PHOTO_HEIGHT;
    videoWidth_ = VIDEO_WIDTH;
    videoHeight_ = VIDEO_HEIGHT;
    previewFormat_ = CAMERA_FORMAT_YUV_420_SP;
    photoFormat_ = CAMERA_FORMAT_JPEG;
    videoFormat_ = CAMERA_FORMAT_YUV_420_SP;
    currentState_ = State::PHOTO_CAPTURE;
    fd_ = -1;
}

int32_t CameraCaptureVideo::TakePhoto()
{
    int32_t result = -1;

    CHECK_ERROR_RETURN_RET_LOG(photoOutput_ == nullptr, result, "photoOutput_ is null");

    result = ((sptr<PhotoOutput> &)photoOutput_)->Capture();
    CHECK_ERROR_RETURN_RET_LOG(result != CAMERA_OK, result, "Failed to capture, result: %{public}d", result);
    sleep(GAP_AFTER_CAPTURE);
    return result;
}

int32_t CameraCaptureVideo::RecordVideo()
{
    int32_t result = -1;

    CHECK_ERROR_RETURN_RET_LOG(videoOutput_ == nullptr, result, "videoOutput_ is null");

    result = ((sptr<VideoOutput> &)videoOutput_)->Start();
    CHECK_ERROR_RETURN_RET_LOG(result != CAMERA_OK, result, "Failed to start recording, result: %{public}d", result);
    sleep(VIDEO_CAPTURE_DURATION);
    result = ((sptr<VideoOutput> &)videoOutput_)->Stop();
    CHECK_ERROR_RETURN_RET_LOG(result != CAMERA_OK, result, "Failed to stop recording, result: %{public}d", result);
    sleep(GAP_AFTER_CAPTURE);
    result = TestUtils::SaveVideoFile(nullptr, 0, VideoSaveMode::CLOSE, fd_);
    fd_ = -1;
    return result;
}

void CameraCaptureVideo::Release()
{
    if (captureSession_ != nullptr) {
        captureSession_->Stop();
        sleep(GAP_AFTER_STOP);
        captureSession_->Release();
        captureSession_ = nullptr;
    }
    if (cameraInput_ != nullptr) {
        cameraInput_->Release();
        cameraInput_ = nullptr;
    }
    cameraInputCallback_ = nullptr;
    previewSurface_ = nullptr;
    previewSurfaceListener_ = nullptr;
    previewOutput_ = nullptr;
    previewOutputCallback_ = nullptr;
    photoSurface_ = nullptr;
    photoSurfaceListener_ = nullptr;
    sptr<CaptureOutput> photoOutput_ = nullptr;
    photoOutputCallback_ = nullptr;
    videoSurface_ = nullptr;
    videoSurfaceListener_ = nullptr;
    videoOutput_ = nullptr;
    videoOutputCallback_ = nullptr;
    secondPreviewSurface_ = nullptr;
    secondPreviewSurfaceListener_ = nullptr;
    secondPreviewOutput_ = nullptr;
    secondPreviewOutputCallback_ = nullptr;
}

int32_t CameraCaptureVideo::InitCameraManager()
{
    int32_t result = -1;

    if (cameraManager_ == nullptr) {
        cameraManager_ = CameraManager::GetInstance();
        CHECK_ERROR_RETURN_RET_LOG(cameraManager_ == nullptr, result, "Failed to get camera manager!");
        cameraMngrCallback_ = std::make_shared<TestCameraMngerCallback>(testName_);
        cameraManager_->RegisterCameraStatusCallback(cameraMngrCallback_);
    }
    result = CAMERA_OK;
    return result;
}

int32_t CameraCaptureVideo::InitCameraFormatAndResolution(sptr<CameraInput> &cameraInput)
{
    std::vector<CameraFormat> previewFormats;
    std::vector<CameraFormat> photoFormats;
    std::vector<CameraFormat> videoFormats;
    std::vector<Size> previewSizes;
    std::vector<Size> photoSizes;
    std::vector<Size> videoSizes;
    std::vector<sptr<CameraDevice>> cameraObjList = cameraManager_->GetSupportedCameras();
    CHECK_ERROR_PRINT_LOG(cameraObjList.size() <= 0, "No cameras are available!!!");
    sptr<CameraOutputCapability> outputcapability =  cameraManager_->GetSupportedOutputCapability(cameraObjList[0]);
    std::vector<Profile> previewProfiles = outputcapability->GetPreviewProfiles();
    for (auto i : previewProfiles) {
        previewFormats.push_back(i.GetCameraFormat());
        previewSizes.push_back(i.GetSize());
    }
    MEDIA_DEBUG_LOG("Supported preview formats:");
    for (auto &formatPreview : previewFormats) {
        MEDIA_DEBUG_LOG("format : %{public}d", formatPreview);
    }
    if (std::find(previewFormats.begin(), previewFormats.end(), CAMERA_FORMAT_YUV_420_SP)
        != previewFormats.end()) {
        previewFormat_ = CAMERA_FORMAT_YUV_420_SP;
        MEDIA_DEBUG_LOG("CAMERA_FORMAT_YUV_420_SP format is present in supported preview formats");
    } else if (!previewFormats.empty()) {
        previewFormat_ = previewFormats[0];
        MEDIA_DEBUG_LOG("CAMERA_FORMAT_YUV_420_SP format is not present in supported preview formats");
    }
    std::vector<Profile> photoProfiles =  outputcapability->GetPhotoProfiles();
    for (auto i : photoProfiles) {
            photoFormats.push_back(i.GetCameraFormat());
            photoSizes.push_back(i.GetSize());
    }
    MEDIA_DEBUG_LOG("Supported photo formats:");
    for (auto &formatPhoto : photoFormats) {
        MEDIA_DEBUG_LOG("format : %{public}d", formatPhoto);
    }
    if (!photoFormats.empty()) {
        photoFormat_ = photoFormats[0];
    }
    std::vector<VideoProfile> videoProfiles = outputcapability->GetVideoProfiles();
    for (auto i : videoProfiles) {
        videoFormats.push_back(i.GetCameraFormat());
        videoSizes.push_back(i.GetSize());
        videoframerates_ = i.GetFrameRates();
    }
    MEDIA_DEBUG_LOG("Supported video formats:");
    for (auto &formatVideo : videoFormats) {
        MEDIA_DEBUG_LOG("format : %{public}d", formatVideo);
    }
    if (std::find(videoFormats.begin(), videoFormats.end(), CAMERA_FORMAT_YUV_420_SP) != videoFormats.end()) {
        videoFormat_ = CAMERA_FORMAT_YUV_420_SP;
        MEDIA_DEBUG_LOG("CAMERA_FORMAT_YUV_420_SP format is present in supported video formats");
    } else if (!videoFormats.empty()) {
        videoFormat_ = videoFormats[0];
        MEDIA_DEBUG_LOG("CAMERA_FORMAT_YUV_420_SP format is not present in supported video formats");
    }
    MEDIA_DEBUG_LOG("Supported sizes for preview:");
    for (auto &sizePreview : previewSizes) {
        MEDIA_DEBUG_LOG("width: %{public}d, height: %{public}d", sizePreview.width, sizePreview.height);
    }
    MEDIA_DEBUG_LOG("Supported sizes for photo:");
    for (auto &sizePhoto : photoSizes) {
        MEDIA_DEBUG_LOG("width: %{public}d, height: %{public}d", sizePhoto.width, sizePhoto.height);
    }
    MEDIA_DEBUG_LOG("Supported sizes for video:");
    for (auto &sizeVideo : videoSizes) {
        MEDIA_DEBUG_LOG("width: %{public}d, height: %{public}d", sizeVideo.width, sizeVideo.height);
    }

    if (!photoSizes.empty()) {
        photoWidth_ = photoSizes[0].width;
        photoHeight_ = photoSizes[0].height;
    }
    if (!videoSizes.empty()) {
        videoWidth_ = videoSizes[0].width;
        videoHeight_ = videoSizes[0].height;
    }
    if (!previewSizes.empty()) {
        previewWidth_ = previewSizes[0].width;
        previewHeight_ = previewSizes[0].height;
    }
    if (previewSizes.size() > 1) {
        previewWidth2_ = previewSizes[1].width;
        previewHeight2_ = previewSizes[1].height;
    }

    MEDIA_DEBUG_LOG("previewFormat: %{public}d, previewWidth: %{public}d, previewHeight: %{public}d",
                    previewFormat_, previewWidth_, previewHeight_);
    MEDIA_DEBUG_LOG("previewFormat: %{public}d, previewWidth2: %{public}d, previewHeight2: %{public}d",
                    previewFormat_, previewWidth2_, previewHeight2_);
    MEDIA_DEBUG_LOG("photoFormat: %{public}d, photoWidth: %{public}d, photoHeight: %{public}d",
                    photoFormat_, photoWidth_, photoHeight_);
    MEDIA_DEBUG_LOG("videoFormat: %{public}d, videoWidth: %{public}d, videoHeight: %{public}d",
                    videoFormat_, videoWidth_, videoHeight_);
    return CAMERA_OK;
}

int32_t CameraCaptureVideo::InitCameraInput()
{
    int32_t result = -1;

    CHECK_ERROR_RETURN_RET_LOG(cameraManager_ == nullptr, result, "cameraManager_ is null");

    if (cameraInput_ == nullptr) {
        std::vector<sptr<CameraDevice>> cameraObjList = cameraManager_->GetSupportedCameras();
        CHECK_ERROR_RETURN_RET_LOG(cameraObjList.size() <= 0, result, "No cameras are available!!!");
        cameraInput_ = cameraManager_->CreateCameraInput(cameraObjList[0]);
        CHECK_ERROR_RETURN_RET_LOG(cameraInput_ == nullptr, result, "Failed to create CameraInput");
        cameraInput_->Open();
        cameraInputCallback_ = std::make_shared<TestDeviceCallback>(testName_);
        ((sptr<CameraInput> &)cameraInput_)->SetErrorCallback(cameraInputCallback_);
        result = InitCameraFormatAndResolution((sptr<CameraInput> &)cameraInput_);
        CHECK_ERROR_RETURN_RET_LOG(result != CAMERA_OK, result,
            "Failed to initialize format and resolution for preview, photo and video");
    }
    result = CAMERA_OK;
    return result;
}

int32_t CameraCaptureVideo::InitPreviewOutput()
{
    int32_t result = -1;
    Size previewsize_;

    CHECK_ERROR_RETURN_RET_LOG(cameraManager_ == nullptr, result, "cameraManager_ is null");

    if (previewOutput_ == nullptr) {
        previewSurface_ = IConsumerSurface::Create();
        CHECK_ERROR_RETURN_RET_LOG(previewSurface_ ==  nullptr, result, "previewSurface_ is null");
        previewsize_.width = previewWidth_;
        previewsize_.height = previewHeight_;
        previewSurface_->SetDefaultWidthAndHeight(previewWidth_, previewHeight_);
        previewSurface_->SetUserData(CameraManager::surfaceFormat, std::to_string(previewFormat_));
        Profile previewprofile_ = Profile(static_cast<CameraFormat>(previewFormat_), previewsize_);
        previewSurfaceListener_ = new(std::nothrow) SurfaceListener(testName_, SurfaceType::PREVIEW,
                                                                    fd_, previewSurface_);
        CHECK_ERROR_RETURN_RET_LOG(previewSurfaceListener_ == nullptr, result, "fail to create new SurfaceListener");
        previewSurface_->RegisterConsumerListener((sptr<IBufferConsumerListener> &)previewSurfaceListener_);
        sptr<IBufferProducer> bp = previewSurface_->GetProducer();
        sptr<Surface> pSurface = Surface::CreateSurfaceAsProducer(bp);
        previewOutput_ = cameraManager_->CreatePreviewOutput(previewprofile_, pSurface);
        CHECK_ERROR_RETURN_RET_LOG(previewOutput_ == nullptr, result, "Failed to create previewOutput");
        previewOutputCallback_ = std::make_shared<TestPreviewOutputCallback>(testName_);
        ((sptr<PreviewOutput> &)previewOutput_)->SetCallback(previewOutputCallback_);
    }
    result = CAMERA_OK;
    return result;
}

int32_t CameraCaptureVideo::InitSecondPreviewOutput()
{
    int32_t result = -1;
    Size previewsize2_;

    CHECK_ERROR_RETURN_RET_LOG(cameraManager_ == nullptr, result, "cameraManager_ is null");

    if (secondPreviewOutput_ == nullptr) {
        secondPreviewSurface_ = IConsumerSurface::Create();
        CHECK_ERROR_RETURN_RET_LOG(secondPreviewSurface_ == nullptr, result, "secondPreviewSurface_ is null");
        previewsize2_.width = previewWidth2_;
        previewsize2_.height = previewHeight2_;
        Profile previewprofile2_ = Profile(static_cast<CameraFormat>(previewFormat_), previewsize2_);
        secondPreviewSurfaceListener_ = new(std::nothrow) SurfaceListener(testName_,
            SurfaceType::SECOND_PREVIEW, fd_, secondPreviewSurface_);
        CHECK_ERROR_RETURN_RET_LOG(secondPreviewSurfaceListener_ == nullptr, result,
            "failed to create new SurfaceListener!");
        secondPreviewSurface_->RegisterConsumerListener(
            (sptr<IBufferConsumerListener> &)secondPreviewSurfaceListener_);
        sptr<IBufferProducer> bp = secondPreviewSurface_->GetProducer();
        sptr<Surface> pSurface = Surface::CreateSurfaceAsProducer(bp);
        secondPreviewOutput_ = cameraManager_->CreatePreviewOutput(previewprofile2_, pSurface);
        CHECK_ERROR_RETURN_RET_LOG(secondPreviewSurfaceListener_ ==  nullptr, result,
            "Failed to create new SurfaceListener");
        CHECK_ERROR_RETURN_RET_LOG(secondPreviewOutput_ == nullptr, result, "Failed to create second previewOutput");
        secondPreviewOutputCallback_ = std::make_shared<TestPreviewOutputCallback>(testName_);
        ((sptr<PreviewOutput> &)secondPreviewOutput_)->SetCallback(secondPreviewOutputCallback_);
    }
    result = CAMERA_OK;
    return result;
}

int32_t CameraCaptureVideo::InitPhotoOutput()
{
    int32_t result = -1;
    Size photosize_;
    CHECK_ERROR_RETURN_RET_LOG(cameraManager_ == nullptr, result, "cameraManager_ is null");

    if (photoOutput_ == nullptr) {
        photoSurface_ = IConsumerSurface::Create();
        CHECK_ERROR_RETURN_RET_LOG(photoSurface_ == nullptr, result, "photoSurface_ is null");
        photosize_.width = photoWidth_;
        photosize_.height = photoHeight_;
        Profile photoprofile_ = Profile(static_cast<CameraFormat>(photoFormat_), photosize_);
        photoSurfaceListener_ = new(std::nothrow) SurfaceListener(testName_, SurfaceType::PHOTO, fd_, photoSurface_);
        CHECK_ERROR_RETURN_RET_LOG(photoSurfaceListener_ == nullptr, result, "Failed to create new SurfaceListener");
        photoSurface_->RegisterConsumerListener((sptr<IBufferConsumerListener> &)photoSurfaceListener_);
        sptr<IBufferProducer> bp = photoSurface_->GetProducer();
        photoOutput_ = cameraManager_->CreatePhotoOutput(photoprofile_, bp);
        CHECK_ERROR_RETURN_RET_LOG(photoOutput_ == nullptr, result, "Failed to create PhotoOutput");
        photoOutputCallback_ = std::make_shared<TestPhotoOutputCallback>(testName_);
        ((sptr<PhotoOutput> &)photoOutput_)->SetCallback(photoOutputCallback_);
    }
    result = CAMERA_OK;
    return result;
}

int32_t CameraCaptureVideo::InitVideoOutput()
{
    int32_t result = -1;
    Size videosize_;

    CHECK_ERROR_RETURN_RET_LOG(cameraManager_ == nullptr, result, "cameraManager_ is null");

    if (videoOutput_ == nullptr) {
        videoSurface_ = IConsumerSurface::Create();
        CHECK_ERROR_RETURN_RET_LOG(videoSurface_ == nullptr, result, "videoSurface_ is null");
        videosize_.width = videoWidth_;
        videosize_.height = videoHeight_;
        VideoProfile videoprofile_ =
            VideoProfile(static_cast<CameraFormat>(videoFormat_), videosize_, videoframerates_);
        videoSurfaceListener_ = new(std::nothrow) SurfaceListener(testName_, SurfaceType::VIDEO, fd_, videoSurface_);
        CHECK_ERROR_RETURN_RET_LOG(videoSurfaceListener_ == nullptr, result, "Failed to create new SurfaceListener");
        videoSurface_->RegisterConsumerListener((sptr<IBufferConsumerListener> &)videoSurfaceListener_);
        sptr<IBufferProducer> bp = videoSurface_->GetProducer();
        sptr<Surface> pSurface = Surface::CreateSurfaceAsProducer(bp);
        videoOutput_ = cameraManager_->CreateVideoOutput(videoprofile_, pSurface);
        CHECK_ERROR_RETURN_RET_LOG(videoOutput_ == nullptr, result, "Failed to create VideoOutput");
        videoOutputCallback_ = std::make_shared<TestVideoOutputCallback>(testName_);
        ((sptr<VideoOutput> &)videoOutput_)->SetCallback(videoOutputCallback_);
    }
    result = CAMERA_OK;
    return result;
}

int32_t CameraCaptureVideo::AddOutputbyState()
{
    int32_t result = -1;

    CHECK_ERROR_RETURN_RET_LOG(captureSession_ == nullptr, result, "captureSession_ is null");
    switch (currentState_) {
        case State::PHOTO_CAPTURE:
            result = InitPhotoOutput();
            if (result == CAMERA_OK) {
                result = captureSession_->AddOutput(photoOutput_);
            }
            break;
        case State::VIDEO_RECORDING:
            result = InitVideoOutput();
            if (result == CAMERA_OK) {
                result = captureSession_->AddOutput(videoOutput_);
            }
            break;
        case State::DOUBLE_PREVIEW:
            result = InitSecondPreviewOutput();
            if (result == CAMERA_OK) {
                result = captureSession_->AddOutput(secondPreviewOutput_);
            }
            break;
        default:
            break;
    }
    return result;
}

int32_t CameraCaptureVideo::StartPreview()
{
    int32_t result = -1;

    result = InitCameraManager();
    CHECK_ERROR_RETURN_RET(result != CAMERA_OK, result);
    result = InitCameraInput();
    CHECK_ERROR_RETURN_RET(result != CAMERA_OK, result);
    captureSession_ = cameraManager_->CreateCaptureSession();
    CHECK_ERROR_RETURN_RET(captureSession_ == nullptr, result);
    captureSession_->BeginConfig();
    result = captureSession_->AddInput(cameraInput_);
    CHECK_ERROR_RETURN_RET(CAMERA_OK != result, result);
    result = AddOutputbyState();
    CHECK_ERROR_RETURN_RET(result != CAMERA_OK, result);
    result = InitPreviewOutput();
    CHECK_ERROR_RETURN_RET(result != CAMERA_OK, result);
    result = captureSession_->AddOutput(previewOutput_);
    CHECK_ERROR_RETURN_RET(CAMERA_OK != result, result);
    result = captureSession_->CommitConfig();
    CHECK_ERROR_RETURN_RET_LOG(CAMERA_OK != result, result, "Failed to Commit config");
    result = captureSession_->Start();
    MEDIA_DEBUG_LOG("Session started, result: %{public}d", result);
    if (CAMERA_OK != result) {
    }
    return result;
}

int32_t main(int32_t argc, char **argv)
{
    uint64_t tokenId;
    const char *perms[0];
    perms[0] = "ohos.permission.CAMERA";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 1,
        .aclsNum = 0,
        .dcaps = NULL,
        .perms = perms,
        .acls = NULL,
        .processName = "camera_capture_video",
        .aplStr = "system_basic",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();

    [[maybe_unused]] int32_t result = 0; // Default result
    std::shared_ptr<CameraCaptureVideo> testObj =
        std::make_shared<CameraCaptureVideo>();
    result = testObj->StartPreview();
    DisplayMenu(testObj);
    return 0;
}
