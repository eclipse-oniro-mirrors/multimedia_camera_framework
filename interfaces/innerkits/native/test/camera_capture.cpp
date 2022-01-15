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

#include "input/camera_input.h"
#include "input/camera_manager.h"
#include "media_log.h"
#include "surface.h"
#include "test_common.h"

#include <unistd.h>

using namespace std;
using namespace OHOS;
using namespace OHOS::CameraStandard;

int main(int argc, char **argv)
{
    const int32_t previewFormatIndex = 1;
    const int32_t previewWidthIndex = 2;
    const int32_t previewHeightIndex = 3;
    const int32_t photoFormatIndex = 4;
    const int32_t photoWidthIndex = 5;
    const int32_t photoHeightIndex = 6;
    const int32_t photoCaptureCountIndex = 7;
    const int32_t validArgCount = 8;
    const int32_t gapAfterCapture = 1; // 1 second
    const int32_t previewCaptureGap = 5; // 5 seconds
    const char *testName = "camera_capture";
    int32_t ret = -1;
    int32_t previewFd = -1;
    int32_t photoFd = -1;
    int32_t previewFormat = OHOS_CAMERA_FORMAT_YCRCB_420_SP;
    int32_t previewWidth = 640;
    int32_t previewHeight = 480;
    int32_t photoFormat = OHOS_CAMERA_FORMAT_JPEG;
    int32_t photoWidth = 1280;
    int32_t photoHeight = 960;
    int32_t photoCaptureCount = 1;
    bool isResolutionConfigured = false;

    MEDIA_DEBUG_LOG("Camera new sample begin.");
    // Update sizes if enough number of valid arguments are passed
    if (argc == validArgCount) {
        // Validate arguments
        for (int counter = 1; counter < argc; counter++) {
            if (!TestUtils::IsNumber(argv[counter])) {
                cout << "Invalid argument: " << argv[counter] << endl;
                cout << "Retry by giving proper sizes" << endl;
                return 0;
            }
        }
        previewFormat = atoi(argv[previewFormatIndex]);
        previewWidth = atoi(argv[previewWidthIndex]);
        previewHeight = atoi(argv[previewHeightIndex]);
        photoFormat = atoi(argv[photoFormatIndex]);
        photoWidth = atoi(argv[photoWidthIndex]);
        photoHeight = atoi(argv[photoHeightIndex]);
        photoCaptureCount = atoi(argv[photoCaptureCountIndex]);
        isResolutionConfigured = true;
    } else if (argc != 1) {
        cout << "Pass " << (validArgCount - 1) << "arguments" << endl;
        cout << "PreviewFormat, PreviewHeight, PreviewWidth, PhotoFormat, PhotoWidth, PhotoHeight, CaptureCount"
            << endl;
        return 0;
    }

    sptr<CameraManager> camManagerObj = CameraManager::GetInstance();
    MEDIA_DEBUG_LOG("Setting callback to listen camera status and flash status");
    camManagerObj->SetCallback(std::make_shared<TestCameraMngerCallback>(testName));
    std::vector<sptr<CameraInfo>> cameraObjList = camManagerObj->GetCameras();
    if (cameraObjList.size() == 0) {
        MEDIA_DEBUG_LOG("No camera devices");
        return 0;
    }

    MEDIA_DEBUG_LOG("Camera ID count: %{public}zu", cameraObjList.size());
    for (auto& it : cameraObjList) {
        MEDIA_DEBUG_LOG("Camera ID: %{public}s", it->GetID().c_str());
    }

    sptr<CaptureSession> captureSession = camManagerObj->CreateCaptureSession();
    if (captureSession == nullptr) {
        MEDIA_DEBUG_LOG("Failed to create capture session");
        return 0;
    }

    captureSession->BeginConfig();

    sptr<CaptureInput> cameraInput = camManagerObj->CreateCameraInput(cameraObjList[0]);
    if (cameraInput == nullptr) {
        MEDIA_DEBUG_LOG("Failed to create camera input");
        return 0;
    }

    if (!isResolutionConfigured) {
        std::vector<camera_format_t> previewFormats = ((sptr<CameraInput> &)cameraInput)->GetSupportedPreviewFormats();
        if (previewFormats.empty()) {
            MEDIA_DEBUG_LOG("No preview formats supported");
        }
        MEDIA_DEBUG_LOG("Supported preview formats:");
        camera_format_t format;
        for (auto item = previewFormats.begin(); item != previewFormats.end(); ++item) {
            format = *item;
            MEDIA_DEBUG_LOG("format : %{public}d", format);
        }
        if (std::find(previewFormats.begin(), previewFormats.end(), OHOS_CAMERA_FORMAT_YCRCB_420_SP)
            != previewFormats.end()) {
            previewFormat = OHOS_CAMERA_FORMAT_YCRCB_420_SP;
            MEDIA_DEBUG_LOG("OHOS_CAMERA_FORMAT_YCRCB_420_SP format is present in supported preview formats");
        } else if(!previewFormats.empty()) {
            previewFormat = previewFormats[0];
            MEDIA_DEBUG_LOG("OHOS_CAMERA_FORMAT_YCRCB_420_SP format is not present in supported preview formats");
        }
        std::vector<camera_format_t> photoFormats = ((sptr<CameraInput> &)cameraInput)->GetSupportedPhotoFormats();
        if (photoFormats.empty()) {
            MEDIA_DEBUG_LOG("No photo formats supported");
        } else {
            photoFormat = photoFormats[0];
        }
        MEDIA_DEBUG_LOG("Supported photo formats:");
        for (auto item = photoFormats.begin(); item != photoFormats.end(); ++item) {
            format = *item;
            MEDIA_DEBUG_LOG("format : %{public}d", format);
        }
        std::vector<CameraPicSize> previewSizes
            = ((sptr<CameraInput> &)cameraInput)->getSupportedSizes(static_cast<camera_format_t>(previewFormat));
        if (previewSizes.empty()) {
            MEDIA_DEBUG_LOG("No preview sizes supported");
        }
        MEDIA_DEBUG_LOG("Supported sizes for preview:");
        CameraPicSize size;
        for (auto item = previewSizes.begin(); item != previewSizes.end(); ++item) {
            size = *item;
            MEDIA_DEBUG_LOG("width: %{public}d, height: %{public}d", size.width, size.height);
        }
        std::vector<CameraPicSize> photoSizes
            = ((sptr<CameraInput> &)cameraInput)->getSupportedSizes(static_cast<camera_format_t>(photoFormat));
        if (photoSizes.empty()) {
            MEDIA_DEBUG_LOG("No photo sizes supported");
        }
        MEDIA_DEBUG_LOG("Supported sizes for photo:");
        for (auto item = photoSizes.begin(); item != photoSizes.end(); ++item) {
            size = *item;
            MEDIA_DEBUG_LOG("width: %{public}d, height: %{public}d", size.width, size.height);
        }
        if (!previewSizes.empty()) {
            previewWidth = previewSizes[0].width;
            previewHeight = previewSizes[0].height;
        }
        if (!photoSizes.empty()) {
            photoWidth = photoSizes[0].width;
            photoHeight = photoSizes[0].height;
        }
    }

    MEDIA_DEBUG_LOG("previewFormat: %{public}d, previewWidth: %{public}d, previewHeight: %{public}d",
                    previewFormat, previewWidth, previewHeight);
    MEDIA_DEBUG_LOG("photoFormat: %{public}d, photoWidth: %{public}d, photoHeight: %{public}d",
                    photoFormat, photoWidth, photoHeight);
    MEDIA_DEBUG_LOG("photoCaptureCount: %{public}d", photoCaptureCount);

    ((sptr<CameraInput> &)cameraInput)->SetErrorCallback(std::make_shared<TestDeviceCallback>(testName));
    ret = captureSession->AddInput(cameraInput);
    if (ret != 0) {
        MEDIA_DEBUG_LOG("Add input to session is failed, ret: %{public}d", ret);
        return 0;
    }

    sptr<Surface> photoSurface = Surface::CreateSurfaceAsConsumer();
    photoSurface->SetDefaultWidthAndHeight(photoWidth, photoHeight);
    photoSurface->SetUserData(CameraManager::surfaceFormat, std::to_string(photoFormat));
    sptr<SurfaceListener> captureListener = new SurfaceListener("Photo", SurfaceType::PHOTO, photoFd, photoSurface);
    photoSurface->RegisterConsumerListener((sptr<IBufferConsumerListener> &)captureListener);
    sptr<CaptureOutput> photoOutput = camManagerObj->CreatePhotoOutput(photoSurface);
    if (photoOutput == nullptr) {
        MEDIA_DEBUG_LOG("Failed to create PhotoOutput");
        return 0;
    }

    MEDIA_DEBUG_LOG("Setting photo callback");
    ((sptr<PhotoOutput> &)photoOutput)->SetCallback(std::make_shared<TestPhotoOutputCallback>(testName));
    ret = captureSession->AddOutput(photoOutput);
    if (ret != 0) {
        MEDIA_DEBUG_LOG("Failed to Add output to session, ret: %{public}d", ret);
        return 0;
    }

    sptr<Surface> previewSurface = Surface::CreateSurfaceAsConsumer();
    previewSurface->SetDefaultWidthAndHeight(previewWidth, previewHeight);
    previewSurface->SetUserData(CameraManager::surfaceFormat, std::to_string(previewFormat));
    sptr<SurfaceListener> listener = new SurfaceListener("Preview", SurfaceType::PREVIEW, previewFd, previewSurface);
    previewSurface->RegisterConsumerListener((sptr<IBufferConsumerListener> &)listener);
    sptr<CaptureOutput> previewOutput = camManagerObj->CreateCustomPreviewOutput(previewSurface, previewWidth,
                                                                                 previewHeight);
    if (previewOutput == nullptr) {
        MEDIA_DEBUG_LOG("Failed to create previewOutput");
        return 0;
    }

    MEDIA_DEBUG_LOG("Setting preview callback");
    ((sptr<PreviewOutput> &)previewOutput)->SetCallback(std::make_shared<TestPreviewOutputCallback>(testName));
    ret = captureSession->AddOutput(previewOutput);
    if (ret != 0) {
        MEDIA_DEBUG_LOG("Failed to Add output to session, ret: %{public}d", ret);
        return 0;
    }

    ret = captureSession->CommitConfig();
    if (ret != 0) {
        MEDIA_DEBUG_LOG("Failed to commit session config, ret: %{public}d", ret);
        return 0;
    }

    ret = captureSession->Start();
    if (ret != 0) {
        MEDIA_DEBUG_LOG("Failed to start session, ret: %{public}d", ret);
        return 0;
    }

    MEDIA_DEBUG_LOG("Preview started");
    sleep(previewCaptureGap);
    for (int i = 1; i <= photoCaptureCount; i++) {
        MEDIA_DEBUG_LOG("Photo capture %{public}d started", i);
        ret = ((sptr<PhotoOutput> &)photoOutput)->Capture();
        if (ret != 0) {
            MEDIA_DEBUG_LOG("Failed to capture, ret: %{public}d", ret);
            return 0;
        }
        sleep(gapAfterCapture);
    }

    MEDIA_DEBUG_LOG("Closing the session");
    captureSession->Stop();
    captureSession->Release();
    camManagerObj->SetCallback(nullptr);

    MEDIA_DEBUG_LOG("Camera new sample end.");
    return 0;
}
