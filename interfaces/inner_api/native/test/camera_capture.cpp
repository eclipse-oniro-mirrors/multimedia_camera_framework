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

#include <unistd.h>
#include "input/camera_input.h"
#include "input/camera_manager.h"
#include "output/camera_output_capability.h"

#include "camera_log.h"
#include "surface.h"
#include "test_common.h"

#include "ipc_skeleton.h"
#include "access_token.h"
#include "hap_token_info.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::CameraStandard;

static std::shared_ptr<PhotoCaptureSetting> ConfigPhotoCaptureSetting()
{
    std::shared_ptr<PhotoCaptureSetting> photoCaptureSettings = std::make_shared<PhotoCaptureSetting>();
    // QualityLevel
    PhotoCaptureSetting::QualityLevel quality = PhotoCaptureSetting::QualityLevel::QUALITY_LEVEL_HIGH;
    photoCaptureSettings->SetQuality(quality);
    return photoCaptureSettings;
}

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
    const char* testName = "camera_capture";
    int32_t ret = -1;
    int32_t previewFd = -1;
    int32_t photoFd = -1;
    int32_t previewFormat = CAMERA_FORMAT_YUV_420_SP;
    int32_t previewWidth = 640;
    int32_t previewHeight = 480;
    int32_t photoFormat = CAMERA_FORMAT_JPEG;
    int32_t photoWidth = 1280;
    int32_t photoHeight = 960;
    int32_t photoCaptureCount = 1;
    bool isResolutionConfigured = false;
    Size previewsize;
    Size photosize;

    MEDIA_DEBUG_LOG("Camera new(std::nothrow) sample begin.");
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
        .processName = "camera_capture",
        .aplStr = "system_basic",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();

    sptr<CameraManager> camManagerObj = CameraManager::GetInstance();
    MEDIA_DEBUG_LOG("Setting callback to listen camera status and flash status");
    camManagerObj->SetCallback(std::make_shared<TestCameraMngerCallback>(testName));
    std::vector<sptr<CameraDevice>> cameraObjList = camManagerObj->GetSupportedCameras();
    if (cameraObjList.size() == 0) {
        return 0;
    }

    MEDIA_DEBUG_LOG("Camera ID count: %{public}zu", cameraObjList.size());
    for (auto& it : cameraObjList) {
        MEDIA_DEBUG_LOG("Camera ID: %{public}s", it->GetID().c_str());
    }

    sptr<CaptureSession> captureSession = camManagerObj->CreateCaptureSession();
    if (captureSession == nullptr) {
        return 0;
    }

    captureSession->BeginConfig();
    sptr<CaptureInput> captureInput = camManagerObj->CreateCameraInput(cameraObjList[0]);
    if (captureInput == nullptr) {
        return 0;
    }

    sptr<CameraInput> cameraInput = (sptr<CameraInput> &)captureInput;
    cameraInput->Open();
    if (!isResolutionConfigured) {
        std::vector<CameraFormat> previewFormats;
        std::vector<CameraFormat> photoFormats;
        std::vector<Size> previewSizes;
        std::vector<Size> photoSizes;
        sptr<CameraOutputCapability> outputcapability =  camManagerObj->GetSupportedOutputCapability(cameraObjList[0]);
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
            previewFormat = CAMERA_FORMAT_YUV_420_SP;
            MEDIA_DEBUG_LOG("CAMERA_FORMAT_YUV_420_SP format is present in supported preview formats");
        } else if (!previewFormats.empty()) {
            previewFormat = previewFormats[0];
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
            photoFormat = photoFormats[0];
        }
        MEDIA_DEBUG_LOG("Supported sizes for preview:");
        for (auto &size : previewSizes) {
            MEDIA_DEBUG_LOG("width: %{public}d, height: %{public}d", size.width, size.height);
        }
        MEDIA_DEBUG_LOG("Supported sizes for photo:");
        for (auto &size : photoSizes) {
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

    cameraInput->SetErrorCallback(std::make_shared<TestDeviceCallback>(testName));
    ret = captureSession->AddInput(captureInput);
    if (ret != 0) {
        return 0;
    }

    sptr<Surface> photoSurface = Surface::CreateSurfaceAsConsumer();
    if (photoSurface == nullptr) {
        return 0;
    }
    photosize.width = photoWidth;
    photosize.height = photoHeight;
    Profile photoprofile = Profile(static_cast<CameraFormat>(photoFormat), photosize);
    sptr<SurfaceListener> captureListener = new(std::nothrow) SurfaceListener("Photo", SurfaceType::PHOTO,
                                                                              photoFd, photoSurface);
    photoSurface->RegisterConsumerListener((sptr<IBufferConsumerListener> &)captureListener);
    sptr<CaptureOutput> photoOutput = camManagerObj->CreatePhotoOutput(photoprofile, photoSurface);
    if (photoOutput == nullptr) {
        return 0;
    }

    MEDIA_DEBUG_LOG("Setting photo callback");
    ((sptr<PhotoOutput> &)photoOutput)->SetCallback(std::make_shared<TestPhotoOutputCallback>(testName));
    ret = captureSession->AddOutput(photoOutput);
    if (ret != 0) {
        return 0;
    }

    sptr<Surface> previewSurface = Surface::CreateSurfaceAsConsumer();
    if (previewSurface == nullptr) {
        return 0;
    }
    previewsize.width = previewWidth;
    previewsize.height = previewHeight;
    Profile previewprofile = Profile(static_cast<CameraFormat>(previewFormat), previewsize);
    sptr<SurfaceListener> listener = new(std::nothrow) SurfaceListener("Preview", SurfaceType::PREVIEW,
                                                                       previewFd, previewSurface);
    previewSurface->RegisterConsumerListener((sptr<IBufferConsumerListener> &)listener);
    sptr<CaptureOutput> previewOutput = camManagerObj->CreatePreviewOutput(previewprofile, previewSurface);
    if (previewOutput == nullptr) {
        return 0;
    }

    MEDIA_DEBUG_LOG("Setting preview callback");
    ((sptr<PreviewOutput> &)previewOutput)->SetCallback(std::make_shared<TestPreviewOutputCallback>(testName));
    ret = captureSession->AddOutput(previewOutput);
    if (ret != 0) {
        return 0;
    }

    ret = captureSession->CommitConfig();
    if (ret != 0) {
        return 0;
    }

    ret = captureSession->Start();
    if (ret != 0) {
        return 0;
    }

    MEDIA_DEBUG_LOG("Preview started");
    sleep(previewCaptureGap);
    for (int i = 1; i <= photoCaptureCount; i++) {
        MEDIA_DEBUG_LOG("Photo capture %{public}d started", i);
        ret = ((sptr<PhotoOutput> &)photoOutput)->Capture(ConfigPhotoCaptureSetting());
        if (ret != 0) {
            return 0;
        }
        sleep(gapAfterCapture);
    }

    MEDIA_DEBUG_LOG("Closing the session");
    ((sptr<PreviewOutput> &)previewOutput)->Stop();
    captureSession->Stop();
    captureSession->Release();
    cameraInput->Release();
    camManagerObj->SetCallback(nullptr);

    MEDIA_DEBUG_LOG("Camera new sample end.");
    return 0;
}
