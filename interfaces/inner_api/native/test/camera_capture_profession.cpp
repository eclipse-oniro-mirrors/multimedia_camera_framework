/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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
#include <iostream>
#include <string>
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

std::map<uint32_t, std::string> g_abilityIdStr_ = {
    {536870912, "OHOS_ABILITY_SCENE_FILTER_TYPES"},
    {536870914, "OHOS_ABILITY_SCENE_PORTRAIT_EFFECT_TYPES"},
    {536870916, "OHOS_ABILITY_SCENE_BEAUTY_TYPES"}
};
int main(int argc, char **argv)
{
    cout<<"-----------------version:20240322-----------------"<<endl;
    // ProfessionSessionStub stub;
    // stub.ExecuteMock();
    const int32_t previewWidthIndex = 1;
    const int32_t previewHeightIndex = 2;
    const int32_t photoWidthIndex = 3;
    const int32_t photoHeightIndex = 4;
    const int32_t devicePosionIndex = 5;
    const int32_t validArgCount = 6;
    const int32_t gapAfterCapture = 3; // 1 second
    const int32_t previewCaptureGap = 5; // 5 seconds
    const int32_t videoDurationGap = 10; // 5 seconds
    const char* testName = "camera_capture_profession";
    int32_t ret = -1;
    int32_t previewFd = -1;
    int32_t photoFd = -1;
    int32_t videoFd = -1;
    int32_t previewFormat = CAMERA_FORMAT_RGBA_8888;
    int32_t previewWidth = 640;
    int32_t previewHeight = 480;
    int32_t photoFormat = CAMERA_FORMAT_JPEG;
    int32_t photoWidth = 640;
    int32_t photoHeight = 480;
    int32_t videoFormat = CAMERA_FORMAT_RGBA_8888;
    int32_t videoWidth = 640;
    int32_t videoHeight = 480;
    int32_t photoCaptureCount = 1;
    int32_t devicePosion = 0;
    bool isResolutionConfigured = true;
    Size previewsize;
    Size photosize;
    Size videosize;

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
        previewWidth = atoi(argv[previewWidthIndex]);
        previewHeight = atoi(argv[previewHeightIndex]);
        photoWidth = atoi(argv[photoWidthIndex]);
        photoHeight = atoi(argv[photoHeightIndex]);
        devicePosion = atoi(argv[devicePosionIndex]);
        isResolutionConfigured = true;
    } else if (argc != 1) {
        cout << "Pass " << (validArgCount - 1) << "arguments" << endl;
        cout << "PreviewHeight, PreviewWidth, PhotoWidth, PhotoHeight"
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
        .processName = "camera_capture_profession",
        .aplStr = "system_basic",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();

    sptr<CameraManager> camManagerObj = CameraManager::GetInstance();
    MEDIA_INFO_LOG("Setting callback to listen camera status and flash status");
    camManagerObj->SetCallback(std::make_shared<TestCameraMngerCallback>(testName));
    std::vector<sptr<CameraDevice>> cameraObjList = camManagerObj->GetSupportedCameras();
    if (cameraObjList.size() == 0) {
        return 0;
    }
    sptr<CameraDevice> device = cameraObjList[0];
    MEDIA_INFO_LOG("Camera ID count: %{public}zu", cameraObjList.size());
    for (auto& it : cameraObjList) {
        MEDIA_INFO_LOG("Camera ID: %{public}s", it->GetID().c_str());
        MEDIA_INFO_LOG("Camera Posion: %{public}d", it->GetPosition());
        if (devicePosion == 0 && it->GetPosition() == CameraPosition::CAMERA_POSITION_BACK) {
            device = it;
            break;
        }
        if (devicePosion == 1 && it->GetPosition() == CameraPosition::CAMERA_POSITION_FRONT) {
            device = it;
            break;
        }
    }
    cout<<"Camera ID ="<<device->GetID()<<",camera Position = "<<device->GetPosition()<<endl;
    std::vector<SceneMode> supportedModes = camManagerObj->GetSupportedModes(device);
    std::string modes = "";
    for (auto mode : supportedModes) {
        modes += std::to_string(static_cast<uint32_t>(mode)) + " , ";
    }
    MEDIA_INFO_LOG("supportedModes : %{public}s", modes.c_str());
    sptr<CaptureSession> captureSession = camManagerObj->CreateCaptureSession(SceneMode::PROFESSIONAL_VIDEO);
    sptr<PortraitSession> professionSession = nullptr;
    professionSession = static_cast<PortraitSession *> (captureSession.GetRefPtr());
    if (professionSession == nullptr) {
        return 0;
    }
    professionSession->BeginConfig();
    sptr<CaptureInput> captureInput = camManagerObj->CreateCameraInput(device);
    if (captureInput == nullptr) {
        return 0;
    }

    sptr<CameraInput> cameraInput = (sptr<CameraInput> &)captureInput;
    cameraInput->Open();
    std::vector<Profile> photoProfiles = {};
    std::vector<Profile> previewProfiles = {};
    std::vector<VideoProfile> videoProfiles = {};
    string abilityIds = "";
    if (isResolutionConfigured) {
        std::vector<CameraFormat> previewFormats;
        std::vector<CameraFormat> photoFormats;
        std::vector<CameraFormat> videoFormats;
        std::vector<Size> previewSizes;
        std::vector<Size> photoSizes;
        std::vector<Size> videoSizes;
        sptr<CameraOutputCapability> outputcapability =
            camManagerObj->GetSupportedOutputCapability(device, SceneMode::PROFESSIONAL_VIDEO);
        previewProfiles = outputcapability->GetPreviewProfiles();
        uint32_t profileIndex = 0;
        for (auto i : previewProfiles) {
            previewFormats.push_back(i.GetCameraFormat());
            previewSizes.push_back(i.GetSize());

            abilityIds = "";
            for (auto id : i.GetAbilityId()) {
                abilityIds += g_abilityIdStr_[id] + "("+std::to_string(id) + ") , ";
            }
            MEDIA_INFO_LOG("index(%{public}d), preview profile f(%{public}d), w(%{public}d), h(%{public}d) "
                           "support ability: %{public}s", profileIndex++,
                           i.GetCameraFormat(), i.GetSize().width, i.GetSize().height, abilityIds.c_str());
        }

        photoProfiles =  outputcapability->GetPhotoProfiles();
        profileIndex = 0;
        for (auto i : photoProfiles) {
            photoFormats.push_back(i.GetCameraFormat());
            photoSizes.push_back(i.GetSize());
            abilityIds = "";
            for (auto id : i.GetAbilityId()) {
                abilityIds += g_abilityIdStr_[id] + "("+std::to_string(id) + ") , ";
            }
            MEDIA_INFO_LOG("index %{public}d, photo support format : %{public}d, width: %{public}d, height: %{public}d"
                           "support ability: %{public}s", profileIndex++,
                           i.GetCameraFormat(), i.GetSize().width, i.GetSize().height, abilityIds.c_str());
        }

        videoProfiles = outputcapability->GetVideoProfiles();
        profileIndex = 0;
        for (auto i : videoProfiles) {
            videoFormats.push_back(i.GetCameraFormat());
            videoSizes.push_back(i.GetSize());

            abilityIds = "";
            for (auto id : i.GetAbilityId()) {
                abilityIds += g_abilityIdStr_[id] + "("+std::to_string(id) + ") , ";
            }
            MEDIA_INFO_LOG("index(%{public}d), video profile f(%{public}d), w(%{public}d), h(%{public}d) "
                           "support ability: %{public}s", profileIndex++,
                           i.GetCameraFormat(), i.GetSize().width, i.GetSize().height, abilityIds.c_str());
        }
    }

    MEDIA_INFO_LOG("photoCaptureCount: %{public}d", photoCaptureCount);

    cameraInput->SetErrorCallback(std::make_shared<TestDeviceCallback>(testName));
    ret = professionSession->AddInput(captureInput);
    if (ret != 0) {
        return 0;
    }

    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    if (photoSurface == nullptr) {
        return 0;
    }
    photosize.width = photoWidth;
    photosize.height = photoHeight;
    Profile photoprofile;
    for (auto it : photoProfiles) {
        if (it.GetSize().width == photosize.width && it.GetSize().height == photosize.height
            && it.GetCameraFormat() == static_cast<CameraFormat>(photoFormat)) {
                photoprofile = it;
        }
    }
    abilityIds = "";
    for (auto id : photoprofile.GetAbilityId()) {
        abilityIds += g_abilityIdStr_[id] + "("+std::to_string(id) + ") , ";
    }
    MEDIA_INFO_LOG("photo support format : %{public}d, width: %{public}d, height: %{public}d"
                   "support ability: %{public}s",
                   photoFormat, photoWidth, photoHeight, abilityIds.c_str());
    cout<< "photoFormat: " << photoFormat << " photoWidth: "<< photoWidth
        << " photoHeight: " << photoHeight << " support ability: " << abilityIds.c_str() << endl;

    sptr<SurfaceListener> captureListener = new(std::nothrow) SurfaceListener("Photo", SurfaceType::PHOTO,
                                                                              photoFd, photoSurface);
    photoSurface->RegisterConsumerListener((sptr<IBufferConsumerListener> &)captureListener);

    sptr<CaptureOutput> metaOutput = camManagerObj->CreateMetadataOutput();
    MEDIA_INFO_LOG("Setting Meta callback");
    ((sptr<MetadataOutput> &)metaOutput)->SetCallback(std::make_shared<TestMetadataOutputObjectCallback>(testName));

    ret = professionSession->AddOutput(metaOutput);
    if (ret != 0) {
        return 0;
    }

    sptr<IConsumerSurface> videoSurface = IConsumerSurface::Create();
    if (videoSurface == nullptr) {
        return 0;
    }
    videosize.width = videoWidth;
    videosize.height = videoHeight;
    VideoProfile videoprofile;
    for (auto it : videoProfiles) {
        if (it.GetSize().width == videosize.width && it.GetSize().height == videosize.height
            && it.GetCameraFormat() == static_cast<CameraFormat>(videoFormat)) {
                videoprofile = it;
            }
    }
    abilityIds = "";
    for (auto id : videoprofile.GetAbilityId()) {
        abilityIds += g_abilityIdStr_[id] + "("+std::to_string(id) + ") , ";
    }
    MEDIA_INFO_LOG("videoFormat: %{public}d, videoWidth: %{public}d, videoHeight: %{public}d"
                   "support ability: %{public}s",
                   videoFormat, videoWidth, videoHeight, abilityIds.c_str());

    cout<< "videoFormat: " << videoFormat << " videoWidth: "<< videoWidth
        << " videoHeight: " << videoHeight << " support ability: " << abilityIds.c_str() <<endl;

    cout << "------------------------------------------------------------------------------------------------"<<endl;
    sptr<SurfaceListener> listener = new(std::nothrow) SurfaceListener("Video", SurfaceType::VIDEO,
                                                                       videoFd, videoSurface);
    videoSurface->RegisterConsumerListener((sptr<IBufferConsumerListener> &)listener);
    sptr<IBufferProducer> videoProducer = videoSurface->GetProducer();
    sptr<Surface> videoProducerSurface = Surface::CreateSurfaceAsProducer(videoProducer);
    sptr<CaptureOutput> videoOutput = camManagerObj->CreateVideoOutput(videoprofile, videoProducerSurface);
    if (videoOutput == nullptr) {
        return 0;
    }

    MEDIA_INFO_LOG("Setting video callback");
    ((sptr<VideoOutput> &)videoOutput)->SetCallback(std::make_shared<TestVideoOutputCallback>(testName));
    ret = professionSession->AddOutput(videoOutput);
    if (ret != 0) {
        return 0;
    }

    sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
    if (previewSurface == nullptr) {
        return 0;
    }
    previewsize.width = previewWidth;
    previewsize.height = previewHeight;
    Profile previewprofile;
    for (auto it : previewProfiles) {
        if (it.GetSize().width == previewsize.width && it.GetSize().height == previewsize.height
            && it.GetCameraFormat() == static_cast<CameraFormat>(previewFormat)) {
                previewprofile = it;
            }
    }
    abilityIds = "";
    for (auto id : previewprofile.GetAbilityId()) {
        abilityIds += g_abilityIdStr_[id] + "("+std::to_string(id) + ") , ";
    }
    MEDIA_INFO_LOG("previewFormat: %{public}d, previewWidth: %{public}d, previewHeight: %{public}d"
                   "support ability: %{public}s",
                   previewFormat, previewWidth, previewHeight, abilityIds.c_str());

    cout<< "previewFormat: " << previewFormat << " previewWidth: "<< previewWidth
        << " previewHeight: " << previewHeight << " support ability: " << abilityIds.c_str() <<endl;

    cout << "------------------------------------------------------------------------------------------------"<<endl;
    sptr<SurfaceListener> videoListener = new(std::nothrow) SurfaceListener("Preview", SurfaceType::PREVIEW,
                                                                       previewFd, previewSurface);
    previewSurface->RegisterConsumerListener((sptr<IBufferConsumerListener> &)videoListener);
    sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
    sptr<Surface> previewProducerSurface = Surface::CreateSurfaceAsProducer(previewProducer);
    sptr<CaptureOutput> previewOutput = camManagerObj->CreatePreviewOutput(previewprofile, previewProducerSurface);
    if (previewOutput == nullptr) {
        return 0;
    }

    MEDIA_INFO_LOG("Setting preview callback");
    ((sptr<PreviewOutput> &)previewOutput)->SetCallback(std::make_shared<TestPreviewOutputCallback>(testName));
    ret = professionSession->AddOutput(previewOutput);
    if (ret != 0) {
        return 0;
    }

    ret = professionSession->CommitConfig();
    if (ret != 0) {
        return 0;
    }

    MEDIA_INFO_LOG("Preview started");
    ret = professionSession->Start();
    if (ret != 0) {
        return 0;
    }

    sleep(previewCaptureGap);

    ret = ((sptr<VideoOutput> &)videoOutput)->Start();
    if (ret != 0) {
        MEDIA_ERR_LOG("Failed to start recording, result: %{public}d", ret);
        return ret;
    }
    sleep(videoDurationGap);
    ret = ((sptr<VideoOutput> &)videoOutput)->Stop();
    if (ret != 0) {
        MEDIA_ERR_LOG("Failed to stop recording, result: %{public}d", ret);
        return ret;
    }
    ret = TestUtils::SaveVideoFile(nullptr, 0, VideoSaveMode::CLOSE, videoFd);
    videoFd = -1;
    sleep(gapAfterCapture);

    MEDIA_INFO_LOG("Closing the session");
    ((sptr<PreviewOutput> &)previewOutput)->Stop();
    professionSession->Stop();
    professionSession->Release();
    cameraInput->Release();
    camManagerObj->SetCallback(nullptr);

    MEDIA_INFO_LOG("Camera new sample end.");
    return 0;
}
