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

static std::shared_ptr<PhotoCaptureSetting> ConfigPhotoCaptureSetting()
{
    std::shared_ptr<PhotoCaptureSetting> photoCaptureSettings = std::make_shared<PhotoCaptureSetting>();
    // QualityLevel
    PhotoCaptureSetting::QualityLevel quality = PhotoCaptureSetting::QualityLevel::QUALITY_LEVEL_HIGH;
    photoCaptureSettings->SetQuality(quality);
    return photoCaptureSettings;
}

std::map<PortraitEffect, camera_portrait_effect_type_t> g_fwToMetaPortraitEffect_ = {
    {OFF_EFFECT, OHOS_CAMERA_PORTRAIT_EFFECT_OFF},
    {CIRCLES, OHOS_CAMERA_PORTRAIT_CIRCLES}
};

std::map<FilterType, camera_filter_type_t> g_fwToMetaFilterType_ = {
    {NONE, OHOS_CAMERA_FILTER_TYPE_OFF},
    {CLASSIC, OHOS_CAMERA_FILTER_TYPE_CLASSIC},
    {DAWN, OHOS_CAMERA_FILTER_TYPE_DAWN},
    {PURE, OHOS_CAMERA_FILTER_TYPE_PURE},
    {GREY, OHOS_CAMERA_FILTER_TYPE_GREY},
    {NATURAL, OHOS_CAMERA_FILTER_TYPE_NATURAL},
    {MORI, OHOS_CAMERA_FILTER_TYPE_MORI},
    {FAIR, OHOS_CAMERA_FILTER_TYPE_FAIR},
    {PINK, OHOS_CAMERA_FILTER_TYPE_PINK}
};

std::map<camera_beauty_type_t, BeautyType> g_metaToFwBeautyType_ = {
    {OHOS_CAMERA_BEAUTY_TYPE_AUTO, AUTO_TYPE},
    {OHOS_CAMERA_BEAUTY_TYPE_SKIN_SMOOTH, SKIN_SMOOTH},
    {OHOS_CAMERA_BEAUTY_TYPE_FACE_SLENDER, FACE_SLENDER},
    {OHOS_CAMERA_BEAUTY_TYPE_SKIN_TONE, SKIN_TONE}
};

std::map<BeautyType, camera_beauty_type_t> g_fwToMetaBeautyType_ = {
    {AUTO_TYPE, OHOS_CAMERA_BEAUTY_TYPE_AUTO},
    {SKIN_SMOOTH, OHOS_CAMERA_BEAUTY_TYPE_SKIN_SMOOTH},
    {FACE_SLENDER, OHOS_CAMERA_BEAUTY_TYPE_FACE_SLENDER},
    {SKIN_TONE, OHOS_CAMERA_BEAUTY_TYPE_SKIN_TONE}
};

std::map<BeautyType, camera_device_metadata_tag_t> g_beautyTypeAbility_ = {
    {SKIN_SMOOTH, OHOS_ABILITY_BEAUTY_SKIN_SMOOTH_VALUES},
    {FACE_SLENDER, OHOS_ABILITY_BEAUTY_FACE_SLENDER_VALUES},
    {SKIN_TONE, OHOS_ABILITY_BEAUTY_SKIN_TONE_VALUES}
};

std::map<BeautyType, std::string> g_beautyTypeStr_ = {
    {AUTO_TYPE, "OHOS_CAMERA_BEAUTY_TYPE_AUTO"},
    {SKIN_SMOOTH, "OHOS_CAMERA_BEAUTY_TYPE_SKIN_SMOOTH"},
    {FACE_SLENDER, "OHOS_CAMERA_BEAUTY_TYPE_FACE_SLENDER"},
    {SKIN_TONE, "OHOS_CAMERA_BEAUTY_TYPE_SKIN_TONE"}
};

std::map<BeautyType, std::string> g_beautyAbilityStr_ = {
    {SKIN_SMOOTH, "OHOS_ABILITY_BEAUTY_SKIN_SMOOTH_VALUES"},
    {FACE_SLENDER, "OHOS_ABILITY_BEAUTY_FACE_SLENDER_VALUES"},
    {SKIN_TONE, "OHOS_ABILITY_BEAUTY_SKIN_TONE_VALUES"}
};

std::map<FilterType, std::string> g_filterTypeStr_ = {
    {NONE, "OHOS_CAMERA_FILTER_TYPE_OFF"},
    {CLASSIC, "OHOS_CAMERA_FILTER_TYPE_CLASSIC"},
    {DAWN, "OHOS_CAMERA_FILTER_TYPE_DAWN"},
    {PURE, "OHOS_CAMERA_FILTER_TYPE_PURE"},
    {GREY, "OHOS_CAMERA_FILTER_TYPE_GREY"},
    {NATURAL, "OHOS_CAMERA_FILTER_TYPE_NATURAL"},
    {MORI, "OHOS_CAMERA_FILTER_TYPE_MORI"},
    {FAIR, "OHOS_CAMERA_FILTER_TYPE_FAIR"},
    {PINK, "OHOS_CAMERA_FILTER_TYPE_PINK"}
};

std::map<PortraitEffect, std::string> g_portraitEffectStr_ = {
    {OFF_EFFECT, "OHOS_CAMERA_PORTRAIT_EFFECT_OFF"},
    {CIRCLES, "OHOS_CAMERA_PORTRAIT_CIRCLES"}
};

std::map<uint32_t, std::string> g_abilityIdStr_ = {
    {536870912, "OHOS_ABILITY_SCENE_FILTER_TYPES"},
    {536870914, "OHOS_ABILITY_SCENE_PORTRAIT_EFFECT_TYPES"},
    {536870916, "OHOS_ABILITY_SCENE_BEAUTY_TYPES"}
};

void PrintSupportBeautyTypes(vector<BeautyType> supportedBeautyTypes)
{
    MEDIA_INFO_LOG("Supported BeautyType size = %{public}zu", supportedBeautyTypes.size());
    cout << g_abilityIdStr_[OHOS_ABILITY_SCENE_BEAUTY_TYPES] << " : size = " << supportedBeautyTypes.size() <<endl;
    uint32_t index = 0;
    for (BeautyType type : supportedBeautyTypes) {
        for (auto itrType = g_fwToMetaBeautyType_.cbegin(); itrType != g_fwToMetaBeautyType_.cend(); itrType++) {
            if (type == itrType->first) {
                break;
            }
        }
        cout << "[" << index++ << "]" << "type = " << g_beautyTypeStr_[type] << ", ";
        MEDIA_INFO_LOG("Supported BeautyType type = %{public}s", g_beautyTypeStr_[type].c_str());
    }
    cout << endl;
    cout << "------------------------------------------------------------------------------------------------"<<endl;
    return;
}

void PrintSupportFilterTypes(vector<FilterType> supportedFilterTypes)
{
    MEDIA_INFO_LOG("Supported FilterTypes size = %{public}zu", supportedFilterTypes.size());
    cout << g_abilityIdStr_[OHOS_ABILITY_SCENE_FILTER_TYPES] <<" : size = " << supportedFilterTypes.size() << endl;
    uint32_t index = 0;
    for (FilterType type : supportedFilterTypes) {
        for (auto itrType = g_fwToMetaFilterType_.cbegin(); itrType != g_fwToMetaFilterType_.cend(); itrType++) {
            if (type == itrType->first) {
                break;
            }
        }
        cout << " [" << index++ << "]" << "type = " << g_filterTypeStr_[type] << ", ";
        MEDIA_INFO_LOG("Supported FilterType type = %{public}s", g_filterTypeStr_[type].c_str());
    }
    cout << endl;
    cout << "------------------------------------------------------------------------------------------------"<<endl;
    return;
}

void PrintSupportPortraitEffects(vector<PortraitEffect> supportedPortraitEffects)
{
    MEDIA_INFO_LOG("Supported PortraitEffects size = %{public}zu", supportedPortraitEffects.size());
    cout << g_abilityIdStr_[OHOS_ABILITY_SCENE_PORTRAIT_EFFECT_TYPES] <<" : size = "
         << supportedPortraitEffects.size() <<endl;
    uint32_t index = 0;
    for (PortraitEffect type : supportedPortraitEffects) {
        for (auto itrType = g_fwToMetaPortraitEffect_.cbegin(); itrType != g_fwToMetaPortraitEffect_.cend();
             itrType++) {
            if (type == itrType->first) {
                break;
            }
        }
        cout << "[" << index++ << "]" << "effect = " << g_portraitEffectStr_[type] << ", ";
        MEDIA_INFO_LOG("Supported PortraitEffect effect = %{public}s", g_portraitEffectStr_[type].c_str());
    }
    cout << endl;
    cout << "------------------------------------------------------------------------------------------------"<<endl;
    return;
}

void PrintSupportBeautyRange(BeautyType beauty, vector<int32_t> range)
{
    MEDIA_INFO_LOG("%{public}s size = %{public}zu", g_beautyAbilityStr_[beauty].c_str(), range.size());
    cout << " " << g_beautyAbilityStr_[beauty] <<" size = " << range.size();
    for (auto val : range) {
        cout << " val = " << val << ", ";
        MEDIA_INFO_LOG("val = %{public}d", val);
    }
    cout << endl;
    return;
}

std::vector<PortraitEffect> GetSupportedPortraitEffectsStub()
{
    cout<<"=================GetSupportedPortraitEffectsStub call================="<<endl;
    std::vector<PortraitEffect> supportedPortraitEffects = {OFF_EFFECT, CIRCLES};
    return supportedPortraitEffects;
}

std::vector<BeautyType> GetSupportedBeautyTypesStub()
{
    cout<<"=================GetSupportedBeautyTypesStub call================="<<endl;
    std::vector<BeautyType> supportedBeautyTypes = {AUTO_TYPE, SKIN_SMOOTH, FACE_SLENDER, SKIN_TONE};
    return supportedBeautyTypes;
}

std::vector<int32_t> GetSupportedBeautyRangeStub(void* obj, BeautyType beautyType)
{
    cout<<"=================GetSupportedBeautyRangeStub call================="<<endl;
    vector<int32_t> beautyRange;
    switch (beautyType) {
        case BeautyType::AUTO_TYPE : {
            std::vector<int32_t> values = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
            beautyRange = values;
            break;
        }
        case BeautyType::SKIN_TONE : {
            std::vector<int32_t> values = {0xFFFFFFFF, 0xBF986C, 0xE9BB97, 0xEDCDA3, 0xF7D7B3, 0xFEE6CF};
            beautyRange = values;
            break;
        }
        case BeautyType::SKIN_SMOOTH : {
            std::vector<int32_t> values = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
            beautyRange = values;
            break;
        }
        case BeautyType::FACE_SLENDER : {
            std::vector<int32_t> values = {0, 1, 2, 3, 4, 5};
            beautyRange = values;
            break;
        }
        default : {
            std::vector<int32_t> values = {};
            beautyRange = values;
        }
    }
    cout<<"BeautyType = " << beautyType << " BeautyType size()" << beautyRange.size() <<endl;
    return beautyRange;
}

int32_t GetExposureRangeStub(std::vector<uint32_t> &exposureRange)
{
    cout<<"=================GetSupportedBeautyRangeStub call================="<<endl;
    exposureRange.clear();
    std::vector<uint32_t> exposureRangeStub = {250, 500, 1000, 2000, 4000, 8000,
        12000, 16000, 20000, 24000, 28000, 32000};
    for (size_t i = 0; i < exposureRangeStub.size(); i++) {
        exposureRange.push_back(exposureRangeStub.at(i));
    }
    cout << " exposureRangeStub size()" << exposureRangeStub.size() <<endl;
    return 0;
}

std::vector<FilterType> GetSupportedFiltersStub()
{
    cout<<"=================GetSupportedFiltersStub call================="<<endl;
    std::vector<FilterType> supportedFilterTypes = { NONE, CLASSIC, DAWN, PURE, GREY, NATURAL, MORI, FAIR, PINK };
    return supportedFilterTypes;
}

int main(int argc, char **argv)
{
    cout<<"-----------------version:20230822-----------------"<<endl;
    const int32_t previewWidthIndex = 1;
    const int32_t previewHeightIndex = 2;
    const int32_t photoWidthIndex = 3;
    const int32_t photoHeightIndex = 4;
    const int32_t devicePosionIndex = 5;
    const int32_t validArgCount = 6;
    const int32_t gapAfterCapture = 3; // 1 second
    const int32_t previewCaptureGap = 5; // 5 seconds
    const char* testName = "camera_capture_mode";
    int32_t ret = -1;
    int32_t previewFd = -1;
    int32_t photoFd = -1;
    int32_t previewFormat = CAMERA_FORMAT_YUV_420_SP;
    int32_t previewWidth = 1280;
    int32_t previewHeight = 960;
    int32_t photoFormat = CAMERA_FORMAT_JPEG;
    int32_t photoWidth = 1280;
    int32_t photoHeight = 960;
    int32_t photoCaptureCount = 1;
    int32_t devicePosion = 0;
    bool isResolutionConfigured = false;
    Size previewsize;
    Size photosize;

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
        .processName = "camera_capture_mode",
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
    sptr<CameraManager> modeManagerObj = CameraManager::GetInstance();
    std::vector<SceneMode> supportedModes = modeManagerObj->GetSupportedModes(device);
    std::string modes = "";
    for (auto mode : supportedModes) {
        modes += std::to_string(static_cast<uint32_t>(mode)) + " , ";
    }
    MEDIA_INFO_LOG("supportedModes : %{public}s", modes.c_str());
    sptr<CaptureSession> captureSession = modeManagerObj->CreateCaptureSession(SceneMode::PORTRAIT);
    sptr<PortraitSession> portraitSession = nullptr;
    portraitSession = static_cast<PortraitSession *> (captureSession.GetRefPtr());
    if (portraitSession == nullptr) {
        return 0;
    }
    portraitSession->BeginConfig();
    sptr<CaptureInput> captureInput = camManagerObj->CreateCameraInput(device);
    if (captureInput == nullptr) {
        return 0;
    }

    sptr<CameraInput> cameraInput = (sptr<CameraInput> &)captureInput;
    cameraInput->Open();
    std::vector<Profile> photoProfiles = {};
    std::vector<Profile> previewProfiles = {};
    std::string abilityIds = "";
    if (isResolutionConfigured) {
        std::vector<CameraFormat> previewFormats;
        std::vector<CameraFormat> photoFormats;
        std::vector<Size> previewSizes;
        std::vector<Size> photoSizes;
        sptr<CameraOutputCapability> outputcapability =
            modeManagerObj->GetSupportedOutputCapability(device, SceneMode::PORTRAIT);
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
    }

    MEDIA_INFO_LOG("photoCaptureCount: %{public}d", photoCaptureCount);

    cameraInput->SetErrorCallback(std::make_shared<TestDeviceCallback>(testName));
    ret = portraitSession->AddInput(captureInput);
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
    sptr<IBufferProducer> bp = photoSurface->GetProducer();
    sptr<CaptureOutput> photoOutput = camManagerObj->CreatePhotoOutput(photoprofile, bp);
    if (photoOutput == nullptr) {
        return 0;
    }

    MEDIA_INFO_LOG("Setting photo callback");
    ((sptr<PhotoOutput> &)photoOutput)->SetCallback(std::make_shared<TestPhotoOutputCallback>(testName));
    ret = portraitSession->AddOutput(photoOutput);
    if (ret != 0) {
        return 0;
    }

    sptr<CaptureOutput> metaOutput = camManagerObj->CreateMetadataOutput();
    MEDIA_INFO_LOG("Setting Meta callback");
    ((sptr<MetadataOutput> &)metaOutput)->SetCallback(std::make_shared<TestMetadataOutputObjectCallback>(testName));

    ret = portraitSession->AddOutput(metaOutput);
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
    sptr<SurfaceListener> listener = new(std::nothrow) SurfaceListener("Preview", SurfaceType::PREVIEW,
                                                                       previewFd, previewSurface);
    previewSurface->RegisterConsumerListener((sptr<IBufferConsumerListener> &)listener);
    sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
    sptr<Surface> previewProducerSurface = Surface::CreateSurfaceAsProducer(previewProducer);
    sptr<CaptureOutput> previewOutput = camManagerObj->CreatePreviewOutput(previewprofile, previewProducerSurface);
    if (previewOutput == nullptr) {
        return 0;
    }

    MEDIA_INFO_LOG("Setting preview callback");
    ((sptr<PreviewOutput> &)previewOutput)->SetCallback(std::make_shared<TestPreviewOutputCallback>(testName));
    ret = portraitSession->AddOutput(previewOutput);
    if (ret != 0) {
        return 0;
    }

    ret = portraitSession->CommitConfig();
    if (ret != 0) {
        return 0;
    }

    MEDIA_INFO_LOG("Preview started");
    ret = portraitSession->Start();
    if (ret != 0) {
        return 0;
    }

    std::vector<float> vecZoomRatioList;
    portraitSession->GetZoomRatioRange(vecZoomRatioList);
    cout<< "getMode:" << portraitSession->GetFeaturesMode().Dump() << ",minZoom:" << vecZoomRatioList[0]
        << ", maxZoom:" << vecZoomRatioList[1]<<endl;
    std::vector<BeautyType> supportedBeautyType = portraitSession->GetSupportedBeautyTypes();
    PrintSupportBeautyTypes(supportedBeautyType);

    std::vector<int32_t> faceSlenderRange = portraitSession->GetSupportedBeautyRange(BeautyType::FACE_SLENDER);
    PrintSupportBeautyRange(BeautyType::FACE_SLENDER, faceSlenderRange);

    std::vector<int32_t> skinSmoothRange = portraitSession->GetSupportedBeautyRange(BeautyType::SKIN_SMOOTH);
    PrintSupportBeautyRange(BeautyType::SKIN_SMOOTH, skinSmoothRange);

    std::vector<int32_t> skinToneRange = portraitSession->GetSupportedBeautyRange(BeautyType::SKIN_TONE);
    PrintSupportBeautyRange(BeautyType::SKIN_TONE, skinToneRange);

    vector<FilterType> supportedFilterTypes = portraitSession->GetSupportedFilters();
    PrintSupportFilterTypes(supportedFilterTypes);

    vector<PortraitEffect> supportedPortraitEffects = portraitSession->GetSupportedPortraitEffects();
    PrintSupportPortraitEffects(supportedPortraitEffects);

    sleep(previewCaptureGap);

    uint32_t photoCnt = 1;

    MEDIA_INFO_LOG("Normal Capture started");
    for (int i = 1; i <= photoCaptureCount; i++) {
        MEDIA_INFO_LOG("Photo capture %{public}d started", i);
        ret = ((sptr<PhotoOutput> &)photoOutput)->Capture(ConfigPhotoCaptureSetting());
        if (ret != 0) {
            MEDIA_INFO_LOG("Photo capture err ret=%{public}d", ret);
            return 0;
        }
        sleep(gapAfterCapture);
    }

    cout<< "Filter Capture started" <<endl;
    for (auto filter : supportedFilterTypes) {
        MEDIA_INFO_LOG("Set Filter: %{public}s", g_filterTypeStr_[filter].c_str());
        portraitSession->LockForControl();
        portraitSession->SetFilter(filter);
        portraitSession->UnlockForControl();
        sleep(gapAfterCapture);
        ret = ((sptr<PhotoOutput> &)photoOutput)->Capture(ConfigPhotoCaptureSetting());
        if (ret != 0) {
            return 0;
        }
        MEDIA_INFO_LOG("Photo capture cnt [%{public}d] filter : %{public}s",
                       photoCnt++, g_filterTypeStr_[filter].c_str());
        sleep(gapAfterCapture);
    }
    cout<< "Filter Capture started" <<endl;

    cout<< "BeautyType::SKIN_TONE Capture started" <<endl;
    for (auto beautyVal : skinToneRange) {
        MEDIA_INFO_LOG("Set Beauty: %{public}s beautyVal= %{public}d",
                       g_beautyTypeStr_[BeautyType::SKIN_TONE].c_str(), beautyVal);
        portraitSession->LockForControl();
        portraitSession->SetBeauty(BeautyType::SKIN_TONE, beautyVal);
        portraitSession->UnlockForControl();
        ret = ((sptr<PhotoOutput> &)photoOutput)->Capture(ConfigPhotoCaptureSetting());
        if (ret != 0) {
            return 0;
        }
        sleep(gapAfterCapture);
    }
    cout<< "BeautyType::SKIN_TONE Capture end" <<endl;

    cout<< "BeautyType::FACE_SLENDER Capture started" <<endl;
    for (auto beautyVal : skinToneRange) {
        MEDIA_INFO_LOG("Set Beauty: %{public}s beautyVal= %{public}d",
                       g_beautyTypeStr_[BeautyType::FACE_SLENDER].c_str(), beautyVal);
        portraitSession->LockForControl();
        portraitSession->SetBeauty(BeautyType::FACE_SLENDER, beautyVal);
        portraitSession->UnlockForControl();
        ret = ((sptr<PhotoOutput> &)photoOutput)->Capture(ConfigPhotoCaptureSetting());
        if (ret != 0) {
            return 0;
        }
        sleep(gapAfterCapture);
    }
    cout<< "BeautyType::FACE_SLENDER Capture end" <<endl;

    cout<< "BeautyType::SKIN_SMOOTH Capture started" <<endl;
    for (auto beautyVal : skinToneRange) {
        MEDIA_INFO_LOG("Set Beauty: %{public}s beautyVal= %{public}d",
                       g_beautyTypeStr_[BeautyType::SKIN_SMOOTH].c_str(), beautyVal);
        portraitSession->LockForControl();
        portraitSession->SetBeauty(BeautyType::SKIN_SMOOTH, beautyVal);
        portraitSession->UnlockForControl();
        ret = ((sptr<PhotoOutput> &)photoOutput)->Capture(ConfigPhotoCaptureSetting());
        if (ret != 0) {
            return 0;
        }
        sleep(gapAfterCapture);
    }
    cout<< "BeautyType::SKIN_SMOOTH Capture end" <<endl;

    cout<< "PortraitEffect Capture started" <<endl;
    for (auto effect : supportedPortraitEffects) {
        MEDIA_INFO_LOG("Set PortraitEffect: %{public}s", g_portraitEffectStr_[effect].c_str());
        portraitSession->LockForControl();
        portraitSession->SetPortraitEffect(effect);
        portraitSession->UnlockForControl();
        ret = ((sptr<PhotoOutput> &)photoOutput)->Capture(ConfigPhotoCaptureSetting());
        if (ret != 0) {
            return 0;
        }
        MEDIA_INFO_LOG("Photo capture [%{public}d] filter : %{public}s",
                       photoCnt++, g_portraitEffectStr_[effect].c_str());
        sleep(gapAfterCapture);
    }
    cout<< "PortraitEffect Capture end" <<endl;
    MEDIA_INFO_LOG("Closing the session");
    ((sptr<PreviewOutput> &)previewOutput)->Stop();
    portraitSession->Stop();
    portraitSession->Release();
    cameraInput->Release();
    camManagerObj->SetCallback(nullptr);

    MEDIA_INFO_LOG("Camera new sample end.");
    return 0;
}
