/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "camera_ffi.h"

using namespace OHOS::FFI;

namespace OHOS {
namespace CameraStandard {

extern "C" {
int64_t FfiCameraManagerConstructor()
{
    auto cameraManagerImpl = FFIData::Create<CJCameraManager>();
    if (cameraManagerImpl == nullptr) {
        return -1;
    }
    return cameraManagerImpl->GetID();
}

CArrI32 FfiCameraManagerGetSupportedSceneModes(int64_t id, CJCameraDevice cameraDevice, int32_t *errCode)
{
    auto cameraManagerImpl = FFIData::GetData<CJCameraManager>(id);
    if (cameraManagerImpl == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return CArrI32{0};
    }
    std::string cameraId = std::string(cameraDevice.cameraId);
    return cameraManagerImpl->GetSupportedSceneModes(cameraId, errCode);
}

CArrCJCameraDevice FfiCameraManagerGetSupportedCameras(int64_t id, int32_t *errCode)
{
    auto cameraManagerImpl = FFIData::GetData<CJCameraManager>(id);
    if (cameraManagerImpl == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return CArrCJCameraDevice{0};
    }
    return cameraManagerImpl->GetSupportedCameras(errCode);
}

CJCameraOutputCapability FfiCameraManagerGetSupportedOutputCapability(int64_t id, CJCameraDevice cameraDevice,
                                                                      int32_t modeType, int32_t *errCode)
{
    auto cameraManagerImpl = FFIData::GetData<CJCameraManager>(id);
    if (cameraManagerImpl == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return CJCameraOutputCapability{CArrCJProfile{0}, CArrCJProfile{0}, CArrCJVideoProfile{0}, CArrI32{0}};
    }
    std::string cameraId = std::string(cameraDevice.cameraId);
    sptr<CameraDevice> cameraInfo = cameraManagerImpl->GetCameraDeviceById(cameraId);
    if (cameraInfo == nullptr) {
        *errCode = CameraError::INVALID_PARAM;
        return CJCameraOutputCapability{CArrCJProfile{0}, CArrCJProfile{0}, CArrCJVideoProfile{0}, CArrI32{0}};
    }
    sptr<CameraOutputCapability> cameraOutputCapability =
        cameraManagerImpl->GetSupportedOutputCapability(cameraInfo, modeType);
    return CameraOutputCapabilityToCJCameraOutputCapability(cameraOutputCapability, errCode);
}

bool FfiCameraManagerIsCameraMuted()
{
    return CJCameraManager::IsCameraMuted();
}

int64_t FfiCameraManagerCreateCameraInputWithCameraDevice(int64_t id, CJCameraDevice cameraDevice, int32_t *errCode)
{
    auto cameraManagerImpl = FFIData::GetData<CJCameraManager>(id);
    if (cameraManagerImpl == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return -1;
    }

    std::string cameraId = std::string(cameraDevice.cameraId);
    sptr<CameraDevice> cameraInfo = cameraManagerImpl->GetCameraDeviceById(cameraId);
    if (cameraInfo == nullptr) {
        *errCode = CameraError::INVALID_PARAM;
        return -1;
    }
    sptr<CameraInput> cameraInput = nullptr;
    *errCode = cameraManagerImpl->CreateCameraInputWithCameraDevice(cameraInfo, &cameraInput);
    if (*errCode != CameraError::NO_ERROR) {
        return -1;
    }
    auto cameraInputImpl = FFIData::Create<CJCameraInput>(cameraInput);
    if (cameraInputImpl == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return -1;
    }

    return cameraInputImpl->GetID();
}

int64_t FfiCameraManagerCreateCameraInputWithCameraDeviceInfo(int64_t id, int32_t cameraPosition, int32_t cameraType,
                                                              int32_t *errCode)
{
    sptr<CameraInput> cameraInput = nullptr;
    auto cameraManagerImpl = FFIData::GetData<CJCameraManager>(id);
    if (cameraManagerImpl == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return -1;
    }

    *errCode = cameraManagerImpl->CreateCameraInputWithCameraDeviceInfo(
        static_cast<const CameraPosition>(cameraPosition), static_cast<const CameraType>(cameraType), &cameraInput);
    if (*errCode != CameraError::NO_ERROR) {
        return -1;
    }
    auto cameraInputImpl = FFIData::Create<CJCameraInput>(cameraInput);
    if (cameraInputImpl == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return -1;
    }

    return cameraInputImpl->GetID();
}

int64_t FfiCameraManagerCreatePreviewOutput(CJProfile profile, const char *surfaceId, int32_t *errCode)
{
    std::string surfaceId_s = std::string(surfaceId);
    Size size = {profile.width, profile.height};
    Profile c_Profile(CameraFormat(profile.format), size);

    *errCode = CJPreviewOutput::CreatePreviewOutput(c_Profile, surfaceId_s);
    if (*errCode == CameraError::CAMERA_SERVICE_ERROR) {
        return -1;
    }

    auto previewOutputImpl = FFIData::Create<CJPreviewOutput>();
    if (previewOutputImpl == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return -1;
    }
    *errCode = CameraError::NO_ERROR;
    return previewOutputImpl->GetID();
}

int64_t FfiCameraManagerCreatePreviewOutputWithoutProfile(const char *surfaceId, int32_t *errCode)
{
    std::string surfaceId_s = std::string(surfaceId);
    *errCode = CJPreviewOutput::CreatePreviewOutputWithoutProfile(surfaceId_s);
    if (*errCode != CameraError::NO_ERROR) {
        return -1;
    }

    auto previewOutputImpl = FFIData::Create<CJPreviewOutput>();
    if (previewOutputImpl == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return -1;
    }
    return previewOutputImpl->GetID();
}

int64_t FfiCameraManagerCreatePhotoOutput(int32_t *errCode)
{
    *errCode = CJPhotoOutput::CreatePhotoOutput();
    if (*errCode != CameraError::NO_ERROR) {
        return -1;
    }

    auto photoOutputImpl = FFIData::Create<CJPhotoOutput>();
    if (photoOutputImpl == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return -1;
    }
    return photoOutputImpl->GetID();
}

int64_t FfiCameraManagerCreatePhotoOutputWithProfile(CJProfile profile, int32_t *errCode)
{
    Size size = {profile.width, profile.height};
    Profile c_Profile(CameraFormat(profile.format), size);

    *errCode = CJPhotoOutput::CreatePhotoOutputWithProfile(c_Profile);
    if (*errCode != CameraError::NO_ERROR) {
        return -1;
    }

    auto photoOutputImpl = FFIData::Create<CJPhotoOutput>();
    if (photoOutputImpl == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return -1;
    }
    return photoOutputImpl->GetID();
}

int64_t FfiCameraManagerCreateVideoOutput(CJVideoProfile profile, char *surfaceId, int32_t *errCode)
{
    Size size = {profile.width, profile.height};
    std::vector<int32_t> framerates = {profile.frameRateRange.min, profile.frameRateRange.max};
    VideoProfile videoProfile = VideoProfile(CameraFormat(profile.format), size, framerates);

    *errCode = CJVideoOutput::CreateVideoOutput(videoProfile, surfaceId);
    if (*errCode != CameraError::NO_ERROR) {
        return -1;
    }

    auto videoOutputImpl = FFIData::Create<CJVideoOutput>();
    if (videoOutputImpl == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return -1;
    }
    return videoOutputImpl->GetID();
}

int64_t FfiCameraManagerCreateVideoOutputWithOutProfile(char *surfaceId, int32_t *errCode)
{
    *errCode = CJVideoOutput::CreateVideoOutputWithOutProfile(surfaceId);
    if (*errCode != CameraError::NO_ERROR) {
        return -1;
    }

    auto videoOutputImpl = FFIData::Create<CJVideoOutput>();
    if (videoOutputImpl == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return -1;
    }
    return videoOutputImpl->GetID();
}

int64_t FfiCameraManagerCreateMetadataOutput(CArrI32 metadataObjectTypes, int32_t *errCode)
{
    std::vector<MetadataObjectType> vec;
    for (int32_t i = 0; i < metadataObjectTypes.size; i++) {
        vec.push_back(static_cast<MetadataObjectType>(metadataObjectTypes.head[i]));
    }
    *errCode = CJMetadataOutput::CreateMetadataOutput(vec);
    if (*errCode != CameraError::NO_ERROR) {
        return -1;
    }

    auto metadataOutputImpl = FFIData::Create<CJMetadataOutput>();
    if (metadataOutputImpl == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return -1;
    }
    return metadataOutputImpl->GetID();
}

int64_t FfiCameraManagerCreateSession(int32_t mode, int32_t *errCode)
{
    auto cameraSession_ = CJCameraManager::CreateSession(mode);
    if (cameraSession_ == nullptr) {
        MEDIA_ERR_LOG("Failed to create Video session instance");
        *errCode = SERVICE_FATL_ERROR;
        return -1;
    }
    auto session = FFIData::Create<CJSession>(cameraSession_);
    if (session == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return -1;
    }
    return session->GetID();
}

bool FfiCameraManagerIsTorchSupported()
{
    return CJCameraManager::IsTorchSupported();
}

bool FfiCameraManagerIsTorchModeSupported(int32_t modeType)
{
    return CJCameraManager::IsTorchModeSupported(modeType);
}

int32_t FfiCameraManagerGetTorchMode()
{
    return CJCameraManager::GetTorchMode();
}

int32_t FfiCameraManagerSetTorchMode(int32_t modeType)
{
    return CJCameraManager::SetTorchMode(modeType);
}

int32_t FfiCameraManagerOnCameraStatusChanged(int64_t id, int64_t callbackId)
{
    auto cameraManagerImpl = FFIData::GetData<CJCameraManager>(id);
    if (cameraManagerImpl == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    cameraManagerImpl->OnCameraStatusChanged(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraManagerOffCameraStatusChanged(int64_t id, int64_t callbackId)
{
    auto cameraManagerImpl = FFIData::GetData<CJCameraManager>(id);
    if (cameraManagerImpl == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    cameraManagerImpl->OffCameraStatusChanged(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraManagerOffAllCameraStatusChanged(int64_t id)
{
    auto cameraManagerImpl = FFIData::GetData<CJCameraManager>(id);
    if (cameraManagerImpl == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    cameraManagerImpl->OffAllCameraStatusChanged();
    return CameraError::NO_ERROR;
}

int32_t FfiCameraManagerOnFoldStatusChanged(int64_t id, int64_t callbackId)
{
    auto cameraManagerImpl = FFIData::GetData<CJCameraManager>(id);
    if (cameraManagerImpl == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    cameraManagerImpl->OnFoldStatusChanged(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraManagerOffFoldStatusChanged(int64_t id, int64_t callbackId)
{
    auto cameraManagerImpl = FFIData::GetData<CJCameraManager>(id);
    if (cameraManagerImpl == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    cameraManagerImpl->OffFoldStatusChanged(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraManagerOffAllFoldStatusChanged(int64_t id)
{
    auto cameraManagerImpl = FFIData::GetData<CJCameraManager>(id);
    if (cameraManagerImpl == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    cameraManagerImpl->OffAllFoldStatusChanged();
    return CameraError::NO_ERROR;
}

int32_t FfiCameraManagerOnTorchStatusChange(int64_t id, int64_t callbackId)
{
    auto cameraManagerImpl = FFIData::GetData<CJCameraManager>(id);
    if (cameraManagerImpl == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    cameraManagerImpl->OnTorchStatusChange(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraManagerOffTorchStatusChange(int64_t id, int64_t callbackId)
{
    auto cameraManagerImpl = FFIData::GetData<CJCameraManager>(id);
    if (cameraManagerImpl == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    cameraManagerImpl->OffTorchStatusChange(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraManagerOffAllTorchStatusChange(int64_t id)
{
    auto cameraManagerImpl = FFIData::GetData<CJCameraManager>(id);
    if (cameraManagerImpl == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    cameraManagerImpl->OffAllTorchStatusChange();
    return CameraError::NO_ERROR;
}

int32_t FfiCameraInputOpen(int64_t id)
{
    auto instance = FFIData::GetData<CJCameraInput>(id);
    if (instance == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return instance->Open();
}

int32_t FfiCameraInputOpenWithIsEnableSecureCamera(int64_t id, bool isEnableSecureCamera, uint64_t *secureSeqId)
{
    auto instance = FFIData::GetData<CJCameraInput>(id);
    if (instance == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return instance->Open(isEnableSecureCamera, secureSeqId);
}

int32_t FfiCameraInputClose(int64_t id)
{
    auto instance = FFIData::GetData<CJCameraInput>(id);
    if (instance == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return instance->Close();
}

int32_t FfiCameraInputOnError(int64_t id, int64_t callbackId)
{
    auto instance = FFIData::GetData<CJCameraInput>(id);
    if (instance == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    instance->OnError(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraInputOffError(int64_t id, int64_t callbackId)
{
    auto instance = FFIData::GetData<CJCameraInput>(id);
    if (instance == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    instance->OffError(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraInputOffAllError(int64_t id)
{
    auto instance = FFIData::GetData<CJCameraInput>(id);
    if (instance == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    instance->OffAllError();
    return CameraError::NO_ERROR;
}

CArrFrameRateRange FfiCameraPreviewOutputGetSupportedFrameRates(int64_t id, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJPreviewOutput>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return CArrFrameRateRange{0};
    }
    return instance->GetSupportedFrameRates(errCode);
}

int32_t FfiCameraPreviewOutputSetFrameRate(int64_t id, int32_t min, int32_t max)
{
    auto instance = FFIData::GetData<CJPreviewOutput>(id);
    if (instance == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return instance->SetFrameRate(min, max);
}

FrameRateRange FfiCameraPreviewOutputGetActiveFrameRate(int64_t id, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJPreviewOutput>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return FrameRateRange{0};
    }
    return instance->GetActiveFrameRate(errCode);
}

CJProfile FfiCameraPreviewOutputGetActiveProfile(int64_t id, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJPreviewOutput>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return CJProfile{0};
    }
    return instance->GetActiveProfile(errCode);
}

int32_t FfiCameraPreviewOutputGetPreviewRotation(int64_t id, int32_t value, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJPreviewOutput>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return 0;
    }
    return instance->GetPreviewRotation(value, errCode);
}

int32_t FfiCameraPreviewOutputSetPreviewRotation(int64_t id, int32_t imageRotation, bool isDisplayLocked)
{
    auto instance = FFIData::GetData<CJPreviewOutput>(id);
    if (instance == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return instance->SetPreviewRotation(imageRotation, isDisplayLocked);
}

int32_t FfiCameraPreviewOutputOnFrameStart(int64_t id, int64_t callbackId)
{
    auto instance = FFIData::GetData<CJPreviewOutput>(id);
    if (instance == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    instance->OnFrameStart(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraPreviewOutputOnFrameEnd(int64_t id, int64_t callbackId)
{
    auto instance = FFIData::GetData<CJPreviewOutput>(id);
    if (instance == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    instance->OnFrameEnd(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraPreviewOutputOnError(int64_t id, int64_t callbackId)
{
    auto instance = FFIData::GetData<CJPreviewOutput>(id);
    if (instance == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    instance->OnError(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraPreviewOutputOffFrameStart(int64_t id, int64_t callbackId)
{
    auto instance = FFIData::GetData<CJPreviewOutput>(id);
    if (instance == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    instance->OffFrameStart(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraPreviewOutputOffFrameEnd(int64_t id, int64_t callbackId)
{
    auto instance = FFIData::GetData<CJPreviewOutput>(id);
    if (instance == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    instance->OffFrameEnd(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraPreviewOutputOffError(int64_t id, int64_t callbackId)
{
    auto instance = FFIData::GetData<CJPreviewOutput>(id);
    if (instance == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    instance->OffError(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraPreviewOutputOffAllFrameStart(int64_t id)
{
    auto instance = FFIData::GetData<CJPreviewOutput>(id);
    if (instance == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    instance->OffAllFrameStart();
    return CameraError::NO_ERROR;
}

int32_t FfiCameraPreviewOutputOffAllFrameEnd(int64_t id)
{
    auto instance = FFIData::GetData<CJPreviewOutput>(id);
    if (instance == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    instance->OffAllFrameEnd();
    return CameraError::NO_ERROR;
}

int32_t FfiCameraPreviewOutputOffAllError(int64_t id)
{
    auto instance = FFIData::GetData<CJPreviewOutput>(id);
    if (instance == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    instance->OffAllError();
    return CameraError::NO_ERROR;
}

int32_t FfiCameraPreviewOutputRelease(int64_t id)
{
    auto instance = FFIData::GetData<CJPreviewOutput>(id);
    if (instance == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return instance->Release();
}

int32_t FfiCameraPhotoOutputCapture(int64_t id)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return photoOutput->Capture();
}

int32_t FfiCameraPhotoOutputCaptureWithSetting(int64_t id, CJPhotoCaptureSetting setting)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return photoOutput->Capture(setting, false);
}

FFI_EXPORT int32_t FfiCameraPhotoOutputCaptureWithSettingV2(int64_t id, CJPhotoCaptureSetting *setting,
    bool isLocationNone)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return photoOutput->Capture(*setting, isLocationNone);
}

int32_t FfiCameraPhotoOutputOnCaptureStartWithInfo(int64_t id, int64_t callbackId)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    photoOutput->OnCaptureStartWithInfo(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraPhotoOutputOffCaptureStartWithInfo(int64_t id, int64_t callbackId)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    photoOutput->OffCaptureStartWithInfo(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraPhotoOutputOffAllCaptureStartWithInfo(int64_t id)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    photoOutput->OffAllCaptureStartWithInfo();
    return CameraError::NO_ERROR;
}

int32_t FfiCameraPhotoOutputOnFrameShutter(int64_t id, int64_t callbackId)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    photoOutput->OnFrameShutter(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraPhotoOutputOffFrameShutter(int64_t id, int64_t callbackId)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    photoOutput->OffFrameShutter(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraPhotoOutputOffAllFrameShutter(int64_t id)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    photoOutput->OffAllFrameShutter();
    return CameraError::NO_ERROR;
}

int32_t FfiCameraPhotoOutputOnCaptureEnd(int64_t id, int64_t callbackId)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    photoOutput->OnCaptureEnd(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraPhotoOutputOffCaptureEnd(int64_t id, int64_t callbackId)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    photoOutput->OffCaptureEnd(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraPhotoOutputOffAllCaptureEnd(int64_t id)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    photoOutput->OffAllCaptureEnd();
    return CameraError::NO_ERROR;
}

int32_t FfiCameraPhotoOutputOnFrameShutterEnd(int64_t id, int64_t callbackId)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    photoOutput->OnFrameShutterEnd(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraPhotoOutputOffFrameShutterEnd(int64_t id, int64_t callbackId)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    photoOutput->OffFrameShutterEnd(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraPhotoOutputOffAllFrameShutterEnd(int64_t id)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    photoOutput->OffAllFrameShutterEnd();
    return CameraError::NO_ERROR;
}

int32_t FfiCameraPhotoOutputOnCaptureReady(int64_t id, int64_t callbackId)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    photoOutput->OnCaptureReady(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraPhotoOutputOffCaptureReady(int64_t id, int64_t callbackId)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    photoOutput->OffCaptureReady(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraPhotoOutputOffAllCaptureReady(int64_t id)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    photoOutput->OffAllCaptureReady();
    return CameraError::NO_ERROR;
}

int32_t FfiCameraPhotoOutputOnEstimatedCaptureDuration(int64_t id, int64_t callbackId)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    photoOutput->OnEstimatedCaptureDuration(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraPhotoOutputOffEstimatedCaptureDuration(int64_t id, int64_t callbackId)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    photoOutput->OffEstimatedCaptureDuration(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraPhotoOutputOffAllEstimatedCaptureDuration(int64_t id)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    photoOutput->OffAllEstimatedCaptureDuration();
    return CameraError::NO_ERROR;
}

int32_t FfiCameraPhotoOutputOnError(int64_t id, int64_t callbackId)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    photoOutput->OnError(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraPhotoOutputOffError(int64_t id, int64_t callbackId)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    photoOutput->OffError(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraPhotoOutputOffAllError(int64_t id)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    photoOutput->OffAllError();
    return CameraError::NO_ERROR;
}

int32_t FfiCameraPhotoOutputOnPhotoAvailable(int64_t id, int64_t callbackId)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    photoOutput->OnPhotoAvailable(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraPhotoOutputOffPhotoAvailable(int64_t id, int64_t callbackId)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    photoOutput->OffPhotoAvailable(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraPhotoOutputOffAllPhotoAvailable(int64_t id)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    photoOutput->OffAllPhotoAvailable();
    return CameraError::NO_ERROR;
}

bool FfiCameraPhotoOutputIsMovingPhotoSupported(int64_t id, int32_t *errCode)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return false;
    }
    return photoOutput->IsMovingPhotoSupported(errCode);
}

int32_t FfiCameraPhotoOutputEnableMovingPhoto(int64_t id, bool enabled)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return photoOutput->EnableMovingPhoto(enabled);
}

bool FfiCameraPhotoOutputIsMirrorSupported(int64_t id, int32_t *errCode)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return false;
    }
    return photoOutput->IsMirrorSupported(errCode);
}

int32_t FfiCameraPhotoOutputEnableMirror(int64_t id, bool isMirror)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return photoOutput->EnableMirror(isMirror);
}

int32_t FfiCameraPhotoOutputSetMovingPhotoVideoCodecType(int64_t id, int32_t codecType)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return photoOutput->SetMovingPhotoVideoCodecType(codecType);
}

CJProfile FfiCameraPhotoOutputGetActiveProfile(int64_t id, int32_t *errCode)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return CJProfile{0};
    }
    return photoOutput->GetActiveProfile(errCode);
}

int32_t FfiCameraPhotoOutputGetPhotoRotation(int64_t id, int32_t deviceDegree, int32_t *errCode)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return -1;
    }
    return photoOutput->GetPhotoRotation(deviceDegree, errCode);
}

int32_t FfiCameraPhotoOutputRelease(int64_t id)
{
    auto photoOutput = FFIData::GetData<CJPhotoOutput>(id);
    if (photoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return photoOutput->Release();
}

int32_t FfiCameraVideoOutputStart(int64_t id)
{
    auto videoOutput = FFIData::GetData<CJVideoOutput>(id);
    if (videoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return videoOutput->Start();
}

int32_t FfiCameraVideoOutputStop(int64_t id)
{
    auto videoOutput = FFIData::GetData<CJVideoOutput>(id);
    if (videoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return videoOutput->Stop();
}

CArrFrameRateRange FfiCameraVideoOutputGetSupportedFrameRates(int64_t id, int32_t *errCode)
{
    auto videoOutput = FFIData::GetData<CJVideoOutput>(id);
    if (videoOutput == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return CArrFrameRateRange{0};
    }
    return videoOutput->GetSupportedFrameRates(errCode);
}

int32_t FfiCameraVideoOutputSetFrameRate(int64_t id, int32_t minFps, int32_t maxFps)
{
    auto videoOutput = FFIData::GetData<CJVideoOutput>(id);
    if (videoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return videoOutput->SetFrameRate(minFps, maxFps);
}

FrameRateRange FfiCameraVideoOutputGetActiveFrameRate(int64_t id, int32_t *errCode)
{
    auto videoOutput = FFIData::GetData<CJVideoOutput>(id);
    if (videoOutput == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return FrameRateRange{0};
    }
    return videoOutput->GetActiveFrameRate(errCode);
}

CJVideoProfile FfiCameraVideoOutputGetActiveProfile(int64_t id, int32_t *errCode)
{
    auto videoOutput = FFIData::GetData<CJVideoOutput>(id);
    if (videoOutput == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return CJVideoProfile{0};
    }
    return videoOutput->GetActiveProfile(errCode);
}

int32_t FfiCameraVideoOutputGetVideoRotation(int64_t id, int32_t imageRotation, int32_t *errCode)
{
    auto videoOutput = FFIData::GetData<CJVideoOutput>(id);
    if (videoOutput == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return -1;
    }
    return videoOutput->GetVideoRotation(imageRotation, errCode);
}

int32_t FfiCameraVideoOutputOnFrameStart(int64_t id, int64_t callbackId)
{
    auto videoOutput = FFIData::GetData<CJVideoOutput>(id);
    if (videoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    videoOutput->OnFrameStart(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraVideoOutputOffFrameStart(int64_t id, int64_t callbackId)
{
    auto videoOutput = FFIData::GetData<CJVideoOutput>(id);
    if (videoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    videoOutput->OffFrameStart(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraVideoOutputOffAllFrameStart(int64_t id)
{
    auto videoOutput = FFIData::GetData<CJVideoOutput>(id);
    if (videoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    videoOutput->OffAllFrameStart();
    return CameraError::NO_ERROR;
}

int32_t FfiCameraVideoOutputOnFrameEnd(int64_t id, int64_t callbackId)
{
    auto videoOutput = FFIData::GetData<CJVideoOutput>(id);
    if (videoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    videoOutput->OnFrameEnd(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraVideoOutputOffFrameEnd(int64_t id, int64_t callbackId)
{
    auto videoOutput = FFIData::GetData<CJVideoOutput>(id);
    if (videoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    videoOutput->OffFrameEnd(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraVideoOutputOffAllFrameEnd(int64_t id)
{
    auto videoOutput = FFIData::GetData<CJVideoOutput>(id);
    if (videoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    videoOutput->OffAllFrameEnd();
    return CameraError::NO_ERROR;
}

int32_t FfiCameraVideoOutputOnError(int64_t id, int64_t callbackId)
{
    auto videoOutput = FFIData::GetData<CJVideoOutput>(id);
    if (videoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    videoOutput->OnError(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraVideoOutputOffError(int64_t id, int64_t callbackId)
{
    auto videoOutput = FFIData::GetData<CJVideoOutput>(id);
    if (videoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    videoOutput->OffError(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraVideoOutputOffAllError(int64_t id)
{
    auto videoOutput = FFIData::GetData<CJVideoOutput>(id);
    if (videoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    videoOutput->OffAllError();
    return CameraError::NO_ERROR;
}

int32_t FfiCameraVideoOutputRelease(int64_t id)
{
    auto videoOutput = FFIData::GetData<CJVideoOutput>(id);
    if (videoOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return videoOutput->Release();
}

int32_t FfiCameraMetadataOutputStart(int64_t id)
{
    auto metadataOutput = FFIData::GetData<CJMetadataOutput>(id);
    if (metadataOutput == nullptr) {
        MEDIA_ERR_LOG("Start Failed!");
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return metadataOutput->Start();
}

int32_t FfiCameraMetadataOutputStop(int64_t id)
{
    auto metadataOutput = FFIData::GetData<CJMetadataOutput>(id);
    if (metadataOutput == nullptr) {
        MEDIA_ERR_LOG("Stop Failed!");
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return metadataOutput->Stop();
}

int32_t FfiCameraMetadataOutputOnMetadataObjectsAvailable(int64_t id, int64_t callbackId)
{
    auto metadataOutput = FFIData::GetData<CJMetadataOutput>(id);
    if (metadataOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    metadataOutput->OnMetadataObjectsAvailable(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraMetadataOutputOffMetadataObjectsAvailable(int64_t id, int64_t callbackId)
{
    auto metadataOutput = FFIData::GetData<CJMetadataOutput>(id);
    if (metadataOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    metadataOutput->OffMetadataObjectsAvailable(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraMetadataOutputOffAllMetadataObjectsAvailable(int64_t id)
{
    auto metadataOutput = FFIData::GetData<CJMetadataOutput>(id);
    if (metadataOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    metadataOutput->OffAllMetadataObjectsAvailable();
    return CameraError::NO_ERROR;
}

int32_t FfiCameraMetadataOutputOnError(int64_t id, int64_t callbackId)
{
    auto metadataOutput = FFIData::GetData<CJMetadataOutput>(id);
    if (metadataOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    metadataOutput->OnError(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraMetadataOutputOffError(int64_t id, int64_t callbackId)
{
    auto metadataOutput = FFIData::GetData<CJMetadataOutput>(id);
    if (metadataOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    metadataOutput->OffError(callbackId);
    return CameraError::NO_ERROR;
}

int32_t FfiCameraMetadataOutputOffAllError(int64_t id)
{
    auto metadataOutput = FFIData::GetData<CJMetadataOutput>(id);
    if (metadataOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    metadataOutput->OffAllError();
    return CameraError::NO_ERROR;
}

int32_t FfiCameraMetadataOutputRelease(int64_t id)
{
    auto metadataOutput = FFIData::GetData<CJMetadataOutput>(id);
    if (metadataOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return metadataOutput->Release();
}

int32_t FfiCameraSessionBeginConfig(int64_t id)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return instance->BeginConfig();
}

int32_t FfiCameraSessionCommitConfig(int64_t id)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return instance->CommitConfig();
}

bool FfiCameraSessionCanAddInput(int64_t id, int64_t cameraInputId, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    auto cameraInput = FFIData::GetData<CJCameraInput>(cameraInputId);
    if (instance == nullptr || cameraInput == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return false;
    }
    return instance->CanAddInput(cameraInput);
}

int32_t FfiCameraSessionAddInput(int64_t id, int64_t cameraInputId)
{
    auto instance = FFIData::GetData<CJSession>(id);
    auto cameraInput = FFIData::GetData<CJCameraInput>(cameraInputId);
    if (instance == nullptr || cameraInput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return instance->AddInput(cameraInput);
}

int32_t FfiCameraSessionRemoveInput(int64_t id, int64_t cameraInputId)
{
    auto instance = FFIData::GetData<CJSession>(id);
    auto cameraInput = FFIData::GetData<CJCameraInput>(cameraInputId);
    if (instance == nullptr || cameraInput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return instance->RemoveInput(cameraInput);
}

static sptr<CameraOutput> GetCameraOutput(int64_t cameraOutputId, int32_t outputType)
{
    if (outputType == METADATA_OUTPUT) {
        return FFIData::GetData<CJMetadataOutput>(cameraOutputId);
    }
    if (outputType == PHOTO_OUTPUT) {
        return FFIData::GetData<CJPhotoOutput>(cameraOutputId);
    }
    if (outputType == PREVIEW_OUTPUT) {
        return FFIData::GetData<CJPreviewOutput>(cameraOutputId);
    }
    return FFIData::GetData<CJVideoOutput>(cameraOutputId);
}

bool FfiCameraSessionCanAddOutput(int64_t id, int64_t cameraOutputId, int32_t outputType, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    auto cameraOutput = GetCameraOutput(cameraOutputId, outputType);
    if (instance == nullptr || cameraOutput == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return false;
    }
    return instance->CanAddOutput(cameraOutput);
}

int32_t FfiCameraSessionAddOutput(int64_t id, int64_t cameraOutputId, int32_t outputType)
{
    auto instance = FFIData::GetData<CJSession>(id);
    auto cameraOutput = GetCameraOutput(cameraOutputId, outputType);
    if (instance == nullptr || cameraOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return instance->AddOutput(cameraOutput);
}

int32_t FfiCameraSessionRemoveOutput(int64_t id, int64_t cameraOutputId, int32_t outputType)
{
    auto instance = FFIData::GetData<CJSession>(id);
    auto cameraOutput = GetCameraOutput(cameraOutputId, outputType);
    if (instance == nullptr || cameraOutput == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return instance->RemoveOutput(cameraOutput);
}

int32_t FfiCameraSessionStart(int64_t id)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return instance->Start();
}

int32_t FfiCameraSessionStop(int64_t id)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return instance->Stop();
}

int32_t FfiCameraSessionRelease(int64_t id)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return instance->Release();
}

FFI_EXPORT bool FfiCameraSessionCanPreconfig(int64_t id, int32_t preconfigType, int32_t preconfigRatio,
                                             int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return false;
    }

    bool isSupported = false;
    *errCode = instance->CanPreconfig(static_cast<PreconfigType>(preconfigType),
                                      static_cast<ProfileSizeRatio>(preconfigRatio), isSupported);
    return isSupported;
}

FFI_EXPORT void FfiCameraSessionPreconfig(int64_t id, int32_t preconfigType, int32_t preconfigRatio, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return;
    }

    *errCode =
        instance->Preconfig(static_cast<PreconfigType>(preconfigType), static_cast<ProfileSizeRatio>(preconfigRatio));
}

FFI_EXPORT void FfiCameraSessionAddSecureOutput(int64_t id, int64_t cameraOutputId, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return;
    }

    auto cameraOutput = FFIData::GetData<CJPreviewOutput>(cameraOutputId);
    if (cameraOutput == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return;
    }

    *errCode = instance->AddSecureOutput(cameraOutput);
}

FFI_EXPORT void FfiCameraOnError(int64_t id, int64_t callbackId, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return;
    }

    instance->OnError(callbackId);
    *errCode = CameraError::NO_ERROR;
}

FFI_EXPORT void FfiCameraOffError(int64_t id, int64_t callbackId, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return;
    }

    instance->OffError(callbackId);
    *errCode = CameraError::NO_ERROR;
}

FFI_EXPORT void FfiCameraOffAllError(int64_t id, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return;
    }

    instance->OffAllError();
    *errCode = CameraError::NO_ERROR;
}

FFI_EXPORT void FfiCameraOnFocusStateChange(int64_t id, int64_t callbackId, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return;
    }

    instance->OnFocusStateChange(callbackId);
    *errCode = CameraError::NO_ERROR;
}

FFI_EXPORT void FfiCameraOffFocusStateChange(int64_t id, int64_t callbackId, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return;
    }

    instance->OffFocusStateChange(callbackId);
    *errCode = CameraError::NO_ERROR;
}

FFI_EXPORT void FfiCameraOffAllFocusStateChange(int64_t id, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return;
    }

    instance->OffAllFocusStateChange();
    *errCode = CameraError::NO_ERROR;
}

FFI_EXPORT void FfiCameraOnSmoothZoomInfoAvailable(int64_t id, int64_t callbackId, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return;
    }

    instance->OnSmoothZoom(callbackId);
    *errCode = CameraError::NO_ERROR;
}

FFI_EXPORT void FfiCameraOffSmoothZoomInfoAvailable(int64_t id, int64_t callbackId, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return;
    }

    instance->OffSmoothZoom(callbackId);
    *errCode = CameraError::NO_ERROR;
}

FFI_EXPORT void FfiCameraOffAllSmoothZoomInfoAvailable(int64_t id, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return;
    }

    instance->OffAllSmoothZoom();
    *errCode = CameraError::NO_ERROR;
}

FFI_EXPORT bool FfiCameraAutoExposureIsExposureModeSupported(int64_t id, int32_t aeMode, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return false;
    }

    bool isSupported = false;
    *errCode = instance->IsExposureModeSupported(static_cast<ExposureMode>(aeMode), isSupported);
    return isSupported;
}

FFI_EXPORT CArrFloat32 FfiCameraAutoExposureGetExposureBiasRange(int64_t id, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return CArrFloat32{0, 0};
    }

    CArrFloat32 cArr = CArrFloat32{0};
    *errCode = instance->GetExposureBiasRange(cArr);
    return cArr;
}

FFI_EXPORT int32_t FfiCameraAutoExposureGetExposureMode(int64_t id, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return static_cast<int32_t>(ExposureMode::EXPOSURE_MODE_UNSUPPORTED);
    }

    ExposureMode aeMode = ExposureMode::EXPOSURE_MODE_UNSUPPORTED;
    *errCode = instance->GetExposureMode(aeMode);
    return static_cast<int32_t>(aeMode);
}

FFI_EXPORT void FfiCameraAutoExposureSetExposureMode(int64_t id, int32_t aeMode, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return;
    }

    *errCode = instance->SetExposureMode(static_cast<ExposureMode>(aeMode));
}

FFI_EXPORT CameraPoint FfiCameraAutoExposureGetMeteringPoint(int64_t id, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return CameraPoint{0, 0};
    }

    CameraPoint point;
    *errCode = instance->GetMeteringPoint(point);
    return point;
}

FFI_EXPORT void FfiCameraAutoExposureSetMeteringPoint(int64_t id, CameraPoint point, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return;
    }

    *errCode = instance->SetMeteringPoint(point);
}

FFI_EXPORT void FfiCameraAutoExposureSetExposureBias(int64_t id, float exposureBias, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return;
    }

    *errCode = instance->SetExposureBias(exposureBias);
}

FFI_EXPORT float FfiCameraAutoExposureGetExposureValue(int64_t id, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return 0;
    }

    float exposureValue = 0;
    *errCode = instance->GetExposureValue(exposureValue);
    return exposureValue;
}

FFI_EXPORT CArrI32 FfiCameraColorManagementGetSupportedColorSpaces(int64_t id, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return CArrI32{0, 0};
    }

    CArrI32 cArr =  CArrI32{0};
    instance->GetSupportedColorSpaces(cArr);
    *errCode = CameraError::NO_ERROR;
    return cArr;
}

FFI_EXPORT void FfiCameraColorManagementSetColorSpace(int64_t id, int32_t colorSpace, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return;
    }

    *errCode = instance->SetColorSpace(static_cast<ColorSpace>(colorSpace));
}

FFI_EXPORT int32_t FfiCameraColorManagementGetActiveColorSpace(int64_t id, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return static_cast<int32_t>(ColorSpace::COLOR_SPACE_UNKNOWN);
    }

    ColorSpace colorSpace = ColorSpace::COLOR_SPACE_UNKNOWN;
    *errCode = instance->GetActiveColorSpace(colorSpace);
    return static_cast<int32_t>(colorSpace);
}

FFI_EXPORT bool FfiCameraFlashQueryFlashModeSupported(int64_t id, int32_t flashMode, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return false;
    }

    bool isSupported = false;
    *errCode = instance->IsFlashModeSupported(static_cast<FlashMode>(flashMode), isSupported);
    return isSupported;
}

FFI_EXPORT bool FfiCameraFlashQueryHasFlash(int64_t id, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return false;
    }

    bool hasFlash = false;
    *errCode = instance->HasFlash(hasFlash);
    return hasFlash;
}

FFI_EXPORT int32_t FfiCameraFlashGetFlashMode(int64_t id, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return 0;
    }

    FlashMode flashMode = FlashMode::FLASH_MODE_CLOSE;
    *errCode = instance->GetFlashMode(flashMode);
    return static_cast<int32_t>(flashMode);
}

FFI_EXPORT void FfiCameraFlashSetFlashMode(int64_t id, int32_t flashMode, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return;
    }

    *errCode = instance->SetFlashMode(static_cast<FlashMode>(flashMode));
}

FFI_EXPORT bool FfiCameraFocusIsFocusModeSupported(int64_t id, int32_t afMode, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return false;
    }

    bool isSupported = false;
    *errCode = instance->IsFocusModeSupported(static_cast<FocusMode>(afMode), isSupported);
    return isSupported;
}

FFI_EXPORT void FfiCameraFocusSetFocusMode(int64_t id, int32_t afMode, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return;
    }

    *errCode = instance->SetFocusMode(static_cast<FocusMode>(afMode));
}

FFI_EXPORT int32_t FfiCameraFocusGetFocusMode(int64_t id, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return 0;
    }

    FocusMode afMode = FocusMode::FOCUS_MODE_MANUAL;
    *errCode = instance->GetFocusMode(afMode);
    return static_cast<int32_t>(afMode);
}

FFI_EXPORT void FfiCameraFocusSetFocusPoint(int64_t id, CameraPoint point, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return;
    }

    *errCode = instance->SetFocusPoint(point);
}

FFI_EXPORT CameraPoint FfiCameraFocusGetFocusPoint(int64_t id, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return CameraPoint{0, 0};
    }

    CameraPoint point;
    *errCode = instance->GetFocusPoint(point);
    return point;
}

FFI_EXPORT float FfiCameraFocusGetFocalLength(int64_t id, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return 0;
    }

    float focalLength = 0;
    *errCode = instance->GetFocalLength(focalLength);
    return focalLength;
}

FFI_EXPORT bool FfiCameraStabilizationIsVideoStabilizationModeSupported(int64_t id, int32_t vsMode, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return false;
    }

    bool isSupported = false;
    *errCode = instance->IsVideoStabilizationModeSupported(static_cast<VideoStabilizationMode>(vsMode), isSupported);
    return isSupported;
}

FFI_EXPORT int32_t FfiCameraStabilizationGetActiveVideoStabilizationMode(int64_t id, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return 0;
    }

    VideoStabilizationMode vsMode = VideoStabilizationMode::OFF;
    *errCode = instance->GetActiveVideoStabilizationMode(vsMode);
    return static_cast<int32_t>(vsMode);
}

FFI_EXPORT void FfiCameraStabilizationSetVideoStabilizationMode(int64_t id, int32_t vsMode, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return;
    }

    *errCode = instance->SetVideoStabilizationMode(static_cast<VideoStabilizationMode>(vsMode));
}

FFI_EXPORT CArrFloat32 FfiCameraZoomGetZoomRatioRange(int64_t id, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return CArrFloat32{0, 0};
    }

    CArrFloat32 cArr = CArrFloat32{0};
    *errCode = instance->GetZoomRatioRange(cArr);
    return cArr;
}

FFI_EXPORT void FfiCameraZoomSetZoomRatio(int64_t id, float zoomRatio, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return;
    }

    *errCode = instance->SetZoomRatio(zoomRatio);
}

FFI_EXPORT float FfiCameraZoomGetZoomRatio(int64_t id, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return 0;
    }

    float zoomRatio = 0;
    *errCode = instance->GetZoomRatio(zoomRatio);
    return zoomRatio;
}

FFI_EXPORT void FfiCameraZoomSetSmoothZoom(int64_t id, float targetRatio, int32_t mode, int32_t *errCode)
{
    auto instance = FFIData::GetData<CJSession>(id);
    if (instance == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return;
    }

    *errCode = instance->SetSmoothZoom(targetRatio, static_cast<uint32_t>(mode));
}

} // extern "C"
} // namespace CameraStandard
} // namespace OHOS