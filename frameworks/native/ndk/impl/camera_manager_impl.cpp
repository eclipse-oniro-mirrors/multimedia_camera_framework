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

#include "camera_manager_impl.h"
#include "camera_log.h"
#include "camera_util.h"
#include "surface_utils.h"
#include "image_receiver.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::CameraStandard;

class InnerCameraManagerCallback : public CameraManagerCallback {
public:
    InnerCameraManagerCallback(Camera_Manager* cameraManager, CameraManager_Callbacks* callback)
        : cameraManager_(cameraManager), callback_(*callback)
        {
            camera_ = new Camera_Device;
        }
    ~InnerCameraManagerCallback()
    {
        if (camera_ != nullptr) {
            delete camera_;
            camera_ = nullptr;
        }
    }

    void OnCameraStatusChanged(const CameraStatusInfo &cameraStatusInfo) const override
    {
        MEDIA_DEBUG_LOG("OnCameraStatusChanged is called!");
        Camera_StatusInfo statusInfo;
        statusInfo.camera = camera_;
        MEDIA_INFO_LOG("cameraId is %{public}s", cameraStatusInfo.cameraDevice->GetID().data());
        MEDIA_INFO_LOG("statusInfo.camera is %{public}p", statusInfo.camera);
        statusInfo.camera->cameraId = cameraStatusInfo.cameraDevice->GetID().data();
        statusInfo.camera->cameraPosition = static_cast<Camera_Position>(cameraStatusInfo.cameraDevice->GetPosition());
        statusInfo.camera->cameraType = static_cast<Camera_Type>(cameraStatusInfo.cameraDevice->GetCameraType());
        statusInfo.camera->connectionType =
            static_cast<Camera_Connection>(cameraStatusInfo.cameraDevice->GetConnectionType());
        statusInfo.status = static_cast<Camera_Status>(cameraStatusInfo.cameraStatus);
        if (cameraManager_ != nullptr && callback_.onCameraStatus != nullptr) {
            callback_.onCameraStatus(cameraManager_, &statusInfo);
        }
    }

    void OnFlashlightStatusChanged(const std::string &cameraID, const FlashStatus flashStatus) const override
    {
        MEDIA_DEBUG_LOG("OnFlashlightStatusChanged is called!");
        (void)cameraID;
        (void)flashStatus;
    }

private:
    Camera_Manager* cameraManager_;
    CameraManager_Callbacks callback_;
    Camera_Device* camera_;
};

Camera_Manager::Camera_Manager()
{
    MEDIA_DEBUG_LOG("Camera_Manager Constructor is called");
    cameraManager_ = CameraManager::GetInstance();
}

Camera_Manager::~Camera_Manager()
{
    MEDIA_DEBUG_LOG("~Camera_Manager is called");
    if (cameraManager_) {
        cameraManager_ = nullptr;
    }
}

Camera_ErrorCode Camera_Manager::RegisterCallback(CameraManager_Callbacks* callback)
{
    shared_ptr<InnerCameraManagerCallback> innerCallback =
                make_shared<InnerCameraManagerCallback>(this, callback);
    cameraManager_->SetCallback(innerCallback);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::UnregisterCallback(CameraManager_Callbacks* callback)
{
    cameraManager_->SetCallback(nullptr);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::GetSupportedCameras(Camera_Device** cameras, uint32_t* size)
{
    std::vector<sptr<CameraDevice>> cameraObjList = CameraManager::GetInstance()->GetSupportedCameras();
    int cameraSize = cameraObjList.size();
    if (cameraSize <= 0) {
        MEDIA_ERR_LOG("camera size <= 0");
        return CAMERA_INVALID_ARGUMENT;
    }
    Camera_Device *outCameras = new Camera_Device[cameraSize];
    for (int i = 0; i < cameraSize; i++) {
        const char* src = cameraObjList[i]->GetID().c_str();
        size_t dstSize = strlen(src) + 1;
        char* dst = new char[dstSize];
        if (!dst) {
            MEDIA_ERR_LOG("Allocate memory for cameraId failed!");
            return CAMERA_SERVICE_FATAL_ERROR;
        }
        strlcpy(dst, src, dstSize);
        outCameras[i].cameraId = dst;
        outCameras[i].cameraPosition = static_cast<Camera_Position>(cameraObjList[i]->GetPosition());
        outCameras[i].cameraType = static_cast<Camera_Type>(cameraObjList[i]->GetCameraType());
        outCameras[i].connectionType = static_cast<Camera_Connection>(cameraObjList[i]->GetConnectionType());
    }
    *size = cameraSize;
    *cameras = outCameras;
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::DeleteSupportedCameras(Camera_Device* cameras, uint32_t size)
{
    if (cameras != nullptr) {
        for (int i = 0; i < size; i++) {
            if (&cameras[i] != nullptr) {
                delete[] cameras[i].cameraId;
            }
        }
        delete[] cameras;
    }
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::GetSupportedCameraOutputCapability(const Camera_Device* camera,
    Camera_OutputCapability** cameraOutputCapability)
{
    Camera_OutputCapability* outCapability = new Camera_OutputCapability;
    if (!outCapability) {
        MEDIA_ERR_LOG("Failed to allocate memory for Camera_OutputCapability！");
    }
    sptr<CameraDevice> cameraDevice = nullptr;
    std::vector<sptr<CameraDevice>> cameraObjList = CameraManager::GetInstance()->GetSupportedCameras();
        MEDIA_ERR_LOG("GetSupportedCameraOutputCapability cameraInfo is null, the cameraObjList size is %{public}zu",
            cameraObjList.size());
        for (size_t i = 0; i < cameraObjList.size(); i++) {
            MEDIA_ERR_LOG("GetSupportedCameraOutputCapability for");
            sptr<CameraDevice> innerCameraDevice = cameraObjList[i];
            if (innerCameraDevice == nullptr) {
                MEDIA_ERR_LOG("GetSupportedCameraOutputCapability innerCameraDevice == null");
                continue;
            }
            if (innerCameraDevice->GetPosition() == static_cast<CameraPosition>(camera->cameraPosition) &&
                innerCameraDevice->GetCameraType() == static_cast<CameraType>(camera->cameraType)) {
                MEDIA_ERR_LOG("GetSupportedCameraOutputCapability position:%{public}d, type:%{public}d ",
                    innerCameraDevice->GetPosition(), innerCameraDevice->GetCameraType());
                cameraDevice = innerCameraDevice;

                break;
            }
        }
    MEDIA_ERR_LOG("GetSupportedCameraOutputCapability  test");
    sptr<CameraOutputCapability> innerCameraOutputCapability =
        CameraManager::GetInstance()->GetSupportedOutputCapability(cameraDevice);
    if (innerCameraOutputCapability == nullptr) {
        MEDIA_ERR_LOG("GetSupportedCameraOutputCapability innerCameraOutputCapability == null");
    }
    MEDIA_ERR_LOG("GetSupportedCameraOutputCapability innerCameraOutputCapability !- null");
    std::vector<Profile> previewProfiles = innerCameraOutputCapability->GetPreviewProfiles();
    std::vector<Profile> photoProfiles = innerCameraOutputCapability->GetPhotoProfiles();
    std::vector<VideoProfile> videoProfiles = innerCameraOutputCapability->GetVideoProfiles();

    std::vector<MetadataObjectType> metadataTypeList = innerCameraOutputCapability->GetSupportedMetadataObjectType();

    GetSupportedPreviewProfiles(outCapability, previewProfiles);
    GetSupportedPhotoProfiles(outCapability, photoProfiles);
    GetSupportedVideoProfiles(outCapability, videoProfiles);
    GetSupportedMetadataTypeList(outCapability, metadataTypeList);

    *cameraOutputCapability = outCapability;
    MEDIA_ERR_LOG("GetSupportedCameraOutputCapability previewOutputSize return");
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::GetSupportedPreviewProfiles(Camera_OutputCapability* outCapability,
    std::vector<Profile> &previewProfiles)
{
    int previewOutputSize = previewProfiles.size();
    outCapability->previewProfilesSize = previewOutputSize;
    if (previewOutputSize <= 0) {
        MEDIA_ERR_LOG("alloc size <= 0");
        outCapability->previewProfiles = nullptr;
        return CAMERA_INVALID_ARGUMENT;
    }
    outCapability->previewProfiles = new Camera_Profile* [previewOutputSize];
    if (!outCapability->previewProfiles) {
        MEDIA_ERR_LOG("Failed to allocate memory for previewProfiles");
    }
    for (int i = 0; i < previewOutputSize; i++) {
        Camera_Profile* outPreviewProfile = new Camera_Profile;
        if (!outPreviewProfile) {
            MEDIA_ERR_LOG("Failed to allocate memory for outPreviewProfile");
        }
        outPreviewProfile->format = static_cast<Camera_Format>(previewProfiles[i].GetCameraFormat());
        outPreviewProfile->size.width = previewProfiles[i].GetSize().width;
        outPreviewProfile->size.height = previewProfiles[i].GetSize().height;
        outCapability->previewProfiles[i] = outPreviewProfile;
        MEDIA_ERR_LOG("GetSupportedCameraOutputCapability previewOutputSize enter");
    }
    MEDIA_ERR_LOG("GetSupportedCameraOutputCapability previewOutputSize exit");
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::GetSupportedPhotoProfiles(Camera_OutputCapability* outCapability,
    std::vector<Profile> &photoProfiles)
{
    int photoOutputSize = photoProfiles.size();
    outCapability->photoProfilesSize = photoOutputSize;
    if (photoOutputSize <= 0) {
        MEDIA_ERR_LOG("alloc size <= 0");
        outCapability->photoProfiles = nullptr;
        return CAMERA_INVALID_ARGUMENT;
    }
    outCapability->photoProfiles = new Camera_Profile* [photoOutputSize];
    if (!outCapability->photoProfiles) {
        MEDIA_ERR_LOG("Failed to allocate memory for photoProfiles");
    }
    for (int i = 0; i < photoOutputSize; i++) {
        Camera_Profile* outPhotoProfile = new Camera_Profile;
        if (!outPhotoProfile) {
            MEDIA_ERR_LOG("Failed to allocate memory for outPhotoProfile");
        }
        outPhotoProfile->format = static_cast<Camera_Format>(photoProfiles[i].GetCameraFormat());
        outPhotoProfile->size.width = photoProfiles[i].GetSize().width;
        outPhotoProfile->size.height = photoProfiles[i].GetSize().height;
        outCapability->photoProfiles[i] = outPhotoProfile;
    }
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::GetSupportedVideoProfiles(Camera_OutputCapability* outCapability,
    std::vector<VideoProfile> &videoProfiles)
{
    int videoOutputSize = videoProfiles.size();
    outCapability->videoProfilesSize = videoOutputSize;
    if (videoOutputSize <= 0) {
        MEDIA_ERR_LOG("alloc size <= 0");
        outCapability->videoProfiles = nullptr;
        return CAMERA_INVALID_ARGUMENT;
    }
    outCapability->videoProfiles = new Camera_VideoProfile* [videoOutputSize];
    if (!outCapability->videoProfiles) {
        MEDIA_ERR_LOG("Failed to allocate memory for videoProfiles");
    }
    for (int i = 0; i < videoOutputSize; i++) {
        Camera_VideoProfile* outVideoProfile = new Camera_VideoProfile;
        if (!outVideoProfile) {
            MEDIA_ERR_LOG("Failed to allocate memory for outVideoProfile");
        }
        outVideoProfile->format = static_cast<Camera_Format>(videoProfiles[i].GetCameraFormat());
        outVideoProfile->size.width = videoProfiles[i].GetSize().width;
        outVideoProfile->size.height = videoProfiles[i].GetSize().height;
        outVideoProfile->range.min  = videoProfiles[i].framerates_[0];
        outVideoProfile->range.max  = videoProfiles[i].framerates_[1];
        outCapability->videoProfiles[i] = outVideoProfile;
    }
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::GetSupportedMetadataTypeList(Camera_OutputCapability* outCapability,
    std::vector<MetadataObjectType> &metadataTypeList)
{
    int metadataOutputSize = metadataTypeList.size();
    outCapability->metadataProfilesSize = metadataOutputSize;
    if (metadataOutputSize <= 0) {
        MEDIA_ERR_LOG("alloc size <= 0");
        outCapability->supportedMetadataObjectTypes = nullptr;
        return CAMERA_INVALID_ARGUMENT;
    }
    outCapability->supportedMetadataObjectTypes = new Camera_MetadataObjectType* [metadataOutputSize];
    if (!outCapability->supportedMetadataObjectTypes) {
        MEDIA_ERR_LOG("Failed to allocate memory for supportedMetadataObjectTypes");
    }
    for (int i = 0; i < metadataOutputSize; i++) {
        Camera_MetadataObjectType outmetadataObject = static_cast<Camera_MetadataObjectType>(metadataTypeList[i]);
        outCapability->supportedMetadataObjectTypes[i] = &outmetadataObject;
    }
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::DeleteSupportedCameraOutputCapability(Camera_OutputCapability* cameraOutputCapability)
{
    if (cameraOutputCapability != nullptr) {
        if (cameraOutputCapability->previewProfiles != nullptr) {
            for (int i = 0; i < cameraOutputCapability->previewProfilesSize; i++) {
                if (cameraOutputCapability->previewProfiles[i] != nullptr) {
                    delete cameraOutputCapability->previewProfiles[i];
                }
            }
            delete[] cameraOutputCapability->previewProfiles;
        }

        if (cameraOutputCapability->photoProfiles != nullptr) {
            for (int i = 0; i < cameraOutputCapability->photoProfilesSize; i++) {
                if (cameraOutputCapability->photoProfiles[i] != nullptr) {
                    delete cameraOutputCapability->photoProfiles[i];
                }
            }
            delete[] cameraOutputCapability->photoProfiles;
        }

        if (cameraOutputCapability->videoProfiles != nullptr) {
            for (int i = 0; i < cameraOutputCapability->videoProfilesSize; i++) {
                if (cameraOutputCapability->videoProfiles[i] != nullptr) {
                    delete cameraOutputCapability->videoProfiles[i];
                }
            }
            delete[] cameraOutputCapability->videoProfiles;
        }

        if (cameraOutputCapability->supportedMetadataObjectTypes != nullptr) {
            delete[] cameraOutputCapability->supportedMetadataObjectTypes;
        }

        delete cameraOutputCapability;
    }
    return CAMERA_OK;
}
Camera_ErrorCode Camera_Manager::IsCameraMuted(bool* isCameraMuted)
{
    MEDIA_ERR_LOG("Camera_Manager IsCameraMuted is called");
    *isCameraMuted = CameraManager::GetInstance()->IsCameraMuted();
    MEDIA_ERR_LOG("IsCameraMuted is %{public}d", *isCameraMuted);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::CreateCaptureSession(Camera_CaptureSession** captureSession)
{
    sptr<CaptureSession> innerCaptureSession = nullptr;
    int retCode = CameraManager::GetInstance()->CreateCaptureSession(&innerCaptureSession);
    if (retCode != CameraErrorCode::SUCCESS) {
        return CAMERA_SERVICE_FATAL_ERROR;
    }
    Camera_CaptureSession* outSession = new Camera_CaptureSession(innerCaptureSession);
    *captureSession = outSession;
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::CreateCameraInput(const Camera_Device* camera, Camera_Input** cameraInput)
{
    sptr<CameraDevice> cameraDevice = nullptr;
    std::vector<sptr<CameraDevice>> cameraObjList = CameraManager::GetInstance()->GetSupportedCameras();
        MEDIA_DEBUG_LOG("cameraInfo is null, the cameraObjList size is %{public}zu",
            cameraObjList.size());
        for (size_t i = 0; i < cameraObjList.size(); i++) {
            sptr<CameraDevice> innerCameraDevice = cameraObjList[i];
            if (innerCameraDevice == nullptr) {
                continue;
            }
            if (innerCameraDevice->GetPosition() == static_cast<CameraPosition>(camera->cameraPosition) &&
                innerCameraDevice->GetCameraType() == static_cast<CameraType>(camera->cameraType)) {
                cameraDevice = innerCameraDevice;
                break;
            }
        }

    sptr<CameraInput> innerCameraInput = nullptr;
    int retCode = CameraManager::GetInstance()->CreateCameraInput(cameraDevice, &innerCameraInput);
    if (retCode != CameraErrorCode::SUCCESS) {
        return CAMERA_SERVICE_FATAL_ERROR;
    }
    Camera_Input* outInput = new Camera_Input(innerCameraInput);
    *cameraInput = outInput;
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::CreateCameraInputWithPositionAndType(Camera_Position position, Camera_Type type,
    Camera_Input** cameraInput)
{
    MEDIA_ERR_LOG("Camera_Manager CreateCameraInputWithPositionAndType is called");
    sptr<CameraInput> innerCameraInput = nullptr;
    CameraPosition innerPosition = static_cast<CameraPosition>(position);
    CameraType innerType = static_cast<CameraType>(type);

    innerCameraInput = CameraManager::GetInstance()->CreateCameraInput(innerPosition, innerType);
    if (innerCameraInput == nullptr) {
        MEDIA_ERR_LOG("failed to CreateCameraInputWithPositionAndType");
    }

    Camera_Input* outInput = new Camera_Input(innerCameraInput);
    *cameraInput = outInput;
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::CreatePreviewOutput(const Camera_Profile* profile,
    const char* surfaceId, Camera_PreviewOutput** previewOutput)
{
    sptr<PreviewOutput> innerPreviewOutput = nullptr;
    Size size;
    size.width = profile->size.width;
    size.height = profile->size.height;
    Profile innerProfile(static_cast<CameraFormat>(profile->format), size);

    uint64_t iSurfaceId;
    std::istringstream iss(surfaceId);
    iss >> iSurfaceId;
    sptr<Surface> surface = SurfaceUtils::GetInstance()->GetSurface(iSurfaceId);
    if (!surface) {
        surface = Media::ImageReceiver::getSurfaceById(surfaceId);
    }
    if (surface == nullptr) {
        MEDIA_ERR_LOG("failed to get previewOutput surface");
    }

    surface->SetUserData(CameraManager::surfaceFormat, std::to_string(innerProfile.GetCameraFormat()));
    int retCode = CameraManager::GetInstance()->CreatePreviewOutput(innerProfile, surface, &innerPreviewOutput);
    if (retCode != CameraErrorCode::SUCCESS) {
        return CAMERA_SERVICE_FATAL_ERROR;
    }
    Camera_PreviewOutput* out = new Camera_PreviewOutput(innerPreviewOutput);
    *previewOutput = out;
    MEDIA_ERR_LOG("Camera_Manager::CreatePreviewOutput");
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::CreatePhotoOutput(const Camera_Profile* profile,
    const char* surfaceId, Camera_PhotoOutput** photoOutput)
{
    MEDIA_ERR_LOG("Camera_Manager CreatePhotoOutput is called");
    sptr<PhotoOutput> innerPhotoOutput = nullptr;
    Size size;
    size.width = profile->size.width;
    size.height = profile->size.height;
    Profile innerProfile(static_cast<CameraFormat>(profile->format), size);

    sptr<Surface> surface = Media::ImageReceiver::getSurfaceById(surfaceId);
    if (surface == nullptr) {
        MEDIA_ERR_LOG("failed to get photoOutput surface");
    }

    surface->SetUserData(CameraManager::surfaceFormat, std::to_string(innerProfile.GetCameraFormat()));
    sptr<IBufferProducer> surfaceProducer = surface->GetProducer();
    int retCode = CameraManager::GetInstance()->CreatePhotoOutput(innerProfile, surfaceProducer, &innerPhotoOutput);
    if (retCode != CameraErrorCode::SUCCESS) {
        return CAMERA_SERVICE_FATAL_ERROR;
    }
    Camera_PhotoOutput* out = new Camera_PhotoOutput(innerPhotoOutput);
    *photoOutput = out;
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::CreateVideoOutput(const Camera_VideoProfile* profile,
    const char* surfaceId, Camera_VideoOutput** videoOutput)
{
    sptr<VideoOutput> innerVideoOutput = nullptr;
    Size size;
    size.width = profile->size.width;
    size.height = profile->size.height;
    std::vector<int32_t> framerates = {profile->range.min, profile->range.max};
    VideoProfile innerProfile(static_cast<CameraFormat>(profile->format), size, framerates);

    uint64_t iSurfaceId;
    std::istringstream iss(surfaceId);
    iss >> iSurfaceId;
    sptr<Surface> surface = SurfaceUtils::GetInstance()->GetSurface(iSurfaceId);
    if (!surface) {
        surface = Media::ImageReceiver::getSurfaceById(surfaceId);
    }
    if (surface == nullptr) {
        MEDIA_ERR_LOG("failed to get videoOutput surface");
    }

    surface->SetUserData(CameraManager::surfaceFormat, std::to_string(innerProfile.GetCameraFormat()));
    int retCode = CameraManager::GetInstance()->CreateVideoOutput(innerProfile, surface, &innerVideoOutput);
    if (retCode != CameraErrorCode::SUCCESS) {
        return CAMERA_SERVICE_FATAL_ERROR;
    }
    Camera_VideoOutput* out = new Camera_VideoOutput(innerVideoOutput);
    *videoOutput = out;
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::CreateMetadataOutput(const Camera_MetadataObjectType* type,
    Camera_MetadataOutput** metadataOutput)
{
    MEDIA_ERR_LOG("Camera_Manager CreateMetadataOutput is called");
    sptr<MetadataOutput> innerMetadataOutput = nullptr;

    int retCode = CameraManager::GetInstance()->CreateMetadataOutput(&innerMetadataOutput);
    if (retCode != CameraErrorCode::SUCCESS) {
        return CAMERA_SERVICE_FATAL_ERROR;
    }
    Camera_MetadataOutput* out = new Camera_MetadataOutput(innerMetadataOutput);
    *metadataOutput = out;
    return CAMERA_OK;
}