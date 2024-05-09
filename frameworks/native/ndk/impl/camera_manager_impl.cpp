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
    uint32_t cameraSize = cameraObjList.size();
    uint32_t cameraMaxSize = 32;
    if (cameraSize == 0 || cameraSize > cameraMaxSize) {
        MEDIA_ERR_LOG("Invalid camera size.");
        return CAMERA_INVALID_ARGUMENT;
    }
    Camera_Device* outCameras = new Camera_Device[cameraSize];
    for (size_t index = 0; index < cameraSize; index++) {
        const string cameraGetID = cameraObjList[index]->GetID();
        const char* src = cameraGetID.c_str();
        size_t dstSize = strlen(src) + 1;
        char* dst = new char[dstSize];
        if (!dst) {
            MEDIA_ERR_LOG("Allocate memory for cameraId Failed!");
            delete[] outCameras;
            return CAMERA_SERVICE_FATAL_ERROR;
        }
        strlcpy(dst, src, dstSize);
        outCameras[index].cameraId = dst;
        outCameras[index].cameraPosition = static_cast<Camera_Position>(cameraObjList[index]->GetPosition());
        outCameras[index].cameraType = static_cast<Camera_Type>(cameraObjList[index]->GetCameraType());
        outCameras[index].connectionType = static_cast<Camera_Connection>(cameraObjList[index]->GetConnectionType());
    }
    *size = cameraSize;
    *cameras = outCameras;
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::DeleteSupportedCameras(Camera_Device* cameras, uint32_t size)
{
    if (cameras != nullptr) {
        for (size_t index = 0; index < size; index++) {
            if (&cameras[index] != nullptr) {
                delete[] cameras[index].cameraId;
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
        return CAMERA_SERVICE_FATAL_ERROR;
    }
    sptr<CameraDevice> cameraDevice = nullptr;
    std::vector<sptr<CameraDevice>> cameraObjList = CameraManager::GetInstance()->GetSupportedCameras();
        MEDIA_ERR_LOG("GetSupportedCameraOutputCapability cameraInfo is null, the cameraObjList size is %{public}zu",
            cameraObjList.size());
        for (size_t index = 0; index < cameraObjList.size(); index++) {
            MEDIA_ERR_LOG("GetSupportedCameraOutputCapability for");
            sptr<CameraDevice> innerCameraDevice = cameraObjList[index];
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
    sptr<CameraOutputCapability> innerCameraOutputCapability =
        CameraManager::GetInstance()->GetSupportedOutputCapability(cameraDevice);
    if (innerCameraOutputCapability == nullptr) {
        MEDIA_ERR_LOG("GetSupportedCameraOutputCapability innerCameraOutputCapability is null");
        delete outCapability;
        return CAMERA_INVALID_ARGUMENT;
    }
    std::vector<Profile> previewProfiles = innerCameraOutputCapability->GetPreviewProfiles();
    std::vector<Profile> photoProfiles = innerCameraOutputCapability->GetPhotoProfiles();
    std::vector<VideoProfile> videoProfiles = innerCameraOutputCapability->GetVideoProfiles();

    std::vector<MetadataObjectType> metadataTypeList = innerCameraOutputCapability->GetSupportedMetadataObjectType();

    GetSupportedPreviewProfiles(outCapability, previewProfiles);
    GetSupportedPhotoProfiles(outCapability, photoProfiles);
    GetSupportedVideoProfiles(outCapability, videoProfiles);
    GetSupportedMetadataTypeList(outCapability, metadataTypeList);

    *cameraOutputCapability = outCapability;
    MEDIA_INFO_LOG("GetSupportedCameraOutputCapability success.");
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::GetSupportedPreviewProfiles(Camera_OutputCapability* outCapability,
    std::vector<Profile> &previewProfiles)
{
    if (previewProfiles.size() == 0) {
        MEDIA_ERR_LOG("Invalid preview profiles size.");
        outCapability->previewProfiles = nullptr;
        return CAMERA_INVALID_ARGUMENT;
    }
    outCapability->previewProfilesSize = previewProfiles.size();
    outCapability->previewProfiles = new Camera_Profile* [previewProfiles.size()];
    if (!outCapability->previewProfiles) {
        MEDIA_ERR_LOG("Failed to allocate memory for preview profiles");
    }
    MEDIA_DEBUG_LOG("GetSupportedCameraOutputCapability previewOutput size enter");
    for (size_t index = 0; index < previewProfiles.size(); index++) {
        Camera_Profile* outPreviewProfile = new Camera_Profile;
        if (!outPreviewProfile) {
            MEDIA_ERR_LOG("Failed to allocate memory for PreviewProfile");
        }
        outPreviewProfile->format = static_cast<Camera_Format>(previewProfiles[index].GetCameraFormat());
        outPreviewProfile->size.width = previewProfiles[index].GetSize().width;
        outPreviewProfile->size.height = previewProfiles[index].GetSize().height;
        outCapability->previewProfiles[index] = outPreviewProfile;
    }
    MEDIA_DEBUG_LOG("GetSupportedCameraOutputCapability previewOutput size exit");
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::GetSupportedPhotoProfiles(Camera_OutputCapability* outCapability,
    std::vector<Profile> &photoProfiles)
{
    if (photoProfiles.size() == 0) {
        MEDIA_ERR_LOG("Invalid photo profiles size.");
        outCapability->photoProfiles = nullptr;
        return CAMERA_INVALID_ARGUMENT;
    }
    outCapability->photoProfilesSize = photoProfiles.size();
    outCapability->photoProfiles = new Camera_Profile* [photoProfiles.size()];
    if (!outCapability->photoProfiles) {
        MEDIA_ERR_LOG("Failed to allocate memory for photo profiles");
    }
    for (size_t index = 0; index < photoProfiles.size(); index++) {
        Camera_Profile* outPhotoProfile = new Camera_Profile;
        if (!outPhotoProfile) {
            MEDIA_ERR_LOG("Failed to allocate memory for PhotoProfile");
        }
        outPhotoProfile->format = static_cast<Camera_Format>(photoProfiles[index].GetCameraFormat());
        outPhotoProfile->size.width = photoProfiles[index].GetSize().width;
        outPhotoProfile->size.height = photoProfiles[index].GetSize().height;
        outCapability->photoProfiles[index] = outPhotoProfile;
    }
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::GetSupportedVideoProfiles(Camera_OutputCapability* outCapability,
    std::vector<VideoProfile> &videoProfiles)
{
    if (videoProfiles.size() == 0) {
        MEDIA_ERR_LOG("Invalid video profiles size.");
        outCapability->videoProfiles = nullptr;
        return CAMERA_INVALID_ARGUMENT;
    }
    outCapability->videoProfilesSize = videoProfiles.size();
    outCapability->videoProfiles = new Camera_VideoProfile* [videoProfiles.size()];
    if (!outCapability->videoProfiles) {
        MEDIA_ERR_LOG("Failed to allocate memory for video profiles");
    }
    for (size_t index = 0; index < videoProfiles.size(); index++) {
        Camera_VideoProfile* outVideoProfile = new Camera_VideoProfile;
        if (!outVideoProfile) {
            MEDIA_ERR_LOG("Failed to allocate memory for VideoProfile");
        }
        outVideoProfile->format = static_cast<Camera_Format>(videoProfiles[index].GetCameraFormat());
        outVideoProfile->size.width = videoProfiles[index].GetSize().width;
        outVideoProfile->size.height = videoProfiles[index].GetSize().height;
        outVideoProfile->range.min  = static_cast<uint32_t>(videoProfiles[index].framerates_[0]);
        outVideoProfile->range.max  = static_cast<uint32_t>(videoProfiles[index].framerates_[1]);
        outCapability->videoProfiles[index] = outVideoProfile;
    }
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::GetSupportedMetadataTypeList(Camera_OutputCapability* outCapability,
    std::vector<MetadataObjectType> &metadataTypeList)
{
    if (metadataTypeList.size() == 0) {
        MEDIA_ERR_LOG("Invalid metadata type size.");
        outCapability->supportedMetadataObjectTypes = nullptr;
        return CAMERA_INVALID_ARGUMENT;
    }
    outCapability->metadataProfilesSize = metadataTypeList.size();
    outCapability->supportedMetadataObjectTypes = new Camera_MetadataObjectType* [metadataTypeList.size()];
    if (!outCapability->supportedMetadataObjectTypes) {
        MEDIA_ERR_LOG("Failed to allocate memory for supportedMetadataObjectTypes");
    }
    for (size_t index = 0; index < metadataTypeList.size(); index++) {
        Camera_MetadataObjectType outmetadataObject = static_cast<Camera_MetadataObjectType>(metadataTypeList[index]);
        outCapability->supportedMetadataObjectTypes[index] = &outmetadataObject;
    }
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::DeleteSupportedCameraOutputCapability(Camera_OutputCapability* cameraOutputCapability)
{
    if (cameraOutputCapability != nullptr) {
        if (cameraOutputCapability->previewProfiles != nullptr) {
            for (size_t index = 0; index < cameraOutputCapability->previewProfilesSize; index++) {
                if (cameraOutputCapability->previewProfiles[index] != nullptr) {
                    delete cameraOutputCapability->previewProfiles[index];
                }
            }
            delete[] cameraOutputCapability->previewProfiles;
        }

        if (cameraOutputCapability->photoProfiles != nullptr) {
            for (size_t index = 0; index < cameraOutputCapability->photoProfilesSize; index++) {
                if (cameraOutputCapability->photoProfiles[index] != nullptr) {
                    delete cameraOutputCapability->photoProfiles[index];
                }
            }
            delete[] cameraOutputCapability->photoProfiles;
        }

        if (cameraOutputCapability->videoProfiles != nullptr) {
            for (size_t index = 0; index < cameraOutputCapability->videoProfilesSize; index++) {
                if (cameraOutputCapability->videoProfiles[index] != nullptr) {
                    delete cameraOutputCapability->videoProfiles[index];
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
    int32_t retCode = CameraManager::GetInstance()->CreateCaptureSession(&innerCaptureSession);
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
        for (size_t index = 0; index < cameraObjList.size(); index++) {
            sptr<CameraDevice> innerCameraDevice = cameraObjList[index];
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
    int32_t retCode = CameraManager::GetInstance()->CreateCameraInput(cameraDevice, &innerCameraInput);
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
        MEDIA_ERR_LOG("Failed to CreateCameraInputWithPositionAndType");
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
        MEDIA_ERR_LOG("Failed to get previewOutput surface");
        return CAMERA_INVALID_ARGUMENT;
    }

    surface->SetUserData(CameraManager::surfaceFormat, std::to_string(innerProfile.GetCameraFormat()));
    int32_t retCode = CameraManager::GetInstance()->CreatePreviewOutput(innerProfile, surface, &innerPreviewOutput);
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
        MEDIA_ERR_LOG("Failed to get photoOutput surface");
        return CAMERA_INVALID_ARGUMENT;
    }

    surface->SetUserData(CameraManager::surfaceFormat, std::to_string(innerProfile.GetCameraFormat()));
    sptr<IBufferProducer> surfaceProducer = surface->GetProducer();
    int32_t retCode = CameraManager::GetInstance()->CreatePhotoOutput(innerProfile, surfaceProducer, &innerPhotoOutput);
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
        MEDIA_ERR_LOG("Failed to get videoOutput surface");
        return CAMERA_INVALID_ARGUMENT;
    }

    surface->SetUserData(CameraManager::surfaceFormat, std::to_string(innerProfile.GetCameraFormat()));
    int32_t retCode = CameraManager::GetInstance()->CreateVideoOutput(innerProfile, surface, &innerVideoOutput);
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

    int32_t retCode = CameraManager::GetInstance()->CreateMetadataOutput(&innerMetadataOutput);
    if (retCode != CameraErrorCode::SUCCESS) {
        return CAMERA_SERVICE_FATAL_ERROR;
    }
    Camera_MetadataOutput* out = new Camera_MetadataOutput(innerMetadataOutput);
    *metadataOutput = out;
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::GetCameraOrientation(Camera_Device* camera, uint32_t* orientation)
{
    sptr<CameraDevice> cameraDevice = nullptr;
    std::vector<sptr<CameraDevice>> cameraObjList = CameraManager::GetInstance()->GetSupportedCameras();
    MEDIA_DEBUG_LOG("the cameraObjList size is %{public}zu",
        cameraObjList.size());
    for (size_t index = 0; index < cameraObjList.size(); index++) {
        sptr<CameraDevice> innerCameraDevice = cameraObjList[index];
        if (innerCameraDevice == nullptr) {
            continue;
        }
        if (innerCameraDevice->GetPosition() == static_cast<CameraPosition>(camera->cameraPosition) &&
            innerCameraDevice->GetCameraType() == static_cast<CameraType>(camera->cameraType) &&
            innerCameraDevice->GetID() == camera->cameraId) {
            cameraDevice = innerCameraDevice;
            break;
        }
    }

    if (cameraDevice == nullptr) {
        return CAMERA_SERVICE_FATAL_ERROR;
    } else {
        *orientation = cameraDevice->GetCameraOrientation();
        return CAMERA_OK;
    }
}