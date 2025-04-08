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

#include <unistd.h>

#include "camera_device.h"
#include "camera_log.h"
#include "camera_util.h"
#include "image_receiver.h"
#include "securec.h"
#include "surface_utils.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::CameraStandard;
const char* DEFAULT_SURFACEID = "photoOutput";
thread_local OHOS::sptr<OHOS::Surface> Camera_Manager::photoSurface_ = nullptr;
NDKCallbackMap<CameraManager_Callbacks*, OHOS::CameraStandard::InnerCameraManagerCameraStatusCallback>
    Camera_Manager::cameraStatusCallbackMap_;

NDKCallbackMap<OH_CameraManager_OnFoldStatusInfoChange, OHOS::CameraStandard::InnerCameraManagerFoldStatusCallback>
    Camera_Manager::cameraFoldStatusCallbackMap_;

NDKCallbackMap<OH_CameraManager_TorchStatusCallback, OHOS::CameraStandard::InnerCameraManagerTorchStatusCallback>
    Camera_Manager::torchStatusCallbackMap_;

const std::unordered_map<SceneMode, Camera_SceneMode> g_fwModeToNdk_ = {
    {SceneMode::CAPTURE, Camera_SceneMode::NORMAL_PHOTO},
    {SceneMode::VIDEO, Camera_SceneMode::NORMAL_VIDEO},
    {SceneMode::SECURE, Camera_SceneMode::SECURE_PHOTO},
};
const std::unordered_map<Camera_SceneMode, SceneMode> g_ndkToFwMode_ = {
    {Camera_SceneMode::NORMAL_PHOTO, SceneMode::CAPTURE},
    {Camera_SceneMode::NORMAL_VIDEO, SceneMode::VIDEO},
    {Camera_SceneMode::SECURE_PHOTO, SceneMode::SECURE},
};
const std::unordered_map<CameraPosition, Camera_Position> g_FwkCameraPositionToNdk_ = {
    {CameraPosition::CAMERA_POSITION_UNSPECIFIED, Camera_Position::CAMERA_POSITION_UNSPECIFIED},
    {CameraPosition::CAMERA_POSITION_BACK, Camera_Position::CAMERA_POSITION_BACK},
    {CameraPosition::CAMERA_POSITION_FRONT, Camera_Position::CAMERA_POSITION_FRONT},
};
const std::unordered_map<Camera_Position, CameraPosition> g_NdkCameraPositionToFwk_ = {
    {Camera_Position::CAMERA_POSITION_UNSPECIFIED, CameraPosition::CAMERA_POSITION_UNSPECIFIED},
    {Camera_Position::CAMERA_POSITION_BACK, CameraPosition::CAMERA_POSITION_BACK},
    {Camera_Position::CAMERA_POSITION_FRONT, CameraPosition::CAMERA_POSITION_FRONT},
};
const std::unordered_map<Camera_TorchMode, TorchMode> g_ndkToFwTorchMode_ = {
    {Camera_TorchMode::OFF, TorchMode::TORCH_MODE_OFF},
    {Camera_TorchMode::ON, TorchMode::TORCH_MODE_ON},
    {Camera_TorchMode::AUTO, TorchMode::TORCH_MODE_AUTO}
};

namespace OHOS::CameraStandard {
class InnerCameraManagerCameraStatusCallback : public CameraManagerCallback {
public:
    InnerCameraManagerCameraStatusCallback(Camera_Manager* cameraManager, CameraManager_Callbacks* callback)
        : cameraManager_(cameraManager), callback_(*callback)
    {}
    ~InnerCameraManagerCameraStatusCallback() {}

    void OnCameraStatusChanged(const CameraStatusInfo& cameraStatusInfo) const override
    {
        MEDIA_DEBUG_LOG("OnCameraStatusChanged is called!");
        Camera_StatusInfo statusInfo;
        Camera_Device cameraDevice;
        statusInfo.camera = &cameraDevice;
        string cameraId = cameraStatusInfo.cameraDevice->GetID();
        statusInfo.camera->cameraId = cameraId.data();
        MEDIA_INFO_LOG("cameraId is %{public}s", statusInfo.camera->cameraId);
        statusInfo.camera->cameraPosition = static_cast<Camera_Position>(cameraStatusInfo.cameraDevice->GetPosition());
        statusInfo.camera->cameraType = static_cast<Camera_Type>(cameraStatusInfo.cameraDevice->GetCameraType());
        statusInfo.camera->connectionType =
            static_cast<Camera_Connection>(cameraStatusInfo.cameraDevice->GetConnectionType());
        statusInfo.status = static_cast<Camera_Status>(cameraStatusInfo.cameraStatus);
        CHECK_EXECUTE(cameraManager_ != nullptr && callback_.onCameraStatus != nullptr,
            callback_.onCameraStatus(cameraManager_, &statusInfo));
    }

    void OnFlashlightStatusChanged(const std::string& cameraID, const FlashStatus flashStatus) const override
    {
        MEDIA_DEBUG_LOG("OnFlashlightStatusChanged is called!");
        (void)cameraID;
        (void)flashStatus;
    }

private:
    Camera_Manager* cameraManager_;
    CameraManager_Callbacks callback_;
};

class InnerCameraManagerTorchStatusCallback : public TorchListener {
public:
    InnerCameraManagerTorchStatusCallback(
        Camera_Manager* cameraManager, OH_CameraManager_TorchStatusCallback torchStatusCallback)
        : cameraManager_(cameraManager), torchStatusCallback_(torchStatusCallback) {};
    ~InnerCameraManagerTorchStatusCallback() = default;

    void OnTorchStatusChange(const TorchStatusInfo& torchStatusInfo) const override
    {
        MEDIA_DEBUG_LOG("OnTorchStatusChange is called!");
        if (cameraManager_ != nullptr && torchStatusCallback_ != nullptr) {
            Camera_TorchStatusInfo statusInfo;
            statusInfo.isTorchAvailable = torchStatusInfo.isTorchAvailable;
            statusInfo.isTorchActive = torchStatusInfo.isTorchActive;
            statusInfo.torchLevel = torchStatusInfo.torchLevel;
            torchStatusCallback_(cameraManager_, &statusInfo);
        }
    }

private:
    Camera_Manager* cameraManager_;
    OH_CameraManager_TorchStatusCallback torchStatusCallback_ = nullptr;
};

class InnerCameraManagerFoldStatusCallback : public FoldListener {
public:
    InnerCameraManagerFoldStatusCallback(
        Camera_Manager* cameraManager, OH_CameraManager_OnFoldStatusInfoChange foldStatusCallback)
        : cameraManager_(cameraManager), foldStatusCallback_(foldStatusCallback) {};
    ~InnerCameraManagerFoldStatusCallback() = default;

    void OnFoldStatusChanged(const FoldStatusInfo& foldStatusInfo) const override
    {
        MEDIA_DEBUG_LOG("OnFoldStatusChanged is called!");
        if (cameraManager_ != nullptr && (foldStatusCallback_ != nullptr)) {
            Camera_FoldStatusInfo statusInfo;
            auto cameraSize = foldStatusInfo.supportedCameras.size();
            CHECK_ERROR_RETURN_LOG(cameraSize <= 0, "Invalid size.");
            Camera_Device supportedCameras[cameraSize];
            Camera_Device* supportedCamerasPtr[cameraSize];
            uint32_t outSize = 0;
            string cameraIds[cameraSize];
            for (size_t index = 0; index < cameraSize; index++) {
                Camera_Device* cameraDevice = &supportedCameras[outSize];
                cameraDevice->cameraPosition =
                    static_cast<Camera_Position>(foldStatusInfo.supportedCameras[index]->GetPosition());
                cameraIds[outSize] = foldStatusInfo.supportedCameras[index]->GetID();
                cameraDevice->cameraId = cameraIds[outSize].data();
                cameraDevice->cameraType =
                    static_cast<Camera_Type>(foldStatusInfo.supportedCameras[index]->GetCameraType());
                cameraDevice->connectionType =
                    static_cast<Camera_Connection>(foldStatusInfo.supportedCameras[index]->GetConnectionType());
                supportedCamerasPtr[outSize] = cameraDevice;
                outSize++;
            }
            statusInfo.supportedCameras = supportedCamerasPtr;
            statusInfo.cameraSize = outSize;
            statusInfo.foldStatus = (Camera_FoldStatus)foldStatusInfo.foldStatus;
            foldStatusCallback_(cameraManager_, &statusInfo);
        }
    }

private:
    Camera_Manager* cameraManager_;
    OH_CameraManager_OnFoldStatusInfoChange foldStatusCallback_ = nullptr;
};
} // namespace OHOS::CameraStandard

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

Camera_ErrorCode Camera_Manager::RegisterCallback(CameraManager_Callbacks* cameraStatusCallback)
{
    auto innerCallback = make_shared<InnerCameraManagerCameraStatusCallback>(this, cameraStatusCallback);
    if (cameraStatusCallbackMap_.SetMapValue(cameraStatusCallback, innerCallback)) {
        cameraManager_->RegisterCameraStatusCallback(innerCallback);
    }
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::UnregisterCallback(CameraManager_Callbacks* cameraStatusCallback)
{
    auto callback = cameraStatusCallbackMap_.RemoveValue(cameraStatusCallback);
    if (callback != nullptr) {
        cameraManager_->UnregisterCameraStatusCallback(callback);
    }
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::RegisterTorchStatusCallback(OH_CameraManager_TorchStatusCallback torchStatusCallback)
{
    auto innerTorchStatusCallback = make_shared<InnerCameraManagerTorchStatusCallback>(this, torchStatusCallback);
    if (torchStatusCallbackMap_.SetMapValue(torchStatusCallback, innerTorchStatusCallback)) {
        cameraManager_->RegisterTorchListener(innerTorchStatusCallback);
    }
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::UnregisterTorchStatusCallback(OH_CameraManager_TorchStatusCallback torchStatusCallback)
{
    auto callback = torchStatusCallbackMap_.RemoveValue(torchStatusCallback);
    if (callback != nullptr) {
        cameraManager_->UnregisterTorchListener(callback);
    }
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::GetSupportedCameras(Camera_Device** cameras, uint32_t* size)
{
    std::vector<sptr<CameraDevice>> cameraObjList = CameraManager::GetInstance()->GetSupportedCameras();
    uint32_t cameraSize = cameraObjList.size();
    uint32_t cameraMaxSize = 32;
    CHECK_ERROR_RETURN_RET_LOG(cameraSize == 0 || cameraSize > cameraMaxSize, CAMERA_INVALID_ARGUMENT,
        "Invalid camera size.");
    Camera_Device* outCameras = new Camera_Device[cameraSize];
    for (size_t index = 0; index < cameraSize; index++) {
        const string cameraGetID = cameraObjList[index]->GetID();
        size_t dstSize = cameraGetID.size() + 1;
        char* dst = new char[dstSize];
        if (!dst) {
            MEDIA_ERR_LOG("Allocate memory for cameraId Failed!");
            delete[] outCameras;
            return CAMERA_SERVICE_FATAL_ERROR;
        }
        strlcpy(dst, cameraGetID.c_str(), dstSize);
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
    sptr<CameraDevice> cameraDevice = CameraManager::GetInstance()->GetCameraDeviceFromId(camera->cameraId);
    CHECK_ERROR_RETURN_RET_LOG(cameraDevice == nullptr, CAMERA_INVALID_ARGUMENT,
        "Camera_Manager::GetSupportedCameraOutputCapability get cameraDevice fail!");
    Camera_OutputCapability* outCapability = new Camera_OutputCapability;
    CHECK_ERROR_RETURN_RET_LOG(outCapability == nullptr, CAMERA_SERVICE_FATAL_ERROR,
        "Camera_Manager::GetSupportedCameraOutputCapability failed to allocate memory for outCapability!");

    sptr<CameraOutputCapability> innerCameraOutputCapability =
        CameraManager::GetInstance()->GetSupportedOutputCapability(cameraDevice);
    if (innerCameraOutputCapability == nullptr) {
        MEDIA_ERR_LOG("Camera_Manager::GetSupportedCameraOutputCapability innerCameraOutputCapability is null!");
        delete outCapability;
        return CAMERA_INVALID_ARGUMENT;
    }
    std::vector<Profile> previewProfiles = innerCameraOutputCapability->GetPreviewProfiles();
    std::vector<Profile> photoProfiles = innerCameraOutputCapability->GetPhotoProfiles();
    std::vector<VideoProfile> videoProfiles = innerCameraOutputCapability->GetVideoProfiles();

    std::vector<MetadataObjectType> metadataTypeList = innerCameraOutputCapability->GetSupportedMetadataObjectType();
    
    std::vector<Profile> uniquePreviewProfiles;
    for (const auto& profile : previewProfiles) {
        if (std::find(uniquePreviewProfiles.begin(), uniquePreviewProfiles.end(),
            profile) == uniquePreviewProfiles.end()) {
            uniquePreviewProfiles.push_back(profile);
        }
    }
    GetSupportedPreviewProfiles(outCapability, uniquePreviewProfiles);
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
    outCapability->previewProfilesSize = previewProfiles.size();
    if (previewProfiles.size() == 0) {
        MEDIA_ERR_LOG("Invalid preview profiles size.");
        outCapability->previewProfiles = nullptr;
        return CAMERA_INVALID_ARGUMENT;
    }
    outCapability->previewProfiles = new Camera_Profile* [previewProfiles.size()];
    CHECK_ERROR_PRINT_LOG(!outCapability->previewProfiles, "Failed to allocate memory for preview profiles");
    MEDIA_DEBUG_LOG("GetSupportedCameraOutputCapability previewOutput size enter");
    for (size_t index = 0; index < previewProfiles.size(); index++) {
        Camera_Profile* outPreviewProfile = new Camera_Profile;
        CHECK_ERROR_PRINT_LOG(!outPreviewProfile, "Failed to allocate memory for PreviewProfile");
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
    outCapability->photoProfilesSize = photoProfiles.size();
    if (photoProfiles.size() == 0) {
        MEDIA_ERR_LOG("Invalid photo profiles size.");
        outCapability->photoProfiles = nullptr;
        return CAMERA_INVALID_ARGUMENT;
    }
    outCapability->photoProfiles = new Camera_Profile* [photoProfiles.size()];
    CHECK_ERROR_PRINT_LOG(!outCapability->photoProfiles, "Failed to allocate memory for photo profiles");
    for (size_t index = 0; index < photoProfiles.size(); index++) {
        Camera_Profile* outPhotoProfile = new Camera_Profile;
        CHECK_ERROR_PRINT_LOG(!outPhotoProfile, "Failed to allocate memory for PhotoProfile");
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
    outCapability->videoProfilesSize = videoProfiles.size();
    if (videoProfiles.size() == 0) {
        MEDIA_ERR_LOG("Invalid video profiles size.");
        outCapability->videoProfiles = nullptr;
        return CAMERA_INVALID_ARGUMENT;
    }
    outCapability->videoProfiles = new Camera_VideoProfile* [videoProfiles.size()];
    CHECK_ERROR_PRINT_LOG(!outCapability->videoProfiles, "Failed to allocate memory for video profiles");
    for (size_t index = 0; index < videoProfiles.size(); index++) {
        Camera_VideoProfile* outVideoProfile = new Camera_VideoProfile;
        CHECK_ERROR_PRINT_LOG(!outVideoProfile, "Failed to allocate memory for VideoProfile");
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
    outCapability->metadataProfilesSize = metadataTypeList.size();
    if (metadataTypeList.size() == 0) {
        MEDIA_ERR_LOG("Invalid metadata type size.");
        outCapability->supportedMetadataObjectTypes = nullptr;
        return CAMERA_INVALID_ARGUMENT;
    }
    outCapability->supportedMetadataObjectTypes = new Camera_MetadataObjectType* [metadataTypeList.size()];
    CHECK_ERROR_PRINT_LOG(!outCapability->supportedMetadataObjectTypes,
        "Failed to allocate memory for supportedMetadataObjectTypes");
    for (size_t index = 0; index < metadataTypeList.size(); index++) {
        Camera_MetadataObjectType* outmetadataObject = new Camera_MetadataObjectType {};
        *outmetadataObject = static_cast<Camera_MetadataObjectType>(metadataTypeList[index]);
        outCapability->supportedMetadataObjectTypes[index] = outmetadataObject;
    }
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::GetSupportedCameraOutputCapabilityWithSceneMode(const Camera_Device* camera,
    Camera_SceneMode sceneMode, Camera_OutputCapability** cameraOutputCapability)
{
    sptr<CameraDevice> cameraDevice = CameraManager::GetInstance()->GetCameraDeviceFromId(camera->cameraId);
    CHECK_ERROR_RETURN_RET_LOG(cameraDevice == nullptr, CAMERA_INVALID_ARGUMENT,
        "Camera_Manager::GetSupportedCameraOutputCapabilityWithSceneMode get cameraDevice fail!");

    auto itr = g_ndkToFwMode_.find(static_cast<Camera_SceneMode>(sceneMode));
    CHECK_ERROR_RETURN_RET_LOG(itr == g_ndkToFwMode_.end(), CAMERA_INVALID_ARGUMENT,
        "Camera_Manager::GetSupportedCameraOutputCapabilityWithSceneMode "
        "sceneMode = %{public}d not supported!", sceneMode);

    SceneMode innerSceneMode = static_cast<SceneMode>(itr->second);
    sptr<CameraOutputCapability> innerCameraOutputCapability =
        CameraManager::GetInstance()->GetSupportedOutputCapability(cameraDevice, innerSceneMode);
    CHECK_ERROR_RETURN_RET_LOG(innerCameraOutputCapability == nullptr, CAMERA_INVALID_ARGUMENT,
        "Camera_Manager::GetSupportedCameraOutputCapabilityWithSceneMode innerCameraOutputCapability is null!");

    Camera_OutputCapability* outCapability = new Camera_OutputCapability;
    CHECK_ERROR_RETURN_RET_LOG(outCapability == nullptr, CAMERA_SERVICE_FATAL_ERROR,
        "Camera_Manager::GetSupportedCameraOutputCapabilityWithSceneMode failed to allocate memory for outCapability!");
    std::vector<Profile> previewProfiles = innerCameraOutputCapability->GetPreviewProfiles();
    std::vector<Profile> uniquePreviewProfiles;
    for (const auto& profile : previewProfiles) {
        if (std::find(uniquePreviewProfiles.begin(), uniquePreviewProfiles.end(),
            profile) == uniquePreviewProfiles.end()) {
            uniquePreviewProfiles.push_back(profile);
        }
    }
    std::vector<Profile> photoProfiles = innerCameraOutputCapability->GetPhotoProfiles();
    std::vector<VideoProfile> videoProfiles = innerCameraOutputCapability->GetVideoProfiles();
    std::vector<MetadataObjectType> metadataTypeList =
        innerCameraOutputCapability->GetSupportedMetadataObjectType();
    GetSupportedPreviewProfiles(outCapability, uniquePreviewProfiles);
    GetSupportedPhotoProfiles(outCapability, photoProfiles);
    GetSupportedVideoProfiles(outCapability, videoProfiles);
    GetSupportedMetadataTypeList(outCapability, metadataTypeList);
    *cameraOutputCapability = outCapability;
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::DeleteSupportedCameraOutputCapability(Camera_OutputCapability* cameraOutputCapability)
{
    CHECK_ERROR_RETURN_RET_LOG(cameraOutputCapability == nullptr, CAMERA_OK,
        "Camera_Manager::DeleteSupportedCameraOutputCapability cameraOutputCapability is nullptr");

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
        for (size_t index = 0; index < cameraOutputCapability->metadataProfilesSize; index++) {
            if (cameraOutputCapability->supportedMetadataObjectTypes[index] != nullptr) {
                delete cameraOutputCapability->supportedMetadataObjectTypes[index];
            }
        }
        delete[] cameraOutputCapability->supportedMetadataObjectTypes;
    }
    delete cameraOutputCapability;
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
    sptr<CaptureSession> innerCaptureSession = CameraManager::GetInstance()->CreateCaptureSession(SceneMode::NORMAL);
    CHECK_ERROR_RETURN_RET_LOG(innerCaptureSession == nullptr, CAMERA_SERVICE_FATAL_ERROR,
        "Camera_Manager::CreateCaptureSession create innerCaptureSession fail!");
    Camera_CaptureSession* outSession = new Camera_CaptureSession(innerCaptureSession);
    *captureSession = outSession;
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::CreateCameraInput(const Camera_Device* camera, Camera_Input** cameraInput)
{
    MEDIA_INFO_LOG("CameraId is: %{public}s", camera->cameraId);
    sptr<CameraDevice> cameraDevice = CameraManager::GetInstance()->GetCameraDeviceFromId(camera->cameraId);
    CHECK_ERROR_RETURN_RET_LOG(cameraDevice == nullptr, CAMERA_INVALID_ARGUMENT,
        "Camera_Manager::CreateCameraInput get cameraDevice fail!");

    sptr<CameraInput> innerCameraInput = nullptr;
    int32_t retCode = CameraManager::GetInstance()->CreateCameraInput(cameraDevice, &innerCameraInput);
    CHECK_ERROR_RETURN_RET(retCode != CameraErrorCode::SUCCESS, CAMERA_SERVICE_FATAL_ERROR);
    Camera_Input* outInput = new Camera_Input(innerCameraInput);
    *cameraInput = outInput;
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::CreateCameraInputWithPositionAndType(Camera_Position position, Camera_Type type,
    Camera_Input** cameraInput)
{
    MEDIA_ERR_LOG("Camera_Manager CreateCameraInputWithPositionAndType is called");
    sptr<CameraInput> innerCameraInput = nullptr;
    CameraPosition innerPosition = CameraPosition::CAMERA_POSITION_UNSPECIFIED;
    auto itr = g_NdkCameraPositionToFwk_.find(position);
    if (itr != g_NdkCameraPositionToFwk_.end()) {
        innerPosition = itr->second;
    } else {
        MEDIA_ERR_LOG("Camera_Manager::CreateCameraInputWithPositionAndType innerPosition not found!");
        return CAMERA_INVALID_ARGUMENT;
    }
    CameraType innerType = static_cast<CameraType>(type);

    innerCameraInput = CameraManager::GetInstance()->CreateCameraInput(innerPosition, innerType);
    CHECK_ERROR_RETURN_RET_LOG(innerCameraInput == nullptr, CAMERA_SERVICE_FATAL_ERROR,
        "Failed to CreateCameraInputWithPositionAndType");

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
    CHECK_ERROR_RETURN_RET_LOG(surface == nullptr, CAMERA_INVALID_ARGUMENT, "Failed to get previewOutput surface");

    surface->SetUserData(CameraManager::surfaceFormat, std::to_string(innerProfile.GetCameraFormat()));
    int32_t retCode = CameraManager::GetInstance()->CreatePreviewOutput(innerProfile, surface, &innerPreviewOutput);
    CHECK_ERROR_RETURN_RET(retCode != CameraErrorCode::SUCCESS, CAMERA_SERVICE_FATAL_ERROR);
    Camera_PreviewOutput* out = new Camera_PreviewOutput(innerPreviewOutput);
    *previewOutput = out;
    MEDIA_ERR_LOG("Camera_Manager::CreatePreviewOutput");
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::CreatePreviewOutputUsedInPreconfig(const char* surfaceId,
    Camera_PreviewOutput** previewOutput)
{
    sptr<PreviewOutput> innerPreviewOutput = nullptr;
    uint64_t iSurfaceId;
    std::istringstream iss(surfaceId);
    iss >> iSurfaceId;
    sptr<Surface> surface = SurfaceUtils::GetInstance()->GetSurface(iSurfaceId);
    if (!surface) {
        surface = Media::ImageReceiver::getSurfaceById(surfaceId);
    }
    CHECK_ERROR_RETURN_RET_LOG(surface == nullptr, CAMERA_INVALID_ARGUMENT,
        "Camera_Manager::CreatePreviewOutputUsedInPreconfig get previewOutput surface fail!");
    int32_t retCode = CameraManager::GetInstance()->CreatePreviewOutputWithoutProfile(surface, &innerPreviewOutput);
    CHECK_ERROR_RETURN_RET_LOG(retCode != CameraErrorCode::SUCCESS, CAMERA_SERVICE_FATAL_ERROR,
        "Camera_Manager::CreatePreviewOutputUsedInPreconfig create innerPreviewOutput fail!");
    CHECK_ERROR_RETURN_RET_LOG(innerPreviewOutput == nullptr, CAMERA_SERVICE_FATAL_ERROR,
        "Camera_Manager::CreatePreviewOutputUsedInPreconfig create innerPreviewOutput fail!");
    Camera_PreviewOutput* out = new Camera_PreviewOutput(innerPreviewOutput);
    *previewOutput = out;
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
    CHECK_ERROR_RETURN_RET_LOG(surface == nullptr, CAMERA_INVALID_ARGUMENT, "Failed to get photoOutput surface");

    surface->SetUserData(CameraManager::surfaceFormat, std::to_string(innerProfile.GetCameraFormat()));
    sptr<IBufferProducer> surfaceProducer = surface->GetProducer();
    int32_t retCode =
        CameraManager::GetInstance()->CreatePhotoOutput(innerProfile, surfaceProducer, &innerPhotoOutput, surface);
    CHECK_ERROR_RETURN_RET(retCode != CameraErrorCode::SUCCESS, CAMERA_SERVICE_FATAL_ERROR);
    Camera_PhotoOutput* out = new Camera_PhotoOutput(innerPhotoOutput);
    *photoOutput = out;
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::CreatePhotoOutputWithoutSurface(const Camera_Profile* profile,
    Camera_PhotoOutput** photoOutput)
{
    MEDIA_ERR_LOG("Camera_Manager CreatePhotoOutputWithoutSurface is called");
    sptr<PhotoOutput> innerPhotoOutput = nullptr;
    Size size;
    size.width = profile->size.width;
    size.height = profile->size.height;
    Profile innerProfile(static_cast<CameraFormat>(profile->format), size);

    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer(DEFAULT_SURFACEID);
    CHECK_ERROR_RETURN_RET_LOG(surface == nullptr, CAMERA_INVALID_ARGUMENT,
        "Failed to get photoOutput surface");

    photoSurface_ = surface;
    surface->SetUserData(CameraManager::surfaceFormat, std::to_string(innerProfile.GetCameraFormat()));
    sptr<IBufferProducer> surfaceProducer = surface->GetProducer();
    CHECK_ERROR_RETURN_RET_LOG(surfaceProducer == nullptr, CAMERA_SERVICE_FATAL_ERROR, "Get producer failed");

    int32_t retCode = CameraManager::GetInstance()->CreatePhotoOutput(innerProfile,
        surfaceProducer, &innerPhotoOutput, surface);
    CHECK_ERROR_RETURN_RET_LOG((retCode != CameraErrorCode::SUCCESS || innerPhotoOutput == nullptr),
        CAMERA_SERVICE_FATAL_ERROR, "Create photo output failed");

    innerPhotoOutput->SetNativeSurface(true);
    Camera_PhotoOutput* out = new Camera_PhotoOutput(innerPhotoOutput);
    CHECK_ERROR_RETURN_RET_LOG(out == nullptr, CAMERA_SERVICE_FATAL_ERROR, "Create Camera_PhotoOutput failed");
    out->SetPhotoSurface(surface);
    *photoOutput = out;
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::CreatePhotoOutputUsedInPreconfig(const char* surfaceId,
    Camera_PhotoOutput** photoOutput)
{
    sptr<PhotoOutput> innerPhotoOutput = nullptr;
    sptr<Surface> surface = nullptr;
    if (strcmp(surfaceId, "")) {
        surface = Media::ImageReceiver::getSurfaceById(surfaceId);
    } else {
        surface = Surface::CreateSurfaceAsConsumer("photoOutput");
    }
    CHECK_ERROR_RETURN_RET_LOG(surface == nullptr, CAMERA_INVALID_ARGUMENT,
        "Camera_Manager::CreatePhotoOutputUsedInPreconfig get photoOutput surface fail!");
    sptr<IBufferProducer> surfaceProducer = surface->GetProducer();
    CHECK_ERROR_RETURN_RET_LOG(surfaceProducer == nullptr, CAMERA_INVALID_ARGUMENT,
        "Camera_Manager::CreatePhotoOutputUsedInPreconfig get surfaceProducer fail!");
    int32_t retCode =
        CameraManager::GetInstance()->CreatePhotoOutputWithoutProfile(surfaceProducer, &innerPhotoOutput, surface);
    CHECK_ERROR_RETURN_RET_LOG(retCode != CameraErrorCode::SUCCESS, CAMERA_SERVICE_FATAL_ERROR,
        "Camera_Manager::CreatePhotoOutputUsedInPreconfig create innerPhotoOutput fail!");
    CHECK_ERROR_RETURN_RET_LOG(innerPhotoOutput == nullptr, CAMERA_SERVICE_FATAL_ERROR,
        "Camera_Manager::CreatePhotoOutputUsedInPreconfig create innerPhotoOutput fail!");
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
    CHECK_ERROR_RETURN_RET_LOG(surface == nullptr, CAMERA_INVALID_ARGUMENT, "Failed to get videoOutput surface");

    surface->SetUserData(CameraManager::surfaceFormat, std::to_string(innerProfile.GetCameraFormat()));
    int32_t retCode = CameraManager::GetInstance()->CreateVideoOutput(innerProfile, surface, &innerVideoOutput);
    CHECK_ERROR_RETURN_RET(retCode != CameraErrorCode::SUCCESS, CAMERA_SERVICE_FATAL_ERROR);
    Camera_VideoOutput* out = new Camera_VideoOutput(innerVideoOutput);
    *videoOutput = out;
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::CreateVideoOutputUsedInPreconfig(const char* surfaceId,
    Camera_VideoOutput** videoOutput)
{
    sptr<VideoOutput> innerVideoOutput = nullptr;
    uint64_t iSurfaceId;
    std::istringstream iss(surfaceId);
    iss >> iSurfaceId;
    sptr<Surface> surface = SurfaceUtils::GetInstance()->GetSurface(iSurfaceId);
    CHECK_ERROR_RETURN_RET_LOG(surface == nullptr, CAMERA_INVALID_ARGUMENT,
        "Camera_Manager::CreateVideoOutputUsedInPreconfig get videoOutput surface fail!");
    int32_t retCode = CameraManager::GetInstance()->CreateVideoOutputWithoutProfile(surface, &innerVideoOutput);
    CHECK_ERROR_RETURN_RET_LOG(retCode != CameraErrorCode::SUCCESS, CAMERA_SERVICE_FATAL_ERROR,
        "Camera_Manager::CreateVideoOutputUsedInPreconfig create innerVideoOutput fail!");
    CHECK_ERROR_RETURN_RET_LOG(innerVideoOutput == nullptr, CAMERA_SERVICE_FATAL_ERROR,
        "Camera_Manager::CreateVideoOutputUsedInPreconfig create innerVideoOutput fail!");
    Camera_VideoOutput* out = new Camera_VideoOutput(innerVideoOutput);
    *videoOutput = out;
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::CreateMetadataOutput(const Camera_MetadataObjectType* type,
    Camera_MetadataOutput** metadataOutput)
{
    MEDIA_ERR_LOG("Camera_Manager CreateMetadataOutput is called");
    sptr<MetadataOutput> innerMetadataOutput = nullptr;

    int32_t retCode = CameraManager::GetInstance()->CreateMetadataOutput(innerMetadataOutput);
    CHECK_ERROR_RETURN_RET(retCode != CameraErrorCode::SUCCESS, CAMERA_SERVICE_FATAL_ERROR);
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
        if (innerCameraDevice->GetID() == camera->cameraId) {
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

Camera_ErrorCode Camera_Manager::GetHostDeviceName(Camera_Device* camera, char** hostDeviceName)
{
    CameraDevice* device = nullptr;
    auto cameras = CameraManager::GetInstance()->GetSupportedCameras();
    MEDIA_DEBUG_LOG("the cameraObjList size is %{public}zu", cameras.size());
    for (auto& innerCamera : cameras) {
        if (innerCamera->GetID() == std::string(camera->cameraId)) {
            device = innerCamera;
            break;
        }
    }

    if (device == nullptr) {
        return CAMERA_SERVICE_FATAL_ERROR;
    } else {
        std::string deviceName = device->GetHostName();
        *hostDeviceName = (char*)malloc(deviceName.size() + 1);
        if (memcpy_s(*hostDeviceName, deviceName.size() + 1, deviceName.c_str(), deviceName.size()) != EOK) {
            free(*hostDeviceName);
            *hostDeviceName = nullptr;
            return CAMERA_SERVICE_FATAL_ERROR;
        }
        (*hostDeviceName)[deviceName.size()] = '\0';
        return CAMERA_OK;
    }
}

Camera_ErrorCode Camera_Manager::GetHostDeviceType(Camera_Device* camera, Camera_HostDeviceType* hostDeviceType)
{
    CameraDevice* device = nullptr;
    auto cameras = CameraManager::GetInstance()->GetSupportedCameras();
    MEDIA_DEBUG_LOG("the cameraObjList size is %{public}zu", cameras.size());
    for (auto& innerCamera : cameras) {
        if (innerCamera->GetID() == std::string(camera->cameraId)) {
            device = innerCamera;
            break;
        }
    }

    if (device == nullptr) {
        return CAMERA_SERVICE_FATAL_ERROR;
    } else {
        switch (device->GetDeviceType()) {
            case Camera_HostDeviceType::HOST_DEVICE_TYPE_PHONE:
                *hostDeviceType = Camera_HostDeviceType::HOST_DEVICE_TYPE_PHONE;
                break;
            case Camera_HostDeviceType::HOST_DEVICE_TYPE_TABLET:
                *hostDeviceType = Camera_HostDeviceType::HOST_DEVICE_TYPE_TABLET;
                break;
            default:
                *hostDeviceType = Camera_HostDeviceType::HOST_DEVICE_TYPE_UNKNOWN_TYPE;
                break;
        }
        return CAMERA_OK;
    }
}

Camera_ErrorCode Camera_Manager::GetSupportedSceneModes(Camera_Device* camera,
    Camera_SceneMode** sceneModes, uint32_t* size)
{
    sptr<CameraDevice> cameraDevice = CameraManager::GetInstance()->GetCameraDeviceFromId(camera->cameraId);
    CHECK_ERROR_RETURN_RET_LOG(cameraDevice == nullptr, CAMERA_INVALID_ARGUMENT,
        "Camera_Manager::GetSupportedSceneModes get cameraDevice fail!");

    std::vector<SceneMode> innerSceneMode = CameraManager::GetInstance()->GetSupportedModes(cameraDevice);
    for (auto it = innerSceneMode.begin(); it != innerSceneMode.end(); it++) {
        if (*it == SCAN) {
            innerSceneMode.erase(it);
            break;
        }
    }
    if (innerSceneMode.empty()) {
        innerSceneMode.emplace_back(CAPTURE);
        innerSceneMode.emplace_back(VIDEO);
    }
    MEDIA_INFO_LOG("Camera_Manager::GetSupportedSceneModes size = [%{public}zu]", innerSceneMode.size());

    std::vector<Camera_SceneMode> cameraSceneMode;
    for (size_t index = 0; index < innerSceneMode.size(); index++) {
        auto itr = g_fwModeToNdk_.find(static_cast<SceneMode>(innerSceneMode[index]));
        CHECK_EXECUTE(itr != g_fwModeToNdk_.end(),
            cameraSceneMode.push_back(static_cast<Camera_SceneMode>(itr->second)));
    }

    Camera_SceneMode* sceneMode = new Camera_SceneMode[cameraSceneMode.size()];
    CHECK_ERROR_RETURN_RET_LOG(sceneMode == nullptr, CAMERA_SERVICE_FATAL_ERROR,
        "Camera_Manager::GetSupportedSceneModes allocate memory for sceneMode fail!");
    for (size_t index = 0; index < cameraSceneMode.size(); index++) {
        sceneMode[index] = cameraSceneMode[index];
    }

    *sceneModes = sceneMode;
    *size = cameraSceneMode.size();
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::DeleteSceneModes(Camera_SceneMode* sceneModes)
{
    if (sceneModes != nullptr) {
        delete[] sceneModes;
    }

    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::IsTorchSupported(bool* isTorchSupported)
{
    MEDIA_DEBUG_LOG("Camera_Manager::IsTorchSupported is called");

    *isTorchSupported = CameraManager::GetInstance()->IsTorchSupported();
    MEDIA_DEBUG_LOG("IsTorchSupported[%{public}d]", *isTorchSupported);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::IsTorchSupportedByTorchMode(Camera_TorchMode torchMode, bool* isTorchSupported)
{
    MEDIA_DEBUG_LOG("Camera_Manager::IsTorchSupportedByTorchMode is called");

    auto itr = g_ndkToFwTorchMode_.find(torchMode);
    CHECK_ERROR_RETURN_RET_LOG(itr == g_ndkToFwTorchMode_.end(), CAMERA_INVALID_ARGUMENT,
        "torchMode[%{public}d] is invalid", torchMode);
    *isTorchSupported = CameraManager::GetInstance()->IsTorchModeSupported(itr->second);
    MEDIA_DEBUG_LOG("IsTorchSupportedByTorchMode[%{public}d]", *isTorchSupported);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::SetTorchMode(Camera_TorchMode torchMode)
{
    MEDIA_DEBUG_LOG("Camera_Manager::SetTorchMode is called");

    auto itr = g_ndkToFwTorchMode_.find(torchMode);
    CHECK_ERROR_RETURN_RET_LOG(itr == g_ndkToFwTorchMode_.end(), CAMERA_INVALID_ARGUMENT,
        "torchMode[%{public}d] is invalid", torchMode);
    int32_t ret = CameraManager::GetInstance()->SetTorchMode(itr->second);
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_Manager::GetCameraDevice(Camera_Position position, Camera_Type type, Camera_Device *camera)
{
    MEDIA_DEBUG_LOG("Camera_Manager::GetCameraDevice is called");

    Camera_Device* outCameras = new Camera_Device;
    CameraPosition innerPosition = CameraPosition::CAMERA_POSITION_UNSPECIFIED;
    auto itr = g_NdkCameraPositionToFwk_.find(position);
    if (itr != g_NdkCameraPositionToFwk_.end()) {
        innerPosition = itr->second;
    } else {
        MEDIA_ERR_LOG("Camera_Manager::CreateCameraInputWithPositionAndType innerPosition not found!");
        return CAMERA_INVALID_ARGUMENT;
    }

    CameraType innerType = static_cast<CameraType>(type);
    
    sptr<CameraDevice> cameraInfo = nullptr;
    std::vector<sptr<CameraDevice>> cameraObjList = CameraManager::GetInstance()->GetSupportedCameras();
    CHECK_ERROR_RETURN_RET_LOG(cameraObjList.size() == 0, CAMERA_SERVICE_FATAL_ERROR,
        "Camera_Manager::GetSupportedCameras  fail!");
    for (size_t i = 0; i < cameraObjList.size(); i++) {
        sptr<CameraDevice> cameraDevice = cameraObjList[i];
        if (cameraDevice == nullptr) {
            continue;
        }
        if (cameraDevice->GetPosition() == innerPosition &&
            cameraDevice->GetCameraType() == innerType) {
            cameraInfo = cameraDevice;
            break;
        }
    }

    if (cameraInfo == nullptr) {
        MEDIA_ERR_LOG("Camera_Manager::GetCameraDevice cameraInfo is null!");
        return CAMERA_SERVICE_FATAL_ERROR;
    }
    outCameras->cameraId = cameraInfo->GetID().data();
    outCameras->cameraPosition = position;
    outCameras->cameraType = type;
    outCameras->connectionType = static_cast<Camera_Connection>(cameraInfo->GetConnectionType());
    camera = outCameras;

    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::GetCameraConcurrentInfos(const Camera_Device *camera, uint32_t deviceSize,
    Camera_ConcurrentInfo **CameraConcurrentInfo, uint32_t *infoSize)
{
    MEDIA_DEBUG_LOG("Camera_Manager::GetCameraConcurrentInfos is called");
    std::vector<string>cameraIdv = {};
    std::vector<bool> cameraConcurrentType = {};
    std::vector<std::vector<SceneMode>> modes = {};
    std::vector<std::vector<sptr<CameraOutputCapability>>> outputCapabilities = {};
    vector<sptr<CameraDevice>> cameraDeviceArrray = {};
    for (uint32_t i = 0; i < deviceSize; i++) {
        string str(camera[i].cameraId);
        cameraIdv.push_back(str);
    }
    for (auto cameraidonly : cameraIdv) {
        cameraDeviceArrray.push_back(CameraManager::GetInstance()->GetCameraDeviceFromId(cameraidonly));
    }
    bool issupported = CameraManager::GetInstance()->GetConcurrentType(cameraDeviceArrray, cameraConcurrentType);
    CHECK_ERROR_RETURN_RET_LOG(!issupported, CAMERA_SERVICE_FATAL_ERROR, "CamagerManager::GetConcurrentType() error");
    issupported = CameraManager::GetInstance()->CheckConcurrentExecution(cameraDeviceArrray);
    CHECK_ERROR_RETURN_RET_LOG(!issupported, CAMERA_SERVICE_FATAL_ERROR, "CamagerManager::CheckConcurrentExe error");
    CameraManager::GetInstance()->GetCameraConcurrentInfos(cameraDeviceArrray,
        cameraConcurrentType, modes, outputCapabilities);
    Camera_ConcurrentInfo *CameraConcurrentInfothis =  new Camera_ConcurrentInfo[deviceSize];
    SetCameraConcurrentInfothis(camera, deviceSize, CameraConcurrentInfothis, cameraConcurrentType, modes,
        outputCapabilities);
    *CameraConcurrentInfo = CameraConcurrentInfothis;
    *infoSize = deviceSize;
    return CAMERA_OK;
}
 
Camera_ErrorCode Camera_Manager::SetCameraConcurrentInfothis(const Camera_Device *camera, uint32_t deviceSize,
    Camera_ConcurrentInfo *CameraConcurrentInfothis,
    std::vector<bool> &cameraConcurrentType, std::vector<std::vector<OHOS::CameraStandard::SceneMode>> &modes,
    std::vector<std::vector<OHOS::sptr<OHOS::CameraStandard::CameraOutputCapability>>> &outputCapabilities)
{
    for (int i = 0; i < deviceSize; i++) {
        CameraConcurrentInfothis[i].camera = camera[i];
        if (cameraConcurrentType[i] == false) {
            CameraConcurrentInfothis[i].type = CONCURRENT_TYPE_LIMITED_CAPABILITY;
        } else {
            CameraConcurrentInfothis[i].type = CONCURRENT_TYPE_FULL_CAPABILITY;
        }
        Camera_SceneMode* newmodes = new Camera_SceneMode[modes.size()];
        for (uint32_t j = 0; j < modes[i].size(); j++) {
            auto itr = g_fwModeToNdk_.find(modes[i][j]);
            newmodes[j] = itr->second;
        }
        CameraConcurrentInfothis[i].sceneModes = newmodes;
        CameraConcurrentInfothis[i].modeAndCapabilitySize = outputCapabilities[i].size();
        Camera_OutputCapability* newOutputCapability = new Camera_OutputCapability[outputCapabilities[i].size()];
        for (uint32_t j = 0; j < outputCapabilities[i].size(); j++) {
            std::vector<Profile> previewProfiles = outputCapabilities[i][j]->GetPreviewProfiles();
            std::vector<Profile> photoProfiles = outputCapabilities[i][j]->GetPhotoProfiles();
            std::vector<VideoProfile> videoProfiles = outputCapabilities[i][j]->GetVideoProfiles();
            std::vector<MetadataObjectType> metadataTypeList =
                outputCapabilities[i][j]->GetSupportedMetadataObjectType();
            std::vector<Profile> uniquePreviewProfiles;
            for (const auto& profile : previewProfiles) {
                if (std::find(uniquePreviewProfiles.begin(), uniquePreviewProfiles.end(),
                    profile) == uniquePreviewProfiles.end()) {
                    uniquePreviewProfiles.push_back(profile);
                }
            }
            GetSupportedPreviewProfiles(&newOutputCapability[j], uniquePreviewProfiles);
            GetSupportedPhotoProfiles(&newOutputCapability[j], photoProfiles);
            GetSupportedVideoProfiles(&newOutputCapability[j], videoProfiles);
            GetSupportedMetadataTypeList(&newOutputCapability[j], metadataTypeList);
        }
        CameraConcurrentInfothis[i].outputCapabilities = newOutputCapability;
    }
    *CameraConcurrentInfo = CameraConcurrentInfothis;
    *infoSize = deviceSize;
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::RegisterFoldStatusCallback(OH_CameraManager_OnFoldStatusInfoChange foldStatusCallback)
{
    auto innerFoldStatusCallback = make_shared<InnerCameraManagerFoldStatusCallback>(this, foldStatusCallback);
    CHECK_ERROR_RETURN_RET_LOG(
        innerFoldStatusCallback == nullptr, CAMERA_SERVICE_FATAL_ERROR, "create innerFoldStatusCallback failed!");
    if (cameraFoldStatusCallbackMap_.SetMapValue(foldStatusCallback, innerFoldStatusCallback)) {
        cameraManager_->RegisterFoldListener(innerFoldStatusCallback);
    }
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Manager::UnregisterFoldStatusCallback(
    OH_CameraManager_OnFoldStatusInfoChange foldStatusCallback)
{
    auto callback = cameraFoldStatusCallbackMap_.RemoveValue(foldStatusCallback);
    if (callback != nullptr) {
        cameraManager_->UnregisterFoldListener(callback);
    }
    return CAMERA_OK;
}