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

#include "input/camera_manager.h"
#include <cstring>

#include "camera_util.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "camera_log.h"
#include "system_ability_definition.h"
#include "camera_error_code.h"
#include "icamera_util.h"

using namespace std;
namespace OHOS {
namespace CameraStandard {
namespace {
    constexpr uint32_t UNIT_LENGTH = 3;
}
sptr<CameraManager> CameraManager::cameraManager_;

const std::string CameraManager::surfaceFormat = "CAMERA_SURFACE_FORMAT";

const std::unordered_map<camera_format_t, CameraFormat> CameraManager::metaToFwCameraFormat_ = {
    {OHOS_CAMERA_FORMAT_YCRCB_420_SP, CAMERA_FORMAT_YUV_420_SP},
    {OHOS_CAMERA_FORMAT_JPEG, CAMERA_FORMAT_JPEG},
    {OHOS_CAMERA_FORMAT_RGBA_8888, CAMERA_FORMAT_RGBA_8888}
};

const std::unordered_map<CameraFormat, camera_format_t> CameraManager::fwToMetaCameraFormat_ = {
    {CAMERA_FORMAT_YUV_420_SP, OHOS_CAMERA_FORMAT_YCRCB_420_SP},
    {CAMERA_FORMAT_JPEG, OHOS_CAMERA_FORMAT_JPEG},
    {CAMERA_FORMAT_RGBA_8888, OHOS_CAMERA_FORMAT_RGBA_8888},
};

CameraManager::CameraManager()
{
    Init();
    cameraObjList = {};
    dcameraObjList = {};
}

CameraManager::~CameraManager()
{
    serviceProxy_ = nullptr;
    listenerStub_ = nullptr;
    deathRecipient_ = nullptr;
    cameraSvcCallback_ = nullptr;
    cameraMuteSvcCallback_ = nullptr;
    cameraMngrCallback_ = nullptr;
    for (unsigned int i = 0; i < cameraMuteListenerList.size(); i++) {
        if (cameraMuteListenerList[i]) {
            cameraMuteListenerList[i] = nullptr;
        }
    }
    cameraMuteListenerList.clear();
    for (unsigned int i = 0; i < cameraObjList.size(); i++) {
        cameraObjList[i] = nullptr;
    }
    cameraObjList.clear();
    dcameraObjList.clear();
    CameraManager::cameraManager_ = nullptr;
}

int32_t CameraManager::CreateListenerObject()
{
    listenerStub_ = new(std::nothrow) CameraListenerStub();
    CHECK_AND_RETURN_RET_LOG(listenerStub_ != nullptr, CAMERA_ALLOC_ERROR,
        "failed to new CameraListenerStub object");
    CHECK_AND_RETURN_RET_LOG(serviceProxy_ != nullptr, CAMERA_ALLOC_ERROR,
        "Camera service does not exist.");

    sptr<IRemoteObject> object = listenerStub_->AsObject();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, CAMERA_ALLOC_ERROR, "listener object is nullptr..");

    MEDIA_DEBUG_LOG("CreateListenerObject");
    return serviceProxy_->SetListenerObject(object);
}

class CameraStatusServiceCallback : public HCameraServiceCallbackStub {
public:
    sptr<CameraManager> camMngr_ = nullptr;
    CameraStatusServiceCallback() : camMngr_(nullptr) {
    }

    explicit CameraStatusServiceCallback(const sptr<CameraManager>& cameraManager) : camMngr_(cameraManager) {
    }

    ~CameraStatusServiceCallback()
    {
        camMngr_ = nullptr;
    }

    int32_t OnCameraStatusChanged(const std::string& cameraId, const CameraStatus status) override
    {
        MEDIA_INFO_LOG("CameraStatusServiceCallback::OnCameraStatusChanged: cameraId: %{public}s, status: %{public}d",
                       cameraId.c_str(), status);
        CameraStatusInfo cameraStatusInfo;
        if (camMngr_ != nullptr && camMngr_->GetApplicationCallback() != nullptr) {
            cameraStatusInfo.cameraDevice = camMngr_->GetCameraDeviceFromId(cameraId);
            cameraStatusInfo.cameraStatus = status;
            if (cameraStatusInfo.cameraDevice) {
                MEDIA_INFO_LOG("OnCameraStatusChanged: cameraId: %{public}s, status: %{public}d",
                               cameraId.c_str(), status);
                camMngr_->GetApplicationCallback()->OnCameraStatusChanged(cameraStatusInfo);
            }
        } else {
            MEDIA_INFO_LOG("CameraManager::Callback not registered!, Ignore the callback");
        }
        return CAMERA_OK;
    }

    int32_t OnFlashlightStatusChanged(const std::string& cameraId, const FlashStatus status) override
    {
        MEDIA_INFO_LOG("OnFlashlightStatusChanged: "
            "cameraId: %{public}s, status: %{public}d", cameraId.c_str(), status);
        if (camMngr_ != nullptr && camMngr_->GetApplicationCallback() != nullptr) {
            camMngr_->GetApplicationCallback()->OnFlashlightStatusChanged(cameraId, status);
        } else {
            MEDIA_INFO_LOG("CameraManager::Callback not registered!, Ignore the callback");
        }
        return CAMERA_OK;
    }
};

sptr<CaptureSession> CameraManager::CreateCaptureSession()
{
    CAMERA_SYNC_TRACE;
    sptr<CaptureSession> captureSession = nullptr;
    int ret = CreateCaptureSession(&captureSession);
    if (ret != CameraErrorCode::SUCCESS) {
        MEDIA_ERR_LOG("Failed to CreateCaptureSession with error code:%{public}d", ret);
        return nullptr;
    }

    return captureSession;
}

int CameraManager::CreateCaptureSession(sptr<CaptureSession> *pCaptureSession)
{
    CAMERA_SYNC_TRACE;
    sptr<ICaptureSession> session = nullptr;
    sptr<CaptureSession> captureSession = nullptr;
    int32_t retCode = CAMERA_OK;

    if (serviceProxy_ == nullptr) {
        MEDIA_ERR_LOG("CameraManager::CreateCaptureSession serviceProxy_ is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    retCode = serviceProxy_->CreateCaptureSession(session);
    if (retCode == CAMERA_OK) {
        if (session != nullptr) {
            captureSession = new(std::nothrow) CaptureSession(session);
            if (captureSession == nullptr) {
                MEDIA_ERR_LOG("Failed to new CaptureSession");
                return CameraErrorCode::SERVICE_FATL_ERROR;
            }
        } else {
            MEDIA_ERR_LOG("Failed to CreateCaptureSession with session is null");
            return CameraErrorCode::SERVICE_FATL_ERROR;
        }
    } else {
        MEDIA_ERR_LOG("Failed to get capture session object from hcamera service!, %{public}d", retCode);
        return ServiceToCameraError(retCode);
    }

    *pCaptureSession = captureSession;

    return CameraErrorCode::SUCCESS;
}

sptr<PhotoOutput> CameraManager::CreatePhotoOutput(sptr<Surface> &surface)
{
    CAMERA_SYNC_TRACE;
    sptr<PhotoOutput> result = nullptr;
    return result;
}

sptr<PhotoOutput> CameraManager::CreatePhotoOutput(Profile &profile, sptr<Surface> &surface)
{
    CAMERA_SYNC_TRACE;
    sptr<PhotoOutput> photoOutput = nullptr;
    int ret = CreatePhotoOutput(profile, surface, &photoOutput);
    if (ret != CameraErrorCode::SUCCESS) {
        MEDIA_ERR_LOG("Failed to CreatePhotoOutput with error code:%{public}d", ret);
        return nullptr;
    }

    return photoOutput;
}

int CameraManager::CreatePhotoOutput(Profile &profile, sptr<Surface> &surface, sptr<PhotoOutput> *pPhotoOutput)
{
    CAMERA_SYNC_TRACE;
    sptr<IStreamCapture> streamCapture = nullptr;
    sptr<PhotoOutput> photoOutput = nullptr;
    int32_t retCode = CAMERA_OK;
    camera_format_t metaFormat;

    if ((serviceProxy_ == nullptr) || (surface == nullptr)) {
        MEDIA_ERR_LOG("CameraManager::CreatePhotoOutput serviceProxy_ is null or surface/profile is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    if ((profile.GetCameraFormat() == CAMERA_FORMAT_INVALID) ||
        (profile.GetSize().width == 0) ||
        (profile.GetSize().height == 0)) {
        MEDIA_ERR_LOG("CameraManager::CreatePhotoOutput invalid fomrat or width or height is zero");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    metaFormat = GetCameraMetadataFormat(profile.GetCameraFormat());
    retCode = serviceProxy_->CreatePhotoOutput(surface->GetProducer(), metaFormat, profile.GetSize().width,
                                               profile.GetSize().height, streamCapture);
    if (retCode == CAMERA_OK) {
        photoOutput = new(std::nothrow) PhotoOutput(streamCapture);
        if (photoOutput == nullptr) {
            MEDIA_ERR_LOG("Failed to new PhotoOutput ");
            return CameraErrorCode::SERVICE_FATL_ERROR;
        } else {
            POWERMGR_SYSEVENT_CAMERA_CONFIG(PHOTO, profile.GetSize().width,
                                            profile.GetSize().height);
        }
    } else {
        MEDIA_ERR_LOG("Failed to get stream capture object from hcamera service!, %{public}d", retCode);
        return ServiceToCameraError(retCode);
    }

    *pPhotoOutput = photoOutput;

    return CameraErrorCode::SUCCESS;
}

sptr<PreviewOutput> CameraManager::CreatePreviewOutput(Profile &profile, sptr<Surface> surface)
{
    CAMERA_SYNC_TRACE;
    sptr<PreviewOutput> previewOutput = nullptr;
    int ret = CreatePreviewOutput(profile, surface, &previewOutput);
    if (ret != CameraErrorCode::SUCCESS) {
        MEDIA_ERR_LOG("Failed to CreatePreviewOutput with error code:%{public}d", ret);
        return nullptr;
    }

    return previewOutput;
}

int CameraManager::CreatePreviewOutput(Profile &profile, sptr<Surface> surface, sptr<PreviewOutput> *pPreviewOutput)
{
    CAMERA_SYNC_TRACE;
    sptr<IStreamRepeat> streamRepeat = nullptr;
    sptr<PreviewOutput> previewOutput = nullptr;
    int32_t retCode = CAMERA_OK;
    camera_format_t metaFormat;

    if ((serviceProxy_ == nullptr) || (surface == nullptr)) {
        MEDIA_ERR_LOG("CameraManager::CreatePhotoOutput serviceProxy_ is null or surface/profile is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    if ((profile.GetCameraFormat() == CAMERA_FORMAT_INVALID) ||
        (profile.GetSize().width == 0) ||
        (profile.GetSize().height == 0)) {
        MEDIA_ERR_LOG("CameraManager::CreatePhotoOutput width or height is zero");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    metaFormat = GetCameraMetadataFormat(profile.GetCameraFormat());
    retCode = serviceProxy_->CreatePreviewOutput(surface->GetProducer(), metaFormat,
                                                 profile.GetSize().width, profile.GetSize().height, streamRepeat);
    if (retCode == CAMERA_OK) {
        previewOutput = new(std::nothrow) PreviewOutput(streamRepeat);
        if (previewOutput == nullptr) {
            MEDIA_ERR_LOG("Failed to new PreviewOutput");
            return CameraErrorCode::SERVICE_FATL_ERROR;
        } else {
            POWERMGR_SYSEVENT_CAMERA_CONFIG(PREVIEW,
                                            profile.GetSize().width,
                                            profile.GetSize().height);
        }
    } else {
        MEDIA_ERR_LOG("PreviewOutput: Failed to get stream repeat object from hcamera service! %{public}d", retCode);
        return ServiceToCameraError(retCode);
    }

    *pPreviewOutput = previewOutput;

    return CameraErrorCode::SUCCESS;
}

sptr<PreviewOutput> CameraManager::CreateDeferredPreviewOutput(Profile &profile)
{
    CAMERA_SYNC_TRACE;
    sptr<PreviewOutput> previewOutput = nullptr;
    int ret = CreateDeferredPreviewOutput(profile, &previewOutput);
    if (ret != CameraErrorCode::SUCCESS) {
        MEDIA_ERR_LOG("Failed to CreateDeferredPreviewOutput with error code:%{public}d", ret);
        return nullptr;
    }

    return previewOutput;
}

int CameraManager::CreateDeferredPreviewOutput(Profile &profile, sptr<PreviewOutput> *pPreviewOutput)
{
    CAMERA_SYNC_TRACE;
    sptr<IStreamRepeat> streamRepeat = nullptr;
    sptr<PreviewOutput> previewOutput = nullptr;
    int32_t retCode = CAMERA_OK;
    camera_format_t metaFormat;

    if ((serviceProxy_ == nullptr)) {
        MEDIA_ERR_LOG("CameraManager::CreatePreviewOutput serviceProxy_ is null or profile is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    if ((profile.GetCameraFormat() == CAMERA_FORMAT_INVALID) ||
        (profile.GetSize().width == 0) ||
        (profile.GetSize().height == 0)) {
        MEDIA_ERR_LOG("CameraManager::CreatePhotoOutput width or height is zero");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    metaFormat = GetCameraMetadataFormat(profile.GetCameraFormat());
    retCode = serviceProxy_->CreateDeferredPreviewOutput(metaFormat, profile.GetSize().width,
                                                         profile.GetSize().height, streamRepeat);
    if (retCode == CAMERA_OK) {
        previewOutput = new(std::nothrow) PreviewOutput(streamRepeat);
        if (previewOutput == nullptr) {
            MEDIA_ERR_LOG("Failed to new PreviewOutput");
            return CameraErrorCode::SERVICE_FATL_ERROR;
        } else {
            POWERMGR_SYSEVENT_CAMERA_CONFIG(PREVIEW,
                                            profile.GetSize().width,
                                            profile.GetSize().height);
        }
    } else {
        MEDIA_ERR_LOG("CreateDeferredPreviewOutput PreviewOutput: "
            "Failed to get stream repeat object from hcamera service!, %{public}d", retCode);
        return ServiceToCameraError(retCode);
    }

    *pPreviewOutput = previewOutput;

    return CameraErrorCode::SUCCESS;
}

sptr<PreviewOutput> CameraManager::CreatePreviewOutput(const sptr<OHOS::IBufferProducer> &producer, int32_t format)
{
    CAMERA_SYNC_TRACE;
    sptr<PreviewOutput> result = nullptr;
    return result;
}

sptr<PreviewOutput> CameraManager::CreateCustomPreviewOutput(sptr<Surface> surface, int32_t width, int32_t height)
{
    CAMERA_SYNC_TRACE;
    sptr<PreviewOutput> result = nullptr;
    return result;
}

sptr<MetadataOutput> CameraManager::CreateMetadataOutput()
{
    CAMERA_SYNC_TRACE;
    sptr<MetadataOutput> metadataOutput = nullptr;
    int ret = CreateMetadataOutput(&metadataOutput);
    if (ret != CameraErrorCode::SUCCESS) {
        MEDIA_ERR_LOG("Failed to CreateMetadataOutput with error code:%{public}d", ret);
        return nullptr;
    }

    return metadataOutput;
}

int CameraManager::CreateMetadataOutput(sptr<MetadataOutput> *pMetadataOutput)
{
    CAMERA_SYNC_TRACE;
    sptr<IStreamMetadata> streamMetadata = nullptr;
    sptr<MetadataOutput> metadataOutput = nullptr;
    int32_t retCode = CAMERA_OK;

    if (!serviceProxy_) {
        MEDIA_ERR_LOG("CameraManager::CreateMetadataOutput serviceProxy_ is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    if (!surface) {
        MEDIA_ERR_LOG("CameraManager::CreateMetadataOutput Failed to create surface");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    // only for face recognize
    int32_t format = OHOS_CAMERA_FORMAT_YCRCB_420_SP;
    int32_t width = 1920;
    int32_t height = 1080;
    surface->SetDefaultWidthAndHeight(width, height);
    retCode = serviceProxy_->CreateMetadataOutput(surface->GetProducer(), format, streamMetadata);
    if (retCode) {
        MEDIA_ERR_LOG("CameraManager::CreateMetadataOutput Failed to get stream metadata object from hcamera service! "
                      "%{public}d", retCode);
        return ServiceToCameraError(retCode);
    }

    metadataOutput = new(std::nothrow) MetadataOutput(surface, streamMetadata);
    if (!metadataOutput) {
        MEDIA_ERR_LOG("CameraManager::CreateMetadataOutput Failed to allocate MetadataOutput");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    sptr<IBufferConsumerListener> listener = new(std::nothrow) MetadataObjectListener(metadataOutput);
    if (!listener) {
        MEDIA_ERR_LOG("CameraManager::CreateMetadataOutput Failed to allocate metadata object listener");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    SurfaceError ret = surface->RegisterConsumerListener(listener);
    if (ret != SURFACE_ERROR_OK) {
        MEDIA_ERR_LOG("CameraManager::CreateMetadataOutput Surface consumer listener registration failed");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }

    *pMetadataOutput = metadataOutput;

    return CameraErrorCode::SUCCESS;
}

sptr<VideoOutput> CameraManager::CreateVideoOutput(sptr<Surface> &surface)
{
    CAMERA_SYNC_TRACE;
    sptr<VideoOutput> result = nullptr;
    return result;
}

sptr<VideoOutput> CameraManager::CreateVideoOutput(VideoProfile &profile, sptr<Surface> &surface)
{
    CAMERA_SYNC_TRACE;
    sptr<VideoOutput> videoOutput = nullptr;
    int ret = CreateVideoOutput(profile, surface, &videoOutput);
    if (ret != CameraErrorCode::SUCCESS) {
        MEDIA_ERR_LOG("Failed to CreateVideoOutput with error code:%{public}d", ret);
        return nullptr;
    }

    return videoOutput;
}

int CameraManager::CreateVideoOutput(VideoProfile &profile, sptr<Surface> &surface, sptr<VideoOutput> *pVideoOutput)
{
    CAMERA_SYNC_TRACE;
    sptr<IStreamRepeat> streamRepeat = nullptr;
    sptr<VideoOutput> videoOutput = nullptr;
    int32_t retCode = CAMERA_OK;
    camera_format_t metaFormat;

    if ((serviceProxy_ == nullptr) || (surface == nullptr)) {
        MEDIA_ERR_LOG("CameraManager::CreatePhotoOutput serviceProxy_ is null or surface/profile is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    if ((profile.GetCameraFormat() == CAMERA_FORMAT_INVALID) ||
        (profile.GetSize().width == 0) ||
        (profile.GetSize().height == 0)) {
        MEDIA_ERR_LOG("CameraManager::CreatePhotoOutput width or height is zero");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    // todo: need to set FPS range passed in video profile.
    metaFormat = GetCameraMetadataFormat(profile.GetCameraFormat());
    retCode = serviceProxy_->CreateVideoOutput(surface->GetProducer(), metaFormat,
                                               profile.GetSize().width, profile.GetSize().height, streamRepeat);
    if (retCode == CAMERA_OK) {
        videoOutput = new(std::nothrow) VideoOutput(streamRepeat);
        if (videoOutput == nullptr) {
            MEDIA_ERR_LOG("Failed to new VideoOutput");
            return CameraErrorCode::SERVICE_FATL_ERROR;
        } else {
            std::vector<int32_t> videoFrameRates = profile.GetFrameRates();
            if (videoFrameRates.size() >= 2) { // vaild frame rate range length is 2
                videoOutput->SetFrameRateRange(videoFrameRates[0], videoFrameRates[1]);
            }
            POWERMGR_SYSEVENT_CAMERA_CONFIG(VIDEO,
                                            profile.GetSize().width,
                                            profile.GetSize().height);
        }
    } else {
        MEDIA_ERR_LOG("VideoOutpout: Failed to get stream repeat object from hcamera service! %{public}d", retCode);
        return ServiceToCameraError(retCode);
    }

    *pVideoOutput = videoOutput;

    return CameraErrorCode::SUCCESS;
}

void CameraManager::Init()
{
    CAMERA_SYNC_TRACE;
    sptr<IRemoteObject> object = nullptr;
    cameraMngrCallback_ = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        MEDIA_ERR_LOG("Failed to get System ability manager");
        return;
    }
    object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    if (object == nullptr) {
        MEDIA_ERR_LOG("CameraManager::GetSystemAbility() is failed");
        return;
    }
    serviceProxy_ = iface_cast<ICameraService>(object);
    if (serviceProxy_ == nullptr) {
        MEDIA_ERR_LOG("CameraManager::init serviceProxy_ is null.");
        return;
    } else {
        cameraSvcCallback_ = new(std::nothrow) CameraStatusServiceCallback(this);
        if (cameraSvcCallback_) {
            SetCameraServiceCallback(cameraSvcCallback_);
        } else {
            MEDIA_ERR_LOG("CameraManager::init Failed to new CameraStatusServiceCallback.");
        }
        cameraMuteSvcCallback_ = new(std::nothrow) CameraMuteServiceCallback(this);
        if (cameraMuteSvcCallback_) {
            SetCameraMuteServiceCallback(cameraMuteSvcCallback_);
        } else {
            MEDIA_ERR_LOG("CameraManager::init Failed to new CameraMuteServiceCallback.");
        }
    }
    pid_t pid = 0;
    deathRecipient_ = new(std::nothrow) CameraDeathRecipient(pid);
    CHECK_AND_RETURN_LOG(deathRecipient_ != nullptr, "failed to new CameraDeathRecipient.");

    deathRecipient_->SetNotifyCb(std::bind(&CameraManager::CameraServerDied, this, std::placeholders::_1));
    bool result = object->AddDeathRecipient(deathRecipient_);
    if (!result) {
        MEDIA_ERR_LOG("failed to add deathRecipient");
        return;
    }

    int32_t ret = CreateListenerObject();
    CHECK_AND_RETURN_LOG(ret == CAMERA_OK, "failed to new MediaListener, ret = %{public}d", ret);
}

void CameraManager::CameraServerDied(pid_t pid)
{
    MEDIA_ERR_LOG("camera server has died, pid:%{public}d!", pid);
    if (serviceProxy_ != nullptr) {
        (void)serviceProxy_->AsObject()->RemoveDeathRecipient(deathRecipient_);
        serviceProxy_ = nullptr;
    }
    listenerStub_ = nullptr;
    deathRecipient_ = nullptr;
}

int CameraManager::CreateCameraDevice(std::string cameraId, sptr<ICameraDeviceService> *pICameraDeviceService)
{
    CAMERA_SYNC_TRACE;
    sptr<ICameraDeviceService> device = nullptr;
    int32_t retCode = CAMERA_OK;

    if (serviceProxy_ == nullptr || cameraId.empty()) {
        MEDIA_ERR_LOG("GetCameaDevice() serviceProxy_ is null or CameraID is empty: %{public}s", cameraId.c_str());
        return CameraErrorCode::INVALID_ARGUMENT;
    }
    retCode = serviceProxy_->CreateCameraDevice(cameraId, device);
    if (retCode != CAMERA_OK) {
        MEDIA_ERR_LOG("ret value from CreateCameraDevice, %{public}d", retCode);
        return ServiceToCameraError(retCode);
    }

    *pICameraDeviceService = device;

    return CameraErrorCode::SUCCESS;
}

void CameraManager::SetCallback(std::shared_ptr<CameraManagerCallback> callback)
{
    if (callback == nullptr) {
        MEDIA_INFO_LOG("CameraManager::SetCallback(): Application unregistering the callback");
    }
    cameraMngrCallback_ = callback;
}

std::shared_ptr<CameraManagerCallback> CameraManager::GetApplicationCallback()
{
    MEDIA_INFO_LOG("CameraManager::GetApplicationCallback callback! isExist = %{public}d",
                   cameraMngrCallback_ != nullptr);
    return cameraMngrCallback_;
}

sptr<CameraDevice> CameraManager::GetCameraDeviceFromId(std::string cameraId)
{
    sptr<CameraDevice> cameraObj = nullptr;

    for (size_t i = 0; i < cameraObjList.size(); i++) {
        if (cameraObjList[i]->GetID() == cameraId) {
            cameraObj = cameraObjList[i];
            break;
        }
    }
    return cameraObj;
}

sptr<CameraManager> &CameraManager::GetInstance()
{
    if (CameraManager::cameraManager_ == nullptr) {
        MEDIA_INFO_LOG("Initializing camera manager for first time!");
        CameraManager::cameraManager_ = new(std::nothrow) CameraManager();
        if (CameraManager::cameraManager_ == nullptr) {
            MEDIA_ERR_LOG("CameraManager::GetInstance failed to new CameraManager");
        }
    }
    return CameraManager::cameraManager_;
}

std::vector<sptr<CameraInfo>> CameraManager::GetCameras()
{
    CAMERA_SYNC_TRACE;
    dcameraObjList.clear();
    return dcameraObjList;
}

std::vector<sptr<CameraDevice>> CameraManager::GetSupportedCameras()
{
    CAMERA_SYNC_TRACE;

    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> cameraIds;
    std::vector<std::shared_ptr<Camera::CameraMetadata>> cameraAbilityList;
    int32_t retCode = -1;
    sptr<CameraDevice> cameraObj = nullptr;
    int32_t index = 0;

    for (unsigned int i = 0; i < cameraObjList.size(); i++) {
        cameraObjList[i] = nullptr;
    }
    cameraObjList.clear();
    if (serviceProxy_ == nullptr) {
        MEDIA_ERR_LOG("CameraManager::GetCameras serviceProxy_ is null, returning empty list!");
        return cameraObjList;
    }
    std::vector<sptr<CameraDevice>> supportedCameras;
    retCode = serviceProxy_->GetCameras(cameraIds, cameraAbilityList);
    if (retCode == CAMERA_OK) {
        for (auto& it : cameraIds) {
            cameraObj = new(std::nothrow) CameraDevice(it, cameraAbilityList[index++]);
            if (cameraObj == nullptr) {
                MEDIA_ERR_LOG("CameraManager::GetCameras new CameraDevice failed for id={public}%s", it.c_str());
                continue;
            }
            supportedCameras.emplace_back(cameraObj);
        }
    } else {
        MEDIA_ERR_LOG("CameraManager::GetCameras failed!, retCode: %{public}d", retCode);
    }

    ChooseDeFaultCameras(supportedCameras);
    return cameraObjList;
}

void CameraManager::ChooseDeFaultCameras(std::vector<sptr<CameraDevice>>& supportedCameras)
{
    for (auto& camera : supportedCameras) {
        bool hasDefaultCamera = false;
        for (auto& defaultCamera : cameraObjList) {
            if ((defaultCamera->GetPosition() == camera->GetPosition()) &&
                (defaultCamera->GetConnectionType() == camera->GetConnectionType())) {
                hasDefaultCamera = true;
                MEDIA_INFO_LOG("CameraManager::alreadly has default camera");
            } else {
                MEDIA_INFO_LOG("CameraManager::need add default camera");
            }
        }
        if (!hasDefaultCamera) {
            cameraObjList.emplace_back(camera);
        }
    }
}

sptr<CameraInput> CameraManager::CreateCameraInput(sptr<CameraInfo> &camera)
{
    CAMERA_SYNC_TRACE;
    sptr<CameraInput> cameraInput = nullptr;
    return cameraInput;
}

sptr<CameraInput> CameraManager::CreateCameraInput(sptr<CameraDevice> &camera)
{
    CAMERA_SYNC_TRACE;
    sptr<CameraInput> cameraInput = nullptr;
    int ret = CreateCameraInput(camera, &cameraInput);
    if (ret != CameraErrorCode::SUCCESS) {
        MEDIA_ERR_LOG("Failed to CreateCameraInput with error code:%{public}d", ret);
        return nullptr;
    }

    return cameraInput;
}

int CameraManager::CreateCameraInput(sptr<CameraDevice> &camera, sptr<CameraInput> *pCameraInput)
{
    CAMERA_SYNC_TRACE;
    sptr<CameraInput> cameraInput = nullptr;
    sptr<ICameraDeviceService> deviceObj = nullptr;

    if (camera != nullptr) {
        int ret = CreateCameraDevice(camera->GetID(), &deviceObj);
        if (ret == CameraErrorCode::SUCCESS) {
            cameraInput = new(std::nothrow) CameraInput(deviceObj, camera);
            if (cameraInput == nullptr) {
                MEDIA_ERR_LOG("failed to new CameraInput Returning null in CreateCameraInput");
                return CameraErrorCode::SERVICE_FATL_ERROR;
            }
        } else {
            MEDIA_ERR_LOG("Returning null in CreateCameraInput");
            return ret;
        }
    } else {
        MEDIA_ERR_LOG("CameraManager::CreateCameraInput: Camera object is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    *pCameraInput = cameraInput;

    return CameraErrorCode::SUCCESS;
}

sptr<CameraInput> CameraManager::CreateCameraInput(CameraPosition position, CameraType cameraType)
{
    CAMERA_SYNC_TRACE;
    sptr<CameraInput> cameraInput = nullptr;
    int ret = CreateCameraInput(position, cameraType, &cameraInput);
    if (ret != CameraErrorCode::SUCCESS) {
        MEDIA_ERR_LOG("Failed to CreateCameraInput with error code:%{public}d", ret);
        return nullptr;
    }

    return cameraInput;
}

int CameraManager::CreateCameraInput(CameraPosition position, CameraType cameraType, sptr<CameraInput> *pCameraInput)
{
    CAMERA_SYNC_TRACE;
    sptr<CameraInput> cameraInput = nullptr;
    if (cameraObjList.empty()) {
        this->GetSupportedCameras();
    }
    for (size_t i = 0; i < cameraObjList.size(); i++) {
        if ((cameraObjList[i]->GetPosition() == position) && (cameraObjList[i]->GetCameraType() == cameraType)) {
            cameraInput = CreateCameraInput(cameraObjList[i]);
            break;
        } else {
            MEDIA_ERR_LOG("No Camera Device for Camera position:%{public}d, Camera Type:%{public}d",
                          position, cameraType);
            return CameraErrorCode::SERVICE_FATL_ERROR;
        }
    }

    *pCameraInput = cameraInput;

    return CameraErrorCode::SUCCESS;
}

sptr<CameraOutputCapability> CameraManager::GetSupportedOutputCapability(sptr<CameraDevice>& camera)
{
    sptr<CameraOutputCapability> cameraOutputCapability = nullptr;
    uint32_t widthOffset = 1;
    uint32_t heightOffset = 2;
    CameraFormat format = CAMERA_FORMAT_INVALID;
    Size size;
    vector<Profile> photoProfile = {};
    vector<Profile> previewProfile = {};
    vector<VideoProfile> videoProfiles = {};
    vector<MetadataObjectType> objectTypes = {};
    std::shared_ptr<Camera::CameraMetadata> metadata = camera->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(),
                                             OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS,
                                             &item);
    if ((ret != CAM_META_SUCCESS) || (item.count % UNIT_LENGTH != 0)) {
        MEDIA_ERR_LOG("Failed to get stream configuration or Invalid stream configuation %{public}d  %{public}d",
            ret, item.count);
        return nullptr;
    }
    cameraOutputCapability = new(std::nothrow) CameraOutputCapability();

    for (uint32_t i = 0; i < item.count; i += UNIT_LENGTH) {
        auto itr = metaToFwCameraFormat_.find(static_cast<camera_format_t>(item.data.i32[i]));
        if (itr != metaToFwCameraFormat_.end()) {
            format = itr->second;
        } else {
            format = CAMERA_FORMAT_INVALID;
            MEDIA_ERR_LOG("format %{public}d is not supported now", item.data.i32[i]);
            continue;
        }
        size.width = item.data.i32[i + widthOffset];
        size.height = item.data.i32[i + heightOffset];
        Profile profile = Profile(format, size);
        if (format == CAMERA_FORMAT_JPEG) {
            photoProfile.push_back(profile);
        } else {
            previewProfile.push_back(profile);
            camera_metadata_item_t fpsItem;
            int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FPS_RANGES, &fpsItem);
            if (ret == CAM_META_SUCCESS) {
                const uint32_t step = 2;
                for (uint32_t i = 0; i < (fpsItem.count - 1); i += step) {
                    std::vector<int32_t> fps = {fpsItem.data.i32[i], fpsItem.data.i32[i+1]};
                    VideoProfile vidProfile = VideoProfile(format, size, fps);
                    videoProfiles.push_back(vidProfile);
                }
            }
        }
    }
    cameraOutputCapability->SetPhotoProfiles(photoProfile);
    MEDIA_DEBUG_LOG("SetPhotoProfiles size = %{public}zu", photoProfile.size());
    cameraOutputCapability->SetPreviewProfiles(previewProfile);
    MEDIA_DEBUG_LOG("SetPreviewProfiles size = %{public}zu", previewProfile.size());
    cameraOutputCapability->SetVideoProfiles(videoProfiles);
    MEDIA_DEBUG_LOG("SetVideoProfiles size = %{public}zu", videoProfiles.size());

    camera_metadata_item_t metadataItem;
    ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_STATISTICS_FACE_DETECT_MODE, &metadataItem);
    if (ret == CAM_META_SUCCESS) {
        for (uint32_t index = 0; index < metadataItem.count; index++) {
            if (metadataItem.data.u8[index] == OHOS_CAMERA_FACE_DETECT_MODE_SIMPLE) {
                objectTypes.push_back(MetadataObjectType::FACE);
            }
        }
    }
    cameraOutputCapability->SetSupportedMetadataObjectType(objectTypes);

    return cameraOutputCapability;
}
void CameraManager::SetCameraServiceCallback(sptr<ICameraServiceCallback>& callback)
{
    int32_t retCode = CAMERA_OK;

    if (serviceProxy_ == nullptr) {
        MEDIA_ERR_LOG("CameraManager::SetCallback serviceProxy_ is null");
        return;
    }
    retCode = serviceProxy_->SetCallback(callback);
    if (retCode != CAMERA_OK) {
        MEDIA_ERR_LOG("CameraManager::Set service Callback failed, retCode: %{public}d", retCode);
    }
    return;
}

camera_format_t CameraManager::GetCameraMetadataFormat(CameraFormat format)
{
    camera_format_t metaFormat = OHOS_CAMERA_FORMAT_YCRCB_420_SP;

    auto itr = fwToMetaCameraFormat_.find(format);
    if (itr != fwToMetaCameraFormat_.end()) {
        metaFormat = itr->second;
    }

    return metaFormat;
}

int32_t CameraMuteServiceCallback::OnCameraMute(bool muteMode)
{
    MEDIA_DEBUG_LOG("CameraMuteServiceCallback::OnCameraMute call! muteMode is %{public}d", muteMode);
    if (camMngr_ == nullptr) {
        MEDIA_INFO_LOG("CameraMuteServiceCallback::OnCameraMute camMngr_ is nullptr");
        return CAMERA_OK;
    }
    std::vector<shared_ptr<CameraMuteListener>> cameraMuteListenerList = camMngr_->GetCameraMuteListener();
    if (cameraMuteListenerList.size() > 0) {
        for (uint32_t i = 0; i < cameraMuteListenerList.size(); ++i) {
            cameraMuteListenerList[i]->OnCameraMute(muteMode);
        }
    } else {
        MEDIA_INFO_LOG("CameraManager::CameraMuteListener not registered!, Ignore the callback");
    }
    return CAMERA_OK;
}

void CameraManager::RegisterCameraMuteListener(std::shared_ptr<CameraMuteListener> listener)
{
    if (listener == nullptr) {
        MEDIA_INFO_LOG("CameraManager::RegisterCameraMuteListener(): unregistering the callback");
    }
    cameraMuteListenerList.push_back(listener);
}

void CameraManager::SetCameraMuteServiceCallback(sptr<ICameraMuteServiceCallback>& callback)
{
    int32_t retCode = CAMERA_OK;

    if (serviceProxy_ == nullptr) {
        MEDIA_ERR_LOG("CameraManager::SetMuteCameraServiceCallback serviceProxy_ is null");
        return;
    }
    retCode = serviceProxy_->SetMuteCallback(callback);
    if (retCode != CAMERA_OK) {
        MEDIA_ERR_LOG("CameraManager::Set Mute service Callback failed, retCode: %{public}d", retCode);
    }
    return;
}

std::vector<shared_ptr<CameraMuteListener>> CameraManager::GetCameraMuteListener()
{
    return cameraMuteListenerList;
}

bool CameraManager::IsCameraMuteSupported()
{
    const uint8_t MUTE_ON = 1;
    bool result = false;
    if (cameraObjList.empty()) {
        this->GetSupportedCameras();
    }
    for (size_t i = 0; i < cameraObjList.size(); i++) {
        std::shared_ptr<Camera::CameraMetadata> metadata = cameraObjList[i]->GetMetadata();
        camera_metadata_item_t item;
        int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_MUTE_MODES, &item);
        if (ret == 0) {
            MEDIA_INFO_LOG("CameraManager::isCameraMuteSupported() OHOS_ABILITY_MUTE_MODES is %{public}d",
                           item.data.u8[0]);
            result = (item.data.u8[0] == MUTE_ON) ? true : false;
        } else {
            MEDIA_ERR_LOG("Failed to get stream configuration or Invalid stream "
                          "configuation OHOS_ABILITY_MUTE_MODES ret = %{public}d", ret);
        }
        if (result == true) {
            break;
        }
    }
    return result;
}

bool CameraManager::IsCameraMuted()
{
    int32_t retCode = CAMERA_OK;
    bool isMuted = false;

    if (serviceProxy_ == nullptr) {
        MEDIA_ERR_LOG("CameraManager::IsCameraMuted serviceProxy_ is null");
        return isMuted;
    }
    retCode = serviceProxy_->IsCameraMuted(isMuted);
    if (retCode != CAMERA_OK) {
        MEDIA_ERR_LOG("CameraManager::IsCameraMuted failed, retCode: %{public}d", retCode);
    }
    return isMuted;
}

void CameraManager::MuteCamera(bool muteMode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t retCode = CAMERA_OK;

    if (serviceProxy_ == nullptr) {
        MEDIA_ERR_LOG("CameraManager::MuteCamera serviceProxy_ is null");
        return;
    }
    retCode = serviceProxy_->MuteCamera(muteMode);
    if (retCode != CAMERA_OK) {
        MEDIA_ERR_LOG("CameraManager::MuteCamera failed, retCode: %{public}d", retCode);
    }
    return;
}
} // CameraStandard
} // OHOS
