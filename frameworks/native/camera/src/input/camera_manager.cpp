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

#include <cstring>
#include "input/camera_manager.h"


#include "camera_util.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "camera_log.h"
#include "system_ability_definition.h"
#include "camera_error_code.h"
#include "icamera_util.h"
#include "device_manager_impl.h"

using namespace std;
namespace OHOS {
namespace CameraStandard {
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
class CameraManager::DeviceInitCallBack : public DistributedHardware::DmInitCallback {
        void OnRemoteDied() override;
};
void CameraManager::DeviceInitCallBack::OnRemoteDied()
{
    MEDIA_INFO_LOG("CameraManager::DeviceInitCallBack OnRemoteDied");
}
int32_t CameraManager::CreateListenerObject()
{
    MEDIA_DEBUG_LOG("CreateListenerObject entry");
    listenerStub_ = new(std::nothrow) CameraListenerStub();
    CHECK_AND_RETURN_RET_LOG(listenerStub_ != nullptr, CAMERA_ALLOC_ERROR,
        "failed to new CameraListenerStub object");
    CHECK_AND_RETURN_RET_LOG(serviceProxy_ != nullptr, CAMERA_ALLOC_ERROR,
        "Camera service does not exist.");

    sptr<IRemoteObject> object = listenerStub_->AsObject();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, CAMERA_ALLOC_ERROR, "listener object is nullptr..");

    return serviceProxy_->SetListenerObject(object);
}

int32_t CameraStatusServiceCallback::OnCameraStatusChanged(const std::string& cameraId, const CameraStatus status)
{
    MEDIA_INFO_LOG("OnCameraStatusChanged entry");
    CameraStatusInfo cameraStatusInfo;
    if (camMngr_ != nullptr && camMngr_->GetApplicationCallback() != nullptr) {
        cameraStatusInfo.cameraDevice = camMngr_->GetCameraDeviceFromId(cameraId);
        cameraStatusInfo.cameraStatus = status;
        if (cameraStatusInfo.cameraDevice) {
            MEDIA_INFO_LOG("cameraId: %{public}s, status: %{public}d",
                           cameraId.c_str(), status);
            camMngr_->GetApplicationCallback()->OnCameraStatusChanged(cameraStatusInfo);
        }
    } else {
        MEDIA_INFO_LOG("Callback not registered!, Ignore the callback");
    }
    return CAMERA_OK;
}

int32_t CameraStatusServiceCallback::OnFlashlightStatusChanged(const std::string& cameraId, const FlashStatus status)
{
    MEDIA_INFO_LOG("cameraId: %{public}s, status: %{public}d", cameraId.c_str(), status);
    if (camMngr_ != nullptr && camMngr_->GetApplicationCallback() != nullptr) {
        camMngr_->GetApplicationCallback()->OnFlashlightStatusChanged(cameraId, status);
    } else {
        MEDIA_INFO_LOG("Callback not registered!, Ignore the callback");
    }
    return CAMERA_OK;
}

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
        MEDIA_ERR_LOG("serviceProxy_ is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    retCode = serviceProxy_->CreateCaptureSession(session);
    if (retCode == CAMERA_OK) {
        if (session != nullptr) {
            captureSession = new(std::nothrow) CaptureSession(session);
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

sptr<PhotoOutput> CameraManager::CreatePhotoOutput(sptr<IBufferProducer> &surface)
{
    CAMERA_SYNC_TRACE;
    sptr<PhotoOutput> result = nullptr;
    return result;
}

sptr<PhotoOutput> CameraManager::CreatePhotoOutput(Profile &profile, sptr<IBufferProducer> &surface)
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

int CameraManager::CreatePhotoOutput(Profile &profile, sptr<IBufferProducer> &surface, sptr<PhotoOutput> *pPhotoOutput)
{
    CAMERA_SYNC_TRACE;
    sptr<IStreamCapture> streamCapture = nullptr;
    sptr<PhotoOutput> photoOutput = nullptr;
    int32_t retCode = CAMERA_OK;
    camera_format_t metaFormat;

    if ((serviceProxy_ == nullptr) || (surface == nullptr)) {
        MEDIA_ERR_LOG("serviceProxy_ is null or PhotoOutputSurface/profile is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    if ((profile.GetCameraFormat() == CAMERA_FORMAT_INVALID) ||
        (profile.GetSize().width == 0) ||
        (profile.GetSize().height == 0)) {
        MEDIA_ERR_LOG("invalid fomrat or width or height is zero");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    metaFormat = GetCameraMetadataFormat(profile.GetCameraFormat());
    retCode = serviceProxy_->CreatePhotoOutput(surface, metaFormat, profile.GetSize().width,
                                               profile.GetSize().height, streamCapture);
    if (retCode == CAMERA_OK) {
        photoOutput = new(std::nothrow) PhotoOutput(streamCapture);
        POWERMGR_SYSEVENT_CAMERA_CONFIG(PHOTO, profile.GetSize().width,
                                        profile.GetSize().height);
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
        MEDIA_ERR_LOG("serviceProxy_ is null or previewOutputSurface/profile is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    if ((profile.GetCameraFormat() == CAMERA_FORMAT_INVALID) ||
        (profile.GetSize().width == 0) ||
        (profile.GetSize().height == 0)) {
        MEDIA_ERR_LOG("width or height is zero");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    metaFormat = GetCameraMetadataFormat(profile.GetCameraFormat());
    retCode = serviceProxy_->CreatePreviewOutput(surface->GetProducer(), metaFormat,
                                                 profile.GetSize().width, profile.GetSize().height, streamRepeat);
    if (retCode == CAMERA_OK) {
        previewOutput = new(std::nothrow) PreviewOutput(streamRepeat);
        POWERMGR_SYSEVENT_CAMERA_CONFIG(PREVIEW,
                                        profile.GetSize().width,
                                        profile.GetSize().height);
    } else {
        MEDIA_ERR_LOG("Failed to get stream repeat object from hcamera service! %{public}d", retCode);
        return ServiceToCameraError(retCode);
    }

    *pPreviewOutput = previewOutput;

    return CameraErrorCode::SUCCESS;
}

sptr<PreviewOutput> CameraManager::CreateDeferredPreviewOutput(Profile &profile)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("CameraManager::CreateDeferredPreviewOutput called");
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
        MEDIA_ERR_LOG("serviceProxy_ is null or profile is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    if ((profile.GetCameraFormat() == CAMERA_FORMAT_INVALID) ||
        (profile.GetSize().width == 0) ||
        (profile.GetSize().height == 0)) {
        MEDIA_ERR_LOG("width or height is zero");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    metaFormat = GetCameraMetadataFormat(profile.GetCameraFormat());
    retCode = serviceProxy_->CreateDeferredPreviewOutput(metaFormat, profile.GetSize().width,
                                                         profile.GetSize().height, streamRepeat);
    if (retCode == CAMERA_OK) {
        previewOutput = new(std::nothrow) PreviewOutput(streamRepeat);
        POWERMGR_SYSEVENT_CAMERA_CONFIG(PREVIEW,
                                        profile.GetSize().width,
                                        profile.GetSize().height);
    } else {
        MEDIA_ERR_LOG("Failed to get stream repeat object from hcamera service!, %{public}d", retCode);
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
        MEDIA_ERR_LOG("serviceProxy_ is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    if (!surface) {
        MEDIA_ERR_LOG("Failed to create MetadataOutputSurface");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    // only for face recognize
    int32_t format = OHOS_CAMERA_FORMAT_YCRCB_420_SP;
    int32_t width = 1920;
    int32_t height = 1080;
    surface->SetDefaultWidthAndHeight(width, height);
    retCode = serviceProxy_->CreateMetadataOutput(surface->GetProducer(), format, streamMetadata);
    if (retCode) {
        MEDIA_ERR_LOG("Failed to get stream metadata object from hcamera service! %{public}d", retCode);
        return ServiceToCameraError(retCode);
    }

    metadataOutput = new(std::nothrow) MetadataOutput(surface, streamMetadata);
    sptr<IBufferConsumerListener> listener = new(std::nothrow) MetadataObjectListener(metadataOutput);
    SurfaceError ret = surface->RegisterConsumerListener(listener);
    if (ret != SURFACE_ERROR_OK) {
        MEDIA_ERR_LOG("MetadataOutputSurface consumer listener registration failed");
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
        MEDIA_ERR_LOG("serviceProxy_ is null or VideoOutputSurface/profile is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    if ((profile.GetCameraFormat() == CAMERA_FORMAT_INVALID) ||
        (profile.GetSize().width == 0) ||
        (profile.GetSize().height == 0)) {
        MEDIA_ERR_LOG("width or height is zero");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    // todo: need to set FPS range passed in video profile.
    metaFormat = GetCameraMetadataFormat(profile.GetCameraFormat());
    retCode = serviceProxy_->CreateVideoOutput(surface->GetProducer(), metaFormat,
                                               profile.GetSize().width, profile.GetSize().height, streamRepeat);
    if (retCode == CAMERA_OK) {
        videoOutput = new(std::nothrow) VideoOutput(streamRepeat);
        std::vector<int32_t> videoFrameRates = profile.GetFrameRates();
        if (videoFrameRates.size() >= 2) { // vaild frame rate range length is 2
            videoOutput->SetFrameRateRange(videoFrameRates[0], videoFrameRates[1]);
        }
        POWERMGR_SYSEVENT_CAMERA_CONFIG(VIDEO,
                                        profile.GetSize().width,
                                        profile.GetSize().height);
    } else {
        MEDIA_ERR_LOG("Failed to get stream repeat object from hcamera service! %{public}d", retCode);
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
        MEDIA_ERR_LOG("object is null");
        return;
    }
    serviceProxy_ = iface_cast<ICameraService>(object);
    if (serviceProxy_ == nullptr) {
        MEDIA_ERR_LOG("serviceProxy_ is null.");
        return;
    } else {
        cameraSvcCallback_ = new(std::nothrow) CameraStatusServiceCallback(this);
        SetCameraServiceCallback(cameraSvcCallback_);
        cameraMuteSvcCallback_ = new(std::nothrow) CameraMuteServiceCallback(this);
        SetCameraMuteServiceCallback(cameraMuteSvcCallback_);
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
        MEDIA_ERR_LOG("serviceProxy_ is null or CameraID is empty: %{public}s", cameraId.c_str());
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
        MEDIA_INFO_LOG("Application unregistering the callback");
    }
    cameraMngrCallback_ = callback;
}

std::shared_ptr<CameraManagerCallback> CameraManager::GetApplicationCallback()
{
    MEDIA_INFO_LOG("callback! isExist = %{public}d",
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
    }
    return CameraManager::cameraManager_;
}

std::vector<sptr<CameraInfo>> CameraManager::GetCameras()
{
    CAMERA_SYNC_TRACE;
    dcameraObjList.clear();
    return dcameraObjList;
}
bool CameraManager::GetDmDeviceInfo()
{
    std::vector <DistributedHardware::DmDeviceInfo> deviceInfos;
    auto &deviceManager = DistributedHardware::DeviceManager::GetInstance();
    std::shared_ptr<DistributedHardware::DmInitCallback> initCallback = std::make_shared<DeviceInitCallBack>();
    std::string pkgName = std::to_string(IPCSkeleton::GetCallingPid());
    const string extraInfo = "";
    deviceManager.InitDeviceManager(pkgName, initCallback);
    deviceManager.RegisterDevStateCallback(pkgName, extraInfo, NULL);
    deviceManager.GetTrustedDeviceList(pkgName, extraInfo, deviceInfos);
    deviceManager.UnInitDeviceManager(pkgName);
    int size = static_cast<int>(deviceInfos.size());
    MEDIA_INFO_LOG("CameraManager::size=%{public}d", size);
    if (size > 0) {
        distributedCamInfo_.resize(size);
        for (int i = 0; i < size; i++) {
            distributedCamInfo_[i].deviceName = deviceInfos[i].deviceName;
            distributedCamInfo_[i].deviceTypeId = deviceInfos[i].deviceTypeId;
            distributedCamInfo_[i].networkId = deviceInfos[i].networkId;
        }
        return true;
    } else {
        return false;
    }
}
bool CameraManager::isDistributeCamera(std::string cameraId, dmDeviceInfo &deviceInfo)
{
    MEDIA_INFO_LOG("CameraManager::cameraId = %{public}s", cameraId.c_str());
    for (auto distributedCamInfo : distributedCamInfo_) {
        if (cameraId.find(distributedCamInfo.networkId) != std::string::npos) {
            deviceInfo = distributedCamInfo;
            return true;
        }
    }
    return false;
}
std::vector<sptr<CameraDevice>> CameraManager::GetSupportedCameras()
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> cameraIds;
    std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>> cameraAbilityList;
    int32_t retCode = -1;
    sptr<CameraDevice> cameraObj = nullptr;
    int32_t index = 0;

    for (unsigned int i = 0; i < cameraObjList.size(); i++) {
        cameraObjList[i] = nullptr;
    }
    cameraObjList.clear();
    if (serviceProxy_ == nullptr) {
        MEDIA_ERR_LOG("serviceProxy_ is null, returning empty list!");
        return cameraObjList;
    }
    std::vector<sptr<CameraDevice>> supportedCameras;
    GetDmDeviceInfo();
    retCode = serviceProxy_->GetCameras(cameraIds, cameraAbilityList);
    if (retCode == CAMERA_OK) {
        for (auto& it : cameraIds) {
            dmDeviceInfo tempDmDeviceInfo;
            if (isDistributeCamera(it, tempDmDeviceInfo)) {
                MEDIA_DEBUG_LOG("CameraManager::it is remoted camera");
            } else {
                tempDmDeviceInfo.deviceName = "";
                tempDmDeviceInfo.deviceTypeId = 0;
                tempDmDeviceInfo.networkId = "";
            }
            cameraObj = new(std::nothrow) CameraDevice(it, cameraAbilityList[index++], tempDmDeviceInfo);
            supportedCameras.emplace_back(cameraObj);
        }
    } else {
        MEDIA_ERR_LOG("Get camera device failed!, retCode: %{public}d", retCode);
    }

    ChooseDeFaultCameras(supportedCameras);
    return cameraObjList;
}

void CameraManager::ChooseDeFaultCameras(std::vector<sptr<CameraDevice>>& supportedCameras)
{
    for (auto& camera : supportedCameras) {
        bool hasDefaultCamera = false;
        for (auto& defaultCamera : cameraObjList) {
            if ((camera->GetConnectionType() != CAMERA_CONNECTION_USB_PLUGIN) &&
                (defaultCamera->GetPosition() == camera->GetPosition()) &&
                (defaultCamera->GetConnectionType() == camera->GetConnectionType())) {
                hasDefaultCamera = true;
                MEDIA_INFO_LOG("ChooseDeFaultCameras alreadly has default camera");
            } else {
                MEDIA_INFO_LOG("ChooseDeFaultCameras need add default camera");
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
        } else {
            MEDIA_ERR_LOG("Returning null in CreateCameraInput");
            return ret;
        }
    } else {
        MEDIA_ERR_LOG("Camera object is null");
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

bool IsCapabilitySupported(std::shared_ptr<OHOS::Camera::CameraMetadata> metadata,
    camera_metadata_item_t &item, uint32_t metadataTag)
{
    bool isSupport = true;
    int32_t retCode = Camera::FindCameraMetadataItem(metadata->get(), metadataTag, &item);
    if (retCode != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG("Failed get metadata info tag = %{public}d, retCode = %{public}d, count = %{public}d",
            metadataTag, retCode, item.count);
        isSupport = false;
    }
    return isSupport;
}

void CameraManager::ParseBasicCapability(sptr<CameraOutputCapability> cameraOutputCapability,
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata, const camera_metadata_item_t &item)
{
    uint32_t widthOffset = 1;
    uint32_t heightOffset = 2;
    const uint8_t UNIT_STEP = 3;
    const uint8_t FPS_STEP = 2;

    CameraFormat format = CAMERA_FORMAT_INVALID;
    Size size;
    for (uint32_t i = 0; i < item.count; i += UNIT_STEP) {
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
            photoProfiles_.push_back(profile);
        } else {
            previewProfiles_.push_back(profile);
            camera_metadata_item_t fpsItem;
            int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FPS_RANGES, &fpsItem);
            if (ret != CAM_META_SUCCESS) {
                continue;
            }
            for (uint32_t j = 0; j < (fpsItem.count - 1); j += FPS_STEP) {
                std::vector<int32_t> fps = {fpsItem.data.i32[j], fpsItem.data.i32[j+1]};
                VideoProfile vidProfile = VideoProfile(format, size, fps);
                vidProfiles_.push_back(vidProfile);
            }
        }
    }
}

void CameraManager::ParseExtendCapability(sptr<CameraOutputCapability> cameraOutputCapability,
    const int32_t modeName, const camera_metadata_item_t &item)
{
    ExtendInfo extendInfo = {};
    std::shared_ptr<CameraStreamInfoParse> modeStreamParse = std::make_shared<CameraStreamInfoParse>();
    modeStreamParse->getModeInfo(item.data.i32, item.count, extendInfo); // 解析tag中带的数据信息意义
    for (uint32_t i = 0; i < extendInfo.modeCount; i++) {
        if (modeName == extendInfo.modeInfo[i].modeName) {
            for (uint32_t j = 0; j < extendInfo.modeInfo[i].streamTypeCount; j++) {
                OutputCapStreamType streamType =
                    static_cast<OutputCapStreamType>(extendInfo.modeInfo[i].streamInfo[j].streamType);
                CreateProfile4StreamType(streamType, i, j, extendInfo);
            }
            break;
        }
    }
}

sptr<CameraOutputCapability> CameraManager::GetSupportedOutputCapability(sptr<CameraDevice>& camera,
    int32_t modeName)
{
    sptr<CameraOutputCapability> cameraOutputCapability = nullptr;
    cameraOutputCapability = new(std::nothrow) CameraOutputCapability();
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = camera->GetMetadata();
    camera_metadata_item_t item;

    if (IsCapabilitySupported(metadata, item, OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS)) {
        ParseExtendCapability(cameraOutputCapability, modeName, item);
    } else if (IsCapabilitySupported(metadata, item, OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS)) {
        ParseBasicCapability(cameraOutputCapability, metadata, item);
    } else {
        MEDIA_ERR_LOG("Failed get stream info");
        return nullptr;
    }

    cameraOutputCapability->SetPhotoProfiles(photoProfiles_);
    MEDIA_DEBUG_LOG("SetPhotoProfiles size = %{public}zu", photoProfiles_.size());
    cameraOutputCapability->SetPreviewProfiles(previewProfiles_);
    MEDIA_DEBUG_LOG("SetPreviewProfiles size = %{public}zu", previewProfiles_.size());
    cameraOutputCapability->SetVideoProfiles(vidProfiles_);
    MEDIA_DEBUG_LOG("SetVideoProfiles size = %{public}zu", vidProfiles_.size());
    camera_metadata_item_t metadataItem;
    vector<MetadataObjectType> objectTypes = {};
    int32_t ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_STATISTICS_FACE_DETECT_MODE, &metadataItem);
    if (ret == CAM_META_SUCCESS) {
        for (uint32_t index = 0; index < metadataItem.count; index++) {
            if (metadataItem.data.u8[index] == OHOS_CAMERA_FACE_DETECT_MODE_SIMPLE) {
                objectTypes.push_back(MetadataObjectType::FACE);
            }
        }
    }
    cameraOutputCapability->SetSupportedMetadataObjectType(objectTypes);
    photoProfiles_.clear();
    previewProfiles_.clear();
    vidProfiles_.clear();
    return cameraOutputCapability;
}

void CameraManager::CreateProfile4StreamType(OutputCapStreamType streamType, uint32_t modeIndex,
    uint32_t streamIndex, ExtendInfo extendInfo)
{
    for (uint32_t k = 0; k < extendInfo.modeInfo[modeIndex].streamInfo[streamIndex].detailInfoCount; k++) {
        CameraFormat format;
        auto itr = metaToFwCameraFormat_.find(static_cast<camera_format_t>(
            extendInfo.modeInfo[modeIndex].streamInfo[streamIndex].detailInfo[k].format));
        if (itr != metaToFwCameraFormat_.end()) {
            format = itr->second;
        } else {
            format = CAMERA_FORMAT_INVALID;
            continue;
        }
        Size size;
        size.width = extendInfo.modeInfo[modeIndex].streamInfo[streamIndex].detailInfo[k].width;
        size.height = extendInfo.modeInfo[modeIndex].streamInfo[streamIndex].detailInfo[k].height;
        Fps fps;
        fps.fixedFps = extendInfo.modeInfo[modeIndex].streamInfo[streamIndex].detailInfo[k].fixedFps;
        fps.minFps = extendInfo.modeInfo[modeIndex].streamInfo[streamIndex].detailInfo[k].minFps;
        fps.maxFps = extendInfo.modeInfo[modeIndex].streamInfo[streamIndex].detailInfo[k].maxFps;
        std::vector<uint32_t> abilityId;
        abilityId = extendInfo.modeInfo[modeIndex].streamInfo[streamIndex].detailInfo[k].abilityId;

        if (streamType == OutputCapStreamType::PREVIEW) {
            Profile previewProfile = Profile(format, size, fps, abilityId);
            previewProfiles_.push_back(previewProfile);
        } else if (streamType == OutputCapStreamType::STILL_CAPTURE) {
            Profile snapProfile = Profile(format, size, fps, abilityId);
            photoProfiles_.push_back(snapProfile);
        } else if (streamType == OutputCapStreamType::VIDEO) {
            std::vector<int32_t> frameRates = {fps.fixedFps, fps.fixedFps};
            VideoProfile vidProfile = VideoProfile(format, size, frameRates);
            vidProfiles_.push_back(vidProfile);
        }
    }
}

void CameraManager::SetCameraServiceCallback(sptr<ICameraServiceCallback>& callback)
{
    int32_t retCode = CAMERA_OK;

    if (serviceProxy_ == nullptr) {
        MEDIA_ERR_LOG("serviceProxy_ is null");
        return;
    }
    retCode = serviceProxy_->SetCallback(callback);
    if (retCode != CAMERA_OK) {
        MEDIA_ERR_LOG("Set service Callback failed, retCode: %{public}d", retCode);
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
    MEDIA_DEBUG_LOG("muteMode is %{public}d", muteMode);
    if (camMngr_ == nullptr) {
        MEDIA_INFO_LOG("camMngr_ is nullptr");
        return CAMERA_OK;
    }
    std::vector<shared_ptr<CameraMuteListener>> cameraMuteListenerList = camMngr_->GetCameraMuteListener();
    if (cameraMuteListenerList.size() > 0) {
        for (uint32_t i = 0; i < cameraMuteListenerList.size(); ++i) {
            cameraMuteListenerList[i]->OnCameraMute(muteMode);
        }
    } else {
        MEDIA_INFO_LOG("OnCameraMute not registered!, Ignore the callback");
    }
    return CAMERA_OK;
}

void CameraManager::RegisterCameraMuteListener(std::shared_ptr<CameraMuteListener> listener)
{
    if (listener == nullptr) {
        MEDIA_INFO_LOG("unregistering the callback");
    }
    cameraMuteListenerList.push_back(listener);
}

void CameraManager::SetCameraMuteServiceCallback(sptr<ICameraMuteServiceCallback>& callback)
{
    int32_t retCode = CAMERA_OK;

    if (serviceProxy_ == nullptr) {
        MEDIA_ERR_LOG("serviceProxy_ is null");
        return;
    }
    retCode = serviceProxy_->SetMuteCallback(callback);
    if (retCode != CAMERA_OK) {
        MEDIA_ERR_LOG("Set Mute service Callback failed, retCode: %{public}d", retCode);
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
        std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameraObjList[i]->GetMetadata();
        camera_metadata_item_t item;
        int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_MUTE_MODES, &item);
        if (ret == 0) {
            MEDIA_INFO_LOG("OHOS_ABILITY_MUTE_MODES is %{public}d", item.data.u8[0]);
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
        MEDIA_ERR_LOG("serviceProxy_ is null");
        return isMuted;
    }
    retCode = serviceProxy_->IsCameraMuted(isMuted);
    if (retCode != CAMERA_OK) {
        MEDIA_ERR_LOG("IsCameraMuted call failed, retCode: %{public}d", retCode);
    }
    return isMuted;
}

void CameraManager::MuteCamera(bool muteMode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t retCode = CAMERA_OK;

    if (serviceProxy_ == nullptr) {
        MEDIA_ERR_LOG("serviceProxy_ is null");
        return;
    }
    retCode = serviceProxy_->MuteCamera(muteMode);
    if (retCode != CAMERA_OK) {
        MEDIA_ERR_LOG("MuteCamera call failed, retCode: %{public}d", retCode);
    }
}

int32_t CameraManager::PrelaunchCamera()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (serviceProxy_ == nullptr) {
        MEDIA_ERR_LOG("CameraManager::PrelaunchCamera serviceProxy_ is null");
        return SERVICE_FATL_ERROR;
    }
    int32_t retCode = serviceProxy_->PrelaunchCamera();
    if (retCode != CAMERA_OK) {
        MEDIA_ERR_LOG("CameraManager::PrelaunchCamera failed, retCode: %{public}d", retCode);
    }
    return ServiceToCameraError(retCode);
}

bool CameraManager::IsPrelaunchSupported(sptr<CameraDevice> camera)
{
    bool isPrelaunch = false;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = camera->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_PRELAUNCH_AVAILABLE, &item);
    if (ret == 0) {
        MEDIA_INFO_LOG("CameraManager::IsPrelaunchSupported() OHOS_ABILITY_PRELAUNCH_AVAILABLE is %{public}d",
                       item.data.u8[0]);
        isPrelaunch = (item.data.u8[0] == 1);
    } else {
        MEDIA_ERR_LOG("Failed to get OHOS_ABILITY_PRELAUNCH_AVAILABLE ret = %{public}d", ret);
    }
    return isPrelaunch;
}

int32_t CameraManager::SetPrelaunchConfig(std::string cameraId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (serviceProxy_ == nullptr) {
        MEDIA_ERR_LOG("CameraManager::SetPrelaunchConfig serviceProxy_ is null");
        return SERVICE_FATL_ERROR;
    }
    int32_t retCode = serviceProxy_->SetPrelaunchConfig(cameraId);
    if (retCode != CAMERA_OK) {
        MEDIA_ERR_LOG("CameraManager::SetPrelaunchConfig failed, retCode: %{public}d", retCode);
    }
    return ServiceToCameraError(retCode);
}
} // namespace CameraStandard
} // namespace OHOS
