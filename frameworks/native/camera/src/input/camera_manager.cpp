/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <ostream>
#include <sstream>

#include "camera_error_code.h"
#include "camera_log.h"
#include "camera_security_utils.h"
#include "camera_util.h"
#include "capture_scene_const.h"
#include "deferred_photo_proc_session.h"
#include "device_manager_impl.h"
#include "dps_metadata_info.h"
#include "icamera_util.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "istream_capture.h"
#include "istream_common.h"
#include "session/capture_session.h"
#include "session/high_res_photo_session.h"
#include "session/macro_photo_session.h"
#include "session/macro_video_session.h"
#include "session/night_session.h"
#include "session/photo_session.h"
#include "session/portrait_session.h"
#include "session/profession_session.h"
#include "session/scan_session.h"
#include "session/slow_motion_session.h"
#include "session/video_session.h"
#include "session/secure_camera_session.h"
#include "system_ability_definition.h"

using namespace std;
namespace OHOS {
namespace CameraStandard {
using OHOS::HDI::Camera::V1_3::OperationMode;
sptr<CameraManager> CameraManager::g_cameraManager = nullptr;
std::mutex CameraManager::g_instanceMutex;

const std::string CameraManager::surfaceFormat = "CAMERA_SURFACE_FORMAT";

const std::unordered_map<camera_format_t, CameraFormat> CameraManager::metaToFwCameraFormat_ = {
    {OHOS_CAMERA_FORMAT_YCRCB_420_SP, CAMERA_FORMAT_YUV_420_SP},
    {OHOS_CAMERA_FORMAT_JPEG, CAMERA_FORMAT_JPEG},
    {OHOS_CAMERA_FORMAT_RGBA_8888, CAMERA_FORMAT_RGBA_8888},
    {OHOS_CAMERA_FORMAT_YCBCR_P010, CAMERA_FORMAT_YCBCR_P010},
    {OHOS_CAMERA_FORMAT_YCRCB_P010, CAMERA_FORMAT_YCRCB_P010},
    {OHOS_CAMERA_FORMAT_YCBCR_420_SP, CAMERA_FORMAT_NV12},
    {OHOS_CAMERA_FORMAT_422_YUYV, CAMERA_FORMAT_YUV_422_YUYV},
    {OHOS_CAMERA_FORMAT_DNG, CAMERA_FORMAT_DNG},
};

const std::unordered_map<CameraFormat, camera_format_t> CameraManager::fwToMetaCameraFormat_ = {
    {CAMERA_FORMAT_YUV_420_SP, OHOS_CAMERA_FORMAT_YCRCB_420_SP},
    {CAMERA_FORMAT_JPEG, OHOS_CAMERA_FORMAT_JPEG},
    {CAMERA_FORMAT_RGBA_8888, OHOS_CAMERA_FORMAT_RGBA_8888},
    {CAMERA_FORMAT_YCBCR_P010, OHOS_CAMERA_FORMAT_YCBCR_P010},
    {CAMERA_FORMAT_YCRCB_P010, OHOS_CAMERA_FORMAT_YCRCB_P010},
    {CAMERA_FORMAT_NV12, OHOS_CAMERA_FORMAT_YCBCR_420_SP},
    {CAMERA_FORMAT_YUV_422_YUYV, OHOS_CAMERA_FORMAT_422_YUYV},
    {CAMERA_FORMAT_DNG, OHOS_CAMERA_FORMAT_DNG},

};

const std::unordered_map<OperationMode, SceneMode> g_metaToFwSupportedMode_ = {
    {OperationMode::NORMAL, NORMAL},
    {OperationMode::CAPTURE, CAPTURE},
    {OperationMode::VIDEO, VIDEO},
    {OperationMode::PORTRAIT, PORTRAIT},
    {OperationMode::NIGHT, NIGHT},
    {OperationMode::PROFESSIONAL_PHOTO, PROFESSIONAL_PHOTO},
    {OperationMode::PROFESSIONAL_VIDEO, PROFESSIONAL_VIDEO},
    {OperationMode::SLOW_MOTION, SLOW_MOTION},
    {OperationMode::SCAN_CODE, SCAN},
    {OperationMode::CAPTURE_MACRO, CAPTURE_MACRO},
    {OperationMode::VIDEO_MACRO, VIDEO_MACRO},
    {OperationMode::HIGH_FRAME_RATE, HIGH_FRAME_RATE},
    {OperationMode::HIGH_RESOLUTION_PHOTO, HIGH_RES_PHOTO},
    {OperationMode::SECURE, SECURE}
};

const std::unordered_map<SceneMode, OperationMode> g_fwToMetaSupportedMode_ = {
    {NORMAL, OperationMode::NORMAL},
    {CAPTURE,  OperationMode::CAPTURE},
    {VIDEO,  OperationMode::VIDEO},
    {PORTRAIT,  OperationMode::PORTRAIT},
    {NIGHT,  OperationMode::NIGHT},
    {PROFESSIONAL_PHOTO,  OperationMode::PROFESSIONAL_PHOTO},
    {PROFESSIONAL_VIDEO,  OperationMode::PROFESSIONAL_VIDEO},
    {SLOW_MOTION,  OperationMode::SLOW_MOTION},
    {SCAN, OperationMode::SCAN_CODE},
    {CAPTURE_MACRO, OperationMode::CAPTURE_MACRO},
    {VIDEO_MACRO, OperationMode::VIDEO_MACRO},
    {HIGH_FRAME_RATE, OperationMode::HIGH_FRAME_RATE},
    {HIGH_RES_PHOTO, OperationMode::HIGH_RESOLUTION_PHOTO},
    {SECURE, OperationMode::SECURE}
};

const std::set<int32_t> isTemplateMode_ = {
    SceneMode::CAPTURE, SceneMode::VIDEO
};

const std::set<int32_t> isPhotoMode_ = {
    SceneMode::CAPTURE, SceneMode::PORTRAIT
};

CameraManager::CameraManager()
{
    MEDIA_INFO_LOG("CameraManager::CameraManager construct enter");
}

CameraManager::~CameraManager()
{
    MEDIA_INFO_LOG("CameraManager::~CameraManager() called");
    RemoveServiceProxyDeathRecipient();
    UnSubscribeSystemAbility();
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
    MEDIA_DEBUG_LOG("CameraManager::CreateListenerObject prepare execute");
    sptr<CameraListenerStub> listenerStub = new (std::nothrow) CameraListenerStub();
    CHECK_AND_RETURN_RET_LOG(listenerStub != nullptr, CAMERA_ALLOC_ERROR, "failed to new CameraListenerStub object");
    sptr<IRemoteObject> object = listenerStub->AsObject();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, CAMERA_ALLOC_ERROR, "listener object is nullptr..");
    auto serviceProxy = GetServiceProxy();
    CHECK_AND_RETURN_RET_LOG(serviceProxy != nullptr, CameraErrorCode::SERVICE_FATL_ERROR, "serviceProxy is null");
    return serviceProxy->SetListenerObject(object);
}

int32_t CameraStatusServiceCallback::OnCameraStatusChanged(const std::string& cameraId, const CameraStatus status)
{
    MEDIA_INFO_LOG("cameraId: %{public}s, status: %{public}d", cameraId.c_str(), status);
    auto cameraManager = cameraManager_.promote();
    if (cameraManager == nullptr) {
        MEDIA_INFO_LOG("cameraManager is nullptr");
        return CAMERA_OK;
    }

    auto listenerMap = cameraManager->GetCameraMngrCallbackMap();
    MEDIA_DEBUG_LOG("CameraMngrCallbackMap size %{public}d", listenerMap.Size());
    if (listenerMap.IsEmpty()) {
        return CAMERA_OK;
    }

    CameraStatusInfo cameraStatusInfo;
    if (status == CAMERA_STATUS_APPEAR) {
        cameraManager->InitCameraList();
    }
    cameraStatusInfo.cameraDevice = cameraManager->GetCameraDeviceFromId(cameraId);
    if (status == CAMERA_STATUS_DISAPPEAR) {
        cameraManager->InitCameraList();
    }
    cameraStatusInfo.cameraStatus = status;
    if (cameraStatusInfo.cameraDevice) {
        listenerMap.Iterate([&](std::thread::id threadId,
                                std::shared_ptr<CameraManagerCallback> cameraManagerCallback) {
            if (cameraManagerCallback != nullptr) {
                MEDIA_INFO_LOG("Callback cameraStatus");
                cameraManagerCallback->OnCameraStatusChanged(cameraStatusInfo);
            } else {
                std::ostringstream oss;
                oss << threadId;
                MEDIA_INFO_LOG("Callback not registered!, Ignore the callback: thread:%{public}s", oss.str().c_str());
            }
        });
    }
    return CAMERA_OK;
}

int32_t CameraStatusServiceCallback::OnFlashlightStatusChanged(const std::string& cameraId, const FlashStatus status)
{
    MEDIA_INFO_LOG("cameraId: %{public}s, status: %{public}d", cameraId.c_str(), status);
    auto cameraManager = cameraManager_.promote();
    if (cameraManager == nullptr) {
        MEDIA_INFO_LOG("cameraManager is nullptr");
        return CAMERA_OK;
    }
    auto listenerMap = cameraManager->GetCameraMngrCallbackMap();
    MEDIA_DEBUG_LOG("CameraMngrCallbackMap size %{public}d", listenerMap.Size());
    if (listenerMap.IsEmpty()) {
        return CAMERA_OK;
    }

    listenerMap.Iterate([&](std::thread::id threadId, std::shared_ptr<CameraManagerCallback> cameraManagerCallback) {
        if (cameraManagerCallback != nullptr) {
            MEDIA_INFO_LOG("Callback cameraStatus");
            cameraManagerCallback->OnFlashlightStatusChanged(cameraId, status);
        } else {
            std::ostringstream oss;
            oss << threadId;
            MEDIA_INFO_LOG("Callback not registered!, Ignore the callback: thread:%{public}s", oss.str().c_str());
        }
    });
    return CAMERA_OK;
}

void CameraServiceSystemAbilityListener::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    MEDIA_INFO_LOG("OnAddSystemAbility,id: %{public}d", systemAbilityId);
    CameraManager::GetInstance()->OnCameraServerAlive();
}

void CameraServiceSystemAbilityListener::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    MEDIA_INFO_LOG("OnRemoveSystemAbility,id: %{public}d", systemAbilityId);
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

sptr<CaptureSession> CameraManager::CreateCaptureSessionImpl(SceneMode mode, sptr<ICaptureSession> session)
{
    switch (mode) {
        case SceneMode::VIDEO:
            return new (std::nothrow) VideoSession(session);
        case SceneMode::CAPTURE:
            return new (std::nothrow) PhotoSession(session);
        case SceneMode::PORTRAIT:
            return new (std::nothrow) PortraitSession(session);
        case SceneMode::PROFESSIONAL_VIDEO:
        case SceneMode::PROFESSIONAL_PHOTO:
            return new (std::nothrow) ProfessionSession(session, cameraObjList_);
        case SceneMode::SCAN:
            return new (std::nothrow) ScanSession(session);
        case SceneMode::NIGHT:
            return new (std::nothrow) NightSession(session);
        case SceneMode::CAPTURE_MACRO:
            return new (std::nothrow) MacroPhotoSession(session);
        case SceneMode::VIDEO_MACRO:
            return new (std::nothrow) MacroVideoSession(session);
        case SceneMode::SLOW_MOTION:
            return new (std::nothrow) SlowMotionSession(session);
        case SceneMode::HIGH_RES_PHOTO:
            return new (std::nothrow) HighResPhotoSession(session);
        case SceneMode::SECURE:
            return new(std::nothrow) SecureCameraSession(session);
        default:
            return new (std::nothrow) CaptureSession(session);
    }
}

sptr<CaptureSession> CameraManager::CreateCaptureSession(SceneMode mode)
{
    CAMERA_SYNC_TRACE;
    sptr<ICaptureSession> session = nullptr;

    int32_t retCode = CAMERA_OK;
    auto serviceProxy = GetServiceProxy();
    if (serviceProxy == nullptr) {
        MEDIA_ERR_LOG("serviceProxy is null");
        return nullptr;
    }
    OperationMode opMode = OperationMode::NORMAL;
    auto it = g_fwToMetaSupportedMode_.find(mode);
    if (it != g_fwToMetaSupportedMode_.end()) {
        opMode = it->second;
    }
    MEDIA_INFO_LOG("CameraManager::CreateCaptureSession prepare proxy execute");
    retCode = serviceProxy->CreateCaptureSession(session, opMode);
    MEDIA_INFO_LOG("CameraManager::CreateCaptureSession proxy execute end, %{public}d", retCode);
    if (retCode == CAMERA_OK && session != nullptr) {
        sptr<CaptureSession> captureSession = CreateCaptureSessionImpl(mode, session);
        captureSession->SetMode(mode);
        return captureSession;
    }
    MEDIA_ERR_LOG("Failed to get capture session object from hcamera service!, %{public}d", retCode);
    return nullptr;
}

int CameraManager::CreateCaptureSession(sptr<CaptureSession> *pCaptureSession)
{
    CAMERA_SYNC_TRACE;
    sptr<ICaptureSession> session = nullptr;
    sptr<CaptureSession> captureSession = nullptr;
    int32_t retCode = CAMERA_OK;
    auto serviceProxy = GetServiceProxy();
    if (serviceProxy == nullptr) {
        MEDIA_ERR_LOG("serviceProxy_ is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    retCode = serviceProxy->CreateCaptureSession(session);
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

sptr<DeferredPhotoProcSession> CameraManager::CreateDeferredPhotoProcessingSession(int userId,
    std::shared_ptr<IDeferredPhotoProcSessionCallback> callback)
{
    CAMERA_SYNC_TRACE;
    sptr<DeferredPhotoProcSession> deferredPhotoProcSession = nullptr;
    int ret = CreateDeferredPhotoProcessingSession(userId, callback, &deferredPhotoProcSession);
    if (ret != CameraErrorCode::SUCCESS) {
        MEDIA_ERR_LOG("Failed to CreateDeferredPhotoProcessingSession with error code:%{public}d", ret);
        return nullptr;
    }
    return deferredPhotoProcSession;
}

int CameraManager::CreateDeferredPhotoProcessingSession(int userId,
    std::shared_ptr<IDeferredPhotoProcSessionCallback> callback,
    sptr<DeferredPhotoProcSession> *pDeferredPhotoProcSession)
{
    CAMERA_SYNC_TRACE;
    sptr<DeferredProcessing::IDeferredPhotoProcessingSession> session = nullptr;
    sptr<DeferredProcessing::IDeferredPhotoProcessingSessionCallback> remoteCallback = nullptr;
    sptr<DeferredPhotoProcSession> deferredPhotoProcSession = nullptr;
    int32_t retCode = CAMERA_OK;

    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        MEDIA_ERR_LOG("Failed to get System ability manager");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    if (object == nullptr) {
        MEDIA_ERR_LOG("object is null");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    sptr<ICameraService> serviceProxy = iface_cast<ICameraService>(object);

    if (serviceProxy == nullptr) {
        MEDIA_ERR_LOG("serviceProxy is null");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }

    deferredPhotoProcSession = new(std::nothrow) DeferredPhotoProcSession(userId, callback);
    remoteCallback = new(std::nothrow) DeferredPhotoProcessingSessionCallback(deferredPhotoProcSession);

    retCode = serviceProxy->CreateDeferredPhotoProcessingSession(userId, remoteCallback, session);
    if (retCode == CAMERA_OK) {
        if (session != nullptr) {
            deferredPhotoProcSession->SetDeferredPhotoSession(session);
        } else {
            MEDIA_ERR_LOG("Failed to CreateDeferredPhotoProcessingSession as session is null");
            return CameraErrorCode::SERVICE_FATL_ERROR;
        }
    } else {
        MEDIA_ERR_LOG("Failed to get photo session!, %{public}d", retCode);
        return ServiceToCameraError(retCode);
    }

    *pDeferredPhotoProcSession = deferredPhotoProcSession;
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

int CameraManager::CreatePhotoOutputWithoutProfile(sptr<IBufferProducer>& surface, sptr<PhotoOutput>* pPhotoOutput)
{
    CAMERA_SYNC_TRACE;
    sptr<IStreamCapture> streamCapture = nullptr;
    sptr<PhotoOutput> photoOutput = nullptr;
    auto serviceProxy = GetServiceProxy();
    if ((serviceProxy == nullptr) || (surface == nullptr)) {
        MEDIA_ERR_LOG("serviceProxy is null or PhotoOutputSurface is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }
    photoOutput = new (std::nothrow) PhotoOutput(surface);
    if (photoOutput == nullptr) {
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    photoOutput->AddTag(CaptureOutput::DYNAMIC_PROFILE);
    *pPhotoOutput = photoOutput;
    return CameraErrorCode::SUCCESS;
}

int CameraManager::CreatePhotoOutput(Profile &profile, sptr<IBufferProducer> &surface, sptr<PhotoOutput> *pPhotoOutput)
{
    CAMERA_SYNC_TRACE;
    sptr<IStreamCapture> streamCapture = nullptr;
    sptr<PhotoOutput> photoOutput = nullptr;
    int32_t retCode = CAMERA_OK;
    camera_format_t metaFormat;
    auto serviceProxy = GetServiceProxy();
    if ((serviceProxy == nullptr) || (surface == nullptr)) {
        MEDIA_ERR_LOG("serviceProxy is null or PhotoOutputSurface/profile is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    if ((profile.GetCameraFormat() == CAMERA_FORMAT_INVALID) ||
        (profile.GetSize().width == 0) ||
        (profile.GetSize().height == 0)) {
        MEDIA_ERR_LOG("invalid fomrat or width or height is zero");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    metaFormat = GetCameraMetadataFormat(profile.GetCameraFormat());
    retCode = serviceProxy->CreatePhotoOutput(
        surface, metaFormat, profile.GetSize().width, profile.GetSize().height, streamCapture);
    if (retCode == CAMERA_OK) {
        photoOutput = new(std::nothrow) PhotoOutput(surface);
        if (photoOutput == nullptr) {
            return CameraErrorCode::SERVICE_FATL_ERROR;
        }
        photoOutput->SetStream(streamCapture);
    } else {
        MEDIA_ERR_LOG("Failed to get stream capture object from hcamera service!, %{public}d", retCode);
        return ServiceToCameraError(retCode);
    }
    photoOutput->SetPhotoProfile(profile);
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

int CameraManager::CreatePreviewOutputWithoutProfile(sptr<Surface> surface, sptr<PreviewOutput>* pPreviewOutput)
{
    CAMERA_SYNC_TRACE;
    sptr<PreviewOutput> previewOutput = nullptr;
    auto serviceProxy = GetServiceProxy();
    if ((serviceProxy == nullptr) || (surface == nullptr)) {
        MEDIA_ERR_LOG("serviceProxy is null or surface is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }
    previewOutput = new (std::nothrow) PreviewOutput(surface->GetProducer());
    if (previewOutput == nullptr) {
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    previewOutput->AddTag(CaptureOutput::DYNAMIC_PROFILE);
    *pPreviewOutput = previewOutput;
    return CAMERA_OK;
}

int CameraManager::CreatePreviewOutput(Profile &profile, sptr<Surface> surface, sptr<PreviewOutput> *pPreviewOutput)
{
    CAMERA_SYNC_TRACE;
    sptr<IStreamRepeat> streamRepeat = nullptr;
    sptr<PreviewOutput> previewOutput = nullptr;
    int32_t retCode = CAMERA_OK;
    camera_format_t metaFormat;

    auto serviceProxy = GetServiceProxy();
    if ((serviceProxy == nullptr) || (surface == nullptr)) {
        MEDIA_ERR_LOG("serviceProxy is null or previewOutputSurface/profile is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    if ((profile.GetCameraFormat() == CAMERA_FORMAT_INVALID) ||
        (profile.GetSize().width == 0) ||
        (profile.GetSize().height == 0)) {
        MEDIA_ERR_LOG("width or height is zero");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    metaFormat = GetCameraMetadataFormat(profile.GetCameraFormat());
    retCode = serviceProxy->CreatePreviewOutput(
        surface->GetProducer(), metaFormat, profile.GetSize().width, profile.GetSize().height, streamRepeat);
    if (retCode != CAMERA_OK) {
        MEDIA_ERR_LOG("Failed to get stream repeat object from hcamera service! %{public}d", retCode);
        return ServiceToCameraError(retCode);
    }
    previewOutput = new (std::nothrow) PreviewOutput(surface->GetProducer());
    if (previewOutput == nullptr) {
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    previewOutput->SetStream(streamRepeat);
    previewOutput->SetOutputFormat(profile.GetCameraFormat());
    previewOutput->SetSize(profile.GetSize());
    previewOutput->SetPreviewProfile(profile);
    *pPreviewOutput = previewOutput;
    return CameraErrorCode::SUCCESS;
}

int32_t CameraManager::CreatePreviewOutputStream(
    sptr<IStreamRepeat>& streamPtr, Profile& profile, const sptr<OHOS::IBufferProducer>& producer)
{
    auto validResult = ValidCreateOutputStream(profile, producer);
    if (validResult != SUCCESS) {
        MEDIA_ERR_LOG("CameraManager::CreatePreviewOutputStream ValidCreateOutputStream fail:%{public}d", validResult);
        return validResult;
    }

    auto serviceProxy = GetServiceProxy();
    if (serviceProxy == nullptr) {
        MEDIA_ERR_LOG("CameraManager::CreatePreviewOutputStream serviceProxy is null");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    camera_format_t metaFormat = GetCameraMetadataFormat(profile.GetCameraFormat());
    int32_t retCode = serviceProxy->CreatePreviewOutput(
        producer, metaFormat, profile.GetSize().width, profile.GetSize().height, streamPtr);
    if (retCode != CAMERA_OK) {
        MEDIA_ERR_LOG("Failed to get stream repeat object from hcamera service! %{public}d", retCode);
        return ServiceToCameraError(retCode);
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CameraManager::CreatePhotoOutputStream(
    sptr<IStreamCapture>& streamPtr, Profile& profile, const sptr<OHOS::IBufferProducer>& producer)
{
    auto validResult = ValidCreateOutputStream(profile, producer);
    if (validResult != SUCCESS) {
        MEDIA_ERR_LOG("CameraManager::CreatePhotoOutputStream ValidCreateOutputStream fail:%{public}d", validResult);
        return validResult;
    }

    auto serviceProxy = GetServiceProxy();
    if ((serviceProxy == nullptr) || (producer == nullptr)) {
        MEDIA_ERR_LOG("CameraManager::CreatePhotoOutputStream serviceProxy is null or producer is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    auto metaFormat = GetCameraMetadataFormat(profile.GetCameraFormat());
    auto retCode = serviceProxy->CreatePhotoOutput(
        producer, metaFormat, profile.GetSize().width, profile.GetSize().height, streamPtr);
    if (retCode != CAMERA_OK) {
        MEDIA_ERR_LOG("CameraManager::CreatePhotoOutputStream Failed to get stream capture object from hcamera "
                      "service! %{public}d",
            retCode);
        return ServiceToCameraError(retCode);
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CameraManager::ValidCreateOutputStream(Profile& profile, const sptr<OHOS::IBufferProducer>& producer)
{
    if (producer == nullptr) {
        MEDIA_ERR_LOG("CameraManager::ValidCreateOutputStream producer is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    if ((profile.GetCameraFormat() == CAMERA_FORMAT_INVALID) || (profile.GetSize().width == 0) ||
        (profile.GetSize().height == 0)) {
        MEDIA_ERR_LOG("CameraManager::ValidCreateOutputStream width or height is zero");
        return CameraErrorCode::INVALID_ARGUMENT;
    }
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

    auto serviceProxy = GetServiceProxy();
    if ((serviceProxy == nullptr)) {
        MEDIA_ERR_LOG("serviceProxy is null or profile is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    if ((profile.GetCameraFormat() == CAMERA_FORMAT_INVALID) ||
        (profile.GetSize().width == 0) ||
        (profile.GetSize().height == 0)) {
        MEDIA_ERR_LOG("width or height is zero");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    metaFormat = GetCameraMetadataFormat(profile.GetCameraFormat());
    retCode = serviceProxy->CreateDeferredPreviewOutput(
        metaFormat, profile.GetSize().width, profile.GetSize().height, streamRepeat);
    if (retCode == CAMERA_OK) {
        previewOutput = new(std::nothrow) PreviewOutput();
        if (previewOutput == nullptr) {
            return CameraErrorCode::SERVICE_FATL_ERROR;
        }
        previewOutput->SetStream(streamRepeat);
    } else {
        MEDIA_ERR_LOG("Failed to get stream repeat object from hcamera service!, %{public}d", retCode);
        return ServiceToCameraError(retCode);
    }
    previewOutput->SetPreviewProfile(profile);
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
    int ret = CreateMetadataOutput(metadataOutput);
    if (ret != CameraErrorCode::SUCCESS) {
        MEDIA_ERR_LOG("Failed to CreateMetadataOutput with error code:%{public}d", ret);
        return nullptr;
    }

    return metadataOutput;
}

int CameraManager::CreateMetadataOutput(sptr<MetadataOutput>& pMetadataOutput)
{
    CAMERA_SYNC_TRACE;
    sptr<IStreamMetadata> streamMetadata = nullptr;
    int32_t retCode = CAMERA_OK;

    auto serviceProxy = GetServiceProxy();
    if (serviceProxy == nullptr) {
        MEDIA_ERR_LOG("serviceProxy_ is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    if (surface == nullptr) {
        MEDIA_ERR_LOG("Failed to create MetadataOutputSurface");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    // only for face recognize
    int32_t format = OHOS_CAMERA_FORMAT_YCRCB_420_SP;
    int32_t width = 1920;
    int32_t height = 1080;
    surface->SetDefaultWidthAndHeight(width, height);
    retCode = serviceProxy->CreateMetadataOutput(surface->GetProducer(), format, streamMetadata);
    if (retCode) {
        MEDIA_ERR_LOG("Failed to get stream metadata object from hcamera service! %{public}d", retCode);
        return ServiceToCameraError(retCode);
    }
    pMetadataOutput = new (std::nothrow) MetadataOutput(surface, streamMetadata);
    pMetadataOutput->SetStream(streamMetadata);
    sptr<IBufferConsumerListener> bufferConsumerListener = new (std::nothrow) MetadataObjectListener(pMetadataOutput);
    SurfaceError ret = surface->RegisterConsumerListener(bufferConsumerListener);
    if (ret != SURFACE_ERROR_OK) {
        MEDIA_ERR_LOG("MetadataOutputSurface consumer listener registration failed:%{public}d", ret);
    }
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

int32_t CameraManager::CreateVideoOutputStream(
    sptr<IStreamRepeat>& streamPtr, Profile& profile, const sptr<OHOS::IBufferProducer>& producer)
{
    auto validResult = ValidCreateOutputStream(profile, producer);
    if (validResult != SUCCESS) {
        MEDIA_ERR_LOG("CameraManager::CreateVideoOutputStream ValidCreateOutputStream fail:%{public}d", validResult);
        return validResult;
    }

    auto serviceProxy = GetServiceProxy();
    if ((serviceProxy == nullptr) || (producer == nullptr)) {
        MEDIA_ERR_LOG("CameraManager::CreateVideoOutputStream serviceProxy is null or producer is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    auto metaFormat = GetCameraMetadataFormat(profile.GetCameraFormat());
    MEDIA_DEBUG_LOG("metaFormat = %{public}d", static_cast<int32_t>(metaFormat));
    auto retCode = serviceProxy->CreateVideoOutput(
        producer, metaFormat, profile.GetSize().width, profile.GetSize().height, streamPtr);
    if (retCode != CAMERA_OK) {
        MEDIA_ERR_LOG("CameraManager::CreateVideoOutputStream Failed to get stream capture object from hcamera "
                      "service! %{public}d",
            retCode);
        return ServiceToCameraError(retCode);
    }
    return CameraErrorCode::SUCCESS;
}

int CameraManager::CreateVideoOutputWithoutProfile(sptr<Surface>& surface, sptr<VideoOutput>* pVideoOutput)
{
    CAMERA_SYNC_TRACE;
    sptr<VideoOutput> videoOutput = nullptr;
    auto serviceProxy = GetServiceProxy();
    if ((serviceProxy == nullptr) || (surface == nullptr)) {
        MEDIA_ERR_LOG("CameraManager::CreateVideoOutput serviceProxy is null or VideoOutputSurface is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    videoOutput = new (std::nothrow) VideoOutput(surface->GetProducer());
    if (videoOutput == nullptr) {
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    videoOutput->AddTag(CaptureOutput::DYNAMIC_PROFILE);
    *pVideoOutput = videoOutput;
    return CameraErrorCode::SUCCESS;
}

int CameraManager::CreateVideoOutput(VideoProfile &profile, sptr<Surface> &surface, sptr<VideoOutput> *pVideoOutput)
{
    CAMERA_SYNC_TRACE;
    sptr<IStreamRepeat> streamRepeat = nullptr;
    sptr<VideoOutput> videoOutput = nullptr;
    int32_t retCode = CAMERA_OK;
    camera_format_t metaFormat;

    auto serviceProxy = GetServiceProxy();
    if ((serviceProxy == nullptr) || (surface == nullptr)) {
        MEDIA_ERR_LOG("serviceProxy is null or VideoOutputSurface/profile is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    if ((profile.GetCameraFormat() == CAMERA_FORMAT_INVALID) ||
        (profile.GetSize().width == 0) ||
        (profile.GetSize().height == 0)) {
        MEDIA_ERR_LOG("width or height is zero");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    metaFormat = GetCameraMetadataFormat(profile.GetCameraFormat());
    MEDIA_DEBUG_LOG("metaFormat = %{public}d", static_cast<int32_t>(metaFormat));
    retCode = serviceProxy->CreateVideoOutput(
        surface->GetProducer(), metaFormat, profile.GetSize().width, profile.GetSize().height, streamRepeat);
    if (retCode == CAMERA_OK) {
        videoOutput = new(std::nothrow) VideoOutput(surface->GetProducer());
        if (videoOutput == nullptr) {
            return CameraErrorCode::SERVICE_FATL_ERROR;
        }
        videoOutput->SetStream(streamRepeat);
        videoOutput->SetOutputFormat(profile.GetCameraFormat());
        videoOutput->SetSize(profile.GetSize());
        videoOutput->SetVideoProfile(profile);
    } else {
        MEDIA_ERR_LOG("Failed to get stream repeat object from hcamera service! %{public}d", retCode);
        return ServiceToCameraError(retCode);
    }

    *pVideoOutput = videoOutput;

    return CameraErrorCode::SUCCESS;
}

void CameraManager::InitCameraManager()
{
    CAMERA_SYNC_TRACE;
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        MEDIA_ERR_LOG("Failed to get System ability manager");
        return;
    }
    object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    if (object == nullptr) {
        MEDIA_ERR_LOG("CameraManager::Init GetSystemAbility %{public}d is null", CAMERA_SERVICE_ID);
        return;
    }
    auto serviceProxy = iface_cast<ICameraService>(object);
    if (serviceProxy == nullptr) {
        MEDIA_ERR_LOG("serviceProxy is null.");
        return;
    }
    SetServiceProxy(serviceProxy);
    int32_t ret = AddServiceProxyDeathRecipient();
    CHECK_AND_RETURN_LOG(ret == CameraErrorCode::SUCCESS, "AddServiceProxyDeathRecipient fail , ret = %{public}d", ret);
    ret = CreateListenerObject();
    CHECK_AND_RETURN_LOG(ret == CAMERA_OK, "failed to new CameraListenerStub, ret = %{public}d", ret);
    ret = SubscribeSystemAbility();
    CHECK_AND_RETURN_LOG(ret == CameraErrorCode::SUCCESS, "failed to SubscribeSystemAbilityd");
    InitCameraList();
}

int32_t CameraManager::SubscribeSystemAbility()
{
    MEDIA_INFO_LOG("Enter Into CameraManager::SubscribeSystemAbility");
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        MEDIA_ERR_LOG("Failed to get System ability manager");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    saListener_ = new CameraServiceSystemAbilityListener();
    if (saListener_ == nullptr) {
        MEDIA_ERR_LOG("saListener_ is null");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    int32_t ret = samgr->SubscribeSystemAbility(CAMERA_SERVICE_ID, saListener_);
    MEDIA_INFO_LOG("SubscribeSystemAbility ret = %{public}d", ret);
    return ret == 0 ? CameraErrorCode::SUCCESS : CameraErrorCode::SERVICE_FATL_ERROR;
}

int32_t CameraManager::UnSubscribeSystemAbility()
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        MEDIA_ERR_LOG("Failed to get System ability manager");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    if (saListener_ == nullptr) {
        return CameraErrorCode::SUCCESS;
    }
    int32_t ret = samgr->UnSubscribeSystemAbility(CAMERA_SERVICE_ID, saListener_);
    MEDIA_INFO_LOG("UnSubscribeSystemAbility ret = %{public}d", ret);
    saListener_ = nullptr;
    return ret == 0 ? CameraErrorCode::SUCCESS : CameraErrorCode::SERVICE_FATL_ERROR;
}

void CameraManager::OnCameraServerAlive()
{
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        MEDIA_ERR_LOG("Failed to get System ability manager");
        return;
    }
    object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    if (object == nullptr) {
        MEDIA_ERR_LOG("CameraManager::Init GetSystemAbility %{public}d is null", CAMERA_SERVICE_ID);
        return;
    }
    auto serviceProxy = iface_cast<ICameraService>(object);
    if (serviceProxy == nullptr) {
        MEDIA_ERR_LOG("serviceProxy is null.");
        return;
    }
    SetServiceProxy(serviceProxy);
    AddServiceProxyDeathRecipient();

    if (cameraSvcCallback_ != nullptr) {
        SetCameraServiceCallback(cameraSvcCallback_);
    }
    if (cameraMuteSvcCallback_ != nullptr) {
        SetCameraMuteServiceCallback(cameraMuteSvcCallback_);
    }
    if (torchSvcCallback_ != nullptr) {
        SetTorchServiceCallback(torchSvcCallback_);
    }
}

int32_t CameraManager::DestroyStubObj()
{
    MEDIA_INFO_LOG("Enter Into CameraManager::DestroyStubObj");
    UnSubscribeSystemAbility();
    int32_t retCode = CAMERA_UNKNOWN_ERROR;
    auto serviceProxy = GetServiceProxy();
    if (serviceProxy == nullptr) {
        MEDIA_ERR_LOG("serviceProxy is null");
    } else {
        retCode = serviceProxy->DestroyStubObj();
        if (retCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to DestroyStubObj, retCode: %{public}d", retCode);
        }
    }
    return ServiceToCameraError(retCode);
}

void CameraManager::CameraServerDied(pid_t pid)
{
    MEDIA_ERR_LOG("camera server has died, pid:%{public}d!", pid);
    RemoveServiceProxyDeathRecipient();
    SetServiceProxy(nullptr);
    if (cameraSvcCallback_ != nullptr) {
        MEDIA_DEBUG_LOG("cameraSvcCallback_ not nullptr");
        std::lock_guard<std::recursive_mutex> lock(cameraListMutex_);
        for (size_t i = 0; i < cameraObjList_.size(); i++) {
            CameraStatusInfo cameraStatusInfo;
            cameraStatusInfo.cameraDevice = cameraObjList_[i];
            cameraStatusInfo.cameraStatus = CAMERA_SERVER_UNAVAILABLE;
            auto listenerMap = GetCameraMngrCallbackMap();
            listenerMap.Iterate([&](std::thread::id threadId,
                std::shared_ptr<CameraManagerCallback> cameraManagerCallback) {
                MEDIA_INFO_LOG("Callback cameraStatus");
                cameraManagerCallback->OnCameraStatusChanged(cameraStatusInfo);
            });
        }
    }
}

int32_t CameraManager::AddServiceProxyDeathRecipient()
{
    std::lock_guard<std::mutex> lock(deathRecipientMutex_);
    pid_t pid = 0;
    deathRecipient_ = new (std::nothrow) CameraDeathRecipient(pid);
    if (deathRecipient_ == nullptr) {
        MEDIA_ERR_LOG("CameraManager::AddServiceProxyDeathRecipient failed to new CameraDeathRecipient");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    deathRecipient_->SetNotifyCb([this](pid_t pid) {
        this->CameraServerDied(pid);
    });
    auto serviceProxy = GetServiceProxy();
    CHECK_AND_RETURN_RET_LOG(serviceProxy != nullptr, CameraErrorCode::SERVICE_FATL_ERROR, "serviceProxy is null");
    bool result = serviceProxy->AsObject()->AddDeathRecipient(deathRecipient_);
    if (!result) {
        MEDIA_ERR_LOG("failed to add deathRecipient");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    return CameraErrorCode::SUCCESS;
}

void CameraManager::RemoveServiceProxyDeathRecipient()
{
    std::lock_guard<std::mutex> lock(deathRecipientMutex_);
    auto serviceProxy = GetServiceProxy();
    if (serviceProxy != nullptr) {
        (void)serviceProxy->AsObject()->RemoveDeathRecipient(deathRecipient_);
    }
    deathRecipient_ = nullptr;
}

int CameraManager::CreateCameraDevice(std::string cameraId, sptr<ICameraDeviceService> *pICameraDeviceService)
{
    CAMERA_SYNC_TRACE;
    sptr<ICameraDeviceService> device = nullptr;
    int32_t retCode = CAMERA_OK;
    auto serviceProxy = GetServiceProxy();
    if (serviceProxy == nullptr || cameraId.empty()) {
        MEDIA_ERR_LOG("serviceProxy is null or CameraID is empty: %{public}s", cameraId.c_str());
        return CameraErrorCode::INVALID_ARGUMENT;
    }
    retCode = serviceProxy->CreateCameraDevice(cameraId, device);
    if (retCode != CAMERA_OK) {
        MEDIA_ERR_LOG("ret value from CreateCameraDevice, %{public}d", retCode);
        return ServiceToCameraError(retCode);
    }

    *pICameraDeviceService = device;

    return CameraErrorCode::SUCCESS;
}

void CameraManager::SetCallback(std::shared_ptr<CameraManagerCallback> callback)
{
    if (cameraSvcCallback_ == nullptr) {
        CreateAndSetCameraServiceCallback();
    }
    std::thread::id threadId = std::this_thread::get_id();
    cameraMngrCallbackMap_.EnsureInsert(threadId, callback);
}

std::shared_ptr<CameraManagerCallback> CameraManager::GetApplicationCallback()
{
    std::thread::id threadId = std::this_thread::get_id();
    std::shared_ptr<CameraManagerCallback> callback = nullptr;
    cameraMngrCallbackMap_.Find(threadId, callback);
    return callback;
}

void CameraManager::RegisterCameraMuteListener(std::shared_ptr<CameraMuteListener> listener)
{
    if (cameraMuteSvcCallback_ == nullptr) {
        CreateAndSetCameraMuteServiceCallback();
    }
    std::thread::id threadId = std::this_thread::get_id();
    cameraMuteListenerMap_.EnsureInsert(threadId, listener);
}

shared_ptr<CameraMuteListener> CameraManager::GetCameraMuteListener()
{
    std::thread::id threadId = std::this_thread::get_id();
    std::shared_ptr<CameraMuteListener> listener = nullptr;
    cameraMuteListenerMap_.Find(threadId, listener);
    return listener;
}

void CameraManager::RegisterTorchListener(shared_ptr<TorchListener> listener)
{
    if (torchSvcCallback_ == nullptr) {
        CreateAndSetTorchServiceCallback();
    }
    std::thread::id threadId = std::this_thread::get_id();
    torchListenerMap_.EnsureInsert(threadId, listener);
}

shared_ptr<TorchListener> CameraManager::GetTorchListener()
{
    std::thread::id threadId = std::this_thread::get_id();
    std::shared_ptr<TorchListener> listener = nullptr;
    torchListenerMap_.Find(threadId, listener);
    return listener;
}

SafeMap<std::thread::id, std::shared_ptr<CameraManagerCallback>> CameraManager::GetCameraMngrCallbackMap()
{
    return cameraMngrCallbackMap_;
}
SafeMap<std::thread::id, std::shared_ptr<CameraMuteListener>> CameraManager::GetCameraMuteListenerMap()
{
    return cameraMuteListenerMap_;
}
SafeMap<std::thread::id, std::shared_ptr<TorchListener>> CameraManager::GetTorchListenerMap()
{
    return torchListenerMap_;
}

sptr<CameraDevice> CameraManager::GetCameraDeviceFromId(std::string cameraId)
{
    sptr<CameraDevice> cameraObj = nullptr;
    std::lock_guard<std::recursive_mutex> lock(cameraListMutex_);
    for (size_t i = 0; i < cameraObjList_.size(); i++) {
        if (cameraObjList_[i]->GetID() == cameraId) {
            cameraObj = cameraObjList_[i];
            break;
        }
    }
    return cameraObj;
}

sptr<CameraManager>& CameraManager::GetInstance()
{
    if (CameraManager::g_cameraManager == nullptr) {
        std::lock_guard<std::mutex> lock(g_instanceMutex);
        if (CameraManager::g_cameraManager == nullptr) {
            MEDIA_INFO_LOG("Initializing camera manager for first time!");
            CameraManager::g_cameraManager = new (std::nothrow) CameraManager();
            CameraManager::g_cameraManager->InitCameraManager();
        }
    }
    return CameraManager::g_cameraManager;
}

std::vector<sptr<CameraInfo>> CameraManager::GetCameras()
{
    CAMERA_SYNC_TRACE;
    dcameraObjList_.clear();
    return dcameraObjList_;
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

void CameraManager::InitCameraList()
{
    CAMERA_SYNC_TRACE;
    auto serviceProxy = GetServiceProxy();
    if (serviceProxy == nullptr) {
        MEDIA_ERR_LOG("serviceProxy is null, returning empty list!");
        return;
    }
    std::vector<std::string> cameraIds;
    std::lock_guard<std::recursive_mutex> lock(cameraListMutex_);
    cameraObjList_.clear();
    GetDmDeviceInfo();
    int32_t retCode = serviceProxy->GetCameraIds(cameraIds);
    if (retCode == CAMERA_OK) {
        for (auto& cameraId : cameraIds) {
            std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility;
            retCode = serviceProxy->GetCameraAbility(cameraId, cameraAbility);
            if (retCode != CAMERA_OK) {
                continue;
            }

            dmDeviceInfo tempDmDeviceInfo;
            if (isDistributeCamera(cameraId, tempDmDeviceInfo)) {
                MEDIA_DEBUG_LOG("CameraManager::it is remoted camera");
            } else {
                tempDmDeviceInfo.deviceName = "";
                tempDmDeviceInfo.deviceTypeId = 0;
                tempDmDeviceInfo.networkId = "";
            }
            sptr<CameraDevice> cameraObj =
                new(std::nothrow) CameraDevice(cameraId, cameraAbility, tempDmDeviceInfo);
            cameraObjList_.emplace_back(cameraObj);
        }
    } else {
        MEDIA_ERR_LOG("Get camera device failed!, retCode: %{public}d", retCode);
    }

    AlignVideoFpsProfile(cameraObjList_);
}

std::vector<sptr<CameraDevice>> CameraManager::GetSupportedCameras()
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::recursive_mutex> lock(cameraListMutex_);
    return cameraObjList_;
}

std::vector<SceneMode> CameraManager::GetSupportedModes(sptr<CameraDevice>& camera)
{
    std::vector<SceneMode> supportedModes = {};

    std::shared_ptr<Camera::CameraMetadata> metadata = camera->GetMetadata();
    if (metadata == nullptr) {
        return supportedModes;
    }
    camera_metadata_item_t item;
    int32_t ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_CAMERA_MODES, &item);
    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG("CaptureSession::GetSupportedModes Failed with return code %{public}d", ret);
        return supportedModes;
    }
    for (uint32_t i = 0; i < item.count; i++) {
        auto itr = g_metaToFwSupportedMode_.find(static_cast<OperationMode>(item.data.u8[i]));
        if (itr != g_metaToFwSupportedMode_.end()) {
            supportedModes.emplace_back(itr->second);
        }
    }
    MEDIA_INFO_LOG("CameraManager::GetSupportedModes supportedModes size: %{public}zu", supportedModes.size());
    return supportedModes;
}

void CameraManager::AlignVideoFpsProfile(std::vector<sptr<CameraDevice>>& cameraObjList)
{
    MEDIA_ERR_LOG("CameraManager::AlignVideoFpsProfile enter");
    uint32_t normalMode = 0;
    int32_t alignFps = 60;
    std::vector<VideoProfile> frontVideoProfiles = {};
    std::vector<VideoProfile> backVideoProfiles = {};
    sptr<CameraDevice> frontCamera = nullptr;
    for (auto& camera : cameraObjList) {
        SetProfile(camera);
        if (camera->GetPosition() == CAMERA_POSITION_FRONT) {
            frontVideoProfiles = camera->modeVideoProfiles_[normalMode];
            frontCamera = camera;
        } else if (camera->GetPosition() == CAMERA_POSITION_BACK) {
            backVideoProfiles = camera->modeVideoProfiles_[normalMode];
        }
    }
    const uint32_t minIndex = 0;
    const uint32_t maxIndex = 1;
    if (!(frontVideoProfiles.size() && backVideoProfiles.size())) {
        MEDIA_ERR_LOG("CameraManager::AlignVideoFpsProfile failed! frontVideoSize = %{public}zu, "
                      "frontVideoSize = %{public}zu", frontVideoProfiles.size(), backVideoProfiles.size());
        return;
    }
    std::vector<VideoProfile> alignFrontVideoProfiles = frontVideoProfiles;
    for (auto &backProfile : backVideoProfiles) {
        for (auto &frontProfile : frontVideoProfiles) {
            if (backProfile.GetSize().width == frontProfile.GetSize().width &&
                backProfile.GetSize().height == frontProfile.GetSize().height) {
                if (backProfile.framerates_[minIndex] == alignFps && backProfile.framerates_[maxIndex] == alignFps) {
                    alignFrontVideoProfiles.push_back(backProfile);
                    MEDIA_INFO_LOG("CameraManager::AlignVideoFpsProfile backProfile w(%{public}d),h(%{public}d), "
                                   "frontProfile w(%{public}d),h(%{public}d)",
                                   backProfile.GetSize().width, backProfile.GetSize().height,
                                   frontProfile.GetSize().width, frontProfile.GetSize().height);
                }
            }
        }
    }
    if (frontCamera) {
        frontCamera->modeVideoProfiles_[normalMode] = alignFrontVideoProfiles;
        for (auto &frontProfile : alignFrontVideoProfiles) {
            MEDIA_INFO_LOG("CameraManager::AlignVideoFpsProfile frontProfile "
                           "w(%{public}d),h(%{public}d) fps min(%{public}d),min(%{public}d)",
                           frontProfile.GetSize().width, frontProfile.GetSize().height,
                           frontProfile.framerates_[minIndex], frontProfile.framerates_[maxIndex]);
        }
    }
}

void CameraManager::SetProfile(sptr<CameraDevice>& cameraObj)
{
    if (cameraObj == nullptr) {
        return;
    }
    std::vector<SceneMode> supportedModes = GetSupportedModes(cameraObj);
    sptr<CameraOutputCapability> capability = nullptr;
    if (supportedModes.empty()) {
        capability = GetSupportedOutputCapability(cameraObj);
        if (capability != nullptr) {
            cameraObj->modePreviewProfiles_[NORMAL] = capability->GetPreviewProfiles();
            cameraObj->modePhotoProfiles_[NORMAL] = capability->GetPhotoProfiles();
            cameraObj->modeVideoProfiles_[NORMAL] = capability->GetVideoProfiles();
            cameraObj->modePreviewProfiles_[CAPTURE] = capability->GetPreviewProfiles();
            cameraObj->modePhotoProfiles_[CAPTURE] = capability->GetPhotoProfiles();
            cameraObj->modePreviewProfiles_[VIDEO] = capability->GetPreviewProfiles();
            cameraObj->modePhotoProfiles_[VIDEO] = capability->GetPhotoProfiles();
            cameraObj->modeVideoProfiles_[VIDEO] = capability->GetVideoProfiles();
        }
    } else {
        supportedModes.emplace_back(NORMAL);
        for (const auto &modeName : supportedModes) {
            capability = GetSupportedOutputCapability(cameraObj, modeName);
            if (capability != nullptr) {
                cameraObj->modePreviewProfiles_[modeName] = capability->GetPreviewProfiles();
                cameraObj->modePhotoProfiles_[modeName] = capability->GetPhotoProfiles();
                cameraObj->modeVideoProfiles_[modeName] = capability->GetVideoProfiles();
            }
        }
    }
}

SceneMode CameraManager::GetFallbackConfigMode(SceneMode profileMode)
{
    MEDIA_INFO_LOG("CameraManager::GetFallbackConfigMode profileMode:%{public}d", profileMode);
    if (photoProfiles_.empty() && previewProfiles_.empty() && vidProfiles_.empty()) {
        switch (profileMode) {
            case CAPTURE_MACRO:
                return CAPTURE;
            case VIDEO_MACRO:
                return VIDEO;
            default:
                return profileMode;
        }
    }
    return profileMode;
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
    std::lock_guard<std::recursive_mutex> lock(cameraListMutex_);
    for (size_t i = 0; i < cameraObjList_.size(); i++) {
        if ((cameraObjList_[i]->GetPosition() == position) && (cameraObjList_[i]->GetCameraType() == cameraType)) {
            cameraInput = CreateCameraInput(cameraObjList_[i]);
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

bool g_isCapabilitySupported(std::shared_ptr<OHOS::Camera::CameraMetadata> metadata,
    camera_metadata_item_t &item, uint32_t metadataTag)
{
    if (metadata == nullptr) {
        return false;
    }
    bool isSupport = true;
    int32_t retCode = Camera::FindCameraMetadataItem(metadata->get(), metadataTag, &item);
    if (retCode != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG("Failed get metadata info tag = %{public}d, retCode = %{public}d, count = %{public}d",
            metadataTag, retCode, item.count);
        isSupport = false;
    }
    return isSupport;
}

void CameraManager::ParseBasicCapability(
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata, const camera_metadata_item_t& item)
{
    if (metadata == nullptr) {
        return;
    }
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
        size.width = static_cast<uint32_t>(item.data.i32[i + widthOffset]);
        size.height = static_cast<uint32_t>(item.data.i32[i + heightOffset]);
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

void CameraManager::ParseExtendCapability(const int32_t modeName, const camera_metadata_item_t& item)
    __attribute__((no_sanitize("cfi")))
{
    ExtendInfo extendInfo = {};
    std::shared_ptr<CameraStreamInfoParse> modeStreamParse = std::make_shared<CameraStreamInfoParse>();
    modeStreamParse->getModeInfo(item.data.i32, item.count, extendInfo); // 解析tag中带的数据信息意义
    if (modeName == SceneMode::VIDEO) {
        for (uint32_t i = 0; i < extendInfo.modeCount; i++) {
            if (SceneMode::HIGH_FRAME_RATE == extendInfo.modeInfo[i].modeName) {
                for (uint32_t j = 0; j < extendInfo.modeInfo[i].streamTypeCount; j++) {
                    OutputCapStreamType streamType =
                        static_cast<OutputCapStreamType>(extendInfo.modeInfo[i].streamInfo[j].streamType);
                    CreateProfile4StreamType(streamType, i, j, extendInfo);
                }
                break;
            }
        }
    }
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

void CameraManager::ParseCapability(sptr<CameraDevice>& camera, const int32_t modeName, camera_metadata_item_t& item,
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata)
{
    if (g_isCapabilitySupported(metadata, item, OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS)) {
        std::vector<SceneMode> supportedModes = GetSupportedModes(camera);
        int32_t mode = (supportedModes.empty() && isTemplateMode_.count(modeName)) ? SceneMode::NORMAL : modeName;
        MEDIA_INFO_LOG(
            "GetSupportedOutputCapability by device = %{public}s, mode = %{public}d", camera->GetID().c_str(), mode);
        ParseExtendCapability(mode, item);
    } else if (g_isCapabilitySupported(metadata, item, OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS)) {
        ParseBasicCapability(metadata, item);
    } else {
        MEDIA_ERR_LOG("Failed get stream info");
    }
}

sptr<CameraOutputCapability> CameraManager::GetSupportedOutputCapability(sptr<CameraDevice>& camera,
    int32_t modeName) __attribute__((no_sanitize("cfi")))
{
    MEDIA_DEBUG_LOG("GetSupportedOutputCapability mode = %{public}d", modeName);
    sptr<CameraOutputCapability> cameraOutputCapability = nullptr;
    cameraOutputCapability = new(std::nothrow) CameraOutputCapability();
    if (camera == nullptr || cameraOutputCapability == nullptr) {
        return nullptr;
    }
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = camera->GetMetadata();
    if (metadata == nullptr) {
        return nullptr;
    }
    camera_metadata_item_t item;
    std::lock_guard<std::mutex> lock(vectorMutex_);
    photoProfiles_.clear();
    previewProfiles_.clear();
    vidProfiles_.clear();

    ParseCapability(camera, modeName, item, metadata);

    SceneMode profileMode = static_cast<SceneMode>(modeName);
    auto fallbackMode = GetFallbackConfigMode(profileMode);
    if (profileMode != fallbackMode) {
        ParseCapability(camera, fallbackMode, item, metadata);
    }

    RemoveDuplicatesProfiles(previewProfiles_);
    cameraOutputCapability->SetPhotoProfiles(photoProfiles_);
    MEDIA_INFO_LOG("SetPhotoProfiles size = %{public}zu", photoProfiles_.size());
    cameraOutputCapability->SetPreviewProfiles(previewProfiles_);
    MEDIA_INFO_LOG("SetPreviewProfiles size = %{public}zu", previewProfiles_.size());
    if (!isPhotoMode_.count(modeName)) {
        cameraOutputCapability->SetVideoProfiles(vidProfiles_);
    }
    MEDIA_INFO_LOG("SetVideoProfiles size = %{public}zu", vidProfiles_.size());
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

    return cameraOutputCapability;
}

void CameraManager::CreateProfile4StreamType(OutputCapStreamType streamType, uint32_t modeIndex,
    uint32_t streamIndex, ExtendInfo extendInfo) __attribute__((no_sanitize("cfi")))
{
    const int frameRate120 = 120;
    const int frameRate240 = 240;
    for (uint32_t k = 0; k < extendInfo.modeInfo[modeIndex].streamInfo[streamIndex].detailInfoCount; k++) {
        const auto& detailInfo = extendInfo.modeInfo[modeIndex].streamInfo[streamIndex].detailInfo[k];
        // Skip profiles with unsupported frame rates for non-system apps
        if ((detailInfo.minFps == frameRate120 || detailInfo.minFps == frameRate240) &&
            streamType == OutputCapStreamType::VIDEO_STREAM && !CameraSecurity::CheckSystemApp()) {
            continue;
        }
        CameraFormat format = CAMERA_FORMAT_INVALID;
        auto itr = metaToFwCameraFormat_.find(static_cast<camera_format_t>(detailInfo.format));
        if (itr != metaToFwCameraFormat_.end()) {
            format = itr->second;
        } else {
            MEDIA_ERR_LOG("CreateProfile4StreamType failed format = %{public}d",
                extendInfo.modeInfo[modeIndex].streamInfo[streamIndex].detailInfo[k].format);
            format = CAMERA_FORMAT_INVALID;
            continue;
        }
        Size size{static_cast<uint32_t>(detailInfo.width), static_cast<uint32_t>(detailInfo.height)};
        Fps fps{static_cast<uint32_t>(detailInfo.fixedFps), static_cast<uint32_t>(detailInfo.minFps),
            static_cast<uint32_t>(detailInfo.maxFps)};
        std::vector<uint32_t> abilityId = detailInfo.abilityId;
        std::string abilityIds = Container2String(abilityId.begin(), abilityId.end());
        if (streamType == OutputCapStreamType::PREVIEW) {
            Profile previewProfile = Profile(format, size, fps, abilityId);
            MEDIA_DEBUG_LOG("preview format : %{public}d, width: %{public}d, height: %{public}d"
                            "support ability: %{public}s, streamType: %{public}d, fixedFps: %{public}d,"
                            " minFps: %{public}d, maxFps: %{public}d",
                            previewProfile.GetCameraFormat(), previewProfile.GetSize().width,
                            previewProfile.GetSize().height, abilityIds.c_str(), streamType, fps.fixedFps, fps.minFps,
                            fps.maxFps);
            previewProfile.fps_.fixedFps = fps.fixedFps;
            previewProfile.fps_.minFps = fps.minFps;
            previewProfile.fps_.maxFps = fps.maxFps;
            previewProfiles_.push_back(previewProfile);
        } else if (streamType == OutputCapStreamType::STILL_CAPTURE) {
            Profile snapProfile = Profile(format, size, fps, abilityId);
            MEDIA_DEBUG_LOG("photo format : %{public}d, width: %{public}d, height: %{public}d"
                            "support ability: %{public}s",
                            snapProfile.GetCameraFormat(), snapProfile.GetSize().width,
                            snapProfile.GetSize().height, abilityIds.c_str());
            photoProfiles_.push_back(snapProfile);
        } else if (streamType == OutputCapStreamType::VIDEO_STREAM) {
            std::vector<int32_t> frameRates = {fps.minFps, fps.maxFps};
            VideoProfile vidProfile = VideoProfile(format, size, frameRates);
            MEDIA_DEBUG_LOG("video format : %{public}d, width: %{public}d, height: %{public}d"
                            "support ability: %{public}s",
                            vidProfile.GetCameraFormat(), vidProfile.GetSize().width,
                            vidProfile.GetSize().height, abilityIds.c_str());
            vidProfiles_.push_back(vidProfile);
        }
    }
}

void CameraManager::CreateAndSetCameraServiceCallback()
{
    if (cameraSvcCallback_ != nullptr) {
        MEDIA_ERR_LOG("cameraSvcCallback_ is not nullptr");
        return;
    }
    auto serviceProxy = GetServiceProxy();
    if (serviceProxy == nullptr) {
        MEDIA_ERR_LOG("serviceProxy is null");
        return;
    }
    int32_t retCode = CAMERA_OK;
    cameraSvcCallback_ = new(std::nothrow) CameraStatusServiceCallback(this);
    retCode = serviceProxy->SetCameraCallback(cameraSvcCallback_);
    if (retCode != CAMERA_OK) {
        MEDIA_ERR_LOG("Set CameraStatus service Callback failed, retCode: %{public}d", retCode);
    }
}

void CameraManager::SetCameraServiceCallback(sptr<ICameraServiceCallback>& callback)
{
    int32_t retCode = CAMERA_OK;
    auto serviceProxy = GetServiceProxy();
    if (serviceProxy == nullptr) {
        MEDIA_ERR_LOG("serviceProxy_ is null");
        return;
    }
    retCode = serviceProxy->SetCameraCallback(callback);
    if (retCode != CAMERA_OK) {
        MEDIA_ERR_LOG("Set service Callback failed, retCode: %{public}d", retCode);
    }
    return;
}

camera_format_t CameraManager::GetCameraMetadataFormat(CameraFormat format)
{
    camera_format_t metaFormat = OHOS_CAMERA_FORMAT_YCRCB_420_SP;
    MEDIA_DEBUG_LOG("format = %{public}d", static_cast<int32_t>(format));

    auto itr = fwToMetaCameraFormat_.find(format);
    if (itr != fwToMetaCameraFormat_.end()) {
        metaFormat = itr->second;
    }
    MEDIA_DEBUG_LOG("metaFormat = %{public}d", static_cast<int32_t>(metaFormat));
    return metaFormat;
}

int32_t TorchServiceCallback::OnTorchStatusChange(const TorchStatus status)
{
    MEDIA_DEBUG_LOG("TorchStatus is %{public}d", status);
    auto cameraManager = cameraManager_.promote();
    if (cameraManager == nullptr) {
        MEDIA_INFO_LOG("cameraManager is nullptr");
        return CAMERA_OK;
    }

    TorchStatusInfo torchStatusInfo;
    if (status == TorchStatus::TORCH_STATUS_UNAVAILABLE) {
        torchStatusInfo.isTorchAvailable = false;
        torchStatusInfo.isTorchActive = false;
        torchStatusInfo.torchLevel = 0;
        cameraManager->UpdateTorchMode(TORCH_MODE_OFF);
    } else if (status == TorchStatus::TORCH_STATUS_ON) {
        torchStatusInfo.isTorchAvailable = true;
        torchStatusInfo.isTorchActive = true;
        torchStatusInfo.torchLevel = 1;
        cameraManager->UpdateTorchMode(TORCH_MODE_ON);
    } else if (status == TorchStatus::TORCH_STATUS_OFF) {
        torchStatusInfo.isTorchAvailable = true;
        torchStatusInfo.isTorchActive = false;
        torchStatusInfo.torchLevel = 0;
        cameraManager->UpdateTorchMode(TORCH_MODE_OFF);
    }

    auto listenerMap = cameraManager->GetTorchListenerMap();
    MEDIA_DEBUG_LOG("TorchListenerMap size %{public}d", listenerMap.Size());
    if (listenerMap.IsEmpty()) {
        return CAMERA_OK;
    }

    listenerMap.Iterate([&](std::thread::id threadId, std::shared_ptr<TorchListener> torchListener) {
        if (torchListener != nullptr) {
            torchListener->OnTorchStatusChange(torchStatusInfo);
        } else {
            std::ostringstream oss;
            oss << threadId;
            MEDIA_INFO_LOG(
                "OnTorchStatusChange not registered!, Ignore the callback: thread:%{public}s", oss.str().c_str());
        }
    });
    return CAMERA_OK;
}

void CameraManager::SetTorchServiceCallback(sptr<ITorchServiceCallback>& callback)
{
    int32_t retCode = CAMERA_OK;
    auto serviceProxy = GetServiceProxy();
    if (serviceProxy == nullptr) {
        MEDIA_ERR_LOG("serviceProxy is null");
        return;
    }
    retCode = serviceProxy->SetTorchCallback(callback);
    if (retCode != CAMERA_OK) {
        MEDIA_ERR_LOG("Set Mute service Callback failed, retCode: %{public}d", retCode);
    }
    return;
}

void CameraManager::CreateAndSetTorchServiceCallback()
{
    if (torchSvcCallback_ != nullptr) {
        MEDIA_ERR_LOG("torchSvcCallback_ is not nullptr");
        return;
    }
    auto serviceProxy = GetServiceProxy();
    if (serviceProxy == nullptr) {
        MEDIA_ERR_LOG("serviceProxy is null");
        return;
    }
    int32_t retCode = CAMERA_OK;
    torchSvcCallback_ = new(std::nothrow) TorchServiceCallback(this);
    retCode = serviceProxy->SetTorchCallback(torchSvcCallback_);
    if (retCode != CAMERA_OK) {
        MEDIA_ERR_LOG("Set Torch service Callback failed, retCode: %{public}d", retCode);
    }
}

int32_t CameraMuteServiceCallback::OnCameraMute(bool muteMode)
{
    MEDIA_DEBUG_LOG("muteMode is %{public}d", muteMode);
    auto cameraManager = cameraManager_.promote();
    if (cameraManager == nullptr) {
        MEDIA_INFO_LOG("cameraManager is nullptr");
        return CAMERA_OK;
    }
    auto listenerMap = cameraManager->GetCameraMuteListenerMap();
    MEDIA_DEBUG_LOG("CameraMuteListenerMap size %{public}d", listenerMap.Size());
    if (listenerMap.IsEmpty()) {
        return CAMERA_OK;
    }
    listenerMap.Iterate([&](std::thread::id threadId, std::shared_ptr<CameraMuteListener> cameraMuteListener) {
        if (cameraMuteListener != nullptr) {
            cameraMuteListener->OnCameraMute(muteMode);
        } else {
            std::ostringstream oss;
            oss << threadId;
            MEDIA_INFO_LOG("OnCameraMute not registered!, Ignore the callback: thread:%{public}s", oss.str().c_str());
        }
    });
    return CAMERA_OK;
}

void CameraManager::CreateAndSetCameraMuteServiceCallback()
{
    if (cameraMuteSvcCallback_ != nullptr) {
        MEDIA_ERR_LOG("cameraMuteSvcCallback_ is not nullptr");
        return;
    }
    auto serviceProxy = GetServiceProxy();
    if (serviceProxy == nullptr) {
        MEDIA_ERR_LOG("serviceProxy is null");
        return;
    }
    int32_t retCode = CAMERA_OK;
    cameraMuteSvcCallback_ = new(std::nothrow) CameraMuteServiceCallback(this);
    retCode = serviceProxy->SetMuteCallback(cameraMuteSvcCallback_);
    if (retCode != CAMERA_OK) {
        MEDIA_ERR_LOG("Set Mute service Callback failed, retCode: %{public}d", retCode);
    }
}

void CameraManager::SetCameraMuteServiceCallback(sptr<ICameraMuteServiceCallback>& callback)
{
    int32_t retCode = CAMERA_OK;
    auto serviceProxy = GetServiceProxy();
    if (serviceProxy == nullptr) {
        MEDIA_ERR_LOG("serviceProxy is null");
        return;
    }
    retCode = serviceProxy->SetMuteCallback(callback);
    if (retCode != CAMERA_OK) {
        MEDIA_ERR_LOG("Set Mute service Callback failed, retCode: %{public}d", retCode);
    }
    return;
}

bool CameraManager::IsCameraMuteSupported()
{
    bool result = false;
    std::lock_guard<std::recursive_mutex> lock(cameraListMutex_);
    for (size_t i = 0; i < cameraObjList_.size(); i++) {
        std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameraObjList_[i]->GetMetadata();
        if (metadata == nullptr) {
            return false;
        }
        camera_metadata_item_t item;
        int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_MUTE_MODES, &item);
        if (ret != 0) {
            MEDIA_ERR_LOG("Failed to get stream configuration or Invalid stream "
                          "configuation OHOS_ABILITY_MUTE_MODES ret = %{public}d", ret);
            return result;
        }
        for (uint32_t j = 0; j < item.count; j++) {
            MEDIA_INFO_LOG("OHOS_ABILITY_MUTE_MODES %{public}d th is %{public}d", j, item.data.u8[j]);
            if (item.data.u8[j] == OHOS_CAMERA_MUTE_MODE_SOLID_COLOR_BLACK) {
                result = true;
                break;
            }
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
    auto serviceProxy = GetServiceProxy();
    if (serviceProxy == nullptr) {
        MEDIA_ERR_LOG("serviceProxy is null");
        return isMuted;
    }
    retCode = serviceProxy->IsCameraMuted(isMuted);
    if (retCode != CAMERA_OK) {
        MEDIA_ERR_LOG("IsCameraMuted call failed, retCode: %{public}d", retCode);
    }
    return isMuted;
}

void CameraManager::MuteCamera(bool muteMode)
{
    int32_t retCode = CAMERA_OK;
    auto serviceProxy = GetServiceProxy();
    if (serviceProxy == nullptr) {
        MEDIA_ERR_LOG("serviceProxy is null");
        return;
    }
    retCode = serviceProxy->MuteCamera(muteMode);
    if (retCode != CAMERA_OK) {
        MEDIA_ERR_LOG("MuteCamera call failed, retCode: %{public}d", retCode);
    }
}

int32_t CameraManager::MuteCameraPersist(PolicyType policyType, bool muteMode)
{
    int32_t retCode = CAMERA_OK;
    auto serviceProxy = GetServiceProxy();
    if (serviceProxy == nullptr) {
        MEDIA_ERR_LOG("serviceProxy is null");
        return SERVICE_FATL_ERROR;
    }
    retCode = serviceProxy->MuteCameraPersist(policyType, muteMode);
    if (retCode != CAMERA_OK) {
        MEDIA_ERR_LOG("MuteCameraPersist call failed, retCode: %{public}d", retCode);
    }
    return ServiceToCameraError(retCode);
}

int32_t CameraManager::PrelaunchCamera()
{
    auto serviceProxy = GetServiceProxy();
    if (serviceProxy == nullptr) {
        MEDIA_ERR_LOG("CameraManager::PrelaunchCamera serviceProxy is null");
        return SERVICE_FATL_ERROR;
    }
    int32_t retCode = serviceProxy->PrelaunchCamera();
    if (retCode != CAMERA_OK) {
        MEDIA_ERR_LOG("CameraManager::PrelaunchCamera failed, retCode: %{public}d", retCode);
    }
    return ServiceToCameraError(retCode);
}

int32_t CameraManager::PreSwitchCamera(const std::string cameraId)
{
    auto serviceProxy = GetServiceProxy();
    if (serviceProxy == nullptr) {
        MEDIA_ERR_LOG("CameraManager::PreSwitchCamera serviceProxy is null");
        return SERVICE_FATL_ERROR;
    }
    int32_t retCode = serviceProxy->PreSwitchCamera(cameraId);
    if (retCode != CAMERA_OK) {
        MEDIA_ERR_LOG("CameraManager::PreSwitchCamera failed, retCode: %{public}d", retCode);
    }
    return ServiceToCameraError(retCode);
}

bool CameraManager::IsPrelaunchSupported(sptr<CameraDevice> camera)
{
    if (camera == nullptr) {
        return false;
    }
    bool isPrelaunch = false;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = camera->GetMetadata();
    if (metadata == nullptr) {
        return false;
    }
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

bool CameraManager::IsTorchSupported()
{
    std::lock_guard<std::recursive_mutex> lock(cameraListMutex_);
    if (cameraObjList_.empty()) {
        InitCameraList();
    }
    for (size_t i = 0; i < cameraObjList_.size(); i++) {
        std::shared_ptr<Camera::CameraMetadata> metadata = cameraObjList_[i]->GetMetadata();
        if (metadata == nullptr) {
        return false;
    }
        camera_metadata_item_t item;
        int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FLASH_AVAILABLE, &item);
        if (ret == CAM_META_SUCCESS) {
            MEDIA_INFO_LOG("OHOS_ABILITY_FLASH_AVAILABLE is %{public}d", item.data.u8[0]);
            if (item.data.u8[0] == 1) {
                return true;
            }
        }
    }
    return false;
}

bool CameraManager::IsTorchModeSupported(TorchMode mode)
{
    return mode == TorchMode::TORCH_MODE_OFF || mode == TorchMode::TORCH_MODE_ON;
}

TorchMode CameraManager::GetTorchMode()
{
    return torchMode_;
}

int32_t CameraManager::SetTorchMode(TorchMode mode)
{
    int32_t retCode = CAMERA_OPERATION_NOT_ALLOWED;
    int32_t pid = IPCSkeleton::GetCallingPid();
    int32_t uid = IPCSkeleton::GetCallingUid();
    POWERMGR_SYSEVENT_TORCH_STATE(pid, uid, mode);
    switch (mode) {
        case TorchMode::TORCH_MODE_OFF:
            retCode = SetTorchLevel(0);
            break;
        case TorchMode::TORCH_MODE_ON:
            retCode = SetTorchLevel(1);
            break;
        case TorchMode::TORCH_MODE_AUTO:
            MEDIA_ERR_LOG("Invalid or unsupported torchMode value received from application");
            break;
        default:
            MEDIA_ERR_LOG("Invalid or unsupported torchMode value received from application");
    }
    if (retCode == CAMERA_OK) {
        UpdateTorchMode(mode);
    }
    return ServiceToCameraError(retCode);
}

void CameraManager::UpdateTorchMode(TorchMode mode)
{
    if (torchMode_ == mode) {
        return;
    }
    torchMode_ = mode;
    MEDIA_INFO_LOG("CameraManager::UpdateTorchMode() mode is %{public}d", mode);
}

int32_t CameraManager::SetTorchLevel(float level)
{
    auto serviceProxy = GetServiceProxy();
    if (serviceProxy == nullptr) {
        MEDIA_ERR_LOG("CameraManager::SetTorchLevel serviceProxy is null");
        return SERVICE_FATL_ERROR;
    }
    int32_t retCode = serviceProxy->SetTorchLevel(level);
    if (retCode != CAMERA_OK) {
        MEDIA_ERR_LOG("CameraManager::SetTorchLevel failed, retCode: %{public}d", retCode);
    }
    return retCode;
}

int32_t CameraManager::SetPrelaunchConfig(
    std::string cameraId, RestoreParamTypeOhos restoreParamType, int activeTime, EffectParam effectParam)
{
    auto serviceProxy = GetServiceProxy();
    if (serviceProxy == nullptr) {
        MEDIA_ERR_LOG("CameraManager::SetPrelaunchConfig serviceProxy is null");
        return SERVICE_FATL_ERROR;
    }
    int32_t retCode = serviceProxy->SetPrelaunchConfig(
        cameraId, static_cast<RestoreParamTypeOhos>(restoreParamType), activeTime, effectParam);
    if (retCode != CAMERA_OK) {
        MEDIA_ERR_LOG("CameraManager::SetPrelaunchConfig failed, retCode: %{public}d", retCode);
    }
    return ServiceToCameraError(retCode);
}

void CameraManager::SetCameraManagerNull()
{
    MEDIA_INFO_LOG("CameraManager::SetCameraManagerNull() called");
    g_cameraManager = nullptr;
}

void CameraManager::RemoveDuplicatesProfiles(std::vector<Profile>& profiles)
{
    std::vector<Profile> uniqueProfiles;
    for (const auto& profile : profiles) {
        if (std::find(uniqueProfiles.begin(), uniqueProfiles.end(), profile) == uniqueProfiles.end()) {
            uniqueProfiles.push_back(profile);
        }
    }
    profiles = uniqueProfiles;
}
} // namespace CameraStandard
} // namespace OHOS
