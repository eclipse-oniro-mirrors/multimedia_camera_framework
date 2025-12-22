/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <ostream>
#include <parameters.h>
#include <regex>
#include <sstream>
#include <unordered_map>

#include "ability/camera_ability_parse_util.h"
#include "bundle_mgr_interface.h"
#include "camera_counting_timer.h"
#include "camera_device.h"
#include "camera_device_ability_items.h"
#include "camera_error_code.h"
#include "camera_input.h"
#include "camera_log.h"
#include "camera_rotation_api_utils.h"
#include "camera_security_utils.h"
#include "camera_service_system_ability_listener.h"
#include "camera_util.h"
#include "capture_input.h"
#include "capture_scene_const.h"
#include "control_center_session.h"
#include "deferred_photo_proc_session.h"
#include "display_manager.h"
#include "icamera_service_callback.h"
#include "icamera_util.h"
#include "icapture_session.h"
#include "icontrol_center_status_callback.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "istream_capture.h"
#include "refbase.h"
#include "session/capture_session.h"
#include "session/photo_session.h"
#include "session/scan_session.h"
#include "session/secure_camera_session.h"
#include "session/video_session.h"
#include "system_ability_definition.h"
#include "anonymization.h"

using namespace std;
namespace OHOS {
namespace CameraStandard {
using OHOS::HDI::Camera::V1_3::OperationMode;
sptr<CameraManager> CameraManager::g_cameraManager = nullptr;
std::mutex CameraManager::g_instanceMutex;

constexpr int32_t CONTROL_CENTER_RESOLUTION_WIDTH_MAX = 1920;
constexpr int32_t CONTROL_CENTER_RESOLUTION_HEIGHT_MAX = 1080;

const std::string CameraManager::surfaceFormat = "CAMERA_SURFACE_FORMAT";

const std::unordered_map<camera_format_t, CameraFormat> CameraManager::metaToFwCameraFormat_ = {
    {OHOS_CAMERA_FORMAT_YCRCB_420_SP, CAMERA_FORMAT_YUV_420_SP},
    {OHOS_CAMERA_FORMAT_JPEG, CAMERA_FORMAT_JPEG},
    {OHOS_CAMERA_FORMAT_RGBA_8888, CAMERA_FORMAT_RGBA_8888},
    {OHOS_CAMERA_FORMAT_YCBCR_P010, CAMERA_FORMAT_YCBCR_P010},
    {OHOS_CAMERA_FORMAT_YCRCB_P010, CAMERA_FORMAT_YCRCB_P010},
    {OHOS_CAMERA_FORMAT_YCBCR_420_SP, CAMERA_FORMAT_NV12},
    {OHOS_CAMERA_FORMAT_422_YUYV, CAMERA_FORMAT_YUV_422_YUYV},
    {OHOS_CAMERA_FORMAT_422_UYVY, CAMERA_FORMAT_YUV_422_UYVY},
    {OHOS_CAMERA_FORMAT_DNG, CAMERA_FORMAT_DNG},
    {OHOS_CAMERA_FORMAT_DNG_XDRAW, CAMERA_FORMAT_DNG_XDRAW},
    {OHOS_CAMERA_FORMAT_HEIC, CAMERA_FORMAT_HEIC},
    {OHOS_CAMERA_FORMAT_DEPTH_16, CAMERA_FORMAT_DEPTH_16},
    {OHOS_CAMERA_FORMAT_DEPTH_32, CAMERA_FORMAT_DEPTH_32},
    {OHOS_CAMERA_FORMAT_MJPEG, CAMERA_FORMAT_MJPEG}
};

const std::unordered_map<DepthDataAccuracyType, DepthDataAccuracy> CameraManager::metaToFwDepthDataAccuracy_ = {
    {OHOS_DEPTH_DATA_ACCURACY_RELATIVE, DEPTH_DATA_ACCURACY_RELATIVE},
    {OHOS_DEPTH_DATA_ACCURACY_ABSOLUTE, DEPTH_DATA_ACCURACY_ABSOLUTE},
};

const std::unordered_map<CameraFormat, camera_format_t> CameraManager::fwToMetaCameraFormat_ = {
    {CAMERA_FORMAT_YUV_420_SP, OHOS_CAMERA_FORMAT_YCRCB_420_SP},
    {CAMERA_FORMAT_JPEG, OHOS_CAMERA_FORMAT_JPEG},
    {CAMERA_FORMAT_RGBA_8888, OHOS_CAMERA_FORMAT_RGBA_8888},
    {CAMERA_FORMAT_YCBCR_P010, OHOS_CAMERA_FORMAT_YCBCR_P010},
    {CAMERA_FORMAT_YCRCB_P010, OHOS_CAMERA_FORMAT_YCRCB_P010},
    {CAMERA_FORMAT_NV12, OHOS_CAMERA_FORMAT_YCBCR_420_SP},
    {CAMERA_FORMAT_YUV_422_YUYV, OHOS_CAMERA_FORMAT_422_YUYV},
    {CAMERA_FORMAT_YUV_422_UYVY, OHOS_CAMERA_FORMAT_422_UYVY},
    {CAMERA_FORMAT_DNG, OHOS_CAMERA_FORMAT_DNG},
    {CAMERA_FORMAT_DNG_XDRAW, OHOS_CAMERA_FORMAT_DNG_XDRAW},
    {CAMERA_FORMAT_HEIC, OHOS_CAMERA_FORMAT_HEIC},
    {CAMERA_FORMAT_DEPTH_16, OHOS_CAMERA_FORMAT_DEPTH_16},
    {CAMERA_FORMAT_DEPTH_32, OHOS_CAMERA_FORMAT_DEPTH_32},
    {CAMERA_FORMAT_MJPEG, OHOS_CAMERA_FORMAT_MJPEG}
};

const std::unordered_map<CameraFoldStatus, FoldStatus> g_metaToFwCameraFoldStatus_ = {
    {OHOS_CAMERA_FOLD_STATUS_NONFOLDABLE, FoldStatus::UNKNOWN_FOLD},
    {OHOS_CAMERA_FOLD_STATUS_EXPANDED, FoldStatus::EXPAND},
    {OHOS_CAMERA_FOLD_STATUS_FOLDED, FoldStatus::FOLDED}
};

const std::set<int32_t> isTemplateMode_ = {
    SceneMode::CAPTURE, SceneMode::VIDEO
};

const std::set<int32_t> isPhotoMode_ = {
    SceneMode::CAPTURE, SceneMode::PORTRAIT
};

const std::unordered_map<CameraPosition, camera_position_enum_t> fwToMetaCameraPosition_ = {
    {CAMERA_POSITION_FRONT, OHOS_CAMERA_POSITION_FRONT},
    {CAMERA_POSITION_BACK, OHOS_CAMERA_POSITION_BACK},
    {CAMERA_POSITION_UNSPECIFIED, OHOS_CAMERA_POSITION_OTHER}
};

bool ConvertMetaToFwkMode(const OperationMode opMode, SceneMode &scMode)
{
    // LCOV_EXCL_START
    auto it = g_metaToFwSupportedMode_.find(opMode);
    if (it != g_metaToFwSupportedMode_.end()) {
        scMode = it->second;
        MEDIA_DEBUG_LOG("ConvertMetaToFwkMode OperationMode = %{public}d to SceneMode %{public}d", opMode, scMode);
        return true;
    }
    MEDIA_ERR_LOG("ConvertMetaToFwkMode OperationMode = %{public}d err", opMode);
    return false;
    // LCOV_EXCL_STOP
}

bool ConvertFwkToMetaMode(const SceneMode scMode, OperationMode &opMode)
{
    auto it = g_fwToMetaSupportedMode_.find(scMode);
    if (it != g_fwToMetaSupportedMode_.end()) {
        opMode = it->second;
        MEDIA_DEBUG_LOG("ConvertFwkToMetaMode SceneMode %{public}d to OperationMode = %{public}d", scMode, opMode);
        return true;
    }
    MEDIA_ERR_LOG("ConvertFwkToMetaMode SceneMode = %{public}d err", scMode);
    return false;
}

CameraManager::CameraManager()
{
    MEDIA_INFO_LOG("CameraManager::CameraManager construct enter");
    cameraStatusListenerManager_->SetCameraManager(this);
    torchServiceListenerManager_->SetCameraManager(this);
    cameraMuteListenerManager_->SetCameraManager(this);
    foldStatusListenerManager_->SetCameraManager(this);
    controlCenterStatusListenerManager_->SetCameraManager(this);
}

CameraManager::~CameraManager()
{
    MEDIA_INFO_LOG("CameraManager::~CameraManager() called");
    RemoveServiceProxyDeathRecipient();
    UnSubscribeSystemAbility();
}

int32_t CameraManager::CreateListenerObject()
{
    MEDIA_DEBUG_LOG("CameraManager::CreateListenerObject prepare execute");
    sptr<CameraListenerStub> listenerStub = new (std::nothrow) CameraListenerStub();
    CHECK_RETURN_RET_ELOG(listenerStub == nullptr, CAMERA_ALLOC_ERROR, "failed to new CameraListenerStub object");
    sptr<IRemoteObject> object = listenerStub->AsObject();
    CHECK_RETURN_RET_ELOG(object == nullptr, CAMERA_ALLOC_ERROR, "listener object is nullptr..");
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, CameraErrorCode::SERVICE_FATL_ERROR, "serviceProxy is null");
    return serviceProxy->SetListenerObject(object);
}

int32_t CameraStatusListenerManager::OnCameraStatusChanged(
    const std::string& cameraId, const int32_t status, const std::string& bundleName)
{
    MEDIA_INFO_LOG("OnCameraStatusChanged cameraId: %{public}s, status: %{public}d", cameraId.c_str(), status);
    auto cameraManager = GetCameraManager();
    CHECK_RETURN_RET_ELOG(cameraManager == nullptr, CAMERA_OK, "OnCameraStatusChanged CameraManager is nullptr");

    CameraStatusInfo cameraStatusInfo;
    // LCOV_EXCL_START
    if (status == static_cast<int32_t>(CameraStatus::CAMERA_STATUS_APPEAR)) {
        cameraManager->ClearCameraDeviceListCache();
        cameraManager->ClearCameraDeviceAbilitySupportMap();
    }
    // LCOV_EXCL_STOP
    sptr<CameraDevice> cameraInfo = cameraManager->GetCameraDeviceFromId(cameraId);
    cameraStatusInfo.cameraDevice = cameraInfo;
    CHECK_EXECUTE(status == static_cast<int32_t>(CameraStatus::CAMERA_STATUS_DISAPPEAR),
        cameraManager->RemoveCameraDeviceFromCache(cameraId));
    cameraStatusInfo.cameraStatus = static_cast<CameraStatus>(status);
    cameraStatusInfo.bundleName = bundleName;

    CHECK_EXECUTE(!CheckCameraStatusValid(cameraInfo), return CAMERA_OK);
    if (cameraStatusInfo.cameraDevice) {
        auto listenerManager = cameraManager->GetCameraStatusListenerManager();
        MEDIA_DEBUG_LOG("CameraStatusListenerManager listeners size: %{public}zu", listenerManager->GetListenerCount());
        listenerManager->TriggerListener([&](auto listener) { listener->OnCameraStatusChanged(cameraStatusInfo); });
        listenerManager->CacheCameraStatus(cameraId, std::make_shared<CameraStatusInfo>(cameraStatusInfo));
    }
    return CAMERA_OK;
}

int32_t CameraStatusListenerManager::OnFlashlightStatusChanged(const std::string& cameraId,
    const int32_t status)
{
    MEDIA_INFO_LOG("cameraId: %{public}s, status: %{public}d", cameraId.c_str(), status);
    auto cameraManager = GetCameraManager();
    CHECK_RETURN_RET_ELOG(
        cameraManager == nullptr, CAMERA_OK, "OnFlashlightStatusChanged CameraManager is nullptr");
    auto listenerManager = cameraManager->GetCameraStatusListenerManager();
    MEDIA_DEBUG_LOG("CameraStatusListenerManager listeners size: %{public}zu", listenerManager->GetListenerCount());
    listenerManager->TriggerListener([&](auto listener) {
        listener->OnFlashlightStatusChanged(cameraId, static_cast<FlashStatus>(status));
    });
    listenerManager->CacheFlashStatus(cameraId, static_cast<FlashStatus>(status));
    return CAMERA_OK;
}

bool CameraStatusListenerManager::CheckCameraStatusValid(sptr<CameraDevice> cameraInfo)
{
    // LCOV_EXCL_START
    auto cameraManager = GetCameraManager();
    CHECK_RETURN_RET_ELOG(cameraManager == nullptr || cameraInfo == nullptr,
        false, "CheckCameraStatusValid CameraManager is nullptr");
    std::string foldScreenType = cameraManager->GetFoldScreenType();
    if (!foldScreenType.empty() && foldScreenType[0] == '4' &&
        cameraInfo->GetPosition() == CAMERA_POSITION_BACK &&
        cameraInfo->GetConnectionType() == CAMERA_CONNECTION_BUILT_IN) {
        std::string bundleName_ = system::GetParameter("const.camera.folded_lens_change", "default");
        FoldStatus curFoldStatus = cameraManager->GetFoldStatus();
        auto supportedFoldStatus = cameraInfo->GetSupportedFoldStatus();
        auto it = g_metaToFwCameraFoldStatus_.find(static_cast<CameraFoldStatus>(supportedFoldStatus));
        CHECK_RETURN_RET_DLOG(it == g_metaToFwCameraFoldStatus_.end(), false,
            "No supported fold status is found");
        CHECK_RETURN_RET_DLOG(it->second != curFoldStatus, false,
            "current foldstatus is inconsistency");
        bool isSpecialScene = it->second == curFoldStatus && curFoldStatus == FoldStatus::FOLDED &&
            bundleName_ != "default" && cameraManager->GetBundleName() != bundleName_;
        MEDIA_DEBUG_LOG("curFoldStatus %{public}d it->second= %{public}d cameraid = %{public}s",
            static_cast<int32_t>(curFoldStatus), it->second, cameraInfo->GetID().c_str());
        CHECK_RETURN_RET_ELOG(isSpecialScene, false, "CameraStatusListenerManager not notify");
    }
    return true;
    // LCOV_EXCL_STOP
}

sptr<CaptureSession> CameraManager::CreateCaptureSession()
{
    CAMERA_SYNC_TRACE;
    sptr<CaptureSession> captureSession = nullptr;
    int ret = CreateCaptureSession(captureSession, SceneMode::NORMAL);
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, nullptr,
        "Failed to CreateCaptureSession with error code:%{public}d", ret);
    return captureSession;
}

sptr<CaptureSession> CameraManager::CreateCaptureSessionImpl(SceneMode mode, sptr<ICaptureSession> session)
{
    // LCOV_EXCL_START
    switch (mode) {
        case SceneMode::VIDEO:
            return new (std::nothrow) VideoSession(session);
        case SceneMode::CAPTURE:
            return new (std::nothrow) PhotoSession(session);
        case SceneMode::SECURE:
            return new (std::nothrow) SecureCameraSession(session);
        case SceneMode::SCAN:
            return new (std::nothrow) ScanSession(session);
        default:
            return new (std::nothrow) CaptureSession(session);
    }
    // LCOV_EXCL_STOP
}

sptr<CaptureSession> CameraManager::CreateCaptureSession(SceneMode mode)
{
    sptr<CaptureSession> session = nullptr;
    CreateCaptureSession(session, mode);
    return session;
}

int32_t CameraManager::CreateCaptureSessionFromService(sptr<ICaptureSession>& session, SceneMode mode)
{
    // LCOV_EXCL_START
    sptr<ICaptureSession> sessionTmp = nullptr;
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, CameraErrorCode::INVALID_ARGUMENT,
        "CreateCaptureSessionFromService serviceProxy is nullptr");
    OperationMode opMode = OperationMode::NORMAL;
    CHECK_PRINT_ELOG(!ConvertFwkToMetaMode(mode, opMode),
        "CameraManager::CreateCaptureSession ConvertFwkToMetaMode mode: %{public}d fail", mode);
    int32_t retCode = serviceProxy->CreateCaptureSession(sessionTmp, opMode);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, ServiceToCameraError(retCode),
        "CreateCaptureSessionFromService Failed to get captureSession object from hcamera service! "
        "%{public}d", retCode);
    CHECK_RETURN_RET_ELOG(sessionTmp == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CreateCaptureSessionFromService Failed to CreateCaptureSession with session is null");
    session = sessionTmp;
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int32_t CameraManager::CreateCaptureSession(sptr<CaptureSession>& pCaptureSession, SceneMode mode)
{
    CAMERA_SYNC_TRACE;
    sptr<ICaptureSession> session = nullptr;
    sptr<CaptureSession> captureSession = nullptr;
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, CameraErrorCode::INVALID_ARGUMENT,
        "CreateCaptureSession(pCaptureSession) serviceProxy is nullptr");
    OperationMode opMode = OperationMode::NORMAL;
    CHECK_PRINT_ELOG(!ConvertFwkToMetaMode(mode, opMode),
        "CameraManager::CreateCaptureSession ConvertFwkToMetaMode mode: %{public}d fail", mode);
    int32_t retCode = serviceProxy->CreateCaptureSession(session, opMode);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, ServiceToCameraError(retCode),
        "CreateCaptureSession(pCaptureSession) Failed to get captureSession object from hcamera service! "
        "%{public}d", retCode);
    CHECK_RETURN_RET_ELOG(session == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CreateCaptureSession(pCaptureSession) Failed to CreateCaptureSession with session is null");
    captureSession = CreateCaptureSessionImpl(mode, session);
    CHECK_RETURN_RET_ELOG(captureSession == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CreateCaptureSession(pCaptureSession) failed to new captureSession!");
    captureSession->SetMode(mode);
    pCaptureSession = captureSession;
    return CameraErrorCode::SUCCESS;
}

int32_t CameraManager::CreateCaptureSession(sptr<CaptureSession>* pCaptureSession)
{
    return CreateCaptureSession(*pCaptureSession, SceneMode::NORMAL);
}

sptr<DeferredPhotoProcSession> CameraManager::CreateDeferredPhotoProcessingSession(int userId,
    std::shared_ptr<IDeferredPhotoProcSessionCallback> callback)
{
    CAMERA_SYNC_TRACE;
    sptr<DeferredPhotoProcSession> deferredPhotoProcSession = nullptr;
    int32_t retCode = CreateDeferredPhotoProcessingSession(userId, callback, &deferredPhotoProcSession);
    CHECK_RETURN_RET_ELOG(retCode != CameraErrorCode::SUCCESS, nullptr,
        "Failed to CreateDeferredPhotoProcessingSession with error code:%{public}d", retCode);
    return deferredPhotoProcSession;
}

int CameraManager::CreateDeferredPhotoProcessingSession(int userId,
    std::shared_ptr<IDeferredPhotoProcSessionCallback> callback,
    sptr<DeferredPhotoProcSession> *pDeferredPhotoProcSession)
{
    CAMERA_SYNC_TRACE;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_RET_ELOG(samgr == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CreateDeferredPhotoProcessingSession Failed to get System ability manager");
    sptr<IRemoteObject> object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_RET_ELOG(object == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CreateDeferredPhotoProcessingSession object is null");
    sptr<ICameraService> serviceProxy = iface_cast<ICameraService>(object);
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CreateDeferredPhotoProcessingSession serviceProxy is null");

    sptr<DeferredPhotoProcSession> deferredPhotoProcSession =
        new(std::nothrow) DeferredPhotoProcSession(userId, callback);
    CHECK_RETURN_RET_ELOG(deferredPhotoProcSession == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CreateDeferredPhotoProcessingSession failed to new deferredPhotoProcSession!");
    sptr<DeferredProcessing::IDeferredPhotoProcessingSessionCallback> remoteCallback =
        new(std::nothrow) DeferredPhotoProcessingSessionCallback(deferredPhotoProcSession);
    CHECK_RETURN_RET_ELOG(remoteCallback == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CreateDeferredPhotoProcessingSession failed to new remoteCallback!");

    sptr<DeferredProcessing::IDeferredPhotoProcessingSession> session = nullptr;
    int32_t retCode = serviceProxy->CreateDeferredPhotoProcessingSession(userId, remoteCallback, session);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, ServiceToCameraError(retCode),
        "Failed to get photo session!, %{public}d", retCode);
    CHECK_RETURN_RET_ELOG(session == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CreateDeferredPhotoProcessingSession Failed to CreateDeferredPhotoProcessingSession as session is null");

    deferredPhotoProcSession->SetDeferredPhotoSession(session);
    *pDeferredPhotoProcSession = deferredPhotoProcSession;
    return CameraErrorCode::SUCCESS;
}

sptr<DeferredVideoProcSession> CameraManager::CreateDeferredVideoProcessingSession(int userId,
    std::shared_ptr<IDeferredVideoProcSessionCallback> callback)
{
    CAMERA_SYNC_TRACE;
    sptr<DeferredVideoProcSession> deferredVideoProcSession = nullptr;
    int ret = CreateDeferredVideoProcessingSession(userId, callback, &deferredVideoProcSession);
    if (ret != CameraErrorCode::SUCCESS) {
        MEDIA_ERR_LOG("Failed to CreateDeferredVideoProcessingSession with error code:%{public}d", ret);
        return nullptr;
    }
    return deferredVideoProcSession;
}

int CameraManager::CreateDeferredVideoProcessingSession(int userId,
    std::shared_ptr<IDeferredVideoProcSessionCallback> callback,
    sptr<DeferredVideoProcSession> *pDeferredVideoProcSession)
{
    CAMERA_SYNC_TRACE;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_RET_ELOG(samgr == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CreateDeferredVideoProcessingSession Failed to get System ability manager");
    sptr<IRemoteObject> object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_RET_ELOG(object == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CreateDeferredVideoProcessingSession object is null");
    sptr<ICameraService> serviceProxy = iface_cast<ICameraService>(object);
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CreateDeferredVideoProcessingSession serviceProxy is null");

    auto deferredVideoProcSession = new(std::nothrow) DeferredVideoProcSession(userId, callback);
    CHECK_RETURN_RET_ELOG(deferredVideoProcSession == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CreateDeferredVideoProcessingSession failed to new deferredVideoProcSession!");
    sptr<DeferredProcessing::IDeferredVideoProcessingSessionCallback> remoteCallback =
        new(std::nothrow) DeferredVideoProcessingSessionCallback(deferredVideoProcSession);
    CHECK_RETURN_RET_ELOG(remoteCallback == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CreateDeferredVideoProcessingSession failed to new remoteCallback!");

    sptr<DeferredProcessing::IDeferredVideoProcessingSession> session = nullptr;
    int32_t retCode = serviceProxy->CreateDeferredVideoProcessingSession(userId, remoteCallback, session);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, ServiceToCameraError(retCode),
        "Failed to get video session!, %{public}d", retCode);
    CHECK_RETURN_RET_ELOG(session == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CreateDeferredVideoProcessingSession Failed to CreateDeferredVideoProcessingSession as session is null");

    deferredVideoProcSession->SetDeferredVideoSession(session);
    *pDeferredVideoProcSession = deferredVideoProcSession;
    return CameraErrorCode::SUCCESS;
}

sptr<MechSession> CameraManager::CreateMechSession(int userId)
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    sptr<MechSession> mechSession = nullptr;
    int32_t retCode = CreateMechSession(userId, &mechSession);
    CHECK_RETURN_RET_ELOG(retCode != CameraErrorCode::SUCCESS, nullptr,
        "Failed to CreateMechSession with error code:%{public}d", retCode);
    return mechSession;
    // LCOV_EXCL_STOP
}

int CameraManager::CreateMechSession(int userId, sptr<MechSession>* pMechSession)
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    sptr<IMechSession> session = nullptr;
    sptr<MechSession> mechSession = nullptr;

    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, CameraErrorCode::INVALID_ARGUMENT,
        "CreateMechSession(pMechSession) serviceProxy is nullptr");
    int32_t retCode = serviceProxy->CreateMechSession(userId, session);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, retCode,
        "Failed to get mech session!, %{public}d", retCode);
    CHECK_RETURN_RET_ELOG(session == nullptr, retCode,
        "CreateMechSession Failed to CreateMechSession as session is null");

    mechSession = new(std::nothrow) MechSession(session);
    CHECK_RETURN_RET_ELOG(mechSession == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CreateMechSession failed to new MechSession!");

    *pMechSession = mechSession;
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

bool CameraManager::IsMechSupported()
{
    // LCOV_EXCL_START
    bool isMechSupported = false;
    bool cacheResult = GetCameraDeviceAbilitySupportValue(CAMERA_ABILITY_SUPPORT_MECH, isMechSupported);
    if (cacheResult) {
        return isMechSupported;
    }

    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, false, "IsMechSupported serviceProxy is null");
    int32_t retCode = serviceProxy->IsMechSupported(isMechSupported);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, false, "IsMechSupported call failed, retCode: %{public}d",
        retCode);
    CacheCameraDeviceAbilitySupportValue(CAMERA_ABILITY_SUPPORT_MECH, isMechSupported);
    return isMechSupported;
    // LCOV_EXCL_STOP
}

sptr<PhotoOutput> CameraManager::CreatePhotoOutput(sptr<IBufferProducer> &surface)
{
    CAMERA_SYNC_TRACE;
    sptr<PhotoOutput> result = nullptr;
    return result;
}

sptr<PhotoOutput> CameraManager::CreatePhotoOutput(Profile &profile, sptr<IBufferProducer> &surfaceProducer)
{
    CAMERA_SYNC_TRACE;
    sptr<PhotoOutput> photoOutput = nullptr;
    int32_t retCode = CreatePhotoOutput(profile, surfaceProducer, &photoOutput);
    CHECK_RETURN_RET_ELOG(retCode != CameraErrorCode::SUCCESS, nullptr,
        "Failed to CreatePhotoOutput with error code:%{public}d", retCode);
    return photoOutput;
}

int CameraManager::CreatePhotoOutputWithoutProfile(sptr<IBufferProducer> surfaceProducer,
                                                   sptr<PhotoOutput>* pPhotoOutput)
{
    CAMERA_SYNC_TRACE;
    auto serviceProxy = GetServiceProxy();
    // LCOV_EXCL_START
    CHECK_RETURN_RET_ELOG((serviceProxy == nullptr) || (surfaceProducer == nullptr), CameraErrorCode::INVALID_ARGUMENT,
        "CreatePhotoOutputWithoutProfile serviceProxy is null or PhotoOutputSurface is null");
    sptr<PhotoOutput> photoOutput = new (std::nothrow) PhotoOutput(surfaceProducer);
    CHECK_RETURN_RET(photoOutput == nullptr, CameraErrorCode::SERVICE_FATL_ERROR);
    photoOutput->AddTag(CaptureOutput::DYNAMIC_PROFILE);
    *pPhotoOutput = photoOutput;
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int CameraManager::CreatePhotoOutputWithoutProfile(sptr<IBufferProducer> surfaceProducer,
                                                   sptr<PhotoOutput>* pPhotoOutput, sptr<Surface> photoSurface)
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG((serviceProxy == nullptr) || (surfaceProducer == nullptr), CameraErrorCode::INVALID_ARGUMENT,
        "CreatePhotoOutputWithoutProfile serviceProxy is null or PhotoOutputSurface is null");
    sptr<PhotoOutput> photoOutput = new (std::nothrow) PhotoOutput(surfaceProducer, photoSurface);
    CHECK_RETURN_RET(photoOutput == nullptr, CameraErrorCode::SERVICE_FATL_ERROR);
    photoOutput->AddTag(CaptureOutput::DYNAMIC_PROFILE);
    *pPhotoOutput = photoOutput;
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int CameraManager::CreatePhotoOutputWithoutProfile(sptr<PhotoOutput>* pPhotoOutput)
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG((serviceProxy == nullptr), CameraErrorCode::INVALID_ARGUMENT,
        "CreatePhotoOutputWithoutProfile serviceProxy is null");
    sptr<PhotoOutput> photoOutput = new (std::nothrow) PhotoOutput();
    CHECK_RETURN_RET(photoOutput == nullptr, CameraErrorCode::SERVICE_FATL_ERROR);
    photoOutput->AddTag(CaptureOutput::DYNAMIC_PROFILE);
    *pPhotoOutput = photoOutput;
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int CameraManager::CreatePhotoOutput(Profile &profile, sptr<IBufferProducer> &surfaceProducer,
                                     sptr<PhotoOutput> *pPhotoOutput) __attribute__((no_sanitize("cfi")))
{
    CAMERA_SYNC_TRACE;
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG((serviceProxy == nullptr) || (surfaceProducer == nullptr), CameraErrorCode::INVALID_ARGUMENT,
        "CreatePhotoOutput serviceProxy is null or PhotoOutputSurface/profile is null");
    CHECK_RETURN_RET_ELOG((profile.GetCameraFormat() == CAMERA_FORMAT_INVALID) || (profile.GetSize().width == 0)
        || (profile.GetSize().height == 0), CameraErrorCode::INVALID_ARGUMENT,
        "CreatePhotoOutput invalid fomrat or width or height is zero");
    // to adapter yuv photo
    CameraFormat yuvFormat = profile.GetCameraFormat();
    camera_format_t metaFormat = GetCameraMetadataFormat(yuvFormat);
    sptr<IStreamCapture> streamCapture = nullptr;
    int32_t retCode = serviceProxy->CreatePhotoOutput(
        surfaceProducer, metaFormat, profile.GetSize().width, profile.GetSize().height, streamCapture);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, ServiceToCameraError(retCode),
        "Failed to get stream capture object from hcamera service!, %{public}d", retCode);
    sptr<PhotoOutput> photoOutput = new(std::nothrow) PhotoOutput(surfaceProducer);
    CHECK_RETURN_RET(photoOutput == nullptr, CameraErrorCode::SERVICE_FATL_ERROR);
    photoOutput->SetStream(streamCapture);
    photoOutput->SetPhotoProfile(profile);
    *pPhotoOutput = photoOutput;
    return CameraErrorCode::SUCCESS;
}

int CameraManager::CreatePhotoOutput(Profile &profile, sptr<IBufferProducer> &surfaceProducer,
                                     sptr<PhotoOutput> *pPhotoOutput, sptr<Surface> photoSurface)
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG((serviceProxy == nullptr) || (surfaceProducer == nullptr),
        CameraErrorCode::INVALID_ARGUMENT,
        "CreatePhotoOutput serviceProxy is null or PhotoOutputSurface/profile is null");
    CHECK_RETURN_RET_ELOG((profile.GetCameraFormat() == CAMERA_FORMAT_INVALID) || (profile.GetSize().width == 0)
        || (profile.GetSize().height == 0), CameraErrorCode::INVALID_ARGUMENT,
        "CreatePhotoOutput invalid fomrat or width or height is zero");
    // to adapter yuv photo
    CameraFormat yuvFormat = profile.GetCameraFormat();
    camera_format_t metaFormat = GetCameraMetadataFormat(yuvFormat);
    sptr<IStreamCapture> streamCapture = nullptr;
    int32_t retCode = serviceProxy->CreatePhotoOutput(
        surfaceProducer, metaFormat, profile.GetSize().width, profile.GetSize().height, streamCapture);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, ServiceToCameraError(retCode),
        "Failed to get stream capture object from hcamera service!, %{public}d", retCode);
    sptr<PhotoOutput> photoOutput = new(std::nothrow) PhotoOutput(surfaceProducer, photoSurface);
    CHECK_RETURN_RET(photoOutput == nullptr, CameraErrorCode::SERVICE_FATL_ERROR);
    photoOutput->SetStream(streamCapture);
    photoOutput->SetPhotoProfile(profile);
    *pPhotoOutput = photoOutput;
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int CameraManager::CreatePhotoOutput(Profile& profile, sptr<PhotoOutput>* pPhotoOutput)
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, CameraErrorCode::INVALID_ARGUMENT,
        "CreatePhotoOutput serviceProxy is null or PhotoOutputSurface/profile is null");
    CHECK_RETURN_RET_ELOG((profile.GetCameraFormat() == CAMERA_FORMAT_INVALID) || (profile.GetSize().width == 0)
        || (profile.GetSize().height == 0), CameraErrorCode::INVALID_ARGUMENT,
        "CreatePhotoOutput invalid fomrat or width or height is zero");
    // to adapter yuv photo
    CameraFormat yuvFormat = profile.GetCameraFormat();
    camera_format_t metaFormat = GetCameraMetadataFormat(yuvFormat);
    sptr<IStreamCapture> streamCapture = nullptr;
    int32_t retCode =
        serviceProxy->CreatePhotoOutput(metaFormat, profile.GetSize().width, profile.GetSize().height, streamCapture);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, ServiceToCameraError(retCode),
        "Failed to get stream capture object from hcamera service!, %{public}d", retCode);
    sptr<PhotoOutput> photoOutput = new(std::nothrow) PhotoOutput();
    CHECK_RETURN_RET(photoOutput == nullptr, CameraErrorCode::SERVICE_FATL_ERROR);
    photoOutput->SetStream(streamCapture);
    photoOutput->SetPhotoProfile(profile);
    *pPhotoOutput = photoOutput;
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

sptr<PreviewOutput> CameraManager::CreatePreviewOutput(Profile &profile, sptr<Surface> surface)
{
    CAMERA_SYNC_TRACE;
    sptr<PreviewOutput> previewOutput = nullptr;
    int32_t retCode = CreatePreviewOutput(profile, surface, &previewOutput);
    CHECK_RETURN_RET_ELOG(retCode != CameraErrorCode::SUCCESS, nullptr,
        "Failed to CreatePreviewOutput with error code:%{public}d", retCode);

    return previewOutput;
}

int CameraManager::CreatePreviewOutputWithoutProfile(sptr<Surface> surface, sptr<PreviewOutput>* pPreviewOutput)
{
    CAMERA_SYNC_TRACE;
    sptr<PreviewOutput> previewOutput = nullptr;
    auto serviceProxy = GetServiceProxy();
    // LCOV_EXCL_START
    CHECK_RETURN_RET_ELOG((serviceProxy == nullptr) || (surface == nullptr), CameraErrorCode::INVALID_ARGUMENT,
        "CreatePreviewOutputWithoutProfile serviceProxy is null or surface is null");
    previewOutput = new (std::nothrow) PreviewOutput(surface->GetProducer());
    CHECK_RETURN_RET(previewOutput == nullptr, CameraErrorCode::SERVICE_FATL_ERROR);
    previewOutput->AddTag(CaptureOutput::DYNAMIC_PROFILE);
    *pPreviewOutput = previewOutput;
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int CameraManager::CreatePreviewOutput(Profile &profile, sptr<Surface> surface, sptr<PreviewOutput> *pPreviewOutput)
{
    CAMERA_SYNC_TRACE;
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG((serviceProxy == nullptr) || (surface == nullptr), CameraErrorCode::INVALID_ARGUMENT,
        "CreatePreviewOutput serviceProxy is null or previewOutputSurface/profile is null");
    CHECK_RETURN_RET_ELOG((profile.GetCameraFormat() == CAMERA_FORMAT_INVALID) || (profile.GetSize().width == 0)
        || (profile.GetSize().height == 0), CameraErrorCode::INVALID_ARGUMENT,
        "CreatePreviewOutput invalid fomrat or width or height is zero");

    camera_format_t metaFormat = GetCameraMetadataFormat(profile.GetCameraFormat());
    sptr<IStreamRepeat> streamRepeat = nullptr;
    int32_t retCode = serviceProxy->CreatePreviewOutput(
        surface->GetProducer(), metaFormat, profile.GetSize().width, profile.GetSize().height, streamRepeat);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, ServiceToCameraError(retCode),
        "Failed to get stream repeat object from hcamera service! %{public}d", retCode);
    sptr<PreviewOutput> previewOutput = new (std::nothrow) PreviewOutput(surface->GetProducer());
    CHECK_RETURN_RET(previewOutput == nullptr, CameraErrorCode::SERVICE_FATL_ERROR);
    previewOutput->SetStream(streamRepeat);
    previewOutput->SetOutputFormat(profile.GetCameraFormat());
    previewOutput->SetSize(profile.GetSize());
    previewOutput->SetPreviewProfile(profile);
    *pPreviewOutput = previewOutput;
    bool resolutionCondition = profile.GetSize().height <= CONTROL_CENTER_RESOLUTION_HEIGHT_MAX
        && profile.GetSize().width <= CONTROL_CENTER_RESOLUTION_WIDTH_MAX;
    SetControlCenterResolutionCondition(resolutionCondition);
    return CameraErrorCode::SUCCESS;
}

int32_t CameraManager::CreatePreviewOutputStream(
    sptr<IStreamRepeat>& streamPtr, Profile& profile, const sptr<OHOS::IBufferProducer>& producer)
{
    auto validResult = ValidCreateOutputStream(profile, producer);
    // LCOV_EXCL_START
    CHECK_RETURN_RET_ELOG(validResult != SUCCESS, validResult,
        "CameraManager::CreatePreviewOutputStream ValidCreateOutputStream fail:%{public}d", validResult);

    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CameraManager::CreatePreviewOutputStream serviceProxy is null");
    camera_format_t metaFormat = GetCameraMetadataFormat(profile.GetCameraFormat());
    int32_t retCode = serviceProxy->CreatePreviewOutput(
        producer, metaFormat, profile.GetSize().width, profile.GetSize().height, streamPtr);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, ServiceToCameraError(retCode),
        "CreatePreviewOutputStream Failed to get stream repeat object from hcamera service! %{public}d", retCode);
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int32_t CameraManager::CreatePhotoOutputStream(
    sptr<IStreamCapture>& streamPtr, Profile& profile, const sptr<OHOS::IBufferProducer>& producer)
{
    // LCOV_EXCL_START
    auto validResult = ValidCreateOutputStream(profile, producer);
    CHECK_RETURN_RET_ELOG(validResult != SUCCESS, validResult,
        "CameraManager::CreatePhotoOutputStream ValidCreateOutputStream fail:%{public}d", validResult);
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG((serviceProxy == nullptr) || (producer == nullptr), CameraErrorCode::INVALID_ARGUMENT,
        "CameraManager::CreatePhotoOutputStream serviceProxy is null or producer is null");

    CameraFormat yuvFormat = profile.GetCameraFormat();
    auto metaFormat = GetCameraMetadataFormat(yuvFormat);
    auto retCode = serviceProxy->CreatePhotoOutput(
        producer, metaFormat, profile.GetSize().width, profile.GetSize().height, streamPtr);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, ServiceToCameraError(retCode),
        "CameraManager::CreatePhotoOutputStream Failed to get stream capture object from hcamera service! "
        "%{public}d", retCode);
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int32_t CameraManager::CreatePhotoOutputStream(
    sptr<IStreamCapture>& streamPtr, Profile& profile)
{
    // LCOV_EXCL_START
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, CameraErrorCode::INVALID_ARGUMENT,
        "CameraManager::CreatePhotoOutputStream serviceProxy is null or producer is null");
    CameraFormat yuvFormat = profile.GetCameraFormat();
    auto metaFormat = GetCameraMetadataFormat(yuvFormat);
    auto retCode =
        serviceProxy->CreatePhotoOutput(metaFormat, profile.GetSize().width, profile.GetSize().height, streamPtr);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, ServiceToCameraError(retCode),
        "CameraManager::CreatePhotoOutputStream Failed to get stream capture object from hcamera service! "
        "%{public}d", retCode);
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int32_t CameraManager::ValidCreateOutputStream(Profile& profile, const sptr<OHOS::IBufferProducer>& producer)
{
    // LCOV_EXCL_START
    CHECK_RETURN_RET_ELOG(producer == nullptr, CameraErrorCode::INVALID_ARGUMENT,
        "CameraManager::ValidCreateOutputStream producer is null");
    CHECK_RETURN_RET_ELOG((profile.GetCameraFormat() == CAMERA_FORMAT_INVALID) || (profile.GetSize().width == 0)
        || (profile.GetSize().height == 0), CameraErrorCode::INVALID_ARGUMENT,
        "CameraManager::ValidCreateOutputStream width or height is zero");
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

sptr<PreviewOutput> CameraManager::CreateDeferredPreviewOutput(Profile &profile)
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("CameraManager::CreateDeferredPreviewOutput called");
    sptr<PreviewOutput> previewOutput = nullptr;
    int32_t retCode = CreateDeferredPreviewOutput(profile, &previewOutput);
    CHECK_RETURN_RET_ELOG(retCode != CameraErrorCode::SUCCESS, nullptr,
        "CameraManager Failed to CreateDeferredPreviewOutput with error code:%{public}d", retCode);
    return previewOutput;
    // LCOV_EXCL_STOP
}

int CameraManager::CreateDeferredPreviewOutput(Profile &profile, sptr<PreviewOutput> *pPreviewOutput)
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, CameraErrorCode::INVALID_ARGUMENT,
        "CameraManager::CreateDeferredPreviewOutput serviceProxy is null");
    CHECK_RETURN_RET_ELOG((profile.GetCameraFormat() == CAMERA_FORMAT_INVALID) || (profile.GetSize().width == 0)
        || (profile.GetSize().height == 0), CameraErrorCode::INVALID_ARGUMENT,
        "CreateDeferredPreviewOutput invalid fomrat or width or height is zero");

    camera_format_t metaFormat = GetCameraMetadataFormat(profile.GetCameraFormat());
    sptr<IStreamRepeat> streamRepeat = nullptr;
    int32_t retCode = serviceProxy->CreateDeferredPreviewOutput(
        metaFormat, profile.GetSize().width, profile.GetSize().height, streamRepeat);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, ServiceToCameraError(retCode),
        "CreateDeferredPreviewOutput Failed to get stream repeat object from hcamera service!, %{public}d", retCode);
    sptr<PreviewOutput> previewOutput = new(std::nothrow) PreviewOutput();
    CHECK_RETURN_RET(previewOutput == nullptr, CameraErrorCode::SERVICE_FATL_ERROR);
    previewOutput->SetStream(streamRepeat);
    previewOutput->SetPreviewProfile(profile);
    *pPreviewOutput = previewOutput;
    bool resolutionCondition = profile.GetSize().height <= CONTROL_CENTER_RESOLUTION_HEIGHT_MAX
        && profile.GetSize().width <= CONTROL_CENTER_RESOLUTION_WIDTH_MAX;
    SetControlCenterResolutionCondition(resolutionCondition);
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
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
    int32_t retCode = CreateMetadataOutput(metadataOutput);
    CHECK_RETURN_RET_ELOG(retCode != CameraErrorCode::SUCCESS, nullptr,
        "CameraManager Failed to CreateMetadataOutput with error code:%{public}d", retCode);
    return metadataOutput;
}

int CameraManager::CreateMetadataOutput(sptr<MetadataOutput>& pMetadataOutput)
{
    return CreateMetadataOutputInternal(pMetadataOutput);
}

int CameraManager::CreateMetadataOutput(sptr<MetadataOutput>& pMetadataOutput,
    std::vector<MetadataObjectType> metadataObjectTypes)
{
    return CreateMetadataOutputInternal(pMetadataOutput, metadataObjectTypes);
}

int CameraManager::GetStreamDepthDataFromService(DepthProfile& depthProfile, sptr<IBufferProducer> &surface,
    sptr<IStreamDepthData>& streamDepthData)
{
    sptr<IStreamDepthData> streamDepthDataTmp = nullptr;
    int32_t retCode = CAMERA_OK;
    camera_format_t metaFormat;

    auto serviceProxy = GetServiceProxy();
    // LCOV_EXCL_START
    CHECK_RETURN_RET_ELOG((serviceProxy == nullptr) || (surface == nullptr), CameraErrorCode::INVALID_ARGUMENT,
        "serviceProxy is null or DepthDataOutputSurface/profile is null");

    if ((depthProfile.GetCameraFormat() == CAMERA_FORMAT_INVALID) ||
        (depthProfile.GetSize().width == 0) ||
        (depthProfile.GetSize().height == 0)) {
        MEDIA_ERR_LOG("invalid fomrat or width or height is zero");
        return CameraErrorCode::INVALID_ARGUMENT;
    }

    metaFormat = GetCameraMetadataFormat(depthProfile.GetCameraFormat());
    retCode = serviceProxy->CreateDepthDataOutput(
        surface, metaFormat, depthProfile.GetSize().width, depthProfile.GetSize().height, streamDepthDataTmp);
    if (retCode == CAMERA_OK) {
        streamDepthData = streamDepthDataTmp;
        return CameraErrorCode::SUCCESS;
    } else {
        MEDIA_ERR_LOG("Failed to get stream depth data object from hcamera service!, %{public}d", retCode);
        return ServiceToCameraError(retCode);
    }
    // LCOV_EXCL_STOP
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
    int32_t retCode = CreateVideoOutput(profile, surface, &videoOutput);
    CHECK_RETURN_RET_ELOG(retCode != CameraErrorCode::SUCCESS, nullptr,
        "CreateVideoOutput Failed to CreateVideoOutput with error code:%{public}d", retCode);
    return videoOutput;
}

int32_t CameraManager::CreateVideoOutputStream(
    sptr<IStreamRepeat>& streamPtr, Profile& profile, const sptr<OHOS::IBufferProducer>& producer)
{
    auto validResult = ValidCreateOutputStream(profile, producer);
    // LCOV_EXCL_START
    CHECK_RETURN_RET_ELOG(validResult != SUCCESS, validResult,
        "CameraManager::CreateVideoOutputStream ValidCreateOutputStream fail:%{public}d", validResult);

    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG((serviceProxy == nullptr) || (producer == nullptr), CameraErrorCode::INVALID_ARGUMENT,
        "CameraManager::CreateVideoOutputStream serviceProxy is null or producer is null");

    auto metaFormat = GetCameraMetadataFormat(profile.GetCameraFormat());
    MEDIA_DEBUG_LOG("metaFormat = %{public}d", static_cast<int32_t>(metaFormat));
    int32_t retCode = serviceProxy->CreateVideoOutput(
        producer, metaFormat, profile.GetSize().width, profile.GetSize().height, streamPtr);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, ServiceToCameraError(retCode),
        "CameraManager::CreateVideoOutputStream Failed to get stream capture object from hcamera service! "
        "%{public}d", retCode);
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int CameraManager::CreateVideoOutputWithoutProfile(sptr<Surface> surface, sptr<VideoOutput>* pVideoOutput)
{
    CAMERA_SYNC_TRACE;
    auto serviceProxy = GetServiceProxy();
    // LCOV_EXCL_START
    CHECK_RETURN_RET_ELOG((serviceProxy == nullptr) || (surface == nullptr), CameraErrorCode::INVALID_ARGUMENT,
        "CameraManager::CreateVideoOutput serviceProxy is null or VideoOutputSurface is null");

    sptr<VideoOutput> videoOutput = new (std::nothrow) VideoOutput(surface->GetProducer());
    CHECK_RETURN_RET(videoOutput == nullptr, CameraErrorCode::SERVICE_FATL_ERROR);
    videoOutput->AddTag(CaptureOutput::DYNAMIC_PROFILE);
    *pVideoOutput = videoOutput;
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int CameraManager::CreateVideoOutput(VideoProfile &profile, sptr<Surface> &surface, sptr<VideoOutput> *pVideoOutput)
{
    CAMERA_SYNC_TRACE;
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG((serviceProxy == nullptr) || (surface == nullptr), CameraErrorCode::INVALID_ARGUMENT,
        "CameraManager::CreateVideoOutput serviceProxy is null or VideoOutputSurface/profile is null");
    CHECK_RETURN_RET_ELOG((profile.GetCameraFormat() == CAMERA_FORMAT_INVALID) || (profile.GetSize().width == 0)
        || (profile.GetSize().height == 0), CameraErrorCode::INVALID_ARGUMENT,
        "CreateVideoOutput invalid format or width or height is zero");

    camera_format_t metaFormat = GetCameraMetadataFormat(profile.GetCameraFormat());
    auto [width, height] = profile.GetSize();
    auto frames = profile.GetFrameRates();
    bool isExistFrames = frames.size() >= 2;
    if (isExistFrames) {
        MEDIA_INFO_LOG("CameraManager::CreateVideoOutput, format: %{public}d, width: %{public}d, height: %{public}d, "
                       "frameRateMin: %{public}d, frameRateMax: %{public}d, surfaceId: %{public}" PRIu64,
            static_cast<int32_t>(metaFormat), width, height, frames[0], frames[1], surface->GetUniqueId());
    } else {
        MEDIA_INFO_LOG("CameraManager::CreateVideoOutput, format: %{public}d, width: %{public}d, height: %{public}d, "
                       "surfaceId: %{public}" PRIu64,
            static_cast<int32_t>(metaFormat), width, height, surface->GetUniqueId());
    }
    sptr<IStreamRepeat> streamRepeat = nullptr;
    int32_t retCode = serviceProxy->CreateVideoOutput(
        surface->GetProducer(), metaFormat, profile.GetSize().width, profile.GetSize().height, streamRepeat);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, ServiceToCameraError(retCode),
        "CameraManager::CreateVideoOutput Failed to get stream capture object from hcamera service! "
        "%{public}d", retCode);
    sptr<VideoOutput> videoOutput = new(std::nothrow) VideoOutput(surface->GetProducer());
    CHECK_RETURN_RET(videoOutput == nullptr, CameraErrorCode::SERVICE_FATL_ERROR);
    videoOutput->SetStream(streamRepeat);
    videoOutput->SetOutputFormat(profile.GetCameraFormat());
    videoOutput->SetSize(profile.GetSize());
    videoOutput->SetVideoProfile(profile);
    *pVideoOutput = videoOutput;

    return CameraErrorCode::SUCCESS;
}

void CameraManager::InitCameraManager()
{
    CAMERA_SYNC_TRACE;
    int32_t retCode = SubscribeSystemAbility();
    CHECK_RETURN_ELOG(retCode != CameraErrorCode::SUCCESS, "failed to SubscribeSystemAbilityd");
    retCode = RefreshServiceProxy();
    CHECK_RETURN_ELOG(retCode != CameraErrorCode::SUCCESS, "RefreshServiceProxy fail , ret = %{public}d",
        retCode);
    retCode = AddServiceProxyDeathRecipient();
    CHECK_RETURN_ELOG(retCode != CameraErrorCode::SUCCESS, "AddServiceProxyDeathRecipient fail ,"
        "ret = %{public}d", retCode);
    retCode = CreateListenerObject();
    CHECK_RETURN_ELOG(retCode != CAMERA_OK, "failed to new CameraListenerStub, ret = %{public}d", retCode);
    foldScreenType_ = system::GetParameter("const.window.foldscreen.type", "");
    isSystemApp_ = CameraSecurity::CheckSystemApp();
    CheckWhiteList();
    bundleName_ = system::GetParameter("const.camera.folded_lens_change", "default");
    curBundleName_ = GetBundleName();
    MEDIA_DEBUG_LOG("IsSystemApp = %{public}d", isSystemApp_);
}

std::string CameraManager::GetBundleName()
{
    auto bundleName = "";
    OHOS::sptr<OHOS::ISystemAbilityManager> samgr =
            OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_RET_ELOG(samgr == nullptr, bundleName, "GetClientBundle Get ability manager failed");
    OHOS::sptr<OHOS::IRemoteObject> remoteObject =
            samgr->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    CHECK_RETURN_RET_ELOG(remoteObject == nullptr, bundleName, "GetClientBundle object is NULL.");
    sptr<AppExecFwk::IBundleMgr> bms = OHOS::iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    CHECK_RETURN_RET_ELOG(bms == nullptr, bundleName, "GetClientBundle bundle manager service is NULL.");
    AppExecFwk::BundleInfo bundleInfo;
    auto ret = bms->GetBundleInfoForSelf(0, bundleInfo);
    CHECK_RETURN_RET_ELOG(ret != ERR_OK, bundleName, "GetBundleInfoForSelf failed.");
    bundleName = bundleInfo.name.c_str();
    MEDIA_INFO_LOG("bundleName: [%{private}s]", bundleName);
    return bundleName;
}

int32_t CameraManager::RefreshServiceProxy()
{
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_RET_ELOG(samgr == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CameraManager::RefreshServiceProxy Failed to get System ability manager");
    object = samgr->CheckSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_RET_ELOG(object == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CameraManager::RefreshServiceProxy Init CheckSystemAbility %{public}d is null", CAMERA_SERVICE_ID);
    auto serviceProxy = iface_cast<ICameraService>(object);
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CameraManager::RefreshServiceProxy serviceProxy is null");
    SetServiceProxy(serviceProxy);
    return CameraErrorCode::SUCCESS;
}

int32_t CameraManager::SubscribeSystemAbility()
{
    MEDIA_INFO_LOG("Enter Into CameraManager::SubscribeSystemAbility");
    // LCOV_EXCL_START
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_RET_ELOG(samgr == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CameraManager::SubscribeSystemAbility Failed to get System ability manager");
    {
        std::lock_guard<std::mutex> lock(saListenerMuxtex_);
        if (saListener_ == nullptr) {
            auto listener = new(std::nothrow) CameraServiceSystemAbilityListener();
            saListener_ = listener;
            CHECK_RETURN_RET_ELOG(saListener_ == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
                "CameraManager::SubscribeSystemAbility saListener_ is null");
            int32_t ret = samgr->SubscribeSystemAbility(CAMERA_SERVICE_ID, listener);
            MEDIA_INFO_LOG("SubscribeSystemAbility ret = %{public}d", ret);
            return ret == 0 ? CameraErrorCode::SUCCESS : CameraErrorCode::SERVICE_FATL_ERROR;
        }
    }
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int32_t CameraManager::UnSubscribeSystemAbility()
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_RET_ELOG(samgr == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CameraManager::UnSubscribeSystemAbility Failed to get System ability manager");
    CHECK_RETURN_RET(saListener_ == nullptr, CameraErrorCode::SUCCESS);
    sptr<ISystemAbilityStatusChange> listener = static_cast<ISystemAbilityStatusChange*>(saListener_.GetRefPtr());
    int32_t ret = samgr->UnSubscribeSystemAbility(CAMERA_SERVICE_ID, listener);
    MEDIA_INFO_LOG("UnSubscribeSystemAbility ret = %{public}d", ret);
    saListener_ = nullptr;
    return ret == 0 ? CameraErrorCode::SUCCESS : CameraErrorCode::SERVICE_FATL_ERROR;
}

void CameraManager::OnCameraServerAlive()
{
    int32_t ret = RefreshServiceProxy();
    CHECK_RETURN_ELOG(ret != CameraErrorCode::SUCCESS, "RefreshServiceProxy fail , ret = %{public}d", ret);
    AddServiceProxyDeathRecipient();
    if (cameraStatusListenerManager_->GetListenerCount() > 0) {
        sptr<ICameraServiceCallback> callback = cameraStatusListenerManager_;
        SetCameraServiceCallback(callback);
    }
    if (cameraMuteListenerManager_->GetListenerCount() > 0) {
        sptr<ICameraMuteServiceCallback> callback = cameraMuteListenerManager_;
        SetCameraMuteServiceCallback(callback);
    }
    if (torchServiceListenerManager_->GetListenerCount() > 0) {
        sptr<ITorchServiceCallback> callback = torchServiceListenerManager_;
        SetTorchServiceCallback(callback);
    }
    if (foldStatusListenerManager_->GetListenerCount() > 0) {
        sptr<IFoldServiceCallback> callback = foldStatusListenerManager_;
        SetFoldServiceCallback(callback);
    }
}

int32_t CameraManager::DestroyStubObj()
{
    MEDIA_INFO_LOG("Enter Into CameraManager::DestroyStubObj");
    UnSubscribeSystemAbility();
    int32_t retCode = CAMERA_UNKNOWN_ERROR;
    auto serviceProxy = GetServiceProxy();
    // LCOV_EXCL_START
    if (serviceProxy == nullptr) {
        MEDIA_ERR_LOG("serviceProxy is null");
    } else {
        retCode = serviceProxy->DestroyStubObj();
        CHECK_PRINT_ELOG(retCode != CAMERA_OK, "Failed to DestroyStubObj, retCode: %{public}d", retCode);
    }
    // LCOV_EXCL_STOP
    return ServiceToCameraError(retCode);
}

void CameraManager::CameraServerDied(pid_t pid)
{
    MEDIA_ERR_LOG("camera server has died, pid:%{public}d!", pid);
    RemoveServiceProxyDeathRecipient();
    SetServiceProxy(nullptr);
    auto cameraDeviceList = GetCameraDeviceList();
    // LCOV_EXCL_START
    for (size_t i = 0; i < cameraDeviceList.size(); i++) {
        CameraStatusInfo cameraStatusInfo;
        cameraStatusInfo.cameraDevice = cameraDeviceList[i];
        cameraStatusInfo.cameraStatus = CAMERA_SERVER_UNAVAILABLE;
        cameraStatusListenerManager_->TriggerListener(
            [&](auto listener) { listener->OnCameraStatusChanged(cameraStatusInfo); });
    }
    // LCOV_EXCL_STOP
}

int32_t CameraManager::AddServiceProxyDeathRecipient()
{
    std::lock_guard<std::mutex> lock(deathRecipientMutex_);
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CameraManager::AddServiceProxyDeathRecipient serviceProxy is null");
    auto remoteObj = serviceProxy->AsObject();
    if (deathRecipient_ != nullptr) {
        MEDIA_INFO_LOG("CameraManager::AddServiceProxyDeathRecipient remove last deathRecipient");
        remoteObj->RemoveDeathRecipient(deathRecipient_);
    }
    pid_t pid = 0;
    deathRecipient_ = new (std::nothrow) CameraDeathRecipient(pid);
    CHECK_RETURN_RET_ELOG(deathRecipient_ == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CameraManager::AddServiceProxyDeathRecipient failed to new CameraDeathRecipient");
    auto thisPtr = wptr<CameraManager>(this);
    deathRecipient_->SetNotifyCb([thisPtr](pid_t pid) {
        auto cameraManagerPtr = thisPtr.promote();
        if (cameraManagerPtr != nullptr) {
            cameraManagerPtr->CameraServerDied(pid);
        }
    });

    bool result = remoteObj->AddDeathRecipient(deathRecipient_);
    CHECK_RETURN_RET_ELOG(!result, CameraErrorCode::SERVICE_FATL_ERROR,
        "CameraManager::AddServiceProxyDeathRecipient failed to add deathRecipient");
    return CameraErrorCode::SUCCESS;
}

void CameraManager::RemoveServiceProxyDeathRecipient()
{
    std::lock_guard<std::mutex> lock(deathRecipientMutex_);
    auto serviceProxy = GetServiceProxy();
    CHECK_EXECUTE(serviceProxy != nullptr, (void)serviceProxy->AsObject()->RemoveDeathRecipient(deathRecipient_));
    deathRecipient_ = nullptr;
}

int CameraManager::CreateCameraDevice(std::string cameraId, sptr<ICameraDeviceService> *pICameraDeviceService)
{
    CAMERA_SYNC_TRACE;
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr || cameraId.empty(), CameraErrorCode::INVALID_ARGUMENT,
        "CameraManager::CreateCameraDevice serviceProxy is null or CameraID is empty: %{public}s", cameraId.c_str());
    sptr<ICameraDeviceService> device = nullptr;
    int32_t retCode = serviceProxy->CreateCameraDevice(cameraId, device);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK,
        retCode == CAMERA_NO_PERMISSION ? CAMERA_NO_PERMISSION: ServiceToCameraError(retCode),
        "CameraManager::CreateCameraDevice Failed to create camera device from hcamera service! %{public}d", retCode);
    *pICameraDeviceService = device;
    return CameraErrorCode::SUCCESS;
}

void CameraManager::SetCallback(std::shared_ptr<CameraManagerCallback> listener)
{
    RegisterCameraStatusCallback(listener);
}

void CameraManager::RegisterCameraStatusCallback(shared_ptr<CameraManagerCallback> listener)
{
    CHECK_RETURN(listener == nullptr);
    bool isSuccess = cameraStatusListenerManager_->AddListener(listener);
    CHECK_RETURN(!isSuccess);

    // First register, set callback to service, service trigger callback.
    if (cameraStatusListenerManager_->GetListenerCount() == 1) {
        sptr<ICameraServiceCallback> callback = cameraStatusListenerManager_;
        SetCameraServiceCallback(callback);
        return;
    }

    // LCOV_EXCL_START
    // Non-First register, async callback by cache data.
    auto cachedStatus = cameraStatusListenerManager_->GetCachedCameraStatus();
    auto cachedFlashStatus = cameraStatusListenerManager_->GetCachedFlashStatus();
    cameraStatusListenerManager_->TriggerTargetListenerAsync(
        listener, [cachedStatus, cachedFlashStatus](auto listener) {
            MEDIA_INFO_LOG("CameraManager::RegisterCameraStatusCallback async trigger status");
            for (auto& status : cachedStatus) {
                if (status == nullptr) {
                    continue;
                }
                listener->OnCameraStatusChanged(*status);
            }
            for (auto& status : cachedFlashStatus) {
                listener->OnFlashlightStatusChanged(status.first, status.second);
            }
        });
    // LCOV_EXCL_STOP
}

void CameraManager::UnregisterCameraStatusCallback(std::shared_ptr<CameraManagerCallback> listener)
{
    // LCOV_EXCL_START
    CHECK_RETURN(listener == nullptr);
    cameraStatusListenerManager_->RemoveListener(listener);
    if (cameraStatusListenerManager_->GetListenerCount() == 0) {
        UnSetCameraServiceCallback();
    }
    // LCOV_EXCL_STOP
}

sptr<CameraStatusListenerManager> CameraManager::GetCameraStatusListenerManager()
{
    return cameraStatusListenerManager_;
}

void CameraManager::RegisterCameraMuteListener(std::shared_ptr<CameraMuteListener> listener)
{
    CHECK_RETURN(listener == nullptr);
    bool isSuccess = cameraMuteListenerManager_->AddListener(listener);
    CHECK_RETURN(!isSuccess);
    if (cameraMuteListenerManager_->GetListenerCount() == 1) {
        sptr<ICameraMuteServiceCallback> callback = cameraMuteListenerManager_;
        int32_t errCode = SetCameraMuteServiceCallback(callback);
        CHECK_RETURN(errCode != CAMERA_OK);
    }
}

void CameraManager::UnregisterCameraMuteListener(std::shared_ptr<CameraMuteListener> listener)
{
    CHECK_RETURN(listener == nullptr);
    cameraMuteListenerManager_->RemoveListener(listener);
    if (cameraMuteListenerManager_->GetListenerCount() == 0) {
        UnSetCameraMuteServiceCallback();
    }
}

sptr<CameraMuteListenerManager> CameraManager::GetCameraMuteListenerManager()
{
    return cameraMuteListenerManager_;
}

void CameraManager::RegisterTorchListener(shared_ptr<TorchListener> listener)
{
    CHECK_RETURN(listener == nullptr);
    bool isSuccess = torchServiceListenerManager_->AddListener(listener);
    CHECK_RETURN(!isSuccess);

    // First register, set callback to service, service trigger callback.
    if (torchServiceListenerManager_->GetListenerCount() == 1) {
        sptr<ITorchServiceCallback> callback = torchServiceListenerManager_;
        SetTorchServiceCallback(callback);
        return;
    }

    // LCOV_EXCL_START
    // Non-First register, async callback by cache data.
    auto torchStatus = torchServiceListenerManager_->GetCachedTorchStatus();
    torchServiceListenerManager_->TriggerTargetListenerAsync(listener, [torchStatus](auto listener) {
        MEDIA_INFO_LOG(
            "CameraManager::RegisterTorchListener async trigger status change %{public}d %{public}d %{public}f",
            torchStatus.isTorchActive, torchStatus.isTorchAvailable, torchStatus.torchLevel);
        listener->OnTorchStatusChange(torchStatus);
    });
    // LCOV_EXCL_STOP
}

void CameraManager::UnregisterTorchListener(std::shared_ptr<TorchListener> listener)
{
    // LCOV_EXCL_START
    CHECK_RETURN(listener == nullptr);
    torchServiceListenerManager_->RemoveListener(listener);
    if (torchServiceListenerManager_->GetListenerCount() == 0) {
        UnSetTorchServiceCallback();
    }
    // LCOV_EXCL_STOP
}

sptr<TorchServiceListenerManager> CameraManager::GetTorchServiceListenerManager()
{
    return torchServiceListenerManager_;
}

void CameraManager::RegisterFoldListener(shared_ptr<FoldListener> listener)
{
    CHECK_RETURN(listener == nullptr);
    bool isSuccess = foldStatusListenerManager_->AddListener(listener);
    CHECK_RETURN(!isSuccess);
    if (foldStatusListenerManager_->GetListenerCount() == 1) {
        sptr<IFoldServiceCallback> callback = foldStatusListenerManager_;
        int32_t errCode = SetFoldServiceCallback(callback);
        CHECK_RETURN(errCode != CAMERA_OK);
    }
}

void CameraManager::UnregisterFoldListener(shared_ptr<FoldListener> listener)
{
    // LCOV_EXCL_START
    CHECK_RETURN(listener == nullptr);
    foldStatusListenerManager_->RemoveListener(listener);
    if (foldStatusListenerManager_->GetListenerCount() == 0) {
        UnSetFoldServiceCallback();
    }
    // LCOV_EXCL_STOP
}

sptr<FoldStatusListenerManager> CameraManager::GetFoldStatusListenerManager()
{
    return foldStatusListenerManager_;
}

void CameraManager::RegisterControlCenterStatusListener(std::shared_ptr<ControlCenterStatusListener> listener)
{
    // LCOV_EXCL_START
    CHECK_RETURN(listener == nullptr);
    bool isSuccess = controlCenterStatusListenerManager_->AddListener(listener);
    CHECK_RETURN(!isSuccess);
    if (controlCenterStatusListenerManager_->GetListenerCount() == 1) {
        sptr<IControlCenterStatusCallback> callback = controlCenterStatusListenerManager_;
        int32_t errCode = SetControlCenterStatusCallback(callback);
        CHECK_RETURN(errCode != CAMERA_OK);
    }
    // LCOV_EXCL_STOP
}

void CameraManager::UnregisterControlCenterStatusListener(std::shared_ptr<ControlCenterStatusListener> listener)
{
    // LCOV_EXCL_START
    CHECK_RETURN(listener == nullptr);
    controlCenterStatusListenerManager_->RemoveListener(listener);
    if (controlCenterStatusListenerManager_->GetListenerCount() == 0) {
        UnSetControlCenterStatusCallback();
    }
    // LCOV_EXCL_STOP
}

sptr<ControlCenterStatusListenerManager> CameraManager::GetControlCenterStatusListenerManager()
{
    return controlCenterStatusListenerManager_;
}

sptr<CameraDevice> CameraManager::GetCameraDeviceFromId(std::string cameraId)
{
    auto cameraDeviceList = GetCameraDeviceList();
    for (auto& deviceInfo : cameraDeviceList) {
        CHECK_RETURN_RET(deviceInfo->GetID() == cameraId, deviceInfo);
    }
    return nullptr;
}

sptr<CameraManager>& CameraManager::GetInstance()
{
    std::lock_guard<std::mutex> lock(g_instanceMutex);
    if (CameraManager::g_cameraManager == nullptr) {
        MEDIA_INFO_LOG("Initializing camera manager for first time!");
        CameraManager::g_cameraManager = new CameraManager();
        CameraManager::g_cameraManager->InitCameraManager();
    } else if (CameraManager::g_cameraManager->GetServiceProxy() == nullptr) {
        CameraManager::g_cameraManager->InitCameraManager();
    }
    return CameraManager::g_cameraManager;
}

std::vector<sptr<CameraInfo>> CameraManager::GetCameras()
{
    CAMERA_SYNC_TRACE;
    return {};
}

std::vector<dmDeviceInfo> CameraManager::GetDmDeviceInfo()
{
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(
        serviceProxy == nullptr, {}, "CameraManager::GetDmDeviceInfo serviceProxy is null, returning empty list!");

    std::vector<std::string> deviceInfos;
    int32_t retCode = serviceProxy->GetDmDeviceInfo(deviceInfos);
    CHECK_RETURN_RET_ELOG(
        retCode != CAMERA_OK, {}, "CameraManager::GetDmDeviceInfo failed!, retCode: %{public}d", retCode);

    int size = static_cast<int>(deviceInfos.size());
    MEDIA_INFO_LOG("CameraManager::GetDmDeviceInfo size=%{public}d", size);
    CHECK_RETURN_RET(size < 0, {});

    std::vector<dmDeviceInfo> distributedCamInfo(size);
    for (int i = 0; i < size; i++) {
        // LCOV_EXCL_START
        std::string deviceInfoStr = deviceInfos[i];
        MEDIA_INFO_LOG("CameraManager::GetDmDeviceInfo deviceInfo: %{public}s",
            OHOS::CameraStandard::Anonymization::AnonymizeString(deviceInfoStr).c_str());
        if (!nlohmann::json::accept(deviceInfoStr)) {
            MEDIA_ERR_LOG("Failed to verify the deviceInfo format, deviceInfo is: %{public}s",
                OHOS::CameraStandard::Anonymization::AnonymizeString(deviceInfoStr).c_str());
        } else {
            nlohmann::json deviceInfoJson = nlohmann::json::parse(deviceInfoStr);
            if ((deviceInfoJson.contains("deviceName") && deviceInfoJson.contains("deviceTypeId") &&
                    deviceInfoJson.contains("networkId")) &&
                (deviceInfoJson["deviceName"].is_string() && deviceInfoJson["networkId"].is_string())) {
                distributedCamInfo[i].deviceName = deviceInfoJson["deviceName"];
                distributedCamInfo[i].deviceTypeId = deviceInfoJson["deviceTypeId"];
                distributedCamInfo[i].networkId = deviceInfoJson["networkId"];
            }
        }
        // LCOV_EXCL_STOP
    }
    return distributedCamInfo;
}

void CameraManager::GetCameraOutputStatus(int32_t pid, int32_t &status)
{
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_ELOG(
        serviceProxy == nullptr, "CameraManager::GetCameraOutputStatus serviceProxy is null");

    int32_t retCode = serviceProxy->GetCameraOutputStatus(pid, status);
    CHECK_RETURN_ELOG(
        retCode != CAMERA_OK, "CameraManager::GetCameraOutputStatus failed!, retCode: %{public}d", retCode);
}

dmDeviceInfo CameraManager::GetDmDeviceInfo(
    const std::string& cameraId, const std::vector<dmDeviceInfo>& dmDeviceInfoList)
{
    dmDeviceInfo deviceInfo = { .deviceName = "", .deviceTypeId = 0, .networkId = "" };
    // LCOV_EXCL_START
    for (auto& info : dmDeviceInfoList) {
        if (cameraId.find(info.networkId) != std::string::npos) {
            deviceInfo = info;
            MEDIA_DEBUG_LOG("CameraManager::GetDmDeviceInfo %{public}s is remote camera", cameraId.c_str());
            break;
        }
    }
    // LCOV_EXCL_STOP
    return deviceInfo;
}

std::vector<sptr<CameraDevice>> CameraManager::GetCameraDeviceListFromServer()
{
    CAMERA_SYNC_TRACE;
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(
        serviceProxy == nullptr, {}, "CameraManager::InitCameraList serviceProxy is null, returning empty list!");
    std::vector<std::string> cameraIds;
    std::vector<sptr<CameraDevice>> deviceInfoList = {};
    int32_t retCode = serviceProxy->GetCameraIds(cameraIds);
    if (retCode == CAMERA_OK) {
        auto dmDeviceInfoList = GetDmDeviceInfo();
        for (auto& cameraId : cameraIds) {
            MEDIA_DEBUG_LOG("InitCameraList cameraId= %{public}s", cameraId.c_str());
            std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility;
            retCode = serviceProxy->GetCameraAbility(cameraId, cameraAbility);
            if (retCode != CAMERA_OK) {
                continue;
            }

            auto dmDeviceInfo = GetDmDeviceInfo(cameraId, dmDeviceInfoList);
            sptr<CameraDevice> cameraObj = new (std::nothrow) CameraDevice(cameraId, dmDeviceInfo, cameraAbility);
            if (cameraObj == nullptr) {
                MEDIA_ERR_LOG("failed to new CameraDevice!");
                continue;
            }
            SetProfile(cameraObj, cameraAbility);
            deviceInfoList.emplace_back(cameraObj);
        }
    } else {
        MEDIA_ERR_LOG("Get camera device failed!, retCode: %{public}d", retCode);
    }
    if (!foldScreenType_.empty() && foldScreenType_[0] == '4' && !GetIsInWhiteList()) {
        for (const auto& deviceInfo : deviceInfoList) {
            if (deviceInfo->GetPosition() == CAMERA_POSITION_FOLD_INNER) {
                SetInnerCamera(deviceInfo);
                break;
            }
        }
    }
    AlignVideoFpsProfile(deviceInfoList);
    std::sort(deviceInfoList.begin(), deviceInfoList.end(),
        [](const sptr<CameraDevice>& a, const sptr<CameraDevice>& b) {
            return static_cast<int>(a->GetConnectionType()) < static_cast<int>(b->GetConnectionType());
    });
    return deviceInfoList;
}

void CameraManager::ProcessModeAndOutputCapability(std::vector<std::vector<SceneMode>> &modes,
    std::vector<SceneMode> modeofThis, std::vector<std::vector<sptr<CameraOutputCapability>>> &outputCapabilities,
    std::vector<sptr<CameraOutputCapability>> outputCapabilitiesofThis)
{
    modes.push_back(modeofThis);
    outputCapabilities.push_back(outputCapabilitiesofThis);
}

void CameraManager::GetCameraConcurrentInfos(std::vector<sptr<CameraDevice>> cameraDeviceArrray,
    std::vector<bool> cameraConcurrentType, std::vector<std::vector<SceneMode>> &modes,
    std::vector<std::vector<sptr<CameraOutputCapability>>> &outputCapabilities)
{
    // LCOV_EXCL_START
    MEDIA_INFO_LOG("CameraManager::GetCameraConcurrentInfos start");
    CAMERA_SYNC_TRACE;
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_ELOG(
        serviceProxy == nullptr, "CameraManager::InitCameraList serviceProxy is null, returning empty list!");
    int32_t retCode;
    int index = 0;
    for (auto cameraDev : cameraDeviceArrray) {
        std::vector<SceneMode> modeofThis = {};
        std::vector<sptr<CameraOutputCapability>> outputCapabilitiesofThis = {};
        CameraPosition cameraPosition = cameraDev->GetPosition();
        auto iter = fwToMetaCameraPosition_.find(cameraPosition);
        if (iter == fwToMetaCameraPosition_.end()) {
            ProcessModeAndOutputCapability(modes, modeofThis, outputCapabilities, outputCapabilitiesofThis);
            continue;
        }
        string idOfThis = {};
        serviceProxy->GetIdforCameraConcurrentType(iter->second, idOfThis);
        sptr<ICameraDeviceService> cameradevicephysic = nullptr;
        CreateCameraDevice(idOfThis, &cameradevicephysic);
        std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility;
        retCode = serviceProxy->GetConcurrentCameraAbility(idOfThis, cameraAbility);
        if (retCode != CAMERA_OK) {
            ProcessModeAndOutputCapability(modes, modeofThis, outputCapabilities, outputCapabilitiesofThis);
            index++;
            continue;
        }
        sptr<CameraDevice> cameraObjnow = new (std::nothrow) CameraDevice(idOfThis, cameraAbility);
        camera_metadata_item_t item;
        if (!cameraConcurrentType[index]) {
            retCode = Camera::FindCameraMetadataItem(cameraAbility->get(),
                OHOS_ABILITY_AVAILABLE_PROFILE_LEVEL, &item);
            if (retCode == CAM_META_SUCCESS) {
                GetMetadataInfos(item, modeofThis, outputCapabilitiesofThis, cameraAbility);
            }
            ProcessModeAndOutputCapability(modes, modeofThis, outputCapabilities, outputCapabilitiesofThis);
        } else {
            retCode = Camera::FindCameraMetadataItem(cameraAbility->get(),
                OHOS_ABILITY_CAMERA_LIMITED_CAPABILITIES, &item);
            if (retCode == CAM_META_SUCCESS) {
                ParsingCameraConcurrentLimted(item, modeofThis, outputCapabilitiesofThis, cameraAbility, cameraObjnow);
            } else {
                MEDIA_ERR_LOG("GetCameraConcurrentInfos error");
            }
            ProcessModeAndOutputCapability(modes, modeofThis, outputCapabilities, outputCapabilitiesofThis);
        }
        index++;
    }
    // LCOV_EXCL_STOP
}

void CameraManager::ParsingCameraConcurrentLimted(camera_metadata_item_t &item,
    std::vector<SceneMode> &mode, std::vector<sptr<CameraOutputCapability>> &outputCapabilitiesofThis,
    shared_ptr<OHOS::Camera::CameraMetadata> &cameraAbility, sptr<CameraDevice>cameraDevNow)
{
    // LCOV_EXCL_START
    MEDIA_INFO_LOG("CameraManager::ParsingCameraConcurrentLimted start");
    double* originInfo = item.data.d;
    uint32_t count = item.count;
    CHECK_RETURN_ELOG(
        cameraDevNow == nullptr, "CameraManager::ParsingCameraConcurrentLimted cameraDevNow is null");
    cameraDevNow->limtedCapabilitySave_.flashmodes.count = 0;
    cameraDevNow->limtedCapabilitySave_.flashmodes.mode.clear();
    cameraDevNow->limtedCapabilitySave_.exposuremodes.count = 0;
    cameraDevNow->limtedCapabilitySave_.exposuremodes.mode.clear();
    cameraDevNow->limtedCapabilitySave_.ratiorange.count = 0;
    cameraDevNow->limtedCapabilitySave_.ratiorange.mode.clear();
    cameraDevNow->limtedCapabilitySave_.ratiorange.range.clear();
    cameraDevNow->limtedCapabilitySave_.compensation.count = 0;
    cameraDevNow->limtedCapabilitySave_.compensation.range.clear();
    cameraDevNow->limtedCapabilitySave_.focusmodes.count = 0;
    cameraDevNow->limtedCapabilitySave_.focusmodes.mode.clear();
    cameraDevNow->limtedCapabilitySave_.stabilizationmodes.count = 0;
    cameraDevNow->limtedCapabilitySave_.stabilizationmodes.mode.clear();
    cameraDevNow->limtedCapabilitySave_.colorspaces.modeCount = 0;
    cameraDevNow->limtedCapabilitySave_.colorspaces.modeInfo.clear();
    for (int32_t i = 0; i < static_cast<int32_t>(count);) {
        if (static_cast<camera_device_metadata_tag>(originInfo[i]) == OHOS_ABILITY_FLASH_MODES) {
            std::vector<int32_t>vec;
            int length = static_cast<int32_t>(originInfo[i + STEP_ONE]);
            cameraDevNow->limtedCapabilitySave_.flashmodes.count = length;
            GetAbilityStructofConcurrentLimted(vec, originInfo + i + STEP_TWO, length);
            cameraDevNow->limtedCapabilitySave_.flashmodes.mode = vec;
            i = i + length + STEP_TWO + STEP_ONE;
        } else if (static_cast<camera_device_metadata_tag>(originInfo[i]) == OHOS_ABILITY_EXPOSURE_MODES) {
            std::vector<int32_t>vec;
            int length = static_cast<int32_t>(originInfo[i + STEP_ONE]);
            cameraDevNow->limtedCapabilitySave_.exposuremodes.count = length;
            GetAbilityStructofConcurrentLimted(vec, originInfo + i + STEP_TWO, length);
            cameraDevNow->limtedCapabilitySave_.exposuremodes.mode = vec;
            i = i + length + STEP_TWO + STEP_ONE;
        } else if (static_cast<camera_device_metadata_tag>(originInfo[i]) == OHOS_ABILITY_ZOOM_RATIO_RANGE) {
            std::vector<float>vec;
            int length = static_cast<int32_t>(originInfo[i + STEP_ONE]);
            cameraDevNow->limtedCapabilitySave_.ratiorange.count = length / STEP_THREE;
            for (int j = i + STEP_TWO; j < i + length + STEP_TWO + STEP_ONE; j += STEP_THREE) {
                cameraDevNow->limtedCapabilitySave_.ratiorange.mode.push_back(static_cast<int32_t>(originInfo[j]));
                cameraDevNow->limtedCapabilitySave_.ratiorange.range.insert({static_cast<int32_t>(originInfo[j]),
                    make_pair(static_cast<float>(originInfo[j + STEP_ONE]),
                        static_cast<float>(originInfo[j + STEP_TWO]))});
            }
            i = i + length + STEP_TWO + STEP_ONE;
        } else if (static_cast<camera_device_metadata_tag>(originInfo[i]) == OHOS_ABILITY_AE_COMPENSATION_RANGE) {
            std::vector<float>vec;
            int length = static_cast<int32_t>(originInfo[i + STEP_ONE]);
            cameraDevNow->limtedCapabilitySave_.compensation.count = length;
            GetAbilityStructofConcurrentLimtedfloat(vec, originInfo + i + STEP_TWO, length);
            cameraDevNow->limtedCapabilitySave_.compensation.range = vec;
            i = i + length + STEP_TWO + STEP_ONE;
        } else if (static_cast<camera_device_metadata_tag>(originInfo[i]) == OHOS_ABILITY_FOCUS_MODES) {
            std::vector<int32_t>vec;
            int length = static_cast<int32_t>(originInfo[i + STEP_ONE]);
            cameraDevNow->limtedCapabilitySave_.focusmodes.count = length;
            GetAbilityStructofConcurrentLimted(vec, originInfo + i + STEP_TWO, length);
            cameraDevNow->limtedCapabilitySave_.focusmodes.mode = vec;
            i = i + length + STEP_TWO + STEP_ONE;
        } else if (static_cast<camera_device_metadata_tag>(originInfo[i]) == OHOS_ABILITY_VIDEO_STABILIZATION_MODES) {
            std::vector<int32_t>vec;
            int length = static_cast<int32_t>(originInfo[i + STEP_ONE]);
            cameraDevNow->limtedCapabilitySave_.stabilizationmodes.count = length;
            GetAbilityStructofConcurrentLimted(vec, originInfo + i + STEP_TWO, length);
            cameraDevNow->limtedCapabilitySave_.stabilizationmodes.mode = vec;
            i = i + length + STEP_TWO + STEP_ONE;
        } else if (static_cast<camera_device_metadata_tag>(originInfo[i]) == OHOS_ABILITY_AVAILABLE_COLOR_SPACES) {
            std::shared_ptr<ColorSpaceInfoParse> colorSpaceParse = std::make_shared<ColorSpaceInfoParse>();
            int countl = 0;
            FindConcurrentLimtedEnd(originInfo, i, count, countl);
            colorSpaceParse->getColorSpaceInfoforConcurrent(originInfo + i + STEP_ONE,
                countl - STEP_ONE, cameraDevNow->limtedCapabilitySave_.colorspaces);
                i = i + countl + STEP_ONE;
        } else if (static_cast<camera_device_metadata_tag>(originInfo[i]) == OHOS_ABILITY_AVAILABLE_PROFILE_LEVEL) {
            GetMetadataInfosfordouble(item, originInfo, i + STEP_ONE, mode, outputCapabilitiesofThis, cameraAbility);
            break;
        } else {
            i++;
        }
    }
    cameraConLimCapMap_.insert({cameraDevNow->GetID(), cameraDevNow->limtedCapabilitySave_});
    // LCOV_EXCL_STOP
}

void CameraManager::FindConcurrentLimtedEnd(double* originInfo, int32_t i, int count, int &countl)
{
    // LCOV_EXCL_START
    for (int32_t j = i + STEP_ONE; j < count; j++) {
        if (static_cast<camera_device_metadata_tag>(originInfo[j]) == OHOS_ABILITY_AVAILABLE_PROFILE_LEVEL) {
            break;
        }
        countl++;
    }
    // LCOV_EXCL_STOP
}

void CameraManager::GetAbilityStructofConcurrentLimted(std::vector<int32_t>&vec, double* originInfo, int length)
{
    // LCOV_EXCL_START
    for (int i = 0; i < length; i++) {
        vec.push_back(static_cast<int32_t>(originInfo[i]));
    }
    // LCOV_EXCL_STOP
}

void CameraManager::GetAbilityStructofConcurrentLimtedfloat(std::vector<float>&vec, double* originInfo, int length)
{
    // LCOV_EXCL_START
    for (int i = 0; i < length; i++) {
        vec.push_back(static_cast<float>(originInfo[i]));
    }
    // LCOV_EXCL_STOP
}

void CameraManager::GetMetadataInfos(camera_metadata_item_t item,
    std::vector<SceneMode> &modeofThis, std::vector<sptr<CameraOutputCapability>> &outputCapabilitiesofThis,
    shared_ptr<OHOS::Camera::CameraMetadata> &cameraAbility)
{
    // LCOV_EXCL_START
    ProfilesWrapper profilesWrapper = {};
    std::vector<ProfileLevelInfo> modeInfosum = {};
    int32_t* originInfo = item.data.i32;
    uint32_t count = item.count;
    CHECK_RETURN(count == 0 || originInfo == nullptr);
    uint32_t i = 0;
    uint32_t j = i + STEP_THREE;
    auto isModeEnd = [](int32_t *originInfo, uint32_t j) {
        return originInfo[j] == MODE_END && originInfo[j - 1] == SPEC_END &&
                originInfo[j - 2] == STREAM_END && originInfo[j - 3] == DETAIL_END;
    };
    while (j < count) {
        if (originInfo[j] != MODE_END) {
            j = j + STEP_FOUR;
            continue;
        }
        if (isModeEnd(originInfo, j)) {
            ProfileLevelInfo modeInfo = {};
            modeofThis.push_back(static_cast<SceneMode>(originInfo[i]));
            CameraAbilityParseUtil::GetSpecInfo(originInfo, i + 1, j - 1, modeInfo);
            i = j + 1;
            j = i + 1;
            modeInfosum.push_back(modeInfo);
        } else {
            j++;
        }
    }
    int32_t mCount = 0;
    for (auto &modeInfo : modeInfosum) {
        std::vector<SpecInfo> specInfos;
        ProfilesWrapper profilesWrapper;
        specInfos.insert(specInfos.end(), modeInfo.specInfos.begin(), modeInfo.specInfos.end());
        sptr<CameraOutputCapability> cameraOutputCapability = new (std::nothrow) CameraOutputCapability();
        for (SpecInfo& specInfo : specInfos) {
            for (StreamInfo& streamInfo : specInfo.streamInfos) {
                CreateProfileLevel4StreamType(profilesWrapper, specInfo.specId, streamInfo);
            }
        }
        int32_t modename = modeofThis[mCount];
        SetCameraOutputCapabilityofthis(cameraOutputCapability, profilesWrapper,
            modename, cameraAbility);
        outputCapabilitiesofThis.push_back(cameraOutputCapability);
        mCount++;
    }
    // LCOV_EXCL_STOP
}

void CameraManager::SetCameraOutputCapabilityofthis(sptr<CameraOutputCapability> &cameraOutputCapability,
    ProfilesWrapper &profilesWrapper, int32_t modeName,
    shared_ptr<OHOS::Camera::CameraMetadata> &cameraAbility)
{
    // LCOV_EXCL_START
    if (IsSystemApp()) {
        FillSupportPhotoFormats(profilesWrapper.photoProfiles);
    }
    CHECK_RETURN_ELOG(
        cameraOutputCapability == nullptr, "cameraOutputCapability is null");
    cameraOutputCapability->SetPhotoProfiles(profilesWrapper.photoProfiles);
    MEDIA_INFO_LOG("SetPhotoProfiles size = %{public}zu", profilesWrapper.photoProfiles.size());
    cameraOutputCapability->SetPreviewProfiles(profilesWrapper.previewProfiles);
    MEDIA_INFO_LOG("SetPreviewProfiles size = %{public}zu", profilesWrapper.previewProfiles.size());
    if (!isPhotoMode_.count(modeName)) {
        cameraOutputCapability->SetVideoProfiles(profilesWrapper.vidProfiles);
    }
    MEDIA_INFO_LOG("SetVideoProfiles size = %{public}zu", profilesWrapper.vidProfiles.size());
    cameraOutputCapability->SetDepthProfiles(depthProfiles_);
    MEDIA_INFO_LOG("SetDepthProfiles size = %{public}zu", depthProfiles_.size());

    std::vector<MetadataObjectType> objectTypes = {};
    camera_metadata_item_t metadataItem;
    int32_t ret = Camera::FindCameraMetadataItem(cameraAbility->get(),
        OHOS_ABILITY_STATISTICS_DETECT_TYPE, &metadataItem);
    if (ret == CAM_META_SUCCESS) {
        for (uint32_t index = 0; index < metadataItem.count; index++) {
            auto iterator =
                g_metaToFwCameraMetaDetect_.find(static_cast<StatisticsDetectType>(metadataItem.data.u8[index]));
            CHECK_PRINT_ELOG(iterator == g_metaToFwCameraMetaDetect_.end(),
                "Not supported metadataItem %{public}d", metadataItem.data.u8[index]);
            if (iterator != g_metaToFwCameraMetaDetect_.end()) {
                objectTypes.push_back(iterator->second);
            }
        }
    }
    if (!CameraSecurity::CheckSystemApp()) {
        MEDIA_DEBUG_LOG("public calling for GetSupportedOutputCapability");
        if (std::any_of(objectTypes.begin(), objectTypes.end(),
                        [](MetadataObjectType type) { return type == MetadataObjectType::FACE; })) {
            cameraOutputCapability->SetSupportedMetadataObjectType({MetadataObjectType::FACE});
        } else {
            cameraOutputCapability->SetSupportedMetadataObjectType({});
        }
    } else {
        cameraOutputCapability->SetSupportedMetadataObjectType(objectTypes);
    }
    MEDIA_INFO_LOG("SetMetadataTypes size = %{public}zu",
                   cameraOutputCapability->GetSupportedMetadataObjectType().size());
    // LCOV_EXCL_STOP
}

bool CameraManager::GetConcurrentType(std::vector<sptr<CameraDevice>> cameraDeviceArrray,
    std::vector<bool> &cameraConcurrentType)
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(
        serviceProxy == nullptr, false, "CameraManager::InitCameraList serviceProxy is null, returning empty list!");
    int32_t retCode;
    for (auto cameraDev : cameraDeviceArrray) {
        CameraPosition cameraPosition = cameraDev->GetPosition();
        CHECK_RETURN_RET_ELOG(cameraPosition == CameraPosition::CAMERA_POSITION_FOLD_INNER, false,
            "CameraManager::GetConcurrentType this device camera position is 3!");
        string idofthis;
        auto iter = fwToMetaCameraPosition_.find(cameraPosition);
        serviceProxy->GetIdforCameraConcurrentType(iter->second, idofthis);

        std::shared_ptr<OHOS::Camera::CameraMetadata> camAbility;
        retCode = serviceProxy->GetConcurrentCameraAbility(idofthis, camAbility);
        if (retCode != CAMERA_OK) {
            continue;
        }
        camera_metadata_item_t item;
        retCode = Camera::FindCameraMetadataItem(camAbility->get(), OHOS_ABILITY_CAMERA_CONCURRENT_TYPE, &item);
        if (retCode != CAMERA_OK) {
            cameraConcurrentType.clear();
            MEDIA_ERR_LOG("cameraAbility not support OHOS_ABILITY_CAMERA_CONCURRENT_TYPE");
            return false;
        }
        bool cameratype = 0;
        if (item.count > 0) {
            cameratype = static_cast<bool>(item.data.u8[0]);
        }
        MEDIA_INFO_LOG("cameraid is %{public}s, type is %{public}d", idofthis.c_str(), cameratype);
        cameraConcurrentType.push_back(cameratype);
    }
    return true;
    // LCOV_EXCL_STOP
}

bool CameraManager::CheckCameraConcurrentId(std::unordered_map<std::string, int32_t> &idmap,
    std::vector<std::string> &cameraIdv)
{
    // LCOV_EXCL_START
    for (uint32_t i = 1; i < cameraIdv.size(); i++) {
        CHECK_PRINT_ELOG(cameraIdv[i].empty(), "CameraManager::CheckCameraConcurrentId get invalid cameraId");
        std::regex regex("\\d+$");
        std::smatch match;
        std::string cameraId;
        if (std::regex_search(cameraIdv[i], match, regex)) {
            cameraId = match[0];
        }
        MEDIA_DEBUG_LOG("CameraManager::CheckCameraConcurrentId check cameraId: %{public}s", cameraId.c_str());
        CHECK_RETURN_RET(!idmap.count(cameraId), false);
    }
    return true;
    // LCOV_EXCL_STOP
}

bool CameraManager::CheckConcurrentExecution(std::vector<sptr<CameraDevice>> cameraDeviceArrray)
{
    // LCOV_EXCL_START
    std::vector<std::string>cameraIdv = {};
    CAMERA_SYNC_TRACE;
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(
        serviceProxy == nullptr, false, "CameraManager::InitCameraList serviceProxy is null, returning empty list!");
    int32_t retCode;
    
    for (auto cameraDev : cameraDeviceArrray) {
        CameraPosition cameraPosition = cameraDev->GetPosition();
        string idofthis;
        auto iter = fwToMetaCameraPosition_.find(cameraPosition);
        serviceProxy->GetIdforCameraConcurrentType(iter->second, idofthis);
        cameraIdv.push_back(idofthis);
    }
    CHECK_RETURN_RET_ELOG(cameraIdv.size() == 0, false, "no find cameraid");
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility;
    retCode = serviceProxy->GetConcurrentCameraAbility(cameraIdv[0], cameraAbility);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, false, "GetCameraAbility fail");
    camera_metadata_item_t item;
    retCode = Camera::FindCameraMetadataItem(cameraAbility->get(), OHOS_ABILITY_CONCURRENT_SUPPORTED_CAMERAS, &item);
    if (retCode == CAMERA_OK) {
        MEDIA_DEBUG_LOG("success find OHOS_ABILITY_CONCURRENT_SUPPORTED_CAMERAS");
        for (uint32_t i = 0; i < item.count; i++) {
            MEDIA_DEBUG_LOG("concurrent cameras: %{public}d", item.data.i32[i]);
        }
    }
    int32_t* originInfo = item.data.i32;
    std::unordered_map<std::string, int32_t>idmap;
    idmap.clear();
    uint32_t count = item.count;
    for (uint32_t i = 0; i < count; i++) {
        if (originInfo[i] == -1) {
            CHECK_RETURN_RET(CheckCameraConcurrentId(idmap, cameraIdv), true);
            idmap.clear();
        } else {
            idmap[std::to_string(originInfo[i])]++;
        }
    }
    if (CheckCameraConcurrentId(idmap, cameraIdv)) {
        return true;
    }
    return false;
    // LCOV_EXCL_STOP
}

void CameraManager::GetMetadataInfosfordouble(camera_metadata_item_t &item, double* originInfo, uint32_t i,
    std::vector<SceneMode> &modeofThis, std::vector<sptr<CameraOutputCapability>> &outputCapabilitiesofThis,
    shared_ptr<OHOS::Camera::CameraMetadata> &cameraAbility)
{
    // LCOV_EXCL_START
    MEDIA_INFO_LOG("CameraManager::GetMetadataInfosfordouble start");
    ProfilesWrapper profilesWrapper = {};
    std::vector<ProfileLevelInfo> modeInfosum = {};
    uint32_t count = item.count;
    CHECK_RETURN(count == 0 || originInfo == nullptr);
    uint32_t j = i + STEP_THREE;
    auto isModeEnd = [](double *originInfo, uint32_t j) {
        return static_cast<int32_t>(originInfo[j]) == INT_MAX && static_cast<int32_t>(originInfo[j - 1]) == INT_MAX &&
                static_cast<int32_t>(originInfo[j - 2]) == INT_MAX &&
                static_cast<int32_t>(originInfo[j - 3]) == INT_MAX;
    };
    while (j < count) {
        if (static_cast<int32_t>(originInfo[j]) != INT_MAX) {
            j = j + STEP_FOUR;
            continue;
        }
        if (isModeEnd(originInfo, j)) {
            ProfileLevelInfo modeInfo = {};
            modeofThis.push_back(static_cast<SceneMode>(originInfo[i]));
            GetSpecInfofordouble(originInfo, i + 1, j - 1, modeInfo);
            modeInfosum.push_back(modeInfo);
            i = j + 1;
            j = i + 1;
        } else {
            j++;
        }
    }
    int32_t modecount = 0;
    for (auto &modeInfo : modeInfosum) {
        std::vector<SpecInfo> specInfos;
        ProfilesWrapper profilesWrapper;
        specInfos.insert(specInfos.end(), modeInfo.specInfos.begin(), modeInfo.specInfos.end());
        sptr<CameraOutputCapability> cameraOutputCapability = new (std::nothrow) CameraOutputCapability();
        for (SpecInfo& specInfo : specInfos) {
            for (StreamInfo& streamInfo : specInfo.streamInfos) {
                CreateProfileLevel4StreamType(profilesWrapper, specInfo.specId, streamInfo);
            }
        }
        int32_t modename = modeofThis[modecount];
        SetCameraOutputCapabilityofthis(cameraOutputCapability, profilesWrapper,
            modename, cameraAbility);
        
        outputCapabilitiesofThis.push_back(cameraOutputCapability);
        modecount++;
    }
    // LCOV_EXCL_STOP
}

void CameraManager::GetSpecInfofordouble(double *originInfo, uint32_t start, uint32_t end, ProfileLevelInfo &modeInfo)
{
    // LCOV_EXCL_START
    uint32_t i = start;
    uint32_t j = i + STEP_TWO;
    std::vector<std::pair<uint32_t, uint32_t>> specIndexRange;
    while (j <= end) {
        if (static_cast<int32_t>(originInfo[j]) != INT_MAX) {
            j = j + STEP_THREE;
            continue;
        }
        if (static_cast<int32_t>(originInfo[j - STEP_ONE]) == INT_MAX &&
            static_cast<int32_t>(originInfo[j - STEP_TWO]) == INT_MAX) {
            std::pair<uint32_t, uint32_t> indexPair(i, j);
            specIndexRange.push_back(indexPair);
            i = j + STEP_ONE;
            j = i + STEP_TWO;
        } else {
            j++;
        }
    }
    uint32_t specCount = specIndexRange.size();
    modeInfo.specInfos.resize(specCount);

    for (uint32_t k = 0; k < specCount; ++k) {
        SpecInfo& specInfo = modeInfo.specInfos[k];
        i = specIndexRange[k].first;
        j = specIndexRange[k].second;
        specInfo.specId = static_cast<int32_t>(originInfo[j]);
        GetStreamInfofordouble(originInfo, i + 1, j - 1, specInfo);
    }
    // LCOV_EXCL_STOP
}

void CameraManager::GetStreamInfofordouble(double *originInfo, uint32_t start, uint32_t end, SpecInfo &specInfo)
{
    // LCOV_EXCL_START
    uint32_t i = start;
    uint32_t j = i + STEP_ONE;

    std::vector<std::pair<uint32_t, uint32_t>> streamIndexRange;
    while (j <= end) {
        if (static_cast<int32_t>(originInfo[j]) == INT_MAX) {
            if (static_cast<int32_t>(originInfo[j - 1]) == INT_MAX) {
                std::pair<uint32_t, uint32_t> indexPair(i, j);
                streamIndexRange.push_back(indexPair);
                i = j + STEP_ONE;
                j = i + STEP_ONE;
            } else {
                j++;
            }
        } else {
            j = j + STEP_TWO;
        }
    }
    uint32_t streamTypeCount = streamIndexRange.size();
    specInfo.streamInfos.resize(streamTypeCount);

    for (uint32_t k = 0; k < streamTypeCount; ++k) {
        StreamInfo& streamInfo = specInfo.streamInfos[k];
        i = streamIndexRange[k].first;
        j = streamIndexRange[k].second;
        streamInfo.streamType = static_cast<int32_t>(originInfo[i]);
        GetDetailInfofordouble(originInfo, i + 1, j - 1, streamInfo);
    }
    // LCOV_EXCL_STOP
}

void CameraManager::GetDetailInfofordouble(double *originInfo, uint32_t start, uint32_t end, StreamInfo &streamInfo)
{
    // LCOV_EXCL_START
    uint32_t i = start;
    uint32_t j = i;
    std::vector<std::pair<uint32_t, uint32_t>> detailIndexRange;
    while (j <= end) {
        if (static_cast<int32_t>(originInfo[j]) == INT_MAX) {
            std::pair<uint32_t, uint32_t> indexPair(i, j);
            detailIndexRange.push_back(indexPair);
            i = j + STEP_ONE;
            j = i;
        } else {
            j++;
        }
    }

    uint32_t detailCount = detailIndexRange.size();
    streamInfo.detailInfos.resize(detailCount);

    for (uint32_t k = 0; k < detailCount; ++k) {
        auto &detailInfo = streamInfo.detailInfos[k];
        i = detailIndexRange[k].first;
        j = detailIndexRange[k].second;
        detailInfo.format = static_cast<uint32_t>(originInfo[i++]);
        detailInfo.width = static_cast<uint32_t>(originInfo[i++]);
        detailInfo.height = static_cast<uint32_t>(originInfo[i++]);
        detailInfo.fixedFps = static_cast<uint32_t>(originInfo[i++]);
        detailInfo.minFps = static_cast<uint32_t>(originInfo[i++]);
        detailInfo.maxFps = static_cast<uint32_t>(originInfo[i++]);
        detailInfo.abilityIds.resize(j - i);
        std::transform(originInfo + i, originInfo + j, detailInfo.abilityIds.begin(),
            [](auto val) { return static_cast<uint32_t>(val); });
    }
    // LCOV_EXCL_STOP
}

void CameraManager::SetProfile(sptr<CameraDevice>& cameraObj, std::shared_ptr<OHOS::Camera::CameraMetadata> metadata)
{
    CHECK_RETURN_ELOG(
        cameraObj == nullptr, "CameraManager::SetProfile cameraObj is null");
    std::vector<SceneMode> supportedModes = GetSupportedModes(cameraObj);
    if (supportedModes.empty()) {
        // LCOV_EXCL_START
        auto capability = ParseSupportedOutputCapability(cameraObj, 0, metadata);
        cameraObj->SetProfile(capability);
        // LCOV_EXCL_STOP
    } else {
        supportedModes.emplace_back(NORMAL);
        for (const auto &modeName : supportedModes) {
            auto capability = ParseSupportedOutputCapability(cameraObj, modeName, metadata);
            cameraObj->SetProfile(capability, modeName);
        }
    }
}

bool CameraManager::GetIsFoldable()
{
    return !foldScreenType_.empty();
}

std::string CameraManager::GetFoldScreenType()
{
    return foldScreenType_;
}

FoldStatus CameraManager::GetFoldStatus()
{
    auto curFoldStatus = (FoldStatus)OHOS::Rosen::DisplayManager::GetInstance().GetFoldStatus();
    if (curFoldStatus == FoldStatus::HALF_FOLD) {
        curFoldStatus = FoldStatus::EXPAND;
    }
    return curFoldStatus;
}

void CameraManager::CheckWhiteList()
{
    // LCOV_EXCL_START
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_ELOG(
        serviceProxy == nullptr, "CameraManager::CheckWhitelist serviceProxy is null");
    serviceProxy->CheckWhiteList(isInWhiteList_);
    // LCOV_EXCL_STOP
}

bool CameraManager::GetIsInWhiteList()
{
    MEDIA_DEBUG_LOG("isInWhiteList: %{public}d", isInWhiteList_);
    return isInWhiteList_;
}

std::vector<sptr<CameraDevice>> CameraManager::GetSupportedCameras()
{
    CAMERA_SYNC_TRACE;
    auto curFoldStatus = GetFoldStatus();
    std::vector<sptr<CameraDevice>> cameraDeviceList;
    // LCOV_EXCL_START
    if (curFoldStatus != preFoldStatus && !foldScreenType_.empty() && foldScreenType_[0] == '4') {
        std::lock_guard<std::mutex> lock(cameraDeviceListMutex_);
        cameraDeviceList = GetCameraDeviceListFromServer();
        cameraDeviceList_ = cameraDeviceList;
        preFoldStatus = curFoldStatus;
    } else {
        cameraDeviceList = GetCameraDeviceList();
    }
    // LCOV_EXCL_STOP
    bool isFoldable = GetIsFoldable();
    CHECK_RETURN_RET(!isFoldable, cameraDeviceList);
    MEDIA_INFO_LOG("fold status: %{public}d", curFoldStatus);
    CHECK_RETURN_RET(curFoldStatus == FoldStatus::UNKNOWN_FOLD &&
        !foldScreenType_.empty() && foldScreenType_[0] == '4', cameraDeviceList);
    std::vector<sptr<CameraDevice>> supportedCameraDeviceList;
    uint32_t apiCompatibleVersion = CameraApiVersion::GetApiVersion();
    // LCOV_EXCL_START
    for (const auto& deviceInfo : cameraDeviceList) {
        // The usb camera is added to the list and is not processed.
        if (deviceInfo->GetConnectionType() == CAMERA_CONNECTION_USB_PLUGIN ||
            (deviceInfo->GetConnectionType() == CAMERA_CONNECTION_REMOTE &&
            deviceInfo->GetSupportedFoldStatus() == OHOS_CAMERA_FOLD_STATUS_NONFOLDABLE)) {
            supportedCameraDeviceList.emplace_back(deviceInfo);
            continue;
        }
        if (!foldScreenType_.empty() && foldScreenType_[0] == '4' &&
            (deviceInfo->GetPosition() == CAMERA_POSITION_BACK ||
            deviceInfo->GetPosition() == CAMERA_POSITION_FOLD_INNER ||
            deviceInfo->GetPosition() == CAMERA_POSITION_FRONT) && !GetIsInWhiteList() &&
            curFoldStatus == FoldStatus::EXPAND) {
            auto it = std::find_if(supportedCameraDeviceList.begin(), supportedCameraDeviceList.end(),
                [&deviceInfo](sptr<CameraDevice> cameraDevice) {
                return cameraDevice->GetPosition() == deviceInfo->GetPosition();
            });
            if (it != supportedCameraDeviceList.end()) {
                continue;
            }
            supportedCameraDeviceList.emplace_back(deviceInfo);
            continue;
        }
        // Check for API compatibility
        if (apiCompatibleVersion < CameraApiVersion::APIVersion::API_FOURTEEN) {
            bool isBackCamera = deviceInfo->GetPosition() == CAMERA_POSITION_BACK;
            bool isInnerOrFrontCamera = (deviceInfo->GetPosition() == CAMERA_POSITION_FOLD_INNER ||
                deviceInfo->GetPosition() == CAMERA_POSITION_FRONT);
            bool isUnsupportedFoldScreenType = (!foldScreenType_.empty() &&
                foldScreenType_[0] != '2' && foldScreenType_[0] != '4' && foldScreenType_[0] != '5');
            if ((isBackCamera || isInnerOrFrontCamera) && isUnsupportedFoldScreenType) {
                supportedCameraDeviceList.emplace_back(deviceInfo);
                continue;
            }
        }

        auto supportedFoldStatus = deviceInfo->GetSupportedFoldStatus();

        auto it = g_metaToFwCameraFoldStatus_.find(static_cast<CameraFoldStatus>(supportedFoldStatus));
        if (it == g_metaToFwCameraFoldStatus_.end()) {
            MEDIA_INFO_LOG("No supported fold status is found, fold status: %{public}d", curFoldStatus);
            supportedCameraDeviceList.emplace_back(deviceInfo);
            continue;
        }
        if (!foldScreenType_.empty() && foldScreenType_[0] == '4' && curFoldStatus == FoldStatus::FOLDED &&
            it->second == curFoldStatus && deviceInfo->GetPosition() == CAMERA_POSITION_BACK
            && bundleName_ != curBundleName_) {
            continue;
        }
        CHECK_EXECUTE(it->second == curFoldStatus, supportedCameraDeviceList.emplace_back(deviceInfo));
    }
    // LCOV_EXCL_STOP
    return supportedCameraDeviceList;
}

std::vector<SceneMode> CameraManager::GetSupportedModes(sptr<CameraDevice>& camera)
{
    CHECK_RETURN_RET(camera == nullptr, {});
    std::vector<SceneMode> supportedSceneModes = camera->GetSupportedModes();
    MEDIA_DEBUG_LOG("CameraManager::GetSupportedModes supportedModes size: %{public}zu", supportedSceneModes.size());
    return supportedSceneModes;
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
        if (camera->GetPosition() == CAMERA_POSITION_FRONT) {
            frontVideoProfiles = camera->modeVideoProfiles_[normalMode];
            frontCamera = camera;
        } else if (camera->GetPosition() == CAMERA_POSITION_BACK) {
            backVideoProfiles = camera->modeVideoProfiles_[normalMode];
        }
    }
    const uint32_t minIndex = 0;
    const uint32_t maxIndex = 1;
    CHECK_RETURN_ELOG(!(frontVideoProfiles.size() && backVideoProfiles.size()),
        "CameraManager::AlignVideoFpsProfile failed! frontVideoSize = %{public}zu, "
        "frontVideoSize = %{public}zu", frontVideoProfiles.size(), backVideoProfiles.size());
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
    CHECK_RETURN(!frontCamera);
    frontCamera->modeVideoProfiles_[normalMode] = alignFrontVideoProfiles;
    for (auto& frontProfile : alignFrontVideoProfiles) {
        MEDIA_INFO_LOG("CameraManager::AlignVideoFpsProfile frontProfile "
                       "w(%{public}d),h(%{public}d) fps min(%{public}d),min(%{public}d)",
            frontProfile.GetSize().width, frontProfile.GetSize().height, frontProfile.framerates_[minIndex],
            frontProfile.framerates_[maxIndex]);
    }
}

SceneMode CameraManager::GetFallbackConfigMode(SceneMode profileMode, ProfilesWrapper& profilesWrapper)
{
    MEDIA_DEBUG_LOG("CameraManager::GetFallbackConfigMode profileMode:%{public}d", profileMode);
    // LCOV_EXCL_START
    if (profilesWrapper.photoProfiles.empty() && profilesWrapper.previewProfiles.empty() &&
        profilesWrapper.vidProfiles.empty()) {
        switch (profileMode) {
            case CAPTURE_MACRO:
                return CAPTURE;
            case VIDEO_MACRO:
                return VIDEO;
            default:
                return profileMode;
        }
    }
    // LCOV_EXCL_STOP
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
    int32_t retCode = CreateCameraInput(camera, &cameraInput);
    CHECK_RETURN_RET_ELOG(retCode != CameraErrorCode::SUCCESS, nullptr,
        "CameraManager::CreateCameraInput Failed to create camera input with error code:%{public}d", retCode);

    return cameraInput;
}

void CameraManager::ReportEvent(const string& cameraId)
{
    int pid = IPCSkeleton::GetCallingPid();
    int uid = IPCSkeleton::GetCallingUid();
    auto clientName = "";
    POWERMGR_SYSEVENT_CAMERA_CONNECT(pid, uid, cameraId, clientName);

    stringstream ss;
    const std::string S_CUR_CAMERAID = "curCameraId:";
    const std::string S_CPID = ",cPid:";
    const std::string S_CUID = ",cUid:";
    const std::string S_CBUNDLENAME = ",cBundleName:";
    ss << S_CUR_CAMERAID << cameraId
    << S_CPID << pid
    << S_CUID << uid
    << S_CBUNDLENAME << clientName;

    HiSysEventWrite(
        HiviewDFX::HiSysEvent::Domain::CAMERA,
        "USER_BEHAVIOR",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "MSG", ss.str());
}

int CameraManager::CreateCameraInput(sptr<CameraDevice> &camera, sptr<CameraInput> *pCameraInput)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(camera == nullptr, CameraErrorCode::INVALID_ARGUMENT,
        "CameraManager::CreateCameraInput Camera object is null");
    CHECK_EXECUTE(camera->GetPosition() == CameraPosition::CAMERA_POSITION_FOLD_INNER, ReportEvent(camera->GetID()));

    // Check for API compatibility
    FoldStatus curFoldStatus = GetFoldStatus();
    MEDIA_INFO_LOG("CreateCameraInput curFoldStatus:%{public}d, position:%{public}d", curFoldStatus,
        camera->GetPosition());
    uint32_t apiCompatibleVersion = CameraApiVersion::GetApiVersion();
    bool isFoldV4 = (!foldScreenType_.empty() && foldScreenType_[0] == '4');
    bool isApiCompatRequired = (apiCompatibleVersion < CameraApiVersion::APIVersion::API_FOURTEEN || isFoldV4);
    bool isFoldStatusValid = (curFoldStatus == FoldStatus::EXPAND) || (curFoldStatus == FoldStatus::HALF_FOLD) ||
        (isFoldV4 && curFoldStatus == FoldStatus::UNKNOWN_FOLD);
    bool isFrontCamera = (camera->GetPosition() == CameraPosition::CAMERA_POSITION_FRONT);
    // LCOV_EXCL_START
    if (isApiCompatRequired && isFoldStatusValid && isFrontCamera) {
        std::vector<sptr<CameraDevice>> cameraObjList = GetSupportedCameras();
        sptr<CameraDevice> cameraInfo;
        for (const auto& cameraDevice : cameraObjList) {
            if (cameraDevice != nullptr &&
                cameraDevice->GetPosition() == CameraPosition::CAMERA_POSITION_FOLD_INNER) {
                camera = cameraDevice;
                break;
            }
        }
    }
    // LCOV_EXCL_STOP
    sptr<ICameraDeviceService> deviceObj = nullptr;
    int32_t retCode = CreateCameraDevice(camera->GetID(), &deviceObj);
    CHECK_RETURN_RET_ELOG(retCode != CameraErrorCode::SUCCESS, retCode,
        "CameraManager::CreateCameraInput Returning null in CreateCameraInput");
    sptr<CameraInput> cameraInput = new(std::nothrow) CameraInput(deviceObj, camera);
    CHECK_RETURN_RET_ELOG(cameraInput == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CameraManager::CreateCameraInput failed to new cameraInput!");
    *pCameraInput = cameraInput;
    return CameraErrorCode::SUCCESS;
}

sptr<CameraInput> CameraManager::CreateCameraInput(CameraPosition position, CameraType cameraType)
{
    CAMERA_SYNC_TRACE;
    sptr<CameraInput> cameraInput = nullptr;
    int32_t retCode = CreateCameraInput(position, cameraType, &cameraInput);
    CHECK_RETURN_RET_ELOG(retCode != CameraErrorCode::SUCCESS, nullptr,
        "CameraManager::CreateCameraInput Failed to CreateCameraInput with error code:%{public}d", retCode);
    return cameraInput;
}

int CameraManager::CreateCameraInput(CameraPosition position, CameraType cameraType, sptr<CameraInput> *pCameraInput)
{
    CAMERA_SYNC_TRACE;
    sptr<CameraInput> cameraInput = nullptr;
    std::vector<sptr<CameraDevice>> cameraDeviceList = GetSupportedCameras();
    for (size_t i = 0; i < cameraDeviceList.size(); i++) {
        MEDIA_DEBUG_LOG("CreateCameraInput position:%{public}d, Camera Type:%{public}d",
            cameraDeviceList[i]->GetPosition(), cameraDeviceList[i]->GetCameraType());
        // LCOV_EXCL_START
        if ((cameraDeviceList[i]->GetPosition() == position) && (cameraDeviceList[i]->GetCameraType() == cameraType)) {
            cameraInput = CreateCameraInput(cameraDeviceList[i]);
            break;
        }
        // LCOV_EXCL_STOP
    }
    CHECK_RETURN_RET_ELOG(!cameraInput, CameraErrorCode::SERVICE_FATL_ERROR,
        "No Camera Device for Camera position:%{public}d, Camera Type:%{public}d", position, cameraType);
    // LCOV_EXCL_START
    *pCameraInput = cameraInput;
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

bool g_isCapabilitySupported(std::shared_ptr<OHOS::Camera::CameraMetadata> metadata,
    camera_metadata_item_t &item, uint32_t metadataTag)
{
    CHECK_RETURN_RET(metadata == nullptr, false);
    bool isSupport = true;
    int32_t retCode = Camera::FindCameraMetadataItem(metadata->get(), metadataTag, &item);
    if (retCode != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_DEBUG_LOG("Failed get metadata info tag = %{public}d, retCode = %{public}d, count = %{public}d",
            metadataTag, retCode, item.count);
        isSupport = false;
    }
    return isSupport;
}

void CameraManager::ParseBasicCapability(ProfilesWrapper& profilesWrapper,
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata, const camera_metadata_item_t& item)
{
    CHECK_RETURN(metadata == nullptr);
    uint32_t widthOffset = 1;
    uint32_t heightOffset = 2;
    const uint8_t UNIT_STEP = 3;
    const uint8_t FPS_STEP = 2;

    CameraFormat format = CAMERA_FORMAT_INVALID;
    Size size;
    // LCOV_EXCL_START
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
#ifdef CAMERA_EMULATOR
        if (format != CAMERA_FORMAT_RGBA_8888) {
            continue;
        }
        profilesWrapper.photoProfiles.push_back(profile);
#else
        if (format == CAMERA_FORMAT_JPEG) {
            profilesWrapper.photoProfiles.push_back(profile);
            continue;
        }
#endif
        profilesWrapper.previewProfiles.push_back(profile);
        camera_metadata_item_t fpsItem;
        int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FPS_RANGES, &fpsItem);
        if (ret != CAM_META_SUCCESS) {
            continue;
        }
        for (uint32_t j = 0; j < (fpsItem.count - 1); j += FPS_STEP) {
            std::vector<int32_t> fps = { fpsItem.data.i32[j], fpsItem.data.i32[j + 1] };
            VideoProfile vidProfile = VideoProfile(format, size, fps);
            profilesWrapper.vidProfiles.push_back(vidProfile);
        }
    }
    // LCOV_EXCL_STOP
}

void CameraManager::ParseExtendCapability(ProfilesWrapper& profilesWrapper, const int32_t modeName,
    const camera_metadata_item_t& item) __attribute__((no_sanitize("cfi")))
{
    ExtendInfo extendInfo = {};
    std::shared_ptr<CameraStreamInfoParse> modeStreamParse = std::make_shared<CameraStreamInfoParse>();
    modeStreamParse->getModeInfo(item.data.i32, item.count, extendInfo); // 解析tag中带的数据信息意义
    // LCOV_EXCL_START
    if (modeName == SceneMode::VIDEO) {
        for (uint32_t i = 0; i < extendInfo.modeCount; i++) {
            SceneMode scMode = SceneMode::NORMAL;
            CHECK_PRINT_ELOG(!ConvertMetaToFwkMode(static_cast<OperationMode>(extendInfo.modeInfo[i].modeName),
                scMode), "ParseExtendCapability mode = %{public}d", extendInfo.modeInfo[i].modeName);
            if (SceneMode::HIGH_FRAME_RATE != scMode) {
                continue;
            }
            for (uint32_t j = 0; j < extendInfo.modeInfo[i].streamTypeCount; j++) {
                OutputCapStreamType streamType =
                    static_cast<OutputCapStreamType>(extendInfo.modeInfo[i].streamInfo[j].streamType);
                CreateProfile4StreamType(profilesWrapper, streamType, i, j, extendInfo);
            }
        }
    }
    for (uint32_t i = 0; i < extendInfo.modeCount; i++) {
        SceneMode scMode = SceneMode::NORMAL;
        CHECK_PRINT_ELOG(!ConvertMetaToFwkMode(static_cast<OperationMode>(extendInfo.modeInfo[i].modeName),
            scMode), "ParseExtendCapability mode = %{public}d", extendInfo.modeInfo[i].modeName);
        if (modeName == scMode) {
            for (uint32_t j = 0; j < extendInfo.modeInfo[i].streamTypeCount; j++) {
                OutputCapStreamType streamType =
                    static_cast<OutputCapStreamType>(extendInfo.modeInfo[i].streamInfo[j].streamType);
                CreateProfile4StreamType(profilesWrapper, streamType, i, j, extendInfo);
            }
            break;
        }
    }
    // LCOV_EXCL_STOP
}

void CameraManager::ParseDepthCapability(const int32_t modeName, const camera_metadata_item_t& item)
    __attribute__((no_sanitize("cfi")))
{
    ExtendInfo extendInfo = {};
    std::shared_ptr<CameraDepthInfoParse> depthStreamParse = std::make_shared<CameraDepthInfoParse>();
    depthStreamParse->getModeInfo(item.data.i32, item.count, extendInfo); // 解析tag中带的数据信息意义
    for (uint32_t i = 0; i < extendInfo.modeCount; i++) {
        if (modeName == extendInfo.modeInfo[i].modeName) {
            for (uint32_t j = 0; j < extendInfo.modeInfo[i].streamTypeCount; j++) {
                OutputCapStreamType streamType =
                    static_cast<OutputCapStreamType>(extendInfo.modeInfo[i].streamInfo[j].streamType);
                CreateDepthProfile4StreamType(streamType, i, j, extendInfo);
            }
            break;
        }
    }
}

void CameraManager::CreateDepthProfile4StreamType(OutputCapStreamType streamType, uint32_t modeIndex,
    uint32_t streamIndex, ExtendInfo extendInfo) __attribute__((no_sanitize("cfi")))
{
    // LCOV_EXCL_START
    for (uint32_t k = 0; k < extendInfo.modeInfo[modeIndex].streamInfo[streamIndex].detailInfoCount; k++) {
        const auto& detailInfo = extendInfo.modeInfo[modeIndex].streamInfo[streamIndex].detailInfo[k];
        CameraFormat format = CAMERA_FORMAT_INVALID;
        auto itr = metaToFwCameraFormat_.find(static_cast<camera_format_t>(detailInfo.format));
        if (itr != metaToFwCameraFormat_.end()) {
            format = itr->second;
        } else {
            MEDIA_ERR_LOG("CreateDepthProfile4StreamType failed format = %{public}d",
                extendInfo.modeInfo[modeIndex].streamInfo[streamIndex].detailInfo[k].format);
            format = CAMERA_FORMAT_INVALID;
            continue;
        }
        Size size{static_cast<uint32_t>(detailInfo.width), static_cast<uint32_t>(detailInfo.height)};
        DepthDataAccuracy dataAccuracy = DEPTH_DATA_ACCURACY_INVALID;
        auto it = metaToFwDepthDataAccuracy_.find(static_cast<DepthDataAccuracyType>(detailInfo.dataAccuracy));
        if (it != metaToFwDepthDataAccuracy_.end()) {
            dataAccuracy = it->second;
        } else {
            MEDIA_ERR_LOG("CreateDepthProfile4StreamType failed dataAccuracy = %{public}d",
                extendInfo.modeInfo[modeIndex].streamInfo[streamIndex].detailInfo[k].dataAccuracy);
            dataAccuracy = DEPTH_DATA_ACCURACY_INVALID;
            continue;
        }
        MEDIA_DEBUG_LOG("streamType: %{public}d, OutputCapStreamType::DEPTH: %{public}d", streamType,
            OutputCapStreamType::DEPTH);
        DepthProfile depthProfile = DepthProfile(format, dataAccuracy, size);
        MEDIA_DEBUG_LOG("depthdata format : %{public}d, data accuracy: %{public}d, width: %{public}d,"
            "height: %{public}d", depthProfile.GetCameraFormat(), depthProfile.GetDataAccuracy(),
            depthProfile.GetSize().width, depthProfile.GetSize().height);
        depthProfiles_.push_back(depthProfile);
    }
    // LCOV_EXCL_STOP
}

void CameraManager::ParseProfileLevel(ProfilesWrapper& profilesWrapper, const int32_t modeName,
    const camera_metadata_item_t& item) __attribute__((no_sanitize("cfi")))
{
    std::vector<SpecInfo> specInfos;
    ProfileLevelInfo modeInfo = {};
    if (IsSystemApp() && modeName == SceneMode::VIDEO) {
        // LCOV_EXCL_START
        CameraAbilityParseUtil::GetModeInfo(SceneMode::HIGH_FRAME_RATE, item, modeInfo);
        specInfos.insert(specInfos.end(), modeInfo.specInfos.begin(), modeInfo.specInfos.end());
        // LCOV_EXCL_STOP
    }
    CameraAbilityParseUtil::GetModeInfo(modeName, item, modeInfo);
    specInfos.insert(specInfos.end(), modeInfo.specInfos.begin(), modeInfo.specInfos.end());
    for (SpecInfo& specInfo : specInfos) {
        MEDIA_DEBUG_LOG("modeName: %{public}d specId: %{public}d", modeName, specInfo.specId);
        for (StreamInfo& streamInfo : specInfo.streamInfos) {
            CreateProfileLevel4StreamType(profilesWrapper, specInfo.specId, streamInfo);
        }
    }
}

void CameraManager::CreateProfileLevel4StreamType(
    ProfilesWrapper& profilesWrapper, int32_t specId, StreamInfo& streamInfo) __attribute__((no_sanitize("cfi")))
{
    auto getCameraFormat = [&](camera_format_t format) -> CameraFormat {
        auto itr = metaToFwCameraFormat_.find(format);
        if (itr != metaToFwCameraFormat_.end()) {
            return itr->second;
        } else {
            // LCOV_EXCL_START
            MEDIA_ERR_LOG("CreateProfile4StreamType failed format = %{public}d", format);
            return CAMERA_FORMAT_INVALID;
            // LCOV_EXCL_STOP
        }
    };

    OutputCapStreamType streamType = static_cast<OutputCapStreamType>(streamInfo.streamType);

    for (const auto &detailInfo : streamInfo.detailInfos) {
        CameraFormat format = getCameraFormat(static_cast<camera_format_t>(detailInfo.format));
        if (format == CAMERA_FORMAT_INVALID) {
            continue;
        }
        Size size{detailInfo.width, detailInfo.height};
        Fps fps{detailInfo.fixedFps, detailInfo.minFps, detailInfo.maxFps};
        std::vector<uint32_t> abilityId = detailInfo.abilityIds;
        std::string abilityIds = Container2String(abilityId.begin(), abilityId.end());
        if (streamType == OutputCapStreamType::PREVIEW) {
            Profile previewProfile = Profile(format, size, fps, abilityId, specId);
            profilesWrapper.previewProfiles.push_back(previewProfile);
            previewProfile.DumpProfile("preview");
        } else if (streamType == OutputCapStreamType::STILL_CAPTURE) {
            Profile snapProfile = Profile(format, size, fps, abilityId, specId);
            profilesWrapper.photoProfiles.push_back(snapProfile);
            snapProfile.DumpProfile("photo");
        } else if (streamType == OutputCapStreamType::VIDEO_STREAM) {
            std::vector<int32_t> frameRates = {fps.minFps, fps.maxFps};
            VideoProfile vidProfile = VideoProfile(format, size, frameRates, specId);
            profilesWrapper.vidProfiles.push_back(vidProfile);
            vidProfile.DumpVideoProfile("video");
        }
    }
}

void CameraManager::ParseCapability(ProfilesWrapper& profilesWrapper, sptr<CameraDevice>& camera,
    const int32_t modeName, camera_metadata_item_t& item, std::shared_ptr<OHOS::Camera::CameraMetadata> metadata)
{
    if (g_isCapabilitySupported(metadata, item, OHOS_ABILITY_AVAILABLE_PROFILE_LEVEL)) {
        std::vector<SceneMode> supportedModes = GetSupportedModes(camera);
        int32_t mode = (supportedModes.empty() && isTemplateMode_.count(modeName)) ? SceneMode::NORMAL : modeName;
        MEDIA_DEBUG_LOG("ParseProfileLevel by device = %{public}s, mode = %{public}d", camera->GetID().c_str(), mode);
        ParseProfileLevel(profilesWrapper, mode, item);
    } else if (g_isCapabilitySupported(metadata, item, OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS)) {
        std::vector<SceneMode> supportedModes = GetSupportedModes(camera);
        int32_t mode = (supportedModes.empty() && isTemplateMode_.count(modeName)) ? SceneMode::NORMAL : modeName;
        MEDIA_INFO_LOG("ParseCapability by device = %{public}s, mode = %{public}d", camera->GetID().c_str(), mode);
        ParseExtendCapability(profilesWrapper, mode, item);
    } else if (g_isCapabilitySupported(metadata, item, OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS)) {
        ParseBasicCapability(profilesWrapper, metadata, item);
    } else {
        MEDIA_ERR_LOG("Failed get stream info");
    }
    // 解析深度流信息
    if (g_isCapabilitySupported(metadata, item, OHOS_ABILITY_DEPTH_DATA_PROFILES)) {
        std::vector<SceneMode> supportedModes = GetSupportedModes(camera);
        int32_t mode = (supportedModes.empty() && isTemplateMode_.count(modeName)) ? SceneMode::NORMAL : modeName;
        MEDIA_INFO_LOG("Depth g_isCapabilitySupported by device = %{public}s, mode = %{public}d, tag = %{public}d",
            camera->GetID().c_str(), mode, OHOS_ABILITY_DEPTH_DATA_PROFILES);
        ParseDepthCapability(mode, item);
    }
}

sptr<CameraOutputCapability> CameraManager::GetSupportedOutputCapability(sptr<CameraDevice>& cameraDevice,
    int32_t modeName) __attribute__((no_sanitize("cfi")))
{
    MEDIA_DEBUG_LOG("GetSupportedOutputCapability mode = %{public}d", modeName);
    auto camera = cameraDevice;
    auto innerCamera = GetInnerCamera();
    if (!foldScreenType_.empty() && foldScreenType_[0] == '4' &&
        camera->GetPosition() == CAMERA_POSITION_FRONT && innerCamera && !GetIsInWhiteList() &&
        (GetFoldStatus() == FoldStatus::EXPAND || GetFoldStatus() == FoldStatus::UNKNOWN_FOLD)) {
        MEDIA_DEBUG_LOG("GetSupportedOutputCapability innerCamera Position = %{public}d", innerCamera->GetPosition());
        camera = innerCamera;
    }
    CHECK_RETURN_RET(camera == nullptr, nullptr);
    sptr<CameraOutputCapability> cameraOutputCapability = new (std::nothrow) CameraOutputCapability();
    CHECK_RETURN_RET(cameraOutputCapability == nullptr, nullptr);
    cameraOutputCapability->SetPhotoProfiles(camera->modePhotoProfiles_[modeName]);
    cameraOutputCapability->SetPreviewProfiles(camera->modePreviewProfiles_[modeName]);
    if (!isPhotoMode_.count(modeName)) {
        cameraOutputCapability->SetVideoProfiles(camera->modeVideoProfiles_[modeName]);
    }
    cameraOutputCapability->SetDepthProfiles(camera->modeDepthProfiles_[modeName]);

    std::vector<MetadataObjectType> objectTypes = camera->GetObjectTypes();

    if (!CameraSecurity::CheckSystemApp()) {
        MEDIA_DEBUG_LOG("public calling for GetsupportedOutputCapability");
        if (std::any_of(objectTypes.begin(), objectTypes.end(),
                        [](MetadataObjectType type) { return type == MetadataObjectType::FACE; })) {
            cameraOutputCapability->SetSupportedMetadataObjectType({MetadataObjectType::FACE});
        } else {
            cameraOutputCapability->SetSupportedMetadataObjectType({});
        }
    } else {
        cameraOutputCapability->SetSupportedMetadataObjectType(objectTypes);
    }
    return cameraOutputCapability;
}

sptr<CameraOutputCapability> CameraManager::ParseSupportedOutputCapability(sptr<CameraDevice>& camera, int32_t modeName,
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility)
{
    MEDIA_DEBUG_LOG("GetSupportedOutputCapability mode = %{public}d", modeName);
    CHECK_RETURN_RET(camera == nullptr || cameraAbility == nullptr, nullptr);
    sptr<CameraOutputCapability> cameraOutputCapability = new (std::nothrow) CameraOutputCapability();
    CHECK_RETURN_RET(cameraOutputCapability == nullptr, nullptr);
    camera_metadata_item_t item;
    ProfilesWrapper profilesWrapper = {};
    depthProfiles_.clear();
    photoFormats_.clear();
    photoFormats_ = GetSupportPhotoFormat(modeName, cameraAbility);

    ParseCapability(profilesWrapper, camera, modeName, item, cameraAbility);
    SceneMode profileMode = static_cast<SceneMode>(modeName);
    auto fallbackMode = GetFallbackConfigMode(profileMode, profilesWrapper);
    if (profileMode != fallbackMode) {
        ParseCapability(profilesWrapper, camera, fallbackMode, item, cameraAbility);
    }
    FillSupportPhotoFormats(profilesWrapper.photoProfiles);
    CHECK_EXECUTE(!IsSystemApp() && modeName == static_cast<int32_t>(SceneMode::CAPTURE),
        FillSupportPreviewFormats(profilesWrapper.previewProfiles));
    cameraOutputCapability->SetPhotoProfiles(profilesWrapper.photoProfiles);
    cameraOutputCapability->SetPreviewProfiles(profilesWrapper.previewProfiles);
    if (!isPhotoMode_.count(modeName)) {
        cameraOutputCapability->SetVideoProfiles(profilesWrapper.vidProfiles);
    }
    cameraOutputCapability->SetDepthProfiles(depthProfiles_);
    MEDIA_DEBUG_LOG("SetPhotoProfiles size = %{public}zu,SetPreviewProfiles size = %{public}zu"
        "SetVideoProfiles size = %{public}zu,SetDepthProfiles size = %{public}zu",
        profilesWrapper.photoProfiles.size(), profilesWrapper.previewProfiles.size(),
        profilesWrapper.vidProfiles.size(), depthProfiles_.size());
    return cameraOutputCapability;
}

vector<CameraFormat> CameraManager::GetSupportPhotoFormat(const int32_t modeName,
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata)
{
    // LCOV_EXCL_START
    CHECK_RETURN_RET(metadata == nullptr, {});
    vector<CameraFormat> photoFormats = {};
    camera_metadata_item_t item;
    int32_t metadataTag = OHOS_STREAM_AVAILABLE_FORMATS;
    int32_t retCode = OHOS::Camera::FindCameraMetadataItem(metadata->get(), metadataTag, &item);
    CHECK_RETURN_RET_ELOG(retCode != CAM_META_SUCCESS || item.count == 0, photoFormats,
        "Failed get metadata info tag = %{public}d, retCode = %{public}d, count = %{public}d",
        metadataTag, retCode, item.count);
    vector<int32_t> formats = {};
    std::map<int32_t, vector<int32_t> > modePhotoFormats = {};
    for (uint32_t i = 0; i < item.count; i++) {
        if (item.data.i32[i] != -1) {
            formats.push_back(item.data.i32[i]);
            continue;
        } else {
            modePhotoFormats.insert(std::make_pair(modeName, std::move(formats)));
            formats.clear();
        }
    }
    CHECK_RETURN_RET_ELOG(!modePhotoFormats.count(modeName), photoFormats,
        "GetSupportPhotoFormat not support mode = %{public}d", modeName);
    for (auto &val : modePhotoFormats[modeName]) {
        camera_format_t hdiFomart = static_cast<camera_format_t>(val);
        CHECK_EXECUTE(metaToFwCameraFormat_.count(hdiFomart),
            photoFormats.push_back(metaToFwCameraFormat_.at(hdiFomart)));
    }
    MEDIA_DEBUG_LOG("GetSupportPhotoFormat, mode = %{public}d, formats = %{public}s", modeName,
        Container2String(photoFormats.begin(), photoFormats.end()).c_str());
    return photoFormats;
    // LCOV_EXCL_STOP
}

bool CameraManager::IsSystemApp()
{
    return isSystemApp_;
}

void CameraManager::CreateProfile4StreamType(ProfilesWrapper& profilesWrapper, OutputCapStreamType streamType,
    uint32_t modeIndex, uint32_t streamIndex, ExtendInfo extendInfo) __attribute__((no_sanitize("cfi")))
{
    const int frameRate120 = 120;
    const int frameRate240 = 240;
    for (uint32_t k = 0; k < extendInfo.modeInfo[modeIndex].streamInfo[streamIndex].detailInfoCount; k++) {
        const auto& detailInfo = extendInfo.modeInfo[modeIndex].streamInfo[streamIndex].detailInfo[k];
        // Skip profiles with unsupported frame rates for non-system apps
        if ((detailInfo.minFps == frameRate120 || detailInfo.minFps == frameRate240) &&
            streamType == OutputCapStreamType::VIDEO_STREAM && !IsSystemApp()) {
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
        Size size { static_cast<uint32_t>(detailInfo.width), static_cast<uint32_t>(detailInfo.height) };
        Fps fps { static_cast<uint32_t>(detailInfo.fixedFps), static_cast<uint32_t>(detailInfo.minFps),
            static_cast<uint32_t>(detailInfo.maxFps) };
        std::vector<uint32_t> abilityId = detailInfo.abilityId;
        std::string abilityIds = Container2String(abilityId.begin(), abilityId.end());
        if (streamType == OutputCapStreamType::PREVIEW) {
            Profile previewProfile = Profile(format, size, fps, abilityId);
            profilesWrapper.previewProfiles.push_back(previewProfile);
            previewProfile.DumpProfile("preview");
        } else if (streamType == OutputCapStreamType::STILL_CAPTURE) {
            Profile snapProfile = Profile(format, size, fps, abilityId);
            profilesWrapper.photoProfiles.push_back(snapProfile);
            snapProfile.DumpProfile("photo");
        } else if (streamType == OutputCapStreamType::VIDEO_STREAM) {
            std::vector<int32_t> frameRates = { fps.minFps, fps.maxFps };
            VideoProfile vidProfile = VideoProfile(format, size, frameRates);
            profilesWrapper.vidProfiles.push_back(vidProfile);
            vidProfile.DumpVideoProfile("video");
        }
    }
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

void CameraManagerGetter::SetCameraManager(wptr<CameraManager> cameraManager)
{
    cameraManager_ = cameraManager;
}

sptr<CameraManager> CameraManagerGetter::GetCameraManager()
{
    return cameraManager_.promote();
}

int32_t TorchServiceListenerManager::OnTorchStatusChange(const TorchStatus status)
{
    MEDIA_DEBUG_LOG("TorchStatus is %{public}d", status);
    auto cameraManager = GetCameraManager();
    CHECK_RETURN_RET_ELOG(cameraManager == nullptr, CAMERA_OK, "OnTorchStatusChange CameraManager is nullptr");

    TorchStatusInfo torchStatusInfo;
    if (status == TorchStatus::TORCH_STATUS_UNAVAILABLE) {
        torchStatusInfo.isTorchAvailable = false;
        torchStatusInfo.isTorchActive = false;
        torchStatusInfo.torchLevel = 0;
        cameraManager->UpdateTorchMode(TORCH_MODE_OFF);
    } else if (status == TorchStatus::TORCH_STATUS_ON) {
        // LCOV_EXCL_START
        torchStatusInfo.isTorchAvailable = true;
        torchStatusInfo.isTorchActive = true;
        torchStatusInfo.torchLevel = 1;
        cameraManager->UpdateTorchMode(TORCH_MODE_ON);
        // LCOV_EXCL_STOP
    } else if (status == TorchStatus::TORCH_STATUS_OFF) {
        torchStatusInfo.isTorchAvailable = true;
        torchStatusInfo.isTorchActive = false;
        torchStatusInfo.torchLevel = 0;
        cameraManager->UpdateTorchMode(TORCH_MODE_OFF);
    }
    auto listener = cameraManager->GetTorchServiceListenerManager();
    listener->TriggerListener([&](auto listener) { listener->OnTorchStatusChange(torchStatusInfo); });
    listener->cachedTorchStatus_ = torchStatusInfo;
    return CAMERA_OK;
}

int32_t FoldStatusListenerManager::OnFoldStatusChanged(const FoldStatus status)
{
    // LCOV_EXCL_START
    MEDIA_DEBUG_LOG("FoldStatus is %{public}d", status);
    auto cameraManager = GetCameraManager();
    CHECK_RETURN_RET_ELOG(cameraManager == nullptr, CAMERA_OK, "OnFoldStatusChanged CameraManager is nullptr");

    FoldStatusInfo foldStatusInfo;
    foldStatusInfo.foldStatus = status;
    foldStatusInfo.supportedCameras = cameraManager->GetSupportedCameras();
    auto listenerManager = cameraManager->GetFoldStatusListenerManager();
    MEDIA_DEBUG_LOG("FoldListeners size %{public}zu", listenerManager->GetListenerCount());
    listenerManager->TriggerListener([&](auto listener) { listener->OnFoldStatusChanged(foldStatusInfo); });
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t ControlCenterStatusListenerManager::OnControlCenterStatusChanged(bool status)
{
    // LCOV_EXCL_START
    MEDIA_INFO_LOG("OnControlCenterStatusChanged");
    auto cameraManager = GetCameraManager();
    CHECK_RETURN_RET_ELOG(cameraManager == nullptr, CAMERA_OK, "CameraManager is nullptr.");
    auto listenerManager = cameraManager->GetControlCenterStatusListenerManager();
    MEDIA_INFO_LOG("ControlCenterStatusListener size %{public}zu", listenerManager->GetListenerCount());
    listenerManager->TriggerListener([&](auto listener) { listener->OnControlCenterStatusChanged(status); });
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t CameraManager::SetCameraServiceCallback(sptr<ICameraServiceCallback>& callback)
{
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(
        serviceProxy == nullptr, CAMERA_UNKNOWN_ERROR, "CameraManager::SetCameraServiceCallback serviceProxy is null");
    int32_t retCode = serviceProxy->SetCameraCallback(callback);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, retCode,
        "SetCameraServiceCallback Set service Callback failed, retCode: %{public}d", retCode);
    return CAMERA_OK;
}

int32_t CameraManager::UnSetCameraServiceCallback()
{
    // LCOV_EXCL_START
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, CAMERA_UNKNOWN_ERROR,
        "CameraManager::UnSetCameraServiceCallback serviceProxy is null");
    int32_t retCode = serviceProxy->UnSetCameraCallback();
    CHECK_RETURN_RET_ELOG(
        retCode != CAMERA_OK, retCode, "UnSetCameraServiceCallback failed, retCode: %{public}d", retCode);
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t CameraManager::SetCameraMuteServiceCallback(sptr<ICameraMuteServiceCallback>& callback)
{
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, CAMERA_UNKNOWN_ERROR,
        "CameraManager::SetCameraMuteServiceCallback serviceProxy is null");
    int32_t retCode = serviceProxy->SetMuteCallback(callback);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, retCode,
        "SetCameraMuteServiceCallback Set Mute service Callback failed, retCode: %{public}d", retCode);
    return CAMERA_OK;
}

int32_t CameraManager::UnSetCameraMuteServiceCallback()
{
    // LCOV_EXCL_START
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, CAMERA_UNKNOWN_ERROR,
        "CameraManager::UnSetCameraMuteServiceCallback serviceProxy is null");
    int32_t retCode = serviceProxy->UnSetMuteCallback();
    CHECK_RETURN_RET_ELOG(
        retCode != CAMERA_OK, retCode, "UnSetCameraMuteServiceCallback failed, retCode: %{public}d", retCode);
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t CameraManager::SetTorchServiceCallback(sptr<ITorchServiceCallback>& callback)
{
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(
        serviceProxy == nullptr, CAMERA_UNKNOWN_ERROR, "CameraManager::SetTorchServiceCallback serviceProxy is null");
    int32_t retCode = serviceProxy->SetTorchCallback(callback);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, retCode,
        "SetTorchServiceCallback Set service Callback failed, retCode: %{public}d", retCode);
    return CAMERA_OK;
}

int32_t CameraManager::UnSetTorchServiceCallback()
{
    // LCOV_EXCL_START
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(
        serviceProxy == nullptr, CAMERA_UNKNOWN_ERROR, "CameraManager::UnSetTorchServiceCallback serviceProxy is null");
    int32_t retCode = serviceProxy->UnSetTorchCallback();
    CHECK_RETURN_RET_ELOG(
        retCode != CAMERA_OK, retCode, "UnSetTorchServiceCallback failed, retCode: %{public}d", retCode);
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t CameraManager::SetFoldServiceCallback(sptr<IFoldServiceCallback>& callback)
{
    bool isInnerCallback = false;
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(
        serviceProxy == nullptr, CAMERA_UNKNOWN_ERROR, "CameraManager::SetFoldServiceCallback serviceProxy is null");
    int32_t retCode = serviceProxy->SetFoldStatusCallback(callback, isInnerCallback);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, retCode,
        "SetFoldServiceCallback Set service Callback failed, retCode: %{public}d", retCode);
    return CAMERA_OK;
}

int32_t CameraManager::UnSetFoldServiceCallback()
{
    // LCOV_EXCL_START
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(
        serviceProxy == nullptr, CAMERA_UNKNOWN_ERROR, "CameraManager::UnSetFoldServiceCallback serviceProxy is null");
    int32_t retCode = serviceProxy->UnSetFoldStatusCallback();
    CHECK_RETURN_RET_ELOG(
        retCode != CAMERA_OK, retCode, "UnSetFoldServiceCallback failed, retCode: %{public}d", retCode);
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t CameraManager::SetControlCenterStatusCallback(sptr<IControlCenterStatusCallback>& callback)
{
    // LCOV_EXCL_START
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, CAMERA_UNKNOWN_ERROR,
        "CameraManager::SetControlCenterStatusCallback serviceProxy is null");
    int32_t retCode = serviceProxy->SetControlCenterCallback(callback);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, retCode,
        "SetControlCenterStatusCallback Set Callback failed, retCode: %{public}d", retCode);
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t CameraManager::UnSetControlCenterStatusCallback()
{
    // LCOV_EXCL_START
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(
        serviceProxy == nullptr, CAMERA_UNKNOWN_ERROR,
            "CameraManager::UnSetControlCenterStatusCallback serviceProxy is null");
    int32_t retCode = serviceProxy->UnSetControlCenterStatusCallback();
    CHECK_RETURN_RET_ELOG(
        retCode != CAMERA_OK, retCode, "UnSetControlCenterStatusCallback failed, retCode: %{public}d", retCode);
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

bool CameraManager::IsControlCenterActive()
{
    // LCOV_EXCL_START
    bool status = false;
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, CAMERA_UNKNOWN_ERROR,
        "CameraManager::IsControlCenterActive serviceProxy is null");
    
    int32_t retCode = serviceProxy->GetControlCenterStatus(status);
    CHECK_RETURN_RET_ELOG(retCode!=CAMERA_OK, false, "CameraManager::IsControlCenterActive failed");
    MEDIA_INFO_LOG("CameraManager::IsControlCenterActive status: %{public}d", status);
    return status;
    // LCOV_EXCL_STOP
}
 
int32_t CameraManager::CreateControlCenterSession(sptr<ControlCenterSession>& pControlCenterSession)
{
    // LCOV_EXCL_START
    pControlCenterSession = new (std::nothrow) ControlCenterSession();
    MEDIA_INFO_LOG("CameraManager::CreateControlCenterSession");
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(
        serviceProxy == nullptr, CAMERA_UNKNOWN_ERROR,
        "CameraManager::CreateControlCenterSession serviceProxy is null");
    int32_t retCode = serviceProxy->CheckControlCenterPermission();
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, false, "CameraManager::CreateControlCenterSession failed");
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}
    
void CameraManager::SetControlCenterFrameCondition(bool frameCondition)
{
    MEDIA_INFO_LOG("SetControlCenterFrameCondition: %{public}d", frameCondition);
    controlCenterFrameCondition_ = frameCondition;
    UpdateControlCenterPrecondition();
}
    
void CameraManager::SetControlCenterResolutionCondition(bool resolutionCondition)
{
    MEDIA_INFO_LOG("SetControlCenterResolutionCondition: %{public}d", resolutionCondition);
    controlCenterResolutionCondition_ = resolutionCondition;
    UpdateControlCenterPrecondition();
}
    
void CameraManager::SetControlCenterPositionCondition(bool positionCondition)
{
    MEDIA_INFO_LOG("SetControlCenterPositionCondition: %{public}d", positionCondition);
    controlCenterPositionCondition_ = positionCondition;
    UpdateControlCenterPrecondition();
}

void CameraManager::UpdateControlCenterPrecondition()
{
    MEDIA_INFO_LOG("UpdateControlCenterPrecondition:  %{public}d,%{public}d,%{public}d,%{public}d",
        controlCenterPrecondition_, controlCenterFrameCondition_,
        controlCenterResolutionCondition_, controlCenterPositionCondition_);
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_ELOG(serviceProxy == nullptr, "UpdateControlCenterPrecondition serviceProxy is null");
    if (controlCenterPrecondition_
        && (!controlCenterFrameCondition_ || !controlCenterResolutionCondition_ || !controlCenterPositionCondition_)) {
        controlCenterPrecondition_ = false;
        serviceProxy->SetControlCenterPrecondition(false);
        return;
    }
    // LCOV_EXCL_START
    if (!controlCenterPrecondition_
        && (controlCenterFrameCondition_ && controlCenterResolutionCondition_ && controlCenterPositionCondition_)) {
        controlCenterPrecondition_ = true;
    }
    serviceProxy->SetControlCenterPrecondition(controlCenterPrecondition_);
    // LCOV_EXCL_STOP
    return;
}

bool CameraManager::GetControlCenterPrecondition()
{
    return controlCenterPrecondition_;
}

void CameraManager::SetIsControlCenterSupported(bool isSupported)
{
    // LCOV_EXCL_START
    MEDIA_DEBUG_LOG("CameraManager::SetIsControlCenterSupported, isSupported: %{public}d", isSupported);
    isControlCenterSupported_ = isSupported;

    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_ELOG(serviceProxy == nullptr, "SetIsControlCenterSupported serviceProxy is null");
    int32_t retCode = serviceProxy->SetDeviceControlCenterAbility(isSupported);
    CHECK_RETURN_ELOG(retCode != CAMERA_OK, "IsControlCenterSupported call failed, retCode: %{public}d", retCode);
    // LCOV_EXCL_STOP
}

bool CameraManager::GetIsControlCenterSupported()
{
    return isControlCenterSupported_;
}

int32_t CameraMuteListenerManager::OnCameraMute(bool muteMode)
{
    MEDIA_DEBUG_LOG("muteMode is %{public}d", muteMode);
    auto cameraManager = GetCameraManager();
    CHECK_RETURN_RET_ELOG(cameraManager == nullptr, CAMERA_OK, "OnCameraMute CameraManager is nullptr");
    auto listenerManager = cameraManager->GetCameraMuteListenerManager();
    MEDIA_DEBUG_LOG("CameraMuteListeners size %{public}zu", listenerManager->GetListenerCount());
    listenerManager->TriggerListener([&](auto listener) { listener->OnCameraMute(muteMode); });
    return CAMERA_OK;
}

bool CameraManager::IsCameraMuteSupported()
{
    bool isCameraMuteSupported = false;
    bool cacheResult = GetCameraDeviceAbilitySupportValue(CAMERA_ABILITY_SUPPORT_MUTE, isCameraMuteSupported);
    CHECK_RETURN_RET(cacheResult, isCameraMuteSupported);

    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, false, "IsCameraMuteSupported serviceProxy is null");
    int32_t retCode = serviceProxy->IsCameraMuteSupported(isCameraMuteSupported);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, false, "IsCameraMuteSupported call failed, retCode: %{public}d",
        retCode);
    CacheCameraDeviceAbilitySupportValue(CAMERA_ABILITY_SUPPORT_MUTE, isCameraMuteSupported);
    return isCameraMuteSupported;
}

bool CameraManager::IsCameraMuted()
{
    bool isMuted = false;
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, isMuted, "CameraManager::IsCameraMuted serviceProxy is null");
    int32_t retCode = serviceProxy->IsCameraMuted(isMuted);
    CHECK_PRINT_ELOG(retCode != CAMERA_OK, "IsCameraMuted call failed, retCode: %{public}d", retCode);
    return isMuted;
}

void CameraManager::MuteCamera(bool muteMode)
{
    // LCOV_EXCL_START
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_ELOG(serviceProxy == nullptr, "CameraManager::MuteCamera serviceProxy is null");
    int32_t retCode = serviceProxy->MuteCamera(muteMode);
    CHECK_PRINT_ELOG(retCode != CAMERA_OK, "MuteCamera call failed, retCode: %{public}d", retCode);
    // LCOV_EXCL_STOP
}

int32_t CameraManager::MuteCameraPersist(PolicyType policyType, bool muteMode)
{
    // LCOV_EXCL_START
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, SERVICE_FATL_ERROR,
        "CameraManager::MuteCameraPersist serviceProxy is null");
    int32_t retCode = serviceProxy->MuteCameraPersist(policyType, muteMode);
    CHECK_PRINT_ELOG(retCode != CAMERA_OK, "MuteCameraPersist call failed, retCode: %{public}d", retCode);
    return ServiceToCameraError(retCode);
    // LCOV_EXCL_STOP
}

int32_t CameraManager::PrelaunchCamera(int32_t flag)
{
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, SERVICE_FATL_ERROR, "PrelaunchCamera serviceProxy is null");
    int32_t retCode = serviceProxy->PrelaunchCamera(flag);
    CHECK_PRINT_ELOG(retCode != CAMERA_OK, "PrelaunchCamera call failed, retCode: %{public}d", retCode);
    return ServiceToCameraError(retCode);
}

int32_t CameraManager::ResetRssPriority()
{
    MEDIA_INFO_LOG("CameraManager::ResetRssPriority");
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, SERVICE_FATL_ERROR, "ResetRssPriority serviceProxy is null");
    int32_t retCode = serviceProxy->ResetRssPriority();
    CHECK_PRINT_ELOG(retCode != CAMERA_OK, "ResetRssPriority call failed, retCode: %{public}d", retCode);
    return ServiceToCameraError(retCode);
}

int32_t CameraManager::PreSwitchCamera(const std::string cameraId)
{
    // LCOV_EXCL_START
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, SERVICE_FATL_ERROR, "PreSwitchCamera serviceProxy is null");
    int32_t retCode = serviceProxy->PreSwitchCamera(cameraId);
    CHECK_PRINT_ELOG(retCode != CAMERA_OK, "PreSwitchCamera call failed, retCode: %{public}d", retCode);
    return ServiceToCameraError(retCode);
    // LCOV_EXCL_STOP
}

bool CameraManager::IsPrelaunchSupported(sptr<CameraDevice> camera)
{
    // LCOV_EXCL_START
    CHECK_RETURN_RET(camera == nullptr, false);
    return camera->IsPrelaunch();
    // LCOV_EXCL_STOP
}

bool CameraManager::IsTorchSupported()
{
    bool isCameraTorchSupported = false;
    bool cacheResult = GetCameraDeviceAbilitySupportValue(CAMERA_ABILITY_SUPPORT_TORCH, isCameraTorchSupported);
    CHECK_RETURN_RET(cacheResult, isCameraTorchSupported);

    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, false, "IsTorchSupported serviceProxy is null");
    int32_t retCode = serviceProxy->IsTorchSupported(isCameraTorchSupported);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, false, "IsTorchSupported call failed, retCode: %{public}d",
        retCode);
    CacheCameraDeviceAbilitySupportValue(CAMERA_ABILITY_SUPPORT_TORCH, isCameraTorchSupported);
    return isCameraTorchSupported;
}

bool CameraManager::IsTorchModeSupported(TorchMode mode)
{
    return mode == TorchMode::TORCH_MODE_OFF || mode == TorchMode::TORCH_MODE_ON;
}

TorchMode CameraManager::GetTorchMode()
{
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, torchMode_, "GetTorchMode serviceProxy is null");
    int32_t status = 0;
    int32_t retCode = serviceProxy->GetTorchStatus(status);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, torchMode_, "GetTorchMode call failed, retCode: %{public}d",
        retCode);
    torchMode_ = (status == static_cast<int32_t>(TorchStatus::TORCH_STATUS_ON)) ? TORCH_MODE_ON : TORCH_MODE_OFF;
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
    CHECK_EXECUTE(retCode == CAMERA_OK, UpdateTorchMode(mode));
    return ServiceToCameraError(retCode);
}

void CameraManager::UpdateTorchMode(TorchMode mode)
{
    CHECK_RETURN(torchMode_ == mode);
    torchMode_ = mode;
    MEDIA_INFO_LOG("CameraManager::UpdateTorchMode() mode is %{public}d", mode);
}

int32_t CameraManager::SetTorchLevel(float level)
{
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, SERVICE_FATL_ERROR, "SetTorchLevel serviceProxy is null");
    int32_t retCode = serviceProxy->SetTorchLevel(level);
    CHECK_PRINT_ELOG(retCode != CAMERA_OK, "SetTorchLevel call failed, retCode: %{public}d", retCode);
    return retCode;
}

int32_t CameraManager::SetPrelaunchConfig(
    std::string cameraId, RestoreParamTypeOhos restoreParamType, int activeTime, EffectParam effectParam)
{
    // LCOV_EXCL_START
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, SERVICE_FATL_ERROR, "SetPrelaunchConfig serviceProxy is null");
    int32_t retCode = serviceProxy->SetPrelaunchConfig(
        cameraId, static_cast<RestoreParamTypeOhos>(restoreParamType), activeTime, effectParam);
    CHECK_PRINT_ELOG(retCode != CAMERA_OK, "SetPrelaunchConfig call failed, retCode: %{public}d", retCode);
    return ServiceToCameraError(retCode);
    // LCOV_EXCL_STOP
}

int32_t CameraManager::GetCameraStorageSize(int64_t& size)
{
    // LCOV_EXCL_START
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, SERVICE_FATL_ERROR,
        "GetCameraStorageSize serviceProxy is null");
    int32_t retCode = serviceProxy->GetCameraStorageSize(size);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, ServiceToCameraError(retCode),
        "GetStorageInfo call failed, retCode: %{public}d", retCode);
    return ServiceToCameraError(retCode);
    // LCOV_EXCL_STOP
}

void CameraManager::SetCameraManagerNull()
{
    MEDIA_INFO_LOG("CameraManager::SetCameraManagerNull() called");
    g_cameraManager = nullptr;
}

void CameraManager::FillSupportPreviewFormats(std::vector<Profile>& previewProfiles)
{
    std::vector<Profile> extendProfiles = {};
    for (const auto& profile : previewProfiles) {
        if (profile.format_ == CAMERA_FORMAT_YCBCR_P010 || profile.format_ == CAMERA_FORMAT_YCRCB_P010) {
            continue;
        }
        extendProfiles.push_back(profile);
    }
    previewProfiles = extendProfiles;
}

void CameraManager::FillSupportPhotoFormats(std::vector<Profile>& photoProfiles)
{
    // LCOV_EXCL_START
    CHECK_RETURN(photoFormats_.size() == 0 || photoProfiles.size() == 0);
    std::vector<Profile> extendProfiles = {};
    // if photo stream support jpeg, it must support yuv.
    for (const auto& profile : photoProfiles) {
        if (profile.format_ != CAMERA_FORMAT_JPEG) {
            extendProfiles.push_back(profile);
            continue;
        }
        for (const auto& format : photoFormats_) {
            Profile extendPhotoProfile = profile;
            extendPhotoProfile.format_ = format;
            extendProfiles.push_back(extendPhotoProfile);
        }
    }
    photoProfiles = extendProfiles;
    // LCOV_EXCL_STOP
}

int32_t CameraManager::CreateMetadataOutputInternal(sptr<MetadataOutput>& pMetadataOutput,
    const std::vector<MetadataObjectType>& metadataObjectTypes)
{
    CAMERA_SYNC_TRACE;
    const size_t maxSize4NonSystemApp = 1;
    if (!CameraSecurity::CheckSystemApp()) {
        MEDIA_DEBUG_LOG("public calling for metadataOutput");
        // LCOV_EXCL_START
        if (metadataObjectTypes.size() > maxSize4NonSystemApp ||
            std::any_of(metadataObjectTypes.begin(), metadataObjectTypes.end(),
                [](MetadataObjectType type) { return type != MetadataObjectType::FACE; })) {
            return CameraErrorCode::INVALID_ARGUMENT;
        }
        // LCOV_EXCL_STOP
    }
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr,  CameraErrorCode::SERVICE_FATL_ERROR,
        "CameraManager::CreateMetadataOutput serviceProxy is null");

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    CHECK_RETURN_RET_ELOG(surface == nullptr,  CameraErrorCode::SERVICE_FATL_ERROR,
        "CameraManager::CreateMetadataOutput Failed to create MetadataOutputSurface");
    // only for face recognize
    int32_t format = OHOS_CAMERA_FORMAT_YCRCB_420_SP;
    int32_t width = 1920;
    int32_t height = 1080;
    surface->SetDefaultWidthAndHeight(width, height);
    sptr<IStreamMetadata> streamMetadata = nullptr;
    std::vector<int32_t> result(metadataObjectTypes.size());
    std::transform(metadataObjectTypes.begin(), metadataObjectTypes.end(), result.begin(), [](MetadataObjectType obj) {
        return static_cast<int32_t>(obj);
    });
    int32_t retCode = serviceProxy->CreateMetadataOutput(surface->GetProducer(), format, result, streamMetadata);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, ServiceToCameraError(retCode),
        "CreateMetadataOutput Failed to get stream metadata object from hcamera service! %{public}d", retCode);
    pMetadataOutput = new (std::nothrow) MetadataOutput(surface, streamMetadata);
    CHECK_RETURN_RET_ELOG(pMetadataOutput == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CreateMetadataOutput Failed to new pMetadataOutput!");
    pMetadataOutput->SetStream(streamMetadata);
    sptr<IBufferConsumerListener> bufferConsumerListener = new (std::nothrow) MetadataObjectListener(pMetadataOutput);
    CHECK_RETURN_RET_ELOG(bufferConsumerListener == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CreateMetadataOutput Failed to new bufferConsumerListener!");
    SurfaceError ret = surface->RegisterConsumerListener(bufferConsumerListener);
    CHECK_PRINT_ELOG(ret != SURFACE_ERROR_OK,
        "MetadataOutputSurface consumer listener registration failed:%{public}d", ret);
    return CameraErrorCode::SUCCESS;
}

int32_t CameraManager::RequireMemorySize(int32_t memSize)
{
    // LCOV_EXCL_START
    auto serviceProxy = GetServiceProxy();
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, SERVICE_FATL_ERROR, "RequireMemorySize serviceProxy is null");
    int32_t retCode = serviceProxy->RequireMemorySize(memSize);
    CHECK_PRINT_ELOG(retCode != CAMERA_OK, "RequireMemorySize call failed, retCode: %{public}d", retCode);
    return retCode;
    // LCOV_EXCL_STOP
}

std::vector<sptr<CameraDevice>> CameraManager::GetSupportedCamerasWithFoldStatus()
{
    // LCOV_EXCL_START
    auto cameraDeviceList = GetCameraDeviceList();
    bool isFoldable = GetIsFoldable();
    CHECK_RETURN_RET(!isFoldable, cameraDeviceList);
    auto curFoldStatus = GetFoldStatus();
    MEDIA_INFO_LOG("fold status: %{public}d", curFoldStatus);
    std::vector<sptr<CameraDevice>> supportedCameraDeviceList;
    for (const auto& deviceInfo : cameraDeviceList) {
        auto supportedFoldStatus = deviceInfo->GetSupportedFoldStatus();
        auto it = g_metaToFwCameraFoldStatus_.find(static_cast<CameraFoldStatus>(supportedFoldStatus));
        if (it == g_metaToFwCameraFoldStatus_.end()) {
            MEDIA_INFO_LOG("No supported fold status is found, fold status: %{public}d", curFoldStatus);
            supportedCameraDeviceList.emplace_back(deviceInfo);
            continue;
        }
        if (it->second == curFoldStatus) {
            supportedCameraDeviceList.emplace_back(deviceInfo);
        }
    }
    return supportedCameraDeviceList;
    // LCOV_EXCL_STOP
}

void CameraManager::SaveOldCameraId(std::string realCameraId, std::string oldCameraId)
{
    realtoVirtual_[realCameraId] = oldCameraId;
}

std::string CameraManager::GetOldCameraIdfromReal(std::string realCameraId)
{
    string resultstr = "";
    auto itr = realtoVirtual_.find(realCameraId);
    if (itr != realtoVirtual_.end()) {
        resultstr = itr->second;
    } else {
        MEDIA_ERR_LOG("Can not GetOldCameraIdfromReal");
    }
    return resultstr;
}

void CameraManager::SaveOldMeta(std::string cameraId, std::shared_ptr<OHOS::Camera::CameraMetadata> metadata)
{
    cameraOldCamera_[cameraId] = metadata;
}

std::shared_ptr<OHOS::Camera::CameraMetadata> CameraManager::GetOldMeta(std::string cameraId)
{
    // LCOV_EXCL_START
    std::shared_ptr<OHOS::Camera::CameraMetadata> result_meta = nullptr;
    auto itr = cameraOldCamera_.find(cameraId);
    if (itr != cameraOldCamera_.end()) {
        result_meta = itr->second;
    } else {
        MEDIA_ERR_LOG("Can not GetOldMeta");
    }
    return result_meta;
    // LCOV_EXCL_STOP
}

void CameraManager::SetOldMetatoInput(sptr<CameraDevice>& cameraObj,
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata)
{
    SetProfile(cameraObj, metadata);
}
} // namespace CameraStandard
} // namespace OHOS
