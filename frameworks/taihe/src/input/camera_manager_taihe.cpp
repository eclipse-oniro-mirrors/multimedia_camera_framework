/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include <unordered_map>
#include "camera_manager_taihe.h"
#include "camera_utils_taihe.h"
#include "camera_log.h"
#include "camera_security_utils_taihe.h"
#include "camera_const_ability_taihe.h"
#include "aperture_video_session_taihe.h"
#include "fluorescence_photo_session_taihe.h"
#include "high_resolution_photo_session_taihe.h"
#include "light_painting_photo_session_taihe.h"
#include "macro_photo_session_taihe.h"
#include "macro_video_session_taihe.h"
#include "metadata_output_taihe.h"
#include "night_photo_session_taihe.h"
#include "panorama_photo_session_taihe.h"
#include "photo_session_taihe.h"
#include "photo_session_for_sys_taihe.h"
#include "portrait_photo_session_taihe.h"
#include "professional_photo_session_taihe.h"
#include "professional_video_session_taihe.h"
#include "quick_shot_photo_session_taihe.h"
#include "secure_session_taihe.h"
#include "slow_motion_video_session_taihe.h"
#include "time_lapse_photo_session_taihe.h"
#include "video_session_taihe.h"
#include "video_session_for_sys_taihe.h"
#include "depth_data_output_taihe.h"
#include "preview_output_taihe.h"
#include "photo_output_taihe.h"
#include "video_output_taihe.h"
#include "camera_input_taihe.h"
#include "camera_manager.h"
#include "camera_device.h"
#include "camera_error_code.h"
#include "camera_template_utils_taihe.h"
#include "input/prelaunch_config.h"
#include "image_receiver.h"
#include "surface_utils.h"
#include "event_handler.h"

using namespace OHOS;
namespace Ani {
namespace Camera {
thread_local std::unordered_map<std::string, sptr<OHOS::CameraStandard::CameraOutputCapability>> g_aniValueCacheMap {};

CameraMuteListenerAni::CameraMuteListenerAni(ani_env* env): ListenerBase(env)
{
    MEDIA_DEBUG_LOG("CameraMuteListenerAni is called.");
}

CameraMuteListenerAni::~CameraMuteListenerAni()
{
    MEDIA_DEBUG_LOG("~CameraMuteListenerAni is called.");
}

void CameraMuteListenerAni::OnCameraMuteCallback(bool muteMode) const
{
    auto sharePtr = shared_from_this();
    auto task = [muteMode, sharePtr]() {
        CHECK_EXECUTE(sharePtr != nullptr, sharePtr->ExecuteAsyncCallback("cameraMute", 0, "Callback is OK", muteMode));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnCameraMute", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
    MEDIA_DEBUG_LOG("OnCameraMuteCallback is called, muteMode: %{public}d", muteMode);
}

void CameraMuteListenerAni::OnCameraMute(bool muteMode) const
{
    MEDIA_DEBUG_LOG("OnCameraMute is called, muteMode: %{public}d", muteMode);
    OnCameraMuteCallback(muteMode);
}

CameraManagerCallbackAni::CameraManagerCallbackAni(ani_env* env): ListenerBase(env) {}

CameraManagerCallbackAni::~CameraManagerCallbackAni()
{
}

void CameraManagerCallbackAni::OnCameraStatusCallback(
    const OHOS::CameraStandard::CameraStatusInfo& cameraStatusInfo) const
{
    OHOS::sptr<OHOS::CameraStandard::CameraDevice> cameraDeviceSptr(cameraStatusInfo.cameraDevice);
    CameraStatusInfo statusInfo {
        .camera = CameraUtilsTaihe::ToTaiheCameraDevice(cameraDeviceSptr),
        .status = static_cast<CameraStatus::key_t>(cameraStatusInfo.cameraStatus),
    };
    auto sharePtr = shared_from_this();
    auto task = [statusInfo, sharePtr]() {
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback<CameraStatusInfo const&>("cameraStatus", 0, "Callback is OK", statusInfo));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnCameraStatus", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void CameraManagerCallbackAni::OnCameraStatusChanged(
    const OHOS::CameraStandard::CameraStatusInfo &cameraStatusInfo) const
{
    MEDIA_DEBUG_LOG("OnCameraStatusChanged is called, CameraStatus: %{public}d", cameraStatusInfo.cameraStatus);
    OnCameraStatusCallback(cameraStatusInfo);
}

void CameraManagerCallbackAni::OnFlashlightStatusChanged(const std::string &cameraID,
    const OHOS::CameraStandard::FlashStatus flashStatus) const
{
    (void)cameraID;
    (void)flashStatus;
}

TorchListenerAni::TorchListenerAni(ani_env* env): ListenerBase(env)
{
    MEDIA_INFO_LOG("TorchListenerNapi is called.");
}

TorchListenerAni::~TorchListenerAni()
{
    MEDIA_DEBUG_LOG("~TorchListenerNapi is called.");
}

void TorchListenerAni::OnTorchStatusChangeCallback(const OHOS::CameraStandard::TorchStatusInfo& torchStatusInfo) const
{
    TorchStatusInfo statusInfo = {
        .isTorchAvailable = torchStatusInfo.isTorchAvailable,
        .isTorchActive= torchStatusInfo.isTorchActive,
        .torchLevel = static_cast<double>(torchStatusInfo.torchLevel),
    };

    auto sharePtr = shared_from_this();
    auto task = [statusInfo, sharePtr]() {
        CHECK_EXECUTE(sharePtr != nullptr, sharePtr->ExecuteAsyncCallback<TorchStatusInfo const&>(
            "torchStatusChange", 0, "Callback is OK", statusInfo));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnTorchStatusChange", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void TorchListenerAni::OnTorchStatusChange(const OHOS::CameraStandard::TorchStatusInfo &torchStatusInfo) const
{
    MEDIA_DEBUG_LOG("OnTorchStatusChange is called");
    OnTorchStatusChangeCallback(torchStatusInfo);
}


FoldListenerAni::FoldListenerAni(ani_env* env): ListenerBase(env)
{
    MEDIA_DEBUG_LOG("FoldListenerAni is called.");
}

FoldListenerAni::~FoldListenerAni()
{
    MEDIA_DEBUG_LOG("~FoldListenerAni is called.");
}

void FoldListenerAni::OnFoldStatusChangedCallback(const OHOS::CameraStandard::FoldStatusInfo& foldStatusInfo) const
{
    FoldStatusInfo statusInfo = {
        .foldStatus = static_cast<FoldStatus::key_t>(foldStatusInfo.foldStatus),
        .supportedCameras = CameraUtilsTaihe::ToTaiheArrayCameraDevice(foldStatusInfo.supportedCameras),
    };

    auto sharePtr = shared_from_this();
    auto task = [statusInfo, sharePtr]() {
        CHECK_EXECUTE(sharePtr != nullptr, sharePtr->ExecuteAsyncCallback<FoldStatusInfo const&>(
            "foldStatusChange", 0, "Callback is OK", statusInfo));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnFoldStatusChange", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void FoldListenerAni::OnFoldStatusChanged(const OHOS::CameraStandard::FoldStatusInfo &foldStatusInfo) const
{
    MEDIA_DEBUG_LOG("OnFoldStatusChanged is called");
    OnFoldStatusChangedCallback(foldStatusInfo);
}

CameraManagerImpl::CameraManagerImpl()
{
    cameraManager_ = OHOS::CameraStandard::CameraManager::GetInstance();
}

array<CameraDevice> CameraManagerImpl::GetSupportedCameras()
{
    CHECK_ERROR_RETURN_RET_LOG(cameraManager_ == nullptr, array<CameraDevice>(nullptr, 0),
        "failed to getSupportedCameras, cameraManager is nullprt");
    std::vector<sptr<OHOS::CameraStandard::CameraDevice>> cameraObjList = cameraManager_->GetSupportedCameras();
    return CameraUtilsTaihe::ToTaiheArrayCameraDevice(cameraObjList);
}

array<SceneMode> CameraManagerImpl::GetSupportedSceneModes(CameraDevice const& camera)
{
    CHECK_ERROR_RETURN_RET_LOG(cameraManager_ == nullptr, array<SceneMode>(nullptr, 0),
        "failed to getSupportedSceneModes, cameraManager is nullprt");

    sptr<OHOS::CameraStandard::CameraDevice> cameraDevice =
        cameraManager_->GetCameraDeviceFromId(std::string(camera.cameraId));
    if (cameraDevice == nullptr) {
        MEDIA_ERR_LOG("CameraManagerImpl::GetSupportedModes get camera info fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "Get camera info fail");
        return array<SceneMode>(nullptr, 0);
    }
    std::vector<OHOS::CameraStandard::SceneMode> modeObjList = cameraManager_->GetSupportedModes(cameraDevice);
    for (auto it = modeObjList.begin(); it != modeObjList.end(); it++) {
        if (*it == OHOS::CameraStandard::SCAN) {
            modeObjList.erase(it);
            break;
        }
    }
    if (modeObjList.empty()) {
        modeObjList.emplace_back(OHOS::CameraStandard::CAPTURE);
        modeObjList.emplace_back(OHOS::CameraStandard::VIDEO);
    }
    MEDIA_DEBUG_LOG("CameraManagerNapi::GetSupportedModes size=[%{public}zu]", modeObjList.size());
    return CameraUtilsTaihe::ToTaiheArraySceneMode(modeObjList);
}

CameraOutputCapability GetCacheAniValue(const std::string& key, bool &isFound)
{
    CameraOutputCapability cacheImpl {
        .previewProfiles = array<Profile>(nullptr, 0),
        .photoProfiles = array<Profile>(nullptr, 0),
        .videoProfiles = array<VideoProfile>(nullptr, 0),
    };
    isFound = false;
    auto it = g_aniValueCacheMap.find(key);
    if (it != g_aniValueCacheMap.end()) {
        isFound = true;
        cacheImpl =  CameraUtilsTaihe::ToTaiheCameraOutputCapability(it->second);
    }
    return cacheImpl;
}

CameraOutputCapability GetCachedSupportedOutputCapability(const std::string& cameraId, int32_t mode, bool &isFound)
{
    std::string key = "OutputCapability:" + cameraId + ":\t" + std::to_string(mode);
    CameraOutputCapability result = GetCacheAniValue(key, isFound);
    return result;
}

void CameraManagerImpl::GetSupportedOutputCapabilityAdaptNormalMode(OHOS::CameraStandard::SceneMode fwkMode,
    sptr<OHOS::CameraStandard::CameraDevice>& cameraInfo,
    sptr<OHOS::CameraStandard::CameraOutputCapability>& outputCapability)
{
    if (fwkMode == OHOS::CameraStandard::SceneMode::NORMAL &&
        cameraInfo->GetPosition() == OHOS::CameraStandard::CAMERA_POSITION_FRONT) {
        auto defaultVideoProfiles = cameraInfo->modeVideoProfiles_[OHOS::CameraStandard::SceneMode::NORMAL];
        if (!defaultVideoProfiles.empty()) {
            MEDIA_INFO_LOG("return align videoProfile size = %{public}zu", defaultVideoProfiles.size());
            outputCapability->SetVideoProfiles(defaultVideoProfiles);
        }
    }
}

void CacheAniValue(const std::string& key, sptr<OHOS::CameraStandard::CameraOutputCapability> &value)
{
    g_aniValueCacheMap[key] = value;
    MEDIA_DEBUG_LOG("CacheNapiValue cache->%{public}s", key.c_str());
}

void CacheSupportedOutputCapability(const std::string& cameraId, int32_t mode,
    sptr<OHOS::CameraStandard::CameraOutputCapability> &value)
{
    std::string key = "OutputCapability:" + cameraId + ":\t" + std::to_string(mode);
    CacheAniValue(key, value);
    MEDIA_DEBUG_LOG("CacheSupportedOutputCapability cache->%{public}s:%{public}d", key.c_str(), mode);
}

CameraOutputCapability CameraManagerImpl::GetSupportedOutputCapability(CameraDevice const& camera, SceneMode mode)
{
    CameraOutputCapability nullImpl {
        .previewProfiles = array<Profile>(nullptr, 0),
        .photoProfiles = array<Profile>(nullptr, 0),
        .videoProfiles = array<VideoProfile>(nullptr, 0),
    };
    CHECK_ERROR_RETURN_RET_LOG(cameraManager_ == nullptr, nullImpl,
        "failed to GetSupportedOutputCapability, cameraManager is nullprt");
    std::string cameraId = std::string(camera.cameraId);

    sptr<OHOS::CameraStandard::CameraDevice> cameraInfo = cameraManager_->GetCameraDeviceFromId(cameraId);
    OHOS::CameraStandard::SceneMode sceneMode = OHOS::CameraStandard::NORMAL;
    std::unordered_map<int32_t, OHOS::CameraStandard::SceneMode> aniToNativeMap = g_aniToNativeSupportedMode;
    if (OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(false)) {
        aniToNativeMap = g_aniToNativeSupportedModeSys;
    }
    int32_t modeValue = mode.get_value();
    MEDIA_INFO_LOG("GetSupportedOutputCapability SceneMode mode = %{public}d ", modeValue);
    auto itr = aniToNativeMap.find(modeValue);
    if (itr != aniToNativeMap.end()) {
        sceneMode = itr->second;
    } else {
        MEDIA_ERR_LOG("CreateCameraSessionInstance mode = %{public}d not supported", sceneMode);
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "Not support the input mode");
        return nullImpl;
    }
    MEDIA_INFO_LOG("GetSupportedOutputCapability SceneMode sceneMode = %{public}d ", sceneMode);

    if (cameraInfo == nullptr) {
        MEDIA_ERR_LOG("CameraManagerImpl::GetSupportedOutputCapability get camera info fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "Get camera info fail");
        return nullImpl;
    }
    bool isFound = false;
    CameraOutputCapability cachedResult = GetCachedSupportedOutputCapability(cameraId, sceneMode, isFound);
    CHECK_ERROR_RETURN_RET(isFound, cachedResult);

    auto outputCapability = cameraManager_->GetSupportedOutputCapability(cameraInfo, sceneMode);
    CHECK_ERROR_RETURN_RET_LOG(outputCapability == nullptr, nullImpl,
        "failed to create CreateCameraOutputCapability");
    outputCapability->RemoveDuplicatesProfiles();
    GetSupportedOutputCapabilityAdaptNormalMode(sceneMode, cameraInfo, outputCapability);

    CacheSupportedOutputCapability(cameraId, sceneMode, outputCapability);
    CameraOutputCapability result = CameraUtilsTaihe::ToTaiheCameraOutputCapability(outputCapability);
    return result;
}

void CameraManagerImpl::Prelaunch()
{
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi PrelaunchCamera is called!");
    CHECK_ERROR_RETURN_LOG(cameraManager_ == nullptr, "failed to Prelaunch, cameraManager is nullprt");
    int32_t retCode = cameraManager_->PrelaunchCamera();
    CHECK_ERROR_RETURN(!CameraUtilsTaihe::CheckError(retCode));
}

void CameraManagerImpl::PreSwitchCamera(string_view cameraId)
{
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi PreSwitchCamera is called!");
    CHECK_ERROR_RETURN_LOG(cameraManager_ == nullptr, "failed to PreSwitchCamera, cameraManager is nullprt");
    int32_t retCode = cameraManager_->PreSwitchCamera(std::string(cameraId));
    CHECK_ERROR_RETURN(!CameraUtilsTaihe::CheckError(retCode));
}

bool CameraManagerImpl::IsTorchSupported()
{
    CHECK_ERROR_RETURN_RET_LOG(cameraManager_ == nullptr, false,
        "failed to IsTorchSupported, cameraManager is nullprt");
    return cameraManager_->IsTorchSupported();
}

bool CameraManagerImpl::IsCameraMuted()
{
    CHECK_ERROR_RETURN_RET_LOG(cameraManager_ == nullptr, false,
        "failed to IsCameraMuted, cameraManager is nullprt");
    return cameraManager_->IsCameraMuted();
}

bool CameraManagerImpl::IsCameraMuteSupported()
{
    CHECK_ERROR_RETURN_RET_LOG(cameraManager_ == nullptr, false,
        "failed to IsCameraMuteSupported, cameraManager is nullprt");
    return cameraManager_->IsCameraMuteSupported();
}

bool CameraManagerImpl::IsPrelaunchSupported(CameraDevice const& camera)
{
    CHECK_ERROR_RETURN_RET_LOG(cameraManager_ == nullptr, false,
        "failed to IsPrelaunchSupported, cameraManager is nullprt");
    std::string nativeStr(camera.cameraId);
    sptr<OHOS::CameraStandard::CameraDevice> cameraInfo = cameraManager_->GetCameraDeviceFromId(nativeStr);
    if (cameraInfo != nullptr) {
        bool isPrelaunchSupported = cameraManager_->IsPrelaunchSupported(cameraInfo);
        return isPrelaunchSupported;
    }
    MEDIA_ERR_LOG("CameraManagerImpl::IsPrelaunchSupported cameraInfo is null!");
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "cameraInfo is null.");
    return false;
}

TorchMode CameraManagerImpl::GetTorchMode()
{
    CHECK_ERROR_RETURN_RET_LOG(cameraManager_ == nullptr, TorchMode(static_cast<TorchMode::key_t>(-1)),
        "failed to GetTorchMode, cameraManager is nullprt");
    return TorchMode(static_cast<TorchMode::key_t>(cameraManager_->GetTorchMode()));
}

void CameraManagerImpl::SetTorchMode(TorchMode mode)
{
    CHECK_ERROR_RETURN_LOG(cameraManager_ == nullptr, "failed to SetTorchMode, cameraManager is nullptr");
    int32_t retCode = cameraManager_->SetTorchMode(static_cast<OHOS::CameraStandard::TorchMode>(mode.get_value()));
    CHECK_ERROR_RETURN(!CameraUtilsTaihe::CheckError(retCode));
}

void CameraManagerImpl::OnCameraMute(callback_view<void(uintptr_t, bool)> callback)
{
    ListenerTemplate<CameraManagerImpl>::On(this, callback, "cameraMute");
}

void CameraManagerImpl::OffCameraMute(optional_view<callback<void(uintptr_t, bool)>> callback)
{
    ListenerTemplate<CameraManagerImpl>::Off(this, callback, "cameraMute");
}

void CameraManagerImpl::OnCameraStatus(callback_view<void(uintptr_t, CameraStatusInfo const&)> callback)
{
    ListenerTemplate<CameraManagerImpl>::On(this, callback, "cameraStatus");
}

void CameraManagerImpl::OffCameraStatus(optional_view<callback<void(uintptr_t, CameraStatusInfo const&)>> callback)
{
    ListenerTemplate<CameraManagerImpl>::Off(this, callback, "cameraStatus");
}

void CameraManagerImpl::OnFoldStatusChange(callback_view<void(uintptr_t, FoldStatusInfo const&)> callback)
{
    ListenerTemplate<CameraManagerImpl>::On(this, callback, "foldStatusChange");
}

void CameraManagerImpl::OffFoldStatusChange(optional_view<callback<void(uintptr_t, FoldStatusInfo const&)>> callback)
{
    ListenerTemplate<CameraManagerImpl>::Off(this, callback, "foldStatusChange");
}

void CameraManagerImpl::OnTorchStatusChange(callback_view<void(uintptr_t, TorchStatusInfo const&)> callback)
{
    ListenerTemplate<CameraManagerImpl>::On(this, callback, "torchStatusChange");
}

void CameraManagerImpl::OffTorchStatusChange(optional_view<callback<void(uintptr_t, TorchStatusInfo const&)>> callback)
{
    ListenerTemplate<CameraManagerImpl>::Off(this, callback, "torchStatusChange");
}

void CameraManagerImpl::RegisterCameraMuteCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(cameraManager_ == nullptr,
        "failed to RegisterCameraMuteCallbackListener, cameraManager is nullptr");
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi On cameraMute is called!");
    ani_env *env = get_env();
    auto listener = CameraAniEventListener<CameraMuteListenerAni>::RegisterCallbackListener(
        eventName, env, callback, isOnce);
    CHECK_ERROR_RETURN_LOG(
        listener == nullptr, "CameraManagerImpl::RegisterCameraMuteCallbackListener listener is null");
    cameraManager_->RegisterCameraMuteListener(listener);
}

void CameraManagerImpl::UnregisterCameraMuteCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi On cameraMute is called!");
    ani_env *env = get_env();
    auto listener =
        CameraAniEventListener<CameraMuteListenerAni>::UnregisterCallbackListener(eventName, env, callback);
    CHECK_ERROR_RETURN(listener == nullptr);
    if (listener->IsEmpty(eventName)) {
        cameraManager_->UnregisterCameraMuteListener(listener);
    }
}

void CameraManagerImpl::RegisterCameraStatusCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(cameraManager_ == nullptr,
        "failed to RegisterCameraStatusCallbackListener, cameraManager is nullptr");
    ani_env *env = get_env();
    auto listener = CameraAniEventListener<CameraManagerCallbackAni>::RegisterCallbackListener(
        eventName, env, callback, isOnce);
    CHECK_ERROR_RETURN_LOG(
        listener == nullptr, "CameraManagerImpl::RegisterCameraStatusCallbackListener listener is null");
    cameraManager_->RegisterCameraStatusCallback(listener);
}

void CameraManagerImpl::UnregisterCameraStatusCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    ani_env *env = get_env();
    auto listener =
        CameraAniEventListener<CameraManagerCallbackAni>::UnregisterCallbackListener(eventName, env, callback);
    CHECK_ERROR_RETURN(listener == nullptr);
    if (listener->IsEmpty(eventName)) {
        cameraManager_->UnregisterCameraStatusCallback(listener);
    }
}

void CameraManagerImpl::RegisterTorchStatusCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    ani_env *env = get_env();
    auto listener =
        CameraAniEventListener<TorchListenerAni>::RegisterCallbackListener(eventName, env, callback, isOnce);
    CHECK_ERROR_RETURN_LOG(
        listener == nullptr, "CameraManagerImpl::RegisterTorchStatusCallbackListener listener is null");
    cameraManager_->RegisterTorchListener(listener);
}

void CameraManagerImpl::UnregisterTorchStatusCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    ani_env *env = get_env();
    auto listener =
        CameraAniEventListener<TorchListenerAni>::UnregisterCallbackListener(eventName, env, callback);
    CHECK_ERROR_RETURN(listener == nullptr);
    if (listener->IsEmpty(eventName)) {
        cameraManager_->UnregisterTorchListener(listener);
    }
}

void CameraManagerImpl::RegisterFoldStatusCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    ani_env *env = get_env();
    auto listener =
        CameraAniEventListener<FoldListenerAni>::RegisterCallbackListener(eventName, env, callback, isOnce);
    CHECK_ERROR_RETURN_LOG(
        listener == nullptr, "CameraManagerImpl::RegisterTorchStatusCallbackListener listener is null");
    cameraManager_->RegisterFoldListener(listener);
}

void CameraManagerImpl::UnregisterFoldStatusCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    ani_env *env = get_env();
    auto listener =
        CameraAniEventListener<FoldListenerAni>::UnregisterCallbackListener(eventName, env, callback);
    CHECK_ERROR_RETURN(listener == nullptr);
    if (listener->IsEmpty(eventName)) {
        cameraManager_->UnregisterFoldListener(listener);
    }
}

const CameraManagerImpl::EmitterFunctions& CameraManagerImpl::GetEmitterFunctions()
{
    static const EmitterFunctions funMap = {
        { "cameraStatus", {
            &CameraManagerImpl::RegisterCameraStatusCallbackListener,
            &CameraManagerImpl::UnregisterCameraStatusCallbackListener } },
        { "cameraMute", {
            &CameraManagerImpl::RegisterCameraMuteCallbackListener,
            &CameraManagerImpl::UnregisterCameraMuteCallbackListener } },
        { "torchStatusChange", {
            &CameraManagerImpl::RegisterTorchStatusCallbackListener,
            &CameraManagerImpl::UnregisterTorchStatusCallbackListener } },
        { "foldStatusChange", {
            &CameraManagerImpl::RegisterFoldStatusCallbackListener,
            &CameraManagerImpl::UnregisterFoldStatusCallbackListener } }
        };
    return funMap;
}

SessionUnion CreateVideoSession(sptr<OHOS::CameraStandard::CaptureSession> &session)
{
    if (OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(false)) {
        return SessionUnion::make_videoSessionForSys(
            make_holder<Ani::Camera::VideoSessionForSysImpl, VideoSessionForSys>(session));
    } else {
        return SessionUnion::make_videoSession(make_holder<Ani::Camera::VideoSessionImpl,
            VideoSession>(session));
    }
}

SessionUnion CreatePhotoSession(sptr<OHOS::CameraStandard::CaptureSession> &session)
{
    if (OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(false)) {
        return SessionUnion::make_photoSessionForSys(
            make_holder<Ani::Camera::PhotoSessionForSysImpl, PhotoSessionForSys>(session));
    } else {
        return SessionUnion::make_photoSession(make_holder<Ani::Camera::PhotoSessionImpl,
            PhotoSession>(session));
    }
}

SessionUnion CameraManagerImpl::CreateSessionWithMode(OHOS::CameraStandard::SceneMode sceneModeInner)
{
    sptr<OHOS::CameraStandard::CaptureSession> session = cameraManager_->CreateCaptureSession(sceneModeInner);
    switch (sceneModeInner) {
        case OHOS::CameraStandard::SceneMode::CAPTURE:
            return CreatePhotoSession(session);
        case OHOS::CameraStandard::SceneMode::VIDEO:
            return CreateVideoSession(session);
        case OHOS::CameraStandard::SceneMode::PORTRAIT:
            return SessionUnion::make_portraitPhotoSession(make_holder<Ani::Camera::PortraitPhotoSessionImpl,
                PortraitPhotoSession>(session));
        case OHOS::CameraStandard::SceneMode::NIGHT:
            return SessionUnion::make_nightPhotoSession(make_holder<Ani::Camera::NightPhotoSessionImpl,
                NightPhotoSession>(session));
        case OHOS::CameraStandard::SceneMode::PROFESSIONAL_PHOTO:
            return SessionUnion::make_professionalPhotoSession(make_holder<Ani::Camera::ProfessionalPhotoSessionImpl,
                ProfessionalPhotoSession>(session));
        case OHOS::CameraStandard::SceneMode::PROFESSIONAL_VIDEO:
            return SessionUnion::make_professionalVideoSession(make_holder<Ani::Camera::ProfessionalVideoSessionImpl,
                ProfessionalVideoSession>(session));
        case OHOS::CameraStandard::SceneMode::SLOW_MOTION:
            return SessionUnion::make_slowMotionVideoSession(make_holder<Ani::Camera::SlowMotionVideoSessionImpl,
                SlowMotionVideoSession>(session));
        case OHOS::CameraStandard::SceneMode::CAPTURE_MACRO:
            return SessionUnion::make_macroPhotoSession(make_holder<Ani::Camera::MacroPhotoSessionImpl,
                MacroPhotoSession>(session));
        case OHOS::CameraStandard::SceneMode::VIDEO_MACRO:
            return SessionUnion::make_macroVideoSession(make_holder<Ani::Camera::MacroVideoSessionImpl,
                MacroVideoSession>(session));
        case OHOS::CameraStandard::SceneMode::LIGHT_PAINTING:
            return SessionUnion::make_lightPaintingPhotoSession(make_holder<Ani::Camera::LightPaintingPhotoSessionImpl,
                LightPaintingPhotoSession>(session));
        case OHOS::CameraStandard::SceneMode::HIGH_RES_PHOTO:
            return SessionUnion::make_highResolutionPhotoSession(
                make_holder<Ani::Camera::HighResolutionPhotoSessionImpl, HighResolutionPhotoSession>(session));
        case OHOS::CameraStandard::SceneMode::SECURE:
            return SessionUnion::make_secureSession(make_holder<Ani::Camera::SecureSessionImpl,
                SecureSession>(session));
        case OHOS::CameraStandard::SceneMode::QUICK_SHOT_PHOTO:
            return SessionUnion::make_quickShotPhotoSession(make_holder<Ani::Camera::QuickShotPhotoSessionImpl,
                QuickShotPhotoSession>(session));
        case OHOS::CameraStandard::SceneMode::APERTURE_VIDEO:
            return SessionUnion::make_apertureVideoSession(make_holder<Ani::Camera::ApertureVideoSessionImpl,
                ApertureVideoSession>(session));
        case OHOS::CameraStandard::SceneMode::PANORAMA_PHOTO:
            return SessionUnion::make_panoramaPhotoSession(make_holder<Ani::Camera::PanoramaPhotoSessionImpl,
                PanoramaPhotoSession>(session));
        case OHOS::CameraStandard::SceneMode::TIMELAPSE_PHOTO:
            return SessionUnion::make_timeLapsePhotoSession(make_holder<Ani::Camera::TimeLapsePhotoSessionImpl,
                TimeLapsePhotoSession>(session));
        case OHOS::CameraStandard::SceneMode::FLUORESCENCE_PHOTO:
            return SessionUnion::make_fluorescencePhotoSession(make_holder<Ani::Camera::FluorescencePhotoSessionImpl,
                FluorescencePhotoSession>(session));
        default:
            CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::PARAMETER_ERROR, "Invalid scene mode");
            return SessionUnion::make_session(make_holder<Ani::Camera::SessionImpl, Session>(session));
    }
}

void CameraManagerImpl::MuteCameraPersistent(bool mute, PolicyType type)
{
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi On cameraMute is called!");
    CHECK_ERROR_RETURN_LOG(cameraManager_ == nullptr, "failed to MuteCameraPersistent, cameraManager is nullptr");
    auto itr = g_jsToFwPolicyType.find(type);
    if (itr == g_jsToFwPolicyType.end()) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "MuteCameraPersistent fail");
        return;
    }
    cameraManager_->MuteCameraPersist(itr->second, mute);
}

SessionUnion CameraManagerImpl::CreateSession(SceneMode mode)
{
    CHECK_ERROR_RETURN_RET_LOG(cameraManager_ == nullptr,
        SessionUnion::make_session(make_holder<Ani::Camera::SessionImpl, Session>(nullptr)),
        "failed to CreateSession, cameraManager is nullptr");
    OHOS::CameraStandard::SceneMode sceneModeInner = OHOS::CameraStandard::NORMAL;
    std::unordered_map<int32_t, OHOS::CameraStandard::SceneMode> aniToNativeMap = g_aniToNativeSupportedMode;
    if (OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(false)) {
        aniToNativeMap = g_aniToNativeSupportedModeSys;
    }
    int32_t modeValue = mode.get_value();
    MEDIA_ERR_LOG("CameraManagerImpl::CreateSession SceneMode mode = %{public}d ", modeValue);
    auto itr = aniToNativeMap.find(modeValue);
    if (itr != aniToNativeMap.end()) {
        sceneModeInner = itr->second;
    } else {
        MEDIA_ERR_LOG("CameraManagerImpl::CreateSession mode = %{public}d not supported", modeValue);
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::PARAMETER_ERROR, "Invalid scene mode");
        return SessionUnion::make_session(make_holder<Ani::Camera::SessionImpl, Session>(
            cameraManager_->CreateCaptureSession(OHOS::CameraStandard::NORMAL)));
    }
    return CreateSessionWithMode(sceneModeInner);
}

PreviewOutput CameraManagerImpl::CreatePreviewOutput(Profile const& profile, string_view surfaceId)
{
    OHOS::CameraStandard::Profile innerProfile {
        static_cast<OHOS::CameraStandard::CameraFormat>(profile.format.get_value()),
        OHOS::CameraStandard::Size{ profile.size.width, profile.size.height }
    };
    std::string innerSurfaceId = std::string(surfaceId);
    uint64_t iSurfaceId;
    std::istringstream iss(innerSurfaceId);
    iss >> iSurfaceId;
    OHOS::sptr<OHOS::Surface> surface = OHOS::SurfaceUtils::GetInstance()->GetSurface(iSurfaceId);
    if (!surface) {
        surface = OHOS::Media::ImageReceiver::getSurfaceById(innerSurfaceId);
    }
    CHECK_ERROR_RETURN_RET_LOG(surface == nullptr,
        (make_holder<Ani::Camera::PreviewOutputImpl, PreviewOutput>(nullptr)), "failed to get surface");

    surface->SetUserData(OHOS::CameraStandard::CameraManager::surfaceFormat,
        std::to_string(innerProfile.GetCameraFormat()));
    OHOS::sptr<OHOS::CameraStandard::PreviewOutput> previewOutput = nullptr;
    int retCode = OHOS::CameraStandard::CameraManager::GetInstance()->CreatePreviewOutput(
        innerProfile, surface, &previewOutput);
    if (retCode != OHOS::CameraStandard::CameraErrorCode::SUCCESS) {
        CameraUtilsTaihe::ThrowError(retCode, "failed to create preview output");
        return make_holder<Ani::Camera::PreviewOutputImpl, PreviewOutput>(nullptr);
    }
    CHECK_EXECUTE(previewOutput == nullptr,
        CameraUtilsTaihe::ThrowError(retCode, "failed to create preview output"));
    return make_holder<Ani::Camera::PreviewOutputImpl, PreviewOutput>(previewOutput);
}

PreviewOutput CameraManagerImpl::CreatePreviewOutputWithoutProfile(string_view surfaceId)
{
    std::string innerSurfaceId = std::string(surfaceId);
    uint64_t iSurfaceId;
    std::istringstream iss(innerSurfaceId);
    iss >> iSurfaceId;
    OHOS::sptr<OHOS::Surface> surface = OHOS::SurfaceUtils::GetInstance()->GetSurface(iSurfaceId);
    if (!surface) {
        surface = OHOS::Media::ImageReceiver::getSurfaceById(innerSurfaceId);
    }
    CHECK_ERROR_RETURN_RET_LOG(surface == nullptr,
        (make_holder<Ani::Camera::PreviewOutputImpl, PreviewOutput>(nullptr)), "failed to get surface");
    OHOS::sptr<OHOS::CameraStandard::PreviewOutput> previewOutput = nullptr;
    int retCode = OHOS::CameraStandard::CameraManager::GetInstance()->CreatePreviewOutputWithoutProfile(
        surface, &previewOutput);
    if (retCode != OHOS::CameraStandard::CameraErrorCode::SUCCESS) {
        CameraUtilsTaihe::ThrowError(retCode, "failed to create preview output");
        return make_holder<Ani::Camera::PreviewOutputImpl, PreviewOutput>(nullptr);
    }
    CHECK_EXECUTE(previewOutput == nullptr,
        CameraUtilsTaihe::ThrowError(retCode, "failed to create preview output"));
    return make_holder<Ani::Camera::PreviewOutputImpl, PreviewOutput>(previewOutput);
}

PreviewOutput CameraManagerImpl::CreateDeferredPreviewOutput(optional_view<Profile> profile)
{
    auto Result = [](OHOS::sptr<OHOS::CameraStandard::PreviewOutput> output) {
        return make_holder<PreviewOutputImpl, PreviewOutput>(output);
    };
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), Result(nullptr),
        "SystemApi CreateDeferredPreviewOutputInstance is called!");
    CHECK_ERROR_RETURN_RET_LOG(!(profile.has_value()), Result(nullptr),
        "CreateDeferredPreviewOutput args is invalid!");
    OHOS::CameraStandard::Profile innerProfile {
        static_cast<OHOS::CameraStandard::CameraFormat>(profile.value().format.get_value()),
        OHOS::CameraStandard::Size{ profile.value().size.width, profile.value().size.height }
    };
    OHOS::sptr<OHOS::CameraStandard::PreviewOutput> previewOutput = nullptr;
    previewOutput = OHOS::CameraStandard::CameraManager::GetInstance()->CreateDeferredPreviewOutput(innerProfile);
    CHECK_ERROR_RETURN_RET_LOG(previewOutput == nullptr, Result(nullptr), "failed to create previewOutput");
    return Result(previewOutput);
}

PhotoOutput CameraManagerImpl::CreatePhotoOutput(optional_view<Profile> profile)
{
    auto Result = [](OHOS::sptr<OHOS::CameraStandard::CaptureOutput> output) {
        return make_holder<PhotoOutputImpl, PhotoOutput>(output);
    };
    OHOS::sptr<OHOS::Surface> photoSurface = OHOS::Surface::CreateSurfaceAsConsumer("photoOutput");
    CHECK_ERROR_RETURN_RET_LOG(photoSurface == nullptr,
        Result(nullptr), "failed to get surface");
    if (profile.has_value()) {
        OHOS::CameraStandard::Profile innerProfile{
            static_cast<OHOS::CameraStandard::CameraFormat>(profile.value().format.get_value()),
            OHOS::CameraStandard::Size{ profile.value().size.width, profile.value().size.height }
        };
        photoSurface->SetUserData(OHOS::CameraStandard::CameraManager::surfaceFormat,
            std::to_string(innerProfile.GetCameraFormat()));
        OHOS::sptr<OHOS::IBufferProducer> surfaceProducer = photoSurface->GetProducer();
        MEDIA_INFO_LOG("profile width: %{public}d, height: %{public}d, format = %{public}d, "
            "surface width: %{public}d, height: %{public}d", innerProfile.GetSize().width,
            innerProfile.GetSize().height, static_cast<int32_t>(innerProfile.GetCameraFormat()),
            photoSurface->GetDefaultWidth(), photoSurface->GetDefaultHeight());
        OHOS::sptr<OHOS::CameraStandard::PhotoOutput> photoOutput = nullptr;
        int retCode = OHOS::CameraStandard::CameraManager::GetInstance()->CreatePhotoOutput(
            innerProfile, surfaceProducer, &photoOutput, photoSurface);
        CHECK_EXECUTE(retCode != OHOS::CameraStandard::CameraErrorCode::SUCCESS,
            CameraUtilsTaihe::ThrowError(retCode, "failed to create photo output"));
        CHECK_ERROR_RETURN_RET_LOG(photoOutput == nullptr, Result(nullptr), "failed to create photo output");
        photoOutput->SetNativeSurface(true);
        CHECK_EXECUTE(photoOutput->IsYuvOrHeifPhoto(), photoOutput->CreateMultiChannel());
        return Result(photoOutput);
    } else {
        OHOS::sptr<OHOS::IBufferProducer> surfaceProducer = photoSurface->GetProducer();
        MEDIA_INFO_LOG("surface width: %{public}d, height: %{public}d", photoSurface->GetDefaultWidth(),
            photoSurface->GetDefaultHeight());
        OHOS::sptr<OHOS::CameraStandard::PhotoOutput> photoOutput = nullptr;
        int retCode = OHOS::CameraStandard::CameraManager::GetInstance()->CreatePhotoOutputWithoutProfile(
            surfaceProducer, &photoOutput, photoSurface);
        CHECK_EXECUTE(retCode != OHOS::CameraStandard::CameraErrorCode::SUCCESS,
            CameraUtilsTaihe::ThrowError(retCode, "failed to create photo output"));
        CHECK_ERROR_RETURN_RET_LOG(photoOutput == nullptr, Result(nullptr), "failed to create photo output");
        photoOutput->SetNativeSurface(true);
        return Result(photoOutput);
    }
}

VideoOutput CameraManagerImpl::CreateVideoOutput(VideoProfile const& profile, string_view surfaceId)
{
    OHOS::CameraStandard::VideoProfile videoProfile{
        static_cast<OHOS::CameraStandard::CameraFormat>(profile.base.format.get_value()),
        OHOS::CameraStandard::Size{ profile.base.size.width, profile.base.size.height },
        { static_cast<int32_t>(profile.frameRateRange.min), static_cast<int32_t>(profile.frameRateRange.max) }
    };
    std::string innerSurfaceId = std::string(surfaceId);
    uint64_t iSurfaceId;
    std::istringstream iss(innerSurfaceId);
    iss >> iSurfaceId;
    OHOS::sptr<OHOS::Surface> surface = OHOS::SurfaceUtils::GetInstance()->GetSurface(iSurfaceId);
    CHECK_ERROR_RETURN_RET_LOG(surface == nullptr, (make_holder<VideoOutputImpl, VideoOutput>(nullptr)),
        "failed to get surface from SurfaceUtils");
    surface->SetUserData(OHOS::CameraStandard::CameraManager::surfaceFormat,
        std::to_string(videoProfile.GetCameraFormat()));
    OHOS::sptr<OHOS::CameraStandard::VideoOutput> videoOutput = nullptr;
    int retCode = OHOS::CameraStandard::CameraManager::GetInstance()->CreateVideoOutput(videoProfile, surface,
        &videoOutput);
    CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode),
        (make_holder<VideoOutputImpl, VideoOutput>(nullptr)));
    CHECK_ERROR_RETURN_RET_LOG(videoOutput == nullptr, (make_holder<VideoOutputImpl, VideoOutput>(nullptr)),
        "failed to create VideoOutput");
    return make_holder<VideoOutputImpl, VideoOutput>(videoOutput);
}

MetadataOutput CameraManagerImpl::CreateMetadataOutput(array_view<MetadataObjectType> metadataObjectTypes)
{
    std::vector<OHOS::CameraStandard::MetadataObjectType> innerMetadataObjectTypes;
    for (const auto& item : metadataObjectTypes) {
        innerMetadataObjectTypes.push_back(static_cast<OHOS::CameraStandard::MetadataObjectType>(item.get_value()));
    }

    OHOS::sptr<OHOS::CameraStandard::MetadataOutput> metadataOutput = nullptr;
    int retCode = OHOS::CameraStandard::CameraManager::GetInstance()->CreateMetadataOutput(
        metadataOutput, innerMetadataObjectTypes);
    CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode),
        (taihe::make_holder<MetadataOutputImpl, MetadataOutput>(nullptr)));
    CHECK_ERROR_RETURN_RET_LOG(metadataOutput == nullptr,
        (taihe::make_holder<MetadataOutputImpl, MetadataOutput>(nullptr)), "failed to create MetadataOutput");

    return taihe::make_holder<MetadataOutputImpl, MetadataOutput>(metadataOutput);
}

VideoOutput CameraManagerImpl::CreateVideoOutputWithoutProfile(string_view surfaceId)
{
    std::string innerSurfaceId = std::string(surfaceId);
    uint64_t iSurfaceId;
    std::istringstream iss(innerSurfaceId);
    iss >> iSurfaceId;
    OHOS::sptr<OHOS::Surface> surface = OHOS::SurfaceUtils::GetInstance()->GetSurface(iSurfaceId);
    CHECK_ERROR_RETURN_RET_LOG(surface == nullptr, (make_holder<VideoOutputImpl, VideoOutput>(nullptr)),
        "failed to get surface from SurfaceUtils");
    OHOS::sptr<OHOS::CameraStandard::VideoOutput> videoOutput = nullptr;
    int retCode = OHOS::CameraStandard::CameraManager::GetInstance()->CreateVideoOutputWithoutProfile(surface,
        &videoOutput);
    CHECK_ERROR_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode),
        (make_holder<VideoOutputImpl, VideoOutput>(nullptr)));
    CHECK_ERROR_RETURN_RET_LOG(videoOutput == nullptr, (make_holder<VideoOutputImpl, VideoOutput>(nullptr)),
        "failed to create VideoOutput");
    return make_holder<VideoOutputImpl, VideoOutput>(videoOutput);
}

CameraInput CameraManagerImpl::CreateCameraInputWithCameraDevice(CameraDevice const& camera)
{
    CHECK_ERROR_RETURN_RET_LOG(cameraManager_ == nullptr, (make_holder<CameraInputImpl, CameraInput>(nullptr)),
        "cameraManager_ is nullptr");
    std::string cameraId = std::string(camera.cameraId);
    OHOS::sptr<OHOS::CameraStandard::CameraDevice> cameraInfo = cameraManager_->GetCameraDeviceFromId(cameraId);
    if (cameraInfo == nullptr) {
        MEDIA_ERR_LOG("cameraInfo is null");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::CameraErrorCode::INVALID_ARGUMENT, "cameraInfo is null");
        return make_holder<CameraInputImpl, CameraInput>(nullptr);
    }
    OHOS::sptr<OHOS::CameraStandard::CameraInput> cameraInput = nullptr;
    int retCode = cameraManager_->CreateCameraInput(cameraInfo, &cameraInput);
    CHECK_EXECUTE(retCode != OHOS::CameraStandard::CameraErrorCode::SUCCESS,
        CameraUtilsTaihe::ThrowError(retCode, "CreateCameraInput failed."));
    return make_holder<CameraInputImpl, CameraInput>(cameraInput);
}

CameraInput CameraManagerImpl::CreateCameraInputWithPosition(CameraPosition position, CameraType type)
{
    CHECK_ERROR_RETURN_RET_LOG(cameraManager_ == nullptr, (make_holder<CameraInputImpl, CameraInput>(nullptr)),
        "cameraManager_ is nullptr");
    int32_t cameraPosition = static_cast<int32_t>(position.get_value());
    int32_t cameraType = static_cast<int32_t>(type.get_value());
    OHOS::sptr<OHOS::CameraStandard::CameraDevice> cameraInfo = nullptr;
    ProcessCameraInfo(cameraManager_, static_cast<const OHOS::CameraStandard::CameraPosition>(cameraPosition),
        static_cast<const OHOS::CameraStandard::CameraType>(cameraType), cameraInfo);
    if (cameraInfo == nullptr) {
        MEDIA_ERR_LOG("cameraInfo is null");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::CameraErrorCode::INVALID_ARGUMENT, "cameraInfo is null");
        return make_holder<CameraInputImpl, CameraInput>(nullptr);
    }
    OHOS::sptr<OHOS::CameraStandard::CameraInput> cameraInput = nullptr;
    int retCode = cameraManager_->CreateCameraInput(cameraInfo, &cameraInput);
    CHECK_EXECUTE(retCode != OHOS::CameraStandard::CameraErrorCode::SUCCESS,
        CameraUtilsTaihe::ThrowError(retCode, "CreateCameraInput failed."));
    return make_holder<CameraInputImpl, CameraInput>(cameraInput);
}


DepthDataOutput CameraManagerImpl::CreateDepthDataOutput(DepthProfile const& profile)
{
    auto Result = [](OHOS::sptr<OHOS::CameraStandard::CaptureOutput> output, OHOS::sptr<OHOS::Surface> surface) {
        return make_holder<DepthDataOutputImpl, DepthDataOutput>(output, surface);
    };
    CHECK_ERROR_RETURN_RET_LOG(cameraManager_ == nullptr, Result(nullptr, nullptr), "cameraManager_ is nullptr");
    OHOS::CameraStandard::CameraFormat cameraFormat =
        static_cast<OHOS::CameraStandard::CameraFormat>(profile.format.get_value());
    OHOS::CameraStandard::DepthDataAccuracy depthDataAccuracy =
    static_cast<OHOS::CameraStandard::DepthDataAccuracy>(profile.dataAccuracy.get_value());
    OHOS::CameraStandard::Size size { static_cast<uint32_t>(profile.size.width),
                                      static_cast<uint32_t>(profile.size.height) };
    OHOS::CameraStandard::DepthProfile depthProfile(cameraFormat, depthDataAccuracy, size);
    MEDIA_INFO_LOG(
        "CameraManagerImpl::CreateDepthDataOutputInstance ParseDepthProfile "
        "size.width = %{public}d, size.height = %{public}d, format = %{public}d, dataAccuracy = %{public}d,",
        depthProfile.size_.width, depthProfile.size_.height, depthProfile.format_, depthProfile.dataAccuracy_);
    OHOS::sptr<OHOS::Surface> depthDataSurface = nullptr;
    MEDIA_INFO_LOG("create surface as consumer");
    depthDataSurface = OHOS::Surface::CreateSurfaceAsConsumer("depthDataOutput");
    CHECK_ERROR_RETURN_RET_LOG(depthDataSurface == nullptr, Result(nullptr, nullptr), "failed to get surface");
    OHOS::sptr<OHOS::IBufferProducer> surfaceProducer = depthDataSurface->GetProducer();
    OHOS::sptr<OHOS::CameraStandard::DepthDataOutput> depthDataOutput;
    int retCode = cameraManager_->CreateDepthDataOutput(depthProfile, surfaceProducer, &depthDataOutput);
    CHECK_ERROR_RETURN_RET_LOG(!CameraUtilsTaihe::CheckError(retCode) || depthDataOutput == nullptr,
        Result(nullptr, nullptr), "failed to create CreateDepthDataOutput");
    return Result(depthDataOutput, depthDataSurface);
}

void CameraManagerImpl::ProcessCameraInfo(OHOS::sptr<OHOS::CameraStandard::CameraManager>& cameraManager,
    const OHOS::CameraStandard::CameraPosition cameraPosition, const OHOS::CameraStandard::CameraType cameraType,
    OHOS::sptr<OHOS::CameraStandard::CameraDevice>& cameraInfo)
{
    std::vector<OHOS::sptr<OHOS::CameraStandard::CameraDevice>> cameraObjList = cameraManager->GetSupportedCameras();
    MEDIA_DEBUG_LOG("cameraInfo is null, the cameraObjList size is %{public}zu", cameraObjList.size());
    for (size_t i = 0; i < cameraObjList.size(); i++) {
        OHOS::sptr<OHOS::CameraStandard::CameraDevice> cameraDevice = cameraObjList[i];
        if (cameraDevice == nullptr) {
            continue;
        }
        if (cameraDevice->GetPosition() == cameraPosition &&
            cameraDevice->GetCameraType() == cameraType) {
            cameraInfo = cameraDevice;
            break;
        }
    }
}

void CameraManagerImpl::SetPrelaunchConfig(PrelaunchConfig const& prelaunchConfig)
{
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi SetPrelaunchConfig is called!");
    CHECK_ERROR_RETURN_LOG(cameraManager_ == nullptr, "failed to SetPrelaunchConfig, cameraManager is nullprt");
    std::string cameraId(prelaunchConfig.cameraDevice.cameraId);
    OHOS::CameraStandard::EffectParam effectParam;
    OHOS::CameraStandard::PrelaunchConfig prelaunchConfigNative;
    if (prelaunchConfig.restoreParamType.has_value()) {
        prelaunchConfigNative.restoreParamType = static_cast<OHOS::CameraStandard::RestoreParamType>(
            prelaunchConfig.restoreParamType.value().get_value());
    }
    if (prelaunchConfig.activeTime.has_value()) {
        prelaunchConfigNative.activeTime = prelaunchConfig.activeTime.value();
    }
    if (prelaunchConfig.settingParam.has_value()) {
        prelaunchConfigNative.settingParam.skinSmoothLevel = prelaunchConfig.settingParam.value().skinSmoothLevel;
        prelaunchConfigNative.settingParam.skinTone = prelaunchConfig.settingParam.value().skinTone;
        prelaunchConfigNative.settingParam.faceSlender = prelaunchConfig.settingParam.value().faceSlender;
        effectParam.skinSmoothLevel = prelaunchConfig.settingParam.value().skinSmoothLevel;
        effectParam.skinTone = prelaunchConfig.settingParam.value().skinTone;
        effectParam.faceSlender = prelaunchConfig.settingParam.value().faceSlender;
    }
    MEDIA_INFO_LOG("SetPrelaunchConfig cameraId = %{public}s", cameraId.c_str());
    int32_t retCode = cameraManager_->SetPrelaunchConfig(cameraId,
        static_cast<OHOS::CameraStandard::RestoreParamTypeOhos>(prelaunchConfigNative.restoreParamType),
        prelaunchConfigNative.activeTime, effectParam);
    CHECK_ERROR_RETURN_LOG(!CameraUtilsTaihe::CheckError(retCode),
        "CameraManagerImpl::SetPrelaunchConfig fail %{public}d", retCode);
}

bool CameraManagerImpl::IsTorchModeSupported(TorchMode mode)
{
    MEDIA_INFO_LOG("IsTorchModeSupported is called");
    bool isTorchModeSupported = OHOS::CameraStandard::CameraManager::GetInstance()->IsTorchModeSupported(
        static_cast<OHOS::CameraStandard::TorchMode>(mode.get_value()));
    MEDIA_DEBUG_LOG("IsTorchModeSupported : %{public}d", isTorchModeSupported);
    return isTorchModeSupported;
}

CameraManager getCameraManager(uintptr_t context)
{
    return make_holder<Ani::Camera::CameraManagerImpl, CameraManager>();
}
} // namespace Camera
} // namespace Ani


TH_EXPORT_CPP_API_getCameraManager(Ani::Camera::getCameraManager);