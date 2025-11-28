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

#include "input/camera_manager_napi.h"

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <uv.h>

#include "camera_device.h"
#include "camera_error_code.h"
#include "camera_log.h"
#include "camera_manager.h"
#include "camera_napi_const.h"
#include "camera_napi_event_emitter.h"
#include "camera_napi_object_types.h"
#include "camera_napi_param_parser.h"
#include "camera_napi_security_utils.h"
#include "camera_napi_template_utils.h"
#include "camera_napi_utils.h"
#include "camera_output_capability.h"
#include "camera_xcollie.h"
#include "capture_scene_const.h"
#include "dynamic_loader/camera_napi_ex_manager.h"
#include "input/camera_napi.h"
#include "input/prelaunch_config.h"
#include "ipc_skeleton.h"
#include "js_native_api.h"
#include "js_native_api_types.h"
#include "mode/photo_session_napi.h"
#include "mode/secure_camera_session_napi.h"
#include "mode/video_session_napi.h"
#include "napi/native_common.h"
#include "refbase.h"
#include "napi/native_node_api.h"
#include "session/control_center_session_napi.h"
#include "camera_security_utils.h"

namespace OHOS {
namespace CameraStandard {
namespace {
thread_local std::unordered_map<std::string, napi_ref> g_napiValueCacheMap {};
void CacheNapiValue(napi_env env, const std::string& key, napi_value value)
{
    napi_ref ref;
    napi_status status = napi_create_reference(env, value, 0, &ref); // 0 is weakref.
    if (status == napi_ok) {
        g_napiValueCacheMap[key] = ref;
        MEDIA_DEBUG_LOG("CacheNapiValue cache->%{public}s", key.c_str());
    }
}

napi_value GetCacheNapiValue(napi_env env, const std::string& key)
{
    napi_ref ref;
    auto it = g_napiValueCacheMap.find(key);
    CHECK_RETURN_RET(it == g_napiValueCacheMap.end(), nullptr);
    ref = it->second;
    napi_value result;
    napi_status status = napi_get_reference_value(env, ref, &result);
    if (status == napi_ok) {
        MEDIA_DEBUG_LOG("GetCacheNapiValue hit cache->%{public}s", key.c_str());
        return result;
    }
    return nullptr;
}

void CacheSupportedOutputCapability(napi_env env, const std::string& cameraId, int32_t mode, napi_value value)
{
    std::string key = "OutputCapability:" + cameraId + ":\t" + to_string(mode);
    CacheNapiValue(env, key, value);
    MEDIA_DEBUG_LOG("CacheSupportedOutputCapability cache->%{public}s:%{public}d", key.c_str(), mode);
}

napi_value GetCachedSupportedOutputCapability(napi_env env, const std::string& cameraId, int32_t mode)
{
    std::string key = "OutputCapability:" + cameraId + ":\t" + to_string(mode);
    napi_value result = GetCacheNapiValue(env, key);
    if (result != nullptr) {
        MEDIA_DEBUG_LOG("GetCachedSupportedOutputCapability hit cache->%{public}s:%{public}d", key.c_str(), mode);
    }
    return result;
}

void CacheSupportedCameras(napi_env env, const std::vector<sptr<CameraDevice>>& cameras, napi_value value)
{
    std::string key = "SupportedCameras:";
    for (auto& camera : cameras) {
        if (camera->GetConnectionType() != CAMERA_CONNECTION_BUILT_IN) {
            // Exist none built_in camera. Give up cache.
            MEDIA_DEBUG_LOG("CacheSupportedCameras exist none built_in camera. Give up cache");
            return;
        }
        key.append("\t:");
        key.append(camera->GetID());
    }
    CacheNapiValue(env, key, value);
    MEDIA_DEBUG_LOG("CacheSupportedCameras cache->%{public}s", key.c_str());
}

napi_value GetCachedSupportedCameras(napi_env env, const std::vector<sptr<CameraDevice>>& cameras)
{
    std::string key = "SupportedCameras:";
    for (auto& camera : cameras) {
        if (camera->GetConnectionType() != CAMERA_CONNECTION_BUILT_IN) {
            // Exist none built_in camera. Give up cache.
            MEDIA_DEBUG_LOG("GetCachedSupportedCameras exist none built_in camera. Give up cache");
            return nullptr;
        }
        key.append("\t:");
        key.append(camera->GetID());
    }
    napi_value result = GetCacheNapiValue(env, key);
    if (result != nullptr) {
        MEDIA_DEBUG_LOG("GetCachedSupportedCameras hit cache->%{public}s", key.c_str());
    }
    return result;
}
} // namespace

namespace {
void AsyncCompleteCallback(napi_env env, napi_status status, void* data)
{
    auto context = static_cast<CameraManagerAsyncContext*>(data);
    CHECK_RETURN_ELOG(context == nullptr, "CameraManagerNapi AsyncCompleteCallback context is null");
    MEDIA_INFO_LOG("CameraManagerNapi AsyncCompleteCallback %{public}s, status = %{public}d", context->funcName.c_str(),
        context->status);
    std::unique_ptr<JSAsyncContextOutput> jsContext = std::make_unique<JSAsyncContextOutput>();
    jsContext->status = context->status;
    if (!context->status) {
        CameraNapiUtils::CreateNapiErrorObject(env, context->errorCode, context->errorMsg.c_str(), jsContext);
    } else {
        napi_create_int64(env, context->storageSize, &jsContext->data);
    }
    if (!context->funcName.empty() && context->taskId > 0) {
        // Finish async trace
        CAMERA_FINISH_ASYNC_TRACE(context->funcName, context->taskId);
        jsContext->funcName = context->funcName.c_str();
    }
    if (context->work != nullptr) {
        CameraNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef, context->work, *jsContext);
    }
    context->FreeHeldNapiValue(env);
    delete context;
}
} // namespace

using namespace std;
using namespace CameraNapiSecurity;
thread_local napi_ref CameraManagerNapi::sConstructor_ = nullptr;
thread_local uint32_t CameraManagerNapi::cameraManagerTaskId = CAMERA_MANAGER_TASKID;

const std::unordered_map<SceneMode, JsSceneMode> g_nativeToNapiSupportedModeForSystem_ = {
    {SceneMode::CAPTURE,  JsSceneMode::JS_CAPTURE},
    {SceneMode::VIDEO,  JsSceneMode::JS_VIDEO},
    {SceneMode::PORTRAIT,  JsSceneMode::JS_PORTRAIT},
    {SceneMode::NIGHT,  JsSceneMode::JS_NIGHT},
    {SceneMode::CAPTURE_MACRO, JsSceneMode::JS_CAPTURE_MARCO},
    {SceneMode::VIDEO_MACRO, JsSceneMode::JS_VIDEO_MARCO},
    {SceneMode::SLOW_MOTION,  JsSceneMode::JS_SLOW_MOTION},
    {SceneMode::PROFESSIONAL_PHOTO,  JsSceneMode::JS_PROFESSIONAL_PHOTO},
    {SceneMode::PROFESSIONAL_VIDEO,  JsSceneMode::JS_PROFESSIONAL_VIDEO},
    {SceneMode::HIGH_RES_PHOTO, JsSceneMode::JS_HIGH_RES_PHOTO},
    {SceneMode::SECURE, JsSceneMode::JS_SECURE_CAMERA},
    {SceneMode::QUICK_SHOT_PHOTO, JsSceneMode::JS_QUICK_SHOT_PHOTO},
    {SceneMode::APERTURE_VIDEO, JsSceneMode::JS_APERTURE_VIDEO},
    {SceneMode::PANORAMA_PHOTO, JsSceneMode::JS_PANORAMA_PHOTO},
    {SceneMode::LIGHT_PAINTING, JsSceneMode::JS_LIGHT_PAINTING},
    {SceneMode::TIMELAPSE_PHOTO, JsSceneMode::JS_TIMELAPSE_PHOTO},
    {SceneMode::FLUORESCENCE_PHOTO, JsSceneMode::JS_FLUORESCENCE_PHOTO},
};

const std::unordered_map<SceneMode, JsSceneMode> g_nativeToNapiSupportedMode_ = {
    {SceneMode::CAPTURE,  JsSceneMode::JS_CAPTURE},
    {SceneMode::VIDEO,  JsSceneMode::JS_VIDEO},
    {SceneMode::SECURE,  JsSceneMode::JS_SECURE_CAMERA},
};

CameraManagerCallbackNapi::CameraManagerCallbackNapi(napi_env env): ListenerBase(env)
{}

CameraManagerCallbackNapi::~CameraManagerCallbackNapi()
{
}

void CameraManagerCallbackNapi::OnCameraStatusCallbackAsync(const CameraStatusInfo &cameraStatusInfo) const
{
    MEDIA_DEBUG_LOG("OnCameraStatusCallbackAsync is called");
    std::unique_ptr<CameraStatusCallbackInfo> callbackInfo =
        std::make_unique<CameraStatusCallbackInfo>(cameraStatusInfo, shared_from_this());
    CameraStatusCallbackInfo *event = callbackInfo.get();
    auto task = [event]() {
        CameraStatusCallbackInfo* callbackInfo = reinterpret_cast<CameraStatusCallbackInfo *>(event);
        if (callbackInfo) {
            auto listener = callbackInfo->listener_.lock();
            CHECK_EXECUTE(listener, listener->OnCameraStatusCallback(callbackInfo->info_));
            delete callbackInfo;
        }
    };
    std::string taskName = "CameraManagerCallbackNapi::OnCameraStatusCallbackAsync"
        "[cameraStatus:" + std::to_string(cameraStatusInfo.cameraStatus) + "]";
    if (napi_ok != napi_send_event(env_, task, napi_eprio_immediate, taskName.c_str())) {
        MEDIA_ERR_LOG("failed to execute work");
    } else {
        callbackInfo.release();
    }
}

void CameraManagerCallbackNapi::OnCameraStatusCallback(const CameraStatusInfo& cameraStatusInfo) const
{
    MEDIA_DEBUG_LOG("OnCameraStatusCallback is called");
    CAMERA_NAPI_CHECK_NULL_PTR_RETURN_VOID(cameraStatusInfo.cameraDevice, "callback cameraDevice is null");
    ExecuteCallbackScopeSafe("cameraStatus", [&]() {
        napi_value callbackObj;
        napi_create_object(env_, &callbackObj);
        napi_value cameraDeviceNapi = CameraNapiObjCameraDevice(*cameraStatusInfo.cameraDevice).GenerateNapiValue(env_);
        napi_set_named_property(env_, callbackObj, "camera", cameraDeviceNapi);
        int32_t jsCameraStatus = cameraStatusInfo.cameraStatus;
        napi_value propValue;
        napi_create_int64(env_, jsCameraStatus, &propValue);
        napi_set_named_property(env_, callbackObj, "status", propValue);
        MEDIA_INFO_LOG("CameraId: %{public}s, CameraStatus: %{public}d",
            cameraStatusInfo.cameraDevice->GetID().c_str(),
            cameraStatusInfo.cameraStatus);
        napi_value errCode = CameraNapiUtils::GetUndefinedValue(env_);
        return ExecuteCallbackData(env_, errCode, callbackObj);
    });
}

void CameraManagerCallbackNapi::OnCameraStatusChanged(const CameraStatusInfo &cameraStatusInfo) const
{
    MEDIA_DEBUG_LOG("OnCameraStatusChanged is called, CameraStatus: %{public}d", cameraStatusInfo.cameraStatus);
    OnCameraStatusCallbackAsync(cameraStatusInfo);
}

void CameraManagerCallbackNapi::OnFlashlightStatusChanged(const std::string &cameraID,
    const FlashStatus flashStatus) const
{
    (void)cameraID;
    (void)flashStatus;
}

CameraMuteListenerNapi::CameraMuteListenerNapi(napi_env env): ListenerBase(env)
{
    MEDIA_DEBUG_LOG("CameraMuteListenerNapi is called.");
}

CameraMuteListenerNapi::~CameraMuteListenerNapi()
{
    MEDIA_DEBUG_LOG("~CameraMuteListenerNapi is called.");
}

void CameraMuteListenerNapi::OnCameraMuteCallbackAsync(bool muteMode) const
{
    std::unique_ptr<CameraMuteCallbackInfo> callbackInfo =
        std::make_unique<CameraMuteCallbackInfo>(muteMode, shared_from_this());
    CameraMuteCallbackInfo *event = callbackInfo.get();
    auto task = [event]() {
        CameraMuteCallbackInfo* callbackInfo = reinterpret_cast<CameraMuteCallbackInfo *>(event);
        if (callbackInfo) {
            auto listener = callbackInfo->listener_.lock();
            CHECK_EXECUTE(listener != nullptr, listener->OnCameraMuteCallback(callbackInfo->muteMode_));
            delete callbackInfo;
        }
    };
    std::string taskName = "CameraMuteListenerNapi::OnCameraMuteCallbackAsync"
        "[muteMode:" + std::to_string(muteMode) + "]";
    if (napi_ok != napi_send_event(env_, task, napi_eprio_immediate, taskName.c_str())) {
        MEDIA_ERR_LOG("Failed to execute work");
    } else {
        callbackInfo.release();
    }
}

void CameraMuteListenerNapi::OnCameraMuteCallback(bool muteMode) const
{
    MEDIA_DEBUG_LOG("OnCameraMuteCallback is called, muteMode: %{public}d", muteMode);

    ExecuteCallbackScopeSafe("cameraMute", [&]() {
        napi_value callbackObj;
        napi_get_boolean(env_, muteMode, &callbackObj);
        napi_value errCode = CameraNapiUtils::GetUndefinedValue(env_);
        return ExecuteCallbackData(env_, errCode, callbackObj);
    });
}

void CameraMuteListenerNapi::OnCameraMute(bool muteMode) const
{
    MEDIA_DEBUG_LOG("OnCameraMute is called, muteMode: %{public}d", muteMode);
    OnCameraMuteCallbackAsync(muteMode);
}

ControlCenterStatusListenerNapi::ControlCenterStatusListenerNapi(napi_env env): ListenerBase(env)
{
    MEDIA_DEBUG_LOG("ControlCenterStatusListenerNapi is called.");
}
 
ControlCenterStatusListenerNapi::~ControlCenterStatusListenerNapi()
{
    MEDIA_DEBUG_LOG("~ControlCenterStatusListenerNapi is called.");
}
 
void ControlCenterStatusListenerNapi::OnControlCenterStatusCallbackAsync(bool status) const
{
    MEDIA_INFO_LOG("OnControlCenterStatusCallbackAsync is called, status: %{public}d", status);
    std::unique_ptr<ControlCenterStatusCallbackInfo> callbackInfo =
        std::make_unique<ControlCenterStatusCallbackInfo>(status, shared_from_this());
    ControlCenterStatusCallbackInfo *event = callbackInfo.get();
    auto task = [event]() {
        ControlCenterStatusCallbackInfo* callbackInfo = reinterpret_cast<ControlCenterStatusCallbackInfo *>(event);
        if (callbackInfo) {
            auto listener = callbackInfo->listener_.lock();
            if (listener != nullptr) {
                listener->OnControlCenterStatusCallback(callbackInfo->controlCenterStatus_);
            }
            delete callbackInfo;
        }
    };
    std::string taskName = "ControlCenterStatusListenerNapi::OnControlCenterStatusCallbackAsync"
        "[status:" + std::to_string(status) + "]";
    if (napi_ok != napi_send_event(env_, task, napi_eprio_immediate, taskName.c_str())) {
        MEDIA_ERR_LOG("Failed to execute work");
    } else {
        callbackInfo.release();
    }
}
 
void ControlCenterStatusListenerNapi::OnControlCenterStatusCallback(bool status) const
{
    MEDIA_INFO_LOG("OnControlCenterStatusCallback is called, status: %{public}d", status);
    ExecuteCallbackScopeSafe("controlCenterStatusChange", [&]() {
        napi_value errCode = CameraNapiUtils::GetUndefinedValue(env_);
        napi_value result;
        napi_create_int32(env_, static_cast<int32_t>(status), &result);
        return ExecuteCallbackData(env_, errCode, result);
    });
}
 
void ControlCenterStatusListenerNapi::OnControlCenterStatusChanged(bool status) const
{
    MEDIA_INFO_LOG("OnControlCenterStatusChanged is called, status: %{public}d", status);
    OnControlCenterStatusCallbackAsync(status);
}

TorchListenerNapi::TorchListenerNapi(napi_env env): ListenerBase(env)
{
    MEDIA_INFO_LOG("TorchListenerNapi is called.");
}

TorchListenerNapi::~TorchListenerNapi()
{
    MEDIA_DEBUG_LOG("~TorchListenerNapi is called.");
}

void TorchListenerNapi::OnTorchStatusChangeCallbackAsync(const TorchStatusInfo &torchStatusInfo) const
{
    MEDIA_DEBUG_LOG("OnTorchStatusChangeCallbackAsync is called");
    std::unique_ptr<TorchStatusChangeCallbackInfo> callbackInfo =
        std::make_unique<TorchStatusChangeCallbackInfo>(torchStatusInfo, shared_from_this());
    TorchStatusChangeCallbackInfo *event = callbackInfo.get();
    auto task = [event]() {
        TorchStatusChangeCallbackInfo* callbackInfo = reinterpret_cast<TorchStatusChangeCallbackInfo *>(event);
        if (callbackInfo) {
            auto listener = callbackInfo->listener_.lock();
            CHECK_EXECUTE(listener != nullptr, listener->OnTorchStatusChangeCallback(callbackInfo->info_));
            delete callbackInfo;
        }
    };
    std::string taskName = "TorchListenerNapi::OnTorchStatusChangeCallbackAsync";
    taskName += torchStatusInfo.isTorchAvailable ? (
        torchStatusInfo.isTorchActive ? "[torchLevel:" + std::to_string(torchStatusInfo.torchLevel) + "]" :
        "[torchActive:0]") : "[torchAvailable:0]";
    if (napi_ok != napi_send_event(env_, task, napi_eprio_immediate, taskName.c_str())) {
        MEDIA_ERR_LOG("Failed to execute work");
    } else {
        callbackInfo.release();
    }
}

void TorchListenerNapi::OnTorchStatusChangeCallback(const TorchStatusInfo& torchStatusInfo) const
{
    MEDIA_DEBUG_LOG("OnTorchStatusChangeCallback is called");
    ExecuteCallbackScopeSafe("torchStatusChange", [&]() {
        napi_value errCode = CameraNapiUtils::GetUndefinedValue(env_);
        napi_value callbackObj;
        TorchStatusInfo info = torchStatusInfo;
        CameraNapiObject torchStateObj {{
            { "isTorchAvailable", &info.isTorchAvailable },
            { "isTorchActive", &info.isTorchActive },
            { "torchLevel", &info.torchLevel }
        }};
        callbackObj = torchStateObj.CreateNapiObjFromMap(env_);
        return ExecuteCallbackData(env_, errCode, callbackObj);
    });
}

void TorchListenerNapi::OnTorchStatusChange(const TorchStatusInfo &torchStatusInfo) const
{
    MEDIA_DEBUG_LOG("OnTorchStatusChange is called");
    OnTorchStatusChangeCallbackAsync(torchStatusInfo);
}

FoldListenerNapi::FoldListenerNapi(napi_env env): ListenerBase(env)
{
    MEDIA_DEBUG_LOG("FoldListenerNapi is called.");
}

FoldListenerNapi::~FoldListenerNapi()
{
    MEDIA_DEBUG_LOG("~FoldListenerNapi is called.");
}

void FoldListenerNapi::OnFoldStatusChangedCallbackAsync(const FoldStatusInfo &foldStatusInfo) const
{
    MEDIA_DEBUG_LOG("OnFoldStatusChangedCallbackAsync is called");
    std::unique_ptr<FoldStatusChangeCallbackInfo> callbackInfo =
        std::make_unique<FoldStatusChangeCallbackInfo>(foldStatusInfo, shared_from_this());
    FoldStatusChangeCallbackInfo *event = callbackInfo.get();
    auto task = [event]() {
        FoldStatusChangeCallbackInfo* callbackInfo = reinterpret_cast<FoldStatusChangeCallbackInfo *>(event);
        if (callbackInfo) {
            auto listener = callbackInfo->listener_.lock();
            if (listener != nullptr) {
                listener->OnFoldStatusChangedCallback(callbackInfo->info_);
            }
            delete callbackInfo;
        }
    };
    std::string taskName = "FoldListenerNapi::OnFoldStatusChangedCallbackAsync"
        "[foldStatus:" + std::to_string(static_cast<int32_t>(foldStatusInfo.foldStatus)) + "]";
    if (napi_ok != napi_send_event(env_, task, napi_eprio_immediate, taskName.c_str())) {
        MEDIA_ERR_LOG("Failed to execute work");
    } else {
        callbackInfo.release();
    }
}

void FoldListenerNapi::OnFoldStatusChangedCallback(const FoldStatusInfo& foldStatusInfo) const
{
    MEDIA_DEBUG_LOG("OnFoldStatusChangedCallback is called");
    ExecuteCallbackScopeSafe("foldStatusChange", [&]() {
        napi_value errCode = CameraNapiUtils::GetUndefinedValue(env_);
        napi_create_object(env_, &errCode);
        napi_value resultObj;
        napi_create_object(env_, &resultObj);

        napi_value foldStatusVal;
        napi_create_int32(env_, static_cast<int32_t>(foldStatusInfo.foldStatus), &foldStatusVal);
        napi_set_named_property(env_, resultObj, "foldStatus", foldStatusVal);
        napi_value camerasArray;
        napi_create_array(env_, &camerasArray);

        const auto& supportedCameras = foldStatusInfo.supportedCameras;
        napi_value jsErrCode;
        if (supportedCameras.empty()) {
            MEDIA_ERR_LOG("supportedCameras is empty");
            napi_create_int32(env_, CameraErrorCode::SERVICE_FATL_ERROR, &jsErrCode);
            napi_set_named_property(env_, errCode, "code", jsErrCode);
            napi_set_named_property(env_, resultObj, "supportedCameras", camerasArray);
            return ExecuteCallbackData(env_, errCode, resultObj);
        }

        for (size_t i = 0; i < supportedCameras.size(); ++i) {
            if (supportedCameras[i] == nullptr) {
                MEDIA_ERR_LOG("cameraDevice is null");
                continue;
            }
            napi_value cameraObj = CameraNapiObjCameraDevice(*supportedCameras[i]).GenerateNapiValue(env_);
            napi_set_element(env_, camerasArray, i, cameraObj);
        }

        napi_create_int32(env_, 0, &jsErrCode);
        napi_set_named_property(env_, errCode, "code", jsErrCode);
        napi_set_named_property(env_, resultObj, "supportedCameras", camerasArray);
        return ExecuteCallbackData(env_, errCode, resultObj);
    });
}

void FoldListenerNapi::OnFoldStatusChanged(const FoldStatusInfo &foldStatusInfo) const
{
    MEDIA_DEBUG_LOG("OnFoldStatusChanged is called");
    OnFoldStatusChangedCallbackAsync(foldStatusInfo);
}

const std::unordered_map<JsSceneMode, SceneMode> g_jsToFwMode_ = {
    {JsSceneMode::JS_NORMAL, SceneMode::NORMAL},
    {JsSceneMode::JS_CAPTURE, SceneMode::CAPTURE},
    {JsSceneMode::JS_VIDEO, SceneMode::VIDEO},
    {JsSceneMode::JS_SECURE_CAMERA, SceneMode::SECURE},
};

const std::unordered_map<JsSceneMode, SceneMode> g_jsToFwMode4Sys_ = {
    {JsSceneMode::JS_NORMAL, SceneMode::NORMAL},
    {JsSceneMode::JS_CAPTURE, SceneMode::CAPTURE},
    {JsSceneMode::JS_VIDEO, SceneMode::VIDEO},
    {JsSceneMode::JS_PORTRAIT, SceneMode::PORTRAIT},
    {JsSceneMode::JS_NIGHT, SceneMode::NIGHT},
    {JsSceneMode::JS_SLOW_MOTION, SceneMode::SLOW_MOTION},
    {JsSceneMode::JS_CAPTURE_MARCO, SceneMode::CAPTURE_MACRO},
    {JsSceneMode::JS_VIDEO_MARCO, SceneMode::VIDEO_MACRO},
    {JsSceneMode::JS_PROFESSIONAL_PHOTO, SceneMode::PROFESSIONAL_PHOTO},
    {JsSceneMode::JS_PROFESSIONAL_VIDEO, SceneMode::PROFESSIONAL_VIDEO},
    {JsSceneMode::JS_HIGH_RES_PHOTO, SceneMode::HIGH_RES_PHOTO},
    {JsSceneMode::JS_SECURE_CAMERA, SceneMode::SECURE},
    {JsSceneMode::JS_QUICK_SHOT_PHOTO, SceneMode::QUICK_SHOT_PHOTO},
    {JsSceneMode::JS_APERTURE_VIDEO, SceneMode::APERTURE_VIDEO},
    {JsSceneMode::JS_PANORAMA_PHOTO, SceneMode::PANORAMA_PHOTO},
    {JsSceneMode::JS_LIGHT_PAINTING, SceneMode::LIGHT_PAINTING},
    {JsSceneMode::JS_TIMELAPSE_PHOTO, SceneMode::TIMELAPSE_PHOTO},
    {JsSceneMode::JS_FLUORESCENCE_PHOTO, SceneMode::FLUORESCENCE_PHOTO},
};

static std::unordered_map<JsPolicyType, PolicyType> g_jsToFwPolicyType_ = {
    {JsPolicyType::JS_PRIVACY, PolicyType::PRIVACY},
};

std::unordered_map<int32_t, std::function<napi_value(napi_env)>> g_sessionFactories = {
    {JsSceneMode::JS_CAPTURE, [] (napi_env env) {
        return PhotoSessionNapi::CreateCameraSession(env); }},
    {JsSceneMode::JS_VIDEO, [] (napi_env env) {
        return VideoSessionNapi::CreateCameraSession(env); }},
    {JsSceneMode::JS_SECURE_CAMERA, [] (napi_env env) {
        return SecureCameraSessionNapi::CreateCameraSession(env); }},
};

CameraManagerNapi::CameraManagerNapi() : env_(nullptr)
{
    CAMERA_SYNC_TRACE;
    CHECK_EXECUTE(CameraSecurity::CheckSystemApp(), {
        thread loadThread = thread([]() {CameraNapiExManager::GetCameraNapiExProxy();});
        loadThread.detach();
    });
}

CameraManagerNapi::~CameraManagerNapi()
{
    MEDIA_DEBUG_LOG("~CameraManagerNapi is called");
    CameraNapiExManager::FreeCameraNapiExProxy();
}

// Constructor callback
napi_value CameraManagerNapi::CameraManagerNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("CameraManagerNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<CameraManagerNapi> obj = std::make_unique<CameraManagerNapi>();
        obj->env_ = env;
        obj->cameraManager_ = CameraManager::GetInstance();
        CHECK_RETURN_RET_ELOG(obj->cameraManager_ == nullptr, result,
            "Failure wrapping js to native napi, obj->cameraManager_ null");
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                           CameraManagerNapi::CameraManagerNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("CameraManagerNapiConstructor call Failed!");
    return result;
}

void CameraManagerNapi::CameraManagerNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("CameraManagerNapiDestructor is called");
    CameraManagerNapi* camera = reinterpret_cast<CameraManagerNapi*>(nativeObject);
    if (camera != nullptr) {
        delete camera;
    }
}

napi_value CameraManagerNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;

    napi_property_descriptor camera_mgr_properties[] = {
        // CameraManager
        DECLARE_NAPI_FUNCTION("getSupportedCameras", GetSupportedCameras),
        DECLARE_NAPI_FUNCTION("getSupportedSceneModes", GetSupportedModes),
        DECLARE_NAPI_FUNCTION("getSupportedOutputCapability", GetSupportedOutputCapability),
        DECLARE_NAPI_FUNCTION("isCameraMuted", IsCameraMuted),
        DECLARE_NAPI_FUNCTION("isCameraMuteSupported", IsCameraMuteSupported),
        DECLARE_NAPI_FUNCTION("muteCamera", MuteCamera),
        DECLARE_NAPI_FUNCTION("muteCameraPersistent", MuteCameraPersist),
        DECLARE_NAPI_FUNCTION("prelaunch", PrelaunchCamera),
        DECLARE_NAPI_FUNCTION("resetRssPriority", ResetRssPriority),
        DECLARE_NAPI_FUNCTION("preSwitchCamera", PreSwitchCamera),
        DECLARE_NAPI_FUNCTION("isControlCenterActive", IsControlCenterActive),
        DECLARE_NAPI_FUNCTION("createControlCenterSession", CreateControlCenterSession),
        DECLARE_NAPI_FUNCTION("isPrelaunchSupported", IsPrelaunchSupported),
        DECLARE_NAPI_FUNCTION("setPrelaunchConfig", SetPrelaunchConfig),
        DECLARE_NAPI_FUNCTION("createCameraInput", CreateCameraInputInstance),
        DECLARE_NAPI_FUNCTION("createCaptureSession", CreateCameraSessionInstance),
        DECLARE_NAPI_FUNCTION("createSession", CreateSessionInstance),
        DECLARE_NAPI_FUNCTION("createPreviewOutput", CreatePreviewOutputInstance),
        DECLARE_NAPI_FUNCTION("createDeferredPreviewOutput", CreateDeferredPreviewOutputInstance),
        DECLARE_NAPI_FUNCTION("createPhotoOutput", CreatePhotoOutputInstance),
        DECLARE_NAPI_FUNCTION("createVideoOutput", CreateVideoOutputInstance),
        DECLARE_NAPI_FUNCTION("createMetadataOutput", CreateMetadataOutputInstance),
        DECLARE_NAPI_FUNCTION("createDepthDataOutput", CreateDepthDataOutputInstance),
        DECLARE_NAPI_FUNCTION("isTorchSupported", IsTorchSupported),
        DECLARE_NAPI_FUNCTION("isTorchModeSupported", IsTorchModeSupported),
        DECLARE_NAPI_FUNCTION("getTorchMode", GetTorchMode),
        DECLARE_NAPI_FUNCTION("setTorchMode", SetTorchMode),
        DECLARE_NAPI_FUNCTION("getCameraDevice", GetCameraDevice),
        DECLARE_NAPI_FUNCTION("getCameraDevices", GetCameraDevices),
        DECLARE_NAPI_FUNCTION("getCameraConcurrentInfos", GetCameraConcurrentInfos),
        DECLARE_NAPI_FUNCTION("getCameraStorageSize", GetCameraStorageSize),
        DECLARE_NAPI_FUNCTION("on", On),
        DECLARE_NAPI_FUNCTION("once", Once),
        DECLARE_NAPI_FUNCTION("off", Off)
    };

    status = napi_define_class(env, CAMERA_MANAGER_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               CameraManagerNapiConstructor, nullptr,
                               sizeof(camera_mgr_properties) / sizeof(camera_mgr_properties[PARAM0]),
                               camera_mgr_properties, &ctorObj);
    if (status == napi_ok) {
        if (NapiRefManager::CreateMemSafetyRef(env, ctorObj, &sConstructor_) == napi_ok) {
            status = napi_set_named_property(env, exports, CAMERA_MANAGER_NAPI_CLASS_NAME, ctorObj);
            CHECK_RETURN_RET(status == napi_ok, exports);
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

napi_value CameraManagerNapi::CreateCameraManager(napi_env env)
{
    MEDIA_INFO_LOG("CreateCameraManager is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value ctor;

    status = napi_get_reference_value(env, sConstructor_, &ctor);
    if (status == napi_ok) {
        status = napi_new_instance(env, ctor, 0, nullptr, &result);
        if (status == napi_ok) {
            MEDIA_INFO_LOG("CreateCameraManager is ok");
            return result;
        } else {
            MEDIA_ERR_LOG("New instance could not be obtained");
        }
    }
    napi_get_undefined(env, &result);
    MEDIA_ERR_LOG("CreateCameraManager call Failed!");
    return result;
}

static napi_value CreateCameraJSArray(napi_env env, std::vector<sptr<CameraDevice>> cameraObjList)
{
    MEDIA_DEBUG_LOG("CreateCameraJSArray is called");
    napi_value cameraArray = nullptr;

    CHECK_PRINT_ELOG(cameraObjList.empty(), "cameraObjList is empty");

    napi_status status = napi_create_array(env, &cameraArray);
    if (status == napi_ok) {
        for (size_t i = 0; i < cameraObjList.size(); i++) {
            if (cameraObjList[i] == nullptr) {
                continue;
            }
            napi_value camera = CameraNapiObjCameraDevice(*cameraObjList[i]).GenerateNapiValue(env);
            CHECK_RETURN_RET_ELOG(camera == nullptr || napi_set_element(env, cameraArray, i, camera) != napi_ok,
                nullptr, "Failed to create camera napi wrapper object");
        }
    }
    return cameraArray;
}

napi_value CameraManagerNapi::CreateCameraSessionInstance(napi_env env, napi_callback_info info)
{
    CAMERA_SYNC_TRACE;
    COMM_INFO_LOG("CreateCameraSessionInstance is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);

    CameraManagerNapi* cameraManagerNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraManagerNapi));
    CHECK_RETURN_RET_ELOG(status != napi_ok || cameraManagerNapi == nullptr, nullptr, "napi_unwrap failure!");
    if (CameraNapiSecurity::CheckSystemApp(env, false)) {
        auto cameraNapiExProxy = CameraNapiExManager::GetCameraNapiExProxy();
        CHECK_RETURN_RET_ELOG(cameraNapiExProxy == nullptr, result, "cameraNapiExProxy is nullptr");
        result = cameraNapiExProxy->CreateDeprecatedSessionForSys(env);
    } else {
        result = CameraSessionNapi::CreateCameraSession(env);
    }
    CHECK_PRINT_ELOG(result == nullptr, "CreateCameraSessionInstance failed");
    return result;
}

napi_value CameraManagerNapi::CreateSessionInstance(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("CreateSessionInstance is called");
    CameraManagerNapi* cameraManagerNapi = nullptr;
    int32_t jsModeName = -1;
    CameraNapiParamParser jsParamParser(env, info, cameraManagerNapi, jsModeName);
    CHECK_PRINT_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "Create session invalid argument!"),
        "CameraManagerNapi::CreateSessionInstance invalid argument: %{public}d", jsModeName);
    MEDIA_INFO_LOG("CameraManagerNapi::CreateSessionInstance mode = %{public}d", jsModeName);
    napi_value result = nullptr;
    if (CameraNapiSecurity::CheckSystemApp(env, false)) {
        auto cameraNapiExProxy = CameraNapiExManager::GetCameraNapiExProxy();
        CHECK_RETURN_RET_ELOG(cameraNapiExProxy == nullptr, result, "cameraNapiExProxy is nullptr");
        result = cameraNapiExProxy->CreateSessionForSys(env, jsModeName);
        if (result == nullptr) {
            MEDIA_ERR_LOG("CreateSessionForSys failed");
            CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "Invalid js mode");
        }
        return result;
    }
    if (g_sessionFactories.find(jsModeName) != g_sessionFactories.end()) {
        result = g_sessionFactories[jsModeName](env);
    } else {
        MEDIA_ERR_LOG("CameraManagerNapi::CreateSessionInstance mode = %{public}d not supported", jsModeName);
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "Invalid js mode");
    }
    return result;
}

bool ParsePrelaunchConfig(napi_env env, napi_value root, PrelaunchConfig* prelaunchConfig)
{
    napi_value res = nullptr;
    int32_t intValue;
    std::string cameraId {};
    CameraNapiObject cameraInfoObj { { { "cameraId", &cameraId } } };
    CameraNapiObject cameraDeviceObj { { { "cameraDevice", &cameraInfoObj } } };
    CameraNapiParamParser paramParser { env, { root }, cameraDeviceObj };
    CHECK_RETURN_RET_ELOG(!paramParser.AssertStatus(INVALID_ARGUMENT, "camera info is invalid."),
        false, "ParsePrelaunchConfig get camera device failure!");
    prelaunchConfig->cameraDevice_ = CameraManager::GetInstance()->GetCameraDeviceFromId(cameraId);
    CHECK_PRINT_ELOG(prelaunchConfig->cameraDevice_ == nullptr,
        "ParsePrelaunchConfig get camera device failure! cameraId:%{public}s", cameraId.c_str());
    if (napi_get_named_property(env, root, "restoreParamType", &res) == napi_ok) {
        napi_get_value_int32(env, res, &intValue);
        prelaunchConfig->restoreParamType = static_cast<RestoreParamType>(intValue);
        COMM_INFO_LOG("SetPrelaunchConfig restoreParamType = %{public}d", intValue);
    }

    if (napi_get_named_property(env, root, "activeTime", &res) == napi_ok) {
        napi_get_value_int32(env, res, &intValue);
        prelaunchConfig->activeTime = intValue;
        COMM_INFO_LOG("SetPrelaunchConfig activeTime = %{public}d", intValue);
    }
    return true;
}

bool ParseSettingParam(napi_env env, napi_value root, EffectParam* effectParam)
{
    napi_value res = nullptr;
    if (napi_get_named_property(env, root, "settingParam",  &res) == napi_ok) {
        napi_value tempValue = nullptr;
        int32_t effectValue;
        if (napi_get_named_property(env, res, "skinSmoothLevel", &tempValue) == napi_ok) {
            napi_get_value_int32(env, tempValue, &effectValue);
            effectParam->skinSmoothLevel = effectValue;
        }
        if (napi_get_named_property(env, res, "faceSlender", &tempValue) == napi_ok) {
            napi_get_value_int32(env, tempValue, &effectValue);
            effectParam->faceSlender = effectValue;
        }

        if (napi_get_named_property(env, res, "skinTone", &tempValue) == napi_ok) {
            napi_get_value_int32(env, tempValue, &effectValue);
            effectParam->skinTone = effectValue;
        }
        MEDIA_INFO_LOG("SetPrelaunchConfig effectParam = %{public}d", effectParam->skinSmoothLevel);
    }
    return true;
}

napi_value CameraManagerNapi::CreatePreviewOutputInstance(napi_env env, napi_callback_info info)
{
    COMM_INFO_LOG("CreatePreviewOutputInstance is called");
    std::string surfaceId;
    CameraManagerNapi* cameraManagerNapi = nullptr;
    size_t napiArgsSize = CameraNapiUtils::GetNapiArgs(env, info);
    MEDIA_INFO_LOG("CameraManagerNapi::CreatePreviewOutputInstance napi args size is %{public}zu", napiArgsSize);

    // Check two parameters
    if (napiArgsSize == 2) { // 2 parameters condition
        Profile profile;
        CameraNapiObject profileSizeObj {{
            { "width", &profile.size_.width },
            { "height", &profile.size_.height }
        }};
        CameraNapiObject profileNapiOjbect {{
            { "size", &profileSizeObj },
            { "format", reinterpret_cast<int32_t*>(&profile.format_) }
        }};
        CameraNapiParamParser jsParamParser(env, info, cameraManagerNapi, profileNapiOjbect, surfaceId);
        CHECK_RETURN_RET(!jsParamParser.AssertStatus(INVALID_ARGUMENT,
            "CameraManagerNapi::CreatePreviewOutputInstance 2 args parse error"), nullptr);
        COMM_INFO_LOG("CameraManagerNapi::CreatePreviewOutputInstance ParseProfile "
                       "size.width = %{public}d, size.height = %{public}d, format = %{public}d, surfaceId = %{public}s",
            profile.size_.width, profile.size_.height, profile.format_, surfaceId.c_str());
        return PreviewOutputNapi::CreatePreviewOutput(env, profile, surfaceId);
    }

    // Check one parameters
    CameraNapiParamParser jsParamParser = CameraNapiParamParser(env, info, cameraManagerNapi, surfaceId);
    CHECK_RETURN_RET(!jsParamParser.AssertStatus(INVALID_ARGUMENT,
        "CameraManagerNapi::CreatePreviewOutputInstance 1 args parse error"), nullptr);
    MEDIA_INFO_LOG("CameraManagerNapi::CreatePreviewOutputInstance surfaceId : %{public}s", surfaceId.c_str());
    return PreviewOutputNapi::CreatePreviewOutput(env, surfaceId);
}

napi_value CameraManagerNapi::CreateDeferredPreviewOutputInstance(napi_env env, napi_callback_info info)
{
    COMM_INFO_LOG("CreateDeferredPreviewOutputInstance is called");
    CHECK_RETURN_RET_ELOG(!CameraNapiSecurity::CheckSystemApp(env), nullptr,
        "SystemApi CreateDeferredPreviewOutputInstance is called!");

    CameraManagerNapi* cameraManagerNapi = nullptr;
    Profile profile;
    CameraNapiObject profileSizeObj {{
        { "width", &profile.size_.width },
        { "height", &profile.size_.height }
    }};
    CameraNapiObject profileNapiOjbect {{
        { "size", &profileSizeObj },
        { "format", reinterpret_cast<int32_t*>(&profile.format_) }
    }};

    CameraNapiParamParser jsParamParser(env, info, cameraManagerNapi, profileNapiOjbect);
    CHECK_RETURN_RET(!jsParamParser.AssertStatus(INVALID_ARGUMENT,
        "CameraManagerNapi::CreateDeferredPreviewOutput args parse error"), nullptr);
    MEDIA_INFO_LOG("CameraManagerNapi::CreateDeferredPreviewOutput ParseProfile "
                   "size.width = %{public}d, size.height = %{public}d, format = %{public}d",
        profile.size_.width, profile.size_.height, profile.format_);
    return PreviewOutputNapi::CreateDeferredPreviewOutput(env, profile);
}

napi_value CameraManagerNapi::CreatePhotoOutputInstance(napi_env env, napi_callback_info info)
{
    COMM_INFO_LOG("CreatePhotoOutputInstance is called");
    std::string surfaceId;
    CameraManagerNapi* cameraManagerNapi = nullptr;
    size_t napiArgsSize = CameraNapiUtils::GetNapiArgs(env, info);
    MEDIA_INFO_LOG("CameraManagerNapi::CreatePhotoOutputInstance napi args size is %{public}zu", napiArgsSize);

    Profile profile;
    CameraNapiObject profileSizeObj {{
        { "width", &profile.size_.width },
        { "height", &profile.size_.height }
    }};
    CameraNapiObject profileNapiOjbect {{
        { "size", &profileSizeObj },
        { "format", reinterpret_cast<int32_t*>(&profile.format_) }
    }};

    if (napiArgsSize == 2) { // 2 parameters condition
        CHECK_RETURN_RET(!CameraNapiParamParser(env, info, cameraManagerNapi,
            profileNapiOjbect, surfaceId).AssertStatus(INVALID_ARGUMENT,
            "CameraManagerNapi::CreatePhotoOutputInstance 2 args parse error"), nullptr);
        COMM_INFO_LOG("CameraManagerNapi::CreatePhotoOutputInstance ParseProfile "
                       "size.width = %{public}d, size.height = %{public}d, format = %{public}d, surfaceId = %{public}s",
            profile.size_.width, profile.size_.height, profile.format_, surfaceId.c_str());
        return PhotoOutputNapi::CreatePhotoOutput(env, profile, surfaceId);
    } else if (napiArgsSize == 1) { // 1 parameters condition
        // Check one parameter only profile
        if (CameraNapiParamParser(env, info, cameraManagerNapi, profileNapiOjbect).IsStatusOk()) {
            COMM_INFO_LOG(
                "CameraManagerNapi::CreatePhotoOutputInstance ParseProfile "
                "size.width = %{public}d, size.height = %{public}d, format = %{public}d, surfaceId = %{public}s",
                profile.size_.width, profile.size_.height, profile.format_, surfaceId.c_str());
            return PhotoOutputNapi::CreatePhotoOutput(env, profile, "");
        }

        // Check one parameter only surfaceId
        CHECK_RETURN_RET(!CameraNapiParamParser(env, info, cameraManagerNapi, surfaceId).AssertStatus(
            INVALID_ARGUMENT, "CameraManagerNapi::CreatePhotoOutputInstance 1 args parse error"), nullptr);
        MEDIA_INFO_LOG("CameraManagerNapi::CreatePhotoOutputInstance surfaceId : %{public}s", surfaceId.c_str());
        return PhotoOutputNapi::CreatePhotoOutput(env, surfaceId);
    }

    MEDIA_WARNING_LOG("CameraManagerNapi::CreatePhotoOutputInstance with none parameter");
    // Check none parameter
    CHECK_RETURN_RET(!CameraNapiParamParser(env, info, cameraManagerNapi).AssertStatus(INVALID_ARGUMENT,
        "CameraManagerNapi::CreatePhotoOutputInstance args parse error"), nullptr);
    return PhotoOutputNapi::CreatePhotoOutput(env, "");
}

napi_value CameraManagerNapi::CreateVideoOutputInstance(napi_env env, napi_callback_info info)
{
    COMM_INFO_LOG("CreateVideoOutputInstance is called");
    std::string surfaceId;
    CameraManagerNapi* cameraManagerNapi = nullptr;
    size_t napiArgsSize = CameraNapiUtils::GetNapiArgs(env, info);
    MEDIA_INFO_LOG("CameraManagerNapi::CreateVideoOutputInstance napi args size is %{public}zu", napiArgsSize);

    if (napiArgsSize == 2) { // 2 parameters condition
        VideoProfile videoProfile;
        videoProfile.framerates_.resize(2); // framerate size is 2
        CameraNapiObject profileSizeObj {{
            { "width", &videoProfile.size_.width },
            { "height", &videoProfile.size_.height }
        }};
        CameraNapiObject profileFrameRateObj {{
            { "min", &videoProfile.framerates_[0] },
            { "max", &videoProfile.framerates_[1] }
        }};
        CameraNapiObject profileNapiOjbect {{
            { "size", &profileSizeObj },
            { "frameRateRange", &profileFrameRateObj },
            { "format", reinterpret_cast<int32_t*>(&videoProfile.format_) }
        }};

        CHECK_RETURN_RET(!CameraNapiParamParser(env, info, cameraManagerNapi, profileNapiOjbect, surfaceId)
            .AssertStatus(INVALID_ARGUMENT, "CameraManagerNapi::CreateVideoOutputInstance 2 args parse error"),
            nullptr);
        MEDIA_INFO_LOG(
            "CameraManagerNapi::CreateVideoOutputInstance ParseVideoProfile "
            "size.width = %{public}d, size.height = %{public}d, format = %{public}d, frameRateMin = %{public}d, "
            "frameRateMax = %{public}d, surfaceId = %{public}s",
            videoProfile.size_.width, videoProfile.size_.height, videoProfile.format_, videoProfile.framerates_[0],
            videoProfile.framerates_[1], surfaceId.c_str());
        return VideoOutputNapi::CreateVideoOutput(env, videoProfile, surfaceId);
    }

    MEDIA_WARNING_LOG("CameraManagerNapi::CreateVideoOutputInstance with only surfaceId");
    // Check one parameters only surfaceId
    CHECK_RETURN_RET(!CameraNapiParamParser(env, info, cameraManagerNapi, surfaceId).AssertStatus(
        INVALID_ARGUMENT, "CameraManagerNapi::CreateVideoOutputInstance args parse error"), nullptr);
    MEDIA_INFO_LOG("CameraManagerNapi::CreateVideoOutputInstance surfaceId : %{public}s", surfaceId.c_str());
    return VideoOutputNapi::CreateVideoOutput(env, surfaceId);
}

napi_value CameraManagerNapi::CreateDepthDataOutputInstance(napi_env env, napi_callback_info info)
{
    COMM_INFO_LOG("CreateDepthDataOutputInstance is called");
    CHECK_RETURN_RET_ELOG(!CameraNapiSecurity::CheckSystemApp(env), nullptr,
        "SystemApi CreateDepthDataOutputInstance is called!");
    CameraManagerNapi* cameraManagerNapi = nullptr;
    size_t napiArgsSize = CameraNapiUtils::GetNapiArgs(env, info);
    MEDIA_INFO_LOG("CameraManagerNapi::CreateDepthDataOutputInstance napi args size is %{public}zu", napiArgsSize);

    DepthProfile depthProfile;
    CameraNapiObject profileSizeObj {{
        { "width", &depthProfile.size_.width },
        { "height", &depthProfile.size_.height }
    }};
    CameraNapiObject profileNapiOjbect {{
        { "size", &profileSizeObj },
        { "dataAccuracy", reinterpret_cast<int32_t*>(&depthProfile.dataAccuracy_) },
        { "format", reinterpret_cast<int32_t*>(&depthProfile.format_) }
    }};

    CHECK_RETURN_RET(!CameraNapiParamParser(env, info, cameraManagerNapi, profileNapiOjbect).AssertStatus(
        INVALID_ARGUMENT, "CameraManagerNapi::CreateDepthDataOutputInstance 1 args parse error"), nullptr);
    MEDIA_INFO_LOG(
        "CameraManagerNapi::CreateDepthDataOutputInstance ParseDepthProfile "
        "size.width = %{public}d, size.height = %{public}d, format = %{public}d, dataAccuracy = %{public}d,",
        depthProfile.size_.width, depthProfile.size_.height, depthProfile.format_, depthProfile.dataAccuracy_);
    auto cameraNapiExProxy = CameraNapiExManager::GetCameraNapiExProxy();
    CHECK_RETURN_RET_ELOG(cameraNapiExProxy == nullptr, nullptr, "cameraNapiExProxy is nullptr");
    return cameraNapiExProxy->CreateDepthDataOutput(env, depthProfile);
}

napi_value CameraManagerNapi::CreateMetadataOutputInstance(napi_env env, napi_callback_info info)
{
    COMM_INFO_LOG("CreateMetadataOutputInstance is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    CHECK_RETURN_RET(!CameraNapiUtils::CheckInvalidArgument(env, argc, ARGS_ONE,
        argv, CREATE_METADATA_OUTPUT_INSTANCE), result);

    napi_get_undefined(env, &result);
    CameraManagerNapi* cameraManagerNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraManagerNapi));
    CHECK_RETURN_RET_ELOG(status != napi_ok || cameraManagerNapi == nullptr, nullptr, "napi_unwrap failure!");
    std::vector<MetadataObjectType> metadataObjectTypes;
    CameraNapiUtils::ParseMetadataObjectTypes(env, argv[PARAM0], metadataObjectTypes);
    result = MetadataOutputNapi::CreateMetadataOutput(env, metadataObjectTypes);
    return result;
}

napi_value CameraManagerNapi::GetSupportedCameras(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("GetSupportedCameras is called");
    CameraManagerNapi* cameraManagerNapi;
    CameraNapiParamParser paramParser(env, info, cameraManagerNapi);
    CHECK_RETURN_RET_ELOG(!paramParser.AssertStatus(INVALID_ARGUMENT, "invalid argument."), nullptr,
        "CameraManagerNapi::GetSupportedCameras invalid argument");
    std::vector<sptr<CameraDevice>> cameraObjList = cameraManagerNapi->cameraManager_->GetSupportedCameras();
    napi_value result = GetCachedSupportedCameras(env, cameraObjList);
    if (result == nullptr) {
        result = CreateCameraJSArray(env, cameraObjList);
        CacheSupportedCameras(env, cameraObjList, result);
    }
    MEDIA_DEBUG_LOG("CameraManagerNapi::GetSupportedCameras size=[%{public}zu]", cameraObjList.size());
    return result;
}

napi_value CameraManagerNapi::GetCameraDevice(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("GetCameraDevice is called");
    CameraManagerNapi* cameraManagerNapi;
    int32_t cameraPosition = 0;
    int32_t cameraType = 0;
    sptr<CameraDevice> cameraInfo = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraManagerNapi, cameraPosition, cameraType);
    if (!jsParamParser.AssertStatus(PARAMETER_ERROR, "GetCameraDevice with 2 invalid arguments!")) {
            MEDIA_ERR_LOG("CameraManagerNapi::GetCameraDevice 2 invalid arguments");
            return nullptr;
    }
    ProcessCameraInfo(cameraManagerNapi->cameraManager_, static_cast<const CameraPosition>(cameraPosition),
        static_cast<const CameraType>(cameraType), cameraInfo);
    if (cameraInfo == nullptr) {
        MEDIA_ERR_LOG("cameraInfo is null");
        CameraNapiUtils::ThrowError(env, SERVICE_FATL_ERROR, "cameraInfo is null.");
        return nullptr;
    }
    napi_value result = nullptr;
    result = CameraNapiObjCameraDevice(*cameraInfo).GenerateNapiValue(env);
    return result;
}

napi_value CameraManagerNapi::GetCameraDevices(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("GetCameraDevices is called");
    CameraManagerNapi* cameraManagerNapi = nullptr;
    int32_t cameraPosition = 0;
    napi_value typesValue = nullptr;
    int32_t connectionType = 0;

    CameraNapiParamParser jsParamParser(env, info, cameraManagerNapi, cameraPosition, typesValue, connectionType);
    if (!jsParamParser.AssertStatus(PARAMETER_ERROR, "GetCameraDevices with 3 invalid arguments!")) {
        MEDIA_ERR_LOG("CameraManagerNapi::GetCameraDevices invalid arguments");
        return nullptr;
    }

    if (cameraManagerNapi == nullptr || cameraManagerNapi->cameraManager_ == nullptr) {
        MEDIA_ERR_LOG("CameraManagerNapi::GetCameraDevices cameraManager is null");
        CameraNapiUtils::ThrowError(env, SERVICE_FATL_ERROR, "Camera manager is null.");
        return nullptr;
    }

    std::vector<CameraType> cameraTypes;
    if (!CameraNapiUtils::ParseCameraTypesArray(env, typesValue, cameraTypes)) {
        MEDIA_ERR_LOG("CameraManagerNapi::GetCameraDevices ParseCameraTypesArray failed");
        return nullptr;
    }

    std::vector<sptr<CameraDevice>> cameraDeviceList;
    ProcessCameraDevices(cameraManagerNapi->cameraManager_, static_cast<CameraPosition>(cameraPosition), cameraTypes,
        static_cast<ConnectionType>(connectionType), cameraDeviceList);

    if (cameraDeviceList.empty()) {
        MEDIA_ERR_LOG("CameraManagerNapi::GetCameraDevices no camera devices found with parameters: "
            "position=%{public}d, connectionType=%{public}d, cameraTypes count=%{public}zu", cameraPosition,
            connectionType, cameraTypes.size());
        CameraNapiUtils::ThrowError(env, SERVICE_FATL_ERROR, "cameraDeviceList is null.");
        return nullptr;
    } else {
        MEDIA_DEBUG_LOG("CameraManagerNapi::GetCameraDevices found %{public}zu camera devices",
            cameraDeviceList.size());
    }

    napi_value result = nullptr;
    napi_create_array_with_length(env, cameraDeviceList.size(), &result);
    for (size_t i = 0; i < cameraDeviceList.size(); ++i) {
        if (cameraDeviceList[i] == nullptr) {
            MEDIA_ERR_LOG("CameraManagerNapi::GetCameraDevices camera device at index %{public}zu is null", i);
            continue;
        }
        napi_value jsDevice = CameraNapiObjCameraDevice(*cameraDeviceList[i]).GenerateNapiValue(env);
        napi_set_element(env, result, i, jsDevice);
    }
    return result;
}

napi_value CameraManagerNapi::GetCameraConcurrentInfos(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("GetCameraConcurrentInfos is called");
    CameraManagerNapi* cameraManagerNapi;
    std::vector<bool> cameraConcurrentType = {};
    std::vector<std::vector<SceneMode>> modes = {};
    std::vector<std::vector<sptr<CameraOutputCapability>>> outputCapabilities = {};
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    napi_status status;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraManagerNapi));
    if (status != napi_ok) {
        CameraNapiUtils::ThrowError(env, PARAMETER_ERROR,
            "CameraManagerNapi::GetCameraConcurrentInfos can not get thisVar");
        return nullptr;
    }
    if (argc != ARGS_ONE) {
        CameraNapiUtils::ThrowError(env, PARAMETER_ERROR,
            "CameraManagerNapi::GetCameraConcurrentInfos argc is not ARGS_ONE");
        return nullptr;
    }
    napi_valuetype argvType;
    napi_typeof(env, argv[PARAM0], &argvType);
    if (argvType != napi_object) {
        CameraNapiUtils::ThrowError(env, PARAMETER_ERROR,
            "CameraManagerNapi::GetCameraConcurrentInfos type of array is error");
        return nullptr;
    }

    std::vector<string>cameraIdv = {};
    vector<sptr<CameraDevice>> cameraReturnNull = {};
    cameraManagerNapi->ParseGetCameraConcurrentInfos(env, argv[PARAM0], cameraIdv);
    CHECK_RETURN_RET_ELOG(cameraIdv.size() == 0,
        CreateCameraConcurrentResult(env, cameraReturnNull, cameraConcurrentType, modes, outputCapabilities),
        "CameraManagerNapi::GetCameraConcurrentInfos ParseGetCameraConcurrentInfos cameraid size is null");
    vector<sptr<CameraDevice>> cameraDeviceArrray = {};
    for (auto cameraidonly : cameraIdv) {
        CHECK_RETURN_RET_ELOG(cameraidonly.empty(),
            CreateCameraConcurrentResult(env, cameraReturnNull, cameraConcurrentType, modes, outputCapabilities),
            "CameraManagerNapi::GetCameraConcurrentInfos ParseGetCameraConcurrentInfos cameraid is null");
        auto getCameraDev = cameraManagerNapi->cameraManager_->GetCameraDeviceFromId(cameraidonly);
        CHECK_RETURN_RET_ELOG(getCameraDev == nullptr,
            CreateCameraConcurrentResult(env, cameraReturnNull, cameraConcurrentType, modes, outputCapabilities),
            "CameraManagerNapi::GetCameraConcurrentInfos GetCameraDeviceFromId get cameraid is null");
        cameraDeviceArrray.push_back(getCameraDev);
    }
   
    bool issupported = cameraManagerNapi->cameraManager_->GetConcurrentType(cameraDeviceArrray, cameraConcurrentType);
    if (issupported == false) {
        MEDIA_ERR_LOG("CameraManagerNapi::Camera is not support ConcurrentType");
        return CreateCameraConcurrentResult(env, cameraReturnNull, cameraConcurrentType, modes, outputCapabilities);
    }
    issupported = cameraManagerNapi->cameraManager_->CheckConcurrentExecution(cameraDeviceArrray);
    if (issupported == false) {
        MEDIA_ERR_LOG("CameraManagerNapi::Camera is not support ConcurrentType");
        return CreateCameraConcurrentResult(env, cameraReturnNull, cameraConcurrentType, modes, outputCapabilities);
    }

    cameraManagerNapi->cameraManager_->GetCameraConcurrentInfos(cameraDeviceArrray,
        cameraConcurrentType, modes, outputCapabilities);
    return CreateCameraConcurrentResult(env, cameraDeviceArrray, cameraConcurrentType, modes, outputCapabilities);
}

void CameraManagerNapi::ParseGetCameraConcurrentInfos(napi_env env, napi_value arrayParam,
    std::vector<std::string> &cameraIdv)
{
    MEDIA_DEBUG_LOG("ParseGetCameraConcurrentInfos is called");
    uint32_t length = 0;
    napi_value value;
    napi_get_array_length(env, arrayParam, &length);
    for (uint32_t i = 0; i < length; i++) {
        napi_get_element(env, arrayParam, i, &value);
        napi_value res = nullptr;
        if (napi_get_named_property(env, value, "cameraId", &res) == napi_ok) {
            size_t sizeofres;
            char buffer[PATH_MAX];
            napi_get_value_string_utf8(env, res, buffer, PATH_MAX, &sizeofres);
            std::string cameraidonly = std::string(buffer);
            cameraIdv.push_back(cameraidonly);
        }
    }
}

napi_value CameraManagerNapi::GetCameraStorageSize(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("GetCameraStorageSize is called");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi GetCameraStorageSize is called!");
        return nullptr;
    }
    std::unique_ptr<CameraManagerAsyncContext> asyncContext = std::make_unique<CameraManagerAsyncContext>(
        "CameraManagerNapi::GetCameraStorageSize", CameraNapiUtils::IncrementAndGet(cameraManagerTaskId));
    auto asyncFunction =
        std::make_shared<CameraNapiAsyncFunction>(env, "GetCameraStorageSize", asyncContext->callbackRef,
            asyncContext->deferred);
    CameraNapiParamParser jsParamParser(env, info, asyncContext->objectInfo, asyncFunction);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
        MEDIA_ERR_LOG("CameraManagerNapi::GetCameraStorageSize invalid argument");
        return nullptr;
    }
    asyncContext->HoldNapiValue(env, jsParamParser.GetThisVar());
    napi_status status = napi_create_async_work(
        env, nullptr, asyncFunction->GetResourceName(),
        [](napi_env env, void* data) {
            MEDIA_INFO_LOG("CameraManagerNapi::GetCameraStorageSize running on worker");
            auto context = static_cast<CameraManagerAsyncContext*>(data);
            CHECK_RETURN_ELOG(context->objectInfo == nullptr,
                "CameraManagerNapi::GetCameraStorageSize async info is nullptr");
            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(context->queueTask, [&context]() {
                int64_t storageSize = 0;
                context->errorCode = context->objectInfo->cameraManager_->GetCameraStorageSize(storageSize);
                context->status = context->errorCode == CameraErrorCode::SUCCESS;
                context->storageSize = storageSize;
            });
        },
        AsyncCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for PreviewOutputNapi::Release");
        asyncFunction->Reset();
    } else {
        asyncContext->queueTask =
            CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("PreviewOutputNapi::Release");
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        asyncContext.release();
    }
    if (asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE) {
        return asyncFunction->GetPromise();
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value CameraManagerNapi::CreateCameraConcurrentResult(napi_env env, vector<sptr<CameraDevice>> &cameraDeviceArrray,
    std::vector<bool> &cameraConcurrentType, std::vector<std::vector<SceneMode>> &modes,
    std::vector<std::vector<sptr<CameraOutputCapability>>> &outputCapabilities)
{
    napi_value resjsArray = nullptr;
    napi_status resjsArraystatus = napi_create_array(env, &resjsArray);
    if (resjsArraystatus != napi_ok) {
        MEDIA_ERR_LOG("resjsArray create is fail");
        return nullptr;
    }
    for (size_t i = 0; i < cameraDeviceArrray.size(); i++) {
        napi_value obj = nullptr;
        napi_create_object(env, &obj);
        napi_value cameranow = CameraNapiObjCameraDevice(*cameraDeviceArrray[i]).GenerateNapiValue(env);
        napi_set_named_property(env, obj, "device", cameranow);
        napi_value cameraconcurrent = nullptr;
        napi_get_boolean(env, cameraConcurrentType[i], &cameraconcurrent);
        napi_set_named_property(env, obj, "type", cameraconcurrent);
        napi_value scenemodearray = nullptr;
        napi_status scenemodearraystatus = napi_create_array(env, &scenemodearray);
        if (scenemodearraystatus != napi_ok) {
            MEDIA_ERR_LOG("scenemodearray create is fail");
            continue;
        }
        int32_t index = 0;
        for (auto modenow : modes[i]) {
            auto itr = g_nativeToNapiSupportedMode_.find(modenow);
            if (itr != g_nativeToNapiSupportedMode_.end()) {
                napi_value modeitem = nullptr;
                napi_create_int32(env, itr->second, &modeitem);
                napi_set_element(env, scenemodearray, index, modeitem);
                index++;
            }
        }
        napi_set_named_property(env, obj, "modes", scenemodearray);
        napi_value outputcapabilitiyarray = nullptr;
        napi_status status = napi_create_array(env, &outputcapabilitiyarray);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("outputcapabilitiyarray create is fail");
            continue;
        }
        index = 0;
        for (auto outputCapability : outputCapabilities[i]) {
            napi_value outputcapability = CameraNapiObjCameraOutputCapability(*outputCapability).GenerateNapiValue(env);
            napi_set_element(env, outputcapabilitiyarray, index, outputcapability);
            index++;
        }
        napi_set_named_property(env, obj, "outputCapabilities", outputcapabilitiyarray);
        napi_set_element(env, resjsArray, i, obj);
    }
    return resjsArray;
}

static napi_value CreateSceneModeJSArray(napi_env env, std::vector<SceneMode>& nativeArray)
{
    MEDIA_DEBUG_LOG("CreateSceneModeJSArray is called");
    napi_value jsArray = nullptr;
    napi_value item = nullptr;

    CHECK_PRINT_ELOG(nativeArray.empty(), "nativeArray is empty");

    napi_status status = napi_create_array(env, &jsArray);
    std::unordered_map<SceneMode, JsSceneMode> nativeToNapiMap = g_nativeToNapiSupportedMode_;
    if (CameraNapiSecurity::CheckSystemApp(env, false)) {
        nativeToNapiMap = g_nativeToNapiSupportedModeForSystem_;
    }
    if (status == napi_ok) {
        uint8_t index = 0;
        for (size_t i = 0; i < nativeArray.size(); i++) {
            auto itr = nativeToNapiMap.find(nativeArray[i]);
            if (itr != nativeToNapiMap.end()) {
                napi_create_int32(env, itr->second, &item);
                napi_set_element(env, jsArray, index, item);
                index++;
            }
        }
    }
    return jsArray;
}

napi_value CameraManagerNapi::GetSupportedModes(napi_env env, napi_callback_info info)
{
    COMM_INFO_LOG("GetSupportedModes is called");
    CameraManagerNapi* cameraManagerNapi = nullptr;
    std::string cameraId {};
    CameraNapiObject cameraInfoObj { { { "cameraId", &cameraId } } };
    CHECK_RETURN_RET(!CameraNapiParamParser(env, info, cameraManagerNapi, cameraInfoObj).AssertStatus(
        INVALID_ARGUMENT, "GetSupportedModes args parse error"), nullptr);
    sptr<CameraDevice> cameraInfo = cameraManagerNapi->cameraManager_->GetCameraDeviceFromId(cameraId);
    if (cameraInfo == nullptr) {
        MEDIA_ERR_LOG("CameraManagerNapi::GetSupportedModes get camera info fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "Get camera info fail");
        return nullptr;
    }

    std::vector<SceneMode> modeObjList = cameraManagerNapi->cameraManager_->GetSupportedModes(cameraInfo);
    for (auto it = modeObjList.begin(); it != modeObjList.end(); it++) {
        if (*it == SCAN) {
            modeObjList.erase(it);
            break;
        }
    }
    if (modeObjList.empty()) {
        modeObjList.emplace_back(CAPTURE);
        modeObjList.emplace_back(VIDEO);
    }
    COMM_INFO_LOG("CameraManagerNapi::GetSupportedModes size=[%{public}zu]", modeObjList.size());
    return CreateSceneModeJSArray(env, modeObjList);
}

void CameraManagerNapi::GetSupportedOutputCapabilityAdaptNormalMode(
    SceneMode fwkMode, sptr<CameraDevice>& cameraInfo, sptr<CameraOutputCapability>& outputCapability)
{
    if (fwkMode == SceneMode::NORMAL && cameraInfo->GetPosition() == CAMERA_POSITION_FRONT) {
        auto defaultVideoProfiles = cameraInfo->modeVideoProfiles_[SceneMode::NORMAL];
        if (!defaultVideoProfiles.empty()) {
            MEDIA_INFO_LOG("return align videoProfile size = %{public}zu", defaultVideoProfiles.size());
            outputCapability->SetVideoProfiles(defaultVideoProfiles);
        }
    }
}

sptr<CameraDevice> CameraManagerNapi::GetSupportedOutputCapabilityGetCameraInfo(
    napi_env env, napi_callback_info info, CameraManagerNapi*& cameraManagerNapi, int32_t& jsSceneMode)
{
    std::string cameraId {};
    CameraNapiObject cameraInfoObj { { { "cameraId", &cameraId } } };
    size_t napiArgsSize = CameraNapiUtils::GetNapiArgs(env, info);
    MEDIA_INFO_LOG("CameraManagerNapi::GetSupportedOutputCapability napi args size is %{public}zu", napiArgsSize);
    if (napiArgsSize == ARGS_ONE) {
        CHECK_RETURN_RET(!CameraNapiParamParser(env, info, cameraManagerNapi, cameraInfoObj)
            .AssertStatus(INVALID_ARGUMENT, "GetSupportedOutputCapability 1 args parse error"), nullptr);
    } else if (napiArgsSize == ARGS_TWO) {
        CHECK_RETURN_RET(!CameraNapiParamParser(env, info, cameraManagerNapi, cameraInfoObj, jsSceneMode)
            .AssertStatus(INVALID_ARGUMENT, "GetSupportedOutputCapability 2 args parse error"), nullptr);
        if (jsSceneMode == JsSceneMode::JS_NORMAL) {
            CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "invalid js mode");
            return nullptr;
        }
    } else {
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "Args size error");
        return nullptr;
    }
    if (cameraManagerNapi == nullptr) {
        MEDIA_ERR_LOG("cameraManagerNapi is null");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "cameraManagerNapi is null");
        return nullptr;
    }
    return cameraManagerNapi->cameraManager_->GetCameraDeviceFromId(cameraId);
}

napi_value CameraManagerNapi::GetSupportedOutputCapability(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("GetSupportedOutputCapability is called");
    CameraManagerNapi* cameraManagerNapi = nullptr;
    int32_t jsSceneMode = JsSceneMode::JS_NORMAL;
    sptr<CameraDevice> cameraInfo =
        GetSupportedOutputCapabilityGetCameraInfo(env, info, cameraManagerNapi, jsSceneMode);

    if (cameraInfo == nullptr) {
        MEDIA_ERR_LOG("CameraManagerNapi::GetSupportedOutputCapability get camera info fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "Get camera info fail");
        return nullptr;
    }
    std::string cameraId = cameraInfo->GetID();
    auto foldType = cameraManagerNapi->cameraManager_->GetFoldScreenType();
    if (!(!foldType.empty() && foldType[0] == '4')) {
        napi_value cachedResult = GetCachedSupportedOutputCapability(env, cameraId, jsSceneMode);
        CHECK_RETURN_RET(cachedResult != nullptr, cachedResult);
    }
    SceneMode fwkMode = SceneMode::NORMAL;
    std::unordered_map<JsSceneMode, SceneMode> jsToFwModeMap = g_jsToFwMode_;
    if (CameraNapiSecurity::CheckSystemApp(env, false)) {
        jsToFwModeMap = g_jsToFwMode4Sys_;
    }
    auto itr = jsToFwModeMap.find(static_cast<JsSceneMode>(jsSceneMode));
    if (itr != jsToFwModeMap.end()) {
        fwkMode = itr->second;
    } else {
        MEDIA_ERR_LOG("CreateCameraSessionInstance mode = %{public}d not supported", jsSceneMode);
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "Not support the input mode");
        return nullptr;
    }
    auto outputCapability = cameraManagerNapi->cameraManager_->GetSupportedOutputCapability(cameraInfo, fwkMode);
    CHECK_RETURN_RET_ELOG(outputCapability == nullptr, nullptr, "failed to create CreateCameraOutputCapability");
    outputCapability->RemoveDuplicatesProfiles();
    GetSupportedOutputCapabilityAdaptNormalMode(fwkMode, cameraInfo, outputCapability);
    napi_value result = CameraNapiObjCameraOutputCapability(*outputCapability).GenerateNapiValue(env);
    CHECK_EXECUTE(cameraInfo->GetConnectionType() == CAMERA_CONNECTION_BUILT_IN,
        CacheSupportedOutputCapability(env, cameraId, jsSceneMode, result));
    return result;
}

napi_value CameraManagerNapi::IsCameraMuted(napi_env env, napi_callback_info info)
{
    CAMERA_SYNC_TRACE;
    COMM_INFO_LOG("IsCameraMuted is called");
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_ONE, "requires 1 parameters maximum");
    bool isMuted = CameraManager::GetInstance()->IsCameraMuted();
    MEDIA_DEBUG_LOG("IsCameraMuted : %{public}d", isMuted);
    napi_get_boolean(env, isMuted, &result);
    return result;
}

napi_value CameraManagerNapi::IsCameraMuteSupported(napi_env env, napi_callback_info info)
{
    CHECK_RETURN_RET_ELOG(!CameraNapiSecurity::CheckSystemApp(env), nullptr,
        "SystemApi IsCameraMuteSupported is called!");
    COMM_INFO_LOG("IsCameraMuteSupported is called");
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_ONE, "requires 1 parameters maximum");

    bool isMuteSupported = CameraManager::GetInstance()->IsCameraMuteSupported();
    MEDIA_DEBUG_LOG("isMuteSupported: %{public}d", isMuteSupported);
    napi_get_boolean(env, isMuteSupported, &result);
    return result;
}

napi_value CameraManagerNapi::MuteCamera(napi_env env, napi_callback_info info)
{
    CHECK_RETURN_RET_ELOG(!CameraNapiSecurity::CheckSystemApp(env), nullptr, "SystemApi MuteCamera is called!");
    COMM_INFO_LOG("MuteCamera is called");
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_TWO, "requires 1 parameters maximum");
    bool isSupported;
    napi_get_value_bool(env, argv[PARAM0], &isSupported);
    CameraManager::GetInstance()->MuteCamera(isSupported);
    napi_get_undefined(env, &result);
    return result;
}

napi_value CameraManagerNapi::MuteCameraPersist(napi_env env, napi_callback_info info)
{
    CHECK_RETURN_RET_ELOG(!CameraNapiSecurity::CheckSystemApp(env), nullptr,
        "SystemApi MuteCameraPersist is called!");
    MEDIA_INFO_LOG("MuteCamera is called");
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc == ARGS_TWO, "requires 2 parameters");
    bool muteMode;
    int32_t jsPolicyType;
    napi_get_value_bool(env, argv[PARAM0], &muteMode);
    napi_get_value_int32(env, argv[PARAM1], &jsPolicyType);
    NAPI_ASSERT(env, g_jsToFwPolicyType_.count(static_cast<JsPolicyType>(jsPolicyType)) != 0,
        "invalid policyType value");
    CameraManager::GetInstance()->MuteCameraPersist(g_jsToFwPolicyType_[static_cast<JsPolicyType>(jsPolicyType)],
        muteMode);
    napi_get_undefined(env, &result);
    return result;
}

napi_value CameraManagerNapi::CreateCameraInputInstance(napi_env env, napi_callback_info info)
{
    COMM_INFO_LOG("CreateCameraInputInstance is called");
    CameraManagerNapi* cameraManagerNapi = nullptr;
    size_t argSize = CameraNapiUtils::GetNapiArgs(env, info);
    sptr<CameraDevice> cameraInfo = nullptr;
    if (argSize == ARGS_ONE) {
        std::string cameraId {};
        CameraNapiObject cameraInfoObj { { { "cameraId", &cameraId } } };
        CameraNapiParamParser jsParamParser(env, info, cameraManagerNapi, cameraInfoObj);
        CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT,
            "Create cameraInput invalid argument!"), nullptr,
            "CameraManagerNapi::CreateCameraInputInstance invalid argument");
        cameraInfo = cameraManagerNapi->cameraManager_->GetCameraDeviceFromId(cameraId);
    } else if (argSize == ARGS_TWO) {
        int32_t cameraPosition = 0;
        int32_t cameraType = 0;
        CameraNapiParamParser jsParamParser(env, info, cameraManagerNapi, cameraPosition, cameraType);
        CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT,
            "Create cameraInput with 2 invalid arguments!"), nullptr,
            "CameraManagerNapi::CreateCameraInputInstance 2 invalid arguments");
        ProcessCameraInfo(cameraManagerNapi->cameraManager_, static_cast<const CameraPosition>(cameraPosition),
            static_cast<const CameraType>(cameraType), cameraInfo);
    } else {
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "invalid argument.");
        return nullptr;
    }
    if (cameraInfo == nullptr) {
        MEDIA_ERR_LOG("cameraInfo is null");
        CameraNapiUtils::ThrowError(env, SERVICE_FATL_ERROR, "cameraInfo is null.");
        return nullptr;
    }
    sptr<CameraInput> cameraInput = nullptr;
    int retCode = cameraManagerNapi->cameraManager_->CreateCameraInput(cameraInfo, &cameraInput);
    if (retCode == CAMERA_NO_PERMISSION) {
        CameraNapiUtils::ThrowError(env, OPERATION_NOT_ALLOWED, "not allowed, because have no permission.");
        return nullptr;
    }
    CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
    return CameraInputNapi::CreateCameraInput(env, cameraInput);
}

void CameraManagerNapi::ProcessCameraInfo(sptr<CameraManager>& cameraManager, const CameraPosition cameraPosition,
    const CameraType cameraType, sptr<CameraDevice>& cameraInfo)
{
    std::vector<sptr<CameraDevice>> cameraObjList = cameraManager->GetSupportedCameras();
    MEDIA_DEBUG_LOG("cameraInfo is null, the cameraObjList size is %{public}zu", cameraObjList.size());
    for (size_t i = 0; i < cameraObjList.size(); i++) {
        sptr<CameraDevice> cameraDevice = cameraObjList[i];
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

void CameraManagerNapi::ProcessCameraDevices(sptr<CameraManager>& cameraManager, const CameraPosition cameraPosition,
    const std::vector<CameraType>& cameraTypes, const ConnectionType connectionType,
    std::vector<sptr<CameraDevice>>& outDevices)
{
    std::vector<sptr<CameraDevice>> cameraObjList = cameraManager->GetSupportedCameras();
    MEDIA_DEBUG_LOG("GetCameraDevices cameraObjList size is %{public}zu", cameraObjList.size());

    for (size_t i = 0; i < cameraObjList.size(); ++i) {
        sptr<CameraDevice> cameraDevice = cameraObjList[i];
        if (cameraDevice == nullptr) {
            continue;
        }

        if (cameraDevice->GetPosition() != cameraPosition) {
            continue;
        }

        if (cameraDevice->GetConnectionType() != connectionType) {
            continue;
        }

        CameraType deviceType = cameraDevice->GetCameraType();
        if (!cameraTypes.empty()) {
            auto it = std::find(cameraTypes.begin(), cameraTypes.end(), deviceType);
            if (it == cameraTypes.end()) {
                continue;
            }
        }
        outDevices.emplace_back(cameraDevice);
    }
    MEDIA_DEBUG_LOG("GetCameraDevices matched size is %{public}zu", outDevices.size());
}

void CameraManagerNapi::RegisterCameraStatusCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    auto listener = CameraNapiEventListener<CameraManagerCallbackNapi>::RegisterCallbackListener(
        eventName, env, callback, args, isOnce);
    CHECK_RETURN_ELOG(
        listener == nullptr, "CameraManagerNapi::RegisterCameraStatusCallbackListener listener is null");
    cameraManager_->RegisterCameraStatusCallback(listener);
}

void CameraManagerNapi::UnregisterCameraStatusCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    auto listener =
        CameraNapiEventListener<CameraManagerCallbackNapi>::UnregisterCallbackListener(eventName, env, callback, args);
    CHECK_RETURN(listener == nullptr);
    if (listener->IsEmpty(eventName)) {
        cameraManager_->UnregisterCameraStatusCallback(listener);
    }
}

void CameraManagerNapi::RegisterCameraMuteCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    CHECK_RETURN_ELOG(!CameraNapiSecurity::CheckSystemApp(env), "SystemApi On cameraMute is called!");
    auto listener = CameraNapiEventListener<CameraMuteListenerNapi>::RegisterCallbackListener(
        eventName, env, callback, args, isOnce);
    CHECK_RETURN_ELOG(
        listener == nullptr, "CameraManagerNapi::RegisterCameraMuteCallbackListener listener is null");
    cameraManager_->RegisterCameraMuteListener(listener);
}

void CameraManagerNapi::UnregisterCameraMuteCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    CHECK_RETURN_ELOG(!CameraNapiSecurity::CheckSystemApp(env), "SystemApi On cameraMute is called!");
    auto listener =
        CameraNapiEventListener<CameraMuteListenerNapi>::UnregisterCallbackListener(eventName, env, callback, args);
    CHECK_RETURN(listener == nullptr);
    if (listener->IsEmpty(eventName)) {
        cameraManager_->UnregisterCameraMuteListener(listener);
    }
}

void CameraManagerNapi::RegisterTorchStatusCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    auto listener =
        CameraNapiEventListener<TorchListenerNapi>::RegisterCallbackListener(eventName, env, callback, args, isOnce);
    CHECK_RETURN_ELOG(
        listener == nullptr, "CameraManagerNapi::RegisterTorchStatusCallbackListener listener is null");
    cameraManager_->RegisterTorchListener(listener);
}

void CameraManagerNapi::UnregisterTorchStatusCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    auto listener =
        CameraNapiEventListener<TorchListenerNapi>::UnregisterCallbackListener(eventName, env, callback, args);
    CHECK_RETURN(listener == nullptr);
    if (listener->IsEmpty(eventName)) {
        cameraManager_->UnregisterTorchListener(listener);
    }
}

void CameraManagerNapi::RegisterFoldStatusCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    auto listener =
        CameraNapiEventListener<FoldListenerNapi>::RegisterCallbackListener(eventName, env, callback, args, isOnce);
    CHECK_RETURN_ELOG(
        listener == nullptr, "CameraManagerNapi::RegisterTorchStatusCallbackListener listener is null");
    cameraManager_->RegisterFoldListener(listener);
}

void CameraManagerNapi::UnregisterFoldStatusCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    auto listener =
        CameraNapiEventListener<FoldListenerNapi>::UnregisterCallbackListener(eventName, env, callback, args);
    CHECK_RETURN(listener == nullptr);
    if (listener->IsEmpty(eventName)) {
        cameraManager_->UnregisterFoldListener(listener);
    }
}

void CameraManagerNapi::RegisterControlCenterStatusCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    MEDIA_INFO_LOG("CameraManagerNapi::RegisterControlCenterStatusCallbackListener is called.");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi On controlCenterStatus is called!");
        return;
    }
    auto listener = CameraNapiEventListener<ControlCenterStatusListenerNapi>::RegisterCallbackListener(
        eventName, env, callback, args, isOnce);
    CHECK_RETURN_ELOG(
        listener == nullptr, "CameraManagerNapi::RegisterControlCenterStatusCallbackListener listener is null");
    cameraManager_->RegisterControlCenterStatusListener(listener);
}
 
void CameraManagerNapi::UnregisterControlCenterStatusCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    MEDIA_INFO_LOG("CameraManagerNapi::UnregisterControlCenterStatusCallbackListener is called.");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi On controlCenterStatus is called!");
        return;
    }
    auto listener = CameraNapiEventListener<ControlCenterStatusListenerNapi>::UnregisterCallbackListener(
        eventName, env, callback, args);
    CHECK_RETURN(listener == nullptr);
    if (listener->IsEmpty(eventName)) {
        cameraManager_->UnregisterControlCenterStatusListener(listener);
    }
}

const CameraManagerNapi::EmitterFunctions& CameraManagerNapi::GetEmitterFunctions()
{
    static const EmitterFunctions funMap = {
        { "cameraStatus", {
            &CameraManagerNapi::RegisterCameraStatusCallbackListener,
            &CameraManagerNapi::UnregisterCameraStatusCallbackListener } },
        { "cameraMute", {
            &CameraManagerNapi::RegisterCameraMuteCallbackListener,
            &CameraManagerNapi::UnregisterCameraMuteCallbackListener } },
        { "torchStatusChange", {
            &CameraManagerNapi::RegisterTorchStatusCallbackListener,
            &CameraManagerNapi::UnregisterTorchStatusCallbackListener } },
        { "foldStatusChange", {
            &CameraManagerNapi::RegisterFoldStatusCallbackListener,
            &CameraManagerNapi::UnregisterFoldStatusCallbackListener } },
        { "controlCenterStatusChange", {
            &CameraManagerNapi::RegisterControlCenterStatusCallbackListener,
            &CameraManagerNapi::UnregisterControlCenterStatusCallbackListener } } };
    return funMap;
}

napi_value CameraManagerNapi::IsControlCenterActive(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("IsControlCenterActive is called.");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsControlCenterActive is called!");
        return nullptr;
    }
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    napi_get_undefined(env, &result);
    CameraManagerNapi* cameraManagerNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraManagerNapi));
    if (status == napi_ok && cameraManagerNapi != nullptr) {
        bool isControlCenterActive = CameraManager::GetInstance()->IsControlCenterActive();
        MEDIA_DEBUG_LOG("isControlCenterActive : %{public}d", isControlCenterActive);
        napi_get_boolean(env, isControlCenterActive, &result);
    } else {
        MEDIA_ERR_LOG("isControlCenterActive call Failed!");
    }
    return result;
}
 
napi_value CameraManagerNapi::CreateControlCenterSession(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("CameraManagerNapi::CreateControlCenterSession is called");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi CreateControlCenterSession is called!");
        return nullptr;
    }
    MEDIA_INFO_LOG("CreateControlCenterSession is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    napi_get_undefined(env, &result);
    CameraManagerNapi* cameraManagerNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraManagerNapi));
    if (status != napi_ok || cameraManagerNapi == nullptr) {
        MEDIA_ERR_LOG("napi_unwrap failure!");
        return nullptr;
    }
    result = ControlCenterSessionNapi::CreateControlCenterSession(env);
    return result;
}

napi_value CameraManagerNapi::IsPrelaunchSupported(napi_env env, napi_callback_info info)
{
    COMM_INFO_LOG("IsPrelaunchSupported is called");
    CHECK_RETURN_RET_ELOG(!CameraNapiSecurity::CheckSystemApp(env), nullptr,
        "SystemApi IsPrelaunchSupported is called!");
    CameraManagerNapi* cameraManagerNapi = nullptr;
    std::string cameraId {};
    CameraNapiObject cameraInfoObj { { { "cameraId", &cameraId } } };
    CameraNapiParamParser jsParamParser(env, info, cameraManagerNapi, cameraInfoObj);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument!"), nullptr,
        "CameraManagerNapi::IsPrelaunchSupported invalid argument");
    sptr<CameraDevice> cameraInfo = cameraManagerNapi->cameraManager_->GetCameraDeviceFromId(cameraId);
    if (cameraInfo != nullptr) {
        bool isPrelaunchSupported = cameraManagerNapi->cameraManager_->IsPrelaunchSupported(cameraInfo);
        COMM_INFO_LOG("isPrelaunchSupported: %{public}d", isPrelaunchSupported);
        napi_value result;
        napi_get_boolean(env, isPrelaunchSupported, &result);
        return result;
    }
    MEDIA_ERR_LOG("CameraManagerNapi::IsPrelaunchSupported cameraInfo is null!");
    CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "cameraInfo is null.");
    return nullptr;
}

napi_value CameraManagerNapi::PrelaunchCamera(napi_env env, napi_callback_info info)
{
    COMM_INFO_LOG("PrelaunchCamera is called");
    CHECK_RETURN_RET_ELOG(!CameraNapiSecurity::CheckSystemApp(env),
        nullptr, "SystemApi PrelaunchCamera is called!");
    napi_value result = nullptr;
    int32_t retCode = 0;
    size_t napiArgsSize = CameraNapiUtils::GetNapiArgs(env, info);
    if (napiArgsSize == 1) {
        MEDIA_INFO_LOG("PrelaunchCamera arg 1");
        size_t argc = ARGS_ONE;
        napi_value argv[ARGS_ONE] = {0};
        napi_value thisVar = nullptr;
        CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
        int32_t value = 0;
        napi_get_value_int32(env, argv[PARAM0], &value);
        COMM_INFO_LOG("PrelaunchCamera value:%{public}d", value);
        retCode = CameraManager::GetInstance()->PrelaunchCamera(value);
    } else if (napiArgsSize == 0) {
        MEDIA_INFO_LOG("PrelaunchCamera arg 0");
        retCode = CameraManager::GetInstance()->PrelaunchCamera();
    }
    CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), result);
    MEDIA_INFO_LOG("PrelaunchCamera");
    napi_get_undefined(env, &result);
    return result;
}

napi_value CameraManagerNapi::ResetRssPriority(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("ResetRssPriority is called");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi ResetRssPriority is called!");
        return nullptr;
    }
    napi_value result = nullptr;
    int32_t retCode = CameraManager::GetInstance()->ResetRssPriority();
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        return result;
    }
    MEDIA_INFO_LOG("ResetRssPriority");
    napi_get_undefined(env, &result);
    return result;
}

napi_value CameraManagerNapi::PreSwitchCamera(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("PreSwitchCamera is called");
    CHECK_RETURN_RET_ELOG(!CameraNapiSecurity::CheckSystemApp(env),
        nullptr, "SystemApi PreSwitchCamera is called!");
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = { 0 };
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc < ARGS_TWO, "requires 1 parameters maximum");
    char buffer[PATH_MAX];
    size_t length;
    napi_get_value_string_utf8(env, argv[ARGS_ZERO], buffer, PATH_MAX, &length);
    int32_t retCode = CameraManager::GetInstance()->PreSwitchCamera(std::string(buffer));
    CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), result);
    MEDIA_INFO_LOG("PreSwitchCamera");
    napi_get_undefined(env, &result);
    return result;
}

napi_value CameraManagerNapi::SetPrelaunchConfig(napi_env env, napi_callback_info info)
{
    COMM_INFO_LOG("SetPrelaunchConfig is called");
    CHECK_RETURN_RET_ELOG(!CameraNapiSecurity::CheckSystemApp(env),
        nullptr, "SystemApi SetPrelaunchConfig is called!");

    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc < ARGS_TWO, "requires 1 parameters maximum");
    PrelaunchConfig prelaunchConfig;
    EffectParam effectParam;
    napi_value result = nullptr;

    bool isConfigSuccess = ParsePrelaunchConfig(env, argv[PARAM0], &prelaunchConfig);
    CHECK_RETURN_RET_ELOG(!isConfigSuccess, result, "SetPrelaunchConfig failed");
    ParseSettingParam(env, argv[PARAM0], &effectParam);
    std::string cameraId = prelaunchConfig.GetCameraDevice()->GetID();
    MEDIA_INFO_LOG("SetPrelaunchConfig cameraId = %{public}s", cameraId.c_str());

    int32_t retCode = CameraManager::GetInstance()->SetPrelaunchConfig(cameraId,
        static_cast<RestoreParamTypeOhos>(prelaunchConfig.restoreParamType), prelaunchConfig.activeTime, effectParam);
    CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), result);
    napi_get_undefined(env, &result);
    return result;
}

napi_value CameraManagerNapi::IsTorchSupported(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("IsTorchSupported is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraManagerNapi* cameraManagerNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraManagerNapi));
    if (status == napi_ok && cameraManagerNapi != nullptr) {
        bool isSupported = CameraManager::GetInstance()->IsTorchSupported();
        MEDIA_DEBUG_LOG("IsTorchSupported : %{public}d", isSupported);
        napi_get_boolean(env, isSupported, &result);
    } else {
        MEDIA_ERR_LOG("IsTorchSupported call Failed!");
    }
    return result;
}

napi_value CameraManagerNapi::IsTorchModeSupported(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("IsTorchModeSupported is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value argv[ARGS_ONE];
    size_t argc = ARGS_ONE;
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraManagerNapi* cameraManagerNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraManagerNapi));
    if (status == napi_ok && cameraManagerNapi != nullptr) {
        int32_t mode;
        napi_get_value_int32(env, argv[PARAM0], &mode);
        MEDIA_INFO_LOG("CameraManagerNapi::IsTorchModeSupported mode = %{public}d", mode);
        TorchMode torchMode = (TorchMode)mode;
        bool isTorchModeSupported = CameraManager::GetInstance()->IsTorchModeSupported(torchMode);
        MEDIA_DEBUG_LOG("IsTorchModeSupported : %{public}d", isTorchModeSupported);
        napi_get_boolean(env, isTorchModeSupported, &result);
    } else {
        MEDIA_ERR_LOG("GetTorchMode call Failed!");
    }
    return result;
}

napi_value CameraManagerNapi::GetTorchMode(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("GetTorchMode is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraManagerNapi* cameraManagerNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraManagerNapi));
    if (status == napi_ok && cameraManagerNapi != nullptr) {
        TorchMode mode = CameraManager::GetInstance()->GetTorchMode();
        MEDIA_DEBUG_LOG("GetTorchMode : %{public}d", mode);
        napi_create_int32(env, mode, &result);
    } else {
        MEDIA_ERR_LOG("GetTorchMode call Failed!");
    }
    return result;
}

napi_value CameraManagerNapi::SetTorchMode(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("SetTorchMode is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value argv[ARGS_ONE];
    size_t argc = ARGS_ONE;
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraManagerNapi* cameraManagerNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraManagerNapi));
    if (status == napi_ok && cameraManagerNapi != nullptr) {
        int32_t mode;
        napi_get_value_int32(env, argv[PARAM0], &mode);
        MEDIA_INFO_LOG("CameraManagerNapi::SetTorchMode mode = %{public}d", mode);
        TorchMode torchMode = (TorchMode)mode;
        int32_t retCode = CameraManager::GetInstance()->SetTorchMode(torchMode);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            MEDIA_DEBUG_LOG("SetTorchMode fail throw error");
        }
    } else {
        MEDIA_ERR_LOG("GetTorchMode call Failed!");
    }
    return result;
}

napi_value CameraManagerNapi::On(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<CameraManagerNapi>::On(env, info);
}

napi_value CameraManagerNapi::Once(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<CameraManagerNapi>::Once(env, info);
}

napi_value CameraManagerNapi::Off(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<CameraManagerNapi>::Off(env, info);
}
} // namespace CameraStandard
} // namespace OHOS