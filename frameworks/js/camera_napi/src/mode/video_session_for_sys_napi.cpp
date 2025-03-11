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

#include <uv.h>

#include "mode/video_session_for_sys_napi.h"
#include "ability/camera_ability_napi.h"
#include "napi/native_common.h"
#include "camera_napi_object_types.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;

thread_local napi_ref VideoSessionForSysNapi::sConstructor_ = nullptr;

VideoSessionForSysNapi::VideoSessionForSysNapi() : env_(nullptr)
{
}
VideoSessionForSysNapi::~VideoSessionForSysNapi()
{
    MEDIA_DEBUG_LOG("~VideoSessionForSysNapi is called");
}
void VideoSessionForSysNapi::VideoSessionForSysNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("VideoSessionForSysNapiDestructor is called");
    VideoSessionForSysNapi* cameraObj = reinterpret_cast<VideoSessionForSysNapi*>(nativeObject);
    if (cameraObj != nullptr) {
        delete cameraObj;
    }
}
napi_value VideoSessionForSysNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;

    std::vector<std::vector<napi_property_descriptor>> descriptors = { camera_process_props, flash_props,
        auto_exposure_props, focus_props, zoom_props, filter_props, beauty_props, color_effect_props, macro_props,
        color_management_props, stabilization_props, preconfig_props, camera_output_capability_props,
        camera_ability_props, aperture_props, color_reservation_props, effect_suggestion_props};
    std::vector<napi_property_descriptor> video_session_props = CameraNapiUtils::GetPropertyDescriptor(descriptors);
    status = napi_define_class(env, VIDEO_SESSION_FOR_SYS_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               VideoSessionForSysNapiConstructor, nullptr,
                               video_session_props.size(),
                               video_session_props.data(), &ctorObj);
    if (status == napi_ok) {
        int32_t refCount = 1;
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, VIDEO_SESSION_FOR_SYS_NAPI_CLASS_NAME, ctorObj);
            CHECK_ERROR_RETURN_RET(status == napi_ok, exports);
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

napi_value VideoSessionForSysNapi::CreateCameraSession(napi_env env)
{
    MEDIA_DEBUG_LOG("CreateCameraSession is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sCameraSession_ = CameraManager::GetInstance()->CreateCaptureSession(SceneMode::VIDEO);
        if (sCameraSession_ == nullptr) {
            MEDIA_ERR_LOG("Failed to create Video session instance");
            napi_get_undefined(env, &result);
            return result;
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCameraSession_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            MEDIA_DEBUG_LOG("success to create Video session napi instance");
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create Video session napi instance");
        }
    }
    MEDIA_ERR_LOG("Failed to create Video session napi instance last");
    napi_get_undefined(env, &result);
    return result;
}

napi_value VideoSessionForSysNapi::VideoSessionForSysNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("VideoSessionForSysNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<VideoSessionForSysNapi> obj = std::make_unique<VideoSessionForSysNapi>();
        obj->env_ = env;
        CHECK_ERROR_RETURN_RET_LOG(sCameraSession_ == nullptr, result, "sCameraSession_ is null");
        obj->videoSession_ = static_cast<VideoSession*>(sCameraSession_.GetRefPtr());
        obj->cameraSession_ = obj->videoSession_;
        CHECK_ERROR_RETURN_RET_LOG(obj->videoSession_ == nullptr, result, "videoSession_ is null");
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
            VideoSessionForSysNapi::VideoSessionForSysNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("VideoSessionForSysNapi Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("VideoSessionForSysNapi call Failed!");
    return result;
}

void VideoSessionForSysNapi::RegisterFocusTrackingInfoCallbackListener(const std::string& eventName,
    napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    MEDIA_DEBUG_LOG("%{public}s is called", __FUNCTION__);
    CHECK_ERROR_RETURN_LOG(videoSession_ == nullptr, "%{public}s videoSession is nullptr!", __FUNCTION__);
    if (focusTrackingInfoCallback_ == nullptr) {
        focusTrackingInfoCallback_ = std::make_shared<FocusTrackingCallbackListener>(env);
        videoSession_->SetFocusTrackingInfoCallback(focusTrackingInfoCallback_);
    }
    focusTrackingInfoCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void VideoSessionForSysNapi::UnregisterFocusTrackingInfoCallbackListener(const std::string& eventName,
    napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    MEDIA_DEBUG_LOG("%{public}s is called", __FUNCTION__);
    CHECK_ERROR_RETURN_LOG(focusTrackingInfoCallback_ == nullptr,
        "%{public}s focusTrackingInfoCallback_ is nullptr", __FUNCTION__);
    focusTrackingInfoCallback_->RemoveCallbackRef(eventName, callback);
}

void FocusTrackingCallbackListener::OnFocusTrackingInfoAvailable(FocusTrackingInfo &focusTrackingInfo) const
{
    MEDIA_DEBUG_LOG("%{public}s is called", __FUNCTION__);
    OnFocusTrackingInfoCallbackAsync(focusTrackingInfo);
}

void FocusTrackingCallbackListener::OnFocusTrackingInfoCallbackAsync(FocusTrackingInfo &focusTrackingInfo) const
{
    MEDIA_DEBUG_LOG("%{public}s is called", __FUNCTION__);
    std::unique_ptr<FocusTrackingCallbackInfo> callback =
        std::make_unique<FocusTrackingCallbackInfo>(focusTrackingInfo, shared_from_this());
    FocusTrackingCallbackInfo *event = callback.get();
    auto task = [event] () {
        FocusTrackingCallbackInfo* callback = reinterpret_cast<FocusTrackingCallbackInfo *>(event);
        if (callback) {
            auto listener = callback->listener_.lock();
            if (listener != nullptr) {
                listener->OnFocusTrackingInfoCallback(callback->focusTrackingInfo_);
            }
            delete callback;
        }
    };
    if (napi_ok != napi_send_event(env_, task, napi_eprio_immediate)) {
        MEDIA_ERR_LOG("%{public}s: failed to execute work", __FUNCTION__);
    } else {
        callback.release();
    }
}

void FocusTrackingCallbackListener::OnFocusTrackingInfoCallback(FocusTrackingInfo &focusTrackingInfo) const
{
    MEDIA_DEBUG_LOG("%{public}s is called", __FUNCTION__);

    napi_value result[ARGS_ONE] = { nullptr };
    napi_value retVal = nullptr;

    result[PARAM0] = CameraNapiFocusTrackingInfo(focusTrackingInfo).GenerateNapiValue(env_);

    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_ONE, .argv = result, .result = &retVal };
    ExecuteCallback("focusTrackingInfoAvailable", callbackNapiPara);
}

void VideoSessionForSysNapi::RegisterLightStatusCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    MEDIA_INFO_LOG("VideoSessionForSysNapi::RegisterLightStatusCallbackListener called");
    if (lightStatusCallback_ == nullptr) {
        lightStatusCallback_ = std::make_shared<LightStatusCallbackListener>(env);
        videoSession_->SetLightStatusCallback(lightStatusCallback_);
        videoSession_->SetLightStatus(0);
    }
    lightStatusCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void VideoSessionForSysNapi::UnregisterLightStatusCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    MEDIA_INFO_LOG("VideoSessionForSysNapi::UnregisterLightStatusCallbackListener is called");
    if (lightStatusCallback_ == nullptr) {
        MEDIA_DEBUG_LOG("abilityCallback is null");
    } else {
        lightStatusCallback_->RemoveCallbackRef(eventName, callback);
    }
}

void LightStatusCallbackListener::OnLightStatusChangedCallbackAsync(LightStatus &status) const
{
    MEDIA_INFO_LOG("OnLightStatusChangedCallbackAsync is called");
    std::unique_ptr<LightStatusChangedCallback> callback =
        std::make_unique<LightStatusChangedCallback>(status, shared_from_this());
    LightStatusChangedCallback *event = callback.get();
    auto task = [event] () {
        LightStatusChangedCallback* callback = reinterpret_cast<LightStatusChangedCallback *>(event);
        if (callback) {
            MEDIA_DEBUG_LOG("the light status is %{public}d", callback->status_.status);
            auto listener = callback->listener_.lock();
            if (listener != nullptr) {
                listener->OnLightStatusChangedCallback(callback->status_);
            }
            delete callback;
        }
    };
    if (napi_ok != napi_send_event(env_, task, napi_eprio_immediate)) {
        MEDIA_ERR_LOG("failed to execute work");
    } else {
        callback.release();
    }
}

void LightStatusCallbackListener::OnLightStatusChangedCallback(LightStatus &status) const
{
    MEDIA_DEBUG_LOG("OnLightStatusChangedCallback is called, light status is %{public}d", status.status);
    ExecuteCallbackScopeSafe("lightStatus", [&]() {
        napi_value errCode = CameraNapiUtils::GetUndefinedValue(env_);
        napi_value result;
        napi_create_uint32(env_, status.status, &result);
        return ExecuteCallbackData(env_, errCode, result);
    });
}

void LightStatusCallbackListener::OnLightStatusChanged(LightStatus &status)
{
    MEDIA_DEBUG_LOG("OnLightStatusChanged is called, lightStatus: %{public}d", status.status);
    OnLightStatusChangedCallbackAsync(status);
}
} // namespace CameraStandard
} // namespace OHOS
