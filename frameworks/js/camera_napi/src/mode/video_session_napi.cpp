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

#include "mode/video_session_napi.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;

thread_local napi_ref VideoSessionNapi::sConstructor_ = nullptr;

VideoSessionNapi::VideoSessionNapi() : env_(nullptr) {}
VideoSessionNapi::~VideoSessionNapi()
{
    MEDIA_DEBUG_LOG("~VideoSessionNapi is called");
    if (videoSession_) {
        videoSession_ = nullptr;
    }
}
void VideoSessionNapi::VideoSessionNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("VideoSessionNapiDestructor is called");
    VideoSessionNapi* cameraObj = reinterpret_cast<VideoSessionNapi*>(nativeObject);
    if (cameraObj != nullptr) {
        delete cameraObj;
    }
}
napi_value VideoSessionNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    std::vector<std::vector<napi_property_descriptor>> descriptors = { camera_process_props, flash_props,
        auto_exposure_props, focus_props, zoom_props, filter_props, stabilization_props, preconfig_props,
        color_management_props, auto_switch_props, quality_prioritization_props, macro_props, white_balance_props };
    std::vector<napi_property_descriptor> video_session_props = CameraNapiUtils::GetPropertyDescriptor(descriptors);
    status = napi_define_class(env, VIDEO_SESSION_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               VideoSessionNapiConstructor, nullptr,
                               video_session_props.size(),
                               video_session_props.data(), &ctorObj);
    if (status == napi_ok) {
        int32_t refCount = 1;
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, VIDEO_SESSION_NAPI_CLASS_NAME, ctorObj);
            CHECK_ERROR_RETURN_RET(status == napi_ok, exports);
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

napi_value VideoSessionNapi::CreateCameraSession(napi_env env)
{
    MEDIA_DEBUG_LOG("VideoSessionNapi::CreateCameraSession is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sCameraSession_ = CameraManager::GetInstance()->CreateCaptureSession(SceneMode::VIDEO);
        if (sCameraSession_ == nullptr) {
            MEDIA_ERR_LOG("VideoSessionNapi::CreateCameraSession Failed to create instance");
            napi_get_undefined(env, &result);
            return result;
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCameraSession_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            MEDIA_DEBUG_LOG("VideoSessionNapi::CreateCameraSession success to create napi instance");
            return result;
        } else {
            MEDIA_ERR_LOG("VideoSessionNapi::CreateCameraSession Failed to create napi instance");
        }
    }
    MEDIA_ERR_LOG("VideoSessionNapi::CreateCameraSession Failed to create napi instance last");
    napi_get_undefined(env, &result);
    return result;
}

napi_value VideoSessionNapi::CreateVideoSessionForTransfer(napi_env env, sptr<VideoSession> videoSession)
{
    MEDIA_INFO_LOG("CreateVideoSessionForTransfer is called");
    CHECK_ERROR_RETURN_RET_LOG(videoSession == nullptr, nullptr,
        "CreateVideoSessionForTransfer videoSession is nullptr");
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sCameraSession_ = videoSession;
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCameraSession_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            MEDIA_INFO_LOG("CreateVideoSessionForTransfer success to create napi instance for transfer");
            return result;
        } else {
            MEDIA_ERR_LOG("CreateVideoSessionForTransfer Failed to create napi instance for transfer");
        }
    }
    MEDIA_ERR_LOG("CreateVideoSessionForTransfer Failed");
    napi_get_undefined(env, &result);
    return result;
}

napi_value VideoSessionNapi::VideoSessionNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("VideoSessionNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<VideoSessionNapi> obj = std::make_unique<VideoSessionNapi>();
        obj->env_ = env;
        CHECK_ERROR_RETURN_RET_LOG(sCameraSession_ == nullptr, result, "sCameraSession_ is null");
        obj->videoSession_ = static_cast<VideoSession*>(sCameraSession_.GetRefPtr());
        obj->cameraSession_ = obj->videoSession_;
        CHECK_ERROR_RETURN_RET_LOG(obj->videoSession_ == nullptr, result, "videoSession_ is null");
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
            VideoSessionNapi::VideoSessionNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("VideoSessionNapi Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("VideoSessionNapi call Failed!");
    return result;
}

void VideoSessionNapi::RegisterPressureStatusCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    MEDIA_INFO_LOG("VideoSessionNapi::RegisterPressureStatusCallbackListener");
    if (pressureCallback_ == nullptr) {
        pressureCallback_ = std::make_shared<PressureCallbackListener>(env);
        cameraSession_->SetPressureCallback(pressureCallback_);
    }
    pressureCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void VideoSessionNapi::UnregisterPressureStatusCallbackListener(
    const std::string &eventName, napi_env env, napi_value callback, const std::vector<napi_value> &args)
{
    MEDIA_INFO_LOG("VideoSessionNapi::UnregisterPressureStatusCallbackListener");
    if (pressureCallback_ == nullptr) {
        MEDIA_INFO_LOG("pressureCallback is null");
        return;
    }
    pressureCallback_->RemoveCallbackRef(eventName, callback);
}

extern "C" {
napi_value GetVideoSessionNapi(napi_env env, sptr<VideoSession> videoSession)
{
    MEDIA_INFO_LOG("%{public}s Called", __func__);
    return VideoSessionNapi::CreateVideoSessionForTransfer(env, videoSession);
}

bool GetNativeVideoSession(void *videoSessionNapiPtr, sptr<CaptureSession> &nativeSession)
{
    MEDIA_INFO_LOG("%{public}s Called", __func__);
    CHECK_ERROR_RETURN_RET_LOG(videoSessionNapiPtr == nullptr,
        false, "%{public}s videoSessionNapiPtr is nullptr", __func__);
    nativeSession = reinterpret_cast<VideoSessionNapi*>(videoSessionNapiPtr)->cameraSession_;
    return true;
}
}
} // namespace CameraStandard
} // namespace OHOS