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

#include "mode/night_session_napi.h"
#include "uv.h"
namespace OHOS {
namespace CameraStandard {
using namespace std;

thread_local napi_ref NightSessionNapi::sConstructor_ = nullptr;

NightSessionNapi::NightSessionNapi() : env_(nullptr), wrapper_(nullptr)
{
}
NightSessionNapi::~NightSessionNapi()
{
    MEDIA_DEBUG_LOG("~NightSessionNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
    if (nightSession_) {
        nightSession_ = nullptr;
    }
}
void NightSessionNapi::NightSessionNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("NightSessionNapiDestructor is called");
    NightSessionNapi* cameraObj = reinterpret_cast<NightSessionNapi*>(nativeObject);
    if (cameraObj != nullptr) {
        delete cameraObj;
    }
}
napi_value NightSessionNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    napi_property_descriptor night_session_props[] = {
        DECLARE_NAPI_FUNCTION("beginConfig", CameraSessionNapi::BeginConfig),
        DECLARE_NAPI_FUNCTION("commitConfig", CameraSessionNapi::CommitConfig),

        DECLARE_NAPI_FUNCTION("canAddInput", CameraSessionNapi::CanAddInput),
        DECLARE_NAPI_FUNCTION("addInput", CameraSessionNapi::AddInput),
        DECLARE_NAPI_FUNCTION("removeInput", CameraSessionNapi::RemoveInput),

        DECLARE_NAPI_FUNCTION("canAddOutput", CameraSessionNapi::CanAddOutput),
        DECLARE_NAPI_FUNCTION("addOutput", CameraSessionNapi::AddOutput),
        DECLARE_NAPI_FUNCTION("removeOutput", CameraSessionNapi::RemoveOutput),

        DECLARE_NAPI_FUNCTION("start", CameraSessionNapi::Start),
        DECLARE_NAPI_FUNCTION("stop", CameraSessionNapi::Stop),
        DECLARE_NAPI_FUNCTION("release", CameraSessionNapi::Release),

        DECLARE_NAPI_FUNCTION("lockForControl", CameraSessionNapi::LockForControl),
        DECLARE_NAPI_FUNCTION("unlockForControl", CameraSessionNapi::UnlockForControl),

        DECLARE_NAPI_FUNCTION("isVideoStabilizationModeSupported",
                              CameraSessionNapi::IsVideoStabilizationModeSupported),
        DECLARE_NAPI_FUNCTION("getActiveVideoStabilizationMode", CameraSessionNapi::GetActiveVideoStabilizationMode),
        DECLARE_NAPI_FUNCTION("setVideoStabilizationMode", CameraSessionNapi::SetVideoStabilizationMode),

        DECLARE_NAPI_FUNCTION("hasFlash", CameraSessionNapi::HasFlash),
        DECLARE_NAPI_FUNCTION("isFlashModeSupported", CameraSessionNapi::IsFlashModeSupported),
        DECLARE_NAPI_FUNCTION("getFlashMode", CameraSessionNapi::GetFlashMode),
        DECLARE_NAPI_FUNCTION("setFlashMode", CameraSessionNapi::SetFlashMode),

        DECLARE_NAPI_FUNCTION("isExposureModeSupported", CameraSessionNapi::IsExposureModeSupported),
        DECLARE_NAPI_FUNCTION("getExposureMode", CameraSessionNapi::GetExposureMode),
        DECLARE_NAPI_FUNCTION("setExposureMode", CameraSessionNapi::SetExposureMode),
        DECLARE_NAPI_FUNCTION("getExposureBiasRange", CameraSessionNapi::GetExposureBiasRange),
        DECLARE_NAPI_FUNCTION("setExposureBias", CameraSessionNapi::SetExposureBias),
        DECLARE_NAPI_FUNCTION("getExposureValue", CameraSessionNapi::GetExposureValue),

        DECLARE_NAPI_FUNCTION("getMeteringPoint", CameraSessionNapi::GetMeteringPoint),
        DECLARE_NAPI_FUNCTION("setMeteringPoint", CameraSessionNapi::SetMeteringPoint),

        DECLARE_NAPI_FUNCTION("isFocusModeSupported", CameraSessionNapi::IsFocusModeSupported),
        DECLARE_NAPI_FUNCTION("getFocusMode", CameraSessionNapi::GetFocusMode),
        DECLARE_NAPI_FUNCTION("setFocusMode", CameraSessionNapi::SetFocusMode),

        DECLARE_NAPI_FUNCTION("getFocusPoint", CameraSessionNapi::GetFocusPoint),
        DECLARE_NAPI_FUNCTION("setFocusPoint", CameraSessionNapi::SetFocusPoint),
        DECLARE_NAPI_FUNCTION("getFocalLength", CameraSessionNapi::GetFocalLength),

        DECLARE_NAPI_FUNCTION("getZoomRatioRange", CameraSessionNapi::GetZoomRatioRange),
        DECLARE_NAPI_FUNCTION("getZoomRatio", CameraSessionNapi::GetZoomRatio),
        DECLARE_NAPI_FUNCTION("setZoomRatio", CameraSessionNapi::SetZoomRatio),

        DECLARE_NAPI_FUNCTION("getSupportedFilters", CameraSessionNapi::GetSupportedFilters),
        DECLARE_NAPI_FUNCTION("getFilter", CameraSessionNapi::GetFilter),
        DECLARE_NAPI_FUNCTION("setFilter", CameraSessionNapi::SetFilter),

        DECLARE_NAPI_FUNCTION("getSupportedBeautyTypes", CameraSessionNapi::GetSupportedBeautyTypes),
        DECLARE_NAPI_FUNCTION("getSupportedBeautyRange", CameraSessionNapi::GetSupportedBeautyRange),
        DECLARE_NAPI_FUNCTION("getBeauty", CameraSessionNapi::GetBeauty),
        DECLARE_NAPI_FUNCTION("setBeauty", CameraSessionNapi::SetBeauty),

        DECLARE_NAPI_FUNCTION("getSupportedExposureRange", NightSessionNapi::GetSupportedExposureRange),
        DECLARE_NAPI_FUNCTION("getExposure", NightSessionNapi::GetExposure),
        DECLARE_NAPI_FUNCTION("setExposure", NightSessionNapi::SetExposure),

        DECLARE_NAPI_FUNCTION("on", NightSessionNapi::On),
        DECLARE_NAPI_FUNCTION("off", NightSessionNapi::Off),
        DECLARE_NAPI_FUNCTION("TryAE", NightSessionNapi::TryAE),

    };
    status = napi_define_class(env, NIGHT_SESSION_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               NightSessionNapiConstructor, nullptr,
                               sizeof(night_session_props) / sizeof(night_session_props[PARAM0]),
                               night_session_props, &ctorObj);
    if (status == napi_ok) {
        int32_t refCount = 1;
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, NIGHT_SESSION_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

napi_value NightSessionNapi::CreateCameraSession(napi_env env)
{
    MEDIA_DEBUG_LOG("CreateCameraSession is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sCameraSession_ = ModeManager::GetInstance()->CreateCaptureSession(CameraMode::NIGHT);
        if (sCameraSession_ == nullptr) {
            MEDIA_ERR_LOG("Failed to create Camera session instance");
            napi_get_undefined(env, &result);
            return result;
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCameraSession_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            MEDIA_DEBUG_LOG("success to create Camera session napi instance");
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create Camera session napi instance");
        }
    }
    MEDIA_ERR_LOG("Failed to create Camera session napi instance last");
    napi_get_undefined(env, &result);
    return result;
}

napi_value NightSessionNapi::TryAE(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("TryAE is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    napi_get_undefined(env, &result);

    bool isDoTryAE = true;
    uint32_t exposureTime = 0;
    NightSessionNapi* nightSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&nightSessionNapi));
    if (status == napi_ok && nightSessionNapi != nullptr && nightSessionNapi->nightSession_ != nullptr) {
        nightSessionNapi->nightSession_->LockForControl();
        nightSessionNapi->nightSession_->DoTryAE(isDoTryAE, exposureTime);
        nightSessionNapi->nightSession_->UnlockForControl();
    } else {
        MEDIA_ERR_LOG("TryAE call Failed!");
    }
    return result;
}

napi_value NightSessionNapi::GetSupportedExposureRange(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedExposureRange is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    NightSessionNapi* nightSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&nightSessionNapi));
    if (status == napi_ok && nightSessionNapi != nullptr) {
        std::vector<uint32_t> vecExposureList;
        int32_t retCode = nightSessionNapi->nightSession_->GetExposureRange(vecExposureList);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        if (vecExposureList.empty() || napi_create_array(env, &result) != napi_ok) {
            return result;
        }
        for (size_t i = 0; i < vecExposureList.size(); i++) {
            uint32_t exposure = vecExposureList[i];
            MEDIA_DEBUG_LOG("EXPOSURE_RANGE : exposure = %{public}d", vecExposureList[i]);
            napi_value value;
            napi_create_uint32(env, exposure, &value);
            napi_set_element(env, result, i, value);
        }
        MEDIA_DEBUG_LOG("EXPOSURE_RANGE ExposureList size : %{public}zu", vecExposureList.size());
    } else {
        MEDIA_ERR_LOG("GetExposureBiasRange call Failed!");
    }
    return result;
}

napi_value NightSessionNapi::GetExposure(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetExposure is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    NightSessionNapi* nightSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&nightSessionNapi));
    if (status == napi_ok && nightSessionNapi!= nullptr) {
        uint32_t exposureValue;
        int32_t retCode = nightSessionNapi->nightSession_->GetExposure(exposureValue);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        MEDIA_DEBUG_LOG("GetExposure : exposure = %{public}d", exposureValue);
        napi_create_uint32(env, exposureValue, &result);
    } else {
        MEDIA_ERR_LOG("GetExposure call Failed!");
    }
    return result;
}

napi_value NightSessionNapi::SetExposure(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetExposure is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    NightSessionNapi* nightSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&nightSessionNapi));
    if (status == napi_ok && nightSessionNapi != nullptr) {
        uint32_t exposureValue;
        napi_get_value_uint32(env, argv[PARAM0], &exposureValue);
        MEDIA_DEBUG_LOG("SetExposure : exposure = %{public}d", exposureValue);
        nightSessionNapi->nightSession_->LockForControl();
        int32_t retCode = nightSessionNapi->nightSession_->SetExposure(exposureValue);
        nightSessionNapi->nightSession_->UnlockForControl();
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return result;
        }
    } else {
        MEDIA_ERR_LOG("SetExposure call Failed!");
    }
    return result;
}

napi_value NightSessionNapi::NightSessionNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("NightSessionNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<NightSessionNapi> obj = std::make_unique<NightSessionNapi>();
        obj->env_ = env;
        if (sCameraSession_ == nullptr) {
            MEDIA_ERR_LOG("sCameraSession_ is null");
            return result;
        }
        obj->nightSession_ = static_cast<NightSession*>(sCameraSession_.GetRefPtr());
        obj->cameraSession_ = obj->nightSession_;
        if (obj->nightSession_ == nullptr) {
            MEDIA_ERR_LOG("nightSession_ is null");
            return result;
        }
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
            NightSessionNapi::NightSessionNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("NightSessionNapi Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("NightSessionNapi call Failed!");
    return result;
}

void LongExposureCallbackListener::OnLongExposureCallbackAsync(uint32_t longExposureTime) const
{
    MEDIA_DEBUG_LOG("OnLongExposureCallbackAsync is called");
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("failed to get event loop");
        return;
    }
    uv_work_t* work = new(std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("failed to allocate work");
        return;
    }
    std::unique_ptr<LongExposureCallbackInfo> callbackInfo =
        std::make_unique<LongExposureCallbackInfo>(longExposureTime, this);
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        LongExposureCallbackInfo* callbackInfo = reinterpret_cast<LongExposureCallbackInfo *>(work->data);
        if (callbackInfo) {
            callbackInfo->listener_->OnLongExposureCallback(callbackInfo->longExposureTime_);
            delete callbackInfo;
        }
        delete work;
    }, uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void LongExposureCallbackListener::OnLongExposureCallback(uint32_t longExposureTime) const
{
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env_, &scope);
    MEDIA_DEBUG_LOG("OnLongExposureCallback is called");
    napi_value result[ARGS_TWO] = {nullptr, nullptr};
    napi_value callback = nullptr;
    napi_value retVal;
    for (auto it = longExposureCbList_.begin(); it != longExposureCbList_.end();) {
        napi_env env = (*it)->env_;
        napi_get_undefined(env, &result[PARAM0]);
        napi_create_int32(env, longExposureTime, &result[PARAM1]);
        napi_get_reference_value(env, (*it)->cb_, &callback);
        napi_call_function(env_, nullptr, callback, ARGS_TWO, result, &retVal);
        if ((*it)->isOnce_) {
            napi_status status = napi_delete_reference(env, (*it)->cb_);
            CHECK_AND_RETURN_LOG(status == napi_ok, "Remove once cb ref: delete reference for callback fail");
            (*it)->cb_ = nullptr;
            longExposureCbList_.erase(it);
        } else {
            it++;
        }
    }
    napi_close_handle_scope(env_, scope);
}

void LongExposureCallbackListener::OnLongExposure(const uint32_t longExposureTime)
{
    MEDIA_DEBUG_LOG("OnLongExposure is called");
    OnLongExposureCallbackAsync(longExposureTime);
}
void LongExposureCallbackListener::SaveCallbackReference(const std::string &eventType, napi_value callback, bool isOnce)
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = longExposureCbList_.begin(); it != longExposureCbList_.end(); ++it) {
        bool isSameCallback = CameraNapiUtils::IsSameCallback(env_, callback, (*it)->cb_);
        CHECK_AND_RETURN_LOG(!isSameCallback, "SaveCallbackReference: has same callback, nothing to do");
    }
    napi_ref callbackRef = nullptr;
    const int32_t refCount = 1;
    napi_status status = napi_create_reference(env_, callback, refCount, &callbackRef);
    CHECK_AND_RETURN_LOG(status == napi_ok && callbackRef != nullptr,
                         "LongExposureCallback: creating reference for callback fail");
    std::shared_ptr<AutoRef> cb = std::make_shared<AutoRef>(env_, callbackRef, isOnce);
    longExposureCbList_.push_back(cb);
    MEDIA_INFO_LOG("Save callback reference success, callback list size [%{public}zu]",
                   longExposureCbList_.size());
}

void LongExposureCallbackListener::RemoveCallbackRef(napi_env env, napi_value callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callback == nullptr) {
        MEDIA_INFO_LOG("RemoveCallbackRef: js callback is nullptr, remove all callback reference");
        RemoveAllCallbacks();
        return;
    }
    for (auto it = longExposureCbList_.begin(); it != longExposureCbList_.end(); ++it) {
        bool isSameCallback = CameraNapiUtils::IsSameCallback(env_, callback, (*it)->cb_);
        if (isSameCallback) {
            MEDIA_INFO_LOG("RemoveCallbackRef: find js callback, delete it");
            napi_status status = napi_delete_reference(env, (*it)->cb_);
            (*it)->cb_ = nullptr;
            CHECK_AND_RETURN_LOG(status == napi_ok, "RemoveCallbackRef: delete reference for callback fail");
            longExposureCbList_.erase(it);
            return;
        }
    }
    MEDIA_INFO_LOG("RemoveCallbackRef: js callback no find");
}

void LongExposureCallbackListener::RemoveAllCallbacks()
{
    for (auto it = longExposureCbList_.begin(); it != longExposureCbList_.end(); ++it) {
        napi_status ret = napi_delete_reference(env_, (*it)->cb_);
        if (ret != napi_ok) {
            MEDIA_ERR_LOG("RemoveAllCallbackReferences: napi_delete_reference err.");
        }
        (*it)->cb_ = nullptr;
    }
    longExposureCbList_.clear();
    MEDIA_INFO_LOG("RemoveAllCallbacks: remove all js callbacks success");
}

napi_value NightSessionNapi::On(napi_env env, napi_callback_info info)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("On is called");
    napi_value undefinedResult = nullptr;
    size_t argCount = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {nullptr, nullptr};
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);

    CAMERA_NAPI_GET_JS_ARGS(env, info, argCount, argv, thisVar);
    NAPI_ASSERT(env, argCount == ARGS_TWO, "requires 2 parameters");

    if (thisVar == nullptr || argv[PARAM0] == nullptr || argv[PARAM1] == nullptr) {
        MEDIA_ERR_LOG("Failed to retrieve details about the callback");
        return undefinedResult;
    }
    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok || valueType != napi_string
        || napi_typeof(env, argv[PARAM1], &valueType) != napi_ok || valueType != napi_function) {
        return undefinedResult;
    }
    std::string eventType = CameraNapiUtils::GetStringArgument(env, argv[PARAM0]);
    MEDIA_INFO_LOG("On eventType: %{public}s", eventType.c_str());
    return RegisterCallback(env, thisVar, eventType, argv[PARAM1], false);
}

napi_value NightSessionNapi::Once(napi_env env, napi_callback_info info)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("Once is called");
    napi_value undefinedResult = nullptr;
    size_t argCount = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {nullptr, nullptr};
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);

    CAMERA_NAPI_GET_JS_ARGS(env, info, argCount, argv, thisVar);
    NAPI_ASSERT(env, argCount == ARGS_TWO, "requires 2 parameters");

    if (thisVar == nullptr || argv[PARAM0] == nullptr || argv[PARAM1] == nullptr) {
        MEDIA_ERR_LOG("Failed to retrieve details about the callback");
        return undefinedResult;
    }
    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok || valueType != napi_string
        || napi_typeof(env, argv[PARAM1], &valueType) != napi_ok || valueType != napi_function) {
        return undefinedResult;
    }
    std::string eventType = CameraNapiUtils::GetStringArgument(env, argv[PARAM0]);
    MEDIA_INFO_LOG("Once eventType: %{public}s", eventType.c_str());
    return RegisterCallback(env, thisVar, eventType, argv[PARAM1], true);
}

napi_value NightSessionNapi::RegisterCallback(napi_env env, napi_value jsThis,
    const string &eventType, napi_value callback, bool isOnce)
{
    MEDIA_DEBUG_LOG("RegisterCallback is called");
    napi_value undefinedResult = nullptr;
    napi_get_undefined(env, &undefinedResult);
    napi_status status;

    NightSessionNapi* nightSessionNapi = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void**>(&nightSessionNapi));
    NAPI_ASSERT(env, status == napi_ok && nightSessionNapi != nullptr,
                "Failed to retrieve nightSessionNapi instance.");
    NAPI_ASSERT(env, nightSessionNapi->nightSession_ != nullptr, "cameraSession is null.");
    if (eventType.compare("nightExposure") == 0) {
        // Set callback for longExposure
        if (nightSessionNapi->longExposureCallback_ == nullptr) {
            std::shared_ptr<LongExposureCallbackListener> longExposureCallback =
                    make_shared<LongExposureCallbackListener>(env);
            nightSessionNapi->longExposureCallback_ = longExposureCallback;
            nightSessionNapi->nightSession_->SetLongExposureCallback(longExposureCallback);
        }
        nightSessionNapi->longExposureCallback_->SaveCallbackReference(eventType, callback, isOnce);
    } else  {
        MEDIA_ERR_LOG("Failed to Register Callback: event type is empty!");
    }
    return undefinedResult;
}

napi_value NightSessionNapi::UnregisterCallback(napi_env env, napi_value jsThis,
    const std::string &eventType, napi_value callback)
{
    MEDIA_DEBUG_LOG("UnregisterCallback is called");
    napi_value undefinedResult = nullptr;
    napi_get_undefined(env, &undefinedResult);
    napi_status status;
    NightSessionNapi* nightSessionNapi = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void**>(&nightSessionNapi));
    NAPI_ASSERT(env, status == napi_ok && nightSessionNapi != nullptr,
                "Failed to retrieve nightSessionNapi instance.");
    if (eventType.compare("LongExposure") == 0) {
        // Set callback for exposureStateChange
        if (nightSessionNapi->longExposureCallback_ == nullptr) {
            MEDIA_ERR_LOG("exposureCallback is null");
        } else {
            nightSessionNapi->longExposureCallback_->RemoveCallbackRef(env, callback);
        }
    } else  {
        MEDIA_ERR_LOG("Failed to Unregister Callback");
    }
    return undefinedResult;
}

napi_value NightSessionNapi::Off(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("Off is called");
    napi_value undefinedResult = nullptr;
    napi_get_undefined(env, &undefinedResult);
    const size_t minArgCount = 1;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {nullptr, nullptr};
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    if (argc < minArgCount) {
        return undefinedResult;
    }

    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok || valueType != napi_string) {
        return undefinedResult;
    }

    napi_valuetype secondArgsType = napi_undefined;
    if (argc > minArgCount &&
        (napi_typeof(env, argv[PARAM1], &secondArgsType) != napi_ok || secondArgsType != napi_function)) {
        return undefinedResult;
    }
    std::string eventType = CameraNapiUtils::GetStringArgument(env, argv[PARAM0]);
    MEDIA_INFO_LOG("Off eventType: %{public}s", eventType.c_str());
    return UnregisterCallback(env, thisVar, eventType, argv[PARAM1]);
}
} // namespace CameraStandard
} // namespace OHOS