/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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
#include <cstddef>
#include <uv.h>

#include "mode/stitching_photo_session_napi.h"

#include "camera_napi_const.h"
#include "camera_napi_param_parser.h"
#include "input/camera_manager_for_sys.h"
#include "js_native_api.h"
#include "napi/native_node_api.h"
#include "pixel_map_napi.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;

thread_local sptr<StitchingPhotoSession> StitchingPhotoSessionNapi::sStitchingPhotoSession_ = nullptr;
thread_local napi_ref StitchingPhotoSessionNapi::sConstructor_ = nullptr;
thread_local sptr<PreviewOutput> StitchingPhotoSessionNapi::sPreviewOutput_ = nullptr;
thread_local uint32_t StitchingPhotoSessionNapi::previewOutputTaskId;

StitchingPhotoSessionNapi::StitchingPhotoSessionNapi() : env_(nullptr), wrapper_(nullptr) {}

StitchingPhotoSessionNapi::~StitchingPhotoSessionNapi()
{
    MEDIA_DEBUG_LOG("~StitchingPhotoSessionNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
}

void StitchingPhotoSessionNapi::StitchingPhotoSessionNapiDestructor(
    napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("StitchingPhotoSessionNapiDestructor is called");
    StitchingPhotoSessionNapi* cameraObj = reinterpret_cast<StitchingPhotoSessionNapi*>(nativeObject);
    if (cameraObj != nullptr) {
        delete cameraObj;
    }
}

void StitchingPhotoSessionNapi::Init(napi_env env)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    std::vector<std::vector<napi_property_descriptor>> descriptors = { camera_process_props, auto_exposure_props,
        CameraSessionForSysNapi::camera_process_sys_props, color_effect_sys_props, color_management_props,
        effect_suggestion_sys_props, flash_props, CameraSessionForSysNapi::flash_sys_props, focus_props,
        CameraSessionForSysNapi::focus_sys_props, zoom_props, CameraSessionForSysNapi::zoom_sys_props,
        manual_focus_sys_props, manual_stitching_funcs_ };

    std::vector<napi_property_descriptor> stitching_photo_session_props =
        CameraNapiUtils::GetPropertyDescriptor(descriptors);

    status = napi_define_class(env, STITCHING_PHOTO_SESSION_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
        StitchingPhotoSessionNapiConstructor, nullptr, stitching_photo_session_props.size(),
        stitching_photo_session_props.data(), &ctorObj);
    CHECK_RETURN_ELOG(status != napi_ok, "StitchingPhotoSessionNapi defined class failed");
    status = NapiRefManager::CreateMemSafetyRef(env, ctorObj, &sConstructor_);
    CHECK_RETURN_ELOG(status != napi_ok, "StitchingPhotoSessionNapi Init failed");
    MEDIA_DEBUG_LOG("StitchingPhotoSessionNapi Init success");
}

napi_value StitchingPhotoSessionNapi::CreateCameraSession(napi_env env)
{
    MEDIA_DEBUG_LOG("CreateCameraSession is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    if (sConstructor_ == nullptr) {
        StitchingPhotoSessionNapi::Init(env);
        CHECK_RETURN_RET_ELOG(sConstructor_ == nullptr, result, "sConstructor_ is null");
    }
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sCameraSessionForSys_ =
            CameraManagerForSys::GetInstance()->CreateCaptureSessionForSys(SceneMode::STITCHING_PHOTO);
        if (sCameraSessionForSys_ == nullptr) {
            MEDIA_ERR_LOG("Failed to create Photo session instance");
            napi_get_undefined(env, &result);
            return result;
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCameraSessionForSys_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            MEDIA_DEBUG_LOG("success to create Photo session napi instance");
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create Photo session napi instance");
        }
    }
    MEDIA_ERR_LOG("Failed to create Photo session napi instance last");
    napi_get_undefined(env, &result);
    return result;
}

napi_value StitchingPhotoSessionNapi::StitchingPhotoSessionNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("StitchingPhotoSessionNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<StitchingPhotoSessionNapi> obj = std::make_unique<StitchingPhotoSessionNapi>();
        obj->env_ = env;
        CHECK_RETURN_RET_ELOG(sCameraSessionForSys_ == nullptr, result, "sCameraSessionForSys_ is null");
        obj->stitchingPhotoSession_ = static_cast<StitchingPhotoSession*>(sCameraSessionForSys_.GetRefPtr());
        obj->cameraSessionForSys_ = obj->stitchingPhotoSession_;
        obj->cameraSession_ = obj->stitchingPhotoSession_;
        CHECK_RETURN_RET_ELOG(obj->stitchingPhotoSession_ == nullptr, result, "stitchingPhotoSession_ is null");
        status = napi_wrap(
            env, thisVar, reinterpret_cast<void*>(obj.get()), StitchingPhotoSessionNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("StitchingPhotoSessionNapiConstructor Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("StitchingPhotoSessionNapiConstructor call Failed!");
    return result;
}

napi_value StitchingPhotoSessionNapi::SetStitchingType(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("%{public}s enter", __PRETTY_FUNCTION__);
    StitchingPhotoSessionNapi* stitchingPhotoSessionNapi = nullptr;
    int32_t type;
    CameraNapiParamParser jsParamParser(env, info, stitchingPhotoSessionNapi, type);
    if (!jsParamParser.AssertStatus(PARAMETER_ERROR, "parse parameter occur error")) {
        MEDIA_ERR_LOG("%{public}s parse parameter occur error", __PRETTY_FUNCTION__);
        return nullptr;
    }
    if (stitchingPhotoSessionNapi->stitchingPhotoSession_ == nullptr) {
        MEDIA_ERR_LOG("%{public}s get native object fail", __PRETTY_FUNCTION__);
        CameraNapiUtils::ThrowError(env, PARAMETER_ERROR, "get native object fail");
        return nullptr;
    }
    stitchingPhotoSessionNapi->stitchingPhotoSession_->LockForControl();
    int retCode = stitchingPhotoSessionNapi->stitchingPhotoSession_->SetStitchingType(static_cast<StitchingType>(type));
    stitchingPhotoSessionNapi->stitchingPhotoSession_->UnlockForControl();
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        MEDIA_ERR_LOG("%{public}s fail! %{public}d", __PRETTY_FUNCTION__, retCode);
        return nullptr;
    }
    MEDIA_DEBUG_LOG("%{public}s success", __PRETTY_FUNCTION__);
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value StitchingPhotoSessionNapi::GetStitchingType(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("%{public}s is called", __PRETTY_FUNCTION__);
    StitchingPhotoSessionNapi* stitchingPhotoSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, stitchingPhotoSessionNapi);
    if (!jsParamParser.AssertStatus(PARAMETER_ERROR, "parse parameter occur error")) {
        MEDIA_ERR_LOG("%{public}s parse parameter occur error", __PRETTY_FUNCTION__);
        return nullptr;
    }
    if (stitchingPhotoSessionNapi->stitchingPhotoSession_ == nullptr) {
        MEDIA_ERR_LOG("%{public}s get native object fail", __PRETTY_FUNCTION__);
        CameraNapiUtils::ThrowError(env, PARAMETER_ERROR, "get native object fail");
        return nullptr;
    }

    stitchingPhotoSessionNapi->stitchingPhotoSession_->LockForControl();
    StitchingType type;
    int32_t retCode = stitchingPhotoSessionNapi->stitchingPhotoSession_->GetStitchingType(type);
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        MEDIA_ERR_LOG("%{public}s fail! %{public}d", __PRETTY_FUNCTION__, retCode);
        return nullptr;
    }
    napi_value result = nullptr;
    napi_create_int32(env, static_cast<int32_t>(type), &result);
    stitchingPhotoSessionNapi->stitchingPhotoSession_->UnlockForControl();
    return result;
}

napi_value StitchingPhotoSessionNapi::SetStitchingDirection(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("%{public}s enter", __PRETTY_FUNCTION__);
    StitchingPhotoSessionNapi* stitchingPhotoSessionNapi = nullptr;
    int32_t direction;
    CameraNapiParamParser jsParamParser(env, info, stitchingPhotoSessionNapi, direction);
    if (!jsParamParser.AssertStatus(PARAMETER_ERROR, "parse parameter occur error")) {
        MEDIA_ERR_LOG("%{public}s parse parameter occur error", __PRETTY_FUNCTION__);
        return nullptr;
    }
    if (stitchingPhotoSessionNapi->stitchingPhotoSession_ == nullptr) {
        MEDIA_ERR_LOG("%{public}s get native object fail", __PRETTY_FUNCTION__);
        CameraNapiUtils::ThrowError(env, PARAMETER_ERROR, "get native object fail");
        return nullptr;
    }
    stitchingPhotoSessionNapi->stitchingPhotoSession_->LockForControl();
    int retCode = stitchingPhotoSessionNapi->stitchingPhotoSession_->SetStitchingDirection(
        static_cast<StitchingDirection>(direction));
    stitchingPhotoSessionNapi->stitchingPhotoSession_->UnlockForControl();
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        MEDIA_ERR_LOG("%{public}s fail! %{public}d", __PRETTY_FUNCTION__, retCode);
        return nullptr;
    }
    MEDIA_DEBUG_LOG("%{public}s success", __PRETTY_FUNCTION__);
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value StitchingPhotoSessionNapi::SetMovingClockwise(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("%{public}s enter", __PRETTY_FUNCTION__);
    StitchingPhotoSessionNapi* stitchingPhotoSessionNapi = nullptr;
    bool clockWise;
    CameraNapiParamParser jsParamParser(env, info, stitchingPhotoSessionNapi, clockWise);
    if (!jsParamParser.AssertStatus(PARAMETER_ERROR, "parse parameter occur error")) {
        MEDIA_ERR_LOG("%{public}s parse parameter occur error", __PRETTY_FUNCTION__);
        return nullptr;
    }
    if (stitchingPhotoSessionNapi->stitchingPhotoSession_ == nullptr) {
        MEDIA_ERR_LOG("%{public}s get native object fail", __PRETTY_FUNCTION__);
        CameraNapiUtils::ThrowError(env, PARAMETER_ERROR, "get native object fail");
        return nullptr;
    }
    stitchingPhotoSessionNapi->stitchingPhotoSession_->LockForControl();
    int retCode = stitchingPhotoSessionNapi->stitchingPhotoSession_->SetMovingClockwise(clockWise);
    stitchingPhotoSessionNapi->stitchingPhotoSession_->UnlockForControl();
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        MEDIA_ERR_LOG("%{public}s fail! %{public}d", __PRETTY_FUNCTION__, retCode);
        return nullptr;
    }
    MEDIA_DEBUG_LOG("%{public}s success", __PRETTY_FUNCTION__);
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value StitchingPhotoSessionNapi::GetMovingClockwise(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("%{public}s is called", __PRETTY_FUNCTION__);
    StitchingPhotoSessionNapi* stitchingPhotoSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, stitchingPhotoSessionNapi);
    if (stitchingPhotoSessionNapi->stitchingPhotoSession_ == nullptr) {
        MEDIA_ERR_LOG("%{public}s get native object fail", __PRETTY_FUNCTION__);
        CameraNapiUtils::ThrowError(env, PARAMETER_ERROR, "get native object fail");
        return nullptr;
    }

    stitchingPhotoSessionNapi->stitchingPhotoSession_->LockForControl();
    bool clockWise;
    int32_t retCode = stitchingPhotoSessionNapi->stitchingPhotoSession_->GetMovingClockwise(clockWise);
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        MEDIA_ERR_LOG("%{public}s fail! %{public}d", __PRETTY_FUNCTION__, retCode);
        return nullptr;
    }
    napi_value result = nullptr;
    napi_create_int32(env, static_cast<int32_t>(clockWise), &result);
    stitchingPhotoSessionNapi->stitchingPhotoSession_->UnlockForControl();
    return result;
}

napi_value StitchingPhotoSessionNapi::GetStitchingDirection(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("%{public}s is called", __PRETTY_FUNCTION__);
    StitchingPhotoSessionNapi* stitchingPhotoSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, stitchingPhotoSessionNapi);
    if (stitchingPhotoSessionNapi->stitchingPhotoSession_ == nullptr) {
        MEDIA_ERR_LOG("%{public}s get native object fail", __PRETTY_FUNCTION__);
        CameraNapiUtils::ThrowError(env, PARAMETER_ERROR, "get native object fail");
        return nullptr;
    }

    stitchingPhotoSessionNapi->stitchingPhotoSession_->LockForControl();
    StitchingDirection direction;
    int32_t retCode = stitchingPhotoSessionNapi->stitchingPhotoSession_->GetStitchingDirection(direction);
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        MEDIA_ERR_LOG("%{public}s fail! %{public}d", __PRETTY_FUNCTION__, retCode);
        return nullptr;
    }
    napi_value result = nullptr;
    napi_create_int32(env, static_cast<int32_t>(direction), &result);
    stitchingPhotoSessionNapi->stitchingPhotoSession_->UnlockForControl();
    return result;
}

void StitchingPhotoSessionNapi::RegisterStitchingTargetInfoCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    MEDIA_INFO_LOG("%{public}s enter", __PRETTY_FUNCTION__);
    Adaptor::RegCallback(eventName, env, callback, args, isOnce, stitchingTargetInfoCallbackListener_,
        &StitchingPhotoSession::SetStitchingTargetInfoCallback, GetSession());
}

void StitchingPhotoSessionNapi::UnregisterStitchingTargetInfoCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    MEDIA_INFO_LOG("%{public}s enter", __PRETTY_FUNCTION__);
    Adaptor::UnregCallback(eventName, env, callback, args, stitchingTargetInfoCallbackListener_);
}

void StitchingPhotoSessionNapi::RegisterStitchingCaptureInfoCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    MEDIA_INFO_LOG("%{public}s enter", __PRETTY_FUNCTION__);
    Adaptor::RegCallback(eventName, env, callback, args, isOnce, stitchingCaptureInfoCallbackListener_,
        &StitchingPhotoSession::SetStitchingCaptureInfoCallback, GetSession());
}

void StitchingPhotoSessionNapi::UnregisterStitchingCaptureInfoCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    MEDIA_INFO_LOG("%{public}s enter", __PRETTY_FUNCTION__);
    Adaptor::UnregCallback(eventName, env, callback, args, stitchingCaptureInfoCallbackListener_);
}

void StitchingPhotoSessionNapi::RegisterStitchingHintInfoCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    MEDIA_INFO_LOG("%{public}s enter", __PRETTY_FUNCTION__);
    Adaptor::RegCallback(eventName, env, callback, args, isOnce, stitchingHintInfoCallbackListener_,
        &StitchingPhotoSession::SetStitchingHintInfoCallback, GetSession());
}

void StitchingPhotoSessionNapi::UnregisterStitchingHintInfoCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    MEDIA_INFO_LOG("%{public}s enter", __PRETTY_FUNCTION__);
    Adaptor::UnregCallback(eventName, env, callback, args, stitchingHintInfoCallbackListener_);
}

void StitchingPhotoSessionNapi::RegisterStitchingCaptureStateCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    MEDIA_INFO_LOG("%{public}s enter", __PRETTY_FUNCTION__);
    Adaptor::RegCallback(eventName, env, callback, args, isOnce, stitchingCaptureStateCallbackListener_,
        &StitchingPhotoSession::SetStitchingCaptureStateCallback, GetSession());
}

void StitchingPhotoSessionNapi::UnregisterStitchingCaptureStateCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    MEDIA_INFO_LOG("%{public}s enter", __PRETTY_FUNCTION__);
    Adaptor::UnregCallback(eventName, env, callback, args, stitchingCaptureStateCallbackListener_);
}

const std::vector<napi_property_descriptor> StitchingPhotoSessionNapi::manual_stitching_funcs_ = {
    DECLARE_NAPI_FUNCTION("getStitchingType", StitchingPhotoSessionNapi::GetStitchingType),
    DECLARE_NAPI_FUNCTION("setStitchingType", StitchingPhotoSessionNapi::SetStitchingType),
    DECLARE_NAPI_FUNCTION("getStitchingDirection", StitchingPhotoSessionNapi::GetStitchingDirection),
    DECLARE_NAPI_FUNCTION("setStitchingDirection", StitchingPhotoSessionNapi::SetStitchingDirection),
    DECLARE_NAPI_FUNCTION("getMovingClockwise", StitchingPhotoSessionNapi::GetMovingClockwise),
    DECLARE_NAPI_FUNCTION("setMovingClockwise", StitchingPhotoSessionNapi::SetMovingClockwise),
};

template<>
void StitchingTargetInfoCallbackListener::ToNapiFormat(const StitchingTargetInfo& info) const
{
    MEDIA_INFO_LOG("%{public}s enter", __PRETTY_FUNCTION__);
    napi_value result[ARGS_TWO] = { nullptr, nullptr };
    napi_value retVal;

    napi_get_undefined(env_, &result[PARAM0]);
    napi_create_object(env_, &result[PARAM1]);

    napi_status status;
    napi_value points = CameraNapiUtils::CreateJsPointArray(env_, status, info.positions_);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("%{public}s status: %{public}d", __PRETTY_FUNCTION__, static_cast<int32_t>(status));
        points = nullptr;
    }
    napi_value angle;
    napi_create_double(env_, CameraNapiUtils::FloatToDouble(info.angle_), &angle);
    napi_set_named_property(env_, result[PARAM1], "position", points);
    napi_set_named_property(env_, result[PARAM1], "angle", angle);
    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback("targetChange", callbackNapiPara);
}

template<>
void StitchingCaptureInfoCallbackListener::ToNapiFormat(const StitchingCaptureInfo& info) const
{
    MEDIA_INFO_LOG("%{public}s enter", __PRETTY_FUNCTION__);
    napi_value result[ARGS_TWO] = { nullptr, nullptr };
    napi_value retVal;

    napi_get_undefined(env_, &result[PARAM0]);
    napi_create_object(env_, &result[PARAM1]);

    napi_value captureNumber;
    napi_create_int32(env_, info.captureNumber_, &captureNumber);
    napi_value previewStitching = OHOS::Media::PixelMapNapi::CreatePixelMap(env_, info.previewStitching_);
    napi_set_named_property(env_, result[PARAM1], "captureNumber", captureNumber);
    napi_set_named_property(env_, result[PARAM1], "previewStitching", previewStitching);
    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback("capture", callbackNapiPara);
}

template<>
void StitchingHintInfoCallbackListener::ToNapiFormat(const StitchingHintInfo& info) const
{
    MEDIA_INFO_LOG("%{public}s enter", __PRETTY_FUNCTION__);
    napi_value result[ARGS_TWO] = { nullptr, nullptr };
    napi_get_undefined(env_, &result[PARAM0]);
    napi_value retVal;
    napi_create_int32(env_, static_cast<int32_t>(info.hint_), &result[PARAM1]);
    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback("stitchingHint", callbackNapiPara);
}

template<>
void StitchingCaptureStateCallbackListener::ToNapiFormat(const StitchingCaptureStateInfo& info) const
{
    MEDIA_INFO_LOG("%{public}s enter", __PRETTY_FUNCTION__);
    napi_value result[ARGS_TWO] = { nullptr, nullptr };
    napi_value retVal;
    napi_get_undefined(env_, &result[PARAM0]);
    napi_create_int32(env_, static_cast<int32_t>(info.state_), &result[PARAM1]);
    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback("captureStateChange", callbackNapiPara);
}

} // namespace CameraStandard
} // namespace OHOS
