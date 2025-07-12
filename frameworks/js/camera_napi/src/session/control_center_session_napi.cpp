/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "camera_log.h"
#include "camera_manager.h"
#include "camera_napi_param_parser.h"
#include "control_center_session.h"
#include "js_native_api.h"
#include "js_native_api_types.h"
#include "napi/native_common.h"
#include "session/camera_session_napi.h"
#include "session/control_center_session_napi.h"
#include <cstddef>
#include <memory>
#include <cstdint>
#include <vector>
#include "capture_session.h"
#include "camera_napi_security_utils.h"

namespace OHOS {
namespace CameraStandard {

void AsyncCompleteCallback(napi_env env, napi_status status, void* data)
{
    auto context = static_cast<ControlCenterSessionAsyncContext*>(data);
    CHECK_RETURN_ELOG(context == nullptr, "ControlCenterSessionNapi AsyncCompleteCallback context is null");
    MEDIA_INFO_LOG("ControlCenterSessionNapi AsyncCompleteCallback %{public}s, status = %{public}d",
        context->funcName.c_str(), context->status);
    std::unique_ptr<JSAsyncContextOutput> jsContext = std::make_unique<JSAsyncContextOutput>();
    jsContext->status = context->status;
    if (!context->status) {
        CameraNapiUtils::CreateNapiErrorObject(env, context->errorCode, context->errorMsg.c_str(), jsContext);
    } else {
        napi_get_undefined(env, &jsContext->data);
    }
    if (!context->funcName.empty() && context->taskId > 0) {
        // Finish async trace
        CAMERA_FINISH_ASYNC_TRACE(context->funcName, context->taskId);
        jsContext->funcName = context->funcName;
    }
    if (context->work != nullptr) {
        CameraNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef, context->work, *jsContext);
    }
    context->FreeHeldNapiValue(env);
    delete context;
}

thread_local napi_ref ControlCenterSessionNapi::sConstructor_ = nullptr;
thread_local sptr<ControlCenterSession> ControlCenterSessionNapi::sControlCenterSession_ = nullptr;
thread_local uint32_t ControlCenterSessionNapi::controlCenterSessionTaskId = CONTROL_CENTER_SESSION_TASKID;

ControlCenterSessionNapi::ControlCenterSessionNapi() {}
 
ControlCenterSessionNapi::~ControlCenterSessionNapi()
{
    MEDIA_INFO_LOG("~ControlCenterSessionNapi is called");
}

void ControlCenterSessionNapi::ControlCenterSessionDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_INFO_LOG("ControlCenterSessionDestructor is called");
    ControlCenterSessionNapi* cameraObj = reinterpret_cast<ControlCenterSessionNapi*>(nativeObject);
    if (cameraObj != nullptr) {
        cameraObj->controlCenterSession_ = nullptr;
        delete cameraObj;
    }
}
 
napi_value ControlCenterSessionNapi::ControlCenterSessionConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("ControlCenterSessionConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<ControlCenterSessionNapi> obj = std::make_unique<ControlCenterSessionNapi>();
        obj->env_ = env;
        if (sControlCenterSession_ == nullptr) {
            MEDIA_ERR_LOG("sControlCenterSession_ is null");
            return result;
        }
        obj->controlCenterSession_ = sControlCenterSession_;
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
            ControlCenterSessionNapi::ControlCenterSessionDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            (void) obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("ControlCenterSessionConstructor failed wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("ControlCenterSessionConstructor call Failed!");
    return result;
}
 
napi_value ControlCenterSessionNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_INFO_LOG("ControlCenterSession::Init is called");
    napi_status status;
    napi_value ctorObj;
    
    napi_property_descriptor control_center_session_props[] = {
        DECLARE_NAPI_FUNCTION("getSupportedVirtualApertures", ControlCenterSessionNapi::GetSupportedVirtualApertures),
        DECLARE_NAPI_FUNCTION("getSupportedPhysicalApertures",
            ControlCenterSessionNapi::GetSupportedPhysicalApertures),
        DECLARE_NAPI_FUNCTION("getVirtualAperture", ControlCenterSessionNapi::GetVirtualAperture),
        DECLARE_NAPI_FUNCTION("setVirtualAperture", ControlCenterSessionNapi::SetVirtualAperture),
        DECLARE_NAPI_FUNCTION("getPhysicalAperture", ControlCenterSessionNapi::GetPhysicalAperture),
        DECLARE_NAPI_FUNCTION("setPhysicalAperture", ControlCenterSessionNapi::SetPhysicalAperture),

        DECLARE_NAPI_FUNCTION("getSupportedBeautyTypes", ControlCenterSessionNapi::GetSupportedBeautyTypes),
        DECLARE_NAPI_FUNCTION("getSupportedBeautyRange", ControlCenterSessionNapi::GetSupportedBeautyRange),
        DECLARE_NAPI_FUNCTION("getBeauty", ControlCenterSessionNapi::GetBeauty),
        DECLARE_NAPI_FUNCTION("setBeauty", ControlCenterSessionNapi::SetBeauty),
        DECLARE_NAPI_FUNCTION("getSupportedPortraitThemeTypes",
            ControlCenterSessionNapi::GetSupportedPortraitThemeTypes),
        DECLARE_NAPI_FUNCTION("isPortraitThemeSupported", ControlCenterSessionNapi::IsPortraitThemeSupported),
        DECLARE_NAPI_FUNCTION("setPortraitThemeType", ControlCenterSessionNapi::SetPortraitThemeType),
        DECLARE_NAPI_FUNCTION("release", Release)
    };

    status = napi_define_class(env, CONTROL_CENTER_SESSION_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
        ControlCenterSessionConstructor, nullptr,
        sizeof(control_center_session_props) / sizeof(control_center_session_props[0]),
        control_center_session_props, &ctorObj);
    if (status == napi_ok) {
        int32_t refCount = 1;
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, CONTROL_CENTER_SESSION_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("ControlCenterSessionNapi::Init Failed!");
    return nullptr;
}
 
napi_value ControlCenterSessionNapi::CreateControlCenterSession(napi_env env)
{
    MEDIA_INFO_LOG("ControlCenterSessionNapi::CreateControlCenterSession is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;

    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        int retCode =  CameraManager::GetInstance()->CreateControlCenterSession(sControlCenterSession_);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        if (sControlCenterSession_ == nullptr) {
            MEDIA_ERR_LOG("failed to create ControlCenterSession");
            return result;
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sControlCenterSession_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create ControlCenterSession instance.");
        }
    }
    MEDIA_ERR_LOG("CreateControlCenterSession call Failed!  %{public}d", status);
    napi_get_undefined(env, &result);
    return result;
}

napi_value ControlCenterSessionNapi::GetSupportedVirtualApertures(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi GetSupportedVirtualApertures is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("GetSupportedVirtualApertures is called");
    ControlCenterSessionNapi* controlCenterSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, controlCenterSessionNapi);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("controlCenterSessionNapi::GetSupportedVirtualApertures parse parameter occur error");
        return nullptr;
    }

    napi_status status;
    napi_value result = nullptr;
    status = napi_create_array(env, &result);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("napi_create_array call Failed!");
        return nullptr;
    }

    if (controlCenterSessionNapi->controlCenterSession_ != nullptr) {
        std::vector<float> virtualApertures = {};
        int32_t retCode =
            controlCenterSessionNapi->controlCenterSession_->GetSupportedVirtualApertures(virtualApertures);
        MEDIA_INFO_LOG("GetSupportedVirtualApertures virtualApertures len = %{public}zu", virtualApertures.size());
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        if (!virtualApertures.empty()) {
            for (size_t i = 0; i < virtualApertures.size(); i++) {
                float virtualAperture = virtualApertures[i];
                napi_value value;
                napi_create_double(env, CameraNapiUtils::FloatToDouble(virtualAperture), &value);
                napi_set_element(env, result, i, value);
            }
        }
    } else {
        MEDIA_ERR_LOG("GetSupportedVirtualApertures call Failed!");
    }
    return result;
}

napi_value ControlCenterSessionNapi::GetVirtualAperture(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi GetVirtualAperture is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("GetVirtualAperture is called");
    ControlCenterSessionNapi* controlCenterSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, controlCenterSessionNapi);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("controlCenterSessionNapi::GetVirtualAperture parse parameter occur error");
        return nullptr;
    }
    if (controlCenterSessionNapi->controlCenterSession_ != nullptr) {
        float virtualAperture;
        int32_t retCode = controlCenterSessionNapi->controlCenterSession_->GetVirtualAperture(virtualAperture);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_value result;
        napi_create_double(env, CameraNapiUtils::FloatToDouble(virtualAperture), &result);
        return result;
    } else {
        MEDIA_ERR_LOG("GetVirtualAperture call Failed!");
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value ControlCenterSessionNapi::SetVirtualAperture(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi SetVirtualAperture is called!");
        return nullptr;
    }
    MEDIA_INFO_LOG("SetVirtualAperture is called");
    double virtualAperture;
    ControlCenterSessionNapi* controlCenterSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, controlCenterSessionNapi, virtualAperture);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("controlCenterSessionNapi::SetVirtualAperture parse parameter occur error");
        return nullptr;
    }
    if (controlCenterSessionNapi->controlCenterSession_ != nullptr) {
        int32_t retCode =
            controlCenterSessionNapi->controlCenterSession_->SetVirtualAperture(static_cast<float>(virtualAperture));
        MEDIA_INFO_LOG("SetVirtualAperture set virtualAperture %{public}f!", virtualAperture);
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
    } else {
        MEDIA_ERR_LOG("SetVirtualAperture call Failed!");
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value ControlCenterSessionNapi::GetSupportedPhysicalApertures(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi GetSupportedPhysicalApertures is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("GetSupportedPhysicalApertures is called");
    ControlCenterSessionNapi* controlCenterSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, controlCenterSessionNapi);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("controlCenterSessionNapi::GetSupportedPhysicalApertures parse parameter occur error");
        return nullptr;
    }

    napi_status status;
    napi_value result = nullptr;
    status = napi_create_array(env, &result);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("napi_create_array call Failed!");
        return nullptr;
    }

    if (status == napi_ok && controlCenterSessionNapi->controlCenterSession_ != nullptr) {
        std::vector<std::vector<float>> physicalApertures = {};
        int32_t retCode =
            controlCenterSessionNapi->controlCenterSession_->GetSupportedPhysicalApertures(physicalApertures);
        MEDIA_INFO_LOG("GetSupportedPhysicalApertures len = %{public}zu", physicalApertures.size());
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        if (!physicalApertures.empty()) {
            result = CameraNapiUtils::ProcessingPhysicalApertures(env, physicalApertures);
        }
    } else {
        MEDIA_ERR_LOG("GetSupportedPhysicalApertures call Failed!");
    }
    return result;
}

napi_value ControlCenterSessionNapi::GetPhysicalAperture(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi GetPhysicalAperture is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("GetPhysicalAperture is called");
    ControlCenterSessionNapi* controlCenterSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, controlCenterSessionNapi);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("controlCenterSessionNapi::GetPhysicalAperture parse parameter occur error");
        return nullptr;
    }

    if (controlCenterSessionNapi->controlCenterSession_ != nullptr) {
        float physicalAperture = 0.0;
        int32_t retCode = controlCenterSessionNapi->controlCenterSession_->GetPhysicalAperture(physicalAperture);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_value result = nullptr;
        napi_create_double(env, CameraNapiUtils::FloatToDouble(physicalAperture), &result);
        return result;
    } else {
        MEDIA_ERR_LOG("GetPhysicalAperture call Failed!");
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value ControlCenterSessionNapi::SetPhysicalAperture(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi SetPhysicalAperture is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("SetPhysicalAperture is called");
    double physicalAperture;
    ControlCenterSessionNapi* controlCenterSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, controlCenterSessionNapi, physicalAperture);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("controlCenterSessionNapi::SetPhysicalAperture parse parameter occur error");
        return nullptr;
    }

    if (controlCenterSessionNapi->controlCenterSession_ != nullptr) {
        int32_t retCode =
            controlCenterSessionNapi->controlCenterSession_->SetPhysicalAperture(static_cast<float>(physicalAperture));
        MEDIA_INFO_LOG("SetPhysicalAperture set physicalAperture %{public}f!", ConfusingNumber(physicalAperture));
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
    } else {
        MEDIA_ERR_LOG("SetPhysicalAperture call Failed!");
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value ControlCenterSessionNapi::GetSupportedBeautyTypes(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi GetSupportedBeautyTypes is called!");
        return nullptr;
    }
    ControlCenterSessionNapi* controlCenterSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, controlCenterSessionNapi);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("controlCenterSessionNapi::GetSupportedBeautyTypes parse parameter occur error");
        return nullptr;
    }

    MEDIA_DEBUG_LOG("GetSupportedBeautyTypes is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    status = napi_create_array(env, &result);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("napi_create_array call Failed!");
        return result;
    }
    
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&controlCenterSessionNapi));
    if (status == napi_ok && controlCenterSessionNapi != nullptr
        && controlCenterSessionNapi->controlCenterSession_ != nullptr) {
        std::vector<int32_t> beautyTypes = controlCenterSessionNapi->controlCenterSession_->GetSupportedBeautyTypes();
        MEDIA_INFO_LOG("controlCenterSessionNapi::GetSupportedBeautyTypes len = %{public}zu",
            beautyTypes.size());
        if (!beautyTypes.empty() && status == napi_ok) {
            for (size_t i = 0; i < beautyTypes.size(); i++) {
                int32_t beautyType = beautyTypes[i];
                napi_value value;
                napi_create_int32(env, beautyType, &value);
                napi_set_element(env, result, i, value);
            }
        }
    } else {
        MEDIA_ERR_LOG("GetSupportedBeautyTypes call Failed!");
    }
    return result;
}

napi_value ControlCenterSessionNapi::GetSupportedBeautyRange(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi GetSupportedBeautyRange is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("GetSupportedBeautyRange is called");
    ControlCenterSessionNapi* controlCenterSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, controlCenterSessionNapi);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("controlCenterSessionNapi::GetSupportedBeautyTypes parse parameter occur error");
        return nullptr;
    }
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    status = napi_create_array(env, &result);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("napi_create_array call Failed!");
        return result;
    }
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&controlCenterSessionNapi));
    if (status == napi_ok && controlCenterSessionNapi != nullptr
        && controlCenterSessionNapi->controlCenterSession_ != nullptr) {
        int32_t beautyType;
        napi_get_value_int32(env, argv[PARAM0], &beautyType);
        std::vector<int32_t> beautyRanges =
            controlCenterSessionNapi->controlCenterSession_->GetSupportedBeautyRange(
                static_cast<BeautyType>(beautyType));
        MEDIA_INFO_LOG("controlCenterSessionNapi::GetSupportedBeautyRange beautyType = %{public}d, len = %{public}zu",
                       beautyType, beautyRanges.size());
        if (!beautyRanges.empty()) {
            for (size_t i = 0; i < beautyRanges.size(); i++) {
                int beautyRange = beautyRanges[i];
                napi_value value;
                napi_create_int32(env, beautyRange, &value);
                napi_set_element(env, result, i, value);
            }
        }
    } else {
        MEDIA_ERR_LOG("GetSupportedBeautyRange call Failed!");
    }
    return result;
}

napi_value ControlCenterSessionNapi::GetBeauty(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("ControlCenterSessionNapi::GetBeauty is called.");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi GetBeauty is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("GetBeauty is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    napi_get_undefined(env, &result);
    ControlCenterSessionNapi* controlCenterSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&controlCenterSessionNapi));
    if (status == napi_ok && controlCenterSessionNapi != nullptr
        && controlCenterSessionNapi->controlCenterSession_ != nullptr) {
        int32_t beautyType;
        napi_get_value_int32(env, argv[PARAM0], &beautyType);
        int32_t beautyStrength =
            controlCenterSessionNapi->controlCenterSession_->GetBeauty(static_cast<BeautyType>(beautyType));

        napi_create_int32(env, beautyStrength, &result);
    } else {
        MEDIA_ERR_LOG("GetBeauty call Failed!");
    }
    return result;
}

napi_value ControlCenterSessionNapi::SetBeauty(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("ControlCenterSessionNapi::SetBeauty is called.");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi SetBeauty is called!");
        return nullptr;
    }
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    napi_get_undefined(env, &result);
    ControlCenterSessionNapi* controlCenterSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&controlCenterSessionNapi));
    MEDIA_INFO_LOG("ControlCenterSessionNapi::SetBeauty is called.");
    if (status == napi_ok && controlCenterSessionNapi != nullptr
        && controlCenterSessionNapi->controlCenterSession_ != nullptr) {
        int32_t beautyType;
        napi_get_value_int32(env, argv[PARAM0], &beautyType);
        int32_t beautyStrength;
        napi_get_value_int32(env, argv[PARAM1], &beautyStrength);
        controlCenterSessionNapi->controlCenterSession_->SetBeauty(
            static_cast<BeautyType>(beautyType), beautyStrength);
    } else {
        MEDIA_ERR_LOG("ControlCenterSessionNapi::SetBeauty Failed!");
    }
    return result;
}

napi_value ControlCenterSessionNapi::GetSupportedPortraitThemeTypes(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi GetSupportedPortraitThemeTypes is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("GetSupportedPortraitThemeTypes is called");
    ControlCenterSessionNapi* controlCenterSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, controlCenterSessionNapi);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("controlCenterSessionNapi::GetSupportedPortraitThemeTypes parse parameter occur error");
        return nullptr;
    }

    napi_status status;
    napi_value result = nullptr;
    status = napi_create_array(env, &result);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("napi_create_array call Failed!");
        return nullptr;
    }

    if (controlCenterSessionNapi->controlCenterSession_ != nullptr) {
        std::vector<PortraitThemeType> themeTypes;
        int32_t retCode = controlCenterSessionNapi->controlCenterSession_->GetSupportedPortraitThemeTypes(themeTypes);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        MEDIA_INFO_LOG("controlCenterSessionNapi::GetSupportedPortraitThemeTypes len = %{public}zu",
            themeTypes.size());
        if (!themeTypes.empty()) {
            for (size_t i = 0; i < themeTypes.size(); i++) {
                napi_value value;
                napi_create_int32(env, static_cast<int32_t>(themeTypes[i]), &value);
                napi_set_element(env, result, i, value);
            }
        }
    } else {
        MEDIA_ERR_LOG("GetSupportedPortraitThemeTypes call Failed!");
    }
    return result;
}

napi_value ControlCenterSessionNapi::IsPortraitThemeSupported(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsPortraitThemeSupported is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("CameraSessionNapi::IsPortraitThemeSupported is called");
    ControlCenterSessionNapi* controlCenterSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, controlCenterSessionNapi);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("CameraSessionNapi::IsPortraitThemeSupported parse parameter occur error");
        return nullptr;
    }
    auto result = CameraNapiUtils::GetUndefinedValue(env);
    if (controlCenterSessionNapi->controlCenterSession_ != nullptr) {
        bool isSupported;
        int32_t retCode = controlCenterSessionNapi->controlCenterSession_->IsPortraitThemeSupported(isSupported);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_get_boolean(env, isSupported, &result);
    } else {
        MEDIA_ERR_LOG("CameraSessionNapi::IsPortraitThemeSupported get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return nullptr;
    }
    return result;
}

napi_value ControlCenterSessionNapi::SetPortraitThemeType(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi SetPortraitThemeType is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("CameraSessionNapi::SetPortraitThemeType is called");
    int32_t type = 0;
    ControlCenterSessionNapi* controlCenterSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, controlCenterSessionNapi, type);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("controlCenterSessionNapi::SetPortraitThemeType parse parameter occur error");
        return nullptr;
    }

    if (controlCenterSessionNapi->controlCenterSession_ != nullptr) {
        PortraitThemeType portraitThemeType = static_cast<PortraitThemeType>(type);
        MEDIA_INFO_LOG("CameraSessionNapi::SetPortraitThemeType:%{public}d", portraitThemeType);
        int32_t retCode = controlCenterSessionNapi->controlCenterSession_->SetPortraitThemeType(portraitThemeType);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            MEDIA_ERR_LOG("CameraSessionNapi::SetPortraitThemeType fail %{public}d", retCode);
            return nullptr;
        }
    } else {
        MEDIA_ERR_LOG("CameraSessionNapi::SetPortraitThemeType get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return nullptr;
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value ControlCenterSessionNapi::Release(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("ControlCenterSessionNapi::Release is called");
    std::unique_ptr<ControlCenterSessionAsyncContext> asyncContext = std::make_unique<ControlCenterSessionAsyncContext>(
        "ControlCenterSessionNapi::Release", CameraNapiUtils::IncrementAndGet(controlCenterSessionTaskId));
    auto asyncFunction =
        std::make_shared<CameraNapiAsyncFunction>(env, "Release", asyncContext->callbackRef, asyncContext->deferred);
    CameraNapiParamParser jsParamParser(env, info, asyncContext->objectInfo, asyncFunction);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
        MEDIA_ERR_LOG("ControlCenterSessionNapi::Release invalid argument");
        return nullptr;
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}
 
 
} // namespace CameraStandard
} // namespace OHOS
 