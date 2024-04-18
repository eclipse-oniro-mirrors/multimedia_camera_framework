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

#include "input/camera_info_napi.h"

#include "camera_napi_security_utils.h"
#include "camera_napi_param_parser.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;

thread_local napi_ref CameraDeviceNapi::sConstructor_ = nullptr;
thread_local sptr<CameraDevice> CameraDeviceNapi::sCameraDevice_ = nullptr;

CameraDeviceNapi::CameraDeviceNapi() : env_(nullptr), wrapper_(nullptr)
{
}

CameraDeviceNapi::~CameraDeviceNapi()
{
    MEDIA_DEBUG_LOG("~CameraDeviceNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
    if (cameraDevice_) {
        cameraDevice_ = nullptr;
    }
}

void CameraDeviceNapi::CameraDeviceNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("CameraDeviceNapiDestructor is called");
    CameraDeviceNapi* cameraObj = reinterpret_cast<CameraDeviceNapi*>(nativeObject);
    if (cameraObj != nullptr) {
        delete cameraObj;
    }
}

napi_value CameraDeviceNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    napi_property_descriptor camera_object_props[] = {
        DECLARE_NAPI_GETTER("cameraId", GetCameraId),
        DECLARE_NAPI_GETTER("cameraPosition", GetCameraPosition),
        DECLARE_NAPI_GETTER("cameraType", GetCameraType),
        DECLARE_NAPI_GETTER("connectionType", GetConnectionType),
        DECLARE_NAPI_GETTER("hostDeviceName", GetHostDeviceName),
        DECLARE_NAPI_GETTER("hostDeviceType", GetHostDeviceType),
        DECLARE_NAPI_GETTER("cameraOrientation", GetCameraOrientation)
    };

    status = napi_define_class(env, CAMERA_OBJECT_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               CameraDeviceNapiConstructor, nullptr,
                               sizeof(camera_object_props) / sizeof(camera_object_props[PARAM0]),
                               camera_object_props, &ctorObj);
    if (status == napi_ok) {
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, CAMERA_OBJECT_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

// Constructor callback
napi_value CameraDeviceNapi::CameraDeviceNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("CameraDeviceNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<CameraDeviceNapi> obj = std::make_unique<CameraDeviceNapi>();
        obj->env_ = env;
        obj->cameraDevice_ = sCameraDevice_;
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                           CameraDeviceNapi::CameraDeviceNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("CameraDeviceNapiConstructor call Failed!");
    return result;
}

napi_value CameraDeviceNapi::CreateCameraObj(napi_env env, sptr<CameraDevice> cameraDevice)
{
    MEDIA_INFO_LOG("CreateCameraObj is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;

    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sCameraDevice_ = cameraDevice;
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCameraDevice_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create Camera obj instance");
        }
    }
    napi_get_undefined(env, &result);
    MEDIA_ERR_LOG("CreateCameraObj call Failed!");
    return result;
}

napi_value CameraDeviceNapi::GetCameraId(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetCameraId is called");
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    CameraDeviceNapi* obj = nullptr;
    napi_value thisVar = nullptr;

    MEDIA_DEBUG_LOG("For get camera id");
    napi_get_undefined(env, &undefinedResult);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status != napi_ok || thisVar == nullptr) {
        MEDIA_ERR_LOG("Invalid arguments!");
        return undefinedResult;
    }
    MEDIA_DEBUG_LOG("To get camera id");
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if (status == napi_ok && obj != nullptr && obj->cameraDevice_ != nullptr) {
        std::string cameraId = obj->cameraDevice_->GetID();
        status = napi_create_string_utf8(env, cameraId.c_str(), NAPI_AUTO_LENGTH, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        } else {
            MEDIA_ERR_LOG("Failed to get camera id!, errorCode : %{public}d", status);
        }
    }
    MEDIA_ERR_LOG("GetCameraId call Failed!");
    return undefinedResult;
}

napi_value CameraDeviceNapi::GetCameraPosition(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetCameraPosition is called");
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    CameraDeviceNapi* obj = nullptr;
    CameraPosition jsCameraPosition;
    napi_value thisVar = nullptr;

    MEDIA_DEBUG_LOG("For get camera position");
    napi_get_undefined(env, &undefinedResult);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status != napi_ok || thisVar == nullptr) {
        MEDIA_ERR_LOG("Invalid arguments!");
        return undefinedResult;
    }
    MEDIA_DEBUG_LOG("To get camera position");
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if (status == napi_ok && obj != nullptr && obj->cameraDevice_ != nullptr) {
        jsCameraPosition = obj->cameraDevice_->GetPosition();
        status = napi_create_int32(env, jsCameraPosition, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        } else {
            MEDIA_ERR_LOG("Failed to get cameraPosition!, errorCode : %{public}d", status);
        }
    }
    MEDIA_ERR_LOG("GetCameraPosition call Failed!");
    return undefinedResult;
}

napi_value CameraDeviceNapi::GetCameraType(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetCameraType is called");
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    CameraDeviceNapi* obj = nullptr;
    CameraType jsCameraType;
    napi_value thisVar = nullptr;

    MEDIA_DEBUG_LOG("For get camera type");
    napi_get_undefined(env, &undefinedResult);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status != napi_ok || thisVar == nullptr) {
        MEDIA_ERR_LOG("Invalid arguments!");
        return undefinedResult;
    }
    MEDIA_DEBUG_LOG("To get camera type");
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if (status == napi_ok && obj != nullptr && obj->cameraDevice_ != nullptr) {
        jsCameraType = obj->cameraDevice_->GetCameraType();
        if (jsCameraType == CAMERA_TYPE_UNSUPPORTED) {
            MEDIA_ERR_LOG("Camera type is not a recognized camera type in JS");
            return undefinedResult;
        }
        status = napi_create_int32(env, jsCameraType, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        } else {
            MEDIA_ERR_LOG("Failed to get cameraType!, errorCode : %{public}d", status);
        }
    }
    MEDIA_ERR_LOG("GetCameraType call Failed!");
    return undefinedResult;
}

napi_value CameraDeviceNapi::GetConnectionType(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetConnectionType is called");
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    CameraDeviceNapi* obj = nullptr;
    ConnectionType jsConnectionType;
    napi_value thisVar = nullptr;

    MEDIA_DEBUG_LOG("For get connection type");
    napi_get_undefined(env, &undefinedResult);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status != napi_ok || thisVar == nullptr) {
        MEDIA_ERR_LOG("Invalid arguments!");
        return undefinedResult;
    }
    MEDIA_DEBUG_LOG("To get connection type");
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if (status == napi_ok && obj != nullptr && obj->cameraDevice_ != nullptr) {
        jsConnectionType = obj->cameraDevice_->GetConnectionType();

        status = napi_create_int32(env, jsConnectionType, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        } else {
            MEDIA_ERR_LOG("Failed to get connectionType!, errorCode : %{public}d", status);
        }
    }
    MEDIA_ERR_LOG("GetConnectionType call Failed!");
    return undefinedResult;
}

napi_value CameraDeviceNapi::GetHostDeviceName(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi GetHostDeviceName is called!");
        return nullptr;
    }
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    CameraDeviceNapi* obj = nullptr;
    napi_value thisVar = nullptr;

    MEDIA_DEBUG_LOG("For get host device name");
    napi_get_undefined(env, &undefinedResult);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status != napi_ok || thisVar == nullptr) {
        MEDIA_ERR_LOG("Invalid arguments!");
        return undefinedResult;
    }
    MEDIA_DEBUG_LOG("to get host device name");
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if (status == napi_ok && obj != nullptr && obj->cameraDevice_ != nullptr) {
        std::string hostDeviceName = obj->cameraDevice_->GetHostName();
        status = napi_create_string_utf8(env, hostDeviceName.c_str(), NAPI_AUTO_LENGTH, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        } else {
            MEDIA_ERR_LOG("Failed to get camera host Device Name!, errorCode : %{public}d", status);
        }
    }
    return undefinedResult;
}
napi_value CameraDeviceNapi::GetHostDeviceType(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi GetHostDeviceType is called!");
        return nullptr;
    }
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    CameraDeviceNapi* obj = nullptr;
    ConnectionType jsConnectionType;
    napi_value thisVar = nullptr;

    MEDIA_DEBUG_LOG("For get host device type");
    napi_get_undefined(env, &undefinedResult);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status != napi_ok || thisVar == nullptr) {
        MEDIA_ERR_LOG("Invalid arguments!");
        return undefinedResult;
    }
    MEDIA_DEBUG_LOG("To get host device type");
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if (status == napi_ok && obj != nullptr && obj->cameraDevice_ != nullptr) {
        jsConnectionType = obj->cameraDevice_->GetConnectionType();
        if (jsConnectionType == CAMERA_CONNECTION_BUILT_IN) {
            MEDIA_DEBUG_LOG("local device cameraHostType is undefine");
            return undefinedResult;
        } else {
            uint32_t hostDeviceType = obj->cameraDevice_->GetDeviceType();
            status = napi_create_uint32(env, hostDeviceType, &jsResult);
        }
        if (status == napi_ok) {
            return jsResult;
        } else {
            MEDIA_ERR_LOG("Failed to get camera host Device Type!, errorCode : %{public}d", status);
        }
    }
    return undefinedResult;
}

napi_value CameraDeviceNapi::GetCameraOrientation(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetCameraOrientation enter");

    CameraDeviceNapi* obj = nullptr;
    CameraNapiParamParser jsParamParser(env, info, obj);
    auto result = CameraNapiUtils::GetUndefinedValue(env);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("GetCameraOrientation parse parameter occur error");
        return result;
    }
    auto cameraDevice = obj->cameraDevice_;
    if (cameraDevice != nullptr) {
        uint32_t cameraOrientation = cameraDevice->GetCameraOrientation();
        napi_create_int32(env, cameraOrientation, &result);
    } else {
        MEDIA_ERR_LOG("GetCameraOrientation get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
    }
    return result;
}
} // namespace CameraStandard
} // namespace OHOS
