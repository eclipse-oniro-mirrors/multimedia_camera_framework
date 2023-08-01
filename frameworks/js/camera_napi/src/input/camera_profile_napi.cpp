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

#include "input/camera_profile_napi.h"
#include "input/camera_size_napi.h"

namespace OHOS {
namespace CameraStandard {
using OHOS::HiviewDFX::HiLog;
using OHOS::HiviewDFX::HiLogLabel;

thread_local napi_ref CameraProfileNapi::sConstructor_ = nullptr;
thread_local Profile* CameraProfileNapi::sCameraProfile_ = nullptr;

CameraProfileNapi::CameraProfileNapi() : env_(nullptr), wrapper_(nullptr)
{
}

CameraProfileNapi::~CameraProfileNapi()
{
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
    if (cameraProfile_) {
        cameraProfile_ = nullptr;
    }
}

void CameraProfileNapi::CameraProfileNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("CameraProfileNapiDestructor enter");
    CameraProfileNapi* cameraProfileNapi = reinterpret_cast<CameraProfileNapi*>(nativeObject);
    if (cameraProfileNapi != nullptr) {
        MEDIA_INFO_LOG("CameraProfileNapi::CameraProfileNapiDestructor ~");
        delete cameraProfileNapi;
    }
}

napi_value CameraProfileNapi::Init(napi_env env, napi_value exports)
{
    napi_status status;
    napi_value ctorObj;
    napi_property_descriptor camera_profile_props[] = {
        DECLARE_NAPI_GETTER("format", GetCameraProfileFormat),
        DECLARE_NAPI_GETTER("size", GetCameraProfileSize)
    };
    status = napi_define_class(env, CAMERA_PROFILE_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               CameraProfileNapiConstructor, nullptr,
                               sizeof(camera_profile_props) / sizeof(camera_profile_props[PARAM0]),
                               camera_profile_props, &ctorObj);
    if (status == napi_ok) {
        int32_t refCount = 1;
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, CAMERA_PROFILE_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    return nullptr;
}

// Constructor callback
napi_value CameraProfileNapi::CameraProfileNapiConstructor(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<CameraProfileNapi> obj = std::make_unique<CameraProfileNapi>();
        obj->env_ = env;
        obj->cameraProfile_ = sCameraProfile_;
        MEDIA_INFO_LOG("CameraProfileNapi::CameraProfileNapiConstructor "
            "size.width = %{public}d, size.height = %{public}d, "
            "format = %{public}d",
            obj->cameraProfile_->GetSize().width,
            obj->cameraProfile_->GetSize().height,
            obj->cameraProfile_->format_);
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                           CameraProfileNapi::CameraProfileNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }
    return result;
}

napi_value CameraProfileNapi::CreateCameraProfile(napi_env env, Profile &profile)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;

    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        CameraFormat format = profile.GetCameraFormat();
        Size size = profile.GetSize();
        MEDIA_INFO_LOG("CameraProfileNapi::CreateCameraProfile size.width = %{public}d, size.height = %{public}d",
            size.width, size.height);
        std::unique_ptr<Profile> profilePtr = std::make_unique<Profile>(format, size);
        sCameraProfile_ = reinterpret_cast<Profile*>(profilePtr.get());
        MEDIA_INFO_LOG("CameraProfileNapi::CreateCameraProfile sCameraProfile_ "
            "size.width = %{public}d, size.height = %{public}d, format = %{public}d",
            sCameraProfile_->GetSize().width, sCameraProfile_->GetSize().height, sCameraProfile_->format_);
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        if (status == napi_ok && result != nullptr) {
            MEDIA_INFO_LOG("GetCameraProfileSize CreateCameraProfile napi_new_instance success");
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create Camera obj instance");
        }
    }

    napi_get_undefined(env, &result);
    return result;
}

napi_value CameraProfileNapi::GetCameraProfileSize(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    CameraProfileNapi* obj = nullptr;
    Size cameraProfileSize;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    MEDIA_INFO_LOG("GetCameraProfileSize cameraProfileSize thisVar");
    if (status != napi_ok || thisVar == nullptr) {
        MEDIA_ERR_LOG("Invalid arguments!");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if ((status == napi_ok) && (obj != nullptr)) {
        cameraProfileSize.height = obj->cameraProfile_->GetSize().height;
        cameraProfileSize.width = obj->cameraProfile_->GetSize().width;
        MEDIA_INFO_LOG("GetCameraProfileSize cameraProfileSize "
            "size.width = %{public}d, size.height = %{public}d",
            cameraProfileSize.width, cameraProfileSize.height);
        jsResult = CameraSizeNapi::CreateCameraSize(env, cameraProfileSize);
        return jsResult;
    }

    return undefinedResult;
}

napi_value CameraProfileNapi::GetCameraProfileFormat(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    CameraProfileNapi* obj = nullptr;
    CameraFormat cameraProfileFormat;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    MEDIA_INFO_LOG("GetCameraProfileSize cameraProfileSize thisVar");
    if (status != napi_ok || thisVar == nullptr) {
        MEDIA_ERR_LOG("Invalid arguments!");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if ((status == napi_ok) && (obj != nullptr)) {
        cameraProfileFormat = obj->cameraProfile_->GetCameraFormat();
        MEDIA_INFO_LOG("GetCameraProfileFormat cameraProfileSize "
            "size.width = %{public}d, size.height = %{public}d, format = %{public}d",
            obj->cameraProfile_->size_.width,
            obj->cameraProfile_->size_.height,
            static_cast<int>(cameraProfileFormat));
        status = napi_create_int32(env, static_cast<int>(cameraProfileFormat), &jsResult);
        if (status == napi_ok) {
            return jsResult;
        } else {
            MEDIA_ERR_LOG("Failed to get CameraProfileFormat!, errorCode : %{public}d", status);
        }
    }

    return undefinedResult;
}

thread_local napi_ref CameraVideoProfileNapi::sVideoConstructor_ = nullptr;
thread_local VideoProfile CameraVideoProfileNapi::sVideoProfile_;

CameraVideoProfileNapi::CameraVideoProfileNapi() : env_(nullptr), wrapper_(nullptr) {}

CameraVideoProfileNapi::~CameraVideoProfileNapi()
{
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
}

void CameraVideoProfileNapi::CameraVideoProfileNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    CameraVideoProfileNapi* cameraVideoProfileNapi = reinterpret_cast<CameraVideoProfileNapi*>(nativeObject);
    if (cameraVideoProfileNapi != nullptr) {
        delete cameraVideoProfileNapi;
    }
}

napi_value CameraVideoProfileNapi::Init(napi_env env, napi_value exports)
{
    napi_status status;
    napi_value ctorObj;

    napi_property_descriptor camera_video_profile_props[] = {
        DECLARE_NAPI_GETTER("format", CameraVideoProfileNapi::GetCameraProfileFormat),
        DECLARE_NAPI_GETTER("size", CameraVideoProfileNapi::GetCameraProfileSize),
        DECLARE_NAPI_GETTER("frameRateRange", GetFrameRateRange)
    };

    status = napi_define_class(env, CAMERA_VIDEO_PROFILE_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               CameraVideoProfileNapiConstructor, nullptr,
                               sizeof(camera_video_profile_props) / sizeof(camera_video_profile_props[PARAM0]),
                               camera_video_profile_props, &ctorObj);
    if (status == napi_ok) {
        int32_t refCount = 1;
        status = napi_create_reference(env, ctorObj, refCount, &sVideoConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, CAMERA_VIDEO_PROFILE_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }

    return nullptr;
}

// Constructor callback
napi_value CameraVideoProfileNapi::CameraVideoProfileNapiConstructor(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<CameraVideoProfileNapi> obj = std::make_unique<CameraVideoProfileNapi>();
        obj->env_ = env;
        obj->videoProfile_ = sVideoProfile_;
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                           CameraVideoProfileNapi::CameraVideoProfileNapiDestructor, nullptr, &(obj->wrapper_));
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }

    return result;
}

napi_value CameraVideoProfileNapi::CreateCameraVideoProfile(napi_env env, VideoProfile &profile)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;

    status = napi_get_reference_value(env, sVideoConstructor_, &constructor);
    if (status == napi_ok) {
        sVideoProfile_ = profile;
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create Camera obj instance");
        }
    }

    napi_get_undefined(env, &result);
    return result;
}

napi_value CameraVideoProfileNapi::GetCameraProfileSize(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    CameraVideoProfileNapi* obj = nullptr;
    Size cameraProfileSize;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status != napi_ok || thisVar == nullptr) {
        MEDIA_ERR_LOG("Invalid arguments!");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if ((status == napi_ok) && (obj != nullptr)) {
        cameraProfileSize.width = obj->videoProfile_.GetSize().width;
        cameraProfileSize.height = obj->videoProfile_.GetSize().height;
        jsResult = CameraSizeNapi::CreateCameraSize(env, cameraProfileSize);
        return jsResult;
    }

    return undefinedResult;
}

napi_value CameraVideoProfileNapi::GetCameraProfileFormat(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    CameraVideoProfileNapi* obj = nullptr;
    CameraFormat CameraProfileFormat;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status != napi_ok || thisVar == nullptr) {
        MEDIA_ERR_LOG("Invalid arguments!");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if ((status == napi_ok) && (obj != nullptr)) {
        CameraProfileFormat = obj->videoProfile_.GetCameraFormat();
        status = napi_create_int32(env, CameraProfileFormat, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        } else {
            MEDIA_ERR_LOG("Failed to get CameraProfileHeight!, errorCode : %{public}d", status);
        }
    }

    return undefinedResult;
}

static napi_value CreateJSArray(napi_env env, napi_status status,
    std::vector<int32_t> nativeArray)
{
    napi_value jsArray = nullptr;
    napi_value item = nullptr;

    if (nativeArray.empty()) {
        MEDIA_ERR_LOG("nativeArray is empty");
        return jsArray;
    }

    status = napi_create_array(env, &jsArray);
    if (status == napi_ok) {
        for (size_t i = 0; i < nativeArray.size(); i++) {
            napi_create_int32(env, nativeArray[i], &item);
            MEDIA_INFO_LOG("CreateJSArray CreateCameraProfile success");
            if (napi_set_element(env, jsArray, i, item) != napi_ok) {
                MEDIA_ERR_LOG("Failed to create profile napi wrapper object");
                return nullptr;
            }
        }
    }
    return jsArray;
}

// todo: should to using CreateFrameRateRange in CreateJSArray
napi_value CameraVideoProfileNapi::GetFrameRateRange(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    CameraVideoProfileNapi* obj = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status != napi_ok || thisVar == nullptr) {
        MEDIA_ERR_LOG("Invalid arguments!");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if ((status == napi_ok) && (obj != nullptr)) {
        std::vector<int32_t> frameRanges = obj->videoProfile_.GetFrameRates();
        jsResult = CreateJSArray(env, status, frameRanges);
        if (status == napi_ok) {
            MEDIA_ERR_LOG("GetFrameRateRange success ");
            return jsResult;
        } else {
            MEDIA_ERR_LOG("Failed to get FrameRateRanges!, errorCode : %{public}d", status);
        }
    }
    return undefinedResult;
}
} // namespace CameraStandard
} // namespace OHOS
