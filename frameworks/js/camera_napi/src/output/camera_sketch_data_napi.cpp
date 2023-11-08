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

#include "output/camera_sketch_data_napi.h"

#include "js_native_api.h"
#include "pixel_map_napi.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;
using OHOS::HiviewDFX::HiLog;
using OHOS::HiviewDFX::HiLogLabel;

thread_local napi_ref CameraSketchDataNapi::sConstructor_ = nullptr;
thread_local unique_ptr<SketchData> CameraSketchDataNapi::sSketchData_ = nullptr;

CameraSketchDataNapi::CameraSketchDataNapi() : env_(nullptr), napiPixelMap_(nullptr) {}

CameraSketchDataNapi::~CameraSketchDataNapi()
{
    MEDIA_DEBUG_LOG("~CameraSketchData is called");
    if (napiPixelMap_ != nullptr) {
        napi_delete_reference(env_, napiPixelMap_);
        napiPixelMap_ = nullptr;
    }
}

void CameraSketchDataNapi::Release()
{
    MEDIA_DEBUG_LOG("CameraSketchDataNapi Release is called");
    if (napiPixelMap_ != nullptr) {
        napi_delete_reference(env_, napiPixelMap_);
        napiPixelMap_ = nullptr;
    }
    if (sketchData_ != nullptr) {
        sketchData_ = nullptr;
    }
}

void CameraSketchDataNapi::CameraSketchDataNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("CameraSketchDataNapiDestructor is called");
    CameraSketchDataNapi* cameraSketchDataNapi = reinterpret_cast<CameraSketchDataNapi*>(nativeObject);
    if (cameraSketchDataNapi != nullptr) {
        delete cameraSketchDataNapi;
    }
}

napi_value CameraSketchDataNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    napi_property_descriptor cameraSketchDataProps[] = { DECLARE_NAPI_GETTER("ratio", GetCameraSketchRatio),
        DECLARE_NAPI_GETTER("pixelMap", GetCameraSketchPixelMap) };

    status = napi_define_class(env, CAMERA_SKETCH_DATA_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
        CameraSketchDataNapiConstructor, nullptr, sizeof(cameraSketchDataProps) / sizeof(cameraSketchDataProps[PARAM0]),
        cameraSketchDataProps, &ctorObj);
    if (status == napi_ok) {
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, CAMERA_SKETCH_DATA_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

// Constructor callback
napi_value CameraSketchDataNapi::CameraSketchDataNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("CameraSketchDataNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<CameraSketchDataNapi> obj = std::make_unique<CameraSketchDataNapi>();
        obj->env_ = env;
        obj->sketchData_ = std::move(sSketchData_);
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
            CameraSketchDataNapi::CameraSketchDataNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("CameraSketchDataNapiConstructor call Failed!");
    return result;
}

napi_value CameraSketchDataNapi::CreateCameraSketchData(napi_env env, SketchData& sketchData)
{
    MEDIA_DEBUG_LOG("CreateCameraSketchData is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;

    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        std::unique_ptr<SketchData> sketchDataPtr = std::make_unique<SketchData>();
        sketchDataPtr->ratio = sketchData.ratio;
        sketchDataPtr->pixelMap = sketchData.pixelMap;
        sSketchData_ = std::move(sketchDataPtr);
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create Camera obj instance");
        }
    }
    MEDIA_ERR_LOG("CreateCameraSketchData call Failed!");
    napi_get_undefined(env, &result);
    return result;
}

napi_value CameraSketchDataNapi::GetCameraSketchRatio(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetCameraSketchRatio is called");
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    CameraSketchDataNapi* obj = nullptr;
    float sketchRatio = 1.0f;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status != napi_ok || thisVar == nullptr) {
        MEDIA_ERR_LOG("Invalid arguments!");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if ((status == napi_ok) && (obj != nullptr)) {
        sketchRatio = obj->sketchData_->ratio;
        MEDIA_INFO_LOG("GetCameraSketchRatio %{public}f", sketchRatio);
        status = napi_create_double(env, static_cast<double>(sketchRatio), &jsResult);
        if (status == napi_ok) {
            return jsResult;
        } else {
            MEDIA_ERR_LOG("Failed to get CameraSketchRatio!, errorCode : %{public}d", status);
        }
    }
    MEDIA_ERR_LOG("GetCameraSketchRatio call Failed!");
    return undefinedResult;
}

napi_value CameraSketchDataNapi::GetCameraSketchPixelMap(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetCameraSketchPixelMap is called");
    napi_status status;
    napi_value result = nullptr;
    CameraSketchDataNapi* obj = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status != napi_ok || thisVar == nullptr) {
        MEDIA_ERR_LOG("Invalid arguments!");
        return result;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if ((status != napi_ok) || (obj == nullptr)) {
        MEDIA_ERR_LOG("GetCameraSketchPixelMap call Failed!");
        return result;
    }

    if (obj->napiPixelMap_ != nullptr) {
        status = napi_get_reference_value(env, obj->napiPixelMap_, &result);
        if (status == napi_ok && result != nullptr) {
            MEDIA_DEBUG_LOG("GetCameraSketchPixelMap get cached pixelMap!");
            return result;
        }
    }

    if ((obj->sketchData_ != nullptr) && obj->sketchData_->pixelMap != nullptr) {
        std::shared_ptr<Media::PixelMap> pixelMap =
            std::static_pointer_cast<Media::PixelMap>(obj->sketchData_->pixelMap);
        napi_value jsResult = Media::PixelMapNapi::CreatePixelMap(obj->env_, std::move(pixelMap));
        if (jsResult == nullptr) {
            MEDIA_ERR_LOG("ImageNapi Create failed");
            return result;
        }
        napi_create_reference(env, jsResult, 1, &obj->napiPixelMap_);
        obj->sketchData_->pixelMap = nullptr;
        return jsResult;
    }
    MEDIA_ERR_LOG("GetCameraSketchPixelMap call Failed! Unknown error");
    return result;
}
} // namespace CameraStandard
} // namespace OHOS
