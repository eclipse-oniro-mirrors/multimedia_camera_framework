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

#include "output/metadata_object_napi.h"

#include "camera_log.h"
#include "input/camera_input_napi.h"

namespace OHOS {
namespace CameraStandard {
thread_local napi_ref MetadataObjectNapi::sConstructor_ = nullptr;
thread_local sptr<MetadataObject> g_metadataObject;

napi_value MetadataObjectNapi::CreateMetaFaceObj(napi_env env, sptr<MetadataObject> metaObj)
{
    MEDIA_DEBUG_LOG("CreateMetaFaceObj is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    MEDIA_INFO_LOG("MetadataObjectNapi::CreateMetaFaceObj metaObjInfo: Timestamp(%{public}f), Type(%{public}d), "
                   "Rect{x(%{pulic}f),y(%{pulic}f),w(%{pulic}f),d(%{pulic}f)}",
        metaObj->GetTimestamp(), metaObj->GetType(), metaObj->GetBoundingBox().topLeftX,
        metaObj->GetBoundingBox().topLeftY, metaObj->GetBoundingBox().width, metaObj->GetBoundingBox().height);
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        g_metadataObject = metaObj;
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        g_metadataObject = nullptr;
        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create Camera obj instance");
        }
    }
    MEDIA_ERR_LOG("CreateMetaFaceObj call Failed");
    napi_get_undefined(env, &result);
    return result;
}

MetadataObjectNapi::MetadataObjectNapi() : env_(nullptr), wrapper_(nullptr) {}

MetadataObjectNapi::~MetadataObjectNapi()
{
    MEDIA_DEBUG_LOG("~MetadataObjectNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
    if (metadataObject_) {
        metadataObject_ = nullptr;
    }
}

void MetadataObjectNapi::MetadataObjectNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("MetadataObjectNapiDestructor is called");
    MetadataObjectNapi* metadataObject = reinterpret_cast<MetadataObjectNapi*>(nativeObject);
    if (metadataObject != nullptr) {
        delete metadataObject;
    }
}

napi_value MetadataObjectNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    napi_property_descriptor metadata_object_props[] = {
        DECLARE_NAPI_GETTER("type", GetType),
        DECLARE_NAPI_GETTER("timestamp", GetTimestamp),
        DECLARE_NAPI_GETTER("boundingBox", GetBoundingBox),
    };

    status = napi_define_class(env, CAMERA_METADATA_OBJECT_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
        MetadataObjectNapiConstructor, nullptr, sizeof(metadata_object_props) / sizeof(metadata_object_props[PARAM0]),
        metadata_object_props, &ctorObj);
    if (status == napi_ok) {
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, CAMERA_METADATA_OBJECT_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed");
    return nullptr;
}

napi_value MetadataObjectNapi::MetadataObjectNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("MetadataObjectNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<MetadataObjectNapi> obj = std::make_unique<MetadataObjectNapi>();
        obj->env_ = env;
        obj->metadataObject_ = g_metadataObject;
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
            MetadataObjectNapi::MetadataObjectNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("MetadataObjectNapiConstructor call Failed");
    return result;
}

sptr<MetadataObject> MetadataObjectNapi::GetMetadataObject()
{
    return metadataObject_;
}

napi_value MetadataObjectNapi::GetType(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetType is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    MetadataObjectNapi* metadataObjectNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&metadataObjectNapi));
    if (status == napi_ok && metadataObjectNapi != nullptr) {
        MetadataObjectType metadataObjType = metadataObjectNapi->metadataObject_->GetType();
        int32_t iProp;
        MapMetadataObjSupportedTypesEnum(metadataObjType, iProp);
        napi_create_int32(env, iProp, &result);
    }
    MEDIA_ERR_LOG("GetType call Failed");
    return result;
}

napi_value MetadataObjectNapi::GetTimestamp(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetTimestamp is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    MetadataObjectNapi* metadataObjectNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&metadataObjectNapi));
    if (status == napi_ok && metadataObjectNapi != nullptr) {
        double metaTimestamp = metadataObjectNapi->metadataObject_->GetTimestamp();
        napi_create_double(env, CameraNapiUtils::FloatToDouble(metaTimestamp), &result);
    }
    MEDIA_ERR_LOG("GetTimestamp call Failed");
    return result;
}

napi_value MetadataObjectNapi::GetBoundingBox(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetBoundingBox is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    MetadataObjectNapi* metadataObjectNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&metadataObjectNapi));
    if (status == napi_ok && metadataObjectNapi != nullptr) {
        Rect metaFace = metadataObjectNapi->metadataObject_->GetBoundingBox();

        napi_value propValue;

        napi_create_object(env, &result);

        napi_create_double(env, CameraNapiUtils::FloatToDouble(metaFace.topLeftX), &propValue);
        napi_set_named_property(env, result, "topLeftX", propValue);

        napi_create_double(env, CameraNapiUtils::FloatToDouble(metaFace.topLeftY), &propValue);
        napi_set_named_property(env, result, "topLeftY", propValue);

        napi_create_double(env, CameraNapiUtils::FloatToDouble(metaFace.width), &propValue);
        napi_set_named_property(env, result, "width", propValue);

        napi_create_double(env, CameraNapiUtils::FloatToDouble(metaFace.height), &propValue);
        napi_set_named_property(env, result, "height", propValue);
    }
    MEDIA_ERR_LOG("GetBoundingBox call Failed");
    return result;
}

void MetadataObjectNapi::MapMetadataObjSupportedTypesEnum(
    MetadataObjectType nativeMetadataObjType, int32_t& jsMetadataObjType)
{
    MEDIA_INFO_LOG("native metadata Object Type = %{public}d", static_cast<int32_t>(nativeMetadataObjType));
    switch (nativeMetadataObjType) {
        case MetadataObjectType::FACE:
            jsMetadataObjType = JSMetadataObjectType::FACE;
            break;
        default:
            jsMetadataObjType = -1;
            MEDIA_ERR_LOG("Native Metadata object type not supported with JS");
    }
}

void MetadataObjectNapi::MapMetadataObjSupportedTypesEnumFromJS(
    int32_t jsMetadataObjType, MetadataObjectType& nativeMetadataObjType, bool& isValid)
{
    MEDIA_INFO_LOG("JS metadata Object Type = %{public}d", jsMetadataObjType);
    switch (jsMetadataObjType) {
        case JSMetadataObjectType::FACE:
            nativeMetadataObjType = MetadataObjectType::FACE;
            break;
        default:
            isValid = false;
            MEDIA_ERR_LOG("JS Metadata object type not supported with native");
    }
}
} // namespace CameraStandard
} // namespace OHOS