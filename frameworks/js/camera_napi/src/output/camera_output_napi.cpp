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

#include "output/camera_output_napi.h"
#include <uv.h>

namespace OHOS {
namespace CameraStandard {
using namespace std;
using OHOS::HiviewDFX::HiLog;
using OHOS::HiviewDFX::HiLogLabel;

thread_local napi_ref CameraOutputCapabilityNapi::sCapabilityConstructor_ = nullptr;
thread_local sptr<CameraOutputCapability> CameraOutputCapabilityNapi::sCameraOutputCapability_ = nullptr;

CameraOutputCapabilityNapi::CameraOutputCapabilityNapi() : env_(nullptr), wrapper_(nullptr)
{
    cameraOutputCapability_ = nullptr;
}

CameraOutputCapabilityNapi::~CameraOutputCapabilityNapi()
{
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
    if (cameraOutputCapability_) {
        cameraOutputCapability_ = nullptr;
    }
}

void CameraOutputCapabilityNapi::CameraOutputCapabilityNapiDestructor(
    napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("CameraOutputCapabilityNapiDestructor enter");
    CameraOutputCapabilityNapi* cameraOutputCapabilityNapi =
        reinterpret_cast<CameraOutputCapabilityNapi*>(nativeObject);
    if (cameraOutputCapabilityNapi != nullptr) {
        delete cameraOutputCapabilityNapi;
    }
}

napi_value CameraOutputCapabilityNapi::Init(napi_env env, napi_value exports)
{
    napi_status status;
    napi_value ctorObj;

    napi_property_descriptor camera_output_capability_props[] = {
        DECLARE_NAPI_GETTER("previewProfiles", GetPreviewProfiles),
        DECLARE_NAPI_GETTER("photoProfiles", GetPhotoProfiles),
        DECLARE_NAPI_GETTER("videoProfiles", GetVideoProfiles),
        DECLARE_NAPI_GETTER("supportedMetadataObjectTypes", GetSupportedMetadataObjectTypes)
    };

    status = napi_define_class(env, CAMERA_OUTPUT_CAPABILITY_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               CameraOutputCapabilityNapiConstructor, nullptr,
                               sizeof(camera_output_capability_props) / sizeof(camera_output_capability_props[PARAM0]),
                               camera_output_capability_props, &ctorObj);
    if (status == napi_ok) {
        int32_t refCount = 1;
        status = napi_create_reference(env, ctorObj, refCount, &sCapabilityConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, CAMERA_OUTPUT_CAPABILITY_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }

    return nullptr;
}

void WrapSizeJs(napi_env env, Size &size, napi_value &result)
{
    napi_value value = nullptr;
    napi_create_int32(env, size.width, &value);
    napi_set_named_property(env, result, "width", value);
    napi_create_int32(env, size.height, &value);
    napi_set_named_property(env, result, "height", value);
}

void WrapProfileJs(napi_env env, Profile &profile, napi_value &result)
{
    napi_value sizeNapi = nullptr;
    napi_create_object(env, &result);
    napi_create_object(env, &sizeNapi);
    WrapSizeJs(env, profile.size_, sizeNapi);
    napi_value value = nullptr;
    napi_create_int32(env, profile.format_, &value);
    napi_set_named_property(env, result, "format", value);
    napi_set_named_property(env, result, "size", sizeNapi);
}

static napi_value CreateProfileJsArray(napi_env env, napi_status status, std::vector<Profile> profileList)
{
    napi_value profileArray = nullptr;

    napi_get_undefined(env, &profileArray);
    if (profileList.empty()) {
        MEDIA_ERR_LOG("profileList is empty");
        return profileArray;
    }

    status = napi_create_array(env, &profileArray);
    if (status == napi_ok) {
        for (uint32_t i = 0; i < profileList.size(); i++) {
            napi_value profile = nullptr;
            WrapProfileJs(env, profileList[i], profile);
            if (profile == nullptr || napi_set_element(env, profileArray, i, profile) != napi_ok) {
                MEDIA_ERR_LOG("Failed to create profile napi wrapper object");
                napi_get_undefined(env, &profileArray);
                return profileArray;
            }
        }
    }
    MEDIA_INFO_LOG("profileList is %{public}zu", profileList.size());
    return profileArray;
}

void WrapJsVideoProfile(napi_env env, VideoProfile &profile, napi_value &result)
{
    napi_value sizeNapi = nullptr;
    napi_create_object(env, &result);
    napi_create_object(env, &sizeNapi);
    WrapSizeJs(env, profile.size_, sizeNapi);
    napi_set_named_property(env, result, "size", sizeNapi);

    napi_value value = nullptr;
    napi_create_int32(env, profile.format_, &value);
    napi_set_named_property(env, result, "format", value);

    napi_value frameRateRange;
    napi_create_object(env, &frameRateRange);
    std::vector<int32_t> ranges = profile.framerates_;
    napi_create_int32(env, ranges[0], &value);
    napi_set_named_property(env, frameRateRange, "min", value);
    napi_create_int32(env, ranges[1], &value);
    napi_set_named_property(env, frameRateRange, "max", value);
    napi_set_named_property(env, result, "frameRateRange", frameRateRange);
}

static napi_value CreateVideoProfileJsArray(napi_env env, napi_status status, std::vector<VideoProfile> profileList)
{
    napi_value profileArray = nullptr;
    napi_value profile = nullptr;

    napi_get_undefined(env, &profileArray);
    if (profileList.empty()) {
        MEDIA_ERR_LOG("profileList is empty");
        return profileArray;
    }

    status = napi_create_array(env, &profileArray);
    if (status == napi_ok) {
        for (size_t i = 0; i < profileList.size(); i++) {
            WrapJsVideoProfile(env, profileList[i], profile);
            if (profile == nullptr || napi_set_element(env, profileArray, i, profile) != napi_ok) {
                MEDIA_ERR_LOG("Failed to create profile napi wrapper object");
                napi_get_undefined(env, &profileArray);
                return profileArray;
            }
        }
    }
    MEDIA_INFO_LOG("VideoProfileList is %{public}zu", profileList.size());
    return profileArray;
}

static napi_value CreateMetadataObjectTypeJsArray(napi_env env, napi_status status,
    std::vector<MetadataObjectType> metadataTypeList)
{
    napi_value metadataTypeArray = nullptr;
    napi_value metadataType = nullptr;

    napi_get_undefined(env, &metadataTypeArray);
    if (metadataTypeList.empty()) {
        MEDIA_ERR_LOG("metadataTypeList is empty");
        return metadataTypeArray;
    }

    status = napi_create_array(env, &metadataTypeArray);
    if (status == napi_ok) {
        for (size_t i = 0; i < metadataTypeList.size(); i++) {
            napi_create_int32(env, static_cast<int32_t>(metadataTypeList[i]), &metadataType);
            MEDIA_INFO_LOG("WrapJsVideoProfile success");
            if (metadataType == nullptr || napi_set_element(env, metadataTypeArray, i, metadataType) != napi_ok) {
                MEDIA_ERR_LOG("Failed to create metadataType napi wrapper object");
                napi_get_undefined(env, &metadataTypeArray);
                return metadataTypeArray;
            }
        }
    }
    return metadataTypeArray;
}

// Constructor callback
napi_value CameraOutputCapabilityNapi::CameraOutputCapabilityNapiConstructor(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<CameraOutputCapabilityNapi> obj = std::make_unique<CameraOutputCapabilityNapi>();
        obj->env_ = env;
        obj->cameraOutputCapability_ = sCameraOutputCapability_;
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                           CameraOutputCapabilityNapi::CameraOutputCapabilityNapiDestructor,
                           nullptr,
                           nullptr);
        if (status == napi_ok) {
            obj.release();
            MEDIA_ERR_LOG("CameraOutputCapabilityNapiConstructor Success wrapping js to native napi");
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }

    return result;
}

napi_value CameraOutputCapabilityNapi::CreateCameraOutputCapability(napi_env env, sptr<CameraDevice> camera)
{
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    if (camera == nullptr) {
        return result;
    }
    status = napi_get_reference_value(env, sCapabilityConstructor_, &constructor);
    if (status == napi_ok) {
        sCameraOutputCapability_ = CameraManager::GetInstance()->GetSupportedOutputCapability(camera);
        if (sCameraOutputCapability_ == nullptr) {
            MEDIA_ERR_LOG("failed to create CreateCameraOutputCapability");
            return result;
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCameraOutputCapability_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            MEDIA_ERR_LOG("success to create CreateCameraOutputCapabilityNapi");
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create photo output instance");
        }
    }
    MEDIA_ERR_LOG("CreateCameraOutputCapability napi_get_reference_value failed");
    napi_get_undefined(env, &result);
    return result;
}

napi_value CameraOutputCapabilityNapi::GetPreviewProfiles(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    CameraOutputCapabilityNapi* obj = nullptr;
    napi_value thisVar = nullptr;
    MEDIA_INFO_LOG("GetPreviewProfiles start!");
    napi_get_undefined(env, &undefinedResult);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    MEDIA_INFO_LOG("GetPreviewProfiles 1!");
    if (status != napi_ok || thisVar == nullptr) {
        MEDIA_INFO_LOG("Invalid arguments!");
        return undefinedResult;
    }
    MEDIA_INFO_LOG("GetPreviewProfiles 2!");
    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    MEDIA_INFO_LOG("GetPreviewProfiles 3!");
    if ((status == napi_ok) && (obj != nullptr)) {
        std::vector<Profile> profileList = obj->cameraOutputCapability_->GetPreviewProfiles();
        MEDIA_INFO_LOG("GetPreviewProfiles 4!");
        jsResult = CreateProfileJsArray(env, status, profileList);
        MEDIA_INFO_LOG("GetPreviewProfiles 5!");
        return jsResult;
    }
    MEDIA_INFO_LOG("GetPreviewProfiles 6!");
    return undefinedResult;
}

napi_value CameraOutputCapabilityNapi::GetPhotoProfiles(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    CameraOutputCapabilityNapi* obj = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status != napi_ok || thisVar == nullptr) {
        MEDIA_ERR_LOG("Invalid arguments!");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if ((status == napi_ok) && (obj != nullptr)) {
        std::vector<Profile> profileList = obj->cameraOutputCapability_->GetPhotoProfiles();
        jsResult = CreateProfileJsArray(env, status, profileList);
        return jsResult;
    }

    return undefinedResult;
}

// todo : should return VideoProfile
napi_value CameraOutputCapabilityNapi::GetVideoProfiles(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    CameraOutputCapabilityNapi* obj = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status != napi_ok || thisVar == nullptr) {
        MEDIA_ERR_LOG("Invalid arguments!");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if ((status == napi_ok) && (obj != nullptr)) {
        std::vector<VideoProfile> profileList = obj->cameraOutputCapability_->GetVideoProfiles();
        jsResult = CreateVideoProfileJsArray(env, status, profileList);
        return jsResult;
    }

    return undefinedResult;
}

napi_value CameraOutputCapabilityNapi::GetSupportedMetadataObjectTypes(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    CameraOutputCapabilityNapi* obj = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status != napi_ok || thisVar == nullptr) {
        MEDIA_ERR_LOG("Invalid arguments!");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if ((status == napi_ok) && (obj != nullptr)) {
        std::vector<MetadataObjectType> metadataTypeList;
        metadataTypeList = obj->cameraOutputCapability_->GetSupportedMetadataObjectType();
        jsResult = CreateMetadataObjectTypeJsArray(env, status, metadataTypeList);
        return jsResult;
    }

    return undefinedResult;
}
} // namespace CameraStandard
} // namespace OHOS
