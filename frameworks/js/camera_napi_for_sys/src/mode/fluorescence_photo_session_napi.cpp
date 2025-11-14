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
 
#include "mode/fluorescence_photo_session_napi.h"

#include "input/camera_manager_for_sys.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;
 
thread_local napi_ref FluorescencePhotoSessionNapi::sConstructor_ = nullptr;
 
FluorescencePhotoSessionNapi::FluorescencePhotoSessionNapi() : env_(nullptr)
{
}

FluorescencePhotoSessionNapi::~FluorescencePhotoSessionNapi()
{
    MEDIA_DEBUG_LOG("~FluorescencePhotoSessionNapi is called");
}

void FluorescencePhotoSessionNapi::FluorescencePhotoSessionNapiDestructor(napi_env env,
    void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("FluorescencePhotoSessionNapiDestructor is called");
    FluorescencePhotoSessionNapi* cameraObj = reinterpret_cast<FluorescencePhotoSessionNapi*>(nativeObject);
    if (cameraObj != nullptr) {
        delete cameraObj;
    }
}

void FluorescencePhotoSessionNapi::Init(napi_env env)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    std::vector<std::vector<napi_property_descriptor>> descriptors = {camera_process_props,
        CameraSessionForSysNapi::camera_process_sys_props, auto_exposure_props, focus_props,
        CameraSessionForSysNapi::focus_sys_props, zoom_props, CameraSessionForSysNapi::zoom_sys_props};
    std::vector<napi_property_descriptor> fluorescence_photo_session_props =
        CameraNapiUtils::GetPropertyDescriptor(descriptors);
    status = napi_define_class(env, FLUORESCENCE_PHOTO_SESSION_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               FluorescencePhotoSessionNapiConstructor, nullptr,
                               fluorescence_photo_session_props.size(),
                               fluorescence_photo_session_props.data(), &ctorObj);
    CHECK_RETURN_ELOG(status != napi_ok, "FluorescencePhotoSessionNapi defined class failed");
    status = NapiRefManager::CreateMemSafetyRef(env, ctorObj, &sConstructor_);
    CHECK_RETURN_ELOG(status != napi_ok, "FluorescencePhotoSessionNapi Init failed");
    MEDIA_DEBUG_LOG("FluorescencePhotoSessionNapi Init success");
}

napi_value FluorescencePhotoSessionNapi::CreateCameraSession(napi_env env)
{
    COMM_INFO_LOG("CreateCameraSession is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    if (sConstructor_ == nullptr) {
        FluorescencePhotoSessionNapi::Init(env);
        CHECK_RETURN_RET_ELOG(sConstructor_ == nullptr, result, "sConstructor_ is null");
    }
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sCameraSessionForSys_ =
            CameraManagerForSys::GetInstance()->CreateCaptureSessionForSys(SceneMode::FLUORESCENCE_PHOTO);
        if (sCameraSessionForSys_ == nullptr) {
            MEDIA_ERR_LOG("Failed to create Fluorescence photo session instance");
            napi_get_undefined(env, &result);
            return result;
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCameraSessionForSys_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            MEDIA_DEBUG_LOG("success to create Fluorescence photo session napi instance");
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create Fluorescence photo session napi instance");
        }
    } else {
        MEDIA_ERR_LOG("Failed to create napi reference value instance");
    }
    MEDIA_ERR_LOG("Failed to create Fluorescence photo session napi instance last");
    napi_get_undefined(env, &result);
    return result;
}
 
napi_value FluorescencePhotoSessionNapi::FluorescencePhotoSessionNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("FluorescencePhotoSessionNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;
 
    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
 
    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<FluorescencePhotoSessionNapi> obj = std::make_unique<FluorescencePhotoSessionNapi>();
        obj->env_ = env;
        CHECK_RETURN_RET_ELOG(sCameraSessionForSys_ == nullptr, result, "sCameraSessionForSys_ is null");
        obj->fluorescencePhotoSession_ = static_cast<FluorescencePhotoSession*>(sCameraSessionForSys_.GetRefPtr());
        obj->cameraSessionForSys_ = obj->fluorescencePhotoSession_;
        obj->cameraSession_ = obj->fluorescencePhotoSession_;
        CHECK_RETURN_RET_ELOG(obj->fluorescencePhotoSession_ == nullptr,
            result, "fluorescencePhotoSession_ is null");
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
            FluorescencePhotoSessionNapi::FluorescencePhotoSessionNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("FluorescencePhotoSessionNapi Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("FluorescencePhotoSessionNapi call Failed!");
    return result;
}
} // namespace CameraStandard
} // namespace OHOS