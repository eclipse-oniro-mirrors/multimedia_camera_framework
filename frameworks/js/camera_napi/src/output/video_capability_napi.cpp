/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "output/video_capability_napi.h"

#include "camera_log.h"
#include "camera_napi_param_parser.h"
#include "camera_napi_security_utils.h"
#include "camera_napi_utils.h"
#include "napi/native_common.h"
#include "napi_ref_manager.h"

namespace OHOS {
namespace CameraStandard {
thread_local napi_ref VideoCapabilityNapi::sConstructor_ = nullptr;
thread_local sptr<VideoCapability> VideoCapabilityNapi::sVideoCapability_ = nullptr;
thread_local uint32_t VideoCapabilityNapi::videoCapabilityTaskId = CAMERA_VIDEO_CAPABILITY_TASKID;

void VideoCapabilityNapi::Init(napi_env env)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;

    napi_property_descriptor video_capability_props[] = {
        DECLARE_NAPI_FUNCTION("isBFrameSupported", IsBFrameSupported),
    };

    status = napi_define_class(env, CAMERA_VIDEO_CAPABILITY_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               VideoCapabilityNapiConstructor, nullptr,
                               sizeof(video_capability_props) / sizeof(video_capability_props[PARAM0]),
                               video_capability_props, &ctorObj);
    CHECK_RETURN_ELOG(status != napi_ok, "VideoCapabilityNapi defined class failed");
    status = NapiRefManager::CreateMemSafetyRef(env, ctorObj, &sConstructor_);
    CHECK_RETURN_ELOG(status != napi_ok, "VideoCapabilityNapi Init failed");
    MEDIA_DEBUG_LOG("VideoCapabilityNapi Init success");
}

napi_value VideoCapabilityNapi::CreateVideoCapability(napi_env env, sptr<VideoCapability>& videoCapability)
{
    MEDIA_DEBUG_LOG("CreateVideoCapability is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;

    napi_get_undefined(env, &result);
    if (sConstructor_ == nullptr) {
        VideoCapabilityNapi::Init(env);
    }
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sVideoCapability_ = videoCapability;
        if (sVideoCapability_ == nullptr) {
            MEDIA_ERR_LOG("failed to create VideoCapability");
            return result;
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sVideoCapability_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create video capability instance");
        }
    }
    MEDIA_ERR_LOG("CreateVideoCapability call Failed!");
    return result;
}

// Constructor callback
napi_value VideoCapabilityNapi::VideoCapabilityNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("VideoCapabilityNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<VideoCapabilityNapi> obj = std::make_unique<VideoCapabilityNapi>();
        if (obj != nullptr) {
            obj->env_ = env;
            obj->videoCapability_ = sVideoCapability_;

            status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                               VideoCapabilityNapi::VideoCapabilityNapiDestructor, nullptr, nullptr);
            if (status == napi_ok) {
                obj.release();
                return thisVar;
            } else {
                MEDIA_ERR_LOG("Failure wrapping js to native napi");
            }
        }
    }
    MEDIA_ERR_LOG("VideoCapabilityNapiConstructor call Failed!");
    return result;
}

void VideoCapabilityNapi::VideoCapabilityNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("VideoCapabilityNapiDestructor is called");
    VideoCapabilityNapi* videoCapability = reinterpret_cast<VideoCapabilityNapi*>(nativeObject);
    if (videoCapability != nullptr) {
        delete videoCapability;
    }
}

napi_value VideoCapabilityNapi::IsBFrameSupported(napi_env env, napi_callback_info info)
{
    napi_value result = CameraNapiUtils::GetUndefinedValue(env);
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsBFrameSupported is called!");
        return result;
    }
    MEDIA_DEBUG_LOG("VideoCapabilityNapi::IsBFrameSupported is called");

    VideoCapabilityNapi* videoCapabilityNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, videoCapabilityNapi);
    if (!jsParamParser.AssertStatus(SERVICE_FATL_ERROR, "parse parameter occur error")) {
        MEDIA_ERR_LOG("VideoCapabilityNapi::IsBFrameSupported parse parameter occur error");
        return result;
    }
    if (videoCapabilityNapi->videoCapability_ == nullptr) {
        MEDIA_ERR_LOG("VideoCapabilityNapi::IsBFrameSupported get native object fail");
        CameraNapiUtils::ThrowError(env, SERVICE_FATL_ERROR, "get native object fail");
        return result;
    }
    bool isBFrameSupported = videoCapabilityNapi->videoCapability_->IsBFrameSupported();
    napi_get_boolean(env, isBFrameSupported, &result);
    return result;
}

VideoCapabilityNapi::VideoCapabilityNapi() : env_(nullptr) {}

VideoCapabilityNapi::~VideoCapabilityNapi()
{
    MEDIA_DEBUG_LOG("~VideoCapabilityNapi is called");
}
} // namespace CameraStandard
} // namespace OHOS
