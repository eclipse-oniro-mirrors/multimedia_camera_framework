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

#include <uv.h>

#include "camera_napi_param_parser.h"
#include "input/camera_manager_for_sys.h"
#include "camera_napi_template_utils.h"
#include "mode/time_lapse_photo_session_napi.h"
#include "napi/native_node_api.h"

using namespace std;

namespace {
template<typename T>
T* Unwrap(napi_env env, napi_value jsObject)
{
    void *result;
    napi_unwrap(env, jsObject, &result);
    return reinterpret_cast<T*>(result);
}
}

namespace OHOS {
namespace CameraStandard {
thread_local napi_ref TimeLapsePhotoSessionNapi::sConstructor_{nullptr};
thread_local napi_ref TryAEInfoNapi::sConstructor_{nullptr};

const unordered_map<string, TimeLapseRecordState> TimeLapseRecordStateMap = {
    {"IDLE", TimeLapseRecordState::IDLE },
    {"RECORDING", TimeLapseRecordState::RECORDING },
};

const unordered_map<string, TimeLapsePreviewType> TimeLapsePreviewTypeMap = {
    {"DARK", TimeLapsePreviewType::DARK},
    {"LIGHT", TimeLapsePreviewType::LIGHT},
};

TryAEInfoNapi::TryAEInfoNapi() {}

TryAEInfoNapi::~TryAEInfoNapi()
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    if (tryAEInfo_) {
        tryAEInfo_ = nullptr;
    }
}

void TryAEInfoNapi::Init(napi_env env)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    napi_status status;
    napi_value ctorObj;

    napi_property_descriptor try_ae_info_properties[] = {
        DECLARE_NAPI_GETTER("isTryAEDone", IsTryAEDone),
        DECLARE_NAPI_GETTER("isTryAEHintNeeded", IsTryAEHintNeeded),
        DECLARE_NAPI_GETTER("previewType", GetPreviewType),
        DECLARE_NAPI_GETTER("captureInterval", GetCaptureInterval),
    };

    status = napi_define_class(env, TRY_AE_INFO_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               Constructor, nullptr,
                               sizeof(try_ae_info_properties) / sizeof(try_ae_info_properties[PARAM0]),
                               try_ae_info_properties, &ctorObj);
    CHECK_RETURN_ELOG(status != napi_ok, "TryAEInfoNapi defined class failed");
    int32_t refCount = 1;
    status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
    CHECK_RETURN_ELOG(status != napi_ok, "TryAEInfoNapi Init failed");
    MEDIA_DEBUG_LOG("TryAEInfoNapi Init success");
}

napi_value TryAEInfoNapi::NewInstance(napi_env env)
{
    CAMERA_NAPI_VALUE result = nullptr;
    CAMERA_NAPI_VALUE constructor;
    if (sConstructor_ == nullptr) {
        TryAEInfoNapi::Init(env);
        CHECK_RETURN_RET_ELOG(sConstructor_ == nullptr, result, "sConstructor_ is null");
    }
    CHECK_EXECUTE(napi_get_reference_value(env, sConstructor_, &constructor) == napi_ok,
        napi_new_instance(env, constructor, 0, nullptr, &result));
    return result;
}

napi_value TryAEInfoNapi::IsTryAEDone(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    napi_status status;
    napi_value thisVar;
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    TryAEInfoNapi* obj = Unwrap<TryAEInfoNapi>(env, thisVar);
    CHECK_RETURN_RET_ELOG(obj == nullptr || obj->tryAEInfo_ == nullptr, nullptr,
        "%{public}s: Unwrap Napi Object Failed", __FUNCTION__);
    auto value = obj->tryAEInfo_->isTryAEDone;
    napi_value result;
    napi_get_boolean(env, value, &result);
    return result;
}

napi_value TryAEInfoNapi::IsTryAEHintNeeded(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    napi_status status;
    napi_value thisVar;
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    TryAEInfoNapi* obj = Unwrap<TryAEInfoNapi>(env, thisVar);
    CHECK_RETURN_RET_ELOG(obj == nullptr || obj->tryAEInfo_ == nullptr, nullptr,
        "%{public}s: Unwrap Napi Object Failed", __FUNCTION__);
    auto value = obj->tryAEInfo_->isTryAEHintNeeded;
    napi_value result;
    napi_get_boolean(env, value, &result);
    return result;
}

napi_value TryAEInfoNapi::GetPreviewType(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    napi_status status;
    napi_value thisVar;
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    TryAEInfoNapi* obj = Unwrap<TryAEInfoNapi>(env, thisVar);
    CHECK_RETURN_RET_ELOG(obj == nullptr || obj->tryAEInfo_ == nullptr, nullptr,
        "%{public}s: Unwrap Napi Object Failed", __FUNCTION__);
    auto value = obj->tryAEInfo_->previewType;
    napi_value result;
    napi_create_int32(env, static_cast<int32_t>(value), &result);
    return result;
}

napi_value TryAEInfoNapi::GetCaptureInterval(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    napi_status status;
    napi_value thisVar;
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    TryAEInfoNapi* obj = Unwrap<TryAEInfoNapi>(env, thisVar);
    CHECK_RETURN_RET_ELOG(obj == nullptr || obj->tryAEInfo_ == nullptr, nullptr,
        "%{public}s: Unwrap Napi Object Failed", __FUNCTION__);
    auto value = obj->tryAEInfo_->captureInterval;
    napi_value result;
    napi_create_int32(env, value, &result);
    return result;
}

napi_value TryAEInfoNapi::Constructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    napi_status status;
    napi_value thisVar;
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        auto obj = std::make_unique<TryAEInfoNapi>();
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                           Destructor, nullptr, nullptr);
        if (status == napi_ok) {
            (void)obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("%{public}s: Failed", __FUNCTION__);
    return nullptr;
}

void TryAEInfoNapi::Destructor(napi_env env, void* nativeObject, void* finalize)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    TryAEInfoNapi* obj = reinterpret_cast<TryAEInfoNapi*>(nativeObject);
    if (obj != nullptr) {
        delete obj;
    }
}

TimeLapsePhotoSessionNapi::TimeLapsePhotoSessionNapi() {}

TimeLapsePhotoSessionNapi::~TimeLapsePhotoSessionNapi()
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    if (timeLapsePhotoSession_) {
        timeLapsePhotoSession_ = nullptr;
    }
}

const vector<napi_property_descriptor> TimeLapsePhotoSessionNapi::time_lapse_photo_props = {
    // TimeLapsePhotoSession properties
    DECLARE_NAPI_FUNCTION("on", On),
    DECLARE_NAPI_FUNCTION("off", Off),
    DECLARE_NAPI_FUNCTION("isTryAENeeded", IsTryAENeeded),
    DECLARE_NAPI_FUNCTION("startTryAE", StartTryAE),
    DECLARE_NAPI_FUNCTION("stopTryAE", StopTryAE),
    DECLARE_NAPI_FUNCTION("getSupportedTimeLapseIntervalRange", GetSupportedTimeLapseIntervalRange),
    DECLARE_NAPI_FUNCTION("getTimeLapseInterval", GetTimeLapseInterval),
    DECLARE_NAPI_FUNCTION("setTimeLapseInterval", SetTimeLapseInterval),
    DECLARE_NAPI_FUNCTION("setTimeLapseRecordState", SetTimeLapseRecordState),
    DECLARE_NAPI_FUNCTION("setTimeLapsePreviewType", SetTimeLapsePreviewType),
};

const vector<napi_property_descriptor> TimeLapsePhotoSessionNapi::manual_exposure_props = {
    // ManualExposure properties
    DECLARE_NAPI_FUNCTION("getExposure", GetExposure),
    DECLARE_NAPI_FUNCTION("setExposure", SetExposure),
    DECLARE_NAPI_FUNCTION("getSupportedExposureRange", GetSupportedExposureRange),
    DECLARE_NAPI_FUNCTION("getSupportedMeteringModes", GetSupportedMeteringModes),
    DECLARE_NAPI_FUNCTION("isExposureMeteringModeSupported", IsExposureMeteringModeSupported),
    DECLARE_NAPI_FUNCTION("getExposureMeteringMode", GetExposureMeteringMode),
    DECLARE_NAPI_FUNCTION("setExposureMeteringMode", SetExposureMeteringMode),
};

const vector<napi_property_descriptor> TimeLapsePhotoSessionNapi::manual_iso_props = {
    // ManualIso properties
    DECLARE_NAPI_FUNCTION("getIso", GetIso),
    DECLARE_NAPI_FUNCTION("setIso", SetIso),
    DECLARE_NAPI_FUNCTION("isManualIsoSupported", IsManualIsoSupported),
    DECLARE_NAPI_FUNCTION("getIsoRange", GetIsoRange),
};

void TimeLapsePhotoSessionNapi::Init(napi_env env)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    napi_status status;
    napi_value ctorObj;
    vector<vector<napi_property_descriptor>> descriptors = {
        camera_process_props, CameraSessionForSysNapi::camera_process_sys_props,
        flash_props, CameraSessionForSysNapi::flash_sys_props,
        auto_exposure_props,
        focus_props, CameraSessionForSysNapi::focus_sys_props,
        zoom_props, CameraSessionForSysNapi::zoom_sys_props,
        color_effect_sys_props,
        manual_focus_sys_props,
        time_lapse_photo_props,
        manual_exposure_props,
        manual_iso_props,
        white_balance_props
    };
    vector<napi_property_descriptor> properties = CameraNapiUtils::GetPropertyDescriptor(descriptors);
    status = napi_define_class(env, TIME_LAPSE_PHOTO_SESSION_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               Constructor, nullptr,
                               properties.size(),
                               properties.data(), &ctorObj);
    CHECK_RETURN_ELOG(status != napi_ok, "TimeLapsePhotoSessionNapi defined class failed");
    int32_t refCount = 1;
    status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
    CHECK_RETURN_ELOG(status != napi_ok, "TimeLapsePhotoSessionNapi Init failed");
    MEDIA_DEBUG_LOG("TimeLapsePhotoSessionNapi Init success");
}

napi_value TimeLapsePhotoSessionNapi::CreateCameraSession(napi_env env)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    if (sConstructor_ == nullptr) {
        TimeLapsePhotoSessionNapi::Init(env);
        CHECK_RETURN_RET_ELOG(sConstructor_ == nullptr, result, "sConstructor_ is null");
    }
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sCameraSessionForSys_ =
            CameraManagerForSys::GetInstance()->CreateCaptureSessionForSys(SceneMode::TIMELAPSE_PHOTO);
        if (sCameraSessionForSys_ == nullptr) {
            MEDIA_ERR_LOG("TimeLapsePhotoSessionNapi::CreateCameraSession Failed to create instance");
            napi_get_undefined(env, &result);
            return result;
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCameraSessionForSys_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            MEDIA_DEBUG_LOG("TimeLapsePhotoSessionNapi::CreateCameraSession success to create napi instance");
            return result;
        } else {
            MEDIA_ERR_LOG("TimeLapsePhotoSessionNapi::CreateCameraSession Failed to create napi instance");
        }
    }
    MEDIA_ERR_LOG("TimeLapsePhotoSessionNapi::CreateCameraSession Failed to create napi instance last");
    napi_get_undefined(env, &result);
    return result;
}

napi_value TimeLapsePhotoSessionNapi::On(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<CameraSessionNapi>::On(env, info);
}

napi_value TimeLapsePhotoSessionNapi::Off(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<CameraSessionNapi>::Off(env, info);
}

napi_value TimeLapsePhotoSessionNapi::IsTryAENeeded(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    napi_status status;
    napi_value thisVar;
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    TimeLapsePhotoSessionNapi* obj = Unwrap<TimeLapsePhotoSessionNapi>(env, thisVar);
    CHECK_RETURN_RET_ELOG(obj == nullptr, nullptr, "%{public}s: Unwrap Napi Object Failed", __FUNCTION__);
    bool needed;
    int32_t ret = obj->timeLapsePhotoSession_->IsTryAENeeded(needed);
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, nullptr,
        "%{public}s: IsTryAENeeded() Failed", __FUNCTION__);
    napi_value result;
    CHECK_PRINT_ELOG(napi_get_boolean(env, ret, &result) != napi_ok,
        "%{public}s: Napi Get Boolean Failed", __FUNCTION__);
    return result;
}

napi_value TimeLapsePhotoSessionNapi::StartTryAE(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    napi_status status;
    napi_value thisVar;
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    TimeLapsePhotoSessionNapi* timeLapseObj  = Unwrap<TimeLapsePhotoSessionNapi>(env, thisVar);
    CHECK_RETURN_RET_ELOG(timeLapseObj  == nullptr, nullptr,
        "%{public}s: Unwrap Napi Object Failed", __FUNCTION__);
    timeLapseObj ->timeLapsePhotoSession_->LockForControl();
    int32_t ret = timeLapseObj ->timeLapsePhotoSession_->StartTryAE();
    timeLapseObj ->timeLapsePhotoSession_->UnlockForControl();
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, nullptr,
        "%{public}s: StartTryAE() Failed", __FUNCTION__);
    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

napi_value TimeLapsePhotoSessionNapi::StopTryAE(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    napi_status status;
    napi_value thisVar;
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    TimeLapsePhotoSessionNapi* obj = Unwrap<TimeLapsePhotoSessionNapi>(env, thisVar);
    CHECK_RETURN_RET_ELOG(obj == nullptr, nullptr, "%{public}s: Unwrap Napi Object Failed", __FUNCTION__);
    obj->timeLapsePhotoSession_->LockForControl();
    int32_t ret = obj->timeLapsePhotoSession_->StopTryAE();
    obj->timeLapsePhotoSession_->UnlockForControl();
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, nullptr,
        "%{public}s: StopTryAE() Failed", __FUNCTION__);
    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

napi_value TimeLapsePhotoSessionNapi::GetSupportedTimeLapseIntervalRange(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    napi_status status;
    napi_value thisVar;
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    TimeLapsePhotoSessionNapi* timeLapsePhotoObj = Unwrap<TimeLapsePhotoSessionNapi>(env, thisVar);
    CHECK_RETURN_RET_ELOG(timeLapsePhotoObj == nullptr,
        nullptr, "%{public}s: Unwrap Napi Object Failed", __FUNCTION__);
    vector<int32_t> range;
    int32_t ret = timeLapsePhotoObj->timeLapsePhotoSession_->GetSupportedTimeLapseIntervalRange(range);
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, nullptr,
        "%{public}s: GetSupportedTimeLapseIntervalRange() Failed", __FUNCTION__);
    napi_value timeLapseIntervalRangeResult;
    if (napi_create_array_with_length(env, range.size(), &timeLapseIntervalRangeResult) == napi_ok) {
        napi_value value;
        for (uint32_t i = 0; i < range.size(); i++) {
            napi_create_int32(env, range[i], &value);
            napi_set_element(env, timeLapseIntervalRangeResult, i, value);
        }
    } else {
        MEDIA_ERR_LOG("%{public}s: Napi Create Array With Length Failed", __FUNCTION__);
    }
    return timeLapseIntervalRangeResult;
}

napi_value TimeLapsePhotoSessionNapi::GetTimeLapseInterval(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    napi_status status;
    napi_value thisVar;
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    TimeLapsePhotoSessionNapi* obj = Unwrap<TimeLapsePhotoSessionNapi>(env, thisVar);
    CHECK_RETURN_RET_ELOG(obj == nullptr, nullptr, "%{public}s: Unwrap Napi Object Failed", __FUNCTION__);
    int32_t interval;
    int32_t ret = obj->timeLapsePhotoSession_->GetTimeLapseInterval(interval);
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, nullptr,
        "%{public}s: GetTimeLapseInterval() Failed", __FUNCTION__);
    napi_value result;
    CHECK_PRINT_ELOG(napi_create_int32(env, interval, &result) != napi_ok,
        "%{public}s: Napi Create Int32 Failed", __FUNCTION__);
    return result;
}

napi_value TimeLapsePhotoSessionNapi::SetTimeLapseInterval(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    TimeLapsePhotoSessionNapi* obj;
    int32_t interval;
    CameraNapiParamParser parser(env, info, obj, interval);
    CHECK_RETURN_RET_ELOG(!parser.AssertStatus(INVALID_ARGUMENT, "Invalid argument!"), nullptr,
        "%{public}s: Read Params Error", __FUNCTION__);
    MEDIA_DEBUG_LOG("interval = %{public}d", interval);
    obj->timeLapsePhotoSession_->LockForControl();
    int32_t ret = obj->timeLapsePhotoSession_->SetTimeLapseInterval(interval);
    obj->timeLapsePhotoSession_->UnlockForControl();
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, nullptr,
        "%{public}s: SetTimeLapseInterval() Failed", __FUNCTION__);
    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

napi_value TimeLapsePhotoSessionNapi::SetTimeLapseRecordState(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    TimeLapsePhotoSessionNapi* obj;
    int32_t state;
    CameraNapiParamParser parser(env, info, obj, state);
    CHECK_RETURN_RET_ELOG(!parser.AssertStatus(INVALID_ARGUMENT, "Invalid argument!"), nullptr,
        "%{public}s: Read Params Error", __FUNCTION__);
    MEDIA_DEBUG_LOG("state = %{public}d", state);
    obj->timeLapsePhotoSession_->LockForControl();
    int32_t ret = obj->timeLapsePhotoSession_->SetTimeLapseRecordState(static_cast<TimeLapseRecordState>(state));
    obj->timeLapsePhotoSession_->UnlockForControl();
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, nullptr,
        "%{public}s: SetTimeLapseRecordState() Failed", __FUNCTION__);
    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

napi_value TimeLapsePhotoSessionNapi::SetTimeLapsePreviewType(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    TimeLapsePhotoSessionNapi* obj;
    int32_t type;
    CameraNapiParamParser parser(env, info, obj, type);
    CHECK_RETURN_RET_ELOG(!parser.AssertStatus(INVALID_ARGUMENT, "Invalid argument!"), nullptr,
        "%{public}s: Read Params Error", __FUNCTION__);
    MEDIA_DEBUG_LOG("type = %{public}d", type);
    obj->timeLapsePhotoSession_->LockForControl();
    int32_t ret = obj->timeLapsePhotoSession_->SetTimeLapsePreviewType(static_cast<TimeLapsePreviewType>(type));
    obj->timeLapsePhotoSession_->UnlockForControl();
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, nullptr,
        "%{public}s: SetTimeLapsePreviewType() Failed", __FUNCTION__);
    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

// ManualExposure
napi_value TimeLapsePhotoSessionNapi::GetExposure(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    napi_status status;
    napi_value thisVar;
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    TimeLapsePhotoSessionNapi* obj = Unwrap<TimeLapsePhotoSessionNapi>(env, thisVar);
    CHECK_RETURN_RET_ELOG(obj == nullptr, nullptr,
        "%{public}s: Unwrap Napi Object Failed", __FUNCTION__);
    uint32_t exposure;
    int32_t ret = obj->timeLapsePhotoSession_->GetExposure(exposure);
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, nullptr,
        "%{public}s: getExposure() Failed", __FUNCTION__);
    napi_value result;
    CHECK_PRINT_ELOG(napi_create_uint32(env, exposure, &result) != napi_ok,
        "%{public}s: Napi Create Double Failed", __FUNCTION__);
    return result;
}

napi_value TimeLapsePhotoSessionNapi::SetExposure(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    TimeLapsePhotoSessionNapi* obj;
    uint32_t exposure;
    CameraNapiParamParser parser(env, info, obj, exposure);
    CHECK_RETURN_RET_ELOG(!parser.AssertStatus(INVALID_ARGUMENT, "Invalid argument!"),
        nullptr, "%{public}s: Read Params Error", __FUNCTION__);
    MEDIA_DEBUG_LOG("exposure = %{public}d", exposure);
    obj->timeLapsePhotoSession_->LockForControl();
    int32_t ret = obj->timeLapsePhotoSession_->SetExposure(exposure);
    obj->timeLapsePhotoSession_->UnlockForControl();
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, nullptr,
        "%{public}s: setExposure() Failed", __FUNCTION__);
    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

napi_value TimeLapsePhotoSessionNapi::GetSupportedExposureRange(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    napi_status status;
    napi_value thisVar;
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    TimeLapsePhotoSessionNapi* obj = Unwrap<TimeLapsePhotoSessionNapi>(env, thisVar);
    CHECK_RETURN_RET_ELOG(obj == nullptr, nullptr, "%{public}s: Unwrap Napi Object Failed", __FUNCTION__);
    vector<uint32_t> range;
    int32_t ret = obj->timeLapsePhotoSession_->GetSupportedExposureRange(range);
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, nullptr,
        "%{public}s: getSupportedExposureRange() Failed", __FUNCTION__);
    napi_value result;
    if (napi_create_array_with_length(env, range.size(), &result) == napi_ok) {
        napi_value value;
        for (uint32_t i = 0; i < range.size(); i++) {
            napi_create_uint32(env, range[i], &value);
            napi_set_element(env, result, i, value);
        }
    } else {
        MEDIA_ERR_LOG("%{public}s: Napi Create Array With Length Failed", __FUNCTION__);
    }
    return result;
}

napi_value TimeLapsePhotoSessionNapi::GetSupportedMeteringModes(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    napi_status status;
    napi_value thisVar;
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    TimeLapsePhotoSessionNapi* obj = Unwrap<TimeLapsePhotoSessionNapi>(env, thisVar);
    CHECK_RETURN_RET_ELOG(obj == nullptr, nullptr,
        "%{public}s: Unwrap Napi Object Failed", __FUNCTION__);
    vector<MeteringMode> modes;
    int32_t ret = obj->timeLapsePhotoSession_->GetSupportedMeteringModes(modes);
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, nullptr,
        "%{public}s: GetSupportedMeteringModes() Failed", __FUNCTION__);
    napi_value result;
    if (napi_create_array_with_length(env, modes.size(), &result) == napi_ok) {
        napi_value value;
        for (uint32_t i = 0; i < modes.size(); i++) {
            napi_create_int32(env, modes[i], &value);
            napi_set_element(env, result, i, value);
        }
    } else {
        MEDIA_ERR_LOG("%{public}s: Napi Create Array With Length Failed", __FUNCTION__);
    }
    return result;
}

napi_value TimeLapsePhotoSessionNapi::IsExposureMeteringModeSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    TimeLapsePhotoSessionNapi* obj;
    int32_t mode;
    CameraNapiParamParser parser(env, info, obj, mode);
    CHECK_RETURN_RET_ELOG(!parser.AssertStatus(INVALID_ARGUMENT, "Invalid argument!"),
        nullptr, "%{public}s: Read Params Error", __FUNCTION__);
    bool supported;
    int32_t ret = obj->timeLapsePhotoSession_->IsExposureMeteringModeSupported(
        static_cast<MeteringMode>(mode), supported);
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, nullptr,
        "%{public}s: IsExposureMeteringModeSupported() Failed", __FUNCTION__);
    napi_value result;
    CHECK_PRINT_ELOG(napi_get_boolean(env, supported, &result) != napi_ok,
        "%{public}s: Napi Get Boolean Failed", __FUNCTION__);
    return result;
}

napi_value TimeLapsePhotoSessionNapi::GetExposureMeteringMode(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    TimeLapsePhotoSessionNapi* obj;
    CameraNapiParamParser parser(env, info, obj);
    CHECK_RETURN_RET_ELOG(!parser.AssertStatus(INVALID_ARGUMENT, "Invalid argument!"), nullptr,
        "%{public}s: Read Params Error", __FUNCTION__);
    MeteringMode mode;
    int32_t ret = obj->timeLapsePhotoSession_->GetExposureMeteringMode(mode);
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, nullptr,
        "%{public}s: GetExposureMeteringMode() Failed", __FUNCTION__);
    napi_value result;
    CHECK_PRINT_ELOG(napi_create_int32(env, static_cast<int32_t>(mode), &result) != napi_ok,
        "%{public}s: Napi Create Int32 Failed", __FUNCTION__);
    return result;
}

napi_value TimeLapsePhotoSessionNapi::SetExposureMeteringMode(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    TimeLapsePhotoSessionNapi* obj;
    int32_t meteringMode;
    CameraNapiParamParser parser(env, info, obj, meteringMode);
    CHECK_RETURN_RET_ELOG(!parser.AssertStatus(INVALID_ARGUMENT, "Invalid argument!"),
        nullptr, "%{public}s: Read Params Error", __FUNCTION__);
    MEDIA_DEBUG_LOG("meteringMode = %{public}d", meteringMode);
    obj->timeLapsePhotoSession_->LockForControl();
    int32_t ret = obj->timeLapsePhotoSession_->SetExposureMeteringMode(static_cast<MeteringMode>(meteringMode));
    obj->timeLapsePhotoSession_->UnlockForControl();
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, nullptr,
        "%{public}s: SetExposureMeteringMode() Failed", __FUNCTION__);
    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

// ManualIso
napi_value TimeLapsePhotoSessionNapi::GetIso(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    napi_status status;
    napi_value thisVar;
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    TimeLapsePhotoSessionNapi* obj = Unwrap<TimeLapsePhotoSessionNapi>(env, thisVar);
    CHECK_RETURN_RET_ELOG(obj == nullptr,
        nullptr, "%{public}s: Unwrap Napi Object Failed", __FUNCTION__);
    int32_t iso;
    int32_t ret = obj->timeLapsePhotoSession_->GetIso(iso);
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, nullptr,
        "%{public}s: getIso() Failed", __FUNCTION__);
    napi_value result;
    CHECK_PRINT_ELOG(napi_create_int32(env, iso, &result) != napi_ok,
        "%{public}s: Napi Create Int32 Failed", __FUNCTION__);
    return result;
}

napi_value TimeLapsePhotoSessionNapi::SetIso(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    TimeLapsePhotoSessionNapi* obj;
    int32_t iso;
    CameraNapiParamParser parser(env, info, obj, iso);
    CHECK_RETURN_RET_ELOG(!parser.AssertStatus(INVALID_ARGUMENT, "Invalid argument!"),
        nullptr, "%{public}s: Read Params Error", __FUNCTION__);
    MEDIA_DEBUG_LOG("iso = %{public}d", iso);
    obj->timeLapsePhotoSession_->LockForControl();
    int32_t ret = obj->timeLapsePhotoSession_->SetIso(iso);
    obj->timeLapsePhotoSession_->UnlockForControl();
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, nullptr, "%{public}s: setIso() Failed", __FUNCTION__);
    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

napi_value TimeLapsePhotoSessionNapi::IsManualIsoSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    napi_status status;
    napi_value thisVar;
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    TimeLapsePhotoSessionNapi* obj = Unwrap<TimeLapsePhotoSessionNapi>(env, thisVar);
    CHECK_RETURN_RET_ELOG(obj == nullptr, nullptr, "%{public}s: Unwrap Napi Object Failed", __FUNCTION__);
    bool supported;
    int32_t ret = obj->timeLapsePhotoSession_->IsManualIsoSupported(supported);
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, nullptr,
        "%{public}s: isManualIsoSupported() Failed", __FUNCTION__);
    napi_value result;
    CHECK_PRINT_ELOG(napi_get_boolean(env, supported, &result) != napi_ok,
        "%{public}s: Napi Get Boolean Failed", __FUNCTION__);
    return result;
}

napi_value TimeLapsePhotoSessionNapi::GetIsoRange(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    napi_status status;
    napi_value thisVar;
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    TimeLapsePhotoSessionNapi* timeLapsePhotoSessionObj = Unwrap<TimeLapsePhotoSessionNapi>(env, thisVar);
    CHECK_RETURN_RET_ELOG(timeLapsePhotoSessionObj == nullptr, nullptr,
        "%{public}s: Unwrap Napi Object Failed", __FUNCTION__);
    vector<int32_t> range;
    int32_t ret = timeLapsePhotoSessionObj->timeLapsePhotoSession_->GetIsoRange(range);
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, nullptr,
        "%{public}s: getIsoRange() Failed", __FUNCTION__);
    napi_value isoRangeResult;
    if (napi_create_array_with_length(env, range.size(), &isoRangeResult) == napi_ok) {
        napi_value value;
        for (uint32_t i = 0; i < range.size(); i++) {
            napi_create_int32(env, range[i], &value);
            napi_set_element(env, isoRangeResult, i, value);
        }
    } else {
        MEDIA_ERR_LOG("%{public}s: Napi Create Array With Length Failed", __FUNCTION__);
    }
    return isoRangeResult;
}

// WhiteBalance
napi_value TimeLapsePhotoSessionNapi::IsWhiteBalanceModeSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    size_t argc;
    napi_value argv[1];
    napi_value thisVar;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    TimeLapsePhotoSessionNapi* obj = Unwrap<TimeLapsePhotoSessionNapi>(env, thisVar);
    CHECK_RETURN_RET_ELOG(obj == nullptr, nullptr, "%{public}s: Unwrap Napi Object Failed", __FUNCTION__);
    int32_t mode;
    napi_get_value_int32(env, argv[0], &mode);
    bool supported;
    int32_t ret = obj->timeLapsePhotoSession_->IsWhiteBalanceModeSupported(
        static_cast<WhiteBalanceMode>(mode), supported);
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, nullptr,
        "%{public}s: isWhiteBalanceModeSupported() Failed", __FUNCTION__);
    napi_value result;
    CHECK_PRINT_ELOG(napi_get_boolean(env, supported, &result) != napi_ok,
        "%{public}s: Napi Get Boolean Failed", __FUNCTION__);
    return result;
}

napi_value TimeLapsePhotoSessionNapi::GetWhiteBalanceRange(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    napi_status status;
    napi_value thisVar;
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    TimeLapsePhotoSessionNapi* obj = Unwrap<TimeLapsePhotoSessionNapi>(env, thisVar);
    CHECK_RETURN_RET_ELOG(obj == nullptr, nullptr, "%{public}s: Unwrap Napi Object Failed", __FUNCTION__);
    vector<int32_t> range;
    int32_t ret = obj->timeLapsePhotoSession_->GetWhiteBalanceRange(range);
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, nullptr,
        "%{public}s: getWhiteBalanceRange() Failed", __FUNCTION__);
    napi_value whiteBalanceRangeResult;
    if (napi_create_array_with_length(env, range.size(), &whiteBalanceRangeResult) == napi_ok) {
        napi_value value;
        for (uint32_t i = 0; i < range.size(); i++) {
            napi_create_int32(env, range[i], &value);
            napi_set_element(env, whiteBalanceRangeResult, i, value);
        }
    } else {
        MEDIA_ERR_LOG("%{public}s: Napi Create Array With Length Failed", __FUNCTION__);
    }
    return whiteBalanceRangeResult;
}

napi_value TimeLapsePhotoSessionNapi::GetWhiteBalanceMode(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    napi_status status;
    napi_value thisVar;
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    TimeLapsePhotoSessionNapi* obj = Unwrap<TimeLapsePhotoSessionNapi>(env, thisVar);
    CHECK_RETURN_RET_ELOG(obj == nullptr, nullptr, "%{public}s: Unwrap Napi Object Failed", __FUNCTION__);
    WhiteBalanceMode mode;
    int32_t ret = obj->timeLapsePhotoSession_->GetWhiteBalanceMode(mode);
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, nullptr,
        "%{public}s: getWhiteBalanceMode() Failed", __FUNCTION__);
    napi_value result;
    CHECK_PRINT_ELOG(napi_create_int32(env, static_cast<int32_t>(mode), &result) != napi_ok,
        "%{public}s: Napi Create Int32 Failed", __FUNCTION__);
    return result;
}

napi_value TimeLapsePhotoSessionNapi::SetWhiteBalanceMode(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    TimeLapsePhotoSessionNapi* obj;
    int32_t whiteBalanceMode;
    CameraNapiParamParser parser(env, info, obj, whiteBalanceMode);
    CHECK_RETURN_RET_ELOG(!parser.AssertStatus(INVALID_ARGUMENT, "Invalid argument!"), nullptr,
        "%{public}s: Read Params Error", __FUNCTION__);
    MEDIA_DEBUG_LOG("whiteBalanceMode = %{public}d", whiteBalanceMode);
    obj->timeLapsePhotoSession_->LockForControl();
    int32_t ret = obj->timeLapsePhotoSession_->SetWhiteBalanceMode(static_cast<WhiteBalanceMode>(whiteBalanceMode));
    obj->timeLapsePhotoSession_->UnlockForControl();
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, nullptr,
        "%{public}s: setWhiteBalanceMode() Failed", __FUNCTION__);
    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

napi_value TimeLapsePhotoSessionNapi::GetWhiteBalance(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    napi_status status;
    napi_value thisVar;
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    TimeLapsePhotoSessionNapi* obj = Unwrap<TimeLapsePhotoSessionNapi>(env, thisVar);
    CHECK_RETURN_RET_ELOG(obj == nullptr, nullptr, "%{public}s: Unwrap Napi Object Failed", __FUNCTION__);
    int32_t balance;
    int32_t ret = obj->timeLapsePhotoSession_->GetWhiteBalance(balance);
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, nullptr,
        "%{public}s: getWhiteBalance() Failed", __FUNCTION__);
    napi_value result;
    CHECK_PRINT_ELOG(napi_create_int32(env, balance, &result) != napi_ok,
        "%{public}s: Napi Create Int32 Failed", __FUNCTION__);
    return result;
}

napi_value TimeLapsePhotoSessionNapi::SetWhiteBalance(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    TimeLapsePhotoSessionNapi* obj;
    int32_t balance;
    CameraNapiParamParser parser(env, info, obj, balance);
    CHECK_RETURN_RET_ELOG(!parser.AssertStatus(INVALID_ARGUMENT, "Invalid argument!"), nullptr,
        "%{public}s: Read Params Error", __FUNCTION__);
    MEDIA_DEBUG_LOG("balance = %{public}d", balance);
    obj->timeLapsePhotoSession_->LockForControl();
    int32_t ret = obj->timeLapsePhotoSession_->SetWhiteBalance(balance);
    obj->timeLapsePhotoSession_->UnlockForControl();
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, nullptr,
        "%{public}s: setWhiteBalance() Failed", __FUNCTION__);
    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

napi_value TimeLapsePhotoSessionNapi::Constructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    napi_status status;
    napi_value thisVar;
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        auto obj = std::make_unique<TimeLapsePhotoSessionNapi>();
        obj->env_ = env;
        CHECK_RETURN_RET_ELOG(sCameraSessionForSys_ == nullptr, nullptr, "sCameraSessionForSys_ is null");
        obj->timeLapsePhotoSession_ = static_cast<TimeLapsePhotoSession*>(sCameraSessionForSys_.GetRefPtr());
        obj->cameraSessionForSys_ = obj->timeLapsePhotoSession_;
        obj->cameraSession_ = obj->timeLapsePhotoSession_;
        CHECK_RETURN_RET_ELOG(obj->timeLapsePhotoSession_ == nullptr, nullptr,
            "%{public}s: timeLapsePhotoSession_ is nullptr", __FUNCTION__);
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                           Destructor, nullptr, nullptr);
        if (status == napi_ok) {
            (void)obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("%{public}s: Failed", __FUNCTION__);
    return nullptr;
}

void TimeLapsePhotoSessionNapi::Destructor(napi_env env, void* nativeObject, void* finalize)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    TimeLapsePhotoSessionNapi* obj = reinterpret_cast<TimeLapsePhotoSessionNapi*>(nativeObject);
    if (obj != nullptr) {
        delete obj;
    }
}

void TimeLapsePhotoSessionNapi::RegisterIsoInfoCallbackListener(const std::string& eventName, napi_env env,
    napi_value callback, const vector<napi_value>& args, bool isOnce)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    if (isoInfoCallback_ == nullptr) {
        isoInfoCallback_ = make_shared<IsoInfoCallbackListener>(env);
        timeLapsePhotoSession_->SetIsoInfoCallback(isoInfoCallback_);
    }
    isoInfoCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void TimeLapsePhotoSessionNapi::UnregisterIsoInfoCallbackListener(const std::string& eventName, napi_env env,
    napi_value callback, const vector<napi_value>& args)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    if (isoInfoCallback_ == nullptr) {
        MEDIA_ERR_LOG("isoInfoCallback is null");
    } else {
        isoInfoCallback_->RemoveCallbackRef(eventName, callback);
    }
}

void TimeLapsePhotoSessionNapi::RegisterExposureInfoCallbackListener(const std::string& eventName, napi_env env,
    napi_value callback, const vector<napi_value>& args, bool isOnce)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    if (exposureInfoCallback_ == nullptr) {
        exposureInfoCallback_ = make_shared<ExposureInfoCallbackListener>(env);
        timeLapsePhotoSession_->SetExposureInfoCallback(exposureInfoCallback_);
    }
    exposureInfoCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void TimeLapsePhotoSessionNapi::UnregisterExposureInfoCallbackListener(const std::string& eventName, napi_env env,
    napi_value callback, const vector<napi_value>& args)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    if (exposureInfoCallback_ == nullptr) {
        MEDIA_ERR_LOG("exposureInfoCallback is null");
    } else {
        exposureInfoCallback_->RemoveCallbackRef(eventName, callback);
    }
}

void TimeLapsePhotoSessionNapi::RegisterLuminationInfoCallbackListener(const std::string& eventName, napi_env env,
    napi_value callback, const vector<napi_value>& args, bool isOnce)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    if (luminationInfoCallback_ == nullptr) {
        ExposureHintMode mode = EXPOSURE_HINT_MODE_ON;
        timeLapsePhotoSession_->LockForControl();
        timeLapsePhotoSession_->SetExposureHintMode(mode);
        timeLapsePhotoSession_->UnlockForControl();
        MEDIA_INFO_LOG("TimeLapsePhotoSessionNapi SetExposureHintMode exposureHint = %{public}d", mode);
        luminationInfoCallback_ = make_shared<LuminationInfoCallbackListener>(env);
        timeLapsePhotoSession_->SetLuminationInfoCallback(luminationInfoCallback_);
    }
    luminationInfoCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void TimeLapsePhotoSessionNapi::UnregisterLuminationInfoCallbackListener(const std::string& eventName, napi_env env,
    napi_value callback, const vector<napi_value>& args)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    if (luminationInfoCallback_ == nullptr) {
        MEDIA_ERR_LOG("luminationInfoCallback is null");
    } else {
        ExposureHintMode mode = EXPOSURE_HINT_MODE_OFF;
        timeLapsePhotoSession_->LockForControl();
        timeLapsePhotoSession_->SetExposureHintMode(mode);
        timeLapsePhotoSession_->UnlockForControl();
        MEDIA_INFO_LOG("TimeLapsePhotoSessionNapi SetExposureHintMode exposureHint = %{public}d!", mode);
        luminationInfoCallback_->RemoveCallbackRef(eventName, callback);
    }
}

void TimeLapsePhotoSessionNapi::RegisterTryAEInfoCallbackListener(const std::string& eventName, napi_env env,
    napi_value callback, const vector<napi_value>& args, bool isOnce)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    if (tryAEInfoCallback_ == nullptr) {
        tryAEInfoCallback_ = make_shared<TryAEInfoCallbackListener>(env);
        timeLapsePhotoSession_->SetTryAEInfoCallback(tryAEInfoCallback_);
    }
    tryAEInfoCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void TimeLapsePhotoSessionNapi::UnregisterTryAEInfoCallbackListener(const std::string& eventName, napi_env env,
    napi_value callback, const vector<napi_value>& args)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    if (tryAEInfoCallback_ == nullptr) {
        MEDIA_ERR_LOG("tryAEInfoCallback is null");
    } else {
        tryAEInfoCallback_->RemoveCallbackRef(eventName, callback);
    }
}

void TryAEInfoCallbackListener::OnTryAEInfoChanged(TryAEInfo info)
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    OnTryAEInfoChangedCallbackAsync(info);
}

void TryAEInfoCallbackListener::OnTryAEInfoChangedCallback(TryAEInfo info) const
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    napi_value result[ARGS_TWO] = { nullptr, nullptr };
    napi_value retVal;

    napi_get_undefined(env_, &result[PARAM0]);
    result[PARAM1] = TryAEInfoNapi::NewInstance(env_);
    TryAEInfoNapi *obj = Unwrap<TryAEInfoNapi>(env_, result[PARAM1]);
    if (obj) {
        obj->tryAEInfo_ = make_unique<TryAEInfo>(info);
    } else {
        MEDIA_ERR_LOG("%{public}s: Enter, TryAEInfoNapi* is nullptr", __FUNCTION__);
    }
    ExecuteCallbackNapiPara callbackPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback("tryAEInfoChange", callbackPara);
}

void TryAEInfoCallbackListener::OnTryAEInfoChangedCallbackAsync(TryAEInfo info) const
{
    MEDIA_DEBUG_LOG("%{public}s: Enter", __FUNCTION__);
    auto callback = make_unique<TryAEInfoChangedCallback>(info, shared_from_this());
    TryAEInfoChangedCallback *event = callback.get();
    auto task = [event]() {
        TryAEInfoChangedCallback* callback = reinterpret_cast<TryAEInfoChangedCallback *>(event);
        if (callback) {
            auto listener = callback->listener_.lock();
            CHECK_EXECUTE(listener != nullptr, listener->OnTryAEInfoChangedCallback(callback->info_));
            delete callback;
        }
    };
    if (napi_ok != napi_send_event(env_, task, napi_eprio_immediate)) {
        MEDIA_ERR_LOG("failed to execute work");
    } else {
        (void)callback.release();
    }
}

}
}