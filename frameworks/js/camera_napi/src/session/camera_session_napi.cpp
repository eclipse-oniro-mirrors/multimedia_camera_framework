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

#include "session/camera_session_napi.h"

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <uv.h>
#include <vector>

#include "camera_error_code.h"
#include "camera_napi_const.h"
#include "camera_napi_param_parser.h"
#include "camera_napi_security_utils.h"
#include "camera_napi_template_utils.h"
#include "camera_napi_utils.h"
#include "camera_output_capability.h"
#include "capture_scene_const.h"
#include "capture_session.h"
#include "js_native_api.h"
#include "js_native_api_types.h"
#include "listener_base.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "output/photo_output_napi.h"
#include "camera_napi_object_types.h"

namespace OHOS {
namespace CameraStandard {
namespace {
void AsyncCompleteCallback(napi_env env, napi_status status, void* data)
{
    auto context = static_cast<CameraSessionAsyncContext*>(data);
    CHECK_ERROR_RETURN_LOG(context == nullptr, "CameraSessionNapi AsyncCompleteCallback context is null");
    MEDIA_INFO_LOG("CameraSessionNapi AsyncCompleteCallback %{public}s, status = %{public}d", context->funcName.c_str(),
        context->status);
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
    delete context;
}
} // namespace

using namespace std;
thread_local napi_ref CameraSessionNapi::sConstructor_ = nullptr;
thread_local sptr<CaptureSession> CameraSessionNapi::sCameraSession_ = nullptr;
thread_local uint32_t CameraSessionNapi::cameraSessionTaskId = CAMERA_SESSION_TASKID;

const std::vector<napi_property_descriptor> CameraSessionNapi::camera_process_props = {
    DECLARE_NAPI_FUNCTION("beginConfig", CameraSessionNapi::BeginConfig),
    DECLARE_NAPI_FUNCTION("commitConfig", CameraSessionNapi::CommitConfig),

    DECLARE_NAPI_FUNCTION("canAddInput", CameraSessionNapi::CanAddInput),
    DECLARE_NAPI_FUNCTION("addInput", CameraSessionNapi::AddInput),
    DECLARE_NAPI_FUNCTION("removeInput", CameraSessionNapi::RemoveInput),

    DECLARE_NAPI_FUNCTION("canAddOutput", CameraSessionNapi::CanAddOutput),
    DECLARE_NAPI_FUNCTION("addOutput", CameraSessionNapi::AddOutput),
    DECLARE_NAPI_FUNCTION("removeOutput", CameraSessionNapi::RemoveOutput),

    DECLARE_NAPI_FUNCTION("start", CameraSessionNapi::Start),
    DECLARE_NAPI_FUNCTION("stop", CameraSessionNapi::Stop),
    DECLARE_NAPI_FUNCTION("release", CameraSessionNapi::Release),

    DECLARE_NAPI_FUNCTION("lockForControl", CameraSessionNapi::LockForControl),
    DECLARE_NAPI_FUNCTION("unlockForControl", CameraSessionNapi::UnlockForControl),

    DECLARE_NAPI_FUNCTION("on", CameraSessionNapi::On),
    DECLARE_NAPI_FUNCTION("once", CameraSessionNapi::Once),
    DECLARE_NAPI_FUNCTION("off", CameraSessionNapi::Off)
};

const std::vector<napi_property_descriptor> CameraSessionNapi::stabilization_props = {
    DECLARE_NAPI_FUNCTION("isVideoStabilizationModeSupported", CameraSessionNapi::IsVideoStabilizationModeSupported),
    DECLARE_NAPI_FUNCTION("getActiveVideoStabilizationMode", CameraSessionNapi::GetActiveVideoStabilizationMode),
    DECLARE_NAPI_FUNCTION("setVideoStabilizationMode", CameraSessionNapi::SetVideoStabilizationMode)
};

const std::vector<napi_property_descriptor> CameraSessionNapi::flash_props = {
    DECLARE_NAPI_FUNCTION("hasFlash", CameraSessionNapi::HasFlash),
    DECLARE_NAPI_FUNCTION("isFlashModeSupported", CameraSessionNapi::IsFlashModeSupported),
    DECLARE_NAPI_FUNCTION("getFlashMode", CameraSessionNapi::GetFlashMode),
    DECLARE_NAPI_FUNCTION("setFlashMode", CameraSessionNapi::SetFlashMode),
    DECLARE_NAPI_FUNCTION("isLcdFlashSupported", CameraSessionNapi::IsLcdFlashSupported),
    DECLARE_NAPI_FUNCTION("enableLcdFlash", CameraSessionNapi::EnableLcdFlash)
};

const std::vector<napi_property_descriptor> CameraSessionNapi::auto_exposure_props = {
    DECLARE_NAPI_FUNCTION("isExposureModeSupported", CameraSessionNapi::IsExposureModeSupported),
    DECLARE_NAPI_FUNCTION("getExposureMode", CameraSessionNapi::GetExposureMode),
    DECLARE_NAPI_FUNCTION("setExposureMode", CameraSessionNapi::SetExposureMode),
    DECLARE_NAPI_FUNCTION("getExposureBiasRange", CameraSessionNapi::GetExposureBiasRange),
    DECLARE_NAPI_FUNCTION("setExposureBias", CameraSessionNapi::SetExposureBias),
    DECLARE_NAPI_FUNCTION("getExposureValue", CameraSessionNapi::GetExposureValue),
    DECLARE_NAPI_FUNCTION("getMeteringPoint", CameraSessionNapi::GetMeteringPoint),
    DECLARE_NAPI_FUNCTION("setMeteringPoint", CameraSessionNapi::SetMeteringPoint)
};

const std::vector<napi_property_descriptor> CameraSessionNapi::focus_props = {
    DECLARE_NAPI_FUNCTION("isFocusModeSupported", CameraSessionNapi::IsFocusModeSupported),
    DECLARE_NAPI_FUNCTION("getFocusMode", CameraSessionNapi::GetFocusMode),
    DECLARE_NAPI_FUNCTION("setFocusMode", CameraSessionNapi::SetFocusMode),
    DECLARE_NAPI_FUNCTION("getFocusPoint", CameraSessionNapi::GetFocusPoint),
    DECLARE_NAPI_FUNCTION("setFocusPoint", CameraSessionNapi::SetFocusPoint),
    DECLARE_NAPI_FUNCTION("getFocalLength", CameraSessionNapi::GetFocalLength)
};

const std::vector<napi_property_descriptor> CameraSessionNapi::manual_focus_props = {
    DECLARE_NAPI_FUNCTION("getFocusDistance", CameraSessionNapi::GetFocusDistance),
    DECLARE_NAPI_FUNCTION("setFocusDistance", CameraSessionNapi::SetFocusDistance),
};

const std::vector<napi_property_descriptor> CameraSessionNapi::zoom_props = {
    DECLARE_NAPI_FUNCTION("getZoomRatioRange", CameraSessionNapi::GetZoomRatioRange),
    DECLARE_NAPI_FUNCTION("getZoomRatio", CameraSessionNapi::GetZoomRatio),
    DECLARE_NAPI_FUNCTION("setZoomRatio", CameraSessionNapi::SetZoomRatio),
    DECLARE_NAPI_FUNCTION("prepareZoom", PrepareZoom),
    DECLARE_NAPI_FUNCTION("unprepareZoom", UnPrepareZoom),
    DECLARE_NAPI_FUNCTION("setSmoothZoom", SetSmoothZoom),
    DECLARE_NAPI_FUNCTION("getZoomPointInfos", CameraSessionNapi::GetZoomPointInfos)
};

const std::vector<napi_property_descriptor> CameraSessionNapi::filter_props = {
    DECLARE_NAPI_FUNCTION("getSupportedFilters", CameraSessionNapi::GetSupportedFilters),
    DECLARE_NAPI_FUNCTION("getFilter", CameraSessionNapi::GetFilter),
    DECLARE_NAPI_FUNCTION("setFilter", CameraSessionNapi::SetFilter)
};

const std::vector<napi_property_descriptor> CameraSessionNapi::beauty_props = {
    DECLARE_NAPI_FUNCTION("getSupportedBeautyTypes", CameraSessionNapi::GetSupportedBeautyTypes),
    DECLARE_NAPI_FUNCTION("getSupportedBeautyRange", CameraSessionNapi::GetSupportedBeautyRange),
    DECLARE_NAPI_FUNCTION("getBeauty", CameraSessionNapi::GetBeauty),
    DECLARE_NAPI_FUNCTION("setBeauty", CameraSessionNapi::SetBeauty)
};

const std::vector<napi_property_descriptor> CameraSessionNapi::color_effect_props = {
    DECLARE_NAPI_FUNCTION("getSupportedColorEffects", CameraSessionNapi::GetSupportedColorEffects),
    DECLARE_NAPI_FUNCTION("getColorEffect", CameraSessionNapi::GetColorEffect),
    DECLARE_NAPI_FUNCTION("setColorEffect", CameraSessionNapi::SetColorEffect)
};

const std::vector<napi_property_descriptor> CameraSessionNapi::macro_props = {
    DECLARE_NAPI_FUNCTION("isMacroSupported", CameraSessionNapi::IsMacroSupported),
    DECLARE_NAPI_FUNCTION("enableMacro", CameraSessionNapi::EnableMacro)
};

const std::vector<napi_property_descriptor> CameraSessionNapi::moon_capture_boost_props = {
    DECLARE_NAPI_FUNCTION("isMoonCaptureBoostSupported", CameraSessionNapi::IsMoonCaptureBoostSupported),
    DECLARE_NAPI_FUNCTION("enableMoonCaptureBoost", CameraSessionNapi::EnableMoonCaptureBoost)
};

const std::vector<napi_property_descriptor> CameraSessionNapi::features_props = {
    DECLARE_NAPI_FUNCTION("isSceneFeatureSupported", CameraSessionNapi::IsFeatureSupported),
    DECLARE_NAPI_FUNCTION("enableSceneFeature", CameraSessionNapi::EnableFeature)
};

const std::vector<napi_property_descriptor> CameraSessionNapi::color_management_props = {
    DECLARE_NAPI_FUNCTION("getSupportedColorSpaces", CameraSessionNapi::GetSupportedColorSpaces),
    DECLARE_NAPI_FUNCTION("getActiveColorSpace", CameraSessionNapi::GetActiveColorSpace),
    DECLARE_NAPI_FUNCTION("setColorSpace", CameraSessionNapi::SetColorSpace)
};

const std::vector<napi_property_descriptor> CameraSessionNapi::preconfig_props = {
    DECLARE_NAPI_FUNCTION("canPreconfig", CameraSessionNapi::CanPreconfig),
    DECLARE_NAPI_FUNCTION("preconfig", CameraSessionNapi::Preconfig)
};

const std::vector<napi_property_descriptor> CameraSessionNapi::camera_output_capability_props = {
    DECLARE_NAPI_FUNCTION("getCameraOutputCapabilities", CameraSessionNapi::GetCameraOutputCapabilities)
};

const std::vector<napi_property_descriptor> CameraSessionNapi::camera_ability_props = {
    DECLARE_NAPI_FUNCTION("getSessionFunctions", CameraSessionNapi::GetSessionFunctions),
    DECLARE_NAPI_FUNCTION("getSessionConflictFunctions", CameraSessionNapi::GetSessionConflictFunctions)
};

const std::vector<napi_property_descriptor> CameraSessionNapi::effect_suggestion_props = {
    DECLARE_NAPI_FUNCTION("isEffectSuggestionSupported", CameraSessionNapi::IsEffectSuggestionSupported),
    DECLARE_NAPI_FUNCTION("enableEffectSuggestion", CameraSessionNapi::EnableEffectSuggestion),
    DECLARE_NAPI_FUNCTION("getSupportedEffectSuggestionType", CameraSessionNapi::GetSupportedEffectSuggestionType),
    DECLARE_NAPI_FUNCTION("getSupportedEffectSuggestionTypes", CameraSessionNapi::GetSupportedEffectSuggestionType),
    DECLARE_NAPI_FUNCTION("setEffectSuggestionStatus", CameraSessionNapi::SetEffectSuggestionStatus),
    DECLARE_NAPI_FUNCTION("updateEffectSuggestion", CameraSessionNapi::UpdateEffectSuggestion)
};

const std::vector<napi_property_descriptor> CameraSessionNapi::auto_wb_props = {
    DECLARE_NAPI_FUNCTION("getSupportedWhiteBalanceModes", CameraSessionNapi::GetSupportedWhiteBalanceModes),
    DECLARE_NAPI_FUNCTION("isWhiteBalanceModeSupported", CameraSessionNapi::IsWhiteBalanceModeSupported),
    DECLARE_NAPI_FUNCTION("getWhiteBalanceMode", CameraSessionNapi::GetWhiteBalanceMode),
    DECLARE_NAPI_FUNCTION("setWhiteBalanceMode", CameraSessionNapi::SetWhiteBalanceMode),
};

const std::vector<napi_property_descriptor> CameraSessionNapi::manual_wb_props = {
    DECLARE_NAPI_FUNCTION("getWhiteBalanceRange", CameraSessionNapi::GetManualWhiteBalanceRange),
    DECLARE_NAPI_FUNCTION("isManualWhiteBalanceSupported", CameraSessionNapi::IsManualWhiteBalanceSupported),
    DECLARE_NAPI_FUNCTION("getWhiteBalance", CameraSessionNapi::GetManualWhiteBalance),
    DECLARE_NAPI_FUNCTION("setWhiteBalance", CameraSessionNapi::SetManualWhiteBalance),
};

const std::vector<napi_property_descriptor> CameraSessionNapi::aperture_props = {
    DECLARE_NAPI_FUNCTION("getSupportedVirtualApertures", CameraSessionNapi::GetSupportedVirtualApertures),
    DECLARE_NAPI_FUNCTION("getVirtualAperture", CameraSessionNapi::GetVirtualAperture),
    DECLARE_NAPI_FUNCTION("setVirtualAperture", CameraSessionNapi::SetVirtualAperture),

    DECLARE_NAPI_FUNCTION("getSupportedPhysicalApertures", CameraSessionNapi::GetSupportedPhysicalApertures),
    DECLARE_NAPI_FUNCTION("getPhysicalAperture", CameraSessionNapi::GetPhysicalAperture),
    DECLARE_NAPI_FUNCTION("setPhysicalAperture", CameraSessionNapi::SetPhysicalAperture)
};

void ExposureCallbackListener::OnExposureStateCallbackAsync(ExposureState state) const
{
    MEDIA_DEBUG_LOG("OnExposureStateCallbackAsync is called");
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("failed to get event loop");
        return;
    }
    uv_work_t* work = new(std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("failed to allocate work");
        return;
    }
    std::unique_ptr<ExposureCallbackInfo> callbackInfo = std::make_unique<ExposureCallbackInfo>(state, this);
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        ExposureCallbackInfo* callbackInfo = reinterpret_cast<ExposureCallbackInfo *>(work->data);
        if (callbackInfo) {
            callbackInfo->listener_->OnExposureStateCallback(callbackInfo->state_);
            delete callbackInfo;
        }
        delete work;
    }, uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void ExposureCallbackListener::OnExposureStateCallback(ExposureState state) const
{
    MEDIA_DEBUG_LOG("OnExposureStateCallback is called");
    napi_value result[ARGS_TWO] = {nullptr, nullptr};
    napi_value retVal;

    napi_get_undefined(env_, &result[PARAM0]);
    napi_create_int32(env_, state, &result[PARAM1]);
    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback("exposureStateChange", callbackNapiPara);
}

void ExposureCallbackListener::OnExposureState(const ExposureState state)
{
    MEDIA_DEBUG_LOG("OnExposureState is called, state: %{public}d", state);
    OnExposureStateCallbackAsync(state);
}

void FocusCallbackListener::OnFocusStateCallbackAsync(FocusState state) const
{
    MEDIA_DEBUG_LOG("OnFocusStateCallbackAsync is called");
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("failed to get event loop");
        return;
    }
    uv_work_t* work = new(std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("failed to allocate work");
        return;
    }
    std::unique_ptr<FocusCallbackInfo> callbackInfo = std::make_unique<FocusCallbackInfo>(state, this);
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        FocusCallbackInfo* callbackInfo = reinterpret_cast<FocusCallbackInfo *>(work->data);
        if (callbackInfo) {
            callbackInfo->listener_->OnFocusStateCallback(callbackInfo->state_);
            delete callbackInfo;
        }
        delete work;
    }, uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void FocusCallbackListener::OnFocusStateCallback(FocusState state) const
{
    MEDIA_DEBUG_LOG("OnFocusStateCallback is called");
    napi_value result[ARGS_TWO] = {nullptr, nullptr};
    napi_value retVal;
    napi_get_undefined(env_, &result[PARAM0]);
    napi_create_int32(env_, state, &result[PARAM1]);
    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback("focusStateChange", callbackNapiPara);
}

void FocusCallbackListener::OnFocusState(FocusState state)
{
    MEDIA_DEBUG_LOG("OnFocusState is called, state: %{public}d", state);
    OnFocusStateCallbackAsync(state);
}

void MacroStatusCallbackListener::OnMacroStatusCallbackAsync(MacroStatus status) const
{
    MEDIA_DEBUG_LOG("OnMacroStatusCallbackAsync is called");
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("failed to get event loop");
        return;
    }
    uv_work_t* work = new (std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("failed to allocate work");
        return;
    }
    auto callbackInfo = std::make_unique<MacroStatusCallbackInfo>(status, this);
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(
        loop, work, [](uv_work_t* work) {},
        [](uv_work_t* work, int status) {
            auto callbackInfo = reinterpret_cast<MacroStatusCallbackInfo*>(work->data);
            if (callbackInfo) {
                callbackInfo->listener_->OnMacroStatusCallback(callbackInfo->status_);
                delete callbackInfo;
            }
            delete work;
        },
        uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void MacroStatusCallbackListener::OnMacroStatusCallback(MacroStatus status) const
{
    MEDIA_DEBUG_LOG("OnMacroStatusCallback is called");
    napi_value result[ARGS_TWO] = { nullptr, nullptr };
    napi_value retVal;
    napi_get_undefined(env_, &result[PARAM0]);
    napi_get_boolean(env_, status == MacroStatus::ACTIVE, &result[PARAM1]);
    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback("macroStatusChanged", callbackNapiPara);
}

void MacroStatusCallbackListener::OnMacroStatusChanged(MacroStatus status)
{
    MEDIA_DEBUG_LOG("OnMacroStatusChanged is called, status: %{public}d", status);
    OnMacroStatusCallbackAsync(status);
}

void MoonCaptureBoostCallbackListener::OnMoonCaptureBoostStatusCallbackAsync(MoonCaptureBoostStatus status) const
{
    MEDIA_DEBUG_LOG("OnMoonCaptureBoostStatusCallbackAsync is called");
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("failed to get event loop");
        return;
    }
    uv_work_t* work = new (std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("failed to allocate work");
        return;
    }
    auto callbackInfo = std::make_unique<MoonCaptureBoostStatusCallbackInfo>(status, this);
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(
        loop, work, [](uv_work_t* work) {},
        [](uv_work_t* work, int status) {
            auto callbackInfo = reinterpret_cast<MoonCaptureBoostStatusCallbackInfo*>(work->data);
            if (callbackInfo) {
                callbackInfo->listener_->OnMoonCaptureBoostStatusCallback(callbackInfo->status_);
                delete callbackInfo;
            }
            delete work;
        },
        uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void MoonCaptureBoostCallbackListener::OnMoonCaptureBoostStatusCallback(MoonCaptureBoostStatus status) const
{
    MEDIA_DEBUG_LOG("OnMoonCaptureBoostStatusCallback is called");
    napi_value result[ARGS_TWO] = { nullptr, nullptr };
    napi_value retVal;
    napi_get_undefined(env_, &result[PARAM0]);
    napi_get_boolean(env_, status == MoonCaptureBoostStatus::ACTIVE, &result[PARAM1]);
    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback("moonCaptureBoostStatus", callbackNapiPara);
}

void MoonCaptureBoostCallbackListener::OnMoonCaptureBoostStatusChanged(MoonCaptureBoostStatus status)
{
    MEDIA_DEBUG_LOG("OnMoonCaptureBoostStatusChanged is called, status: %{public}d", status);
    OnMoonCaptureBoostStatusCallbackAsync(status);
}

void FeatureDetectionStatusCallbackListener::OnFeatureDetectionStatusChangedCallbackAsync(
    SceneFeature feature, FeatureDetectionStatus status) const
{
    MEDIA_DEBUG_LOG("OnFeatureDetectionStatusChangedCallbackAsync is called");
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("failed to get event loop");
        return;
    }
    uv_work_t* work = new (std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("failed to allocate work");
        return;
    }
    auto callbackInfo = std::make_unique<FeatureDetectionStatusCallbackInfo>(feature, status, this);
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(
        loop, work, [](uv_work_t* work) {},
        [](uv_work_t* work, int status) {
            auto callbackInfo = reinterpret_cast<FeatureDetectionStatusCallbackInfo*>(work->data);
            if (callbackInfo) {
                callbackInfo->listener_->OnFeatureDetectionStatusChangedCallback(
                    callbackInfo->feature_, callbackInfo->status_);
                delete callbackInfo;
            }
            delete work;
        },
        uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void FeatureDetectionStatusCallbackListener::OnFeatureDetectionStatusChangedCallback(
    SceneFeature feature, FeatureDetectionStatus status) const
{
    MEDIA_DEBUG_LOG("OnFeatureDetectionStatusChangedCallback is called");
    std::string eventName = "featureDetection" + std::to_string(static_cast<int32_t>(feature));
    std::string eventNameOld = "featureDetectionStatus" + std::to_string(static_cast<int32_t>(feature));

    napi_value result[ARGS_TWO] = { nullptr, nullptr };
    napi_value retVal;
    napi_get_undefined(env_, &result[PARAM0]);
    napi_create_object(env_, &result[PARAM1]);

    napi_value featureNapiValue;
    napi_create_int32(env_, feature, &featureNapiValue);
    napi_set_named_property(env_, result[PARAM1], "featureType", featureNapiValue);

    napi_value statusValue;
    napi_get_boolean(env_, status == FeatureDetectionStatus::ACTIVE, &statusValue);
    napi_set_named_property(env_, result[PARAM1], "detected", statusValue);

    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback(eventName, callbackNapiPara);
    ExecuteCallback(eventNameOld, callbackNapiPara);
}

void FeatureDetectionStatusCallbackListener::OnFeatureDetectionStatusChanged(
    SceneFeature feature, FeatureDetectionStatus status)
{
    MEDIA_DEBUG_LOG(
        "OnFeatureDetectionStatusChanged is called,feature:%{public}d, status: %{public}d", feature, status);
    OnFeatureDetectionStatusChangedCallbackAsync(feature, status);
}

bool FeatureDetectionStatusCallbackListener::IsFeatureSubscribed(SceneFeature feature)
{
    std::string eventName = "featureDetection" + std::to_string(static_cast<int32_t>(feature));
    std::string eventNameOld = "featureDetectionStatus" + std::to_string(static_cast<int32_t>(feature));

    return !IsEmpty(eventName) || !IsEmpty(eventNameOld);
}

void SessionCallbackListener::OnErrorCallbackAsync(int32_t errorCode) const
{
    MEDIA_DEBUG_LOG("OnErrorCallbackAsync is called");
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("failed to get event loop");
        return;
    }
    uv_work_t* work = new(std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("failed to allocate work");
        return;
    }
    std::unique_ptr<SessionCallbackInfo> callbackInfo = std::make_unique<SessionCallbackInfo>(errorCode, this);
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        SessionCallbackInfo* callbackInfo = reinterpret_cast<SessionCallbackInfo *>(work->data);
        if (callbackInfo) {
            callbackInfo->listener_->OnErrorCallback(callbackInfo->errorCode_);
            delete callbackInfo;
        }
        delete work;
    }, uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void SessionCallbackListener::OnErrorCallback(int32_t errorCode) const
{
    MEDIA_DEBUG_LOG("OnErrorCallback is called");
    napi_value result[ARGS_ONE] = {nullptr};
    napi_value retVal;
    napi_value propValue;

    napi_create_object(env_, &result[PARAM0]);
    napi_create_int32(env_, errorCode, &propValue);
    napi_set_named_property(env_, result[PARAM0], "code", propValue);
    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_ONE, .argv = result, .result = &retVal };
    ExecuteCallback("error", callbackNapiPara);
}

void SessionCallbackListener::OnError(int32_t errorCode)
{
    MEDIA_DEBUG_LOG("OnError is called, errorCode: %{public}d", errorCode);
    OnErrorCallbackAsync(errorCode);
}

void SmoothZoomCallbackListener::OnSmoothZoomCallbackAsync(int32_t duration) const
{
    MEDIA_DEBUG_LOG("OnSmoothZoomCallbackAsync is called");
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("failed to get event loop");
        return;
    }
    uv_work_t* work = new(std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("failed to allocate work");
        return;
    }
    std::unique_ptr<SmoothZoomCallbackInfo> callbackInfo = std::make_unique<SmoothZoomCallbackInfo>(duration, this);
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        SmoothZoomCallbackInfo* callbackInfo = reinterpret_cast<SmoothZoomCallbackInfo *>(work->data);
        if (callbackInfo) {
            callbackInfo->listener_->OnSmoothZoomCallback(callbackInfo->duration_);
            delete callbackInfo;
        }
        delete work;
    }, uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void SmoothZoomCallbackListener::OnSmoothZoomCallback(int32_t duration) const
{
    MEDIA_DEBUG_LOG("OnSmoothZoomCallback is called");
    napi_value result[ARGS_TWO];
    napi_value retVal;
    napi_value propValue;

    napi_get_undefined(env_, &result[PARAM0]);
    napi_create_object(env_, &result[PARAM1]);
    napi_create_int32(env_, duration, &propValue);
    napi_set_named_property(env_, result[PARAM1], "duration", propValue);

    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback("smoothZoomInfoAvailable", callbackNapiPara);
}

void SmoothZoomCallbackListener::OnSmoothZoom(int32_t duration)
{
    MEDIA_DEBUG_LOG("OnSmoothZoom is called, duration: %{public}d", duration);
    OnSmoothZoomCallbackAsync(duration);
}

void AbilityCallbackListener::OnAbilityChangeCallbackAsync() const
{
    MEDIA_DEBUG_LOG("OnAbilityChangeCallbackAsync is called");
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("failed to get event loop");
        return;
    }
    uv_work_t* work = new(std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("failed to allocate work");
        return;
    }
    std::unique_ptr<AbilityCallbackInfo> callbackInfo = std::make_unique<AbilityCallbackInfo>(this);
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        AbilityCallbackInfo* callbackInfo = reinterpret_cast<AbilityCallbackInfo *>(work->data);
        if (callbackInfo) {
            callbackInfo->listener_->OnAbilityChangeCallback();
            delete callbackInfo;
        }
        delete work;
    }, uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void AbilityCallbackListener::OnAbilityChangeCallback() const
{
    MEDIA_DEBUG_LOG("OnAbilityChangeCallback is called");
    napi_value result[ARGS_TWO];
    napi_value retVal;
    napi_get_undefined(env_, &result[PARAM0]);
    napi_get_undefined(env_, &result[PARAM1]);

    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback("abilityChange", callbackNapiPara);
}

void AbilityCallbackListener::OnAbilityChange()
{
    MEDIA_DEBUG_LOG("OnAbilityChange is called");
    OnAbilityChangeCallbackAsync();
}

void EffectSuggestionCallbackListener::OnEffectSuggestionCallbackAsync(EffectSuggestionType effectSuggestionType) const
{
    MEDIA_DEBUG_LOG("OnEffectSuggestionCallbackAsync is called");
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("failed to get event loop");
        return;
    }
    uv_work_t* work = new(std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("failed to allocate work");
        return;
    }
    std::unique_ptr<EffectSuggestionCallbackInfo> callbackInfo =
        std::make_unique<EffectSuggestionCallbackInfo>(effectSuggestionType, this);
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        EffectSuggestionCallbackInfo* callbackInfo = reinterpret_cast<EffectSuggestionCallbackInfo *>(work->data);
        if (callbackInfo) {
            callbackInfo->listener_->OnEffectSuggestionCallback(callbackInfo->effectSuggestionType_);
            delete callbackInfo;
        }
        delete work;
    }, uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void EffectSuggestionCallbackListener::OnEffectSuggestionCallback(EffectSuggestionType effectSuggestionType) const
{
    MEDIA_DEBUG_LOG("OnEffectSuggestionCallback is called");
    napi_value result[ARGS_TWO] = {nullptr, nullptr};
    napi_value retVal;
    napi_get_undefined(env_, &result[PARAM0]);
    napi_create_int32(env_, effectSuggestionType, &result[PARAM1]);
    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback("effectSuggestionChange", callbackNapiPara);
}

void EffectSuggestionCallbackListener::OnEffectSuggestionChange(EffectSuggestionType effectSuggestionType)
{
    MEDIA_DEBUG_LOG("OnEffectSuggestionChange is called, effectSuggestionType: %{public}d", effectSuggestionType);
    OnEffectSuggestionCallbackAsync(effectSuggestionType);
}

void LcdFlashStatusCallbackListener::OnLcdFlashStatusCallbackAsync(LcdFlashStatusInfo lcdFlashStatusInfo) const
{
    MEDIA_DEBUG_LOG("OnLcdFlashStatusCallbackAsync is called");
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("failed to get event loop");
        return;
    }
    uv_work_t* work = new (std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("failed to allocate work");
        return;
    }
    auto callbackInfo = std::make_unique<LcdFlashStatusStatusCallbackInfo>(lcdFlashStatusInfo, this);
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(
        loop, work, [](uv_work_t* work) {},
        [](uv_work_t* work, int status) {
            auto callbackInfo = reinterpret_cast<LcdFlashStatusStatusCallbackInfo*>(work->data);
            if (callbackInfo) {
                callbackInfo->listener_->OnLcdFlashStatusCallback(callbackInfo->lcdFlashStatusInfo_);
                delete callbackInfo;
            }
            delete work;
        },
        uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void LcdFlashStatusCallbackListener::OnLcdFlashStatusCallback(LcdFlashStatusInfo lcdFlashStatusInfo) const
{
    MEDIA_DEBUG_LOG("OnLcdFlashStatusCallback is called");
    napi_value result[ARGS_TWO] = { nullptr, nullptr };
    napi_get_undefined(env_, &result[PARAM0]);
    napi_value retVal;
    napi_value propValue;
    napi_create_object(env_, &result[PARAM1]);
    napi_get_boolean(env_, lcdFlashStatusInfo.isLcdFlashNeeded, &propValue);
    napi_set_named_property(env_, result[PARAM1], "isLcdFlashNeeded", propValue);
    napi_create_int32(env_, lcdFlashStatusInfo.lcdCompensation, &propValue);
    napi_set_named_property(env_, result[PARAM1], "lcdCompensation", propValue);
    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback("lcdFlashStatus", callbackNapiPara);
}

void LcdFlashStatusCallbackListener::OnLcdFlashStatusChanged(LcdFlashStatusInfo lcdFlashStatusInfo)
{
    MEDIA_DEBUG_LOG("OnLcdFlashStatusChanged is called, isLcdFlashNeeded: %{public}d, lcdCompensation: %{public}d",
        lcdFlashStatusInfo.isLcdFlashNeeded, lcdFlashStatusInfo.lcdCompensation);
    OnLcdFlashStatusCallbackAsync(lcdFlashStatusInfo);
}

CameraSessionNapi::CameraSessionNapi() : env_(nullptr) {}

CameraSessionNapi::~CameraSessionNapi()
{
    MEDIA_DEBUG_LOG("~CameraSessionNapi is called");
}

void CameraSessionNapi::CameraSessionNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("CameraSessionNapiDestructor is called");
}

napi_value CameraSessionNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;
    std::vector<std::vector<napi_property_descriptor>> descriptors = { camera_process_props, stabilization_props,
        flash_props, auto_exposure_props, focus_props, zoom_props, filter_props, beauty_props, color_effect_props,
        macro_props, moon_capture_boost_props, features_props, color_management_props, manual_focus_props,
        preconfig_props, camera_output_capability_props };
    std::vector<napi_property_descriptor> camera_session_props = CameraNapiUtils::GetPropertyDescriptor(descriptors);
    status = napi_define_class(env, CAMERA_SESSION_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               CameraSessionNapiConstructor, nullptr,
                               camera_session_props.size(),
                               camera_session_props.data(), &ctorObj);
    if (status == napi_ok) {
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, CAMERA_SESSION_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

// Constructor callback
napi_value CameraSessionNapi::CameraSessionNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("CameraSessionNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<CameraSessionNapi> obj = std::make_unique<CameraSessionNapi>();
        if (obj != nullptr) {
            obj->env_ = env;
            if (sCameraSession_ == nullptr) {
                MEDIA_ERR_LOG("sCameraSession_ is null");
                return result;
            }
            obj->cameraSession_ = sCameraSession_;
            status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                               CameraSessionNapi::CameraSessionNapiDestructor, nullptr, nullptr);
            if (status == napi_ok) {
                obj.release();
                return thisVar;
            } else {
                MEDIA_ERR_LOG("CameraSessionNapi Failure wrapping js to native napi");
            }
        }
    }
    MEDIA_ERR_LOG("CameraSessionNapiConstructor call Failed!");
    return result;
}

int32_t QueryAndGetInputProperty(napi_env env, napi_value arg, const string &propertyName, napi_value &property)
{
    MEDIA_DEBUG_LOG("QueryAndGetInputProperty is called");
    bool present = false;
    int32_t retval = 0;
    if ((napi_has_named_property(env, arg, propertyName.c_str(), &present) != napi_ok)
        || (!present) || (napi_get_named_property(env, arg, propertyName.c_str(), &property) != napi_ok)) {
            MEDIA_ERR_LOG("Failed to obtain property: %{public}s", propertyName.c_str());
            retval = -1;
    }

    return retval;
}

int32_t GetPointProperties(napi_env env, napi_value pointObj, Point &point)
{
    MEDIA_DEBUG_LOG("GetPointProperties is called");
    napi_value propertyX = nullptr;
    napi_value propertyY = nullptr;
    double pointX = -1.0;
    double pointY = -1.0;

    if ((QueryAndGetInputProperty(env, pointObj, "x", propertyX) == 0) &&
        (QueryAndGetInputProperty(env, pointObj, "y", propertyY) == 0)) {
        if ((napi_get_value_double(env, propertyX, &pointX) != napi_ok) ||
            (napi_get_value_double(env, propertyY, &pointY) != napi_ok)) {
            MEDIA_ERR_LOG("GetPointProperties: get propery for x & y failed");
            return -1;
        } else {
            point.x = pointX;
            point.y = pointY;
        }
    } else {
        return -1;
    }

    // Return 0 after focus point properties are successfully obtained
    return 0;
}

napi_value GetPointNapiValue(napi_env env, Point &point)
{
    MEDIA_DEBUG_LOG("GetPointNapiValue is called");
    napi_value result;
    napi_value propValue;
    napi_create_object(env, &result);
    napi_create_double(env, CameraNapiUtils::FloatToDouble(point.x), &propValue);
    napi_set_named_property(env, result, "x", propValue);
    napi_create_double(env, CameraNapiUtils::FloatToDouble(point.y), &propValue);
    napi_set_named_property(env, result, "y", propValue);
    return result;
}

napi_value CameraSessionNapi::CreateCameraSession(napi_env env)
{
    MEDIA_DEBUG_LOG("CreateCameraSession is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;

    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        int retCode = CameraManager::GetInstance()->CreateCaptureSession(&sCameraSession_);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        if (sCameraSession_ == nullptr) {
            MEDIA_ERR_LOG("Failed to create Camera session instance");
            napi_get_undefined(env, &result);
            return result;
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCameraSession_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            MEDIA_DEBUG_LOG("success to create Camera session napi instance");
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create Camera session napi instance");
        }
    }
    MEDIA_ERR_LOG("Failed to create Camera session napi instance last");
    napi_get_undefined(env, &result);
    return result;
}

napi_value CameraSessionNapi::BeginConfig(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("BeginConfig is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;
    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        int32_t ret = cameraSessionNapi->cameraSession_->BeginConfig();
        if (!CameraNapiUtils::CheckError(env, ret)) {
            return nullptr;
        }
    } else {
        MEDIA_ERR_LOG("BeginConfig call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::CommitConfig(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("CommitConfig is called");
    std::unique_ptr<CameraSessionAsyncContext> asyncContext = std::make_unique<CameraSessionAsyncContext>(
        "CameraSessionNapi::CommitConfig", CameraNapiUtils::IncrementAndGet(cameraSessionTaskId));
    auto asyncFunction = std::make_shared<CameraNapiAsyncFunction>(
        env, "CommitConfig", asyncContext->callbackRef, asyncContext->deferred);
    CameraNapiParamParser jsParamParser(env, info, asyncContext->objectInfo, asyncFunction);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
        MEDIA_ERR_LOG("CameraSessionNapi::CommitConfig invalid argument");
        return nullptr;
    }

    napi_status status = napi_create_async_work(
        env, nullptr, asyncFunction->GetResourceName(),
        [](napi_env env, void* data) {
            MEDIA_INFO_LOG("CameraSessionNapi::CommitConfig running on worker");
            auto context = static_cast<CameraSessionAsyncContext*>(data);
            CHECK_ERROR_RETURN_LOG(
                context->objectInfo == nullptr, "CameraSessionNapi::CommitConfig async info is nullptr");
            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueId(context->queueId, [&context]() {
                context->errorCode = context->objectInfo->cameraSession_->CommitConfig();
                context->status = context->errorCode == CameraErrorCode::SUCCESS;
                MEDIA_INFO_LOG("CameraSessionNapi::CommitConfig errorCode:%{public}d", context->errorCode);
            });
        },
        AsyncCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for CameraSessionNapi::CommitConfig");
        asyncFunction->Reset();
    } else {
        CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueId(asyncContext->queueId);
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        asyncContext.release();
    }
    if (asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE) {
        return asyncFunction->GetPromise();
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value CameraSessionNapi::LockForControl(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("LockForControl is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        cameraSessionNapi->cameraSession_->LockForControl();
    } else {
        MEDIA_ERR_LOG("LockForControl call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::UnlockForControl(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("UnlockForControl is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        cameraSessionNapi->cameraSession_->UnlockForControl();
    } else {
        MEDIA_ERR_LOG("UnlockForControl call Failed!");
    }
    return result;
}

napi_value GetJSArgsForCameraInput(napi_env env, size_t argc, const napi_value argv[],
    sptr<CaptureInput> &cameraInput)
{
    MEDIA_DEBUG_LOG("GetJSArgsForCameraInput is called");
    napi_value result = nullptr;
    CameraInputNapi* cameraInputNapiObj = nullptr;

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == PARAM0 && valueType == napi_object) {
            napi_unwrap(env, argv[i], reinterpret_cast<void**>(&cameraInputNapiObj));
            if (cameraInputNapiObj != nullptr) {
                cameraInput = cameraInputNapiObj->GetCameraInput();
            } else {
                NAPI_ASSERT(env, false, "type mismatch");
            }
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }
    napi_get_boolean(env, true, &result);
    return result;
}

napi_value CameraSessionNapi::AddInput(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("AddInput is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    if (!CameraNapiUtils::CheckInvalidArgument(env, argc, ARGS_ONE, argv, ADD_INPUT)) {
        return result;
    }

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    sptr<CaptureInput> cameraInput = nullptr;
    GetJSArgsForCameraInput(env, argc, argv, cameraInput);
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        int32_t ret = cameraSessionNapi->cameraSession_->AddInput(cameraInput);
        if (!CameraNapiUtils::CheckError(env, ret)) {
            return nullptr;
        }
    } else {
        MEDIA_ERR_LOG("AddInput call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::CanAddInput(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("CanAddInput is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        sptr<CaptureInput> cameraInput = nullptr;
        GetJSArgsForCameraInput(env, argc, argv, cameraInput);
        bool isSupported = cameraSessionNapi->cameraSession_->CanAddInput(cameraInput);
        napi_get_boolean(env, isSupported, &result);
    } else {
        MEDIA_ERR_LOG("CanAddInput call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::RemoveInput(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("RemoveInput is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    if (!CameraNapiUtils::CheckInvalidArgument(env, argc, ARGS_ONE, argv, REMOVE_INPUT)) {
        return result;
    }

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        sptr<CaptureInput> cameraInput = nullptr;
        GetJSArgsForCameraInput(env, argc, argv, cameraInput);
        int32_t ret = cameraSessionNapi->cameraSession_->RemoveInput(cameraInput);
        if (!CameraNapiUtils::CheckError(env, ret)) {
            return nullptr;
        }
        return result;
    } else {
        MEDIA_ERR_LOG("RemoveInput call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::GetJSArgsForCameraOutput(napi_env env, size_t argc, const napi_value argv[],
    sptr<CaptureOutput> &cameraOutput)
{
    MEDIA_DEBUG_LOG("GetJSArgsForCameraOutput is called");
    napi_value result = nullptr;
    PreviewOutputNapi* previewOutputNapiObj = nullptr;
    PhotoOutputNapi* photoOutputNapiObj = nullptr;
    VideoOutputNapi* videoOutputNapiObj = nullptr;
    MetadataOutputNapi* metadataOutputNapiObj = nullptr;
    DepthDataOutputNapi* depthDataOutputNapiObj = nullptr;

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if (i == PARAM0 && valueType == napi_object) {
            if (PreviewOutputNapi::IsPreviewOutput(env, argv[i])) {
                MEDIA_INFO_LOG("preview output adding..");
                napi_unwrap(env, argv[i], reinterpret_cast<void**>(&previewOutputNapiObj));
                cameraOutput = previewOutputNapiObj->GetPreviewOutput();
            } else if (PhotoOutputNapi::IsPhotoOutput(env, argv[i])) {
                MEDIA_INFO_LOG("photo output adding..");
                napi_unwrap(env, argv[i], reinterpret_cast<void**>(&photoOutputNapiObj));
                cameraOutput = photoOutputNapiObj->GetPhotoOutput();
            } else if (VideoOutputNapi::IsVideoOutput(env, argv[i])) {
                MEDIA_INFO_LOG("video output adding..");
                napi_unwrap(env, argv[i], reinterpret_cast<void**>(&videoOutputNapiObj));
                cameraOutput = videoOutputNapiObj->GetVideoOutput();
            } else if (MetadataOutputNapi::IsMetadataOutput(env, argv[i])) {
                MEDIA_INFO_LOG("metadata output adding..");
                napi_unwrap(env, argv[i], reinterpret_cast<void**>(&metadataOutputNapiObj));
                cameraOutput = metadataOutputNapiObj->GetMetadataOutput();
            } else if (DepthDataOutputNapi::IsDepthDataOutput(env, argv[i])) {
                MEDIA_INFO_LOG("depth data output adding..");
                napi_unwrap(env, argv[i], reinterpret_cast<void**>(&depthDataOutputNapiObj));
                cameraOutput = depthDataOutputNapiObj->GetDepthDataOutput();
            } else {
                MEDIA_INFO_LOG("invalid output ..");
                NAPI_ASSERT(env, false, "type mismatch");
            }
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }
    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    return result;
}

napi_value CameraSessionNapi::AddOutput(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("AddOutput is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    if (!CameraNapiUtils::CheckInvalidArgument(env, argc, ARGS_ONE, argv, ADD_OUTPUT)) {
        return result;
    }

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        sptr<CaptureOutput> cameraOutput = nullptr;
        result = GetJSArgsForCameraOutput(env, argc, argv, cameraOutput);
        int32_t ret = cameraSessionNapi->cameraSession_->AddOutput(cameraOutput);
        if (!CameraNapiUtils::CheckError(env, ret)) {
            return nullptr;
        }
    } else {
        MEDIA_ERR_LOG("AddOutput call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::CanAddOutput(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("CanAddOutput is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        sptr<CaptureOutput> cameraOutput = nullptr;
        result = GetJSArgsForCameraOutput(env, argc, argv, cameraOutput);
        bool isSupported = cameraSessionNapi->cameraSession_->CanAddOutput(cameraOutput);
        napi_get_boolean(env, isSupported, &result);
    } else {
        MEDIA_ERR_LOG("CanAddOutput call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::RemoveOutput(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("RemoveOutput is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    if (!CameraNapiUtils::CheckInvalidArgument(env, argc, ARGS_ONE, argv, REMOVE_OUTPUT)) {
        return result;
    }

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        sptr<CaptureOutput> cameraOutput = nullptr;
        result = GetJSArgsForCameraOutput(env, argc, argv, cameraOutput);
        int32_t ret = cameraSessionNapi->cameraSession_->RemoveOutput(cameraOutput);
        if (!CameraNapiUtils::CheckError(env, ret)) {
            return nullptr;
        }
    } else {
        MEDIA_ERR_LOG("RemoveOutput call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::Start(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("Start is called");
    std::unique_ptr<CameraSessionAsyncContext> asyncContext = std::make_unique<CameraSessionAsyncContext>(
        "CameraSessionNapi::Start", CameraNapiUtils::IncrementAndGet(cameraSessionTaskId));
    auto asyncFunction =
        std::make_shared<CameraNapiAsyncFunction>(env, "Start", asyncContext->callbackRef, asyncContext->deferred);
    CameraNapiParamParser jsParamParser(env, info, asyncContext->objectInfo, asyncFunction);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
        MEDIA_ERR_LOG("CameraSessionNapi::Start invalid argument");
        return nullptr;
    }

    napi_status status = napi_create_async_work(
        env, nullptr, asyncFunction->GetResourceName(),
        [](napi_env env, void* data) {
            MEDIA_INFO_LOG("CameraSessionNapi::Start running on worker");
            auto context = static_cast<CameraSessionAsyncContext*>(data);
            CHECK_ERROR_RETURN_LOG(context->objectInfo == nullptr, "CameraSessionNapi::Start async info is nullptr");
            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueId(context->queueId, [&context]() {
                context->errorCode = context->objectInfo->cameraSession_->Start();
                context->status = context->errorCode == CameraErrorCode::SUCCESS;
                MEDIA_INFO_LOG("CameraSessionNapi::Start errorCode:%{public}d", context->errorCode);
            });
        },
        AsyncCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for CameraSessionNapi::Start");
        asyncFunction->Reset();
    } else {
        CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueId(asyncContext->queueId);
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        asyncContext.release();
    }
    if (asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE) {
        return asyncFunction->GetPromise();
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value CameraSessionNapi::Stop(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("Stop is called");
    std::unique_ptr<CameraSessionAsyncContext> asyncContext = std::make_unique<CameraSessionAsyncContext>(
        "CameraSessionNapi::Stop", CameraNapiUtils::IncrementAndGet(cameraSessionTaskId));
    auto asyncFunction =
        std::make_shared<CameraNapiAsyncFunction>(env, "Stop", asyncContext->callbackRef, asyncContext->deferred);
    CameraNapiParamParser jsParamParser(env, info, asyncContext->objectInfo, asyncFunction);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
        MEDIA_ERR_LOG("CameraSessionNapi::Stop invalid argument");
        return nullptr;
    }

    napi_status status = napi_create_async_work(
        env, nullptr, asyncFunction->GetResourceName(),
        [](napi_env env, void* data) {
            MEDIA_INFO_LOG("CameraSessionNapi::Stop running on worker");
            auto context = static_cast<CameraSessionAsyncContext*>(data);
            CHECK_ERROR_RETURN_LOG(context->objectInfo == nullptr, "CameraSessionNapi::Stop async info is nullptr");
            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueId(context->queueId, [&context]() {
                context->errorCode = context->objectInfo->cameraSession_->Stop();
                context->status = context->errorCode == CameraErrorCode::SUCCESS;
                MEDIA_INFO_LOG("CameraSessionNapi::Stop errorCode:%{public}d", context->errorCode);
            });
        },
        AsyncCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for CameraSessionNapi::Stop");
        asyncFunction->Reset();
    } else {
        CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueId(asyncContext->queueId);
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        asyncContext.release();
    }
    if (asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE) {
        return asyncFunction->GetPromise();
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value CameraSessionNapi::Release(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("Release is called");
    std::unique_ptr<CameraSessionAsyncContext> asyncContext = std::make_unique<CameraSessionAsyncContext>(
        "CameraSessionNapi::Release", CameraNapiUtils::IncrementAndGet(cameraSessionTaskId));
    auto asyncFunction =
        std::make_shared<CameraNapiAsyncFunction>(env, "Release", asyncContext->callbackRef, asyncContext->deferred);
    CameraNapiParamParser jsParamParser(env, info, asyncContext->objectInfo, asyncFunction);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
        MEDIA_ERR_LOG("CameraSessionNapi::Release invalid argument");
        return nullptr;
    }

    napi_status status = napi_create_async_work(
        env, nullptr, asyncFunction->GetResourceName(),
        [](napi_env env, void* data) {
            MEDIA_INFO_LOG("CameraSessionNapi::Release running on worker");
            auto context = static_cast<CameraSessionAsyncContext*>(data);
            CHECK_ERROR_RETURN_LOG(context->objectInfo == nullptr, "CameraSessionNapi::Release async info is nullptr");
            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueId(context->queueId, [&context]() {
                context->errorCode = context->objectInfo->cameraSession_->Release();
                context->status = context->errorCode == CameraErrorCode::SUCCESS;
                MEDIA_INFO_LOG("CameraSessionNapi::Release errorCode:%{public}d", context->errorCode);
            });
        },
        AsyncCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for CameraSessionNapi::Release");
        asyncFunction->Reset();
    } else {
        CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueId(asyncContext->queueId);
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        asyncContext.release();
    }
    if (asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE) {
        return asyncFunction->GetPromise();
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value CameraSessionNapi::IsVideoStabilizationModeSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("IsVideoStabilizationModeSupported is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        VideoStabilizationMode videoStabilizationMode = (VideoStabilizationMode)value;
        bool isSupported;
        int32_t retCode = cameraSessionNapi->cameraSession_->
                          IsVideoStabilizationModeSupported(videoStabilizationMode, isSupported);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_get_boolean(env, isSupported, &result);
    } else {
        MEDIA_ERR_LOG("IsVideoStabilizationModeSupported call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::GetActiveVideoStabilizationMode(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetActiveVideoStabilizationMode is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        VideoStabilizationMode videoStabilizationMode;
        int32_t retCode = cameraSessionNapi->cameraSession_->
                          GetActiveVideoStabilizationMode(videoStabilizationMode);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_create_int32(env, videoStabilizationMode, &result);
    } else {
        MEDIA_ERR_LOG("GetActiveVideoStabilizationMode call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::SetVideoStabilizationMode(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetVideoStabilizationMode is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        VideoStabilizationMode videoStabilizationMode = (VideoStabilizationMode)value;
        int retCode = cameraSessionNapi->cameraSession_->SetVideoStabilizationMode(videoStabilizationMode);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
    } else {
        MEDIA_ERR_LOG("SetVideoStabilizationMode call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::HasFlash(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("HasFlash is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        bool isSupported = false;
        int retCode = cameraSessionNapi->cameraSession_->HasFlash(isSupported);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_get_boolean(env, isSupported, &result);
    } else {
        MEDIA_ERR_LOG("HasFlash call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::IsFlashModeSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("IsFlashModeSupported is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        FlashMode flashMode = (FlashMode)value;
        bool isSupported;
        int32_t retCode = cameraSessionNapi->cameraSession_->IsFlashModeSupported(flashMode, isSupported);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_get_boolean(env, isSupported, &result);
    } else {
        MEDIA_ERR_LOG("IsFlashModeSupported call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::SetFlashMode(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetFlashMode is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        FlashMode flashMode = (FlashMode)value;
        cameraSessionNapi->cameraSession_->LockForControl();
        int retCode = cameraSessionNapi->cameraSession_->SetFlashMode(flashMode);
        cameraSessionNapi->cameraSession_->UnlockForControl();
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
    } else {
        MEDIA_ERR_LOG("SetFlashMode call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::GetFlashMode(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetFlashMode is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        FlashMode flashMode;
        int32_t retCode = cameraSessionNapi->cameraSession_->GetFlashMode(flashMode);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_create_int32(env, flashMode, &result);
    } else {
        MEDIA_ERR_LOG("GetFlashMode call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::IsLcdFlashSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("IsLcdFlashSupported is called");
    CAMERA_SYNC_TRACE;
    napi_value result = CameraNapiUtils::GetUndefinedValue(env);
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi isLcdFlashSupported is called!");
        return result;
    }
    CameraSessionNapi* cameraSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionNapi);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("IsLcdFlashSupported parse parameter occur error");
        return result;
    }
    if (cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        bool isSupported = cameraSessionNapi->cameraSession_->IsLcdFlashSupported();
        napi_get_boolean(env, isSupported, &result);
    } else {
        MEDIA_ERR_LOG("IsLcdFlashSupported call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::EnableLcdFlash(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("EnableLcdFlash is called");
    napi_value result = CameraNapiUtils::GetUndefinedValue(env);
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi enableLcdFlash is called!");
        return result;
    }
    bool isEnable;
    CameraSessionNapi* cameraSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionNapi, isEnable);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("EnableLcdFlash parse parameter occur error");
        return result;
    }

    if (cameraSessionNapi->cameraSession_ != nullptr) {
        MEDIA_INFO_LOG("EnableLcdFlash:%{public}d", isEnable);
        cameraSessionNapi->cameraSession_->LockForControl();
        int32_t retCode = cameraSessionNapi->cameraSession_->EnableLcdFlash(isEnable);
        cameraSessionNapi->cameraSession_->UnlockForControl();
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            MEDIA_ERR_LOG("EnableLcdFlash fail %{public}d", retCode);
            return result;
        }
    } else {
        MEDIA_ERR_LOG("EnableLcdFlash get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return result;
    }
    return result;
}

napi_value CameraSessionNapi::IsExposureModeSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("IsExposureModeSupported is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        ExposureMode exposureMode = (ExposureMode)value;
        bool isSupported;
        int32_t retCode = cameraSessionNapi->cameraSession_->
                    IsExposureModeSupported(static_cast<ExposureMode>(exposureMode), isSupported);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_get_boolean(env, isSupported, &result);
    } else {
        MEDIA_ERR_LOG("IsExposureModeSupported call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::GetExposureMode(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetExposureMode is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        ExposureMode exposureMode;
        int32_t retCode = cameraSessionNapi->cameraSession_->GetExposureMode(exposureMode);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_create_int32(env, exposureMode, &result);
    } else {
        MEDIA_ERR_LOG("GetExposureMode call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::SetExposureMode(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetExposureMode is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        ExposureMode exposureMode = (ExposureMode)value;
        cameraSessionNapi->cameraSession_->LockForControl();
        int retCode = cameraSessionNapi->cameraSession_->SetExposureMode(exposureMode);
        cameraSessionNapi->cameraSession_->UnlockForControl();
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
    } else {
        MEDIA_ERR_LOG("SetExposureMode call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::SetMeteringPoint(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetMeteringPoint is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        Point exposurePoint;
        if (GetPointProperties(env, argv[PARAM0], exposurePoint) == 0) {
            cameraSessionNapi->cameraSession_->LockForControl();
            int32_t retCode = cameraSessionNapi->cameraSession_->SetMeteringPoint(exposurePoint);
            cameraSessionNapi->cameraSession_->UnlockForControl();
            if (!CameraNapiUtils::CheckError(env, retCode)) {
                return nullptr;
            }
        } else {
            MEDIA_ERR_LOG("get point failed");
        }
    } else {
        MEDIA_ERR_LOG("SetMeteringPoint call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::GetMeteringPoint(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetMeteringPoint is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        Point exposurePoint;
        int32_t retCode = cameraSessionNapi->cameraSession_->GetMeteringPoint(exposurePoint);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        return GetPointNapiValue(env, exposurePoint);
    } else {
        MEDIA_ERR_LOG("GetMeteringPoint call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::GetExposureBiasRange(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetExposureBiasRange is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        std::vector<float> vecExposureBiasList;
        int32_t retCode = cameraSessionNapi->cameraSession_->GetExposureBiasRange(vecExposureBiasList);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        if (vecExposureBiasList.empty() || napi_create_array(env, &result) != napi_ok) {
            return result;
        }
        size_t len = vecExposureBiasList.size();
        for (size_t i = 0; i < len; i++) {
            float exposureBias = vecExposureBiasList[i];
            MEDIA_DEBUG_LOG("EXPOSURE_BIAS_RANGE : exposureBias = %{public}f", vecExposureBiasList[i]);
            napi_value value;
            napi_create_double(env, CameraNapiUtils::FloatToDouble(exposureBias), &value);
            napi_set_element(env, result, i, value);
        }
        MEDIA_DEBUG_LOG("EXPOSURE_BIAS_RANGE ExposureBiasList size : %{public}zu", vecExposureBiasList.size());
    } else {
        MEDIA_ERR_LOG("GetExposureBiasRange call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::GetExposureValue(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetExposureValue is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi!= nullptr) {
        float exposureValue;
        int32_t retCode = cameraSessionNapi->cameraSession_->GetExposureValue(exposureValue);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_create_double(env, CameraNapiUtils::FloatToDouble(exposureValue), &result);
    } else {
        MEDIA_ERR_LOG("GetExposureValue call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::SetExposureBias(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetExposureBias is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        double exposureValue;
        napi_get_value_double(env, argv[PARAM0], &exposureValue);
        cameraSessionNapi->cameraSession_->LockForControl();
        int32_t retCode = cameraSessionNapi->cameraSession_->SetExposureBias((float)exposureValue);
        cameraSessionNapi->cameraSession_->UnlockForControl();
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
    } else {
        MEDIA_ERR_LOG("SetExposureBias call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::IsFocusModeSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("IsFocusModeSupported is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        FocusMode focusMode = (FocusMode)value;
        bool isSupported;
        int32_t retCode = cameraSessionNapi->cameraSession_->IsFocusModeSupported(focusMode,
                                                                                  isSupported);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_get_boolean(env, isSupported, &result);
    } else {
        MEDIA_ERR_LOG("IsFocusModeSupported call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::GetFocalLength(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetFocalLength is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        float focalLength;
        int32_t retCode = cameraSessionNapi->cameraSession_->GetFocalLength(focalLength);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_create_double(env, CameraNapiUtils::FloatToDouble(focalLength), &result);
    } else {
        MEDIA_ERR_LOG("GetFocalLength call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::SetFocusPoint(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetFocusPoint is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        Point focusPoint;
        if (GetPointProperties(env, argv[PARAM0], focusPoint) == 0) {
            cameraSessionNapi->cameraSession_->LockForControl();
            int32_t retCode = cameraSessionNapi->cameraSession_->SetFocusPoint(focusPoint);
            cameraSessionNapi->cameraSession_->UnlockForControl();
            if (!CameraNapiUtils::CheckError(env, retCode)) {
                return nullptr;
            }
        } else {
            MEDIA_ERR_LOG("get point failed");
        }
    } else {
        MEDIA_ERR_LOG("SetFocusPoint call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::GetFocusPoint(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetFocusPoint is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        Point focusPoint;
        int32_t retCode = cameraSessionNapi->cameraSession_->GetFocusPoint(focusPoint);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        return GetPointNapiValue(env, focusPoint);
    } else {
        MEDIA_ERR_LOG("GetFocusPoint call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::GetFocusMode(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetFocusMode is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        FocusMode focusMode;
        int32_t retCode = cameraSessionNapi->cameraSession_->GetFocusMode(focusMode);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_create_int32(env, focusMode, &result);
    } else {
        MEDIA_ERR_LOG("GetFocusMode call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::SetFocusMode(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetFocusMode is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        FocusMode focusMode = (FocusMode)value;
        cameraSessionNapi->cameraSession_->LockForControl();
        int retCode = cameraSessionNapi->cameraSession_->
                SetFocusMode(static_cast<FocusMode>(focusMode));
        cameraSessionNapi->cameraSession_->UnlockForControl();
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
    } else {
        MEDIA_ERR_LOG("SetFocusMode call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::GetZoomRatioRange(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetZoomRatioRange is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);

    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        std::vector<float> vecZoomRatioList;
        int32_t retCode = cameraSessionNapi->cameraSession_->GetZoomRatioRange(vecZoomRatioList);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        MEDIA_INFO_LOG("CameraSessionNapi::GetZoomRatioRange len = %{public}zu",
            vecZoomRatioList.size());

        if (!vecZoomRatioList.empty() && napi_create_array(env, &result) == napi_ok) {
            for (size_t i = 0; i < vecZoomRatioList.size(); i++) {
                float zoomRatio = vecZoomRatioList[i];
                napi_value value;
                napi_create_double(env, CameraNapiUtils::FloatToDouble(zoomRatio), &value);
                napi_set_element(env, result, i, value);
            }
        } else {
            MEDIA_ERR_LOG("vecSupportedZoomRatioList is empty or failed to create array!");
        }
    } else {
        MEDIA_ERR_LOG("GetZoomRatioRange call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::GetZoomRatio(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetZoomRatio is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        float zoomRatio;
        int32_t retCode = cameraSessionNapi->cameraSession_->GetZoomRatio(zoomRatio);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_create_double(env, CameraNapiUtils::FloatToDouble(zoomRatio), &result);
    } else {
        MEDIA_ERR_LOG("GetZoomRatio call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::SetZoomRatio(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetZoomRatio is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;

    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        double zoomRatio;
        napi_get_value_double(env, argv[PARAM0], &zoomRatio);
        cameraSessionNapi->cameraSession_->LockForControl();
        int32_t retCode = cameraSessionNapi->cameraSession_->SetZoomRatio((float)zoomRatio);
        cameraSessionNapi->cameraSession_->UnlockForControl();
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
    } else {
        MEDIA_ERR_LOG("SetZoomRatio call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::PrepareZoom(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("PrepareZoom is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;

    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        cameraSessionNapi->cameraSession_->LockForControl();
        int32_t retCode = cameraSessionNapi->cameraSession_->PrepareZoom();
        cameraSessionNapi->cameraSession_->UnlockForControl();
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
    } else {
        MEDIA_ERR_LOG("PrepareZoom call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::UnPrepareZoom(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("PrepareZoom is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;

    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        cameraSessionNapi->cameraSession_->LockForControl();
        int32_t retCode = cameraSessionNapi->cameraSession_->UnPrepareZoom();
        cameraSessionNapi->cameraSession_->UnlockForControl();
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
    } else {
        MEDIA_ERR_LOG("PrepareZoom call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::SetSmoothZoom(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetSmoothZoom is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;

    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        double targetZoomRatio;
        int32_t smoothZoomType;
        napi_get_value_double(env, argv[PARAM0], &targetZoomRatio);
        napi_get_value_int32(env, argv[PARAM1], &smoothZoomType);
        cameraSessionNapi->cameraSession_->SetSmoothZoom((float)targetZoomRatio, smoothZoomType);
    } else {
        MEDIA_ERR_LOG("SetSmoothZoom call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::GetZoomPointInfos(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi GetZoomPointInfos is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("GetZoomPointInfos is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);

    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        std::vector<ZoomPointInfo> vecZoomPointInfoList;
        int32_t retCode = cameraSessionNapi->cameraSession_->GetZoomPointInfos(vecZoomPointInfoList);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        MEDIA_INFO_LOG("CameraSessionNapi::GetZoomPointInfos len = %{public}zu",
            vecZoomPointInfoList.size());

        if (!vecZoomPointInfoList.empty() && napi_create_array(env, &result) == napi_ok) {
            for (size_t i = 0; i < vecZoomPointInfoList.size(); i++) {
                ZoomPointInfo zoomPointInfo = vecZoomPointInfoList[i];
                napi_value value;
                napi_value zoomRatio;
                napi_value equivalentFocus;
                napi_create_object(env, &value);
                napi_create_double(env, CameraNapiUtils::FloatToDouble(zoomPointInfo.zoomRatio), &zoomRatio);
                napi_set_named_property(env, value, "zoomRatio", zoomRatio);
                napi_create_double(env, zoomPointInfo.equivalentFocalLength, &equivalentFocus);
                napi_set_named_property(env, value, "equivalentFocalLength", equivalentFocus);
                napi_set_element(env, result, i, value);
            }
        } else {
            MEDIA_ERR_LOG("vecSupportedZoomRatioList is empty or failed to create array!");
        }
    } else {
        MEDIA_ERR_LOG("GetZoomPointInfos call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::GetSupportedFilters(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("getSupportedFilters is called");
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
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        std::vector<FilterType> filterTypes = cameraSessionNapi->cameraSession_->GetSupportedFilters();
        MEDIA_INFO_LOG("CameraSessionNapi::GetSupportedFilters len = %{public}zu",
            filterTypes.size());
        if (!filterTypes.empty()) {
            for (size_t i = 0; i < filterTypes.size(); i++) {
                FilterType filterType = filterTypes[i];
                napi_value value;
                napi_create_int32(env, filterType, &value);
                napi_set_element(env, result, i, value);
            }
        }
    } else {
        MEDIA_ERR_LOG("GetSupportedFilters call Failed!");
    }
    return result;
}
napi_value CameraSessionNapi::GetFilter(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetFilter is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        FilterType filterType = cameraSessionNapi->cameraSession_->GetFilter();
        napi_create_int32(env, filterType, &result);
    } else {
        MEDIA_ERR_LOG("GetFilter call Failed!");
    }
    return result;
}
napi_value CameraSessionNapi::SetFilter(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("setFilter is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        FilterType filterType = (FilterType)value;
        cameraSessionNapi->cameraSession_->LockForControl();
        cameraSessionNapi->cameraSession_->
                SetFilter(static_cast<FilterType>(filterType));
        cameraSessionNapi->cameraSession_->UnlockForControl();
    } else {
        MEDIA_ERR_LOG("SetFilter call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::GetSupportedBeautyTypes(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi GetSupportedBeautyTypes is called!");
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
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        std::vector<BeautyType> beautyTypes = cameraSessionNapi->cameraSession_->GetSupportedBeautyTypes();
        MEDIA_INFO_LOG("CameraSessionNapi::GetSupportedBeautyTypes len = %{public}zu",
            beautyTypes.size());
        if (!beautyTypes.empty() && status == napi_ok) {
            for (size_t i = 0; i < beautyTypes.size(); i++) {
                BeautyType beautyType = beautyTypes[i];
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

napi_value CameraSessionNapi::GetSupportedBeautyRange(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi GetSupportedBeautyRange is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("GetSupportedBeautyRange is called");
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
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        int32_t beautyType;
        napi_get_value_int32(env, argv[PARAM0], &beautyType);
        std::vector<int32_t> beautyRanges =
            cameraSessionNapi->cameraSession_->GetSupportedBeautyRange(static_cast<BeautyType>(beautyType));
        MEDIA_INFO_LOG("CameraSessionNapi::GetSupportedBeautyRange beautyType = %{public}d, len = %{public}zu",
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

napi_value CameraSessionNapi::GetBeauty(napi_env env, napi_callback_info info)
{
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
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        int32_t beautyType;
        napi_get_value_int32(env, argv[PARAM0], &beautyType);
        int32_t beautyStrength = cameraSessionNapi->cameraSession_->GetBeauty(static_cast<BeautyType>(beautyType));
        napi_create_int32(env, beautyStrength, &result);
    } else {
        MEDIA_ERR_LOG("GetBeauty call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::SetBeauty(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi SetBeauty is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("SetBeauty is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        int32_t beautyType;
        napi_get_value_int32(env, argv[PARAM0], &beautyType);
        int32_t beautyStrength;
        napi_get_value_int32(env, argv[PARAM1], &beautyStrength);
        cameraSessionNapi->cameraSession_->LockForControl();
        cameraSessionNapi->cameraSession_->SetBeauty(static_cast<BeautyType>(beautyType), beautyStrength);
        cameraSessionNapi->cameraSession_->UnlockForControl();
    } else {
        MEDIA_ERR_LOG("SetBeauty call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::GetSupportedColorSpaces(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedColorSpaces is called.");
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
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        std::vector<ColorSpace> colorSpaces = cameraSessionNapi->cameraSession_->GetSupportedColorSpaces();
        if (!colorSpaces.empty()) {
            for (size_t i = 0; i < colorSpaces.size(); i++) {
                int colorSpace = colorSpaces[i];
                napi_value value;
                napi_create_int32(env, colorSpace, &value);
                napi_set_element(env, result, i, value);
            }
        }
    } else {
        MEDIA_ERR_LOG("GetSupportedColorSpaces call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::GetActiveColorSpace(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetActiveColorSpace is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        ColorSpace colorSpace;
        int32_t retCode = cameraSessionNapi->cameraSession_->GetActiveColorSpace(colorSpace);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return result;
        }
        napi_create_int32(env, colorSpace, &result);
    } else {
        MEDIA_ERR_LOG("GetActiveColorSpace call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::SetColorSpace(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetColorSpace is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        int32_t colorSpaceNumber;
        napi_get_value_int32(env, argv[PARAM0], &colorSpaceNumber);
        ColorSpace colorSpace = (ColorSpace)colorSpaceNumber;
        int32_t retCode = cameraSessionNapi->cameraSession_->SetColorSpace(colorSpace);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return result;
        }
    } else {
        MEDIA_ERR_LOG("SetColorSpace call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::GetSupportedColorEffects(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedColorEffects is called");
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
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        std::vector<ColorEffect> colorEffects = cameraSessionNapi->cameraSession_->GetSupportedColorEffects();
        if (!colorEffects.empty()) {
            for (size_t i = 0; i < colorEffects.size(); i++) {
                int colorEffect = colorEffects[i];
                napi_value value;
                napi_create_int32(env, colorEffect, &value);
                napi_set_element(env, result, i, value);
            }
        }
    } else {
        MEDIA_ERR_LOG("GetSupportedColorEffects call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::GetColorEffect(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetColorEffect is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        ColorEffect colorEffect = cameraSessionNapi->cameraSession_->GetColorEffect();
        napi_create_int32(env, colorEffect, &result);
    } else {
        MEDIA_ERR_LOG("GetColorEffect call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::SetColorEffect(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetColorEffect is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        int32_t colorEffectNumber;
        napi_get_value_int32(env, argv[PARAM0], &colorEffectNumber);
        ColorEffect colorEffect = (ColorEffect)colorEffectNumber;
        cameraSessionNapi->cameraSession_->LockForControl();
        cameraSessionNapi->cameraSession_->SetColorEffect(static_cast<ColorEffect>(colorEffect));
        cameraSessionNapi->cameraSession_->UnlockForControl();
    } else {
        MEDIA_ERR_LOG("SetColorEffect call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::GetFocusDistance(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetFocusDistance is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        float distance;
        int32_t retCode = cameraSessionNapi->cameraSession_->GetFocusDistance(distance);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_create_double(env, distance, &result);
    } else {
        MEDIA_ERR_LOG("GetFocusDistance call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::SetFocusDistance(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetFocusDistance is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        double value;
        napi_get_value_double(env, argv[PARAM0], &value);
        float distance = static_cast<float>(value);
        cameraSessionNapi->cameraSession_->LockForControl();
        cameraSessionNapi->cameraSession_->SetFocusDistance(distance);
        MEDIA_INFO_LOG("CameraSessionNapi::SetFocusDistance set focusDistance:%{public}f!", distance);
        cameraSessionNapi->cameraSession_->UnlockForControl();
    } else {
        MEDIA_ERR_LOG("SetFocusDistance call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::IsMacroSupported(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsMacroSupported is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("CameraSessionNapi::IsMacroSupported is called");
    CameraSessionNapi* cameraSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionNapi);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("CameraSessionNapi::IsMacroSupported parse parameter occur error");
        return nullptr;
    }
    auto result = CameraNapiUtils::GetUndefinedValue(env);
    if (cameraSessionNapi->cameraSession_ != nullptr) {
        bool isSupported = cameraSessionNapi->cameraSession_->IsMacroSupported();
        napi_get_boolean(env, isSupported, &result);
    } else {
        MEDIA_ERR_LOG("CameraSessionNapi::IsMacroSupported get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return nullptr;
    }
    return result;
}

napi_value CameraSessionNapi::EnableMacro(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi EnableMacro is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("CameraSessionNapi::EnableMacro is called");
    bool isEnableMacro;
    CameraSessionNapi* cameraSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionNapi, isEnableMacro);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("CameraSessionNapi::EnableMacro parse parameter occur error");
        return nullptr;
    }

    if (cameraSessionNapi->cameraSession_ != nullptr) {
        MEDIA_INFO_LOG("CameraSessionNapi::EnableMacro:%{public}d", isEnableMacro);
        cameraSessionNapi->cameraSession_->LockForControl();
        int32_t retCode = cameraSessionNapi->cameraSession_->EnableMacro(isEnableMacro);
        cameraSessionNapi->cameraSession_->UnlockForControl();
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            MEDIA_ERR_LOG("CameraSessionNapi::EnableMacro fail %{public}d", retCode);
            return nullptr;
        }
    } else {
        MEDIA_ERR_LOG("CameraSessionNapi::EnableMacro get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return nullptr;
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value CameraSessionNapi::IsMoonCaptureBoostSupported(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsMoonCaptureBoostSupported is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("IsMoonCaptureBoostSupported is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        bool isSupported = cameraSessionNapi->cameraSession_->IsMoonCaptureBoostSupported();
        napi_get_boolean(env, isSupported, &result);
    } else {
        MEDIA_ERR_LOG("IsMoonCaptureBoostSupported call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::EnableMoonCaptureBoost(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi EnableMoonCaptureBoost is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("EnableMoonCaptureBoost is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = { 0 };
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc == ARGS_ONE, "requires one parameter");
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    if (valueType != napi_boolean && !CameraNapiUtils::CheckError(env, INVALID_ARGUMENT)) {
        return result;
    }
    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        bool isEnableMoonCaptureBoost;
        napi_get_value_bool(env, argv[PARAM0], &isEnableMoonCaptureBoost);
        MEDIA_INFO_LOG("CameraSessionNapi::EnableMoonCaptureBoost:%{public}d", isEnableMoonCaptureBoost);
        cameraSessionNapi->cameraSession_->LockForControl();
        int32_t retCode = cameraSessionNapi->cameraSession_->EnableMoonCaptureBoost(isEnableMoonCaptureBoost);
        cameraSessionNapi->cameraSession_->UnlockForControl();
        if (retCode != 0 && !CameraNapiUtils::CheckError(env, retCode)) {
            return result;
        }
    }
    return result;
}

napi_value CameraSessionNapi::IsFeatureSupported(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsFeatureSupported is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("IsFeatureSupported is called");
    int32_t sceneFeature;
    CameraSessionNapi* cameraSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionNapi, sceneFeature);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("CameraSessionNapi::IsFeatureSupported parse parameter occur error");
        return nullptr;
    }

    napi_value result = nullptr;
    napi_get_boolean(
        env, cameraSessionNapi->cameraSession_->IsFeatureSupported(static_cast<SceneFeature>(sceneFeature)), &result);
    return result;
}

napi_value CameraSessionNapi::EnableFeature(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi EnableFeature is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("EnableFeature is called");
    int32_t sceneFeature;
    bool isEnable;
    CameraSessionNapi* cameraSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionNapi, sceneFeature, isEnable);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("CameraSessionNapi::EnableFeature parse parameter occur error");
        return nullptr;
    }

    MEDIA_INFO_LOG("CameraSessionNapi::EnableFeature:%{public}d", isEnable);
    int32_t retCode =
        cameraSessionNapi->cameraSession_->EnableFeature(static_cast<SceneFeature>(sceneFeature), isEnable);
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        return nullptr;
    }

    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value CameraSessionNapi::CanPreconfig(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("CanPreconfig is called");
    size_t argSize = CameraNapiUtils::GetNapiArgs(env, info);
    int32_t configType;
    int32_t profileSizeRatio = ProfileSizeRatio::UNSPECIFIED;
    CameraSessionNapi* cameraSessionNapi = nullptr;
    if (argSize == ARGS_ONE) {
        CameraNapiParamParser jsParamParser(env, info, cameraSessionNapi, configType);
        if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
            MEDIA_ERR_LOG("CameraSessionNapi::CanPreconfig parse parameter occur error");
            return nullptr;
        }
    } else {
        CameraNapiParamParser jsParamParser(env, info, cameraSessionNapi, configType, profileSizeRatio);
        if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
            MEDIA_ERR_LOG("CameraSessionNapi::CanPreconfig parse 2 parameter occur error");
            return nullptr;
        }
    }

    MEDIA_INFO_LOG("CameraSessionNapi::CanPreconfig: %{public}d, ratioType:%{public}d", configType, profileSizeRatio);
    bool result = cameraSessionNapi->cameraSession_->CanPreconfig(
        static_cast<PreconfigType>(configType), static_cast<ProfileSizeRatio>(profileSizeRatio));
    return CameraNapiUtils::GetBooleanValue(env, result);
}

napi_value CameraSessionNapi::Preconfig(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("Preconfig is called");
    size_t argSize = CameraNapiUtils::GetNapiArgs(env, info);
    int32_t configType;
    int32_t profileSizeRatio = ProfileSizeRatio::UNSPECIFIED;
    CameraSessionNapi* cameraSessionNapi = nullptr;
    if (argSize == ARGS_ONE) {
        CameraNapiParamParser jsParamParser(env, info, cameraSessionNapi, configType);
        if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
            MEDIA_ERR_LOG("CameraSessionNapi::Preconfig parse parameter occur error");
            return nullptr;
        }
    } else {
        CameraNapiParamParser jsParamParser(env, info, cameraSessionNapi, configType, profileSizeRatio);
        if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
            MEDIA_ERR_LOG("CameraSessionNapi::Preconfig parse 2 parameter occur error");
            return nullptr;
        }
    }
    int32_t retCode = cameraSessionNapi->cameraSession_->Preconfig(
        static_cast<PreconfigType>(configType), static_cast<ProfileSizeRatio>(profileSizeRatio));
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        return nullptr;
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value CameraSessionNapi::GetCameraOutputCapabilities(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("GetCameraOutputCapabilities is called");

    size_t argSize = CameraNapiUtils::GetNapiArgs(env, info);
    if (argSize != ARGS_ONE) {
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "Invalid argument.");
        return nullptr;
    }

    std::string cameraId;
    CameraNapiObject cameraInfoObj { { { "cameraId", &cameraId } } };
    CameraSessionNapi* cameraSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionNapi, cameraInfoObj);

    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "Create cameraInput invalid argument!")) {
        MEDIA_ERR_LOG("CameraSessionNapi::GetCameraOutputCapabilities invalid argument");
        return nullptr;
    }

    sptr<CameraDevice> cameraInfo = CameraManager::GetInstance()->GetCameraDeviceFromId(cameraId);
    if (cameraInfo == nullptr) {
        MEDIA_ERR_LOG("cameraInfo is null");
        CameraNapiUtils::ThrowError(env, SERVICE_FATL_ERROR, "cameraInfo is null.");
        return nullptr;
    }

    std::vector<sptr<CameraOutputCapability>> caplist =
        cameraSessionNapi->cameraSession_->GetCameraOutputCapabilities(cameraInfo);
    if (caplist.empty()) {
        MEDIA_ERR_LOG("caplist is empty");
        return nullptr;
    }

    napi_value capArray;
    napi_status status = napi_create_array(env, &capArray);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi array");
        return nullptr;
    }

    for (size_t i = 0; i < caplist.size(); i++) {
        if (caplist[i] == nullptr) {
            continue;
        }
        caplist[i]->RemoveDuplicatesProfiles();
        napi_value cap = CameraNapiObjCameraOutputCapability(*caplist[i]).GenerateNapiValue(env);
        if (cap == nullptr || napi_set_element(env, capArray, i, cap) != napi_ok) {
            MEDIA_ERR_LOG("Failed to create camera napi wrapper object");
            return nullptr;
        }
    }

    return capArray;
}

void ParseSize(napi_env env, napi_value root, Size& size)
{
    MEDIA_DEBUG_LOG("ParseSize is called");
    napi_value res = nullptr;
    if (napi_get_named_property(env, root, "width", &res) == napi_ok) {
        napi_get_value_uint32(env, res, &size.width);
    }

    if (napi_get_named_property(env, root, "height", &res) == napi_ok) {
        napi_get_value_uint32(env, res, &size.height);
    }
}

void ParseProfile(napi_env env, napi_value root, Profile& profile)
{
    MEDIA_DEBUG_LOG("ParseProfile is called");
    napi_value res = nullptr;

    if (napi_get_named_property(env, root, "size", &res) == napi_ok) {
        ParseSize(env, res, profile.size_);
    }

    int32_t intValue = 0;
    if (napi_get_named_property(env, root, "format", &res) == napi_ok) {
        napi_get_value_int32(env, res, &intValue);
        profile.format_ = static_cast<CameraFormat>(intValue);
    }
}

void ParseVideoProfile(napi_env env, napi_value root, VideoProfile& profile)
{
    MEDIA_DEBUG_LOG("ParseVideoProfile is called");
    napi_value res = nullptr;

    if (napi_get_named_property(env, root, "size", &res) == napi_ok) {
        ParseSize(env, res, profile.size_);
    }

    int32_t intValue = 0;
    if (napi_get_named_property(env, root, "format", &res) == napi_ok) {
        napi_get_value_int32(env, res, &intValue);
        profile.format_ = static_cast<CameraFormat>(intValue);
    }

    if (napi_get_named_property(env, root, "frameRateRange", &res) == napi_ok) {
        const int32_t LENGTH = 2;
        std::vector<int32_t> rateRanges(LENGTH);
        napi_value value;

        if (napi_get_named_property(env, res, "min", &value) == napi_ok) {
            napi_get_value_int32(env, value, &rateRanges[0]);
        }
        if (napi_get_named_property(env, res, "max", &value) == napi_ok) {
            napi_get_value_int32(env, value, &rateRanges[1]);
        }
        profile.framerates_ = rateRanges;
    }
}


void ParseProfileList(napi_env env, napi_value arrayParam, std::vector<Profile> &profiles)
{
    uint32_t length = 0;
    napi_get_array_length(env, arrayParam, &length);
    for (uint32_t i = 0; i < length; ++i) {
        napi_value value;
        napi_get_element(env, arrayParam, i, &value);
        Profile profile; // 在栈上创建 Profile 对象
        ParseProfile(env, value, profile);
        profiles.push_back(profile);
    }
}

void ParseVideoProfileList(napi_env env, napi_value arrayParam, std::vector<VideoProfile> &profiles)
{
    uint32_t length = 0;
    napi_get_array_length(env, arrayParam, &length);
    for (uint32_t i = 0; i < length; ++i) {
        napi_value value;
        napi_get_element(env, arrayParam, i, &value);
        VideoProfile profile;
        ParseVideoProfile(env, value, profile);
        profiles.push_back(profile);
    }
}

void ParseCameraOutputCapability(napi_env env, napi_value root,
                                 std::vector<Profile>& previewProfiles,
                                 std::vector<Profile>& photoProfiles,
                                 std::vector<VideoProfile>& videoProfiles)
{
    previewProfiles.clear();
    photoProfiles.clear();
    videoProfiles.clear();
    napi_value res = nullptr;

    if (napi_get_named_property(env, root, "previewProfiles", &res) == napi_ok) {
        ParseProfileList(env, res, previewProfiles);
    }
    if (napi_get_named_property(env, root, "photoProfiles", &res) == napi_ok) {
        ParseProfileList(env, res, photoProfiles);
    }
    if (napi_get_named_property(env, root, "videoProfiles", &res) == napi_ok) {
        ParseVideoProfileList(env, res, videoProfiles);
    }
}

napi_value CameraSessionNapi::GetSessionFunctions(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("GetSessionFunctions is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    std::vector<Profile> previewProfiles;
    std::vector<Profile> photoProfiles;
    std::vector<VideoProfile> videoProfiles;
    ParseCameraOutputCapability(env, argv[PARAM0], previewProfiles, photoProfiles, videoProfiles);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status != napi_ok || cameraSessionNapi == nullptr) {
        MEDIA_ERR_LOG("napi_unwrap failure!");
        return nullptr;
    }
    SceneMode mode = cameraSessionNapi->cameraSession_->GetMode();
    auto cameraAbilityList = cameraSessionNapi->cameraSession_->GetSessionFunctions(
        previewProfiles, photoProfiles, videoProfiles);
    result = CreateAbilitiesJSArray(env, mode, cameraAbilityList, false);
    return result;
}

napi_value CameraSessionNapi::GetSessionConflictFunctions(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("GetSessionConflictFunctions is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);

    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status != napi_ok || cameraSessionNapi == nullptr) {
        MEDIA_ERR_LOG("napi_unwrap failure!");
        return nullptr;
    }
    SceneMode mode = cameraSessionNapi->cameraSession_->GetMode();
    auto conflictAbilityList = cameraSessionNapi->cameraSession_->GetSessionConflictFunctions();
    result = CreateAbilitiesJSArray(env, mode, conflictAbilityList, true);
    return result;
}

napi_value CameraSessionNapi::CreateAbilitiesJSArray(
    napi_env env, SceneMode mode, std::vector<sptr<CameraAbility>> abilityList, bool isConflict)
{
    MEDIA_DEBUG_LOG("create conflict ability is called");
    napi_value abilityArray = nullptr;
    napi_value ability = nullptr;
    napi_status status;

    if (abilityList.empty()) {
        MEDIA_ERR_LOG("abilityArray is empty");
    }

    status = napi_create_array(env, &abilityArray);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("napi_create_array failed");
        return abilityArray;
    }

    using CreateFunc = std::function<napi_value(napi_env, sptr<CameraAbility>)>;
    CreateFunc createFunc;
    if (mode == SceneMode::PORTRAIT) {
        createFunc = isConflict ? PortraitPhotoConflictAbilityNapi::CreatePortraitPhotoConflictAbility
                                : PortraitPhotoAbilityNapi::CreatePortraitPhotoAbility;
    } else if (mode == SceneMode::CAPTURE) {
        createFunc = isConflict ? PhotoConflictAbilityNapi::CreatePhotoConflictAbility
                                : PhotoAbilityNapi::CreatePhotoAbility;
    } else if (mode == SceneMode::VIDEO) {
        createFunc = isConflict ? VideoConflictAbilityNapi::CreateVideoConflictAbility
                                : VideoAbilityNapi::CreateVideoAbility;
    } else {
        MEDIA_ERR_LOG("mode: %{public}d not suppport", static_cast<int32_t>(mode));
        return nullptr;
    }

    size_t j = 0;
    for (size_t i = 0; i < abilityList.size(); i++) {
        ability = createFunc(env, abilityList[i]);
        if ((ability == nullptr) || napi_set_element(env, abilityArray, j++, ability) != napi_ok) {
            MEDIA_ERR_LOG("failed to create conflict ability object napi wrapper object");
            return nullptr;
        }
    }
    MEDIA_INFO_LOG("create conflict ability count = %{public}zu", j);
    return abilityArray;
}

napi_value CameraSessionNapi::IsEffectSuggestionSupported(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env, false)) {
        MEDIA_ERR_LOG("SystemApi IsEffectSuggestionSupported is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("IsEffectSuggestionSupported is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        bool isEffectSuggestionSupported = cameraSessionNapi->cameraSession_->IsEffectSuggestionSupported();
        napi_get_boolean(env, isEffectSuggestionSupported, &result);
    } else {
        MEDIA_ERR_LOG("IsEffectSuggestionSupported call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::EnableEffectSuggestion(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env, false)) {
        MEDIA_ERR_LOG("SystemApi EnableEffectSuggestion is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("EnableEffectSuggestion is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = { 0 };
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc == ARGS_ONE, "requires one parameter");
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    if (valueType != napi_boolean && !CameraNapiUtils::CheckError(env, INVALID_ARGUMENT)) {
        return result;
    }
    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        bool enabled;
        napi_get_value_bool(env, argv[PARAM0], &enabled);
        MEDIA_INFO_LOG("CameraSessionNapi::EnableEffectSuggestion:%{public}d", enabled);
        cameraSessionNapi->cameraSession_->LockForControl();
        int32_t retCode = cameraSessionNapi->cameraSession_->EnableEffectSuggestion(enabled);
        cameraSessionNapi->cameraSession_->UnlockForControl();
        if (retCode != 0 && !CameraNapiUtils::CheckError(env, retCode)) {
            return result;
        }
    }
    return result;
}

napi_value CameraSessionNapi::GetSupportedEffectSuggestionType(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env, false)) {
        MEDIA_ERR_LOG("SystemApi GetSupportedEffectSuggestionType is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("GetSupportedEffectSuggestionType is called");
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
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        std::vector<EffectSuggestionType> effectSuggestionTypeList =
            cameraSessionNapi->cameraSession_->GetSupportedEffectSuggestionType();
        if (!effectSuggestionTypeList.empty()) {
            for (size_t i = 0; i < effectSuggestionTypeList.size(); i++) {
                int type = effectSuggestionTypeList[i];
                napi_value value;
                napi_create_int32(env, type, &value);
                napi_set_element(env, result, i, value);
            }
        }
    } else {
        MEDIA_ERR_LOG("GetSupportedEffectSuggestionType call Failed!");
    }
    return result;
}

static void ParseEffectSuggestionStatus(napi_env env, napi_value arrayParam,
    std::vector<EffectSuggestionStatus> &effectSuggestionStatusList)
{
    MEDIA_DEBUG_LOG("ParseEffectSuggestionStatus is called");
    uint32_t length = 0;
    napi_value value;
    napi_get_array_length(env, arrayParam, &length);
    for (uint32_t i = 0; i < length; i++) {
        napi_get_element(env, arrayParam, i, &value);
        napi_value res = nullptr;
        EffectSuggestionStatus effectSuggestionStatus;
        int32_t intValue = 0;
        if (napi_get_named_property(env, value, "type", &res) == napi_ok) {
            napi_get_value_int32(env, res, &intValue);
            effectSuggestionStatus.type = static_cast<EffectSuggestionType>(intValue);
        }
        bool enabled = false;
        if (napi_get_named_property(env, value, "status", &res) == napi_ok) {
            napi_get_value_bool(env, res, &enabled);
            effectSuggestionStatus.status = enabled;
        }
        effectSuggestionStatusList.push_back(effectSuggestionStatus);
    }
}

napi_value CameraSessionNapi::SetEffectSuggestionStatus(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env, false)) {
        MEDIA_ERR_LOG("SystemApi SetEffectSuggestionStatus is called!");
        return nullptr;
    }
    MEDIA_INFO_LOG("SetEffectSuggestionStatus is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    std::vector<EffectSuggestionStatus> effectSuggestionStatusList;
    ParseEffectSuggestionStatus(env, argv[PARAM0], effectSuggestionStatusList);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        cameraSessionNapi->cameraSession_->LockForControl();
        int32_t retCode = cameraSessionNapi->cameraSession_->SetEffectSuggestionStatus(effectSuggestionStatusList);
        cameraSessionNapi->cameraSession_->UnlockForControl();
        if (retCode != 0 && !CameraNapiUtils::CheckError(env, retCode)) {
            return result;
        }
    }
    return result;
}

napi_value CameraSessionNapi::UpdateEffectSuggestion(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env, false)) {
        MEDIA_ERR_LOG("SystemApi UpdateEffectSuggestion is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("UpdateEffectSuggestion is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = { 0, 0 };
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc == ARGS_TWO, "requires two parameter");
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[PARAM0], &valueType);
    if (valueType != napi_number && !CameraNapiUtils::CheckError(env, INVALID_ARGUMENT)) {
        return result;
    }
    napi_typeof(env, argv[PARAM1], &valueType);
    if (valueType != napi_boolean && !CameraNapiUtils::CheckError(env, INVALID_ARGUMENT)) {
        return result;
    }

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        auto effectSuggestionType = (EffectSuggestionType)value;
        bool enabled;
        napi_get_value_bool(env, argv[PARAM1], &enabled);
        MEDIA_INFO_LOG("CameraSessionNapi::UpdateEffectSuggestion:%{public}d enabled:%{public}d",
            effectSuggestionType, enabled);
        cameraSessionNapi->cameraSession_->LockForControl();
        int32_t retCode = cameraSessionNapi->cameraSession_->UpdateEffectSuggestion(effectSuggestionType, enabled);
        cameraSessionNapi->cameraSession_->UnlockForControl();
        if (retCode != 0 && !CameraNapiUtils::CheckError(env, retCode)) {
            return result;
        }
    }
    return result;
}

// ------------------------------------------------auto_awb_props-------------------------------------------------------
napi_value CameraSessionNapi::GetSupportedWhiteBalanceModes(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedWhiteBalanceModes is called");
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
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        std::vector<WhiteBalanceMode> whiteBalanceModes;
        int32_t retCode = cameraSessionNapi->cameraSession_->GetSupportedWhiteBalanceModes(whiteBalanceModes);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }

        MEDIA_INFO_LOG("ProfessionSessionNapi::GetSupportedWhiteBalanceModes len = %{public}zu",
            whiteBalanceModes.size());
        if (!whiteBalanceModes.empty()) {
            for (size_t i = 0; i < whiteBalanceModes.size(); i++) {
                WhiteBalanceMode whiteBalanceMode = whiteBalanceModes[i];
                napi_value value;
                napi_create_int32(env, whiteBalanceMode, &value);
                napi_set_element(env, result, i, value);
            }
        }
    } else {
        MEDIA_ERR_LOG("GetSupportedWhiteBalanceModes call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::IsWhiteBalanceModeSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("IsWhiteBalanceModeSupported is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        WhiteBalanceMode mode = (WhiteBalanceMode)value;
        bool isSupported;
        int32_t retCode = cameraSessionNapi->cameraSession_->IsWhiteBalanceModeSupported(mode, isSupported);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_get_boolean(env, isSupported, &result);
    } else {
        MEDIA_ERR_LOG("IsWhiteBalanceModeSupported call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::GetWhiteBalanceMode(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetWhiteBalanceMode is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        WhiteBalanceMode whiteBalanceMode;
        int32_t retCode = cameraSessionNapi->cameraSession_->GetWhiteBalanceMode(whiteBalanceMode);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_create_int32(env, whiteBalanceMode, &result);
    } else {
        MEDIA_ERR_LOG("GetWhiteBalanceMode call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::SetWhiteBalanceMode(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetWhiteBalanceMode is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        WhiteBalanceMode mode = (WhiteBalanceMode)value;
        cameraSessionNapi->cameraSession_->LockForControl();
        cameraSessionNapi->cameraSession_->SetWhiteBalanceMode(mode);
        MEDIA_INFO_LOG("ProfessionSessionNapi::SetWhiteBalanceMode set mode:%{public}d", value);
        cameraSessionNapi->cameraSession_->UnlockForControl();
    } else {
        MEDIA_ERR_LOG("SetWhiteBalanceMode call Failed!");
    }
    return result;
}

// -----------------------------------------------manual_awb_props------------------------------------------------------
napi_value CameraSessionNapi::GetManualWhiteBalanceRange(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetManualWhiteBalanceRange is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);

    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        std::vector<int32_t> whiteBalanceRange = {};
        int32_t retCode = cameraSessionNapi->cameraSession_->GetManualWhiteBalanceRange(whiteBalanceRange);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        MEDIA_INFO_LOG("ProfessionSessionNapi::GetManualWhiteBalanceRange len = %{public}zu", whiteBalanceRange.size());

        if (!whiteBalanceRange.empty() && napi_create_array(env, &result) == napi_ok) {
            for (size_t i = 0; i < whiteBalanceRange.size(); i++) {
                int32_t iso = whiteBalanceRange[i];
                napi_value value;
                napi_create_int32(env, iso, &value);
                napi_set_element(env, result, i, value);
            }
        } else {
            MEDIA_ERR_LOG("whiteBalanceRange is empty or failed to create array!");
        }
    } else {
        MEDIA_ERR_LOG("GetManualWhiteBalanceRange call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::IsManualWhiteBalanceSupported(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsManualIsoSupported is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("IsManualIsoSupported is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        bool isSupported;
        int32_t retCode = cameraSessionNapi->cameraSession_->IsManualWhiteBalanceSupported(isSupported);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_get_boolean(env, isSupported, &result);
    } else {
        MEDIA_ERR_LOG("IsManualIsoSupported call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::GetManualWhiteBalance(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetISO is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        int32_t wbValue;
        int32_t retCode = cameraSessionNapi->cameraSession_->GetManualWhiteBalance(wbValue);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_create_int32(env, wbValue, &result);
    } else {
        MEDIA_ERR_LOG("GetISO call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::SetManualWhiteBalance(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetManualWhiteBalance is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        int32_t wbValue;
        napi_get_value_int32(env, argv[PARAM0], &wbValue);
        cameraSessionNapi->cameraSession_->LockForControl();
        cameraSessionNapi->cameraSession_->SetManualWhiteBalance(wbValue);
        MEDIA_INFO_LOG("ProfessionSessionNapi::SetManualWhiteBalance set wbValue:%{public}d", wbValue);
        cameraSessionNapi->cameraSession_->UnlockForControl();
    } else {
        MEDIA_ERR_LOG("SetManualWhiteBalance call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::GetSupportedVirtualApertures(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi GetSupportedVirtualApertures is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("GetSupportedVirtualApertures is called");
    CameraSessionNapi* cameraSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionNapi);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("CameraSessionNapi::GetSupportedVirtualApertures parse parameter occur error");
        return nullptr;
    }

    napi_status status;
    napi_value result = nullptr;
    status = napi_create_array(env, &result);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("napi_create_array call Failed!");
        return nullptr;
    }

    if (cameraSessionNapi->cameraSession_ != nullptr) {
        std::vector<float> virtualApertures = {};
        int32_t retCode = cameraSessionNapi->cameraSession_->GetSupportedVirtualApertures(virtualApertures);
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

napi_value CameraSessionNapi::GetVirtualAperture(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi GetVirtualAperture is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("GetVirtualAperture is called");
    CameraSessionNapi* cameraSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionNapi);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("CameraSessionNapi::GetVirtualAperture parse parameter occur error");
        return nullptr;
    }
    if (cameraSessionNapi->cameraSession_ != nullptr) {
        float virtualAperture;
        int32_t retCode = cameraSessionNapi->cameraSession_->GetVirtualAperture(virtualAperture);
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

napi_value CameraSessionNapi::SetVirtualAperture(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi SetVirtualAperture is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("SetVirtualAperture is called");
    double virtualAperture;
    CameraSessionNapi* cameraSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionNapi, virtualAperture);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("CameraSessionNapi::SetVirtualAperture parse parameter occur error");
        return nullptr;
    }
    if (cameraSessionNapi->cameraSession_ != nullptr) {
        cameraSessionNapi->cameraSession_->LockForControl();
        cameraSessionNapi->cameraSession_->SetVirtualAperture((float)virtualAperture);
        MEDIA_INFO_LOG("SetVirtualAperture set virtualAperture %{public}f!", virtualAperture);
        cameraSessionNapi->cameraSession_->UnlockForControl();
    } else {
        MEDIA_ERR_LOG("SetVirtualAperture call Failed!");
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value CameraSessionNapi::GetSupportedPhysicalApertures(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi GetSupportedPhysicalApertures is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("GetSupportedPhysicalApertures is called");
    CameraSessionNapi* cameraSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionNapi);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("CameraSessionNapi::GetSupportedPhysicalApertures parse parameter occur error");
        return nullptr;
    }

    napi_status status;
    napi_value result = nullptr;
    status = napi_create_array(env, &result);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("napi_create_array call Failed!");
        return nullptr;
    }

    if (status == napi_ok && cameraSessionNapi->cameraSession_ != nullptr) {
        std::vector<std::vector<float>> physicalApertures = {};
        int32_t retCode = cameraSessionNapi->cameraSession_->GetSupportedPhysicalApertures(physicalApertures);
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

napi_value CameraSessionNapi::GetPhysicalAperture(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi GetPhysicalAperture is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("GetPhysicalAperture is called");
    CameraSessionNapi* cameraSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionNapi);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("CameraSessionNapi::GetPhysicalAperture parse parameter occur error");
        return nullptr;
    }

    if (cameraSessionNapi->cameraSession_ != nullptr) {
        float physicalAperture = 0.0;
        int32_t retCode = cameraSessionNapi->cameraSession_->GetPhysicalAperture(physicalAperture);
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

napi_value CameraSessionNapi::SetPhysicalAperture(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi SetPhysicalAperture is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("SetPhysicalAperture is called");
    double physicalAperture;
    CameraSessionNapi* cameraSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionNapi, physicalAperture);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("CameraSessionNapi::SetPhysicalAperture parse parameter occur error");
        return nullptr;
    }

    if (cameraSessionNapi->cameraSession_ != nullptr) {
        cameraSessionNapi->cameraSession_->LockForControl();
        int32_t retCode = cameraSessionNapi->cameraSession_->SetPhysicalAperture((float)physicalAperture);
        MEDIA_INFO_LOG("SetPhysicalAperture set physicalAperture %{public}f!", ConfusingNumber(physicalAperture));
        cameraSessionNapi->cameraSession_->UnlockForControl();
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
    } else {
        MEDIA_ERR_LOG("SetPhysicalAperture call Failed!");
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

void CameraSessionNapi::RegisterExposureCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (exposureCallback_ == nullptr) {
        exposureCallback_ = std::make_shared<ExposureCallbackListener>(env);
        cameraSession_->SetExposureCallback(exposureCallback_);
    }
    exposureCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void CameraSessionNapi::UnregisterExposureCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (exposureCallback_ == nullptr) {
        MEDIA_ERR_LOG("exposureCallback is null");
        return;
    }
    exposureCallback_->RemoveCallbackRef(eventName, callback);
}

void CameraSessionNapi::RegisterFocusCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (focusCallback_ == nullptr) {
        focusCallback_ = make_shared<FocusCallbackListener>(env);
        cameraSession_->SetFocusCallback(focusCallback_);
    }
    focusCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void CameraSessionNapi::UnregisterFocusCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (focusCallback_ == nullptr) {
        MEDIA_ERR_LOG("focusCallback is null");
        return;
    }
    focusCallback_->RemoveCallbackRef(eventName, callback);
}

void CameraSessionNapi::RegisterMacroStatusCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi on macroStatusChanged is called!");
        return;
    }
    if (macroStatusCallback_ == nullptr) {
        macroStatusCallback_ = std::make_shared<MacroStatusCallbackListener>(env);
        cameraSession_->SetMacroStatusCallback(macroStatusCallback_);
    }
    macroStatusCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void CameraSessionNapi::UnregisterMacroStatusCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi off macroStatusChanged is called!");
        return;
    }
    if (macroStatusCallback_ == nullptr) {
        MEDIA_ERR_LOG("macroStatusCallback is null");
        return;
    }
    macroStatusCallback_->RemoveCallbackRef(eventName, callback);
}

void CameraSessionNapi::RegisterMoonCaptureBoostCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi on moonCaptureBoostStatus is called!");
        return;
    }
    if (moonCaptureBoostCallback_ == nullptr) {
        moonCaptureBoostCallback_ = std::make_shared<MoonCaptureBoostCallbackListener>(env);
        cameraSession_->SetMoonCaptureBoostStatusCallback(moonCaptureBoostCallback_);
    }
    moonCaptureBoostCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void CameraSessionNapi::UnregisterMoonCaptureBoostCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi off moonCaptureBoostStatus is called!");
        return;
    }
    if (moonCaptureBoostCallback_ == nullptr) {
        MEDIA_ERR_LOG("macroStatusCallback is null");
        return;
    }
    moonCaptureBoostCallback_->RemoveCallbackRef(eventName, callback);
}

void CameraSessionNapi::RegisterFeatureDetectionStatusListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi on featureDetectionStatus is called!");
        return;
    }
    int32_t featureType = SceneFeature::FEATURE_ENUM_MAX;
    CameraNapiParamParser jsParamParser(env, args, featureType);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "Invalid feature type")) {
        MEDIA_ERR_LOG("CameraSessionNapi::RegisterFeatureDetectionStatusListener Invalid feature type");
        return;
    }
    if (featureType < SceneFeature::FEATURE_ENUM_MIN || featureType >= SceneFeature::FEATURE_ENUM_MAX) {
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "scene feature invalid");
        MEDIA_ERR_LOG("CameraSessionNapi::RegisterFeatureDetectionStatusListener scene feature invalid");
        return;
    }

    if (featureDetectionStatusCallback_ == nullptr) {
        featureDetectionStatusCallback_ = std::make_shared<FeatureDetectionStatusCallbackListener>(env);
        cameraSession_->SetFeatureDetectionStatusCallback(featureDetectionStatusCallback_);
    }

    if (featureType == SceneFeature::FEATURE_LOW_LIGHT_BOOST) {
        cameraSession_->LockForControl();
        cameraSession_->EnableLowLightDetection(true);
        cameraSession_->UnlockForControl();
    }

    featureDetectionStatusCallback_->SaveCallbackReference(eventName + std::to_string(featureType), callback, isOnce);
}

void CameraSessionNapi::UnregisterFeatureDetectionStatusListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi off featureDetectionStatus is called!");
        return;
    }
    if (featureDetectionStatusCallback_ == nullptr) {
        MEDIA_WARNING_LOG("featureDetectionStatusCallback_ is null");
        return;
    }
    int32_t featureType = SceneFeature::FEATURE_ENUM_MAX;
    CameraNapiParamParser jsParamParser(env, args, featureType);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "Invalid feature type")) {
        MEDIA_ERR_LOG("CameraSessionNapi::RegisterFeatureDetectionStatusListener Invalid feature type");
        return;
    }
    if (featureType < SceneFeature::FEATURE_ENUM_MIN || featureType >= SceneFeature::FEATURE_ENUM_MAX) {
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "scene feature invalid");
        MEDIA_ERR_LOG("CameraSessionNapi::RegisterFeatureDetectionStatusListener scene feature invalid");
        return;
    }

    featureDetectionStatusCallback_->RemoveCallbackRef(eventName + std::to_string(featureType), callback);

    if (featureType == SceneFeature::FEATURE_LOW_LIGHT_BOOST &&
        !featureDetectionStatusCallback_->IsFeatureSubscribed(SceneFeature::FEATURE_LOW_LIGHT_BOOST)) {
        cameraSession_->LockForControl();
        cameraSession_->EnableLowLightDetection(false);
        cameraSession_->UnlockForControl();
    }
}

void CameraSessionNapi::RegisterSessionErrorCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (sessionCallback_ == nullptr) {
        sessionCallback_ = std::make_shared<SessionCallbackListener>(env);
        cameraSession_->SetCallback(sessionCallback_);
    }
    sessionCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void CameraSessionNapi::UnregisterSessionErrorCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (sessionCallback_ == nullptr) {
        MEDIA_ERR_LOG("sessionCallback is null");
        return;
    }
    sessionCallback_->RemoveCallbackRef(eventName, callback);
}

void CameraSessionNapi::RegisterEffectSuggestionCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (effectSuggestionCallback_ == nullptr) {
        auto effectSuggestionCallback = std::make_shared<EffectSuggestionCallbackListener>(env);
        effectSuggestionCallback_ = effectSuggestionCallback;
        cameraSession_->SetEffectSuggestionCallback(effectSuggestionCallback);
    }
    effectSuggestionCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void CameraSessionNapi::UnregisterEffectSuggestionCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (effectSuggestionCallback_ == nullptr) {
        MEDIA_ERR_LOG("effectSuggestionCallback is null");
    } else {
        effectSuggestionCallback_->RemoveCallbackRef(eventName, callback);
    }
}

void CameraSessionNapi::RegisterAbilityChangeCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (abilityCallback_ == nullptr) {
        auto abilityCallback = std::make_shared<AbilityCallbackListener>(env);
        abilityCallback_ = abilityCallback;
        cameraSession_->SetAbilityCallback(abilityCallback);
    }
    abilityCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void CameraSessionNapi::UnregisterAbilityChangeCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (abilityCallback_ == nullptr) {
        MEDIA_ERR_LOG("abilityCallback is null");
    } else {
        abilityCallback_->RemoveCallbackRef(eventName, callback);
    }
}

void CameraSessionNapi::RegisterSmoothZoomCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (smoothZoomCallback_ == nullptr) {
        smoothZoomCallback_ = std::make_shared<SmoothZoomCallbackListener>(env);
        cameraSession_->SetSmoothZoomCallback(smoothZoomCallback_);
    }
    smoothZoomCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void CameraSessionNapi::UnregisterSmoothZoomCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (smoothZoomCallback_ == nullptr) {
        MEDIA_ERR_LOG("smoothZoomCallback is null");
        return;
    }
    smoothZoomCallback_->RemoveCallbackRef(eventName, callback);
}

void CameraSessionNapi::RegisterExposureInfoCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    CameraNapiUtils::ThrowError(
        env, CameraErrorCode::OPERATION_NOT_ALLOWED, "this type callback can not be registered in current session!");
}

void CameraSessionNapi::UnregisterExposureInfoCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    CameraNapiUtils::ThrowError(
        env, CameraErrorCode::OPERATION_NOT_ALLOWED, "this type callback can not be unregistered in current session!");
}

void CameraSessionNapi::RegisterIsoInfoCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    CameraNapiUtils::ThrowError(
        env, CameraErrorCode::OPERATION_NOT_ALLOWED, "this type callback can not be registered in current session!");
}

void CameraSessionNapi::UnregisterIsoInfoCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    CameraNapiUtils::ThrowError(
        env, CameraErrorCode::OPERATION_NOT_ALLOWED, "this type callback can not be unregistered in current session!");
}

void CameraSessionNapi::RegisterApertureInfoCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    CameraNapiUtils::ThrowError(
        env, CameraErrorCode::OPERATION_NOT_ALLOWED, "this type callback can not be registered in current session!");
}

void CameraSessionNapi::UnregisterApertureInfoCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    CameraNapiUtils::ThrowError(
        env, CameraErrorCode::OPERATION_NOT_ALLOWED, "this type callback can not be unregistered in current session!");
}

void CameraSessionNapi::RegisterLuminationInfoCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    CameraNapiUtils::ThrowError(
        env, CameraErrorCode::OPERATION_NOT_ALLOWED, "this type callback can not be registered in current session!");
}

void CameraSessionNapi::UnregisterLuminationInfoCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    CameraNapiUtils::ThrowError(
        env, CameraErrorCode::OPERATION_NOT_ALLOWED, "this type callback can not be unregistered in current session!");
}

void CameraSessionNapi::RegisterSlowMotionStateCb(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    CameraNapiUtils::ThrowError(
        env, CameraErrorCode::OPERATION_NOT_ALLOWED, "this type callback can not be unregistered in current session!");
}

void CameraSessionNapi::UnregisterSlowMotionStateCb(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    CameraNapiUtils::ThrowError(
        env, CameraErrorCode::OPERATION_NOT_ALLOWED, "this type callback can not be unregistered in current session!");
}

void CameraSessionNapi::RegisterTryAEInfoCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    CameraNapiUtils::ThrowError(env, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "this type callback can not be registered in current session!");
}

void CameraSessionNapi::UnregisterTryAEInfoCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    CameraNapiUtils::ThrowError(env, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "this type callback can not be unregistered in current session!");
}

const CameraSessionNapi::EmitterFunctions CameraSessionNapi::fun_map_ = {
    { "exposureStateChange", {
        &CameraSessionNapi::RegisterExposureCallbackListener,
        &CameraSessionNapi::UnregisterExposureCallbackListener} },
    { "focusStateChange", {
        &CameraSessionNapi::RegisterFocusCallbackListener,
        &CameraSessionNapi::UnregisterFocusCallbackListener } },
    { "macroStatusChanged", {
        &CameraSessionNapi::RegisterMacroStatusCallbackListener,
        &CameraSessionNapi::UnregisterMacroStatusCallbackListener } },
    { "moonCaptureBoostStatus", {
        &CameraSessionNapi::RegisterMoonCaptureBoostCallbackListener,
        &CameraSessionNapi::UnregisterMoonCaptureBoostCallbackListener } },
    { "featureDetection", {
        &CameraSessionNapi::RegisterFeatureDetectionStatusListener,
        &CameraSessionNapi::UnregisterFeatureDetectionStatusListener } },
    { "featureDetectionStatus", {
        &CameraSessionNapi::RegisterFeatureDetectionStatusListener,
        &CameraSessionNapi::UnregisterFeatureDetectionStatusListener } },
    { "error", {
        &CameraSessionNapi::RegisterSessionErrorCallbackListener,
        &CameraSessionNapi::UnregisterSessionErrorCallbackListener } },
    { "smoothZoomInfoAvailable", {
        &CameraSessionNapi::RegisterSmoothZoomCallbackListener,
        &CameraSessionNapi::UnregisterSmoothZoomCallbackListener } },
    { "slowMotionStatus", {
        &CameraSessionNapi::RegisterSlowMotionStateCb,
        &CameraSessionNapi::UnregisterSlowMotionStateCb } },
    { "exposureInfoChange", {
        &CameraSessionNapi::RegisterExposureInfoCallbackListener,
        &CameraSessionNapi::UnregisterExposureInfoCallbackListener} },
    { "isoInfoChange", {
        &CameraSessionNapi::RegisterIsoInfoCallbackListener,
        &CameraSessionNapi::UnregisterIsoInfoCallbackListener } },
    { "apertureInfoChange", {
        &CameraSessionNapi::RegisterApertureInfoCallbackListener,
        &CameraSessionNapi::UnregisterApertureInfoCallbackListener } },
    { "luminationInfoChange", {
        &CameraSessionNapi::RegisterLuminationInfoCallbackListener,
        &CameraSessionNapi::UnregisterLuminationInfoCallbackListener } },
    { "abilityChange", {
        &CameraSessionNapi::RegisterAbilityChangeCallbackListener,
        &CameraSessionNapi::UnregisterAbilityChangeCallbackListener } },
    { "effectSuggestionChange", {
        &CameraSessionNapi::RegisterEffectSuggestionCallbackListener,
        &CameraSessionNapi::UnregisterEffectSuggestionCallbackListener } },
    { "tryAEInfoChange", {
        &CameraSessionNapi::RegisterTryAEInfoCallbackListener,
        &CameraSessionNapi::UnregisterTryAEInfoCallbackListener } },
    { "lcdFlashStatus", {
        &CameraSessionNapi::RegisterLcdFlashStatusCallbackListener,
        &CameraSessionNapi::UnregisterLcdFlashStatusCallbackListener } },
};

const CameraSessionNapi::EmitterFunctions& CameraSessionNapi::GetEmitterFunctions()
{
    return fun_map_;
}

napi_value CameraSessionNapi::On(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<CameraSessionNapi>::On(env, info);
}

napi_value CameraSessionNapi::Once(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<CameraSessionNapi>::Once(env, info);
}

napi_value CameraSessionNapi::Off(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<CameraSessionNapi>::Off(env, info);
}

void CameraSessionNapi::RegisterLcdFlashStatusCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi on LcdFlashStatus is called!");
        return;
    }
    if (cameraSession_ == nullptr) {
        MEDIA_ERR_LOG("cameraSession is null!");
        return;
    }
    if (lcdFlashStatusCallback_ == nullptr) {
        lcdFlashStatusCallback_ = std::make_shared<LcdFlashStatusCallbackListener>(env);
        cameraSession_->SetLcdFlashStatusCallback(lcdFlashStatusCallback_);
    }
    lcdFlashStatusCallback_->SaveCallbackReference(eventName, callback, isOnce);
    cameraSession_->LockForControl();
    cameraSession_->EnableLcdFlashDetection(true);
    cameraSession_->UnlockForControl();
}

void CameraSessionNapi::UnregisterLcdFlashStatusCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (lcdFlashStatusCallback_ == nullptr) {
        MEDIA_ERR_LOG("lcdFlashStatusCallback is null");
        return;
    }
    lcdFlashStatusCallback_->RemoveCallbackRef(eventName, callback);
    if (lcdFlashStatusCallback_->IsEmpty("lcdFlashStatus")) {
        cameraSession_->LockForControl();
        cameraSession_->EnableLcdFlashDetection(false);
        cameraSession_->UnlockForControl();
    }
}
} // namespace CameraStandard
} // namespace OHOS
