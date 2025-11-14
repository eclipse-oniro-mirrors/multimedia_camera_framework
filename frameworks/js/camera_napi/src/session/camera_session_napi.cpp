/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#include "camera_log.h"
#include "camera_napi_const.h"
#include "camera_napi_object.h"
#include "camera_napi_object_types.h"
#include "camera_napi_param_parser.h"
#include "camera_napi_security_utils.h"
#include "camera_napi_template_utils.h"
#include "camera_napi_utils.h"
#include "camera_output_capability.h"
#include "capture_scene_const.h"
#include "capture_session.h"
#include "dynamic_loader/camera_napi_ex_manager.h"
#include "icapture_session_callback.h"
#include "input/camera_device.h"
#include "input/camera_input_napi.h"
#include "js_native_api.h"
#include "js_native_api_types.h"
#include "listener_base.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "output/metadata_output_napi.h"
#include "output/photo_output_napi.h"
#include "output/preview_output_napi.h"
#include "output/video_output_napi.h"
#include "napi/native_node_api.h"
#include "common/qos_utils.h"

namespace OHOS {
namespace CameraStandard {
namespace {
void AsyncCompleteCallback(napi_env env, napi_status status, void* data)
{
    auto context = static_cast<CameraSessionAsyncContext*>(data);
    CHECK_RETURN_ELOG(context == nullptr, "CameraSessionNapi AsyncCompleteCallback context is null");
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
    CHECK_EXECUTE(context->work != nullptr,
        CameraNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef, context->work, *jsContext));
    context->FreeHeldNapiValue(env);
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

const std::vector<napi_property_descriptor> CameraSessionNapi::camera_process_sys_props = {
    DECLARE_NAPI_FUNCTION("setUsage", CameraSessionNapi::SetUsage)
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
    DECLARE_NAPI_FUNCTION("setFlashMode", CameraSessionNapi::SetFlashMode)
};


const std::vector<napi_property_descriptor> CameraSessionNapi::flash_sys_props = {
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

const std::vector<napi_property_descriptor> CameraSessionNapi::focus_sys_props = {
    DECLARE_NAPI_FUNCTION("isFocusRangeTypeSupported", CameraSessionNapi::IsFocusRangeTypeSupported),
    DECLARE_NAPI_FUNCTION("getFocusRange", CameraSessionNapi::GetFocusRange),
    DECLARE_NAPI_FUNCTION("setFocusRange", CameraSessionNapi::SetFocusRange),
    DECLARE_NAPI_FUNCTION("isFocusDrivenTypeSupported", CameraSessionNapi::IsFocusDrivenTypeSupported),
    DECLARE_NAPI_FUNCTION("getFocusDriven", CameraSessionNapi::GetFocusDriven),
    DECLARE_NAPI_FUNCTION("setFocusDriven", CameraSessionNapi::SetFocusDriven)
};

const std::vector<napi_property_descriptor> CameraSessionNapi::quality_prioritization_props = {
    DECLARE_NAPI_FUNCTION("setQualityPrioritization", CameraSessionNapi::SetQualityPrioritization),
};

const std::vector<napi_property_descriptor> CameraSessionNapi::zoom_props = {
    DECLARE_NAPI_FUNCTION("getZoomRatioRange", CameraSessionNapi::GetZoomRatioRange),
    DECLARE_NAPI_FUNCTION("getZoomRatio", CameraSessionNapi::GetZoomRatio),
    DECLARE_NAPI_FUNCTION("setZoomRatio", CameraSessionNapi::SetZoomRatio),
    DECLARE_NAPI_FUNCTION("setSmoothZoom", CameraSessionNapi::SetSmoothZoom),
    DECLARE_NAPI_FUNCTION("isZoomCenterPointSupported", CameraSessionNapi::IsZoomCenterPointSupported),
    DECLARE_NAPI_FUNCTION("getZoomCenterPoint", CameraSessionNapi::GetZoomCenterPoint),
    DECLARE_NAPI_FUNCTION("setZoomCenterPoint", CameraSessionNapi::SetZoomCenterPoint)
};

const std::vector<napi_property_descriptor> CameraSessionNapi::zoom_sys_props = {
    DECLARE_NAPI_FUNCTION("prepareZoom", CameraSessionNapi::PrepareZoom),
    DECLARE_NAPI_FUNCTION("unprepareZoom", CameraSessionNapi::UnPrepareZoom),
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
const std::vector<napi_property_descriptor> CameraSessionNapi::macro_props = {
    DECLARE_NAPI_FUNCTION("isMacroSupported", CameraSessionNapi::IsMacroSupported),
    DECLARE_NAPI_FUNCTION("enableMacro", CameraSessionNapi::EnableMacro)
};

const std::vector<napi_property_descriptor> CameraSessionNapi::moon_capture_boost_props = {
    DECLARE_NAPI_FUNCTION("isMoonCaptureBoostSupported", CameraSessionNapi::IsMoonCaptureBoostSupported),
    DECLARE_NAPI_FUNCTION("enableMoonCaptureBoost", CameraSessionNapi::EnableMoonCaptureBoost)
};

const std::vector<napi_property_descriptor> CameraSessionNapi::color_management_props = {
    DECLARE_NAPI_FUNCTION("getSupportedColorSpaces", CameraSessionNapi::GetSupportedColorSpaces),
    DECLARE_NAPI_FUNCTION("getActiveColorSpace", CameraSessionNapi::GetActiveColorSpace),
    DECLARE_NAPI_FUNCTION("setColorSpace", CameraSessionNapi::SetColorSpace)
};

const std::vector<napi_property_descriptor> CameraSessionNapi::control_center_props = {
    DECLARE_NAPI_FUNCTION("isControlCenterSupported", CameraSessionNapi::IsControlCenterSupported),
    DECLARE_NAPI_FUNCTION("getSupportedEffectTypes", CameraSessionNapi::GetSupportedEffectTypes),
    DECLARE_NAPI_FUNCTION("enableControlCenter", CameraSessionNapi::EnableControlCenter)
};

const std::vector<napi_property_descriptor> CameraSessionNapi::preconfig_props = {
    DECLARE_NAPI_FUNCTION("canPreconfig", CameraSessionNapi::CanPreconfig),
    DECLARE_NAPI_FUNCTION("preconfig", CameraSessionNapi::Preconfig)
};

const std::vector<napi_property_descriptor> CameraSessionNapi::camera_output_capability_sys_props = {
    DECLARE_NAPI_FUNCTION("getCameraOutputCapabilities", CameraSessionNapi::GetCameraOutputCapabilities)
};

const std::vector<napi_property_descriptor> CameraSessionNapi::camera_ability_sys_props = {
    DECLARE_NAPI_FUNCTION("getSessionFunctions", CameraSessionNapi::GetSessionFunctions),
    DECLARE_NAPI_FUNCTION("getSessionConflictFunctions", CameraSessionNapi::GetSessionConflictFunctions)
};

const std::vector<napi_property_descriptor> CameraSessionNapi::white_balance_props = {
    DECLARE_NAPI_FUNCTION("getSupportedWhiteBalanceModes", CameraSessionNapi::GetSupportedWhiteBalanceModes),
    DECLARE_NAPI_FUNCTION("isManualWhiteBalanceSupported", CameraSessionNapi::IsManualWhiteBalanceSupported),
    DECLARE_NAPI_FUNCTION("isWhiteBalanceModeSupported", CameraSessionNapi::IsWhiteBalanceModeSupported),
    DECLARE_NAPI_FUNCTION("getWhiteBalanceRange", CameraSessionNapi::GetWhiteBalanceRange),
    DECLARE_NAPI_FUNCTION("getWhiteBalanceMode", CameraSessionNapi::GetWhiteBalanceMode),
    DECLARE_NAPI_FUNCTION("setWhiteBalanceMode", CameraSessionNapi::SetWhiteBalanceMode),
    DECLARE_NAPI_FUNCTION("getWhiteBalance", CameraSessionNapi::GetWhiteBalance),
    DECLARE_NAPI_FUNCTION("setWhiteBalance", CameraSessionNapi::SetWhiteBalance),
};

const std::vector<napi_property_descriptor> CameraSessionNapi::auto_switch_props = {
    DECLARE_NAPI_FUNCTION("isAutoDeviceSwitchSupported", CameraSessionNapi::IsAutoDeviceSwitchSupported),
    DECLARE_NAPI_FUNCTION("enableAutoDeviceSwitch", CameraSessionNapi::EnableAutoDeviceSwitch)
};

void ExposureCallbackListener::OnExposureStateCallbackAsync(ExposureState state) const
{
    MEDIA_DEBUG_LOG("OnExposureStateCallbackAsync is called");
    std::unique_ptr<ExposureCallbackInfo> callbackInfo =
        std::make_unique<ExposureCallbackInfo>(state, shared_from_this());
    ExposureCallbackInfo *event = callbackInfo.get();
    auto task = [event]() {
        ExposureCallbackInfo* callbackInfo = reinterpret_cast<ExposureCallbackInfo *>(event);
        if (callbackInfo) {
            auto listener = callbackInfo->listener_.lock();
            CHECK_EXECUTE(listener != nullptr, listener->OnExposureStateCallback(callbackInfo->state_));
            delete callbackInfo;
        }
    };
    if (napi_ok != napi_send_event(env_, task, napi_eprio_immediate)) {
        MEDIA_ERR_LOG("failed to execute work");
    } else {
        callbackInfo.release();
    }
}

void ExposureCallbackListener::OnExposureStateCallback(ExposureState state) const
{
    MEDIA_DEBUG_LOG("OnExposureStateCallback is called");

    ExecuteCallbackScopeSafe("exposureStateChange", [&]() {
        napi_value callbackObj;
        napi_value errCode;

        napi_create_int32(env_, state, &callbackObj);
        errCode = CameraNapiUtils::GetUndefinedValue(env_);
        return ExecuteCallbackData(env_, errCode, callbackObj);
    });
}

void ExposureCallbackListener::OnExposureState(const ExposureState state)
{
    MEDIA_DEBUG_LOG("OnExposureState is called, state: %{public}d", state);
    OnExposureStateCallbackAsync(state);
}

void FocusCallbackListener::OnFocusStateCallbackAsync(FocusState state) const
{
    MEDIA_DEBUG_LOG("OnFocusStateCallbackAsync is called");
    std::unique_ptr<FocusCallbackInfo> callbackInfo = std::make_unique<FocusCallbackInfo>(state, shared_from_this());
    FocusCallbackInfo *event = callbackInfo.get();
    auto task = [event]() {
        FocusCallbackInfo* callbackInfo = reinterpret_cast<FocusCallbackInfo *>(event);
        if (callbackInfo) {
            auto listener = callbackInfo->listener_.lock();
            CHECK_EXECUTE(listener != nullptr, listener->OnFocusStateCallback(callbackInfo->state_));
            delete callbackInfo;
        }
    };
    if (napi_ok != napi_send_event(env_, task, napi_eprio_immediate)) {
        MEDIA_ERR_LOG("failed to execute work");
    } else {
        callbackInfo.release();
    }
}

void FocusCallbackListener::OnFocusStateCallback(FocusState state) const
{
    MEDIA_DEBUG_LOG("OnFocusStateCallback is called");

    ExecuteCallbackScopeSafe("focusStateChange", [&]() {
        napi_value callbackObj;
        napi_value errCode;

        napi_create_int32(env_, state, &callbackObj);
        errCode = CameraNapiUtils::GetUndefinedValue(env_);
        return ExecuteCallbackData(env_, errCode, callbackObj);
    });
}

void FocusCallbackListener::OnFocusState(FocusState state)
{
    MEDIA_DEBUG_LOG("OnFocusState is called, state: %{public}d", state);
    OnFocusStateCallbackAsync(state);
}

void MoonCaptureBoostCallbackListener::OnMoonCaptureBoostStatusCallbackAsync(MoonCaptureBoostStatus status) const
{
    MEDIA_DEBUG_LOG("OnMoonCaptureBoostStatusCallbackAsync is called");
    auto callbackInfo = std::make_unique<MoonCaptureBoostStatusCallbackInfo>(status, shared_from_this());
    MoonCaptureBoostStatusCallbackInfo *event = callbackInfo.get();
    auto task = [event]() {
        auto callbackInfo = reinterpret_cast<MoonCaptureBoostStatusCallbackInfo*>(event);
        if (callbackInfo) {
            auto listener = callbackInfo->listener_.lock();
            CHECK_EXECUTE(listener != nullptr, listener->OnMoonCaptureBoostStatusCallback(callbackInfo->status_));
            delete callbackInfo;
        }
    };
    if (napi_ok != napi_send_event(env_, task, napi_eprio_immediate)) {
        MEDIA_ERR_LOG("failed to execute work");
    } else {
        callbackInfo.release();
    }
}

void MoonCaptureBoostCallbackListener::OnMoonCaptureBoostStatusCallback(MoonCaptureBoostStatus status) const
{
    MEDIA_DEBUG_LOG("OnMoonCaptureBoostStatusCallback is called");
    
    ExecuteCallbackScopeSafe("moonCaptureBoostStatus", [&]() {
        napi_value callbackObj;
        napi_value errCode;

        napi_get_boolean(env_, status == MoonCaptureBoostStatus::ACTIVE, &callbackObj);
        errCode = CameraNapiUtils::GetUndefinedValue(env_);
        return ExecuteCallbackData(env_, errCode, callbackObj);
    });
}

void MoonCaptureBoostCallbackListener::OnMoonCaptureBoostStatusChanged(MoonCaptureBoostStatus status)
{
    MEDIA_DEBUG_LOG("OnMoonCaptureBoostStatusChanged is called, status: %{public}d", status);
    OnMoonCaptureBoostStatusCallbackAsync(status);
}

void SessionCallbackListener::OnErrorCallbackAsync(int32_t errorCode) const
{
    MEDIA_DEBUG_LOG("OnErrorCallbackAsync is called");
    std::unique_ptr<SessionCallbackInfo> callbackInfo =
        std::make_unique<SessionCallbackInfo>(errorCode, shared_from_this());
    SessionCallbackInfo *event = callbackInfo.get();
    auto task = [event]() {
        SessionCallbackInfo* callbackInfo = reinterpret_cast<SessionCallbackInfo *>(event);
        if (callbackInfo) {
            auto listener = callbackInfo->listener_.lock();
            CHECK_EXECUTE(listener != nullptr, listener->OnErrorCallback(callbackInfo->errorCode_));
            delete callbackInfo;
        }
    };
    if (napi_ok != napi_send_event(env_, task, napi_eprio_immediate)) {
        MEDIA_ERR_LOG("failed to execute work");
    } else {
        callbackInfo.release();
    }
}

void SessionCallbackListener::OnErrorCallback(int32_t errorCode) const
{
    MEDIA_DEBUG_LOG("OnErrorCallback is called");

    ExecuteCallbackScopeSafe("error", [&]() {
        napi_value callbackObj;
        napi_value propValue;
        napi_value errCode;

        napi_create_object(env_, &callbackObj);
        napi_create_int32(env_, errorCode, &propValue);
        napi_set_named_property(env_, callbackObj, "code", propValue);
        errCode = CameraNapiUtils::GetUndefinedValue(env_);
        return ExecuteCallbackData(env_, errCode, callbackObj);
    });
}

void SessionCallbackListener::OnError(int32_t errorCode)
{
    MEDIA_DEBUG_LOG("OnError is called, errorCode: %{public}d", errorCode);
    OnErrorCallbackAsync(errorCode);
}

void PressureCallbackListener::OnPressureCallbackAsync(PressureStatus status) const
{
    MEDIA_INFO_LOG("OnPressureCallbackAsync is called");
    std::unique_ptr<PressureCallbackInfo> callbackInfo =
        std::make_unique<PressureCallbackInfo>(status, shared_from_this());
    PressureCallbackInfo *event = callbackInfo.get();
    auto task = [event]() {
        PressureCallbackInfo* callbackInfo = reinterpret_cast<PressureCallbackInfo *>(event);
        if (callbackInfo) {
            auto listener = callbackInfo->listener_.lock();
            if (listener != nullptr) {
                listener->OnPressureCallback(callbackInfo->status_);
            }
            delete callbackInfo;
        }
    };
    if (napi_ok != napi_send_event(env_, task, napi_eprio_immediate)) {
        MEDIA_ERR_LOG("failed to execute work");
    } else {
        callbackInfo.release();
    }
}

void PressureCallbackListener::OnPressureCallback(PressureStatus status) const
{
    MEDIA_INFO_LOG("OnPressureCallback is called   %{public}d ", status);

    ExecuteCallbackScopeSafe("systemPressureLevelChange", [&]() {
        napi_value callbackObj;
        napi_value errCode;

        napi_create_int32(env_, static_cast<int32_t>(status), &callbackObj);
        errCode = CameraNapiUtils::GetUndefinedValue(env_);
        return ExecuteCallbackData(env_, errCode, callbackObj);
    });
}

void PressureCallbackListener::OnPressureStatusChanged(PressureStatus status)
{
    MEDIA_INFO_LOG("OnPressureStatusChanged is called, status: %{public}d", status);
    OnPressureCallbackAsync(status);
}

void ControlCenterEffectStatusCallbackListener::OnControlCenterEffectStatusCallbackAsync(
    ControlCenterStatusInfo controlCenterStatusInfo) const
{
    MEDIA_INFO_LOG("OnControlCenterEffectStatusCallbackAsync is called");
    std::unique_ptr<ControlCenterEffectCallbackInfo> callbackInfo =
        std::make_unique<ControlCenterEffectCallbackInfo>(controlCenterStatusInfo, shared_from_this());
    ControlCenterEffectCallbackInfo *event = callbackInfo.get();
    auto task = [event]() {
        ControlCenterEffectCallbackInfo* callbackInfo = reinterpret_cast<ControlCenterEffectCallbackInfo *>(event);
        if (callbackInfo) {
            auto listener = callbackInfo->listener_.lock();
            if (listener != nullptr) {
                listener->OnControlCenterEffectStatusCallback(callbackInfo->statusInfo_);
            }
            delete callbackInfo;
        }
    };
    if (napi_ok != napi_send_event(env_, task, napi_eprio_immediate)) {
        MEDIA_ERR_LOG("failed to execute work");
    } else {
        callbackInfo.release();
    }
}

void ControlCenterEffectStatusCallbackListener::OnControlCenterEffectStatusCallback(
    ControlCenterStatusInfo controlCenterStatusInfo) const
{
    MEDIA_INFO_LOG("OnControlCenterEffectStatusCallback is called");
    ExecuteCallbackScopeSafe("controlCenterEffectStatusChange", [&]() {
        napi_value errCode = CameraNapiUtils::GetUndefinedValue(env_);
        napi_value callbackObj;
        ControlCenterStatusInfo info = controlCenterStatusInfo;
        CameraNapiObject controlCenterStatusObj {{
            { "effectType", reinterpret_cast<int32_t*>(&info.effectType)},
            { "isActive", &info.isActive }
        }};
        callbackObj = controlCenterStatusObj.CreateNapiObjFromMap(env_);
        return ExecuteCallbackData(env_, errCode, callbackObj);
    });
}

void ControlCenterEffectStatusCallbackListener::OnControlCenterEffectStatusChanged(
    ControlCenterStatusInfo controlCenterStatusInfo)
{
    MEDIA_INFO_LOG("ControlCenterEffectStatusCallbackListener::OnControlCenterEffectStatusChanged");
    OnControlCenterEffectStatusCallbackAsync(controlCenterStatusInfo);
}

void SmoothZoomCallbackListener::OnSmoothZoomCallbackAsync(int32_t duration) const
{
    MEDIA_DEBUG_LOG("OnSmoothZoomCallbackAsync is called");
    std::unique_ptr<SmoothZoomCallbackInfo> callbackInfo =
        std::make_unique<SmoothZoomCallbackInfo>(duration, shared_from_this());
    SmoothZoomCallbackInfo *event = callbackInfo.get();
    auto task = [event]() {
        SmoothZoomCallbackInfo* callbackInfo = reinterpret_cast<SmoothZoomCallbackInfo *>(event);
        if (callbackInfo) {
            auto listener = callbackInfo->listener_.lock();
            CHECK_EXECUTE(listener != nullptr, listener->OnSmoothZoomCallback(callbackInfo->duration_));
            delete callbackInfo;
        }
    };
    if (napi_ok != napi_send_event(env_, task, napi_eprio_immediate)) {
        MEDIA_ERR_LOG("failed to execute work");
    } else {
        callbackInfo.release();
    }
}

void SmoothZoomCallbackListener::OnSmoothZoomCallback(int32_t duration) const
{
    MEDIA_DEBUG_LOG("OnSmoothZoomCallback is called");

    ExecuteCallbackScopeSafe("smoothZoomInfoAvailable", [&]() {
        napi_value callbackObj;
        napi_value propValue;
        napi_value errCode;

        napi_create_object(env_, &callbackObj);
        napi_create_int32(env_, duration, &propValue);
        napi_set_named_property(env_, callbackObj, "duration", propValue);
        errCode = CameraNapiUtils::GetUndefinedValue(env_);
        return ExecuteCallbackData(env_, errCode, callbackObj);
    });
}

void SmoothZoomCallbackListener::OnSmoothZoom(int32_t duration)
{
    MEDIA_DEBUG_LOG("OnSmoothZoom is called, duration: %{public}d", duration);
    OnSmoothZoomCallbackAsync(duration);
}

void AbilityCallbackListener::OnAbilityChangeCallbackAsync() const
{
    MEDIA_DEBUG_LOG("OnAbilityChangeCallbackAsync is called");
    std::unique_ptr<AbilityCallbackInfo> callbackInfo = std::make_unique<AbilityCallbackInfo>(shared_from_this());
    AbilityCallbackInfo *event = callbackInfo.get();
    auto task = [event]() {
        AbilityCallbackInfo* callbackInfo = reinterpret_cast<AbilityCallbackInfo *>(event);
        if (callbackInfo) {
            auto listener = callbackInfo->listener_.lock();
            CHECK_EXECUTE(listener != nullptr, listener->OnAbilityChangeCallback());
            delete callbackInfo;
        }
    };
    if (napi_ok != napi_send_event(env_, task, napi_eprio_immediate)) {
        MEDIA_ERR_LOG("failed to execute work");
    } else {
        callbackInfo.release();
    }
}

void AbilityCallbackListener::OnAbilityChangeCallback() const
{
    MEDIA_DEBUG_LOG("OnAbilityChangeCallback is called");

    ExecuteCallbackScopeSafe("abilityChange", [&]() {
        napi_value callbackObj;
        napi_value errCode;

        napi_get_undefined(env_, &callbackObj);
        errCode = CameraNapiUtils::GetUndefinedValue(env_);
        return ExecuteCallbackData(env_, errCode, callbackObj);
    });
}

void AbilityCallbackListener::OnAbilityChange()
{
    MEDIA_DEBUG_LOG("OnAbilityChange is called");
    OnAbilityChangeCallbackAsync();
}

void AutoDeviceSwitchCallbackListener::OnAutoDeviceSwitchCallbackAsync(
    bool isDeviceSwitched, bool isDeviceCapabilityChanged) const
{
    MEDIA_DEBUG_LOG("OnAutoDeviceSwitchCallbackAsync is called");
    auto callbackInfo = std::make_unique<AutoDeviceSwitchCallbackListenerInfo>(
        isDeviceSwitched, isDeviceCapabilityChanged, shared_from_this());
    AutoDeviceSwitchCallbackListenerInfo *event = callbackInfo.get();
    auto task = [event]() {
        auto callbackInfo = reinterpret_cast<AutoDeviceSwitchCallbackListenerInfo*>(event);
        if (callbackInfo) {
            auto listener = callbackInfo->listener_.lock();
            CHECK_EXECUTE(listener != nullptr, listener->OnAutoDeviceSwitchCallback(callbackInfo->isDeviceSwitched_,
                callbackInfo->isDeviceCapabilityChanged_));
            delete callbackInfo;
        }
    };
    if (napi_ok != napi_send_event(env_, task, napi_eprio_immediate)) {
        MEDIA_ERR_LOG("failed to execute work");
    } else {
        callbackInfo.release();
    }
}

void AutoDeviceSwitchCallbackListener::OnAutoDeviceSwitchCallback(
    bool isDeviceSwitched, bool isDeviceCapabilityChanged) const
{
    MEDIA_INFO_LOG("OnAutoDeviceSwitchCallback is called");

    ExecuteCallbackScopeSafe("autoDevceSwitchStatusChange", [&]() {
        napi_value callbackObj;
        napi_value propValue;
        napi_value errCode;

        napi_create_object(env_, &callbackObj);
        napi_get_boolean(env_, isDeviceSwitched, &propValue);
        napi_set_named_property(env_, callbackObj, "isDeviceSwitched", propValue);
        napi_get_boolean(env_, isDeviceCapabilityChanged, &propValue);
        napi_set_named_property(env_, callbackObj, "isDeviceCapabilityChanged", propValue);
        errCode = CameraNapiUtils::GetUndefinedValue(env_);
        return ExecuteCallbackData(env_, errCode, callbackObj);
    });
}

void AutoDeviceSwitchCallbackListener::OnAutoDeviceSwitchStatusChange(
    bool isDeviceSwitched, bool isDeviceCapabilityChanged) const
{
    MEDIA_INFO_LOG("isDeviceSwitched: %{public}d, isDeviceCapabilityChanged: %{public}d",
        isDeviceSwitched, isDeviceCapabilityChanged);
    OnAutoDeviceSwitchCallbackAsync(isDeviceSwitched, isDeviceCapabilityChanged);
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

void CameraSessionNapi::Init(napi_env env)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    std::vector<std::vector<napi_property_descriptor>> descriptors = { camera_process_props, camera_process_sys_props,
        stabilization_props, flash_props, flash_sys_props, auto_exposure_props, focus_props, focus_sys_props,
        zoom_props, zoom_sys_props, filter_props, macro_props,  moon_capture_boost_props, color_management_props,
        preconfig_props, camera_output_capability_sys_props, beauty_props };
    std::vector<napi_property_descriptor> camera_session_props = CameraNapiUtils::GetPropertyDescriptor(descriptors);
    status = napi_define_class(env, CAMERA_SESSION_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               CameraSessionNapiConstructor, nullptr,
                               camera_session_props.size(),
                               camera_session_props.data(), &ctorObj);
    CHECK_RETURN_ELOG(status != napi_ok, "CameraSessionNapi defined class failed");
    status = NapiRefManager::CreateMemSafetyRef(env, ctorObj, &sConstructor_);
    CHECK_RETURN_ELOG(status != napi_ok, "CameraSessionNapi Init failed");
    MEDIA_DEBUG_LOG("CameraSessionNapi Init success");
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
            CHECK_RETURN_RET_ELOG(sCameraSession_ == nullptr, result, "sCameraSession_ is null");
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
    COMM_INFO_LOG("CreateCameraSession is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;

    if (sConstructor_ == nullptr) {
        CameraSessionNapi::Init(env);
        CHECK_RETURN_RET_ELOG(sConstructor_ == nullptr, result, "sConstructor_ is null");
    }
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        int retCode = CameraManager::GetInstance()->CreateCaptureSession(sCameraSession_, SceneMode::NORMAL);
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
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
    COMM_INFO_LOG("BeginConfig is called");
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
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, ret), nullptr);
    } else {
        MEDIA_ERR_LOG("BeginConfig call Failed!");
    }
    return result;
}

void CameraSessionNapi::CommitConfigAsync(uv_work_t* work)
{
    CHECK_RETURN_ELOG(work == nullptr, "CommitConfigAsync null work");
    COMM_INFO_LOG("CommitConfigAsync running on worker");
    auto context = static_cast<CameraSessionAsyncContext*>(work->data);
    CHECK_RETURN_ELOG(context == nullptr, "CommitConfigAsync context is null");
    CHECK_RETURN_ELOG(
        context->objectInfo == nullptr, "CommitConfigAsync async info is nullptr");
    CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
    CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(context->queueTask, [&context]() {
        context->errorCode = context->objectInfo->cameraSession_->CommitConfig();
        context->status = context->errorCode == CameraErrorCode::SUCCESS;
        MEDIA_INFO_LOG("CommitConfigAsync errorCode:%{public}d", context->errorCode);
    });
}

void CameraSessionNapi::UvWorkAsyncCompleted(uv_work_t* work, int status)
{
    CHECK_RETURN_ELOG(work == nullptr, "UvWorkAsyncCompleted null work");
    auto context = static_cast<CameraSessionAsyncContext*>(work->data);
    CHECK_RETURN_ELOG(context == nullptr, "UvWorkAsyncCompleted context is null");
    MEDIA_INFO_LOG("UvWorkAsyncCompleted %{public}s, status = %{public}d", context->funcName.c_str(),
        context->status);
    std::unique_ptr<JSAsyncContextOutput> jsContext = std::make_unique<JSAsyncContextOutput>();
    jsContext->status = context->status;
    if (!context->status) {
        CameraNapiUtils::CreateNapiErrorObject(context->env, context->errorCode, context->errorMsg.c_str(), jsContext);
    } else {
        napi_get_undefined(context->env, &jsContext->data);
    }
    if (!context->funcName.empty() && context->taskId > 0) {
        // Finish async trace
        CAMERA_FINISH_ASYNC_TRACE(context->funcName, context->taskId);
        jsContext->funcName = context->funcName.c_str();
    }
    CHECK_EXECUTE(work != nullptr,
        CameraNapiUtils::InvokeJSAsyncMethodWithUvWork(context->env, context->deferred,
            context->callbackRef, *jsContext));
    context->FreeHeldNapiValue(context->env);
    delete context;
    context= nullptr;
    delete work;
    work = nullptr;
}

napi_value CameraSessionNapi::CommitConfig(napi_env env, napi_callback_info info)
{
    COMM_INFO_LOG("CommitConfig is called");
    std::unique_ptr<CameraSessionAsyncContext> asyncContext = std::make_unique<CameraSessionAsyncContext>(
        "CameraSessionNapi::CommitConfig", CameraNapiUtils::IncrementAndGet(cameraSessionTaskId));
    auto asyncFunction = std::make_shared<CameraNapiAsyncFunction>(
        env, "CommitConfig", asyncContext->callbackRef, asyncContext->deferred);
    CameraNapiParamParser jsParamParser(env, info, asyncContext->objectInfo, asyncFunction);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument"), nullptr,
        "CameraSessionNapi::CommitConfig invalid argument");
    asyncContext->HoldNapiValue(env, jsParamParser.GetThisVar());
    asyncContext->env = env;
    uv_qos_t uvQos = QosUtils::GetUvWorkQos();
    MEDIA_DEBUG_LOG("CameraSessionNapi::CommitConfig Qos level: %{public}d", uvQos);
    uv_loop_s *loop = CameraInputNapi::GetEventLoop(env);
    if (!loop) {
        return nullptr;
    }
    uv_work_t *work = new(std::nothrow) uv_work_t;
    if (work == nullptr) {
        return nullptr;
    }
    work->data = static_cast<void*>(asyncContext.get());
    asyncContext->queueTask =
        CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("CameraSessionNapi::CommitConfig");
    int rev = uv_queue_work_with_qos(
        loop, work, CameraSessionNapi::CommitConfigAsync,
        CameraSessionNapi::UvWorkAsyncCompleted, uvQos);
    if (rev != 0) {
        MEDIA_ERR_LOG("Failed to call uv_queue_work_with_qos for CameraSessionNapi::CommitConfig");
        asyncFunction->Reset();
        if (work != nullptr) {
            delete work;
            work = nullptr;
        }
        CameraNapiWorkerQueueKeeper::GetInstance()->RemoveWorkerTask(asyncContext->queueTask);
    } else {
        asyncContext.release();
    }
    CHECK_RETURN_RET(asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE,
        asyncFunction->GetPromise());
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
    COMM_INFO_LOG("AddInput is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    CHECK_RETURN_RET(!CameraNapiUtils::CheckInvalidArgument(env, argc, ARGS_ONE, argv, ADD_INPUT), result);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    sptr<CaptureInput> cameraInput = nullptr;
    GetJSArgsForCameraInput(env, argc, argv, cameraInput);
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        int32_t ret = cameraSessionNapi->cameraSession_->AddInput(cameraInput);
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, ret), nullptr);
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
    CHECK_RETURN_RET(!CameraNapiUtils::CheckInvalidArgument(env, argc, ARGS_ONE, argv, REMOVE_INPUT), result);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        sptr<CaptureInput> cameraInput = nullptr;
        GetJSArgsForCameraInput(env, argc, argv, cameraInput);
        int32_t ret = cameraSessionNapi->cameraSession_->RemoveInput(cameraInput);
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, ret), nullptr);
        return result;
    } else {
        MEDIA_ERR_LOG("RemoveInput call Failed!");
    }
    return result;
}

void CheckExtensionCameraOutput(napi_env env, napi_value obj, sptr<CaptureOutput> &output)
{
    MEDIA_DEBUG_LOG("CheckExtensionCameraOutput is called");
    output = nullptr;
    auto cameraNapiExProxy = CameraNapiExManager::GetCameraNapiExProxy();
    CHECK_RETURN_ELOG(cameraNapiExProxy == nullptr, "cameraNapiExProxy is nullptr");
    if (cameraNapiExProxy->CheckAndGetOutput(env, obj, output)) {
        MEDIA_DEBUG_LOG("system output adding..");
    } else {
        MEDIA_ERR_LOG("invalid output ..");
    }
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

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        cameraOutput = nullptr;
        if (i == PARAM0 && valueType == napi_object) {
            if (PreviewOutputNapi::IsPreviewOutput(env, argv[i])) {
                MEDIA_DEBUG_LOG("preview output adding..");
                napi_unwrap(env, argv[i], reinterpret_cast<void**>(&previewOutputNapiObj));
                NAPI_ASSERT(env, previewOutputNapiObj != nullptr, "type mismatch");
                cameraOutput = previewOutputNapiObj->GetPreviewOutput();
            } else if (PhotoOutputNapi::IsPhotoOutput(env, argv[i])) {
                MEDIA_DEBUG_LOG("photo output adding..");
                napi_unwrap(env, argv[i], reinterpret_cast<void**>(&photoOutputNapiObj));
                NAPI_ASSERT(env, photoOutputNapiObj != nullptr, "type mismatch");
                cameraOutput = photoOutputNapiObj->GetPhotoOutput();
            } else if (VideoOutputNapi::IsVideoOutput(env, argv[i])) {
                MEDIA_DEBUG_LOG("video output adding..");
                napi_unwrap(env, argv[i], reinterpret_cast<void**>(&videoOutputNapiObj));
                NAPI_ASSERT(env, videoOutputNapiObj != nullptr, "type mismatch");
                cameraOutput = videoOutputNapiObj->GetVideoOutput();
            } else if (MetadataOutputNapi::IsMetadataOutput(env, argv[i])) {
                MEDIA_DEBUG_LOG("metadata output adding..");
                napi_unwrap(env, argv[i], reinterpret_cast<void**>(&metadataOutputNapiObj));
                NAPI_ASSERT(env, metadataOutputNapiObj != nullptr, "type mismatch");
                cameraOutput = metadataOutputNapiObj->GetMetadataOutput();
            }
            if (CameraNapiSecurity::CheckSystemApp(env, false) && cameraOutput == nullptr) {
                CheckExtensionCameraOutput(env, argv[i], cameraOutput);
            }
            CHECK_EXECUTE(cameraOutput == nullptr, NAPI_ASSERT(env, false, "type mismatch"));
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
    COMM_INFO_LOG("AddOutput is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    CHECK_RETURN_RET(!CameraNapiUtils::CheckInvalidArgument(env, argc, ARGS_ONE, argv, ADD_OUTPUT), result);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        sptr<CaptureOutput> cameraOutput = nullptr;
        result = GetJSArgsForCameraOutput(env, argc, argv, cameraOutput);
        int32_t ret = cameraSessionNapi->cameraSession_->AddOutput(cameraOutput);
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, ret), nullptr);
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

    MEDIA_DEBUG_LOG("CameraSessionNapi::CanAddOutput get js args");
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
    CHECK_RETURN_RET(!CameraNapiUtils::CheckInvalidArgument(env, argc, ARGS_ONE, argv, REMOVE_OUTPUT), result);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        sptr<CaptureOutput> cameraOutput = nullptr;
        result = GetJSArgsForCameraOutput(env, argc, argv, cameraOutput);
        int32_t ret = cameraSessionNapi->cameraSession_->RemoveOutput(cameraOutput);
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, ret), nullptr);
    } else {
        MEDIA_ERR_LOG("RemoveOutput call Failed!");
    }
    return result;
}

void CameraSessionNapi::StartAsync(uv_work_t* work)
{
    CHECK_RETURN_ELOG(work == nullptr, "StartAsync null work");
    MEDIA_INFO_LOG("StartAsync running on worker");
    auto context = static_cast<CameraSessionAsyncContext*>(work->data);
    CHECK_RETURN_ELOG(context == nullptr, "StartAsync context is null");
    CHECK_RETURN_ELOG(context->objectInfo == nullptr, "StartAsync async info is nullptr");
    CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
    CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(context->queueTask, [&context]() {
        context->errorCode = context->objectInfo->cameraSession_->Start();
        context->status = context->errorCode == CameraErrorCode::SUCCESS;
        MEDIA_INFO_LOG("StartAsync errorCode:%{public}d", context->errorCode);
    });
}

napi_value CameraSessionNapi::Start(napi_env env, napi_callback_info info)
{
    COMM_INFO_LOG("Start is called");
    std::unique_ptr<CameraSessionAsyncContext> asyncContext = std::make_unique<CameraSessionAsyncContext>(
        "CameraSessionNapi::Start", CameraNapiUtils::IncrementAndGet(cameraSessionTaskId));
    auto asyncFunction =
        std::make_shared<CameraNapiAsyncFunction>(env, "Start", asyncContext->callbackRef, asyncContext->deferred);
    CameraNapiParamParser jsParamParser(env, info, asyncContext->objectInfo, asyncFunction);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument"),
        nullptr, "CameraSessionNapi::Start invalid argument");
    asyncContext->HoldNapiValue(env, jsParamParser.GetThisVar());
    asyncContext->env = env;
    uv_qos_t uvQos = QosUtils::GetUvWorkQos();
    MEDIA_DEBUG_LOG("CameraSessionNapi::Start Qos level: %{public}d", uvQos);
    uv_loop_s *loop = CameraInputNapi::GetEventLoop(env);
    if (!loop) {
        return nullptr;
    }
    uv_work_t *work = new(std::nothrow) uv_work_t;
    if (work == nullptr) {
        return nullptr;
    }
    work->data = static_cast<void*>(asyncContext.get());
    asyncContext->queueTask =
        CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("CameraSessionNapi::Start");
    int rev = uv_queue_work_with_qos(
        loop, work, CameraSessionNapi::StartAsync,
        CameraSessionNapi::UvWorkAsyncCompleted, uvQos);
    if (rev != 0) {
        MEDIA_ERR_LOG("Failed to call uv_queue_work_with_qos for CameraSessionNapi::Start");
        asyncFunction->Reset();
        if (work != nullptr) {
            delete work;
            work = nullptr;
        }
        CameraNapiWorkerQueueKeeper::GetInstance()->RemoveWorkerTask(asyncContext->queueTask);
    } else {
        asyncContext.release();
    }
    CHECK_RETURN_RET(asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE,
        asyncFunction->GetPromise());
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value CameraSessionNapi::Stop(napi_env env, napi_callback_info info)
{
    COMM_INFO_LOG("Stop is called");
    std::unique_ptr<CameraSessionAsyncContext> asyncContext = std::make_unique<CameraSessionAsyncContext>(
        "CameraSessionNapi::Stop", CameraNapiUtils::IncrementAndGet(cameraSessionTaskId));
    auto asyncFunction =
        std::make_shared<CameraNapiAsyncFunction>(env, "Stop", asyncContext->callbackRef, asyncContext->deferred);
    CameraNapiParamParser jsParamParser(env, info, asyncContext->objectInfo, asyncFunction);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument"), nullptr,
        "CameraSessionNapi::Stop invalid argument");
    asyncContext->HoldNapiValue(env, jsParamParser.GetThisVar());
    napi_status status = napi_create_async_work(
        env, nullptr, asyncFunction->GetResourceName(),
        [](napi_env env, void* data) {
            COMM_INFO_LOG("CameraSessionNapi::Stop running on worker");
            auto context = static_cast<CameraSessionAsyncContext*>(data);
            CHECK_RETURN_ELOG(context->objectInfo == nullptr, "CameraSessionNapi::Stop async info is nullptr");
            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(context->queueTask, [&context]() {
                context->errorCode = context->objectInfo->cameraSession_->Stop();
                context->status = context->errorCode == CameraErrorCode::SUCCESS;
                COMM_INFO_LOG("CameraSessionNapi::Stop errorCode:%{public}d", context->errorCode);
            });
        },
        AsyncCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for CameraSessionNapi::Stop");
        asyncFunction->Reset();
    } else {
        asyncContext->queueTask =
            CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("CameraSessionNapi::Stop");
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        asyncContext.release();
    }
    CHECK_RETURN_RET(asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE,
        asyncFunction->GetPromise());
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value CameraSessionNapi::Release(napi_env env, napi_callback_info info)
{
    COMM_INFO_LOG("Release is called");
    std::unique_ptr<CameraSessionAsyncContext> asyncContext = std::make_unique<CameraSessionAsyncContext>(
        "CameraSessionNapi::Release", CameraNapiUtils::IncrementAndGet(cameraSessionTaskId));
    auto asyncFunction =
        std::make_shared<CameraNapiAsyncFunction>(env, "Release", asyncContext->callbackRef, asyncContext->deferred);
    CameraNapiParamParser jsParamParser(env, info, asyncContext->objectInfo, asyncFunction);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument"), nullptr,
        "CameraSessionNapi::Release invalid argument");
    asyncContext->HoldNapiValue(env, jsParamParser.GetThisVar());
    napi_status status = napi_create_async_work(
        env, nullptr, asyncFunction->GetResourceName(),
        [](napi_env env, void* data) {
            COMM_INFO_LOG("CameraSessionNapi::Release running on worker");
            auto context = static_cast<CameraSessionAsyncContext*>(data);
            CHECK_RETURN_ELOG(context->objectInfo == nullptr, "CameraSessionNapi::Release async info is nullptr");
            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(context->queueTask, [&context]() {
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
        asyncContext->queueTask =
            CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("CameraSessionNapi::Release");
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        asyncContext.release();
    }
    CHECK_RETURN_RET(asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE,
        asyncFunction->GetPromise());
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
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
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
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
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
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
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
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
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
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
        napi_get_boolean(env, isSupported, &result);
    } else {
        MEDIA_ERR_LOG("IsFlashModeSupported call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::SetFlashMode(napi_env env, napi_callback_info info)
{
    COMM_INFO_LOG("SetFlashMode is called");
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
        MEDIA_INFO_LOG("CameraSessionNapi::SetFlashMode mode:%{public}d", value);
        FlashMode flashMode = (FlashMode)value;
        cameraSessionNapi->cameraSession_->LockForControl();
        int retCode = cameraSessionNapi->cameraSession_->SetFlashMode(flashMode);
        cameraSessionNapi->cameraSession_->UnlockForControl();
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
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
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
        napi_create_int32(env, flashMode, &result);
    } else {
        MEDIA_ERR_LOG("GetFlashMode call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::IsLcdFlashSupported(napi_env env, napi_callback_info info)
{
    MEDIA_ERR_LOG("SystemApi IsLcdFlashSupported is called!");
    CameraNapiUtils::ThrowError(env, CameraErrorCode::NO_SYSTEM_APP_PERMISSION,
        "System api can be invoked only by system applications");
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value CameraSessionNapi::EnableLcdFlash(napi_env env, napi_callback_info info)
{
    MEDIA_ERR_LOG("SystemApi EnableLcdFlash is called!");
    CameraNapiUtils::ThrowError(env, CameraErrorCode::NO_SYSTEM_APP_PERMISSION,
        "System api can be invoked only by system applications");
    return CameraNapiUtils::GetUndefinedValue(env);
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
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
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
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
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
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
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
            CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
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
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
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
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
        CHECK_RETURN_RET(vecExposureBiasList.empty() || napi_create_array(env, &result) != napi_ok, result);
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
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
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
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
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
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
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
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
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
            CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
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
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
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
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
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
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
    } else {
        MEDIA_ERR_LOG("SetFocusMode call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::IsFocusRangeTypeSupported(napi_env env, napi_callback_info info)
{
    MEDIA_ERR_LOG("SystemApi IsFocusRangeTypeSupported is called!");
    CameraNapiUtils::ThrowError(env, CameraErrorCode::NO_SYSTEM_APP_PERMISSION,
        "System api can be invoked only by system applications");
    return nullptr;
}

napi_value CameraSessionNapi::GetFocusRange(napi_env env, napi_callback_info info)
{
    MEDIA_ERR_LOG("SystemApi IsFocusRangeTypeSupported is called!");
    CameraNapiUtils::ThrowError(env, CameraErrorCode::NO_SYSTEM_APP_PERMISSION,
        "System api can be invoked only by system applications");
    return nullptr;
}

napi_value CameraSessionNapi::SetFocusRange(napi_env env, napi_callback_info info)
{
    MEDIA_ERR_LOG("SystemApi IsFocusRangeTypeSupported is called!");
    CameraNapiUtils::ThrowError(env, CameraErrorCode::NO_SYSTEM_APP_PERMISSION,
        "System api can be invoked only by system applications");
    return nullptr;
}

napi_value CameraSessionNapi::IsFocusDrivenTypeSupported(napi_env env, napi_callback_info info)
{
    MEDIA_ERR_LOG("SystemApi IsFocusRangeTypeSupported is called!");
    CameraNapiUtils::ThrowError(env, CameraErrorCode::NO_SYSTEM_APP_PERMISSION,
        "System api can be invoked only by system applications");
    return nullptr;
}

napi_value CameraSessionNapi::GetFocusDriven(napi_env env, napi_callback_info info)
{
    MEDIA_ERR_LOG("SystemApi GetFocusDriven is called!");
    CameraNapiUtils::ThrowError(env, CameraErrorCode::NO_SYSTEM_APP_PERMISSION,
        "System api can be invoked only by system applications");
    return nullptr;
}

napi_value CameraSessionNapi::SetFocusDriven(napi_env env, napi_callback_info info)
{
    MEDIA_ERR_LOG("SystemApi SetFocusDriven is called!");
    CameraNapiUtils::ThrowError(env, CameraErrorCode::NO_SYSTEM_APP_PERMISSION,
        "System api can be invoked only by system applications");
    return nullptr;
}

napi_value CameraSessionNapi::SetQualityPrioritization(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetQualityPrioritization is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = { 0 };
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        QualityPrioritization qualityPrioritization = (QualityPrioritization)value;
        cameraSessionNapi->cameraSession_->LockForControl();
        int retCode = cameraSessionNapi->cameraSession_->SetQualityPrioritization(
            static_cast<QualityPrioritization>(qualityPrioritization));
        cameraSessionNapi->cameraSession_->UnlockForControl();
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
    } else {
        MEDIA_ERR_LOG("SetQualityPrioritization call Failed!");
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
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
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
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
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
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
    } else {
        MEDIA_ERR_LOG("SetZoomRatio call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::PrepareZoom(napi_env env, napi_callback_info info)
{
    MEDIA_ERR_LOG("SystemApi PrepareZoom is called!");
    CameraNapiUtils::ThrowError(env, CameraErrorCode::NO_SYSTEM_APP_PERMISSION,
        "System api can be invoked only by system applications");
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value CameraSessionNapi::UnPrepareZoom(napi_env env, napi_callback_info info)
{
    MEDIA_ERR_LOG("SystemApi UnPrepareZoom is called!");
    CameraNapiUtils::ThrowError(env, CameraErrorCode::NO_SYSTEM_APP_PERMISSION,
        "System api can be invoked only by system applications");
    return CameraNapiUtils::GetUndefinedValue(env);
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
    CameraNapiUtils::ThrowError(env, CameraErrorCode::NO_SYSTEM_APP_PERMISSION,
        "SystemApi GetZoomPointInfos is called!");
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value CameraSessionNapi::IsZoomCenterPointSupported(napi_env env, napi_callback_info info)
{
    CHECK_RETURN_RET_ELOG(!CameraNapiSecurity::CheckSystemApp(env), nullptr,
        "SystemApi IsZoomCenterPointSupported is called!");
    MEDIA_DEBUG_LOG("CameraSessionNapi::IsZoomCenterPointSupported is called");
    CameraSessionNapi* cameraSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionNapi);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(PARAMETER_ERROR, "parse parameter occur error"), nullptr,
        "CameraSessionNapi::IsZoomCenterPointSupported parse parameter occur error");

    auto result = CameraNapiUtils::GetUndefinedValue(env);
    if (cameraSessionNapi->cameraSession_ != nullptr) {
        bool isSupported = false;
        int32_t retCode = cameraSessionNapi->cameraSession_->IsZoomCenterPointSupported(isSupported);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_get_boolean(env, isSupported, &result);
    } else {
        MEDIA_ERR_LOG("CameraSessionNapi::IsZoomCenterPointSupported get native object fail");
        CameraNapiUtils::ThrowError(env, PARAMETER_ERROR, "get native object fail");
        return nullptr;
    }
    return result;
}

napi_value CameraSessionNapi::GetZoomCenterPoint(napi_env env, napi_callback_info info)
{
    CHECK_RETURN_RET_ELOG(!CameraNapiSecurity::CheckSystemApp(env), nullptr,
        "SystemApi GetZoomCenterPoint is called!");
    MEDIA_DEBUG_LOG("CameraSessionNapi::GetZoomCenterPoint is called");
    CameraSessionNapi* cameraSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionNapi);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(PARAMETER_ERROR, "parse parameter occur error"), nullptr,
        "CameraSessionNapi::GetZoomCenterPoint parse parameter occur error");

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    if (cameraSessionNapi->cameraSession_ == nullptr) {
        MEDIA_ERR_LOG("CameraSessionNapi::GetZoomCenterPoint get native object fail");
        CameraNapiUtils::ThrowError(env, PARAMETER_ERROR, "get native object fail");
        return nullptr;
    } else {
        Point zoomCenterPoint;
        int32_t retCode = cameraSessionNapi->cameraSession_->GetZoomCenterPoint(zoomCenterPoint);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        return GetPointNapiValue(env, zoomCenterPoint);
    }
    return result;
}

napi_value CameraSessionNapi::SetZoomCenterPoint(napi_env env, napi_callback_info info)
{
    CHECK_RETURN_RET_ELOG(!CameraNapiSecurity::CheckSystemApp(env), nullptr,
        "SystemApi SetZoomCenterPoint is called!");
    MEDIA_DEBUG_LOG("CameraSessionNapi::SetZoomCenterPoint is called");
    Point zoomCenterPoint;
    CameraNapiObject pointArg = {{{ "x", &zoomCenterPoint.x }, { "y", &zoomCenterPoint.y }}};
    CameraSessionNapi* cameraSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionNapi, pointArg);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(PARAMETER_ERROR, "parse parameter occur error"), nullptr,
        "CameraSessionNapi::SetZoomCenterPoint parse parameter occur error");
    MEDIA_DEBUG_LOG("CameraSessionNapi::SetZoomCenterPoint is called x:%f, y:%f",
        zoomCenterPoint.x, zoomCenterPoint.y);
    if (cameraSessionNapi->cameraSession_ == nullptr) {
        MEDIA_ERR_LOG("CameraSessionNapi::SetZoomCenterPoint get native object fail");
        CameraNapiUtils::ThrowError(env, PARAMETER_ERROR, "get native object fail");
        return nullptr;
    } else {
        cameraSessionNapi->cameraSession_->LockForControl();
        int32_t retCode = cameraSessionNapi->cameraSession_->SetZoomCenterPoint(zoomCenterPoint);
        cameraSessionNapi->cameraSession_->UnlockForControl();
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
    }
    return CameraNapiUtils::GetUndefinedValue(env);
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
    CHECK_RETURN_RET_ELOG(status != napi_ok, result, "napi_create_array call Failed!");
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        std::vector<FilterType> filterTypes = cameraSessionNapi->cameraSession_->GetSupportedFilters();
        COMM_INFO_LOG("CameraSessionNapi::GetSupportedFilters len = %{public}zu",
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
    napi_value result = nullptr;
    napi_status status;
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

napi_value CameraSessionNapi::GetSupportedColorSpaces(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedColorSpaces is called.");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    MEDIA_DEBUG_LOG("CameraSessionNapi::GetSupportedColorSpaces get js args");
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    status = napi_create_array(env, &result);
    CHECK_RETURN_RET_ELOG(status != napi_ok, result, "napi_create_array call Failed!");
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

napi_value CameraSessionNapi::IsControlCenterSupported(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("CameraSessionNapi::IsControlCenterSupported is called.");
    CameraSessionNapi* cameraSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionNapi);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("CameraSessionNapi::IsControlCenterSupported parse parameter occur error");
        return nullptr;
    }
    auto result = CameraNapiUtils::GetUndefinedValue(env);
    if (cameraSessionNapi->cameraSession_ != nullptr) {
        bool isSupported = cameraSessionNapi->cameraSession_->IsControlCenterSupported();
        napi_get_boolean(env, isSupported, &result);
    } else {
        MEDIA_ERR_LOG("CameraSessionNapi::IsControlCenterSupported get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return nullptr;
    }
    return result;
}
 
napi_value CameraSessionNapi::GetSupportedEffectTypes(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("CameraSessionNapi::GetSupportedEffectTypes is called.");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;
 
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    napi_get_undefined(env, &result);
    status = napi_create_array(env, &result);
    CHECK_RETURN_RET_ELOG(status != napi_ok, result, "napi_create_array call Failed!");
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        std::vector<ControlCenterEffectType> effectTypes
            = cameraSessionNapi->cameraSession_->GetSupportedEffectTypes();
        if (!effectTypes.empty()) {
            for (size_t i = 0; i < effectTypes.size(); i++) {
                ControlCenterEffectType effectType = effectTypes[i];
                napi_value value;
                napi_create_int32(env, static_cast<int32_t>(effectType), &value);
                napi_set_element(env, result, i, value);
            }
        }
    } else {
        MEDIA_ERR_LOG("GetSupportedEffectTypes call Failed!");
    }
    return result;
}
 
napi_value CameraSessionNapi::EnableControlCenter(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("CameraSessionNapi::EnableControlCenter");
    napi_value result = CameraNapiUtils::GetUndefinedValue(env);
    bool isEnableControlCenter;
    CameraSessionNapi* cameraSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionNapi, isEnableControlCenter);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("CameraSessionNapi::EnableControlCenter parse parameter occur error");
        return result;
    }
    if (cameraSessionNapi->cameraSession_ != nullptr) {
        MEDIA_INFO_LOG("CameraSessionNapi::EnableMacro:%{public}d", isEnableControlCenter);
        cameraSessionNapi->cameraSession_->LockForControl();
        cameraSessionNapi->cameraSession_->EnableControlCenter(isEnableControlCenter);
        cameraSessionNapi->cameraSession_->UnlockForControl();
    } else {
        MEDIA_ERR_LOG("CameraSessionNapi::EnableControlCenter get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return result;
    }
    return result;
}

napi_value CameraSessionNapi::GetActiveColorSpace(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetActiveColorSpace is called");
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_status status;
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        ColorSpace colorSpace;
        int32_t retCode = cameraSessionNapi->cameraSession_->GetActiveColorSpace(colorSpace);
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), result);
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
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), result);
    } else {
        MEDIA_ERR_LOG("SetColorSpace call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::IsMacroSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("CameraSessionNapi::IsMacroSupported is called");
    CameraSessionNapi* cameraSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionNapi);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"), nullptr,
        "CameraSessionNapi::IsMacroSupported parse parameter occur error");
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
    MEDIA_DEBUG_LOG("CameraSessionNapi::EnableMacro is called");
    bool isEnableMacro;
    CameraSessionNapi* cameraSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionNapi, isEnableMacro);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"), nullptr,
        "CameraSessionNapi::EnableMacro parse parameter occur error");

    if (cameraSessionNapi->cameraSession_ != nullptr) {
        MEDIA_INFO_LOG("CameraSessionNapi::EnableMacro:%{public}d", isEnableMacro);
        cameraSessionNapi->cameraSession_->LockForControl();
        int32_t retCode = cameraSessionNapi->cameraSession_->EnableMacro(isEnableMacro);
        cameraSessionNapi->cameraSession_->UnlockForControl();
        CHECK_RETURN_RET_ELOG(!CameraNapiUtils::CheckError(env, retCode), nullptr,
            "CameraSessionNapi::EnableMacro fail %{public}d", retCode);
    } else {
        MEDIA_ERR_LOG("CameraSessionNapi::EnableMacro get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return nullptr;
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value CameraSessionNapi::GetSupportedBeautyTypes(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedBeautyTypes is called");
    CameraNapiUtils::ThrowError(env, CameraErrorCode::NO_SYSTEM_APP_PERMISSION,
        "SystemApi GetSupportedBeautyTypes is called!");
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value CameraSessionNapi::GetSupportedBeautyRange(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedBeautyRange is called");
    CameraNapiUtils::ThrowError(env, CameraErrorCode::NO_SYSTEM_APP_PERMISSION,
        "SystemApi GetSupportedBeautyRange is called!");
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value CameraSessionNapi::GetBeauty(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetBeauty is called");
    CameraNapiUtils::ThrowError(env, CameraErrorCode::NO_SYSTEM_APP_PERMISSION,
        "SystemApi GetBeauty is called!");
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value CameraSessionNapi::SetBeauty(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetBeauty is called");
    CameraNapiUtils::ThrowError(env, CameraErrorCode::NO_SYSTEM_APP_PERMISSION,
        "SystemApi SetBeauty is called!");
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value CameraSessionNapi::IsMoonCaptureBoostSupported(napi_env env, napi_callback_info info)
{
    CHECK_RETURN_RET_ELOG(!CameraNapiSecurity::CheckSystemApp(env), nullptr,
        "SystemApi IsMoonCaptureBoostSupported is called!");
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
    CHECK_RETURN_RET_ELOG(!CameraNapiSecurity::CheckSystemApp(env), nullptr,
        "SystemApi EnableMoonCaptureBoost is called!");
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
    CHECK_RETURN_RET(valueType != napi_boolean && !CameraNapiUtils::CheckError(env, INVALID_ARGUMENT), result);
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
        CHECK_RETURN_RET(retCode != 0 && !CameraNapiUtils::CheckError(env, retCode), result);
    }
    return result;
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
        CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"),
            nullptr, "CameraSessionNapi::CanPreconfig parse parameter occur error");
    } else {
        CameraNapiParamParser jsParamParser(env, info, cameraSessionNapi, configType, profileSizeRatio);
        CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"),
            nullptr, "CameraSessionNapi::CanPreconfig parse 2 parameter occur error");
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
        CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"),
            nullptr, "CameraSessionNapi::Preconfig parse parameter occur error");
    } else {
        CameraNapiParamParser jsParamParser(env, info, cameraSessionNapi, configType, profileSizeRatio);
        CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"),
            nullptr, "CameraSessionNapi::Preconfig parse 2 parameter occur error");
    }
    int32_t retCode = cameraSessionNapi->cameraSession_->Preconfig(
        static_cast<PreconfigType>(configType), static_cast<ProfileSizeRatio>(profileSizeRatio));
    CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value CameraSessionNapi::GetCameraOutputCapabilities(napi_env env, napi_callback_info info)
{
    CameraNapiUtils::ThrowError(env, CameraErrorCode::NO_SYSTEM_APP_PERMISSION,
        "SystemApi GetCameraOutputCapabilities is called!");
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value CameraSessionNapi::GetSessionFunctions(napi_env env, napi_callback_info info)
{
    CameraNapiUtils::ThrowError(env, CameraErrorCode::NO_SYSTEM_APP_PERMISSION,
        "SystemApi GetSessionFunctions is called!");
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value CameraSessionNapi::GetSessionConflictFunctions(napi_env env, napi_callback_info info)
{
    CameraNapiUtils::ThrowError(env, CameraErrorCode::NO_SYSTEM_APP_PERMISSION,
        "SystemApi GetSessionConflictFunctions is called!");
    return CameraNapiUtils::GetUndefinedValue(env);
}

// ------------------------------------------------auto_awb_props-------------------------------------------------------
napi_value CameraSessionNapi::GetSupportedWhiteBalanceModes(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("CameraSessionNapi::GetSupportedWhiteBalanceModes is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    status = napi_create_array(env, &result);
    CHECK_RETURN_RET_ELOG(status != napi_ok, result,
        "CameraSessionNapi::GetSupportedWhiteBalanceModes napi_create_array call Failed!");
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        std::vector<WhiteBalanceMode> whiteBalanceModes;
        int32_t retCode = cameraSessionNapi->cameraSession_->GetSupportedWhiteBalanceModes(whiteBalanceModes);
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);

        MEDIA_INFO_LOG("CameraSessionNapi::GetSupportedWhiteBalanceModes len = %{public}zu",
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
        MEDIA_ERR_LOG("CameraSessionNapi::GetSupportedWhiteBalanceModes call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::IsWhiteBalanceModeSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("IsWhiteBalanceModeSupported is called");
    napi_status status;
    size_t argc = ARGS_ONE;
    napi_value result = nullptr;
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
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
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
    napi_value whiteBalanceResult = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &whiteBalanceResult);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        WhiteBalanceMode whiteBalanceMode;
        int32_t retCode = cameraSessionNapi->cameraSession_->GetWhiteBalanceMode(whiteBalanceMode);
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
        napi_create_int32(env, whiteBalanceMode, &whiteBalanceResult);
    } else {
        MEDIA_ERR_LOG("GetWhiteBalanceMode call Failed!");
    }
    return whiteBalanceResult;
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
        MEDIA_INFO_LOG("CameraSessionNapi::SetWhiteBalanceMode set mode:%{public}d", value);
        cameraSessionNapi->cameraSession_->UnlockForControl();
    } else {
        MEDIA_ERR_LOG("SetWhiteBalanceMode call Failed!");
    }
    return result;
}

// -----------------------------------------------manual_awb_props------------------------------------------------------
napi_value CameraSessionNapi::GetWhiteBalanceRange(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetWhiteBalanceRange is called");
    napi_status status;
    napi_value whiteBalanceRangeResult = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &whiteBalanceRangeResult);

    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        std::vector<int32_t> whiteBalanceRange = {};
        int32_t retCode = cameraSessionNapi->cameraSession_->GetManualWhiteBalanceRange(whiteBalanceRange);
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
        MEDIA_INFO_LOG("CameraSessionNapi::GetWhiteBalanceRange len = %{public}zu", whiteBalanceRange.size());

        if (!whiteBalanceRange.empty() && napi_create_array(env, &whiteBalanceRangeResult) == napi_ok) {
            for (size_t i = 0; i < whiteBalanceRange.size(); i++) {
                int32_t iso = whiteBalanceRange[i];
                napi_value value;
                napi_create_int32(env, iso, &value);
                napi_set_element(env, whiteBalanceRangeResult, i, value);
            }
        } else {
            MEDIA_ERR_LOG("whiteBalanceRange is empty or failed to create array!");
        }
    } else {
        MEDIA_ERR_LOG("GetWhiteBalanceRange call Failed!");
    }
    return whiteBalanceRangeResult;
}

napi_value CameraSessionNapi::IsManualWhiteBalanceSupported(napi_env env, napi_callback_info info)
{
    CHECK_RETURN_RET_ELOG(!CameraNapiSecurity::CheckSystemApp(env), nullptr,
        "SystemApi IsManualWhiteBalanceSupported is called!");
    MEDIA_DEBUG_LOG("IsManualWhiteBalanceSupported is called");
    napi_status status;
    napi_value manualWhiteBalanceSupportedResult = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &manualWhiteBalanceSupportedResult);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr && cameraSessionNapi->cameraSession_ != nullptr) {
        bool isSupported;
        int32_t retCode = cameraSessionNapi->cameraSession_->IsManualWhiteBalanceSupported(isSupported);
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
        napi_get_boolean(env, isSupported, &manualWhiteBalanceSupportedResult);
    } else {
        MEDIA_ERR_LOG("IsManualIsoSupported call Failed!");
    }
    return manualWhiteBalanceSupportedResult;
}

napi_value CameraSessionNapi::GetWhiteBalance(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetWhiteBalance is called");
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
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
        napi_create_int32(env, wbValue, &result);
    } else {
        MEDIA_ERR_LOG("GetWhiteBalance call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::SetWhiteBalance(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetWhiteBalance is called");
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
        MEDIA_INFO_LOG("CameraSessionNapi::SetWhiteBalance set wbValue:%{public}d", wbValue);
        cameraSessionNapi->cameraSession_->UnlockForControl();
    } else {
        MEDIA_ERR_LOG("SetWhiteBalance call Failed!");
    }
    return result;
}

napi_value CameraSessionNapi::SetUsage(napi_env env, napi_callback_info info)
{
    CameraNapiUtils::ThrowError(env, CameraErrorCode::NO_SYSTEM_APP_PERMISSION,
        "SystemApi SetUsage is called!");
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
    CHECK_RETURN_ELOG(exposureCallback_ == nullptr, "exposureCallback is null");
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
    CHECK_RETURN_ELOG(focusCallback_ == nullptr, "focusCallback is null");
    focusCallback_->RemoveCallbackRef(eventName, callback);
}

void CameraSessionNapi::RegisterMacroStatusCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (macroStatusCallback_ == nullptr) {
        MEDIA_DEBUG_LOG("CameraSessionNapi::RegisterMacroStatusCallbackListener SET CALLBACK");
        macroStatusCallback_ = std::make_shared<MacroStatusCallbackListener>(env);
        CHECK_RETURN_ELOG(macroStatusCallback_ == nullptr,
            "CameraSessionNapi::RegisterMacroStatusCallbackListener THE CALLBACK IS NULL");
        cameraSession_->SetMacroStatusCallback(macroStatusCallback_);
    }
    macroStatusCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void CameraSessionNapi::UnregisterMacroStatusCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    CHECK_RETURN_ELOG(macroStatusCallback_ == nullptr, "macroStatusCallback is null");
    macroStatusCallback_->RemoveCallbackRef(eventName, callback);
}

void CameraSessionNapi::RegisterMoonCaptureBoostCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    CHECK_RETURN_ELOG(!CameraNapiSecurity::CheckSystemApp(env), "SystemApi on moonCaptureBoostStatus is called!");
    if (moonCaptureBoostCallback_ == nullptr) {
        moonCaptureBoostCallback_ = std::make_shared<MoonCaptureBoostCallbackListener>(env);
        cameraSession_->SetMoonCaptureBoostStatusCallback(moonCaptureBoostCallback_);
    }
    moonCaptureBoostCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void CameraSessionNapi::UnregisterMoonCaptureBoostCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    CHECK_RETURN_ELOG(!CameraNapiSecurity::CheckSystemApp(env), "SystemApi off moonCaptureBoostStatus is called!");
    CHECK_RETURN_ELOG(moonCaptureBoostCallback_ == nullptr, "macroStatusCallback is null");
    moonCaptureBoostCallback_->RemoveCallbackRef(eventName, callback);
}

void CameraSessionNapi::RegisterFeatureDetectionStatusListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    CameraNapiUtils::ThrowError(env, CameraErrorCode::NO_SYSTEM_APP_PERMISSION,
        "SystemApi on featureDetection is called");
}

void CameraSessionNapi::UnregisterFeatureDetectionStatusListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    CameraNapiUtils::ThrowError(env, CameraErrorCode::NO_SYSTEM_APP_PERMISSION,
        "SystemApi off featureDetection is called");
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
        MEDIA_DEBUG_LOG("sessionCallback is null");
        return;
    }
    sessionCallback_->RemoveCallbackRef(eventName, callback);
}

void CameraSessionNapi::RegisterEffectSuggestionCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    CameraNapiUtils::ThrowError(env, CameraErrorCode::NO_SYSTEM_APP_PERMISSION,
        "SystemApi on effectSuggestionChange is called");
}

void CameraSessionNapi::UnregisterEffectSuggestionCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    CameraNapiUtils::ThrowError(env, CameraErrorCode::NO_SYSTEM_APP_PERMISSION,
        "SystemApi off effectSuggestionChange is called");
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
    CHECK_RETURN_ELOG(smoothZoomCallback_ == nullptr, "smoothZoomCallback is null");
    smoothZoomCallback_->RemoveCallbackRef(eventName, callback);
}

void CameraSessionNapi::RegisterFocusTrackingInfoCallbackListener(const std::string& eventName,
    napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    CameraNapiUtils::ThrowError(env, CameraErrorCode::NO_SYSTEM_APP_PERMISSION,
        "SystemApi on focusTrackingInfoAvailable is called");
}

void CameraSessionNapi::UnregisterFocusTrackingInfoCallbackListener(const std::string& eventName,
    napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    CameraNapiUtils::ThrowError(env, CameraErrorCode::NO_SYSTEM_APP_PERMISSION,
        "SystemApi off focusTrackingInfoAvailable is called");
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
    { "systemPressureLevelChange", {
        &CameraSessionNapi::RegisterPressureStatusCallbackListener,
        &CameraSessionNapi::UnregisterPressureStatusCallbackListener } },
    { "controlCenterEffectStatusChange", {
        &CameraSessionNapi::RegisterControlCenterEffectStatusCallbackListener,
        &CameraSessionNapi::UnregisterControlCenterEffectStatusCallbackListener } },
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
    { "autoDeviceSwitchStatusChange", {
        &CameraSessionNapi::RegisterAutoDeviceSwitchCallbackListener,
        &CameraSessionNapi::UnregisterAutoDeviceSwitchCallbackListener } },
    { "focusTrackingInfoAvailable", {
        &CameraSessionNapi::RegisterFocusTrackingInfoCallbackListener,
        &CameraSessionNapi::UnregisterFocusTrackingInfoCallbackListener } },
    { "lightStatusChange", {
        &CameraSessionNapi::RegisterLightStatusCallbackListener,
        &CameraSessionNapi::UnregisterLightStatusCallbackListener } },
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
    CameraNapiUtils::ThrowError(env, CameraErrorCode::NO_SYSTEM_APP_PERMISSION,
        "SystemApi on lcdFlashStatus is called");
}

void CameraSessionNapi::UnregisterLcdFlashStatusCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    CameraNapiUtils::ThrowError(env, CameraErrorCode::NO_SYSTEM_APP_PERMISSION,
        "SystemApi off lcdFlashStatus is called");
}

napi_value CameraSessionNapi::IsAutoDeviceSwitchSupported(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("IsAutoDeviceSwitchSupported is called");
    CameraSessionNapi* cameraSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionNapi);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"), nullptr,
        "CameraSessionNapi::IsAutoDeviceSwitchSupported parse parameter occur error");
    auto result = CameraNapiUtils::GetUndefinedValue(env);
    if (cameraSessionNapi->cameraSession_ != nullptr) {
        bool isSupported = cameraSessionNapi->cameraSession_->IsAutoDeviceSwitchSupported();
        napi_get_boolean(env, isSupported, &result);
    } else {
        MEDIA_ERR_LOG("CameraSessionNapi::IsAutoDeviceSwitchSupported get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return nullptr;
    }
    return result;
}

napi_value CameraSessionNapi::EnableAutoDeviceSwitch(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("CameraSessionNapi::EnableAutoDeviceSwitch is called");
    bool isEnable;
    CameraSessionNapi* cameraSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionNapi, isEnable);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"), nullptr,
        "CameraSessionNapi::EnableAutoDeviceSwitch parse parameter occur error");

    if (cameraSessionNapi->cameraSession_ != nullptr) {
        MEDIA_INFO_LOG("CameraSessionNapi::EnableAutoDeviceSwitch:%{public}d", isEnable);
        cameraSessionNapi->cameraSession_->LockForControl();
        int32_t retCode = cameraSessionNapi->cameraSession_->EnableAutoDeviceSwitch(isEnable);
        cameraSessionNapi->cameraSession_->UnlockForControl();
        CHECK_RETURN_RET_ELOG(!CameraNapiUtils::CheckError(env, retCode), nullptr,
            "CameraSessionNapi::EnableAutoSwitchDevice fail %{public}d", retCode);
    } else {
        MEDIA_ERR_LOG("CameraSessionNapi::EnableAutoDeviceSwitch get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return nullptr;
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

void CameraSessionNapi::RegisterAutoDeviceSwitchCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    CHECK_RETURN_ELOG(cameraSession_ == nullptr, "cameraSession is null!");
    if (autoDeviceSwitchCallback_ == nullptr) {
        autoDeviceSwitchCallback_ = std::make_shared<AutoDeviceSwitchCallbackListener>(env);
        cameraSession_->SetAutoDeviceSwitchCallback(autoDeviceSwitchCallback_);
    }
    autoDeviceSwitchCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void CameraSessionNapi::UnregisterAutoDeviceSwitchCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    CHECK_RETURN_ELOG(autoDeviceSwitchCallback_ == nullptr, "autoDeviceSwitchCallback is nullptr.");
    autoDeviceSwitchCallback_->RemoveCallbackRef(eventName, callback);
}

void CameraSessionNapi::RegisterPressureStatusCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    CameraNapiUtils::ThrowError(env, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "this type callback can not be registered in current session!");
}

void CameraSessionNapi::UnregisterPressureStatusCallbackListener(
    const std::string &eventName, napi_env env, napi_value callback, const std::vector<napi_value> &args)
{
    CameraNapiUtils::ThrowError(env, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "this type callback can not be registered in current session!");
}

void CameraSessionNapi::RegisterControlCenterEffectStatusCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    CameraNapiUtils::ThrowError(env, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "this type callback can not be registered in current session!");
}
 
void CameraSessionNapi::UnregisterControlCenterEffectStatusCallbackListener(
    const std::string &eventName, napi_env env, napi_value callback, const std::vector<napi_value> &args)
{
    CameraNapiUtils::ThrowError(env, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "this type callback can not be unregistered in current session!");
}

void MacroStatusCallbackListener::OnMacroStatusCallbackAsync(MacroStatus status) const
{
    MEDIA_DEBUG_LOG("OnMacroStatusCallbackAsync is called");
    auto callbackInfo = std::make_unique<MacroStatusCallbackInfo>(status, shared_from_this());
    MacroStatusCallbackInfo *event = callbackInfo.get();
    auto task = [event]() {
        auto callbackInfo = reinterpret_cast<MacroStatusCallbackInfo*>(event);
        if (callbackInfo) {
            auto listener = callbackInfo->listener_.lock();
            CHECK_EXECUTE(listener != nullptr, listener->OnMacroStatusCallback(callbackInfo->status_));
            delete callbackInfo;
        }
    };
    if (napi_ok != napi_send_event(env_, task, napi_eprio_immediate)) {
        MEDIA_ERR_LOG("failed to execute work");
    } else {
        callbackInfo.release();
    }
}

void MacroStatusCallbackListener::OnMacroStatusCallback(MacroStatus status) const
{
    MEDIA_DEBUG_LOG("OnMacroStatusCallback is called");
    ExecuteCallbackScopeSafe("macroStatusChanged", [&]() {
        napi_value result;
        napi_value errCode = CameraNapiUtils::GetUndefinedValue(env_);
        napi_get_boolean(env_, status == MacroStatus::ACTIVE, &result);
        return ExecuteCallbackData(env_, errCode, result);
    });
}

void MacroStatusCallbackListener::OnMacroStatusChanged(MacroStatus status)
{
    MEDIA_DEBUG_LOG("OnMacroStatusChanged is called, status: %{public}d", status);
    OnMacroStatusCallbackAsync(status);
}

} // namespace CameraStandard
} // namespace OHOS