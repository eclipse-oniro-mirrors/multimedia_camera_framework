/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#include "output/unify_movie_file_output_napi.h"

#include <unordered_set>

#include "camera_log.h"
#include "camera_manager.h"
#include "camera_napi_object_types.h"
#include "camera_napi_security_utils.h"
#include "camera_napi_template_utils.h"
#include "camera_napi_worker_queue_keeper.h"
#include "media_library_comm_napi.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "output/video_capability_napi.h"
#include "unify_movie_file_output.h"
#include "uv.h"

namespace OHOS {
namespace CameraStandard {
thread_local sptr<UnifyMovieFileOutput> UnifyMovieFileOutputNapi::sUnifyMovieFileOutput_ = nullptr;
thread_local napi_ref UnifyMovieFileOutputNapi::constructor_ = nullptr;
thread_local uint32_t UnifyMovieFileOutputNapi::movieFileOutputTaskId = CAMERA_MOVIE_FILE_OUTPUT_TASKID;

UnifyMovieFileOutputCallback::UnifyMovieFileOutputCallback(napi_env env) : ListenerBase(env) {}

void UnifyMovieFileOutputCallback::UpdateJSCallbackAsync(UnifyMovieFileOutputCallbackInfo callbackInfo) const
{
    MEDIA_DEBUG_LOG("UpdateJSCallbackAsync is called");
    std::unique_ptr<UnifyMovieFileOutputCallbackInfo> asyncInfo =
        std::make_unique<UnifyMovieFileOutputCallbackInfo>(callbackInfo);
    UnifyMovieFileOutputCallbackInfo *event = asyncInfo.get();
    auto task = [event]() {
        UnifyMovieFileOutputCallbackInfo* callbackInfo =
            reinterpret_cast<UnifyMovieFileOutputCallbackInfo*>(event);
        if (callbackInfo) {
            auto listener = callbackInfo->listener.lock();
            if (listener) {
                listener->UpdateJSCallback(*callbackInfo);
            }
            delete callbackInfo;
         }
    };
    std::unordered_map<std::string, std::string> params = {
        {"eventName", callbackInfo.eventName},
    };
    std::string taskName = CameraNapiUtils::GetTaskName("UnifyMovieFileOutputCallback::UpdateJSCallbackAsync", params);
    if (napi_ok != napi_send_event(env_, task, napi_eprio_immediate, taskName.c_str())) {
        MEDIA_ERR_LOG("failed to execute work");
    } else {
        (void)asyncInfo.release();
    }
}

void UnifyMovieFileOutputCallback::UpdateJSCallback(UnifyMovieFileOutputCallbackInfo callbackInfo) const
{
    MEDIA_DEBUG_LOG("UpdateJSCallback is called");
    CHECK_RETURN_ELOG(
        callbackInfo.eventName.empty(), "UnifyMovieFileOutputCallback::UpdateJSCallback, event is empty");
    ExecuteCallbackScopeSafe(callbackInfo.eventName, [&]() {
        napi_value errCode = CameraNapiUtils::GetUndefinedValue(env_);
        napi_value callbackObj = CameraNapiUtils::GetUndefinedValue(env_);
        if (callbackInfo.eventName == CONST_UNIFY_MOVIE_FILE_RECORDING_ERROR) {
            CameraNapiObject errObj { { { "code", &callbackInfo.errorCode } } };
            errCode = errObj.CreateNapiObjFromMap(env_);
        } else if (callbackInfo.eventName == CONST_UNIFY_MOVIE_FILE_MOVIE_INFO_AVAILABLE) {
            constexpr int32_t VIDEO_SHOT_TYPE = 1;
            CameraNapiObject::CameraNapiObjFieldMap fieldMap { { { "captureId", &callbackInfo.captureId } } };
            if (!callbackInfo.uri.empty()) {
                fieldMap.insert({ "uri", &callbackInfo.uri });
            }
            CameraNapiObject dataObj { fieldMap };
            callbackObj = dataObj.CreateNapiObjFromMap(env_);

            if (!callbackInfo.uri.empty()) {
                napi_value assetObj = Media::MediaLibraryCommNapi::CreatePhotoAssetNapi(
                    env_, callbackInfo.uri, static_cast<int32_t>(VIDEO_SHOT_TYPE));
                napi_set_named_property(env_, callbackObj, "asset", assetObj);
            }
        }
        return ExecuteCallbackData(env_, errCode, callbackObj);
    });
}

void UnifyMovieFileOutputCallback::OnStart()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("UnifyMovieFileOutputCallback::OnStart is called");
    UnifyMovieFileOutputCallbackInfo callbackInfo(CONST_UNIFY_MOVIE_FILE_RECORDING_START, shared_from_this());
    UpdateJSCallbackAsync(callbackInfo);
}

void UnifyMovieFileOutputCallback::OnPause()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("UnifyMovieFileOutputCallback::OnPause is called");
    UnifyMovieFileOutputCallbackInfo callbackInfo(CONST_UNIFY_MOVIE_FILE_RECORDING_PAUSE, shared_from_this());
    UpdateJSCallbackAsync(callbackInfo);
}

void UnifyMovieFileOutputCallback::OnResume()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("UnifyMovieFileOutputCallback::OnResume is called");
    UnifyMovieFileOutputCallbackInfo callbackInfo(CONST_UNIFY_MOVIE_FILE_RECORDING_RESUME, shared_from_this());
    UpdateJSCallbackAsync(callbackInfo);
}

void UnifyMovieFileOutputCallback::OnStop()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("UnifyMovieFileOutputCallback::OnStop is called");
    UnifyMovieFileOutputCallbackInfo callbackInfo(CONST_UNIFY_MOVIE_FILE_RECORDING_STOP, shared_from_this());
    UpdateJSCallbackAsync(callbackInfo);
}

void UnifyMovieFileOutputCallback::OnMovieInfoAvailable(int32_t captureId, std::string uri)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("UnifyMovieFileOutputCallback::OnMovieInfoAvailable is called");
    UnifyMovieFileOutputCallbackInfo callbackInfo(CONST_UNIFY_MOVIE_FILE_MOVIE_INFO_AVAILABLE, shared_from_this());
    callbackInfo.captureId = captureId;
    callbackInfo.uri = uri;
    UpdateJSCallbackAsync(callbackInfo);
}

void UnifyMovieFileOutputCallback::OnError(const int32_t errorCode)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("UnifyMovieFileOutputCallback::OnError is called");
    UnifyMovieFileOutputCallbackInfo callbackInfo(CONST_UNIFY_MOVIE_FILE_RECORDING_ERROR, shared_from_this());
    callbackInfo.errorCode = errorCode;
    UpdateJSCallbackAsync(callbackInfo);
}

napi_value UnifyMovieFileOutputNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("UnifyMovieFileOutputNapi::Init is called");
    napi_status status;
    napi_value constructor;

    napi_property_descriptor movie_file_output_props[] = {
        DECLARE_NAPI_FUNCTION("start", Start),
        DECLARE_NAPI_FUNCTION("pause", Pause),
        DECLARE_NAPI_FUNCTION("resume", Resume),
        DECLARE_NAPI_FUNCTION("stop", Stop),
        DECLARE_NAPI_FUNCTION("getActiveProfile", GetActiveProfile),
        DECLARE_NAPI_FUNCTION("setOutputSettings", SetOutputSettings),
        DECLARE_NAPI_FUNCTION("getOutputSettings", GetOutputSettings),
        DECLARE_NAPI_FUNCTION("getSupportedVideoCodecTypes", GetSupportedVideoCodecTypes),
        DECLARE_NAPI_FUNCTION("getSupportedVideoFilters", GetSupportedVideoFilters),
        DECLARE_NAPI_FUNCTION("addVideoFilter", AddVideoFilter),
        DECLARE_NAPI_FUNCTION("removeVideoFilter", RemoveVideoFilter),
        DECLARE_NAPI_FUNCTION("isMirrorSupported", IsMirrorSupported),
        DECLARE_NAPI_FUNCTION("enableMirror", EnableMirror),
        DECLARE_NAPI_FUNCTION("release", Release),
        DECLARE_NAPI_FUNCTION("isAutoDeferredVideoEnhancementSupported", IsAutoDeferredVideoEnhancementSupported),
        DECLARE_NAPI_FUNCTION("isAutoDeferredVideoEnhancementEnabled", IsAutoDeferredVideoEnhancementEnabled),
        DECLARE_NAPI_FUNCTION("enableAutoDeferredVideoEnhancement", EnableAutoDeferredVideoEnhancement),
        DECLARE_NAPI_FUNCTION("isAutoVideoFrameRateSupported", IsAutoVideoFrameRateSupported),
        DECLARE_NAPI_FUNCTION("enableAutoVideoFrameRate", EnableAutoVideoFrameRate),
        DECLARE_NAPI_FUNCTION("getVideoRotation", GetVideoRotation),
        DECLARE_NAPI_FUNCTION("getSupportedVideoCapability", GetSupportedVideoCapability),
        DECLARE_NAPI_FUNCTION("on", On),
        DECLARE_NAPI_FUNCTION("off", Off) };

    status = napi_define_class(env, CAMERA_UNIFY_MOVIE_FILE_OUTPUT_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
        MovieFileOutputNapiConstructor, nullptr,
        sizeof(movie_file_output_props) / sizeof(movie_file_output_props[PARAM0]), movie_file_output_props,
        &constructor);
    if (status == napi_ok) {
        // create a strong ref to prevent the constructor be garbage-collected
        status = NapiRefManager::CreateMemSafetyRef(env, constructor, &constructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, CAMERA_UNIFY_MOVIE_FILE_OUTPUT_NAPI_CLASS_NAME, constructor);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("UnifyMovieFileOutputNapi::Init Failed!");
    return nullptr;
}

UnifyMovieFileOutputNapi::UnifyMovieFileOutputNapi() : env_(nullptr)
{
    MEDIA_DEBUG_LOG("UnifyMovieFileOutputNapi::UnifyMovieFileOutputNapi() is called");
}

napi_value UnifyMovieFileOutputNapi::MovieFileOutputNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("UnifyMovieFileOutputNapi::MovieFileOutputNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<UnifyMovieFileOutputNapi> obj = std::make_unique<UnifyMovieFileOutputNapi>();
        obj->env_ = env;
        obj->unifyMovieFileOutput_ = sUnifyMovieFileOutput_;
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
            UnifyMovieFileOutputNapi::MovieFileOutputNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            (void)obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("UnifyMovieFileOutputNapi::MovieFileOutputNapiConstructor failed wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("UnifyMovieFileOutputNapi::MovieFileOutputNapiConstructor call Failed!");
    return result;
}

void UnifyMovieFileOutputNapi::MovieFileOutputNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("UnifyMovieFileOutputNapi::MovieFileOutputNapiDestructor is called");
    UnifyMovieFileOutputNapi* cameraObj = reinterpret_cast<UnifyMovieFileOutputNapi*>(nativeObject);
    if (cameraObj != nullptr) {
        delete cameraObj;
    }
}

napi_value UnifyMovieFileOutputNapi::CreateUnifyMovieFileOutput(napi_env env, VideoProfile& videoProfile)
{
    MEDIA_DEBUG_LOG("CreateUnifyMovieFileOutput is called");
    napi_status status;
    napi_value result;
    napi_value constructor;

    napi_get_undefined(env, &result);
    status = napi_get_reference_value(env, constructor_, &constructor);
    if (status == napi_ok) {
        int retCode = CameraManager::GetInstance()->CreateMovieFileOutput(videoProfile, &sUnifyMovieFileOutput_);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        if (sUnifyMovieFileOutput_ == nullptr) {
            MEDIA_ERR_LOG("failed to create UnifyMovieFileOutput");
            return result;
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sUnifyMovieFileOutput_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create movie file output instance");
        }
    }
    MEDIA_ERR_LOG("CreateUnifyMovieFileOutput call Failed!");
    return result;
}

bool UnifyMovieFileOutputNapi::IsMovieFileOutput(napi_env env, napi_value obj)
{
    MEDIA_DEBUG_LOG("IsMovieFileOutput is called");
    bool result = false;
    napi_status status;
    napi_value constructor;

    status = napi_get_reference_value(env, constructor_, &constructor);
    if (status == napi_ok) {
        status = napi_instanceof(env, obj, constructor, &result);
        if (status != napi_ok) {
            result = false;
        }
    }
    return result;
}

sptr<UnifyMovieFileOutput> UnifyMovieFileOutputNapi::GetMovieFileOutput()
{
    return unifyMovieFileOutput_;
}

const UnifyMovieFileOutputNapi::EmitterFunctions& UnifyMovieFileOutputNapi::GetEmitterFunctions()
{
    static const EmitterFunctions funMap = {
        { CONST_UNIFY_MOVIE_FILE_RECORDING_START,
            { &UnifyMovieFileOutputNapi::RegisterRecordingStartCallbackListener,
                &UnifyMovieFileOutputNapi::UnregisterRecordingStartCallbackListener } },
        { CONST_UNIFY_MOVIE_FILE_RECORDING_PAUSE,
            { &UnifyMovieFileOutputNapi::RegisterRecordingPauseCallbackListener,
                &UnifyMovieFileOutputNapi::UnregisterRecordingPauseCallbackListener } },
        { CONST_UNIFY_MOVIE_FILE_RECORDING_RESUME,
            { &UnifyMovieFileOutputNapi::RegisterRecordingResumeCallbackListener,
                &UnifyMovieFileOutputNapi::UnregisterRecordingResumeCallbackListener } },
        { CONST_UNIFY_MOVIE_FILE_RECORDING_STOP,
            { &UnifyMovieFileOutputNapi::RegisterRecordingStopCallbackListener,
                &UnifyMovieFileOutputNapi::UnregisterRecordingStopCallbackListener } },
        { CONST_UNIFY_MOVIE_FILE_MOVIE_INFO_AVAILABLE,
            { &UnifyMovieFileOutputNapi::RegisterMovieInfoAvailableCallbackListener,
                &UnifyMovieFileOutputNapi::UnregisterMovieInfoAvailableCallbackListener } },
        { CONST_UNIFY_MOVIE_FILE_RECORDING_ERROR,
            { &UnifyMovieFileOutputNapi::RegisterErrorCallbackListener,
                &UnifyMovieFileOutputNapi::UnregisterErrorCallbackListener } }
    };
    return funMap;
}

void UnifyMovieFileOutputNapi::RegisterRecordingStartCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi RegisterRecordingStartCallbackListener is called!");
        return;
    }
    auto listener = RegisterCallbackListener(eventName, env, callback, args, isOnce);
    CHECK_RETURN_ELOG(
        listener == nullptr, "UnifyMovieFileOutputNapi::RegisterRecordingStartCallbackListener listener is null");
    unifyMovieFileOutput_->AddUnifyMovieFileOutputStateCallback(listener);
}

void UnifyMovieFileOutputNapi::UnregisterRecordingStartCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi UnregisterRecordingStartCallbackListener is called!");
        return;
    }
    auto listener = UnregisterCallbackListener(eventName, env, callback, args);
    CHECK_RETURN_ELOG(listener == nullptr,
        "UnifyMovieFileOutputNapi::UnregisterRecordingStartCallbackListener %{public}s listener is null",
        eventName.c_str());
    if (listener->IsEmpty(eventName)) {
        unifyMovieFileOutput_->RemoveUnifyMovieFileOutputStateCallback(listener);
    }
}

void UnifyMovieFileOutputNapi::RegisterRecordingPauseCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi RegisterRecordingPauseCallbackListener is called!");
        return;
    }
    auto listener = RegisterCallbackListener(eventName, env, callback, args, isOnce);
    CHECK_RETURN_ELOG(
        listener == nullptr, "UnifyMovieFileOutputNapi::RegisterRecordingPauseCallbackListener listener is null");
    unifyMovieFileOutput_->AddUnifyMovieFileOutputStateCallback(listener);
}

void UnifyMovieFileOutputNapi::UnregisterRecordingPauseCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi UnregisterRecordingPauseCallbackListener is called!");
        return;
    }
    auto listener = UnregisterCallbackListener(eventName, env, callback, args);
    CHECK_RETURN_ELOG(listener == nullptr,
        "UnifyMovieFileOutputNapi::UnregisterRecordingPauseCallbackListener %{public}s listener is null",
        eventName.c_str());
    if (listener->IsEmpty(eventName)) {
        unifyMovieFileOutput_->RemoveUnifyMovieFileOutputStateCallback(listener);
    }
}

void UnifyMovieFileOutputNapi::RegisterRecordingResumeCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi RegisterRecordingResumeCallbackListener is called!");
        return;
    }
    auto listener = RegisterCallbackListener(eventName, env, callback, args, isOnce);
    CHECK_RETURN_ELOG(
        listener == nullptr, "UnifyMovieFileOutputNapi::RegisterRecordingResumeCallbackListener listener is null");
    unifyMovieFileOutput_->AddUnifyMovieFileOutputStateCallback(listener);
}

void UnifyMovieFileOutputNapi::UnregisterRecordingResumeCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi UnregisterRecordingResumeCallbackListener is called!");
        return;
    }
    auto listener = UnregisterCallbackListener(eventName, env, callback, args);
    CHECK_RETURN_ELOG(listener == nullptr,
        "UnifyMovieFileOutputNapi::UnregisterRecordingResumeCallbackListener %{public}s listener is null",
        eventName.c_str());
    if (listener->IsEmpty(eventName)) {
        unifyMovieFileOutput_->RemoveUnifyMovieFileOutputStateCallback(listener);
    }
}

void UnifyMovieFileOutputNapi::RegisterRecordingStopCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi RegisterRecordingStopCallbackListener is called!");
        return;
    }
    auto listener = RegisterCallbackListener(eventName, env, callback, args, isOnce);
    CHECK_RETURN_ELOG(
        listener == nullptr, "UnifyMovieFileOutputNapi::RegisterRecordingStopCallbackListener listener is null");
    unifyMovieFileOutput_->AddUnifyMovieFileOutputStateCallback(listener);
}

void UnifyMovieFileOutputNapi::UnregisterRecordingStopCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi UnregisterRecordingStopCallbackListener is called!");
        return;
    }
    auto listener = UnregisterCallbackListener(eventName, env, callback, args);
    CHECK_RETURN_ELOG(listener == nullptr,
        "UnifyMovieFileOutputNapi::UnregisterRecordingStopCallbackListener %{public}s listener is null",
        eventName.c_str());
    if (listener->IsEmpty(eventName)) {
        unifyMovieFileOutput_->RemoveUnifyMovieFileOutputStateCallback(listener);
    }
}

void UnifyMovieFileOutputNapi::RegisterMovieInfoAvailableCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi RegisterMovieInfoAvailableCallbackListener is called!");
        return;
    }
    auto listener = RegisterCallbackListener(eventName, env, callback, args, isOnce);
    CHECK_RETURN_ELOG(
        listener == nullptr, "UnifyMovieFileOutputNapi::RegisterMovieInfoAvailableCallbackListener listener is null");
    unifyMovieFileOutput_->AddUnifyMovieFileOutputStateCallback(listener);
}

void UnifyMovieFileOutputNapi::UnregisterMovieInfoAvailableCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi UnregisterMovieInfoAvailableCallbackListener is called!");
        return;
    }
    auto listener = UnregisterCallbackListener(eventName, env, callback, args);
    CHECK_RETURN_ELOG(listener == nullptr,
        "UnifyMovieFileOutputNapi::UnregisterMovieInfoAvailableCallbackListener %{public}s listener is null",
        eventName.c_str());
    if (listener->IsEmpty(eventName)) {
        unifyMovieFileOutput_->RemoveUnifyMovieFileOutputStateCallback(listener);
    }
}

void UnifyMovieFileOutputNapi::RegisterErrorCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi RegisterErrorCallbackListener is called!");
        return;
    }
    auto listener = RegisterCallbackListener(eventName, env, callback, args, isOnce);
    CHECK_RETURN_ELOG(
        listener == nullptr, "UnifyMovieFileOutputNapi::RegisterErrorCallbackListener listener is null");
    unifyMovieFileOutput_->AddUnifyMovieFileOutputStateCallback(listener);
}

void UnifyMovieFileOutputNapi::UnregisterErrorCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi UnregisterErrorCallbackListener is called!");
        return;
    }
    auto listener = UnregisterCallbackListener(eventName, env, callback, args);
    CHECK_RETURN_ELOG(listener == nullptr,
        "UnifyMovieFileOutputNapi::UnregisterErrorCallbackListener %{public}s listener is null", eventName.c_str());
    if (listener->IsEmpty(eventName)) {
        unifyMovieFileOutput_->RemoveUnifyMovieFileOutputStateCallback(listener);
    }
}

namespace {
void AsyncCompleteCallback(napi_env env, napi_status status, void* data)
{
    auto context = static_cast<UnifyMovieFileOutputAsyncContext*>(data);
    CHECK_RETURN_ELOG(context == nullptr, "UnifyMovieFileOutputNapi AsyncCompleteCallback context is null");
    MEDIA_INFO_LOG("UnifyMovieFileOutputNapi AsyncCompleteCallback %{public}s, status = %{public}d",
        context->funcName.c_str(), context->status);
    std::unique_ptr<JSAsyncContextOutput> jsContext = std::make_unique<JSAsyncContextOutput>();
    jsContext->status = context->status;
    if (!context->status) {
        CameraNapiUtils::CreateNapiErrorObject(env, context->errorCode, context->errorMsg.c_str(), jsContext);
    } else {
        if (context->captureId != -1) {
            MEDIA_INFO_LOG("AsyncCompleteCallback captureId = %{public}d", context->captureId);
            napi_create_int32(env, context->captureId, &jsContext->data);
        } else {
            napi_get_undefined(env, &jsContext->data);
        }
    }
    if (!context->funcName.empty() && context->taskId > 0) {
        // Finish async trace
        CAMERA_FINISH_ASYNC_TRACE(context->funcName, context->taskId);
        jsContext->funcName = context->funcName;
    }
    if (context->work != nullptr) {
        CameraNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef, context->work, *jsContext);
    }
    context->FreeHeldNapiValue(env);
    delete context;
}
} // namespace

bool UnifyMovieFileOutputNapi::ParseOutputSettings(napi_env env, napi_callback_info info,
    UnifyMovieFileOutputAsyncContext* asyncContext, std::shared_ptr<CameraNapiAsyncFunction>& asyncFunction)
{
    Location settingsLocation;
    CameraNapiObject settingsLocationNapiOjbect { {
        { "latitude", &settingsLocation.latitude },
        { "longitude", &settingsLocation.longitude },
        { "altitude", &settingsLocation.altitude },
    } };

    bool settingsBFrameEnabled;
    int32_t videoBitrate;
    CameraNapiObject settingsNapiOjbect { {
        { "videoCodec", &asyncContext->videoCodec },
        { "rotation", &asyncContext->rotation },
        { "location", &settingsLocationNapiOjbect },
        { "isBFrameEnabled", &settingsBFrameEnabled },
        { "videoBitrate", &videoBitrate },
    } };

    std::unordered_set<std::string> optionalKeys = { "location", "rotation", "isBFrameEnabled", "videoBitrate"};
    settingsNapiOjbect.SetOptionalKeys(optionalKeys);
    asyncFunction = std::make_shared<CameraNapiAsyncFunction>(
        env, "SetOutputSettings", asyncContext->callbackRef, asyncContext->deferred);
    CameraNapiParamParser jsParamParser(env, info, asyncContext->nativeNapiObj, asyncFunction, settingsNapiOjbect);
    if (jsParamParser.IsStatusOk()) {
        if (settingsNapiOjbect.IsKeySetted("location")) {
            asyncContext->location = settingsLocation;
        }
        if (settingsNapiOjbect.IsKeySetted("isBFrameEnabled")) {
            asyncContext->isBFrameEnabled = settingsBFrameEnabled;
        }
        if (settingsNapiOjbect.IsKeySetted("videoBitrate")) {
            asyncContext->videoBitrate = videoBitrate;
            MEDIA_INFO_LOG("unify-ParseOutputSettings->videoBitrate has_value: bitrate:%{public}d,%{public}d",
                videoBitrate, asyncContext->videoBitrate.value_or(-1));
        }
        MEDIA_INFO_LOG("ParseOutputSettings pass");
    }
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
        MEDIA_ERR_LOG("ParseOutputSettings invalid argument");
        return false;
    }
    asyncContext->HoldNapiValue(env, jsParamParser.GetThisVar());
    return true;
}

napi_value UnifyMovieFileOutputNapi::SetOutputSettings(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("unify-SetOutputSettings is called");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi SetOutputSettings is called!");
        return nullptr;
    }

    std::unique_ptr<UnifyMovieFileOutputAsyncContext> asyncContext = std::make_unique<UnifyMovieFileOutputAsyncContext>(
        "UnifyMovieFileOutputNapi::SetOutputSettings", CameraNapiUtils::IncrementAndGet(movieFileOutputTaskId));
    std::shared_ptr<CameraNapiAsyncFunction> asyncFunction;
    if (!ParseOutputSettings(env, info, asyncContext.get(), asyncFunction)) {
        MEDIA_ERR_LOG("UnifyMovieFileOutputNapi::SetOutputSettings parse parameters fail.");
        return nullptr;
    }
    napi_status status = napi_create_async_work(
        env, nullptr, asyncFunction->GetResourceName(),
        [](napi_env env, void* data) {
            MEDIA_INFO_LOG("UnifyMovieFileOutputNapi::SetOutputSettings running on worker");
            auto context = static_cast<UnifyMovieFileOutputAsyncContext*>(data);
            CHECK_RETURN_ELOG(
                context->nativeNapiObj == nullptr, "UnifyMovieFileOutputNapi::SetOutputSettings async info is nullptr");
            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(context->queueTask, [&context]() {
                context->status = true;
                sptr<UnifyMovieFileOutput> movieFileOutput = context->nativeNapiObj->GetMovieFileOutput();
                std::shared_ptr<MovieSettings> movieSettings = make_shared<MovieSettings>(MovieSettings {
                    .videoCodecType = VideoCodecType::VIDEO_ENCODE_TYPE_AVC,
                    .rotation = 0,
                    .isHasLocation = false,
                    .location = Location {0, 0, 0},
                    .isBFrameEnabled = false,
                    .videoBitrate = 30000000,
                });
                movieSettings->rotation = context->rotation;
                movieSettings->videoCodecType = static_cast<VideoCodecType>(context->videoCodec);
                if (context->location.has_value()) {
                    movieSettings->isHasLocation = true;
                    movieSettings->location = context->location.value();
                }
                if (context->isBFrameEnabled.has_value()) {
                    movieSettings->isBFrameEnabled = context->isBFrameEnabled.value();
                }
                if (context->videoBitrate.has_value()) {
                    movieSettings->videoBitrate = context->videoBitrate.value();
                    MEDIA_INFO_LOG("unify-movieSettings->videoBitrate has_value: bitrate:%{public}d,%{public}d",
                        context->videoBitrate.value(), movieSettings->videoBitrate);
                }
                context->errorCode = movieFileOutput->SetOutputSettings(movieSettings);
                context->status = context->errorCode == CameraErrorCode::SUCCESS;
            });
        },
        AsyncCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for UnifyMovieFileOutputNapi::SetOutputSettings");
        asyncFunction->Reset();
    } else {
        asyncContext->queueTask = CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask(
            "UnifyMovieFileOutputNapi::SetOutputSettings");
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        (void)asyncContext.release();
    }
    if (asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE) {
        return asyncFunction->GetPromise();
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value UnifyMovieFileOutputNapi::GetOutputSettings(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("GetOutputSettings is called");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi GetOutputSettings is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("UnifyMovieFileOutputNapi::GetOutputSettings is called");
    UnifyMovieFileOutputNapi* unifyMovieFileOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, unifyMovieFileOutputNapi);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("UnifyMovieFileOutputNapi::GetOutputSettings parse parameter occur error");
        return nullptr;
    }
    auto settings = unifyMovieFileOutputNapi->unifyMovieFileOutput_->GetOutputSettings();
    if (settings == nullptr) {
        return CameraNapiUtils::GetUndefinedValue(env);
    }
    return CameraNapiObjOutputSettings(*settings).GenerateNapiValue(env);
}

napi_value UnifyMovieFileOutputNapi::GetSupportedVideoCodecTypes(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("UnifyMovieFileOutputNapi::GetSupportedVideoCodecTypes is called");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi GetSupportedVideoCodecTypes is called!");
        return nullptr;
    }
    napi_value result = CameraNapiUtils::GetUndefinedValue(env);
    UnifyMovieFileOutputNapi* unifyMovieFileOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, unifyMovieFileOutputNapi);
    if (!jsParamParser.AssertStatus(SERVICE_FATL_ERROR, "parse parameter occur error")) {
        MEDIA_ERR_LOG("UnifyMovieFileOutputNapi::GetSupportedVideoCodecTypes parse parameter occur error");
        return result;
    }
    if (unifyMovieFileOutputNapi->unifyMovieFileOutput_ == nullptr) {
        MEDIA_ERR_LOG("UnifyMovieFileOutputNapi::GetSupportedVideoCodecTypes get native object fail");
        CameraNapiUtils::ThrowError(env, SERVICE_FATL_ERROR, "get native object fail");
        return result;
    }
    std::vector<int32_t> supportedVideoCodecTypes;
    int32_t retCode =
        unifyMovieFileOutputNapi->unifyMovieFileOutput_->GetSupportedVideoCodecTypes(supportedVideoCodecTypes);
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        return nullptr;
    }
    napi_status status = napi_create_array(env, &result);
    CHECK_RETURN_RET_ELOG(status != napi_ok, result, "napi_create_array call Failed!");
    for (size_t i = 0; i < supportedVideoCodecTypes.size(); i++) {
        int32_t value = supportedVideoCodecTypes[i];
        napi_value element;
        napi_create_int32(env, value, &element);
        napi_set_element(env, result, i, element);
    }
    return result;
}

napi_value UnifyMovieFileOutputNapi::GetActiveProfile(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("UnifyMovieFileOutputNapi::GetActiveProfile is called");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi GetActiveProfile is called!");
        return nullptr;
    }
    UnifyMovieFileOutputNapi* unifyMovieFileOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, unifyMovieFileOutputNapi);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("UnifyMovieFileOutputNapi::GetActiveProfile parse parameter occur error");
        return nullptr;
    }
    auto profile = unifyMovieFileOutputNapi->unifyMovieFileOutput_->GetVideoProfile();
    if (profile == nullptr) {
        return CameraNapiUtils::GetUndefinedValue(env);
    }
    return CameraNapiObjVideoProfile(*profile).GenerateNapiValue(env);
}

napi_value UnifyMovieFileOutputNapi::GetSupportedVideoFilters(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("UnifyMovieFileOutputNapi::GetSupportedVideoFilters is called");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi GetSupportedVideoFilters is called!");
        return nullptr;
    }
    napi_value result = CameraNapiUtils::GetUndefinedValue(env);
    UnifyMovieFileOutputNapi* unifyMovieFileOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, unifyMovieFileOutputNapi);
    if (!jsParamParser.AssertStatus(SERVICE_FATL_ERROR, "parse parameter occur error")) {
        MEDIA_ERR_LOG("UnifyMovieFileOutputNapi::GetSupportedVideoFilters parse parameter occur error");
        return result;
    }
    if (unifyMovieFileOutputNapi->unifyMovieFileOutput_ == nullptr) {
        MEDIA_ERR_LOG("UnifyMovieFileOutputNapi::GetSupportedVideoFilters get native object fail");
        CameraNapiUtils::ThrowError(env, SERVICE_FATL_ERROR, "get native object fail");
        return result;
    }
    std::vector<std::string> supportedVideoFilters;
    int32_t retCode = unifyMovieFileOutputNapi->unifyMovieFileOutput_->GetSupportedVideoFilters(supportedVideoFilters);
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        return nullptr;
    }
    napi_status status = napi_create_array(env, &result);
    CHECK_RETURN_RET_ELOG(status != napi_ok, result, "napi_create_array call Failed!");
    for (size_t i = 0; i < supportedVideoFilters.size(); i++) {
        std::string value = supportedVideoFilters[i];
        napi_value element;
        napi_create_string_utf8(env, value.c_str(), NAPI_AUTO_LENGTH, &element);
        napi_set_element(env, result, i, element);
    }
    return result;
}

napi_value UnifyMovieFileOutputNapi::AddVideoFilter(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("AddVideoFilter is called");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi AddVideoFilter is called!");
        return nullptr;
    }

    std::unique_ptr<UnifyMovieFileOutputAsyncContext> asyncContext = std::make_unique<UnifyMovieFileOutputAsyncContext>(
        "UnifyMovieFileOutputNapi::AddVideoFilter", CameraNapiUtils::IncrementAndGet(movieFileOutputTaskId));
    auto asyncFunction = std::make_shared<CameraNapiAsyncFunction>(
        env, "AddVideoFilter", asyncContext->callbackRef, asyncContext->deferred);
    CameraNapiParamParser jsParamParser(
        env, info, asyncContext->nativeNapiObj, asyncFunction, asyncContext->filter, asyncContext->filterParam);
    if (!jsParamParser.IsStatusOk()) {
        jsParamParser =
            CameraNapiParamParser(env, info, asyncContext->nativeNapiObj, asyncFunction, asyncContext->filter);
    }
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
        MEDIA_ERR_LOG("AddVideoFilter invalid argument");
        return nullptr;
    }
    asyncContext->HoldNapiValue(env, jsParamParser.GetThisVar());
    napi_status status = napi_create_async_work(env, nullptr, asyncFunction->GetResourceName(),
        [](napi_env env, void* data) {
            MEDIA_INFO_LOG("UnifyMovieFileOutputNapi::AddVideoFilter running on worker");
            auto context = static_cast<UnifyMovieFileOutputAsyncContext*>(data);
            CHECK_RETURN_ELOG(
                context->nativeNapiObj == nullptr, "UnifyMovieFileOutputNapi::AddVideoFilter async info is nullptr");
            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(context->queueTask, [&context]() {
                context->status = true;
                sptr<UnifyMovieFileOutput> movieFileOutput = context->nativeNapiObj->GetMovieFileOutput();
                context->errorCode = movieFileOutput->AddVideoFilter(context->filter, context->filterParam);
                context->status = context->errorCode == 0;
            });
        },
        AsyncCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for UnifyMovieFileOutputNapi::AddVideoFilter");
        asyncFunction->Reset();
    } else {
        asyncContext->queueTask = CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask(
            "UnifyMovieFileOutputNapi::AddVideoFilter");
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        (void)asyncContext.release();
    }
    if (asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE) {
        return asyncFunction->GetPromise();
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value UnifyMovieFileOutputNapi::RemoveVideoFilter(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("RemoveVideoFilter is called");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi RemoveVideoFilter is called!");
        return nullptr;
    }
    std::unique_ptr<UnifyMovieFileOutputAsyncContext> asyncContext = std::make_unique<UnifyMovieFileOutputAsyncContext>(
        "UnifyMovieFileOutputNapi::RemoveVideoFilter", CameraNapiUtils::IncrementAndGet(movieFileOutputTaskId));
    auto asyncFunction = std::make_shared<CameraNapiAsyncFunction>(
        env, "RemoveVideoFilter", asyncContext->callbackRef, asyncContext->deferred);
    CameraNapiParamParser jsParamParser(env, info, asyncContext->nativeNapiObj, asyncFunction, asyncContext->filter);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
        MEDIA_ERR_LOG("RemoveVideoFilter invalid argument");
        return nullptr;
    }
    asyncContext->HoldNapiValue(env, jsParamParser.GetThisVar());
    napi_status status = napi_create_async_work(
        env, nullptr, asyncFunction->GetResourceName(),
        [](napi_env env, void* data) {
            MEDIA_INFO_LOG("UnifyMovieFileOutputNapi::RemoveVideoFilter running on worker");
            auto context = static_cast<UnifyMovieFileOutputAsyncContext*>(data);
            CHECK_RETURN_ELOG(
                context->nativeNapiObj == nullptr, "UnifyMovieFileOutputNapi::RemoveVideoFilter async info is nullptr");
            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(context->queueTask, [&context]() {
                context->status = true;
                sptr<UnifyMovieFileOutput> movieFileOutput = context->nativeNapiObj->GetMovieFileOutput();
                context->errorCode = movieFileOutput->RemoveVideoFilter(context->filter);
                context->status = context->errorCode == 0;
            });
        },
        AsyncCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for UnifyMovieFileOutputNapi::RemoveVideoFilter");
        asyncFunction->Reset();
    } else {
        asyncContext->queueTask = CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask(
            "UnifyMovieFileOutputNapi::RemoveVideoFilter");
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        (void)asyncContext.release();
    }
    if (asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE) {
        return asyncFunction->GetPromise();
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value UnifyMovieFileOutputNapi::IsMirrorSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("UnifyMovieFileOutputNapi::IsMirrorSupported is called");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsMirrorSupported is called!");
        return nullptr;
    }
    napi_value result = CameraNapiUtils::GetUndefinedValue(env);
    UnifyMovieFileOutputNapi* unifyMovieFileOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, unifyMovieFileOutputNapi);
    if (!jsParamParser.AssertStatus(SERVICE_FATL_ERROR, "parse parameter occur error")) {
        MEDIA_ERR_LOG("UnifyMovieFileOutputNapi::IsMirrorSupported parse parameter occur error");
        return result;
    }
    if (unifyMovieFileOutputNapi->unifyMovieFileOutput_ == nullptr) {
        MEDIA_ERR_LOG("UnifyMovieFileOutputNapi::IsMirrorSupported get native object fail");
        CameraNapiUtils::ThrowError(env, SERVICE_FATL_ERROR, "get native object fail");
        return result;
    }
    bool isMirrorSupported = unifyMovieFileOutputNapi->unifyMovieFileOutput_->IsMirrorSupported();
    napi_get_boolean(env, isMirrorSupported, &result);
    return result;
}

napi_value UnifyMovieFileOutputNapi::EnableMirror(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("UnifyMovieFileOutputNapi::EnableMirror is called");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi EnableMirror is called!");
        return nullptr;
    }
    napi_value result = CameraNapiUtils::GetUndefinedValue(env);

    bool isEnable = false;
    UnifyMovieFileOutputNapi* unifyMovieFileOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, unifyMovieFileOutputNapi, isEnable);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("UnifyMovieFileOutputNapi::EnableMirror parse parameter occur error");
        return nullptr;
    }
    MEDIA_INFO_LOG("UnifyMovieFileOutputNapi::EnableMirror is %{public}d", isEnable);

    if (unifyMovieFileOutputNapi->unifyMovieFileOutput_ == nullptr) {
        MEDIA_ERR_LOG("UnifyMovieFileOutputNapi::EnableMirror get native object fail");
        CameraNapiUtils::ThrowError(env, SERVICE_FATL_ERROR, "get native object fail");
        return result;
    }
    int32_t retCode = unifyMovieFileOutputNapi->unifyMovieFileOutput_->EnableMirror(isEnable);
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        MEDIA_ERR_LOG("UnifyMovieFileOutputNapi::EnableMirror fail %{public}d", retCode);
        return nullptr;
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value UnifyMovieFileOutputNapi::Start(napi_env env, napi_callback_info info)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("UnifyMovieFileOutputNapi::Start is called");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi Start is called!");
        return nullptr;
    }
    std::unique_ptr<UnifyMovieFileOutputAsyncContext> asyncContext = std::make_unique<UnifyMovieFileOutputAsyncContext>(
        "UnifyMovieFileOutputNapi::Start", CameraNapiUtils::IncrementAndGet(movieFileOutputTaskId));
    auto asyncFunction = std::make_shared<CameraNapiAsyncFunction>(
        env, "UnifyMovieFileOutputNapi::Start", asyncContext->callbackRef, asyncContext->deferred);
    CameraNapiParamParser jsParamParser(env, info, asyncContext->nativeNapiObj, asyncFunction);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
        MEDIA_ERR_LOG("UnifyMovieFileOutputNapi::Start invalid argument");
        return nullptr;
    }
    asyncContext->HoldNapiValue(env, jsParamParser.GetThisVar());
    napi_status status = napi_create_async_work(
        env, nullptr, asyncFunction->GetResourceName(),
        [](napi_env env, void* data) {
            MEDIA_INFO_LOG("UnifyMovieFileOutputNapi::Start running on worker");
            UnifyMovieFileOutputAsyncContext* context = static_cast<UnifyMovieFileOutputAsyncContext*>(data);
            CHECK_RETURN_ELOG(
                context->nativeNapiObj == nullptr, "UnifyMovieFileOutputNapi::Start async info is nullptr");
            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(context->queueTask, [&context]() {
                context->status = true;
                sptr<UnifyMovieFileOutput> movieFileOutput = context->nativeNapiObj->GetMovieFileOutput();
                context->errorCode = movieFileOutput->Start();
                context->status = context->errorCode == 0;
            });
        },
        AsyncCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for UnifyMovieFileOutputNapi::Start");
        asyncFunction->Reset();
    } else {
        asyncContext->queueTask =
            CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("UnifyMovieFileOutputNapi::Start");
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        (void)asyncContext.release();
    }
    if (asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE) {
        return asyncFunction->GetPromise();
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value UnifyMovieFileOutputNapi::Pause(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("UnifyMovieFileOutputNapi::Pause is called");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi Pause is called!");
        return nullptr;
    }
    std::unique_ptr<UnifyMovieFileOutputAsyncContext> asyncContext = std::make_unique<UnifyMovieFileOutputAsyncContext>(
        "UnifyMovieFileOutputNapi::Pause", CameraNapiUtils::IncrementAndGet(movieFileOutputTaskId));
    auto asyncFunction = std::make_shared<CameraNapiAsyncFunction>(
        env, "UnifyMovieFileOutputNapi::Pause", asyncContext->callbackRef, asyncContext->deferred);
    CameraNapiParamParser jsParamParser(env, info, asyncContext->nativeNapiObj, asyncFunction);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
        MEDIA_ERR_LOG("UnifyMovieFileOutputNapi::Pause invalid argument");
        return nullptr;
    }
    asyncContext->HoldNapiValue(env, jsParamParser.GetThisVar());
    napi_status status = napi_create_async_work(
        env, nullptr, asyncFunction->GetResourceName(),
        [](napi_env env, void* data) {
            MEDIA_INFO_LOG("UnifyMovieFileOutputNapi::Pause running on worker");
            UnifyMovieFileOutputAsyncContext* context = static_cast<UnifyMovieFileOutputAsyncContext*>(data);
            CHECK_RETURN_ELOG(
                context->nativeNapiObj == nullptr, "UnifyMovieFileOutputNapi::Pause async info is nullptr");
            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(context->queueTask, [&context]() {
                context->status = true;
                sptr<UnifyMovieFileOutput> movieFileOutput = context->nativeNapiObj->GetMovieFileOutput();
                context->errorCode = movieFileOutput->Pause();
                context->status = context->errorCode == 0;
            });
        },
        AsyncCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for UnifyMovieFileOutputNapi::Pause");
        asyncFunction->Reset();
    } else {
        asyncContext->queueTask =
            CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("UnifyMovieFileOutputNapi::Pause");
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        (void)asyncContext.release();
    }
    if (asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE) {
        return asyncFunction->GetPromise();
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value UnifyMovieFileOutputNapi::Resume(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("UnifyMovieFileOutputNapi::Resume is called");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi Resume is called!");
        return nullptr;
    }
    std::unique_ptr<UnifyMovieFileOutputAsyncContext> asyncContext = std::make_unique<UnifyMovieFileOutputAsyncContext>(
        "UnifyMovieFileOutputNapi::Resume", CameraNapiUtils::IncrementAndGet(movieFileOutputTaskId));
    auto asyncFunction = std::make_shared<CameraNapiAsyncFunction>(
        env, "UnifyMovieFileOutputNapi::Resume", asyncContext->callbackRef, asyncContext->deferred);
    CameraNapiParamParser jsParamParser(env, info, asyncContext->nativeNapiObj, asyncFunction);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
        MEDIA_ERR_LOG("UnifyMovieFileOutputNapi::Resume invalid argument");
        return nullptr;
    }
    asyncContext->HoldNapiValue(env, jsParamParser.GetThisVar());
    napi_status status = napi_create_async_work(
        env, nullptr, asyncFunction->GetResourceName(),
        [](napi_env env, void* data) {
            MEDIA_INFO_LOG("UnifyMovieFileOutputNapi::Resume running on worker");
            UnifyMovieFileOutputAsyncContext* context = static_cast<UnifyMovieFileOutputAsyncContext*>(data);
            CHECK_RETURN_ELOG(
                context->nativeNapiObj == nullptr, "UnifyMovieFileOutputNapi::Resume async info is nullptr");
            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(context->queueTask, [&context]() {
                context->status = true;
                sptr<UnifyMovieFileOutput> movieFileOutput = context->nativeNapiObj->GetMovieFileOutput();
                context->errorCode = movieFileOutput->Resume();
                context->status = context->errorCode == 0;
            });
        },
        AsyncCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for UnifyMovieFileOutputNapi::Resume");
        asyncFunction->Reset();
    } else {
        asyncContext->queueTask =
            CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("UnifyMovieFileOutputNapi::Resume");
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        (void)asyncContext.release();
    }
    if (asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE) {
        return asyncFunction->GetPromise();
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value UnifyMovieFileOutputNapi::Stop(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("UnifyMovieFileOutputNapi::Stop is called");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi Stop is called!");
        return nullptr;
    }
    std::unique_ptr<UnifyMovieFileOutputAsyncContext> asyncContext = std::make_unique<UnifyMovieFileOutputAsyncContext>(
        "UnifyMovieFileOutputNapi::Stop", CameraNapiUtils::IncrementAndGet(movieFileOutputTaskId));
    auto asyncFunction = std::make_shared<CameraNapiAsyncFunction>(
        env, "UnifyMovieFileOutputNapi::Stop", asyncContext->callbackRef, asyncContext->deferred);
    CameraNapiParamParser jsParamParser(env, info, asyncContext->nativeNapiObj, asyncFunction);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
        MEDIA_ERR_LOG("UnifyMovieFileOutputNapi::Stop invalid argument");
        return nullptr;
    }
    asyncContext->HoldNapiValue(env, jsParamParser.GetThisVar());
    napi_status status = napi_create_async_work(
        env, nullptr, asyncFunction->GetResourceName(),
        [](napi_env env, void* data) {
            MEDIA_INFO_LOG("UnifyMovieFileOutputNapi::Stop running on worker");
            UnifyMovieFileOutputAsyncContext* context = static_cast<UnifyMovieFileOutputAsyncContext*>(data);
            CHECK_RETURN_ELOG(
                context->nativeNapiObj == nullptr, "UnifyMovieFileOutputNapi::Stop async info is nullptr");
            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(context->queueTask, [&context]() {
                context->status = true;
                sptr<UnifyMovieFileOutput> movieFileOutput = context->nativeNapiObj->GetMovieFileOutput();
                context->errorCode = movieFileOutput->Stop();
                context->status = context->errorCode == 0;
            });
        },
        AsyncCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for UnifyMovieFileOutputNapi::Stop");
        asyncFunction->Reset();
    } else {
        asyncContext->queueTask =
            CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("UnifyMovieFileOutputNapi::Stop");
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        (void)asyncContext.release();
    }
    if (asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE) {
        return asyncFunction->GetPromise();
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value UnifyMovieFileOutputNapi::Release(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("UnifyMovieFileOutputNapi::Release is called");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi Release is called!");
        return nullptr;
    }
    std::unique_ptr<UnifyMovieFileOutputAsyncContext> asyncContext = std::make_unique<UnifyMovieFileOutputAsyncContext>(
        "UnifyMovieFileOutputNapi::Release", CameraNapiUtils::IncrementAndGet(movieFileOutputTaskId));
    auto asyncFunction =
        std::make_shared<CameraNapiAsyncFunction>(env, "Release", asyncContext->callbackRef, asyncContext->deferred);
    CameraNapiParamParser jsParamParser(env, info, asyncContext->nativeNapiObj, asyncFunction);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
        MEDIA_ERR_LOG("UnifyMovieFileOutputNapi::Release invalid argument");
        return nullptr;
    }
    asyncContext->HoldNapiValue(env, jsParamParser.GetThisVar());
    napi_status status = napi_create_async_work(
        env, nullptr, asyncFunction->GetResourceName(),
        [](napi_env env, void* data) {
            MEDIA_INFO_LOG("UnifyMovieFileOutputNapi::Release running on worker");
            auto context = static_cast<UnifyMovieFileOutputAsyncContext*>(data);
            CHECK_RETURN_ELOG(
                context->nativeNapiObj == nullptr, "UnifyMovieFileOutputNapi::Release async info is nullptr");
            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(context->queueTask, [&context]() {
                context->errorCode = context->nativeNapiObj->unifyMovieFileOutput_->Release();
                context->status = context->errorCode == CameraErrorCode::SUCCESS;
            });
        },
        AsyncCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for UnifyMovieFileOutputNapi::Release");
        asyncFunction->Reset();
    } else {
        asyncContext->queueTask =
            CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("UnifyMovieFileOutputNapi::Release");
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        (void)asyncContext.release();
    }
    if (asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE) {
        return asyncFunction->GetPromise();
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value UnifyMovieFileOutputNapi::IsAutoDeferredVideoEnhancementSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("UnifyMovieFileOutputNapi::IsAutoDeferredVideoEnhancementSupported is called");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsAutoDeferredVideoEnhancementSupported is called!");
        return nullptr;
    }
    napi_value result = CameraNapiUtils::GetUndefinedValue(env);
    UnifyMovieFileOutputNapi* unifyMovieFileOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, unifyMovieFileOutputNapi);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("UnifyMovieFileOutputNapi::IsAutoDeferredVideoEnhancementSupported parse parameter occur error");
        return result;
    }
    bool isSupported = false;
    int32_t res = unifyMovieFileOutputNapi->unifyMovieFileOutput_->IsAutoDeferredVideoEnhancementSupported(isSupported);

    if (!CameraNapiUtils::CheckError(env, res)) {
        MEDIA_ERR_LOG("UnifyMovieFileOutputNapi::IsAutoDeferredVideoEnhancementSupported error");
        return result;
    }
    napi_get_boolean(env, isSupported, &result);
    return result;
}

napi_value UnifyMovieFileOutputNapi::IsAutoDeferredVideoEnhancementEnabled(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("UnifyMovieFileOutputNapi::IsAutoDeferredVideoEnhancementEnabled is called");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsAutoDeferredVideoEnhancementEnabled is called!");
        return nullptr;
    }
    napi_value result = CameraNapiUtils::GetUndefinedValue(env);
    UnifyMovieFileOutputNapi* unifyMovieFileOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, unifyMovieFileOutputNapi);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("UnifyMovieFileOutputNapi::IsAutoDeferredVideoEnhancementEnabled parse parameter occur error");
        return result;
    }

    bool isEnabled = false;
    int32_t res = unifyMovieFileOutputNapi->unifyMovieFileOutput_->IsAutoDeferredVideoEnhancementEnabled(isEnabled);
    if (!CameraNapiUtils::CheckError(env, res)) {
        MEDIA_ERR_LOG("UnifyMovieFileOutputNapi::IsAutoDeferredVideoEnhancementEnabled error");
        return result;
    }
    napi_get_boolean(env, isEnabled, &result);
    return result;
}

napi_value UnifyMovieFileOutputNapi::EnableAutoDeferredVideoEnhancement(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("UnifyMovieFileOutputNapi::EnableAutoDeferredVideoEnhancement is called");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi EnableAutoDeferredVideoEnhancement is called!");
        return nullptr;
    }
    napi_value result = CameraNapiUtils::GetUndefinedValue(env);
    bool isEnable = false;
    UnifyMovieFileOutputNapi* unifyMovieFileOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, unifyMovieFileOutputNapi, isEnable);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("UnifyMovieFileOutputNapi::EnableAutoDeferredVideoEnhancement parse parameter occur error");
        return result;
    }
    int32_t res = unifyMovieFileOutputNapi->unifyMovieFileOutput_->EnableAutoDeferredVideoEnhancement(isEnable);
    if (!CameraNapiUtils::CheckError(env, res)) {
        MEDIA_ERR_LOG("UnifyMovieFileOutputNapi::EnableAutoDeferredVideoEnhancement error");
    }
    return result;
}

napi_value UnifyMovieFileOutputNapi::IsAutoVideoFrameRateSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("UnifyMovieFileOutputNapi::IsAutoVideoFrameRateSupported is called");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsAutoVideoFrameRateSupported is called!");
        return nullptr;
    }
    auto result = CameraNapiUtils::GetUndefinedValue(env);

    UnifyMovieFileOutputNapi* unifyMovieFileOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, unifyMovieFileOutputNapi);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("UnifyMovieFileOutputNapi::IsAutoVideoFrameRateSupported parse parameter occur error");
        return result;
    }
    bool isAutoVideoFrameRateSupported =
        unifyMovieFileOutputNapi->unifyMovieFileOutput_->IsAutoVideoFrameRateSupported();
    if (isAutoVideoFrameRateSupported) {
        napi_get_boolean(env, true, &result);
        return result;
    }
    MEDIA_ERR_LOG("UnifyMovieFileOutputNapi::IsAutoVideoFrameRateSupported is not supported");
    napi_get_boolean(env, false, &result);
    return result;
}

napi_value UnifyMovieFileOutputNapi::EnableAutoVideoFrameRate(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("UnifyMovieFileOutputNapi::EnableAutoVideoFrameRate is called");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi EnableAutoVideoFrameRate is called!");
        return nullptr;
    }
    auto result = CameraNapiUtils::GetUndefinedValue(env);
    UnifyMovieFileOutputNapi* unifyMovieFileOutputNapi = nullptr;
    bool isEnable = false;
    CameraNapiParamParser jsParamParser(env, info, unifyMovieFileOutputNapi, isEnable);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("UnifyMovieFileOutputNapi::EnableAutoVideoFrameRate parse parameter occur error");
        return result;
    }
    int32_t retCode = unifyMovieFileOutputNapi->unifyMovieFileOutput_->EnableAutoVideoFrameRate(isEnable);
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        MEDIA_ERR_LOG("UnifyMovieFileOutputNapi::EnableAutoVideoFrameRate fail %{public}d", retCode);
    }
    return result;
}

napi_value UnifyMovieFileOutputNapi::GetVideoRotation(napi_env env, napi_callback_info info)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("UnifyMovieFileOutputNapi::GetVideoRotation is called!");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi GetVideoRotation is called!");
        return nullptr;
    }
    UnifyMovieFileOutputNapi* unifyMovieFileOutputNapi = nullptr;
    int32_t deviceDegree = 0;
    CameraNapiParamParser jsParamParser(env, info, unifyMovieFileOutputNapi, deviceDegree);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("UnifyMovieFileOutputNapi::GetVideoRotation parse parameter occur error");
        return nullptr;
    }

    int32_t imageRotation = deviceDegree;
    int32_t retCode = unifyMovieFileOutputNapi->unifyMovieFileOutput_->GetVideoRotation(imageRotation);
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        MEDIA_ERR_LOG("UnifyMovieFileOutputNapi::EnableAutoVideoFrameRate fail %{public}d", retCode);
        return nullptr;
    }
    MEDIA_INFO_LOG("UnifyMovieFileOutputNapi GetVideoRotation! %{public}d", imageRotation);
    napi_value result;
    napi_create_int32(env, imageRotation, &result);
    return result;
}

napi_value UnifyMovieFileOutputNapi::GetSupportedVideoCapability(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("GetSupportedVideoCapability is called");
    int32_t videoCodecType = 0;
    UnifyMovieFileOutputNapi* movieFileOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, movieFileOutputNapi, videoCodecType);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("MovieFileOutputNapi::GetSupportedVideoCapability parse parameter occur error");
        return nullptr;
    }
    auto videoCapability = movieFileOutputNapi->unifyMovieFileOutput_->GetSupportedVideoCapability(videoCodecType);
    if (videoCapability == nullptr) {
        return CameraNapiUtils::GetUndefinedValue(env);
    }
    return VideoCapabilityNapi::CreateVideoCapability(env, videoCapability);
}

napi_value UnifyMovieFileOutputNapi::On(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<UnifyMovieFileOutputNapi>::On(env, info);
}

napi_value UnifyMovieFileOutputNapi::Off(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<UnifyMovieFileOutputNapi>::Off(env, info);
}

UnifyMovieFileOutputAsyncContext::UnifyMovieFileOutputAsyncContext(std::string funcName, int32_t taskId)
    : AsyncContext(funcName, taskId)
{}

} // namespace CameraStandard
} // namespace OHOS