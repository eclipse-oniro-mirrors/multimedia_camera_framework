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
#include "output/movie_file_output_napi.h"

#include "camera_log.h"
#include "camera_manager.h"
#include "camera_napi_object_types.h"
#include "camera_napi_security_utils.h"
#include "camera_napi_template_utils.h"
#include "camera_napi_worker_queue_keeper.h"
#include "media_library_comm_napi.h"
#include "movie_file_output.h"
#include "napi/native_common.h"
#include "output/video_capability_napi.h"
#include "uv.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace CameraStandard {

thread_local sptr<MovieFileOutput> MovieFileOutputNapi::sMovieFileOutput_ = nullptr;
thread_local napi_ref MovieFileOutputNapi::constructor_ = nullptr;
thread_local uint32_t MovieFileOutputNapi::movieFileOutputTaskId = CAMERA_MOVIE_FILE_OUTPUT_TASKID;

void MovieFileOutputNapi::Init(napi_env env)
{
    MEDIA_DEBUG_LOG("MovieFileOutputNapi::Init is called");
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
        DECLARE_NAPI_FUNCTION("getSupportedVideoCapability", GetSupportedVideoCapability),
        DECLARE_NAPI_FUNCTION("getSupportedVideoCodecTypes", GetSupportedVideoCodecTypes),
        DECLARE_NAPI_FUNCTION("getSupportedVideoFilters", GetSupportedVideoFilters),
        DECLARE_NAPI_FUNCTION("setVideoFilter", SetVideoFilter),
        DECLARE_NAPI_FUNCTION("isMirrorSupported", IsMirrorSupported),
        DECLARE_NAPI_FUNCTION("enableMirror", EnableMirror),
        DECLARE_NAPI_FUNCTION("setRotation", SetRotation),
        DECLARE_NAPI_FUNCTION("release", Release),
        DECLARE_NAPI_FUNCTION("on", On),
        DECLARE_NAPI_FUNCTION("off", Off)
    };

    status = napi_define_class(env, CAMERA_MOVIE_FILE_OUTPUT_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
        MovieFileOutputNapiConstructor, nullptr,
        sizeof(movie_file_output_props) / sizeof(movie_file_output_props[PARAM0]),
        movie_file_output_props, &constructor);
    CHECK_RETURN_ELOG(status != napi_ok, "MovieFileOutputNapi defined class failed");
    // create a strong ref to prevent the constructor be garbage-collected
    status = NapiRefManager::CreateMemSafetyRef(env, constructor, &constructor_);
    CHECK_RETURN_ELOG(status != napi_ok, "MovieFileOutputNapi Init failed");
    MEDIA_DEBUG_LOG("MovieFileOutputNapi Init success");
}

MovieFileOutputCallbackListener::MovieFileOutputCallbackListener(napi_env env) : ListenerBase(env)
{
}

void MovieFileOutputCallbackListener::OnRecordingStart() const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("OnRecordingStart is called");
    MovieFileCallbackInfo info;
    UpdateJSCallbackAsync(MovieFileOutputEventType::RECORDING_START, info);
}

void MovieFileOutputCallbackListener::OnRecordingPause() const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("OnRecordingPause is called");
    MovieFileCallbackInfo info;
    UpdateJSCallbackAsync(MovieFileOutputEventType::RECORDING_PAUSE, info);
}

void MovieFileOutputCallbackListener::OnRecordingResume() const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("OnRecordingResume is called");
    MovieFileCallbackInfo info;
    UpdateJSCallbackAsync(MovieFileOutputEventType::RECORDING_RESUME, info);
}

void MovieFileOutputCallbackListener::OnRecordingStop() const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("OnRecordingStop is called");
    MovieFileCallbackInfo info;
    UpdateJSCallbackAsync(MovieFileOutputEventType::RECORDING_STOP, info);
}

void MovieFileOutputCallbackListener::OnPhotoAssetAvailable(const std::string& uri) const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("MovieFileOutputCallbackListener::OnPhotoAssetAvailable is called");
    MovieFileCallbackInfo info;
    info.uri = uri;
    UpdateJSCallbackAsync(MovieFileOutputEventType::PHOTO_ASSET_AVAILABLE, info);
}

void MovieFileOutputCallbackListener::OnError(const int32_t errorCode) const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("OnError is called");
    MovieFileCallbackInfo info;
    info.errorCode = errorCode;
    UpdateJSCallbackAsync(MovieFileOutputEventType::ERROR, info);
}

void MovieFileOutputCallbackListener::UpdateJSCallbackAsync(
    MovieFileOutputEventType eventType, const MovieFileCallbackInfo& info) const
{
    MEDIA_DEBUG_LOG("MovieFileOutputCallbackListener::UpdateJSCallbackAsync is called");
    std::unique_ptr<MovieFileOutputCallbackInfo> callbackInfo =
        std::make_unique<MovieFileOutputCallbackInfo>(eventType, info, shared_from_this());
    MovieFileOutputCallbackInfo *event = callbackInfo.get();
    auto task = [event]() {
        MovieFileOutputCallbackInfo* callbackInfo = reinterpret_cast<MovieFileOutputCallbackInfo *>(event);
        if (callbackInfo) {
            auto listener = callbackInfo->listener_.lock();
            if (listener) {
                listener->UpdateJSCallback(callbackInfo->eventType_, callbackInfo->info_);
            }
            delete callbackInfo;
        }
    };
    std::unordered_map<std::string, std::string> params = {
        {"eventType", MovieFileOutputEventTypeHelper.GetKeyString(eventType)},
    };
    std::string taskName =
        CameraNapiUtils::GetTaskName("MovieFileOutputCallbackListener::UpdateJSCallbackAsync", params);
    if (napi_ok != napi_send_event(env_, task, napi_eprio_immediate, taskName.c_str())) {
        MEDIA_ERR_LOG("failed to execute work");
    } else {
        (void)callbackInfo.release();
    }
}

void MovieFileOutputCallbackListener::UpdateJSCallback(
    MovieFileOutputEventType eventType, const MovieFileCallbackInfo& info) const
{
    MEDIA_DEBUG_LOG("UpdateJSCallback is called");
    switch (eventType) {
        case MovieFileOutputEventType::RECORDING_START:
            ExecuteRecordingStartCb(info);
            break;
        case MovieFileOutputEventType::RECORDING_PAUSE:
            ExecuteRecordingPauseCb(info);
            break;
        case MovieFileOutputEventType::RECORDING_RESUME:
            ExecuteRecordingResumeCb(info);
            break;
        case MovieFileOutputEventType::RECORDING_STOP:
            ExecuteRecordingStopCb(info);
            break;
        case MovieFileOutputEventType::PHOTO_ASSET_AVAILABLE:
            ExecutePhotoAssetAvailableCb(info);
            break;
        case MovieFileOutputEventType::ERROR:
            ExecuteErrorCb(info);
            break;
        default:
            MEDIA_ERR_LOG("Incorrect movie file callback event type received from JS");
    }
}

void MovieFileOutputCallbackListener::ExecuteRecordingStartCb(const MovieFileCallbackInfo& info) const
{
    ExecuteCallbackScopeSafe(CONST_MOVIE_FILE_RECORDING_START, [&]() {
        napi_value errCode = CameraNapiUtils::GetUndefinedValue(env_);
        napi_value callbackObj;
        MovieFileCallbackInfo callbackInfo = info;
        CameraNapiObject movieFileObj ({});
        callbackObj = movieFileObj.CreateNapiObjFromMap(env_);
        return ExecuteCallbackData(env_, errCode, callbackObj);
    });
}

void MovieFileOutputCallbackListener::ExecuteRecordingPauseCb(const MovieFileCallbackInfo& info) const
{
    ExecuteCallbackScopeSafe(CONST_MOVIE_FILE_RECORDING_PAUSE, [&]() {
        napi_value errCode = CameraNapiUtils::GetUndefinedValue(env_);
        napi_value callbackObj;
        MovieFileCallbackInfo callbackInfo = info;
        CameraNapiObject movieFileObj ({});
        callbackObj = movieFileObj.CreateNapiObjFromMap(env_);
        return ExecuteCallbackData(env_, errCode, callbackObj);
    });
}

void MovieFileOutputCallbackListener::ExecuteRecordingResumeCb(const MovieFileCallbackInfo& info) const
{
    ExecuteCallbackScopeSafe(CONST_MOVIE_FILE_RECORDING_RESUME, [&]() {
        napi_value errCode = CameraNapiUtils::GetUndefinedValue(env_);
        napi_value callbackObj;
        MovieFileCallbackInfo callbackInfo = info;
        CameraNapiObject movieFileObj ({});
        callbackObj = movieFileObj.CreateNapiObjFromMap(env_);
        return ExecuteCallbackData(env_, errCode, callbackObj);
    });
}

void MovieFileOutputCallbackListener::ExecuteRecordingStopCb(const MovieFileCallbackInfo& info) const
{
    ExecuteCallbackScopeSafe(CONST_MOVIE_FILE_RECORDING_STOP, [&]() {
        napi_value errCode = CameraNapiUtils::GetUndefinedValue(env_);
        napi_value callbackObj;
        MovieFileCallbackInfo callbackInfo = info;
        CameraNapiObject movieFileObj ({});
        callbackObj = movieFileObj.CreateNapiObjFromMap(env_);
        return ExecuteCallbackData(env_, errCode, callbackObj);
    });
}

void MovieFileOutputCallbackListener::ExecutePhotoAssetAvailableCb(const MovieFileCallbackInfo& info) const
{
    ExecuteCallbackScopeSafe("photoAssetAvailable", [&]() {
        napi_value errCode = CameraNapiUtils::GetUndefinedValue(env_);
        napi_value callbackObj;
        constexpr int32_t videoShotType = 1;
        callbackObj = Media::MediaLibraryCommNapi::CreatePhotoAssetNapi(
            env_,
            info.uri,
            videoShotType
        );
        return ExecuteCallbackData(env_, errCode, callbackObj);
    });
}

void MovieFileOutputCallbackListener::ExecuteErrorCb(const MovieFileCallbackInfo& info) const
{
    MEDIA_DEBUG_LOG("OnErrorCallback is called");
    int32_t nonConstValue = info.errorCode;
    ExecuteCallbackScopeSafe(CONST_MOVIE_FILE_RECORDING_ERROR, [&]() {
        napi_value errCode = CameraNapiUtils::GetUndefinedValue(env_);
        napi_value callbackObj = CameraNapiUtils::GetUndefinedValue(env_);
        CameraNapiObject errObj { { { "code", &nonConstValue } } };
        errCode = errObj.CreateNapiObjFromMap(env_);
        return ExecuteCallbackData(env_, errCode, callbackObj);
    });
}

MovieFileOutputNapi::MovieFileOutputNapi()
    : wrapper_(nullptr)
    , env_(nullptr)
{
    MEDIA_DEBUG_LOG("MovieFileOutputNapi::MovieFileOutputNapi() is called");
}

napi_value MovieFileOutputNapi::MovieFileOutputNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("MovieFileOutputNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<MovieFileOutputNapi> obj = std::make_unique<MovieFileOutputNapi>();
        if (obj != nullptr) {
            obj->env_ = env;
            obj->movieFileOutput_ = sMovieFileOutput_;

            status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                               MovieFileOutputNapi::MovieFileOutputNapiDestructor, nullptr, nullptr);
            if (status == napi_ok) {
                (void)obj.release();
                return thisVar;
            } else {
                MEDIA_ERR_LOG("MovieFileOutputNapiConstructor failed wrapping js to native napi");
            }
        }
    }
    MEDIA_ERR_LOG("MovieFileOutputNapiConstructor call Failed!");
    return result;
}

void MovieFileOutputNapi::MovieFileOutputNapiDestructor(
    napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("MovieFileOutputNapiDestructor is called");
    MovieFileOutputNapi* cameraObj = reinterpret_cast<MovieFileOutputNapi*>(nativeObject);
    if (cameraObj != nullptr) {
        delete cameraObj;
    }
}

napi_value MovieFileOutputNapi::CreateMovieFileOutput(napi_env env)
{
    MEDIA_DEBUG_LOG("MovieFileOutputNapi::CreateMovieFileOutput without config start");
    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

napi_value MovieFileOutputNapi::CreateMovieFileOutput(napi_env env, VideoProfile& videoProfile)
{
    MEDIA_DEBUG_LOG("CreateMovieFileOutput is called");
    napi_status status;
    napi_value result;
    napi_value constructor;

    napi_get_undefined(env, &result);
    if (constructor_ == nullptr) {
        MovieFileOutputNapi::Init(env);
        CHECK_RETURN_RET_ELOG(constructor_ == nullptr, result, "constructor_ is null");
    }
    status = napi_get_reference_value(env, constructor_, &constructor);
    if (status == napi_ok) {
        int retCode = CameraManager::GetInstance()->CreateMovieFileOutput(videoProfile, &sMovieFileOutput_);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        if (sMovieFileOutput_ == nullptr) {
            MEDIA_ERR_LOG("failed to create MovieFileOutput");
            return result;
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sMovieFileOutput_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create movie file output instance");
        }
    }
    MEDIA_ERR_LOG("CreateMovieFileOutput call Failed!");
    return result;
}

bool MovieFileOutputNapi::IsMovieFileOutput(napi_env env, napi_value obj)
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

sptr<MovieFileOutput> MovieFileOutputNapi::GetMovieFileOutput()
{
    return movieFileOutput_;
}

const MovieFileOutputNapi::EmitterFunctions& MovieFileOutputNapi::GetEmitterFunctions()
{
    static const EmitterFunctions funMap = {
        { CONST_MOVIE_FILE_RECORDING_START, {
            &MovieFileOutputNapi::RegisterRecordingStartCallbackListener,
            &MovieFileOutputNapi::UnregisterRecordingStartCallbackListener } },
        { CONST_MOVIE_FILE_RECORDING_PAUSE, {
            &MovieFileOutputNapi::RegisterRecordingPauseCallbackListener,
            &MovieFileOutputNapi::UnregisterRecordingPauseCallbackListener } },
        { CONST_MOVIE_FILE_RECORDING_RESUME, {
            &MovieFileOutputNapi::RegisterRecordingResumeCallbackListener,
            &MovieFileOutputNapi::UnregisterRecordingResumeCallbackListener } },
        { CONST_MOVIE_FILE_RECORDING_STOP, {
            &MovieFileOutputNapi::RegisterRecordingStopCallbackListener,
            &MovieFileOutputNapi::UnregisterRecordingStopCallbackListener } },
        { CONST_MOVIE_FILE_PHOTO_ASSET_AVAILABLE, {
            &MovieFileOutputNapi::RegisterPhotoAssetAvailableCallbackListener,
            &MovieFileOutputNapi::UnregisterPhotoAssetAvailableCallbackListener } },
        { CONST_MOVIE_FILE_RECORDING_ERROR, {
            &MovieFileOutputNapi::RegisterErrorCallbackListener,
            &MovieFileOutputNapi::UnregisterErrorCallbackListener } } };
    return funMap;
}

void MovieFileOutputNapi::RegisterRecordingStartCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback,
    const std::vector<napi_value>& args, bool isOnce)
{
    if (movieFileOutputCallback_ == nullptr) {
        movieFileOutputCallback_ = make_shared<MovieFileOutputCallbackListener>(env);
        movieFileOutput_->SetCallback(movieFileOutputCallback_);
    }
    movieFileOutputCallback_->SaveCallbackReference(CONST_MOVIE_FILE_RECORDING_START, callback, isOnce);
}

void MovieFileOutputNapi::UnregisterRecordingStartCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (movieFileOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("movieFileOutputCallback is null");
        return;
    }
    movieFileOutputCallback_->RemoveCallbackRef(CONST_MOVIE_FILE_RECORDING_START, callback);
}

void MovieFileOutputNapi::RegisterRecordingPauseCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback,
    const std::vector<napi_value>& args, bool isOnce)
{
    if (movieFileOutputCallback_ == nullptr) {
        movieFileOutputCallback_ = make_shared<MovieFileOutputCallbackListener>(env);
        movieFileOutput_->SetCallback(movieFileOutputCallback_);
    }
    movieFileOutputCallback_->SaveCallbackReference(CONST_MOVIE_FILE_RECORDING_PAUSE, callback, isOnce);
}

void MovieFileOutputNapi::UnregisterRecordingPauseCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (movieFileOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("movieFileOutputCallback is null");
        return;
    }
    movieFileOutputCallback_->RemoveCallbackRef(CONST_MOVIE_FILE_RECORDING_PAUSE, callback);
}

void MovieFileOutputNapi::RegisterRecordingResumeCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback,
    const std::vector<napi_value>& args, bool isOnce)
{
    if (movieFileOutputCallback_ == nullptr) {
        movieFileOutputCallback_ = make_shared<MovieFileOutputCallbackListener>(env);
        movieFileOutput_->SetCallback(movieFileOutputCallback_);
    }
    movieFileOutputCallback_->SaveCallbackReference(CONST_MOVIE_FILE_RECORDING_RESUME, callback, isOnce);
}

void MovieFileOutputNapi::UnregisterRecordingResumeCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (movieFileOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("movieFileOutputCallback is null");
        return;
    }
    movieFileOutputCallback_->RemoveCallbackRef(CONST_MOVIE_FILE_RECORDING_RESUME, callback);
}

void MovieFileOutputNapi::RegisterRecordingStopCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback,
    const std::vector<napi_value>& args, bool isOnce)
{
    if (movieFileOutputCallback_ == nullptr) {
        movieFileOutputCallback_ = make_shared<MovieFileOutputCallbackListener>(env);
        movieFileOutput_->SetCallback(movieFileOutputCallback_);
    }
    movieFileOutputCallback_->SaveCallbackReference(CONST_MOVIE_FILE_RECORDING_STOP, callback, isOnce);
}

void MovieFileOutputNapi::UnregisterRecordingStopCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (movieFileOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("movieFileOutputCallback is null");
        return;
    }
    movieFileOutputCallback_->RemoveCallbackRef(CONST_MOVIE_FILE_RECORDING_STOP, callback);
}

void MovieFileOutputNapi::RegisterPhotoAssetAvailableCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback,
    const std::vector<napi_value>& args, bool isOnce)
{
    MEDIA_INFO_LOG("RegisterPhotoAssetAvailableCallbackListener is called");
    if (movieFileOutputCallback_ == nullptr) {
        movieFileOutputCallback_ = make_shared<MovieFileOutputCallbackListener>(env);
        movieFileOutput_->SetCallback(movieFileOutputCallback_);
    }
    movieFileOutputCallback_->SaveCallbackReference(CONST_MOVIE_FILE_PHOTO_ASSET_AVAILABLE, callback, isOnce);
}

void MovieFileOutputNapi::UnregisterPhotoAssetAvailableCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    MEDIA_INFO_LOG("UnRegisterPhotoAssetAvailableCallbackListener is called");
    if (movieFileOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("movieFileOutputCallback is null");
        return;
    }
    movieFileOutputCallback_->RemoveCallbackRef(CONST_MOVIE_FILE_PHOTO_ASSET_AVAILABLE, callback);
}

void MovieFileOutputNapi::RegisterErrorCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
    const std::vector<napi_value>& args, bool isOnce)
{
    if (movieFileOutputCallback_ == nullptr) {
        movieFileOutputCallback_ = make_shared<MovieFileOutputCallbackListener>(env);
        movieFileOutput_->SetCallback(movieFileOutputCallback_);
    }
    movieFileOutputCallback_->SaveCallbackReference(CONST_MOVIE_FILE_RECORDING_ERROR, callback, isOnce);
}

void MovieFileOutputNapi::UnregisterErrorCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (movieFileOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("movieFileOutputCallback is null");
        return;
    }
    movieFileOutputCallback_->RemoveCallbackRef(CONST_MOVIE_FILE_RECORDING_ERROR, callback);
}

namespace {
void AsyncCompleteCallback(napi_env env, napi_status status, void* data)
{
    auto context = static_cast<MovieFileOutputAsyncContext*>(data);
    CHECK_RETURN_ELOG(context == nullptr, "MovieFileOutputNapi AsyncCompleteCallback context is null");
    MEDIA_INFO_LOG("MovieFileOutputNapi AsyncCompleteCallback %{public}s, status = %{public}d",
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
        jsContext->funcName = context->funcName;
    }
    if (context->work != nullptr) {
        CameraNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef, context->work, *jsContext);
    }
    context->FreeHeldNapiValue(env);
    delete context;
}
} // namespace anonymous

bool MovieFileOutputNapi::ParseOutputSettings(napi_env env, napi_callback_info info,
    MovieFileOutputAsyncContext* asyncContext, std::shared_ptr<CameraNapiAsyncFunction>& asyncFunction)
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
        { "codecType",  &asyncContext->videoCodecType },
        { "location", &settingsLocationNapiOjbect },
        { "isBFrameEnabled", &settingsBFrameEnabled },
        { "videoBitrate", &videoBitrate },

    } };

    unordered_set<std::string> optionalKeys = { "location", "isBFrameEnabled", "videoBitrate"};
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
            MEDIA_INFO_LOG("ParseOutputSettings->videoBitrate has_value: bitrate:%{public}d,%{public}d",
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

napi_value MovieFileOutputNapi::SetOutputSettings(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("SetOutputSettings is called");
    std::unique_ptr<MovieFileOutputAsyncContext> asyncContext = std::make_unique<MovieFileOutputAsyncContext>(
        "MovieFileOutputNapi::SetOutputSettings", CameraNapiUtils::IncrementAndGet(movieFileOutputTaskId));
    std::shared_ptr<CameraNapiAsyncFunction> asyncFunction;
    if (!ParseOutputSettings(env, info, asyncContext.get(), asyncFunction)) {
        MEDIA_ERR_LOG("MovieFileOutputNapi::SetOutputSettings parse parameters fail.");
        return nullptr;
    }
    napi_status status = napi_create_async_work(
        env, nullptr, asyncFunction->GetResourceName(),
        [](napi_env env, void* data) {
            MEDIA_INFO_LOG("MovieFileOutputNapi::SetOutputSettings running on worker");
            auto context = static_cast<MovieFileOutputAsyncContext*>(data);
            CHECK_RETURN_ELOG(
                context->nativeNapiObj == nullptr, "MovieFileOutputNapi::SetOutputSettings async info is nullptr");
            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(
                context->queueTask, [&context]() {
                    context->status = true;
                    sptr<MovieFileOutput> movieFileOutput = context->nativeNapiObj->GetMovieFileOutput();
                    std::shared_ptr<MovieSettings> movieSettings = make_shared<MovieSettings>(MovieSettings {
                        .videoCodecType = VideoCodecType::VIDEO_ENCODE_TYPE_AVC,
                        .rotation = 0,
                        .isHasLocation = false,
                        .location = Location {0, 0, 0},
                        .isBFrameEnabled = false,
                        .videoBitrate = 30000000,
                    });
                    movieSettings->videoCodecType = static_cast<VideoCodecType>(context->videoCodecType);
                    if (context->location.has_value()) {
                        movieSettings->isHasLocation = true;
                        movieSettings->location = context->location.value();
                    }
                    if (context->isBFrameEnabled.has_value()) {
                        movieSettings->isBFrameEnabled = context->isBFrameEnabled.value();
                    }
                    if (context->videoBitrate.has_value()) {
                        movieSettings->videoBitrate = context->videoBitrate.value();
                        MEDIA_INFO_LOG("movieSettings->videoBitrate has_value: bitrate:%{public}d,%{public}d",
                            context->videoBitrate.value(), movieSettings->videoBitrate);
                    } else {
                        MEDIA_INFO_LOG("movieSettings->videoBitrate not has_value");
                    }
                    context->errorCode = movieFileOutput->SetOutputSettings(movieSettings);
                    context->status = context->errorCode == 0;
                });
        },
        AsyncCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for MovieFileOutputNapi::SetOutputSettings");
        asyncFunction->Reset();
    } else {
        asyncContext->queueTask = CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask(
            "MovieFileOutputNapi::SetOutputSettings");
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        (void)asyncContext.release();
    }
    if (asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE) {
        return asyncFunction->GetPromise();
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value MovieFileOutputNapi::GetOutputSettings(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("GetOutputSettings is called");

    MEDIA_DEBUG_LOG("MovieFileOutputNapi::GetOutputSettings is called");
    MovieFileOutputNapi* movieFileOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, movieFileOutputNapi);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("MovieFileOutputNapi::GetOutputSettings parse parameter occur error");
        return nullptr;
    }
    auto settings = movieFileOutputNapi->movieFileOutput_->GetOutputSettings();
    if (settings == nullptr) {
        return CameraNapiUtils::GetUndefinedValue(env);
    }
    return CameraNapiObjOutputSettings(*settings).GenerateNapiValue(env);
}

napi_value MovieFileOutputNapi::GetSupportedVideoCodecTypes(napi_env env, napi_callback_info info)
{
    napi_value result = CameraNapiUtils::GetUndefinedValue(env);
    MEDIA_DEBUG_LOG("MovieFileOutputNapi::GetSupportedVideoCodecTypes is called");
    MovieFileOutputNapi* movieFileOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, movieFileOutputNapi);
    if (!jsParamParser.AssertStatus(SERVICE_FATL_ERROR, "parse parameter occur error")) {
        MEDIA_ERR_LOG("MovieFileOutputNapi::GetSupportedVideoCodecTypes parse parameter occur error");
        return result;
    }
    if (movieFileOutputNapi->movieFileOutput_ == nullptr) {
        MEDIA_ERR_LOG("MovieFileOutputNapi::GetSupportedVideoCodecTypes get native object fail");
        CameraNapiUtils::ThrowError(env, SERVICE_FATL_ERROR, "get native object fail");
        return result;
    }
    std::vector<int32_t> supportedVideoCodecTypes;
    int32_t retCode = movieFileOutputNapi->movieFileOutput_->GetSupportedVideoCodecTypes(supportedVideoCodecTypes);
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

napi_value MovieFileOutputNapi::GetActiveProfile(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("MovieFileOutputNapi::GetActiveProfile is called");
    MovieFileOutputNapi* movieFileOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, movieFileOutputNapi);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("MovieFileOutputNapi::GetActiveProfile parse parameter occur error");
        return nullptr;
    }
    auto profile = movieFileOutputNapi->movieFileOutput_->GetVideoProfile();
    if (profile == nullptr) {
        return CameraNapiUtils::GetUndefinedValue(env);
    }
    return CameraNapiObjVideoProfile(*profile).GenerateNapiValue(env);
}

napi_value MovieFileOutputNapi::GetSupportedVideoFilters(napi_env env, napi_callback_info info)
{
    napi_value result = CameraNapiUtils::GetUndefinedValue(env);
    MEDIA_DEBUG_LOG("MovieFileOutputNapi::GetSupportedVideoFilters is called");
    MovieFileOutputNapi* movieFileOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, movieFileOutputNapi);
    if (!jsParamParser.AssertStatus(SERVICE_FATL_ERROR, "parse parameter occur error")) {
        MEDIA_ERR_LOG("MovieFileOutputNapi::GetSupportedVideoFilters parse parameter occur error");
        return result;
    }
    if (movieFileOutputNapi->movieFileOutput_ == nullptr) {
        MEDIA_ERR_LOG("MovieFileOutputNapi::GetSupportedVideoFilters get native object fail");
        CameraNapiUtils::ThrowError(env, SERVICE_FATL_ERROR, "get native object fail");
        return result;
    }
    std::vector<std::string> supportedVideoFilters;
    int32_t retCode = movieFileOutputNapi->movieFileOutput_->GetSupportedVideoFilters(supportedVideoFilters);
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

napi_value MovieFileOutputNapi::SetVideoFilter(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("SetVideoFilter is called");
    std::unique_ptr<MovieFileOutputAsyncContext> asyncContext = std::make_unique<MovieFileOutputAsyncContext>(
        "MovieFileOutputNapi::SetVideoFilter", CameraNapiUtils::IncrementAndGet(movieFileOutputTaskId));
    auto asyncFunction = std::make_shared<CameraNapiAsyncFunction>(
        env, "SetVideoFilter", asyncContext->callbackRef, asyncContext->deferred);
    CameraNapiParamParser jsParamParser(
        env, info, asyncContext->nativeNapiObj, asyncFunction, asyncContext->filter, asyncContext->filterParam);
    if (!jsParamParser.IsStatusOk()) {
        jsParamParser = CameraNapiParamParser(env, info, asyncContext->nativeNapiObj,
            asyncFunction, asyncContext->filter);
    }
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
        MEDIA_ERR_LOG("SetVideoFilter invalid argument");
        return nullptr;
    }
    asyncContext->HoldNapiValue(env, jsParamParser.GetThisVar());
    napi_status status = napi_create_async_work(
        env, nullptr, asyncFunction->GetResourceName(),
        [](napi_env env, void* data) {
            MEDIA_INFO_LOG("MovieFileOutputNapi::SetVideoFilter running on worker");
            auto context = static_cast<MovieFileOutputAsyncContext*>(data);
            CHECK_RETURN_ELOG(
                context->nativeNapiObj == nullptr, "MovieFileOutputNapi::SetVideoFilter async info is nullptr");
            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(
                context->queueTask, [&context]() {
                    context->status = true;
                    sptr<MovieFileOutput> movieFileOutput = context->nativeNapiObj->GetMovieFileOutput();
                    context->errorCode = movieFileOutput->SetVideoFilter(context->filter, context->filterParam);
                    context->status = context->errorCode == 0;
                });
        },
        AsyncCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for MovieFileOutputNapi::Start");
        asyncFunction->Reset();
    } else {
        asyncContext->queueTask =
            CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("MovieFileOutputNapi::SetVideoFilter");
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        (void)asyncContext.release();
    }
    if (asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE) {
        return asyncFunction->GetPromise();
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value MovieFileOutputNapi::IsMirrorSupported(napi_env env, napi_callback_info info)
{
    napi_value result = CameraNapiUtils::GetUndefinedValue(env);
    MEDIA_DEBUG_LOG("MovieFileOutputNapi::IsMirrorSupported is called");
 
    MovieFileOutputNapi* movieFileOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, movieFileOutputNapi);
    if (!jsParamParser.AssertStatus(SERVICE_FATL_ERROR, "parse parameter occur error")) {
        MEDIA_ERR_LOG("MovieFileOutputNapi::IsMirrorSupported parse parameter occur error");
        return result;
    }
    if (movieFileOutputNapi->movieFileOutput_ == nullptr) {
        MEDIA_ERR_LOG("MovieFileOutputNapi::IsMirrorSupported get native object fail");
        CameraNapiUtils::ThrowError(env, SERVICE_FATL_ERROR, "get native object fail");
        return result;
    }
    bool isMirrorSupported = movieFileOutputNapi->movieFileOutput_->IsMirrorSupported();
    napi_get_boolean(env, isMirrorSupported, &result);
    return result;
}

napi_value MovieFileOutputNapi::EnableMirror(napi_env env, napi_callback_info info)
{
    napi_value result = CameraNapiUtils::GetUndefinedValue(env);
    bool isEnable = false;
    MovieFileOutputNapi* movieFileOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, movieFileOutputNapi, isEnable);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("MovieFileOutputNapi::EnableMirror parse parameter occur error");
        return nullptr;
    }

    if (movieFileOutputNapi->movieFileOutput_ == nullptr) {
        MEDIA_ERR_LOG("MovieFileOutputNapi::EnableMirror get native object fail");
        CameraNapiUtils::ThrowError(env, SERVICE_FATL_ERROR, "get native object fail");
        return result;
    }
    int32_t retCode = movieFileOutputNapi->movieFileOutput_->EnableMirror(isEnable);
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        MEDIA_ERR_LOG("MovieFileOutputNapi::EnableMirror fail %{public}d", retCode);
        return nullptr;
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value MovieFileOutputNapi::Start(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("MovieFileOutputNapi::Start is called");
    std::unique_ptr<MovieFileOutputAsyncContext> asyncContext = std::make_unique<MovieFileOutputAsyncContext>(
        "MovieFileOutputNapi::Start", CameraNapiUtils::IncrementAndGet(movieFileOutputTaskId));
    auto asyncFunction = std::make_shared<CameraNapiAsyncFunction>(env, "MovieFileOutputNapi::Start",
        asyncContext->callbackRef, asyncContext->deferred);
    CameraNapiParamParser jsParamParser(env, info, asyncContext->nativeNapiObj, asyncFunction);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
        MEDIA_ERR_LOG("MovieFileOutputNapi::Start invalid argument");
        return nullptr;
    }
    asyncContext->HoldNapiValue(env, jsParamParser.GetThisVar());
    napi_status status = napi_create_async_work(
        env, nullptr, asyncFunction->GetResourceName(),
        [](napi_env env, void* data) {
            MEDIA_INFO_LOG("MovieFileOutputNapi::Start running on worker");
            MovieFileOutputAsyncContext* context = static_cast<MovieFileOutputAsyncContext*>(data);
            CHECK_RETURN_ELOG(context->nativeNapiObj == nullptr, "MovieFileOutputNapi::Start async info is nullptr");
            CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(
                context->queueTask, [&context]() {
                    context->status = true;
                    sptr<MovieFileOutput> movieFileOutput = context->nativeNapiObj->GetMovieFileOutput();
                    context->errorCode = movieFileOutput->Start();
                    context->status = context->errorCode == 0;
                });
        },
        AsyncCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for MovieFileOutputNapi::Start");
        asyncFunction->Reset();
    } else {
        asyncContext->queueTask =
            CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("MovieFileOutputNapi::Start");
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        (void)asyncContext.release();
    }
    if (asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE) {
        return asyncFunction->GetPromise();
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value MovieFileOutputNapi::Pause(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("MovieFileOutputNapi::Pause is called");
    std::unique_ptr<MovieFileOutputAsyncContext> asyncContext = std::make_unique<MovieFileOutputAsyncContext>(
        "MovieFileOutputNapi::Pause", CameraNapiUtils::IncrementAndGet(movieFileOutputTaskId));
    auto asyncFunction = std::make_shared<CameraNapiAsyncFunction>(env, "MovieFileOutputNapi::Pause",
        asyncContext->callbackRef, asyncContext->deferred);
    CameraNapiParamParser jsParamParser(env, info, asyncContext->nativeNapiObj, asyncFunction);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
        MEDIA_ERR_LOG("MovieFileOutputNapi::Pause invalid argument");
        return nullptr;
    }
    asyncContext->HoldNapiValue(env, jsParamParser.GetThisVar());
    napi_status status = napi_create_async_work(
        env, nullptr, asyncFunction->GetResourceName(),
        [](napi_env env, void* data) {
            MEDIA_INFO_LOG("MovieFileOutputNapi::Pause running on worker");
            MovieFileOutputAsyncContext* context = static_cast<MovieFileOutputAsyncContext*>(data);
            CHECK_RETURN_ELOG(context->nativeNapiObj == nullptr, "MovieFileOutputNapi::Pause async info is nullptr");
            CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(
                context->queueTask, [&context]() {
                    context->status = true;
                    sptr<MovieFileOutput> movieFileOutput = context->nativeNapiObj->GetMovieFileOutput();
                    context->errorCode = movieFileOutput->Pause();
                    context->status = context->errorCode == 0;
                });
        },
        AsyncCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for MovieFileOutputNapi::Pause");
        asyncFunction->Reset();
    } else {
        asyncContext->queueTask =
            CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("MovieFileOutputNapi::Pause");
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        (void)asyncContext.release();
    }
    if (asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE) {
        return asyncFunction->GetPromise();
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value MovieFileOutputNapi::Resume(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("MovieFileOutputNapi::Resume is called");
    std::unique_ptr<MovieFileOutputAsyncContext> asyncContext = std::make_unique<MovieFileOutputAsyncContext>(
        "MovieFileOutputNapi::Resume", CameraNapiUtils::IncrementAndGet(movieFileOutputTaskId));
    auto asyncFunction = std::make_shared<CameraNapiAsyncFunction>(env, "MovieFileOutputNapi::Resume",
        asyncContext->callbackRef, asyncContext->deferred);
    CameraNapiParamParser jsParamParser(env, info, asyncContext->nativeNapiObj, asyncFunction);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
        MEDIA_ERR_LOG("MovieFileOutputNapi::Resume invalid argument");
        return nullptr;
    }
    asyncContext->HoldNapiValue(env, jsParamParser.GetThisVar());
    napi_status status = napi_create_async_work(
        env, nullptr, asyncFunction->GetResourceName(),
        [](napi_env env, void* data) {
            MEDIA_INFO_LOG("MovieFileOutputNapi::Resume running on worker");
            MovieFileOutputAsyncContext* context = static_cast<MovieFileOutputAsyncContext*>(data);
            CHECK_RETURN_ELOG(context->nativeNapiObj == nullptr, "MovieFileOutputNapi::Resume async info is nullptr");
            CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(
                context->queueTask, [&context]() {
                    context->status = true;
                    sptr<MovieFileOutput> movieFileOutput = context->nativeNapiObj->GetMovieFileOutput();
                    context->errorCode = movieFileOutput->Resume();
                    context->status = context->errorCode == 0;
                });
        },
        AsyncCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for MovieFileOutputNapi::Resume");
        asyncFunction->Reset();
    } else {
        asyncContext->queueTask =
            CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("MovieFileOutputNapi::Resume");
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        (void)asyncContext.release();
    }
    if (asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE) {
        return asyncFunction->GetPromise();
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}


napi_value MovieFileOutputNapi::Stop(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("MovieFileOutputNapi::Stop is called");
    std::unique_ptr<MovieFileOutputAsyncContext> asyncContext = std::make_unique<MovieFileOutputAsyncContext>(
        "MovieFileOutputNapi::Stop", CameraNapiUtils::IncrementAndGet(movieFileOutputTaskId));
    auto asyncFunction = std::make_shared<CameraNapiAsyncFunction>(env, "MovieFileOutputNapi::Stop",
        asyncContext->callbackRef, asyncContext->deferred);
    CameraNapiParamParser jsParamParser(env, info, asyncContext->nativeNapiObj, asyncFunction);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
        MEDIA_ERR_LOG("MovieFileOutputNapi::Stop invalid argument");
        return nullptr;
    }
    asyncContext->HoldNapiValue(env, jsParamParser.GetThisVar());
    napi_status status = napi_create_async_work(
        env, nullptr, asyncFunction->GetResourceName(),
        [](napi_env env, void* data) {
            MEDIA_INFO_LOG("MovieFileOutputNapi::Stop running on worker");
            MovieFileOutputAsyncContext* context = static_cast<MovieFileOutputAsyncContext*>(data);
            CHECK_RETURN_ELOG(context->nativeNapiObj == nullptr, "MovieFileOutputNapi::Stop async info is nullptr");
            CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(
                context->queueTask, [&context]() {
                    context->status = true;
                    sptr<MovieFileOutput> movieFileOutput = context->nativeNapiObj->GetMovieFileOutput();
                    context->errorCode = movieFileOutput->Stop();
                    context->status = context->errorCode == 0;
                });
        },
        AsyncCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for MovieFileOutputNapi::Stop");
        asyncFunction->Reset();
    } else {
        asyncContext->queueTask =
            CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("MovieFileOutputNapi::Stop");
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        (void)asyncContext.release();
    }
    if (asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE) {
        return asyncFunction->GetPromise();
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value MovieFileOutputNapi::SetRotation(napi_env env, napi_callback_info info)
{
    napi_value result = CameraNapiUtils::GetUndefinedValue(env);
    MEDIA_DEBUG_LOG("MovieFileOutputNapi::SetRotation is called");
    MovieFileOutputNapi* movieFileOutputNapi = nullptr;
    int32_t rotation;
    CameraNapiParamParser jsParamParser(env, info, movieFileOutputNapi, rotation);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("MovieFileOutputNapi::SetRotation parse parameter occur error");
        return result;
    }
    if (movieFileOutputNapi->movieFileOutput_ == nullptr) {
        MEDIA_ERR_LOG("MovieFileOutputNapi::SetRotation get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return result;
    }
    int32_t retCode = movieFileOutputNapi->movieFileOutput_->SetRotation(rotation);
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        MEDIA_ERR_LOG("MovieFileOutputNapi::SetRotation fail %{public}d", retCode);
    }
    return result;
}

napi_value MovieFileOutputNapi::GetSupportedVideoCapability(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("GetSupportedVideoCapability is called");
    int32_t videoCodecType = 0;
    MovieFileOutputNapi* movieFileOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, movieFileOutputNapi, videoCodecType);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("MovieFileOutputNapi::GetSupportedVideoCapability parse parameter occur error");
        return nullptr;
    }
    auto videoCapability = movieFileOutputNapi->movieFileOutput_->GetSupportedVideoCapability(videoCodecType);
    if (videoCapability == nullptr) {
        return CameraNapiUtils::GetUndefinedValue(env);
    }
    return VideoCapabilityNapi::CreateVideoCapability(env, videoCapability);
}

napi_value MovieFileOutputNapi::Release(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("MovieFileOutputNapi::Release is called");
    std::unique_ptr<MovieFileOutputAsyncContext> asyncContext = std::make_unique<MovieFileOutputAsyncContext>(
        "MovieFileOutputNapi::Release", CameraNapiUtils::IncrementAndGet(movieFileOutputTaskId));
    auto asyncFunction =
        std::make_shared<CameraNapiAsyncFunction>(env, "Release", asyncContext->callbackRef, asyncContext->deferred);
    CameraNapiParamParser jsParamParser(env, info, asyncContext->nativeNapiObj, asyncFunction);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
        MEDIA_ERR_LOG("MovieFileOutputNapi::Release invalid argument");
        return nullptr;
    }
    asyncContext->HoldNapiValue(env, jsParamParser.GetThisVar());
    napi_status status = napi_create_async_work(
        env, nullptr, asyncFunction->GetResourceName(),
        [](napi_env env, void* data) {
            MEDIA_INFO_LOG("MovieFileOutputNapi::Release running on worker");
            auto context = static_cast<MovieFileOutputAsyncContext*>(data);
            CHECK_RETURN_ELOG(context->nativeNapiObj == nullptr, "MovieFileOutputNapi::Release async info is nullptr");
            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(context->queueTask, [&context]() {
                context->errorCode = context->nativeNapiObj->movieFileOutput_->Release();
                context->status = context->errorCode == CameraErrorCode::SUCCESS;
            });
        },
        AsyncCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for MovieFileOutputNapi::Release");
        asyncFunction->Reset();
    } else {
        asyncContext->queueTask =
            CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("MovieFileOutputNapi::Release");
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        (void)asyncContext.release();
    }
    if (asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE) {
        return asyncFunction->GetPromise();
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value MovieFileOutputNapi::On(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<MovieFileOutputNapi>::On(env, info);
}

napi_value MovieFileOutputNapi::Off(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<MovieFileOutputNapi>::Off(env, info);
}

MovieFileOutputAsyncContext::MovieFileOutputAsyncContext(std::string funcName, int32_t taskId)
    : AsyncContext(funcName, taskId)
    , nativeNapiObj(nullptr)
{
}

extern "C" napi_value createMovieFileOutputInstance(napi_env env, VideoProfile& videoProfile)
{
    MEDIA_DEBUG_LOG("createMovieFileOutputInstance is called");
    return MovieFileOutputNapi::CreateMovieFileOutput(env, videoProfile);
}
} // namespace CameraStandard
} // namespace OHOS