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

#ifndef CAMERA_UNIFY_MOVIE_FILE_OUTPUT_NAPI_H
#define CAMERA_UNIFY_MOVIE_FILE_OUTPUT_NAPI_H

#include <unordered_map>

#include "camera_napi_event_emitter.h"
#include "camera_napi_event_listener.h"
#include "camera_napi_param_parser.h"
#include "camera_napi_utils.h"
#include "listener_base.h"
#include "unify_movie_file_output.h"

namespace OHOS {
namespace CameraStandard {

static const char CAMERA_UNIFY_MOVIE_FILE_OUTPUT_NAPI_CLASS_NAME[] = "UnifyMovieFileOutput";

static const std::string CONST_UNIFY_MOVIE_FILE_RECORDING_START = "recordingStart";
static const std::string CONST_UNIFY_MOVIE_FILE_RECORDING_PAUSE = "recordingPause";
static const std::string CONST_UNIFY_MOVIE_FILE_RECORDING_RESUME = "recordingResume";
static const std::string CONST_UNIFY_MOVIE_FILE_RECORDING_STOP = "recordingStop";
static const std::string CONST_UNIFY_MOVIE_FILE_MOVIE_INFO_AVAILABLE = "movieInfoAvailable";
static const std::string CONST_UNIFY_MOVIE_FILE_RECORDING_ERROR = "error";

struct UnifyMovieFileOutputCallbackInfo;
class UnifyMovieFileOutputCallback : public UnifyMovieFileOutputStateCallback,
                                     public ListenerBase,
                                     public std::enable_shared_from_this<UnifyMovieFileOutputCallback> {
public:
    explicit UnifyMovieFileOutputCallback(napi_env env);
    ~UnifyMovieFileOutputCallback() = default;

    void OnStart() override;
    void OnPause() override;
    void OnResume() override;
    void OnStop() override;
    void OnMovieInfoAvailable(int32_t captureId, std::string uri) override;
    void OnError(const int32_t errorCode) override;

private:
    void UpdateJSCallback(UnifyMovieFileOutputCallbackInfo callbackInfo) const;
    void UpdateJSCallbackAsync(UnifyMovieFileOutputCallbackInfo callbackInfo) const;
};

struct UnifyMovieFileOutputCallbackInfo {
    std::string eventName = "";
    int32_t errorCode = 0;
    int32_t captureId = -1;
    std::string uri = "";
    std::weak_ptr<const UnifyMovieFileOutputCallback> listener;
    UnifyMovieFileOutputCallbackInfo(
        std::string eventName, std::shared_ptr<const UnifyMovieFileOutputCallback> listener)
        : eventName(eventName), listener(listener)
    {}
};

struct UnifyMovieFileOutputAsyncContext;

class UnifyMovieFileOutputNapi : public CameraNapiEventEmitter<UnifyMovieFileOutputNapi>,
                                 public CameraNapiEventListener<UnifyMovieFileOutputCallback> {
public:
    UnifyMovieFileOutputNapi();
    virtual ~UnifyMovieFileOutputNapi() = default;
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateUnifyMovieFileOutput(napi_env env, VideoProfile& profile);
    static napi_value MovieFileOutputNapiConstructor(napi_env env, napi_callback_info info);
    static void MovieFileOutputNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static bool IsMovieFileOutput(napi_env env, napi_value obj);
    static napi_value GetOutputSettings(napi_env env, napi_callback_info info);
    static napi_value SetOutputSettings(napi_env env, napi_callback_info info);
    static napi_value GetSupportedVideoCodecTypes(napi_env env, napi_callback_info info);
    static napi_value GetActiveProfile(napi_env env, napi_callback_info info);
    static napi_value GetSupportedVideoFilters(napi_env env, napi_callback_info info);
    static napi_value AddVideoFilter(napi_env env, napi_callback_info info);
    static napi_value RemoveVideoFilter(napi_env env, napi_callback_info info);
    static napi_value IsMirrorSupported(napi_env env, napi_callback_info info);
    static napi_value EnableMirror(napi_env env, napi_callback_info info);
    static napi_value Start(napi_env env, napi_callback_info info);
    static napi_value Pause(napi_env env, napi_callback_info info);
    static napi_value Resume(napi_env env, napi_callback_info info);
    static napi_value Stop(napi_env env, napi_callback_info info);
    static napi_value Release(napi_env env, napi_callback_info info);
    static napi_value IsAutoDeferredVideoEnhancementSupported(napi_env env, napi_callback_info info);
    static napi_value IsAutoDeferredVideoEnhancementEnabled(napi_env env, napi_callback_info info);
    static napi_value EnableAutoDeferredVideoEnhancement(napi_env env, napi_callback_info info);
    static napi_value IsAutoVideoFrameRateSupported(napi_env env, napi_callback_info info);
    static napi_value EnableAutoVideoFrameRate(napi_env env, napi_callback_info info);
    static napi_value GetVideoRotation(napi_env env, napi_callback_info info);
    static napi_value GetSupportedVideoCapability(napi_env env, napi_callback_info info);
    static napi_value On(napi_env env, napi_callback_info info);
    static napi_value Off(napi_env env, napi_callback_info info);

    sptr<UnifyMovieFileOutput> GetMovieFileOutput();
    const EmitterFunctions& GetEmitterFunctions() override;

private:
    static bool ParseOutputSettings(napi_env env, napi_callback_info info,
        UnifyMovieFileOutputAsyncContext* asyncContext, std::shared_ptr<CameraNapiAsyncFunction>& asyncFunction);
    void RegisterRecordingStartCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce);
    void UnregisterRecordingStartCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);
    void RegisterRecordingPauseCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce);
    void UnregisterRecordingPauseCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);
    void RegisterRecordingResumeCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce);
    void UnregisterRecordingResumeCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);
    void RegisterRecordingStopCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce);
    void UnregisterRecordingStopCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);
    void RegisterMovieInfoAvailableCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce);
    void UnregisterMovieInfoAvailableCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);
    void RegisterErrorCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce);
    void UnregisterErrorCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);
    napi_env env_;
    sptr<UnifyMovieFileOutput> unifyMovieFileOutput_;
    static thread_local napi_ref constructor_;
    static thread_local sptr<UnifyMovieFileOutput> sUnifyMovieFileOutput_;
    static thread_local uint32_t movieFileOutputTaskId;
};

struct UnifyMovieFileOutputAsyncContext : public AsyncContext {
    UnifyMovieFileOutputAsyncContext(std::string funcName, int32_t taskId);
    virtual ~UnifyMovieFileOutputAsyncContext() = default;
    UnifyMovieFileOutputNapi* nativeNapiObj = nullptr;
    std::string errorMsg;
    int32_t captureId { -1 };
    int32_t videoCodec { 0 };
    int32_t rotation = { 0 };
    std::optional<Location> location;
    std::optional<bool> isBFrameEnabled;
    std::optional<int32_t> videoBitrate;
    std::string filter = "";
    std::string filterParam = "";
};
} // namespace CameraStandard
} // namespace OHOS
#endif
