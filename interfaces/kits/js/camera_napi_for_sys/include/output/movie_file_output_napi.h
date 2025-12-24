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

#ifndef MOVIE_FILE_OUTPUT_NAPI_H
#define MOVIE_FILE_OUTPUT_NAPI_H

#include "camera_napi_template_utils.h"
#include "camera_napi_event_emitter.h"
#include "camera_napi_param_parser.h"
#include "camera_napi_utils.h"
#include "listener_base.h"
#include "output/movie_file_output.h"
#include <unordered_map>

namespace OHOS {
namespace CameraStandard {

static const char CAMERA_MOVIE_FILE_OUTPUT_NAPI_CLASS_NAME[] = "MovieFileOutput";

static const std::string CONST_MOVIE_FILE_RECORDING_START = "recordingStart";
static const std::string CONST_MOVIE_FILE_RECORDING_PAUSE = "recordingPause";
static const std::string CONST_MOVIE_FILE_RECORDING_RESUME = "recordingResume";
static const std::string CONST_MOVIE_FILE_RECORDING_STOP = "recordingStop";
static const std::string CONST_MOVIE_FILE_PHOTO_ASSET_AVAILABLE = "photoAssetAvailable";
static const std::string CONST_MOVIE_FILE_RECORDING_ERROR = "error";

struct MovieFileCallbackInfo {
    int32_t duration = 0;
    int32_t errorCode = 0;
    int32_t captureId = 0;
    std::string uri = "";
};

enum class MovieFileOutputEventType {
    RECORDING_START,
    RECORDING_PAUSE,
    RECORDING_RESUME,
    RECORDING_STOP,
    PHOTO_ASSET_AVAILABLE,
    ERROR,
    RECORDING_INVALID_TYPE
};

static EnumHelper<MovieFileOutputEventType> MovieFileOutputEventTypeHelper({
        {MovieFileOutputEventType::RECORDING_START, CONST_MOVIE_FILE_RECORDING_START},
        {MovieFileOutputEventType::RECORDING_PAUSE, CONST_MOVIE_FILE_RECORDING_PAUSE},
        {MovieFileOutputEventType::RECORDING_RESUME, CONST_MOVIE_FILE_RECORDING_RESUME},
        {MovieFileOutputEventType::RECORDING_STOP, CONST_MOVIE_FILE_RECORDING_STOP},
        {MovieFileOutputEventType::PHOTO_ASSET_AVAILABLE, CONST_MOVIE_FILE_PHOTO_ASSET_AVAILABLE},
        {MovieFileOutputEventType::ERROR, CONST_MOVIE_FILE_RECORDING_ERROR},
    },
    MovieFileOutputEventType::RECORDING_INVALID_TYPE
);

class MovieFileOutputCallbackListener : public IMovieFileOutputStateCallback,
                                        public ListenerBase,
                                        public std::enable_shared_from_this<MovieFileOutputCallbackListener> {
public:
    explicit MovieFileOutputCallbackListener(napi_env env);
    virtual ~MovieFileOutputCallbackListener() = default;
    void OnRecordingStart() const override;
    void OnRecordingPause() const override;
    void OnRecordingResume() const override;
    void OnRecordingStop() const override;
    void OnPhotoAssetAvailable(const std::string& uri) const override;
    void OnError(const int32_t errorCode) const override;
private:
    void UpdateJSCallback(MovieFileOutputEventType eventType, const MovieFileCallbackInfo& info) const;
    void UpdateJSCallbackAsync(MovieFileOutputEventType eventType, const MovieFileCallbackInfo& info) const;
    void ExecuteRecordingStartCb(const MovieFileCallbackInfo& info) const;
    void ExecuteRecordingPauseCb(const MovieFileCallbackInfo& info) const;
    void ExecuteRecordingResumeCb(const MovieFileCallbackInfo& info) const;
    void ExecuteRecordingStopCb(const MovieFileCallbackInfo& info) const;
    void ExecutePhotoAssetAvailableCb(const MovieFileCallbackInfo& info) const;
    void ExecuteErrorCb(const MovieFileCallbackInfo& info) const;
};

struct MovieFileOutputCallbackInfo {
    MovieFileOutputEventType eventType_;
    MovieFileCallbackInfo info_;
    std::weak_ptr<const MovieFileOutputCallbackListener> listener_;
    MovieFileOutputCallbackInfo(MovieFileOutputEventType eventType, MovieFileCallbackInfo info,
        std::shared_ptr<const MovieFileOutputCallbackListener> listener)
        : eventType_(eventType), info_(info), listener_(listener) {}
};

struct MovieFileOutputAsyncContext;

class MovieFileOutputNapi : public CameraNapiEventEmitter<MovieFileOutputNapi> {
public:
    MovieFileOutputNapi();
    virtual ~MovieFileOutputNapi() = default;
    static void Init(napi_env env);
    static napi_value CreateMovieFileOutput(napi_env env);
    static napi_value CreateMovieFileOutput(napi_env env, VideoProfile& profile);
    static napi_value MovieFileOutputNapiConstructor(napi_env env, napi_callback_info info);
    static void MovieFileOutputNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static bool IsMovieFileOutput(napi_env env, napi_value obj);
    static napi_value GetOutputSettings(napi_env env, napi_callback_info info);
    static napi_value SetOutputSettings(napi_env env, napi_callback_info info);
    static napi_value GetSupportedVideoCodecTypes(napi_env env, napi_callback_info info);
    static napi_value GetActiveProfile(napi_env env, napi_callback_info info);
    static napi_value GetSupportedVideoFilters(napi_env env, napi_callback_info info);
    static napi_value SetVideoFilter(napi_env env, napi_callback_info info);
    static napi_value IsMirrorSupported(napi_env env, napi_callback_info info);
    static napi_value EnableMirror(napi_env env, napi_callback_info info);
    static napi_value Start(napi_env env, napi_callback_info info);
    static napi_value Pause(napi_env env, napi_callback_info info);
    static napi_value Resume(napi_env env, napi_callback_info info);
    static napi_value Stop(napi_env env, napi_callback_info info);
    static napi_value Release(napi_env env, napi_callback_info info);
    static napi_value On(napi_env env, napi_callback_info info);
    static napi_value Off(napi_env env, napi_callback_info info);
    static napi_value SetRotation(napi_env env, napi_callback_info info);
    static napi_value GetSupportedVideoCapability(napi_env env, napi_callback_info info);
    sptr<MovieFileOutput> GetMovieFileOutput();
    const EmitterFunctions& GetEmitterFunctions() override;

    napi_ref wrapper_; // TODO: remove this

private:
    static bool ParseOutputSettings(napi_env env, napi_callback_info info,
        MovieFileOutputAsyncContext* asyncContext, std::shared_ptr<CameraNapiAsyncFunction>& asyncFunction);
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
    void RegisterPhotoAssetAvailableCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce);
    void UnregisterPhotoAssetAvailableCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);
    void RegisterErrorCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce);
    void UnregisterErrorCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);
    napi_env env_;
    sptr<MovieFileOutput> movieFileOutput_;
    std::shared_ptr<MovieFileOutputCallbackListener> movieFileOutputCallback_;
    static thread_local napi_ref constructor_;
    static thread_local sptr<MovieFileOutput> sMovieFileOutput_;
    static thread_local uint32_t movieFileOutputTaskId;
};

struct MovieFileOutputAsyncContext : public AsyncContext {
    MovieFileOutputAsyncContext(std::string funcName, int32_t taskId);
    virtual ~MovieFileOutputAsyncContext() = default;
    MovieFileOutputNapi* nativeNapiObj;
    std::string errorMsg;
    int32_t captureId{-1};
    int32_t videoCodecType{-1};
    std::optional<Location> location;
    std::optional<bool> isBFrameEnabled;
    std::optional<int32_t> videoBitrate;
    std::string filter = "";
    std::string filterParam = "";
};
} // namespace CameraStandard
} // namespace OHOS
#endif
