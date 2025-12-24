/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_TAIHE_INCLUDE_MOVIE_FILE_OUTPUT_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_MOVIE_FILE_OUTPUT_TAIHE_H

#include <unordered_map>

#include "ohos.multimedia.camera.proj.hpp"
#include "ohos.multimedia.camera.impl.hpp"
#include "taihe/runtime.hpp"

#include "camera_event_emitter_taihe.h"
#include "camera_output_taihe.h"
#include "camera_worker_queue_keeper_taihe.h"
#include "listener_base_taihe.h"
#include "output/movie_file_output.h"
#include "video_capability_taihe.h"

namespace Ani {
namespace Camera {
using namespace taihe;
using namespace ohos::multimedia::camera;

static const std::string CONST_MOVIE_FILE_RECORDING_START = "recordingStart";
static const std::string CONST_MOVIE_FILE_RECORDING_PAUSE = "recordingPause";
static const std::string CONST_MOVIE_FILE_RECORDING_RESUME = "recordingResume";
static const std::string CONST_MOVIE_FILE_RECORDING_STOP = "recordingStop";
static const std::string CONST_MOVIE_FILE_RECORDING_ERROR = "error";

class MovieFileOutputCallbackListener : public OHOS::CameraStandard::IMovieFileOutputStateCallback,
                                        public ListenerBase,
                                        public std::enable_shared_from_this<MovieFileOutputCallbackListener> {
public:
    explicit MovieFileOutputCallbackListener(ani_env* env) : ListenerBase(env) {}
    virtual ~MovieFileOutputCallbackListener() = default;
    void OnRecordingStart() const override;
    void OnRecordingPause() const override;
    void OnRecordingResume() const override;
    void OnRecordingStop() const override;
    void OnPhotoAssetAvailable(const std::string& uri) const override {}
    void OnError(const int32_t errorCode) const override;
private:
    void OnErrorCallback(int32_t errorCode) const;
    void OnRecordingResumeCallback() const;
    void OnRecordingStartCallback() const;
    void OnRecordingStopCallback() const;
    void OnRecordingPauseCallback() const;
};

class MovieFileOutputImpl : public CameraOutputImpl,
                            public CameraAniEventEmitter<MovieFileOutputImpl> {
public:
    MovieFileOutputImpl(OHOS::sptr<OHOS::CameraStandard::CaptureOutput> output);
    ~MovieFileOutputImpl() = default;
    void StartSync();
    void StopSync();
    void ResumeSync();
    void PauseSync();
    void OnError(callback_view<void(uintptr_t)> callback);
    void OffError(optional_view<callback<void(uintptr_t)>> callback);
    void OnRecordingResume(callback_view<void(uintptr_t err, int32_t data)> callback);
    void OffRecordingResume(optional_view<callback<void(uintptr_t err, int32_t data)>> callback);
    void OnRecordingStart(callback_view<void(uintptr_t err, int32_t data)> callback);
    void OffRecordingStart(optional_view<callback<void(uintptr_t err, int32_t data)>> callback);
    void OnRecordingStop(callback_view<void(uintptr_t err, int32_t data)> callback);
    void OffRecordingStop(optional_view<callback<void(uintptr_t err, int32_t data)>> callback);
    void OnRecordingPause(callback_view<void(uintptr_t err, int32_t data)> callback);
    void OffRecordingPause(optional_view<callback<void(uintptr_t err, int32_t data)>> callback);
    void OnMovieInfoAvailable(callback_view<void(uintptr_t err, MovieInfo const& data)> callback) {}
    void OffMovieInfoAvailable(optional_view<callback<void(uintptr_t err, MovieInfo const& data)>> callback) {}
    VideoCapability GetSupportedVideoCapability(VideoCodecType videoCodecType);
    array<VideoCodecType> GetSupportedVideoCodecTypes();
    void SetOutputSettingsSync(MovieSettings const& settings);
    MovieSettings GetOutputSettings();
    bool IsMirrorSupported();
    void EnableMirror(bool enabled);
    array<string> GetSupportedVideoFilters();
    VideoProfile GetActiveVideoProfile();
    void AddVideoFilterSync(string_view filter, optional_view<string> param);
    bool IsAutoDeferredVideoEnhancementEnabled();
    void EnableAutoDeferredVideoEnhancement(bool enabled);
    bool IsAutoDeferredVideoEnhancementSupported();
    void RemoveVideoFilterSync(string_view filter);
    bool IsAutoVideoFrameRateSupported();
    void EnableAutoVideoFrameRate(bool enabled);
    ImageRotation GetVideoRotation(int32_t deviceDegree);
    static uint32_t movieFileOutputTaskId_;
private:
    virtual const EmitterFunctions& GetEmitterFunctions() override;
    void RegisterErrorCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterErrorCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    void RegisterRecordingResumeCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterRecordingResumeCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    void RegisterRecordingStartCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterRecordingStartCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    void RegisterRecordingStopCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterRecordingStopCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    void RegisterRecordingPauseCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterRecordingPauseCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    std::shared_ptr<MovieFileOutputCallbackListener> movieFileOutputCallback_ = nullptr;
    OHOS::sptr<OHOS::CameraStandard::MovieFileOutput> movieFileOutput_ = nullptr;
};

struct MovieFileOutputTaiheAsyncContext : public TaiheAsyncContext {
    MovieFileOutputTaiheAsyncContext(std::string funcName, int32_t taskId) : TaiheAsyncContext(funcName, taskId) {};
    ~MovieFileOutputTaiheAsyncContext(){
        objectInfo = nullptr;
    }

    MovieFileOutputImpl* objectInfo = nullptr;
    std::string errorMsg;
};
} // namespace Camera
} // namespace Ani

#endif // FRAMEWORKS_TAIHE_INCLUDE_MOVIE_FILE_OUTPUT_TAIHE_H