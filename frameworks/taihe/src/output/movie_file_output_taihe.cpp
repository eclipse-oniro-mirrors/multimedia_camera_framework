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

#include "movie_file_output_taihe.h"

#include "media_library_comm_ani.h"
#include "camera_log.h"
#include "camera_error_code.h"
#include "camera_event_emitter_taihe.h"
#include "camera_security_utils_taihe.h"
#include "camera_template_utils_taihe.h"
#include "camera_utils_taihe.h"

using namespace taihe;
using namespace ohos::multimedia::camera;

namespace Ani {
namespace Camera {
uint32_t MovieFileOutputImpl::movieFileOutputTaskId_ = CAMERA_MOVIE_FILE_OUTPUT_TASKID;
MovieFileOutputImpl::MovieFileOutputImpl(
    OHOS::sptr<OHOS::CameraStandard::CaptureOutput> output) : CameraOutputImpl(output)
{
    movieFileOutput_ = static_cast<OHOS::CameraStandard::MovieFileOutput*>(output.GetRefPtr());
}

void MovieFileOutputImpl::StartSync()
{
    MEDIA_DEBUG_LOG("StartSync is called");
    std::unique_ptr<MovieFileOutputTaiheAsyncContext> asyncContext =
        std::make_unique<MovieFileOutputTaiheAsyncContext>(
            "MovieFileOutputImpl::StartSync",
            CameraUtilsTaihe::IncrementAndGet(movieFileOutputTaskId_));
    CHECK_RETURN_ELOG(movieFileOutput_ == nullptr, "movieFileOutput_ is nullptr");
    asyncContext->queueTask = CameraTaiheWorkerQueueKeeper::GetInstance()->
        AcquireWorkerQueueTask("MovieFileOutputImpl::StartSync");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_RETURN_ELOG(asyncContext == nullptr, "asyncContext is nullptr");
        CHECK_RETURN_ELOG(asyncContext->objectInfo == nullptr, "MovieFileOutputImpl is nullptr");
        CHECK_RETURN_ELOG(asyncContext->objectInfo->movieFileOutput_ == nullptr, "MovieFileOutput is nullptr");
        asyncContext->errorCode = asyncContext->objectInfo->movieFileOutput_->Start();
        MEDIA_INFO_LOG("MovieFileOutputImpl::StartSync errorCode: %{public}d", asyncContext->errorCode);
        CameraUtilsTaihe::CheckError(asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

void MovieFileOutputImpl::StopSync()
{
    MEDIA_DEBUG_LOG("StopSync is called");
    std::unique_ptr<MovieFileOutputTaiheAsyncContext> asyncContext =
        std::make_unique<MovieFileOutputTaiheAsyncContext>(
            "MovieFileOutputImpl::StopSync",
            CameraUtilsTaihe::IncrementAndGet(movieFileOutputTaskId_));
    CHECK_RETURN_ELOG(movieFileOutput_ == nullptr, "movieFileOutput_ is nullptr");
    asyncContext->queueTask = CameraTaiheWorkerQueueKeeper::GetInstance()->
        AcquireWorkerQueueTask("MovieFileOutputImpl::StopSync");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_RETURN_ELOG(asyncContext == nullptr, "asyncContext is nullptr");
        CHECK_RETURN_ELOG(asyncContext->objectInfo == nullptr, "MovieFileOutputImpl is nullptr");
        CHECK_RETURN_ELOG(asyncContext->objectInfo->movieFileOutput_ == nullptr, "MovieFileOutput is nullptr");
        asyncContext->errorCode = asyncContext->objectInfo->movieFileOutput_->Stop();
        MEDIA_INFO_LOG("MovieFileOutputImpl::StopSync errorCode: %{public}d", asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

void MovieFileOutputImpl::PauseSync()
{
    MEDIA_DEBUG_LOG("PauseSync is called");
    std::unique_ptr<MovieFileOutputTaiheAsyncContext> asyncContext =
        std::make_unique<MovieFileOutputTaiheAsyncContext>(
            "MovieFileOutputImpl::PauseSync",
            CameraUtilsTaihe::IncrementAndGet(movieFileOutputTaskId_));
    CHECK_RETURN_ELOG(movieFileOutput_ == nullptr, "movieFileOutput_ is nullptr");
    asyncContext->queueTask = CameraTaiheWorkerQueueKeeper::GetInstance()->
        AcquireWorkerQueueTask("MovieFileOutputImpl::PauseSync");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_RETURN_ELOG(asyncContext == nullptr, "asyncContext is nullptr");
        CHECK_RETURN_ELOG(asyncContext->objectInfo == nullptr, "MovieFileOutputImpl is nullptr");
        OHOS::sptr<OHOS::CameraStandard::MovieFileOutput> movieFileOutput = asyncContext->objectInfo->movieFileOutput_;
        CHECK_RETURN_ELOG(movieFileOutput == nullptr, "movieFileOutput is nullptr");
        asyncContext->errorCode = movieFileOutput->Pause();
        MEDIA_INFO_LOG("MovieFileOutputImpl::PauseSync errorCode: %{public}d", asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

void MovieFileOutputImpl::ResumeSync()
{
    MEDIA_DEBUG_LOG("ResumeSync is called");
    std::unique_ptr<MovieFileOutputTaiheAsyncContext> asyncContext =
        std::make_unique<MovieFileOutputTaiheAsyncContext>(
            "MovieFileOutputImpl::ResumeSync",
            CameraUtilsTaihe::IncrementAndGet(movieFileOutputTaskId_));
    CHECK_RETURN_ELOG(movieFileOutput_ == nullptr, "movieFileOutput_ is nullptr");
    asyncContext->queueTask = CameraTaiheWorkerQueueKeeper::GetInstance()->
        AcquireWorkerQueueTask("MovieFileOutputImpl::ResumeSync");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_RETURN_ELOG(asyncContext == nullptr, "asyncContext is nullptr");
        CHECK_RETURN_ELOG(asyncContext->objectInfo == nullptr, "MovieFileOutputImpl is nullptr");
        OHOS::sptr<OHOS::CameraStandard::MovieFileOutput> movieFileOutput = asyncContext->objectInfo->movieFileOutput_;
        CHECK_RETURN_ELOG(movieFileOutput == nullptr, "movieFileOutput is nullptr");
        asyncContext->errorCode = movieFileOutput->Resume();
        MEDIA_INFO_LOG("MovieFileOutputImpl::ResumeSync errorCode: %{public}d", asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

void MovieFileOutputImpl::OnError(callback_view<void(uintptr_t err)> callback)
{
    ListenerTemplate<MovieFileOutputImpl>::On(this, callback, CONST_MOVIE_FILE_RECORDING_ERROR);
}

void MovieFileOutputImpl::OffError(optional_view<callback<void(uintptr_t err)>> callback)
{
    ListenerTemplate<MovieFileOutputImpl>::Off(this, callback, CONST_MOVIE_FILE_RECORDING_ERROR);
}

void MovieFileOutputCallbackListener::OnError(int32_t errorCode) const
{
    MEDIA_DEBUG_LOG("OnError is called, errorCode: %{public}d", errorCode);
    OnErrorCallback(errorCode);
}

void MovieFileOutputCallbackListener::OnErrorCallback(int32_t errorCode) const
{
    MEDIA_DEBUG_LOG("OnErrorCallback is called, errorCode: %{public}d", errorCode);
    auto sharePtr = shared_from_this();
    auto task = [errorCode, sharePtr]() {
        CHECK_EXECUTE(sharePtr != nullptr, sharePtr->ExecuteErrorCallback(CONST_MOVIE_FILE_RECORDING_ERROR, errorCode));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnError", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void MovieFileOutputImpl::RegisterErrorCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    if (movieFileOutputCallback_ == nullptr) {
        ani_env *env = get_env();
        movieFileOutputCallback_ = std::make_shared<MovieFileOutputCallbackListener>(env);
        CHECK_RETURN_ELOG(!movieFileOutput_, "movieFileOutput_ is nullptr");
        movieFileOutput_->SetCallback(movieFileOutputCallback_);
    }
    movieFileOutputCallback_->SaveCallbackReference(CONST_MOVIE_FILE_RECORDING_ERROR, callback, isOnce);
}

void MovieFileOutputImpl::UnregisterErrorCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    if (movieFileOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("movieFileOutputCallback_ is nullptr");
        return;
    }
    movieFileOutputCallback_->RemoveCallbackRef(CONST_MOVIE_FILE_RECORDING_ERROR, callback);
}

void MovieFileOutputImpl::OnRecordingResume(callback_view<void(uintptr_t err, int32_t data)> callback)
{
    ListenerTemplate<MovieFileOutputImpl>::On(this, callback, CONST_MOVIE_FILE_RECORDING_RESUME);
}

void MovieFileOutputImpl::OffRecordingResume(optional_view<callback<void(uintptr_t err, int32_t data)>> callback)
{
    ListenerTemplate<MovieFileOutputImpl>::Off(this, callback, CONST_MOVIE_FILE_RECORDING_RESUME);
}

void MovieFileOutputCallbackListener::OnRecordingResume() const
{
    MEDIA_DEBUG_LOG("MovieFileOutputCallbackListener::OnRecordingResume is called");
    OnRecordingResumeCallback();
}

void MovieFileOutputCallbackListener::OnRecordingResumeCallback() const
{
    MEDIA_DEBUG_LOG("OnRecordingResumeCallback is called");
    auto sharePtr = shared_from_this();
    auto task = [sharePtr]() {
        int32_t data = 0;
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback(CONST_MOVIE_FILE_RECORDING_RESUME, 0, "Callback is OK", data));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnRecordingResume", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void MovieFileOutputImpl::RegisterRecordingResumeCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    if (movieFileOutputCallback_ == nullptr) {
        ani_env *env = get_env();
        movieFileOutputCallback_ = std::make_shared<MovieFileOutputCallbackListener>(env);
        CHECK_RETURN_ELOG(!movieFileOutput_, "movieFileOutput_ is nullptr");
        movieFileOutput_->SetCallback(movieFileOutputCallback_);
    }
    movieFileOutputCallback_->SaveCallbackReference(CONST_MOVIE_FILE_RECORDING_RESUME, callback, isOnce);
}

void MovieFileOutputImpl::UnregisterRecordingResumeCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    if (movieFileOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("movieFileOutputCallback_ is nullptr");
        return;
    }
    movieFileOutputCallback_->RemoveCallbackRef(CONST_MOVIE_FILE_RECORDING_RESUME, callback);
}

void MovieFileOutputImpl::OnRecordingStart(callback_view<void(uintptr_t err, int32_t data)> callback)
{
    ListenerTemplate<MovieFileOutputImpl>::On(this, callback, CONST_MOVIE_FILE_RECORDING_START);
}

void MovieFileOutputImpl::OffRecordingStart(optional_view<callback<void(uintptr_t err, int32_t data)>> callback)
{
    ListenerTemplate<MovieFileOutputImpl>::Off(this, callback, CONST_MOVIE_FILE_RECORDING_START);
}

void MovieFileOutputCallbackListener::OnRecordingStart() const
{
    MEDIA_DEBUG_LOG("MovieFileOutputCallbackListener::OnRecordingStart is called");
    OnRecordingStartCallback();
}

void MovieFileOutputCallbackListener::OnRecordingStartCallback() const
{
    MEDIA_DEBUG_LOG("OnRecordingStartCallback is called");
    auto sharePtr = shared_from_this();
    auto task = [sharePtr]() {
        int32_t data = 0;
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback(CONST_MOVIE_FILE_RECORDING_START, 0, "Callback is OK", data));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnRecordingStart", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void MovieFileOutputImpl::RegisterRecordingStartCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    if (movieFileOutputCallback_ == nullptr) {
        ani_env *env = get_env();
        movieFileOutputCallback_ = std::make_shared<MovieFileOutputCallbackListener>(env);
        CHECK_RETURN_ELOG(!movieFileOutput_, "movieFileOutput_ is nullptr");
        movieFileOutput_->SetCallback(movieFileOutputCallback_);
    }
    movieFileOutputCallback_->SaveCallbackReference(CONST_MOVIE_FILE_RECORDING_START, callback, isOnce);
}

void MovieFileOutputImpl::UnregisterRecordingStartCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    if (movieFileOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("movieFileOutputCallback_ is nullptr");
        return;
    }
    movieFileOutputCallback_->RemoveCallbackRef(CONST_MOVIE_FILE_RECORDING_START, callback);
}

void MovieFileOutputImpl::OnRecordingStop(callback_view<void(uintptr_t err, int32_t data)> callback)
{
    ListenerTemplate<MovieFileOutputImpl>::On(this, callback, CONST_MOVIE_FILE_RECORDING_STOP);
}

void MovieFileOutputImpl::OffRecordingStop(optional_view<callback<void(uintptr_t err, int32_t data)>> callback)
{
    ListenerTemplate<MovieFileOutputImpl>::Off(this, callback, CONST_MOVIE_FILE_RECORDING_STOP);
}

void MovieFileOutputCallbackListener::OnRecordingStop() const
{
    MEDIA_DEBUG_LOG("MovieFileOutputCallbackListener::OnRecordingStop is called");
    OnRecordingStopCallback();
}

void MovieFileOutputCallbackListener::OnRecordingStopCallback() const
{
    MEDIA_DEBUG_LOG("OnRecordingStopCallback is called");
    auto sharePtr = shared_from_this();
    auto task = [sharePtr]() {
        int32_t data = 0;
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback(CONST_MOVIE_FILE_RECORDING_STOP, 0, "Callback is OK", data));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnRecordingStop", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void MovieFileOutputImpl::RegisterRecordingStopCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    if (movieFileOutputCallback_ == nullptr) {
        ani_env *env = get_env();
        movieFileOutputCallback_ = std::make_shared<MovieFileOutputCallbackListener>(env);
        CHECK_RETURN_ELOG(!movieFileOutput_, "movieFileOutput_ is nullptr");
        movieFileOutput_->SetCallback(movieFileOutputCallback_);
    }
    movieFileOutputCallback_->SaveCallbackReference(CONST_MOVIE_FILE_RECORDING_STOP, callback, isOnce);
}

void MovieFileOutputImpl::UnregisterRecordingStopCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    if (movieFileOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("movieFileOutputCallback_ is nullptr");
        return;
    }
    movieFileOutputCallback_->RemoveCallbackRef(CONST_MOVIE_FILE_RECORDING_STOP, callback);
}

void MovieFileOutputImpl::OnRecordingPause(callback_view<void(uintptr_t err, int32_t data)> callback)
{
    ListenerTemplate<MovieFileOutputImpl>::On(this, callback, CONST_MOVIE_FILE_RECORDING_PAUSE);
}

void MovieFileOutputImpl::OffRecordingPause(optional_view<callback<void(uintptr_t err, int32_t data)>> callback)
{
    ListenerTemplate<MovieFileOutputImpl>::Off(this, callback, CONST_MOVIE_FILE_RECORDING_PAUSE);
}

void MovieFileOutputCallbackListener::OnRecordingPause() const
{
    MEDIA_DEBUG_LOG("MovieFileOutputCallbackListener::OnRecordingPause is called");
    OnRecordingPauseCallback();
}

void MovieFileOutputCallbackListener::OnRecordingPauseCallback() const
{
    MEDIA_DEBUG_LOG("OnRecordingPauseCallback is called");
    auto sharePtr = shared_from_this();
    auto task = [sharePtr]() {
        int32_t data = 0;
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback(CONST_MOVIE_FILE_RECORDING_PAUSE, 0, "Callback is OK", data));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnRecordingPause", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void MovieFileOutputImpl::RegisterRecordingPauseCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    if (movieFileOutputCallback_ == nullptr) {
        ani_env *env = get_env();
        movieFileOutputCallback_ = std::make_shared<MovieFileOutputCallbackListener>(env);
        CHECK_RETURN_ELOG(!movieFileOutput_, "movieFileOutput_ is nullptr");
        movieFileOutput_->SetCallback(movieFileOutputCallback_);
    }
    movieFileOutputCallback_->SaveCallbackReference(CONST_MOVIE_FILE_RECORDING_PAUSE, callback, isOnce);
}

void MovieFileOutputImpl::UnregisterRecordingPauseCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    if (movieFileOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("movieFileOutputCallback_ is nullptr");
        return;
    }
    movieFileOutputCallback_->RemoveCallbackRef(CONST_MOVIE_FILE_RECORDING_PAUSE, callback);
}

const MovieFileOutputImpl::EmitterFunctions& MovieFileOutputImpl::GetEmitterFunctions()
{
    static const EmitterFunctions funMap = {
        { CONST_MOVIE_FILE_RECORDING_START, {
            &MovieFileOutputImpl::RegisterRecordingStartCallbackListener,
            &MovieFileOutputImpl::UnregisterRecordingStartCallbackListener } },
        { CONST_MOVIE_FILE_RECORDING_PAUSE, {
            &MovieFileOutputImpl::RegisterRecordingPauseCallbackListener,
            &MovieFileOutputImpl::UnregisterRecordingPauseCallbackListener } },
        { CONST_MOVIE_FILE_RECORDING_RESUME, {
            &MovieFileOutputImpl::RegisterRecordingResumeCallbackListener,
            &MovieFileOutputImpl::UnregisterRecordingResumeCallbackListener } },
        { CONST_MOVIE_FILE_RECORDING_STOP, {
            &MovieFileOutputImpl::RegisterRecordingStopCallbackListener,
            &MovieFileOutputImpl::UnregisterRecordingStopCallbackListener } },
        { CONST_MOVIE_FILE_RECORDING_ERROR, {
            &MovieFileOutputImpl::RegisterErrorCallbackListener,
            &MovieFileOutputImpl::UnregisterErrorCallbackListener } }
    };
    return funMap;
}

VideoCapability MovieFileOutputImpl::GetSupportedVideoCapability(VideoCodecType videoCodecType)
{
    MEDIA_INFO_LOG("GetSupportedVideoCapability is called");
    auto Result = [](OHOS::sptr<OHOS::CameraStandard::VideoCapability> output) {
        return make_holder<VideoCapabilityImpl, VideoCapability>(output);
    };
    CHECK_RETURN_RET_ELOG(!movieFileOutput_, Result(nullptr), "movieFileOutput_ is nullptr");
    auto taiheVideoCapability = movieFileOutput_->GetSupportedVideoCapability(
        static_cast<int32_t>(videoCodecType.get_value()));
    CHECK_RETURN_RET_ELOG(!taiheVideoCapability, Result(nullptr), "supported videoCapability is null");
    return Result(taiheVideoCapability);
}

array<VideoCodecType> MovieFileOutputImpl::GetSupportedVideoCodecTypes()
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        array<VideoCodecType>(nullptr, 0), "SystemApi GetSupportedVideoCodecTypes is called!");
    if (movieFileOutput_) {
        std::vector<int32_t> codecTypes;
        movieFileOutput_->GetSupportedVideoCodecTypes(codecTypes);
        return CameraUtilsTaihe::ToTaiheArrayEnum<VideoCodecType, int32_t>(codecTypes);
    } else {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::SERVICE_FATL_ERROR,
            "GetSupportedVideoCodecTypes failed, movieFileOutput_ is nullptr");
        return array<VideoCodecType>(nullptr, 0);
    }
}

void MovieFileOutputImpl::SetOutputSettingsSync(MovieSettings const& settings)
{
    MEDIA_INFO_LOG("MovieFileOutputImpl::SetOutputSettingsSync is called");
    std::unique_ptr<MovieFileOutputTaiheAsyncContext> asyncContext =
        std::make_unique<MovieFileOutputTaiheAsyncContext>(
            "MovieFileOutputImpl::SetOutputSettingsSync",
            CameraUtilsTaihe::IncrementAndGet(movieFileOutputTaskId_));
    CHECK_RETURN_ELOG(movieFileOutput_ == nullptr, "movieFileOutput_ is nullptr");
    asyncContext->queueTask = CameraTaiheWorkerQueueKeeper::GetInstance()->
        AcquireWorkerQueueTask("MovieFileOutputImpl::SetOutputSettingsSync");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(
        asyncContext->queueTask, [&asyncContext, &settings]() {
            CHECK_RETURN_ELOG(asyncContext == nullptr, "asyncContext is nullptr");
            CHECK_RETURN_ELOG(asyncContext->objectInfo == nullptr, "MovieFileOutputImpl is nullptr");
            std::shared_ptr<OHOS::CameraStandard::MovieSettings> movieSettings =
            std::make_shared<OHOS::CameraStandard::MovieSettings>(OHOS::CameraStandard::MovieSettings {
                .videoCodecType =
                    static_cast<OHOS::CameraStandard::VideoCodecType>(settings.videoCodecType.get_value()),
                .rotation = 0,
                .isHasLocation = false,
                .location = {
                    .latitude = 0,
                    .longitude = 0,
                    .altitude = 0,
                },
                .isBFrameEnabled = settings.isBFrameEnabled,
            });
            if (settings.location.has_value()) {
                movieSettings->isHasLocation = true;
                movieSettings->location.latitude = settings.location.value().latitude;
                movieSettings->location.longitude = settings.location.value().longitude;
                movieSettings->location.altitude = settings.location.value().altitude;
            }
            if (settings.rotation.has_value()) {
                movieSettings->rotation = settings.rotation.value().get_value();
            }
            OHOS::sptr<OHOS::CameraStandard::MovieFileOutput> movieFileOutput =
                asyncContext->objectInfo->movieFileOutput_;
            CHECK_RETURN_ELOG(movieFileOutput == nullptr, "movieFileOutput is nullptr");
            asyncContext->errorCode = movieFileOutput->SetOutputSettings(movieSettings);
            MEDIA_INFO_LOG("MovieFileOutputImpl::SetOutputSettingsSync errorCode: %{public}d", asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

MovieSettings MovieFileOutputImpl::GetOutputSettings()
{
    MEDIA_INFO_LOG("MovieFileOutputImpl::GetoutputSettings is called");
    MovieSettings res {
        .videoCodecType = VideoCodecType(static_cast<VideoCodecType::key_t>(-1)),
        .rotation = optional<ImageRotation>(std::nullopt),
        .location = optional<Location>(std::nullopt),
        .isBFrameEnabled = false,
    };
    CHECK_RETURN_RET_ELOG(movieFileOutput_ == nullptr, res,
        "MovieFileOutputImpl::GetoutputSettings movieFileOutput_ is null");
    auto settings = movieFileOutput_->GetOutputSettings();
    CHECK_RETURN_RET_ELOG(settings == nullptr, res,
        "MovieFileOutputImpl::GetoutputSettings settings is null");
    Location location {
        .latitude = settings->location.latitude,
        .longitude = settings->location.longitude,
        .altitude = settings->location.altitude,
    };
    res.videoCodecType = VideoCodecType::from_value(static_cast<int32_t>(settings->videoCodecType));
    res.rotation = optional<ImageRotation>(std::in_place_t{},
        ImageRotation::from_value(static_cast<int32_t>(settings->rotation)));
    res.location = optional<Location>(std::in_place, location);
    res.isBFrameEnabled = settings->isBFrameEnabled;
    return res;
}

bool MovieFileOutputImpl::IsMirrorSupported()
{
    MEDIA_DEBUG_LOG("MovieFileOutputImpl::IsMirrorSupported is called");
    if (movieFileOutput_ == nullptr) {
        MEDIA_ERR_LOG("MovieFileOutputImpl::IsMirrorSupported get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::SERVICE_FATL_ERROR, "get native object fail");
        return false;
    }
    return movieFileOutput_->IsMirrorSupported();
}

void MovieFileOutputImpl::EnableMirror(bool enabled)
{
    if (movieFileOutput_ == nullptr) {
        MEDIA_ERR_LOG("MovieFileOutputImpl::EnableMirror get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::SERVICE_FATL_ERROR, "get native object fail");
        return;
    }
    int32_t retCode = movieFileOutput_->EnableMirror(enabled);
    CHECK_PRINT_ELOG(!CameraUtilsTaihe::CheckError(retCode),
        "MovieFileOutputImpl::EnableMirror fail %{public}d", retCode);
}

array<string> MovieFileOutputImpl::GetSupportedVideoFilters()
{
    if (movieFileOutput_ == nullptr) {
        MEDIA_ERR_LOG("MovieFileOutputImpl::GetSupportedVideoFilters get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::SERVICE_FATL_ERROR, "get native object fail");
        return {};
    }
    std::vector<std::string> supportedVideoFilters;
    int32_t retCode = movieFileOutput_->GetSupportedVideoFilters(supportedVideoFilters);
    CHECK_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), {});
    std::vector<::taihe::string> res;
    for (const auto &item : supportedVideoFilters) {
        res.emplace_back(item);
    }
    return array<string>(res);
}

VideoProfile MovieFileOutputImpl::GetActiveVideoProfile()
{
    VideoProfile res {
        .base = {
            .size = {
                .height = 0,
                .width = 0,
            },
            .format = CameraFormat(static_cast<CameraFormat::key_t>(-1)),
        },
        .frameRateRange = {
            .min = -1,
            .max = -1,
        },
    };
    CHECK_RETURN_RET_ELOG(movieFileOutput_ == nullptr, res,
        "GetActiveVideoProfile failed, movieFileOutput_ is nullptr");
    auto profile = movieFileOutput_->GetVideoProfile();
    CHECK_RETURN_RET_ELOG(profile == nullptr, res, "GetActiveVideoProfile failed, profile is nullptr");
    CameraFormat cameraFormat = CameraUtilsTaihe::ToTaiheCameraFormat(profile->GetCameraFormat());
    res.base.size.height = profile->GetSize().height;
    res.base.size.width = profile->GetSize().width;
    res.base.format = cameraFormat;
    auto frameRates = profile->GetFrameRates();
    CHECK_RETURN_RET_ELOG(frameRates.size() < 2, res, "GetActiveVideoProfile failed, frameRates is error");
    res.frameRateRange.min = frameRates[0] >= frameRates[1] ? frameRates[1] : frameRates[0];
    res.frameRateRange.max = frameRates[0] >= frameRates[1] ? frameRates[0] : frameRates[1];
    return res;
}

void MovieFileOutputImpl::AddVideoFilterSync(string_view filter, optional_view<string> param)
{
    MEDIA_ERR_LOG("MovieFileOutputImpl::AddVideoFilterSync is not suppoted!");
}

bool MovieFileOutputImpl::IsAutoDeferredVideoEnhancementEnabled()
{
    bool isEnabled = false;
    MEDIA_ERR_LOG("MovieFileOutputImpl::IsAutoDeferredVideoEnhancementEnabled is not suppoted!");
    return isEnabled;
}

void MovieFileOutputImpl::EnableAutoDeferredVideoEnhancement(bool enabled)
{
    MEDIA_ERR_LOG("MovieFileOutputImpl::EnableAutoDeferredVideoEnhancement is not suppoted!");
}

bool MovieFileOutputImpl::IsAutoDeferredVideoEnhancementSupported()
{
    bool isSupported = false;
    MEDIA_ERR_LOG("MovieFileOutputImpl::IsAutoDeferredVideoEnhancementSupported is not suppoted!");
    return isSupported;
}

void MovieFileOutputImpl::RemoveVideoFilterSync(string_view filter)
{
    MEDIA_ERR_LOG("MovieFileOutputImpl::RemoveVideoFilterSync is not suppoted!");
}

bool MovieFileOutputImpl::IsAutoVideoFrameRateSupported()
{
    bool isAutoVideoFrameRateSupported = false;
    MEDIA_ERR_LOG("MovieFileOutputImpl::IsAutoVideoFrameRateSupported is not suppoted!");
    return isAutoVideoFrameRateSupported;
}

void MovieFileOutputImpl::EnableAutoVideoFrameRate(bool enabled)
{
    MEDIA_ERR_LOG("MovieFileOutputImpl::EnableAutoVideoFrameRate is not suppoted!");
}

ImageRotation MovieFileOutputImpl::GetVideoRotation(int32_t deviceDegree)
{
    ImageRotation imageRotation = ImageRotation(static_cast<ImageRotation::key_t>(-1));
    MEDIA_ERR_LOG("MovieFileOutputImpl::GetVideoRotation is not suppoted!");
    return imageRotation;
}
} // Camera
} // Ani