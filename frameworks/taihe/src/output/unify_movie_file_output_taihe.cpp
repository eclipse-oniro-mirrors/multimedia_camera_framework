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

#include "unify_movie_file_output_taihe.h"

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
uint32_t UnifyMovieFileOutputImpl::unifyMovieFileOutputTaskId_ = CAMERA_UNIFY_MOVIE_FILE_OUTPUT_TASKID;
UnifyMovieFileOutputImpl::UnifyMovieFileOutputImpl(
    OHOS::sptr<OHOS::CameraStandard::CaptureOutput> output) : CameraOutputImpl(output)
{
    unifyMovieFileOutput_ = static_cast<OHOS::CameraStandard::UnifyMovieFileOutput*>(output.GetRefPtr());
}

void UnifyMovieFileOutputImpl::StartSync()
{
    MEDIA_DEBUG_LOG("StartSync is called");
    std::unique_ptr<UnifyMovieFileOutputTaiheAsyncContext> asyncContext =
        std::make_unique<UnifyMovieFileOutputTaiheAsyncContext>(
            "UnifyMovieFileOutputImpl::StartSync",
            CameraUtilsTaihe::IncrementAndGet(unifyMovieFileOutputTaskId_));
    CHECK_RETURN_ELOG(unifyMovieFileOutput_ == nullptr, "unifyMovieFileOutput_ is nullptr");
    asyncContext->queueTask = CameraTaiheWorkerQueueKeeper::GetInstance()->
        AcquireWorkerQueueTask("UnifyMovieFileOutputImpl::StartSync");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_RETURN_ELOG(asyncContext == nullptr, "asyncContext is nullptr");
        CHECK_RETURN_ELOG(asyncContext->objectInfo == nullptr, "UnifyMovieFileOutputImpl is nullptr");
        OHOS::sptr<OHOS::CameraStandard::UnifyMovieFileOutput> movieFileOutput =
            asyncContext->objectInfo->unifyMovieFileOutput_;
        CHECK_RETURN_ELOG(movieFileOutput == nullptr, "movieFileOutput is nullptr");
        asyncContext->errorCode = movieFileOutput->Start();
        MEDIA_INFO_LOG("UnifyMovieFileOutputImpl::StartSync errorCode: %{public}d", asyncContext->errorCode);
        CameraUtilsTaihe::CheckError(asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

void UnifyMovieFileOutputImpl::StopSync()
{
    MEDIA_DEBUG_LOG("StopSync is called");
    std::unique_ptr<UnifyMovieFileOutputTaiheAsyncContext> asyncContext =
        std::make_unique<UnifyMovieFileOutputTaiheAsyncContext>(
            "UnifyMovieFileOutputImpl::StopSync",
            CameraUtilsTaihe::IncrementAndGet(unifyMovieFileOutputTaskId_));
    CHECK_RETURN_ELOG(unifyMovieFileOutput_ == nullptr, "unifyMovieFileOutput_ is nullptr");
    asyncContext->queueTask = CameraTaiheWorkerQueueKeeper::GetInstance()->
        AcquireWorkerQueueTask("UnifyMovieFileOutputImpl::StopSync");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_RETURN_ELOG(asyncContext == nullptr, "asyncContext is nullptr");
        CHECK_RETURN_ELOG(asyncContext->objectInfo == nullptr, "UnifyMovieFileOutputImpl is nullptr");
        OHOS::sptr<OHOS::CameraStandard::UnifyMovieFileOutput> movieFileOutput =
            asyncContext->objectInfo->unifyMovieFileOutput_;
        CHECK_RETURN_ELOG(movieFileOutput == nullptr, "movieFileOutput is nullptr");
        asyncContext->errorCode = movieFileOutput->Stop();
        MEDIA_INFO_LOG("UnifyMovieFileOutputImpl::StopSync errorCode: %{public}d", asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

void UnifyMovieFileOutputImpl::PauseSync()
{
    MEDIA_DEBUG_LOG("PauseSync is called");
    std::unique_ptr<UnifyMovieFileOutputTaiheAsyncContext> asyncContext =
        std::make_unique<UnifyMovieFileOutputTaiheAsyncContext>(
            "UnifyMovieFileOutputImpl::PauseSync",
            CameraUtilsTaihe::IncrementAndGet(unifyMovieFileOutputTaskId_));
    CHECK_RETURN_ELOG(unifyMovieFileOutput_ == nullptr, "unifyMovieFileOutput_ is nullptr");
    asyncContext->queueTask = CameraTaiheWorkerQueueKeeper::GetInstance()->
        AcquireWorkerQueueTask("UnifyMovieFileOutputImpl::PauseSync");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_RETURN_ELOG(asyncContext == nullptr, "asyncContext is nullptr");
        CHECK_RETURN_ELOG(asyncContext->objectInfo == nullptr, "UnifyMovieFileOutputImpl is nullptr");
        OHOS::sptr<OHOS::CameraStandard::UnifyMovieFileOutput> movieFileOutput =
            asyncContext->objectInfo->unifyMovieFileOutput_;
        CHECK_RETURN_ELOG(movieFileOutput == nullptr, "movieFileOutput is nullptr");
        asyncContext->errorCode = movieFileOutput->Pause();
        MEDIA_INFO_LOG("UnifyMovieFileOutputImpl::PauseSync errorCode: %{public}d", asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

void UnifyMovieFileOutputImpl::ResumeSync()
{
    MEDIA_DEBUG_LOG("ResumeSync is called");
    std::unique_ptr<UnifyMovieFileOutputTaiheAsyncContext> asyncContext =
        std::make_unique<UnifyMovieFileOutputTaiheAsyncContext>(
            "UnifyMovieFileOutputImpl::ResumeSync",
            CameraUtilsTaihe::IncrementAndGet(unifyMovieFileOutputTaskId_));
    CHECK_RETURN_ELOG(unifyMovieFileOutput_ == nullptr, "unifyMovieFileOutput_ is nullptr");
    asyncContext->queueTask = CameraTaiheWorkerQueueKeeper::GetInstance()->
        AcquireWorkerQueueTask("UnifyMovieFileOutputImpl::ResumeSync");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_RETURN_ELOG(asyncContext == nullptr, "asyncContext is nullptr");
        CHECK_RETURN_ELOG(asyncContext->objectInfo == nullptr, "UnifyMovieFileOutputImpl is nullptr");
        OHOS::sptr<OHOS::CameraStandard::UnifyMovieFileOutput> movieFileOutput =
            asyncContext->objectInfo->unifyMovieFileOutput_;
        CHECK_RETURN_ELOG(movieFileOutput == nullptr, "movieFileOutput is nullptr");
        asyncContext->errorCode = movieFileOutput->Resume();
        MEDIA_INFO_LOG("UnifyMovieFileOutputImpl::ResumeSync errorCode: %{public}d", asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

void UnifyMovieFileOutputImpl::OnError(callback_view<void(uintptr_t err)> callback)
{
    ListenerTemplate<UnifyMovieFileOutputImpl>::On(this, callback, CONST_UNIFY_MOVIE_FILE_RECORDING_ERROR);
}

void UnifyMovieFileOutputImpl::OffError(optional_view<callback<void(uintptr_t err)>> callback)
{
    ListenerTemplate<UnifyMovieFileOutputImpl>::Off(this, callback, CONST_UNIFY_MOVIE_FILE_RECORDING_ERROR);
}

void UnifyMovieFileOutputCallbackListener::OnError(int32_t errorCode)
{
    MEDIA_DEBUG_LOG("OnError is called, errorCode: %{public}d", errorCode);
    OnErrorCallback(errorCode);
}

void UnifyMovieFileOutputCallbackListener::OnErrorCallback(int32_t errorCode) const
{
    MEDIA_DEBUG_LOG("OnErrorCallback is called, errorCode: %{public}d", errorCode);
    auto sharePtr = shared_from_this();
    auto task = [errorCode, sharePtr]() {
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteErrorCallback(CONST_UNIFY_MOVIE_FILE_RECORDING_ERROR, errorCode));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnError", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void UnifyMovieFileOutputImpl::RegisterErrorCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    if (movieFileOutputCallback_ == nullptr) {
        ani_env *env = get_env();
        movieFileOutputCallback_ = std::make_shared<UnifyMovieFileOutputCallbackListener>(env);
        CHECK_RETURN_ELOG(unifyMovieFileOutput_ == nullptr,
            "UnifyMovieFileOutputImpl::RegisterErrorCallbackListener unifyMovieFileOutput_ is null");
        unifyMovieFileOutput_->AddUnifyMovieFileOutputStateCallback(movieFileOutputCallback_);
    }
    movieFileOutputCallback_->SaveCallbackReference(CONST_UNIFY_MOVIE_FILE_RECORDING_ERROR, callback, isOnce);
}

void UnifyMovieFileOutputImpl::UnregisterErrorCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    if (movieFileOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("movieFileOutputCallback_ is nullptr");
        return;
    }
    movieFileOutputCallback_->RemoveCallbackRef(CONST_UNIFY_MOVIE_FILE_RECORDING_ERROR, callback);
}

void UnifyMovieFileOutputImpl::OnRecordingResume(callback_view<void(uintptr_t err, int32_t data)> callback)
{
    ListenerTemplate<UnifyMovieFileOutputImpl>::On(this, callback, CONST_UNIFY_MOVIE_FILE_RECORDING_RESUME);
}

void UnifyMovieFileOutputImpl::OffRecordingResume(optional_view<callback<void(uintptr_t err, int32_t data)>> callback)
{
    ListenerTemplate<UnifyMovieFileOutputImpl>::Off(this, callback, CONST_UNIFY_MOVIE_FILE_RECORDING_RESUME);
}

void UnifyMovieFileOutputCallbackListener::OnResume()
{
    MEDIA_DEBUG_LOG("UnifyMovieFileOutputCallbackListener::OnRecordingResume is called");
    OnRecordingResumeCallback();
}

void UnifyMovieFileOutputCallbackListener::OnRecordingResumeCallback() const
{
    MEDIA_DEBUG_LOG("OnRecordingResumeCallback is called");
    auto sharePtr = shared_from_this();
    auto task = [sharePtr]() {
        int32_t data = 0;
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback(CONST_UNIFY_MOVIE_FILE_RECORDING_RESUME, 0, "Callback is OK", data));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnRecordingResume", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void UnifyMovieFileOutputImpl::RegisterRecordingResumeCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    if (movieFileOutputCallback_ == nullptr) {
        ani_env *env = get_env();
        movieFileOutputCallback_ = std::make_shared<UnifyMovieFileOutputCallbackListener>(env);
        CHECK_RETURN_ELOG(unifyMovieFileOutput_ == nullptr,
            "UnifyMovieFileOutputImpl::RegisterRecordingResumeCallbackListener unifyMovieFileOutput_ is null");
        unifyMovieFileOutput_->AddUnifyMovieFileOutputStateCallback(movieFileOutputCallback_);
    }
    movieFileOutputCallback_->SaveCallbackReference(CONST_UNIFY_MOVIE_FILE_RECORDING_RESUME, callback, isOnce);
}

void UnifyMovieFileOutputImpl::UnregisterRecordingResumeCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    if (movieFileOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("movieFileOutputCallback_ is nullptr");
        return;
    }
    movieFileOutputCallback_->RemoveCallbackRef(CONST_UNIFY_MOVIE_FILE_RECORDING_RESUME, callback);
}

void UnifyMovieFileOutputImpl::OnRecordingStart(callback_view<void(uintptr_t err, int32_t data)> callback)
{
    ListenerTemplate<UnifyMovieFileOutputImpl>::On(this, callback, CONST_UNIFY_MOVIE_FILE_RECORDING_START);
}

void UnifyMovieFileOutputImpl::OffRecordingStart(optional_view<callback<void(uintptr_t err, int32_t data)>> callback)
{
    ListenerTemplate<UnifyMovieFileOutputImpl>::Off(this, callback, CONST_UNIFY_MOVIE_FILE_RECORDING_START);
}

void UnifyMovieFileOutputCallbackListener::OnStart()
{
    MEDIA_DEBUG_LOG("UnifyMovieFileOutputCallbackListener::OnRecordingStart is called");
    OnRecordingStartCallback();
}

void UnifyMovieFileOutputCallbackListener::OnRecordingStartCallback() const
{
    MEDIA_DEBUG_LOG("OnRecordingStartCallback is called");
    auto sharePtr = shared_from_this();
    auto task = [sharePtr]() {
        int32_t data = 0;
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback(CONST_UNIFY_MOVIE_FILE_RECORDING_START, 0, "Callback is OK", data));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnRecordingStart", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void UnifyMovieFileOutputImpl::RegisterRecordingStartCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    if (movieFileOutputCallback_ == nullptr) {
        ani_env *env = get_env();
        movieFileOutputCallback_ = std::make_shared<UnifyMovieFileOutputCallbackListener>(env);
        CHECK_RETURN_ELOG(unifyMovieFileOutput_ == nullptr,
            "UnifyMovieFileOutputImpl::RegisterRecordingStartCallbackListener unifyMovieFileOutput_ is null");
        unifyMovieFileOutput_->AddUnifyMovieFileOutputStateCallback(movieFileOutputCallback_);
    }
    movieFileOutputCallback_->SaveCallbackReference(CONST_UNIFY_MOVIE_FILE_RECORDING_START, callback, isOnce);
}

void UnifyMovieFileOutputImpl::UnregisterRecordingStartCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    if (movieFileOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("movieFileOutputCallback_ is nullptr");
        return;
    }
    movieFileOutputCallback_->RemoveCallbackRef(CONST_UNIFY_MOVIE_FILE_RECORDING_START, callback);
}

void UnifyMovieFileOutputImpl::OnRecordingStop(callback_view<void(uintptr_t err, int32_t data)> callback)
{
    ListenerTemplate<UnifyMovieFileOutputImpl>::On(this, callback, CONST_UNIFY_MOVIE_FILE_RECORDING_STOP);
}

void UnifyMovieFileOutputImpl::OffRecordingStop(optional_view<callback<void(uintptr_t err, int32_t data)>> callback)
{
    ListenerTemplate<UnifyMovieFileOutputImpl>::Off(this, callback, CONST_UNIFY_MOVIE_FILE_RECORDING_STOP);
}

void UnifyMovieFileOutputCallbackListener::OnStop()
{
    MEDIA_DEBUG_LOG("UnifyMovieFileOutputCallbackListener::OnRecordingStop is called");
    OnRecordingStopCallback();
}

void UnifyMovieFileOutputCallbackListener::OnRecordingStopCallback() const
{
    MEDIA_DEBUG_LOG("OnRecordingStopCallback is called");
    auto sharePtr = shared_from_this();
    auto task = [sharePtr]() {
        int32_t data = 0;
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback(CONST_UNIFY_MOVIE_FILE_RECORDING_STOP, 0, "Callback is OK", data));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnRecordingStop", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void UnifyMovieFileOutputImpl::RegisterRecordingStopCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    if (movieFileOutputCallback_ == nullptr) {
        ani_env *env = get_env();
        movieFileOutputCallback_ = std::make_shared<UnifyMovieFileOutputCallbackListener>(env);
        CHECK_RETURN_ELOG(unifyMovieFileOutput_ == nullptr,
            "UnifyMovieFileOutputImpl::RegisterRecordingStopCallbackListener unifyMovieFileOutput_ is null");
        unifyMovieFileOutput_->AddUnifyMovieFileOutputStateCallback(movieFileOutputCallback_);
    }
    movieFileOutputCallback_->SaveCallbackReference(CONST_UNIFY_MOVIE_FILE_RECORDING_STOP, callback, isOnce);
}

void UnifyMovieFileOutputImpl::UnregisterRecordingStopCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    if (movieFileOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("movieFileOutputCallback_ is nullptr");
        return;
    }
    movieFileOutputCallback_->RemoveCallbackRef(CONST_UNIFY_MOVIE_FILE_RECORDING_STOP, callback);
}

void UnifyMovieFileOutputImpl::OnRecordingPause(callback_view<void(uintptr_t err, int32_t data)> callback)
{
    ListenerTemplate<UnifyMovieFileOutputImpl>::On(this, callback, CONST_UNIFY_MOVIE_FILE_RECORDING_PAUSE);
}

void UnifyMovieFileOutputImpl::OffRecordingPause(optional_view<callback<void(uintptr_t err, int32_t data)>> callback)
{
    ListenerTemplate<UnifyMovieFileOutputImpl>::Off(this, callback, CONST_UNIFY_MOVIE_FILE_RECORDING_PAUSE);
}

void UnifyMovieFileOutputCallbackListener::OnPause()
{
    MEDIA_DEBUG_LOG("UnifyMovieFileOutputCallbackListener::OnRecordingPause is called");
    OnRecordingPauseCallback();
}

void UnifyMovieFileOutputCallbackListener::OnRecordingPauseCallback() const
{
    MEDIA_DEBUG_LOG("OnRecordingPauseCallback is called");
    auto sharePtr = shared_from_this();
    auto task = [sharePtr]() {
        int32_t data = 0;
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback(CONST_UNIFY_MOVIE_FILE_RECORDING_PAUSE, 0, "Callback is OK", data));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnRecordingPause", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void UnifyMovieFileOutputImpl::RegisterRecordingPauseCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    if (movieFileOutputCallback_ == nullptr) {
        ani_env *env = get_env();
        movieFileOutputCallback_ = std::make_shared<UnifyMovieFileOutputCallbackListener>(env);
        CHECK_RETURN_ELOG(unifyMovieFileOutput_ == nullptr,
            "UnifyMovieFileOutputImpl::RegisterRecordingPauseCallbackListener unifyMovieFileOutput_ is null");
        unifyMovieFileOutput_->AddUnifyMovieFileOutputStateCallback(movieFileOutputCallback_);
    }
    movieFileOutputCallback_->SaveCallbackReference(CONST_UNIFY_MOVIE_FILE_RECORDING_PAUSE, callback, isOnce);
}

void UnifyMovieFileOutputImpl::UnregisterRecordingPauseCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    if (movieFileOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("movieFileOutputCallback_ is nullptr");
        return;
    }
    movieFileOutputCallback_->RemoveCallbackRef(CONST_UNIFY_MOVIE_FILE_RECORDING_PAUSE, callback);
}

void UnifyMovieFileOutputImpl::OnMovieInfoAvailable(callback_view<void(uintptr_t err, MovieInfo const& data)> callback)
{
    ListenerTemplate<UnifyMovieFileOutputImpl>::On(this, callback, CONST_UNIFY_MOVIE_FILE_MOVIE_INFO_AVAILABLE);
}

void UnifyMovieFileOutputImpl::OffMovieInfoAvailable(
    optional_view<callback<void(uintptr_t err, MovieInfo const& data)>> callback)
{
    ListenerTemplate<UnifyMovieFileOutputImpl>::Off(this, callback, CONST_UNIFY_MOVIE_FILE_MOVIE_INFO_AVAILABLE);
}

void UnifyMovieFileOutputCallbackListener::OnMovieInfoAvailable(int32_t captureId, std::string uri)
{
    MEDIA_DEBUG_LOG("UnifyMovieFileOutputCallbackListener::OnPhotoAssetAvailable is called");
    OnMovieInfoAvailableCallback(captureId, uri);
}

void UnifyMovieFileOutputCallbackListener::OnMovieInfoAvailableCallback(int32_t captureId, const std::string &uri) const
{
    MEDIA_INFO_LOG("UnifyMovieFileOutputCallbackListener::OnPhotoAssetAvailableCallback called");
    constexpr int32_t cameraShotType = 1;
    ani_object photoAssetValue =
        Media::MediaLibraryCommAni::CreatePhotoAssetAni(get_env(), uri, cameraShotType);
    uintptr_t taihephotoAsset = reinterpret_cast<uintptr_t>(photoAssetValue);
    MovieInfo taiheMovieInfo = {
        captureId,
        optional<uintptr_t>::make(taihephotoAsset)
    };
    auto sharePtr = shared_from_this();
    auto task = [taiheMovieInfo, sharePtr]() {
        CHECK_EXECUTE(sharePtr != nullptr, sharePtr->ExecuteAsyncCallback(
            CONST_UNIFY_MOVIE_FILE_MOVIE_INFO_AVAILABLE, 0, "success", taiheMovieInfo));
    };
    mainHandler_->PostTask(task, "OnMovieInfoAvailable", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void UnifyMovieFileOutputImpl::RegisterPhotoAssetAvailableCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    if (movieFileOutputCallback_ == nullptr) {
        ani_env *env = get_env();
        movieFileOutputCallback_ = std::make_shared<UnifyMovieFileOutputCallbackListener>(env);
        CHECK_RETURN_ELOG(unifyMovieFileOutput_ == nullptr,
            "UnifyMovieFileOutputImpl::RegisterPhotoAssetAvailableCallbackListener unifyMovieFileOutput_ is null");
        unifyMovieFileOutput_->AddUnifyMovieFileOutputStateCallback(movieFileOutputCallback_);
    }
    movieFileOutputCallback_->SaveCallbackReference(CONST_UNIFY_MOVIE_FILE_MOVIE_INFO_AVAILABLE, callback, isOnce);
}

void UnifyMovieFileOutputImpl::UnregisterPhotoAssetAvailableCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    if (movieFileOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("movieFileOutputCallback_ is nullptr");
        return;
    }
    movieFileOutputCallback_->RemoveCallbackRef(CONST_UNIFY_MOVIE_FILE_MOVIE_INFO_AVAILABLE, callback);
}

const UnifyMovieFileOutputImpl::EmitterFunctions& UnifyMovieFileOutputImpl::GetEmitterFunctions()
{
    static const EmitterFunctions funMap = {
        { CONST_UNIFY_MOVIE_FILE_RECORDING_START, {
            &UnifyMovieFileOutputImpl::RegisterRecordingStartCallbackListener,
            &UnifyMovieFileOutputImpl::UnregisterRecordingStartCallbackListener } },
        { CONST_UNIFY_MOVIE_FILE_RECORDING_PAUSE, {
            &UnifyMovieFileOutputImpl::RegisterRecordingPauseCallbackListener,
            &UnifyMovieFileOutputImpl::UnregisterRecordingPauseCallbackListener } },
        { CONST_UNIFY_MOVIE_FILE_RECORDING_RESUME, {
            &UnifyMovieFileOutputImpl::RegisterRecordingResumeCallbackListener,
            &UnifyMovieFileOutputImpl::UnregisterRecordingResumeCallbackListener } },
        { CONST_UNIFY_MOVIE_FILE_RECORDING_STOP, {
            &UnifyMovieFileOutputImpl::RegisterRecordingStopCallbackListener,
            &UnifyMovieFileOutputImpl::UnregisterRecordingStopCallbackListener } },
        { CONST_UNIFY_MOVIE_FILE_MOVIE_INFO_AVAILABLE, {
            &UnifyMovieFileOutputImpl::RegisterPhotoAssetAvailableCallbackListener,
            &UnifyMovieFileOutputImpl::UnregisterPhotoAssetAvailableCallbackListener } },
        { CONST_UNIFY_MOVIE_FILE_RECORDING_ERROR, {
            &UnifyMovieFileOutputImpl::RegisterErrorCallbackListener,
            &UnifyMovieFileOutputImpl::UnregisterErrorCallbackListener } }
    };
    return funMap;
}

VideoCapability UnifyMovieFileOutputImpl::GetSupportedVideoCapability(VideoCodecType videoCodecType)
{
    MEDIA_INFO_LOG("GetSupportedVideoCapability is called");
    auto Result = [](OHOS::sptr<OHOS::CameraStandard::VideoCapability> output) {
        return make_holder<VideoCapabilityImpl, VideoCapability>(output);
    };
    CHECK_RETURN_RET_ELOG(unifyMovieFileOutput_ == nullptr, Result(nullptr),
        "GetSupportedVideoCapability failed, unifyMovieFileOutput_ is nullptr");
    auto taiheVideoCapability = unifyMovieFileOutput_->GetSupportedVideoCapability(
        static_cast<int32_t>(videoCodecType.get_value()));
    if (taiheVideoCapability == nullptr) {
        return Result(nullptr);
    }
    return Result(taiheVideoCapability);
}

array<VideoCodecType> UnifyMovieFileOutputImpl::GetSupportedVideoCodecTypes()
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        array<VideoCodecType>(nullptr, 0), "SystemApi GetSupportedVideoCodecTypes is called!");
    if (unifyMovieFileOutput_) {
        std::vector<int32_t> codecTypes;
        unifyMovieFileOutput_->GetSupportedVideoCodecTypes(codecTypes);
        return CameraUtilsTaihe::ToTaiheArrayEnum<VideoCodecType, int32_t>(codecTypes);
    } else {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::SERVICE_FATL_ERROR,
            "GetSupportedVideoCodecTypes failed, unifyMovieFileOutput_ is nullptr");
        return array<VideoCodecType>(nullptr, 0);
    }
}

void UnifyMovieFileOutputImpl::SetOutputSettingsSync(MovieSettings const& settings)
{
    MEDIA_INFO_LOG("UnifyMovieFileOutputImpl::SetOutputSettingsSync is called");
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi SetOutputSettingsSync is called!");
    std::unique_ptr<UnifyMovieFileOutputTaiheAsyncContext> asyncContext =
        std::make_unique<UnifyMovieFileOutputTaiheAsyncContext>(
            "UnifyMovieFileOutputImpl::SetOutputSettingsSync",
                CameraUtilsTaihe::IncrementAndGet(unifyMovieFileOutputTaskId_));
    CHECK_RETURN_ELOG(unifyMovieFileOutput_ == nullptr, "unifyMovieFileOutput_ is nullptr");
    asyncContext->queueTask = CameraTaiheWorkerQueueKeeper::GetInstance()->
        AcquireWorkerQueueTask("UnifyMovieFileOutputImpl::SetOutputSettingsSync");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(
        asyncContext->queueTask, [&asyncContext, &settings]() {
            CHECK_RETURN_ELOG(asyncContext == nullptr, "asyncContext is nullptr");
            CHECK_RETURN_ELOG(asyncContext->objectInfo == nullptr, "UnifyMovieFileOutputImpl is nullptr");
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
                movieSettings->rotation = settings.rotation.value();
            }
            OHOS::sptr<OHOS::CameraStandard::UnifyMovieFileOutput> movieFileOutput =
                asyncContext->objectInfo->unifyMovieFileOutput_;
            CHECK_RETURN_ELOG(movieFileOutput == nullptr, "movieFileOutput is nullptr");
            asyncContext->errorCode = movieFileOutput->SetOutputSettings(movieSettings);
            MEDIA_INFO_LOG("UnifyMovieFileOutputImpl::SetOutputSettingsSync errorCode: %{public}d",
                asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

MovieSettings UnifyMovieFileOutputImpl::GetOutputSettings()
{
    MEDIA_INFO_LOG("UnifyMovieFileOutputImpl::GetoutputSettings is called");
    MovieSettings res {
        .videoCodecType = VideoCodecType(static_cast<VideoCodecType::key_t>(-1)),
        .rotation = optional<ImageRotation>(std::in_place_t{},
            ImageRotation(static_cast<ImageRotation::key_t>(-1))),
        .location = optional<Location>(std::nullopt),
        .isBFrameEnabled = false,
    };
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), res,
        "SystemApi GetoutputSettings is called!");
    CHECK_RETURN_RET_ELOG(unifyMovieFileOutput_ == nullptr, res,
        "UnifyMovieFileOutputImpl::GetoutputSettings unifyMovieFileOutput_ is null");
    auto settings = unifyMovieFileOutput_->GetOutputSettings();
    CHECK_RETURN_RET_ELOG(settings == nullptr, res,
        "UnifyMovieFileOutputImpl::GetoutputSettings settings is null");
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

bool UnifyMovieFileOutputImpl::IsMirrorSupported()
{
    MEDIA_DEBUG_LOG("UnifyMovieFileOutputImpl::IsMirrorSupported is called");
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), false,
        "SystemApi IsMirrorSupported is called!");
    if (unifyMovieFileOutput_ == nullptr) {
        MEDIA_ERR_LOG("UnifyMovieFileOutputImpl::IsMirrorSupported get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::SERVICE_FATL_ERROR, "get native object fail");
        return false;
    }
    return unifyMovieFileOutput_->IsMirrorSupported();
}

void UnifyMovieFileOutputImpl::EnableMirror(bool enabled)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi EnableMirror is called!");
    if (unifyMovieFileOutput_ == nullptr) {
        MEDIA_ERR_LOG("UnifyMovieFileOutputImpl::EnableMirror get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::SERVICE_FATL_ERROR, "get native object fail");
        return;
    }
    int32_t retCode = unifyMovieFileOutput_->EnableMirror(enabled);
    CHECK_PRINT_ELOG(!CameraUtilsTaihe::CheckError(retCode),
        "UnifyMovieFileOutputImpl::EnableMirror fail %{public}d", retCode);
}

array<string> UnifyMovieFileOutputImpl::GetSupportedVideoFilters()
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), {},
        "SystemApi GetSupportedVideoFilters is called!");
    if (unifyMovieFileOutput_ == nullptr) {
        MEDIA_ERR_LOG("UnifyMovieFileOutputImpl::GetSupportedVideoFilters get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::SERVICE_FATL_ERROR, "get native object fail");
        return {};
    }
    std::vector<std::string> supportedVideoFilters;
    int32_t retCode = unifyMovieFileOutput_->GetSupportedVideoFilters(supportedVideoFilters);
    CHECK_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), {});
    std::vector<::taihe::string> res;
    for (const auto &item : supportedVideoFilters) {
        res.emplace_back(item);
    }
    return array<string>(res);
}

VideoProfile UnifyMovieFileOutputImpl::GetActiveVideoProfile()
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
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), res,
        "SystemApi GetActiveVideoProfile is called!");
    CHECK_RETURN_RET_ELOG(unifyMovieFileOutput_ == nullptr, res,
        "GetActiveVideoProfile failed, unifyMovieFileOutput_ is nullptr");
    auto profile = unifyMovieFileOutput_->GetVideoProfile();
    CHECK_RETURN_RET_ELOG(profile == nullptr, res, "GetActiveVideoProfile failed, profile is nullptr");
    CameraFormat cameraFormat = CameraFormat::from_value(static_cast<int32_t>(profile->GetCameraFormat()));
    res.base.size.height = profile->GetSize().height;
    res.base.size.width = profile->GetSize().width;
    res.base.format = cameraFormat;
    auto frameRates = profile->GetFrameRates();
    CHECK_RETURN_RET_ELOG(frameRates.size() < 2, res, "GetActiveVideoProfile failed, frameRates is error");
    res.frameRateRange.min = frameRates[0] >= frameRates[1] ? frameRates[1] : frameRates[0];
    res.frameRateRange.max = frameRates[0] >= frameRates[1] ? frameRates[0] : frameRates[1];
    return res;
}

void UnifyMovieFileOutputImpl::AddVideoFilterSync(string_view filter, optional_view<string> param)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi AddVideoFilterSync is called!");
    std::string filterParam = "";
    if (param.has_value()) {
        filterParam = std::string(param.value());
    }
    CHECK_RETURN_ELOG(unifyMovieFileOutput_ == nullptr,
        "UnifyMovieFileOutputImpl::AddVideoFilterSync unifyMovieFileOutput_ is null");
    std::unique_ptr<UnifyMovieFileOutputTaiheAsyncContext> asyncContext =
        std::make_unique<UnifyMovieFileOutputTaiheAsyncContext>(
            "UnifyMovieFileOutputImpl::AddVideoFilterSync",
                CameraUtilsTaihe::IncrementAndGet(unifyMovieFileOutputTaskId_));
    CHECK_RETURN_ELOG(unifyMovieFileOutput_ == nullptr, "unifyMovieFileOutput_ is nullptr");
    asyncContext->queueTask = CameraTaiheWorkerQueueKeeper::GetInstance()->
        AcquireWorkerQueueTask("UnifyMovieFileOutputImpl::AddVideoFilterSync");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(
        asyncContext->queueTask, [&asyncContext, &filter, &filterParam]() {
            CHECK_RETURN_ELOG(asyncContext == nullptr, "asyncContext is nullptr");
            CHECK_RETURN_ELOG(asyncContext->objectInfo == nullptr, "UnifyMovieFileOutputImpl is nullptr");
            OHOS::sptr<OHOS::CameraStandard::UnifyMovieFileOutput> movieFileOutput =
                asyncContext->objectInfo->unifyMovieFileOutput_;
            CHECK_RETURN_ELOG(movieFileOutput == nullptr, "movieFileOutput is nullptr");
            asyncContext->errorCode = movieFileOutput->AddVideoFilter(std::string(filter), filterParam);
            CHECK_PRINT_ELOG(!CameraUtilsTaihe::CheckError(asyncContext->errorCode),
                "UnifyMovieFileOutputImpl::AddVideoFilterSync fail %{public}d", asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

bool UnifyMovieFileOutputImpl::IsAutoDeferredVideoEnhancementEnabled()
{
    bool isEnabled = false;
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), isEnabled,
        "SystemApi IsAutoDeferredVideoEnhancementEnabled is called!");
    CHECK_RETURN_RET_ELOG(unifyMovieFileOutput_ == nullptr, isEnabled,
        "IsAutoDeferredVideoEnhancementEnabled failed, unifyMovieFileOutput_ is nullptr");
    int32_t retCode = unifyMovieFileOutput_->IsAutoDeferredVideoEnhancementEnabled(isEnabled);
    CHECK_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), isEnabled);
    return isEnabled;
}

void UnifyMovieFileOutputImpl::EnableAutoDeferredVideoEnhancement(bool enabled)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi EnableAutoDeferredVideoEnhancement is called!");
    CHECK_RETURN_ELOG(unifyMovieFileOutput_ == nullptr,
        "UnifyMovieFileOutputImpl::EnableAutoDeferredVideoEnhancement unifyMovieFileOutput_ is null");
    int32_t retCode = unifyMovieFileOutput_->EnableAutoDeferredVideoEnhancement(enabled);
    CHECK_PRINT_ELOG(!CameraUtilsTaihe::CheckError(retCode),
        "UnifyMovieFileOutputImpl::EnableAutoDeferredVideoEnhancement fail %{public}d", retCode);
}

bool UnifyMovieFileOutputImpl::IsAutoDeferredVideoEnhancementSupported()
{
    bool isSupported = false;
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), isSupported,
        "SystemApi IsAutoDeferredVideoEnhancementSupported is called!");
    CHECK_RETURN_RET_ELOG(unifyMovieFileOutput_ == nullptr, isSupported,
        "IsAutoDeferredVideoEnhancementSupported failed, unifyMovieFileOutput_ is nullptr");
    int32_t retCode = unifyMovieFileOutput_->IsAutoDeferredVideoEnhancementSupported(isSupported);
    CHECK_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), isSupported);
    return isSupported;
}

void UnifyMovieFileOutputImpl::RemoveVideoFilterSync(string_view filter)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi RemoveVideoFilterSync is called!");
    CHECK_RETURN_ELOG(unifyMovieFileOutput_ == nullptr,
        "UnifyMovieFileOutputImpl::RemoveVideoFilterSync unifyMovieFileOutput_ is null");
    std::unique_ptr<UnifyMovieFileOutputTaiheAsyncContext> asyncContext =
        std::make_unique<UnifyMovieFileOutputTaiheAsyncContext>(
            "UnifyMovieFileOutputImpl::RemoveVideoFilterSync",
                CameraUtilsTaihe::IncrementAndGet(unifyMovieFileOutputTaskId_));
    asyncContext->queueTask = CameraTaiheWorkerQueueKeeper::GetInstance()->
        AcquireWorkerQueueTask("UnifyMovieFileOutputImpl::RemoveVideoFilterSync");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(
        asyncContext->queueTask, [&asyncContext, &filter]() {
            CHECK_RETURN_ELOG(asyncContext == nullptr, "asyncContext is nullptr");
            CHECK_RETURN_ELOG(asyncContext->objectInfo == nullptr, "UnifyMovieFileOutputImpl is nullptr");
            OHOS::sptr<OHOS::CameraStandard::UnifyMovieFileOutput> movieFileOutput =
                asyncContext->objectInfo->unifyMovieFileOutput_;
            CHECK_RETURN_ELOG(movieFileOutput == nullptr, "movieFileOutput is nullptr");
            asyncContext->errorCode = movieFileOutput->RemoveVideoFilter(std::string(filter));
            CHECK_PRINT_ELOG(!CameraUtilsTaihe::CheckError(asyncContext->errorCode),
                "UnifyMovieFileOutputImpl::RemoveVideoFilterSync fail %{public}d", asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

bool UnifyMovieFileOutputImpl::IsAutoVideoFrameRateSupported()
{
    bool isAutoVideoFrameRateSupported = false;
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), isAutoVideoFrameRateSupported,
        "SystemApi IsAutoVideoFrameRateSupported is called!");
    CHECK_RETURN_RET_ELOG(unifyMovieFileOutput_ == nullptr, isAutoVideoFrameRateSupported,
        "IsAutoVideoFrameRateSupported failed, unifyMovieFileOutput_ is nullptr");
    isAutoVideoFrameRateSupported = unifyMovieFileOutput_->IsAutoVideoFrameRateSupported();
    return isAutoVideoFrameRateSupported;
}

void UnifyMovieFileOutputImpl::EnableAutoVideoFrameRate(bool enabled)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi EnableAutoVideoFrameRate is called!");
    CHECK_RETURN_ELOG(unifyMovieFileOutput_ == nullptr,
        "UnifyMovieFileOutputImpl::EnableAutoVideoFrameRate unifyMovieFileOutput_ is null");
    int32_t retCode = unifyMovieFileOutput_->EnableAutoVideoFrameRate(enabled);
    CHECK_PRINT_ELOG(!CameraUtilsTaihe::CheckError(retCode),
        "UnifyMovieFileOutputImpl::EnableAutoVideoFrameRate fail %{public}d", retCode);
}

ImageRotation UnifyMovieFileOutputImpl::GetVideoRotation(int32_t deviceDegree)
{
    ImageRotation imageRotation = ImageRotation::from_value(static_cast<int32_t>(-1));
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        imageRotation, "SystemApi GetVideoRotation is called!");
    CHECK_RETURN_RET_ELOG(unifyMovieFileOutput_ == nullptr, imageRotation,
        "GetVideoRotation failed, unifyMovieFileOutput_ is nullptr");
    int32_t retCode = unifyMovieFileOutput_->GetVideoRotation(deviceDegree);
    CHECK_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), imageRotation);
    imageRotation = ImageRotation::from_value(static_cast<int32_t>(deviceDegree));
    return imageRotation;
}
} // Camera
} // Ani
