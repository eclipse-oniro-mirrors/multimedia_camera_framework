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
#include "video_output_taihe.h"
#include "camera_utils_taihe.h"
#include "camera_log.h"
#include "camera_template_utils_taihe.h"
#include "camera_error_code.h"
#include "camera_event_emitter_taihe.h"

using namespace taihe;
using namespace ohos::multimedia::camera;
using namespace OHOS;
using namespace std;

namespace Ani {
namespace Camera {
uint32_t VideoOutputImpl::videoOutputTaskId_ = CAMERA_VIDEO_OUTPUT_TASKID;
VideoOutputImpl::VideoOutputImpl(sptr<OHOS::CameraStandard::CaptureOutput> output) : CameraOutputImpl(output)
{
    videoOutput_ = static_cast<OHOS::CameraStandard::VideoOutput*>(output.GetRefPtr());
}

void VideoOutputImpl::StartSync()
{
    MEDIA_DEBUG_LOG("StartSync is called");
    std::unique_ptr<VideoOutputTaiheAsyncContext> asyncContext = std::make_unique<VideoOutputTaiheAsyncContext>(
        "VideoOutputImpl::StartSync", CameraUtilsTaihe::IncrementAndGet(videoOutputTaskId_));
    CHECK_ERROR_RETURN_LOG(videoOutput_ == nullptr, "videoOutput_ is nullptr");
    asyncContext->queueTask =
        CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("VideoOutputImpl::StartSync");
    asyncContext->objectInfo = std::make_shared<VideoOutputImpl>(videoOutput_);
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_ERROR_RETURN_LOG(asyncContext->objectInfo == nullptr, "videoOutput_ is nullptr");
        asyncContext->errorCode = asyncContext->objectInfo->videoOutput_->Start();
        CameraUtilsTaihe::CheckError(asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

void VideoOutputImpl::StopSync()
{
    MEDIA_DEBUG_LOG("StopSync is called");
    std::unique_ptr<VideoOutputTaiheAsyncContext> asyncContext = std::make_unique<VideoOutputTaiheAsyncContext>(
        "VideoOutputImpl::StopSync", CameraUtilsTaihe::IncrementAndGet(videoOutputTaskId_));
    CHECK_ERROR_RETURN_LOG(videoOutput_ == nullptr, "videoOutput_ is nullptr");
    asyncContext->queueTask =
        CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("VideoOutputImpl::StopSync");
    asyncContext->objectInfo = std::make_shared<VideoOutputImpl>(videoOutput_);
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_ERROR_RETURN_LOG(asyncContext->objectInfo == nullptr, "videoOutput_ is nullptr");
        asyncContext->errorCode = asyncContext->objectInfo->videoOutput_->Stop();
        CameraUtilsTaihe::CheckError(asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

void VideoOutputImpl::ReleaseSync()
{
    MEDIA_DEBUG_LOG("ReleaseSync is called");
    std::unique_ptr<VideoOutputTaiheAsyncContext> asyncContext = std::make_unique<VideoOutputTaiheAsyncContext>(
        "VideoOutputImpl::ReleaseSync", CameraUtilsTaihe::IncrementAndGet(videoOutputTaskId_));
    CHECK_ERROR_RETURN_LOG(videoOutput_ == nullptr, "videoOutput_ is nullptr");
    asyncContext->queueTask =
        CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("VideoOutputImpl::ReleaseSync");
    asyncContext->objectInfo = std::make_shared<VideoOutputImpl>(videoOutput_);
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_ERROR_RETURN_LOG(asyncContext->objectInfo == nullptr, "videoOutput_ is nullptr");
        asyncContext->errorCode = asyncContext->objectInfo->videoOutput_->Release();
        CameraUtilsTaihe::CheckError(asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

void VideoCallbackListener::OnError(int32_t errorCode) const
{
    MEDIA_DEBUG_LOG("OnError is called, errorCode: %{public}d", errorCode);
    OnErrorCallback(errorCode);
}

void VideoCallbackListener::OnErrorCallback(int32_t errorCode) const
{
    MEDIA_INFO_LOG("OnErrorCallback is called, errorCode: %{public}d", errorCode);
    auto sharePtr = shared_from_this();
    auto task = [errorCode, sharePtr]() {
        CHECK_EXECUTE(sharePtr != nullptr, sharePtr->ExecuteErrorCallback("error", errorCode));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnError", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void VideoCallbackListener::OnFrameStarted() const
{
    MEDIA_DEBUG_LOG("OnFrameStarted is called");
    OnFrameStartedCallback();
}

void VideoCallbackListener::OnFrameStartedCallback() const
{
    MEDIA_DEBUG_LOG("OnFrameStartedCallback is called");
    auto sharePtr = shared_from_this();
    auto task = [sharePtr, this]() {
        uintptr_t undefined = CameraUtilsTaihe::GetUndefined(get_env());
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback("frameStart", 0, "Callback is OK", undefined));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnFrameStart", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void VideoCallbackListener::OnFrameEnded(const int32_t frameCount) const
{
    MEDIA_DEBUG_LOG("OnFrameEnded is called, frameCount: %{public}d", frameCount);
    OnFrameEndedCallback(frameCount);
}

void VideoCallbackListener::OnFrameEndedCallback(const int32_t frameCount) const
{
    MEDIA_DEBUG_LOG("OnFrameEndedCallback is called");
    auto sharePtr = shared_from_this();
    auto task = [sharePtr, this]() {
        uintptr_t undefined = CameraUtilsTaihe::GetUndefined(get_env());
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback("frameEnd", 0, "Callback is OK", undefined));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnFrameEnd", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void VideoCallbackListener::OnDeferredVideoEnhancementInfo(
    const OHOS::CameraStandard::CaptureEndedInfoExt captureEndedInfo) const
{
    MEDIA_DEBUG_LOG("OnDeferredVideoEnhancementInfo is called");
    DeferredVideoEnhancementInfo info{
        captureEndedInfo.isDeferredVideoEnhancementAvailable,
        taihe::optional<::taihe::string>::make(captureEndedInfo.videoId)
    };
    MEDIA_INFO_LOG("OnDeferredVideoEnhancementInfo isDeferredVideo:%{public}d videoId:%{public}s ",
        captureEndedInfo.isDeferredVideoEnhancementAvailable, captureEndedInfo.videoId.c_str());

    auto sharePtr = shared_from_this();
    auto task = [info, sharePtr]() {
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback("deferredVideoEnhancementInfo", 0, "Callback is OK", info));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnDeferredVideoEnhancementInfo", 0,
        OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void VideoOutputImpl::RegisterVideoOutputErrorCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    if (videoCallback_ == nullptr) {
        ani_env *env = get_env();
        videoCallback_ = make_shared<VideoCallbackListener>(env);
        videoOutput_->SetCallback(videoCallback_);
    }
    videoCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void VideoOutputImpl::UnregisterVideoOutputErrorCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    CHECK_ERROR_RETURN_LOG(videoCallback_ == nullptr, "videoCallback is null");
    videoCallback_->RemoveCallbackRef(eventName, callback);
}

void VideoOutputImpl::RegisterDeferredVideoCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    if (videoCallback_ == nullptr) {
        ani_env *env = get_env();
        videoCallback_ = make_shared<VideoCallbackListener>(env);
        videoOutput_->SetCallback(videoCallback_);
    }
    videoCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void VideoOutputImpl::UnregisterDeferredVideoCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    CHECK_ERROR_RETURN_LOG(videoCallback_ == nullptr, "videoCallback is null");
    videoCallback_->RemoveCallbackRef(eventName, callback);
}

void VideoOutputImpl::RegisterFrameStartCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    if (videoCallback_ == nullptr) {
        ani_env *env = get_env();
        videoCallback_ = make_shared<VideoCallbackListener>(env);
        videoOutput_->SetCallback(videoCallback_);
    }
    videoCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void VideoOutputImpl::UnregisterFrameStartCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_ERROR_RETURN_LOG(videoCallback_ == nullptr, "videoCallback is null");
    videoCallback_->RemoveCallbackRef(eventName, callback);
}

void VideoOutputImpl::RegisterFrameEndCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    if (videoCallback_ == nullptr) {
        ani_env *env = get_env();
        videoCallback_ = make_shared<VideoCallbackListener>(env);
        videoOutput_->SetCallback(videoCallback_);
    }
    videoCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void VideoOutputImpl::UnregisterFrameEndCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_ERROR_RETURN_LOG(videoCallback_ == nullptr, "videoCallback is null");
    videoCallback_->RemoveCallbackRef(eventName, callback);
}

const VideoOutputImpl::EmitterFunctions VideoOutputImpl::fun_map_ = {
    { "error", {
        &VideoOutputImpl::RegisterVideoOutputErrorCallbackListener,
        &VideoOutputImpl::UnregisterVideoOutputErrorCallbackListener } },
    { "frameStart", {
        &VideoOutputImpl::RegisterFrameStartCallbackListener,
        &VideoOutputImpl::UnregisterFrameStartCallbackListener } },
    { "frameEnd", {
        &VideoOutputImpl::RegisterFrameEndCallbackListener,
        &VideoOutputImpl::UnregisterFrameEndCallbackListener } },
    { "deferredVideoEnhancementInfo", {
        &VideoOutputImpl::RegisterDeferredVideoCallbackListener,
        &VideoOutputImpl::UnregisterDeferredVideoCallbackListener } }
};

const VideoOutputImpl::EmitterFunctions& VideoOutputImpl::GetEmitterFunctions()
{
    return fun_map_;
}

void VideoOutputImpl::OnError(callback_view<void(uintptr_t)> callback)
{
    ListenerTemplate<VideoOutputImpl>::On(this, callback, "error");
}

void VideoOutputImpl::OffError(optional_view<callback<void(uintptr_t)>> callback)
{
    ListenerTemplate<VideoOutputImpl>::Off(this, callback, "error");
}

void VideoOutputImpl::OnDeferredVideoEnhancementInfo(
    callback_view<void(uintptr_t, DeferredVideoEnhancementInfo const&)> callback)
{
    ListenerTemplate<VideoOutputImpl>::On(this, callback, "deferredVideoEnhancementInfo");
}

void VideoOutputImpl::OffDeferredVideoEnhancementInfo(
    optional_view<callback<void(uintptr_t, DeferredVideoEnhancementInfo const&)>> callback)
{
    ListenerTemplate<VideoOutputImpl>::Off(this, callback, "deferredVideoEnhancementInfo");
}

void VideoOutputImpl::OnFrameStart(callback_view<void(uintptr_t, uintptr_t)> callback)
{
    MEDIA_ERR_LOG("VideoOutputImpl::OnFrameStart");
    ListenerTemplate<VideoOutputImpl>::On(this, callback, "frameStart");
}

void VideoOutputImpl::OffFrameStart(optional_view<callback<void(uintptr_t, uintptr_t)>> callback)
{
    MEDIA_ERR_LOG("VideoOutputImpl::OffFrameStart");
    ListenerTemplate<VideoOutputImpl>::Off(this, callback, "frameStart");
}

void VideoOutputImpl::OnFrameEnd(callback_view<void(uintptr_t, uintptr_t)> callback)
{
    MEDIA_ERR_LOG("VideoOutputImpl::OnFrameEnd");
    ListenerTemplate<VideoOutputImpl>::On(this, callback, "frameEnd");
}

void VideoOutputImpl::OffFrameEnd(optional_view<callback<void(uintptr_t, uintptr_t)>> callback)
{
    MEDIA_ERR_LOG("VideoOutputImpl::OffFrameEnd");
    ListenerTemplate<VideoOutputImpl>::Off(this, callback, "frameEnd");
}
} // namespace Camera
} // namespace Ani
