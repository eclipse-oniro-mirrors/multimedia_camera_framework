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

#include "preview_output_taihe.h"
#include "camera_utils_taihe.h"
#include "camera_log.h"
#include "camera_security_utils_taihe.h"
#include "camera_template_utils_taihe.h"

namespace Ani {
namespace Camera {
uint32_t PreviewOutputImpl::previewOutputTaskId_ = CAMERA_PREVIEW_OUTPUT_TASKID;

PreviewOutputCallbackAni::PreviewOutputCallbackAni(ani_env* env): ListenerBase(env)
{
    MEDIA_DEBUG_LOG("PreviewOutputCallbackAni is called.");
}

void PreviewOutputCallbackAni::OnFrameStartedCallback() const
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

void PreviewOutputCallbackAni::OnFrameEndedCallback(const int32_t frameCount) const
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

void PreviewOutputCallbackAni::OnErrorCallback(const int32_t errorCode) const
{
    MEDIA_DEBUG_LOG("OnErrorCallback is called, errorCode: %{public}d", errorCode);
    auto sharePtr = shared_from_this();
    auto task = [errorCode, sharePtr]() {
        CHECK_EXECUTE(sharePtr != nullptr, sharePtr->ExecuteErrorCallback("error", errorCode));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnError", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void PreviewOutputCallbackAni::OnSketchStatusDataChangedCallback(
    const OHOS::CameraStandard::SketchStatusData& sketchStatusData) const
{
    MEDIA_DEBUG_LOG("OnSketchStatusDataChangedCallback is called");
    auto sharePtr = shared_from_this();
    auto task = [sketchStatusData, sharePtr]() {
        SketchStatusData aniSketchStatusData = CameraUtilsTaihe::ToTaiheSketchStatusData(sketchStatusData);
        CHECK_EXECUTE(sharePtr != nullptr, sharePtr->ExecuteAsyncCallback<SketchStatusData const&>(
            "sketchStatusChanged", 0, "Callback is OK", aniSketchStatusData));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnSketchStatusChanged", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void PreviewOutputCallbackAni::OnFrameStarted() const
{
    MEDIA_DEBUG_LOG("OnFrameStarted is called");
    OnFrameStartedCallback();
}
void PreviewOutputCallbackAni::OnFrameEnded(const int32_t frameCount) const
{
    MEDIA_DEBUG_LOG("OnFrameEnded is called, frameCount: %{public}d", frameCount);
    OnFrameEndedCallback(frameCount);
}

void PreviewOutputCallbackAni::OnError(const int32_t errorCode) const
{
    MEDIA_DEBUG_LOG("OnError is called, errorCode: %{public}d", errorCode);
    OnErrorCallback(errorCode);
}

void PreviewOutputCallbackAni::OnSketchStatusDataChanged(
    const OHOS::CameraStandard::SketchStatusData& sketchStatusData) const
{
    MEDIA_DEBUG_LOG("OnSketchStatusDataChanged is called");
    OnSketchStatusDataChangedCallback(sketchStatusData);
}

PreviewOutputImpl::PreviewOutputImpl(OHOS::sptr<OHOS::CameraStandard::CaptureOutput> output) : CameraOutputImpl(output)
{
    previewOutput_ = static_cast<OHOS::CameraStandard::PreviewOutput*>(output.GetRefPtr());
}


void PreviewOutputImpl::ReleaseSync()
{
    MEDIA_DEBUG_LOG("ReleaseSync is called");
    std::unique_ptr<PreviewOutputTaiheAsyncContext> asyncContext = std::make_unique<PreviewOutputTaiheAsyncContext>(
        "PreviewOutputImpl::ReleaseSync", CameraUtilsTaihe::IncrementAndGet(previewOutputTaskId_));
    CHECK_ERROR_RETURN_LOG(previewOutput_ == nullptr, "previewOutput_ is nullptr");
    asyncContext->queueTask =
        CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("PreviewOutputImpl::ReleaseSync");
    asyncContext->objectInfo = std::make_shared<PreviewOutputImpl>(previewOutput_);
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_ERROR_RETURN_LOG(asyncContext->objectInfo == nullptr, "previewOutput_ is nullptr");
        asyncContext->errorCode = asyncContext->objectInfo->previewOutput_->Release();
        CameraUtilsTaihe::CheckError(asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

const PreviewOutputImpl::EmitterFunctions& PreviewOutputImpl::GetEmitterFunctions()
{
    static const EmitterFunctions funMap = {
        { "error", {
            &PreviewOutputImpl::RegisterErrorCallbackListener,
            &PreviewOutputImpl::UnregisterCommonCallbackListener } },
        { "frameStart", {
            &PreviewOutputImpl::RegisterFrameStartCallbackListener,
            &PreviewOutputImpl::UnregisterCommonCallbackListener } },
        { "frameEnd", {
            &PreviewOutputImpl::RegisterFrameEndCallbackListener,
            &PreviewOutputImpl::UnregisterCommonCallbackListener } },
        { "sketchStatusChanged", {
            &PreviewOutputImpl::RegisterSketchStatusChangedCallbackListener,
            &PreviewOutputImpl::UnregisterSketchStatusChangedCallbackListener } }
        };
    return funMap;
}

void PreviewOutputImpl::RegisterErrorCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(previewOutput_ == nullptr,
        "failed to RegisterErrorCallbackListener, previewOutput is nullptr");
    ani_env *env = get_env();
    auto listener =
        CameraAniEventListener<PreviewOutputCallbackAni>::RegisterCallbackListener(eventName, env, callback, isOnce);
    CHECK_ERROR_RETURN_LOG(
        listener == nullptr, "CameraManagerAni::RegisterErrorCallbackListener listener is null");
    previewOutput_->SetCallback(listener);
}

void PreviewOutputImpl::RegisterFrameStartCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(previewOutput_ == nullptr,
        "failed to RegisterFrameStartCallbackListener, previewOutput is nullptr");
    ani_env *env = get_env();
    auto listener =
        CameraAniEventListener<PreviewOutputCallbackAni>::RegisterCallbackListener(eventName, env, callback, isOnce);
    CHECK_ERROR_RETURN_LOG(
        listener == nullptr, "CameraManagerAni::RegisterFrameStartCallbackListener listener is null");
    previewOutput_->SetCallback(listener);
}

void PreviewOutputImpl::RegisterFrameEndCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(previewOutput_ == nullptr,
        "failed to RegisterFrameEndCallbackListener, previewOutput is nullptr");
    ani_env *env = get_env();
    auto listener =
        CameraAniEventListener<PreviewOutputCallbackAni>::RegisterCallbackListener(eventName, env, callback, isOnce);
    CHECK_ERROR_RETURN_LOG(
        listener == nullptr, "CameraManagerAni::RegisterFrameEndCallbackListener listener is null");
    previewOutput_->SetCallback(listener);
}

void PreviewOutputImpl::UnregisterCommonCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_ERROR_RETURN_LOG(previewOutput_ == nullptr,
        "failed to UnregisterCommonCallbackListener, previewOutput is nullptr");
    ani_env *env = get_env();
    auto listener =
        CameraAniEventListener<PreviewOutputCallbackAni>::UnregisterCallbackListener(eventName, env, callback);
    CHECK_ERROR_RETURN_LOG(listener == nullptr,
        "PreviewOutputImpl::UnregisterCommonCallbackListener %{public}s listener is null",
        eventName.c_str());
    if (listener->IsEmpty(eventName)) {
        previewOutput_->RemoveCallback(listener);
    }
}

void PreviewOutputImpl::RegisterSketchStatusChangedCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(previewOutput_ == nullptr,
        "failed to RegisterSketchStatusChangedCallbackListener, previewOutput is nullptr");
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi On sketchStatusChanged is called!");
    ani_env *env = get_env();
    auto listener =
        CameraAniEventListener<PreviewOutputCallbackAni>::RegisterCallbackListener(eventName, env, callback, isOnce);
    CHECK_ERROR_RETURN_LOG(
        listener == nullptr, "PreviewOutputImpl::RegisterSketchStatusChangedCallbackListener listener is null");
    previewOutput_->SetCallback(listener);
    previewOutput_->OnNativeRegisterCallback(eventName);
}

void PreviewOutputImpl::UnregisterSketchStatusChangedCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_ERROR_RETURN_LOG(previewOutput_ == nullptr,
        "failed to UnregisterSketchStatusChangedCallbackListener, previewOutput is nullptr");
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi Off sketchStatusChanged is called!");
    ani_env *env = get_env();
    auto listener =
        CameraAniEventListener<PreviewOutputCallbackAni>::UnregisterCallbackListener(eventName, env, callback);
    CHECK_ERROR_RETURN_LOG(
        listener == nullptr, "PreviewOutputImpl::UnregisterSketchStatusChangedCallbackListener listener is null");
    previewOutput_->OnNativeUnregisterCallback(eventName);
    if (listener->IsEmpty(eventName)) {
        previewOutput_->RemoveCallback(listener);
    }
}

void PreviewOutputImpl::OnError(callback_view<void(uintptr_t)> callback)
{
    MEDIA_ERR_LOG("PreviewOutputImpl::OnError");
    ListenerTemplate<PreviewOutputImpl>::On(this, callback, "error");
}

void PreviewOutputImpl::OffError(optional_view<callback<void(uintptr_t)>> callback)
{
    MEDIA_ERR_LOG("PreviewOutputImpl::OffError");
    ListenerTemplate<PreviewOutputImpl>::Off(this, callback, "error");
}

void PreviewOutputImpl::OnFrameStart(callback_view<void(uintptr_t, uintptr_t)> callback)
{
    MEDIA_ERR_LOG("PreviewOutputImpl::OnFrameStart");
    ListenerTemplate<PreviewOutputImpl>::On(this, callback, "frameStart");
}

void PreviewOutputImpl::OffFrameStart(optional_view<callback<void(uintptr_t, uintptr_t)>> callback)
{
    MEDIA_ERR_LOG("PreviewOutputImpl::OffFrameStart");
    ListenerTemplate<PreviewOutputImpl>::Off(this, callback, "frameStart");
}

void PreviewOutputImpl::OnFrameEnd(callback_view<void(uintptr_t, uintptr_t)> callback)
{
    MEDIA_ERR_LOG("PreviewOutputImpl::OnFrameEnd");
    ListenerTemplate<PreviewOutputImpl>::On(this, callback, "frameEnd");
}

void PreviewOutputImpl::OffFrameEnd(optional_view<callback<void(uintptr_t, uintptr_t)>> callback)
{
    MEDIA_ERR_LOG("PreviewOutputImpl::OffFrameEnd");
    ListenerTemplate<PreviewOutputImpl>::Off(this, callback, "frameEnd");
}

void PreviewOutputImpl::OnSketchStatusChanged(callback_view<void(uintptr_t, SketchStatusData const&)> callback)
{
    MEDIA_ERR_LOG("PreviewOutputImpl::OnSketchStatusChanged");
    ListenerTemplate<PreviewOutputImpl>::On(this, callback, "sketchStatusChanged");
}

void PreviewOutputImpl::OffSketchStatusChanged(
    optional_view<callback<void(uintptr_t, SketchStatusData const&)>> callback)
{
    MEDIA_ERR_LOG("PreviewOutputImpl::OffSketchStatusChanged");
    ListenerTemplate<PreviewOutputImpl>::Off(this, callback, "sketchStatusChanged");
}
} // namespace Camera
} // namespace Ani