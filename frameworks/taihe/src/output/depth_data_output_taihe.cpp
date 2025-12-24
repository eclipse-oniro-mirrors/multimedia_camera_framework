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

#include "depth_data_output_taihe.h"
#include "depth_data_taihe.h"
#include "camera_template_utils_taihe.h"
#include "camera_utils_taihe.h"
#include "camera_log.h"
#include "camera_security_utils_taihe.h"
#include "video_key_info.h"
#include "pixel_map.h"

namespace Ani {
namespace Camera {
std::mutex DepthDataTaiheListener::depthDataMutex_;
uint32_t DepthDataOutputImpl::depthDataOutputTaskId_ = CAMERA_DEPTH_DATA_OUTPUT_TASKID;
thread_local std::shared_ptr<OHOS::CameraStandard::DepthProfile> DepthDataOutputImpl::depthProfile_ = nullptr;
thread_local OHOS::sptr<OHOS::Surface> DepthDataOutputImpl::sDepthDataSurface_ = nullptr;

DepthDataTaiheListener::DepthDataTaiheListener(ani_env* env, const OHOS::sptr<OHOS::Surface> depthDataSurface,
    OHOS::sptr<OHOS::CameraStandard::DepthDataOutput> depthDataOutput) : ListenerBase(env),
    depthDataSurface_(depthDataSurface), depthDataOutput_(depthDataOutput)
{
    if (bufferProcessor_ == nullptr && depthDataSurface != nullptr) {
        bufferProcessor_ = std::make_shared<DepthDataTaiheBufferProcessor>(depthDataSurface);
    }
}

void DepthDataTaiheListener::SetDepthProfile(std::shared_ptr<OHOS::CameraStandard::DepthProfile> depthProfile)
{
    depthProfile_ = depthProfile;
}

DepthDataOutputImpl::DepthDataOutputImpl(OHOS::sptr<OHOS::CameraStandard::CaptureOutput> output,
    OHOS::sptr<OHOS::Surface> surface) : CameraOutputImpl(output)
{
    depthDataOutput_ = static_cast<OHOS::CameraStandard::DepthDataOutput*>(output.GetRefPtr());
    sDepthDataSurface_ = surface;
}

void DepthDataOutputImpl::StartSync()
{
    MEDIA_DEBUG_LOG("StartSync is called");
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi StartSync is called!");
    std::unique_ptr<DepthDataOutputTaiheAsyncContext> asyncContext = std::make_unique<DepthDataOutputTaiheAsyncContext>(
        "DepthDataOutputImpl::StartSync", CameraUtilsTaihe::IncrementAndGet(depthDataOutputTaskId_));
    CHECK_RETURN_ELOG(depthDataOutput_ == nullptr, "depthDataOutput_ is nullptr");
    asyncContext->queueTask =
        CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("DepthDataOutputImpl::StartSync");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_RETURN_ELOG(asyncContext->objectInfo == nullptr, "depthDataOutput_ is nullptr");
        asyncContext->errorCode = asyncContext->objectInfo->depthDataOutput_->Start();
        CameraUtilsTaihe::CheckError(asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

void DepthDataOutputImpl::StopSync()
{
    MEDIA_DEBUG_LOG("StopSync is called");
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi StopSync is called!");
    std::unique_ptr<DepthDataOutputTaiheAsyncContext> asyncContext = std::make_unique<DepthDataOutputTaiheAsyncContext>(
        "DepthDataOutputImpl::StopSync", CameraUtilsTaihe::IncrementAndGet(depthDataOutputTaskId_));
    CHECK_RETURN_ELOG(depthDataOutput_ == nullptr, "depthDataOutput_ is nullptr");
    asyncContext->queueTask =
        CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("DepthDataOutputImpl::StopSync");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_RETURN_ELOG(asyncContext->objectInfo == nullptr, "depthDataOutput_ is nullptr");
        asyncContext->errorCode = asyncContext->objectInfo->depthDataOutput_->Stop();
        CameraUtilsTaihe::CheckError(asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

void DepthDataOutputImpl::ReleaseSync()
{
    MEDIA_DEBUG_LOG("ReleaseSync is called");
    std::unique_ptr<DepthDataOutputTaiheAsyncContext> asyncContext = std::make_unique<DepthDataOutputTaiheAsyncContext>(
        "DepthDataOutputImpl::ReleaseSync", CameraUtilsTaihe::IncrementAndGet(depthDataOutputTaskId_));
    CHECK_RETURN_ELOG(depthDataOutput_ == nullptr, "depthDataOutput_ is nullptr");
    asyncContext->queueTask =
        CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("DepthDataOutputImpl::ReleaseSync");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_RETURN_ELOG(asyncContext->objectInfo == nullptr, "depthDataOutput_ is nullptr");
        asyncContext->errorCode = asyncContext->objectInfo->depthDataOutput_->Release();
        CameraUtilsTaihe::CheckError(asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

const DepthDataOutputImpl::EmitterFunctions DepthDataOutputImpl::fun_map_ = {
    { "depthDataAvailable", {
        &DepthDataOutputImpl::RegisterDepthDataAvailableCallbackListener,
        &DepthDataOutputImpl::UnregisterDepthDataAvailableCallbackListener } },
    { "error", {
        &DepthDataOutputImpl::RegisterErrorCallbackListener,
        &DepthDataOutputImpl::UnregisterErrorCallbackListener } },
};

const DepthDataOutputImpl::EmitterFunctions& DepthDataOutputImpl::GetEmitterFunctions()
{
    return fun_map_;
}

void DepthDataOutputImpl::OnError(callback_view<void(uintptr_t)> callback)
{
    ListenerTemplate<DepthDataOutputImpl>::On(this, callback, "error");
}

void DepthDataOutputImpl::OffError(optional_view<callback<void(uintptr_t)>> callback)
{
    ListenerTemplate<DepthDataOutputImpl>::Off(this, callback, "error");
}

void DepthDataOutputImpl::RegisterErrorCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi on error is called!");
    CHECK_RETURN_ELOG(depthDataOutput_ == nullptr, "depthDataOutput_ is null!");
    if (depthDataCallback_ == nullptr) {
        ani_env *env = get_env();
        depthDataCallback_ = std::make_shared<DepthDataOutputErrorListener>(env);
        depthDataOutput_->SetCallback(depthDataCallback_);
    }
    depthDataCallback_->SaveCallbackReference("error", callback, isOnce);
}

void DepthDataOutputImpl::UnregisterErrorCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi off error is called!");
    CHECK_RETURN_ELOG(depthDataCallback_ == nullptr, "depthDataCallback is null");
    depthDataCallback_->RemoveCallbackRef("error", callback);
}

void DepthDataOutputErrorListener::OnDepthDataError(const int32_t errorCode) const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("OnDepthDataError is called, errorCode: %{public}d", errorCode);
    OnDepthDataErrorCallback(errorCode);
}

void DepthDataOutputErrorListener::OnDepthDataErrorCallback(const int32_t errorCode) const
{
    MEDIA_DEBUG_LOG("OnDepthDataErrorCallback is called");
    auto sharePtr = shared_from_this();
    auto task = [errorCode, sharePtr]() {
        CHECK_EXECUTE(sharePtr != nullptr, sharePtr->ExecuteErrorCallback("error", errorCode));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnError", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void DepthDataOutputImpl::OnDepthDataAvailable(callback_view<void(uintptr_t, weak::DepthData)> callback)
{
    ListenerTemplate<DepthDataOutputImpl>::On(this, callback, "depthDataAvailable");
}

void DepthDataOutputImpl::OffDepthDataAvailable(optional_view<callback<void(uintptr_t, weak::DepthData)>> callback)
{
    ListenerTemplate<DepthDataOutputImpl>::Off(this, callback, "depthDataAvailable");
}

void DepthDataOutputImpl::RegisterDepthDataAvailableCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi on depthDataAvailable is called!");
    CHECK_RETURN_ELOG(sDepthDataSurface_ == nullptr, "sDepthDataSurface_ is null!");
    if (depthDataListener_ == nullptr) {
        MEDIA_DEBUG_LOG("new depthDataListener_ and register surface consumer listener");
        ani_env *env = get_env();
        OHOS::sptr<DepthDataTaiheListener> depthDataListener = new (std::nothrow) DepthDataTaiheListener(env,
            sDepthDataSurface_, depthDataOutput_);
        OHOS::SurfaceError ret = sDepthDataSurface_->RegisterConsumerListener((
            OHOS::sptr<OHOS::IBufferConsumerListener>&)depthDataListener);
        CHECK_PRINT_ELOG(ret != OHOS::SURFACE_ERROR_OK, "register surface consumer listener failed!");
        depthDataListener_ = depthDataListener;
    }
    depthDataListener_->SetDepthProfile(depthProfile_);
    depthDataListener_->SaveCallbackReference("depthDataAvailable", callback, isOnce);
}

void DepthDataOutputImpl::UnregisterDepthDataAvailableCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi off depthDataAvailable is called!");
    CHECK_EXECUTE(depthDataListener_ != nullptr,
        depthDataListener_->RemoveCallbackRef("depthDataAvailable", callback));
}

void DepthDataTaiheListener::OnBufferAvailable()
{
    std::lock_guard<std::mutex> lock(depthDataMutex_);
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("DepthDataTaiheListener::OnBufferAvailable is called");
    OnBufferAvailableCallback();
}

void DepthDataTaiheListener::OnBufferAvailableCallback() const
{
    MEDIA_DEBUG_LOG("OnBufferAvailableCallback is called");
    CHECK_RETURN_ELOG(!depthDataSurface_, "depthDataSurface_ is null");
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer = nullptr;
    int32_t fence = -1;
    int64_t timestamp;
    OHOS::Rect damage;
    OHOS::SurfaceError surfaceRet = depthDataSurface_->AcquireBuffer(surfaceBuffer, fence, timestamp, damage);
    CHECK_RETURN_ELOG(surfaceRet != OHOS::SURFACE_ERROR_OK, "Failed to acquire surface buffer");

    ExecuteDepthData(surfaceBuffer);
}

void DepthDataTaiheListener::ExecuteDepthData(OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer) const
{
    MEDIA_DEBUG_LOG("ExecuteDepthData is called");
    CHECK_RETURN_ELOG(!depthProfile_, "depthProfile_ is null");

    int32_t depthDataWidth = static_cast<int32_t>(depthProfile_->GetSize().width);
    int32_t depthDataHeight = static_cast<int32_t>(depthProfile_->GetSize().height);
    OHOS::Media::InitializationOptions opts;
    opts.srcPixelFormat = OHOS::Media::PixelFormat::RGBA_F16;
    opts.pixelFormat = OHOS::Media::PixelFormat::RGBA_F16;
    opts.size = { .width = depthDataWidth, .height = depthDataHeight };
    MEDIA_INFO_LOG("ExecuteDepthData depthDataWidth: %{public}d, depthDataHeight: %{public}d",
        depthDataWidth, depthDataHeight);
    CHECK_RETURN_ELOG(!surfaceBuffer, "surfaceBuffer is null");
    const int32_t formatSize = 4;
    auto pixelMap = OHOS::Media::PixelMap::Create(static_cast<const uint32_t*>(surfaceBuffer->GetVirAddr()),
        depthDataWidth * depthDataHeight * formatSize, 0, depthDataWidth, opts, true);
    CHECK_PRINT_ELOG(pixelMap == nullptr, "create pixelMap failed, pixelMap is null");
    std::shared_ptr<OHOS::Media::PixelMap> sharedPtr = std::shared_ptr<OHOS::Media::PixelMap>(pixelMap.release());
    auto pixelMapTaihe = make_holder<ANI::Image::PixelMapImpl, ImageTaihe::PixelMap>(sharedPtr);
    OHOS::CameraStandard::CameraFormat nativeFormat = depthProfile_->GetCameraFormat();
    OHOS::CameraStandard::DepthDataAccuracy nativeDataAccuracy = depthProfile_->GetDataAccuracy();
    int32_t nativeQualityLevel = 0;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::depthDataQualityLevel, nativeQualityLevel);

    DepthData depthData = make_holder<DepthDataImpl, DepthData>(
        nativeFormat, nativeDataAccuracy, nativeQualityLevel, pixelMapTaihe);
    auto sharePtr = shared_from_this();
    auto task = [depthData, sharePtr, surfaceBuffer]() {
        CHECK_RETURN_ELOG(sharePtr == nullptr, "sharePtr is nullptr");
        sharePtr->ExecuteAsyncCallback("depthDataAvailable", 0, "Callback is OK", depthData);
        CHECK_RETURN_ELOG(sharePtr->depthDataSurface_ == nullptr, "depthDataSurface_ is nullptr");
        auto buffer = surfaceBuffer;
        sharePtr->depthDataSurface_->ReleaseBuffer(buffer, -1);
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnDepthDataAvailable", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}
} // namespace Camera
} // namespace Ani