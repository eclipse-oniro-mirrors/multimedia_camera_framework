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

#include "photo_output_taihe.h"
#include "camera_buffer_handle_utils.h"
#include "camera_utils_taihe.h"
#include "camera_log.h"
#include "camera_manager.h"
#include "camera_security_utils_taihe.h"
#include "camera_template_utils_taihe.h"
#include "picture_proxy.h"
#include "task_manager.h"
#include "video_key_info.h"
#include "buffer_extra_data_impl.h"
#include "dp_utils.h"
#include "deferred_photo_proxy_taihe.h"
#include "video_key_info.h"
#include "image_receiver.h"
#include "hdr_type.h"

#include "metadata_helper.h"
#include <drivers/interface/display/graphic/common/v1_0/cm_color_space.h>

namespace Ani {
namespace Camera {
using namespace OHOS;
using namespace taihe;
using namespace ohos::multimedia::camera;
static std::mutex g_photoImageMutex;
static std::mutex g_assembleImageMutex;
uint32_t PhotoOutputImpl::photoOutputTaskId_ = CAMERA_PHOTO_OUTPUT_TASKID;

static const std::unordered_map<OHOS::CameraStandard::CM_ColorSpaceType, OHOS::ColorManager::ColorSpaceName>
    COLORSPACE_MAP = {
    {OHOS::CameraStandard::CM_COLORSPACE_NONE, OHOS::ColorManager::ColorSpaceName::NONE},
    {OHOS::CameraStandard::CM_BT601_EBU_FULL, OHOS::ColorManager::ColorSpaceName::BT601_EBU},
    {OHOS::CameraStandard::CM_BT601_SMPTE_C_FULL, OHOS::ColorManager::ColorSpaceName::BT601_SMPTE_C},
    {OHOS::CameraStandard::CM_BT709_FULL, OHOS::ColorManager::ColorSpaceName::BT709},
    {OHOS::CameraStandard::CM_BT2020_HLG_FULL, OHOS::ColorManager::ColorSpaceName::BT2020_HLG},
    {OHOS::CameraStandard::CM_BT2020_PQ_FULL, OHOS::ColorManager::ColorSpaceName::BT2020_PQ},
    {OHOS::CameraStandard::CM_BT601_EBU_LIMIT, OHOS::ColorManager::ColorSpaceName::BT601_EBU_LIMIT},
    {OHOS::CameraStandard::CM_BT601_SMPTE_C_LIMIT, OHOS::ColorManager::ColorSpaceName::BT601_SMPTE_C_LIMIT},
    {OHOS::CameraStandard::CM_BT709_LIMIT, OHOS::ColorManager::ColorSpaceName::BT709_LIMIT},
    {OHOS::CameraStandard::CM_BT2020_HLG_LIMIT, OHOS::ColorManager::ColorSpaceName::BT2020_HLG_LIMIT},
    {OHOS::CameraStandard::CM_BT2020_PQ_LIMIT, OHOS::ColorManager::ColorSpaceName::BT2020_PQ_LIMIT},
    {OHOS::CameraStandard::CM_SRGB_FULL, OHOS::ColorManager::ColorSpaceName::SRGB},
    {OHOS::CameraStandard::CM_P3_FULL, OHOS::ColorManager::ColorSpaceName::DISPLAY_P3},
    {OHOS::CameraStandard::CM_P3_HLG_FULL, OHOS::ColorManager::ColorSpaceName::P3_HLG},
    {OHOS::CameraStandard::CM_P3_PQ_FULL, OHOS::ColorManager::ColorSpaceName::P3_PQ},
    {OHOS::CameraStandard::CM_ADOBERGB_FULL, OHOS::ColorManager::ColorSpaceName::ADOBE_RGB},
    {OHOS::CameraStandard::CM_SRGB_LIMIT, OHOS::ColorManager::ColorSpaceName::SRGB_LIMIT},
    {OHOS::CameraStandard::CM_P3_LIMIT, OHOS::ColorManager::ColorSpaceName::DISPLAY_P3_LIMIT},
    {OHOS::CameraStandard::CM_P3_HLG_LIMIT, OHOS::ColorManager::ColorSpaceName::P3_HLG_LIMIT},
    {OHOS::CameraStandard::CM_P3_PQ_LIMIT, OHOS::ColorManager::ColorSpaceName::P3_PQ_LIMIT},
    {OHOS::CameraStandard::CM_ADOBERGB_LIMIT, OHOS::ColorManager::ColorSpaceName::ADOBE_RGB_LIMIT},
    {OHOS::CameraStandard::CM_LINEAR_SRGB, OHOS::ColorManager::ColorSpaceName::LINEAR_SRGB},
    {OHOS::CameraStandard::CM_LINEAR_BT709, OHOS::ColorManager::ColorSpaceName::LINEAR_BT709},
    {OHOS::CameraStandard::CM_LINEAR_P3, OHOS::ColorManager::ColorSpaceName::LINEAR_P3},
    {OHOS::CameraStandard::CM_LINEAR_BT2020, OHOS::ColorManager::ColorSpaceName::LINEAR_BT2020},
    {OHOS::CameraStandard::CM_DISPLAY_SRGB, OHOS::ColorManager::ColorSpaceName::DISPLAY_SRGB},
    {OHOS::CameraStandard::CM_DISPLAY_P3_SRGB, OHOS::ColorManager::ColorSpaceName::DISPLAY_P3_SRGB},
    {OHOS::CameraStandard::CM_DISPLAY_P3_HLG, OHOS::ColorManager::ColorSpaceName::DISPLAY_P3_HLG},
    {OHOS::CameraStandard::CM_DISPLAY_P3_PQ, OHOS::ColorManager::ColorSpaceName::DISPLAY_P3_PQ},
    {OHOS::CameraStandard::CM_DISPLAY_BT2020_SRGB, OHOS::ColorManager::ColorSpaceName::DISPLAY_BT2020_SRGB},
    {OHOS::CameraStandard::CM_DISPLAY_BT2020_HLG, OHOS::ColorManager::ColorSpaceName::DISPLAY_BT2020_HLG},
    {OHOS::CameraStandard::CM_DISPLAY_BT2020_PQ, OHOS::ColorManager::ColorSpaceName::DISPLAY_BT2020_PQ}
};

void PhotoOutputCallbackAni::OnCaptureStartedWithInfoCallback(const int32_t captureId, uint32_t exposureTime) const
{
    MEDIA_DEBUG_LOG("OnCaptureStartedWithInfoCallback is called, captureId: %{public}d, exposureTime: %{public}d",
        captureId, exposureTime);
    auto sharePtr = shared_from_this();
    auto task = [captureId, exposureTime, sharePtr]() {
        CaptureStartInfo captureStartInfoAni = {
            .captureId = static_cast<int32_t>(captureId),
            .time = static_cast<int32_t>(exposureTime),
        };
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback<CaptureStartInfo const&>(CONST_CAPTURE_START_WITH_INFO, 0,
                "Callback is OK", captureStartInfoAni));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnCaptureStartWithInfo", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void PhotoOutputCallbackAni::OnCaptureEndedCallback(const int32_t captureId, const int32_t frameCount) const
{
    MEDIA_DEBUG_LOG("OnCaptureEndedCallback is called, captureId: %{public}d, frameCount: %{public}d",
        captureId, frameCount);
    auto sharePtr = shared_from_this();
    auto task = [captureId, frameCount, sharePtr]() {
        CaptureEndInfo captureEndInfoAni = {
            .captureId = static_cast<int32_t>(captureId),
            .frameCount = static_cast<int32_t>(frameCount),
        };
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback<CaptureEndInfo const&>(CONST_CAPTURE_END, 0,
                "Callback is OK", captureEndInfoAni));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnCaptureEnd", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void PhotoOutputCallbackAni::OnFrameShutterCallback(const int32_t captureId, const uint64_t timestamp) const
{
    MEDIA_DEBUG_LOG("OnFrameShutterCallback is called, captureId: %{public}d, timestamp: %{public}" PRIu64,
        captureId, timestamp);
    auto sharePtr = shared_from_this();
    auto task = [captureId, timestamp, sharePtr]() {
        FrameShutterInfo frameShutterInfoAni = {
            .captureId = static_cast<int32_t>(captureId),
            .timestamp = static_cast<int64_t>(timestamp),
        };
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback<FrameShutterInfo const&>(CONST_CAPTURE_FRAME_SHUTTER, 0,
                "Callback is OK", frameShutterInfoAni));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnFrameShutter", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void PhotoOutputCallbackAni::OnFrameShutterEndCallback(const int32_t captureId, const uint64_t timestamp) const
{
    MEDIA_DEBUG_LOG("OnFrameShutterEndCallback is called, captureId: %{public}d, timestamp: %{public}" PRIu64,
        captureId, timestamp);
    auto sharePtr = shared_from_this();
    auto task = [captureId, timestamp, sharePtr]() {
        FrameShutterEndInfo frameShutterEndInfoAni = {
            .captureId = static_cast<int32_t>(captureId)
        };
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback<FrameShutterEndInfo const&>(
                CONST_CAPTURE_FRAME_SHUTTER_END, 0, "Callback is OK", frameShutterEndInfoAni));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnFrameShutterEnd", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void PhotoOutputCallbackAni::OnCaptureReadyCallback(const int32_t captureId, const uint64_t timestamp) const
{
    MEDIA_DEBUG_LOG("OnCaptureReadyCallback is called, captureId: %{public}d, timestamp: %{public}" PRIu64,
        captureId, timestamp);
    auto sharePtr = shared_from_this();
    auto task = [captureId, timestamp, sharePtr, this]() {
        uintptr_t undefined = CameraUtilsTaihe::GetUndefined(get_env());
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback(CONST_CAPTURE_READY, 0, "Callback is OK", undefined));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnCaptureReady", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void PhotoOutputCallbackAni::OnCaptureErrorCallback(const int32_t captureId, const int32_t errorCode) const
{
    MEDIA_DEBUG_LOG("OnCaptureErrorCallback is called, captureId: %{public}d, errorCode: %{public}d",
        captureId, errorCode);
    auto sharePtr = shared_from_this();
    auto task = [captureId, errorCode, sharePtr]() {
        CHECK_EXECUTE(sharePtr != nullptr, sharePtr->ExecuteErrorCallback(CONST_CAPTURE_ERROR, errorCode));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnError", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void PhotoOutputCallbackAni::OnEstimatedCaptureDurationCallback(const int32_t duration) const
{
    MEDIA_DEBUG_LOG("OnEstimatedCaptureDuration is called, duration: %{public}d", duration);
    auto sharePtr = shared_from_this();
    auto task = [duration, sharePtr]() {
        double durationAni = static_cast<double>(duration);
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback(CONST_CAPTURE_ESTIMATED_CAPTURE_DURATION, 0, "Callback is OK", durationAni));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task,
        "OnEstimatedCaptureDuration", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void PhotoOutputCallbackAni::OnOfflineDeliveryFinishedCallback(const int32_t captureId) const
{
    MEDIA_DEBUG_LOG("OnOfflineDeliveryFinished is called, captureId: %{public}d", captureId);
    auto sharePtr = shared_from_this();
    auto task = [captureId, sharePtr, this]() {
        uintptr_t undefined = CameraUtilsTaihe::GetUndefined(get_env());
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback(CONST_CAPTURE_OFFLINE_DELIVERY_FINISHED, 0, "Callback is OK", undefined));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnOfflineDeliveryFinished", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void PhotoOutputCallbackAni::OnCaptureStarted(const int32_t captureId) const
{
    MEDIA_DEBUG_LOG("OnCaptureStarted is called, captureId: %{public}d", captureId);
}

void PhotoOutputCallbackAni::OnCaptureStarted(const int32_t captureId, uint32_t exposureTime) const
{
    MEDIA_DEBUG_LOG("OnCaptureStarted is called, captureId: %{public}d, exposureTime: %{public}d",
        captureId, exposureTime);
    OnCaptureStartedWithInfoCallback(captureId, exposureTime);
}

void PhotoOutputCallbackAni::OnCaptureEnded(const int32_t captureId, const int32_t frameCount) const
{
    MEDIA_DEBUG_LOG("OnCaptureEnded is called, captureId: %{public}d, frameCount: %{public}d",
        captureId, frameCount);
    OnCaptureEndedCallback(captureId, frameCount);
}

void PhotoOutputCallbackAni::OnFrameShutter(const int32_t captureId, const uint64_t timestamp) const
{
    MEDIA_DEBUG_LOG("OnFrameShutter is called, captureId: %{public}d, timestamp: %{public}" PRIu64,
        captureId, timestamp);
    OnFrameShutterCallback(captureId, timestamp);
}

void PhotoOutputCallbackAni::OnFrameShutterEnd(const int32_t captureId, const uint64_t timestamp) const
{
    MEDIA_DEBUG_LOG("OnFrameShutterEnd is called, captureId: %{public}d, timestamp: %{public}" PRIu64,
        captureId, timestamp);
    OnFrameShutterEndCallback(captureId, timestamp);
}

void PhotoOutputCallbackAni::OnCaptureReady(const int32_t captureId, const uint64_t timestamp) const
{
    MEDIA_DEBUG_LOG("OnCaptureReady is called, captureId: %{public}d, timestamp: %{public}" PRIu64,
        captureId, timestamp);
    OnCaptureReadyCallback(captureId, timestamp);
}

void PhotoOutputCallbackAni::OnCaptureError(const int32_t captureId, const int32_t errorCode) const
{
    MEDIA_DEBUG_LOG("OnCaptureError is called, captureId: %{public}d, errorCode: %{public}d",
        captureId, errorCode);
    OnCaptureErrorCallback(captureId, errorCode);
}

void PhotoOutputCallbackAni::OnEstimatedCaptureDuration(const int32_t duration) const
{
    MEDIA_DEBUG_LOG("OnEstimatedCaptureDuration is called, duration: %{public}d", duration);
    OnEstimatedCaptureDurationCallback(duration);
}

void PhotoOutputCallbackAni::OnOfflineDeliveryFinished(const int32_t captureId) const
{
    MEDIA_DEBUG_LOG("OnOfflineDeliveryFinished is called, captureId: %{public}d", captureId);
    OnOfflineDeliveryFinishedCallback(captureId);
}

PhotoOutputImpl::PhotoOutputImpl(sptr<OHOS::CameraStandard::CaptureOutput> output) : CameraOutputImpl(output)
{
    photoOutput_ = static_cast<OHOS::CameraStandard::PhotoOutput*>(output.GetRefPtr());
}

void PhotoOutputImpl::ReleaseSync()
{
    MEDIA_DEBUG_LOG("ReleaseSync is called");
    std::unique_ptr<PhotoOutputTaiheAsyncContext> asyncContext = std::make_unique<PhotoOutputTaiheAsyncContext>(
        "PhotoOutputImpl::ReleaseSync", CameraUtilsTaihe::IncrementAndGet(photoOutputTaskId_));
    CHECK_ERROR_RETURN_LOG(photoOutput_ == nullptr, "photoOutput_ is nullptr");
    asyncContext->queueTask =
        CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("PhotoOutputImpl::ReleaseSync");
    asyncContext->objectInfo = std::make_shared<PhotoOutputImpl>(photoOutput_);
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_ERROR_RETURN_LOG(asyncContext->objectInfo == nullptr, "photoOutput_ is nullptr");
        asyncContext->errorCode = asyncContext->objectInfo->photoOutput_->Release();
        CameraUtilsTaihe::CheckError(asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

const PhotoOutputImpl::EmitterFunctions& PhotoOutputImpl::GetEmitterFunctions()
{
    static const EmitterFunctions funMap = {
        { CONST_CAPTURE_ERROR, {
            &PhotoOutputImpl::RegisterErrorCallbackListener,
            &PhotoOutputImpl::UnregisterErrorCallbackListener } },
        { CONST_CAPTURE_START_WITH_INFO, {
            &PhotoOutputImpl::RegisterCaptureStartWithInfoCallbackListener,
            &PhotoOutputImpl::UnregisterCaptureStartWithInfoCallbackListener } },
        { CONST_CAPTURE_END, {
            &PhotoOutputImpl::RegisterCaptureEndCallbackListener,
            &PhotoOutputImpl::UnregisterCaptureEndCallbackListener } },
        { CONST_CAPTURE_READY, {
            &PhotoOutputImpl::RegisterReadyCallbackListener,
            &PhotoOutputImpl::UnregisterReadyCallbackListener } },
        { CONST_CAPTURE_FRAME_SHUTTER, {
            &PhotoOutputImpl::RegisterFrameShutterCallbackListener,
            &PhotoOutputImpl::UnregisterFrameShutterCallbackListener } },
        { CONST_CAPTURE_FRAME_SHUTTER_END, {
            &PhotoOutputImpl::RegisterFrameShutterEndCallbackListener,
            &PhotoOutputImpl::UnregisterFrameShutterEndCallbackListener } },
        { CONST_CAPTURE_ESTIMATED_CAPTURE_DURATION, {
            &PhotoOutputImpl::RegisterEstimatedCaptureDurationCallbackListener,
            &PhotoOutputImpl::UnregisterEstimatedCaptureDurationCallbackListener } },
        { CONST_CAPTURE_OFFLINE_DELIVERY_FINISHED, {
            &PhotoOutputImpl::RegisterOfflineDeliveryFinishedCallbackListener,
            &PhotoOutputImpl::UnregisterOfflineDeliveryFinishedCallbackListener } }, };
    return funMap;
}

void PhotoOutputImpl::RegisterErrorCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(photoOutput_ == nullptr,
        "failed to RegisterErrorCallbackListener, photoOutput is nullptr");
    if (photoOutputCallback_ == nullptr) {
        ani_env *env = get_env();
        photoOutputCallback_ = std::make_shared<PhotoOutputCallbackAni>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void PhotoOutputImpl::UnregisterErrorCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    CHECK_ERROR_RETURN_LOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null");
    photoOutputCallback_->RemoveCallbackRef(eventName, callback);
}

void PhotoOutputImpl::RegisterCaptureStartWithInfoCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(photoOutput_ == nullptr,
        "failed to RegisterCaptureStartWithInfoCallbackListener, photoOutput is nullptr");
    if (photoOutputCallback_ == nullptr) {
        ani_env *env = get_env();
        photoOutputCallback_ = std::make_shared<PhotoOutputCallbackAni>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void PhotoOutputImpl::UnregisterCaptureStartWithInfoCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_ERROR_RETURN_LOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null");
    photoOutputCallback_->RemoveCallbackRef(eventName, callback);
}

void PhotoOutputImpl::RegisterCaptureEndCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(photoOutput_ == nullptr,
        "failed to RegisterCaptureEndCallbackListener, photoOutput is nullptr");
    if (photoOutputCallback_ == nullptr) {
        ani_env *env = get_env();
        photoOutputCallback_ = std::make_shared<PhotoOutputCallbackAni>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void PhotoOutputImpl::UnregisterCaptureEndCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_ERROR_RETURN_LOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null");
    photoOutputCallback_->RemoveCallbackRef(eventName, callback);
}

void PhotoOutputImpl::RegisterReadyCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(photoOutput_ == nullptr,
        "failed to RegisterReadyCallbackListener, photoOutput is nullptr");
    if (photoOutputCallback_ == nullptr) {
        ani_env *env = get_env();
        photoOutputCallback_ = std::make_shared<PhotoOutputCallbackAni>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void PhotoOutputImpl::UnregisterReadyCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_ERROR_RETURN_LOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null");
    photoOutputCallback_->RemoveCallbackRef(eventName, callback);
}

void PhotoOutputImpl::RegisterFrameShutterCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(photoOutput_ == nullptr,
        "failed to RegisterFrameShutterCallbackListener, photoOutput is nullptr");
    if (photoOutputCallback_ == nullptr) {
        ani_env *env = get_env();
        photoOutputCallback_ = std::make_shared<PhotoOutputCallbackAni>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void PhotoOutputImpl::UnregisterFrameShutterCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_ERROR_RETURN_LOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null");
    photoOutputCallback_->RemoveCallbackRef(eventName, callback);
}

void PhotoOutputImpl::RegisterFrameShutterEndCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(photoOutput_ == nullptr,
        "failed to RegisterFrameShutterEndCallbackListener, photoOutput is nullptr");
    if (photoOutputCallback_ == nullptr) {
        ani_env *env = get_env();
        photoOutputCallback_ = std::make_shared<PhotoOutputCallbackAni>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void PhotoOutputImpl::UnregisterFrameShutterEndCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_ERROR_RETURN_LOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null");
    photoOutputCallback_->RemoveCallbackRef(eventName, callback);
}

void PhotoOutputImpl::RegisterEstimatedCaptureDurationCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(photoOutput_ == nullptr,
        "failed to RegisterEstimatedCaptureDurationCallbackListener, photoOutput is nullptr");
    if (photoOutputCallback_ == nullptr) {
        ani_env *env = get_env();
        photoOutputCallback_ = std::make_shared<PhotoOutputCallbackAni>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void PhotoOutputImpl::UnregisterEstimatedCaptureDurationCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_ERROR_RETURN_LOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null");
    photoOutputCallback_->RemoveCallbackRef(eventName, callback);
}

void PhotoOutputImpl::RegisterOfflineDeliveryFinishedCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(photoOutput_ == nullptr,
        "failed to RegisterOfflineDeliveryFinishedCallbackListener, photoOutput is nullptr");
    if (photoOutputCallback_ == nullptr) {
        ani_env *env = get_env();
        photoOutputCallback_ = std::make_shared<PhotoOutputCallbackAni>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void PhotoOutputImpl::UnregisterOfflineDeliveryFinishedCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    if (photoOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("photoOutputCallback is null");
        return;
    }
    photoOutputCallback_->RemoveCallbackRef(eventName, callback);
}

void PhotoOutputImpl::OnError(callback_view<void(uintptr_t)> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OnError");
    ListenerTemplate<PhotoOutputImpl>::On(this, callback, CONST_CAPTURE_ERROR);
}

void PhotoOutputImpl::OffError(optional_view<callback<void(uintptr_t)>> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OffError");
    ListenerTemplate<PhotoOutputImpl>::Off(this, callback, CONST_CAPTURE_ERROR);
}

void PhotoOutputImpl::OnCaptureStartWithInfo(callback_view<void(uintptr_t, CaptureStartInfo const&)> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OnCaptureStartWithInfo");
    ListenerTemplate<PhotoOutputImpl>::On(this, callback, CONST_CAPTURE_START_WITH_INFO);
}

void PhotoOutputImpl::OffCaptureStartWithInfo(
    optional_view<callback<void(uintptr_t, CaptureStartInfo const&)>> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OffCaptureStartWithInfo");
    ListenerTemplate<PhotoOutputImpl>::Off(this, callback, CONST_CAPTURE_START_WITH_INFO);
}

void PhotoOutputImpl::OnCaptureEnd(callback_view<void(uintptr_t, CaptureEndInfo const&)> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OnCaptureEnd");
    ListenerTemplate<PhotoOutputImpl>::On(this, callback, CONST_CAPTURE_END);
}

void PhotoOutputImpl::OffCaptureEnd(optional_view<callback<void(uintptr_t, CaptureEndInfo const&)>> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OffCaptureEnd");
    ListenerTemplate<PhotoOutputImpl>::Off(this, callback, CONST_CAPTURE_END);
}

void PhotoOutputImpl::OnCaptureReady(callback_view<void(uintptr_t, uintptr_t)> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OnCaptureReady");
    ListenerTemplate<PhotoOutputImpl>::On(this, callback, CONST_CAPTURE_READY);
}

void PhotoOutputImpl::OffCaptureReady(optional_view<callback<void(uintptr_t, uintptr_t)>> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OffCaptureReady");
    ListenerTemplate<PhotoOutputImpl>::Off(this, callback, CONST_CAPTURE_READY);
}

void PhotoOutputImpl::OnFrameShutter(callback_view<void(uintptr_t, FrameShutterInfo const&)> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OnFrameShutter");
    ListenerTemplate<PhotoOutputImpl>::On(this, callback, CONST_CAPTURE_FRAME_SHUTTER);
}

void PhotoOutputImpl::OffFrameShutter(optional_view<callback<void(uintptr_t, FrameShutterInfo const&)>> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OffFrameShutter");
    ListenerTemplate<PhotoOutputImpl>::Off(this, callback, CONST_CAPTURE_FRAME_SHUTTER);
}

void PhotoOutputImpl::OnFrameShutterEnd(callback_view<void(uintptr_t, FrameShutterEndInfo const&)> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OnFrameShutterEnd");
    ListenerTemplate<PhotoOutputImpl>::On(this, callback, CONST_CAPTURE_FRAME_SHUTTER_END);
}

void PhotoOutputImpl::OffFrameShutterEnd(optional_view<callback<void(uintptr_t, FrameShutterEndInfo const&)>> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OffFrameShutterEnd");
    ListenerTemplate<PhotoOutputImpl>::Off(this, callback, CONST_CAPTURE_FRAME_SHUTTER_END);
}

void PhotoOutputImpl::OnEstimatedCaptureDuration(callback_view<void(uintptr_t, double)> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OnEstimatedCaptureDuration");
    ListenerTemplate<PhotoOutputImpl>::On(this, callback, CONST_CAPTURE_ESTIMATED_CAPTURE_DURATION);
}

void PhotoOutputImpl::OffEstimatedCaptureDuration(optional_view<callback<void(uintptr_t, double)>> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OffEstimatedCaptureDuration");
    ListenerTemplate<PhotoOutputImpl>::Off(this, callback, CONST_CAPTURE_ESTIMATED_CAPTURE_DURATION);
}

void PhotoOutputImpl::OnOfflineDeliveryFinished(callback_view<void(uintptr_t, uintptr_t)> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OnOfflineDeliveryFinished");
    ListenerTemplate<PhotoOutputImpl>::On(this, callback, CONST_CAPTURE_OFFLINE_DELIVERY_FINISHED);
}

void PhotoOutputImpl::OffOfflineDeliveryFinished(optional_view<callback<void(uintptr_t, uintptr_t)>> callback)
{
    MEDIA_ERR_LOG("PhotoOutputImpl::OffOfflineDeliveryFinished");
    ListenerTemplate<PhotoOutputImpl>::Off(this, callback, CONST_CAPTURE_OFFLINE_DELIVERY_FINISHED);
}
} // namespace Camera
} // namespace Ani