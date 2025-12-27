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
#include "image_taihe.h"
#include "image_receiver.h"
#include "hdr_type.h"
#include "photo_taihe.h"
#include "pixel_map_taihe.h"
#include "media_library_comm_ani.h"
#include "metadata_helper.h"
#include "photo_output_callback.h"

namespace Ani {
namespace Camera {
using namespace OHOS;
using namespace taihe;
using namespace ohos::multimedia::camera;
static std::mutex g_photoImageMutex;
static std::mutex g_assembleImageMutex;
uint32_t PhotoOutputImpl::photoOutputTaskId_ = CAMERA_PHOTO_OUTPUT_TASKID;

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
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnCaptureStartWithInfo", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void PhotoOutputCallbackAni::OnPhotoAvailableCallback(const std::shared_ptr<Media::NativeImage> nativeImage,
    bool isRaw) const
{
    MEDIA_INFO_LOG("PhotoOutputCallbackAni::OnPhotoAvailableCallback");
    int32_t errCode = 0;
    std::string message = "success";
    ohos::multimedia::image::image::Image mainImage = ANI::Image::ImageImpl::Create(nativeImage);
    if (has_error()) {
        reset_error();
        errCode = -1;
        message = "ImageTaihe Create failed";
    }
    Photo photoValue = make_holder<Ani::Camera::PhotoImpl, Photo>(mainImage, isRaw);
    auto sharePtr = shared_from_this();
    auto task = [photoValue, errCode, message, sharePtr]() {
        CHECK_EXECUTE(sharePtr != nullptr, sharePtr->ExecuteAsyncCallback(
            CONST_CAPTURE_PHOTO_AVAILABLE, errCode, message, photoValue));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnPhotoAvailableCallback", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void PhotoOutputCallbackAni::OnPhotoAssetAvailableCallback(const int32_t captureId, const std::string &uri,
    int32_t cameraShotType, const std::string &burstKey) const
{
    MEDIA_INFO_LOG("PhotoOutputCallbackAni::OnPhotoAssetAvailableCallback called");
    ani_object photoAssetValue =
        Media::MediaLibraryCommAni::CreatePhotoAssetAni(get_env(), uri, cameraShotType, captureId, burstKey);
    auto sharePtr = shared_from_this();
    auto task = [photoAssetValue, sharePtr]() {
        CHECK_EXECUTE(sharePtr != nullptr, sharePtr->ExecuteAsyncCallback(
            CONST_CAPTURE_PHOTO_ASSET_AVAILABLE, 0, "success", reinterpret_cast<uintptr_t>(photoAssetValue)));
        MEDIA_DEBUG_LOG("ExecuteCallback CONST_CAPTURE_PHOTO_ASSET_AVAILABLE X");
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnPhotoAssetAvailableCallback", 0,
        OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void PhotoOutputCallbackAni::OnThumbnailAvailableCallback(int32_t captureId, int64_t timestamp,
    std::unique_ptr<Media::PixelMap>& pixelMap) const
{
    ohos::multimedia::image::image::PixelMap pixelMapVal =
        make_holder<ANI::Image::PixelMapImpl, ohos::multimedia::image::image::PixelMap>(std::move(pixelMap));
    pixelMapVal->SetCaptureId(captureId);
    pixelMapVal->SetTimestamp(timestamp);
    auto sharePtr = shared_from_this();
    auto task = [pixelMapVal, sharePtr]() {
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback(CONST_CAPTURE_QUICK_THUMBNAIL, 0, "Callback is OK", pixelMapVal));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnThumbnailAvailableCallback",
        0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
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
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
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
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
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
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnFrameShutterEnd", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void PhotoOutputCallbackAni::OnCaptureReadyCallback(const int32_t captureId, const uint64_t timestamp) const
{
    MEDIA_DEBUG_LOG("OnCaptureReadyCallback is called, captureId: %{public}d, timestamp: %{public}" PRIu64,
        captureId, timestamp);
    auto sharePtr = shared_from_this();
    auto task = [captureId, timestamp, sharePtr]() {
        uintptr_t undefined = CameraUtilsTaihe::GetUndefined(get_env());
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback(CONST_CAPTURE_READY, 0, "Callback is OK", undefined));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
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
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
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
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task,
        "OnEstimatedCaptureDuration", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void PhotoOutputCallbackAni::OnOfflineDeliveryFinishedCallback(const int32_t captureId) const
{
    MEDIA_DEBUG_LOG("OnOfflineDeliveryFinished is called, captureId: %{public}d", captureId);
    auto sharePtr = shared_from_this();
    auto task = [captureId, sharePtr]() {
        uintptr_t undefined = CameraUtilsTaihe::GetUndefined(get_env());
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback(CONST_CAPTURE_OFFLINE_DELIVERY_FINISHED, 0, "Callback is OK", undefined));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
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

void PhotoOutputCallbackAni::OnConstellationDrawingState(const int32_t state) const
{
}

void PhotoOutputCallbackAni::OnPhotoAvailable(const std::shared_ptr<Media::NativeImage> nativeImage, bool isRaw) const
{
    MEDIA_DEBUG_LOG("OnPhotoAvailable is called!");
    OnPhotoAvailableCallback(nativeImage, isRaw);
}

void PhotoOutputCallbackAni::OnPhotoAvailable(const std::shared_ptr<Media::Picture> picture) const
{
    MEDIA_DEBUG_LOG("OnPhotoAvailable is called!");
}

void PhotoOutputCallbackAni::OnPhotoAssetAvailable(const int32_t captureId, const std::string &uri,
    int32_t cameraShotType, const std::string &burstKey) const
{
    MEDIA_DEBUG_LOG("OnPhotoAssetAvailable is called!");
    OnPhotoAssetAvailableCallback(captureId, uri, cameraShotType, burstKey);
}

void PhotoOutputCallbackAni::OnThumbnailAvailable(int32_t captureId, int64_t timestamp,
    std::unique_ptr<Media::PixelMap> pixelMap) const
{
    MEDIA_DEBUG_LOG("OnThumbnailAvailable is called!");
    OnThumbnailAvailableCallback(captureId, timestamp, pixelMap);
}

int32_t GetBurstSeqId(int32_t captureId)
{
    const uint32_t burstSeqIdMask = 0xFFFF;
    return captureId > 0 ? (static_cast<uint32_t>(captureId) & burstSeqIdMask) : captureId;
}

std::shared_ptr<OHOS::CameraStandard::Location> GetLocationBySettings(
    std::shared_ptr<OHOS::CameraStandard::PhotoCaptureSetting> settings)
{
    auto location = std::make_shared<OHOS::CameraStandard::Location>();
    if (settings) {
        settings->GetLocation(location);
        MEDIA_INFO_LOG("GetLocationBySettings latitude:%{private}f, longitude:%{private}f",
            location->latitude, location->longitude);
    } else {
        MEDIA_ERR_LOG("GetLocationBySettings failed!");
    }
    return location;
}

void CleanAfterTransPicture(sptr<OHOS::CameraStandard::PhotoOutput> photoOutput, int32_t captureId)
{
    CHECK_RETURN_ELOG(!photoOutput, "CleanAfterTransPicture photoOutput is nullptr");
    photoOutput->photoProxyMap_[captureId] = nullptr;
    photoOutput->photoProxyMap_.erase(captureId);
    photoOutput->captureIdPictureMap_.erase(captureId);
    photoOutput->captureIdGainmapMap_.erase(captureId);
    photoOutput->captureIdDepthMap_.Erase(captureId);
    photoOutput->captureIdExifMap_.erase(captureId);
    photoOutput->captureIdDebugMap_.erase(captureId);
    photoOutput->captureIdAuxiliaryCountMap_.erase(captureId);
    photoOutput->captureIdCountMap_.erase(captureId);
    photoOutput->captureIdHandleMap_.erase(captureId);
}

void ThumbnailSetColorSpaceAndRotate(std::unique_ptr<Media::PixelMap>& pixelMap, sptr<SurfaceBuffer> surfaceBuffer,
    OHOS::ColorManager::ColorSpaceName colorSpaceName)
{
    int32_t thumbnailrotation = 0;
    CHECK_RETURN_ELOG(!surfaceBuffer, "surfaceBuffer is nullptr");
    CHECK_RETURN_ELOG(!(surfaceBuffer->GetExtraData()), "surfaceBuffer extra data is nullptr");
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::dataRotation, thumbnailrotation);
    MEDIA_DEBUG_LOG("ThumbnailListener current rotation is : %{public}d", thumbnailrotation);
    if (!pixelMap) {
        MEDIA_ERR_LOG("ThumbnailListener Failed to create PixelMap.");
    } else {
        pixelMap->InnerSetColorSpace(OHOS::ColorManager::ColorSpace(colorSpaceName));
        pixelMap->rotate(thumbnailrotation);
    }
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
    CHECK_RETURN_ELOG(photoOutput_ == nullptr, "photoOutput_ is nullptr");
    asyncContext->queueTask =
        CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("PhotoOutputImpl::ReleaseSync");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_RETURN_ELOG(asyncContext->objectInfo == nullptr, "photoOutput_ is nullptr");
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
        { CONST_CAPTURE_PHOTO_AVAILABLE, {
            &PhotoOutputImpl::RegisterPhotoAvailableCallbackListener,
            &PhotoOutputImpl::UnregisterPhotoAvailableCallbackListener } },
        { CONST_CAPTURE_DEFERRED_PHOTO_AVAILABLE, {
            &PhotoOutputImpl::RegisterDeferredPhotoProxyAvailableCallbackListener,
            &PhotoOutputImpl::UnregisterDeferredPhotoProxyAvailableCallbackListener } },
        { CONST_CAPTURE_OFFLINE_DELIVERY_FINISHED, {
            &PhotoOutputImpl::RegisterOfflineDeliveryFinishedCallbackListener,
            &PhotoOutputImpl::UnregisterOfflineDeliveryFinishedCallbackListener } },
        { CONST_CAPTURE_PHOTO_ASSET_AVAILABLE, {
            &PhotoOutputImpl::RegisterPhotoAssetAvailableCallbackListener,
            &PhotoOutputImpl::UnregisterPhotoAssetAvailableCallbackListener } },
        { CONST_CAPTURE_QUICK_THUMBNAIL, {
            &PhotoOutputImpl::RegisterQuickThumbnailCallbackListener,
            &PhotoOutputImpl::UnregisterQuickThumbnailCallbackListener } }, };
    return funMap;
}

void PhotoOutputImpl::RegisterErrorCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_RETURN_ELOG(photoOutput_ == nullptr,
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
    CHECK_RETURN_ELOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null");
    photoOutputCallback_->RemoveCallbackRef(eventName, callback);
}

void PhotoOutputImpl::RegisterCaptureStartWithInfoCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_RETURN_ELOG(photoOutput_ == nullptr,
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
    CHECK_RETURN_ELOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null");
    photoOutputCallback_->RemoveCallbackRef(eventName, callback);
}

void PhotoOutputImpl::RegisterCaptureEndCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_RETURN_ELOG(photoOutput_ == nullptr,
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
    CHECK_RETURN_ELOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null");
    photoOutputCallback_->RemoveCallbackRef(eventName, callback);
}

void PhotoOutputImpl::RegisterReadyCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_RETURN_ELOG(photoOutput_ == nullptr,
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
    CHECK_RETURN_ELOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null");
    photoOutputCallback_->RemoveCallbackRef(eventName, callback);
}

void PhotoOutputImpl::RegisterFrameShutterCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_RETURN_ELOG(photoOutput_ == nullptr,
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
    CHECK_RETURN_ELOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null");
    photoOutputCallback_->RemoveCallbackRef(eventName, callback);
}

void PhotoOutputImpl::RegisterFrameShutterEndCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_RETURN_ELOG(photoOutput_ == nullptr,
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
    CHECK_RETURN_ELOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null");
    photoOutputCallback_->RemoveCallbackRef(eventName, callback);
}

void PhotoOutputImpl::RegisterEstimatedCaptureDurationCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_RETURN_ELOG(photoOutput_ == nullptr,
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
    CHECK_RETURN_ELOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null");
    photoOutputCallback_->RemoveCallbackRef(eventName, callback);
}

void PhotoOutputImpl::RegisterPhotoAvailableCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    MEDIA_INFO_LOG("PhotoOutputImpl::RegisterPhotoAvailableCallbackListener!");
    CHECK_RETURN_ELOG(photoOutput_ == nullptr,
        "failed to RegisterPhotoAvailableCallbackListener, photoOutput is nullptr");
    if (photoOutputCallback_ == nullptr) {
        ani_env *env = get_env();
        photoOutputCallback_ = std::make_shared<PhotoOutputCallbackAni>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutput_->SetPhotoAvailableCallback(photoOutputCallback_);
    photoOutputCallback_->SaveCallbackReference(eventName, callback, isOnce);
    callbackFlag_ |= OHOS::CameraStandard::CAPTURE_PHOTO;
    photoOutput_->SetCallbackFlag(callbackFlag_);
}

void PhotoOutputImpl::UnregisterPhotoAvailableCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_RETURN_ELOG(photoOutput_ == nullptr, "PhotoOutput is null!");
    CHECK_RETURN_ELOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null!");
    photoOutput_->UnSetPhotoAvailableCallback();
    callbackFlag_ &= ~OHOS::CameraStandard::CAPTURE_PHOTO;
    photoOutput_->SetCallbackFlag(callbackFlag_, false);
    photoOutputCallback_->RemoveCallbackRef(eventName, callback);
}

void PhotoOutputImpl::RegisterDeferredPhotoProxyAvailableCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    MEDIA_INFO_LOG("PhotoOutputImpl RegisterDeferredPhotoProxyAvailableCallbackListener!");
    CHECK_RETURN_ELOG(photoOutput_ == nullptr, "PhotoOutput is null!");
}

void PhotoOutputImpl::UnregisterDeferredPhotoProxyAvailableCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
}

void PhotoOutputImpl::RegisterOfflineDeliveryFinishedCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi RegisterOfflineDeliveryFinishedCallbackListener is called!");
    CHECK_RETURN_ELOG(photoOutput_ == nullptr, "PhotoOutput is null!");
    if (photoOutputCallback_ == nullptr) {
        ani_env* env = get_env();
        photoOutputCallback_ = std::make_shared<PhotoOutputCallbackAni>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(CONST_CAPTURE_OFFLINE_DELIVERY_FINISHED, callback, isOnce);
}

void PhotoOutputImpl::UnregisterOfflineDeliveryFinishedCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi UnregisterOfflineDeliveryFinishedCallbackListener is called!");
    if (photoOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("photoOutputCallback is null");
        return;
    }
    photoOutputCallback_->RemoveCallbackRef(CONST_CAPTURE_OFFLINE_DELIVERY_FINISHED, callback);
}

void PhotoOutputImpl::RegisterPhotoAssetAvailableCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    MEDIA_INFO_LOG("PhotoOutputImpl RegisterPhotoAssetAvailableCallbackListener!");
    CHECK_RETURN_ELOG(photoOutput_ == nullptr, "PhotoOutput is null!");
    if (photoOutputCallback_ == nullptr) {
        ani_env* env = get_env();
        photoOutputCallback_ = std::make_shared<PhotoOutputCallbackAni>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutput_->SetPhotoAssetAvailableCallback(photoOutputCallback_);
    photoOutputCallback_->SaveCallbackReference(CONST_CAPTURE_PHOTO_ASSET_AVAILABLE, callback, isOnce);
    callbackFlag_ |= OHOS::CameraStandard::CAPTURE_PHOTO_ASSET;
    photoOutput_->SetCallbackFlag(callbackFlag_);
}

void PhotoOutputImpl::UnregisterPhotoAssetAvailableCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_RETURN_ELOG(photoOutput_ == nullptr, "PhotoOutput is null!");
    CHECK_RETURN_ELOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null!");
    photoOutput_->UnSetPhotoAssetAvailableCallback();
    callbackFlag_ &= ~OHOS::CameraStandard::CAPTURE_PHOTO_ASSET;
    photoOutput_->SetCallbackFlag(callbackFlag_, false);
    photoOutput_->DeferImageDeliveryFor(OHOS::CameraStandard::DeferredDeliveryImageType::DELIVERY_NONE);
    photoOutputCallback_->RemoveCallbackRef(CONST_CAPTURE_PHOTO_ASSET_AVAILABLE, callback);
}

void PhotoOutputImpl::RegisterQuickThumbnailCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi quickThumbnail on is called!");
    MEDIA_INFO_LOG("PhotoOutputImpl RegisterQuickThumbnailCallbackListener!");
    CHECK_RETURN_ELOG(photoOutput_ == nullptr, "PhotoOutput is null!");
    if (photoOutputCallback_ == nullptr) {
        ani_env* env = get_env();
        photoOutputCallback_ = std::make_shared<PhotoOutputCallbackAni>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
        photoOutput_->SetThumbnailCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void PhotoOutputImpl::UnregisterQuickThumbnailCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi quickThumbnail off is called!");
    if (!isQuickThumbnailEnabled_) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::SESSION_NOT_RUNNING, "quickThumbnail is not enabled!");
        return;
    }
    CHECK_RETURN_ELOG(photoOutput_ == nullptr, "PhotoOutput is null!");
    CHECK_RETURN_ELOG(photoOutputCallback_ == nullptr, "photoOutputCallback is null!");
    photoOutput_->UnSetThumbnailAvailableCallback();
    photoOutputCallback_->RemoveCallbackRef(eventName, callback);
}

void PhotoOutputImpl::OnError(callback_view<void(uintptr_t)> callback)
{
    ListenerTemplate<PhotoOutputImpl>::On(this, callback, CONST_CAPTURE_ERROR);
}

void PhotoOutputImpl::OffError(optional_view<callback<void(uintptr_t)>> callback)
{
    ListenerTemplate<PhotoOutputImpl>::Off(this, callback, CONST_CAPTURE_ERROR);
}

void PhotoOutputImpl::OnCaptureStartWithInfo(callback_view<void(uintptr_t, CaptureStartInfo const&)> callback)
{
    ListenerTemplate<PhotoOutputImpl>::On(this, callback, CONST_CAPTURE_START_WITH_INFO);
}

void PhotoOutputImpl::OffCaptureStartWithInfo(
    optional_view<callback<void(uintptr_t, CaptureStartInfo const&)>> callback)
{
    ListenerTemplate<PhotoOutputImpl>::Off(this, callback, CONST_CAPTURE_START_WITH_INFO);
}

void PhotoOutputImpl::OnCaptureEnd(callback_view<void(uintptr_t, CaptureEndInfo const&)> callback)
{
    ListenerTemplate<PhotoOutputImpl>::On(this, callback, CONST_CAPTURE_END);
}

void PhotoOutputImpl::OffCaptureEnd(optional_view<callback<void(uintptr_t, CaptureEndInfo const&)>> callback)
{
    ListenerTemplate<PhotoOutputImpl>::Off(this, callback, CONST_CAPTURE_END);
}

void PhotoOutputImpl::OnCaptureReady(callback_view<void(uintptr_t, uintptr_t)> callback)
{
    ListenerTemplate<PhotoOutputImpl>::On(this, callback, CONST_CAPTURE_READY);
}

void PhotoOutputImpl::OffCaptureReady(optional_view<callback<void(uintptr_t, uintptr_t)>> callback)
{
    ListenerTemplate<PhotoOutputImpl>::Off(this, callback, CONST_CAPTURE_READY);
}

void PhotoOutputImpl::OnFrameShutter(callback_view<void(uintptr_t, FrameShutterInfo const&)> callback)
{
    ListenerTemplate<PhotoOutputImpl>::On(this, callback, CONST_CAPTURE_FRAME_SHUTTER);
}

void PhotoOutputImpl::OffFrameShutter(optional_view<callback<void(uintptr_t, FrameShutterInfo const&)>> callback)
{
    ListenerTemplate<PhotoOutputImpl>::Off(this, callback, CONST_CAPTURE_FRAME_SHUTTER);
}

void PhotoOutputImpl::OnFrameShutterEnd(callback_view<void(uintptr_t, FrameShutterEndInfo const&)> callback)
{
    ListenerTemplate<PhotoOutputImpl>::On(this, callback, CONST_CAPTURE_FRAME_SHUTTER_END);
}

void PhotoOutputImpl::OffFrameShutterEnd(optional_view<callback<void(uintptr_t, FrameShutterEndInfo const&)>> callback)
{
    ListenerTemplate<PhotoOutputImpl>::Off(this, callback, CONST_CAPTURE_FRAME_SHUTTER_END);
}

void PhotoOutputImpl::OnEstimatedCaptureDuration(callback_view<void(uintptr_t, double)> callback)
{
    ListenerTemplate<PhotoOutputImpl>::On(this, callback, CONST_CAPTURE_ESTIMATED_CAPTURE_DURATION);
}

void PhotoOutputImpl::OffEstimatedCaptureDuration(optional_view<callback<void(uintptr_t, double)>> callback)
{
    ListenerTemplate<PhotoOutputImpl>::Off(this, callback, CONST_CAPTURE_ESTIMATED_CAPTURE_DURATION);
}

void PhotoOutputImpl::OnPhotoAvailable(callback_view<void(uintptr_t, weak::Photo)> callback)
{
    ListenerTemplate<PhotoOutputImpl>::On(this, callback, CONST_CAPTURE_PHOTO_AVAILABLE);
}

void PhotoOutputImpl::OffPhotoAvailable(optional_view<callback<void(uintptr_t, weak::Photo)>> callback)
{
    ListenerTemplate<PhotoOutputImpl>::Off(this, callback, CONST_CAPTURE_PHOTO_AVAILABLE);
}

void PhotoOutputImpl::OnDeferredPhotoProxyAvailable(callback_view<void(uintptr_t, weak::DeferredPhotoProxy)> callback)
{
    ListenerTemplate<PhotoOutputImpl>::On(this, callback, CONST_CAPTURE_DEFERRED_PHOTO_AVAILABLE);
}

void PhotoOutputImpl::OffDeferredPhotoProxyAvailable(
    optional_view<callback<void(uintptr_t, weak::DeferredPhotoProxy)>> callback)
{
    ListenerTemplate<PhotoOutputImpl>::Off(this, callback, CONST_CAPTURE_DEFERRED_PHOTO_AVAILABLE);
}

void PhotoOutputImpl::OnOfflineDeliveryFinished(callback_view<void(uintptr_t, uintptr_t)> callback)
{
    ListenerTemplate<PhotoOutputImpl>::On(this, callback, CONST_CAPTURE_OFFLINE_DELIVERY_FINISHED);
}

void PhotoOutputImpl::OffOfflineDeliveryFinished(optional_view<callback<void(uintptr_t, uintptr_t)>> callback)
{
    ListenerTemplate<PhotoOutputImpl>::Off(this, callback, CONST_CAPTURE_OFFLINE_DELIVERY_FINISHED);
}

void PhotoOutputImpl::OnPhotoAssetAvailable(callback_view<void(uintptr_t, uintptr_t)> callback)
{
    ListenerTemplate<PhotoOutputImpl>::On(this, callback, CONST_CAPTURE_PHOTO_ASSET_AVAILABLE);
}
void PhotoOutputImpl::OffPhotoAssetAvailable(optional_view<callback<void(uintptr_t, uintptr_t)>> callback)
{
    ListenerTemplate<PhotoOutputImpl>::Off(this, callback, CONST_CAPTURE_PHOTO_ASSET_AVAILABLE);
}

void PhotoOutputImpl::OnQuickThumbnail(
    callback_view<void(uintptr_t, ohos::multimedia::image::image::weak::PixelMap)> callback)
{
    ListenerTemplate<PhotoOutputImpl>::On(this, callback, CONST_CAPTURE_QUICK_THUMBNAIL);
}
void PhotoOutputImpl::OffQuickThumbnail(
    optional_view<callback<void(uintptr_t, ohos::multimedia::image::image::weak::PixelMap)>> callback)
{
    ListenerTemplate<PhotoOutputImpl>::Off(this, callback, CONST_CAPTURE_QUICK_THUMBNAIL);
}

bool PhotoOutputImpl::GetEnableMirror()
{
    return isMirrorEnabled_;
}

void PhotoOutputImpl::EnableMirror(bool enabled)
{
    if (photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("PhotoOutputImpl::EnableMirror get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "get native object fail");
        return;
    }
    int32_t retCode = photoOutput_->EnableMirror(enabled);
    CHECK_PRINT_ELOG(!CameraUtilsTaihe::CheckError(retCode),
        "PhotoOutputImpl::EnableMirror fail %{public}d", retCode);
}

bool PhotoOutputImpl::IsMirrorSupported()
{
    if (photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("PhotoOutputImpl::IsMirrorSupported get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "get native object fail");
        return false;
    }
    return photoOutput_->IsMirrorSupported();
}

Profile PhotoOutputImpl::GetActiveProfile()
{
    Profile res {
        .size = {
            .height = -1,
            .width = -1,
        },
        .format = CameraFormat::key_t::CAMERA_FORMAT_YUV_420_SP,
    };
    CHECK_RETURN_RET_ELOG(photoOutput_ == nullptr, res, "GetActiveProfile failed, photoOutput_ is nullptr");
    auto profile = photoOutput_->GetPhotoProfile();
    CHECK_RETURN_RET_ELOG(profile == nullptr, res, "GetActiveProfile failed, profile is nullptr");
    CameraFormat cameraFormat = CameraUtilsTaihe::ToTaiheCameraFormat(profile->GetCameraFormat());
    res.size.height = profile->GetSize().height;
    res.size.width = profile->GetSize().width;
    res.format = cameraFormat;
    return res;
}

void PhotoOutputImpl::EnableMovingPhoto(bool enabled)
{
    CHECK_RETURN_ELOG(photoOutput_ == nullptr, "EnableMovingPhoto photoOutput_ is null");
    auto session = GetPhotoOutput()->GetSession();
    CHECK_RETURN_ELOG(session == nullptr, "EnableMovingPhoto session is null");
    photoOutput_->EnableMovingPhoto(enabled);
    session->LockForControl();
    int32_t retCode = session->EnableMovingPhoto(enabled);
    session->UnlockForControl();
    CHECK_RETURN_ELOG(retCode != 0 && !CameraUtilsTaihe::CheckError(retCode), "EnableMovingPhoto failed");
}

bool PhotoOutputImpl::IsMovingPhotoSupported()
{
    CHECK_RETURN_RET_ELOG(photoOutput_ == nullptr,
        false, "IsMovingPhotoSupported failed, photoOutput_ is nullptr");
    auto session = photoOutput_->GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, false, "EnableMovingPhoto session is null");
    return session->IsMovingPhotoSupported();
}

ImageRotation PhotoOutputImpl::GetPhotoRotation()
{
    CHECK_RETURN_RET_ELOG(photoOutput_ == nullptr, ImageRotation(static_cast<ImageRotation::key_t>(-1)),
        "GetPhotoRotation failed, photoOutput_ is nullptr");
    int32_t retCode = photoOutput_->GetPhotoRotation();
    if (retCode == OHOS::CameraStandard::SERVICE_FATL_ERROR) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::SERVICE_FATL_ERROR,
            "GetPhotoRotation Camera service fatal error.");
        return ImageRotation(static_cast<ImageRotation::key_t>(-1));
    }
    int32_t taiheRetCode = CameraUtilsTaihe::ToTaiheImageRotation(retCode);
    return ImageRotation(static_cast<ImageRotation::key_t>(taiheRetCode));
}

ImageRotation PhotoOutputImpl::GetPhotoRotation(int32_t deviceDegree)
{
    CHECK_RETURN_RET_ELOG(photoOutput_ == nullptr, ImageRotation(static_cast<ImageRotation::key_t>(-1)),
        "GetPhotoRotation failed, photoOutput_ is nullptr");
    int32_t retCode = photoOutput_->GetPhotoRotation(deviceDegree);
    if (retCode == OHOS::CameraStandard::SERVICE_FATL_ERROR) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::SERVICE_FATL_ERROR,
            "GetPhotoRotation Camera service fatal error.");
        return ImageRotation(static_cast<ImageRotation::key_t>(-1));
    }
    int32_t taiheRetCode = CameraUtilsTaihe::ToTaiheImageRotation(retCode);
    return ImageRotation(static_cast<ImageRotation::key_t>(taiheRetCode));
}

void PhotoOutputImpl::EnableQuickThumbnail(bool enabled)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi EnableQuickThumbnail is called!");
    CHECK_RETURN_ELOG(photoOutput_ == nullptr, "EnableQuickThumbnail photoOutput_ is null");
    isQuickThumbnailEnabled_ = enabled;
    int32_t retCode = photoOutput_->SetThumbnail(enabled);
    CHECK_RETURN(retCode != 0 && !CameraUtilsTaihe::CheckError(retCode));
}

void PhotoOutputImpl::EnableOffline()
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi EnableOffline on is called!");
    CHECK_RETURN_ELOG(photoOutput_ == nullptr, "EnableOfflinePhoto photoOutput_ is null");
    auto session = GetPhotoOutput()->GetSession();
    CHECK_RETURN_ELOG(session == nullptr, "EnableOfflinePhoto session is null");
    photoOutput_->EnableOfflinePhoto();
}

bool PhotoOutputImpl::IsOfflineSupported()
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        false, "SystemApi IsOfflineSupported is called!");
    CHECK_RETURN_RET_ELOG(photoOutput_ == nullptr, false, "IsOfflineSupported failed, photoOutput_ is nullptr");
    return photoOutput_->IsOfflineSupported();
}

OHOS::sptr<OHOS::CameraStandard::PhotoOutput> PhotoOutputImpl::GetPhotoOutput()
{
    return photoOutput_;
}

void ProcessCapture(PhotoOutputTaiheAsyncContext* context, bool isBurst)
{
    CHECK_RETURN(context == nullptr);
    context->status = true;
    CHECK_RETURN_ELOG(context->objectInfo == nullptr, "context->objectInfo is null");
    OHOS::sptr<OHOS::CameraStandard::PhotoOutput> photoOutput = context->objectInfo->GetPhotoOutput();
    CHECK_RETURN_ELOG(!photoOutput, "photoOutput is null");
    MEDIA_INFO_LOG("PhotoOutputTaiheAsyncContext objectInfo GetEnableMirror is %{public}d",
        context->objectInfo->GetEnableMirror());
    if (context->hasPhotoSettings) {
        std::shared_ptr<OHOS::CameraStandard::PhotoCaptureSetting> capSettings =
            std::make_shared<OHOS::CameraStandard::PhotoCaptureSetting>();
        CHECK_EXECUTE(context->quality != -1,
            capSettings->SetQuality(static_cast<OHOS::CameraStandard::PhotoCaptureSetting::QualityLevel>(
                context->quality)));
        CHECK_EXECUTE(context->rotation != -1,
            capSettings->SetRotation(static_cast<OHOS::CameraStandard::PhotoCaptureSetting::RotationConfig>(
                context->rotation)));
        if (!context->isMirrorSettedByUser) {
            capSettings->SetMirror(context->objectInfo->GetEnableMirror());
        } else {
            capSettings->SetMirror(context->isMirror);
        }
        CHECK_EXECUTE(context->location != nullptr, capSettings->SetLocation(context->location));
        if (isBurst) {
            MEDIA_ERR_LOG("ProcessContext BurstCapture");
            uint8_t burstState = 1; // 0:end 1:start
            capSettings->SetBurstCaptureState(burstState);
        }
        context->errorCode = photoOutput->Capture(capSettings);
    } else {
        std::shared_ptr<OHOS::CameraStandard::PhotoCaptureSetting> capSettings =
            std::make_shared<OHOS::CameraStandard::PhotoCaptureSetting>();
        capSettings->SetMirror(context->objectInfo->GetEnableMirror());
        context->errorCode = photoOutput->Capture(capSettings);
    }
    context->status = context->errorCode == 0;
}

void PhotoOutputImpl::CaptureSync()
{
    std::unique_ptr<PhotoOutputTaiheAsyncContext> asyncContext = std::make_unique<PhotoOutputTaiheAsyncContext>(
        "PhotoOutputTaihe::Capture", CameraUtilsTaihe::IncrementAndGet(photoOutputTaskId_));
    asyncContext->queueTask =
        CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("PhotoOutputTaihe::Capture");
    asyncContext->objectInfo = this;
    CHECK_RETURN_ELOG(asyncContext->objectInfo == nullptr, "PhotoOutputAni::Capture async info is nullptr");
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    auto context = static_cast<PhotoOutputTaiheAsyncContext*>(asyncContext.release());

    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(context->queueTask, [&context]() {
        ProcessCapture(context, false);
    });

    if (!(context->status)) {
        CameraUtilsTaihe::CheckError(context->errorCode);
    }

    context->objectInfo = nullptr;
    delete context;
}

static bool ParseCaptureSettings(PhotoOutputTaiheAsyncContext* asyncContext, PhotoCaptureSetting const& setting)
{
    CHECK_RETURN_RET_ELOG(asyncContext == nullptr, false, "ParseCaptureSettings asyncContext is nullptr");
    bool res = false;
    if (setting.quality.has_value()) {
        asyncContext->quality = setting.quality.value().get_value();
        res = true;
    }
    if (setting.rotation.has_value()) {
        asyncContext->rotation = setting.rotation.value().get_value();
        res = true;
    }
    if (setting.mirror.has_value()) {
        asyncContext->isMirror = setting.mirror.value();
        res = true;
    }
    if (setting.location.has_value()) {
        OHOS::CameraStandard::Location settingsLocation;
        settingsLocation.latitude = setting.location.value().latitude;
        settingsLocation.longitude = setting.location.value().longitude;
        settingsLocation.altitude = setting.location.value().altitude;
        asyncContext->location = std::make_shared<OHOS::CameraStandard::Location>(settingsLocation);
        res = true;
    }
    return res;
}

void PhotoOutputImpl::CaptureSyncWithSetting(PhotoCaptureSetting const& setting)
{
    std::unique_ptr<PhotoOutputTaiheAsyncContext> asyncContext = std::make_unique<PhotoOutputTaiheAsyncContext>(
        "PhotoOutputTaihe::Capture", CameraUtilsTaihe::IncrementAndGet(photoOutputTaskId_));
    asyncContext->queueTask =
        CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("PhotoOutputTaihe::Capture");
    asyncContext->objectInfo = this;
    asyncContext->hasPhotoSettings = ParseCaptureSettings(asyncContext.get(), setting);
    CHECK_RETURN_ELOG(asyncContext->objectInfo == nullptr, "PhotoOutputAni::Capture async info is nullptr");
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    auto context = static_cast<PhotoOutputTaiheAsyncContext*>(asyncContext.release());
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(context->queueTask, [&context]() {
        ProcessCapture(context, false);
    });
    if (!(context->status)) {
        CameraUtilsTaihe::CheckError(context->errorCode);
    }
    context->objectInfo = nullptr;
    delete context;
}

void PhotoOutputImpl::BurstCaptureSync(PhotoCaptureSetting const& setting)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi BurstCaptureSync  is called!");
    std::unique_ptr<PhotoOutputTaiheAsyncContext> asyncContext = std::make_unique<PhotoOutputTaiheAsyncContext>(
        "PhotoOutputTaihe::BurstCapture", CameraUtilsTaihe::IncrementAndGet(photoOutputTaskId_));
    asyncContext->queueTask =
        CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("PhotoOutputTaihe::BurstCapture");
    asyncContext->objectInfo = this;
    asyncContext->hasPhotoSettings = ParseCaptureSettings(asyncContext.get(), setting);
    CHECK_RETURN_ELOG(asyncContext->objectInfo == nullptr, "PhotoOutputAni::BurstCapture async info is nullptr");
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    auto context = static_cast<PhotoOutputTaiheAsyncContext*>(asyncContext.release());
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(context->queueTask, [&context]() {
        ProcessCapture(context, false);
    });
    if (!(context->status)) {
        CameraUtilsTaihe::CheckError(context->errorCode);
    }
    context->objectInfo = nullptr;
    delete context;
}

void PhotoOutputImpl::EnableAutoCloudImageEnhancement(bool enabled)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi EnableAutoCloudImageEnhancement is called!");
    CHECK_RETURN_ELOG(photoOutput_ == nullptr, "EnableAutoCloudImageEnhancement photoOutput_ is null");
    int32_t retCode = photoOutput_->EnableAutoCloudImageEnhancement(enabled);
    CHECK_PRINT_ELOG(!CameraUtilsTaihe::CheckError(retCode),
        "PhotoOutputImpl::EnableAutoCloudImageEnhancement fail %{public}d", retCode);
    MEDIA_DEBUG_LOG("PhotoOutputImpl::EnableAutoCloudImageEnhancement success");
}

bool PhotoOutputImpl::IsAutoCloudImageEnhancementSupported()
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        false, "SystemApi IsAutoCloudImageEnhancementSupported is called!");
    MEDIA_DEBUG_LOG("PhotoOutputImpl::IsAutoCloudImageEnhancementSupported is called");
    if (photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("PhotoOutputImpl::IsAutoCloudImageEnhancementSupported get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "get native object fail");
        return false;
    }

    bool isAutoCloudImageEnhancementSupported = false;
    int32_t retCode = photoOutput_->IsAutoCloudImageEnhancementSupported(isAutoCloudImageEnhancementSupported);
    CHECK_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), false);
    MEDIA_DEBUG_LOG("PhotoOutputImpl::IsAutoCloudImageEnhancementSupported is %{public}d",
        isAutoCloudImageEnhancementSupported);
    return isAutoCloudImageEnhancementSupported;
}

bool PhotoOutputImpl::IsDepthDataDeliverySupported()
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        false, "SystemApi IsDepthDataDeliverySupported is called!");
    if (photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("PhotoOutputImpl::IsDepthDataDeliverySupported get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "get native object fail");
        return false;
    }
    return photoOutput_->IsDepthDataDeliverySupported();
}

void PhotoOutputImpl::EnableDepthDataDelivery(bool enabled)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi EnableDepthDataDelivery is called!");
    if (photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("PhotoOutputImpl::EnableDepthDataDelivery get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "get native object fail");
        return;
    }
    int32_t retCode = photoOutput_->EnableDepthDataDelivery(enabled);
    CHECK_PRINT_ELOG(!CameraUtilsTaihe::CheckError(retCode),
        "PhotoOutputNapi::EnableDepthDataDelivery fail %{public}d", retCode);
}

bool PhotoOutputImpl::IsAutoHighQualityPhotoSupported()
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        false, "SystemApi IsAutoHighQualityPhotoSupported is called!");
    MEDIA_DEBUG_LOG("PhotoOutputImpl::IsAutoHighQualityPhotoSupported is called");
    if (photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("PhotoOutputImpl::IsAutoHighQualityPhotoSupported get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "get native object fail");
        return false;
    }

    int32_t isAutoHighQualityPhotoSupported;
    int32_t retCode = photoOutput_->IsAutoHighQualityPhotoSupported(isAutoHighQualityPhotoSupported);
    CHECK_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), false);
    return isAutoHighQualityPhotoSupported != -1;
}

void PhotoOutputImpl::EnableAutoHighQualityPhoto(bool enabled)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi EnableAutoHighQualityPhoto is called!");
    if (photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("PhotoOutputImpl::EnableAutoHighQualityPhoto get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "get native object fail");
        return;
    }
    int32_t retCode = photoOutput_->EnableAutoHighQualityPhoto(enabled);
    CHECK_PRINT_ELOG(!CameraUtilsTaihe::CheckError(retCode),
        "PhotoOutputNapi::EnableAutoHighQualityPhoto fail %{public}d", retCode);
}

void PhotoOutputImpl::EnableRawDelivery(bool enabled)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi quickThumbnail on is called!");
    CHECK_RETURN_ELOG(photoOutput_ == nullptr, "EnableRawDelivery photoOutput_ is null");
    int32_t retCode = photoOutput_->EnableRawDelivery(enabled);
    CHECK_PRINT_ELOG(retCode != 0 && !CameraUtilsTaihe::CheckError(retCode),
        "PhotoOutputImpl::EnableRawDelivery fail %{public}d", retCode);
}

bool PhotoOutputImpl::IsRawDeliverySupported()
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        false, "SystemApi IsRawDeliverySupported is called!");
    bool isSupported = false;
    CHECK_RETURN_RET_ELOG(photoOutput_ == nullptr,
        false, "IsRawDeliverySupported failed, photoOutput_ is nullptr");
    int32_t retCode = photoOutput_->IsRawDeliverySupported(isSupported);
    CHECK_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), false);
    return isSupported;
}

void PhotoOutputImpl::SetMovingPhotoVideoCodecType(VideoCodecType codecType)
{
    MEDIA_DEBUG_LOG("PhotoOutputImpl::SetMovingPhotoVideoCodecType is called");
    CHECK_RETURN_ELOG(!photoOutput_, "photoOutput_ is null");
    int32_t retCode = photoOutput_->SetMovingPhotoVideoCodecType(static_cast<int32_t>(codecType.get_value()));
    CHECK_PRINT_ELOG(retCode != 0 && !CameraUtilsTaihe::CheckError(retCode),
        "PhotoOutputImpl::SetMovingPhotoVideoCodecType fail %{public}d", retCode);
}

array<VideoCodecType> PhotoOutputImpl::GetSupportedMovingPhotoVideoCodecTypes()
{
    MEDIA_DEBUG_LOG("GetSupportedMovingPhotoVideoCodecTypes is called");
    std::vector<VideoCodecType> videoCodecTypes;
    videoCodecTypes.emplace_back(VideoCodecType::key_t::AVC);
    videoCodecTypes.emplace_back(VideoCodecType::key_t::HEVC);
    return array<VideoCodecType>(videoCodecTypes);
}

void PhotoOutputImpl::ConfirmCapture()
{
    MEDIA_INFO_LOG("ConfirmCapture is called");
    CHECK_RETURN_ELOG(photoOutput_ == nullptr, "PhotoOutputImpl::ConfirmCapture photoOutput_ is nullptr");
    int32_t retCode = photoOutput_->ConfirmCapture();
    CHECK_PRINT_ELOG(!CameraUtilsTaihe::CheckError(retCode),
        "PhotoOutputImpl::ConfirmCapture fail %{public}d", retCode);
}

bool PhotoOutputImpl::IsDeferredImageDeliverySupported(DeferredDeliveryImageType type)
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        false, "SystemApi IsDeferredImageDeliverySupported is called!");
    CHECK_RETURN_RET_ELOG(photoOutput_ == nullptr,
        false, "IsDeferredImageDeliverySupported failed, photoOutput_ is nullptr");
    int32_t retCode = photoOutput_->IsDeferredImageDeliverySupported(
        static_cast<OHOS::CameraStandard::DeferredDeliveryImageType>(type.get_value()));
    bool isSupported = (retCode == 0);
    CHECK_RETURN_RET(retCode > 0 && !CameraUtilsTaihe::CheckError(retCode), false);
    return isSupported;
}

bool PhotoOutputImpl::IsDeferredImageDeliveryEnabled(DeferredDeliveryImageType type)
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        false, "SystemApi IsDeferredImageDeliveryEnabled is called!");
    CHECK_RETURN_RET_ELOG(photoOutput_ == nullptr,
        false, "IsDeferredImageDeliveryEnabled failed, photoOutput_ is nullptr");
    int32_t retCode = photoOutput_->IsDeferredImageDeliveryEnabled(
        static_cast<OHOS::CameraStandard::DeferredDeliveryImageType>(type.get_value()));
    bool isSupported = (retCode == 0);
    CHECK_RETURN_RET(retCode > 0 && !CameraUtilsTaihe::CheckError(retCode), false);
    return isSupported;
}

bool PhotoOutputImpl::IsQuickThumbnailSupported()
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        false, "SystemApi IsQuickThumbnailSupported is called!");
    CHECK_RETURN_RET_ELOG(photoOutput_ == nullptr,
        false, "IsQuickThumbnailSupported failed, photoOutput_ is nullptr");
    int32_t retCode = photoOutput_->IsQuickThumbnailSupported();
    bool isSupported = (retCode == 0);
    CHECK_RETURN_RET(retCode > 0 && !CameraUtilsTaihe::CheckError(retCode), false);
    return isSupported;
}

void PhotoOutputImpl::DeferImageDelivery(DeferredDeliveryImageType type)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi DeferImageDelivery is called!");
    CHECK_RETURN_ELOG(photoOutput_ == nullptr, "photoOutput_ is nullptr");
    photoOutput_->DeferImageDeliveryFor(
        static_cast<OHOS::CameraStandard::DeferredDeliveryImageType>(type.get_value()));
    isDeferredPhotoEnabled_ = type.get_value() == OHOS::CameraStandard::DeferredDeliveryImageType::DELIVERY_PHOTO;
}
} // namespace Camera
} // namespace Ani