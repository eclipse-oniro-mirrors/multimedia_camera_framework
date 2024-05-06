/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include <mutex>
#include <uv.h>
#include <unistd.h>
#include "camera_buffer_handle_utils.h"
#include "camera_error_code.h"
#include "camera_napi_security_utils.h"
#include "camera_napi_template_utils.h"
#include "camera_napi_utils.h"
#include "camera_napi_param_parser.h"
#include "camera_output_capability.h"
#include "image_napi.h"
#include "image_receiver.h"
#include "pixel_map_napi.h"
#include "image_packer.h"
#include "video_key_info.h"
#include "output/photo_output_napi.h"
#include "output/photo_napi.h"
#include "output/deferred_photo_proxy_napi.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;
thread_local napi_ref PhotoOutputNapi::sConstructor_ = nullptr;
thread_local sptr<PhotoOutput> PhotoOutputNapi::sPhotoOutput_ = nullptr;
thread_local sptr<Surface> PhotoOutputNapi::sPhotoSurface_ = nullptr;
thread_local uint32_t PhotoOutputNapi::photoOutputTaskId = CAMERA_PHOTO_OUTPUT_TASKID;
static uv_sem_t g_captureStartSem;
static bool g_isSemInited;
static std::mutex g_photoImageMutex;
PhotoListener::PhotoListener(napi_env env, const sptr<Surface> photoSurface) : env_(env), photoSurface_(photoSurface)
{
    if (bufferProcessor_ == nullptr && photoSurface != nullptr) {
        bufferProcessor_ = std::make_shared<PhotoBufferProcessor> (photoSurface);
    }
    capturePhotoCb_ = nullptr;
    captureDeferredPhotoCb_ = nullptr;
}
RawPhotoListener::RawPhotoListener(napi_env env,
    const sptr<Surface> rawPhotoSurface) : env_(env), rawPhotoSurface_(rawPhotoSurface)
{
    if (bufferProcessor_ == nullptr && rawPhotoSurface != nullptr) {
        bufferProcessor_ = std::make_shared<PhotoBufferProcessor> (rawPhotoSurface);
    }
}

void PhotoListener::OnBufferAvailable()
{
    std::lock_guard<std::mutex> lock(g_photoImageMutex);
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("PhotoListener::OnBufferAvailable is called");
    if (!photoSurface_) {
        MEDIA_ERR_LOG("photoOutput napi photoSurface_ is null");
        return;
    }
    UpdateJSCallbackAsync(photoSurface_);
}

void PhotoListener::ExecutePhoto(sptr<SurfaceBuffer> surfaceBuffer) const
{
    MEDIA_INFO_LOG("ExecutePhoto");
    napi_value result[ARGS_TWO] = {nullptr, nullptr};
    napi_value callback = nullptr;
    napi_value retVal;

    napi_value mainImage = nullptr;

    std::shared_ptr<Media::NativeImage> image = std::make_shared<Media::NativeImage>(surfaceBuffer, bufferProcessor_);

    napi_get_undefined(env_, &result[PARAM0]);
    napi_get_undefined(env_, &result[PARAM1]);

    mainImage = Media::ImageNapi::Create(env_, image);
    if (mainImage == nullptr) {
        MEDIA_ERR_LOG("ImageNapi Create failed");
        napi_get_undefined(env_, &mainImage);
    }

    result[PARAM1] = PhotoNapi::CreatePhoto(env_, mainImage);

    napi_get_reference_value(env_, capturePhotoCb_, &callback);
    napi_call_function(env_, nullptr, callback, ARGS_TWO, result, &retVal);
    photoSurface_->ReleaseBuffer(surfaceBuffer, -1);
}

void PhotoListener::ExecuteDeferredPhoto(sptr<SurfaceBuffer> surfaceBuffer) const
{
    MEDIA_INFO_LOG("ExecuteDeferredPhoto");
    napi_value result[ARGS_TWO] = {nullptr, nullptr};
    napi_value callback = nullptr;
    napi_value retVal;

    BufferHandle* bufferHandle = surfaceBuffer->GetBufferHandle();
    int64_t imageId;
    int32_t deferredProcessingType;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::imageId, imageId);
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::deferredProcessingType, deferredProcessingType);
    MEDIA_INFO_LOG("PhotoListener ExecuteDeferredPhoto imageId:%{public}" PRId64 ", deferredProcessingType:%{public}d",
        imageId, deferredProcessingType);

    // create pixelMap to encode
    int32_t thumbnailWidth;
    int32_t thumbnailHeight;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::CameraStandard::dataWidth, thumbnailWidth);
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::CameraStandard::dataHeight, thumbnailHeight);
    MEDIA_INFO_LOG("thumbnailWidth:%{public}d, thumbnailHeight: %{public}d", thumbnailWidth, thumbnailHeight);

    int32_t width = bufferHandle->width;
    int32_t height = bufferHandle->height;
    int32_t stride = bufferHandle->stride;
    int32_t fd = bufferHandle->fd;
    int32_t size = bufferHandle->size;
    int32_t format = bufferHandle->format;
    MEDIA_DEBUG_LOG("w:%{public}d, h:%{public}d, s:%{public}d, fd:%{public}d, size: %{public}d, format: %{public}d",
        width, height, stride, fd, size, format);

    napi_get_undefined(env_, &result[PARAM0]);
    napi_get_undefined(env_, &result[PARAM1]);

    // deep copy buffer
    sptr<SurfaceBuffer> newSurfaceBuffer = SurfaceBuffer::Create();
    DeepCopyBuffer(newSurfaceBuffer, surfaceBuffer);
    BufferHandle *newBufferHandle = CameraCloneBufferHandle(newSurfaceBuffer->GetBufferHandle());
    if (newBufferHandle == nullptr) {
        napi_value errorCode;
        napi_create_int32(env_, CameraErrorCode::INVALID_ARGUMENT, &errorCode);
        result[PARAM0] = errorCode;
        MEDIA_ERR_LOG("invalid bufferHandle");
    }

    // call js function
    sptr<DeferredPhotoProxy> deferredPhotoProxy;
    std::string imageIdStr = std::to_string(imageId);
    deferredPhotoProxy = new(std::nothrow) DeferredPhotoProxy(newBufferHandle, imageIdStr, deferredProcessingType,
        thumbnailWidth, thumbnailHeight);
    result[PARAM1] = DeferredPhotoProxyNapi::CreateDeferredPhotoProxy(env_, deferredPhotoProxy);
    napi_get_reference_value(env_, captureDeferredPhotoCb_, &callback);
    napi_call_function(env_, nullptr, callback, ARGS_TWO, result, &retVal);

    // return buffer to buffer queue
    photoSurface_->ReleaseBuffer(surfaceBuffer, -1);
}

void PhotoListener::DeepCopyBuffer(sptr<SurfaceBuffer> newSurfaceBuffer, sptr<SurfaceBuffer> surfaceBuffer) const
{
    BufferRequestConfig requestConfig = {
        .width = surfaceBuffer->GetWidth(),
        .height = surfaceBuffer->GetHeight(),
        .strideAlignment = 0x8, // default stride is 8 Bytes.
        .format = surfaceBuffer->GetFormat(),
        .usage = surfaceBuffer->GetUsage(),
        .timeout = 0,
        .colorGamut = surfaceBuffer->GetSurfaceBufferColorGamut(),
        .transform = surfaceBuffer->GetSurfaceBufferTransform(),
    };
    auto allocErrorCode = newSurfaceBuffer->Alloc(requestConfig);
    MEDIA_INFO_LOG("SurfaceBuffer alloc ret: %d", allocErrorCode);
    if (memcpy_s(newSurfaceBuffer->GetVirAddr(), newSurfaceBuffer->GetSize(),
        surfaceBuffer->GetVirAddr(), surfaceBuffer->GetSize()) != EOK) {
        MEDIA_ERR_LOG("PhotoListener memcpy_s failed");
    }
}

void PhotoListener::UpdateJSCallback(sptr<Surface> photoSurface) const
{
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    int32_t fence = -1;
    int64_t timestamp;
    OHOS::Rect damage;
    SurfaceError surfaceRet = photoSurface->AcquireBuffer(surfaceBuffer, fence, timestamp, damage);
    if (surfaceRet != SURFACE_ERROR_OK) {
        MEDIA_ERR_LOG("PhotoListener Failed to acquire surface buffer");
        return;
    }

    int32_t isDegradedImage;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::isDegradedImage, isDegradedImage);
    MEDIA_INFO_LOG("PhotoListener UpdateJSCallback isDegradedImage:%{public}d", isDegradedImage);

    if (isDegradedImage == 0) {
        ExecutePhoto(surfaceBuffer);
    } else {
        ExecuteDeferredPhoto(surfaceBuffer);
    }
}

void PhotoListener::UpdateJSCallbackAsync(sptr<Surface> photoSurface) const
{
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("PhotoListener:UpdateJSCallbackAsync() failed to get event loop");
        return;
    }
    uv_work_t* work = new (std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("PhotoListener:UpdateJSCallbackAsync() failed to allocate work");
        return;
    }
    std::unique_ptr<PhotoListenerInfo> callbackInfo = std::make_unique<PhotoListenerInfo>(photoSurface, this);
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(
        loop, work, [](uv_work_t* work) {},
        [](uv_work_t* work, int status) {
            PhotoListenerInfo* callbackInfo = reinterpret_cast<PhotoListenerInfo*>(work->data);
            if (callbackInfo) {
                callbackInfo->listener_->UpdateJSCallback(callbackInfo->photoSurface_);
                MEDIA_INFO_LOG("PhotoListener:UpdateJSCallbackAsync() complete");
                callbackInfo->photoSurface_ = nullptr;
                callbackInfo->listener_ = nullptr;
                delete callbackInfo;
            }
            delete work;
        },
        uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("PhotoListener:UpdateJSCallbackAsync() failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void PhotoListener::SaveCallbackReference(const std::string &eventType, napi_value callback)
{
    MEDIA_INFO_LOG("PhotoListener SaveCallbackReference is called eventType:%{public}s", eventType.c_str());
    std::lock_guard<std::mutex> lock(mutex_);
    napi_ref *curCallbackRef;
    auto eventTypeEnum = PhotoOutputEventTypeHelper.ToEnum(eventType);
    switch (eventTypeEnum) {
        case PhotoOutputEventType::CAPTURE_PHOTO_AVAILABLE:
            curCallbackRef = &capturePhotoCb_;
            break;
        case PhotoOutputEventType::CAPTURE_DEFERRED_PHOTO_AVAILABLE:
            curCallbackRef = &captureDeferredPhotoCb_;
            break;
        default:
            MEDIA_ERR_LOG("Incorrect photo callback event type received from JS");
            return;
    }

    napi_ref callbackRef = nullptr;
    const int32_t refCount = 1;
    napi_status status = napi_create_reference(env_, callback, refCount, &callbackRef);
    CHECK_AND_RETURN_LOG(status == napi_ok && callbackRef != nullptr,
                         "creating reference for callback fail");
    *curCallbackRef = callbackRef;
}

void PhotoListener::RemoveCallbackRef(napi_env env, napi_value callback, const std::string &eventType)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (eventType == CONST_CAPTURE_PHOTO_AVAILABLE) {
        napi_delete_reference(env_, capturePhotoCb_);
        capturePhotoCb_ = nullptr;
    } else if (eventType == CONST_CAPTURE_DEFERRED_PHOTO_AVAILABLE) {
        napi_delete_reference(env_, captureDeferredPhotoCb_);
        captureDeferredPhotoCb_ = nullptr;
    }

    MEDIA_INFO_LOG("RemoveCallbackReference: js callback no find");
}

void RawPhotoListener::OnBufferAvailable()
{
    std::lock_guard<std::mutex> lock(g_photoImageMutex);
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("RawPhotoListener::OnBufferAvailable is called");
    if (!rawPhotoSurface_) {
        MEDIA_ERR_LOG("RawPhotoListener napi rawPhotoSurface_ is null");
        return;
    }
    UpdateJSCallbackAsync(rawPhotoSurface_);
}

void RawPhotoListener::ExecuteRawPhoto(sptr<SurfaceBuffer> surfaceBuffer) const
{
    MEDIA_INFO_LOG("ExecuteRawPhoto");
    napi_value result[ARGS_TWO] = {nullptr, nullptr};
    napi_value callback = nullptr;
    napi_value retVal;

    napi_value rawImage = nullptr;

    std::shared_ptr<Media::NativeImage> image = std::make_shared<Media::NativeImage>(surfaceBuffer, bufferProcessor_);

    napi_get_undefined(env_, &result[PARAM0]);
    napi_get_undefined(env_, &result[PARAM1]);

    rawImage = Media::ImageNapi::Create(env_, image);
    if (rawImage == nullptr) {
        MEDIA_ERR_LOG("ImageNapi Create failed");
        napi_get_undefined(env_, &rawImage);
    }

    result[PARAM1] = PhotoNapi::CreateRawPhoto(env_, rawImage);

    napi_get_reference_value(env_, captureRawPhotoCb_, &callback);
    napi_call_function(env_, nullptr, callback, ARGS_TWO, result, &retVal);
    rawPhotoSurface_->ReleaseBuffer(surfaceBuffer, -1);
}

void RawPhotoListener::UpdateJSCallback(sptr<Surface> rawPhotoSurface) const
{
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    int32_t fence = -1;
    int64_t timestamp;
    OHOS::Rect damage;
    SurfaceError surfaceRet = rawPhotoSurface->AcquireBuffer(surfaceBuffer, fence, timestamp, damage);
    if (surfaceRet != SURFACE_ERROR_OK) {
        MEDIA_ERR_LOG("RawPhotoListener Failed to acquire surface buffer");
        return;
    }

    int32_t isDegradedImage;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::isDegradedImage, isDegradedImage);
    MEDIA_INFO_LOG("RawPhotoListener UpdateJSCallback isDegradedImage:%{public}d", isDegradedImage);

    if (isDegradedImage == 0) {
        ExecuteRawPhoto(surfaceBuffer);
    } else {
        MEDIA_ERR_LOG("RawPhoto not support deferred photo");
    }
}

void RawPhotoListener::UpdateJSCallbackAsync(sptr<Surface> rawPhotoSurface) const
{
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("RawPhotoListener:UpdateJSCallbackAsync() failed to get event loop");
        return;
    }
    uv_work_t* work = new (std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("RawPhotoListener:UpdateJSCallbackAsync() failed to allocate work");
        return;
    }
    std::unique_ptr<RawPhotoListenerInfo> callbackInfo = std::make_unique<RawPhotoListenerInfo>(rawPhotoSurface, this);
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(
        loop, work, [](uv_work_t* work) {},
        [](uv_work_t* work, int status) {
            RawPhotoListenerInfo* callbackInfo = reinterpret_cast<RawPhotoListenerInfo*>(work->data);
            if (callbackInfo) {
                callbackInfo->listener_->UpdateJSCallback(callbackInfo->rawPhotoSurface_);
                MEDIA_INFO_LOG("RawPhotoListener:UpdateJSCallbackAsync() complete");
                callbackInfo->rawPhotoSurface_ = nullptr;
                callbackInfo->listener_ = nullptr;
                delete callbackInfo;
            }
            delete work;
        },
        uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("RawPhotoListener:UpdateJSCallbackAsync() failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void RawPhotoListener::SaveCallbackReference(const std::string &eventType, napi_value callback)
{
    MEDIA_INFO_LOG("RawPhotoListener SaveCallbackReference is called eventType:%{public}s", eventType.c_str());
    std::lock_guard<std::mutex> lock(mutex_);
    napi_ref *curCallbackRef;
    auto eventTypeEnum = PhotoOutputEventTypeHelper.ToEnum(eventType);
    switch (eventTypeEnum) {
        case PhotoOutputEventType::CAPTURE_PHOTO_AVAILABLE:
            curCallbackRef = &captureRawPhotoCb_;
            break;
        default:
            MEDIA_ERR_LOG("Incorrect photo callback event type received from JS");
            return;
    }

    napi_ref callbackRef = nullptr;
    const int32_t refCount = 1;
    napi_status status = napi_create_reference(env_, callback, refCount, &callbackRef);
    CHECK_AND_RETURN_LOG(status == napi_ok && callbackRef != nullptr,
                         "creating reference for callback fail");
    *curCallbackRef = callbackRef;
}

void RawPhotoListener::RemoveCallbackRef(napi_env env, napi_value callback, const std::string &eventType)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (eventType == CONST_CAPTURE_PHOTO_AVAILABLE) {
        napi_delete_reference(env_, captureRawPhotoCb_);
        captureRawPhotoCb_ = nullptr;
    }

    MEDIA_INFO_LOG("RemoveCallbackReference: js callback no find");
}

PhotoOutputCallback::PhotoOutputCallback(napi_env env) : env_(env) {}

void UpdateJSExecute(uv_work_t* work)
{
    PhotoOutputCallbackInfo* callbackInfo = reinterpret_cast<PhotoOutputCallbackInfo*>(work->data);
    if (callbackInfo) {
        if (callbackInfo->eventType_ == PhotoOutputEventType::CAPTURE_FRAME_SHUTTER) {
            uv_sem_wait(&g_captureStartSem);
        }
    }
}

void PhotoOutputCallback::UpdateJSCallbackAsync(PhotoOutputEventType eventType, const CallbackInfo &info) const
{
    MEDIA_DEBUG_LOG("UpdateJSCallbackAsync is called");
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr) {
        MEDIA_ERR_LOG("failed to get event loop or failed to allocate work");
        return;
    }
    uv_work_t* work = new(std::nothrow) uv_work_t;
    if (work == nullptr) {
        MEDIA_ERR_LOG("UpdateJSCallbackAsync work is null");
        return;
    }
    if (!g_isSemInited) {
        uv_sem_init(&g_captureStartSem, 0);
        g_isSemInited = true;
    }
    std::unique_ptr<PhotoOutputCallbackInfo> callbackInfo =
        std::make_unique<PhotoOutputCallbackInfo>(eventType, info, shared_from_this());
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(loop, work, UpdateJSExecute, [] (uv_work_t* work, int status) {
        PhotoOutputCallbackInfo* callbackInfo = reinterpret_cast<PhotoOutputCallbackInfo *>(work->data);
        if (callbackInfo) {
            auto listener = callbackInfo->listener_.lock();
            if (listener) {
                listener->UpdateJSCallback(callbackInfo->eventType_, callbackInfo->info_);
                if (callbackInfo->eventType_ == PhotoOutputEventType::CAPTURE_START ||
                    callbackInfo->eventType_ == PhotoOutputEventType::CAPTURE_START_WITH_INFO) {
                    MEDIA_DEBUG_LOG("PhotoOutputEventType::CAPTURE_START work done execute!");
                    uv_sem_post(&g_captureStartSem);
                } else if (callbackInfo->eventType_ == PhotoOutputEventType::CAPTURE_FRAME_SHUTTER) {
                    MEDIA_DEBUG_LOG("PhotoOutputEventType::CAPTURE_FRAME_SHUTTER work done execute!");
                    uv_sem_destroy(&g_captureStartSem);
                    g_isSemInited = false;
                }
            }
            delete callbackInfo;
        }
        delete work;
    }, uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void PhotoOutputCallback::OnCaptureStarted(const int32_t captureID) const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("OnCaptureStarted is called!, captureID: %{public}d", captureID);
    CallbackInfo info;
    info.captureID = captureID;
    UpdateJSCallbackAsync(PhotoOutputEventType::CAPTURE_START_WITH_INFO, info);
}

void PhotoOutputCallback::OnCaptureStarted(const int32_t captureID, uint32_t exposureTime) const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("OnCaptureStarted is called!, captureID: %{public}d", captureID);
    CallbackInfo info;
    info.captureID = captureID;
    info.timestamp = exposureTime;
    UpdateJSCallbackAsync(PhotoOutputEventType::CAPTURE_START, info);
}

void PhotoOutputCallback::OnCaptureEnded(const int32_t captureID, const int32_t frameCount) const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("OnCaptureEnded is called!, captureID: %{public}d, frameCount: %{public}d",
        captureID, frameCount);
    CallbackInfo info;
    info.captureID = captureID;
    info.frameCount = frameCount;
    UpdateJSCallbackAsync(PhotoOutputEventType::CAPTURE_END, info);
}

void PhotoOutputCallback::OnFrameShutter(const int32_t captureId, const uint64_t timestamp) const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG(
        "OnFrameShutter is called, captureID: %{public}d, timestamp: %{public}" PRIu64, captureId, timestamp);
    CallbackInfo info;
    info.captureID = captureId;
    info.timestamp = timestamp;
    UpdateJSCallbackAsync(PhotoOutputEventType::CAPTURE_FRAME_SHUTTER, info);
}

void PhotoOutputCallback::OnFrameShutterEnd(const int32_t captureId, const uint64_t timestamp) const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG(
        "OnFrameShutterEnd is called, captureID: %{public}d, timestamp: %{public}" PRIu64, captureId, timestamp);
    CallbackInfo info;
    info.captureID = captureId;
    info.timestamp = timestamp;
    UpdateJSCallbackAsync(PhotoOutputEventType::CAPTURE_FRAME_SHUTTER_END, info);
}

void PhotoOutputCallback::OnCaptureReady(const int32_t captureId, const uint64_t timestamp) const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG(
        "OnCaptureReady is called, captureID: %{public}d, timestamp: %{public}" PRIu64, captureId, timestamp);
    CallbackInfo info;
    info.captureID = captureId;
    info.timestamp = timestamp;
    UpdateJSCallbackAsync(PhotoOutputEventType::CAPTURE_READY, info);
}

void PhotoOutputCallback::OnCaptureError(const int32_t captureId, const int32_t errorCode) const
{
    MEDIA_DEBUG_LOG("OnCaptureError is called!, captureID: %{public}d, errorCode: %{public}d", captureId, errorCode);
    CallbackInfo info;
    info.captureID = captureId;
    info.errorCode = errorCode;
    UpdateJSCallbackAsync(PhotoOutputEventType::CAPTURE_ERROR, info);
}

void PhotoOutputCallback::OnEstimatedCaptureDuration(const int32_t duration) const
{
    MEDIA_DEBUG_LOG("OnEstimatedCaptureDuration is called!, duration: %{public}d", duration);
    CallbackInfo info;
    info.duration = duration;
    UpdateJSCallbackAsync(PhotoOutputEventType::CAPTURE_ESTIMATED_CAPTURE_DURATION, info);
}

void PhotoOutputCallback::SaveCallbackReference(const std::string& eventType, napi_value callback, bool isOnce)
{
    MEDIA_INFO_LOG("SaveCallbackReference is called");
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<AutoRef>>* callbackList;
    auto eventTypeEnum = PhotoOutputEventTypeHelper.ToEnum(eventType);
    switch (eventTypeEnum) {
        case PhotoOutputEventType::CAPTURE_START:
            callbackList = &captureStartCbList_;
            break;
        case PhotoOutputEventType::CAPTURE_END:
            callbackList = &captureEndCbList_;
            break;
        case PhotoOutputEventType::CAPTURE_FRAME_SHUTTER:
            callbackList = &frameShutterCbList_;
            break;
        case PhotoOutputEventType::CAPTURE_ERROR:
            callbackList = &errorCbList_;
            break;
        case PhotoOutputEventType::CAPTURE_FRAME_SHUTTER_END:
            callbackList = &frameShutterEndCbList_;
            break;
        case PhotoOutputEventType::CAPTURE_READY:
            callbackList = &captureReadyCbList_;
            break;
        case PhotoOutputEventType::CAPTURE_ESTIMATED_CAPTURE_DURATION:
            callbackList = &estimatedCaptureDurationCbList_;
            break;
        case PhotoOutputEventType::CAPTURE_START_WITH_INFO:
            callbackList = &captureStartCbList_;
            break;
        default:
            MEDIA_ERR_LOG("Incorrect photo callback event type received from JS");
            CameraNapiUtils::ThrowError(env_, INVALID_ARGUMENT, "Incorrect photo callback event type received from JS");
            return;
    }
    for (auto it = callbackList->begin(); it != callbackList->end(); ++it) {
        bool isSameCallback = CameraNapiUtils::IsSameCallback(env_, callback, (*it)->cb_);
        CHECK_AND_RETURN_LOG(!isSameCallback, "UpdateList: has same callback, nothing to do");
    }
    napi_ref callbackRef = nullptr;
    const int32_t refCount = 1;
    napi_status status = napi_create_reference(env_, callback, refCount, &callbackRef);
    CHECK_AND_RETURN_LOG(status == napi_ok && callbackRef != nullptr, "creating reference for callback fail");
    std::shared_ptr<AutoRef> cb = std::make_shared<AutoRef>(env_, callbackRef, isOnce);
    callbackList->push_back(cb);
    MEDIA_DEBUG_LOG("Save callback reference success, %{public}s callback list size [%{public}zu]", eventType.c_str(),
        callbackList->size());
}

void PhotoOutputCallback::RemoveCallbackRef(napi_env env, napi_value callback, const std::string& eventType)
{
    MEDIA_INFO_LOG("RemoveCallbackRef is called");
    std::lock_guard<std::mutex> lock(mutex_);
    if (callback == nullptr) {
        MEDIA_INFO_LOG("RemoveCallbackRef: js callback is nullptr, remove all callback reference");
        RemoveAllCallbacks(eventType);
        return;
    }
    std::map<PhotoOutputEventType, std::vector<std::shared_ptr<AutoRef>>*> callbackLists = {
        {PhotoOutputEventType::CAPTURE_START, &captureStartCbList_},
        {PhotoOutputEventType::CAPTURE_END, &captureEndCbList_},
        {PhotoOutputEventType::CAPTURE_FRAME_SHUTTER, &frameShutterCbList_},
        {PhotoOutputEventType::CAPTURE_ERROR, &errorCbList_},
        {PhotoOutputEventType::CAPTURE_FRAME_SHUTTER_END, &frameShutterEndCbList_},
        {PhotoOutputEventType::CAPTURE_READY, &captureReadyCbList_},
        {PhotoOutputEventType::CAPTURE_ESTIMATED_CAPTURE_DURATION, &estimatedCaptureDurationCbList_},
        {PhotoOutputEventType::CAPTURE_START_WITH_INFO, &captureStartCbList_}
    };
    auto eventTypeEnum = PhotoOutputEventTypeHelper.ToEnum(eventType);
    auto callbackListIt = callbackLists.find(eventTypeEnum);
    if (callbackListIt == callbackLists.end()) {
        MEDIA_ERR_LOG("Incorrect photo callback event type received from JS");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "Incorrect photo callback event type received from JS");
        return;
    }
    auto& callbackList = *(callbackListIt->second);
    for (auto it = callbackList.begin(); it != callbackList.end(); ++it) {
        if (CameraNapiUtils::IsSameCallback(env_, callback, (*it)->cb_)) {
            MEDIA_INFO_LOG("RemoveCallbackRef: find js callback, delete it");
            napi_status status = napi_delete_reference(env_, (*it)->cb_);
            (*it)->cb_ = nullptr;
            CHECK_AND_RETURN_LOG(status == napi_ok, "RemoveCallbackRef: delete reference for callback fail");
            callbackList.erase(it);
            MEDIA_DEBUG_LOG("RemoveCallbackRef success, %{public}s callback list size [%{public}zu]",
                eventType.c_str(), callbackList.size());
            return;
        }
    }
    MEDIA_DEBUG_LOG("Callback not found, %{public}s callback list size [%{public}zu]",
        eventType.c_str(), callbackList.size());
}

void PhotoOutputCallback::RemoveAllCallbacks(const std::string& eventType)
{
    std::vector<std::shared_ptr<AutoRef>>* callbackList;
    auto eventTypeEnum = PhotoOutputEventTypeHelper.ToEnum(eventType);
    switch (eventTypeEnum) {
        case PhotoOutputEventType::CAPTURE_START:
            callbackList = &captureStartCbList_;
            break;
        case PhotoOutputEventType::CAPTURE_END:
            callbackList = &captureEndCbList_;
            break;
        case PhotoOutputEventType::CAPTURE_FRAME_SHUTTER:
            callbackList = &frameShutterCbList_;
            break;
        case PhotoOutputEventType::CAPTURE_ERROR:
            callbackList = &errorCbList_;
            break;
        case PhotoOutputEventType::CAPTURE_FRAME_SHUTTER_END:
            callbackList = &frameShutterEndCbList_;
            break;
        case PhotoOutputEventType::CAPTURE_READY:
            callbackList = &captureReadyCbList_;
            break;
        case PhotoOutputEventType::CAPTURE_ESTIMATED_CAPTURE_DURATION:
            callbackList = &estimatedCaptureDurationCbList_;
            break;
        case PhotoOutputEventType::CAPTURE_START_WITH_INFO:
            callbackList = &captureStartCbList_;
            break;
        default:
            MEDIA_ERR_LOG("Incorrect photo callback event type received from JS");
            return;
    }
    for (auto it = callbackList->begin(); it != callbackList->end(); ++it) {
        napi_status ret = napi_delete_reference(env_, (*it)->cb_);
        if (ret != napi_ok) {
            MEDIA_ERR_LOG("RemoveAllCallbackReferences: napi_delete_reference err.");
        }
        (*it)->cb_ = nullptr;
    }
    callbackList->clear();
    MEDIA_DEBUG_LOG("RemoveAllCallbacks success, %{public}s callback list size [%{public}zu]", eventType.c_str(),
        callbackList->size());
}

void PhotoOutputCallback::ExecuteCaptureStartCb(const CallbackInfo& info) const
{
    napi_value result[ARGS_TWO] = { nullptr, nullptr };
    napi_value callback = nullptr;
    napi_value retVal;
    napi_value propValue;
    napi_get_undefined(env_, &result[PARAM0]);
    napi_get_undefined(env_, &result[PARAM1]);
    for (auto it = captureStartCbList_.begin(); it != captureStartCbList_.end();) {
        napi_env env = (*it)->env_;
        napi_create_object(env, &result[PARAM1]);
        napi_create_int32(env, info.captureID, &propValue);
        napi_set_named_property(env, result[PARAM1], "captureId", propValue);
        napi_create_int32(env, info.timestamp, &propValue);
        napi_set_named_property(env, result[PARAM1], "time", propValue);
        napi_get_reference_value(env, (*it)->cb_, &callback);
        napi_call_function(env, nullptr, callback, ARGS_TWO, result, &retVal);
        if ((*it)->isOnce_) {
            napi_status status = napi_delete_reference(env, (*it)->cb_);
            CHECK_AND_RETURN_LOG(status == napi_ok, "Remove once cb ref: delete reference for callback fail");
            (*it)->cb_ = nullptr;
            captureStartCbList_.erase(it);
        } else {
            it++;
        }
    }
}

void PhotoOutputCallback::ExecuteCaptureStartWithInfoCb(const CallbackInfo& info) const
{
    napi_value result[ARGS_TWO] = { nullptr, nullptr };
    napi_value callback = nullptr;
    napi_value retVal;
    napi_value propValue;
    napi_get_undefined(env_, &result[PARAM0]);
    napi_get_undefined(env_, &result[PARAM1]);
    for (auto it = captureStartCbList_.begin(); it != captureStartCbList_.end();) {
        napi_env env = (*it)->env_;
        napi_create_object(env, &result[PARAM1]);
        napi_create_int32(env, info.captureID, &propValue);
        napi_set_named_property(env, result[PARAM1], "captureId", propValue);
        napi_create_int32(env, info.timestamp, &propValue);
        napi_set_named_property(env, result[PARAM1], "time", propValue);
        napi_get_reference_value(env, (*it)->cb_, &callback);
        napi_call_function(env, nullptr, callback, ARGS_TWO, result, &retVal);
        if ((*it)->isOnce_) {
            napi_status status = napi_delete_reference(env, (*it)->cb_);
            CHECK_AND_RETURN_LOG(status == napi_ok, "Remove once cb ref: delete reference for callback fail");
            (*it)->cb_ = nullptr;
            captureStartCbList_.erase(it);
        } else {
            it++;
        }
    }
}

void PhotoOutputCallback::ExecuteCaptureEndCb(const CallbackInfo& info) const
{
    napi_value result[ARGS_TWO] = { nullptr, nullptr };
    napi_value callback = nullptr;
    napi_value retVal;
    napi_value propValue;
    napi_get_undefined(env_, &result[PARAM0]);
    napi_get_undefined(env_, &result[PARAM1]);
    for (auto it = captureEndCbList_.begin(); it != captureEndCbList_.end();) {
        napi_env env = (*it)->env_;
        napi_create_object(env, &result[PARAM1]);
        napi_create_int32(env, info.captureID, &propValue);
        napi_set_named_property(env, result[PARAM1], "captureId", propValue);
        napi_create_int32(env, info.frameCount, &propValue);
        napi_set_named_property(env, result[PARAM1], "frameCount", propValue);
        napi_get_reference_value(env, (*it)->cb_, &callback);
        napi_call_function(env, nullptr, callback, ARGS_TWO, result, &retVal);
        if ((*it)->isOnce_) {
            napi_status status = napi_delete_reference(env, (*it)->cb_);
            CHECK_AND_RETURN_LOG(status == napi_ok, "Remove once cb ref: delete reference for callback fail");
            (*it)->cb_ = nullptr;
            captureEndCbList_.erase(it);
        } else {
            it++;
        }
    }
}

void PhotoOutputCallback::ExecuteFrameShutterCb(const CallbackInfo& info) const
{
    napi_value result[ARGS_TWO] = { nullptr, nullptr };
    napi_value callback = nullptr;
    napi_value retVal;
    napi_value propValue;
    napi_get_undefined(env_, &result[PARAM0]);
    napi_get_undefined(env_, &result[PARAM1]);
    for (auto it = frameShutterCbList_.begin(); it != frameShutterCbList_.end();) {
        napi_env env = (*it)->env_;
        napi_create_object(env, &result[PARAM1]);
        napi_create_int32(env, info.captureID, &propValue);
        napi_set_named_property(env, result[PARAM1], "captureId", propValue);
        napi_create_int64(env, info.timestamp, &propValue);
        napi_set_named_property(env, result[PARAM1], "timestamp", propValue);
        napi_get_reference_value(env, (*it)->cb_, &callback);
        napi_call_function(env, nullptr, callback, ARGS_TWO, result, &retVal);
        if ((*it)->isOnce_) {
            napi_status status = napi_delete_reference(env, (*it)->cb_);
            CHECK_AND_RETURN_LOG(status == napi_ok, "Remove once cb ref: delete reference for callback fail");
            (*it)->cb_ = nullptr;
            frameShutterCbList_.erase(it);
        } else {
            it++;
        }
    }
}

void PhotoOutputCallback::ExecuteFrameShutterEndCb(const CallbackInfo& info) const
{
    napi_value result[ARGS_TWO] = { nullptr, nullptr };
    napi_value callback = nullptr;
    napi_value retVal;
    napi_value propValue;
    napi_get_undefined(env_, &result[PARAM0]);
    napi_get_undefined(env_, &result[PARAM1]);
    for (auto it = frameShutterEndCbList_.begin(); it != frameShutterEndCbList_.end();) {
        napi_env env = (*it)->env_;
        napi_create_object(env, &result[PARAM1]);
        napi_create_int32(env, info.captureID, &propValue);
        napi_set_named_property(env, result[PARAM1], "captureId", propValue);
        napi_get_reference_value(env, (*it)->cb_, &callback);
        napi_call_function(env, nullptr, callback, ARGS_TWO, result, &retVal);
        if ((*it)->isOnce_) {
            napi_status status = napi_delete_reference(env, (*it)->cb_);
            CHECK_AND_RETURN_LOG(status == napi_ok, "Remove once cb ref: delete reference for callback fail");
            (*it)->cb_ = nullptr;
            frameShutterEndCbList_.erase(it);
        } else {
            it++;
        }
    }
}

void PhotoOutputCallback::ExecuteCaptureReadyCb(const CallbackInfo& info) const
{
    napi_value result[ARGS_ONE] = { nullptr };
    napi_value callback = nullptr;
    napi_value retVal;
    napi_get_undefined(env_, &result[PARAM0]);
    for (auto it = captureReadyCbList_.begin(); it != captureReadyCbList_.end();) {
        napi_env env = (*it)->env_;
        napi_get_reference_value(env, (*it)->cb_, &callback);
        napi_call_function(env, nullptr, callback, ARGS_ONE, result, &retVal);
        if ((*it)->isOnce_) {
            napi_status status = napi_delete_reference(env, (*it)->cb_);
            CHECK_AND_RETURN_LOG(status == napi_ok, "Remove once cb ref: delete reference for callback fail");
            (*it)->cb_ = nullptr;
            captureReadyCbList_.erase(it);
        } else {
            it++;
        }
    }
}

void PhotoOutputCallback::ExecuteCaptureErrorCb(const CallbackInfo& info) const
{
    napi_value errJsResult[ARGS_ONE] = { nullptr };
    napi_value callback = nullptr;
    napi_value retVal;
    napi_value propValue;
    for (auto it = errorCbList_.begin(); it != errorCbList_.end();) {
        napi_env env = (*it)->env_;
        napi_create_object(env, &errJsResult[PARAM0]);
        napi_create_int32(env, info.errorCode, &propValue);
        napi_set_named_property(env, errJsResult[PARAM0], "code", propValue);
        napi_get_reference_value(env, (*it)->cb_, &callback);
        napi_call_function(env, nullptr, callback, ARGS_ONE, errJsResult, &retVal);
        if ((*it)->isOnce_) {
            napi_status status = napi_delete_reference(env, (*it)->cb_);
            CHECK_AND_RETURN_LOG(status == napi_ok, "Remove once cb ref: delete reference for callback fail");
            (*it)->cb_ = nullptr;
            errorCbList_.erase(it);
        } else {
            it++;
        }
    }
}

void PhotoOutputCallback::ExecuteEstimatedCaptureDurationCb(const CallbackInfo& info) const
{
    napi_value result[ARGS_TWO] = { nullptr, nullptr };
    napi_value callback = nullptr;
    napi_value retVal;
    napi_get_undefined(env_, &result[PARAM0]);
    napi_get_undefined(env_, &result[PARAM1]);
    for (auto it = estimatedCaptureDurationCbList_.begin(); it != estimatedCaptureDurationCbList_.end();) {
        napi_env env = (*it)->env_;
        napi_create_int32(env, info.duration, &result[PARAM1]);
        napi_get_reference_value(env, (*it)->cb_, &callback);
        napi_call_function(env, nullptr, callback, ARGS_TWO, result, &retVal);
        if ((*it)->isOnce_) {
            napi_status status = napi_delete_reference(env, (*it)->cb_);
            CHECK_AND_RETURN_LOG(status == napi_ok, "Remove once cb ref: delete reference for callback fail");
            (*it)->cb_ = nullptr;
            estimatedCaptureDurationCbList_.erase(it);
        } else {
            it++;
        }
    }
}

void PhotoOutputCallback::UpdateJSCallback(PhotoOutputEventType eventType, const CallbackInfo& info) const
{
    MEDIA_DEBUG_LOG("UpdateJSCallback is called");
    switch (eventType) {
        case PhotoOutputEventType::CAPTURE_START:
            ExecuteCaptureStartCb(info);
            break;
        case PhotoOutputEventType::CAPTURE_END:
            ExecuteCaptureEndCb(info);
            break;
        case PhotoOutputEventType::CAPTURE_FRAME_SHUTTER:
            ExecuteFrameShutterCb(info);
            break;
        case PhotoOutputEventType::CAPTURE_ERROR:
            ExecuteCaptureErrorCb(info);
            break;
        case PhotoOutputEventType::CAPTURE_FRAME_SHUTTER_END:
            ExecuteFrameShutterEndCb(info);
            break;
        case PhotoOutputEventType::CAPTURE_READY:
            ExecuteCaptureReadyCb(info);
            break;
        case PhotoOutputEventType::CAPTURE_ESTIMATED_CAPTURE_DURATION:
            ExecuteEstimatedCaptureDurationCb(info);
            break;
        case PhotoOutputEventType::CAPTURE_START_WITH_INFO:
            ExecuteCaptureStartWithInfoCb(info);
            break;
        default:
            MEDIA_ERR_LOG("Incorrect photo callback event type received from JS");
    }
}

ThumbnailListener::ThumbnailListener(napi_env env, const sptr<PhotoOutput> photoOutput)
    : ListenerBase(env), photoOutput_(photoOutput)
{}

void ThumbnailListener::OnBufferAvailable()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("ThumbnailListener:OnBufferAvailable() called");
    if (!photoOutput_) {
        MEDIA_ERR_LOG("photoOutput napi sPhotoOutput_ is null");
        return;
    }
    UpdateJSCallbackAsync(photoOutput_);
}

void ThumbnailListener::UpdateJSCallback(sptr<PhotoOutput> photoOutput) const
{
    napi_value result[ARGS_TWO] = { 0 };
    napi_get_undefined(env_, &result[0]);
    napi_get_undefined(env_, &result[1]);
    napi_value retVal;
    MEDIA_INFO_LOG("enter ImageNapi::Create start");
    int32_t fence = -1;
    int64_t timestamp;
    OHOS::Rect damage;
    sptr<SurfaceBuffer> thumbnailBuffer = nullptr;
    SurfaceError surfaceRet = photoOutput_->thumbnailSurface_->AcquireBuffer(thumbnailBuffer, fence, timestamp, damage);
    if (surfaceRet != SURFACE_ERROR_OK) {
        MEDIA_ERR_LOG("ThumbnailListener Failed to acquire surface buffer");
        return;
    }
    int32_t thumbnailWidth;
    int32_t thumbnailHeight;
    thumbnailBuffer->GetExtraData()->ExtraGet(OHOS::CameraStandard::dataWidth, thumbnailWidth);
    thumbnailBuffer->GetExtraData()->ExtraGet(OHOS::CameraStandard::dataHeight, thumbnailHeight);
    Media::InitializationOptions opts;
    opts.srcPixelFormat = Media::PixelFormat::RGBA_8888;
    opts.pixelFormat = Media::PixelFormat::RGBA_8888;
    opts.size = { .width = thumbnailWidth, .height = thumbnailHeight };
    MEDIA_INFO_LOG("thumbnailWidth:%{public}d, thumbnailheight: %{public}d", thumbnailWidth, thumbnailHeight);
    const int32_t formatSize = 4;
    auto pixelMap = Media::PixelMap::Create(static_cast<const uint32_t*>(thumbnailBuffer->GetVirAddr()),
        thumbnailWidth * thumbnailHeight * formatSize, 0, thumbnailWidth, opts, true);
    napi_value valueParam = Media::PixelMapNapi::CreatePixelMap(env_, std::move(pixelMap));
    if (valueParam == nullptr) {
        MEDIA_ERR_LOG("ImageNapi Create failed");
        napi_get_undefined(env_, &valueParam);
    }
    MEDIA_INFO_LOG("enter ImageNapi::Create end");
    result[1] = valueParam;

    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback(callbackNapiPara);
    photoOutput_->thumbnailSurface_->ReleaseBuffer(thumbnailBuffer, -1);
}

void ThumbnailListener::UpdateJSCallbackAsync(sptr<PhotoOutput> photoOutput) const
{
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("ThumbnailListener:UpdateJSCallbackAsync() failed to get event loop");
        return;
    }
    uv_work_t* work = new (std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("ThumbnailListener:UpdateJSCallbackAsync() failed to allocate work");
        return;
    }
    std::unique_ptr<ThumbnailListenerInfo> callbackInfo = std::make_unique<ThumbnailListenerInfo>(photoOutput, this);
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(
        loop, work, [](uv_work_t* work) {},
        [](uv_work_t* work, int status) {
            ThumbnailListenerInfo* callbackInfo = reinterpret_cast<ThumbnailListenerInfo*>(work->data);
            if (callbackInfo) {
                callbackInfo->listener_->UpdateJSCallback(callbackInfo->photoOutput_);
                MEDIA_ERR_LOG("ThumbnailListener:UpdateJSCallbackAsync() complete");
                callbackInfo->photoOutput_ = nullptr;
                callbackInfo->listener_ = nullptr;
                delete callbackInfo;
            }
            delete work;
        },
        uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("ThumbnailListener:UpdateJSCallbackAsync() failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

PhotoOutputNapi::PhotoOutputNapi() : env_(nullptr), wrapper_(nullptr) {}

PhotoOutputNapi::~PhotoOutputNapi()
{
    MEDIA_DEBUG_LOG("~PhotoOutputNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
}

void PhotoOutputNapi::PhotoOutputNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("PhotoOutputNapiDestructor is called");
    PhotoOutputNapi* photoOutput = reinterpret_cast<PhotoOutputNapi*>(nativeObject);
    if (photoOutput != nullptr) {
        delete photoOutput;
    }
}

napi_value PhotoOutputNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    napi_property_descriptor photo_output_props[] = {
        DECLARE_NAPI_FUNCTION("getDefaultCaptureSetting", GetDefaultCaptureSetting),
        DECLARE_NAPI_FUNCTION("capture", Capture), DECLARE_NAPI_FUNCTION("confirmCapture", ConfirmCapture),
        DECLARE_NAPI_FUNCTION("release", Release), DECLARE_NAPI_FUNCTION("isMirrorSupported", IsMirrorSupported),
        DECLARE_NAPI_FUNCTION("setMirror", SetMirror),
        DECLARE_NAPI_FUNCTION("enableQuickThumbnail", EnableQuickThumbnail),
        DECLARE_NAPI_FUNCTION("isQuickThumbnailSupported", IsQuickThumbnailSupported), DECLARE_NAPI_FUNCTION("on", On),
        DECLARE_NAPI_FUNCTION("once", Once), DECLARE_NAPI_FUNCTION("off", Off),
        DECLARE_NAPI_FUNCTION("deferImageDelivery", DeferImageDeliveryFor),
        DECLARE_NAPI_FUNCTION("deferImageDeliveryFor", DeferImageDeliveryFor),
        DECLARE_NAPI_FUNCTION("isDeferredImageDeliverySupported", IsDeferredImageDeliverySupported),
        DECLARE_NAPI_FUNCTION("isDeferredImageDeliveryEnabled", IsDeferredImageDeliveryEnabled),
        DECLARE_NAPI_FUNCTION("isAutoHighQualityPhotoSupported", IsAutoHighQualityPhotoSupported),
        DECLARE_NAPI_FUNCTION("enableAutoHighQualityPhoto", EnableAutoHighQualityPhoto)
    };

    status = napi_define_class(env, CAMERA_PHOTO_OUTPUT_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH, PhotoOutputNapiConstructor,
        nullptr, sizeof(photo_output_props) / sizeof(photo_output_props[PARAM0]), photo_output_props, &ctorObj);
    if (status == napi_ok) {
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, CAMERA_PHOTO_OUTPUT_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

// Constructor callback
napi_value PhotoOutputNapi::PhotoOutputNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("PhotoOutputNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<PhotoOutputNapi> obj = std::make_unique<PhotoOutputNapi>();
        obj->photoOutput_ = sPhotoOutput_;
        obj->profile_ = sPhotoOutput_->GetPhotoProfile();
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
		    PhotoOutputNapi::PhotoOutputNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("PhotoOutputNapiConstructor call Failed!");
    return result;
}

sptr<PhotoOutput> PhotoOutputNapi::GetPhotoOutput()
{
    return photoOutput_;
}

bool PhotoOutputNapi::IsPhotoOutput(napi_env env, napi_value obj)
{
    MEDIA_DEBUG_LOG("IsPhotoOutput is called");
    bool result = false;
    napi_status status;
    napi_value constructor = nullptr;

    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        status = napi_instanceof(env, obj, constructor, &result);
        if (status != napi_ok) {
            result = false;
        }
    }
    return result;
}

napi_value PhotoOutputNapi::CreatePhotoOutput(napi_env env, Profile& profile, std::string surfaceId)
{
    MEDIA_DEBUG_LOG("CreatePhotoOutput is called, profile CameraFormat= %{public}d", profile.GetCameraFormat());
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    napi_get_undefined(env, &result);
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        MEDIA_INFO_LOG("CreatePhotoOutput surfaceId: %{public}s", surfaceId.c_str());
        sptr<Surface> photoSurface;
        if (surfaceId == "") {
            MEDIA_INFO_LOG("create surface as consumer");
            photoSurface = Surface::CreateSurfaceAsConsumer("photoOutput");
            sPhotoSurface_ = photoSurface;
        } else {
            MEDIA_INFO_LOG("get surface by surfaceId");
            photoSurface = Media::ImageReceiver::getSurfaceById(surfaceId);
        }
        if (photoSurface == nullptr) {
            MEDIA_ERR_LOG("failed to get surface");
            return result;
        }
        photoSurface->SetUserData(CameraManager::surfaceFormat, std::to_string(profile.GetCameraFormat()));
        sptr<IBufferProducer> surfaceProducer = photoSurface->GetProducer();
        MEDIA_INFO_LOG("profile width: %{public}d, height: %{public}d, format = %{public}d, "
                       "surface width: %{public}d, height: %{public}d", profile.GetSize().height,
                       profile.GetSize().width, static_cast<int32_t>(profile.GetCameraFormat()),
                       photoSurface->GetDefaultWidth(), photoSurface->GetDefaultHeight());
        int retCode = CameraManager::GetInstance()->CreatePhotoOutput(profile, surfaceProducer, &sPhotoOutput_);
        if (!CameraNapiUtils::CheckError(env, retCode) || sPhotoOutput_ == nullptr) {
            MEDIA_ERR_LOG("failed to create CreatePhotoOutput");
            return result;
        }
        if (profile.GetCameraFormat() == CAMERA_FORMAT_DNG) {
            sptr<Surface> rawPhotoSurface = Surface::CreateSurfaceAsConsumer("rawPhotoOutput");
            sPhotoOutput_->SetRawPhotoInfo(rawPhotoSurface);
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sPhotoOutput_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            MEDIA_DEBUG_LOG("Success to create photo output instance");
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create photo output instance");
        }
    }
    MEDIA_ERR_LOG("CreatePhotoOutput call Failed!");
    return result;
}

int32_t PhotoOutputNapi::MapQualityLevelFromJs(int32_t jsQuality, PhotoCaptureSetting::QualityLevel& nativeQuality)
{
    MEDIA_INFO_LOG("js quality level = %{public}d", jsQuality);
    switch (jsQuality) {
        case QUALITY_LEVEL_HIGH:
            nativeQuality = PhotoCaptureSetting::QUALITY_LEVEL_HIGH;
            break;
        case QUALITY_LEVEL_MEDIUM:
            nativeQuality = PhotoCaptureSetting::QUALITY_LEVEL_MEDIUM;
            break;
        case QUALITY_LEVEL_LOW:
            nativeQuality = PhotoCaptureSetting::QUALITY_LEVEL_LOW;
            break;
        default:
            MEDIA_ERR_LOG("Invalid quality value received from application");
            return -1;
    }

    return 0;
}

int32_t PhotoOutputNapi::MapImageRotationFromJs(int32_t jsRotation, PhotoCaptureSetting::RotationConfig& nativeRotation)
{
    MEDIA_INFO_LOG("js rotation = %{public}d", jsRotation);
    switch (jsRotation) {
        case ROTATION_0:
            nativeRotation = PhotoCaptureSetting::Rotation_0;
            break;
        case ROTATION_90:
            nativeRotation = PhotoCaptureSetting::Rotation_90;
            break;
        case ROTATION_180:
            nativeRotation = PhotoCaptureSetting::Rotation_180;
            break;
        case ROTATION_270:
            nativeRotation = PhotoCaptureSetting::Rotation_270;
            break;
        default:
            MEDIA_ERR_LOG("Invalid rotation value received from application");
            return -1;
    }

    return 0;
}

static void CommonCompleteCallback(napi_env env, napi_status status, void* data)
{
    MEDIA_DEBUG_LOG("CommonCompleteCallback is called");
    auto context = static_cast<PhotoOutputAsyncContext*>(data);
    if (context == nullptr) {
        MEDIA_ERR_LOG("Async context is null");
        return;
    }

    std::unique_ptr<JSAsyncContextOutput> jsContext = std::make_unique<JSAsyncContextOutput>();

    if (!context->status) {
        CameraNapiUtils::CreateNapiErrorObject(env, context->errorCode, context->errorMsg.c_str(), jsContext);
    } else {
        jsContext->status = true;
        napi_get_undefined(env, &jsContext->error);
        if (context->bRetBool) {
            napi_get_boolean(env, context->isSupported, &jsContext->data);
        } else {
            napi_get_undefined(env, &jsContext->data);
        }
    }

    if (!context->funcName.empty() && context->taskId > 0) {
        // Finish async trace
        CAMERA_FINISH_ASYNC_TRACE(context->funcName, context->taskId);
        jsContext->funcName = context->funcName;
    }

    if (context->work != nullptr) {
        CameraNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef, context->work, *jsContext);
    }
    delete context;
}

int32_t QueryAndGetProperty(napi_env env, napi_value arg, const string& propertyName, napi_value& property)
{
    MEDIA_DEBUG_LOG("QueryAndGetProperty is called");
    bool present = false;
    int32_t retval = 0;
    if ((napi_has_named_property(env, arg, propertyName.c_str(), &present) != napi_ok) || (!present) ||
        (napi_get_named_property(env, arg, propertyName.c_str(), &property) != napi_ok)) {
        MEDIA_ERR_LOG("Failed to obtain property: %{public}s", propertyName.c_str());
        retval = -1;
    }

    return retval;
}

int32_t GetLocationProperties(napi_env env, napi_value locationObj, const PhotoOutputAsyncContext& context)
{
    MEDIA_DEBUG_LOG("GetLocationProperties is called");
    PhotoOutputAsyncContext* asyncContext = const_cast<PhotoOutputAsyncContext*>(&context);
    napi_value latproperty = nullptr;
    napi_value lonproperty = nullptr;
    napi_value altproperty = nullptr;
    double latitude = -1.0;
    double longitude = -1.0;
    double altitude = -1.0;

    if ((QueryAndGetProperty(env, locationObj, "latitude", latproperty) == 0) &&
        (QueryAndGetProperty(env, locationObj, "longitude", lonproperty) == 0) &&
        (QueryAndGetProperty(env, locationObj, "altitude", altproperty) == 0)) {
        if ((napi_get_value_double(env, latproperty, &latitude) != napi_ok) ||
            (napi_get_value_double(env, lonproperty, &longitude) != napi_ok) ||
            (napi_get_value_double(env, altproperty, &altitude) != napi_ok)) {
            return -1;
        } else {
            asyncContext->location = std::make_unique<Location>();
            asyncContext->location->latitude = latitude;
            asyncContext->location->longitude = longitude;
            asyncContext->location->altitude = altitude;
        }
    } else {
        return -1;
    }

    return 0;
}

static void GetFetchOptionsParam(napi_env env, napi_value arg, const PhotoOutputAsyncContext& context, bool& err)
{
    MEDIA_DEBUG_LOG("GetFetchOptionsParam is called");
    PhotoOutputAsyncContext* asyncContext = const_cast<PhotoOutputAsyncContext*>(&context);
    int32_t intValue;
    std::string strValue;
    napi_value property = nullptr;
    PhotoCaptureSetting::QualityLevel quality;
    PhotoCaptureSetting::RotationConfig rotation;

    if (QueryAndGetProperty(env, arg, "quality", property) == 0) {
        if (napi_get_value_int32(env, property, &intValue) != napi_ok ||
            PhotoOutputNapi::MapQualityLevelFromJs(intValue, quality) == -1) {
            err = true;
            return;
        } else {
            asyncContext->quality = quality;
        }
    }

    if (QueryAndGetProperty(env, arg, "rotation", property) == 0) {
        if (napi_get_value_int32(env, property, &intValue) != napi_ok ||
            PhotoOutputNapi::MapImageRotationFromJs(intValue, rotation) == -1) {
            err = true;
            return;
        } else {
            asyncContext->rotation = rotation;
        }
    }

    if (QueryAndGetProperty(env, arg, "location", property) == 0) {
        if (GetLocationProperties(env, property, context) == -1) {
            err = true;
            return;
        }
    }

    if (QueryAndGetProperty(env, arg, "mirror", property) == 0) {
        bool isMirror = false;
        if (napi_get_value_bool(env, property, &isMirror) != napi_ok) {
            err = true;
            return;
        } else {
            asyncContext->isMirror = isMirror;
        }
    }
}

static napi_value ConvertJSArgsToNative(
    napi_env env, size_t argc, const napi_value argv[], PhotoOutputAsyncContext& asyncContext)
{
    MEDIA_DEBUG_LOG("ConvertJSArgsToNative is called");
    const int32_t refCount = 1;
    napi_value result = nullptr;
    auto context = &asyncContext;
    bool err = false;

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == PARAM0 && valueType == napi_object) {
            GetFetchOptionsParam(env, argv[PARAM0], asyncContext, err);
            if (err) {
                MEDIA_ERR_LOG("fetch options retrieval failed");
                NAPI_ASSERT(env, false, "type mismatch");
            }
            asyncContext.hasPhotoSettings = true;
        } else if ((i == PARAM0) && (valueType == napi_function)) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else if ((i == PARAM1) && (valueType == napi_function)) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else if ((i == PARAM0) && (valueType == napi_boolean)) {
            napi_get_value_bool(env, argv[i], &context->isSupported);
            break;
        } else if ((i == PARAM0) && (valueType == napi_undefined)) {
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }

    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    return result;
}

napi_value PhotoOutputNapi::Capture(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("Capture is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = { 0 };
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    unique_ptr<PhotoOutputAsyncContext> asyncContext = make_unique<PhotoOutputAsyncContext>();
    if (!CameraNapiUtils::CheckInvalidArgument(env, argc, ARGS_TWO, argv, PHOTO_OUT_CAPTURE)) {
        asyncContext->isInvalidArgument = true;
        asyncContext->status = false;
        asyncContext->errorCode = INVALID_ARGUMENT;
    }
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (!asyncContext->isInvalidArgument) {
            result = ConvertJSArgsToNative(env, argc, argv, *asyncContext);
        }
        CAMERA_NAPI_CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");
        CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "Capture");
        status = napi_create_async_work(
            env, nullptr, resource,
            [](napi_env env, void* data) {
                PhotoOutputAsyncContext* context = static_cast<PhotoOutputAsyncContext*>(data);
                // Start async trace
                context->funcName = "PhotoOutputNapi::Capture";
                context->taskId = CameraNapiUtils::IncreamentAndGet(photoOutputTaskId);
                if (context->isInvalidArgument) {
                    return;
                }
                CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
                if (context->objectInfo == nullptr) {
                    context->status = false;
                    return;
                }

                ProcessContext(context);
            },
            CommonCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        ProcessAsyncContext(status, env, result, std::move(asyncContext));
    } else {
        MEDIA_ERR_LOG("Capture call Failed!");
    }
    return result;
}

void PhotoOutputNapi::ProcessContext(PhotoOutputAsyncContext* context)
{
    context->bRetBool = false;
    context->status = true;
    sptr<PhotoOutput> photoOutput = ((sptr<PhotoOutput>&)(context->objectInfo->photoOutput_));
    if ((context->hasPhotoSettings)) {
        std::shared_ptr<PhotoCaptureSetting> capSettings = make_shared<PhotoCaptureSetting>();

        if (context->quality != -1) {
            capSettings->SetQuality(static_cast<PhotoCaptureSetting::QualityLevel>(context->quality));
        }

        if (context->rotation != -1) {
            capSettings->SetRotation(static_cast<PhotoCaptureSetting::RotationConfig>(context->rotation));
        }

        capSettings->SetMirror(context->isMirror);

        if (context->location != nullptr) {
            capSettings->SetLocation(context->location);
        }

        context->errorCode = photoOutput->Capture(capSettings);
    } else {
        context->errorCode = photoOutput->Capture();
    }
    context->status = context->errorCode == 0;
}

void PhotoOutputNapi::ProcessAsyncContext(napi_status status, napi_env env, napi_value result,
    unique_ptr<PhotoOutputAsyncContext> asyncContext)
{
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for PhotoOutputNapi::Capture");
        napi_get_undefined(env, &result);
    } else {
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        asyncContext.release();
    }
}

napi_value PhotoOutputNapi::ConfirmCapture(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("ConfirmCapture is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO] = {};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    PhotoOutputNapi* photoOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&photoOutputNapi));
    if (status == napi_ok && photoOutputNapi != nullptr) {
        int32_t retCode = photoOutputNapi->photoOutput_->ConfirmCapture();
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return result;
        }
    }
    return result;
}

napi_value PhotoOutputNapi::Release(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("Release is called");
    napi_status status;
    napi_value result = nullptr;
    const int32_t refCount = 1;
    napi_value resource = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = { 0 };
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_ONE, "requires 1 parameter maximum");

    napi_get_undefined(env, &result);
    std::unique_ptr<PhotoOutputAsyncContext> asyncContext = std::make_unique<PhotoOutputAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (argc == ARGS_ONE) {
            CAMERA_NAPI_GET_JS_ASYNC_CB_REF(env, argv[PARAM0], refCount, asyncContext->callbackRef);
        }

        CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "Release");

        status = napi_create_async_work(
            env, nullptr, resource,
            [](napi_env env, void* data) {
                auto context = static_cast<PhotoOutputAsyncContext*>(data);
                context->status = false;
                // Start async trace
                context->funcName = "PhotoOutputNapi::Release";
                context->taskId = CameraNapiUtils::IncreamentAndGet(photoOutputTaskId);
                CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
                if (context->objectInfo != nullptr) {
                    context->bRetBool = false;
                    context->status = true;
                    ((sptr<PhotoOutput>&)(context->objectInfo->photoOutput_))->Release();
                }
            },
            CommonCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for PhotoOutputNapi::Release");
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
            asyncContext.release();
        }
    } else {
        MEDIA_ERR_LOG("Release call Failed!");
    }
    return result;
}

napi_value PhotoOutputNapi::GetDefaultCaptureSetting(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetDefaultCaptureSetting is called");
    napi_status status;
    napi_value result = nullptr;
    const int32_t refCount = 1;
    napi_value resource = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = { 0 };
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_ONE, "requires 1 parameter maximum");

    napi_get_undefined(env, &result);
    std::unique_ptr<PhotoOutputAsyncContext> asyncContext = std::make_unique<PhotoOutputAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (argc == ARGS_ONE) {
            CAMERA_NAPI_GET_JS_ASYNC_CB_REF(env, argv[PARAM0], refCount, asyncContext->callbackRef);
        }

        CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "GetDefaultCaptureSetting");

        status = napi_create_async_work(
            env, nullptr, resource,
            [](napi_env env, void* data) {
                auto context = static_cast<PhotoOutputAsyncContext*>(data);
                context->status = false;
                // Start async trace
                context->funcName = "PhotoOutputNapi::GetDefaultCaptureSetting";
                context->taskId = CameraNapiUtils::IncreamentAndGet(photoOutputTaskId);
                CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
                if (context->objectInfo != nullptr) {
                    context->bRetBool = false;
                    context->status = true;
                }
            },
            CommonCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for PhotoOutputNapi::GetDefaultCaptureSetting");
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
            asyncContext.release();
        }
    } else {
        MEDIA_ERR_LOG("GetDefaultCaptureSetting call Failed!");
    }
    return result;
}

napi_value PhotoOutputNapi::IsMirrorSupported(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("IsMirrorSupported is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    PhotoOutputNapi* photoOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&photoOutputNapi));
    if (status == napi_ok && photoOutputNapi != nullptr) {
        bool isSupported = photoOutputNapi->photoOutput_->IsMirrorSupported();
        napi_get_boolean(env, isSupported, &result);
    } else {
        MEDIA_ERR_LOG("IsMirrorSupported call Failed!");
    }
    return result;
}

napi_value PhotoOutputNapi::IsQuickThumbnailSupported(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsQuickThumbnailSupported is called!");
        return nullptr;
    }
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    PhotoOutputNapi* photoOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&photoOutputNapi));
    if (status == napi_ok && photoOutputNapi != nullptr) {
        int32_t retCode = photoOutputNapi->photoOutput_->IsQuickThumbnailSupported();
        bool isSupported = (retCode == 0);
        if (retCode > 0 && !CameraNapiUtils::CheckError(env, retCode)) {
            return result;
        }
        napi_get_boolean(env, isSupported, &result);
    }
    return result;
}

napi_value PhotoOutputNapi::DeferImageDeliveryFor(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi DeferImageDeliveryFor is called!");
        return nullptr;
    }
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc == ARGS_ONE, "requires one parameter");
    napi_get_undefined(env, &result);
    PhotoOutputNapi* photoOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&photoOutputNapi));
    if (status == napi_ok && photoOutputNapi != nullptr) {
        int32_t deliveryType;
        napi_get_value_int32(env, argv[PARAM0], &deliveryType);
        photoOutputNapi->photoOutput_->DeferImageDeliveryFor(static_cast<DeferredDeliveryImageType>(deliveryType));
        photoOutputNapi->isDeferredPhotoEnabled_ = deliveryType == DELIVERY_PHOTO;
    }
    return result;
}

napi_value PhotoOutputNapi::IsDeferredImageDeliverySupported(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsDeferredImageDeliverySupported is called!");
        return nullptr;
    }
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc == ARGS_ONE, "requires one parameter");
    napi_get_undefined(env, &result);
    PhotoOutputNapi* photoOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&photoOutputNapi));
    if (status == napi_ok && photoOutputNapi != nullptr) {
        int32_t deliveryType;
        napi_get_value_int32(env, argv[PARAM0], &deliveryType);
        int32_t retCode = photoOutputNapi->photoOutput_->IsDeferredImageDeliverySupported(
            static_cast<DeferredDeliveryImageType>(deliveryType));
        bool isSupported = (retCode == 0);
        if (retCode > 0 && !CameraNapiUtils::CheckError(env, retCode)) {
            return result;
        }
        napi_get_boolean(env, isSupported, &result);
    }
    return result;
}

napi_value PhotoOutputNapi::IsDeferredImageDeliveryEnabled(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsDeferredImageDeliveryEnabled is called!");
        return nullptr;
    }
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc == ARGS_ONE, "requires one parameter");
    napi_get_undefined(env, &result);
    PhotoOutputNapi* photoOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&photoOutputNapi));
    if (status == napi_ok && photoOutputNapi != nullptr) {
        int32_t deliveryType;
        napi_get_value_int32(env, argv[PARAM0], &deliveryType);
        int32_t retCode = photoOutputNapi->photoOutput_->IsDeferredImageDeliveryEnabled(
            static_cast<DeferredDeliveryImageType>(deliveryType));
        bool isSupported = (retCode == 0);
        if (retCode > 0 && !CameraNapiUtils::CheckError(env, retCode)) {
            return result;
        }
        napi_get_boolean(env, isSupported, &result);
    }
    return result;
}

napi_value PhotoOutputNapi::SetMirror(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetMirror is called");
    napi_status status;
    napi_value result = nullptr;
    const int32_t refCount = 1;
    napi_value resource = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = { 0 };
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_TWO, "requires 2 parameters maximum");

    napi_get_undefined(env, &result);
    std::unique_ptr<PhotoOutputAsyncContext> asyncContext = std::make_unique<PhotoOutputAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (argc == ARGS_TWO) {
            CAMERA_NAPI_GET_JS_ASYNC_CB_REF(env, argv[PARAM1], refCount, asyncContext->callbackRef);
        }

        result = ConvertJSArgsToNative(env, argc, argv, *asyncContext);
        asyncContext->isMirror = asyncContext->isSupported;
        CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "SetMirror");
        status = napi_create_async_work(
            env, nullptr, resource,
            [](napi_env env, void* data) {
                auto context = static_cast<PhotoOutputAsyncContext*>(data);
                context->status = false;
                // Start async trace
                context->funcName = "PhotoOutputNapi::SetMirror";
                context->taskId = CameraNapiUtils::IncreamentAndGet(photoOutputTaskId);
                CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
                if (context->objectInfo != nullptr) {
                    context->bRetBool = false;
                    context->status = true;
                }
            },
            CommonCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for SetMirror");
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
            asyncContext.release();
        }
    } else {
        MEDIA_ERR_LOG("SetMirror call Failed!");
    }

    return result;
}

napi_value PhotoOutputNapi::EnableQuickThumbnail(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi EnableQuickThumbnail is called!");
        return nullptr;
    }
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = { 0 };
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc == ARGS_ONE, "requires one parameter");
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    if (valueType != napi_boolean && !CameraNapiUtils::CheckError(env, INVALID_ARGUMENT)) {
        return result;
    }
    napi_get_undefined(env, &result);
    PhotoOutputNapi* photoOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&photoOutputNapi));
    bool thumbnailSwitch;
    if (status == napi_ok && photoOutputNapi != nullptr) {
        napi_get_value_bool(env, argv[PARAM0], &thumbnailSwitch);
        photoOutputNapi->isQuickThumbnailEnabled_ = thumbnailSwitch;
        int32_t retCode = photoOutputNapi->photoOutput_->SetThumbnail(thumbnailSwitch);
        if (retCode != 0 && !CameraNapiUtils::CheckError(env, retCode)) {
            return result;
        }
    }
    return result;
}

void PhotoOutputNapi::RegisterQuickThumbnailCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi quickThumbnail on is called!");
        return;
    }

    // Set callback for exposureStateChange
    if (thumbnailListener_ == nullptr) {
        if (!isQuickThumbnailEnabled_) {
            MEDIA_ERR_LOG("quickThumbnail is not enabled!");
            napi_throw_error(env, std::to_string(SESSION_NOT_RUNNING).c_str(), "");
            return;
        }
        thumbnailListener_ = new ThumbnailListener(env, photoOutput_);
        photoOutput_->SetThumbnailListener((sptr<IBufferConsumerListener>&)thumbnailListener_);
    }
    thumbnailListener_->SaveCallbackReference(callback, isOnce);
}

void PhotoOutputNapi::UnregisterQuickThumbnailCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi quickThumbnail off is called!");
        return;
    }
    if (!isQuickThumbnailEnabled_) {
        MEDIA_ERR_LOG("quickThumbnail is not enabled!");
        napi_throw_error(env, std::to_string(SESSION_NOT_RUNNING).c_str(), "");
        return;
    }
    if (thumbnailListener_ != nullptr) {
        thumbnailListener_->RemoveCallbackRef(env, callback);
    }
}

void PhotoOutputNapi::RegisterPhotoAvailableCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (sPhotoSurface_ == nullptr) {
        MEDIA_ERR_LOG("sPhotoSurface_ is null!");
        return;
    }
    if (photoListener_ == nullptr) {
        MEDIA_INFO_LOG("new photoListener and register surface consumer listener");
        sptr<PhotoListener> photoListener = new (std::nothrow) PhotoListener(env, sPhotoSurface_);
        SurfaceError ret = sPhotoSurface_->RegisterConsumerListener((sptr<IBufferConsumerListener>&)photoListener);
        if (ret != SURFACE_ERROR_OK) {
            MEDIA_ERR_LOG("register surface consumer listener failed!");
        }
        photoListener_ = photoListener;
    }
    photoListener_->SaveCallbackReference(CONST_CAPTURE_PHOTO_AVAILABLE, callback);
    if (photoOutput_ != nullptr && rawPhotoListener_ == nullptr && profile_.GetCameraFormat() == CAMERA_FORMAT_DNG) {
        MEDIA_INFO_LOG("new rawPhotoListener and register surface consumer listener");
        if (photoOutput_->rawPhotoSurface_ == nullptr) {
            MEDIA_ERR_LOG("rawPhotoSurface_ is null!");
            return;
        }
        sptr<RawPhotoListener> rawPhotoListener =
            new (std::nothrow) RawPhotoListener(env, photoOutput_->rawPhotoSurface_);
        SurfaceError ret = photoOutput_->rawPhotoSurface_->RegisterConsumerListener(
            (sptr<IBufferConsumerListener>&)rawPhotoListener);
        if (ret != SURFACE_ERROR_OK) {
            MEDIA_ERR_LOG("register surface consumer listener failed!");
        }
        rawPhotoListener_ = rawPhotoListener;
        rawPhotoListener_->SaveCallbackReference(CONST_CAPTURE_PHOTO_AVAILABLE, callback);
    }
}

void PhotoOutputNapi::UnregisterPhotoAvailableCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (photoListener_ != nullptr) {
        photoListener_->RemoveCallbackRef(env, callback, CONST_CAPTURE_PHOTO_AVAILABLE);
    }
    if (rawPhotoListener_ != nullptr) {
        rawPhotoListener_->RemoveCallbackRef(env, callback, CONST_CAPTURE_PHOTO_AVAILABLE);
    }
}

void PhotoOutputNapi::RegisterDeferredPhotoProxyAvailableCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (sPhotoSurface_ == nullptr) {
        MEDIA_ERR_LOG("sPhotoSurface_ is null!");
        return;
    }
    if (photoListener_ == nullptr) {
        MEDIA_INFO_LOG("new deferred photoListener and register surface consumer listener");
        sptr<PhotoListener> photoListener = new (std::nothrow) PhotoListener(env, sPhotoSurface_);
        SurfaceError ret = sPhotoSurface_->RegisterConsumerListener((sptr<IBufferConsumerListener>&)photoListener);
        if (ret != SURFACE_ERROR_OK) {
            MEDIA_ERR_LOG("register surface consumer listener failed!");
        }
        photoListener_ = photoListener;
    }
    photoListener_->SaveCallbackReference(CONST_CAPTURE_DEFERRED_PHOTO_AVAILABLE, callback);
}

void PhotoOutputNapi::UnregisterDeferredPhotoProxyAvailableCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (photoListener_ != nullptr) {
        photoListener_->RemoveCallbackRef(env, callback, CONST_CAPTURE_DEFERRED_PHOTO_AVAILABLE);
    }
}

void PhotoOutputNapi::RegisterCaptureStartCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (photoOutputCallback_ == nullptr) {
        photoOutputCallback_ = std::make_shared<PhotoOutputCallback>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(CONST_CAPTURE_START, callback, isOnce);
}

void PhotoOutputNapi::UnregisterCaptureStartCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (photoOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("photoOutputCallback is null");
        return;
    }
    photoOutputCallback_->RemoveCallbackRef(env, callback, CONST_CAPTURE_START);
}

void PhotoOutputNapi::RegisterCaptureStartWithInfoCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (photoOutputCallback_ == nullptr) {
        photoOutputCallback_ = std::make_shared<PhotoOutputCallback>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(CONST_CAPTURE_START_WITH_INFO, callback, isOnce);
}

void PhotoOutputNapi::UnregisterCaptureStartWithInfoCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (photoOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("photoOutputCallback is null");
        return;
    }
    photoOutputCallback_->RemoveCallbackRef(env, callback, CONST_CAPTURE_START_WITH_INFO);
}

void PhotoOutputNapi::RegisterCaptureEndCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (photoOutputCallback_ == nullptr) {
        photoOutputCallback_ = std::make_shared<PhotoOutputCallback>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(CONST_CAPTURE_END, callback, isOnce);
}

void PhotoOutputNapi::UnregisterCaptureEndCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (photoOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("photoOutputCallback is null");
        return;
    }
    photoOutputCallback_->RemoveCallbackRef(env, callback, CONST_CAPTURE_END);
}

void PhotoOutputNapi::RegisterFrameShutterCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (photoOutputCallback_ == nullptr) {
        photoOutputCallback_ = std::make_shared<PhotoOutputCallback>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(CONST_CAPTURE_FRAME_SHUTTER, callback, isOnce);
}

void PhotoOutputNapi::UnregisterFrameShutterCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (photoOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("photoOutputCallback is null");
        return;
    }
    photoOutputCallback_->RemoveCallbackRef(env, callback, CONST_CAPTURE_FRAME_SHUTTER);
}

void PhotoOutputNapi::RegisterErrorCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (photoOutputCallback_ == nullptr) {
        photoOutputCallback_ = std::make_shared<PhotoOutputCallback>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(CONST_CAPTURE_ERROR, callback, isOnce);
}

void PhotoOutputNapi::UnregisterErrorCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (photoOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("photoOutputCallback is null");
        return;
    }
    photoOutputCallback_->RemoveCallbackRef(env, callback, CONST_CAPTURE_ERROR);
}

void PhotoOutputNapi::RegisterFrameShutterEndCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (photoOutputCallback_ == nullptr) {
        photoOutputCallback_ = std::make_shared<PhotoOutputCallback>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(CONST_CAPTURE_FRAME_SHUTTER_END, callback, isOnce);
}

void PhotoOutputNapi::UnregisterFrameShutterEndCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (photoOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("photoOutputCallback is null");
        return;
    }
    photoOutputCallback_->RemoveCallbackRef(env, callback, CONST_CAPTURE_FRAME_SHUTTER_END);
}

void PhotoOutputNapi::RegisterReadyCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (photoOutputCallback_ == nullptr) {
        photoOutputCallback_ = std::make_shared<PhotoOutputCallback>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(CONST_CAPTURE_READY, callback, isOnce);
}

void PhotoOutputNapi::UnregisterReadyCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (photoOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("photoOutputCallback is null");
        return;
    }
    photoOutputCallback_->RemoveCallbackRef(env, callback, CONST_CAPTURE_READY);
}

void PhotoOutputNapi::RegisterEstimatedCaptureDurationCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (photoOutputCallback_ == nullptr) {
        photoOutputCallback_ = std::make_shared<PhotoOutputCallback>(env);
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    photoOutputCallback_->SaveCallbackReference(CONST_CAPTURE_ESTIMATED_CAPTURE_DURATION, callback, isOnce);
}

void PhotoOutputNapi::UnregisterEstimatedCaptureDurationCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (photoOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("photoOutputCallback is null");
        return;
    }
    photoOutputCallback_->RemoveCallbackRef(env, callback, CONST_CAPTURE_ESTIMATED_CAPTURE_DURATION);
}

const PhotoOutputNapi::EmitterFunctions& PhotoOutputNapi::GetEmitterFunctions()
{
    static const EmitterFunctions funMap = {
        { CONST_CAPTURE_QUICK_THUMBNAIL, {
            &PhotoOutputNapi::RegisterQuickThumbnailCallbackListener,
            &PhotoOutputNapi::UnregisterQuickThumbnailCallbackListener } },
        { CONST_CAPTURE_PHOTO_AVAILABLE, {
            &PhotoOutputNapi::RegisterPhotoAvailableCallbackListener,
            &PhotoOutputNapi::UnregisterPhotoAvailableCallbackListener } },
        { CONST_CAPTURE_DEFERRED_PHOTO_AVAILABLE, {
            &PhotoOutputNapi::RegisterDeferredPhotoProxyAvailableCallbackListener,
            &PhotoOutputNapi::UnregisterDeferredPhotoProxyAvailableCallbackListener } },
        { CONST_CAPTURE_START, {
            &PhotoOutputNapi::RegisterCaptureStartCallbackListener,
            &PhotoOutputNapi::UnregisterCaptureStartCallbackListener } },
        { CONST_CAPTURE_END, {
            &PhotoOutputNapi::RegisterCaptureEndCallbackListener,
            &PhotoOutputNapi::UnregisterCaptureEndCallbackListener } },
        { CONST_CAPTURE_FRAME_SHUTTER, {
            &PhotoOutputNapi::RegisterFrameShutterCallbackListener,
            &PhotoOutputNapi::UnregisterFrameShutterCallbackListener } },
        { CONST_CAPTURE_ERROR, {
            &PhotoOutputNapi::RegisterErrorCallbackListener,
            &PhotoOutputNapi::UnregisterErrorCallbackListener } },
        { CONST_CAPTURE_FRAME_SHUTTER_END, {
            &PhotoOutputNapi::RegisterFrameShutterEndCallbackListener,
            &PhotoOutputNapi::UnregisterFrameShutterEndCallbackListener } },
        { CONST_CAPTURE_READY, {
            &PhotoOutputNapi::RegisterReadyCallbackListener,
            &PhotoOutputNapi::UnregisterReadyCallbackListener } },
        { CONST_CAPTURE_ESTIMATED_CAPTURE_DURATION, {
            &PhotoOutputNapi::RegisterEstimatedCaptureDurationCallbackListener,
            &PhotoOutputNapi::UnregisterEstimatedCaptureDurationCallbackListener } },
        { CONST_CAPTURE_START_WITH_INFO, {
            &PhotoOutputNapi::RegisterCaptureStartWithInfoCallbackListener,
            &PhotoOutputNapi::UnregisterCaptureStartWithInfoCallbackListener } } };
    return funMap;
}

napi_value PhotoOutputNapi::On(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<PhotoOutputNapi>::On(env, info);
}

napi_value PhotoOutputNapi::Once(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<PhotoOutputNapi>::Once(env, info);
}

napi_value PhotoOutputNapi::Off(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<PhotoOutputNapi>::Off(env, info);
}

napi_value PhotoOutputNapi::IsAutoHighQualityPhotoSupported(napi_env env, napi_callback_info info)
{
    auto result = CameraNapiUtils::GetUndefinedValue(env);
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsAutoHighQualityPhotoSupported is called!");
        return result;
    }
    MEDIA_DEBUG_LOG("PhotoOutputNapi::IsAutoHighQualityPhotoSupported is called");
    PhotoOutputNapi* photoOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, photoOutputNapi);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("PhotoOutputNapi::IsAutoHighQualityPhotoSupported parse parameter occur error");
        return result;
    }
    if (photoOutputNapi->photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("PhotoOutputNapi::IsAutoHighQualityPhotoSupported get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return result;
    }

    int32_t isAutoHighQualityPhotoSupported;
    int32_t retCode = photoOutputNapi->photoOutput_->IsAutoHighQualityPhotoSupported(isAutoHighQualityPhotoSupported);
    if (retCode == 0 && isAutoHighQualityPhotoSupported != -1) {
        napi_get_boolean(env, true, &result);
        return result;
    }
    MEDIA_ERR_LOG("PhotoOutputNapi::IsAutoHighQualityPhotoSupported is not supported");
    napi_get_boolean(env, false, &result);
    return result;
}

napi_value PhotoOutputNapi::EnableAutoHighQualityPhoto(napi_env env, napi_callback_info info)
{
    auto result = CameraNapiUtils::GetUndefinedValue(env);
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi EnableAutoHighQualityPhoto is called!");
        return result;
    }
    MEDIA_DEBUG_LOG("PhotoOutputNapi::EnableAutoHighQualityPhoto is called");
    PhotoOutputNapi* photoOutputNapi = nullptr;
    bool isEnable;
    CameraNapiParamParser jsParamParser(env, info, photoOutputNapi, isEnable);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("PhotoOutputNapi::EnableAutoHighQualityPhoto parse parameter occur error");
        return result;
    }
    if (photoOutputNapi->photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("PhotoOutputNapi::EnableAutoHighQualityPhoto get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return result;
    }

    int32_t retCode = photoOutputNapi->photoOutput_->EnableAutoHighQualityPhoto(isEnable);
    if (CameraNapiUtils::CheckError(env, retCode)) {
        MEDIA_ERR_LOG("PhotoOutputNapi::EnableAutoHighQualityPhoto fail %{public}d", retCode);
    }
    return result;
}
} // namespace CameraStandard
} // namespace OHOS