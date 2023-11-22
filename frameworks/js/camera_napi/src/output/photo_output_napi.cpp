/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "output/photo_output_napi.h"
#include <uv.h>
#include "image_napi.h"
#include "image_receiver.h"
#include "pixel_map_napi.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;
using OHOS::HiviewDFX::HiLog;
using OHOS::HiviewDFX::HiLogLabel;
namespace {
    constexpr HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN, "PhotoOutputNapi"};
}
thread_local napi_ref PhotoOutputNapi::sConstructor_ = nullptr;
thread_local sptr<PhotoOutput> PhotoOutputNapi::sPhotoOutput_ = nullptr;
thread_local sptr<Surface> PhotoOutputNapi::sPhotoSurface_ = nullptr;
thread_local uint32_t PhotoOutputNapi::photoOutputTaskId = CAMERA_PHOTO_OUTPUT_TASKID;

PhotoListener::PhotoListener(napi_env env, const sptr<Surface> photoSurface) : env_(env), photoSurface_(photoSurface)
{
    if (bufferProcessor_ == nullptr && photoSurface != nullptr) {
        bufferProcessor_ = std::make_shared<PhotoBufferProcessor> (photoSurface);
    }
}

void PhotoListener::OnBufferAvailable()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("PhotoListener::OnBufferAvailable is called");
    if (!photoSurface_) {
        MEDIA_ERR_LOG("photoOutput napi photoSurface_ is null");
        return;
    }
    UpdateJSCallbackAsync(photoSurface_);
}

void PhotoListener::UpdateJSCallback(sptr<Surface> photoSurface) const
{
    napi_value result[ARGS_TWO] = {0};
    napi_get_undefined(env_, &result[0]);
    napi_get_undefined(env_, &result[1]);
    napi_value callback = nullptr;
    napi_value retVal;
    int32_t fence = -1;
    int64_t timestamp;
    OHOS::Rect damage;
    sptr<SurfaceBuffer> photoBuffer = nullptr;
    SurfaceError surfaceRet = photoSurface->AcquireBuffer(photoBuffer, fence, timestamp, damage);
    if (surfaceRet != SURFACE_ERROR_OK) {
        MEDIA_ERR_LOG("PhotoListener Failed to acquire surface buffer");
        return;
    }
    std::shared_ptr<Media::NativeImage> image = std::make_shared<Media::NativeImage>(photoBuffer, bufferProcessor_);
    napi_value valueParam = Media::ImageNapi::Create(env_, image);
    if (valueParam == nullptr) {
        MEDIA_ERR_LOG("ImageNapi Create failed");
        napi_get_undefined(env_, &valueParam);
    }
    MEDIA_INFO_LOG("enter ImageNapi::Create end");
    result[1] = valueParam;
    for (auto it = photoListenerList_.begin(); it != photoListenerList_.end();) {
        napi_get_reference_value((*it)->env_, (*it)->cb_, &callback);
        napi_call_function(env_, nullptr, callback, ARGS_TWO, result, &retVal);
        if ((*it)->isOnce_) {
            napi_status status = napi_delete_reference((*it)->env_, (*it)->cb_);
            CHECK_AND_RETURN_LOG(status == napi_ok, "Remove once cb ref: delete reference for callback fail");
            (*it)->cb_ = nullptr;
            photoListenerList_.erase(it);
        } else {
            it++;
        }
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
    uv_work_t* work = new(std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("PhotoListener:UpdateJSCallbackAsync() failed to allocate work");
        return;
    }
    std::unique_ptr<PhotoListenerInfo> callbackInfo =
            std::make_unique<PhotoListenerInfo>(photoSurface, this);
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        PhotoListenerInfo* callbackInfo = reinterpret_cast<PhotoListenerInfo *>(work->data);
        if (callbackInfo) {
            callbackInfo->listener_->UpdateJSCallback(callbackInfo->photoSurface_);
            MEDIA_ERR_LOG("PhotoListener:UpdateJSCallbackAsync() complete");
            callbackInfo->photoSurface_ =  nullptr;
            callbackInfo->listener_ = nullptr;
            delete callbackInfo;
        }
        delete work;
    }, uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("PhotoListener:UpdateJSCallbackAsync() failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void PhotoListener::SaveCallbackReference(napi_value callback, bool isOnce)
{
    std::lock_guard<std::mutex> lock(mutex_);
    napi_ref callbackRef = nullptr;
    const int32_t refCount = 1;

    for (auto it = photoListenerList_.begin(); it != photoListenerList_.end(); ++it) {
        bool isSameCallback = CameraNapiUtils::IsSameCallback(env_, callback, (*it)->cb_);
        CHECK_AND_RETURN_LOG(!isSameCallback, "SaveCallbackReference: has same callback, nothing to do");
    }
    napi_status status = napi_create_reference(env_, callback, refCount, &callbackRef);
    CHECK_AND_RETURN_LOG(status == napi_ok && callbackRef != nullptr,
                         "ErrorCallbackListener: creating reference for callback fail");
    std::shared_ptr<AutoRef> cb = std::make_shared<AutoRef>(env_, callbackRef, isOnce);
    photoListenerList_.push_back(cb);
    MEDIA_DEBUG_LOG("Save callback reference success, PhotoListener list size [%{public}zu]",
        photoListenerList_.size());
}

void PhotoListener::RemoveCallbackRef(napi_env env, napi_value callback)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (callback == nullptr) {
        MEDIA_INFO_LOG("RemoveCallbackReference: js callback is nullptr, remove all callback reference");
        RemoveAllCallbacks();
        return;
    }
    for (auto it = photoListenerList_.begin(); it != photoListenerList_.end(); ++it) {
        bool isSameCallback = CameraNapiUtils::IsSameCallback(env_, callback, (*it)->cb_);
        if (isSameCallback) {
            MEDIA_INFO_LOG("RemoveCallbackReference: find js callback, delete it");
            napi_status status = napi_delete_reference(env, (*it)->cb_);
            (*it)->cb_ = nullptr;
            CHECK_AND_RETURN_LOG(status == napi_ok, "RemoveCallbackReference: delete reference for callback fail");
            photoListenerList_.erase(it);
            return;
        }
    }
    MEDIA_INFO_LOG("RemoveCallbackReference: js callback no find");
}

void PhotoListener::RemoveAllCallbacks()
{
    for (auto it = photoListenerList_.begin(); it != photoListenerList_.end(); ++it) {
        napi_delete_reference(env_, (*it)->cb_);
        (*it)->cb_ = nullptr;
    }
    photoListenerList_.clear();
    MEDIA_INFO_LOG("RemoveAllCallbacks: remove all js callbacks success");
}

PhotoOutputCallback::PhotoOutputCallback(napi_env env) : env_(env) {}

void PhotoOutputCallback::UpdateJSCallbackAsync(PhotoOutputEventType eventType, const CallbackInfo &info) const
{
    MEDIA_DEBUG_LOG("UpdateJSCallbackAsync is called");
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("failed to get event loop");
        return;
    }
    uv_work_t* work = new(std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("failed to allocate work");
        return;
    }
    std::unique_ptr<PhotoOutputCallbackInfo> callbackInfo =
        std::make_unique<PhotoOutputCallbackInfo>(eventType, info, this);
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        PhotoOutputCallbackInfo* callbackInfo = reinterpret_cast<PhotoOutputCallbackInfo *>(work->data);
        if (callbackInfo) {
            callbackInfo->listener_->UpdateJSCallback(callbackInfo->eventType_, callbackInfo->info_);
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
    MEDIA_DEBUG_LOG("OnFrameShutter is called, captureID: %{public}d, timestamp: %{public}" PRIu64,
        captureId, timestamp);
    CallbackInfo info;
    info.captureID = captureId;
    info.timestamp = timestamp;
    UpdateJSCallbackAsync(PhotoOutputEventType::CAPTURE_FRAME_SHUTTER, info);
}

void PhotoOutputCallback::OnCaptureError(const int32_t captureId, const int32_t errorCode) const
{
    MEDIA_DEBUG_LOG("OnCaptureError is called!, captureID: %{public}d, errorCode: %{public}d",
        captureId, errorCode);
    CallbackInfo info;
    info.captureID = captureId;
    info.errorCode = errorCode;
    UpdateJSCallbackAsync(PhotoOutputEventType::CAPTURE_ERROR, info);
}

void PhotoOutputCallback::SaveCallbackReference(const std::string &eventType, napi_value callback, bool isOnce)
{
    MEDIA_INFO_LOG("SaveCallbackReference is called");
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<AutoRef>> *callbackList;
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
        default:
            MEDIA_ERR_LOG("Incorrect photo callback event type received from JS");
            return;
    }
    for (auto it = callbackList->begin(); it != callbackList->end(); ++it) {
        bool isSameCallback = CameraNapiUtils::IsSameCallback(env_, callback, (*it)->cb_);
        CHECK_AND_RETURN_LOG(!isSameCallback, "UpdateList: has same callback, nothing to do");
    }
    napi_ref callbackRef = nullptr;
    const int32_t refCount = 1;
    napi_status status = napi_create_reference(env_, callback, refCount, &callbackRef);
    CHECK_AND_RETURN_LOG(status == napi_ok && callbackRef != nullptr,
                         "creating reference for callback fail");
    std::shared_ptr<AutoRef> cb = std::make_shared<AutoRef>(env_, callbackRef, isOnce);
    callbackList->push_back(cb);
    MEDIA_DEBUG_LOG("Save callback reference success, %{public}s callback list size [%{public}zu]",
        eventType.c_str(), callbackList->size());
}

void PhotoOutputCallback::RemoveCallbackRef(napi_env env, napi_value callback, const std::string &eventType)
{
    MEDIA_INFO_LOG("RemoveCallbackRef is called");
    std::lock_guard<std::mutex> lock(mutex_);
    if (callback == nullptr) {
        MEDIA_INFO_LOG("RemoveCallbackRef: js callback is nullptr, remove all callback reference");
        RemoveAllCallbacks(eventType);
        return;
    }
    std::vector<std::shared_ptr<AutoRef>> *callbackList;
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
        default:
            MEDIA_ERR_LOG("Incorrect photo callback event type received from JS");
            return;
    }
    for (auto it = callbackList->begin(); it != callbackList->end(); ++it) {
        bool isSameCallback = CameraNapiUtils::IsSameCallback(env_, callback, (*it)->cb_);
        if (isSameCallback) {
            MEDIA_INFO_LOG("RemoveCallbackRef: find js callback, delete it");
            napi_status status = napi_delete_reference(env_, (*it)->cb_);
            (*it)->cb_ = nullptr;
            CHECK_AND_RETURN_LOG(status == napi_ok, "RemoveCallbackRef: delete reference for callback fail");
            callbackList->erase(it);
            return;
        }
    }
    MEDIA_DEBUG_LOG("RemoveCallbackRef success, %{public}s callback list size [%{public}zu]",
        eventType.c_str(), callbackList->size());
}

void PhotoOutputCallback::RemoveAllCallbacks(const std::string &eventType)
{
    std::vector<std::shared_ptr<AutoRef>> *callbackList;
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
    MEDIA_DEBUG_LOG("RemoveAllCallbacks success, %{public}s callback list size [%{public}zu]",
        eventType.c_str(), callbackList->size());
}

void PhotoOutputCallback::ExecuteCaptureStartCb(const CallbackInfo &info) const
{
    napi_value result[ARGS_TWO] = {nullptr, nullptr};
    napi_value callback = nullptr;
    napi_value retVal;
    napi_get_undefined(env_, &result[PARAM0]);
    napi_get_undefined(env_, &result[PARAM1]);
    for (auto it = captureStartCbList_.begin(); it != captureStartCbList_.end();) {
        napi_env env = (*it)->env_;
        napi_create_int32(env, info.captureID, &result[PARAM1]);
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

void PhotoOutputCallback::ExecuteCaptureEndCb(const CallbackInfo &info) const
{
    napi_value result[ARGS_TWO] = {nullptr, nullptr};
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

void PhotoOutputCallback::ExecuteFrameShutterCb(const CallbackInfo &info) const
{
    napi_value result[ARGS_TWO] = {nullptr, nullptr};
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

void PhotoOutputCallback::ExecuteCaptureErrorCb(const CallbackInfo &info) const
{
    napi_value errJsResult[ARGS_ONE] = {nullptr};
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

void PhotoOutputCallback::UpdateJSCallback(PhotoOutputEventType eventType, const CallbackInfo &info) const
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
        default:
            MEDIA_ERR_LOG("Incorrect photo callback event type received from JS");
    }
}

ThumbnailListener::ThumbnailListener(napi_env env, const sptr<PhotoOutput> photoOutput)
    : env_(env), photoOutput_(photoOutput) {}

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
    napi_value result[ARGS_TWO] = {0};
    napi_get_undefined(env_, &result[0]);
    napi_get_undefined(env_, &result[1]);
    napi_value callback = nullptr;
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
    opts.pixelFormat = Media::PixelFormat::RGBA_8888;
    opts.size = {
            .width = thumbnailWidth,
            .height = thumbnailHeight
    };
    MEDIA_INFO_LOG("thumbnailWidth:%{public}d, thumbnailheight: %{public}d, bufSize: %{public}d",
        thumbnailWidth, thumbnailHeight, thumbnailBuffer->GetSize());
    auto pixelMap = Media::PixelMap::Create(opts);
    pixelMap->SetPixelsAddr(thumbnailBuffer->GetVirAddr(), nullptr, thumbnailBuffer->GetSize(),
        Media::AllocatorType::HEAP_ALLOC, nullptr);
    napi_value valueParam = Media::PixelMapNapi::CreatePixelMap(env_, std::move(pixelMap));
    if (valueParam == nullptr) {
        MEDIA_ERR_LOG("ImageNapi Create failed");
        napi_get_undefined(env_, &valueParam);
    }
    MEDIA_INFO_LOG("enter ImageNapi::Create end");
    result[1] = valueParam;
    for (auto it = thumbnailListenerList_.begin(); it != thumbnailListenerList_.end();) {
        napi_get_reference_value((*it)->env_, (*it)->cb_, &callback);
        napi_call_function(env_, nullptr, callback, ARGS_TWO, result, &retVal);
        if ((*it)->isOnce_) {
            napi_status status = napi_delete_reference((*it)->env_, (*it)->cb_);
            CHECK_AND_RETURN_LOG(status == napi_ok, "Remove once cb ref: delete reference for callback fail");
            (*it)->cb_ = nullptr;
            thumbnailListenerList_.erase(it);
        } else {
            it++;
        }
    }
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
    uv_work_t* work = new(std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("ThumbnailListener:UpdateJSCallbackAsync() failed to allocate work");
        return;
    }
    std::unique_ptr<ThumbnailListenerInfo> callbackInfo =
            std::make_unique<ThumbnailListenerInfo>(photoOutput, this);
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        ThumbnailListenerInfo* callbackInfo = reinterpret_cast<ThumbnailListenerInfo *>(work->data);
        if (callbackInfo) {
            callbackInfo->listener_->UpdateJSCallback(callbackInfo->photoOutput_);
            MEDIA_ERR_LOG("ThumbnailListener:UpdateJSCallbackAsync() complete");
            callbackInfo->photoOutput_ =  nullptr;
            callbackInfo->listener_ = nullptr;
            delete callbackInfo;
        }
        delete work;
    }, uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("ThumbnailListener:UpdateJSCallbackAsync() failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void ThumbnailListener::SaveCallbackReference(napi_value callback, bool isOnce)
{
    std::lock_guard<std::mutex> lock(mutex_);
    napi_ref callbackRef = nullptr;
    const int32_t refCount = 1;

    for (auto it = thumbnailListenerList_.begin(); it != thumbnailListenerList_.end(); ++it) {
        bool isSameCallback = CameraNapiUtils::IsSameCallback(env_, callback, (*it)->cb_);
        CHECK_AND_RETURN_LOG(!isSameCallback, "SaveCallbackReference: has same callback, nothing to do");
    }
    napi_status status = napi_create_reference(env_, callback, refCount, &callbackRef);
    CHECK_AND_RETURN_LOG(status == napi_ok && callbackRef != nullptr,
                         "ErrorCallbackListener: creating reference for callback fail");
    std::shared_ptr<AutoRef> cb = std::make_shared<AutoRef>(env_, callbackRef, isOnce);
    thumbnailListenerList_.push_back(cb);
    MEDIA_DEBUG_LOG("Save callback reference success, thumbnailListener list size [%{public}zu]",
        thumbnailListenerList_.size());
}

void ThumbnailListener::RemoveCallbackRef(napi_env env, napi_value callback)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (callback == nullptr) {
        MEDIA_INFO_LOG("RemoveCallbackReference: js callback is nullptr, remove all callback reference");
        RemoveAllCallbacks();
        return;
    }
    for (auto it = thumbnailListenerList_.begin(); it != thumbnailListenerList_.end(); ++it) {
        bool isSameCallback = CameraNapiUtils::IsSameCallback(env_, callback, (*it)->cb_);
        if (isSameCallback) {
            MEDIA_INFO_LOG("RemoveCallbackReference: find js callback, delete it");
            napi_status status = napi_delete_reference(env, (*it)->cb_);
            (*it)->cb_ = nullptr;
            CHECK_AND_RETURN_LOG(status == napi_ok, "RemoveCallbackReference: delete reference for callback fail");
            thumbnailListenerList_.erase(it);
            return;
        }
    }
    MEDIA_INFO_LOG("RemoveCallbackReference: js callback no find");
}

void ThumbnailListener::RemoveAllCallbacks()
{
    for (auto it = thumbnailListenerList_.begin(); it != thumbnailListenerList_.end(); ++it) {
        napi_delete_reference(env_, (*it)->cb_);
        (*it)->cb_ = nullptr;
    }
    thumbnailListenerList_.clear();
    MEDIA_INFO_LOG("RemoveAllCallbacks: remove all js callbacks success");
}

PhotoOutputNapi::PhotoOutputNapi() : env_(nullptr), wrapper_(nullptr)
{
}

PhotoOutputNapi::~PhotoOutputNapi()
{
    MEDIA_DEBUG_LOG("~PhotoOutputNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
    if (photoOutput_) {
        photoOutput_ = nullptr;
    }
    if (photoCallback_) {
        photoCallback_ = nullptr;
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
        DECLARE_NAPI_FUNCTION("capture", Capture),
        DECLARE_NAPI_FUNCTION("release", Release),
        DECLARE_NAPI_FUNCTION("isMirrorSupported", IsMirrorSupported),
        DECLARE_NAPI_FUNCTION("setMirror", SetMirror),
        DECLARE_NAPI_FUNCTION("enableQuickThumbnail", EnableQuickThumbnail),
        DECLARE_NAPI_FUNCTION("isQuickThumbnailSupported", IsQuickThumbnailSupported),
        DECLARE_NAPI_FUNCTION("on", On),
        DECLARE_NAPI_FUNCTION("once", Once),
        DECLARE_NAPI_FUNCTION("off", Off)

    };

    status = napi_define_class(env, CAMERA_PHOTO_OUTPUT_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               PhotoOutputNapiConstructor, nullptr,
                               sizeof(photo_output_props) / sizeof(photo_output_props[PARAM0]),
                               photo_output_props, &ctorObj);
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

napi_value PhotoOutputNapi::CreatePhotoOutput(napi_env env, Profile &profile, std::string surfaceId)
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
            MEDIA_ERR_LOG("create surface as consumer");
            photoSurface = Surface::CreateSurfaceAsConsumer("photoOutput");
            sPhotoSurface_ = photoSurface;
        } else {
            MEDIA_ERR_LOG("get surface by surfaceId");
            photoSurface = Media::ImageReceiver::getSurfaceById(surfaceId);
        }
        if (photoSurface == nullptr) {
            MEDIA_ERR_LOG("failed to get surface");
            return result;
        }

        MEDIA_INFO_LOG("surface width: %{public}d, height: %{public}d", photoSurface->GetDefaultWidth(),
                       photoSurface->GetDefaultHeight());
        photoSurface->SetUserData(CameraManager::surfaceFormat, std::to_string(profile.GetCameraFormat()));
        sptr<IBufferProducer> surfaceProducer = photoSurface->GetProducer();
        int retCode = CameraManager::GetInstance()->CreatePhotoOutput(profile, surfaceProducer, &sPhotoOutput_);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        if (sPhotoOutput_ == nullptr) {
            MEDIA_ERR_LOG("failed to create CreatePhotoOutput");
            return result;
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
        CameraNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                             context->work, *jsContext);
    }
    delete context;
}

int32_t QueryAndGetProperty(napi_env env, napi_value arg, const string &propertyName, napi_value &property)
{
    MEDIA_DEBUG_LOG("QueryAndGetProperty is called");
    bool present = false;
    int32_t retval = 0;
    if ((napi_has_named_property(env, arg, propertyName.c_str(), &present) != napi_ok)
        || (!present) || (napi_get_named_property(env, arg, propertyName.c_str(), &property) != napi_ok)) {
            MEDIA_ERR_LOG("Failed to obtain property: %{public}s", propertyName.c_str());
            retval = -1;
    }

    return retval;
}

int32_t GetLocationProperties(napi_env env, napi_value locationObj, const PhotoOutputAsyncContext &context)
{
    MEDIA_DEBUG_LOG("GetLocationProperties is called");
    PhotoOutputAsyncContext* asyncContext = const_cast<PhotoOutputAsyncContext *>(&context);
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

static void GetFetchOptionsParam(napi_env env, napi_value arg, const PhotoOutputAsyncContext &context, bool &err)
{
    MEDIA_DEBUG_LOG("GetFetchOptionsParam is called");
    PhotoOutputAsyncContext* asyncContext = const_cast<PhotoOutputAsyncContext *>(&context);
    int32_t intValue;
    std::string strValue;
    napi_value property = nullptr;
    PhotoCaptureSetting::QualityLevel quality;
    PhotoCaptureSetting::RotationConfig rotation;

    if (QueryAndGetProperty(env, arg, "quality", property) == 0) {
        if (napi_get_value_int32(env, property, &intValue) != napi_ok
            || CameraNapiUtils::MapQualityLevelFromJs(intValue, quality) == -1) {
            err = true;
            return;
        } else {
            asyncContext->quality = quality;
        }
    }

    if (QueryAndGetProperty(env, arg, "rotation", property) == 0) {
        if (napi_get_value_int32(env, property, &intValue) != napi_ok
            || CameraNapiUtils::MapImageRotationFromJs(intValue, rotation) == -1) {
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

static napi_value ConvertJSArgsToNative(napi_env env, size_t argc, const napi_value argv[],
    PhotoOutputAsyncContext &asyncContext)
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
    napi_value argv[ARGS_TWO] = {0};
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
            env, nullptr, resource, [](napi_env env, void* data) {
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

                context->bRetBool = false;
                context->status = true;
                sptr<PhotoOutput> photoOutput = ((sptr<PhotoOutput> &)(context->objectInfo->photoOutput_));
                if ((context->hasPhotoSettings)) {
                    std::shared_ptr<PhotoCaptureSetting> capSettings = make_shared<PhotoCaptureSetting>();

                    if (context->quality != -1) {
                        capSettings->SetQuality(
                            static_cast<PhotoCaptureSetting::QualityLevel>(context->quality));
                    }

                    if (context->rotation != -1) {
                        capSettings->SetRotation(
                            static_cast<PhotoCaptureSetting::RotationConfig>(context->rotation));
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
            }, CommonCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for PhotoOutputNapi::Capture");
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
            asyncContext.release();
        }
    } else {
        MEDIA_ERR_LOG("Capture call Failed!");
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
    napi_value argv[ARGS_ONE] = {0};
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
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<PhotoOutputAsyncContext*>(data);
                context->status = false;
                // Start async trace
                context->funcName = "PhotoOutputNapi::Release";
                context->taskId = CameraNapiUtils::IncreamentAndGet(photoOutputTaskId);
                CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
                if (context->objectInfo != nullptr && context->objectInfo->photoOutput_ != nullptr) {
                    context->bRetBool = false;
                    context->status = true;
                    ((sptr<PhotoOutput> &)(context->objectInfo->photoOutput_))->Release();
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
    napi_value argv[ARGS_ONE] = {0};
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
            env, nullptr, resource, [](napi_env env, void* data) {
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
    if (!CameraNapiUtils::CheckSystemApp(env)) {
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

napi_value PhotoOutputNapi::SetMirror(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetMirror is called");
    napi_status status;
    napi_value result = nullptr;
    const int32_t refCount = 1;
    napi_value resource = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
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
            env, nullptr, resource, [](napi_env env, void* data) {
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
    if (!CameraNapiUtils::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi EnableQuickThumbnail is called!");
        return nullptr;
    }
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
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

napi_value PhotoOutputNapi::RegisterCallback(napi_env env, napi_value jsThis,
    const string &eventType, napi_value callback, bool isOnce)
{
    MEDIA_INFO_LOG("RegisterCallback is called");
    napi_value undefinedResult = nullptr;
    napi_get_undefined(env, &undefinedResult);
    napi_status status;
    PhotoOutputNapi* photoOutputNapi = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void**>(&photoOutputNapi));
    NAPI_ASSERT(env, status == napi_ok && photoOutputNapi != nullptr,
                "Failed to retrieve photoOutputNapi instance.");
    NAPI_ASSERT(env, photoOutputNapi->photoOutput_ != nullptr, "photoOutput is null.");
    if (eventType.compare(OHOS::CameraStandard::thumbnailRegisterName) == 0) {
        // Set callback for exposureStateChange
        if (photoOutputNapi->thumbnailListener_ == nullptr) {
            if (!CameraNapiUtils::CheckSystemApp(env)) {
                MEDIA_ERR_LOG("SystemApi quickThumbnail on is called!");
                return nullptr;
            }
            if (!photoOutputNapi->isQuickThumbnailEnabled_) {
                MEDIA_ERR_LOG("quickThumbnail is not enabled!");
                napi_throw_error(env, std::to_string(SESSION_NOT_RUNNING).c_str(), "");
                return undefinedResult;
            }
            sptr<ThumbnailListener> listener = new ThumbnailListener(env, photoOutputNapi->photoOutput_);
            photoOutputNapi->thumbnailListener_ = listener;
            photoOutputNapi->photoOutput_->SetThumbnailListener((sptr<IBufferConsumerListener>&)listener);
        }
        photoOutputNapi->thumbnailListener_->SaveCallbackReference(callback, isOnce);
    } else if (eventType.compare(OHOS::CameraStandard::captureRegisterName) == 0 && sPhotoSurface_) {
        if (photoOutputNapi->photoListener_ == nullptr) {
            sptr<PhotoListener> phtotListener = new PhotoListener(env, sPhotoSurface_);
            SurfaceError ret = sPhotoSurface_->RegisterConsumerListener((sptr<IBufferConsumerListener> &)phtotListener);
            if (ret != SURFACE_ERROR_OK) {
                MEDIA_ERR_LOG("PhotoOutputNapi RegisterCallback failed!");
            }
            photoOutputNapi->photoListener_ = phtotListener;
        }
        photoOutputNapi->photoListener_->SaveCallbackReference(callback, isOnce);
    } else if (!eventType.empty()) {
        // Set callback for focusStateChange
        if (photoOutputNapi->photoCallback_ == nullptr) {
            std::shared_ptr<PhotoOutputCallback> photoOutputCallback = std::make_shared<PhotoOutputCallback>(env);
            ((sptr<PhotoOutput> &)(photoOutputNapi->photoOutput_))->SetCallback(photoOutputCallback);
            photoOutputNapi->photoCallback_ = photoOutputCallback;
        }
        std::shared_ptr<PhotoOutputCallback> cb =
                std::static_pointer_cast<PhotoOutputCallback>(photoOutputNapi->photoCallback_);
        cb->SaveCallbackReference(eventType, callback, isOnce);
    } else  {
        MEDIA_ERR_LOG("Failed to Register Callback: event type is empty!");
    }
    return undefinedResult;
}

napi_value PhotoOutputNapi::On(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("On is called");
    CAMERA_SYNC_TRACE;
    napi_value undefinedResult = nullptr;
    size_t argCount = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {nullptr, nullptr};
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);

    CAMERA_NAPI_GET_JS_ARGS(env, info, argCount, argv, thisVar);
    NAPI_ASSERT(env, argCount == ARGS_TWO, "requires 2 parameters");

    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok || valueType != napi_string
        || napi_typeof(env, argv[PARAM1], &valueType) != napi_ok || valueType != napi_function) {
        return undefinedResult;
    }
    std::string eventType = CameraNapiUtils::GetStringArgument(env, argv[PARAM0]);
    MEDIA_INFO_LOG("On eventType: %{public}s", eventType.c_str());
    return RegisterCallback(env, thisVar, eventType, argv[PARAM1], false);
}

napi_value PhotoOutputNapi::UnregisterCallback(napi_env env, napi_value jsThis,
    const std::string& eventType, napi_value callback)
{
    MEDIA_INFO_LOG("UnregisterCallback is called");
    napi_value undefinedResult = nullptr;
    napi_get_undefined(env, &undefinedResult);
    PhotoOutputNapi *photoOutputNapi = nullptr;
    napi_status status = napi_unwrap(env, jsThis, reinterpret_cast<void**>(&photoOutputNapi));
    NAPI_ASSERT(env, status == napi_ok && photoOutputNapi != nullptr, "Failed to photoOutputNapi instance.");
    NAPI_ASSERT(env, photoOutputNapi->photoOutput_ != nullptr, "photoOutput is null.");
    if (eventType == OHOS::CameraStandard::thumbnailRegisterName) {
        if (!CameraNapiUtils::CheckSystemApp(env)) {
            MEDIA_ERR_LOG("SystemApi quickThumbnail off is called!");
            return undefinedResult;
        }
        if (!photoOutputNapi->isQuickThumbnailEnabled_) {
            MEDIA_ERR_LOG("quickThumbnail is not enabled!");
            napi_throw_error(env, std::to_string(SESSION_NOT_RUNNING).c_str(), "");
            return undefinedResult;
        }
        if (photoOutputNapi->thumbnailListener_ != nullptr) {
            photoOutputNapi->thumbnailListener_->RemoveCallbackRef(env, callback);
        }
    } else if (!eventType.empty()) {
        photoOutputNapi->photoCallback_->RemoveCallbackRef(env, callback, eventType);
    } else {
        MEDIA_ERR_LOG("Failed to Register Callback: event type is empty!");
    }
    return undefinedResult;
}

napi_value PhotoOutputNapi::Off(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("Off is called");
    napi_value undefinedResult = nullptr;
    napi_get_undefined(env, &undefinedResult);
    const size_t minArgCount = 1;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {nullptr, nullptr};
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    if (argc < minArgCount) {
        return undefinedResult;
    }

    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok || valueType != napi_string) {
        return undefinedResult;
    }

    napi_valuetype secondArgsType = napi_undefined;
    if (argc > minArgCount &&
        (napi_typeof(env, argv[PARAM1], &secondArgsType) != napi_ok || secondArgsType != napi_function)) {
        return undefinedResult;
    }
    std::string eventType = CameraNapiUtils::GetStringArgument(env, argv[0]);
    MEDIA_INFO_LOG("Off eventType: %{public}s", eventType.c_str());
    return UnregisterCallback(env, thisVar, eventType, argv[PARAM1]);
}

napi_value PhotoOutputNapi::Once(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("Once is called");
    CAMERA_SYNC_TRACE;
    napi_value undefinedResult = nullptr;
    size_t argCount = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {nullptr, nullptr};
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);

    CAMERA_NAPI_GET_JS_ARGS(env, info, argCount, argv, thisVar);
    NAPI_ASSERT(env, argCount == ARGS_TWO, "requires 2 parameters");

    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok || valueType != napi_string
        || napi_typeof(env, argv[PARAM1], &valueType) != napi_ok || valueType != napi_function) {
        return undefinedResult;
    }
    std::string eventType = CameraNapiUtils::GetStringArgument(env, argv[PARAM0]);
    MEDIA_INFO_LOG("Once eventType: %{public}s", eventType.c_str());
    return RegisterCallback(env, thisVar, eventType, argv[PARAM1], true);
}
} // namespace CameraStandard
} // namespace OHOS
