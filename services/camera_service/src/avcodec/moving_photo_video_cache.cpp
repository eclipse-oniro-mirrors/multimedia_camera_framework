/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "moving_photo_video_cache.h"
#include <cinttypes>
#include <unistd.h>
#include <chrono>
#include <fcntl.h>
#include <memory>
#include <utility>
#include "external_window.h"
#include "native_buffer_inner.h"
#include "camera_log.h"
#include "refbase.h"
#include "surface_buffer.h"

namespace {
    using namespace std::string_literals;
    using namespace std::chrono_literals;
}
namespace OHOS {
namespace CameraStandard {

MovingPhotoVideoCache::~MovingPhotoVideoCache()
{
    MEDIA_DEBUG_LOG("~MovingPhotoVideoCache enter");
    taskManagerLock_.lock();
    taskManager_ = nullptr;
    taskManagerLock_.unlock();
    std::lock_guard<std::mutex> lock(callbackVecLock_);
    cachedFrameCallbackHandles_.clear();
}

MovingPhotoVideoCache::MovingPhotoVideoCache(sptr<AvcodecTaskManager> taskManager) : taskManager_(taskManager)
{
}

void MovingPhotoVideoCache::CacheFrame(sptr<FrameRecord> frameRecord)
{
    MEDIA_DEBUG_LOG("CacheFrame enter");
    std::lock_guard<std::mutex> lock(taskManagerLock_);
    if (taskManager_) {
        frameRecord->SetStatusReadyConvertStatus();
        auto thisPtr = sptr<MovingPhotoVideoCache>(this);
        taskManager_->EncodeVideoBuffer(frameRecord, [thisPtr](sptr<FrameRecord> frameRecord, bool encodeResult) {
            thisPtr->OnImageEncoded(frameRecord, encodeResult);
        });
    }
}

void MovingPhotoVideoCache::DoMuxerVideo(std::vector<sptr<FrameRecord>> frameRecords, uint64_t taskName,
                                         int32_t rotation)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("DoMuxerVideo enter");
    std::sort(frameRecords.begin(), frameRecords.end(),
        [](const sptr<FrameRecord>& a, const sptr<FrameRecord>& b) {
        return a->GetTimeStamp() < b->GetTimeStamp();
    });
    std::lock_guard<std::mutex> lock(taskManagerLock_);
    if (taskManager_) {
        taskManager_->DoMuxerVideo(frameRecords, taskName, rotation);
        auto thisPtr = sptr<MovingPhotoVideoCache>(this);
        taskManager_->SubmitTask([thisPtr]() {
            thisPtr->ClearCallbackHandler();
        });
    }
}

// Call this function after buffer has been encoded
void MovingPhotoVideoCache::OnImageEncoded(sptr<FrameRecord> frameRecord, bool encodeResult)
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(callbackVecLock_);
    for (auto cachedFrameCallbackHandle : cachedFrameCallbackHandles_) {
        if (cachedFrameCallbackHandle == nullptr) {
            MEDIA_ERR_LOG("MovingPhotoVideoCache::OnImageEncoded with null cachedFrameCallbackHandle");
            continue;
        }
        cachedFrameCallbackHandle->OnCacheFrameFinish(frameRecord, encodeResult);
    }
}

void MovingPhotoVideoCache::GetFrameCachedResult(std::vector<sptr<FrameRecord>> frameRecords,
    EncodedEndCbFunc encodedEndCbFunc, uint64_t taskName, int32_t rotation)
{
    callbackVecLock_.lock();
    MEDIA_INFO_LOG("GetFrameCachedResult enter frameRecords size: %{public}zu", frameRecords.size());
    sptr<CachedFrameCallbackHandle> cacheFrameHandler =
        new CachedFrameCallbackHandle(frameRecords, encodedEndCbFunc, taskName, rotation);
    cachedFrameCallbackHandles_.push_back(cacheFrameHandler);
    callbackVecLock_.unlock();
    for (auto frameRecord : frameRecords) {
        if (frameRecord->IsEncoded()) {
            cacheFrameHandler->OnCacheFrameFinish(frameRecord, frameRecord->IsEncoded());
        }
    }
}

void MovingPhotoVideoCache::ClearCallbackHandler()
{
    // OnImageEncoded has callbackVecLock_
    MEDIA_INFO_LOG("ClearCallbackHandler enter");
    std::lock_guard<std::mutex> lock(callbackVecLock_);
    MEDIA_DEBUG_LOG("ClearCallbackHandler get callbackVecLock_");
    cachedFrameCallbackHandles_.erase(std::remove_if(cachedFrameCallbackHandles_.begin(),
        cachedFrameCallbackHandles_.end(),
        [](const sptr<CachedFrameCallbackHandle>& obj) {return obj->GetCacheRecord().empty();}),
        cachedFrameCallbackHandles_.end());
}

void MovingPhotoVideoCache::ClearCache()
{
    MEDIA_INFO_LOG("ClearCache enter");
    // clear cache and muxer success buffer
    std::lock_guard<std::mutex> lock(callbackVecLock_);
    for (auto cachedFrameCallbackHandle : cachedFrameCallbackHandles_) {
        cachedFrameCallbackHandle->AbortCapture();
    }
    cachedFrameCallbackHandles_.clear();
}

CachedFrameCallbackHandle::CachedFrameCallbackHandle(std::vector<sptr<FrameRecord>> frameRecords,
    EncodedEndCbFunc encodedEndCbFunc, uint64_t taskName, int32_t rotation)
    : encodedEndCbFunc_(encodedEndCbFunc), isAbort_(false), taskName_(taskName), rotation_(rotation)
{
    std::lock_guard<std::mutex> lock(cacheFrameMutex_);
    cacheRecords_.insert(frameRecords.begin(), frameRecords.end());
}

CachedFrameCallbackHandle::~CachedFrameCallbackHandle()
{
    MEDIA_INFO_LOG("~CachedFrameCallbackHandle enter");
}

void CachedFrameCallbackHandle::OnCacheFrameFinish(sptr<FrameRecord> frameRecord, bool cachedSuccess)
{
    MEDIA_INFO_LOG("OnCacheFrameFinish enter cachedSuccess: %{public}d", cachedSuccess);
    std::lock_guard<std::mutex> lock(cacheFrameMutex_);
    if (isAbort_) {
        // Handle abort
        MEDIA_INFO_LOG("OnCacheFrameFinish is abort");
        return;
    }
    auto it = cacheRecords_.find(frameRecord);
    if (it != cacheRecords_.end()) {
        cacheRecords_.erase(it);
        if (cachedSuccess && frameRecord != nullptr && frameRecord->encodedBuffer != nullptr) {
            successCacheRecords_.push_back(frameRecord);
        } else {
            errorCacheRecords_.push_back(frameRecord);
        }
        if (!cacheRecords_.empty()) {
            // Still waiting for more cache encoded buffer
            return;
        }
        MEDIA_INFO_LOG("encodedEndCbFunc_ is called success count: %{public}zu", successCacheRecords_.size());
        // All buffer have been encoded
        if (encodedEndCbFunc_ != nullptr) {
            encodedEndCbFunc_(successCacheRecords_, taskName_, rotation_);
            encodedEndCbFunc_ = nullptr;
        }
    }
}

// This function is called when prestop capture
void CachedFrameCallbackHandle::AbortCapture()
{
    std::lock_guard<std::mutex> lock(cacheFrameMutex_);
    isAbort_ = true;
    cacheRecords_.clear();
    if (encodedEndCbFunc_ != nullptr) {
        encodedEndCbFunc_(successCacheRecords_, taskName_, rotation_);
        encodedEndCbFunc_ = nullptr;
    }
}

CachedFrameSet CachedFrameCallbackHandle::GetCacheRecord()
{
    std::lock_guard<std::mutex> lock(cacheFrameMutex_);
    return cacheRecords_;
}

} // CameraStandard
} // OHOS