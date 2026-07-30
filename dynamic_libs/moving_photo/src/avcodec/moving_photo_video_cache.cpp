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
#include "utils/camera_log.h"
#include "refbase.h"
#include "surface_buffer.h"
#include "video_encoder.h"

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
    manualTaskManagerLock_.lock();
    manualTaskManager_ = nullptr;
    manualTaskManagerLock_.unlock();
    std::lock_guard<std::mutex> lock(callbackVecLock_);
    cachedFrameCallbackHandles_.clear();
}

MovingPhotoVideoCache::MovingPhotoVideoCache(sptr<AvcodecTaskManager> taskManager,
    sptr<AvcodecExtendImageTaskManager> manualTaskManager) : taskManager_(taskManager),
    manualTaskManager_(manualTaskManager)
{
}

void MovingPhotoVideoCache::CacheFrame(sptr<FrameRecord> frameRecord)
{
    MEDIA_DEBUG_LOG("CacheFrame enter");
    if (frameRecord->IsManual()) {
        MEDIA_INFO_LOG("Do manual encode");
        std::lock_guard<std::mutex> lock(manualTaskManagerLock_);
        if (manualTaskManager_) {
            frameRecord->SetStatusReadyConvertStatus();
            auto thisPtr = sptr<MovingPhotoVideoCache>(this);
            manualTaskManager_->EncodeVideoExtendBuffer(frameRecord,
                [thisPtr](sptr<FrameRecord> frameRecord, bool encodeResult) {
                    thisPtr->OnManualImageEncoded(frameRecord, encodeResult);
            });
        }
    } else {
        std::lock_guard<std::mutex> lock(taskManagerLock_);
        if (taskManager_) {
            frameRecord->SetStatusReadyConvertStatus();
            auto thisPtr = sptr<MovingPhotoVideoCache>(this);
            taskManager_->EncodeVideoBuffer(frameRecord, [thisPtr](sptr<FrameRecord> frameRecord, bool encodeResult) {
                thisPtr->OnImageEncoded(frameRecord, encodeResult);
            });
        }
    }
}

void MovingPhotoVideoCache::OnManualImageEncoded(sptr<FrameRecord> frameRecord, bool encodedResult)
{
    // LCOV_EXCL_START
    bool isSuccessed = encodedResult && frameRecord != nullptr && frameRecord->GetEncodeBuffer() != nullptr;
    if (isSuccessed) {
        manualImageEncodedCache_.push_back(frameRecord);
    }

    std::lock_guard<std::mutex> lock(callbackVecLock_);
    for (auto cachedFrameCallbackHandle : cachedFrameCallbackHandles_) {
        CHECK_CONTINUE_ELOG(cachedFrameCallbackHandle == nullptr,
            "MovingPhotoVideoCache::OnManualImageEncoded with null cachedFrameCallbackHandle");
        cachedFrameCallbackHandle->OnCacheFrameFinish(frameRecord, isSuccessed);
    }
    // LCOV_EXCL_END
}

void MovingPhotoVideoCache::DoMuxerVideo(std::vector<sptr<FrameRecord>> frameRecords, uint64_t taskName,
                                         int32_t rotation, int32_t captureId)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("DoMuxerVideo enter");
    std::sort(frameRecords.begin(), frameRecords.end(),
        [](const sptr<FrameRecord>& a, const sptr<FrameRecord>& b) {
        return a->GetTimeStamp() < b->GetTimeStamp();
    });
    std::lock_guard<std::mutex> lock(taskManagerLock_);
    CHECK_RETURN(!taskManager_);
    taskManager_->DoMuxerVideo(frameRecords, manualTaskManager_->GetXpsBuffer(), manualImageEncodedCache_, taskName,
        rotation, captureId);
    auto thisPtr = sptr<MovingPhotoVideoCache>(this);
    taskManager_->SubmitTask([thisPtr]() { thisPtr->ClearCallbackHandler(); });
}

// Call this function after buffer has been encoded
void MovingPhotoVideoCache::OnImageEncoded(sptr<FrameRecord> frameRecord, bool encodeResult)
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(callbackVecLock_);
    for (auto cachedFrameCallbackHandle : cachedFrameCallbackHandles_) {
        CHECK_CONTINUE_ELOG(cachedFrameCallbackHandle == nullptr,
            "MovingPhotoVideoCache::OnImageEncoded with null cachedFrameCallbackHandle");
        cachedFrameCallbackHandle->OnCacheFrameFinish(frameRecord, encodeResult);
        MEDIA_INFO_LOG("cId:%{public}d: cachedSuccess frameRecords size:%{public}d",
            cachedFrameCallbackHandle->GetCaptureId(), cachedFrameCallbackHandle->GetSuccessSize());
    }
}

void MovingPhotoVideoCache::GetFrameCachedResult(std::vector<sptr<FrameRecord>> frameRecords,
    EncodedEndCbFunc encodedEndCbFunc, uint64_t taskName, int32_t rotation, int32_t captureId)
{
    callbackVecLock_.lock();
    MEDIA_INFO_LOG("GetFrameCachedResult enter frameRecords size: %{public}zu", frameRecords.size());
    auto Find = find_if(cachedFrameCallbackHandles_.begin(), cachedFrameCallbackHandles_.end(),
        [captureId](const sptr<CachedFrameCallbackHandle>& cacheFrameHandler) {
            return cacheFrameHandler->GetCaptureId() == captureId;
        });
    if (Find != cachedFrameCallbackHandles_.end()) {
        MEDIA_INFO_LOG("capture task:%{public}d already process GetFrameCachedResult.", captureId);
        callbackVecLock_.unlock();
        return;
    }
    sptr<CachedFrameCallbackHandle> cacheFrameHandler =
        new CachedFrameCallbackHandle(frameRecords, encodedEndCbFunc, taskName, rotation, captureId, taskManager_);
    cachedFrameCallbackHandles_.push_back(cacheFrameHandler);
    callbackVecLock_.unlock();
    //Reentrant
    for (auto frameRecord : frameRecords) {
        if (frameRecord == nullptr) { continue; }
        if (frameRecord->IsFinishCache()) {
            cacheFrameHandler->OnCacheFrameFinish(frameRecord, frameRecord->IsEncoded());
        }
    }
    MEDIA_INFO_LOG("cId:%{public}d: cachedSuccess frameRecords size:%{public}d", cacheFrameHandler->GetCaptureId(),
        cacheFrameHandler->GetSuccessSize());
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
    EncodedEndCbFunc encodedEndCbFunc, uint64_t taskName, int32_t rotation, int32_t captureId,
    wptr<AvcodecTaskManager> taskManager)
    : encodedEndCbFunc_(encodedEndCbFunc), isAbort_(false), taskName_(taskName), rotation_(rotation),
      captureId_(captureId), taskManager_(taskManager)
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
    CHECK_EXECUTE(frameRecord != nullptr && frameRecord->IsEncoded(), encodedSuccessSize_++);
    std::lock_guard<std::mutex> lock(cacheFrameMutex_);
    if (isAbort_) {
        // Handle abort
        MEDIA_INFO_LOG("OnCacheFrameFinish is abort");
        return;
    }
    auto it = cacheRecords_.find(frameRecord);
    CHECK_RETURN(it == cacheRecords_.end());
    cacheRecords_.erase(it);
    // If cachedSuccess is fail, try to process overtime frame
    bool hasOverTimeEntry = false;
    if (!cachedSuccess && frameRecord != nullptr) {
        {
            auto taskManager = taskManager_.promote();
            if (taskManager) {
                hasOverTimeEntry = taskManager->ProcessOverTimeFrame(frameRecord);
                MEDIA_INFO_LOG("OnCacheFrameFinish: ProcessOverTimeFrame for timestamp: %{public}" PRId64
                               ", result: %{public}d",
                    frameRecord->GetTimeStamp(), hasOverTimeEntry);
            }
        }
    }
    // If overTimeMap has entry for this timestamp and cachedSuccess is fail, treat as success
    bool isSucc =
        (hasOverTimeEntry || cachedSuccess) && frameRecord != nullptr && frameRecord->GetEncodeBuffer() != nullptr;
    if (isSucc) {
        if (!frameRecord->IsManual()) {
            successCacheRecords_.push_back(frameRecord);
        }
    } else {
        errorCacheRecords_.push_back(frameRecord);
    }

    // Still waiting for more cache encoded buffer
    CHECK_RETURN(!cacheRecords_.empty());
    MEDIA_INFO_LOG("encodedEndCbFunc_ is called success count: %{public}zu", successCacheRecords_.size());
    // All buffer have been encoded
    CHECK_RETURN(encodedEndCbFunc_ == nullptr);
    encodedEndCbFunc_(successCacheRecords_, taskName_, rotation_, captureId_);
    encodedEndCbFunc_ = nullptr;
}

// This function is called when prestop capture
void CachedFrameCallbackHandle::AbortCapture()
{
    std::lock_guard<std::mutex> lock(cacheFrameMutex_);
    isAbort_ = true;
    cacheRecords_.clear();
    CHECK_RETURN(encodedEndCbFunc_ == nullptr);
    encodedEndCbFunc_(successCacheRecords_, taskName_, rotation_, captureId_);
    encodedEndCbFunc_ = nullptr;
}

CachedFrameSet CachedFrameCallbackHandle::GetCacheRecord()
{
    std::lock_guard<std::mutex> lock(cacheFrameMutex_);
    return cacheRecords_;
}
} // CameraStandard
} // OHOS