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

#ifndef CAMERA_FRAMEWORK_MOVING_PHOTO_VIDEO_CACHE_H
#define CAMERA_FRAMEWORK_MOVING_PHOTO_VIDEO_CACHE_H

#include <functional>
#include <mutex>
#include <memory>
#include <atomic>
#include <thread>
#include <fstream>
#include "native_avmuxer.h"
#include "refbase.h"
#include "video_encoder.h"
#include "audio_encoder.h"
#include "audio_video_muxer.h"
#include "iconsumer_surface.h"
#include <unordered_set>
#include <vector>
#include "frame_record.h"
#include <refbase.h>
#include "avcodec_task_manager.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;
using CachedFrameSet = unordered_set<sptr<FrameRecord>, FrameRecord::HashFunction, FrameRecord::EqualFunction>;
using EncodedEndCbFunc = function<void(vector<sptr<FrameRecord>>, uint64_t, int32_t)>;
class CachedFrameCallbackHandle;
class MovingPhotoVideoCache : public RefBase {
public:
    explicit MovingPhotoVideoCache(sptr<AvcodecTaskManager> taskManager);
    ~MovingPhotoVideoCache();
    void CacheFrame(sptr<FrameRecord> frameRecord);
    void OnImageEncoded(sptr<FrameRecord> frameRecord, bool encodeResult);
    void GetFrameCachedResult(vector<sptr<FrameRecord>> frameRecords,
        EncodedEndCbFunc encodedEndCbFunc, uint64_t taskName, int32_t rotation);
    void DoMuxerVideo(vector<sptr<FrameRecord>> frameRecords, uint64_t taskName, int32_t rotation);
    void ClearCallbackHandler();
    void ClearCache();
private:
    mutex callbackVecLock_; // Guard cachedFrameCallbackHandles
    vector<sptr<CachedFrameCallbackHandle>> cachedFrameCallbackHandles_;
    mutex taskManagerLock_; // Guard cachedFrameCallbackHandles
    sptr<AvcodecTaskManager> taskManager_;
};

class CachedFrameCallbackHandle : public RefBase {
public:
    CachedFrameCallbackHandle(vector<sptr<FrameRecord>> frameRecords,
        EncodedEndCbFunc encodedEndCbFunc, uint64_t taskName, int32_t rotation);
    ~CachedFrameCallbackHandle();
    void OnCacheFrameFinish(sptr<FrameRecord> frameRecord, bool cachedSuccess);
    void AbortCapture();
    CachedFrameSet GetCacheRecord();
private:
    CachedFrameSet cacheRecords_; //set
    vector<sptr<FrameRecord>> errorCacheRecords_;
    vector<sptr<FrameRecord>> successCacheRecords_;
    EncodedEndCbFunc encodedEndCbFunc_;
    atomic<bool> isAbort_ { false };
    mutex cacheFrameMutex_;
    uint64_t taskName_;
    int32_t rotation_;
};
} // CameraStandard
} // OHOS
#endif // CAMERA_FRAMEWORK_MOVING_PHOTO_VIDEO_CACHE_H