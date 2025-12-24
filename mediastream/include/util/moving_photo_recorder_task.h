/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_MEDIA_STREAM_MOVING_PHOTO_RECORDER_TASK_H
#define OHOS_CAMERA_MEDIA_STREAM_MOVING_PHOTO_RECORDER_TASK_H

#include <cstdint>
#include <mutex>
#include <refbase.h>
#include "video_buffer_wrapper.h"
#include "safe_map.h"
#include "photo_asset_proxy.h"
#include <unordered_set>
#include <condition_variable>
#include "audio_buffer_wrapper.h"
#include "engine_context_ext.h"
#include "safe_map.h"

namespace OHOS {
namespace CameraStandard {

// 1.6s
constexpr int64_t NANOSEC_DURATION = 1600000000LL; 

class MovingPhotoRecorderTaskManager;
class MovingPhotoRecorderTask : public RefBase {
public:
    explicit MovingPhotoRecorderTask(sptr<MovingPhotoRecorderTaskManager> taskManager,
        int32_t rotation, int32_t captureId, int32_t maxSize);

    void OnBufferEncoded(sptr<VideoBufferWrapper> videoBufferWrapper, bool encodeResult);
    void OnVideoSaveFinish();

    ~MovingPhotoRecorderTask();
    void DrainImage(sptr<VideoBufferWrapper> videoBufferWrapper);
    void DrainFinish(bool isFinished);
    std::pair<int64_t, shared_ptr<PhotoAssetIntf>> GetPhotoAsset();

    inline int32_t GetTaskId()
    {
        return taskId_;
    }

    inline int32_t GetCaptureId()
    {
        return captureId_;
    }

    inline int32_t GetRotation()
    {
        return rotation_;
    }

    inline bool IsAllBufferEncoded()
    {
        return bufferSet_.empty() && drainImageFinish_;
    }

    void OnAllBufferEncoded();

    bool GetStartTime(int64_t& startTime);
    bool GetEndTime(int64_t& endTime);
    bool GetDeferredVideoEnhanceFlag(uint32_t& flag);
    bool GetVideoId(std::string& videoId);

    inline void GetEncodedBufferList(std::vector<sptr<VideoBufferWrapper>>& bufferList)
    {
        bufferList = encodedBufferList_;
    }

    void AbortCapture();

    inline bool IsNeedRemove()
    {
        return needRemove_;
    }

    void MarkNeedRemove() {
        needRemove_ = true;
    }
private:
    void OnDrainImage(sptr<VideoBufferWrapper> frame);
    void OnDrainImageFinish(bool isFinished);
    
    wptr<MovingPhotoRecorderTaskManager> taskManager_;
    std::mutex mutex_;
    std::vector<sptr<VideoBufferWrapper>> videoBufferWrapperList_;
    std::vector<sptr<VideoBufferWrapper>> encodedBufferList_;
    int32_t rotation_;
    int32_t captureId_;
    int32_t taskId_;
    int32_t usableCnt_;

    std::mutex bufferSetLock_;
    std::unordered_set<int64_t> bufferSet_;
    std::atomic<bool> isAbort_ { false };
    std::atomic<bool> drainImageFinish_{false};
    std::atomic<bool> needRemove_ { false };
};

class MovingPhotoRecorderTaskManager : public RefBase, public EngineContextExt {
public:
    MovingPhotoRecorderTaskManager(){}
    ~MovingPhotoRecorderTaskManager();

    sptr<MovingPhotoRecorderTask> CreateTask(int32_t rotation, int32_t captureId, int32_t maxSize);
    void DrainImage(sptr<VideoBufferWrapper> videoBufferWrapper);
    void EncodeBuffer(sptr<VideoBufferWrapper> videoBufferWrapper);
    void OnBufferEncoded(sptr<VideoBufferWrapper> videoBufferWrapper, bool encodeResult);
    void OnBufferEncodedNoLock(sptr<VideoBufferWrapper> videoBufferWrapper, bool encodeResult);
    void CreateMuxerTask(sptr<MovingPhotoRecorderTask> task);
    void GetChooseVideoBuffer(
        sptr<MovingPhotoRecorderTask> task, std::vector<sptr<VideoBufferWrapper>>& choosedBufferList);
    void GetAudioRecords(
        std::vector<sptr<VideoBufferWrapper>>& choosedBufferList, std::vector<sptr<AudioBufferWrapper>>& audioRecords);
    void InsertPhotoAsset(int64_t timestamp, shared_ptr<PhotoAssetIntf> photoAssetProxy, int32_t captureId);
    std::pair<int64_t, shared_ptr<PhotoAssetIntf>> GetPhotoAsset(int32_t taskId);

    void InsertStartTime(int32_t taskId, int64_t startTime);
    void InsertEndTime(int32_t taskId, int64_t endTime);
    void InsertDeferredVideoEnhanceFlag(int32_t taskId, uint32_t deferredVideoEnhanceFlag);
    void InsertVideoId(int32_t taskId, std::string videoId);
    bool GetStartTime(int32_t taskId, int64_t& startTime);
    bool GetEndTime(int32_t taskId, int64_t& endTime);
    bool GetDeferredVideoEnhanceFlag(int32_t taskId, uint32_t& flag);
    bool GetVideoId(int32_t taskId, std::string& videoId);

    void SetVideoBufferDuration(int64_t preBufferDuration, uint32_t postBufferDuration);
    bool IsEmpty();
    void StopDrainOut();
private:
    bool IsPhotoAssetSaved(int32_t taskId);

    size_t FindIdrFrameIndex(sptr<MovingPhotoRecorderTask> task,
        vector<sptr<VideoBufferWrapper>> bufferList, int64_t clearVideoEndTime, int64_t shutterTime);

    void IgnoreDeblur(vector<sptr<VideoBufferWrapper>>& bufferList, vector<sptr<VideoBufferWrapper>> &choosedBufferList,
        int64_t shutterTime);

    std::mutex mutex_;
    std::vector<sptr<MovingPhotoRecorderTask>> taskList_;

    std::mutex photoAssetMutex_;
    std::map<int32_t, std::pair<int64_t, shared_ptr<PhotoAssetIntf>>> photoAssetMap_;

    condition_variable cvEmpty_;

    SafeMap<int32_t, int64_t> startTimeMap_ = {};
    SafeMap<int32_t, int64_t> endTimeMap_ = {};
    SafeMap<int32_t, uint32_t> deferredVideoEnhanceFlagMap_ = {};
    SafeMap<int32_t, std::string> videoIdMap_ = {};

    int64_t preBufferDuration_ = NANOSEC_DURATION;
    int64_t postBufferDuration_ = NANOSEC_DURATION;
};
} // namespace CameraStandard
} // namespace OHOS
#endif