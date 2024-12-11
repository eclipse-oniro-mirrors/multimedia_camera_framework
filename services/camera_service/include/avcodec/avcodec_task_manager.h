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

#ifndef CAMERA_FRAMEWORK_LIVEPHOTO_GENERATOR_H
#define CAMERA_FRAMEWORK_LIVEPHOTO_GENERATOR_H

#include <mutex>
#include <memory>
#include <atomic>
#include <queue>
#include <thread>
#include <fstream>
#include "frame_record.h"
#include "audio_record.h"
#include "audio_capturer_session.h"
#include "native_avmuxer.h"
#include "refbase.h"
#include "surface_buffer.h"
#include "video_encoder.h"
#include "audio_encoder.h"
#include "audio_video_muxer.h"
#include "iconsumer_surface.h"
#include "blocking_queue.h"
#include "task_manager.h"
#include "camera_util.h"
namespace OHOS {
namespace CameraStandard {
using namespace std;
using namespace DeferredProcessing;
using namespace Media;
using CacheCbFunc = function<void(sptr<FrameRecord>, bool)>;
constexpr uint32_t DEFAULT_THREAD_NUMBER = 6;
constexpr uint32_t DEFAULT_ENCODER_THREAD_NUMBER = 1;
constexpr uint32_t GET_FD_EXPIREATION_TIME = 2000;
constexpr int64_t ONE_BILLION = 1000000000LL;
constexpr uint32_t MAX_FRAME_COUNT = 90;

class AvcodecTaskManager : public RefBase, public std::enable_shared_from_this<AvcodecTaskManager> {
public:
    explicit AvcodecTaskManager(sptr<AudioCapturerSession> audioCapturerSession, VideoCodecType type);
    ~AvcodecTaskManager();
    void EncodeVideoBuffer(sptr<FrameRecord> frameRecord, CacheCbFunc cacheCallback);
    void PrepareAudioBuffer(vector<sptr<FrameRecord>>& choosedBuffer, vector<sptr<AudioRecord>>& audioRecords,
        vector<sptr<AudioRecord>>& processedRecords);
    void CollectAudioBuffer(vector<sptr<AudioRecord>> audioRecordVec, sptr<AudioVideoMuxer> muxer);
    void DoMuxerVideo(vector<sptr<FrameRecord>> frameRecords, uint64_t taskName, int32_t captureRotation,
        int32_t captureId);
    sptr<AudioVideoMuxer> CreateAVMuxer(vector<sptr<FrameRecord>> frameRecords, int32_t captureRotation,
        vector<sptr<FrameRecord>> &choosedBuffer, int32_t captureId);
    void SubmitTask(function<void()> task);
    void SetVideoFd(int64_t timestamp, PhotoAssetIntf* photoAssetProxy, int32_t captureId);
    void Stop();
    void ClearTaskResource();
    void SetVideoBufferDuration(uint32_t preBufferCount, uint32_t postBufferCount);
    shared_ptr<TaskManager>& GetTaskManager();
    shared_ptr<TaskManager>& GetEncoderManager();
    mutex startTimeMutex_;
    mutex endTimeMutex_;
    std::map<int32_t, int64_t> mPStartTimeMap_ = {};
    std::map<int32_t, int64_t> mPEndTimeMap_ = {};

private:
    void FinishMuxer(sptr<AudioVideoMuxer> muxer);
    void ChooseVideoBuffer(vector<sptr<FrameRecord>> frameRecords, vector<sptr<FrameRecord>> &choosedBuffer,
        int64_t shutterTime, int32_t captureId);
    size_t FindIdrFrameIndex(vector<sptr<FrameRecord>> frameRecords, int64_t shutterTime, int32_t captureId);
    void IgnoreDeblur(vector<sptr<FrameRecord>> frameRecords, vector<sptr<FrameRecord>> &choosedBuffer,
        int64_t shutterTime);
    void Release();
    unique_ptr<VideoEncoder> videoEncoder_ = nullptr;
    unique_ptr<AudioEncoder> audioEncoder_ = nullptr;
    shared_ptr<TaskManager> taskManager_ = nullptr;
    shared_ptr<TaskManager> videoEncoderManager_ = nullptr;
    sptr<AudioCapturerSession> audioCapturerSession_ = nullptr;
    condition_variable cvEmpty_;
    mutex videoFdMutex_;
    mutex taskManagerMutex_;
    mutex encoderManagerMutex_;
    std::atomic<bool> isActive_ { true };
    map<int32_t, std::pair<int64_t, PhotoAssetIntf*>> videoFdMap_;
    VideoCodecType videoCodecType_ = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    int64_t preBufferDuration_ = NANOSEC_RANGE;
    int64_t postBufferDuration_ = NANOSEC_RANGE;
};
} // CameraStandard
} // OHOS
#endif // CAMERA_FRAMEWORK_LIVEPHOTO_GENERATOR_H