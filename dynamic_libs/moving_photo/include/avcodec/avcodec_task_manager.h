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
#include "camera_timer.h"
namespace OHOS {
namespace CameraStandard {
using namespace std;
using namespace DeferredProcessing;
using namespace Media;
using CacheCbFunc = function<void(sptr<FrameRecord>, bool)>;
constexpr uint32_t DEFAULT_THREAD_NUMBER = 6;
constexpr uint32_t DEFAULT_ENCODER_THREAD_NUMBER = 5;
constexpr uint32_t GET_FD_EXPIREATION_TIME = 2000;
constexpr int64_t ONE_BILLION = 1000000000LL;
constexpr uint32_t MAX_FRAME_COUNT = 90;
constexpr uint32_t RELEASE_WAIT_TIME = 10000;
constexpr size_t MIN_FRAME_RECORD_BUFFER_SIZE = 9;
constexpr int32_t NUM_ONE = 1;
constexpr int32_t NUM_TWO = 2;
constexpr int32_t NUM_FIVE = 5;
constexpr int32_t NUM_NINE = 9;
constexpr int64_t MAX_NANOSEC_RANGE = 3200000000LL;
constexpr int32_t WAIT_AUDIO_PROCESS = 8;
constexpr uint32_t WAIT_AUDIO_PROCESSED_EXPIREATION_TIME = 200;
constexpr uint32_t AUDIO_RECORD_DURATION = 32;
constexpr uint32_t WAIT_AUDIO_PROCESSED_DURATION_TIME = 100;
constexpr uint32_t DEFAULT_AUDIO_TASK_THREAD_NUMBER = 3;
constexpr uint32_t DEFAULT_PROCESSED_THREAD_NUMBER = 1;
constexpr uint32_t AUDIO_RECORD_CACHE_SIZE = 200;
constexpr int64_t MAX_AUDIO_NANOSEC_RANGE = 3200;
constexpr int32_t AUDIO_PROCESS_MATCH_SIZE = 5;


class AudioDeferredProcessSingle {
public:
    ~AudioDeferredProcessSingle();
    AudioDeferredProcessSingle(const AudioDeferredProcessSingle&) = delete;
    AudioDeferredProcessSingle operator=(const AudioDeferredProcessSingle&) = delete;

    static AudioDeferredProcessSingle& GetInstance();
    void ConfigAndProcess(sptr<AudioCapturerSession> audioCapturerSession, vector<sptr<AudioRecord>>& audioRecords,
        vector<sptr<AudioRecord>>& processedAudioRecords);
    void CreateAudioDeferredProcess(sptr<AudioCapturerSession> audioCapturerSession);
    void DestroyAudioDeferredProcess();
    void TimerDestroyAudioDeferredProcess();
    mutex deferredProcessMutex_;
    void ProcessMutedAudioBufferForVecs(sptr<AudioCapturerSession> audioCapturerSession_,
        vector<sptr<AudioRecord>>& audioRecords, vector<sptr<AudioRecord>>& encodeAudioRecords);

private:
    AudioDeferredProcessSingle();

    unique_ptr<AudioDeferredProcess> audioDeferredProcessPtr_;
};

class AudioTaskManager;
class AvcodecTaskManager : public RefBase, public std::enable_shared_from_this<AvcodecTaskManager> {
public:
    explicit AvcodecTaskManager(sptr<AudioCapturerSession> audioCapturerSession, VideoCodecType codecType,
        ColorSpace colorSpace);
    AvcodecTaskManager(wptr<Surface> movingSurface, shared_ptr<Size> size,
        sptr<AudioTaskManager> audioTaskManager, VideoCodecType type, ColorSpace colorSpace);
    ~AvcodecTaskManager();
    void EncodeVideoBuffer(sptr<FrameRecord> frameRecord, CacheCbFunc cacheCallback);
    void CollectAudioBuffer(vector<sptr<FrameRecord>>& choosedBuffer, sptr<AudioVideoMuxer> muxer, bool isNeedEncode);
    void WaitForAudioRecordFinished(vector<sptr<FrameRecord>>& choosedBuffer);
    void DoMuxerVideo(vector<sptr<FrameRecord>> frameRecords, uint64_t taskName, int32_t captureRotation,
        int32_t captureId);
    sptr<AudioVideoMuxer> CreateAVMuxer(vector<sptr<FrameRecord>> frameRecords, int32_t captureRotation,
        vector<sptr<FrameRecord>> &choosedBuffer, int32_t captureId, int64_t& backTimestamp);
    inline int32_t CalComplete(int32_t size)
    {
        size = size % NUM_NINE;
        //can only be 0,1,5,end up with I or P
        return (size - NUM_FIVE) >= 0 ? (size - NUM_FIVE) : (size - NUM_ONE) >= 0 ? (size - NUM_ONE) : 0;

    }
    void SubmitTask(function<void()> task);
    void SetVideoFd(int64_t timestamp, shared_ptr<PhotoAssetIntf> photoAssetProxy, int32_t captureId);
    void Stop();
    void ClearTaskResource();
    void SetVideoBufferDuration(uint32_t preBufferCount, uint32_t postBufferCount);
    bool isEmptyVideoFdMap();
    shared_ptr<TaskManager>& GetTaskManager();
    shared_ptr<TaskManager>& GetEncoderManager();
    uint32_t GetDeferredVideoEnhanceFlag(int32_t captureId);
    std::string GetVideoId(int32_t captureId);
    void SetDeferredVideoEnhanceFlag(int32_t captureId, uint32_t deferredVideoEnhanceFlag);
    void SetVideoId(int32_t captureId, std::string videoId);
    void RecordVideoType(int32_t captureId, VideoType type);
    void AsyncInitVideoCodec();
    mutex startTimeMutex_;
    mutex endTimeMutex_;
    std::map<int32_t, int64_t> mPStartTimeMap_ = {};
    std::map<int32_t, int64_t> mPEndTimeMap_ = {};
private:
    void FinishMuxer(sptr<AudioVideoMuxer> muxer, int32_t captureId);
    void ChooseVideoBuffer(vector<sptr<FrameRecord>> frameRecords, vector<sptr<FrameRecord>> &choosedBuffer,
        int64_t shutterTime, int32_t captureId, int64_t& backTimestamp);
    size_t FindIdrFrameIndex(vector<sptr<FrameRecord>> frameRecords,
        int64_t clearVideoEndTime, int64_t shutterTime, int32_t captureId);
    void IgnoreDeblur(vector<sptr<FrameRecord>> frameRecords, vector<sptr<FrameRecord>> &choosedBuffer,
        int64_t shutterTime);
    void Release();
    shared_ptr<VideoEncoder> videoEncoder_ = nullptr;
    unique_ptr<AudioEncoder> audioEncoder_ = nullptr;
    shared_ptr<TaskManager> taskManager_ = nullptr;
    shared_ptr<TaskManager> videoEncoderManager_ = nullptr;
    sptr<AudioCapturerSession> audioCapturerSession_ = nullptr;
    condition_variable cvEmpty_;
    mutex videoFdMutex_;
    mutex taskManagerMutex_;
    mutex encoderManagerMutex_;
    mutex deferredVideoEnhanceMutex_;
    std::mutex startAvcodecMutex_;
    mutex videoIdMutex_;
    mutex videoTypeMutex_;
    std::atomic<bool> isActive_ { true };
    map<int32_t, std::pair<int64_t, shared_ptr<PhotoAssetIntf>>> videoFdMap_;
    VideoCodecType videoCodecType_ = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    std::atomic<int64_t> preBufferDuration_ = NANOSEC_RANGE;
    std::atomic<int64_t> postBufferDuration_ = NANOSEC_RANGE;
    ColorSpace colorSpace_ = ColorSpace::COLOR_SPACE_UNKNOWN;
    std::map<int32_t, uint32_t> mDeferredVideoEnhanceMap_ = {};
    std::map<int32_t, std::string> mVideoIdMap_ = {};
    std::map<int32_t, VideoType> videoTypeMap_ = {};
    wptr<Surface> movingSurface_;
    shared_ptr<Size> size_ = std::make_shared<Size>();
    sptr<AudioTaskManager> audioTaskManager_ = nullptr;
    std::condition_variable audioProcessFinish_;
    std::mutex audioProcessMutex_;
};

class AudioTaskManager : public RefBase {
public:
    explicit AudioTaskManager(sptr<AudioCapturerSession> audioCapturerSession);
    ~AudioTaskManager();
    void SubmitTask(function<void()> task);
    void Release();
    void ClearTaskResource();
    shared_ptr<TaskManager>& GetAudioTaskManager();
    shared_ptr<TaskManager>& GetAudioProcessManager();
    void ProcessAudioBuffer(int32_t captureId, int64_t StartTimeStamp);
    void PrepareAudioBuffer(int64_t startTime);
    void RegisterAudioBuffeArrivalCallback(int64_t startTimeStamp);
    void OnAudioBufferArrival(sptr<AudioRecord>& audioRecord, bool isFinished);
    void ProcessAudioBufferToMuted(vector<sptr<AudioRecord>>& audioRecords,
        vector<sptr<AudioRecord>>& encodeAudioRecords);
    void ProcessAudioFromAudioBufferQueue();
    void SetTimerForAudioDeferredProcess();
    int32_t ClearProcessedAudioCache(int32_t captureId);
    void RemovePreviousCaptureForTimeMap(int32_t captureId);
    std::vector<sptr<AudioRecord>>& GetProcessedAudioRecordCache()
    {
        return processedAudioRecordCache_;
    }

    bool GetBufferArrivalFinished_()
    {
        return isBufferArrivalFinished_;
    }

    inline sptr<AudioCapturerSession>& GetAudioCaptureSession()
    {
        return audioCapturerSession_;
    }

    inline std::map<int32_t, int64_t>& GetCurrentCaptureIdToTimeMap()
    {
        return curCaptureIdToTimeMap_;
    }

    BlockingQueue<sptr<AudioRecord>>& GetArrivalAudioBufferQueue()
    {
        return arrivalAudioBufferQueue_;
    }

    bool GetIsBufferArrivalFinished()
    {
        return isBufferArrivalFinished_.load();
    }

    void SetIsBufferArrivalFinished(bool value)
    {
        isBufferArrivalFinished_.store(value);
    }

    std::atomic<bool> isAllFinished_ = false;
    std::mutex mutex_;
    std::mutex audioCacheMutex_;
    std::mutex captureIdToTimMutex_;

private:
    uint32_t timerId_ = 0;
    sptr<AudioCapturerSession> audioCapturerSession_ = nullptr;
    std::mutex audioProcessManagerMutex_;
    std::mutex audioTaskManagerMutex_;
    shared_ptr<TaskManager> audioProcessTaskManager_ = nullptr;
    shared_ptr<TaskManager> audioRecordProcessManager_ = nullptr;
    std::atomic<bool> isAudioTaskActive_ { true };
    BlockingQueue<sptr<AudioRecord>> arrivalAudioBufferQueue_;
    std::condition_variable arrivalVarible_;
    std::map<int32_t, int64_t> curCaptureIdToTimeMap_;
    std::atomic<bool> isBufferArrivalFinished_ = true;
    vector<sptr<AudioRecord>> processedAudioRecordCache_;
};

} // CameraStandard
} // OHOS
#endif // CAMERA_FRAMEWORK_LIVEPHOTO_GENERATOR_H