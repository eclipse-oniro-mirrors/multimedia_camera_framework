/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "moving_photo_adapter.h"
#include "frame_record.h"
#include "camera_log.h"
#include "fixed_size_list.h"
#include "audio_capturer_session.h"
#include "avcodec_task_manager.h"
#include "moving_photo_video_cache.h"
#include "camera_util.h"
#include "icapture_session.h"

namespace OHOS {
namespace CameraStandard {
AvcodecTaskManagerAdapter::AvcodecTaskManagerAdapter()
{
    MEDIA_DEBUG_LOG("AvcodecTaskManagerAdapter constructor");
}

AvcodecTaskManagerAdapter::~AvcodecTaskManagerAdapter()
{
    MEDIA_DEBUG_LOG("AvcodecTaskManagerAdapter destructor");
}

int32_t AvcodecTaskManagerAdapter::CreateAvcodecTaskManager(sptr<AudioCapturerSessionIntf> audioCapturerSessionIntf,
    VideoCodecType type, int32_t colorSpace)
{
    MEDIA_DEBUG_LOG("CreateAvcodecTaskManager start, type: %{public}d, colorSpace: %{public}d",
        static_cast<int32_t>(type), colorSpace);
    CHECK_RETURN_RET_ELOG(audioCapturerSessionIntf == nullptr, -1, "AudioCapturerSessionIntf is null");
    sptr<AudioCapturerSessionAdapter> captureSessionAdapter =
        static_cast<AudioCapturerSessionAdapter*>(audioCapturerSessionIntf.GetRefPtr());
    CHECK_RETURN_RET_ELOG(captureSessionAdapter == nullptr, -1, "captureSessionAdapter is nullptr");
    sptr<AudioCapturerSession> audioCaptureSession = captureSessionAdapter->GetCapturerSession();
    CHECK_RETURN_RET_ELOG(audioCaptureSession == nullptr, -1, "audioCaptureSession is nullptr");
    avcodecTaskManager_ = new AvcodecTaskManager(audioCaptureSession, type, static_cast<ColorSpace>(colorSpace));
    CHECK_RETURN_RET_ELOG(avcodecTaskManager_ == nullptr, -1, "CreateAvcodecTaskManager failed");
    return 0;
}

int32_t AvcodecTaskManagerAdapter::CreateAvcodecTaskManager(wptr<Surface> movingSurface, shared_ptr<Size> size,
    sptr<AudioCapturerSessionIntf> audioCapturerSessionIntf, VideoCodecType type, int32_t colorSpace)
{
    MEDIA_DEBUG_LOG("CreateAvcodecTaskManager start, type: %{public}d, colorSpace: %{public}d",
        static_cast<int32_t>(type), colorSpace);
    CHECK_RETURN_RET_ELOG(audioCapturerSessionIntf == nullptr, -1, "audioCapturerSessionIntf is nullptr");
    sptr<AudioCapturerSessionAdapter> captureSessionAdapter =
        static_cast<AudioCapturerSessionAdapter*>(audioCapturerSessionIntf.GetRefPtr());
    CHECK_RETURN_RET_ELOG(captureSessionAdapter == nullptr, -1, "captureSessionAdapter is nullptr");
    sptr<AudioCapturerSession> audioCaptureSession = captureSessionAdapter->GetCapturerSession();
    CHECK_RETURN_RET_ELOG(audioCaptureSession == nullptr, -1, "audioCaptureSession is nullptr");
    avcodecTaskManager_ =
        new AvcodecTaskManager(movingSurface, size, audioCaptureSession, type, static_cast<ColorSpace>(colorSpace));
    CHECK_RETURN_RET_ELOG(avcodecTaskManager_ == nullptr, -1, "CreateAvcodecTaskManager failed");
    avcodecTaskManager_->AsyncInitVideoCodec();
    return 0;
}

void AvcodecTaskManagerAdapter::SetVideoBufferDuration(uint32_t preBufferCount, uint32_t postBufferCount)
{
    MEDIA_DEBUG_LOG("SetVideoBufferDuration start, preBufferCount: %{public}u, postBufferCount: %{public}u",
        preBufferCount, postBufferCount);
    CHECK_RETURN_ELOG(avcodecTaskManager_ == nullptr, "AvcodecTaskManager not created");
    avcodecTaskManager_->SetVideoBufferDuration(preBufferCount, postBufferCount);
    MEDIA_DEBUG_LOG("SetVideoBufferDuration success");
}

void AvcodecTaskManagerAdapter::SetVideoFd(
    int64_t timestamp, std::shared_ptr<PhotoAssetIntf> photoAssetProxy, int32_t captureId)
{
    MEDIA_DEBUG_LOG("SetVideoFd start, timestamp: %{public}" PRIu64 ", captureId: %{public}d",
        timestamp, captureId);
    CHECK_RETURN_ELOG(avcodecTaskManager_ == nullptr, "AvcodecTaskManager not created");
    avcodecTaskManager_->SetVideoFd(timestamp, photoAssetProxy, captureId);
}

void AvcodecTaskManagerAdapter::SubmitTask(std::function<void()> task)
{
    MEDIA_DEBUG_LOG("SubmitTask start");
    CHECK_RETURN_ELOG(avcodecTaskManager_ == nullptr, "AvcodecTaskManager not created");
    avcodecTaskManager_->SubmitTask(task);
}

void AvcodecTaskManagerAdapter::EncodeVideoBuffer(sptr<FrameRecord> frameRecord, CacheCbFunc cacheCallback)
{
    MEDIA_DEBUG_LOG("EncodeVideoBuffer start, frameId: %{public}s",
        frameRecord->GetFrameId().c_str());
    CHECK_RETURN_ELOG(avcodecTaskManager_ == nullptr, "AvcodecTaskManager not created");
    avcodecTaskManager_->EncodeVideoBuffer(frameRecord, cacheCallback);
}

void AvcodecTaskManagerAdapter::DoMuxerVideo(std::vector<sptr<FrameRecord>> frameRecords, uint64_t taskName,
    int32_t rotation, int32_t captureId)
{
    MEDIA_DEBUG_LOG("DoMuxerVideo start, taskName: %{public}" PRIu64 ", rotation: %{public}d, captureId: %{public}d",
        taskName, rotation, captureId);
    CHECK_RETURN_ELOG(avcodecTaskManager_ == nullptr, "AvcodecTaskManager not created");
    avcodecTaskManager_->DoMuxerVideo(frameRecords, taskName, rotation, captureId);
}

bool AvcodecTaskManagerAdapter::isEmptyVideoFdMap()
{
    MEDIA_DEBUG_LOG("isEmptyVideoFdMap start");
    CHECK_RETURN_RET_ELOG(avcodecTaskManager_ == nullptr, true, "AvcodecTaskManager not created");
    bool isEmpty = avcodecTaskManager_->isEmptyVideoFdMap();
    MEDIA_DEBUG_LOG("isEmptyVideoFdMap success, isEmpty: %{public}d", isEmpty);
    return isEmpty;
}

bool AvcodecTaskManagerAdapter::TaskManagerInsertStartTime(int32_t captureId, int64_t startTimeStamp)
{
    MEDIA_DEBUG_LOG("TaskManagerInsertStartTime start, captureId: %{public}d, startTimeStamp: %{public}" PRIu64,
        captureId, startTimeStamp);
    CHECK_RETURN_RET_ELOG(avcodecTaskManager_ == nullptr, false, "Set start time callback taskManager_ is null");
    std::lock_guard<mutex> lock(avcodecTaskManager_->startTimeMutex_);
    if (avcodecTaskManager_->mPStartTimeMap_.count(captureId) == 0) {
        MEDIA_INFO_LOG("Save moving photo start info, captureId : %{public}d, start timestamp : %{public}" PRIu64,
            captureId, startTimeStamp);
        avcodecTaskManager_->mPStartTimeMap_.insert(make_pair(captureId, startTimeStamp));
    }
    return true;
}

bool AvcodecTaskManagerAdapter::TaskManagerInsertEndTime(int32_t captureId, int64_t endTimeStamp)
{
    MEDIA_DEBUG_LOG("TaskManagerInsertEndTime start, captureId: %{public}d, endTimeStamp: %{public}" PRIu64,
        captureId, endTimeStamp);
    CHECK_RETURN_RET_ELOG(avcodecTaskManager_ == nullptr, false, "Set end time callback taskManager_ is null");
    std::lock_guard<mutex> lock(avcodecTaskManager_->endTimeMutex_);
    if (avcodecTaskManager_->mPEndTimeMap_.count(captureId) != 0) {
        MEDIA_INFO_LOG("Save moving photo end info, captureId : %{public}d, end timestamp : %{public}" PRIu64,
            captureId, endTimeStamp);
        avcodecTaskManager_->mPEndTimeMap_.insert(make_pair(captureId, endTimeStamp));
    }
    return true;
}

sptr<AvcodecTaskManager> AvcodecTaskManagerAdapter::GetTaskManager() const
{
    return avcodecTaskManager_;
}

AudioCapturerSessionAdapter::AudioCapturerSessionAdapter()
{
    MEDIA_DEBUG_LOG("AudioCapturerSessionAdapter constructor");
}

AudioCapturerSessionAdapter::~AudioCapturerSessionAdapter()
{
    MEDIA_DEBUG_LOG("AudioCapturerSessionAdapter destructor");
}

int32_t AudioCapturerSessionAdapter::CreateAudioSession()
{
    MEDIA_DEBUG_LOG("CreateAudioSession start");
    audioCapturerSession_ = new AudioCapturerSession();
    CHECK_RETURN_RET_ELOG(audioCapturerSession_ == nullptr, -1, "CreateAudioSession failed");
    return 0;
}

bool AudioCapturerSessionAdapter::StartAudioCapture()
{
    MEDIA_DEBUG_LOG("StartAudioCapture start");
    CHECK_RETURN_RET_ELOG(audioCapturerSession_ == nullptr, false, "AudioCapturerSession not created");
    bool result = audioCapturerSession_->StartAudioCapture();
    MEDIA_DEBUG_LOG("StartAudioCapture success, result: %{public}d", result);
    return result;
}

void AudioCapturerSessionAdapter::StopAudioCapture()
{
    MEDIA_DEBUG_LOG("StopAudioCapture start");
    CHECK_RETURN_ELOG(audioCapturerSession_ == nullptr, "AudioCapturerSession not created");
    audioCapturerSession_->Stop();
}

sptr<AudioCapturerSession> AudioCapturerSessionAdapter::GetCapturerSession() const
{
    return audioCapturerSession_;
}

MovingPhotoVideoCacheAdapter::MovingPhotoVideoCacheAdapter()
{
    MEDIA_DEBUG_LOG("MovingPhotoVideoCacheAdapter constructor");
}

MovingPhotoVideoCacheAdapter::~MovingPhotoVideoCacheAdapter()
{
    MEDIA_DEBUG_LOG("MovingPhotoVideoCacheAdapter destructor");
}

int32_t MovingPhotoVideoCacheAdapter::CreateMovingPhotoVideoCache(sptr<AvcodecTaskManagerIntf> avcodecTaskManagerIntf)
{
    MEDIA_DEBUG_LOG("CreateMovingPhotoVideoCache start");
    CHECK_RETURN_RET_ELOG(avcodecTaskManagerIntf == nullptr, -1, "AvcodecTaskManagerIntf is null");
    sptr<AvcodecTaskManagerAdapter> avcodecTaskManagerAdapter =
        static_cast<AvcodecTaskManagerAdapter*>(avcodecTaskManagerIntf.GetRefPtr());
    CHECK_RETURN_RET_ELOG(avcodecTaskManagerAdapter == nullptr, -1, "AvcodecTaskManagerAdapter is null");
    movingPhotoVideoCache_ = new MovingPhotoVideoCache(avcodecTaskManagerAdapter->GetTaskManager());
    CHECK_RETURN_RET_ELOG(movingPhotoVideoCache_ == nullptr, -1, "CreateMovingPhotoVideoCache failed");
    videoCache_ = movingPhotoVideoCache_;
    return 0;
}

void MovingPhotoVideoCacheAdapter::OnDrainFrameRecord(sptr<FrameRecord> frame)
{
    MEDIA_DEBUG_LOG("OnDrainFrameRecord start");
    CHECK_RETURN_ELOG(frame == nullptr, "FrameRecord is null");
    CHECK_RETURN_ELOG(videoCache_ == nullptr, "CreateMovingPhotoVideoCache failed");
    auto videoCache = videoCache_.promote();
    if (frame->IsIdle() && videoCache) {
        videoCache->CacheFrame(frame);
    } else if (frame->IsFinishCache() && videoCache) {
        videoCache->OnImageEncoded(frame, frame->IsEncoded());
    } else if (frame->IsReadyConvert()) {
        MEDIA_DEBUG_LOG("frame is ready convert");
    } else {
        MEDIA_INFO_LOG("videoCache and frame is not useful");
    }
}

void MovingPhotoVideoCacheAdapter::GetFrameCachedResult(std::vector<sptr<FrameRecord>> frameRecords,
    uint64_t taskName, int32_t rotation, int32_t captureId)
{
    MEDIA_DEBUG_LOG("GetFrameCachedResult start");
    CHECK_RETURN_ELOG(videoCache_ == nullptr, "CreateMovingPhotoVideoCache failed");
    auto videoCache = videoCache_.promote();
    if (videoCache) {
        videoCache_->GetFrameCachedResult(
            frameRecords,
            [videoCache](const std::vector<sptr<FrameRecord>> &lframeRecords, uint64_t ltimestamp, int32_t lrotation,
                         int32_t lcaptureId) {
                            videoCache->DoMuxerVideo(lframeRecords, ltimestamp, lrotation, lcaptureId);
                        },
            taskName,
            rotation,
            captureId);
    }
}

extern "C" AvcodecTaskManagerIntf *createAVCodecTaskManagerIntf()
{
    return new AvcodecTaskManagerAdapter();
}

extern "C" AudioCapturerSessionIntf *createAudioCapturerSessionIntf()
{
    return new AudioCapturerSessionAdapter();
}

extern "C" MovingPhotoVideoCacheIntf *createMovingPhotoVideoCacheIntf()
{
    return new MovingPhotoVideoCacheAdapter();
}
} // namespace CameraStandard
} // namespace OHOS