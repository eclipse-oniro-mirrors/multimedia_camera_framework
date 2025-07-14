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
#include "audio_capturer_session.h"
#include "frame_record.h"
#include "camera_log.h"
#include "fixed_size_list.h"
#include "audio_capturer_session.h"
#include "avcodec_task_manager.h"
#include "camera_server_photo_proxy.h"
#include "moving_photo_video_cache.h"
#include "camera_util.h"
#include "icapture_session.h"

namespace OHOS {
namespace CameraStandard {
MovingPhotoAdapter::MovingPhotoAdapter()
{
    MEDIA_DEBUG_LOG("MovingPhotoAdapter constructor");
}

MovingPhotoAdapter::~MovingPhotoAdapter()
{
    MEDIA_DEBUG_LOG("MovingPhotoAdapter destructor");
}

void MovingPhotoAdapter::CreateAvcodecTaskManager(VideoCodecType type, int32_t colorSpace)
{
    MEDIA_DEBUG_LOG("CreateAvcodecTaskManager start, type: %{public}d, colorSpace: %{public}d",
        static_cast<int32_t>(type), colorSpace);
    avcodecTaskManager_ = new AvcodecTaskManager(audioCapturerSession_, type, static_cast<ColorSpace> (colorSpace));
    CHECK_RETURN_ELOG(avcodecTaskManager_ == nullptr, "CreateAvcodecTaskManager failed");
    MEDIA_DEBUG_LOG("CreateAvcodecTaskManager success");
}

bool MovingPhotoAdapter::IsTaskManagerExist()
{
    MEDIA_DEBUG_LOG("IsTaskManagerExist start");
    CHECK_RETURN_RET_ELOG(avcodecTaskManager_ == nullptr, false, "avcodecTaskManager_ is nullptr");
    return true;
}

void MovingPhotoAdapter::ReleaseTaskManager()
{
    avcodecTaskManager_ = nullptr;
}

void MovingPhotoAdapter::SetVideoBufferDuration(uint32_t preBufferCount, uint32_t postBufferCount)
{
    MEDIA_DEBUG_LOG("SetVideoBufferDuration start, preBufferCount: %{public}u, postBufferCount: %{public}u",
        preBufferCount, postBufferCount);
    CHECK_RETURN_ELOG(avcodecTaskManager_ == nullptr, "AvcodecTaskManager not created");
    avcodecTaskManager_->SetVideoBufferDuration(preBufferCount, postBufferCount);
    MEDIA_DEBUG_LOG("SetVideoBufferDuration success");
}

void MovingPhotoAdapter::SetVideoFd(
    int64_t timestamp, std::shared_ptr<PhotoAssetIntf> photoAssetProxy, int32_t captureId)
{
    MEDIA_DEBUG_LOG("SetVideoFd start, timestamp: %{public}" PRIu64 ", captureId: %{public}d",
        timestamp, captureId);
    CHECK_RETURN_ELOG(avcodecTaskManager_ == nullptr, "AvcodecTaskManager not created");
    avcodecTaskManager_->SetVideoFd(timestamp, photoAssetProxy, captureId);
    MEDIA_DEBUG_LOG("SetVideoFd success");
}

void MovingPhotoAdapter::SubmitTask(std::function<void()> task)
{
    MEDIA_DEBUG_LOG("SubmitTask start");
    CHECK_RETURN_ELOG(avcodecTaskManager_ == nullptr, "AvcodecTaskManager not created");
    avcodecTaskManager_->SubmitTask(task);
    MEDIA_DEBUG_LOG("SubmitTask success");
}

void MovingPhotoAdapter::EncodeVideoBuffer(sptr<FrameRecord> frameRecord, CacheCbFunc cacheCallback)
{
    MEDIA_DEBUG_LOG("EncodeVideoBuffer start, frameId: %{public}s",
        frameRecord->GetFrameId().c_str());
    CHECK_RETURN_ELOG(avcodecTaskManager_ == nullptr, "AvcodecTaskManager not created");
    avcodecTaskManager_->EncodeVideoBuffer(frameRecord, cacheCallback);
    MEDIA_DEBUG_LOG("EncodeVideoBuffer success");
}

void MovingPhotoAdapter::DoMuxerVideo(std::vector<sptr<FrameRecord>> frameRecords, uint64_t taskName, int32_t rotation,
    int32_t captureId)
{
    MEDIA_DEBUG_LOG("DoMuxerVideo start, taskName: %{public}" PRIu64 ", rotation: %{public}d, captureId: %{public}d",
        taskName, rotation, captureId);
    CHECK_RETURN_ELOG(avcodecTaskManager_ == nullptr, "AvcodecTaskManager not created");
    avcodecTaskManager_->DoMuxerVideo(frameRecords, taskName, rotation, captureId);
    MEDIA_DEBUG_LOG("DoMuxerVideo success");
}

bool MovingPhotoAdapter::isEmptyVideoFdMap()
{
    MEDIA_DEBUG_LOG("isEmptyVideoFdMap start");
    CHECK_RETURN_RET_ELOG(avcodecTaskManager_ == nullptr, true, "AvcodecTaskManager not created");
    bool isEmpty = avcodecTaskManager_->isEmptyVideoFdMap();
    MEDIA_DEBUG_LOG("isEmptyVideoFdMap success, isEmpty: %{public}d", isEmpty);
    return isEmpty;
}

void MovingPhotoAdapter::TaskManagerInsertStartTime(int32_t captureId, int64_t startTimeStamp)
{
    MEDIA_DEBUG_LOG("TaskManagerInsertStartTime start, captureId: %{public}d, startTimeStamp: %{public}" PRIu64,
        captureId, startTimeStamp);
    CHECK_RETURN_ELOG(
        avcodecTaskManager_ == nullptr, "Set start time callback taskManager_ is null");
    std::lock_guard<mutex> lock(avcodecTaskManager_->startTimeMutex_);
    CHECK_RETURN(avcodecTaskManager_->mPStartTimeMap_.count(captureId) != 0);
    MEDIA_INFO_LOG("Save moving photo start info, captureId : %{public}d, start timestamp : %{public}" PRIu64,
        captureId, startTimeStamp);
    avcodecTaskManager_->mPStartTimeMap_.insert(make_pair(captureId, startTimeStamp));
}

void MovingPhotoAdapter::TaskManagerInsertEndTime(int32_t captureId, int64_t endTimeStamp)
{
    MEDIA_DEBUG_LOG("TaskManagerInsertEndTime start, captureId: %{public}d, endTimeStamp: %{public}" PRIu64,
        captureId, endTimeStamp);
    CHECK_RETURN_ELOG(
        avcodecTaskManager_ == nullptr, "Set end time callback taskManager_ is null");
    std::lock_guard<mutex> lock(avcodecTaskManager_->endTimeMutex_);
    CHECK_RETURN(avcodecTaskManager_->mPEndTimeMap_.count(captureId) != 0);
    MEDIA_INFO_LOG("Save moving photo end info, captureId : %{public}d, end timestamp : %{public}" PRIu64,
        captureId, endTimeStamp);
    avcodecTaskManager_->mPEndTimeMap_.insert(make_pair(captureId, endTimeStamp));
}

void MovingPhotoAdapter::CreateAudioSession()
{
    MEDIA_DEBUG_LOG("CreateAudioSession start");
    audioCapturerSession_ = new AudioCapturerSession();
    CHECK_RETURN_ELOG(audioCapturerSession_ == nullptr, "CreateAudioSession failed");
    MEDIA_DEBUG_LOG("CreateAudioSession success");
}

bool MovingPhotoAdapter::IsAudioSessionExist()
{
    MEDIA_DEBUG_LOG("IsAudioSessionExist start");
    CHECK_RETURN_RET_ELOG(audioCapturerSession_ == nullptr, false, "audioCapturerSession_ is nullptr");
    return true;
}

bool MovingPhotoAdapter::StartAudioCapture()
{
    MEDIA_DEBUG_LOG("StartAudioCapture start");
    CHECK_RETURN_RET_ELOG(audioCapturerSession_ == nullptr, false, "AudioCapturerSession not created");
    bool result = audioCapturerSession_->StartAudioCapture();
    MEDIA_DEBUG_LOG("StartAudioCapture success, result: %{public}d", result);
    return result;
}

void MovingPhotoAdapter::StopAudioCapture()
{
    MEDIA_DEBUG_LOG("StopAudioCapture start");
    CHECK_RETURN_ELOG(audioCapturerSession_ == nullptr, "AudioCapturerSession not created");
    audioCapturerSession_->Stop();
    MEDIA_DEBUG_LOG("StopAudioCapture success");
}

void MovingPhotoAdapter::CreateMovingPhotoVideoCache()
{
    MEDIA_DEBUG_LOG("CreateMovingPhotoVideoCache start");
    movingPhotoVideoCache_ = new MovingPhotoVideoCache(avcodecTaskManager_);
    CHECK_RETURN_ELOG(movingPhotoVideoCache_ == nullptr, "CreateMovingPhotoVideoCache failed");
    videoCache_ = movingPhotoVideoCache_;
    MEDIA_DEBUG_LOG("CreateMovingPhotoVideoCache success");
}

bool MovingPhotoAdapter::IsVideoCacheExist()
{
    MEDIA_DEBUG_LOG("IsVideoCacheExist start");
    CHECK_RETURN_RET_ELOG(movingPhotoVideoCache_ == nullptr, false, "movingPhotoVideoCache_ is nullptr");
    return true;
}

void MovingPhotoAdapter::ReleaseVideoCache()
{
    movingPhotoVideoCache_ = nullptr;
}

void MovingPhotoAdapter::OnDrainFrameRecord(sptr<FrameRecord> frame)
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

void MovingPhotoAdapter::GetFrameCachedResult(std::vector<sptr<FrameRecord>> frameRecords,
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

extern "C" MovingPhotoIntf *createMovingPhotoIntf()
{
    return new MovingPhotoAdapter();
}

} // namespace CameraStandard
} // namespace OHOS