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
    CHECK_RETURN_RET_ELOG(audioCapturerSessionIntf == nullptr, -1, "audioCapturerSessionIntf is nullptr");
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
}

void AvcodecTaskManagerAdapter::SetVideoFd(
    int64_t timestamp, std::shared_ptr<PhotoAssetIntf> photoAssetProxy, int32_t captureId)
{
    MEDIA_DEBUG_LOG("SetVideoFd start, timestamp: %{public}" PRIu64 ", captureId: %{public}d",
        timestamp, captureId);
    CHECK_RETURN_ELOG(avcodecTaskManager_ == nullptr, "AvcodecTaskManager not created");
    avcodecTaskManager_->SetVideoFd(timestamp, photoAssetProxy, captureId);
}

uint32_t AvcodecTaskManagerAdapter::GetDeferredVideoEnhanceFlag(int32_t captureId)
{
    MEDIA_DEBUG_LOG("GetDeferredVideoEnhanceFlag start, captureId: %{public}d", captureId);
    CHECK_RETURN_RET_ELOG(avcodecTaskManager_ == nullptr, 0, "AvcodecTaskManager not created");
    auto flag = avcodecTaskManager_->GetDeferredVideoEnhanceFlag(captureId);
    return flag;
}

void AvcodecTaskManagerAdapter::SetDeferredVideoEnhanceFlag(int32_t captureId, uint32_t deferredVideoEnhanceFlag)
{
    MEDIA_DEBUG_LOG("SetDeferredVideoEnhanceFlag start, captureId: %{public}d, deferredVideoEnhanceFlag: %{public}d",
        captureId, deferredVideoEnhanceFlag);
    CHECK_RETURN_ELOG(avcodecTaskManager_ == nullptr, "AvcodecTaskManager not created");
    avcodecTaskManager_->SetDeferredVideoEnhanceFlag(captureId, deferredVideoEnhanceFlag);
}

void AvcodecTaskManagerAdapter::SetVideoId(int32_t captureId, std::string videoId)
{
    MEDIA_DEBUG_LOG("SetDeferredVideoEnhanceFlag start, captureId: %{public}d", captureId);
    CHECK_RETURN_ELOG(avcodecTaskManager_ == nullptr, "AvcodecTaskManager not created");
    avcodecTaskManager_->SetVideoId(captureId, videoId);
}

void AvcodecTaskManagerAdapter::SubmitTask(std::function<void()> task)
{
    MEDIA_DEBUG_LOG("SubmitTask start");
    CHECK_RETURN_ELOG(avcodecTaskManager_ == nullptr, "AvcodecTaskManager not created");
    avcodecTaskManager_->SubmitTask(task);
}

bool AvcodecTaskManagerAdapter::isEmptyVideoFdMap()
{
    MEDIA_DEBUG_LOG("isEmptyVideoFdMap start");
    CHECK_RETURN_RET_ELOG(avcodecTaskManager_ == nullptr, true, "AvcodecTaskManager not created");
    return avcodecTaskManager_->isEmptyVideoFdMap();
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
    if (avcodecTaskManager_->mPEndTimeMap_.count(captureId) == 0) {
        MEDIA_INFO_LOG("Save moving photo end info, captureId : %{public}d, end timestamp : %{public}" PRIu64,
            captureId, endTimeStamp);
        avcodecTaskManager_->mPEndTimeMap_.insert(make_pair(captureId, endTimeStamp));
    }
    return true;
}

void AvcodecTaskManagerAdapter::SetMutexMap(int64_t timestamp)
{
    auto curMutex = std::make_shared<std::mutex>();
    AvcodecTaskManager::mutexMap_.EnsureInsert(timestamp, curMutex);
}

void AvcodecTaskManagerAdapter::RecordVideoType(int32_t captureId, VideoType type)
{
    MEDIA_DEBUG_LOG("RecordVideoType start, captureId: %{public}d %{public}d", captureId, static_cast<int32_t>(type));
    CHECK_RETURN_ELOG(avcodecTaskManager_ == nullptr, "RecordVideoType taskManager_ is null");
    avcodecTaskManager_->RecordVideoType(captureId, type);
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
    return audioCapturerSession_->StartAudioCapture();
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

MovingPhotoManagerAdapter::MovingPhotoManagerAdapter()
{
    MEDIA_DEBUG_LOG("MovingPhotoManagerAdapter ctor is called");
    movingPhotoManager_ = new MovingPhotoManager();
}

MovingPhotoManagerAdapter::~MovingPhotoManagerAdapter()
{
    MEDIA_DEBUG_LOG("MovingPhotoManagerAdapter dtor is called");
}

void MovingPhotoManagerAdapter::StartAudioCapture()
{
    CHECK_RETURN_ELOG(movingPhotoManager_ == nullptr, "movingPhotoManager_ is null");
    movingPhotoManager_->StartAudioCapture();
}

void MovingPhotoManagerAdapter::SetVideoFd(
    int64_t timestamp, std::shared_ptr<PhotoAssetIntf> photoAssetProxy, int32_t captureId)
{
    CHECK_RETURN_ELOG(movingPhotoManager_ == nullptr, "movingPhotoManager_ is null");
    movingPhotoManager_->SetVideoFd(timestamp, photoAssetProxy, captureId);
}

void MovingPhotoManagerAdapter::ExpandMovingPhoto(
    VideoType videoType, int32_t width, int32_t height, ColorSpace colorspace,
    sptr<Surface> videoSurface, sptr<Surface> metaSurface, sptr<AvcodecTaskManagerIntf>& avcodecTaskManager)
{
    CHECK_RETURN_ELOG(movingPhotoManager_ == nullptr, "movingPhotoManager_ is null");
    movingPhotoManager_->ExpandMovingPhoto(
        videoType, width, height, colorspace, videoSurface, metaSurface, avcodecTaskManager);
}

void MovingPhotoManagerAdapter::SetBrotherListener()
{
    CHECK_RETURN_ELOG(movingPhotoManager_ == nullptr, "movingPhotoManager_ is null");
    movingPhotoManager_->SetBrotherListener();
}

void MovingPhotoManagerAdapter::SetBufferDuration(uint32_t preBufferDuration, uint32_t postBufferDuration)
{
    CHECK_RETURN_ELOG(movingPhotoManager_ == nullptr, "movingPhotoManager_ is null");
    movingPhotoManager_->SetBufferDuration(preBufferDuration, postBufferDuration);
}

void MovingPhotoManagerAdapter::ReleaseStreamStruct(VideoType videoType)
{
    CHECK_RETURN_ELOG(movingPhotoManager_ == nullptr, "movingPhotoManager_ is null");
    movingPhotoManager_->ReleaseStreamStruct(videoType);
}

void MovingPhotoManagerAdapter::StopMovingPhoto(VideoType type)
{
    CHECK_RETURN_ELOG(movingPhotoManager_ == nullptr, "movingPhotoManager_ is null");
    movingPhotoManager_->StopMovingPhoto(type);
}

void MovingPhotoManagerAdapter::ChangeListenerSetXtStyleType(bool isXtStyleEnabled)
{
    CHECK_RETURN_ELOG(movingPhotoManager_ == nullptr, "movingPhotoManager_ is null");
    movingPhotoManager_->ChangeListenerSetXtStyleType(isXtStyleEnabled);
}

void MovingPhotoManagerAdapter::StartRecord(uint64_t timestamp, int32_t rotation, int32_t captureId,
    ColorStylePhotoType colorStylePhotoType, bool isXtStyleEnabled)
{
    CHECK_RETURN_ELOG(movingPhotoManager_ == nullptr, "movingPhotoManager_ is null");
    movingPhotoManager_->StartRecord(timestamp, rotation, captureId, colorStylePhotoType, isXtStyleEnabled);
}

void MovingPhotoManagerAdapter::InsertStartTime(int32_t captureId, int64_t startTimeStamp)
{
    CHECK_RETURN_ELOG(movingPhotoManager_ == nullptr, "movingPhotoManager_ is null");
    movingPhotoManager_->InsertStartTime(captureId, startTimeStamp);
}

void MovingPhotoManagerAdapter::InsertEndTime(int32_t captureId, int64_t endTimeStamp)
{
    CHECK_RETURN_ELOG(movingPhotoManager_ == nullptr, "movingPhotoManager_ is null");
    movingPhotoManager_->InsertEndTime(captureId, endTimeStamp);
}

void MovingPhotoManagerAdapter::SetClearFlag()
{
    CHECK_RETURN_ELOG(movingPhotoManager_ == nullptr, "movingPhotoManager_ is null");
    movingPhotoManager_->SetClearFlag();
}

void MovingPhotoManagerAdapter::SetDeferredVideoEnhanceFlag(int32_t captureId, uint32_t flag, std::string videoId,
    ColorStylePhotoType colorStylePhotoType, bool isXtStyleEnabled)
{
    CHECK_RETURN_ELOG(movingPhotoManager_ == nullptr, "movingPhotoManager_ is null");
    movingPhotoManager_->SetDeferredVideoEnhanceFlag(captureId, flag, videoId, colorStylePhotoType, isXtStyleEnabled);
}

void MovingPhotoManagerAdapter::Release()
{
    CHECK_RETURN_ELOG(movingPhotoManager_ == nullptr, "movingPhotoManager_ is null");
    movingPhotoManager_->Release();
}

extern "C" AvcodecTaskManagerIntf *createAvcodecTaskManagerIntf()
{
    return new AvcodecTaskManagerAdapter();
}

extern "C" AudioCapturerSessionIntf *createAudioCapturerSessionIntf()
{
    return new AudioCapturerSessionAdapter();
}

extern "C" MovingPhotoManagerIntf *createMovingPhotoManagerIntf()
{
    return new MovingPhotoManagerAdapter();
}
} // namespace CameraStandard
} // namespace OHOS