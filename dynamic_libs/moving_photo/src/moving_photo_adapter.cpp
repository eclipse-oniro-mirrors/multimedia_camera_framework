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
    CHECK_EXECUTE(cameraServerPhotoProxy_ != nullptr, cameraServerPhotoProxy_ = nullptr);
    CHECK_EXECUTE(avcodecTaskManager_ != nullptr, avcodecTaskManager_ = nullptr);
    CHECK_EXECUTE(audioCapturerSession_ != nullptr, audioCapturerSession_ = nullptr);
    CHECK_EXECUTE(movingPhotoVideoCache_ != nullptr, movingPhotoVideoCache_ = nullptr);
    CHECK_EXECUTE(videoCache_ != nullptr, videoCache_ = nullptr);
}

void MovingPhotoAdapter::CreateCameraServerProxy()
{
    MEDIA_DEBUG_LOG("CreateCameraServerProxy start");
    cameraServerPhotoProxy_ = new CameraServerPhotoProxy();
    CHECK_ERROR_RETURN_LOG(cameraServerPhotoProxy_ == nullptr, "CreateCameraServerProxy failed");
    MEDIA_DEBUG_LOG("CreateCameraServerProxy success");
}

void MovingPhotoAdapter::ReadFromParcel(MessageParcel &parcel)
{
    MEDIA_DEBUG_LOG("ReadFromParcel start");
    CHECK_ERROR_RETURN_LOG(cameraServerPhotoProxy_ == nullptr, "CameraServerPhotoProxy not created");
    cameraServerPhotoProxy_->ReadFromParcel(parcel);
    MEDIA_DEBUG_LOG("ReadFromParcel success");
}

void MovingPhotoAdapter::SetDisplayName(const std::string &displayName)
{
    MEDIA_DEBUG_LOG("SetDisplayName start");
    CHECK_ERROR_RETURN_LOG(cameraServerPhotoProxy_ == nullptr, "CameraServerPhotoProxy not created");
    cameraServerPhotoProxy_->SetDisplayName(displayName);
    MEDIA_DEBUG_LOG("SetDisplayName success");
}

int32_t MovingPhotoAdapter::GetCaptureId() const
{
    MEDIA_DEBUG_LOG("GetCaptureId start");
    CHECK_ERROR_RETURN_RET_LOG(cameraServerPhotoProxy_ == nullptr, 0, "CameraServerPhotoProxy not created");
    int32_t captureId = cameraServerPhotoProxy_->GetCaptureId();
    MEDIA_DEBUG_LOG("GetCaptureId success, captureId: %{public}d", captureId);
    return captureId;
}

void MovingPhotoAdapter::SetShootingMode(int32_t mode)
{
    MEDIA_DEBUG_LOG("SetShootingMode start, mode: %{public}d", mode);
    CHECK_ERROR_RETURN_LOG(cameraServerPhotoProxy_ == nullptr, "CameraServerPhotoProxy not created");
    cameraServerPhotoProxy_->SetShootingMode(mode);
    MEDIA_DEBUG_LOG("SetShootingMode success");
}

std::string MovingPhotoAdapter::GetPhotoId() const
{
    MEDIA_DEBUG_LOG("GetPhotoId start");
    CHECK_ERROR_RETURN_RET_LOG(cameraServerPhotoProxy_ == nullptr, "", "CameraServerPhotoProxy not created");
    std::string photoId = cameraServerPhotoProxy_->GetPhotoId();
    MEDIA_DEBUG_LOG("GetPhotoId success, photoId: %{public}s", photoId.c_str());
    return photoId;
}

int32_t MovingPhotoAdapter::GetBurstSeqId() const
{
    MEDIA_DEBUG_LOG("GetBurstSeqId start");
    CHECK_ERROR_RETURN_RET_LOG(cameraServerPhotoProxy_ == nullptr, -1, "CameraServerPhotoProxy not created");
    int32_t ret = cameraServerPhotoProxy_->GetBurstSeqId();
    MEDIA_DEBUG_LOG("GetBurstSeqId success");
    return ret;
}

void MovingPhotoAdapter::SetBurstInfo(const std::string &burstKey, bool isCoverPhoto)
{
    MEDIA_DEBUG_LOG("SetBurstInfo start, burstKey: %{public}s, isCoverPhoto: %{public}d",
        burstKey.c_str(), isCoverPhoto);
    CHECK_ERROR_RETURN_LOG(cameraServerPhotoProxy_ == nullptr, "CameraServerPhotoProxy not created");
    cameraServerPhotoProxy_->SetBurstInfo(burstKey, isCoverPhoto);
    MEDIA_DEBUG_LOG("SetBurstInfo success");
}

std::string MovingPhotoAdapter::GetTitle() const
{
    MEDIA_DEBUG_LOG("GetTitle start");
    CHECK_ERROR_RETURN_RET_LOG(cameraServerPhotoProxy_ == nullptr, "", "CameraServerPhotoProxy not created");
    std::string title = cameraServerPhotoProxy_->GetTitle();
    MEDIA_DEBUG_LOG("GetTitle success, title: %{public}s", title.c_str());
    return title;
}

std::string MovingPhotoAdapter::GetExtension() const
{
    MEDIA_DEBUG_LOG("GetExtension start");
    CHECK_ERROR_RETURN_RET_LOG(cameraServerPhotoProxy_ == nullptr, "", "CameraServerPhotoProxy not created");
    std::string extension = cameraServerPhotoProxy_->GetExtension();
    MEDIA_DEBUG_LOG("GetExtension success, extension: %{public}s", extension.c_str());
    return extension;
}

PhotoQuality MovingPhotoAdapter::GetPhotoQuality() const
{
    MEDIA_DEBUG_LOG("GetPhotoQuality start");
    CHECK_ERROR_RETURN_RET_LOG(cameraServerPhotoProxy_ == nullptr, PhotoQuality::LOW,
        "CameraServerPhotoProxy not created");
    PhotoQuality quality = cameraServerPhotoProxy_->GetPhotoQuality();
    MEDIA_DEBUG_LOG("GetPhotoQuality success, quality: %{public}d", static_cast<int32_t>(quality));
    return quality;
}

int32_t MovingPhotoAdapter::GetFormat() const
{
    MEDIA_DEBUG_LOG("GetFormat start");
    CHECK_ERROR_RETURN_RET_LOG(cameraServerPhotoProxy_ == nullptr, 0, "CameraServerPhotoProxy not created");
    int32_t format = static_cast<int32_t> (cameraServerPhotoProxy_->GetFormat());
    MEDIA_DEBUG_LOG("GetFormat success, format: %{public}d", format);
    return format;
}

void MovingPhotoAdapter::SetStageVideoTaskStatus(uint8_t status)
{
    MEDIA_DEBUG_LOG("SetStageVideoTaskStatus start, status: %{public}d", status);
    CHECK_ERROR_RETURN_LOG(cameraServerPhotoProxy_ == nullptr, "CameraServerPhotoProxy not created");
    cameraServerPhotoProxy_->SetStageVideoTaskStatus(status);
    MEDIA_DEBUG_LOG("SetStageVideoTaskStatus success");
}

void MovingPhotoAdapter::CreateAvcodecTaskManager(VideoCodecType type, int32_t colorSpace)
{
    MEDIA_DEBUG_LOG("CreateAvcodecTaskManager start, type: %{public}d, colorSpace: %{public}d",
        static_cast<int32_t>(type), colorSpace);
    avcodecTaskManager_ = new AvcodecTaskManager(audioCapturerSession_, type, static_cast<ColorSpace> (colorSpace));
    CHECK_ERROR_RETURN_LOG(avcodecTaskManager_ == nullptr, "CreateAvcodecTaskManager failed");
    MEDIA_DEBUG_LOG("CreateAvcodecTaskManager success");
}

bool MovingPhotoAdapter::IsTaskManagerExist()
{
    MEDIA_DEBUG_LOG("IsTaskManagerExist start");
    CHECK_ERROR_RETURN_RET_LOG(avcodecTaskManager_ == nullptr, false, "avcodecTaskManager_ is nullptr");
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
    CHECK_ERROR_RETURN_LOG(avcodecTaskManager_ == nullptr, "AvcodecTaskManager not created");
    avcodecTaskManager_->SetVideoBufferDuration(preBufferCount, postBufferCount);
    MEDIA_DEBUG_LOG("SetVideoBufferDuration success");
}

void MovingPhotoAdapter::SetVideoFd(
    int64_t timestamp, std::shared_ptr<PhotoAssetIntf> photoAssetProxy, int32_t captureId)
{
    MEDIA_DEBUG_LOG("SetVideoFd start, timestamp: %{public}" PRIu64 ", captureId: %{public}d",
        timestamp, captureId);
    CHECK_ERROR_RETURN_LOG(avcodecTaskManager_ == nullptr, "AvcodecTaskManager not created");
    avcodecTaskManager_->SetVideoFd(timestamp, photoAssetProxy, captureId);
    MEDIA_DEBUG_LOG("SetVideoFd success");
}

void MovingPhotoAdapter::SetLatitude(double latitude)
{
    MEDIA_DEBUG_LOG("SetLatitude start");
    CHECK_ERROR_RETURN_LOG(cameraServerPhotoProxy_ == nullptr, "CameraServerPhotoProxy not created");
    cameraServerPhotoProxy_->SetLatitude(latitude);
    MEDIA_DEBUG_LOG("SetLatitude success");
}

void MovingPhotoAdapter::SetLongitude(double longitude)
{
    MEDIA_DEBUG_LOG("SetLongitude start");
    CHECK_ERROR_RETURN_LOG(cameraServerPhotoProxy_ == nullptr, "CameraServerPhotoProxy not created");
    cameraServerPhotoProxy_->SetLongitude(longitude);
    MEDIA_DEBUG_LOG("SetLongitude success");
}

void MovingPhotoAdapter::GetServerPhotoProxyInfo(sptr<OHOS::SurfaceBuffer>& surfaceBuffer)
{
    MEDIA_DEBUG_LOG("GetServerPhotoProxyInfo start");
    CHECK_ERROR_RETURN_LOG(cameraServerPhotoProxy_ == nullptr, "CameraServerPhotoProxy not created");
    cameraServerPhotoProxy_->GetServerPhotoProxyInfo(surfaceBuffer);
    MEDIA_DEBUG_LOG("GetServerPhotoProxyInfo success");
}

void MovingPhotoAdapter::SetFormat(int32_t format)
{
    MEDIA_DEBUG_LOG("SetFormat start, format: %{public}d", format);
    CHECK_ERROR_RETURN_LOG(cameraServerPhotoProxy_ == nullptr, "CameraServerPhotoProxy not created");
    cameraServerPhotoProxy_->SetFormat(format);
    MEDIA_DEBUG_LOG("SetFormat success");
}

void MovingPhotoAdapter::SetImageFormat(int32_t imageFormat)
{
    MEDIA_DEBUG_LOG("SetImageFormat start, imageFormat: %{public}d", imageFormat);
    CHECK_ERROR_RETURN_LOG(cameraServerPhotoProxy_ == nullptr, "CameraServerPhotoProxy not created");
    cameraServerPhotoProxy_->SetImageFormat(imageFormat);
    MEDIA_DEBUG_LOG("SetImageFormat success");
}

void MovingPhotoAdapter::SetIsVideo(bool isVideo)
{
    MEDIA_DEBUG_LOG("SetIsVideo start, isVideo: %{public}d", isVideo);
    CHECK_ERROR_RETURN_LOG(cameraServerPhotoProxy_ == nullptr, "CameraServerPhotoProxy not created");
    cameraServerPhotoProxy_->SetIsVideo(isVideo);
    MEDIA_DEBUG_LOG("SetIsVideo success");
}

void MovingPhotoAdapter::SubmitTask(std::function<void()> task)
{
    MEDIA_DEBUG_LOG("SubmitTask start");
    CHECK_ERROR_RETURN_LOG(avcodecTaskManager_ == nullptr, "AvcodecTaskManager not created");
    avcodecTaskManager_->SubmitTask(task);
    MEDIA_DEBUG_LOG("SubmitTask success");
}

void MovingPhotoAdapter::EncodeVideoBuffer(sptr<FrameRecord> frameRecord, CacheCbFunc cacheCallback)
{
    MEDIA_DEBUG_LOG("EncodeVideoBuffer start, frameId: %{public}s",
        frameRecord->GetFrameId().c_str());
    CHECK_ERROR_RETURN_LOG(avcodecTaskManager_ == nullptr, "AvcodecTaskManager not created");
    avcodecTaskManager_->EncodeVideoBuffer(frameRecord, cacheCallback);
    MEDIA_DEBUG_LOG("EncodeVideoBuffer success");
}

void MovingPhotoAdapter::DoMuxerVideo(std::vector<sptr<FrameRecord>> frameRecords, uint64_t taskName, int32_t rotation,
    int32_t captureId)
{
    MEDIA_DEBUG_LOG("DoMuxerVideo start, taskName: %{public}" PRIu64 ", rotation: %{public}d, captureId: %{public}d",
        taskName, rotation, captureId);
    CHECK_ERROR_RETURN_LOG(avcodecTaskManager_ == nullptr, "AvcodecTaskManager not created");
    avcodecTaskManager_->DoMuxerVideo(frameRecords, taskName, rotation, captureId);
    MEDIA_DEBUG_LOG("DoMuxerVideo success");
}

bool MovingPhotoAdapter::isEmptyVideoFdMap()
{
    MEDIA_DEBUG_LOG("isEmptyVideoFdMap start");
    CHECK_ERROR_RETURN_RET_LOG(avcodecTaskManager_ == nullptr, true, "AvcodecTaskManager not created");
    bool isEmpty = avcodecTaskManager_->isEmptyVideoFdMap();
    MEDIA_DEBUG_LOG("isEmptyVideoFdMap success, isEmpty: %{public}d", isEmpty);
    return isEmpty;
}

void MovingPhotoAdapter::TaskManagerInsertStartTime(int32_t captureId, int64_t startTimeStamp)
{
    MEDIA_DEBUG_LOG("TaskManagerInsertStartTime start, captureId: %{public}d, startTimeStamp: %{public}" PRIu64,
        captureId, startTimeStamp);
    CHECK_ERROR_RETURN_LOG(
        avcodecTaskManager_ == nullptr, "Set start time callback taskManager_ is null");
    std::lock_guard<mutex> lock(avcodecTaskManager_->startTimeMutex_);
    CHECK_ERROR_RETURN(avcodecTaskManager_->mPStartTimeMap_.count(captureId) != 0);
    MEDIA_INFO_LOG("Save moving photo start info, captureId : %{public}d, start timestamp : %{public}" PRIu64,
        captureId, startTimeStamp);
    avcodecTaskManager_->mPStartTimeMap_.insert(make_pair(captureId, startTimeStamp));
}

void MovingPhotoAdapter::TaskManagerInsertEndTime(int32_t captureId, int64_t endTimeStamp)
{
    MEDIA_DEBUG_LOG("TaskManagerInsertEndTime start, captureId: %{public}d, endTimeStamp: %{public}" PRIu64,
        captureId, endTimeStamp);
    CHECK_ERROR_RETURN_LOG(
        avcodecTaskManager_ == nullptr, "Set end time callback taskManager_ is null");
    std::lock_guard<mutex> lock(avcodecTaskManager_->endTimeMutex_);
    CHECK_ERROR_RETURN(avcodecTaskManager_->mPEndTimeMap_.count(captureId) != 0);
    MEDIA_INFO_LOG("Save moving photo end info, captureId : %{public}d, end timestamp : %{public}" PRIu64,
        captureId, endTimeStamp);
    avcodecTaskManager_->mPEndTimeMap_.insert(make_pair(captureId, endTimeStamp));
}

void MovingPhotoAdapter::CreateAudioSession()
{
    MEDIA_DEBUG_LOG("CreateAudioSession start");
    audioCapturerSession_ = new AudioCapturerSession();
    CHECK_ERROR_RETURN_LOG(audioCapturerSession_ == nullptr, "CreateAudioSession failed");
    MEDIA_DEBUG_LOG("CreateAudioSession success");
}

bool MovingPhotoAdapter::IsAudioSessionExist()
{
    MEDIA_DEBUG_LOG("IsAudioSessionExist start");
    CHECK_ERROR_RETURN_RET_LOG(audioCapturerSession_ == nullptr, false, "audioCapturerSession_ is nullptr");
    return true;
}

bool MovingPhotoAdapter::StartAudioCapture()
{
    MEDIA_DEBUG_LOG("StartAudioCapture start");
    CHECK_ERROR_RETURN_RET_LOG(audioCapturerSession_ == nullptr, false, "AudioCapturerSession not created");
    bool result = audioCapturerSession_->StartAudioCapture();
    MEDIA_DEBUG_LOG("StartAudioCapture success, result: %{public}d", result);
    return result;
}

void MovingPhotoAdapter::StopAudioCapture()
{
    MEDIA_DEBUG_LOG("StopAudioCapture start");
    CHECK_ERROR_RETURN_LOG(audioCapturerSession_ == nullptr, "AudioCapturerSession not created");
    audioCapturerSession_->Stop();
    MEDIA_DEBUG_LOG("StopAudioCapture success");
}

void MovingPhotoAdapter::CreateMovingPhotoVideoCache()
{
    MEDIA_DEBUG_LOG("CreateMovingPhotoVideoCache start");
    movingPhotoVideoCache_ = new MovingPhotoVideoCache(avcodecTaskManager_);
    CHECK_ERROR_RETURN_LOG(movingPhotoVideoCache_ == nullptr, "CreateMovingPhotoVideoCache failed");
    videoCache_ = movingPhotoVideoCache_;
    MEDIA_DEBUG_LOG("CreateMovingPhotoVideoCache success");
}

bool MovingPhotoAdapter::IsVideoCacheExist()
{
    MEDIA_DEBUG_LOG("IsVideoCacheExist start");
    CHECK_ERROR_RETURN_RET_LOG(movingPhotoVideoCache_ == nullptr, false, "movingPhotoVideoCache_ is nullptr");
    return true;
}

void MovingPhotoAdapter::ReleaseVideoCache()
{
    movingPhotoVideoCache_ = nullptr;
}

void MovingPhotoAdapter::OnDrainFrameRecord(sptr<FrameRecord> frame)
{
    MEDIA_DEBUG_LOG("OnDrainFrameRecord start");
    CHECK_ERROR_RETURN_LOG(frame == nullptr, "FrameRecord is null");
    CHECK_ERROR_RETURN_LOG(videoCache_ == nullptr, "CreateMovingPhotoVideoCache failed");
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
    CHECK_ERROR_RETURN_LOG(videoCache_ == nullptr, "CreateMovingPhotoVideoCache failed");
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