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
#include <iomanip>
#include <mutex>
#include "moving_photo_proxy.h"
#include "utils/camera_log.h"

namespace OHOS {
namespace CameraStandard {
typedef AvcodecTaskManagerIntf* (*CreateAVCodecTaskManagerIntf)();
typedef AudioCapturerSessionIntf* (*CreateAudioCapturerSessionIntf)();
typedef MovingPhotoVideoCacheIntf* (*CreateMovingPhotoVideoCacheIntf)();

AvcodecTaskManagerProxy::AvcodecTaskManagerProxy(
    std::shared_ptr<Dynamiclib> avcodecTaskManagerLib, sptr<AvcodecTaskManagerIntf> avcodecTaskManagerIntf)
    : avcodecTaskManagerLib_(avcodecTaskManagerLib), avcodecTaskManagerIntf_(avcodecTaskManagerIntf)
{
    MEDIA_DEBUG_LOG("AvcodecTaskManagerProxy constructor");
    CHECK_RETURN_ELOG(avcodecTaskManagerLib_ == nullptr, "avcodecTaskManagerLib_ is nullptr");
    CHECK_RETURN_ELOG(avcodecTaskManagerIntf_ == nullptr, "avcodecTaskManagerIntf_ is nullptr");
}

AvcodecTaskManagerProxy::~AvcodecTaskManagerProxy()
{
    MEDIA_DEBUG_LOG("AvcodecTaskManagerProxy destructor");
}

sptr<AvcodecTaskManagerProxy> AvcodecTaskManagerProxy::CreateAvcodecTaskManagerProxy()
{
    std::shared_ptr<Dynamiclib> dynamiclib = CameraDynamicLoader::GetDynamiclib(MOVING_PHOTO_SO);
    CHECK_RETURN_RET_ELOG(dynamiclib == nullptr, nullptr, "Failed to load moving photo library");
    CreateAVCodecTaskManagerIntf createAVCodecTaskManagerIntf =
        (CreateAVCodecTaskManagerIntf)dynamiclib->GetFunction("createAVCodecTaskManagerIntf");
    CHECK_RETURN_RET_ELOG(
        createAVCodecTaskManagerIntf == nullptr, nullptr, "Failed to get createAVCodecTaskManagerIntf function");
    AvcodecTaskManagerIntf* avcodecTaskManagerIntf = createAVCodecTaskManagerIntf();
    CHECK_RETURN_RET_ELOG(
        avcodecTaskManagerIntf == nullptr, nullptr, "Failed to create AvcodecTaskManagerIntf instance");
    sptr<AvcodecTaskManagerProxy> aVCodecTaskManagerProxy =
        new AvcodecTaskManagerProxy(dynamiclib, sptr<AvcodecTaskManagerIntf>(avcodecTaskManagerIntf));
    return aVCodecTaskManagerProxy;
}

int32_t AvcodecTaskManagerProxy::CreateAvcodecTaskManager(sptr<AudioCapturerSessionIntf> audioCapturerSessionIntf,
    VideoCodecType type, int32_t colorSpace)
{
    MEDIA_DEBUG_LOG("CreateAvcodecTaskManager start, type: %{public}d, colorSpace: %{public}d",
        static_cast<int32_t>(type), colorSpace);
    CHECK_RETURN_RET_ELOG(audioCapturerSessionIntf == nullptr, -1, "audioCapturerSessionIntf is nullptr");
    CHECK_RETURN_RET_ELOG(avcodecTaskManagerIntf_ == nullptr, -1, "avcodecTaskManagerIntf_ is nullptr");
    sptr<AudioCapturerSessionProxy> audioCapturerSessionProxy =
        static_cast<AudioCapturerSessionProxy*>(audioCapturerSessionIntf.GetRefPtr());
    CHECK_RETURN_RET_ELOG(audioCapturerSessionProxy == nullptr, -1, "audioCapturerSessionProxy is nullptr");
    return avcodecTaskManagerIntf_->CreateAvcodecTaskManager(
        audioCapturerSessionProxy->GetAudioCapturerSessionAdapter(), type, colorSpace);
}

void AvcodecTaskManagerProxy::SetVideoBufferDuration(uint32_t preBufferCount, uint32_t postBufferCount)
{
    MEDIA_DEBUG_LOG("SetVideoBufferDuration start, preBufferCount: %{public}u, postBufferCount: %{public}u",
        preBufferCount, postBufferCount);
    CHECK_RETURN_ELOG(avcodecTaskManagerIntf_ == nullptr, "avcodecTaskManagerIntf_ is nullptr");
    avcodecTaskManagerIntf_->SetVideoBufferDuration(preBufferCount, postBufferCount);
}

void AvcodecTaskManagerProxy::SetVideoFd(int64_t timestamp, std::shared_ptr<PhotoAssetIntf> photoAssetProxy,
    int32_t captureId)
{
    MEDIA_DEBUG_LOG("SetVideoFd start, timestamp: %{public}" PRIu64 ", captureId: %{public}d",
        timestamp, captureId);
    CHECK_RETURN_ELOG(avcodecTaskManagerIntf_ == nullptr, "avcodecTaskManagerIntf_ is nullptr");
    avcodecTaskManagerIntf_->SetVideoFd(timestamp, photoAssetProxy, captureId);
}

void AvcodecTaskManagerProxy::SubmitTask(std::function<void()> task)
{
    MEDIA_DEBUG_LOG("SubmitTask start");
    CHECK_RETURN_ELOG(avcodecTaskManagerIntf_ == nullptr, "avcodecTaskManagerIntf_ is nullptr");
    avcodecTaskManagerIntf_->SubmitTask(task);
}

void AvcodecTaskManagerProxy::EncodeVideoBuffer(sptr<FrameRecord> frameRecord, CacheCbFunc cacheCallback)
{
    MEDIA_DEBUG_LOG("EncodeVideoBuffer start");
    CHECK_RETURN_ELOG(avcodecTaskManagerIntf_ == nullptr, "avcodecTaskManagerIntf_ is nullptr");
    avcodecTaskManagerIntf_->EncodeVideoBuffer(frameRecord, cacheCallback);
}

void AvcodecTaskManagerProxy::DoMuxerVideo(std::vector<sptr<FrameRecord>> frameRecords, uint64_t taskName,
    int32_t rotation, int32_t captureId)
{
    MEDIA_DEBUG_LOG("DoMuxerVideo start, taskName: %{public}" PRIu64 ", rotation: %{public}d, captureId: %{public}d",
        taskName, rotation, captureId);
    CHECK_RETURN_ELOG(avcodecTaskManagerIntf_ == nullptr, "avcodecTaskManagerIntf_ is nullptr");
    avcodecTaskManagerIntf_->DoMuxerVideo(frameRecords, taskName, rotation, captureId);
}

bool AvcodecTaskManagerProxy::isEmptyVideoFdMap()
{
    MEDIA_DEBUG_LOG("isEmptyVideoFdMap start");
    CHECK_RETURN_RET_ELOG(avcodecTaskManagerIntf_ == nullptr, true, "avcodecTaskManagerIntf_ is nullptr");
    bool result = avcodecTaskManagerIntf_->isEmptyVideoFdMap();
    MEDIA_DEBUG_LOG("isEmptyVideoFdMap success, result: %{public}d", result);
    return result;
}

bool AvcodecTaskManagerProxy::TaskManagerInsertStartTime(int32_t captureId, int64_t startTimeStamp)
{
    MEDIA_DEBUG_LOG("TaskManagerInsertStartTime start, captureId: %{public}d, startTimeStamp: %{public}" PRIu64,
        captureId, startTimeStamp);
    CHECK_RETURN_RET_ELOG(avcodecTaskManagerIntf_ == nullptr, false, "avcodecTaskManagerIntf_ is nullptr");
    return avcodecTaskManagerIntf_->TaskManagerInsertStartTime(captureId, startTimeStamp);
}

bool AvcodecTaskManagerProxy::TaskManagerInsertEndTime(int32_t captureId, int64_t endTimeStamp)
{
    MEDIA_DEBUG_LOG("TaskManagerInsertEndTime start, captureId: %{public}d, endTimeStamp: %{public}" PRIu64,
        captureId, endTimeStamp);
    CHECK_RETURN_RET_ELOG(avcodecTaskManagerIntf_ == nullptr, false, "avcodecTaskManagerIntf_ is nullptr");
    return avcodecTaskManagerIntf_->TaskManagerInsertEndTime(captureId, endTimeStamp);
}

sptr<AvcodecTaskManagerIntf> AvcodecTaskManagerProxy::GetTaskManagerAdapter() const
{
    return avcodecTaskManagerIntf_;
}

AudioCapturerSessionProxy::AudioCapturerSessionProxy(
    std::shared_ptr<Dynamiclib> audioCapturerSessionLib, sptr<AudioCapturerSessionIntf> audioCapturerSessionIntf)
    : audioCapturerSessionLib_(audioCapturerSessionLib), audioCapturerSessionIntf_(audioCapturerSessionIntf)
{
    MEDIA_DEBUG_LOG("AudioCapturerSessionProxy constructor");
    CHECK_RETURN_ELOG(audioCapturerSessionLib_ == nullptr, "audioCapturerSessionLib_ is nullptr");
    CHECK_RETURN_ELOG(audioCapturerSessionIntf_ == nullptr, "audioCapturerSessionIntf_ is nullptr");
}

AudioCapturerSessionProxy::~AudioCapturerSessionProxy()
{
    MEDIA_DEBUG_LOG("AudioCapturerSessionProxy destructor");
}

sptr<AudioCapturerSessionProxy> AudioCapturerSessionProxy::CreateAudioCapturerSessionProxy()
{
    std::shared_ptr<Dynamiclib> dynamiclib = CameraDynamicLoader::GetDynamiclib(MOVING_PHOTO_SO);
    CHECK_RETURN_RET_ELOG(dynamiclib == nullptr, nullptr, "Failed to load moving photo library");

    CreateAudioCapturerSessionIntf createAudioCapturerSessionIntf =
        (CreateAudioCapturerSessionIntf)dynamiclib->GetFunction("createAudioCapturerSessionIntf");
    CHECK_RETURN_RET_ELOG(
        createAudioCapturerSessionIntf == nullptr, nullptr, "Failed to get createAudioCapturerSessionIntf function");

    AudioCapturerSessionIntf* audioCapturerSessionIntf = createAudioCapturerSessionIntf();
    CHECK_RETURN_RET_ELOG(
        audioCapturerSessionIntf == nullptr, nullptr, "Failed to create AudioCapturerSessionIntf instance");

    sptr<AudioCapturerSessionProxy> audioCapturerSessionProxy =
        new AudioCapturerSessionProxy(dynamiclib, sptr<AudioCapturerSessionIntf>(audioCapturerSessionIntf));
    return audioCapturerSessionProxy;
}

int32_t AudioCapturerSessionProxy::CreateAudioSession()
{
    MEDIA_DEBUG_LOG("CreateAudioSession start");
    CHECK_RETURN_RET_ELOG(audioCapturerSessionIntf_ == nullptr, -1, "audioCapturerSessionIntf_ is nullptr");
    return audioCapturerSessionIntf_->CreateAudioSession();
}

bool AudioCapturerSessionProxy::StartAudioCapture()
{
    MEDIA_DEBUG_LOG("StartAudioCapture start");
    CHECK_RETURN_RET_ELOG(audioCapturerSessionIntf_ == nullptr, false, "audioCapturerSessionIntf_ is nullptr");
    bool result = audioCapturerSessionIntf_->StartAudioCapture();
    MEDIA_DEBUG_LOG("StartAudioCapture success, result: %{public}d", result);
    return result;
}

void AudioCapturerSessionProxy::StopAudioCapture()
{
    MEDIA_DEBUG_LOG("StopAudioCapture start");
    std::lock_guard<std::mutex> lock(audioCaptureLock_);
    CHECK_RETURN_ELOG(audioCapturerSessionIntf_ == nullptr, "audioCapturerSessionIntf_ is nullptr");
    audioCapturerSessionIntf_->StopAudioCapture();
}

sptr<AudioCapturerSessionIntf> AudioCapturerSessionProxy::GetAudioCapturerSessionAdapter() const
{
    return audioCapturerSessionIntf_;
}

MovingPhotoVideoCacheProxy::MovingPhotoVideoCacheProxy(
    std::shared_ptr<Dynamiclib> movingPhotoVideoCacheLib, sptr<MovingPhotoVideoCacheIntf> movingPhotoVideoCacheIntf)
    : movingPhotoVideoCacheLib_(movingPhotoVideoCacheLib), movingPhotoVideoCacheIntf_(movingPhotoVideoCacheIntf)
{
    MEDIA_DEBUG_LOG("MovingPhotoVideoCacheProxy constructor");
    CHECK_RETURN_ELOG(movingPhotoVideoCacheLib_ == nullptr, "movingPhotoVideoCacheLib_ is nullptr");
    CHECK_RETURN_ELOG(movingPhotoVideoCacheIntf_ == nullptr, "movingPhotoVideoCacheIntf_ is nullptr");
}

MovingPhotoVideoCacheProxy::~MovingPhotoVideoCacheProxy()
{
    MEDIA_DEBUG_LOG("MovingPhotoVideoCacheProxy destructor");
}

sptr<MovingPhotoVideoCacheProxy> MovingPhotoVideoCacheProxy::CreateMovingPhotoVideoCacheProxy()
{
    std::shared_ptr<Dynamiclib> dynamiclib = CameraDynamicLoader::GetDynamiclib(MOVING_PHOTO_SO);
    CHECK_RETURN_RET_ELOG(dynamiclib == nullptr, nullptr, "Failed to load moving photo library");

    CreateMovingPhotoVideoCacheIntf createMovingPhotoVideoCacheIntf =
        (CreateMovingPhotoVideoCacheIntf)dynamiclib->GetFunction("createMovingPhotoVideoCacheIntf");
    CHECK_RETURN_RET_ELOG(createMovingPhotoVideoCacheIntf == nullptr, nullptr,
        "Failed to get createMovingPhotoVideoCacheIntf function");
    MovingPhotoVideoCacheIntf* movingPhotoVideoCacheIntf = createMovingPhotoVideoCacheIntf();
    CHECK_RETURN_RET_ELOG(
        movingPhotoVideoCacheIntf == nullptr, nullptr, "Failed to create MovingPhotoVideoCacheIntf instance");
    sptr<MovingPhotoVideoCacheProxy> movingPhotoVideoCacheProxy =
        new MovingPhotoVideoCacheProxy(dynamiclib, sptr<MovingPhotoVideoCacheIntf>(movingPhotoVideoCacheIntf));
    return movingPhotoVideoCacheProxy;
}

int32_t MovingPhotoVideoCacheProxy::CreateMovingPhotoVideoCache(sptr<AvcodecTaskManagerIntf> avcodecTaskManagerIntf)
{
    MEDIA_DEBUG_LOG("CreateMovingPhotoVideoCache start");
    CHECK_RETURN_RET_ELOG(avcodecTaskManagerIntf == nullptr, -1, "avcodecTaskManagerIntf is nullptr");
    CHECK_RETURN_RET_ELOG(movingPhotoVideoCacheIntf_ == nullptr, -1, "movingPhotoVideoCacheIntf_ is nullptr");
    sptr<AvcodecTaskManagerProxy> avcodecTaskManagerProxy =
        static_cast<AvcodecTaskManagerProxy*>(avcodecTaskManagerIntf.GetRefPtr());
    CHECK_RETURN_RET_ELOG(avcodecTaskManagerProxy == nullptr, -1, "avcodecTaskManagerProxy is nullptr");
    return movingPhotoVideoCacheIntf_->CreateMovingPhotoVideoCache(avcodecTaskManagerProxy->GetTaskManagerAdapter());
}

void MovingPhotoVideoCacheProxy::OnDrainFrameRecord(sptr<FrameRecord> frame)
{
    MEDIA_DEBUG_LOG("OnDrainFrameRecord start");
    CHECK_RETURN_ELOG(movingPhotoVideoCacheIntf_ == nullptr, "movingPhotoVideoCacheIntf_ is nullptr");
    movingPhotoVideoCacheIntf_->OnDrainFrameRecord(frame);
}

void MovingPhotoVideoCacheProxy::GetFrameCachedResult(std::vector<sptr<FrameRecord>> frameRecords,
    uint64_t taskName, int32_t rotation, int32_t captureId)
{
    MEDIA_DEBUG_LOG("GetFrameCachedResult start");
    CHECK_RETURN_ELOG(movingPhotoVideoCacheIntf_ == nullptr, "movingPhotoVideoCacheIntf_ is nullptr");
    movingPhotoVideoCacheIntf_->GetFrameCachedResult(frameRecords, taskName, rotation, captureId);
}
} // namespace CameraStandard
} // namespace OHOS