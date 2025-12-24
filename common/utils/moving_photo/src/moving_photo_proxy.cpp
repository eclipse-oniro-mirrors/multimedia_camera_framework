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
#include "photo_asset_interface.h"
#include "utils/camera_log.h"

namespace OHOS {
namespace CameraStandard {
using CreateAvcodecTaskManagerIntf = AvcodecTaskManagerIntf*(*)();
using CreateAudioCapturerSessionIntf = AudioCapturerSessionIntf*(*)();
using CreateMovingPhotoManagerIntf = MovingPhotoManagerIntf*(*)();

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
    MEDIA_DEBUG_LOG("CreateAvcodecTaskManagerProxy start");
    std::shared_ptr<Dynamiclib> dynamiclib = CameraDynamicLoader::GetDynamiclib(MOVING_PHOTO_SO);
    CHECK_RETURN_RET_ELOG(dynamiclib == nullptr, nullptr, "Failed to load moving photo library");
    CreateAvcodecTaskManagerIntf createAvcodecTaskManagerIntf =
        (CreateAvcodecTaskManagerIntf)dynamiclib->GetFunction("createAvcodecTaskManagerIntf");
    CHECK_RETURN_RET_ELOG(
        createAvcodecTaskManagerIntf == nullptr, nullptr, "Failed to get createAvcodecTaskManagerIntf function");
    AvcodecTaskManagerIntf* avcodecTaskManagerIntf = createAvcodecTaskManagerIntf();
    CHECK_RETURN_RET_ELOG(
        avcodecTaskManagerIntf == nullptr, nullptr, "Failed to create AvcodecTaskManagerIntf instance");
    sptr<AvcodecTaskManagerProxy> avcodecTaskManagerProxy =
        new AvcodecTaskManagerProxy(dynamiclib, sptr<AvcodecTaskManagerIntf>(avcodecTaskManagerIntf));
    return avcodecTaskManagerProxy;
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

int32_t AvcodecTaskManagerProxy::CreateAvcodecTaskManager(wptr<Surface> movingSurface, shared_ptr<Size> size,
    sptr<AudioCapturerSessionIntf> audioCapturerSessionIntf, VideoCodecType type, int32_t colorSpace)
{
    MEDIA_DEBUG_LOG("CreateAvcodecTaskManager start, type: %{public}d, colorSpace: %{public}d",
        static_cast<int32_t>(type), colorSpace);
    CHECK_RETURN_RET_ELOG(audioCapturerSessionIntf == nullptr, -1, "audioCapturerSessionIntf is nullptr");
    CHECK_RETURN_RET_ELOG(avcodecTaskManagerIntf_ == nullptr, -1, "avcodecTaskManagerIntf_ is nullptr");
    sptr<AudioCapturerSessionProxy> audioCapturerSessionProxy =
        static_cast<AudioCapturerSessionProxy*>(audioCapturerSessionIntf.GetRefPtr());
    CHECK_RETURN_RET_ELOG(audioCapturerSessionProxy == nullptr, -1, "audioCapturerSessionProxy is nullptr");
    return avcodecTaskManagerIntf_->CreateAvcodecTaskManager(movingSurface, size,
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

uint32_t AvcodecTaskManagerProxy::GetDeferredVideoEnhanceFlag(int32_t captureId)
{
    MEDIA_DEBUG_LOG("GetDeferredVideoEnhanceFlag start, captureId: %{public}d", captureId);
    CHECK_RETURN_RET_ELOG(avcodecTaskManagerIntf_ == nullptr, 0, "avcodecTaskManagerIntf_ is nullptr");
    return avcodecTaskManagerIntf_->GetDeferredVideoEnhanceFlag(captureId);
}

void AvcodecTaskManagerProxy::SetDeferredVideoEnhanceFlag(int32_t captureId, uint32_t deferredVideoEnhanceFlag)
{
    MEDIA_DEBUG_LOG("SetDeferredVideoEnhanceFlag start, captureId: %{public}d, deferredVideoEnhanceFlag: %{public}d",
        captureId, deferredVideoEnhanceFlag);
    CHECK_RETURN_ELOG(avcodecTaskManagerIntf_ == nullptr, "avcodecTaskManagerIntf_ is nullptr");
    avcodecTaskManagerIntf_->SetDeferredVideoEnhanceFlag(captureId, deferredVideoEnhanceFlag);
}

void AvcodecTaskManagerProxy::SetVideoId(int32_t captureId, std::string videoId)
{
    MEDIA_DEBUG_LOG("SetDeferredVideoEnhanceFlag start, captureId: %{public}d", captureId);
    CHECK_RETURN_ELOG(avcodecTaskManagerIntf_ == nullptr, "avcodecTaskManagerIntf_ is nullptr");
    avcodecTaskManagerIntf_->SetVideoId(captureId, videoId);
}

void AvcodecTaskManagerProxy::SubmitTask(std::function<void()> task)
{
    MEDIA_DEBUG_LOG("SubmitTask start");
    CHECK_RETURN_ELOG(avcodecTaskManagerIntf_ == nullptr, "avcodecTaskManagerIntf_ is nullptr");
    avcodecTaskManagerIntf_->SubmitTask(task);
}

bool AvcodecTaskManagerProxy::isEmptyVideoFdMap()
{
    MEDIA_DEBUG_LOG("isEmptyVideoFdMap start");
    CHECK_RETURN_RET_ELOG(avcodecTaskManagerIntf_ == nullptr, true, "avcodecTaskManagerIntf_ is nullptr");
    return avcodecTaskManagerIntf_->isEmptyVideoFdMap();
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

void AvcodecTaskManagerProxy::SetMutexMap(int64_t timestamp)
{
    MEDIA_DEBUG_LOG("SetMutexMap start, timestamp: %{public} " PRId64, timestamp);
    CHECK_RETURN_ELOG(avcodecTaskManagerIntf_ == nullptr, "avcodecTaskManagerIntf_ is nullptr");
    return avcodecTaskManagerIntf_->SetMutexMap(timestamp);
}

void AvcodecTaskManagerProxy::RecordVideoType(int32_t captureId, VideoType type)
{
    MEDIA_DEBUG_LOG("RecordVideoType start, captureId: %{public}d %{public}d", captureId, static_cast<int32_t>(type));
    CHECK_RETURN_ELOG(avcodecTaskManagerIntf_ == nullptr, "avcodecTaskManagerIntf_ is nullptr");
    return avcodecTaskManagerIntf_->RecordVideoType(captureId, type);
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
    MEDIA_DEBUG_LOG("CreateAudioCapturerSessionProxy start");
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
    return audioCapturerSessionIntf_->StartAudioCapture();
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

MovingPhotoManagerProxy::MovingPhotoManagerProxy(
    std::shared_ptr<Dynamiclib> movingPhotoManagerLib, sptr<MovingPhotoManagerIntf> movingPhotoManagerIntf)
    : movingPhotoManagerLib_(movingPhotoManagerLib), movingPhotoManagerIntf_(movingPhotoManagerIntf)
{
    MEDIA_DEBUG_LOG("MovingPhotoManagerProxy ctor is called");
}

MovingPhotoManagerProxy::~MovingPhotoManagerProxy()
{
    MEDIA_DEBUG_LOG("MovingPhotoManagerProxy dtor is called");
}

sptr<MovingPhotoManagerProxy> MovingPhotoManagerProxy::CreateMovingPhotoManagerProxy()
{
    MEDIA_DEBUG_LOG("CreateMovingPhotoManagerProxy is called");
    std::shared_ptr<Dynamiclib> dynamiclib = CameraDynamicLoader::GetDynamiclib(MOVING_PHOTO_SO);
    CHECK_RETURN_RET_ELOG(dynamiclib == nullptr, nullptr, "Failed to load moving photo library");
    CreateMovingPhotoManagerIntf createMovingPhotoManagerIntf =
        (CreateMovingPhotoManagerIntf)dynamiclib->GetFunction("createMovingPhotoManagerIntf");
    CHECK_RETURN_RET_ELOG(createMovingPhotoManagerIntf == nullptr, nullptr, "createMovingPhotoManagerIntf is null");
    MovingPhotoManagerIntf* movingPhotoManagerIntf = createMovingPhotoManagerIntf();
    CHECK_RETURN_RET_ELOG(movingPhotoManagerIntf == nullptr, nullptr, "movingPhotoManagerIntf is null");
    return sptr<MovingPhotoManagerProxy>::MakeSptr(dynamiclib, sptr<MovingPhotoManagerIntf>(movingPhotoManagerIntf));
}

void MovingPhotoManagerProxy::FreeMovingPhotoManagerDynamiclib()
{
    constexpr uint32_t delayMs = 60 * 1000; // 60 second
    CameraDynamicLoader::FreeDynamicLibDelayed(MOVING_PHOTO_SO, delayMs);
}

void MovingPhotoManagerProxy::StartAudioCapture()
{
    CHECK_RETURN_ELOG(movingPhotoManagerIntf_ == nullptr, "movingPhotoManagerIntf_ is nullptr");
    movingPhotoManagerIntf_->StartAudioCapture();
}

void MovingPhotoManagerProxy::SetVideoFd(
    int64_t timestamp, std::shared_ptr<PhotoAssetIntf> photoAssetProxy, int32_t captureId)
{
    CHECK_RETURN_ELOG(movingPhotoManagerIntf_ == nullptr, "movingPhotoManagerIntf_ is nullptr");
    movingPhotoManagerIntf_->SetVideoFd(timestamp, photoAssetProxy, captureId); 
}

void MovingPhotoManagerProxy::ExpandMovingPhoto(
    VideoType videoType, int32_t width, int32_t height, ColorSpace colorspace,
    sptr<Surface> videoSurface, sptr<Surface> metaSurface, sptr<AvcodecTaskManagerIntf>& avcodecTaskManager)
{
    CHECK_RETURN_ELOG(movingPhotoManagerIntf_ == nullptr, "movingPhotoManagerIntf_ is null");
    movingPhotoManagerIntf_->ExpandMovingPhoto(
        videoType, width, height, colorspace, videoSurface, metaSurface, avcodecTaskManager);
}

void MovingPhotoManagerProxy::SetBrotherListener()
{
    CHECK_RETURN_ELOG(movingPhotoManagerIntf_ == nullptr, "movingPhotoManagerIntf_ is null");
    movingPhotoManagerIntf_->SetBrotherListener();
}

void MovingPhotoManagerProxy::SetBufferDuration(uint32_t preBufferDuration, uint32_t postBufferDuration)
{
    CHECK_RETURN_ELOG(movingPhotoManagerIntf_ == nullptr, "movingPhotoManagerIntf_ is null");
    movingPhotoManagerIntf_->SetBufferDuration(preBufferDuration, postBufferDuration);
}

void MovingPhotoManagerProxy::ReleaseStreamStruct(VideoType videoType)
{
    CHECK_RETURN_ELOG(movingPhotoManagerIntf_ == nullptr, "movingPhotoManagerIntf_ is null");
    movingPhotoManagerIntf_->ReleaseStreamStruct(videoType);
}

void MovingPhotoManagerProxy::StopMovingPhoto(VideoType type)
{
    CHECK_RETURN_ELOG(movingPhotoManagerIntf_ == nullptr, "movingPhotoManagerIntf_ is null");
    movingPhotoManagerIntf_->StopMovingPhoto(type);
}

void MovingPhotoManagerProxy::ChangeListenerSetXtStyleType(bool isXtStyleEnabled)
{
    CHECK_RETURN_ELOG(movingPhotoManagerIntf_ == nullptr, "movingPhotoManagerIntf_ is null");
    movingPhotoManagerIntf_->ChangeListenerSetXtStyleType(isXtStyleEnabled);
}

void MovingPhotoManagerProxy::StartRecord(uint64_t timestamp, int32_t rotation, int32_t captureId,
    ColorStylePhotoType colorStylePhotoType, bool isXtStyleEnabled)
{
    CHECK_RETURN_ELOG(movingPhotoManagerIntf_ == nullptr, "movingPhotoManagerIntf_ is null");
    movingPhotoManagerIntf_->StartRecord(timestamp, rotation, captureId, colorStylePhotoType, isXtStyleEnabled);
}

void MovingPhotoManagerProxy::InsertStartTime(int32_t captureId, int64_t startTimeStamp)
{
    CHECK_RETURN_ELOG(movingPhotoManagerIntf_ == nullptr, "movingPhotoManagerIntf_ is null");
    movingPhotoManagerIntf_->InsertStartTime(captureId, startTimeStamp);
}

void MovingPhotoManagerProxy::InsertEndTime(int32_t captureId, int64_t endTimeStamp)
{
    CHECK_RETURN_ELOG(movingPhotoManagerIntf_ == nullptr, "movingPhotoManagerIntf_ is null");
    movingPhotoManagerIntf_->InsertEndTime(captureId, endTimeStamp);
}

void MovingPhotoManagerProxy::SetClearFlag()
{
    CHECK_RETURN_ELOG(movingPhotoManagerIntf_ == nullptr, "movingPhotoManagerIntf_ is null");
    movingPhotoManagerIntf_->SetClearFlag();
}

void MovingPhotoManagerProxy::SetDeferredVideoEnhanceFlag(int32_t captureId, uint32_t deferredFlag, std::string videoId,
    ColorStylePhotoType colorStylePhotoType, bool isXtStyleEnabled)
{
    CHECK_RETURN_ELOG(movingPhotoManagerIntf_ == nullptr, "movingPhotoManagerIntf_ is null");
    movingPhotoManagerIntf_->SetDeferredVideoEnhanceFlag(
        captureId, deferredFlag, videoId, colorStylePhotoType, isXtStyleEnabled);
}

void MovingPhotoManagerProxy::Release()
{
    CHECK_RETURN_ELOG(movingPhotoManagerIntf_ == nullptr, "movingPhotoManagerIntf_ is null");
    movingPhotoManagerIntf_->Release();
}
} // namespace CameraStandard
} // namespace OHOS