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

#include "moving_photo_manager.h"
#include "ability/camera_ability_const.h"
#include "camera_log.h"
#include "photo_asset_interface.h"
#include "audio_session_manager.h"
#include "moving_photo_video_cache.h"
#include "moving_photo_adapter.h"

namespace OHOS::CameraStandard {

void MovingPhotoResource::SetXtStyleType(VideoType type)
{
    auto livephotoListener = livephotoListener_;
    CHECK_EXECUTE(livephotoListener, livephotoListener->SetXtStyleType(type));
}

void MovingPhotoResource::StartOnceRecord(uint64_t timestamp, int32_t rotation, int32_t captureId)
{
    CHECK_RETURN_ELOG(!livephotoListener_, "StartOnceRecord livephotoListener_ is null");
    CHECK_RETURN_ELOG(!avcodecTaskManagerProxy_, "StartOnceRecord avcodecTaskManagerProxy_ is null");
    std::vector<sptr<FrameRecord>> frameCacheList;
    sptr<SessionDrainImageCallback> imageCallback = new SessionDrainImageCallback(frameCacheList,
        livephotoListener_, movingPhotoVideoCache_, timestamp, rotation, captureId);
    livephotoListener_->ClearCache(timestamp);
    avcodecTaskManagerProxy_->RecordVideoType(captureId, livephotoListener_->GetXtStyleType());
    livephotoListener_->DrainOutImage(imageCallback);
}

void MovingPhotoResource::InsertStartTime(int32_t captureId, int64_t startTimeStamp)
{
    auto avcodecTaskManager = avcodecTaskManagerProxy_;
    CHECK_RETURN_ELOG(avcodecTaskManager == nullptr, "avcodecTaskManager is nullptr.");
    avcodecTaskManager->TaskManagerInsertStartTime(captureId, startTimeStamp);
}

void MovingPhotoResource::InsertEndTime(int32_t captureId, int64_t endTimeStamp)
{
    auto avcodecTaskManager = avcodecTaskManagerProxy_;
    CHECK_RETURN_ELOG(avcodecTaskManager == nullptr, "avcodecTaskManager is nullptr.");
    avcodecTaskManager->TaskManagerInsertEndTime(captureId, endTimeStamp);
}

void MovingPhotoResource::SetClearFlag()
{
    auto livephotoListener = livephotoListener_;
    CHECK_EXECUTE(livephotoListener, livephotoListener->SetClearFlag());
}

void MovingPhotoResource::StopDrainOut()
{
    auto livephotoListener = livephotoListener_;
    CHECK_EXECUTE(livephotoListener, livephotoListener->StopDrainOut());
}

void MovingPhotoResource::SetVideoFd(int64_t timestamp, std::shared_ptr<PhotoAssetIntf> photoAsset, int32_t captureId)
{
    auto avcodecTaskManager = avcodecTaskManagerProxy_;
    CHECK_RETURN_ELOG(avcodecTaskManager == nullptr, "avcodecTaskManager is nullptr.");
    avcodecTaskManager->SetVideoFd(timestamp, photoAsset, captureId);
}

void MovingPhotoResource::CreateMovingPhotoVideoCache()
{
    CHECK_RETURN_ELOG(movingPhotoVideoCache_ != nullptr, "video cache already exists");
    sptr<AvcodecTaskManagerProxy> avcodecTaskManagerProxy =
        static_cast<AvcodecTaskManagerProxy*>(avcodecTaskManagerProxy_.GetRefPtr());
    CHECK_RETURN_ELOG(avcodecTaskManagerProxy == nullptr, "avcodec task manager proxy is null");
    sptr<AvcodecTaskManagerAdapter> avcodecTaskManagerAdapter =
        static_cast<AvcodecTaskManagerAdapter*>(avcodecTaskManagerProxy->GetTaskManagerAdapter().GetRefPtr());
    CHECK_RETURN_ELOG(avcodecTaskManagerAdapter == nullptr, "avcodec task manager adapter is null");
    movingPhotoVideoCache_ = new MovingPhotoVideoCache(avcodecTaskManagerAdapter->GetTaskManager());
}

MovingPhotoManager::MovingPhotoManager()
{
    MEDIA_INFO_LOG("MovingPhotoManager ctor is callled");
}
 
MovingPhotoManager::~MovingPhotoManager()
{
    MEDIA_INFO_LOG("MovingPhotoManager dtor is callled");
}

void MovingPhotoManager::StartAudioCapture()
{
    MEDIA_DEBUG_LOG("MovingPhotoManager::StartAudioCapture is callled");
    std::lock_guard<std::mutex> lock(movingPhotoStatusLock_);
    CHECK_EXECUTE(audioCapturerSessionProxy_, audioCapturerSessionProxy_->StartAudioCapture());
}

void MovingPhotoManager::SetVideoFd(
    int64_t timestamp, std::shared_ptr<PhotoAssetIntf> photoAssetProxy, int32_t captureId)
{
    MEDIA_DEBUG_LOG("MovingPhotoManager::SetVideoFd is callled");
    movingPhotoResource_.SetVideoFd(timestamp, photoAssetProxy, captureId);
    xtStyleMovingPhotoResource_.SetVideoFd(timestamp, photoAssetProxy, captureId);
}

void MovingPhotoManager::ReleaseStreamStruct(VideoType videoType)
{
    MEDIA_DEBUG_LOG("MovingPhotoManager::ReleaseStreamStruct is callled");
    auto& streamStruct = GetMovingPhotoResource(videoType);
    std::lock_guard<std::mutex> lock(GetLock(videoType));
    streamStruct.livephotoListener_ = nullptr;
    streamStruct.livephotoMetaListener_ = nullptr;
    streamStruct.movingPhotoVideoCache_ = nullptr;
}

void MovingPhotoManager::ChangeListenerSetXtStyleType(bool isXtStyleEnabled)
{
    MEDIA_DEBUG_LOG("MovingPhotoManager::ChangeListenerSetXtStyleType is callled");
    CHECK_EXECUTE(isXtStyleEnabled, movingPhotoResource_.SetXtStyleType(VideoType::XT_EFFECT_VIDEO));
    CHECK_EXECUTE(isXtStyleEnabled, xtStyleMovingPhotoResource_.SetXtStyleType(VideoType::XT_ORIGIN_VIDEO));
    CHECK_EXECUTE(!isXtStyleEnabled, movingPhotoResource_.SetXtStyleType(VideoType::ORIGIN_VIDEO));
}

void MovingPhotoManager::StartRecord(uint64_t timestamp, int32_t rotation, int32_t captureId,
    ColorStylePhotoType colorStylePhotoType, bool isXtStyleEnabled)
{
    MEDIA_DEBUG_LOG("MovingPhotoManager::StartRecord is callled");
    CHECK_RETURN(movingPhotoResource_.avcodecTaskManagerProxy_ == nullptr);
    CHECK_EXECUTE(colorStylePhotoType == ORIGIN_AND_EFFECT,
        movingPhotoResource_.avcodecTaskManagerProxy_->SetMutexMap(timestamp));
    // LCOV_EXCL_START
    auto weakThis = wptr<MovingPhotoManager>(this);
    movingPhotoResource_.avcodecTaskManagerProxy_->SubmitTask([weakThis, timestamp, rotation, captureId]() {
        auto manager = weakThis.promote();
        CHECK_RETURN(!manager);
        manager->StartOnceRecord(timestamp, rotation, captureId, ORIGIN_VIDEO);
    });
    CHECK_RETURN(colorStylePhotoType != ORIGIN_AND_EFFECT || !isXtStyleEnabled ||
        !xtStyleMovingPhotoResource_.avcodecTaskManagerProxy_);
    xtStyleMovingPhotoResource_.avcodecTaskManagerProxy_->SubmitTask([weakThis, timestamp, rotation, captureId]() {
        auto manager = weakThis.promote();
        CHECK_RETURN(!manager);
        manager->StartOnceRecord(timestamp, rotation, captureId, XT_ORIGIN_VIDEO);
    });
}

void MovingPhotoManager::StartOnceRecord(uint64_t timestamp, int32_t rotation, int32_t captureId, VideoType videoType)
{
    MEDIA_DEBUG_LOG("MovingPhotoManager::StartOnceRecord is callled");
    // frameCacheList only used by now thread
    auto& streamStruct = GetMovingPhotoResource(videoType);
    std::lock_guard<std::mutex> lock(GetLock(videoType));
    streamStruct.StartOnceRecord(timestamp, rotation, captureId);
    MEDIA_INFO_LOG("StartOnceRecord END");
}

void MovingPhotoManager::InsertStartTime(int32_t captureId, int64_t startTimeStamp)
{
    MEDIA_DEBUG_LOG("MovingPhotoManager::InsertStartTime is callled");
    std::lock_guard<std::mutex> statusLock(movingPhotoStatusLock_);
    movingPhotoResource_.InsertStartTime(captureId, startTimeStamp);
}

void MovingPhotoManager::InsertEndTime(int32_t captureId, int64_t endTimeStamp)
{
    MEDIA_DEBUG_LOG("MovingPhotoManager::InsertEndTime is callled");
    std::lock_guard<std::mutex> statusLock(movingPhotoStatusLock_);
    movingPhotoResource_.InsertEndTime(captureId, endTimeStamp);
}

void MovingPhotoManager::SetClearFlag()
{
    MEDIA_DEBUG_LOG("MovingPhotoManager::SetClearFlag is callled");
    {
        std::lock_guard<std::mutex> lock(movingPhotoStatusLock_);
        movingPhotoResource_.SetClearFlag();
    }
    {
        std::lock_guard<std::mutex> lock(xtStyleMovingPhotoStatusLock_);
        xtStyleMovingPhotoResource_.SetClearFlag();
    }
}

void MovingPhotoManager::SetDeferredVideoEnhanceFlag(int32_t captureId, uint32_t deferredFlag, std::string videoId,
    ColorStylePhotoType colorStylePhotoType, bool isXtStyleEnabled)
{
    MEDIA_DEBUG_LOG("MovingPhotoManager::SetDeferredVideoEnhanceFlag is callled");
    CHECK_RETURN_ELOG(movingPhotoResource_.avcodecTaskManagerProxy_ == nullptr,
        "Set DeferredVideoEnhanceFlag callback taskManager_ is null");
    movingPhotoResource_.avcodecTaskManagerProxy_->SetDeferredVideoEnhanceFlag(captureId, deferredFlag);
    movingPhotoResource_.avcodecTaskManagerProxy_->SetVideoId(captureId, videoId);
    if (colorStylePhotoType == ORIGIN_AND_EFFECT && isXtStyleEnabled) {
        CHECK_RETURN_ELOG(xtStyleMovingPhotoResource_.avcodecTaskManagerProxy_ == nullptr,
            "Set DeferredVideoEnhanceFlag callback xtStyleTaskManager_ is null");
        xtStyleMovingPhotoResource_.avcodecTaskManagerProxy_->SetDeferredVideoEnhanceFlag(captureId, deferredFlag);
        xtStyleMovingPhotoResource_.avcodecTaskManagerProxy_->SetVideoId(captureId, videoId);
    }
}

void MovingPhotoManager::Release()
{
    MEDIA_DEBUG_LOG("MovingPhotoManager::Release is callled");
    {
        std::lock_guard<std::mutex> lock(movingPhotoStatusLock_);
        movingPhotoResource_ = {};
    }
    {
        std::lock_guard<std::mutex> lock(xtStyleMovingPhotoStatusLock_);
        xtStyleMovingPhotoResource_ = {};
    }
}

void MovingPhotoManager::StopMovingPhoto(VideoType type)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("MovingPhotoManager::StopMovingPhoto is callled");
    std::lock_guard<std::mutex> lock(movingPhotoStatusLock_);
    movingPhotoResource_.StopDrainOut();
    CHECK_PRINT_ILOG(!audioCapturerSessionProxy_, "audioCapturerSessionProxy_ is nullptr");
    auto audioCaptureSessionProxy = sptr<AudioCapturerSessionIntf>(audioCapturerSessionProxy_);
    std::thread asyncAudioReleaseThread = thread([audioCaptureSessionProxy]() {
        CHECK_EXECUTE(audioCaptureSessionProxy, audioCaptureSessionProxy->StopAudioCapture());
    });
    asyncAudioReleaseThread.detach();
    AudioStandard::AudioSessionManager::GetInstance()->DeactivateAudioSession();
    CHECK_EXECUTE((type == VideoType::ORIGIN_VIDEO || type == VideoType::XT_ORIGIN_VIDEO),
        xtStyleMovingPhotoResource_.StopDrainOut());
}

uint32_t Duration2FrameCount(uint32_t duration)
{
    constexpr int32_t MILLSEC_MULTIPLE = 1000;
    return static_cast<uint32_t>(float(duration) / MILLSEC_MULTIPLE * VIDEO_FRAME_RATE);
}

void MovingPhotoManager::SetBufferDuration(uint32_t preBufferDuration, uint32_t postBufferDuration)
{
    MEDIA_DEBUG_LOG("MovingPhotoManager::SetBufferDuration is callled");
    preCacheFrameCount_ = preBufferDuration == 0 ? preCacheFrameCount_ : Duration2FrameCount(preBufferDuration);
    postCacheFrameCount_ = preBufferDuration == 0 ? postCacheFrameCount_ : Duration2FrameCount(postBufferDuration);
    MEDIA_INFO_LOG(
        "MovingPhotoManager::SetBufferDuration preBufferDuration : %{public}u, "
        "postBufferDuration : %{public}u, preCacheFrameCount_ : %{public}u, postCacheFrameCount_ : %{public}u",
        preBufferDuration, postBufferDuration, preCacheFrameCount_, postCacheFrameCount_);
}

void MovingPhotoManager::SetBrotherListener()
{
    MEDIA_DEBUG_LOG("MovingPhotoManager::SetBrotherListener is callled");
    auto aListener = xtStyleMovingPhotoResource_.livephotoListener_;
    auto bListener = movingPhotoResource_.livephotoListener_;
    CHECK_RETURN(aListener == nullptr || bListener == nullptr);
    aListener->SetBrotherListener(bListener);
    bListener->SetBrotherListener(aListener);
}

void MovingPhotoManager::ExpandMovingPhoto(VideoType videoType, int32_t width, int32_t height, ColorSpace colorspace,
    sptr<Surface> videoSurface, sptr<Surface> metaSurface, sptr<AvcodecTaskManagerIntf>& avcodecTaskManager)
{
    MEDIA_DEBUG_LOG("MovingPhotoManager::ExpandMovingPhoto is callled");
    auto& streamStruct = GetMovingPhotoResource(videoType);
    std::lock_guard<std::mutex> lock(GetLock(videoType));
    auto surfaceWrapper = MovingPhotoSurfaceWrapper::CreateMovingPhotoSurfaceWrapper(videoSurface, width, height);
    CHECK_RETURN_ELOG(surfaceWrapper == nullptr,
        "HStreamOperator::ExpandMovingPhotoRepeatStream CreateMovingPhotoSurfaceWrapper fail.");
    CHECK_RETURN_ELOG(metaSurface == nullptr, "metaSurface is nullptr");
    auto metaCache = make_shared<FixedSizeList<pair<int64_t, sptr<SurfaceBuffer>>>>(8);
    streamStruct.livephotoListener_ = new (std::nothrow) MovingPhotoListener(surfaceWrapper,
        metaSurface, metaCache, preCacheFrameCount_, postCacheFrameCount_, videoType);
    CHECK_RETURN_ELOG(streamStruct.livephotoListener_ == nullptr, "failed to new livephotoListener_!");
    surfaceWrapper->SetSurfaceBufferListener(streamStruct.livephotoListener_);
    sptr<MovingPhotoMetaListener> metaListener = new(std::nothrow) MovingPhotoMetaListener(
        metaSurface, metaCache, streamStruct.livephotoListener_);
    streamStruct.livephotoMetaListener_ = metaListener;
    CHECK_RETURN_ELOG(metaListener == nullptr, "failed to new livephotoMetaListener_!");
    metaSurface->RegisterConsumerListener((sptr<IBufferConsumerListener> &)metaListener);
    if (!audioCapturerSessionProxy_) {
        audioCapturerSessionProxy_ = AudioCapturerSessionProxy::CreateAudioCapturerSessionProxy();
        CHECK_EXECUTE(audioCapturerSessionProxy_, audioCapturerSessionProxy_->CreateAudioSession());
    }
    bool isExec = !streamStruct.avcodecTaskManagerProxy_ && audioCapturerSessionProxy_;
    if (isExec) {
        shared_ptr<Size> size = std::make_shared<Size>();
        size->width = static_cast<uint32_t>(width);
        size->height = static_cast<uint32_t>(height);
        avcodecTaskManager = AvcodecTaskManagerProxy::CreateAvcodecTaskManagerProxy();
        avcodecTaskManager->CreateAvcodecTaskManager(videoSurface,
            size, audioCapturerSessionProxy_, VideoCodecType::VIDEO_ENCODE_TYPE_HEVC, colorspace);
        avcodecTaskManager->SetVideoBufferDuration(preCacheFrameCount_, postCacheFrameCount_);
        streamStruct.avcodecTaskManagerProxy_ = avcodecTaskManager;
    }
    streamStruct.CreateMovingPhotoVideoCache();
}
}