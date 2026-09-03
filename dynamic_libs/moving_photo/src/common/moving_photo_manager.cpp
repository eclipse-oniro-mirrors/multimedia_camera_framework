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
#include "moving_photo_warp_grid_surface_wrapper.h"
#include "parameters.h"
#include "moving_photo_lifecycle_manager.h"

namespace OHOS::CameraStandard {

namespace {
constexpr uint32_t PROFILE_INDEX_WIDTH = 2;
constexpr uint32_t PROFILE_INDEX_HEIGHT = 3;
}

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

void MovingPhotoResource::StartStageEisRecord(sptr<DrainImageManager> drainImageManager, int64_t timestamp)
{
    CHECK_RETURN_ELOG(!livephotoListener_, "StartOnceRecord livephotoListener_ is null");
    offlineSessionCallback_->OnDrainCachedVideoBuffer(drainImageManager, timestamp);
}

void MovingPhotoResource::StartProcessAudioTask(int32_t captureId, int64_t middleTimeStamp)
{
    CHECK_EXECUTE(audioTaskManagerProxy_ && middleTimeStamp != 0,
        audioTaskManagerProxy_->ProcessAudioBuffer(captureId, middleTimeStamp));
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

    sptr<AvcodecManualTaskManagerProxy> avcodecManualTaskManagerProxy =
        static_cast<AvcodecManualTaskManagerProxy*>(avcodecManualTaskManagerProxy_.GetRefPtr());
    CHECK_RETURN_ELOG(avcodecManualTaskManagerProxy == nullptr, "avcodec manual task manager proxy is nullptr");
    sptr<AvcodecManualTaskManagerAdapter> avcodecManualTaskManagerAdapter =
        static_cast<AvcodecManualTaskManagerAdapter*>(
        avcodecManualTaskManagerProxy->GetManualTaskManagerAdapter().GetRefPtr());
    CHECK_RETURN_ELOG(avcodecManualTaskManagerAdapter == nullptr, "avcodec manual task manager adapter is nullptr");
    movingPhotoVideoCache_ = new MovingPhotoVideoCache(avcodecTaskManagerAdapter->GetTaskManager(),
        avcodecManualTaskManagerAdapter->GetManualImageTaskManager());
}

MovingPhotoManager::MovingPhotoManager()
{
    MEDIA_INFO_LOG("MovingPhotoManager ctor is callled");
    lifecycleManager_ = new MovingPhotoLifecycleManager();
}
 
MovingPhotoManager::~MovingPhotoManager()
{
    MEDIA_INFO_LOG("MovingPhotoManager dtor is callled");
    lifecycleManager_ = nullptr;
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
    streamStruct.livephotoStageEisListener_ = nullptr;
}

void MovingPhotoManager::ChangeListenerSetXtStyleType(bool isXtStyleEnabled)
{
    MEDIA_DEBUG_LOG("MovingPhotoManager::ChangeListenerSetXtStyleType is callled");
    {
        std::lock_guard<std::mutex> lock(GetLock(XT_ORIGIN_VIDEO));
        CHECK_EXECUTE(isXtStyleEnabled, xtStyleMovingPhotoResource_.SetXtStyleType(VideoType::XT_ORIGIN_VIDEO));
    }
    {
        std::lock_guard<std::mutex> lock(GetLock(ORIGIN_VIDEO));
        CHECK_EXECUTE(isXtStyleEnabled, movingPhotoResource_.SetXtStyleType(VideoType::XT_EFFECT_VIDEO));
        CHECK_EXECUTE(!isXtStyleEnabled, movingPhotoResource_.SetXtStyleType(VideoType::ORIGIN_VIDEO));
    }
}

void MovingPhotoManager::StartRecord(uint64_t timestamp, int32_t rotation, int32_t captureId,
    ColorStylePhotoType colorStylePhotoType, bool isXtStyleEnabled)
{
    MEDIA_DEBUG_LOG("MovingPhotoManager::StartRecord is callled");
    CHECK_RETURN(movingPhotoResource_.avcodecTaskManagerProxy_ == nullptr);
    // LCOV_EXCL_START
    auto weakThis = wptr<MovingPhotoManager>(this);
    if (movingPhotoStageEisEnabledFlag_) {
        std::vector<sptr<FrameRecord>> frameCacheList;
        if (movingPhotoResource_.movingPhotoVideoCache_ == nullptr) {
            MEDIA_ERR_LOG("MovingPhotoManager::StartRecord movingPhotoVideoCache is nullptr");
        }
        sptr<SessionDrainImageCallback> imageCallback =
            new SessionDrainImageCallback(frameCacheList, movingPhotoResource_.livephotoListener_,
                                          movingPhotoResource_.movingPhotoVideoCache_, timestamp, rotation, captureId);
        auto size = movingPhotoResource_.livephotoListener_->GetQueueSize();
        sptr<DrainImageManager> drainImageManager = new DrainImageManager(imageCallback, size + postCacheFrameCount_);
        movingPhotoResource_.livephotoListener_->SetCallbackMap(imageCallback, drainImageManager);
        int64_t shutterTimeStamp =  movingPhotoResource_.livephotoListener_->GetBackTimeStamp();
        movingPhotoResource_.avcodecTaskManagerProxy_->SubmitTask([weakThis, drainImageManager, shutterTimeStamp]() {
            auto manager = weakThis.promote();
            CHECK_RETURN(!manager);
            manager->StartStageEisRecord(drainImageManager, shutterTimeStamp);
        });
    } else {
        movingPhotoResource_.avcodecTaskManagerProxy_->SubmitTask([weakThis, timestamp, rotation, captureId]() {
            auto manager = weakThis.promote();
            CHECK_RETURN(!manager);
            manager->StartOnceRecord(timestamp, rotation, captureId, ORIGIN_VIDEO);
        });
    }

    auto weakThisForAudioTask = wptr<MovingPhotoManager>(this);
    CHECK_RETURN_ELOG(!movingPhotoResource_.livephotoListener_,
        "MovingPhotoResource livephotoListener is nullptr");
    int64_t middleTimeStamp = movingPhotoResource_.livephotoListener_->GetBackTimeStamp();
    movingPhotoResource_.audioTaskManagerProxy_->SubmitTask([weakThisForAudioTask, captureId, middleTimeStamp]() {
        auto manager = weakThisForAudioTask.promote();
        CHECK_RETURN(!manager);
        manager->StartProcessAudioTask(captureId, middleTimeStamp);
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

void MovingPhotoManager::StartStageEisRecord(sptr<DrainImageManager> drainImageManager, int64_t timestamp)
{
    auto& streamStruct = GetMovingPhotoResource(ORIGIN_VIDEO);
    std::lock_guard<std::mutex> lock(GetLock(ORIGIN_VIDEO));
    streamStruct.StartStageEisRecord(drainImageManager, timestamp);
}

void MovingPhotoManager::StartProcessAudioTask(int32_t captureId, int64_t middleTimeStamp)
{
    MEDIA_DEBUG_LOG("MovingPhotoManager::StartProcessAudioTask is callled");
    movingPhotoResource_.StartProcessAudioTask(captureId, middleTimeStamp);
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
        if (movingPhotoResource_.livephotoStageEisListener_ != nullptr) {
            movingPhotoResource_.livephotoStageEisListener_->UnregisterFromSurface();
        }
        if (movingPhotoResource_.movingPhotoOfflineSession_ != nullptr) {
            movingPhotoResource_.movingPhotoOfflineSession_->SetStageEisResultCb(nullptr);
        }
        if (movingPhotoResource_.livephotoListener_ != nullptr) {
            movingPhotoResource_.livephotoListener_->SetOfflineSession(nullptr);
        }
        // Note: movingPhotoVideoCache_ will be released in the async thread after all tasks complete
        movingPhotoResource_.livephotoListener_ = nullptr;
        movingPhotoResource_.livephotoMetaListener_ = nullptr;
        movingPhotoResource_.livephotoStageEisListener_ = nullptr;
        movingPhotoResource_.movingPhotoOfflineSession_ = nullptr;
    }
    {
        std::lock_guard<std::mutex> lock(xtStyleMovingPhotoStatusLock_);
        if (xtStyleMovingPhotoResource_.livephotoStageEisListener_ != nullptr) {
            xtStyleMovingPhotoResource_.livephotoStageEisListener_->UnregisterFromSurface();
        }
        if (xtStyleMovingPhotoResource_.livephotoListener_ != nullptr) {
            xtStyleMovingPhotoResource_.livephotoListener_->SetOfflineSession(nullptr);
        }
        // Note: movingPhotoVideoCache_ will be released in the async thread after all tasks complete
        xtStyleMovingPhotoResource_.livephotoListener_ = nullptr;
        xtStyleMovingPhotoResource_.livephotoMetaListener_ = nullptr;
        xtStyleMovingPhotoResource_.livephotoStageEisListener_ = nullptr;
    }
    // Clear lifecycleManager listeners to prevent dangling references
    if (lifecycleManager_ != nullptr) {
        lifecycleManager_->movingPhotoListener_ = nullptr;
    }
}

void MovingPhotoManager::StopMovingPhoto(VideoType type)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("MovingPhotoManager::StopMovingPhoto is called");
    std::lock_guard<std::mutex> lock(movingPhotoStatusLock_);
    CHECK_EXECUTE(!movingPhotoStageEisEnabledFlag_, movingPhotoResource_.StopDrainOut());
    auto audioCaptureSessionProxy = sptr<AudioCapturerSessionIntf>(audioCapturerSessionProxy_);
    std::thread asyncAudioReleaseThread = thread([audioCaptureSessionProxy]() {
        CHECK_PRINT_ELOG(!audioCaptureSessionProxy, "audioCapturerSessionProxy is nullptr");
        CHECK_EXECUTE(audioCaptureSessionProxy, audioCaptureSessionProxy->StopAudioCapture());
        if (AudioStandard::AudioSessionManager::GetInstance()->IsAudioSessionActivated()) {
            AudioStandard::AudioSessionManager::GetInstance()->DeactivateAudioSession();
        }
    });
    asyncAudioReleaseThread.detach();
    CHECK_EXECUTE((type == VideoType::ORIGIN_VIDEO || type == VideoType::XT_ORIGIN_VIDEO),
        xtStyleMovingPhotoResource_.StopDrainOut());
}

void MovingPhotoManager::RecordStreamStopStatus(bool isStreamStop)
{
    CHECK_RETURN_ELOG(lifecycleManager_ == nullptr, "lifecycleManager is nullptr");
    lifecycleManager_->RecordStopStatus(isStreamStop);
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

void MovingPhotoManager::SetMovingPhotoStageEisSupport(bool isSupport)
{
    MEDIA_DEBUG_LOG("MovingPhotoManager::SetMovingPhotoStageEisSupport support: %{public}d", isSupport);
    movingPhotoStageEisSupport_ = isSupport;
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
    uint32_t cacheSize = movingPhotoStageEisSupport_ ? MOVING_PHOTO_STAGE_EIS_CACHE_SIZE : preCacheFrameCount_;
    streamStruct.livephotoListener_ = new (std::nothrow) MovingPhotoListener(surfaceWrapper,
        metaSurface, metaCache, cacheSize, postCacheFrameCount_, videoType);
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
    if (!streamStruct.audioTaskManagerProxy_ && audioCapturerSessionProxy_) {
        sptr<AudioTaskManagerIntf> audioTaskManager = AudioTaskManagerProxy::CreateAudioTaskManagerProxy();
        audioTaskManager->CreateAudioTaskManager(audioCapturerSessionProxy_);
        streamStruct.audioTaskManagerProxy_ = audioTaskManager;
    }
    bool isExec = !streamStruct.avcodecTaskManagerProxy_ && streamStruct.audioTaskManagerProxy_;
    if (isExec) {
        shared_ptr<Size> size = std::make_shared<Size>();
        size->width = static_cast<uint32_t>(width);
        size->height = static_cast<uint32_t>(height);
        avcodecTaskManager = AvcodecTaskManagerProxy::CreateAvcodecTaskManagerProxy();
        CHECK_RETURN_ELOG(avcodecTaskManager == nullptr,
            "HStreamOperator::avcodecTaskManager is nullptr.");
        avcodecTaskManager->CreateAvcodecTaskManagerForAudio(videoSurface,
            size, streamStruct.audioTaskManagerProxy_, VideoCodecType::VIDEO_ENCODE_TYPE_HEVC, colorspace);
        avcodecTaskManager->SetVideoBufferDuration(preCacheFrameCount_, postCacheFrameCount_);
        streamStruct.avcodecTaskManagerProxy_ = avcodecTaskManager;
    }
    CreateManualTaskManager(streamStruct, videoSurface, colorspace);
    streamStruct.CreateMovingPhotoVideoCache();
}

void MovingPhotoManager::ConfigMovingPhotoStageEisStream(std::vector<int32_t> movingPhotoStageProfile,
                                                         sptr<Surface> fisrtStageEisSurface)
{
    MEDIA_INFO_LOG("MovingPhotoManager::ConfigMovingPhotoStageEisStream is called");
    auto &streamStruct = GetMovingPhotoResource(ORIGIN_VIDEO);
    CHECK_RETURN_ELOG(streamStruct.livephotoListener_ == nullptr,
        "ConfigMovingPhotoStageEisStream livephotoListener is nullptr");
    auto stageEisCache = make_shared<FixedSizeList<pair<int64_t, sptr<SurfaceBuffer>>>>(8);
    streamStruct.livephotoListener_->SetStageEisCache(stageEisCache);
    sptr<MovingPhotoStageEisListener> stageEisListener = new (std::nothrow)
        MovingPhotoStageEisListener(fisrtStageEisSurface, streamStruct.livephotoListener_, stageEisCache);
    streamStruct.livephotoStageEisListener_ = stageEisListener;
    CHECK_RETURN_ELOG(stageEisListener == nullptr, "stageEisListener is nullptr");
    fisrtStageEisSurface->RegisterConsumerListener((sptr<IBufferConsumerListener> &)stageEisListener);
}

void MovingPhotoManager::SetStageEisFlag(bool stageEisFlag)
{
    CHECK_RETURN_ELOG(movingPhotoResource_.avcodecTaskManagerProxy_ == nullptr,
                      "SetLivePhotoFireworkFlag callback taskManager is null");
    movingPhotoResource_.avcodecTaskManagerProxy_->SetLivePhotoStageEisFlag(stageEisFlag);
    CHECK_EXECUTE(movingPhotoResource_.avcodecManualTaskManagerProxy_,
        movingPhotoResource_.avcodecManualTaskManagerProxy_->SetLivePhotoStageEisEnableFlag(stageEisFlag));
}

void MovingPhotoManager::SetStageEisEnabledFlag(bool isEnable)
{
    movingPhotoStageEisEnabledFlag_ = isEnable;
    auto &streamStruct = GetMovingPhotoResource(ORIGIN_VIDEO);
    streamStruct.livephotoListener_->SetLivePhotoStageEisEnableFlag(isEnable);
}

void MovingPhotoManager::SetVideoFdMapEmptyCallback(sptr<VideoFdMapEmptyCallbackIntf> callback)
{
    MEDIA_DEBUG_LOG("MovingPhotoManager::SetVideoFdMapEmptyCallback is called");
    CHECK_RETURN_ELOG(movingPhotoResource_.avcodecTaskManagerProxy_ == nullptr,
                      "SetVideoFdMapEmptyCallback callback taskManager_ is null");
    movingPhotoResource_.avcodecTaskManagerProxy_->SetVideoFdMapEmptyCallback(callback);
}

void MovingPhotoManager::SetLivePhotoOfflineSession(sptr<MovingPhotoOfflineSessionProxy> offlineSession)
{
    CHECK_RETURN_ELOG(offlineSession == nullptr, "offlineSession is nullptr");
    auto &streamStruct = GetMovingPhotoResource(ORIGIN_VIDEO);
    CHECK_RETURN_ELOG(streamStruct.livephotoListener_ == nullptr, "livephotoListener_ is nullptr");
    streamStruct.livephotoListener_->SetOfflineSession(offlineSession);
    streamStruct.movingPhotoOfflineSession_ = offlineSession;
}

void MovingPhotoManager::SetOfflineSessionCallback()
{
    auto &streamStruct = GetMovingPhotoResource(ORIGIN_VIDEO);
    CHECK_RETURN_ELOG(streamStruct.livephotoListener_ == nullptr,
        "SetOfflineSessionCallback livephotoListener is nullptr");
    sptr<MovingPhotoMediaOfflineSessionListener> offlineSessionCallback = new (std::nothrow)
        MovingPhotoMediaOfflineSessionListener(streamStruct.livephotoListener_);
    streamStruct.offlineSessionCallback_ = offlineSessionCallback;
    CHECK_EXECUTE(streamStruct.movingPhotoOfflineSession_ != nullptr,
                  streamStruct.movingPhotoOfflineSession_->SetStageEisResultCb(offlineSessionCallback));
    if (lifecycleManager_ != nullptr) {
        lifecycleManager_->SetMovingPhotoListener(streamStruct.livephotoListener_);
        lifecycleManager_->SetStageEisListener(streamStruct.livephotoStageEisListener_);
        lifecycleManager_->SetOfflineSessionListener(streamStruct.offlineSessionCallback_);
        lifecycleManager_->SetOfflineSession(streamStruct.movingPhotoOfflineSession_);
        lifecycleManager_->SetVideoCache(movingPhotoResource_.movingPhotoVideoCache_);

        streamStruct.livephotoListener_->SetLifecycleManager(lifecycleManager_);
        if (streamStruct.livephotoStageEisListener_ != nullptr) {
            streamStruct.livephotoStageEisListener_->SetLifecycleManager(lifecycleManager_);
        }
        if (streamStruct.offlineSessionCallback_ != nullptr) {
            streamStruct.offlineSessionCallback_->SetLifecycleManager(lifecycleManager_);
        }
    }
}

void MovingPhotoManager::SetMovingPhotoMirror(bool isMirror)
{
    auto &streamStruct = GetMovingPhotoResource(ORIGIN_VIDEO);
    CHECK_EXECUTE(streamStruct.movingPhotoOfflineSession_ != nullptr,
        streamStruct.movingPhotoOfflineSession_->SetMovingPhotoMirror(isMirror));
}

void MovingPhotoManager::StartReleaseAndWaitForComplete(bool isOfflineSessionProcess)
{
    MEDIA_INFO_LOG("MovingPhotoManager::StartReleaseAndWaitForComplete is called");
    CHECK_RETURN(!movingPhotoStageEisEnabledFlag_);
    if (lifecycleManager_ == nullptr) {
        return;
    }
    if (isAsyncReleaseStarted_.exchange(true)) {
        MEDIA_INFO_LOG("StartReleaseAndWaitForComplete async thread already started, skip");
        return;
    }
    auto thisPtr = wptr<MovingPhotoManager>(this);
    sptr<MovingPhotoLifecycleManager> lifecycleManager = lifecycleManager_;
    // Hold strong references to video caches to ensure they stay alive during async callbacks
    std::thread asyncThread([thisPtr, lifecycleManager, isOfflineSessionProcess]() mutable {
        CAMERA_SYNC_TRACE;
        MEDIA_INFO_LOG("StartReleaseAndWaitForComplete async thread start");
        if (lifecycleManager == nullptr) {
            MEDIA_ERR_LOG("StartReleaseAndWaitForComplete lifecycleManager is null");
            return;
        }
        if (isOfflineSessionProcess) {
            std::this_thread::sleep_for(std::chrono::milliseconds(MOVING_PHOTO_OFFLINE_WAIT_TIME));
        }
        MEDIA_INFO_LOG("StartReleaseAndWaitForComplete async thread done, lifecycleManager ref will release");
        if (lifecycleManager->movingPhotoListener_ != nullptr) {
            lifecycleManager->movingPhotoListener_->StopDrainOut();
        } else {
            MEDIA_INFO_LOG("StartReleaseAndWaitForComplete movingPhotoListener is null, skip StopDrainOut");
        }
        // Release video caches after all tasks are complete
        MEDIA_INFO_LOG("StartReleaseAndWaitForComplete releasing video caches");
        auto sharedThis = thisPtr.promote();
        CHECK_EXECUTE(sharedThis != nullptr, sharedThis->Release());
    });
    asyncThread.detach();
}

void MovingPhotoManager::SetLivePhotoOfflineEisSurface(std::vector<int32_t> movingPhotoStageProfile,
    sptr<Surface> offlineEisSurface, sptr<Surface> offlineEisMetaSurface)
{
    CHECK_RETURN_ELOG(offlineEisSurface == nullptr, "offlineEisSurface is nullptr");
    offlineEisSurface->SetDefaultUsage(BUFFER_USAGE_VIDEO_ENCODER);
    offlineEisSurface->SetDefaultWidthAndHeight(movingPhotoStageProfile[PROFILE_INDEX_WIDTH],
        movingPhotoStageProfile[PROFILE_INDEX_HEIGHT]);
    CHECK_RETURN_ELOG(offlineEisMetaSurface == nullptr, "offlineEisMetaSurface is nullptr");
    offlineEisMetaSurface->SetDefaultUsage(BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA);
    CHECK_RETURN_ELOG(movingPhotoResource_.movingPhotoOfflineSession_ == nullptr,
        "movingPhotoOfflineSession_ is nullptr");
    bool result = movingPhotoResource_.movingPhotoOfflineSession_->SetSurface(offlineEisSurface, offlineEisMetaSurface);
    CHECK_RETURN_ELOG(result == false, "movingPhotoOfflineSession_ SetSurface failed!");

    CHECK_RETURN_ELOG(movingPhotoResource_.avcodecTaskManagerProxy_ == nullptr, "avcodecTaskManagerProxy_ is nullptr");
    movingPhotoResource_.avcodecTaskManagerProxy_->SetLivePhotoOfflineEisSurface(offlineEisSurface);
    if (movingPhotoResource_.avcodecManualTaskManagerProxy_) {
        movingPhotoResource_.avcodecManualTaskManagerProxy_->SetLivePhotoOfflineEisSurface(offlineEisSurface);
    }
}

void MovingPhotoManager::CreateManualTaskManager(MovingPhotoResource& streamStruct, sptr<Surface> videoSurface,
    ColorSpace colorspace)
{
    if (!streamStruct.avcodecManualTaskManagerProxy_) {
        sptr<AvcodecManualTaskManagerIntf> avcodecManualTaskManager =
            AvcodecManualTaskManagerProxy::CreateAvcodecManualTaskManagerProxy();
        CHECK_EXECUTE(avcodecManualTaskManager != nullptr, {
            avcodecManualTaskManager->CreateAvcodecManualTaskManager(videoSurface,
                VideoCodecType::VIDEO_ENCODE_TYPE_HEVC, colorspace);
            streamStruct.avcodecManualTaskManagerProxy_ = avcodecManualTaskManager;
        });
    }
}
}