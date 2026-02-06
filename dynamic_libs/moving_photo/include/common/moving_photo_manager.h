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

#ifndef OHOS_CAMERA_MOVING_PHOTO_MANAGER_H
#define OHOS_CAMERA_MOVING_PHOTO_MANAGER_H
 
#include "refbase.h"
#include "photo_asset_interface.h"
#include "moving_photo_proxy.h"
#include "moving_photo_listener.h"

namespace OHOS::CameraStandard {
class MovingPhotoResource {
public:
    void SetXtStyleType(VideoType type);
    void StartOnceRecord(uint64_t timestamp, int32_t rotation, int32_t captureId);
    void StartProcessAudioTask(int32_t captureId, int64_t startTimeStamp);
    void InsertStartTime(int32_t captureId, int64_t startTimeStamp);
    void InsertEndTime(int32_t captureId, int64_t endTimeStamp);
    void SetClearFlag();
    void StopDrainOut();
    void CreateMovingPhotoVideoCache();
    void SetVideoFd(int64_t timestamp, std::shared_ptr<PhotoAssetIntf> photoAssetProxy, int32_t captureId);

    sptr<MovingPhotoListener> livephotoListener_ = nullptr;
    sptr<MovingPhotoMetaListener> livephotoMetaListener_ = nullptr;
    sptr<MovingPhotoVideoCache> movingPhotoVideoCache_ = nullptr;
    sptr<AvcodecTaskManagerIntf> avcodecTaskManagerProxy_ = nullptr;
    sptr<AudioTaskManagerIntf> audioTaskManagerProxy_ = nullptr;
 
    MovingPhotoResource() {}
};

class MovingPhotoManager : public RefBase {
public:
    explicit MovingPhotoManager();
    ~MovingPhotoManager();
    void StartAudioCapture();
    void SetVideoFd(int64_t timestamp, std::shared_ptr<PhotoAssetIntf> photoAssetProxy, int32_t captureId);
    void SetBufferDuration(uint32_t preBufferDuration, uint32_t postBufferDuration);
    void ExpandMovingPhoto(VideoType videoType, int32_t width, int32_t height, ColorSpace colorspace,
        sptr<Surface> videoSurface, sptr<Surface> metaSurface, sptr<AvcodecTaskManagerIntf>& avcodecTaskManager);
    void SetBrotherListener();
    void ReleaseStreamStruct(VideoType videoType);
    void StopMovingPhoto(VideoType videoType);
    void ChangeListenerSetXtStyleType(bool isXtStyleEnabled);
    void StartRecord(uint64_t timestamp, int32_t rotation, int32_t captureId,
        ColorStylePhotoType colorStylePhotoType, bool isXtStyleEnabled);
    void InsertStartTime(int32_t captureId, int64_t startTimeStamp);
    void InsertEndTime(int32_t captureId, int64_t endTimeStamp);
    void SetClearFlag();
    void SetDeferredVideoEnhanceFlag(int32_t captureId, uint32_t deferredFlag, std::string videoId,
        ColorStylePhotoType colorStylePhotoType, bool isXtStyleEnabled);
    void Release();
private:
    void StartOnceRecord(uint64_t timestamp, int32_t rotation, int32_t captureId, VideoType videoType);
    void StartProcessAudioTask(int32_t captureId, int64_t startTimeStamp);
    std::queue<int32_t> audioTaskQueue;

    inline MovingPhotoResource &GetMovingPhotoResource(VideoType videoType)
    {
        return videoType == XT_ORIGIN_VIDEO ? xtStyleMovingPhotoResource_ : movingPhotoResource_;
    }

    inline std::mutex &GetLock(VideoType videoType)
    {
        return videoType == XT_ORIGIN_VIDEO ? xtStyleMovingPhotoStatusLock_ : movingPhotoStatusLock_;
    }

    sptr<AudioCapturerSessionIntf> audioCapturerSessionProxy_ = nullptr;
    MovingPhotoResource movingPhotoResource_;
    MovingPhotoResource xtStyleMovingPhotoResource_;
    std::mutex movingPhotoStatusLock_; // Guard movingPhotoStatus
    std::mutex xtStyleMovingPhotoStatusLock_; // Guard movingPhotoStatus
    uint32_t preCacheFrameCount_ = CACHE_FRAME_COUNT;
    uint32_t postCacheFrameCount_ = CACHE_FRAME_COUNT;
};
} // namespace OHOS::CameraStandard
#endif // OHOS_CAMERA_MOVING_PHOTO_MANAGER_H