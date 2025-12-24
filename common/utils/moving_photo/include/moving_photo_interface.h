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

#ifndef MOVING_PHOTO_INTERFACE_H
#define MOVING_PHOTO_INTERFACE_H
#include "surface.h"
#include "refbase.h"
#include "photo_asset_interface.h"
#include "output/camera_output_capability.h"
#include "ability/camera_ability_const.h"

namespace OHOS {
class MessageParcel;
class SurfaceBuffer;
class IBufferProducer;
}

namespace OHOS {
namespace CameraStandard {
template <typename T> class FixedSizeList;
class AudioCapturerSession;
class AvcodecTaskManager;
class PhotoAssetIntf;
class MovingPhotoVideoCache;
class AudioCapturerSessionIntf;
using MetaElementType = std::pair<int64_t, sptr<OHOS::SurfaceBuffer>>;
class AvcodecTaskManagerIntf : public RefBase {
public:
    virtual ~AvcodecTaskManagerIntf() = default;
    virtual int32_t CreateAvcodecTaskManager(sptr<AudioCapturerSessionIntf> audioCapturerSessionIntf,
        VideoCodecType type, int32_t colorSpace) = 0;
    virtual int32_t CreateAvcodecTaskManager(wptr<Surface> movingSurface, std::shared_ptr<Size> size,
        sptr<AudioCapturerSessionIntf> audioCapturerSessionIntf, VideoCodecType type, int32_t colorSpace) = 0;
    virtual void SetVideoBufferDuration(uint32_t preBufferCount, uint32_t postBufferCount) = 0;
    virtual void SetVideoFd(int64_t timestamp, std::shared_ptr<PhotoAssetIntf> photoAssetProxy, int32_t captureId) = 0;
    virtual uint32_t GetDeferredVideoEnhanceFlag(int32_t captureId) = 0;
    virtual void SetDeferredVideoEnhanceFlag(int32_t captureId, uint32_t deferredVideoEnhanceFlag) = 0;
    virtual void SetVideoId(int32_t captureId, std::string videoId) = 0;
    virtual void SubmitTask(std::function<void()> task) = 0;
    virtual bool isEmptyVideoFdMap() = 0;
    virtual bool TaskManagerInsertStartTime(int32_t captureId, int64_t startTimeStamp) = 0;
    virtual bool TaskManagerInsertEndTime(int32_t captureId, int64_t endTimeStamp) = 0;
    virtual void SetMutexMap(int64_t timestamp) = 0;
    virtual void RecordVideoType(int32_t captureId, VideoType type) = 0;
};

class AudioCapturerSessionIntf : public RefBase {
public:
    virtual ~AudioCapturerSessionIntf() = default;
    virtual int32_t CreateAudioSession() = 0;
    virtual bool StartAudioCapture() = 0;
    virtual void StopAudioCapture() = 0;
};

class MovingPhotoManagerIntf : public RefBase {
public:
    virtual ~MovingPhotoManagerIntf() = default;
    virtual void StartAudioCapture() = 0;
    virtual void SetVideoFd(int64_t timestamp, std::shared_ptr<PhotoAssetIntf> photoAssetProxy, int32_t captureId) = 0;
    virtual void ExpandMovingPhoto(VideoType videoType, int32_t width, int32_t height, ColorSpace colorspace,
        sptr<Surface> videoSurface, sptr<Surface> metaSurface, sptr<AvcodecTaskManagerIntf>& avcodecTaskManager) = 0;
    virtual void SetBrotherListener() = 0;
    virtual void SetBufferDuration(uint32_t preBufferDuration, uint32_t postBufferDuration) = 0;
    virtual void ReleaseStreamStruct(VideoType videoType);
    virtual void StopMovingPhoto(VideoType type) = 0;
    virtual void ChangeListenerSetXtStyleType(bool isXtStyleEnabled) = 0;
    virtual void StartRecord(uint64_t timestamp, int32_t rotation, int32_t captureId,
        ColorStylePhotoType colorStylePhotoType, bool isXtStyleEnabled) = 0;
    virtual void InsertStartTime(int32_t captureId, int64_t startTimeStamp) = 0;
    virtual void InsertEndTime(int32_t captureId, int64_t endTimeStamp) = 0;
    virtual void SetClearFlag() = 0;
    virtual void SetDeferredVideoEnhanceFlag(int32_t captureId, uint32_t deferredFlag, std::string videoId,
        ColorStylePhotoType colorStylePhotoType, bool isXtStyleEnabled) = 0;
    virtual void Release() = 0;
};
} // namespace CameraStandard
} // namespace OHOS
#endif