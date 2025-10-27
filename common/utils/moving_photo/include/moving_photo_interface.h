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
#include "frame_record.h"
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
enum VideoCodecType : int32_t;

using MetaElementType = std::pair<int64_t, sptr<OHOS::SurfaceBuffer>>;
using CacheCbFunc = std::function<void(sptr<FrameRecord>, bool)>;
using EncodedEndCbFunc = std::function<void(vector<sptr<FrameRecord>>, uint64_t, int32_t, int32_t)>;
class AvcodecTaskManagerIntf : public RefBase {
public:
    virtual ~AvcodecTaskManagerIntf() = default;
    virtual int32_t CreateAvcodecTaskManager(sptr<AudioCapturerSessionIntf> audioCapturerSessionIntf,
        VideoCodecType type, int32_t colorSpace) = 0;
    virtual int32_t CreateAvcodecTaskManager(wptr<Surface> movingSurface, shared_ptr<Size> size,
        sptr<AudioCapturerSessionIntf> audioCapturerSessionIntf, VideoCodecType type, int32_t colorSpace) = 0;
    virtual void SetVideoBufferDuration(uint32_t preBufferCount, uint32_t postBufferCount) = 0;
    virtual void SetVideoFd(int64_t timestamp, std::shared_ptr<PhotoAssetIntf> photoAssetProxy,
        int32_t captureId) = 0;
    virtual void SubmitTask(std::function<void()> task) = 0;
    virtual void EncodeVideoBuffer(sptr<FrameRecord> frameRecord, CacheCbFunc cacheCallback) = 0;
    virtual void DoMuxerVideo(std::vector<sptr<FrameRecord>> frameRecords,
        uint64_t taskName, int32_t rotation, int32_t captureId) = 0;
    virtual bool isEmptyVideoFdMap() = 0;
    virtual void NotifyEOS() = 0;
    virtual bool TaskManagerInsertStartTime(int32_t captureId, int64_t startTimeStamp) = 0;
    virtual bool TaskManagerInsertEndTime(int32_t captureId, int64_t endTimeStamp) = 0;
};

class AudioCapturerSessionIntf : public RefBase {
public:
    virtual ~AudioCapturerSessionIntf() = default;
    virtual int32_t CreateAudioSession() = 0;
    virtual bool StartAudioCapture() = 0;
    virtual void StopAudioCapture() = 0;
};

class MovingPhotoVideoCacheIntf : public RefBase {
public:
    virtual ~MovingPhotoVideoCacheIntf() = default;
    virtual int32_t CreateMovingPhotoVideoCache(sptr<AvcodecTaskManagerIntf> avcodecTaskManagerIntf) = 0;
    virtual void OnDrainFrameRecord(sptr<FrameRecord> frame) = 0;
    virtual void GetFrameCachedResult(std::vector<sptr<FrameRecord>> frameRecords,
        uint64_t taskName, int32_t rotation, int32_t captureId) = 0;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // MOVING_PHOTO_INTERFACE_H