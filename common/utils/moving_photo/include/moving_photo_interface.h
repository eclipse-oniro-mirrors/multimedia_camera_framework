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

#include "photo_proxy.h"
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
class CameraServerPhotoProxy;
class PhotoAssetIntf;
class MovingPhotoVideoCache;
class FrameRecord;
enum VideoCodecType : int32_t;

using PhotoQuality = OHOS::Media::PhotoQuality;
using MetaElementType = std::pair<int64_t, sptr<OHOS::SurfaceBuffer>>;
using CacheCbFunc = std::function<void(sptr<FrameRecord>, bool)>;
using PhotoProxy = OHOS::Media::PhotoProxy;
using EncodedEndCbFunc = std::function<void(vector<sptr<FrameRecord>>, uint64_t, int32_t, int32_t)>;
class MovingPhotoIntf : public RefBase {
public:
    virtual ~MovingPhotoIntf() = default;

    virtual void CreateCameraServerProxy() = 0;
    virtual void ReadFromParcel(MessageParcel& parcel) = 0;
    virtual void SetDisplayName(const std::string& displayName) = 0;
    virtual int32_t GetCaptureId() const = 0;
    virtual void SetShootingMode(int32_t mode) = 0;
    virtual std::string GetPhotoId() const = 0;
    virtual int32_t GetBurstSeqId() const = 0;
    virtual void SetBurstInfo(const std::string& burstKey, bool isCoverPhoto) = 0;
    virtual std::string GetTitle() const = 0;
    virtual std::string GetExtension() const = 0;
    virtual PhotoQuality GetPhotoQuality() const = 0;
    virtual int32_t GetFormat() const = 0;
    virtual void SetStageVideoTaskStatus(uint8_t status) = 0;
    virtual void CreateAvcodecTaskManager(VideoCodecType type, int32_t colorSpace) = 0;
    virtual bool IsTaskManagerExist() = 0;
    virtual void ReleaseTaskManager() = 0;
    virtual void SetVideoBufferDuration(uint32_t preBufferCount, uint32_t postBufferCount) = 0;
    virtual void SetVideoFd(int64_t timestamp, std::shared_ptr<PhotoAssetIntf> photoAssetProxy, int32_t captureId) = 0;
    virtual void SetLatitude(double latitude) = 0;
    virtual void SetLongitude(double longitude) = 0;
    virtual void GetServerPhotoProxyInfo(sptr<OHOS::SurfaceBuffer>& surfaceBuffer) = 0;
    virtual void SetFormat(int32_t format) = 0;
    virtual void SetImageFormat(int32_t imageFormat) = 0;
    virtual void SetIsVideo(bool isVideo) = 0;
    virtual void SubmitTask(std::function<void()> task) = 0;
    virtual void EncodeVideoBuffer(sptr<FrameRecord> frameRecord, CacheCbFunc cacheCallback) = 0;
    virtual void DoMuxerVideo(std::vector<sptr<FrameRecord>> frameRecords,
        uint64_t taskName, int32_t rotation, int32_t captureId) = 0;
    virtual bool isEmptyVideoFdMap() = 0;
    virtual void TaskManagerInsertStartTime(int32_t captureId, int64_t startTimeStamp) = 0;
    virtual void TaskManagerInsertEndTime(int32_t captureId, int64_t endTimeStamp) = 0;
    virtual void CreateAudioSession() = 0;
    virtual bool IsAudioSessionExist() = 0;
    virtual bool StartAudioCapture() = 0;
    virtual void StopAudioCapture() = 0;
    virtual void CreateMovingPhotoVideoCache() = 0;
    virtual bool IsVideoCacheExist() = 0;
    virtual void ReleaseVideoCache() = 0;
    virtual void OnDrainFrameRecord(sptr<FrameRecord> frame) = 0;
    virtual void GetFrameCachedResult(std::vector<sptr<FrameRecord>> frameRecords,
        uint64_t taskName, int32_t rotation, int32_t captureId) = 0;
    virtual sptr<PhotoProxy> GetCameraServerPhotoProxy() const = 0;
};

} // namespace CameraStandard
} // namespace OHOS
#endif