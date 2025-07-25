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

#ifndef MOVING_PHOTO_ADAPTER_H
#define MOVING_PHOTO_ADAPTER_H

#include "moving_photo_interface.h"

namespace OHOS {
namespace CameraStandard {
class MovingPhotoAdapter : public MovingPhotoIntf {
public:
    MovingPhotoAdapter();
    ~MovingPhotoAdapter() override;
    void CreateAvcodecTaskManager(VideoCodecType type, int32_t colorSpace) override;
    bool IsTaskManagerExist() override;
    void ReleaseTaskManager() override;
    void SetVideoBufferDuration(uint32_t preBufferCount, uint32_t postBufferCount) override;
    void SetVideoFd(int64_t timestamp, std::shared_ptr<PhotoAssetIntf> photoAssetProxy, int32_t captureId) override;
    void SubmitTask(std::function<void()> task) override;
    void EncodeVideoBuffer(sptr<FrameRecord> frameRecord, CacheCbFunc cacheCallback) override;
    void DoMuxerVideo(std::vector<sptr<FrameRecord>> frameRecords,
        uint64_t taskName, int32_t rotation, int32_t captureId) override;
    bool isEmptyVideoFdMap() override;
    void TaskManagerInsertStartTime(int32_t captureId, int64_t startTimeStamp) override;
    void TaskManagerInsertEndTime(int32_t captureId, int64_t endTimeStamp) override;
    void CreateAudioSession() override;
    bool IsAudioSessionExist() override;
    bool StartAudioCapture() override;
    void StopAudioCapture() override;
    void CreateMovingPhotoVideoCache() override;
    bool IsVideoCacheExist() override;
    void ReleaseVideoCache() override;
    void OnDrainFrameRecord(sptr<FrameRecord> frame) override;
    void GetFrameCachedResult(std::vector<sptr<FrameRecord>> frameRecords,
        uint64_t taskName, int32_t rotation, int32_t captureId) override;
private:
    sptr<AvcodecTaskManager> avcodecTaskManager_ = nullptr;
    sptr<AudioCapturerSession> audioCapturerSession_ = nullptr;
    sptr<MovingPhotoVideoCache> movingPhotoVideoCache_ = nullptr;
    wptr<MovingPhotoVideoCache> videoCache_ = nullptr;
};
} // namespace CameraStandard
} // namespace OHOS
#endif //MOVING_PHOTO_ADAPTER_H