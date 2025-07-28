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

#ifndef MOVING_PHOTO_PROXY_H
#define MOVING_PHOTO_PROXY_H

#include "camera_dynamic_loader.h"
#include "moving_photo_interface.h"
namespace OHOS {
namespace CameraStandard {
class AvcodecTaskManagerProxy : public AvcodecTaskManagerIntf {
public:
    explicit AvcodecTaskManagerProxy(
        std::shared_ptr<Dynamiclib> avcodecTaskManagerLib, sptr<AvcodecTaskManagerIntf> avcodecTaskManagerIntf);
    ~AvcodecTaskManagerProxy() override;
    static sptr<AvcodecTaskManagerProxy> CreateAvcodecTaskManagerProxy();
    int32_t CreateAvcodecTaskManager(sptr<AudioCapturerSessionIntf> audioCapturerSessionIntf,
        VideoCodecType type, int32_t colorSpace) override;
    void SetVideoBufferDuration(uint32_t preBufferCount, uint32_t postBufferCount) override;
    void SetVideoFd(int64_t timestamp, std::shared_ptr<PhotoAssetIntf> photoAssetProxy, int32_t captureId) override;
    void SubmitTask(std::function<void()> task) override;
    void EncodeVideoBuffer(sptr<FrameRecord> frameRecord, CacheCbFunc cacheCallback) override;
    void DoMuxerVideo(std::vector<sptr<FrameRecord>> frameRecords, uint64_t taskName, int32_t rotation,
        int32_t captureId) override;
    bool isEmptyVideoFdMap() override;
    bool TaskManagerInsertStartTime(int32_t captureId, int64_t startTimeStamp) override;
    bool TaskManagerInsertEndTime(int32_t captureId, int64_t endTimeStamp) override;
    sptr<AvcodecTaskManagerIntf> GetTaskManagerAdapter() const;
private:
    std::shared_ptr<Dynamiclib> avcodecTaskManagerLib_ = {nullptr};
    sptr<AvcodecTaskManagerIntf> avcodecTaskManagerIntf_ = {nullptr};
};

class AudioCapturerSessionProxy : public AudioCapturerSessionIntf {
public:
    explicit AudioCapturerSessionProxy(std::shared_ptr<Dynamiclib> audioCapturerSessionLib,
        sptr<AudioCapturerSessionIntf> audioCapturerSessionIntf);
    ~AudioCapturerSessionProxy() override;
    static sptr<AudioCapturerSessionProxy> CreateAudioCapturerSessionProxy();
    int32_t CreateAudioSession() override;
    bool StartAudioCapture() override;
    void StopAudioCapture() override;
    sptr<AudioCapturerSessionIntf> GetAudioCapturerSessionAdapter() const;
private:
    std::shared_ptr<Dynamiclib> audioCapturerSessionLib_ = {nullptr};
    sptr<AudioCapturerSessionIntf> audioCapturerSessionIntf_ = {nullptr};
    std::mutex audioCaptureLock_;
};

class MovingPhotoVideoCacheProxy : public MovingPhotoVideoCacheIntf {
public:
    explicit MovingPhotoVideoCacheProxy(std::shared_ptr<Dynamiclib> movingPhotoVideoCacheLib,
        sptr<MovingPhotoVideoCacheIntf> movingPhotoVideoCacheIntf);
    ~MovingPhotoVideoCacheProxy() override;
    static sptr<MovingPhotoVideoCacheProxy> CreateMovingPhotoVideoCacheProxy();
    int32_t CreateMovingPhotoVideoCache(sptr<AvcodecTaskManagerIntf> avcodecTaskManagerIntf) override;
    void OnDrainFrameRecord(sptr<FrameRecord> frame) override;
    void GetFrameCachedResult(std::vector<sptr<FrameRecord>> frameRecords,
        uint64_t taskName, int32_t rotation, int32_t captureId) override;
private:
    std::shared_ptr<Dynamiclib> movingPhotoVideoCacheLib_ = {nullptr};
    sptr<MovingPhotoVideoCacheIntf> movingPhotoVideoCacheIntf_ = {nullptr};
};
} // namespace CameraStandard
} // namespace OHOS
#endif // MOVING_PHOTO_PROXY_H