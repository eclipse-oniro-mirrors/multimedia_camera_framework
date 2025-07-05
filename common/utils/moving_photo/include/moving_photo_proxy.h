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
using PhotoFormat = OHOS::Media::PhotoFormat;
constexpr const char* prefix = "IMG_";
constexpr const char* suffixJpeg = "jpg";
constexpr const char* suffixHeif = "heic";
constexpr const char* suffixDng = "dng";
constexpr const char* connector = "_";
constexpr const char* burstTag = "BURST";
constexpr const char* coverTag = "_COVER";
constexpr const char placeholder = '0';
constexpr const int8_t yearWidth = 4;
constexpr const int8_t otherWidth = 2;
constexpr const int8_t burstWidth = 3;
constexpr const int16_t startYear = 1900;

static const std::map<int32_t, int32_t> modeMap = {
    { 3, 23},
    { 4, 7},
    { 6, 33},
    { 7, 74},
    { 8, 47},
    { 9, 68},
    { 11, 2},
    { 12, 31},
    { 13, 33},
    { 14, 52}
};
static const std::map<int32_t, PhotoFormat> formatMap = {
    {0, PhotoFormat::RGBA},
    {1, PhotoFormat::JPG},
    {2, PhotoFormat::HEIF},
    {3, PhotoFormat::YUV},
    {4, PhotoFormat::DNG},
};
std::string CreateDisplayName(const std::string& suffix);
class MovingPhotoProxy : public MovingPhotoIntf {
public:
    explicit MovingPhotoProxy(
        std::shared_ptr<Dynamiclib> movingPhotoLib, sptr<MovingPhotoIntf> movingPhotoIntf);
    ~MovingPhotoProxy() override;
    static sptr<MovingPhotoProxy> CreateMovingPhotoProxy();
    static void Release();
    void CreateCameraServerProxy() override;
    void ReadFromParcel(MessageParcel& parcel) override;
    void SetDisplayName(const std::string& displayName) override;
    int32_t GetCaptureId() const override;
    void SetShootingMode(int32_t mode) override;
    std::string GetPhotoId() const override;
    int32_t GetBurstSeqId() const override;
    void SetBurstInfo(const std::string& burstKey, bool isCoverPhoto) override;
    std::string GetTitle() const override;
    std::string GetExtension() const override;
    PhotoQuality GetPhotoQuality() const override;
    int32_t GetFormat() const override;
    void SetStageVideoTaskStatus(uint8_t status) override;
    void CreateAvcodecTaskManager(VideoCodecType type, int32_t colorSpace) override;
    bool IsTaskManagerExist() override;
    void ReleaseTaskManager() override;
    void SetVideoBufferDuration(uint32_t preBufferCount, uint32_t postBufferCount) override;
    void SetVideoFd(int64_t timestamp, std::shared_ptr<PhotoAssetIntf> photoAssetProxy, int32_t captureId) override;
    void SetLatitude(double latitude) override;
    void SetLongitude(double longitude) override;
    void GetServerPhotoProxyInfo(sptr<OHOS::SurfaceBuffer>& surfaceBuffer) override;
    void SetFormat(int32_t format) override;
    void SetImageFormat(int32_t imageFormat) override;
    void SetIsVideo(bool isVideo) override;
    void SubmitTask(std::function<void()> task) override;
    void EncodeVideoBuffer(sptr<FrameRecord> frameRecord, CacheCbFunc cacheCallback) override;
    void DoMuxerVideo(std::vector<sptr<FrameRecord>> frameRecords, uint64_t taskName, int32_t rotation,
        int32_t captureId) override;
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
    sptr<PhotoProxy> GetCameraServerPhotoProxy() const override;
private:
    std::shared_ptr<Dynamiclib> movingPhotoLib_ = {nullptr};
    sptr<MovingPhotoIntf> movingPhotoIntf_ = {nullptr};
};
} // namespace CameraStandard
} // namespace OHOS
#endif // MOVING_PHOTO_PROXY_H