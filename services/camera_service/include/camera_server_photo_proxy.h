/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_SERVER_PHOTO_PROXY_H
#define OHOS_CAMERA_SERVER_PHOTO_PROXY_H

#include "message_parcel.h"
#include "surface.h"
#include "photo_proxy.h"
#include <cstdint>

namespace OHOS {
namespace CameraStandard {
using namespace Media;
static const std::string prefix = "IMG_";
static const std::string videoPrefix = "VID_";
static const std::string suffixJpeg = "jpg";
static const std::string suffixHeif = "heic";
static const std::string suffixDng = "dng";
static const std::string suffixMp4 = "mp4";
static const std::string connector = "_";
static const std::string burstTag = "BURST";
static const std::string coverTag = "_COVER";
static const char placeholder = '0';
static const int yearWidth = 4;
static const int otherWidth = 2;
static const int burstWidth = 3;
static const int startYear = 1900;

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
std::string CreateVideoDisplayName();

class CameraServerPhotoProxy : public PhotoProxy {
public:
    CameraServerPhotoProxy();
    virtual ~CameraServerPhotoProxy();
    void GetServerPhotoProxyInfo(sptr<SurfaceBuffer>& surfaceBuffer);
    void ReadFromParcel(MessageParcel &parcel);
    std::string GetTitle() override;
    std::string GetExtension() override;
    std::string GetPhotoId() override;
    Media::DeferredProcType GetDeferredProcType() override;
    void* GetFileDataAddr() override;
    size_t GetFileSize() override;
    int32_t GetWidth() override;
    int32_t GetHeight() override;
    PhotoFormat GetFormat() override;
    PhotoQuality GetPhotoQuality() override;
    void SetDisplayName(std::string displayName);
    double GetLatitude() override;
    double GetLongitude() override;
    int32_t GetShootingMode() override;
    void SetShootingMode(int32_t mode);
    void Release() override;
    std::string GetBurstKey() override;
    bool IsCoverPhoto() override;
    void SetBurstInfo(std::string burstKey, bool isCoverPhoto);
    int32_t GetCaptureId();
    int32_t GetBurstSeqId();
    uint32_t GetCloudImageEnhanceFlag() override;
    void SetStageVideoTaskStatus(uint8_t status);
    int32_t GetStageVideoTaskStatus() override;
    void SetFormat(int32_t format);
    void SetImageFormat(int32_t imageFormat);
    void SetIsVideo(bool isVideo);
    void SetLatitude(double latitude);
    void SetLongitude(double longitude);

private:
    uint32_t cloudImageEnhanceFlag_;
    BufferHandle* bufferHandle_;
    int32_t format_;
    int32_t photoWidth_;
    int32_t photoHeight_;
    void* fileDataAddr_;
    size_t fileSize_;
    bool isMmaped_;
    std::mutex mutex_;
    std::string photoId_;
    int32_t deferredProcType_;
    int32_t isDeferredPhoto_;
    sptr<Surface> photoSurface_;
    std::string displayName_;
    bool isHighQuality_;
    double latitude_;
    double longitude_;
    int32_t mode_;
    int32_t captureId_;
    int32_t burstSeqId_;
    std::string burstKey_;
    bool isCoverPhoto_;
    int32_t imageFormat_;
    uint8_t stageVideoTaskStatus_;
    bool isVideo_ = false;
    int32_t CameraFreeBufferHandle(BufferHandle *handle);
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_SERVER_PHOTO_PROXY_H