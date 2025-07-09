/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include <unistd.h>
#include <sys/mman.h>
#include <iomanip>

#include <buffer_handle_parcel.h>
#include "camera_log.h"
#include "datetime_ex.h"
#include "camera_server_photo_proxy.h"
#include "camera_surface_buffer_util.h"
#include "format.h"
#include "photo_proxy.h"

namespace OHOS {
namespace CameraStandard {

static std::string g_lastDisplayName = "";
static int32_t g_saveIndex = 0;
CameraServerPhotoProxy::CameraServerPhotoProxy()
{
    format_ = 0;
    photoId_ = "";
    deferredProcType_ = 0;
    photoWidth_ = 0;
    photoHeight_ = 0;
    bufferHandle_ = nullptr;
    fileDataAddr_ = nullptr;
    fileSize_ = 0;
    isMmaped_ = false;
    isDeferredPhoto_ = 0;
    isHighQuality_ = false;
    mode_ = 0;
    longitude_ = 0.0;
    latitude_ = 0.0;
    captureId_ = 0;
    burstSeqId_ = -1;
    burstKey_ = "";
    isCoverPhoto_ = false;
    imageFormat_ = 0;
    stageVideoTaskStatus_ = 0;
    cloudImageEnhanceFlag_ = 0;
}

CameraServerPhotoProxy::~CameraServerPhotoProxy()
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_INFO_LOG("~CameraServerPhotoProxy");
    fileDataAddr_ = nullptr;
    fileSize_ = 0;
}

int32_t CameraServerPhotoProxy::CameraFreeBufferHandle(BufferHandle *handle)
{
    CHECK_RETURN_RET_ELOG(handle == nullptr, 0, "CameraFreeBufferHandle with nullptr handle");
    if (handle->fd >= 0) {
        close(handle->fd);
        handle->fd = -1;
    }
    const uint32_t reserveFds = handle->reserveFds;
    for (uint32_t i = 0; i < reserveFds; i++) {
        if (handle->reserve[i] >= 0) {
            close(handle->reserve[i]);
            handle->reserve[i] = -1;
        }
    }
    free(handle);
    return 0;
}

std::string CreateDisplayName(const std::string& suffix)
{
    struct tm currentTime;
    std::string formattedTime = "";
    if (GetSystemCurrentTime(&currentTime)) {
        std::stringstream ss;
        ss << prefix << std::setw(yearWidth) << std::setfill(placeholder) << currentTime.tm_year + startYear
           << std::setw(otherWidth) << std::setfill(placeholder) << (currentTime.tm_mon + 1)
           << std::setw(otherWidth) << std::setfill(placeholder) << currentTime.tm_mday
           << connector << std::setw(otherWidth) << std::setfill(placeholder) << currentTime.tm_hour
           << std::setw(otherWidth) << std::setfill(placeholder) << currentTime.tm_min
           << std::setw(otherWidth) << std::setfill(placeholder) << currentTime.tm_sec;
        formattedTime = ss.str();
    } else {
        MEDIA_ERR_LOG("Failed to get current time.");
    }
    if (g_lastDisplayName == formattedTime) {
        g_saveIndex++;
        formattedTime = formattedTime + connector + std::to_string(g_saveIndex);
        MEDIA_INFO_LOG("CreateDisplayName is %{private}s", formattedTime.c_str());
        return formattedTime;
    }
    g_lastDisplayName = formattedTime;
    g_saveIndex = 0;
    MEDIA_INFO_LOG("CreateDisplayName is %{private}s", formattedTime.c_str());
    return formattedTime;
}

std::string CreateVideoDisplayName()
{
    struct tm currentTime;
    std::string formattedTime = "";
    if (GetSystemCurrentTime(&currentTime)) {
        std::stringstream ss;
        ss << videoPrefix << std::setw(yearWidth) << std::setfill(placeholder) << currentTime.tm_year + startYear
           << std::setw(otherWidth) << std::setfill(placeholder) << (currentTime.tm_mon + 1)
           << std::setw(otherWidth) << std::setfill(placeholder) << currentTime.tm_mday
           << connector << std::setw(otherWidth) << std::setfill(placeholder) << currentTime.tm_hour
           << std::setw(otherWidth) << std::setfill(placeholder) << currentTime.tm_min
           << std::setw(otherWidth) << std::setfill(placeholder) << currentTime.tm_sec;
        formattedTime = ss.str();
    } else {
        MEDIA_ERR_LOG("Failed to get current time.");
    }
    if (g_lastDisplayName == formattedTime) {
        g_saveIndex++;
        formattedTime = formattedTime + connector + std::to_string(g_saveIndex);
        MEDIA_INFO_LOG("CreateVideoDisplayName is %{private}s", formattedTime.c_str());
        return formattedTime;
    }
    g_lastDisplayName = formattedTime;
    g_saveIndex = 0;
    MEDIA_INFO_LOG("CreateVideoDisplayName is %{private}s", formattedTime.c_str());
    return formattedTime;
}

void CameraServerPhotoProxy::SetDisplayName(std::string displayName)
{
    displayName_ = displayName;
}

void CameraServerPhotoProxy::ReadFromParcel(MessageParcel &parcel)
{
    std::lock_guard<std::mutex> lock(mutex_);
    photoId_ = parcel.ReadString();
    deferredProcType_ = parcel.ReadInt32();
    isDeferredPhoto_ = parcel.ReadInt32();
    format_ = parcel.ReadInt32();
    photoWidth_ = parcel.ReadInt32();
    photoHeight_ = parcel.ReadInt32();
    isHighQuality_ = parcel.ReadBool();
    fileSize_ = parcel.ReadUint64();
    latitude_ = parcel.ReadDouble();
    longitude_ = parcel.ReadDouble();
    captureId_ = parcel.ReadInt32();
    burstSeqId_ = parcel.ReadInt32();
    imageFormat_ = parcel.ReadInt32();
    cloudImageEnhanceFlag_ = parcel.ReadUint32();
    bufferHandle_ = ReadBufferHandle(parcel);
    MEDIA_INFO_LOG("CameraServerPhotoProxy::ReadFromParcel");
}

void CameraServerPhotoProxy::GetServerPhotoProxyInfo(sptr<SurfaceBuffer>& surfaceBuffer)
{
    MEDIA_INFO_LOG("GetServerPhotoProxyInfo E");
    CHECK_RETURN_ELOG(surfaceBuffer == nullptr, "surfaceBuffer is null");
    std::lock_guard<std::mutex> lock(mutex_);
    captureId_ = CameraSurfaceBufferUtil::GetCaptureId(surfaceBuffer);
    BufferHandle *bufferHandle = surfaceBuffer->GetBufferHandle();
    bufferHandle_ = bufferHandle;
    CHECK_PRINT_ELOG(bufferHandle == nullptr, "invalid bufferHandle");
    format_ = bufferHandle->format;
    std::string imageIdStr = std::to_string(CameraSurfaceBufferUtil::GetImageId(surfaceBuffer));
    photoId_ = imageIdStr;
    photoWidth_ = CameraSurfaceBufferUtil::GetDataWidth(surfaceBuffer);
    photoHeight_ = CameraSurfaceBufferUtil::GetDataHeight(surfaceBuffer);
    deferredProcType_ = CameraSurfaceBufferUtil::GetDeferredProcessingType(surfaceBuffer);
    isDeferredPhoto_ = 1;
    bool isHighQuality = (CameraSurfaceBufferUtil::GetIsDegradedImage(surfaceBuffer) == 0);
    isHighQuality_ = isHighQuality;
    if (isHighQuality) { // get cloudImageEnhanceFlag for 100 picture
        cloudImageEnhanceFlag_ = CameraSurfaceBufferUtil::GetCloudImageEnhanceFlag(surfaceBuffer);
    }
    uint64_t size = static_cast<uint64_t>(surfaceBuffer->GetSize());
    int32_t extraDataSize = CameraSurfaceBufferUtil::GetDataSize(surfaceBuffer);
    if (extraDataSize <= 0) {
        MEDIA_INFO_LOG("ExtraGet dataSize Ok, but size <= 0");
    } else if (static_cast<uint64_t>(extraDataSize) > size) {
        MEDIA_INFO_LOG("ExtraGet dataSize Ok,but dataSize %{public}d is bigger than bufferSize %{public}" PRIu64,
            extraDataSize, size);
    } else {
        MEDIA_INFO_LOG("ExtraGet dataSize %{public}d", extraDataSize);
        size = static_cast<uint64_t>(extraDataSize);
    }
    fileSize_ = size;
    burstSeqId_ = CameraSurfaceBufferUtil::GetBurstSequenceId(surfaceBuffer);
    imageFormat_ = CameraSurfaceBufferUtil::GetDeferredImageFormat(surfaceBuffer);
    latitude_ = 0.0;
    longitude_ = 0.0;
    MEDIA_INFO_LOG("GetServerPhotoProxyInfo X,cId:%{public}d pId:%{public}s w:%{public}d h:%{public}d f:%{public}d "
                   "s:%{public}zu dT:%{public}d iH:%{public}d",
        captureId_, photoId_.c_str(), photoWidth_, photoHeight_, format_, fileSize_, deferredProcType_, isHighQuality_);
}

int32_t CameraServerPhotoProxy::GetCaptureId()
{
    MEDIA_INFO_LOG("CameraServerPhotoProxy::GetCaptureId captureId:%{public}d", captureId_);
    std::lock_guard<std::mutex> lock(mutex_);
    return captureId_;
}

int32_t CameraServerPhotoProxy::GetBurstSeqId()
{
    MEDIA_INFO_LOG("CameraServerPhotoProxy::GetBurstSeqId burstSeqId:%{public}d", burstSeqId_);
    std::lock_guard<std::mutex> lock(mutex_);
    return burstSeqId_;
}

std::string CameraServerPhotoProxy::GetPhotoId()
{
    MEDIA_INFO_LOG("CameraServerPhotoProxy::GetPhotoId photoId:%{public}s", photoId_.c_str());
    std::lock_guard<std::mutex> lock(mutex_);
    return photoId_;
}

Media::DeferredProcType CameraServerPhotoProxy::GetDeferredProcType()
{
    MEDIA_DEBUG_LOG("CameraServerPhotoProxy::GetDeferredProcType");
    std::lock_guard<std::mutex> lock(mutex_);
    if (deferredProcType_ == 0) {
        return Media::DeferredProcType::BACKGROUND;
    } else {
        return Media::DeferredProcType::OFFLINE;
    }
}

void* CameraServerPhotoProxy::GetFileDataAddr()
{
    MEDIA_INFO_LOG("CameraServerPhotoProxy::GetFileDataAddr");
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_RETURN_RET_ELOG(
        bufferHandle_ == nullptr, fileDataAddr_, "CameraServerPhotoProxy::GetFileDataAddr bufferHandle_ is nullptr");
    if (!isMmaped_) {
        MEDIA_INFO_LOG("CameraServerPhotoProxy::GetFileDataAddr mmap");
        fileDataAddr_ = mmap(nullptr, bufferHandle_->size, PROT_READ, MAP_SHARED, bufferHandle_->fd, 0);
        CHECK_RETURN_RET_ELOG(
            fileDataAddr_ == MAP_FAILED, fileDataAddr_, "CameraServerPhotoProxy::GetFileDataAddr mmap failed");
        isMmaped_ = true;
    } else {
        MEDIA_ERR_LOG("CameraServerPhotoProxy::GetFileDataAddr mmap failed");
    }
    return fileDataAddr_;
}

size_t CameraServerPhotoProxy::GetFileSize()
{
    MEDIA_INFO_LOG("CameraServerPhotoProxy::GetFileSize");
    std::lock_guard<std::mutex> lock(mutex_);
    return fileSize_;
}

int32_t CameraServerPhotoProxy::GetWidth()
{
    return photoWidth_;
}

int32_t CameraServerPhotoProxy::GetHeight()
{
    return photoHeight_;
}

PhotoFormat CameraServerPhotoProxy::GetFormat()
{
    auto iter = formatMap.find(imageFormat_);
    return iter != formatMap.end() ? iter->second : Media::PhotoFormat::RGBA;
}

PhotoQuality CameraServerPhotoProxy::GetPhotoQuality()
{
    return isHighQuality_ ? Media::PhotoQuality::HIGH : Media::PhotoQuality::LOW;
}

void CameraServerPhotoProxy::Release()
{
    MEDIA_INFO_LOG("CameraServerPhotoProxy release enter");
    bool isMmappedAndBufferValid = isMmaped_ && bufferHandle_ != nullptr;
    if (isMmappedAndBufferValid) {
        munmap(fileDataAddr_, bufferHandle_->size);
    } else {
        MEDIA_ERR_LOG("CameraServerPhotoProxy munmap failed");
    }
}

std::string CameraServerPhotoProxy::GetTitle()
{
    return displayName_;
}

std::string CameraServerPhotoProxy::GetExtension()
{
    std::string suffix = suffixJpeg;
    if (isVideo_) {
        suffix = suffixMp4;
        return suffix;
    }
    switch (GetFormat()) {
        case PhotoFormat::HEIF : {
            suffix = suffixHeif;
            break;
        }
        case PhotoFormat::DNG : {
            suffix = suffixDng;
            break;
        }
        default: {
            suffix = suffixJpeg;
            break;
        }
    }
    return suffix;
}

void CameraServerPhotoProxy::SetLatitude(double latitude)
{
    latitude_ = latitude;
}
void CameraServerPhotoProxy::SetLongitude(double longitude)
{
    longitude_ = longitude;
}

double CameraServerPhotoProxy::GetLatitude()
{
    return latitude_;
}
double CameraServerPhotoProxy::GetLongitude()
{
    return longitude_;
}
int32_t CameraServerPhotoProxy::GetShootingMode()
{
    auto iter = modeMap.find(mode_);
    return iter != modeMap.end() ? iter->second : 0;
}
void CameraServerPhotoProxy::SetShootingMode(int32_t mode)
{
    mode_ = mode;
}

std::string CameraServerPhotoProxy::GetBurstKey()
{
    MEDIA_DEBUG_LOG("CameraServerPhotoProxy GetBurstKey");
    return burstKey_;
}

bool CameraServerPhotoProxy::IsCoverPhoto()
{
    MEDIA_DEBUG_LOG("CameraServerPhotoProxy IsCoverPhoto");
    return isCoverPhoto_;
}

void CameraServerPhotoProxy::SetBurstInfo(std::string burstKey, bool isCoverPhoto)
{
    MEDIA_INFO_LOG("CameraServerPhotoProxy SetBurstInfo");
    burstKey_ = burstKey;
    isCoverPhoto_ = isCoverPhoto;
    isHighQuality_ = true; // tell media lib disable deferred photo
}

uint32_t CameraServerPhotoProxy::GetCloudImageEnhanceFlag()
{
    MEDIA_DEBUG_LOG("%{public}s get value: %{public}u", __FUNCTION__, cloudImageEnhanceFlag_);
    return cloudImageEnhanceFlag_;
}

void CameraServerPhotoProxy::SetIsVideo(bool isVideo)
{
    isVideo_ = isVideo;
}

void CameraServerPhotoProxy::SetStageVideoTaskStatus(uint8_t status)
{
    stageVideoTaskStatus_ = static_cast<int32_t>(status);
    MEDIA_INFO_LOG("StageVideoTaskStatus is %{public}d", stageVideoTaskStatus_);
}

int32_t CameraServerPhotoProxy::GetStageVideoTaskStatus()
{
    MEDIA_DEBUG_LOG("%{public}s get value: %{public}d", __FUNCTION__, stageVideoTaskStatus_);
    return stageVideoTaskStatus_;
}

void CameraServerPhotoProxy::SetFormat(int32_t format)
{
    format_ = format;
}

void CameraServerPhotoProxy::SetImageFormat(int32_t imageFormat)
{
    imageFormat_ = imageFormat;
}
} // namespace CameraStandard
} // namespace OHOS
