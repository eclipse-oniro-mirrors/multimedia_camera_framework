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
#include "format.h"
#include "photo_proxy.h"

namespace OHOS {
namespace CameraStandard {

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
    burstKey_ = "";
    isCoverPhoto_ = false;
    imageFormat_ = 0;
}

CameraServerPhotoProxy::~CameraServerPhotoProxy()
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_INFO_LOG("~CameraServerPhotoProxy");
    CameraFreeBufferHandle(const_cast<BufferHandle*>(bufferHandle_));
    fileDataAddr_ = nullptr;
    fileSize_ = 0;
}

int32_t CameraServerPhotoProxy::CameraFreeBufferHandle(BufferHandle *handle)
{
    CHECK_ERROR_RETURN_RET_LOG(handle == nullptr, 0, "CameraFreeBufferHandle with nullptr handle");
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
    imageFormat_ = parcel.ReadInt32();
    bufferHandle_ = ReadBufferHandle(parcel);
    MEDIA_INFO_LOG("CameraServerPhotoProxy::ReadFromParcel");
}

int32_t CameraServerPhotoProxy::GetCaptureId()
{
    MEDIA_INFO_LOG("CameraServerPhotoProxy::GetCaptureId captureId:%{public}d", captureId_);
    std::lock_guard<std::mutex> lock(mutex_);
    return captureId_;
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
    CHECK_ERROR_RETURN_RET_LOG(
        bufferHandle_ == nullptr, fileDataAddr_, "CameraServerPhotoProxy::GetFileDataAddr bufferHandle_ is nullptr");
    if (!isMmaped_) {
        MEDIA_INFO_LOG("CameraServerPhotoProxy::GetFileDataAddr mmap");
        fileDataAddr_ = mmap(nullptr, bufferHandle_->size, PROT_READ, MAP_SHARED, bufferHandle_->fd, 0);
        CHECK_ERROR_RETURN_RET_LOG(
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
    if (iter != formatMap.end()) {
        return iter->second;
    }
    return Media::PhotoFormat::RGBA;
}

PhotoQuality CameraServerPhotoProxy::GetPhotoQuality()
{
    return isHighQuality_ ? Media::PhotoQuality::HIGH : Media::PhotoQuality::LOW;
}

void CameraServerPhotoProxy::Release()
{
    MEDIA_INFO_LOG("CameraServerPhotoProxy release enter");
    if (isMmaped_ && bufferHandle_ != nullptr) {
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
    return (GetFormat() == PhotoFormat::HEIF) ? suffixHeif : suffixJpeg;
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
    if (iter != modeMap.end()) {
        return iter->second;
    }
    return 0;
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
} // namespace CameraStandard
} // namespace OHOS
