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

#include <cstdint>
#include <unistd.h>
#include <sys/mman.h>
#include <iomanip>

#include <buffer_handle_parcel.h>
#include "camera_log.h"
#include "camera_photo_proxy.h"

namespace OHOS {
namespace CameraStandard {

CameraPhotoProxy::CameraPhotoProxy()
{
    format_ = 0;
    photoId_ = "";
    deferredProcType_ = 0;
    photoWidth_ = 0;
    photoHeight_ = 0;
    isHighQuality_ = false;
    bufferHandle_ = nullptr;
    fileSize_ = 0;
    isDeferredPhoto_ = 0;
    longitude_ = -1.0;
    latitude_ = -1.0;
    imageFormat_ = 0;
}

CameraPhotoProxy::CameraPhotoProxy(BufferHandle* bufferHandle, int32_t format,
    int32_t photoWidth, int32_t photoHeight, bool isHighQuality)
{
    MEDIA_INFO_LOG("CameraPhotoProxy");
    bufferHandle_ = bufferHandle;
    format_ = format;
    photoWidth_ = photoWidth;
    photoHeight_ = photoHeight;
    fileSize_ = 0;
    isHighQuality_ = isHighQuality;
    deferredProcType_ = 0;
    isDeferredPhoto_ = 0;
    longitude_ = -1.0;
    latitude_ = -1.0;
    imageFormat_ = 0;
    MEDIA_INFO_LOG("format = %{public}d, width = %{public}d, height = %{public}d",
        format_, photoWidth, photoHeight);
}

CameraPhotoProxy::~CameraPhotoProxy()
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_INFO_LOG("~CameraPhotoProxy");
    fileSize_ = 0;
}

void CameraPhotoProxy::ReadFromParcel(MessageParcel &parcel)
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
    imageFormat_ = parcel.ReadInt32();
    bufferHandle_ = ReadBufferHandle(parcel);
    MEDIA_INFO_LOG("PhotoProxy::ReadFromParcel");
}

int32_t CameraPhotoProxy::CameraFreeBufferHandle()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (bufferHandle_ == nullptr) {
        MEDIA_ERR_LOG("CameraFreeBufferHandle with nullptr handle");
        return 0;
    }
    if (bufferHandle_->fd >= 0) {
        close(bufferHandle_->fd);
        bufferHandle_->fd = -1;
    }
    const uint32_t reserveFds = bufferHandle_->reserveFds;
    for (uint32_t i = 0; i < reserveFds; i++) {
        if (bufferHandle_->reserve[i] >= 0) {
            close(bufferHandle_->reserve[i]);
            bufferHandle_->reserve[i] = -1;
        }
    }
    free(bufferHandle_);
    return 0;
}

void CameraPhotoProxy::WriteToParcel(MessageParcel &parcel)
{
    std::lock_guard<std::mutex> lock(mutex_);
    parcel.WriteString(photoId_);
    parcel.WriteInt32(deferredProcType_);
    parcel.WriteInt32(isDeferredPhoto_);
    parcel.WriteInt32(format_);
    parcel.WriteInt32(photoWidth_);
    parcel.WriteInt32(photoHeight_);
    parcel.WriteBool(isHighQuality_);
    parcel.WriteUint64(fileSize_);
    parcel.WriteDouble(latitude_);
    parcel.WriteDouble(longitude_);
    parcel.WriteInt32(imageFormat_);
    if (bufferHandle_) {
        MEDIA_DEBUG_LOG("PhotoProxy::WriteToParcel %{public}d", bufferHandle_->fd);
        bool ret = WriteBufferHandle(parcel, *bufferHandle_);
        if (ret == false) {
            MEDIA_ERR_LOG("Failure, Reason: WriteBufferHandle return false");
        }
    } else {
        MEDIA_ERR_LOG("PhotoProxy::WriteToParcel without bufferHandle_");
    }
    MEDIA_INFO_LOG("PhotoProxy::WriteToParcel");
}

void CameraPhotoProxy::SetDeferredAttrs(std::string photoId, int32_t deferredProcType,
    uint64_t fileSize, int32_t imageFormat)
{
    std::lock_guard<std::mutex> lock(mutex_);
    isDeferredPhoto_ = 1;
    photoId_ = photoId;
    deferredProcType_ = deferredProcType;
    fileSize_ = fileSize;
    imageFormat_ = imageFormat;
}

void CameraPhotoProxy::SetLocation(double latitude, double longitude)
{
    std::lock_guard<std::mutex> lock(mutex_);
    latitude_ = latitude;
    longitude_ = longitude;
}
} // namespace CameraStandard
} // namespace OHOS
