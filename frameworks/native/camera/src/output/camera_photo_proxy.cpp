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
#include "camera_photo_proxy.h"

namespace OHOS {
namespace CameraStandard {

CameraPhotoProxy::CameraPhotoProxy()
{
    photoId_ = "";
    deferredProcType_ = 0;
    photoWidth_ = 0;
    photoHeight_ = 0;
    bufferHandle_ = nullptr;
    fileSize_ = 0;
}

CameraPhotoProxy::CameraPhotoProxy(const BufferHandle* bufferHandle, int32_t format,
    int32_t photoWidth, int32_t photoHeight, bool isHighQuality)
{
    MEDIA_INFO_LOG("CameraPhotoProxy");
    bufferHandle_ = bufferHandle;
    format_ = format;
    photoWidth_ = photoWidth;
    photoHeight_ = photoHeight;
    fileSize_ = 0;
    isHighQuality_ = isHighQuality;
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
    bufferHandle_ = ReadBufferHandle(parcel);
    MEDIA_INFO_LOG("PhotoProxy::ReadFromParcel");
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

void CameraPhotoProxy::SetDeferredAttrs(std::string photoId, int32_t deferredProcType)
{
    isDeferredPhoto_ = 1;
    photoId_ = photoId;
    deferredProcType_ = deferredProcType;
}
} // namespace CameraStandard
} // namespace OHOS
