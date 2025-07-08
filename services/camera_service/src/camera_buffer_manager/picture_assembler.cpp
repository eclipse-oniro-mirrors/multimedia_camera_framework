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

#include "picture_assembler.h"

#include "camera_log.h"
#include "hstream_capture.h"
#include "photo_asset_auxiliary_consumer.h"

namespace OHOS {
namespace CameraStandard {

PictureAssembler::PictureAssembler(wptr<HStreamCapture> streamCapture)
    : streamCapture_(streamCapture)
{
    MEDIA_INFO_LOG("PictureAssembler new E");
}

PictureAssembler::~PictureAssembler()
{
    MEDIA_INFO_LOG("PictureAssembler ~ E");
}

void PictureAssembler::RegisterAuxiliaryConsumers()
{
    MEDIA_INFO_LOG("RegisterAuxiliaryConsumers E");
    sptr<HStreamCapture> streamCapture = streamCapture_.promote();
    CHECK_RETURN_ELOG(streamCapture == nullptr, "streamCapture is null");
    SurfaceError ret;
    std::string retStr = "";
    if (streamCapture->gainmapSurface_ != nullptr) {
        MEDIA_INFO_LOG("RegisterAuxiliaryConsumers 1 surfaceId: %{public}" PRIu64,
            streamCapture->gainmapSurface_->GetUniqueId());
        streamCapture->gainmapListener_ = new (std::nothrow) AuxiliaryBufferConsumer(S_GAINMAP, streamCapture);
        ret = streamCapture->gainmapSurface_->RegisterConsumerListener(
            (sptr<IBufferConsumerListener> &)streamCapture->gainmapListener_);
        retStr = ret != SURFACE_ERROR_OK ? retStr + "[gainmap]" : retStr;
    }
    if (streamCapture->deepSurface_ != nullptr) {
        MEDIA_INFO_LOG("RegisterAuxiliaryConsumers 2 surfaceId: %{public}" PRIu64,
            streamCapture->deepSurface_->GetUniqueId());
        streamCapture->deepListener_ = new (std::nothrow) AuxiliaryBufferConsumer(S_DEEP, streamCapture);
        ret = streamCapture->deepSurface_->RegisterConsumerListener(
            (sptr<IBufferConsumerListener> &)streamCapture->deepListener_);
        retStr = ret != SURFACE_ERROR_OK ? retStr + "[deep]" : retStr;
    }
    if (streamCapture->exifSurface_ != nullptr) {
        MEDIA_INFO_LOG("RegisterAuxiliaryConsumers 3 surfaceId: %{public}" PRIu64,
            streamCapture->exifSurface_->GetUniqueId());
        streamCapture->exifListener_ = new (std::nothrow) AuxiliaryBufferConsumer(S_EXIF, streamCapture);
        ret = streamCapture->exifSurface_->RegisterConsumerListener(
            (sptr<IBufferConsumerListener> &)streamCapture->exifListener_);
        retStr = ret != SURFACE_ERROR_OK ? retStr + "[exif]" : retStr;
    }
    if (streamCapture->debugSurface_ != nullptr) {
        MEDIA_INFO_LOG("RegisterAuxiliaryConsumers 4 surfaceId: %{public}" PRIu64,
            streamCapture->debugSurface_->GetUniqueId());
        streamCapture->debugListener_ = new (std::nothrow) AuxiliaryBufferConsumer(S_DEBUG, streamCapture);
        ret = streamCapture->debugSurface_->RegisterConsumerListener(
            (sptr<IBufferConsumerListener> &)streamCapture->debugListener_);
        retStr = ret != SURFACE_ERROR_OK ? retStr + "[debug]" : retStr;
    }
    if (retStr != "") {
        MEDIA_ERR_LOG("register surface consumer listener failed! type = %{public}s", retStr.c_str());
    }
    MEDIA_INFO_LOG("RegisterAuxiliaryConsumers X");
}
}  // namespace CameraStandard
}  // namespace OHOS
