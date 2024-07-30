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

#include "avcodec/common/frame_record.h"

#include "moving_photo/moving_photo_surface_wrapper.h"

namespace OHOS {
namespace CameraStandard {

FrameRecord::FrameRecord(sptr<SurfaceBuffer> videoBuffer, int64_t timestamp, GraphicTransformType type)
    : videoBuffer_(videoBuffer), timestamp_(timestamp), transformType_(type)
{
    frameId_ = std::to_string(timestamp);
    size = make_shared<Size>();
    size->width = static_cast<uint32_t>(videoBuffer->GetSurfaceBufferWidth());
    size->height = static_cast<uint32_t>(videoBuffer->GetSurfaceBufferHeight());
    bufferSize = videoBuffer->GetSize();
}

FrameRecord::~FrameRecord()
{
    MEDIA_DEBUG_LOG("FrameRecord::~FrameRecord");
    if (encodedBuffer) {
        OH_AVBuffer_Destroy(encodedBuffer);
    }
    encodedBuffer = nullptr;
}

void FrameRecord::ReleaseSurfaceBuffer(sptr<MovingPhotoSurfaceWrapper> surfaceWrapper)
{
    std::unique_lock<std::mutex> lock(mutex_);
    if (IsReadyConvert()) {
        MEDIA_DEBUG_LOG("FrameRecord::ReleaseSurfaceBuffer isReadyConvert");
        auto thisPtr = sptr<FrameRecord>(this);
        canReleased_.wait_for(lock, std::chrono::milliseconds(BUFFER_RELEASE_EXPIREATION_TIME),
            [thisPtr] { return thisPtr->IsFinishCache(); });
        MEDIA_DEBUG_LOG("FrameRecord::ReleaseSurfaceBuffer wait end");
    }
    if (videoBuffer_) {
        if (surfaceWrapper != nullptr) {
            surfaceWrapper->RecycleBuffer(videoBuffer_);
        }
        videoBuffer_ = nullptr;
        MEDIA_INFO_LOG("release buffer end %{public}s", frameId_.c_str());
    }
}

void FrameRecord::NotifyBufferRelease()
{
    MEDIA_DEBUG_LOG("notifyBufferRelease");
    status = STATUS_FINISH_ENCODE;
    canReleased_.notify_one();
}
} // namespace CameraStandard
} // namespace OHOS