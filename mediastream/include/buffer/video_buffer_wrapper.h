/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_MEDIA_STREAM_VIDEO_BUFFER_WRAPPER_H
#define OHOS_CAMERA_MEDIA_STREAM_VIDEO_BUFFER_WRAPPER_H

#include "buffer_wrapper_base.h"
#include "meta_buffer_wrapper.h"
#include "surface.h"

namespace OHOS {
namespace CameraStandard {

class VideoBufferWrapper : public BufferWrapperBase {
public:

    explicit VideoBufferWrapper(sptr<SurfaceBuffer> videoBuffer, int64_t timestamp, GraphicTransformType transformType,
                                sptr<Surface> inputSurface, sptr<Surface> outputSurface);

    ~VideoBufferWrapper() override;

    inline sptr<SurfaceBuffer> GetVideoBuffer() { return videoBuffer_; }

    inline void SetVideoBuffer(sptr<SurfaceBuffer> buffer) {
      videoBuffer_ = buffer;
    }

    bool Release() override;
    bool DetachBufferFromOutputSurface();
    bool Flush2Target();

    inline void SetMetaBuffer(sptr<MetaBufferWrapper> metaBuffer)
    {
        std::unique_lock<std::mutex> lock(metaBufferMutex_);
        metaBuffer_ = metaBuffer;
    }

    inline sptr<MetaBufferWrapper> GetMetaBuffer()
    {
        std::unique_lock<std::mutex> lock(metaBufferMutex_);
        return metaBuffer_;
    }

    void ReleaseMetaBuffer();

private:
    sptr<SurfaceBuffer> videoBuffer_;
    sptr<MetaBufferWrapper> metaBuffer_;
    std::mutex metaBufferMutex_;

    std::shared_ptr<AVBuffer> encodedBuffer_ = nullptr;
    GraphicTransformType transformType_;
    wptr<Surface> inputSurface_;
    wptr<Surface> outputSurface_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif