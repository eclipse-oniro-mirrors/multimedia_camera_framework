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

#ifndef OHOS_CAMERA_MEDIA_STREAM_META_BUFFER_WRAPPER_H
#define OHOS_CAMERA_MEDIA_STREAM_META_BUFFER_WRAPPER_H

#include "buffer_wrapper_base.h"
#include "surface.h"

namespace OHOS {
namespace CameraStandard {
class MetaBufferWrapper : public BufferWrapperBase {
public:
    explicit MetaBufferWrapper(sptr<SurfaceBuffer> metaBuffer, int64_t timestamp, sptr<Surface> inputSurface);
    ~MetaBufferWrapper() override;

    sptr<SurfaceBuffer> GetMetaBuffer();
    void SetMetaBuffer(sptr<SurfaceBuffer> buffer);
    bool Release() override;

private:
    void DeepCopyBuffer(sptr<SurfaceBuffer> newSurfaceBuffer, sptr<SurfaceBuffer> surfaceBuffer);
    sptr<SurfaceBuffer> metaBuffer_;
    std::mutex metaBufferMutex_;
    wptr<Surface> inputSurface_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif