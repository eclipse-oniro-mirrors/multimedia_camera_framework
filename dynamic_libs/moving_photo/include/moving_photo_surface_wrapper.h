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

#ifndef OHOS_CAMERA_MOVING_PHOTO_SURFACE_WRAPPER_H
#define OHOS_CAMERA_MOVING_PHOTO_SURFACE_WRAPPER_H

#include <cstdint>
#include <memory>
#include <mutex>
#include <ratio>

#include "refbase.h"
#include "surface.h"

namespace OHOS {
namespace CameraStandard {
class MovingPhotoSurfaceWrapper : public RefBase {
public:
    class SurfaceBufferListener : public RefBase {
    public:
        virtual void OnBufferArrival(sptr<SurfaceBuffer> buffer, int64_t timestamp, GraphicTransformType transform) = 0;
    };

    static sptr<MovingPhotoSurfaceWrapper> CreateMovingPhotoSurfaceWrapper(int32_t width, int32_t height);
    sptr<OHOS::IBufferProducer> GetProducer() const;

    void RecycleBuffer(sptr<SurfaceBuffer> buffer);
    void OnBufferArrival();

    inline void SetSurfaceBufferListener(sptr<SurfaceBufferListener> listener)
    {
        std::lock_guard<std::mutex> lock(surfaceBufferListenerMutex_);
        surfaceBufferListener_ = listener;
    }

    inline sptr<SurfaceBufferListener> GetSurfaceBufferListener()
    {
        std::lock_guard<std::mutex> lock(surfaceBufferListenerMutex_);
        return surfaceBufferListener_.promote();
    }

private:
    class BufferConsumerListener : public IBufferConsumerListener {
    public:
        explicit BufferConsumerListener(sptr<MovingPhotoSurfaceWrapper> surfaceWrapper);
        void OnBufferAvailable() override;

    private:
        wptr<MovingPhotoSurfaceWrapper> movingPhotoSurfaceWrapper_ = nullptr;
    };

    explicit MovingPhotoSurfaceWrapper() = default;
    ~MovingPhotoSurfaceWrapper() override;
    bool Init(int32_t width, int32_t height);

    mutable std::recursive_mutex videoSurfaceMutex_;
    sptr<Surface> videoSurface_ = nullptr;

    sptr<IBufferConsumerListener> bufferConsumerListener_ = nullptr;

    std::mutex surfaceBufferListenerMutex_;
    wptr<SurfaceBufferListener> surfaceBufferListener_ = nullptr;
};
} // namespace CameraStandard
} // namespace OHOS
#endif