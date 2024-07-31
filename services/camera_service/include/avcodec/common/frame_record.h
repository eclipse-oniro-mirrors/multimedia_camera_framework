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

#ifndef CAMERA_FRAMEWORK_FRAME_RECORD_H
#define CAMERA_FRAMEWORK_FRAME_RECORD_H
#include <condition_variable>
#include <cstdint>
#include <queue>
#include <refbase.h>
#include <string>

#include "camera_log.h"
#include "iconsumer_surface.h"
#include "native_avbuffer.h"
#include "native_avcodec_base.h"
#include "output/camera_output_capability.h"
#include "sample_info.h"
#include "surface_type.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;

class MovingPhotoSurfaceWrapper;
class FrameRecord : public RefBase {
public:
    explicit FrameRecord(sptr<SurfaceBuffer> videoBuffer, int64_t timestamp, GraphicTransformType type);
    ~FrameRecord() override;

    void ReleaseSurfaceBuffer(sptr<MovingPhotoSurfaceWrapper> surfaceWrapper);
    void NotifyBufferRelease();

    inline void SetStatusReadyConvertStatus()
    {
        status = STATUS_READY_CONVERT;
    }

    inline void SetCoverFrame()
    {
        isCover_ = true;
    }

    inline bool IsCoverFrame()
    {
        return isCover_.load();
    }

    inline bool IsIdle()
    {
        return status == STATUS_NONE;
    }

    inline bool IsReadyConvert()
    {
        return status == STATUS_READY_CONVERT;
    }

    inline bool IsFinishCache()
    {
        return status == STATUS_FINISH_ENCODE;
    }

    inline sptr<SurfaceBuffer> GetSurfaceBuffer()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        return videoBuffer_;
    }

    inline void SetSurfaceBuffer(sptr<SurfaceBuffer> buffer)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        videoBuffer_ = buffer;
    }

    inline OH_AVBuffer* GetEncodeBuffer()
    {
        return encodedBuffer;
    }

    inline void CacheIDRBuffer(OH_AVBuffer* buffer)
    {
        MEDIA_DEBUG_LOG("cacheIDRBuffer start");
        encodedBuffer = buffer;
    }

    inline void SetEncodedResult(bool encodedResult)
    {
        isEncoded_ = encodedResult;
    }

    inline bool IsEncoded()
    {
        return isEncoded_;
    }

    inline const std::string& GetFrameId() const
    {
        return frameId_;
    }

    inline uint32_t GetBufferSize()
    {
        return bufferSize;
    }

    inline int64_t GetTimeStamp()
    {
        return timestamp_;
    }

    inline shared_ptr<Size> GetFrameSize()
    {
        return size;
    }

    inline int32_t GetRotation()
    {
        auto it = transformTypeToValue.find(transformType_);
        return it == transformTypeToValue.end() ? 0 : it->second;
    }

    struct HashFunction {
        std::size_t operator()(const sptr<FrameRecord>& obj) const
        {
            return std::hash<std::string>()(obj->GetFrameId());
        }
    };

    struct EqualFunction {
        bool operator()(const sptr<FrameRecord>& obj1, const sptr<FrameRecord>& obj2) const
        {
            return obj1->GetFrameId() == obj2->GetFrameId();
        }
    };

    const unordered_map<GraphicTransformType, int32_t> transformTypeToValue = {
        { GRAPHIC_FLIP_H_ROT90, 90 },
        { GRAPHIC_FLIP_H_ROT180, 180 },
        { GRAPHIC_FLIP_H_ROT270, 270 },
        { GRAPHIC_ROTATE_90, 270 },
        { GRAPHIC_ROTATE_180, 180 },
        { GRAPHIC_ROTATE_270, 90 },
    };

    OH_AVBuffer* encodedBuffer = nullptr;
    std::string frameId_;

private:
    static const int32_t STATUS_NONE = 0;
    static const int32_t STATUS_READY_CONVERT = 1;
    static const int32_t STATUS_FINISH_ENCODE = 2;
    std::atomic<int32_t> status = STATUS_NONE;
    std::atomic<bool> isEncoded_ { false };
    std::atomic<bool> isCover_ { false };
    shared_ptr<Size> size;
    uint32_t bufferSize;
    sptr<SurfaceBuffer> videoBuffer_;
    int64_t timestamp_;
    GraphicTransformType transformType_;
    std::mutex mutex_;
    std::condition_variable canReleased_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // CAMERA_FRAMEWORK_CODEC_BUFFER_INFO_H
