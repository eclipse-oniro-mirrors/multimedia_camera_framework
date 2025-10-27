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

#include "iconsumer_surface.h"
#include "native_avbuffer.h"
#include "native_avcodec_base.h"
#include "output/camera_output_capability.h"
#include "sample_info.h"
#include "surface_buffer.h"
#include "surface_type.h"
#include "utils/camera_log.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;

class MovingPhotoSurfaceWrapper;
class FrameRecord : public RefBase {
public:
    explicit FrameRecord(sptr<SurfaceBuffer> videoBuffer, int64_t timestamp, GraphicTransformType type);
    ~FrameRecord() override;

    void ReleaseSurfaceBuffer(sptr<MovingPhotoSurfaceWrapper> surfaceWrapper);
    void ReleaseMetaBuffer(sptr<Surface> surface, bool reuse);
    void NotifyBufferRelease();
    void DeepCopyBuffer(sptr<SurfaceBuffer> newSurfaceBuffer, sptr<SurfaceBuffer> surfaceBuffer) const;

    inline void SetStatusReadyConvertStatus()
    {
        status = STATUS_READY_CONVERT;
    }

    inline void SetFinishStatus()
    {
        status = STATUS_FINISH_ENCODE;
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

    inline std::shared_ptr<Media::AVBuffer> GetEncodeBuffer()
    {
        return encodedBuffer;
    }

    inline void CacheBuffer(std::shared_ptr<Media::AVBuffer> buffer)
    {
        MEDIA_DEBUG_LOG("cacheBuffer start");
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

    inline int32_t GetFormat()
    {
        auto surfaceBuffer = GetSurfaceBuffer();
        if (surfaceBuffer) {
            return surfaceBuffer->GetFormat();
        }
        return -1;
    }

    inline uint64_t GetUsage()
    {
        auto surfaceBuffer = GetSurfaceBuffer();
        if (surfaceBuffer) {
            return surfaceBuffer->GetUsage();
        }
        return std::numeric_limits<uint64_t>::max();
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

    inline void SetMetaBuffer(sptr<SurfaceBuffer> buffer)
    {
        std::unique_lock<std::mutex> lock(metaBufferMutex_);
        metaBuffer_ = buffer;
    }

    inline sptr<SurfaceBuffer> GetMetaBuffer()
    {
        std::unique_lock<std::mutex> lock(metaBufferMutex_);
        return metaBuffer_;
    }

    inline void SetIDRProperty(bool isIDRFrame)
    {
        isIDRFrame_ = isIDRFrame;
    }

    inline void SetMuxerIndex(int64_t muxerIndex)
    {
        muxerIndex_ = muxerIndex;
    }

    inline int64_t GetMuxerIndex()
    {
        return muxerIndex_;
    }

    inline bool IsIDRFrame()
    {
        return isIDRFrame_;
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

    std::shared_ptr<Media::AVBuffer> encodedBuffer = nullptr;
    std::string frameId_;
    std::mutex bufferMutex_;
    int32_t muxerIndex_;
private:
    static const int32_t STATUS_NONE = 0;
    static const int32_t STATUS_READY_CONVERT = 1;
    static const int32_t STATUS_FINISH_ENCODE = 2;
    std::atomic<int32_t> status = STATUS_NONE;
    std::atomic<bool> isEncoded_ { false };
    std::atomic<bool> isCover_ { false };
    shared_ptr<Size> size;
    uint32_t bufferSize;
    int32_t format;
    uint64_t usage;
    sptr<SurfaceBuffer> videoBuffer_;
    int64_t timestamp_;
    GraphicTransformType transformType_;
    std::mutex mutex_;
    std::condition_variable canReleased_;
    bool isIDRFrame_ = false;
    std::mutex metaBufferMutex_;
    sptr<SurfaceBuffer> metaBuffer_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // CAMERA_FRAMEWORK_CODEC_BUFFER_INFO_H
