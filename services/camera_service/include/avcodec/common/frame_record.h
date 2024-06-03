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
#include "iconsumer_surface.h"
#include <cstdint>
#include <string>
#include <condition_variable>
#include <queue>
#include "native_avcodec_base.h"
#include "native_avbuffer.h"
#include <refbase.h>
#include "camera_log.h"
#include "output/camera_output_capability.h"
#include "surface_type.h"
#include "sample_info.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;

class FrameRecord : public RefBase {
public:
    explicit FrameRecord(sptr<SurfaceBuffer> videoBuffer, int64_t timestamp, GraphicTransformType type)
        : videoBuffer_(videoBuffer), timestamp_(timestamp), transformType_(type)
    {
        frameId_ = std::to_string(timestamp);
        size = make_shared<Size>();
        size->width = static_cast<uint32_t>(videoBuffer->GetSurfaceBufferWidth());
        size->height = static_cast<uint32_t>(videoBuffer->GetSurfaceBufferHeight());
        bufferSize = videoBuffer->GetSize();
    }

    ~FrameRecord()
    {
        MEDIA_DEBUG_LOG("FrameRecord release start %{public}p", OH_AVBuffer_GetAddr(encodedBuffer));
        if (encodedBuffer) {
            OH_AVBuffer_Destroy(encodedBuffer);
        }
        encodedBuffer = nullptr;
    }

    OH_AVBuffer *encodedBuffer = nullptr;
    std::string frameId_;

    void SetStatusReadyConvertStatus()
    {
        status = STATUS_READY_CONVERT;
    }

    void SetCoverFrame()
    {
        isCover_ = true;
    }

    bool IsCoverFrame()
    {
        return isCover_.load();
    }

    bool IsIdle()
    {
        return status == STATUS_NONE;
    }

    bool IsReadyConvert()
    {
        return status == STATUS_READY_CONVERT;
    }

    bool IsFinishCache()
    {
        return status == STATUS_FINISH_ENCODE;
    }

    sptr<SurfaceBuffer> GetSurfaceBuffer()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        return videoBuffer_;
    }

    void SetSurfaceBuffer(sptr<SurfaceBuffer> buffer)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        videoBuffer_ = buffer;
    }

    void ReleaseSurfaceBuffer(sptr<Surface> surface, bool reuse)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (IsReadyConvert()) {
            MEDIA_DEBUG_LOG("releaseSurfaceBuffer when isReadyConvert %{public}p", this);
            canReleased_.wait_for(lock, std::chrono::milliseconds(BUFFER_RELEASE_EXPIREATION_TIME),
                [this] { return IsFinishCache(); });
            MEDIA_DEBUG_LOG("releaseSurfaceBuffer go %{public}p", this);
        }
        if (videoBuffer_) {
            if (reuse) {
                SurfaceError surfaceRet = surface->AttachBufferToQueue(videoBuffer_);
                if (surfaceRet != SURFACE_ERROR_OK) {
                    MEDIA_ERR_LOG("Failed to attach buffer %{public}d", surfaceRet);
                    return;
                }
                surfaceRet = surface->ReleaseBuffer(videoBuffer_, -1);
                if (surfaceRet != SURFACE_ERROR_OK) {
                    MEDIA_ERR_LOG("Failed to Release Buffer %{public}d", surfaceRet);
                    return;
                }
            }
            videoBuffer_ = nullptr;
            MEDIA_INFO_LOG("release buffer end %{public}s", frameId_.c_str());
        }
    }

    void NotifyBufferRelease()
    {
        MEDIA_DEBUG_LOG("notifyBufferRelease");
        status = STATUS_FINISH_ENCODE;
        canReleased_.notify_one();
    }

    OH_AVBuffer *GetEncodeBuffer()
    {
        return encodedBuffer;
    }

    void CacheIDRBuffer(OH_AVBuffer *buffer)
    {
        MEDIA_DEBUG_LOG("cacheIDRBuffer start");
        encodedBuffer = buffer;
    }

    void SetEncodedResult(bool encodedResult)
    {
        isEncoded_ = encodedResult;
    }

    bool IsEncoded()
    {
        return isEncoded_;
    }

    const std::string& GetFrameId() const
    {
        return frameId_;
    }

    uint32_t GetBufferSize()
    {
        return bufferSize;
    }

    int64_t GetTimeStamp()
    {
        return timestamp_;
    }

    shared_ptr<Size> GetFrameSize()
    {
        return size;
    }

    int32_t GetRotation()
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
        {GRAPHIC_FLIP_H_ROT90, 90},
        {GRAPHIC_FLIP_H_ROT180, 180},
        {GRAPHIC_FLIP_H_ROT270, 270},
        {GRAPHIC_ROTATE_90, 270},
        {GRAPHIC_ROTATE_180, 180},
        {GRAPHIC_ROTATE_270, 90}
    };

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
} // CameraStandard
} // OHOS
#endif //CAMERA_FRAMEWORK_CODEC_BUFFER_INFO_H
