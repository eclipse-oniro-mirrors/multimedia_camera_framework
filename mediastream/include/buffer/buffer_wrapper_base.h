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

#ifndef OHOS_CAMERA_MEDIA_STREAM_BUFFER_WRAPPER_BASE_H
#define OHOS_CAMERA_MEDIA_STREAM_BUFFER_WRAPPER_BASE_H

#include <refbase.h>
#include "avbuffer.h"

namespace OHOS {
namespace CameraStandard {
using OHOS::Media::AVBuffer;
class BufferWrapperBase : public RefBase {
public:

    enum class Type {
        VIDEO = 0,
        META,
        AUDIO
    };

    enum class Status {
        IDLE = 0,
        READY_CONVERT,
        FINISH_ENCODE
    };

    explicit BufferWrapperBase(Type type, int64_t timestamp): type_(type), timestamp_(timestamp) {
    }

    virtual bool Release() = 0;

    virtual ~BufferWrapperBase() 
    {
        encodedBuffer_= nullptr;
    }

    inline int64_t GetTimestamp()
    {
        return timestamp_;
    }

    inline int64_t GetBufferId()
    { 
        return timestamp_;
    }

    inline void SetCoverFrame()
    {
        isCoverFrame_ = true;
    }

    inline bool IsCoverFrame()
    {
        return isCoverFrame_.load();
    }

    inline bool IsIdle()
    {
        return status_ == Status::IDLE;
    }

    inline bool IsReadyConvert()
    {
        return status_ == Status::READY_CONVERT;
    }

    inline bool IsFinishEncode()
    {
        return status_ == Status::FINISH_ENCODE;
    }

    inline void SetReadyConvert()
    {
        status_ = Status::READY_CONVERT;
    }

    inline void SetFinishEncode()
    {
        status_ = Status::FINISH_ENCODE;
    }

    inline void SetEncodeResult(bool encodeResult)
    {
        isEncoded_ = encodeResult;
    }

    inline bool IsEncoded()
    {
        return isEncoded_;
    }

    inline void MarkIDRFrame()
    {
        isIDRFrame_ = true;
    }

    inline bool IsIDRFrame()
    {
        return isIDRFrame_;
    }

    inline Type GetType()
    {
        return type_;
    }

    inline void SetEncodedBuffer(std::shared_ptr<AVBuffer> buffer)
    {
        encodedBuffer_ = buffer;
    }

    inline std::shared_ptr<AVBuffer> GetEncodedBuffer()
    {
        return encodedBuffer_;
    }

private:
    Type type_;
    int64_t timestamp_;
    std::atomic<bool> isCoverFrame_ { false };
    std::atomic<bool> isEncoded_ { false };
    std::atomic<bool> isIDRFrame_ { false };
    std::atomic<Status> status_{Status::IDLE};
    std::shared_ptr<AVBuffer> encodedBuffer_ = nullptr;
};
} // CameraStandard
} // OHOS
#endif //OHOS_CAMERA_MEDIA_STREAM_BUFFER_WRAPPER_BASE_H
