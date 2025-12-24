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

#ifndef OHOS_CAMERA_MEDIA_STREAM_AUDIO_BUFFER_WRAPPER_H
#define OHOS_CAMERA_MEDIA_STREAM_AUDIO_BUFFER_WRAPPER_H

#include "buffer_wrapper_base.h"
#include <string>
#include <condition_variable>

namespace OHOS {
namespace CameraStandard {
using namespace std;

class AudioBufferWrapper : public BufferWrapperBase {
public:
    explicit AudioBufferWrapper(int64_t timestamp);
    explicit AudioBufferWrapper(int64_t timestamp, uint8_t* audioBuffer, uint32_t bufferSize);
    ~AudioBufferWrapper() override;

    void SetStatusFinishEncodeStatus()
    {
        SetFinishEncode();
        canReleased_.notify_one();
    }

    const std::string& GetWrapperId() const
    {
        return wrapperId_;
    }

    struct HashFunction {
        std::size_t operator()(const sptr<AudioBufferWrapper>& obj) const
        {
            return std::hash<std::string>()(obj->GetWrapperId());
        }
    };

    struct EqualFunction {
        bool operator()(const sptr<AudioBufferWrapper>& obj1, const sptr<AudioBufferWrapper>& obj2) const
        {
            return obj1->GetWrapperId() == obj2->GetWrapperId();
        }
    };

    bool Release() override;

    uint8_t* GetAudioBuffer()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        return audioBuffer_;
    }

    uint32_t GetBufferSize()
    {
        return bufferSize_;
    }

    void SetAudioBuffer(uint8_t* audioBuffer, uint32_t bufferSize)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        audioBuffer_ = audioBuffer;
        bufferSize_ = bufferSize;
    }

private:
    std::string wrapperId_;
    std::mutex mutex_;
    std::condition_variable canReleased_;
    uint8_t* audioBuffer_ {nullptr};
    uint32_t bufferSize_ {0};
};
} // CameraStandard
} // OHOS
#endif //OHOS_CAMERA_MEDIA_STREAM_AUDIO_BUFFER_WRAPPER_H
