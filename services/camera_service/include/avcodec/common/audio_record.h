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

#ifndef CAMERA_FRAMEWORK_AUDIO_RECORD_H
#define CAMERA_FRAMEWORK_AUDIO_RECORD_H
#include <memory>
#include <string>
#include <condition_variable>
#include "native_avcodec_base.h"
#include "native_avbuffer.h"
#include <refbase.h>
#include "camera_log.h"
#include "sample_info.h"


namespace OHOS {
namespace CameraStandard {
using namespace std;
using ByteArrayPtr = std::unique_ptr<uint8_t[]>;

class AudioRecord : public RefBase {
public:
    explicit AudioRecord(int64_t timestamp) : timestamp_(timestamp)
    {
        frameId_ = std::to_string(timestamp);
    }
    ~AudioRecord() = default;
    OH_AVBuffer *encodedBuffer = nullptr;

    std::string frameId_;

    void SetStatusReadyConvertStatus()
    {
        status = STATUS_READY_CONVERT;
    }

    void SetStatusFinishEncodeStatus()
    {
        status = STATUS_FINISH_ENCODE;
        canReleased_.notify_one();
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

    void CacheEncodedBuffer(OH_AVBuffer *buffer)
    {
        MEDIA_DEBUG_LOG("cacheEncodedBuffer start");
        encodedBuffer = buffer;
        SetStatusFinishEncodeStatus();
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

    struct HashFunction {
        std::size_t operator()(const sptr<AudioRecord>& obj) const
        {
            return std::hash<std::string>()(obj->GetFrameId());
        }
    };

    struct EqualFunction {
        bool operator()(const sptr<AudioRecord>& obj1, const sptr<AudioRecord>& obj2) const
        {
            return obj1->GetFrameId() == obj2->GetFrameId();
        }
    };

    void ReleaseAudioBuffer()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (IsReadyConvert()) {
            MEDIA_DEBUG_LOG("ReleaseAudioBuffer when isReadyConvert");
            canReleased_.wait_for(lock, std::chrono::milliseconds(BUFFER_RELEASE_EXPIREATION_TIME),
                [this] { return IsFinishCache(); });
            MEDIA_DEBUG_LOG("releaseSurfaceBuffer go %{public}s", frameId_.c_str());
        }
        if (audioBuffer_ != nullptr) {
            delete audioBuffer_;
            audioBuffer_ = nullptr;
        }
    }

    uint8_t* GetAudioBuffer()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        return audioBuffer_;
    }

    void SetAudioBuffer(uint8_t* audioBuffer)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        audioBuffer_ = audioBuffer;
    }

private:
    static const int32_t STATUS_NONE = 0;
    static const int32_t STATUS_READY_CONVERT = 1;
    static const int32_t STATUS_FINISH_ENCODE = 2;
    int status = STATUS_NONE;
    std::atomic<bool> isEncoded_ { false };
    uint32_t bufferSize;
    int64_t timestamp_;
    std::mutex mutex_;
    std::condition_variable canReleased_;
    uint8_t* audioBuffer_ = nullptr;
};
} // CameraStandard
} // OHOS
#endif //CAMERA_FRAMEWORK_AUDIO_RECORD_H
