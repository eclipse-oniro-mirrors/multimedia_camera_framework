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

#ifndef OHOS_CAMERA_MEDIA_STREAM_AUDIO_CAPTURER_SESSION_ADAPTER_H
#define OHOS_CAMERA_MEDIA_STREAM_AUDIO_CAPTURER_SESSION_ADAPTER_H

#include "audio_capturer.h"
#include "blocking_queue.h"
#include "refbase.h"
#include <atomic>
#include <cstdint>
#include <string>
#include <condition_variable>
#include "native_avcodec_base.h"
#include "native_avbuffer.h"
#include <refbase.h>
#include "camera_log.h"
#include "audio_buffer_wrapper.h"

namespace OHOS {
namespace CameraStandard {
using namespace AudioStandard;
using namespace std::chrono;

class AudioCapturerSessionAdapter : public RefBase, public std::enable_shared_from_this<AudioCapturerSessionAdapter> {
public:

    static constexpr uint32_t AUDIO_CACHE_NUMBER = 400;
    static constexpr int64_t TIME_OFFSET = 32;

    explicit AudioCapturerSessionAdapter();
    ~AudioCapturerSessionAdapter();
    bool Start();
    void ReadLoop();
    void Stop();
    void Release();
    void GetAudioBuffersInTimeRange(int64_t startTime, int64_t endTime, vector<sptr<AudioBufferWrapper>> &audioBuffers);
    AudioChannel getMicNum();
    AudioStreamInfo deferredInputOptions_;
    AudioStreamInfo deferredOutputOptions_;
    inline size_t GetBufferSize()
    {
        return bufferSize_;
    }
private:
    AudioCapturerInfo capturerInfo_;
    bool CreateAudioCapturer();
    std::unique_ptr<AudioCapturer> audioCapturer_ = nullptr;
    BlockingQueue<sptr<AudioBufferWrapper>> audioBufferQueue_;
    std::atomic<bool> startAudioCapture_ { false };
    std::unique_ptr<std::thread> audioThread_ = nullptr;
    size_t bufferSize_;
};
} // CameraStandard
} // OHOS
#endif // OHOS_CAMERA_MEDIA_STREAM_AUDIO_CAPTURER_SESSION_ADAPTER_H