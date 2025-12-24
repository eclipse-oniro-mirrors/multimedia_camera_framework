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

#ifndef OHOS_UNIFIED_PIPELINE_AUDIO_CAPTURE_WRAP_H
#define OHOS_UNIFIED_PIPELINE_AUDIO_CAPTURE_WRAP_H

#include <memory>
#include <mutex>

#include "audio_capturer.h"

namespace OHOS {
namespace CameraStandard {
// 设计这个UnifiedPipelineAudioCaptureWrap是为了进行异步释放线程，提升对象析构性能。
// StartCapture函数调用时，会将UnifiedPipelineAudioCaptureWrap的智能指针传入异步线程中。
// 线程运行时，始终持有UnifiedPipelineAudioCaptureWrap的指针，只有当ReleaseCapture接口被调用时，触发线程运行结束的条件，
// 线程运行结束后会释放指针，当指针计数为0时，触发UnifiedPipelineAudioCaptureWrap的析构。
// 如果不调用ReleaseCapture接口，UnifiedPipelineAudioCaptureWrap启动后内存将泄露。
class UnifiedPipelineAudioCaptureWrap : public std::enable_shared_from_this<UnifiedPipelineAudioCaptureWrap> {
public:
    static const AudioStandard::AudioSamplingRate AUDIO_PRODUCER_SAMPLING_RATE =
        AudioStandard::AudioSamplingRate::SAMPLE_RATE_48000;

    class AudioCaptureBufferListener {
    public:
        virtual ~AudioCaptureBufferListener() = default;
        virtual void OnBufferArrival(int64_t timestamp, std::unique_ptr<uint8_t[]> buffer, size_t bufferSize) = 0;
        virtual void OnBufferStart() = 0;
        virtual void OnBufferEnd() = 0;
    };

    static AudioStandard::AudioChannel GetMicNum();

public:
    UnifiedPipelineAudioCaptureWrap(AudioStandard::AudioCapturerOptions capturerOptions);
    ~UnifiedPipelineAudioCaptureWrap();

    void InitThread();

    void StartCapture();
    void StopCapture();
    void ReleaseCapture();

    void AddBufferListener(std::weak_ptr<AudioCaptureBufferListener> bufferListener);
    void RemoveBufferListener(std::weak_ptr<AudioCaptureBufferListener> bufferListener);

private:
    enum class State : int32_t { STOPPED, STARTED };

    void ProcessAudioBuffer();

    void OnReadBufferStart();
    void OnReadBuffer(uint8_t* buffer, size_t bufferSize, int64_t timestamp);

    // 基于基础时间，向前填充空音频
    void FillEmptyBuffer(size_t oneBufferSize, int64_t baseTimestamp, int32_t count);
    void OnReadBufferEnd();

    inline std::shared_ptr<AudioStandard::AudioCapturer> GetAudioCapture()
    {
        std::lock_guard<std::mutex> lock(audioCapturerMutex_);
        return audioCapturer_;
    }

    inline void SetAudioCapture(std::shared_ptr<AudioStandard::AudioCapturer> audioCapturer)
    {
        std::lock_guard<std::mutex> lock(audioCapturerMutex_);
        audioCapturer_ = audioCapturer;
    }

    std::mutex audioCapturerMutex_;
    std::shared_ptr<AudioStandard::AudioCapturer> audioCapturer_ = nullptr;

    std::atomic<bool> isCaptureAlive_ = true;

    std::mutex bufferListenerMutex_;
    std::set<std::weak_ptr<AudioCaptureBufferListener>, std::owner_less<>> bufferListeners_;
    size_t captureBufferSize_ = 0;

    std::atomic<State> runningState_ = State::STOPPED;
    std::atomic<bool> isReadFirstFrame_ = false;
};

} // namespace CameraStandard
} // namespace OHOS

#endif