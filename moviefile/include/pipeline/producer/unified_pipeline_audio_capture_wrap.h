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

#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <set>
#include <vector>

#include "camera_log.h"
#include "audio_capturer.h"
#include "audio_routing_manager.h"

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

    int32_t GetPreferredInputDeviceForCapturerInfo(
        std::vector<std::shared_ptr<AudioStandard::AudioDeviceDescriptor>> &desc);
    int32_t SetPreferredInputDeviceChangeCallback(
        const std::shared_ptr<AudioStandard::AudioPreferredInputDeviceChangeCallback> &callback);
    void UnsetPreferredInputDeviceChangeCallback();

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

    AudioStandard::AudioCapturerInfo capturerInfo_;
    std::shared_ptr<AudioStandard::AudioPreferredInputDeviceChangeCallback> preferredInputDeviceChangeCallback_;

    std::atomic<bool> isCaptureAlive_ = true;

    std::mutex bufferListenerMutex_;
    std::set<std::weak_ptr<AudioCaptureBufferListener>, std::owner_less<>> bufferListeners_;
    size_t captureBufferSize_ = 0;

    std::atomic<State> runningState_ = State::STOPPED;
    std::atomic<bool> isReadFirstFrame_ = false;
};

class MyPreferredInputDeviceChangeCallback : public AudioStandard::AudioPreferredInputDeviceChangeCallback {
public:
    explicit MyPreferredInputDeviceChangeCallback(std::shared_ptr<UnifiedPipelineAudioCaptureWrap> wrap,
        std::function<void()> deviceChangeCallback = nullptr)
        : wrapPtr_(wrap), deviceChangeCallback_(deviceChangeCallback)
    {}

    void OnPreferredInputDeviceUpdated(
        const std::vector<std::shared_ptr<AudioStandard::AudioDeviceDescriptor>> &desc) override
    {
        auto wrap = wrapPtr_.lock();
        CHECK_RETURN(wrap == nullptr);
        if (deviceChangeCallback_ != nullptr) {
            deviceChangeCallback_();
        }
        MEDIA_INFO_LOG("Preferred input device updated, size:%{public}zu", desc.size());
        for (const auto &device : desc) {
            CHECK_CONTINUE(device == nullptr);
            MEDIA_INFO_LOG("Preferred input device type:%{public}d, role:%{public}d, networkId:%{public}s",
                static_cast<int32_t>(device->deviceType_), static_cast<int32_t>(device->deviceRole_),
                device->networkId_.c_str());
        }
    }

private:
    std::weak_ptr<UnifiedPipelineAudioCaptureWrap> wrapPtr_;
    std::function<void()> deviceChangeCallback_;
};

} // namespace CameraStandard
} // namespace OHOS

#endif