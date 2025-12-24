/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_AUDIO_CAPTURE_ADAPTER_H
#define OHOS_CAMERA_AUDIO_CAPTURE_ADAPTER_H

#include <any>
#include <mutex>

#include "audio_capturer.h"
#include "avbuffer.h"

namespace OHOS {
namespace CameraStandard {
using namespace Media;
using namespace AudioStandard;
using ValueType = std::any;

class AudioCaptureAdapterCallback {
public:
    virtual ~AudioCaptureAdapterCallback() = default;

    virtual void OnInterrupt(const std::string& interruptInfo) = 0;
};

class AudioCaptureAdapter {
public:
    explicit AudioCaptureAdapter();
    ~AudioCaptureAdapter();
    Status Init();
    Status Deinit();
    Status Prepare();
    Status Reset();
    Status Start();
    Status Stop();
    Status GetParameter(std::shared_ptr<Meta>& meta);
    Status SetParameter(const std::shared_ptr<Meta>& meta);
    Status Read(std::shared_ptr<AVBuffer>& buffer, size_t expectedLen);
    Status Read(uint8_t *cacheAudioData, size_t expectedLen);
    void GetAudioTime(int64_t &audioDataTime, bool isFirstFrame);
    Status GetSize(uint64_t& size);
    Status SetAudioInterruptListener(const std::shared_ptr<AudioCaptureAdapterCallback>& callback);
    Status SetAudioCapturerInfoChangeCallback(const std::shared_ptr<AudioCapturerInfoChangeCallback>& callback);
    Status GetCurrentCapturerChangeInfo(AudioCapturerChangeInfo& changeInfo);
    int32_t GetMaxAmplitude();
    void SetAudioSource(SourceType source);
    void SetFaultEvent(const std::string& errMsg);
    void SetFaultEvent(const std::string& errMsg, int32_t ret);
    void SetCallingInfo(int32_t appUid, int32_t appPid, const std::string& bundleName, uint64_t instanceId);
    Status GetAudioCaptureOptions(AudioCapturerOptions& options);

private:
    Status DoDeinit();
    bool AssignSampleRateIfSupported(const int32_t value);
    bool AssignChannelNumIfSupported(const int32_t value);
    bool AssignSampleFmtIfSupported(const Plugins::AudioSampleFormat value);
    void TrackMaxAmplitude(int16_t *data, int32_t size);

    std::mutex captureMutex_ {};
    std::unique_ptr<AudioCapturer> audioCapturer_ {nullptr};
    std::shared_ptr<AudioCapturerInfoChangeCallback> audioCapturerInfoChangeCallback_ {nullptr};
    AudioCapturerOptions options_ {};
    std::shared_ptr<AudioCaptureAdapterCallback> audioCaptureAdapterCallback_ {nullptr};
    std::shared_ptr<AudioCapturerCallback> audioInterruptCallback_ {nullptr};
    int64_t bitRate_ {0};
    int32_t appTokenId_ {0};
    int32_t appUid_ {0};
    int32_t appPid_ {0};
    int64_t appFullTokenId_ {0};
    size_t bufferSize_ {0};
    int32_t maxAmplitude_ {0};
    bool isTrackMaxAmplitude {false};
    std::string bundleName_;
    uint64_t instanceId_ {0};
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_AUDIO_CAPTURE_ADAPTER_H

