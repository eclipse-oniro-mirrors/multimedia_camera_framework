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

#ifndef AUDIO_CAPTURER_SESSION_H
#define AUDIO_CAPTURER_SESSION_H

#include "audio_capturer.h"
#include "blocking_queue.h"
#include "refbase.h"
#include "audio_record.h"
#include <atomic>
#include <cstdint>

namespace OHOS {
namespace CameraStandard {
using namespace AudioStandard;
using namespace std::chrono;
using namespace DeferredProcessing;
constexpr uint32_t DEFAULT_AUDIO_CACHE_NUMBER = 400;
class AudioCapturerSession : public RefBase, public std::enable_shared_from_this<AudioCapturerSession> {
public:
    explicit AudioCapturerSession();
    ~AudioCapturerSession();
    bool StartAudioCapture();
    void ProcessAudioBuffer();
    void Stop();
    void Release();
    void GetAudioRecords(int64_t startTime, int64_t endTime, vector<sptr<AudioRecord>> &audioRecords);

private:
    bool CreateAudioCapturer();
    // Already guard by hcapture_session
    std::unique_ptr<AudioCapturer> audioCapturer_ = nullptr;
    BlockingQueue<sptr<AudioRecord>> audioBufferQueue_;
    std::atomic<bool> startAudioCapture_ { false };
    std::unique_ptr<std::thread> audioThread_ = nullptr;
};
} // CameraStandard
} // OHOS
#endif // AUDIO_CAPTURER_SESSION_H