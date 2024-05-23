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

#include "audio_capturer_session.h"

#include <algorithm>
#include <functional>
#include <thread>
#include "audio_record.h"
#include "camera_log.h"
#include "sample_info.h"
#include "datetime_ex.h"

namespace OHOS {
namespace CameraStandard {

AudioCapturerSession::AudioCapturerSession()
    : audioBufferQueue_("audioBuffer", DEFAULT_AUDIO_CACHE_NUMBER)
{
    audioTaskManager_ = make_unique<TaskManager>("audioCaptureTaskManager", DEFAULT_AUDIO_THREAD_NUMBER, true);
    AudioCapturerOptions capturerOptions;
    capturerOptions.streamInfo.samplingRate = static_cast<AudioSamplingRate>(AudioSamplingRate::SAMPLE_RATE_48000);
    capturerOptions.streamInfo.encoding = AudioEncodingType::ENCODING_PCM;
    capturerOptions.streamInfo.format = AudioSampleFormat::SAMPLE_S16LE;
    capturerOptions.streamInfo.channels = AudioChannel::STEREO;
    capturerOptions.capturerInfo.sourceType = SourceType::SOURCE_TYPE_MIC;
    capturerOptions.capturerInfo.capturerFlags = 0;
    audioCapturer_ = AudioCapturer::Create(capturerOptions);
    if (audioCapturer_ == nullptr) {
        MEDIA_ERR_LOG("AudioCapturerSession::Create AudioCapturer failed");
    }
}

AudioCapturerSession::~AudioCapturerSession()
{
    MEDIA_INFO_LOG("~AudioCapturerSession enter");
    audioBufferQueue_.SetActive(false);
    audioBufferQueue_.Clear();
    Release();
}

bool AudioCapturerSession::StartAudioCapture()
{
    MEDIA_INFO_LOG("Starting moving photo audio stream");
    if (audioCapturer_ == nullptr) {
        MEDIA_ERR_LOG("audioCapturer is not create");
        return false;
    }
    if (!audioCapturer_->Start()) {
        MEDIA_ERR_LOG("Start stream failed");
        audioCapturer_->Release();
        return false;
    }
    startAudioCapture_ = true;
    MEDIA_INFO_LOG("Capturing started");
    AudioCapturerParams getCapturerParams;
    if (audioCapturer_->GetParams(getCapturerParams) == 0) {
        MEDIA_INFO_LOG("Get Audio format: %{public}d", getCapturerParams.audioSampleFormat);
        MEDIA_INFO_LOG("Get Audio sampling rate: %{public}d", getCapturerParams.samplingRate);
        MEDIA_INFO_LOG("Get Audio channels: %{public}d", getCapturerParams.audioChannel);
    }
    audioTaskManager_->SubmitTask([this]() {
        this->ProcessAudioBuffer();
    });
    return true;
}

void AudioCapturerSession::GetAudioRecords(int64_t startTime, int64_t endTime, vector<sptr<AudioRecord>> &audioRecords)
{
    vector<sptr<AudioRecord>> allRecords = audioBufferQueue_.GetAllElements();
    for (const auto& record : allRecords) {
        if (record->GetTimeStamp() >= startTime && record->GetTimeStamp() < endTime) {
            audioRecords.push_back(record);
        }
    }
}

void AudioCapturerSession::ProcessAudioBuffer()
{
    if (audioCapturer_ == nullptr) {
        MEDIA_ERR_LOG("AudioCapturer_ is not init");
        return;
    }
    size_t bufferLen = DEFAULT_MAX_INPUT_SIZE;
    while (true) {
        CHECK_AND_BREAK_LOG(startAudioCapture_, "Audio capture work done, thread out");
        auto buffer = std::make_unique<uint8_t[]>(bufferLen);
        if (buffer == nullptr) {
            MEDIA_ERR_LOG("Failed to allocate buffer");
            return;
        }
        size_t bytesRead = 0;
        while (bytesRead < bufferLen) {
            int32_t len = audioCapturer_->Read(*(buffer.get() + bytesRead), bufferLen - bytesRead, true);
            if (len >= 0) {
                bytesRead += static_cast<size_t>(len);
            } else {
                bytesRead = static_cast<size_t>(len);
                break;
            }
        }
        if (audioBufferQueue_.Full()) {
            sptr<AudioRecord> audioRecord = audioBufferQueue_.Pop();
            audioRecord->ReleaseAudioBuffer();
            MEDIA_DEBUG_LOG("audio release popBuffer");
        }
        int64_t timeOffset = 20;
        sptr<AudioRecord> audioRecord = new AudioRecord(GetTickCount() - timeOffset);
        audioRecord->SetAudioBuffer(buffer.get());
        MEDIA_DEBUG_LOG("audio push buffer frameId: %{public}s", audioRecord->GetFrameId().c_str());
        buffer.release();
        audioBufferQueue_.Push(audioRecord);
    }
}

void AudioCapturerSession::Stop()
{
    MEDIA_INFO_LOG("Audio capture stop enter");
    if (startAudioCapture_) {
        startAudioCapture_ = false;
        MEDIA_INFO_LOG("Audio capture stop out");
        if (audioCapturer_ != nullptr && audioCapturer_->Stop()) {
            MEDIA_INFO_LOG("Audio capturer stop success");
        }
    }
}

void AudioCapturerSession::Release()
{
    Stop();
    if (audioCapturer_ != nullptr) {
        MEDIA_INFO_LOG("Audio capture Release enter");
        audioCapturer_->Release();
    }
    MEDIA_INFO_LOG("Audio capture released");
}
} // namespace CameraStandard
} // namespace OHOS