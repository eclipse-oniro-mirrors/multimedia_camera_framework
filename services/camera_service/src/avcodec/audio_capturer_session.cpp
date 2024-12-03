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
#include "audio_session_manager.h"
#include "camera_log.h"
#include "datetime_ex.h"
#include "ipc_skeleton.h"
#include "sample_info.h"
#include "token_setproc.h"

namespace OHOS {
namespace CameraStandard {

AudioCapturerSession::AudioCapturerSession()
    : audioBufferQueue_("audioBuffer", DEFAULT_AUDIO_CACHE_NUMBER)
{
}

bool AudioCapturerSession::CreateAudioCapturer()
{
    auto callingTokenID = IPCSkeleton::GetCallingTokenID();
    SetFirstCallerTokenID(callingTokenID);
    AudioCapturerOptions capturerOptions;
    capturerOptions.streamInfo.samplingRate = static_cast<AudioSamplingRate>(AudioSamplingRate::SAMPLE_RATE_48000);
    capturerOptions.streamInfo.encoding = AudioEncodingType::ENCODING_PCM;
    capturerOptions.streamInfo.format = AudioSampleFormat::SAMPLE_S16LE;
    capturerOptions.streamInfo.channels = AudioChannel::MONO;
    capturerOptions.capturerInfo.sourceType = SourceType::SOURCE_TYPE_MIC;
    capturerOptions.capturerInfo.capturerFlags = 0;
    audioCapturer_ = AudioCapturer::Create(capturerOptions);
    if (audioCapturer_ == nullptr) {
        MEDIA_ERR_LOG("AudioCapturerSession::Create AudioCapturer failed");
        return false;
    }
    AudioSessionStrategy sessionStrategy;
    sessionStrategy.concurrencyMode = AudioConcurrencyMode::MIX_WITH_OTHERS;
    AudioSessionManager::GetInstance()->ActivateAudioSession(sessionStrategy);
    return true;
}

AudioCapturerSession::~AudioCapturerSession()
{
    MEDIA_INFO_LOG("~AudioCapturerSession enter");
    audioBufferQueue_.SetActive(false);
    audioBufferQueue_.Clear();
    Stop();
}

bool AudioCapturerSession::StartAudioCapture()
{
    MEDIA_INFO_LOG("Starting moving photo audio stream");
    if (audioCapturer_ == nullptr && !CreateAudioCapturer()) {
        MEDIA_INFO_LOG("audioCapturer is not create");
        return false;
    }
    if (!audioCapturer_->Start()) {
        MEDIA_INFO_LOG("Start stream failed");
        audioCapturer_->Release();
        return false;
    }
    if (audioThread_ && audioThread_->joinable()) {
        MEDIA_INFO_LOG("audioThread_ is already start, reset");
        startAudioCapture_ = false;
        audioThread_->join();
        audioThread_.reset();
    }
    startAudioCapture_ = true;
    audioThread_ = std::make_unique<std::thread>([this]() { this->ProcessAudioBuffer(); });
    if (audioThread_ == nullptr) {
        MEDIA_ERR_LOG("Create auido thread failed");
        return false;
    }
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
    CHECK_ERROR_RETURN_LOG(audioCapturer_ == nullptr, "AudioCapturer_ is not init");
    size_t bufferLen = DEFAULT_MAX_INPUT_SIZE;
    while (true) {
        CHECK_AND_BREAK_LOG(startAudioCapture_, "Audio capture work done, thread out");
        auto buffer = std::make_unique<uint8_t[]>(bufferLen);
        CHECK_ERROR_RETURN_LOG(buffer == nullptr, "Failed to allocate buffer");
        size_t bytesRead = 0;
        while (bytesRead < bufferLen) {
            MEDIA_DEBUG_LOG("ProcessAudioBuffer loop");
            CHECK_AND_BREAK_LOG(startAudioCapture_, "ProcessAudioBuffer loop, break out");
            int32_t len = audioCapturer_->Read(*(buffer.get() + bytesRead), bufferLen - bytesRead, true);
            if (len >= 0) {
                bytesRead += static_cast<size_t>(len);
            } else {
                MEDIA_ERR_LOG("ProcessAudioBuffer loop read error: %{public}d", len);
                startAudioCapture_ = false;
                break;
            }
        }
        if (!startAudioCapture_) {
            buffer.reset();
            MEDIA_INFO_LOG("Audio capture work done, thread out");
            break;
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
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("Audio capture stop enter");
    startAudioCapture_ = false;
    if (audioThread_ && audioThread_->joinable()) {
        audioThread_->join();
        audioThread_.reset();
    }
    AudioSessionManager::GetInstance()->DeactivateAudioSession();
    MEDIA_INFO_LOG("Audio capture stop out");
    Release();
}

void AudioCapturerSession::Release()
{
    CAMERA_SYNC_TRACE;
    if (audioCapturer_ != nullptr) {
        MEDIA_INFO_LOG("Audio capture Release enter");
        audioCapturer_->Release();
    }
    audioCapturer_ = nullptr;
    MEDIA_INFO_LOG("Audio capture released");
}
} // namespace CameraStandard
} // namespace OHOS
