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
#include "audio_deferred_process.h"
#include "utils/camera_log.h"
#include "datetime_ex.h"
#include "ipc_skeleton.h"
#include "sample_info.h"
#include "token_setproc.h"

namespace OHOS {
namespace CameraStandard {

constexpr int32_t READ_AUDIO_WAIT_TIME = 5;

AudioCapturerSession::AudioCapturerSession()
    : audioBufferQueue_("audioBuffer", DEFAULT_AUDIO_CACHE_NUMBER)
{
    AudioStreamInfo streamInfo;
    streamInfo.samplingRate = static_cast<AudioSamplingRate>(AudioSamplingRate::SAMPLE_RATE_48000);
    streamInfo.encoding = AudioEncodingType::ENCODING_PCM;
    streamInfo.format = AudioSampleFormat::SAMPLE_S16LE;
    streamInfo.channels = getMicNum();
    deferredInputOptions_ = streamInfo;
    AudioStreamInfo outputOptions;
    outputOptions.samplingRate = static_cast<AudioSamplingRate>(AudioSamplingRate::SAMPLE_RATE_32000);
    outputOptions.encoding = AudioEncodingType::ENCODING_PCM;
    outputOptions.format = AudioSampleFormat::SAMPLE_S16LE;
    outputOptions.channels = AudioChannel::MONO;
    deferredOutputOptions_ = outputOptions;
}

AudioChannel AudioCapturerSession::getMicNum()
{
    MEDIA_INFO_LOG("AudioCapturerSession::getMicNum");
    std::string mainKey = "device_status";
    std::vector<std::string> subKeys = {"hardware_info#mic_num"};
    std::vector<std::pair<std::string, std::string>> result = {};
    AudioSystemManager* audioSystemMgr = AudioSystemManager::GetInstance();
    if (audioSystemMgr == nullptr) {
        MEDIA_WARNING_LOG("AudioCapturerSession::getMicNum GetAudioSystemManagerInstance err");
        return AudioChannel::STEREO;
    }
    int32_t ret = audioSystemMgr->GetExtraParameters(mainKey, subKeys, result);
    if (ret != 0) {
        MEDIA_WARNING_LOG("AudioCapturerSession::getMicNum GetExtraParameters err");
        return AudioChannel::STEREO;
    }
    if (result.empty() || result[0].second.empty() || result[0].first.empty()) {
        MEDIA_WARNING_LOG("AudioCapturerSession::getMicNum result empty");
        return AudioChannel::STEREO;
    }
    for (auto i: result[0].second) {
        if (!std::isdigit(i)) {
            MEDIA_WARNING_LOG("AudioCapturerSession::getMicNum result illegal");
            return AudioChannel::STEREO;
        }
    }
    int32_t micNum = std::stoi(result[0].second);
    MEDIA_INFO_LOG("AudioCapturerSession::getMicNum %{public}d + %{public}d", micNum, micNum % I32_TWO);
    // odd channel should + 1
    return static_cast<AudioChannel>(micNum + (micNum % I32_TWO));
}

bool AudioCapturerSession::CreateAudioCapturer()
{
    auto callingTokenID = IPCSkeleton::GetCallingTokenID();
    SetFirstCallerTokenID(callingTokenID);
    AudioCapturerOptions capturerOptions;
    capturerOptions.streamInfo = deferredInputOptions_;
    capturerOptions.capturerInfo.sourceType = SourceType::SOURCE_TYPE_UNPROCESSED;
    capturerOptions.capturerInfo.capturerFlags = 0;
    audioCapturer_ = AudioCapturer::Create(capturerOptions);
    CHECK_RETURN_RET_ELOG(audioCapturer_ == nullptr, false, "AudioCapturerSession::Create AudioCapturer failed");
    audioCapturer_->SetInputDevice(AudioStandard::DeviceType::DEVICE_TYPE_MIC);
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
    CHECK_RETURN_RET_ELOG(startAudioCapture_, true, "AudioCapture is already started.");
    if (audioCapturer_ == nullptr && !CreateAudioCapturer()) {
        MEDIA_INFO_LOG("audioCapturer is not create");
        return false;
    }
    if (!audioCapturer_->Start()) {
        MEDIA_INFO_LOG("Start stream failed");
        audioCapturer_->Release();
        startAudioCapture_ = false;
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
    CHECK_RETURN_RET_ELOG(audioThread_ == nullptr, false, "Create auido thread failed");
    return true;
}

void AudioCapturerSession::GetAudioRecords(int64_t startTime, int64_t endTime, vector<sptr<AudioRecord>> &audioRecords)
{
    vector<sptr<AudioRecord>> allRecords = audioBufferQueue_.GetAllElements();
    for (const auto& record : allRecords) {
        CHECK_EXECUTE(record->GetTimeStamp() >= startTime && record->GetTimeStamp() < endTime,
            audioRecords.push_back(record));
    }
}

void AudioCapturerSession::ProcessAudioBuffer()
{
    CHECK_RETURN_ELOG(audioCapturer_ == nullptr, "AudioCapturer_ is not init");
    size_t bufferLen = static_cast<size_t>(deferredInputOptions_.samplingRate / AudioDeferredProcess::ONE_THOUSAND *
        deferredInputOptions_.channels * AudioDeferredProcess::DURATION_EACH_AUDIO_FRAME * sizeof(short));
    while (true) {
        CHECK_BREAK_WLOG(!startAudioCapture_, "Audio capture work done, thread out");
        auto buffer = std::make_unique<uint8_t[]>(bufferLen);
        CHECK_RETURN_ELOG(buffer == nullptr, "Failed to allocate buffer");
        size_t bytesRead = 0;
        while (bytesRead < bufferLen) {
            MEDIA_DEBUG_LOG("ProcessAudioBuffer loop");
            CHECK_BREAK_WLOG(!startAudioCapture_, "ProcessAudioBuffer loop, break out");
            int32_t len = audioCapturer_->Read(*(buffer.get() + bytesRead), bufferLen - bytesRead, false);
            if (len >= 0) {
                bytesRead += static_cast<size_t>(len);
            } else {
                MEDIA_ERR_LOG("ProcessAudioBuffer loop read error: %{public}d", len);
                startAudioCapture_ = false;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(READ_AUDIO_WAIT_TIME));
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
        int64_t timeOffset = 32;
        sptr<AudioRecord> audioRecord = new AudioRecord(GetTickCount() - timeOffset);
        audioRecord->SetAudioBuffer(buffer.get(), bufferLen);
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
