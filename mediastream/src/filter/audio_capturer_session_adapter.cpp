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

#include "audio_capturer_session_adapter.h"

#include <algorithm>
#include <functional>
#include <thread>
#include "audio_session_manager.h"
#include "audio_deferred_process_adapter.h"
#include "camera_log.h"
#include "datetime_ex.h"
#include "ipc_skeleton.h"
#include "token_setproc.h"
#include "string_ex.h"

// LCOV_EXCL_START
namespace OHOS {
namespace CameraStandard {

constexpr int32_t READ_AUDIO_WAIT_TIME = 5;

AudioCapturerSessionAdapter::AudioCapturerSessionAdapter()
    : audioBufferQueue_("audioBuffer", AUDIO_CACHE_NUMBER)
{
    deferredInputOptions_ = AudioStreamInfo(
        AudioSamplingRate::SAMPLE_RATE_48000,
        AudioEncodingType::ENCODING_PCM,
        AudioSampleFormat::SAMPLE_S16LE,
        getMicNum());

    deferredOutputOptions_ = AudioStreamInfo(
        AudioSamplingRate::SAMPLE_RATE_32000,
        AudioEncodingType::ENCODING_PCM,
        AudioSampleFormat::SAMPLE_S16LE,
        AudioChannel::MONO
    );

    capturerInfo_ = AudioCapturerInfo(SourceType::SOURCE_TYPE_UNPROCESSED, 0);

    bufferSize_ = static_cast<size_t>(deferredInputOptions_.samplingRate / AudioDeferredProcessAdapter::ONE_THOUSAND *
        deferredInputOptions_.channels * AudioDeferredProcessAdapter::DURATION_EACH_AUDIO_FRAME * sizeof(short));
}

AudioChannel AudioCapturerSessionAdapter::getMicNum()
{
    MEDIA_INFO_LOG("AudioCapturerSessionAdapter::getMicNum");
    std::string mainKey = "device_status";
    std::vector<std::string> subKeys = {"hardware_info#mic_num"};
    std::vector<std::pair<std::string, std::string>> result = {};
    AudioSystemManager* audioSystemMgr = AudioSystemManager::GetInstance();
    CHECK_RETURN_RET_WLOG(audioSystemMgr == nullptr, AudioChannel::STEREO,
        "AudioCapturerSessionAdapter::getMicNum GetAudioSystemManagerInstance err");
    int32_t ret = audioSystemMgr->GetExtraParameters(mainKey, subKeys, result);
    CHECK_RETURN_RET_WLOG(
        ret != 0, AudioChannel::STEREO, "AudioCapturerSessionAdapter::getMicNum GetExtraParameters err");
    CHECK_RETURN_RET_WLOG(result.empty() || result[0].second.empty() || result[0].first.empty(), AudioChannel::STEREO,
        "AudioCapturerSessionAdapter::getMicNum result empty");
    for (auto i: result[0].second) {
        CHECK_RETURN_RET_WLOG(
            !std::isdigit(i), AudioChannel::STEREO, "AudioCapturerSessionAdapter::getMicNum result illegal");
    }
    int32_t micNum = 0;
    CHECK_RETURN_RET_WLOG(!StrToInt(result[0].second, micNum), AudioChannel::STEREO, "Convert result[0].second failed");
    MEDIA_INFO_LOG("AudioCapturerSessionAdapter::getMicNum %{public}d + %{public}d", micNum, micNum % 2);
    // odd channel should + 1
    return static_cast<AudioChannel>(micNum + (micNum % 2));
}

bool AudioCapturerSessionAdapter::CreateAudioCapturer()
{
    auto callingTokenID = IPCSkeleton::GetCallingTokenID();
    SetFirstCallerTokenID(callingTokenID);
    AudioCapturerOptions capturerOptions = { .streamInfo = deferredInputOptions_, .capturerInfo = capturerInfo_ };
    audioCapturer_ = AudioCapturer::Create(capturerOptions);
    CHECK_RETURN_RET_ELOG(audioCapturer_ == nullptr, false, "CreateAudioCapturer failed");
    AudioSessionStrategy sessionStrategy = { .concurrencyMode = AudioConcurrencyMode::MIX_WITH_OTHERS };
    AudioSessionManager::GetInstance()->ActivateAudioSession(sessionStrategy);
    return true;
}

AudioCapturerSessionAdapter::~AudioCapturerSessionAdapter()
{
    MEDIA_INFO_LOG("~AudioCapturerSessionAdapter enter");
    audioBufferQueue_.SetActive(false);
    audioBufferQueue_.Clear();
    Stop();
}

bool AudioCapturerSessionAdapter::Start()
{
    MEDIA_INFO_LOG("Starting moving photo audio stream");
    CHECK_RETURN_RET_ELOG(startAudioCapture_, true, "AudioCapture is already started.");
    CHECK_RETURN_RET_ILOG(audioCapturer_ == nullptr && !CreateAudioCapturer(), false, "audioCapturer is not create");
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
    audioThread_ = std::make_unique<std::thread>([this]() { this->ReadLoop(); });
    CHECK_RETURN_RET_ELOG(audioThread_ == nullptr, false, "Create auido thread failed");
    return true;
}

void AudioCapturerSessionAdapter::GetAudioBuffersInTimeRange(
    int64_t startTime, int64_t endTime, vector<sptr<AudioBufferWrapper>> &audioBuffers)
{
    audioBuffers.clear();
    vector<sptr<AudioBufferWrapper>> cachedAudioBuffers = audioBufferQueue_.GetAllElements();
    for (const auto& audioBuffer : cachedAudioBuffers) {
        if (audioBuffer->GetTimestamp() >= startTime && audioBuffer->GetTimestamp() < endTime) {
            audioBuffers.push_back(audioBuffer);
        }
    }
}

void AudioCapturerSessionAdapter::ReadLoop()
{
    CHECK_RETURN_ELOG(audioCapturer_ == nullptr, "AudioCapturer_ is not init");
    size_t bufferLen = GetBufferSize();
    while (true) {
        CHECK_BREAK_WLOG(!startAudioCapture_, "Audio capture work done, thread out");
        auto buffer = std::make_unique<uint8_t[]>(bufferLen);
        CHECK_RETURN_ELOG(buffer == nullptr, "Failed to allocate buffer");
        size_t bytesRead = 0;
        while (bytesRead < bufferLen) {
            MEDIA_DEBUG_LOG("ReadLoop loop");
            CHECK_BREAK_WLOG(!startAudioCapture_, "ReadLoop loop, break out");
            int32_t len = audioCapturer_->Read(*(buffer.get() + bytesRead), bufferLen - bytesRead, false);
            if (len >= 0) {
                bytesRead += static_cast<size_t>(len);
            } else {
                MEDIA_ERR_LOG("ReadLoop loop read error: %{public}d", len);
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
            auto popWrapper = audioBufferQueue_.Pop();
            CHECK_EXECUTE(popWrapper, popWrapper->Release());
            MEDIA_DEBUG_LOG("audio release popBuffer");
        }
        sptr<AudioBufferWrapper> bufferWrapper = new AudioBufferWrapper(
            GetTickCount() - TIME_OFFSET, buffer.get(), bufferLen);
        MEDIA_DEBUG_LOG("OnBufferAvailable timestamp: %{public}" PRId64, bufferWrapper->GetTimestamp());
        buffer.release();
        audioBufferQueue_.Push(bufferWrapper);
    }
}

void AudioCapturerSessionAdapter::Stop()
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

void AudioCapturerSessionAdapter::Release()
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
// LCOV_EXCL_STOP
