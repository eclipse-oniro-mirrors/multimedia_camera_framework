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
#include "string_ex.h"

namespace OHOS {
namespace CameraStandard {
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
    CHECK_RETURN_RET_WLOG(audioSystemMgr == nullptr, AudioChannel::STEREO,
        "AudioCapturerSession::getMicNum GetAudioSystemManagerInstance err");
    int32_t ret = audioSystemMgr->GetExtraParameters(mainKey, subKeys, result);
    CHECK_RETURN_RET_WLOG(ret != 0, AudioChannel::STEREO, "AudioCapturerSession::getMicNum GetExtraParameters err");
    CHECK_RETURN_RET_WLOG(result.empty() || result[0].second.empty() || result[0].first.empty(), AudioChannel::STEREO,
        "AudioCapturerSession::getMicNum result empty");
    for (auto i: result[0].second) {
        CHECK_RETURN_RET_WLOG(!std::isdigit(i), AudioChannel::STEREO, "AudioCapturerSession::getMicNum result illegal");
    }
    int32_t micNum = 0;
    CHECK_RETURN_RET_WLOG(!StrToInt(result[0].second, micNum), AudioChannel::STEREO, "Convert result[0].second failed");
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

    std::shared_ptr<AudioCapturer> audioCapturer = AudioCapturer::Create(capturerOptions);
    CHECK_RETURN_RET_ELOG(audioCapturer == nullptr, false, "AudioCapturerSession::Create AudioCapturer failed");
    // LCOV_EXCL_START
    audioCapturer->SetInputDevice(AudioStandard::DeviceType::DEVICE_TYPE_MIC);
    SetAudioCapturer(audioCapturer);
    AudioSessionStrategy sessionStrategy;
    sessionStrategy.concurrencyMode = AudioConcurrencyMode::MIX_WITH_OTHERS;
    AudioSessionManager::GetInstance()->ActivateAudioSession(sessionStrategy);
    return true;
    // LCOV_EXCL_STOP
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
    std::shared_ptr<AudioCapturer> audioCapturer = GetAudioCapturer();
    if (audioCapturer == nullptr) {
        if(!CreateAudioCapturer()) {
            MEDIA_INFO_LOG("audioCapturer is not create");
            return false;
        } else {
            audioCapturer = GetAudioCapturer();
            if (audioCapturer == nullptr) {
                MEDIA_INFO_LOG("audioCapturer is null");
                return false;
            }
        }
    }
    // LCOV_EXCL_START
    if (!audioCapturer->Start()) {
        MEDIA_INFO_LOG("Start stream failed");
        audioCapturer->Release();
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
    // LCOV_EXCL_STOP
}

void AudioCapturerSession::GetAudioRecords(int64_t startTime, int64_t endTime, vector<sptr<AudioRecord>> &audioRecords)
{
    vector<sptr<AudioRecord>> allRecords = audioBufferQueue_.GetAllElements();
    for (const auto& record : allRecords) {
        // LCOV_EXCL_START
        if (record->GetTimeStamp() >= startTime && record->GetTimeStamp() < endTime) {
            CHECK_EXECUTE(!record->GetFinishProcessedStatus(), audioRecords.push_back(record));
        }
        // LCOV_EXCL_STOP
    }
}

void AudioCapturerSession::ProcessAudioBuffer()
{
    std::shared_ptr<AudioCapturer> audioCapturer = GetAudioCapturer();
    CHECK_RETURN_ELOG(audioCapturer == nullptr, "AudioCapturer_ is not init");
    // LCOV_EXCL_START
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
            int32_t len = audioCapturer->Read(*(buffer.get() + bytesRead), bufferLen - bytesRead, true);
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
        int64_t timeOffset = 32;
        sptr<AudioRecord> audioRecord = new AudioRecord(GetTickCount() - timeOffset);
        audioRecord->SetAudioBuffer(buffer.get(), bufferLen);
        MEDIA_DEBUG_LOG("audio push buffer frameId: %{public}s, timestamp:%{public}" PRId64,
            audioRecord->GetFrameId().c_str(), audioRecord->GetTimeStamp());
        buffer.release();
        audioBufferQueue_.Push(audioRecord);
        if (audioRecord->GetTimeStamp() >= curCaptureTimeRange_.first &&
            audioRecord->GetTimeStamp() < curCaptureTimeRange_.second) {
            bool isFinished = false;
            if ((audioRecord->GetTimeStamp() + AudioDeferredProcess::MAX_MAX_DURATION_EACH_AUDIO_FRAME)
                > curCaptureTimeRange_.second) {
                isFinished = true;
            }
            CHECK_EXECUTE(processCallback_, processCallback_(audioRecord, isFinished));
        }
    }
    // LCOV_EXCL_STOP
}

void AudioCapturerSession::Stop()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("Audio capture stop enter");
    startAudioCapture_ = false;
    if (audioThread_ && audioThread_->joinable()) {
        // LCOV_EXCL_START
        audioThread_->join();
        audioThread_.reset();
        // LCOV_EXCL_STOP
    }
    MEDIA_INFO_LOG("Audio capture stop out");
    Release();
}

void AudioCapturerSession::Release()
{
    CAMERA_SYNC_TRACE;
    auto audioCapturer = GetAudioCapturer();
    CHECK_PRINT_ILOG(!audioCapturer, "current audioCapturer is nullptr");
    if (audioCapturer != nullptr) {
        // LCOV_EXCL_START
        MEDIA_INFO_LOG("Audio capture Release enter");
        bool ret = audioCapturer->Release();
        CHECK_PRINT_ELOG(!ret, "audioCapturer release failed");
        // LCOV_EXCL_STOP
    }
    SetAudioCapturer(nullptr);
    SetStopAudioRecord();
    MEDIA_INFO_LOG("Audio capture released");
}

void AudioCapturerSession::SetStopAudioRecord()
{
    // LCOV_EXCL_START
    sptr<AudioRecord> audioRecord = new AudioRecord(-1);
    CHECK_EXECUTE(processCallback_, processCallback_(audioRecord, true));
    SetAudioBufferCallback(nullptr);
    // LCOV_EXCL_STOP
}

void AudioCapturerSession::SetAudioBufferCallback(ProcessCbFunc processAudioFunc)
{
    std::lock_guard<std::mutex> lock(processCallbackMutex_);
    processCallback_ = processAudioFunc;
}

void AudioCapturerSession::ExecuteOnceRecord(int64_t startTime, int64_t endTime,
    ProcessCbFunc processAudioFunc)
{
    // LCOV_EXCL_START
    curCaptureTimeRange_.first = startTime;
    curCaptureTimeRange_.second = endTime;
    SetAudioBufferCallback(processAudioFunc);
    // LCOV_EXCL_STOP
}

} // namespace CameraStandard
} // namespace OHOS
