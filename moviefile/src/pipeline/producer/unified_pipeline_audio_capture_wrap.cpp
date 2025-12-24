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

#include "unified_pipeline_audio_capture_wrap.h"

#include "audio_session_manager.h"
#include "camera_log.h"
#include "datetime_ex.h"
#include "ipc_skeleton.h"
#include "movie_file_common_const.h"
#include "string_ex.h"
#include "timestamp.h"
#include "token_setproc.h"

namespace OHOS {
namespace CameraStandard {
static constexpr int64_t ONE_FRAME_OFFSET = MOVIE_FILE_AUDIO_DURATION_EACH_AUDIO_FRAME * MOVIE_FILE_AUDIO_ONE_THOUSAND;
static constexpr int32_t BLUETOOTH_DELAY_FRAME = 30;
static constexpr uint32_t BUFFERSIZE_MAX = 10000000;
static constexpr int64_t MOVIE_FILE_AUDIO_MILLION = 1000000;

UnifiedPipelineAudioCaptureWrap::UnifiedPipelineAudioCaptureWrap(AudioStandard::AudioCapturerOptions capturerOptions)
{
    captureBufferSize_ = static_cast<size_t>(AUDIO_PRODUCER_SAMPLING_RATE / MOVIE_FILE_AUDIO_ONE_THOUSAND *
                                             capturerOptions.streamInfo.channels *
                                             MOVIE_FILE_AUDIO_DURATION_EACH_AUDIO_FRAME * sizeof(short));
    MEDIA_INFO_LOG("UnifiedPipelineAudioCaptureWrap capture buffer size is:%{public}zu", captureBufferSize_);

    auto callingTokenID = IPCSkeleton::GetCallingTokenID();
    SetFirstCallerTokenID(callingTokenID);
    std::shared_ptr<AudioStandard::AudioCapturer> audioCapturer = AudioStandard::AudioCapturer::Create(capturerOptions);
    CHECK_RETURN_ELOG(audioCapturer == nullptr, "UnifiedPipelineAudioCaptureWrap create AudioCapturer failed");
    SetAudioCapture(audioCapturer);
    AudioStandard::AudioSessionStrategy sessionStrategy;
    sessionStrategy.concurrencyMode = AudioStandard::AudioConcurrencyMode::PAUSE_OTHERS;
    AudioStandard::AudioSessionManager::GetInstance()->ActivateAudioSession(sessionStrategy);
};

void UnifiedPipelineAudioCaptureWrap::InitThread()
{
    std::shared_ptr<UnifiedPipelineAudioCaptureWrap> thisPtr = shared_from_this();
    std::thread workThread([thisPtr]() { thisPtr->ProcessAudioBuffer(); });
    workThread.detach();
}

UnifiedPipelineAudioCaptureWrap::~UnifiedPipelineAudioCaptureWrap()
{
    MEDIA_INFO_LOG("UnifiedPipelineAudioCaptureWrap destruct finish");
}

void UnifiedPipelineAudioCaptureWrap::StartCapture()
{
    CAMERA_SYNC_TRACE;
    auto audioCapturer = GetAudioCapture();
    CHECK_RETURN_ELOG(!audioCapturer, "UnifiedPipelineAudioCaptureWrap::StartCapture audioCapture is nullptr");
    CHECK_RETURN_ELOG(!isCaptureAlive_, "UnifiedPipelineAudioCaptureWrap::StartCapture is already released");
    runningState_ = State::STARTED;
    OnReadBufferStart();
    isReadFirstFrame_ = false;
    CHECK_PRINT_ELOG(!audioCapturer->Start(), "UnifiedPipelineAudioCaptureWrap Start stream failed");
}

void UnifiedPipelineAudioCaptureWrap::StopCapture()
{
    CAMERA_SYNC_TRACE;
    auto audioCapturer = GetAudioCapture();
    CHECK_RETURN_ELOG(!audioCapturer, "UnifiedPipelineAudioCaptureWrap::StopCapture audioCapture is nullptr");
    CHECK_RETURN_ELOG(!isCaptureAlive_, "UnifiedPipelineAudioCaptureWrap::StopCapture is already released");
    CHECK_PRINT_ELOG(!audioCapturer->Stop(), "UnifiedPipelineAudioCaptureWrap Stop stream failed");
    runningState_ = State::STOPPED;
    OnReadBufferEnd();
}

void UnifiedPipelineAudioCaptureWrap::ReleaseCapture()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("UnifiedPipelineAudioCaptureWrap Audio capture Release enter");
    isCaptureAlive_ = false;

    auto audioCapture = GetAudioCapture();
    if (audioCapture != nullptr) {
        audioCapture->Stop();
        MEDIA_INFO_LOG("Audio capture Release enter");
        audioCapture->Release();
    }
    SetAudioCapture(nullptr);
};

void UnifiedPipelineAudioCaptureWrap::AddBufferListener(std::weak_ptr<AudioCaptureBufferListener> bufferListener)
{
    std::lock_guard<std::mutex> lock(bufferListenerMutex_);
    bufferListeners_.insert(bufferListener);
}

void UnifiedPipelineAudioCaptureWrap::RemoveBufferListener(std::weak_ptr<AudioCaptureBufferListener> bufferListener)
{
    std::lock_guard<std::mutex> lock(bufferListenerMutex_);
    bufferListeners_.erase(bufferListener);
}

void UnifiedPipelineAudioCaptureWrap::OnReadBufferStart()
{
    std::lock_guard<std::mutex> lock(bufferListenerMutex_);
    for (auto& listener : bufferListeners_) {
        auto bufferListener = listener.lock();
        if (bufferListener) {
            bufferListener->OnBufferStart();
        }
    }
}

void UnifiedPipelineAudioCaptureWrap::OnReadBuffer(uint8_t* buffer, size_t bufferSize, int64_t timestamp)
{
    std::lock_guard<std::mutex> lock(bufferListenerMutex_);
    CHECK_RETURN_ELOG(bufferSize > BUFFERSIZE_MAX, "bufferSize is valid");
    for (auto& listener : bufferListeners_) {
        auto bufferListener = listener.lock();
        CHECK_CONTINUE(bufferListener == nullptr);
        CHECK_CONTINUE(runningState_ != State::STARTED);
        auto bufferCopy = std::make_unique<uint8_t[]>(bufferSize);
        memcpy_s(bufferCopy.get(), bufferSize, buffer, bufferSize);
        bufferListener->OnBufferArrival(timestamp, std::move(bufferCopy), bufferSize);
    }
}

void UnifiedPipelineAudioCaptureWrap::FillEmptyBuffer(size_t oneBufferSize, int64_t baseTimestamp, int32_t count)
{
    int64_t startTimestamp = baseTimestamp - ONE_FRAME_OFFSET * count;
    MEDIA_INFO_LOG("UnifiedPipelineAudioCaptureWrap::FillEmptyBuffer timestampRange:%{public}" PRIi64
                   " - %{public}" PRIi64,
        startTimestamp, baseTimestamp);
    std::lock_guard<std::mutex> lock(bufferListenerMutex_);
    for (int32_t i = 0; i < count; i++) {
        int64_t timestamp = startTimestamp + i * ONE_FRAME_OFFSET;
        for (auto& listener : bufferListeners_) {
            auto bufferListener = listener.lock();
            CHECK_CONTINUE(bufferListener == nullptr);
            CHECK_CONTINUE(runningState_ != State::STARTED);
            auto bufferCopy = std::make_unique<uint8_t[]>(oneBufferSize);
            memset_s(bufferCopy.get(), oneBufferSize, 0, oneBufferSize);
            bufferListener->OnBufferArrival(timestamp, std::move(bufferCopy), oneBufferSize);
        }
    }
}

void UnifiedPipelineAudioCaptureWrap::OnReadBufferEnd()
{
    std::lock_guard<std::mutex> lock(bufferListenerMutex_);
    for (auto& listener : bufferListeners_) {
        auto bufferListener = listener.lock();
        if (bufferListener) {
            bufferListener->OnBufferEnd();
        }
    }
}

void UnifiedPipelineAudioCaptureWrap::ProcessAudioBuffer()
{
    static constexpr int64_t SEC_TO_MICROSEC = 1000000LL;
    static constexpr int64_t MICROSEC_TO_NANOSEC = 1000LL;
    auto audioCapture = GetAudioCapture();
    CHECK_RETURN_ELOG(audioCapture == nullptr, "AudioCapturer_ is not init");
    auto bufferLen = captureBufferSize_;
    std::vector<uint8_t> bufferCache(bufferLen, 0); // 全初始化为 0
    while (true) {
        CHECK_RETURN_WLOG(!isCaptureAlive_, "Audio capture work done, return");
        size_t bytesRead = 0;
        do {
            CHECK_RETURN_WLOG(!isCaptureAlive_, "ProcessAudioBuffer loop not alive, return");
            if (runningState_ != State::STARTED) {
                bytesRead = 0;
                std::this_thread::sleep_for(std::chrono::milliseconds(MOVIE_FILE_AUDIO_READ_WAIT_TIME));
                continue;
            }
            int32_t len = audioCapture->Read(*(bufferCache.data() + bytesRead), bufferLen - bytesRead, true);
            if (len > 0) {
                bytesRead += static_cast<size_t>(len);
            } else if (len == 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(MOVIE_FILE_AUDIO_READ_WAIT_TIME));
            } else {
                bytesRead = 0;
                std::this_thread::sleep_for(std::chrono::milliseconds(MOVIE_FILE_AUDIO_READ_WAIT_TIME));
            }
        } while (bytesRead < bufferLen);
        AudioStandard::Timestamp timestamp;
        audioCapture->GetTimeStampInfo(timestamp, AudioStandard::Timestamp::Timestampbase::MONOTONIC);
        int64_t microTimestamp =
            (timestamp.time.tv_sec * SEC_TO_MICROSEC + timestamp.time.tv_nsec / MICROSEC_TO_NANOSEC);
        int64_t nowTime = GetMicroTickCount() - ONE_FRAME_OFFSET;
        int64_t diff = abs(nowTime - microTimestamp);
        if (diff > MOVIE_FILE_AUDIO_MILLION) { // 时间戳出错兜底方案
            MEDIA_ERR_LOG("audioCapture::GetTimeStampInfo error: microTimestamp:%{public} " PRIi64
                          "nowtime:%{public}" PRIi64 "Difference:%{public}" PRIi64,
                microTimestamp, nowTime, diff);
            microTimestamp = nowTime;
        }
        if (!isReadFirstFrame_) {
            FillEmptyBuffer(bufferLen, microTimestamp,
                BLUETOOTH_DELAY_FRAME); // 蓝牙场景音频延迟可能有1s，这里进行对应处理，避免音频时长短导致视频播放加速
            isReadFirstFrame_ = true;
        }
        OnReadBuffer(bufferCache.data(), bytesRead, microTimestamp);
    }
}

AudioStandard::AudioChannel UnifiedPipelineAudioCaptureWrap::GetMicNum()
{
    MEDIA_INFO_LOG("UnifiedPipelineAudioCaptureWrap::getMicNum");
    std::string mainKey = "device_status";
    std::vector<std::string> subKeys = { "hardware_info#mic_num" };
    std::vector<std::pair<std::string, std::string>> result = {};
    AudioStandard::AudioSystemManager* audioSystemMgr = AudioStandard::AudioSystemManager::GetInstance();
    CHECK_RETURN_RET_WLOG(audioSystemMgr == nullptr, AudioStandard::AudioChannel::STEREO,
        "UnifiedPipelineAudioCaptureWrap::getMicNum GetAudioSystemManagerInstance err");
    int32_t ret = audioSystemMgr->GetExtraParameters(mainKey, subKeys, result);
    CHECK_RETURN_RET_WLOG(ret != 0, AudioStandard::AudioChannel::STEREO,
        "UnifiedPipelineAudioCaptureWrap::getMicNum GetExtraParameters err");
    CHECK_RETURN_RET_WLOG(result.empty() || result[0].second.empty() || result[0].first.empty(),
        AudioStandard::AudioChannel::STEREO, "UnifiedPipelineAudioCaptureWrap::getMicNum result empty");
    for (auto i : result[0].second) {
        CHECK_RETURN_RET_WLOG(!std::isdigit(i), AudioStandard::AudioChannel::STEREO,
            "UnifiedPipelineAudioCaptureWrap::getMicNum result illegal");
    }
    int32_t micNum = 0;
    if (!StrToInt(result[0].second, micNum)) {
        MEDIA_WARNING_LOG("Convert micNum failed");
        return AudioStandard::AudioChannel::STEREO;
    }
    int32_t oddFlag = micNum % 2; // 2 is odd channel + 1
    MEDIA_INFO_LOG("UnifiedPipelineAudioCaptureWrap::getMicNum %{public}d + %{public}d", micNum, oddFlag);
    // odd channel should + 1
    return static_cast<AudioStandard::AudioChannel>(micNum + oddFlag);
}
} // namespace CameraStandard
} // namespace OHOS