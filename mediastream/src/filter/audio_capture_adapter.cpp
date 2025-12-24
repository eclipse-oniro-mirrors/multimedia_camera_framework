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

#include "audio_capture_adapter.h"

#include "audio_errors.h"
#include "audio_session_manager.h"
#include "camera_log.h"
#include "errors.h"
#include "source/audio_capture/audio_type_translate.h"

// LCOV_EXCL_START
namespace OHOS {
namespace CameraStandard {
namespace {
    constexpr size_t MAX_CAPTURE_BUFFER_SIZE = 100000;
    constexpr uint64_t AUDIO_NS_PER_SECOND = 1000000000;
    constexpr uint64_t AUDIO_CAPTURE_READ_FRAME_TIME = 20000000; // 20000000 ns 20ms
}

class AudioCapturerCallbackImpl : public AudioStandard::AudioCapturerCallback {
public:
    explicit AudioCapturerCallbackImpl(std::shared_ptr<AudioCaptureAdapterCallback> audioCaptureAdapterCallback)
        : audioCaptureAdapterCallback_(audioCaptureAdapterCallback)
    {
    }

    void OnInterrupt(const AudioStandard::InterruptEvent &interruptEvent) override
    {
        MEDIA_ERR_LOG("AudioCapture OnInterrupt Hint: %{public}d, FilterEventType: %{public}d, forceType: %{public}d",
            interruptEvent.hintType, interruptEvent.eventType, interruptEvent.forceType);
        if (audioCaptureAdapterCallback_ != nullptr) {
            MEDIA_INFO_LOG("audioCaptureAdapterCallback_ send info to audioCaptureFilter");
            audioCaptureAdapterCallback_->OnInterrupt("AudioCapture OnInterrupt");
        }
    }

    void OnStateChange(const AudioStandard::CapturerState state) override
    {
    }

private:
    std::shared_ptr<AudioCaptureAdapterCallback> audioCaptureAdapterCallback_;
};

AudioCaptureAdapter::AudioCaptureAdapter()
{
}

AudioCaptureAdapter::~AudioCaptureAdapter()
{
    DoDeinit();
}

Status AudioCaptureAdapter::Init()
{
    std::lock_guard lock(captureMutex_);
    if (audioCapturer_ == nullptr) {
        AudioStandard::AppInfo appInfo;
        appInfo.appTokenId = static_cast<uint32_t>(appTokenId_);
        appInfo.appUid = appUid_;
        appInfo.appPid = appPid_;
        appInfo.appFullTokenId = static_cast<uint64_t>(appFullTokenId_);
        audioCapturer_ = AudioStandard::AudioCapturer::Create(options_, appInfo);
        MEDIA_INFO_LOG("options_ info, samplingRate:%{public}u, encoding:%{public}d, format:%{public}d, "
                       "channels:%{public}d, sourceType:%{public}d, capturerFlags:%{public}d",
                       options_.streamInfo.samplingRate, options_.streamInfo.encoding, options_.streamInfo.format,
                       options_.streamInfo.channels, options_.capturerInfo.sourceType,
                       options_.capturerInfo.capturerFlags);
        if (audioCapturer_ == nullptr) {
            MEDIA_ERR_LOG("Create audioCapturer fail");
            SetFaultEvent("AudioCaptureAdapter::Init, create audioCapturer fail");
            return Status::ERROR_UNKNOWN;
        }
        audioInterruptCallback_ = std::make_shared<AudioCapturerCallbackImpl>(audioCaptureAdapterCallback_);
        audioCapturer_->SetCapturerCallback(audioInterruptCallback_);
        AudioStandard::AudioSessionStrategy sessionStrategy;
        sessionStrategy.concurrencyMode = AudioStandard::AudioConcurrencyMode::PAUSE_OTHERS;
        AudioStandard::AudioSessionManager::GetInstance()->ActivateAudioSession(sessionStrategy);
    }
    return Status::OK;
}

Status AudioCaptureAdapter::DoDeinit()
{
    std::lock_guard lock(captureMutex_);
    if (audioCapturer_) {
        if (audioCapturer_->GetStatus() == AudioStandard::CapturerState::CAPTURER_RUNNING) {
            CHECK_PRINT_ELOG(!audioCapturer_->Stop(), "stop audioCapturer fail");
        }
        CHECK_PRINT_ELOG(!audioCapturer_->Release(), "Release audioCapturer fail");
        audioCapturer_->RemoveAudioCapturerInfoChangeCallback(audioCapturerInfoChangeCallback_);
        audioCapturer_ = nullptr;
    }
    return Status::OK;
}

Status AudioCaptureAdapter::Deinit()
{
    MEDIA_INFO_LOG("Deinit");
    return DoDeinit();
}

Status AudioCaptureAdapter::Prepare()
{
    MEDIA_INFO_LOG("Prepare enter.");
    size_t size;
    {
        std::lock_guard lock(captureMutex_);
        CHECK_RETURN_RET_ELOG(audioCapturer_ == nullptr, Status::ERROR_WRONG_STATE, "no available audio capture");
        auto ret = audioCapturer_->GetBufferSize(size);
        CHECK_RETURN_RET_ELOG(ret != 0, AudioCaptureModule::Error2Status(ret),
            "audioCapturer GetBufferSize failed, ret: %{public}d", ret);
    }
    CHECK_RETURN_RET_ELOG(
        size >= MAX_CAPTURE_BUFFER_SIZE, Status::ERROR_INVALID_PARAMETER, "bufferSize is too big: %{public}zu", size);
    bufferSize_ = options_.streamInfo.samplingRate * options_.streamInfo.channels * sizeof(short) *
                  AUDIO_CAPTURE_READ_FRAME_TIME / AUDIO_NS_PER_SECOND;
    MEDIA_INFO_LOG("bufferSize is: %{public}zu", bufferSize_);
    return Status::OK;
}

Status AudioCaptureAdapter::Reset()
{
    MEDIA_INFO_LOG("Reset enter.");
    {
        std::lock_guard lock(captureMutex_);
        CHECK_RETURN_RET_ELOG(audioCapturer_ == nullptr, Status::ERROR_WRONG_STATE, "no available audio capture");
        if (audioCapturer_->GetStatus() == AudioStandard::CapturerState::CAPTURER_RUNNING) {
            CHECK_PRINT_ELOG(!audioCapturer_->Stop(), "Stop audioCapturer fail");
        }
    }
    bufferSize_ = 0;
    bitRate_ = 0;
    options_ = AudioStandard::AudioCapturerOptions();
    return Status::OK;
}

Status AudioCaptureAdapter::Start()
{
    MEDIA_INFO_LOG("start enter.");
    std::lock_guard lock(captureMutex_);
    CHECK_RETURN_RET_ELOG(audioCapturer_ == nullptr, Status::ERROR_WRONG_STATE, "no available audio capture");
    if (audioCapturer_->GetStatus() != AudioStandard::CapturerState::CAPTURER_RUNNING) {
        if (!audioCapturer_->Start()) {
            MEDIA_ERR_LOG("audioCapturer start failed");
            SetFaultEvent("AudioCaptureAdapter::Start error");
            return Status::ERROR_UNKNOWN;
        }
    }
    isTrackMaxAmplitude = false;
    return Status::OK;
}

Status AudioCaptureAdapter::Stop()
{
    MEDIA_INFO_LOG("stop enter.");
    std::lock_guard lock(captureMutex_);
    if (audioCapturer_ && audioCapturer_->GetStatus() == AudioStandard::CAPTURER_RUNNING) {
        if (!audioCapturer_->Stop()) {
            MEDIA_ERR_LOG("Stop audioCapturer fail");
            SetFaultEvent("AudioCaptureAdapter::Stop error");
            return Status::ERROR_UNKNOWN;
        }
    }
    return Status::OK;
}

Status AudioCaptureAdapter::GetParameter(std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("GetParameter enter.");
    AudioStandard::AudioCapturerParams params;
    {
        std::lock_guard lock(captureMutex_);
        CHECK_RETURN_RET(!audioCapturer_, Status::ERROR_WRONG_STATE);
        auto ret = audioCapturer_->GetParams(params);
        CHECK_RETURN_RET_ELOG(
            ret != 0, AudioCaptureModule::Error2Status(ret), "audioCapturer GetParams failed, ret: %{public}d", ret);
    }

    CHECK_PRINT_WLOG(params.samplingRate != options_.streamInfo.samplingRate,
        "samplingRate has changed from %{public}u to %{public}u", options_.streamInfo.samplingRate,
        params.samplingRate);
    CHECK_RETURN_RET_ELOG(meta == nullptr, Status::ERROR_NULL_POINTER, "meta is null, set audio sample rate");
    CHECK_PRINT_ELOG(!meta->Set<Tag::AUDIO_SAMPLE_RATE>(params.samplingRate), "set samplingRate failed.");

    CHECK_PRINT_WLOG(params.audioChannel != options_.streamInfo.channels,
        "audioChannel has changed from %{public}u to %{public}u", options_.streamInfo.channels, params.audioChannel);
    CHECK_RETURN_RET_ELOG(meta == nullptr, Status::ERROR_NULL_POINTER, "meta is null, set audio channel");
    CHECK_PRINT_ELOG(!meta->Set<Tag::AUDIO_CHANNEL_COUNT>(params.audioChannel), "set audioChannel failed.");

    CHECK_PRINT_WLOG(params.audioSampleFormat != options_.streamInfo.format,
        "audioSampleFormat has changed from %{public}u to %{public}u", options_.streamInfo.format,
        params.audioSampleFormat);
    CHECK_RETURN_RET_ELOG(meta == nullptr, Status::ERROR_NULL_POINTER, "meta is null, set audio sample format");
    CHECK_PRINT_ELOG(
        !meta->Set<Tag::AUDIO_SAMPLE_FORMAT>(static_cast<Plugins::AudioSampleFormat>(params.audioSampleFormat)),
        "set audioSampleFormat failed.");

    CHECK_RETURN_RET_ELOG(meta == nullptr, Status::ERROR_NULL_POINTER, "meta is null, set audio bitrate");
    CHECK_PRINT_ELOG(!meta->Set<Tag::MEDIA_BITRATE>(bitRate_), "set bitRate failed.");
    return Status::OK;
}

Status AudioCaptureAdapter::SetParameter(const std::shared_ptr<Meta> &meta)
{
    CHECK_PRINT_ELOG(!meta->Get<Tag::APP_TOKEN_ID>(appTokenId_), "Unknown APP_TOKEN_ID");
    CHECK_PRINT_ELOG(!meta->Get<Tag::APP_UID>(appUid_), "Unknown APP_UID");
    CHECK_PRINT_ELOG(!meta->Get<Tag::APP_PID>(appPid_), "Unknown APP_PID");
    CHECK_PRINT_ELOG(!meta->Get<Tag::APP_FULL_TOKEN_ID>(appFullTokenId_), "Unknown appFullTokenId_");
    CHECK_PRINT_ELOG(!meta->Get<Tag::MEDIA_BITRATE>(bitRate_), "Unknown MEDIA_BITRATE");

    int32_t sampleRate = 0;
    if (meta->Get<Tag::AUDIO_SAMPLE_RATE>(sampleRate)) {
        CHECK_RETURN_RET_ELOG(!AssignSampleRateIfSupported(sampleRate), Status::ERROR_INVALID_PARAMETER,
            "SampleRate is unsupported by audiocapturer");
    }

    int32_t channelCount = 0;
    if (meta->Get<Tag::AUDIO_CHANNEL_COUNT>(channelCount)) {
        CHECK_RETURN_RET_ELOG(!AssignChannelNumIfSupported(channelCount), Status::ERROR_INVALID_PARAMETER,
            "ChannelNum is unsupported by audiocapturer");
    }

    Plugins::AudioSampleFormat sampleFormat;
    if (meta->Get<Tag::AUDIO_SAMPLE_FORMAT>(sampleFormat)) {
        CHECK_RETURN_RET_ELOG(!AssignSampleFmtIfSupported(static_cast<Plugins::AudioSampleFormat>(sampleFormat)),
            Status::ERROR_INVALID_PARAMETER, "SampleFormat is unsupported by audiocapturer");
    }

    AudioStandard::AudioEncodingType audioEncoding = AudioStandard::ENCODING_INVALID;
    auto supportedEncodingTypes = OHOS::AudioStandard::AudioCapturer::GetSupportedEncodingTypes();
    for (auto& supportedEncodingType : supportedEncodingTypes) {
        if (supportedEncodingType == AudioStandard::ENCODING_PCM) {
            audioEncoding = AudioStandard::ENCODING_PCM;
            break;
        }
    }

    if (audioEncoding != AudioStandard::ENCODING_PCM) {
        MEDIA_ERR_LOG("audioCapturer do not support pcm encoding");
        SetFaultEvent("AudioCaptureAdapter::Prepare, audioCapturer do not support pcm encoding");
        return Status::ERROR_UNKNOWN;
    }
    options_.streamInfo.encoding = AudioStandard::ENCODING_PCM;
    return Status::OK;
}

bool AudioCaptureAdapter::AssignSampleRateIfSupported(const int32_t value)
{
    uint32_t sampleRate = static_cast<uint32_t>(value);
    AudioStandard::AudioSamplingRate aRate = AudioStandard::SAMPLE_RATE_8000;
    CHECK_RETURN_RET_ELOG(!AudioCaptureModule::SampleRateNum2Enum(sampleRate, aRate), false,
        "sample rate: %{public}u not supported", sampleRate);
    for (const auto& rate : AudioStandard::AudioCapturer::GetSupportedSamplingRates()) {
        if (rate == sampleRate) {
            options_.streamInfo.samplingRate = rate;
            return true;
        }
    }
    return false;
}

bool AudioCaptureAdapter::AssignChannelNumIfSupported(const int32_t value)
{
    uint32_t channelNum = static_cast<uint32_t>(value);
    for (const auto& channel : AudioStandard::AudioCapturer::GetSupportedChannels()) {
        if (channel == channelNum) {
            options_.streamInfo.channels = channel;
            return true;
        }
    }
    return false;
}

bool AudioCaptureAdapter::AssignSampleFmtIfSupported(const Plugins::AudioSampleFormat value)
{
    Plugins::AudioSampleFormat sampleFormat = value;
    AudioStandard::AudioSampleFormat aFmt = AudioStandard::AudioSampleFormat::INVALID_WIDTH;
    CHECK_RETURN_RET_ELOG(!AudioCaptureModule::ModuleFmt2SampleFmt(sampleFormat, aFmt), false,
        "sample format %{public}u not supported", static_cast<uint8_t>(sampleFormat));
    for (const auto& fmt : AudioStandard::AudioCapturer::GetSupportedFormats()) {
        if (fmt == aFmt) {
            options_.streamInfo.format = fmt;
            return true;
        }
    }
    return false;
}

Status AudioCaptureAdapter::Read(std::shared_ptr<AVBuffer> &buffer, size_t expectedLen)
{
    MEDIA_DEBUG_LOG("AudioCaptureAdapter Read");
    auto bufferMeta = buffer->meta_;
    CHECK_RETURN_RET(!bufferMeta, Status::ERROR_INVALID_PARAMETER);
    std::shared_ptr<AVMemory> bufData = buffer->memory_;
    CHECK_RETURN_RET(bufData->GetCapacity() <= 0, Status::ERROR_NO_MEMORY);
    auto size = 0;
    Status ret = Status::OK;
    {
        std::lock_guard lock(captureMutex_);
        CHECK_RETURN_RET_ELOG(audioCapturer_ == nullptr, Status::ERROR_WRONG_STATE, "Audio capture is null");
        CHECK_RETURN_RET(audioCapturer_->GetStatus() != AudioStandard::CAPTURER_RUNNING, Status::ERROR_AGAIN);
        auto addr = bufData->GetAddr();
        CHECK_RETURN_RET(addr == nullptr, Status::ERROR_INVALID_PARAMETER);
        size = audioCapturer_->Read(*addr, expectedLen, true);
        static constexpr int64_t SEC_TO_MICROSEC = 1000000LL;
        static constexpr int64_t MICROSEC_TO_NANOSEC = 1000LL;
        AudioStandard::Timestamp timestamp;
        audioCapturer_->GetTimeStampInfo(timestamp, AudioStandard::Timestamp::Timestampbase::MONOTONIC);
        int64_t microTimestamp =
            (timestamp.time.tv_sec * SEC_TO_MICROSEC + timestamp.time.tv_nsec / MICROSEC_TO_NANOSEC);
        buffer->pts_ = microTimestamp;
        MEDIA_DEBUG_LOG(
            "read size: %{public}d, expectedLen:%{public}zu, ts:%{public}" PRId64, size, expectedLen, microTimestamp);
    }
    CHECK_RETURN_RET_ELOG(size < 0, Status::ERROR_NOT_ENOUGH_DATA, "audioCapturer Read() fail");

    if (isTrackMaxAmplitude) {
        TrackMaxAmplitude(reinterpret_cast<int16_t *>(bufData->GetAddr()),
            static_cast<int32_t>(static_cast<uint32_t>(bufData->GetSize()) >> 1));
    }
    return ret;
}

Status AudioCaptureAdapter::Read(uint8_t *cacheAudioData, size_t expectedLen)
{
    MEDIA_DEBUG_LOG("AudioCaptureModule Read");
    auto size = 0;
    {
        std::lock_guard lock(captureMutex_);
        CHECK_RETURN_RET_ELOG(audioCapturer_ == nullptr, Status::ERROR_WRONG_STATE, "Audio capture is null");
        CHECK_RETURN_RET_ELOG(audioCapturer_->GetStatus() != AudioStandard::CAPTURER_RUNNING,
            Status::ERROR_AGAIN, "Audio capture Status error");
        CHECK_RETURN_RET_ELOG(cacheAudioData == nullptr, Status::ERROR_UNKNOWN, "cacheAudioData is null");
        size = audioCapturer_->Read(*cacheAudioData, expectedLen, true);
    }
    CHECK_RETURN_RET_ELOG(size < 0, Status::ERROR_NOT_ENOUGH_DATA, "audioCapturer Read() fail");

    if (isTrackMaxAmplitude) {
        TrackMaxAmplitude(reinterpret_cast<int16_t *>(cacheAudioData),
            static_cast<int32_t>(static_cast<uint32_t>(size) >> 1));
    }
    return Status::OK;
}

void AudioCaptureAdapter::GetAudioTime(int64_t &audioDataTime, bool isFirstFrame)
{
    MEDIA_DEBUG_LOG("AudioCaptureModule GetAudioTime");
    bool ret = true;
    {
        std::lock_guard lock(captureMutex_);
        CHECK_RETURN_ELOG(audioCapturer_ == nullptr, "Audio capture is null");
        CHECK_RETURN_ELOG(audioCapturer_->GetStatus() != AudioStandard::CAPTURER_RUNNING,
            "Audio capture Status error");
        AudioStandard::Timestamp timestamp{};
        ret = audioCapturer_->GetTimeStampInfo(timestamp, AudioStandard::Timestamp::Timestampbase::MONOTONIC);
        CHECK_RETURN_ELOG(!ret, "audioCapturer GetAudioTime fail");

        audioDataTime = static_cast<int64_t>(timestamp.time.tv_sec) * AUDIO_NS_PER_SECOND
            + static_cast<int64_t>(timestamp.time.tv_nsec);
        MEDIA_DEBUG_LOG("GetTimeStampInfo audioDataTime: %{public}" PRId64, audioDataTime);

        if (isFirstFrame) {
            audioDataTime -= AUDIO_CAPTURE_READ_FRAME_TIME;
        }
    }
}

Status AudioCaptureAdapter::GetSize(uint64_t& size)
{
    CHECK_RETURN_RET(bufferSize_ == 0, Status::ERROR_INVALID_PARAMETER);
    size = bufferSize_;
    return Status::OK;
}

Status AudioCaptureAdapter::SetAudioInterruptListener(const std::shared_ptr<AudioCaptureAdapterCallback> &callback)
{
    CHECK_RETURN_RET_ELOG(callback == nullptr, Status::ERROR_INVALID_PARAMETER,
        "SetAudioInterruptListener callback input param is nullptr");
    audioCaptureAdapterCallback_ = callback;
    return Status::OK;
}

Status AudioCaptureAdapter::SetAudioCapturerInfoChangeCallback(
    const std::shared_ptr<AudioStandard::AudioCapturerInfoChangeCallback> &callback)
{
    CHECK_RETURN_RET(audioCapturer_ == nullptr, Status::ERROR_WRONG_STATE);
    audioCapturerInfoChangeCallback_ = callback;
    int32_t ret = audioCapturer_->SetAudioCapturerInfoChangeCallback(audioCapturerInfoChangeCallback_);
    if (ret != (int32_t)Status::OK) {
        MEDIA_ERR_LOG("SetAudioCapturerInfoChangeCallback fail error code: %{public}d", ret);
        SetFaultEvent("SetAudioCapturerInfoChangeCallback error", ret);
        return Status::ERROR_UNKNOWN;
    }
    return Status::OK;
}

Status AudioCaptureAdapter::GetCurrentCapturerChangeInfo(AudioStandard::AudioCapturerChangeInfo &changeInfo)
{
    CHECK_RETURN_RET_ELOG(audioCapturer_ == nullptr, Status::ERROR_INVALID_OPERATION,
        "audioCapturer is nullptr, cannot get audio capturer change info");
    audioCapturer_->GetCurrentCapturerChangeInfo(changeInfo);
    return Status::OK;
}

int32_t AudioCaptureAdapter::GetMaxAmplitude()
{
    if (!isTrackMaxAmplitude) {
        isTrackMaxAmplitude = true;
    }
    int16_t value = maxAmplitude_;
    maxAmplitude_ = 0;
    return value;
}

void AudioCaptureAdapter::SetAudioSource(AudioStandard::SourceType source)
{
    options_.capturerInfo.sourceType = source;
}

void AudioCaptureAdapter::TrackMaxAmplitude(int16_t *data, int32_t size)
{
    for (int32_t i = 0; i < size; i++) {
        int16_t value = *data++;
        if (value < 0) {
            value = -value;
        }
        if (maxAmplitude_ < value) {
            maxAmplitude_ = value;
        }
    }
}

void AudioCaptureAdapter::SetFaultEvent(const std::string &errMsg, int32_t ret)
{
    SetFaultEvent(errMsg + ", ret = " + std::to_string(ret));
}

void AudioCaptureAdapter::SetFaultEvent(const std::string &errMsg)
{
}

void AudioCaptureAdapter::SetCallingInfo(int32_t appUid, int32_t appPid,
    const std::string &bundleName, uint64_t instanceId)
{
    appUid_ = appUid;
    appPid_ = appPid;
    bundleName_ = bundleName;
    instanceId_ = instanceId;
}

Status AudioCaptureAdapter::GetAudioCaptureOptions(AudioCapturerOptions& options)
{
    options = options_;
    return Status::OK;
}
} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP