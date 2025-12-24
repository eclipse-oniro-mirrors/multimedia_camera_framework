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

#include "audio_capture_filter.h"

#include "camera_log.h"
#include "cfilter.h"
#include "cfilter_factory.h"

// LCOV_EXCL_START
namespace OHOS {
namespace CameraStandard {
namespace {
    constexpr uint64_t AUDIO_NS_PER_SECOND = 1000000000;
    constexpr int64_t AUDIO_UNREGULAR_DELTA_TIME = 100000000;
    constexpr int64_t AUDIO_CAPTURE_READ_FAILED_WAIT_TIME = 20000000; // 20000000 us 20ms
    constexpr int64_t AUDIO_CAPTURE_READ_FRAME_TIME = 20000000; // 20000000 ns 20ms
    constexpr int64_t AUDIO_CAPTURE_READ_FRAME_TIME_HALF = 10000000;
    constexpr int32_t AUDIO_CAPTURE_MAX_CACHED_FRAMES = 256;
    constexpr int32_t AUDIO_RECORDER_FRAME_NUM = 5;
    constexpr uint64_t MAX_CAPTURE_BUFFER_SIZE = 100000;
    constexpr uint32_t TIME_OUT_MS = 0;
    // End of Stream Buffer Flag
    constexpr uint32_t BUFFER_FLAG_EOS = 0x00000001;
}

static AutoRegisterCFilter<AudioCaptureFilter> g_registerAudioCaptureFilter("camera.audiocapture",
    CFilterType::AUDIO_CAPTURE,
    [](const std::string& name, const CFilterType type) {
        return std::make_shared<AudioCaptureFilter>(name, CFilterType::AUDIO_CAPTURE);
    });

class AudioCaptureFilterLinkCallback : public CFilterLinkCallback {
public:
    explicit AudioCaptureFilterLinkCallback(std::shared_ptr<AudioCaptureFilter> audioCaptureFilter)
        : audioCaptureFilter_(std::move(audioCaptureFilter))
    {
    }

    void OnLinkedResult(const sptr<AVBufferQueueProducer> &queue, std::shared_ptr<Meta> &meta) override
    {
        if (auto captureFilter = audioCaptureFilter_.lock()) {
            captureFilter->OnLinkedResult(queue, meta);
        } else {
            MEDIA_INFO_LOG("invalid captureFilter");
        }
    }

    void OnUnlinkedResult(std::shared_ptr<Meta> &meta) override
    {
        if (auto captureFilter = audioCaptureFilter_.lock()) {
            captureFilter->OnUnlinkedResult(meta);
        } else {
            MEDIA_INFO_LOG("invalid captureFilter");
        }
    }

    void OnUpdatedResult(std::shared_ptr<Meta> &meta) override
    {
        if (auto captureFilter = audioCaptureFilter_.lock()) {
            captureFilter->OnUpdatedResult(meta);
        } else {
            MEDIA_INFO_LOG("invalid captureFilter");
        }
    }

private:
    std::weak_ptr<AudioCaptureFilter> audioCaptureFilter_;
};

class AudioCaptureAdapterCallbackImpl : public AudioCaptureAdapterCallback {
public:
    explicit AudioCaptureAdapterCallbackImpl(std::shared_ptr<CEventReceiver> receiver)
        : receiver_(receiver)
    {
    }
    void OnInterrupt(const std::string &interruptInfo) override
    {
        MEDIA_INFO_LOG("AudioCaptureAdapterCallback interrupt: %{public}s", interruptInfo.c_str());
        receiver_->OnEvent({"audio_capture_filter", FilterEventType::EVENT_ERROR, Status::ERROR_AUDIO_INTERRUPT});
    }
private:
    std::shared_ptr<CEventReceiver> receiver_;
};

AudioCaptureFilter::AudioCaptureFilter(std::string name, CFilterType type): CFilter(name, type)
{
    MEDIA_INFO_LOG("audio capture filter create");
}

AudioCaptureFilter::~AudioCaptureFilter()
{
    MEDIA_INFO_LOG("audio capture filter destroy");
    DoRelease();
}

void AudioCaptureFilter::Init(const std::shared_ptr<CEventReceiver> &receiver,
    const std::shared_ptr<CFilterCallback> &callback)
{
    MEDIA_INFO_LOG("Init");
    CAMERA_SYNC_TRACE;
    receiver_ = receiver;
    callback_ = callback;
    audioCaptureModule_ = std::make_shared<AudioCaptureAdapter>();
    auto cb = std::make_shared<AudioCaptureAdapterCallbackImpl>(receiver_);
    CHECK_RETURN_ELOG(audioCaptureModule_ == nullptr, "AudioCaptureFilter audioCaptureModule_ is nullptr, Init fail.");
    Status cbError = audioCaptureModule_->SetAudioInterruptListener(cb);
    CHECK_PRINT_ELOG(cbError != Status::OK, "audioCaptureModule_ SetAudioInterruptListener failed.");
    audioCaptureModule_->SetAudioSource(sourceType_);
    audioCaptureModule_->SetParameter(audioCaptureConfig_);
    audioCaptureModule_->SetCallingInfo(appUid_, appPid_, bundleName_, instanceId_);
    Status err = audioCaptureModule_->Init();
    if (err != Status::OK) {
        MEDIA_ERR_LOG("Init audioCaptureModule fail");
        receiver_->OnEvent({"audio_capture_filter", FilterEventType::EVENT_ERROR, Status::ERROR_PERMISSION_DENIED});
    }
}

Status AudioCaptureFilter::PrepareAudioCapture()
{
    MEDIA_INFO_LOG("PrepareAudioCapture");
    CAMERA_SYNC_TRACE;
    if (!taskPtr_) {
        taskPtr_ = std::make_shared<Task>("DataReader", groupId_);
        taskPtr_->RegisterJob([this] {
            ReadLoop();
            return 0;
        });
    }

    Status err = audioCaptureModule_->Prepare();
    CHECK_PRINT_ELOG(err != Status::OK, "audioCaptureModule prepare fail");
    return err;
}

Status AudioCaptureFilter::SetAudioCaptureChangeCallback(
    const std::shared_ptr<AudioStandard::AudioCapturerInfoChangeCallback> &callback)
{
    CHECK_RETURN_RET(audioCaptureModule_ == nullptr, Status::ERROR_WRONG_STATE);
    return audioCaptureModule_->SetAudioCapturerInfoChangeCallback(callback);
}

Status AudioCaptureFilter::DoPrepare()
{
    MEDIA_INFO_LOG("Prepare");
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(callback_ == nullptr, Status::ERROR_NULL_POINTER, "callback is nullptr");
    return callback_->OnCallback(shared_from_this(), CFilterCallBackCommand::NEXT_FILTER_NEEDED,
        CStreamType::RAW_AUDIO);
}

Status AudioCaptureFilter::DoStart()
{
    MEDIA_INFO_LOG("Start");
    CAMERA_SYNC_TRACE;
    eos_ = false;
    currentTime_ = 0;
    firstAudioFramePts_.store(-1);
    firstVideoFramePts_.store(-1);
    hasCalculateAVTime_ = false;
    GetCurrentTime(startTime_);
    MEDIA_INFO_LOG("[audio] startTime_: %{public}" PRId64, startTime_);
    auto res = Status::ERROR_INVALID_OPERATION;
    // start audioCaptureModule firstly
    if (audioCaptureModule_) {
        res = audioCaptureModule_->Start();
    }
    CHECK_RETURN_RET_ELOG(res != Status::OK, res, "start audioCaptureModule failed");
    // start task secondly
    if (taskPtr_) {
        taskPtr_->Start();
    }
    return res;
}

Status AudioCaptureFilter::DoPause()
{
    MEDIA_INFO_LOG("Pause");
    CAMERA_SYNC_TRACE;
    if (taskPtr_) {
        taskPtr_->Pause();
    }
    Status ret = Status::ERROR_INVALID_OPERATION;
    if (audioCaptureModule_) {
        ret = audioCaptureModule_->Stop();
    }
    CHECK_PRINT_ELOG(ret != Status::OK, "audioCaptureModule stop fail");

    GetCurrentTime(pauseTime_);
    MEDIA_INFO_LOG("[audio] pauseTime: %{public}" PRId64, pauseTime_);
    CHECK_RETURN_RET(!withVideo_, ret);
    int32_t lostCount = 0;
    if (currentTime_ != 0 && currentTime_ < pauseTime_) {
        lostCount = ((pauseTime_ - currentTime_) + AUDIO_CAPTURE_READ_FRAME_TIME_HALF)
            / AUDIO_CAPTURE_READ_FRAME_TIME;
    } else if (currentTime_ == 0) {
        lostCount = ((pauseTime_ - startTime_ + AUDIO_CAPTURE_READ_FRAME_TIME_HALF)
            / AUDIO_CAPTURE_READ_FRAME_TIME) - static_cast<int64_t>(cachedAudioDataDeque_.size());
        MEDIA_INFO_LOG("[audio] no video frame return, fill audio frame by startTime");
    }
    if (lostCount > AUDIO_CAPTURE_MAX_CACHED_FRAMES) {
        // time diff is abnormal, do not fill data frame.
        MEDIA_INFO_LOG("[audio] abnormal time diff, please check");
    } else {
        FillLostFrame(lostCount);
    }
    if (!cachedAudioDataDeque_.empty()) {
        RecordCachedData(cachedAudioDataDeque_.size());
    }
    return ret;
}

Status AudioCaptureFilter::DoResume()
{
    MEDIA_INFO_LOG("Resume");
    CAMERA_SYNC_TRACE;
    currentTime_ = 0;
    firstAudioFramePts_.store(-1);
    firstVideoFramePts_.store(-1);
    hasCalculateAVTime_ = false;
    GetCurrentTime(startTime_);
    MEDIA_INFO_LOG("[audio] resumeTime: %{public}" PRId64, startTime_);
    if (taskPtr_) {
        taskPtr_->Start();
    }
    Status ret = Status::ERROR_INVALID_OPERATION;
    if (audioCaptureModule_) {
        ret = audioCaptureModule_->Start();
    }
    CHECK_PRINT_ELOG(ret != Status::OK, "audioCaptureModule start fail");
    return ret;
}

Status AudioCaptureFilter::DoStop()
{
    MEDIA_INFO_LOG("Stop");
    CAMERA_SYNC_TRACE;
    // stop task firstly
    if (taskPtr_) {
        taskPtr_->StopAsync();
    }
    // stop audioCaptureModule secondly
    Status ret = Status::OK;
    if (audioCaptureModule_) {
        ret = audioCaptureModule_->Stop();
    }
    CHECK_PRINT_ELOG(ret != Status::OK, "audioCaptureModule stop fail");
    firstAudioFramePts_.store(-1);
    firstVideoFramePts_.store(-1);
    currentTime_ = 0;
    startTime_ = 0;
    if (!cachedAudioDataDeque_.empty()) {
        RecordCachedData(cachedAudioDataDeque_.size());
    }
    return ret;
}

Status AudioCaptureFilter::DoFlush()
{
    MEDIA_INFO_LOG("Flush");
    return Status::OK;
}

Status AudioCaptureFilter::DoRelease()
{
    MEDIA_INFO_LOG("Release");
    CAMERA_SYNC_TRACE;
    if (taskPtr_) {
        taskPtr_->Stop();
    }
    if (audioCaptureModule_) {
        audioCaptureModule_->Deinit();
    }
    audioCaptureModule_ = nullptr;
    taskPtr_ = nullptr;
    return Status::OK;
}

void AudioCaptureFilter::SetParameter(const std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("SetParameter");
    CAMERA_SYNC_TRACE;
    audioCaptureConfig_ = meta;
}

void AudioCaptureFilter::GetParameter(std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("GetParameter");
    CAMERA_SYNC_TRACE;
    audioCaptureModule_->GetParameter(meta);
}

Status AudioCaptureFilter::LinkNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("LinkNext");
    CAMERA_SYNC_TRACE;
    auto meta = std::make_shared<Meta>();
    GetParameter(meta);
    nextFilter_ = nextFilter;
    nextCFiltersMap_[outType].push_back(nextFilter_);
    std::shared_ptr<CFilterLinkCallback> filterLinkCallback =
        std::make_shared<AudioCaptureFilterLinkCallback>(shared_from_this());
    nextFilter->OnLinked(outType, meta, filterLinkCallback);
    return Status::OK;
}

CFilterType AudioCaptureFilter::GetFilterType()
{
    MEDIA_INFO_LOG("GetFilterType");
    return CFilterType::AUDIO_CAPTURE;
}

void AudioCaptureFilter::SetAudioSource(int32_t source)
{
    if (source == 1) {
        sourceType_ = AudioStandard::SourceType::SOURCE_TYPE_MIC;
    } else {
        sourceType_ = static_cast<AudioStandard::SourceType>(source);
    }
}

Status AudioCaptureFilter::SendEos()
{
    MEDIA_INFO_LOG("SendEos");
    Status ret = Status::OK;
    eos_ = true;
    GetCurrentTime(stopTime_);
    MEDIA_INFO_LOG("[audio] stopTime: %{public}" PRId64, stopTime_);
    if (outputBufferQueue_) {
        if (!cachedAudioDataDeque_.empty()) {
            RecordCachedData(cachedAudioDataDeque_.size());
        }

        std::shared_ptr<AVBuffer> buffer;
        AVBufferConfig avBufferConfig;
        ret = outputBufferQueue_->RequestBuffer(buffer, avBufferConfig, TIME_OUT_MS);
        CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "RequestBuffer fail, ret: %{public}d", ret);
        buffer->flag_ |= BUFFER_FLAG_EOS;
        outputBufferQueue_->PushBuffer(buffer, false);
    }
    return ret;
}

void AudioCaptureFilter::ReadLoop()
{
    MEDIA_DEBUG_LOG("ReadLoop");
    CAMERA_SYNC_TRACE;
    CHECK_RETURN(eos_.load());
    uint64_t bufferSize = 0;
    auto ret = audioCaptureModule_->GetSize(bufferSize);
    if (ret != Status::OK) {
        MEDIA_ERR_LOG("Get audioCaptureModule buffer size fail");
        RelativeSleep(AUDIO_CAPTURE_READ_FAILED_WAIT_TIME);
        return;
    }

    if ((firstVideoFramePts_.load() < 0 || firstAudioFramePts_.load() < 0) && withVideo_) {
        if (cachedAudioDataDeque_.size() > AUDIO_CAPTURE_MAX_CACHED_FRAMES) {
            MEDIA_ERR_LOG("audioCapture cached frame over maxnum");
            firstVideoFramePts_.store(0);
            return;
        }
        auto cachedAudioData = AllocateAudioDataBuffer(bufferSize);
        if (!cachedAudioData) {
            return;
        }
        ret = audioCaptureModule_->Read(cachedAudioData.get(), bufferSize);
        if (ret != Status::OK) {
            MEDIA_ERR_LOG("audioCaptureModule read return again");
            RelativeSleep(AUDIO_CAPTURE_READ_FAILED_WAIT_TIME);
            return;
        }
        if (firstAudioFramePts_.load() < 0) {
            int64_t audioDataTime = 0;
            audioCaptureModule_->GetAudioTime(audioDataTime, true);
            if (audioDataTime == 0) {
                GetCurrentTime(audioDataTime);
            }
            firstAudioFramePts_.store(audioDataTime);
            MEDIA_INFO_LOG("firstAudioFramePts: %{public}" PRId64, firstAudioFramePts_.load());
        }
        std::lock_guard<std::mutex> lock(cachedAudioDataMutex_);
        cachedAudioDataDeque_.push_back(cachedAudioData);
    } else {
        if (!hasCalculateAVTime_ && withVideo_) {
            CalculateAVTime();
        } else {
            RecordAudioFrame();
        }
    }
}

void AudioCaptureFilter::CalculateAVTime()
{
    uint64_t bufferSize = 0;
    audioCaptureModule_->GetSize(bufferSize);

    if (firstAudioFramePts_.load() > firstVideoFramePts_.load()) {
        // audio frame is later than video frame, add zeros to the front of the cache queue.
        int32_t diffCount = static_cast<int32_t>((firstAudioFramePts_.load() - firstVideoFramePts_.load()
            + AUDIO_CAPTURE_READ_FRAME_TIME_HALF) / AUDIO_CAPTURE_READ_FRAME_TIME);
        if (diffCount > AUDIO_CAPTURE_MAX_CACHED_FRAMES) {
            // video time is abnormal, do not fill data frame.
            currentTime_ = firstAudioFramePts_.load();
        } else {
            currentTime_ = firstAudioFramePts_.load() - diffCount * AUDIO_CAPTURE_READ_FRAME_TIME;
            MEDIA_INFO_LOG("Audio late, diffCount: %{public}d", diffCount);
            FillLostFrame(diffCount);
        }
    } else {
        // audio frame is faster than video frame, crop frames of the cache queue.
        int32_t diffCount = static_cast<int32_t>((firstVideoFramePts_.load() - firstAudioFramePts_.load()
            + AUDIO_CAPTURE_READ_FRAME_TIME_HALF) / AUDIO_CAPTURE_READ_FRAME_TIME);
        if (diffCount > AUDIO_CAPTURE_MAX_CACHED_FRAMES) {
            // video time is abnormal, do not crop data frame.
            currentTime_ = firstAudioFramePts_.load();
        } else {
            currentTime_ = firstAudioFramePts_.load() + diffCount * AUDIO_CAPTURE_READ_FRAME_TIME;
            MEDIA_INFO_LOG("Video late, diffCount: %{public}d, cached size: %{public}zu", diffCount,
                           cachedAudioDataDeque_.size());
            std::lock_guard<std::mutex> lock(cachedAudioDataMutex_);
            while (diffCount > 0 && !cachedAudioDataDeque_.empty()) {
                cachedAudioDataDeque_.pop_front();
                --diffCount;
            }
        }
    }
    hasCalculateAVTime_ = true;
}

void AudioCaptureFilter::FillLostFrame(int32_t lostCount)
{
    uint64_t bufferSize = 0;
    audioCaptureModule_->GetSize(bufferSize);
    auto cachedAudioData = AllocateAudioDataBuffer(bufferSize);
    CHECK_RETURN(cachedAudioData == nullptr);
    std::lock_guard<std::mutex> lock(cachedAudioDataMutex_);
    while (lostCount > 0) {
        cachedAudioDataDeque_.push_front(cachedAudioData);
        --lostCount;
    }
}

void AudioCaptureFilter::RecordAudioFrame()
{
    uint64_t bufferSize = 0;
    audioCaptureModule_->GetSize(bufferSize);

    if (!cachedAudioDataDeque_.empty()) {
        auto cachedAudioData = AllocateAudioDataBuffer(bufferSize);
        CHECK_RETURN(cachedAudioData == nullptr);
        auto ret = audioCaptureModule_->Read(cachedAudioData.get(), bufferSize);
        if (ret != Status::OK) {
            MEDIA_ERR_LOG("audioCaptureModule read return fail");
            RelativeSleep(AUDIO_CAPTURE_READ_FAILED_WAIT_TIME);
            return;
        }
        int32_t lostCount = FillLostFrameNum();
        if (lostCount <= AUDIO_CAPTURE_MAX_CACHED_FRAMES && lostCount > 0) {
            FillLostFrame(lostCount);
        }
        {
            std::lock_guard<std::mutex> lock(cachedAudioDataMutex_);
            cachedAudioDataDeque_.push_back(cachedAudioData);
        }
        RecordCachedData(AUDIO_RECORDER_FRAME_NUM);
    } else {
        RecordOneAudioFrame(bufferSize);
    }
}

std::shared_ptr<uint8_t> AudioCaptureFilter::AllocateAudioDataBuffer(uint64_t bufferSize)
{
    if (bufferSize >= MAX_CAPTURE_BUFFER_SIZE) {
        MEDIA_ERR_LOG("bufferSize is too big, bufferSize: %{public}" PRId64, bufferSize);
        return nullptr;
    }
    auto buffer = std::shared_ptr<uint8_t>(new (std::nothrow) uint8_t[bufferSize]{0},
        std::default_delete<uint8_t[]>());
    CHECK_PRINT_WLOG(buffer.get() == nullptr, "create buffer fail");
    return buffer;
}

int32_t AudioCaptureFilter::FillLostFrameNum()
{
    int64_t audioDataTime = 0;
    int32_t lostCount = 0;
    int64_t cachedAudioDateTime = static_cast<int64_t>(cachedAudioDataDeque_.size()) * AUDIO_CAPTURE_READ_FRAME_TIME;
    audioCaptureModule_->GetAudioTime(audioDataTime, false);
    if (audioDataTime > currentTime_ + cachedAudioDateTime
        && (audioDataTime - currentTime_ - cachedAudioDateTime) > static_cast<int64_t>(AUDIO_UNREGULAR_DELTA_TIME)
        && withVideo_) {
        MEDIA_INFO_LOG("[audio] audioDataTime: %{public}" PRId64, audioDataTime);
        lostCount = (audioDataTime - AUDIO_CAPTURE_READ_FRAME_TIME - currentTime_
            - cachedAudioDateTime + AUDIO_CAPTURE_READ_FRAME_TIME_HALF) / AUDIO_CAPTURE_READ_FRAME_TIME;
        // time diff is abnormal, please check
        CHECK_PRINT_WLOG(lostCount > AUDIO_CAPTURE_MAX_CACHED_FRAMES, "[audio] abnormal time diff, please check");
    }
    return lostCount;
}

void AudioCaptureFilter::RecordOneAudioFrame(uint64_t bufferSize)
{
    std::shared_ptr<AVBuffer> buffer;
    AVBufferConfig avBufferConfig;
    avBufferConfig.size = static_cast<int32_t>(bufferSize);
    avBufferConfig.memoryFlag = MemoryFlag::MEMORY_READ_WRITE;
    auto ret = outputBufferQueue_->RequestBuffer(buffer, avBufferConfig, TIME_OUT_MS);
    if (ret != Status::OK || buffer == nullptr
        || buffer->memory_ == nullptr || buffer->memory_->GetCapacity() <= 0) {
        MEDIA_ERR_LOG("AudioCaptureFilter RequestBuffer fail");
        RelativeSleep(AUDIO_CAPTURE_READ_FAILED_WAIT_TIME);
        return;
    }
    std::shared_ptr<AVMemory> bufData = buffer->memory_;
    ret = audioCaptureModule_->Read(bufData->GetAddr(), bufferSize);
    if (ret != Status::OK) {
        MEDIA_ERR_LOG("audioCaptureModule read return fail");
        outputBufferQueue_->PushBuffer(buffer, false);
        RelativeSleep(AUDIO_CAPTURE_READ_FAILED_WAIT_TIME);
        return;
    }
    int32_t lostCount = FillLostFrameNum();
    if (lostCount <= AUDIO_CAPTURE_MAX_CACHED_FRAMES && lostCount > 0) {
        FillLostFrame(lostCount);
        RecordCachedData(lostCount);
    }
    buffer->memory_->SetSize(bufferSize);
    ret = outputBufferQueue_->PushBuffer(buffer, true);
    if (ret != Status::OK) {
        MEDIA_ERR_LOG("PushBuffer fail");
        RelativeSleep(AUDIO_CAPTURE_READ_FAILED_WAIT_TIME);
        return;
    }
    currentTime_ += AUDIO_CAPTURE_READ_FRAME_TIME;
    MEDIA_DEBUG_LOG("[audio] currentTime_: %{public}" PRId64, currentTime_);
}

void AudioCaptureFilter::RecordCachedData(int32_t recordFrameNum)
{
    uint64_t bufferSize = 0;
    audioCaptureModule_->GetSize(bufferSize);

    std::deque<std::shared_ptr<uint8_t>> tempDataDeque;
    {
        std::lock_guard<std::mutex> lock(cachedAudioDataMutex_);
        MEDIA_INFO_LOG("cachedAudioDataList count: %{public}d", static_cast<int32_t>(cachedAudioDataDeque_.size()));
        auto endIt = cachedAudioDataDeque_.begin()
            + std::min(recordFrameNum, static_cast<int32_t>(cachedAudioDataDeque_.size()));
        tempDataDeque.assign(cachedAudioDataDeque_.begin(), endIt);
        cachedAudioDataDeque_.erase(cachedAudioDataDeque_.begin(), endIt);
    }
    while (!tempDataDeque.empty() && outputBufferQueue_ && recordFrameNum > 0) {
        auto tmpData = tempDataDeque.front();
        tempDataDeque.pop_front();

        std::shared_ptr<AVBuffer> buffer;
        AVBufferConfig avBufferConfig;
        avBufferConfig.size = static_cast<int32_t>(bufferSize);
        avBufferConfig.memoryFlag = MemoryFlag::MEMORY_READ_WRITE;
        auto ret = outputBufferQueue_->RequestBuffer(buffer, avBufferConfig, TIME_OUT_MS);
        if (ret != Status::OK || buffer == nullptr
            || buffer->memory_ == nullptr || buffer->memory_->GetCapacity() <= 0) {
            MEDIA_ERR_LOG("AudioCaptureFilter RequestBuffer fail");
            RelativeSleep(AUDIO_CAPTURE_READ_FAILED_WAIT_TIME);
            continue;
        }
        buffer->memory_->Write(tmpData.get(), static_cast<int32_t>(bufferSize), 0);
        ret = outputBufferQueue_->PushBuffer(buffer, true);
        if (ret != Status::OK) {
            MEDIA_ERR_LOG("PushBuffer fail");
            RelativeSleep(AUDIO_CAPTURE_READ_FAILED_WAIT_TIME);
            continue;
        }
        currentTime_ += AUDIO_CAPTURE_READ_FRAME_TIME;
        recordFrameNum--;
        MEDIA_DEBUG_LOG("[audio] currentTime_: %{public}" PRId64, currentTime_);
    }
}

void AudioCaptureFilter::GetCurrentTime(int64_t &currentTime)
{
    struct timespec timestamp = {0, 0};
    clock_gettime(CLOCK_MONOTONIC, &timestamp);
    currentTime = static_cast<int64_t>(timestamp.tv_sec) * static_cast<int64_t>(AUDIO_NS_PER_SECOND)
        + static_cast<int64_t>(timestamp.tv_nsec);
}

void AudioCaptureFilter::SetVideoFirstFramePts(int64_t firstFramePts)
{
    if (firstFramePts > startTime_ || !hasCalculateAVTime_) {
        firstVideoFramePts_.store(firstFramePts);
        MEDIA_INFO_LOG("set firstVideoFramePts: %{public}" PRId64, firstVideoFramePts_.load());
    }
}

void AudioCaptureFilter::SetWithVideo(bool withVideo)
{
    withVideo_ = withVideo;
    MEDIA_INFO_LOG("set withVideo: %{public}d", withVideo_);
}

Status AudioCaptureFilter::GetCurrentCapturerChangeInfo(AudioStandard::AudioCapturerChangeInfo &changeInfo)
{
    MEDIA_INFO_LOG("GetCurrentCapturerChangeInfo");
    CHECK_RETURN_RET_ELOG(audioCaptureModule_ == nullptr, Status::ERROR_INVALID_OPERATION,
        "audioCaptureModule_ is nullptr, cannot get audio capturer change info");
    audioCaptureModule_->GetCurrentCapturerChangeInfo(changeInfo);
    return Status::OK;
}

int32_t AudioCaptureFilter::GetMaxAmplitude()
{
    MEDIA_INFO_LOG("GetMaxAmplitude");
    CHECK_RETURN_RET_ELOG(audioCaptureModule_ == nullptr, (int32_t)Status::ERROR_INVALID_OPERATION,
        "audioCaptureModule_ is nullptr, cannot get audio capturer change info");
    return audioCaptureModule_->GetMaxAmplitude();
}

void AudioCaptureFilter::OnLinkedResult(const sptr<AVBufferQueueProducer> &queue, std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("OnLinkedResult");
    CAMERA_SYNC_TRACE;
    outputBufferQueue_ = queue;
    PrepareAudioCapture();
}

Status AudioCaptureFilter::UpdateNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("UpdateNext");
    return Status::OK;
}

Status AudioCaptureFilter::UnLinkNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("UnLinkNext");
    return Status::OK;
}

Status AudioCaptureFilter::OnLinked(CStreamType inType, const std::shared_ptr<Meta> &meta,
    const std::shared_ptr<CFilterLinkCallback> &callback)
{
    MEDIA_INFO_LOG("OnLinked");
    return Status::OK;
}

Status AudioCaptureFilter::OnUpdated(CStreamType inType, const std::shared_ptr<Meta> &meta,
    const std::shared_ptr<CFilterLinkCallback> &callback)
{
    MEDIA_INFO_LOG("OnUpdated");
    return Status::OK;
}

Status AudioCaptureFilter::OnUnLinked(CStreamType inType, const std::shared_ptr<CFilterLinkCallback> &callback)
{
    MEDIA_INFO_LOG("OnUnLinked");
    return Status::OK;
}

void AudioCaptureFilter::OnUnlinkedResult(const std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("OnUnlinkedResult");
    (void) meta;
}

void AudioCaptureFilter::OnUpdatedResult(const std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("OnUpdatedResult");
    (void) meta;
}

void AudioCaptureFilter::SetCallingInfo(int32_t appUid, int32_t appPid,
    const std::string &bundleName, uint64_t instanceId)
{
    appUid_ = appUid;
    appPid_ = appPid;
    bundleName_ = bundleName;
    instanceId_ = instanceId;
    if (audioCaptureModule_) {
        audioCaptureModule_->SetCallingInfo(appUid, appPid, bundleName, instanceId);
    }
}

int32_t AudioCaptureFilter::RelativeSleep(int64_t nanoTime)
{
    int32_t ret = -1; // -1 for bad result.
    CHECK_RETURN_RET_ELOG(nanoTime <= 0, ret, "RelativeSleep nanoTime <= 0");
    struct timespec time;
    time.tv_sec = nanoTime / static_cast<int64_t>(AUDIO_NS_PER_SECOND);
    // Avoids % operation.
    time.tv_nsec = nanoTime - (static_cast<int64_t>(time.tv_sec) * static_cast<int64_t>(AUDIO_NS_PER_SECOND));
    clockid_t clockId = CLOCK_MONOTONIC;
    const int relativeFlag = 0; // flag of relative sleep.
    ret = clock_nanosleep(clockId, relativeFlag, &time, nullptr);
    CHECK_PRINT_ILOG(ret != 0, "RelativeSleep may failed, ret is :%{public}d", ret);
    return ret;
}

Status AudioCaptureFilter::GetAudioCaptureOptions(AudioCapturerOptions& options)
{
    CHECK_RETURN_RET_ELOG(!audioCaptureModule_, Status::ERROR_NULL_POINTER, "audioCaptureModule_ is null");
    return audioCaptureModule_->GetAudioCaptureOptions(options);
}
} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP