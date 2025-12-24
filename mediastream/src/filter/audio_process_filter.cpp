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

#include <algorithm>

#include "audio_process_filter.h"
#include "audio_stream_info.h"
#include "camera_log.h"
#include "cfilter_factory.h"

// LCOV_EXCL_START
namespace OHOS {
namespace CameraStandard {
using namespace AudioStandard;
namespace {
constexpr int32_t TIME_OUT_MS = 0;
constexpr int32_t AUDIO_PROCESS_BUFFER_QUEUE_SIZE = 10;
constexpr int32_t AUDIO_FRAME_DURATION = 20;  // 20ms
constexpr int32_t AUDIO_POST_EDIT_DURATION = 160; // 160ms
constexpr int32_t FRAME_COUNT_PER_BATCH = AUDIO_POST_EDIT_DURATION / AUDIO_FRAME_DURATION;
constexpr int32_t MS_PER_SECOND = 1000; // 1000ms = 1s
constexpr int32_t AUDIO_PROCESS_TASK_DELAY_TIME = 100000; // 100000us = 100ms
const std::string CHAIN_NAME_OFFLINE = "offline_record_algo";
const std::string CHAIN_NAME_POST_EDIT = "record_post_edit";
}

static AutoRegisterCFilter<AudioProcessFilter> g_registerAudioProcessFilter("camera.audio.process",
    CFilterType::AUDIO_PROCESS,
    [](const std::string& name, const CFilterType type) {
        return std::make_shared<AudioProcessFilter>(name, CFilterType::AUDIO_PROCESS);
    });

AudioProcessFilterLinkCallback::AudioProcessFilterLinkCallback(
    const std::weak_ptr<AudioProcessFilter> &audioProcessFilter) : audioProcessFilter_(audioProcessFilter)
{
    MEDIA_DEBUG_LOG("entered.");
}

void AudioProcessFilterLinkCallback::OnLinkedResult(const sptr<AVBufferQueueProducer> &queue,
                                                    std::shared_ptr<Meta> &meta)
{
    if (auto filter = audioProcessFilter_.lock()) {
        filter->OnLinkedResult(queue, meta);
        return;
    }
    MEDIA_ERR_LOG("invalid audioProcessFilter");
}

void AudioProcessFilterLinkCallback::OnUnlinkedResult(std::shared_ptr<Meta> &meta)
{
    if (auto filter = audioProcessFilter_.lock()) {
        filter->OnUnlinkedResult(meta);
        return;
    }
    MEDIA_ERR_LOG("invalid audioProcessFilter");
}

void AudioProcessFilterLinkCallback::OnUpdatedResult(std::shared_ptr<Meta> &meta)
{
    if (auto filter = audioProcessFilter_.lock()) {
        filter->OnUpdatedResult(meta);
        return;
    }
    MEDIA_ERR_LOG("invalid audioProcessFilter");
}

AudioProcessConsumerListener::AudioProcessConsumerListener(const std::weak_ptr<AudioProcessFilter>& audioProcessFilter)
    : audioProcessFilter_(audioProcessFilter)
{
    MEDIA_DEBUG_LOG("entered.");
}

void AudioProcessConsumerListener::OnBufferAvailable()
{
    if (auto filter = audioProcessFilter_.lock()) {
        filter->OnBufferAvailable();
        return;
    }
    MEDIA_ERR_LOG("invalid audioProcessFilter");
}

AudioProcessFilter::AudioProcessFilter(std::string name, CFilterType type): CFilter(name, type)
{
    MEDIA_INFO_LOG("%{public}s - AudioProcessFilter ctor called", name_.c_str());
}

AudioProcessFilter::~AudioProcessFilter()
{
    MEDIA_INFO_LOG("%{public}s - AudioProcessFilter dtor called", name_.c_str());
    CHECK_EXECUTE(offlineEffectChain_, offlineEffectChain_->Release());
}

void AudioProcessFilter::Init(const std::shared_ptr<CEventReceiver>& receiver,
    const std::shared_ptr<CFilterCallback>& callback)
{
    MEDIA_INFO_LOG("AudioProcessFilter::Init is called");
    CAMERA_SYNC_TRACE;
    receiver_ = receiver;
    filterCallback_ = callback;

    if (!taskPtr_) {
        taskPtr_ = std::make_shared<Task>("AudioPostEditProcesser", groupId_);
        taskPtr_->RegisterJob([this] {
            ProcessLoop();
            return AUDIO_PROCESS_TASK_DELAY_TIME;
        });
    }
}

Status AudioProcessFilter::DoPrepare()
{
    MEDIA_INFO_LOG("AudioProcessFilter DoPrepare");
    CHECK_RETURN_RET(!filterCallback_, Status::ERROR_NULL_POINTER);
    return filterCallback_->OnCallback(shared_from_this(), CFilterCallBackCommand::NEXT_FILTER_NEEDED,
        CStreamType::PROCESSED_AUDIO);
}

Status AudioProcessFilter::DoStart()
{
    MEDIA_INFO_LOG("Start");
    CHECK_EXECUTE(taskPtr_, taskPtr_->Start());
    return Status::OK;
}

Status AudioProcessFilter::DoPause()
{
    MEDIA_INFO_LOG("Pause");
    return Status::OK;
}

Status AudioProcessFilter::DoResume()
{
    MEDIA_INFO_LOG("Resume");
    return Status::OK;
}

Status AudioProcessFilter::DoStop()
{
    MEDIA_INFO_LOG("Stop");
    CHECK_EXECUTE(taskPtr_, taskPtr_->StopAsync());
    return Status::OK;
}

Status AudioProcessFilter::DoFlush()
{
    MEDIA_INFO_LOG("Flush");
    return Status::OK;
}

Status AudioProcessFilter::DoRelease()
{
    MEDIA_INFO_LOG("Release");
    CHECK_EXECUTE(taskPtr_, taskPtr_->Stop());
    taskPtr_ = nullptr;
    CHECK_EXECUTE(offlineEffectChain_, offlineEffectChain_->Release());
    return Status::OK;
}

void AudioProcessFilter::SetParameter(const std::shared_ptr<Meta>& meta)
{
    MEDIA_INFO_LOG("SetParameter");
    audioParameter_ = meta;
}

void AudioProcessFilter::GetParameter(std::shared_ptr<Meta>& meta)
{
    MEDIA_INFO_LOG("GetParameter");
    meta = audioParameter_;
}

Status AudioProcessFilter::LinkNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType)
{
    CHECK_RETURN_RET_ELOG(!nextFilter, Status::ERROR_NULL_POINTER, "nextFilter is null");
    MEDIA_INFO_LOG("LinkNext type: %{public}d", nextFilter->GetCFilterType());
    nextFilter_ = nextFilter;
    nextCFiltersMap_[outType].push_back(nextFilter);
    std::shared_ptr<CFilterLinkCallback> filterLinkCallback =
        std::make_shared<AudioProcessFilterLinkCallback>(weak_from_this());
    auto ret = nextFilter->OnLinked(outType, audioParameter_, filterLinkCallback);
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "OnLinked failed");
    return Status::OK;
}

Status AudioProcessFilter::UpdateNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("OnUpdated");
    return Status::OK;
}

Status AudioProcessFilter::UnLinkNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("OnUnLinked");
    return Status::OK;
}

CFilterType AudioProcessFilter::GetFilterType()
{
    MEDIA_INFO_LOG("GetFilterType");
    return CFilterType::AUDIO_PROCESS;
}

void AudioProcessFilter::OnLinkedResult(const sptr<AVBufferQueueProducer> &outputBufferQueue,
                                        std::shared_ptr<Meta> &meta)
{
    CHECK_RETURN_ELOG(!linkCallback_, "OnLinkedResultCallback is nullptr");
    std::string encoderName;
    CHECK_EXECUTE(meta, meta->GetData("audio.encoder.name", encoderName));
    MEDIA_INFO_LOG("OnLinkedResult audio.encoder.name:%{public}s", encoderName.c_str());
    CHECK_RETURN_ELOG(!outputBufferQueue, "outputBufferQueue is null");
    if (encoderName == "RawAudioEncoderFilter") {
        rawAudEncProducer_ = outputBufferQueue;
    } else {
        procAudEncProducer_ = outputBufferQueue;
    }
    if (!audioProcessBufferQueue_) {
        audioProcessBufferQueue_ = AVBufferQueue::Create(AUDIO_PROCESS_BUFFER_QUEUE_SIZE, MemoryType::SHARED_MEMORY,
                                                         "AudioProcessBufferQueue");
        CHECK_RETURN_ELOG(!audioProcessBufferQueue_, "create AudioProcessBufferQueue failed");
        consumer_ = audioProcessBufferQueue_->GetConsumer();
        CHECK_RETURN_ELOG(!consumer_, "GetConsumer failed");
        sptr<IConsumerListener> consumerListener = sptr<AudioProcessConsumerListener>::MakeSptr(shared_from_this());
        consumer_->SetBufferAvailableListener(consumerListener);
    }
    auto producer = audioProcessBufferQueue_->GetProducer();
    linkCallback_->OnLinkedResult(producer, meta);
}

Status AudioProcessFilter::OnLinked(CStreamType inType, const std::shared_ptr<Meta>& meta,
    const std::shared_ptr<CFilterLinkCallback>& callback)
{
    MEDIA_INFO_LOG("OnLinked");
    audioParameter_ = meta;
    linkCallback_ = callback;
    return Status::OK;
}

Status AudioProcessFilter::OnUpdated(CStreamType inType, const std::shared_ptr<Meta>& meta,
    const std::shared_ptr<CFilterLinkCallback>& callback)
{
    MEDIA_INFO_LOG("OnUpdated");
    return Status::OK;
}

Status AudioProcessFilter::OnUnLinked(CStreamType inType, const std::shared_ptr<CFilterLinkCallback>& callback)
{
    MEDIA_INFO_LOG("OnUnLinked");
    return Status::OK;
}

void AudioProcessFilter::OnUnlinkedResult(const std::shared_ptr<Meta>& meta)
{
    MEDIA_INFO_LOG("OnUnlinkedResult");
    (void) meta;
}

void AudioProcessFilter::OnUpdatedResult(const std::shared_ptr<Meta>& meta)
{
    MEDIA_INFO_LOG("OnUpdatedResult");
    (void) meta;
}

Status AudioProcessFilter::CreateOfflineAudioEffectChain()
{
    offlineAudioEffectManager_ = std::make_unique<AudioStandard::OfflineAudioEffectManager>();
    CHECK_RETURN_RET_ELOG(!offlineAudioEffectManager_, Status::ERROR_NULL_POINTER, "offlineAudioEffectManager is null");
    std::vector<std::string> effectChains = offlineAudioEffectManager_->GetOfflineAudioEffectChains();
    // 1st choice CHAIN_NAME_POST_EDIT
    auto iter = std::find_if(effectChains.begin(), effectChains.end(),
                             [](const std::string &s) { return s.find(CHAIN_NAME_POST_EDIT) != std::string::npos; });
    if (iter != effectChains.end()) {
        selectedChain_ = *iter;
    } else {
        // 2nd choice CHAIN_NAME_OFFLINE
        iter = std::find_if(effectChains.begin(), effectChains.end(),
                            [](const std::string &s) { return s.find(CHAIN_NAME_OFFLINE) != std::string::npos; });
        CHECK_EXECUTE(iter != effectChains.end(), selectedChain_ = *iter);
    }
    CHECK_RETURN_RET_ELOG(
        selectedChain_.empty(), Status::ERROR_NULL_POINTER, "AudioProcessFilter no effectChain is selected");
    offlineEffectChain_ = offlineAudioEffectManager_->CreateOfflineAudioEffectChain(selectedChain_);
    CHECK_RETURN_RET_ELOG(!offlineEffectChain_, Status::ERROR_NULL_POINTER,
                          "AudioProcessFilter GetOfflineEffectChain ERR");
    MEDIA_INFO_LOG("CreateOfflineAudioEffectChain of chain name:%{public}s", selectedChain_.c_str());
    return Status::OK;
}

Status AudioProcessFilter::InitAudioProcessConfig()
{
    Status status = Status::OK;
    status = CreateOfflineAudioEffectChain();
    CHECK_RETURN_RET_ELOG(status != Status::OK, status, "CreateOfflineAudioEffectChain failed");

    AudioStreamInfo inputStreamInfo = inputOptions_.streamInfo;
    AudioStreamInfo outputStreamInfo = inputStreamInfo;
    outputStreamInfo.channels = AudioChannel::MONO;
    outputStreamInfo.samplingRate = static_cast<AudioSamplingRate>(AudioSamplingRate::SAMPLE_RATE_48000);
    if (selectedChain_ == CHAIN_NAME_POST_EDIT) {
        outputStreamInfo.channels = AudioChannel::STEREO;
    }
    outputStreamInfo_ = outputStreamInfo;

    CHECK_RETURN_RET_ELOG(!offlineEffectChain_, Status::ERROR_NULL_POINTER, "offlineEffectChain_ is null");

    int32_t ret = offlineEffectChain_->Configure(inputStreamInfo, outputStreamInfo);
    CHECK_RETURN_RET_ELOG(ret != 0, Status::ERROR_INVALID_STATE, "EffectChain Configure failed, ret:%{public}d", ret);

    ret = offlineEffectChain_->Prepare();
    CHECK_RETURN_RET_ELOG(ret != 0, Status::ERROR_INVALID_STATE, "EffectChain Prepare failed, ret:%{public}d", ret);

    uint32_t effectInputBufferSize = 0;
    uint32_t effectOutputBufferSize = 0;
    ret = offlineEffectChain_->GetEffectBufferSize(effectInputBufferSize, effectOutputBufferSize);
    CHECK_RETURN_RET_ELOG(ret != 0, Status::ERROR_INVALID_STATE,
        "EffectChain GetEffectBufferSize failed, ret:%{public}d", ret);
    MEDIA_INFO_LOG("InitAudioProcessConfig effectInputBufferSize:%{public}d, effectOutputBufferSize:%{public}d",
        effectInputBufferSize, effectOutputBufferSize);
    MEDIA_INFO_LOG("Dump input stream info, samplingRate:%{public}d, encoding: %{public}d, format:%{public}d, "
                "channels:%{public}d, channelLayout:%{public}" PRIu64,
                inputStreamInfo.samplingRate, inputStreamInfo.encoding, inputStreamInfo.format,
                inputStreamInfo.channels, inputStreamInfo.channelLayout);
    MEDIA_INFO_LOG("Dump output stream info, samplingRate:%{public}d, encoding: %{public}d, format:%{public}d, "
                "channels:%{public}d, channelLayout:%{public}" PRIu64,
                outputStreamInfo.samplingRate, outputStreamInfo.encoding, outputStreamInfo.format,
                outputStreamInfo.channels, outputStreamInfo.channelLayout);

    preFrameSize_ = inputStreamInfo.samplingRate / MS_PER_SECOND * inputStreamInfo.channels *
                          AUDIO_FRAME_DURATION * sizeof(short);
    postFrameSize_ = outputStreamInfo.samplingRate / MS_PER_SECOND * outputStreamInfo.channels *
                          AUDIO_FRAME_DURATION * sizeof(short);
    preBatchSize_ = preFrameSize_ * FRAME_COUNT_PER_BATCH;
    postBatchSize_ = postFrameSize_ * FRAME_COUNT_PER_BATCH;
    MEDIA_INFO_LOG("InitAudioProcessConfig, preFrameSize_: %{public}d, postFrameSize_: %{public}d, "
                   "preBatchSize_: %{public}d, postBatchSize_: %{public}d",
                   preFrameSize_, postFrameSize_, preBatchSize_, postBatchSize_);
    return Status::OK;
}

void AudioProcessFilter::SetAudioCaptureOptions(AudioStandard::AudioCapturerOptions& options)
{
    MEDIA_INFO_LOG("SetAudioCaptureOptions is called");
    inputOptions_ = options;
}

void AudioProcessFilter::GetOutputAudioStreamInfo(AudioStreamInfo& outputStreamInfo)
{
    outputStreamInfo = outputStreamInfo_;
}

void AudioProcessFilter::OnBufferAvailable()
{
    MEDIA_DEBUG_LOG("AudioProcessFilter::OnBufferAvailable is called");
    CHECK_RETURN_ELOG(!consumer_, "consumer_ is nullptr");

    std::shared_ptr<AVBuffer> inputBuffer;
    Status ret = consumer_->AcquireBuffer(inputBuffer);
    CHECK_RETURN_ELOG(ret != Status::OK, "AcquireBuffer from consumer_ failed, ret %{public}d", ret);

    AVBufferConfig inputBufferConfig = inputBuffer->GetConfig();
    int32_t bufferSize = inputBufferConfig.size;
    int64_t bufferPts = inputBuffer->pts_;
    MEDIA_DEBUG_LOG("input buffer info, size: %{public}d, ts: %{public}" PRId64, bufferSize, bufferPts);
    if (bufferSize != preFrameSize_) {
        MEDIA_ERR_LOG("bufferSize: %{public}d is not equal to preFrameSize_: %{public}d", bufferSize, preFrameSize_);
        consumer_->ReleaseBuffer(inputBuffer);
        return;
    }

    // cache 160ms audio data
    if (!cachedAudBuf_) {
        AVBufferConfig rawCfg;
        rawCfg.size = preBatchSize_;
        rawCfg.memoryType = MemoryType::SHARED_MEMORY;
        CHECK_RETURN_ELOG(!rawAudEncProducer_, "rawAudEncProducer_ is null");
        rawAudEncProducer_->RequestBuffer(cachedAudBuf_, rawCfg, TIME_OUT_MS);
        CHECK_RETURN_ELOG(ret != Status::OK, "rawAudEncProducer_ RequestBuffer failed, ret:%{public}d", ret);
    }
    CHECK_RETURN_ELOG(!cachedAudBuf_ || !cachedAudBuf_->memory_, "cachedAudBuf_ is invalid");
    int32_t len = cachedAudBuf_->memory_->Write(inputBuffer->memory_->GetAddr(), bufferSize,
                                                cachedAudioFrameCount_ * preFrameSize_);
    ret = consumer_->ReleaseBuffer(inputBuffer);  // always release buffer even if cpy failed
    CHECK_PRINT_ELOG(ret != Status::OK, "consumer_->ReleaseBuffer failed");
    CHECK_RETURN_ELOG(len < bufferSize, "memory write failed, write: %{public}d, buf len: %{public}d", len, bufferSize);
    cachedAudioFrameCount_++;
    CHECK_RETURN_DLOG(cachedAudioFrameCount_ < FRAME_COUNT_PER_BATCH, "current cached frame count: %{public}d",
                      cachedAudioFrameCount_);
    cachedAudBuf_->memory_->SetSize(preBatchSize_);

    // process audio when data count is enough
    {
        // move cached audio data, so the main thread is not blocked by algo process
        std::unique_lock<std::mutex> lock(dataMutex_);
        cachedAudBufList_.push_back(std::move(cachedAudBuf_));
    }
    cachedAudBuf_.reset();
    cachedAudioFrameCount_ = 0;
    // wake up the task
    CHECK_EXECUTE(taskPtr_, taskPtr_->UpdateDelayTime(0));
}


void AudioProcessFilter::ProcessLoop()
{
    // process 160ms cached audio
    MEDIA_DEBUG_LOG("AudioProcessFilter::ProcessLoop is called");
    // move data into current thread
    std::vector<std::shared_ptr<AVBuffer>> dataBatch;
    {
        std::unique_lock<std::mutex> lock(dataMutex_);
        CHECK_EXECUTE(!cachedAudBufList_.empty(), dataBatch.swap(cachedAudBufList_));
    }
    CHECK_RETURN_DLOG(dataBatch.empty(), "not enough data, waiting...");

    Status ret = Status::OK;
    for (auto& data : dataBatch) {
        ret = SendPostEditAudioToEncoder(data);
        CHECK_PRINT_ELOG(ret != Status::OK, "SendPostEditAudioToEncoder failed, ret: %{public}d", ret);
        ret = SendRawAudioToEncoder(data);
        CHECK_PRINT_ELOG(ret != Status::OK, "SendRawAudioToEncoder failed, ret: %{public}d", ret);
    }
}

Status AudioProcessFilter::SendRawAudioToEncoder(std::shared_ptr<AVBuffer>& inputBuffer)
{
    Status ret = Status::OK;

    // push buffer
    CHECK_RETURN_RET_ELOG(!rawAudEncProducer_, Status::ERROR_NULL_POINTER, "rawAudEncProducer_ is null");
    ret = rawAudEncProducer_->PushBuffer(inputBuffer, true);
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "rawAudEncProducer_ PushBuffer failed, ret:%{public}d", ret);

    MEDIA_DEBUG_LOG("push raw audio buffer to encoder, size:%{public}d", inputBuffer->GetConfig().size);
    return ret;
}

Status AudioProcessFilter::SendPostEditAudioToEncoder(std::shared_ptr<AVBuffer>& inputBuffer)
{
    Status ret = Status::OK;
    CHECK_RETURN_RET_ELOG(!offlineEffectChain_, Status::ERROR_NULL_POINTER, "offlineEffectChain_ is null");
    AVBufferConfig procCfg;
    procCfg.memoryType = MemoryType::SHARED_MEMORY;
    procCfg.size = postBatchSize_;
    std::shared_ptr<AVBuffer> procBuffer;

    // request buffer
    CHECK_RETURN_RET_ELOG(!procAudEncProducer_, Status::ERROR_NULL_POINTER, "procAudEncProducer_ is null");
    ret = procAudEncProducer_->RequestBuffer(procBuffer, procCfg, TIME_OUT_MS);
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "procAudEncProducer_ RequestBuffer failed, ret:%{public}d", ret);

    // process audio effect
    CHECK_RETURN_RET_ELOG(!procBuffer->memory_, Status::ERROR_NULL_POINTER, "procBuffer->memory_ is null");
    int32_t err = offlineEffectChain_->Process(inputBuffer->memory_->GetAddr(), preBatchSize_,
                                               procBuffer->memory_->GetAddr(), postBatchSize_);
    if (err) {
        MEDIA_ERR_LOG("offlineEffectChain process audio failed, ret:%{public}d", err);
        ret = procAudEncProducer_->PushBuffer(procBuffer, false);
        return ret;
    }
    procBuffer->memory_->SetSize(postBatchSize_);

    // push buffer
    ret = procAudEncProducer_->PushBuffer(procBuffer, true);
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "procAudEncProducer_ PushBuffer failed, ret:%{public}d", ret);

    MEDIA_DEBUG_LOG("push post edit audio buffer to encoder, size:%{public}d", procBuffer->GetConfig().size);
    return ret;
}
} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP