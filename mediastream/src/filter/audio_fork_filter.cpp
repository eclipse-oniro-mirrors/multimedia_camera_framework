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

#include "audio_fork_filter.h"

#include "camera_log.h"
#include "cfilter.h"
#include "cfilter_factory.h"

// LCOV_EXCL_START
namespace OHOS {
namespace CameraStandard {
namespace {
    constexpr uint32_t TIME_OUT_MS = 0;
}
static AutoRegisterCFilter<AudioForkFilter> g_registerAudioForkFilter("camera.audiofork",
    CFilterType::AUDIO_CAPTURE,
    [](const std::string& name, const CFilterType type) {
        return std::make_shared<AudioForkFilter>(name, CFilterType::AUDIO_FORK);
    });

AudioForkFilterLinkCallback::AudioForkFilterLinkCallback(const std::weak_ptr<AudioForkFilter>& audioForkFilter)
    : audioForkFilter_(audioForkFilter)
{
    MEDIA_DEBUG_LOG("entered.");
}

void AudioForkFilterLinkCallback::OnLinkedResult(const sptr<AVBufferQueueProducer>& queue, std::shared_ptr<Meta>& meta)
{
    if (auto filter = audioForkFilter_.lock()) {
        filter->OnLinkedResult(queue, meta);
        return;
    }
    MEDIA_ERR_LOG("invalid audioForkFilter");
}

void AudioForkFilterLinkCallback::OnUnlinkedResult(std::shared_ptr<Meta> &meta)
{
    if (auto filter = audioForkFilter_.lock()) {
        filter->OnUnlinkedResult(meta);
        return;
    }
    MEDIA_ERR_LOG("invalid audioForkFilter");
}

void AudioForkFilterLinkCallback::OnUpdatedResult(std::shared_ptr<Meta> &meta)
{
    if (auto filter = audioForkFilter_.lock()) {
        filter->OnUpdatedResult(meta);
        return;
    }
    MEDIA_ERR_LOG("invalid audioForkFilter");
}

AudioForkBrokerListener::AudioForkBrokerListener(const std::weak_ptr<AudioForkFilter>& audioForkFilter,
    const sptr<AVBufferQueueProducer>& inputBufferQueue)
    : audioForkFilter_(audioForkFilter), inputBufferQueue_(inputBufferQueue)
{
    MEDIA_DEBUG_LOG("entered.");
}

sptr<IRemoteObject> AudioForkBrokerListener::AsObject()
{
    return nullptr;
}

void AudioForkBrokerListener::OnBufferFilled(std::shared_ptr<AVBuffer>& avBuffer)
{
    if (auto filter = audioForkFilter_.lock()) {
        auto spInputBufferQueue = inputBufferQueue_.promote();
        CHECK_EXECUTE(spInputBufferQueue != nullptr,
            filter->ProcessAudioFork(avBuffer, inputBufferQueue_.promote()));
        return;
    }
    MEDIA_ERR_LOG("invalid audioForkFilter");
}

AudioForkConsumerListener::AudioForkConsumerListener(const std::weak_ptr<AudioForkFilter>& audioForkFilter)
    : audioForkFilter_(audioForkFilter)
{
    MEDIA_DEBUG_LOG("entered.");
}

void AudioForkConsumerListener::OnBufferAvailable()
{
    if (auto filter = audioForkFilter_.lock()) {
        filter->OnBufferAvailable();
        return;
    }
    MEDIA_ERR_LOG("invalid audioForkFilter");
}

AudioForkFilter::AudioForkFilter(std::string name, CFilterType type): CFilter(name, type)
{
    MEDIA_DEBUG_LOG("entered.");
}

AudioForkFilter::~AudioForkFilter()
{
    MEDIA_INFO_LOG("entered.");
}

void AudioForkFilter::Init(const std::shared_ptr<CEventReceiver>& receiver,
    const std::shared_ptr<CFilterCallback>& callback)
{
    MEDIA_INFO_LOG("Init");
    CAMERA_SYNC_TRACE;
    receiver_ = receiver;
    filterCallback_ = callback;
}

Status AudioForkFilter::DoPrepare()
{
    CHECK_RETURN_RET(filterCallback_ == nullptr, Status::ERROR_NULL_POINTER);
    MEDIA_INFO_LOG("AudioForkFilter DoPrepare");
    return filterCallback_->OnCallback(shared_from_this(), CFilterCallBackCommand::NEXT_FILTER_NEEDED,
        CStreamType::FORK_AUDIO);
}

Status AudioForkFilter::DoStart()
{
    MEDIA_INFO_LOG("Start");
    return Status::OK;
}

Status AudioForkFilter::DoPause()
{
    MEDIA_INFO_LOG("Pause");
    return Status::OK;
}

Status AudioForkFilter::DoResume()
{
    MEDIA_INFO_LOG("Resume");
    return Status::OK;
}

Status AudioForkFilter::DoStop()
{
    MEDIA_INFO_LOG("Stop");
    return Status::OK;
}

Status AudioForkFilter::DoFlush()
{
    MEDIA_INFO_LOG("Flush");
    return Status::OK;
}

Status AudioForkFilter::DoRelease()
{
    MEDIA_INFO_LOG("Release");
    return Status::OK;
}

void AudioForkFilter::SetParameter(const std::shared_ptr<Meta>& meta)
{
    MEDIA_INFO_LOG("SetParameter");
    audioParameter_ = meta;
}

void AudioForkFilter::GetParameter(std::shared_ptr<Meta>& meta)
{
    MEDIA_INFO_LOG("GetParameter");
    meta = audioParameter_;
}

Status AudioForkFilter::LinkNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("LinkNext type: %{public}d", nextFilter->GetCFilterType());
    nextCFiltersMap_[outType].push_back(nextFilter);
    std::shared_ptr<CFilterLinkCallback> filterLinkCallback =
        std::make_shared<AudioForkFilterLinkCallback>(weak_from_this());
    auto ret = nextFilter->OnLinked(outType, audioParameter_, filterLinkCallback);
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "OnLinked failed");
    return Status::OK;
}

Status AudioForkFilter::UpdateNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("OnUpdated");
    return Status::OK;
}

Status AudioForkFilter::UnLinkNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("OnUnLinked");
    return Status::OK;
}

CFilterType AudioForkFilter::GetFilterType()
{
    MEDIA_INFO_LOG("GetFilterType");
    return CFilterType::AUDIO_FORK;
}

void AudioForkFilter::OnLinkedResult(const sptr<AVBufferQueueProducer>& outputBufferQueue, std::shared_ptr<Meta>& meta)
{   
    std::string muxerName;
    meta->GetData("muxer_name", muxerName);
    MEDIA_DEBUG_LOG("AudioForkFilter::OnLinkedResult muxer_name: %{public}s", muxerName.c_str());
    CHECK_RETURN_ELOG(linkCallback_ == nullptr, "onLinkedResultCallback is nullptr");
    if (muxerName == "MovieMuxerFilter") {
        MEDIA_DEBUG_LOG("MovieMuxerFilter OnLinkedResult");
        movieAudioProducer_ = outputBufferQueue;
    } else if (muxerName == "RawMuxerFilter") {
        MEDIA_DEBUG_LOG("RawMuxerFilter OnLinkedResult");
        rawAudioProducer_ = outputBufferQueue;
    }
    if (!audioForkBufferQueue_) {
        audioForkBufferQueue_ = AVBufferQueue::Create(10, MemoryType::SHARED_MEMORY, "AudioForkBufferQueue");
        auto producer = audioForkBufferQueue_->GetProducer();
        sptr<IBrokerListener> brokerListener = sptr<AudioForkBrokerListener>::MakeSptr(shared_from_this(), producer);
        producer->SetBufferFilledListener(brokerListener);
        linkCallback_->OnLinkedResult(producer, meta);
        consumer_ = audioForkBufferQueue_->GetConsumer();
        sptr<IConsumerListener> consumerListener = sptr<AudioForkConsumerListener>::MakeSptr(shared_from_this());
        consumer_->SetBufferAvailableListener(consumerListener);
    }
}

Status AudioForkFilter::OnLinked(CStreamType inType, const std::shared_ptr<Meta>& meta,
    const std::shared_ptr<CFilterLinkCallback>& callback)
{
    MEDIA_INFO_LOG("OnLinked");
    audioParameter_ = meta;
    linkCallback_ = callback;
    return Status::OK;
}

Status AudioForkFilter::OnUpdated(CStreamType inType, const std::shared_ptr<Meta>& meta,
    const std::shared_ptr<CFilterLinkCallback>& callback)
{
    MEDIA_INFO_LOG("OnUpdated");
    return Status::OK;
}

Status AudioForkFilter::OnUnLinked(CStreamType inType, const std::shared_ptr<CFilterLinkCallback>& callback)
{
    MEDIA_INFO_LOG("OnUnLinked");
    return Status::OK;
}

void AudioForkFilter::OnUnlinkedResult(const std::shared_ptr<Meta>& meta)
{

}

void AudioForkFilter::OnUpdatedResult(const std::shared_ptr<Meta>& meta)
{

}

void AudioForkFilter::ProcessAudioFork(std::shared_ptr<AVBuffer>& inputBuffer,
    const sptr<AVBufferQueueProducer>& inputBufferQueue)
{
    MEDIA_DEBUG_LOG("AudioForkFilter::ProcessAudioFork is called");
    if (rawAudioProducer_ != nullptr) {
        AVBufferConfig avBufferConfig = inputBuffer->GetConfig();
        MEDIA_DEBUG_LOG("AudioForkFilter::ProcessAudioFork avBufferConfig, capacity: %{public}d, size %{public}d, "
            "memoryType: %{public}hhu,", avBufferConfig.capacity, avBufferConfig.size, avBufferConfig.memoryType);
        std::shared_ptr<AVBuffer> rawBuffer;
        auto ret = rawAudioProducer_->RequestBuffer(rawBuffer, avBufferConfig, TIME_OUT_MS);
        if (ret == Status::OK) {
            ret = CopyAVBuffer(inputBuffer, rawBuffer);
            CHECK_PRINT_ELOG(ret != Status::OK, "raw audio CopyAVBuffer failed, ret %{public}d", ret);
            bool available = ret == Status::OK;
            ret = rawAudioProducer_->PushBuffer(rawBuffer, available);
            CHECK_PRINT_ELOG(ret != Status::OK,
                "raw audio PushBuffer to rawAudioProducer_ failed, ret %{public}d", ret);
        } else {
            MEDIA_ERR_LOG("raw audio RequestBuffer from rawAudioProducer_ failed, ret %{public}d", ret);
        }
    }

    auto ret = inputBufferQueue->ReturnBuffer(inputBuffer, true);
    CHECK_RETURN_ELOG(ret != Status::OK, "audio ReturnBuffer failed, ret %{public}d", ret);
}

void AudioForkFilter::OnBufferAvailable()
{
    MEDIA_DEBUG_LOG("AudioForkFilter::OnBufferAvailable is called");
    CHECK_RETURN_ELOG(consumer_ == nullptr || movieAudioProducer_ == nullptr,
        "consumer_ or movieAudioProducer_ is nullptr");
    std::shared_ptr<AVBuffer> inputBuffer;
    auto ret = consumer_->AcquireBuffer(inputBuffer);
    CHECK_RETURN_ELOG(ret != Status::OK, "AcquireBuffer from consumer_ failed, ret %{public}d", ret);
    ret = consumer_->DetachBuffer(inputBuffer);
    if (ret != Status::OK) {
        consumer_->ReleaseBuffer(inputBuffer);
        MEDIA_ERR_LOG("DetachBuffer from consumer_ failed, ret %{public}d", ret);
        return;
    }

    std::shared_ptr<AVBuffer> movieBuffer;
    AVBufferConfig avBufferConfig = inputBuffer->GetConfig();
    MEDIA_DEBUG_LOG("AudioForkFilter::OnBufferAvailable avBufferConfig, capacity: %{public}d, size %{public}d, "
        "memoryType: %{public}hhu,", avBufferConfig.capacity, avBufferConfig.size, avBufferConfig.memoryType);

    ret = movieAudioProducer_->RequestBuffer(movieBuffer, avBufferConfig, TIME_OUT_MS);
    if (ret != Status::OK) {
        MEDIA_ERR_LOG("movie audio RequestBuffer from movieAudioProducer_ failed, ret %{public}d", ret);
        consumer_->AttachBuffer(inputBuffer, false);
        return;
    }

    ret = movieAudioProducer_->DetachBuffer(movieBuffer);
    if (ret != Status::OK) {
        MEDIA_ERR_LOG("movie audio DetachBuffer from movieAudioProducer_ failed, ret %{public}d", ret);
        movieAudioProducer_->PushBuffer(movieBuffer, false);
        consumer_->AttachBuffer(inputBuffer, false);
        return;
    }

    ret = movieAudioProducer_->AttachBuffer(inputBuffer, true);
    if (ret != Status::OK) {
        MEDIA_ERR_LOG("movie audio AttachBuffer to movieAudioProducer_ failed, ret %{public}d", ret);
        movieAudioProducer_->AttachBuffer(movieBuffer, false);
        consumer_->AttachBuffer(inputBuffer, false);
        return;
    }

    ret = consumer_->AttachBuffer(movieBuffer, false);
    CHECK_PRINT_ELOG(ret != Status::OK, "movie audio AttachBuffer to consumer_ failed");
}

Status AudioForkFilter::CopyAVBuffer(std::shared_ptr<AVBuffer> &inputBuffer, std::shared_ptr<AVBuffer> &outputBuffer)
{
    // deep copy input buffer to output buffer
    CHECK_RETURN_RET_ELOG(!inputBuffer, Status::ERROR_INVALID_BUFFER_SIZE, "input buffer is null");

    outputBuffer->dts_ = inputBuffer->dts_;
    outputBuffer->pts_ = inputBuffer->pts_;
    outputBuffer->duration_ = inputBuffer->duration_;
    outputBuffer->flag_ = inputBuffer->flag_;
    *outputBuffer->meta_.get() = *inputBuffer->meta_.get();
    if (inputBuffer->memory_ != nullptr && inputBuffer->memory_->GetSize() > 0) {
        int32_t retInt = outputBuffer->memory_->Write(inputBuffer->memory_->GetAddr(),
            inputBuffer->memory_->GetSize(), 0);
        CHECK_RETURN_RET_ELOG(retInt <= 0, Status::ERROR_NO_MEMORY, "Write sample in buffer failed.");
    } else {
        outputBuffer->memory_->SetSize(0);
    }
    return Status::OK;
}
} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP