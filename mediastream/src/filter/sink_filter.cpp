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

#include "sink_filter.h"

#include "avbuffer_queue_define.h"
#include "camera_log.h"
#include "cfilter_factory.h"

// LCOV_EXCL_START
namespace OHOS {
namespace CameraStandard {
namespace {
    constexpr uint32_t MAX_BUFFER_COUNT = 10;
    constexpr uint32_t REQUEST_BUFFER_TIMEOUT = 0; 
    const std::string INPUT_BUFFER_QUEUE_NAME = "DeferredSinkInputBufferQueue";
}
static AutoRegisterCFilter<SinkFilter> g_registerSinkFilter("camera.sink",
    CFilterType::DEFER_AUDIO_SOURCE,
    [](const std::string& name, const CFilterType type) {
        return std::make_shared<SinkFilter>(name, CFilterType::DEFER_AUDIO_SOURCE);
    });

class SinkFilterLinkCallback : public CFilterLinkCallback {
public:
    explicit SinkFilterLinkCallback(const std::weak_ptr<SinkFilter>& sinkFilter)
        : sinkFilter_(sinkFilter) {}

    void OnLinkedResult(const sptr<AVBufferQueueProducer>& queue, std::shared_ptr<Meta>& meta) override
    {
        auto sinkFilter = sinkFilter_.lock();
        CHECK_RETURN(sinkFilter == nullptr);
        sinkFilter->OnLinkedResult(queue, meta);
    }

    void OnUnlinkedResult(std::shared_ptr<Meta>& meta) override
    {
        auto sinkFilter = sinkFilter_.lock();
        CHECK_RETURN(sinkFilter == nullptr);
        sinkFilter->OnUnlinkedResult(meta);
    }

    void OnUpdatedResult(std::shared_ptr<Meta>& meta) override
    {
        auto sinkFilter = sinkFilter_.lock();
        CHECK_RETURN(sinkFilter == nullptr);
        sinkFilter->OnUpdatedResult(meta);
    }
private:
    std::weak_ptr<SinkFilter> sinkFilter_;
};

SinkTrack::SinkTrack(const std::weak_ptr<SinkFilter>& filter) : filter_(filter)
{
    MEDIA_DEBUG_LOG("entered.");
}

std::shared_ptr<AVBuffer> SinkTrack::GetBuffer()
{
    std::shared_ptr<AVBuffer> outBuffer;
    CHECK_RETURN_RET(bufferAvailableCount_ <= 0, outBuffer);
    Status ret = consumer_->AcquireBuffer(outBuffer);
    if (ret != Status::OK) {
        MEDIA_ERR_LOG("Track %{public}s lost %{public}d frames",
            mimeType_.c_str(), bufferAvailableCount_.load());
        --bufferAvailableCount_;
        auto filter = filter_.lock();
        CHECK_EXECUTE(filter, filter->ReleaseBuffer());
        return outBuffer;
    }
    consumer_->DetachBuffer(outBuffer);
    return outBuffer;
}

void SinkTrack::ReleaseBuffer(std::shared_ptr<AVBuffer>& inputBuffer)
{
    if (inputBuffer != nullptr) {
        auto ret = consumer_->AttachBuffer(inputBuffer, false);
        MEDIA_DEBUG_LOG("-------AttachBuffer-------ret: %{public}d", ret);
        --bufferAvailableCount_;
        auto filter = filter_.lock();
        CHECK_EXECUTE(filter, filter->ReleaseBuffer());
    }
}

void SinkTrack::OnBufferAvailable()
{
    ++bufferAvailableCount_;
    MEDIA_INFO_LOG("Track %{public}s bufferAvailableCount: %{public}d",
        mimeType_.c_str(), bufferAvailableCount_.load());
    auto filter = filter_.lock();
    CHECK_EXECUTE(filter, filter->OnBufferAvailable());
}

SinkFilter::SinkFilter(std::string name, CFilterType type): CFilter(name, type)
{
    MEDIA_DEBUG_LOG("entered.");
}

SinkFilter::~SinkFilter()
{
    MEDIA_INFO_LOG("entered. name:%{public}s", name_.c_str());
}

void SinkFilter::Init(const std::shared_ptr<CEventReceiver>& receiver,
    const std::shared_ptr<CFilterCallback>& callback)
{
    MEDIA_INFO_LOG("Init");
    CAMERA_SYNC_TRACE;
    receiver_ = receiver;
    callback_ = callback;
}

Status SinkFilter::DoPrepare()
{
    MEDIA_INFO_LOG("Prepare");
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET(callback_ == nullptr || audioTrack_ == nullptr, Status::ERROR_NULL_POINTER);
    sptr<IConsumerListener> listener = audioTrack_;
    audioTrack_->consumer_->SetBufferAvailableListener(listener);
    callback_->OnCallback(shared_from_this(), CFilterCallBackCommand::NEXT_FILTER_NEEDED, CStreamType::ENCODED_AUDIO);
    return Status::OK;
}

Status SinkFilter::DoStart()
{
    MEDIA_INFO_LOG("Start");
    CAMERA_SYNC_TRACE;
    return Status::OK;
}

Status SinkFilter::DoPause()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("Pause");
    return Status::OK;
}

Status SinkFilter::DoResume()
{
    MEDIA_INFO_LOG("Resume");
    return Status::OK;
}

Status SinkFilter::DoStop()
{
    MEDIA_INFO_LOG("DoStop");
    return Status::OK;
}

Status SinkFilter::DoFlush()
{
    return Status::OK;
}

Status SinkFilter::DoRelease()
{
    MEDIA_INFO_LOG("Release");
    return Status::OK;
}

Status SinkFilter::LinkNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("LinkNext type: %{public}d", nextFilter->GetCFilterType());
    nextCFiltersMap_[outType].push_back(nextFilter);
    auto filterLinkCallback = std::make_shared<SinkFilterLinkCallback>(weak_from_this());
    auto ret = nextFilter->OnLinked(outType, audioTrack_->trackMeta_, filterLinkCallback);
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "OnLinked failed");
    return Status::OK;
}

Status SinkFilter::UpdateNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("UpdateNext");
    return Status::OK;
}

Status SinkFilter::UnLinkNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("UnLinkNext");
    return Status::OK;
}

Status SinkFilter::OnLinked(CStreamType inType, const std::shared_ptr<Meta>& meta,
    const std::shared_ptr<CFilterLinkCallback>& callback)
{
    MEDIA_INFO_LOG("OnLinked");
    onLinkedResultCallback_ = callback;
    if (inType == CStreamType::RAW_AUDIO) {
        sptr<SinkTrack> track = sptr<SinkTrack>::MakeSptr(shared_from_this());
        track->trackMeta_ = meta;
        track->bufferQueuq_ = AVBufferQueue::Create(
            MAX_BUFFER_COUNT, MemoryType::SHARED_MEMORY, INPUT_BUFFER_QUEUE_NAME);
        track->producer_ = track->bufferQueuq_->GetProducer();
        track->consumer_ = track->bufferQueuq_->GetConsumer();
        audioTrack_ = track;
    }
    return Status::OK;
}

Status SinkFilter::OnUpdated(CStreamType inType, const std::shared_ptr<Meta>& meta,
    const std::shared_ptr<CFilterLinkCallback>& callback)
{
    MEDIA_INFO_LOG("OnUpdated");
    return Status::OK;
}

Status SinkFilter::OnUnLinked(CStreamType inType, const std::shared_ptr<CFilterLinkCallback>& callback)
{
    MEDIA_INFO_LOG("OnUnLinked");
    return Status::OK;
}

void SinkFilter::OnLinkedResult(const sptr<AVBufferQueueProducer>& outputBufferQueue, std::shared_ptr<Meta>& meta)
{
    CHECK_RETURN_ELOG(onLinkedResultCallback_ == nullptr || audioTrack_ == nullptr, "OnLinkedResult is nullptr");
    outputBufferProducer_ = outputBufferQueue;
    onLinkedResultCallback_->OnLinkedResult(audioTrack_->producer_, meta);
}

void SinkFilter::OnUpdatedResult(std::shared_ptr<Meta>& meta)
{
}

void SinkFilter::OnUnlinkedResult(std::shared_ptr<Meta>& meta)
{
}

void SinkFilter::OnBufferAvailable()
{
    auto outBuffer = audioTrack_->GetBuffer();
    CHECK_RETURN_ELOG(outBuffer == nullptr, "OutBuffer is bullptr.");
    MEDIA_INFO_LOG("OnBufferAvailable flag:%{public}d, pts: %{public}" PRId64, outBuffer->flag_, outBuffer->pts_);
    
    AVBufferConfig avBufferConfig;
    avBufferConfig.capacity = outBuffer->memory_->GetCapacity();
    avBufferConfig.size = outBuffer->memory_->GetSize();
    avBufferConfig.memoryType = outBuffer->GetConfig().memoryType;
    CHECK_RETURN_ELOG(outputBufferProducer_ == nullptr, "outputBufferProducer_ is nullptr");
    std::shared_ptr<AVBuffer> inputBuffer;
    outputBufferProducer_->RequestBuffer(inputBuffer, avBufferConfig, REQUEST_BUFFER_TIMEOUT);
    outputBufferProducer_->DetachBuffer(inputBuffer);
    CHECK_RETURN_ELOG(inputBuffer == nullptr, "inputBuffer is bullptr.");

    auto ret = outputBufferProducer_->AttachBuffer(outBuffer, true);
    MEDIA_DEBUG_LOG("AttachBuffer ret: %{public}d", ret);
    audioTrack_->ReleaseBuffer(inputBuffer);
}

void SinkFilter::ReleaseBuffer()
{
}
} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP