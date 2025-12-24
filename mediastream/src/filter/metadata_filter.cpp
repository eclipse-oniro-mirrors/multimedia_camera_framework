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

#include "metadata_filter.h"

#include "camera_log.h"
#include "cfilter_factory.h"
#include "muxer_filter.h"
#include "sync_fence.h"

// LCOV_EXCL_START
namespace OHOS {
namespace CameraStandard {
namespace {
    constexpr uint32_t NS_PER_US = 1000;
}

static AutoRegisterCFilter<MetaDataFilter> g_registerTimedMetaSurfaceFilter("camera.timed_metadata",
    CFilterType::TIMED_METADATA,
    [](const std::string& name, const CFilterType type) {
        return std::make_shared<MetaDataFilter>(name, CFilterType::TIMED_METADATA);
    });

class MetaDataFilterLinkCallback : public CFilterLinkCallback {
public:
    explicit MetaDataFilterLinkCallback(std::shared_ptr<MetaDataFilter> metaDataFilter)
        : metaDataFilter_(std::move(metaDataFilter))
    {
    }

    ~MetaDataFilterLinkCallback() = default;

    void OnLinkedResult(const sptr<AVBufferQueueProducer>& queue, std::shared_ptr<Meta>& meta) override
    {
        if (auto metaDataFilter = metaDataFilter_.lock()) {
            metaDataFilter->OnLinkedResult(queue, meta);
        } else {
            MEDIA_INFO_LOG("invalid metaDataFilter");
        }
    }

    void OnUnlinkedResult(std::shared_ptr<Meta>& meta) override
    {
        if (auto metaDataFilter = metaDataFilter_.lock()) {
            metaDataFilter->OnUnlinkedResult(meta);
        } else {
            MEDIA_INFO_LOG("invalid metaDataFilter");
        }
    }

    void OnUpdatedResult(std::shared_ptr<Meta>& meta) override
    {
        if (auto metaDataFilter = metaDataFilter_.lock()) {
            metaDataFilter->OnUpdatedResult(meta);
        } else {
            MEDIA_INFO_LOG("invalid metaDataFilter");
        }
    }
private:
    std::weak_ptr<MetaDataFilter> metaDataFilter_;
};

class MetaDataSurfaceBufferListener : public IBufferConsumerListener {
public:
    explicit MetaDataSurfaceBufferListener(std::shared_ptr<MetaDataFilter> metaDataFilter)
        : metaDataFilter_(std::move(metaDataFilter))
    {
    }
    
    void OnBufferAvailable()
    {
        if (auto metaDataFilter = metaDataFilter_.lock()) {
            metaDataFilter->OnBufferAvailable();
        } else {
            MEDIA_INFO_LOG("invalid metaDataFilter");
        }
    }

private:
    std::weak_ptr<MetaDataFilter> metaDataFilter_;
};

MetaDataFilter::MetaDataFilter(std::string name, CFilterType type): CFilter(name, type), name_(name)
{
    MEDIA_INFO_LOG("timed meta data filter create, name:%{public}s", name_.c_str());
}

MetaDataFilter::~MetaDataFilter()
{
    MEDIA_INFO_LOG("timed meta data filter destroy, name:%{public}s", name_.c_str());
}

Status MetaDataFilter::SetCodecFormat(const std::shared_ptr<Meta>& format)
{
    MEDIA_INFO_LOG("SetCodecFormat");
    return Status::OK;
}

void MetaDataFilter::Init(const std::shared_ptr<CEventReceiver>& receiver,
    const std::shared_ptr<CFilterCallback>& callback)
{
    MEDIA_INFO_LOG("Init");
    CAMERA_SYNC_TRACE;
    eventReceiver_ = receiver;
    filterCallback_ = callback;
}

Status MetaDataFilter::Configure(const std::shared_ptr<Meta>& parameter)
{
    MEDIA_INFO_LOG("Configure");
    configureParameter_ = parameter;
    return Status::OK;
}

Status MetaDataFilter::SetInputMetaSurface(sptr<Surface> surface)
{
    MEDIA_INFO_LOG("SetInputMetaSurface");
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(surface == nullptr, Status::ERROR_UNKNOWN, "surface is nullptr");
    inputSurface_ = surface;
    sptr<IBufferConsumerListener> listener = new MetaDataSurfaceBufferListener(shared_from_this());
    inputSurface_->RegisterConsumerListener(listener);
    return Status::OK;
}

sptr<Surface> MetaDataFilter::GetInputMetaSurface()
{
    MEDIA_INFO_LOG("GetInputMetaSurface");
    CHECK_RETURN_RET_ILOG(producerSurface_ != nullptr, producerSurface_, "producerSurface_ is already exist");
    CAMERA_SYNC_TRACE;
    sptr<Surface> consumerSurface = Surface::CreateSurfaceAsConsumer("MetadataSurface");
    CHECK_RETURN_RET_ELOG(consumerSurface == nullptr, nullptr, "Create the surface consumer fail");
    GSError err = consumerSurface->SetDefaultUsage(METASURFACE_USAGE);
    if (err == GSERROR_OK) {
        MEDIA_INFO_LOG("set consumer usage 0x%{public}x succ", METASURFACE_USAGE);
    } else {
        MEDIA_ERR_LOG("set consumer usage 0x%{public}x fail", METASURFACE_USAGE);
    }
    sptr<IBufferProducer> producer = consumerSurface->GetProducer();
    CHECK_RETURN_RET_ELOG(producer == nullptr, nullptr, "Get the surface producer fail");
    sptr<Surface> producerSurface = Surface::CreateSurfaceAsProducer(producer);
    CHECK_RETURN_RET_ELOG(producerSurface == nullptr, nullptr, "CreateSurfaceAsProducer fail");
    inputSurface_ = consumerSurface;
    producerSurface_ = producerSurface;
    sptr<IBufferConsumerListener> listener = new MetaDataSurfaceBufferListener(shared_from_this());
    inputSurface_->RegisterConsumerListener(listener);
    return producerSurface;
}

Status MetaDataFilter::DoPrepare()
{
    MEDIA_INFO_LOG("Prepare");
    CAMERA_SYNC_TRACE;
    filterCallback_->OnCallback(shared_from_this(), CFilterCallBackCommand::NEXT_FILTER_NEEDED,
        CStreamType::ENCODED_VIDEO);
    return Status::OK;
}

Status MetaDataFilter::DoStart()
{
    MEDIA_INFO_LOG("Start");
    CAMERA_SYNC_TRACE;
    isStop_ = false;
    startBufferTime_ = -1;
    latestBufferTime_ = -1;
    return Status::OK;
}

Status MetaDataFilter::DoPause()
{
    MEDIA_INFO_LOG("Pause");
    CAMERA_SYNC_TRACE;
    isStop_ = true;
    latestPausedTime_ = latestBufferTime_;
    return Status::OK;
}

Status MetaDataFilter::DoResume()
{
    MEDIA_INFO_LOG("Resume");
    CAMERA_SYNC_TRACE;
    isStop_ = false;
    refreshTotalPauseTime_ = true;
    return Status::OK;
}

Status MetaDataFilter::DoStop()
{
    MEDIA_INFO_LOG("Stop");
    CAMERA_SYNC_TRACE;
    isStop_ = true;
    startBufferTime_ = -1;
    latestBufferTime_ = -1;
    latestPausedTime_ = -1;
    totalPausedTime_ = 0;
    refreshTotalPauseTime_ = false;
    return Status::OK;
}

Status MetaDataFilter::DoFlush()
{
    MEDIA_INFO_LOG("Flush");
    return Status::OK;
}

Status MetaDataFilter::DoRelease()
{
    MEDIA_INFO_LOG("Release");
    CAMERA_SYNC_TRACE;
    return Status::OK;
}

Status MetaDataFilter::NotifyEos()
{
    MEDIA_INFO_LOG("NotifyEos");
    return Status::OK;
}

void MetaDataFilter::SetParameter(const std::shared_ptr<Meta>& parameter)
{
    MEDIA_INFO_LOG("SetParameter");
    CAMERA_SYNC_TRACE;
}

void MetaDataFilter::GetParameter(std::shared_ptr<Meta>& parameter)
{
    MEDIA_INFO_LOG("GetParameter");
    CAMERA_SYNC_TRACE;
}

Status MetaDataFilter::LinkNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("LinkNext");
    CAMERA_SYNC_TRACE;
    nextFilter_ = nextFilter;
    nextCFiltersMap_[outType].push_back(nextFilter_);
    std::shared_ptr<CFilterLinkCallback> filterLinkCallback =
        std::make_shared<MetaDataFilterLinkCallback>(shared_from_this());
    nextFilter->OnLinked(outType, configureParameter_, filterLinkCallback);
    return Status::OK;
}

Status MetaDataFilter::UpdateNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("UpdateNext");
    return Status::OK;
}

Status MetaDataFilter::UnLinkNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("UnLinkNext");
    return Status::OK;
}

CFilterType MetaDataFilter::GetFilterType()
{
    MEDIA_INFO_LOG("GetFilterType");
    return filterType_;
}

Status MetaDataFilter::OnLinked(CStreamType inType, const std::shared_ptr<Meta>& meta,
    const std::shared_ptr<CFilterLinkCallback>& callback)
{
    MEDIA_INFO_LOG("OnLinked");
    return Status::OK;
}

Status MetaDataFilter::OnUpdated(CStreamType inType, const std::shared_ptr<Meta>& meta,
    const std::shared_ptr<CFilterLinkCallback>& callback)
{
    MEDIA_INFO_LOG("OnUpdated");
    return Status::OK;
}

Status MetaDataFilter::OnUnLinked(CStreamType inType, const std::shared_ptr<CFilterLinkCallback>& callback)
{
    MEDIA_INFO_LOG("OnUnLinked");
    return Status::OK;
}

void MetaDataFilter::OnLinkedResult(const sptr<AVBufferQueueProducer>& outputBufferQueue,
    std::shared_ptr<Meta>& meta)
{
    MEDIA_INFO_LOG("OnLinkedResult");
    CAMERA_SYNC_TRACE;
    outputBufferQueueProducer_ = outputBufferQueue;
}

void MetaDataFilter::OnUpdatedResult(std::shared_ptr<Meta>& meta)
{
    MEDIA_INFO_LOG("OnUpdatedResult");
}

void MetaDataFilter::OnUnlinkedResult(std::shared_ptr<Meta>& meta)
{
    MEDIA_INFO_LOG("OnUnlinkedResult");
}

void MetaDataFilter::OnBufferAvailable()
{
    CAMERA_SYNC_TRACE;
    sptr<SurfaceBuffer> buffer;
    sptr<SyncFence> fence;
    int64_t timestamp;
    int32_t bufferSize = 0;
    OHOS::Rect damage;
    GSError ret = inputSurface_->AcquireBuffer(buffer, fence, timestamp, damage);
    CHECK_RETURN(ret != GSERROR_OK || buffer == nullptr);

    constexpr uint32_t waitForEver = -1;
    (void)fence->Wait(waitForEver);
    if (isStop_) {
        inputSurface_->ReleaseBuffer(buffer, -1);
        return;
    }
    auto extraData = buffer->GetExtraData();
    if (extraData) {
        extraData->ExtraGet("timeStamp", timestamp);
        extraData->ExtraGet("dataSize", bufferSize);
    }
    int64_t yuvFirstFrameTs;
    GetMuxerFirstFrameTimestamp(yuvFirstFrameTs);
    MEDIA_DEBUG_LOG("metadata filter name:%{public}s, buffer timestamp:%{public}" PRId64
                    ", dataSize:%{public}d, buffer szie: %{public}u, yuvFirstFrameTs:%{public}" PRId64,
                    name_.c_str(), timestamp, bufferSize, buffer->GetSize(), yuvFirstFrameTs);
    if (timestamp == 0 || timestamp <= latestBufferTime_) {
        MEDIA_ERR_LOG("timestamp invalid. name: %{public}s, ts:%{public}" PRId64 ", latestBufferTime_:%{public}" PRId64
                      ", yuvFirstFrameTs:%{public}" PRId64,
                      name_.c_str(), timestamp, latestBufferTime_, yuvFirstFrameTs);
        inputSurface_->ReleaseBuffer(buffer, -1);
        return;
    }

    std::shared_ptr<AVBuffer> emptyOutputBuffer;
    AVBufferConfig avBufferConfig;
    avBufferConfig.size = bufferSize;
    avBufferConfig.memoryType = MemoryType::SHARED_MEMORY;
    avBufferConfig.memoryFlag = MemoryFlag::MEMORY_READ_WRITE;
    int32_t timeOutMs = 100;
    Status status = outputBufferQueueProducer_->RequestBuffer(emptyOutputBuffer, avBufferConfig, timeOutMs);
    if (status != Status::OK) {
        MEDIA_ERR_LOG("RequestBuffer fail.");
        inputSurface_->ReleaseBuffer(buffer, -1);
        return;
    }
    std::shared_ptr<AVMemory>& bufferMem = emptyOutputBuffer->memory_;
    if (emptyOutputBuffer->memory_ == nullptr) {
        MEDIA_INFO_LOG("emptyOutputBuffer->memory_ is nullptr.");
        inputSurface_->ReleaseBuffer(buffer, -1);
        return;
    }
    bufferMem->Write((const uint8_t *)buffer->GetVirAddr(), bufferSize, 0);
    UpdateBufferConfig(emptyOutputBuffer, timestamp);
    status = outputBufferQueueProducer_->PushBuffer(emptyOutputBuffer, true);
    CHECK_RETURN_ELOG(status != Status::OK, "PushBuffer fail");

    inputSurface_->ReleaseBuffer(buffer, -1);
}

void MetaDataFilter::UpdateBufferConfig(std::shared_ptr<AVBuffer> buffer, int64_t timestamp)
{
    if (startBufferTime_ == -1) {
        startBufferTime_ = timestamp;
    }
    latestBufferTime_ = timestamp;
    if (refreshTotalPauseTime_) {
        if (latestPausedTime_ != -1 && latestBufferTime_ > latestPausedTime_) {
            totalPausedTime_ += latestBufferTime_ - latestPausedTime_;
        }
        refreshTotalPauseTime_ = false;
    }
    // meta track is NS based, debug track is US based
    if (name_ == "RawDebugFilter" || (name_ == "MovieDebugFilter")) {
        buffer->pts_ = (timestamp - startBufferTime_ - totalPausedTime_);
    } else {
        buffer->pts_ = (timestamp - startBufferTime_ - totalPausedTime_) / NS_PER_US;
    }
    
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("UpdateBufferConfig buffer->pts: %{public}" PRId64, buffer->pts_);
}

void MetaDataFilter::GetMuxerFirstFrameTimestamp(int64_t& timestamp)
{
    MEDIA_DEBUG_LOG("called");
    CHECK_RETURN_ELOG(!nextFilter_, "nextFilter_ is null");
    std::shared_ptr<MuxerFilter> muxerFilter = std::static_pointer_cast<MuxerFilter>(nextFilter_);
    if (muxerFilter != nullptr) {
        muxerFilter->GetMuxerFirstFrameTimestamp(timestamp);
    } else {
        MEDIA_ERR_LOG("muxerFilter is null");
    }
}

} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP