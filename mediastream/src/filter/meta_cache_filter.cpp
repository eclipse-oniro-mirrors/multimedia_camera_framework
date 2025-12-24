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

#include "meta_cache_filter.h"
#include <ctime>
#include <sys/time.h>
#include "blocking_queue.h"
#include "meta_buffer_wrapper.h"
#include "video_buffer_wrapper.h"
#include "sync_fence.h"
#include "camera_log.h"
#include "video_encoder_filter.h"
#include "moving_photo_engine_context.h"
#include "cfilter.h"
#include "cfilter_factory.h"


// LCOV_EXCL_START
namespace OHOS {
namespace CameraStandard {

static AutoRegisterCFilter<MetaCacheFilter> g_registerMetaCacheFilter("builtin.camera.meta_cache",
    CFilterType::MOVING_PHOTO_META_CACHE,
    [](const std::string& name, const CFilterType type) {
        return std::make_shared<MetaCacheFilter>(name, CFilterType::MOVING_PHOTO_META_CACHE);
    });


class MetaCacheFilterLinkCallback : public CFilterLinkCallback {
public:
    explicit MetaCacheFilterLinkCallback(std::shared_ptr<MetaCacheFilter> metaCacheFilter)
        : metaCacheFilter_(std::move(metaCacheFilter))
    {
    }

    ~MetaCacheFilterLinkCallback() = default;

    void OnLinkedResult(const sptr<AVBufferQueueProducer> &queue, std::shared_ptr<Meta> &meta) override
    {
        if (auto metaCacheFilter = metaCacheFilter_.lock()) {
            metaCacheFilter->OnLinkedResult(queue, meta);
        } else {
            MEDIA_INFO_LOG("invalid metaCacheFilter");
        }
    }

    void OnUnlinkedResult(std::shared_ptr<Meta> &meta) override
    {
        if (auto metaCacheFilter = metaCacheFilter_.lock()) {
            metaCacheFilter->OnUnlinkedResult(meta);
        } else {
            MEDIA_INFO_LOG("invalid metaCacheFilter");
        }
    }

    void OnUpdatedResult(std::shared_ptr<Meta> &meta) override
    {
        if (auto metaCacheFilter = metaCacheFilter_.lock()) {
            metaCacheFilter->OnUpdatedResult(meta);
        } else {
            MEDIA_INFO_LOG("invalid metaCacheFilter");
        }
    }
private:
    std::weak_ptr<MetaCacheFilter> metaCacheFilter_;
};

class ConsumerMetaSurfaceBufferListener : public IBufferConsumerListener {
public:
    explicit ConsumerMetaSurfaceBufferListener(std::shared_ptr<MetaCacheFilter> metaCacheFilter)
        : metaCacheFilter_(std::move(metaCacheFilter))
    {
    }
    
    void OnBufferAvailable()
    {
        if (auto metaCacheFilter = metaCacheFilter_.lock()) {
            metaCacheFilter->OnBufferAvailable();
        } else {
            MEDIA_INFO_LOG("invalid metaCacheFilter");
        }
    }

private:
    std::weak_ptr<MetaCacheFilter> metaCacheFilter_;
};

MetaCacheFilter::MetaCacheFilter(std::string name, CFilterType type)
    : CFilter(name, type) {

    metaCache_ = make_shared<FixedSizeList<sptr<MetaBufferWrapper>>>(8);

    MEDIA_INFO_LOG("MetaCacheFilter::MetaCacheFilter called");
}

MetaCacheFilter::~MetaCacheFilter()
{
    MEDIA_INFO_LOG("MetaCacheFilter::~MetaCacheFilter called");
}

Status MetaCacheFilter::SetCodecFormat(const std::shared_ptr<Meta> &format)
{
    MEDIA_INFO_LOG("SetCodecFormat");
    return Status::OK;
}

void MetaCacheFilter::Init(const std::shared_ptr<CEventReceiver> &receiver,
    const std::shared_ptr<CFilterCallback> &callback)
{
    MEDIA_INFO_LOG("MetaCacheFilter::Init E");
    eventReceiver_ = receiver;
    filterCallback_ = callback;
}

Status MetaCacheFilter::Configure(const std::shared_ptr<Meta> &parameter)
{
    MEDIA_INFO_LOG("Configure");
    configureParameter_ = parameter;
    return Status::OK;
}

sptr<Surface> MetaCacheFilter::GetInputSurface()
{
    MEDIA_INFO_LOG("MetaCacheFilter::GetInputSurface");
    sptr<Surface> consumerSurface = Surface::CreateSurfaceAsConsumer("movingPhotoMeta");
    CHECK_RETURN_RET_ELOG(consumerSurface == nullptr, nullptr, "Create the surface consumer fail");
    sptr<IBufferProducer> producer = consumerSurface->GetProducer();
    CHECK_RETURN_RET_ELOG(producer == nullptr, nullptr, "Get the surface producer fail");
    sptr<Surface> producerSurface = Surface::CreateSurfaceAsProducer(producer);
    CHECK_RETURN_RET_ELOG(producerSurface == nullptr, nullptr, "CreateSurfaceAsProducer fail");
    inputSurface_ = consumerSurface;
    sptr<IBufferConsumerListener> listener = new ConsumerMetaSurfaceBufferListener(shared_from_this());
    inputSurface_->RegisterConsumerListener(listener);
    return producerSurface;
}

Status MetaCacheFilter::DoPrepare()
{
    MEDIA_INFO_LOG("MetaCacheFilter::DoPrepare E");
    filterCallback_->OnCallback(shared_from_this(),
                                CFilterCallBackCommand::NEXT_FILTER_NEEDED,
                                CStreamType::RAW_METADATA);
    return Status::OK;
}

Status MetaCacheFilter::DoStart()
{
    MEDIA_INFO_LOG("MetaCacheFilter::Start");
    isStop_ = false;
    return Status::OK;
}

Status MetaCacheFilter::DoPause()
{
    MEDIA_INFO_LOG("Pause");
    isStop_ = true;
    latestPausedTime_ = latestBufferTime_;
    return Status::OK;
}

Status MetaCacheFilter::DoResume()
{
    MEDIA_INFO_LOG("Resume");
    isStop_ = false;
    refreshTotalPauseTime_ = true;
    return Status::OK;
}

Status MetaCacheFilter::DoStop()
{
    MEDIA_INFO_LOG("Stop");
    isStop_ = true;
    latestBufferTime_ = -1;
    latestPausedTime_ = -1;
    totalPausedTime_ = 0;
    refreshTotalPauseTime_ = false;
    return Status::OK;
}

Status MetaCacheFilter::DoFlush()
{
    MEDIA_INFO_LOG("Flush");
    return Status::OK;
}

Status MetaCacheFilter::DoRelease()
{
    MEDIA_INFO_LOG("Release");
    return Status::OK;
}

Status MetaCacheFilter::NotifyEos()
{
    MEDIA_INFO_LOG("NotifyEos");
    return Status::OK;
}

void MetaCacheFilter::SetParameter(const std::shared_ptr<Meta> &parameter)
{
    MEDIA_INFO_LOG("SetParameter");
}

void MetaCacheFilter::GetParameter(std::shared_ptr<Meta> &parameter)
{
    MEDIA_INFO_LOG("GetParameter");
}

Status MetaCacheFilter::LinkNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("LinkNext filterType:%{public}d", (int32_t)nextFilter->GetCFilterType());
    nextFilter_ = nextFilter;
    nextCFiltersMap_[outType].push_back(nextFilter_);
    auto filterLinkCallback = std::make_shared<MetaCacheFilterLinkCallback>(shared_from_this());
    nextFilter->OnLinked(outType, configureParameter_, filterLinkCallback);
    return Status::OK;
}

Status MetaCacheFilter::UpdateNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("UpdateNext");
    return Status::OK;
}

Status MetaCacheFilter::UnLinkNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("UnLinkNext");
    return Status::OK;
}

CFilterType MetaCacheFilter::GetFilterType()
{
    MEDIA_INFO_LOG("GetFilterType");
    return filterType_;
}

Status MetaCacheFilter::OnLinked(CStreamType inType, const std::shared_ptr<Meta> &meta,
    const std::shared_ptr<CFilterLinkCallback> &callback)
{
    MEDIA_INFO_LOG("OnLinked");
    return Status::OK;
}

Status MetaCacheFilter::OnUpdated(CStreamType inType, const std::shared_ptr<Meta> &meta,
    const std::shared_ptr<CFilterLinkCallback> &callback)
{
    MEDIA_INFO_LOG("OnUpdated");
    return Status::OK;
}

Status MetaCacheFilter::OnUnLinked(CStreamType inType, const std::shared_ptr<CFilterLinkCallback>& callback)
{
    MEDIA_INFO_LOG("OnUnLinked");
    return Status::OK;
}

void MetaCacheFilter::OnLinkedResult(const sptr<AVBufferQueueProducer> &outputBufferQueue,
    std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("OnLinkedResult");
    outputBufferQueueProducer_ = outputBufferQueue;
}

void MetaCacheFilter::OnUpdatedResult(std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("OnUpdatedResult");
}

void MetaCacheFilter::OnUnlinkedResult(std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("OnUnlinkedResult");
}

void MetaCacheFilter::OnBufferAvailable()
{
    MEDIA_DEBUG_LOG("MetaCacheFilter::OnBufferAvailable E");
    CHECK_RETURN_ELOG(inputSurface_ == nullptr, "MetaCacheFilter::OnBufferAvailable inputSurface_ is nullptr");
    int64_t timestamp;
    OHOS::Rect damage;
    sptr<SurfaceBuffer> buffer;
    sptr<SyncFence> syncFence = SyncFence::INVALID_FENCE;
    SurfaceError surfaceRet = inputSurface_->AcquireBuffer(buffer, syncFence, timestamp, damage);
    CHECK_RETURN_ELOG(surfaceRet != SURFACE_ERROR_OK, "Failed to acquire meta surface buffer");
    surfaceRet = inputSurface_->DetachBufferFromQueue(buffer, true);
    CHECK_RETURN_ELOG(surfaceRet != SURFACE_ERROR_OK, "Failed to detach meta buffer. %{public}d", surfaceRet);
    sptr<MetaBufferWrapper> metaRecord = new MetaBufferWrapper(buffer, timestamp, inputSurface_);
    metaCache_->add(metaRecord);
    MEDIA_DEBUG_LOG("MetaCacheFilter::OnBufferAvailable %{public}" PRId64, timestamp);
    MEDIA_DEBUG_LOG("MetaCacheFilter::OnBufferAvailable X");
}

sptr<MetaBufferWrapper> MetaCacheFilter::FindMetaBufferWrapper(int64_t timestamp)
{
    auto metaRecord =
        metaCache_->find_if([timestamp](const sptr<MetaBufferWrapper> obj) {
          return obj && obj->GetTimestamp() == timestamp;
        });
    if (metaRecord.has_value()) {
        MEDIA_DEBUG_LOG("MetaCacheFilter::FindMetaBufferWrapper success");\
        return metaRecord.value();
    }
    return nullptr;
}
} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP