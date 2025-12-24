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

#include "video_cache_filter.h"
#include <ctime>
#include <sys/time.h>
#include "avbuffer_common.h"
#include "avbuffer_queue_define.h"
#include "blocking_queue.h"
#include "meta_key.h"
#include "moving_photo_video_encoder_filter.h"
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

static AutoRegisterCFilter<VideoCacheFilter> g_registerVideoCacheFilter("camera.video_cache",
    CFilterType::MOVING_PHOTO_VIDEO_CACHE,
    [](const std::string& name, const CFilterType type) {
        return std::make_shared<VideoCacheFilter>(name, CFilterType::MOVING_PHOTO_VIDEO_CACHE);
    });


class VideoCacheFilterLinkCallback : public CFilterLinkCallback {
public:
    explicit VideoCacheFilterLinkCallback(std::shared_ptr<VideoCacheFilter> videoCacheFilter)
        : videoCacheFilter_(std::move(videoCacheFilter))
    {
    }

    ~VideoCacheFilterLinkCallback() = default;

    void OnLinkedResult(const sptr<AVBufferQueueProducer> &queue, std::shared_ptr<Meta> &meta) override
    {
        if (auto videoCacheFilter = videoCacheFilter_.lock()) {
            videoCacheFilter->OnLinkedResult(queue, meta);
        } else {
            MEDIA_INFO_LOG("invalid videoCacheFilter");
        }
    }

    void OnUnlinkedResult(std::shared_ptr<Meta> &meta) override
    {
        if (auto videoCacheFilter = videoCacheFilter_.lock()) {
            videoCacheFilter->OnUnlinkedResult(meta);
        } else {
            MEDIA_INFO_LOG("invalid videoCacheFilter");
        }
    }

    void OnUpdatedResult(std::shared_ptr<Meta> &meta) override
    {
        if (auto videoCacheFilter = videoCacheFilter_.lock()) {
            videoCacheFilter->OnUpdatedResult(meta);
        } else {
            MEDIA_INFO_LOG("invalid videoCacheFilter");
        }
    }
private:
    std::weak_ptr<VideoCacheFilter> videoCacheFilter_;
};

class ConsumerSurfaceBufferListener : public IBufferConsumerListener {
public:
    explicit ConsumerSurfaceBufferListener(std::shared_ptr<VideoCacheFilter> videoCacheFilter)
        : videoCacheFilter_(std::move(videoCacheFilter))
    {
    }
    
    void OnBufferAvailable()
    {
        if (auto videoCacheFilter = videoCacheFilter_.lock()) {
            videoCacheFilter->OnBufferAvailable();
        } else {
            MEDIA_INFO_LOG("invalid videoCacheFilter");
        }
    }

private:
    std::weak_ptr<VideoCacheFilter> videoCacheFilter_;
};

VideoCacheFilter::VideoCacheFilter(std::string name, CFilterType type)
    : CFilter(name, type),
      videoBufferWrapperQueue_("videoBufferWrapperQueue", DEFAULT_BUFFER_SIZE) {
    MEDIA_INFO_LOG("VideoCacheFilter::VideoCacheFilter called");
}

VideoCacheFilter::~VideoCacheFilter()
{
    MEDIA_INFO_LOG("VideoCacheFilter::~VideoCacheFilter called");
}

Status VideoCacheFilter::SetCodecFormat(const std::shared_ptr<Meta> &format)
{
    MEDIA_INFO_LOG("SetCodecFormat");
    return Status::OK;
}

void VideoCacheFilter::Init(const std::shared_ptr<CEventReceiver> &receiver,
    const std::shared_ptr<CFilterCallback> &callback)
{
    MEDIA_INFO_LOG("VideoCacheFilter::Init E");
    eventReceiver_ = receiver;
    filterCallback_ = callback;
}

Status VideoCacheFilter::Configure(const std::shared_ptr<Meta> &parameter)
{
    MEDIA_INFO_LOG("Configure");
    configureParameter_ = parameter;
    return Status::OK;
}

sptr<Surface> VideoCacheFilter::GetInputSurface()
{
    MEDIA_INFO_LOG("VideoCacheFilter::GetInputSurface E");
    sptr<Surface> consumerSurface = Surface::CreateSurfaceAsConsumer("movingPhoto");
    CHECK_RETURN_RET_ELOG(consumerSurface == nullptr, nullptr, "Create the surface consumer fail");
    GSError err = consumerSurface->SetDefaultUsage(BUFFER_USAGE_VIDEO_ENCODER);
    CHECK_PRINT_ELOG(err != GSERROR_OK, "set consumer usage fail");
    sptr<IBufferProducer> producer = consumerSurface->GetProducer();
    CHECK_RETURN_RET_ELOG(producer == nullptr, nullptr, "Get the surface producer fail");
    sptr<Surface> producerSurface = Surface::CreateSurfaceAsProducer(producer);
    CHECK_RETURN_RET_ELOG(producerSurface == nullptr, nullptr, "CreateSurfaceAsProducer fail");
    inputSurface_ = consumerSurface;
    sptr<IBufferConsumerListener> listener = new ConsumerSurfaceBufferListener(shared_from_this());
    inputSurface_->RegisterConsumerListener(listener);
    int32_t width = 0;
    int32_t height = 0;
    bool existSize = configureParameter_ && 
                     configureParameter_->GetData(Tag::VIDEO_WIDTH, width) &&
                     configureParameter_->GetData(Tag::VIDEO_HEIGHT, height);
    CHECK_EXECUTE(inputSurface_ && existSize, inputSurface_->SetDefaultWidthAndHeight(width, height));
    return producerSurface;
}

void VideoCacheFilter::SetCacheFrameCount(uint32_t preCacheFrameCount, uint32_t postCacheFrameCount)
{
    preCacheFrameCount_ = preCacheFrameCount;
    postCacheFrameCount_ = postCacheFrameCount;
}

Status VideoCacheFilter::DoPrepare()
{
    MEDIA_INFO_LOG("VideoCacheFilter::DoPrepare E");
    filterCallback_->OnCallback(
        shared_from_this(), CFilterCallBackCommand::NEXT_FILTER_NEEDED, CStreamType::RAW_VIDEO);
    return Status::OK;
}

Status VideoCacheFilter::DoStart()
{
    MEDIA_INFO_LOG("VideoCacheFilter::DoStart E");
    isStop_ = false;
    return Status::OK;
}

Status VideoCacheFilter::DoPause()
{
    MEDIA_INFO_LOG("Pause");
    isStop_ = true;
    latestPausedTime_ = latestBufferTime_;
    return Status::OK;
}

Status VideoCacheFilter::DoResume()
{
    MEDIA_INFO_LOG("Resume");
    isStop_ = false;
    refreshTotalPauseTime_ = true;
    return Status::OK;
}

Status VideoCacheFilter::DoStop()
{
    MEDIA_INFO_LOG("Stop");
    isStop_ = true;
    latestBufferTime_ = -1;
    latestPausedTime_ = -1;
    totalPausedTime_ = 0;
    refreshTotalPauseTime_ = false;
    return Status::OK;
}

Status VideoCacheFilter::DoFlush()
{
    MEDIA_INFO_LOG("Flush");
    return Status::OK;
}

Status VideoCacheFilter::DoRelease()
{
    MEDIA_INFO_LOG("Release");
    return Status::OK;
}

Status VideoCacheFilter::NotifyEos()
{
    MEDIA_INFO_LOG("NotifyEos");
    return Status::OK;
}

void VideoCacheFilter::SetParameter(const std::shared_ptr<Meta> &parameter)
{
    MEDIA_INFO_LOG("SetParameter");
}

void VideoCacheFilter::GetParameter(std::shared_ptr<Meta> &parameter)
{
    MEDIA_INFO_LOG("GetParameter");
}

Status VideoCacheFilter::LinkNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("VideoCacheFilter::LinkNext filterType:%{public}d", (int32_t)nextFilter->GetCFilterType());
    nextFilter_.Set(nextFilter);
    nextCFiltersMap_[outType].push_back(nextFilter);
    auto filterLinkCallback = std::make_shared<VideoCacheFilterLinkCallback>(shared_from_this());
    nextFilter->OnLinked(outType, configureParameter_, filterLinkCallback);
    outputSurface_ = nextFilter->GetInputSurface();
    return Status::OK;
}

Status VideoCacheFilter::UpdateNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("UpdateNext");
    return Status::OK;
}

Status VideoCacheFilter::UnLinkNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("UnLinkNext");
    return Status::OK;
}

CFilterType VideoCacheFilter::GetFilterType()
{
    MEDIA_INFO_LOG("GetFilterType");
    return filterType_;
}

Status VideoCacheFilter::OnLinked(CStreamType inType, const std::shared_ptr<Meta> &meta,
    const std::shared_ptr<CFilterLinkCallback> &callback)
{
    MEDIA_INFO_LOG("VideoCacheFilter::OnLinked E");
    return Status::OK;
}

Status VideoCacheFilter::OnUpdated(CStreamType inType, const std::shared_ptr<Meta> &meta,
    const std::shared_ptr<CFilterLinkCallback> &callback)
{
    MEDIA_INFO_LOG("OnUpdated");
    return Status::OK;
}

Status VideoCacheFilter::OnUnLinked(CStreamType inType, const std::shared_ptr<CFilterLinkCallback>& callback)
{
    MEDIA_INFO_LOG("OnUnLinked");
    return Status::OK;
}

void VideoCacheFilter::OnLinkedResult(const sptr<AVBufferQueueProducer> &outputBufferQueue,
    std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("VideoCacheFilter::OnLinkedResult E");
    outputBufferQueueProducer_ = outputBufferQueue;
}

void VideoCacheFilter::OnUpdatedResult(std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("OnUpdatedResult");
}

void VideoCacheFilter::OnUnlinkedResult(std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("OnUnlinkedResult");
}

void VideoCacheFilter::OnBufferAvailable()
{
    MEDIA_DEBUG_LOG("VideoCacheFilter::OnBufferAvailable E");
    CHECK_RETURN_ELOG(inputSurface_ == nullptr, "VideoCacheFilter::OnBufferAvailable inputSurface_ is nullptr");
    CHECK_RETURN_ELOG(outputSurface_ == nullptr, "VideoCacheFilter::OnBufferAvailable outputSurface_ is nullptr.");
    auto transform = inputSurface_->GetTransform();

    int64_t timestamp;
    OHOS::Rect damage;
    sptr<SurfaceBuffer> videoBuffer;
    sptr<SyncFence> fence;

    GSError ret = inputSurface_->AcquireBuffer(videoBuffer, fence, timestamp, damage);
    CHECK_RETURN_ELOG(ret != GSERROR_OK || !videoBuffer, "VideoCacheFilter::OnBufferAvailable AcquireBuffer failed");
    ret = inputSurface_->DetachBufferFromQueue(videoBuffer,true);
    CHECK_RETURN_ELOG(ret != GSERROR_OK, "VideoCacheFilter::OnBufferAvailable DetachBuffer fail. %{public}d", ret);
    MEDIA_DEBUG_LOG("VideoCacheFilter::OnBufferAvailable timestamp %{public}" PRId64, timestamp);
    if (videoBufferWrapperQueue_.Full()) {
        MEDIA_DEBUG_LOG("VideoCacheFilter::OnBufferAvailable videoBufferWrapperQueue_ is FULL");
        sptr<VideoBufferWrapper> popVideoBufferWrapper = videoBufferWrapperQueue_.Pop();
        CHECK_EXECUTE(popVideoBufferWrapper, popVideoBufferWrapper->Release());
        CHECK_EXECUTE(popVideoBufferWrapper, popVideoBufferWrapper->ReleaseMetaBuffer());
    }
    sptr<VideoBufferWrapper> videoBufferWrapper = new (std::nothrow) VideoBufferWrapper(
        videoBuffer, timestamp, transform, inputSurface_, outputSurface_);
    CHECK_RETURN_ELOG(videoBufferWrapper == nullptr, "videoBufferWrapper is nullptr");
    if (clearFlag_ && popFlag_) {
        if (timestamp < shutterTime_) {
            videoBufferWrapper->Release();
        } else {
            clearFlag_ = false;
            popFlag_ = false;
        }
    }
    videoBufferWrapperQueue_.Push(videoBufferWrapper);
    videoBufferWrapper->SetMetaBuffer(FindMetaBuffer(timestamp));
    DrainImage(videoBufferWrapper);
    MEDIA_DEBUG_LOG("VideoCacheFilter::OnBufferAvailable X");
}

void VideoCacheFilter::DrainImage(sptr<VideoBufferWrapper> videoBufferWrapper)
{
    auto engineContext = GetEngineContext();
    CHECK_RETURN_ELOG(engineContext == nullptr, "engineContext is nullptr");
    auto taskmanager = engineContext->GetTaskManager();
    CHECK_RETURN_ELOG(taskmanager == nullptr, "taskmanager is nullptr");
    taskmanager->DrainImage(videoBufferWrapper); 
}

sptr<MetaBufferWrapper> VideoCacheFilter::FindMetaBuffer(int64_t timestamp)
{
    auto engineContext = GetEngineContext();
    CHECK_RETURN_RET_ELOG(engineContext == nullptr, nullptr, "engineContext is nullptr");
    auto metaCacheFilter = engineContext->GetMetaCacheFilter();
    CHECK_RETURN_RET_ELOG(metaCacheFilter == nullptr, nullptr, "metaCacheFilter is nullptr");
    return metaCacheFilter->FindMetaBufferWrapper(timestamp);
}

void VideoCacheFilter::ClearCache(uint64_t timestamp)
{
    CHECK_RETURN_ELOG(!clearFlag_, "not need clear"); // flag 是从切镜像时设置
    shutterTime_ = static_cast<int64_t>(timestamp);
    while (!videoBufferWrapperQueue_.Empty()) {
        sptr<VideoBufferWrapper> popFrame = videoBufferWrapperQueue_.Front();
        if (popFrame->GetTimestamp() > shutterTime_) {
            clearFlag_ = false;
            return;
        }
        videoBufferWrapperQueue_.Pop();
        popFrame->Release();
    }
    popFlag_ = true;
}

void VideoCacheFilter::StartOnceRecord(int32_t rotation, int32_t captureId)
{
    MEDIA_INFO_LOG("VideoCacheFilter::StartOnceRecord E captureId:%{public}d", captureId);
    auto engineContext = GetEngineContext();
    CHECK_RETURN_ELOG(engineContext == nullptr, "engineContext is nullptr");
    auto taskmanager = engineContext->GetTaskManager();
    CHECK_RETURN_ELOG(taskmanager == nullptr, "taskmanager is nullptr");
    std::vector<sptr<VideoBufferWrapper>> cachedBuffers = videoBufferWrapperQueue_.GetAllElements();
    auto task = taskmanager->CreateTask(rotation, captureId, cachedBuffers.size() + postCacheFrameCount_);
    CHECK_RETURN_ELOG(task == nullptr, "task is nullptr");
    CHECK_EXECUTE(!cachedBuffers.empty(), cachedBuffers.back()->SetCoverFrame());
    for (const auto& buffer : cachedBuffers) {
        task->DrainImage(buffer);
    }
    MEDIA_INFO_LOG("VideoCacheFilter::StartOnceRecord X captureId:%{public}d", captureId);
}
} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP