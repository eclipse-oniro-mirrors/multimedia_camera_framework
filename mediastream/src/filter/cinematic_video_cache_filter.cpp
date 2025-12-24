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

#include "cinematic_video_cache_filter.h"

#include "avbuffer_common.h"
#include "avbuffer_queue_define.h"
#include "graphic_common_c.h"
#include "meta_key.h"
#include "surface_type.h"
#include "sync_fence.h"
#include "camera_log.h"
#include "video_encoder_filter.h"

// LCOV_EXCL_START
namespace OHOS {
namespace CameraStandard {
class CinematicVideoCacheFilterLinkCallback : public CFilterLinkCallback {
public:
    explicit CinematicVideoCacheFilterLinkCallback(std::shared_ptr<CinematicVideoCacheFilter> videoCacheFilter)
        : videoCacheFilter_(std::move(videoCacheFilter)) {}
    ~CinematicVideoCacheFilterLinkCallback() = default;

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
    std::weak_ptr<CinematicVideoCacheFilter> videoCacheFilter_;
};

class CinematicCacheConsumerBufferListener : public IBufferConsumerListener {
public:
    explicit CinematicCacheConsumerBufferListener(std::shared_ptr<CinematicVideoCacheFilter> videoCacheFilter)
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
    std::weak_ptr<CinematicVideoCacheFilter> videoCacheFilter_;
};

CinematicVideoCacheFilter::CinematicVideoCacheFilter(std::string name, CFilterType type)
    : CFilter(name, type), name_(name)
{
    MEDIA_INFO_LOG("%{public}s ctor called", name_.c_str());
}

CinematicVideoCacheFilter::~CinematicVideoCacheFilter()
{
    MEDIA_INFO_LOG("%{public}s dtor called", name_.c_str());
    CHECK_EXECUTE(inputSurface_, inputSurface_->UnregisterConsumerListener());
}


void CinematicVideoCacheFilter::Init(const std::shared_ptr<CEventReceiver> &receiver,
    const std::shared_ptr<CFilterCallback> &callback)
{
    MEDIA_INFO_LOG("CinematicVideoCacheFilter::Init called");
    eventReceiver_ = receiver;
    filterCallback_ = callback;
}

Status CinematicVideoCacheFilter::Configure(const std::shared_ptr<Meta> &parameter)
{
    MEDIA_INFO_LOG("CinematicVideoCacheFilter::Configure called");
    configureParameter_ = parameter;
    return Status::OK;
}

sptr<Surface> CinematicVideoCacheFilter::GetInputSurface()
{
    MEDIA_INFO_LOG("CinematicVideoCacheFilter::GetInputSurface called");
    CHECK_RETURN_RET_ILOG(inputSurface_, inputSurface_, "return existing input surface");
    inputSurface_ = Surface::CreateSurfaceAsConsumer(name_+"_Surface");
    CHECK_RETURN_RET_ELOG(inputSurface_ == nullptr, nullptr, "Create the surface consumer fail");
    GSError err = inputSurface_->SetDefaultUsage(BUFFER_USAGE_VIDEO_ENCODER | BUFFER_USAGE_MEM_DMA);
    CHECK_PRINT_ELOG(err != GSERROR_OK, "set consumer usage fail");
    sptr<IBufferConsumerListener> listener = new CinematicCacheConsumerBufferListener(shared_from_this());
    inputSurface_->RegisterConsumerListener(listener);
    int32_t width = 0;
    int32_t height = 0;
    bool existSize = configureParameter_ &&
                     configureParameter_->GetData(Tag::VIDEO_WIDTH, width) &&
                     configureParameter_->GetData(Tag::VIDEO_HEIGHT, height);
    CHECK_EXECUTE(inputSurface_ && existSize, inputSurface_->SetDefaultWidthAndHeight(width, height));
    return inputSurface_;
}


Status CinematicVideoCacheFilter::DoPrepare()
{
    MEDIA_INFO_LOG("CinematicVideoCacheFilter::DoPrepare called");
    CHECK_RETURN_RET_ELOG(!filterCallback_, Status::ERROR_NULL_POINTER, "filterCallback_ is nullptr");
    filterCallback_->OnCallback(
        shared_from_this(), CFilterCallBackCommand::NEXT_FILTER_NEEDED, CStreamType::CACHED_VIDEO);
    return Status::OK;
}

Status CinematicVideoCacheFilter::DoStart()
{
    MEDIA_INFO_LOG("CinematicVideoCacheFilter::DoStart called");
    firstFrameTimestamp_ = -1;
    return Status::OK;
}

Status CinematicVideoCacheFilter::DoPause()
{
    MEDIA_INFO_LOG("CinematicVideoCacheFilter::DoPause called");
    return Status::OK;
}

Status CinematicVideoCacheFilter::DoResume()
{
    MEDIA_INFO_LOG("CinematicVideoCacheFilter::DoResume called");
    return Status::OK;
}

Status CinematicVideoCacheFilter::DoStop()
{
    MEDIA_INFO_LOG("CinematicVideoCacheFilter::DoStop called");
    return Status::OK;
}

Status CinematicVideoCacheFilter::DoFlush()
{
    MEDIA_INFO_LOG("CinematicVideoCacheFilter::DoFlush called");
    return Status::OK;
}

Status CinematicVideoCacheFilter::DoRelease()
{
    MEDIA_INFO_LOG("CinematicVideoCacheFilter::DoRelease called");
    return Status::OK;
}

Status CinematicVideoCacheFilter::LinkNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("CinematicVideoCacheFilter::LinkNext filterType:%{public}d", (int32_t)nextFilter->GetCFilterType());
    nextFilter_ = nextFilter;
    nextCFiltersMap_[outType].push_back(nextFilter_);
    auto filterLinkCallback = std::make_shared<CinematicVideoCacheFilterLinkCallback>(shared_from_this());
    nextFilter->OnLinked(outType, configureParameter_, filterLinkCallback);
    outputSurface_ = nextFilter->GetInputSurface();
    return Status::OK;
}

Status CinematicVideoCacheFilter::UpdateNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("CinematicVideoCacheFilter::UpdateNext called");
    return Status::OK;
}

Status CinematicVideoCacheFilter::UnLinkNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("CinematicVideoCacheFilter::UnLinkNext called");
    return Status::OK;
}

CFilterType CinematicVideoCacheFilter::GetFilterType()
{
    MEDIA_INFO_LOG("CinematicVideoCacheFilter::GetFilterType called");
    return filterType_;
}

Status CinematicVideoCacheFilter::OnLinked(CStreamType inType, const std::shared_ptr<Meta> &meta,
    const std::shared_ptr<CFilterLinkCallback> &callback)
{
    MEDIA_INFO_LOG("CinematicVideoCacheFilter::OnLinked called");
    return Status::OK;
}

Status CinematicVideoCacheFilter::OnUpdated(CStreamType inType, const std::shared_ptr<Meta> &meta,
    const std::shared_ptr<CFilterLinkCallback> &callback)
{
    MEDIA_INFO_LOG("CinematicVideoCacheFilter::OnUpdated called");
    return Status::OK;
}

Status CinematicVideoCacheFilter::OnUnLinked(CStreamType inType, const std::shared_ptr<CFilterLinkCallback>& callback)
{
    MEDIA_INFO_LOG("CinematicVideoCacheFilter::OnUnLinked called");
    return Status::OK;
}

void CinematicVideoCacheFilter::OnLinkedResult(const sptr<AVBufferQueueProducer> &outputBufferQueue,
    std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("CinematicVideoCacheFilter::OnLinkedResult called");
}

void CinematicVideoCacheFilter::OnUpdatedResult(std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("CinematicVideoCacheFilter::OnUpdatedResult called");
}

void CinematicVideoCacheFilter::OnUnlinkedResult(std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("CinematicVideoCacheFilter::OnUnlinkedResult called");
}

void CinematicVideoCacheFilter::ProcessCachedFrames()
{
    CHECK_RETURN(cachedBufferProcessInfoList_.empty());
    MEDIA_INFO_LOG("[CFDB] name:%{public}s, start push cached buffer to encoder, size:%{public}zu"
                    ", frist frame ts: %{public}" PRId64,
                    name_.c_str(), cachedBufferProcessInfoList_.size(), firstFrameTimestamp_);
    while (!cachedBufferProcessInfoList_.empty()) {
        auto bufferInfo = std::move(cachedBufferProcessInfoList_.front());
        cachedBufferProcessInfoList_.pop_front();
        int64_t ts = bufferInfo.timestamp;
        GSError ret = GSERROR_OK;
        if (ts >= firstFrameTimestamp_) {
            // push cached aux frames whose ts is greater than or equal to first yuv ts to encoder
            MEDIA_INFO_LOG("[CFDB] name:%{public}s, push cached buffer to encoder, buffer ts: %{public}" PRId64
                            ", frist frame ts: %{public}" PRId64,
                            name_.c_str(), ts, firstFrameTimestamp_);
            ret = RequestAndDetachOutputBuffer(bufferInfo);
            CHECK_CONTINUE_ELOG(ret != GSERROR_OK, "RequestAndDetachOutputBuffer failed, ret:%{public}d", ret);
            ret = ReturnBuffers(bufferInfo);
            CHECK_CONTINUE_ELOG(ret != GSERROR_OK, "ReturnBuffers failed, ret:%{public}d", ret);
        } else {
            // return cached aux frames whose ts is less than first yuv ts to our buffer queue
            MEDIA_INFO_LOG("[CFDB] name:%{public}s, return cached buffer to hal, buffer ts: %{public}" PRId64
                            ", frist frame ts: %{public}" PRId64,
                            name_.c_str(), ts, firstFrameTimestamp_);
            ret = AttachAndReleaseInputBuffer(bufferInfo);
            CHECK_CONTINUE_ELOG(ret != GSERROR_OK, "AttachAndReleaseInputBuffer failed, ret:%{public}d", ret);
        }
    }
}

BufferRequestConfig CinematicVideoCacheFilter::GetBufferRequestConfig(const sptr<SurfaceBuffer>& buffer)
{
    CHECK_RETURN_RET_ELOG(!buffer, {}, "invalid input, buffer is nullptr");
    return {
        .width = buffer->GetWidth(),
        .height = buffer->GetHeight(),
        .strideAlignment = buffer->GetStride(),
        .format = buffer->GetFormat(),
        .usage = buffer->GetUsage(),
        .timeout = 0,
        .colorGamut = buffer->GetSurfaceBufferColorGamut(),
        .transform = buffer->GetSurfaceBufferTransform(),
    };
}

void CinematicVideoCacheFilter::UpdateOutputSurfaceInfo()
{
    UpdateOutputTransform();
    UpdateOutputBufferQueueSize();
    UpdateOutputCycleBuffersNumber();
}

void CinematicVideoCacheFilter::UpdateOutputTransform()
{
    CHECK_RETURN_ELOG(!inputSurface_, "inputSurface_ is null, return");
    auto transform = inputSurface_->GetTransform();
    CHECK_RETURN(transform == outputSurfaceTransform_);
    outputSurfaceTransform_ = transform;
    MEDIA_INFO_LOG("[CFDB] set output surface transform: %{public}d", transform);
    CHECK_RETURN_ELOG(!outputSurface_, "outputSurface_ is null, return");
    outputSurface_->SetTransform(transform);
}

void CinematicVideoCacheFilter::UpdateOutputBufferQueueSize()
{
    CHECK_RETURN(isOutputBufferQueueSizeSet_);
    CHECK_RETURN_ELOG(!inputSurface_ || !outputSurface_, "inputSurface_ or outputSurface_ is null, return");
    GSError ret = outputSurface_->SetQueueSize(inputSurface_->GetQueueSize());
    CHECK_RETURN_ELOG(ret != GSERROR_OK, "SetQueueSize failed, ret: %{public}d", ret);
    MEDIA_INFO_LOG("[CFDB] set output surface queue size: %{public}d", outputSurface_->GetQueueSize());
    isOutputBufferQueueSizeSet_ = true;
}

void CinematicVideoCacheFilter::UpdateOutputCycleBuffersNumber()
{
    CHECK_RETURN(isOutputCycleBuffersNumberSet_);
    CHECK_RETURN_ELOG(!inputSurface_ || !outputSurface_, "inputSurface_ or outputSurface_ is null, return");
    uint32_t cycleBuffersNumber = inputSurface_->GetQueueSize() + outputSurface_->GetQueueSize();
    GSError ret = outputSurface_->SetCycleBuffersNumber(cycleBuffersNumber);
    CHECK_RETURN_ELOG(ret != GSERROR_OK, "SetCycleBuffersNumber failed, ret: %{public}d", ret);
    MEDIA_INFO_LOG("[CFDB] set output surface cycle buffers num: %{public}d", cycleBuffersNumber);
    isOutputCycleBuffersNumberSet_ = true;
    return;
}

GSError CinematicVideoCacheFilter::AcquireInputBuffer(BufferProcessInfo& bufferProcessInfo)
{
    sptr<SurfaceBuffer>& inputBuffer = bufferProcessInfo.inputBuffer;
    sptr<SyncFence>& inputSyncFence = bufferProcessInfo.inputSyncFence;
    int64_t& timestamp = bufferProcessInfo.timestamp;
    GSError ret = GSERROR_OK;

    // acquire input buffer from input surface
    CHECK_RETURN_RET_ELOG(!inputSurface_, GSERROR_NOT_INIT, "input surface is nullptr");
    OHOS::Rect damages = {};
    ret = inputSurface_->AcquireBuffer(inputBuffer, inputSyncFence, timestamp, damages);
    CHECK_RETURN_RET_ELOG(ret != GSERROR_OK || !inputBuffer, ret, "Failed to AcquireBuffer, ret:%{public}d", ret);
    // get input buffer ts
    auto extraData = inputBuffer->GetExtraData();
    CHECK_EXECUTE(extraData, extraData->ExtraGet("timeStamp", timestamp));
    return ret;
}

GSError CinematicVideoCacheFilter::ReleaseInputBuffer(BufferProcessInfo& bufferProcessInfo)
{
    sptr<SurfaceBuffer>& inputBuffer = bufferProcessInfo.inputBuffer;
    sptr<SyncFence>& inputSyncFence = bufferProcessInfo.inputSyncFence;
    GSError ret = GSERROR_OK;
    CHECK_RETURN_RET_ELOG(!inputSurface_ || !inputBuffer, GSERROR_NOT_INIT,
                          "invalid input, surface or buffer is null, return");
    ret = inputSurface_->ReleaseBuffer(inputBuffer, inputSyncFence);
    CHECK_RETURN_RET_ELOG(ret != GSERROR_OK, ret, "Failed to ReleaseBuffer, ret: %{public}d", ret);
    return ret;
}

GSError CinematicVideoCacheFilter::ReleaseOutputBuffer(BufferProcessInfo& bufferProcessInfo)
{
    sptr<SurfaceBuffer>& outputBuffer = bufferProcessInfo.outputBuffer;
    sptr<SyncFence>& outputSyncFence = bufferProcessInfo.outputSyncFence;
    GSError ret = GSERROR_OK;
    CHECK_RETURN_RET_ELOG(!inputSurface_, GSERROR_NOT_INIT,
                          "invalid input, surface or buffer is null, return");
    ret = inputSurface_->ReleaseBuffer(outputBuffer, outputSyncFence);
    CHECK_RETURN_RET_ELOG(ret != GSERROR_OK, ret, "Failed to ReleaseBuffer, ret: %{public}d", ret);
    return ret;
}

GSError CinematicVideoCacheFilter::AttachInputBuffer(BufferProcessInfo& bufferProcessInfo)
{
    sptr<SurfaceBuffer>& inputBuffer = bufferProcessInfo.inputBuffer;
    GSError ret = GSERROR_OK;
    // detach input buffer from input surface
    CHECK_RETURN_RET_ELOG(!inputSurface_ || !inputBuffer, GSERROR_NOT_INIT, "inputSurface_ or inputBuffer is null");
    ret = inputSurface_->AttachBufferToQueue(inputBuffer);
    CHECK_RETURN_RET_ELOG(ret != GSERROR_OK, ret, "attach input buffer to input surface failed, ret: %{public}d", ret);
    return ret;
}

GSError CinematicVideoCacheFilter::DetachInputBuffer(BufferProcessInfo& bufferProcessInfo)
{
    sptr<SurfaceBuffer>& inputBuffer = bufferProcessInfo.inputBuffer;
    GSError ret = GSERROR_OK;
    // detach input buffer from input surface
    CHECK_RETURN_RET_ELOG(!inputSurface_ || !inputBuffer, GSERROR_NOT_INIT, "inputSurface_ or inputBuffer is null");
    ret = inputSurface_->DetachBufferFromQueue(inputBuffer, true);
    // if detach failed, release input buffer to input surface
    if (ret != GSERROR_OK) {
        MEDIA_ERR_LOG("inputSurface_ DetachBufferFromQueue failed, ret:%{public}d", ret);
        ReleaseInputBuffer(bufferProcessInfo);
        return ret;
    }
    return ret;
}

GSError CinematicVideoCacheFilter::AttachAndReleaseInputBuffer(BufferProcessInfo& bufferProcessInfo)
{
    GSError ret = GSERROR_OK;
    ret = AttachInputBuffer(bufferProcessInfo);
    CHECK_RETURN_RET_ELOG(ret != GSERROR_OK, ret, "Failed to AttachBuffer, ret:%{public}d", ret);
    ret = ReleaseInputBuffer(bufferProcessInfo);
    CHECK_RETURN_RET_ELOG(ret != GSERROR_OK, ret, "Failed to ReleaseBuffer, ret: %{public}d", ret);
    return ret;
}

GSError CinematicVideoCacheFilter::AttachAndFlushInputBuffer(BufferProcessInfo& bufferProcessInfo)
{
    sptr<SurfaceBuffer>& inputBuffer = bufferProcessInfo.inputBuffer;
    sptr<SyncFence>& inputSyncFence = bufferProcessInfo.inputSyncFence;
    int64_t& timestamp = bufferProcessInfo.timestamp;
    GSError ret = GSERROR_OK;
    if (!outputSurface_) {
        MEDIA_ERR_LOG("outputSurface_ is null, release output buffer");
        ReleaseOutputBuffer(bufferProcessInfo);
        return ret;
    }
    // request and detach output buffer from output surface
    BufferFlushConfig flushConfig = {
        .damage = {
            .w = inputBuffer->GetWidth(),
            .h = inputBuffer->GetHeight(),
        },
        .timestamp = timestamp,
    };
    ret = outputSurface_->AttachAndFlushBuffer(inputBuffer, inputSyncFence, flushConfig, false);
    // if request and detach buffer from output surface failed, release output buffer to input surface
    if (ret != GSERROR_OK) {
        MEDIA_ERR_LOG("outputSurface_ RequestAndDetachBuffer failed, ret:%{public}d", ret);
        ReleaseOutputBuffer(bufferProcessInfo);
        return ret;
    }
    return ret;
}

GSError CinematicVideoCacheFilter::RequestAndDetachOutputBuffer(BufferProcessInfo& bufferProcessInfo)
{
    sptr<SurfaceBuffer>& inputBuffer = bufferProcessInfo.inputBuffer;
    sptr<SurfaceBuffer>& outputBuffer = bufferProcessInfo.outputBuffer;
    sptr<SyncFence>& outputSyncFence = bufferProcessInfo.outputSyncFence;
    GSError ret = GSERROR_OK;
    // if output surface is null, attach and release input buffer to input surface
    if (!outputSurface_) {
        MEDIA_ERR_LOG("outputSurface_ is null, attach and release input buffer");
        AttachAndReleaseInputBuffer(bufferProcessInfo);
        return ret;
    }
    // request and detach output buffer from output surface
    BufferRequestConfig requestConfig = GetBufferRequestConfig(inputBuffer);
    ret = outputSurface_->RequestAndDetachBuffer(outputBuffer, outputSyncFence, requestConfig);
    // if request and detach buffer from output surface failed, attach and release input buffer to input surface
    if (ret != GSERROR_OK || !outputBuffer) {
        MEDIA_ERR_LOG("outputSurface_ RequestAndDetachBuffer failed, ret:%{public}d", ret);
        AttachAndReleaseInputBuffer(bufferProcessInfo);
        return ret;
    }
    return ret;
}

GSError CinematicVideoCacheFilter::AttachAndFlushOutputBuffer(BufferProcessInfo& bufferProcessInfo)
{
    // attach and flush output buffer to output surface
    sptr<SurfaceBuffer>& outputBuffer = bufferProcessInfo.outputBuffer;
    sptr<SyncFence>& outputSyncFence = bufferProcessInfo.outputSyncFence;
    int64_t& timestamp = bufferProcessInfo.timestamp;
    GSError ret = GSERROR_OK;
    CHECK_RETURN_RET_ELOG(!outputSurface_ || !outputBuffer, GSERROR_NOT_INIT, "outputSurface_ or outputBuffer is null");
    BufferFlushConfig flushConfig = {
        .damage = {
            .w = outputBuffer->GetWidth(),
            .h = outputBuffer->GetHeight(),
        },
        .timestamp = timestamp,
    };
    ret = outputSurface_->AttachAndFlushBuffer(outputBuffer, outputSyncFence, flushConfig, false);
    CHECK_RETURN_RET_ELOG(ret != GSERROR_OK, ret,
                          "attach and flush output buffer to output surface failed, ret: %{public}d", ret);
    return ret;
}

GSError CinematicVideoCacheFilter::ReturnBuffers(BufferProcessInfo& bufferProcessInfo)
{
    sptr<SurfaceBuffer>& outputBuffer = bufferProcessInfo.outputBuffer;
    sptr<SyncFence>& outputSyncFence = bufferProcessInfo.outputSyncFence;
    GSError ret = GSERROR_OK;
    CHECK_RETURN_RET_ELOG(!inputSurface_, GSERROR_NOT_INIT, "input surface is null");
    // attach output buffer to input surface
    ret = inputSurface_->AttachBufferToQueue(outputBuffer);
    if (ret != GSERROR_OK) {
        // if failed, attach and release input buffer to input surface, attach output buffer to output surface
        MEDIA_ERR_LOG("inputSurface_ AttachBufferToQueue failed, ret:%{public}d", ret);
        AttachAndReleaseInputBuffer(bufferProcessInfo);
        AttachAndFlushOutputBuffer(bufferProcessInfo);
        return ret;
    }

    // attach and flush input buffer to output surface
    ret = AttachAndFlushInputBuffer(bufferProcessInfo);
    CHECK_RETURN_RET_ELOG(ret != GSERROR_OK, ret, "AttachAndFlushInputBuffer failed, ret:%{public}d", ret);

    // release output buffer to input surface
    ret = inputSurface_->ReleaseBuffer(outputBuffer, outputSyncFence);
    CHECK_RETURN_RET_ELOG(ret != GSERROR_OK, ret, "inputSurface_ Release outputBuffer failed, ret:%{public}d", ret);
    return ret;
}

/**
    -------------------------------------------------------------------------------------------------------------------
    Cinematic Aux Track OnBufferAvailable Logic
    -------------------------------------------------------------------------------------------------------------------
    1. acquire input buffer from input surface
    2. a. if YUV first frame is not arrived
          - detach input buffer from input surface
          - cache input buffer
       b. if YUV first frame is arrvied
          - for cached buffers
            - timestamp is less than YUV first frame timestamp
              - attach input buffer to input surface
              - release input buffer to input surface
            - timestamp is greater than or equal to YUV first frame timestamp
              - request and detach output buffer from output surface
              - attach output buffer to input surface
              - attach and flush cached input buffer to output surface
              - release output buffer to input surface
          i.  input buffer timestamp is less than YUV first frame timestamp
            - release input buffer to input surface
          ii. input buffer timestamp is greater than or equal to YUV first frame timestamp
            - detach input buffer from input surface
            - request and detach output buffer from output surface
            - attach output buffer to input surface
            - attach and flush input buffer to output surface
            - release output buffer to input surface
    -------------------------------------------------------------------------------------------------------------------
*/
void CinematicVideoCacheFilter::OnBufferAvailable()
{
    // acquire input buffer from input surface
    CHECK_RETURN_ELOG(inputSurface_ == nullptr, "inputSurface_ is nullptr");
    // update output surface transform, buffer queue size and cycle buffer nums once
    UpdateOutputSurfaceInfo();

    BufferProcessInfo bufferProcessInfo;
    GSError ret = GSERROR_OK;
    ret = AcquireInputBuffer(bufferProcessInfo);
    CHECK_RETURN_ELOG(ret != GSERROR_OK, "AcquireInputBuffer failed, ret:%{public}d", ret);

    // get first yuv frame timestamp from muxer if its not set
    if (firstFrameTimestamp_ == -1) {
        std::shared_ptr<VideoEncoderFilter> videoEncoderFilter =
            std::static_pointer_cast<VideoEncoderFilter>(nextFilter_);
        videoEncoderFilter->GetMuxerFirstFrameTimestamp(firstFrameTimestamp_);
    }

    // if first yuv buffer is not arrived, detach and cache aux buffer, then return
    int64_t& timestamp = bufferProcessInfo.timestamp;
    if (firstFrameTimestamp_ == -1) {
        MEDIA_INFO_LOG("[CFDB] name:%{public}s, cache buffer, current frame ts:%{public}" PRId64
                       ", first frame ts:%{public}" PRId64,
                       name_.c_str(), timestamp, firstFrameTimestamp_);
        ret = DetachInputBuffer(bufferProcessInfo);
        CHECK_RETURN_ELOG(ret != GSERROR_OK, "DetachInputBuffer failed, ret:%{public}d", ret);
        cachedBufferProcessInfoList_.push_back(std::move(bufferProcessInfo));
        return;
    }

    // if first yuv buffer is arrived
    ProcessCachedFrames();

    if (timestamp < firstFrameTimestamp_) {
        // push current frame to our buffer queue if its ts is less than first yuv ts
        MEDIA_INFO_LOG("[CFDB] name:%{public}s, return current buffer to hal, buffer ts: %{public}" PRId64
                       ", frist frame ts: %{public}" PRId64,
                       name_.c_str(), timestamp, firstFrameTimestamp_);
        ret = ReleaseInputBuffer(bufferProcessInfo);
        CHECK_RETURN_ELOG(ret != GSERROR_OK, "ReleaseInputBuffer failed, ret:%{public}d", ret);
    } else {
        // push current frame to encoder if its ts is greater than or equal to first yuv ts
        MEDIA_INFO_LOG("[CFDB] name:%{public}s, push current buffer to encoder, buffer ts: %{public}" PRId64
                       ", frist frame ts: %{public}" PRId64,
                       name_.c_str(), timestamp, firstFrameTimestamp_);
        ret = DetachInputBuffer(bufferProcessInfo);
        CHECK_RETURN_ELOG(ret != GSERROR_OK, "DetachInputBuffer failed, ret:%{public}d", ret);
        ret = RequestAndDetachOutputBuffer(bufferProcessInfo);
        CHECK_RETURN_ELOG(ret != GSERROR_OK, "RequestAndDetachOutputBuffer failed, ret:%{public}d", ret);
        ret = ReturnBuffers(bufferProcessInfo);
        CHECK_RETURN_ELOG(ret != GSERROR_OK, "ReturnBuffers failed, ret:%{public}d", ret);
    }
}

/**
    swap steps: 1~3 obtain buffers, 4~6 return buffers
    -------------------------------------------------------------------------------------------------------------------
    1. acquire input buffer from input surface
    2. request and detach output buffer from output surface
    3. detach input buffer from input surface
    4. attach output buffer to input surface
    5. attach and flush input buffer to output surface
    6. release output buffer to input surface
    -------------------------------------------------------------------------------------------------------------------
 */
} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP