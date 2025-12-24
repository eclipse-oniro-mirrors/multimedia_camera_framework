/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_VIDEO_ENCODER_FILTER_H
#define OHOS_CAMERA_VIDEO_ENCODER_FILTER_H

#include "cfilter.h"
#include "avcodec_common.h"
#include "video_encoder_adapter.h"
#include "video_buffer_wrapper.h"

namespace OHOS {
namespace CameraStandard {

using EncodeCallback = std::function<void(sptr<VideoBufferWrapper>, bool)>;

class VideoEncoderAdapter;
class VideoEncoderFilter : public CFilter, public std::enable_shared_from_this<VideoEncoderFilter> {
public:
    explicit VideoEncoderFilter(std::string name, CFilterType type);
    ~VideoEncoderFilter() override;

    Status SetCodecFormat(const std::shared_ptr<Meta>& format);
    void Init(const std::shared_ptr<CEventReceiver>& receiver,
        const std::shared_ptr<CFilterCallback>& callback) override;
    Status Configure(const std::shared_ptr<Meta>& parameter);
    Status SetWatermark(std::shared_ptr<AVBuffer>& waterMarkBuffer);
    Status SetStopTime();
    Status SetTransCoderMode();
    sptr<Surface> GetInputSurface() override;
    Status DoPrepare() override;
    Status DoStart() override;
    Status DoPause() override;
    Status DoResume() override;
    Status Reset();
    Status DoStop() override;
    Status DoFlush() override;
    Status DoRelease() override;
    Status NotifyEos(int64_t pts);
    void SetParameter(const std::shared_ptr<Meta>& parameter) override;
    void GetParameter(std::shared_ptr<Meta>& parameter) override;
    Status LinkNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType) override;
    Status UpdateNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType) override;
    Status UnLinkNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType) override;
    CFilterType GetFilterType();
    void OnLinkedResult(const sptr<AVBufferQueueProducer>& outputBufferQueue, std::shared_ptr<Meta>& meta);
    void OnUpdatedResult(std::shared_ptr<Meta>& meta);
    void OnUnlinkedResult(std::shared_ptr<Meta>& meta);
    void SetCallingInfo(int32_t appUid, int32_t appPid, const std::string& bundleName, uint64_t instanceId);
    void OnError(MediaAVCodec::AVCodecErrorType errorType, int32_t errorCode);
    void OnReportKeyFramePts(std::string KeyFramePts);
    void OnReportFirstFramePts(int64_t firstFramePts);
    void EncodeVideoBuffer(sptr<VideoBufferWrapper> videoBufferWrapper, EncodeCallback encodeCallback);
    void EnableVirtualAperture(bool isVirtualApertureEnabled);
    void SetStreamStarted(bool isStreamStarted);
    int64_t GetStopTimestamp();
    void GetMuxerFirstFrameTimestamp(int64_t& timestamp);
    void SetMuxerFirstFrameTimestamp(int64_t timestamp);
protected:
    Status OnLinked(CStreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<CFilterLinkCallback>& callback) override;
    Status OnUpdated(CStreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<CFilterLinkCallback>& callback) override;
    Status OnUnLinked(CStreamType inType, const std::shared_ptr<CFilterLinkCallback>& callback) override;

private:
    std::string name_;
    CFilterType filterType_ {CFilterType::VIDEO_ENC};
    std::shared_ptr<CEventReceiver> eventReceiver_ {nullptr};
    std::shared_ptr<CFilterCallback> filterCallback_ {nullptr};
    std::shared_ptr<CFilterLinkCallback> onLinkedResultCallback_ {nullptr};
    std::shared_ptr<VideoEncoderAdapter> mediaCodec_ {nullptr};
    std::string codecMimeType_;
    std::shared_ptr<Meta> configureParameter_ {nullptr};
    std::shared_ptr<CFilter> nextFilter_ {nullptr};
    std::atomic_bool isUpdateCodecNeeded_ {false};
    sptr<Surface> surface_ {nullptr};
    std::string bundleName_;
    bool isTranscoderMode_ {false};
    uint64_t instanceId_ {0};
    int32_t appUid_ {0};
    int32_t appPid_ {0};
};

class VideoEncoderFilterImplEncoderAdapterCallback : public EncoderAdapterCallback {
public:
    explicit VideoEncoderFilterImplEncoderAdapterCallback(std::shared_ptr<VideoEncoderFilter> videoEncoderFilter)
        : videoEncoderFilter_(std::move(videoEncoderFilter))
    {
    }

    void OnError(MediaAVCodec::AVCodecErrorType type, int32_t errorCode)
    {
        if (auto videoEncoderFilter = videoEncoderFilter_.lock()) {
            videoEncoderFilter->OnError(type, errorCode);
        }
    }

    void OnOutputFormatChanged(const std::shared_ptr<Meta> &format)
    {
    }

private:
    std::weak_ptr<VideoEncoderFilter> videoEncoderFilter_;
};

class VideoEncoderFilterImplEncoderAdapterKeyFramePtsCallback : public EncoderAdapterKeyFramePtsCallback {
public:
    explicit VideoEncoderFilterImplEncoderAdapterKeyFramePtsCallback
    (std::shared_ptr<VideoEncoderFilter> videoEncoderFilter) : videoEncoderFilter_(std::move(videoEncoderFilter))
    {
    }
    
    void OnReportKeyFramePts(std::string KeyFramePts) override
    {
        if (auto videoEncoderFilter = videoEncoderFilter_.lock()) {
            MEDIA_DEBUG_LOG("filter name: %{public}s", videoEncoderFilter->GetName().c_str());
            if (videoEncoderFilter->GetName() != "PreyEncoderFilter"
                && videoEncoderFilter->GetName() != "DepthEncoderFilter") {
                videoEncoderFilter->OnReportKeyFramePts(KeyFramePts);
            }
        }
    }

    void OnFirstFrameArrival(std::string name, int64_t& startPts) override
    {
        if (auto videoEncoderFilter = videoEncoderFilter_.lock()) {
            if (name == "RawEncoderFilter_EncoderAdapter" || name == "MovieEncoderFilter_EncoderAdapter") {
                // main track
                videoEncoderFilter->SetMuxerFirstFrameTimestamp(startPts);
            } else if (name == "PreyEncoderFilter_EncoderAdapter" || name == "DepthEncoderFilter_EncoderAdapter") {
                // aux track
                videoEncoderFilter->GetMuxerFirstFrameTimestamp(startPts);
            }
        }
    }

    void OnReportFirstFramePts(int64_t firstFramePts) override
    {
        if (auto videoEncoderFilter = videoEncoderFilter_.lock()) {
            MEDIA_DEBUG_LOG("filter name: %{public}s", videoEncoderFilter->GetName().c_str());
            if (videoEncoderFilter->GetName() == "MovieEncoderFilter") {
                videoEncoderFilter->OnReportFirstFramePts(firstFramePts);
            }
        }
    }

private:
    std::weak_ptr<VideoEncoderFilter> videoEncoderFilter_;
};

class VideoEncoderFilterLinkCallback : public CFilterLinkCallback {
public:
    explicit VideoEncoderFilterLinkCallback(std::shared_ptr<VideoEncoderFilter> videoEncoderFilter)
        : videoEncoderFilter_(std::move(videoEncoderFilter))
    {
    }
    void OnLinkedResult(const sptr<AVBufferQueueProducer> &queue, std::shared_ptr<Meta> &meta) override
    {
        if (auto videoEncoderFilter = videoEncoderFilter_.lock()) {
            videoEncoderFilter->OnLinkedResult(queue, meta);
        }
    }
    void OnUnlinkedResult(std::shared_ptr<Meta> &meta) override
    {
        if (auto videoEncoderFilter = videoEncoderFilter_.lock()) {
            videoEncoderFilter->OnUnlinkedResult(meta);
        }
    }
    void OnUpdatedResult(std::shared_ptr<Meta> &meta) override
    {
        if (auto videoEncoderFilter = videoEncoderFilter_.lock()) {
            videoEncoderFilter->OnUpdatedResult(meta);
        }
    }
private:
    std::weak_ptr<VideoEncoderFilter> videoEncoderFilter_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_VIDEO_ENCODER_FILTER_H
