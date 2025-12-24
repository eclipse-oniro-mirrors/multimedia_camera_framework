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

#ifndef OHOS_CAMERA_DEFERRED_PROCESS_H
#define OHOS_CAMERA_DEFERRED_PROCESS_H

#include "demuxer_filter.h"
#include "i_recorder.h"
#include "metadata_filter.h"
#include "muxer_filter.h"
#include "pipeline.h"
#include "sink_filter.h"
#include "surface.h"
#include "video_encoder_filter.h"

namespace OHOS {
namespace CameraStandard {
class DeferredProcess : public std::enable_shared_from_this<DeferredProcess>{
public:
    DeferredProcess() = default;
    ~DeferredProcess() = default;

    Status SetMediaSource(int32_t srcFd, int32_t outFd);
    int32_t Init();
    int32_t Prepare();
    int32_t Start();
    int32_t Pause();
    int32_t Resume();
    int32_t Stop();
    int32_t Release();    

    sptr<Surface> GetVideoSurface();
    sptr<Surface> GetMetaSurface();

    // filter callback
    void OnEvent(const Event &event);
    Status OnCallback(const std::shared_ptr<CFilter>& filter, const CFilterCallBackCommand cmd, CStreamType outType);

    bool IsVideoMime(const std::string& mime);
    bool IsAudioMime(const std::string& mime);
    bool IsMetaMime(const std::string& mime);
    void HandleAudioTrack();

private:
    Status AddDemuxerFilter();
    Status AddVideoFilter();
    Status AddMetaFilter();
    Status LinkMuxerFilter(const std::shared_ptr<CFilter>& filter, CStreamType outType);
    Status LinkSinkFilter(const std::shared_ptr<CFilter>& filter, CStreamType outType);
    void RemoveFilter();
    void OnStateChanged(StateId state);
    Status HandleStopOperation();

    int32_t fd_;
    std::atomic<StateId> curState_;
    std::string processId_ ;
    std::shared_ptr<Pipeline> pipeline_;
    std::shared_ptr<CEventReceiver> processEventReceiver_;
    std::shared_ptr<CFilterCallback> processCallback_;
    std::shared_ptr<VideoEncoderFilter> videoEncoderFilter_;
    std::shared_ptr<MetaDataFilter> metaDataFilter_;
    std::shared_ptr<DemuxerFilter> demuxerFilter_;
    std::shared_ptr<MuxerFilter> muxerFilter_;
    std::shared_ptr<SinkFilter> sinkFilter_;

    std::shared_ptr<Meta> audioFormat_ = std::make_shared<Meta>();
    std::shared_ptr<Meta> videoFormat_ = std::make_shared<Meta>();
    std::shared_ptr<Meta> metaDataFormat_ = std::make_shared<Meta>();
    std::shared_ptr<Meta> muxerFormat_ = std::make_shared<Meta>();
    std::shared_ptr<Meta> userMeta_ = std::make_shared<Meta>();
    
    sptr<Surface> videoSurface_ {nullptr};
    sptr<Surface> metaSurface_ {nullptr};
};

class DeferredProcessCEventReceiver : public CEventReceiver {
public:
    explicit DeferredProcessCEventReceiver(const std::weak_ptr<DeferredProcess>& process);
    void OnEvent(const Event& event);

private:
    std::weak_ptr<DeferredProcess> process_;
};

class DeferredProcessFilterCallback : public CFilterCallback {
public:
    explicit DeferredProcessFilterCallback(const std::weak_ptr<DeferredProcess>& process);
    Status OnCallback(const std::shared_ptr<CFilter>& filter, CFilterCallBackCommand cmd, CStreamType outType);

private:
    std::weak_ptr<DeferredProcess> process_;
};
}
}
#endif // OHOS_CAMERA_DEFERRED_PROCESS_H
