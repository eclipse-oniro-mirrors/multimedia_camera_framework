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
 
#ifndef MOVING_PHOTO_MUXER_FILTER_H
#define MOVING_PHOTO_MUXER_FILTER_H
 
#include <cstring>
#include <map>
#include <string>
 
#include "cfilter.h"
#include "common/status.h"
#include "meta/media_types.h"
#include "osal/task/task.h"
#include "photo_asset_proxy.h"
#include "moving_photo_recorder_task.h"
#include "video_buffer_wrapper.h"
#include "refbase.h"
#include "moving_photo_avmuxer.h"
#include "engine_context_ext.h"
 
namespace OHOS {
namespace Media {
class MediaMuxer;
}
 
namespace CameraStandard {

const std::string MOVING_PHOTO_ENCODER_PARAM_VALUE = "video_encode_bitrate_mode=SQR:bitrate=";
class MovingPhotoMuxerFilter : public CFilter, public std::enable_shared_from_this<MovingPhotoMuxerFilter>,
    public EngineContextExt {
public:
    explicit MovingPhotoMuxerFilter(std::string name, CFilterType type);
    ~MovingPhotoMuxerFilter() override;
    Status SetOutputParameter(int32_t appUid, int32_t appPid, int32_t fd, int32_t format);
    void Init(
        const std::shared_ptr<CEventReceiver> &receiver, const std::shared_ptr<CFilterCallback> &callback) override;
    Status DoPrepare() override;
    Status DoStart() override;
    Status DoPause() override;
    Status DoResume() override;
    Status DoStop() override;
    Status DoFlush() override;
    Status DoRelease() override;
    void SetParameter(const std::shared_ptr<Meta> &parameter) override;
    void GetParameter(std::shared_ptr<Meta> &parameter) override;
    Status LinkNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType) override;
    Status UpdateNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType) override;
    Status UnLinkNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType) override;
    CFilterType GetFilterType();
    Status OnLinked(CStreamType inType, const std::shared_ptr<Meta> &meta,
        const std::shared_ptr<CFilterLinkCallback> &callback) override;
    Status OnUpdated(CStreamType inType, const std::shared_ptr<Meta> &meta,
        const std::shared_ptr<CFilterLinkCallback> &callback) override;
    Status OnUnLinked(CStreamType inType, const std::shared_ptr<CFilterLinkCallback>& callback) override;

    const std::string& GetContainerFormat(Plugins::OutputFormat format);
    void SetCallingInfo(int32_t appUid, int32_t appPid, const std::string &bundleName, uint64_t instanceId);
    void CreateMuxerTask(sptr<MovingPhotoRecorderTask> task);
private:
    struct MetaInfo {
        std::shared_ptr<Meta> audioMeta{nullptr};
        std::shared_ptr<Meta> videoMeta{nullptr};
        std::shared_ptr<Meta> metaMeta{nullptr};
        std::shared_ptr<Meta> muxerMeta{nullptr};
    } metaInfo_;

    std::string name_;
 
    std::shared_ptr<CEventReceiver> eventReceiver_;
    std::shared_ptr<CFilterCallback> filterCallback_;
 
    std::shared_ptr<MediaMuxer> mediaMuxer_;
 
    void DoMuxerVideo(sptr<MovingPhotoRecorderTask> task);
    bool EncodeAudioBuffer(std::vector<sptr<AudioBufferWrapper>>& audioBuffers);


    class MuxerTask : public RefBase {
    public:
        MuxerTask(sptr<MovingPhotoRecorderTask> task) : recorderTask_(task) {}
        bool CreateAVMuxer(int64_t startTimeStamp, int64_t endTimeStamp, MetaInfo& metaInfo);
        void WriteAVBuffer(std::vector<sptr<VideoBufferWrapper>>& videoBuffers);
        void WriteAVBuffer(std::vector<sptr<AudioBufferWrapper>>& audioBuffers);
        void Start();
        void Stop();
 
        int32_t fd_ = -1;
        sptr<MovingPhotoAVMuxer> muxer_{nullptr};
        sptr<MovingPhotoRecorderTask> recorderTask_ {nullptr};
    };
    CFilterType filterType_ = CFilterType::MOVING_PHOTO_MUXER;
    std::shared_ptr<Task> taskPtr_{nullptr};
    int32_t preFilterCount_{0};
    int32_t stopCount_{0};
    std::map<int32_t, int64_t> bufferPtsMap_;
    std::map<std::string, int32_t> trackIndexMap_;
    std::string videoCodecMimeType_;
    std::string audioCodecMimeType_;
    std::string metaDataCodecMimeType_;
    std::string bundleName_;
    uint64_t instanceId_{0};
    int32_t appUid_ {0};
    int32_t appPid_ {0};
    Plugins::OutputFormat outputFormat_ {Plugins::OutputFormat::DEFAULT};

    bool isStarted{false};
};
} // namespace CameraStandard
} // namespace OHOS
#endif // MOVING_PHOTO_MUXER_FILTER_H