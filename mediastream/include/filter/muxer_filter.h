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

#ifndef OHOS_CAMERA_MUXER_FILTER_H
#define OHOS_CAMERA_MUXER_FILTER_H

#include "cfilter.h"
#include "media_muxer.h"

namespace OHOS {
namespace CameraStandard {
class MuxerFilter : public CFilter, public std::enable_shared_from_this<MuxerFilter> {
public:
    explicit MuxerFilter(std::string name, CFilterType type);
    ~MuxerFilter() override;

    Status SetOutputParameter(int32_t appUid, int32_t appPid, int32_t fd, int32_t format);
    Status SetTransCoderMode();
    int64_t GetCurrentPtsMs();
    void Init(
        const std::shared_ptr<CEventReceiver>& receiver, const std::shared_ptr<CFilterCallback>& callback) override;
    Status DoPrepare() override;
    Status DoStart() override;
    Status DoPause() override;
    Status DoResume() override;
    Status DoStop() override;
    Status DoFlush() override;
    Status DoRelease() override;
    void SetParameter(const std::shared_ptr<Meta>& parameter) override;
    void SetUserMeta(const std::shared_ptr<Meta>& userMeta);
    void GetParameter(std::shared_ptr<Meta>& parameter) override;
    Status LinkNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType) override;
    Status UpdateNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType) override;
    Status UnLinkNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType) override;
    CFilterType GetFilterType();
    Status OnLinked(CStreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<CFilterLinkCallback>& callback) override;
    Status OnUpdated(CStreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<CFilterLinkCallback>& callback) override;
    Status OnUnLinked(CStreamType inType, const std::shared_ptr<CFilterLinkCallback>& callback) override;
    void OnBufferFilled(std::shared_ptr<AVBuffer>& inputBuffer, int32_t trackIndex,
        CStreamType streamType, sptr<AVBufferQueueProducer> inputBufferQueue);
    void OnTransCoderBufferFilled(std::shared_ptr<AVBuffer>& inputBuffer, int32_t trackIndex,
        CStreamType streamType, sptr<AVBufferQueueProducer> inputBufferQueue);
    void SetFaultEvent(const std::string& errMsg);
    void SetFaultEvent(const std::string& errMsg, int32_t ret);
    const std::string& GetContainerFormat(Plugins::OutputFormat format);
    void SetCallingInfo(int32_t appUid, int32_t appPid, const std::string& bundleName, uint64_t instanceId);
    void SetMaxDuration(int32_t maxDuration);
    void EventCompleteStopAsync();
    void NotifyWaitForUserMeta();
    void SetUserMetaAllSet(bool isUserMetaAllSet);
    void GetMuxerFirstFrameTimestamp(int64_t& timestamp);
    void SetMuxerFirstFrameTimestamp(int64_t timestamp);

private:
    Status HandleAudioMimeType(const std::shared_ptr<Meta>& meta);
    Status HandleVideoMimeType(const std::shared_ptr<Meta>& meta);
    Status HandleMetaDataMimeType(const std::shared_ptr<Meta>& meta);
    void WaitForUserMetaToStop();

    std::shared_ptr<CEventReceiver> eventReceiver_ {nullptr};
    std::shared_ptr<CFilterCallback> filterCallback_ {nullptr};
    std::shared_ptr<MediaMuxer> mediaMuxer_ {nullptr};
    int32_t preFilterCount_ {0};
    int32_t stopCount_ {0};
    int32_t eosCount_ {0};
    std::map<int32_t, int64_t> bufferPtsMap_ {};
    std::map<std::string, int32_t> trackIndexMap_ {};
    std::string videoCodecMimeType_;
    std::string audioCodecMimeType_;
    std::string metaDataCodecMimeType_;
    std::string bundleName_;
    uint64_t instanceId_ {0};
    int32_t appUid_ {0};
    int32_t appPid_ {0};
    Plugins::OutputFormat outputFormat_ {Plugins::OutputFormat::DEFAULT};

    int64_t lastVideoPts_ {0};
    int64_t lastAudioPts_ {0};
    bool videoIsEos {false};
    bool audioIsEos {false};
    bool isTransCoderMode {false};

    std::mutex stopMutex_;
    std::mutex userMetaMutex_;
    std::condition_variable stopCondition_;
    std::condition_variable userMetaCondition_;
    bool isUserMetaAllSet_{false};
    std::mutex eosMutex_;
    
    std::atomic<bool> isStarted{false};
    int32_t maxDuration_ {INT32_MAX};
    std::atomic<bool> isReachMaxDuration_{false};
    int64_t firstFrameTimestamp_ {-1};
    std::mutex firstTsMutex_;

    bool isAdts_ {true};
    int32_t audCodecProfile_ {0}; // default value: AAC_LC
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_MUXER_FILTER_H
