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

#ifndef OHOS_CAMERA_DEMUXER_FILTER_H
#define OHOS_CAMERA_DEMUXER_FILTER_H

#include "cfilter.h"
#include "media_demuxer.h"

namespace OHOS {
namespace CameraStandard {
class DemuxerFilter : public CFilter, public std::enable_shared_from_this<DemuxerFilter> {
public:
    explicit DemuxerFilter(std::string name, CFilterType type);
    ~DemuxerFilter() override;

    void Init(
        const std::shared_ptr<CEventReceiver>& receiver, const std::shared_ptr<CFilterCallback>& callback) override;
    Status DoPrepare() override;
    Status DoStart() override;
    Status DoStop() override;
    Status DoPause() override;
    Status DoPauseDragging() override;
    Status DoPauseAudioAlign() override;
    Status DoResume() override;
    Status DoResumeDragging() override;
    Status DoResumeAudioAlign() override;
    Status DoFlush() override;
    Status DoPreroll() override;
    Status DoWaitPrerollDone(bool render) override;
    Status DoSetPerfRecEnabled(bool isPerfRecEnabled) override;
    Status Reset();

    Status PauseForSeek();
    Status ResumeForSeek();
    Status PrepareBeforeStart();

    void SetParameter(const std::shared_ptr<Meta>& parameter) override;
    void GetParameter(std::shared_ptr<Meta>& parameter) override;

    Status SetDataSource(const std::shared_ptr<MediaSource> source);
    Status SetSubtitleSource(const std::shared_ptr<MediaSource> source);
    void SetBundleName(const std::string& bundleName);
    Status SeekTo(int64_t seekTime, Plugins::SeekMode mode, int64_t& realSeekTime);

    bool IsRefParserSupported();
    Status StartReferenceParser(int64_t startTimeMs, bool isForward = true);
    Status GetFrameLayerInfo(std::shared_ptr<AVBuffer> videoSample, FrameLayerInfo& frameLayerInfo);
    Status GetFrameLayerInfo(uint32_t frameId, FrameLayerInfo& frameLayerInfo);
    Status GetGopLayerInfo(uint32_t gopId, GopLayerInfo& gopLayerInfo);

    Status GetIFramePos(std::vector<uint32_t>& IFramePos);
    Status Dts2FrameId(int64_t dts, uint32_t& frameId);
    Status SeekMs2FrameId(int64_t seekMs, uint32_t& frameId);
    Status FrameId2SeekMs(uint32_t frameId, int64_t& seekMs);

    Status StartTask(int32_t trackId);
    Status SelectTrack(int32_t trackId);

    std::shared_ptr<Meta> GetGlobalMetaInfo() const;
    std::vector<std::shared_ptr<Meta>> GetStreamMetaInfo() const;
    std::shared_ptr<Meta> GetUserMetaInfo() const;

    Status LinkNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType) override;
    Status UpdateNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType) override;
    Status UnLinkNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType) override;
    Status GetBitRates(std::vector<uint32_t>& bitRates);
    Status SelectBitRate(uint32_t bitRate);
    Status GetDownloadInfo(DownloadInfo& downloadInfo);
    Status GetPlaybackInfo(PlaybackInfo& playbackInfo);
    CFilterType GetFilterType();

    void OnLinkedResult(const sptr<AVBufferQueueProducer>& outputBufferQueue, std::shared_ptr<Meta>& meta);
    void OnUpdatedResult(std::shared_ptr<Meta>& meta);
    void OnUnlinkedResult(std::shared_ptr<Meta>& meta);

    std::map<int32_t, sptr<AVBufferQueueProducer>> GetBufferQueueProducerMap();
    Status PauseTaskByTrackId(int32_t trackId);
    bool IsRenderNextVideoFrameSupported();

    bool IsDrmProtected();
    // drm callback
    void OnDrmInfoUpdated(const std::multimap<std::string, std::vector<uint8_t>>& drmInfo);
    bool GetDuration(int64_t& durationMs);
    Status OptimizeDecodeSlow(bool isDecodeOptimizationEnabled);
    Status SetSpeed(float speed);
    Status DisableMediaTrack(Plugins::MediaType mediaType);
    void SetDumpFlag(bool isdump);
    void OnDumpInfo(int32_t fd);
    void SetCallerInfo(uint64_t instanceId, const std::string& appName);
    bool IsVideoEos();
    bool HasEosTrack();
    void RegisterVideoStreamReadyCallback(const std::shared_ptr<VideoStreamReadyCallback>& callback);
    void DeregisterVideoStreamReadyCallback();
    Status ResumeDemuxerReadLoop();
    Status PauseDemuxerReadLoop();
    void WaitForBufferingEnd();
    int32_t GetCurrentVideoTrackId();
    void SetSyncCenter(std::shared_ptr<MediaSyncManager> syncCenter);
    void SetIsNotPrepareBeforeStart(bool isNotPrepareBeforeStart);
    void SetIsEnableReselectVideoTrack(bool isEnable);
    void SetApiVersion(int32_t apiVersion);
    bool IsLocalFd();
    Status RebootPlugin();
    uint64_t GetCachedDuration();
    void RestartAndClearBuffer();
    bool IsFlvLive();

protected:
    Status OnLinked(CStreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<CFilterLinkCallback>& callback) override;

    Status OnUpdated(CStreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<CFilterLinkCallback>& callback) override;

    Status OnUnLinked(CStreamType inType, const std::shared_ptr<CFilterLinkCallback>& callback) override;

private:
    bool FindTrackId(CStreamType outType, int32_t& trackId);
    bool FindCStreamType(CStreamType& streamType, Plugins::MediaType mediaType, std::string mime, size_t index);
    bool ShouldTrackSkipped(Plugins::MediaType mediaType, std::string mime, size_t index);
    void UpdateTrackIdMap(CStreamType streamType, int32_t index);
    Status FaultDemuxerEventInfoWrite(CStreamType& streamType);
    bool IsVideoMime(const std::string& mime);
    bool IsAudioMime(const std::string& mime);
    Status HandleTrackInfos(const std::vector<std::shared_ptr<Meta>>& trackInfos, int32_t& successNodeCount);
    std::string CollectVideoAndAudioMime();
    std::string uri_;

    std::atomic_bool isLoopStarted {false};

    std::shared_ptr<CFilter> nextFilter_ {nullptr};
    std::shared_ptr<MediaDemuxer> demuxer_ {nullptr};
    std::shared_ptr<MediaSource> mediaSource_ {nullptr};
    std::shared_ptr<CFilterLinkCallback> onLinkedResultCallback_ {nullptr};

    std::map<CStreamType, std::vector<int32_t>> track_id_map_ {};
    std::mutex mapMutex_;
    std::unordered_set<Plugins::MediaType> disabledMediaTracks_ {};

    bool isDump_ = false;
    std::string bundleName_;
    uint64_t instanceId_ {0};
    std::string videoMime_;
    std::string audioMime_;
    bool isNotPrepareBeforeStart_ {true};
    bool isEnableReselectVideoTrack_ {false};
    int32_t apiVersion_ {0};
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DEMUXER_FILTER_H
