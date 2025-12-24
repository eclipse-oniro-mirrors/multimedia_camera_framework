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

#include "demuxer_filter.h"

#include "avbuffer_queue_define.h"
#include "camera_log.h"
#include "cfilter_factory.h"

// LCOV_EXCL_START
namespace OHOS {
namespace CameraStandard {
using namespace MediaAVCodec;
using MediaType = OHOS::Media::Plugins::MediaType;
using FileType = OHOS::Media::Plugins::FileType;
namespace {
    const std::string MIME_IMAGE = "image";
    const uint32_t DEFAULT_CACHE_LIMIT = 50 * 1024 * 1024; // 50M
}

static AutoRegisterCFilter<DemuxerFilter> g_registerDemuxerFilter("camera.demuxer",
    CFilterType::DEMUXER,
    [](const std::string& name, const CFilterType type) {
        return std::make_shared<DemuxerFilter>(name, CFilterType::DEMUXER);
    });

class DemuxerFilterLinkCallback : public CFilterLinkCallback {
public:
    explicit DemuxerFilterLinkCallback(std::shared_ptr<DemuxerFilter> demuxerFilter)
        : demuxerFilter_(demuxerFilter) {}

    void OnLinkedResult(const sptr<AVBufferQueueProducer>& queue, std::shared_ptr<Meta>& meta) override
    {
        auto demuxerFilter = demuxerFilter_.lock();
        CHECK_RETURN(demuxerFilter == nullptr);
        demuxerFilter->OnLinkedResult(queue, meta);
    }

    void OnUnlinkedResult(std::shared_ptr<Meta>& meta) override
    {
        auto demuxerFilter = demuxerFilter_.lock();
        CHECK_RETURN(demuxerFilter == nullptr);
        demuxerFilter->OnUnlinkedResult(meta);
    }

    void OnUpdatedResult(std::shared_ptr<Meta>& meta) override
    {
        auto demuxerFilter = demuxerFilter_.lock();
        CHECK_RETURN(demuxerFilter == nullptr);
        demuxerFilter->OnUpdatedResult(meta);
    }
private:
    std::weak_ptr<DemuxerFilter> demuxerFilter_;
};

class DemuxerFilterDrmCallback : public OHOS::MediaAVCodec::AVDemuxerCallback {
public:
    explicit DemuxerFilterDrmCallback(std::shared_ptr<DemuxerFilter> demuxerFilter) : demuxerFilter_(demuxerFilter)
    {
    }

    ~DemuxerFilterDrmCallback()
    {
        MEDIA_INFO_LOG("~DemuxerFilterDrmCallback");
    }

    void OnDrmInfoChanged(const std::multimap<std::string, std::vector<uint8_t>>& drmInfo) override
    {
        MEDIA_INFO_LOG("DemuxerFilterDrmCallback OnDrmInfoChanged");
        if (auto callback = demuxerFilter_.lock()) {
            callback->OnDrmInfoUpdated(drmInfo);
        }
    }

private:
    std::weak_ptr<DemuxerFilter> demuxerFilter_;
};

DemuxerFilter::DemuxerFilter(std::string name, CFilterType type) : CFilter(name, type)
{
    demuxer_ = std::make_shared<MediaDemuxer>();
    {
        std::lock_guard lock(mapMutex_);
        track_id_map_.clear();
    }
    CHECK_EXECUTE(demuxer_, demuxer_->SetIsCreatedByFilter(true));    
}

DemuxerFilter::~DemuxerFilter()
{
    MEDIA_INFO_LOG("~DemuxerFilter enter");
}

void DemuxerFilter::Init(const std::shared_ptr<CEventReceiver>& receiver,
    const std::shared_ptr<CFilterCallback>& callback)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("DemuxerFilter Init");
    this->receiver_ = receiver;
    this->callback_ = callback;
    MEDIA_DEBUG_LOG("DemuxerFilter Init for drm callback");

    std::shared_ptr<OHOS::MediaAVCodec::AVDemuxerCallback> drmCallback =
        std::make_shared<DemuxerFilterDrmCallback>(shared_from_this());
    demuxer_->SetDrmCallback(drmCallback);
    demuxer_->SetPlayerId(groupId_);
}

Status DemuxerFilter::SetDataSource(const std::shared_ptr<MediaSource> source)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("SetDataSource entered.");
    CHECK_RETURN_RET_ELOG(source == nullptr, Status::ERROR_INVALID_PARAMETER, "Invalid source");
    mediaSource_ = source;
    Status ret = demuxer_->SetDataSource(mediaSource_);
    demuxer_->SetCacheLimit(DEFAULT_CACHE_LIMIT);
    return ret;
}

Status DemuxerFilter::SetSubtitleSource(const std::shared_ptr<MediaSource> source)
{
    return demuxer_->SetSubtitleSource(source);
}

Status DemuxerFilter::DoSetPerfRecEnabled(bool isPerfRecEnabled)
{
    isPerfRecEnabled_ = isPerfRecEnabled;
    CHECK_RETURN_RET(demuxer_ == nullptr, Status::OK);
    demuxer_->SetPerfRecEnabled(isPerfRecEnabled);
    return Status::OK;
}

void DemuxerFilter::SetBundleName(const std::string& bundleName)
{
    if (demuxer_ != nullptr) {
        MEDIA_DEBUG_LOG("SetBundleName bundleName: %{public}s", bundleName.c_str());
        demuxer_->SetBundleName(bundleName);
    }
}

void DemuxerFilter::SetCallerInfo(uint64_t instanceId, const std::string& appName)
{
    instanceId_ = instanceId;
    bundleName_ = appName;
}

void DemuxerFilter::RegisterVideoStreamReadyCallback(const std::shared_ptr<VideoStreamReadyCallback>& callback)
{
    MEDIA_INFO_LOG("RegisterVideoStreamReadyCallback step into");
    if (callback != nullptr) {
        demuxer_->RegisterVideoStreamReadyCallback(callback);
    }
}

void DemuxerFilter::DeregisterVideoStreamReadyCallback()
{
    MEDIA_INFO_LOG("DeregisterVideoStreamReadyCallback step into");
    demuxer_->DeregisterVideoStreamReadyCallback();
}

Status DemuxerFilter::DoPrepare()
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(mediaSource_ == nullptr, Status::ERROR_INVALID_PARAMETER, "No valid media source");
    std::vector<std::shared_ptr<Meta>> trackInfos = demuxer_->GetStreamMetaInfo();
    MEDIA_INFO_LOG("trackCount: %{public}zu", trackInfos.size());
    if (trackInfos.size() == 0) {
        MEDIA_ERR_LOG("Doprepare: trackCount is invalid.");
        receiver_->OnEvent({"demuxer_filter", FilterEventType::EVENT_ERROR, MSERR_DEMUXER_FAILED});
        return Status::ERROR_INVALID_PARAMETER;
    }
    int32_t successNodeCount = 0;
    Status ret = HandleTrackInfos(trackInfos, successNodeCount);
    CHECK_RETURN_RET(ret != Status::OK, ret);
    if (successNodeCount == 0) {
        receiver_->OnEvent({"demuxer_filter", FilterEventType::EVENT_ERROR, MSERR_UNSUPPORT_CONTAINER_TYPE});
        return Status::ERROR_UNSUPPORTED_FORMAT;
    }
    return Status::OK;
}

Status DemuxerFilter::HandleTrackInfos(const std::vector<std::shared_ptr<Meta>>& trackInfos, int32_t& successNodeCount)
{
    Status ret = Status::OK;
    bool hasVideoFilter = false;
    bool hasInvalidVideo = false;
    bool hasInvalidAudio = false;
    CHECK_RETURN_RET_ELOG(callback_ == nullptr, Status::OK, "callback is nullptr");

    for (size_t index = 0; index < trackInfos.size(); index++) {
        std::shared_ptr<Meta> meta = trackInfos[index];
        CHECK_RETURN_RET_ELOG(
            meta == nullptr, Status::ERROR_INVALID_PARAMETER, "meta is invalid, index: %{public}zu", index);
        std::string mime;
        CHECK_CONTINUE_ELOG(!meta->GetData(Tag::MIME_TYPE, mime), "mimeType not found, index: %{public}zu", index);
        CHECK_CONTINUE_ELOG(mime.empty(), "mimeType is empty, index: %{public}zu", index);
        MEDIA_DEBUG_LOG("mimeType: %{public}s, index: %{public}zu", mime.c_str(), index);
        MediaType mediaType;
        CHECK_CONTINUE_ELOG(
            !meta->GetData(Tag::MEDIA_TYPE, mediaType), "mediaType not found, index: %{public}zu", index);
        CHECK_CONTINUE_WLOG(ShouldTrackSkipped(mediaType, mime, index), "Skipped mimeType: %{public}d", mediaType);

        CStreamType streamType;
        CHECK_RETURN_RET(!FindCStreamType(streamType, mediaType, mime, index), Status::ERROR_INVALID_PARAMETER);
        bool isTrackInvalid = mime.find("invalid") == 0;
        hasInvalidVideo |= (isTrackInvalid && streamType == CStreamType::ENCODED_VIDEO);
        hasInvalidAudio |= (isTrackInvalid && streamType == CStreamType::ENCODED_AUDIO);
        CHECK_CONTINUE(isTrackInvalid);

        UpdateTrackIdMap(streamType, static_cast<int32_t>(index));
        CHECK_CONTINUE(streamType == CStreamType::ENCODED_VIDEO && hasVideoFilter);

        hasVideoFilter |= (streamType == CStreamType::ENCODED_VIDEO && isEnableReselectVideoTrack_);
        ret = callback_->OnCallback(shared_from_this(), CFilterCallBackCommand::NEXT_FILTER_NEEDED, streamType);
        CHECK_RETURN_RET_ELOG(ret != Status::OK && FaultDemuxerEventInfoWrite(streamType) == Status::OK, ret,
            "OnCallback Link Filter Fail.");
        successNodeCount++;
    }
    bool isOnlyInvalidAVTrack = (hasInvalidVideo && !demuxer_->HasVideo()) ||
        (hasInvalidAudio && !demuxer_->HasAudio());
    if (isOnlyInvalidAVTrack) {
        MEDIA_ERR_LOG("Only has invalid video or invalid audio track");
        receiver_->OnEvent({"demuxer_filter", FilterEventType::EVENT_ERROR, MSERR_DEMUXER_FAILED});
    }
    return ret;
}

Status DemuxerFilter::FaultDemuxerEventInfoWrite(CStreamType& streamType)
{
    MEDIA_INFO_LOG("FaultDemuxerEventInfoWrite enter.");
    return Status::OK;
}

std::string DemuxerFilter::CollectVideoAndAudioMime()
{
    MEDIA_INFO_LOG("CollectVideoAndAudioInfo entered.");
    std::string mime;
    std::string videoMime = "";
    std::string audioMime = "";
    std::vector<std::shared_ptr<Meta>> metaInfo = demuxer_->GetStreamMetaInfo();
    for (const auto& trackInfo : metaInfo) {
        CHECK_CONTINUE_WLOG(!(trackInfo->GetData(Tag::MIME_TYPE, mime)), "Get MIME fail");
        if (IsVideoMime(mime)) {
            videoMime += (mime + ",");
        } else if (IsAudioMime(mime)) {
            audioMime += (mime + ",");
        }
    }
    return videoMime + " : " + audioMime;
}

bool DemuxerFilter::IsVideoMime(const std::string& mime)
{
    return mime.find("video/") == 0;
}

bool DemuxerFilter::IsAudioMime(const std::string& mime)
{
    return mime.find("audio/") == 0;
}

void DemuxerFilter::UpdateTrackIdMap(CStreamType streamType, int32_t index)
{
    std::lock_guard lock(mapMutex_);
    auto it = track_id_map_.find(streamType);
    if (it != track_id_map_.end()) {
        it->second.push_back(index);
    } else {
        std::vector<int32_t> vec = {index};
        track_id_map_.insert({streamType, vec});
    }
}

Status DemuxerFilter::PrepareBeforeStart()
{
    CHECK_RETURN_RET_ILOG(isLoopStarted.load(), Status::OK, "Loop is started. Not need start again.");
    SetIsNotPrepareBeforeStart(false);
    return CFilter::Start();
}

Status DemuxerFilter::DoStart()
{
    CHECK_RETURN_RET_ILOG(isLoopStarted.load(), DoResume(), "Loop is started. Resume only.");
    MEDIA_INFO_LOG("Loop is not started. PrepareBeforeStart firstly.");
    isLoopStarted = true;
    CAMERA_SYNC_TRACE;
    return demuxer_->Start();
}

Status DemuxerFilter::DoStop()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("Stop in");
    isLoopStarted = false;
    return demuxer_->Stop();
}

Status DemuxerFilter::DoPause()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("Pause in");
    return demuxer_->Pause();
}

Status DemuxerFilter::DoPauseDragging()
{
    MEDIA_INFO_LOG("DoPauseDragging in");
    return demuxer_->PauseDragging();
}

Status DemuxerFilter::DoPauseAudioAlign()
{
    MEDIA_INFO_LOG("DoPauseAudioAlign in");
    return demuxer_->PauseAudioAlign();
}

Status DemuxerFilter::PauseForSeek()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("PauseForSeek in");
    // demuxer pause first for auido render immediatly
    demuxer_->Pause();
    auto it = nextCFiltersMap_.find(CStreamType::ENCODED_VIDEO);
    if (it != nextCFiltersMap_.end() && it->second.size() == 1) {
        auto filter = it->second.back();
        CHECK_RETURN_RET_ILOG(filter != nullptr, filter->Pause(), "filter pause");
    }
    return Status::ERROR_INVALID_OPERATION;
}

Status DemuxerFilter::DoResume()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("Resume in");
    return demuxer_->Resume();
}

Status DemuxerFilter::DoResumeDragging()
{
    MEDIA_INFO_LOG("DoResumeDragging in");
    return demuxer_->ResumeDragging();
}

Status DemuxerFilter::DoResumeAudioAlign()
{
    MEDIA_INFO_LOG("DoResumeAudioAlign in");
    return demuxer_->ResumeAudioAlign();
}

Status DemuxerFilter::ResumeForSeek()
{
    CHECK_RETURN_RET_ELOG(!isNotPrepareBeforeStart_, Status::OK, "Current is not need resumeForSeek");

    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("ResumeForSeek in size: %{public}zu", nextCFiltersMap_.size());
    auto it = nextCFiltersMap_.find(CStreamType::ENCODED_VIDEO);
    if (it != nextCFiltersMap_.end() && it->second.size() == 1) {
        auto filter = it->second.back();
        if (filter != nullptr) {
            MEDIA_INFO_LOG("filter resume");
            filter->Resume();
            filter->WaitAllState(CFilterState::RUNNING);
        }
    }
    return demuxer_->Resume();
}

Status DemuxerFilter::DoFlush()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Flush entered");
    return demuxer_->Flush();
}

Status DemuxerFilter::DoPreroll()
{
    MEDIA_INFO_LOG("DoPreroll in");
    Status ret = demuxer_->Preroll();
    isLoopStarted.store(true);
    return ret;
}

Status DemuxerFilter::DoWaitPrerollDone(bool render)
{
    (void)render;
    MEDIA_INFO_LOG("DoWaitPrerollDone in.");
    return demuxer_->PausePreroll();
}

Status DemuxerFilter::Reset()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("Reset in");
    {
        std::lock_guard lock(mapMutex_);
        track_id_map_.clear();
    }
    return demuxer_->Reset();
}

bool DemuxerFilter::IsRefParserSupported()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("IsRefParserSupported entered");
    return demuxer_->IsRefParserSupported();
}

Status DemuxerFilter::StartReferenceParser(int64_t startTimeMs, bool isForward)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("StartReferenceParser entered");
    return demuxer_->StartReferenceParser(startTimeMs, isForward);
}

Status DemuxerFilter::GetFrameLayerInfo(std::shared_ptr<AVBuffer> videoSample, FrameLayerInfo& frameLayerInfo)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("GetFrameLayerInfo entered");
    return demuxer_->GetFrameLayerInfo(videoSample, frameLayerInfo);
}

Status DemuxerFilter::GetFrameLayerInfo(uint32_t frameId, FrameLayerInfo& frameLayerInfo)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("GetFrameLayerInfo entered");
    return demuxer_->GetFrameLayerInfo(frameId, frameLayerInfo);
}

Status DemuxerFilter::GetGopLayerInfo(uint32_t gopId, GopLayerInfo& gopLayerInfo)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("GetGopLayerInfo entered");
    return demuxer_->GetGopLayerInfo(gopId, gopLayerInfo);
}

Status DemuxerFilter::GetIFramePos(std::vector<uint32_t>& IFramePos)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("GetIFramePos entered");
    return demuxer_->GetIFramePos(IFramePos);
}

Status DemuxerFilter::Dts2FrameId(int64_t dts, uint32_t& frameId)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Dts2FrameId entered");
    return demuxer_->Dts2FrameId(dts, frameId);
}

Status DemuxerFilter::SeekMs2FrameId(int64_t seekMs, uint32_t& frameId)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("SeekMs2FrameId entered");
    return demuxer_->SeekMs2FrameId(seekMs, frameId);
}

Status DemuxerFilter::FrameId2SeekMs(uint32_t frameId, int64_t& seekMs)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("FrameId2SeekMs entered");
    return demuxer_->FrameId2SeekMs(frameId, seekMs);
}

void DemuxerFilter::SetParameter(const std::shared_ptr<Meta>& parameter)
{
    MEDIA_INFO_LOG("SetParameter enter");
}

void DemuxerFilter::GetParameter(std::shared_ptr<Meta>& parameter)
{
    MEDIA_INFO_LOG("GetParameter enter");
}

void DemuxerFilter::SetDumpFlag(bool isDump)
{
    isDump_ = isDump;
    if (demuxer_ != nullptr) {
        demuxer_->SetDumpInfo(isDump_, instanceId_);
    }
}

std::map<int32_t, sptr<AVBufferQueueProducer>> DemuxerFilter::GetBufferQueueProducerMap()
{
    return demuxer_->GetBufferQueueProducerMap();
}

Status DemuxerFilter::PauseTaskByTrackId(int32_t trackId)
{
    return demuxer_->PauseTaskByTrackId(trackId);
}

Status DemuxerFilter::SeekTo(int64_t seekTime, Plugins::SeekMode mode, int64_t& realSeekTime)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("SeekTo in");
    return demuxer_->SeekTo(seekTime, mode, realSeekTime);
}

Status DemuxerFilter::StartTask(int32_t trackId)
{
    return demuxer_->StartTask(trackId);
}

Status DemuxerFilter::SelectTrack(int32_t trackId)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("SelectTrack called");
    return demuxer_->SelectTrack(trackId);
}

std::vector<std::shared_ptr<Meta>> DemuxerFilter::GetStreamMetaInfo() const
{
    return demuxer_->GetStreamMetaInfo();
}

std::shared_ptr<Meta> DemuxerFilter::GetGlobalMetaInfo() const
{
    return demuxer_->GetGlobalMetaInfo();
}

std::shared_ptr<Meta> DemuxerFilter::GetUserMetaInfo() const
{
    return demuxer_->GetUserMeta();
}

Status DemuxerFilter::LinkNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType)
{
    int32_t trackId = -1;
    CHECK_RETURN_RET_ELOG(!FindTrackId(outType, trackId), Status::ERROR_INVALID_PARAMETER, "FindTrackId failed.");
    std::shared_ptr<Meta> globalInfo = demuxer_->GetGlobalMetaInfo();
    FileType fileType = FileType::UNKNOW;
    CHECK_PRINT_WLOG(
        globalInfo == nullptr || !globalInfo->GetData(Tag::MEDIA_FILE_TYPE, fileType), "Get file type failed");
    std::vector<std::shared_ptr<Meta>> trackInfos = demuxer_->GetStreamMetaInfo();
    std::shared_ptr<Meta> meta = trackInfos[trackId];
    for (MapIt iter = meta->begin(); iter != meta->end(); iter++) {
        MEDIA_DEBUG_LOG("Link %{public}s", iter->first.c_str());
    }
    std::string mimeType;
    meta->GetData(Tag::MIME_TYPE, mimeType);
    MEDIA_INFO_LOG("LinkNext mimeType %{public}s", mimeType.c_str());

    nextFilter_ = nextFilter;
    nextCFiltersMap_[outType].push_back(nextFilter_);
    MEDIA_INFO_LOG("LinkNext NextFilter FilterType %{public}d", nextFilter_->GetCFilterType());
    meta->SetData(Tag::REGULAR_TRACK_ID, trackId);
    if (fileType == FileType::AVI) {
        MEDIA_INFO_LOG("File type is AVI %{public}d", static_cast<int32_t>(FileType::AVI));
        meta->SetData(Tag::MEDIA_FILE_TYPE, FileType::AVI);
    }
    std::shared_ptr<CFilterLinkCallback> filterLinkCallback
        = std::make_shared<DemuxerFilterLinkCallback>(shared_from_this());
    return nextFilter->OnLinked(outType, meta, filterLinkCallback);
}

Status DemuxerFilter::GetBitRates(std::vector<uint32_t>& bitRates)
{
    CHECK_PRINT_ELOG(mediaSource_ == nullptr, "GetBitRates failed, mediaSource = nullptr");
    return demuxer_->GetBitRates(bitRates);
}

Status DemuxerFilter::GetDownloadInfo(DownloadInfo& downloadInfo)
{
    CHECK_RETURN_RET(demuxer_ == nullptr, Status::ERROR_INVALID_OPERATION);
    return demuxer_->GetDownloadInfo(downloadInfo);
}

Status DemuxerFilter::GetPlaybackInfo(PlaybackInfo& playbackInfo)
{
    CHECK_RETURN_RET(demuxer_ == nullptr, Status::ERROR_INVALID_OPERATION);
    return demuxer_->GetPlaybackInfo(playbackInfo);
}

Status DemuxerFilter::SelectBitRate(uint32_t bitRate)
{
    CHECK_PRINT_ELOG(mediaSource_ == nullptr, "SelectBitRate failed, mediaSource = nullptr");
    return demuxer_->SelectBitRate(bitRate);
}

bool DemuxerFilter::FindTrackId(CStreamType outType, int32_t& trackId)
{
    std::lock_guard lock(mapMutex_);
    auto it = track_id_map_.find(outType);
    if (it != track_id_map_.end()) {
        trackId = it->second.front();
        it->second.erase(it->second.begin());
        if (it->second.empty()) {
            track_id_map_.erase(it);
        }
        return true;
    }
    return false;
}

bool DemuxerFilter::FindCStreamType(
    CStreamType& streamType, Plugins::MediaType mediaType, std::string mime, size_t index)
{
    MEDIA_INFO_LOG("mediaType: %{public}d, mine: %{public}s", static_cast<int32_t>(mediaType), mime.c_str());
    if (mediaType == Plugins::MediaType::SUBTITLE) {
        streamType = CStreamType::SUBTITLE;
    } else if (mediaType == Plugins::MediaType::AUDIO) {
        streamType = CStreamType::RAW_AUDIO;
    } else if (mediaType == Plugins::MediaType::VIDEO) {
        streamType = CStreamType::RAW_VIDEO;
    } else if (mediaType == Plugins::MediaType::TIMEDMETA) {
        streamType = CStreamType::RAW_METADATA;
    } else {
        MEDIA_ERR_LOG("streamType not found, index: %{public}zu", index);
        return false;
    }
    return true;
}

bool DemuxerFilter::ShouldTrackSkipped(Plugins::MediaType mediaType, std::string mime, size_t index)
{
    if (mime.substr(0, MIME_IMAGE.size()).compare(MIME_IMAGE) == 0) {
        MEDIA_WARNING_LOG("is image track, continue");
        return true;
    } else if (!disabledMediaTracks_.empty() && disabledMediaTracks_.find(mediaType) != disabledMediaTracks_.end()) {
        MEDIA_WARNING_LOG("mediaType disabled, index: %{public}zu", index);
        return true;
    }
    return false;
}

Status DemuxerFilter::UpdateNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType)
{
    return Status::OK;
}

Status DemuxerFilter::UnLinkNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType)
{
    return Status::OK;
}

CFilterType DemuxerFilter::GetFilterType()
{
    return filterType_;
}

Status DemuxerFilter::OnLinked(CStreamType inType, const std::shared_ptr<Meta>& meta,
    const std::shared_ptr<CFilterLinkCallback>& callback)
{
    onLinkedResultCallback_ = callback;
    return Status::OK;
}

Status DemuxerFilter::OnUpdated(CStreamType inType, const std::shared_ptr<Meta>& meta,
    const std::shared_ptr<CFilterLinkCallback>& callback)
{
    return Status::OK;
}

Status DemuxerFilter::OnUnLinked(CStreamType inType, const std::shared_ptr<CFilterLinkCallback>& callback)
{
    return Status::OK;
}

void DemuxerFilter::OnLinkedResult(const sptr<AVBufferQueueProducer>& outputBufferQueue, std::shared_ptr<Meta>& meta)
{
    CHECK_RETURN_ELOG(meta == nullptr, "meta is invalid.");
    int32_t trackId;
    CHECK_RETURN_ELOG(!meta->GetData(Tag::REGULAR_TRACK_ID, trackId), "trackId not found");
    demuxer_->SetOutputBufferQueue(trackId, outputBufferQueue);
    CHECK_RETURN(trackId < 0);
    uint32_t trackIdU32 = static_cast<uint32_t>(trackId);
    int32_t decoderFramerateUpperLimit = 0;
    if (meta->GetData(Tag::VIDEO_DECODER_RATE_UPPER_LIMIT, decoderFramerateUpperLimit)) {
        demuxer_->SetDecoderFramerateUpperLimit(decoderFramerateUpperLimit, trackIdU32);
    }
    double framerate;
    if (meta->GetData(Tag::VIDEO_FRAME_RATE, framerate)) {
        demuxer_->SetFrameRate(framerate, trackIdU32);
    }
}

void DemuxerFilter::OnUpdatedResult(std::shared_ptr<Meta>& meta)
{
}

void DemuxerFilter::OnUnlinkedResult(std::shared_ptr<Meta>& meta)
{
}

bool DemuxerFilter::IsDrmProtected()
{
    MEDIA_INFO_LOG("IsDrmProtected");
    return demuxer_->IsLocalDrmInfosExisted();
}

void DemuxerFilter::OnDrmInfoUpdated(const std::multimap<std::string, std::vector<uint8_t>>& drmInfo)
{
    MEDIA_INFO_LOG("OnDrmInfoUpdated");
    if (this->receiver_ != nullptr) {
        this->receiver_->OnEvent({"demuxer_filter", FilterEventType::EVENT_DRM_INFO_UPDATED, drmInfo});
    } else {
        MEDIA_ERR_LOG("OnDrmInfoUpdated failed receiver is nullptr");
    }
}

bool DemuxerFilter::GetDuration(int64_t& durationMs)
{
    return demuxer_->GetDuration(durationMs);
}

Status DemuxerFilter::OptimizeDecodeSlow(bool isDecodeOptimizationEnabled)
{
    CHECK_RETURN_RET_ELOG(demuxer_ == nullptr, Status::ERROR_INVALID_OPERATION, "OptimizeDecodeSlow failed.");
    return demuxer_->OptimizeDecodeSlow(isDecodeOptimizationEnabled);
}

Status DemuxerFilter::SetSpeed(float speed)
{
    CHECK_RETURN_RET_ELOG(demuxer_ == nullptr, Status::ERROR_INVALID_OPERATION, "SetSpeed failed.");
    return demuxer_->SetSpeed(speed);
}

Status DemuxerFilter::DisableMediaTrack(Plugins::MediaType mediaType)
{
    disabledMediaTracks_.emplace(mediaType);
    return demuxer_->DisableMediaTrack(mediaType);
}

void DemuxerFilter::OnDumpInfo(int32_t fd)
{
    MEDIA_DEBUG_LOG("DemuxerFilter::OnDumpInfo called.");
    if (demuxer_ != nullptr) {
        demuxer_->OnDumpInfo(fd);
    }
}

bool DemuxerFilter::IsRenderNextVideoFrameSupported()
{
    MEDIA_DEBUG_LOG("DemuxerFilter::OnDumpInfo called.");
    CHECK_RETURN_RET_ELOG(demuxer_ == nullptr, false, "demuxer_ is nullptr");
    return demuxer_->IsRenderNextVideoFrameSupported();
}

Status DemuxerFilter::ResumeDemuxerReadLoop()
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(demuxer_ == nullptr, Status::ERROR_INVALID_OPERATION, "ResumeDemuxerReadLoop failed.");
    MEDIA_INFO_LOG("ResumeDemuxerReadLoop start.");
    return demuxer_->ResumeDemuxerReadLoop();
}

Status DemuxerFilter::PauseDemuxerReadLoop()
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(demuxer_ == nullptr, Status::ERROR_INVALID_OPERATION, "PauseDemuxerReadLoop failed.");
    MEDIA_INFO_LOG("PauseDemuxerReadLoop start.");
    return demuxer_->PauseDemuxerReadLoop();
}

bool DemuxerFilter::IsVideoEos()
{
    CHECK_RETURN_RET_ELOG(demuxer_ == nullptr, false, "demuxer_ is nullptr");
    return demuxer_->IsVideoEos();
}

bool DemuxerFilter::HasEosTrack()
{
    CHECK_RETURN_RET_ELOG(demuxer_ == nullptr, false, "demuxer_ is nullptr");
    return demuxer_->HasEosTrack();
}

void DemuxerFilter::WaitForBufferingEnd()
{
    CHECK_RETURN_ELOG(demuxer_ == nullptr, "demuxer_ is nullptr");
    demuxer_->WaitForBufferingEnd();
}

int32_t DemuxerFilter::GetCurrentVideoTrackId()
{
    CHECK_RETURN_RET_ELOG(demuxer_ == nullptr, -1, "demuxer_ is nullptr");
    return demuxer_->GetCurrentVideoTrackId();
}

void DemuxerFilter::SetIsNotPrepareBeforeStart(bool isNotPrepareBeforeStart)
{
    isNotPrepareBeforeStart_ = isNotPrepareBeforeStart;
}

void DemuxerFilter::SetIsEnableReselectVideoTrack(bool isEnable)
{
    isEnableReselectVideoTrack_ = isEnable;
    demuxer_->SetIsEnableReselectVideoTrack(isEnable);
}

void DemuxerFilter::SetApiVersion(int32_t apiVersion)
{
    apiVersion_ = apiVersion;
    demuxer_->SetApiVersion(apiVersion);
}

bool DemuxerFilter::IsLocalFd()
{
    CHECK_RETURN_RET_ELOG(demuxer_ == nullptr, false, "demuxer_ is nullptr");
    return demuxer_->IsLocalFd();
}

Status DemuxerFilter::RebootPlugin()
{
    CHECK_RETURN_RET_ELOG(demuxer_ == nullptr, Status::ERROR_UNKNOWN, "demuxer_ is nullptr");
    return demuxer_->RebootPlugin();
}

uint64_t DemuxerFilter::GetCachedDuration()
{
    CHECK_RETURN_RET_ELOG(demuxer_ == nullptr, 0, "demuxer_ is nullptr");
    return demuxer_->GetCachedDuration();
}

void DemuxerFilter::RestartAndClearBuffer()
{
    CHECK_RETURN_ELOG(demuxer_ != nullptr, "demuxer_ is nullptr");
    return demuxer_->RestartAndClearBuffer();
}

bool DemuxerFilter::IsFlvLive()
{
    CHECK_RETURN_RET_ELOG(demuxer_ != nullptr, false, "demuxer_ is nullptr");
    return demuxer_->IsFlvLive();
}

void DemuxerFilter::SetSyncCenter(std::shared_ptr<MediaSyncManager> syncCenter)
{
    CHECK_RETURN_ELOG(demuxer_ != nullptr, "demuxer_ is nullptr");
    demuxer_->SetSyncCenter(syncCenter);
}
} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP