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

#include "muxer_filter.h"

#include "camera_log.h"
#include "cfilter_factory.h"
#include "media_types.h"

// LCOV_EXCL_START
namespace OHOS {
namespace CameraStandard {
namespace {
    static const std::unordered_map<OHOS::Media::Plugins::OutputFormat, std::string> FORMAT_TABLE = {
        {OHOS::Media::Plugins::OutputFormat::DEFAULT, OHOS::Media::Plugins::MimeType::MEDIA_MP4},
        {OHOS::Media::Plugins::OutputFormat::MPEG_4, OHOS::Media::Plugins::MimeType::MEDIA_MP4},
        {OHOS::Media::Plugins::OutputFormat::M4A, OHOS::Media::Plugins::MimeType::MEDIA_M4A},
        {OHOS::Media::Plugins::OutputFormat::AMR, OHOS::Media::Plugins::MimeType::MEDIA_AMR},
        {OHOS::Media::Plugins::OutputFormat::MP3, OHOS::Media::Plugins::MimeType::MEDIA_MP3},
        {OHOS::Media::Plugins::OutputFormat::WAV, OHOS::Media::Plugins::MimeType::MEDIA_WAV},
    };
    constexpr int64_t WAIT_TIME_OUT_NS = 3000000000;
    constexpr int64_t US_TO_MS = 1000;
    constexpr int64_t S_TO_MS = 1000;
    constexpr uint32_t BUFFER_IS_EOS = 1;
    constexpr int32_t VALID_MIN_DURATION = 1;
    constexpr uint32_t STOP_TIME_OUT_MS = 1000;
}

static AutoRegisterCFilter<MuxerFilter> g_registerMuxerFilter("camera.muxer", CFilterType::MUXER,
    [](const std::string& name, const CFilterType type) {
        return std::make_shared<MuxerFilter>(name, CFilterType::MUXER);
    });

class MuxerBrokerListener : public IBrokerListener {
public:
    MuxerBrokerListener(std::shared_ptr<MuxerFilter> muxerFilter, int32_t trackIndex,
        CStreamType streamType, sptr<AVBufferQueueProducer> inputBufferQueue)
        : muxerFilter_(std::move(muxerFilter)), trackIndex_(trackIndex), streamType_(streamType),
        inputBufferQueue_(inputBufferQueue)
    {
    }

    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }

    void OnBufferFilled(std::shared_ptr<AVBuffer>& avBuffer) override
    {
        sptr<AVBufferQueueProducer> inputBufferQueue = inputBufferQueue_.promote();
        if (inputBufferQueue != nullptr) {
            if (auto muxerFilter = muxerFilter_.lock()) {
                muxerFilter->OnBufferFilled(avBuffer, trackIndex_, streamType_, inputBufferQueue);
            } else {
                MEDIA_ERR_LOG("invalid muxerFilter");
            }
        }
    }

private:
    std::weak_ptr<MuxerFilter> muxerFilter_;
    int32_t trackIndex_;
    CStreamType streamType_;
    wptr<AVBufferQueueProducer> inputBufferQueue_;
};

MuxerFilter::MuxerFilter(std::string name, CFilterType type): CFilter(name, type)
{
    MEDIA_DEBUG_LOG("entered.");
}

MuxerFilter::~MuxerFilter()
{
    MEDIA_INFO_LOG("entered. name:%{public}s", name_.c_str());
}

Status MuxerFilter::SetOutputParameter(int32_t appUid, int32_t appPid, int32_t fd, int32_t format)
{
    MEDIA_INFO_LOG("SetOutputParameter, appUid: %{public}d, appPid: %{public}d, format: %{public}d",
        appUid, appPid, format);
    mediaMuxer_ = std::make_shared<MediaMuxer>(appUid, appPid);
    outputFormat_ = static_cast<Plugins::OutputFormat>(format);
    Status ret = mediaMuxer_->Init(fd, outputFormat_);
    if (ret != Status::OK) {
        SetFaultEvent("MuxerFilter::SetOutputParameter, muxerFilter init error", static_cast<int32_t>(ret));
    }
    return ret;
}

Status MuxerFilter::SetTransCoderMode()
{
    MEDIA_INFO_LOG("SetTransCoderMode");
    isTransCoderMode = true;
    return Status::OK;
}

int64_t MuxerFilter::GetCurrentPtsMs()
{
    return (lastVideoPts_ ? lastVideoPts_ : lastAudioPts_) / US_TO_MS;
}

void MuxerFilter::Init(const std::shared_ptr<CEventReceiver>& receiver,
    const std::shared_ptr<CFilterCallback>& callback)
{
    MEDIA_INFO_LOG("Init");
    CAMERA_SYNC_TRACE;
    eventReceiver_ = receiver;
    filterCallback_ = callback;
}

Status MuxerFilter::DoPrepare()
{
    MEDIA_INFO_LOG("Prepare");
    CAMERA_SYNC_TRACE;
    return Status::OK;
}

Status MuxerFilter::DoStart()
{
    MEDIA_INFO_LOG("MuxerFilter Start");
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET(isStarted, Status::OK);
    CHECK_RETURN_RET_ELOG(!mediaMuxer_, Status::ERROR_NULL_POINTER, "mediaMuxer_ is null");
    Status ret = mediaMuxer_->Start();
    if (ret != Status::OK) {
        SetFaultEvent("MuxerFilter::DoStart error", static_cast<int32_t>(ret));
    } else {
        isStarted = true;
        isReachMaxDuration_ = false;
    }
    return ret;
}

Status MuxerFilter::DoPause()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("Pause");
    return Status::OK;
}

Status MuxerFilter::DoResume()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("Resume");
    return Status::OK;
}

Status MuxerFilter::DoStop()
{
    MEDIA_INFO_LOG("MuxerFilter Stop");
    CAMERA_SYNC_TRACE;
    stopCount_++;
    if (stopCount_ == preFilterCount_) {
        stopCount_ = 0;
        if (clusterId_ == 1) {
            // todo improve thread to avoid wild pointer
            auto thisWptr = weak_from_this();
            std::thread asyncThread([thisWptr]() {
                auto thisPtr = thisWptr.lock();
                CHECK_EXECUTE(thisPtr != nullptr, thisPtr->WaitForUserMetaToStop());
            });
            asyncThread.detach();
        } else {
            MEDIA_INFO_LOG("mediaMuxer_ stop is called");
            CHECK_RETURN_RET_ELOG(!mediaMuxer_, Status::ERROR_NULL_POINTER, "mediaMuxer_ is null");
            Status ret = mediaMuxer_->Stop();
            if (ret == Status::OK) {
                isStarted = false;
            } else if (ret == Status::ERROR_WRONG_STATE) {
                ret = Status::OK;
            } else {
                SetFaultEvent("MuxerFilter::DoStop error", static_cast<int32_t>(ret));
            }
            eventReceiver_->OnEvent({"movie_muxer_filter", FilterEventType::EVENT_COMPLETE, Status::OK});
            return ret;
        }
    }
    return Status::OK;
}

Status MuxerFilter::DoFlush()
{
    return Status::OK;
}

Status MuxerFilter::DoRelease()
{
    MEDIA_INFO_LOG("Release");
    return Status::OK;
}

void MuxerFilter::SetParameter(const std::shared_ptr<Meta>& parameter)
{
    MEDIA_INFO_LOG("SetParameter");
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_ELOG(!mediaMuxer_, "mediaMuxer_ is null");
    mediaMuxer_->SetParameter(parameter);
}

void MuxerFilter::SetUserMeta(const std::shared_ptr<Meta>& userMeta)
{
    MEDIA_INFO_LOG("SetUserMeta enter");
    CHECK_RETURN_ELOG(!mediaMuxer_, "mediaMuxer_ is null");
    Status ret = mediaMuxer_->SetUserMeta(userMeta);
    CHECK_PRINT_ILOG(ret != Status::OK, "SetUserMeta failed");
}

void MuxerFilter::GetParameter(std::shared_ptr<Meta>& parameter)
{
    MEDIA_INFO_LOG("GetParameter");
    CAMERA_SYNC_TRACE;
}

Status MuxerFilter::LinkNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType)
{
    return Status::OK;
}

Status MuxerFilter::UpdateNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("UpdateNext");
    return Status::OK;
}

Status MuxerFilter::UnLinkNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("UnLinkNext");
    return Status::OK;
}

CFilterType MuxerFilter::GetFilterType()
{
    MEDIA_INFO_LOG("GetFilterType");
    return CFilterType::MUXER;
}

Status MuxerFilter::HandleAudioMimeType(const std::shared_ptr<Meta>& meta)
{
    std::string mimeType;
    meta->Get<Tag::MIME_TYPE>(mimeType);
    if (mimeType.find("audio/") == 0) {
        if (mimeType == "audio/mp4a-latm") {
            meta->Set<Tag::AUDIO_AAC_IS_ADTS>(isAdts_);
            meta->Set<Tag::MEDIA_PROFILE>(audCodecProfile_);
        }
        Plugins::MediaType type = Plugins::MediaType::UNKNOWN;
        meta->Get<Tag::MEDIA_TYPE>(type);
        if (type == Plugins::MediaType::AUXILIARY && trackIndexMap_.find(audioCodecMimeType_) != trackIndexMap_.end()) {
            // provide REFERENCE_TRACK_IDS for auxiliary track
            auto sourceTrackIndex = trackIndexMap_.at(audioCodecMimeType_);
            meta->Set<Tag::REFERENCE_TRACK_IDS>({sourceTrackIndex});
            MEDIA_INFO_LOG("add audio REFERENCE_TRACK_IDS: %{public}d", sourceTrackIndex);
        } else {
            audioCodecMimeType_ = mimeType;
        }
    }
    return Status::OK;
}

Status MuxerFilter::HandleVideoMimeType(const std::shared_ptr<Meta>& meta)
{
    std::string mimeType;
    meta->Get<Tag::MIME_TYPE>(mimeType);
    if (mimeType.find("video/") == 0) {
        Plugins::MediaType type = Plugins::MediaType::UNKNOWN;
        meta->Get<Tag::MEDIA_TYPE>(type);
        if (type == Plugins::MediaType::AUXILIARY && trackIndexMap_.find(videoCodecMimeType_) != trackIndexMap_.end()) {
            // provide REFERENCE_TRACK_IDS for auxiliary track
            auto sourceTrackIndex = trackIndexMap_.at(videoCodecMimeType_);
            meta->Set<Tag::REFERENCE_TRACK_IDS>({sourceTrackIndex});
            MEDIA_INFO_LOG("add video REFERENCE_TRACK_IDS: %{public}d", sourceTrackIndex);
        } else {
            videoCodecMimeType_ = mimeType;
        }
    }
    return Status::OK;
}

Status MuxerFilter::HandleMetaDataMimeType(const std::shared_ptr<Meta>& meta)
{
    std::string mimeType;
    meta->Get<Tag::MIME_TYPE>(mimeType);
    if (mimeType.find("meta/") == 0) {
        metaDataCodecMimeType_ = mimeType;
        std::string srcMimeType;
        meta->Get<Tag::TIMED_METADATA_SRC_TRACK_MIME>(srcMimeType);
        if (trackIndexMap_.find(srcMimeType) != trackIndexMap_.end()) {
            auto sourceTrackIndex = trackIndexMap_.at(videoCodecMimeType_);
            meta->Set<Tag::TIMED_METADATA_SRC_TRACK>(sourceTrackIndex);
            MEDIA_INFO_LOG("add meta TIMED_METADATA_SRC_TRACK: %{public}d", sourceTrackIndex);
        }
    }
    return Status::OK;
}

Status MuxerFilter::OnLinked(CStreamType inType, const std::shared_ptr<Meta>& meta,
    const std::shared_ptr<CFilterLinkCallback>& callback)
{
    MEDIA_INFO_LOG("OnLinked");
    CAMERA_SYNC_TRACE;
    int32_t trackIndex;
    std::string mimeType;
    meta->Get<Tag::MIME_TYPE>(mimeType);
    HandleAudioMimeType(meta);
    HandleVideoMimeType(meta);
    HandleMetaDataMimeType(meta);
    CHECK_RETURN_RET_ELOG(!mediaMuxer_, Status::ERROR_NULL_POINTER, "mediaMuxer_ is null");
    auto ret = mediaMuxer_->AddTrack(trackIndex, meta);
    if (ret != Status::OK) {
        eventReceiver_->OnEvent({"muxer_filter", FilterEventType::EVENT_ERROR, ret});
        SetFaultEvent("MuxerFilter::OnLinked error", static_cast<int32_t>(ret));
        return ret;
    }

    if (trackIndexMap_.find(videoCodecMimeType_) == trackIndexMap_.end() ||
        trackIndexMap_.find(audioCodecMimeType_) == trackIndexMap_.end()) {
        trackIndexMap_.emplace(std::make_pair(mimeType, trackIndex));
    }
    sptr<AVBufferQueueProducer> inputBufferQueue = mediaMuxer_->GetInputBufferQueue(trackIndex);

    meta->SetData("muxer_name", name_);
    callback->OnLinkedResult(inputBufferQueue, const_cast<std::shared_ptr<Meta>& >(meta));
    sptr<IBrokerListener> listener = new MuxerBrokerListener(shared_from_this(), trackIndex,
        inType, inputBufferQueue);
    CHECK_RETURN_RET_ELOG(inputBufferQueue == nullptr, Status::ERROR_UNKNOWN, "OnLinked:inputBufferQueue is null");
    inputBufferQueue->SetBufferFilledListener(listener);
    preFilterCount_++;
    bufferPtsMap_.insert(std::pair<int32_t, int64_t>(trackIndex, 0));
    return Status::OK;
}

Status MuxerFilter::OnUpdated(CStreamType inType, const std::shared_ptr<Meta>& meta,
    const std::shared_ptr<CFilterLinkCallback>& callback)
{
    MEDIA_INFO_LOG("OnUpdated");
    return Status::OK;
}


Status MuxerFilter::OnUnLinked(CStreamType inType, const std::shared_ptr<CFilterLinkCallback>& callback)
{
    MEDIA_INFO_LOG("OnUnLinked");
    return Status::OK;
}

void MuxerFilter::OnBufferFilled(std::shared_ptr<AVBuffer>& inputBuffer, int32_t trackIndex,
    CStreamType streamType, sptr<AVBufferQueueProducer> inputBufferQueue)
{
    CAMERA_SYNC_TRACE;
    if (!isTransCoderMode) {
        int64_t currentBufferPts = inputBuffer->pts_;
        if (currentBufferPts / US_TO_MS > maxDuration_ * S_TO_MS && isReachMaxDuration_ == false) {
            MEDIA_INFO_LOG("MuxerFilter::OnBufferFilled currentBufferPts > maxDuration_ start to stop");
            isReachMaxDuration_ = true;
            std::thread asyncThread(std::bind(&MuxerFilter::EventCompleteStopAsync, this));
            asyncThread.detach();
        }
        int64_t anotherBufferPts = 0;
        for (auto mapInterator = bufferPtsMap_.begin(); mapInterator != bufferPtsMap_.end(); mapInterator++) {
            if (mapInterator->first != trackIndex) {
                anotherBufferPts = mapInterator->second;
            }
        }
        bufferPtsMap_[trackIndex] = currentBufferPts;
        CHECK_PRINT_ILOG(preFilterCount_ != 1 && std::abs(currentBufferPts - anotherBufferPts) >= WAIT_TIME_OUT_NS,
            "OnBufferFilled pts time interval is greater than 3 seconds");
        MEDIA_INFO_LOG("OnBufferFilled clusterId: %{public}d, trackIndex: %{public}d, streamType: %{public}d, "
                       "buffer->pts: %{public}" PRId64 ", size: %{public}d, flag: %{public}u, UniqueId: "
                       "%{public}" PRIu64,
                       clusterId_, trackIndex, streamType, inputBuffer->pts_, inputBuffer->memory_->GetSize(),
                       inputBuffer->flag_, inputBuffer->GetUniqueId());
        inputBufferQueue->ReturnBuffer(inputBuffer, true);
        return;
    }
    OnTransCoderBufferFilled(inputBuffer, trackIndex, streamType, inputBufferQueue);
}

void MuxerFilter::EventCompleteStopAsync()
{
    MEDIA_INFO_LOG("MuxerFilter EventCompleteStopAsync");
    eventReceiver_->OnEvent({"muxer_filter", FilterEventType::EVENT_COMPLETE, Status::OK});
}
          
void MuxerFilter::OnTransCoderBufferFilled(std::shared_ptr<AVBuffer>& inputBuffer, int32_t trackIndex,
    CStreamType streamType, sptr<AVBufferQueueProducer> inputBufferQueue)
{
    MEDIA_DEBUG_LOG("OnTransCoderBufferFilled");
    if ((inputBuffer->flag_ & BUFFER_IS_EOS) == 1) {
        std::unique_lock<std::mutex> lock(eosMutex_);
        eosCount_++;
        if (streamType == CStreamType::ENCODED_VIDEO) {
            MEDIA_INFO_LOG("video is eos");
            videoIsEos = true;
        } else if (streamType == CStreamType::ENCODED_AUDIO) {
            MEDIA_INFO_LOG("audio is eos");
            audioIsEos = true;
        }
        if ((eosCount_ == preFilterCount_) || (videoIsEos && audioIsEos)) {
            eventReceiver_->OnEvent({"muxer_filter", FilterEventType::EVENT_COMPLETE, Status::OK});
        }
    }
    if (streamType == CStreamType::ENCODED_AUDIO) {
        lastAudioPts_ = inputBuffer->pts_;
        if (videoCodecMimeType_.empty()) {
            inputBufferQueue->ReturnBuffer(inputBuffer, true);
        } else if (inputBuffer->pts_ <= lastVideoPts_ || videoIsEos) {
            inputBufferQueue->ReturnBuffer(inputBuffer, true);
        } else {
            std::unique_lock<std::mutex> lock(stopMutex_);
            stopCondition_.wait_for(lock, std::chrono::milliseconds(US_TO_MS));
            inputBufferQueue->ReturnBuffer(inputBuffer, true);
        }
    } else if (streamType == CStreamType::ENCODED_VIDEO) {
        lastVideoPts_ = inputBuffer->pts_;
        std::unique_lock<std::mutex> lock(stopMutex_);
        stopCondition_.notify_all();
        inputBufferQueue->ReturnBuffer(inputBuffer, true);
    } else {
        inputBufferQueue->ReturnBuffer(inputBuffer, true);
    }
}

void MuxerFilter::SetFaultEvent(const std::string& errMsg, int32_t ret)
{
    SetFaultEvent(errMsg + ", ret = " + std::to_string(ret));
}

void MuxerFilter::SetFaultEvent(const std::string& errMsg)
{
    MEDIA_ERR_LOG("MuxerFilter::SetFaultEvent, %{public}s", errMsg.c_str());
}

const std::string& MuxerFilter::GetContainerFormat(Plugins::OutputFormat format)
{
    static std::string emptyFormat = "";
    CHECK_RETURN_RET_ELOG(FORMAT_TABLE.find(format) == FORMAT_TABLE.end(), emptyFormat,
        "The output format %{public}d is not supported!", format);
    return FORMAT_TABLE.at(format);
}

void MuxerFilter::SetCallingInfo(int32_t appUid, int32_t appPid,
    const std::string& bundleName, uint64_t instanceId)
{
    appUid_ = appUid;
    appPid_ = appPid;
    bundleName_ = bundleName;
    instanceId_ = instanceId;
}

void MuxerFilter::SetMaxDuration(int32_t maxDuration)
{
    MEDIA_INFO_LOG("MuxerFilter SetMaxDuration = %{public}d", maxDuration);
    CAMERA_SYNC_TRACE;
    if (maxDuration < VALID_MIN_DURATION) {
        maxDuration = INT32_MAX;
        MEDIA_INFO_LOG("MuxerFilter MaxDuration set to INT32_MAX");
    }
    maxDuration_ = maxDuration;
}

void MuxerFilter::SetUserMetaAllSet(bool isUserMetaAllSet) {
    isUserMetaAllSet_ = isUserMetaAllSet;
}

void MuxerFilter::NotifyWaitForUserMeta()
{
    MEDIA_INFO_LOG("MuxerFilter::NotifyWaitForUserMeta is called");
    std::unique_lock<std::mutex> lock(userMetaMutex_);
    userMetaCondition_.notify_one();
}

void MuxerFilter::WaitForUserMetaToStop()
{
    MEDIA_INFO_LOG("MuxerFilter::WaitForUserMetaSet is called");
    auto thisWptr = weak_from_this();
    std::thread asyncThread([thisWptr]() {
        auto thisPtr = thisWptr.lock();
        if (thisPtr != nullptr && !thisPtr->isUserMetaAllSet_) {
            std::unique_lock<std::mutex> lock(thisPtr->userMetaMutex_);
            std::cv_status waitStatus =
                thisPtr->userMetaCondition_.wait_for(lock, std::chrono::milliseconds(STOP_TIME_OUT_MS));
            // Waiting timeout with no video frame received
            CHECK_PRINT_ELOG(waitStatus == std::cv_status::timeout,
                "%{public}s wait timeout with no user meta received", thisPtr->name_.c_str());
        }
        MEDIA_INFO_LOG("MuxerFilter::WaitForUserMetaToStop waiting end");
        CHECK_RETURN_ELOG(thisPtr == nullptr || thisPtr->mediaMuxer_ == nullptr, "mediaMuxer_ is null");
        MEDIA_DEBUG_LOG("MuxerFilter::WaitForUserMetaToStop Stop muxer and execute OnEvent callback");
        Status ret = thisPtr->mediaMuxer_->Stop();
        if (ret == Status::OK) {
            thisPtr->isStarted = false;
        } else if (ret == Status::ERROR_WRONG_STATE) {
            ret = Status::OK;
        } else {
            thisPtr->SetFaultEvent("MuxerFilter::DoStop error", static_cast<int32_t>(ret));
        }
        thisPtr->eventReceiver_->OnEvent({"raw_muxer_filter", FilterEventType::EVENT_COMPLETE, Status::OK});
    });
    asyncThread.detach();
}

void MuxerFilter::GetMuxerFirstFrameTimestamp(int64_t& timestamp)
{
    std::lock_guard<std::mutex> lock(firstTsMutex_);
    timestamp = firstFrameTimestamp_;
}

void MuxerFilter::SetMuxerFirstFrameTimestamp(int64_t timestamp)
{
    std::lock_guard<std::mutex> lock(firstTsMutex_);
    if (firstFrameTimestamp_ == -1) {
        firstFrameTimestamp_ = timestamp;
        MEDIA_INFO_LOG("first frame ts set to %{public}" PRId64, firstFrameTimestamp_);
    }
}
} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP