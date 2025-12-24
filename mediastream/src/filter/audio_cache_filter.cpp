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

#include "audio_cache_filter.h"
#include <ctime>
#include <sys/time.h>
#include "avbuffer_common.h"
#include "avbuffer_queue_define.h"
#include "blocking_queue.h"
#include "meta_key.h"
#include "video_buffer_wrapper.h"
#include "sync_fence.h"
#include "camera_log.h"
#include "moving_photo_engine_context.h"
#include "cfilter.h"
#include "cfilter_factory.h"

// LCOV_EXCL_START
namespace OHOS {
namespace CameraStandard {

static AutoRegisterCFilter<AudioCacheFilter> g_registerAudioCacheFilter("camera.audio_cache",
    CFilterType::MOVING_PHOTO_AUDIO_CACHE,
    [](const std::string& name, const CFilterType type) {
        return std::make_shared<AudioCacheFilter>(name, CFilterType::MOVING_PHOTO_AUDIO_CACHE);
    });


class AudioCacheFilterLinkCallback : public CFilterLinkCallback {
public:
    explicit AudioCacheFilterLinkCallback(std::shared_ptr<AudioCacheFilter> audioCacheFilter)
        : audioCacheFilter_(std::move(audioCacheFilter))
    {
    }

    ~AudioCacheFilterLinkCallback() = default;

    void OnLinkedResult(const sptr<AVBufferQueueProducer> &queue, std::shared_ptr<Meta> &meta) override
    {
        if (auto audioCacheFilter = audioCacheFilter_.lock()) {
            audioCacheFilter->OnLinkedResult(queue, meta);
        } else {
            MEDIA_INFO_LOG("invalid audioCacheFilter");
        }
    }

    void OnUnlinkedResult(std::shared_ptr<Meta> &meta) override
    {
        if (auto audioCacheFilter = audioCacheFilter_.lock()) {
            audioCacheFilter->OnUnlinkedResult(meta);
        } else {
            MEDIA_INFO_LOG("invalid audioCacheFilter");
        }
    }

    void OnUpdatedResult(std::shared_ptr<Meta> &meta) override
    {
        if (auto audioCacheFilter = audioCacheFilter_.lock()) {
            audioCacheFilter->OnUpdatedResult(meta);
        } else {
            MEDIA_INFO_LOG("invalid audioCacheFilter");
        }
    }
private:
    std::weak_ptr<AudioCacheFilter> audioCacheFilter_;
};

AudioCacheFilter::AudioCacheFilter(std::string name, CFilterType type) : CFilter(name, type)
{
    MEDIA_INFO_LOG("AudioCacheFilter::AudioCacheFilter called");
}

AudioCacheFilter::~AudioCacheFilter()
{
    MEDIA_INFO_LOG("AudioCacheFilter::~AudioCacheFilter called");
}

Status AudioCacheFilter::SetCodecFormat(const std::shared_ptr<Meta> &format)
{
    MEDIA_INFO_LOG("SetCodecFormat");
    return Status::OK;
}

void AudioCacheFilter::Init(const std::shared_ptr<CEventReceiver> &receiver,
    const std::shared_ptr<CFilterCallback> &callback)
{
    MEDIA_INFO_LOG("AudioCacheFilter::Init E");
    eventReceiver_ = receiver;
    filterCallback_ = callback;
    audioCapturerInner_ = new AudioCapturerSessionAdapter();
}

Status AudioCacheFilter::Configure(const std::shared_ptr<Meta> &parameter)
{
    MEDIA_INFO_LOG("Configure");
    configureParameter_ = parameter;
    return Status::OK;
}

Status AudioCacheFilter::DoPrepare()
{
    MEDIA_INFO_LOG("AudioCacheFilter::DoPrepare E");
    filterCallback_->OnCallback(
        shared_from_this(), CFilterCallBackCommand::NEXT_FILTER_NEEDED, CStreamType::RAW_AUDIO);
    return Status::OK;
}

Status AudioCacheFilter::DoStart()
{
    MEDIA_INFO_LOG("AudioCacheFilter::DoStart E");
    isStop_ = false;
    audioCapturerInner_->Start();
    return Status::OK;
}

Status AudioCacheFilter::DoPause()
{
    MEDIA_INFO_LOG("Pause");
    isStop_ = true;
    latestPausedTime_ = latestBufferTime_;
    return Status::OK;
}

Status AudioCacheFilter::DoResume()
{
    MEDIA_INFO_LOG("Resume");
    isStop_ = false;
    refreshTotalPauseTime_ = true;
    return Status::OK;
}

Status AudioCacheFilter::DoStop()
{
    MEDIA_INFO_LOG("AudioCacheFilter::Stop");
    isStop_ = true;
    latestBufferTime_ = -1;
    latestPausedTime_ = -1;
    totalPausedTime_ = 0;
    refreshTotalPauseTime_ = false;
    audioCapturerInner_->Stop();
    return Status::OK;
}

Status AudioCacheFilter::DoFlush()
{
    MEDIA_INFO_LOG("Flush");
    return Status::OK;
}

Status AudioCacheFilter::DoRelease()
{
    MEDIA_INFO_LOG("Release");
    return Status::OK;
}

Status AudioCacheFilter::NotifyEos()
{
    MEDIA_INFO_LOG("NotifyEos");
    return Status::OK;
}

void AudioCacheFilter::SetParameter(const std::shared_ptr<Meta> &parameter)
{
    MEDIA_INFO_LOG("SetParameter");
}

void AudioCacheFilter::GetParameter(std::shared_ptr<Meta> &parameter)
{
    MEDIA_INFO_LOG("GetParameter");
}

Status AudioCacheFilter::LinkNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("AudioCacheFilter::LinkNext filterType:%{public}d", (int32_t)nextFilter->GetCFilterType());
    nextFilter_ = nextFilter;
    nextCFiltersMap_[outType].push_back(nextFilter_);
    auto filterLinkCallback = std::make_shared<AudioCacheFilterLinkCallback>(shared_from_this());
    nextFilter->OnLinked(outType, configureParameter_, filterLinkCallback);
    return Status::OK;
}

Status AudioCacheFilter::UpdateNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("UpdateNext");
    return Status::OK;
}

Status AudioCacheFilter::UnLinkNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("UnLinkNext");
    return Status::OK;
}

CFilterType AudioCacheFilter::GetFilterType()
{
    MEDIA_INFO_LOG("GetFilterType");
    return filterType_;
}

Status AudioCacheFilter::OnLinked(CStreamType inType, const std::shared_ptr<Meta> &meta,
    const std::shared_ptr<CFilterLinkCallback> &callback)
{
    MEDIA_INFO_LOG("AudioCacheFilter::OnLinked E");
    return Status::OK;
}

Status AudioCacheFilter::OnUpdated(CStreamType inType, const std::shared_ptr<Meta> &meta,
    const std::shared_ptr<CFilterLinkCallback> &callback)
{
    MEDIA_INFO_LOG("OnUpdated");
    return Status::OK;
}

Status AudioCacheFilter::OnUnLinked(CStreamType inType, const std::shared_ptr<CFilterLinkCallback>& callback)
{
    MEDIA_INFO_LOG("OnUnLinked");
    return Status::OK;
}

void AudioCacheFilter::OnLinkedResult(const sptr<AVBufferQueueProducer> &outputBufferQueue,
    std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("AudioCacheFilter::OnLinkedResult E");
    CHECK_RETURN_ELOG(outputBufferQueue == nullptr, "AudioCacheFilter::OnLinkedResult outputBufferQueue is null");
    outputBufferQueueProducer_ = outputBufferQueue;
}

void AudioCacheFilter::OnUpdatedResult(std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("OnUpdatedResult");
}

void AudioCacheFilter::OnUnlinkedResult(std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("OnUnlinkedResult");
}

void AudioCacheFilter::GetAudioRecords(
    int64_t startTime, int64_t endTime, vector<sptr<AudioBufferWrapper>>& processedAudioRecords)
{
    vector<sptr<AudioBufferWrapper>> audioRecords;
    if (audioCapturerInner_ && isNeedDeferredProcess_) {
        audioCapturerInner_->GetAudioBuffersInTimeRange(startTime, endTime, audioRecords);
        for (const auto &ptr: audioRecords) {
            CHECK_CONTINUE(ptr == nullptr);
            processedAudioRecords.emplace_back(new AudioBufferWrapper(ptr->GetTimestamp()));
        }
        std::lock_guard<mutex> lock(deferredProcessMutex_);
        if (audioDeferredProcess_ == nullptr) {
            audioDeferredProcess_ = std::make_shared<AudioDeferredProcessAdapter>();
            CHECK_RETURN(audioDeferredProcess_ == nullptr);
            CHECK_RETURN(audioDeferredProcess_->Init(audioCapturerInner_->deferredInputOptions_,
                             audioCapturerInner_->deferredOutputOptions_) != MEDIA_OK);
        }
        audioDeferredProcess_->Process(audioRecords, processedAudioRecords);
    }
}

void AudioCacheFilter::StartAudio()
{
    CHECK_EXECUTE(audioCapturerInner_, audioCapturerInner_->Start());
}   

void AudioCacheFilter::StopAudio()
{
    CHECK_EXECUTE(audioCapturerInner_, audioCapturerInner_->Stop());
}
} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP