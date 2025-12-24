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

#include "audio_encoder_filter.h"

#include "camera_log.h"
#include "cfilter_factory.h"

#include "media_core.h"

// LCOV_EXCL_START
namespace OHOS {
namespace CameraStandard {
static AutoRegisterCFilter<AudioEncoderFilter> g_registerAudioEncoderFilter("camera.audioencoder",
    CFilterType::AUDIO_ENC,
    [](const std::string& name, const CFilterType type) {
        return std::make_shared<AudioEncoderFilter>(name, CFilterType::AUDIO_ENC);
    });

class AudioEncoderFilterLinkCallback : public CFilterLinkCallback {
public:
    explicit AudioEncoderFilterLinkCallback(std::shared_ptr<AudioEncoderFilter> audioEncoderFilter)
        : audioEncoderFilter_(std::move(audioEncoderFilter))
    {
    }

    ~AudioEncoderFilterLinkCallback() = default;

    void OnLinkedResult(const sptr<AVBufferQueueProducer> &queue, std::shared_ptr<Meta> &meta) override
    {
        if (auto encoderFilter = audioEncoderFilter_.lock()) {
            encoderFilter->OnLinkedResult(queue, meta);
        } else {
            MEDIA_INFO_LOG("invalid encoderFilter");
        }
    }

    void OnUnlinkedResult(std::shared_ptr<Meta> &meta) override
    {
        if (auto encoderFilter = audioEncoderFilter_.lock()) {
            encoderFilter->OnUnlinkedResult(meta);
        } else {
            MEDIA_INFO_LOG("invalid encoderFilter");
        }
    }

    void OnUpdatedResult(std::shared_ptr<Meta> &meta) override
    {
        if (auto encoderFilter = audioEncoderFilter_.lock()) {
            encoderFilter->OnUpdatedResult(meta);
        } else {
            MEDIA_INFO_LOG("invalid encoderFilter");
        }
    }
private:
    std::weak_ptr<AudioEncoderFilter> audioEncoderFilter_;
};

AudioEncoderFilter::AudioEncoderFilter(std::string name, CFilterType type) : CFilter(name, type)
{
    filterType_ = type;
    name_ = name;
    MEDIA_INFO_LOG("audio encoder filter create");
}

AudioEncoderFilter::~AudioEncoderFilter()
{
    MEDIA_INFO_LOG("audio encoder filter destroy");
}

Status AudioEncoderFilter::SetCodecFormat(const std::shared_ptr<Meta> &format)
{
    MEDIA_INFO_LOG("SetCodecFormat");
    CHECK_RETURN_RET(!format->Get<Tag::MIME_TYPE>(codecMimeType_), Status::ERROR_INVALID_PARAMETER);
    return Status::OK;
}

void AudioEncoderFilter::Init(const std::shared_ptr<CEventReceiver> &receiver,
    const std::shared_ptr<CFilterCallback> &callback)
{
    MEDIA_INFO_LOG("Init");
    eventReceiver_ = receiver;
    filterCallback_ = callback;
    mediaCodec_ = std::make_shared<MediaCodec>();

    CHECK_RETURN_ELOG(mediaCodec_ == nullptr, "mediaCodec is nullptr");
    int32_t ret = mediaCodec_->Init(codecMimeType_, true);
    if (ret != 0 && isTranscoderMode_) {
        MEDIA_INFO_LOG("TranscoderMode");
        CHECK_RETURN(eventReceiver_ == nullptr);
        eventReceiver_->OnEvent({"audio_encoder_filter", FilterEventType::EVENT_ERROR, MSERR_UNSUPPORT_AUD_ENC_TYPE});
    }
}

Status AudioEncoderFilter::Configure(const std::shared_ptr<Meta> &parameter)
{
    MEDIA_INFO_LOG("Configure");
    configureParameter_ = parameter;
    CHECK_RETURN_RET(mediaCodec_ == nullptr, Status::ERROR_NULL_POINTER);
    int32_t ret = mediaCodec_->Configure(parameter);
    if (ret != 0) {
        SetFaultEvent("AudioEncoderFilter::Configure error", ret);
        return Status::ERROR_UNKNOWN;
    }
    return Status::OK;
}

sptr<Surface> AudioEncoderFilter::GetInputSurface()
{
    CHECK_RETURN_RET(mediaCodec_ == nullptr, nullptr);
    MEDIA_INFO_LOG("GetInputSurface");
    return mediaCodec_->GetInputSurface();
}

Status AudioEncoderFilter::DoPrepare()
{
    CHECK_RETURN_RET(filterCallback_ == nullptr, Status::ERROR_NULL_POINTER);
    MEDIA_INFO_LOG("Prepare");
    switch (filterType_) {
        case CFilterType::AUDIO_ENC:
            if (isTranscoderMode_) {
                MEDIA_INFO_LOG("TranscoderMode");
                return filterCallback_->OnCallback(shared_from_this(), CFilterCallBackCommand::NEXT_FILTER_NEEDED,
                    CStreamType::ENCODED_AUDIO);
            }
            filterCallback_->OnCallback(shared_from_this(), CFilterCallBackCommand::NEXT_FILTER_NEEDED,
                CStreamType::ENCODED_AUDIO);
            break;
        default:
            break;
    }
    return Status::OK;
}

Status AudioEncoderFilter::DoStart()
{
    CHECK_RETURN_RET(mediaCodec_ == nullptr, Status::ERROR_NULL_POINTER);
    MEDIA_INFO_LOG("Start");
    int32_t ret = mediaCodec_->Start();
    if (ret != 0) {
        SetFaultEvent("AudioEncoderFilter::DoStart error", ret);
        return Status::ERROR_UNKNOWN;
    }
    return Status::OK;
}

Status AudioEncoderFilter::DoPause()
{
    MEDIA_INFO_LOG("Pause");
    return Status::OK;
}

Status AudioEncoderFilter::DoResume()
{
    MEDIA_INFO_LOG("Resume");
    return Status::OK;
}

Status AudioEncoderFilter::DoStop()
{
    CHECK_RETURN_RET(mediaCodec_ == nullptr, Status::ERROR_NULL_POINTER);
    MEDIA_INFO_LOG("Stop");
    int32_t ret = mediaCodec_->Stop();
    if (ret != 0) {
        SetFaultEvent("AudioEncoderFilter::DoStop error", ret);
        return Status::ERROR_UNKNOWN;
    }
    return Status::OK;
}

Status AudioEncoderFilter::DoFlush()
{
    CHECK_RETURN_RET(mediaCodec_ == nullptr, Status::ERROR_NULL_POINTER);
    MEDIA_INFO_LOG("Flush");
    int32_t ret = mediaCodec_->Flush();
    if (ret != 0) {
        SetFaultEvent("AudioEncoderFilter::DoFlush error", ret);
        return Status::ERROR_UNKNOWN;
    }
    return Status::OK;
}

Status AudioEncoderFilter::DoRelease()
{
    CHECK_RETURN_RET(mediaCodec_ == nullptr, Status::ERROR_NULL_POINTER);
    MEDIA_INFO_LOG("Release");
    int32_t ret = mediaCodec_->Release();
    if (ret != 0) {
        SetFaultEvent("AudioEncoderFilter::DoRelease error", ret);
        return Status::ERROR_UNKNOWN;
    }
    return Status::OK;
}

Status AudioEncoderFilter::NotifyEos()
{
    CHECK_RETURN_RET(mediaCodec_ == nullptr, Status::ERROR_NULL_POINTER);
    MEDIA_INFO_LOG("NotifyEos");
    int32_t ret = mediaCodec_->NotifyEos();
    if (ret != 0) {
        SetFaultEvent("AudioEncoderFilter::NotifyEos error", ret);
        return Status::ERROR_UNKNOWN;
    }
    return Status::OK;
}

Status AudioEncoderFilter::SetTranscoderMode()
{
    MEDIA_INFO_LOG("SetTranscoderMode");
    isTranscoderMode_ = true;
    return Status::OK;
}

void AudioEncoderFilter::SetParameter(const std::shared_ptr<Meta> &parameter)
{
    CHECK_RETURN_ELOG(mediaCodec_ == nullptr, "mediaCodec is nullptr");
    MEDIA_INFO_LOG("SetParameter");
    mediaCodec_->SetParameter(parameter);
}

void AudioEncoderFilter::GetParameter(std::shared_ptr<Meta> &parameter)
{
    MEDIA_INFO_LOG("GetParameter");
}

Status AudioEncoderFilter::LinkNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("LinkNext");
    nextFilter_ = nextFilter;
    nextCFiltersMap_[outType].push_back(nextFilter_);
    std::shared_ptr<CFilterLinkCallback> filterLinkCallback =
        std::make_shared<AudioEncoderFilterLinkCallback>(shared_from_this());
    if (mediaCodec_) {
        std::shared_ptr<Meta> parameter = std::make_shared<Meta>();
        mediaCodec_->GetOutputFormat(parameter);
        int32_t frameSize = 0;
        if (parameter->Find(Tag::AUDIO_SAMPLE_PER_FRAME) != parameter->end() &&
            parameter->Get<Tag::AUDIO_SAMPLE_PER_FRAME>(frameSize)) {
            configureParameter_->Set<Tag::AUDIO_SAMPLE_PER_FRAME>(frameSize);
        }
    }
    auto ret = nextFilter->OnLinked(outType, configureParameter_, filterLinkCallback);
    if (ret != Status::OK) {
        SetFaultEvent("AudioEncoderFilter::LinkNext error", (int32_t)ret);
    }
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "OnLinked failed");
    return Status::OK;
}

Status AudioEncoderFilter::UpdateNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("UpdateNext");
    return Status::OK;
}

Status AudioEncoderFilter::UnLinkNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("UnLinkNext");
    return Status::OK;
}

CFilterType AudioEncoderFilter::GetFilterType()
{
    MEDIA_INFO_LOG("GetFilterType");
    return filterType_;
}

Status AudioEncoderFilter::OnLinked(CStreamType inType, const std::shared_ptr<Meta> &meta,
    const std::shared_ptr<CFilterLinkCallback> &callback)
{
    MEDIA_INFO_LOG("OnLinked");
    onLinkedResultCallback_ = callback;
    if (isTranscoderMode_) {
        transcoderMeta_ = meta;
    }
    return Status::OK;
}

Status AudioEncoderFilter::OnUpdated(CStreamType inType, const std::shared_ptr<Meta> &meta,
    const std::shared_ptr<CFilterLinkCallback> &callback)
{
    MEDIA_INFO_LOG("OnUpdated");
    return Status::OK;
}

Status AudioEncoderFilter::OnUnLinked(CStreamType inType, const std::shared_ptr<CFilterLinkCallback>& callback)
{
    MEDIA_INFO_LOG("OnUnLinked");
    return Status::OK;
}

void AudioEncoderFilter::OnLinkedResult(const sptr<AVBufferQueueProducer> &outputBufferQueue,
    std::shared_ptr<Meta> &meta)
{
    CHECK_RETURN_ELOG(mediaCodec_ == nullptr, "mediaCodec is nullptr");
    CHECK_RETURN_ELOG(onLinkedResultCallback_ == nullptr, "onLinkedResultCallback is nullptr");
    MEDIA_INFO_LOG("AudioEncoderFilter::OnLinkedResult");
    mediaCodec_->SetOutputBufferQueue(outputBufferQueue);
    mediaCodec_->Prepare();
    meta->SetData("audio.encoder.name", name_);
    if (isTranscoderMode_) {
        onLinkedResultCallback_->OnLinkedResult(mediaCodec_->GetInputBufferQueue(), transcoderMeta_);
        return;
    }
    onLinkedResultCallback_->OnLinkedResult(mediaCodec_->GetInputBufferQueue(), meta);
}

void AudioEncoderFilter::OnUpdatedResult(std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("OnUpdatedResult");
    (void) meta;
}

void AudioEncoderFilter::OnUnlinkedResult(std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("OnUnlinkedResult");
    (void) meta;
}

void AudioEncoderFilter::SetFaultEvent(const std::string &errMsg, int32_t ret)
{
    SetFaultEvent(errMsg + ", ret = " + std::to_string(ret));
}

void AudioEncoderFilter::SetFaultEvent(const std::string &errMsg)
{
    MEDIA_INFO_LOG("%{public}s AudioEncoderFilter::SetFaultEvent is called", errMsg.c_str());
}

void AudioEncoderFilter::SetCallingInfo(int32_t appUid, int32_t appPid,
    const std::string &bundleName, uint64_t instanceId)
{
    appUid_ = appUid;
    appPid_ = appPid;
    bundleName_ = bundleName;
    instanceId_ = instanceId;
}
} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP