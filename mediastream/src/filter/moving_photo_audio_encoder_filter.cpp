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

#include "moving_photo_audio_encoder_filter.h"

#include "common/audio_record.h"
#include "camera_log.h"
#include "cfilter_factory.h"

#include "media_core.h"
#include "status.h"

// LCOV_EXCL_START
namespace OHOS {
namespace CameraStandard {
static AutoRegisterCFilter<MovingPhotoAudioEncoderFilter> g_registerMovingPhotoAudioEncoderFilter(
    "camera.moving_photo_audio_encoder",
    CFilterType::MOVING_PHOTO_AUDIO_ENCODE,
    [](const std::string& name, const CFilterType type) {
        return std::make_shared<MovingPhotoAudioEncoderFilter>(name, CFilterType::MOVING_PHOTO_AUDIO_ENCODE);
    });

class MovingPhotoAudioEncoderFilterLinkCallback : public CFilterLinkCallback {
public:
    explicit MovingPhotoAudioEncoderFilterLinkCallback(std::shared_ptr<MovingPhotoAudioEncoderFilter> encoderFilter)
        : movingPhotoAudioEncoderFilter_(std::move(encoderFilter))
    {
    }

    ~MovingPhotoAudioEncoderFilterLinkCallback() = default;

    void OnLinkedResult(const sptr<AVBufferQueueProducer> &queue, std::shared_ptr<Meta> &meta) override
    {
        if (auto encoderFilter = movingPhotoAudioEncoderFilter_.lock()) {
            encoderFilter->OnLinkedResult(queue, meta);
        } else {
            MEDIA_INFO_LOG("invalid encoderFilter");
        }
    }

    void OnUnlinkedResult(std::shared_ptr<Meta> &meta) override
    {
        if (auto encoderFilter = movingPhotoAudioEncoderFilter_.lock()) {
            encoderFilter->OnUnlinkedResult(meta);
        } else {
            MEDIA_INFO_LOG("invalid encoderFilter");
        }
    }

    void OnUpdatedResult(std::shared_ptr<Meta> &meta) override
    {
        if (auto encoderFilter = movingPhotoAudioEncoderFilter_.lock()) {
            encoderFilter->OnUpdatedResult(meta);
        } else {
            MEDIA_INFO_LOG("invalid encoderFilter");
        }
    }
private:
    std::weak_ptr<MovingPhotoAudioEncoderFilter> movingPhotoAudioEncoderFilter_;
};

MovingPhotoAudioEncoderFilter::MovingPhotoAudioEncoderFilter(std::string name, CFilterType type) : CFilter(name, type)
{
    filterType_ = type;
    MEDIA_INFO_LOG("audio encoder filter create");
}

MovingPhotoAudioEncoderFilter::~MovingPhotoAudioEncoderFilter()
{
    MEDIA_INFO_LOG("audio encoder filter destroy");
}

Status MovingPhotoAudioEncoderFilter::SetCodecFormat(const std::shared_ptr<Meta> &format)
{
    MEDIA_INFO_LOG("SetCodecFormat");
    CHECK_RETURN_RET(!format->Get<Tag::MIME_TYPE>(codecMimeType_), Status::ERROR_INVALID_PARAMETER);
    return Status::OK;
}

void MovingPhotoAudioEncoderFilter::Init(const std::shared_ptr<CEventReceiver> &receiver,
    const std::shared_ptr<CFilterCallback> &callback)
{
    MEDIA_INFO_LOG("MovingPhotoAudioEncoderFilter::Init E");
    eventReceiver_ = receiver;
    filterCallback_ = callback;
    mediaCodec_ = std::make_shared<MediaCodec>();

    CHECK_RETURN_ELOG(mediaCodec_ == nullptr, "mediaCodec is nullptr");
    int32_t ret = mediaCodec_->Init(codecMimeType_, true);
    if (ret != 0 && isTranscoderMode_) {
        MEDIA_INFO_LOG("TranscoderMode");
        CHECK_RETURN(eventReceiver_ != nullptr);
        eventReceiver_->OnEvent(
            {"moving_photo_audio_encoder_filter", FilterEventType::EVENT_ERROR, MSERR_UNSUPPORT_AUD_ENC_TYPE});
    }
}

Status MovingPhotoAudioEncoderFilter::Configure(const std::shared_ptr<Meta> &parameter)
{
    MEDIA_INFO_LOG("Configure");
    configureParameter_ = parameter;
    CHECK_RETURN_RET(mediaCodec_ == nullptr, Status::ERROR_NULL_POINTER);
    int32_t ret = mediaCodec_->Configure(parameter);
    if (ret != 0) {
        SetFaultEvent("MovingPhotoAudioEncoderFilter::Configure error", ret);
        return Status::ERROR_UNKNOWN;
    }
    return Status::OK;
}

sptr<Surface> MovingPhotoAudioEncoderFilter::GetInputSurface()
{
    CHECK_RETURN_RET(mediaCodec_ == nullptr, nullptr);
    MEDIA_INFO_LOG("GetInputSurface");
    return mediaCodec_->GetInputSurface();
}

Status MovingPhotoAudioEncoderFilter::DoPrepare()
{
    MEDIA_INFO_LOG("MovingPhotoAudioEncoderFilter::DoPrepare E");
    CHECK_RETURN_RET(filterCallback_ == nullptr, Status::ERROR_NULL_POINTER);
    filterCallback_->OnCallback(
        shared_from_this(), CFilterCallBackCommand::NEXT_FILTER_NEEDED, CStreamType::ENCODED_AUDIO);
    return Status::OK;
}

Status MovingPhotoAudioEncoderFilter::DoStart()
{
    MEDIA_INFO_LOG("MovingPhotoAudioEncoderFilter::DoStart E");
    CHECK_RETURN_RET(mediaCodec_ == nullptr, Status::ERROR_NULL_POINTER);
    int32_t ret = mediaCodec_->Start();
    if (ret != 0) {
        SetFaultEvent("MovingPhotoAudioEncoderFilter::DoStart error", ret);
        return Status::ERROR_UNKNOWN;
    }
    return Status::OK;
}

Status MovingPhotoAudioEncoderFilter::DoPause()
{
    MEDIA_INFO_LOG("Pause");
    return Status::OK;
}

Status MovingPhotoAudioEncoderFilter::DoResume()
{
    MEDIA_INFO_LOG("Resume");
    return Status::OK;
}

Status MovingPhotoAudioEncoderFilter::DoStop()
{
    CHECK_RETURN_RET(mediaCodec_ == nullptr, Status::ERROR_NULL_POINTER);
    MEDIA_INFO_LOG("MovingPhotoAudioEncoderFilter::DoStop E");
    int32_t ret = mediaCodec_->Stop();
    if (ret != 0) {
        SetFaultEvent("MovingPhotoAudioEncoderFilter::DoStop error", ret);
        return Status::ERROR_UNKNOWN;
    }
    return Status::OK;
}

Status MovingPhotoAudioEncoderFilter::DoFlush()
{
    CHECK_RETURN_RET(mediaCodec_ == nullptr, Status::ERROR_NULL_POINTER);
    MEDIA_INFO_LOG("Flush");
    int32_t ret = mediaCodec_->Flush();
    if (ret != 0) {
        SetFaultEvent("MovingPhotoAudioEncoderFilter::DoFlush error", ret);
        return Status::ERROR_UNKNOWN;
    }
    return Status::OK;
}

Status MovingPhotoAudioEncoderFilter::DoRelease()
{
    CHECK_RETURN_RET(mediaCodec_ == nullptr, Status::ERROR_NULL_POINTER);
    MEDIA_INFO_LOG("MovingPhotoAudioEncoderFilter::Release");
    int32_t ret = mediaCodec_->Release();
    if (ret != 0) {
        SetFaultEvent("MovingPhotoAudioEncoderFilter::DoRelease error", ret);
        return Status::ERROR_UNKNOWN;
    }
    return Status::OK;
}

Status MovingPhotoAudioEncoderFilter::NotifyEos()
{
    CHECK_RETURN_RET(mediaCodec_ == nullptr, Status::ERROR_NULL_POINTER);
    MEDIA_INFO_LOG("NotifyEos");
    int32_t ret = mediaCodec_->NotifyEos();
    if (ret != 0) {
        SetFaultEvent("MovingPhotoAudioEncoderFilter::NotifyEos error", ret);
        return Status::ERROR_UNKNOWN;
    }
    return Status::OK;
}

Status MovingPhotoAudioEncoderFilter::SetTranscoderMode()
{
    MEDIA_INFO_LOG("SetTranscoderMode");
    isTranscoderMode_ = true;
    return Status::OK;
}

void MovingPhotoAudioEncoderFilter::SetParameter(const std::shared_ptr<Meta> &parameter)
{
    CHECK_RETURN_ELOG(mediaCodec_ == nullptr, "mediaCodec is nullptr");
    MEDIA_INFO_LOG("SetParameter");
    mediaCodec_->SetParameter(parameter);
}

void MovingPhotoAudioEncoderFilter::GetParameter(std::shared_ptr<Meta> &parameter)
{
    MEDIA_INFO_LOG("GetParameter");
}

Status MovingPhotoAudioEncoderFilter::LinkNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("MovingPhotoAudioEncoderFilter::LinkNext filterType:%{public}d",
        (int32_t)nextFilter->GetCFilterType());
    nextFilter_ = nextFilter;
    nextCFiltersMap_[outType].push_back(nextFilter_);
    std::shared_ptr<CFilterLinkCallback> filterLinkCallback =
        std::make_shared<MovingPhotoAudioEncoderFilterLinkCallback>(shared_from_this());
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
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "OnLinked failed");
    return Status::OK;
}

Status MovingPhotoAudioEncoderFilter::UpdateNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("UpdateNext");
    return Status::OK;
}

Status MovingPhotoAudioEncoderFilter::UnLinkNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("UnLinkNext");
    return Status::OK;
}

CFilterType MovingPhotoAudioEncoderFilter::GetFilterType()
{
    MEDIA_INFO_LOG("GetFilterType");
    return filterType_;
}

Status MovingPhotoAudioEncoderFilter::OnLinked(CStreamType inType, const std::shared_ptr<Meta> &meta,
    const std::shared_ptr<CFilterLinkCallback> &callback)
{
    MEDIA_INFO_LOG("MovingPhotoAudioEncoderFilter::OnLinked E");
    onLinkedResultCallback_ = callback;
    if (isTranscoderMode_) {
        transcoderMeta_ = meta;
    }
    return Status::OK;
}

Status MovingPhotoAudioEncoderFilter::OnUpdated(CStreamType inType, const std::shared_ptr<Meta> &meta,
    const std::shared_ptr<CFilterLinkCallback> &callback)
{
    MEDIA_INFO_LOG("OnUpdated");
    return Status::OK;
}

Status MovingPhotoAudioEncoderFilter::OnUnLinked(
    CStreamType inType, const std::shared_ptr<CFilterLinkCallback>& callback)
{
    MEDIA_INFO_LOG("OnUnLinked");
    return Status::OK;
}

class AudioEncoderConsumerListener : public IConsumerListener {
public:
    explicit AudioEncoderConsumerListener(std::shared_ptr<MovingPhotoAudioEncoderFilter> movingPhotoAudioEncoderFilter)
        : movingPhotoAudioEncoderFilter_(std::move(movingPhotoAudioEncoderFilter))
    {
    }

    ~AudioEncoderConsumerListener() = default;

    void OnBufferAvailable() override
    {
        if (auto encoderFilter = movingPhotoAudioEncoderFilter_.lock()) {
            encoderFilter->OnBufferAvailable();
        } else {
            MEDIA_INFO_LOG("invalid encoderFilter");
        }
    }
private:
    std::weak_ptr<MovingPhotoAudioEncoderFilter> movingPhotoAudioEncoderFilter_;
};

void MovingPhotoAudioEncoderFilter::OnBufferAvailable()
{
    std::shared_ptr<AVBuffer> buffer;
    consumer_->AcquireBuffer(buffer);
    CHECK_RETURN_ELOG(buffer == nullptr, "buffer is nullptr");
    MEDIA_DEBUG_LOG("MovingPhotoAudioEncoderFilter::OnBufferAvailable E %{public} " PRId64, buffer->pts_);
    CHECK_RETURN_ELOG(avbufferContext_ == nullptr, "avbufferContext_ is nullptr");
    std::unique_lock<std::mutex> lock(avbufferContext_->outputMutex_);
    avbufferContext_->outputBufferInfoQueue_.emplace(new AVBufferInfo(0, buffer));
    avbufferContext_->outputCond_.notify_all();
}

void MovingPhotoAudioEncoderFilter::OnLinkedResult(const sptr<AVBufferQueueProducer> &outputBufferQueue,
    std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("MovingPhotoAudioEncoderFilter::OnLinkedResult E");
    CHECK_RETURN_ELOG(mediaCodec_ == nullptr, "mediaCodec is nullptr");
    auto prevFilterCallback = onLinkedResultCallback_;
    CHECK_RETURN_ELOG(prevFilterCallback == nullptr, "onLinkedResultCallback is nullptr");

    std::string mimeType = {};
    meta->Get<Tag::MIME_TYPE>(mimeType);
    bufferQ_ = AVBufferQueue::Create(10, MemoryType::UNKNOWN_MEMORY, mimeType);
    sptr<AVBufferQueueProducer> producer = bufferQ_->GetProducer();
    sptr<AVBufferQueueConsumer> consumer = bufferQ_->GetConsumer();
    sptr<IConsumerListener> listener = new AudioEncoderConsumerListener(shared_from_this());
    CHECK_RETURN_ELOG(consumer == nullptr, "consumer is nullptr");
    consumer->SetBufferAvailableListener(listener);
    SetOutputBufferQueue(producer);
    mediaCodec_->Prepare();
    producer_ = GetInputBufferQueue();
    consumer_ = consumer;
    prevFilterCallback->OnLinkedResult(producer_, meta);
}

sptr<AVBufferQueueProducer> MovingPhotoAudioEncoderFilter::GetInputBufferQueue()
{
    CHECK_RETURN_RET_ELOG(mediaCodec_ == nullptr, nullptr, "mediaCodec is nullptr");
    return mediaCodec_->GetInputBufferQueue();
}

void MovingPhotoAudioEncoderFilter::SetOutputBufferQueue(const sptr<AVBufferQueueProducer> &outputBufferQueue)
{
    CHECK_RETURN_ELOG(mediaCodec_ == nullptr, "mediaCodec is nullptr");
    mediaCodec_->SetOutputBufferQueue(outputBufferQueue);
}

void MovingPhotoAudioEncoderFilter::OnUpdatedResult(std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("OnUpdatedResult");
    (void) meta;
}

void MovingPhotoAudioEncoderFilter::OnUnlinkedResult(std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("OnUnlinkedResult");
    (void) meta;
}

void MovingPhotoAudioEncoderFilter::SetFaultEvent(const std::string &errMsg, int32_t ret)
{
    SetFaultEvent(errMsg + ", ret = " + std::to_string(ret));
}

void MovingPhotoAudioEncoderFilter::SetFaultEvent(const std::string &errMsg)
{
    MEDIA_ERR_LOG("%{public}s MovingPhotoAudioEncoderFilter::SetFaultEvent is called", errMsg.c_str());
}

void MovingPhotoAudioEncoderFilter::SetCallingInfo(int32_t appUid, int32_t appPid,
    const std::string &bundleName, uint64_t instanceId)
{
    appUid_ = appUid;
    appPid_ = appPid;
    bundleName_ = bundleName;
    instanceId_ = instanceId;
}

bool MovingPhotoAudioEncoderFilter::EncodeAudioRecord(std::vector<sptr<AudioBufferWrapper>>& audioRecords)
{
    MEDIA_INFO_LOG("MovingPhotoAudioEncoderFilter::EncodeAudioRecord ALL E");
    std::lock_guard<std::mutex> lock(serialMutex_);
    bool isSuccess = true;
    for (sptr<AudioBufferWrapper> audioRecord : audioRecords) {
        if (!audioRecord->IsEncoded() && !EncodeAudioRecord(audioRecord)) {
            isSuccess = false;
            MEDIA_ERR_LOG("Failed audio buffer timestamp : %{public}" PRId64, audioRecord->GetTimestamp());
        }
    }
    return isSuccess;
}

bool MovingPhotoAudioEncoderFilter::EnqueueBuffer(sptr<AudioBufferWrapper> audioRecord)
{
    CHECK_RETURN_RET_ELOG(audioRecord == nullptr, false, "audioRecord is null");
    auto producer = producer_;
    CHECK_RETURN_RET_ELOG(producer == nullptr, false, "producer is null");
    std::shared_ptr<AVBuffer> buffer;
    AVBufferConfig avBufferConfig;
    avBufferConfig.size = static_cast<int32_t>(audioRecord->GetBufferSize());
    avBufferConfig.memoryFlag = MemoryFlag::MEMORY_READ_WRITE;
    
    Status ret = producer->RequestBuffer(buffer, avBufferConfig, 0);
    CHECK_RETURN_RET_ELOG(ret != Status::OK, false, "RequestBuffer failed ret:%{public}d", ret);
    uint32_t buffSize = audioRecord->GetBufferSize();
    uint8_t* rawAudio = audioRecord->GetAudioBuffer();
    CHECK_RETURN_RET_ELOG(
        buffer->memory_ == nullptr, false, "MovingPhotoAudioEncoderFilter::EnqueueBuffer buffer->memory_ is nullptr");
    auto destAddr = buffer->memory_->GetAddr();
    CHECK_RETURN_RET_ELOG(buffer->memory_->GetSize() < static_cast<int32_t>(buffSize), false,
        "Destination buffer capacity is insufficient to hold the data.");
    errno_t cpyRet = memcpy_s(reinterpret_cast<void *>(destAddr), buffSize,
        reinterpret_cast<void *>(rawAudio), buffSize);
    buffer->memory_->SetSize(audioRecord->GetBufferSize());

    buffer->pts_ = audioRecord->GetTimestamp();
    buffer->flag_ = AVCODEC_BUFFER_FLAGS_NONE;

    CHECK_PRINT_ELOG(0 != cpyRet, "EnqueueBuffer memcpy_s failed. %{public}d", cpyRet);
    ret = producer->PushBuffer(buffer, true);
    CHECK_RETURN_RET_ELOG(ret != Status::OK, false, "PushBuffer failed");
    return true;
}

bool MovingPhotoAudioEncoderFilter::EncodeAudioRecord(sptr<AudioBufferWrapper> bufferWrapper)
{
    MEDIA_DEBUG_LOG("MovingPhotoAudioEncoderFilter::EncodeAudioRecord E");
    CHECK_RETURN_RET_ELOG(bufferWrapper == nullptr, false, "audioRecord is null");
    MEDIA_DEBUG_LOG("MovingPhotoAudioEncoderFilter::EncodeAudioRecord E %{public}" PRId64 " size:%{public}u",
        bufferWrapper->GetTimestamp(), bufferWrapper->GetBufferSize());
    bufferWrapper->SetReadyConvert();
    CHECK_RETURN_RET_ELOG(!EnqueueBuffer(bufferWrapper), false, "EnqueueBuffer failed");
    int retryCount = 2;
    while (retryCount > 0) {
        retryCount--;
        CHECK_RETURN_RET_ELOG(avbufferContext_ == nullptr, false, "avbufferContext is nullptr");
        std::unique_lock<std::mutex> lock(avbufferContext_->outputMutex_);

        bool condRet = avbufferContext_->outputCond_.wait_for(lock, std::chrono::milliseconds(10),
            [this]() { return !this->avbufferContext_->outputBufferInfoQueue_.empty(); });

        CHECK_CONTINUE_DLOG(avbufferContext_->outputBufferInfoQueue_.empty(),
            "Buffer queue is empty, continue, cond ret: %{public}d", condRet);

        sptr<AVBufferInfo> bufferInfo = avbufferContext_->outputBufferInfoQueue_.front();
        CHECK_RETURN_RET_ELOG(bufferInfo->avBuffer_->memory_ == nullptr, false, "memory is alloced failed!");
        avbufferContext_->outputBufferInfoQueue_.pop();
        avbufferContext_->outputFrameCount_++;
        lock.unlock();
        
        std::shared_ptr<Media::AVBuffer> encodedBuffer = bufferInfo->GetCopyAVBuffer();
        bufferWrapper->SetEncodedBuffer(encodedBuffer);
        bufferWrapper->SetStatusFinishEncodeStatus();
        consumer_->ReleaseBuffer(bufferInfo->avBuffer_);

        MEDIA_DEBUG_LOG("Success audio buffer timestamp is : %{public}" PRId64, bufferWrapper->GetTimestamp());
        bufferWrapper->SetEncodeResult(true);
        return true;
    }
    MEDIA_ERR_LOG("Failed audio buffer timestamp is : %{public}" PRId64, bufferWrapper->GetTimestamp());
    return false;
}
} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP