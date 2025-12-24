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

#include "moving_photo_muxer_filter.h"
#include "avbuffer.h"
#include "meta_key.h"
#include "muxer_filter.h"
#include <memory>
#include <sys/timeb.h>
#include <thread>
#include <unordered_map>
#include "muxer/media_muxer.h"
#include "avcodec_trace.h"
#include "avcodec_sysevent.h"
#include "avcodec_log.h"
#include "camera_log.h"
#include "datetime_ex.h"
#include "status.h"
#include <algorithm>
#include <vector>
#include "moving_photo_engine_context.h"
#include "native_mfmagic.h"
#include "cfilter.h"
#include "cfilter_factory.h"


// LCOV_EXCL_START
namespace {
static const std::unordered_map<OHOS::Media::Plugins::OutputFormat, std::string> FORMAT_TABLE = {
    {OHOS::Media::Plugins::OutputFormat::DEFAULT, OHOS::Media::Plugins::MimeType::MEDIA_MP4},
    {OHOS::Media::Plugins::OutputFormat::MPEG_4, OHOS::Media::Plugins::MimeType::MEDIA_MP4},
    {OHOS::Media::Plugins::OutputFormat::M4A, OHOS::Media::Plugins::MimeType::MEDIA_M4A},
    {OHOS::Media::Plugins::OutputFormat::AMR, OHOS::Media::Plugins::MimeType::MEDIA_AMR},
    {OHOS::Media::Plugins::OutputFormat::MP3, OHOS::Media::Plugins::MimeType::MEDIA_MP3},
    {OHOS::Media::Plugins::OutputFormat::WAV, OHOS::Media::Plugins::MimeType::MEDIA_WAV},
};
}

namespace OHOS {
namespace CameraStandard {

static AutoRegisterCFilter<MovingPhotoMuxerFilter> g_registerMovingPhotoMuxerFilter(
    "builtin.camera.moving_photo_muxer", CFilterType::MOVING_PHOTO_MUXER,
    [](const std::string& name, const CFilterType type) {
        return std::make_shared<MovingPhotoMuxerFilter>(name, CFilterType::MOVING_PHOTO_MUXER);
    });

MovingPhotoMuxerFilter::MovingPhotoMuxerFilter(std::string name, CFilterType type): CFilter(name, type)
{
    MEDIA_INFO_LOG("MovingPhotoMuxerFilter create");
}

MovingPhotoMuxerFilter::~MovingPhotoMuxerFilter()
{
    MEDIA_INFO_LOG("MovingPhotoMuxerFilter destroy");
}

Status MovingPhotoMuxerFilter::SetOutputParameter(int32_t appUid, int32_t appPid, int32_t fd, int32_t format)
{
    MEDIA_INFO_LOG("SetOutputParameter, appUid: %{public}d , appPid:%{public}d, format:%{public}d",
        static_cast<int32_t>(appUid), static_cast<int32_t>(appPid), static_cast<int32_t>(format));
    mediaMuxer_ = std::make_shared<MediaMuxer>(appUid, appPid);
    outputFormat_ = (Plugins::OutputFormat)format;
    appUid_ = appUid;
    appPid_ = appPid;
    return Status::OK;
}

void MovingPhotoMuxerFilter::Init(const std::shared_ptr<CEventReceiver> &receiver,
    const std::shared_ptr<CFilterCallback> &callback)
{
    MEDIA_INFO_LOG("MovingPhotoMuxerFilter::Init E");
    eventReceiver_ = receiver;
    filterCallback_ = callback;
}

Status MovingPhotoMuxerFilter::DoPrepare()
{
    MEDIA_INFO_LOG("MovingPhotoMuxerFilter::DoPrepare E");
    return Status::OK;
}

Status MovingPhotoMuxerFilter::DoStart()
{
    MEDIA_INFO_LOG("MovingPhotoMuxerFilter::DoStart E");
    return Status::OK;
}

Status MovingPhotoMuxerFilter::DoPause()
{
    MEDIA_INFO_LOG("MovingPhotoMuxerFilter::Pause");
    return Status::OK;
}

Status MovingPhotoMuxerFilter::DoResume()
{
    MEDIA_INFO_LOG("MovingPhotoMuxerFilter::Resume");
    return Status::OK;
}

Status MovingPhotoMuxerFilter::DoStop()
{
    MEDIA_INFO_LOG("MovingPhotoMuxerFilter::Stop");
    stopCount_++;
    if (stopCount_ == preFilterCount_) {
        stopCount_ = 0;
        Status ret = mediaMuxer_->Stop();
        if (ret == Status::OK) {
            isStarted = false;
        } else if (ret == Status::ERROR_WRONG_STATE) {
            ret = Status::OK;
        } else {
            MEDIA_ERR_LOG("MovingPhotoMuxerFilter::DoStop error ret %{public}d", (int32_t)ret);
        }
        return ret;
    }
    return Status::OK;
}

Status MovingPhotoMuxerFilter::DoFlush()
{
    return Status::OK;
}

Status MovingPhotoMuxerFilter::DoRelease()
{
    MEDIA_INFO_LOG("Release");
    return Status::OK;
}

void MovingPhotoMuxerFilter::SetParameter(const std::shared_ptr<Meta> &parameter)
{
    MEDIA_INFO_LOG("MovingPhotoMuxerFilter::SetParameter");
    if (parameter) {
        metaInfo_.muxerMeta = std::make_shared<Meta>(*parameter);
    }
}

void MovingPhotoMuxerFilter::GetParameter(std::shared_ptr<Meta> &parameter)
{
    MEDIA_INFO_LOG("MovingPhotoMuxerFilter::GetParameter");
}

Status MovingPhotoMuxerFilter::LinkNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("MovingPhotoMuxerFilter::LinkNext filterType:%{public}d", (int32_t)nextFilter->GetCFilterType());
    return Status::OK;
}

Status MovingPhotoMuxerFilter::UpdateNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("UpdateNext");
    return Status::OK;
}

Status MovingPhotoMuxerFilter::UnLinkNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("UnLinkNext");
    return Status::OK;
}

CFilterType MovingPhotoMuxerFilter::GetFilterType()
{
    MEDIA_INFO_LOG("GetFilterType");
    return filterType_;
}

Status MovingPhotoMuxerFilter::OnLinked(CStreamType inType, const std::shared_ptr<Meta> &meta,
    const std::shared_ptr<CFilterLinkCallback> &callback)
{
    MEDIA_INFO_LOG("MovingPhotoMuxerFilter::OnLinked E");
    int32_t trackIndex = -1;
    std::string mimeType;
    meta->Get<Tag::MIME_TYPE>(mimeType);
    MEDIA_INFO_LOG("MovingPhotoMuxerFilter::OnLinked %{public}s", mimeType.c_str());
    if (mimeType.find("audio/") == 0) {
        audioCodecMimeType_ = mimeType;
        trackIndex = 0;
        metaInfo_.audioMeta = std::make_shared<Meta>(*meta);
    } else if (mimeType.find("video/") == 0) {
        videoCodecMimeType_ = mimeType;
        trackIndex = 1;
        metaInfo_.videoMeta = std::make_shared<Meta>(*meta);
    } else if (mimeType.find("meta/") == 0) {
        metaDataCodecMimeType_ = mimeType;
        metaInfo_.metaMeta = std::make_shared<Meta>(*meta);
        trackIndex = 2;
    }
    CHECK_RETURN_RET_ELOG(trackIndexMap_.find(mimeType) != trackIndexMap_.end(), Status::ERROR_WRONG_STATE,
        "MovingPhotoMuxerFilter::OnLinked exist, %{public}s", mimeType.c_str());
    trackIndexMap_.emplace(std::make_pair(mimeType, trackIndex));
    MEDIA_INFO_LOG("MovingPhotoMuxerFilter::OnLinked OnLinkedResult call, %{public}s", mimeType.c_str());
    callback->OnLinkedResult(nullptr, const_cast<std::shared_ptr<Meta> &>(meta));
    return Status::OK;
}

std::string Time2String(float timems)
{
    MEDIA_INFO_LOG("Time2String timems: %{public}f", timems);
    constexpr int64_t SEC_TO_MSEC = 1e3;
    constexpr int64_t MSEC_TO_NSEC = 1e6;
    struct timespec realTime;
    struct timespec monotonic;
    clock_gettime(CLOCK_REALTIME, &realTime);
    clock_gettime(CLOCK_MONOTONIC, &monotonic);
    int64_t realTimeStamp = realTime.tv_sec * SEC_TO_MSEC + realTime.tv_nsec / MSEC_TO_NSEC;
    int64_t monotonicTimeStamp = monotonic.tv_sec * SEC_TO_MSEC + monotonic.tv_nsec / MSEC_TO_NSEC;
    int64_t firstFrameTime = realTimeStamp - monotonicTimeStamp + int64_t(timems);
    return std::to_string(firstFrameTime);
}

constexpr inline float Ns2Ms(int64_t nanosec)
{
    return static_cast<float>(nanosec) / 1000000.0f;
}

bool MovingPhotoMuxerFilter::MuxerTask::CreateAVMuxer(int64_t startTimeStamp, int64_t endTimeStamp, MetaInfo& metaInfo)
{
    auto task = recorderTask_;
    auto pair = task->GetPhotoAsset();
    std::shared_ptr<PhotoAssetIntf> photoAssetProxy = pair.second;
    CHECK_RETURN_RET_ELOG(photoAssetProxy == nullptr, false, "photoAssetProxy is nullptr");
    int64_t shutterTime = pair.first;
    muxer_ = new MovingPhotoAVMuxer();
    CHECK_RETURN_RET_ELOG(muxer_ == nullptr, false, "muxer is nullptr");
    fd_ = photoAssetProxy->GetVideoFd(VideoType::ORIGIN_VIDEO);
    MEDIA_INFO_LOG("MuxerTask::CreateAVMuxer with videoFd: %{public}d", fd_);

    Plugins::OutputFormat format = Plugins::OutputFormat::MPEG_4;
    muxer_->Create(format, fd_);

    MEDIA_INFO_LOG("MuxerTask::CreateAVMuxer rotation: %{public}d", task->GetRotation());

    auto copyMuxerMeta = std::make_shared<Meta>(*(metaInfo.muxerMeta));
    copyMuxerMeta->Set<Tag::VIDEO_ROTATION>(static_cast<Plugins::VideoRotation>(task->GetRotation()));
    muxer_->SetParameter(copyMuxerMeta);

    int64_t coverTimestamp = std::min(shutterTime, endTimeStamp) - startTimeStamp;
    MuxerConfig config;
    config.covertime = Ns2Ms(coverTimestamp);
    config.starttime = Time2String(Ns2Ms(startTimeStamp));
    config.hasEnhanceFlag = task->GetDeferredVideoEnhanceFlag(config.videoEnhanceFlag);
    config.hasVideoId = task->GetVideoId(config.videoId);
    int64_t bitrate = 0;
    metaInfo.videoMeta->Get<Tag::MEDIA_BITRATE>(bitrate);
    MEDIA_DEBUG_LOG("MuxerTask::CreateAVMuxer bitrate: %{public}" PRId64, bitrate);
    CHECK_EXECUTE(bitrate > 0, {
        config.bitrateString = MOVING_PHOTO_ENCODER_PARAM_VALUE + std::to_string(bitrate);
        config.hasBitrateString = true;
    });
    muxer_->SetUserMeta(config);

    int videoTrackId = -1;
    muxer_->AddTrack(videoTrackId, metaInfo.videoMeta);

    int audioTrackId = -1;
    muxer_->AddTrack(audioTrackId, metaInfo.audioMeta);

    int metaTrackId = -1;
    auto copyMetaMeta = std::make_shared<Meta>(*(metaInfo.metaMeta));
    copyMetaMeta->SetData(Tag::TIMED_METADATA_SRC_TRACK, videoTrackId);
    muxer_->AddTrack(metaTrackId, copyMetaMeta);
    return true;
}

void MovingPhotoMuxerFilter::MuxerTask::Start()
{
    CHECK_EXECUTE(muxer_, muxer_->Start());
}

void MovingPhotoMuxerFilter::MuxerTask::Stop()
{
    CHECK_EXECUTE(muxer_, muxer_->Stop());
    CHECK_EXECUTE(fd_>=0, {
        close(fd_);
        MEDIA_INFO_LOG("MuxerTask::Stop closeFd: %{public}d", fd_);
        fd_ = -1;
    });
    CHECK_EXECUTE(recorderTask_, recorderTask_->OnVideoSaveFinish());
    muxer_ = nullptr;
    recorderTask_ = nullptr;
}

void MovingPhotoMuxerFilter::MuxerTask::WriteAVBuffer(std::vector<sptr<VideoBufferWrapper>>& videoBuffers)
{
    int32_t videoCnt = 0;
    int32_t metaCnt = 0;
    CHECK_RETURN_ELOG(videoBuffers.empty(), "bufferList is empty");
    int64_t firstTs = videoBuffers.front()->GetTimestamp();
    sptr<MovingPhotoAVMuxer> muxer = muxer_;
    for (size_t index = 0; index < videoBuffers.size(); index++) {
        auto& videoBuffer = videoBuffers[index];
        CHECK_CONTINUE(videoBuffer == nullptr);
        shared_ptr<AVBuffer> videoAVBuffer = videoBuffer->GetEncodedBuffer();
        videoAVBuffer->pts_ = NanosecToMicrosec(videoBuffer->GetTimestamp() - firstTs);
        MEDIA_DEBUG_LOG("WriteSampleBuffer video buffer pts: %{public}" PRId64, videoAVBuffer->pts_);
        int32_t ret = muxer->WriteSampleBuffer(muxer->videoTrackId_, videoAVBuffer);
        CHECK_CONTINUE(ret != AV_ERR_OK);
        videoCnt++;
        auto metaBuffer = videoBuffer->GetMetaBuffer();
        CHECK_CONTINUE(metaBuffer == nullptr);
        sptr<SurfaceBuffer> metaSurfaceBuffer = metaBuffer->GetMetaBuffer();
        CHECK_CONTINUE(metaSurfaceBuffer == nullptr);
        shared_ptr<AVBuffer> metaAVBuffer = AVBuffer::CreateAVBuffer(metaSurfaceBuffer);
        CHECK_CONTINUE(metaAVBuffer == nullptr);
        metaAVBuffer->pts_ = videoAVBuffer->pts_;
        ret = muxer->WriteSampleBuffer(muxer->metaTrackId_, metaAVBuffer);
        CHECK_EXECUTE(ret == AV_ERR_OK, metaCnt++);
        MEDIA_DEBUG_LOG("WriteSampleBuffer  meta buffer pts: %{public}" PRId64, metaAVBuffer->pts_);
    }
    MEDIA_INFO_LOG("WriteAVBuffer videoCnt: %{public}d metaCnt: %{public}d", videoCnt, metaCnt);
}

void MovingPhotoMuxerFilter::MuxerTask::WriteAVBuffer(std::vector<sptr<AudioBufferWrapper>>& audioBuffers)
{
    int32_t audioCnt = 0;
    constexpr size_t MAX_AUDIO_FRAME_COUNT = 140;
    sptr<MovingPhotoAVMuxer> muxer = muxer_;
    size_t maxFrameCount = std::min(audioBuffers.size(), MAX_AUDIO_FRAME_COUNT);
    for (size_t index = 0; index < maxFrameCount; index++) {
        std::shared_ptr<AVBuffer> audioAVBuffer = audioBuffers[index]->GetEncodedBuffer();
        CHECK_CONTINUE_WLOG(audioAVBuffer == nullptr, "audio encodedBuffer is null");
        audioAVBuffer->flag_ = AVCODEC_BUFFER_FLAGS_NONE;
        constexpr int32_t AUDIO_FRAME_INTERVAL = 32000;
        audioAVBuffer->pts_  = static_cast<int64_t>(index * AUDIO_FRAME_INTERVAL);
        CHECK_EXECUTE(index == maxFrameCount - 1, audioAVBuffer->flag_  = AVCODEC_BUFFER_FLAGS_EOS);
        int32_t ret = muxer->WriteSampleBuffer(muxer->audioTrackId_, audioAVBuffer);
        CHECK_EXECUTE(ret == AV_ERR_OK, audioCnt++);
        MEDIA_DEBUG_LOG("WriteSampleBuffer audio buffer pts: %{public}" PRId64, audioAVBuffer->pts_);
    }
    MEDIA_INFO_LOG("WriteAVBuffer audioCnt: %{public}d", audioCnt);
}

void MovingPhotoMuxerFilter::DoMuxerVideo(sptr<MovingPhotoRecorderTask> task)
{
    MEDIA_INFO_LOG("MovingPhotoMuxerFilter::DoMuxerVideo E");
    CHECK_RETURN_ELOG(task == nullptr, "task is nullptr");
    auto engineContext = GetEngineContext();
    CHECK_RETURN_ELOG(engineContext == nullptr, "engineContext is nullptr");
    auto taskManager = engineContext->GetTaskManager();
    CHECK_RETURN_ELOG(taskManager == nullptr, "taskManager is nullptr");
    std::vector<sptr<VideoBufferWrapper>> chosenVideoBuffers;
    taskManager->GetChooseVideoBuffer(task, chosenVideoBuffers);
    CHECK_RETURN_ELOG(chosenVideoBuffers.empty(), "DoMuxerVideo chosenVideoBuffers is empty");
    int64_t startTimeStamp = chosenVideoBuffers.front()->GetTimestamp();
    int64_t endTimeStamp = chosenVideoBuffers.back()->GetTimestamp();
    sptr<MuxerTask> muxerTask = new MuxerTask(task);
    bool ret = muxerTask->CreateAVMuxer(startTimeStamp, endTimeStamp, metaInfo_);
    CHECK_RETURN_ELOG(!ret, "CreateAVMuxer failed");
    muxerTask->Start();
    muxerTask->WriteAVBuffer(chosenVideoBuffers);

    std::vector<sptr<AudioBufferWrapper>> audioBuffers;
    taskManager->GetAudioRecords(chosenVideoBuffers, audioBuffers);
    bool isEncodeSuccess = EncodeAudioBuffer(audioBuffers);
    MEDIA_DEBUG_LOG("encode audio buffer result %{public}d", isEncodeSuccess);
    muxerTask->WriteAVBuffer(audioBuffers);
    muxerTask->Stop();
    MEDIA_INFO_LOG("MovingPhotoMuxerFilter::DoMuxerVideo X");
}

bool MovingPhotoMuxerFilter::EncodeAudioBuffer(std::vector<sptr<AudioBufferWrapper>>& audioBuffers)
{
    MEDIA_INFO_LOG("MovingPhotoMuxerFilter::EncodeAudioBuffer X");
    auto engineContext = GetEngineContext();
    CHECK_RETURN_RET_ELOG(engineContext == nullptr, false, "engineContext is nullptr");
    auto audioEncoderilter = engineContext->GetAudioEncoderFilter();
    CHECK_RETURN_RET_ELOG(audioEncoderilter == nullptr, false, "audioEncoderilter is nullptr");
    return audioEncoderilter->EncodeAudioRecord(audioBuffers);
}

void MovingPhotoMuxerFilter::CreateMuxerTask(sptr<MovingPhotoRecorderTask> task)
{
    if (!taskPtr_) {
        taskPtr_ = std::make_shared<Task>("MovingPhotoMuxer", groupId_, TaskType::VIDEO, TaskPriority::HIGH, false);
    }
    MEDIA_INFO_LOG("MovingPhotoMuxerFilter::CreateMuxerTask E");
    auto thisPtr = shared_from_this();
    taskPtr_->SubmitJobOnce([thisPtr, task]{
        thisPtr->DoMuxerVideo(task);
    });
}

Status MovingPhotoMuxerFilter::OnUpdated(CStreamType inType, const std::shared_ptr<Meta> &meta,
    const std::shared_ptr<CFilterLinkCallback> &callback)
{
    MEDIA_INFO_LOG("OnUpdated");
    return Status::OK;
}


Status MovingPhotoMuxerFilter::OnUnLinked(CStreamType inType, const std::shared_ptr<CFilterLinkCallback> &callback)
{
    MEDIA_INFO_LOG("OnUnLinked");
    return Status::OK;
}

const std::string &MovingPhotoMuxerFilter::GetContainerFormat(Plugins::OutputFormat format)
{
    static std::string emptyFormat = "";
    CHECK_RETURN_RET_ELOG(FORMAT_TABLE.find(format) == FORMAT_TABLE.end(), emptyFormat,
        "The output format %{public}d is not supported!", format);
    return FORMAT_TABLE.at(format);
}

void MovingPhotoMuxerFilter::SetCallingInfo(int32_t appUid, int32_t appPid,
    const std::string &bundleName, uint64_t instanceId)
{
    appUid_ = appUid;
    appPid_ = appPid;
    bundleName_ = bundleName;
    instanceId_ = instanceId;
}
} // namespace MEDIA
} // namespace OHOS
// LCOV_EXCL_STOP