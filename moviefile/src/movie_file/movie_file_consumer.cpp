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

#include "movie_file_consumer.h"

#include <memory>
#include <mutex>
#include <string>

#include "av_common.h"
#include "avcodec_errors.h"
#include "avcodec_info.h"
#include "camera_log.h"
#include "datetime_ex.h"
#include "media_description.h"
#include "movie_file_common_const.h"
#include "native_audio_channel_layout.h"
#include "native_avcodec_base.h"
#include "native_mfmagic.h"

namespace OHOS {
namespace CameraStandard {
using namespace MediaAVCodec;

bool MovieFileConsumer::ConsumerTimeKeeper::WaitFirstVideoFrame()
{
    static constexpr int64_t FIRST_FRAME_TIMEOUT = 3000;
    std::unique_lock<std::mutex> lock(timeMutex_);
    bool isNotify = videoFrameCond_.wait_for(lock, std::chrono::milliseconds(FIRST_FRAME_TIMEOUT),
        [this]() { return firstVideoTimestamp_ != INVALID_TIMESTAMP; });
    return isNotify;
}

MovieFileConsumer::MovieFileConsumer() {}

void MovieFileConsumer::SetUp(MovieFileConfig config)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("MovieFileConsumer SetUp");
    movieFileConfig_ = config;
    CHECK_RETURN_ELOG(config.fd < 0, "MovieFileConsumer SetUp fd is invalid");
    muxer_ = AVMuxerFactory::CreateAVMuxer(config.fd, Plugins::OutputFormat::MPEG_4);
    CHECK_RETURN_ELOG(muxer_ == nullptr, "MovieFileConsumer create muxer failed!");

    ConfigMuxerInfo(config.rotation, config.location);
    SetMovieFileConfigToMuxer(config);
    AddVideoTrack(config.videoWidth, config.videoHeight, config.isVideoHdr, config.videoCodecMime, config.frameRate);
    if (config.audiostreamInfo) {
        AddAudioTrack(*config.audiostreamInfo);
    }
    if (config.rawAudiostreamInfo) {
        AddAudioRawTrack(*config.rawAudiostreamInfo);
    }

    AddMetadataTrack();
    MEDIA_INFO_LOG("MovieFileConsumer vId:%{public}d,aid:%{public}d,arid:%{public}d,mid:%{public}d", videoTrackId_,
        audioTrackId_, audioRawTrackId_, metaTrackId_);
    int32_t ret = muxer_->Start();
    CHECK_RETURN_ELOG(ret != AVCS_ERR_OK, "MovieFileConsumer muxer_ Start failed, ret: %{public}d", ret);
}

MovieFileConsumer::~MovieFileConsumer()
{
    MEDIA_INFO_LOG("MovieFileConsumer ~MovieFileConsumer");

    if (muxer_) {
        MEDIA_INFO_LOG("MovieFileConsumer muxer_->Stop");

        std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
        auto timeStamps = GetTimeStamps();
        userMeta->SetData("com.openharmony.recorder.timestamp", timeStamps);
        int32_t ret = muxer_->SetUserMeta(userMeta);

        MEDIA_INFO_LOG("com.openharmony.recorder.timestamp is %{public}s", timeStamps.c_str());

        ret = muxer_->Stop();
        CHECK_RETURN_ELOG(ret != AVCS_ERR_OK, "~MovieFileConsumer muxer_ Stop failed, ret: %{public}d", ret);
    }
    if (movieFileConfig_.fd >= 0) {
        close(movieFileConfig_.fd);
    }
    MEDIA_INFO_LOG("MovieFileConsumer ~MovieFileConsumer done");
}

void MovieFileConsumer::AddVideoTrack(
    int32_t width, int32_t height, bool isHdr, std::string mimeCodec, int32_t frameRate)
{
    Format formatVideo {};
    formatVideo.PutStringValue(MediaDescriptionKey::MD_KEY_CODEC_MIME, mimeCodec);
    // hdr 必须配合 hevc 编码否则忽略 hdr
    if (isHdr && mimeCodec == std::string(CodecMimeType::VIDEO_HEVC)) {
        formatVideo.PutIntValue(MediaDescriptionKey::MD_KEY_VIDEO_IS_HDR_VIVID, 1);
    }
    formatVideo.PutIntValue(MediaDescriptionKey::MD_KEY_WIDTH, width);
    formatVideo.PutIntValue(MediaDescriptionKey::MD_KEY_HEIGHT, height);
    formatVideo.PutDoubleValue(MediaDescriptionKey::MD_KEY_FRAME_RATE, static_cast<double>(frameRate));
    muxer_->AddTrack(videoTrackId_, formatVideo.GetMeta());
}

void MovieFileConsumer::AddMetadataTrack()
{
    CHECK_RETURN_ELOG(videoTrackId_ == INVALID_TRACKID, "MovieFileConsumer::AddMetadataTrack videoTrackId_ is invalid");
    Format formatMeta {};
    formatMeta.PutStringValue(MediaDescriptionKey::MD_KEY_CODEC_MIME, "meta/timed-metadata");
    formatMeta.PutStringValue(
        MediaDescriptionKey::MD_KEY_TIMED_METADATA_KEY, "com.openharmony.timed_metadata.vid_maker_info");
    formatMeta.PutIntValue(MediaDescriptionKey::MD_KEY_TIMED_METADATA_SRC_TRACK_ID, videoTrackId_);
    muxer_->AddTrack(metaTrackId_, formatMeta.GetMeta());
    if (metaTrackId_ != INVALID_TRACKID) {
        std::shared_ptr<Meta> param = std::make_shared<Meta>();
        param->SetData("use_timed_meta_track", 1);
        muxer_->SetParameter(param);
    }
}

void MovieFileConsumer::AddAudioTrack(AudioStandard::AudioStreamInfo audioStreamInfo)
{
    MEDIA_INFO_LOG("MovieFileConsumer::AddAudioTrack samplingRate: %{public}d  channels: %{public}d",
        audioStreamInfo.samplingRate, audioStreamInfo.channels);
    Format formatAudio {};
    formatAudio.PutStringValue(MediaDescriptionKey::MD_KEY_CODEC_MIME, CodecMimeType::AUDIO_AAC);
    formatAudio.PutIntValue(MediaDescriptionKey::MD_KEY_SAMPLE_RATE, audioStreamInfo.samplingRate);
    formatAudio.PutIntValue(MediaDescriptionKey::MD_KEY_CHANNEL_COUNT, audioStreamInfo.channels);
    formatAudio.PutIntValue(MediaDescriptionKey::MD_KEY_AUDIO_SAMPLE_FORMAT, audioStreamInfo.format);
    formatAudio.PutIntValue(MediaDescriptionKey::MD_KEY_PROFILE, MOVIE_FILE_AUDIO_DEFAULT_PROFILE);
    int32_t retCode = muxer_->AddTrack(audioTrackId_, formatAudio.GetMeta());
    MEDIA_INFO_LOG("MovieFileConsumer::AddAudioTrack retCode: %{public}d", retCode);
}

const std::string AUXILIARY_AUDIO_TRACK_KEY = "com.openharmony.audiomode.auxiliary";
const std::string TRACK_REF_TYPE_AUDIO = "auxl";
void MovieFileConsumer::AddAudioRawTrack(AudioStandard::AudioStreamInfo audioStreamInfo)
{
    MEDIA_INFO_LOG("MovieFileConsumer::AddAudioRawTrack samplingRate: %{public}d  channels: %{public}d",
        audioStreamInfo.samplingRate, audioStreamInfo.channels);
    Format formatAudio {};
    formatAudio.PutStringValue(MediaDescriptionKey::MD_KEY_CODEC_MIME, CodecMimeType::AUDIO_AAC);
    formatAudio.PutIntValue(MediaDescriptionKey::MD_KEY_SAMPLE_RATE, audioStreamInfo.samplingRate);
    formatAudio.PutIntValue(MediaDescriptionKey::MD_KEY_CHANNEL_COUNT, audioStreamInfo.channels);
    formatAudio.PutIntValue(MediaDescriptionKey::MD_KEY_AUDIO_SAMPLE_FORMAT, audioStreamInfo.format);

    formatAudio.PutIntValue(MediaDescriptionKey::MD_KEY_TRACK_TYPE, static_cast<int32_t>(MEDIA_TYPE_AUXILIARY));
    formatAudio.PutStringValue(MediaDescriptionKey::MD_KEY_TRACK_REFERENCE_TYPE, TRACK_REF_TYPE_AUDIO);
    formatAudio.PutStringValue(MediaDescriptionKey::MD_KEY_TRACK_DESCRIPTION, AUXILIARY_AUDIO_TRACK_KEY);
    formatAudio.PutIntBuffer(MediaDescriptionKey::MD_KEY_REFERENCE_TRACK_IDS, &audioTrackId_, 1);

    formatAudio.PutIntValue(MediaDescriptionKey::MD_KEY_PROFILE, MOVIE_FILE_AUDIO_DEFAULT_PROFILE);
    int32_t retCode = muxer_->AddTrack(audioRawTrackId_, formatAudio.GetMeta());
    MEDIA_INFO_LOG("MovieFileConsumer::AddAudioRawTrack retCode: %{public}d", retCode);
}

void MovieFileConsumer::ConfigMuxerInfo(int32_t rotation, std::vector<float> location)
{
    MEDIA_INFO_LOG("MovieFileConsumer::ConfigMuxerInfo rotation : %{public}d", rotation);
    CHECK_RETURN_ELOG(muxer_ == nullptr, "MovieFileConsumer::ConfigMuxerInfo muxer_ is null");
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    param->Set<Tag::MEDIA_CREATION_TIME>("now");
    param->Set<Tag::VIDEO_ROTATION>(static_cast<Plugins::VideoRotation>(rotation));

    if (location.size() >= 2) {
        param->Set<Tag::MEDIA_LATITUDE>(location[0]);
        param->Set<Tag::MEDIA_LONGITUDE>(location[1]);
    }
    int32_t ret = muxer_->SetParameter(param);
    CHECK_RETURN_ELOG(ret != AVCS_ERR_OK, "MovieFileConsumer::ConfigMuxerInfo failed, ret: %{public}d", ret);
}

void MovieFileConsumer::SetMovieFileConfigToMuxer(MovieFileConfig& config)
{
    MEDIA_INFO_LOG("MovieFileConsumer::SetCoverTime coverTime :%{public}f is set water mark:%{public}d "
                   "foldState:%{public}d deviceModel:%{public}s",
        config.coverTime, movieFileConfig_.isSetWaterMark, movieFileConfig_.deviceFoldState,
        movieFileConfig_.deviceModel.c_str());
    CHECK_RETURN_ELOG(muxer_ == nullptr, "MovieFileConsumer::SetCoverTime muxer_ is null");
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    std::string isWaterMark = movieFileConfig_.isSetWaterMark ? "true" : "false";
    userMeta->SetData("com.openharmony.isWaterMark", isWaterMark);
    userMeta->SetData("com.openharmony.encParam",
        "video_encode_bitrate_mode=SQR:bitrate=" + std::to_string(movieFileConfig_.bitrate) +
            ":video_encoder_enable_b_frame=" + std::to_string(movieFileConfig_.isBFrame));
    userMeta->SetData("com.openharmony.deviceFoldState", std::to_string(movieFileConfig_.deviceFoldState));
    userMeta->SetData("com.openharmony.deviceModel", movieFileConfig_.deviceModel);
    userMeta->SetData("com.openharmony.cameraPosition", std::to_string(movieFileConfig_.cameraPosition));
    int32_t ret = muxer_->SetUserMeta(userMeta);
    CHECK_RETURN_ELOG(ret != AVCS_ERR_OK, "MovieFileConsumer::SetCoverTime failed, ret: %{public}d", ret);
}

void MovieFileConsumer::SetDeferredVideoInfo(uint32_t flag, std::string videoId)
{
    MEDIA_INFO_LOG("MovieFileConsumer::SetDeferredVideoInfo ENTER");
    CHECK_RETURN_ELOG(muxer_ == nullptr, "MovieFileConsumer::SetDeferredVideoInfo muxer_ is null");
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    userMeta->SetData("com.openharmony.deferredVideoEnhanceFlag", std::to_string(flag));
    userMeta->SetData("com.openharmony.videoId", videoId);
    int32_t ret = muxer_->SetUserMeta(userMeta);
    CHECK_RETURN_ELOG(ret != AVCS_ERR_OK, "MovieFileConsumer::SetDeferredVideoInfo failed, ret: %{public}d", ret);
}

void MovieFileConsumer::RecordTimeStamps(int64_t startTimeStamp, int64_t endTimeStamp)
{
    if (startTimeStamp > endTimeStamp) {
        return;
    }
    if (!recordTimeStamps_.empty() && recordTimeStamps_.back() > startTimeStamp) {
        return;
    }
    recordTimeStamps_.emplace_back(startTimeStamp);
    recordTimeStamps_.emplace_back(endTimeStamp);
}

std::string MovieFileConsumer::GetTimeStamps()
{
    std::stringstream value("");
    for (auto it = recordTimeStamps_.begin(); it != recordTimeStamps_.end(); it++) {
        if (it == recordTimeStamps_.end() - 1) {
            value << std::to_string(*it);
        } else {
            value << std::to_string(*it) << ",";
        }
    }
    return value.str();
}

void MovieFileConsumer::OnCommandArrival(std::unique_ptr<UnifiedPipelineCommand> command)
{
    if (command == nullptr || command->IsConsumed()) {
        return;
    }
    auto commandId = command->GetCommandId();
    MEDIA_INFO_LOG("MovieFileConsumer::OnCommandArrival command:%{public}d ", commandId);
}

void MovieFileConsumer::OnBufferArrival(std::unique_ptr<UnifiedPipelineBuffer> pipelineBuffer)
{
    if (isWaitingBuffer_) {
        std::lock_guard<std::mutex> lock(bufferEndCondMtx_);
        isReceivedBuffer_ = true;
        bufferEndCondition_.notify_all();
    }

    BufferType bufferType = pipelineBuffer->GetBufferType();
    MEDIA_DEBUG_LOG("MovieFileConsumer::OnBufferArrival bufferType:%{public}d", bufferType);
    CHECK_RETURN_ELOG(
        muxer_ == nullptr, "MovieFileConsumer::OnBufferArrival muxer_ is null, bufferType:%{public}d", bufferType);
    switch (bufferType) {
        case BufferType::CAMERA_AUDIO_PACKAGED_ENCODED_RAW_BUFFER:
            OnAudioEncodedRawBufferArrival(
                UnifiedPipelineBuffer::CastPtr<UnifiedPipelineAudioPackagedEncodedBuffer>(std::move(pipelineBuffer)));
            break;
        case BufferType::CAMERA_AUDIO_PACKAGED_ENCODED_BUFFER:
            OnAudioEncodedBufferArrival(
                UnifiedPipelineBuffer::CastPtr<UnifiedPipelineAudioPackagedEncodedBuffer>(std::move(pipelineBuffer)));
            break;
        case BufferType::CAMERA_VIDEO_PACKAGED_ENCODED_BUFFER:
            OnVideoEncodedBufferArrival(
                UnifiedPipelineBuffer::CastPtr<UnifiedPipelineVideoEncodedBuffer>(std::move(pipelineBuffer)));
            break;
        case BufferType::CAMERA_VIDEO_META:
            OnMetaBufferArrival(
                UnifiedPipelineBuffer::CastPtr<UnifiedPipelineSurfaceBuffer>(std::move(pipelineBuffer)));
            break;
        default:
            // do nothing.
            break;
    }
};

bool MovieFileConsumer::WaitFirstFrame()
{
    MEDIA_INFO_LOG("MovieFileConsumer::WaitFirstFrame start");
    bool isWakeUp = timeKeeper_.WaitFirstVideoFrame();
    MEDIA_INFO_LOG("MovieFileConsumer::WaitFirstFrame end, isWakeUp:%{public}d", isWakeUp);
    return isWakeUp;
}

void MovieFileConsumer::Start()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("MovieFileConsumer::Start start");
    int64_t startTimeout = 0;
    if (timeKeeper_.IsStarted()) {
        // 启动前确认buffer干净
        isWaitingBuffer_ = true;
        startTimeout = WaitBufferReceivedFinish() * MILLISEC_TO_MICROSEC;
        isWaitingBuffer_ = false;
    }
    timeKeeper_.UpdateStartTime(GetMicroTickCount() - startTimeout);
    MEDIA_INFO_LOG("MovieFileConsumer::Start end");
}

void MovieFileConsumer::Pause()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("MovieFileConsumer::Pause start");
    isWaitingBuffer_ = true;
    WaitBufferReceivedFinish();
    isWaitingBuffer_ = false;
    RecordTimeStamps(videoStartPts_, videoStopPts_);
    FlushBufferQueueCache();
    MEDIA_INFO_LOG("MovieFileConsumer::Pause end");
}

void MovieFileConsumer::Resume()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("MovieFileConsumer::Resume start");
    int64_t startTimeout = 0;
    if (timeKeeper_.IsStarted()) {
        // 启动前确认buffer干净
        isWaitingBuffer_ = true;
        startTimeout = WaitBufferReceivedFinish() * MILLISEC_TO_MICROSEC;
        isWaitingBuffer_ = false;
    }
    timeKeeper_.UpdateStartTime(GetMicroTickCount() - startTimeout);
    MEDIA_INFO_LOG("MovieFileConsumer::Resume end");
}

void MovieFileConsumer::Stop()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("MovieFileConsumer::Stop start");
    isWaitingBuffer_ = true;
    WaitBufferReceivedFinish();
    isWaitingBuffer_ = false;
    RecordTimeStamps(videoStartPts_, videoStopPts_);
    FlushBufferQueueCache();
    MEDIA_INFO_LOG("MovieFileConsumer::Stop end");
}

int64_t MovieFileConsumer::WaitBufferReceivedFinish()
{
    CAMERA_SYNC_TRACE;
    constexpr int64_t WAIT_TIME_OUT = 3000;  // 最长等待3秒
    constexpr int64_t BUFFER_TIME_OUT = 80; // 80毫秒没收到数据认为当前buffer接收结束
    int64_t startMillisec = GetTickCount();  // 获取当前毫秒
    std::unique_lock<std::mutex> lock(bufferEndCondMtx_);
    while (GetTickCount() - startMillisec < WAIT_TIME_OUT) {
        bool isNotifyCondition = bufferEndCondition_.wait_for(
            lock, std::chrono::milliseconds(BUFFER_TIME_OUT), [this]() { return isReceivedBuffer_; });
        // 等待buffer超时，认为所有的buffer已经接收完毕
        CHECK_RETURN_RET(!isNotifyCondition, GetTickCount() - startMillisec);
        isReceivedBuffer_ = false;
    }
    MEDIA_WARNING_LOG("MovieFileConsumer::WaitBufferReceivedFinish timeout");
    return GetTickCount() - startMillisec;
}

void MovieFileConsumer::OnAudioEncodedRawBufferArrival(
    std::unique_ptr<UnifiedPipelineAudioPackagedEncodedBuffer> audioPackagedEncodedRawBuffer)
{
    CHECK_RETURN(audioRawTrackId_ == INVALID_TRACKID);
    audioEncodedRawBufferQueue_.Push(std::move(audioPackagedEncodedRawBuffer));
    if (!timeKeeper_.IsVideoStarted()) {
        return;
    }
    for (auto buffer = audioEncodedRawBufferQueue_.Pop(); buffer != nullptr;
         buffer = audioEncodedRawBufferQueue_.Pop()) {
        WriteAudioEncodedRawBuffer(std::move(buffer));
    }
}

void MovieFileConsumer::WriteAudioEncodedRawBuffer(
    std::unique_ptr<UnifiedPipelineAudioPackagedEncodedBuffer> audioPackagedEncodedRawBuffer)
{
    auto packagedData = audioPackagedEncodedRawBuffer->UnwrapData();
    CHECK_RETURN(packagedData.infos.empty());

    for (auto& data : packagedData.infos) {
        if (!timeKeeper_.IsTimestampVaild(data.timestamp)) {
            MEDIA_WARNING_LOG(
                "MovieFileConsumer::WriteAudioEncodedRawBuffer drop buffer pts:%{public}" PRIi64, data.timestamp);
            continue;
        }
        data.buffer->buffer_->pts_ = timeKeeper_.GetRelativeTime(data.timestamp);
        int32_t ret = muxer_->WriteSample(audioRawTrackId_, data.buffer->buffer_);
        MEDIA_DEBUG_LOG(
            "MovieFileConsumer::WriteAudioEncodedRawBuffer WriteSample done:%{public}d origin timestamp "
            "is:%{public}" PRIi64 ", fixed timestamp is:%{public}" PRIi64 " buffer size is %{public}zu"
            " flag is:%{public}d",
            ret, data.timestamp, data.buffer->buffer_->pts_, data.size, data.buffer->buffer_->flag_);
    }
}

void MovieFileConsumer::OnAudioEncodedBufferArrival(
    std::unique_ptr<UnifiedPipelineAudioPackagedEncodedBuffer> audioPackagedEncodedBuffer)
{
    CHECK_RETURN(audioTrackId_ == INVALID_TRACKID);
    audioEncodedBufferQueue_.Push(std::move(audioPackagedEncodedBuffer));
    if (!timeKeeper_.IsVideoStarted()) {
        return;
    }
    for (auto buffer = audioEncodedBufferQueue_.Pop(); buffer != nullptr; buffer = audioEncodedBufferQueue_.Pop()) {
        WriteAudioEncodedBuffer(std::move(buffer));
    }
}

void MovieFileConsumer::WriteAudioEncodedBuffer(
    std::unique_ptr<UnifiedPipelineAudioPackagedEncodedBuffer> audioPackagedEncodedBuffer)
{
    auto packagedData = audioPackagedEncodedBuffer->UnwrapData();
    CHECK_RETURN(packagedData.infos.empty());

    for (auto& data : packagedData.infos) {
        if (!timeKeeper_.IsTimestampVaild(data.timestamp)) {
            MEDIA_WARNING_LOG(
                "MovieFileConsumer::OnAudioEncodedBufferArrival drop buffer pts:%{public}" PRIi64, data.timestamp);
            continue;
        }
        data.buffer->buffer_->pts_ = timeKeeper_.GetRelativeTime(data.timestamp);
        int32_t ret = muxer_->WriteSample(audioTrackId_, data.buffer->buffer_);
        MEDIA_DEBUG_LOG("MovieFileConsumer::OnAudioEncodedBufferArrival WriteSample done:%{public}d origin timestamp "
                        "is:%{public}" PRIi64 ", fixed timestamp is:%{public}" PRIi64 " buffer size is %{public}zu"
                        " flag is:%{public}d",
            ret, data.timestamp, data.buffer->buffer_->pts_, data.size, data.buffer->buffer_->flag_);
    }
}

void MovieFileConsumer::OnVideoEncodedBufferArrival(
    std::unique_ptr<UnifiedPipelineVideoEncodedBuffer> videoEncodedBuffer)
{
    CHECK_RETURN(videoTrackId_ == INVALID_TRACKID);
    auto packagedData = videoEncodedBuffer->UnwrapData();
    if (packagedData.infos.empty()) {
        return;
    }
    for (auto& data : packagedData.infos) {
        int64_t bufferMicroPts = NanosecToMicrosec(data.buffer->pts_);
        MEDIA_DEBUG_LOG("MovieFileConsumer::OnVideoEncodedBufferArrival pts:%{public} " PRIi64 " flag:%{public}d",
            bufferMicroPts, data.buffer->flag_);
        // 刚启动muxer，没收到I帧，不要写入muxer
        if (!timeKeeper_.IsVideoStarted() &&
            !(data.buffer->flag_ & (AVCODEC_BUFFER_FLAGS_SYNC_FRAME | AVCODEC_BUFFER_FLAGS_CODEC_DATA))) {
            MEDIA_WARNING_LOG("MovieFileConsumer::OnVideoEncodedBufferArrival no first frame, drop frame");
            continue;
        }
        if (data.buffer->pts_ != 0) {
            if (!timeKeeper_.IsVideoStarted()) {
                videoStartPts_ = bufferMicroPts;
            }
            auto fixTimestamp = timeKeeper_.GetVideoRelativeTime(bufferMicroPts);
            MEDIA_DEBUG_LOG("MovieFileConsumer::OnVideoEncodedBufferArrival WriteSample origin is:%{public}" PRIi64
                            " fix is:%{public}" PRIi64 " videoDuration:%{public}" PRIi64,
                data.buffer->pts_, fixTimestamp, timeKeeper_.GetVideoDuration());
            if (bufferMicroPts > videoStopPts_) {
                videoStopPts_ = bufferMicroPts;
            }
            data.buffer->pts_ = fixTimestamp;
        }
        if (data.buffer->flag_ & AVCODEC_BUFFER_FLAGS_EOS) {
            data.buffer->flag_ &= ~AVCODEC_BUFFER_FLAGS_EOS; // 剔除EOS flag, 将 EOS 写入 muxer 中会影响分段录像成片。
            if (!data.buffer->flag_) { // 剔除EOS之后没有其他flag，buffer无效，不用写入
                continue;
            }
        }
        muxer_->WriteSample(videoTrackId_, data.buffer);
    }
}

void MovieFileConsumer::OnMetaBufferArrival(std::unique_ptr<UnifiedPipelineSurfaceBuffer> metaBuffer)
{
    CHECK_RETURN(metaTrackId_ == INVALID_TRACKID);
    if (!timeKeeper_.IsVideoStarted()) {
        return;
    }
    WriteMetaBuffer(std::move(metaBuffer));
}

void MovieFileConsumer::WriteMetaBuffer(std::unique_ptr<UnifiedPipelineSurfaceBuffer> metaBuffer)
{
    auto data = metaBuffer->UnwrapData();
    auto buffer = data.surfaceBuffer;
    if (buffer == nullptr) {
        return;
    }
    int32_t bufferSize = 0;
    auto extraData = buffer->GetExtraData();
    if (extraData) {
        extraData->ExtraGet("dataSize", bufferSize);
    }
    if (bufferSize == 0) {
        return;
    }

    AVBufferConfig avBufferConfig;
    avBufferConfig.size = bufferSize;
    avBufferConfig.memoryType = MemoryType::SHARED_MEMORY;
    avBufferConfig.memoryFlag = MemoryFlag::MEMORY_READ_WRITE;

    std::shared_ptr<AVBuffer> metaAvBuffer = AVBuffer::CreateAVBuffer(avBufferConfig);
    CHECK_RETURN_ELOG(metaAvBuffer == nullptr, "MovieFileConsumer::OnMetaBufferArrival metaAvBuffer is nullptr");
    CHECK_RETURN_ELOG(
        metaAvBuffer->memory_ == nullptr, "MovieFileConsumer::OnMetaBufferArrival metaAvBuffer->memory_ is nullptr.");

    std::shared_ptr<AVMemory>& bufferMem = metaAvBuffer->memory_;
    bufferMem->Write((const uint8_t*)buffer->GetVirAddr(), bufferSize, 0);
    metaAvBuffer->pts_ = timeKeeper_.GetMetadataRelativeTime(data.timestamp);
    muxer_->WriteSample(metaTrackId_, metaAvBuffer);
    MEDIA_DEBUG_LOG("MovieFileConsumer::OnMetaBufferArrival metaAvBuffer->pts is %{public}" PRIi64
                    " fixed pts is %{public}" PRIi64 " bufferSize is %{public}d",
        data.timestamp, metaAvBuffer->pts_, bufferSize);
}

void MovieFileConsumer::FlushBufferQueueCache()
{
    CAMERA_SYNC_TRACE;
    auto audioEncodedBufferQueue = audioEncodedBufferQueue_.Flush();
    MEDIA_INFO_LOG("MovieFileConsumer::FlushBufferQueueCache audioEncodedBufferQueue size is:%{public}zu",
        audioEncodedBufferQueue.size());
    while (!audioEncodedBufferQueue.empty()) {
        WriteAudioEncodedBuffer(std::move(audioEncodedBufferQueue.front()));
        audioEncodedBufferQueue.pop();
    }

    auto audioEncodedRawBufferQueue = audioEncodedRawBufferQueue_.Flush();
    MEDIA_INFO_LOG("MovieFileConsumer::FlushBufferQueueCache audioEncodedRawBufferQueue size is:%{public}zu",
        audioEncodedRawBufferQueue.size());
    while (!audioEncodedRawBufferQueue.empty()) {
        WriteAudioEncodedRawBuffer(std::move(audioEncodedRawBufferQueue.front()));
        audioEncodedRawBufferQueue.pop();
    }
}

} // namespace CameraStandard
} // namespace OHOS
