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

#include "movie_file_video_encoded_buffer_producer.h"

#include <fcntl.h>

#include "avcodec_errors.h"
#include "avcodec_info.h"
#include "camera_log.h"
#include "camera_xml_parser.h"
#include "datetime_ex.h"
#include "image_source.h"
#include "media_description.h"
#include "native_avformat.h"
#include "nlohmann/json.hpp"
#include "pixel_map.h"
#include "unified_pipeline_video_encoded_buffer.h"
#include "watermark_util.h"

namespace OHOS {
namespace CameraStandard {
using namespace MediaAVCodec;
namespace {
    constexpr int64_t SEC_TO_NS = 1000000000;
} // namespace
MovieFileVideoEncodedBufferProducer::VideoEncoderCallback::VideoEncoderCallback(
    MovieFileVideoEncodedBufferProducer* bufferProducer)
    : bufferProducer_(bufferProducer) {};

MovieFileVideoEncodedBufferProducer::VideoEncoderCallback::~VideoEncoderCallback()
{
    MEDIA_INFO_LOG("MovieFileVideoEncodedBufferProducer::VideoEncoderCallback::~VideoEncoderCallback");
}

void MovieFileVideoEncodedBufferProducer::VideoEncoderCallback::OnError(AVCodecErrorType errorType, int32_t errorCode)
{}

void MovieFileVideoEncodedBufferProducer::VideoEncoderCallback::OnOutputFormatChanged(const Format& format) {}

void MovieFileVideoEncodedBufferProducer::VideoEncoderCallback::OnInputBufferAvailable(
    uint32_t index, std::shared_ptr<AVBuffer> buffer)
{}

void MovieFileVideoEncodedBufferProducer::VideoEncoderCallback::OnOutputBufferAvailable(
    uint32_t index, std::shared_ptr<AVBuffer> buffer)
{
    std::lock_guard<std::mutex> lock(bufferProducerMutex_);
    if (!bufferProducer_) {
        return;
    }
    bufferProducer_->OnOutputBufferAvailable(index, buffer);
}

void MovieFileVideoEncodedBufferProducer::VideoEncoderCallback::Release()
{
    std::lock_guard<std::mutex> lock(bufferProducerMutex_);
    bufferProducer_ = nullptr;
}

MovieFileVideoEncodedBufferProducer::VideoEncoderParameterWithAttrCallback::VideoEncoderParameterWithAttrCallback(
    MovieFileVideoEncodedBufferProducer* bufferProducer) : bufferProducer_(bufferProducer)
{
    MEDIA_INFO_LOG("VideoEncoderParameterWithAttrCallback construct");
}

MovieFileVideoEncodedBufferProducer::VideoEncoderParameterWithAttrCallback::~VideoEncoderParameterWithAttrCallback()
{
    MEDIA_INFO_LOG("VideoEncoderParameterWithAttrCallback destruct");
}

void MovieFileVideoEncodedBufferProducer::VideoEncoderParameterWithAttrCallback::OnInputParameterWithAttrAvailable(
    uint32_t index, std::shared_ptr<OHOS::Media::Format> attribute, std::shared_ptr<OHOS::Media::Format> parameter)
{
    MEDIA_DEBUG_LOG(":VideoEncoderParameterWithAttrCallback::OnInputParameterWithAttrAvailable");
    std::lock_guard<std::mutex> lock(bufferParameterProducerMutex_);
    if (!bufferProducer_) {
        return;
    }
    bufferProducer_->OnInputParameterWithAttrAvailable(index, attribute, parameter);
}

void MovieFileVideoEncodedBufferProducer::VideoEncoderParameterWithAttrCallback::Release()
{
    std::lock_guard<std::mutex> lock(bufferParameterProducerMutex_);
    bufferProducer_ = nullptr;
}

MovieFileVideoEncodedBufferProducer::EncoderWarp::EncoderWarp(
    const VideoEncoderConfig& config, std::shared_ptr<MediaCodecCallback> codecCallback,
    std::shared_ptr<MediaAVCodec::MediaCodecParameterWithAttrCallback> codecParameterCallback)
    : encodeConfig_(config)
{
    encoder_ = MediaAVCodec::VideoEncoderFactory::CreateByMime(config.mimeType);
    CHECK_RETURN_ELOG(!encoder_, "EncoderWarp create encoder fail");
    int32_t ret = encoder_->SetCallback(codecParameterCallback);
    CHECK_RETURN_ELOG(ret != AVCS_ERR_OK,
        "MovieFileVideoEncoderEncodeNode set codecParameterCallback failed, ret: %{public}d", ret);
    ret = encoder_->SetCallback(codecCallback);
    CHECK_RETURN_ELOG(ret != AVCS_ERR_OK, "MovieFileVideoEncoderEncodeNode set callback failed, ret: %{public}d", ret);
    UpdateConfig(config);
}

int32_t MovieFileVideoEncodedBufferProducer::EncoderWarp::GetEncodeBitrate()
{
    return encodeConfig_.videoBitrate;
}

int32_t MovieFileVideoEncodedBufferProducer::EncoderWarp::GetFrameRate()
{
    return encodeConfig_.frameRate;
}

void MovieFileVideoEncodedBufferProducer::EncoderWarp::UpdateConfig(const VideoEncoderConfig& config)
{
    CAMERA_SYNC_TRACE;
    // Config encoder
    MediaAVCodec::Format format = MediaAVCodec::Format();
    MEDIA_INFO_LOG("EncoderWarp Current resolution is :%{public}d*%{public}d "
                   "bitrate:%{public}d rotation:%{public}d "
                   "isHdr:%{public}d mineType:%{public}s framerate:%{public}d isBFrame:%{public}d",
        config.width, config.height, config.videoBitrate, config.rotation, config.isHdr,
        config.mimeType.c_str(), config.frameRate, config.isBFrame);

    format.PutIntValue(MediaDescriptionKey::MD_KEY_WIDTH, config.width);
    format.PutIntValue(MediaDescriptionKey::MD_KEY_HEIGHT, config.height);
    format.PutIntValue(MediaDescriptionKey::MD_KEY_ROTATION_ANGLE, config.rotation);
    format.PutDoubleValue(MediaDescriptionKey::MD_KEY_FRAME_RATE, config.frameRate);
    format.PutIntValue(MediaDescriptionKey::MD_KEY_VIDEO_ENCODE_BITRATE_MODE, SQR);
    // set videobitrate
    format.PutLongValue(MediaDescriptionKey::MD_KEY_BITRATE, config.videoBitrate);
    format.PutIntValue(MediaDescriptionKey::MD_KEY_PIXEL_FORMAT, AV_PIXEL_FORMAT_NV21);

    // hdr 必须配合 hevc 编码否则忽略 hdr
    if (config.isHdr && config.mimeType == std::string(CodecMimeType::VIDEO_HEVC)) {
        format.PutIntValue(MediaDescriptionKey::MD_KEY_PROFILE, HEVC_PROFILE_MAIN_10);
        format.PutIntValue(MediaDescriptionKey::MD_KEY_VIDEO_IS_HDR_VIVID, true);
    }
    if (config.isBFrame) {
        format.PutIntValue(Media::Tag::VIDEO_ENCODE_B_FRAME_GOP_MODE,
            Media::Plugins::VideoEncodeBFrameGopMode::VIDEO_ENCODE_GOP_ADAPTIVE_B_MODE);
        format.PutIntValue(Media::Tag::VIDEO_ENCODER_ENABLE_B_FRAME, config.isBFrame);
    }
    CHECK_RETURN_ELOG(!encoder_, "encoder_ is null");
    int32_t ret = encoder_->Configure(format);
    CHECK_RETURN_ELOG(ret != AVCS_ERR_OK, "EncoderWarp configure encoder fail:%{public}d", ret);

    auto waterMarkBuffer = waterMarkBuffer_.Get();
    if (waterMarkBuffer && encoder_) {
        encoder_->SetCustomBuffer(waterMarkBuffer);
    }

    // GetSurface
    codecSurface_ = encoder_->CreateInputSurface();

    // Prepare video encoder
    ret = encoder_->Prepare();
    CHECK_RETURN_ELOG(ret != AVCS_ERR_OK, "EncoderWarp prepare failed, ret: %{public}d", ret);
}

void MovieFileVideoEncodedBufferProducer::EncoderWarp::WaitState(State state)
{
    static constexpr int32_t WAIT_TIME = 3000;
    std::unique_lock<std::mutex> lock(stateMutex_);
    stateCondition_.wait_for(lock, std::chrono::milliseconds(WAIT_TIME), [this, state]() { return state_ == state; });
}

void MovieFileVideoEncodedBufferProducer::EncoderWarp::CheckStoppedState()
{
    {
        std::unique_lock<std::mutex> lock(stateMutex_);
        CHECK_RETURN(state_ == EncoderWarp::State::STOPPED);
    }
    MEDIA_INFO_LOG("stop encoder before start");
    Stop();
}

void MovieFileVideoEncodedBufferProducer::EncoderWarp::Start()
{
    if (!encoder_) {
        return;
    }
    int32_t ret = encoder_->Start();
    CHECK_RETURN_ELOG(ret != AVCS_ERR_OK, "EncoderWarp start failed, ret: %{public}d", ret);
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        state_ = State::STARTED;
        stateCondition_.notify_all();
    }
}

void MovieFileVideoEncodedBufferProducer::EncoderWarp::Stop()
{
    CAMERA_SYNC_TRACE;
    if (!encoder_) {
        return;
    }
    encoder_->Stop();
    encoder_->Reset();
    UpdateConfig(encodeConfig_);
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        state_ = State::STOPPED;
        stateCondition_.notify_all();
    }
}

MovieFileVideoEncodedBufferProducer::EncoderWarp::~EncoderWarp()
{
    if (encoder_) {
        encoder_->Flush();
        encoder_->Release();
    }
}

void MovieFileVideoEncodedBufferProducer::EncoderWarp::RequestIFrame()
{
    if (!encoder_) {
        return;
    }
    MediaAVCodec::Format format = MediaAVCodec::Format();
    format.PutIntValue(MediaDescriptionKey::MD_KEY_REQUEST_I_FRAME, true);
    encoder_->SetParameter(format);
}

void MovieFileVideoEncodedBufferProducer::EncoderWarp::FlushBuffer()
{
    if (!encoder_) {
        return;
    }
    encoder_->Flush();
}

void MovieFileVideoEncodedBufferProducer::EncoderWarp::NotifyEos()
{
    if (!encoder_) {
        return;
    }
    encoder_->NotifyEos();
}

void MovieFileVideoEncodedBufferProducer::EncoderWarp::SetWatermark(
    std::shared_ptr<MediaAVCodec::AVBuffer> waterMarkBuffer)
{
    if (!encoder_) {
        return;
    }
    waterMarkBuffer_.Set(waterMarkBuffer);
    encoder_->SetCustomBuffer(waterMarkBuffer);
}

void MovieFileVideoEncodedBufferProducer::EncoderWarp::Reset()
{
    if (!encoder_) {
        return;
    }
    encoder_->Reset();
}

void MovieFileVideoEncodedBufferProducer::EncoderWarp::ReleaseOutputBuffer(uint32_t index)
{
    if (encoder_) {
        encoder_->ReleaseOutputBuffer(index);
    }
}

sptr<IBufferProducer> MovieFileVideoEncodedBufferProducer::EncoderWarp::GetProducer()
{
    if (codecSurface_) {
        return codecSurface_->GetProducer();
    }
    return nullptr;
}

void MovieFileVideoEncodedBufferProducer::EncoderWarp::QueueInputParameter(uint32_t index)
{
    if (encoder_) {
        encoder_->QueueInputParameter(index);
    }
}

MovieFileVideoEncodedBufferProducer::MovieFileVideoEncodedBufferProducer()
{
    videoEncoderCallback_ = std::make_shared<VideoEncoderCallback>(this);
    videoEncoderParameterWithAttrCallback_ = std::make_shared<VideoEncoderParameterWithAttrCallback>(this);
}

MovieFileVideoEncodedBufferProducer::~MovieFileVideoEncodedBufferProducer()
{
    // encoderWarp_ 需要先于 videoEncoderCallback_
    // 析构，触发资源释放后再将编码回调资源清空，避免回调释放之后编码器依然工作导致异常。
    encoderWarp_.Set(nullptr);
    videoEncoderCallback_->Release();
    videoEncoderParameterWithAttrCallback_->Release();
}

void MovieFileVideoEncodedBufferProducer::OnCommandArrival(std::unique_ptr<UnifiedPipelineCommand> command)
{
    if (command == nullptr || command->IsConsumed()) {
        return;
    }
    UnifiedPipelineDataProducer::OnCommandArrival(std::move(command));
}

void MovieFileVideoEncodedBufferProducer::OnOutputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer)
{
    MEDIA_DEBUG_LOG("MovieFileVideoEncodedBufferProducer::OnOutputBufferAvailable memory size: %{public}d "
                    "flag:%{public}d timestamp:%{public}" PRIi64,
        buffer->memory_->GetSize(), buffer->flag_, buffer->pts_);

    if (isWaitingBuffer_) {
        std::lock_guard<std::mutex> lock(bufferEndCondMtx_);
        isReceivedBuffer_ = true;
        bufferEndCondition_.notify_all();
    }

    AVEncoderPackagedAVBufferInfo packagedAVBufferInfo {};
    packagedAVBufferInfo.infos.emplace_back(AVEncoderAVBufferInfo { .index = index, .buffer = buffer });
    auto encodedBuffer =
        std::make_unique<UnifiedPipelineVideoEncodedBuffer>(BufferType::CAMERA_VIDEO_PACKAGED_ENCODED_BUFFER);
    encodedBuffer->WrapData(packagedAVBufferInfo);
    std::weak_ptr<EncoderWarp> weakEncoderWarp = encoderWarp_.Get();
    encodedBuffer->SetBufferMemoryReleaser([weakEncoderWarp](AVEncoderPackagedAVBufferInfo* bufferInfo) {
        auto encoderWarp = weakEncoderWarp.lock();
        if (encoderWarp) {
            for (auto& info : bufferInfo->infos) {
                MEDIA_DEBUG_LOG("OnOutputBufferAvailable ReleaseOutputBuffer index: %{public}d ", info.index);
                encoderWarp->ReleaseOutputBuffer(info.index);
            }
        }
    });
    OnBufferArrival(std::move(encodedBuffer));
}

void MovieFileVideoEncodedBufferProducer::OnInputParameterWithAttrAvailable(
    uint32_t index, std::shared_ptr<OHOS::Media::Format> attribute, std::shared_ptr<OHOS::Media::Format> parameter)
{
    CAMERA_SYNC_TRACE;
    auto encoderWarp = encoderWarp_.Get();
    if (!encoderWarp) {
        return;
    }
    int64_t currentPts = 0;
    attribute->GetLongValue(Tag::MEDIA_TIME_STAMP, currentPts);
    encoderWarp->QueueInputParameter(index);
    auto videoFrameRate = encoderWarp->GetFrameRate();
    CHECK_RETURN_ELOG(videoFrameRate == 0, "videoFrameRate = 0, invalid value.");
    MEDIA_DEBUG_LOG("currentPts: %{public}" PRId64 ",  stopTime_: %{public}" PRId64
                    ", fixed stopTime_: %{public}" PRId64,
        currentPts, stopTime_, stopTime_ - (SEC_TO_NS / videoFrameRate));
    if (stopTime_ != -1 && currentPts > stopTime_ - (SEC_TO_NS / videoFrameRate)) {
        MEDIA_INFO_LOG("currentPts > stopTime, send EOS and Stop.");
        isWaitingBuffer_ = false;
        encoderWarp->NotifyEos();
        encoderWarp->Stop();
    }
}

void MovieFileVideoEncodedBufferProducer::ConfigVideoEncoder(const VideoEncoderConfig& config)
{
    videoEncoderConfig_ = config;
}

void MovieFileVideoEncodedBufferProducer::ChangeCodecSettings(
    const std::string& mimeType, int32_t rotation, bool isBFrame, int32_t videoBitrate)
{
    if (encoderWarp_.Get() == nullptr || videoEncoderConfig_.mimeType != mimeType ||
        videoEncoderConfig_.rotation != rotation || videoEncoderConfig_.isBFrame != isBFrame||
        videoEncoderConfig_.videoBitrate != videoBitrate) {
        videoEncoderConfig_.mimeType = mimeType;
        videoEncoderConfig_.rotation = rotation;
        videoEncoderConfig_.isBFrame = isBFrame;
        videoEncoderConfig_.videoBitrate = videoBitrate;
        ConfigVideoEncoder(videoEncoderConfig_);
        UpdateEncoderWarpConfig();
    }
}

void MovieFileVideoEncodedBufferProducer::UpdateEncoderWarpConfig()
{
    auto encoderWarp = encoderWarp_.Get();
    if (!encoderWarp) {
        encoderWarp = std::make_shared<EncoderWarp>(videoEncoderConfig_, videoEncoderCallback_,
            videoEncoderParameterWithAttrCallback_);
        encoderWarp_.Set(encoderWarp);
    } else {
        encoderWarp->UpdateConfig(videoEncoderConfig_);
    }
}

sptr<IBufferProducer> MovieFileVideoEncodedBufferProducer::GetSurfaceProducer()
{
    auto encoderWarp = encoderWarp_.Get();
    if (encoderWarp) {
        return encoderWarp->GetProducer();
    }
    return nullptr;
}

void MovieFileVideoEncodedBufferProducer::RequestIFrame()
{
    auto encoderWarp = encoderWarp_.Get();
    if (encoderWarp) {
        encoderWarp->RequestIFrame();
    }
}

void MovieFileVideoEncodedBufferProducer::FlushBuffer()
{
    auto encoderWarp = encoderWarp_.Get();
    if (encoderWarp) {
        encoderWarp->FlushBuffer();
    }
}

void MovieFileVideoEncodedBufferProducer::StartEncoder()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("MovieFileVideoEncodedBufferProducer::StartEncoder start");
    auto encoderWarp = encoderWarp_.Get();
    if (encoderWarp) {
        stopTime_ = -1;
        encoderWarp->CheckStoppedState();
        encoderWarp->Start();
    }
    MEDIA_INFO_LOG("MovieFileVideoEncodedBufferProducer::StartEncoder end");
}

void MovieFileVideoEncodedBufferProducer::StopEncoder(int64_t timestamp)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("MovieFileVideoEncodedBufferProducer::StopEncoder start");
    auto encoderWarp = encoderWarp_.Get();
    if (encoderWarp) {
        stopTime_ = timestamp;
        encoderWarp->WaitState(EncoderWarp::State::STARTED);

        isWaitingBuffer_ = true;
    }
    MEDIA_INFO_LOG("MovieFileVideoEncodedBufferProducer::StopEncoder end");
}

int32_t MovieFileVideoEncodedBufferProducer::GetVideoBitrate()
{
    auto encoderWarp = encoderWarp_.Get();
    if (encoderWarp == nullptr) {
        return DEFAULT_BIT_RATE; // default is 30M bitrate
    }
    return encoderWarp->GetEncodeBitrate();
}

void MovieFileVideoEncodedBufferProducer::WaitOutbufferEnd()
{
    CAMERA_SYNC_TRACE;
    constexpr int64_t WAIT_TIME_OUT = 3000;  // 最长等待3秒
    constexpr int64_t BUFFER_TIME_OUT = 120; // 120毫秒没收到数据认为当前buffer接收结束
    int64_t startMillisec = GetTickCount();  // 获取当前毫秒
    std::unique_lock<std::mutex> lock(bufferEndCondMtx_);
    while (GetTickCount() - startMillisec < WAIT_TIME_OUT) {
        bool isNotifyCondition = bufferEndCondition_.wait_for(
            lock, std::chrono::milliseconds(BUFFER_TIME_OUT), [this]() { return isReceivedBuffer_; });
        // 等待buffer超时，认为所有的buffer已经接收完毕
        CHECK_RETURN(!isNotifyCondition);
        isReceivedBuffer_ = false;
    }
    MEDIA_WARNING_LOG("MovieFileConsumer::WaitBufferReceivedFinish timeout");
}

void MovieFileVideoEncodedBufferProducer::AddVideoFilter(const std::string& filterName, const std::string& filterParam)
{
    auto encoderWarp = encoderWarp_.Get();
    if (!encoderWarp) {
        return;
    }
    // set empty buffer if filter name is not Inplace Sticker or filterParam is empty
    if (filterName != INPLACE_STICKER_NAME || filterParam.empty() || !nlohmann::json::accept(filterParam)) {
        MEDIA_INFO_LOG("MovieFileVideoEncodedBufferProducer::AddVideoFilter set empty watermark buffer");
        std::shared_ptr<AVBuffer> waterMarkBuffer = AVBuffer::CreateAVBuffer();
        encoderWarp->SetWatermark(waterMarkBuffer);
        encoderWarp->Reset();
        encoderWarp->UpdateConfig(videoEncoderConfig_);
        return;
    }
    // parse json info from app
    WatermarkEncodeConfig config;
    ParseWatermarkConfigFromJson(config, filterParam);
    // create pixel map
    std::shared_ptr<PixelMap> pixelMap;
    CreatePixelMapFromPath(pixelMap, config.imagePath);
    // scale pixel map
    ScalePixelMap(pixelMap, config, videoEncoderConfig_.width, videoEncoderConfig_.height);
    // rotate pixel map
    RotatePixelMap(pixelMap, config);
    // get av buffer config
    std::shared_ptr<Meta> meta = GetAvBufferMeta(config, videoEncoderConfig_.width, videoEncoderConfig_.height);
    // create watermark buffer
    auto buffer = CreateWatermarkBuffer(pixelMap, meta);
    encoderWarp->SetWatermark(buffer);
}

void MovieFileVideoEncodedBufferProducer::RemoveVideoFilter(const std::string& filterName)
{
    auto encoderWarp = encoderWarp_.Get();
    if (!encoderWarp) {
        return;
    }
    encoderWarp->SetWatermark(nullptr);
}

} // namespace CameraStandard
} // namespace OHOS