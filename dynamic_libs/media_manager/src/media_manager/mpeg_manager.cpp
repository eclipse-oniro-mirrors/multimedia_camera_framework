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
// LCOV_EXCL_START
#include "mpeg_manager.h"

#include <fcntl.h>
#include <filesystem>
#include <regex>

#include "avcodec_list.h"
#include "basic_definitions.h"
#include "dp_log.h"
#include "dps_event_report.h"
#include "dps_fd.h"
#include "image_source.h"
#include "image_type.h"
#include "pixel_map.h"
#include "sync_fence.h"
#include "media_format_info.h"
#include "media_format.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    constexpr char VIDEO_MAKER_NAME[] = "DpsVideoMaker";
    constexpr int64_t DEFAULT_TIME_TAMP = 0;
    constexpr char IMAGE_PATH[] = "IMAGE_PATH";
    constexpr char ROTATION[] = "ROTATION";
    constexpr char SCALE_FACTOR[] = "SCALE_FACTOR";
    constexpr char COORDINATE_X[] = "COORDINATE_X";
    constexpr char COORDINATE_Y[] = "COORDINATE_Y";
    constexpr char COORDINATE_W[] = "COORDINATE_W";
    constexpr char COORDINATE_H[] = "COORDINATE_H";
    constexpr int32_t ROTATION_360 = 360;
    constexpr int32_t WAIT_EOS_FRAME_TIME = 1000;
}

class MpegManager::VideoCodecCallback : public MediaCodecCallback {
public:
    explicit VideoCodecCallback(const std::weak_ptr<MpegManager>& mpegManager) : mpegManager_(mpegManager)
    {
        DP_DEBUG_LOG("entered.");
    }

    ~VideoCodecCallback() = default;

    void OnError(AVCodecErrorType errorType, int32_t errorCode) override
    {
        DP_ERR_LOG("entered, errorType: %{public}d, errorCode: %{public}d", errorType, errorCode);
    }

    void OnOutputFormatChanged(const Format &format) override
    {
        DP_DEBUG_LOG("entered.");
    }

    void OnInputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer) override
    {
        DP_DEBUG_LOG("entered, index: %{public}u", index);
    }

    void OnOutputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer) override
    {
        DP_CHECK_ERROR_RETURN_LOG(buffer == nullptr, "OutputBuffer is null");
        auto manager = mpegManager_.lock();
        DP_CHECK_ERROR_RETURN_LOG(manager == nullptr, "MpegManager is nullptr.");
        manager->OnBufferAvailable(index, buffer);
    }

private:
    std::weak_ptr<MpegManager> mpegManager_;
};

class MpegManager::VideoMakerListener : public IBufferConsumerListener {
public:
    explicit VideoMakerListener(const std::weak_ptr<MpegManager>& mpegManager) : mpegManager_(mpegManager)
    {
        DP_DEBUG_LOG("entered.");
    }
    ~VideoMakerListener() = default;

    void OnBufferAvailable() override
    {
        auto manager = mpegManager_.lock();
        DP_CHECK_ERROR_RETURN_LOG(manager == nullptr, "MpegManager is nullptr.");
        manager->OnMakerBufferAvailable();
    }

private:
    std::weak_ptr<MpegManager> mpegManager_;
};

MpegManager::MpegManager()
{
    DP_DEBUG_LOG("entered.");
    mediaManager_ = std::make_unique<MediaManager>();
}

MpegManager::~MpegManager()
{
    DP_INFO_LOG("entered.");
    remove(tempPath_.c_str());
    if (result_ == MediaResult::PAUSE) {
        int ret = rename(outPath_.c_str(), tempPath_.c_str());
        if (ret != 0) {
            DP_ERR_LOG("Rename %{public}s to %{public}s failde, ret: %{public}d",
                outPath_.c_str(), tempPath_.c_str(), ret);
        } else {
            DP_INFO_LOG("Rename %{public}s to %{public}s success.", outPath_.c_str(), tempPath_.c_str());
        }
    } else {
        remove(outPath_.c_str());
        DP_INFO_LOG("Reremove %{public}s success.", outPath_.c_str());
    }
    DPSEventReport::GetInstance().ReportPartitionUsage();
}

MediaManagerError MpegManager::Init(const std::string& requestId, const DpsFdPtr& inputFd,
    int32_t width, int32_t height)
{
    DP_INFO_LOG("Pipeline Init.");
    outputFd_ = GetFileFd(requestId, O_CREAT | O_RDWR, OUT_TAG);
    DP_CHECK_ERROR_RETURN_RET_LOG(outputFd_ == nullptr, ERROR_FAIL, "Output video create failde.");

    tempFd_ = GetFileFd(requestId, O_RDONLY, TEMP_TAG);
    int32_t temp = -1;
    DP_CHECK_EXECUTE(tempFd_ != nullptr, temp = tempFd_->GetFd());
    auto ret = mediaManager_->Create(inputFd->GetFd(), outputFd_->GetFd(), temp);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "Media manager create failde.");

    {
        std::lock_guard<std::mutex> lock(mediaInfoMutex_);
        mediaManager_->GetMediaInfo(mediaInfo_);
    }
    DP_CHECK_ERROR_RETURN_RET_LOG(InitVideoCodec(width, height) != OK, ERROR_FAIL, "Init video codec failde.");

    DP_CHECK_ERROR_RETURN_RET_LOG(InitVideoMakerSurface() != OK, ERROR_FAIL, "Init video maker surface failde.");
    isRunning_.store(true);
    return OK;
}

MediaManagerError MpegManager::UnInit(const MediaResult result)
{
    DP_INFO_LOG("Pipeline Stop.");
    DP_CHECK_RETURN_RET(!isRunning_.load(), OK);
    bool ret = UnInitVideoCodec();
    result_ = result;
    if (result == MediaResult::PAUSE) {
        if (mediaManager_->Pause() == PAUSE_ABNORMAL) {
            remove(outPath_.c_str());
        }
    } else {
        mediaManager_->Stop();
    }
    isRunning_.store(false);
    return ret ? OK : ERROR_TIME_OUT;
}

sptr<Surface> MpegManager::GetSurface()
{
    return codecSurface_;
}

sptr<Surface> MpegManager::GetMakerSurface()
{
    DP_INFO_LOG("MetaDataFilter Start.");
    return makerSurface_;
}

uint64_t MpegManager::GetProcessTimeStamp()
{
    std::lock_guard<std::mutex> lock(mediaInfoMutex_);
    DP_CHECK_RETURN_RET_LOG(mediaInfo_ == nullptr, DEFAULT_TIME_TAMP, "mediaInfo_ is nullptr");
    DP_CHECK_RETURN_RET(mediaInfo_->recoverTime < DEFAULT_TIME_TAMP, DEFAULT_TIME_TAMP);
    return static_cast<uint64_t>(mediaInfo_->recoverTime);
}

uint32_t MpegManager::GetDuration()
{
    std::lock_guard<std::mutex> lock(mediaInfoMutex_);
    DP_CHECK_RETURN_RET_LOG(mediaInfo_ == nullptr, DEFAULT_TIME_TAMP, "mediaInfo_ is nullptr");
    return static_cast<uint32_t>(mediaInfo_->codecInfo.duration / 1000);
}

MediaManagerError MpegManager::NotifyEnd()
{
    DP_CHECK_RETURN_RET(encoder_ == nullptr, ERROR_FAIL);
    auto ret = encoder_->NotifyEos();
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL, "Video codec notify end failde.");
    return OK;
}

DpsFdPtr MpegManager::GetResultFd()
{
    return outputFd_;
}

void MpegManager::AddUserMeta(std::unique_ptr<MediaUserInfo> userInfo)
{
    DP_CHECK_RETURN(userInfo == nullptr);
    DP_INFO_LOG("SetUserMeta entered.");
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    DP_CHECK_EXECUTE(userInfo->scalingFactor != DEFAULT_SCALING_FACTOR,
        userMeta->SetData(SCALING_FACTOR_KEY, userInfo->scalingFactor));
    DP_CHECK_EXECUTE(!userInfo->interpolationFramePts.empty(),
        userMeta->SetData(INTERPOLATION_FRAME_PTS_KEY, userInfo->interpolationFramePts));
    DP_CHECK_EXECUTE(!userInfo->stageVid.empty(), userMeta->SetData(STAGE_VID_KEY, userInfo->stageVid));
    mediaManager_->AddUserMeta(userMeta);
}

void MpegManager::SetProgressNotifer(std::unique_ptr<MediaProgressNotifier> processNotifer)
{
    processNotifer_ = std::move(processNotifer);
    DP_CHECK_EXECUTE(processNotifer_ != nullptr && mediaInfo_ != nullptr,
        processNotifer_->SetTotalDuration(mediaInfo_->codecInfo.duration));
}

MediaManagerError MpegManager::InitVideoCodec(int32_t width, int32_t height)
{
    DP_INFO_LOG("Add VideoEncoderFilter.");
    CodecInfo codecInfo;
    {
        std::lock_guard<std::mutex> lock(mediaInfoMutex_);
        DP_CHECK_RETURN_RET_LOG(mediaInfo_ == nullptr, OK, "mediaInfo_ is nullptr");
        codecInfo = mediaInfo_->codecInfo;
    }
    encoder_ = VideoEncoderFactory::CreateByMime(codecInfo.mimeType);
    DP_CHECK_ERROR_RETURN_RET_LOG(encoder_ == nullptr, ERROR_FAIL, "Video codec create failde.");

    auto callback = std::make_shared<VideoCodecCallback>(weak_from_this());
    auto ret = encoder_->SetCallback(callback);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL,
        "Video codec set callback failde, ret:%{public}d.", ret);

    auto errCode = ConfigVideoCodec(codecInfo, width, height);
    DP_CHECK_RETURN_RET(errCode != OK, errCode);
    
    std::string waterMarkInfo = mediaInfo_->waterMarkInfo;
    if (!waterMarkInfo.empty()) {
        auto buffer = CreateWatermarkBuffer(waterMarkInfo);
        DP_CHECK_EXECUTE(buffer != nullptr, encoder_->SetCustomBuffer(buffer));
    }

    codecSurface_ = encoder_->CreateInputSurface();
    DP_INFO_LOG("VideoEncoderFilter Prepare.");
    ret = encoder_->Prepare();
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL, "Video codec prepare failde.");

    DP_INFO_LOG("VideoEncoderFilter Start.");
    ret = encoder_->Start();
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL, "Video codec start failde.");

    return OK;
}

MediaManagerError MpegManager::ConfigVideoCodec(const CodecInfo& codecInfo, int32_t width, int32_t height)
{
    Format videoFormat;
    if (codecInfo.mimeType == MIME_VIDEO_HEVC) {
        videoFormat.PutIntValue(Tag::VIDEO_COLOR_RANGE, static_cast<int32_t>(codecInfo.colorRange));
        videoFormat.PutIntValue(Tag::VIDEO_COLOR_PRIMARIES, static_cast<int32_t>(codecInfo.colorPrimary));
        videoFormat.PutIntValue(Tag::VIDEO_COLOR_TRC, static_cast<int32_t>(codecInfo.colorTransferCharacter));
        videoFormat.PutIntValue(Tag::MEDIA_LEVEL, codecInfo.level);
        videoFormat.PutIntValue(Tag::MEDIA_PROFILE, codecInfo.profile);
    }
    videoFormat.PutIntValue(Tag::VIDEO_PIXEL_FORMAT, static_cast<int32_t>(Media::Plugins::VideoPixelFormat::NV12));
    videoFormat.PutIntValue(Tag::VIDEO_ENCODE_BITRATE_MODE, codecInfo.bitMode);
    videoFormat.PutStringValue(Tag::MIME_TYPE, codecInfo.mimeType);
    videoFormat.PutLongValue(Tag::MEDIA_BITRATE, codecInfo.bitRate);
    videoFormat.PutDoubleValue(Tag::VIDEO_FRAME_RATE, codecInfo.fps);
    videoFormat.PutIntValue(Tag::VIDEO_WIDTH, width);
    videoFormat.PutIntValue(Tag::VIDEO_HEIGHT, height);
    videoFormat.PutIntValue(Tag::VIDEO_ROTATION, codecInfo.rotation);
    videoFormat.PutLongValue(Tag::MEDIA_DURATION, codecInfo.duration);
    videoFormat.PutIntValue(Media::Tag::VIDEO_ENCODER_ENABLE_B_FRAME, codecInfo.isBFrame);
    DP_CHECK_EXECUTE(codecInfo.isBFrame,
        videoFormat.PutIntValue(Media::Tag::VIDEO_ENCODE_B_FRAME_GOP_MODE, codecInfo.bFrameGopMode));

    auto ret = encoder_->Configure(videoFormat);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL,
        "Video codec configure failde, ret: %{public}d.", ret);
    return OK;
}

bool MpegManager::UnInitVideoCodec()
{
    DP_DEBUG_LOG("entered.");
    NotifyEnd();
    std::unique_lock<std::mutex> lock(eosMutex_);
    bool ret = eosCondition_.wait_for(lock, std::chrono::milliseconds(WAIT_EOS_FRAME_TIME),
        [this]{return eos_ == true;});

    DP_CHECK_RETURN_RET(encoder_ == nullptr, false);
    if (isRunning_) {
        DP_INFO_LOG("VideoEncoderFilter Stop.");
        encoder_->Stop();
    }
    DP_INFO_LOG("VideoEncoderFilter Release.");
    encoder_->Release();
    return ret;
}

MediaManagerError MpegManager::InitVideoMakerSurface()
{
    DP_INFO_LOG("MetaDataFilter Prepare.");
    makerSurface_ = Surface::CreateSurfaceAsConsumer(VIDEO_MAKER_NAME);
    DP_CHECK_ERROR_RETURN_RET_LOG(makerSurface_ == nullptr, ERROR_FAIL, "Video maker surface create failde.");

    auto listener = sptr<VideoMakerListener>::MakeSptr(weak_from_this());
    auto ret = makerSurface_->RegisterConsumerListener((sptr<IBufferConsumerListener> &)listener);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL,
        "Video maker surface set callback failde, ret:%{public}d.", ret);

    return OK;
}

void MpegManager::UnInitVideoMaker()
{
    DP_DEBUG_LOG("entered.");
}

void MpegManager::OnBufferAvailable(uint32_t index, const std::shared_ptr<AVBuffer>& buffer)
{
    DP_DEBUG_LOG("OnBufferAvailable: pts: %{public}" PRId64 ", flag: %{public}u, dts: %{public}" PRId64,
        buffer->pts_, buffer->flag_, buffer->dts_);
    mediaManager_->WriteSample(Media::Plugins::MediaType::VIDEO, buffer);
    ReleaseBuffer(index);
    videoNum_.fetch_add(1);
    if (buffer->flag_ & AVCODEC_BUFFER_FLAG_EOS) {
        {
            std::lock_guard<std::mutex> lock(eosMutex_);
            eos_ = true;
        }
        eosCondition_.notify_one();
        DP_INFO_LOG("OnBufferAvailable video count: %{public}d.", videoNum_.load());
    }
    DP_CHECK_EXECUTE(processNotifer_ != nullptr, processNotifer_->CheckNotify(buffer->pts_));
}

MediaManagerError MpegManager::ReleaseBuffer(uint32_t index)
{
    auto ret = encoder_->ReleaseOutputBuffer(index);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL, "Video codec release buffer failde.");
    return OK;
}

void MpegManager::OnMakerBufferAvailable()
{
    DP_CHECK_ERROR_RETURN_LOG(makerSurface_ == nullptr, "MakerSurface is nullptr.");
    DP_DEBUG_LOG("OnMakerBufferAvailable: surface size: %{public}u", makerSurface_->GetQueueSize());

    int64_t timestamp;
    auto buffer = AcquireMakerBuffer(timestamp);
    DP_CHECK_ERROR_RETURN_LOG(buffer == nullptr, "MakerBuffer is nullptr.");
    if (timestamp < 0) {
        ReleaseMakerBuffer(buffer);
        return;
    }

    std::lock_guard<std::mutex> lock(makerMutex_);
    auto makerBuffer = AVBuffer::CreateAVBuffer(buffer);
    if (makerBuffer == nullptr) {
        ReleaseMakerBuffer(buffer);
        return;
    }

    makerBuffer->pts_ = timestamp;
    makerBuffer->memory_->SetSize(buffer->GetWidth());
    DP_DEBUG_LOG("MakerBuffer pts %{public}" PRId64 " marke size: %{public}d",
        makerBuffer->pts_, makerBuffer->memory_->GetSize());
    auto ret = mediaManager_->WriteSample(Media::Plugins::MediaType::TIMEDMETA, makerBuffer);
    DP_CHECK_ERROR_PRINT_LOG(ret != OK, "Video maker data write failde.");

    ret = ReleaseMakerBuffer(buffer);
    DP_CHECK_ERROR_PRINT_LOG(ret != OK, "Video maker data release buffer failde.");
}

sptr<SurfaceBuffer> MpegManager::AcquireMakerBuffer(int64_t& timestamp)
{
    OHOS::Rect damage;
    sptr<SurfaceBuffer> buffer;
    sptr<SyncFence> syncFence = SyncFence::INVALID_FENCE;
    auto surfaceRet = makerSurface_->AcquireBuffer(buffer, syncFence, timestamp, damage);
    DP_CHECK_ERROR_RETURN_RET_LOG(surfaceRet != SURFACE_ERROR_OK, nullptr,
        "Acquire maker buffer failed, ret: %{public}d", surfaceRet);

    surfaceRet = makerSurface_->DetachBufferFromQueue(buffer);
    DP_CHECK_ERROR_RETURN_RET_LOG(surfaceRet != SURFACE_ERROR_OK, nullptr,
        "Detach maker buffer failed, ret: %{public}d", surfaceRet);
    return buffer;
}

MediaManagerError MpegManager::ReleaseMakerBuffer(sptr<SurfaceBuffer>& buffer)
{
    auto ret = makerSurface_->AttachBufferToQueue(buffer);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != SURFACE_ERROR_OK, ERROR_FAIL, "Attach maker buffer failde.");

    ret = makerSurface_->ReleaseBuffer(buffer, -1);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != SURFACE_ERROR_OK, ERROR_FAIL, "Release maker buffer failde.");
    return OK;
}

DpsFdPtr MpegManager::GetFileFd(const std::string& requestId, int flags, const std::string& tag)
{
    const std::string path = PATH + requestId + tag;
    DP_CHECK_RETURN_RET(!CheckFilePath(path), nullptr);
    int fd;
    if (tag == TEMP_TAG) {
        tempPath_ = path;
        fd = open(path.c_str(), flags);
    } else {
        outPath_ = path;
        fd = open(path.c_str(), flags, S_IRUSR | S_IWUSR);
    }
    DP_CHECK_RETURN_RET(fd < 0, nullptr);
    DP_DEBUG_LOG("GetFileFd path: %{private}s, fd: %{public}d", path.c_str(), fd);
    return std::make_shared<DpsFd>(fd);
}

bool MpegManager::CheckFilePath(const std::string& path)
{
    const std::filesystem::path p(path);
    const auto fileName = p.filename().string();
    const auto filePath = p.parent_path().string();
    DP_DEBUG_LOG("filePath path: %{public}s, fileName: %{public}s", filePath.c_str(), fileName.c_str());
    DP_CHECK_ERROR_RETURN_RET_LOG(!std::filesystem::exists(filePath), false, "video path invalid.");
    const std::regex pattern(R"(^\d+_vid(_temp)?$)");
    return std::regex_match(fileName, pattern);
}

std::shared_ptr<AVBuffer> MpegManager::CreateWatermarkBuffer(const std::string& infoParam)
{
    WaterMarkInfo watermarkInfo;
    ParseWatermarkConfigFromJson(watermarkInfo, infoParam);
    auto imagePath = watermarkInfo.imagePath;
    char canonicalPath[PATH_MAX] = {0};
    DP_CHECK_RETURN_RET(realpath(imagePath.c_str(), canonicalPath) == nullptr, nullptr);

    DpsFd fd(open(canonicalPath, O_RDONLY));
    SourceOptions info { .formatHint = "image/png" };
    uint32_t error;
    auto imageSource = ImageSource::CreateImageSource(fd.GetFd(), info, error);
    DP_CHECK_ERROR_RETURN_RET_LOG(imageSource == nullptr, nullptr, "CreateImageSource error: %{public}u.", error);

    DecodeOptions decodeOptions { .allocatorType = AllocatorType::DMA_ALLOC, .editable = true };
    auto pixelMap = imageSource->CreatePixelMap(decodeOptions, error);
    DP_CHECK_ERROR_RETURN_RET_LOG(pixelMap == nullptr, nullptr, "Create pixelMap error: %{public}u.", error);

    error = pixelMap->ConvertAlphaFormat(*pixelMap.get(), false);
    DP_CHECK_ERROR_RETURN_RET_LOG(error != 0, nullptr, "ConvertAlphaFormat error: %{public}u.", error);

    pixelMap->scale(watermarkInfo.scaleFactor, watermarkInfo.scaleFactor);
    pixelMap->rotate(ROTATION_360 - watermarkInfo.rotation);
    sptr<SurfaceBuffer> surfaceBuffer = reinterpret_cast<SurfaceBuffer*>(pixelMap->GetFd());
    DP_CHECK_ERROR_RETURN_RET_LOG(surfaceBuffer == nullptr, nullptr, "SurfaceBuffer is nullptr");
    std::shared_ptr<AVBuffer> waterMarkBuffer = AVBuffer::CreateAVBuffer(surfaceBuffer);
    DP_CHECK_ERROR_RETURN_RET_LOG(waterMarkBuffer == nullptr, nullptr, "AVBuffer is nullptr");

    waterMarkBuffer->meta_->Set<Tag::VIDEO_ENCODER_ENABLE_WATERMARK>(true);
    waterMarkBuffer->meta_->Set<Tag::VIDEO_COORDINATE_X>(watermarkInfo.x);
    waterMarkBuffer->meta_->Set<Tag::VIDEO_COORDINATE_Y>(watermarkInfo.y);
    waterMarkBuffer->meta_->Set<Tag::VIDEO_COORDINATE_W>(watermarkInfo.width);
    waterMarkBuffer->meta_->Set<Tag::VIDEO_COORDINATE_H>(watermarkInfo.height);
    return waterMarkBuffer;
}

void MpegManager::ParseWatermarkConfigFromJson(WaterMarkInfo& waterMarkInfo, const std::string& infoParam)
{
    DP_CHECK_ERROR_RETURN_LOG(infoParam.empty() || !nlohmann::json::accept(infoParam),
        "infoParam is Illegal.");
    nlohmann::json waterMark = nlohmann::json::parse(infoParam);
    DP_CHECK_ERROR_RETURN_LOG(!waterMark.contains(IMAGE_PATH) || !waterMark[IMAGE_PATH].is_string(),
        "infoParam is Illegal: IMAGE_PATH field is missing.");
    waterMarkInfo.imagePath = waterMark[IMAGE_PATH];
    DP_CHECK_ERROR_RETURN_LOG(!waterMark.contains(ROTATION) || !waterMark[ROTATION].is_number_integer(),
        "infoParam is Illegal: ROTATION field is missing.");
    waterMarkInfo.rotation = waterMark[ROTATION];
    DP_CHECK_ERROR_RETURN_LOG(!waterMark.contains(SCALE_FACTOR) || !waterMark[SCALE_FACTOR].is_number_float(),
        "infoParam is Illegal: SCALE_FACTOR field is missing.");
    waterMarkInfo.scaleFactor = waterMark[SCALE_FACTOR];
    DP_CHECK_ERROR_RETURN_LOG(!waterMark.contains(COORDINATE_X) || !waterMark[COORDINATE_X].is_number_integer(),
        "infoParam is Illegal: COORDINATE_X field is missing.");
    waterMarkInfo.x = waterMark[COORDINATE_X];
    DP_CHECK_ERROR_RETURN_LOG(!waterMark.contains(COORDINATE_Y) || !waterMark[COORDINATE_Y].is_number_integer(),
        "infoParam is Illegal: COORDINATE_Y field is missing.");
    waterMarkInfo.y = waterMark[COORDINATE_Y];
    DP_CHECK_ERROR_RETURN_LOG(!waterMark.contains(COORDINATE_W) || !waterMark[COORDINATE_W].is_number_integer(),
        "infoParam is Illegal: COORDINATE_W field is missing.");
    waterMarkInfo.width = waterMark[COORDINATE_W];
    DP_CHECK_ERROR_RETURN_LOG(!waterMark.contains(COORDINATE_H) || !waterMark[COORDINATE_H].is_number_integer(),
        "infoParam is Illegal: COORDINATE_H field is missing.");
    waterMarkInfo.height = waterMark[COORDINATE_H];
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP