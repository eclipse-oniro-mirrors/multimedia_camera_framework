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

#include "mpeg_manager.h"

#include <fcntl.h>

#include "dp_log.h"
#include "sync_fence.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    const std::string VIDEO_MAKER_NAME = "DpsVideoMaker";
    constexpr int64_t DEFAULT_TIME_TAMP = 0;
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
    }
}

MediaManagerError MpegManager::Init(const std::string& requestId, const sptr<IPCFileDescriptor>& inputFd)
{
    DP_DEBUG_LOG("entered.");
    outputFd_ = GetFileFd(requestId, O_CREAT | O_RDWR, OUT_TAG);
    DP_CHECK_ERROR_RETURN_RET_LOG(outputFd_ == nullptr, ERROR_FAIL, "Output video create failde.");

    tempFd_ = GetFileFd(requestId, O_RDONLY, TEMP_TAG);
    DP_CHECK_ERROR_RETURN_RET_LOG(tempFd_ == nullptr, ERROR_FAIL, "Temp video create failde.");

    auto ret = mediaManager_->Create(inputFd->GetFd(), outputFd_->GetFd(), tempFd_->GetFd());
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "Media manager create failde.");

    mediaManager_->GetMediaInfo(mediaInfo_);
    DP_CHECK_ERROR_RETURN_RET_LOG(InitVideoCodec() != OK, ERROR_FAIL, "Init video codec failde.");

    DP_CHECK_ERROR_RETURN_RET_LOG(InitVideoMakerSurface() != OK, ERROR_FAIL, "Init video maker surface failde.");
    isRunning_.store(true);
    return OK;
}

MediaManagerError MpegManager::UnInit(const MediaResult result)
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_RETURN_RET(!isRunning_.load(), OK);
    result_ = result;
    if (result == MediaResult::PAUSE) {
        if (mediaManager_->Pause() == PAUSE_ABNORMAL) {
            remove(outPath_.c_str());
        }
    } else {
        mediaManager_->Stop();
    }
    UnInitVideoCodec();
    isRunning_.store(false);
    return OK;
}

sptr<Surface> MpegManager::GetSurface()
{
    return codecSurface_;
}

sptr<Surface> MpegManager::GetMakerSurface()
{
    return makerSurface_;
}

uint64_t MpegManager::GetProcessTimeStamp()
{
    DP_CHECK_RETURN_RET(mediaInfo_->recoverTime < DEFAULT_TIME_TAMP, DEFAULT_TIME_TAMP);
    return static_cast<uint64_t>(mediaInfo_->recoverTime);
}

MediaManagerError MpegManager::NotifyEnd()
{
    auto ret = encoder_->NotifyEos();
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL, "Video codec notify end failde.");
    return OK;
}

sptr<IPCFileDescriptor> MpegManager::GetResultFd()
{
    return outputFd_;
}

MediaManagerError MpegManager::InitVideoCodec()
{
    DP_INFO_LOG("DPS_VIDEO: Create video codec.");
    auto codecInfo = mediaInfo_->codecInfo;
    encoder_ = VideoEncoderFactory::CreateByMime(codecInfo.mimeType);
    DP_CHECK_ERROR_RETURN_RET_LOG(encoder_ == nullptr, ERROR_FAIL, "Video codec create failde.");

    auto callback = std::make_shared<VideoCodecCallback>(weak_from_this());
    auto ret = encoder_->SetCallback(callback);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL,
        "Video codec set callback failde, ret:%{public}d.", ret);

    Format videoFormat;
    if (codecInfo.mimeType == MINE_VIDEO_HEVC) {
        videoFormat.PutIntValue(Tag::VIDEO_COLOR_RANGE, static_cast<int32_t>(codecInfo.colorRange));
        videoFormat.PutIntValue(Tag::VIDEO_COLOR_PRIMARIES, static_cast<int32_t>(codecInfo.colorPrimary));
        videoFormat.PutIntValue(Tag::VIDEO_COLOR_TRC, static_cast<int32_t>(codecInfo.colorTransferCharacter));
        videoFormat.PutIntValue(Tag::MEDIA_LEVEL, codecInfo.level);
        videoFormat.PutIntValue(Tag::MEDIA_PROFILE, codecInfo.profile);
    }
    videoFormat.PutIntValue(Tag::VIDEO_ENCODE_BITRATE_MODE, codecInfo.bitMode);
    videoFormat.PutIntValue(Tag::VIDEO_PIXEL_FORMAT, static_cast<int32_t>(PixelFormat::PIX_FMT_NV12));
    videoFormat.PutStringValue(Tag::MIME_TYPE, codecInfo.mimeType);
    videoFormat.PutLongValue(Tag::MEDIA_BITRATE, codecInfo.bitRate);
    videoFormat.PutDoubleValue(Tag::VIDEO_FRAME_RATE, codecInfo.fps);
    videoFormat.PutIntValue(Tag::VIDEO_WIDTH, codecInfo.width);
    videoFormat.PutIntValue(Tag::VIDEO_HEIGHT, codecInfo.height);
    videoFormat.PutIntValue(Tag::VIDEO_ROTATION, codecInfo.rotation);
    videoFormat.PutLongValue(Tag::MEDIA_DURATION, codecInfo.duration);

    ret = encoder_->Configure(videoFormat);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL,
        "Video codec configure failde, ret: %{public}d.", ret);

    codecSurface_ = encoder_->CreateInputSurface();
    ret = encoder_->Prepare();
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL, "Video codec prepare failde.");

    ret = encoder_->Start();
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL, "Video codec start failde.");

    return OK;
}

void MpegManager::UnInitVideoCodec()
{
    DP_DEBUG_LOG("entered.");
    if (isRunning_) {
        encoder_->Stop();
    }
    DP_CHECK_RETURN(encoder_ == nullptr);
    encoder_->Release();
}

MediaManagerError MpegManager::InitVideoMakerSurface()
{
    DP_INFO_LOG("DPS_VIDEO: Create video maker surface.");
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
    DP_DEBUG_LOG("OnBufferAvailable: pts: %{public}" PRId64 ", duration: %{public}" PRId64,
        buffer->pts_, buffer->duration_);
    auto ret = mediaManager_->WriteSample(Media::Plugins::MediaType::VIDEO, buffer);
    DP_CHECK_ERROR_PRINT_LOG(ret != OK, "Video codec write failde.");

    ret = ReleaseBuffer(index);
    DP_CHECK_ERROR_PRINT_LOG(ret != OK, "Video codec release buffer failde.");
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

    std::lock_guard<std::mutex> lock(makerMutex_);
    auto makerBuffer = AVBuffer::CreateAVBuffer(buffer);
    DP_CHECK_ERROR_RETURN_LOG(makerBuffer == nullptr, "CreateAVBuffer is failde.");

    makerBuffer->pts_ = timestamp;
    DP_DEBUG_LOG("MakerBuffer pts %{public}" PRId64, makerBuffer->pts_);
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

sptr<IPCFileDescriptor> MpegManager::GetFileFd(const std::string& requestId, int flags, const std::string& tag)
{
    std::string path = PATH + requestId + tag;
    if (tag == TEMP_TAG) {
        tempPath_ = path;
    } else {
        outPath_ = path;
    }
    DP_DEBUG_LOG("GetFileFd path: %{public}s", path.c_str());
    int fd = open(path.c_str(), flags, S_IRUSR | S_IWUSR);
    return sptr<IPCFileDescriptor>::MakeSptr(fd);
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS