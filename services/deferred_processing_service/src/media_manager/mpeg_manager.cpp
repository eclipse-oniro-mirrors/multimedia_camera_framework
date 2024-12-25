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

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
constexpr int64_t DEFAULT_TIME_TAMP = 0;

class MpegManager::VideoCodecCallback : public MediaCodecCallback {
public:
    explicit VideoCodecCallback(const std::weak_ptr<MpegManager>& mpegManager) : mpegManager_(mpegManager)
    {
        DP_DEBUG_LOG("entered.");
    }

    ~VideoCodecCallback()
    {
        DP_DEBUG_LOG("entered.");
    }

    void OnError(AVCodecErrorType errorType, int32_t errorCode) override;
    void OnOutputFormatChanged(const Format &format) override;
    void OnInputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer) override;
    void OnOutputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer) override;

private:
    std::weak_ptr<MpegManager> mpegManager_;
};

void MpegManager::VideoCodecCallback::OnError(AVCodecErrorType errorType, int32_t errorCode)
{
    DP_ERR_LOG("entered, errorType: %{public}d, errorCode: %{public}d", errorType, errorCode);
}

void MpegManager::VideoCodecCallback::OnOutputFormatChanged(const Format &format)
{
    DP_DEBUG_LOG("entered.");
}

void MpegManager::VideoCodecCallback::OnInputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer)
{
    DP_DEBUG_LOG("entered.");
    (void)index;
}

void MpegManager::VideoCodecCallback::OnOutputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer)
{
    DP_CHECK_ERROR_RETURN_LOG(buffer == nullptr, "OutputBuffer is null");
    auto manager = mpegManager_.lock();
    if (manager != nullptr) {
        manager->OnBufferAvailable(index, buffer);
    }
}

MpegManager::MpegManager()
{
    DP_DEBUG_LOG("entered.");
    mediaManager_ = std::make_unique<MediaManager>();
}

MpegManager::~MpegManager()
{
    DP_DEBUG_LOG("entered.");
    mediaManager_ = nullptr;
    codecSurface_ = nullptr;
    processThread_ = nullptr;
    mediaInfo_ = nullptr;
    outputFd_ = nullptr;
    tempFd_ = nullptr;
    remove(tempPath_.c_str());
    if (result_ == MediaResult::PAUSE) {
        int ret = rename(outPath_.c_str(), tempPath_.c_str());
        if (ret != 0) {
            DP_ERR_LOG("rename %{public}s to %{public}s failde, ret: %{public}d",
                outPath_.c_str(), tempPath_.c_str(), ret);
        } else {
            DP_INFO_LOG("rename %{public}s to %{public}s success.", outPath_.c_str(), tempPath_.c_str());
        }
    }
}

MediaManagerError MpegManager::Init(const std::string& requestId, const sptr<IPCFileDescriptor>& inputFd)
{
    DP_DEBUG_LOG("entered.");
    outputFd_ = GetFileFd(requestId, O_CREAT | O_RDWR, OUT_TAG);
    DP_CHECK_ERROR_RETURN_RET_LOG(outputFd_ == nullptr, ERROR_FAIL, "output video create failde.");

    tempFd_ = GetFileFd(requestId, O_RDONLY, TEMP_TAG);
    DP_CHECK_ERROR_RETURN_RET_LOG(tempFd_ == nullptr, ERROR_FAIL, "temp video create failde.");

    auto ret = mediaManager_->Create(inputFd->GetFd(), outputFd_->GetFd(), tempFd_->GetFd());
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "media manager create failde.");

    mediaManager_->GetMediaInfo(mediaInfo_);
    DP_CHECK_ERROR_RETURN_RET_LOG(InitVideoCodec() != OK, ERROR_FAIL, "init video codec failde.");

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

uint64_t MpegManager::GetProcessTimeStamp()
{
    DP_CHECK_RETURN_RET(mediaInfo_->recoverTime < DEFAULT_TIME_TAMP, DEFAULT_TIME_TAMP);
    return static_cast<uint64_t>(mediaInfo_->recoverTime);
}

MediaManagerError MpegManager::NotifyEnd()
{
    auto ret = encoder_->NotifyEos();
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL, "video codec notify end failde.");
    return OK;
}

MediaManagerError MpegManager::ReleaseBuffer(uint32_t index)
{
    auto ret = encoder_->ReleaseOutputBuffer(index);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL, "video codec release buffer failde.");
    return OK;
}

sptr<IPCFileDescriptor> MpegManager::GetResultFd()
{
    return outputFd_;
}

MediaManagerError MpegManager::InitVideoCodec()
{
    DP_INFO_LOG("entered.");
    auto codecInfo = mediaInfo_->codecInfo;
    encoder_ = VideoEncoderFactory::CreateByMime(codecInfo.mimeType);
    DP_CHECK_ERROR_RETURN_RET_LOG(encoder_ == nullptr, ERROR_FAIL, "video codec create failde.");

    auto callback = std::make_shared<VideoCodecCallback>(weak_from_this());
    auto ret = encoder_->SetCallback(callback);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL, "video codec set callback failde.");

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
        "video codec configure failde, ret: %{public}d.", ret);

    codecSurface_ = encoder_->CreateInputSurface();
    ret = encoder_->Prepare();
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL, "video codec prepare failde.");

    ret = encoder_->Start();
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL, "video codec start failde.");

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
    encoder_ = nullptr;
}

void MpegManager::OnBufferAvailable(uint32_t index, const std::shared_ptr<AVBuffer>& buffer)
{
    auto ret = mediaManager_->WriteSample(TrackType::AV_KEY_VIDEO_TYPE, buffer);
    DP_CHECK_ERROR_RETURN_LOG(ret != OK, "video codec write failde.");
    ret = ReleaseBuffer(index);
    DP_CHECK_ERROR_RETURN_LOG(ret != OK, "video codec release buffer failde.");
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