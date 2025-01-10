/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "media_manager.h"

#include "basic_definitions.h"
#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    const std::string TEMP_PTS_TAG = "tempPTS:";
    constexpr int32_t TEMP_PTS_SIZE = 50;
    constexpr int32_t DEFAULT_CHANNEL_COUNT = 1;
    constexpr int32_t DEFAULT_AUDIO_INPUT_SIZE = 1024 * DEFAULT_CHANNEL_COUNT * sizeof(short);
    constexpr int32_t DEFAULT_MARK_INPUT_SIZE = 1024 * 20;
    constexpr uint32_t DPS_FLAG_SYNC_FRAME = 10;
}

MediaManagerError MediaManager::Create(int32_t inFd, int32_t outFd, int32_t tempFd)
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_RET_LOG(inFd == INVALID_FD || outFd == INVALID_FD, ERROR_FAIL,
        "fd is invalid: inFd(%{public}d), outFd(%{public}d).", inFd, outFd);
    
    mediaInfo_ = std::make_shared<MediaInfo>();
    inputFileFd_ = inFd;
    outputFileFd_ = outFd;
    int64_t tempSize = -1;
    int64_t tempDuration = -1;
    int64_t tempBitRate = 0;
    if (tempFd != INVALID_FD) {
        tempFileFd_ = tempFd;
        tempSize = lseek(tempFileFd_, DEFAULT_OFFSET, SEEK_END);
        DP_CHECK_RETURN_RET(tempSize > 0 && InitRecoverReader(tempSize, tempDuration, tempBitRate) != OK, ERROR_FAIL);
    }

    lseek(inputFileFd_, DEFAULT_OFFSET, SEEK_SET);
    auto ret = InitReader();
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "Init reader failed.");

    ret = InitWriter();
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "Init writer failed.");

    if (tempFileFd_ > 0 && tempSize > 0) {
        ret = Recover(tempSize);
        DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "Recover failed.");

        RecoverDebugInfo();
    }

    mediaInfo_->recoverTime = pausePts_;
    mediaInfo_->codecInfo.numFrames = mediaInfo_->codecInfo.numFrames - finalFrameNum_;
    return OK;
}

MediaManagerError MediaManager::Pause()
{
    DP_DEBUG_LOG("entered.");
    if (!started_) {
        auto ret = ftruncate(outputFileFd_, 0);
        DP_WARNING_LOG("Stop failed, state is not started, ret: %{public}d.", ret);
        return PAUSE_RECEIVED;
    }

    DP_CHECK_ERROR_RETURN_RET_LOG(outputWriter_->Stop() == ERROR_FAIL, ERROR_FAIL, "Stop writer failed.");
    DP_CHECK_ERROR_RETURN_RET_LOG(resumePts_ < pausePts_, PAUSE_ABNORMAL, "Pause abnormal, will reprocess recover.");

    if (curProcessSyncPts_ == -1) {
        curProcessSyncPts_ = pausePts_;
    }
    
    std::string lastPts = TEMP_PTS_TAG + std::to_string(curProcessSyncPts_);
    DP_INFO_LOG("pausePts: %{public}s", lastPts.c_str());
    auto off = lseek(outputFileFd_, 0, SEEK_END);
    DP_CHECK_ERROR_RETURN_RET_LOG(off == static_cast<off_t>(ERROR_FAIL), ERROR_FAIL, "Write temp lseek failed.");
    auto ret = write(outputFileFd_, lastPts.c_str(), lastPts.size());
    DP_CHECK_ERROR_RETURN_RET_LOG(ret == static_cast<int64_t>(ERROR_FAIL), ERROR_FAIL, "Write temp final pts failed.");
    return PAUSE_RECEIVED;
}

MediaManagerError MediaManager::Stop()
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_RET_LOG(!started_, ERROR_FAIL, "Stop failed, state is not started.");

    if (hasAudio_) {
        DP_INFO_LOG("Start copy audio track.");
        DP_CHECK_ERROR_RETURN_RET_LOG(CopyAudioTrack() == ERROR_FAIL, ERROR_FAIL, "Read audio track failed.");
    }

    DP_CHECK_ERROR_RETURN_RET_LOG(outputWriter_->Stop() == ERROR_FAIL, ERROR_FAIL, "Stop writer failed.");
    started_ = false;
    return OK;
}

MediaManagerError MediaManager::ReadSample(Media::Plugins::MediaType type, std::shared_ptr<AVBuffer>& sample)
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_RET_LOG(inputReader_ == nullptr, ERROR_FAIL, "Reader is nullptr.");

    auto ret = inputReader_->Read(type, sample);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret == ERROR_FAIL, ERROR_FAIL, "Read sample failed.");
    DP_CHECK_RETURN_RET_LOG(ret == EOS, EOS, "Read sample finished.");
    return OK;
}

MediaManagerError MediaManager::WriteSample(Media::Plugins::MediaType type, const std::shared_ptr<AVBuffer>& sample)
{
    DP_DEBUG_LOG("entered, track type: %{public}d", type);
    DP_CHECK_ERROR_RETURN_RET_LOG(outputWriter_ == nullptr, ERROR_FAIL, "Writer is nullptr.");

    if (type == Media::Plugins::MediaType::TIMEDMETA) {
        DP_CHECK_ERROR_RETURN_RET_LOG(!started_, ERROR_FAIL, "Writer is not start.");

        auto ret = outputWriter_->Write(type, sample);
        DP_CHECK_ERROR_RETURN_RET_LOG(ret == ERROR_FAIL, ERROR_FAIL, "Writer meta sample failed.");
        return OK;
    }

    if (!started_) {
        auto ret = outputWriter_->Start();
        DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "Start writer failed.");
        started_ = true;
    }

    auto ret = outputWriter_->Write(type, sample);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret == ERROR_FAIL, ERROR_FAIL, "Writer sample failed.");

    if (sample->flag_ == AVCODEC_BUFFER_FLAG_SYNC_FRAME) {
        curProcessSyncPts_ = sample->pts_;
    }

    DP_DEBUG_LOG("ProcessPts: %{public}" PRId64 ", ProcessSyncPts: %{public}" PRId64,
        sample->pts_, curProcessSyncPts_);
    return OK;
}

MediaManagerError MediaManager::Recover(const int64_t size)
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_RET_LOG(recoverReader_ == nullptr, ERROR_FAIL, "Recover reader is nullptr.");
    DP_CHECK_ERROR_RETURN_RET_LOG(outputWriter_ == nullptr, ERROR_FAIL, "Recover writer is nullptr.");

    auto ret = outputWriter_->Start();
    DP_CHECK_ERROR_RETURN_RET_LOG(ret == ERROR_FAIL, ERROR_FAIL, "Start recovering failed.");

    started_ = true;
    int32_t frameNum = 0;
    AVBufferConfig config;
    config.size = size;
    config.memoryType = MemoryType::SHARED_MEMORY;
    auto sample = AVBuffer::CreateAVBuffer(config);
    DP_CHECK_ERROR_RETURN_RET_LOG(sample == nullptr, ERROR_FAIL, "Create video buffer failed.");

    int64_t curPts = 0;
    while (true) {
        ret = recoverReader_->Read(Media::Plugins::MediaType::VIDEO, sample);
        DP_LOOP_ERROR_RETURN_RET_LOG(ret == ERROR_FAIL, ERROR_FAIL, "Read temp data failed.");

        ++frameNum;
        curPts = sample->pts_;
        if (sample->flag_ == AVCODEC_BUFFER_FLAG_SYNC_FRAME || sample->flag_ == DPS_FLAG_SYNC_FRAME) {
            resumePts_ = sample->pts_;
            finalFrameNum_ = frameNum;
        }
        DP_LOOP_BREAK_LOG(sample->pts_ == pausePts_ || ret == EOS, "Recovering finished.");

        DP_DEBUG_LOG("VideoInfo pts: %{public}" PRId64 ", frame-num(%{public}d), resume pts: %{public}" PRId64,
            sample->pts_, frameNum, resumePts_);
        ret = outputWriter_->Write(Media::Plugins::MediaType::VIDEO, sample);
        DP_LOOP_ERROR_RETURN_RET_LOG(ret == ERROR_FAIL, ERROR_FAIL, "Write temp data failed.");
    }
    DP_INFO_LOG("Recover sync end, process total num: %{public}d, "
        "resumePts: %{public}" PRId64", curPts: %{public}" PRId64, finalFrameNum_, resumePts_, curPts);
    outputWriter_->SetLastPause(pausePts_);
    return OK;
}

MediaManagerError MediaManager::RecoverDebugInfo()
{
    DP_CHECK_ERROR_RETURN_RET_LOG(recoverReader_ == nullptr, ERROR_FAIL, "Recover reader is nullptr.");
    DP_CHECK_ERROR_RETURN_RET_LOG(outputWriter_ == nullptr, ERROR_FAIL, "Recover writer is nullptr.");

    DP_CHECK_ERROR_RETURN_RET_LOG(!started_, ERROR_FAIL, "Recovering debug data failed.");

    int32_t frameNum = 0;
    AVBufferConfig config;
    config.size = DEFAULT_MARK_INPUT_SIZE;
    config.memoryType = MemoryType::SHARED_MEMORY;
    auto sample = AVBuffer::CreateAVBuffer(config);
    DP_CHECK_ERROR_RETURN_RET_LOG(sample == nullptr, ERROR_FAIL, "Create meta buffer failed.");
    while (true) {
        auto ret = recoverReader_->Read(Media::Plugins::MediaType::TIMEDMETA, sample);
        DP_LOOP_ERROR_RETURN_RET_LOG(ret == ERROR_FAIL, ERROR_DEBUG_INFO, "Read debug data failed.");

        ++frameNum;
        DP_DEBUG_LOG("DebugInfo pts: %{public}" PRId64 ", frame-num(%{public}d)", sample->pts_, frameNum);
        DP_LOOP_BREAK_LOG(ret == EOS, "Recovering debug data finished.");

        ret = outputWriter_->Write(Media::Plugins::MediaType::TIMEDMETA, sample);
        DP_LOOP_ERROR_RETURN_RET_LOG(ret == ERROR_FAIL, ERROR_DEBUG_INFO, "Write debug data failed.");
    }
    DP_INFO_LOG("Recover debug end, process total num: %{public}d", frameNum);
    return OK;
}

MediaManagerError MediaManager::CopyAudioTrack()
{
    DP_CHECK_ERROR_RETURN_RET_LOG(inputReader_ == nullptr, ERROR_FAIL, "Copy reader is nullptr.");
    DP_CHECK_ERROR_RETURN_RET_LOG(outputWriter_ == nullptr, ERROR_FAIL, "Copy writer is nullptr.");
    DP_CHECK_ERROR_RETURN_RET_LOG(inputReader_->Reset(0) != OK, ERROR_FAIL, "Reset reader failed.");

    AVBufferConfig config;
    config.size = DEFAULT_AUDIO_INPUT_SIZE;
    config.memoryType = MemoryType::SHARED_MEMORY;
    auto sample = AVBuffer::CreateAVBuffer(config);
    DP_CHECK_ERROR_RETURN_RET_LOG(sample == nullptr, ERROR_FAIL, "Create audio buffer failed.");

    while (true) {
        auto ret = inputReader_->Read(Media::Plugins::MediaType::AUDIO, sample);
        DP_LOOP_ERROR_RETURN_RET_LOG(ret == ERROR_FAIL, ERROR_FAIL, "Read audio data failed.");
        DP_LOOP_BREAK_LOG(ret == EOS, "Read audio data finished.");

        ret = outputWriter_->Write(Media::Plugins::MediaType::AUDIO, sample);
        DP_LOOP_ERROR_RETURN_RET_LOG(ret == ERROR_FAIL, ERROR_FAIL, "Write audio data failed.");
    }
    return OK;
}

MediaManagerError MediaManager::InitReader()
{
    DP_DEBUG_LOG("entered.");
    inputReader_ = std::make_shared<Reader>();
    auto ret = inputReader_->Create(inputFileFd_);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "Open the video source failed, cannot demux data.");

    ret = inputReader_->GetMediaInfo(mediaInfo_);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "Get meta info failed, cannot demux data.");
    return OK;
}

MediaManagerError MediaManager::InitWriter()
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_RET_LOG(inputReader_ == nullptr, ERROR_FAIL, "Input reader is nullptr.");

    auto tracks = inputReader_->GetTracks();
    hasAudio_ = tracks.find(Media::Plugins::MediaType::AUDIO) == tracks.end() ? false : true;
    outputWriter_ = std::make_shared<Writer>();
    auto ret = outputWriter_->Create(outputFileFd_, tracks);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "Don't create mux data.");

    ret = outputWriter_->AddMediaInfo(mediaInfo_);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "Add metadata to writer failed.");
    return OK;
}

MediaManagerError MediaManager::InitRecoverReader(const int64_t size, int64_t& duration, int64_t& bitRate)
{
    DP_DEBUG_LOG("entered.");
    recoverReader_ = std::make_shared<Reader>();
    DP_CHECK_ERROR_RETURN_RET_LOG(recoverReader_ == nullptr, ERROR_FAIL, "Init recover reader failed.");
    DP_CHECK_ERROR_RETURN_RET_LOG(GetRecoverInfo(size) != OK, ERROR_FAIL, "Invalid final info.");

    auto ret = recoverReader_->Create(tempFileFd_);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret == ERROR_FAIL, ERROR_FAIL, "Open recover source failed, cannot demux data.");

    auto recover = std::make_shared<MediaInfo>();
    ret = recoverReader_->GetMediaInfo(recover);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret == ERROR_FAIL, ERROR_FAIL, "Get recover media info failed.");

    duration = recover->codecInfo.duration;
    bitRate = recover->codecInfo.bitRate;
    return OK;
}

MediaManagerError MediaManager::GetRecoverInfo(const int64_t size)
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_RET_LOG(size < TEMP_PTS_SIZE, ERROR_FAIL, "Invalid recover file size.");

    auto off = lseek(tempFileFd_, size - TEMP_PTS_SIZE, SEEK_SET);
    DP_CHECK_ERROR_RETURN_RET_LOG(off == static_cast<off_t>(ERROR_FAIL), ERROR_FAIL, "Lseek recover failed.");

    std::vector<uint8_t> tempTail(TEMP_PTS_SIZE);
    auto ret = read(tempFileFd_, tempTail.data(), TEMP_PTS_SIZE);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret == static_cast<int64_t>(ERROR_FAIL), ERROR_FAIL, "Read recover pts failed.");

    std::vector<uint8_t> tag2search(TEMP_PTS_TAG.begin(), TEMP_PTS_TAG.end());
    auto findTag = std::search(tempTail.begin(), tempTail.end(), tag2search.begin(), tag2search.end());
    DP_CHECK_ERROR_RETURN_RET_LOG(findTag == tempTail.end(), ERROR_FAIL, "Cannot find temp pts tag.");

    std::string pauseTime(findTag + TEMP_PTS_TAG.size(), tempTail.end());
    pausePts_ = std::stol(pauseTime);
    DP_INFO_LOG("pausePts: %{public}s", pauseTime.c_str());
    lseek(tempFileFd_, 0, SEEK_SET);
    return OK;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS