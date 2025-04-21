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
#include "dp_utils.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    const std::string TEMP_PTS_TAG = "tempPTS:";
    constexpr int32_t TEMP_PTS_SIZE = 50;
    constexpr int32_t DEFAULT_CHANNEL_COUNT = 1;
    constexpr int32_t DEFAULT_AUDIO_INPUT_SIZE = 1024 * DEFAULT_CHANNEL_COUNT * sizeof(short);
    constexpr int32_t DEFAULT_MARK_INPUT_SIZE = 1024 * 20;
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
    if (curIFramePts_ == -1) {
        curIFramePts_ = pausePts_;
    }
    DP_CHECK_ERROR_RETURN_RET_LOG(curIFramePts_ < pausePts_, PAUSE_ABNORMAL, "Pause abnormal, will reprocess recover.");

    std::string lastPts = TEMP_PTS_TAG + std::to_string(curIFramePts_);
    DP_INFO_LOG("pausePts: %{public}s", lastPts.c_str());
    auto off = lseek(outputFileFd_, 0, SEEK_END);
    DP_CHECK_ERROR_RETURN_RET_LOG(off == static_cast<off_t>(ERROR_FAIL), ERROR_FAIL, "Write temp lseek failed.");
    auto ret = write(outputFileFd_, lastPts.c_str(), lastPts.size());
    DP_CHECK_ERROR_RETURN_RET_LOG(ret == static_cast<int64_t>(ERROR_FAIL), ERROR_FAIL, "Write temp final pts failed.");
    return PAUSE_RECEIVED;
}

MediaManagerError MediaManager::Stop()
{
    DP_CHECK_ERROR_RETURN_RET_LOG(!started_, ERROR_FAIL, "Stop failed, state is not started.");

    if (hasAudio_) {
        DP_DEBUG_LOG("Start copy audio track.");
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

    auto ret = outputWriter_->Write(type, sample);
    if (type == Media::Plugins::MediaType::VIDEO) {
        finalPtsToDrop_ = sample->pts_;
        // Update I-frame timestamp only for key frames.
        if (sample->flag_ & AVCODEC_BUFFER_FLAG_SYNC_FRAME) {
            curIFramePts_ = finalPtsToDrop_;
        }
    }
    DP_CHECK_ERROR_RETURN_RET_LOG(ret == ERROR_FAIL, ERROR_FAIL, "Writer sample type: %{public}d failed.", type);

    DP_DEBUG_LOG("ProcessPts: %{public}" PRId64 ", ProcessSyncPts: %{public}" PRId64,
        sample->pts_, curIFramePts_);
    return OK;
}

void MediaManager::AddUserMeta(const std::shared_ptr<Meta>& userMeta)
{
    DP_CHECK_ERROR_RETURN_LOG(outputWriter_ == nullptr, "Writer is nullptr.");
    outputWriter_->AddUserMeta(userMeta);
}

MediaManagerError MediaManager::Recover(const int64_t size)
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_RET_LOG(recoverReader_ == nullptr, ERROR_FAIL, "Recover reader is nullptr.");
    DP_CHECK_ERROR_RETURN_RET_LOG(outputWriter_ == nullptr, ERROR_FAIL, "Recover writer is nullptr.");

    int32_t frameNum = 0;
    AVBufferConfig config;
    config.size = size;
    config.memoryType = MemoryType::SHARED_MEMORY;
    auto sample = AVBuffer::CreateAVBuffer(config);
    DP_CHECK_ERROR_RETURN_RET_LOG(sample == nullptr, ERROR_FAIL, "Create video buffer failed.");

    int64_t curPts = 0;
    for (;;) {
        auto ret = recoverReader_->Read(Media::Plugins::MediaType::VIDEO, sample);
        DP_LOOP_ERROR_RETURN_RET_LOG(ret == ERROR_FAIL, ERROR_FAIL, "Read temp data failed.");

        curPts = sample->pts_;
        if (sample->flag_ & AVCODEC_BUFFER_FLAG_SYNC_FRAME) {
            recoverPts_ = curPts;
        }
        DP_LOOP_BREAK_LOG(curPts == pausePts_ || ret == EOS, "Recovering finished.");

        ret = outputWriter_->Write(Media::Plugins::MediaType::VIDEO, sample);
        DP_LOOP_ERROR_RETURN_RET_LOG(ret == ERROR_FAIL, ERROR_FAIL, "Write temp data failed.");

        DP_DEBUG_LOG("VideoInfo frame-num(%{public}d), curPts: %{public}" PRId64 ", recoverPts: %{public}" PRId64,
            frameNum, curPts, recoverPts_);
        ++frameNum;
    }
    DP_INFO_LOG("Recover end, process total num: %{public}d, recoverPts: %{public}" PRId64
        ", pausePts: %{public}" PRId64" , curPts: %{public}" PRId64,
        frameNum, recoverPts_, pausePts_, curPts);
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
    for (;;) {
        auto ret = recoverReader_->Read(Media::Plugins::MediaType::TIMEDMETA, sample);
        DP_LOOP_ERROR_RETURN_RET_LOG(ret == ERROR_FAIL, ERROR_DEBUG_INFO, "Read debug data failed.");
        DP_LOOP_BREAK_LOG(sample->pts_ == pausePts_ || ret == EOS, "Recovering debug data finished.");

        ret = outputWriter_->Write(Media::Plugins::MediaType::TIMEDMETA, sample);
        DP_LOOP_ERROR_RETURN_RET_LOG(ret == ERROR_FAIL, ERROR_DEBUG_INFO, "Write debug data failed.");

        DP_DEBUG_LOG("DebugInfo frame-num(%{public}d), curPts: %{public}" PRId64, frameNum, sample->pts_);
        ++frameNum;
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

    int32_t frameNum = 0;
    for (;;) {
        auto ret = inputReader_->Read(Media::Plugins::MediaType::AUDIO, sample);
        DP_LOOP_ERROR_RETURN_RET_LOG(ret == ERROR_FAIL, ERROR_FAIL, "Read audio data failed.");
        DP_LOOP_BREAK_LOG(ret == EOS, "Read audio data finished.");
        DP_LOOP_BREAK_LOG(finalPtsToDrop_ != -1 && sample->pts_ > finalPtsToDrop_,
            "Video pts: %{public}" PRId64 ", drop audio sample from pts: %{public}" PRId64 " to the end.",
            finalPtsToDrop_, sample->pts_);

        ret = outputWriter_->Write(Media::Plugins::MediaType::AUDIO, sample);
        DP_LOOP_ERROR_RETURN_RET_LOG(ret == ERROR_FAIL, ERROR_FAIL, "Write audio data failed.");

        DP_DEBUG_LOG("AudioInfo frame-num(%{public}d), pts: %{public}" PRId64, frameNum, sample->pts_);
        ++frameNum;
    }
    DP_INFO_LOG("CopyAudio end, process total num: %{public}d", frameNum);
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

    if (!started_) {
        ret = outputWriter_->Start();
        DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "Start writer failed.");
        started_ = true;
    }
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
    DP_INFO_LOG("Recover pausePts: %{public}s", pauseTime.c_str());
    if (!StrToI64(pauseTime, pausePts_)) {
        pausePts_ = 0;
    }
    lseek(tempFileFd_, 0, SEEK_SET);
    return OK;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS