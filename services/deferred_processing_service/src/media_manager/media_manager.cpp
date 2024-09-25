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

#include "media_manager.h"

#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    const std::string TEMP_PTS_TAG = "tempPTS:";
    constexpr int32_t TEMP_PTS_SIZE = 50;
    constexpr int32_t DEFAULT_CHANNEL_COUNT = 1;
    constexpr int32_t DEFAULT_AUDIO_INPUT_SIZE = 1024 * DEFAULT_CHANNEL_COUNT * sizeof(short);
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
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "init reader failed.");

    ret = InitWriter();
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "init writer failed.");

    if (tempFileFd_ > 0 && tempSize > 0) {
        ret = Recover(tempSize);
        DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "recover failed.");
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
        DP_WARNING_LOG("stop failed, state is not started, ret:%{public}d.", ret);
        return PAUSE_RECEIVED;
    }

    DP_CHECK_ERROR_RETURN_RET_LOG(outputWriter_->Stop() == ERROR_FAIL, ERROR_FAIL, "stop writer failed.");
    DP_CHECK_ERROR_RETURN_RET_LOG(resumePts_ < pausePts_, PAUSE_ABNORMAL, "pause abnormal, will reprocess recover.");

    if (finalSyncPts_ == -1) {
        finalSyncPts_ = pausePts_;
    }
    
    std::string lastPts = TEMP_PTS_TAG + std::to_string(finalSyncPts_);
    DP_INFO_LOG("lastPts: %{public}s", lastPts.c_str());
    auto off = lseek(outputFileFd_, 0, SEEK_END);
    DP_CHECK_ERROR_RETURN_RET_LOG(off == static_cast<off_t>(ERROR_FAIL), ERROR_FAIL, "write temp lseek failed.");
    auto ret = write(outputFileFd_, lastPts.c_str(), lastPts.size());
    DP_CHECK_ERROR_RETURN_RET_LOG(ret == static_cast<int64_t>(ERROR_FAIL), ERROR_FAIL, "write temp final pts failed.");
    return PAUSE_RECEIVED;
}

MediaManagerError MediaManager::Stop()
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_RET_LOG(!started_, ERROR_FAIL, "stop failed, state is not started.");

    if (hasAudio_) {
        DP_INFO_LOG("start copy audio track.");
        DP_CHECK_ERROR_RETURN_RET_LOG(CopyAudioTrack() == ERROR_FAIL, ERROR_FAIL, "read audio track failed.");
    }

    DP_CHECK_ERROR_RETURN_RET_LOG(outputWriter_->Stop() == ERROR_FAIL, ERROR_FAIL, "stop writer failed.");
    started_ = false;
    return OK;
}

MediaManagerError MediaManager::ReadSample(TrackType type, std::shared_ptr<AVBuffer>& sample)
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_RET_LOG(inputReader_ == nullptr, ERROR_FAIL, "reader is nullptr.");

    auto ret = inputReader_->Read(type, sample);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret == ERROR_FAIL, ERROR_FAIL, "read sample failed.");
    DP_CHECK_RETURN_RET_LOG(ret == EOS, EOS, "read sample finished.");
    return OK;
}

MediaManagerError MediaManager::WriteSample(TrackType type, const std::shared_ptr<AVBuffer>& sample)
{
    DP_DEBUG_LOG("entered, track type: %{public}d", type);
    DP_CHECK_ERROR_RETURN_RET_LOG(outputWriter_ == nullptr, ERROR_FAIL, "writer is nullptr.");
    if (!started_) {
        auto ret = outputWriter_->Start();
        DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "start writer failed.");
        started_ = true;
    }

    auto ret = outputWriter_->Write(type, sample);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret == ERROR_FAIL, ERROR_FAIL, "writer sample failed.");
    if (sample->flag_ == AVCODEC_BUFFER_FLAG_SYNC_FRAME) {
        finalSyncPts_ = sample->pts_;
    }

    curProcessPts_ = sample->pts_;
    DP_DEBUG_LOG("process sync pts: %{public}lld, finalSyncPts_: %{public}lld",
        static_cast<long long>(curProcessPts_), static_cast<long long>(finalSyncPts_));
    return OK;
}

MediaManagerError MediaManager::Recover(const int64_t size)
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_RET_LOG(recoverReader_ == nullptr, ERROR_FAIL, "recover reader is nullptr.");
    DP_CHECK_ERROR_RETURN_RET_LOG(outputWriter_ == nullptr, ERROR_FAIL, "recover writer is nullptr.");

    auto ret = outputWriter_->Start();
    DP_CHECK_ERROR_RETURN_RET_LOG(ret == ERROR_FAIL, ERROR_FAIL, "start recovering failed.");

    started_ = true;
    int32_t frameNum = 0;
    AVBufferConfig config;
    config.size = size;
    config.memoryType = MemoryType::SHARED_MEMORY;
    auto sample = AVBuffer::CreateAVBuffer(config);
    DP_CHECK_ERROR_RETURN_RET_LOG(sample == nullptr, ERROR_FAIL, "create avbuffer failed.");
    while (true) {
        ret = recoverReader_->Read(TrackType::AV_KEY_VIDEO_TYPE, sample);
        DP_CHECK_ERROR_RETURN_RET_LOG(ret == ERROR_FAIL, ERROR_FAIL, "read temp data failed.");
        DP_CHECK_BREAK_LOG(sample->pts_ == pausePts_, "recovering finished.");

        if (sample->flag_ == AVCODEC_BUFFER_FLAG_SYNC_FRAME) {
            resumePts_ = sample->pts_;
            finalFrameNum_ = frameNum;
        }

        ++frameNum;
        DP_DEBUG_LOG("pts: %{public}lld, frame-num(%{public}d)", static_cast<long long>(sample->pts_), frameNum);
        ret = outputWriter_->Write(TrackType::AV_KEY_VIDEO_TYPE, sample);
        DP_CHECK_ERROR_RETURN_RET_LOG(ret == ERROR_FAIL, ERROR_FAIL, "write temp data failed.");
    }
    DP_INFO_LOG("recover sync end, process total num: %{public}d, resume pts: %{public}lld",
        finalFrameNum_, static_cast<long long>(resumePts_));
    outputWriter_->SetLastPause(pausePts_);
    return OK;
}

MediaManagerError MediaManager::CopyAudioTrack()
{
    DP_CHECK_ERROR_RETURN_RET_LOG(inputReader_ == nullptr, ERROR_FAIL, "copy reader is nullptr.");
    DP_CHECK_ERROR_RETURN_RET_LOG(outputWriter_ == nullptr, ERROR_FAIL, "copy writer is nullptr.");
    DP_CHECK_ERROR_RETURN_RET_LOG(inputReader_->Reset(0) != OK, ERROR_FAIL, "reset reader failed.");

    AVBufferConfig config;
    config.size = DEFAULT_AUDIO_INPUT_SIZE;
    config.memoryType = MemoryType::SHARED_MEMORY;
    auto sample = AVBuffer::CreateAVBuffer(config);
    DP_CHECK_ERROR_RETURN_RET_LOG(sample == nullptr, ERROR_FAIL, "create avbuffer failed.");

    while (true) {
        auto ret = inputReader_->Read(TrackType::AV_KEY_AUDIO_TYPE, sample);
        DP_CHECK_ERROR_RETURN_RET_LOG(ret == ERROR_FAIL, ERROR_FAIL, "read audio data failed.");
        DP_CHECK_BREAK_LOG(ret == EOS, "read audio data finished.");

        ret = outputWriter_->Write(TrackType::AV_KEY_AUDIO_TYPE, sample);
        DP_CHECK_ERROR_RETURN_RET_LOG(ret == ERROR_FAIL, ERROR_FAIL, "write audio data failed.");
    }
    return OK;
}

MediaManagerError MediaManager::InitReader()
{
    DP_DEBUG_LOG("entered.");
    inputReader_ = std::make_shared<Reader>();
    auto ret = inputReader_->Create(inputFileFd_);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "open the video source failed, cannot demux data.");

    ret = inputReader_->GetMediaInfo(mediaInfo_);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "get meta info failed, cannot demux data.");
    return OK;
}

MediaManagerError MediaManager::InitWriter()
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_RET_LOG(inputReader_ == nullptr, ERROR_FAIL, "input reader is nullptr.");

    auto tracks = inputReader_->GetTracks();
    hasAudio_ = tracks.find(TrackType::AV_KEY_AUDIO_TYPE) == tracks.end() ? false : true;
    outputWriter_ = std::make_shared<Writer>();
    auto ret = outputWriter_->Create(outputFileFd_, tracks);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "cannot create mux data.");

    ret = outputWriter_->AddMediaInfo(mediaInfo_);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "add metadata to writer failed.");
    return OK;
}

MediaManagerError MediaManager::InitRecoverReader(const int64_t size, int64_t& duration, int64_t& bitRate)
{
    DP_DEBUG_LOG("entered.");
    recoverReader_ = std::make_shared<Reader>();
    DP_CHECK_ERROR_RETURN_RET_LOG(recoverReader_ == nullptr, ERROR_FAIL, "init recover reader failed.");
    DP_CHECK_ERROR_RETURN_RET_LOG(GetRecoverInfo(size) != OK, ERROR_FAIL, "invalid final info.");

    auto ret = recoverReader_->Create(tempFileFd_);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret == ERROR_FAIL, ERROR_FAIL, "open recover source failed, cannot demux data.");

    auto recover = std::make_shared<MediaInfo>();
    ret = recoverReader_->GetMediaInfo(recover);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret == ERROR_FAIL, ERROR_FAIL, "get recover media info failed.");

    duration = recover->codecInfo.duration;
    bitRate = recover->codecInfo.bitRate;
    return OK;
}

MediaManagerError MediaManager::GetRecoverInfo(const int64_t size)
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_RET_LOG(size < TEMP_PTS_SIZE, ERROR_FAIL, "invalid recover file size.");

    auto off = lseek(tempFileFd_, size - TEMP_PTS_SIZE, SEEK_SET);
    DP_CHECK_ERROR_RETURN_RET_LOG(off == static_cast<off_t>(ERROR_FAIL), ERROR_FAIL, "lseek recover failed.");

    std::vector<uint8_t> tempTail(TEMP_PTS_SIZE);
    auto ret = read(tempFileFd_, tempTail.data(), TEMP_PTS_SIZE);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret == static_cast<int64_t>(ERROR_FAIL), ERROR_FAIL, "read recover pts failed.");

    std::vector<uint8_t> tag2search(TEMP_PTS_TAG.begin(), TEMP_PTS_TAG.end());
    auto findTag = std::search(tempTail.begin(), tempTail.end(), tag2search.begin(), tag2search.end());
    DP_CHECK_ERROR_RETURN_RET_LOG(findTag == tempTail.end(), ERROR_FAIL, "cannot find temp pts tag.");

    std::string pauseTime(findTag + TEMP_PTS_TAG.size(), tempTail.end());
    pausePts_ = std::stol(pauseTime);
    lseek(tempFileFd_, 0, SEEK_SET);
    return OK;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS