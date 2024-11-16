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

#include "writer.h"

#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
Writer::~Writer()
{
    outputMuxer_ = nullptr;
}

MediaManagerError Writer::Create(int32_t outputFd,
    const std::map<Media::Plugins::MediaType, std::shared_ptr<Track>>& trackMap)
{
    DP_CHECK_ERROR_RETURN_RET_LOG(outputFd == INVALID_FD, ERROR_FAIL, "outputFd is invalid: %{public}d.", outputFd);
    DP_CHECK_ERROR_RETURN_RET_LOG(trackMap.empty(), ERROR_FAIL, "Finvalid track map.");

    outputFileFd_ = outputFd;
    outputMuxer_ = std::make_shared<Muxer>();
    DP_DEBUG_LOG("outputFd: %{public}d, track size: %{public}d",
        outputFileFd_, static_cast<int32_t>(trackMap.size()));
    auto ret = outputMuxer_->Create(outputFileFd_, Plugins::OutputFormat::MPEG_4);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "Create muxer failed.");

    ret = outputMuxer_->AddTracks(trackMap);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "Add track failed.");

    return ret;
}

MediaManagerError Writer::Write(Media::Plugins::MediaType type, const std::shared_ptr<AVBuffer>& sample)
{
    DP_DEBUG_LOG("pts: %{public}" PRId64 ", flag: %{public}d", sample->pts_, sample->flag_);
    if (sample->memory_ != nullptr) {
        DP_DEBUG_LOG("sample size: %{public}d", sample->memory_->GetSize());
    }
    
    DP_CHECK_RETURN_RET_LOG(sample->pts_ < lastPause_ && type == Media::Plugins::MediaType::VIDEO, OK,
        "Drop feame pts: %{public}" PRId64, sample->pts_);

    auto ret = outputMuxer_->WriteStream(type, sample);
    DP_CHECK_RETURN_RET_LOG(ret != OK, ERROR_FAIL,
        "Write sample failed, type: %{public}d", static_cast<int32_t>(type));
    return OK;
}

MediaManagerError Writer::Start()
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_RETURN_RET(started_, OK);
    DP_CHECK_ERROR_RETURN_RET_LOG(outputMuxer_ == nullptr, ERROR_FAIL, "Failed to start, muxer is nullptr.");

    auto ret = outputMuxer_->Start();
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "Start failed, ret: %{public}d", ret);

    started_ = true;
    return OK;
}

MediaManagerError Writer::Stop()
{
    DP_DEBUG_LOG("entered.");
    auto ret = outputMuxer_->Stop();
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "Stop failed, ret: %{public}d", ret);

    started_ = false;
    return OK;
}

MediaManagerError Writer::AddMediaInfo(const std::shared_ptr<MediaInfo>& mediaInfo)
{
    DP_DEBUG_LOG("entered.");
    auto ret = outputMuxer_->AddMediaInfo(mediaInfo);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "Add media info failed.");
    return OK;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
