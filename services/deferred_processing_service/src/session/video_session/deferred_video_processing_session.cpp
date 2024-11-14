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

#include "deferred_video_processing_session.h"

#include "dps_video_report.h"
#include "dps.h"
#include "video_command.h"
#include "sync_command.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
DeferredVideoProcessingSession::DeferredVideoProcessingSession(const int32_t userId)
    : userId_(userId)
{
    DP_DEBUG_LOG("entered. userId: %{public}d", userId_);
}

DeferredVideoProcessingSession::~DeferredVideoProcessingSession()
{
    DP_DEBUG_LOG("entered.");
    videoIds_.clear();
}

int32_t DeferredVideoProcessingSession::BeginSynchronize()
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_INFO_LOG("DPS_VIDEO: BeginSynchronize.");
    inSync_.store(true);
    return DP_OK;
}

int32_t DeferredVideoProcessingSession::EndSynchronize()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (inSync_.load()) {
        DP_INFO_LOG("DPS_VIDEO: EndSynchronize video job num: %{public}d", static_cast<int32_t>(videoIds_.size()));
        auto ret = DPS_SendCommand<VideoSyncCommand>(userId_, videoIds_);
        inSync_.store(false);
        DP_CHECK_ERROR_RETURN_RET_LOG(ret != DP_OK, ret, "video synchronize failed, ret: %{public}d", ret);
        videoIds_.clear();
    }
    return DP_OK;
}

int32_t DeferredVideoProcessingSession::AddVideo(const std::string& videoId,
    const sptr<IPCFileDescriptor>& srcFd, const sptr<IPCFileDescriptor>& dstFd)
{
    auto infd = sptr<IPCFileDescriptor>::MakeSptr(dup(srcFd->GetFd()));
    auto outFd = sptr<IPCFileDescriptor>::MakeSptr(dup(dstFd->GetFd()));
    if (inSync_.load()) {
        std::lock_guard<std::mutex> lock(mutex_);
        DP_INFO_LOG("AddVideo error, inSync!");
        auto info = std::make_shared<VideoInfo>(infd, outFd);
        videoIds_.emplace(videoId, info);
        return DP_OK;
    }

    auto ret = DPS_SendCommand<AddVideoCommand>(userId_, videoId, infd, outFd);
    DP_INFO_LOG("DPS_VIDEO: AddVideo videoId: %{public}s, ret: %{public}d", videoId.c_str(), ret);
    DfxVideoReport::GetInstance().ReportAddVideoEvent(videoId, GetDpsCallerInfo());
    return ret;
}

int32_t DeferredVideoProcessingSession::RemoveVideo(const std::string& videoId, bool restorable)
{
    DP_CHECK_RETURN_RET_LOG(inSync_.load(), DP_OK, "RemoveVideo error, inSync!");

    auto ret = DPS_SendCommand<RemoveVideoCommand>(userId_, videoId, restorable);
    DP_INFO_LOG("DPS_VIDEO: RemoveVideo videoId: %{public}s, ret: %{public}d", videoId.c_str(), ret);
    DfxVideoReport::GetInstance().ReportRemoveVideoEvent(videoId, GetDpsCallerInfo());
    return ret;
}

int32_t DeferredVideoProcessingSession::RestoreVideo(const std::string& videoId)
{
    DP_CHECK_RETURN_RET_LOG(inSync_.load(), DP_OK, "RestoreVideo error, inSync!");

    auto ret = DPS_SendCommand<RestoreCommand>(userId_, videoId);
    DP_INFO_LOG("DPS_VIDEO: RestoreVideo videoId: %{public}s, ret: %{public}d", videoId.c_str(), ret);
    return ret;
}

} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS