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

#include "video_process_result.h"

#include "dp_log.h"
#include "dps.h"
#include "events_monitor.h"
#include "service_died_command.h"
#include "video_process_command.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
VideoProcessResult::VideoProcessResult(const int32_t userId) : userId_(userId)
{
    DP_DEBUG_LOG("entered.");
}

VideoProcessResult::~VideoProcessResult()
{
    DP_DEBUG_LOG("entered.");
}

void VideoProcessResult::OnProcessDone(const std::string& videoId)
{
    DP_DEBUG_LOG("DPS_VIDEO: OnProcessDone videoId: %{public}s", videoId.c_str());
    auto ret = DPS_SendCommand<VideoProcessSuccessCommand>(userId_, videoId);
    DP_CHECK_ERROR_PRINT_LOG(ret != DP_OK,
        "process success videoId: %{public}s failed. ret: %{public}d", videoId.c_str(), ret);
}

void VideoProcessResult::OnProcessDone(const std::string& videoId, std::unique_ptr<MediaUserInfo> userInfo)
{
    DP_DEBUG_LOG("DPS_VIDEO: OnProcessDone videoId: %{public}s", videoId.c_str());
    auto ret = DPS_SendCommand<VideoProcessSuccessCommand>(userId_, videoId, std::move(userInfo));
    DP_CHECK_ERROR_PRINT_LOG(ret != DP_OK,
        "process success videoId: %{public}s failed. ret: %{public}d", videoId.c_str(), ret);
}

void VideoProcessResult::OnError(const std::string& videoId, DpsError errorCode)
{
    DP_DEBUG_LOG("DPS_VIDEO: OnError videoId: %{public}s, error: %{public}d", videoId.c_str(), errorCode);
    auto ret = DPS_SendCommand<VideoProcessFailedCommand>(userId_, videoId, errorCode);
    DP_CHECK_ERROR_PRINT_LOG(ret != DP_OK,
        "process error videoId: %{public}s failed. ret: %{public}d", videoId.c_str(), ret);
}

void VideoProcessResult::OnStateChanged(HdiStatus hdiStatus)
{
    DP_DEBUG_LOG("DPS_VIDEO: OnStateChanged hdiStatus: %{public}d", hdiStatus);
    EventsMonitor::GetInstance().NotifyVideoEnhanceStatus(hdiStatus);
}

void VideoProcessResult::OnVideoSessionDied()
{
    DP_ERR_LOG("DPS_VIDEO: OnVideoSessionDied");
    auto ret = DPS_SendCommand<VideoDiedCommand>(userId_);
    DP_CHECK_ERROR_PRINT_LOG(ret != DP_OK, "process video session deied failed, ret: %{public}d", ret);
}

int32_t VideoProcessResult::ProcessVideoInfo(const std::string& videoId,
    const sptr<HDI::Camera::V1_0::MapDataSequenceable>& metaData)
{
    if (metaData == nullptr) {
        OnProcessDone(videoId);
        return DP_OK;
    }

    auto userInfo = std::make_unique<MediaUserInfo>();
    double scalingFactor;
    if (GetMetadataValue(metaData, VideoMetadataKeys::SCALING_FACTOR, scalingFactor)) {
        userInfo->scalingFactor = static_cast<float>(scalingFactor);
    }
    std::string stringValue;
    if (GetMetadataValue(metaData, VideoMetadataKeys::INTERPOLATION_FRAME_PTS, stringValue)) {
        userInfo->interpolationFramePts = stringValue;
    }
    if (GetMetadataValue(metaData, VideoMetadataKeys::STAGE_VID, stringValue)) {
        userInfo->stageVid = stringValue;
    }

    DP_INFO_LOG("DPS_VIDEO: scalingFactor: %{public}f, interpolationFramePts: %{public}s, stageVid: %{public}s",
        userInfo->scalingFactor, userInfo->interpolationFramePts.c_str(), userInfo->stageVid.c_str());
    OnProcessDone(videoId, std::move(userInfo));
    return DP_OK;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
