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

#ifndef OHOS_CAMERA_DPS_VIDEO_PROCESS_RESULT_H
#define OHOS_CAMERA_DPS_VIDEO_PROCESS_RESULT_H

#include "basic_definitions.h"
#include "dp_log.h"
#include "map_data_sequenceable.h"
#include "media_format_info.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
struct VideoMetadataKeys {
    static constexpr auto SCALING_FACTOR = "scalingFactor";
    static constexpr auto INTERPOLATION_FRAME_PTS = "interpFramePts";
    static constexpr auto STAGE_VID = "stageVid";
};

class VideoProcessResult {
public:
    explicit VideoProcessResult(const int32_t userId);
    ~VideoProcessResult();

    void OnProcessDone(const std::string& videoId);
    void OnProcessDone(const std::string& videoId, std::unique_ptr<MediaUserInfo> metaInfo);
    void OnError(const std::string& videoId, DpsError errorCode);
    void OnStateChanged(HdiStatus hdiStatus);
    void OnVideoSessionDied();
    int32_t ProcessVideoInfo(const std::string& videoId,
        const sptr<HDI::Camera::V1_0::MapDataSequenceable>& metaData);

private:
    const int32_t userId_;

    template <typename T>
    bool GetMetadataValue(const sptr<HDI::Camera::V1_0::MapDataSequenceable>& metadata,
        const std::string& key, T& value)
    {
        DP_CHECK_RETURN_RET(metadata == nullptr, false);
        auto ret = metadata->Get(key, value);
        DP_CHECK_RETURN_RET_LOG(ret != DP_OK, false, "GetMetaTag: %{public}s, ret: %{public}d", key.c_str(), ret);
        return true;
    }
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_VIDEO_PROCESS_RESULT_H