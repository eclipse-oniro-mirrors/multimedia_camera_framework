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

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class VideoProcessResult {
public:
    explicit VideoProcessResult(const int32_t userId);
    ~VideoProcessResult();

    void OnProcessDone(const std::string& videoId);
    void OnError(const std::string& videoId, DpsError errorCode);
    void OnStateChanged(HdiStatus hdiStatus);
    void OnVideoSessionDied();

private:
    const int32_t userId_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_VIDEO_PROCESS_RESULT_H