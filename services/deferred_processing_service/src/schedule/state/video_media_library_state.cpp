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

#include "video_media_library_state.h"

#include "dp_log.h"
#include "state_factory.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
REGISTER_STATE(VideoMediaLibraryState, VIDEO_MEDIA_LIBRARY_STATE, MEDIA_LIBRARY_DISCONNECTED);

VideoMediaLibraryState::VideoMediaLibraryState(SchedulerType type, int32_t stateValue)
    : IState(type, stateValue)
{
    DP_DEBUG_LOG("entered.");
}

SchedulerInfo VideoMediaLibraryState::ReevaluateSchedulerInfo()
{
    DP_DEBUG_LOG("VideoMediaLibraryState: %{public}d", stateValue_);
    bool isNeedStop = stateValue_ == MediaLibraryStatus::MEDIA_LIBRARY_DISCONNECTED;
    return {isNeedStop};
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS