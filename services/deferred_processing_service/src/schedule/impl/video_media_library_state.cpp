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

#include "video_media_library_state.h"

#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
VideoMediaLibraryState::VideoMediaLibraryState(int32_t stateValue) : ISchedulerVideoState(stateValue)
{
    DP_DEBUG_LOG("entered.");
}

VideoMediaLibraryState::~VideoMediaLibraryState()
{
    DP_DEBUG_LOG("entered.");
}

VideoMediaLibraryState::VideoSchedulerInfo VideoMediaLibraryState::ReevaluateSchedulerInfo()
{
    DP_INFO_LOG("entered, VideoMediaLibraryState: %{public}d", stateValue_);
    bool isNeedStop = stateValue_ == MediaLibraryStatus::MEDIA_LIBRARY_DISCONNECTED;
    return {isNeedStop, false};
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS