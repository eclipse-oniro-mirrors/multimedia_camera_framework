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

#ifndef OHOS_CAMERA_DPS_I_VIDEO_STATE_CHANGE_LISTENER_H
#define OHOS_CAMERA_DPS_I_VIDEO_STATE_CHANGE_LISTENER_H

#include "basic_definitions.h"
#include "ischeduler_video_state.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
using ScheduleInfo = ISchedulerVideoState::VideoSchedulerInfo;

class IVideoStateChangeListener {
public:
    IVideoStateChangeListener() = default;
    virtual ~IVideoStateChangeListener() = default;
    
    virtual void OnSchedulerChanged(const ScheduleType& type, const ScheduleInfo& scheduleInfo) = 0;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_I_VIDEO_STATE_CHANGE_LISTENER_H