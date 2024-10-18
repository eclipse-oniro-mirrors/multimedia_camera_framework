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

#ifndef OHOS_CAMERA_DPS_VIDEO_PROCESS_COMMAND_H
#define OHOS_CAMERA_DPS_VIDEO_PROCESS_COMMAND_H

#include "command.h"
#include "scheduler_manager.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class VideoProcessCommand : public Command {
public:
    VideoProcessCommand(const int32_t userId);
    ~VideoProcessCommand();

protected:
    int32_t Initialize();

    const int32_t userId_;
    std::atomic<bool> initialized_ {false};
    std::shared_ptr<SchedulerManager> schedulerManager_ {nullptr};
    std::shared_ptr<DeferredVideoController> controller_ {nullptr};
};

class VideoProcessSuccessCommand : public VideoProcessCommand {
    DECLARE_CMD_CLASS(VideoProcessSuccessCommand);
public:
    VideoProcessSuccessCommand(const int32_t userId, const DeferredVideoWorkPtr& work);
    ~VideoProcessSuccessCommand() override;

protected:
    int32_t Executing() override;

    DeferredVideoWorkPtr work_;
};

class VideoProcessFailedCommand : public VideoProcessCommand {
    DECLARE_CMD_CLASS(VideoProcessFailedCommand);
public:
    VideoProcessFailedCommand(const int32_t userId, const DeferredVideoWorkPtr& work, DpsError errorCode);
    ~VideoProcessFailedCommand() override;

protected:
    int32_t Executing() override;

    DeferredVideoWorkPtr work_;
    DpsError error_;
};

class VideoStateChangedCommand : public VideoProcessCommand {
    DECLARE_CMD_CLASS(VideoStateChangedCommand);
public:
    VideoStateChangedCommand(const int32_t userId, HdiStatus status)
        : VideoProcessCommand(userId), status_(status)
    {
        DP_DEBUG_LOG("entered.");
    }
    ~VideoStateChangedCommand() override = default;

protected:
    int32_t Executing() override;

    HdiStatus status_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_VIDEO_PROCESS_COMMAND_H