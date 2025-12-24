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

#ifndef OHOS_CAMERA_DPS_VIDEO_COMMAND_H
#define OHOS_CAMERA_DPS_VIDEO_COMMAND_H

#include "command.h"
#include "dps_fd.h"
#include "ipc_file_descriptor.h"
#include "scheduler_manager.h"
#include "video_info.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class VideoCommand : public Command {
public:
    VideoCommand(const int32_t userId, const std::string& videoId);
    virtual ~VideoCommand() override;

protected:
    int32_t Initialize();

    const int32_t userId_;
    const std::string videoId_;
    std::atomic<bool> initialized_ {false};
    std::shared_ptr<SchedulerManager> schedulerManager_ {nullptr};
    std::shared_ptr<DeferredVideoProcessor> processor_ {nullptr};
};

class AddVideoCommand : public VideoCommand {
    DECLARE_CMD_CLASS(AddVideoCommand)
public:
    AddVideoCommand(const int32_t userId, const std::string& videoId, const std::shared_ptr<VideoInfo>& info);

protected:
    int32_t Executing() override;

    std::shared_ptr<VideoInfo> info_ {nullptr};
};

class RemoveVideoCommand : public VideoCommand {
    DECLARE_CMD_CLASS(RemoveVideoCommand)
public:
    RemoveVideoCommand(const int32_t userId, const std::string& videoId, const bool restorable);

protected:
    int32_t Executing() override;

    const bool restorable_;
};

class RestoreVideoCommand : public VideoCommand {
    DECLARE_CMD_CLASS(RestoreCommand)
public:
    using VideoCommand::VideoCommand;

protected:
    int32_t Executing() override;
};

class ProcessVideoCommand : public VideoCommand {
    DECLARE_CMD_CLASS(ProcessVideoCommand)
public:
    using VideoCommand::VideoCommand;

protected:
    int32_t Executing() override;
};

class CancelProcessVideoCommand : public VideoCommand {
    DECLARE_CMD_CLASS(CancelProcessVideoCommand)
public:
    using VideoCommand::VideoCommand;

protected:
    int32_t Executing() override;
};

} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_VIDEO_COMMAND_H