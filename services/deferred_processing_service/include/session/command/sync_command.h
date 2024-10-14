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

#ifndef OHOS_CAMERA_DPS_SYNC_COMMAND_H
#define OHOS_CAMERA_DPS_SYNC_COMMAND_H

#include "command.h"
#include "deferred_video_processing_session.h"
#include "scheduler_manager.h"
#include "session_manager.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class SyncCommand : public Command {
public:
    SyncCommand(const int32_t userId);
    ~SyncCommand();

protected:
    int32_t Initialize();

    const int32_t userId_;
    std::atomic_bool initialized_ {false};
    std::shared_ptr<SessionManager> sessionManager_ {nullptr};
    std::shared_ptr<SchedulerManager> schedulerManager_ {nullptr};
    std::shared_ptr<DeferredVideoProcessor> processor_ {nullptr};
};

class VideoSyncCommand : public SyncCommand {
    DECLARE_CMD_CLASS(VideoSyncCommand)
public:
    VideoSyncCommand(const int32_t userId,
        const std::unordered_map<std::string, std::shared_ptr<DeferredVideoProcessingSession::VideoInfo>>& videoIds);

protected:
    int32_t Executing() override;

    std::unordered_map<std::string, std::shared_ptr<DeferredVideoProcessingSession::VideoInfo>> videoIds_ {};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_SYNC_COMMAND_H