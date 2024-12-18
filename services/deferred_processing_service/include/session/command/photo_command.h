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

#ifndef OHOS_CAMERA_DPS_PHOTO_COMMAND_H
#define OHOS_CAMERA_DPS_PHOTO_COMMAND_H

#include "command.h"
#include "ipc_file_descriptor.h"
#include "scheduler_manager.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class PhotoCommand : public Command {
public:
    PhotoCommand(const int32_t userId, const std::string& photoId);
    ~PhotoCommand();

protected:
    int32_t Initialize();

    const int32_t userId_;
    const std::string photoId_;
    std::atomic<bool> initialized_ {false};
    std::shared_ptr<SchedulerManager> schedulerManager_ {nullptr};
    std::shared_ptr<DeferredPhotoProcessor> processor_ {nullptr};
};

class AddPhotoCommand : public PhotoCommand {
    DECLARE_CMD_CLASS(AddPhotoCommand)
public:
    AddPhotoCommand(const int32_t userId, const std::string& photoId,
        const DpsMetadata& metadata, const bool discardable);

protected:
    int32_t Executing() override;

    DpsMetadata metadata_;
    const bool discardable_;
};

class RemovePhotoCommand : public PhotoCommand {
    DECLARE_CMD_CLASS(RemovePhotoCommand)
public:
    RemovePhotoCommand(const int32_t userId, const std::string& photoId, const bool restorable);

protected:
    int32_t Executing() override;

    const bool restorable_;
};

class RestorePhotoCommand : public PhotoCommand {
    DECLARE_CMD_CLASS(RestorePhotoCommand)
public:
    using PhotoCommand::PhotoCommand;

protected:
    int32_t Executing() override;
};

class ProcessPhotoCommand : public PhotoCommand {
    DECLARE_CMD_CLASS(ProcessPhotoCommand)
public:
    ProcessPhotoCommand(const int32_t userId, const std::string& photoId, const std::string& appName);

protected:
    int32_t Executing() override;

    const std::string appName_;
};

class CancelProcessPhotoCommand : public PhotoCommand {
    DECLARE_CMD_CLASS(CancelProcessPhotoCommand)
public:
    using PhotoCommand::PhotoCommand;

protected:
    int32_t Executing() override;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_PHOTO_COMMAND_H