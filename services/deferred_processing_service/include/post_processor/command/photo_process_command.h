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

#ifndef OHOS_CAMERA_DPS_PHOTO_PROCESS_COMMAND_H
#define OHOS_CAMERA_DPS_PHOTO_PROCESS_COMMAND_H

#include "command.h"
#include "image_info.h"
#include "photo_post_processor.h"
#include "scheduler_manager.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class PhotoProcessCommand : public Command {
public:
    PhotoProcessCommand(const int32_t userId);
    ~PhotoProcessCommand() override;

protected:
    int32_t Initialize();

    const int32_t userId_;
    std::atomic<bool> initialized_ {false};
    std::shared_ptr<DeferredPhotoProcessor> photoProcessor_ {nullptr};
};

class PhotoProcessSuccessCommand : public PhotoProcessCommand {
    DECLARE_CMD_CLASS(PhotoProcessSuccessCommand);
public:
    PhotoProcessSuccessCommand(const int32_t userId, const std::string& imageId,
        std::unique_ptr<ImageInfo> imageInfo);
    ~PhotoProcessSuccessCommand() override = default;

protected:
    int32_t Executing() override;

    const std::string imageId_;
    std::unique_ptr<ImageInfo> imageInfo_;
};

class PhotoProcessFailedCommand : public PhotoProcessCommand {
    DECLARE_CMD_CLASS(PhotoProcessFailedCommand);
public:
    PhotoProcessFailedCommand(const int32_t userId, const std::string& imageId, DpsError errorCode);
    ~PhotoProcessFailedCommand() override = default;

protected:
    int32_t Executing() override;

    const std::string imageId_;
    DpsError error_;
};

class PhotoProcessTimeOutCommand : public PhotoProcessFailedCommand {
    DECLARE_CMD_CLASS(PhotoProcessTimeOutCommand);
public:
    using PhotoProcessFailedCommand::PhotoProcessFailedCommand;

protected:
    int32_t Executing() override;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_PHOTO_PROCESS_COMMAND_H