/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "unified_pipeline_command.h"

namespace OHOS {
namespace CameraStandard {

UnifiedPipelineCommand::UnifiedPipelineCommand(
    UnifiedPipelineCommandId commandId, std::unique_ptr<CommandData> commandData)
{
    commandId_ = commandId;
    commandData_ = std::move(commandData);
}

UnifiedPipelineCommandId UnifiedPipelineCommand::GetCommandId()
{
    return commandId_;
}

UnifiedPipelineCommand::CommandData* UnifiedPipelineCommand::GetCommandData()
{
    return commandData_.get();
}

void UnifiedPipelineCommand::AddFlag(uint32_t flag)
{
    flag_ |= flag;
}

void UnifiedPipelineCommand::RemoveFlag(uint32_t flag)
{
    flag_ &= ~flag;
}

bool UnifiedPipelineCommand::IsConsumed()
{
    return flag_ & FLAG_CONSUMED;
}

} // namespace CameraStandard
} // namespace OHOS
