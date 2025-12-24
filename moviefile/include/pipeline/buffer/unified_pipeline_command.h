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

#ifndef OHOS_UNIFIED_PIPELINE_COMMAND_H
#define OHOS_UNIFIED_PIPELINE_COMMAND_H

#include <list>
#include <memory>
#include <type_traits>

#include "unified_pipeline_command_id.h"

namespace OHOS {
namespace CameraStandard {
class UnifiedPipelineCommand {
public:
    class CommandData {
    public:
        virtual ~CommandData() = default;
    };

    static const uint32_t FLAG_CONSUMED = 0x01;

public:
    UnifiedPipelineCommand(UnifiedPipelineCommandId commandId, std::unique_ptr<CommandData> commandData);

    ~UnifiedPipelineCommand() = default;

    UnifiedPipelineCommandId GetCommandId();

    // 返回数据可能为nullptr, 调用方注意判空
    CommandData* GetCommandData();

    void AddFlag(uint32_t flag);

    void RemoveFlag(uint32_t flag);

    bool IsConsumed();

private:
    UnifiedPipelineCommandId commandId_ = UnifiedPipelineCommandId::NONE;
    std::unique_ptr<CommandData> commandData_ = nullptr;

    uint32_t flag_ = 0;
};
} // namespace CameraStandard
} // namespace OHOS

#endif