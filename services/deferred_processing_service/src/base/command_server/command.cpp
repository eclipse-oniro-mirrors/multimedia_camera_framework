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

#include "command.h"

#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
Command::Command()
{
    DP_DEBUG_LOG("entered.");
}

Command::~Command()
{
    DP_DEBUG_LOG("entered.");
}

int32_t Command::Do()
{
    auto name = GetCommandName();
    DP_INFO_LOG("DPS_CommandName: %{public}s", name);
    auto timeStart = std::chrono::steady_clock::now();
    auto ret = Executing();
    auto timeEnd = std::chrono::steady_clock::now();
    auto commandTimeCost = std::chrono::duration_cast<std::chrono::microseconds>(timeEnd - timeStart).count();
    DP_DEBUG_LOG("CommandName: %{public}s Executing time (%{public}lld µs)", name, commandTimeCost);
    return ret;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS