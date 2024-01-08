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

#ifndef OHOS_CAMERA_DPS_USERINITIATED_STRATEGY_H
#define OHOS_CAMERA_DPS_USERINITIATED_STRATEGY_H

#include <memory>

#include "istrategy.h"
#include "photo_job_repository.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
/*
用户前台调度关注的事件：
是否有ready状态的高优先级任务
其余温度是否超标 hal是否可用 统统不关注。下发任务，如果无法处理 则返回失败
*/
class UserInitiatedStrategy : public IStrategy {
public:
    UserInitiatedStrategy(std::shared_ptr<PhotoJobRepository> photoJobRepository);
    ~UserInitiatedStrategy();
    DeferredPhotoWorkPtr GetWork() override;
    DeferredPhotoJobPtr GetJob() override;
    ExecutionMode GetExecutionMode() override;

private:
    std::shared_ptr<PhotoJobRepository> photoJobRepository_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_USERINITIATED_STRATEGY_H