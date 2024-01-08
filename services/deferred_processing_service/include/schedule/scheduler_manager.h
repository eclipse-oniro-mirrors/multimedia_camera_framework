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

#ifndef OHOS_CAMERA_DPS_SCHEDULE_MANAGER_H
#define OHOS_CAMERA_DPS_SCHEDULE_MANAGER_H

#include<memory>
#include<unordered_map>

#include "scheduler_coordinator.h"
#include "deferred_photo_controller.h"
#include "deferred_photo_processor.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class SchedulerManager {
public:
    SchedulerManager();
    ~SchedulerManager();
    void Initialize();

    // 用于session获取对应的processor，如果有则直接返回 如果没有则创建后返回 这里的callback是sessioncoordinator对象
    // 创建任务仓库 processor  并把仓库传给processor，再创建processor对应的controller
    // controller向任务仓库注册任务监听（关注任务添加、任务running个数改变）+向事件监听模块注册监听
    std::shared_ptr<DeferredPhotoProcessor> GetPhotoProcessor(int userId,
                                                              TaskManager* taskManager,
                                                              std::shared_ptr<IImageProcessCallbacks> callbacks);

private:
    void CreatePhotoProcessor(int userId, TaskManager* taskManager, std::shared_ptr<IImageProcessCallbacks> callbacks);

    std::unordered_map<int, std::shared_ptr<DeferredPhotoProcessor>> photoProcessors_;
    std::unordered_map<int, std::shared_ptr<DeferredPhotoController>> photoController_;
    std::shared_ptr<SchedulerCoordinator> schedulerCoordinator_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_SCHEDULE_MANAGER_H