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

#ifndef OHOS_CAMERA_DPS_BACKGROUND_STRATEGY_H
#define OHOS_CAMERA_DPS_BACKGROUND_STRATEGY_H

#include <cstdint>
#include <memory>

#include "istrategy.h"
#include "photo_job_repository.h"


namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class BackgroundStrategy : public IStrategy {
public:
    BackgroundStrategy(std::shared_ptr<PhotoJobRepository> repository);
    ~BackgroundStrategy();
    DeferredPhotoWorkPtr GetWork() override;
    DeferredPhotoJobPtr GetJob() override;
    ExecutionMode GetExecutionMode() override;
    HdiStatus GetHdiStatus();
    void NotifyPressureLevelChanged(SystemPressureLevel level);
    void NotifyHdiStatusChanged(HdiStatus status);
    void NotifyMediaLibStatusChanged(MediaLibraryStatus status);
    void NotifyCameraStatusChanged(CameraSessionStatus status);

private:
    void StartTrailing(uint64_t duration);
    void StopTrailing();
    void FlashTrailingState();

    uint64_t trailingStartTimeStamp_;
    uint64_t remainingTrailingTime_;
    bool isInTrailing_;
    CameraSessionStatus cameraSessionStatus_;
    HdiStatus hdiStatus_;
    MediaLibraryStatus mediaLibraryStatus_;
    SystemPressureLevel systemPressureLevel_;
    std::shared_ptr<PhotoJobRepository> jobRepository_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_BACKGROUND_STRATEGY_H