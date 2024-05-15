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

#ifndef CAMERA_FRAMEWORK_DRAIN_MANAGER_H
#define CAMERA_FRAMEWORK_DRAIN_MANAGER_H

#include <vector>
#include <unordered_map>
#include <functional>
#include "frame_record.h"
#include <refbase.h>

namespace OHOS {
namespace CameraStandard {
class DrainImageCallback : public RefBase {
public:
    ~DrainImageCallback() = default;
    virtual void OnDrainImage(sptr<FrameRecord> frame) = 0;
    virtual void OnDrainImageFinish(bool isFinished) = 0;
};

class DrainImageManager : public RefBase {
private:
    sptr<DrainImageCallback> drainImageCallback;
    std::function<void()> drainFinishCallback;

public:
    int drainCount;
    DrainImageManager(sptr<DrainImageCallback> callback, int count) : drainImageCallback(callback), drainCount(count) {}
    void DrainImage(sptr<FrameRecord> frame)
    {
        if (drainCount <= 0) {
            return;
        }
        drainImageCallback->OnDrainImage(frame);
        drainCount--;
        if (drainCount == 0) {
            DrainFinish(true);
        }
    }

    void DrainFinish(bool isFinished)
    {
        drainImageCallback->OnDrainImageFinish(isFinished);
    }
};
} // CameraStandard
} // OHOS
#endif //CAMERA_FRAMEWORK_DRAIN_MANAGER_H
