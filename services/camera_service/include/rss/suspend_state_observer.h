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
#ifndef OHOS_CAMERA_SUSPEND_STATE_OBSERVER_H
#define OHOS_CAMERA_SUSPEND_STATE_OBSERVER_H

#include "suspend_state_observer_base_stub.h"

namespace OHOS::CameraStandard {
class HCameraService;
class SuspendStateObserver : public ResourceSchedule::SuspendStateObserverBaseStub {
public:
    explicit SuspendStateObserver(wptr<HCameraService> service) : service_(service) {}

    virtual ErrCode OnActive(const std::vector<int32_t> &pidList, int32_t uid);
    virtual ErrCode OnDoze(const std::vector<int32_t> &pidList, int32_t uid);
    virtual ErrCode OnFrozen(const std::vector<int32_t> &pidList, int32_t uid);
private:
    wptr<HCameraService> service_;
};
} // namespace OHOS::CameraStandard
#endif // OHOS_CAMERA_SUSPEND_STATE_OBSERVER_H