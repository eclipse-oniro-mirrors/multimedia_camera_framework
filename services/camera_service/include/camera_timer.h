/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#ifndef CAMERA_TIMER_H
#define CAMERA_TIMER_H

#include <memory>
#include <atomic>
#include <commonlibrary/c_utils/base/include/timer.h>

namespace OHOS {
namespace CameraStandard {
using TimerCallback = std::function<void()>;

class CameraTimer {
public:
    CameraTimer();
    ~CameraTimer();

    static CameraTimer *GetInstance();
    void IncreaseUserCount();
    void DecreaseUserCount();
    uint32_t Register(const TimerCallback& callback, uint32_t interval, bool once);
    void Unregister(uint32_t timerId);

private:
    std::atomic<int32_t> userCount_;
    std::unique_ptr<OHOS::Utils::Timer> timer_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // CAMERA_TIMER_H