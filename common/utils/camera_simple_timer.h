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

#ifndef OHOS_CAMERA_SIMPLE_TIMER_H
#define OHOS_CAMERA_SIMPLE_TIMER_H

#include <condition_variable>
#include <functional>
#include <mutex>

namespace OHOS {
namespace CameraStandard {

class SimpleTimer {
public:
    enum TimerStatus { IDLE, RUNNING, CANCEL, DONE };

public:
    explicit SimpleTimer(std::function<void()> fun);
    ~SimpleTimer();
    bool StartTask(uint64_t timeoutMs);
    bool CancelTask();

private:
    void InterruptableSleep(uint64_t timeoutMs);
    std::mutex timerMtx_;
    std::condition_variable timerCv_;
    TimerStatus timerStatus_ = IDLE;

    std::function<void()> innerFun_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif