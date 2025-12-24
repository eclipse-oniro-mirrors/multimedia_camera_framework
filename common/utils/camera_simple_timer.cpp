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

#include "camera_simple_timer.h"
#include "camera_log.h"

#include <chrono>
#include <thread>

namespace OHOS {
namespace CameraStandard {

SimpleTimer::SimpleTimer(std::function<void()> fun) : innerFun_(fun)  {
};

SimpleTimer::~SimpleTimer()
{
    std::unique_lock<std::mutex> lock(timerMtx_);
    if (timerStatus_ == TimerStatus::RUNNING) {
        timerStatus_ = TimerStatus::CANCEL;
        timerCv_.notify_all();
        timerCv_.wait(lock, [this]() { return timerStatus_ == TimerStatus::DONE; });
    } else if (timerStatus_ == TimerStatus::CANCEL) {
        timerCv_.wait(lock, [this]() { return timerStatus_ == TimerStatus::DONE; });
    }
}

void SimpleTimer::InterruptableSleep(uint64_t timeoutMs)
{
    std::unique_lock<std::mutex> lock(timerMtx_);
    bool isWakeUp = timerCv_.wait_for(
        lock, std::chrono::milliseconds(timeoutMs), [this] { return timerStatus_ != TimerStatus::RUNNING; });
    if (!isWakeUp && innerFun_ != nullptr) {
        innerFun_();
    }

    timerStatus_ = TimerStatus::DONE;
    timerCv_.notify_all();
}

bool SimpleTimer::StartTask(uint64_t timeoutMs)
{
    std::unique_lock<std::mutex> lockStatus(timerMtx_);
    CHECK_RETURN_RET(timerStatus_ == TimerStatus::RUNNING, false);
    timerStatus_ = TimerStatus::RUNNING;
    std::thread taskThread(&SimpleTimer::InterruptableSleep, this, timeoutMs);
    taskThread.detach();
    return true;
}

bool SimpleTimer::CancelTask()
{
    std::unique_lock<std::mutex> lockStatus(timerMtx_);
    CHECK_RETURN_RET(timerStatus_ != TimerStatus::RUNNING, false);
    timerStatus_ = TimerStatus::CANCEL;
    timerCv_.notify_all();
    return true;
}
} // namespace CameraStandard
} // namespace OHOS