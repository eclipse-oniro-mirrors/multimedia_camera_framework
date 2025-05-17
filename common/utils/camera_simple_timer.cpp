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

#include <chrono>

#include <thread>

namespace OHOS {
namespace CameraStandard {

SimpleTimer::SimpleTimer(std::function<void()> fun) : innerFun_(fun)  {

};

SimpleTimer::~SimpleTimer()
{
    std::unique_lock<std::mutex> lock(timerMtx_);
    if (timerStatus_ == RUNNING) {
        timerStatus_ = CANCEL;
        timerCv_.notify_all();
        timerCv_.wait(lock, [this]() { return timerStatus_ == DONE; });
    } else if(timerStatus_ == CANCEL) {
        timerCv_.wait(lock, [this]() { return timerStatus_ == DONE; });
    }
}

void SimpleTimer::InterruptableSleep(uint64_t timeoutMs)
{
    std::unique_lock<std::mutex> lock(timerMtx_);
    bool isWakeUp =
        timerCv_.wait_for(lock, std::chrono::milliseconds(timeoutMs), [this] { return timerStatus_ != RUNNING; });
    if (!isWakeUp && innerFun_ != nullptr) {
        innerFun_();
    }

    timerStatus_ = DONE;
    timerCv_.notify_all();
}

bool SimpleTimer::StartTask(uint64_t timeoutMs)
{
    std::unique_lock<std::mutex> lockStatus(timerMtx_);
    if (timerStatus_ == RUNNING) {
        return false;
    }
    timerStatus_ = RUNNING;
    std::thread taskThread(&SimpleTimer::InterruptableSleep, this, timeoutMs);
    taskThread.detach();
    return true;
}

bool SimpleTimer::CancelTask()
{
    std::unique_lock<std::mutex> lockStatus(timerMtx_);
    if (timerStatus_ != RUNNING) {
        return false;
    }
    timerStatus_ = CANCEL;
    timerCv_.notify_all();
    return true;
}
} // namespace CameraStandard
} // namespace OHOS