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

#include "steady_clock.h"
#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {

uint64_t SteadyClock::GetTimestampMilli()
{
    auto timePoint = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch()).count();
}

uint64_t SteadyClock::GetTimestampMicro()
{
    auto timePoint = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(timePoint.time_since_epoch()).count();
}

uint64_t SteadyClock::GetElapsedTimeMs(uint64_t startMs)
{
    auto currTime = SteadyClock::GetTimestampMilli();
    uint64_t diff = 0;
    if (currTime > startMs) {
        diff = currTime - startMs;
    } else {
        DP_ERR_LOG("invalid parameter, startMs: %d, currTime: %d", static_cast<int>(startMs),
            static_cast<int>(currTime));
    }
    return diff;
}

std::chrono::milliseconds SteadyClock::GetRemainingTimeMs(uint64_t expirationTimeMs)
{
    auto currTime = SteadyClock::GetTimestampMilli();
    uint64_t remainingTimeMs = (expirationTimeMs > currTime) ? (expirationTimeMs - currTime) : 0;
    DP_DEBUG_LOG("expirationTimeMs: %d, currTime: %d, remainingTime: %d",
        static_cast<int>(expirationTimeMs), static_cast<int>(currTime), static_cast<int>(remainingTimeMs));
    return std::chrono::milliseconds(remainingTimeMs);
}

SteadyClock::SteadyClock() : start_(std::chrono::steady_clock::now())
{
    DP_DEBUG_LOG("entered.");
}

void SteadyClock::Reset()
{
    DP_DEBUG_LOG("entered.");
    start_ = std::chrono::steady_clock::now();
    return;
}

uint64_t SteadyClock::GetElapsedTimeMs()
{
    DP_DEBUG_LOG("entered.");
    constexpr int timescale = 1000;
    auto end = std::chrono::steady_clock::now();
    return static_cast<uint64_t>(std::chrono::duration<double>(end - start_).count() * timescale);
}
} //namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
