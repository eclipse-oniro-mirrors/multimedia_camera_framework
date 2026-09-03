/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <fuzzer/FuzzedDataProvider.h>
#include <memory>
#include <string>
#include <functional>
#include "camera_log.h"
#include "fuzz_util.h"
#include "test_token.h"
#include "timer/timer.h"
#include "timer/core/timer_core.h"
#include "timer/steady_clock.h"

using namespace OHOS;
using namespace OHOS::CameraStandard;
using namespace OHOS::CameraStandard::DeferredProcessing;

static constexpr uint32_t TIMER_DELAY_MS = 1000;
static constexpr uint32_t TIMER_PERIOD_MS = 500;
static constexpr uint32_t TIMER_REPEAT_DELAY_MS = 200;
static constexpr uint32_t TIMER_START_MAX_MS = 5000;
static constexpr uint64_t TIMER_START_OFFSET_MIN_MS = 1000;
static constexpr uint64_t TIMER_START_OFFSET_MAX_MS = 100000;

static void TestInitialize(FuzzedDataProvider& fdp)
{
    (void)fdp;
    TimerCore::GetInstance().Initialize();
    TimerCore::GetInstance().Initialize();
}

static void TestRegisterTimer(FuzzedDataProvider& fdp)
{
    uint64_t timestampMs = fdp.ConsumeIntegral<uint64_t>();
    auto timer = Timer::Create("fuzz_timer_once", TimerType::ONCE, TIMER_DELAY_MS, []() {});
    (void)TimerCore::GetInstance().RegisterTimer(timestampMs, timer);
}

static void TestRegisterTimerPeriodic(FuzzedDataProvider& fdp)
{
    uint64_t timestampMs = fdp.ConsumeIntegral<uint64_t>();
    auto timer = Timer::Create("fuzz_timer_periodic", TimerType::PERIODIC, TIMER_PERIOD_MS, []() {});
    (void)TimerCore::GetInstance().RegisterTimer(timestampMs, timer);
}

static void TestRegisterTimerNullptr(FuzzedDataProvider& fdp)
{
    uint64_t timestampMs = fdp.ConsumeIntegral<uint64_t>();
    std::shared_ptr<Timer> timer = nullptr;
    (void)TimerCore::GetInstance().RegisterTimer(timestampMs, timer);
}

static void TestDeregisterTimer(FuzzedDataProvider& fdp)
{
    uint64_t timestampMs = fdp.ConsumeIntegral<uint64_t>();
    auto timer = Timer::Create("fuzz_timer", TimerType::ONCE, TIMER_DELAY_MS, []() {});
    (void)TimerCore::GetInstance().DeregisterTimer(timestampMs, timer);
}

static void TestDeregisterTimerNullptr(FuzzedDataProvider& fdp)
{
    uint64_t timestampMs = fdp.ConsumeIntegral<uint64_t>();
    std::shared_ptr<Timer> timer = nullptr;
    (void)TimerCore::GetInstance().DeregisterTimer(timestampMs, timer);
}

static void TestRegisterMultipleTimersSameTimestamp(FuzzedDataProvider& fdp)
{
    uint64_t timestampMs = fdp.ConsumeIntegral<uint64_t>();
    auto timer1 = Timer::Create("fuzz_timer_1", TimerType::ONCE, TIMER_DELAY_MS, []() {});
    auto timer2 = Timer::Create("fuzz_timer_2", TimerType::ONCE, TIMER_DELAY_MS, []() {});
    auto timer3 = Timer::Create("fuzz_timer_3", TimerType::PERIODIC, TIMER_PERIOD_MS, []() {});
    (void)TimerCore::GetInstance().RegisterTimer(timestampMs, timer1);
    (void)TimerCore::GetInstance().RegisterTimer(timestampMs, timer2);
    (void)TimerCore::GetInstance().RegisterTimer(timestampMs, timer3);
    (void)TimerCore::GetInstance().DeregisterTimer(timestampMs, timer1);
    (void)TimerCore::GetInstance().DeregisterTimer(timestampMs, timer2);
    (void)TimerCore::GetInstance().DeregisterTimer(timestampMs, timer3);
}

static void TestTimerStart(FuzzedDataProvider& fdp)
{
    uint32_t delayMs = fdp.ConsumeIntegralInRange<uint32_t>(0, TIMER_START_MAX_MS);
    auto timer = Timer::Create("fuzz_timer_start", TimerType::ONCE, TIMER_DELAY_MS, []() {});
    if (timer) {
        (void)timer->Start(delayMs);
        (void)timer->Stop();
    }
}

static void TestTimerStartPeriodic(FuzzedDataProvider& fdp)
{
    uint32_t delayMs = fdp.ConsumeIntegralInRange<uint32_t>(0, TIMER_START_MAX_MS);
    auto timer = Timer::Create("fuzz_timer_start_periodic", TimerType::PERIODIC, TIMER_PERIOD_MS, []() {});
    if (timer) {
        (void)timer->Start(delayMs);
        (void)timer->IsActive();
        (void)timer->GetName();
        (void)timer->Stop();
    }
}

static void TestTimerStartAt(FuzzedDataProvider& fdp)
{
    uint64_t timestampMs = SteadyClock::GetTimestampMilli() +
        fdp.ConsumeIntegralInRange<uint64_t>(TIMER_START_OFFSET_MIN_MS, TIMER_START_OFFSET_MAX_MS);
    auto timer = Timer::Create("fuzz_timer_start_at", TimerType::ONCE, TIMER_DELAY_MS, []() {});
    if (timer) {
        (void)timer->StartAt(timestampMs);
    }
}

static void TestTimerMultipleStartStop(FuzzedDataProvider& fdp)
{
    auto timer = Timer::Create("fuzz_timer_multi", TimerType::PERIODIC, TIMER_REPEAT_DELAY_MS, []() {});
    if (timer) {
        (void)timer->Start(100);
        (void)timer->Start(TIMER_REPEAT_DELAY_MS);
        (void)timer->Stop();
        (void)timer->Stop();
    }
}

static void TestRegisterAndDeregister(FuzzedDataProvider& fdp)
{
    uint64_t timestampMs = fdp.ConsumeIntegral<uint64_t>();
    auto timer = Timer::Create("fuzz_timer", TimerType::ONCE, TIMER_DELAY_MS, []() {});
    (void)TimerCore::GetInstance().RegisterTimer(timestampMs, timer);
    (void)TimerCore::GetInstance().DeregisterTimer(timestampMs, timer);
}

static void Init()
{
    CHECK_RETURN_ELOG(!TestToken().GetAllCameraPermission(), "Get permission fail");
}

static void Test(FuzzedDataProvider& fdp)
{
    auto func = fdp.PickValueInArray({
        TestInitialize,
        TestRegisterTimer,
        TestRegisterTimerPeriodic,
        TestRegisterTimerNullptr,
        TestDeregisterTimer,
        TestDeregisterTimerNullptr,
        TestRegisterMultipleTimersSameTimestamp,
        TestTimerStart,
        TestTimerStartPeriodic,
        TestTimerStartAt,
        TestTimerMultipleStartStop,
        TestRegisterAndDeregister,
    });
    func(fdp);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    Test(fdp);
    return 0;
}

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    Init();
    return 0;
}
