/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "time_broker_fuzzer.h"
#include "camera_log.h"
#include "message_parcel.h"
#include "securec.h"
#include <memory>
#include "timer/camera_deferred_timer.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace CameraStandard {
using namespace DeferredProcessing;
static constexpr int32_t MIN_SIZE_NUM = 10;
std::shared_ptr<TimeBroker> TimeBrokerFuzzer::fuzz_{nullptr};

void TimeBrokerFuzzer::TimeBrokerFuzzTest(FuzzedDataProvider& fdp)
{
    fuzz_ = TimeBroker::Create("camera_deferred_base");
    CHECK_RETURN_ELOG(!fuzz_, "Create fuzz_ Error");
    fuzz_->Initialize();
    uint32_t handle = fuzz_->GenerateHandle();
    std::function<void(uint32_t handle)> timerCallback = fuzz_->GetExpiredFunc(handle);
    fuzz_->GetNextHandle(handle);
    uint32_t delayTimeMs = fdp.ConsumeIntegralInRange<uint32_t>(0, 10);
    bool force = fdp.ConsumeBool();
    fuzz_->RegisterCallback(delayTimeMs, timerCallback, handle);
    fuzz_->RestartTimer(force);
    fuzz_->TimerExpired();
    fuzz_->DeregisterCallback(handle);
}

void Test(uint8_t* data, size_t size)
{
    auto timeBroker = std::make_unique<TimeBrokerFuzzer>();
    if (timeBroker == nullptr) {
        MEDIA_INFO_LOG("TimeBroker is null");
        return;
    }
    FuzzedDataProvider fdp(data, size);
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    timeBroker->TimeBrokerFuzzTest(fdp);
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}