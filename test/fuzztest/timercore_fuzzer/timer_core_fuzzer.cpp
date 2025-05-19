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

#include "timer_core_fuzzer.h"
#include "camera_log.h"
#include "message_parcel.h"
#include "securec.h"
#include <memory>
#include "timer.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace CameraStandard {
using namespace DeferredProcessing;
static constexpr int32_t MIN_SIZE_NUM = 10;
const size_t THRESHOLD = 10;
std::shared_ptr<TimerCore> TimerCoreFuzzer::fuzz_{nullptr};

void TimerCoreFuzzer::TimerCoreFuzzTest(FuzzedDataProvider& fdp)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }

    fuzz_ = std::make_shared<TimerCore>();
    CHECK_ERROR_RETURN_LOG(!fuzz_, "Create fuzz_ Error");
    fuzz_->Initialize();
    uint64_t timestampMs = fdp.ConsumeIntegralInRange<uint64_t>(0, 1000);
    std::function<void()> timerCallback;
    const std::shared_ptr<Timer>& timer = Timer::Create("camera_deferred_base",
        static_cast<TimerType>(fdp.ConsumeIntegralInRange(0, 1)), 0, timerCallback);
    fuzz_->GetInstance();
    fuzz_->RegisterTimer(timestampMs, timer);
    fuzz_->DeregisterTimer(timestampMs, timer);
}

void Test(uint8_t* data, size_t size)
{
    auto timercore = std::make_unique<TimerCoreFuzzer>();
    if (timercore == nullptr) {
        MEDIA_INFO_LOG("TimerCore is null");
        return;
    }
    FuzzedDataProvider fdp(data, size);
    timercore->TimerCoreFuzzTest(fdp);
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}