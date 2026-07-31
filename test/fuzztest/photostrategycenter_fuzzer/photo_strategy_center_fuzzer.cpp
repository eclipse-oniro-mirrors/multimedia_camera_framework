/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "photo_strategy_center_fuzzer.h"
#include "basic_definitions.h"
#include "camera_log.h"
#include "securec.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace OHOS {
namespace CameraStandard {
using namespace DeferredProcessing;
std::shared_ptr<PhotoStrategyCenter> PhotoStrategyCenterFuzzer::fuzz_{nullptr};
static constexpr int32_t MAX_CODE_LEN = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static const uint8_t* RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
static size_t g_dataSize = 0;
static size_t g_pos;

template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (RAW_DATA == nullptr || objectSize > g_dataSize - g_pos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, RAW_DATA + g_pos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_pos += objectSize;
    return object;
}

// covers: RegisterStateChangeListener(null/non-null), IsReady, GetExecutionMode(NORMAL/HIGH),
// GetHdiStatus, HandleEventChanged(event found / not found)
void PhotoStrategyCenterFuzzer::FuzzTest1()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    auto repository = PhotoJobRepository::Create(GetData<int32_t>());
    CHECK_RETURN_ELOG(!repository, "Create repository Error");
    fuzz_ = PhotoStrategyCenter::Create(repository);
    CHECK_RETURN_ELOG(!fuzz_, "Create fuzz_ Error");
    auto listener = std::make_shared<FuzzStateListener>();
    fuzz_->RegisterStateChangeListener(listener);
    fuzz_->IsReady();
    fuzz_->GetExecutionMode(JobPriority::NORMAL);
    fuzz_->GetExecutionMode(JobPriority::HIGH);
    fuzz_->GetHdiStatus();
    int32_t value = GetData<int32_t>();
    fuzz_->HandleEventChanged(CAMERA_SESSION_STATUS_EVENT, value);
    fuzz_->HandleEventChanged(static_cast<EventType>(99), value);
}

// covers: HandleCameraEvent switch (SYSTEM_CAMERA_CLOSED / NORMAL_CAMERA_CLOSED / default),
// HandleHalEvent/HandleTrailingEvent/HandleMedialLibraryEvent; listener null -> UpdateValue null branch
void PhotoStrategyCenterFuzzer::FuzzTest2()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    auto repository = PhotoJobRepository::Create(GetData<int32_t>());
    CHECK_RETURN_ELOG(!repository, "Create repository Error");
    fuzz_ = PhotoStrategyCenter::Create(repository);
    CHECK_RETURN_ELOG(!fuzz_, "Create fuzz_ Error");
    fuzz_->HandleCameraEvent(CameraSessionStatus::SYSTEM_CAMERA_CLOSED);
    fuzz_->HandleCameraEvent(CameraSessionStatus::NORMAL_CAMERA_CLOSED);
    fuzz_->HandleCameraEvent(CameraSessionStatus::SYSTEM_CAMERA_OPEN);
    int32_t value = GetData<int32_t>();
    fuzz_->HandleHalEvent(value);
    fuzz_->HandleTrailingEvent(value);
    fuzz_->HandleMedialLibraryEvent(value);
}

// covers: HandleTemperatureEvent/HandleInterruptEvent/HandleCacheEvent, UpdateValue with listener set
// (OnSchedulerChanged branch) and multiple SchedulerType to trigger UpdateSchedulerInfo true/false
void PhotoStrategyCenterFuzzer::FuzzTest3()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    auto repository = PhotoJobRepository::Create(GetData<int32_t>());
    CHECK_RETURN_ELOG(!repository, "Create repository Error");
    fuzz_ = PhotoStrategyCenter::Create(repository);
    CHECK_RETURN_ELOG(!fuzz_, "Create fuzz_ Error");
    auto listener = std::make_shared<FuzzStateListener>();
    fuzz_->RegisterStateChangeListener(listener);
    int32_t value = GetData<int32_t>();
    fuzz_->HandleTemperatureEvent(value);
    fuzz_->HandleInterruptEvent(value);
    fuzz_->HandleCacheEvent(value);
    fuzz_->UpdateValue(PHOTO_CAMERA_STATE, CameraSessionStatus::SYSTEM_CAMERA_OPEN);
    fuzz_->UpdateValue(PHOTO_HAL_STATE, HdiStatus::HDI_READY);
    fuzz_->UpdateValue(PHOTO_INTERRUPT_STATE, InterruptStatus::IS_INTERRUPT);
}

// covers: GetJob (repository_->GetJob() null with empty repo / non-null with added job + mode DUMMY)
void PhotoStrategyCenterFuzzer::FuzzTest4()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    auto repository = PhotoJobRepository::Create(GetData<int32_t>());
    CHECK_RETURN_ELOG(!repository, "Create repository Error");
    DpsMetadata metadata;
    repository->AddDeferredJob("img1", false, metadata, "com.test.bundle");
    fuzz_ = PhotoStrategyCenter::Create(repository);
    CHECK_RETURN_ELOG(!fuzz_, "Create fuzz_ Error");
    fuzz_->GetJob();
    auto emptyRepo = PhotoJobRepository::Create(GetData<int32_t>());
    auto emptyStrategy = PhotoStrategyCenter::Create(emptyRepo);
    CHECK_RETURN_ELOG(!emptyStrategy, "Create emptyStrategy Error");
    emptyStrategy->GetJob();
}

void RunFuzzTest1() { PhotoStrategyCenterFuzzer::FuzzTest1(); }
void RunFuzzTest2() { PhotoStrategyCenterFuzzer::FuzzTest2(); }
void RunFuzzTest3() { PhotoStrategyCenterFuzzer::FuzzTest3(); }
void RunFuzzTest4() { PhotoStrategyCenterFuzzer::FuzzTest4(); }

typedef void (*TestFuncs[4])();
TestFuncs g_testFuncs = { RunFuzzTest1, RunFuzzTest2, RunFuzzTest3, RunFuzzTest4 };

bool FuzzTest(const uint8_t* rawData, size_t size)
{
    RAW_DATA = rawData;
    g_dataSize = size;
    g_pos = 0;
    uint32_t code = GetData<uint32_t>();
    uint32_t len = sizeof(g_testFuncs) / sizeof(g_testFuncs[0]);
    if (len > 0) {
        g_testFuncs[code % len]();
    }
    return true;
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    if (size < OHOS::CameraStandard::THRESHOLD) {
        return 0;
    }
    OHOS::CameraStandard::FuzzTest(data, size);
    return 0;
}
