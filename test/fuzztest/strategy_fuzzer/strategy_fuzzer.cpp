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

#include "strategy_fuzzer.h"
#include "camera_log.h"
#include "message_parcel.h"
#include "common_event_support.h"
#include "securec.h"
#include "camera_util.h"

namespace OHOS {
namespace CameraStandard {
using namespace DeferredProcessing;
static constexpr int32_t MAX_CODE_LEN  = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static const uint8_t* RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
static size_t g_dataSize = 0;
static size_t g_pos;
BatteryLevelStrategy *BatteryLevelStrategyFuzzer::fuzz = nullptr;
BatteryStrategy *BatteryStrategyFuzzer::fuzz = nullptr;
ChargingStrategy *ChargingStrategyFuzzer::fuzz = nullptr;
ScreenStrategy *ScreenStrategyFuzzer::fuzz = nullptr;
ThermalStrategy *ThermalStrategyFuzzer::fuzz = nullptr;
EventFwk::CommonEventData CommonEventData;

/*
* describe: get data from outside untrusted data(g_data) which size is according to sizeof(T)
* tips: only support basic type
*/
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

template<class T>
uint32_t GetArrLength(T& arr)
{
    if (arr == nullptr) {
        MEDIA_INFO_LOG("%{public}s: The array length is equal to 0", __func__);
        return 0;
    }
    return sizeof(arr) / sizeof(arr[0]);
}

void BatteryLevelStrategyFuzzer::BatteryLevelStrategyFuzzTest()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    if (fuzz) {
        fuzz = new BatteryLevelStrategy();
    }
}

void BatteryStrategyFuzzer::BatteryStrategyFuzzTest()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    if (fuzz) {
        fuzz = new BatteryStrategy();
    }
    fuzz->handleEvent(CommonEventData);
}

void ChargingStrategyFuzzer::ChargingStrategyFuzzTest()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    if (fuzz) {
        fuzz = new ChargingStrategy();
    }
    fuzz->handleEvent(CommonEventData);
}

void ScreenStrategyFuzzer::ScreenStrategyFuzzTest()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    if (fuzz) {
        fuzz = new ScreenStrategy();
    }
    fuzz->handleEvent(CommonEventData);
}

void ThermalStrategyFuzzer::ThermalStrategyFuzzTest()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    if (fuzz) {
        fuzz = new ThermalStrategy();
    }
}

void Test()
{
    OHOS::AAFwk::Want want;
    uint8_t randomNum = GetData<uint8_t>();
    std::vector<std::string> testStrings = {"test1", "test2"};
    std::string cameraID_(testStrings[randomNum % testStrings.size()]);
    //int32_t state = GetData<int32_t>();
    int clientUserId_ = GetData<int>();
    want.SetAction(COMMON_EVENT_CAMERA_STATUS);
    want.SetParam(CLIENT_USER_ID, clientUserId_);
    want.SetParam(CAMERA_ID, cameraID_);
    //want.SetParam(CAMERA_STATE, state);
    // int32_t type = GetCameraType();
    // want.SetParam(IS_SYSTEM_CAMERA, type);
    EventFwk::CommonEventData CommonEventData { want };
    //CommonEventData = { want };
    auto batteryLevelStrategy = std::make_unique<BatteryLevelStrategyFuzzer>();
    if (batteryLevelStrategy == nullptr) {
        MEDIA_INFO_LOG("batteryLevelStrategy is null");
        return;
    }
    batteryLevelStrategy->BatteryLevelStrategyFuzzTest();
    auto batteryStrategy = std::make_unique<BatteryStrategyFuzzer>();
    if (batteryStrategy == nullptr) {
        MEDIA_INFO_LOG("batteryStrategy is null");
        return;
    }
    batteryStrategy->BatteryStrategyFuzzTest();
    auto chargingStrategy = std::make_unique<ChargingStrategyFuzzer>();
    if (chargingStrategy == nullptr) {
        MEDIA_INFO_LOG("chargingStrategy is null");
        return;
    }
    chargingStrategy->ChargingStrategyFuzzTest();
    auto screenStrategy = std::make_unique<ScreenStrategyFuzzer>();
    if (screenStrategy == nullptr) {
        MEDIA_INFO_LOG("screenStrategy is null");
        return;
    }
    screenStrategy->ScreenStrategyFuzzTest();
    auto thermalStrategy = std::make_unique<ThermalStrategyFuzzer>();
    if (thermalStrategy == nullptr) {
        MEDIA_INFO_LOG("thermalStrategy is null");
        return;
    }
    thermalStrategy->ThermalStrategyFuzzTest();
}

typedef void (*TestFuncs[1])();

TestFuncs g_testFuncs = {
    Test,
};

bool FuzzTest(const uint8_t* rawData, size_t size)
{
    // initialize data
    RAW_DATA = rawData;
    g_dataSize = size;
    g_pos = 0;

    uint32_t code = GetData<uint32_t>();
    uint32_t len = GetArrLength(g_testFuncs);
    if (len > 0) {
        g_testFuncs[code % len]();
    } else {
        MEDIA_INFO_LOG("%{public}s: The len length is equal to 0", __func__);
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

    OHOS::AAFwk::Want want;
    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_LOW);
    OHOS::EventFwk::CommonEventData CommonEventData { want };
    OHOS::CameraStandard::FuzzTest(data, size);
    return 0;
}