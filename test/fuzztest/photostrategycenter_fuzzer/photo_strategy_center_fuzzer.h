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

#ifndef PHOTO_STRATEGY_CENTER_FUZZER_H
#define PHOTO_STRATEGY_CENTER_FUZZER_H

#include "photo_strategy_center.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::CameraStandard::DeferredProcessing;

class FuzzStateListener : public PhotoStateListener {
public:
    void OnSchedulerChanged(const SchedulerType& type, const SchedulerInfo& info) override {}
};

class PhotoStrategyCenterFuzzer {
public:
    static std::shared_ptr<PhotoStrategyCenter> fuzz_;
    static void FuzzTest1();
    static void FuzzTest2();
    static void FuzzTest3();
    static void FuzzTest4();
};
} //CameraStandard
} //OHOS
#endif //PHOTO_STRATEGY_CENTER_FUZZER_H
