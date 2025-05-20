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

#ifndef LIGHT_SACAN_SESSION_FUZZER_H
#define LIGHT_SACAN_SESSION_FUZZER_H

#include "light_painting_session.h"
#include "session/scan_session.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace CameraStandard {
class LightScanSessionFuzzer {
public:
static sptr<LightPaintingSession> fuzzLight_;
static sptr<ScanSession> fuzzScan_;
static void LightPaintingSessionFuzzTest(FuzzedDataProvider& fdp);
static void ScanSessionFuzzTest(FuzzedDataProvider& fdp);
};
} //CameraStandard
} //OHOS
#endif //LIGHT_SACAN_SESSION_FUZZER_H