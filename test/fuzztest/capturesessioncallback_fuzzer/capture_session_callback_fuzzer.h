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

#ifndef CAPTURE_SESSION_CALLBACK_FUZZER_H
#define CAPTURE_SESSION_CALLBACK_FUZZER_H

#include "session/capture_session.h"
#include "capture_session_callback_stub.h"
#include "fuzzer/FuzzedDataProvider.h"

namespace OHOS {
namespace CameraStandard {
namespace CaptureSessionCallbackFuzzer {

void Test(uint8_t* data, size_t size);
void TestCalculationHelper(FuzzedDataProvider& fdp);
void TestPressureStatusCallback(FuzzedDataProvider& fdp);
void TestControlCenterEffectStatusCallback(FuzzedDataProvider& fdp);
void TestCameraSwitchSessionCallback(FuzzedDataProvider& fdp);

class SessionCallbackMock : public SessionCallback {
public:
    void OnError(int32_t errorCode) override {}
};

} // CaptureSessionCallbackFuzzer
} // CameraStandard
} // OHOS
#endif // CAPTURE_SESSION_CALLBACK_FUZZER_H
