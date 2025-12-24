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

#ifndef CAPTURE_SESSION_PROXY_FUZZER_H
#define CAPTURE_SESSION_PROXY_FUZZER_H

#include "capture_session_proxy.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace CameraStandard {
class CaptureSessionProxyFuzz {
public:
    static std::shared_ptr<CaptureSessionProxy> fuzz_;
    static void CaptureSessionProxyFuzzTest1(FuzzedDataProvider &fdp);
    static void CaptureSessionProxyFuzzTest2(FuzzedDataProvider &fdp);
    static void CaptureSessionProxyFuzzTest3(FuzzedDataProvider &fdp);
    static void CaptureSessionProxyFuzzTest4(FuzzedDataProvider &fdp);
    static void CaptureSessionProxyFuzzTest5(FuzzedDataProvider &fdp);
    static void CaptureSessionProxyFuzzTest6();
    static void CaptureSessionProxyFuzzTest7(FuzzedDataProvider &fdp);
    static void CaptureSessionProxyFuzzTest8(FuzzedDataProvider &fdp);
    static void CaptureSessionProxyFuzzTest9(FuzzedDataProvider &fdp);
};
}  // namespace CameraStandard
}  // namespace OHOS
#endif  // CAPTURE_SESSION_PROXY_FUZZER_H