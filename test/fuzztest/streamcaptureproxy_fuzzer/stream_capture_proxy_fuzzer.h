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

#ifndef STREAM_CAPTURE_PROXY_FUZZER_H
#define STREAM_CAPTURE_PROXY_FUZZER_H
#define FUZZ_PROJECT_NAME "streamcaptureproxy_fuzzer"

#include "stream_capture_proxy.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace CameraStandard {
class StreamCaptureProxyFuzzer {
public:
static std::shared_ptr<StreamCaptureProxy> fuzz_;
static void StreamCaptureProxyFuzzTest1(FuzzedDataProvider& fdp);
static void StreamCaptureProxyFuzzTest2(FuzzedDataProvider& fdp);
static void StreamCaptureProxyFuzzTest3(FuzzedDataProvider& fdp);
static void StreamCaptureProxyFuzzTest4(FuzzedDataProvider& fdp);
static void StreamCaptureProxyFuzzTest5(FuzzedDataProvider& fdp);
static void StreamCaptureProxyFuzzTest6(FuzzedDataProvider& fdp);
static void StreamCaptureProxyFuzzTest7(FuzzedDataProvider& fdp);
static void StreamCaptureProxyFuzzTest8(FuzzedDataProvider& fdp);
static void StreamCaptureProxyFuzzTest9(FuzzedDataProvider& fdp);
static void StreamCaptureProxyFuzzTest10(FuzzedDataProvider& fdp);
static void StreamCaptureProxyFuzzTest11(FuzzedDataProvider& fdp);
static void StreamCaptureProxyFuzzTest12(FuzzedDataProvider& fdp);
static void StreamCaptureProxyFuzzTest13(FuzzedDataProvider& fdp);
static void StreamCaptureProxyFuzzTest14(FuzzedDataProvider& fdp);
static void StreamCaptureProxyFuzzTest15(FuzzedDataProvider& fdp);
static void StreamCaptureProxyFuzzTest16(FuzzedDataProvider& fdp);
static void StreamCaptureProxyFuzzTest17(FuzzedDataProvider& fdp);
static void StreamCaptureProxyFuzzTest18(FuzzedDataProvider& fdp);
static void StreamCaptureProxyFuzzTest19(FuzzedDataProvider& fdp);
static void StreamCaptureProxyFuzzTest20();
};


} //CameraStandard
} //OHOS
#endif //STREAM_CAPTURE_PROXY_FUZZER_H
