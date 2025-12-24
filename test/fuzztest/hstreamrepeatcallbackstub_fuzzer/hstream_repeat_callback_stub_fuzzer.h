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

#ifndef HSTREAM_REPEAT_CALLBACK_STUB_FUZZER_H
#define HSTREAM_REPEAT_CALLBACK_STUB_FUZZER_H

#include "stream_repeat_callback_stub.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace CameraStandard {
class HStreamRepeatCallbackStubFuzz : public StreamRepeatCallbackStub {
public:
    int32_t OnFrameStarted() override
    {
        return 0;
    }

    int32_t OnFrameEnded(int32_t frameCount) override
    {
        return 0;
    }

    int32_t OnFrameError(int32_t errorCode) override
    {
        return 0;
    }

    int32_t OnSketchStatusChanged(SketchStatus status) override
    {
        return 0;
    }

    int32_t OnDeferredVideoEnhancementInfo(const CaptureEndedInfoExt& captureEndedInfo) override
    {
        return 0;
    }

    int32_t OnFramePaused() override
    {
        return 0;
    }

    int32_t OnFrameResumed() override
    {
        return 0;
    }
};
class HStreamRepeatCallbackStubFuzzer {
public:
    static std::shared_ptr<HStreamRepeatCallbackStubFuzz> fuzz_;
    static void HStreamRepeatCallbackStubFuzzTest1();
    static void HStreamRepeatCallbackStubFuzzTest2(FuzzedDataProvider &fdp);
    static void HStreamRepeatCallbackStubFuzzTest3(FuzzedDataProvider &fdp);
    static void HStreamRepeatCallbackStubFuzzTest4(FuzzedDataProvider &fdp);
    static void HStreamRepeatCallbackStubFuzzTest5();
    static void HStreamRepeatCallbackStubFuzzTest6();
};
}  // namespace CameraStandard
}  // namespace OHOS
#endif  // HSTREAM_REPEAT_CALLBACK_STUB_FUZZER_H