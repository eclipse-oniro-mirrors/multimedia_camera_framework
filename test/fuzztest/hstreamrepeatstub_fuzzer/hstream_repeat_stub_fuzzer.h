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

#ifndef HSTREAM_REPEAT_STUB_FUZZER_H
#define HSTREAM_REPEAT_STUB_FUZZER_H

#include "stream_repeat_stub.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace CameraStandard {
class HStreamRepeatStubFuzz : public StreamRepeatStub {
public:
    int32_t Start() override
    {
        return 0;
    }

    int32_t Stop() override
    {
        return 0;
    }

    int32_t SetCallback(const sptr<IStreamRepeatCallback>& callbackFunc) override
    {
        return 0;
    }

    int32_t Release() override
    {
        return 0;
    }

    int32_t AddDeferredSurface(const sptr<IBufferProducer>& producer) override
    {
        return 0;
    }

    int32_t RemoveDeferredSurface(const sptr<IBufferProducer>& producer) override
    {
        return 0;
    }

    int32_t ForkSketchStreamRepeat(
        int32_t width,
        int32_t height,
        sptr<IRemoteObject>& sketchStream,
        float sketchRatio) override
    {
        return 0;
    }

    int32_t RemoveSketchStreamRepeat() override
    {
        return 0;
    }

    int32_t UpdateSketchRatio(float sketchRatio) override
    {
        return 0;
    }

    int32_t SetFrameRate(int32_t minFrameRate, int32_t maxFrameRate) override
    {
        return 0;
    }

    int32_t EnableSecure(bool isEnable) override
    {
        return 0;
    }

    int32_t SetMirror(bool isEnable) override
    {
        return 0;
    }

    int32_t AttachMetaSurface(const sptr<IBufferProducer>& producer, int32_t videoMetaType) override
    {
        return 0;
    }

    int32_t SetCameraRotation(bool isEnable, int32_t rotation) override
    {
        return 0;
    }

    int32_t SetCameraApi(uint32_t apiCompatibleVersion) override
    {
        return 0;
    }

    int32_t GetMirror(bool& isEnable) override
    {
        return 0;
    }

    int32_t UnSetCallback() override
    {
        return 0;
    }

    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override
    {
        return 0;
    }

    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override
    {
        return 0;
    }
};
class HStreamRepeatStubFuzzer {
public:
    static std::shared_ptr<HStreamRepeatStubFuzz> fuzz_;
    static void HStreamRepeatStubFuzzTest1();
    static void HStreamRepeatStubFuzzTest2();
    static void HStreamRepeatStubFuzzTest3();
    static void HStreamRepeatStubFuzzTest4();
    static void HStreamRepeatStubFuzzTest5();
    static void HStreamRepeatStubFuzzTest6(FuzzedDataProvider &fdp);
    static void HStreamRepeatStubFuzzTest7();
    static void HStreamRepeatStubFuzzTest8(FuzzedDataProvider &fdp);
    static void HStreamRepeatStubFuzzTest9(FuzzedDataProvider &fdp);
    static void HStreamRepeatStubFuzzTest10(FuzzedDataProvider &fdp);
    static void HStreamRepeatStubFuzzTest11(FuzzedDataProvider &fdp);
    static void HStreamRepeatStubFuzzTest12(FuzzedDataProvider &fdp);
    static void HStreamRepeatStubFuzzTest13(FuzzedDataProvider &fdp);
    static void HStreamRepeatStubFuzzTest14(FuzzedDataProvider &fdp);
    static void HStreamRepeatStubFuzzTest15();
    static void HStreamRepeatStubFuzzTest16();
};
}  // namespace CameraStandard
}  // namespace OHOS
#endif  // HSTREAM_REPEAT_STUB_FUZZER_H