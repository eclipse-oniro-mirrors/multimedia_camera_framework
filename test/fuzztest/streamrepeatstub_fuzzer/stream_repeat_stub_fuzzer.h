 /*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef STREAM_REPEAT_STUB_FUZZER_H
#define STREAM_REPEAT_STUB_FUZZER_H

#include "hstream_repeat_stub.h"

namespace OHOS {
namespace CameraStandard {
namespace StreamRepeatStubFuzzer {

class HStreamRepeatStubMock : public HStreamRepeatStub {
public:
    int32_t RemoveSketchStreamRepeat() override
    {
        return 0;
    }
    int32_t SetFrameRate(int32_t minFrameRate, int32_t maxFrameRate) override
    {
        return 0;
    }
    int32_t SetCameraRotation(bool isEnable = false, int32_t rotation = 0, uint32_t apiCompatibleVersion = 0) override
    {
        return 0;
    }
    int32_t EnableSecure(bool isEnable = false) override
    {
        return 0;
    }
    int32_t SetMirror(bool isEnable) override
    {
        return 0;
    }
    int32_t OperatePermissionCheck(uint32_t interfaceCode) override
    {
        return 0;
    }
    int32_t Start() override
    {
        return 0;
    }
    int32_t Stop() override
    {
        return 0;
    }
    int32_t SetCallback(sptr<IStreamRepeatCallback>& callback) override
    {
        return 0;
    }
    int32_t Release() override
    {
        return 0;
    }
    int32_t AddDeferredSurface(const sptr<OHOS::IBufferProducer>& producer) override
    {
        return 0;
    }
    int32_t ForkSketchStreamRepeat(int32_t width, int32_t height,
        sptr<IStreamRepeat>& sketchStream, float sketchRatio) override
    {
        return 0;
    }
    int32_t UpdateSketchRatio(float sketchRatio) override
    {
        return 0;
    }
    int32_t AttachMetaSurface(const sptr<OHOS::IBufferProducer>& producer, int32_t videoMetaType) override
    {
        return 0;
    }
};

void Test(uint8_t *rawData, size_t size);
void Test_OnRemoteRequest(uint8_t *rawData, size_t size);

void CheckPermission();

}
}
}
#endif