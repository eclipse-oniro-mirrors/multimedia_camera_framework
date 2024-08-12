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

#ifndef CAMERA_INPUT_FUZZER_H
#define CAMERA_INPUT_FUZZER_H

#include "hstream_repeat_stub.h"
#include "input/camera_input.h"

namespace OHOS {
namespace CameraStandard {
namespace CameraInputFuzzer {

class ResultCallbackMock : public ResultCallback {
public:
    void OnResult(const uint64_t timestamp,
    const std::shared_ptr<OHOS::Camera::CameraMetadata> &result) const override {}
};

class ErrorCallbackMock : public ErrorCallback {
public:
    void OnError(const int32_t errorType, const int32_t errorMsg) const override {}
};

void Test(uint8_t *rawData, size_t size);
void TestInput(sptr<CameraInput> input, uint8_t *rawData, size_t size);

}
}
}
#endif