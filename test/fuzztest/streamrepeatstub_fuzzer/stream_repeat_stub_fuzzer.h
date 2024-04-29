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

class StreamRepeatStubFuzzer {
public:
static bool hasPermission;
static HStreamRepeatStub *fuzz;

static void Test(uint8_t *rawData, size_t size);
static void CheckPermission();
};

}
}
#endif