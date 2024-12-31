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

#ifndef HSTREAM_DEPTH_CALLBACK_STUB_FUZZER_H
#define HSTREAM_DEPTH_CALLBACK_STUB_FUZZER_H

#include "hstream_depth_data_callback_stub.h"

namespace OHOS {
namespace CameraStandard {

class HStreamDepthDataCallbackFuzz : public HStreamDepthDataCallbackStub {
public:
    int32_t OnDepthDataError(int32_t errorCode) override
    {
        return 0;
    }
};

class HStreamDepthDataCallbackStubFuzzer {
public:
static HStreamDepthDataCallbackFuzz *fuzz_;
static void OnRemoteRequest(int32_t code);
};
} //CameraStandard
} //OHOS
#endif //HSTREAM_DEPTH_CALLBACK_STUB_FUZZER_H