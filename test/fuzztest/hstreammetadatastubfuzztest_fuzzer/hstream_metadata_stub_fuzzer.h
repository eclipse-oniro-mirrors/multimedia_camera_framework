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

#ifndef HSTREAM_METADATA_STUB_FUZZER_H
#define HSTREAM_METADATA_STUB_FUZZER_H

#include "hstream_metadata_stub.h"

namespace OHOS {
namespace CameraStandard {

class HStreamMetadataStubFuzz : public HStreamMetadataStub {
public:
    int32_t Start() override
    {
        return 0;
    }
    int32_t Stop() override
    {
        return 0;
    }
    int32_t SetCallback(sptr<IStreamMetadataCallback>& callback) override
    {
        return 0;
    }
    int32_t Release() override
    {
        return 0;
    }
    int32_t OperatePermissionCheck(uint32_t interfaceCode) override
    {
        return 0;
    }
    int32_t EnableMetadataType(std::vector<int32_t> metadataTypes) override
    {
        return 0;
    }
    int32_t DisableMetadataType(std::vector<int32_t> metadataTypes) override
    {
        return 0;
    }
};

class HStreamMetadataStubFuzzer {
public:
static HStreamMetadataStubFuzz *fuzz_;
static void OnRemoteRequest(int32_t code);
};
} //CameraStandard
} //OHOS
#endif //HSTREAM_METADATA_STUB_FUZZER_H