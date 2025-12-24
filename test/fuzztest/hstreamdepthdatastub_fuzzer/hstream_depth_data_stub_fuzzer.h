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

#ifndef HSTREAM_DEPTH_STUB_FUZZER_H
#define HSTREAM_DEPTH_STUB_FUZZER_H

#include "stream_depth_data_stub.h"
#include <fuzzer/FuzzedDataProvider.h>
#include "icamera_ipc_checker.h"

namespace OHOS {
namespace CameraStandard {

class HStreamDepthDataStubFuzz : public StreamDepthDataStub, public ICameraIpcChecker {
public:
    int32_t Start() override
    {
        return 0;
    }
    int32_t Stop() override
    {
        return 0;
    }
    int32_t SetCallback(const sptr<IStreamDepthDataCallback>& callback) override
    {
        return 0;
    }
    int32_t UnSetCallback() override
    {
        return 0;
    }
    int32_t SetDataAccuracy(int32_t dataAccuracy) override
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
    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override
    {
        return 0;
    }
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override
    {
        return 0;
    }
};

class HStreamDepthDataStubFuzzer {
public:
static std::shared_ptr<HStreamDepthDataStubFuzz> fuzz_;
static void OnRemoteRequest(FuzzedDataProvider& fdp, int32_t code);
};
} //CameraStandard
} //OHOS
#endif //HSTREAM_DEPTH_STUB_FUZZER_H