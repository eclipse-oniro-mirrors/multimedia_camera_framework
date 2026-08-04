/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <fuzzer/FuzzedDataProvider.h>
#include <memory>
#include <string>
#include <vector>
#include "fuzz_util.h"
#include "test_token.h"
#include "post_processor/photo_process_result.h"
#include "camera_log.h"

using namespace OHOS;
using namespace OHOS::CameraStandard;
using namespace OHOS::CameraStandard::DeferredProcessing;

void TestOnProcessDone(FuzzedDataProvider& fdp)
{
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    auto photoProcessResult = std::make_shared<PhotoProcessResult>(userId);
    std::string imageId = "img_" + std::to_string(fdp.ConsumeIntegral<int32_t>());
    (void)photoProcessResult->OnProcessDone(imageId, nullptr);
}

void TestOnError(FuzzedDataProvider& fdp)
{
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    auto photoProcessResult = std::make_shared<PhotoProcessResult>(userId);
    std::string imageId = "img_" + std::to_string(fdp.ConsumeIntegral<int32_t>());
    int32_t errorCode = fdp.ConsumeIntegral<int32_t>();
    (void)photoProcessResult->OnError(imageId, static_cast<DpsError>(errorCode));
}

void TestOnStateChanged(FuzzedDataProvider& fdp)
{
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    auto photoProcessResult = std::make_shared<PhotoProcessResult>(userId);
    int32_t status = fdp.ConsumeIntegral<int32_t>();
    (void)photoProcessResult->OnStateChanged(static_cast<HdiStatus>(status));
}

void TestOnPhotoSessionDied(FuzzedDataProvider& fdp)
{
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    auto photoProcessResult = std::make_shared<PhotoProcessResult>(userId);
    (void)photoProcessResult->OnPhotoSessionDied();
}

static void Init()
{
    CHECK_RETURN_ELOG(!TestToken().GetAllCameraPermission(), "Get permission fail");
}

static void Test(FuzzedDataProvider& fdp)
{
    auto func = fdp.PickValueInArray({
        TestOnProcessDone,
        TestOnError,
        TestOnStateChanged,
        TestOnPhotoSessionDied,
    });
    func(fdp);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    Test(fdp);
    return 0;
}

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    if (SetSelfTokenID(718336240ull | (1ull << 32)) < 0) {
        return -1;
    }
    Init();
    return 0;
}
