/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "smooth_zoom_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>
#include "test_token.h"

namespace OHOS {
namespace CameraStandard {

std::shared_ptr<SmoothZoom> SmoothZoomFuzzer::fuzz_ { nullptr };
static constexpr int32_t MIN_SIZE_NUM = 13;

void SmoothZoomFuzzer::Test(uint8_t* rawData, size_t size)
{
    FuzzedDataProvider fdp(rawData, size);
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    CHECK_RETURN_ELOG(!TestToken().GetAllCameraPermission(), "GetPermission error");

    fuzz_ = std::make_shared<SmoothZoom>();
    CHECK_RETURN_ELOG(!fuzz_, "Create fuzz_ Error");

    SmoothZoomType mode = static_cast<SmoothZoomType>(fdp.ConsumeBool());
    auto alg = fuzz_->GetZoomAlgorithm(mode);

    float currentZoom = fdp.ConsumeFloatingPoint<float>();
    float targetZoom = fdp.ConsumeFloatingPoint<float>();
    float frameInterval = fdp.ConsumeFloatingPoint<float>();
    alg->GetZoomArray(currentZoom, targetZoom, frameInterval);
}

} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::CameraStandard::SmoothZoomFuzzer::Test(data, size);
    return 0;
}