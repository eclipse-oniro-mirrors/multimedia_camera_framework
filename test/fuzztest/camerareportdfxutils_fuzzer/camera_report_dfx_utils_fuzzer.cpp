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

#include "camera_report_dfx_utils_fuzzer.h"
#include "camera_log.h"
#include "message_parcel.h"
#include "securec.h"
#include <mutex>

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MIN_SIZE_NUM = 4;

std::shared_ptr<CameraReportDfxUtils> CameraReportDfxUtilsFuzzer::fuzz_{nullptr};

/*
* describe: get data from outside untrusted data(g_data) which size is according to sizeof(T)
* tips: only support basic type
*/
void CameraReportDfxUtilsFuzzer::CameraReportDfxUtilsFuzzTest(FuzzedDataProvider& fdp)
{
    fuzz_ = std::make_shared<CameraReportDfxUtils>();
    CHECK_RETURN_ELOG(!fuzz_, "Create fuzz_ Error");
    int32_t captureId = fdp.ConsumeIntegral<int32_t>();
    fuzz_->SetFirstBufferEndInfo(captureId);
    fuzz_->SetPrepareProxyStartInfo(captureId);
    fuzz_->SetAddProxyEndInfo(captureId);
    fuzz_->SetAddProxyStartInfo(captureId);
    fuzz_->SetAddProxyEndInfo(captureId);
    CaptureDfxInfo captureInfo;
    fuzz_->ReportPerformanceDeferredPhoto(captureInfo);
}

void Test(uint8_t* data, size_t size)
{
    auto cameraReportDfxUtils = std::make_unique<CameraReportDfxUtilsFuzzer>();
    if (cameraReportDfxUtils == nullptr) {
        MEDIA_INFO_LOG("cameraReportDfxUtils is null");
        return;
    }
    FuzzedDataProvider fdp(data, size);
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    cameraReportDfxUtils->CameraReportDfxUtilsFuzzTest(fdp);
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}