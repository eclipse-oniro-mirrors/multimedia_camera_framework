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

#include "dps_video_report_fuzzer.h"
#include "camera_log.h"
#include "message_parcel.h"
#include "securec.h"

namespace OHOS {
namespace CameraStandard {
using namespace DeferredProcessing;
static constexpr int32_t MIN_SIZE_NUM = 4;
const size_t THRESHOLD = 10;
const size_t MAX_LENGTH_STRING = 64;

std::shared_ptr<DfxVideoReport> DfxVideoReportFuzzer::fuzz_{nullptr};

void DfxVideoReportFuzzer::DfxVideoReportFuzzTest(FuzzedDataProvider& fdp)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    fuzz_ = std::make_shared<DfxVideoReport>();
    CHECK_ERROR_RETURN_LOG(!fuzz_, "Create fuzz_ Error");
    DpsCallerInfo callerInfo;
    std::string videoId(fdp.ConsumeRandomLengthString(MAX_LENGTH_STRING));
    callerInfo.bundleName = (fdp.ConsumeRandomLengthString(MAX_LENGTH_STRING));
    callerInfo.version = (fdp.ConsumeRandomLengthString(MAX_LENGTH_STRING));
    callerInfo.pid = 0;
    callerInfo.uid = 0;
    callerInfo.tokenID = 0;
    DfxVideoReport::GetInstance().ReportAddVideoEvent(videoId, callerInfo);
    int32_t pauseReason = fdp.ConsumeIntegral<int32_t>();
    DfxVideoReport::GetInstance().ReportPauseVideoEvent(videoId, pauseReason);
    DfxVideoReport::GetInstance().ReportResumeVideoEvent(videoId);
    DfxVideoReport::GetInstance().ReportCompleteVideoEvent(videoId);
}

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    auto dfxVideoReport = std::make_unique<DfxVideoReportFuzzer>();
    if (dfxVideoReport == nullptr) {
        MEDIA_INFO_LOG("dfxVideoReport is null");
        return;
    }
    dfxVideoReport->DfxVideoReportFuzzTest(fdp);
}

} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    if (size < OHOS::CameraStandard::THRESHOLD) {
        return 0;
    }

    OHOS::CameraStandard::Test(data, size);
    return 0;
}