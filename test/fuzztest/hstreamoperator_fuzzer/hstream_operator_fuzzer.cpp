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

#include "hstream_operator_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include "camera_log.h"
#include "message_parcel.h"
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "accesstoken_kit.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "ipc_skeleton.h"
#include "buffer_extra_data_impl.h"
#include "camera_server_photo_proxy.h"
#include "camera_photo_proxy.h"

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MIN_SIZE_NUM = 64;
static constexpr int32_t NUM_1 = 1;
const size_t THRESHOLD = 10;

sptr<HStreamOperator> HStreamOperatorFuzzer::fuzz_{nullptr};

void HStreamOperatorFuzzer::HStreamOperatorFuzzTest(FuzzedDataProvider& fdp)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    fuzz_ = HStreamOperator::NewInstance(0, 0);
    CHECK_ERROR_RETURN_LOG(!fuzz_, "NewInstance Error");
    int32_t streamId = fdp.ConsumeIntegral<int32_t>();
    fuzz_->GetStreamByStreamID(streamId);
    int32_t rotation = fdp.ConsumeIntegral<int32_t>();
    int32_t format = fdp.ConsumeIntegral<int32_t>();
    int32_t captureId = fdp.ConsumeIntegral<int32_t>();
    int64_t timestamp = fdp.ConsumeIntegral<int64_t>();
    fuzz_->StartMovingPhotoEncode(rotation, timestamp, format, captureId);
    fuzz_->StartRecord(timestamp, rotation, captureId);
    fuzz_->GetHdiStreamByStreamID(streamId);
    fuzz_->EnableMovingPhotoMirror(fdp.ConsumeBool(), fdp.ConsumeBool());
    ColorSpace getColorSpace;
    fuzz_->GetActiveColorSpace(getColorSpace);
    constexpr int32_t executionModeCount = static_cast<int32_t>(ColorSpace::P3_PQ_LIMIT) + NUM_1;
    ColorSpace colorSpace = static_cast<ColorSpace>(fdp.ConsumeIntegral<uint8_t>() % executionModeCount);
    fuzz_->SetColorSpace(colorSpace, fdp.ConsumeBool());
    fuzz_->GetStreamOperator();
    std::vector<int32_t> results = {fdp.ConsumeIntegral<uint32_t>()};
    fuzz_->ReleaseStreams();
    std::vector<HDI::Camera::V1_1::StreamInfo_V1_1> streamInfos;
    fuzz_->CreateStreams(streamInfos);
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings;
    const int32_t NUM_10 = 10;
    const int32_t NUM_100 = 100;
    settings = std::make_shared<OHOS::Camera::CameraMetadata>(NUM_10, NUM_100);
    int32_t operationMode = fdp.ConsumeIntegral<int32_t>();
    fuzz_->CommitStreams(settings, operationMode);
    fuzz_->UpdateStreams(streamInfos);
    fuzz_->CreateAndCommitStreams(streamInfos, settings, operationMode);
    const std::vector<int32_t> streamIds;
    fuzz_->OnCaptureStarted(captureId, streamIds);
    const std::vector<OHOS::HDI::Camera::V1_2::CaptureStartedInfo> infos;
    fuzz_->OnCaptureStarted_V1_2(captureId, infos);
    const std::vector<CaptureEndedInfo> infos_OnCaptureEnded;
    fuzz_->OnCaptureEnded(captureId, infos_OnCaptureEnded);
    const std::vector<OHOS::HDI::Camera::V1_3::CaptureEndedInfoExt> infos_OnCaptureEndedExt;
    fuzz_->OnCaptureEndedExt(captureId, infos_OnCaptureEndedExt);
    const std::vector<CaptureErrorInfo> infos_OnCaptureError;
    fuzz_->OnCaptureError(captureId, infos_OnCaptureError);
    fuzz_->OnFrameShutter(captureId, results, timestamp);
    fuzz_->OnFrameShutterEnd(captureId, results, timestamp);
    fuzz_->OnCaptureReady(captureId, results, timestamp);
}

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    auto HStreamOperator = std::make_unique<HStreamOperatorFuzzer>();
    if (HStreamOperator == nullptr) {
        MEDIA_INFO_LOG("HStreamOperator is null");
        return;
    }
    HStreamOperator->HStreamOperatorFuzzTest(fdp);
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