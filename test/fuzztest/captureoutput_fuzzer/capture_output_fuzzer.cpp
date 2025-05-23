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

#include "capture_output_fuzzer.h"
#include "camera_input.h"
#include "camera_log.h"
#include "camera_photo_proxy.h"
#include "capture_input.h"
#include "capture_output.h"
#include "capture_scene_const.h"
#include "input/camera_manager.h"
#include "message_parcel.h"
#include "refbase.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "accesstoken_kit.h"
#include "securec.h"

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MIN_SIZE_NUM = 8;

std::shared_ptr<CaptureOutput> CaptureOutputFuzzer::fuzz_{nullptr};

/*
* describe: get data from outside untrusted data(g_data) which size is according to sizeof(T)
* tips: only support basic type
*/
void CaptureOutputFuzzer::CaptureOutputFuzzTest(FuzzedDataProvider& fdp)
{
    int32_t randomInt = fdp.ConsumeIntegral<int32_t>();
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    CHECK_ERROR_RETURN_LOG(photoSurface, "PhotoOutputFuzzer: create photoSurface Error");
    sptr<IBufferProducer> bufferProducer = photoSurface->GetProducer();
    CHECK_ERROR_RETURN_LOG(bufferProducer, "GetProducer Error");
    sptr<IStreamCommon> stream;
    CaptureOutputType randomOutputType = static_cast<CaptureOutputType>(
    (randomInt % static_cast<int32_t>(CAPTURE_OUTPUT_TYPE_MAX)));
    fuzz_ = std::make_shared<CaptureOutputTest>(randomOutputType, StreamType::CAPTURE, bufferProducer, stream);
    CHECK_ERROR_RETURN_LOG(!fuzz_, "Create fuzz_ Error");
    fuzz_->GetBufferProducer();
    int32_t pid = fdp.ConsumeIntegral<int32_t>();
    fuzz_->OnCameraServerDied(pid);
    fuzz_->IsStreamCreated();
    DepthProfile depthProfile;
    fuzz_->SetDepthProfile(depthProfile);
    fuzz_->GetDepthProfile();
    fuzz_->ClearProfiles();
    fuzz_->AddTag(CaptureOutput::Tag::DYNAMIC_PROFILE);
    fuzz_->RemoveTag(CaptureOutput::Tag::DYNAMIC_PROFILE);
}

void Test(uint8_t* data, size_t size)
{
    auto captureOutput = std::make_unique<CaptureOutputFuzzer>();
    if (captureOutput == nullptr) {
        MEDIA_INFO_LOG("captureOutput is null");
        return;
    }
    FuzzedDataProvider fdp(data, size);
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    captureOutput->CaptureOutputFuzzTest(fdp);
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}