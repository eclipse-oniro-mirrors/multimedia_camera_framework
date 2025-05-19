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

#include "hstream_metadata_callback_proxy_fuzzer.h"
#include "camera_log.h"
#include "message_parcel.h"
#include "metadata_utils.h"
#include "securec.h"

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MIN_SIZE_NUM = 8;
const size_t THRESHOLD = 10;

std::shared_ptr<HStreamMetadataCallbackProxy> HStreamMetadataCallbackProxyFuzzer::fuzz_{nullptr};

void HStreamMetadataCallbackProxyFuzzer::HStreamMetadataCallbackProxyFuzzTest(FuzzedDataProvider& fdp)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    sptr<IRemoteObject> impl;
    fuzz_ = std::make_shared<HStreamMetadataCallbackProxy>(impl);
    CHECK_ERROR_RETURN_LOG(!fuzz_, "Create fuzz_ Error");
    int32_t streamId = fdp.ConsumeIntegral<int32_t>();
    const std::shared_ptr<OHOS::Camera::CameraMetadata> result;
    fuzz_->OnMetadataResult(streamId, result);
}

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    auto hstreamMetadataCallbackProxy = std::make_unique<HStreamMetadataCallbackProxyFuzzer>();
    if (hstreamMetadataCallbackProxy == nullptr) {
        MEDIA_INFO_LOG("hstreamMetadataCallbackProxy is null");
        return;
    }
    hstreamMetadataCallbackProxy->HStreamMetadataCallbackProxyFuzzTest(fdp);
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