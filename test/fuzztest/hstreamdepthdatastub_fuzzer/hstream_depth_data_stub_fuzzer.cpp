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

#include "hstream_depth_data_stub_fuzzer.h"
#include "camera_log.h"
#include "hstream_capture.h"
#include "iservice_registry.h"
#include "message_parcel.h"
#include "accesstoken_kit.h"
#include "camera_metadata_info.h"
#include "metadata_utils.h"
#include "iconsumer_surface.h"
#include "securec.h"
#include "stream_depth_data_callback_proxy.h"

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MIN_SIZE_NUM = 64;
static constexpr int32_t MAX_CODE_NUM = 4;
static const size_t MAX_BUFFER_SIZE = 32;

std::shared_ptr<HStreamDepthDataStubFuzz> HStreamDepthDataStubFuzzer::fuzz_{nullptr};

void HStreamDepthDataStubFuzzer::OnRemoteRequest(FuzzedDataProvider& fdp, int32_t code)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    fuzz_ = std::make_shared<HStreamDepthDataStubFuzz>();
    CHECK_ERROR_RETURN_LOG(!fuzz_, "Create fuzz_ Error");
    MessageParcel reply;
    MessageOption option;
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInterfaceToken(HStreamDepthDataStubFuzz::GetDescriptor());
    size_t bufferSize = fdp.ConsumeIntegralInRange<size_t>(0, MAX_BUFFER_SIZE);
    std::vector<uint8_t> buffer = fdp.ConsumeBytes<uint8_t>(bufferSize);
    dataMessageParcel.WriteBuffer(buffer.data(), buffer.size());
    dataMessageParcel.RewindRead(0);
    fuzz_->OnRemoteRequest(code, dataMessageParcel, reply, option);
}

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    auto hstreamDepthDataStub = std::make_unique<HStreamDepthDataStubFuzzer>();
    if (hstreamDepthDataStub == nullptr) {
        MEDIA_INFO_LOG("hstreamDepthDataStub is null");
        return;
    }
    for (uint32_t i = 0; i <= MAX_CODE_NUM; i++) {
        hstreamDepthDataStub->OnRemoteRequest(fdp, i);
    }
}

} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}