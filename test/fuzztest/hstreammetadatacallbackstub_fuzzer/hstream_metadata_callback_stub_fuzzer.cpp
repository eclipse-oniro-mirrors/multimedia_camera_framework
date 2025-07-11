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

#include "hstream_metadata_callback_stub_fuzzer.h"
#include "camera_log.h"
#include "hstream_capture.h"
#include "iservice_registry.h"
#include "message_parcel.h"
#include "accesstoken_kit.h"
#include "camera_metadata_info.h"
#include "metadata_utils.h"
#include "iconsumer_surface.h"
#include "securec.h"

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MIN_SIZE_NUM = 44;
static const size_t MAX_BUFFER_SIZE = 32;
std::shared_ptr<HStreamMetadataCallbackStubFuzz> HStreamMetadataCallbackStubFuzzer::fuzz_{nullptr};

/*
* describe: get data from outside untrusted data(g_data) which size is according to sizeof(T)
* tips: only support basic type
*/

void HStreamMetadataCallbackStubFuzzer::HStreamMetadataCallbackStubFuzzerTest(FuzzedDataProvider& fdp)
{
    fuzz_ = std::make_shared<HStreamMetadataCallbackStubFuzz>();
    CHECK_RETURN_ELOG(!fuzz_, "Create fuzz_ Error");
    MessageParcel reply;
    MessageOption option;
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInterfaceToken(HStreamMetadataCallbackStubFuzz::GetDescriptor());
    size_t bufferSize = fdp.ConsumeIntegralInRange<size_t>(0, MAX_BUFFER_SIZE);
    std::vector<uint8_t> buffer = fdp.ConsumeBytes<uint8_t>(bufferSize);
    dataMessageParcel.WriteBuffer(buffer.data(), buffer.size());
    dataMessageParcel.RewindRead(0);
    int32_t code = fdp.ConsumeIntegral<int32_t>();
    fuzz_->OnRemoteRequest(code, dataMessageParcel, reply, option);
}

void Test(uint8_t* data, size_t size)
{
    auto hstreamMetadataCallbackStub = std::make_unique<HStreamMetadataCallbackStubFuzzer>();
    CHECK_ERROR_RETURN_LOG(hstreamMetadataCallbackStub == nullptr, "hstreamMetadataCallbackStub is null");
    FuzzedDataProvider fdp(data, size);
    CHECK_ERROR_RETURN(fdp.remaining_bytes()  < MIN_SIZE_NUM);
    hstreamMetadataCallbackStub->HStreamMetadataCallbackStubFuzzerTest(fdp);
}

} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}