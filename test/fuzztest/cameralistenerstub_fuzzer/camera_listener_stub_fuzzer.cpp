/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "camera_listener_stub_fuzzer.h"
#include "camera_log.h"
#include "hcamera_listener_proxy.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "accesstoken_kit.h"

namespace {
    const size_t MAX_DATA_SIZE = 18;
    const int32_t LIMITSIZE = (MAX_DATA_SIZE + 1) * 9;
}

namespace OHOS {
namespace CameraStandard {

bool CameraListenerStubFuzzer::hasPermission = false;
std::shared_ptr<CameraListenerStub> CameraListenerStubFuzzer::fuzz_{nullptr};

void CameraListenerStubFuzzer::CheckPermission()
{
    if (!hasPermission) {
        uint64_t tokenId;
        const char *perms[0];
        perms[0] = "ohos.permission.CAMERA";
        NativeTokenInfoParams infoInstance = { .dcapsNum = 0, .permsNum = 1, .aclsNum = 0, .dcaps = NULL,
            .perms = perms, .acls = NULL, .processName = "camera_capture", .aplStr = "system_basic",
        };
        tokenId = GetAccessTokenId(&infoInstance);
        SetSelfTokenID(tokenId);
        OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
        hasPermission = true;
    }
}

void CameraListenerStubFuzzer::Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (fdp.remaining_bytes() < LIMITSIZE) {
        return;
    }
    CheckPermission();

    fuzz_ = std::make_shared<CameraListenerStub>();
    CHECK_ERROR_RETURN_LOG(!fuzz_, "Create fuzz_ Error");

    MessageParcel reply;
    uint32_t code = 0;
    MessageOption option;

    {
        MessageParcel dataMessageParcel;
        uint8_t dataSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_DATA_SIZE);
        std::vector<uint8_t> values = fdp.ConsumeBytes<uint8_t>(dataSize);
        dataMessageParcel.WriteRawData(values.data(), values.size());
        fuzz_->AddAuthInfo(dataMessageParcel, reply, code);
    }

    {
        MessageParcel dataMessageParcel;
        uint8_t dataSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_DATA_SIZE);
        std::vector<uint8_t> values = fdp.ConsumeBytes<uint8_t>(dataSize);
        dataMessageParcel.WriteRawData(values.data(), values.size());
        fuzz_->InvokerDataBusThread(dataMessageParcel, reply);
    }

    {
        MessageParcel dataMessageParcel;
        uint8_t dataSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_DATA_SIZE);
        std::vector<uint8_t> values = fdp.ConsumeBytes<uint8_t>(dataSize);
        dataMessageParcel.WriteRawData(values.data(), values.size());
        fuzz_->InvokerThread(code, dataMessageParcel, reply, option);
    }

    {
        MessageParcel dataMessageParcel;
        uint8_t dataSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_DATA_SIZE);
        std::vector<uint8_t> values = fdp.ConsumeBytes<uint8_t>(dataSize);
        dataMessageParcel.WriteRawData(values.data(), values.size());
        fuzz_->Marshalling(dataMessageParcel);
    }
 
    {
       MessageParcel dataMessageParcel;
        uint8_t dataSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_DATA_SIZE);
        std::vector<uint8_t> values = fdp.ConsumeBytes<uint8_t>(dataSize);
        dataMessageParcel.WriteRawData(values.data(), values.size());
        fuzz_->NoticeServiceDie(dataMessageParcel, reply, option);
    }
 
    {
        MessageParcel dataMessageParcel;
        uint8_t dataSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_DATA_SIZE);
        std::vector<uint8_t> values = fdp.ConsumeBytes<uint8_t>(dataSize);
        dataMessageParcel.WriteRawData(values.data(), values.size());
        fuzz_->SendRequest(code, dataMessageParcel, reply, option);
    }
 
    {
        MessageParcel dataMessageParcel;
        uint8_t dataSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_DATA_SIZE);
        std::vector<uint8_t> values = fdp.ConsumeBytes<uint8_t>(dataSize);
        dataMessageParcel.WriteRawData(values.data(), values.size());
        fuzz_->ProcessProto(code, dataMessageParcel, reply, option);
    }

    {
        MessageParcel dataMessageParcel;
        uint8_t dataSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_DATA_SIZE);
        std::vector<uint8_t> values = fdp.ConsumeBytes<uint8_t>(dataSize);
        dataMessageParcel.WriteRawData(values.data(), values.size());
        fuzz_->OnRemoteDump(code, dataMessageParcel, reply, option);
    }
 

    {
        MessageParcel dataMessageParcel;
        uint8_t dataSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_DATA_SIZE);
        std::vector<uint8_t> values = fdp.ConsumeBytes<uint8_t>(dataSize);
        dataMessageParcel.WriteRawData(values.data(), values.size());
        fuzz_->OnRemoteRequest(code, dataMessageParcel, reply, option);
    }
}

} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::CameraStandard::CameraListenerStubFuzzer::Test(data, size);
    return 0;
}