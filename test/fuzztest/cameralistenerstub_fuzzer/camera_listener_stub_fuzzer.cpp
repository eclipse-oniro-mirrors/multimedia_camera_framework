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
#include "hcamera_listener_proxy.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "accesstoken_kit.h"
#include <memory>

namespace {
    const int32_t LIMITSIZE = 2;
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

void CameraListenerStubFuzzer::Test(uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    CheckPermission();

    if (fuzz_ == nullptr) {
        fuzz_ = std::make_shared<CameraListenerStub>();
    }

    MessageParcel data;
    data.WriteRawData(rawData, size);
    MessageParcel reply;
    uint32_t code = 0;
    MessageOption option;

    data.RewindRead(0);
    fuzz_->AddAuthInfo(data, reply, code);

    data.RewindRead(0);
    fuzz_->InvokerDataBusThread(data, reply);

    data.RewindRead(0);
    fuzz_->InvokerThread(code, data, reply, option);

    data.RewindRead(0);
    fuzz_->Marshalling(data);

    data.RewindRead(0);
    fuzz_->NoticeServiceDie(data, reply, option);

    data.RewindRead(0);
    fuzz_->SendRequest(code, data, reply, option);

    data.RewindRead(0);
    fuzz_->ProcessProto(code, data, reply, option);

    data.RewindRead(0);
    fuzz_->OnRemoteDump(code, data, reply, option);

    data.RewindRead(0);
    fuzz_->OnRemoteRequest(code, data, reply, option);
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