/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef STREAM_METADATA_CALLBACK_PROXY_FUZZER_H
#define STREAM_METADATA_CALLBACK_PROXY_FUZZER_H

#include "stream_metadata_callback_proxy.h"
#include <fuzzer/FuzzedDataProvider.h>
#include "iremote_object.h"
#include "ipc_object_stub.h"

namespace OHOS {
namespace CameraStandard {
class MockIRemoteObject : public IPCObjectStub {
public:
    MockIRemoteObject() : IPCObjectStub(u"mock_i_remote_object") {
        member_descriptor = u"mock_i_remote_object";
        shouldFail = false;
        errorCode = 0;
    }

    bool shouldFail;
    int32_t errorCode;
    std::u16string member_descriptor;

    int OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override {
        if (shouldFail) {
            return errorCode;
        }
        reply.WriteInt32(0);
        return 0;
    }
};

class StreamMetadataCallbackProxyFuzz {
public:
    static std::shared_ptr<StreamMetadataCallbackProxy> fuzz_;
    static void StreamMetadataCallbackProxyTestWithMock(FuzzedDataProvider &fdp);
    static void StreamMetadataCallbackProxyTestErrorBranches(FuzzedDataProvider &fdp);
};
}  // namespace CameraStandard
}  // namespace OHOS
#endif  // STREAM_METADATA_CALLBACK_PROXY_FUZZER_H
