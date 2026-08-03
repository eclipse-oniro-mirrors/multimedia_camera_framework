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

#ifndef CAMERA_DEVICE_SERVICE_PROXY_FUZZER_H
#define CAMERA_DEVICE_SERVICE_PROXY_FUZZER_H

#include "camera_device_service_proxy.h"
#include <fuzzer/FuzzedDataProvider.h>
#include "message_parcel.h"
#include "ipc_object_stub.h"

namespace OHOS {
namespace CameraStandard {
class MockIRemoteObject : public IPCObjectStub {
public:
    MockIRemoteObject() : IPCObjectStub(u"mock_i_remote_object")
    {
        member_descriptor = u"mock_i_remote_object";
        shouldFail = false;
        errorCode = 0;
    }

    ~MockIRemoteObject() {}

    std::u16string member_descriptor;
    bool shouldFail;
    int32_t errorCode;

    int OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override
    {
        if (shouldFail) {
            return errorCode;
        }
        reply.WriteInt32(0);
        return 0;
    }
};

class CameraDeviceServiceProxyFuzz {
public:
    static std::shared_ptr<CameraDeviceServiceProxy> fuzz_;
    static void CameraDeviceServiceProxyTest(FuzzedDataProvider &fdp);
    static void CameraDeviceServiceProxyTestWithMock(FuzzedDataProvider &fdp);
    static void CameraDeviceServiceProxyTestUncoveredMethods(FuzzedDataProvider &fdp);
    static void CameraDeviceServiceProxyTestErrorBranches(FuzzedDataProvider &fdp);
};
}  // namespace CameraStandard
}  // namespace OHOS
#endif  // CAMERA_DEVICE_SERVICE_PROXY_FUZZER_H