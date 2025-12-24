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
#ifndef FUZZ_UTIL_H
#define FUZZ_UTIL_H
#include <fuzzer/FuzzedDataProvider.h>
#include "message_parcel.h"
#include "ipc_object_stub.h"

namespace OHOS::CameraStandard {
template<typename T>
T PickEnumInRange(FuzzedDataProvider& fdp, T tail)
{
    return PickEnumInRange(fdp, static_cast<T>(0), tail);
}

template<typename T>
T PickEnumInRange(FuzzedDataProvider& fdp, T head, T tail)
{
    int32_t size = static_cast<int32_t>(tail) - static_cast<int32_t>(head) + 1;
    return static_cast<T>(fdp.ConsumeIntegral<uint8_t>() % size + static_cast<int32_t>(head));
}

template<typename T, typename S = uint8_t>
std::vector<T> ConsumeRandomVector(FuzzedDataProvider& fdp)
{
    S size = fdp.ConsumeIntegral<S>();
    std::vector<T> rdnVec;
    for (S i = 0; i < size; ++i) {
        if constexpr (std::is_same_v<T, uint8_t> || std::is_same_v<T, int8_t> || std::is_same_v<T, int32_t> ||
            std::is_same_v<T, uint32_t> || std::is_same_v<T, int64_t> || std::is_same_v<T, uint64_t>) {
            rdnVec.emplace_back(fdp.ConsumeIntegral<T>());
        } else if constexpr (std::is_same_v<T, float> || std::is_same_v<T, double>) {
            rdnVec.emplace_back(fdp.ConsumeFloatingPoint<T>());
        }
    }
    return rdnVec;
}

class MockIRemoteObject : public IPCObjectStub {
public:
    MockIRemoteObject() : IPCObjectStub(u"mock_i_remote_object")
    {
        member_descriptor = u"mock_i_remote_object";
    }

    ~MockIRemoteObject() {}

    std::u16string member_descriptor;

    int OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override
    {
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
};

} // namespace OHOS::CameraStandard
#endif