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

#ifndef HSTREAM_DEPTH_PROXY_FUZZER_H
#define HSTREAM_DEPTH_PROXY_FUZZER_H

#include "hstream_depth_data_proxy.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "token_setproc.h"

namespace OHOS {
namespace CameraStandard {

class IRemoteObjectMock : public IRemoteObject {
public:
    inline int32_t GetObjectRefCount() override
    {
        return 0;
    }
    inline int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        return 0;
    }
    inline bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return true;
    }
    inline bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return true;
    }
    inline int Dump(int fd, const std::vector<std::u16string> &args) override
    {
        return 0;
    }
};

class IStreamDepthDataCallbackMock : public IStreamDepthDataCallback, public IRemoteObjectMock {
public:
    inline int32_t OnDepthDataError(int32_t errorCode) override
    {
        return 0;
    }
    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};

class HStreamDepthDataProxyFuzzer {
public:
static HStreamDepthDataProxy *fuzz_;
static void HStreamDepthDataProxyFuzzTest();
};
} //CameraStandard
} //OHOS
#endif //HSTREAM_DEPTH_PROXY_FUZZER_H