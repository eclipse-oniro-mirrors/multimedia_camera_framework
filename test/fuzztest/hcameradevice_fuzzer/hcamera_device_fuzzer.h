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

#ifndef CAMERA_INPUT_FUZZER_H
#define CAMERA_INPUT_FUZZER_H

#include "hcamera_device_stub.h"
#include "hcamera_device.h"

namespace OHOS {
namespace CameraStandard {

class FoldScreenListener;

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

class ICameraDeviceServiceCallbackMock : public ICameraDeviceServiceCallback, public IRemoteObjectMock {
public:
    inline int32_t OnError(const int32_t errorType, const int32_t errorMsg) override
    {
        return 0;
    }
    inline int32_t OnResult(const uint64_t timestamp,
        const std::shared_ptr<OHOS::Camera::CameraMetadata> &result) override
    {
        return 0;
    }
    sptr<IRemoteObject> AsObject() override
    {
        return this;
    }
};

class HCameraDeviceFuzzer {
public:
static bool hasPermission;
static HCameraDevice *fuzz_;
static void HCameraDeviceFuzzTest1();
static void HCameraDeviceFuzzTest2();
};
} //CameraStandard
} //OHOS
#endif //CAMERA_INPUT_FUZZER_H