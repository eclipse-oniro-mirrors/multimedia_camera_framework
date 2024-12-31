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

#ifndef CAMERADEVICE_FUZZER_H
#define CAMERADEVICE_FUZZER_H
#define FUZZ_PROJECT_NAME "cameradevice_fuzzer"
#include <iostream>
#include "hcamera_host_manager.h"
#include "hcamera_device.h"
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

class IStreamOperatorCallbackMock : public IStreamOperatorCallback {
public:
    inline int32_t OnCaptureReady(int32_t captureId,
        const std::vector<int32_t>& streamIds, uint64_t timestamp) override
    {
        return 0;
    }

    inline int32_t OnFrameShutterEnd(int32_t captureId,
        const std::vector<int32_t>& streamIds, uint64_t timestamp) override
    {
        return 0;
    }

    inline int32_t OnCaptureEndedExt(int32_t captureId,
         const std::vector<OHOS::HDI::Camera::V1_3::CaptureEndedInfoExt>& infos) override
    {
        return 0;
    }
    inline int32_t OnCaptureStarted(int32_t captureId, const std::vector<int32_t>& streamIds) override
    {
        return 0;
    }

    inline int32_t OnCaptureEnded(int32_t captureId,
         const std::vector<OHOS::HDI::Camera::V1_0::CaptureEndedInfo>& infos) override
    {
        return 0;
    }

    inline int32_t OnCaptureError(int32_t captureId,
         const std::vector<OHOS::HDI::Camera::V1_0::CaptureErrorInfo>& infos) override
    {
        return 0;
    }

    inline int32_t OnFrameShutter(int32_t captureId,
        const std::vector<int32_t>& streamIds, uint64_t timestamp) override
    {
        return 0;
    }
    inline int32_t OnCaptureStarted_V1_2(int32_t captureId,
         const std::vector<OHOS::HDI::Camera::V1_2::CaptureStartedInfo>& infos) override
    {
        return 0;
    }
    inline int32_t OnResult(int32_t streamId, const std::vector<uint8_t>& result) override
    {
        return 0;
    }
};

void CameraDeviceFuzzTest(uint8_t *rawData, size_t size);
void CameraDeviceFuzzTestGetPermission();
void CameraDeviceFuzzTest2(uint8_t *rawData, size_t size);
void Test3(uint8_t *rawData, size_t size);
void TestXCollie(uint8_t *rawData, size_t size);
} //CameraStandard
} //OHOS
#endif //CAMERADEVICE_FUZZER_H

