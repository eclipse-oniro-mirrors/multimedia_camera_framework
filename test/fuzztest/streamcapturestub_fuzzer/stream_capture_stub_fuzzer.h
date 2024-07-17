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

#ifndef STREAM_CAPTURE_STUB_FUZZER_H
#define STREAM_CAPTURE_STUB_FUZZER_H

#include "hstream_capture_stub.h"

namespace OHOS {
namespace CameraStandard {
class IRemoteObjectMock : public IRemoteObject {
public:
    int32_t GetObjectRefCount()
    {
        return 0;
    }
    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
    {
        return 0;
    }
    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient)
    {
        return true;
    }
    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient)
    {
        return true;
    }
    int Dump(int fd, const std::vector<std::u16string> &args)
    {
        return 0;
    }
};

class IStreamCaptureCallbackMock : public IStreamCaptureCallback, public IRemoteObjectMock {
public:
    int32_t OnCaptureStarted(int32_t captureId)
    {
        return 0;
    }
    int32_t OnCaptureStarted(int32_t captureId, uint32_t exposureTime)
    {
        return 0;
    }
    int32_t OnCaptureEnded(int32_t captureId, int32_t frameCount)
    {
        return 0;
    }
    int32_t OnCaptureError(int32_t captureId, int32_t errorType)
    {
        return 0;
    }
    int32_t OnFrameShutter(int32_t captureId, uint64_t timestamp)
    {
        return 0;
    }
    int32_t OnFrameShutterEnd(int32_t captureId, uint64_t timestamp)
    {
        return 0;
    }
    int32_t OnCaptureReady(int32_t captureId, uint64_t timestamp)
    {
        return 0;
    }
    sptr<IRemoteObject> AsObject()
    {
        return this;
    }
};
namespace StreamCaptureStubFuzzer {

void Test(uint8_t *rawData, size_t size);
void Test_OnRemoteRequest(uint8_t *rawData, size_t size);
void Test_HandleCapture(uint8_t *rawData, size_t size);
void Test_HandleSetThumbnail(uint8_t *rawData, size_t size);
void Test_HandleSetRawPhotoInfo(uint8_t *rawData, size_t size);
void Test_HandleEnableDeferredType(uint8_t *rawData, size_t size);
void Test_HandleSetCallback(uint8_t *rawData, size_t size);

void CheckPermission();
std::shared_ptr<OHOS::Camera::CameraMetadata> MakeMetadata(uint8_t *rawData, size_t size);

}
}
}
#endif