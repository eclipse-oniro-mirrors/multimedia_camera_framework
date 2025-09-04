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

#ifndef CAMERA_DEVICE_SERVICE_STUB_FUZZER_H
#define CAMERA_DEVICE_SERVICE_STUB_FUZZER_H

#include "camera_device_service_stub.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace CameraStandard {
class CameraDeviceServiceStubFuzz : public CameraDeviceServiceStub {
public:
    int32_t Open() override
    {
        return 0;
    }
    int32_t OpenSecureCamera(uint64_t& secureSeqId) override
    {
        return 0;
    }
    int32_t GetIsNeedDynamicMeta(int32_t& isNeedDynamicMeta) override
    {
        return 0;
    }
    int32_t Open(int32_t concurrentType) override
    {
        return 0;
    }
    int32_t Close() override
    {
        return 0;
    }
    int32_t closeDelayed() override
    {
        return 0;
    }
    int32_t Release() override
    {
        return 0;
    }
    int32_t UpdateSetting(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings) override
    {
        return 0;
    }
    int32_t SetUsedAsPosition(uint8_t value) override
    {
        return 0;
    }
    int32_t UpdateSettingOnce(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings)
    {
        return 0;
    }
    int32_t GetStatus(const std::shared_ptr<OHOS::Camera::CameraMetadata> &metaIn,
            std::shared_ptr<OHOS::Camera::CameraMetadata> &metaOut) override
    {
        return 0;
    }
    int32_t GetEnabledResults(std::vector<int32_t>& results) override
    {
        return 0;
    }
    int32_t EnableResult(const std::vector<int32_t>& results) override
    {
        return 0;
    }
    int32_t DisableResult(const std::vector<int32_t>& results) override
    {
        return 0;
    }
    int32_t SetDeviceRetryTime() override
    {
        return 0;
    }
    int32_t ReleaseStreams(std::vector<int32_t>& releaseStreamIds)
    {
        return 0;
    }
    int32_t SetCallback(const sptr<ICameraDeviceServiceCallback>& callback) override
    {
        return 0;
    }
    int32_t UnSetCallback() override
    {
        return 0;
    }
    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override
    {
        return 0;
    }
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override
    {
        return 0;
    }
};
class CameraDeviceServiceStubFuzzer {
public:
    static std::shared_ptr<CameraDeviceServiceStubFuzz> fuzz_;
    static void CameraDeviceServiceStubFuzzTest1();
    static void CameraDeviceServiceStubFuzzTest2();
    static void CameraDeviceServiceStubFuzzTest3();
    static void CameraDeviceServiceStubFuzzTest4();
    static void CameraDeviceServiceStubFuzzTest5();
    static void CameraDeviceServiceStubFuzzTest6(FuzzedDataProvider &fdp);
    static void CameraDeviceServiceStubFuzzTest7();
    static void CameraDeviceServiceStubFuzzTest8(FuzzedDataProvider &fdp);
    static void CameraDeviceServiceStubFuzzTest9();
    static void CameraDeviceServiceStubFuzzTest10(FuzzedDataProvider &fdp);
    static void CameraDeviceServiceStubFuzzTest11();
    static void CameraDeviceServiceStubFuzzTest12();
    static void CameraDeviceServiceStubFuzzTest13(FuzzedDataProvider &fdp);
    static void CameraDeviceServiceStubFuzzTest14();
    static void CameraDeviceServiceStubFuzzTest15();
};
}  // namespace CameraStandard
}  // namespace OHOS
#endif  // CAMERA_DEVICE_SERVICE_STUB_FUZZER_H