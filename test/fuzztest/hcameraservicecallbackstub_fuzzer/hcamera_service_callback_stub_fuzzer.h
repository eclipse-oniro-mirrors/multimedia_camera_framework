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

#ifndef HCAMERA_SERVICE_CALLBACK_STUB_FUZZER_H
#define HCAMERA_SERVICE_CALLBACK_STUB_FUZZER_H

#include "hcamera_service_callback_stub.h"
#include <memory>

namespace OHOS {
namespace CameraStandard {

class HCameraServiceCallbackStubFuzz : public HCameraServiceCallbackStub {
public:
    int32_t OnCameraStatusChanged(const std::string& cameraId, const CameraStatus status,
        const std::string& bundleName = "") override
    {
        return 0;
    }
    int32_t OnFlashlightStatusChanged(const std::string& cameraId, const FlashStatus status) override
    {
        return 0;
    }
};

class HCameraMuteServiceCallbackStubFuzz : public HCameraMuteServiceCallbackStub {
public:
    int32_t OnCameraMute(bool muteMode) override
    {
        return 0;
    }
};

class HTorchServiceCallbackStubFuzz : public HTorchServiceCallbackStub {
public:
    int32_t OnTorchStatusChange(const TorchStatus status) override
    {
        return 0;
    }
};

class HFoldServiceCallbackStubFuzz : public HFoldServiceCallbackStub {
public:
    int32_t OnFoldStatusChanged(const FoldStatus status) override
    {
        return 0;
    }
};

class HCameraServiceCallbackStubFuzzer {
public:
static void HCameraServiceCallbackStubFuzzTest(int32_t code);
static void HCameraMuteServiceCallbackStuFuzzTest(int32_t code);
static void HTorchServiceCallbackStubFuzzTest(int32_t code);
static void HFoldServiceCallbackStubFuzzTest(int32_t code);
};
} //CameraStandard
} //OHOS
#endif //HCAMERA_SERVICE_CALLBACK_STUB_FUZZER_H