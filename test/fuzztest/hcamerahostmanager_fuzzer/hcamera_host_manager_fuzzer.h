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

#ifndef HCAMERA_HOST_MANAGER_FUZZER_H
#define HCAMERA_HOST_MANAGER_FUZZER_H

#include "hcamera_host_manager.h"

namespace OHOS {
namespace CameraStandard {

class StatusCallbackDemo : public HCameraHostManager::StatusCallback {
    public:
        virtual ~StatusCallbackDemo() = default;
        virtual void OnCameraStatus(const std::string& cameraId, CameraStatus status,
            CallbackInvoker invoker = CallbackInvoker::CAMERA_HOST) {}
        virtual void OnFlashlightStatus(const std::string& cameraId, FlashStatus status) {}
        virtual void OnTorchStatus(TorchStatus status) {}
};

class HCameraHostManagerFuzzer {
public:
static std::shared_ptr<HCameraHostManager> fuzz_;
static std::shared_ptr<HCameraHostManager::CameraHostInfo> hostInfo;
static void HCameraHostManagerFuzzTest1();
};

} //CameraStandard
} //OHOS
#endif //HCAMERA_HOST_MANAGER_FUZZER_H