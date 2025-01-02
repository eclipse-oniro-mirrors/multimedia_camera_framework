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

#include "hcamera_service.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "deferred_processing_service.h"

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::CameraStandard::DeferredProcessing;

class IDeferredPhotoProcessingSessionCallbackFuzz : public IDeferredPhotoProcessingSessionCallback {
public:
    explicit IDeferredPhotoProcessingSessionCallbackFuzz() = default;
    virtual ~IDeferredPhotoProcessingSessionCallbackFuzz() = default;
    inline int32_t OnProcessImageDone(const std::string &imageId,
        sptr<IPCFileDescriptor> ipcFd, const long bytes, bool isCloudImageEnhanceSupported) override
    {
        return 0;
    }
    inline int32_t OnProcessImageDone(const std::string &imageId, std::shared_ptr<Media::Picture> picture,
        bool isCloudImageEnhanceSupported) override
    {
        return 0;
    }
    inline int32_t OnDeliveryLowQualityImage(const std::string &imageId,
        std::shared_ptr<Media::Picture> picture) override
    {
        return 0;
    }
    inline int32_t OnError(const std::string &imageId, const ErrorCode errorCode) override
    {
        return 0;
    }
    inline int32_t OnStateChanged(const StatusCode status) override
    {
        return 0;
    }
    sptr<IRemoteObject> AsObject() override
    {
        auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgr == nullptr) {
            return nullptr;
        }
        sptr<IRemoteObject> object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
        return object;
    }
};

class HCameraServiceFuzzer {
public:
static bool hasPermission;
static HCameraService *fuzz_;
static HCameraService *manager_;
static void HCameraServiceFuzzTest1();
static void HCameraServiceFuzzTest2();
};
} //CameraStandard
} //OHOS
#endif //CAMERA_INPUT_FUZZER_H