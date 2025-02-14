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

#ifndef METADATA_OUTPUT_FUZZER_H
#define METADATA_OUTPUT_FUZZER_H

#include "metadata_output.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "deferred_processing_service.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
using namespace DeferredProcessing;
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

class AppMetadataCallback : public MetadataObjectCallback, public MetadataStateCallback {
public:
    void OnMetadataObjectsAvailable(std::vector<sptr<MetadataObject>> metaObjects) const
    {
        MEDIA_INFO_LOG("AppMetadataCallback::OnMetadataObjectsAvailable received");
    }
    void OnError(int32_t errorCode) const
    {
        MEDIA_INFO_LOG("AppMetadataCallback::OnError %{public}d", errorCode);
    }
};

class MetadataStateCallbackTest : public MetadataStateCallback {
public:
    MetadataStateCallbackTest() = default;
    virtual ~MetadataStateCallbackTest() = default;
    virtual void OnError(int32_t errorCode) const {};
};

class MetadataOutputFuzzer {
public:
static std::shared_ptr<MetadataOutput> fuzz_;
static void MetadataOutputFuzzTest();
static void MetadataOutputFuzzTest1();
};
} //CameraStandard
} //OHOS
#endif //METADATA_OUTPUT_FUZZER_H