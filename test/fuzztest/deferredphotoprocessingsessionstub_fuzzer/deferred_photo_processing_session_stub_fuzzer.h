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

#ifndef DEFERREDPROCESSING_SESSION_STUB_FUZZER_H
#define DEFERREDPROCESSING_SESSION_STUB_FUZZER_H

#include <iostream>
#include "deferred_video_processing_session.h"
#include "ideferred_video_processing_session_callback.h"
#include "deferred_photo_processing_session_stub.h"
#include "dp_power_manager.h"

namespace OHOS {
namespace CameraStandard {
using namespace DeferredProcessing;

class DeferredPhotoProcessingSessionStubFuzz : public DeferredPhotoProcessingSessionStub {
public:
    int32_t BeginSynchronize() override
    {
        return 0;
    }
    int32_t EndSynchronize() override
    {
        return 0;
    }
    int32_t AddImage(
        const std::string& imageId,
        DpsMetadata& metadata,
        const bool discardable = false) override
    {
        return 0;
    }
    int32_t RemoveImage(const std::string& imageId, const bool restorable = false) override
    {
        return 0;
    }
    int32_t RestoreImage(const std::string& imageId) override
    {
        return 0;
    }
    int32_t ProcessImage(const std::string& appName, const std::string& imageId) override
    {
        return 0;
    }
    int32_t CancelProcessImage(const std::string& imageId) override
    {
        return 0;
    }
};

class DeferredPhotoProcessingSessionStubFuzzer {
public:
static DeferredPhotoProcessingSessionStubFuzz *fuzz_;
static DPSProwerManager *manager_;
static void OnRemoteRequest(int32_t code);
static void FuzzTest();
};
} //CameraStandard
} //OHOS
#endif //DEFERREDPROCESSING_SESSION_STUB_FUZZER_H