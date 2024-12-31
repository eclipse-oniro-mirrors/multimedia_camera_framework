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

#ifndef DEFERREDPROCESSING_FUZZER_H
#define DEFERREDPROCESSING_FUZZER_H
#include <iostream>
#include "deferred_video_processing_session.h"
#include "ideferred_video_processing_session_callback.h"
#include "deferred_video_processing_session_stub.h"

namespace OHOS {
namespace CameraStandard {
using namespace DeferredProcessing;

class DeferredVideoProcessingSessionStubFuzz : public DeferredVideoProcessingSessionStub {
public:
    int32_t BeginSynchronize() override
    {
        return 0;
    }
    int32_t EndSynchronize() override
    {
        return 0;
    }
    int32_t AddVideo(
        const std::string& videoId,
        const sptr<IPCFileDescriptor>& srcFd,
        const sptr<IPCFileDescriptor>& dstFd) override
    {
        return 0;
    }
    int32_t RemoveVideo(
        const std::string& videoId,
        bool restorable) override
    {
        return 0;
    }
    int32_t RestoreVideo(
        const std::string& videoId) override
    {
        return 0;
    }
};

class DeferredVideoProcessingSessionStubFuzzer {
public:
static DeferredVideoProcessingSessionStubFuzz *fuzz_;
static void OnRemoteRequest(int32_t code);
};
} //CameraStandard
} //OHOS
#endif //DEFERREDPROCESSING_FUZZER_H