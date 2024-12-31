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

#ifndef DEFERREDPROCESSING_FUZZER_H
#define DEFERREDPROCESSING_FUZZER_H

#include "deferred_video_controller.h"
#include "video_job_repository.h"
#include "video_strategy_center.h"
#include "video_post_processor.h"

namespace OHOS {
namespace CameraStandard {
using namespace DeferredProcessing;
class IVideoProcessCallbacksFuzz : public IVideoProcessCallbacks {
public:
    void OnProcessDone(const int32_t userId,
        const std::string& videoId, const sptr<IPCFileDescriptor>& ipcFd) override {}
    void OnError(const int32_t userId, const std::string& videoId, DpsError errorCode) override {}
    void OnStateChanged(const int32_t userId, DpsStatus statusCode) override {}
};

class DeferredVideoControllerFuzzer {
public:
static DeferredProcessing::DeferredVideoController *fuzz_;
static DeferredProcessing::VideoStrategyCenter *center_;
static void DeferredVideoControllerFuzzTest();
};
} //CameraStandard
} //OHOS
#endif //DEFERREDPROCESSING_FUZZER_H