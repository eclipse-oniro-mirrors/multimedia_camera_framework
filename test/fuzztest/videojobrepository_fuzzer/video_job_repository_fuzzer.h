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

#ifndef VIDEO_JOB_REPOSITORY_FUZZER_H
#define VIDEO_JOB_REPOSITORY_FUZZER_H

#include "video_job_repository.h"

namespace OHOS {
namespace CameraStandard {

class VideoJobRepositoryFuzzer {
public:
static std::shared_ptr<DeferredProcessing::VideoJobRepository> fuzz_;
static void VideoJobRepositoryFuzzTest();
};
} //CameraStandard
} //OHOS
#endif //VIDEO_JOB_REPOSITORY_FUZZER_H