/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_DEFERRED_PROCESSING_SERVICE_THREAD_UTILS_H
#define OHOS_DEFERRED_PROCESSING_SERVICE_THREAD_UTILS_H

#include <pthread.h>
#include <string>

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
enum {
    PRIORITY_NORMAL = 0,
    PRIORITY_BACKGROUND = 10
};

void SetThreadName(pthread_t tid, const std::string& name);
void SetThreadPriority(pthread_t tid, int priority);
} //namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_DEFERRED_PROCESSING_SERVICE_THREAD_UTILS_H
