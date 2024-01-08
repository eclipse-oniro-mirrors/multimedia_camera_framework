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

#include "thread_utils.h"
#include <sys/resource.h>
#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
extern "C" pid_t __attribute__((weak)) pthread_gettid_np(pthread_t threadId);

void SetThreadName(pthread_t tid, const std::string& name)
{
    constexpr int threadNameMaxSize = 15;
    auto threadName = name.size() > threadNameMaxSize ? name.substr(0, threadNameMaxSize).c_str() : name;
    if (name.size() > threadNameMaxSize) {
        DP_DEBUG_LOG("task name %s exceed max size: %d", name.c_str(), threadNameMaxSize);
    }
    int ret = pthread_setname_np(tid, threadName.c_str());
    DP_DEBUG_LOG("threadId: %ld, threadName: %s, pthread_setname_np ret = %d.",
        static_cast<long>(pthread_gettid_np(tid)), threadName.c_str(), ret);
}

void SetThreadPriority(pthread_t handle, int priority)
{
    pid_t tid = pthread_gettid_np(handle);
    int currPri = getpriority(PRIO_PROCESS, tid);
    if (currPri == priority) {
        return;
    }
    int ret = setpriority(PRIO_PROCESS, tid, priority);
    if (ret == 0) {
        DP_DEBUG_LOG("succeed for tid (%ld) with priority (%d).", static_cast<long>(tid), priority);
    } else {
        DP_DEBUG_LOG("failed for tid (%ld) with priority (%d), ret = %d.", static_cast<long>(tid), priority, ret);
    }
}
} //namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
