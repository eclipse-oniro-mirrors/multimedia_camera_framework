/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
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

#ifndef OHOS_CAMERA_DPS_MPEG__MANAGER_FACTORY_H
#define OHOS_CAMERA_DPS_MPEG__MANAGER_FACTORY_H

#include "mpeg_manager.h"
#include "singleton.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class MpegManagerFactory : public Singleton<MpegManagerFactory> {
    DECLARE_SINGLETON(MpegManagerFactory)

public:
    std::shared_ptr<MpegManager> Acquire(const std::string& requestId, const sptr<IPCFileDescriptor>& inputFd);
    void Release(std::shared_ptr<MpegManager>& mpegManager);

private:
    std::mutex mutex_;
    std::string requestId_;
    uint32_t refCount_ {0};
    std::shared_ptr<MpegManager> mpegManager_ {nullptr};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_MPEG__MANAGER_FACTORY_H