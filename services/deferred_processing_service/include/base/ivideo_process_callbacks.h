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

#ifndef OHOS_CAMERA_DPS_I_VIDEO_PROCESS_CALLBACKS_H
#define OHOS_CAMERA_DPS_I_VIDEO_PROCESS_CALLBACKS_H

#include "basic_definitions.h"
#include "ipc_file_descriptor.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class IVideoProcessCallbacks {
public:
    virtual ~IVideoProcessCallbacks() = default;
    virtual void OnProcessDone(const int32_t userId,
        const std::string& videoId, const sptr<IPCFileDescriptor>& ipcFd) = 0;
    virtual void OnError(const int32_t userId, const std::string& videoId, DpsError errorCode) = 0;
    virtual void OnStateChanged(const int32_t userId, DpsStatus statusCode) = 0;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_I_VIDEO_PROCESS_CALLBACKS_H
