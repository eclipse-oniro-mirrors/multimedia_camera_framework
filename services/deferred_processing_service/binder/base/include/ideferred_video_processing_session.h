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

#ifndef OHOS_CAMERASTANDARD_DEFERREDPROCESSING_IDEFERREDVIDEOPROCESSINGSESSION_H
#define OHOS_CAMERASTANDARD_DEFERREDPROCESSING_IDEFERREDVIDEOPROCESSINGSESSION_H

#include <string_ex.h>
#include <cstdint>
#include <iremote_broker.h>
#include "ipc_file_descriptor.h"

using OHOS::IPCFileDescriptor;

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class IDeferredVideoProcessingSession : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.CameraStandard.DeferredProcessing.IDeferredVideoProcessingSession");

    virtual int32_t BeginSynchronize() = 0;

    virtual int32_t EndSynchronize() = 0;

    virtual int32_t AddVideo(
        const std::string& videoId,
        const sptr<IPCFileDescriptor>& srcFd,
        const sptr<IPCFileDescriptor>& dstFd) = 0;

    virtual int32_t RemoveVideo(
        const std::string& videoId,
        bool restorable) = 0;

    virtual int32_t RestoreVideo(
        const std::string& videoId) = 0;
protected:
    const int VECTOR_MAX_SIZE = 102400;
    const int LIST_MAX_SIZE = 102400;
    const int MAP_MAX_SIZE = 102400;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERASTANDARD_DEFERREDPROCESSING_IDEFERREDVIDEOPROCESSINGSESSION_H

