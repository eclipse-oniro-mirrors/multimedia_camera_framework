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

#ifndef OHOS_CAMERASTANDARD_DEFERREDPROCESSING_IDEFERREDVIDEOPROCESSINGSESSIONCALLBACK_H
#define OHOS_CAMERASTANDARD_DEFERREDPROCESSING_IDEFERREDVIDEOPROCESSINGSESSIONCALLBACK_H

#include <string_ex.h>
#include <cstdint>
#include <iremote_broker.h>
#include "ipc_file_descriptor.h"

using OHOS::IPCFileDescriptor;

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class IDeferredVideoProcessingSessionCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.CameraStandard.DeferredProcessing.IDeferredVideoProcessingSessionCallback");

    virtual ErrCode OnProcessVideoDone(
        const std::string& videoId,
        const sptr<IPCFileDescriptor>& fd) = 0;

    virtual ErrCode OnError(
        const std::string& videoId,
        int32_t errorCode) = 0;

    virtual ErrCode OnStateChanged(
        int32_t status) = 0;
protected:
    const int VECTOR_MAX_SIZE = 102400;
    const int LIST_MAX_SIZE = 102400;
    const int MAP_MAX_SIZE = 102400;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERASTANDARD_DEFERREDPROCESSING_IDEFERREDVIDEOPROCESSINGSESSIONCALLBACK_H

