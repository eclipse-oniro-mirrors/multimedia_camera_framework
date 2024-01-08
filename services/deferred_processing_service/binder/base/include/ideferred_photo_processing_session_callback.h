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

#ifndef OHOS_IDEFERRED_PHOTO_PROCESSING_SESSION_CALLBACK_H
#define OHOS_IDEFERRED_PHOTO_PROCESSING_SESSION_CALLBACK_H

#include "iremote_broker.h"
#include "ipc_file_descriptor.h"
#include "basic_definitions.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
enum ErrorCode {
    // session specific error code
    ERROR_SESSION_SYNC_NEEDED = 0,
    ERROR_SESSION_NOT_READY_TEMPORARILY = 1,

    // process error code
    ERROR_IMAGE_PROC_INVALID_PHOTO_ID = 2,
    ERROR_IMAGE_PROC_FAILED = 3,
    ERROR_IMAGE_PROC_TIMEOUT = 4,
    ERROR_IMAGE_PROC_ABNORMAL = 5,
    ERROR_IMAGE_PROC_INTERRUPTED = 6,
};

enum StatusCode {
    SESSION_STATE_IDLE = 0,
    SESSION_STATE_RUNNALBE,
    SESSION_STATE_RUNNING,
    SESSION_STATE_SUSPENDED,
};

class IDeferredPhotoProcessingSessionCallback : public IRemoteBroker {
public:
    virtual int32_t OnProcessImageDone(const std::string &imageId, sptr<IPCFileDescriptor> ipcFd, const long bytes) = 0;
    virtual int32_t OnError(const std::string &imageId, const ErrorCode errorCode) = 0;
    virtual int32_t OnStateChanged(const StatusCode status) = 0;
    DECLARE_INTERFACE_DESCRIPTOR(u"IDeferredPhotoProcessingSessionCallback");
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_IDEFERRED_PHOTO_PROCESSING_SESSION_CALLBACK_H