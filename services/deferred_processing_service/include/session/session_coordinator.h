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

#ifndef OHOS_CAMERA_DPS_SESSION_COORDINATOR_H
#define OHOS_CAMERA_DPS_SESSION_COORDINATOR_H
#include <vector>
#include <shared_mutex>
#include <iostream>
#include <refbase.h>
#include <deque>
#include <map>
#include "base/iimage_process_callbacks.h"
#include "ipc_file_descriptor.h"
#include "ideferred_photo_processing_session_callback.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class SessionCoordinator : public RefBase {
public:
    SessionCoordinator();
    ~SessionCoordinator();
    void Initialize();
    void Start();
    void Stop();

    void OnProcessDone(int userId, const std::string& imageId, sptr<IPCFileDescriptor> ipcFd, long dataSize);
    void OnError(int userId, const std::string& imageId, DpsError errorCode);
    void OnStateChanged(int userId, DpsStatus statusCode);
    std::shared_ptr<IImageProcessCallbacks> GetImageProcCallbacks();
    void NotifySessionCreated(int userId, sptr<IDeferredPhotoProcessingSessionCallback> callback);
    void NotifyCallbackDestroyed(int userId);

private:
    class ImageProcCallbacks;

    enum struct CallbackType {
        ON_PROCESS_DONE,
        ON_ERROR,
        ON_STATE_CHANGED
    };

    struct ImageResult {
        CallbackType callbackType;
        int userId;
        std::string imageId;
        sptr<IPCFileDescriptor> ipcFd;
        long dataSize;
        DpsError errorCode;
        DpsStatus statusCode;
    };

    void ProcessPendingResults(sptr<IDeferredPhotoProcessingSessionCallback> callback);
    std::shared_ptr<IImageProcessCallbacks> imageProcCallbacks_;
    std::map<int, wptr<IDeferredPhotoProcessingSessionCallback>> remoteImageCallbacksMap_;
    std::deque<ImageResult> pendingImageResults_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_SESSION_COORDINATOR_H