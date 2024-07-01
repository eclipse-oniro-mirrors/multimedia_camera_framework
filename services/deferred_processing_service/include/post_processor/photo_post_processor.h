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

#ifndef OHOS_CAMERA_DPS_PHOTO_POST_PROCESSOR_H
#define OHOS_CAMERA_DPS_PHOTO_POST_PROCESSOR_H

#include <vector>
#include <shared_mutex>
#include <iostream>
#include <mutex>
#include <list>
#include <atomic>

#include "ipc_file_descriptor.h"
#include "v1_2/icamera_host_callback.h"
#include "v1_2/iimage_process_service.h"
#include "v1_2/iimage_process_session.h"
#include "v1_2/iimage_process_callback.h"
#include "v1_2/types.h"
#include "iremote_object.h"
#include "deferred_photo_job.h"
#include "iimage_process_callbacks.h"
#include "task_manager.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
enum class IveResult : int32_t {
    ERROR = 0
};

enum class IveErrorCode : int32_t {
    ERROR = 0
};

enum class IveStateCode : int32_t {
    ERROR = 0
};

class PhotoPostProcessor {
public:
    PhotoPostProcessor(int userId, TaskManager* taskManager, IImageProcessCallbacks* callbacks);
    ~PhotoPostProcessor();
    void Initialize();
    int GetConcurrency(ExecutionMode mode);
    bool GetPendingImages(std::vector<std::string>& pendingImages);
    void SetExecutionMode(ExecutionMode executionMode);
    void SetDefaultExecutionMode();
    void ProcessImage(std::string imageId);
    void RemoveImage(std::string imageId);
    void Interrupt();
    void Reset();
    void OnSessionDied();
    int GetUserId();

    inline sptr<OHOS::HDI::Camera::V1_2::IImageProcessSession> GetImageProcessSession()
    {
        std::lock_guard<std::mutex> lock(imageProcessSessionMutex_);
        return innerImageProcessSession_;
    }

    inline void SetImageProcessSession(sptr<OHOS::HDI::Camera::V1_2::IImageProcessSession> ImageProcessSession)
    {
        std::lock_guard<std::mutex> lock(imageProcessSessionMutex_);
        innerImageProcessSession_ = ImageProcessSession;
    }

private:
    class PhotoProcessListener;
    class SessionDeathRecipient;

    void OnProcessDone(const std::string& imageId, std::shared_ptr<BufferInfo> bufferInfo);
    void OnError(const std::string& imageId,  DpsError errorCode);
    void OnStateChanged(HdiStatus HdiStatus);

    bool ConnectServiceIfNecessary();
    void DisconnectServiceIfNecessary();
    void ScheduleConnectService();
    std::mutex mutex_;
    std::mutex imageProcessSessionMutex_;
    std::mutex imageId2HandleMutex_;
    std::mutex imageId2CrashCountMutex_;
    std::mutex removeNeededListMutex_;
    int userId_;
    TaskManager* taskManager_;
    std::shared_ptr<IImageProcessCallbacks> imageProcessCallacks_;
    sptr<PhotoProcessListener> listener_;
    sptr<OHOS::HDI::Camera::V1_2::IImageProcessSession> innerImageProcessSession_;
    sptr<IRemoteObject::DeathRecipient> sessionDeathRecipient_;
    std::unordered_map<std::string, uint32_t> imageId2Handle_;
    std::unordered_map<std::string, uint32_t> imageId2CrashCount_;
    std::list<std::string> removeNeededList_;
    std::atomic<int> consecutiveTimeoutCount_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_PHOTO_POST_PROCESSOR_H