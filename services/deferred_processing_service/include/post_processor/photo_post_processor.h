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

#include "basic_definitions.h"
#include "buffer_info.h"
#include "iimage_process_callbacks.h"
#include "iservstat_listener_hdi.h"
#include "photo_process_result.h"
#include "v1_2/iimage_process_session.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
using OHOS::HDI::Camera::V1_2::IImageProcessSession;
enum class IveResult : int32_t {
    ERROR = 0
};

enum class IveErrorCode : int32_t {
    ERROR = 0
};

enum class IveStateCode : int32_t {
    ERROR = 0
};

class PhotoPostProcessor : public std::enable_shared_from_this<PhotoPostProcessor> {
public:
    ~PhotoPostProcessor();

    void Initialize();
    int32_t GetConcurrency(ExecutionMode mode);
    bool GetPendingImages(std::vector<std::string>& pendingImages);
    void SetExecutionMode(ExecutionMode executionMode);
    void SetDefaultExecutionMode();
    void ProcessImage(const std::string& imageId);
    void RemoveImage(const std::string& imageId);
    void Interrupt();
    void Reset();
    void OnProcessDone(const std::string& imageId, const std::shared_ptr<BufferInfo>& bufferInfo);
    void OnProcessDoneExt(const std::string& imageId, const std::shared_ptr<BufferInfoExt>& bufferInfo);
    void OnError(const std::string& imageId,  DpsError errorCode);
    void OnStateChanged(HdiStatus HdiStatus);
    void OnSessionDied();
    void SetCallback(const std::weak_ptr<IImageProcessCallbacks>& callback_);

protected:
    PhotoPostProcessor(const int32_t userId);

private:
    class PhotoServiceListener;
    class PhotoProcessListener;
    class SessionDeathRecipient;

    void ConnectService();
    void DisconnectService();
    void StartTimer(const std::string& imageId);
    void StopTimer(const std::string& imageId);
    void OnTimerOut(const std::string& imageId);
    void OnServiceChange(const HDI::ServiceManager::V1_0::ServiceStatus& status);
    void RemoveNeedJbo(const sptr<IImageProcessSession>& session);

    inline sptr<IImageProcessSession> GetPhotoSession()
    {
        std::lock_guard<std::mutex> lock(sessionMutex_);
        return session_;
    }

    inline void SetPhotoSession(const sptr<IImageProcessSession>& session)
    {
        std::lock_guard<std::mutex> lock(sessionMutex_);
        session_ = session;
    }

    std::mutex sessionMutex_;
    std::mutex removeMutex_;
    const int32_t userId_;
    sptr<PhotoServiceListener> serviceListener_;
    sptr<PhotoProcessListener> processListener_;
    sptr<SessionDeathRecipient> sessionDeathRecipient_;
    sptr<IImageProcessSession> session_ {nullptr};
    std::unordered_map<std::string, uint32_t> runningWork_ {};
    std::unordered_map<std::string, uint32_t> imageId2CrashCount_ {};
    std::list<std::string> removeNeededList_ {};
    std::atomic<int32_t> consecutiveTimeoutCount_ {DEFAULT_COUNT};
    std::shared_ptr<PhotoProcessResult> processResult_ {nullptr};
    std::weak_ptr<IImageProcessCallbacks> callback_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_PHOTO_POST_PROCESSOR_H