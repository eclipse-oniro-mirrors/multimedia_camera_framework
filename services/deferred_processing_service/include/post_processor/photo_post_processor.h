/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include <unordered_set>

#include "basic_definitions.h"
#include "enable_shared_create.h"
#include "iservstat_listener_hdi.h"
#include "photo_process_result.h"
#include "v1_2/iimage_process_session.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
using OHOS::HDI::Camera::V1_2::IImageProcessSession;

class PhotoPostProcessor : public EnableSharedCreateInit<PhotoPostProcessor> {
public:
    ~PhotoPostProcessor();

    int32_t Initialize() override;
    int32_t GetConcurrency(ExecutionMode mode);
    bool GetPendingImages(std::vector<std::string>& pendingImages);
    void SetExecutionMode(ExecutionMode executionMode);
    void SetDefaultExecutionMode();
    void ProcessImage(const std::string& imageId);
    void RemoveImage(const std::string& imageId);
    void Interrupt();
    void Reset();
    void OnSessionDied();
    void SetProcessBundleNameResult(const std::string& bundleName);

protected:
    PhotoPostProcessor(const int32_t userId);

private:
    class PhotoServiceListener;
    class PhotoProcessListener;
    class SessionDeathRecipient;

    void ConnectService();
    void DisconnectService();
    void OnServiceChange(const HDI::ServiceManager::V1_0::ServiceStatus& status);
    void RemoveNeedJbo(const sptr<IImageProcessSession>& session);
    void NotifyHalStateChanged(HdiStatus hdiStatus);

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
    std::list<std::string> removeNeededList_ {};
    std::shared_ptr<PhotoProcessResult> processResult_ {nullptr};
    std::unordered_set<std::string> runningId_ {};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_PHOTO_POST_PROCESSOR_H