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

#ifndef OHOS_DEFERRED_PHOTO_PROCESSING_SESSION_PROXY_H
#define OHOS_DEFERRED_PHOTO_PROCESSING_SESSION_PROXY_H

#include "iremote_proxy.h"
#include "ideferred_photo_processing_session.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class DeferredPhotoProcessingSessionProxy : public IRemoteProxy<IDeferredPhotoProcessingSession> {
public:
    explicit DeferredPhotoProcessingSessionProxy(const sptr<IRemoteObject> &impl);
    virtual ~DeferredPhotoProcessingSessionProxy() = default;
    int32_t BeginSynchronize() override;
    int32_t EndSynchronize() override;
    int32_t AddImage(const std::string imageId, DpsMetadata& metadata, const bool discardable) override;
    int32_t RemoveImage(const std::string imageId, const bool restorable) override;
    int32_t RestoreImage(const std::string imageId) override;
    int32_t ProcessImage(const std::string appName, const std::string imageId) override;
    int32_t CancelProcessImage(const std::string imageId) override;

private:
    static inline BrokerDelegator<DeferredPhotoProcessingSessionProxy> delegator_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_DEFERRED_PHOTO_PROCESSING_SESSION_PROXY_H
