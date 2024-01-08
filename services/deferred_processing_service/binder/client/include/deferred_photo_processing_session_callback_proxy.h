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

#ifndef OHOS_DEFERRED_PHOTO_PROCESSING_SESSION_CALLBACK_PROXY_H
#define OHOS_DEFERRED_PHOTO_PROCESSING_SESSION_CALLBACK_PROXY_H

#include "iremote_proxy.h"
#include "ideferred_photo_processing_session_callback.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class DeferredPhotoProcessingSessionCallbackProxy : public IRemoteProxy<IDeferredPhotoProcessingSessionCallback> {
public:
    explicit DeferredPhotoProcessingSessionCallbackProxy(const sptr<IRemoteObject> &impl);
    virtual ~DeferredPhotoProcessingSessionCallbackProxy() = default;
    int32_t OnProcessImageDone(const std::string &imageId, sptr<IPCFileDescriptor> ipcFd, long bytes) override;
    int32_t OnError(const std::string &imageId, ErrorCode errorCode) override;
    int32_t OnStateChanged(StatusCode status) override;

private:
    static inline BrokerDelegator<DeferredPhotoProcessingSessionCallbackProxy> delegator_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_DEFERRED_PHOTO_PROCESSING_SESSION_CALLBACK_PROXY_H