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

#ifndef OHOS_CAMERASTANDARD_DEFERREDPROCESSING_DEFERREDVIDEOPROCESSINGSESSIONCALLBACKPROXY_H
#define OHOS_CAMERASTANDARD_DEFERREDPROCESSING_DEFERREDVIDEOPROCESSINGSESSIONCALLBACKPROXY_H

#include "ideferred_video_processing_session_callback.h"
#include <iremote_proxy.h>

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class DeferredVideoProcessingSessionCallbackProxy : public IRemoteProxy<IDeferredVideoProcessingSessionCallback> {
public:
    explicit DeferredVideoProcessingSessionCallbackProxy(
        const sptr<IRemoteObject>& remote)
        : IRemoteProxy<IDeferredVideoProcessingSessionCallback>(remote)
    {
    }

    virtual ~DeferredVideoProcessingSessionCallbackProxy()
    {
    }

    ErrCode OnProcessVideoDone(
        const std::string& videoId,
        const sptr<IPCFileDescriptor>& fd) override;

    ErrCode OnError(
        const std::string& videoId,
        int32_t errorCode) override;

    ErrCode OnStateChanged(
        int32_t status) override;

private:
    static constexpr int32_t COMMAND_ON_PROCESS_VIDEO_DONE = MIN_TRANSACTION_ID + 0;
    static constexpr int32_t COMMAND_ON_ERROR = MIN_TRANSACTION_ID + 1;
    static constexpr int32_t COMMAND_ON_STATE_CHANGED = MIN_TRANSACTION_ID + 2;

    static inline BrokerDelegator<DeferredVideoProcessingSessionCallbackProxy> delegator_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERASTANDARD_DEFERREDPROCESSING_DEFERREDVIDEOPROCESSINGSESSIONCALLBACKPROXY_H

