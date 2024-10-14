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

#ifndef OHOS_CAMERA_DPS_VIDEO_SESSION_INFO_H
#define OHOS_CAMERA_DPS_VIDEO_SESSION_INFO_H

#include "ideferred_video_processing_session_callback.h"
#include "ideferred_video_processing_session.h"
#include "ivideo_process_callbacks.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class VideoSessionInfo : public RefBase {
public:
    VideoSessionInfo(const int32_t userId, const sptr<IDeferredVideoProcessingSessionCallback>& callback);
    virtual ~VideoSessionInfo();

    int32_t Initialize();
    sptr<IDeferredVideoProcessingSession> GetDeferredVideoProcessingSession();
    sptr<IDeferredVideoProcessingSessionCallback> GetRemoteCallback();
    int32_t GetUserId() const;
    void OnCallbackDied();
    void SetCallback(const sptr<IDeferredVideoProcessingSessionCallback>& callback);

private:
    class CallbackDeathRecipient;

    const int32_t userId_;
    sptr<IDeferredVideoProcessingSession> session_ {nullptr};
    sptr<IDeferredVideoProcessingSessionCallback> callback_;
    sptr<CallbackDeathRecipient> deathRecipient_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_VIDEO_SESSION_INFO_H