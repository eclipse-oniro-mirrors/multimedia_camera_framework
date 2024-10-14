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

#ifndef OHOS_CAMERASTANDARD_DEFERREDPROCESSING_DEFERREDVIDEOPROCESSINGSESSIONCALLBACKSTUB_H
#define OHOS_CAMERASTANDARD_DEFERREDPROCESSING_DEFERREDVIDEOPROCESSINGSESSIONCALLBACKSTUB_H

#include "ideferred_video_processing_session_callback.h"
#include <iremote_stub.h>

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class DeferredVideoProcessingSessionCallbackStub : public IRemoteStub<IDeferredVideoProcessingSessionCallback> {
public:
    int32_t OnRemoteRequest(
        uint32_t code,
        MessageParcel& data,
        MessageParcel& reply,
        MessageOption& option) override;

private:
    static constexpr int32_t COMMAND_ON_PROCESS_VIDEO_DONE = MIN_TRANSACTION_ID + 0;
    static constexpr int32_t COMMAND_ON_ERROR = MIN_TRANSACTION_ID + 1;
    static constexpr int32_t COMMAND_ON_STATE_CHANGED = MIN_TRANSACTION_ID + 2;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERASTANDARD_DEFERREDPROCESSING_DEFERREDVIDEOPROCESSINGSESSIONCALLBACKSTUB_H

