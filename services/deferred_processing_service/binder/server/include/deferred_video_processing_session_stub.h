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

#ifndef OHOS_CAMERASTANDARD_DEFERREDPROCESSING_DEFERREDVIDEOPROCESSINGSESSIONSTUB_H
#define OHOS_CAMERASTANDARD_DEFERREDPROCESSING_DEFERREDVIDEOPROCESSINGSESSIONSTUB_H

#include "ideferred_video_processing_session.h"
#include <iremote_stub.h>

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class DeferredVideoProcessingSessionStub : public IRemoteStub<IDeferredVideoProcessingSession> {
public:
    int32_t OnRemoteRequest(
        uint32_t code,
        MessageParcel& data,
        MessageParcel& reply,
        MessageOption& option) override;

private:
    static constexpr int32_t COMMAND_BEGIN_SYNCHRONIZE = MIN_TRANSACTION_ID + 0;
    static constexpr int32_t COMMAND_END_SYNCHRONIZE = MIN_TRANSACTION_ID + 1;
    static constexpr int32_t COMMAND_ADD_VIDEO = MIN_TRANSACTION_ID + 2;
    static constexpr int32_t COMMAND_REMOVE_VIDEO = MIN_TRANSACTION_ID + 3;
    static constexpr int32_t COMMAND_RESTORE_VIDEO = MIN_TRANSACTION_ID + 4;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERASTANDARD_DEFERREDPROCESSING_DEFERREDVIDEOPROCESSINGSESSIONSTUB_H

