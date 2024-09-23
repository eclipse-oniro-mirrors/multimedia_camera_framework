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

#include "deferred_video_processing_session_callback_stub.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
int32_t DeferredVideoProcessingSessionCallbackStub::OnRemoteRequest(
    uint32_t code,
    MessageParcel& data,
    MessageParcel& reply,
    MessageOption& option)
{
    std::u16string localDescriptor = GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (localDescriptor != remoteDescriptor) {
        return ERR_TRANSACTION_FAILED;
    }
    switch (code) {
        case COMMAND_ON_PROCESS_VIDEO_DONE: {
            std::string videoId = Str16ToStr8(data.ReadString16());
            sptr<IPCFileDescriptor> fd(data.ReadParcelable<IPCFileDescriptor>());
            ErrCode errCode = OnProcessVideoDone(videoId, fd);
            if (!reply.WriteInt32(errCode)) {
                return ERR_INVALID_VALUE;
            }
            return ERR_NONE;
        }
        case COMMAND_ON_ERROR: {
            std::string videoId = Str16ToStr8(data.ReadString16());
            int32_t errorCode = data.ReadInt32();
            ErrCode errCode = OnError(videoId, errorCode);
            if (!reply.WriteInt32(errCode)) {
                return ERR_INVALID_VALUE;
            }
            return ERR_NONE;
        }
        case COMMAND_ON_STATE_CHANGED: {
            int32_t status = data.ReadInt32();
            ErrCode errCode = OnStateChanged(status);
            if (!reply.WriteInt32(errCode)) {
                return ERR_INVALID_VALUE;
            }
            return ERR_NONE;
        }
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }

    return ERR_TRANSACTION_FAILED;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
