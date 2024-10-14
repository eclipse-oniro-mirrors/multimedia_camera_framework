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

#include "deferred_video_processing_session_stub.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
int32_t DeferredVideoProcessingSessionStub::OnRemoteRequest(
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
        case COMMAND_BEGIN_SYNCHRONIZE: {
            ErrCode errCode = BeginSynchronize();
            if (!reply.WriteInt32(errCode)) {
                return ERR_INVALID_VALUE;
            }
            return ERR_NONE;
        }
        case COMMAND_END_SYNCHRONIZE: {
            ErrCode errCode = EndSynchronize();
            if (!reply.WriteInt32(errCode)) {
                return ERR_INVALID_VALUE;
            }
            return ERR_NONE;
        }
        case COMMAND_ADD_VIDEO: {
            std::string videoId = Str16ToStr8(data.ReadString16());
            sptr<IPCFileDescriptor> srcFd(data.ReadParcelable<IPCFileDescriptor>());

            if (!srcFd) {
                return ERR_INVALID_DATA;
            }
            sptr<IPCFileDescriptor> dstFd(data.ReadParcelable<IPCFileDescriptor>());

            if (!dstFd) {
                return ERR_INVALID_DATA;
            }
            ErrCode errCode = AddVideo(videoId, srcFd, dstFd);
            if (!reply.WriteInt32(errCode)) {
                return ERR_INVALID_VALUE;
            }
            return ERR_NONE;
        }
        case COMMAND_REMOVE_VIDEO: {
            std::string videoId = Str16ToStr8(data.ReadString16());
            bool restorable = data.ReadInt32() == 1 ? true : false;
            ErrCode errCode = RemoveVideo(videoId, restorable);
            if (!reply.WriteInt32(errCode)) {
                return ERR_INVALID_VALUE;
            }
            return ERR_NONE;
        }
        case COMMAND_RESTORE_VIDEO: {
            std::string videoId = Str16ToStr8(data.ReadString16());
            ErrCode errCode = RestoreVideo(videoId);
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
