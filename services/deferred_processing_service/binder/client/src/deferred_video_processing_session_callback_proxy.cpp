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

#include "deferred_video_processing_session_callback_proxy.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
ErrCode DeferredVideoProcessingSessionCallbackProxy::OnProcessVideoDone(
    const std::string& videoId, const sptr<IPCFileDescriptor>& fd)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return ERR_INVALID_VALUE;
    }

    if (!data.WriteString16(Str8ToStr16(videoId))) {
        return ERR_INVALID_DATA;
    }
    if (!data.WriteParcelable(fd)) {
        return ERR_INVALID_DATA;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return ERR_INVALID_DATA;
    }

    int32_t result = remote->SendRequest(COMMAND_ON_PROCESS_VIDEO_DONE, data, reply, option);
    if (FAILED(result)) {
        return result;
    }
    ErrCode errCode = reply.ReadInt32();
    if (FAILED(errCode)) {
        return errCode;
    }

    return ERR_OK;
}

ErrCode DeferredVideoProcessingSessionCallbackProxy::OnError(
    const std::string& videoId,
    int32_t errorCode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return ERR_INVALID_VALUE;
    }

    if (!data.WriteString16(Str8ToStr16(videoId))) {
        return ERR_INVALID_DATA;
    }
    if (!data.WriteInt32(errorCode)) {
        return ERR_INVALID_DATA;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return ERR_INVALID_DATA;
    }

    int32_t result = remote->SendRequest(COMMAND_ON_ERROR, data, reply, option);
    if (FAILED(result)) {
        return result;
    }
    ErrCode errCode = reply.ReadInt32();
    if (FAILED(errCode)) {
        return errCode;
    }

    return ERR_OK;
}

ErrCode DeferredVideoProcessingSessionCallbackProxy::OnStateChanged(
    int32_t status)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return ERR_INVALID_VALUE;
    }

    if (!data.WriteInt32(status)) {
        return ERR_INVALID_DATA;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return ERR_INVALID_DATA;
    }

    int32_t result = remote->SendRequest(COMMAND_ON_STATE_CHANGED, data, reply, option);
    if (FAILED(result)) {
        return result;
    }
    ErrCode errCode = reply.ReadInt32();
    if (FAILED(errCode)) {
        return errCode;
    }

    return ERR_OK;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
