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

#include "deferred_video_processing_session_proxy.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
ErrCode DeferredVideoProcessingSessionProxy::BeginSynchronize()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return ERR_INVALID_VALUE;
    }

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return ERR_INVALID_DATA;
    }

    int32_t result = remote->SendRequest(COMMAND_BEGIN_SYNCHRONIZE, data, reply, option);
    if (FAILED(result)) {
        return result;
    }
    ErrCode errCode = reply.ReadInt32();
    if (FAILED(errCode)) {
        return errCode;
    }

    return ERR_OK;
}

ErrCode DeferredVideoProcessingSessionProxy::EndSynchronize()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return ERR_INVALID_VALUE;
    }

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return ERR_INVALID_DATA;
    }

    int32_t result = remote->SendRequest(COMMAND_END_SYNCHRONIZE, data, reply, option);
    if (FAILED(result)) {
        return result;
    }
    ErrCode errCode = reply.ReadInt32();
    if (FAILED(errCode)) {
        return errCode;
    }

    return ERR_OK;
}

ErrCode DeferredVideoProcessingSessionProxy::AddVideo(
    const std::string& videoId,
    const sptr<IPCFileDescriptor>& srcFd,
    const sptr<IPCFileDescriptor>& dstFd)
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
    if (!data.WriteParcelable(srcFd)) {
        return ERR_INVALID_DATA;
    }
    if (!data.WriteParcelable(dstFd)) {
        return ERR_INVALID_DATA;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return ERR_INVALID_DATA;
    }

    int32_t result = remote->SendRequest(COMMAND_ADD_VIDEO, data, reply, option);
    if (FAILED(result)) {
        return result;
    }
    ErrCode errCode = reply.ReadInt32();
    if (FAILED(errCode)) {
        return errCode;
    }

    return ERR_OK;
}

ErrCode DeferredVideoProcessingSessionProxy::RemoveVideo(
    const std::string& videoId,
    bool restorable)
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
    if (!data.WriteInt32(restorable ? 1 : 0)) {
        return ERR_INVALID_DATA;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return ERR_INVALID_DATA;
    }

    int32_t result = remote->SendRequest(COMMAND_REMOVE_VIDEO, data, reply, option);
    if (FAILED(result)) {
        return result;
    }
    ErrCode errCode = reply.ReadInt32();
    if (FAILED(errCode)) {
        return errCode;
    }

    return ERR_OK;
}

ErrCode DeferredVideoProcessingSessionProxy::RestoreVideo(
    const std::string& videoId)
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
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return ERR_INVALID_DATA;
    }

    int32_t result = remote->SendRequest(COMMAND_RESTORE_VIDEO, data, reply, option);
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
