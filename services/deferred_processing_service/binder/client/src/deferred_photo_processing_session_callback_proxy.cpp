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

#include "deferred_photo_processing_session_callback_proxy.h"
#include "deferred_processing_service_ipc_interface_code.h"
#include "utils/dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
DeferredPhotoProcessingSessionCallbackProxy::DeferredPhotoProcessingSessionCallbackProxy(
    const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IDeferredPhotoProcessingSessionCallback>(impl) { }

int32_t DeferredPhotoProcessingSessionCallbackProxy::OnProcessImageDone(const std::string &imageId,
    sptr<IPCFileDescriptor> ipcFd, long bytes)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(imageId);
    data.WriteObject<IPCFileDescriptor>(ipcFd);
    data.WriteInt64(bytes);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(DeferredProcessingServiceCallbackInterfaceCode::DPS_PHOTO_CALLBACK_PROCESS_IMAGE_DONE),
        data, reply, option);
    if (error != ERR_NONE) {
        DP_ERR_LOG("DeferredPhotoProcessingSessionCallbackProxy OnProcessImageDone failed, error: %{public}d", error);
    }
    return error;
}

int32_t DeferredPhotoProcessingSessionCallbackProxy::OnError(const std::string &imageId, ErrorCode errorCode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(imageId);
    data.WriteInt32(errorCode);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(DeferredProcessingServiceCallbackInterfaceCode::DPS_PHOTO_CALLBACK_ERROR),
        data, reply, option);
    if (error != ERR_NONE) {
        DP_ERR_LOG("DeferredPhotoProcessingSessionCallbackProxy OnError failed, error: %{public}d", error);
    }
    return error;
}

int32_t DeferredPhotoProcessingSessionCallbackProxy::OnStateChanged(StatusCode status)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteInt32(status);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(DeferredProcessingServiceCallbackInterfaceCode::DPS_PHOTO_CALLBACK_STATE_CHANGED),
        data, reply, option);
    if (error != ERR_NONE) {
        DP_ERR_LOG("DeferredPhotoProcessingSessionCallbackProxy OnStateChanged failed, error: %{public}d", error);
    }
    return error;
}
} //namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS