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

#include "deferred_photo_processing_session_proxy.h"
#include "deferred_processing_service_ipc_interface_code.h"
#include "metadata_utils.h"
#include "utils/dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
DeferredPhotoProcessingSessionProxy::DeferredPhotoProcessingSessionProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IDeferredPhotoProcessingSession>(impl) { }

int32_t DeferredPhotoProcessingSessionProxy::BeginSynchronize()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(DeferredProcessingServiceInterfaceCode::DPS_BEGIN_SYNCHRONIZE), data, reply, option);
    if (error != ERR_NONE) {
        DP_ERR_LOG("DeferredPhotoProcessingSessionProxy::BeginSynchronize failed, error: %{public}d", error);
    }
    return error;
}

int32_t DeferredPhotoProcessingSessionProxy::EndSynchronize()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(DeferredProcessingServiceInterfaceCode::DPS_END_SYNCHRONIZE), data, reply, option);
    if (error != ERR_NONE) {
        DP_ERR_LOG("DeferredPhotoProcessingSessionProxy::EndSynchronize failed, error: %{public}d", error);
    }
    return error;
}

int32_t DeferredPhotoProcessingSessionProxy::AddImage(const std::string imageId,
                                                      DpsMetadata& metadata, const bool discardable)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(imageId);
    metadata.WriteToParcel(data);
    data.WriteBool(discardable);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(DeferredProcessingServiceInterfaceCode::DPS_ADD_IMAGE), data, reply, option);
    if (error != ERR_NONE) {
        DP_ERR_LOG("DeferredPhotoProcessingSessionProxy::AddImage failed, error: %{public}d", error);
    }
    return error;
}

int32_t DeferredPhotoProcessingSessionProxy::RemoveImage(const std::string imageId, const bool restorable)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(imageId);
    data.WriteBool(restorable);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(DeferredProcessingServiceInterfaceCode::DPS_REMOVE_IMAGE), data, reply, option);
    if (error != ERR_NONE) {
        DP_ERR_LOG("DeferredPhotoProcessingSessionProxy::RemoveImage failed, error: %{public}d", error);
    }
    return error;
}

int32_t DeferredPhotoProcessingSessionProxy::RestoreImage(const std::string imageId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(imageId);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(DeferredProcessingServiceInterfaceCode::DPS_RESTORE_IMAGE), data, reply, option);
    if (error != ERR_NONE) {
        DP_ERR_LOG("DeferredPhotoProcessingSessionProxy::RestoreImage failed, error: %{public}d", error);
    }
    return error;
}

int32_t DeferredPhotoProcessingSessionProxy::ProcessImage(const std::string appName, const std::string imageId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(appName);
    data.WriteString(imageId);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(DeferredProcessingServiceInterfaceCode::DPS_PROCESS_IMAGE), data, reply, option);
    if (error != ERR_NONE) {
        DP_ERR_LOG("DeferredPhotoProcessingSessionProxy::ProcessImage failed, error: %{public}d", error);
    }
    return error;
}

int32_t DeferredPhotoProcessingSessionProxy::CancelProcessImage(const std::string imageId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(imageId);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(DeferredProcessingServiceInterfaceCode::DPS_CANCEL_PROCESS_IMAGE), data, reply, option);
    if (error != ERR_NONE) {
        DP_ERR_LOG("DeferredPhotoProcessingSessionProxy::CancelProcessImage failed, error: %{public}d", error);
    }
    return error;
}

} //namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
