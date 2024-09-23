/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "hstream_metadata_callback_proxy.h"
#include "camera_log.h"
#include "metadata_utils.h"
#include "camera_service_ipc_interface_code.h"

namespace OHOS {
namespace CameraStandard {
HStreamMetadataCallbackProxy::HStreamMetadataCallbackProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IStreamMetadataCallback>(impl) { }

int32_t HStreamMetadataCallbackProxy::OnMetadataResult(const int32_t streamId,
    const std::shared_ptr<OHOS::Camera::CameraMetadata> &result)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    option.SetFlags(option.TF_ASYNC);

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteInt32(streamId);

    if (!(Camera::MetadataUtils::EncodeCameraMetadata(result, data))) {
        MEDIA_ERR_LOG("HCameraDeviceCallbackProxy OnResult EncodeCameraMetadata failed");
        return IPC_PROXY_ERR;
    }
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamMetadataCallbackInterfaceCode::CAMERA_META_OPERATOR_ON_RESULT),
        data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraDeviceCallbackProxy OnResult failed, error: %{public}d", error);
    }
    return error;
}
} // namespace CameraStandard
} // namespace OHOS
