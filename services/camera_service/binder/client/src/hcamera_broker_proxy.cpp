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

#include "hcamera_broker_proxy.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
HCameraProxy::HCameraProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<ICameraBroker>(impl) { }

int32_t HCameraProxy::NotifyCloseCamera(std::string cameraId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(cameraId);
    option.SetFlags(option.TF_SYNC);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceDHInterfaceCode::CAMERA_SERVICE_NOTIFY_CLOSE_CAMERA), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HCameraServiceProxy notifyCloseCamera failed, error: %{public}d", error);
    MEDIA_DEBUG_LOG("HCameraServiceProxy notifyCloseCamera");
    return error;
}

int32_t HCameraProxy::NotifyMuteCamera(bool muteMode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteBool(muteMode);
    option.SetFlags(option.TF_SYNC);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceDHInterfaceCode::CAMERA_SERVICE_NOTIFY_MUTE_CAMERA), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HCameraServiceProxy NotifyMuteCamera failed, error: %{public}d", error);
    MEDIA_DEBUG_LOG("HCameraServiceProxy NotifyMuteCamera");
    return error;
}

} // namespace CameraStandard
} // namespace OHOS
