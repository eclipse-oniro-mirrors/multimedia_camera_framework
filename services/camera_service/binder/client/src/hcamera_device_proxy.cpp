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

#include "hcamera_device_proxy.h"
#include "camera_log.h"
#include "metadata_utils.h"
#include "camera_service_ipc_interface_code.h"

namespace OHOS {
namespace CameraStandard {
HCameraDeviceProxy::HCameraDeviceProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<ICameraDeviceService>(impl) { }

HCameraDeviceProxy::~HCameraDeviceProxy()
{
    MEDIA_INFO_LOG("~HCameraDeviceProxy is called");
}

int32_t HCameraDeviceProxy::Open()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteBool(false);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraDeviceInterfaceCode::CAMERA_DEVICE_OPEN), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraDeviceProxy Open failed, error: %{public}d", error);
    }
    return error;
}

int32_t HCameraDeviceProxy::OpenSecureCamera(uint64_t* secureSeqId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteBool(true);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraDeviceInterfaceCode::CAMERA_DEVICE_OPEN), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraDeviceProxy Open failed, error: %{public}d", error);
    }
    *secureSeqId = reply.ReadInt64();
    return error;
}

int32_t HCameraDeviceProxy::Close()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraDeviceInterfaceCode::CAMERA_DEVICE_CLOSE), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraDeviceProxy Close failed, error: %{public}d", error);
    }

    return error;
}

int32_t HCameraDeviceProxy::Release()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraDeviceInterfaceCode::CAMERA_DEVICE_RELEASE), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraDeviceProxy Release failed, error: %{public}d", error);
    }

    return error;
}

int32_t HCameraDeviceProxy::SetCallback(sptr<ICameraDeviceServiceCallback>& callback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (callback == nullptr) {
        MEDIA_ERR_LOG("HCameraDeviceProxy SetCallback callback is null");
        return IPC_PROXY_ERR;
    }

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteRemoteObject(callback->AsObject());

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraDeviceInterfaceCode::CAMERA_DEVICE_SET_CALLBACK), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraDeviceProxy SetCallback failed, error: %{public}d", error);
    }

    return error;
}

int32_t HCameraDeviceProxy::UpdateSetting(const std::shared_ptr<Camera::CameraMetadata> &settings)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    if (!(Camera::MetadataUtils::EncodeCameraMetadata(settings, data))) {
        MEDIA_ERR_LOG("HCameraDeviceProxy UpdateSetting EncodeCameraMetadata failed");
        return IPC_PROXY_ERR;
    }

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraDeviceInterfaceCode::CAMERA_DEVICE_UPDATE_SETTNGS), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraDeviceProxy UpdateSetting failed, error: %{public}d", error);
    }

    return error;
}

int32_t HCameraDeviceProxy::GetStatus(std::shared_ptr<OHOS::Camera::CameraMetadata> &metaIn,
    std::shared_ptr<OHOS::Camera::CameraMetadata> &metaOut)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    if (!(Camera::MetadataUtils::EncodeCameraMetadata(metaIn, data))) {
        MEDIA_ERR_LOG("HCameraDeviceProxy UpdateSetting EncodeCameraMetadata failed");
        return IPC_PROXY_ERR;
    }

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraDeviceInterfaceCode::CAMERA_DEVICE_GET_STATUS), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraDeviceProxy GetStatus failed, error: %{public}d", error);
    } else {
        Camera::MetadataUtils::DecodeCameraMetadata(reply, metaOut);
    }

    return error;
}

int32_t HCameraDeviceProxy::GetEnabledResults(std::vector<int32_t> &results)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraDeviceInterfaceCode::CAMERA_DEVICE_GET_ENABLED_RESULT), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraDeviceProxy GetEnabledResults failed, error: %{public}d", error);
        return IPC_PROXY_ERR;
    }

    reply.ReadInt32Vector(&results);

    return error;
}

int32_t HCameraDeviceProxy::EnableResult(std::vector<int32_t> &results)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteInt32Vector(results);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraDeviceInterfaceCode::CAMERA_DEVICE_ENABLED_RESULT), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraDeviceProxy EnableResult failed, error: %{public}d", error);
    }

    return error;
}

int32_t HCameraDeviceProxy::DisableResult(std::vector<int32_t> &results)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteInt32Vector(results);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraDeviceInterfaceCode::CAMERA_DEVICE_DISABLED_RESULT), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraDeviceProxy DisableResult failed, error: %{public}d", error);
    }

    return error;
}
} // namespace CameraStandard
} // namespace OHOS
