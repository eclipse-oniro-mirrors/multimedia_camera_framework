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

int32_t HCameraDeviceProxy::closeDelayed()
{
    MEDIA_INFO_LOG("HCameraDeviceProxy::closeDelayed() start");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteBool(false);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraDeviceInterfaceCode::CAMERA_DEVICE_DELAYED_CLOSE), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraDeviceProxy closeDelayed failed, error: %{public}d", error);
    }
    return error;
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
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HCameraDeviceProxy Open failed, error: %{public}d", error);
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
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HCameraDeviceProxy Open failed, error: %{public}d", error);
    *secureSeqId = reply.ReadInt64();
    return error;
}

int32_t HCameraDeviceProxy::Open(int32_t concurrentTypeofcamera)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteInt32(concurrentTypeofcamera);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraDeviceInterfaceCode::CAMERA_DEVICE_OPEN_CONCURRENT), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraDeviceProxy Open failed, error: %{public}d", error);
    }
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
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HCameraDeviceProxy Close failed, error: %{public}d", error);

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
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HCameraDeviceProxy Release failed, error: %{public}d", error);

    return error;
}

int32_t HCameraDeviceProxy::SetCallback(sptr<ICameraDeviceServiceCallback>& callback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    CHECK_ERROR_RETURN_RET_LOG(callback == nullptr, IPC_PROXY_ERR, "HCameraDeviceProxy SetCallback callback is null");

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteRemoteObject(callback->AsObject());

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraDeviceInterfaceCode::CAMERA_DEVICE_SET_CALLBACK), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HCameraDeviceProxy SetCallback failed, error: %{public}d", error);

    return error;
}

int32_t HCameraDeviceProxy::UnSetCallback()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraDeviceInterfaceCode::CAMERA_DEVICE_UNSET_CALLBACK), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraDeviceProxy UnSetCallback failed, error: %{public}d", error);
    }

    return error;
}

int32_t HCameraDeviceProxy::UpdateSetting(const std::shared_ptr<Camera::CameraMetadata> &settings)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    CHECK_ERROR_RETURN_RET_LOG(!(Camera::MetadataUtils::EncodeCameraMetadata(settings, data)), IPC_PROXY_ERR,
        "HCameraDeviceProxy UpdateSetting EncodeCameraMetadata failed");

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraDeviceInterfaceCode::CAMERA_DEVICE_UPDATE_SETTNGS), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HCameraDeviceProxy UpdateSetting failed, error: %{public}d", error);

    return error;
}

int32_t HCameraDeviceProxy::SetUsedAsPosition(uint8_t value)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    CHECK_ERROR_RETURN_RET_LOG(!data.WriteUint8(value), IPC_PROXY_ERR,
        "HCameraDeviceProxy SetUsedAsPosition Encode failed");

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraDeviceInterfaceCode::CAMERA_DEVICE_SET_USED_POS), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HCameraDeviceProxy SetUsedAsPosition failed, error: %{public}d", error);

    return error;
}

int32_t HCameraDeviceProxy::GetStatus(std::shared_ptr<OHOS::Camera::CameraMetadata> &metaIn,
    std::shared_ptr<OHOS::Camera::CameraMetadata> &metaOut)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    CHECK_ERROR_RETURN_RET_LOG(!(Camera::MetadataUtils::EncodeCameraMetadata(metaIn, data)), IPC_PROXY_ERR,
        "HCameraDeviceProxy UpdateSetting EncodeCameraMetadata failed");

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
    CHECK_ERROR_RETURN_RET_LOG(error != ERR_NONE, IPC_PROXY_ERR,
        "HCameraDeviceProxy GetEnabledResults failed, error: %{public}d", error);

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
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HCameraDeviceProxy EnableResult failed, error: %{public}d", error);

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
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HCameraDeviceProxy DisableResult failed, error: %{public}d", error);

    return error;
}

int32_t HCameraDeviceProxy::SetDeviceRetryTime()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraDeviceInterfaceCode::CAMERA_DEVICE_SET_DEVICE_RETRY_TIME),
        data, reply, option);
    return error;
}
} // namespace CameraStandard
} // namespace OHOS
