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

#include "hcamera_service_proxy.h"
#include "camera_log.h"
#include "metadata_utils.h"
#include "camera_service_ipc_interface_code.h"

namespace OHOS {
namespace CameraStandard {
HCameraServiceProxy::HCameraServiceProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<ICameraService>(impl) { }

int32_t HCameraServiceProxy::GetCameras(std::vector<std::string> &cameraIds,
    std::vector<std::shared_ptr<Camera::CameraMetadata>> &cameraAbilityList)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    constexpr int32_t MAX_SUPPORTED_CAMERAS = 100;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_GET_CAMERAS), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceProxy GetCameras failed, error: %{public}d", error);
        return error;
    }

    reply.ReadStringVector(&cameraIds);
    int32_t count = reply.ReadInt32();
    if ((cameraIds.size() != static_cast<uint32_t>(count)) || (count > MAX_SUPPORTED_CAMERAS)) {
        MEDIA_ERR_LOG("HCameraServiceProxy GetCameras Malformed camera count value");
        return IPC_PROXY_ERR;
    }

    std::shared_ptr<Camera::CameraMetadata> cameraAbility;
    for (int i = 0; i < count; i++) {
        Camera::MetadataUtils::DecodeCameraMetadata(reply, cameraAbility);
        cameraAbilityList.emplace_back(cameraAbility);
    }

    return error;
}

int32_t HCameraServiceProxy::CreateCameraDevice(std::string cameraId, sptr<ICameraDeviceService> &device)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(cameraId);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_CREATE_DEVICE), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceProxy CreateCameraDevice failed, error: %{public}d", error);
        return error;
    }

    auto remoteObject = reply.ReadRemoteObject();
    if (remoteObject != nullptr) {
        device = iface_cast<ICameraDeviceService>(remoteObject);
    } else {
        MEDIA_ERR_LOG("HCameraServiceProxy CreateCameraDevice CameraDevice is null");
        error = IPC_PROXY_ERR;
    }

    return error;
}

int32_t HCameraServiceProxy::SetCallback(sptr<ICameraServiceCallback>& callback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (callback == nullptr) {
        MEDIA_ERR_LOG("HCameraServiceProxy SetCallback callback is null");
        return IPC_PROXY_ERR;
    }

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteRemoteObject(callback->AsObject());

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_SET_CALLBACK), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceProxy SetCallback failed, error: %{public}d", error);
    }

    return error;
}

int32_t HCameraServiceProxy::SetMuteCallback(sptr<ICameraMuteServiceCallback>& callback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (callback == nullptr) {
        MEDIA_ERR_LOG("HCameraServiceProxy SetMuteCallback callback is null");
        return IPC_PROXY_ERR;
    }

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteRemoteObject(callback->AsObject());

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_SET_MUTE_CALLBACK), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceProxy SetMuteCallback failed, error: %{public}d", error);
    }

    return error;
}

int32_t HCameraServiceProxy::SetTorchCallback(sptr<ITorchServiceCallback>& callback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option; 
    if (callback == nullptr) {
        MEDIA_ERR_LOG("HCameraServiceProxy SetTorchCallback callback is null");
        return IPC_PROXY_ERR;
    }

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteRemoteObject(callback->AsObject());

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_SET_TORCH_CALLBACK), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceProxy SetTorchCallback failed, error: %{public}d", error);
    }

    return error;
}

int32_t HCameraServiceProxy::CreateCaptureSession(sptr<ICaptureSession>& session, int32_t operationMode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteInt32(operationMode);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_CREATE_CAPTURE_SESSION), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceProxy CreateCaptureSession failed, error: %{public}d", error);
        return error;
    }

    auto remoteObject = reply.ReadRemoteObject();
    if (remoteObject != nullptr) {
        session = iface_cast<ICaptureSession>(remoteObject);
    } else {
        MEDIA_ERR_LOG("HCameraServiceProxy CreateCaptureSession CaptureSession is null");
        error = IPC_PROXY_ERR;
    }

    return error;
}

int32_t HCameraServiceProxy::CreatePhotoOutput(const sptr<OHOS::IBufferProducer> &producer, int32_t format,
                                               int32_t width, int32_t height,
                                               sptr<IStreamCapture> &photoOutput)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (producer == nullptr) {
        MEDIA_ERR_LOG("HCameraServiceProxy CreatePhotoOutput producer is null");
        return IPC_PROXY_ERR;
    }

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteRemoteObject(producer->AsObject());
    data.WriteInt32(format);
    data.WriteInt32(width);
    data.WriteInt32(height);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_CREATE_PHOTO_OUTPUT), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceProxy CreatePhotoOutput failed, error: %{public}d", error);
        return error;
    }

    auto remoteObject = reply.ReadRemoteObject();
    if (remoteObject != nullptr) {
        photoOutput = iface_cast<IStreamCapture>(remoteObject);
    } else {
        MEDIA_ERR_LOG("HCameraServiceProxy CreatePhotoOutput photoOutput is null");
        error = IPC_PROXY_ERR;
    }

    return error;
}

int32_t HCameraServiceProxy::CreatePreviewOutput(const sptr<OHOS::IBufferProducer> &producer, int32_t format,
                                                 int32_t width, int32_t height,
                                                 sptr<IStreamRepeat>& previewOutput)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if ((producer == nullptr) || (width == 0) || (height == 0)) {
        MEDIA_ERR_LOG("HCameraServiceProxy CreatePreviewOutput producer is null or invalid size is set");
        return IPC_PROXY_ERR;
    }

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteRemoteObject(producer->AsObject());
    data.WriteInt32(format);
    data.WriteInt32(width);
    data.WriteInt32(height);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_CREATE_PREVIEW_OUTPUT), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceProxy CreatePreviewOutput failed, error: %{public}d", error);
        return error;
    }
    auto remoteObject = reply.ReadRemoteObject();
    if (remoteObject != nullptr) {
        previewOutput = iface_cast<IStreamRepeat>(remoteObject);
    } else {
        MEDIA_ERR_LOG("HCameraServiceProxy CreatePreviewOutput previewOutput is null");
        error = IPC_PROXY_ERR;
    }
    return error;
}

int32_t HCameraServiceProxy::CreateDeferredPreviewOutput(int32_t format, int32_t width, int32_t height,
                                                         sptr<IStreamRepeat> &previewOutput)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if ((width == 0) || (height == 0)) {
        MEDIA_ERR_LOG("HCameraServiceProxy CreateDeferredPreviewOutput producer is null or invalid size is set");
        return IPC_PROXY_ERR;
    }

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteInt32(format);
    data.WriteInt32(width);
    data.WriteInt32(height);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_CREATE_DEFERRED_PREVIEW_OUTPUT),
        data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceProxy CreateDeferredPreviewOutput failed, error: %{public}d", error);
        return error;
    }
    auto remoteObject = reply.ReadRemoteObject();
    if (remoteObject != nullptr) {
        previewOutput = iface_cast<IStreamRepeat>(remoteObject);
    } else {
        MEDIA_ERR_LOG("HCameraServiceProxy CreateDeferredPreviewOutput previewOutput is null");
        error = IPC_PROXY_ERR;
    }
    return error;
}

int32_t HCameraServiceProxy::CreateMetadataOutput(const sptr<OHOS::IBufferProducer> &producer, int32_t format,
                                                  sptr<IStreamMetadata>& metadataOutput)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (producer == nullptr) {
        MEDIA_ERR_LOG("HCameraServiceProxy CreateMetadataOutput producer is null");
        return IPC_PROXY_ERR;
    }

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteRemoteObject(producer->AsObject());
    data.WriteInt32(format);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_CREATE_METADATA_OUTPUT), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceProxy CreateMetadataOutput failed, error: %{public}d", error);
        return error;
    }

    auto remoteObject = reply.ReadRemoteObject();
    if (remoteObject != nullptr) {
        metadataOutput = iface_cast<IStreamMetadata>(remoteObject);
    } else {
        MEDIA_ERR_LOG("HCameraServiceProxy CreateMetadataOutput metadataOutput is null");
        error = IPC_PROXY_ERR;
    }

    return error;
}

int32_t HCameraServiceProxy::CreateVideoOutput(const sptr<OHOS::IBufferProducer> &producer, int32_t format,
                                               int32_t width, int32_t height,
                                               sptr<IStreamRepeat>& videoOutput)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (producer == nullptr) {
        MEDIA_ERR_LOG("HCameraServiceProxy CreateVideoOutput producer is null");
        return IPC_PROXY_ERR;
    }

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteRemoteObject(producer->AsObject());
    data.WriteInt32(format);
    data.WriteInt32(width);
    data.WriteInt32(height);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_CREATE_VIDEO_OUTPUT), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceProxy::CreateVideoOutput failed, error: %{public}d", error);
        return error;
    }

    auto remoteObject = reply.ReadRemoteObject();
    if (remoteObject != nullptr) {
        videoOutput = iface_cast<IStreamRepeat>(remoteObject);
    } else {
        MEDIA_ERR_LOG("HCameraServiceProxy CreateVideoOutput videoOutput is null");
        error = IPC_PROXY_ERR;
    }

    return error;
}

int32_t HCameraServiceProxy::SetListenerObject(const sptr<IRemoteObject> &object)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    (void)data.WriteRemoteObject(object);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_SET_LISTENER_OBJ), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceProxy::SetListenerObject Set listener obj failed, error: %{public}d", error);
        return IPC_PROXY_ERR;
    }

    return reply.ReadInt32();
}

int32_t HCameraServiceProxy::MuteCamera(bool muteMode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    (void)data.WriteBool(muteMode);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_MUTE_CAMERA), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceProxy::MuteCamera failed, error: %{public}d", error);
    }
    return error;
}

int32_t HCameraServiceProxy::PrelaunchCamera()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_PRE_LAUNCH_CAMERA), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceProxy::PrelaunchCamera failed, error: %{public}d", error);
    }
    return error;
}

int32_t HCameraServiceProxy::SetPrelaunchConfig(std::string cameraId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(cameraId);

    int32_t error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_SET_PRE_LAUNCH_CAMERA), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceProxy::SetPrelaunchConfig failed, error: %{public}d", error);
    }
    return error;
}

int32_t HCameraServiceProxy::IsCameraMuted(bool &muteMode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    (void)data.WriteBool(muteMode);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_IS_CAMERA_MUTED), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceProxy::IsCameraMuted Set listener obj failed, error: %{public}d", error);
        return error;
    }

    muteMode = reply.ReadBool();
    MEDIA_DEBUG_LOG("HCameraServiceProxy IsCameraMuted Read muteMode is %{public}d", muteMode);
    return error;
}

int32_t HCameraServiceProxy::SetTorchModeOnWithLevel(float level)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteFloat(level);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_SET_TORCH_MODE_ON_WITH_LEVEL), data, reply, option);
    if (error != ERR_NONE) { 
        MEDIA_ERR_LOG("HCameraServiceProxy::SetTorchModeOnWithLevel Set listener obj failed, error: %{public}d", error);
        return error;
    }
    return error;
}
} // namespace CameraStandard
} // namespace OHOS
