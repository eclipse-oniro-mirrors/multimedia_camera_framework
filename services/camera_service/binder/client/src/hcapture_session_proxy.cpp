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

#include "hcapture_session_proxy.h"
#include "camera_log.h"
#include "camera_service_ipc_interface_code.h"

namespace OHOS {
namespace CameraStandard {
HCaptureSessionProxy::HCaptureSessionProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<ICaptureSession>(impl) { }

int32_t HCaptureSessionProxy::BeginConfig()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_SESSION_BEGIN_CONFIG), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCaptureSessionProxy BeginConfig failed, error: %{public}d", error);
    }

    return error;
}

int32_t HCaptureSessionProxy::CanAddInput(sptr<ICameraDeviceService> cameraDevice, bool& result)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (cameraDevice == nullptr) {
        MEDIA_ERR_LOG("HCaptureSessionProxy CanAddInput cameraDevice is null");
        return IPC_PROXY_ERR;
    }

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteRemoteObject(cameraDevice->AsObject());
    (void)data.WriteBool(result);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_SESSION_CAN_ADD_INPUT), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCaptureSessionProxy CanAddInput failed, error: %{public}d", error);
        return error;
    }
    result = reply.ReadBool();
    MEDIA_DEBUG_LOG("CanAddInput result is %{public}d", result);
    return error;
}

int32_t HCaptureSessionProxy::AddInput(sptr<ICameraDeviceService> cameraDevice)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (cameraDevice == nullptr) {
        MEDIA_ERR_LOG("HCaptureSessionProxy AddInput cameraDevice is null");
        return IPC_PROXY_ERR;
    }

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteRemoteObject(cameraDevice->AsObject());

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_SESSION_ADD_INPUT), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCaptureSessionProxy AddInput failed, error: %{public}d", error);
    }

    return error;
}

int32_t HCaptureSessionProxy::AddOutput(StreamType streamType, sptr<IStreamCommon> stream)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (stream == nullptr) {
        MEDIA_ERR_LOG("HCaptureSessionProxy AddOutput stream is null");
        return IPC_PROXY_ERR;
    }

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteUint32(static_cast<uint32_t>(streamType));
    data.WriteRemoteObject(stream->AsObject());

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_SESSION_ADD_OUTPUT), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCaptureSessionProxy AddOutput failed, error: %{public}d", error);
    }

    return error;
}

int32_t HCaptureSessionProxy::RemoveInput(sptr<ICameraDeviceService> cameraDevice)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (cameraDevice == nullptr) {
        MEDIA_ERR_LOG("HCaptureSessionProxy RemoveInput cameraDevice is null");
        return IPC_PROXY_ERR;
    }

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteRemoteObject(cameraDevice->AsObject());

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_SESSION_REMOVE_INPUT), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCaptureSessionProxy RemoveInput failed, error: %{public}d", error);
    }

    return error;
}

int32_t HCaptureSessionProxy::RemoveOutput(StreamType streamType, sptr<IStreamCommon> stream)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (stream == nullptr) {
        MEDIA_ERR_LOG("HCaptureSessionProxy RemoveOutput stream is null");
        return IPC_PROXY_ERR;
    }

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteUint32(static_cast<uint32_t>(streamType));
    data.WriteRemoteObject(stream->AsObject());

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_SESSION_REMOVE_OUTPUT), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCaptureSessionProxy RemoveOutput failed, error: %{public}d", error);
    }

    return error;
}

int32_t HCaptureSessionProxy::CommitConfig()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_SESSION_COMMIT_CONFIG), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCaptureSessionProxy CommitConfig failed, error: %{public}d", error);
    }

    return error;
}

int32_t HCaptureSessionProxy::Start()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_SESSION_START), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCaptureSessionProxy Start failed, error: %{public}d", error);
    }

    return error;
}

int32_t HCaptureSessionProxy::Stop()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_SESSION_STOP), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCaptureSessionProxy Stop failed, error: %{public}d", error);
    }

    return error;
}

int32_t HCaptureSessionProxy::Release()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_SESSION_RELEASE), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCaptureSessionProxy Release failed, error: %{public}d", error);
    }

    return error;
}

int32_t HCaptureSessionProxy::SetCallback(sptr<ICaptureSessionCallback> &callback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (callback == nullptr) {
        MEDIA_ERR_LOG("HCaptureSessionProxy SetCallback callback is null");
        return IPC_PROXY_ERR;
    }

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteRemoteObject(callback->AsObject());

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_SESSION_SET_CALLBACK), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCaptureSessionProxy SetCallback failed, error: %{public}d", error);
    }

    return error;
}

int32_t HCaptureSessionProxy::GetSessionState(CaptureSessionState &sessionState)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_GET_SESSION_STATE), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCaptureSessionProxy GetSessionState failed, error: %{public}d", error);
    }
    sessionState = static_cast<CaptureSessionState>(reply.ReadUint32());
    return error;
}

int32_t HCaptureSessionProxy::GetActiveColorSpace(ColorSpace& colorSpace)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_GET_ACTIVE_COLOR_SPACE), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCaptureSessionProxy GetActiveColorSpace failed, error: %{public}d", error);
    }
    colorSpace = static_cast<ColorSpace>(reply.ReadInt32());
    return error;
}

int32_t HCaptureSessionProxy::SetColorSpace(ColorSpace colorSpace, ColorSpace captureColorSpace, bool isNeedUpdate)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteInt32(static_cast<int32_t>(colorSpace));
    data.WriteInt32(static_cast<int32_t>(captureColorSpace));
    data.WriteBool(isNeedUpdate);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_SET_COLOR_SPACE), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCaptureSessionProxy SetCallback failed, error: %{public}d", error);
    }
    return error;
}

int32_t HCaptureSessionProxy::SetSmoothZoom(int32_t mode, int32_t operationMode, float targetZoomRatio, float &duration)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteUint32(static_cast<uint32_t>(mode));
    data.WriteUint32(static_cast<uint32_t>(operationMode));
    data.WriteFloat(targetZoomRatio);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_SESSION_SET_SMOOTH_ZOOM),
        data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCaptureSessionProxy set smooth zoom failed, error: %{public}d", error);
    }
    duration = reply.ReadFloat();
    return error;
}

int32_t HCaptureSessionProxy::SetFeatureMode(int32_t featureMode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteInt32(static_cast<int32_t>(featureMode));

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_SESSION_SET_FEATURE_MODE), data, reply,
        option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("SetFeatureMode failed, error: %{public}d", error);
    }
    return error;
}
} // namespace CameraStandard
} // namespace OHOS
