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

#include "hstream_repeat_proxy.h"

#include "camera_log.h"
#include "camera_service_ipc_interface_code.h"

namespace OHOS {
namespace CameraStandard {
static constexpr float SKETCH_RATIO_MAX_VALUE = 100.0f;
HStreamRepeatProxy::HStreamRepeatProxy(const sptr<IRemoteObject>& impl) : IRemoteProxy<IStreamRepeat>(impl) {}

HStreamRepeatProxy::~HStreamRepeatProxy()
{
    MEDIA_INFO_LOG("~HStreamRepeatProxy is called");
}

int32_t HStreamRepeatProxy::Start()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamRepeatInterfaceCode::CAMERA_START_VIDEO_RECORDING), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HStreamRepeatProxy Start failed, error: %{public}d", error);

    return error;
}

int32_t HStreamRepeatProxy::Stop()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamRepeatInterfaceCode::CAMERA_STOP_VIDEO_RECORDING), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HStreamRepeatProxy Stop failed, error: %{public}d", error);

    return error;
}

int32_t HStreamRepeatProxy::Release()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamRepeatInterfaceCode::CAMERA_STREAM_REPEAT_RELEASE), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HStreamRepeatProxy Stop failed, error: %{public}d", error);
    return error;
}

int32_t HStreamRepeatProxy::SetCallback(sptr<IStreamRepeatCallback>& callback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    CHECK_ERROR_RETURN_RET_LOG(callback == nullptr, IPC_PROXY_ERR, "HStreamRepeatProxy SetCallback callback is null");

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteRemoteObject(callback->AsObject());

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamRepeatInterfaceCode::CAMERA_STREAM_REPEAT_SET_CALLBACK), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HStreamRepeatProxy SetCallback failed, error: %{public}d", error);

    return error;
}

int32_t HStreamRepeatProxy::UnSetCallback()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamRepeatInterfaceCode::CAMERA_STREAM_REPEAT_UNSET_CALLBACK), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HStreamRepeatProxy UnSetCallback failed, error: %{public}d", error);
    }
    return error;
}

int32_t HStreamRepeatProxy::AddDeferredSurface(const sptr<OHOS::IBufferProducer>& producer)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    CHECK_ERROR_RETURN_RET_LOG(producer == nullptr, IPC_PROXY_ERR,
        "HStreamRepeatProxy AddDeferredSurface producer is null");

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteRemoteObject(producer->AsObject());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamRepeatInterfaceCode::CAMERA_ADD_DEFERRED_SURFACE), data, reply, option);
    CHECK_ERROR_RETURN_RET_LOG(error != ERR_NONE, error,
        "HStreamRepeatProxy::AddDeferredSurface failed, error: %{public}d", error);

    return error;
}

int32_t HStreamRepeatProxy::ForkSketchStreamRepeat(
    int32_t width, int32_t height, sptr<IStreamRepeat>& sketchStream, float sketchRatio)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    CHECK_ERROR_RETURN_RET_LOG(width <= 0 || height <= 0, IPC_PROXY_ERR,
        "HStreamRepeatProxy ForkSketchStreamRepeat producer is null or invalid size is set");

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteInt32(width);
    data.WriteInt32(height);
    data.WriteFloat(sketchRatio);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamRepeatInterfaceCode::CAMERA_FORK_SKETCH_STREAM_REPEAT), data, reply, option);
    auto remoteObject = reply.ReadRemoteObject();
    if (remoteObject != nullptr) {
        sketchStream = iface_cast<IStreamRepeat>(remoteObject);
    } else {
        MEDIA_ERR_LOG("HCameraServiceProxy ForkSketchStreamRepeat sketchStream is null");
        error = IPC_PROXY_ERR;
    }
    return error;
}

int32_t HStreamRepeatProxy::UpdateSketchRatio(float sketchRatio)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    // SketchRatio value could be negative value
    CHECK_ERROR_RETURN_RET_LOG(sketchRatio > SKETCH_RATIO_MAX_VALUE, IPC_PROXY_ERR,
        "HStreamRepeatProxy UpdateSketchRatio value is illegal %{public}f", sketchRatio);

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteFloat(sketchRatio);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamRepeatInterfaceCode::CAMERA_UPDATE_SKETCH_RATIO), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HStreamRepeatProxy UpdateSketchRatio failed, error: %{public}d", error);
    return error;
}

int32_t HStreamRepeatProxy::RemoveSketchStreamRepeat()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamRepeatInterfaceCode::CAMERA_REMOVE_SKETCH_STREAM_REPEAT), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HStreamRepeatProxy Stop failed, error: %{public}d", error);
    return error;
}

int32_t HStreamRepeatProxy::SetFrameRate(int32_t minFrameRate, int32_t maxFrameRate)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
 
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteInt32(minFrameRate);
    data.WriteInt32(maxFrameRate);
 
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamRepeatInterfaceCode::CAMERA_STREAM_FRAME_RANGE_SET), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HStreamRepeatProxy SetFrameRate failed, error: %{public}d", error);
    return error;
}

int32_t HStreamRepeatProxy::EnableSecure(bool isEnable)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteBool(isEnable);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamRepeatInterfaceCode::CAMERA_ENABLE_SECURE_STREAM), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HStreamRepeatProxy EnableSecure failed, error: %{public}d", error);
    return error;
}
 
int32_t HStreamRepeatProxy::SetMirror(bool isEnable)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
 
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteBool(isEnable);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamRepeatInterfaceCode::CAMERA_ENABLE_STREAM_MIRROR), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HStreamRepeatProxy SetMirror failed, error: %{public}d", error);
    return error;
}

int32_t HStreamRepeatProxy::GetMirror(bool& isEnable)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamRepeatInterfaceCode::CAMERA_GET_STREAM_MIRROR), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HStreamRepeatProxy GetMirror failed, error: %{public}d", error);
    }
    isEnable = reply.ReadBool();
    MEDIA_DEBUG_LOG("HCameraServiceProxy mirror Enabled is %{public}d", isEnable);
    return error;
}

int32_t HStreamRepeatProxy::AttachMetaSurface(const sptr<OHOS::IBufferProducer>& producer, int32_t videoMetaType)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    CHECK_ERROR_RETURN_RET_LOG(producer == nullptr, IPC_PROXY_ERR,
        "HStreamRepeatProxy AttachMetaSurface producer is null");

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteRemoteObject(producer->AsObject());
    data.WriteInt32(videoMetaType);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamRepeatInterfaceCode::CAMERA_ATTACH_META_SURFACE), data, reply, option);
    CHECK_ERROR_RETURN_RET_LOG(error != ERR_NONE, error,
        "HStreamRepeatProxy::AttachMetaSurface failed, error: %{public}d", error);

    return error;
}

int32_t HStreamRepeatProxy::SetCameraRotation(bool isEnable, int32_t rotation)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
 
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteBool(isEnable);
    data.WriteInt32(rotation);
 
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamRepeatInterfaceCode::CAMERA_PRIVIEW_ROTATION), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HStreamRepeatProxy SetCameraRotation failed, error: %{public}d", error);
    }
    return error;
}

int32_t HStreamRepeatProxy::SetCameraApi(uint32_t apiCompatibleVersion)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
 
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteUint32(apiCompatibleVersion);
 
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamRepeatInterfaceCode::CAMERA_API_VERSION), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HStreamRepeatProxy SetCameraApi failed, error: %{public}d", error);
    }
    return error;
}

int32_t HStreamRepeatProxy::ToggleAutoVideoFrameRate(bool isEnable)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
 
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteBool(isEnable);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamRepeatInterfaceCode::CAMERA_ENABLE_AUTO_FRAME_RATE), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HStreamRepeatProxy SetCameraRotation failed, error: %{public}d", error);
    }
    return error;
}
} // namespace CameraStandard
} // namespace OHOS
