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

#include "hstream_repeat_stub.h"

#include "camera_log.h"
#include "camera_service_ipc_interface_code.h"
#include "camera_util.h"

namespace OHOS {
namespace CameraStandard {
static constexpr float SKETCH_RATIO_MAX_VALUE = 100.0f;
int HStreamRepeatStub::OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    DisableJeMalloc();
    int errCode = -1;

    CHECK_ERROR_RETURN_RET(data.ReadInterfaceToken() != GetDescriptor(), errCode);
    errCode = OperatePermissionCheck(code);
    CHECK_ERROR_RETURN_RET(errCode != CAMERA_OK, errCode);
    switch (code) {
        case static_cast<uint32_t>(StreamRepeatInterfaceCode::CAMERA_START_VIDEO_RECORDING):
            errCode = Start();
            break;
        case static_cast<uint32_t>(StreamRepeatInterfaceCode::CAMERA_STOP_VIDEO_RECORDING):
            errCode = Stop();
            break;
        case static_cast<uint32_t>(StreamRepeatInterfaceCode::CAMERA_STREAM_REPEAT_SET_CALLBACK):
            errCode = HStreamRepeatStub::HandleSetCallback(data);
            break;
        case static_cast<uint32_t>(StreamRepeatInterfaceCode::CAMERA_STREAM_REPEAT_RELEASE):
            errCode = Release();
            break;
        case static_cast<uint32_t>(StreamRepeatInterfaceCode::CAMERA_ADD_DEFERRED_SURFACE):
            errCode = HStreamRepeatStub::HandleAddDeferredSurface(data);
            break;
        case static_cast<uint32_t>(StreamRepeatInterfaceCode::CAMERA_FORK_SKETCH_STREAM_REPEAT):
            errCode = HStreamRepeatStub::HandleForkSketchStreamRepeat(data, reply);
            break;
        case static_cast<uint32_t>(StreamRepeatInterfaceCode::CAMERA_REMOVE_SKETCH_STREAM_REPEAT):
            errCode = RemoveSketchStreamRepeat();
            break;
        case static_cast<uint32_t>(StreamRepeatInterfaceCode::CAMERA_UPDATE_SKETCH_RATIO):
            errCode = HandleUpdateSketchRatio(data);
            break;
        case static_cast<uint32_t>(StreamRepeatInterfaceCode::CAMERA_STREAM_FRAME_RANGE_SET):
            errCode = HandleSetFrameRate(data);
            break;
        case static_cast<uint32_t>(StreamRepeatInterfaceCode::CAMERA_ENABLE_SECURE_STREAM):
            errCode = EnableSecure(data.ReadBool());
            break;
        case static_cast<uint32_t>(StreamRepeatInterfaceCode::CAMERA_ENABLE_STREAM_MIRROR):
            errCode = HandleSetMirror(data);
            break;
        case static_cast<uint32_t>(StreamRepeatInterfaceCode::CAMERA_ATTACH_META_SURFACE):
            errCode = HandleAttachMetaSurface(data);
            break;
        case static_cast<uint32_t>(StreamRepeatInterfaceCode::CAMERA_PRIVIEW_ROTATION):
            errCode = HandleSetCameraRotation(data);
            break;
        default:
            MEDIA_ERR_LOG("HStreamRepeatStub request code %{public}u not handled", code);
            errCode = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
            break;
    }

    return errCode;
}

int32_t HStreamRepeatStub::HandleSetCallback(MessageParcel& data)
{
    auto remoteObject = data.ReadRemoteObject();
    CHECK_ERROR_RETURN_RET_LOG(remoteObject == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HStreamRepeatStub HandleSetCallback StreamRepeatCallback is null");

    auto callback = iface_cast<IStreamRepeatCallback>(remoteObject);
    CHECK_ERROR_RETURN_RET_LOG(callback == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HStreamRepeatStub HandleSetCallback callback is null");

    return SetCallback(callback);
}

int32_t HStreamRepeatStub::HandleAddDeferredSurface(MessageParcel& data)
{
    CHECK_ERROR_RETURN_RET(!CheckSystemApp(), CAMERA_NO_PERMISSION);

    sptr<IRemoteObject> remoteObj = data.ReadRemoteObject();
    CHECK_ERROR_RETURN_RET_LOG(remoteObj == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HStreamRepeatStub HandleAddDeferredSurface BufferProducer is null");

    sptr<OHOS::IBufferProducer> producer = iface_cast<OHOS::IBufferProducer>(remoteObj);
    CHECK_ERROR_RETURN_RET_LOG(producer == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HStreamRepeatStub HandleAddDeferredSurface producer is null");

    int ret = AddDeferredSurface(producer);
    CHECK_ERROR_PRINT_LOG(ret != ERR_NONE,
        "HStreamRepeatStub::HandleAddDeferredSurface add deferred surface failed : %{public}d", ret);

    return ret;
}

int32_t HStreamRepeatStub::HandleForkSketchStreamRepeat(MessageParcel& data, MessageParcel& reply)
{
    CHECK_ERROR_RETURN_RET(!CheckSystemApp(), CAMERA_NO_PERMISSION);

    sptr<IStreamRepeat> sketchStream = nullptr;
    int32_t width = data.ReadInt32();
    int32_t height = data.ReadInt32();
    float sketchRatio = data.ReadFloat();
    int ret = ForkSketchStreamRepeat(width, height, sketchStream, sketchRatio);
    CHECK_ERROR_RETURN_RET_LOG(ret != ERR_NONE, ret,
        "HStreamRepeatStub::HandleForkSketchStreamRepeat failed : %{public}d", ret);
    CHECK_ERROR_RETURN_RET_LOG(!reply.WriteRemoteObject(sketchStream->AsObject()), IPC_STUB_WRITE_PARCEL_ERR,
        "HStreamRepeatStub HandleForkSketchStreamRepeat Write sketchStream obj failed");

    return ret;
}

int32_t HStreamRepeatStub::HandleUpdateSketchRatio(MessageParcel& data)
{
    CHECK_ERROR_RETURN_RET(!CheckSystemApp(), CAMERA_NO_PERMISSION);
    float sketchRatio = data.ReadFloat();
    // SketchRatio value could be negative value
    CHECK_ERROR_RETURN_RET_LOG(sketchRatio > SKETCH_RATIO_MAX_VALUE, IPC_STUB_INVALID_DATA_ERR,
        "HStreamRepeatStub HandleUpdateSketchRatio sketchRatio value is illegal %{public}f", sketchRatio);
    return UpdateSketchRatio(sketchRatio);
}

int32_t HStreamRepeatStub::HandleSetFrameRate(MessageParcel& data)
{
    int32_t minFrameRate = data.ReadInt32();
    int32_t maxFrameRate = data.ReadInt32();
 
    int ret = SetFrameRate(minFrameRate, maxFrameRate);
    CHECK_ERROR_PRINT_LOG(ret != ERR_NONE, "HStreamRepeatStub::HandleSetFrameRate failed : %{public}d", ret);
    return ret;
}

int32_t HStreamRepeatStub::HandleSetMirror(MessageParcel& data)
{
    bool isEnable = data.ReadBool();
 
    int ret = SetMirror(isEnable);
    CHECK_ERROR_PRINT_LOG(ret != ERR_NONE, "HStreamRepeatStub::HandleSetMirror failed : %{public}d", ret);
    return ret;
}

int32_t HStreamRepeatStub::HandleAttachMetaSurface(MessageParcel& data)
{
    sptr<IRemoteObject> remoteObj = data.ReadRemoteObject();
    int32_t videoMetaType = data.ReadInt32();

    CHECK_ERROR_RETURN_RET_LOG(remoteObj == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HStreamRepeatStub HandleAttachMetaSurface BufferProducer is null");

    sptr<OHOS::IBufferProducer> producer = iface_cast<OHOS::IBufferProducer>(remoteObj);
    CHECK_ERROR_RETURN_RET_LOG(producer == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HStreamRepeatStub HandleAttachMetaSurface producer is null");
    int errCode = AttachMetaSurface(producer, videoMetaType);
    CHECK_ERROR_RETURN_RET_LOG(errCode != ERR_NONE, errCode,
        "HStreamRepeatStub::HandleAttachMetaSurface add deferred surface failed : %{public}d", errCode);

    return errCode;
}

int32_t HStreamRepeatStub::HandleSetCameraRotation(MessageParcel& data)
{
    bool isEnable = data.ReadBool();
    int32_t rotation = data.ReadInt32();
    uint32_t apiCompatibleVersion = data.ReadUint32();

    int ret = SetCameraRotation(isEnable, rotation, apiCompatibleVersion);
    CHECK_ERROR_PRINT_LOG(ret != ERR_NONE, "HStreamRepeatStub::SetCameraRotation failed : %{public}d", ret);
    return ret;
}
} // namespace CameraStandard
} // namespace OHOS
