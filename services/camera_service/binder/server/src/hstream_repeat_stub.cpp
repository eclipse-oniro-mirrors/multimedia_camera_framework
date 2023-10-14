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
int HStreamRepeatStub::OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    DisableJeMalloc();
    int errCode = -1;

    CHECK_AND_RETURN_RET(data.ReadInterfaceToken() == GetDescriptor(), errCode);
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
        default:
            MEDIA_ERR_LOG("HStreamRepeatStub request code %{public}u not handled", code);
            errCode = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
            break;
    }

    return errCode;
}

int HStreamRepeatStub::HandleSetCallback(MessageParcel& data)
{
    auto remoteObject = data.ReadRemoteObject();
    CHECK_AND_RETURN_RET_LOG(remoteObject != nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HStreamRepeatStub HandleSetCallback StreamRepeatCallback is null");

    auto callback = iface_cast<IStreamRepeatCallback>(remoteObject);

    return SetCallback(callback);
}

int HStreamRepeatStub::HandleAddDeferredSurface(MessageParcel& data)
{
    sptr<IRemoteObject> remoteObj = data.ReadRemoteObject();

    CHECK_AND_RETURN_RET_LOG(remoteObj != nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HStreamRepeatStub HandleAddDeferredSurface BufferProducer is null");

    sptr<OHOS::IBufferProducer> producer = iface_cast<OHOS::IBufferProducer>(remoteObj);
    int errCode = AddDeferredSurface(producer);
    if (errCode != ERR_NONE) {
        MEDIA_ERR_LOG("HStreamRepeatStub::HandleAddDeferredSurface add deferred surface failed : %{public}d", errCode);
        return errCode;
    }

    return errCode;
}

int HStreamRepeatStub::HandleForkSketchStreamRepeat(MessageParcel& data, MessageParcel& reply)
{
    sptr<IStreamRepeat> sketchStream = nullptr;
    sptr<IRemoteObject> remoteObj = data.ReadRemoteObject();
    CHECK_AND_RETURN_RET_LOG(remoteObj != nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HStreamRepeatStub HandleForkSketchStreamRepeat BufferProducer is null");
    int32_t width = data.ReadInt32();
    int32_t height = data.ReadInt32();
    sptr<OHOS::IBufferProducer> producer = iface_cast<OHOS::IBufferProducer>(remoteObj);
    int errCode = ForkSketchStreamRepeat(producer, width, height, sketchStream);
    if (errCode != ERR_NONE) {
        MEDIA_ERR_LOG("HStreamRepeatStub::HandleForkSketchStreamRepeat failed : %{public}d", errCode);
        return errCode;
    }
    CHECK_AND_RETURN_RET_LOG(reply.WriteRemoteObject(sketchStream->AsObject()), IPC_STUB_WRITE_PARCEL_ERR,
        "HStreamRepeatStub HandleForkSketchStreamRepeat Write sketchStream obj failed");
    return errCode;
}
} // namespace CameraStandard
} // namespace OHOS
