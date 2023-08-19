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

#include "hcapture_session_stub.h"
#include "camera_log.h"
#include "camera_util.h"
#include "ipc_skeleton.h"
#include "camera_service_ipc_interface_code.h"

namespace OHOS {
namespace CameraStandard {
int HCaptureSessionStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    DisableJeMalloc();
    int errCode = -1;

    CHECK_AND_RETURN_RET(data.ReadInterfaceToken() == GetDescriptor(), errCode);
    switch (code) {
        case static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_SESSION_BEGIN_CONFIG):
            errCode = BeginConfig();
            break;
        case static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_SESSION_ADD_INPUT):
            errCode = HCaptureSessionStub::HandleAddInput(data);
            break;
        case static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_SESSION_ADD_OUTPUT):
            errCode = HCaptureSessionStub::HandleAddOutput(data);
            break;
        case static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_SESSION_REMOVE_INPUT):
            errCode = HCaptureSessionStub::HandleRemoveInput(data);
            break;
        case static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_SESSION_REMOVE_OUTPUT):
            errCode = HCaptureSessionStub::HandleRemoveOutput(data);
            break;
        case static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_SESSION_COMMIT_CONFIG):
            errCode = CommitConfig();
            break;
        case static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_SESSION_START):
            errCode = Start();
            break;
        case static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_SESSION_STOP):
            errCode = Stop();
            break;
        case static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_SESSION_RELEASE): {
                pid_t pid = IPCSkeleton::GetCallingPid();
                errCode = Release(pid);
            }
            break;
        case static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_SESSION_SET_CALLBACK):
            errCode = HandleSetCallback(data);
            break;
        case static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_GET_SESSION_STATE):
            errCode =  HandleGetSesstionState(reply);
            break;
        default:
            MEDIA_ERR_LOG("HCaptureSessionStub request code %{public}u not handled", code);
            errCode = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
            break;
    }

    return errCode;
}

int HCaptureSessionStub::HandleAddInput(MessageParcel &data)
{
    sptr<IRemoteObject> remoteObj = data.ReadRemoteObject();
    CHECK_AND_RETURN_RET_LOG(remoteObj != nullptr, IPC_STUB_INVALID_DATA_ERR,
                             "HCaptureSessionStub HandleAddInput CameraDevice is null");

    sptr<ICameraDeviceService> cameraDevice = iface_cast<ICameraDeviceService>(remoteObj);

    return AddInput(cameraDevice);
}

int HCaptureSessionStub::HandleRemoveInput(MessageParcel &data)
{
    sptr<IRemoteObject> remoteObj = data.ReadRemoteObject();
    CHECK_AND_RETURN_RET_LOG(remoteObj != nullptr, IPC_STUB_INVALID_DATA_ERR,
                             "HCaptureSessionStub HandleRemoveInput CameraDevice is null");

    sptr<ICameraDeviceService> cameraDevice = iface_cast<ICameraDeviceService>(remoteObj);

    return RemoveInput(cameraDevice);
}

int HCaptureSessionStub::HandleAddOutput(MessageParcel &data)
{
    StreamType streamType = static_cast<StreamType>(data.ReadUint32());
    sptr<IRemoteObject> remoteObj = data.ReadRemoteObject();
    CHECK_AND_RETURN_RET_LOG(remoteObj != nullptr, IPC_STUB_INVALID_DATA_ERR,
                             "HCaptureSessionStub HandleAddOutput remoteObj is null");
    sptr<IStreamCommon> stream = nullptr;
    if (streamType == StreamType::CAPTURE) {
        stream = iface_cast<IStreamCapture>(remoteObj);
    } else if (streamType == StreamType::REPEAT) {
        stream = iface_cast<IStreamRepeat>(remoteObj);
    }  else if (streamType == StreamType::METADATA) {
        stream = iface_cast<IStreamMetadata>(remoteObj);
    }

    return AddOutput(streamType, stream);
}

int HCaptureSessionStub::HandleRemoveOutput(MessageParcel &data)
{
    StreamType streamType = static_cast<StreamType>(data.ReadUint32());
    sptr<IRemoteObject> remoteObj = data.ReadRemoteObject();
    CHECK_AND_RETURN_RET_LOG(remoteObj != nullptr, IPC_STUB_INVALID_DATA_ERR,
                             "HCaptureSessionStub HandleRemoveOutput remoteObj is null");
    sptr<IStreamCommon> stream = nullptr;
    if (streamType == StreamType::CAPTURE) {
        stream = iface_cast<IStreamCapture>(remoteObj);
    } else if (streamType == StreamType::REPEAT) {
        stream = iface_cast<IStreamRepeat>(remoteObj);
    }  else if (streamType == StreamType::METADATA) {
        stream = iface_cast<IStreamMetadata>(remoteObj);
    }
    return RemoveOutput(streamType, stream);
}

int HCaptureSessionStub::HandleSetCallback(MessageParcel &data)
{
    auto remoteObject = data.ReadRemoteObject();
    CHECK_AND_RETURN_RET_LOG(remoteObject != nullptr, IPC_STUB_INVALID_DATA_ERR,
                             "HCaptureSessionStub HandleSetCallback CaptureSessionCallback is null");

    auto callback = iface_cast<ICaptureSessionCallback>(remoteObject);

    return SetCallback(callback);
}

int HCaptureSessionStub::HandleGetSesstionState(MessageParcel &reply)
{
    CaptureSessionState sessionState;
    int32_t ret = GetSessionState(sessionState);
    CHECK_AND_RETURN_RET_LOG(reply.WriteUint32(static_cast<uint32_t>(sessionState)), IPC_STUB_WRITE_PARCEL_ERR,
                             "HCaptureSessionStub HandleGetSesstionState Write sessionState failed");
    return ret;
}
} // namespace CameraStandard
} // namespace OHOS
