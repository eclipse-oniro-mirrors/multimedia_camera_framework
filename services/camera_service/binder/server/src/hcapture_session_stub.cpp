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
    errCode = OperatePermissionCheck(code);
    CHECK_AND_RETURN_RET(errCode == CAMERA_OK, errCode);
    switch (code) {
        case static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_SESSION_BEGIN_CONFIG):
            errCode = BeginConfig();
            break;
        case static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_SESSION_CAN_ADD_INPUT):
            errCode = HCaptureSessionStub::HandleCanAddInput(data, reply);
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
        case static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_SESSION_RELEASE):
            errCode = Release();
            break;
        case static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_SESSION_SET_CALLBACK):
            errCode = HandleSetCallback(data);
            break;
        case static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_GET_SESSION_STATE):
            errCode = HandleGetSessionState(reply);
            break;
        case static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_SESSION_SET_SMOOTH_ZOOM):
            errCode = HandleSetSmoothZoom(data, reply);
            break;
        case static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_GET_ACTIVE_COLOR_SPACE):
            errCode = HandleGetActiveColorSpace(reply);
            break;
        case static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_SET_COLOR_SPACE):
            errCode = HandleSetColorSpace(data);
            break;
        case static_cast<uint32_t>(CaptureSessionInterfaceCode::CAMERA_CAPTURE_SESSION_SET_FEATURE_MODE):
            errCode = HandleSetFeatureMode(data);
            break;
        default:
            MEDIA_ERR_LOG("HCaptureSessionStub request code %{public}u not handled", code);
            errCode = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
            break;
    }

    return errCode;
}

int32_t HCaptureSessionStub::HandleAddInput(MessageParcel &data)
{
    sptr<IRemoteObject> remoteObj = data.ReadRemoteObject();
    CHECK_AND_RETURN_RET_LOG(remoteObj != nullptr, IPC_STUB_INVALID_DATA_ERR,
                             "HCaptureSessionStub HandleAddInput CameraDevice is null");

    sptr<ICameraDeviceService> cameraDevice = iface_cast<ICameraDeviceService>(remoteObj);
    CHECK_AND_RETURN_RET_LOG(cameraDevice != nullptr, IPC_STUB_INVALID_DATA_ERR,
                             "HCaptureSessionStub HandleAddInput Device is null");
    return AddInput(cameraDevice);
}

int HCaptureSessionStub::HandleCanAddInput(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> remoteObj = data.ReadRemoteObject();
    CHECK_AND_RETURN_RET_LOG(remoteObj != nullptr, IPC_STUB_INVALID_DATA_ERR,
                             "HCaptureSessionStub HandleAddInput CameraDevice is null");
    sptr<ICameraDeviceService> cameraDevice = iface_cast<ICameraDeviceService>(remoteObj);
    CHECK_AND_RETURN_RET_LOG(cameraDevice != nullptr, IPC_STUB_INVALID_DATA_ERR,
                             "HCaptureSessionStub HandleCanAddInput CameraDevice is null");
    bool result = false;
    int32_t ret = CanAddInput(cameraDevice, result);
    MEDIA_INFO_LOG("HandleCanAddInput ret: %{public}d, result: %{public}d", ret, result);
    CHECK_AND_RETURN_RET_LOG(reply.WriteBool(result), IPC_STUB_WRITE_PARCEL_ERR,
        "HCaptureSessionStub HandleCanAddInput Write result failed");
    return ret;
}

int32_t HCaptureSessionStub::HandleRemoveInput(MessageParcel &data)
{
    sptr<IRemoteObject> remoteObj = data.ReadRemoteObject();
    CHECK_AND_RETURN_RET_LOG(remoteObj != nullptr, IPC_STUB_INVALID_DATA_ERR,
                             "HCaptureSessionStub HandleRemoveInput CameraDevice is null");

    sptr<ICameraDeviceService> cameraDevice = iface_cast<ICameraDeviceService>(remoteObj);
    CHECK_AND_RETURN_RET_LOG(cameraDevice != nullptr, IPC_STUB_INVALID_DATA_ERR,
                             "HCaptureSessionStub HandleRemoveInput CameraDevice is null");
    return RemoveInput(cameraDevice);
}

int32_t HCaptureSessionStub::HandleAddOutput(MessageParcel &data)
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

int32_t HCaptureSessionStub::HandleRemoveOutput(MessageParcel &data)
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

int32_t HCaptureSessionStub::HandleSetCallback(MessageParcel &data)
{
    auto remoteObject = data.ReadRemoteObject();
    CHECK_AND_RETURN_RET_LOG(remoteObject != nullptr, IPC_STUB_INVALID_DATA_ERR,
                             "HCaptureSessionStub HandleSetCallback CaptureSessionCallback is null");

    auto callback = iface_cast<ICaptureSessionCallback>(remoteObject);
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, IPC_STUB_INVALID_DATA_ERR,
                             "HCaptureSessionStub HandleSetCallback callback is null");
    return SetCallback(callback);
}

int32_t HCaptureSessionStub::HandleGetSessionState(MessageParcel &reply)
{
    CaptureSessionState sessionState;
    int32_t ret = GetSessionState(sessionState);
    CHECK_AND_RETURN_RET_LOG(reply.WriteUint32(static_cast<uint32_t>(sessionState)), IPC_STUB_WRITE_PARCEL_ERR,
                             "HCaptureSessionStub HandleGetSesstionState Write sessionState failed");
    return ret;
}

int HCaptureSessionStub::HandleGetActiveColorSpace(MessageParcel &reply)
{
    ColorSpace currColorSpace;
    int32_t ret = GetActiveColorSpace(currColorSpace);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(static_cast<int32_t>(currColorSpace)), IPC_STUB_WRITE_PARCEL_ERR,
                             "HCaptureSessionStub HandleGetActiveColorSpace write colorSpace failed");
    return ret;
}

int HCaptureSessionStub::HandleSetColorSpace(MessageParcel &data)
{
    ColorSpace colorSpace = static_cast<ColorSpace>(data.ReadInt32());
    ColorSpace colorSpaceForCapture = static_cast<ColorSpace>(data.ReadInt32());
    bool isNeedUpdate = data.ReadBool();
    return SetColorSpace(colorSpace, colorSpaceForCapture, isNeedUpdate);
}

int HCaptureSessionStub::HandleSetSmoothZoom(MessageParcel &data, MessageParcel &reply)
{
    int smoothZoomType = static_cast<int32_t>(data.ReadUint32());
    int operationMode = static_cast<int32_t>(data.ReadUint32());
    float targetZoomRatio = data.ReadFloat();
    float duration;
    int32_t ret = SetSmoothZoom(smoothZoomType, operationMode, targetZoomRatio, duration);
    CHECK_AND_RETURN_RET_LOG(reply.WriteFloat(duration), IPC_STUB_WRITE_PARCEL_ERR,
                             "HCaptureSessionStub HandleSetSmoothZoom Write duration failed");
    return ret;
}

int HCaptureSessionStub::HandleSetFeatureMode(MessageParcel &data)
{
    int featureMode = static_cast<int>(data.ReadUint32());
    return SetFeatureMode(featureMode);
}
} // namespace CameraStandard
} // namespace OHOS
