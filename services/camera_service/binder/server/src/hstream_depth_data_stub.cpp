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

#include "hstream_depth_data_stub.h"

#include "camera_log.h"
#include "camera_service_ipc_interface_code.h"
#include "camera_util.h"

namespace OHOS {
namespace CameraStandard {

int HStreamDepthDataStub::OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply,
                                          MessageOption& option)
{
    DisableJeMalloc();
    int errCode = -1;

    CHECK_AND_RETURN_RET(data.ReadInterfaceToken() == GetDescriptor(), errCode);
    errCode = OperatePermissionCheck(code);
    CHECK_AND_RETURN_RET(errCode == CAMERA_OK, errCode);
    switch (code) {
        case static_cast<uint32_t>(StreamDepthDataInterfaceCode::CAMERA_STREAM_DEPTH_DATA_START):
            errCode = Start();
            break;
        case static_cast<uint32_t>(StreamDepthDataInterfaceCode::CAMERA_STREAM_DEPTH_DATA_STOP):
            errCode = Stop();
            break;
        case static_cast<uint32_t>(StreamDepthDataInterfaceCode::CAMERA_STREAM_DEPTH_DATA_SET_CALLBACK):
            errCode = HStreamDepthDataStub::HandleSetCallback(data);
            break;
        case static_cast<uint32_t>(StreamDepthDataInterfaceCode::CAMERA_STREAM_DEPTH_DATA_ACCURACY_SET):
            errCode = HStreamDepthDataStub::HandleSetDataAccuracy(data);
            break;
        case static_cast<uint32_t>(StreamDepthDataInterfaceCode::CAMERA_STREAM_DEPTH_DATA_RELEASE):
            errCode = Release();
            break;
        default:
            MEDIA_ERR_LOG("HStreamDepthDataStub request code %{public}u not handled", code);
            errCode = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
            break;
    }

    return errCode;
}

int32_t HStreamDepthDataStub::HandleSetCallback(MessageParcel& data)
{
    auto remoteObject = data.ReadRemoteObject();
    CHECK_AND_RETURN_RET_LOG(remoteObject != nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HStreamDepthDataStub HandleSetCallback StreamDepthDataCallback is null");

    auto callback = iface_cast<IStreamDepthDataCallback>(remoteObject);
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, IPC_STUB_INVALID_DATA_ERR,
                             "HStreamDepthDataStub HandleSetCallback callback is null");
    return SetCallback(callback);
}

int32_t HStreamDepthDataStub::HandleSetDataAccuracy(MessageParcel& data)
{
    int32_t dataAccuracy = data.ReadInt32();

    int error = SetDataAccuracy(dataAccuracy);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HStreamDepthDataStub::HandleSetDataAccuracy failed : %{public}d", error);
    }
    return error;
}
} // namespace CameraStandard
} // namespace OHOS