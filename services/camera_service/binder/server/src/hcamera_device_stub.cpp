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

#include "hcamera_device_stub.h"
#include "camera_log.h"
#include "camera_util.h"
#include "metadata_utils.h"
#include "camera_service_ipc_interface_code.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace CameraStandard {
int HCameraDeviceStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    DisableJeMalloc();
    int errCode = -1;
    CHECK_AND_RETURN_RET(data.ReadInterfaceToken() == GetDescriptor(), errCode);
    errCode = OperatePermissionCheck(code);
    CHECK_AND_RETURN_RET(errCode == CAMERA_OK, errCode);
    switch (code) {
        case static_cast<uint32_t>(CameraDeviceInterfaceCode::CAMERA_DEVICE_OPEN): {
            errCode =HCameraDeviceStub::HandleOpenSecureCameraResults(data, reply);
            break;
        }
        case static_cast<uint32_t>(CameraDeviceInterfaceCode::CAMERA_DEVICE_CLOSE):
            errCode = Close();
            break;
        case static_cast<uint32_t>(CameraDeviceInterfaceCode::CAMERA_DEVICE_RELEASE):
            errCode = Release();
            break;
        case static_cast<uint32_t>(CameraDeviceInterfaceCode::CAMERA_DEVICE_SET_CALLBACK):
            errCode = HCameraDeviceStub::HandleSetCallback(data);
            break;
        case static_cast<uint32_t>(CameraDeviceInterfaceCode::CAMERA_DEVICE_UPDATE_SETTNGS):
            errCode = HCameraDeviceStub::HandleUpdateSetting(data);
            break;
        case static_cast<uint32_t>(CameraDeviceInterfaceCode::CAMERA_DEVICE_GET_STATUS):
            errCode = HCameraDeviceStub::HandleGetStatus(data, reply);
            break;
        case static_cast<uint32_t>(CameraDeviceInterfaceCode::CAMERA_DEVICE_ENABLED_RESULT):
            errCode = HCameraDeviceStub::HandleEnableResult(data);
            break;
        case static_cast<uint32_t>(CameraDeviceInterfaceCode::CAMERA_DEVICE_GET_ENABLED_RESULT):
            errCode = HCameraDeviceStub::HandleGetEnabledResults(reply);
            break;
        case static_cast<uint32_t>(CameraDeviceInterfaceCode::CAMERA_DEVICE_DISABLED_RESULT):
            errCode = HCameraDeviceStub::HandleDisableResult(data);
            break;
        default:
            MEDIA_ERR_LOG("HCameraDeviceStub request code %{public}d not handled", code);
            errCode = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
            break;
    }

    return errCode;
}

int32_t HCameraDeviceStub::HandleSetCallback(MessageParcel &data)
{
    auto remoteObject = data.ReadRemoteObject();
    CHECK_AND_RETURN_RET_LOG(remoteObject != nullptr, IPC_STUB_INVALID_DATA_ERR,
                             "HCameraDeviceStub HandleSetCallback CameraDeviceServiceCallback is null");

    auto callback = iface_cast<ICameraDeviceServiceCallback>(remoteObject);
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, IPC_STUB_INVALID_DATA_ERR,
                             "HCameraDeviceStub HandleSetCallback callback is null");

    return SetCallback(callback);
}

int32_t HCameraDeviceStub::HandleUpdateSetting(MessageParcel &data)
{
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = nullptr;
    OHOS::Camera::MetadataUtils::DecodeCameraMetadata(data, metadata);

    return UpdateSetting(metadata);
}

int32_t HCameraDeviceStub::HandleGetStatus(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadataIn = nullptr;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadataOut = nullptr;

    OHOS::Camera::MetadataUtils::DecodeCameraMetadata(data, metadataIn);

    int errCode = GetStatus(metadataIn, metadataOut);

    if (!(OHOS::Camera::MetadataUtils::EncodeCameraMetadata(metadataOut, reply))) {
        MEDIA_ERR_LOG("HCameraServiceStub HandleGetStatus write metadata failed");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    return errCode;
}

int32_t HCameraDeviceStub::HandleGetEnabledResults(MessageParcel &reply)
{
    std::vector<int32_t> results;
    int ret = GetEnabledResults(results);
    if (ret != ERR_NONE) {
        MEDIA_ERR_LOG("CameraDeviceStub::HandleGetEnabledResults GetEnabledResults failed : %{public}d", ret);
        return ret;
    }

    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32Vector(results), IPC_STUB_WRITE_PARCEL_ERR,
                             "HCameraDeviceStub::HandleGetEnabledResults write results failed");

    return ret;
}

int32_t HCameraDeviceStub::HandleEnableResult(MessageParcel &data)
{
    std::vector<int32_t> results;
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32Vector(&results), IPC_STUB_INVALID_DATA_ERR,
                             "CameraDeviceStub::HandleEnableResult read results failed");

    int ret = EnableResult(results);
    if (ret != ERR_NONE) {
        MEDIA_ERR_LOG("CameraDeviceStub::HandleEnableResult EnableResult failed : %{public}d", ret);
    }

    return ret;
}

int32_t HCameraDeviceStub::HandleDisableResult(MessageParcel &data)
{
    std::vector<int32_t> results;
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32Vector(&results), IPC_STUB_INVALID_DATA_ERR,
                             "CameraDeviceStub::HandleDisableResult read results failed");

    int ret = DisableResult(results);
    if (ret != ERR_NONE) {
        MEDIA_ERR_LOG("CameraDeviceStub::HandleDisableResult DisableResult failed : %{public}d", ret);
    }

    return ret;
}

int32_t HCameraDeviceStub::HandleOpenSecureCameraResults(MessageParcel &data, MessageParcel &reply)
{
    int32_t errorCode;
    if (data.ReadBool()) {
        uint64_t secureSeqId = 0L;
        errorCode = OpenSecureCamera(&secureSeqId);
        if (errorCode != ERR_NONE) {
            MEDIA_ERR_LOG("CameraDeviceStub::HandleGetEnabledResults GetEnabledResults failed : %{public}d", errorCode);
            return errorCode;
        }
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt64(secureSeqId), IPC_STUB_WRITE_PARCEL_ERR,
            "HCameraDeviceStub::openSecureCamera write results failed");
    } else {
        errorCode = Open();
    }

    return errorCode;
}
} // namespace CameraStandard
} // namespace OHOS
