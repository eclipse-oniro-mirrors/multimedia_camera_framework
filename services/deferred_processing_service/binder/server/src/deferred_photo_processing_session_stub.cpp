/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "deferred_photo_processing_session_stub.h"
#include "deferred_processing_service_ipc_interface_code.h"
#include "metadata_utils.h"
#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
DeferredPhotoProcessingSessionStub::DeferredPhotoProcessingSessionStub()
{
    DP_DEBUG_LOG("DeferredPhotoProcessingSessionStub Instances create");
}

DeferredPhotoProcessingSessionStub::~DeferredPhotoProcessingSessionStub()
{
    DP_DEBUG_LOG("DeferredPhotoProcessingSessionStub Instances destroy");
}

int DeferredPhotoProcessingSessionStub::OnRemoteRequest(uint32_t code, MessageParcel& data,
    MessageParcel& reply, MessageOption& option)
{
    int errCode = -1;
    DP_CHECK_AND_RETURN_RET(data.ReadInterfaceToken() == GetDescriptor(), errCode);
    
    switch (code) {
        case static_cast<uint32_t>(DeferredProcessingServiceInterfaceCode::DPS_BEGIN_SYNCHRONIZE): {
            errCode = DeferredPhotoProcessingSessionStub::HandleBeginSynchronize(data);
            break;
        }
        case static_cast<uint32_t>(DeferredProcessingServiceInterfaceCode::DPS_END_SYNCHRONIZE):
            errCode = DeferredPhotoProcessingSessionStub::HandleEndSynchronize(data);
            break;
        case static_cast<uint32_t>(DeferredProcessingServiceInterfaceCode::DPS_ADD_IMAGE): {
            errCode = DeferredPhotoProcessingSessionStub::HandleAddImage(data);
            break;
        }
        case static_cast<uint32_t>(DeferredProcessingServiceInterfaceCode::DPS_REMOVE_IMAGE):
            errCode = DeferredPhotoProcessingSessionStub::HandleRemoveImage(data);
            break;
        case static_cast<uint32_t>(DeferredProcessingServiceInterfaceCode::DPS_RESTORE_IMAGE): {
            errCode = DeferredPhotoProcessingSessionStub::HandleRestoreImage(data);
            break;
        }
        case static_cast<uint32_t>(DeferredProcessingServiceInterfaceCode::DPS_PROCESS_IMAGE): {
            errCode = DeferredPhotoProcessingSessionStub::HandleProcessImage(data);
            break;
        }
        case static_cast<uint32_t>(DeferredProcessingServiceInterfaceCode::DPS_CANCEL_PROCESS_IMAGE): {
            errCode = DeferredPhotoProcessingSessionStub::HandleCancelProcessImage(data);
            break;
        }
        default:
            DP_ERR_LOG("DeferredPhotoProcessingSessionStub request code %{public}d not handled", code);
            errCode = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
            break;
    }
    return errCode;
}

int DeferredPhotoProcessingSessionStub::HandleBeginSynchronize(MessageParcel& data)
{
    DP_DEBUG_LOG("DeferredPhotoProcessingSessionStub HandleBeginSynchronize enter");
    int32_t ret = BeginSynchronize();
    DP_INFO_LOG("DeferredPhotoProcessingSessionStub HandleBeginSynchronize result: %{public}d", ret);
    return ret;
}

int DeferredPhotoProcessingSessionStub::HandleEndSynchronize(MessageParcel& data)
{
    DP_DEBUG_LOG("DeferredPhotoProcessingSessionStub HandleEndSynchronize enter");
    int32_t ret = EndSynchronize();
    DP_INFO_LOG("DeferredPhotoProcessingSessionStub HandleEndSynchronize result: %{public}d", ret);
    return ret;
}

int DeferredPhotoProcessingSessionStub::HandleAddImage(MessageParcel& data)
{
    DP_DEBUG_LOG("DeferredPhotoProcessingSessionStub HandleAddImage enter");
    std::string imageId = data.ReadString();
    DpsMetadata metadata;
    metadata.ReadFromParcel(data);
    bool discardable = data.ReadBool();

    int32_t ret = AddImage(imageId, metadata, discardable);
    DP_INFO_LOG("DeferredPhotoProcessingSessionStub HandleAddImage result: %{public}d", ret);
    return ret;
}

int DeferredPhotoProcessingSessionStub::HandleRemoveImage(MessageParcel& data)
{
    DP_DEBUG_LOG("DeferredPhotoProcessingSessionStub HandleRemoveImage enter");
    std::string imageId = data.ReadString();
    bool restorable = data.ReadBool();

    int32_t ret = RemoveImage(imageId, restorable);
    DP_INFO_LOG("DeferredPhotoProcessingSessionStub HandleRemoveImage result: %{public}d", ret);
    return ret;
}

int DeferredPhotoProcessingSessionStub::HandleRestoreImage(MessageParcel& data)
{
    DP_DEBUG_LOG("DeferredPhotoProcessingSessionStub HandleRestoreImage enter");
    std::string imageId = data.ReadString();

    int32_t ret = RestoreImage(imageId);
    DP_INFO_LOG("DeferredPhotoProcessingSessionStub HandleRestoreImage result: %{public}d", ret);
    return ret;
}

int DeferredPhotoProcessingSessionStub::HandleProcessImage(MessageParcel& data)
{
    DP_DEBUG_LOG("DeferredPhotoProcessingSessionStub HandleProcessImage enter");
    std::string appName = data.ReadString();
    std::string imageId = data.ReadString();
    
    int32_t ret = ProcessImage(appName, imageId);
    DP_INFO_LOG("DeferredPhotoProcessingSessionStub HandleProcessImage result: %{public}d", ret);
    return ret;
}

int DeferredPhotoProcessingSessionStub::HandleCancelProcessImage(MessageParcel& data)
{
    DP_DEBUG_LOG("DeferredPhotoProcessingSessionStub HandleCancelProcessImage enter");
    std::string imageId = data.ReadString();
    int32_t ret = CancelProcessImage(imageId);
    DP_INFO_LOG("DeferredPhotoProcessingSessionStub HandleCancelProcessImage result: %{public}d", ret);
    return ret;
}

} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS