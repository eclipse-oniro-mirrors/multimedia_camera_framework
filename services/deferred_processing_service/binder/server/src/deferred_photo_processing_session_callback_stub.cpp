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
#include "deferred_photo_processing_session_callback_stub.h"
#include "deferred_processing_service_ipc_interface_code.h"
#include "dp_log.h"
#include "picture_proxy.h"
#include "camera_dynamic_loader.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {

int DeferredPhotoProcessingSessionCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int errCode = -1;

    DP_CHECK_RETURN_RET(data.ReadInterfaceToken() != GetDescriptor(), errCode);
    switch (code) {
        case static_cast<uint32_t>(
            DeferredProcessingServiceCallbackInterfaceCode::DPS_PHOTO_CALLBACK_PROCESS_IMAGE_DONE): {
            errCode = DeferredPhotoProcessingSessionCallbackStub::HandleOnProcessImageDone(data);
            break;
        }
        case static_cast<uint32_t>(DeferredProcessingServiceCallbackInterfaceCode::DPS_PHOTO_CALLBACK_ERROR): {
            errCode = DeferredPhotoProcessingSessionCallbackStub::HandleOnError(data);
            break;
        }
        case static_cast<uint32_t>(DeferredProcessingServiceCallbackInterfaceCode::DPS_PHOTO_CALLBACK_STATE_CHANGED): {
            errCode = DeferredPhotoProcessingSessionCallbackStub::HandleOnStateChanged(data);
            break;
        }
        case static_cast<uint32_t>(
            DeferredProcessingServiceCallbackInterfaceCode::DPS_PHOTO_CALLBACK_LOW_QUALITY_IMAGE): {
            errCode = DeferredPhotoProcessingSessionCallbackStub::HandleProcessLowQualityImage(data);
            break;
        }
        case static_cast<uint32_t>(
            DeferredProcessingServiceCallbackInterfaceCode::DPS_PHOTO_CALLBACK_PROCESS_PICTURE_DONE): {
            errCode = DeferredPhotoProcessingSessionCallbackStub::HandleOnProcessPictureDone(data);
            break;
        }
        default:
            DP_ERR_LOG("DeferredPhotoProcessingSessionCallbackStub request code %{public}d not handled", code);
            errCode = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
            break;
    }
    return errCode;
}

int DeferredPhotoProcessingSessionCallbackStub::HandleOnProcessImageDone(MessageParcel& data)
{
    DP_INFO_LOG("DeferredPhotoProcessingSessionCallbackStub HandleOnProcessImageDone enter");
    std::string imageId = data.ReadString();
    sptr<IPCFileDescriptor> ipcFd = data.ReadObject<IPCFileDescriptor>();
    long bytes = data.ReadInt64();
    uint32_t cloudImageEnhanceFlag = data.ReadUint32();
    int32_t ret = OnProcessImageDone(imageId, ipcFd, bytes, cloudImageEnhanceFlag);
    DP_INFO_LOG("DeferredPhotoProcessingSessionCallbackStub HandleOnProcessImageDone result: %{public}d,"
        "cloudImageEnhanceFlag: %{public}u", ret, cloudImageEnhanceFlag);
    return ret;
}

int DeferredPhotoProcessingSessionCallbackStub::HandleOnError(MessageParcel& data)
{
    DP_INFO_LOG("DeferredPhotoProcessingSessionCallbackStub HandleOnError enter");
    std::string imageId = data.ReadString();
    int32_t errorCode = data.ReadInt32();

    int32_t ret = OnError(imageId, (ErrorCode)errorCode);
    DP_INFO_LOG("DeferredPhotoProcessingSessionCallbackStub HandleOnError result: %{public}d", ret);
    return ret;
}

int DeferredPhotoProcessingSessionCallbackStub::HandleOnStateChanged(MessageParcel& data)
{
    DP_INFO_LOG("DeferredPhotoProcessingSessionCallbackStub HandleOnStateChanged enter");
    int32_t status = data.ReadInt32();

    int32_t ret = OnStateChanged((StatusCode)status);
    DP_INFO_LOG("DeferredPhotoProcessingSessionCallbackStub HandleOnStateChanged result: %{public}d,"
        "status: %{public}d", ret, status);
    return ret;
}

int DeferredPhotoProcessingSessionCallbackStub::HandleProcessLowQualityImage(MessageParcel& data)
{
    DP_INFO_LOG("DeferredPhotoProcessingSessionCallbackStub HandleProcessLowQualityImage enter");
    std::string imageId = data.ReadString();
    std::shared_ptr<PictureIntf> picturePtr = PictureProxy::CreatePictureProxy();
    DP_CHECK_ERROR_RETURN_RET_LOG(picturePtr == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "picturePtr is nullptr");
    DP_DEBUG_LOG("HandleProcessLowQualityImage Picture::Unmarshalling E");
    picturePtr->Unmarshalling(data);
    DP_DEBUG_LOG("HandleProcessLowQualityImage Picture::Unmarshalling X");
    int32_t ret = OnDeliveryLowQualityImage(imageId, picturePtr);
    DP_INFO_LOG("DeferredPhotoProcessingSessionCallbackStub HandleProcessLowQualityImage result: %{public}d", ret);
    return ret;
}

int DeferredPhotoProcessingSessionCallbackStub::HandleOnProcessPictureDone(MessageParcel& data)
{
    DP_INFO_LOG("DeferredPhotoProcessingSessionCallbackStub HandleOnProcessPictureDone enter");
    std::string imageId = data.ReadString();
    uint32_t cloudImageEnhanceFlag = data.ReadUint32();
    std::shared_ptr<PictureIntf> picturePtr = PictureProxy::CreatePictureProxy();
    DP_CHECK_ERROR_RETURN_RET_LOG(picturePtr == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "picturePtr is nullptr");
    DP_DEBUG_LOG("HandleOnProcessPictureDone Picture::Unmarshalling E");
    picturePtr->Unmarshalling(data);
    DP_DEBUG_LOG("HandleOnProcessPictureDone Picture::Unmarshalling X");
    int32_t ret = OnProcessImageDone(imageId, picturePtr, cloudImageEnhanceFlag);
    DP_INFO_LOG("DeferredPhotoProcessingSessionCallbackStub HandleOnProcessPictureDone result: %{public}d,"
        "cloudImageEnhanceFlag: %{public}u", ret, cloudImageEnhanceFlag);
    return ret;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS