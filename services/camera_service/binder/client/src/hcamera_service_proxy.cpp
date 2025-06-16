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

#include "hcamera_service_proxy.h"
#include "camera_log.h"
#include "metadata_utils.h"
#include "camera_service_ipc_interface_code.h"
#include <cstdint>

namespace OHOS {
namespace CameraStandard {
HCameraProxy::HCameraProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<ICameraBroker>(impl) { }

int32_t HCameraProxy::NotifyCloseCamera(std::string cameraId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(cameraId);
    option.SetFlags(option.TF_SYNC);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceDHInterfaceCode::CAMERA_SERVICE_NOTIFY_CLOSE_CAMERA), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HCameraServiceProxy notifyCloseCamera failed, error: %{public}d", error);
    MEDIA_DEBUG_LOG("HCameraServiceProxy notifyCloseCamera");
    return error;
}

int32_t HCameraProxy::NotifyMuteCamera(bool muteMode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteBool(muteMode);
    option.SetFlags(option.TF_SYNC);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceDHInterfaceCode::CAMERA_SERVICE_NOTIFY_MUTE_CAMERA), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HCameraServiceProxy NotifyMuteCamera failed, error: %{public}d", error);
    MEDIA_DEBUG_LOG("HCameraServiceProxy NotifyMuteCamera");
    return error;
}

HCameraServiceProxy::HCameraServiceProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<ICameraService>(impl) { }

int32_t HCameraServiceProxy::GetCameras(std::vector<std::string> &cameraIds,
    std::vector<std::shared_ptr<Camera::CameraMetadata>> &cameraAbilityList)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    constexpr int32_t MAX_SUPPORTED_CAMERAS = 100;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_GET_CAMERAS), data, reply, option);
    CHECK_ERROR_RETURN_RET_LOG(error != ERR_NONE, error,
        "HCameraServiceProxy GetCameras failed, error: %{public}d", error);

    reply.ReadStringVector(&cameraIds);
    int32_t count = reply.ReadInt32();
    CHECK_ERROR_RETURN_RET_LOG((cameraIds.size() != static_cast<uint32_t>(count)) || (count > MAX_SUPPORTED_CAMERAS),
        IPC_PROXY_ERR, "HCameraServiceProxy GetCameras Malformed camera count value");

    std::shared_ptr<Camera::CameraMetadata> cameraAbility;
    for (int i = 0; i < count; i++) {
        Camera::MetadataUtils::DecodeCameraMetadata(reply, cameraAbility);
        cameraAbilityList.emplace_back(cameraAbility);
    }

    return error;
}

int32_t HCameraServiceProxy::GetCameraIds(std::vector<std::string> &cameraIds)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    constexpr int32_t MAX_SUPPORTED_CAMERAS = 100;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_GET_CAMERA_IDS), data, reply, option);
    CHECK_ERROR_RETURN_RET_LOG(error != ERR_NONE, error,
        "HCameraServiceProxy GetCameraIds failed, error: %{public}d", error);

    reply.ReadStringVector(&cameraIds);
    int32_t count = reply.ReadInt32();
    CHECK_ERROR_RETURN_RET_LOG((cameraIds.size() != static_cast<uint32_t>(count)) || (count > MAX_SUPPORTED_CAMERAS),
        IPC_PROXY_ERR, "HCameraServiceProxy GetCameraIds Malformed camera count: %{public}d", count);

    return error;
}

int32_t HCameraServiceProxy::GetCameraAbility(std::string &cameraId,
    std::shared_ptr<Camera::CameraMetadata> &cameraAbility)
{
    CAMERA_SYNC_TRACE;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(cameraId);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_GET_CAMERA_ABILITY), data, reply, option);
    CHECK_ERROR_RETURN_RET_LOG(error != ERR_NONE, error,
        "HCameraServiceProxy GetCameraAbility failed, error: %{public}d", error);

    Camera::MetadataUtils::DecodeCameraMetadata(reply, cameraAbility);
    return error;
}

int32_t HCameraServiceProxy::CreateCameraDevice(std::string cameraId, sptr<ICameraDeviceService> &device)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(cameraId);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_CREATE_DEVICE), data, reply, option);
    CHECK_ERROR_RETURN_RET_LOG(error != ERR_NONE, error,
        "HCameraServiceProxy CreateCameraDevice failed, error: %{public}d", error);

    auto remoteObject = reply.ReadRemoteObject();
    CHECK_ERROR_RETURN_RET_LOG(remoteObject == nullptr, IPC_PROXY_ERR,
        "HCameraServiceProxy CreateCameraDevice CameraDevice is null");
        device = iface_cast<ICameraDeviceService>(remoteObject);

    return error;
}

int32_t HCameraServiceProxy::SetCameraCallback(sptr<ICameraServiceCallback>& callback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    CHECK_ERROR_RETURN_RET_LOG(callback == nullptr, IPC_PROXY_ERR,
        "HCameraServiceProxy SetCameraCallback callback is null");

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteRemoteObject(callback->AsObject());

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_SET_CAMERA_CALLBACK), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HCameraServiceProxy SetCameraCallback failed, error: %{public}d", error);

    return error;
}

int32_t HCameraServiceProxy::UnSetCameraCallback()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_UNSET_CAMERA_CALLBACK), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceProxy UnSetCameraCallback failed, error: %{public}d", error);
    }
    return error;
}

int32_t HCameraServiceProxy::SetMuteCallback(sptr<ICameraMuteServiceCallback>& callback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    CHECK_ERROR_RETURN_RET_LOG(callback == nullptr, IPC_PROXY_ERR,
        "HCameraServiceProxy SetMuteCallback callback is null");

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteRemoteObject(callback->AsObject());

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_SET_MUTE_CALLBACK), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HCameraServiceProxy SetMuteCallback failed, error: %{public}d", error);

    return error;
}

int32_t HCameraServiceProxy::UnSetMuteCallback()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_UNSET_MUTE_CALLBACK), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceProxy UnSetMuteCallback failed, error: %{public}d", error);
    }
    return error;
}

int32_t HCameraServiceProxy::SetTorchCallback(sptr<ITorchServiceCallback>& callback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    CHECK_ERROR_RETURN_RET_LOG(callback == nullptr, IPC_PROXY_ERR,
        "HCameraServiceProxy SetTorchCallback callback is null");
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteRemoteObject(callback->AsObject());

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_SET_TORCH_CALLBACK), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HCameraServiceProxy SetTorchCallback failed, error: %{public}d", error);
    return error;
}

int32_t HCameraServiceProxy::UnSetTorchCallback()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_UNSET_TORCH_CALLBACK), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceProxy UnSetTorchCallback failed, error: %{public}d", error);
    }
    return error;
}

int32_t HCameraServiceProxy::SetFoldStatusCallback(sptr<IFoldServiceCallback>& callback, bool isInnerCallback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    CHECK_ERROR_RETURN_RET_LOG(callback == nullptr, IPC_PROXY_ERR,
        "HCameraServiceProxy SetFoldStatusCallback callback is null");

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteRemoteObject(callback->AsObject());
    data.WriteBool(isInnerCallback);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_SET_FOLD_CALLBACK), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE,
        "HCameraServiceProxy SetFoldStatusCallback failed, error: %{public}d", error);

    return error;
}

int32_t HCameraServiceProxy::UnSetFoldStatusCallback()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_UNSET_FOLD_CALLBACK), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceProxy UnSetFoldStatusCallback failed, error: %{public}d", error);
    }
    return error;
}

int32_t HCameraServiceProxy::CreateCaptureSession(sptr<ICaptureSession>& session, int32_t operationMode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteInt32(operationMode);
    MEDIA_INFO_LOG("HCameraServiceProxy::CreateCaptureSession opMode_= %{public}d", operationMode);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_CREATE_CAPTURE_SESSION), data, reply, option);
    CHECK_ERROR_RETURN_RET_LOG(error != ERR_NONE, error,
        "HCameraServiceProxy CreateCaptureSession failed, error: %{public}d", error);

    auto remoteObject = reply.ReadRemoteObject();
    CHECK_ERROR_RETURN_RET_LOG(remoteObject == nullptr, IPC_PROXY_ERR,
        "HCameraServiceProxy CreateCaptureSession CaptureSession is null");
        session = iface_cast<ICaptureSession>(remoteObject);

    return error;
}

int32_t HCameraServiceProxy::CreateDeferredPhotoProcessingSession(int32_t userId,
    sptr<DeferredProcessing::IDeferredPhotoProcessingSessionCallback>& callback,
    sptr<DeferredProcessing::IDeferredPhotoProcessingSession>& session)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    CHECK_ERROR_RETURN_RET_LOG(callback == nullptr, IPC_PROXY_ERR,
        "HCameraServiceProxy CreateDeferredPhotoProcessingSession callback is null");

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteInt32(userId);
    data.WriteRemoteObject(callback->AsObject());

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_CREATE_DEFERRED_PHOTO_PROCESSING_SESSION),
        data, reply, option);
    CHECK_ERROR_RETURN_RET_LOG(error != ERR_NONE, error,
        "HCameraServiceProxy CreateDeferredPhotoProcessingSession failed, error: %{public}d", error);

    auto remoteObject = reply.ReadRemoteObject();
    CHECK_ERROR_RETURN_RET_LOG(remoteObject == nullptr, IPC_PROXY_ERR,
        "HCameraServiceProxy CreateDeferredPhotoProcessingSession session is null");
        session = iface_cast<DeferredProcessing::IDeferredPhotoProcessingSession>(remoteObject);

    return error;
}

int32_t HCameraServiceProxy::CreateDeferredVideoProcessingSession(int32_t userId,
    sptr<DeferredProcessing::IDeferredVideoProcessingSessionCallback>& callback,
    sptr<DeferredProcessing::IDeferredVideoProcessingSession>& session)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    CHECK_ERROR_RETURN_RET_LOG(callback == nullptr, IPC_PROXY_ERR,
        "HCameraServiceProxy CreateDeferredVideoProcessingSession callback is null");

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteInt32(userId);
    data.WriteRemoteObject(callback->AsObject());

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_CREATE_DEFERRED_VIDEO_PROCESSING_SESSION),
        data, reply, option);
    CHECK_ERROR_RETURN_RET_LOG(error != ERR_NONE, error,
        "HCameraServiceProxy CreateDeferredVideoProcessingSession failed, error: %{public}d", error);

    auto remoteObject = reply.ReadRemoteObject();
    CHECK_ERROR_RETURN_RET_LOG(remoteObject == nullptr, IPC_PROXY_ERR,
        "HCameraServiceProxy CreateDeferredVideoProcessingSession session is null");
    session = iface_cast<DeferredProcessing::IDeferredVideoProcessingSession>(remoteObject);
    return error;
}

int32_t HCameraServiceProxy::CreatePhotoOutput(const sptr<OHOS::IBufferProducer> &producer, int32_t format,
                                               int32_t width, int32_t height,
                                               sptr<IStreamCapture> &photoOutput)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    CHECK_ERROR_RETURN_RET_LOG(producer == nullptr, IPC_PROXY_ERR,
        "HCameraServiceProxy CreatePhotoOutput producer is null");

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteRemoteObject(producer->AsObject());
    data.WriteInt32(format);
    data.WriteInt32(width);
    data.WriteInt32(height);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_CREATE_PHOTO_OUTPUT), data, reply, option);
    CHECK_ERROR_RETURN_RET_LOG(error != ERR_NONE, error,
        "HCameraServiceProxy CreatePhotoOutput failed, error: %{public}d", error);

    auto remoteObject = reply.ReadRemoteObject();
    CHECK_ERROR_RETURN_RET_LOG(remoteObject == nullptr, IPC_PROXY_ERR,
        "HCameraServiceProxy CreatePhotoOutput photoOutput is null");
        photoOutput = iface_cast<IStreamCapture>(remoteObject);

    return error;
}

int32_t HCameraServiceProxy::CreatePreviewOutput(const sptr<OHOS::IBufferProducer> &producer, int32_t format,
                                                 int32_t width, int32_t height,
                                                 sptr<IStreamRepeat>& previewOutput)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    CHECK_ERROR_RETURN_RET_LOG((producer == nullptr) || (width == 0) || (height == 0), IPC_PROXY_ERR,
        "HCameraServiceProxy CreatePreviewOutput producer is null or invalid size is set");

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteRemoteObject(producer->AsObject());
    data.WriteInt32(format);
    data.WriteInt32(width);
    data.WriteInt32(height);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_CREATE_PREVIEW_OUTPUT), data, reply, option);
    CHECK_ERROR_RETURN_RET_LOG(error != ERR_NONE, error,
        "HCameraServiceProxy CreatePreviewOutput failed, error: %{public}d", error);
    auto remoteObject = reply.ReadRemoteObject();
    CHECK_ERROR_RETURN_RET_LOG(remoteObject == nullptr, IPC_PROXY_ERR,
        "HCameraServiceProxy CreatePreviewOutput previewOutput is null");
        previewOutput = iface_cast<IStreamRepeat>(remoteObject);

    return error;
}

int32_t HCameraServiceProxy::CreateDeferredPreviewOutput(int32_t format, int32_t width, int32_t height,
                                                         sptr<IStreamRepeat> &previewOutput)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    CHECK_ERROR_RETURN_RET_LOG((width == 0) || (height == 0), IPC_PROXY_ERR,
        "HCameraServiceProxy CreateDeferredPreviewOutput producer is null or invalid size is set");

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteInt32(format);
    data.WriteInt32(width);
    data.WriteInt32(height);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_CREATE_DEFERRED_PREVIEW_OUTPUT),
        data, reply, option);
    CHECK_ERROR_RETURN_RET_LOG(error != ERR_NONE, error,
        "HCameraServiceProxy CreateDeferredPreviewOutput failed, error: %{public}d", error);
    auto remoteObject = reply.ReadRemoteObject();
    CHECK_ERROR_RETURN_RET_LOG(remoteObject == nullptr, IPC_PROXY_ERR,
        "HCameraServiceProxy CreateDeferredPreviewOutput previewOutput is null");
        previewOutput = iface_cast<IStreamRepeat>(remoteObject);

    return error;
}

int32_t HCameraServiceProxy::CreateDepthDataOutput(const sptr<OHOS::IBufferProducer> &producer, int32_t format,
                                                   int32_t width, int32_t height,
                                                   sptr<IStreamDepthData>& depthDataOutput)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    CHECK_ERROR_RETURN_RET_LOG((producer == nullptr) || (width == 0) || (height == 0), IPC_PROXY_ERR,
        "HCameraServiceProxy CreateDepthDataOutput producer is null or invalid size is set");

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteRemoteObject(producer->AsObject());
    data.WriteInt32(format);
    data.WriteInt32(width);
    data.WriteInt32(height);

    int error = Remote()->SendRequest(static_cast<uint32_t>(
        CameraServiceInterfaceCode::CAMERA_SERVICE_CREATE_DEPTH_DATA_OUTPUT), data, reply, option);
    CHECK_ERROR_RETURN_RET_LOG(error != ERR_NONE, error,
        "HCameraServiceProxy CreateDepthDataOutput failed, error: %{public}d", error);
    auto remoteObject = reply.ReadRemoteObject();
    if (remoteObject != nullptr) {
        depthDataOutput = iface_cast<IStreamDepthData>(remoteObject);
    } else {
        MEDIA_ERR_LOG("HCameraServiceProxy CreateDepthDataOutput depthDataOutput is null");
        error = IPC_PROXY_ERR;
    }
    return error;
}

int32_t HCameraServiceProxy::CreateMetadataOutput(const sptr<OHOS::IBufferProducer> &producer, int32_t format,
                                                  std::vector<int32_t> metadataTypes,
                                                  sptr<IStreamMetadata>& metadataOutput)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    CHECK_ERROR_RETURN_RET_LOG(producer == nullptr, IPC_PROXY_ERR,
        "HCameraServiceProxy CreateMetadataOutput producer is null");

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteRemoteObject(producer->AsObject());
    data.WriteInt32(format);
    data.WriteInt32Vector(metadataTypes);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_CREATE_METADATA_OUTPUT), data, reply, option);
    CHECK_ERROR_RETURN_RET_LOG(error != ERR_NONE, error,
        "HCameraServiceProxy CreateMetadataOutput failed, error: %{public}d", error);

    auto remoteObject = reply.ReadRemoteObject();
    CHECK_ERROR_RETURN_RET_LOG(remoteObject == nullptr, IPC_PROXY_ERR,
        "HCameraServiceProxy CreateMetadataOutput metadataOutput is null");
        metadataOutput = iface_cast<IStreamMetadata>(remoteObject);

    return error;
}

int32_t HCameraServiceProxy::CreateVideoOutput(const sptr<OHOS::IBufferProducer> &producer, int32_t format,
                                               int32_t width, int32_t height,
                                               sptr<IStreamRepeat>& videoOutput)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    CHECK_ERROR_RETURN_RET_LOG(producer == nullptr, IPC_PROXY_ERR,
        "HCameraServiceProxy CreateVideoOutput producer is null");

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteRemoteObject(producer->AsObject());
    data.WriteInt32(format);
    data.WriteInt32(width);
    data.WriteInt32(height);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_CREATE_VIDEO_OUTPUT), data, reply, option);
    CHECK_ERROR_RETURN_RET_LOG(error != ERR_NONE, error,
        "HCameraServiceProxy::CreateVideoOutput failed, error: %{public}d", error);

    auto remoteObject = reply.ReadRemoteObject();
    CHECK_ERROR_RETURN_RET_LOG(remoteObject == nullptr, IPC_PROXY_ERR,
        "HCameraServiceProxy CreateVideoOutput videoOutput is null");
        videoOutput = iface_cast<IStreamRepeat>(remoteObject);

    return error;
}

int32_t HCameraServiceProxy::SetListenerObject(const sptr<IRemoteObject> &object)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    (void)data.WriteRemoteObject(object);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_SET_LISTENER_OBJ), data, reply, option);
    CHECK_ERROR_RETURN_RET_LOG(error != ERR_NONE, IPC_PROXY_ERR,
        "HCameraServiceProxy::SetListenerObject Set listener obj failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t HCameraServiceProxy::MuteCamera(bool muteMode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    (void)data.WriteBool(muteMode);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_MUTE_CAMERA), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HCameraServiceProxy::MuteCamera failed, error: %{public}d", error);
    return error;
}

int32_t HCameraServiceProxy::MuteCameraPersist(PolicyType policyType, bool muteMode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    (void)data.WriteInt32(static_cast<int32_t>(policyType));
    (void)data.WriteBool(muteMode);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_MUTE_CAMERA_PERSIST), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE,
        "HCameraServiceProxy::MuteCameraPersist failed, error: %{public}d", error);

    return error;
}

int32_t HCameraServiceProxy::PrelaunchCamera()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_PRE_LAUNCH_CAMERA), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HCameraServiceProxy::PrelaunchCamera failed, error: %{public}d", error);
    return error;
}

int32_t HCameraServiceProxy::ResetRssPriority()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_RESET_RSS_PRIORITY), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HCameraServiceProxy::ResetRssPriority failed, error: %{public}d", error);
    return error;
}

int32_t HCameraServiceProxy::SetPrelaunchConfig(std::string cameraId, RestoreParamTypeOhos restoreParamType,
    int activeTime, EffectParam effectParam)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(cameraId);
    data.WriteUint32(restoreParamType);
    data.WriteUint32(activeTime);
    data.WriteUint32(effectParam.skinSmoothLevel);
    data.WriteUint32(effectParam.faceSlender);
    data.WriteUint32(effectParam.skinTone);
    int32_t error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_SET_PRE_LAUNCH_CAMERA), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE,
        "HCameraServiceProxy::SetPrelaunchConfig failed, error: %{public}d", error);
    return error;
}

int32_t HCameraServiceProxy::PreSwitchCamera(const std::string cameraId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(cameraId);
    int32_t error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_PRE_SWITCH_CAMERA), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HCameraServiceProxy::PreSwitchCamera failed, error: %{public}d", error);

    return error;
}

int32_t HCameraServiceProxy::IsTorchSupported(bool &isTorchSupported)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_IS_TORCH_SUPPORTED), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceProxy::IsTorchSupported failed, error: %{public}d", error);
        return error;
    }

    isTorchSupported = reply.ReadBool();
    MEDIA_DEBUG_LOG("HCameraServiceProxy IsTorchSupported Read isTorchSupported is %{public}d", isTorchSupported);
    return error;
}

int32_t HCameraServiceProxy::IsCameraMuteSupported(bool &isCameraMuteSupported)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_IS_MUTE_SUPPORTED), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceProxy::IsCameraMuteSupported failed, error: %{public}d", error);
        return error;
    }

    isCameraMuteSupported = reply.ReadBool();
    MEDIA_DEBUG_LOG("HCameraServiceProxy IsCameraMuteSupported Read isCameraMuteSupported is %{public}d",
                    isCameraMuteSupported);
    return error;
}

int32_t HCameraServiceProxy::IsCameraMuted(bool &muteMode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    (void)data.WriteBool(muteMode);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_IS_CAMERA_MUTED), data, reply, option);
    CHECK_ERROR_RETURN_RET_LOG(error != ERR_NONE, error,
        "HCameraServiceProxy::IsCameraMuted Set listener obj failed, error: %{public}d", error);

    muteMode = reply.ReadBool();
    MEDIA_DEBUG_LOG("HCameraServiceProxy IsCameraMuted Read muteMode is %{public}d", muteMode);
    return error;
}

int32_t HCameraServiceProxy::GetTorchStatus(int32_t &status)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_GET_TORCH_STATUS), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceProxy::GetTorchStatus failed, error: %{public}d", error);
        return error;
    }

    status = reply.ReadInt32();
    MEDIA_DEBUG_LOG("HCameraServiceProxy::GetTorchStatus Read status is %{public}d", status);

    return error;
}

int32_t HCameraServiceProxy::SetTorchLevel(float level)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteFloat(level);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_SET_TORCH_LEVEL),
        data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HCameraServiceProxy::SetTorchLevel failed, error: %{public}d", error);
    return error;
}

int32_t HCameraServiceProxy::AllowOpenByOHSide(std::string cameraId, int32_t state, bool &canOpenCamera)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(cameraId);
    data.WriteInt32(state);
    (void)data.WriteBool(canOpenCamera);

    int32_t error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceDHInterfaceCode::CAMERA_SERVICE_ALLOW_OPEN_BY_OHSIDE), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE,
        "HCameraServiceProxy::AllowOpenByOHSide failed, error: %{public}d", error);

    canOpenCamera = reply.ReadBool();
    MEDIA_DEBUG_LOG("HCameraServiceProxy::AllowOpenByOHSide read canOpenCamera is %{public}d", canOpenCamera);
    return error;
}

int32_t HCameraServiceProxy::NotifyCameraState(std::string cameraId, int32_t state)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(cameraId);
    data.WriteInt32(state);
    option.SetFlags(option.TF_ASYNC);

    int32_t error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceDHInterfaceCode::CAMERA_SERVICE_NOTIFY_CAMERA_STATE), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE,
        "HCameraServiceProxy::NotifyCameraState failed, error: %{public}d", error);

    return error;
}

int32_t HCameraServiceProxy::SetPeerCallback(sptr<ICameraBroker>& callback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    CHECK_ERROR_RETURN_RET_LOG(callback == nullptr, IPC_PROXY_ERR,
        "HCameraServiceProxy SetCallback callback is null");

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteRemoteObject(callback->AsObject());

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceDHInterfaceCode::CAMERA_SERVICE_SET_PEER_CALLBACK), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HCameraServiceProxy::SetCallback failed, error: %{public}d", error);

    return error;
}

int32_t HCameraServiceProxy::UnsetPeerCallback()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceDHInterfaceCode::CAMERA_SERVICE_UNSET_PEER_CALLBACK), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE,
        "HCameraServiceProxy::UnsetPeerCallback failed, error: %{public}d", error);

    return error;
}

int32_t HCameraServiceProxy::DestroyStubObj()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_DESTROY_STUB_OBJ), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HCameraServiceProxy::DestroyStubObj failed, error: %{public}d", error);

    return error;
}

int32_t HCameraServiceProxy::ProxyForFreeze(const std::set<int32_t>& pidList, bool isProxy)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteInt32(pidList.size());
    for (auto it = pidList.begin(); it != pidList.end(); it++) {
        data.WriteInt32(*it);
    }
    MEDIA_DEBUG_LOG("isProxy value: %{public}d", isProxy);
    data.WriteBool(isProxy);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_PROXY_FOR_FREEZE), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HCameraServiceProxy::ProxyForFreeze failed, error: %{public}d", error);

    return error;
}
int32_t HCameraServiceProxy::ResetAllFreezeStatus()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_RESET_ALL_FREEZE_STATUS),
        data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE,
        "HCameraServiceProxy::ResetAllFreezeStatus failed, error: %{public}d", error);
    return error;
}
int32_t HCameraServiceProxy::GetDmDeviceInfo(std::vector<std::string> &deviceInfos)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_GET_DM_DEVICE_INFOS), data, reply, option);
    CHECK_ERROR_RETURN_RET_LOG(error != ERR_NONE, error,
        "HCameraServiceProxy GetDmDeviceInfo failed, error: %{public}d", error);
    reply.ReadStringVector(&deviceInfos);

    return error;
}
int32_t HCameraServiceProxy::GetCameraOutputStatus(int32_t pid, int32_t &status)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteInt32(pid);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_GET_CAMERA_OUTPUT_STATUS),
        data, reply, option);
    CHECK_ERROR_RETURN_RET_LOG(error != ERR_NONE, error,
        "GetCameraOutputStatus, error: %{public}d", error);
    status = reply.ReadInt32();
    return error;
}

int32_t HCameraServiceProxy::RequireMemorySize(int32_t memSize)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteInt32(memSize);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_REQUIRE_MEMORY_SIZE),
        data, reply, option);
    CHECK_ERROR_RETURN_RET_LOG(error != ERR_NONE, error, "RequireMemorySize, error: %{public}d", error);
    return error;
}

int32_t HCameraServiceProxy::GetIdforCameraConcurrentType(int32_t cameraPosition, std::string &cameraId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteInt32(cameraPosition);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_GETID_FOR_CONCURRENT),
        data, reply, option);
    CHECK_ERROR_RETURN_RET_LOG(error != ERR_NONE, error, "GetIdforCameraConcurrentType, error: %{public}d", error);
    cameraId = reply.ReadString();
    return error;
}

int32_t HCameraServiceProxy::GetConcurrentCameraAbility(std::string& cameraId,
    std::shared_ptr<OHOS::Camera::CameraMetadata>& cameraAbility)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(cameraId);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_GET_CONCURRENT_CAMERA_ABILITY),
        data, reply, option);
    CHECK_ERROR_RETURN_RET_LOG(error != ERR_NONE, error,
        "HCameraServiceProxy GetConcurrentCameraAbility failed, error: %{public}d", error);

    Camera::MetadataUtils::DecodeCameraMetadata(reply, cameraAbility);
    return error;
}

int32_t HCameraServiceProxy::CheckWhiteList(bool &isInWhiteList)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    (void)data.WriteBool(isInWhiteList);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_CHECK_WHITE_LIST), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceProxy::CheckWhiteList failed, error: %{public}d", error);
        return error;
    }

    isInWhiteList = reply.ReadBool();
    MEDIA_DEBUG_LOG("HCameraServiceProxy CheckWhiteList Read muteMode is %{public}d", isInWhiteList);

    return error;
}
} // namespace CameraStandard
} // namespace OHOS
