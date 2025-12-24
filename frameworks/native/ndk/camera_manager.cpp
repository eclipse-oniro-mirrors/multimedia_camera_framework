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

#include "kits/native/include/camera/camera_manager.h"
#include "impl/camera_manager_impl.h"
#include "camera_log.h"
#include "hilog/log.h"

Camera_ErrorCode OH_CameraManager_RegisterFoldStatusInfoCallback(Camera_Manager* cameraManager,
    OH_CameraManager_OnFoldStatusInfoChange foldStatusInfoCallback)
{
    CHECK_RETURN_RET_ELOG(
        cameraManager == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraManager is null!");
    CHECK_RETURN_RET_ELOG(
        foldStatusInfoCallback == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, callback is null!");
    cameraManager->RegisterFoldStatusCallback(foldStatusInfoCallback);
    return CAMERA_OK;
}

Camera_ErrorCode OH_CameraManager_UnregisterFoldStatusInfoCallback(Camera_Manager* cameraManager,
    OH_CameraManager_OnFoldStatusInfoChange foldStatusInfoCallback)
{
    CHECK_RETURN_RET_ELOG(
        cameraManager == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraManager is null!");
    CHECK_RETURN_RET_ELOG(
        foldStatusInfoCallback == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, callback is null!");
    cameraManager->UnregisterFoldStatusCallback(foldStatusInfoCallback);
    return CAMERA_OK;
}

#ifdef __cplusplus
extern "C" {
#endif

Camera_ErrorCode OH_Camera_GetCameraManager(Camera_Manager** cameraManager)
{
    CHECK_RETURN_RET_ELOG(
        cameraManager == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraManager is null!");
    *cameraManager = new Camera_Manager();
    return CAMERA_OK;
}

Camera_ErrorCode OH_Camera_DeleteCameraManager(Camera_Manager* cameraManager)
{
    CHECK_RETURN_RET_ELOG(
        cameraManager == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraManager is null!");
    delete cameraManager;
    return CAMERA_OK;
}

Camera_ErrorCode OH_CameraManager_RegisterCallback(Camera_Manager* cameraManager, CameraManager_Callbacks* callback)
{
    CHECK_RETURN_RET_ELOG(
        cameraManager == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraManager is null!");
    CHECK_RETURN_RET_ELOG(callback == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, callback is null!");
    CHECK_RETURN_RET_ELOG(callback->onCameraStatus == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, callback onCameraStatus is null!");

    cameraManager->RegisterCallback(callback);
    return CAMERA_OK;
}

Camera_ErrorCode OH_CameraManager_UnregisterCallback(Camera_Manager* cameraManager, CameraManager_Callbacks* callback)
{
    CHECK_RETURN_RET_ELOG(
        cameraManager == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraManager is null!");
    CHECK_RETURN_RET_ELOG(callback == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, callback is null!");
    CHECK_RETURN_RET_ELOG(callback->onCameraStatus == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, callback onCameraStatus is null!");

    cameraManager->UnregisterCallback(callback);
    return CAMERA_OK;
}

Camera_ErrorCode OH_CameraManager_RegisterTorchStatusCallback(Camera_Manager* cameraManager,
    OH_CameraManager_TorchStatusCallback torchStatusCallback)
{
    CHECK_RETURN_RET_ELOG(
        cameraManager == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraManager is null!");
    CHECK_RETURN_RET_ELOG(
        torchStatusCallback == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, callback is null!");
    cameraManager->RegisterTorchStatusCallback(torchStatusCallback);
    return CAMERA_OK;
}

Camera_ErrorCode OH_CameraManager_UnregisterTorchStatusCallback(Camera_Manager* cameraManager,
    OH_CameraManager_TorchStatusCallback torchStatusCallback)
{
    CHECK_RETURN_RET_ELOG(
        cameraManager == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraManager is null!");
    CHECK_RETURN_RET_ELOG(
        torchStatusCallback == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, callback is null!");
    cameraManager->UnregisterTorchStatusCallback(torchStatusCallback);
    return CAMERA_OK;
}

Camera_ErrorCode OH_CameraManager_GetSupportedCameras(Camera_Manager* cameraManager,
    Camera_Device** cameras, uint32_t* size)
{
    CHECK_RETURN_RET_ELOG(
        cameraManager == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraManager is null!");
    CHECK_RETURN_RET_ELOG(cameras == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameras is null!");
    CHECK_RETURN_RET_ELOG(size == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, size is null!");

    return cameraManager->GetSupportedCameras(cameras, size);
}

Camera_ErrorCode OH_CameraManager_DeleteSupportedCameras(Camera_Manager* cameraManager,
    Camera_Device* cameras, uint32_t size)
{
    CHECK_RETURN_RET_ELOG(
        cameraManager == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraManager is null!");
    CHECK_RETURN_RET_ELOG(cameras == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameras is null!");
    uint32_t sizeMax = 0;
    cameraManager->GetSupportedCameras(&cameras, &sizeMax);
    CHECK_RETURN_RET_ELOG(size > sizeMax, CAMERA_INVALID_ARGUMENT, "Invalid argument,size is Invalid");

    return cameraManager->DeleteSupportedCameras(cameras, size);
}

Camera_ErrorCode OH_CameraManager_GetSupportedCameraOutputCapability(Camera_Manager* cameraManager,
    const Camera_Device* camera, Camera_OutputCapability** cameraOutputCapability)
{
    CHECK_RETURN_RET_ELOG(
        cameraManager == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraManager is null!");
    CHECK_RETURN_RET_ELOG(cameraOutputCapability == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, cameraOutputCapability is null!");
    CHECK_RETURN_RET_ELOG(camera == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument,camera is null!");
    CHECK_RETURN_RET_ELOG(camera->cameraId == nullptr, CAMERA_INVALID_ARGUMENT, "lnvalid argument,cameraId is null!");

    return cameraManager->GetSupportedCameraOutputCapability(camera, cameraOutputCapability);
}

Camera_ErrorCode OH_CameraManager_GetSupportedCameraOutputCapabilityWithSceneMode(Camera_Manager* cameraManager,
    const Camera_Device* camera, Camera_SceneMode sceneMode, Camera_OutputCapability** cameraOutputCapability)
{
    MEDIA_DEBUG_LOG("OH_CameraManager_GetSupportedCameraOutputCapabilityWithSceneMode is called.");
    CHECK_RETURN_RET_ELOG(
        cameraManager == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraManager is null!");
    CHECK_RETURN_RET_ELOG(camera == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, camera is null!");
    CHECK_RETURN_RET_ELOG(cameraOutputCapability == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, cameraOutputCapability is null!");
    CHECK_RETURN_RET_ELOG(camera->cameraId == nullptr, CAMERA_INVALID_ARGUMENT, "lnvalid argument,cameraId is null!");

    return cameraManager->GetSupportedCameraOutputCapabilityWithSceneMode(camera, sceneMode, cameraOutputCapability);
}

Camera_ErrorCode OH_CameraManager_GetSupportedFullCameraOutputCapabilityWithSceneMode(Camera_Manager* cameraManager,
    const Camera_Device* camera, Camera_SceneMode sceneMode, Camera_OutputCapability** cameraOutputCapability)
{
    MEDIA_DEBUG_LOG("OH_CameraManager_GetSupportedFullCameraOutputCapabilityWithSceneMode is called.");
    CHECK_RETURN_RET_ELOG(cameraManager == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, cameraManager is null!");
    CHECK_RETURN_RET_ELOG(camera == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, camera is null!");
    CHECK_RETURN_RET_ELOG(cameraOutputCapability == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, cameraOutputCapability is null!");
    CHECK_RETURN_RET_ELOG(camera->cameraId == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, cameraId is null!");

    return cameraManager->GetSupportedFullCameraOutputCapabilityWithSceneMode(camera, sceneMode,
        cameraOutputCapability);
}

Camera_ErrorCode OH_CameraManager_DeleteSupportedCameraOutputCapability(Camera_Manager* cameraManager,
    Camera_OutputCapability* cameraOutputCapability)
{
    CHECK_RETURN_RET_ELOG(
        cameraManager == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraManager is null!");
    CHECK_RETURN_RET_ELOG(cameraOutputCapability == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, cameraOutputCapability is null!");

    return cameraManager->DeleteSupportedCameraOutputCapability(cameraOutputCapability);
}

Camera_ErrorCode OH_CameraManager_IsCameraMuted(Camera_Manager* cameraManager, bool* isCameraMuted)
{
    MEDIA_DEBUG_LOG("OH_CameraManager_IsCameraMuted is called");
    CHECK_RETURN_RET_ELOG(
        cameraManager == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraManager is null!");

    return cameraManager->IsCameraMuted(isCameraMuted);
}

Camera_ErrorCode OH_CameraManager_CreateCaptureSession(Camera_Manager* cameraManager,
    Camera_CaptureSession** captureSession)
{
    CHECK_RETURN_RET_ELOG(
        cameraManager == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraManager is null!");
    CHECK_RETURN_RET_ELOG(
        captureSession == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, captureSession is null!");

    return cameraManager->CreateCaptureSession(captureSession);
}

Camera_ErrorCode OH_CameraManager_CreateCameraInput(Camera_Manager* cameraManager,
    const Camera_Device* camera, Camera_Input** cameraInput)
{
    CHECK_RETURN_RET_ELOG(
        cameraManager == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraManager is null!");
    CHECK_RETURN_RET_ELOG(camera == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraDevice is null!");
    CHECK_RETURN_RET_ELOG(cameraInput == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraInput is null!");

    return cameraManager->CreateCameraInput(camera, cameraInput);
}

Camera_ErrorCode OH_CameraManager_CreateCameraInput_WithPositionAndType(Camera_Manager* cameraManager,
    Camera_Position position, Camera_Type type, Camera_Input** cameraInput)
{
    MEDIA_DEBUG_LOG("OH_CameraManager_CreateCameraInput_WithPositionAndType is called");
    CHECK_RETURN_RET_ELOG(
        cameraManager == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraManager is null!");
    CHECK_RETURN_RET_ELOG(cameraInput == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraInput is null!");
    return cameraManager->CreateCameraInputWithPositionAndType(position, type, cameraInput);
}

Camera_ErrorCode OH_CameraManager_CreatePreviewOutput(Camera_Manager* cameraManager, const Camera_Profile* profile,
    const char* surfaceId, Camera_PreviewOutput** previewOutput)
{
    CHECK_RETURN_RET_ELOG(
        cameraManager == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraManager is null!");
    CHECK_RETURN_RET_ELOG(profile == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, profile is null!");
    CHECK_RETURN_RET_ELOG(surfaceId == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, surfaceId is null!");
    CHECK_RETURN_RET_ELOG(
        previewOutput == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, previewOutput is null!");

    return cameraManager->CreatePreviewOutput(profile, surfaceId, previewOutput);
}

Camera_ErrorCode OH_CameraManager_CreatePreviewOutputUsedInPreconfig(Camera_Manager* cameraManager,
    const char* surfaceId, Camera_PreviewOutput** previewOutput)
{
    MEDIA_DEBUG_LOG("OH_CameraManager_CreatePreviewOutputUsedInPreconfig is called.");
    CHECK_RETURN_RET_ELOG(
        cameraManager == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraManager is null!");
    CHECK_RETURN_RET_ELOG(surfaceId == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, surfaceId is null!");
    CHECK_RETURN_RET_ELOG(
        previewOutput == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, previewOutput is null!");

    return cameraManager->CreatePreviewOutputUsedInPreconfig(surfaceId, previewOutput);
}

Camera_ErrorCode OH_CameraManager_CreatePhotoOutput(Camera_Manager* cameraManager, const Camera_Profile* profile,
    const char* surfaceId, Camera_PhotoOutput** photoOutput)
{
    MEDIA_DEBUG_LOG("OH_CameraManager_CreatePhotoOutput is called");
    CHECK_RETURN_RET_ELOG(
        cameraManager == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraManager is null!");
    CHECK_RETURN_RET_ELOG(profile == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, profile is null!");
    CHECK_RETURN_RET_ELOG(surfaceId == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, surfaceId is null!");
    CHECK_RETURN_RET_ELOG(photoOutput == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, photoOutput is null!");

    return cameraManager->CreatePhotoOutput(profile, surfaceId, photoOutput);
}

Camera_ErrorCode OH_CameraManager_CreatePhotoOutputWithoutSurface(Camera_Manager* cameraManager,
    const Camera_Profile* profile, Camera_PhotoOutput** photoOutput)
{
    MEDIA_DEBUG_LOG("OH_CameraManager_CreatePhotoOutputWithoutSurface is called");
    CHECK_RETURN_RET_ELOG(
        cameraManager == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraManager is null!");
    CHECK_RETURN_RET_ELOG(profile == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, profile is null!");
    CHECK_RETURN_RET_ELOG(photoOutput == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, photoOutput is null!");

    return cameraManager->CreatePhotoOutputWithoutSurface(profile, photoOutput);
}

Camera_ErrorCode OH_CameraManager_CreatePhotoOutputUsedInPreconfig(Camera_Manager* cameraManager,
    const char* surfaceId, Camera_PhotoOutput** photoOutput)
{
    MEDIA_DEBUG_LOG("OH_CameraManager_CreatePhotoOutputUsedInPreconfig is called.");
    CHECK_RETURN_RET_ELOG(
        cameraManager == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraManager is null!");
    CHECK_RETURN_RET_ELOG(surfaceId == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, surfaceId is null!");
    CHECK_RETURN_RET_ELOG(photoOutput == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, photoOutput is null!");

    return cameraManager->CreatePhotoOutputUsedInPreconfig(surfaceId, photoOutput);
}

Camera_ErrorCode OH_CameraManager_CreateVideoOutput(Camera_Manager* cameraManager, const Camera_VideoProfile* profile,
    const char* surfaceId, Camera_VideoOutput** videoOutput)
{
    CHECK_RETURN_RET_ELOG(
        cameraManager == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraManager is null!");
    CHECK_RETURN_RET_ELOG(profile == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, profile is null!");
    CHECK_RETURN_RET_ELOG(surfaceId == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, surfaceId is null!");
    CHECK_RETURN_RET_ELOG(videoOutput == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, videoOutput is null!");

    return cameraManager->CreateVideoOutput(profile, surfaceId, videoOutput);
}

Camera_ErrorCode OH_CameraManager_CreateVideoOutputUsedInPreconfig(Camera_Manager* cameraManager,
    const char* surfaceId, Camera_VideoOutput** videoOutput)
{
    MEDIA_DEBUG_LOG("OH_CameraManager_CreateVideoOutputUsedInPreconfig is called.");
    CHECK_RETURN_RET_ELOG(
        cameraManager == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraManager is null!");
    CHECK_RETURN_RET_ELOG(surfaceId == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, surfaceId is null!");
    CHECK_RETURN_RET_ELOG(videoOutput == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, videoOutput is null!");

    return cameraManager->CreateVideoOutputUsedInPreconfig(surfaceId, videoOutput);
}

Camera_ErrorCode OH_CameraManager_CreateMetadataOutput(Camera_Manager* cameraManager,
    const Camera_MetadataObjectType* type, Camera_MetadataOutput** metadataOutput)
{
    CHECK_RETURN_RET_ELOG(
        cameraManager == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraManager is null!");
    CHECK_RETURN_RET_ELOG(type == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, type is null!");
    CHECK_RETURN_RET_ELOG(
        metadataOutput == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, metadataOutput is null!");

    return cameraManager->CreateMetadataOutput(type, metadataOutput);
}

Camera_ErrorCode OH_CameraDevice_GetCameraOrientation(Camera_Device* camera, uint32_t* orientation)
{
    CHECK_RETURN_RET_ELOG(camera == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraDevice is null!");
    CHECK_RETURN_RET_ELOG(orientation == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, orientation is null!");
    return Camera_Manager::GetCameraOrientation(camera, orientation);
}

Camera_ErrorCode OH_CameraDevice_GetHostDeviceName(Camera_Device* camera, char** hostDeviceName)
{
    CHECK_RETURN_RET_ELOG(camera == nullptr, CAMERA_INVALID_ARGUMENT, "lnvalid argument, cameraDevice is null!");
    CHECK_RETURN_RET_ELOG(
        hostDeviceName == nullptr, CAMERA_INVALID_ARGUMENT, "lnvalid argument, hostDeviceName is null!");
    return Camera_Manager::GetHostDeviceName(camera, hostDeviceName);
}

Camera_ErrorCode OH_CameraDevice_GetHostDeviceType(Camera_Device* camera, Camera_HostDeviceType* hostDeviceType)
{
    CHECK_RETURN_RET_ELOG(camera == nullptr, CAMERA_INVALID_ARGUMENT, "lnvalid argument, cameraDevice is null!");
    CHECK_RETURN_RET_ELOG(
        hostDeviceType == nullptr, CAMERA_INVALID_ARGUMENT, "lnvalid argument, hostDeviceType is null!");
    return Camera_Manager::GetHostDeviceType(camera, hostDeviceType);
}

Camera_ErrorCode OH_CameraManager_GetSupportedSceneModes(Camera_Device* camera,
    Camera_SceneMode** sceneModes, uint32_t* size)
{
    MEDIA_DEBUG_LOG("OH_CameraManager_GetSupportedSceneModes is called.");
    CHECK_RETURN_RET_ELOG(camera == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, camera is null!");
    CHECK_RETURN_RET_ELOG(sceneModes == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, sceneModes is null!");
    CHECK_RETURN_RET_ELOG(size == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, size is null!");

    return Camera_Manager::GetSupportedSceneModes(camera, sceneModes, size);
}

Camera_ErrorCode OH_CameraManager_DeleteSceneModes(Camera_Manager* cameraManager, Camera_SceneMode* sceneModes)
{
    MEDIA_DEBUG_LOG("OH_CameraManager_DeleteSceneModes is called.");
    CHECK_RETURN_RET_ELOG(
        cameraManager == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraManager is null!");
    CHECK_RETURN_RET_ELOG(sceneModes == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, sceneModes is null!");

    return cameraManager->DeleteSceneModes(sceneModes);
}

/**
 * @since 12
 * @version 1.0
 */
Camera_ErrorCode OH_CameraManager_IsTorchSupported(Camera_Manager* cameraManager,
    bool* isTorchSupported)
{
    CHECK_RETURN_RET_ELOG(
        cameraManager == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraManager is null!");
    CHECK_RETURN_RET_ELOG(
        isTorchSupported == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, isTorchSupported is null!");

    return cameraManager->IsTorchSupported(isTorchSupported);
}

/**
 * @since 12
 * @version 1.0
 */
Camera_ErrorCode OH_CameraManager_IsTorchSupportedByTorchMode(Camera_Manager* cameraManager,
    Camera_TorchMode torchMode, bool* isTorchSupported)
{
    CHECK_RETURN_RET_ELOG(cameraManager == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraManager is null");
    CHECK_RETURN_RET_ELOG(
        isTorchSupported == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, isTorchSupported is null");

    return cameraManager->IsTorchSupportedByTorchMode(torchMode, isTorchSupported);
}

/**
 * @since 12
 * @version 1.0
 */
Camera_ErrorCode OH_CameraManager_SetTorchMode(Camera_Manager* cameraManager, Camera_TorchMode torchMode)
{
    CHECK_RETURN_RET_ELOG(
        cameraManager == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraManager is null!");

    return cameraManager->SetTorchMode(torchMode);
}

/**
 * @since 16
 * @version 1.0
 */
Camera_ErrorCode OH_CameraManager_GetCameraDevice(Camera_Manager *cameraManager, Camera_Position position,
                                                  Camera_Type type, Camera_Device *camera)
{
    CHECK_RETURN_RET_ELOG(
        cameraManager == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraManager is null!");
    return cameraManager->GetCameraDevice(position, type, camera);
}

/**
 * @since 23
 * @version 1.0
 */
Camera_ErrorCode OH_CameraManager_GetCameraDevices(Camera_Manager* cameraManager,
    Camera_DeviceQueryInfo* deviceQueryInfo, uint32_t* cameraSize, Camera_Device** cameras)
{
    CHECK_RETURN_RET_ELOG(cameraManager == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, cameraManager is null!");
    CHECK_RETURN_RET_ELOG(deviceQueryInfo == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, deviceQueryInfo is null!");
    CHECK_RETURN_RET_ELOG(cameraSize == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, cameraSize is null!");
    CHECK_RETURN_RET_ELOG(cameras == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, cameras is null!");

    return cameraManager->GetCameraDevices(deviceQueryInfo, cameraSize, cameras);
}

Camera_ErrorCode OH_CameraManager_DeleteCameraDevices(Camera_Manager* cameraManager, Camera_Device* cameras)
{
    CHECK_RETURN_RET_ELOG(cameraManager == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, cameraManager is null!");
    CHECK_RETURN_RET_ELOG(cameras == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, cameras is null!");

    return cameraManager->DeleteCameraDevices(cameras);
}

/**
 * @since 16
 * @version 1.0
 */
Camera_ErrorCode OH_CameraManager_GetCameraConcurrentInfos(Camera_Manager *cameraManager, const Camera_Device *camera,
                                                           uint32_t deviceSize,
                                                           Camera_ConcurrentInfo **cameraConcurrentInfo,
                                                           uint32_t *infoSize)
{
    CHECK_RETURN_RET_ELOG(
        cameraManager == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraManager is null!");
    CHECK_RETURN_RET_ELOG(camera == nullptr, CAMERA_INVALID_ARGUMENT, "lnvalid argument, cameraDevice is null!");
    return cameraManager->GetCameraConcurrentInfos(camera, deviceSize, cameraConcurrentInfo, infoSize);
}
#ifdef __cplusplus
}
#endif