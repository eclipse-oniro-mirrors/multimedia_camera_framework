/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef CAMERA_FFI_H
#define CAMERA_FFI_H

#include <cstdint>
#include "camera_input_impl.h"
#include "camera_log.h"
#include "camera_manager_impl.h"
#include "camera_output_impl.h"
#include "camera_session_impl.h"
#include "camera_utils.h"
#include "capture_session.h"
#include "cj_common_ffi.h"
#include "ffi_remote_data.h"
#include "metadata_output_impl.h"
#include "photo_output_impl.h"
#include "preview_output_impl.h"
#include "video_output_impl.h"

namespace OHOS {
namespace CameraStandard {

extern "C" {
// CameraManager
FFI_EXPORT int64_t FfiCameraManagerConstructor();
FFI_EXPORT CArrI32 FfiCameraManagerGetSupportedSceneModes(int64_t id, CJCameraDevice cameraDevice, int32_t *errCode);
FFI_EXPORT CArrCJCameraDevice FfiCameraManagerGetSupportedCameras(int64_t id, int32_t *errCode);
FFI_EXPORT CJCameraOutputCapability FfiCameraManagerGetSupportedOutputCapability(int64_t id,
                                                                                 CJCameraDevice cameraDevice,
                                                                                 int32_t modeType, int32_t *errCode);
FFI_EXPORT bool FfiCameraManagerIsCameraMuted();
FFI_EXPORT int64_t FfiCameraManagerCreateCameraInputWithCameraDevice(int64_t id, CJCameraDevice cameraDevice,
                                                                     int32_t *errCode);
FFI_EXPORT int64_t FfiCameraManagerCreateCameraInputWithCameraDeviceInfo(int64_t id, int32_t cameraPosition,
                                                                         int32_t cameraType, int32_t *errCode);
FFI_EXPORT int64_t FfiCameraManagerCreatePreviewOutput(CJProfile profile, const char *surfaceId, int32_t *errCode);
FFI_EXPORT int64_t FfiCameraManagerCreatePreviewOutputWithoutProfile(const char *surfaceId, int32_t *errCode);
FFI_EXPORT int64_t FfiCameraManagerCreatePhotoOutput(int32_t *errCode);
FFI_EXPORT int64_t FfiCameraManagerCreatePhotoOutputWithProfile(CJProfile profile, int32_t *errCode);
FFI_EXPORT int64_t FfiCameraManagerCreateVideoOutput(CJVideoProfile profile, char *surfaceId, int32_t *errCode);
FFI_EXPORT int64_t FfiCameraManagerCreateVideoOutputWithOutProfile(char *surfaceId, int32_t *errCode);
FFI_EXPORT int64_t FfiCameraManagerCreateMetadataOutput(CArrI32 metadataObjectTypes, int32_t *errCode);
FFI_EXPORT int64_t FfiCameraManagerCreateSession(int32_t mode, int32_t *errCode);
FFI_EXPORT bool FfiCameraManagerIsTorchSupported();
FFI_EXPORT bool FfiCameraManagerIsTorchModeSupported(int32_t modeType);
FFI_EXPORT int32_t FfiCameraManagerGetTorchMode();
FFI_EXPORT int32_t FfiCameraManagerSetTorchMode(int32_t modeType);
FFI_EXPORT int32_t FfiCameraManagerOnCameraStatusChanged(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraManagerOffCameraStatusChanged(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraManagerOffAllCameraStatusChanged(int64_t id);
FFI_EXPORT int32_t FfiCameraManagerOnFoldStatusChanged(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraManagerOffFoldStatusChanged(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraManagerOffAllFoldStatusChanged(int64_t id);
FFI_EXPORT int32_t FfiCameraManagerOnTorchStatusChange(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraManagerOffTorchStatusChange(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraManagerOffAllTorchStatusChange(int64_t id);

// CameraInput
FFI_EXPORT int32_t FfiCameraInputOpen(int64_t id);
FFI_EXPORT int32_t FfiCameraInputOpenWithIsEnableSecureCamera(int64_t id, bool isEnableSecureCamera,
                                                              uint64_t *secureSeqId);
FFI_EXPORT int32_t FfiCameraInputClose(int64_t id);
FFI_EXPORT int32_t FfiCameraInputOnError(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraInputOffError(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraInputOffAllError(int64_t id);

// PreviewOutput
FFI_EXPORT CArrFrameRateRange FfiCameraPreviewOutputGetSupportedFrameRates(int64_t id, int32_t *errCode);
FFI_EXPORT int32_t FfiCameraPreviewOutputSetFrameRate(int64_t id, int32_t min, int32_t max);
FFI_EXPORT FrameRateRange FfiCameraPreviewOutputGetActiveFrameRate(int64_t id, int32_t *errCode);
FFI_EXPORT CJProfile FfiCameraPreviewOutputGetActiveProfile(int64_t id, int32_t *errCode);
FFI_EXPORT int32_t FfiCameraPreviewOutputGetPreviewRotation(int64_t id, int32_t value, int32_t *errCode);
FFI_EXPORT int32_t FfiCameraPreviewOutputSetPreviewRotation(int64_t id, int32_t imageRotation, bool isDisplayLocked);
FFI_EXPORT int32_t FfiCameraPreviewOutputOnFrameStart(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraPreviewOutputOnFrameEnd(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraPreviewOutputOnError(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraPreviewOutputOffFrameStart(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraPreviewOutputOffFrameEnd(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraPreviewOutputOffError(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraPreviewOutputOffAllFrameStart(int64_t id);
FFI_EXPORT int32_t FfiCameraPreviewOutputOffAllFrameEnd(int64_t id);
FFI_EXPORT int32_t FfiCameraPreviewOutputOffAllError(int64_t id);
FFI_EXPORT int32_t FfiCameraPreviewOutputRelease(int64_t id);

// PhotoOutput
FFI_EXPORT int32_t FfiCameraPhotoOutputCapture(int64_t id);
FFI_EXPORT int32_t FfiCameraPhotoOutputCaptureWithSetting(int64_t id, CJPhotoCaptureSetting setting);
FFI_EXPORT bool FfiCameraPhotoOutputIsMovingPhotoSupported(int64_t id, int32_t *errCode);
FFI_EXPORT int32_t FfiCameraPhotoOutputEnableMovingPhoto(int64_t id, bool enabled);
FFI_EXPORT bool FfiCameraPhotoOutputIsMirrorSupported(int64_t id, int32_t *errCode);
FFI_EXPORT int32_t FfiCameraPhotoOutputEnableMirror(int64_t id, bool isMirror);
FFI_EXPORT int32_t FfiCameraPhotoOutputSetMovingPhotoVideoCodecType(int64_t id, int32_t codecType);
FFI_EXPORT CJProfile FfiCameraPhotoOutputGetActiveProfile(int64_t id, int32_t *errCode);
FFI_EXPORT int32_t FfiCameraPhotoOutputGetPhotoRotation(int64_t id, int32_t deviceDegree, int32_t *errCode);
FFI_EXPORT int32_t FfiCameraPhotoOutputOnCaptureStartWithInfo(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraPhotoOutputOffCaptureStartWithInfo(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraPhotoOutputOffAllCaptureStartWithInfo(int64_t id);
FFI_EXPORT int32_t FfiCameraPhotoOutputOnFrameShutter(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraPhotoOutputOffFrameShutter(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraPhotoOutputOffAllFrameShutter(int64_t id);
FFI_EXPORT int32_t FfiCameraPhotoOutputOnCaptureEnd(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraPhotoOutputOffCaptureEnd(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraPhotoOutputOffAllCaptureEnd(int64_t id);
FFI_EXPORT int32_t FfiCameraPhotoOutputOnFrameShutterEnd(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraPhotoOutputOffFrameShutterEnd(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraPhotoOutputOffAllFrameShutterEnd(int64_t id);
FFI_EXPORT int32_t FfiCameraPhotoOutputOnCaptureReady(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraPhotoOutputOffCaptureReady(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraPhotoOutputOffAllCaptureReady(int64_t id);
FFI_EXPORT int32_t FfiCameraPhotoOutputOnEstimatedCaptureDuration(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraPhotoOutputOffEstimatedCaptureDuration(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraPhotoOutputOffAllEstimatedCaptureDuration(int64_t id);
FFI_EXPORT int32_t FfiCameraPhotoOutputOnError(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraPhotoOutputOffError(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraPhotoOutputOffAllError(int64_t id);
FFI_EXPORT int32_t FfiCameraPhotoOutputOnPhotoAvailable(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraPhotoOutputOffPhotoAvailable(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraPhotoOutputOffAllPhotoAvailable(int64_t id);
FFI_EXPORT int32_t FfiCameraPhotoOutputRelease(int64_t id);

// videooutput
FFI_EXPORT int32_t FfiCameraVideoOutputStart(int64_t id);
FFI_EXPORT int32_t FfiCameraVideoOutputStop(int64_t id);
FFI_EXPORT CArrFrameRateRange FfiCameraVideoOutputGetSupportedFrameRates(int64_t id, int32_t *errCode);
FFI_EXPORT int32_t FfiCameraVideoOutputSetFrameRate(int64_t id, int32_t minFps, int32_t maxFps);
FFI_EXPORT FrameRateRange FfiCameraVideoOutputGetActiveFrameRate(int64_t id, int32_t *errCode);
FFI_EXPORT CJVideoProfile FfiCameraVideoOutputGetActiveProfile(int64_t id, int32_t *errCode);
FFI_EXPORT int32_t FfiCameraVideoOutputGetVideoRotation(int64_t id, int32_t imageRotation, int32_t *errCode);
FFI_EXPORT int32_t FfiCameraVideoOutputOnFrameStart(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraVideoOutputOffFrameStart(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraVideoOutputOffAllFrameStart(int64_t id);
FFI_EXPORT int32_t FfiCameraVideoOutputOnFrameEnd(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraVideoOutputOffFrameEnd(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraVideoOutputOffAllFrameEnd(int64_t id);
FFI_EXPORT int32_t FfiCameraVideoOutputOnError(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraVideoOutputOffError(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraVideoOutputOffAllError(int64_t id);
FFI_EXPORT int32_t FfiCameraVideoOutputRelease(int64_t id);

// MetadataOutput
FFI_EXPORT int32_t FfiCameraMetadataOutputStart(int64_t id);
FFI_EXPORT int32_t FfiCameraMetadataOutputStop(int64_t id);
FFI_EXPORT int32_t FfiCameraMetadataOutputOnMetadataObjectsAvailable(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraMetadataOutputOffMetadataObjectsAvailable(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraMetadataOutputOffAllMetadataObjectsAvailable(int64_t id);
FFI_EXPORT int32_t FfiCameraMetadataOutputOnError(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraMetadataOutputOffError(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiCameraMetadataOutputOffAllError(int64_t id);
FFI_EXPORT int32_t FfiCameraMetadataOutputRelease(int64_t id);

// Session
FFI_EXPORT int32_t FfiCameraSessionBeginConfig(int64_t id);
FFI_EXPORT int32_t FfiCameraSessionCommitConfig(int64_t id);
FFI_EXPORT bool FfiCameraSessionCanAddInput(int64_t id, int64_t cameraInputId, int32_t *errCode);
FFI_EXPORT int32_t FfiCameraSessionAddInput(int64_t id, int64_t cameraInputId);
FFI_EXPORT int32_t FfiCameraSessionRemoveInput(int64_t id, int64_t cameraInputId);
FFI_EXPORT bool FfiCameraSessionCanAddOutput(int64_t id, int64_t cameraOutputId, int32_t outputType, int32_t *errCode);
FFI_EXPORT int32_t FfiCameraSessionAddOutput(int64_t id, int64_t cameraOutputId, int32_t outputType);
FFI_EXPORT int32_t FfiCameraSessionRemoveOutput(int64_t id, int64_t cameraOutputId, int32_t outputType);
FFI_EXPORT int32_t FfiCameraSessionStart(int64_t id);
FFI_EXPORT int32_t FfiCameraSessionStop(int64_t id);
FFI_EXPORT int32_t FfiCameraSessionRelease(int64_t id);
FFI_EXPORT bool FfiCameraSessionCanPreconfig(int64_t id, int32_t preconfigType, int32_t preconfigRatio,
                                             int32_t *errCode);
FFI_EXPORT void FfiCameraSessionPreconfig(int64_t id, int32_t preconfigType, int32_t preconfigRatio, int32_t *errCode);
FFI_EXPORT void FfiCameraSessionAddSecureOutput(int64_t id, int64_t cameraOutputId, int32_t *errCode);
FFI_EXPORT void FfiCameraOnError(int64_t id, int64_t callbackId, int32_t *errCode);
FFI_EXPORT void FfiCameraOffError(int64_t id, int64_t callbackId, int32_t *errCode);
FFI_EXPORT void FfiCameraOffAllError(int64_t id, int32_t *errCode);
FFI_EXPORT void FfiCameraOnFocusStateChange(int64_t id, int64_t callbackId, int32_t *errCode);
FFI_EXPORT void FfiCameraOffFocusStateChange(int64_t id, int64_t callbackId, int32_t *errCode);
FFI_EXPORT void FfiCameraOffAllFocusStateChange(int64_t id, int32_t *errCode);
FFI_EXPORT void FfiCameraOnSmoothZoomInfoAvailable(int64_t id, int64_t callbackId, int32_t *errCode);
FFI_EXPORT void FfiCameraOffSmoothZoomInfoAvailable(int64_t id, int64_t callbackId, int32_t *errCode);
FFI_EXPORT void FfiCameraOffAllSmoothZoomInfoAvailable(int64_t id, int32_t *errCode);

// abilities
// auto exposure
FFI_EXPORT bool FfiCameraAutoExposureIsExposureModeSupported(int64_t id, int32_t aeMode, int32_t *errCode);
FFI_EXPORT CArrFloat32 FfiCameraAutoExposureGetExposureBiasRange(int64_t id, int32_t *errCode);
FFI_EXPORT int32_t FfiCameraAutoExposureGetExposureMode(int64_t id, int32_t *errCode);
FFI_EXPORT void FfiCameraAutoExposureSetExposureMode(int64_t id, int32_t aeMode, int32_t *errCode);
FFI_EXPORT CameraPoint FfiCameraAutoExposureGetMeteringPoint(int64_t id, int32_t *errCode);
FFI_EXPORT void FfiCameraAutoExposureSetMeteringPoint(int64_t id, CameraPoint point, int32_t *errCode);
FFI_EXPORT void FfiCameraAutoExposureSetExposureBias(int64_t id, float exposureBias, int32_t *errCode);
FFI_EXPORT float FfiCameraAutoExposureGetExposureValue(int64_t id, int32_t *errCode);

// color management
FFI_EXPORT CArrI32 FfiCameraColorManagementGetSupportedColorSpaces(int64_t id, int32_t *errCode);
FFI_EXPORT void FfiCameraColorManagementSetColorSpace(int64_t id, int32_t colorSpace, int32_t *errCode);
FFI_EXPORT int32_t FfiCameraColorManagementGetActiveColorSpace(int64_t id, int32_t *errCode);

// flash
FFI_EXPORT bool FfiCameraFlashQueryFlashModeSupported(int64_t id, int32_t focusMode, int32_t *errCode);
FFI_EXPORT bool FfiCameraFlashQueryHasFlash(int64_t id, int32_t *errCode);
FFI_EXPORT int32_t FfiCameraFlashGetFlashMode(int64_t id, int32_t *errCode);
FFI_EXPORT void FfiCameraFlashSetFlashMode(int64_t id, int32_t flashMode, int32_t *errCode);

// focus
FFI_EXPORT bool FfiCameraFocusIsFocusModeSupported(int64_t id, int32_t afMode, int32_t *errCode);
FFI_EXPORT void FfiCameraFocusSetFocusMode(int64_t id, int32_t afMode, int32_t *errCode);
FFI_EXPORT int32_t FfiCameraFocusGetFocusMode(int64_t id, int32_t *errCode);
FFI_EXPORT void FfiCameraFocusSetFocusPoint(int64_t id, CameraPoint point, int32_t *errCode);
FFI_EXPORT CameraPoint FfiCameraFocusGetFocusPoint(int64_t id, int32_t *errCode);
FFI_EXPORT float FfiCameraFocusGetFocalLength(int64_t id, int32_t *errCode);

// stabilization
FFI_EXPORT bool FfiCameraStabilizationIsVideoStabilizationModeSupported(int64_t id, int32_t vsMode, int32_t *errCode);
FFI_EXPORT int32_t FfiCameraStabilizationGetActiveVideoStabilizationMode(int64_t id, int32_t *errCode);
FFI_EXPORT void FfiCameraStabilizationSetVideoStabilizationMode(int64_t id, int32_t vsMode, int32_t *errCode);

// zoom
FFI_EXPORT CArrFloat32 FfiCameraZoomGetZoomRatioRange(int64_t id, int32_t *errCode);
FFI_EXPORT void FfiCameraZoomSetZoomRatio(int64_t id, float zoomRatio, int32_t *errCode);
FFI_EXPORT float FfiCameraZoomGetZoomRatio(int64_t id, int32_t *errCode);
FFI_EXPORT void FfiCameraZoomSetSmoothZoom(int64_t id, float targetRatio, int32_t mode, int32_t *errCode);
}
} // namespace CameraStandard
} // namespace OHOS
#endif