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

#ifndef OHOS_CAMERA_ICAMERA_SERVICE_H
#define OHOS_CAMERA_ICAMERA_SERVICE_H

#include "camera_metadata_info.h"
#include "icamera_service_callback.h"
#include "icamera_device_service.h"
#include "icapture_session.h"
#include "iremote_broker.h"
#include "istream_capture.h"
#include "istream_metadata.h"
#include "istream_repeat.h"
#include "surface.h"
#include "ideferred_photo_processing_session.h"
#include "ideferred_photo_processing_session_callback.h"

namespace OHOS {
namespace CameraStandard {
enum RestoreParamTypeOhos {
    NO_NEED_RESTORE_PARAM_OHOS = 0,
    PERSISTENT_DEFAULT_PARAM_OHOS = 1,
    TRANSIENT_ACTIVE_PARAM_OHOS = 2,
};

struct EffectParam {
    int skinSmoothLevel;
    int faceSlender;
    int skinTone;
};

class ICameraBroker : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Anco.Service.Camera");

    virtual int32_t NotifyCloseCamera(std::string cameraId) = 0;
};

class ICameraService : public IRemoteBroker {
public:
    virtual int32_t CreateCameraDevice(std::string cameraId, sptr<ICameraDeviceService>& device) = 0;

    virtual int32_t SetCallback(sptr<ICameraServiceCallback>& callback) = 0;

    virtual int32_t SetMuteCallback(sptr<ICameraMuteServiceCallback>& callback) = 0;

    virtual int32_t SetTorchCallback(sptr<ITorchServiceCallback>& callback) = 0;

    virtual int32_t GetCameras(std::vector<std::string> &cameraIds,
        std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>> &cameraAbilityList) = 0;

    virtual int32_t GetCameraIds(std::vector<std::string>& cameraIds) = 0;

    virtual int32_t GetCameraAbility(std::string& cameraId,
        std::shared_ptr<OHOS::Camera::CameraMetadata>& cameraAbility) = 0;

    virtual int32_t CreateCaptureSession(sptr<ICaptureSession> &session, int32_t operationMode = 0) = 0;

    virtual int32_t CreateDeferredPhotoProcessingSession(int32_t userId,
        sptr<DeferredProcessing::IDeferredPhotoProcessingSessionCallback>& callback,
        sptr<DeferredProcessing::IDeferredPhotoProcessingSession>& session) = 0;

    virtual int32_t CreatePhotoOutput(const sptr<OHOS::IBufferProducer> &producer, int32_t format,
                                      int32_t width, int32_t height, sptr<IStreamCapture> &photoOutput) = 0;

    virtual int32_t CreatePreviewOutput(const sptr<OHOS::IBufferProducer> &producer, int32_t format,
                                        int32_t width, int32_t height, sptr<IStreamRepeat> &previewOutput) = 0;

    virtual int32_t CreateDeferredPreviewOutput(int32_t format, int32_t width, int32_t height,
                                                sptr<IStreamRepeat> &previewOutput) = 0;

    virtual int32_t CreateMetadataOutput(const sptr<OHOS::IBufferProducer> &producer, int32_t format,
                                         sptr<IStreamMetadata> &metadataOutput) = 0;

    virtual int32_t CreateVideoOutput(const sptr<OHOS::IBufferProducer> &producer, int32_t format,
                                      int32_t width, int32_t height, sptr<IStreamRepeat> &videoOutput) = 0;

    virtual int32_t SetListenerObject(const sptr<IRemoteObject> &object) = 0;

    virtual int32_t MuteCamera(bool muteMode) = 0;

    virtual int32_t PrelaunchCamera() = 0;

    virtual int32_t PreSwitchCamera(const std::string cameraId) = 0;

    virtual int32_t SetPrelaunchConfig(std::string cameraId, RestoreParamTypeOhos restoreParamType, int activeTime,
        EffectParam effectParam) = 0;

    virtual int32_t IsCameraMuted(bool &muteMode) = 0;

    virtual int32_t SetTorchLevel(float level) = 0;

    virtual int32_t AllowOpenByOHSide(std::string cameraId, int32_t state, bool &canOpenCamera) = 0;

    virtual int32_t NotifyCameraState(std::string cameraId, int32_t state) = 0;

    virtual int32_t SetPeerCallback(sptr<ICameraBroker>& callback) = 0;

    DECLARE_INTERFACE_DESCRIPTOR(u"ICameraService");
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_ICAMERA_SERVICE_H
