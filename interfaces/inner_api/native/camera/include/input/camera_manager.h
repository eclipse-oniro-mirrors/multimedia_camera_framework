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

#ifndef OHOS_CAMERA_CAMERA_MANAGER_H
#define OHOS_CAMERA_CAMERA_MANAGER_H

#include <iostream>
#include <refbase.h>
#include <vector>
#include "input/camera_input.h"
#include "input/camera_info.h"
#include "input/camera_device.h"
#include "hcamera_service_proxy.h"
#include "icamera_device_service.h"
#include "session/capture_session.h"
#include "output/camera_output_capability.h"
#include "output/metadata_output.h"
#include "output/photo_output.h"
#include "output/video_output.h"
#include "output/preview_output.h"
#include "hcamera_listener_stub.h"
#include "input/camera_death_recipient.h"
#include "hcamera_service_callback_stub.h"

namespace OHOS {
namespace CameraStandard {
enum CameraDeviceStatus {
    CAMERA_DEVICE_STATUS_UNAVAILABLE = 0,
    CAMERA_DEVICE_STATUS_AVAILABLE
};

enum FlashlightStatus {
    FLASHLIGHT_STATUS_OFF = 0,
    FLASHLIGHT_STATUS_ON,
    FLASHLIGHT_STATUS_UNAVAILABLE
};

struct CameraStatusInfo {
    sptr<CameraInfo> cameraInfo;
    sptr<CameraDevice> cameraDevice;
    CameraStatus cameraStatus;
    ~CameraStatusInfo()
    {
        cameraInfo = nullptr;
        cameraDevice = nullptr;
    }
};

class CameraManagerCallback {
public:
    CameraManagerCallback() = default;
    virtual ~CameraManagerCallback() = default;
    virtual void OnCameraStatusChanged(const CameraStatusInfo &cameraStatusInfo) const = 0;
    virtual void OnFlashlightStatusChanged(const std::string &cameraID, const FlashStatus flashStatus) const = 0;
};

class CameraMuteListener {
public:
    CameraMuteListener() = default;
    virtual ~CameraMuteListener() = default;
    virtual void OnCameraMute(bool muteMode) const = 0;
};

class CameraManager;
class CameraMuteServiceCallback : public HCameraMuteServiceCallbackStub {
public:
    sptr<CameraManager> camMngr_ = nullptr;
    CameraMuteServiceCallback() : camMngr_(nullptr) {
    }

    explicit CameraMuteServiceCallback(const sptr<CameraManager>& cameraManager) : camMngr_(cameraManager) {
    }

    ~CameraMuteServiceCallback()
    {
        camMngr_ = nullptr;
    }

    int32_t OnCameraMute(bool muteMode) override;
};

class CameraManager : public RefBase {
public:
    ~CameraManager();
    /**
    * @brief Get camera manager instance.
    *
    * @return Returns pointer to camera manager instance.
    */
    static sptr<CameraManager> &GetInstance();

    /**
    * @brief Get all available cameras.
    *
    * @return Returns vector of cameraDevice of available camera.
    */
    std::vector<sptr<CameraDevice>> GetSupportedCameras();

    /**
    * @brief Get output capaility of the given camera.
    *
    * @param Camera device for which capability need to be fetched.
    * @return Returns vector of cameraDevice of available camera.
    */
    sptr<CameraOutputCapability> GetSupportedOutputCapability(sptr<CameraDevice>& camera);

    /**
    * @brief Create camera input instance with provided camera position and type.
    *
    * @param The cameraDevice for which input has to be created.
    * @return Returns pointer to camera input instance.
    */
    sptr<CameraInput> CreateCameraInput(CameraPosition position, CameraType cameraType);

    /**
    * @brief Create camera input instance with provided camera position and type.
    *
    * @param The cameraDevice for which input has to be created.
    * @param Returns pointer to camera input instance.
    * @return Returns error code.
    */
    int CreateCameraInput(CameraPosition position, CameraType cameraType, sptr<CameraInput> *pCameraInput);

    /**
    * @brief Create camera input instance.
    *
    * @param The cameraDevice for which input has to be created.
    * @return Returns pointer to camera input instance.
    */
    sptr<CameraInput> CreateCameraInput(sptr<CameraDevice> &camera);

    /**
    * @brief Create camera input instance.
    *
    * @param The cameraDevice for which input has to be created.
    * @param Returns pointer to camera input instance.
    * @return Returns error code.
    */
    int CreateCameraInput(sptr<CameraDevice> &camera, sptr<CameraInput> *pCameraInput);

    /**
    * @brief Get all available cameras.
    *
    * @return Returns vector of cameraInfo of available camera.
    */
    [[deprecated]] std::vector<sptr<CameraInfo>> GetCameras();

    /**
    * @brief Create camera input instance.
    *
    * @param The cameraInfo for which input has to be created.
    * @return Returns pointer to camera input instance.
    */
    [[deprecated]] sptr<CameraInput> CreateCameraInput(sptr<CameraInfo> &camera);

    /**
    * @brief Create capture session.
    *
    * @return Returns pointer to capture session.
    */
    sptr<CaptureSession> CreateCaptureSession();

    /**
    * @brief Create capture session.
    *
    * @param Returns pointer to capture session.
    * @return Returns error code.
    */
    int CreateCaptureSession(sptr<CaptureSession> *pCaptureSession);

    /**
    * @brief Create photo output instance using surface.
    *
    * @param The surface to be used for photo output.
    * @return Returns pointer to photo output instance.
    */
    sptr<PhotoOutput> CreatePhotoOutput(Profile &profile, sptr<Surface> &surface);

    /**
    * @brief Create photo output instance using surface.
    *
    * @param The surface to be used for photo output.
    * @param Returns pointer to photo output instance.
    * @return Returns error code.
    */
    int CreatePhotoOutput(Profile &profile, sptr<Surface> &surface, sptr<PhotoOutput> *pPhotoOutput);

    /**
    * @brief Create photo output instance using surface.
    *
    * @param The surface to be used for photo output.
    * @return Returns pointer to photo output instance.
    */
    [[deprecated]] sptr<PhotoOutput> CreatePhotoOutput(sptr<Surface> &surface);

    /**
    * @brief Create photo output instance using IBufferProducer.
    *
    * @param The IBufferProducer to be used for photo output.
    * @param The format to be used for photo capture.
    * @return Returns pointer to photo output instance.
    */
    [[deprecated]] sptr<PhotoOutput> CreatePhotoOutput(const sptr<OHOS::IBufferProducer> &producer, int32_t format);

    /**
    * @brief Create video output instance using surface.
    *
    * @param The surface to be used for video output.
    * @return Returns pointer to video output instance.
    */
    sptr<VideoOutput> CreateVideoOutput(VideoProfile &profile, sptr<Surface> &surface);

    /**
    * @brief Create video output instance using surface.
    *
    * @param The surface to be used for video output.
    * @param Returns pointer to video output instance.
    * @return Returns error code.
    */
    int CreateVideoOutput(VideoProfile &profile, sptr<Surface> &surface, sptr<VideoOutput> *pVideoOutput);

    /**
    * @brief Create video output instance using surface.
    *
    * @param The surface to be used for video output.
    * @return Returns pointer to video output instance.
    */
    [[deprecated]] sptr<VideoOutput> CreateVideoOutput(sptr<Surface> &surface);

    /**
    * @brief Create video output instance using IBufferProducer.
    *
    * @param The IBufferProducer to be used for video output.
    * @param The format to be used for video capture.
    * @return Returns pointer to video output instance.
    */
    [[deprecated]] sptr<VideoOutput> CreateVideoOutput(const sptr<OHOS::IBufferProducer> &producer, int32_t format);

    /**
    * @brief Create preview output instance using surface.
    *
    * @param The surface to be used for preview.
    * @return Returns pointer to preview output instance.
    */
    sptr<PreviewOutput> CreatePreviewOutput(Profile &profile, sptr<Surface> surface);

    /**
    * @brief Create preview output instance using surface.
    *
    * @param The surface to be used for preview.
    * @param Returns pointer to camera preview output instance.
    * @return Returns error code.
    */
    int CreatePreviewOutput(Profile &profile, sptr<Surface> surface, sptr<PreviewOutput> *pPreviewOutput);

    /**
    * @brief Create preview output instance using surface.
    *
    * @param The surface to be used for preview.
    * @return Returns pointer to preview output instance.
    */
    [[deprecated]] sptr<PreviewOutput> CreatePreviewOutput(sptr<Surface> surface);

    /**
    * @brief Create preview output instance using IBufferProducer.
    *
    * @param The IBufferProducer to be used for preview output.
    * @param The format to be used for preview.
    * @return Returns pointer to video preview instance.
    */
    [[deprecated]] sptr<PreviewOutput> CreatePreviewOutput(const sptr<OHOS::IBufferProducer> &producer,
        int32_t format);

    /**
    * @brief Create preview output instance using surface.
    *
    * @param The surface to be used for preview.
    * @return Returns pointer to preview output instance.
    */
    sptr<PreviewOutput> CreateDeferredPreviewOutput(Profile &profile);

    /**
    * @brief Create preview output instance using surface.
    *
    * @param The surface to be used for preview.
    * @param Returns pointer to preview output instance.
    * @return Returns error code.
    */
    int CreateDeferredPreviewOutput(Profile &profile, sptr<PreviewOutput> *pPreviewOutput);

    /**
    * @brief Create preview output instance using surface
    * with custom width and height.
    *
    * @param The surface to be used for preview.
    * @param preview width.
    * @param preview height.
    * @return Returns pointer to preview output instance.
    */
    [[deprecated]] sptr<PreviewOutput> CreateCustomPreviewOutput(sptr<Surface> surface, int32_t width, int32_t height);

    /**
    * @brief Create preview output instance using IBufferProducer
    * with custom width and height.
    *
    * @param The IBufferProducer to be used for preview output.
    * @param The format to be used for preview.
    * @param preview width.
    * @param preview height.
    * @return Returns pointer to preview output instance.
    */
    [[deprecated]] sptr<PreviewOutput> CreateCustomPreviewOutput(const sptr<OHOS::IBufferProducer> &producer,
        int32_t format, int32_t width, int32_t height);

    /**
    * @brief Create metadata output instance.
    *
    * @return Returns pointer to metadata output instance.
    */
    sptr<MetadataOutput> CreateMetadataOutput();

    /**
    * @brief Create metadata output instance.
    *
    * @param Returns pointer to metadata output instance.
    * @return Returns error code.
    */
    int CreateMetadataOutput(sptr<MetadataOutput> *pMetadataOutput);

    /**
    * @brief Set camera manager callback.
    *
    * @param CameraManagerCallback pointer.
    */
    void SetCallback(std::shared_ptr<CameraManagerCallback> callback);

    /**
    * @brief Get the application callback.
    *
    * @return CameraManagerCallback pointer is set by application.
    */
    std::shared_ptr<CameraManagerCallback> GetApplicationCallback();

    /**
    * @brief Get cameraDevice of specific camera id.
    *
    * @param std::string camera id.
    * @return Returns pointer to cameraDevice of given Id if found else return nullptr.
    */
    sptr<CameraDevice> GetCameraDeviceFromId(std::string cameraId);

    /**
    * @brief Get cameraInfo of specific camera id.
    *
    * @param std::string camera id.
    * @return Returns pointer to cameraInfo of given Id if found else return nullptr.
    */
    [[deprecated]] sptr<CameraInfo> GetCameraInfo(std::string cameraId);

    /**
    * @brief Get the support of camera mute mode.
    *
    * @return Returns true is supported, false is not supported.
    */
    bool IsCameraMuteSupported();

    /**
    * @brief Get camera mute mode.
    *
    * @return Returns true is in mute, else is not in mute.
    */
    bool IsCameraMuted();

    /**
    * @brief Mute the camera
    *
    * @return.
    */
    void MuteCamera(bool muteMode);

    /**
    * @brief register camera mute listener
    *
    * @param CameraMuteListener listener object.
    * @return.
    */
    void RegisterCameraMuteListener(std::shared_ptr<CameraMuteListener> listener);

    /**
    * @brief get the camera mute listener
    *
    * @return CameraMuteListener point..
    */
    std::vector<std::shared_ptr<CameraMuteListener>> GetCameraMuteListener();

    static const std::string surfaceFormat;

protected:
    explicit CameraManager(sptr<ICameraService> serviceProxy) : serviceProxy_(serviceProxy) {}

private:
    CameraManager();
    void Init();
    void SetCameraServiceCallback(sptr<ICameraServiceCallback>& callback);
    void SetCameraMuteServiceCallback(sptr<ICameraMuteServiceCallback>& callback);
    int32_t CreateListenerObject();
    void CameraServerDied(pid_t pid);
    void ChooseDeFaultCameras(std::vector<sptr<CameraDevice>>& supportedCameras);
    static const std::unordered_map<camera_format_t, CameraFormat> metaToFwCameraFormat_;
    static const std::unordered_map<CameraFormat, camera_format_t> fwToMetaCameraFormat_;

    std::mutex mutex_;
    int CreateCameraDevice(std::string cameraId, sptr<ICameraDeviceService> *pICameraDeviceService);
    camera_format_t GetCameraMetadataFormat(CameraFormat format);
    sptr<ICameraService> serviceProxy_;
    sptr<CameraListenerStub> listenerStub_ = nullptr;
    sptr<CameraDeathRecipient> deathRecipient_ = nullptr;
    static sptr<CameraManager> cameraManager_;
    sptr<ICameraServiceCallback> cameraSvcCallback_;
    std::shared_ptr<CameraManagerCallback> cameraMngrCallback_;

    sptr<ICameraMuteServiceCallback> cameraMuteSvcCallback_;
    std::vector<std::shared_ptr<CameraMuteListener>> cameraMuteListenerList;
    std::vector<sptr<CameraDevice>> cameraObjList;
    std::vector<sptr<CameraInfo>> dcameraObjList;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_CAMERA_MANAGER_H
