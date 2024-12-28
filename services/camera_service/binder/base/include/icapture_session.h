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

#ifndef OHOS_CAMERA_ICAPTURE_SESSION_H
#define OHOS_CAMERA_ICAPTURE_SESSION_H

#include <cstdint>
#include "icamera_device_service.h"
#include "icapture_session_callback.h"
#include "iremote_broker.h"
#include "istream_common.h"
#include "camera_photo_proxy.h"
#include "ability/camera_ability.h"

namespace OHOS::Media {
    class Picture;
}
namespace OHOS {
namespace CameraStandard {
enum class CaptureSessionState : uint32_t {
    SESSION_INIT = 0,
    SESSION_CONFIG_INPROGRESS = 1,
    SESSION_CONFIG_COMMITTED = 2,
    SESSION_RELEASED = 3,
    SESSION_STARTED = 4,
    SESSION_STATE_MAX = 5
};

class ICaptureSession : public IRemoteBroker {
public:
    virtual int32_t BeginConfig() = 0;

    virtual int32_t AddInput(sptr<ICameraDeviceService> cameraDevice) = 0;

    virtual int32_t CanAddInput(sptr<ICameraDeviceService> cameraDevice, bool& result) = 0;

    virtual int32_t AddOutput(StreamType streamType, sptr<IStreamCommon> stream) = 0;

    virtual int32_t RemoveInput(sptr<ICameraDeviceService> cameraDevice) = 0;

    virtual int32_t RemoveOutput(StreamType streamType, sptr<IStreamCommon> stream) = 0;

    virtual int32_t CommitConfig() = 0;

    virtual int32_t Start() = 0;

    virtual int32_t Stop() = 0;

    virtual int32_t Release() = 0;

    virtual int32_t SetCallback(sptr<ICaptureSessionCallback> &callback) = 0;

    virtual int32_t GetSessionState(CaptureSessionState &sessionState) = 0;

    virtual int32_t SetSmoothZoom(int32_t smoothZoomType, int32_t operationMode,
            float targetZoomRatio, float &duration) = 0;

    virtual int32_t GetActiveColorSpace(ColorSpace& colorSpace) = 0;

    virtual int32_t SetColorSpace(ColorSpace colorSpace, ColorSpace captureColorSpace, bool isNeedUpdate) = 0;

    virtual int32_t SetFeatureMode(int32_t featureMode) = 0;

    virtual int32_t EnableMovingPhoto(bool isEnable) = 0;

    virtual int32_t EnableMovingPhotoMirror(bool isMirror, bool isConfig) = 0;

    virtual int32_t CreateMediaLibrary(sptr<CameraPhotoProxy> &photoProxy,
        std::string &uri, int32_t &cameraShotType, std::string &burstKey, int64_t timestamp) = 0;

    virtual int32_t CreateMediaLibrary(std::unique_ptr<Media::Picture> picture, sptr<CameraPhotoProxy> &photoProxy,
        std::string &uri, int32_t &cameraShotType, std::string &burstKey, int64_t timestamp) = 0;
    virtual int32_t SetPreviewRotation(std::string &deviceClass) = 0;

    DECLARE_INTERFACE_DESCRIPTOR(u"ICaptureSession");
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_ICAPTURE_SESSION_H
