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

namespace OHOS {
namespace CameraStandard {
enum class CaptureSessionState : uint32_t {
    SESSION_INIT = 0,
    SESSION_CONFIG_INPROGRESS = 1,
    SESSION_CONFIG_COMMITTED = 2,
    SESSION_RELEASED = 3,
    SESSION_STATE_MAX = 4
};

enum ColorSpace {
    COLOR_SPACE_UNKNOWN = 0,
    DISPLAY_P3 = 3, // CM_P3_FULL
    SRGB = 4, // CM_SRGB_FULL
    BT709 = 6, // CM_BT709_FULL
    BT2020_HLG = 9, // CM_BT2020_HLG_FULL
    BT2020_PQ = 10, // CM_BT2020_PQ_FULL
    P3_HLG = 11, // CM_P3_HLG_FULL
    P3_PQ = 12, // CM_P3_PQ_FULL
    DISPLAY_P3_LIMIT = 14, // CM_P3_LIMIT
    SRGB_LIMIT = 15, // CM_SRGB_LIMIT
    BT709_LIMIT = 16, // CM_BT709_LIMIT
    BT2020_HLG_LIMIT = 19, // CM_BT2020_HLG_LIMIT
    BT2020_PQ_LIMIT = 20, // CM_BT2020_PQ_LIMIT
    P3_HLG_LIMIT = 21, // CM_P3_HLG_LIMIT
    P3_PQ_LIMIT = 22 // CM_P3_PQ_LIMIT
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

    DECLARE_INTERFACE_DESCRIPTOR(u"ICaptureSession");
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_ICAPTURE_SESSION_H
