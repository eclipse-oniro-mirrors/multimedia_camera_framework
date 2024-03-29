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

#ifndef OHOS_CAMERA_HCAPTURE_SESSION_PROXY_H
#define OHOS_CAMERA_HCAPTURE_SESSION_PROXY_H

#include "icapture_session.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace CameraStandard {
class HCaptureSessionProxy : public IRemoteProxy<ICaptureSession> {
public:
    explicit HCaptureSessionProxy(const sptr<IRemoteObject> &impl);

    virtual ~HCaptureSessionProxy() = default;

    int32_t BeginConfig() override;

    int32_t CanAddInput(sptr<ICameraDeviceService> cameraDevice, bool& result) override;

    int32_t AddInput(sptr<ICameraDeviceService> cameraDevice) override;

    int32_t AddOutput(StreamType streamType, sptr<IStreamCommon> stream) override;

    int32_t RemoveInput(sptr<ICameraDeviceService> cameraDevice) override;

    int32_t RemoveOutput(StreamType streamType, sptr<IStreamCommon> stream) override;

    int32_t CommitConfig() override;

    int32_t Start() override;

    int32_t Stop() override;

    int32_t Release() override;

    int32_t SetCallback(sptr<ICaptureSessionCallback> &callback) override;

    int32_t GetSessionState(CaptureSessionState &sessionState) override;

    int32_t SetSmoothZoom(int32_t smoothZoomType, int32_t operationMode,
        float targetZoomRatio, float &duration) override;

    int32_t GetActiveColorSpace(ColorSpace& colorSpace) override;

    int32_t SetColorSpace(ColorSpace colorSpace, ColorSpace captureColorSpace, bool isNeedUpdate) override;

    int32_t SetFeatureMode(int32_t featureMode) override;

private:
    static inline BrokerDelegator<HCaptureSessionProxy> delegator_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_HCAPTURE_SESSION_PROXY_H
