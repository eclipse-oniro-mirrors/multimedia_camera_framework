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

#ifndef OHOS_CAMERA_HCAMERA_BROKER_PROXY_H
#define OHOS_CAMERA_HCAMERA_BROKER_PROXY_H

#include "icamera_broker.h"
#include "iremote_object.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace CameraStandard {
class HCameraProxy : public IRemoteProxy<ICameraBroker> {
public:
    explicit HCameraProxy(const sptr<IRemoteObject> &impl);
    ~HCameraProxy() = default;

    int32_t NotifyCloseCamera(std::string cameraId) override;
    int32_t NotifyMuteCamera(bool muteMode) override;
private:
    static inline BrokerDelegator<HCameraProxy> delegator_;
};
  
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_HCAMERA_BROKER_PROXY_H
