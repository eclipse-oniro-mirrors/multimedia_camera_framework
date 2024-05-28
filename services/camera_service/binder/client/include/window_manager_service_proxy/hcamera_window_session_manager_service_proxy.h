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
 
#ifndef OHOS_CAMERA_HCAMERA_WINDOW_SESSION_MANAGER_SERVICE_PROXY_H
#define OHOS_CAMERA_HCAMERA_WINDOW_SESSION_MANAGER_SERVICE_PROXY_H
 
#include "icamera_window_session_manager_service.h"
#include <iremote_proxy.h>
 
namespace OHOS {
namespace CameraStandard {
class CameraWindowSessionManagerProxy : public IRemoteProxy<ISessionManagerService> {
public:
    explicit CameraWindowSessionManagerProxy(const sptr<IRemoteObject>& object)
        : IRemoteProxy<ISessionManagerService>(object) {}
    virtual ~CameraWindowSessionManagerProxy() = default;
 
    sptr<IRemoteObject> GetSceneSessionManager() override;
 
private:
    static inline BrokerDelegator<CameraWindowSessionManagerProxy> delegator_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_HCAMERA_WINDOW_SESSION_MANAGER_SERVICE_PROXY_H