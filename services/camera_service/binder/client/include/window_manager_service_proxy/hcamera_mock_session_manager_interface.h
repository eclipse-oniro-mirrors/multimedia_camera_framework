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
 
#ifndef OHOS_CAMERA_HCAMERA_MOCK_SESSION_MANAGER_INTERFACE_H
#define OHOS_CAMERA_HCAMERA_MOCK_SESSION_MANAGER_INTERFACE_H
 
#include "icamera_mock_session_manager_interface.h"
#include <iremote_proxy.h>
 
namespace OHOS {
namespace CameraStandard {
class CameraMockSessionManagerProxy : public IRemoteProxy<IMockSessionManagerInterface> {
public:
    explicit CameraMockSessionManagerProxy(const sptr<IRemoteObject>& impl)
        : IRemoteProxy<IMockSessionManagerInterface>(impl) {}
    ~CameraMockSessionManagerProxy() {}
    sptr<IRemoteObject> GetSessionManagerService() override;
private:
    static inline BrokerDelegator<CameraMockSessionManagerProxy> delegator_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_HCAMERA_MOCK_SESSION_MANAGER_INTERFACE_H