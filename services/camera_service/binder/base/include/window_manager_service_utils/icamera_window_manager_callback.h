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
 
#ifndef OHOS_CAMERA_ICAMERA_WINDOW_MANAGER_CALLBACK_H
#define OHOS_CAMERA_ICAMERA_WINDOW_MANAGER_CALLBACK_H
 
#include <iremote_broker.h>
 
namespace OHOS {
namespace CameraStandard {
enum class WindowServiceInterfaceCode {
    TRANS_ID_UPDATE_CAMERA_WINDOW_STATUS = 10,
};
class IWindowManagerAgent : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.IWindowManagerAgent");
 
    virtual void UpdateCameraWindowStatus(uint32_t accessTokenId, bool isShowing) = 0;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_ICAMERA_WINDOW_SESSION_MANAGER_SERVICE_H