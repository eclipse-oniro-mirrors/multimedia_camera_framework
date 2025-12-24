/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_ICAMERA_BROKER_H
#define OHOS_CAMERA_ICAMERA_BROKER_H

#include "iremote_broker.h"

namespace OHOS {
namespace CameraStandard {

/**
 * @brief Camera service remote request code for DH IPC.
 *
 * @since 1.0
 * @version 1.0
 */
enum CameraServiceDHInterfaceCode {
    CAMERA_SERVICE_ALLOW_OPEN_BY_OHSIDE = 101,
    CAMERA_SERVICE_NOTIFY_CAMERA_STATE = 102,
    CAMERA_SERVICE_NOTIFY_CLOSE_CAMERA = 2,
    CAMERA_SERVICE_NOTIFY_MUTE_CAMERA = 4,
    CAMERA_SERVICE_SET_PEER_CALLBACK = 104,
    CAMERA_SERVICE_UNSET_PEER_CALLBACK = 105
};

class ICameraBroker : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Anco.Service.Camera");

    virtual int32_t NotifyCloseCamera(std::string cameraId) = 0;
    virtual int32_t NotifyMuteCamera(bool muteMode) = 0;
};

} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_ICAMERA_BROKER_H
