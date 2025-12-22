/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef DEVICE_PROTECTION_ABILITY_CONNECTION_H
#define DEVICE_PROTECTION_ABILITY_CONNECTION_H

#include "ability_connection.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
typedef void (*DeviceProtectionAbilityCallBack)();
class DeviceProtectionAbilityConnection : public AAFwk::AbilityConnectionStub {
public:
    DeviceProtectionAbilityConnection(const std::string &commandStr, const int32_t &code,
        DeviceProtectionAbilityCallBack callback)
    {
        commandStr_ = commandStr;
        code_ = code;
        callback_ = callback;
    }

    virtual ~DeviceProtectionAbilityConnection() = default;

    void OnAbilityConnectDone(const AppExecFwk::ElementName &element,
        const sptr<IRemoteObject> &remoteObject, int32_t resultCode) override;
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int32_t resultCode) override;

private:
    std::string commandStr_;
    int32_t code_;
    DeviceProtectionAbilityCallBack callback_;
};
} // namespace CameraStandard
} // namespace OHOS

#endif // DEVICE_PROTECTION_ABILITY_CONNECTION_H