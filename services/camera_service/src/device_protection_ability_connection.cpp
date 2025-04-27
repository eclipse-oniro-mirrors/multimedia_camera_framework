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

#include "device_protection_ability_connection.h"

namespace OHOS {
namespace CameraStandard {
constexpr int32_t PARAM_NUM = 1;
void DeviceProtectionAbilityConnection::OnAbilityConnectDone(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int32_t resultCode)
{
    MEDIA_INFO_LOG("OnAbilityConnectDone, resultCode = %{public}d", resultCode);
    CHECK_ERROR_RETURN_LOG(remoteObject == nullptr, "remote object is nullptr");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInt32(PARAM_NUM);
    data.WriteString16(u"parameters");
    data.WriteString16(Str8ToStr16(commandStr_));
    int32_t sendRequestRet = remoteObject->SendRequest(code_,
        data, reply, option);
    MEDIA_INFO_LOG("OnAbilityConnectDone, sendRequestRet = %{public}d", sendRequestRet);
}

void DeviceProtectionAbilityConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element,
    int32_t resultCode)
{
    MEDIA_INFO_LOG("OnAbilityDisconnectDone, resultCode = %{public}d", resultCode);
    callback_();
}

} // namespace CameraStandard
} // namespace OHOS