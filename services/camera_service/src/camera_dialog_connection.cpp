/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "camera_dialog_connection.h"
#include <nlohmann/json.hpp>
#include "extension_manager_client.h"
#include "camera_dialog_manager.h"

constexpr int32_t PARAM_NUM = 3;

namespace OHOS {
namespace CameraStandard {

void NoFrontCameraAbilityConnection::OnAbilityConnectDone(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int32_t resultCode)
{
    MEDIA_INFO_LOG("OnAbilityConnectDone, resultCode = %{public}d", resultCode);
    CHECK_RETURN_ELOG(remoteObject == nullptr, "remote object is nullptr");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInt32(PARAM_NUM);
    data.WriteString16(u"bundleName");
    data.WriteString16(Str8ToStr16(bundleName_));
    data.WriteString16(u"abilityName");
    data.WriteString16(Str8ToStr16(abilityName_));
    data.WriteString16(u"parameters");
    nlohmann::json param;
    param["ability.want.params.uiExtensionType"] = "sysDialog/common";
    std::string paramStr = param.dump();
    data.WriteString16(Str8ToStr16(paramStr));
    int32_t sendRequestRet = remoteObject->SendRequest(IAbilityConnection::ON_ABILITY_CONNECT_DONE,
        data, reply, option);
    MEDIA_INFO_LOG("OnAbilityConnectDone, sendRequestRet = %{public}d", sendRequestRet);
    NoFrontCameraDialog::GetInstance()->DisconnectAbilityForDialog();
}

void NoFrontCameraAbilityConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element,
    int32_t resultCode)
{
    MEDIA_INFO_LOG("OnAbilityDisconnectDone, resultCode = %{public}d", resultCode);
}
} // namespace CameraStandard
} // namespace OHOS