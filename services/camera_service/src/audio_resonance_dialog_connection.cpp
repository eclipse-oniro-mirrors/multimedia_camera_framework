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

#include "audio_resonance_dialog_connection.h"
#include <nlohmann/json.hpp>
#include "extension_manager_client.h"
#include "audio_resonance_dialog_manager.h"

namespace OHOS {
namespace CameraStandard {
constexpr int32_t PARAM_NUM = 4;

void AudioResonanceAbilityConnection::OnAbilityConnectDone(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int32_t resultCode)
{
    MEDIA_INFO_LOG("AudioResonance OnAbilityConnectDone, resultCode: %{public}d", resultCode);
    CHECK_RETURN_ELOG(remoteObject == nullptr, "AudioResonance remote object is nullptr");

    // send dialog params to sceneboard: bundleName/abilityName/moduleName/parameters
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInt32(PARAM_NUM);
    auto writeParam = [&data](const std::u16string& key, const std::string& value) {
        data.WriteString16(key);
        data.WriteString16(Str8ToStr16(value));
    };
    writeParam(u"bundleName", CAMERA_BUNDLE);
    writeParam(u"abilityName", CAMERA_DIALOG_ABILITY);
    writeParam(u"moduleName", CAMERA_DIALOG_MODULE);
    nlohmann::json param;
    param["ability.want.params.uiExtensionType"] = "sys/commonUI";
    writeParam(u"parameters", param.dump());
    int32_t ret = remoteObject->SendRequest(IAbilityConnection::ON_ABILITY_CONNECT_DONE, data, reply, option);
    MEDIA_INFO_LOG("AudioResonance send dialog request ret: %{public}d", ret);
    AudioResonanceDialog::GetInstance()->DisconnectAbilityForDialog();
}

void AudioResonanceAbilityConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element,
    int32_t resultCode)
{
    MEDIA_INFO_LOG("AudioResonance OnAbilityDisconnectDone, resultCode: %{public}d", resultCode);
}
} // namespace CameraStandard
} // namespace OHOS
