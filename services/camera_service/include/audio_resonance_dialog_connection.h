/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef AUDIO_RESONANCE_DIALOG_CONNECTION_H
#define AUDIO_RESONANCE_DIALOG_CONNECTION_H

#include "ability_connection.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
class AudioResonanceAbilityConnection : public AAFwk::AbilityConnectionStub {
public:
    AudioResonanceAbilityConnection() = default;
    virtual ~AudioResonanceAbilityConnection() = default;

    void OnAbilityConnectDone(const AppExecFwk::ElementName &element,
        const sptr<IRemoteObject> &remoteObject, int32_t resultCode) override;
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int32_t resultCode) override;

private:
    static constexpr const char *CAMERA_BUNDLE = "com.huawei.hmos.camera";
    static constexpr const char *CAMERA_DIALOG_ABILITY = "com.huawei.hmos.camera.DialogMessageExtAbility";
    static constexpr const char *CAMERA_DIALOG_MODULE = "pcpicker";
};
} // namespace CameraStandard
} // namespace OHOS

#endif // AUDIO_RESONANCE_DIALOG_CONNECTION_H
