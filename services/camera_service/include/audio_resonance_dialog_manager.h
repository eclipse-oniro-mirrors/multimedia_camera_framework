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

#ifndef AUDIO_RESONANCE_DIALOG_MANAGER_H
#define AUDIO_RESONANCE_DIALOG_MANAGER_H

#include "ability_connection.h"
#include "camera_log.h"
#include "audio_resonance_dialog_connection.h"

namespace OHOS {
namespace CameraStandard {

class AudioResonanceDialog : public std::enable_shared_from_this<AudioResonanceDialog> {
public:
    static std::shared_ptr<AudioResonanceDialog> GetInstance();

    void DisconnectAbilityForDialog();
    void ShowCameraDialog();

    AudioResonanceDialog() = default;
    ~AudioResonanceDialog() = default;
    AudioResonanceDialog(const AudioResonanceDialog&) = delete;
    AudioResonanceDialog& operator=(const AudioResonanceDialog&) = delete;
    void SetConnection(sptr<AudioResonanceAbilityConnection> connection);
    void Reset();

    std::mutex connectMutex_;
    sptr<AudioResonanceAbilityConnection> connection_;
    std::atomic<bool> isNeedShowDialog_{true};
};
} // namespace CameraStandard
} // namespace OHOS

#endif // AUDIO_RESONANCE_DIALOG_MANAGER_H
