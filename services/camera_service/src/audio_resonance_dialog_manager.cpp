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

#include "audio_resonance_dialog_manager.h"
#include "extension_manager_client.h"
#include "ipc_skeleton.h"
#include "ipc_types.h"
#include <thread>

namespace OHOS {
namespace CameraStandard {
constexpr int32_t DEFAULT_USER_ID = -1;
constexpr int32_t DIALOG_SHOW_INTERVAL_MS = 3000;
const std::string SCENEBOARD_BUNDLE = "com.ohos.sceneboard";
const std::string SCENEBOARD_DIALOG_ABILITY = "com.ohos.sceneboard.systemdialog";

std::shared_ptr<AudioResonanceDialog> AudioResonanceDialog::GetInstance()
{
    static std::shared_ptr<AudioResonanceDialog> instance = std::make_shared<AudioResonanceDialog>();
    return instance;
}

void AudioResonanceDialog::Reset()
{
    isNeedShowDialog_.store(true);
}

void AudioResonanceDialog::ShowCameraDialog()
{
    // atomic reentry guard: only one dialog within DIALOG_SHOW_INTERVAL_MS
    CHECK_RETURN_ELOG(!isNeedShowDialog_.exchange(false), "AudioResonance dialog already showing");
    std::weak_ptr<AudioResonanceDialog> weakThis(shared_from_this());
    std::thread([weakThis]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(DIALOG_SHOW_INTERVAL_MS));
        auto dialog = weakThis.lock();
        CHECK_RETURN_ELOG(dialog == nullptr, "AudioResonance dialog is null");
        dialog->Reset();
    }).detach();

    AAFwk::Want want;
    want.SetElementName(SCENEBOARD_BUNDLE, SCENEBOARD_DIALOG_ABILITY);
    sptr<AudioResonanceAbilityConnection> connection =
        sptr<AudioResonanceAbilityConnection>(new (std::nothrow) AudioResonanceAbilityConnection());
    CHECK_RETURN_ELOG(connection == nullptr, "AudioResonance connection is nullptr");
    DisconnectAbilityForDialog();
    SetConnection(connection);
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    auto connectResult = AAFwk::ExtensionManagerClient::GetInstance().ConnectServiceExtensionAbility(
        want, connection, nullptr, DEFAULT_USER_ID);
    IPCSkeleton::SetCallingIdentity(identity);
    if (connectResult != 0) {
        MEDIA_ERR_LOG("AudioResonance ConnectServiceExtensionAbility failed, ret: %{public}d", connectResult);
        SetConnection(nullptr);
        return;
    }
    MEDIA_INFO_LOG("AudioResonance dialog shown");
}

void AudioResonanceDialog::DisconnectAbilityForDialog()
{
    std::lock_guard<std::mutex> lock(connectMutex_);
    CHECK_RETURN(connection_ == nullptr);
    AAFwk::ExtensionManagerClient::GetInstance().DisconnectAbility(connection_);
    connection_ = nullptr;
}

void AudioResonanceDialog::SetConnection(sptr<AudioResonanceAbilityConnection> connection)
{
    std::lock_guard<std::mutex> lock(connectMutex_);
    connection_ = connection;
}

} // namespace CameraStandard
} // namespace OHOS
