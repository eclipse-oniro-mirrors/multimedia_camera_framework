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

#include "camera_dialog_manager.h"
#include "extension_manager_client.h"
#include "ipc_skeleton.h"
#include "ipc_types.h"
#include <thread>

namespace OHOS {
namespace CameraStandard {
constexpr int32_t DEFAULT_USER_ID = -1;
constexpr int32_t DIALOG_DURATION = 3000;

std::shared_ptr<NoFrontCameraDialog> NoFrontCameraDialog::instance_ = nullptr;
std::mutex NoFrontCameraDialog::mutex_;
 
std::shared_ptr<NoFrontCameraDialog> NoFrontCameraDialog::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<NoFrontCameraDialog>();
        }
    }
    return instance_;
}

void NoFrontCameraDialog::Reset()
{
    isNeedShowDialog_.store(true);
}

void NoFrontCameraDialog::ShowCameraDialog()
{
    MEDIA_INFO_LOG("HCameraDevice::ShowCameraDialog start");
    CHECK_RETURN_ELOG(!isNeedShowDialog_.load(), "no need show dialog");
    isNeedShowDialog_.store(false);
    std::weak_ptr<NoFrontCameraDialog> weakThis(shared_from_this());
    std::thread([weakThis]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(DIALOG_DURATION));
        auto dialog = weakThis.lock();
        CHECK_RETURN_ELOG(dialog == nullptr, "dialog is null");
        dialog->Reset();
    }).detach();
    AAFwk::Want want;
    std::string bundleName = "com.ohos.sceneboard";
    std::string abilityName = "com.ohos.sceneboard.systemdialog";
    want.SetElementName(bundleName, abilityName);

    std::string commandStr = "";
    sptr<NoFrontCameraAbilityConnection> connection =
        sptr<NoFrontCameraAbilityConnection>(new (std::nothrow) NoFrontCameraAbilityConnection(commandStr));
    CHECK_RETURN_ELOG(connection == nullptr, "connection is nullptr");
    DisconnectAbilityForDialog();
    NoFrontCameraDialog::GetInstance()->SetConnection(connection);
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    auto connectResult = AAFwk::ExtensionManagerClient::GetInstance().ConnectServiceExtensionAbility(want,
        connection, nullptr, DEFAULT_USER_ID);
    IPCSkeleton::SetCallingIdentity(identity);
    CHECK_RETURN_ELOG(connectResult != 0, "ConnectServiceExtensionAbility Failed!");
    MEDIA_INFO_LOG("HCameraDevice::ShowCameraDialog end");
}

void NoFrontCameraDialog::DisconnectAbilityForDialog()
{
    std::lock_guard<std::mutex> lock(connectMutex_);
    if (connection_ != nullptr) {
        MEDIA_INFO_LOG("connection_ is not null, begin DisconnectAbility");
        AAFwk::ExtensionManagerClient::GetInstance().DisconnectAbility(connection_);
        connection_ = nullptr;
    }
}

void NoFrontCameraDialog::SetConnection(sptr<NoFrontCameraAbilityConnection> connection)
{
    std::lock_guard<std::mutex> lock(connectMutex_);
    connection_ = connection;
}

} // namespace CameraStandard
} // namespace OHOS