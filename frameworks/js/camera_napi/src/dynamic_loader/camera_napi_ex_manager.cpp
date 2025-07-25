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

#include "dynamic_loader/camera_napi_ex_manager.h"

#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
std::shared_ptr<CameraNapiExProxy> CameraNapiExManager::cameraNapiExProxy_ = nullptr;
std::vector<CameraNapiExProxyUserType> CameraNapiExManager::userList_ = {};
std::mutex CameraNapiExManager::mutex_;

std::shared_ptr<CameraNapiExProxy> CameraNapiExManager::GetCameraNapiExProxy(CameraNapiExProxyUserType type)
{
    MEDIA_DEBUG_LOG("CameraNapiExManager::GetCameraNapiExProxy is called");
    std::lock_guard<std::mutex> lock(mutex_);
    if (cameraNapiExProxy_ == nullptr) {
        cameraNapiExProxy_ = CameraNapiExProxy::GetCameraNapiExProxy();
        CHECK_RETURN_RET_ELOG(cameraNapiExProxy_ == nullptr, nullptr,
            "get cameraNapiExProxy failed");
    }
    auto item = std::find(userList_.begin(), userList_.end(), type);
    if (item == userList_.end()) {
        userList_.push_back(type);
    }
    return cameraNapiExProxy_;
}

void CameraNapiExManager::FreeCameraNapiExProxy(CameraNapiExProxyUserType type)
{
    MEDIA_DEBUG_LOG("CameraNapiExManager::FreeCameraNapiExProxy is called");
    std::lock_guard<std::mutex> lock(mutex_);
    auto item = std::find(userList_.begin(), userList_.end(), type);
    if (item != userList_.end()) {
        userList_.erase(item);
    }
    if (userList_.empty() && cameraNapiExProxy_ != nullptr) {
        cameraNapiExProxy_ = nullptr;
    }
}
} // namespace CameraStandard
} // namespace OHOS