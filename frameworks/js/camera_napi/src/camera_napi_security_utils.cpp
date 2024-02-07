/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "camera_napi_security_utils.h"

#include "camera_error_code.h"
#include "camera_napi_utils.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace CameraStandard {
namespace CameraNapiSecurity {
bool CheckSystemApp(napi_env env, bool enableThrowError)
{
    uint64_t tokenId = IPCSkeleton::GetSelfTokenID();
    int32_t errorCode = CameraErrorCode::NO_SYSTEM_APP_PERMISSION;
    if (!Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(tokenId)) {
        if (enableThrowError) {
            std::string errorMessage = "System api can be invoked only by system applications";
            if (napi_throw_error(env, std::to_string(errorCode).c_str(), errorMessage.c_str()) != napi_ok) {
                MEDIA_ERR_LOG("failed to throw err, code=%{public}d, msg=%{public}s.", errorCode, errorMessage.c_str());
            }
        }
        return false;
    }
    return true;
}
} // namespace CameraNapiSecurity
} // namespace CameraStandard
} // namespace OHOS
