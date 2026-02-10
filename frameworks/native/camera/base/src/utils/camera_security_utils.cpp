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

#include "camera_security_utils.h"
#include "camera_log.h"
#include "camera_util.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"
#include "access_token.h"
#include "accesstoken_kit.h"
#include <cstdint>

namespace OHOS {
namespace CameraStandard {
namespace CameraSecurity {
using namespace OHOS::Security::AccessToken;
bool CheckSystemApp()
{
    uint64_t tokenId = IPCSkeleton::GetSelfTokenID();
    return !Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(tokenId) ? false : true;
}

bool IsSystemAbility()
{
    uint32_t uid = IPCSkeleton::GetCallingUid();
    constexper uint32_t maxSaUid = 10000;
    return uid < maxSaUid;
}

bool CheckSystemSA()
{
    AccessTokenID callerTokenId = IPCSkeleton::GetCallingTokenID();
    bool isHapToken = AccessTokenKit::GetTokenTypeFlag(callerTokenId) == ATokenTypeEnum::TOKEN_HAP;
    return isHapToken ? CheckSystemApp() : IsSystemAbility();
}
} // namespace CameraSecurity
} // namespace CameraStandard
} // namespace OHOS
