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

#ifndef TEST_TOKEN_COMMON_H
#define TEST_TOKEN_COMMON_H

#include "access_token.h"
#include "accesstoken_kit.h"
#include "atm_tools_param_info.h"
#include "nativetoken_kit.h"
#include "permission_def.h"
#include "permission_state_full.h"
#include "token_setproc.h"

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::Security::AccessToken;

class TestToken {
public:
    static bool GetAllCameraPermission();

private:
    static uint64_t GetTokenId(const AtmToolsParamInfo &info);
    static uint64_t GetTokenIdFromProcess(const std::string &process);
    static bool MockTokenId(const std::string &process);
};

} // namespace CameraStandard
} // namespace OHOS
#endif
