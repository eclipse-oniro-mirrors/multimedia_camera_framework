/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "anonymization.h"
#include "camera_log.h"
#include <string>
 

namespace OHOS {
namespace CameraStandard {
namespace Anonymization {
std::string AnonymizeString(const std::string& input)
{
    CHECK_RETURN_RET(input.empty(), input);
    const size_t len = input.length();
    CHECK_RETURN_RET(len == 1, input + "****" + input);
    return input.substr(0, 1) + "****" + input.substr(len - 1);
}
} // namespace Anonymization
} // namespace CameraStandard
} // namespace OHOS