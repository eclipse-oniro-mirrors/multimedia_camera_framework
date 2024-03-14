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

#include "camera_napi_callback_param_parser.h"

namespace OHOS {
namespace CameraStandard {
bool CameraNapiCallbackParamParser::AssertStatus(CameraErrorCode errorCode, const char* message)
{
    if (napiError != napi_ok) {
        napi_throw_error(env_, std::to_string(errorCode).c_str(), message);
    }
    return napiError == napi_ok;
}
} // namespace CameraStandard
} // namespace OHOS