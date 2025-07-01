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

#ifndef CAMERA_NAPI_EX_MANAGER_H_
#define CAMERA_NAPI_EX_MANAGER_H_

#include "camera_dynamic_loader.h"
#include "dynamic_loader/camera_napi_ex_proxy.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace CameraStandard {
enum CameraNapiExProxyUserType : int32_t {
    CAMERA_MANAGER_NAPI = 0,
    MODE_MANAGER_NAPI,
};

class CameraNapiExManager {
public:
    static std::shared_ptr<CameraNapiExProxy>
        GetCameraNapiExProxy(CameraNapiExProxyUserType type = CameraNapiExProxyUserType::CAMERA_MANAGER_NAPI);
    static void FreeCameraNapiExProxy(CameraNapiExProxyUserType type = CameraNapiExProxyUserType::CAMERA_MANAGER_NAPI);
private:
    static std::shared_ptr<CameraNapiExProxy> cameraNapiExProxy_;
    static std::vector<CameraNapiExProxyUserType> userList_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // CAMERA_NAPI_EX_MANAGER_H_