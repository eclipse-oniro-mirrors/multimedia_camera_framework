/*
* Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef CAMERA_NAPI_REF_MANAGER
#define CAMERA_NAPI_REF_MANAGER

#include <mutex>
#include <unordered_set>
#include "js_native_api.h"
#include "js_native_api_types.h"

namespace OHOS {
namespace CameraStandard {

class NapiRefManager {
public:
    static napi_status CreateMemSafetyRef(napi_env env, napi_value value, napi_ref* result);

private:
    NapiRefManager() {};
    static void CleanUpHook(void* iEnv);
    static void CleanUpHookImpl(napi_env env);
    static void OnUnload();
    static std::mutex mutex_;
    static std::unordered_map<napi_env, std::pair<napi_env, std::unordered_set<napi_ref>>> envToRefMap_;
};

} // namespace CameraStandard
} // namespace OHOS
#endif /* CAMERA_NAPI_REF_MANAGER */
