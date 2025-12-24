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

#include "napi_ref_manager.h"

#include "camera_log.h"
#include "napi/native_api.h"

namespace OHOS {
namespace CameraStandard {
/**
 * Create a memory-safe reference
 * @param env The napi environment
 * @param value The napi value
 * @param result Output parameter, returns the created reference
 * @return napi status code, napi_ok indicates success
 */
napi_status NapiRefManager::CreateMemSafetyRef(napi_env env, napi_value value, napi_ref* result)
{
    MEDIA_DEBUG_LOG("NapiRefManager::CreateMemSafetyRef enter");
    CHECK_RETURN_RET_ELOG(
        !result || !env, napi_status::napi_invalid_arg, "NapiRefManager::CreateMemSafetyRef env or result is nullptr ");
    napi_status status = napi_create_reference(env, value, 1, result);
    CHECK_RETURN_RET_ELOG(status != napi_ok, status, "NapiRefManager::CreateMemSafetyRef create ref fail");
    std::lock_guard<std::mutex> lock(mutex_);
    auto& pr = envToRefMap_[env];
    auto& [mpEnv, mpRefSet] = pr;
    mpEnv = env;
    mpRefSet.insert(*result);
    MEDIA_DEBUG_LOG("NapiRefManager::CreateMemSafetyRef map.size: %{public}d, set.size: %{public}d",
        static_cast<int32_t>(envToRefMap_.size()), static_cast<int32_t>(mpRefSet.size()));
    // Add an environment cleanup hook for the first time
    if (mpRefSet.size() == 1) {
        status = napi_add_env_cleanup_hook(env, NapiRefManager::CleanUpHook, &pr);
        CHECK_PRINT_WLOG(status != napi_ok,
            "NapiRefManager::CreateMemSafetyRef napi_add_env_cleanup_hook status: %{public}d",
            static_cast<int32_t>(status));
    }
    return status;
}

/**
 * Cleanup hook function
 * @param pPr Pointer to the pair of env and refSet
 */
void NapiRefManager::CleanUpHook(void* pPr)
{
    MEDIA_INFO_LOG("NapiRefManager::CleanUpHook CleanUpHook enter");
    CHECK_RETURN(!pPr);
    auto& [mpEnv, _] = *reinterpret_cast<std::pair<napi_env, std::unordered_set<napi_ref>>*>(pPr);
    NapiRefManager::CleanUpHookImpl(mpEnv);
}

/**
 * Cleanup hook implementation function
 * @param env The napi environment
 */
void NapiRefManager::CleanUpHookImpl(napi_env env)
{
    MEDIA_INFO_LOG("NapiRefManager::CleanUpHookImpl enter");
    CHECK_RETURN(!env);
    std::lock_guard<std::mutex> lock(mutex_);
    auto& [_, refSet] = envToRefMap_[env];
    MEDIA_INFO_LOG("NapiRefManager::CleanUpHookImpl to del ref, size: %{public}d", static_cast<int32_t>(refSet.size()));
    // Iterate through the set and delete all references
    for (auto& ref : refSet) {
        napi_status status = napi_delete_reference(env, ref);
        CHECK_PRINT_WLOG(
            status != napi_ok, "NapiRefManager::CleanUpHookImpl status: %{public}d", static_cast<int32_t>(status));
    }
    // Remove the environment entry from the map
    envToRefMap_.erase(env);
}

std::mutex NapiRefManager::mutex_;
std::unordered_map<napi_env, std::pair<napi_env, std::unordered_set<napi_ref>>> NapiRefManager::envToRefMap_;
} // namespace CameraStandard
} // namespace OHOS
