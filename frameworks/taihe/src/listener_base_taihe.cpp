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
#include "listener_base_taihe.h"
#include "camera_utils_taihe.h"
#include "camera_log.h"
#include "event_handler.h"

using namespace taihe;
using namespace ohos::multimedia::camera;
using namespace OHOS;

namespace Ani {
namespace Camera {
ListenerBase::ListenerBase(ani_env* env) : env_(env)
{
    MEDIA_DEBUG_LOG("ListenerBase is called.");
}

ListenerBase::~ListenerBase()
{
    MEDIA_DEBUG_LOG("~ListenerBase is called.");
}

void ListenerBase::SaveCallbackReference(const std::string eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(callback == nullptr,
        "SaveCallbackReference:%s callback is nullptr, save nothing", eventName.c_str());
    auto& callbackList = GetCallbackList(eventName);
    std::lock_guard<std::mutex> lock(callbackList.listMutex);
    for (auto it = callbackList.refList.begin(); it != callbackList.refList.end(); ++it) {
        if (IsSameRef(callback, it->get()->GetCallbackFunction())) {
            MEDIA_DEBUG_LOG("SaveCallbackReference: has same callback, nothing to do");
            return;
        }
    }
    callbackList.refList.emplace_back(std::make_shared<Ani::Camera::AutoRef>(env_, callback, isOnce));
    std::shared_ptr<OHOS::AppExecFwk::EventRunner> runner = OHOS::AppExecFwk::EventRunner::GetMainEventRunner();
    mainHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    MEDIA_DEBUG_LOG("Save callback reference success, %s callback list size [%{public}zu]", eventName.c_str(),
        callbackList.refList.size());
}

void ListenerBase::RemoveCallbackRef(const std::string eventName, std::shared_ptr<uintptr_t> callback)
{
    if (callback == nullptr) {
        MEDIA_INFO_LOG("RemoveCallbackReference: js callback is nullptr, remove all callback reference");
        RemoveAllCallbacks(eventName);
        return;
    }
    auto& callbackList = GetCallbackList(eventName);
    std::lock_guard<std::mutex> lock(callbackList.listMutex);
    for (auto it = callbackList.refList.begin(); it != callbackList.refList.end(); ++it) {
        if (IsSameRef(callback, it->get()->GetCallbackFunction())) {
            MEDIA_INFO_LOG("RemoveCallbackReference: find %s callback, delete it", eventName.c_str());
            callbackList.refList.erase(it);
            return;
        }
    }
    MEDIA_INFO_LOG("RemoveCallbackReference: %s callback", eventName.c_str());
}

void ListenerBase::RemoveAllCallbacks(const std::string eventName)
{
    auto& callbackList = GetCallbackList(eventName);
    std::lock_guard<std::mutex> lock(callbackList.listMutex);
    callbackList.refList.clear();
    MEDIA_INFO_LOG("RemoveAllCallbacks: remove all js callbacks success");
}

bool ListenerBase::IsEmpty(const std::string eventName) const
{
    auto& callbackList = GetCallbackList(eventName);
    std::lock_guard<std::mutex> lock(callbackList.listMutex);
    return callbackList.refList.empty();
}
} // namespace Camera
} // namespace Ani
