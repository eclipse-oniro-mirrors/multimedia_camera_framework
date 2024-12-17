/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "camera_dynamic_loader.h"

#include <cstddef>
#include <cstdint>
#include <dlfcn.h>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>

#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;

enum AsyncLoadingState : int32_t { NONE, PREPARE, LOADING };

static const uint32_t HANDLE_MASK = 0xffffffff;
static mutex g_libMutex;
static map<const string, shared_ptr<Dynamiclib>> g_dynamiclibMap = {};
static map<const string, weak_ptr<Dynamiclib>> g_weakDynamiclibMap = {};

static mutex g_asyncLoadingMutex;
static condition_variable g_asyncLiblockCondition;
static AsyncLoadingState g_isAsyncLoading = AsyncLoadingState::NONE;

Dynamiclib::Dynamiclib(const string& libName) : libName_(libName)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("Dynamiclib::Dynamiclib dlopen %{public}s", libName_.c_str());
    libHandle_ = dlopen(libName_.c_str(), RTLD_NOW);
    CHECK_ERROR_RETURN_LOG(
        libHandle_ == nullptr, "Dynamiclib::Dynamiclib dlopen name:%{public}s return null", libName_.c_str());
    MEDIA_INFO_LOG("Dynamiclib::Dynamiclib dlopen %{public}s success handle:%{public}u", libName_.c_str(),
        static_cast<uint32_t>(HANDLE_MASK & reinterpret_cast<uintptr_t>(libHandle_)));
}

Dynamiclib::~Dynamiclib()
{
    CAMERA_SYNC_TRACE;
    if (libHandle_ != nullptr) {
        int ret = dlclose(libHandle_);
        MEDIA_INFO_LOG("Dynamiclib::~Dynamiclib dlclose name:%{public}s handle:%{public}u result:%{public}d",
            libName_.c_str(), static_cast<uint32_t>(HANDLE_MASK & reinterpret_cast<uintptr_t>(libHandle_)), ret);
        libHandle_ = nullptr;
    }
}

bool Dynamiclib::IsLoaded()
{
    return libHandle_ != nullptr;
}

void* Dynamiclib::GetFunction(const string& functionName)
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_RET_LOG(
        !IsLoaded(), nullptr, "Dynamiclib::GetFunction fail libname:%{public}s not loaded", libName_.c_str());

    void* handle = dlsym(libHandle_, functionName.c_str());
    CHECK_ERROR_RETURN_RET_LOG(
        handle == nullptr, nullptr, "Dynamiclib::GetFunction fail function:%{public}s not find", functionName.c_str());
    MEDIA_INFO_LOG("Dynamiclib::GetFunction %{public}s success", functionName.c_str());
    return handle;
}
shared_ptr<Dynamiclib> CameraDynamicLoader::GetDynamiclibNoLock(const string& libName)
{
    auto loadedIterator = g_dynamiclibMap.find(libName);
    if (loadedIterator != g_dynamiclibMap.end()) {
        MEDIA_INFO_LOG("Dynamiclib::GetDynamiclib %{public}s by cache", libName.c_str());
        return loadedIterator->second;
    }

    shared_ptr<Dynamiclib> dynamiclib = nullptr;
    auto loadedWeakIterator = g_weakDynamiclibMap.find(libName);
    if (loadedWeakIterator != g_weakDynamiclibMap.end()) {
        dynamiclib = loadedWeakIterator->second.lock();
    }
    if (dynamiclib != nullptr) {
        MEDIA_INFO_LOG("Dynamiclib::GetDynamiclib %{public}s by weak cache", libName.c_str());
    } else {
        dynamiclib = make_shared<Dynamiclib>(libName);
    }
    CHECK_ERROR_RETURN_RET_LOG(
        !dynamiclib->IsLoaded(), nullptr, "CameraDynamicLoader::GetDynamiclib name:%{public}s fail", libName.c_str());
    g_dynamiclibMap.emplace(pair<const string, shared_ptr<Dynamiclib>>(libName, dynamiclib));
    MEDIA_INFO_LOG("Dynamiclib::GetDynamiclib %{public}s load first", libName.c_str());
    return dynamiclib;
}

shared_ptr<Dynamiclib> CameraDynamicLoader::GetDynamiclib(const string& libName)
{
    CAMERA_SYNC_TRACE;
    lock_guard<mutex> lock(g_libMutex);
    return GetDynamiclibNoLock(libName);
}

void CameraDynamicLoader::LoadDynamiclibAsync(const std::string& libName)
{
    CAMERA_SYNC_TRACE;
    unique_lock<mutex> asyncLock(g_asyncLoadingMutex);
    MEDIA_INFO_LOG("CameraDynamicLoader::LoadDynamiclibAsync %{public}s", libName.c_str());
    if (g_isAsyncLoading != AsyncLoadingState::NONE) {
        MEDIA_INFO_LOG("CameraDynamicLoader::LoadDynamiclibAsync %{public}s is loading", libName.c_str());
        return;
    }
    g_isAsyncLoading = AsyncLoadingState::PREPARE;
    thread asyncThread = thread([libName]() {
        unique_lock<mutex> lock(g_libMutex);
        {
            unique_lock<mutex> asyncLock(g_asyncLoadingMutex);
            g_isAsyncLoading = AsyncLoadingState::LOADING;
            g_asyncLiblockCondition.notify_all();
        }
        GetDynamiclibNoLock(libName);
        {
            unique_lock<mutex> asyncLock(g_asyncLoadingMutex);
            g_isAsyncLoading = AsyncLoadingState::NONE;
        }
        MEDIA_INFO_LOG("CameraDynamicLoader::LoadDynamiclibAsync %{public}s finish", libName.c_str());
    });
    asyncThread.detach();
    g_asyncLiblockCondition.wait(asyncLock, []() { return g_isAsyncLoading != AsyncLoadingState::PREPARE; });
}

void CameraDynamicLoader::FreeDynamiclib(const string& libName)
{
    CAMERA_SYNC_TRACE;
    lock_guard<mutex> lock(g_libMutex);
    auto loadedIterator = g_dynamiclibMap.find(libName);
    if (loadedIterator == g_dynamiclibMap.end()) {
        return;
    }
    MEDIA_INFO_LOG("Dynamiclib::FreeDynamiclib %{public}s lib use count is:%{public}d", libName.c_str(),
        static_cast<int32_t>(loadedIterator->second.use_count()));

    weak_ptr<Dynamiclib> weaklib = loadedIterator->second;
    g_weakDynamiclibMap[libName] = weaklib;
    g_dynamiclibMap.erase(loadedIterator);
}
} // namespace CameraStandard
} // namespace OHOS