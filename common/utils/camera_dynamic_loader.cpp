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
#include "camera_simple_timer.h"
#include "thread_priority_util.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;
namespace {
enum AsyncLoadingState : int32_t { NONE, PREPARE, LOADING };
enum DynamiclibState : int32_t { UNLOAD, LOADED };

static const uint32_t HANDLE_MASK = 0xff0000ff;

static mutex g_libStateMutex;
static condition_variable g_libStateCondition;
static map<const string, DynamiclibState> g_dynamiclibStateMap = {};

static mutex g_libMutex;
static map<const string, shared_ptr<Dynamiclib>> g_dynamiclibMap = {};
static map<const string, weak_ptr<Dynamiclib>> g_weakDynamiclibMap = {};

static mutex g_delayedCloseTimerMutex;
static map<const string, shared_ptr<SimpleTimer>> g_delayedCloseTimerMap = {};

static mutex g_asyncLoadingMutex;
static condition_variable g_asyncLiblockCondition;
static AsyncLoadingState g_isAsyncLoading = AsyncLoadingState::NONE;

shared_ptr<SimpleTimer> GetDelayedCloseTimer(const string& libName)
{
    lock_guard<mutex> lock(g_delayedCloseTimerMutex);
    auto it = g_delayedCloseTimerMap.find(libName);
    CHECK_RETURN_RET(it == g_delayedCloseTimerMap.end(), nullptr);
    return it->second;
}

void SetDelayedCloseTimer(const string& libName, shared_ptr<SimpleTimer> timer)
{
    lock_guard<mutex> lock(g_delayedCloseTimerMutex);
    g_delayedCloseTimerMap[libName] = timer;
}

void RemoveDelayedCloseTimer(const string& libName)
{
    lock_guard<mutex> lock(g_delayedCloseTimerMutex);
    auto it = g_delayedCloseTimerMap.find(libName);
    CHECK_RETURN(it == g_delayedCloseTimerMap.end());
    g_delayedCloseTimerMap.erase(it);
}

void UpdateDynamiclibState(const string& libName, DynamiclibState state)
{
    lock_guard<mutex> lock(g_libStateMutex);
    auto it = g_dynamiclibStateMap.find(libName);
    if (it == g_dynamiclibStateMap.end()) {
        g_dynamiclibStateMap.insert({ libName, state });
    } else {
        it->second = state;
    }
    g_libStateCondition.notify_all();
}

void WaitDynamiclibState(const string& libName, DynamiclibState targetState)
{
    static const int32_t WAIT_TIME_OUT = 5000;
    unique_lock<mutex> lock(g_libStateMutex);
    auto it = g_dynamiclibStateMap.find(libName);
    if (it == g_dynamiclibStateMap.end()) {
        return;
    }
    g_libStateCondition.wait_for(lock, chrono::milliseconds(WAIT_TIME_OUT), [&libName, targetState]() {
        auto it = g_dynamiclibStateMap.find(libName);
        return it == g_dynamiclibStateMap.end() || it->second == targetState;
    });
}
} // namespace

Dynamiclib::Dynamiclib(const string& libName) : libName_(libName)
{
    CAMERA_SYNC_TRACE_FMT("Dynamiclib::Dynamiclib %s", libName_.c_str());
    WaitDynamiclibState(libName, UNLOAD);
    MEDIA_INFO_LOG("Dynamiclib::Dynamiclib dlopen %{public}s", libName_.c_str());
    libHandle_ = dlopen(libName_.c_str(), RTLD_NOW);
    CHECK_RETURN_ELOG(
        libHandle_ == nullptr, "Dynamiclib::Dynamiclib dlopen name:%{public}s return null", libName_.c_str());
    MEDIA_INFO_LOG("Dynamiclib::Dynamiclib dlopen %{public}s success handle:%{public}u", libName_.c_str(),
        static_cast<uint32_t>(HANDLE_MASK & reinterpret_cast<uintptr_t>(libHandle_)));
    UpdateDynamiclibState(libName, LOADED);
}

Dynamiclib::~Dynamiclib()
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN(libHandle_ == nullptr);
    int ret = dlclose(libHandle_);
    MEDIA_INFO_LOG("Dynamiclib::~Dynamiclib dlclose name:%{public}s handle:%{public}u result:%{public}d",
        libName_.c_str(), static_cast<uint32_t>(HANDLE_MASK & reinterpret_cast<uintptr_t>(libHandle_)), ret);
    libHandle_ = nullptr;
    UpdateDynamiclibState(libName_, UNLOAD);
}

bool Dynamiclib::IsLoaded()
{
    return libHandle_ != nullptr;
}

void* Dynamiclib::GetFunction(const string& functionName)
{
    CAMERA_SYNC_TRACE_FMT("Dynamiclib::GetFunction %s", functionName.c_str());
    CHECK_RETURN_RET_ELOG(
        !IsLoaded(), nullptr, "Dynamiclib::GetFunction fail libname:%{public}s not loaded", libName_.c_str());

    void* handle = dlsym(libHandle_, functionName.c_str());
    CHECK_RETURN_RET_ELOG(
        handle == nullptr, nullptr, "Dynamiclib::GetFunction fail function:%{public}s not find", functionName.c_str());
    MEDIA_INFO_LOG("Dynamiclib::GetFunction %{public}s success", functionName.c_str());
    return handle;
}
shared_ptr<Dynamiclib> CameraDynamicLoader::GetDynamiclibNoLock(const string& libName)
{
    auto loadedIterator = g_dynamiclibMap.find(libName);
    CHECK_RETURN_RET_ILOG(loadedIterator != g_dynamiclibMap.end(), loadedIterator->second,
        "Dynamiclib::GetDynamiclib %{public}s by cache", libName.c_str());

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
    CHECK_RETURN_RET_ELOG(
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
// LCOV_EXCL_START
void CameraDynamicLoader::LoadDynamiclibAsync(const std::string& libName)
{
    CAMERA_SYNC_TRACE;
    unique_lock<mutex> asyncLock(g_asyncLoadingMutex);
    MEDIA_INFO_LOG("CameraDynamicLoader::LoadDynamiclibAsync %{public}s", libName.c_str());
    CHECK_RETURN_ILOG(g_isAsyncLoading != AsyncLoadingState::NONE,
        "CameraDynamicLoader::LoadDynamiclibAsync %{public}s is loading", libName.c_str());
    g_isAsyncLoading = AsyncLoadingState::PREPARE;
    thread asyncThread = thread([libName]() {
        SetVipPrioThread(VIP_PRIO_LEVEL_10);
        CancelFreeDynamicLibDelayed(libName);
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

void CameraDynamicLoader::FreeDynamiclibNoLock(const string& libName)
{
    CAMERA_SYNC_TRACE;
    auto loadedIterator = g_dynamiclibMap.find(libName);
    CHECK_RETURN(loadedIterator == g_dynamiclibMap.end());
    MEDIA_INFO_LOG("Dynamiclib::FreeDynamiclib %{public}s lib use count is:%{public}ld", libName.c_str(),
        loadedIterator->second.use_count());

    weak_ptr<Dynamiclib> weaklib = loadedIterator->second;
    g_weakDynamiclibMap[libName] = weaklib;
    g_dynamiclibMap.erase(loadedIterator);
}

void CameraDynamicLoader::CancelFreeDynamicLibDelayed(const std::string& libName)
{
    auto closeTimer = GetDelayedCloseTimer(libName);
    CHECK_RETURN(!closeTimer);
    // Cancel old task
    bool isCancelSuccess = closeTimer->CancelTask();
    MEDIA_INFO_LOG("CameraDynamicLoader::CancelFreeDynamicLibDelayed %{public}s CancelTask success:%{public}d",
        libName.c_str(), isCancelSuccess);
    RemoveDelayedCloseTimer(libName);
}

void CameraDynamicLoader::FreeDynamicLibDelayed(const std::string& libName, uint32_t delayMs)
{
    MEDIA_INFO_LOG(
        "CameraDynamicLoader::FreeDynamicLibDelayed %{public}s  delayMs:%{public}d", libName.c_str(), delayMs);
    CancelFreeDynamicLibDelayed(libName);
    shared_ptr<SimpleTimer> closeTimer = make_shared<SimpleTimer>([&, libName]() {
        lock_guard<mutex> lock(g_libMutex);
        FreeDynamiclibNoLock(libName);
    });
    bool isStartSuccess = closeTimer->StartTask(delayMs);

    SetDelayedCloseTimer(libName, closeTimer);
    MEDIA_INFO_LOG("CameraDynamicLoader::FreeDynamicLibDelayed %{public}s StartTask success:%{public}d",
        libName.c_str(), isStartSuccess);
}
// LCOV_EXCL_STOP
} // namespace CameraStandard
} // namespace OHOS