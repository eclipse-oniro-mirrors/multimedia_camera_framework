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

#include "camera_sensor_plugin.h"

namespace OHOS {
namespace Rosen {
namespace {
    constexpr uint32_t SLEEP_TIME_US = 10000;
}

static void *g_handle = nullptr;

bool LoadMotionSensor(void)
{
    if (g_handle != nullptr) {
        MEDIA_INFO_LOG("motion plugin has already exits.");
        return true;
    }
    int32_t cnt = 0;
    int32_t retryTimes = 3;
    do {
        cnt++;
        g_handle = dlopen(PLUGIN_SO_PATH.c_str(), RTLD_LAZY);
        MEDIA_INFO_LOG("dlopen %{public}s, retry cnt: %{public}d", PLUGIN_SO_PATH.c_str(), cnt);
        usleep(SLEEP_TIME_US);
    } while (!g_handle && cnt < retryTimes);
    return g_handle != nullptr;
}

void UnloadMotionSensor(void)
{
    MEDIA_INFO_LOG("unload motion plugin.");
    if (g_handle != nullptr) {
        dlclose(g_handle);
        g_handle = nullptr;
    }
}

__attribute__((no_sanitize("cfi"))) bool SubscribeCallback(int32_t motionType, OnMotionChangedPtr callback)
{
    if (callback == nullptr) {
        MEDIA_ERR_LOG("callback is nullptr");
        return false;
    }
    if (g_handle == nullptr) {
        MEDIA_ERR_LOG("g_handle is nullptr");
        return false;
    }
    MotionSubscribeCallbackPtr func = (MotionSubscribeCallbackPtr)(dlsym(g_handle, "MotionSubscribeCallback"));
    const char* dlsymError = dlerror();
    if  (dlsymError) {
        MEDIA_INFO_LOG("dlsym error: %{public}s", dlsymError);
        return false;
    }
    return func(motionType, callback);
}

__attribute__((no_sanitize("cfi"))) bool UnsubscribeCallback(int32_t motionType, OnMotionChangedPtr callback)
{
    if (callback == nullptr) {
        MEDIA_ERR_LOG("callback is nullptr");
        return false;
    }
    if (g_handle == nullptr) {
        MEDIA_ERR_LOG("g_handle is nullptr");
        return false;
    }
    MotionUnsubscribeCallbackPtr func =
        (MotionUnsubscribeCallbackPtr)(dlsym(g_handle, "MotionUnsubscribeCallback"));
    const char* dlsymError = dlerror();
    if  (dlsymError) {
        MEDIA_ERR_LOG("dlsym error: %{public}s", dlsymError);
        return false;
    }
    return func(motionType, callback);
}
}
}