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

#ifndef FRAMEWORKS_TAIHE_INCLUDE_CAMERA_LIB_MANAGER_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_CAMERA_LIB_MANAGER_TAIHE_H
#include <memory>
#include <string>
#include <mutex>
#include <dlfcn.h>

#include "camera_log.h"

namespace Ani {
namespace Camera {
const std::string LIB_CAMERA_NAPI_SO = "libcamera_napi.z.so";

class LibHandle {
public:
    explicit LibHandle(const std::string& lib_name) : lib_name_(lib_name)
    {
        handle_ = dlopen(lib_name.c_str(), RTLD_LAZY | RTLD_LOCAL);
        if (!handle_) {
            MEDIA_ERR_LOG("%{public}s dlopen failed, lib: %{public}s, error: %{public}s", __func__,
                LIB_CAMERA_NAPI_SO.c_str(), dlerror());
        }
    }

    ~LibHandle()
    {
        if (handle_) {
            dlclose(handle_);
        }
    }

    bool IsValid() const { return handle_ != nullptr; }
    void* GetHandlePtr() const { return handle_; }
    
    LibHandle(const LibHandle&) = delete;
    LibHandle& operator=(const LibHandle&) = delete;
    
private:
    std::string lib_name_;
    void* handle_;
};

class LibManager {
public:
    static std::shared_ptr<LibHandle> GetCameraNapiLibHandle()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!instance_) {
            instance_ = std::make_shared<LibHandle>(LIB_CAMERA_NAPI_SO);
            if (!instance_->IsValid()) {
                instance_.reset();
            }
        }
        return instance_;
    }

    template <typename Func>
    static bool GetSymbol(const char* name, Func& outFunc)
    {
        auto lib = GetCameraNapiLibHandle();
        if (!lib || !lib->IsValid()) {
            MEDIA_ERR_LOG("%{public}s Library not loaded when getting symbol: %{public}s", __func__, name);
            return false;
        }
        
        void* symbol = dlsym(lib->GetHandlePtr(), name);
        if (!symbol) {
            MEDIA_ERR_LOG("%{public}s Failed to find symbol: %{public}s", __func__, name);
            return false;
        }
        
        outFunc = reinterpret_cast<Func>(symbol);
        return true;
    }
    
private:
    static std::mutex mutex_;
    static std::shared_ptr<LibHandle> instance_;
};

} // namespace Camera
} // namespace Ani

#endif // FRAMEWORKS_TAIHE_INCLUDE_CAMERA_TRANSFER_TAIHE_H