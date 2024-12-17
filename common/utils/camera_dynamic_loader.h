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

#ifndef OHOS_CAMERA_DYNAMIC_LOADER_H
#define OHOS_CAMERA_DYNAMIC_LOADER_H

#include <string>

namespace OHOS {
namespace CameraStandard {
using namespace std;

const std::string MEDIA_LIB_SO = "libcamera_dynamic_medialibrary.z.so";

class Dynamiclib {
public:
    explicit Dynamiclib(const std::string& libName);
    ~Dynamiclib();
    bool IsLoaded();
    void* GetFunction(const std::string& functionName);

private:
    std::string libName_;
    void* libHandle_ = nullptr;
};

class CameraDynamicLoader {
public:
    static std::shared_ptr<Dynamiclib> GetDynamiclib(const std::string& libName);
    static void LoadDynamiclibAsync(const std::string& libName);
    static void FreeDynamiclib(const std::string& libName);

private:
    explicit CameraDynamicLoader() = delete;
    CameraDynamicLoader(const CameraDynamicLoader&) = delete;
    CameraDynamicLoader& operator=(const CameraDynamicLoader&) = delete;

    static std::shared_ptr<Dynamiclib> GetDynamiclibNoLock(const std::string& libName);
};

} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DYNAMIC_LOADER_H