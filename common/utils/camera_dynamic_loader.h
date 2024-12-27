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

#include <map>
#include <memory>
#include <mutex>
#include <string>

namespace OHOS {
namespace CameraStandard {
using namespace std;

const std::string MEDIA_LIB_SO = "libcamera_dynamic_medialibrary.z.so";

class CameraDynamicLoader {
public:
    static CameraDynamicLoader* GetInstance()
    {
        std::call_once(onceFlag, []() { instance.reset(new CameraDynamicLoader()); });
        return instance.get();
    };
    ~CameraDynamicLoader();

    void* OpenDynamicHandle(std::string dynamicLibrary);
    void CloseDynamicHandle(std::string dynamicLibrary);
    void* GetFunction(std::string dynamicLibrary, std::string function);
    inline bool EndsWith(const std::string& str, const std::string& suffix)
    {
        if (str.length() >= suffix.length()) {
            return str.compare(str.length() - suffix.length(), suffix.length(), suffix) == 0;
        }
        return false;
    }

private:
    CameraDynamicLoader(const CameraDynamicLoader&) = delete;
    CameraDynamicLoader& operator=(const CameraDynamicLoader&) = delete;
    static std::unique_ptr<CameraDynamicLoader> instance;
    static std::once_flag onceFlag;
    CameraDynamicLoader();
    std::map<std::string, void *> dynamicLibHandle_;
    std::recursive_mutex libLock_;
};

}  // namespace Camera
}  // namespace OHOS
#endif // OHOS_CAMERA_DYNAMIC_LOADER_H