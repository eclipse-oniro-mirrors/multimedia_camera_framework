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
 
#ifndef CAMERA_DISPLAY_PLUGIN_H
#define CAMERA_DISPLAY_PLUGIN_H

#include <mutex>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <refbase.h>

namespace OHOS {
namespace CameraStandard {

class CameraDisplayPlugin : public RefBase {
public:
    CameraDisplayPlugin();
    ~CameraDisplayPlugin();
    CameraDisplayPlugin(const CameraDisplayPlugin&) = delete;
    CameraDisplayPlugin& operator=(const CameraDisplayPlugin&) = delete;

    static sptr<CameraDisplayPlugin> GetInstance();
    bool LoadSo();
    void UnLoadSo();
    void* GetFunction(const std::string& functionName);

private:
    void* handle_ = nullptr;
    std::mutex mutex_;

    bool CheckSoExists(const std::string& soPath) const;
};
}
}
#endif /* CAMERA_DISPLAY_PLUGIN_H */
