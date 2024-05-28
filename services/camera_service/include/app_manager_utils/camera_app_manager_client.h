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
 
#ifndef OHOS_CAMERA_CAMERA_APP_MANAGER_CLIENT_H
#define OHOS_CAMERA_CAMERA_APP_MANAGER_CLIENT_H
 
#include "app_mgr_client.h"
#include <cstdint>
#include <memory>
#include <mutex>
#include "refbase.h"
 
namespace OHOS {
namespace CameraStandard {
class CameraAppManagerClient : public RefBase {
public:
    static sptr<CameraAppManagerClient>& GetInstance();
    ~CameraAppManagerClient();
 
    int32_t GetProcessState(int32_t pid);
private:
    CameraAppManagerClient();
    static std::mutex instanceMutex_;
    static sptr<CameraAppManagerClient> cameraAppManagerClient_;
    std::shared_ptr<AppExecFwk::AppMgrClient> appMgrHolder_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif