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

#ifndef OHOS_CAMERA_CAMERA_MANAGER_FOR_SYS_H
#define OHOS_CAMERA_CAMERA_MANAGER_FOR_SYS_H

#include <mutex>
#include <refbase.h>

#include "output/depth_data_output.h"
#include "session/capture_session_for_sys.h"
namespace OHOS {
namespace CameraStandard {

class CameraManagerForSys : public RefBase {
public:
    virtual ~CameraManagerForSys();
    static sptr<CameraManagerForSys>& GetInstance();

    sptr<CaptureSessionForSys> CreateCaptureSessionForSysImpl(SceneMode mode, sptr<ICaptureSession> session);
    sptr<CaptureSessionForSys> CreateCaptureSessionForSys(SceneMode mode);
    int32_t CreateCaptureSessionForSys(sptr<CaptureSessionForSys>& pCaptureSession, SceneMode mode);
    int CreateDepthDataOutput(DepthProfile& depthProfile, sptr<IBufferProducer> &surface,
                              sptr<DepthDataOutput>* pDepthDataOutput);

private:
    explicit CameraManagerForSys();
    static sptr<CameraManagerForSys> g_cameraManagerForSys;
    static std::mutex g_sysInstanceMutex;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_CAMERA_MANAGER_FOR_SYS_H