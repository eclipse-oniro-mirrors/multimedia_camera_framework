/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_RESTORE_PARAM_H
#define OHOS_CAMERA_RESTORE_PARAM_H

#include <iostream>
#include <refbase.h>
#include <sys/time.h>

#include "camera/v1_2/types.h"
#include "camera_metadata_info.h"
#include "icamera_service.h"

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_0;
using OHOS::HDI::Camera::V1_1::StreamInfo_V1_1;
class HCameraRestoreParam : virtual public RefBase {
public:
    HCameraRestoreParam(std::string clientName, std::string cameraId, std::vector<StreamInfo_V1_1> streamInfos,
        std::shared_ptr<OHOS::Camera::CameraMetadata> settings,
        RestoreParamTypeOhos restoreParamType, int startActiveTime);
    HCameraRestoreParam(std::string clientName, std::string cameraId);
    ~HCameraRestoreParam();

    std::vector<StreamInfo_V1_1> GetStreamInfo();
    std::shared_ptr<OHOS::Camera::CameraMetadata> GetSetting();
    RestoreParamTypeOhos GetRestoreParamType();
    timeval GetCloseCameraTime();
    int GetStartActiveTime();
    std::string GetClientName();
    std::string GetCameraId();
    int32_t GetCameraOpMode();

    void SetStreamInfo(std::vector<StreamInfo_V1_1> &streamInfos);
    void SetSetting(std::shared_ptr<OHOS::Camera::CameraMetadata>& settings);
    void SetRestoreParamType(RestoreParamTypeOhos restoreParamType);
    void SetStartActiveTime(int activeTime);
    void SetCloseCameraTime(timeval closeCameraTime);
    void SetCameraOpMode(int32_t opMode);
    int GetFlodStatus();
    void SetFoldStatus(int foldStaus);

private:
    std::string mClientName;
    std::string mCameraId;
    std::vector<StreamInfo_V1_1> mStreamInfos;
    std::shared_ptr<OHOS::Camera::CameraMetadata> mSettings;
    timeval mCloseCameraTime;
    RestoreParamTypeOhos mRestoreParamType;
    int mStartActiveTime = 0;
    int32_t mOpMode = 0;
    int mFoldStatus = 0;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_STREAM_COMMON_H
