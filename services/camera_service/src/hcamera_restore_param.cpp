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

#include "hcamera_restore_param.h"
#include "camera_util.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
HCameraRestoreParam::HCameraRestoreParam(std::string clientName, std::string cameraId,
    std::vector<StreamInfo_V1_1> streamInfos,
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings, RestoreParamTypeOhos restoreParamType,
    int startActiveTime)
{
    MEDIA_DEBUG_LOG("Enter Into HCameraRestoreParam::HCameraRestoreParam");
    mClientName = clientName;
    mCameraId = cameraId;
    mStreamInfos = streamInfos;
    mSettings = settings;
    mRestoreParamType = restoreParamType;
    mStartActiveTime = startActiveTime;
}

HCameraRestoreParam::HCameraRestoreParam(std::string clientName, std::string cameraId)
{
    MEDIA_DEBUG_LOG("Enter Into HCameraRestoreParam::HCameraRestoreParam");
    mClientName = clientName;
    mCameraId = cameraId;
}

HCameraRestoreParam::~HCameraRestoreParam()
{}

std::vector<StreamInfo_V1_1> HCameraRestoreParam::GetStreamInfo()
{
    return mStreamInfos;
}

std::shared_ptr<OHOS::Camera::CameraMetadata> HCameraRestoreParam::GetSetting()
{
    return mSettings;
}

RestoreParamTypeOhos HCameraRestoreParam::GetRestoreParamType()
{
    return mRestoreParamType;
}

timeval HCameraRestoreParam::GetCloseCameraTime()
{
    return mCloseCameraTime;
}

int HCameraRestoreParam::GetStartActiveTime()
{
    return mStartActiveTime;
}

void HCameraRestoreParam::SetCloseCameraTime(timeval closeCameraTime)
{
    mCloseCameraTime = closeCameraTime;
}

std::string HCameraRestoreParam::GetCameraId()
{
    return mCameraId;
}

std::string HCameraRestoreParam::GetClientName()
{
    return mClientName;
}

void HCameraRestoreParam::SetCameraOpMode(int32_t opMode)
{
    mOpMode = opMode;
}

int32_t HCameraRestoreParam::GetCameraOpMode()
{
    return mOpMode;
}

void HCameraRestoreParam::SetStreamInfo(std::vector<StreamInfo_V1_1> &streamInfos)
{
    mStreamInfos = streamInfos;
}

void HCameraRestoreParam::SetSetting(std::shared_ptr<OHOS::Camera::CameraMetadata>& settings)
{
    mSettings = settings;
}

void HCameraRestoreParam::SetRestoreParamType(RestoreParamTypeOhos restoreParamType)
{
    mRestoreParamType = restoreParamType;
}

void HCameraRestoreParam::SetStartActiveTime(int activeTime)
{
    mStartActiveTime = activeTime;
}

int HCameraRestoreParam::GetFlodStatus()
{
    return mFoldStatus;
}

void HCameraRestoreParam::SetFoldStatus(int foldStaus)
{
    mFoldStatus = foldStaus;
}
} // namespace CameraStandard
} // namespace OHOS
