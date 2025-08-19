/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
// LCOV_EXCL_START
#include "camera_beauty_notification.h"
#include "camera_dynamic_loader.h"
#include "camera_notification_proxy.h"
#include "string_ex.h"

namespace OHOS {
namespace CameraStandard {
typedef int32_t (*PublishBeautyNotification)(bool, int32_t, int32_t);
typedef int32_t (*CancelBeautyNotification)();

sptr<CameraBeautyNotification> CameraBeautyNotification::instance_ = nullptr;
std::mutex CameraBeautyNotification::instanceMutex_;

CameraBeautyNotification::CameraBeautyNotification()
{
    InitBeautyStatus();
}

CameraBeautyNotification::~CameraBeautyNotification()
{}

sptr<CameraBeautyNotification> CameraBeautyNotification::GetInstance()
{
    CHECK_RETURN_RET(instance_ != nullptr, instance_);
    std::lock_guard<std::mutex> lock(instanceMutex_);
    CHECK_RETURN_RET(instance_ != nullptr, instance_);
    instance_ = new (std::nothrow) CameraBeautyNotification();
    return instance_;
}

void CameraBeautyNotification::PublishNotification(bool isRecordTimes)
{
    std::lock_guard<std::mutex> lock(notificationMutex_);
    isNotificationSuccess_ = false;
    int32_t beautyStatus = GetBeautyStatus();
    int32_t beautyTimes = GetBeautyTimes();

    std::shared_ptr<CameraNotificationProxy> cameraNotificationProxy =
        CameraNotificationProxy::CreateCameraNotificationProxy();
    int32_t ret = cameraNotificationProxy->PublishBeautyNotification(isRecordTimes, beautyStatus, beautyTimes);
    MEDIA_INFO_LOG("CameraBeautyNotification::PublishNotification result = %{public}d", ret);
    isNotificationSuccess_ = (ret == CAMERA_OK);
    bool isSetTimes = (ret == CAMERA_OK) && (beautyTimes < CONTROL_FLAG_LIMIT) && isRecordTimes;
    CHECK_RETURN(!isSetTimes);
    beautyTimes_.operator++();
    SetBeautyTimesFromDataShareHelper(GetBeautyTimes());
}

void CameraBeautyNotification::CancelNotification()
{
    std::lock_guard<std::mutex> lock(notificationMutex_);
    CHECK_RETURN(!isNotificationSuccess_);
    isNotificationSuccess_ = false;

    std::shared_ptr<CameraNotificationProxy> cameraNotificationProxy =
        CameraNotificationProxy::CreateCameraNotificationProxy();
    int32_t ret = cameraNotificationProxy->CancelBeautyNotification();
    MEDIA_INFO_LOG("CameraBeautyNotification::CancelNotification result = %{public}d", ret);
}

void CameraBeautyNotification::SetBeautyStatus(int32_t beautyStatus)
{
    beautyStatus_.store(beautyStatus);
}

int32_t CameraBeautyNotification::GetBeautyStatus()
{
    return beautyStatus_.load();
}

void CameraBeautyNotification::SetBeautyTimes(int32_t beautyTimes)
{
    beautyTimes_.store(beautyTimes);
}

int32_t CameraBeautyNotification::GetBeautyTimes()
{
    return beautyTimes_.load();
}

int32_t CameraBeautyNotification::GetBeautyStatusFromDataShareHelper(int32_t &beautyStatus)
{
    if (cameraDataShareHelper_ == nullptr) {
        cameraDataShareHelper_ = std::make_shared<CameraDataShareHelper>();
    }
    std::string value = "";
    auto ret = cameraDataShareHelper_->QueryOnce(PREDICATES_CAMERA_BEAUTY_STATUS, value);
    if (ret != CAMERA_OK) {
        beautyStatus = BEAUTY_STATUS_OFF;
    } else {
        int32_t convertedValue = 0;
        if (!StrToInt(value, convertedValue)) {
            MEDIA_INFO_LOG("Convert value to int32_t failed");
            beautyStatus = 0;
            return CAMERA_ALLOC_ERROR;
        }
        beautyStatus = convertedValue;
    }
    return CAMERA_OK;
}

int32_t CameraBeautyNotification::SetBeautyStatusFromDataShareHelper(int32_t beautyStatus)
{
    if (cameraDataShareHelper_ == nullptr) {
        cameraDataShareHelper_ = std::make_shared<CameraDataShareHelper>();
    }
    auto ret = cameraDataShareHelper_->UpdateOnce(PREDICATES_CAMERA_BEAUTY_STATUS, std::to_string(beautyStatus));
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, CAMERA_ALLOC_ERROR, "SetBeautyStatusFromDataShareHelper UpdateOnce fail.");
    return CAMERA_OK;
}

int32_t CameraBeautyNotification::GetBeautyTimesFromDataShareHelper(int32_t &times)
{
    if (cameraDataShareHelper_ == nullptr) {
        cameraDataShareHelper_ = std::make_shared<CameraDataShareHelper>();
    }
    std::string value = "";
    auto ret = cameraDataShareHelper_->QueryOnce(PREDICATES_CAMERA_BEAUTY_TIMES, value);
    if (ret != CAMERA_OK) {
        times = 0;
    } else {
        int32_t convertedValue = 0;
        if (!StrToInt(value, convertedValue)) {
            MEDIA_INFO_LOG("Convert value to int32_t failed");
            times = 0;
            return CAMERA_ALLOC_ERROR;
        }
        times = convertedValue;
    }
    return CAMERA_OK;
}

int32_t CameraBeautyNotification::SetBeautyTimesFromDataShareHelper(int32_t times)
{
    if (cameraDataShareHelper_ == nullptr) {
        cameraDataShareHelper_ = std::make_shared<CameraDataShareHelper>();
    }
    auto ret = cameraDataShareHelper_->UpdateOnce(PREDICATES_CAMERA_BEAUTY_TIMES, std::to_string(times));
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, CAMERA_ALLOC_ERROR, "SetBeautyTimesFromDataShareHelper UpdateOnce fail.");
    return CAMERA_OK;
}

void CameraBeautyNotification::InitBeautyStatus()
{
    int32_t beautyStatus = BEAUTY_STATUS_OFF;
    int32_t times = 0;
    GetBeautyStatusFromDataShareHelper(beautyStatus);
    GetBeautyTimesFromDataShareHelper(times);
    MEDIA_INFO_LOG("InitBeautyStatus beautyStatus = %{public}d, times = %{public}d", beautyStatus, times);
    SetBeautyStatus(beautyStatus);
    SetBeautyTimes(times);
}
} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP