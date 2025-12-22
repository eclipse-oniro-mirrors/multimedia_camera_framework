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

#ifndef CAMERA_BEAUTY_NOTIFICATION_H
#define CAMERA_BEAUTY_NOTIFICATION_H

#include <atomic>

#include "camera_datashare_helper.h"
#include "camera_log.h"
#include "camera_util.h"
#include "refbase.h"

namespace OHOS {
namespace CameraStandard {

class CameraBeautyNotification : public RefBase {
public:
    CameraBeautyNotification();
    ~CameraBeautyNotification();
    static sptr<CameraBeautyNotification> GetInstance();
    void PublishNotification(bool isRecordTimes);
    void CancelNotification();
    void SetBeautyStatus(int32_t beautyStatus);
    int32_t GetBeautyStatus();
    void SetBeautyTimes(int32_t beautyTimes);
    int32_t GetBeautyTimes();
    int32_t GetBeautyStatusFromDataShareHelper(int32_t &beautyStatus);
    int32_t SetBeautyStatusFromDataShareHelper(int32_t beautyStatus);
    int32_t GetBeautyTimesFromDataShareHelper(int32_t &times);
    int32_t SetBeautyTimesFromDataShareHelper(int32_t times);

private:
    void InitBeautyStatus();

    static sptr<CameraBeautyNotification> instance_;
    static std::mutex instanceMutex_;
    std::mutex notificationMutex_;
    std::atomic<int32_t> beautyTimes_ = 0;
    std::atomic<int32_t> beautyStatus_ = 0;
    std::shared_ptr<CameraDataShareHelper> cameraDataShareHelper_ = nullptr;
    bool isNotificationSuccess_ = false;
};

} // namespace CameraStandard
} // namespace OHOS
#endif // CAMERA_BEAUTY_NOTIFICATION_H
