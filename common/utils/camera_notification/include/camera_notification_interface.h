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

#ifndef OHOS_CAMERA_NOTIFICATION_INTERFACE_H
#define OHOS_CAMERA_NOTIFICATION_INTERFACE_H

#include <stdint.h>
#include <string>

/**
 * @brief Internal usage only, for camera framework interacts with camera notification related interfaces.
 * @since 12
 */
namespace OHOS::CameraStandard {
static const std::string EVENT_CAMERA_BEAUTY_NOTIFICATION = "CAMERA_BEAUTY_NOTIFICATION";
static const std::string BEAUTY_NOTIFICATION_ACTION_PARAM = "currentFlag";
static const int32_t BEAUTY_STATUS_OFF = 0;
static const int32_t BEAUTY_STATUS_ON = 1;
static const int32_t BEAUTY_LEVEL = 100;
static const int32_t CONTROL_FLAG_LIMIT = 3;

class CameraNotificationIntf {
public:
    virtual ~CameraNotificationIntf() = default;
    virtual int32_t PublishBeautyNotification(bool isRecordTimes, int32_t beautyStatus, int32_t beautyTimes) = 0;
    virtual int32_t CancelBeautyNotification() = 0;
};
} // namespace OHOS::CameraStandard
#endif // OHOS_CAMERA_NOTIFICATION_INTERFACE_H