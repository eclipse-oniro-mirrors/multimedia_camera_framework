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

#ifndef CAMERA_NOTIFICATION_PROXY_H
#define CAMERA_NOTIFICATION_PROXY_H

#include "camera_notification_interface.h"
#include "camera_dynamic_loader.h"

namespace OHOS {
namespace CameraStandard {
class CameraNotificationProxy : public CameraNotificationIntf {
public:
    explicit CameraNotificationProxy(std::shared_ptr<Dynamiclib> cameraNotificationLib,
        std::shared_ptr<CameraNotificationIntf> CameraNotificationIntf);

    ~CameraNotificationProxy() override;
    static std::shared_ptr<CameraNotificationProxy> CreateCameraNotificationProxy();
    int32_t PublishBeautyNotification(bool isRecordTimes, int32_t beautyStatus, int32_t beautyTimes) override;
    int32_t CancelBeautyNotification() override;

private:
    // Keep the order of members in this class, the bottom member will be destroyed first
    std::shared_ptr<Dynamiclib> cameraNotificationLib_ = {nullptr};
    std::shared_ptr<CameraNotificationIntf> cameraNotificationIntf_ = {nullptr};
};
} // namespace CameraStandard
} // namespace OHOS
#endif // CAMERA_NOTIFICATION_PROXY_H
