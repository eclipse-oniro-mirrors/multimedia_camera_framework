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
#include "image_source.h"
#include "int_wrapper.h"
#include "ipc_skeleton.h"
#include "locale_config.h"
#include "notification_helper.h"
#include "notification_normal_content.h"
#include "notification_request.h"
#include "os_account_manager.h"
#include "pixel_map.h"
#include "refbase.h"
#include "want_agent_helper.h"
#include "want_agent_info.h"

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
    std::string GetSystemStringByName(std::string name);
    void GetPixelMap();
    std::shared_ptr<Notification::NotificationNormalContent> CreateNotificationNormalContent(int32_t beautyStatus);
    void SetActionButton(const std::string& buttonName, Notification::NotificationRequest& request,
        int32_t beautyStatus);
    Global::Resource::RState GetMediaDataByName(std::string name, size_t& len, std::unique_ptr<uint8_t[]> &outValue,
        uint32_t density = 0);
    void InitResourceManager();
    void RefreshResConfig();

    static sptr<CameraBeautyNotification> instance_;
    static std::mutex instanceMutex_;

    std::mutex notificationMutex_;
    std::atomic<int32_t> beautyTimes_ = 0;
    std::atomic<int32_t> beautyStatus_ = 0;
    std::shared_ptr<Media::PixelMap> iconPixelMap_ = nullptr;
    std::shared_ptr<CameraDataShareHelper> cameraDataShareHelper_ = nullptr;
    Global::Resource::ResourceManager *resourceManager_ = nullptr;
    Global::Resource::ResConfig *resConfig_ = nullptr;
    bool isNotificationSuccess_ = false;
};

} // namespace CameraStandard
} // namespace OHOS
#endif // CAMERA_BEAUTY_NOTIFICATION_H