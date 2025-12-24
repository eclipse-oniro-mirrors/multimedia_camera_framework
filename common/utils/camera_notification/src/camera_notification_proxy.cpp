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

#include "camera_notification_proxy.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
CameraNotificationProxy::CameraNotificationProxy(std::shared_ptr<Dynamiclib> cameraNotificationLib,
    std::shared_ptr<CameraNotificationIntf> cameraNotificationIntf) : cameraNotificationLib_(cameraNotificationLib),
    cameraNotificationIntf_(cameraNotificationIntf)
{
    MEDIA_DEBUG_LOG("CameraNotificationProxy constructor");
    CHECK_RETURN_ELOG(cameraNotificationLib_ == nullptr, "cameraNotificationLib_ is nullptr");
    CHECK_RETURN_ELOG(cameraNotificationIntf_ == nullptr, "cameraNotificationIntf_ is nullptr");
}

CameraNotificationProxy::~CameraNotificationProxy()
{
    MEDIA_DEBUG_LOG("CameraNotificationProxy destructor");
}

typedef CameraNotificationIntf* (*CreateCameraNotificationIntf)();
std::shared_ptr<CameraNotificationProxy> CameraNotificationProxy::CreateCameraNotificationProxy()
{
    MEDIA_DEBUG_LOG("CreateCameraNotificationProxy start");
    auto dynamiclib = CameraDynamicLoader::GetDynamiclib(CAMERA_NOTIFICATION_SO);
    CHECK_RETURN_RET_ELOG(dynamiclib == nullptr, nullptr, "get dynamiclib fail");
    CreateCameraNotificationIntf createCameraNotificationIntf =
        (CreateCameraNotificationIntf)dynamiclib->GetFunction("createCameraNotificationIntf");
    CHECK_RETURN_RET_ELOG(createCameraNotificationIntf == nullptr, nullptr, "get createCameraNotificationIntf fail");
    CameraNotificationIntf* cameraNotificationIntf = createCameraNotificationIntf();
    CHECK_RETURN_RET_ELOG(cameraNotificationIntf == nullptr, nullptr, "get CameraNotificationIntf fail");
    std::shared_ptr<CameraNotificationProxy> cameraNotificationProxy = std::make_shared<CameraNotificationProxy>(
        dynamiclib, std::shared_ptr<CameraNotificationIntf>(cameraNotificationIntf));
    return cameraNotificationProxy;
}

int32_t CameraNotificationProxy::PublishBeautyNotification(bool isRecordTimes, int32_t beautyStatus,
    int32_t beautyTimes)
{
    MEDIA_DEBUG_LOG("PublishBeautyNotification start");
    CHECK_RETURN_RET_ELOG(cameraNotificationIntf_ == nullptr, -1, "cameraNotificationIntf_ is nullptr");
    return cameraNotificationIntf_->PublishBeautyNotification(isRecordTimes, beautyStatus, beautyTimes);
}

int32_t CameraNotificationProxy::CancelBeautyNotification()
{
    MEDIA_DEBUG_LOG("CancelBeautyNotification start");
    CHECK_RETURN_RET_ELOG(cameraNotificationIntf_ == nullptr, -1, "cameraNotificationIntf_ is nullptr");
    return cameraNotificationIntf_->CancelBeautyNotification();
}
}  // namespace CameraStandard
}  // namespace OHOS
