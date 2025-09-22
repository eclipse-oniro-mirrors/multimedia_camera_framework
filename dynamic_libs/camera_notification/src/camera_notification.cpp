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
#include "camera_notification.h"

namespace OHOS {
namespace CameraStandard {

static constexpr int32_t CAMERA_UID = 1047;
const int BEAUTY_NOTIFICATION_ID = 1047001;
const std::string BEAUTY_NOTIFICATION_TITLE = "title_adjust_beauty";
const std::string BEAUTY_NOTIFICATION_CONTENT_ON = "summary_closed_beauty";
const std::string BEAUTY_NOTIFICATION_CONTENT_OFF = "summary_opened_beauty";
const std::string BEAUTY_NOTIFICATION_BUTTON_ON = "open_beauty";
const std::string BEAUTY_NOTIFICATION_BUTTON_OFF = "close_beauty";
const uint32_t BEAUTY_NOTIFICATION_CLOSE_SOUND_FLAG = 1 << 0;
const uint32_t BEAUTY_NOTIFICATION_CONTROL_FLAG = 1 << 9;
const uint32_t BEAUTY_NOTIFICATION_LOCKSCREEN_FLAG = 1 << 1;
const uint32_t BEAUTY_NOTIFICATION_CLOSE_VIBRATION_FLAG = 1 << 4;
const std::string BEAUTY_NOTIFICATION_ICON_NAME = "ic_public_camera_beauty";
const std::string BEAUTY_NOTIFICATION_GROUP_NAME = "camera_beauty";
const int32_t ICON_WIDTH = 220;
const int32_t ICON_HEIGHT = 220;

int32_t CameraNotification::PublishBeautyNotification(bool isRecordTimes, int32_t beautyStatus, int32_t beautyTimes)
{
    std::shared_ptr<Notification::NotificationContent> content =
        std::make_shared<Notification::NotificationContent>(CreateNotificationNormalContent(beautyStatus));

    CHECK_RETURN_RET_ELOG(content == nullptr, -1, "Create notification content failed");

    Notification::NotificationRequest request;
    request.SetCreatorUid(CAMERA_UID);
    request.SetCreatorPid(getpid());

    int32_t userId;
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(CAMERA_UID, userId);

    request.SetCreatorUserId(userId);
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    request.SetDeliveryTime(duration.count());
    request.SetAutoDeletedTime(OHOS::Notification::NotificationConstant::INVALID_AUTO_DELETE_TIME);
    request.SetTapDismissed(false);
    request.SetSlotType(OHOS::Notification::NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request.SetNotificationId(BEAUTY_NOTIFICATION_ID);
    request.SetGroupName(BEAUTY_NOTIFICATION_GROUP_NAME);
    request.SetUnremovable(true);
    uint32_t baseFlag = BEAUTY_NOTIFICATION_CLOSE_SOUND_FLAG |
        BEAUTY_NOTIFICATION_CLOSE_VIBRATION_FLAG | BEAUTY_NOTIFICATION_LOCKSCREEN_FLAG;

    bool isBanner = beautyTimes < CONTROL_FLAG_LIMIT;
    if (isBanner) {
        request.SetNotificationControlFlags(baseFlag|BEAUTY_NOTIFICATION_CONTROL_FLAG);
    } else {
        request.SetNotificationControlFlags(baseFlag);
    }
    request.SetContent(content);

    GetPixelMap();
    if (iconPixelMap_ != nullptr) {
        request.SetLittleIcon(iconPixelMap_);
        request.SetBadgeIconStyle(Notification::NotificationRequest::BadgeStyle::LITTLE);
    }

    std::string buttonName = beautyStatus == BEAUTY_STATUS_OFF ? GetSystemStringByName(BEAUTY_NOTIFICATION_BUTTON_ON) :
        GetSystemStringByName(BEAUTY_NOTIFICATION_BUTTON_OFF);
    SetActionButton(buttonName, request, beautyStatus);

    return Notification::NotificationHelper::PublishNotification(request);
}

int32_t CameraNotification::CancelBeautyNotification()
{
    int32_t ret = Notification::NotificationHelper::CancelNotification(BEAUTY_NOTIFICATION_ID);
    resourceManager_ = nullptr;
    resConfig_ = nullptr;
    return ret;
}

std::shared_ptr<Notification::NotificationNormalContent> CameraNotification::CreateNotificationNormalContent(
    int32_t beautyStatus)
{
    std::shared_ptr<Notification::NotificationNormalContent> normalContent =
        std::make_shared<Notification::NotificationNormalContent>();
    CHECK_RETURN_RET_ELOG(normalContent == nullptr, nullptr, "Create normalContent failed");
    normalContent->SetTitle(GetSystemStringByName(BEAUTY_NOTIFICATION_TITLE));
    normalContent->SetText(beautyStatus == BEAUTY_STATUS_OFF ? GetSystemStringByName(BEAUTY_NOTIFICATION_CONTENT_ON) :
        GetSystemStringByName(BEAUTY_NOTIFICATION_CONTENT_OFF));
    return normalContent;
}

void CameraNotification::SetActionButton(const std::string& buttonName,
    Notification::NotificationRequest& request, int32_t beautyStatus)
{
    auto want = std::make_shared<AAFwk::Want>();
    want->SetAction(EVENT_CAMERA_BEAUTY_NOTIFICATION);

    std::shared_ptr<OHOS::AAFwk::WantParams> wantParams = std::make_shared<OHOS::AAFwk::WantParams>();
    sptr<OHOS::AAFwk::IInterface> intIt = OHOS::AAFwk::Integer::Box(beautyStatus);
    wantParams->SetParam(BEAUTY_NOTIFICATION_ACTION_PARAM, intIt);

    want->SetParams(*wantParams);
    std::vector<std::shared_ptr<AAFwk::Want>> wants;
    wants.push_back(want);

    std::vector<AbilityRuntime::WantAgent::WantAgentConstant::Flags> flags;
    flags.push_back(AbilityRuntime::WantAgent::WantAgentConstant::Flags::CONSTANT_FLAG);

    AbilityRuntime::WantAgent::WantAgentInfo wantAgentInfo(
        0, AbilityRuntime::WantAgent::WantAgentConstant::OperationType::SEND_COMMON_EVENT,
        flags, wants, wantParams
    );
    auto wantAgentDeal = AbilityRuntime::WantAgent::WantAgentHelper::GetWantAgent(wantAgentInfo);
    std::shared_ptr<Notification::NotificationActionButton> actionButtonDeal =
        Notification::NotificationActionButton::Create(nullptr, buttonName, wantAgentDeal);
    CHECK_RETURN_ILOG(actionButtonDeal == nullptr, "Create actionButtonDeal failed");
    request.AddActionButton(actionButtonDeal);
}

std::string CameraNotification::GetSystemStringByName(const std::string& name)
{
    InitResourceManager();
    std::string result;
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    resourceManager_->GetStringByName(name.c_str(), result);
    IPCSkeleton::SetCallingIdentity(identity);
    MEDIA_DEBUG_LOG("name: %{public}s, result: %{public}s", name.c_str(), result.c_str());
    return result;
}

void CameraNotification::GetPixelMap()
{
    CHECK_RETURN_ELOG(iconPixelMap_ != nullptr, "Pixel map already exists.");

    size_t len = 0;
    std::unique_ptr<uint8_t[]> data;
    Global::Resource::RState rstate = GetMediaDataByName(BEAUTY_NOTIFICATION_ICON_NAME.c_str(), len, data);
    CHECK_RETURN_ELOG(rstate != Global::Resource::RState::SUCCESS, "GetMediaDataByName failed");

    OHOS::Media::SourceOptions opts;
    uint32_t errorCode = 0;
    std::shared_ptr<ImageSourceProxy> imageSourceProxy = ImageSourceProxy::CreateImageSourceProxy();
    CHECK_RETURN_ELOG(imageSourceProxy == nullptr, "CreateImageSourceProxy failed");
    auto ret = imageSourceProxy->CreateImageSource(data.get(), len, opts, errorCode);
    MEDIA_INFO_LOG("CreateImageSource errorCode: %{public}d", static_cast<int32_t>(errorCode));
    CHECK_RETURN_ELOG(ret != 0, "CreateImageSource failed");
    OHOS::Media::DecodeOptions decodeOpts;
    decodeOpts.desiredSize = {ICON_WIDTH, ICON_HEIGHT};
    decodeOpts.desiredPixelFormat = OHOS::Media::PixelFormat::BGRA_8888;
    std::unique_ptr<Media::PixelMap> pixelMap = imageSourceProxy->CreatePixelMap(decodeOpts, errorCode);
    MEDIA_INFO_LOG("CreateImageSource errorCode: %{public}d", static_cast<int32_t>(errorCode));
    CHECK_RETURN_ELOG(pixelMap == nullptr, "Create icon pixel map failed,pixelMap is nullptr");
    iconPixelMap_ = std::move(pixelMap);
}

Global::Resource::RState CameraNotification::GetMediaDataByName(std::string name, size_t& len,
    std::unique_ptr<uint8_t[]> &outValue, uint32_t density)
{
    InitResourceManager();
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    Global::Resource::RState rstate = resourceManager_->GetMediaDataByName(name.c_str(), len, outValue);
    IPCSkeleton::SetCallingIdentity(identity);
    MEDIA_INFO_LOG("rstate: %{public}d", static_cast<int32_t>(rstate));
    return rstate;
}

void CameraNotification::InitResourceManager()
{
    if (!resourceManager_) {
        MEDIA_INFO_LOG("Init");
        resourceManager_ = Global::Resource::GetSystemResourceManagerNoSandBox();
    }
    if (!resConfig_) {
        resConfig_ = Global::Resource::CreateResConfig();
    }
    RefreshResConfig();
}
 
void CameraNotification::RefreshResConfig()
{
    std::string language = Global::I18n::LocaleConfig::GetSystemLanguage();
    CHECK_RETURN_ILOG(language.empty(), "Get system language failed, skip RefreshResConfig");
    UErrorCode status = U_ZERO_ERROR;
    icu::Locale locale = icu::Locale::forLanguageTag(language, status);
    bool isSupportZero = status != U_ZERO_ERROR;
    CHECK_RETURN_ILOG(isSupportZero, "forLanguageTag failed, errCode:%{public}d", status);
    CHECK_RETURN_ILOG(!resConfig_, "resConfig_ is nullptr");
    std::string region = Global::I18n::LocaleConfig::GetSystemRegion();
    resConfig_->SetLocaleInfo(locale.getLanguage(), locale.getScript(), region.c_str());
    CHECK_RETURN_ILOG(!resourceManager_, "resourceManager_ is nullptr");
    resourceManager_->UpdateResConfig(*resConfig_);
    MEDIA_INFO_LOG("Refresh success");
}

extern "C" CameraNotificationIntf *createCameraNotificationIntf()
{
    return new CameraNotification();
}
} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP