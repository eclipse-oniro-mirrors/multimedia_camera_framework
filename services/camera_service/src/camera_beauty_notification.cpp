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

#include "camera_beauty_notification.h"

namespace OHOS {
namespace CameraStandard {

sptr<CameraBeautyNotification> CameraBeautyNotification::instance_ = nullptr;
std::mutex CameraBeautyNotification::instanceMutex_;
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
const int32_t CONTROL_FLAG_LIMIT = 3;

CameraBeautyNotification::CameraBeautyNotification()
{
    InitBeautyStatus();
}

CameraBeautyNotification::~CameraBeautyNotification()
{}

sptr<CameraBeautyNotification> CameraBeautyNotification::GetInstance()
{
    CHECK_ERROR_RETURN_RET(instance_ != nullptr, instance_);
    std::lock_guard<std::mutex> lock(instanceMutex_);
    CHECK_ERROR_RETURN_RET(instance_ != nullptr, instance_);
    instance_ = new (std::nothrow) CameraBeautyNotification();
    return instance_;
}

void CameraBeautyNotification::PublishNotification(bool isRecordTimes)
{
    std::lock_guard<std::mutex> lock(notificationMutex_);
    isNotificationSuccess_ = false;
    int32_t beautyStatus = GetBeautyStatus();
    int32_t beautyTimes = GetBeautyTimes();
    std::shared_ptr<Notification::NotificationContent> content =
        std::make_shared<Notification::NotificationContent>(CreateNotificationNormalContent(beautyStatus));

    if (content == nullptr) {
        MEDIA_ERR_LOG("Create notification content failed");
        return;
    }

    Notification::NotificationRequest request;
    request.SetCreatorUid(CAMERA_UID);
    request.SetCreatorPid(getpid());

    int32_t userId;
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(CAMERA_UID, userId);

    request.SetCreatorUserId(userId);
    request.SetDeliveryTime(GetTimestamp());
    request.SetAutoDeletedTime(OHOS::Notification::NotificationConstant::INVALID_AUTO_DELETE_TIME);
    request.SetTapDismissed(false);
    request.SetSlotType(OHOS::Notification::NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request.SetNotificationId(BEAUTY_NOTIFICATION_ID);
    request.SetGroupName(BEAUTY_NOTIFICATION_GROUP_NAME);
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
    int ret = Notification::NotificationHelper::PublishNotification(request);
    MEDIA_INFO_LOG("CameraBeautyNotification::PublishNotification result = %{public}d", ret);
    isNotificationSuccess_ = (ret == CAMERA_OK);
    if (ret == CAMERA_OK && isBanner && beautyTimes <= CONTROL_FLAG_LIMIT && isRecordTimes) {
        beautyTimes_.operator++();
        SetBeautyTimesFromDataShareHelper(GetBeautyTimes());
    }
}

void CameraBeautyNotification::CancelNotification()
{
    std::lock_guard<std::mutex> lock(notificationMutex_);
    if (!isNotificationSuccess_) {
        return;
    }
    isNotificationSuccess_ = false;
    int ret = Notification::NotificationHelper::CancelNotification(BEAUTY_NOTIFICATION_ID);
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
        beautyStatus = std::stoi(value);
    }
    return CAMERA_OK;
}

int32_t CameraBeautyNotification::SetBeautyStatusFromDataShareHelper(int32_t beautyStatus)
{
    if (cameraDataShareHelper_ == nullptr) {
        cameraDataShareHelper_ = std::make_shared<CameraDataShareHelper>();
    }
    auto ret = cameraDataShareHelper_->UpdateOnce(PREDICATES_CAMERA_BEAUTY_STATUS, std::to_string(beautyStatus));
    CHECK_ERROR_RETURN_RET_LOG(ret != CAMERA_OK, CAMERA_ALLOC_ERROR,
        "SetBeautyStatusFromDataShareHelper UpdateOnce fail.");
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
        times = std::stoi(value);
    }
    return CAMERA_OK;
}

int32_t CameraBeautyNotification::SetBeautyTimesFromDataShareHelper(int32_t times)
{
    if (cameraDataShareHelper_ == nullptr) {
        cameraDataShareHelper_ = std::make_shared<CameraDataShareHelper>();
    }
    auto ret = cameraDataShareHelper_->UpdateOnce(PREDICATES_CAMERA_BEAUTY_TIMES, std::to_string(times));
    CHECK_ERROR_RETURN_RET_LOG(ret != CAMERA_OK, CAMERA_ALLOC_ERROR,
        "SetBeautyTimesFromDataShareHelper UpdateOnce fail.");
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

std::shared_ptr<Notification::NotificationNormalContent> CameraBeautyNotification::CreateNotificationNormalContent(
    int32_t beautyStatus)
{
    std::shared_ptr<Notification::NotificationNormalContent> normalContent =
        std::make_shared<Notification::NotificationNormalContent>();
    CHECK_ERROR_RETURN_RET_LOG(normalContent == nullptr, nullptr, "Create normalContent failed");
    normalContent->SetTitle(GetSystemStringByName(BEAUTY_NOTIFICATION_TITLE));
    normalContent->SetText(beautyStatus == BEAUTY_STATUS_OFF ? GetSystemStringByName(BEAUTY_NOTIFICATION_CONTENT_ON) :
        GetSystemStringByName(BEAUTY_NOTIFICATION_CONTENT_OFF));
    return normalContent;
}

void CameraBeautyNotification::SetActionButton(const std::string& buttonName,
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
    if (actionButtonDeal == nullptr) {
        MEDIA_INFO_LOG("Create actionButtonDeal failed");
        return;
    }
    request.AddActionButton(actionButtonDeal);
}

std::string CameraBeautyNotification::GetSystemStringByName(std::string name)
{
    InitResourceManager();
    std::string result;
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    resourceManager_->GetStringByName(name.c_str(), result);
    IPCSkeleton::SetCallingIdentity(identity);
    MEDIA_DEBUG_LOG("name: %{public}s, result: %{public}s", name.c_str(), result.c_str());
    return result;
}

void CameraBeautyNotification::GetPixelMap()
{
    if (iconPixelMap_ != nullptr) {
        MEDIA_ERR_LOG("Pixel map already exists.");
        return;
    }

    size_t len = 0;
    std::unique_ptr<uint8_t[]> data;
    Global::Resource::RState rstate = GetMediaDataByName(BEAUTY_NOTIFICATION_ICON_NAME.c_str(), len, data);
    if (rstate != Global::Resource::RState::SUCCESS) {
        MEDIA_ERR_LOG("GetMediaDataByName failed");
        return;
    }

    OHOS::Media::SourceOptions opts;
    uint32_t errorCode = 0;
    std::unique_ptr<OHOS::Media::ImageSource> imageSource =
        OHOS::Media::ImageSource::CreateImageSource(data.get(), len, opts, errorCode);
    MEDIA_INFO_LOG("CreateImageSource errorCode: %{public}d", static_cast<int32_t>(errorCode));
    if (imageSource == nullptr) {
        MEDIA_ERR_LOG("imageSource is nullptr");
        return;
    }
    OHOS::Media::DecodeOptions decodeOpts;
    decodeOpts.desiredSize = {ICON_WIDTH, ICON_HEIGHT};
    decodeOpts.desiredPixelFormat = OHOS::Media::PixelFormat::BGRA_8888;
    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    MEDIA_INFO_LOG("CreatePixelMap errorCode: %{public}d", static_cast<int32_t>(errorCode));
    if (pixelMap == nullptr) {
        MEDIA_ERR_LOG("pixelMap is nullptr");
        return;
    }
    iconPixelMap_ = std::move(pixelMap);
}

Global::Resource::RState CameraBeautyNotification::GetMediaDataByName(std::string name, size_t& len,
    std::unique_ptr<uint8_t[]> &outValue, uint32_t density)
{
    InitResourceManager();
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    Global::Resource::RState rstate = resourceManager_->GetMediaDataByName(name.c_str(), len, outValue);
    IPCSkeleton::SetCallingIdentity(identity);
    MEDIA_INFO_LOG("rstate: %{public}d", static_cast<int32_t>(rstate));
    return rstate;
}

void CameraBeautyNotification::InitResourceManager()
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
 
void CameraBeautyNotification::RefreshResConfig()
{
    std::string language = Global::I18n::LocaleConfig::GetSystemLanguage();
    if (language.empty()) {
        MEDIA_INFO_LOG("Get system language failed, skip RefreshResConfig");
        return;
    }
    UErrorCode status = U_ZERO_ERROR;
    icu::Locale locale = icu::Locale::forLanguageTag(language, status);
    if (status != U_ZERO_ERROR || locale == nullptr) {
        MEDIA_INFO_LOG("forLanguageTag failed, errCode:%{public}d", status);
        return;
    }
    if (!resConfig_) {
        MEDIA_INFO_LOG("resConfig_ is nullptr");
        return;
    }
    std::string region = Global::I18n::LocaleConfig::GetSystemRegion();
    resConfig_->SetLocaleInfo(locale.getLanguage(), locale.getScript(), region.c_str());
    if (!resourceManager_) {
        MEDIA_INFO_LOG("resourceManager_ is nullptr");
        return;
    }
    resourceManager_->UpdateResConfig(*resConfig_);
    MEDIA_INFO_LOG("Refresh success");
}
} // namespace CameraStandard
} // namespace OHOS
