/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "hcamera_service.h"

#include <algorithm>
#include <memory>
#include <mutex>
#include <parameter.h>
#include <parameters.h>
#include <securec.h>
#include <cstdint>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include "ability/camera_ability_const.h"
#include "access_token.h"
#include "accesstoken_kit.h"
#include "bms_adapter.h"
#include "icapture_session_callback.h"
#include "session/capture_scene_const.h"
#ifdef NOTIFICATION_ENABLE
#include "camera_beauty_notification.h"
#include "camera_notification_interface.h"
#endif
#include "camera_info_dumper.h"
#include "camera_log.h"
#include "camera_report_uitls.h"
#include "camera_report_dfx_uitls.h"
#include "camera_util.h"
#include "camera_common_event_manager.h"
#include "camera_metadata.h"
#include "datashare_predicates.h"
#include "datashare_result_set.h"
#include "deferred_processing_service.h"
#include "display_manager_lite.h"
#include "hcamera_device_manager.h"
#include "hstream_operator_manager.h"
#include "hcamera_preconfig.h"
#ifdef CAMERA_MOVIE_FILE
#include "hcamera_movie_file_output.h"
#endif
#include "hcamera_session_manager.h"
#include "icamera_service_callback.h"
#include "hcamera_switch_session.h"

#ifdef DEVICE_MANAGER
#include "device_manager_impl.h"
#endif
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "os_account_manager.h"
#include "system_ability_definition.h"
#include "tokenid_kit.h"
#include "uri.h"
#ifdef MEMMGR_OVERRID
#include "mem_mgr_client.h"
#include "mem_mgr_constant.h"
#endif
#ifdef CAMERA_ROTATE_PARAM_UPDATE
#include "camera_rotate_param_manager.h"
#endif
#include "camera_xcollie.h"
#include "res_type.h"
#include "res_sched_client.h"
#include "suspend_manager_base_client.h"
#ifdef HOOK_CAMERA_OPERATOR
#include "camera_rotate_plugin.h"
#endif

namespace OHOS {
namespace CameraStandard {
REGISTER_SYSTEM_ABILITY_BY_ID(HCameraService, CAMERA_SERVICE_ID, true)
constexpr uint8_t POSITION_FOLD_INNER = 3;
#ifdef MEMMGR_OVERRID
constexpr int32_t OLD_LAUNCH = -1;
constexpr int32_t TOUCH_DOWN = 0;
constexpr int32_t TOUCH_UP = 1;
constexpr int32_t TOUCH_CANCEL = 2;
#endif
static sptr<HCameraService> g_cameraServiceHolder = nullptr;
static bool g_isFoldScreen = system::GetParameter("const.window.foldscreen.type", "") != "";
const std::string NOTIFICATION_PERMISSION = "ohos.permission.CAMERA";
const std::string PRE_CAMERA_DEFAULT_ID = "device/0";
const std::string KEY_SEPARATOR= "_";
const std::string NO_NEED_RESTORE_NAME = "no_save_restore";
const std::string PRE_SCAN_REASON = "SCAN_PRELAUNCH";
const std::string PRE_SCAN_NAME = "camera_service";
constexpr int32_t ACTIVE_TIME_DEFAULT = 0;

std::vector<uint32_t> restoreMetadataTag { // item.type is uint8
    OHOS_CONTROL_VIDEO_STABILIZATION_MODE,
    OHOS_CONTROL_DEFERRED_IMAGE_DELIVERY,
    OHOS_CONTROL_SUPPORTED_COLOR_MODES,
    OHOS_CONTROL_PORTRAIT_EFFECT_TYPE,
    OHOS_CONTROL_FILTER_TYPE,
    OHOS_CONTROL_EFFECT_SUGGESTION,
    OHOS_CONTROL_MOTION_DETECTION,
    OHOS_CONTROL_HIGH_QUALITY_MODE,
    OHOS_CONTROL_CAMERA_USED_AS_POSITION,
    OHOS_CONTROL_MOVING_PHOTO,
    OHOS_CONTROL_AUTO_CLOUD_IMAGE_ENHANCE,
    OHOS_CONTROL_BEAUTY_TYPE,
    OHOS_CONTROL_BEAUTY_AUTO_VALUE,
    OHOS_CONTROL_FOCUS_DRIVEN_TYPE,
    OHOS_CONTROL_COLOR_RESERVATION_TYPE,
    OHOS_CONTROL_FOCUS_RANGE_TYPE,
    OHOS_CONTROL_CAMERA_VIRTUAL_APERTURE_VALUE,
};
mutex g_dataShareHelperMutex;
mutex g_dmDeviceInfoMutex;
thread_local uint32_t g_dumpDepth = 0;

HCameraService::HCameraService(int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate), muteModeStored_(false), pressurePid_(0)
{
    MEDIA_INFO_LOG("HCameraService Construct begin");
    g_cameraServiceHolder = this;
    statusCallback_ = std::make_shared<ServiceHostStatus>(this);
    cameraHostManager_ = new (std::nothrow) HCameraHostManager(statusCallback_);
    CHECK_RETURN_ELOG(cameraHostManager_ == nullptr, "HCameraService OnStart failed to create HCameraHostManager obj");
    MEDIA_INFO_LOG("HCameraService Construct end");
    serviceStatus_ = CameraServiceStatus::SERVICE_NOT_READY;
}

HCameraService::HCameraService(sptr<HCameraHostManager> cameraHostManager)
    : cameraHostManager_(cameraHostManager), muteModeStored_(false)
{}

HCameraService::~HCameraService() {}

#ifdef DEVICE_MANAGER
class HCameraService::DeviceInitCallBack : public DistributedHardware::DmInitCallback {
    void OnRemoteDied() override;
};

void HCameraService::DeviceInitCallBack::OnRemoteDied()
{
    MEDIA_INFO_LOG("CameraManager::DeviceInitCallBack OnRemoteDied");
}
#endif

void HCameraService::OnStart()
{
    MEDIA_INFO_LOG("HCameraService OnStart begin");
    CHECK_PRINT_ELOG(
        cameraHostManager_->Init() != CAMERA_OK, "HCameraService OnStart failed to init camera host manager.");
    // initialize deferred processing service.
    DeferredProcessing::DeferredProcessingService::GetInstance().Initialize();
    cameraDataShareHelper_ = std::make_shared<CameraDataShareHelper>();
    AddSystemAbilityListener(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID);
    AddSystemAbilityListener(COMMON_EVENT_SERVICE_ID);
    AddSystemAbilityListener(RES_SCHED_SYS_ABILITY_ID);
    if (Publish(this)) {
        MEDIA_INFO_LOG("HCameraService publish OnStart sucess");
    } else {
        MEDIA_INFO_LOG("HCameraService publish OnStart failed");
    }
#ifdef CAMERA_ROTATE_PARAM_UPDATE
    if (g_isFoldScreen) {
        CameraRoateParamManager::GetInstance().InitParam(); // 先初始化再监听
        CameraRoateParamManager::GetInstance().SubscriberEvent();
    }
#endif
    isLogicCamera_ = system::GetParameter("const.system.sensor_correction_enable", "0") == "1";
    foldScreenType_ = system::GetParameter("const.window.foldscreen.type", "");
    cameraHostManager_->ParseJsonFileToMap(SAVE_RESTORE_FILE_PATH, preCameraClient_, preCameraId_);
    MEDIA_INFO_LOG("HCameraService OnStart end");
}

void HCameraService::RegisterSuspendObserver()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HCameraService::RegisterSuspendObserver");
    std::lock_guard<std::mutex> lock(observerMutex_);
    if (suspendStateObserver_ == nullptr) {
        suspendStateObserver_ = sptr<SuspendStateObserver>::MakeSptr(this);
    }
    CHECK_RETURN_ELOG(suspendStateObserver_ == nullptr, "suspendStateObserver is null");
    ResourceSchedule::SuspendManagerBaseClient::GetInstance().RegisterSuspendObserver(suspendStateObserver_);
}

void HCameraService::UnregisterSuspendObserver()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HCameraService::UnregisterSuspendObserver");
    std::lock_guard<std::mutex> lock(observerMutex_);
    ResourceSchedule::SuspendManagerBaseClient::GetInstance().UnregisterSuspendObserver(suspendStateObserver_);
    suspendStateObserver_ = nullptr;
}

void HCameraService::OnDump()
{
    MEDIA_INFO_LOG("HCameraService::OnDump called");
}

void HCameraService::OnStop()
{
    MEDIA_INFO_LOG("HCameraService::OnStop called");
    cameraHostManager_->DeInit();
    UnregisterFoldStatusListener();
}

int32_t HCameraService::GetMuteModeFromDataShareHelper(bool &muteMode)
{
    lock_guard<mutex> lock(g_dataShareHelperMutex);
    CHECK_RETURN_RET_ELOG(cameraDataShareHelper_ == nullptr, CAMERA_INVALID_ARG, "GetMuteModeFromDataShareHelper NULL");
    std::string value = "";
    auto ret = cameraDataShareHelper_->QueryOnce(PREDICATES_STRING, value);
    MEDIA_INFO_LOG("GetMuteModeFromDataShareHelper Query ret = %{public}d, value = %{public}s", ret, value.c_str());
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, CAMERA_INVALID_ARG, "GetMuteModeFromDataShareHelper QueryOnce fail.");
    value = (value == "0" || value == "1") ? value : "0";
    int32_t muteModeVal = std::stoi(value);
    CHECK_RETURN_RET_ELOG(muteModeVal != 0 && muteModeVal != 1, CAMERA_INVALID_ARG,
        "GetMuteModeFromDataShareHelper Query MuteMode invald, value = %{public}d", muteModeVal);
    muteMode = (muteModeVal == 1) ? true: false;
    this->muteModeStored_ = muteMode;
    return CAMERA_OK;
}

bool HCameraService::SetMuteModeFromDataShareHelper()
{
    CHECK_RETURN_RET(GetServiceStatus() == CameraServiceStatus::SERVICE_READY, true);
    this->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
    bool muteMode = false;
    int32_t ret = GetMuteModeFromDataShareHelper(muteMode);
    CHECK_RETURN_RET_ELOG((ret != CAMERA_OK), false, "GetMuteModeFromDataShareHelper failed");
    MuteCameraFunc(muteMode);
    muteModeStored_ = muteMode;
    MEDIA_INFO_LOG("SetMuteModeFromDataShareHelper Success, muteMode = %{public}d", muteMode);
    return true;
}

int32_t HCameraService::SetUsePhysicalCameraOrientation(bool isUsed)
{
    lock_guard<mutex> lock(usePhysicalCameraOrientationMutex_);
    usePhysicalCameraOrientation_ = isUsed;
    MEDIA_INFO_LOG("HCameraService::SetUsePhysicalCameraOrientation isUsed %{public}d", isUsed);
    return CAMERA_OK;
}

bool HCameraService::GetUsePhysicalCameraOrientation()
{
    lock_guard<mutex> lock(usePhysicalCameraOrientationMutex_);
    return usePhysicalCameraOrientation_;
}

int32_t HCameraService::GetAppNaturalDirection(int32_t& naturalDirection)
{
    naturalDirection = 0;
    CHECK_RETURN_RET(!isLogicCamera_, CAMERA_INVALID_STATE);
    int tokenId = static_cast<int32_t>(IPCSkeleton::GetCallingTokenID());
    std::string clientName = GetClientNameByToken(tokenId);
    CameraApplistManager::GetInstance()->GetAppNaturalDirectionByBundleName(clientName, naturalDirection);
    return CAMERA_OK;
}

int32_t HCameraService::GetLogicCameraConfig(const std::string& clientName, std::vector<int32_t>& useLogicCamera,
    std::vector<int32_t>& customLogicDirection)
{
    MEDIA_DEBUG_LOG("HCameraService::GetLogicCameraConfig is called");
    useLogicCamera = {};
    customLogicDirection = {};
    CHECK_RETURN_RET(!isLogicCamera_ || foldScreenType_.empty() || foldScreenType_[0] != '7',
        CAMERA_OPERATION_NOT_ALLOWED);
    auto appConfigure = CameraApplistManager::GetInstance()->GetConfigureByBundleName(clientName);
    CHECK_RETURN_RET_DLOG(
        appConfigure == nullptr, CAMERA_OK, "HCameraService::GetLogicCameraConfig appConfigure is nullptr");
    std::map<int32_t, int32_t> innerUseLogicCamera = appConfigure->useLogicCamera;
    for (auto &[key, value] : innerUseLogicCamera) {
        useLogicCamera.emplace_back(key);
        useLogicCamera.emplace_back(value);
    }
    std::map<int32_t, int32_t> innerCustomLogicDirection = appConfigure->useLogicCamera;
    for (auto &[key, value] : innerCustomLogicDirection) {
        customLogicDirection.emplace_back(key);
        customLogicDirection.emplace_back(value);
    }
    return CAMERA_OK;
}

void HCameraService::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    auto const &want = data.GetWant();
    std::string action = want.GetAction();
    if (action == COMMON_EVENT_DATA_SHARE_READY) {
        MEDIA_INFO_LOG("on receive datashare ready.");
        SetMuteModeFromDataShareHelper();
    }
#ifdef NOTIFICATION_ENABLE
    if (action == EVENT_CAMERA_BEAUTY_NOTIFICATION) {
        MEDIA_INFO_LOG("on receive camera beauty.");
        OHOS::AAFwk::WantParams wantParams = data.GetWant().GetParams();
        int32_t currentFlag = wantParams.GetIntParam(BEAUTY_NOTIFICATION_ACTION_PARAM, -1);
        MEDIA_INFO_LOG("currentFlag: %{public}d", currentFlag);
        int32_t beautyStatus = currentFlag == BEAUTY_STATUS_OFF ? BEAUTY_STATUS_ON : BEAUTY_STATUS_OFF;
        SetBeauty(beautyStatus);
        auto notification = CameraBeautyNotification::GetInstance();
        if (notification != nullptr) {
            notification->SetBeautyStatusFromDataShareHelper(beautyStatus);
            notification->SetBeautyStatus(beautyStatus);
            notification->PublishNotification(false);
        }
    }
#endif
    if (action == COMMON_EVENT_SCREEN_LOCKED) {
        MEDIA_DEBUG_LOG("on receive usual.event.SCREEN_LOCKED.");
        CameraCommonEventManager::GetInstance()->SetScreenLocked(true);
    }
    if (action == COMMON_EVENT_SCREEN_UNLOCKED) {
        MEDIA_DEBUG_LOG("on receive usual.event.SCREEN_UNLOCKED.");
        CameraCommonEventManager::GetInstance()->SetScreenLocked(false);
    }
    if (action == COMMON_EVENT_RSS_MULTI_WINDOW_TYPE) {
        MEDIA_DEBUG_LOG("on receive common.event.ressched.window.state.");
        int32_t rssMultiWindowStatus = data.GetCode();
        MEDIA_DEBUG_LOG("HCameraService::OnReceiveEvent rssMultiWindowStatus is %{public}d", rssMultiWindowStatus);
        cameraHostManager_->NotifyDeviceStateChangeInfo(DeviceType::RSS_MULTI_WINDOW_TYPE, rssMultiWindowStatus);
    }
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_THERMAL_LEVEL_CHANGED) {
        int32_t temperLevel = data.GetWant().GetIntParam("0", -1);
        MEDIA_INFO_LOG("On receive thermal %{public}d ", temperLevel);

        sptr<HCaptureSession> captureSession_ = nullptr;
        auto &sessionManager = HCameraSessionManager::GetInstance();
        captureSession_ = sessionManager.GetGroupDefaultSession(pressurePid_);
        CHECK_RETURN_ELOG(captureSession_ == nullptr, "captureSession is null");
        captureSession_->SetPressureStatus(TransferTemperToPressure(temperLevel));
    }
}

PressureStatus HCameraService::TransferTemperToPressure(int32_t temperLevel)
{
    switch (temperLevel) {
        case TEMPER_PRESSURE_COOL:
        case TEMPER_PRESSURE_NORMAL:
            return PressureStatus::SYSTEM_PRESSURE_NORMAL;
        case TEMPER_PRESSURE_WARM:
            return PressureStatus::SYSTEM_PRESSURE_MILD;
        case TEMPER_PRESSURE_HOT:
        case TEMPER_PRESSURE_OVERHEATED:
            return PressureStatus::SYSTEM_PRESSURE_SEVERE;
        case TEMPER_PRESSURE_WARNING:
        case TEMPER_PRESSURE_EMERGENCY:
            return PressureStatus::SYSTEM_PRESSURE_CRITICAL;
        case TEMPER_PRESSURE_ESCAPE:
            return PressureStatus::SYSTEM_PRESSURE_SHUTDOWN;
    }
    return PressureStatus::SYSTEM_PRESSURE_NORMAL;
}

#ifdef NOTIFICATION_ENABLE
int32_t HCameraService::SetBeauty(int32_t beautyStatus)
{
    constexpr int32_t DEFAULT_ITEMS = 1;
    constexpr int32_t DEFAULT_DATA_LENGTH = 1;
    shared_ptr<OHOS::Camera::CameraMetadata> changedMetadata =
        make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    int32_t count = 1;
    uint8_t beautyLevel = 0;
    uint8_t beautyType = OHOS_CAMERA_BEAUTY_TYPE_OFF;
    if (beautyStatus == BEAUTY_STATUS_ON) {
        beautyLevel = BEAUTY_LEVEL;
        beautyType = OHOS_CAMERA_BEAUTY_TYPE_AUTO;
    }
    MEDIA_INFO_LOG("HCameraService::SetBeauty beautyType: %{public}d, beautyLevel: %{public}d",
        beautyType, beautyLevel);
    AddOrUpdateMetadata(changedMetadata, OHOS_CONTROL_BEAUTY_TYPE, &beautyType, count);
    AddOrUpdateMetadata(changedMetadata, OHOS_CONTROL_BEAUTY_AUTO_VALUE, &beautyLevel, count);
    sptr<HCameraDeviceManager> deviceManager = HCameraDeviceManager::GetInstance();
    std::vector<sptr<HCameraDeviceHolder>> deviceHolderVector = deviceManager->GetActiveCameraHolders();
    for (sptr<HCameraDeviceHolder> activeDeviceHolder : deviceHolderVector) {
        sptr<HCameraDevice> activeDevice = activeDeviceHolder->GetDevice();
        bool isChangedMetadata = activeDevice != nullptr && activeDevice->IsOpenedCameraDevice();
        if (isChangedMetadata) {
            activeDevice->UpdateSetting(changedMetadata);
            MEDIA_INFO_LOG("HCameraService::SetBeauty UpdateSetting");
        }
    }
    return CAMERA_OK;
}
#endif

int32_t HCameraService::SetMuteModeByDataShareHelper(bool muteMode)
{
    MEDIA_INFO_LOG("SetMuteModeByDataShareHelper enter.");
    lock_guard<mutex> lock(g_dataShareHelperMutex);
    CHECK_RETURN_RET_ELOG(cameraDataShareHelper_ == nullptr, CAMERA_ALLOC_ERROR, "GetMuteModeFromDataShareHelper NULL");
    std::string unMuteModeStr = "0";
    std::string muteModeStr = "1";
    std::string value = muteMode? muteModeStr : unMuteModeStr;
    auto ret = cameraDataShareHelper_->UpdateOnce(PREDICATES_STRING, value);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, CAMERA_ALLOC_ERROR, "SetMuteModeByDataShareHelper UpdateOnce fail.");
    return CAMERA_OK;
}

int32_t HCameraService::GetControlCenterStatusFromDataShareHelper(bool &status)
{
    MEDIA_INFO_LOG("HCameraService::GetControlCenterStatusFromDataShareHelper");
    lock_guard<mutex> lock(g_dataShareHelperMutex);
    CHECK_RETURN_RET_ELOG(
        cameraDataShareHelper_ == nullptr, CAMERA_INVALID_ARG, "GetControlCenterStatusFromDataShareHelper NULL");
    sptr<HCaptureSession> sessionForControlCenter = GetSessionForControlCenter();
    CHECK_RETURN_RET_ELOG(sessionForControlCenter == nullptr, CAMERA_INVALID_STATE,
        "GetControlCenterStatusFromDataShareHelper failed, not in video session.");

    std::string value = "";
    auto ret = cameraDataShareHelper_->QueryOnce(CONTROL_CENTER_DATA, value);
    MEDIA_INFO_LOG("GetControlCenterStatusFromDataShareHelper Query ret = %{public}d, value = %{public}s",
        ret, value.c_str());
    if (ret != CAMERA_OK) {
        status = false;
        isControlCenterEnabled_ = false;
        return ret;
    }

    std::string bundleName = sessionForControlCenter->GetBundleForControlCenter();
    std::map<std::string, std::array<float, CONTROL_CENTER_DATA_SIZE>> controlCenterMap
        = StringToControlCenterMap(value);
    if (controlCenterMap.find(bundleName) != controlCenterMap.end()) {
        int32_t statusVal = static_cast<int32_t>(controlCenterMap[bundleName][CONTROL_CENTER_STATUS_INDEX]);
        MEDIA_INFO_LOG("GetControlCenterStatusFromDataShareHelper success value: %{public}d", statusVal);
        status = (statusVal == 1) ? true: false;
    } else {
        MEDIA_ERR_LOG("GetControlCenterStatusFromDataShareHelper failed, no bundle.");
        status = false;
        return CAMERA_OK;
    }
    isControlCenterEnabled_ = status;
    return CAMERA_OK;
}

void HCameraService::UpdateControlCenterStatus(bool isStart)
{
    bool controlCenterStatus = false;
    CHECK_EXECUTE(isStart, GetControlCenterStatusFromDataShareHelper(controlCenterStatus));
    MEDIA_INFO_LOG("HCameraService::UpdateControlCenterStatus, isStart: %{public}d, status: %{public}d",
        isStart, controlCenterStatus);
    EnableControlCenter(controlCenterStatus, false);
}

int32_t HCameraService::UpdateDataShareAndTag(bool status, bool needPersistEnable)
{
    MEDIA_INFO_LOG("HCameraService::UpdateDataShareAndTag");
    lock_guard<mutex> lock(g_dataShareHelperMutex);
    sptr<HCaptureSession> sessionForControlCenter = GetSessionForControlCenter();
    CHECK_RETURN_RET_ELOG(cameraDataShareHelper_ == nullptr, CAMERA_ALLOC_ERROR, "GetMuteModeFromDataShareHelper NULL");
    CHECK_RETURN_RET_ELOG(sessionForControlCenter == nullptr, CAMERA_INVALID_STATE,
        "GetControlCenterStatusFromDataShareHelper failed, not in video session.");
    std::string bundleName = sessionForControlCenter->GetBundleForControlCenter();
    std::map<std::string, std::array<float, CONTROL_CENTER_DATA_SIZE>> controlCenterMap;
    std::string value = "";
    auto ret = cameraDataShareHelper_->QueryOnce(CONTROL_CENTER_DATA, value);
    MEDIA_INFO_LOG("UpdateDataShareAndTag Query ret = %{public}d, value = %{public}s", ret, value.c_str());
    if (ret != CAMERA_OK) {
        ret = CreateControlCenterDataShare(controlCenterMap, bundleName, status);
        return ret;
    }
    controlCenterMap = StringToControlCenterMap(value);
    if (controlCenterMap.find(bundleName) != controlCenterMap.end()) {
        controlCenterMap[bundleName][CONTROL_CENTER_STATUS_INDEX] = status;
        std::string controlCenterString = ControlCenterMapToString(controlCenterMap);
        if (needPersistEnable) {
            ret = cameraDataShareHelper_->UpdateOnce(CONTROL_CENTER_DATA, controlCenterString);
            MEDIA_INFO_LOG("UpdateDataShareAndTag ret:  %{public}d", ret);
        }
        if (status) {
            sessionForControlCenter->SetBeautyValue(
                BeautyType::AUTO_TYPE, controlCenterMap[bundleName][CONTROL_CENTER_BEAUTY_INDEX], false);
            sessionForControlCenter->SetVirtualApertureValue(
                controlCenterMap[bundleName][CONTROL_CENTER_APERTURE_INDEX], false);
        } else if (needPersistEnable) {
            sessionForControlCenter->SetBeautyValue(BeautyType::AUTO_TYPE, 0, false);
            sessionForControlCenter->SetVirtualApertureValue(0, false);
        }
    } else if (needPersistEnable) {
        MEDIA_INFO_LOG("UpdateDataShareAndTag no bundle, create info for new bundle.");
        ret = CreateControlCenterDataShare(controlCenterMap, bundleName, status);
    }
    return ret;
}

int32_t HCameraService::CreateControlCenterDataShare(std::map<std::string,
    std::array<float, CONTROL_CENTER_DATA_SIZE>> controlCenterMap, std::string bundleName, bool status)
{
    sptr<HCaptureSession> sessionForControlCenter = GetSessionForControlCenter();
    CHECK_RETURN_RET_ELOG(sessionForControlCenter == nullptr, CAMERA_INVALID_STATE,
        "CreateControlCenterDataShare failed, not in video session.");
    std::vector<float> virtualMetadata = {};
    sessionForControlCenter->GetVirtualApertureMetadata(virtualMetadata);
    float biggestAperture = 0;
    CHECK_EXECUTE(virtualMetadata.size() > 0, biggestAperture = virtualMetadata.back());

    controlCenterMap[bundleName] = {status, 0, biggestAperture};
    std::string controlCenterString = ControlCenterMapToString(controlCenterMap);
    auto ret = cameraDataShareHelper_->UpdateOnce(CONTROL_CENTER_DATA, controlCenterString);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, ret, "CreateControlCenterDataShare failed.");

    sessionForControlCenter->SetBeautyValue(BeautyType::AUTO_TYPE, 0, false);
    if (status) {
        sessionForControlCenter->SetVirtualApertureValue(biggestAperture, false);
    } else {
        sessionForControlCenter->SetVirtualApertureValue(0, false);
    }
    return ret;
}

#ifdef CAMERA_LIVE_SCENE_RECOGNITION
void HCameraService::RegisterEventListenerToRss()
{
    eventListener_ = new (std::nothrow) ResSchedToCameraEventListener;
    if (eventListener_ != nullptr) {
        MEDIA_DEBUG_LOG("HCameraService::RegisterEventListenerToRss RegisterEventListener");
        OHOS::ResourceSchedule::ResSchedClient::GetInstance().RegisterEventListener(eventListener_,
            OHOS::ResourceSchedule::ResType::EventType::EVENT_REPORT_HFLS_LIVE_SCENE_CHANGED);
    }
}

void HCameraService::UnRegisterEventListenerToRss()
{
    if (eventListener_ != nullptr) {
        MEDIA_DEBUG_LOG("HCameraService::UnRegisterEventListenerToRss UnRegisterEventListener");
        OHOS::ResourceSchedule::ResSchedClient::GetInstance().UnRegisterEventListener(eventListener_,
            OHOS::ResourceSchedule::ResType::EventType::EVENT_REPORT_HFLS_LIVE_SCENE_CHANGED);
    }
    eventListener_ = nullptr;
}
#endif

void HCameraService::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    MEDIA_INFO_LOG("OnAddSystemAbility systemAbilityId:%{public}d", systemAbilityId);
    switch (systemAbilityId) {
        case DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID:
            MEDIA_INFO_LOG("OnAddSystemAbility RegisterObserver start");
            if (cameraDataShareHelper_->IsDataShareReady()) {
                SetMuteModeFromDataShareHelper();
                CHECK_EXECUTE(isLogicCamera_, CameraApplistManager::GetInstance()->Init());
            }
            break;
        case COMMON_EVENT_SERVICE_ID:
            MEDIA_INFO_LOG("OnAddSystemAbility COMMON_EVENT_SERVICE");
#ifdef NOTIFICATION_ENABLE
            CameraCommonEventManager::GetInstance()->SubscribeCommonEvent(EVENT_CAMERA_BEAUTY_NOTIFICATION,
                std::bind(&HCameraService::OnReceiveEvent, this, std::placeholders::_1), NOTIFICATION_PERMISSION);
#endif
            CameraCommonEventManager::GetInstance()->SubscribeCommonEvent(COMMON_EVENT_DATA_SHARE_READY,
                std::bind(&HCameraService::OnReceiveEvent, this, std::placeholders::_1));
            CameraCommonEventManager::GetInstance()->SubscribeCommonEvent(COMMON_EVENT_SCREEN_LOCKED,
                std::bind(&HCameraService::OnReceiveEvent, this, std::placeholders::_1));
            CameraCommonEventManager::GetInstance()->SubscribeCommonEvent(COMMON_EVENT_SCREEN_UNLOCKED,
                std::bind(&HCameraService::OnReceiveEvent, this, std::placeholders::_1));
            CameraCommonEventManager::GetInstance()->SubscribeCommonEvent(COMMON_EVENT_RSS_MULTI_WINDOW_TYPE,
                std::bind(&HCameraService::OnReceiveEvent, this, std::placeholders::_1));
            CameraCommonEventManager::GetInstance()->SubscribeCommonEvent(
                EventFwk::CommonEventSupport::COMMON_EVENT_THERMAL_LEVEL_CHANGED,
                std::bind(&HCameraService::OnReceiveEvent, this, std::placeholders::_1));
            break;
        case RES_SCHED_SYS_ABILITY_ID:
            MEDIA_INFO_LOG("OnAddSystemAbility RES_SCHED_SYS_ABILITY_ID");
            RegisterSuspendObserver();
#ifdef CAMERA_LIVE_SCENE_RECOGNITION
            RegisterEventListenerToRss();
#endif
            break;
        default:
            MEDIA_INFO_LOG("OnAddSystemAbility unhandled sysabilityId:%{public}d", systemAbilityId);
            break;
    }
    MEDIA_INFO_LOG("OnAddSystemAbility done");
}

void HCameraService::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    MEDIA_DEBUG_LOG("HCameraService::OnRemoveSystemAbility systemAbilityId:%{public}d removed", systemAbilityId);
    switch (systemAbilityId) {
        case DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID:
            CameraCommonEventManager::GetInstance()->UnSubscribeCommonEvent(COMMON_EVENT_DATA_SHARE_READY);
            break;
        case RES_SCHED_SYS_ABILITY_ID:
            MEDIA_INFO_LOG("OnRemoveSystemAbility RES_SCHED_SYS_ABILITY_ID");
            ClearFreezedPidList();
            UnregisterSuspendObserver();
#ifdef CAMERA_LIVE_SCENE_RECOGNITION
            UnRegisterEventListenerToRss();
#endif
            break;
        default:
            break;
    }
    MEDIA_DEBUG_LOG("HCameraService::OnRemoveSystemAbility done");
}

int32_t HCameraService::GetCameras(
    vector<string>& cameraIds, vector<shared_ptr<OHOS::Camera::CameraMetadata>>& cameraAbilityList)
{
    CAMERA_SYNC_TRACE;
    isFoldable = isFoldableInit ? isFoldable : g_isFoldScreen;
    isFoldableInit = true;
    int32_t ret = cameraHostManager_->GetCameras(cameraIds);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, ret, "HCameraService::GetCameras failed");
    shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility;
    vector<shared_ptr<CameraMetaInfo>> cameraInfos;
    for (auto id : cameraIds) {
        ret = cameraHostManager_->GetCameraAbility(id, cameraAbility);
        CHECK_RETURN_RET_ELOG(
            ret != CAMERA_OK || cameraAbility == nullptr, ret, "HCameraService::GetCameraAbility failed");
        auto cameraMetaInfo = GetCameraMetaInfo(id, cameraAbility);
        CHECK_CONTINUE(cameraMetaInfo == nullptr);
        cameraInfos.emplace_back(cameraMetaInfo);
    }
    FillCameras(cameraInfos, cameraIds, cameraAbilityList);
    return ret;
}

shared_ptr<CameraMetaInfo> HCameraService::GetCameraMetaInfo(std::string &cameraId,
    shared_ptr<OHOS::Camera::CameraMetadata>cameraAbility)
{
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = cameraAbility->get();
    int32_t res = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_CAMERA_POSITION, &item);
    uint8_t cameraPosition = (res == CAM_META_SUCCESS && item.count) ? item.data.u8[0] : OHOS_CAMERA_POSITION_OTHER;
    res = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_CAMERA_FOLDSCREEN_TYPE, &item);
    uint8_t foldType = (res == CAM_META_SUCCESS) ? item.data.u8[0] : OHOS_CAMERA_FOLDSCREEN_OTHER;
    auto foldScreenType = system::GetParameter("const.window.foldscreen.type", "")[0];
    bool isOtherFold = isFoldable && cameraPosition == OHOS_CAMERA_POSITION_FRONT &&
        foldType == OHOS_CAMERA_FOLDSCREEN_OTHER && (foldScreenType == '1' || foldScreenType == '7');
    CHECK_RETURN_RET(isOtherFold, nullptr);
    bool isFoldInner =
        isFoldable && cameraPosition == OHOS_CAMERA_POSITION_FRONT && foldType == OHOS_CAMERA_FOLDSCREEN_INNER;
    if (isFoldInner) {
        cameraPosition = POSITION_FOLD_INNER;
    }
    res = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_CAMERA_TYPE, &item);
    uint8_t cameraType = (res == CAM_META_SUCCESS && item.count) ? item.data.u8[0] : OHOS_CAMERA_TYPE_UNSPECIFIED;
    res = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_CAMERA_CONNECTION_TYPE, &item);
    uint8_t connectionType =
        (res == CAM_META_SUCCESS && item.count) ? item.data.u8[0] : OHOS_CAMERA_CONNECTION_TYPE_BUILTIN;
    res = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED, &item);
    bool isMirrorSupported = res == CAM_META_SUCCESS && item.count;
    res = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_CAMERA_FOLD_STATUS, &item);
    uint8_t foldStatus =
        (res == CAM_META_SUCCESS && item.count) ? item.data.u8[0] : OHOS_CAMERA_FOLD_STATUS_NONFOLDABLE;
    res = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_CAMERA_MODES, &item);
    std::vector<uint8_t> supportModes = {};
    for (uint32_t i = 0; i < item.count; i++) {
        supportModes.push_back(item.data.u8[i]);
    }
    CAMERA_SYSEVENT_STATISTIC(CreateMsg("CameraManager GetCameras camera ID:%s, Camera position:%d, "
                                        "Camera Type:%d, Connection Type:%d, Mirror support:%d, Fold status %d",
        cameraId.c_str(), cameraPosition, cameraType, connectionType, isMirrorSupported, foldStatus));
    return make_shared<CameraMetaInfo>(cameraId, cameraType, cameraPosition, connectionType,
        foldStatus, supportModes, cameraAbility);
}

void HCameraService::FillCameras(vector<shared_ptr<CameraMetaInfo>>& cameraInfos,
    vector<string>& cameraIds, vector<shared_ptr<OHOS::Camera::CameraMetadata>>& cameraAbilityList)
{
    vector<shared_ptr<CameraMetaInfo>> choosedCameras = ChooseDeFaultCameras(cameraInfos);
    cameraIds.clear();
    cameraAbilityList.clear();
    for (const auto& camera: choosedCameras) {
        cameraIds.emplace_back(camera->cameraId);
        cameraAbilityList.emplace_back(camera->cameraAbility);
    }
    int32_t uid = IPCSkeleton::GetCallingUid();
    if (uid == ROOT_UID || uid == FACE_CLIENT_UID || uid == RSS_UID ||
        OHOS::Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(IPCSkeleton::GetCallingFullTokenID())) {
        vector<shared_ptr<CameraMetaInfo>> physicalCameras = ChoosePhysicalCameras(cameraInfos, choosedCameras);
        for (const auto& camera: physicalCameras) {
            cameraIds.emplace_back(camera->cameraId);
            cameraAbilityList.emplace_back(camera->cameraAbility);
        }
    } else {
        MEDIA_INFO_LOG("current token id not support physical camera");
    }
}

vector<shared_ptr<CameraMetaInfo>> HCameraService::ChoosePhysicalCameras(
    const vector<shared_ptr<CameraMetaInfo>>& cameraInfos, const vector<shared_ptr<CameraMetaInfo>>& choosedCameras)
{
    std::vector<OHOS::HDI::Camera::V1_3::OperationMode> supportedPhysicalCamerasModes = {
        OHOS::HDI::Camera::V1_3::OperationMode::PROFESSIONAL_PHOTO,
        OHOS::HDI::Camera::V1_3::OperationMode::PROFESSIONAL_VIDEO,
        OHOS::HDI::Camera::V1_3::OperationMode::HIGH_RESOLUTION_PHOTO,
    };
    vector<shared_ptr<CameraMetaInfo>> physicalCameraInfos = {};
    for (auto& camera : cameraInfos) {
        if (std::any_of(choosedCameras.begin(), choosedCameras.end(), [camera](const auto& defaultCamera) {
                return camera->cameraId == defaultCamera->cameraId;
            })
        ) {
            MEDIA_INFO_LOG("ChoosePhysicalCameras alreadly has default camera: %{public}s", camera->cameraId.c_str());
        } else {
            physicalCameraInfos.push_back(camera);
        }
    }
    vector<shared_ptr<CameraMetaInfo>> physicalCameras = {};
    for (auto& camera : physicalCameraInfos) {
        MEDIA_INFO_LOG("ChoosePhysicalCameras camera ID:%s, CameraType: %{public}d, Camera position:%{public}d, "
                       "Connection Type:%{public}d",
                       camera->cameraId.c_str(), camera->cameraType, camera->position, camera->connectionType);
        bool isSupportPhysicalCamera = std::any_of(camera->supportModes.begin(), camera->supportModes.end(),
            [&supportedPhysicalCamerasModes](auto mode) -> bool {
                return any_of(supportedPhysicalCamerasModes.begin(), supportedPhysicalCamerasModes.end(),
                    [mode](auto it)-> bool { return it == mode; });
            });
        bool isAddCameraInfos = camera->cameraType != camera_type_enum_t::OHOS_CAMERA_TYPE_UNSPECIFIED &&
            isSupportPhysicalCamera;
        if (isAddCameraInfos) {
            physicalCameras.emplace_back(camera);
            MEDIA_INFO_LOG("ChoosePhysicalCameras add camera ID:%{public}s", camera->cameraId.c_str());
        }
    }
    return physicalCameras;
}

vector<shared_ptr<CameraMetaInfo>> HCameraService::ChooseDeFaultCameras(vector<shared_ptr<CameraMetaInfo>> cameraInfos)
{
    vector<shared_ptr<CameraMetaInfo>> choosedCameras;
    for (auto& camera : cameraInfos) {
        MEDIA_DEBUG_LOG("ChooseDeFaultCameras camera ID:%s, Camera position:%{public}d, Connection Type:%{public}d",
            camera->cameraId.c_str(), camera->position, camera->connectionType);
        if (any_of(choosedCameras.begin(), choosedCameras.end(),
            [camera](const auto& defaultCamera) {
                return (camera->connectionType == OHOS_CAMERA_CONNECTION_TYPE_BUILTIN &&
                    defaultCamera->position == camera->position &&
                    defaultCamera->connectionType == camera->connectionType &&
                    defaultCamera->foldStatus == camera->foldStatus);
            })
        ) {
            MEDIA_DEBUG_LOG("ChooseDeFaultCameras alreadly has default camera");
        } else {
            choosedCameras.emplace_back(camera);
            MEDIA_INFO_LOG("add camera ID:%{public}s", camera->cameraId.c_str());
        }
    }
    return choosedCameras;
}

int32_t HCameraService::GetCameraIds(vector<string>& cameraIds)
{
    CAMERA_SYNC_TRACE;
    int32_t ret = CAMERA_OK;
    MEDIA_DEBUG_LOG("HCameraService::GetCameraIds");
    std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>> cameraAbilityList;
    ret = GetCameras(cameraIds, cameraAbilityList);
    CHECK_PRINT_ELOG(ret != CAMERA_OK, "HCameraService::GetCameraIds failed");
    for (auto id : cameraIds) {
        MEDIA_INFO_LOG("HCameraService::GetCameraIds cameraId:%{public}s", id.c_str());
    }
    return ret;
}

int32_t HCameraService::GetCameraAbility(const std::string& cameraId,
    std::shared_ptr<OHOS::Camera::CameraMetadata>& cameraAbility)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("HCameraService::GetCameraAbility");
    int32_t ret = cameraHostManager_->GetCameraAbility(cameraId, cameraAbility);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, ret, "HCameraService::GetCameraAbility failed");
    return ret;
}

int32_t HCameraService::GetOnBoardDisplayId(int32_t& displayId)
{
    MEDIA_DEBUG_LOG("HCameraService::GetOnBoardDisplayId is called");
    return GetDisplayId(displayId);
}

int32_t HCameraService::CreateCameraDevice(const string& cameraId, sptr<ICameraDeviceService>& device)
{
    CAMERA_SYNC_TRACE;
    OHOS::Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    MEDIA_INFO_LOG("HCameraService::CreateCameraDevice prepare execute, cameraId:%{public}s", cameraId.c_str());

    string permissionName = OHOS_PERMISSION_CAMERA;
    int32_t ret = CheckPermission(permissionName, callerToken);
    CHECK_RETURN_RET_ELOG(
        ret != CAMERA_OK, ret, "HCameraService::CreateCameraDevice Check OHOS_PERMISSION_CAMERA fail %{public}d", ret);
    // if callerToken is invalid, will not call IsAllowedUsingPermission
    CHECK_RETURN_RET_ELOG(
        !IsInForeGround(callerToken), CAMERA_ALLOC_ERROR, "HCameraService::CreateCameraDevice is not allowed!");
    sptr<HCameraDevice> cameraDevice = new (nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    CHECK_RETURN_RET_ELOG(cameraDevice == nullptr, CAMERA_ALLOC_ERROR,
        "HCameraService::CreateCameraDevice HCameraDevice allocation failed");
    CHECK_RETURN_RET_ELOG(GetServiceStatus() != CameraServiceStatus::SERVICE_READY, CAMERA_INVALID_STATE,
        "HCameraService::CreateCameraDevice CameraService not ready!");
    {
        lock_guard<mutex> lock(g_dataShareHelperMutex);
        // when create camera device, update mute setting truely.
        if (IsCameraMuteSupported(cameraId)) {
            CHECK_PRINT_ELOG(UpdateMuteSetting(cameraDevice, muteModeStored_) != CAMERA_OK,
                "UpdateMuteSetting Failed, cameraId: %{public}s", cameraId.c_str());
        } else {
            MEDIA_ERR_LOG("HCameraService::CreateCameraDevice MuteCamera not Supported");
        }
        device = cameraDevice;
        cameraDevice->SetDeviceMuteMode(muteModeStored_);
#ifdef CAMERA_ROTATE_PARAM_UPDATE
        if (g_isFoldScreen) {
            cameraDevice->SetCameraRotateStrategyInfos(
                CameraRoateParamManager::GetInstance().GetCameraRotateStrategyInfos());
        }
#endif
    }
    CAMERA_SYSEVENT_STATISTIC(CreateMsg("CameraManager_CreateCameraInput CameraId:%s", cameraId.c_str()));
    MEDIA_INFO_LOG("HCameraService::CreateCameraDevice execute success");
    return CAMERA_OK;
}

int32_t HCameraService::CreateCaptureSession(sptr<ICaptureSession>& session, int32_t opMode)
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t rc = CAMERA_OK;
    HILOG_COMM_INFO("HCameraService::CreateCaptureSession opMode_= %{public}d", opMode);
    CameraReportUtils::GetInstance().updateModeChangePerfInfo(opMode, CameraReportUtils::GetCallerInfo());

    OHOS::Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> captureSession = nullptr;
    rc = HCaptureSession::NewInstance(callerToken, opMode, captureSession);
    if (rc != CAMERA_OK) { // LCOV_EXCL_LINE
        MEDIA_ERR_LOG("HCameraService::CreateCaptureSession allocation failed");
        CameraReportUtils::ReportCameraError(
            "HCameraService::CreateCaptureSession", rc, false, CameraReportUtils::GetCallerInfo());
        return rc;
    }
    pressurePid_ = IPCSkeleton::GetCallingPid();
    session = captureSession;
    if (opMode == SceneMode::VIDEO) {
        SetSessionForControlCenter(captureSession);
        captureSession->SetUpdateControlCenterCallback(
            std::bind(&HCameraService::UpdateControlCenterStatus, this, std::placeholders::_1));
        std::string bundleName = BmsAdapter::GetInstance()->GetBundleName(IPCSkeleton::GetCallingUid());
        captureSession->SetBundleForControlCenter(bundleName);
        MEDIA_INFO_LOG("Save videoSession for controlCenter");
    } else {
        SetSessionForControlCenter(nullptr);
        MEDIA_INFO_LOG("Clear videoSession of controlCenter");
    }
    #ifdef HOOK_CAMERA_OPERATOR
        std::string clientName = GetClientBundle(IPCSkeleton::GetCallingUid());
        CameraRotatePlugin::GetInstance()->SetCaptureSession(clientName, captureSession);
    #endif
    int32_t uid = IPCSkeleton::GetCallingUid();
    int32_t userId;
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, userId);
    MEDIA_INFO_LOG("HCameraService::CreateCaptureSession userId= %{public}d", userId);
    captureSession->SetUserId(userId);

    auto &sessionManager = HCameraSessionManager::GetInstance();
    auto mechSession = sessionManager.GetMechSession(userId);
    if (mechSession != nullptr && mechSession->IsEnableMech()) {
        captureSession->SetMechDeliveryState(MechDeliveryState::NEED_ENABLE);
    }
    captureSession->registerSessionStartCallback([this](string bundleName) {
        std::lock_guard<std::mutex> lock(preCameraMutex_);
        SetPrelaunchScanCameraConfig(bundleName);
        clearPreScanConfig();
    });
    return rc;
}

int32_t HCameraService::GetVideoSessionForControlCenter(sptr<ICaptureSession>& session)
{
    MEDIA_INFO_LOG("HCameraService::GetVideoSessionForControlCenter");
    CHECK_RETURN_RET_ELOG(!CheckSystemApp(), CAMERA_NO_PERMISSION, "HCameraService::CheckSystemApp fail");
    sptr<HCaptureSession> sessionForControlCenter = GetSessionForControlCenter();
    CHECK_RETURN_RET_ELOG(sessionForControlCenter == nullptr, CAMERA_INVALID_ARG,
        "GetVideoSessionForControlCenter failed, session == nullptr.");
    session = sessionForControlCenter;
    return CAMERA_OK;
}

int32_t HCameraService::CreateDeferredPhotoProcessingSession(int32_t userId,
    const sptr<DeferredProcessing::IDeferredPhotoProcessingSessionCallback>& callback,
    sptr<DeferredProcessing::IDeferredPhotoProcessingSession>& session)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(!CheckSystemApp(), CAMERA_NO_PERMISSION, "HCameraService::CheckSystemApp fail");
    CameraXCollie cameraXCollie = CameraXCollie("HCameraService::CreateDeferredPhotoProcessingSession");
    MEDIA_INFO_LOG("HCameraService::CreateDeferredPhotoProcessingSession enter.");
    sptr<DeferredProcessing::IDeferredPhotoProcessingSession> photoSession;
    int32_t uid = IPCSkeleton::GetCallingUid();
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, userId);
    MEDIA_INFO_LOG("CreateDeferredPhotoProcessingSession get uid:%{public}d userId:%{public}d", uid, userId);
    photoSession =
        DeferredProcessing::DeferredProcessingService::GetInstance().CreateDeferredPhotoProcessingSession(userId,
        callback);
    session = photoSession;
    return CAMERA_OK;
}

int32_t HCameraService::CreateDeferredVideoProcessingSession(int32_t userId,
    const sptr<DeferredProcessing::IDeferredVideoProcessingSessionCallback>& callback,
    sptr<DeferredProcessing::IDeferredVideoProcessingSession>& session)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HCameraService::CreateDeferredVideoProcessingSession enter.");
    sptr<DeferredProcessing::IDeferredVideoProcessingSession> videoSession;
    int32_t uid = IPCSkeleton::GetCallingUid();
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, userId);
    MEDIA_INFO_LOG("CreateDeferredVideoProcessingSession get uid:%{public}d userId:%{public}d", uid, userId);
    videoSession =
        DeferredProcessing::DeferredProcessingService::GetInstance().CreateDeferredVideoProcessingSession(userId,
        callback);
    session = videoSession;
    return CAMERA_OK;
}

int32_t HCameraService::CreateMechSession(int32_t userId, sptr<IMechSession>& session)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HCameraService::CreateMechSession enter.");

    OHOS::Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    string permissionName = OHOS_PERMISSION_CAMERA;
    int32_t ret = CheckPermission(permissionName, callerToken);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, ret, "HCameraService::CreateMechSession failed permission is: %{public}s",
        permissionName.c_str());

    auto &sessionManager = HCameraSessionManager::GetInstance();
    auto mechSession = sessionManager.GetMechSession(userId);
    if (mechSession != nullptr) {
        session = mechSession;
        return CAMERA_OK;
    }

    mechSession = new (std::nothrow) HMechSession(userId);
    CHECK_RETURN_RET_ELOG(
        mechSession == nullptr, CAMERA_ALLOC_ERROR, "HMechSession::NewInstance mechSession is nullptr");
    session = mechSession;
    sessionManager.AddMechSession(userId, mechSession);
    return CAMERA_OK;
}

int32_t HCameraService::IsMechSupported(bool &isMechSupported)
{
    CAMERA_SYNC_TRACE;
    isMechSupported = false;
    std::vector<std::string> cameraIds;
    std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>> cameraAbilityList;
    int32_t retCode = GetCameras(cameraIds, cameraAbilityList);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, retCode, "HCameraService::IsMechSupported failed");
    for (auto& cameraAbility : cameraAbilityList) {
        camera_metadata_item_t item;
        int ret = OHOS::Camera::FindCameraMetadataItem(cameraAbility->get(),
            OHOS_ABILITY_FOCUS_TRACKING_MECH_AVAILABLE, &item);
        if (ret == CAM_META_SUCCESS && item.count > 0) {
            MEDIA_DEBUG_LOG("IsMechSupported data is %{public}d", item.data.u8[0]);
            if (item.data.u8[0] == OHOS_CAMERA_MECH_MODE_ON) {
                isMechSupported = true;
                break;
            }
        }
    }
    MEDIA_INFO_LOG("HCameraService::IsMechSupported success. isMechSupported: %{public}d", isMechSupported);
    return retCode;
}

int32_t HCameraService::CreateCameraSwitchSession(sptr<ICameraSwitchSession> &session)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HCameraService::CreateCameraSwitchSession enter,pid = %{public}d", IPCSkeleton::GetCallingPid());
    OHOS::Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    string permissionName = OHOS_PERMISSION_CAMERA_CONTROL;
    int32_t ret = CheckPermission(permissionName, callerToken);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, ret,
        "HCameraService::CreateCameraSwitchSession failed permission is: %{public}s", permissionName.c_str());
    auto &sessionManager = HCameraSessionManager::GetInstance();
    auto switchSession = sessionManager.GetCameraSwitchSession();
    if (switchSession != nullptr) {
        session = switchSession;
        return CAMERA_OK;
    }
    switchSession = new (std::nothrow) HCameraSwitchSession();
    CHECK_RETURN_RET_ELOG(switchSession == nullptr,
        CAMERA_ALLOC_ERROR,
        "HCameraSwitchSession::CreateCameraSwitchSession switchSession is nullptr");
    session = switchSession;
    sessionManager.SetCameraSwitchSession(switchSession);
    return CAMERA_OK;
}

int32_t HCameraService::CreatePhotoOutput(const sptr<OHOS::IBufferProducer>& producer, int32_t format, int32_t width,
    int32_t height, sptr<IStreamCapture>& photoOutput)
{
    CAMERA_SYNC_TRACE;
    int32_t rc = CAMERA_OK;
    MEDIA_INFO_LOG("HCameraService::CreatePhotoOutput prepare execute");
    if ((producer == nullptr) || (width == 0) || (height == 0)) {
        rc = CAMERA_INVALID_ARG;
        MEDIA_ERR_LOG("HCameraService::CreatePhotoOutput producer is null");
        CameraReportUtils::ReportCameraError(
            "HCameraService::CreatePhotoOutput", rc, false, CameraReportUtils::GetCallerInfo());
        return rc;
    }
    sptr<HStreamCapture> streamCapture = new (nothrow) HStreamCapture(producer, format, width, height);
    if (streamCapture == nullptr) {
        rc = CAMERA_ALLOC_ERROR;
        MEDIA_ERR_LOG("HCameraService::CreatePhotoOutput streamCapture is null");
        CameraReportUtils::ReportCameraError(
            "HCameraService::CreatePhotoOutput", rc, false, CameraReportUtils::GetCallerInfo());
        return rc;
    }

    stringstream ss;
    ss << "format=" << format << " width=" << width << " height=" << height;
    CameraReportUtils::GetInstance().UpdateProfileInfo(ss.str());
    photoOutput = streamCapture;
    MEDIA_INFO_LOG("HCameraService::CreatePhotoOutput execute success");
    return rc;
}

int32_t HCameraService::CreatePhotoOutput(
    int32_t format, int32_t width, int32_t height, sptr<IStreamCapture> &photoOutput)
{
    CAMERA_SYNC_TRACE;
    int32_t rc = CAMERA_OK;
    MEDIA_INFO_LOG("HCameraService::CreatePhotoOutput prepare execute");
    sptr<HStreamCapture> streamCapture = new (nothrow) HStreamCapture(format, width, height);
    if (streamCapture == nullptr) {
        rc = CAMERA_ALLOC_ERROR;
        MEDIA_ERR_LOG("HCameraService::CreatePhotoOutput streamCapture is null");
        CameraReportUtils::ReportCameraError(
            "HCameraService::CreatePhotoOutput", rc, false, CameraReportUtils::GetCallerInfo());
        return rc;
    }

    stringstream ss;
    ss << "format=" << format << " width=" << width << " height=" << height;
    CameraReportUtils::GetInstance().UpdateProfileInfo(ss.str());
    photoOutput = streamCapture;
    MEDIA_INFO_LOG("HCameraService::CreatePhotoOutput execute success");
    return rc;
}

int32_t HCameraService::CreateDeferredPreviewOutput(
    int32_t format, int32_t width, int32_t height, sptr<IStreamRepeat>& previewOutput)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(!CheckSystemApp(), CAMERA_NO_PERMISSION, "HCameraService::CheckSystemApp fail");
    CameraXCollie cameraXCollie = CameraXCollie("HCameraService::CreateDeferredPreviewOutput");
    sptr<HStreamRepeat> streamDeferredPreview;
    MEDIA_INFO_LOG("HCameraService::CreateDeferredPreviewOutput prepare execute");
    CHECK_RETURN_RET_ELOG((width == 0) || (height == 0), CAMERA_INVALID_ARG,
        "HCameraService::CreateDeferredPreviewOutput producer is null!");
    streamDeferredPreview = new (nothrow) HStreamRepeat(nullptr, format, width, height, RepeatStreamType::PREVIEW);
    CHECK_RETURN_RET_ELOG(streamDeferredPreview == nullptr, CAMERA_ALLOC_ERROR,
        "HCameraService::CreateDeferredPreviewOutput HStreamRepeat allocation failed");
    previewOutput = streamDeferredPreview;
    MEDIA_INFO_LOG("HCameraService::CreateDeferredPreviewOutput execute success");
    return CAMERA_OK;
}

int32_t HCameraService::CreatePreviewOutput(const sptr<OHOS::IBufferProducer>& producer, int32_t format, int32_t width,
    int32_t height, sptr<IStreamRepeat>& previewOutput)
{
    CAMERA_SYNC_TRACE;
    sptr<HStreamRepeat> streamRepeatPreview;
    int32_t rc = CAMERA_OK;
    MEDIA_INFO_LOG("HCameraService::CreatePreviewOutput prepare execute");

    if ((producer == nullptr) || (width == 0) || (height == 0)) {
        rc = CAMERA_INVALID_ARG;
        MEDIA_ERR_LOG("HCameraService::CreatePreviewOutput producer is null");
        CameraReportUtils::ReportCameraError(
            "HCameraService::CreatePreviewOutput", rc, false, CameraReportUtils::GetCallerInfo());
        return rc;
    }
#ifdef HOOK_CAMERA_OPERATOR
    if (!CameraRotatePlugin::GetInstance()->
        HookCreatePreviewFormat(GetClientBundle(IPCSkeleton::GetCallingUid()), format)) {
        MEDIA_ERR_LOG("HCameraService::CreatePreviewOutput HookCreatePreviewFormat is failed");
    }
#endif
    streamRepeatPreview = new (nothrow) HStreamRepeat(producer, format, width, height, RepeatStreamType::PREVIEW);
    if (streamRepeatPreview == nullptr) { // LCOV_EXCL_LINE
        rc = CAMERA_ALLOC_ERROR;
        MEDIA_ERR_LOG("HCameraService::CreatePreviewOutput HStreamRepeat allocation failed");
        CameraReportUtils::ReportCameraError(
            "HCameraService::CreatePreviewOutput", rc, false, CameraReportUtils::GetCallerInfo());
        return rc;
    }
    previewOutput = streamRepeatPreview;
    MEDIA_INFO_LOG("HCameraService::CreatePreviewOutput execute success");
    return rc;
}

int32_t HCameraService::CreateDepthDataOutput(const sptr<OHOS::IBufferProducer>& producer, int32_t format,
    int32_t width, int32_t height, sptr<IStreamDepthData>& depthDataOutput)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(
        !CheckSystemApp(), CAMERA_NO_PERMISSION, "HCameraService::CreateDepthDataOutput:SystemApi is called");
    sptr<HStreamDepthData> streamDepthData;
    int32_t rc = CAMERA_OK;
    MEDIA_INFO_LOG("HCameraService::CreateDepthDataOutput prepare execute");

    if ((producer == nullptr) || (width == 0) || (height == 0)) {
        rc = CAMERA_INVALID_ARG;
        MEDIA_ERR_LOG("HCameraService::CreateDepthDataOutput producer is null");
        CameraReportUtils::ReportCameraError(
            "HCameraService::CreateDepthDataOutput", rc, false, CameraReportUtils::GetCallerInfo());
        return rc;
    }
    streamDepthData = new (nothrow) HStreamDepthData(producer, format, width, height);
    if (streamDepthData == nullptr) { // LCOV_EXCL_LINE
        rc = CAMERA_ALLOC_ERROR;
        MEDIA_ERR_LOG("HCameraService::CreateDepthDataOutput HStreamRepeat allocation failed");
        CameraReportUtils::ReportCameraError(
            "HCameraService::CreateDepthDataOutput", rc, false, CameraReportUtils::GetCallerInfo());
        return rc;
    }
    depthDataOutput = streamDepthData;
    MEDIA_INFO_LOG("HCameraService::CreateDepthDataOutput execute success");
    return rc;
}

int32_t HCameraService::CreateMetadataOutput(const sptr<OHOS::IBufferProducer>& producer, int32_t format,
    const std::vector<int32_t>& metadataTypes, sptr<IStreamMetadata>& metadataOutput)
{
    CAMERA_SYNC_TRACE;
    sptr<HStreamMetadata> streamMetadata;
    MEDIA_INFO_LOG("HCameraService::CreateMetadataOutput prepare execute");

    CHECK_RETURN_RET_ELOG(
        producer == nullptr, CAMERA_INVALID_ARG, "HCameraService::CreateMetadataOutput producer is null");
    streamMetadata = new (nothrow) HStreamMetadata(producer, format, metadataTypes);
    CHECK_RETURN_RET_ELOG(streamMetadata == nullptr, CAMERA_ALLOC_ERROR,
        "HCameraService::CreateMetadataOutput HStreamMetadata allocation failed");

    metadataOutput = streamMetadata;
    MEDIA_INFO_LOG("HCameraService::CreateMetadataOutput execute success");
    return CAMERA_OK;
}

int32_t HCameraService::CreateVideoOutput(const sptr<OHOS::IBufferProducer>& producer, int32_t format, int32_t width,
    int32_t height, sptr<IStreamRepeat>& videoOutput)
{
    CAMERA_SYNC_TRACE;
    sptr<HStreamRepeat> streamRepeatVideo;
    int32_t rc = CAMERA_OK;
    MEDIA_INFO_LOG("HCameraService::CreateVideoOutput prepare execute");

    if ((producer == nullptr) || (width == 0) || (height == 0)) {
        rc = CAMERA_INVALID_ARG;
        MEDIA_ERR_LOG("HCameraService::CreateVideoOutput producer is null");
        CameraReportUtils::ReportCameraError(
            "HCameraService::CreateVideoOutput", rc, false, CameraReportUtils::GetCallerInfo());
        return rc;
    }
    streamRepeatVideo = new (nothrow) HStreamRepeat(producer, format, width, height, RepeatStreamType::VIDEO);
    if (streamRepeatVideo == nullptr) { // LCOV_EXCL_LINE
        rc = CAMERA_ALLOC_ERROR;
        MEDIA_ERR_LOG("HCameraService::CreateVideoOutput HStreamRepeat allocation failed");
        CameraReportUtils::ReportCameraError(
            "HCameraService::CreateVideoOutput", rc, false, CameraReportUtils::GetCallerInfo());
        return rc;
    }
    stringstream ss;
    ss << "format=" << format << " width=" << width << " height=" << height;
    CameraReportUtils::GetInstance().UpdateProfileInfo(ss.str());
    videoOutput = streamRepeatVideo;
    MEDIA_INFO_LOG("HCameraService::CreateVideoOutput execute success");
    return rc;
}

int32_t HCameraService::CreateMovieFileOutput(
    int32_t format, int32_t width, int32_t height, sptr<IStreamRepeat>& movieFileStream)
{
#ifdef CAMERA_FRAMEWORK_FEATURE_MEDIA_STREAM
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("CreateMovieFileOutput is called");
    CHECK_RETURN_RET_ELOG(
        !CheckSystemApp(), CAMERA_NO_PERMISSION, "HCameraService::CreateMovieFileOutput CheckSystemApp failed");
    int32_t rc = CAMERA_OK;
    if (width == 0 || height == 0) {
        rc = CAMERA_INVALID_ARG;
        MEDIA_ERR_LOG("input check failed, width or height is invalid");
        return rc;
    }

    auto movieFileStreamRepeat = new (nothrow) HStreamRepeat(
        nullptr, format, width, height, RepeatStreamType::MOVIE_FILE);
    CHECK_RETURN_RET_ELOG(
        movieFileStreamRepeat == nullptr, CAMERA_ALLOC_ERROR, "nullptr check failed, movieFileStreamRepeat is null");
    movieFileStream = movieFileStreamRepeat;
    return rc;
#else
    return CAMERA_OK;
#endif
}

int32_t HCameraService::CreateMovieFileOutput(
    const IpcVideoProfile& videoProfile, sptr<IMovieFileOutput>& movieFileOutput)
{
#ifdef CAMERA_MOVIE_FILE
    int32_t rc = CAMERA_OK;
    MEDIA_INFO_LOG("HCameraService::CreateMovieFileOutput start");
    if (videoProfile.width <= 0 || videoProfile.height <= 0) {
        rc = CAMERA_INVALID_ARG;
        MEDIA_ERR_LOG("HCameraService::CreateMovieFileOutput width or height is invalid");
        return rc;
    }
    HCameraMovieFileOutput::MovieFileOutputFrameRateRange frameRateRange { .minFrameRate = videoProfile.minFrameRate,
        .maxFrameRate = videoProfile.maxFrameRate };
    movieFileOutput = new (nothrow)
        HCameraMovieFileOutput(videoProfile.format, videoProfile.width, videoProfile.height, frameRateRange);
    CHECK_RETURN_RET_ELOG(movieFileOutput == nullptr, CAMERA_ALLOC_ERROR,
        "HCameraService::CreateMovieFileOutput movieFileOutput alloc failed");
    return rc;
#else
    return CAMERA_OK;
#endif
}

bool HCameraService::ShouldSkipStatusUpdates(pid_t pid)
{
    std::lock_guard<std::mutex> lock(freezedPidListMutex_);
    CHECK_RETURN_RET(freezedPidList_.count(pid) == 0, false);
    MEDIA_INFO_LOG("ShouldSkipStatusUpdates pid = %{public}d", pid);
    return true;
}

void HCameraService::CreateAndSaveTask(const string& cameraId, CameraStatus status, uint32_t pid)
{
    auto thisPtr = sptr<HCameraService>(this);
    CHECK_RETURN(!(status == CAMERA_STATUS_APPEAR || status == CAMERA_STATUS_DISAPPEAR));
    auto task = [cameraId, status, pid, thisPtr]() {
        auto itr = thisPtr->cameraServiceCallbacks_.find(pid);
        CHECK_RETURN(itr == thisPtr->cameraServiceCallbacks_.end() || !itr->second);
        MEDIA_INFO_LOG("trigger callback due to unfreeze pid: %{public}d", pid);
        itr->second->OnCameraStatusChanged(cameraId, status, "");
    };
    delayCbtaskMap_[pid][cameraId] = task;
}

void HCameraService::OnCameraStatus(const string& cameraId, CameraStatus status, CallbackInvoker invoker)
{
    lock_guard<mutex> lock(cameraCbMutex_);
    std::string bundleName = "";
    if (invoker == CallbackInvoker::APPLICATION) {
        bundleName = GetClientBundle(IPCSkeleton::GetCallingUid());
    }
    MEDIA_INFO_LOG("HCameraService::OnCameraStatus callbacks.size = %{public}zu, cameraId = %{public}s, "
                   "status = %{public}d, pid = %{public}d, bundleName = %{public}s",
        cameraServiceCallbacks_.size(), cameraId.c_str(), status, IPCSkeleton::GetCallingPid(), bundleName.c_str());
    CacheCameraStatus(
        cameraId, std::make_shared<CameraStatusCallbacksInfo>(CameraStatusCallbacksInfo { status, bundleName }));
    for (auto it : cameraServiceCallbacks_) {
        CHECK_CONTINUE_ELOG(it.second == nullptr,
            "HCameraService::OnCameraStatus pid:%{public}d cameraServiceCallback is null", it.first);
        uint32_t pid = it.first;
        if (ShouldSkipStatusUpdates(pid)) {
            CreateAndSaveTask(cameraId, status, pid);
            continue;
        }
        it.second->OnCameraStatusChanged(cameraId, status, bundleName);
        CAMERA_SYSEVENT_BEHAVIOR(
            CreateMsg("OnCameraStatusChanged! for cameraId:%s, current Camera Status:%d", cameraId.c_str(), status));
    }
    ReportRssCameraStatus(cameraId, status, bundleName);
}

void HCameraService::ReportRssCameraStatus(const std::string& cameraId, int32_t status, const std::string& bundleName)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HCameraService::ReportRssCameraStatus cameraId = %{public}s, status = %{public}d, "
        "bundleName = %{public}s", cameraId.c_str(), status, bundleName.c_str());
    using namespace OHOS::ResourceSchedule;
    std::unordered_map<std::string, std::string> mapPayload;
    mapPayload["camId"] = cameraId;
    mapPayload["cameraStatus"] = std::to_string(status);
    mapPayload["bundleName"] = bundleName;
    ResSchedClient::GetInstance().ReportData(ResType::RES_TYPE_CAMERA_STATUS_CHANGED, 0, mapPayload);
}

void HCameraService::OnFlashlightStatus(const string& cameraId, FlashStatus status)
{
    lock_guard<mutex> lock(cameraCbMutex_);
    MEDIA_INFO_LOG("HCameraService::OnFlashlightStatus callbacks.size = %{public}zu, cameraId = %{public}s, "
                   "status = %{public}d, pid = %{public}d",
        cameraServiceCallbacks_.size(), cameraId.c_str(), status, IPCSkeleton::GetCallingPid());
    for (auto it : cameraServiceCallbacks_) {
        CHECK_CONTINUE_ELOG(it.second == nullptr,
            "HCameraService::OnCameraStatus pid:%{public}d cameraServiceCallback is null", it.first);
        uint32_t pid = it.first;
        CHECK_CONTINUE(ShouldSkipStatusUpdates(pid));
        it.second->OnFlashlightStatusChanged(cameraId, status);
        CacheFlashStatus(cameraId, status);
    }
}

void HCameraService::OnMute(bool muteMode)
{
    lock_guard<mutex> lock(muteCbMutex_);
    if (!cameraMuteServiceCallbacks_.empty()) {
        for (auto it : cameraMuteServiceCallbacks_) {
            CHECK_CONTINUE_ELOG(it.second == nullptr,
                "HCameraService::OnMute pid:%{public}d cameraMuteServiceCallback is null", it.first);
            uint32_t pid = it.first;
            CHECK_CONTINUE(ShouldSkipStatusUpdates(pid));
            it.second->OnCameraMute(muteMode);
            CAMERA_SYSEVENT_BEHAVIOR(CreateMsg("OnCameraMute! current Camera muteMode:%d", muteMode));
        }
    }
    {
        std::lock_guard<std::mutex> peerLock(peerCallbackMutex_);
        if (peerCallback_ != nullptr) {
            MEDIA_INFO_LOG(
                "HCameraService::NotifyMuteCamera peerCallback current camera muteMode:%{public}d", muteMode);
            peerCallback_->NotifyMuteCamera(muteMode);
        }
    }
}

int32_t HCameraService::GetTorchStatus(int32_t &status)
{
    status = static_cast<int32_t>(torchStatus_);
    return CAMERA_OK;
}

void HCameraService::OnTorchStatus(TorchStatus status)
{
    lock_guard<recursive_mutex> lock(torchCbMutex_);
    torchStatus_ = status;
    MEDIA_INFO_LOG("HCameraService::OnTorchtStatus callbacks.size = %{public}zu, status = %{public}d, pid = %{public}d",
        torchServiceCallbacks_.size(), status, IPCSkeleton::GetCallingPid());
    for (auto it : torchServiceCallbacks_) {
        CHECK_CONTINUE_ELOG(it.second == nullptr,
            "HCameraService::OnTorchtStatus pid:%{public}d torchServiceCallback is null", it.first);
        uint32_t pid = it.first;
        CHECK_CONTINUE(ShouldSkipStatusUpdates(pid));
        MEDIA_INFO_LOG("HCameraService::OnTorchStatus level = %{public}f", torchlevel_);
        it.second->OnTorchStatusChange(status, torchlevel_);
    }
}

void HCameraService::OnFoldStatusChanged(OHOS::Rosen::FoldStatus foldStatus)
{
    MEDIA_INFO_LOG("OnFoldStatusChanged preFoldStatus = %{public}d, foldStatus = %{public}d, pid = %{public}d",
        preFoldStatus_, foldStatus, IPCSkeleton::GetCallingPid());
    auto curFoldStatus = (FoldStatus)foldStatus;
    bool isFoldStatusChanged = (curFoldStatus == FoldStatus::HALF_FOLD && preFoldStatus_ == FoldStatus::EXPAND) ||
        (curFoldStatus == FoldStatus::EXPAND && preFoldStatus_ == FoldStatus::HALF_FOLD);
    if (isFoldStatusChanged) {
        preFoldStatus_ = curFoldStatus;
        return;
    }
    preFoldStatus_ = curFoldStatus;
    if (curFoldStatus == FoldStatus::HALF_FOLD) {
        curFoldStatus = FoldStatus::EXPAND;
    }
    lock_guard<recursive_mutex> lock(foldCbMutex_);
    CHECK_EXECUTE(innerFoldCallback_, innerFoldCallback_->OnFoldStatusChanged(curFoldStatus));
    CHECK_RETURN_ELOG(foldServiceCallbacks_.empty(), "OnFoldStatusChanged foldServiceCallbacks is empty");
    MEDIA_INFO_LOG("OnFoldStatusChanged foldStatusCallback size = %{public}zu", foldServiceCallbacks_.size());
    for (auto it : foldServiceCallbacks_) {
        CHECK_CONTINUE_ELOG(
            it.second == nullptr, "OnFoldStatusChanged pid:%{public}d foldStatusCallbacks is null", it.first);
        uint32_t pid = it.first;
        CHECK_CONTINUE(ShouldSkipStatusUpdates(pid));
        it.second->OnFoldStatusChanged(curFoldStatus);
    }
}

int32_t HCameraService::CloseCameraForDestory(pid_t pid)
{
    MEDIA_INFO_LOG("HCameraService::CloseCameraForDestory enter");
    sptr<HCameraDeviceManager> deviceManager = HCameraDeviceManager::GetInstance();
    std::vector<sptr<HCameraDevice>> devicesNeedClose = deviceManager->GetCamerasByPid(pid);
    for (auto device : devicesNeedClose) {
        device->Close();
    }

    std::vector<sptr<HStreamOperator>> streamOperatorToRelease =
        HStreamOperatorManager::GetInstance()->GetStreamOperatorByPid(pid);
    for (auto streamoperator : streamOperatorToRelease) {
        streamoperator->UnlinkOfflineInputAndOutputs();
        streamoperator->Release();
    }
    return CAMERA_OK;
}

void HCameraService::ExecutePidSetCallback(const sptr<ICameraServiceCallback>& callback,
    std::vector<std::string>& cameraIds)
{
    for (const auto& cameraId : cameraIds) {
        auto info = GetCachedCameraStatus(cameraId);
        auto flashStatus = GetCachedFlashStatus(cameraId);
        if (info != nullptr) {
            MEDIA_INFO_LOG("ExecutePidSetCallback cameraId = %{public}s, status = %{public}d, bundleName = %{public}s, "
                           "flash status = %{public}d",
                cameraId.c_str(), info->status, info->bundleName.c_str(), flashStatus);
            callback->OnCameraStatusChanged(cameraId, info->status, info->bundleName);
            callback->OnFlashlightStatusChanged(cameraId, flashStatus);
        } else {
            MEDIA_INFO_LOG("ExecutePidSetCallback cameraId = %{public}s, status = 2", cameraId.c_str());
            callback->OnCameraStatusChanged(cameraId, static_cast<int32_t>(CameraStatus::CAMERA_STATUS_AVAILABLE), "");
            callback->OnFlashlightStatusChanged(cameraId, static_cast<int32_t>(FlashStatus::FLASH_STATUS_UNAVAILABLE));
        }
    }
}

int32_t HCameraService::SetCameraCallback(const sptr<ICameraServiceCallback>& callback)
{
    std::vector<std::string> cameraIds;
    GetCameraIds(cameraIds);
    lock_guard<mutex> lock(cameraCbMutex_);
    pid_t pid = IPCSkeleton::GetCallingPid();
    MEDIA_INFO_LOG("HCameraService::SetCameraCallback pid = %{public}d", pid);
    CHECK_RETURN_RET_ELOG(
        callback == nullptr, CAMERA_INVALID_ARG, "HCameraService::SetCameraCallback callback is null");
    auto callbackItem = cameraServiceCallbacks_.find(pid);
    if (callbackItem != cameraServiceCallbacks_.end()) {
        callbackItem->second = nullptr;
        (void)cameraServiceCallbacks_.erase(callbackItem);
    }
    cameraServiceCallbacks_.insert(make_pair(pid, callback));
    ExecutePidSetCallback(callback, cameraIds);
    return CAMERA_OK;
}

int32_t HCameraService::UnSetCameraCallback()
{
    pid_t pid = IPCSkeleton::GetCallingPid();
    return UnSetCameraCallback(pid);
}

int32_t HCameraService::SetMuteCallback(const sptr<ICameraMuteServiceCallback>& callback)
{
    CHECK_RETURN_RET_ELOG(!CheckSystemApp(), CAMERA_NO_PERMISSION, "HCameraService::CheckSystemApp fail");
    CameraXCollie cameraXCollie = CameraXCollie("HCameraService::SetMuteCallback");
    lock_guard<mutex> lock(muteCbMutex_);
    pid_t pid = IPCSkeleton::GetCallingPid();
    MEDIA_INFO_LOG("HCameraService::SetMuteCallback pid = %{public}d, muteMode:%{public}d", pid, muteModeStored_);
    CHECK_RETURN_RET_ELOG(callback == nullptr, CAMERA_INVALID_ARG, "HCameraService::SetMuteCallback callback is null");
    // If the callback set by the SA caller is later than the camera service is started,
    // the callback cannot be triggered to obtain the mute state. Therefore,
    // when the SA sets the callback, the callback is triggered immediately to return the mute state.
    callback->OnCameraMute(muteModeStored_);
    cameraMuteServiceCallbacks_.insert(make_pair(pid, callback));
    return CAMERA_OK;
}

int32_t HCameraService::UnSetMuteCallback()
{
    pid_t pid = IPCSkeleton::GetCallingPid();
    return UnSetMuteCallback(pid);
}

int32_t HCameraService::SetControlCenterCallback(const sptr<IControlCenterStatusCallback>& callback)
{
    CHECK_RETURN_RET_ELOG(!CheckSystemApp(), CAMERA_NO_PERMISSION, "HCameraService::CheckSystemApp fail");
    lock_guard<mutex> lock(controlCenterStatusMutex_);
    pid_t pid = IPCSkeleton::GetCallingPid();
    MEDIA_INFO_LOG("HCameraService::SetControlCenterCallback pid = %{public}d", pid);
    CHECK_RETURN_RET_ELOG(
        callback == nullptr, CAMERA_INVALID_ARG, "HCameraService::SetControlCenterCallback callback is null");
    controlcenterCallbacks_.insert(make_pair(pid, callback));
    return CAMERA_OK;
}

int32_t HCameraService::UnSetControlCenterStatusCallback()
{
    CHECK_RETURN_RET_ELOG(!CheckSystemApp(), CAMERA_NO_PERMISSION,
        "UnSetControlCenterStatusCallback HCameraService::CheckSystemApp fail");
    pid_t pid = IPCSkeleton::GetCallingPid();
    return UnSetControlCenterStatusCallback(pid);
}

int32_t HCameraService::UnSetControlCenterStatusCallback(pid_t pid)
{
    CHECK_RETURN_RET_ELOG(!CheckSystemApp(), CAMERA_NO_PERMISSION,
        "UnSetControlCenterStatusCallback HCameraService::CheckSystemApp fail");
    lock_guard<mutex> lock(controlCenterStatusMutex_);
    MEDIA_INFO_LOG("HCameraService::UnSetControlCenterStatusCallback pid = %{public}d, size = %{public}zu",
        pid, controlcenterCallbacks_.size());
    if (!controlcenterCallbacks_.empty()) {
        MEDIA_INFO_LOG("UnSetControlCenterStatusCallback controlcenterCallbacks_ is not empty, reset it");
        auto it = controlcenterCallbacks_.find(pid);
        bool isErasePid = (it != controlcenterCallbacks_.end()) && (it->second);
        if (isErasePid) {
            it->second = nullptr;
            controlcenterCallbacks_.erase(it);
        }
    }
    MEDIA_INFO_LOG("HCameraService::UnSetControlCenterStatusCallback after erase pid = %{public}d, size = %{public}zu",
        pid, controlcenterCallbacks_.size());
    return CAMERA_OK;
}

int32_t HCameraService::GetControlCenterStatus(bool& status)
{
    MEDIA_INFO_LOG("HCameraService::GetControlCenterStatus");
    CHECK_RETURN_RET_ELOG(!CheckSystemApp(), CAMERA_NO_PERMISSION, "HCameraService::CheckSystemApp fail");
    CHECK_RETURN_RET_ELOG(
        !controlCenterPrecondition_, CAMERA_OK, "HCameraService::GetControlCenterStatus precondition false.");
    status = isControlCenterEnabled_;
    return CAMERA_OK;
}

int32_t HCameraService::CheckControlCenterPermission()
{
    MEDIA_INFO_LOG("HCameraService::CheckControlCenterPermission");
    int32_t ret = CheckPermission(OHOS_PERMISSION_CAMERA_CONTROL, IPCSkeleton::GetCallingTokenID());
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, ret, "CheckPermission argumentis failed!");
    return CAMERA_OK;
}

int32_t HCameraService::SetCameraSharedStatusCallback(const sptr<IControlCenterStatusCallback>& callback)
{
    CHECK_RETURN_RET_ELOG(!CheckSystemApp(), CAMERA_NO_PERMISSION, "HCameraService::CheckSystemApp fail");
    lock_guard<mutex> lock(cameraSharedStatusMutex_);
    pid_t pid = IPCSkeleton::GetCallingPid();
    MEDIA_INFO_LOG("HCameraService::SetCameraSharedStatusCallback pid = %{public}d", pid);
    CHECK_RETURN_RET_ELOG(
        callback == nullptr, CAMERA_INVALID_ARG, "HCameraService::SetCameraSharedStatusCallback callback is null");
    cameraSharedServiceCallbacks_.insert(make_pair(pid, callback));
    return CAMERA_OK;
}

int32_t HCameraService::UnSetCameraSharedStatusCallback()
{
    CHECK_RETURN_RET_ELOG(!CheckSystemApp(), CAMERA_NO_PERMISSION,
        "UnSetCameraSharedStatusCallback HCameraService::CheckSystemApp fail");
    pid_t pid = IPCSkeleton::GetCallingPid();
    return UnSetCameraSharedStatusCallback(pid);
}

int32_t HCameraService::UnSetCameraSharedStatusCallback(pid_t pid)
{
    CHECK_RETURN_RET_ELOG(!CheckSystemApp(), CAMERA_NO_PERMISSION,
        "UnSetCameraSharedStatusCallback HCameraService::CheckSystemApp fail");
    lock_guard<mutex> lock(cameraSharedStatusMutex_);
    MEDIA_INFO_LOG("HCameraService::UnSetCameraSharedStatusCallback pid = %{public}d, size = %{public}zu",
        pid, cameraSharedServiceCallbacks_.size());
    if (!cameraSharedServiceCallbacks_.empty()) {
        MEDIA_INFO_LOG("UnSetCameraSharedStatusCallback cameraSharedServiceCallbacks_ is not empty, reset it");
        auto it = cameraSharedServiceCallbacks_.find(pid);
        bool isErasePid = (it != cameraSharedServiceCallbacks_.end()) && (it->second);
        if (isErasePid) {
            it->second = nullptr;
            cameraSharedServiceCallbacks_.erase(it);
        }
    }
    MEDIA_INFO_LOG("HCameraService::UnSetCameraSharedStatusCallback after erase pid = %{public}d, size = %{public}zu",
        pid, cameraSharedServiceCallbacks_.size());
    return CAMERA_OK;
}

int32_t HCameraService::SetTorchCallback(const sptr<ITorchServiceCallback>& callback)
{
    lock_guard<recursive_mutex> lock(torchCbMutex_);
    pid_t pid = IPCSkeleton::GetCallingPid();
    MEDIA_INFO_LOG("HCameraService::SetTorchCallback pid = %{public}d", pid);
    CHECK_RETURN_RET_ELOG(callback == nullptr, CAMERA_INVALID_ARG, "HCameraService::SetTorchCallback callback is null");
    torchServiceCallbacks_.insert(make_pair(pid, callback));
    MEDIA_INFO_LOG("HCameraService::SetTorchCallback notify pid = %{public}d, Torchlevel = %{public}f",
        pid, torchlevel_);
    callback->OnTorchStatusChange(torchStatus_, torchlevel_);
    return CAMERA_OK;
}

int32_t HCameraService::UnSetTorchCallback()
{
    pid_t pid = IPCSkeleton::GetCallingPid();
    return UnSetTorchCallback(pid);
}

int32_t HCameraService::SetFoldStatusCallback(const sptr<IFoldServiceCallback>& callback, bool isInnerCallback)
{
    lock_guard<recursive_mutex> lock(foldCbMutex_);
    isFoldable = isFoldableInit ? isFoldable : g_isFoldScreen;
    CHECK_EXECUTE((isFoldable && !isFoldRegister), RegisterFoldStatusListener());
    if (isInnerCallback) {
        innerFoldCallback_ = callback;
    } else {
        pid_t pid = IPCSkeleton::GetCallingPid();
        MEDIA_INFO_LOG("HCameraService::SetFoldStatusCallback pid = %{public}d", pid);
        CHECK_RETURN_RET_ELOG(
            callback == nullptr, CAMERA_INVALID_ARG, "HCameraService::SetFoldStatusCallback callback is null");
        foldServiceCallbacks_.insert(make_pair(pid, callback));
    }
    return CAMERA_OK;
}

int32_t HCameraService::UnSetFoldStatusCallback()
{
    pid_t pid = IPCSkeleton::GetCallingPid();
    return UnSetFoldStatusCallback(pid);
}

int32_t HCameraService::UnSetCameraCallback(pid_t pid)
{
    lock_guard<mutex> lock(cameraCbMutex_);
    MEDIA_INFO_LOG("HCameraService::UnSetCameraCallback pid = %{public}d, size = %{public}zu",
        pid, cameraServiceCallbacks_.size());
    if (!cameraServiceCallbacks_.empty()) {
        MEDIA_INFO_LOG("HCameraService::UnSetCameraCallback cameraServiceCallbacks_ is not empty, reset it");
        auto it = cameraServiceCallbacks_.find(pid);
        bool isErssePid = (it != cameraServiceCallbacks_.end()) && (it->second != nullptr);
        if (isErssePid) {
            it->second = nullptr;
            cameraServiceCallbacks_.erase(it);
        }
    }
    MEDIA_INFO_LOG("HCameraService::UnSetCameraCallback after erase pid = %{public}d, size = %{public}zu",
        pid, cameraServiceCallbacks_.size());
    return CAMERA_OK;
}

int32_t HCameraService::UnSetMuteCallback(pid_t pid)
{
    lock_guard<mutex> lock(muteCbMutex_);
    MEDIA_INFO_LOG("HCameraService::UnSetMuteCallback pid = %{public}d, size = %{public}zu",
        pid, cameraMuteServiceCallbacks_.size());
    if (!cameraMuteServiceCallbacks_.empty()) {
        MEDIA_INFO_LOG("HCameraService::UnSetMuteCallback cameraMuteServiceCallbacks_ is not empty, reset it");
        auto it = cameraMuteServiceCallbacks_.find(pid);
        bool isErasePid = (it != cameraMuteServiceCallbacks_.end()) && (it->second);
        if (isErasePid) {
            it->second = nullptr;
            cameraMuteServiceCallbacks_.erase(it);
        }
    }

    MEDIA_INFO_LOG("HCameraService::UnSetMuteCallback after erase pid = %{public}d, size = %{public}zu",
        pid, cameraMuteServiceCallbacks_.size());
    return CAMERA_OK;
}

int32_t HCameraService::UnSetTorchCallback(pid_t pid)
{
    lock_guard<recursive_mutex> lock(torchCbMutex_);
    MEDIA_INFO_LOG("HCameraService::UnSetTorchCallback pid = %{public}d, size = %{public}zu",
        pid, torchServiceCallbacks_.size());
    if (!torchServiceCallbacks_.empty()) {
        MEDIA_INFO_LOG("HCameraService::UnSetTorchCallback torchServiceCallbacks_ is not empty, reset it");
        auto it = torchServiceCallbacks_.find(pid);
        bool isErasePid = (it != torchServiceCallbacks_.end()) && (it->second);
        if (isErasePid) {
            it->second = nullptr;
            torchServiceCallbacks_.erase(it);
        }
    }

    MEDIA_INFO_LOG("HCameraService::UnSetTorchCallback after erase pid = %{public}d, size = %{public}zu",
        pid, torchServiceCallbacks_.size());
    return CAMERA_OK;
}

int32_t HCameraService::UnSetFoldStatusCallback(pid_t pid)
{
    lock_guard<recursive_mutex> lock(foldCbMutex_);
    MEDIA_INFO_LOG("HCameraService::UnSetFoldStatusCallback pid = %{public}d, size = %{public}zu",
        pid, foldServiceCallbacks_.size());
    if (!foldServiceCallbacks_.empty()) {
        MEDIA_INFO_LOG("HCameraService::UnSetFoldStatusCallback foldServiceCallbacks_ is not empty, reset it");
        auto it = foldServiceCallbacks_.find(pid);
        bool isErasePid = (it != foldServiceCallbacks_.end()) && (it->second);
        if (isErasePid) {
            it->second = nullptr;
            foldServiceCallbacks_.erase(it);
        }
    }
    MEDIA_INFO_LOG("HCameraService::UnSetFoldStatusCallback after erase pid = %{public}d, size = %{public}zu",
        pid, foldServiceCallbacks_.size());
    innerFoldCallback_ = nullptr;
    return CAMERA_OK;
}

void HCameraService::RegisterFoldStatusListener()
{
    MEDIA_INFO_LOG("RegisterFoldStatusListener is called");
    preFoldStatus_ = (FoldStatus)OHOS::Rosen::DisplayManagerLite::GetInstance().GetFoldStatus();
    auto ret = OHOS::Rosen::DisplayManagerLite::GetInstance().RegisterFoldStatusListener(this);
    CHECK_RETURN_ELOG(ret != OHOS::Rosen::DMError::DM_OK, "RegisterFoldStatusListener failed");
    isFoldRegister = true;
}

void HCameraService::UnregisterFoldStatusListener()
{
    MEDIA_INFO_LOG("UnregisterFoldStatusListener is called");
    auto ret = OHOS::Rosen::DisplayManagerLite::GetInstance().UnregisterFoldStatusListener(this);
    preFoldStatus_ = FoldStatus::UNKNOWN_FOLD;
    CHECK_PRINT_ELOG(ret != OHOS::Rosen::DMError::DM_OK, "UnregisterFoldStatusListener failed");
    isFoldRegister = false;
}

int32_t HCameraService::UnSetAllCallback(pid_t pid)
{
    MEDIA_INFO_LOG("HCameraService::UnSetAllCallback enter");
    UnSetCameraCallback(pid);
    UnSetMuteCallback(pid);
    UnSetTorchCallback(pid);
    UnSetFoldStatusCallback(pid);
    return CAMERA_OK;
}

bool HCameraService::IsCameraMuteSupported(string cameraId)
{
    bool isMuteSupported = false;
    shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility;
    int32_t ret = cameraHostManager_->GetCameraAbility(cameraId, cameraAbility);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, false, "HCameraService::IsCameraMuted GetCameraAbility failed");
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = cameraAbility->get();
    ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_MUTE_MODES, &item);
    CHECK_RETURN_RET_ELOG(
        ret != CAM_META_SUCCESS, false, "HCameraService::IsCameraMuted not find MUTE ability, ret: %{public}d", ret);
    for (uint32_t i = 0; i < item.count; i++) {
        MEDIA_INFO_LOG("OHOS_ABILITY_MUTE_MODES %{public}d th is %{public}d", i, item.data.u8[i]);
        if (item.data.u8[i] == OHOS_CAMERA_MUTE_MODE_SOLID_COLOR_BLACK) {
            isMuteSupported = true;
            break;
        }
    }
    MEDIA_DEBUG_LOG("HCameraService::IsCameraMuted supported: %{public}d", isMuteSupported);
    return isMuteSupported;
}

int32_t HCameraService::UpdateMuteSetting(sptr<HCameraDevice> cameraDevice, bool muteMode)
{
    constexpr int32_t DEFAULT_ITEMS = 1;
    constexpr int32_t DEFAULT_DATA_LENGTH = 1;
    shared_ptr<OHOS::Camera::CameraMetadata> changedMetadata =
        make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    int32_t count = 1;
    uint8_t mode = muteMode ? OHOS_CAMERA_MUTE_MODE_SOLID_COLOR_BLACK : OHOS_CAMERA_MUTE_MODE_OFF;

    MEDIA_DEBUG_LOG("UpdateMuteSetting muteMode: %{public}d", muteMode);

    bool status = AddOrUpdateMetadata(changedMetadata, OHOS_CONTROL_MUTE_MODE, &mode, count);
    int32_t ret = cameraDevice->UpdateSetting(changedMetadata);
    CHECK_RETURN_RET_ELOG(!status || ret != CAMERA_OK, CAMERA_UNKNOWN_ERROR, "UpdateMuteSetting muteMode Failed");
    return CAMERA_OK;
}

int32_t HCameraService::MuteCameraFunc(bool muteMode)
{
    {
        lock_guard<mutex> lock(g_dataShareHelperMutex);
        cameraHostManager_->SetMuteMode(muteMode);
    }
    int32_t ret = CAMERA_OK;
    bool currentMuteMode = muteModeStored_;
    sptr<HCameraDeviceManager> deviceManager = HCameraDeviceManager::GetInstance();
    std::vector<sptr<HCameraDeviceHolder>> deviceHolderVector = deviceManager->GetActiveCameraHolders();
    if (deviceHolderVector.size() == 0) {
        OnMute(muteMode);
        int32_t retCode = SetMuteModeByDataShareHelper(muteMode);
        muteModeStored_ = muteMode;
        if (retCode != CAMERA_OK) {
            MEDIA_ERR_LOG("no activeClient, SetMuteModeByDataShareHelper: ret=%{public}d", retCode);
            muteModeStored_ = currentMuteMode;
        }
        return retCode;
    }
    for (sptr<HCameraDeviceHolder> activeDeviceHolder : deviceHolderVector) {
        sptr<HCameraDevice> activeDevice = activeDeviceHolder->GetDevice();
        if (activeDevice != nullptr) {
            string cameraId = activeDevice->GetCameraId();
            CHECK_RETURN_RET_ELOG(!IsCameraMuteSupported(cameraId), CAMERA_UNSUPPORTED,
                "Not Supported Mute,cameraId: %{public}s", cameraId.c_str());
            if (activeDevice != nullptr) {
                ret = UpdateMuteSetting(activeDevice, muteMode);
            }
            if (ret != CAMERA_OK) {
                MEDIA_ERR_LOG("UpdateMuteSetting Failed, cameraId: %{public}s", cameraId.c_str());
                muteModeStored_ = currentMuteMode;
            }
        }
        if (activeDevice != nullptr) {
            activeDevice->SetDeviceMuteMode(muteMode);
        }
    }

    if (ret == CAMERA_OK) {
        OnMute(muteMode);
    }
    ret = SetMuteModeByDataShareHelper(muteMode);
    if (ret == CAMERA_OK) {
        muteModeStored_ = muteMode;
    }
    return ret;
}

int32_t HCameraService::EnableControlCenter(bool status, bool needPersistEnable)
{
    MEDIA_INFO_LOG("HCameraService::EnableControlCenter");
    CHECK_RETURN_RET_ELOG(!controlCenterPrecondition_, CAMERA_INVALID_STATE, "ControlCenterPrecondition false.");
    lock_guard<mutex> lock(controlCenterStatusMutex_);
    auto ret = UpdateDataShareAndTag(status, needPersistEnable);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, ret, "UpdateDataShareAndTag failed.");

    MEDIA_INFO_LOG("EnableControlCenter success.");
    isControlCenterEnabled_ = status;
    CHECK_RETURN_RET_ELOG(controlcenterCallbacks_.empty(), ret, "IControlCenterStatusCallback is empty.");
    for (auto it : controlcenterCallbacks_) {
        if (it.second == nullptr) {
            MEDIA_ERR_LOG("OnControlCenterStatusChanged pid:%{public}d Callbacks is null", it.first);
            continue;
        }
        uint32_t pid = it.first;
        if (ShouldSkipStatusUpdates(pid)) {
            continue;
        }
        it.second->OnControlCenterStatusChanged(status);
    }
    return ret;
}

int32_t HCameraService::SetControlCenterPrecondition(bool condition)
{
    MEDIA_INFO_LOG("HCameraService::SetControlCenterPrecondition %{public}d", condition);
    sptr<HCaptureSession> sessionForControlCenter = GetSessionForControlCenter();
    controlCenterPrecondition_ = condition;
    if (sessionForControlCenter != nullptr) {
        sessionForControlCenter->SetControlCenterPrecondition(controlCenterPrecondition_);
    }
    CHECK_RETURN_RET_DLOG(
        controlCenterPrecondition_ || !isControlCenterEnabled_, CAMERA_OK, "SetControlCenterPrecondition success.");
    auto ret = EnableControlCenter(false, true);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, ret, "EnableControlCenter failed.");
    isControlCenterEnabled_ = false;
    lock_guard<mutex> lock(controlCenterStatusMutex_);
    for (auto it : controlcenterCallbacks_) {
        if (it.second == nullptr) {
            MEDIA_ERR_LOG("OnControlCenterStatusChanged pid:%{public}d Callbacks is null", it.first);
            continue;
        }
        uint32_t pid = it.first;
        if (ShouldSkipStatusUpdates(pid)) {
            continue;
        }
        it.second->OnControlCenterStatusChanged(false);
    }
    return CAMERA_OK;
}

int32_t HCameraService::SetDeviceControlCenterAbility(bool ability)
{
    deviceControlCenterAbility_ = ability;
    return CAMERA_OK;
}

int32_t HCameraService::GetDeviceControlCenterAbility(bool &ability)
{
    ability = deviceControlCenterAbility_;
    return CAMERA_OK;
}

void HCameraService::CacheCameraStatus(const string& cameraId, std::shared_ptr<CameraStatusCallbacksInfo> info)
{
    std::lock_guard<std::mutex> lock(cameraStatusCallbacksMutex_);
    cameraStatusCallbacks_[cameraId] = info;
}

std::shared_ptr<CameraStatusCallbacksInfo> HCameraService::GetCachedCameraStatus(const string& cameraId)
{
    std::lock_guard<std::mutex> lock(cameraStatusCallbacksMutex_);
    auto it = cameraStatusCallbacks_.find(cameraId);
    return it == cameraStatusCallbacks_.end() ? nullptr : it->second;
}

void HCameraService::CacheFlashStatus(const string& cameraId, FlashStatus flashStatus)
{
    std::lock_guard<std::mutex> lock(flashStatusCallbacksMutex_);
    flashStatusCallbacks_[cameraId] = flashStatus;
}

FlashStatus HCameraService::GetCachedFlashStatus(const string& cameraId)
{
    std::lock_guard<std::mutex> lock(flashStatusCallbacksMutex_);
    auto it = flashStatusCallbacks_.find(cameraId);
    return it == flashStatusCallbacks_.end() ? FlashStatus::FLASH_STATUS_UNAVAILABLE : it->second;
}

static std::map<PolicyType, Security::AccessToken::PolicyType> g_policyTypeMap_ = {
    {PolicyType::EDM, Security::AccessToken::PolicyType::EDM},
    {PolicyType::PRIVACY, Security::AccessToken::PolicyType::PRIVACY},
};

int32_t HCameraService::MuteCamera(bool muteMode)
{
    CHECK_RETURN_RET_ELOG(!CheckSystemApp(), CAMERA_NO_PERMISSION, "HCameraService::CheckSystemApp fail");
    CameraXCollie cameraXCollie = CameraXCollie("HCameraService::MuteCamera");
    int32_t ret = CheckPermission(OHOS_PERMISSION_MANAGE_CAMERA_CONFIG, IPCSkeleton::GetCallingTokenID());
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, ret, "CheckPermission argumentis failed!");
    CameraReportUtils::GetInstance().ReportUserBehavior(DFX_UB_MUTE_CAMERA,
        to_string(muteMode), CameraReportUtils::GetCallerInfo());
    return MuteCameraFunc(muteMode);
}

int32_t HCameraService::MuteCameraPersist(PolicyType policyType, bool isMute)
{
    CHECK_RETURN_RET_ELOG(!CheckSystemApp(), CAMERA_NO_PERMISSION, "HCameraService::CheckSystemApp fail");
    CameraXCollie cameraXCollie = CameraXCollie("HCameraService::MuteCameraPersist");
    OHOS::Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t ret = CheckPermission(OHOS_PERMISSION_CAMERA_CONTROL, callerToken);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, ret, "CheckPermission arguments failed!");
    CameraReportUtils::GetInstance().ReportUserBehavior(DFX_UB_MUTE_CAMERA,
        to_string(isMute), CameraReportUtils::GetCallerInfo());
    CHECK_RETURN_RET_ELOG(g_policyTypeMap_.count(policyType) == 0, CAMERA_INVALID_ARG,
        "MuteCameraPersist Failed, invalid param policyType = %{public}d", static_cast<int32_t>(policyType));
    bool targetMuteMode = isMute;
    const Security::AccessToken::PolicyType secPolicyType = g_policyTypeMap_[policyType];
    const Security::AccessToken::CallerType secCaller = Security::AccessToken::CallerType::CAMERA;
    ret = Security::AccessToken::PrivacyKit::SetMutePolicy(secPolicyType, secCaller, isMute, callerToken);
    if (ret != Security::AccessToken::RET_SUCCESS) { // LCOV_EXCL_LINE
        MEDIA_ERR_LOG("MuteCameraPersist SetMutePolicy return false, policyType = %{public}d, retCode = %{public}d",
            static_cast<int32_t>(policyType), static_cast<int32_t>(ret));
        targetMuteMode = muteModeStored_;
    }
    return MuteCameraFunc(targetMuteMode);
}

int32_t HCameraService::PrelaunchCamera(int32_t flag)
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(preCameraMutex_);
    CHECK_RETURN_RET_ELOG(!CheckSystemApp(), CAMERA_NO_PERMISSION, "HCameraService::CheckSystemApp fail");
    CameraXCollie cameraXCollie = CameraXCollie("HCameraService::PrelaunchCamera");
    MEDIA_INFO_LOG("HCameraService::PrelaunchCamera");
    CHECK_RETURN_RET_ELOG(torchStatus_ == TorchStatus::TORCH_STATUS_ON, CAMERA_DEVICE_CONFLICT,
        "HCameraService::PrelaunchCamera torch is running, abort!");
    #ifdef MEMMGR_OVERRID
        PrelaunchRequireMemory(flag);
    #endif
    // only touch up and no flag enable prelaunch
    CHECK_RETURN_RET((flag != 1) && (flag != -1), CAMERA_OK);
    // notify deferredprocess stop
    DeferredProcessing::DeferredProcessingService::GetInstance().NotifyInterrupt();
    MEDIA_INFO_LOG("HCameraService::PrelaunchCamera E");
    CHECK_RETURN_RET_ELOG(HCameraDeviceManager::GetInstance()->GetCameraStateOfASide().Size() != 0,
        CAMERA_DEVICE_CONFLICT, "HCameraService::PrelaunchCamera there is a device active in A side, abort!");
    if (preCameraId_.empty()) {
        MEDIA_DEBUG_LOG("HCameraService::PrelaunchCamera firstBoot in");
        if (OHOS::Rosen::DisplayManagerLite::GetInstance().IsFoldable()) { // LCOV_EXCL_LINE
            // foldable devices
            MEDIA_DEBUG_LOG("HCameraService::PrelaunchCamera firstBoot foldable");
            FoldStatus curFoldStatus = (FoldStatus)OHOS::Rosen::DisplayManagerLite::GetInstance().GetFoldStatus();
            MEDIA_DEBUG_LOG("HCameraService::PrelaunchCamera curFoldStatus:%d", curFoldStatus);
            std::vector<std::string> cameraIds;
            std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>> cameraAbilityList;
            int32_t retCode = GetCameras(cameraIds, cameraAbilityList);
            CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, CAMERA_OK, "HCameraService::PrelaunchCamera exit");
            int8_t camIdx = ChooseFisrtBootFoldCamIdx(curFoldStatus, cameraAbilityList);
            CHECK_RETURN_RET_ELOG(camIdx == -1, CAMERA_OK, "HCameraService::PrelaunchCamera exit");
            preCameraId_ = cameraIds[camIdx];
        } else {
            // unfoldable devices
            MEDIA_DEBUG_LOG("HCameraService::PrelaunchCamera firstBoot unfoldable");
            vector<string> cameraIds_;
            cameraHostManager_->GetCameras(cameraIds_);
            CHECK_RETURN_RET_ELOG(cameraIds_.empty(), CAMERA_OK, "HCameraService::PrelaunchCamera exit");
            preCameraId_ = cameraIds_.front();
        }
    }
    HILOG_COMM_INFO("HCameraService::PrelaunchCamera preCameraId_ is: %{public}s", preCameraId_.c_str());
    CAMERA_SYSEVENT_STATISTIC(CreateMsg("Camera Prelaunch CameraId:%s", preCameraId_.c_str()));
    CameraReportUtils::GetInstance().SetOpenCamPerfPreInfo(preCameraId_.c_str(), CameraReportUtils::GetCallerInfo());
    int32_t ret = cameraHostManager_->Prelaunch(preCameraId_, preCameraClient_);
    CHECK_PRINT_ELOG(ret != CAMERA_OK, "HCameraService::Prelaunch failed");
    return ret;
}

int32_t HCameraService::ResetRssPriority()
{
    CHECK_RETURN_RET_ELOG(!CheckSystemApp(), CAMERA_NO_PERMISSION, "HCameraService::CheckSystemApp fail");
    CameraXCollie cameraXCollie = CameraXCollie("HCameraService::ResetRssPriority");
    MEDIA_INFO_LOG("HCameraService::ResetRssPriority");
    std::unordered_map<std::string, std::string> payload;
    OHOS::ResourceSchedule::ResSchedClient::GetInstance()
        .ReportData(ResourceSchedule::ResType::RES_TYPE_CAMERA_RESET_PRIORITY, 0, payload);
    return CAMERA_OK;
}

// LCOV_EXCL_START
/**
    camIdx select strategy:
    1. make sure curFoldStatus match foldStatusValue
    2. priority: BACK > FRONT > OTHER
    curFoldStatus 0: UNKNOWN_FOLD
    curFoldStatus 1: EXPAND
    curFoldStatus 2: FOLDED
    curFoldStatus 3: HALF_FOLD
    foldStatusValue 0: OHOS_CAMERA_FOLD_STATUS_NONFOLDABLE
    foldStatusValue 1: OHOS_CAMERA_FOLD_STATUS_EXPANDED
    foldStatusValue 2: OHOS_CAMERA_FOLD_STATUS_FOLDED
    foldStatusValue 3: OHOS_CAMERA_FOLD_STATUS_EXPANDED + OHOS_CAMERA_FOLD_STATUS_FOLDED
    positionValue 0: OHOS_CAMERA_POSITION_FRONT
    positionValue 1: OHOS_CAMERA_POSITION_BACK
    positionValue 2: OHOS_CAMERA_POSITION_OTHER
*/
int8_t HCameraService::ChooseFisrtBootFoldCamIdx(
    FoldStatus curFoldStatus, std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>> cameraAbilityList)
{
    int8_t camIdx = -1;
    uint8_t foldStatusValue = 0;
    uint8_t positionValue = 0;
    uint8_t EXPAND_SUPPORT = 1;
    uint8_t FOLD_SUPPORT = 2;
    uint8_t ALL_SUPPORT = 3;
    for (size_t i = 0; i < cameraAbilityList.size(); i++) {
        camera_metadata_item_t item;
        int ret =
            OHOS::Camera::FindCameraMetadataItem(cameraAbilityList[i]->get(), OHOS_ABILITY_CAMERA_FOLD_STATUS, &item);
        bool isSupportCurrentDevice = ret == CAM_META_SUCCESS && item.count > 0;
        if (isSupportCurrentDevice) {
            MEDIA_DEBUG_LOG("HCameraService::PrelaunchCamera device fold ablity is %{public}d", item.data.u8[0]);
            foldStatusValue = item.data.u8[0];
        } else {
            MEDIA_DEBUG_LOG("HCameraService::PrelaunchCamera device ablity not found");
            foldStatusValue = 0;
        }
        ret = OHOS::Camera::FindCameraMetadataItem(cameraAbilityList[i]->get(), OHOS_ABILITY_CAMERA_POSITION, &item);
        isSupportCurrentDevice = ret == CAM_META_SUCCESS && item.count > 0;
        if (isSupportCurrentDevice) {
            MEDIA_DEBUG_LOG("HCameraService::PrelaunchCamera device position is %{public}d", item.data.u8[0]);
            positionValue = item.data.u8[0];
        } else {
            MEDIA_DEBUG_LOG("HCameraService::PrelaunchCamera device position not found");
            positionValue = 0;
        }
        // check is fold supported
        bool isFoldSupported = false;
        if (curFoldStatus == FoldStatus::FOLDED) {
            isFoldSupported = (foldStatusValue == FOLD_SUPPORT || foldStatusValue == ALL_SUPPORT);
        } else if (curFoldStatus == FoldStatus::EXPAND || curFoldStatus == FoldStatus::HALF_FOLD) {
            isFoldSupported = (foldStatusValue == EXPAND_SUPPORT || foldStatusValue == ALL_SUPPORT);
        }
        // choose camIdx by priority
        if (isFoldSupported) {
            if (positionValue == OHOS_CAMERA_POSITION_BACK) {
                camIdx = i;
                break; // use BACK
            } else if (positionValue == OHOS_CAMERA_POSITION_FRONT && camIdx == -1) {
                camIdx = i; // record FRONT find BACK continue
            } else if (positionValue == OHOS_CAMERA_POSITION_OTHER && camIdx == -1) {
                camIdx = i; // record OTHER find BACK&FRONT continue
            }
        }
    }
    return camIdx;
}
// LCOV_EXCL_STOP

int32_t HCameraService::PreSwitchCamera(const std::string& cameraId)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(!CheckSystemApp(), CAMERA_NO_PERMISSION, "HCameraService::CheckSystemApp fail");
    CameraXCollie cameraXCollie = CameraXCollie("HCameraService::PreSwitchCamera");
    MEDIA_INFO_LOG("HCameraService::PreSwitchCamera");
    CHECK_RETURN_RET(cameraId.empty() || cameraId.length() > PATH_MAX, CAMERA_INVALID_ARG);
    std::vector<std::string> cameraIds_;
    cameraHostManager_->GetCameras(cameraIds_);
    CHECK_RETURN_RET(cameraIds_.empty(), CAMERA_INVALID_STATE);
    auto it = std::find(cameraIds_.begin(), cameraIds_.end(), cameraId);
    CHECK_RETURN_RET(it == cameraIds_.end(), CAMERA_INVALID_ARG);
    MEDIA_INFO_LOG("HCameraService::PreSwitchCamera cameraId is: %{public}s", cameraId.c_str());
    CameraReportUtils::GetInstance().SetSwitchCamPerfStartInfo(CameraReportUtils::GetCallerInfo());
    int32_t ret = cameraHostManager_->PreSwitchCamera(cameraId);
    CHECK_PRINT_ELOG(ret != CAMERA_OK, "HCameraService::Prelaunch failed");
    return ret;
}

int32_t HCameraService::SetPrelaunchConfig(const string& cameraId, RestoreParamTypeOhos restoreParamType,
    int activeTime, const EffectParam& effectParam)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(!CheckSystemApp(), CAMERA_NO_PERMISSION, "HCameraService::CheckSystemApp fail");
    CameraXCollie cameraXCollie = CameraXCollie("HCameraService::SetPrelaunchConfig");
    OHOS::Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    string permissionName = OHOS_PERMISSION_CAMERA;
    int32_t ret = CheckPermission(permissionName, callerToken);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, ret, "HCameraService::SetPrelaunchConfig failed permission is: %{public}s",
        permissionName.c_str());

    MEDIA_INFO_LOG("HCameraService::SetPrelaunchConfig cameraId %{public}s", (cameraId).c_str());
    vector<string> cameraIds_;
    cameraHostManager_->GetCameras(cameraIds_);
    bool isFindCameraIds =
        (find(cameraIds_.begin(), cameraIds_.end(), cameraId) != cameraIds_.end()) && IsPrelaunchSupported(cameraId);
    if (isFindCameraIds) {
        preCameraId_ = cameraId;
        MEDIA_INFO_LOG("CameraHostInfo::SetPrelaunchConfig for cameraId %{public}s", (cameraId).c_str());
        sptr<HCaptureSession> captureSession_ = nullptr;
        pid_t pid = IPCSkeleton::GetCallingPid();
        auto &sessionManager = HCameraSessionManager::GetInstance();
        captureSession_ = sessionManager.GetGroupDefaultSession(pid);
        preCameraClient_ = GetClientBundle(IPCSkeleton::GetCallingUid());
        sptr<HCameraRestoreParam> cameraRestoreParam = new HCameraRestoreParam(preCameraClient_, cameraId);
        SaveCurrentParamForRestore(cameraRestoreParam, static_cast<RestoreParamTypeOhos>(restoreParamType), activeTime,
            effectParam, captureSession_);
    } else {
        MEDIA_ERR_LOG("HCameraService::SetPrelaunchConfig illegal");
        ret = CAMERA_INVALID_ARG;
    }
    return ret;
}

int32_t HCameraService::SetTorchLevel(float level)
{
    float oldlevel = torchlevel_;
    torchlevel_ = level;
    int32_t ret = cameraHostManager_->SetTorchLevel(level);
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("Failed to SetTorchLevel");
        torchlevel_ = oldlevel;
    }
    MEDIA_INFO_LOG("HCameraService::SetTorchLevelBack = %{public}f", torchlevel_);
    return ret;
}

int32_t HCameraService::AllowOpenByOHSide(const std::string& cameraId, int32_t state, bool& canOpenCamera)
{
    MEDIA_INFO_LOG("HCameraService::AllowOpenByOHSide start");
    std::vector<pid_t> activePids = HCameraDeviceManager::GetInstance()->GetActiveClient();
    if (activePids.size() == 0) {
        MEDIA_INFO_LOG("AllowOpenByOHSide::Open allow open camera");
        NotifyCameraState(cameraId, 0);
        canOpenCamera = true;
        return CAMERA_OK;
    }
    for (auto eachPid : activePids) {
        std::vector<sptr<HCameraDevice>> camerasNeedEvict =
            HCameraDeviceManager::GetInstance()->GetCamerasByPid(eachPid);
        for (auto device : camerasNeedEvict) {
            device->OnError(DEVICE_PREEMPT, 0);
            device->Close();
            NotifyCameraState(cameraId, 0);
        }
    }
    canOpenCamera = true;
    MEDIA_INFO_LOG("HCameraService::AllowOpenByOHSide end");
    return CAMERA_OK;
}

int32_t HCameraService::NotifyCameraState(const std::string& cameraId, int32_t state)
{
    // 把cameraId和前后台状态刷新给device manager
    MEDIA_INFO_LOG(
        "HCameraService::NotifyCameraState SetStateOfACamera %{public}s:%{public}d", cameraId.c_str(), state);
    HCameraDeviceManager::GetInstance()->SetStateOfACamera(cameraId, state);
    return CAMERA_OK;
}

int32_t HCameraService::SetPeerCallback(const sptr<ICameraBroker>& callback)
{
    MEDIA_INFO_LOG("SetPeerCallback get callback");
    CHECK_RETURN_RET(callback == nullptr, CAMERA_INVALID_ARG);
    {
        std::lock_guard<std::mutex> lock(peerCallbackMutex_);
        peerCallback_ = callback;
    }
    MEDIA_INFO_LOG("HCameraService::SetPeerCallback current muteMode:%{public}d", muteModeStored_);
    callback->NotifyMuteCamera(muteModeStored_);
    HCameraDeviceManager::GetInstance()->SetPeerCallback(callback);
    return CAMERA_OK;
}

int32_t HCameraService::UnsetPeerCallback()
{
    MEDIA_INFO_LOG("UnsetPeerCallback callback");
    {
        std::lock_guard<std::mutex> lock(peerCallbackMutex_);
        peerCallback_ = nullptr;
    }
    HCameraDeviceManager::GetInstance()->UnsetPeerCallback();
    return CAMERA_OK;
}

bool HCameraService::IsPrelaunchSupported(string cameraId)
{
    bool isPrelaunchSupported = false;
    shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility;
    int32_t ret = cameraHostManager_->GetCameraAbility(cameraId, cameraAbility);
    CHECK_RETURN_RET_ELOG(
        ret != CAMERA_OK, isPrelaunchSupported, "HCameraService::IsCameraMuted GetCameraAbility failed");
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = cameraAbility->get();
    ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_PRELAUNCH_AVAILABLE, &item);
    if (ret == 0) {
        MEDIA_INFO_LOG(
            "CameraManager::IsPrelaunchSupported() OHOS_ABILITY_PRELAUNCH_AVAILABLE is %{public}d", item.data.u8[0]);
        isPrelaunchSupported = (item.data.u8[0] == 1);
    } else {
        MEDIA_ERR_LOG("Failed to get OHOS_ABILITY_PRELAUNCH_AVAILABLE ret = %{public}d", ret);
    }
    return isPrelaunchSupported;
}

CameraServiceStatus HCameraService::GetServiceStatus()
{
    lock_guard<mutex> lock(serviceStatusMutex_);
    return serviceStatus_;
}

void HCameraService::SetServiceStatus(CameraServiceStatus serviceStatus)
{
    lock_guard<mutex> lock(serviceStatusMutex_);
    serviceStatus_ = serviceStatus;
    MEDIA_DEBUG_LOG("HCameraService::SetServiceStatus success. serviceStatus: %{public}d", serviceStatus);
}

int32_t HCameraService::IsTorchSupported(bool &isTorchSupported)
{
    isTorchSupported = false;
    std::vector<std::string> cameraIds;
    std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>> cameraAbilityList;
    int32_t retCode = GetCameras(cameraIds, cameraAbilityList);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, retCode, "HCameraService::IsTorchSupported failed");
    for (auto& cameraAbility : cameraAbilityList) {
        camera_metadata_item_t item;
        int ret = OHOS::Camera::FindCameraMetadataItem(cameraAbility->get(), OHOS_ABILITY_FLASH_AVAILABLE, &item);
        bool isSupportedTorch = ret == CAM_META_SUCCESS && item.count > 0;
        if (isSupportedTorch) {
            MEDIA_DEBUG_LOG("OHOS_ABILITY_FLASH_AVAILABLE is %{public}d", item.data.u8[0]);
            if (item.data.u8[0] == 1) { // LCOV_EXCL_LINE
                isTorchSupported = true;
                break;
            }
        }
    }
    MEDIA_DEBUG_LOG("HCameraService::isTorchSupported success. isTorchSupported: %{public}d", isTorchSupported);
    return retCode;
}

int32_t HCameraService::IsCameraMuteSupported(bool &isCameraMuteSupported)
{
    CHECK_RETURN_RET_ELOG(
        !CheckSystemApp(), CAMERA_NO_PERMISSION, "HCameraService::IsCameraMuteSupported:SystemApi is called");
    std::vector<std::string> cameraIds;
    std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>> cameraAbilityList;
    int32_t retCode = GetCameras(cameraIds, cameraAbilityList);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, retCode, "HCameraService::IsCameraMuteSupported failed");
    isCameraMuteSupported = std::any_of(
        cameraIds.begin(), cameraIds.end(), [&](auto& cameraId) { return IsCameraMuteSupported(cameraId); });
    return retCode;
}

int32_t HCameraService::IsCameraMuted(bool& muteMode)
{
    CAMERA_SYNC_TRACE;
    lock_guard<mutex> lock(g_dataShareHelperMutex);
    CHECK_RETURN_RET(GetServiceStatus() != CameraServiceStatus::SERVICE_READY, CAMERA_INVALID_STATE);
    muteMode = muteModeStored_;

    MEDIA_DEBUG_LOG("HCameraService::IsCameraMuted success. isMuted: %{public}d", muteMode);
    return CAMERA_OK;
}

void HCameraService::DumpCameraSummary(vector<string> cameraIds, CameraInfoDumper& infoDumper)
{
    infoDumper.Tip("--------Dump Summary Begin-------");
    infoDumper.Title("Number of Cameras:[" + to_string(cameraIds.size()) + "]");
    infoDumper.Title(
        "Number of Active Cameras:[" + to_string(HCameraDeviceManager::GetInstance()->GetActiveCamerasCount()) + "]");
    infoDumper.Title("Current session summary:");
    HCaptureSession::DumpCameraSessionSummary(infoDumper);
}

void HCameraService::DumpCameraInfo(CameraInfoDumper& infoDumper, std::vector<std::string>& cameraIds,
    std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>>& cameraAbilityList)
{
    infoDumper.Tip("--------Dump CameraDevice Begin-------");
    int32_t capIdx = 0;
    for (auto& it : cameraIds) {
        auto metadata = cameraAbilityList[capIdx++];
        common_metadata_header_t* metadataEntry = metadata->get();
        infoDumper.Title("Camera ID:[" + it + "]:");
        infoDumper.Push();
        DumpCameraAbility(metadataEntry, infoDumper);
        DumpCameraStreamInfo(metadataEntry, infoDumper);
        DumpCameraZoom(metadataEntry, infoDumper);
        DumpCameraFlash(metadataEntry, infoDumper);
        DumpCameraCompensation(metadataEntry, infoDumper);
        DumpCameraColorSpace(metadataEntry, infoDumper);
        DumpCameraAF(metadataEntry, infoDumper);
        DumpCameraAE(metadataEntry, infoDumper);
        DumpCameraSensorInfo(metadataEntry, infoDumper);
        DumpCameraVideoStabilization(metadataEntry, infoDumper);
        DumpCameraVideoFrameRateRange(metadataEntry, infoDumper);
        DumpCameraPrelaunch(metadataEntry, infoDumper);
        DumpCameraThumbnail(metadataEntry, infoDumper);
        infoDumper.Pop();
    }
}

void HCameraService::DumpCameraAbility(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper)
{
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_CAMERA_POSITION, &item);
    if (ret == CAM_META_SUCCESS) {
        map<int, string>::const_iterator iter = g_cameraPos.find(item.data.u8[0]);
        if (iter != g_cameraPos.end()) {
            infoDumper.Title("Camera Position:[" + iter->second + "]");
        }
    }

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_CAMERA_TYPE, &item);
    if (ret == CAM_META_SUCCESS) {
        map<int, string>::const_iterator iter = g_cameraType.find(item.data.u8[0]);
        if (iter != g_cameraType.end()) {
            infoDumper.Title("Camera Type:[" + iter->second + "]");
        }
    }

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_CAMERA_CONNECTION_TYPE, &item);
    CHECK_RETURN(ret != CAM_META_SUCCESS);
    map<int, string>::const_iterator iter = g_cameraConType.find(item.data.u8[0]);
    if (iter != g_cameraConType.end()) {
        infoDumper.Title("Camera Connection Type:[" + iter->second + "]");
        }
}

void HCameraService::DumpCameraStreamInfo(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper)
{
    camera_metadata_item_t item;
    int ret;
    constexpr uint32_t unitLen = 3;
    uint32_t widthOffset = 1;
    uint32_t heightOffset = 2;
    infoDumper.Title("Camera Available stream configuration List:");
    infoDumper.Push();
    ret =
        OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS, &item);
    if (ret == CAM_META_SUCCESS) {
        infoDumper.Title("Basic Stream Info Size: " + to_string(item.count / unitLen));
        for (uint32_t index = 0; index < item.count; index += unitLen) {
            map<int, string>::const_iterator iter = g_cameraFormat.find(item.data.i32[index]);
            if (iter != g_cameraFormat.end()) {
                infoDumper.Msg("Format:[" + iter->second + "]    " +
                               "Size:[Width:" + to_string(item.data.i32[index + widthOffset]) +
                               " Height:" + to_string(item.data.i32[index + heightOffset]) + "]");
            } else {
                infoDumper.Msg("Format:[" + to_string(item.data.i32[index]) + "]    " +
                               "Size:[Width:" + to_string(item.data.i32[index + widthOffset]) +
                               " Height:" + to_string(item.data.i32[index + heightOffset]) + "]");
            }
        }
    }

    infoDumper.Pop();
}

void HCameraService::DumpCameraZoom(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper)
{
    camera_metadata_item_t item;
    int ret;
    int32_t minIndex = 0;
    int32_t maxIndex = 1;
    uint32_t zoomRangeCount = 2;
    infoDumper.Title("Zoom Related Info:");

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_ZOOM_CAP, &item);
    if (ret == CAM_META_SUCCESS) {
        infoDumper.Msg("OHOS_ABILITY_ZOOM_CAP data size:" + to_string(item.count));
        if (item.count == zoomRangeCount) {
            infoDumper.Msg("Available Zoom Capability:[" + to_string(item.data.i32[minIndex]) + "  " +
                           to_string(item.data.i32[maxIndex]) + "]");
        }
    }

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_SCENE_ZOOM_CAP, &item);
    if (ret == CAM_META_SUCCESS) {
        infoDumper.Msg("OHOS_ABILITY_SCENE_ZOOM_CAP data size:" + to_string(item.count));
        string zoomAbilityString = "Available Zoom Modes:[ ";
        int reduce = 100;
        uint32_t size = 3;
        float range;
        int32_t val;
        for (uint32_t i = 0; i < item.count; i++) {
            val = item.data.i32[i];
            if (i % size != 0) {
                range = (float)val / reduce;
                zoomAbilityString.append(to_string(range) + " ");
            } else {
                zoomAbilityString.append(" mode: " + to_string(val) + " ");
            }
        }
        zoomAbilityString.append("]");
        infoDumper.Msg(zoomAbilityString);
    }

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_ZOOM_RATIO_RANGE, &item);
    CHECK_RETURN(ret != CAM_META_SUCCESS);
    infoDumper.Msg("OHOS_ABILITY_ZOOM_RATIO_RANGE data size:" + to_string(item.count));
    if (item.count == zoomRangeCount) {
        infoDumper.Msg(
            "Available Zoom Ratio Range:[" + to_string(item.data.f[minIndex]) + to_string(item.data.f[maxIndex]) + "]");
        }
}

void HCameraService::DumpCameraFlash(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper)
{
    camera_metadata_item_t item;
    int ret;
    infoDumper.Title("Flash Related Info:");
    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_FLASH_MODES, &item);
    CHECK_RETURN(ret != CAM_META_SUCCESS);
    string flashAbilityString = "Available Flash Modes:[ ";
    for (uint32_t i = 0; i < item.count; i++) {
            map<int, string>::const_iterator iter = g_cameraFlashMode.find(item.data.u8[i]);
            if (iter != g_cameraFlashMode.end()) {
                flashAbilityString.append(iter->second + " ");
            }
        }
        flashAbilityString.append("]");
        infoDumper.Msg(flashAbilityString);
}

void HCameraService::DumpCameraCompensation(common_metadata_header_t *metadataEntry, CameraInfoDumper &infoDumper)
{
    camera_metadata_item_t item;
    int ret;
    infoDumper.Title("Compensation Related Info:");
    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_AE_COMPENSATION_RANGE, &item);
    CHECK_RETURN(ret != CAM_META_SUCCESS);
    string compensationAbilityString = "Available Compensation Modes:[ ";
    for (uint32_t i = 0; i < item.count; i++) {
            int32_t val = item.data.i32[i];
            compensationAbilityString.append(to_string(val));
        }
        compensationAbilityString.append("]");
        infoDumper.Msg(compensationAbilityString);
}

void HCameraService::DumpCameraColorSpace(common_metadata_header_t *metadataEntry, CameraInfoDumper &infoDumper)
{
    camera_metadata_item_t item;
    int ret;
    infoDumper.Title("Color Space Related Info:");
    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_AVAILABLE_COLOR_SPACES, &item);
    CHECK_RETURN(ret != CAM_META_SUCCESS);
    string colorSpaceAbilityString = "Available Color Space Modes:[ ";
    for (uint32_t i = 0; i < item.count; i++) {
            int32_t val = item.data.i32[i];
            colorSpaceAbilityString.append(to_string(val));
        }
        colorSpaceAbilityString.append("]");
        infoDumper.Msg(colorSpaceAbilityString);
}

void HCameraService::DumpCameraAF(common_metadata_header_t *metadataEntry, CameraInfoDumper &infoDumper)
{
    camera_metadata_item_t item;
    int ret;
    infoDumper.Title("AF Related Info:");
    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_FOCUS_MODES, &item);
    CHECK_RETURN(ret != CAM_META_SUCCESS);
    string afAbilityString = "Available Focus Modes:[ ";
    for (uint32_t i = 0; i < item.count; i++) {
            map<int, string>::const_iterator iter = g_cameraFocusMode.find(item.data.u8[i]);
            if (iter != g_cameraFocusMode.end()) {
                afAbilityString.append(iter->second + " ");
            }
        }
        afAbilityString.append("]");
        infoDumper.Msg(afAbilityString);
}

void HCameraService::DumpCameraAE(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper)
{
    camera_metadata_item_t item;
    int ret;
    infoDumper.Title("AE Related Info:");
    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_EXPOSURE_MODES, &item);
    CHECK_RETURN(ret != CAM_META_SUCCESS);
    string aeAbilityString = "Available Exposure Modes:[ ";
    for (uint32_t i = 0; i < item.count; i++) {
            map<int, string>::const_iterator iter = g_cameraExposureMode.find(item.data.u8[i]);
            if (iter != g_cameraExposureMode.end()) {
                aeAbilityString.append(iter->second + " ");
            }
        }
        aeAbilityString.append("]");
        infoDumper.Msg(aeAbilityString);
}

void HCameraService::DumpCameraSensorInfo(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper)
{
    camera_metadata_item_t item;
    int ret;
    int32_t leftIndex = 0;
    int32_t topIndex = 1;
    int32_t rightIndex = 2;
    int32_t bottomIndex = 3;
    infoDumper.Title("Sensor Related Info:");
    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_SENSOR_INFO_ACTIVE_ARRAY_SIZE, &item);
    CHECK_RETURN(ret != CAM_META_SUCCESS);
    infoDumper.Msg("Array:[" + to_string(item.data.i32[leftIndex]) + " " + to_string(item.data.i32[topIndex]) + " " +
        to_string(item.data.i32[rightIndex]) + " " + to_string(item.data.i32[bottomIndex]) + "]:\n");
}

void HCameraService::DumpCameraVideoStabilization(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper)
{
    camera_metadata_item_t item;
    int ret;
    infoDumper.Title("Video Stabilization Related Info:");
    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_VIDEO_STABILIZATION_MODES, &item);
    CHECK_RETURN(ret != CAM_META_SUCCESS);
    std::string infoString = "Available Video Stabilization Modes:[ ";
    for (uint32_t i = 0; i < item.count; i++) {
            map<int, string>::const_iterator iter = g_cameraVideoStabilizationMode.find(item.data.u8[i]);
            if (iter != g_cameraVideoStabilizationMode.end()) {
                infoString.append(iter->second + " ");
            }
        }
        infoString.append("]:");
        infoDumper.Msg(infoString);
}

void HCameraService::DumpCameraVideoFrameRateRange(
    common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper)
{
    camera_metadata_item_t item;
    const int32_t FRAME_RATE_RANGE_STEP = 2;
    int ret;
    infoDumper.Title("Video FrameRateRange Related Info:");
    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_FPS_RANGES, &item);
    bool isFindMetadata = ret == CAM_META_SUCCESS && item.count > 0;
    CHECK_RETURN(!isFindMetadata);
    infoDumper.Msg("Available FrameRateRange:");
    for (uint32_t i = 0; i < (item.count - 1); i += FRAME_RATE_RANGE_STEP) {
            infoDumper.Msg("[ " + to_string(item.data.i32[i]) + ", " + to_string(item.data.i32[i + 1]) + " ]");
        }
}

void HCameraService::DumpCameraPrelaunch(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper)
{
    camera_metadata_item_t item;
    int ret;
    infoDumper.Title("Camera Prelaunch Related Info:");
    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_PRELAUNCH_AVAILABLE, &item);
    CHECK_RETURN(ret != CAM_META_SUCCESS);
    map<int, string>::const_iterator iter = g_cameraPrelaunchAvailable.find(item.data.u8[0]);
    bool isSupport = false;
    if (iter != g_cameraPrelaunchAvailable.end()) {
            isSupport = true;
        }
        std::string infoString = "Available Prelaunch Info:[";
        infoString.append(isSupport ? "True" : "False");
        infoString.append("]");
        infoDumper.Msg(infoString);
}

void HCameraService::DumpCameraThumbnail(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper)
{
    camera_metadata_item_t item;
    int ret;
    infoDumper.Title("Camera Thumbnail Related Info:");
    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_STREAM_QUICK_THUMBNAIL_AVAILABLE, &item);
    CHECK_RETURN(ret != CAM_META_SUCCESS);
    map<int, string>::const_iterator iter = g_cameraQuickThumbnailAvailable.find(item.data.u8[0]);
    bool isSupport = false;
    if (iter != g_cameraQuickThumbnailAvailable.end()) {
            isSupport = true;
        }
        std::string infoString = "Available Thumbnail Info:[";
        infoString.append(isSupport ? "True" : "False");
        infoString.append("]");
        infoDumper.Msg(infoString);
}

void HCameraService::DumpCameraConcurrency(
    CameraInfoDumper &infoDumper, std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>> &cameraAbilityList)
{
    infoDumper.Title("Concurrency Camera Info");
    HCameraDeviceManager *deviceManager = HCameraDeviceManager::GetInstance();
    std::vector<sptr<HCameraDeviceHolder>> cameraHolder = deviceManager->GetActiveCameraHolders();
    std::vector<std::string> cameraIds;
    std::vector<sptr<HCameraDevice>> cameraDevices;
    for (auto entry : cameraHolder) {
        cameraIds.push_back(entry->GetDevice()->GetCameraId());
        cameraDevices.push_back(entry->GetDevice());
    }
    size_t activeCamerasCount = deviceManager->GetActiveCamerasCount();
    infoDumper.Title("Number of Active Cameras:[" + to_string(activeCamerasCount) + "]");
    DumpCameraInfo(infoDumper, cameraIds, cameraAbilityList);
    HCaptureSession::DumpSessions(infoDumper);
}

int32_t HCameraService::Dump(int fd, const vector<u16string> &args)
{
    unordered_set<u16string> argSets;
    for (decltype(args.size()) index = 0; index < args.size(); ++index) {
        argSets.insert(args[index]);
    }
    std::string dumpString;
    std::vector<std::string> cameraIds;
    std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>> cameraAbilityList;
    int ret = GetCameras(cameraIds, cameraAbilityList);
    CHECK_RETURN_RET((ret != CAMERA_OK) || cameraIds.empty() || cameraAbilityList.empty(), OHOS::UNKNOWN_ERROR);
    CameraInfoDumper infoDumper(fd);
    bool result = args.empty() || argSets.count(u16string(u"summary"));
    if (result) {
        DumpCameraSummary(cameraIds, infoDumper);
    }
    result = args.empty() || argSets.count(u16string(u"ability"));
    if (result) {
        DumpCameraInfo(infoDumper, cameraIds, cameraAbilityList);
    }
    result = args.empty() || argSets.count(u16string(u"preconfig"));
    if (result) {
        infoDumper.Tip("--------Dump PreconfigInfo Begin-------");
        DumpPreconfigInfo(infoDumper, cameraHostManager_);
    }
    result = args.empty() || argSets.count(u16string(u"clientwiseinfo"));
    if (result) {
        infoDumper.Tip("--------Dump Clientwise Info Begin-------");
        HCaptureSession::DumpSessions(infoDumper);
    }
    CHECK_EXECUTE(argSets.count(std::u16string(u"debugOn")), SetCameraDebugValue(true));
    if (argSets.count(std::u16string(u"concurrency"))) {
        DumpCameraConcurrency(infoDumper, cameraAbilityList);
    }
    infoDumper.Print();
    return OHOS::NO_ERROR;
}

int32_t HCameraService::UpdateBeautySetting(std::shared_ptr<OHOS::Camera::CameraMetadata> changedMetadata,
    EffectParam effectParam)
{
    CHECK_RETURN_RET(nullptr == changedMetadata, CAMERA_OK);
    std::vector<std::pair<camera_device_metadata_tag, int>> paramArray{
        {OHOS_CONTROL_BEAUTY_SKIN_SMOOTH_VALUE, effectParam.skinSmoothLevel},
        {OHOS_CONTROL_BEAUTY_FACE_SLENDER_VALUE, effectParam.faceSlender},
        {OHOS_CONTROL_BEAUTY_SKIN_TONE_VALUE, effectParam.skinTone},
        {OHOS_CONTROL_BEAUTY_SKIN_TONEBRIGHT_VALUE, effectParam.skinToneBright},
        {OHOS_CONTROL_BEAUTY_EYE_BIGEYES_VALUE, effectParam.eyeBigEyes},
        {OHOS_CONTROL_BEAUTY_HAIR_HAIRLINE_VALUE, effectParam.hairHairline},
        {OHOS_CONTROL_BEAUTY_FACE_MAKEUP_VALUE, effectParam.faceMakeUp},
        {OHOS_CONTROL_BEAUTY_HEAD_SHRINK_VALUE, effectParam.headShrink},
        {OHOS_CONTROL_BEAUTY_NOSE_SLENDER_VALUE, effectParam.noseSlender}
    };
    auto UpdateEachBeautySetting = [changedMetadata](
                                       std::pair<camera_device_metadata_tag, int32_t>& paramPair) -> int32_t {
        CHECK_RETURN_RET(paramPair.second <= 0, CAMERA_OK);
        int32_t count = 1;
        MEDIA_DEBUG_LOG("UpdateBeautySetting %{public}d", paramPair.second);
        uint8_t beauty = OHOS_CAMERA_BEAUTY_TYPE_SKIN_SMOOTH;
        auto metadata = changedMetadata;
        AddOrUpdateMetadata(metadata, OHOS_CONTROL_BEAUTY_TYPE, &beauty, count);
        bool status = AddOrUpdateMetadata(metadata, paramPair.first, &paramPair.second, count);
        CHECK_PRINT_ILOG(status, "UpdateBeautySetting status: %{public}d", status);
        return CAMERA_OK;
    };
    for (auto paramPair: paramArray) {
        UpdateEachBeautySetting(paramPair);
    }
    return CAMERA_OK;
}

void HCameraService::ClearCameraListenerByPid(pid_t pid)
{
    sptr<IStandardCameraListener> cameraListenerTmp = nullptr;
    if (cameraListenerMap_.Find(pid, cameraListenerTmp)) {
        CHECK_EXECUTE(cameraListenerTmp != nullptr && cameraListenerTmp->AsObject() != nullptr,
            cameraListenerTmp->RemoveCameraDeathRecipient());
        cameraListenerMap_.Erase(pid);
        CameraReportDfxUtils::GetInstance()->UpdateAliveClient(pid, ClientState::DIED);
    }
}

int HCameraService::DestroyStubForPid(pid_t pid)
{
    UnSetAllCallback(pid);
    ClearCameraListenerByPid(pid);
    HCaptureSession::DestroyStubObjectForPid(pid);
    CloseCameraForDestory(pid);

    return CAMERA_OK;
}

int HCameraService::DestroyStubObj()
{
    pid_t pid = IPCSkeleton::GetCallingPid();
    MEDIA_DEBUG_LOG("DestroyStubObj client pid:%{public}d", pid);
    (void)DestroyStubForPid(pid);

    return CAMERA_OK;
}

void HCameraService::ClientDied(pid_t pid)
{
    DisableJeMalloc();
    MEDIA_ERR_LOG("client pid is dead, pid:%{public}d", pid);
    (void)DestroyStubForPid(pid);
}

int HCameraService::SetListenerObject(const sptr<IRemoteObject>& object)
{
    pid_t pid = IPCSkeleton::GetCallingPid();
    ClearCameraListenerByPid(pid); // Ensure cleanup before starting the listener if this is the second call
    CHECK_RETURN_RET_ELOG(object == nullptr, CAMERA_ALLOC_ERROR, "set listener object is nullptr");

    sptr<IStandardCameraListener> cameraListener = iface_cast<IStandardCameraListener>(object);
    CHECK_RETURN_RET_ELOG(cameraListener == nullptr, CAMERA_ALLOC_ERROR, "failed to cast IStandardCameraListener");

    sptr<CameraDeathRecipient> deathRecipient = new (std::nothrow) CameraDeathRecipient(pid);
    CHECK_RETURN_RET_ELOG(deathRecipient == nullptr, CAMERA_ALLOC_ERROR, "failed to new CameraDeathRecipient");

    auto thisPtr = wptr<HCameraService>(this);
    deathRecipient->SetNotifyCb([thisPtr](pid_t pid) {
        auto hCameraServicePtr = thisPtr.promote();
        CHECK_EXECUTE(hCameraServicePtr != nullptr, hCameraServicePtr->ClientDied(pid));
    });
    cameraListener->AddCameraDeathRecipient(deathRecipient);
    cameraListenerMap_.EnsureInsert(pid, cameraListener);
    CameraReportDfxUtils::GetInstance()->UpdateAliveClient(pid, ClientState::ALIVE);
    return CAMERA_OK;
}

int32_t HCameraService::SaveCurrentParamForRestore(sptr<HCameraRestoreParam> cameraRestoreParam,
    RestoreParamTypeOhos restoreParamType, int activeTime, EffectParam effectParam,
    sptr<HCaptureSession> captureSession)
{
    MEDIA_INFO_LOG("HCameraService::SaveCurrentParamForRestore enter");
    int32_t rc = CAMERA_OK;
    cameraRestoreParam->SetRestoreParamType(restoreParamType);
    cameraRestoreParam->SetStartActiveTime(activeTime);
    int foldStatus = static_cast<int>(OHOS::Rosen::DisplayManagerLite::GetInstance().GetFoldStatus());
    cameraRestoreParam->SetFoldStatus(foldStatus);
    if (captureSession == nullptr || restoreParamType == RestoreParamTypeOhos::NO_NEED_RESTORE_PARAM_OHOS) {
        cameraHostManager_->SaveRestoreParam(cameraRestoreParam);
        return rc;
    }
    sptr<HCameraDeviceManager> deviceManager = HCameraDeviceManager::GetInstance();
    std::vector<pid_t> pidOfActiveClients = deviceManager->GetActiveClient();
    CHECK_RETURN_RET_ELOG(pidOfActiveClients.size() == 0, CAMERA_OPERATION_NOT_ALLOWED,
        "HCaptureSession::SaveCurrentParamForRestore() Failed to save param cause no device is opening");
    CHECK_RETURN_RET_ELOG(pidOfActiveClients.size() > 1, CAMERA_OPERATION_NOT_ALLOWED,
        "HCaptureSession::SaveCurrentParamForRestore() not supported for Multi-Device is opening");
    std::vector<sptr<HCameraDevice>> activeDevices = deviceManager->GetCamerasByPid(pidOfActiveClients[0]);
    CHECK_RETURN_RET(activeDevices.empty(), CAMERA_OK);
    std::vector<StreamInfo_V1_5> allStreamInfos;
    if (activeDevices.size() == 1) { // LCOV_EXCL_LINE
        std::shared_ptr<OHOS::Camera::CameraMetadata> defaultSettings
            = CreateDefaultSettingForRestore(activeDevices[0]);
        UpdateBeautySetting(defaultSettings, effectParam);
        cameraRestoreParam->SetSetting(defaultSettings);
    }
    rc = captureSession->GetCurrentStreamInfos(allStreamInfos);
    CHECK_RETURN_RET_ELOG(rc != CAMERA_OK, rc, "SaveCurrentParamForRestore get streamInfo err:%{public}d", rc);
    int count = 0;
    std::vector<StreamInfo_V1_1> allStreamInfos_v1_1;
    for (auto& info : allStreamInfos) {
        MEDIA_INFO_LOG("HCameraService::SaveCurrentParamForRestore: streamId is:%{public}d", info.v1_0.streamId_);
        count += (info.v1_0.streamId_ == 0) ? 1: 0;
        StreamInfo_V1_1 streamInfo_V1_1 = {info.v1_0, info.extendedStreamInfos};
        allStreamInfos_v1_1.emplace_back(streamInfo_V1_1);
    }
    CaptureSessionState currentState;
    captureSession->GetSessionState(currentState);
    bool isCommitConfig = (currentState == CaptureSessionState::SESSION_CONFIG_COMMITTED)
            || (currentState == CaptureSessionState::SESSION_STARTED);
    CHECK_RETURN_RET_ELOG((!isCommitConfig || count > 1), CAMERA_INVALID_ARG,
        "HCameraService::SaveCurrentParamForRestore stream is not commit or streamId is all 0");
    cameraRestoreParam->SetStreamInfo(allStreamInfos_v1_1);
    cameraRestoreParam->SetCameraOpMode(captureSession->GetopMode());
    cameraHostManager_->SaveRestoreParam(cameraRestoreParam);
    return rc;
}

std::shared_ptr<OHOS::Camera::CameraMetadata> HCameraService::CreateDefaultSettingForRestore(
    sptr<HCameraDevice> activeDevice)
{
    constexpr int32_t DEFAULT_ITEMS = 1;
    constexpr int32_t DEFAULT_DATA_LENGTH = 1;
    auto defaultSettings = std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    float zoomRatio = 1.0f;
    int32_t count = 1;
    int32_t ret = 0;
    camera_metadata_item_t item;
    defaultSettings->addEntry(OHOS_CONTROL_ZOOM_RATIO, &zoomRatio, count);
    defaultSettings->addEntry(OHOS_CONTROL_TIME_LAPSE_RECORD_STATE, &ret, count);
    std::shared_ptr<OHOS::Camera::CameraMetadata> currentSetting = activeDevice->CloneCachedSettings();
    CHECK_RETURN_RET_ELOG(currentSetting == nullptr, defaultSettings,
        "HCameraService::CreateDefaultSettingForRestore:currentSetting is null");
    ret = OHOS::Camera::FindCameraMetadataItem(currentSetting->get(), OHOS_CONTROL_FPS_RANGES, &item);
    if (ret == CAM_META_SUCCESS) {
        uint32_t fpscount = item.count;
        std::vector<int32_t> fpsRange;
        for (uint32_t i = 0; i < fpscount; i++) {
            fpsRange.push_back(*(item.data.i32 + i));
        }
        defaultSettings->addEntry(OHOS_CONTROL_FPS_RANGES, fpsRange.data(), fpscount);
    }

    ret = OHOS::Camera::FindCameraMetadataItem(currentSetting->get(), OHOS_CAMERA_USER_ID, &item);
    if (ret == CAM_META_SUCCESS && item.count > 0) {
        int32_t userId = item.data.i32[0];
        defaultSettings->addEntry(OHOS_CAMERA_USER_ID, &userId, count);
    }

    ret = OHOS::Camera::FindCameraMetadataItem(currentSetting->get(), OHOS_CONTROL_COLOR_STYLE_SETTING, &item);
    if (ret == CAM_META_SUCCESS && item.count > 0) {
        std::vector<float> colorStyleSetting;
        for (uint32_t i = 0; i < item.count; ++i) {
            colorStyleSetting.emplace_back(*(item.data.f + i));
        }
        defaultSettings->addEntry(OHOS_CONTROL_COLOR_STYLE_SETTING, colorStyleSetting.data(), item.count);
    }

    ret = OHOS::Camera::FindCameraMetadataItem(currentSetting->get(), OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &item);
    if (ret == CAM_META_SUCCESS && item.count > 0) {
        int32_t exporseValue = item.data.i32[0];
        defaultSettings->addEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &exporseValue, count);
    }

    uint8_t enableValue = true;
    defaultSettings->addEntry(OHOS_CONTROL_VIDEO_DEBUG_SWITCH, &enableValue, 1);

    for (uint32_t metadataTag : restoreMetadataTag) { // item.type is uint8
        ret = OHOS::Camera::FindCameraMetadataItem(currentSetting->get(), metadataTag, &item);
        if (ret == 0 && item.count > 0) {
            defaultSettings->addEntry(item.item, item.data.u8, item.count);
        }
    }
    return defaultSettings;
}

std::string g_toString(std::set<int32_t>& pidList)
{
    std::ostringstream oss;
    oss << '[';
    for (auto it = pidList.begin(); it != pidList.end(); ++it) {
        CHECK_EXECUTE(it != pidList.begin(), oss << ',');
        oss << *it;
    }
    oss << ']';
    return oss.str();
}

int32_t HCameraService::ProxyForFreeze(const std::set<int32_t>& pidList, bool isProxy)
{
    MEDIA_ERR_LOG("HCameraService::ProxyForFreeze is Deprecated");
    return CAMERA_OPERATION_NOT_ALLOWED;
}

int32_t HCameraService::ResetAllFreezeStatus()
{
    MEDIA_ERR_LOG("HCameraService::ResetAllFreezeStatus is Deprecated");
    return CAMERA_OPERATION_NOT_ALLOWED;
}

int32_t HCameraService::GetDmDeviceInfo(std::vector<dmDeviceInfo> &deviceInfos)
{
#ifdef DEVICE_MANAGER
    lock_guard<mutex> lock(g_dmDeviceInfoMutex);
    std::vector <DistributedHardware::DmDeviceInfo> deviceInfoList;
    auto &deviceManager = DistributedHardware::DeviceManager::GetInstance();
    std::shared_ptr<DistributedHardware::DmInitCallback> initCallback = std::make_shared<DeviceInitCallBack>();
    std::string pkgName = std::to_string(IPCSkeleton::GetCallingTokenID());
    const string extraInfo = "";
    deviceManager.InitDeviceManager(pkgName, initCallback);
    deviceManager.RegisterDevStateCallback(pkgName, extraInfo, NULL);
    deviceManager.GetTrustedDeviceList(pkgName, extraInfo, deviceInfoList);
    deviceManager.UnInitDeviceManager(pkgName);
    int32_t size = static_cast<int32_t>(deviceInfoList.size());
    MEDIA_INFO_LOG("HCameraService::GetDmDeviceInfo size=%{public}d", size);
    CHECK_RETURN_RET(size == 0, CAMERA_OK);
    for (int32_t i = 0; i < size; i++) {
        dmDeviceInfo deviceInfo;
        deviceInfo.deviceName = deviceInfoList[i].deviceName;
        deviceInfo.deviceTypeId = deviceInfoList[i].deviceTypeId;
        deviceInfo.networkId = deviceInfoList[i].networkId;
        MEDIA_INFO_LOG("HCameraService::GetDmDeviceInfo deviceName=%{public}s, networkId=%{public}s",
            deviceInfo.deviceName.c_str(), deviceInfo.networkId.c_str());
        deviceInfos.emplace_back(deviceInfo);
    }
#endif
    return CAMERA_OK;
}

int32_t HCameraService::GetCameraOutputStatus(int32_t pid, int32_t &status)
{
    sptr<HCaptureSession> captureSession = nullptr;
    auto &sessionManager = HCameraSessionManager::GetInstance();
    captureSession = sessionManager.GetGroupDefaultSession(pid);
    if (captureSession) {
        captureSession->GetOutputStatus(status);
    } else {
        status = 0;
    }
    return CAMERA_OK;
}

int32_t HCameraService::RequireMemorySize(int32_t requiredMemSizeKB)
{
    #ifdef MEMMGR_OVERRID
    CameraXCollie cameraXCollie = CameraXCollie("HCameraService::RequireMemorySize");
    CHECK_RETURN_RET_ELOG(!CheckSystemApp(), CAMERA_NO_PERMISSION, "HCameraService::CheckSystemApp fail");
    int32_t pid = getpid();
    const std::string reason = "HW_CAMERA_TO_PHOTO";
    std::string clientName = SYSTEM_CAMERA;
    int32_t ret = Memory::MemMgrClient::GetInstance().RequireBigMem(pid, reason, requiredMemSizeKB, clientName);
    MEDIA_INFO_LOG("HCameraDevice::RequireMemory reason:%{public}s, clientName:%{public}s, ret:%{public}d",
        reason.c_str(), clientName.c_str(), ret);
    CHECK_RETURN_RET(ret == 0, CAMERA_OK);
#endif
    return CAMERA_UNKNOWN_ERROR;
}

#ifdef MEMMGR_OVERRID
void HCameraService::PrelaunchRequireMemory(int32_t flag)
{
    CAMERA_SYNC_TRACE;
    int32_t pid = getpid();
    int32_t requiredMemSizeKB = 0;

    if (flag == TOUCH_DOWN) {
        // touch down
        MEDIA_INFO_LOG("PrelaunchRequireMemory touch down");
        Memory::MemMgrClient::GetInstance().RequireBigMem(
            pid, Memory::CAMERA_TOUCH_DOWN, requiredMemSizeKB, SYSTEM_CAMERA);
    } else if (flag == TOUCH_UP || flag == OLD_LAUNCH) {
        // touch up
        MEDIA_INFO_LOG("PrelaunchRequireMemory touch up");
        Memory::MemMgrClient::GetInstance().RequireBigMem(
            pid, Memory::CAMERA_PRELAUNCH, requiredMemSizeKB, SYSTEM_CAMERA);
    } else if (flag == TOUCH_CANCEL) {
        // touch cancel
        MEDIA_INFO_LOG("PrelaunchRequireMemory touch cancel");
        Memory::MemMgrClient::GetInstance().RequireBigMem(
            pid, Memory::CAMERA_LAUNCH_CANCEL, requiredMemSizeKB, SYSTEM_CAMERA);
    }
}
#endif

int32_t HCameraService::GetIdforCameraConcurrentType(int32_t cameraPosition, std::string &cameraId)
{
    std::string cameraIdnow;
    cameraHostManager_->GetPhysicCameraId(cameraPosition, cameraIdnow);
    cameraId = cameraIdnow;
    return CAMERA_OK;
}

int32_t HCameraService::GetConcurrentCameraAbility(const std::string& cameraId,
    std::shared_ptr<OHOS::Camera::CameraMetadata>& cameraAbility)
{
    MEDIA_DEBUG_LOG("HCameraService::GetConcurrentCameraAbility cameraId: %{public}s", cameraId.c_str());
    return cameraHostManager_->GetCameraAbility(cameraId, cameraAbility);
}

int32_t HCameraService::CheckWhiteList(bool &isInWhiteList)
{
    int32_t uid = IPCSkeleton::GetCallingUid();
    MEDIA_DEBUG_LOG("CheckWhitelist uid: %{public}d", uid);
    isInWhiteList = (uid == ROOT_UID || uid == FACE_CLIENT_UID || uid == RSS_UID ||
        OHOS::Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(IPCSkeleton::GetCallingFullTokenID()));
    return CAMERA_OK;
}

int32_t HCameraService::CloseDelayed(const std::string& cameraId)
{
    CHECK_RETURN_RET_ELOG(cameraHostManager_ == nullptr, CAMERA_INVALID_ARG,
        "HCameraHostManager::EntireCloseDevice cameraHostManager_ is nullptr");
    cameraHostManager_->EntireCloseDevice(const_cast<std::string&>(cameraId));
    return CAMERA_OK;
}

int32_t HCameraService::CallbackEnter([[maybe_unused]] uint32_t code)
{
    MEDIA_DEBUG_LOG("start, code:%{public}u", code);
    DisableJeMalloc();
    return CAMERA_OK;
}

int32_t HCameraService::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    MEDIA_DEBUG_LOG("leave, code:%{public}u, result:%{public}d", code, result);
    return CAMERA_OK;
}

int32_t HCameraService::GetCameraStorageSize(int64_t& size)
{
    CHECK_RETURN_RET_ELOG(
        !CheckSystemApp(), CAMERA_NO_PERMISSION, "HCameraService::GetCameraStorageSize:SystemApi is called");
    int32_t userId = 0;
    int32_t uid = IPCSkeleton::GetCallingUid();
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, userId);
    cameraHostManager_->GetCameraStorageSize(userId, size);
    return CAMERA_OK;
}

void HCameraService::ClearFreezedPidList()
{
    std::lock_guard<std::mutex> lock(freezedPidListMutex_);
    freezedPidList_.clear();
    MEDIA_INFO_LOG("freezedPidList_ has been clear");
}

void HCameraService::InsertFrozenPidList(const std::vector<int32_t>& pidList)
{
    std::lock_guard<std::mutex> lock(freezedPidListMutex_);
    freezedPidList_.insert(pidList.begin(), pidList.end());
    MEDIA_DEBUG_LOG("after freeze freezedPidList_:%{public}s", g_toString(freezedPidList_).c_str());
}

void HCameraService::EraseActivePidList(const std::vector<int32_t>& pidList)
{
    std::lock_guard<std::mutex> lock(freezedPidListMutex_);
    for (auto pid : pidList) {
        freezedPidList_.erase(pid);
    }
    MEDIA_DEBUG_LOG("after unfreeze freezedPidList_:%{public}s", g_toString(freezedPidList_).c_str());
}

void HCameraService::ExecuteDelayCallbackTask(const std::vector<int32_t>& pidList)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("HCameraService::ExecuteDelayCallbackTask is called");
    std::lock_guard<std::mutex> lock(cameraCbMutex_);
    std::for_each(pidList.begin(), pidList.end(), [this](auto pid) -> void {
        auto pidIt = delayCbtaskMap_.find(pid);
        CHECK_RETURN(pidIt == delayCbtaskMap_.end());
        for (const auto &[cameraId, taskCallback] : pidIt->second) {
            CHECK_EXECUTE(taskCallback, taskCallback());
        }
        delayCbtaskMap_.erase(pidIt);
    });
}

int32_t HCameraService::PrelaunchScanCamera(const std::string& bundleName, const std::string& pageName,
    PrelaunchScanModeOhos preCameraMode)
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(preCameraMutex_);
    bool isValidParameter = !bundleName.empty() && (preCameraMode == PrelaunchScanModeOhos::PRE_CAMERA_NO_STREAM ||
        preCameraMode == PrelaunchScanModeOhos::PRE_CAMERA_AND_RESTORE);
    CHECK_RETURN_RET_ELOG(!isValidParameter, PRE_SCAN_MODE_UNSUPPORTED,
        "HCameraService::PrelaunchScanCamera not need");
    CHECK_RETURN_RET_ELOG(IPCSkeleton::GetCallingUid() != RSS_UID, UID_NO_PERMISSION,
        "HCameraService::PrelaunchScanCamera no permission");
    CameraXCollie cameraXCollie = CameraXCollie("HCameraService::PrelaunchScanCamera");
    MEDIA_INFO_LOG("HCameraService::PrelaunchScanCamera");
    #ifdef MEMMGR_OVERRID
    int32_t requiredMemSizeKB = 0;
    Memory::MemMgrClient::GetInstance()
        .RequireBigMem(getpid(), PRE_SCAN_REASON, requiredMemSizeKB, PRE_SCAN_NAME);
    #endif
    // notify deferredprocess stop
    DeferredProcessing::DeferredProcessingService::GetInstance().NotifyInterrupt();
    CHECK_RETURN_RET_ELOG(HCameraDeviceManager::GetInstance()->GetCameraStateOfASide().Size() != 0,
        CAMERA_DEVICE_CONFLICT, "HCameraService::PrelaunchScanCamera there is a device active in A side, abort!");
    std::string preCameraId = PRE_CAMERA_DEFAULT_ID;
    preScanCameraBundleName_ = bundleName;
    preScanCameraPageName_ = pageName;
    preScanCameraMode_ = preCameraMode;
    CAMERA_SYSEVENT_STATISTIC(CreateMsg("Scan Camera Prelaunch CameraId:%s", preCameraId.c_str()));
    CameraReportUtils::GetInstance().SetOpenCamPerfPreInfo(preCameraId.c_str(), CameraReportUtils::GetCallerInfo());
    int32_t ret = cameraHostManager_->Prelaunch(preCameraId, GetPreScanBundleNameKey());
    CHECK_PRINT_ELOG(ret != PRE_SCAN_OK, "HCameraService::PrelaunchScanCamera failed");
    return ret;
}

void HCameraService::SetPrelaunchScanCameraConfig(const std::string& bundleName)
{
    CAMERA_SYNC_TRACE;
    bool isNeedSave = !preScanCameraBundleName_.empty() && preScanCameraBundleName_ == bundleName &&
        preScanCameraMode_ == PrelaunchScanModeOhos::PRE_CAMERA_AND_RESTORE;
    CHECK_RETURN_ELOG(!isNeedSave, "HCameraService::SetPrelaunchScanCameraConfig no need save: %{public}s",
        bundleName.c_str());
     CameraXCollie cameraXCollie = CameraXCollie("HCameraService::SetPrelaunchScanCameraConfig");
      OHOS::Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    string permissionName = OHOS_PERMISSION_CAMERA;
    int32_t ret = CheckPermission(permissionName, callerToken);
     CHECK_RETURN_ELOG(ret != CAMERA_OK, "HCameraService::SetPrelaunchScanCameraConfig failed permission is: %{public}s",
        permissionName.c_str());
    string preCameraId = PRE_CAMERA_DEFAULT_ID;
    int activeTime = ACTIVE_TIME_DEFAULT;
    CameraStandard::RestoreParamTypeOhos restoreParamType{RestoreParamTypeOhos::PERSISTENT_DEFAULT_PARAM_OHOS};
    CameraStandard::EffectParam effectParam;
    vector<string> cameraIds_;
    cameraHostManager_->GetCameras(cameraIds_);
    bool isFindCameraIds = (find(cameraIds_.begin(), cameraIds_.end(), preCameraId) != cameraIds_.end()) &&
        IsPrelaunchSupported(preCameraId);
    if (isFindCameraIds) {
        MEDIA_INFO_LOG("HCameraService::SetPreluanchScanCameraConfig start");
        sptr<HCaptureSession> captureSession_ = nullptr;
        pid_t pid = IPCSkeleton::GetCallingPid();
        auto &sessionManager = HCameraSessionManager::GetInstance();
        captureSession_ = sessionManager.GetGroupDefaultSession(pid);
        sptr<HCameraRestoreParam> cameraRestoreParam = new HCameraRestoreParam(GetPreScanBundleNameKey(), preCameraId);
        SaveCurrentParamForRestore(cameraRestoreParam, static_cast<RestoreParamTypeOhos>(restoreParamType), activeTime,
            effectParam, captureSession_);
    } else {
        MEDIA_ERR_LOG("HCameraService::SetPrelaunchScanCameraConfig not find cameraId");
    }
}

std::string HCameraService::GetPreScanBundleNameKey()
{
    return (preScanCameraMode_ != PrelaunchScanModeOhos::PRE_CAMERA_AND_RESTORE) ? NO_NEED_RESTORE_NAME :
      preScanCameraBundleName_ + KEY_SEPARATOR + preScanCameraPageName_;
}

void HCameraService::clearPreScanConfig()
{
    if (!preScanCameraBundleName_.empty()) {
        MEDIA_INFO_LOG("HCameraService::clearPreScanConfig");
        preScanCameraBundleName_.clear();
        preScanCameraPageName_.clear();
        preScanCameraMode_ = PrelaunchScanModeOhos::NO_NEED_PRE_CAMERA;
    }
}

#ifdef CAMERA_LIVE_SCENE_RECOGNITION
void ResSchedToCameraEventListener::OnReceiveEvent(uint32_t eventType, uint32_t eventValue,
    std::unordered_map<std::string, std::string> extInfo)
{
    MEDIA_DEBUG_LOG("ResSchedToCameraEventListener::OnReceiveEvent eventType is %{public}d, eventValue is %{public}d",
        eventType, eventValue);
    if (eventType != OHOS::ResourceSchedule::ResType::EventType::EVENT_REPORT_HFLS_LIVE_SCENE_CHANGED) {
        MEDIA_ERR_LOG("current scene is not live scene");
        return;
    }
    if (eventValue == OHOS::ResourceSchedule::ResType::EventValue::EVENT_VALUE_HFLS_BEGIN) {
        HCameraDeviceManager::GetInstance()->SetLiveScene(true);
    } else if (eventValue == OHOS::ResourceSchedule::ResType::EventValue::EVENT_VALUE_HFLS_END) {
        HCameraDeviceManager::GetInstance()->SetLiveScene(false);
    } else {
        MEDIA_ERR_LOG("current eventValue: %{public}d is not supported", eventValue);
    }
    return;
}
#endif
} // namespace CameraStandard
} // namespace OHOS
