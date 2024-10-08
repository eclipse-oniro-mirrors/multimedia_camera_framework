/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include <string>
#include <unordered_set>
#include <vector>

#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_info_dumper.h"
#include "camera_log.h"
#include "camera_report_uitls.h"
#include "camera_util.h"
#include "datashare_helper.h"
#include "datashare_predicates.h"
#include "datashare_result_set.h"
#include "deferred_processing_service.h"
#include "display_manager.h"
#include "hcamera_device_manager.h"
#include "hcamera_preconfig.h"
#ifdef DEVICE_MANAGER
#include "device_manager_impl.h"
#endif
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "os_account_manager.h"
#include "system_ability_definition.h"
#include "tokenid_kit.h"
#include "uri.h"

namespace OHOS {
namespace CameraStandard {
REGISTER_SYSTEM_ABILITY_BY_ID(HCameraService, CAMERA_SERVICE_ID, true)
#ifdef CAMERA_USE_SENSOR
constexpr int32_t SENSOR_SUCCESS = 0;
constexpr int32_t POSTURE_INTERVAL = 1000000;
#endif
constexpr uint8_t POSITION_FOLD_INNER = 3;
constexpr uint32_t ROOT_UID = 0;
constexpr uint32_t FACE_CLIENT_UID = 1088;
constexpr uint32_t RSS_UID = 1096;
static std::mutex g_cameraServiceInstanceMutex;
static HCameraService* g_cameraServiceInstance = nullptr;
static sptr<HCameraService> g_cameraServiceHolder = nullptr;
static bool g_isFoldScreen = system::GetParameter("const.window.foldscreen.type", "") != "";

static const std::string SETTINGS_DATA_BASE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true";
static const std::string SETTINGS_DATA_EXT_URI = "datashare:///com.ohos.settingsdata.DataAbility";
static const std::string SETTINGS_DATA_FIELD_KEYWORD = "KEYWORD";
static const std::string SETTINGS_DATA_FIELD_VALUE = "VALUE";
static const std::string PREDICATES_STRING = "settings.camera.mute_persist";
mutex g_dataShareHelperMutex;
mutex g_dmDeviceInfoMutex;
thread_local uint32_t g_dumpDepth = 0;

HCameraService::HCameraService(int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate), muteModeStored_(false), isRegisterSensorSuccess(false)
{
    MEDIA_INFO_LOG("HCameraService Construct begin");
    g_cameraServiceHolder = this;
    {
        std::lock_guard<std::mutex> lock(g_cameraServiceInstanceMutex);
        g_cameraServiceInstance = this;
    }
    statusCallback_ = std::make_shared<ServiceHostStatus>(this);
    cameraHostManager_ = new (std::nothrow) HCameraHostManager(statusCallback_);
    CHECK_AND_RETURN_LOG(
        cameraHostManager_ != nullptr, "HCameraService OnStart failed to create HCameraHostManager obj");
    MEDIA_INFO_LOG("HCameraService Construct end");
    serviceStatus_ = CameraServiceStatus::SERVICE_NOT_READY;
}

HCameraService::HCameraService(sptr<HCameraHostManager> cameraHostManager)
    : cameraHostManager_(cameraHostManager), muteModeStored_(false), isRegisterSensorSuccess(false)
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
    CHECK_ERROR_PRINT_LOG(cameraHostManager_->Init() != CAMERA_OK,
        "HCameraService OnStart failed to init camera host manager.");
    // initialize deferred processing service.
    DeferredProcessing::DeferredProcessingService::GetInstance().Initialize();
    DeferredProcessing::DeferredProcessingService::GetInstance().Start();

#ifdef CAMERA_USE_SENSOR
    RegisterSensorCallback();
#endif
    AddSystemAbilityListener(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID);
    cameraDataShareHelper_ = std::make_shared<CameraDataShareHelper>();
    if (Publish(this)) {
        MEDIA_INFO_LOG("HCameraService publish OnStart sucess");
    } else {
        MEDIA_INFO_LOG("HCameraService publish OnStart failed");
    }
    MEDIA_INFO_LOG("HCameraService OnStart end");
}

void HCameraService::OnDump()
{
    MEDIA_INFO_LOG("HCameraService::OnDump called");
}

void HCameraService::OnStop()
{
    MEDIA_INFO_LOG("HCameraService::OnStop called");
    cameraHostManager_->DeInit();
    UnRegisterFoldStatusListener();
#ifdef CAMERA_USE_SENSOR
    UnRegisterSensorCallback();
#endif
    DeferredProcessing::DeferredProcessingService::GetInstance().Stop();
}

int32_t HCameraService::GetMuteModeFromDataShareHelper(bool &muteMode)
{
    lock_guard<mutex> lock(g_dataShareHelperMutex);
    CHECK_ERROR_RETURN_RET_LOG(cameraDataShareHelper_ == nullptr, CAMERA_INVALID_ARG,
        "GetMuteModeFromDataShareHelper NULL");
    std::string value = "";
    auto ret = cameraDataShareHelper_->QueryOnce(PREDICATES_STRING, value);
    MEDIA_INFO_LOG("GetMuteModeFromDataShareHelper Query ret = %{public}d, value = %{public}s", ret, value.c_str());
    CHECK_ERROR_RETURN_RET_LOG(ret != CAMERA_OK, CAMERA_INVALID_ARG, "GetMuteModeFromDataShareHelper QueryOnce fail.");
    value = (value == "0" || value == "1") ? value : "0";
    int32_t muteModeVal = std::stoi(value);
    CHECK_ERROR_RETURN_RET_LOG(muteModeVal != 0 && muteModeVal != 1, CAMERA_INVALID_ARG,
        "GetMuteModeFromDataShareHelper Query MuteMode invald, value = %{public}d", muteModeVal);
    muteMode = (muteModeVal == 1) ? true: false;
    this->muteModeStored_ = muteMode;
    return CAMERA_OK;
}

int32_t HCameraService::SetMuteModeByDataShareHelper(bool muteMode)
{
    lock_guard<mutex> lock(g_dataShareHelperMutex);
    CHECK_ERROR_RETURN_RET_LOG(cameraDataShareHelper_ == nullptr, CAMERA_ALLOC_ERROR,
        "GetMuteModeFromDataShareHelper NULL");
    std::string unMuteModeStr = "0";
    std::string muteModeStr = "1";
    std::string value = muteMode? muteModeStr : unMuteModeStr;
    auto ret = cameraDataShareHelper_->UpdateOnce(PREDICATES_STRING, value);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAMERA_OK, CAMERA_ALLOC_ERROR, "SetMuteModeByDataShareHelper UpdateOnce fail.");
    return CAMERA_OK;
}

void HCameraService::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    MEDIA_INFO_LOG("OnAddSystemAbility systemAbilityId:%{public}d", systemAbilityId);
    bool muteMode = false;
    int32_t ret = -1;
    int32_t cnt = 0;
    const int32_t retryCnt = 5;
    const int32_t retryTimeout = 1;
    switch (systemAbilityId) {
        case DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID:
            MEDIA_INFO_LOG("OnAddSystemAbility RegisterObserver start");
            while (cnt++ < retryCnt) {
                ret = GetMuteModeFromDataShareHelper(muteMode);
                MEDIA_INFO_LOG("OnAddSystemAbility GetMuteModeFromDataShareHelper, tryCount=%{public}d", cnt);
                if (ret == CAMERA_OK) {
                    break;
                }
                sleep(retryTimeout);
            }
            this->SetServiceStatus(CameraServiceStatus::SERVICE_READY);
            MuteCameraFunc(muteMode);
            muteModeStored_ = muteMode;
            MEDIA_INFO_LOG("OnAddSystemAbility GetMuteModeFromDataShareHelper Success, muteMode = %{public}d, "
                           "final retryCnt=%{public}d",
                muteMode, cnt);
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
}

int32_t HCameraService::GetCameras(
    vector<string>& cameraIds, vector<shared_ptr<OHOS::Camera::CameraMetadata>>& cameraAbilityList)
{
    CAMERA_SYNC_TRACE;
    isFoldable = isFoldableInit ? isFoldable : g_isFoldScreen;
    isFoldableInit = true;
    int32_t ret = cameraHostManager_->GetCameras(cameraIds);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAMERA_OK, ret, "HCameraService::GetCameras failed");
    shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility;
    vector<shared_ptr<CameraMetaInfo>> cameraInfos;
    for (auto id : cameraIds) {
        ret = cameraHostManager_->GetCameraAbility(id, cameraAbility);
        CHECK_ERROR_RETURN_RET_LOG(ret != CAMERA_OK || cameraAbility == nullptr, ret,
            "HCameraService::GetCameraAbility failed");
        auto cameraMetaInfo = GetCameraMetaInfo(id, cameraAbility);
        if (cameraMetaInfo == nullptr) {
            continue;
        }
        cameraInfos.emplace_back(cameraMetaInfo);
    }
    FillCameras(cameraInfos, cameraIds, cameraAbilityList);
    return ret;
}

shared_ptr<CameraMetaInfo>HCameraService::GetCameraMetaInfo(std::string &cameraId,
    shared_ptr<OHOS::Camera::CameraMetadata>cameraAbility)
{
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = cameraAbility->get();
    int32_t res = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_CAMERA_POSITION, &item);
    uint8_t cameraPosition = (res == CAM_META_SUCCESS) ? item.data.u8[0] : OHOS_CAMERA_POSITION_OTHER;
    res = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_CAMERA_FOLDSCREEN_TYPE, &item);
    uint8_t foldType = (res == CAM_META_SUCCESS) ? item.data.u8[0] : OHOS_CAMERA_FOLDSCREEN_OTHER;
    if (isFoldable && cameraPosition == OHOS_CAMERA_POSITION_FRONT && foldType == OHOS_CAMERA_FOLDSCREEN_INNER) {
        cameraPosition = POSITION_FOLD_INNER;
    }
    res = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_CAMERA_TYPE, &item);
    uint8_t cameraType = (res == CAM_META_SUCCESS) ? item.data.u8[0] : OHOS_CAMERA_TYPE_UNSPECIFIED;
    res = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_CAMERA_CONNECTION_TYPE, &item);
    uint8_t connectionType = (res == CAM_META_SUCCESS) ? item.data.u8[0] : OHOS_CAMERA_CONNECTION_TYPE_BUILTIN;
    res = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED, &item);
    bool isMirrorSupported = (res == CAM_META_SUCCESS) ? (item.count != 0) : false;
    res = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_CAMERA_FOLD_STATUS, &item);
    uint8_t foldStatus = (res == CAM_META_SUCCESS) ? item.data.u8[0] : OHOS_CAMERA_FOLD_STATUS_NONFOLDABLE;
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
        if (camera->cameraType != camera_type_enum_t::OHOS_CAMERA_TYPE_UNSPECIFIED && isSupportPhysicalCamera) {
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
        MEDIA_INFO_LOG("ChooseDeFaultCameras camera ID:%s, Camera position:%{public}d, Connection Type:%{public}d",
            camera->cameraId.c_str(), camera->position, camera->connectionType);
        if (any_of(choosedCameras.begin(), choosedCameras.end(),
            [camera](const auto& defaultCamera) {
                return (camera->connectionType != OHOS_CAMERA_CONNECTION_TYPE_USB_PLUGIN &&
                    defaultCamera->position == camera->position &&
                    defaultCamera->connectionType == camera->connectionType &&
                    defaultCamera->foldStatus == camera->foldStatus);
            })
        ) {
            MEDIA_INFO_LOG("ChooseDeFaultCameras alreadly has default camera");
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
    CHECK_ERROR_PRINT_LOG(ret != CAMERA_OK, "HCameraService::GetCameraIds failed");
    return ret;
}

int32_t HCameraService::GetCameraAbility(std::string& cameraId,
    std::shared_ptr<OHOS::Camera::CameraMetadata>& cameraAbility)
{
    CAMERA_SYNC_TRACE;
    int32_t ret = CAMERA_OK;
    MEDIA_DEBUG_LOG("HCameraService::GetCameraAbility");

    std::vector<std::string> cameraIds;
    std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>> cameraAbilityList;
    ret = GetCameras(cameraIds, cameraAbilityList);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAMERA_OK, ret, "HCameraService::GetCameraAbility failed");

    int32_t index = 0;
    for (auto id : cameraIds) {
        if (id.compare(cameraId) == 0) {
            break;
        }
        index++;
    }
    int32_t abilityIndex = 0;
    for (auto it : cameraAbilityList) {
        if (abilityIndex == index) {
            cameraAbility = it;
            break;
        }
        abilityIndex++;
    }
    return ret;
}

int32_t HCameraService::CreateCameraDevice(string cameraId, sptr<ICameraDeviceService>& device)
{
    CAMERA_SYNC_TRACE;
    OHOS::Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    MEDIA_INFO_LOG("HCameraService::CreateCameraDevice prepare execute, cameraId:%{public}s", cameraId.c_str());

    string permissionName = OHOS_PERMISSION_CAMERA;
    int32_t ret = CheckPermission(permissionName, callerToken);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAMERA_OK, ret,
        "HCameraService::CreateCameraDevice Check OHOS_PERMISSION_CAMERA fail %{public}d", ret);
    // if callerToken is invalid, will not call IsAllowedUsingPermission
    CHECK_ERROR_RETURN_RET_LOG(!IsInForeGround(callerToken), CAMERA_ALLOC_ERROR,
        "HCameraService::CreateCameraDevice is not allowed!");
    sptr<HCameraDevice> cameraDevice = new (nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    CHECK_ERROR_RETURN_RET_LOG(cameraDevice == nullptr, CAMERA_ALLOC_ERROR,
        "HCameraService::CreateCameraDevice HCameraDevice allocation failed");
    CHECK_ERROR_RETURN_RET_LOG(GetServiceStatus() != CameraServiceStatus::SERVICE_READY, CAMERA_INVALID_STATE,
        "HCameraService::CreateCameraDevice CameraService not ready!");
    {
        lock_guard<mutex> lock(g_dataShareHelperMutex);
        // when create camera device, update mute setting truely.
        if (IsCameraMuteSupported(cameraId)) {
            if (UpdateMuteSetting(cameraDevice, muteModeStored_) != CAMERA_OK) {
                MEDIA_ERR_LOG("UpdateMuteSetting Failed, cameraId: %{public}s", cameraId.c_str());
            }
        } else {
            MEDIA_ERR_LOG("HCameraService::CreateCameraDevice MuteCamera not Supported");
        }
        device = cameraDevice;
        cameraDevice->SetDeviceMuteMode(muteModeStored_);
    }
#ifdef CAMERA_USE_SENSOR
    RegisterSensorCallback();
#endif
    CAMERA_SYSEVENT_STATISTIC(CreateMsg("CameraManager_CreateCameraInput CameraId:%s", cameraId.c_str()));
    MEDIA_INFO_LOG("HCameraService::CreateCameraDevice execute success");
    return CAMERA_OK;
}

int32_t HCameraService::CreateCaptureSession(sptr<ICaptureSession>& session, int32_t opMode)
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t rc = CAMERA_OK;
    MEDIA_INFO_LOG("HCameraService::CreateCaptureSession opMode_= %{public}d", opMode);

    OHOS::Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    sptr<HCaptureSession> captureSession = HCaptureSession::NewInstance(callerToken, opMode);
    if (captureSession == nullptr) {
        rc = CAMERA_ALLOC_ERROR;
        MEDIA_ERR_LOG("HCameraService::CreateCaptureSession allocation failed");
        CameraReportUtils::ReportCameraError(
            "HCameraService::CreateCaptureSession", rc, false, CameraReportUtils::GetCallerInfo());
        return rc;
    }
    session = captureSession;
    pid_t pid = IPCSkeleton::GetCallingPid();
    captureSessionsManager_.EnsureInsert(pid, captureSession);
    return rc;
}

int32_t HCameraService::CreateDeferredPhotoProcessingSession(int32_t userId,
    sptr<DeferredProcessing::IDeferredPhotoProcessingSessionCallback>& callback,
    sptr<DeferredProcessing::IDeferredPhotoProcessingSession>& session)
{
    CAMERA_SYNC_TRACE;
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
    sptr<DeferredProcessing::IDeferredVideoProcessingSessionCallback>& callback,
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

int32_t HCameraService::CreateDeferredPreviewOutput(
    int32_t format, int32_t width, int32_t height, sptr<IStreamRepeat>& previewOutput)
{
    CAMERA_SYNC_TRACE;
    sptr<HStreamRepeat> streamDeferredPreview;
    MEDIA_INFO_LOG("HCameraService::CreateDeferredPreviewOutput prepare execute");
    CHECK_ERROR_RETURN_RET_LOG((width == 0) || (height == 0), CAMERA_INVALID_ARG,
        "HCameraService::CreateDeferredPreviewOutput producer is null!");
    streamDeferredPreview = new (nothrow) HStreamRepeat(nullptr, format, width, height, RepeatStreamType::PREVIEW);
    CHECK_ERROR_RETURN_RET_LOG(streamDeferredPreview == nullptr, CAMERA_ALLOC_ERROR,
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
    streamRepeatPreview = new (nothrow) HStreamRepeat(producer, format, width, height, RepeatStreamType::PREVIEW);
    if (streamRepeatPreview == nullptr) {
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
    if (streamDepthData == nullptr) {
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
    std::vector<int32_t> metadataTypes, sptr<IStreamMetadata>& metadataOutput)
{
    CAMERA_SYNC_TRACE;
    sptr<HStreamMetadata> streamMetadata;
    MEDIA_INFO_LOG("HCameraService::CreateMetadataOutput prepare execute");

    CHECK_ERROR_RETURN_RET_LOG(producer == nullptr, CAMERA_INVALID_ARG,
        "HCameraService::CreateMetadataOutput producer is null");
    streamMetadata = new (nothrow) HStreamMetadata(producer, format, metadataTypes);
    CHECK_ERROR_RETURN_RET_LOG(streamMetadata == nullptr, CAMERA_ALLOC_ERROR,
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
    if (streamRepeatVideo == nullptr) {
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

bool HCameraService::ShouldSkipStatusUpdates(pid_t pid)
{
    std::lock_guard<std::mutex> lock(freezedPidListMutex_);
    CHECK_AND_RETURN_RET(freezedPidList_.count(pid) != 0, false);
    MEDIA_INFO_LOG("ShouldSkipStatusUpdates pid = %{public}d", pid);
    return true;
}

void HCameraService::OnCameraStatus(const string& cameraId, CameraStatus status, CallbackInvoker invoker)
{
    lock_guard<mutex> lock(cameraCbMutex_);
    std::string bundleName = "";
    if (invoker == CallbackInvoker::APPLICATION) {
        bundleName = GetClientBundle(IPCSkeleton::GetCallingUid());
    }
    MEDIA_INFO_LOG("HCameraService::OnCameraStatus callbacks.size = %{public}zu, cameraId = %{public}s, "
        "status = %{public}d, pid = %{public}d, bundleName = %{public}s", cameraServiceCallbacks_.size(),
        cameraId.c_str(), status, IPCSkeleton::GetCallingPid(), bundleName.c_str());
    for (auto it : cameraServiceCallbacks_) {
        if (it.second == nullptr) {
            MEDIA_ERR_LOG("HCameraService::OnCameraStatus pid:%{public}d cameraServiceCallback is null", it.first);
            continue;
        }
        uint32_t pid = it.first;
        if (ShouldSkipStatusUpdates(pid)) {
            continue;
        }
        it.second->OnCameraStatusChanged(cameraId, status, bundleName);
        cameraStatusCallbacks_[cameraId] = CameraStatusCallbacksInfo{status, bundleName};
        CAMERA_SYSEVENT_BEHAVIOR(CreateMsg("OnCameraStatusChanged! for cameraId:%s, current Camera Status:%d",
            cameraId.c_str(), status));
    }
}

void HCameraService::OnFlashlightStatus(const string& cameraId, FlashStatus status)
{
    lock_guard<mutex> lock(cameraCbMutex_);
    MEDIA_INFO_LOG("HCameraService::OnFlashlightStatus callbacks.size = %{public}zu, cameraId = %{public}s, "
        "status = %{public}d, pid = %{public}d", cameraServiceCallbacks_.size(), cameraId.c_str(), status,
        IPCSkeleton::GetCallingPid());
    for (auto it : cameraServiceCallbacks_) {
        if (it.second == nullptr) {
            MEDIA_ERR_LOG("HCameraService::OnCameraStatus pid:%{public}d cameraServiceCallback is null", it.first);
            continue;
        }
        uint32_t pid = it.first;
        if (ShouldSkipStatusUpdates(pid)) {
            continue;
        }
        it.second->OnFlashlightStatusChanged(cameraId, status);
    }
}

void HCameraService::OnMute(bool muteMode)
{
    lock_guard<mutex> lock(muteCbMutex_);
    if (!cameraMuteServiceCallbacks_.empty()) {
        for (auto it : cameraMuteServiceCallbacks_) {
            if (it.second == nullptr) {
                MEDIA_ERR_LOG("HCameraService::OnMute pid:%{public}d cameraMuteServiceCallback is null", it.first);
                continue;
            }
            uint32_t pid = it.first;
            if (ShouldSkipStatusUpdates(pid)) {
                continue;
            }
            it.second->OnCameraMute(muteMode);
            CAMERA_SYSEVENT_BEHAVIOR(CreateMsg("OnCameraMute! current Camera muteMode:%d", muteMode));
        }
    }
    if (peerCallback_ != nullptr) {
        MEDIA_INFO_LOG("HCameraService::NotifyMuteCamera peerCallback current camera muteMode:%{public}d", muteMode);
        peerCallback_->NotifyMuteCamera(muteMode);
    }
}

void HCameraService::OnTorchStatus(TorchStatus status)
{
    lock_guard<recursive_mutex> lock(torchCbMutex_);
    torchStatus_ = status;
    MEDIA_INFO_LOG("HCameraService::OnTorchtStatus callbacks.size = %{public}zu, status = %{public}d, pid = %{public}d",
        torchServiceCallbacks_.size(), status, IPCSkeleton::GetCallingPid());
    for (auto it : torchServiceCallbacks_) {
        if (it.second == nullptr) {
            MEDIA_ERR_LOG("HCameraService::OnTorchtStatus pid:%{public}d torchServiceCallback is null", it.first);
            continue;
        }
        uint32_t pid = it.first;
        if (ShouldSkipStatusUpdates(pid)) {
            continue;
        }
        it.second->OnTorchStatusChange(status);
    }
}

void HCameraService::OnFoldStatusChanged(OHOS::Rosen::FoldStatus foldStatus)
{
    MEDIA_INFO_LOG("OnFoldStatusChanged preFoldStatus = %{public}d, foldStatus = %{public}d, pid = %{public}d",
        preFoldStatus_, foldStatus, IPCSkeleton::GetCallingPid());
    auto curFoldStatus = (FoldStatus)foldStatus;
    if ((curFoldStatus == FoldStatus::HALF_FOLD && preFoldStatus_ == FoldStatus::EXPAND) ||
        (curFoldStatus == FoldStatus::EXPAND && preFoldStatus_ == FoldStatus::HALF_FOLD)) {
        preFoldStatus_ = curFoldStatus;
        return;
    }
    preFoldStatus_ = curFoldStatus;
    if (curFoldStatus == FoldStatus::HALF_FOLD) {
        curFoldStatus = FoldStatus::EXPAND;
    }
    lock_guard<recursive_mutex> lock(foldCbMutex_);
    CHECK_ERROR_RETURN_LOG(foldServiceCallbacks_.empty(), "OnFoldStatusChanged foldServiceCallbacks is empty");
    MEDIA_INFO_LOG("OnFoldStatusChanged foldStatusCallback size = %{public}zu", foldServiceCallbacks_.size());
    for (auto it : foldServiceCallbacks_) {
        if (it.second == nullptr) {
            MEDIA_ERR_LOG("OnFoldStatusChanged pid:%{public}d foldStatusCallbacks is null", it.first);
            continue;
        }
        uint32_t pid = it.first;
        if (ShouldSkipStatusUpdates(pid)) {
            continue;
        }
        it.second->OnFoldStatusChanged(curFoldStatus);
    }
}

int32_t HCameraService::CloseCameraForDestory(pid_t pid)
{
    MEDIA_INFO_LOG("HCameraService::CloseCameraForDestory enter");
    sptr<HCameraDeviceManager> deviceManager = HCameraDeviceManager::GetInstance();
    sptr<HCameraDevice> deviceNeedClose = deviceManager->GetCameraByPid(pid);
    if (deviceNeedClose != nullptr) {
        deviceNeedClose->Close();
    }
    return CAMERA_OK;
}

void HCameraService::ExecutePidSetCallback(sptr<ICameraServiceCallback>& callback, std::vector<std::string> &cameraIds)
{
    for (const auto& cameraId : cameraIds) {
        auto it = cameraStatusCallbacks_.find(cameraId);
        if (it != cameraStatusCallbacks_.end()) {
            MEDIA_INFO_LOG("ExecutePidSetCallback cameraId = %{public}s, status = %{public}d, bundleName = %{public}s",
                cameraId.c_str(), it->second.status, it->second.bundleName.c_str());
            callback->OnCameraStatusChanged(cameraId, it->second.status, it->second.bundleName);
        } else {
            MEDIA_INFO_LOG("ExecutePidSetCallback cameraId = %{public}s, status = 2", cameraId.c_str());
            callback->OnCameraStatusChanged(cameraId, CameraStatus::CAMERA_STATUS_AVAILABLE);
        }
    }
}

int32_t HCameraService::SetCameraCallback(sptr<ICameraServiceCallback>& callback)
{
    std::vector<std::string> cameraIds;
    GetCameraIds(cameraIds);
    lock_guard<mutex> lock(cameraCbMutex_);
    pid_t pid = IPCSkeleton::GetCallingPid();
    MEDIA_INFO_LOG("HCameraService::SetCameraCallback pid = %{public}d", pid);
    CHECK_ERROR_RETURN_RET_LOG(callback == nullptr, CAMERA_INVALID_ARG,
        "HCameraService::SetCameraCallback callback is null");
    auto callbackItem = cameraServiceCallbacks_.find(pid);
    if (callbackItem != cameraServiceCallbacks_.end()) {
        callbackItem->second = nullptr;
        (void)cameraServiceCallbacks_.erase(callbackItem);
    }
    cameraServiceCallbacks_.insert(make_pair(pid, callback));
    ExecutePidSetCallback(callback, cameraIds);
    return CAMERA_OK;
}

int32_t HCameraService::SetMuteCallback(sptr<ICameraMuteServiceCallback>& callback)
{
    lock_guard<mutex> lock(muteCbMutex_);
    pid_t pid = IPCSkeleton::GetCallingPid();
    MEDIA_INFO_LOG("HCameraService::SetMuteCallback pid = %{public}d", pid);
    CHECK_ERROR_RETURN_RET_LOG(callback == nullptr, CAMERA_INVALID_ARG,
        "HCameraService::SetMuteCallback callback is null");
    // If the callback set by the SA caller is later than the camera service is started,
    // the callback cannot be triggered to obtain the mute state. Therefore,
    // when the SA sets the callback, the callback is triggered immediately to return the mute state.
    constexpr int32_t maxSaUid = 10000;
    if (IPCSkeleton::GetCallingUid() > 0 && IPCSkeleton::GetCallingUid() < maxSaUid) {
        callback->OnCameraMute(muteModeStored_);
    }
    cameraMuteServiceCallbacks_.insert(make_pair(pid, callback));
    return CAMERA_OK;
}

int32_t HCameraService::SetTorchCallback(sptr<ITorchServiceCallback>& callback)
{
    lock_guard<recursive_mutex> lock(torchCbMutex_);
    pid_t pid = IPCSkeleton::GetCallingPid();
    MEDIA_INFO_LOG("HCameraService::SetTorchCallback pid = %{public}d", pid);
    CHECK_ERROR_RETURN_RET_LOG(callback == nullptr, CAMERA_INVALID_ARG,
        "HCameraService::SetTorchCallback callback is null");
    torchServiceCallbacks_.insert(make_pair(pid, callback));

    MEDIA_INFO_LOG("HCameraService::SetTorchCallback notify pid = %{public}d", pid);
    callback->OnTorchStatusChange(torchStatus_);
    return CAMERA_OK;
}

int32_t HCameraService::SetFoldStatusCallback(sptr<IFoldServiceCallback>& callback)
{
    lock_guard<recursive_mutex> lock(foldCbMutex_);
    isFoldable = isFoldableInit ? isFoldable : g_isFoldScreen;
    CHECK_EXECUTE((isFoldable && !isFoldRegister), RegisterFoldStatusListener());
    pid_t pid = IPCSkeleton::GetCallingPid();
    MEDIA_INFO_LOG("HCameraService::SetFoldStatusCallback pid = %{public}d", pid);
    CHECK_ERROR_RETURN_RET_LOG(callback == nullptr, CAMERA_INVALID_ARG,
        "HCameraService::SetFoldStatusCallback callback is null");
    foldServiceCallbacks_.insert(make_pair(pid, callback));
    return CAMERA_OK;
}

int32_t HCameraService::UnSetCameraCallback(pid_t pid)
{
    lock_guard<mutex> lock(cameraCbMutex_);
    MEDIA_INFO_LOG("HCameraService::UnSetCameraCallback pid = %{public}d, size = %{public}zu",
        pid, cameraServiceCallbacks_.size());
    if (!cameraServiceCallbacks_.empty()) {
        MEDIA_INFO_LOG("HCameraService::UnSetCameraCallback cameraServiceCallbacks_ is not empty, reset it");
        auto it = cameraServiceCallbacks_.find(pid);
        if ((it != cameraServiceCallbacks_.end()) && (it->second != nullptr)) {
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
        if ((it != cameraMuteServiceCallbacks_.end()) && (it->second)) {
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
        if ((it != torchServiceCallbacks_.end()) && (it->second)) {
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
        if ((it != foldServiceCallbacks_.end()) && (it->second)) {
            it->second = nullptr;
            foldServiceCallbacks_.erase(it);
        }
    }
    MEDIA_INFO_LOG("HCameraService::UnSetFoldStatusCallback after erase pid = %{public}d, size = %{public}zu",
        pid, foldServiceCallbacks_.size());
    return CAMERA_OK;
}

void HCameraService::RegisterFoldStatusListener()
{
    MEDIA_INFO_LOG("RegisterFoldStatusListener is called");
    auto ret = OHOS::Rosen::DisplayManager::GetInstance().RegisterFoldStatusListener(this);
    CHECK_ERROR_RETURN_LOG(ret != OHOS::Rosen::DMError::DM_OK, "RegisterFoldStatusListener failed");
    isFoldRegister = true;
}

void HCameraService::UnRegisterFoldStatusListener()
{
    MEDIA_INFO_LOG("UnRegisterFoldStatusListener is called");
    auto ret = OHOS::Rosen::DisplayManager::GetInstance().UnregisterFoldStatusListener(this);
    CHECK_ERROR_PRINT_LOG(ret != OHOS::Rosen::DMError::DM_OK, "UnRegisterFoldStatusListener failed");
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
    CHECK_ERROR_RETURN_RET_LOG(ret != CAMERA_OK, false, "HCameraService::IsCameraMuted GetCameraAbility failed");
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = cameraAbility->get();
    ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_MUTE_MODES, &item);
    if (ret == CAM_META_SUCCESS) {
        for (uint32_t i = 0; i < item.count; i++) {
            MEDIA_INFO_LOG("OHOS_ABILITY_MUTE_MODES %{public}d th is %{public}d", i, item.data.u8[i]);
            if (item.data.u8[i] == OHOS_CAMERA_MUTE_MODE_SOLID_COLOR_BLACK) {
                isMuteSupported = true;
                break;
            }
        }
    } else {
        isMuteSupported = false;
        MEDIA_ERR_LOG("HCameraService::IsCameraMuted not find MUTE ability");
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
    bool status = false;
    int32_t ret;
    int32_t count = 1;
    uint8_t mode = muteMode ? OHOS_CAMERA_MUTE_MODE_SOLID_COLOR_BLACK : OHOS_CAMERA_MUTE_MODE_OFF;
    camera_metadata_item_t item;

    MEDIA_DEBUG_LOG("UpdateMuteSetting muteMode: %{public}d", muteMode);

    ret = OHOS::Camera::FindCameraMetadataItem(changedMetadata->get(), OHOS_CONTROL_MUTE_MODE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata->addEntry(OHOS_CONTROL_MUTE_MODE, &mode, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata->updateEntry(OHOS_CONTROL_MUTE_MODE, &mode, count);
    }
    ret = cameraDevice->UpdateSetting(changedMetadata);
    CHECK_ERROR_RETURN_RET_LOG(!status || ret != CAMERA_OK, CAMERA_UNKNOWN_ERROR, "UpdateMuteSetting muteMode Failed");
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
    pid_t activeClient = deviceManager->GetActiveClient();
    if (activeClient == -1) {
        OnMute(muteMode);
        int32_t retCode = SetMuteModeByDataShareHelper(muteMode);
        muteModeStored_ = muteMode;
        if (retCode != CAMERA_OK) {
            MEDIA_ERR_LOG("no activeClient, SetMuteModeByDataShareHelper: ret=%{public}d", retCode);
            muteModeStored_ = currentMuteMode;
        }
        return retCode;
    }
    sptr<HCameraDevice> activeDevice = deviceManager->GetCameraByPid(activeClient);
    if (activeDevice != nullptr) {
        string cameraId = activeDevice->GetCameraId();
        CHECK_ERROR_RETURN_RET_LOG(!IsCameraMuteSupported(cameraId), CAMERA_UNSUPPORTED,
            "Not Supported Mute,cameraId: %{public}s", cameraId.c_str());
        if (activeDevice != nullptr) {
            ret = UpdateMuteSetting(activeDevice, muteMode);
        }
        if (ret != CAMERA_OK) {
            MEDIA_ERR_LOG("UpdateMuteSetting Failed, cameraId: %{public}s", cameraId.c_str());
            muteModeStored_ = currentMuteMode;
        }
    }
    if (ret == CAMERA_OK) {
        OnMute(muteMode);
    }
    if (activeDevice != nullptr) {
        activeDevice->SetDeviceMuteMode(muteMode);
    }
    ret = SetMuteModeByDataShareHelper(muteMode);
    if (ret == CAMERA_OK) {
        muteModeStored_ = muteMode;
    }
    return ret;
}

static std::map<PolicyType, Security::AccessToken::PolicyType> g_policyTypeMap_ = {
    {PolicyType::EDM, Security::AccessToken::PolicyType::EDM},
    {PolicyType::PRIVACY, Security::AccessToken::PolicyType::PRIVACY},
};

int32_t HCameraService::MuteCamera(bool muteMode)
{
    int32_t ret = CheckPermission(OHOS_PERMISSION_MANAGE_CAMERA_CONFIG, IPCSkeleton::GetCallingTokenID());
    CHECK_ERROR_RETURN_RET_LOG(ret != CAMERA_OK, ret, "CheckPermission argumentis failed!");
    CameraReportUtils::GetInstance().ReportUserBehavior(DFX_UB_MUTE_CAMERA,
        to_string(muteMode), CameraReportUtils::GetCallerInfo());
    return MuteCameraFunc(muteMode);
}

int32_t HCameraService::MuteCameraPersist(PolicyType policyType, bool isMute)
{
    int32_t ret = CheckPermission(OHOS_PERMISSION_CAMERA_CONTROL, IPCSkeleton::GetCallingTokenID());
    CHECK_ERROR_RETURN_RET_LOG(ret != CAMERA_OK, ret, "CheckPermission arguments failed!");
    CameraReportUtils::GetInstance().ReportUserBehavior(DFX_UB_MUTE_CAMERA,
        to_string(isMute), CameraReportUtils::GetCallerInfo());
    CHECK_ERROR_RETURN_RET_LOG(g_policyTypeMap_.count(policyType) == 0, CAMERA_INVALID_ARG,
        "MuteCameraPersist Failed, invalid param policyType = %{public}d", static_cast<int32_t>(policyType));
    bool targetMuteMode = isMute;
    const Security::AccessToken::PolicyType secPolicyType = g_policyTypeMap_[policyType];
    const Security::AccessToken::CallerType secCaller = Security::AccessToken::CallerType::CAMERA;
    ret = Security::AccessToken::PrivacyKit::SetMutePolicy(secPolicyType, secCaller, isMute);
    if (ret != Security::AccessToken::RET_SUCCESS) {
        MEDIA_ERR_LOG("MuteCameraPersist SetMutePolicy return false, policyType = %{public}d, retCode = %{public}d",
            static_cast<int32_t>(policyType), static_cast<int32_t>(ret));
        targetMuteMode = muteModeStored_;
    }
    return MuteCameraFunc(targetMuteMode);
}

int32_t HCameraService::PrelaunchCamera()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HCameraService::PrelaunchCamera");
    CHECK_ERROR_RETURN_RET_LOG(HCameraDeviceManager::GetInstance()->GetCameraStateOfASide().Size() != 0,
        CAMERA_DEVICE_CONFLICT, "HCameraService::PrelaunchCamera there is a device active in A side, abort!");
    if (preCameraId_.empty()) {
        vector<string> cameraIds_;
        cameraHostManager_->GetCameras(cameraIds_);
        if (cameraIds_.empty()) {
            return CAMERA_OK;
        }
        preCameraId_ = cameraIds_.front();
    }
    MEDIA_INFO_LOG("HCameraService::PrelaunchCamera preCameraId_ is: %{public}s", preCameraId_.c_str());
    CAMERA_SYSEVENT_STATISTIC(CreateMsg("Camera Prelaunch CameraId:%s", preCameraId_.c_str()));
    CameraReportUtils::GetInstance().SetOpenCamPerfPreInfo(preCameraId_.c_str(), CameraReportUtils::GetCallerInfo());
    int32_t ret = cameraHostManager_->Prelaunch(preCameraId_, preCameraClient_);
    CHECK_ERROR_PRINT_LOG(ret != CAMERA_OK, "HCameraService::Prelaunch failed");
    return ret;
}

int32_t HCameraService::PreSwitchCamera(const std::string cameraId)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HCameraService::PreSwitchCamera");
    if (cameraId.empty()) {
        return CAMERA_INVALID_ARG;
    }
    std::vector<std::string> cameraIds_;
    cameraHostManager_->GetCameras(cameraIds_);
    CHECK_AND_RETURN_RET(!cameraIds_.empty(), CAMERA_INVALID_STATE);
    auto it = std::find(cameraIds_.begin(), cameraIds_.end(), cameraId);
    CHECK_AND_RETURN_RET(it != cameraIds_.end(), CAMERA_INVALID_ARG);
    MEDIA_INFO_LOG("HCameraService::PreSwitchCamera cameraId is: %{public}s", cameraId.c_str());
    CameraReportUtils::GetInstance().SetSwitchCamPerfStartInfo(CameraReportUtils::GetCallerInfo());
    int32_t ret = cameraHostManager_->PreSwitchCamera(cameraId);
    CHECK_ERROR_PRINT_LOG(ret != CAMERA_OK, "HCameraService::Prelaunch failed");
    return ret;
}

int32_t HCameraService::SetPrelaunchConfig(string cameraId, RestoreParamTypeOhos restoreParamType, int activeTime,
    EffectParam effectParam)
{
    CAMERA_SYNC_TRACE;
    OHOS::Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    string permissionName = OHOS_PERMISSION_CAMERA;
    int32_t ret = CheckPermission(permissionName, callerToken);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAMERA_OK, ret,
        "HCameraService::SetPrelaunchConfig failed permission is: %{public}s", permissionName.c_str());

    MEDIA_INFO_LOG("HCameraService::SetPrelaunchConfig cameraId %{public}s", (cameraId).c_str());
    vector<string> cameraIds_;
    cameraHostManager_->GetCameras(cameraIds_);
    if ((find(cameraIds_.begin(), cameraIds_.end(), cameraId) != cameraIds_.end()) && IsPrelaunchSupported(cameraId)) {
        preCameraId_ = cameraId;
        MEDIA_INFO_LOG("CameraHostInfo::prelaunch 111 for cameraId %{public}s", (cameraId).c_str());
        sptr<HCaptureSession> captureSession_ = nullptr;
        pid_t pid = IPCSkeleton::GetCallingPid();
        captureSessionsManager_.Find(pid, captureSession_);
        SaveCurrentParamForRestore(cameraId, static_cast<RestoreParamTypeOhos>(restoreParamType), activeTime,
            effectParam, captureSession_);
        captureSessionsManager_.Clear();
        captureSessionsManager_.EnsureInsert(pid, captureSession_);
    } else {
        MEDIA_ERR_LOG("HCameraService::SetPrelaunchConfig illegal");
        ret = CAMERA_INVALID_ARG;
    }
    return ret;
}

int32_t HCameraService::SetTorchLevel(float level)
{
    int32_t ret = cameraHostManager_->SetTorchLevel(level);
    CHECK_ERROR_PRINT_LOG(ret != CAMERA_OK, "Failed to SetTorchLevel");
    return ret;
}

int32_t HCameraService::AllowOpenByOHSide(std::string cameraId, int32_t state, bool& canOpenCamera)
{
    MEDIA_INFO_LOG("HCameraService::AllowOpenByOHSide start");
    pid_t activePid = HCameraDeviceManager::GetInstance()->GetActiveClient();
    if (activePid == -1) {
        MEDIA_INFO_LOG("AllowOpenByOHSide::Open allow open camera");
        NotifyCameraState(cameraId, 0);
        canOpenCamera = true;
        return CAMERA_OK;
    }
    sptr<HCameraDevice> cameraNeedEvict = HCameraDeviceManager::GetInstance()->GetCameraByPid(activePid);
    if (cameraNeedEvict != nullptr) {
        cameraNeedEvict->OnError(DEVICE_PREEMPT, 0);
        cameraNeedEvict->Close();
        NotifyCameraState(cameraId, 0);
        canOpenCamera = true;
    }
    MEDIA_INFO_LOG("HCameraService::AllowOpenByOHSide end");
    return CAMERA_OK;
}

int32_t HCameraService::NotifyCameraState(std::string cameraId, int32_t state)
{
    // 把cameraId和前后台状态刷新给device manager
    MEDIA_INFO_LOG(
        "HCameraService::NotifyCameraState SetStateOfACamera %{public}s:%{public}d", cameraId.c_str(), state);
    HCameraDeviceManager::GetInstance()->SetStateOfACamera(cameraId, state);
    return CAMERA_OK;
}

int32_t HCameraService::SetPeerCallback(sptr<ICameraBroker>& callback)
{
    MEDIA_INFO_LOG("SetPeerCallback get callback");
    CHECK_ERROR_RETURN_RET(callback == nullptr, CAMERA_INVALID_ARG);
    peerCallback_ = callback;
    MEDIA_INFO_LOG("HCameraService::SetPeerCallback current muteMode:%{public}d", muteModeStored_);
    callback->NotifyMuteCamera(muteModeStored_);
    HCameraDeviceManager::GetInstance()->SetPeerCallback(callback);
    return CAMERA_OK;
}

int32_t HCameraService::UnsetPeerCallback()
{
    MEDIA_INFO_LOG("UnsetPeerCallback callback");
    peerCallback_ = nullptr;
    HCameraDeviceManager::GetInstance()->UnsetPeerCallback();
    return CAMERA_OK;
}

bool HCameraService::IsPrelaunchSupported(string cameraId)
{
    bool isPrelaunchSupported = false;
    shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility;
    int32_t ret = cameraHostManager_->GetCameraAbility(cameraId, cameraAbility);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAMERA_OK, isPrelaunchSupported,
        "HCameraService::IsCameraMuted GetCameraAbility failed");
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

int32_t HCameraService::IsCameraMuted(bool& muteMode)
{
    lock_guard<mutex> lock(g_dataShareHelperMutex);
    CHECK_ERROR_RETURN_RET(GetServiceStatus() != CameraServiceStatus::SERVICE_READY, CAMERA_INVALID_STATE);
    muteMode = muteModeStored_;

    MEDIA_DEBUG_LOG("HCameraService::IsCameraMuted success. isMuted: %{public}d", muteMode);
    return CAMERA_OK;
}

void HCameraService::DumpCameraSummary(vector<string> cameraIds, CameraInfoDumper& infoDumper)
{
    infoDumper.Tip("--------Dump Summary Begin-------");
    infoDumper.Title("Number of Cameras:[" + to_string(cameraIds.size()) + "]");
    infoDumper.Title("Number of Active Cameras:[" + to_string(1) + "]");
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
    if (ret == CAM_META_SUCCESS) {
        map<int, string>::const_iterator iter = g_cameraConType.find(item.data.u8[0]);
        if (iter != g_cameraConType.end()) {
            infoDumper.Title("Camera Connection Type:[" + iter->second + "]");
        }
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
        if (item.count == zoomRangeCount) {
            infoDumper.Msg("Available scene Zoom Capability:[" + to_string(item.data.i32[minIndex]) + "  " +
                           to_string(item.data.i32[maxIndex]) + "]");
        }
    }

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_ZOOM_RATIO_RANGE, &item);
    if (ret == CAM_META_SUCCESS) {
        infoDumper.Msg("OHOS_ABILITY_ZOOM_RATIO_RANGE data size:" + to_string(item.count));
        if (item.count == zoomRangeCount) {
            infoDumper.Msg("Available Zoom Ratio Range:[" + to_string(item.data.f[minIndex]) +
                           to_string(item.data.f[maxIndex]) + "]");
        }
    }
}

void HCameraService::DumpCameraFlash(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper)
{
    camera_metadata_item_t item;
    int ret;
    infoDumper.Title("Flash Related Info:");
    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_FLASH_MODES, &item);
    if (ret == CAM_META_SUCCESS) {
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
}

void HCameraService::DumpCameraAF(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper)
{
    camera_metadata_item_t item;
    int ret;
    infoDumper.Title("AF Related Info:");
    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_FOCUS_MODES, &item);
    if (ret == CAM_META_SUCCESS) {
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
}

void HCameraService::DumpCameraAE(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper)
{
    camera_metadata_item_t item;
    int ret;
    infoDumper.Title("AE Related Info:");
    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_EXPOSURE_MODES, &item);
    if (ret == CAM_META_SUCCESS) {
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
    if (ret == CAM_META_SUCCESS) {
        infoDumper.Msg("Array:[" +
            to_string(item.data.i32[leftIndex]) + " " +
            to_string(item.data.i32[topIndex]) + " " +
            to_string(item.data.i32[rightIndex]) + " " +
            to_string(item.data.i32[bottomIndex]) + "]:\n");
    }
}

void HCameraService::DumpCameraVideoStabilization(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper)
{
    camera_metadata_item_t item;
    int ret;
    infoDumper.Title("Video Stabilization Related Info:");
    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_VIDEO_STABILIZATION_MODES, &item);
    if (ret == CAM_META_SUCCESS) {
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
}

void HCameraService::DumpCameraVideoFrameRateRange(
    common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper)
{
    camera_metadata_item_t item;
    const int32_t FRAME_RATE_RANGE_STEP = 2;
    int ret;
    infoDumper.Title("Video FrameRateRange Related Info:");
    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_FPS_RANGES, &item);
    if (ret == CAM_META_SUCCESS && item.count > 0) {
        infoDumper.Msg("Available FrameRateRange:");
        for (uint32_t i = 0; i < (item.count - 1); i += FRAME_RATE_RANGE_STEP) {
            infoDumper.Msg("[ " + to_string(item.data.i32[i]) + ", " + to_string(item.data.i32[i + 1]) + " ]");
        }
    }
}

void HCameraService::DumpCameraPrelaunch(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper)
{
    camera_metadata_item_t item;
    int ret;
    infoDumper.Title("Camera Prelaunch Related Info:");
    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_PRELAUNCH_AVAILABLE, &item);
    if (ret == CAM_META_SUCCESS) {
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
}

void HCameraService::DumpCameraThumbnail(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper)
{
    camera_metadata_item_t item;
    int ret;
    infoDumper.Title("Camera Thumbnail Related Info:");
    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_STREAM_QUICK_THUMBNAIL_AVAILABLE, &item);
    if (ret == CAM_META_SUCCESS) {
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
}

int32_t HCameraService::Dump(int fd, const vector<u16string>& args)
{
    unordered_set<u16string> argSets;
    for (decltype(args.size()) index = 0; index < args.size(); ++index) {
        argSets.insert(args[index]);
    }
    std::string dumpString;
    std::vector<std::string> cameraIds;
    std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>> cameraAbilityList;
    int ret = GetCameras(cameraIds, cameraAbilityList);
    CHECK_ERROR_RETURN_RET((ret != CAMERA_OK) || cameraIds.empty() || cameraAbilityList.empty(), OHOS::UNKNOWN_ERROR);
    CameraInfoDumper infoDumper(fd);
    if (args.empty() || argSets.count(u16string(u"summary"))) {
        DumpCameraSummary(cameraIds, infoDumper);
    }
    if (args.empty() || argSets.count(u16string(u"ability"))) {
        DumpCameraInfo(infoDumper, cameraIds, cameraAbilityList);
    }
    if (args.empty() || argSets.count(u16string(u"preconfig"))) {
        infoDumper.Tip("--------Dump PreconfigInfo Begin-------");
        DumpPreconfigInfo(infoDumper, cameraHostManager_);
    }
    if (args.empty() || argSets.count(u16string(u"clientwiseinfo"))) {
        infoDumper.Tip("--------Dump Clientwise Info Begin-------");
        HCaptureSession::DumpSessions(infoDumper);
    }
    if (argSets.count(std::u16string(u"debugOn"))) {
        SetCameraDebugValue(true);
    }
    infoDumper.Print();
    return OHOS::NO_ERROR;
}

#ifdef CAMERA_USE_SENSOR
void HCameraService::RegisterSensorCallback()
{
    if (isRegisterSensorSuccess) {
        MEDIA_INFO_LOG("HCameraService::RegisterSensorCallback isRegisterSensorSuccess return");
        return;
    }
    MEDIA_INFO_LOG("HCameraService::RegisterSensorCallback start");
    user.callback = DropDetectionDataCallbackImpl;
    int32_t subscribeRet = SubscribeSensor(SENSOR_TYPE_ID_DROP_DETECTION, &user);
    MEDIA_INFO_LOG("RegisterSensorCallback, subscribeRet: %{public}d", subscribeRet);
    int32_t setBatchRet = SetBatch(SENSOR_TYPE_ID_DROP_DETECTION, &user, POSTURE_INTERVAL, POSTURE_INTERVAL);
    MEDIA_INFO_LOG("RegisterSensorCallback, setBatchRet: %{public}d", setBatchRet);
    int32_t activateRet = ActivateSensor(SENSOR_TYPE_ID_DROP_DETECTION, &user);
    MEDIA_INFO_LOG("RegisterSensorCallback, activateRet: %{public}d", activateRet);
    if (subscribeRet != SENSOR_SUCCESS || setBatchRet != SENSOR_SUCCESS || activateRet != SENSOR_SUCCESS) {
        isRegisterSensorSuccess = false;
        MEDIA_INFO_LOG("RegisterSensorCallback failed.");
    }  else {
        isRegisterSensorSuccess = true;
    }
}

void HCameraService::UnRegisterSensorCallback()
{
    int32_t deactivateRet = DeactivateSensor(SENSOR_TYPE_ID_DROP_DETECTION, &user);
    int32_t unsubscribeRet = UnsubscribeSensor(SENSOR_TYPE_ID_DROP_DETECTION, &user);
    if (deactivateRet == SENSOR_SUCCESS && unsubscribeRet == SENSOR_SUCCESS) {
        MEDIA_INFO_LOG("HCameraService.UnRegisterSensorCallback success.");
    }
}

void HCameraService::DropDetectionDataCallbackImpl(SensorEvent* event)
{
    MEDIA_INFO_LOG("HCameraService::DropDetectionDataCallbackImpl prepare execute");
    CHECK_ERROR_RETURN_LOG(event == nullptr, "SensorEvent is nullptr.");
    CHECK_ERROR_RETURN_LOG(event[0].data == nullptr, "SensorEvent[0].data is nullptr.");
    CHECK_ERROR_RETURN_LOG(event[0].dataLen < sizeof(DropDetectionData),
        "less than drop detection data size, event.dataLen:%{public}u", event[0].dataLen);
    {
        std::lock_guard<std::mutex> lock(g_cameraServiceInstanceMutex);
        g_cameraServiceInstance->cameraHostManager_->NotifyDeviceStateChangeInfo(
            DeviceType::FALLING_TYPE, FallingState::FALLING_STATE);
    }
}
#endif

int32_t HCameraService::SaveCurrentParamForRestore(std::string cameraId, RestoreParamTypeOhos restoreParamType,
    int activeTime, EffectParam effectParam, sptr<HCaptureSession> captureSession)
{
    MEDIA_INFO_LOG("HCameraService::SaveCurrentParamForRestore enter");
    int32_t rc = CAMERA_OK;
    preCameraClient_ = GetClientBundle(IPCSkeleton::GetCallingUid());
    sptr<HCameraRestoreParam> cameraRestoreParam = new HCameraRestoreParam(
        preCameraClient_, cameraId);
    cameraRestoreParam->SetRestoreParamType(restoreParamType);
    cameraRestoreParam->SetStartActiveTime(activeTime);
    int foldStatus = static_cast<int>(OHOS::Rosen::DisplayManager::GetInstance().GetFoldStatus());
    cameraRestoreParam->SetFoldStatus(foldStatus);
    if (captureSession == nullptr || restoreParamType == NO_NEED_RESTORE_PARAM_OHOS) {
        cameraHostManager_->SaveRestoreParam(cameraRestoreParam);
        return rc;
    }

    sptr<HCameraDeviceManager> deviceManager = HCameraDeviceManager::GetInstance();
    pid_t activeClient = deviceManager->GetActiveClient();
    CHECK_ERROR_RETURN_RET_LOG(activeClient == -1, CAMERA_OPERATION_NOT_ALLOWED,
        "HCaptureSession::SaveCurrentParamForRestore() Failed to save param");
    sptr<HCameraDevice> activeDevice = deviceManager->GetCameraByPid(activeClient);
    CHECK_AND_RETURN_RET(activeDevice != nullptr, CAMERA_OK);
    std::vector<StreamInfo_V1_1> allStreamInfos;

    if (activeDevice != nullptr) {
        std::shared_ptr<OHOS::Camera::CameraMetadata> defaultSettings = CreateDefaultSettingForRestore(activeDevice);
        UpdateSkinSmoothSetting(defaultSettings, effectParam.skinSmoothLevel);
        UpdateFaceSlenderSetting(defaultSettings, effectParam.faceSlender);
        UpdateSkinToneSetting(defaultSettings, effectParam.skinTone);
        cameraRestoreParam->SetSetting(defaultSettings);
    }
    CHECK_AND_RETURN_RET(activeDevice != nullptr, CAMERA_UNKNOWN_ERROR);
    MEDIA_DEBUG_LOG("HCameraService::SaveCurrentParamForRestore param %{public}d", effectParam.skinSmoothLevel);
    rc = captureSession->GetCurrentStreamInfos(allStreamInfos);
    CHECK_ERROR_RETURN_RET_LOG(rc != CAMERA_OK, rc,
        "HCaptureSession::SaveCurrentParamForRestore() Failed to get streams info, %{public}d", rc);
    for (auto& info : allStreamInfos) {
        MEDIA_INFO_LOG("HCameraService::SaveCurrentParamForRestore: streamId is:%{public}d", info.v1_0.streamId_);
    }
    cameraRestoreParam->SetStreamInfo(allStreamInfos);
    cameraRestoreParam->SetCameraOpMode(captureSession->GetopMode());
    cameraHostManager_->SaveRestoreParam(cameraRestoreParam);
    MEDIA_INFO_LOG("HCameraService::SaveCurrentParamForRestore end");
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
    CHECK_ERROR_RETURN_RET_LOG(currentSetting == nullptr, defaultSettings,
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
    ret = OHOS::Camera::FindCameraMetadataItem(currentSetting->get(), OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &item);
    if (ret == CAM_META_SUCCESS) {
        uint8_t stabilizationMode_ = item.data.u8[0];
        defaultSettings->addEntry(OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &stabilizationMode_, count);
    }

    ret = OHOS::Camera::FindCameraMetadataItem(currentSetting->get(), OHOS_CONTROL_DEFERRED_IMAGE_DELIVERY, &item);
    if (ret == CAM_META_SUCCESS) {
        uint8_t deferredType = item.data.u8[0];
        defaultSettings->addEntry(OHOS_CONTROL_DEFERRED_IMAGE_DELIVERY, &deferredType, count);
    }

    ret = OHOS::Camera::FindCameraMetadataItem(currentSetting->get(), OHOS_CONTROL_SUPPORTED_COLOR_MODES, &item);
    if (ret == CAM_META_SUCCESS) {
        uint8_t colorEffectTemp = item.data.u8[0];
        defaultSettings->addEntry(OHOS_CONTROL_SUPPORTED_COLOR_MODES, &colorEffectTemp, count);
    }

    ret = OHOS::Camera::FindCameraMetadataItem(currentSetting->get(), OHOS_CONTROL_PORTRAIT_EFFECT_TYPE, &item);
    if (ret == CAM_META_SUCCESS) {
        uint8_t effect = item.data.u8[0];
        defaultSettings->addEntry(OHOS_CONTROL_PORTRAIT_EFFECT_TYPE, &effect, count);
    }
    ret = OHOS::Camera::FindCameraMetadataItem(currentSetting->get(), OHOS_CONTROL_FILTER_TYPE, &item);
    if (ret == CAM_META_SUCCESS) {
        uint8_t filterValue = item.data.u8[0];
        defaultSettings->addEntry(OHOS_CONTROL_FILTER_TYPE, &filterValue, count);
    }

    ret = OHOS::Camera::FindCameraMetadataItem(currentSetting->get(), OHOS_CONTROL_EFFECT_SUGGESTION, &item);
    if (ret == CAM_META_SUCCESS) {
        uint8_t enableValue = item.data.u8[0];
        defaultSettings->addEntry(OHOS_CONTROL_EFFECT_SUGGESTION, &enableValue, count);
    }

    ret = OHOS::Camera::FindCameraMetadataItem(currentSetting->get(), OHOS_CONTROL_MOTION_DETECTION, &item);
    if (ret == CAM_META_SUCCESS) {
        uint8_t enableValue = item.data.u8[0];
        defaultSettings->addEntry(OHOS_CONTROL_MOTION_DETECTION, &enableValue, count);
    }

    ret = OHOS::Camera::FindCameraMetadataItem(currentSetting->get(), OHOS_CONTROL_HIGH_QUALITY_MODE, &item);
    if (ret == CAM_META_SUCCESS) {
        uint8_t enableValue = item.data.u8[0];
        defaultSettings->addEntry(OHOS_CONTROL_HIGH_QUALITY_MODE, &enableValue, count);
    }

    ret = OHOS::Camera::FindCameraMetadataItem(currentSetting->get(), OHOS_CAMERA_USER_ID, &item);
    if (ret == CAM_META_SUCCESS) {
        int32_t enableValue = item.data.i32[0];
        defaultSettings->addEntry(OHOS_CAMERA_USER_ID, &enableValue, count);
    }

    ret = OHOS::Camera::FindCameraMetadataItem(currentSetting->get(), OHOS_CONTROL_MOVING_PHOTO, &item);
    if (ret == CAM_META_SUCCESS) {
        uint8_t enableValue = item.data.u8[0];
        defaultSettings->addEntry(OHOS_CONTROL_MOVING_PHOTO, &enableValue, count);
    }
    
    ret = OHOS::Camera::FindCameraMetadataItem(currentSetting->get(), OHOS_CONTROL_AUTO_CLOUD_IMAGE_ENHANCE, &item);
    if (ret == CAM_META_SUCCESS) {
        uint8_t filterValue = item.data.u8[0];
        defaultSettings->addEntry(OHOS_CONTROL_AUTO_CLOUD_IMAGE_ENHANCE, &filterValue, count);
    }

    ret = OHOS::Camera::FindCameraMetadataItem(currentSetting->get(), OHOS_CONTROL_BEAUTY_AUTO_VALUE, &item);
    if (ret == CAM_META_SUCCESS) {
        uint8_t enableValue = item.data.u8[0];
        defaultSettings->addEntry(OHOS_CONTROL_BEAUTY_AUTO_VALUE, &enableValue, count);
    }

    ret = OHOS::Camera::FindCameraMetadataItem(currentSetting->get(), OHOS_CONTROL_CAMERA_USED_AS_POSITION, &item);
    if (ret == CAM_META_SUCCESS) {
        uint8_t enableValue = item.data.u8[0];
        defaultSettings->addEntry(OHOS_CONTROL_CAMERA_USED_AS_POSITION, &enableValue, count);
    }
    uint8_t enableValue = true;
    defaultSettings->addEntry(OHOS_CONTROL_VIDEO_DEBUG_SWITCH, &enableValue, 1);
    return defaultSettings;
}

int32_t HCameraService::UpdateSkinSmoothSetting(std::shared_ptr<OHOS::Camera::CameraMetadata> changedMetadata,
                                                int skinSmoothValue)
{
    if (skinSmoothValue <= 0 || changedMetadata == nullptr) {
        return CAMERA_OK;
    }
    bool status = false;
    int32_t count = 1;
    int ret;
    camera_metadata_item_t item;

    MEDIA_DEBUG_LOG("UpdateBeautySetting skinsmooth: %{public}d", skinSmoothValue);
    uint8_t beauty = OHOS_CAMERA_BEAUTY_TYPE_SKIN_SMOOTH;
    ret = OHOS::Camera::FindCameraMetadataItem(changedMetadata->get(), OHOS_CONTROL_BEAUTY_TYPE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata->addEntry(OHOS_CONTROL_BEAUTY_TYPE, &beauty, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata->updateEntry(OHOS_CONTROL_BEAUTY_TYPE, &beauty, count);
    }

    ret = OHOS::Camera::FindCameraMetadataItem(changedMetadata->get(), OHOS_CONTROL_BEAUTY_SKIN_SMOOTH_VALUE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata->addEntry(OHOS_CONTROL_BEAUTY_SKIN_SMOOTH_VALUE, &skinSmoothValue, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata->updateEntry(OHOS_CONTROL_BEAUTY_SKIN_SMOOTH_VALUE, &skinSmoothValue, count);
    }
    if (status) {
        MEDIA_INFO_LOG("UpdateBeautySetting status: %{public}d", status);
    }

    return CAMERA_OK;
}

int32_t HCameraService::UpdateFaceSlenderSetting(std::shared_ptr<OHOS::Camera::CameraMetadata> changedMetadata,
                                                 int faceSlenderValue)
{
    if (faceSlenderValue <= 0 || changedMetadata == nullptr) {
        return CAMERA_OK;
    }
    bool status = false;
    int32_t count = 1;
    int ret;
    camera_metadata_item_t item;

    MEDIA_DEBUG_LOG("UpdateBeautySetting faceSlender: %{public}d", faceSlenderValue);
    uint8_t beauty = OHOS_CAMERA_BEAUTY_TYPE_FACE_SLENDER;
    ret = OHOS::Camera::FindCameraMetadataItem(changedMetadata->get(), OHOS_CONTROL_BEAUTY_TYPE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata->addEntry(OHOS_CONTROL_BEAUTY_TYPE, &beauty, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata->updateEntry(OHOS_CONTROL_BEAUTY_TYPE, &beauty, count);
    }

    ret = OHOS::Camera::FindCameraMetadataItem(changedMetadata->get(), OHOS_CONTROL_BEAUTY_FACE_SLENDER_VALUE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata->addEntry(OHOS_CONTROL_BEAUTY_FACE_SLENDER_VALUE, &faceSlenderValue, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata->updateEntry(OHOS_CONTROL_BEAUTY_FACE_SLENDER_VALUE, &faceSlenderValue, count);
    }
    if (status) {
        MEDIA_INFO_LOG("UpdateBeautySetting status: %{public}d", status);
    }

    return CAMERA_OK;
}

int32_t HCameraService::UpdateSkinToneSetting(std::shared_ptr<OHOS::Camera::CameraMetadata> changedMetadata,
    int skinToneValue)
{
    if (skinToneValue <= 0 || changedMetadata == nullptr) {
        return CAMERA_OK;
    }
    bool status = false;
    int32_t count = 1;
    int ret;
    camera_metadata_item_t item;

    MEDIA_DEBUG_LOG("UpdateBeautySetting skinTone: %{public}d", skinToneValue);
    uint8_t beauty = OHOS_CAMERA_BEAUTY_TYPE_SKIN_TONE;
    ret = OHOS::Camera::FindCameraMetadataItem(changedMetadata->get(), OHOS_CONTROL_BEAUTY_TYPE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata->addEntry(OHOS_CONTROL_BEAUTY_TYPE, &beauty, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata->updateEntry(OHOS_CONTROL_BEAUTY_TYPE, &beauty, count);
    }

    ret = OHOS::Camera::FindCameraMetadataItem(changedMetadata->get(), OHOS_CONTROL_BEAUTY_SKIN_TONE_VALUE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata->addEntry(OHOS_CONTROL_BEAUTY_SKIN_TONE_VALUE, &skinToneValue, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata->updateEntry(OHOS_CONTROL_BEAUTY_SKIN_TONE_VALUE, &skinToneValue, count);
    }
    if (status) {
        MEDIA_INFO_LOG("UpdateBeautySetting status: %{public}d", status);
    }

    return CAMERA_OK;
}

std::string g_toString(std::set<int32_t>& pidList)
{
    std::string ret = "[";
    for (const auto& pid : pidList) {
        ret += std::to_string(pid) + ",";
    }
    ret += "]";
    return ret;
}

int32_t HCameraService::ProxyForFreeze(const std::set<int32_t>& pidList, bool isProxy)
{
    constexpr int32_t maxSaUid = 10000;
    CHECK_ERROR_RETURN_RET_LOG(IPCSkeleton::GetCallingUid() >= maxSaUid, CAMERA_OPERATION_NOT_ALLOWED, "not allow");
    MEDIA_INFO_LOG("isProxy value: %{public}d", isProxy);
    {
        std::lock_guard<std::mutex> lock(freezedPidListMutex_);
        if (isProxy) {
            freezedPidList_.insert(pidList.begin(), pidList.end());
            MEDIA_DEBUG_LOG("after freeze freezedPidList_:%{public}s", g_toString(freezedPidList_).c_str());
            return CAMERA_OK;
        } else {
            for (auto pid : pidList) {
                freezedPidList_.erase(pid);
            }
            MEDIA_DEBUG_LOG("after unfreeze freezedPidList_:%{public}s", g_toString(freezedPidList_).c_str());
        }
    }

    {
        std::lock_guard<std::mutex> lock(cameraCbMutex_);
        for (auto pid : pidList) {
            auto it = delayCbtaskMap.find(pid);
            if (it != delayCbtaskMap.end()) {
                it->second();
                delayCbtaskMap.erase(it);
            }
        }
    }
    return CAMERA_OK;
}

int32_t HCameraService::ResetAllFreezeStatus()
{
    if (IPCSkeleton::GetCallingUid() != 0) {
        return CAMERA_OPERATION_NOT_ALLOWED;
    }
    std::lock_guard<std::mutex> lock(freezedPidListMutex_);
    freezedPidList_.clear();
    MEDIA_INFO_LOG("freezedPidList_ has been clear");
    return CAMERA_OK;
}

int32_t HCameraService::GetDmDeviceInfo(std::vector<std::string> &deviceInfos)
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
    int size = static_cast<int>(deviceInfoList.size());
    MEDIA_INFO_LOG("HCameraService::GetDmDeviceInfo size=%{public}d", size);
    if (size > 0) {
        for (int i = 0; i < size; i++) {
            nlohmann::json deviceInfo;
            deviceInfo["deviceName"] = deviceInfoList[i].deviceName;
            deviceInfo["deviceTypeId"] = deviceInfoList[i].deviceTypeId;
            deviceInfo["networkId"] = deviceInfoList[i].networkId;
            std::string deviceInfoStr = deviceInfo.dump();
            MEDIA_INFO_LOG("HCameraService::GetDmDeviceInfo deviceInfo:%{public}s", deviceInfoStr.c_str());
            deviceInfos.emplace_back(deviceInfoStr);
        }
    }
#endif
    return CAMERA_OK;
}

int32_t HCameraService::GetCameraOutputStatus(int32_t pid, int32_t &status)
{
    sptr<HCaptureSession> captureSession = nullptr;
    captureSessionsManager_.Find(pid,  captureSession);
    if (captureSession) {
        captureSession->GetOutputStatus(status);
    } else {
        status = 0;
    }
    return CAMERA_OK;
}

std::shared_ptr<DataShare::DataShareHelper> HCameraService::CameraDataShareHelper::CreateCameraDataShareHelper()
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_ERROR_RETURN_RET_LOG(samgr == nullptr, nullptr, "CameraDataShareHelper GetSystemAbilityManager failed.");
    sptr<IRemoteObject> remoteObj = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_ERROR_RETURN_RET_LOG(remoteObj == nullptr, nullptr, "CameraDataShareHelper GetSystemAbility Service Failed.");
    return DataShare::DataShareHelper::Creator(remoteObj, SETTINGS_DATA_BASE_URI, SETTINGS_DATA_EXT_URI);
}

int32_t HCameraService::CameraDataShareHelper::QueryOnce(const std::string key, std::string &value)
{
    auto dataShareHelper = CreateCameraDataShareHelper();
    CHECK_ERROR_RETURN_RET_LOG(dataShareHelper == nullptr, CAMERA_INVALID_ARG, "dataShareHelper_ is nullptr");
    Uri uri(SETTINGS_DATA_BASE_URI);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTINGS_DATA_FIELD_KEYWORD, key);
    std::vector<std::string> columns;
    columns.emplace_back(SETTINGS_DATA_FIELD_VALUE);

    auto resultSet = dataShareHelper->Query(uri, predicates, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, CAMERA_INVALID_ARG, "CameraDataShareHelper query fail");

    int32_t numRows = 0;
    resultSet->GetRowCount(numRows);
    CHECK_AND_RETURN_RET_LOG(numRows > 0, CAMERA_INVALID_ARG, "CameraDataShareHelper query failed, row is zero.");

    if (resultSet->GoToFirstRow() != DataShare::E_OK) {
        MEDIA_INFO_LOG("CameraDataShareHelper Query failed,go to first row error");
        resultSet->Close();
        return CAMERA_INVALID_ARG;
    }

    int columnIndex;
    resultSet->GetColumnIndex(SETTINGS_DATA_FIELD_VALUE, columnIndex);
    resultSet->GetString(columnIndex, value);
    resultSet->Close();
    dataShareHelper->Release();
    MEDIA_INFO_LOG("CameraDataShareHelper query success,value=%{public}s", value.c_str());
    return CAMERA_OK;
}

int32_t HCameraService::CameraDataShareHelper::UpdateOnce(const std::string key, std::string value)
{
    auto dataShareHelper = CreateCameraDataShareHelper();
    CHECK_ERROR_RETURN_RET_LOG(dataShareHelper == nullptr, CAMERA_INVALID_ARG, "dataShareHelper_ is nullptr");
    Uri uri(SETTINGS_DATA_BASE_URI);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTINGS_DATA_FIELD_KEYWORD, key);

    DataShare::DataShareValuesBucket bucket;
    DataShare::DataShareValueObject keywordObj(key);
    DataShare::DataShareValueObject valueObj(value);
    bucket.Put(SETTINGS_DATA_FIELD_KEYWORD, keywordObj);
    bucket.Put(SETTINGS_DATA_FIELD_VALUE, valueObj);

    if (dataShareHelper->Update(uri, predicates, bucket) <= 0) {
        dataShareHelper->Insert(uri, bucket);
        MEDIA_ERR_LOG("CameraDataShareHelper Update:%{public}s failed", key.c_str());
        return CAMERA_INVALID_ARG;
    }
    MEDIA_INFO_LOG("CameraDataShareHelper Update:%{public}s success", key.c_str());
    dataShareHelper->Release();
    return CAMERA_OK;
}
} // namespace CameraStandard
} // namespace OHOS
