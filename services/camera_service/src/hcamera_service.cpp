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
#include "deferred_processing_service.h"

#include <algorithm>
#include <memory>
#include <mutex>
#include <securec.h>
#include <unordered_set>
#include <vector>

#include "access_token.h"
#include "accesstoken_kit.h"
#include "tokenid_kit.h"

#include "camera_log.h"
#include "camera_util.h"
#include "display_manager.h"
#include "hcamera_device_manager.h"
#include "ipc_skeleton.h"
#include "system_ability_definition.h"
#include "display_manager.h"
#include "os_account_manager.h"
#include "camera_report_uitls.h"

namespace OHOS {
namespace CameraStandard {
REGISTER_SYSTEM_ABILITY_BY_ID(HCameraService, CAMERA_SERVICE_ID, true)
#ifdef CAMERA_USE_SENSOR
constexpr int32_t SENSOR_SUCCESS = 0;
constexpr int32_t POSTURE_INTERVAL = 1000000;
#endif
constexpr uint8_t POSITION_FOLD_INNER = 3;
static std::mutex g_cameraServiceInstanceMutex;
static HCameraService* g_cameraServiceInstance = nullptr;
static sptr<HCameraService> g_cameraServiceHolder = nullptr;

HCameraService::HCameraService(int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate), muteMode_(false), isRegisterSensorSuccess(false)
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
}

HCameraService::HCameraService(sptr<HCameraHostManager> cameraHostManager)
    : cameraHostManager_(cameraHostManager), muteMode_(false), isRegisterSensorSuccess(false)
{}

HCameraService::~HCameraService() {}

void HCameraService::OnStart()
{
    MEDIA_INFO_LOG("HCameraService OnStart begin");
    if (cameraHostManager_->Init() != CAMERA_OK) {
        MEDIA_ERR_LOG("HCameraService OnStart failed to init camera host manager.");
    }

    // initialize deferred processing service.
    DeferredProcessing::DeferredProcessingService::GetInstance().Initialize();
    DeferredProcessing::DeferredProcessingService::GetInstance().Start();

    bool res = Publish(this);
    if (res) {
        MEDIA_INFO_LOG("HCameraService OnStart res=%{public}d", res);
    }
#ifdef CAMERA_USE_SENSOR
    RegisterSensorCallback();
#endif
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
#ifdef CAMERA_USE_SENSOR
    UnRegisterSensorCallback();
#endif
    DeferredProcessing::DeferredProcessingService::GetInstance().Stop();
}

int32_t HCameraService::GetCameras(
    vector<string>& cameraIds, vector<shared_ptr<OHOS::Camera::CameraMetadata>>& cameraAbilityList)
{
    CAMERA_SYNC_TRACE;
    isFoldable = isFoldableInit ? isFoldable : OHOS::Rosen::DisplayManager::GetInstance().IsFoldable();
    isFoldableInit = true;
    int32_t ret = cameraHostManager_->GetCameras(cameraIds);
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("HCameraService::GetCameras failed");
        return ret;
    }
    shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility;
    vector<shared_ptr<CameraMetaInfo>> cameraInfos;
    for (auto id : cameraIds) {
        ret = cameraHostManager_->GetCameraAbility(id, cameraAbility);
        if (ret != CAMERA_OK || cameraAbility == nullptr) {
            MEDIA_ERR_LOG("HCameraService::GetCameraAbility failed");
            return ret;
        }
        camera_metadata_item_t item;
        common_metadata_header_t* metadata = cameraAbility->get();
        int32_t res = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_CAMERA_POSITION, &item);
        uint8_t cameraPosition = (res == CAM_META_SUCCESS) ? item.data.u8[0] : OHOS_CAMERA_POSITION_OTHER;
        res = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_CAMERA_FOLDSCREEN_TYPE, &item);
        uint8_t foldType = (res == CAM_META_SUCCESS) ? item.data.u8[0] : OHOS_CAMERA_FOLDSCREEN_OTHER;
        if (isFoldable && cameraPosition == OHOS_CAMERA_POSITION_FRONT && foldType == OHOS_CAMERA_FOLDSCREEN_OTHER) {
            continue;
        }
        if (isFoldable && cameraPosition == OHOS_CAMERA_POSITION_FRONT && foldType == OHOS_CAMERA_FOLDSCREEN_INNER) {
            cameraPosition = POSITION_FOLD_INNER;
        }
        res = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_CAMERA_TYPE, &item);
        uint8_t cameraType = (res == CAM_META_SUCCESS) ? item.data.u8[0] : OHOS_CAMERA_TYPE_UNSPECIFIED;
        res = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_CAMERA_CONNECTION_TYPE, &item);
        uint8_t connectionType = (res == CAM_META_SUCCESS) ? item.data.u8[0] : OHOS_CAMERA_CONNECTION_TYPE_BUILTIN;
        res = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED, &item);
        bool isMirrorSupported = (res == CAM_META_SUCCESS) ?
            ((item.data.u8[0] == 1) || (item.data.u8[0] == 0)) : false;
        res = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_CAMERA_MODES, &item);
        std::vector<uint8_t> supportModes = {};
        for (uint32_t i = 0; i < item.count; i++) {
            supportModes.push_back(item.data.u8[i]);
        }
        CAMERA_SYSEVENT_STATISTIC(CreateMsg("CameraManager GetCameras camera ID:%s, Camera position:%d, "
                                            "Camera Type:%d, Connection Type:%d, Mirror support:%d",
            id.c_str(), cameraPosition, cameraType, connectionType, isMirrorSupported));
        cameraInfos.emplace_back(make_shared<CameraMetaInfo>(id, cameraType, cameraPosition,
            connectionType, supportModes, cameraAbility));
    }
    FillCameras(cameraInfos, cameraIds, cameraAbilityList);
    return ret;
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
    if (IPCSkeleton::GetCallingUid() == 0 ||
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


int32_t HCameraService::GetCameraIds(std::vector<std::string>& cameraIds)
{
    CAMERA_SYNC_TRACE;
    int32_t ret = CAMERA_OK;
    MEDIA_DEBUG_LOG("HCameraService::GetCameraIds");
    std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>> cameraAbilityList;
    ret = GetCameras(cameraIds, cameraAbilityList);
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("HCameraService::GetCameraIds failed");
    }
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
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("HCameraService::GetCameraAbility failed");
        return ret;
    }

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
                    defaultCamera->connectionType == camera->connectionType);
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

int32_t HCameraService::CreateCameraDevice(string cameraId, sptr<ICameraDeviceService>& device)
{
    CAMERA_SYNC_TRACE;
    OHOS::Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    MEDIA_INFO_LOG("HCameraService::CreateCameraDevice prepare execute, cameraId:%{public}s", cameraId.c_str());

    string permissionName = OHOS_PERMISSION_CAMERA;
    int32_t ret = CheckPermission(permissionName, callerToken);
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("HCameraService::CreateCameraDevice Check OHOS_PERMISSION_CAMERA fail %{public}d", ret);
        return ret;
    }
    // if callerToken is invalid, will not call IsAllowedUsingPermission
    if (IsValidTokenId(callerToken) &&
        !Security::AccessToken::PrivacyKit::IsAllowedUsingPermission(callerToken, permissionName)) {
        MEDIA_ERR_LOG("HCameraService::CreateCameraDevice is not allowed!");
        return CAMERA_ALLOC_ERROR;
    }

    lock_guard<mutex> lock(mapOperatorsLock_);
    sptr<HCameraDevice> cameraDevice = new (nothrow) HCameraDevice(cameraHostManager_, cameraId, callerToken);
    CHECK_AND_RETURN_RET_LOG(cameraDevice != nullptr, CAMERA_ALLOC_ERROR,
        "HCameraService::CreateCameraDevice HCameraDevice allocation failed");

    // when create camera device, update mute setting truely.
    if (IsCameraMuteSupported(cameraId)) {
        if (UpdateMuteSetting(cameraDevice, muteMode_) != CAMERA_OK) {
            MEDIA_ERR_LOG("UpdateMuteSetting Failed, cameraId: %{public}s", cameraId.c_str());
        }
    } else {
        MEDIA_ERR_LOG("HCameraService::CreateCameraDevice MuteCamera not Supported");
    }
    device = cameraDevice;
    cameraDevice->SetDeviceMuteMode(muteMode_);
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
    sptr<HCaptureSession> captureSession = new (nothrow) HCaptureSession(callerToken, opMode);
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

    if ((width == 0) || (height == 0)) {
        MEDIA_ERR_LOG("HCameraService::CreateDeferredPreviewOutput producer is null");
        return CAMERA_INVALID_ARG;
    }
    streamDeferredPreview = new (nothrow) HStreamRepeat(nullptr, format, width, height, RepeatStreamType::PREVIEW);
    CHECK_AND_RETURN_RET_LOG(streamDeferredPreview != nullptr, CAMERA_ALLOC_ERROR,
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

int32_t HCameraService::CreateMetadataOutput(
    const sptr<OHOS::IBufferProducer>& producer, int32_t format, sptr<IStreamMetadata>& metadataOutput)
{
    CAMERA_SYNC_TRACE;
    sptr<HStreamMetadata> streamMetadata;
    MEDIA_INFO_LOG("HCameraService::CreateMetadataOutput prepare execute");

    if (producer == nullptr) {
        MEDIA_ERR_LOG("HCameraService::CreateMetadataOutput producer is null");
        return CAMERA_INVALID_ARG;
    }
    streamMetadata = new (nothrow) HStreamMetadata(producer, format);
    CHECK_AND_RETURN_RET_LOG(streamMetadata != nullptr, CAMERA_ALLOC_ERROR,
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

void HCameraService::OnCameraStatus(const string& cameraId, CameraStatus status)
{
    lock_guard<mutex> lock(cbMutex_);
    MEDIA_INFO_LOG("HCameraService::OnCameraStatus "
                   "callbacks.size = %{public}zu, cameraId = %{public}s, status = %{public}d, pid = %{public}d",
        cameraServiceCallbacks_.size(), cameraId.c_str(), status, IPCSkeleton::GetCallingPid());
    for (auto it : cameraServiceCallbacks_) {
        if (it.second == nullptr) {
            MEDIA_ERR_LOG("HCameraService::OnCameraStatus cameraServiceCallback is null, pid = %{public}d",
                IPCSkeleton::GetCallingPid());
            continue;
        } else {
            it.second->OnCameraStatusChanged(cameraId, status);
        }
        CAMERA_SYSEVENT_BEHAVIOR(
            CreateMsg("OnCameraStatusChanged! for cameraId:%s, current Camera Status:%d", cameraId.c_str(), status));
    }
}

void HCameraService::OnFlashlightStatus(const string& cameraId, FlashStatus status)
{
    lock_guard<mutex> lock(cbMutex_);
    MEDIA_INFO_LOG("HCameraService::OnFlashlightStatus "
                   "callbacks.size = %{public}zu, cameraId = %{public}s, status = %{public}d, pid = %{public}d",
        cameraServiceCallbacks_.size(), cameraId.c_str(), status, IPCSkeleton::GetCallingPid());
    for (auto it : cameraServiceCallbacks_) {
        if (it.second == nullptr) {
            MEDIA_ERR_LOG("HCameraService::OnCameraStatus cameraServiceCallback is null, pid = %{public}d",
                IPCSkeleton::GetCallingPid());
            continue;
        } else {
            it.second->OnFlashlightStatusChanged(cameraId, status);
        }
    }
}

void HCameraService::OnTorchStatus(TorchStatus status)
{
    lock_guard<recursive_mutex> lock(torchCbMutex_);
    torchStatus_ = status;
    MEDIA_INFO_LOG("HCameraService::OnTorchtStatus "
                   "callbacks.size = %{public}zu,  status = %{public}d, pid = %{public}d",
        torchServiceCallbacks_.size(), status, IPCSkeleton::GetCallingPid());
    for (auto it : torchServiceCallbacks_) {
        if (it.second == nullptr) {
            MEDIA_ERR_LOG("HCameraService::OnTorchtStatus torchServiceCallback is null, pid = %{public}d",
                IPCSkeleton::GetCallingPid());
            continue;
        } else {
            it.second->OnTorchStatusChange(status);
        }
    }
}

int32_t HCameraService::SetCallback(sptr<ICameraServiceCallback>& callback)
{
    lock_guard<mutex> lock(cbMutex_);
    pid_t pid = IPCSkeleton::GetCallingPid();
    MEDIA_INFO_LOG("HCameraService::SetCallback pid = %{public}d", pid);
    if (callback == nullptr) {
        MEDIA_ERR_LOG("HCameraService::SetCallback callback is null");
        return CAMERA_INVALID_ARG;
    }
    auto callbackItem = cameraServiceCallbacks_.find(pid);
    if (callbackItem != cameraServiceCallbacks_.end()) {
        callbackItem->second = nullptr;
        (void)cameraServiceCallbacks_.erase(callbackItem);
    }
    cameraServiceCallbacks_.insert(make_pair(pid, callback));
    return CAMERA_OK;
}

int32_t HCameraService::CloseCameraForDestory(pid_t pid)
{
    sptr<HCameraDeviceManager> deviceManager = HCameraDeviceManager::GetInstance();
    sptr<HCameraDevice> deviceNeedClose = deviceManager->GetCameraByPid(pid);
    if (deviceNeedClose != nullptr) {
        deviceNeedClose->Close();
    }
    return CAMERA_OK;
}

int32_t HCameraService::UnSetMuteCallback(pid_t pid)
{
    lock_guard<mutex> lock(muteCbMutex_);
    MEDIA_INFO_LOG("HCameraService::UnSetMuteCallback pid = %{public}d, size = %{public}zu", pid,
        cameraMuteServiceCallbacks_.size());
    if (!cameraMuteServiceCallbacks_.empty()) {
        MEDIA_INFO_LOG("HCameraDevice::UnSetMuteCallback cameraMuteServiceCallbacks_ is not empty, reset it");
        auto it = cameraMuteServiceCallbacks_.find(pid);
        if ((it != cameraMuteServiceCallbacks_.end()) && (it->second)) {
            it->second = nullptr;
            cameraMuteServiceCallbacks_.erase(it);
        }
    }

    MEDIA_INFO_LOG("HCameraService::UnSetMuteCallback after erase pid = %{public}d, size = %{public}zu", pid,
        cameraMuteServiceCallbacks_.size());
    return CAMERA_OK;
}

int32_t HCameraService::UnSetCallback(pid_t pid)
{
    lock_guard<mutex> lock(cbMutex_);
    MEDIA_INFO_LOG(
        "HCameraService::UnSetCallback pid = %{public}d, size = %{public}zu", pid, cameraServiceCallbacks_.size());
    if (!cameraServiceCallbacks_.empty()) {
        MEDIA_INFO_LOG("HCameraDevice::SetStatusCallback statusSvcCallbacks_ is not empty, reset it");
        auto it = cameraServiceCallbacks_.find(pid);
        if ((it != cameraServiceCallbacks_.end()) && (it->second != nullptr)) {
            it->second = nullptr;
            cameraServiceCallbacks_.erase(it);
        }
    }
    MEDIA_INFO_LOG("HCameraService::UnSetCallback after erase pid = %{public}d, size = %{public}zu", pid,
        cameraServiceCallbacks_.size());
    int32_t ret = CAMERA_OK;
    ret = UnSetMuteCallback(pid);
    UnSetTorchCallback(pid);
    return ret;
}

int32_t HCameraService::SetMuteCallback(sptr<ICameraMuteServiceCallback>& callback)
{
    lock_guard<mutex> lock(muteCbMutex_);
    pid_t pid = IPCSkeleton::GetCallingPid();
    if (callback == nullptr) {
        MEDIA_ERR_LOG("HCameraService::SetMuteCallback callback is null");
        return CAMERA_INVALID_ARG;
    }
    cameraMuteServiceCallbacks_.insert(make_pair(pid, callback));
    return CAMERA_OK;
}

int32_t HCameraService::SetTorchCallback(sptr<ITorchServiceCallback>& callback)
{
    lock_guard<recursive_mutex> lock(torchCbMutex_);
    pid_t pid = IPCSkeleton::GetCallingPid();
    if (callback == nullptr) {
        MEDIA_ERR_LOG("HCameraService::SetTorchCallback callback is null");
        return CAMERA_INVALID_ARG;
    }
    torchServiceCallbacks_.insert(make_pair(pid, callback));

    MEDIA_INFO_LOG("HCameraService::SetTorchCallback notify pid = %{public}d", pid);
    callback->OnTorchStatusChange(torchStatus_);
    return CAMERA_OK;
}

int32_t HCameraService::UnSetTorchCallback(pid_t pid)
{
    lock_guard<recursive_mutex> lock(torchCbMutex_);
    MEDIA_INFO_LOG("HCameraService::UnSetTorchCallback pid = %{public}d, size = %{public}zu", pid,
        torchServiceCallbacks_.size());
    if (!torchServiceCallbacks_.empty()) {
        MEDIA_INFO_LOG("HCameraDevice::UnSetTorchCallback torchServiceCallbacks_ is not empty, reset it");
        auto it = torchServiceCallbacks_.find(pid);
        if ((it != torchServiceCallbacks_.end()) && (it->second)) {
            it->second = nullptr;
            torchServiceCallbacks_.erase(it);
        }
    }

    MEDIA_INFO_LOG("HCameraService::UnSetTorchCallback after erase pid = %{public}d, size = %{public}zu", pid,
        torchServiceCallbacks_.size());
    return CAMERA_OK;
}

bool HCameraService::IsCameraMuteSupported(string cameraId)
{
    bool isMuteSupported = false;
    shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility;
    int32_t ret = cameraHostManager_->GetCameraAbility(cameraId, cameraAbility);
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("HCameraService::IsCameraMuted GetCameraAbility failed");
        return false;
    }
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
    if (!status || ret != CAMERA_OK) {
        MEDIA_ERR_LOG("UpdateMuteSetting muteMode Failed");
        return CAMERA_UNKNOWN_ERROR;
    }
    return CAMERA_OK;
}

int32_t HCameraService::MuteCamera(bool muteMode)
{
    OHOS::Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t ret = CheckPermission(OHOS_PERMISSION_MANAGE_CAMERA_CONFIG, callerToken);
    CHECK_AND_RETURN_RET_LOG(ret == CAMERA_OK, ret, "CheckPermission argumentis failed!");
    CameraReportUtils::GetInstance().ReportUserBehavior(DFX_UB_MUTE_CAMERA,
        to_string(muteMode), CameraReportUtils::GetCallerInfo());
    cameraHostManager_->SetMuteMode(muteMode);
    bool oldMuteMode = muteMode_;
    if (muteMode == oldMuteMode) {
        return CAMERA_OK;
    }
    muteMode_ = muteMode;
    sptr<HCameraDeviceManager> deviceManager = HCameraDeviceManager::GetInstance();
    pid_t activeClient = deviceManager->GetActiveClient();
    if (activeClient == -1) {
        lock_guard<mutex> lock(muteCbMutex_);
        CheckCameraMute(muteMode);
        return CAMERA_OK;
    }
    sptr<HCameraDevice> activeDevice = deviceManager->GetCameraByPid(activeClient);
    if (activeDevice != nullptr) {
        string cameraId = activeDevice->GetCameraId();
        if (!IsCameraMuteSupported(cameraId)) {
            MEDIA_ERR_LOG("Not Supported Mute,cameraId: %{public}s", cameraId.c_str());
            return CAMERA_UNSUPPORTED;
        }
        if (activeDevice != nullptr) {
            ret = UpdateMuteSetting(activeDevice, muteMode);
        }
        if (ret != CAMERA_OK) {
            MEDIA_ERR_LOG("UpdateMuteSetting Failed, cameraId: %{public}s", cameraId.c_str());
            muteMode_ = oldMuteMode;
        }
    }
    lock_guard<mutex> lock(muteCbMutex_);
    if (!cameraMuteServiceCallbacks_.empty() && ret == CAMERA_OK) {
        for (auto cb : cameraMuteServiceCallbacks_) {
            if (cb.second) {
                cb.second->OnCameraMute(muteMode);
            }
            CAMERA_SYSEVENT_BEHAVIOR(CreateMsg("OnCameraMute! current Camera muteMode:%d", muteMode));
        }
    }
    if (activeDevice != nullptr) {
        activeDevice->SetDeviceMuteMode(muteMode_);
    }
    return ret;
}

void HCameraService::CheckCameraMute(bool muteMode)
{
    if (!cameraMuteServiceCallbacks_.empty()) {
        for (auto cb : cameraMuteServiceCallbacks_) {
            cb.second->OnCameraMute(muteMode);
            CAMERA_SYSEVENT_BEHAVIOR(CreateMsg("OnCameraMute! current Camera muteMode:%d", muteMode));
        }
    }
}

int32_t HCameraService::PrelaunchCamera()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HCameraService::PrelaunchCamera");
    if (HCameraDeviceManager::GetInstance()->GetCameraStateOfASide().Size() != 0) {
        MEDIA_INFO_LOG("HCameraService::PrelaunchCamera there is a device active in A side, abort!");
        return CAMERA_DEVICE_CONFLICT;
    }
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
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("HCameraService::Prelaunch failed");
    }
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
    if (cameraIds_.empty()) {
        return CAMERA_INVALID_STATE;
    }

    auto it = std::find(cameraIds_.begin(), cameraIds_.end(), cameraId);
    if (it == cameraIds_.end()) {
        return CAMERA_INVALID_ARG;
    }
    MEDIA_INFO_LOG("HCameraService::PreSwitchCamera cameraId is: %{public}s", cameraId.c_str());
    CameraReportUtils::GetInstance().SetSwitchCamPerfStartInfo(CameraReportUtils::GetCallerInfo());
    int32_t ret = cameraHostManager_->PreSwitchCamera(cameraId);
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("HCameraService::Prelaunch failed");
    }
    return ret;
}

int32_t HCameraService::SetPrelaunchConfig(string cameraId, RestoreParamTypeOhos restoreParamType, int activeTime,
    EffectParam effectParam)
{
    CAMERA_SYNC_TRACE;
    OHOS::Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    string permissionName = OHOS_PERMISSION_CAMERA;
    int32_t ret = CheckPermission(permissionName, callerToken);
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("HCameraService::SetPrelaunchConfig failed permission is: %{public}s", permissionName.c_str());
        return ret;
    }

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
    if (ret != CAMERA_OK) {
        MEDIA_DEBUG_LOG("Failed to SetTorchLevel");
    }
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
    cameraNeedEvict->OnError(DEVICE_PREEMPT, 0);
    cameraNeedEvict->Close();
    NotifyCameraState(cameraId, 0);
    canOpenCamera = true;
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
    if (callback == nullptr) {
        return CAMERA_INVALID_ARG;
    }
    HCameraDeviceManager::GetInstance()->SetPeerCallback(callback);
    return CAMERA_OK;
}

bool HCameraService::IsPrelaunchSupported(string cameraId)
{
    bool isPrelaunchSupported = false;
    shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility;
    int32_t ret = cameraHostManager_->GetCameraAbility(cameraId, cameraAbility);
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("HCameraService::IsCameraMuted GetCameraAbility failed");
        return isPrelaunchSupported;
    }
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

int32_t HCameraService::IsCameraMuted(bool& muteMode)
{
    muteMode = muteMode_;
    MEDIA_DEBUG_LOG("HCameraService::IsCameraMuted success. isMuted: %{public}d", muteMode);
    return CAMERA_OK;
}

void HCameraService::CameraSummary(vector<string> cameraIds, string& dumpString)
{
    dumpString += "# Number of Cameras:[" + to_string(cameraIds.size()) + "]:\n";
    dumpString += "# Number of Active Cameras:[" + to_string(1) + "]:\n";
    HCaptureSession::CameraSessionSummary(dumpString);
}

void HCameraService::CameraDumpCameraInfo(std::string& dumpString, std::vector<std::string>& cameraIds,
    std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>>& cameraAbilityList)
{
    int32_t capIdx = 0;
    for (auto& it : cameraIds) {
        auto metadata = cameraAbilityList[capIdx++];
        common_metadata_header_t* metadataEntry = metadata->get();
        dumpString += "# Camera ID:[" + it + "]: \n";
        CameraDumpAbility(metadataEntry, dumpString);
        CameraDumpStreaminfo(metadataEntry, dumpString);
        CameraDumpZoom(metadataEntry, dumpString);
        CameraDumpFlash(metadataEntry, dumpString);
        CameraDumpAF(metadataEntry, dumpString);
        CameraDumpAE(metadataEntry, dumpString);
        CameraDumpSensorInfo(metadataEntry, dumpString);
        CameraDumpVideoStabilization(metadataEntry, dumpString);
        CameraDumpVideoFrameRateRange(metadataEntry, dumpString);
        CameraDumpPrelaunch(metadataEntry, dumpString);
        CameraDumpThumbnail(metadataEntry, dumpString);
    }
}

void HCameraService::CameraDumpAbility(common_metadata_header_t* metadataEntry, string& dumpString)
{
    camera_metadata_item_t item;
    int ret;
    dumpString += "    ## Camera Ability List: \n";

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_CAMERA_POSITION, &item);
    if (ret == CAM_META_SUCCESS) {
        map<int, string>::const_iterator iter =
            g_cameraPos.find(item.data.u8[0]);
        if (iter != g_cameraPos.end()) {
            dumpString += "        Camera Position:["
                + iter->second
                + "]:    ";
        }
    }

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_CAMERA_TYPE, &item);
    if (ret == CAM_META_SUCCESS) {
        map<int, string>::const_iterator iter =
            g_cameraType.find(item.data.u8[0]);
        if (iter != g_cameraType.end()) {
            dumpString += "Camera Type:["
                + iter->second
                + "]:    ";
        }
    }

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_CAMERA_CONNECTION_TYPE, &item);
    if (ret == CAM_META_SUCCESS) {
        map<int, string>::const_iterator iter =
            g_cameraConType.find(item.data.u8[0]);
        if (iter != g_cameraConType.end()) {
            dumpString += "Camera Connection Type:["
                + iter->second
                + "]:\n";
        }
    }
}

void HCameraService::CameraDumpStreaminfo(common_metadata_header_t* metadataEntry, string& dumpString)
{
    camera_metadata_item_t item;
    int ret;
    constexpr uint32_t unitLen = 3;
    uint32_t widthOffset = 1;
    uint32_t heightOffset = 2;
    dumpString += "        ### Camera Available stream configuration List: \n";
    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry,
                                               OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS, &item);
    if (ret == CAM_META_SUCCESS) {
        dumpString += "            Number Stream Info: "
            + to_string(item.count/unitLen) + "\n";
        for (uint32_t index = 0; index < item.count; index += unitLen) {
            map<int, string>::const_iterator iter =
                g_cameraFormat.find(item.data.i32[index]);
            if (iter != g_cameraFormat.end()) {
                dumpString += "            Format:["
                        + iter->second
                        + "]:    ";
                dumpString += "Size:[Width:"
                        + to_string(item.data.i32[index + widthOffset])
                        + " Height:"
                        + to_string(item.data.i32[index + heightOffset])
                        + "]:\n";
            }
        }
    }
}

void HCameraService::CameraDumpZoom(common_metadata_header_t* metadataEntry, string& dumpString)
{
    dumpString += "    ## Zoom Related Info: \n";
    camera_metadata_item_t item;
    int ret;
    int32_t minIndex = 0;
    int32_t maxIndex = 1;
    uint32_t zoomRangeCount = 2;
    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_ZOOM_CAP, &item);
    if ((ret == CAM_META_SUCCESS) && (item.count == zoomRangeCount)) {
        dumpString += "        Available Zoom Capability:["
            + to_string(item.data.i32[minIndex]) + "  "
            + to_string(item.data.i32[maxIndex])
            + "]:\n";
    }

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_SCENE_ZOOM_CAP, &item);
    if ((ret == CAM_META_SUCCESS) && (item.count == zoomRangeCount)) {
        dumpString += "        Available scene Zoom Capability:["
            + to_string(item.data.i32[minIndex]) + "  "
            + to_string(item.data.i32[maxIndex])
            + "]:\n";
    }

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_ZOOM_RATIO_RANGE, &item);
    if ((ret == CAM_META_SUCCESS) && (item.count == zoomRangeCount)) {
        dumpString += "        Available Zoom Ratio Range:["
            + to_string(item.data.f[minIndex])
            + to_string(item.data.f[maxIndex])
            + "]:\n";
    }

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_CONTROL_ZOOM_RATIO, &item);
    if (ret == CAM_META_SUCCESS) {
        dumpString += "        Set Zoom Ratio:["
            + to_string(item.data.f[0])
            + "]:\n";
    }
}

void HCameraService::CameraDumpFlash(common_metadata_header_t* metadataEntry, string& dumpString)
{
    camera_metadata_item_t item;
    int ret;
    dumpString += "    ## Flash Related Info: \n";
    dumpString += "        Available Flash Modes:[";
    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_FLASH_MODES, &item);
    if (ret == CAM_META_SUCCESS) {
        for (uint32_t i = 0; i < item.count; i++) {
            map<int, string>::const_iterator iter =
                g_cameraFlashMode.find(item.data.u8[i]);
            if (iter != g_cameraFlashMode.end()) {
                dumpString += " " + iter->second;
            }
        }
        dumpString += "]:\n";
    }

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_CONTROL_FLASH_MODE, &item);
    if (ret == CAM_META_SUCCESS) {
        map<int, string>::const_iterator iter =
            g_cameraFlashMode.find(item.data.u8[0]);
        if (iter != g_cameraFlashMode.end()) {
            dumpString += "        Set Flash Mode:["
                + iter->second
                + "]:\n";
        }
    }
}

void HCameraService::CameraDumpAF(common_metadata_header_t* metadataEntry, string& dumpString)
{
    camera_metadata_item_t item;
    int ret;
    dumpString += "    ## AF Related Info: \n";
    dumpString += "        Available Focus Modes:[";

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_FOCUS_MODES, &item);
    if (ret == CAM_META_SUCCESS) {
        for (uint32_t i = 0; i < item.count; i++) {
            map<int, string>::const_iterator iter =
                g_cameraFocusMode.find(item.data.u8[i]);
            if (iter != g_cameraFocusMode.end()) {
                dumpString += " " + iter->second;
            }
        }
        dumpString += "]:\n";
    }

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_CONTROL_FOCUS_MODE, &item);
    if (ret == CAM_META_SUCCESS) {
        map<int, string>::const_iterator iter =
            g_cameraFocusMode.find(item.data.u8[0]);
        if (iter != g_cameraFocusMode.end()) {
            dumpString += "        Set Focus Mode:["
                + iter->second
                + "]:\n";
        }
    }
}

void HCameraService::CameraDumpAE(common_metadata_header_t* metadataEntry, string& dumpString)
{
    camera_metadata_item_t item;
    int ret;
    dumpString += "    ## AE Related Info: \n";
    dumpString += "        Available Exposure Modes:[";

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_EXPOSURE_MODES, &item);
    if (ret == CAM_META_SUCCESS) {
        for (uint32_t i = 0; i < item.count; i++) {
            map<int, string>::const_iterator iter =
                g_cameraExposureMode.find(item.data.u8[i]);
            if (iter != g_cameraExposureMode.end()) {
                dumpString += " " + iter->second;
            }
        }
        dumpString += "]:\n";
    }

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_CONTROL_EXPOSURE_MODE, &item);
    if (ret == CAM_META_SUCCESS) {
        map<int, string>::const_iterator iter =
            g_cameraExposureMode.find(item.data.u8[0]);
        if (iter != g_cameraExposureMode.end()) {
            dumpString += "        Set exposure Mode:["
                + iter->second
                + "]:\n";
        }
    }
}

void HCameraService::CameraDumpSensorInfo(common_metadata_header_t* metadataEntry, string& dumpString)
{
    camera_metadata_item_t item;
    int ret;
    dumpString += "    ## Sensor Info Info: \n";
    int32_t leftIndex = 0;
    int32_t topIndex = 1;
    int32_t rightIndex = 2;
    int32_t bottomIndex = 3;
    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_SENSOR_INFO_ACTIVE_ARRAY_SIZE, &item);
    if (ret == CAM_META_SUCCESS) {
        dumpString += "        Array:["
            + to_string(item.data.i32[leftIndex]) + " "
            + to_string(item.data.i32[topIndex]) + " "
            + to_string(item.data.i32[rightIndex]) + " "
            + to_string(item.data.i32[bottomIndex])
            + "]:\n";
    }
}

void HCameraService::CameraDumpVideoStabilization(common_metadata_header_t* metadataEntry, string& dumpString)
{
    camera_metadata_item_t item;
    int ret;
    dumpString += "    ## Video Stabilization Related Info: \n";
    dumpString += "        Available Video Stabilization Modes:[";

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_VIDEO_STABILIZATION_MODES, &item);
    if (ret == CAM_META_SUCCESS) {
        for (uint32_t i = 0; i < item.count; i++) {
            map<int, string>::const_iterator iter =
                g_cameraVideoStabilizationMode.find(item.data.u8[i]);
            if (iter != g_cameraVideoStabilizationMode.end()) {
                dumpString += " " + iter->second;
            }
        }
        dumpString += "]:\n";
    }

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &item);
    if (ret == CAM_META_SUCCESS) {
        map<int, string>::const_iterator iter =
            g_cameraVideoStabilizationMode.find(item.data.u8[0]);
        if (iter != g_cameraVideoStabilizationMode.end()) {
            dumpString += "        Set Stabilization Mode:["
                + iter->second
                + "]:\n";
        }
    }
}

void HCameraService::CameraDumpVideoFrameRateRange(common_metadata_header_t* metadataEntry, string& dumpString)
{
    camera_metadata_item_t item;
    const int32_t FRAME_RATE_RANGE_STEP = 2;
    int ret;
    dumpString += "    ## Video FrameRateRange Related Info: \n";
    dumpString += "        Available FrameRateRange :\n";

    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_FPS_RANGES, &item);
    if (ret == CAM_META_SUCCESS) {
        for (uint32_t i = 0; i < (item.count - 1); i += FRAME_RATE_RANGE_STEP) {
            dumpString += "            [ " + to_string(item.data.i32[i]) + ", " +
                          to_string(item.data.i32[i+1]) + " ]\n";
        }
        dumpString += "\n";
    }
}

void HCameraService::CameraDumpPrelaunch(common_metadata_header_t* metadataEntry, string& dumpString)
{
    camera_metadata_item_t item;
    int ret;
    dumpString += "    ## Camera Prelaunch Related Info: \n";
    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_PRELAUNCH_AVAILABLE, &item);
    if (ret == CAM_META_SUCCESS) {
        map<int, string>::const_iterator iter =
            g_cameraPrelaunchAvailable.find(item.data.u8[0]);
        if (iter != g_cameraPrelaunchAvailable.end()) {
            dumpString += "        Available Prelaunch Info:["
                + iter->second
                + "]:\n";
        }
    }
}

void HCameraService::CameraDumpThumbnail(common_metadata_header_t* metadataEntry, string& dumpString)
{
    camera_metadata_item_t item;
    int ret;
    dumpString += "    ## Camera Thumbnail Related Info: \n";
    ret = OHOS::Camera::FindCameraMetadataItem(metadataEntry, OHOS_ABILITY_STREAM_QUICK_THUMBNAIL_AVAILABLE, &item);
    if (ret == CAM_META_SUCCESS) {
        map<int, string>::const_iterator iter =
            g_cameraQuickThumbnailAvailable.find(item.data.u8[0]);
        if (iter != g_cameraQuickThumbnailAvailable.end()) {
            dumpString += "        Available Thumbnail Info:["
                + iter->second
                + "]:\n";
        }
    }
}

int32_t HCameraService::Dump(int fd, const vector<u16string>& args)
{
    unordered_set<u16string> argSets;
    u16string summary(u"summary");
    u16string ability(u"ability");
    u16string clientwiseinfo(u"clientwiseinfo");
    std::u16string debugOn(u"debugOn");
    for (decltype(args.size()) index = 0; index < args.size(); ++index) {
        argSets.insert(args[index]);
    }
    std::string dumpString;
    std::vector<std::string> cameraIds;
    std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>> cameraAbilityList;
    int ret;

    ret = GetCameras(cameraIds, cameraAbilityList);
    if ((ret != CAMERA_OK) || cameraIds.empty() || (cameraAbilityList.empty())) {
        return CAMERA_INVALID_STATE;
    }
    if (args.size() == 0 || argSets.count(summary) != 0) {
        dumpString += "-------- Summary -------\n";
        CameraSummary(cameraIds, dumpString);
    }
    if (args.size() == 0 || argSets.count(ability) != 0) {
        dumpString += "-------- CameraDevice -------\n";
        CameraDumpCameraInfo(dumpString, cameraIds, cameraAbilityList);
    }
    if (args.size() == 0 || argSets.count(clientwiseinfo) != 0) {
        dumpString += "-------- Clientwise Info -------\n";
        HCaptureSession::dumpSessions(dumpString);
    }
    if (argSets.count(debugOn) != 0) {
        dumpString += "-------- Debug On -------\n";
        SetCameraDebugValue(true);
    }

    if (dumpString.size() == 0) {
        MEDIA_ERR_LOG("Dump string empty!");
        return CAMERA_INVALID_STATE;
    }

    (void)write(fd, dumpString.c_str(), dumpString.size());
    return CAMERA_OK;
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
    if (event == nullptr) {
        MEDIA_INFO_LOG("SensorEvent is nullptr.");
        return;
    }
    if (event[0].data == nullptr) {
        MEDIA_INFO_LOG("SensorEvent[0].data is nullptr.");
        return;
    }
    if (event[0].dataLen < sizeof(DropDetectionData)) {
        MEDIA_INFO_LOG("less than drop detection data size, event.dataLen:%{public}u", event[0].dataLen);
        return;
    }
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
    if (captureSession == nullptr) {
        cameraHostManager_->SaveRestoreParam(cameraRestoreParam);
        return rc;
    }

    sptr<HCameraDeviceManager> deviceManager = HCameraDeviceManager::GetInstance();
    pid_t activeClient = deviceManager->GetActiveClient();
    if (activeClient == -1) {
        MEDIA_ERR_LOG("HCaptureSession::SaveCurrentParamForRestore() Failed to save param");
        return CAMERA_OPERATION_NOT_ALLOWED;
    }
    sptr<HCameraDevice> activeDevice = deviceManager->GetCameraByPid(activeClient);
    if (activeDevice == nullptr) {
        return CAMERA_OK;
    }

    std::vector<StreamInfo_V1_1> allStreamInfos;

    if (activeDevice != nullptr) {
        std::shared_ptr<OHOS::Camera::CameraMetadata> defaultSettings = CreateDefaultSettingForRestore(activeDevice);
        UpdateSkinSmoothSetting(defaultSettings, effectParam.skinSmoothLevel);
        UpdateFaceSlenderSetting(defaultSettings, effectParam.faceSlender);
        UpdateSkinToneSetting(defaultSettings, effectParam.skinTone);
        cameraRestoreParam->SetSetting(defaultSettings);
    }
    if (activeDevice == nullptr) {
        return CAMERA_UNKNOWN_ERROR;
    }
    MEDIA_DEBUG_LOG("HCameraService::SaveCurrentParamForRestore param %{public}d", effectParam.skinSmoothLevel);
    rc = captureSession->GetCurrentStreamInfos(allStreamInfos);
    if (rc != CAMERA_OK) {
        MEDIA_ERR_LOG("HCaptureSession::SaveCurrentParamForRestore() Failed to get streams info, %{public}d", rc);
        return rc;
    }
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
    std::shared_ptr<OHOS::Camera::CameraMetadata> currentSetting = activeDevice->CloneCachedSettings();
    if (currentSetting == nullptr) {
        MEDIA_ERR_LOG("HCameraService::CreateDefaultSettingForRestore:currentSetting is null");
        return defaultSettings;
    }
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
} // namespace CameraStandard
} // namespace OHOS
