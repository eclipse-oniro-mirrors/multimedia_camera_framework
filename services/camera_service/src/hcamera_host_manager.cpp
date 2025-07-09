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

#include "hcamera_host_manager.h"

#include "camera_report_uitls.h"
#include "camera_util.h"
#include "display_manager.h"
#include "hcamera_device.h"
#include "icamera_service_callback.h"
#include "ipc_skeleton.h"
#include "iproxy_broker.h"
#include "metadata_utils.h"
#include "os_account_manager.h"
#include "v1_2/icamera_host_callback.h"
#include <cstddef>
#include <cstdint>
#include <iterator>
#include "rotate_plugin/camera_rotate_plugin.h"
#include "camera_fwk_metadata_utils.h"
#include "camera_simple_timer.h"

namespace OHOS {
namespace CameraStandard {

const std::string HCameraHostManager::LOCAL_SERVICE_NAME = "camera_service";
const std::string HCameraHostManager::DISTRIBUTED_SERVICE_NAME = "distributed_camera_provider_service";
constexpr uint32_t MILLISEC_TIME = 1000;
constexpr int32_t MAX_SYS_UID = 10000;
std::shared_ptr<SimpleTimer> closeTimer_;

using namespace OHOS::HDI::Camera::V1_0;
struct HCameraHostManager::CameraDeviceInfo {
    std::string cameraId;
    std::shared_ptr<OHOS::Camera::CameraMetadata> ability;
    std::mutex mutex;

    explicit CameraDeviceInfo(const std::string& cameraId, sptr<ICameraDevice> device = nullptr)
        : cameraId(cameraId), ability(nullptr)
    {
    }

    ~CameraDeviceInfo() = default;
};

class HCameraHostManager::CameraHostInfo : public OHOS::HDI::Camera::V1_2::ICameraHostCallback {
public:
    class CameraHostDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit CameraHostDeathRecipient(const sptr<HCameraHostManager::CameraHostInfo> &hostInfo)
            : cameraHostInfo_(hostInfo)
        {
        }
        virtual ~CameraHostDeathRecipient() = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override
        {
            MEDIA_ERR_LOG("Remote died, do clean works.");
            auto cameraHostInfo = cameraHostInfo_.promote();
            CHECK_RETURN(cameraHostInfo == nullptr);
            cameraHostInfo->NotifyCameraHostDied();
            cameraHostInfo->CameraHostDied();
        }

    private:
        wptr<HCameraHostManager::CameraHostInfo> cameraHostInfo_;
    };

    explicit CameraHostInfo(std::shared_ptr<StatusCallback> statusCallback,
        std::shared_ptr<CameraHostDeadCallback> cameraHostDeadCallback, std::string name)
        : statusCallback_(statusCallback), cameraHostDeadCallback_(cameraHostDeadCallback), name_(std::move(name)),
          majorVer_(0), minorVer_(0), cameraHostProxy_(nullptr) {};
    ~CameraHostInfo();
    bool Init();
    void CameraHostDied();
    bool IsCameraSupported(const std::string& cameraId);
    const std::string& GetName();
    int32_t GetCameraHostVersion();
    int32_t GetCameras(std::vector<std::string>& cameraIds);
    int32_t GetCameraAbility(const std::string& cameraId, std::shared_ptr<OHOS::Camera::CameraMetadata>& ability);
    int32_t OpenCamera(std::string& cameraId, const sptr<ICameraDeviceCallback>& callback,
                       sptr<OHOS::HDI::Camera::V1_0::ICameraDevice>& pDevice, bool isEnableSecCam = false);
    int32_t SetFlashlight(const std::string& cameraId, bool isEnable);
    int32_t SetTorchLevel(float level);
    int32_t Prelaunch(sptr<HCameraRestoreParam> cameraRestoreParam, bool muteMode);
    int32_t PreCameraSwitch(const std::string& cameraId);
    bool IsNeedRestore(int32_t opMode,
        std::shared_ptr<OHOS::Camera::CameraMetadata> cameraSettings, std::string& cameraId);
    void NotifyDeviceStateChangeInfo(int notifyType, int deviceState);
    bool CheckUserHasChanged(std::shared_ptr<OHOS::Camera::CameraMetadata> cameraSettings);

    int32_t GetCameraResourceCost(const std::string& cameraId,
        OHOS::HDI::Camera::V1_3::CameraDeviceResourceCost& resourceCost);
    void GetCameraStorageSize(const int& userId, int64_t& storageSize);

    // CameraHostCallbackStub
    int32_t OnCameraStatus(const std::string& cameraId, HDI::Camera::V1_0::CameraStatus status) override;
    int32_t OnFlashlightStatus(const std::string& cameraId, FlashlightStatus status) override;
    int32_t OnFlashlightStatus_V1_2(FlashlightStatus status) override;
    int32_t OnCameraEvent(const std::string &cameraId, CameraEvent event) override;

private:
    std::shared_ptr<CameraDeviceInfo> FindCameraDeviceInfo(const std::string& cameraId);
    void NotifyCameraHostDied();
    void AddDevice(const std::string& cameraId);
    void RemoveDevice(const std::string& cameraId);
    void Cast2MultiVersionCameraHost();
    void UpdateMuteSetting(std::shared_ptr<OHOS::Camera::CameraMetadata> setting);

    std::weak_ptr<StatusCallback> statusCallback_;
    std::weak_ptr<CameraHostDeadCallback> cameraHostDeadCallback_;
    std::string name_;
    uint32_t majorVer_;
    uint32_t minorVer_;
    sptr<OHOS::HDI::Camera::V1_0::ICameraHost> cameraHostProxy_;
    sptr<OHOS::HDI::Camera::V1_1::ICameraHost> cameraHostProxyV1_1_;
    sptr<OHOS::HDI::Camera::V1_2::ICameraHost> cameraHostProxyV1_2_;
    sptr<OHOS::HDI::Camera::V1_3::ICameraHost> cameraHostProxyV1_3_;

    sptr<CameraHostDeathRecipient> cameraHostDeathRecipient_ = nullptr;

    std::mutex mutex_;
    std::vector<std::string> cameraIds_;
    std::vector<std::shared_ptr<CameraDeviceInfo>> devices_;
};

HCameraHostManager::CameraHostInfo::~CameraHostInfo()
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_INFO_LOG("CameraHostInfo ~CameraHostInfo");
    if (cameraHostProxy_ && cameraHostDeathRecipient_) {
        const sptr<IRemoteObject>& remote = OHOS::HDI::hdi_objcast<ICameraHost>(cameraHostProxy_);
        remote->RemoveDeathRecipient(cameraHostDeathRecipient_);
        cameraHostDeathRecipient_ = nullptr;
    }
    cameraHostProxy_ = nullptr;
    cameraHostProxyV1_1_ = nullptr;
    cameraHostProxyV1_2_ = nullptr;
    cameraHostProxyV1_3_ = nullptr;
    for (unsigned i = 0; i < devices_.size(); i++) {
        devices_.at(i) = nullptr;
    }
    cameraIds_.clear();
    devices_.clear();
}

void HCameraHostManager::CameraHostInfo::Cast2MultiVersionCameraHost()
{
    cameraHostProxy_->GetVersion(majorVer_, minorVer_);
    MEDIA_INFO_LOG("CameraHostInfo::Init cameraHostProxy_version %{public}u _ %{public}u", majorVer_, minorVer_);
    if (GetCameraHostVersion() > OHOS::CameraStandard::GetVersionId(HDI_VERSION_1, HDI_VERSION_2)) {
        MEDIA_DEBUG_LOG("CameraHostInfo::Init ICameraHost cast to V1_3");
        auto castResult_V1_3 = OHOS::HDI::Camera::V1_3::ICameraHost::CastFrom(cameraHostProxy_);
        if (castResult_V1_3 != nullptr) {
            cameraHostProxyV1_3_ = castResult_V1_3;
        }
    }
    if (GetCameraHostVersion() > OHOS::CameraStandard::GetVersionId(1, 1)) {
        MEDIA_DEBUG_LOG("CameraHostInfo::Init ICameraHost cast to V1_2");
        auto castResult_V1_2 = OHOS::HDI::Camera::V1_2::ICameraHost::CastFrom(cameraHostProxy_);
        if (castResult_V1_2 != nullptr) {
            cameraHostProxyV1_2_ = castResult_V1_2;
        }
    }
    if (GetCameraHostVersion() > OHOS::CameraStandard::GetVersionId(1, 0)) {
        MEDIA_DEBUG_LOG("CameraHostInfo::Init ICameraHost cast to V1_1");
        auto castResult_V1_1 = OHOS::HDI::Camera::V1_1::ICameraHost::CastFrom(cameraHostProxy_);
        if (castResult_V1_1 != nullptr) {
            cameraHostProxyV1_1_ = castResult_V1_1;
        }
    }
}

bool HCameraHostManager::CameraHostInfo::Init()
{
    CHECK_RETURN_RET_ELOG(cameraHostProxy_ != nullptr, true, "CameraHostInfo::Init, no camera host proxy");
    cameraHostProxy_ = OHOS::HDI::Camera::V1_0::ICameraHost::Get(name_.c_str(), false);
    CHECK_RETURN_RET_ELOG(cameraHostProxy_ == nullptr, false, "Failed to get ICameraHost");
    Cast2MultiVersionCameraHost();

    if (cameraHostProxyV1_3_ != nullptr && GetCameraHostVersion() >=
        OHOS::CameraStandard::GetVersionId(HDI_VERSION_1, HDI_VERSION_3)) {
        MEDIA_DEBUG_LOG("CameraHostInfo::Init SetCallback ICameraHost V1_3");
        cameraHostProxyV1_3_->SetCallback_V1_2(this);
        // LCOV_EXCL_START
    } else if (cameraHostProxyV1_2_ != nullptr &&
        GetCameraHostVersion() >= OHOS::CameraStandard::GetVersionId(HDI_VERSION_1, HDI_VERSION_2)) {
        MEDIA_DEBUG_LOG("CameraHostInfo::Init SetCallback ICameraHost V1_2");
        cameraHostProxyV1_2_->SetCallback_V1_2(this);
    } else {
        MEDIA_DEBUG_LOG("CameraHostInfo::Init SetCallback ICameraHost V1_0");
        cameraHostProxy_->SetCallback(this);
        // LCOV_EXCL_STOP
    }
    cameraHostDeathRecipient_ = new CameraHostDeathRecipient(this);
    const sptr<IRemoteObject> &remote = OHOS::HDI::hdi_objcast<ICameraHost>(cameraHostProxy_);
    CHECK_PRINT_ELOG(!remote->AddDeathRecipient(cameraHostDeathRecipient_),
        "AddDeathRecipient for CameraHost failed.");
    std::lock_guard<std::mutex> lock(mutex_);
    CamRetCode ret = (CamRetCode)(cameraHostProxy_->GetCameraIds(cameraIds_));
    if (ret != HDI::Camera::V1_0::NO_ERROR) {
        MEDIA_ERR_LOG("Init, GetCameraIds failed, ret = %{public}d", ret);
        CameraReportUtils::ReportCameraError(
            "CameraHostInfo::Init", ret, true, CameraReportUtils::GetCallerInfo());
        return false;
    }
    for (const auto& cameraId : cameraIds_) {
        devices_.push_back(std::make_shared<HCameraHostManager::CameraDeviceInfo>(cameraId));
    }
    return true;
}

void HCameraHostManager::CameraHostInfo::CameraHostDied()
{
    auto hostDeadCallback = cameraHostDeadCallback_.lock();
    CHECK_RETURN_ELOG(hostDeadCallback == nullptr,
        "%{public}s CameraHostDied but hostDeadCallback is null.", name_.c_str());
    hostDeadCallback->OnCameraHostDied(name_);
}

bool HCameraHostManager::CameraHostInfo::IsCameraSupported(const std::string& cameraId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    return std::any_of(cameraIds_.begin(), cameraIds_.end(),
                       [&cameraId](const auto& camId) { return camId == cameraId; });
}

const std::string& HCameraHostManager::CameraHostInfo::GetName()
{
    return name_;
}

int32_t HCameraHostManager::CameraHostInfo::GetCameraHostVersion()
{
    MEDIA_DEBUG_LOG("cameraHostProxy_ GetVersion majorVer_: %{public}u, minorVers_: %{public}u", majorVer_, minorVer_);
    return OHOS::CameraStandard::GetVersionId(majorVer_, minorVer_);
}

int32_t HCameraHostManager::CameraHostInfo::GetCameras(std::vector<std::string>& cameraIds)
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto id : cameraIds_) {
        MEDIA_INFO_LOG("CameraHostInfo::GetCameras, current camera %{public}s", id.c_str());
    }
    cameraIds.insert(cameraIds.end(), cameraIds_.begin(), cameraIds_.end());
    return CAMERA_OK;
}

int32_t HCameraHostManager::CameraHostInfo::GetCameraAbility(const std::string& cameraId,
    std::shared_ptr<OHOS::Camera::CameraMetadata>& ability)
{
    auto deviceInfo = FindCameraDeviceInfo(cameraId);
    CHECK_RETURN_RET_ELOG(deviceInfo == nullptr, CAMERA_UNKNOWN_ERROR,
        "CameraHostInfo::GetCameraAbility deviceInfo is null");
    std::lock_guard<std::mutex> lock(deviceInfo->mutex);
    if (deviceInfo->ability) {
        ability = deviceInfo->ability;
    } else {
        CHECK_RETURN_RET_ELOG(cameraHostProxy_ == nullptr, CAMERA_UNKNOWN_ERROR,
            "CameraHostInfo::GetCameraAbility cameraHostProxy_ is null");
        if (!deviceInfo->ability) {
            std::vector<uint8_t> cameraAbility;
            CamRetCode rc = (CamRetCode)(cameraHostProxy_->GetCameraAbility(cameraId, cameraAbility));
            if (rc != HDI::Camera::V1_0::NO_ERROR) {
                MEDIA_ERR_LOG("CameraHostInfo::GetCameraAbility failed with error Code:%{public}d", rc);
                CameraReportUtils::ReportCameraError(
                    "CameraHostInfo::GetCameraAbility", rc, true, CameraReportUtils::GetCallerInfo());
                return HdiToServiceError(rc);
            }
            OHOS::Camera::MetadataUtils::ConvertVecToMetadata(cameraAbility, ability);
            if (ability == nullptr) {
                ability = std::make_shared<OHOS::Camera::CameraMetadata>(0, 0);
            }
            deviceInfo->ability = ability;
        }
    }
#ifdef HOOK_CAMERA_OPERATOR
    if (!CameraRotatePlugin::GetInstance()->HookCameraAbility(cameraId, ability)) {
        MEDIA_DEBUG_LOG("CameraHostInfo::HookCameraAbility failed ");
    }
#endif
    return CAMERA_OK;
}

int32_t HCameraHostManager::CameraHostInfo::OpenCamera(std::string& cameraId,
    const sptr<ICameraDeviceCallback>& callback,
    sptr<OHOS::HDI::Camera::V1_0::ICameraDevice>& pDevice,
    bool isEnableSecCam)
{
    MEDIA_INFO_LOG("CameraHostInfo::OpenCamera %{public}s", cameraId.c_str());
    auto deviceInfo = FindCameraDeviceInfo(cameraId);
    CHECK_RETURN_RET_ELOG(deviceInfo == nullptr, CAMERA_UNKNOWN_ERROR,
        "CameraHostInfo::GetCameraAbility deviceInfo is null");
    std::lock_guard<std::mutex> lock(deviceInfo->mutex);
    CHECK_RETURN_RET_ELOG(cameraHostProxy_ == nullptr, CAMERA_UNKNOWN_ERROR,
        "CameraHostInfo::OpenCamera cameraHostProxy_ is null");
    CamRetCode rc;
    // try to get higher version
    sptr<OHOS::HDI::Camera::V1_1::ICameraDevice> hdiDevice_v1_1;
    sptr<OHOS::HDI::Camera::V1_2::ICameraDevice> hdiDevice_v1_2;
    sptr<OHOS::HDI::Camera::V1_3::ICameraDevice> hdiDevice_v1_3;
    // LCOV_EXCL_START
    if (cameraHostProxyV1_3_ != nullptr && GetCameraHostVersion() >=
        OHOS::CameraStandard::GetVersionId(HDI_VERSION_1, HDI_VERSION_3)) {
        MEDIA_DEBUG_LOG("CameraHostInfo::OpenCamera ICameraDevice V1_3");
        if (isEnableSecCam) {
            MEDIA_INFO_LOG("CameraHostInfo::OpenCamera OpenSecureCamera");
            rc = (CamRetCode)(cameraHostProxyV1_3_->OpenSecureCamera(cameraId, callback, hdiDevice_v1_3));
        } else {
            rc = (CamRetCode)(cameraHostProxyV1_3_->OpenCamera_V1_3(cameraId, callback, hdiDevice_v1_3));
        }
        pDevice = hdiDevice_v1_3.GetRefPtr();
    } else if (cameraHostProxyV1_2_ != nullptr && GetCameraHostVersion() >=
        OHOS::CameraStandard::GetVersionId(HDI_VERSION_1, HDI_VERSION_2)) {
        MEDIA_DEBUG_LOG("CameraHostInfo::OpenCamera ICameraDevice V1_2");
        rc = (CamRetCode)(cameraHostProxyV1_2_->OpenCamera_V1_2(cameraId, callback, hdiDevice_v1_2));
        pDevice = hdiDevice_v1_2.GetRefPtr();
    } else if (cameraHostProxyV1_1_ != nullptr
        && GetCameraHostVersion() == OHOS::CameraStandard::GetVersionId(HDI_VERSION_1, HDI_VERSION_1)) {
        MEDIA_DEBUG_LOG("CameraHostInfo::OpenCamera ICameraDevice V1_1");
        rc = (CamRetCode)(cameraHostProxyV1_1_->OpenCamera_V1_1(cameraId, callback, hdiDevice_v1_1));
        pDevice = hdiDevice_v1_1.GetRefPtr();
    } else {
        MEDIA_DEBUG_LOG("CameraHostInfo::OpenCamera ICameraDevice V1_0");
        rc = (CamRetCode)(cameraHostProxy_->OpenCamera(cameraId, callback, pDevice));
    }
    // LCOV_EXCL_STOP
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        MEDIA_ERR_LOG("CameraHostInfo::OpenCamera failed with error Code:%{public}d", rc);
        CameraReportUtils::ReportCameraError(
            "CameraHostInfo::OpenCamera", rc, true, CameraReportUtils::GetCallerInfo());
        pDevice = nullptr;
        return HdiToServiceError(rc);
    }
    return CAMERA_OK;
}

int32_t HCameraHostManager::CameraHostInfo::SetFlashlight(const std::string& cameraId, bool isEnable)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_RETURN_RET_ELOG(cameraHostProxy_ == nullptr, CAMERA_UNKNOWN_ERROR,
        "CameraHostInfo::SetFlashlight cameraHostProxy_ is null");
    CamRetCode rc = (CamRetCode)(cameraHostProxy_->SetFlashlight(cameraId, isEnable));
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        MEDIA_ERR_LOG("CameraHostInfo::SetFlashlight failed with error Code:%{public}d", rc);
        CameraReportUtils::ReportCameraError(
            "CameraHostInfo::SetFlashlight", rc, true, CameraReportUtils::GetCallerInfo());
        return HdiToServiceError(rc);
    }
    return CAMERA_OK;
}

int32_t HCameraHostManager::CameraHostInfo::SetTorchLevel(float level)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_RETURN_RET_ELOG(cameraHostProxyV1_2_ == nullptr, CAMERA_UNKNOWN_ERROR,
        "CameraHostInfo::SetTorchLevel cameraHostProxyV1_2_ is null");
    HDI::Camera::V1_2::CamRetCode rc = (HDI::Camera::V1_2::CamRetCode)(cameraHostProxyV1_2_->SetFlashlight_V1_2(level));
    if (rc != HDI::Camera::V1_2::NO_ERROR) {
        MEDIA_ERR_LOG("CameraHostInfo::SetTorchLevel failed with error Code:%{public}d", rc);
        CameraReportUtils::ReportCameraError(
            "CameraHostInfo::SetTorchLevel", rc, true, CameraReportUtils::GetCallerInfo());
        return HdiToServiceErrorV1_2(rc);
    }
    return CAMERA_OK;
}

void HCameraHostManager::CameraHostInfo::UpdateMuteSetting(std::shared_ptr<OHOS::Camera::CameraMetadata> setting)
{
    MEDIA_DEBUG_LOG("CameraHostInfo::UpdateMuteSetting enter");
    int32_t count = 1;
    uint8_t mode = OHOS_CAMERA_MUTE_MODE_SOLID_COLOR_BLACK;
    if (setting == nullptr) {
        MEDIA_DEBUG_LOG("CameraHostInfo::UpdateMuteSetting setting is null");
        constexpr int32_t DEFAULT_ITEMS = 1;
        constexpr int32_t DEFAULT_DATA_LENGTH = 1;
        setting = std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    }
    setting->addEntry(OHOS_CONTROL_MUTE_MODE, &mode, count);
}

int32_t HCameraHostManager::CameraHostInfo::Prelaunch(sptr<HCameraRestoreParam> cameraRestoreParam, bool muteMode)
{
    CHECK_RETURN_RET_ELOG(cameraRestoreParam == nullptr, CAMERA_UNKNOWN_ERROR,
        "CameraHostInfo::Prelaunch cameraRestoreParam is null");
    CHECK_RETURN_RET(CheckUserHasChanged(cameraRestoreParam->GetSetting()), CAMERA_UNKNOWN_ERROR);
    CHECK_RETURN_RET_ELOG(cameraHostProxy_ == nullptr, CAMERA_UNKNOWN_ERROR,
        "CameraHostInfo::Prelaunch cameraHostProxy_ is null");
    CHECK_RETURN_RET_ELOG(GetCameraHostVersion() < OHOS::CameraStandard::GetVersionId(1, 1), CAMERA_UNKNOWN_ERROR,
        "CameraHostInfo::Prelaunch not support host V1_0!");
    MEDIA_INFO_LOG("CameraHostInfo::prelaunch for cameraId %{public}s", (cameraRestoreParam->GetCameraId()).c_str());
    for (auto& streamInfo : cameraRestoreParam->GetStreamInfo()) {
        MEDIA_DEBUG_LOG("CameraHostInfo::prelaunch for stream id is:%{public}d", streamInfo.v1_0.streamId_);
    }
    OHOS::HDI::Camera::V1_1::PrelaunchConfig prelaunchConfig;
    std::vector<uint8_t> settings;
    prelaunchConfig.cameraId = cameraRestoreParam->GetCameraId();
    prelaunchConfig.streamInfos_V1_1 = cameraRestoreParam->GetStreamInfo();
    DumpMetadata(cameraRestoreParam->GetSetting());
    CHECK_EXECUTE(muteMode, UpdateMuteSetting(cameraRestoreParam->GetSetting()));
    OHOS::Camera::MetadataUtils::ConvertMetadataToVec(cameraRestoreParam->GetSetting(), settings);
    prelaunchConfig.setting = settings;
    int32_t opMode = cameraRestoreParam->GetCameraOpMode();
    bool isNeedRestore = IsNeedRestore(opMode, cameraRestoreParam->GetSetting(), prelaunchConfig.cameraId);
    CamRetCode rc;
    if (cameraHostProxyV1_2_ != nullptr && GetCameraHostVersion() > OHOS::CameraStandard::GetVersionId(1, 1)) {
        if (isNeedRestore) {
            MEDIA_INFO_LOG("CameraHostInfo::PrelaunchWithOpMode ICameraHost V1_2 %{public}d", opMode);
            rc = (CamRetCode)(cameraHostProxyV1_2_->PrelaunchWithOpMode(prelaunchConfig, opMode));
        } else {
            MEDIA_INFO_LOG("CameraHostInfo::Prelaunch ICameraHost V1_2 %{public}d", opMode);
            rc = (CamRetCode)(cameraHostProxyV1_2_->Prelaunch(prelaunchConfig));
        }
        // LCOV_EXCL_START
    } else if (cameraHostProxyV1_1_ != nullptr && GetCameraHostVersion() == OHOS::CameraStandard::GetVersionId(1, 1)) {
        MEDIA_DEBUG_LOG("CameraHostInfo::Prelaunch ICameraHost V1_1");
        rc = (CamRetCode)(cameraHostProxyV1_1_->Prelaunch(prelaunchConfig));
    } else {
        rc = HDI::Camera::V1_0::NO_ERROR;
        // LCOV_EXCL_STOP
    }
    CHECK_RETURN_RET_ELOG(rc != HDI::Camera::V1_0::NO_ERROR, HdiToServiceError(rc),
        "CameraHostInfo::Prelaunch failed with error Code:%{public}d", rc);
    return CAMERA_OK;
}

bool HCameraHostManager::CameraHostInfo::IsNeedRestore(int32_t opMode,
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraSettings, std::string& cameraId)
{
    CHECK_RETURN_RET(cameraSettings == nullptr, false);
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility;
    int32_t ret = GetCameraAbility(cameraId, cameraAbility);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK || cameraAbility == nullptr, false,
        "CameraHostInfo::IsNeedRestore failed");
    if (opMode == 0) { // 0 is normal mode
        MEDIA_INFO_LOG("operationMode:%{public}d", opMode);
        return true;
    }
    camera_metadata_item_t item;
    ret = OHOS::Camera::FindCameraMetadataItem(cameraAbility->get(), OHOS_ABILITY_CAMERA_MODES, &item);
    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG("Failed to find stream extend configuration return code %{public}d", ret);
        ret = OHOS::Camera::FindCameraMetadataItem(cameraAbility->get(),
            OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS, &item);
        if (ret == CAM_META_SUCCESS && item.count != 0) {
            MEDIA_INFO_LOG("basic config no need valid mode");
            return true;
        }
        return false;
    }

    for (uint32_t i = 0; i < item.count; i++) {
        if (opMode == item.data.u8[i]) {
            MEDIA_DEBUG_LOG("operationMode:%{public}d found in supported streams", opMode);
            return true;
        }
    }
    MEDIA_ERR_LOG("operationMode:%{public}d not found in supported streams", opMode);
    return false;
}
int32_t HCameraHostManager::CameraHostInfo::PreCameraSwitch(const std::string& cameraId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_RETURN_RET_ELOG(cameraHostProxy_ == nullptr, CAMERA_UNKNOWN_ERROR,
        "CameraHostInfo::PreCameraSwitch cameraHostProxy_ is null");
    CHECK_RETURN_RET_ELOG(GetCameraHostVersion() <= OHOS::CameraStandard::GetVersionId(1, 1), CAMERA_UNKNOWN_ERROR,
        "CameraHostInfo::PreCameraSwitch not support host V1_0 and V1_1!");
    if (cameraHostProxyV1_2_ != nullptr) {
        MEDIA_DEBUG_LOG("CameraHostInfo::PreCameraSwitch ICameraHost V1_2");
        CamRetCode rc = (CamRetCode)(cameraHostProxyV1_2_->PreCameraSwitch(cameraId));
        CHECK_RETURN_RET_ELOG(rc != HDI::Camera::V1_0::NO_ERROR, HdiToServiceError(rc),
            "CameraHostInfo::PreCameraSwitch failed with error Code:%{public}d", rc);
    }
    return CAMERA_OK;
}

void HCameraHostManager::CameraHostInfo::NotifyDeviceStateChangeInfo(int notifyType, int deviceState)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_RETURN_ELOG(cameraHostProxy_ == nullptr, "CameraHostInfo::Prelaunch cameraHostProxy_ is null");
    MEDIA_DEBUG_LOG("CameraHostInfo::NotifyDeviceStateChangeInfo notifyType = %{public}d, deviceState = %{public}d",
        notifyType, deviceState);
    if (cameraHostProxyV1_3_ != nullptr && GetCameraHostVersion() > OHOS::CameraStandard::GetVersionId(1, 1)) {
        MEDIA_DEBUG_LOG("CameraHostInfo::NotifyDeviceStateChangeInfo ICameraHost V1_2");
        cameraHostProxyV1_3_->NotifyDeviceStateChangeInfo(notifyType, deviceState);
        // LCOV_EXCL_START
    } else if (cameraHostProxyV1_2_ != nullptr && GetCameraHostVersion() > OHOS::CameraStandard::GetVersionId(1, 1)) {
        MEDIA_DEBUG_LOG("CameraHostInfo::NotifyDeviceStateChangeInfo ICameraHost V1_2");
        cameraHostProxyV1_2_->NotifyDeviceStateChangeInfo(notifyType, deviceState);
        // LCOV_EXCL_STOP
    }
}

void HCameraHostManager::CameraHostInfo::GetCameraStorageSize(const int& userId, int64_t& storageSize)
{
}

bool HCameraHostManager::CameraHostInfo::CheckUserHasChanged(
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraSettings)
{
    CHECK_RETURN_RET_ELOG(cameraSettings == nullptr, false, "camera settings is nullptr.");
    int32_t userId;
    int32_t uid = IPCSkeleton::GetCallingUid();
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, userId);
    camera_metadata_item_t item;
    int32_t ret = OHOS::Camera::FindCameraMetadataItem(cameraSettings->get(), OHOS_CAMERA_USER_ID, &item);
    if (ret == CAM_META_SUCCESS && userId != item.data.i32[0]) {
        MEDIA_INFO_LOG("userId changed from %{public}d to %{public}d", item.data.i32[0], userId);
        return true;
    }
    return false;
}

int32_t HCameraHostManager::CameraHostInfo::GetCameraResourceCost(const std::string& cameraId,
    OHOS::HDI::Camera::V1_3::CameraDeviceResourceCost& resourceCost)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (cameraHostProxyV1_3_ != nullptr &&
        cameraHostProxyV1_3_->GetResourceCost(cameraId, resourceCost) ==
        HDI::Camera::V1_0::CamRetCode::NO_ERROR) {
        return CAMERA_OK;
    }
    return CAMERA_UNSUPPORTED;
}

int32_t HCameraHostManager::CameraHostInfo::OnCameraStatus(
    const std::string& cameraId, HDI::Camera::V1_0::CameraStatus status)
{
    auto statusCallback = statusCallback_.lock();
    if (statusCallback == nullptr) {
        MEDIA_WARNING_LOG("CameraHostInfo::OnCameraStatus for %{public}s with status %{public}d "
                          "failed due to no callback",
            cameraId.c_str(), status);
        return CAMERA_UNKNOWN_ERROR;
    }
    CameraStatus svcStatus = CAMERA_STATUS_UNAVAILABLE;
    switch (status) {
        case UN_AVAILABLE: {
            MEDIA_INFO_LOG("CameraHostInfo::OnCameraStatus, camera %{public}s unavailable", cameraId.c_str());
            svcStatus = CAMERA_STATUS_UNAVAILABLE;
            break;
        }
        case AVAILABLE: {
            MEDIA_INFO_LOG("CameraHostInfo::OnCameraStatus, camera %{public}s available", cameraId.c_str());
            svcStatus = CAMERA_STATUS_AVAILABLE;
            AddDevice(cameraId);
            break;
        }
        default:
            MEDIA_ERR_LOG("Unknown camera status: %{public}d", status);
            return CAMERA_UNKNOWN_ERROR;
    }
    statusCallback->OnCameraStatus(cameraId, svcStatus);
    return CAMERA_OK;
}

void HCameraHostManager::CameraHostInfo::NotifyCameraHostDied()
{
    auto statusCallback = statusCallback_.lock();
    if (statusCallback == nullptr) {
        MEDIA_WARNING_LOG("CameraHostInfo::NotifyCameraHostDied failed due to no callback!");
        return;
    }
    std::vector<std::string> cameraIds;
    if (statusCallback && this->GetCameras(cameraIds) == CAMERA_OK) {
        for (const auto& cameraId : cameraIds) {
            statusCallback->OnCameraStatus(cameraId, CAMERA_SERVER_UNAVAILABLE);
        }
    }
}

// LCOV_EXCL_START
int32_t HCameraHostManager::CameraHostInfo::OnFlashlightStatus(const std::string& cameraId, FlashlightStatus status)
{
    auto statusCallback = statusCallback_.lock();
    if (statusCallback == nullptr) {
        MEDIA_WARNING_LOG("CameraHostInfo::OnFlashlightStatus for %{public}s with status %{public}d "
                          "failed due to no callback",
            cameraId.c_str(), status);
        return CAMERA_UNKNOWN_ERROR;
    }
    FlashStatus flashStatus = FLASH_STATUS_OFF;
    switch (status) {
        case FLASHLIGHT_OFF:
            flashStatus = FLASH_STATUS_OFF;
            MEDIA_INFO_LOG(
                "CameraHostInfo::OnFlashlightStatus, camera %{public}s flash light is off", cameraId.c_str());
            break;

        case FLASHLIGHT_ON:
            flashStatus = FLASH_STATUS_ON;
            MEDIA_INFO_LOG("CameraHostInfo::OnFlashlightStatus, camera %{public}s flash light is on", cameraId.c_str());
            break;

        case FLASHLIGHT_UNAVAILABLE:
            flashStatus = FLASH_STATUS_UNAVAILABLE;
            MEDIA_INFO_LOG(
                "CameraHostInfo::OnFlashlightStatus, camera %{public}s flash light is unavailable", cameraId.c_str());
            break;

        default:
            MEDIA_ERR_LOG("Unknown flashlight status: %{public}d for camera %{public}s", status, cameraId.c_str());
            return CAMERA_UNKNOWN_ERROR;
    }
    statusCallback->OnFlashlightStatus(cameraId, flashStatus);
    return CAMERA_OK;
}
// LCOV_EXCL_STOP

int32_t HCameraHostManager::CameraHostInfo::OnFlashlightStatus_V1_2(FlashlightStatus status)
{
    auto statusCallback = statusCallback_.lock();
    if (statusCallback == nullptr) {
        MEDIA_WARNING_LOG(
            "CameraHostInfo::OnFlashlightStatus_V1_2 with status %{public}d failed due to no callback", status);
        return CAMERA_UNKNOWN_ERROR;
    }
    TorchStatus torchStatus = TorchStatus::TORCH_STATUS_OFF;
    switch (status) {
        case FLASHLIGHT_OFF:
            torchStatus = TorchStatus::TORCH_STATUS_OFF;
            MEDIA_INFO_LOG("CameraHostInfo::OnFlashlightStatus_V1_2, torch status is off");
            break;

        case FLASHLIGHT_ON:
            torchStatus = TorchStatus::TORCH_STATUS_ON;
            MEDIA_INFO_LOG("CameraHostInfo::OnFlashlightStatus_V1_2, torch status is on");
            break;

        case FLASHLIGHT_UNAVAILABLE:
            torchStatus = TorchStatus::TORCH_STATUS_UNAVAILABLE;
            MEDIA_INFO_LOG("CameraHostInfo::OnFlashlightStatus_V1_2, torch status is unavailable");
            break;

        default:
            MEDIA_ERR_LOG("CameraHostInfo::OnFlashlightStatus_V1_2, Unknown flashlight status: %{public}d", status);
            return CAMERA_UNKNOWN_ERROR;
    }
    statusCallback->OnTorchStatus(torchStatus);
    return CAMERA_OK;
}

int32_t HCameraHostManager::CameraHostInfo::OnCameraEvent(const std::string& cameraId, CameraEvent event)
{
    auto statusCallback = statusCallback_.lock();
    if (statusCallback == nullptr) {
        MEDIA_WARNING_LOG(
            "CameraHostInfo::OnCameraEvent for %{public}s with status %{public}d failed due to no callback",
            cameraId.c_str(), event);
        return CAMERA_UNKNOWN_ERROR;
    }
    CameraStatus svcStatus = CAMERA_STATUS_UNAVAILABLE;
    switch (event) {
        case CAMERA_EVENT_DEVICE_RMV: {
            MEDIA_INFO_LOG("CameraHostInfo::OnCameraEvent, camera %{public}s unavailable", cameraId.c_str());
            svcStatus = CAMERA_STATUS_DISAPPEAR;
            RemoveDevice(cameraId);
            break;
        }
        case CAMERA_EVENT_DEVICE_ADD: {
            MEDIA_INFO_LOG("CameraHostInfo::OnCameraEvent camera %{public}s available", cameraId.c_str());
            svcStatus = CAMERA_STATUS_APPEAR;
            AddDevice(cameraId);
            std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility;
            camera_metadata_item_t item;
            std::string camera = cameraId;
            AddDevice(cameraId);
            int32_t ret = GetCameraAbility(camera, cameraAbility);
            CHECK_RETURN_RET_ELOG(ret != CAMERA_OK || cameraAbility == nullptr, CAMERA_DEVICE_ERROR,
                "CameraHostInfo::OnCameraEvent can't get camera ability");
            svcStatus = CAMERA_STATUS_APPEAR;
            ret =
                OHOS::Camera::FindCameraMetadataItem(cameraAbility->get(), OHOS_ABILITY_CAMERA_CONNECTION_TYPE, &item);
            if (ret == CAM_META_SUCCESS) {
                auto connectionType = item.data.u8[0];
                if (connectionType == 1) {
                    CameraReportUtils::GetInstance().ReportUserBehaviorAddDevice(
                        "AddDevice", camera, CameraReportUtils::GetCallerInfo());
                }
            }
            break;
        }
        default:
            MEDIA_ERR_LOG("Unknown camera event: %{public}d", event);
            return CAMERA_UNKNOWN_ERROR;
    }
    statusCallback->OnCameraStatus(cameraId, svcStatus);
    return CAMERA_OK;
}

std::shared_ptr<HCameraHostManager::CameraDeviceInfo> HCameraHostManager::CameraHostInfo::FindCameraDeviceInfo
   (const std::string& cameraId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<CameraDeviceInfo>>::iterator it = std::find_if(devices_.begin(), devices_.end(),
        [cameraId](const auto& deviceInfo) { return deviceInfo->cameraId == cameraId; });
    if (it != devices_.end()) {
        MEDIA_INFO_LOG("CameraHostInfo::FindCameraDeviceInfo succeed for %{public}s", cameraId.c_str());
        return (*it);
    }
    MEDIA_WARNING_LOG("CameraHostInfo::FindCameraDeviceInfo failed for %{public}s", cameraId.c_str());
    return nullptr;
}

void HCameraHostManager::CameraHostInfo::AddDevice(const std::string& cameraId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (std::none_of(devices_.begin(), devices_.end(),
                     [&cameraId](auto& devInfo) { return devInfo->cameraId == cameraId; })) {
        cameraIds_.push_back(cameraId);
        devices_.push_back(std::make_shared<HCameraHostManager::CameraDeviceInfo>(cameraId));
        MEDIA_INFO_LOG("CameraHostInfo::AddDevice, camera %{public}s added", cameraId.c_str());
    } else {
        MEDIA_WARNING_LOG("CameraHostInfo::AddDevice, camera %{public}s already exists", cameraId.c_str());
    }
}

void HCameraHostManager::CameraHostInfo::RemoveDevice(const std::string& cameraId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_INFO_LOG("CameraHostInfo::RemoveDevice, camera %{public}s removed", cameraId.c_str());
    cameraIds_.erase(std::remove(cameraIds_.begin(), cameraIds_.end(), cameraId), cameraIds_.end());
    devices_.erase(std::remove_if(devices_.begin(), devices_.end(),
        [&cameraId](const auto& devInfo) { return devInfo->cameraId == cameraId; }),
        devices_.end());
    for (auto id : cameraIds_) {
        MEDIA_INFO_LOG("CameraHostInfo::RemoveDevice, current camera %{public}s", id.c_str());
    }
}

HCameraHostManager::HCameraHostManager(std::shared_ptr<StatusCallback> statusCallback)
    : statusCallback_(statusCallback), cameraHostInfos_(), muteMode_(false)
{
    MEDIA_INFO_LOG("HCameraHostManager construct called");
}

HCameraHostManager::~HCameraHostManager()
{
    MEDIA_INFO_LOG("HCameraHostManager deconstruct called");
    std::lock_guard<std::mutex> lock(deviceMutex_);
    for (auto it = cameraDevices_.begin(); it != cameraDevices_.end(); it++) {
        if (it->second) {
            it->second = nullptr;
        }
    }
    cameraDevices_.clear();

    for (unsigned i = 0; i < cameraHostInfos_.size(); i++) {
        cameraHostInfos_[i] = nullptr;
    }
    cameraHostInfos_.clear();
}

int32_t HCameraHostManager::Init()
{
    MEDIA_INFO_LOG("HCameraHostManager::Init");
    using namespace OHOS::HDI::ServiceManager::V1_0;
    auto svcMgr = IServiceManager::Get();
    CHECK_RETURN_RET_ELOG(svcMgr == nullptr, CAMERA_UNKNOWN_ERROR,
        "HCameraHostManager::Init IServiceManager failed!");

    ::OHOS::sptr<IServStatListener> listener(
        new RegisterServStatListener(RegisterServStatListener::StatusCallback([&](const ServiceStatus& status) {
            using namespace OHOS::HDI::ServiceManager::V1_0;

            switch (status.status) {
                case SERVIE_STATUS_START:
                    AddCameraHost(status.serviceName);
                    break;
                case SERVIE_STATUS_STOP:
                    RemoveCameraHost(status.serviceName);
                    break;
                default:
                    MEDIA_ERR_LOG("HCameraHostManager::OnReceive unexpected service status %{public}d", status.status);
            }
        })
    ));

    auto rt = svcMgr->RegisterServiceStatusListener(listener, DEVICE_CLASS_CAMERA);
    CHECK_RETURN_RET_ELOG(rt != 0, CAMERA_UNKNOWN_ERROR,
        "HCameraHostManager::Init RegisterServiceStatusListener failed!");
    registerServStatListener_ = listener;

    return CAMERA_OK;
}

void HCameraHostManager::DeInit()
{
    using namespace OHOS::HDI::ServiceManager::V1_0;
    auto svcMgr = IServiceManager::Get();
    CHECK_RETURN_ELOG(svcMgr == nullptr, "HCameraHostManager::DeInit(): IServiceManager failed");
    auto rt = svcMgr->UnregisterServiceStatusListener(registerServStatListener_);
    CHECK_PRINT_ELOG(rt != 0, "HCameraHostManager::DeInit(): UnregisterServiceStatusListener failed!");
    registerServStatListener_ = nullptr;
}

void HCameraHostManager::AddCameraDevice(const std::string& cameraId, sptr<ICameraDeviceService> cameraDevice)
{
    std::lock_guard<std::mutex> lock(deviceMutex_);
    auto it = cameraDevices_.find(cameraId);
    if (it != cameraDevices_.end()) {
        it->second = nullptr;
        cameraDevices_.erase(cameraId);
    }
    cameraDevices_[cameraId] = cameraDevice;
    auto statusCallback = statusCallback_.lock();
    CHECK_EXECUTE(statusCallback != nullptr,
        statusCallback->OnCameraStatus(cameraId, CAMERA_STATUS_UNAVAILABLE, CallbackInvoker::APPLICATION));
}

void HCameraHostManager::RemoveCameraDevice(const std::string& cameraId)
{
    MEDIA_DEBUG_LOG("HCameraHostManager::RemoveCameraDevice start");
    {
        std::lock_guard<std::mutex> lock(deviceMutex_);
        auto it = cameraDevices_.find(cameraId);
        if (it != cameraDevices_.end()) {
            it->second = nullptr;
        }
        cameraDevices_.erase(cameraId);
        auto statusCallback = statusCallback_.lock();
        CHECK_EXECUTE(statusCallback,
            statusCallback->OnCameraStatus(cameraId, CAMERA_STATUS_AVAILABLE, CallbackInvoker::APPLICATION));
    }
    {
        std::lock_guard<std::mutex> lock(openPrelaunchMutex_);
        if (cameraDevices_.size() == 0) {
            isHasOpenCamera_ = false;
        }
        isHasPrelaunch_ = false;
    }
    MEDIA_DEBUG_LOG("HCameraHostManager::RemoveCameraDevice end");
}

void HCameraHostManager::CloseCameraDevice(const std::string& cameraId)
{
    sptr<ICameraDeviceService> deviceToDisconnect = nullptr;
    {
        std::lock_guard<std::mutex> lock(deviceMutex_);
        auto iter = cameraDevices_.find(cameraId);
        if (iter != cameraDevices_.end()) {
            deviceToDisconnect = iter->second;
        }
    }
    CHECK_RETURN(!deviceToDisconnect);
    MEDIA_DEBUG_LOG("HCameraDevice::CloseCameraDevice should clean %{public}s device", cameraId.c_str());
    HCameraDevice* devicePtr = static_cast<HCameraDevice*>(deviceToDisconnect.GetRefPtr());
    devicePtr->RemoveResourceWhenHostDied();
}

int32_t HCameraHostManager::GetCameras(std::vector<std::string>& cameraIds)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HCameraHostManager::GetCameras");
    CHECK_EXECUTE(!IsCameraHostInfoAdded(LOCAL_SERVICE_NAME), AddCameraHost(LOCAL_SERVICE_NAME));
    std::lock_guard<std::mutex> lock(mutex_);
    cameraIds.clear();
    for (const auto& cameraHost : cameraHostInfos_) {
        cameraHost->GetCameras(cameraIds);
    }
    return CAMERA_OK;
}

int32_t HCameraHostManager::GetCameraIdSortedByCameraType(std::vector<std::string>& cameraIds)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HCameraHostManager::GetCameraIdSortedByCameraType");
    if (!IsCameraHostInfoAdded(LOCAL_SERVICE_NAME)) {
        AddCameraHost(LOCAL_SERVICE_NAME);
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        cameraIds.clear();
        for (const auto& cameraHost : cameraHostInfos_) {
            cameraHost->GetCameras(cameraIds);
        }
    }
    std::vector<camera_type_enum_t> cameraTypes;
    for (auto id : cameraIds) {
        std::shared_ptr<OHOS::Camera::CameraMetadata> ability;
        GetCameraAbility(id, ability);
        int32_t cameratypenow = 0;
        camera_metadata_item_t item;
        int32_t ret = OHOS::Camera::FindCameraMetadataItem(ability->get(), OHOS_ABILITY_CAMERA_TYPE, &item);
        if (item.count < 1) {
            cameraTypes.emplace_back(static_cast<camera_type_enum_t>(cameratypenow));
            continue;
        }
        cameratypenow = (ret == CAM_META_SUCCESS) ? item.data.u8[0] : OHOS_CAMERA_TYPE_UNSPECIFIED;
        cameraTypes.emplace_back(static_cast<camera_type_enum_t>(cameratypenow));
    }

    std::sort(cameraIds.begin(), cameraIds.end(), [&](const std::string& first, const std::string& second) {
        size_t indexFirst = std::distance(cameraIds.begin(), std::find(cameraIds.begin(), cameraIds.end(), first));
        size_t indexSecond = std::distance(cameraIds.begin(), std::find(cameraIds.begin(), cameraIds.end(), second));
        return cameraTypes[indexFirst] < cameraTypes[indexSecond];
    });
    return CAMERA_OK;
}

int32_t HCameraHostManager::GetCameraAbility(const std::string &cameraId,
                                             std::shared_ptr<OHOS::Camera::CameraMetadata> &ability)
{
    auto cameraHostInfo = FindCameraHostInfo(cameraId);
    CHECK_RETURN_RET_ELOG(cameraHostInfo == nullptr, CAMERA_INVALID_ARG,
        "HCameraHostManager::GetCameraAbility failed with invalid device info.");
    return cameraHostInfo->GetCameraAbility(cameraId, ability);
}

int32_t HCameraHostManager::GetVersionByCamera(const std::string& cameraId)
{
    MEDIA_INFO_LOG("GetVersionByCamera camera = %{public}s", cameraId.c_str());
    auto cameraHostInfo = FindCameraHostInfo(cameraId);
    CHECK_RETURN_RET_ELOG(cameraHostInfo == nullptr, 0, "GetVersionByCamera failed with invalid device info");
    return cameraHostInfo->GetCameraHostVersion();
}

int32_t HCameraHostManager::OpenCameraDevice(std::string &cameraId,
    const sptr<ICameraDeviceCallback> &callback,
    sptr<OHOS::HDI::Camera::V1_0::ICameraDevice> &pDevice,
    bool isEnableSecCam)
{
    MEDIA_INFO_LOG("HCameraHostManager::OpenCameraDevice try to open camera = %{public}s", cameraId.c_str());
    auto cameraHostInfo = FindCameraHostInfo(cameraId);
    CHECK_RETURN_RET_ELOG(cameraHostInfo == nullptr, CAMERA_INVALID_ARG,
        "HCameraHostManager::OpenCameraDevice failed with invalid device info.");
    {
        std::lock_guard<std::mutex> lock(openPrelaunchMutex_);
        int32_t uid = IPCSkeleton::GetCallingUid();
        CHECK_RETURN_RET_ELOG((isHasPrelaunch_ && uid < MAX_SYS_UID), CAMERA_INVALID_ARG,
            "HCameraHostManager::OpenCameraDevice sys is not allowed after prelaunch.");
        int32_t ret =  cameraHostInfo->OpenCamera(cameraId, callback, pDevice, isEnableSecCam);
        CHECK_EXECUTE(ret == 0, isHasOpenCamera_ = true);
        CHECK_EXECUTE(closeTimer_, {closeTimer_->CancelTask(); closeTimer_ = nullptr;});
        return ret;
    }
}

int32_t HCameraHostManager::SetTorchLevel(float level)
{
    CHECK_EXECUTE(!IsCameraHostInfoAdded(LOCAL_SERVICE_NAME), AddCameraHost(LOCAL_SERVICE_NAME));
    auto cameraHostInfo = FindLocalCameraHostInfo();
    CHECK_RETURN_RET_ELOG(cameraHostInfo == nullptr, CAMERA_INVALID_ARG,
        "HCameraHostManager::SetTorchLevel failed with not exist support device info");
    return cameraHostInfo->SetTorchLevel(level);
}

int32_t HCameraHostManager::SetFlashlight(const std::string& cameraId, bool isEnable)
{
    auto cameraHostInfo = FindCameraHostInfo(cameraId);
    CHECK_RETURN_RET_ELOG(cameraHostInfo == nullptr, CAMERA_INVALID_ARG,
        "HCameraHostManager::SetFlashlight failed with invalid device info");
    return cameraHostInfo->SetFlashlight(cameraId, isEnable);
}

int32_t HCameraHostManager::Prelaunch(const std::string& cameraId, std::string clientName)
{
    MEDIA_DEBUG_LOG("HCameraHostManager::Prelaunch start");
    auto cameraHostInfo = FindCameraHostInfo(cameraId);
    CHECK_RETURN_RET_ELOG(cameraHostInfo == nullptr, CAMERA_INVALID_ARG,
        "HCameraHostManager::Prelaunch failed with invalid device info");
    sptr<HCameraRestoreParam> cameraRestoreParam = GetRestoreParam(clientName, cameraId);
    CHECK_RETURN_RET_ELOG(cameraRestoreParam == nullptr, CAMERA_INVALID_ARG,
        "HCameraHostManager::Prelaunch cameraRestoreParam is null");
    int foldStatus = static_cast<int>(OHOS::Rosen::DisplayManager::GetInstance().GetFoldStatus());
    int restoreFoldStatus = cameraRestoreParam->GetFlodStatus();
    MEDIA_DEBUG_LOG("HCameraHostManager::Prelaunch foldStatus:%{public}d, restoreFoldStatus:%{public}d",
        foldStatus, restoreFoldStatus);
    if (foldStatus != restoreFoldStatus && restoreFoldStatus != 0) {
        MEDIA_DEBUG_LOG("HCameraHostManager::SaveRestoreParam %d", foldStatus);
        return 0;
    }
    {
        std::lock_guard<std::mutex> lock(openPrelaunchMutex_);
        CHECK_RETURN_RET_ELOG(isHasOpenCamera_, CAMERA_INVALID_ARG,
            "HCameraHostManager::Prelaunch failed that has been running");
        int32_t ret = cameraHostInfo->Prelaunch(cameraRestoreParam, muteMode_);
        constexpr uint32_t delayMilli = 2 * 1000; // 2S 1000 is ms
        CHECK_EXECUTE(closeTimer_, closeTimer_->CancelTask());
        closeTimer_ = std::make_shared<SimpleTimer>([this] {
            this->isHasPrelaunch_ = false;
        });
        bool isStartSuccess = closeTimer_->StartTask(delayMilli);
        CHECK_EXECUTE(ret == 0 && isStartSuccess, isHasPrelaunch_ = true);
        if (ret == 0 && cameraRestoreParam->GetRestoreParamType() ==
            RestoreParamTypeOhos::PERSISTENT_DEFAULT_PARAM_OHOS) {
            return CAMERA_OK;
        }
    }
    // 使用后删除存储的动态数据
    std::lock_guard<std::mutex> lock(saveRestoreMutex_);
    auto it = transitentParamMap_.find(clientName);
    CHECK_EXECUTE(it != transitentParamMap_.end() && CheckCameraId(it->second, cameraId),
        transitentParamMap_.erase(clientName));
    return 0;
}

int32_t HCameraHostManager::PreSwitchCamera(const std::string& cameraId)
{
    auto cameraHostInfo = FindCameraHostInfo(cameraId);
    CHECK_RETURN_RET_ELOG(cameraHostInfo == nullptr, CAMERA_INVALID_ARG,
        "HCameraHostManager::PreSwitchCamera failed with invalid device info");
    return cameraHostInfo->PreCameraSwitch(cameraId);
}

void HCameraHostManager::NotifyDeviceStateChangeInfo(int notifyType, int deviceState)
{
    auto cameraHostInfo = FindLocalCameraHostInfo();
    CHECK_RETURN_ELOG(cameraHostInfo == nullptr,
        "HCameraHostManager::NotifyDeviceStateChangeInfo failed with not exist support device info");
    
    cameraHostInfo->NotifyDeviceStateChangeInfo(notifyType, deviceState);
}

void HCameraHostManager::SaveRestoreParam(sptr<HCameraRestoreParam> cameraRestoreParam)
{
    std::lock_guard<std::mutex> lock(saveRestoreMutex_);
    CHECK_RETURN_ELOG(cameraRestoreParam == nullptr, "HCameraRestoreParam is nullptr");
    std::string clientName = cameraRestoreParam->GetClientName();
    if (cameraRestoreParam->GetRestoreParamType() == RestoreParamTypeOhos::PERSISTENT_DEFAULT_PARAM_OHOS) {
        DeleteRestoreParam(clientName, cameraRestoreParam->GetCameraId());
        (persistentParamMap_[clientName])[cameraRestoreParam->GetCameraId()] = cameraRestoreParam;
        MEDIA_DEBUG_LOG("HCameraHostManager::SaveRestoreParam save persistent param");
    } else {
        auto itTransitent = transitentParamMap_.find(clientName);
        CHECK_EXECUTE(itTransitent != transitentParamMap_.end(), transitentParamMap_.erase(clientName));
        transitentParamMap_[clientName] = cameraRestoreParam;
        MEDIA_DEBUG_LOG("HCameraHostManager::SaveRestoreParam save transist param");
        isHasSavedParam = true;
    }
}

void HCameraHostManager::UpdateRestoreParamCloseTime(const std::string& clientName, const std::string& cameraId)
{
    MEDIA_DEBUG_LOG("HCameraHostManager::UpdateRestoreParamCloseTime enter");
    timeval closeTime;
    gettimeofday(&closeTime, nullptr);
    std::lock_guard<std::mutex> lock(saveRestoreMutex_);
    auto itPersistent = persistentParamMap_.find(clientName);
    if (itPersistent != persistentParamMap_.end()) {
        MEDIA_DEBUG_LOG("HCameraHostManager::UpdateRestoreParamCloseTime find persistentParam");
        std::map<std::string, sptr<HCameraRestoreParam>>::iterator iter = (persistentParamMap_[clientName]).begin();
        while (iter != (persistentParamMap_[clientName]).end()) {
            auto cameraRestoreParam = iter->second;
            if (cameraId == cameraRestoreParam->GetCameraId()) {
                cameraRestoreParam->SetCloseCameraTime(closeTime);
                MEDIA_DEBUG_LOG("HCameraHostManager::Update persistent closeTime");
            } else {
                cameraRestoreParam->SetCloseCameraTime({0, 0});
            }
            ++iter;
        }
    }

    auto itTransitent = transitentParamMap_.find(clientName);
    if (!isHasSavedParam && itTransitent != transitentParamMap_.end()) {
        transitentParamMap_.erase(clientName);
        return;
    }

    CHECK_RETURN(itTransitent == transitentParamMap_.end());
    MEDIA_INFO_LOG("HCameraHostManager::Update transient CloseTime ");
    transitentParamMap_[clientName]->SetCloseCameraTime(closeTime);
    isHasSavedParam = false;
}

void HCameraHostManager::DeleteRestoreParam(const std::string& clientName, const std::string& cameraId)
{
    MEDIA_DEBUG_LOG("HCameraHostManager::DeleteRestoreParam enter");
    auto itPersistent = persistentParamMap_.find(clientName);
    CHECK_RETURN(itPersistent == persistentParamMap_.end());
    auto iterParamMap = (itPersistent->second).find(cameraId);
    if (iterParamMap != (itPersistent->second).end()) {
        iterParamMap->second = nullptr;
        (itPersistent->second).erase(cameraId);
    }
}

sptr<HCameraRestoreParam> HCameraHostManager::GetRestoreParam(const std::string& clientName,
    const std::string& cameraId)
{
    MEDIA_DEBUG_LOG("HCameraHostManager::GetRestoreParam enter");
    std::lock_guard<std::mutex> lock(saveRestoreMutex_);
    std::vector<StreamInfo_V1_1> streamInfos;
    RestoreParamTypeOhos restoreParamType = RestoreParamTypeOhos::NO_NEED_RESTORE_PARAM_OHOS;
    sptr<HCameraRestoreParam> cameraRestoreParam = new HCameraRestoreParam(clientName, cameraId,
        streamInfos, nullptr, restoreParamType, 0);
    auto it = persistentParamMap_.find(clientName);
    if (it != persistentParamMap_.end()) {
        MEDIA_DEBUG_LOG("HCameraHostManager::GetRestoreParam find persistent param");
        UpdateRestoreParam(cameraRestoreParam);
    } else {
        cameraRestoreParam = GetTransitentParam(clientName, cameraId);
        MEDIA_DEBUG_LOG("HCameraHostManager::GetRestoreParam find transist param");
    }
    return cameraRestoreParam;
}

void HCameraHostManager::UpdateRestoreParam(sptr<HCameraRestoreParam> &cameraRestoreParam)
{
    CHECK_RETURN_ELOG(cameraRestoreParam == nullptr, "HCameraHostManager::UpdateRestoreParam is nullptr");
    std::string clientName = cameraRestoreParam->GetClientName();
    std::string cameraId = cameraRestoreParam->GetCameraId();
    std::map<std::string, sptr<HCameraRestoreParam>>::iterator iter = (persistentParamMap_[clientName]).begin();
    while (iter != (persistentParamMap_[clientName]).end()) {
        auto restoreParam = iter->second;
        timeval closeTime = restoreParam->GetCloseCameraTime();
        MEDIA_DEBUG_LOG("HCameraHostManager::UpdateRestoreParam closeTime.tv_sec");
        if (closeTime.tv_sec != 0 && CheckCameraId(restoreParam, cameraId)) {
            timeval openTime;
            gettimeofday(&openTime, nullptr);
            int64_t sec_diff = openTime.tv_sec - closeTime.tv_sec;
            int64_t usec_diff = openTime.tv_usec - closeTime.tv_usec;
            if (usec_diff < 0) {
                sec_diff -= 1;
                usec_diff += MILLISEC_TIME * MILLISEC_TIME;
            }
            int64_t timeInterval = sec_diff * MILLISEC_TIME + usec_diff / MILLISEC_TIME;
            if ((restoreParam->GetStartActiveTime() * 60 * MILLISEC_TIME) < timeInterval) { // 60 is 60 Seconds
                MEDIA_DEBUG_LOG("HCameraHostManager::UpdateRestoreParam get persistent");
                cameraRestoreParam = restoreParam;
            } else {
                MEDIA_DEBUG_LOG("HCameraHostManager::UpdateRestoreParam get transistent ");
                cameraRestoreParam = GetTransitentParam(clientName, cameraId);
            }
            cameraRestoreParam->UpdateExposureSetting(timeInterval);
            break;
        }
        ++iter;
    }
}

sptr<HCameraRestoreParam> HCameraHostManager::GetTransitentParam(const std::string& clientName,
    const std::string& cameraId)
{
    std::vector<StreamInfo_V1_1> streamInfos;
    RestoreParamTypeOhos restoreParamType = RestoreParamTypeOhos::NO_NEED_RESTORE_PARAM_OHOS;
    sptr<HCameraRestoreParam> cameraRestoreParam = new HCameraRestoreParam(clientName, cameraId,
        streamInfos, nullptr, restoreParamType, 0);
    auto iter = transitentParamMap_.find(clientName);
    if (iter != transitentParamMap_.end() && (CheckCameraId(transitentParamMap_[clientName], cameraId))) {
        cameraRestoreParam = transitentParamMap_[clientName];
        MEDIA_DEBUG_LOG("HCameraHostManager::GetTransitentParam end");
    }
    return cameraRestoreParam;
}

bool HCameraHostManager::CheckCameraId(sptr<HCameraRestoreParam> cameraRestoreParam, const std::string& cameraId)
{
    CHECK_RETURN_RET(cameraRestoreParam == nullptr, false);
    CHECK_RETURN_RET(cameraRestoreParam->GetCameraId() == cameraId, true);
    return false;
}


void HCameraHostManager::AddCameraHost(const std::string& svcName)
{
    MEDIA_INFO_LOG("HCameraHostManager::AddCameraHost camera host %{public}s added", svcName.c_str());
    std::lock_guard<std::mutex> lock(mutex_);
    if (std::any_of(cameraHostInfos_.begin(), cameraHostInfos_.end(),
                    [&svcName](const auto& camHost) { return camHost->GetName() == svcName; })) {
        MEDIA_INFO_LOG("HCameraHostManager::AddCameraHost camera host  %{public}s already exists", svcName.c_str());
        return;
    }
    if (cameraHostDeadCallback_ == nullptr) {
        cameraHostDeadCallback_ = std::make_shared<CameraHostDeadCallback>(this);
    }
    auto statusCallback = statusCallback_.lock();
    sptr<HCameraHostManager::CameraHostInfo> cameraHost =
        new (std::nothrow) HCameraHostManager::CameraHostInfo(statusCallback, cameraHostDeadCallback_, svcName);
    CHECK_RETURN_ELOG(cameraHost == nullptr, "failed to new cameraHost!");
    CHECK_RETURN_ELOG(!cameraHost->Init(), "HCameraHostManager::AddCameraHost failed due to init failure");
    cameraHostInfos_.push_back(cameraHost);
    std::vector<std::string> cameraIds;
    if (statusCallback && cameraHost->GetCameras(cameraIds) == CAMERA_OK) {
        for (const auto& cameraId : cameraIds) {
            statusCallback->OnCameraStatus(cameraId, CAMERA_STATUS_AVAILABLE);
        }
    }
    CHECK_EXECUTE(statusCallback && svcName == LOCAL_SERVICE_NAME,
        statusCallback->OnTorchStatus(TorchStatus::TORCH_STATUS_OFF));
}

void HCameraHostManager::RemoveCameraHost(const std::string& svcName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_INFO_LOG("HCameraHostManager::RemoveCameraHost camera host %{public}s removed", svcName.c_str());
    std::vector<sptr<CameraHostInfo>>::iterator it = std::find_if(cameraHostInfos_.begin(), cameraHostInfos_.end(),
        [&svcName](const auto& camHost) { return camHost->GetName() == svcName; });
    if (it == cameraHostInfos_.end()) {
        MEDIA_WARNING_LOG("HCameraHostManager::RemoveCameraHost camera host %{public}s doesn't exist",
            svcName.c_str());
        return;
    }
    std::vector<std::string> cameraIds;
    if ((*it)->GetCameras(cameraIds) == CAMERA_OK) {
        for (const auto& cameraId : cameraIds) {
            (*it)->OnCameraStatus(cameraId, UN_AVAILABLE);
            CloseCameraDevice(cameraId);
        }
    }
    *it = nullptr;
    cameraHostInfos_.erase(it);
    auto statusCallback = statusCallback_.lock();
    CHECK_EXECUTE(statusCallback && svcName == LOCAL_SERVICE_NAME,
        statusCallback->OnTorchStatus(TorchStatus::TORCH_STATUS_UNAVAILABLE));
}

sptr<HCameraHostManager::CameraHostInfo> HCameraHostManager::FindCameraHostInfo(const std::string& cameraId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& cameraHostInfo : cameraHostInfos_) {
        CHECK_RETURN_RET(cameraHostInfo->IsCameraSupported(cameraId), cameraHostInfo);
    }
    return nullptr;
}

sptr<HCameraHostManager::CameraHostInfo> HCameraHostManager::FindLocalCameraHostInfo()
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<sptr<CameraHostInfo>>::iterator it = std::find_if(cameraHostInfos_.begin(), cameraHostInfos_.end(),
        [](const auto& cameraHostInfo) { return cameraHostInfo->GetName() == LOCAL_SERVICE_NAME; });
    CHECK_RETURN_RET(it != cameraHostInfos_.end(), (*it));
    return nullptr;
}

bool HCameraHostManager::IsCameraHostInfoAdded(const std::string& svcName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    return std::any_of(cameraHostInfos_.begin(), cameraHostInfos_.end(),
                       [&svcName](const auto& camHost) {return camHost->GetName() == svcName; });
}

::OHOS::sptr<HDI::ServiceManager::V1_0::IServStatListener> HCameraHostManager::GetRegisterServStatListener()
{
    return registerServStatListener_;
}

void HCameraHostManager::SetMuteMode(bool muteMode)
{
    muteMode_ = muteMode;
}

int32_t HCameraHostManager::GetCameraResourceCost(const std::string& cameraId,
    OHOS::HDI::Camera::V1_3::CameraDeviceResourceCost& resourceCost)
{
    auto cameraHostInfo = FindCameraHostInfo(cameraId);
    CHECK_RETURN_RET_ELOG(cameraHostInfo == nullptr, CAMERA_INVALID_ARG,
        "HCameraHostManager::GetCameraResourceCost failed with invalid device info");
    return cameraHostInfo->GetCameraResourceCost(cameraId, resourceCost);
}

void RegisterServStatListener::OnReceive(const HDI::ServiceManager::V1_0::ServiceStatus& status)
{
    MEDIA_INFO_LOG("HCameraHostManager::OnReceive for camerahost %{public}s, status %{public}d, deviceClass %{public}d",
        status.serviceName.c_str(), status.status, status.deviceClass);

    CHECK_RETURN_ELOG(status.deviceClass != DEVICE_CLASS_CAMERA,
        "HCameraHostManager::OnReceive invalid device class %{public}d", status.deviceClass);
    callback_(status);
}

void HCameraHostManager::GetPhysicCameraId(int32_t position, std::string &cameraid)
{
    std::vector<std::string> cameraIds;
    MEDIA_DEBUG_LOG("GetPhysicCameraId target position %{public}d", position);
    GetCameraIdSortedByCameraType(cameraIds);
    for (auto iterOfCameraIds : cameraIds) {
        std::shared_ptr<OHOS::Camera::CameraMetadata> ability;
        GetCameraAbility(iterOfCameraIds, ability);
        camera_metadata_item_t itemp;
        int issup = OHOS::Camera::FindCameraMetadataItem(ability->get(), OHOS_ABILITY_CAMERA_CONCURRENT_TYPE, &itemp);
        MEDIA_DEBUG_LOG("GetPhysicCameraId cameraid = %{public}s CONCURRENT_TYPE is support limted = %{public}d",
            iterOfCameraIds.c_str(), issup);
        issup = OHOS::Camera::FindCameraMetadataItem(ability->get(), OHOS_ABILITY_CONCURRENT_SUPPORTED_CAMERAS, &itemp);
        MEDIA_DEBUG_LOG("GetPhysicCameraId cameraid = %{public}s CONCURRENT_SUPPORTED_CAMERAS"
            "is support limted = %{public}d",
            iterOfCameraIds.c_str(), issup);
        issup = OHOS::Camera::FindCameraMetadataItem(ability->get(), OHOS_ABILITY_CAMERA_LIMITED_CAPABILITIES, &itemp);
        MEDIA_DEBUG_LOG("GetPhysicCameraId cameraid = %{public}s LIMITED_CAPABILITIES "
            "is support limted = %{public}d",
            iterOfCameraIds.c_str(), issup);

        int32_t positionNow;
        int32_t cameratypeNow;
        camera_metadata_item_t item;
        int ret = OHOS::Camera::FindCameraMetadataItem(ability->get(), OHOS_ABILITY_CAMERA_POSITION, &item);
        positionNow = (ret == CAM_META_SUCCESS) ? item.data.u8[0] : OHOS_CAMERA_POSITION_OTHER;
        ret = OHOS::Camera::FindCameraMetadataItem(ability->get(), OHOS_ABILITY_CAMERA_TYPE, &item);
        cameratypeNow = (ret == CAM_META_SUCCESS) ? item.data.u8[0] : OHOS_CAMERA_TYPE_UNSPECIFIED;
        if (positionNow != position || cameratypeNow == OHOS_CAMERA_TYPE_UNSPECIFIED) {
            MEDIA_DEBUG_LOG("iter cameraId : %{public}s continue, position: %{public}d, type: %{public}d",
                iterOfCameraIds.c_str(), positionNow, cameratypeNow);
            continue;
        }
        ret = OHOS::Camera::FindCameraMetadataItem(ability->get(), OHOS_ABILITY_CONCURRENT_SUPPORTED_CAMERAS, &item);
        if (ret == CAM_META_SUCCESS) {
            cameraid = iterOfCameraIds;
            break;
        }
    }
}

void HCameraHostManager::GetCameraStorageSize(const int& userId, int64_t& storageSize)
{
    auto cameraHostInfo = FindLocalCameraHostInfo();
    CHECK_RETURN_ELOG(cameraHostInfo == nullptr,
        "HCameraHostManager::GetCameraStorageSize failed with not exist support device info");
    cameraHostInfo->GetCameraStorageSize(userId, storageSize);
}
} // namespace CameraStandard
} // namespace OHOS
