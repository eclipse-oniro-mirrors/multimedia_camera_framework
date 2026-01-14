/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "bms_adapter.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::AppExecFwk;
sptr<BmsAdapter> BmsAdapter::bmsAdapter_;
std::mutex BmsAdapter::instanceMutex_;

void BmsSaListener::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    MEDIA_INFO_LOG("OnAddSystemAbility,id: %{public}d", systemAbilityId);
}

void BmsSaListener::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    MEDIA_INFO_LOG("OnRemoveSystemAbility,id: %{public}d", systemAbilityId);
    CHECK_RETURN(systemAbilityId != BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    callback_();
}

BmsAdapter::BmsAdapter()
{
}

BmsAdapter::~BmsAdapter()
{
    UnregisterListener();
}

sptr<BmsAdapter> BmsAdapter::GetInstance()
{
    if (BmsAdapter::bmsAdapter_ == nullptr) {
        std::unique_lock<std::mutex> lock(instanceMutex_);
        if (BmsAdapter::bmsAdapter_ == nullptr) {
            MEDIA_INFO_LOG("Initializing bms adapter instance");
            BmsAdapter::bmsAdapter_ = new BmsAdapter();
        }
    }
    return BmsAdapter::bmsAdapter_;
}

sptr<OHOS::AppExecFwk::IBundleMgr> BmsAdapter::GetBms()
{
    std::lock_guard<std::mutex> lock(bmslock_);
    CHECK_RETURN_RET(bms_, bms_);
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_RET_ELOG(samgr == nullptr, nullptr, "GetBms failed, samgr is null");
    sptr<IRemoteObject> object = samgr->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    CHECK_RETURN_RET_ELOG(object == nullptr, nullptr, "GetBms failed, object is null");
    bms_ = iface_cast<OHOS::AppExecFwk::IBundleMgr>(object);
    CHECK_RETURN_RET_ELOG(bms_ == nullptr, nullptr, "GetBms failed, bms is null");
    RegisterListener();
    return bms_;
}

void BmsAdapter::SetBms(sptr<OHOS::AppExecFwk::IBundleMgr> bms)
{
    std::lock_guard<std::mutex> lock(bmslock_);
    bms_ = bms;
}

std::string BmsAdapter::GetBundleName(int uid)
{
    auto bundleName = "";
    OHOS::sptr<OHOS::ISystemAbilityManager> samgr =
        OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_RET_ELOG(samgr == nullptr, bundleName, "GetClientBundle Get ability manager failed");
    OHOS::sptr<OHOS::IRemoteObject> remoteObject = samgr->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    CHECK_RETURN_RET_ELOG(remoteObject == nullptr, bundleName, "GetClientBundle object is NULL.");
    sptr<AppExecFwk::IBundleMgr> bms = OHOS::iface_castAppExecFwk::IBundleMgr(remoteObject);
    CHECK_RETURN_RET_ELOG(bms == nullptr, bundleName, "GetClientBundle bundle manager service is NULL.");
    AppExecFwk::BundleInfo bundleInfo;
    auto ret = bms->GetBundleInfoForSelf(0, bundleInfo);
    CHECK_RETURN_RET_ELOG(ret != ERR_OK, bundleName, "GetBundleInfoForSelf failed.");
    bundleName = bundleInfo.name.c_str();
    MEDIA_INFO_LOG("bundleName: [%{private}s]", bundleName);
    return bundleName;
}

bool BmsAdapter::RegisterListener()
{
    MEDIA_INFO_LOG("Enter Into BmsAdapter::RegisterListener");
    CHECK_RETURN_RET_ELOG(bmsSaListener_ != nullptr, false, "has register listener");
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_RET_ELOG(samgr == nullptr, false, "samgr is null");
    auto bmsAdapterWptr = wptr<BmsAdapter>(this);
    auto removeCallback = [bmsAdapterWptr]() {
        auto adapter = bmsAdapterWptr.promote();
        if (adapter) {
            adapter->SetBms(nullptr);
        }
    };
    bmsSaListener_ = new BmsSaListener(removeCallback);
    CHECK_RETURN_RET_ELOG(bmsSaListener_ == nullptr, false, "bmsSaListener_ alloc failed");
    int32_t ret = samgr->SubscribeSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID, bmsSaListener_);
    CHECK_RETURN_RET_ELOG(ret != 0, false, "SubscribeSystemAbility ret = %{public}d", ret);
    return true;
}

bool BmsAdapter::UnregisterListener()
{
    MEDIA_INFO_LOG("Enter Into BmsAdapter::UnregisterListener");
    CHECK_RETURN_RET_ELOG(bmsSaListener_ == nullptr, false, "bmsSaListener_ is null not need unregister");
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_RET_ELOG(samgr == nullptr, false, "samgr is null");
    CHECK_RETURN_RET_ELOG(bmsSaListener_ == nullptr, false, "bmsSaListener_ is null");
    int32_t ret = samgr->UnSubscribeSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID, bmsSaListener_);
    CHECK_RETURN_RET_ELOG(ret != 0, false, "UnSubscribeSystemAbility ret = %{public}d", ret);
    bmsSaListener_ = nullptr;
    return true;
}
} // namespace CameraStandard
} // namespace OHOS