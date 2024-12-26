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
sptr<BmsAdapter> BmsAdapter::bmsAdapter_;
std::mutex BmsAdapter::instanceMutex_;

void BmsSaListener::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    MEDIA_INFO_LOG("OnAddSystemAbility,id: %{public}d", systemAbilityId);
}

void BmsSaListener::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    MEDIA_INFO_LOG("OnRemoveSystemAbility,id: %{public}d", systemAbilityId);
    if (systemAbilityId == BUNDLE_MGR_SERVICE_SYS_ABILITY_ID) {
        callback_();
    }
}

BmsAdapter::BmsAdapter()
{
}

BmsAdapter::~BmsAdapter()
{
    UnRegisterListener();
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
    if (bms_) {
        return bms_;
    }
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_ERROR_RETURN_RET_LOG(samgr == nullptr, nullptr, "GetBms failed, samgr is null");
    sptr<IRemoteObject> object = samgr->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    CHECK_ERROR_RETURN_RET_LOG(object == nullptr, nullptr, "GetBms failed, object is null");
    bms_ = iface_cast<OHOS::AppExecFwk::IBundleMgr>(object);
    CHECK_ERROR_RETURN_RET_LOG(bms_ == nullptr, nullptr, "GetBms failed, bms is null");
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
    std::string bundleName = "";
    if (cacheMap.Get(uid, bundleName)) {
        MEDIA_DEBUG_LOG("GetBundleName by cache, uid: %{public}d bundleName is %{public}s", uid, bundleName.c_str());
        return bundleName;
    }
    auto bms = GetBms();
    CHECK_ERROR_RETURN_RET_LOG(bms == nullptr, "", "bms is null");
    auto result = bms->GetNameForUid(uid, bundleName);
    if (result != ERR_OK) {
        MEDIA_DEBUG_LOG("GetNameForUid fail, ret: %{public}d", result);
        return "";
    }
    MEDIA_DEBUG_LOG("GetBundleName by GetNameForUid, uid: %{public}d bundleName is %{public}s",
        uid, bundleName.c_str());
    cacheMap.Put(uid, bundleName);
    return bundleName;
}

bool BmsAdapter::RegisterListener()
{
    MEDIA_INFO_LOG("Enter Into BmsAdapter::RegisterListener");
    CHECK_ERROR_RETURN_RET_LOG(bmsSaListener_ != nullptr, false, "has register listener");
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_ERROR_RETURN_RET_LOG(samgr == nullptr, false, "samgr is null");
    auto bmsAdapterWptr = wptr<BmsAdapter>(this);
    auto removeCallback = [bmsAdapterWptr]() {
        auto adapter = bmsAdapterWptr.promote();
        if (adapter) {
            adapter->SetBms(nullptr);
        }
    };
    bmsSaListener_ = new BmsSaListener(removeCallback);
    CHECK_ERROR_RETURN_RET_LOG(bmsSaListener_ == nullptr, false, "bmsSaListener_ alloc failed");
    int32_t ret = samgr->SubscribeSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID, bmsSaListener_);
    CHECK_ERROR_RETURN_RET_LOG(ret != 0, false, "SubscribeSystemAbility ret = %{public}d", ret);
    return true;
}

bool BmsAdapter::UnRegisterListener()
{
    MEDIA_INFO_LOG("Enter Into BmsAdapter::UnRegisterListener");
    CHECK_ERROR_RETURN_RET_LOG(bmsSaListener_ == nullptr, false, "bmsSaListener_ is null not need unregister");
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_ERROR_RETURN_RET_LOG(samgr == nullptr, false, "samgr is null");
    CHECK_ERROR_RETURN_RET_LOG(bmsSaListener_ == nullptr, false, "bmsSaListener_ is null");
    int32_t ret = samgr->UnSubscribeSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID, bmsSaListener_);
    CHECK_ERROR_RETURN_RET_LOG(ret != 0, false, "UnSubscribeSystemAbility ret = %{public}d", ret);
    bmsSaListener_ = nullptr;
    return true;
}
} // namespace CameraStandard
} // namespace OHOS