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

#ifndef OHOS_CAMERA_BMS_ADAPTER_H
#define OHOS_CAMERA_BMS_ADAPTER_H

#include <refbase.h>
#include "camera_util.h"
#include "system_ability_status_change_stub.h"
#include "iservice_registry.h"
#include "bundle_mgr_interface.h"
#include "system_ability_definition.h"
#include "lru_map.h"

namespace OHOS {
namespace CameraStandard {

class BmsSaListener : public SystemAbilityStatusChangeStub {
public:
    using RemoveCallback = std::function<void()>;
    explicit BmsSaListener(RemoveCallback callback) : callback_(std::move(callback)) {
    }
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
private:
    RemoveCallback callback_;
};

class BmsAdapter : public RefBase {
public:
    ~BmsAdapter();
    static sptr<BmsAdapter> &GetInstance();
    std::string GetBundleName(int uid);
    sptr<OHOS::AppExecFwk::IBundleMgr> GetBms();
    void SetBms(sptr<OHOS::AppExecFwk::IBundleMgr> bms);

private:
    BmsAdapter();
    bool RegisterListener();
    bool UnRegisterListener();
    static sptr<BmsAdapter> bmsAdapter_;
    static std::mutex instanceMutex_;
    std::mutex bmslock_;
    sptr<OHOS::AppExecFwk::IBundleMgr> bms_ = nullptr;
    sptr<BmsSaListener> bmsSaListener_ = nullptr;
    LruMap<int, std::string> cacheMap;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_BMS_ADAPTER_H