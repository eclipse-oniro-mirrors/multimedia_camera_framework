/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "bms_adapter_fuzzer.h"
#include "foundation/multimedia/camera_framework/common/utils/camera_log.h"
#include "message_parcel.h"
#include "system_ability_definition.h"
#include "securec.h"
#include "iservice_registry.h"
#include "token_setproc.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>

namespace OHOS {
namespace CameraStandard {
using RemoveCallback = std::function<void()>;
const size_t MAX_LENGTH_STRING = 64;
static const int32_t MIN_SIZE_NUM = 68;

std::shared_ptr<BmsAdapter> BmsAdapterFuzzer::fuzz_ {nullptr};
std::shared_ptr<BmsSaListener> BmsSaListenerFuzzer::bmsfuzz_ {nullptr};

/*
* describe: get data from outside untrusted data(g_data) which size is according to sizeof(T)
* tips: only support basic type
*/

void BmsAdapterFuzzer::Initialize()
{
    fuzz_ = std::make_shared<BmsAdapter>();
    CHECK_RETURN_ELOG(!fuzz_, "Create fuzz_ Error");

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (object == nullptr) {
        return;
    }
    sptr<OHOS::AppExecFwk::IBundleMgr> bms = iface_cast<OHOS::AppExecFwk::IBundleMgr>(object);
    fuzz_->SetBms(bms);
}

void BmsSaListenerFuzzer::BmsSaListenerFuzzTest(FuzzedDataProvider& fdp)
{
    if (bmsfuzz_ == nullptr) {
        auto bmsAdapterWptr = wptr<BmsAdapter>();
        auto removeCallback = [bmsAdapterWptr]() {
            auto adapter = bmsAdapterWptr.promote();
            if (adapter) {
                adapter->SetBms(nullptr);
            }
        };
        bmsfuzz_ = std::make_shared<BmsSaListener>(removeCallback);
    }
    int32_t systemAbilityId = fdp.ConsumeIntegral<int32_t>();
    std::string deviceId(fdp.ConsumeRandomLengthString(MAX_LENGTH_STRING));
    bmsfuzz_->OnAddSystemAbility(systemAbilityId, deviceId);
    bmsfuzz_->OnRemoveSystemAbility(systemAbilityId, deviceId);
}

void Test(uint8_t* data, size_t size)
{
    auto bmsSaListener = std::make_unique<BmsSaListenerFuzzer>();
    auto bmsAdapterFuzzer = std::make_unique<BmsAdapterFuzzer>();
    if (bmsSaListener == nullptr) {
        MEDIA_INFO_LOG("bmsSaListener is null");
        return;
    }
    if (bmsAdapterFuzzer == nullptr) {
        MEDIA_INFO_LOG("bmsAdapterFuzzer is null");
        return;
    }
    
    FuzzedDataProvider fdp(data, size);
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    bmsSaListener->BmsSaListenerFuzzTest(fdp);
    bmsAdapterFuzzer->Initialize();
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}