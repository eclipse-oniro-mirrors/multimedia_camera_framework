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

#include "camera_window_manager_client_fuzzer.h"
#include "camera_log.h"
#include "securec.h"

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MIN_SIZE_NUM = 5;
const size_t THRESHOLD = 10;

sptr<CameraWindowManagerClient> CameraWindowManagerClientFuzzer::fuzz_{nullptr};
std::shared_ptr<CameraWindowManagerClient::WMSSaStatusChangeCallback>
    CameraWindowManagerClientFuzzer::callback_{nullptr};

/*
* describe: get data from outside untrusted data(g_data) which size is according to sizeof(T)
* tips: only support basic type
*/
void CameraWindowManagerClientFuzzer::CameraWindowManagerClientFuzzTest(FuzzedDataProvider& fdp)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }

    fuzz_ = CameraWindowManagerClient::GetInstance();
    CHECK_RETURN_ELOG(!fuzz_, "Create fuzz_ Error");
    pid_t pid;
    int32_t systemAbilityId = fdp.ConsumeIntegral<int32_t>();
    uint8_t randomNum = fdp.ConsumeIntegral<uint8_t>();
    std::vector<std::string> testStrings = {"test1", "test2"};
    std::string deviceId(testStrings[randomNum % testStrings.size()]);
    fuzz_->InitWindowProxy();
    fuzz_->GetFocusWindowInfo(pid);
    fuzz_->GetWindowManagerAgent();
    if (callback_ == nullptr) {
        callback_ = std::make_shared<CameraWindowManagerClient::WMSSaStatusChangeCallback>();
    }
    callback_->OnRemoveSystemAbility(systemAbilityId, deviceId);
    fuzz_->UnregisterWindowManagerAgent();
}

void Test(uint8_t* data, size_t size)
{
    auto cameraWindowManagerClient = std::make_unique<CameraWindowManagerClientFuzzer>();
    if (cameraWindowManagerClient == nullptr) {
        MEDIA_INFO_LOG("cameraWindowManagerClient is null");
        return;
    }
    FuzzedDataProvider fdp(data, size);
    cameraWindowManagerClient->CameraWindowManagerClientFuzzTest(fdp);
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    if (size < OHOS::CameraStandard::THRESHOLD) {
        return 0;
    }

    OHOS::CameraStandard::Test(data, size);
    return 0;
}