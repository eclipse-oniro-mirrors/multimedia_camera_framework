/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "stream_depth_data_proxy_fuzzer.h"
#include "camera_log.h"
#include "iconsumer_surface.h"
#include "securec.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "output/depth_data_output.h"

namespace OHOS {
namespace CameraStandard {
const size_t THRESHOLD = 10;
std::shared_ptr<StreamDepthDataProxy> StreamDepthDataProxyFuzz::fuzz_{nullptr};

void StreamDepthDataProxyFuzz::StreamDepthDataProxyTest1()
{
    auto mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!mgr, "samgr nullptr");
    auto object = mgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!object, "object nullptr");
    fuzz_ = std::make_shared<StreamDepthDataProxy>(object);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ nullptr");
    sptr<IStreamDepthDataCallback> callbackFunc = new (std::nothrow)DepthDataOutputCallbackImpl();
    fuzz_->SetCallback(callbackFunc);
    fuzz_->UnSetCallback();
}

void StreamDepthDataProxyFuzz::StreamDepthDataProxyTest2(FuzzedDataProvider &fdp)
{
    auto mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!mgr, "samgr nullptr");
    auto object = mgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!object, "object nullptr");
    fuzz_ = std::make_shared<StreamDepthDataProxy>(object);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ nullptr");
    fuzz_->Start();
    int32_t dataAccuracy = fdp.ConsumeIntegral<int32_t>();
    fuzz_->SetDataAccuracy(dataAccuracy);
    fuzz_->Stop();
    fuzz_->Release();
}


void FuzzTest(const uint8_t *rawData, size_t size)
{
    FuzzedDataProvider fdp(rawData, size);
    auto streamDepthDataProxy = std::make_unique<StreamDepthDataProxyFuzz>();
    if (streamDepthDataProxy == nullptr) {
        MEDIA_INFO_LOG("streamDepthDataProxy is null");
        return;
    }
    streamDepthDataProxy->StreamDepthDataProxyTest1();
    streamDepthDataProxy->StreamDepthDataProxyTest2(fdp);
}
}  // namespace CameraStandard
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    if (size < OHOS::CameraStandard::THRESHOLD) {
        return 0;
    }

    OHOS::CameraStandard::FuzzTest(data, size);
    return 0;
}