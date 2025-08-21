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

#include "camera_device_service_proxy_fuzzer.h"
#include "camera_log.h"
#include "iconsumer_surface.h"
#include "securec.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "token_setproc.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>

namespace OHOS {
namespace CameraStandard {
const size_t THRESHOLD = 10;
const int32_t MAX_BUFFER_SIZE = 16;
const int32_t NUM_10 = 10;
const int32_t NUM_100 = 100;
std::shared_ptr<CameraDeviceServiceProxy> CameraDeviceServiceProxyFuzz::fuzz_{nullptr};

void CameraDeviceServiceProxyFuzz::CameraDeviceServiceProxyTest(FuzzedDataProvider &fdp)
{
    auto mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (mgr == nullptr) {
        return;
    }
    auto object = mgr->GetSystemAbility(CAMERA_SERVICE_ID);
    if (object == nullptr) {
        return;
    }
    fuzz_ = std::make_shared<CameraDeviceServiceProxy>(object);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ nullptr");
    fuzz_->Close();
    uint8_t vectorSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_BUFFER_SIZE);
    std::vector<int32_t> results;
    for (int i = 0; i < vectorSize; ++i) {
        results.push_back(fdp.ConsumeIntegral<int32_t>());
    }
    fuzz_->GetEnabledResults(results);
    fuzz_->EnableResult(results);
    fuzz_->DisableResult(results);

    std::shared_ptr<OHOS::Camera::CameraMetadata> metaIn = nullptr;
    const int32_t defaultItems = 10;
    const int32_t defaultDataLength = 100;
    int32_t count = 1;
    int32_t isOcclusionDetected = 1;
    metaIn = std::make_shared<OHOS::Camera::CameraMetadata>(defaultItems, defaultDataLength);
    metaIn->addEntry(OHOS_STATUS_CAMERA_OCCLUSION_DETECTION, &isOcclusionDetected, count);
    std::shared_ptr<OHOS::Camera::CameraMetadata> metaOut =
        std::make_shared<OHOS::Camera::CameraMetadata>(NUM_10, NUM_100);
    fuzz_->GetStatus(metaIn, metaOut);

    auto value = fdp.ConsumeIntegral<uint8_t>();
    fuzz_->SetUsedAsPosition(value);
    fuzz_->closeDelayed();
    int32_t concurrentTypeofcamera = fdp.ConsumeIntegral<int32_t>();
    fuzz_->Open(concurrentTypeofcamera);
    fuzz_->SetDeviceRetryTime();
    uint64_t secureSeqId = fdp.ConsumeIntegral<uint64_t>();
    fuzz_->OpenSecureCamera(secureSeqId);
}

void FuzzTest(const uint8_t *rawData, size_t size)
{
    FuzzedDataProvider fdp(rawData, size);
    auto cameraDeviceServiceProxy = std::make_unique<CameraDeviceServiceProxyFuzz>();
    if (cameraDeviceServiceProxy == nullptr) {
        MEDIA_INFO_LOG("cameraDeviceServiceProxy is null");
        return;
    }
    cameraDeviceServiceProxy->CameraDeviceServiceProxyTest(fdp);
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