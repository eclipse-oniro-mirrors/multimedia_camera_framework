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

#include "stream_repeat_proxy_fuzzer.h"
#include "camera_log.h"
#include "iconsumer_surface.h"
#include "securec.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"

namespace OHOS {
namespace CameraStandard {
const size_t THRESHOLD = 10;
std::shared_ptr<StreamRepeatProxy> StreamRepeatProxyFuzz::fuzz_{nullptr};

void StreamRepeatProxyFuzz::StreamRepeatProxyFuzzTest(FuzzedDataProvider &fdp)
{
    auto mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (mgr == nullptr) {
        return;
    }
    auto object = mgr->GetSystemAbility(CAMERA_SERVICE_ID);
    if (object == nullptr) {
        return;
    }
    fuzz_ = std::make_shared<StreamRepeatProxy>(object);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ nullptr");
    int32_t minFrameRate = fdp.ConsumeIntegral<int32_t>();
    int32_t maxFrameRate = fdp.ConsumeIntegral<int32_t>();
    fuzz_->SetFrameRate(minFrameRate, maxFrameRate);
    bool isEnable = fdp.ConsumeIntegral<int32_t>() ? 1 : 0;
    fuzz_->EnableSecure(isEnable);
    fuzz_->SetMirror(isEnable);
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    CHECK_RETURN_ELOG(!photoSurface, "photoSurface is nullptr");
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    CHECK_RETURN_ELOG(!producer, "producer is nullptr");
    int32_t videoMetaType = fdp.ConsumeIntegral<int32_t>();
    fuzz_->AttachMetaSurface(producer, videoMetaType);
    int32_t rotation = fdp.ConsumeIntegral<int32_t>();
    fuzz_->SetCameraRotation(isEnable, rotation);
    fuzz_->SetBandwidthCompression(isEnable);
    std::vector<int32_t> supportedVideoCodecTypes;
    fuzz_->GetSupportedVideoCodecTypes(supportedVideoCodecTypes);
    MovieSettings movieSettings;
    fuzz_->SetOutputSettings(movieSettings);
    fuzz_->GetMirror(isEnable);
    fuzz_->UnSetCallback();
}

void FuzzTest(const uint8_t *rawData, size_t size)
{
    FuzzedDataProvider fdp(rawData, size);
    auto streamRepeatProxy = std::make_unique<StreamRepeatProxyFuzz>();
    if (streamRepeatProxy == nullptr) {
        MEDIA_INFO_LOG("streamRepeatProxy is null");
        return;
    }
    streamRepeatProxy->StreamRepeatProxyFuzzTest(fdp);
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