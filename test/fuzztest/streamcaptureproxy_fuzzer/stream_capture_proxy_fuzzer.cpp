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

#include "stream_capture_proxy_fuzzer.h"

#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_log.h"
#include "hap_token_info.h"
#include "icapture_session.h"
#include "iconsumer_surface.h"
#include "iservice_registry.h"
#include "istream_common.h"
#include "ipc_skeleton.h"
#include "metadata_utils.h"
#include "nativetoken_kit.h"
#include "system_ability_definition.h"
#include "token_setproc.h"
#include <fuzzer/FuzzedDataProvider.h>

using namespace std;

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MIN_SIZE_NUM = 64;
static constexpr int32_t ITEM_COUNT = 10;
static constexpr int32_t DATA_SIZE = 100;
std::shared_ptr<StreamCaptureProxy> StreamCaptureProxyFuzzer::fuzz_{nullptr};

void StreamCaptureProxyFuzzer::StreamCaptureProxyFuzzTest1(FuzzedDataProvider& fdp)
{
    sptr<IRemoteObject> remote = nullptr;
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    std::shared_ptr<OHOS::Camera::CameraMetadata> ability;
    ability = std::make_shared<OHOS::Camera::CameraMetadata>(ITEM_COUNT, DATA_SIZE);
    fuzz_->Capture(ability);

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr nullptr");
    remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ nullptr");
    fuzz_->Capture(ability);
}

void StreamCaptureProxyFuzzer::StreamCaptureProxyFuzzTest2(FuzzedDataProvider& fdp)
{
    sptr<IRemoteObject> remote = nullptr;
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    fuzz_->CancelCapture();

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr nullptr");
    remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ nullptr");
    fuzz_->CancelCapture();
}

void StreamCaptureProxyFuzzer::StreamCaptureProxyFuzzTest3(FuzzedDataProvider& fdp)
{
    sptr<IRemoteObject> remote = nullptr;
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    sptr<IStreamCaptureCallback> callback;
    fuzz_->SetCallback(callback);

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr nullptr");
    remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ nullptr");
    fuzz_->SetCallback(callback);
}

void StreamCaptureProxyFuzzer::StreamCaptureProxyFuzzTest4(FuzzedDataProvider& fdp)
{
    sptr<IRemoteObject> remote = nullptr;
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    fuzz_->Release();

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr nullptr");
    remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ nullptr");
    fuzz_->Release();
}

void StreamCaptureProxyFuzzer::StreamCaptureProxyFuzzTest5(FuzzedDataProvider& fdp)
{
    sptr<IRemoteObject> remote = nullptr;
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    bool isEnabled = fdp.ConsumeBool();
    fuzz_->SetThumbnail(isEnabled);

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr nullptr");
    remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ nullptr");
    fuzz_->SetThumbnail(isEnabled);
}

void StreamCaptureProxyFuzzer::StreamCaptureProxyFuzzTest6(FuzzedDataProvider& fdp)
{
    sptr<IRemoteObject> remote = nullptr;
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    fuzz_->ConfirmCapture();

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr nullptr");
    remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ nullptr");
    fuzz_->ConfirmCapture();
}

void StreamCaptureProxyFuzzer::StreamCaptureProxyFuzzTest7(FuzzedDataProvider& fdp)
{
    sptr<IRemoteObject> remote = nullptr;
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    int32_t type = fdp.ConsumeIntegral<int32_t>();
    fuzz_->DeferImageDeliveryFor(type);

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr nullptr");
    remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ nullptr");
    fuzz_->DeferImageDeliveryFor(type);
}

void StreamCaptureProxyFuzzer::StreamCaptureProxyFuzzTest8(FuzzedDataProvider& fdp)
{
    sptr<IRemoteObject> remote = nullptr;
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    fuzz_->IsDeferredPhotoEnabled();

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr nullptr");
    remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ nullptr");
    fuzz_->IsDeferredPhotoEnabled();
}

void StreamCaptureProxyFuzzer::StreamCaptureProxyFuzzTest9(FuzzedDataProvider& fdp)
{
    sptr<IRemoteObject> remote = nullptr;
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    fuzz_->IsDeferredVideoEnabled();

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr nullptr");
    remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ nullptr");
    fuzz_->IsDeferredVideoEnabled();
}

void StreamCaptureProxyFuzzer::StreamCaptureProxyFuzzTest10(FuzzedDataProvider& fdp)
{
    sptr<IRemoteObject> remote = nullptr;
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    std::vector<std::string> bufferNames = {"rawImage",
        "gainmapImage", "deepImage", "exifImage", "debugImage"};
    size_t ind = fdp.ConsumeIntegral<size_t>() % bufferNames.size();
    std::string name = bufferNames[ind];
    sptr<IBufferProducer> producer = nullptr;
    fuzz_->SetBufferProducerInfo(name, producer);

    sptr<Surface> photoSurface;
    photoSurface = Surface::CreateSurfaceAsConsumer("streamcaptureproxy");
    producer = photoSurface->GetProducer();
    fuzz_->SetBufferProducerInfo(name, producer);

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr nullptr");
    remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ nullptr");
    fuzz_->SetBufferProducerInfo(name, producer);
}

void StreamCaptureProxyFuzzer::StreamCaptureProxyFuzzTest11(FuzzedDataProvider& fdp)
{
    sptr<IRemoteObject> remote = nullptr;
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    int32_t type = fdp.ConsumeIntegral<int32_t>();
    fuzz_->SetMovingPhotoVideoCodecType(type);

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr nullptr");
    remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ nullptr");
    fuzz_->SetMovingPhotoVideoCodecType(type);
}

void StreamCaptureProxyFuzzer::StreamCaptureProxyFuzzTest12(FuzzedDataProvider& fdp)
{
    sptr<IRemoteObject> remote = nullptr;
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    bool isEnabled = fdp.ConsumeBool();
    fuzz_->EnableRawDelivery(isEnabled);

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr nullptr");
    remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ nullptr");
    fuzz_->EnableRawDelivery(isEnabled);
}

void StreamCaptureProxyFuzzer::StreamCaptureProxyFuzzTest13(FuzzedDataProvider& fdp)
{
    sptr<IRemoteObject> remote = nullptr;
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    bool isEnabled = fdp.ConsumeBool();
    fuzz_->SetCameraPhotoRotation(isEnabled);

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr nullptr");
    remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ nullptr");
    fuzz_->SetCameraPhotoRotation(isEnabled);
}

void StreamCaptureProxyFuzzer::StreamCaptureProxyFuzzTest14(FuzzedDataProvider& fdp)
{
    sptr<IRemoteObject> remote = nullptr;
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    bool isEnabled = fdp.ConsumeBool();
    fuzz_->EnableMovingPhoto(isEnabled);

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr nullptr");
    remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ nullptr");
    fuzz_->EnableMovingPhoto(isEnabled);
}

void StreamCaptureProxyFuzzer::StreamCaptureProxyFuzzTest15(FuzzedDataProvider& fdp)
{
    sptr<IRemoteObject> remote = nullptr;
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    fuzz_->UnSetCallback();

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr nullptr");
    remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ nullptr");
    fuzz_->UnSetCallback();
}

void StreamCaptureProxyFuzzer::StreamCaptureProxyFuzzTest16(FuzzedDataProvider& fdp)
{
    sptr<IRemoteObject> remote = nullptr;
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    bool isEnabled = fdp.ConsumeBool();
    fuzz_->EnableOfflinePhoto(isEnabled);

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr nullptr");
    remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ nullptr");
    fuzz_->EnableOfflinePhoto(isEnabled);
}

void StreamCaptureProxyFuzzer::StreamCaptureProxyFuzzTest17(FuzzedDataProvider& fdp)
{
    sptr<IRemoteObject> remote = nullptr;
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    sptr<IStreamCapturePhotoCallback> callback;
    fuzz_->SetPhotoAvailableCallback(callback);

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr nullptr");
    remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ nullptr");
    fuzz_->SetPhotoAvailableCallback(callback);
}

void StreamCaptureProxyFuzzer::StreamCaptureProxyFuzzTest18(FuzzedDataProvider& fdp)
{
    sptr<IRemoteObject> remote = nullptr;
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    sptr<IStreamCaptureThumbnailCallback> callback;
    fuzz_->SetThumbnailCallback(callback);

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr nullptr");
    remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ nullptr");
    fuzz_->SetThumbnailCallback(callback);
}

void StreamCaptureProxyFuzzer::StreamCaptureProxyFuzzTest19(FuzzedDataProvider& fdp)
{
    sptr<IRemoteObject> remote = nullptr;
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    sptr<IStreamCapturePhotoAssetCallback> callback;
    fuzz_->SetPhotoAssetAvailableCallback(callback);

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr nullptr");
    remote = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    fuzz_ = std::make_shared<StreamCaptureProxy>(remote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ nullptr");
    fuzz_->SetPhotoAssetAvailableCallback(callback);
}

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    auto streamCaptureProxy = std::make_unique<StreamCaptureProxyFuzzer>();
    if (streamCaptureProxy == nullptr) {
        MEDIA_INFO_LOG("streamCaptureProxy is null");
        return;
    }
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    streamCaptureProxy->StreamCaptureProxyFuzzTest1(fdp);
    streamCaptureProxy->StreamCaptureProxyFuzzTest2(fdp);
    streamCaptureProxy->StreamCaptureProxyFuzzTest3(fdp);
    streamCaptureProxy->StreamCaptureProxyFuzzTest4(fdp);
    streamCaptureProxy->StreamCaptureProxyFuzzTest5(fdp);
    streamCaptureProxy->StreamCaptureProxyFuzzTest6(fdp);
    streamCaptureProxy->StreamCaptureProxyFuzzTest7(fdp);
    streamCaptureProxy->StreamCaptureProxyFuzzTest8(fdp);
    streamCaptureProxy->StreamCaptureProxyFuzzTest9(fdp);
    streamCaptureProxy->StreamCaptureProxyFuzzTest10(fdp);
    streamCaptureProxy->StreamCaptureProxyFuzzTest11(fdp);
    streamCaptureProxy->StreamCaptureProxyFuzzTest12(fdp);
    streamCaptureProxy->StreamCaptureProxyFuzzTest13(fdp);
    streamCaptureProxy->StreamCaptureProxyFuzzTest14(fdp);
    streamCaptureProxy->StreamCaptureProxyFuzzTest15(fdp);
    streamCaptureProxy->StreamCaptureProxyFuzzTest16(fdp);
    streamCaptureProxy->StreamCaptureProxyFuzzTest17(fdp);
    streamCaptureProxy->StreamCaptureProxyFuzzTest18(fdp);
    streamCaptureProxy->StreamCaptureProxyFuzzTest19(fdp);
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::CameraStandard::Test(data, size);
    return 0;
}
