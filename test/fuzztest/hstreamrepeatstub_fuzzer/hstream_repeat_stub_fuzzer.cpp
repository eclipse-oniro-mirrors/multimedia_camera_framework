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

#include "hstream_repeat_stub_fuzzer.h"
#include "camera_log.h"
#include "hstream_repeat.h"
#include "iservice_registry.h"
#include "message_parcel.h"
#include "nativetoken_kit.h"
#include "string_ex.h"
#include "token_setproc.h"
#include "accesstoken_kit.h"
#include "camera_metadata_info.h"
#include "metadata_utils.h"
#include "iconsumer_surface.h"
#include "securec.h"
#include "stream_repeat_callback_proxy.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"

namespace OHOS {
namespace CameraStandard {
const size_t THRESHOLD = 10;
static const std::u16string g_interfaceToken = u"OHOS.CameraStandard.IStreamRepeat";
std::shared_ptr<HStreamRepeatStubFuzz> HStreamRepeatStubFuzzer::fuzz_{nullptr};

void HStreamRepeatStubFuzzer::HStreamRepeatStubFuzzTest1()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(g_interfaceToken);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamRepeatIpcCode::COMMAND_START), data, reply, option);
}

void HStreamRepeatStubFuzzer::HStreamRepeatStubFuzzTest2()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(g_interfaceToken);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamRepeatIpcCode::COMMAND_STOP), data, reply, option);
}

void HStreamRepeatStubFuzzer::HStreamRepeatStubFuzzTest3()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    auto proxy = std::make_shared<StreamRepeatCallbackProxy>(object);
    data.WriteInterfaceToken(g_interfaceToken);
    data.WriteRemoteObject(proxy->AsObject());
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamRepeatIpcCode::COMMAND_SET_CALLBACK), data, reply, option);
}

void HStreamRepeatStubFuzzer::HStreamRepeatStubFuzzTest4()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(g_interfaceToken);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamRepeatIpcCode::COMMAND_RELEASE), data, reply, option);
}

void HStreamRepeatStubFuzzer::HStreamRepeatStubFuzzTest5()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    CHECK_RETURN(photoSurface == nullptr);
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    data.WriteInterfaceToken(g_interfaceToken);
    data.WriteRemoteObject(producer->AsObject());
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamRepeatIpcCode::COMMAND_ADD_DEFERRED_SURFACE), data, reply, option);
}

void HStreamRepeatStubFuzzer::HStreamRepeatStubFuzzTest6(FuzzedDataProvider &fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto width = fdp.ConsumeIntegral<int32_t>();
    auto height = fdp.ConsumeIntegral<int32_t>();
    auto sketchRatio = fdp.ConsumeFloatingPoint<float>();
    data.WriteInterfaceToken(g_interfaceToken);
    data.WriteInt32(width);
    data.WriteInt32(height);
    data.WriteFloat(sketchRatio);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamRepeatIpcCode::COMMAND_FORK_SKETCH_STREAM_REPEAT), data, reply, option);
}

void HStreamRepeatStubFuzzer::HStreamRepeatStubFuzzTest7()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(g_interfaceToken);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamRepeatIpcCode::COMMAND_REMOVE_SKETCH_STREAM_REPEAT), data, reply, option);
}

void HStreamRepeatStubFuzzer::HStreamRepeatStubFuzzTest8(FuzzedDataProvider &fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto sketchRatio = fdp.ConsumeFloatingPoint<float>();
    data.WriteInterfaceToken(g_interfaceToken);
    data.WriteFloat(sketchRatio);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamRepeatIpcCode::COMMAND_UPDATE_SKETCH_RATIO), data, reply, option);
}

void HStreamRepeatStubFuzzer::HStreamRepeatStubFuzzTest9(FuzzedDataProvider &fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto minFrameRate = fdp.ConsumeIntegral<int32_t>();
    auto maxFrameRate = fdp.ConsumeIntegral<int32_t>();
    data.WriteInterfaceToken(g_interfaceToken);
    data.WriteInt32(minFrameRate);
    data.WriteInt32(maxFrameRate);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamRepeatIpcCode::COMMAND_SET_FRAME_RATE), data, reply, option);
}

void HStreamRepeatStubFuzzer::HStreamRepeatStubFuzzTest10(FuzzedDataProvider &fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto isEnable = fdp.ConsumeIntegral<int32_t>();
    data.WriteInterfaceToken(g_interfaceToken);
    data.WriteInt32(isEnable ? 1 : 0);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamRepeatIpcCode::COMMAND_ENABLE_SECURE), data, reply, option);
}

void HStreamRepeatStubFuzzer::HStreamRepeatStubFuzzTest11(FuzzedDataProvider &fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto isEnable = fdp.ConsumeIntegral<int32_t>();
    data.WriteInterfaceToken(g_interfaceToken);
    data.WriteInt32(isEnable ? 1 : 0);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamRepeatIpcCode::COMMAND_SET_MIRROR), data, reply, option);
}

void HStreamRepeatStubFuzzer::HStreamRepeatStubFuzzTest12(FuzzedDataProvider &fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto videoMetaType = fdp.ConsumeIntegral<int32_t>();
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    CHECK_RETURN(photoSurface == nullptr);
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    data.WriteInterfaceToken(g_interfaceToken);
    data.WriteInt32(videoMetaType);
    data.WriteRemoteObject(producer->AsObject());
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamRepeatIpcCode::COMMAND_ATTACH_META_SURFACE), data, reply, option);
}

void HStreamRepeatStubFuzzer::HStreamRepeatStubFuzzTest13(FuzzedDataProvider &fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto isEnable = fdp.ConsumeIntegral<int32_t>();
    auto rotation = fdp.ConsumeIntegral<int32_t>();
    data.WriteInterfaceToken(g_interfaceToken);
    data.WriteInt32(isEnable ? 1 : 0);
    data.WriteInt32(rotation);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamRepeatIpcCode::COMMAND_SET_CAMERA_ROTATION), data, reply, option);
}

void HStreamRepeatStubFuzzer::HStreamRepeatStubFuzzTest14(FuzzedDataProvider &fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto apiCompatibleVersion = fdp.ConsumeIntegral<uint32_t>();
    data.WriteInterfaceToken(g_interfaceToken);
    data.WriteInt32(apiCompatibleVersion);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamRepeatIpcCode::COMMAND_SET_CAMERA_API), data, reply, option);
}

void HStreamRepeatStubFuzzer::HStreamRepeatStubFuzzTest15()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(g_interfaceToken);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamRepeatIpcCode::COMMAND_GET_MIRROR), data, reply, option);
}

void HStreamRepeatStubFuzzer::HStreamRepeatStubFuzzTest16()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(g_interfaceToken);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamRepeatIpcCode::COMMAND_UN_SET_CALLBACK), data, reply, option);
}

void FuzzTest(const uint8_t *rawData, size_t size)
{
    FuzzedDataProvider fdp(rawData, size);
    auto hStreamRepeatStub = std::make_unique<HStreamRepeatStubFuzzer>();
    if (hStreamRepeatStub == nullptr) {
        MEDIA_INFO_LOG("HStreamRepeatStub is null");
        return;
    }
    HStreamRepeatStubFuzzer::fuzz_ = std::make_shared<HStreamRepeatStubFuzz>();
    hStreamRepeatStub->HStreamRepeatStubFuzzTest1();
    hStreamRepeatStub->HStreamRepeatStubFuzzTest2();
    hStreamRepeatStub->HStreamRepeatStubFuzzTest3();
    hStreamRepeatStub->HStreamRepeatStubFuzzTest4();
    hStreamRepeatStub->HStreamRepeatStubFuzzTest5();
    hStreamRepeatStub->HStreamRepeatStubFuzzTest6(fdp);
    hStreamRepeatStub->HStreamRepeatStubFuzzTest7();
    hStreamRepeatStub->HStreamRepeatStubFuzzTest8(fdp);
    hStreamRepeatStub->HStreamRepeatStubFuzzTest9(fdp);
    hStreamRepeatStub->HStreamRepeatStubFuzzTest10(fdp);
    hStreamRepeatStub->HStreamRepeatStubFuzzTest11(fdp);
    hStreamRepeatStub->HStreamRepeatStubFuzzTest12(fdp);
    hStreamRepeatStub->HStreamRepeatStubFuzzTest13(fdp);
    hStreamRepeatStub->HStreamRepeatStubFuzzTest14(fdp);
    hStreamRepeatStub->HStreamRepeatStubFuzzTest15();
    hStreamRepeatStub->HStreamRepeatStubFuzzTest16();
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