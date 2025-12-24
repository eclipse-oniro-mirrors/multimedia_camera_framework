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

#include "hstream_repeat_callback_stub_fuzzer.h"
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

namespace OHOS {
namespace CameraStandard {
const size_t THRESHOLD = 10;
static constexpr int32_t NUM_1 = 1;
static const std::u16string g_interfaceToken = u"OHOS.CameraStandard.IStreamRepeatCallback";
std::shared_ptr<HStreamRepeatCallbackStubFuzz> HStreamRepeatCallbackStubFuzzer::fuzz_{nullptr};

void HStreamRepeatCallbackStubFuzzer::HStreamRepeatCallbackStubFuzzTest1()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(g_interfaceToken);
    fuzz_->OnRemoteRequest(
        static_cast<uint32_t>(IStreamRepeatCallbackIpcCode::COMMAND_ON_FRAME_STARTED), data, reply, option);
}

void HStreamRepeatCallbackStubFuzzer::HStreamRepeatCallbackStubFuzzTest2(FuzzedDataProvider &fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto frameCount = fdp.ConsumeIntegral<int32_t>();
    data.WriteInterfaceToken(g_interfaceToken);
    data.WriteInt32(frameCount);
    fuzz_->OnRemoteRequest(
        static_cast<uint32_t>(IStreamRepeatCallbackIpcCode::COMMAND_ON_FRAME_ENDED), data, reply, option);
}

void HStreamRepeatCallbackStubFuzzer::HStreamRepeatCallbackStubFuzzTest3(FuzzedDataProvider &fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto errorCode = fdp.ConsumeIntegral<int32_t>();
    data.WriteInterfaceToken(g_interfaceToken);
    data.WriteInt32(errorCode);
    fuzz_->OnRemoteRequest(
        static_cast<uint32_t>(IStreamRepeatCallbackIpcCode::COMMAND_ON_FRAME_ERROR), data, reply, option);
}

void HStreamRepeatCallbackStubFuzzer::HStreamRepeatCallbackStubFuzzTest4(FuzzedDataProvider &fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(g_interfaceToken);
    constexpr int32_t executionModeCount = static_cast<int32_t>(SketchStatus::STARTING) + NUM_1;
    SketchStatus status = static_cast<SketchStatus>(fdp.ConsumeIntegral<uint8_t>() % executionModeCount);
    data.WriteInt32(static_cast<int32_t>(status));
    fuzz_->OnRemoteRequest(
        static_cast<uint32_t>(IStreamRepeatCallbackIpcCode::COMMAND_ON_SKETCH_STATUS_CHANGED), data, reply, option);
}

void HStreamRepeatCallbackStubFuzzer::HStreamRepeatCallbackStubFuzzTest5()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(g_interfaceToken);
    fuzz_->OnRemoteRequest(
        static_cast<uint32_t>(IStreamRepeatCallbackIpcCode::COMMAND_ON_FRAME_PAUSED), data, reply, option);
}

void HStreamRepeatCallbackStubFuzzer::HStreamRepeatCallbackStubFuzzTest6()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(g_interfaceToken);
    fuzz_->OnRemoteRequest(
        static_cast<uint32_t>(IStreamRepeatCallbackIpcCode::COMMAND_ON_FRAME_RESUMED), data, reply, option);
}

void FuzzTest(const uint8_t *rawData, size_t size)
{
    FuzzedDataProvider fdp(rawData, size);
    auto hStreamRepeatCallbackStub = std::make_unique<HStreamRepeatCallbackStubFuzzer>();
    if (hStreamRepeatCallbackStub == nullptr) {
        MEDIA_INFO_LOG("hStreamRepeatCallbackStub is null");
        return;
    }
    HStreamRepeatCallbackStubFuzzer::fuzz_ = std::make_shared<HStreamRepeatCallbackStubFuzz>();
    if (HStreamRepeatCallbackStubFuzzer::fuzz_ == nullptr) {
        MEDIA_INFO_LOG("fuzz_ is null");
        return;
    }
    hStreamRepeatCallbackStub->HStreamRepeatCallbackStubFuzzTest1();
    hStreamRepeatCallbackStub->HStreamRepeatCallbackStubFuzzTest2(fdp);
    hStreamRepeatCallbackStub->HStreamRepeatCallbackStubFuzzTest3(fdp);
    hStreamRepeatCallbackStub->HStreamRepeatCallbackStubFuzzTest4(fdp);
    hStreamRepeatCallbackStub->HStreamRepeatCallbackStubFuzzTest5();
    hStreamRepeatCallbackStub->HStreamRepeatCallbackStubFuzzTest6();
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