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

#include "hstream_capture_stub_fuzzer.h"
#include "camera_log.h"
#include "hstream_capture.h"
#include "iservice_registry.h"
#include "message_parcel.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "accesstoken_kit.h"
#include "camera_metadata_info.h"
#include "metadata_utils.h"
#include "iconsumer_surface.h"
#include "camera_service_ipc_interface_code.h"
#include "securec.h"
#include <memory>
#include "hstream_capture_callback_proxy.h"

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MAX_CODE_LEN = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static const uint8_t* RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
static size_t g_dataSize = 0;
static size_t g_pos;
static constexpr int32_t MAX_CODE_NUM = 17;
std::shared_ptr<HStreamCaptureStubFuzz> HStreamCaptureStubFuzzer::fuzz_{nullptr};

/*
* describe: get data from outside untrusted data(g_data) which size is according to sizeof(T)
* tips: only support basic type
*/
template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (RAW_DATA == nullptr || objectSize > g_dataSize - g_pos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, RAW_DATA + g_pos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_pos += objectSize;
    return object;
}

template<class T>
uint32_t GetArrLength(T& arr)
{
    if (arr == nullptr) {
        MEDIA_INFO_LOG("%{public}s: The array length is equal to 0", __func__);
        return 0;
    }
    return sizeof(arr) / sizeof(arr[0]);
}

void HStreamCaptureStubFuzzer::OnRemoteRequest(int32_t code)
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    if (fuzz_ == nullptr) {
        fuzz_ = std::make_shared<HStreamCaptureStubFuzz>();
    }
    MessageParcel data;
    MessageOption option;
    MessageParcel reply;
    data.WriteInterfaceToken(HStreamCaptureStubFuzz::GetDescriptor());
    data.WriteBuffer(RAW_DATA + sizeof(uint32_t), g_dataSize - sizeof(uint32_t));
    data.RewindRead(0);
    fuzz_->OnRemoteRequest(code, data, reply, option);
}

void HStreamCaptureStubFuzzer::HStreamCaptureStubFuzzTest1()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    auto fuzz = std::make_shared<HStreamCaptureStubFuzz>();
    MessageParcel data;
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    CHECK_ERROR_RETURN(photoSurface == nullptr);
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    data.WriteBool(1);
    data.WriteRemoteObject(producer->AsObject());
    fuzz->HandleSetBufferProducerInfo(data);
    fuzz->HandleSetThumbnail(data);
}

void HStreamCaptureStubFuzzer::HStreamCaptureStubFuzzTest2()
{
    auto fuzz = std::make_shared<HStreamCaptureStubFuzz>();
    MessageParcel data;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    static const int32_t audioPolicyServiceId = 3009;
    auto object = samgr->GetSystemAbility(audioPolicyServiceId);
    auto proxy = std::make_shared<HStreamCaptureCallbackProxy>(object);
    data.WriteRemoteObject(proxy->AsObject());
    fuzz->HandleSetCallback(data);
}

void Test()
{
    auto hstreamCaptureStub = std::make_unique<HStreamCaptureStubFuzzer>();
    if (hstreamCaptureStub == nullptr) {
        MEDIA_INFO_LOG("hstreamCaptureStub is null");
        return;
    }
    for (uint32_t i = 0; i <= MAX_CODE_NUM; i++) {
        hstreamCaptureStub->OnRemoteRequest(i);
    }
    hstreamCaptureStub->HStreamCaptureStubFuzzTest1();
    hstreamCaptureStub->HStreamCaptureStubFuzzTest2();
}

typedef void (*TestFuncs[1])();

TestFuncs g_testFuncs = {
    Test,
};

bool FuzzTest(const uint8_t* rawData, size_t size)
{
    // initialize data
    RAW_DATA = rawData;
    g_dataSize = size;
    g_pos = 0;

    uint32_t code = GetData<uint32_t>();
    uint32_t len = GetArrLength(g_testFuncs);
    if (len > 0) {
        g_testFuncs[code % len]();
    } else {
        MEDIA_INFO_LOG("%{public}s: The len length is equal to 0", __func__);
    }

    return true;
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    if (size < OHOS::CameraStandard::THRESHOLD) {
        return 0;
    }

    OHOS::CameraStandard::FuzzTest(data, size);
    return 0;
}