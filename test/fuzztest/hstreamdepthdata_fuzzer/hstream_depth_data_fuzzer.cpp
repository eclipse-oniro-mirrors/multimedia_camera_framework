/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "hstream_depth_data_fuzzer.h"
#include "foundation/multimedia/camera_framework/common/utils/camera_log.h"
#include "message_parcel.h"
#include "iconsumer_surface.h"
#include "securec.h"
#include "test_token.h"
#include <fuzzer/FuzzedDataProvider.h>

using namespace OHOS;
using namespace OHOS::CameraStandard;
using namespace OHOS::HDI::Camera::V1_0;
const int32_t PHOTO_WIDTH = 1280;
const int32_t PHOTO_HEIGHT = 960;
const int32_t PHOTO_FORMAT = 2000;
std::shared_ptr<HStreamDepthData> g_hStreamDepthData;

void Start(FuzzedDataProvider& fdp)
{
    g_hStreamDepthData->Start();
}

void Stop(FuzzedDataProvider& fdp)
{
    g_hStreamDepthData->Stop();
}

void SetCallback(FuzzedDataProvider& fdp)
{
    auto cb = sptr<MockStreamDepthDataCallback>::MakeSptr();
    g_hStreamDepthData->SetCallback(cb);
}

void SetDataAccuracy(FuzzedDataProvider& fdp)
{
    g_hStreamDepthData->SetDataAccuracy(fdp.ConsumeIntegral<int32_t>());
}

void Release(FuzzedDataProvider& fdp)
{
    g_hStreamDepthData->Release();
}

void UnSetCallback(FuzzedDataProvider& fdp)
{
    g_hStreamDepthData->UnSetCallback();
}

void Init()
{
    CHECK_RETURN_ELOG(!TestToken().GetAllCameraPermission(), "Get permission fail");
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    g_hStreamDepthData = std::make_shared<HStreamDepthData>(producer, PHOTO_FORMAT, PHOTO_WIDTH, PHOTO_HEIGHT);
}

void Test(FuzzedDataProvider& fdp)
{
    auto func = fdp.PickValueInArray({
        Start,
        Stop,
        SetCallback,
        SetDataAccuracy,
        Release,
        UnSetCallback,
    });
    func(fdp);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    Test(fdp);
    return 0;
}

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    if (SetSelfTokenID(718336240ull | (1ull << 32)) < 0) {
        return -1;
    }
    Init();
    return 0;
}