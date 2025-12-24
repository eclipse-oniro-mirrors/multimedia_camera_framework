/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "hstream_metadata_fuzzer.h"
#include "camera_log.h"
#include "hstream_capture.h"
#include "iservice_registry.h"
#include "message_parcel.h"
#include "accesstoken_kit.h"
#include "camera_metadata_info.h"
#include "metadata_utils.h"
#include "iconsumer_surface.h"
#include "securec.h"
#include "stream_metadata_callback_proxy.h"
#include "hstream_metadata.h"
#include <fuzzer/FuzzedDataProvider.h>
#include "fuzz_util.h"
#include "test_token.h"

using namespace OHOS;
using namespace OHOS::CameraStandard;
static sptr<IStreamMetadata> g_hStreamMetadata;

void Start(FuzzedDataProvider& fdp)
{
    g_hStreamMetadata->Start();
}

void Stop(FuzzedDataProvider& fdp)
{
    g_hStreamMetadata->Stop();
}

void Release(FuzzedDataProvider& fdp)
{
    g_hStreamMetadata->Release();
}

void SetCallback(FuzzedDataProvider& fdp)
{
    auto cb = sptr<MockStreamMetadataCallback>::MakeSptr();
    g_hStreamMetadata->SetCallback(cb);
}

void EnableMetadataType(FuzzedDataProvider& fdp)
{

    g_hStreamMetadata->EnableMetadataType(ConsumeRandomVector<int32_t>(fdp));
}

void DisableMetadataType(FuzzedDataProvider& fdp)
{
    g_hStreamMetadata->DisableMetadataType(ConsumeRandomVector<int32_t>(fdp));
}

void UnSetCallback(FuzzedDataProvider& fdp)
{
    g_hStreamMetadata->UnSetCallback();
}

void AddMetadataType(FuzzedDataProvider& fdp)
{
    g_hStreamMetadata->AddMetadataType(ConsumeRandomVector<int32_t>(fdp));
}

void RemoveMetadataType(FuzzedDataProvider& fdp)
{
    g_hStreamMetadata->RemoveMetadataType(ConsumeRandomVector<int32_t>(fdp));
}

void Init()
{
    CHECK_RETURN_ELOG(!TestToken().GetAllCameraPermission(), "Get permission fail");
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    g_hStreamMetadata = new HStreamMetadata(producer, OHOS_CAMERA_FORMAT_RGBA_8888, { 1 });
}

void Test(FuzzedDataProvider& fdp)
{
    CHECK_RETURN_ELOG(g_hStreamMetadata==nullptr,"g_hStreamMetadata is nullptr");
    auto func = fdp.PickValueInArray({
        Start,
        Stop,
        Release,
        SetCallback,
        EnableMetadataType,
        DisableMetadataType,
        UnSetCallback,
        AddMetadataType,
        RemoveMetadataType,
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