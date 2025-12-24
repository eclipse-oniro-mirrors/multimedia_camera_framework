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

#include "hmech_session_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include "camera_log.h"
#include "message_parcel.h"
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "accesstoken_kit.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "ipc_skeleton.h"
#include "buffer_extra_data_impl.h"
#include "capture_session.h"
#include "test_token.h"
#include "camera_service_proxy.h"
#include "hmech_session.h"

using namespace OHOS;
using namespace OHOS::CameraStandard;
sptr<HMechSession> g_hMechSession;

void EnableMechDelivery(FuzzedDataProvider& fdp)
{
    g_hMechSession->EnableMechDelivery(fdp.ConsumeBool());
}

void SetCallback(FuzzedDataProvider& fdp)
{
    auto cb = sptr<MockMechSessionCallback>::MakeSptr();
    g_hMechSession->SetCallback(cb);
}

void Release(FuzzedDataProvider& fdp)
{
    g_hMechSession->Release();
}

void Init()
{
    CHECK_RETURN_ELOG(!TestToken().GetAllCameraPermission(), "Get permission fail");
    const int32_t UID = 0;
    g_hMechSession = new HMechSession(UID);
}

void Test(FuzzedDataProvider& fdp)
{
    CHECK_RETURN_ELOG(g_hMechSession == nullptr, "g_cameraService is nullptr");
    auto func = fdp.PickValueInArray({
        EnableMechDelivery,
        SetCallback,
        Release,
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