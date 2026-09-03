/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <fuzzer/FuzzedDataProvider.h>
#include <memory>
#include <vector>
#include <string>
#include <cstdint>
#include "camera_error_code.h"
#include "ability/camera_ability_enum.h"
#include "session/features/control_ring_feature.h"
#include "icapture_session.h"
#include "iremote_object.h"
#include "fuzz_util.h"
#include "test_token.h"
#include "camera_log.h"
#include "capture_session.h"

using namespace OHOS;
using namespace CameraStandard;

static void TestSetControlRingMode(FuzzedDataProvider& fdp)
{
    sptr<ICaptureSession> captureSession = nullptr;
    auto controlRingFeature = std::make_shared<ControlRingFeature>(captureSession);
    if (!controlRingFeature) {
        return;
    }

    int32_t mode = fdp.ConsumeIntegral<int32_t>();
    (void)controlRingFeature->SetControlRingMode(mode);
}

static void TestSetControlRingSpeed(FuzzedDataProvider& fdp)
{
    sptr<ICaptureSession> captureSession = nullptr;
    auto controlRingFeature = std::make_shared<ControlRingFeature>(captureSession);
    if (!controlRingFeature) {
        return;
    }

    std::vector<int32_t> speeds;
    int32_t speedCount = fdp.ConsumeIntegralInRange<int32_t>(1, 3);
    for (int32_t i = 0; i < speedCount; i++) {
        speeds.push_back(fdp.ConsumeIntegral<int32_t>());
    }

    (void)controlRingFeature->SetControlRingSpeed(speeds);
}

static void TestGetControlRingMode(FuzzedDataProvider& fdp)
{
    sptr<ICaptureSession> captureSession = nullptr;
    auto controlRingFeature = std::make_shared<ControlRingFeature>(captureSession);
    if (!controlRingFeature) {
        return;
    }

    ControlRingMode mode = PickEnumInRange<ControlRingMode>(
        fdp, ControlRingMode::CONTROL_RING_MODE_ZOOM, ControlRingMode::CONTROL_RING_MODE_VA);
    (void)controlRingFeature->GetControlRingMode(mode);
}

static void TestGetVariableApertureInfo(FuzzedDataProvider& fdp)
{
    sptr<ICaptureSession> captureSession = nullptr;
    auto controlRingFeature = std::make_shared<ControlRingFeature>(captureSession);
    if (!controlRingFeature) {
        return;
    }

    VariableApertureInfo info;
    (void)controlRingFeature->GetVariableApertureInfo(info);
}

static void TestGetSupportedControlRingMode(FuzzedDataProvider& fdp)
{
    sptr<ICaptureSession> captureSession = nullptr;
    auto controlRingFeature = std::make_shared<ControlRingFeature>(captureSession);
    if (!controlRingFeature) {
        return;
    }

    std::vector<ControlRingMode> modes;
    (void)controlRingFeature->GetSupportedControlRingMode(modes);
}

static void TestGetControlRingPhotoSpeed(FuzzedDataProvider& fdp)
{
    sptr<ICaptureSession> captureSession = nullptr;
    auto controlRingFeature = std::make_shared<ControlRingFeature>(captureSession);
    if (!controlRingFeature) {
        return;
    }

    ControlRingSpeed speed = PickEnumInRange<ControlRingSpeed>(
        fdp, ControlRingSpeed::CONTROL_RING_SPEED_FAST, ControlRingSpeed::CONTROL_RING_SPEED_SLOW);
    (void)controlRingFeature->GetControlRingPhotoSpeed(speed);
}

static void TestGetControlRingVideoSpeed(FuzzedDataProvider& fdp)
{
    sptr<ICaptureSession> captureSession = nullptr;
    auto controlRingFeature = std::make_shared<ControlRingFeature>(captureSession);
    if (!controlRingFeature) {
        return;
    }

    ControlRingSpeed speed = PickEnumInRange<ControlRingSpeed>(
        fdp, ControlRingSpeed::CONTROL_RING_SPEED_FAST, ControlRingSpeed::CONTROL_RING_SPEED_SLOW);
    (void)controlRingFeature->GetControlRingVideoSpeed(speed);
}

static void TestGetSupportedControlRingSpeed(FuzzedDataProvider& fdp)
{
    sptr<ICaptureSession> captureSession = nullptr;
    auto controlRingFeature = std::make_shared<ControlRingFeature>(captureSession);
    if (!controlRingFeature) {
        return;
    }

    std::vector<ControlRingSpeed> speeds;
    (void)controlRingFeature->GetSupportedControlRingSpeed(speeds);
}

static void TestUpdateControlRingMode(FuzzedDataProvider& fdp)
{
    sptr<ICaptureSession> captureSession = nullptr;
    auto controlRingFeature = std::make_shared<ControlRingFeature>(captureSession);
    if (!controlRingFeature) {
        return;
    }

    ControlRingMode mode = PickEnumInRange<ControlRingMode>(
        fdp, ControlRingMode::CONTROL_RING_MODE_ZOOM, ControlRingMode::CONTROL_RING_MODE_VA);
    controlRingFeature->UpdateControlRingMode(mode);
}

static void TestUpdateControlRingPhotoSpeed(FuzzedDataProvider& fdp)
{
    sptr<ICaptureSession> captureSession = nullptr;
    auto controlRingFeature = std::make_shared<ControlRingFeature>(captureSession);
    if (!controlRingFeature) {
        return;
    }

    ControlRingSpeed speed = PickEnumInRange<ControlRingSpeed>(
        fdp, ControlRingSpeed::CONTROL_RING_SPEED_FAST, ControlRingSpeed::CONTROL_RING_SPEED_SLOW);
    controlRingFeature->UpdateControlRingPhotoSpeed(speed);
}

static void TestUpdateControlRingVideoSpeed(FuzzedDataProvider& fdp)
{
    sptr<ICaptureSession> captureSession = nullptr;
    auto controlRingFeature = std::make_shared<ControlRingFeature>(captureSession);
    if (!controlRingFeature) {
        return;
    }

    ControlRingSpeed speed = PickEnumInRange<ControlRingSpeed>(
        fdp, ControlRingSpeed::CONTROL_RING_SPEED_FAST, ControlRingSpeed::CONTROL_RING_SPEED_SLOW);
    controlRingFeature->UpdateControlRingVideoSpeed(speed);
}

static void Test(FuzzedDataProvider& fdp)
{
    auto func = fdp.PickValueInArray({
        TestSetControlRingMode,
        TestSetControlRingSpeed,
        TestGetControlRingMode,
        TestGetVariableApertureInfo,
        TestGetSupportedControlRingMode,
        TestGetControlRingPhotoSpeed,
        TestGetControlRingVideoSpeed,
        TestGetSupportedControlRingSpeed,
        TestUpdateControlRingMode,
        TestUpdateControlRingPhotoSpeed,
        TestUpdateControlRingVideoSpeed,
    });
    func(fdp);
}

static void Init()
{
    CHECK_RETURN_ELOG(!TestToken().GetAllCameraPermission(), "Get permission fail");
}

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    Init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    Test(fdp);
    return 0;
}