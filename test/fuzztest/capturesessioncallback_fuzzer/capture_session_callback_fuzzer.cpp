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

#include "capture_session_callback_fuzzer.h"
#include "capture_scene_const.h"
#include "camera_log.h"
#include "input/camera_manager.h"
#include "input/camera_manager_for_sys.h"
#include "test_token.h"
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "accesstoken_kit.h"
#include "session/capture_session_for_sys.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace OHOS {
namespace CameraStandard {
namespace CaptureSessionCallbackFuzzer {
const int32_t MIN_SIZE = 20;

void TestCalculationHelper(FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("TestCalculationHelper: ENTER");
    std::vector<float> vectorA;
    std::vector<float> vectorB;

    size_t vectorSize = fdp.ConsumeIntegralInRange<size_t>(1, 10);
    for (size_t i = 0; i < vectorSize; i++) {
        vectorA.push_back(fdp.ConsumeFloatingPoint<float>());
        vectorB.push_back(fdp.ConsumeFloatingPoint<float>());
    }

    float epsilon = fdp.ConsumeFloatingPoint<float>();
    CalculationHelper::AreVectorsEqual(vectorA, vectorB, epsilon);
}

void TestPressureStatusCallback(FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("TestPressureStatusCallback: ENTER");
    auto manager = CameraManager::GetInstance();
    auto cameras = manager->GetSupportedCameras();
    CHECK_RETURN_ELOG(cameras.empty(), "GetSupportedCameras Error");

    auto session = CameraManagerForSys::GetInstance()->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    CHECK_RETURN_ELOG(!session, "CreateCaptureSessionForSys Error");

    auto input = manager->CreateCameraInput(cameras[0]);
    CHECK_RETURN_ELOG(!input, "CreateCameraInput Error");

    sptr<CaptureInput> captureInput = input;
    session->BeginConfig();
    session->AddInput(captureInput);
    session->CommitConfig();

    auto pressureCallback = sptr<PressureStatusCallback>::MakeSptr();
    pressureCallback->captureSession_ = session;
    PressureStatus status = static_cast<PressureStatus>(fdp.ConsumeIntegral<int32_t>() % 5);
    pressureCallback->OnPressureStatusChanged(status);

    session->Release();
}

void TestControlCenterEffectStatusCallback(FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("TestControlCenterEffectStatusCallback: ENTER");
    auto manager = CameraManager::GetInstance();
    auto cameras = manager->GetSupportedCameras();
    CHECK_RETURN_ELOG(cameras.empty(), "GetSupportedCameras Error");

    auto session = CameraManagerForSys::GetInstance()->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    CHECK_RETURN_ELOG(!session, "CreateCaptureSessionForSys Error");

    auto input = manager->CreateCameraInput(cameras[0]);
    CHECK_RETURN_ELOG(!input, "CreateCameraInput Error");

    sptr<CaptureInput> captureInput = input;
    session->BeginConfig();
    session->AddInput(captureInput);
    session->CommitConfig();

    auto controlCenterCallback = sptr<ControlCenterEffectStatusCallback>::MakeSptr();
    controlCenterCallback->captureSession_ = session;
    ControlCenterStatusInfo statusInfo;
    statusInfo.isActive = fdp.ConsumeBool();
    statusInfo.effectType = static_cast<ControlCenterEffectType>(fdp.ConsumeIntegral<int32_t>());
    controlCenterCallback->OnControlCenterEffectStatusChanged(statusInfo);

    session->Release();
}

void TestCameraSwitchSessionCallback(FuzzedDataProvider& fdp)
{
    MEDIA_INFO_LOG("TestCameraSwitchSessionCallback: ENTER");
    auto manager = CameraManager::GetInstance();
    auto cameras = manager->GetSupportedCameras();
    CHECK_RETURN_ELOG(cameras.empty(), "GetSupportedCameras Error");

    auto session = CameraManagerForSys::GetInstance()->CreateCaptureSessionForSys(SceneMode::CAPTURE);
    CHECK_RETURN_ELOG(!session, "CreateCaptureSessionForSys Error");

    auto input = manager->CreateCameraInput(cameras[0]);
    CHECK_RETURN_ELOG(!input, "CreateCameraInput Error");

    sptr<CaptureInput> captureInput = input;
    session->BeginConfig();
    session->AddInput(captureInput);
    session->CommitConfig();

    auto cameraSwitchCallback = sptr<CameraSwitchSessionCallback>::MakeSptr();
    cameraSwitchCallback->captureSession_ = session;

    std::string cameraId = cameras[0]->GetID();
    bool isRegisterCameraSwitchCallback = fdp.ConsumeBool();
    CaptureSessionInfo sessionInfo;
    sessionInfo.sessionMode = static_cast<int32_t>(fdp.ConsumeIntegral<int32_t>());

    cameraSwitchCallback->OnCameraActive(cameraId, isRegisterCameraSwitchCallback, sessionInfo);
    cameraSwitchCallback->OnCameraUnactive(cameraId);

    std::string destCameraId = cameras.size() > 1 ? cameras[1]->GetID() : cameraId;
    bool status = fdp.ConsumeBool();
    cameraSwitchCallback->OnCameraSwitch(cameraId, destCameraId, status);

    session->Release();
}

void Test(uint8_t* data, size_t size)
{
    CHECK_RETURN(size < MIN_SIZE);
    CHECK_RETURN_ELOG(!TestToken().GetAllCameraPermission(), "GetPermission error");

    FuzzedDataProvider fdp(data, size);

    TestCalculationHelper(fdp);
    TestPressureStatusCallback(fdp);
    TestControlCenterEffectStatusCallback(fdp);
    TestCameraSwitchSessionCallback(fdp);
}

} // CaptureSessionCallbackFuzzer
} // CameraStandard
} // OHOS

extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::CaptureSessionCallbackFuzzer::Test(data, size);
    return 0;
}
