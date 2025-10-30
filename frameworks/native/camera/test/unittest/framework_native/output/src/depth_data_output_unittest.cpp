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

#include "depth_data_output_unittest.h"

#include "gtest/gtest.h"
#include <cstdint>
#include <vector>

#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_log.h"
#include "camera_manager.h"
#include "camera_util.h"
#include "capture_output.h"
#include "capture_session.h"
#include "gmock/gmock.h"
#include "input/camera_input.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "surface.h"
#include "test_common.h"
#include "token_setproc.h"
#include "os_account_manager.h"
#include "test_token.h"

using namespace testing::ext;
using ::testing::A;
using ::testing::InSequence;
using ::testing::Mock;
using ::testing::Return;
using ::testing::_;

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;

void DepthDataOutputUnit::SetUpTestCase(void)
{
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
}

void DepthDataOutputUnit::TearDownTestCase(void) {}

void DepthDataOutputUnit::SetUp()
{
    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);
    cameraManagerForSys_ = CameraManagerForSys::GetInstance();
    ASSERT_NE(cameraManagerForSys_, nullptr);
}

void DepthDataOutputUnit::TearDown()
{
    cameraManager_ = nullptr;
    cameraManagerForSys_ = nullptr;
}

/*
 * Feature: Framework
 * Function: Test depthDataOutput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test depthDataOutput with a normal stream for normal branches
 */
HWTEST_F(DepthDataOutputUnit, depth_data_output_unittest_001, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    Size size = {640, 480};
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> surfaceProducer = surface->GetProducer();
    CameraFormat format = CAMERA_FORMAT_DEPTH_32;
    DepthDataAccuracy dataAccuracy = DEPTH_DATA_ACCURACY_RELATIVE;
    DepthProfile depthProfile = DepthProfile(format, dataAccuracy, size);
    sptr<DepthDataOutput> depthDataOutput = nullptr;
    cameraManagerForSys_->CreateDepthDataOutput(depthProfile, surfaceProducer, &depthDataOutput);
    ASSERT_NE(depthDataOutput, nullptr);

    sptr<CaptureOutput> output = depthDataOutput;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    session->BeginConfig();
    session->AddInput(input);
    session->AddOutput(output);
    session->CommitConfig();
    session->Start();

    int32_t dataAccuracy_ = 0;
    EXPECT_EQ(depthDataOutput->CreateStream(), CameraErrorCode::SUCCESS);
    EXPECT_NE(depthDataOutput->Start(), CameraErrorCode::CONFLICT_CAMERA);
    EXPECT_NE(depthDataOutput->SetDataAccuracy(dataAccuracy_), CameraErrorCode::CONFLICT_CAMERA);
    EXPECT_NE(depthDataOutput->Stop(), CameraErrorCode::CONFLICT_CAMERA);
    EXPECT_EQ(depthDataOutput->Release(), 0);

    input->Close();
    session->Stop();
    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test depthDataOutput when session is null or session is not commit
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test depthDataOutput when session is null or session is not commit for abnormal branches
 */
HWTEST_F(DepthDataOutputUnit, depth_data_output_unittest_002, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    Size size = {640, 480};
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> surfaceProducer = surface->GetProducer();
    CameraFormat format = CAMERA_FORMAT_DEPTH_32;
    DepthDataAccuracy dataAccuracy = DEPTH_DATA_ACCURACY_RELATIVE;
    DepthProfile depthProfile = DepthProfile(format, dataAccuracy, size);
    sptr<DepthDataOutput> depthDataOutput = nullptr;
    cameraManagerForSys_->CreateDepthDataOutput(depthProfile, surfaceProducer, &depthDataOutput);
    ASSERT_NE(depthDataOutput, nullptr);

    sptr<CaptureOutput> output = depthDataOutput;

    depthDataOutput->session_ = nullptr;
    int32_t dataAccuracy_ = 0;
    EXPECT_EQ(depthDataOutput->Start(), SESSION_NOT_CONFIG);
    EXPECT_EQ(depthDataOutput->Stop(), SERVICE_FATL_ERROR);
    EXPECT_EQ(depthDataOutput->Release(), 0);

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);
    session->BeginConfig();
    session->AddInput(input);
    session->AddOutput(output);

    EXPECT_EQ(depthDataOutput->Start(), SESSION_NOT_CONFIG);
    EXPECT_EQ(depthDataOutput->SetDataAccuracy(dataAccuracy_), SERVICE_FATL_ERROR);
    EXPECT_EQ(depthDataOutput->Stop(), SERVICE_FATL_ERROR);
    EXPECT_EQ(depthDataOutput->Release(), SERVICE_FATL_ERROR);

    input->Close();
    session->Stop();
    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test depthDataOutput when stream is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test depthDataOutput when stream is nullptr
 */
HWTEST_F(DepthDataOutputUnit, depth_data_output_unittest_003, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    Size size = {640, 480};
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> surfaceProducer = surface->GetProducer();
    CameraFormat format = CAMERA_FORMAT_DEPTH_32;
    DepthDataAccuracy dataAccuracy = DEPTH_DATA_ACCURACY_RELATIVE;
    DepthProfile depthProfile = DepthProfile(format, dataAccuracy, size);
    sptr<DepthDataOutput> depthDataOutput = nullptr;
    cameraManagerForSys_->CreateDepthDataOutput(depthProfile, surfaceProducer, &depthDataOutput);
    ASSERT_NE(depthDataOutput, nullptr);

    sptr<CaptureOutput> output = depthDataOutput;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    session->BeginConfig();
    session->AddInput(input);
    session->AddOutput(output);
    session->CommitConfig();
    session->Start();

    depthDataOutput->stream_ = nullptr;
    int32_t dataAccuracy_ = 0;
    EXPECT_NE(depthDataOutput->Start(), CameraErrorCode::CONFLICT_CAMERA);
    EXPECT_EQ(depthDataOutput->SetDataAccuracy(dataAccuracy_), SERVICE_FATL_ERROR);
    EXPECT_EQ(depthDataOutput->Stop(), SERVICE_FATL_ERROR);
    EXPECT_EQ(depthDataOutput->Release(), SERVICE_FATL_ERROR);

    input->Close();
    session->Stop();
    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test depthDataOutput when appCallback_ is not nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test depthDataOutput when appCallback_ is not nullptr
 */
HWTEST_F(DepthDataOutputUnit, depth_data_output_unittest_004, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    Size size = {640, 480};
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> surfaceProducer = surface->GetProducer();
    CameraFormat format = CAMERA_FORMAT_DEPTH_32;
    DepthDataAccuracy dataAccuracy = DEPTH_DATA_ACCURACY_RELATIVE;
    DepthProfile depthProfile = DepthProfile(format, dataAccuracy, size);
    sptr<DepthDataOutput> depthDataOutput = nullptr;
    cameraManagerForSys_->CreateDepthDataOutput(depthProfile, surfaceProducer, &depthDataOutput);
    ASSERT_NE(depthDataOutput, nullptr);

    sptr<CaptureOutput> output = depthDataOutput;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    session->BeginConfig();
    session->AddInput(input);
    session->AddOutput(output);
    session->CommitConfig();
    session->Start();

    std::shared_ptr<DepthDataStateCallback> appCallback = std::make_shared<DepthDataStateCallbackTest>();
    depthDataOutput->appCallback_ = appCallback;
    depthDataOutput->svcCallback_ = nullptr;
    depthDataOutput->SetCallback(appCallback);
    EXPECT_EQ(depthDataOutput->GetApplicationCallback(), appCallback);

    depthDataOutput->stream_ = nullptr;
    depthDataOutput->SetCallback(appCallback);
    EXPECT_EQ(depthDataOutput->GetApplicationCallback(), appCallback);

    pid_t pid = 0;
    depthDataOutput->CameraServerDied(pid);
    EXPECT_EQ(depthDataOutput->Release(), SERVICE_FATL_ERROR);

    input->Close();
    session->Stop();
    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test depthDataOutput when appCallback_ is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test depthDataOutput when appCallback_ is nullptr
 */
HWTEST_F(DepthDataOutputUnit, depth_data_output_unittest_005, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    Size size = {640, 480};
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> surfaceProducer = surface->GetProducer();
    CameraFormat format = CAMERA_FORMAT_DEPTH_32;
    DepthDataAccuracy dataAccuracy = DEPTH_DATA_ACCURACY_RELATIVE;
    DepthProfile depthProfile = DepthProfile(format, dataAccuracy, size);
    sptr<DepthDataOutput> depthDataOutput = nullptr;
    cameraManagerForSys_->CreateDepthDataOutput(depthProfile, surfaceProducer, &depthDataOutput);
    ASSERT_NE(depthDataOutput, nullptr);

    sptr<CaptureOutput> output = depthDataOutput;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    session->BeginConfig();
    session->AddInput(input);
    session->AddOutput(output);
    session->CommitConfig();
    session->Start();

    std::shared_ptr<DepthDataStateCallback> appCallback = nullptr;
    depthDataOutput->appCallback_ = appCallback;
    depthDataOutput->svcCallback_ = nullptr;
    depthDataOutput->SetCallback(appCallback);
    EXPECT_EQ(depthDataOutput->GetApplicationCallback(), appCallback);

    pid_t pid = 0;
    depthDataOutput->CameraServerDied(pid);
    EXPECT_EQ(depthDataOutput->Release(), 0);

    input->Close();
    session->Stop();
    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test depthDataOutput when svcCallback_ is not nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test depthDataOutput when svcCallback_ is not nullptr
 */
HWTEST_F(DepthDataOutputUnit, depth_data_output_unittest_006, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    Size size = {640, 480};
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> surfaceProducer = surface->GetProducer();
    CameraFormat format = CAMERA_FORMAT_DEPTH_32;
    DepthDataAccuracy dataAccuracy = DEPTH_DATA_ACCURACY_RELATIVE;
    DepthProfile depthProfile = DepthProfile(format, dataAccuracy, size);
    sptr<DepthDataOutput> depthDataOutput = nullptr;
    cameraManagerForSys_->CreateDepthDataOutput(depthProfile, surfaceProducer, &depthDataOutput);
    ASSERT_NE(depthDataOutput, nullptr);

    sptr<CaptureOutput> output = depthDataOutput;
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    session->BeginConfig();
    session->AddInput(input);
    session->AddOutput(output);
    session->CommitConfig();
    session->Start();

    std::shared_ptr<DepthDataStateCallback> appCallback = std::make_shared<DepthDataStateCallbackTest>();
    depthDataOutput->appCallback_ = appCallback;
    depthDataOutput->svcCallback_ = new (std::nothrow) DepthDataOutputCallbackImpl(depthDataOutput);
    ASSERT_NE(depthDataOutput->svcCallback_, nullptr);
    depthDataOutput->SetCallback(appCallback);
    EXPECT_EQ(depthDataOutput->GetApplicationCallback(), appCallback);

    pid_t pid = 0;
    depthDataOutput->CameraServerDied(pid);
    EXPECT_EQ(depthDataOutput->Release(), 0);

    if (depthDataOutput->svcCallback_) {
        depthDataOutput->svcCallback_ = nullptr;
    }
    input->Close();
    session->Stop();
    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test DepthDataOutputCallbackImpl
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DepthDataOutputCallbackImpl when appCallback_ is nullptr or is not nullptr
 */
HWTEST_F(DepthDataOutputUnit, depth_data_output_unittest_007, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    Size size = {640, 480};
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> surfaceProducer = surface->GetProducer();
    CameraFormat format = CAMERA_FORMAT_DEPTH_32;
    DepthDataAccuracy dataAccuracy = DEPTH_DATA_ACCURACY_RELATIVE;
    DepthProfile depthProfile = DepthProfile(format, dataAccuracy, size);
    sptr<DepthDataOutput> depthDataOutput = nullptr;
    cameraManagerForSys_->CreateDepthDataOutput(depthProfile, surfaceProducer, &depthDataOutput);
    ASSERT_NE(depthDataOutput, nullptr);

    std::shared_ptr<DepthDataStateCallback> appCallback = std::make_shared<DepthDataStateCallbackTest>();
    depthDataOutput->appCallback_ = appCallback;
    depthDataOutput->svcCallback_ = new (std::nothrow) DepthDataOutputCallbackImpl(depthDataOutput);
    ASSERT_NE(depthDataOutput->svcCallback_, nullptr);
    int32_t errCode = 0;
    EXPECT_EQ(depthDataOutput->svcCallback_->OnDepthDataError(errCode), 0);

    depthDataOutput->appCallback_ = nullptr;
    EXPECT_EQ(depthDataOutput->svcCallback_->OnDepthDataError(errCode), 0);

    sptr<DepthDataOutputCallbackImpl> depthDataOutputCallbackImpl =
        new (std::nothrow) DepthDataOutputCallbackImpl(depthDataOutput);
    ASSERT_NE(depthDataOutputCallbackImpl, nullptr);
    depthDataOutputCallbackImpl->depthDataOutput_ = nullptr;
    EXPECT_EQ(depthDataOutputCallbackImpl->OnDepthDataError(errCode), 0);

    if (depthDataOutput->svcCallback_) {
        depthDataOutput->svcCallback_ = nullptr;
    }
    if (depthDataOutputCallbackImpl) {
        depthDataOutputCallbackImpl = nullptr;
    }
    input->Close();
    input->Release();
}

}
}