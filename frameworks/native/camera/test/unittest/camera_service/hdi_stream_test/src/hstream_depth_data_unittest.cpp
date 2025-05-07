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

#include "camera_log.h"
#include "hstream_depth_data_unittest.h"
#include "iconsumer_surface.h"
#include "test_common.h"
#include "camera_device.h"
#include "capture_session.h"
#include "camera_service_ipc_interface_code.h"
#include "gmock/gmock.h"
#include "hstream_depth_data_callback_stub.h"
#include "camera_service_ipc_interface_code.h"

using namespace testing::ext;
using ::testing::Return;
using ::testing::_;

namespace OHOS {
namespace CameraStandard {

constexpr static uint32_t CAMERA_STREAM_DEPTH_ON_DEFAULT = 1;

void HStreamDepthDataUnitTest::SetUpTestCase(void) {}

void HStreamDepthDataUnitTest::TearDownTestCase(void) {}

void HStreamDepthDataUnitTest::TearDown(void) {}

void HStreamDepthDataUnitTest::SetUp(void) {}

class MockHStreamDepthDataCallbackStub : public HStreamDepthDataCallbackStub {
public:
    MOCK_METHOD1(OnDepthDataError, int32_t(int32_t errorCode));
    ~MockHStreamDepthDataCallbackStub() {}
};

/*
 * Feature: Framework
 * Function: Test LinkInput
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the LinkInput function. When invalid input parameters are provided,
 * the expected return value is CAMERA_INVALID_ARG.
 */
HWTEST_F(HStreamDepthDataUnitTest, hstream_depth_data_unittest_001, TestSize.Level1)
{
    sptr<OHOS::IConsumerSurface> cSurface = IConsumerSurface::Create();
    sptr<OHOS::IBufferProducer> producer = cSurface->GetProducer();
    int32_t format = 1;
    int32_t width = 1920;
    int32_t height = 1080;
    int32_t systemAbilityId = 110;
    bool runOnCreate = true;
    HStreamDepthData* depthDataPtr;
    sptr<HCameraService> cameraService;
    sptr<IStreamDepthData> depthDataOutput;
    cameraService = new (nothrow) HCameraService(systemAbilityId, runOnCreate);
    cameraService->CreateDepthDataOutput(producer, format, width, height, depthDataOutput);
    ASSERT_NE(depthDataOutput, nullptr);
    depthDataPtr = static_cast<HStreamDepthData*>(depthDataOutput.GetRefPtr());
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility;
    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator;
    int32_t ret = depthDataPtr->LinkInput(streamOperator, cameraAbility);
    EXPECT_EQ(ret, CAMERA_INVALID_ARG);
}

/*
 * Feature: Framework
 * Function: Test SetDataAccuracy
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the SetDataAccuracy function. When a valid accuracy value is provided,
 *    the expected return value is CAMERA_OK.
 */
HWTEST_F(HStreamDepthDataUnitTest, hstream_depth_data_unittest_002, TestSize.Level1)
{
    sptr<OHOS::IConsumerSurface> cSurface = IConsumerSurface::Create();
    sptr<OHOS::IBufferProducer> producer = cSurface->GetProducer();
    int32_t format = 1;
    int32_t width = 1920;
    int32_t height = 1080;
    int32_t systemAbilityId = 110;
    bool runOnCreate = true;
    HStreamDepthData* depthDataPtr;
    sptr<HCameraService> cameraService;
    sptr<IStreamDepthData> depthDataOutput;
    cameraService = new (nothrow) HCameraService(systemAbilityId, runOnCreate);
    cameraService->CreateDepthDataOutput(producer, format, width, height, depthDataOutput);
    ASSERT_NE(depthDataOutput, nullptr);
    depthDataPtr = static_cast<HStreamDepthData*>(depthDataOutput.GetRefPtr());
    int32_t accuracy = 1;
    int32_t ret = depthDataPtr->SetDataAccuracy(accuracy);
    EXPECT_EQ(ret, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test Start
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the Start function. When the depth data stream is not ready,
 *    the expected return value is CAMERA_INVALID_STATE.
 */
HWTEST_F(HStreamDepthDataUnitTest, hstream_depth_data_unittest_003, TestSize.Level1)
{
    sptr<OHOS::IConsumerSurface> cSurface = IConsumerSurface::Create();
    sptr<OHOS::IBufferProducer> producer = cSurface->GetProducer();
    int32_t format = 1;
    int32_t width = 1920;
    int32_t height = 1080;
    int32_t systemAbilityId = 110;
    bool runOnCreate = true;
    HStreamDepthData* depthDataPtr;
    sptr<HCameraService> cameraService;
    sptr<IStreamDepthData> depthDataOutput;
    cameraService = new (nothrow) HCameraService(systemAbilityId, runOnCreate);
    cameraService->CreateDepthDataOutput(producer, format, width, height, depthDataOutput);
    ASSERT_NE(depthDataOutput, nullptr);
    depthDataPtr = static_cast<HStreamDepthData*>(depthDataOutput.GetRefPtr());
    int32_t ret = depthDataPtr->Start();
    EXPECT_EQ(ret, CAMERA_INVALID_STATE);
}

/*
 * Feature: Framework
 * Function: Test Stop
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the Stop function. When the depth data stream is not ready,
 *    the expected return value is CAMERA_INVALID_STATE.
 */
HWTEST_F(HStreamDepthDataUnitTest, hstream_depth_data_unittest_004, TestSize.Level1)
{
    sptr<OHOS::IConsumerSurface> cSurface = IConsumerSurface::Create();
    sptr<OHOS::IBufferProducer> producer = cSurface->GetProducer();
    int32_t format = 1;
    int32_t width = 1920;
    int32_t height = 1080;
    int32_t systemAbilityId = 110;
    bool runOnCreate = true;
    HStreamDepthData* depthDataPtr;
    sptr<HCameraService> cameraService;
    sptr<IStreamDepthData> depthDataOutput;
    cameraService = new (nothrow) HCameraService(systemAbilityId, runOnCreate);
    cameraService->CreateDepthDataOutput(producer, format, width, height, depthDataOutput);
    ASSERT_NE(depthDataOutput, nullptr);
    depthDataPtr = static_cast<HStreamDepthData*>(depthDataOutput.GetRefPtr());
    int32_t ret = depthDataPtr->Stop();
    EXPECT_EQ(ret, CAMERA_INVALID_STATE);
}


/*
 * Feature: Framework
 * Function: Test SetCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the SetCallback function. When an invalid callback object is provided,
 *    the expected return value is CAMERA_INVALID_ARG.
 */
HWTEST_F(HStreamDepthDataUnitTest, hstream_depth_data_unittest_005, TestSize.Level1)
{
    sptr<OHOS::IConsumerSurface> cSurface = IConsumerSurface::Create();
    sptr<OHOS::IBufferProducer> producer = cSurface->GetProducer();
    int32_t format = 1;
    int32_t width = 1920;
    int32_t height = 1080;
    int32_t systemAbilityId = 110;
    bool runOnCreate = true;
    HStreamDepthData* depthDataPtr;
    sptr<HCameraService> cameraService;
    sptr<IStreamDepthData> depthDataOutput;
    cameraService = new (nothrow) HCameraService(systemAbilityId, runOnCreate);
    cameraService->CreateDepthDataOutput(producer, format, width, height, depthDataOutput);
    ASSERT_NE(depthDataOutput, nullptr);
    depthDataPtr = static_cast<HStreamDepthData*>(depthDataOutput.GetRefPtr());
    sptr<IStreamDepthDataCallback> callback = nullptr;
    int32_t ret = depthDataPtr->SetCallback(callback);
    EXPECT_EQ(ret, CAMERA_INVALID_ARG);
}

/*
 * Feature: Framework
 * Function: Test OperatePermissionCheck
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the OperatePermissionCheck function.
 * When checking the permission for the start and stop interface,
 * the expected return value is CAMERA_OK.
 */
HWTEST_F(HStreamDepthDataUnitTest, hstream_depth_data_unittest_006, TestSize.Level1)
{
    sptr<OHOS::IConsumerSurface> cSurface = IConsumerSurface::Create();
    sptr<OHOS::IBufferProducer> producer = cSurface->GetProducer();
    int32_t format = 1;
    int32_t width = 1920;
    int32_t height = 1080;
    int32_t systemAbilityId = 110;
    bool runOnCreate = true;
    HStreamDepthData* depthDataPtr;
    sptr<HCameraService> cameraService;
    sptr<IStreamDepthData> depthDataOutput;
    cameraService = new (nothrow) HCameraService(systemAbilityId, runOnCreate);
    cameraService->CreateDepthDataOutput(producer, format, width, height, depthDataOutput);
    ASSERT_NE(depthDataOutput, nullptr);
    depthDataPtr = static_cast<HStreamDepthData*>(depthDataOutput.GetRefPtr());
    int32_t ret01 = depthDataPtr->OperatePermissionCheck(CAMERA_STREAM_DEPTH_DATA_START);
    EXPECT_EQ(ret01, CAMERA_OK);
    int32_t ret02 = depthDataPtr->OperatePermissionCheck(CAMERA_STREAM_DEPTH_DATA_STOP);
    EXPECT_EQ(ret02, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test HStreamCaptureCallbackStub with OnRemoteRequest
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnRemoteRequest for branches of switch
 */
HWTEST_F(HStreamDepthDataUnitTest, hstream_depth_data_unittest_007, TestSize.Level1)
{
    MockHStreamDepthDataCallbackStub stub;
    MessageParcel data;
    data.WriteInterfaceToken(stub.GetDescriptor());
    data.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    uint32_t code = StreamDepthDataCallbackInterfaceCode::CAMERA_STREAM_DEPTH_DATA_ON_ERROR;
    EXPECT_CALL(stub, OnDepthDataError(_))
        .WillOnce(Return(0));
    int errCode = stub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(errCode, 0);
}

/*
 * Feature: Framework
 * Function: Test HStreamCaptureCallbackStub with OnRemoteRequest
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnRemoteRequest for switch of default case
 */
HWTEST_F(HStreamDepthDataUnitTest, hstream_depth_data_unittest_008, TestSize.Level1)
{
    MockHStreamDepthDataCallbackStub stub;
    MessageParcel data;
    data.WriteInterfaceToken(stub.GetDescriptor());
    data.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    uint32_t code = CAMERA_STREAM_DEPTH_ON_DEFAULT;
    int errCode = stub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(errCode, IPC_STUB_UNKNOW_TRANS_ERR);
}

} // CameraStandard
} // OHOS