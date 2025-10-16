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
#include "gmock/gmock.h"
#include "stream_depth_data_callback_stub.h"

using namespace testing::ext;
using ::testing::Return;
using ::testing::_;

namespace OHOS {
namespace CameraStandard {

constexpr static uint32_t CAMERA_STREAM_DEPTH_ON_DEFAULT = 1;
const uint32_t METADATA_ITEM_SIZE = 20;
const uint32_t METADATA_DATA_SIZE = 200;

void HStreamDepthDataUnitTest::SetUpTestCase(void) {}

void HStreamDepthDataUnitTest::TearDownTestCase(void) {}

void HStreamDepthDataUnitTest::TearDown(void) {}

void HStreamDepthDataUnitTest::SetUp(void) {}

class MockHStreamDepthDataCallbackStub : public StreamDepthDataCallbackStub {
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
    int32_t ret01 = depthDataPtr->OperatePermissionCheck(static_cast<uint32_t>(IStreamDepthDataIpcCode::COMMAND_START));
    EXPECT_EQ(ret01, CAMERA_OK);
    int32_t ret02 = depthDataPtr->OperatePermissionCheck(static_cast<uint32_t>(IStreamDepthDataIpcCode::COMMAND_STOP));
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
    uint32_t code = static_cast<uint32_t>(IStreamDepthDataCallbackIpcCode::COMMAND_ON_DEPTH_DATA_ERROR);
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

/*
 * Feature: Framework
 * Function: Test  SetStreamInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetStreamInfo for assign streamInfo correctly.
 */
HWTEST_F(HStreamDepthDataUnitTest, hstream_depth_data_unittest_009, TestSize.Level1)
{
    int32_t systemAbilityId = 110;
    bool runOnCreate = true;
    sptr<HCameraService> cameraService;
    cameraService = new (nothrow) HCameraService(systemAbilityId, runOnCreate);

    sptr<OHOS::IConsumerSurface> cSurface = IConsumerSurface::Create();
    sptr<OHOS::IBufferProducer> producer = cSurface->GetProducer();
    int32_t format = OHOS_CAMERA_FORMAT_RGBA_8888;
    int32_t width = 1920;
    int32_t height = 1080;
    sptr<IStreamDepthData> depthDataOutput;
    cameraService->CreateDepthDataOutput(producer, format, width, height, depthDataOutput);
    ASSERT_NE(depthDataOutput, nullptr);

    HStreamDepthData* depthDataPtr = static_cast<HStreamDepthData*>(depthDataOutput.GetRefPtr());

    StreamInfo_V1_5 streamInfo;
    depthDataPtr->SetStreamInfo(streamInfo);
    EXPECT_EQ(streamInfo.v1_0.intent_, static_cast<OHOS::HDI::Camera::V1_0::StreamIntent>(
        OHOS::HDI::Camera::V1_3::StreamType::STREAM_TYPE_DEPTH));
    EXPECT_EQ(streamInfo.v1_0.format_, GRAPHIC_PIXEL_FMT_RGBA_8888);

    format = OHOS_CAMERA_FORMAT_YCBCR_420_888;
    sptr<IStreamDepthData> depthDataOutput2;
    cameraService->CreateDepthDataOutput(producer, format, width, height, depthDataOutput2);
    ASSERT_NE(depthDataOutput2, nullptr);

    HStreamDepthData* depthDataPtr2 = static_cast<HStreamDepthData*>(depthDataOutput2.GetRefPtr());

    StreamInfo_V1_5 streamInfo2;
    depthDataPtr2->SetStreamInfo(streamInfo2);
    EXPECT_EQ(streamInfo2.v1_0.intent_, static_cast<OHOS::HDI::Camera::V1_0::StreamIntent>(
        OHOS::HDI::Camera::V1_3::StreamType::STREAM_TYPE_DEPTH));
    EXPECT_EQ(streamInfo2.v1_0.format_, GRAPHIC_PIXEL_FMT_YCBCR_420_SP);
}

/*
 * Feature: Framework
 * Function: Test Release
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Release. If streamOperator is not nullptr, it is expected to be null
 *                  after release streamMetaData.
 */
HWTEST_F(HStreamDepthDataUnitTest, hstream_depth_data_unittest_010, TestSize.Level1)
{
    int32_t systemAbilityId = 110;
    bool runOnCreate = true;
    sptr<HCameraService> cameraService;
    cameraService = new (nothrow) HCameraService(systemAbilityId, runOnCreate);

    sptr<OHOS::IConsumerSurface> cSurface = IConsumerSurface::Create();
    sptr<OHOS::IBufferProducer> producer = cSurface->GetProducer();
    int32_t format = OHOS_CAMERA_FORMAT_RGBA_8888;
    int32_t width = 1920;
    int32_t height = 1080;
    sptr<IStreamDepthData> depthDataOutput;
    cameraService->CreateDepthDataOutput(producer, format, width, height, depthDataOutput);
    ASSERT_NE(depthDataOutput, nullptr);

    HStreamDepthData* depthDataPtr = static_cast<HStreamDepthData*>(depthDataOutput.GetRefPtr());

    int32_t ret = depthDataPtr->Release();
    EXPECT_EQ(ret, CAMERA_OK);

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator;
    depthDataPtr->LinkInput(streamOperator, metadata);
    EXPECT_EQ(depthDataPtr->GetStreamOperator(), streamOperator);
    ret = depthDataPtr->Release();
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(depthDataPtr->GetStreamOperator(), nullptr);
}

/*
 * Feature: Framework
 * Function: Test DumpStreamInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DumpStreamInfo.
 */
HWTEST_F(HStreamDepthDataUnitTest, hstream_depth_data_unittest_011, TestSize.Level1)
{
    int32_t systemAbilityId = 110;
    bool runOnCreate = true;
    sptr<HCameraService> cameraService;
    cameraService = new (nothrow) HCameraService(systemAbilityId, runOnCreate);

    sptr<OHOS::IConsumerSurface> cSurface = IConsumerSurface::Create();
    sptr<OHOS::IBufferProducer> producer = cSurface->GetProducer();
    int32_t format = OHOS_CAMERA_FORMAT_RGBA_8888;
    int32_t width = 1920;
    int32_t height = 1080;
    sptr<IStreamDepthData> depthDataOutput;
    cameraService->CreateDepthDataOutput(producer, format, width, height, depthDataOutput);
    ASSERT_NE(depthDataOutput, nullptr);

    HStreamDepthData* depthDataPtr = static_cast<HStreamDepthData*>(depthDataOutput.GetRefPtr());
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
    std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);

    CameraInfoDumper infoDumper(0);
    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator;
    depthDataPtr->LinkInput(streamOperator, metadata);
    depthDataPtr->LinkInput(nullptr, metadata);
    depthDataPtr->Stop();
    depthDataPtr->Start();
    depthDataPtr->DumpStreamInfo(infoDumper);
    depthDataPtr->Start();
    depthDataPtr->Stop();
    EXPECT_NE(infoDumper.dumperString_.find("depth stream"), std::string::npos);
    EXPECT_NE(infoDumper.dumperString_.find("Stream Extened Info"), std::string::npos);
}

/*
 * Feature: Framework
 * Function: Test CallbackEnter and CallbackExit
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CallbackEnter and CallbackExit for an unauthorized caller token when starting a
 *                  stream metadata operation. The expected return value is CAMERA_OPERATION_NOT_ALLOWED.
 */
HWTEST_F(HStreamDepthDataUnitTest, hstream_depth_data_unittest_012, TestSize.Level1)
{
    int32_t systemAbilityId = 110;
    bool runOnCreate = true;
    sptr<HCameraService> cameraService;
    cameraService = new (nothrow) HCameraService(systemAbilityId, runOnCreate);

    sptr<OHOS::IConsumerSurface> cSurface = IConsumerSurface::Create();
    sptr<OHOS::IBufferProducer> producer = cSurface->GetProducer();
    int32_t format = OHOS_CAMERA_FORMAT_RGBA_8888;
    int32_t width = 1920;
    int32_t height = 1080;
    sptr<IStreamDepthData> depthDataOutput;
    cameraService->CreateDepthDataOutput(producer, format, width, height, depthDataOutput);
    ASSERT_NE(depthDataOutput, nullptr);

    HStreamDepthData* depthDataPtr = static_cast<HStreamDepthData*>(depthDataOutput.GetRefPtr());

    uint32_t interfaceCode = static_cast<uint32_t>(IStreamDepthDataIpcCode::COMMAND_START);
    depthDataPtr->callerToken_ = 110;
    int32_t ret = depthDataPtr->CallbackEnter(interfaceCode);
    EXPECT_EQ(ret, CAMERA_OPERATION_NOT_ALLOWED);

    int32_t ret2 = depthDataPtr->CallbackExit(interfaceCode, ret);
    EXPECT_EQ(ret2, CAMERA_OK);
}
} // CameraStandard
} // OHOS