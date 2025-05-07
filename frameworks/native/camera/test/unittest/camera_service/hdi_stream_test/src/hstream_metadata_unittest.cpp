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
#include "hstream_metadata_unittest.h"
#include "camera_service_ipc_interface_code.h"
#include "test_common.h"
#include "gmock/gmock.h"
#include "hstream_metadata_callback_stub.h"
#include "camera_service_ipc_interface_code.h"

using namespace testing::ext;
using ::testing::Return;
using ::testing::_;

namespace OHOS {
namespace CameraStandard {
constexpr static uint32_t CAMERA_STREAM_METADATA_ON_DEFAULT = 1;
const uint32_t METADATA_ITEM_SIZE = 20;
const uint32_t METADATA_DATA_SIZE = 200;
void HStreamMetadataUnit::SetUpTestCase(void) {}

void HStreamMetadataUnit::TearDownTestCase(void) {}

void HStreamMetadataUnit::TearDown(void) {}

void HStreamMetadataUnit::SetUp(void) {}

class MockHStreamMetadataCallbackStub : public HStreamMetadataCallbackStub {
public:
    MOCK_METHOD2(OnMetadataResult, int32_t(const int32_t streamId,
        const std::shared_ptr<OHOS::Camera::CameraMetadata> &result));
    ~MockHStreamMetadataCallbackStub() {}
};

/*
 * Feature: Framework
 * Function: Test OperatePermissionCheck
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OperatePermissionCheck for an unauthorized caller token when starting a stream metadata
 *                  operation. The expected return value is CAMERA_OPERATION_NOT_ALLOWED.
 */
HWTEST_F(HStreamMetadataUnit, hstream_metadata_unittest_001, TestSize.Level1)
{
    sptr<OHOS::IConsumerSurface> cSurface = IConsumerSurface::Create();
    sptr<OHOS::IBufferProducer> producer = cSurface->GetProducer();
    int32_t format = 1;
    sptr<HStreamMetadata> streamMetadata =
        new(std::nothrow) HStreamMetadata(producer, format, {1});
    ASSERT_NE(streamMetadata, nullptr);
    uint32_t interfaceCode = CAMERA_STREAM_META_START;
    streamMetadata->callerToken_ = 110;
    int32_t ret = streamMetadata->OperatePermissionCheck(interfaceCode);
    EXPECT_EQ(ret, CAMERA_OPERATION_NOT_ALLOWED);
}

/*
 * Feature: Framework
 * Function: Test HStreamMetadata & HStreamCommon
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HStreamMetadata & HStreamCommon
 */
HWTEST_F(HStreamMetadataUnit, camera_fwcoverage_unittest_027, TestSize.Level1)
{
    int32_t format = 0;
    CameraInfoDumper infoDumper(0);
    std::string  dumpString ="HStreamMetadata";
    std::vector<sptr<CameraDevice>> cameras = CameraManager::GetInstance()->GetSupportedCameras();
    sptr<IConsumerSurface> Surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = Surface->GetProducer();
    sptr<HStreamMetadata> streamMetadata= new(std::nothrow) HStreamMetadata(producer, format, {1});
    ASSERT_NE(streamMetadata, nullptr);
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata1 = nullptr;
    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator;
    streamMetadata->LinkInput(streamOperator, metadata);
    streamMetadata->LinkInput(streamOperator, metadata1);
    streamOperator = nullptr;
    streamMetadata->LinkInput(streamOperator, metadata);
    streamMetadata->Stop();
    streamMetadata->Start();
    streamMetadata->DumpStreamInfo(infoDumper);
    streamMetadata->Start();
    streamMetadata->Stop();
}

/*
 * Feature: Framework
 * Function: Test HStreamMetadata & HStreamCommon
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HStreamMetadata & HStreamCommon
 */
HWTEST_F(HStreamMetadataUnit, camera_fwcoverage_unittest_028, TestSize.Level1)
{
    int32_t format = 0;
    std::string  dumpString ="HStreamMetadata";
    std::vector<sptr<CameraDevice>> cameras = CameraManager::GetInstance()->GetSupportedCameras();
    sptr<IConsumerSurface> Surface = IConsumerSurface::Create();
    sptr<IBufferProducer> producer = Surface->GetProducer();
    sptr<HStreamMetadata> streamMetadata= new(std::nothrow) HStreamMetadata(producer, format, {1});
    ASSERT_NE(streamMetadata, nullptr);
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    streamMetadata->Start();
    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator;
    streamMetadata->LinkInput(streamOperator, metadata);
    streamMetadata->Stop();
}

/*
 * Feature: Framework
 * Function: Test HStreamMetadataCallbackStub with OnRemoteRequest
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnRemoteRequest for switch of CAMERA_META_OPERATOR_ON_RESULT
 */
HWTEST_F(HStreamMetadataUnit, camera_fwcoverage_unittest_029, TestSize.Level1)
{
    MockHStreamMetadataCallbackStub stub;
    MessageParcel data;
    data.WriteInterfaceToken(stub.GetDescriptor());
    data.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    uint32_t code = StreamMetadataCallbackInterfaceCode::CAMERA_META_OPERATOR_ON_RESULT;
    EXPECT_CALL(stub, OnMetadataResult(_, _))
        .WillOnce(Return(0));
    int errCode = stub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(errCode, 0);
}

/*
 * Feature: Framework
 * Function: Test HStreamMetadataCallbackStub with OnRemoteRequest
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnRemoteRequest for switch of default
 */
HWTEST_F(HStreamMetadataUnit, camera_fwcoverage_unittest_030, TestSize.Level1)
{
    MockHStreamMetadataCallbackStub stub;
    MessageParcel data;
    data.WriteInterfaceToken(stub.GetDescriptor());
    data.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    uint32_t code = CAMERA_STREAM_METADATA_ON_DEFAULT;
    int errCode = stub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(errCode, IPC_STUB_UNKNOW_TRANS_ERR);
}

}
}