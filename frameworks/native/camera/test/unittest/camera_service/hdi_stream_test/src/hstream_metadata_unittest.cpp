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
#include "test_common.h"
#include "gmock/gmock.h"
#include "stream_metadata_callback_stub.h"
#include "camera_metadata_info.h"

using namespace testing::ext;
using ::testing::Return;
using ::testing::_;
using ::testing::A;

namespace OHOS {
namespace CameraStandard {
const uint32_t METADATA_ITEM_SIZE = 20;
const uint32_t METADATA_DATA_SIZE = 200;
void HStreamMetadataUnit::SetUpTestCase(void) {}

void HStreamMetadataUnit::TearDownTestCase(void) {}

void HStreamMetadataUnit::TearDown(void) {}

void HStreamMetadataUnit::SetUp(void) {}

class MockStreamOperator : public OHOS::HDI::Camera::V1_1::IStreamOperator {
public:
    MockStreamOperator()
    {
        ON_CALL(*this, CreateStreams(_)).WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, CreateStreams_V1_1(_)).WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, ReleaseStreams(_)).WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, CommitStreams(_, _)).WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, CommitStreams_V1_1(_, _)).WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, Capture(_, _, _)).WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, CancelCapture(_)).WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, IsStreamsSupported(_, _, A<const std::shared_ptr<OHOS::HDI::Camera::V1_0::StreamInfo> &>(), _))
            .WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, IsStreamsSupported(_, _, A<const std::vector<OHOS::HDI::Camera::V1_0::StreamInfo> &>(), _))
            .WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, IsStreamsSupported_V1_1(_, _, A<const std::shared_ptr<StreamInfo> &>(), _))
            .WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, IsStreamsSupported_V1_1(_, _, A<const std::vector<StreamInfo_V1_1> &>(), _))
            .WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, GetStreamAttributes(_)).WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, AttachBufferQueue(_, _)).WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, DetachBufferQueue(_)).WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
        ON_CALL(*this, ChangeToOfflineStream(_, _, _)).WillByDefault(Return(HDI::Camera::V1_0::NO_ERROR));
    }
    virtual ~MockStreamOperator() {}
    MOCK_METHOD1(CreateStreams, int32_t(
        const std::vector<OHOS::HDI::Camera::V1_0::StreamInfo>& streamInfos));
    MOCK_METHOD1(CreateStreams_V1_1, int32_t(
        const std::vector<StreamInfo_V1_1>& streamInfos));
    MOCK_METHOD1(ReleaseStreams, int32_t(const std::vector<int32_t>& streamIds));
    MOCK_METHOD1(CancelCapture, int32_t(int32_t captureId));
    MOCK_METHOD1(GetStreamAttributes, int32_t(
        std::vector<StreamAttribute>& attributes));
    MOCK_METHOD1(DetachBufferQueue, int32_t(int32_t streamId));
    MOCK_METHOD2(CommitStreams, int32_t(OperationMode mode, const std::vector<uint8_t>& modeSetting));
    MOCK_METHOD2(CommitStreams_V1_1, int32_t(OHOS::HDI::Camera::V1_1::OperationMode_V1_1 mode,
        const std::vector<uint8_t>& modeSetting));
    MOCK_METHOD2(AttachBufferQueue, int32_t(int32_t streamId,
        const sptr<BufferProducerSequenceable>& bufferProducer));
    MOCK_METHOD3(Capture, int32_t(int32_t captureId, const CaptureInfo& info, bool isStreaming));
    MOCK_METHOD3(ChangeToOfflineStream, int32_t(const std::vector<int32_t>& streamIds,
                                            const sptr<HDI::Camera::V1_0::IStreamOperatorCallback>& callbackObj,
                                            sptr<HDI::Camera::V1_0::IOfflineStreamOperator>& offlineOperator));
    MOCK_METHOD4(IsStreamsSupported, int32_t(OperationMode mode,
        const std::shared_ptr<OHOS::Camera::CameraMetadata> &modeSetting,
        const std::shared_ptr<OHOS::HDI::Camera::V1_0::StreamInfo> &info, StreamSupportType &type));
    MOCK_METHOD4(IsStreamsSupported, int32_t(OperationMode mode, const std::vector<uint8_t>& modeSetting,
        const std::vector<OHOS::HDI::Camera::V1_0::StreamInfo>& infos, StreamSupportType& type));
    MOCK_METHOD4(IsStreamsSupported_V1_1, int32_t(OHOS::HDI::Camera::V1_1::OperationMode_V1_1 mode,
        const std::shared_ptr<OHOS::Camera::CameraMetadata> &modeSetting,
        const std::shared_ptr<StreamInfo> &info, StreamSupportType &type));
    MOCK_METHOD4(IsStreamsSupported_V1_1, int32_t(OHOS::HDI::Camera::V1_1::OperationMode_V1_1 mode,
        const std::vector<uint8_t>& modeSetting,
        const std::vector<StreamInfo_V1_1>& infos, StreamSupportType& type));
};

class MockStreamMetadataCallback : public OHOS::CameraStandard::IStreamMetadataCallback {
public:
    MockStreamMetadataCallback()
    {
        ON_CALL(*this, OnMetadataResult(_, _)).WillByDefault(Return(0));
        ON_CALL(*this, AsObject()).WillByDefault(Return(nullptr));
    }
    virtual ~MockStreamMetadataCallback() {}
    MOCK_METHOD2(OnMetadataResult, ErrCode(int32_t streamId,
        const std::shared_ptr<CameraMetadata>& results));
    MOCK_METHOD0(AsObject, sptr<IRemoteObject>());
};

class MockHStreamMetadataCallbackStub : public StreamMetadataCallbackStub {
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
HWTEST_F(HStreamMetadataUnit, hstream_metadata_unittest_001, TestSize.Level0)
{
    sptr<OHOS::IConsumerSurface> cSurface = IConsumerSurface::Create();
    sptr<OHOS::IBufferProducer> producer = cSurface->GetProducer();
    int32_t format = 1;
    sptr<HStreamMetadata> streamMetadata =
        new(std::nothrow) HStreamMetadata(producer, format, {1});
    ASSERT_NE(streamMetadata, nullptr);
    uint32_t interfaceCode = static_cast<uint32_t>(IStreamMetadataIpcCode::COMMAND_START);
    streamMetadata->callerToken_ = 110;
    int32_t ret = streamMetadata->OperatePermissionCheck(interfaceCode);
    EXPECT_EQ(ret, CAMERA_OPERATION_NOT_ALLOWED);
}

/*
 * Feature: Framework
 * Function: Test SetStreamInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetStreamInfo for assign streamInfo correctly.
 */
HWTEST_F(HStreamMetadataUnit, hstream_metadata_unittest_002, TestSize.Level0)
{
    sptr<OHOS::IConsumerSurface> cSurface = IConsumerSurface::Create();
    sptr<OHOS::IBufferProducer> producer = cSurface->GetProducer();
    sptr<HStreamMetadata> streamMetadata =
        new(std::nothrow) HStreamMetadata(producer, OHOS_CAMERA_FORMAT_RGBA_8888, {1});
    ASSERT_NE(streamMetadata, nullptr);
    StreamInfo_V1_5 streamInfo;
    streamMetadata->SetStreamInfo(streamInfo);
    EXPECT_EQ(streamInfo.v1_0.intent_, OHOS::HDI::Camera::V1_0::StreamIntent::ANALYZE);
    EXPECT_EQ(streamInfo.v1_0.format_, GRAPHIC_PIXEL_FMT_RGBA_8888);

    sptr<HStreamMetadata> streamMetadata2 =
        new(std::nothrow) HStreamMetadata(producer, OHOS_CAMERA_FORMAT_YCBCR_420_888, {1});
    ASSERT_NE(streamMetadata2, nullptr);
    StreamInfo_V1_5 streamInfo2;
    streamMetadata2->SetStreamInfo(streamInfo2);
    EXPECT_EQ(streamInfo2.v1_0.intent_, OHOS::HDI::Camera::V1_0::StreamIntent::ANALYZE);
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
HWTEST_F(HStreamMetadataUnit, hstream_metadata_unittest_003, TestSize.Level0)
{
    sptr<OHOS::IConsumerSurface> cSurface = IConsumerSurface::Create();
    sptr<OHOS::IBufferProducer> producer = cSurface->GetProducer();
    sptr<HStreamMetadata> streamMetadata =
        new(std::nothrow) HStreamMetadata(producer, OHOS_CAMERA_FORMAT_RGBA_8888, {1});
    ASSERT_NE(streamMetadata, nullptr);
    int32_t ret = streamMetadata->Release();
    EXPECT_EQ(ret, CAMERA_OK);

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator = new MockStreamOperator();
    streamMetadata->LinkInput(streamOperator, metadata);
    EXPECT_EQ(streamMetadata->GetStreamOperator(), streamOperator);
    ret = streamMetadata->Release();
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(streamMetadata->GetStreamOperator(), nullptr);
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
HWTEST_F(HStreamMetadataUnit, hstream_metadata_unittest_004, TestSize.Level0)
{
    sptr<OHOS::IConsumerSurface> cSurface = IConsumerSurface::Create();
    sptr<OHOS::IBufferProducer> producer = cSurface->GetProducer();
    sptr<HStreamMetadata> streamMetadata =
        new(std::nothrow) HStreamMetadata(producer, OHOS_CAMERA_FORMAT_RGBA_8888, {1});
    ASSERT_NE(streamMetadata, nullptr);

    uint32_t interfaceCode = static_cast<uint32_t>(IStreamMetadataIpcCode::COMMAND_START);
    streamMetadata->callerToken_ = 110;
    int32_t ret = streamMetadata->CallbackEnter(interfaceCode);
    EXPECT_EQ(ret, CAMERA_OPERATION_NOT_ALLOWED);

    int32_t ret2 = streamMetadata->CallbackExit(interfaceCode, ret);
    EXPECT_EQ(ret2, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test EnableMetadataType and DisableMetadataType
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test EnableMetadataType and DisableMetadataType when streamOperator is not nullptr
 *                  and hdi version >= 1.3.
 */
HWTEST_F(HStreamMetadataUnit, hstream_metadata_unittest_005, TestSize.Level0)
{
    sptr<OHOS::IConsumerSurface> cSurface = IConsumerSurface::Create();
    sptr<OHOS::IBufferProducer> producer = cSurface->GetProducer();
    sptr<HStreamMetadata> streamMetadata =
        new(std::nothrow) HStreamMetadata(producer, OHOS_CAMERA_FORMAT_RGBA_8888, {1});
    ASSERT_NE(streamMetadata, nullptr);

    std::vector<int32_t> metadataTypes = {0, 1, 2};
    EXPECT_EQ(streamMetadata->EnableMetadataType(metadataTypes), CAMERA_INVALID_STATE);
    EXPECT_EQ(streamMetadata->DisableMetadataType(metadataTypes), CAMERA_INVALID_STATE);

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
    std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator = new MockStreamOperator();
    streamMetadata->LinkInput(streamOperator, metadata);
    EXPECT_EQ(streamMetadata->EnableMetadataType(metadataTypes), CAMERA_OK);
    EXPECT_EQ(streamMetadata->DisableMetadataType(metadataTypes), CAMERA_OK);
    
    streamMetadata->majorVer_ = 1;
    streamMetadata->minorVer_ = 3;
    EXPECT_EQ(streamMetadata->EnableMetadataType(metadataTypes), CAMERA_OK);
    EXPECT_EQ(streamMetadata->DisableMetadataType(metadataTypes), CAMERA_OK);

    streamMetadata->Release();
}

/*
 * Feature: Framework
 * Function: Test AddMetadataType and RemoveMetadataType
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AddMetadataType when metadataObjectTypes_ is initialized with one element. After
 *                  appending 3 elements, size of metadataObjectTypes_ is expected to be 4. Then, test removing
 *                  an element from the middle of the list. The size of metadataObjectTypes_ is expected to be 3.
 */
HWTEST_F(HStreamMetadataUnit, hstream_metadata_unittest_006, TestSize.Level0)
{
    sptr<OHOS::IConsumerSurface> cSurface = IConsumerSurface::Create();
    sptr<OHOS::IBufferProducer> producer = cSurface->GetProducer();
    sptr<HStreamMetadata> streamMetadata =
        new(std::nothrow) HStreamMetadata(producer, OHOS_CAMERA_FORMAT_RGBA_8888, {0});
    ASSERT_NE(streamMetadata, nullptr);

    std::vector<int32_t> metadataTypes = {1, 2, 3};
    streamMetadata->AddMetadataType(metadataTypes);
    EXPECT_EQ(streamMetadata->GetMetadataObjectTypes().size(), 4);

    std::vector<int32_t> removeMetadataTypes = {1};
    streamMetadata->RemoveMetadataType(removeMetadataTypes);
    EXPECT_EQ(streamMetadata->GetMetadataObjectTypes().size(), 3);
}

/*
 * Feature: Framework
 * Function: Test SetCallback, UnSetCallback and OnMetaResult
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetCallback, UnSetCallback and OnMetaResult.
 */
HWTEST_F(HStreamMetadataUnit, hstream_metadata_unittest_007, TestSize.Level0)
{
    sptr<OHOS::IConsumerSurface> cSurface = IConsumerSurface::Create();
    sptr<OHOS::IBufferProducer> producer = cSurface->GetProducer();
    sptr<HStreamMetadata> streamMetadata =
        new(std::nothrow) HStreamMetadata(producer, OHOS_CAMERA_FORMAT_RGBA_8888, {0});
    ASSERT_NE(streamMetadata, nullptr);

    auto callback = new MockStreamMetadataCallback();
    EXPECT_EQ(streamMetadata->SetCallback(nullptr), CAMERA_INVALID_ARG);
    EXPECT_EQ(streamMetadata->SetCallback(callback), CAMERA_OK);

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
    std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    EXPECT_CALL(*callback, OnMetadataResult(_, _)).WillRepeatedly(Return(0));

    EXPECT_EQ(streamMetadata->OnMetaResult(0, nullptr), CAMERA_OK);
    EXPECT_EQ(streamMetadata->OnMetaResult(0, metadata), CAMERA_OK);

    EXPECT_EQ(streamMetadata->UnSetCallback(), CAMERA_OK);
    EXPECT_EQ(streamMetadata->OnMetaResult(0, metadata), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test EnableDetectedObjectLifecycleReport
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: When isEnabled is true, objectLifecycleMap should be cleared for recording.
 *                  Else if isEnable is false, timestamp of the stop moment will be written in stopTime_.
 */
HWTEST_F(HStreamMetadataUnit, hstream_metadata_unittest_008, TestSize.Level0)
{
    sptr<OHOS::IConsumerSurface> cSurface = IConsumerSurface::Create();
    sptr<OHOS::IBufferProducer> producer = cSurface->GetProducer();
    sptr<HStreamMetadata> streamMetadata =
        new(std::nothrow) HStreamMetadata(producer, OHOS_CAMERA_FORMAT_RGBA_8888, {0});
    ASSERT_NE(streamMetadata, nullptr);

    EXPECT_EQ(streamMetadata->EnableDetectedObjectLifecycleReport(false, 3000), CAMERA_OK);
    EXPECT_EQ(streamMetadata->stopTime_, 3);
    
    EXPECT_EQ(streamMetadata->EnableDetectedObjectLifecycleReport(true, 0), CAMERA_OK);
    EXPECT_TRUE(streamMetadata->isDetectedObjectLifecycleReportEnabled_.load());
    EXPECT_TRUE(streamMetadata->objectLifecycleMap_.empty());
}

/*
 * Feature: Framework
 * Function: Test ProcessDetectedObjectLifecycle
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessDetectedObjectLifecycle with empty result vector and vector
 *                  with valid arguments.
 */
HWTEST_F(HStreamMetadataUnit, hstream_metadata_unittest_009, TestSize.Level0)
{
    sptr<OHOS::IConsumerSurface> cSurface = IConsumerSurface::Create();
    sptr<OHOS::IBufferProducer> producer = cSurface->GetProducer();
    sptr<HStreamMetadata> streamMetadata =
        new(std::nothrow) HStreamMetadata(producer, OHOS_CAMERA_FORMAT_RGBA_8888, {0});
    ASSERT_NE(streamMetadata, nullptr);

    streamMetadata->EnableDetectedObjectLifecycleReport(true, 0);
    std::vector<uint8_t> emptyResult;
    streamMetadata->ProcessDetectedObjectLifecycle(emptyResult);
    EXPECT_TRUE(streamMetadata->objectLifecycleMap_.empty());

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
    std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    ASSERT_NE(metadata, nullptr);
    int64_t timestamp = 2;
    EXPECT_TRUE(metadata->addEntry(OHOS_STATISTICS_TIMESTAMP, &timestamp, 1));
    int32_t objectId = 0;
    EXPECT_TRUE(metadata->addEntry(OHOS_CONTROL_FOCUS_TRACKING_OBJECT_ID, &objectId, 1));

    std::vector<uint8_t> result;
    OHOS::Camera::MetadataUtils::ConvertMetadataToVec(metadata, result);
    EXPECT_FALSE(result.empty());
    streamMetadata->ProcessDetectedObjectLifecycle(result);
    EXPECT_FALSE(streamMetadata->objectLifecycleMap_.empty());
}

/*
 * Feature: Framework
 * Function: Test SetFirstFrameTimestamp
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetFirstFrameTimestamp
 */
HWTEST_F(HStreamMetadataUnit, hstream_metadata_unittest_010, TestSize.Level0)
{
    sptr<OHOS::IConsumerSurface> cSurface = IConsumerSurface::Create();
    sptr<OHOS::IBufferProducer> producer = cSurface->GetProducer();
    sptr<HStreamMetadata> streamMetadata =
        new(std::nothrow) HStreamMetadata(producer, OHOS_CAMERA_FORMAT_RGBA_8888, {0});
    ASSERT_NE(streamMetadata, nullptr);

    streamMetadata->EnableDetectedObjectLifecycleReport(true, 0);
    streamMetadata->SetFirstFrameTimestamp(0);

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
    std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    ASSERT_NE(metadata, nullptr);
    int64_t timestamp = 2;
    EXPECT_TRUE(metadata->addEntry(OHOS_STATISTICS_TIMESTAMP, &timestamp, 1));
    int32_t objectId = 0;
    EXPECT_TRUE(metadata->addEntry(OHOS_CONTROL_FOCUS_TRACKING_OBJECT_ID, &objectId, 1));

    std::vector<uint8_t> result;
    OHOS::Camera::MetadataUtils::ConvertMetadataToVec(metadata, result);
    streamMetadata->ProcessDetectedObjectLifecycle(result);
    streamMetadata->EnableDetectedObjectLifecycleReport(false, 3000);

    vector<uint8_t> buffer;
    streamMetadata->GetDetectedObjectLifecycleBuffer(buffer);
    EXPECT_FALSE(buffer.empty());
}

/*
 * Feature: Framework
 * Function: Test HStreamMetadata & HStreamCommon
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HStreamMetadata & HStreamCommon
 */
HWTEST_F(HStreamMetadataUnit, camera_fwcoverage_unittest_027, TestSize.Level0)
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
HWTEST_F(HStreamMetadataUnit, camera_fwcoverage_unittest_028, TestSize.Level0)
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
HWTEST_F(HStreamMetadataUnit, camera_fwcoverage_unittest_029, TestSize.Level0)
{
    MockHStreamMetadataCallbackStub stub;
    MessageParcel data;
    data.WriteInterfaceToken(stub.GetDescriptor());
    data.WriteInt32(0);
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    data.WriteParcelable(metadata.get());
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(IStreamMetadataCallbackIpcCode::COMMAND_ON_METADATA_RESULT);
    EXPECT_CALL(stub, OnMetadataResult(_, _))
        .WillOnce(Return(0));
    int errCode = stub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(errCode, 0);
}
}
}