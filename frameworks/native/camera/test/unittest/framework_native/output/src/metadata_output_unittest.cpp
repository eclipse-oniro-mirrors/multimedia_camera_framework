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

#include "metadata_output_unittest.h"

#include "gtest/gtest.h"
#include <cstdint>
#include <vector>

#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera/metadata_output.h"
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

void CameraMetadataOutputUnit::SetUpTestCase(void)
{
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
}

void CameraMetadataOutputUnit::TearDownTestCase(void) {}

void CameraMetadataOutputUnit::SetUp()
{
    cameraManager_ = CameraManager::GetInstance();
}

void CameraMetadataOutputUnit::TearDown()
{
    cameraManager_ = nullptr;
}

class AppMetadataCallback : public MetadataObjectCallback, public MetadataStateCallback {
public:
    void OnMetadataObjectsAvailable(std::vector<sptr<MetadataObject>> metaObjects) const
    {
        MEDIA_DEBUG_LOG("AppMetadataCallback::OnMetadataObjectsAvailable received");
    }
    void OnError(int32_t errorCode) const
    {
        MEDIA_DEBUG_LOG("AppMetadataCallback::OnError %{public}d", errorCode);
    }
};

/*
 * Feature: Framework
 * Function: Test metadataoutput with SetCapturingMetadataObjectTypes
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput when ObjectTypes is not empty
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_001, TestSize.Level1)
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

    sptr<CaptureOutput> metadata = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(metadata, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)metadata;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    session->BeginConfig();
    session->AddInput(input);
    session->AddOutput(metadata);
    session->CommitConfig();
    session->Start();

    std::vector<MetadataObjectType> metadataObjectTypes = {
        MetadataObjectType::BAR_CODE_DETECTION,
        MetadataObjectType::BASE_FACE_DETECTION,
        MetadataObjectType::CAT_BODY,
        MetadataObjectType::CAT_FACE,
        MetadataObjectType::FACE,
    };
    metadatOutput->SetCapturingMetadataObjectTypes(metadataObjectTypes);
    EXPECT_NE(metadatOutput, nullptr);

    input->Close();
    session->Stop();
    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test metadataoutput with SetCapturingMetadataObjectTypes
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput when ObjectTypes is not empty
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_002, TestSize.Level1)
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

    sptr<CaptureOutput> metadata = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(metadata, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)metadata;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    session->BeginConfig();
    session->AddInput(input);
    session->AddOutput(metadata);
    session->CommitConfig();
    session->Start();

    std::vector<MetadataObjectType> metadataObjectTypes = {
        MetadataObjectType::BAR_CODE_DETECTION,
        MetadataObjectType::BASE_FACE_DETECTION,
        MetadataObjectType::CAT_BODY,
        MetadataObjectType::CAT_FACE,
        MetadataObjectType::HUMAN_BODY,
    };
    metadatOutput->SetCapturingMetadataObjectTypes(metadataObjectTypes);
    EXPECT_NE(metadatOutput, nullptr);

    input->Close();
    session->Stop();
    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test metadataoutput with SetCapturingMetadataObjectTypes
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput when ObjectTypes is empty
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_003, TestSize.Level1)
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

    sptr<CaptureOutput> metadata = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(metadata, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)metadata;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    session->BeginConfig();

    session->AddInput(input);
    session->AddOutput(metadata);

    session->CommitConfig();
    session->Start();

    std::vector<MetadataObjectType> metadataObjectTypes = {};
    metadatOutput->SetCapturingMetadataObjectTypes(metadataObjectTypes);
    EXPECT_NE(metadatOutput, nullptr);

    input->Close();
    session->Stop();
    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test metadataoutput with Get and Set AppObjectCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput with Get and Set AppObjectCallback when appStateCallback_ is
 *          nullptr or is not nullptr
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_004, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());

    sptr<CaptureOutput> output = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(output, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)output;

    std::shared_ptr<MetadataObjectCallback> metadataObjectCallback =
        std::make_shared<AppMetadataCallback>();
    metadatOutput->SetCallback(metadataObjectCallback);
    std::shared_ptr<MetadataObjectCallback> ret = metadatOutput->GetAppObjectCallback();
    EXPECT_EQ(ret, metadataObjectCallback);

    pid_t pid = 0;
    metadatOutput->appStateCallback_ = nullptr;
    metadatOutput->CameraServerDied(pid);
}

/*
 * Feature: Framework
 * Function: Test metadataoutput with checkValidType
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput with checkValidType when ret is true
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_005, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());

    sptr<CaptureOutput> output = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(output, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)output;

    std::vector<MetadataObjectType> typeAdded = {
        MetadataObjectType::CAT_BODY,
        MetadataObjectType::CAT_FACE,
        MetadataObjectType::FACE,
    };
    std::vector<MetadataObjectType> supportedType = {
        MetadataObjectType::CAT_BODY,
        MetadataObjectType::CAT_FACE,
        MetadataObjectType::FACE,
        MetadataObjectType::HUMAN_BODY,
    };
    bool ret = metadatOutput->checkValidType(typeAdded, supportedType);
    EXPECT_TRUE(ret);
}

/*
 * Feature: Framework
 * Function: Test metadataoutput with checkValidType
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput with checkValidType when ret is false
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_006, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());

    sptr<CaptureOutput> output = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(output, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)output;

    std::vector<MetadataObjectType> typeAdded = {
        MetadataObjectType::DOG_BODY,
        MetadataObjectType::DOG_FACE,
        MetadataObjectType::BASE_FACE_DETECTION,
    };
    std::vector<MetadataObjectType> supportedType = {
        MetadataObjectType::CAT_BODY,
        MetadataObjectType::CAT_FACE,
        MetadataObjectType::FACE,
        MetadataObjectType::HUMAN_BODY,
    };
    bool ret = metadatOutput->checkValidType(typeAdded, supportedType);
    EXPECT_FALSE(ret);
}

/*
 * Feature: Framework
 * Function: Test metadataoutput with CreateStream
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput with CreateStream for normal branches
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_007, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());

    sptr<CaptureOutput> output = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(output, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)output;

    int32_t ret = metadatOutput->CreateStream();
    EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test metadataoutput with ReleaseSurface
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput with ReleaseSurface when surface_ is nullptr
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_008, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());

    sptr<CaptureOutput> output = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(output, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)output;

    metadatOutput->surface_ = nullptr;
    metadatOutput->ReleaseSurface();
    EXPECT_NE(metadatOutput, nullptr);
}

/*
 * Feature: Framework
 * Function: Test metadataoutput with ReleaseSurface and GetSurface
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput  when surface_ is not nullptr
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_009, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());

    sptr<CaptureOutput> output = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(output, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)output;

    metadatOutput->surface_ = IConsumerSurface::Create();
    metadatOutput->ReleaseSurface();
    EXPECT_NE(metadatOutput, nullptr);
    sptr<IConsumerSurface> ret = metadatOutput->GetSurface();
    EXPECT_EQ(ret, nullptr);
}

/*
 * Feature: Framework
 * Function: Test metadataoutput with ProcessMetadata
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput with ProcessMetadata when result is nullptr
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_010, TestSize.Level1)
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

    sptr<CaptureOutput> metadata = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(metadata, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)metadata;

    std::shared_ptr<OHOS::Camera::CameraMetadata> result = nullptr;
    int32_t streamId = 0;
    std::vector<sptr<MetadataObject>> metaObjects = {};
    bool isNeedMirror = true;
    bool isNeedFlip = true;
    metadatOutput->ProcessMetadata(streamId, result, metaObjects, isNeedMirror, isNeedFlip);
    EXPECT_NE(metadatOutput, nullptr);
}

/*
 * Feature: Framework
 * Function: Test metadataoutput with ProcessMetadata
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput with ProcessMetadata when result is not nullptr
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_011, TestSize.Level1)
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

    sptr<CaptureOutput> metadata = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(metadata, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)metadata;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    session->BeginConfig();
    session->AddInput(input);
    session->AddOutput(metadata);
    session->CommitConfig();
    session->Start();

    std::shared_ptr<OHOS::Camera::CameraMetadata> result = session->GetMetadata();
    EXPECT_NE(result, nullptr);
    int32_t streamId = 0;
    std::vector<sptr<MetadataObject>> metaObjects = {};
    bool isNeedMirror = true;
    bool isNeedFlip = true;
    metadatOutput->reportFaceResults_ = true;
    metadatOutput->ProcessMetadata(streamId, result, metaObjects, isNeedMirror, isNeedFlip);
    EXPECT_NE(metadatOutput, nullptr);

    std::vector<uint8_t> mockHumanFaceTagfromHal = {
        0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    bool status = result->addEntry(OHOS_STATISTICS_DETECT_HUMAN_FACE_INFOS, mockHumanFaceTagfromHal.data(),
        mockHumanFaceTagfromHal.size());
    ASSERT_TRUE(status);
    metadatOutput->ProcessMetadata(streamId, result, metaObjects, isNeedMirror, isNeedFlip);
    EXPECT_NE(metadatOutput, nullptr);

    input->Close();
    session->Stop();
    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test metadataoutput with appObjectCallback_ is nullptr or cameraMetadataCallback_ is not nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput with appObjectCallback_ is nullptr or cameraMetadataCallback_ is not nullptr
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_012, TestSize.Level1)
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

    sptr<CaptureOutput> metadata = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(metadata, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)metadata;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    session->BeginConfig();
    session->AddInput(input);
    session->AddOutput(metadata);
    session->CommitConfig();
    session->Start();

    std::shared_ptr<MetadataObjectCallback> appObjectCallback = std::make_shared<AppMetadataCallback>();
    metadatOutput->appObjectCallback_ = appObjectCallback;
    sptr<IStreamMetadataCallback> cameraMetadataCallback = new HStreamMetadataCallbackImpl(metadatOutput);
    metadatOutput->cameraMetadataCallback_ = cameraMetadataCallback;
    metadatOutput->SetCallback(appObjectCallback);
    EXPECT_EQ(metadatOutput->GetAppObjectCallback(), appObjectCallback);

    metadatOutput->appObjectCallback_ = nullptr;
    metadatOutput->SetCallback(appObjectCallback);
    EXPECT_EQ(metadatOutput->GetAppObjectCallback(), appObjectCallback);

    metadatOutput->stream_ = nullptr;
    metadatOutput->SetCallback(appObjectCallback);
    EXPECT_EQ(metadatOutput->GetAppObjectCallback(), appObjectCallback);

    if (cameraMetadataCallback) {
        cameraMetadataCallback = nullptr;
    }
    input->Close();
    session->Stop();
    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test metadataoutput with GenerateObjects and ProcessRectBox
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput with GenerateObjects when is not supported and ProcessRectBox
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_013, TestSize.Level1)
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

    sptr<CaptureOutput> metadata = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(metadata, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)metadata;

    MetadataObjectType type = MetadataObjectType::INVALID;
    camera_metadata_item_t metadataItem;
    std::vector<sptr<MetadataObject>> metaObjects = {};
    bool isNeedMirror = true;
    bool isNeedFlip = false;
    metadatOutput->reportFaceResults_ = true;
    MetadataCommonUtils::GenerateObjects(metadataItem, type, metaObjects, isNeedMirror, isNeedFlip,
        RectBoxType::RECT_CAMERA);
    EXPECT_EQ(metaObjects.size(), 0);

    Rect ret = MetadataCommonUtils::ProcessRectBox(1, 1, 1, 1, isNeedMirror, isNeedFlip,
        RectBoxType::RECT_CAMERA);
    EXPECT_EQ(ret.topLeftX, 0.999999);
    EXPECT_EQ(ret.topLeftY, 0.999999);
    EXPECT_EQ(ret.width, 0);
    EXPECT_EQ(ret.height, 0);

    isNeedMirror = false;
    isNeedFlip = true;
    ret = MetadataCommonUtils::ProcessRectBox(1, 1, 1, 1, isNeedMirror, isNeedFlip,
        RectBoxType::RECT_CAMERA);
    EXPECT_EQ(ret.topLeftX, 0.000001);
    EXPECT_EQ(ret.topLeftY, 0.000001);
    EXPECT_EQ(ret.width, 0);
    EXPECT_EQ(ret.height, 0);

    input->Close();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test metadataoutput with ProcessExternInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput with ProcessExternInfo when MetadataObjectType is different
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_014, TestSize.Level1)
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

    sptr<CaptureOutput> metadata = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(metadata, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)metadata;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    session->BeginConfig();
    session->AddInput(input);
    session->AddOutput(metadata);
    session->CommitConfig();
    session->Start();

    sptr<MetadataObjectFactory> factoryPtr = new MetadataObjectFactory();
    std::shared_ptr<OHOS::Camera::CameraMetadata> result = session->GetMetadata();
    int32_t format = OHOS_CAMERA_FORMAT_YCRCB_420_SP;
    result->addEntry(OHOS_ABILITY_CAMERA_MODES, &format, 1);
    camera_metadata_item_t metadataItem;
    int32_t ret = OHOS::Camera::FindCameraMetadataItem(result->get(), OHOS_ABILITY_CAMERA_MODES, &metadataItem);
    EXPECT_EQ(ret, CAM_META_SUCCESS);
    int32_t index = 0;
    MetadataObjectType type = MetadataObjectType::FACE;
    bool isNeedMirror = true;
    bool isNeedFlip = false;
    MetadataCommonUtils::ProcessExternInfo(factoryPtr, metadataItem, index, type, isNeedMirror, isNeedFlip,
        RectBoxType::RECT_CAMERA);
    EXPECT_NE(factoryPtr, nullptr);

    type = MetadataObjectType::CAT_FACE;
    MetadataCommonUtils::ProcessExternInfo(factoryPtr, metadataItem, index, type, isNeedMirror, isNeedFlip,
        RectBoxType::RECT_CAMERA);
    EXPECT_NE(factoryPtr, nullptr);

    type = MetadataObjectType::DOG_FACE;
    MetadataCommonUtils::ProcessExternInfo(factoryPtr, metadataItem, index, type, isNeedMirror, isNeedFlip,
        RectBoxType::RECT_CAMERA);
    EXPECT_NE(factoryPtr, nullptr);

    type = static_cast<MetadataObjectType>(64);
    MetadataCommonUtils::ProcessExternInfo(factoryPtr, metadataItem, index, type, isNeedMirror, isNeedFlip,
        RectBoxType::RECT_CAMERA);
    EXPECT_NE(factoryPtr, nullptr);

    input->Close();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test MetadataObjectFactory with OnMetadataResult when inputDevice is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test MetadataObjectFactory with OnMetadataResult when inputDevice is nullptr
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_015, TestSize.Level1)
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

    sptr<CaptureOutput> metadata = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(metadata, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)metadata;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    session->BeginConfig();
    session->AddInput(input);
    session->AddOutput(metadata);
    session->CommitConfig();
    session->Start();
    session->innerInputDevice_ = nullptr;

    int32_t streamId = 0;
    std::shared_ptr<OHOS::Camera::CameraMetadata> result = session->GetMetadata();
    EXPECT_NE(result, nullptr);
    std::shared_ptr<HStreamMetadataCallbackImpl> hstreamMetadataCallbackImpl =
        std::make_shared<HStreamMetadataCallbackImpl>(metadatOutput);
    int32_t ret = hstreamMetadataCallbackImpl->OnMetadataResult(streamId, result);
    EXPECT_EQ(ret, CameraErrorCode::SUCCESS);

    input->Close();
    session->Stop();
    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test MetadataObjectFactory with createMetadataObject when MetadataObjectType is different
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test MetadataObjectFactory with createMetadataObject when MetadataObjectType is different
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_016, TestSize.Level1)
{
    std::shared_ptr<MetadataObjectFactory> factory = std::make_shared<MetadataObjectFactory>();
    ASSERT_NE(factory, nullptr);

    MetadataObjectType type = MetadataObjectType::HUMAN_BODY;
    sptr<MetadataObject> ret = factory->createMetadataObject(type);
    EXPECT_NE(ret, nullptr);

    type = MetadataObjectType::FACE;
    ret = factory->createMetadataObject(type);
    EXPECT_NE(ret, nullptr);

    type = MetadataObjectType::CAT_FACE;
    ret = factory->createMetadataObject(type);
    EXPECT_NE(ret, nullptr);

    type = MetadataObjectType::CAT_BODY;
    ret = factory->createMetadataObject(type);
    EXPECT_NE(ret, nullptr);

    type = MetadataObjectType::DOG_FACE;
    ret = factory->createMetadataObject(type);
    EXPECT_NE(ret, nullptr);

    type = MetadataObjectType::DOG_BODY;
    ret = factory->createMetadataObject(type);
    EXPECT_NE(ret, nullptr);

    type = MetadataObjectType::SALIENT_DETECTION;
    ret = factory->createMetadataObject(type);
    EXPECT_NE(ret, nullptr);

    type = MetadataObjectType::BAR_CODE_DETECTION;
    ret = factory->createMetadataObject(type);
    EXPECT_NE(ret, nullptr);

    type = MetadataObjectType::INVALID;
    ret = factory->createMetadataObject(type);
    EXPECT_NE(ret, nullptr);
}

/*
 * Feature: Framework
 * Function: Test metadataoutput with cameraserverdied and stop
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput with cameraserverdied and stop
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_017, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    sptr<CaptureOutput> output = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(output, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)output;

    pid_t pid = 0;
    metadatOutput->CameraServerDied(pid);
    EXPECT_EQ(metadatOutput->Stop(), CameraErrorCode::SERVICE_FATL_ERROR);
}

/*
 * Feature: Framework
 * Function: Test metadataoutput with stream_ is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput with stream_ is nullptr
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_018, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();

    sptr<CaptureOutput> output = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(output, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)output;

    pid_t pid = 0;
    metadatOutput->stream_ = nullptr;
    metadatOutput->CameraServerDied(pid);
    EXPECT_EQ(metadatOutput->Stop(), CameraErrorCode::SERVICE_FATL_ERROR);
    EXPECT_EQ(metadatOutput->Release(), CameraErrorCode::SERVICE_FATL_ERROR);
}

/*
 * Feature: Framework
 * Function: Test metadataoutput with start when session_ is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput with start when session_ is nullptr
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_019, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();

    sptr<CaptureOutput> metadata = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(metadata, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)metadata;

    metadatOutput->session_ = nullptr;
    EXPECT_EQ(metadatOutput->Start(), CameraErrorCode::SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test metadataoutput with start when not commit
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput with start when not commit
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_020, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureOutput> metadata = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(metadata, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)metadata;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    session->BeginConfig();
    session->AddInput(input);
    session->AddOutput(metadata);

    EXPECT_EQ(metadatOutput->Start(), CameraErrorCode::SUCCESS);

    session->CommitConfig();
    session->Start();

    input->Close();
}

/*
 * Feature: Framework
 * Function: Test metadataoutput with start when stream_ is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput with start when stream_ is nullptr
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_021, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureOutput> metadata = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(metadata, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)metadata;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    session->BeginConfig();

    session->AddInput(input);
    session->AddOutput(metadata);

    session->CommitConfig();
    session->Start();

    metadatOutput->stream_ = nullptr;
    EXPECT_EQ(metadatOutput->Start(), CameraErrorCode::SUCCESS);

    input->Close();
}

/*
 * Feature: Framework
 * Function: Test metadataoutput with start
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput with start
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_022, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureOutput> metadata = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(metadata, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)metadata;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    ASSERT_NE(session, nullptr);

    session->BeginConfig();

    session->AddInput(input);
    session->AddOutput(metadata);

    session->CommitConfig();
    session->Start();

    metadatOutput->stream_ = nullptr;
    EXPECT_EQ(metadatOutput->Start(), CameraErrorCode::SUCCESS);
    EXPECT_EQ(metadatOutput->Stop(), CameraErrorCode::SERVICE_FATL_ERROR);
    metadatOutput->Release();

    input->Close();
}

/*
 * Feature: Framework
 * Function: Test metadataoutput when destruction
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput when destruction
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_023, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();

    sptr<CaptureOutput> output = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(output, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)output;

    metadatOutput->Release();
    EXPECT_NE(metadatOutput->Stop(), CameraErrorCode::SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test MetadataObject when multiple construction parameters
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test MetadataObject when multiple construction parameters
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_024, TestSize.Level1)
{
    MetadataObjectType type = MetadataObjectType::FACE;
    int32_t timestamp = 0;
    Rect rect = {0, 0, 0, 0};
    int32_t objectId = 0;
    int32_t confidence = 0;
    std::shared_ptr<MetadataObject> object = std::make_shared<MetadataObject>(type, timestamp, rect,
        objectId, confidence);
    ASSERT_NE(object, nullptr);
}

/*
 * Feature: Framework
 * Function: Test MetadataObject with GetAppStateCallback and convert
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test MetadataObject with GetAppStateCallback and convert
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_025, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureOutput> metadata = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(metadata, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)metadata;

    metadatOutput->appStateCallback_ = nullptr;
    std::shared_ptr<MetadataStateCallback> ret = metadatOutput->GetAppStateCallback();
    EXPECT_EQ(ret, nullptr);

    std::vector<MetadataObjectType> typesOfMetadata;
    typesOfMetadata.push_back(MetadataObjectType::FACE);
    std::vector<int32_t> result = metadatOutput->convert(typesOfMetadata);
    EXPECT_TRUE(std::find(result.begin(), result.end(), 0) != result.end());
}

/*
 * Feature: Framework
 * Function: Test MetadataObjectListener with ProcessMetadataBuffer
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test MetadataObjectListener with ProcessMetadataBuffer
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_026, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureOutput> metadata = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(metadata, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)metadata;

    std::shared_ptr<MetadataObjectListener> listener = std::make_shared<MetadataObjectListener>(metadatOutput);
    sptr<SurfaceBuffer> buffer = nullptr;
    int32_t ret = listener->ProcessMetadataBuffer(buffer, 0);
    EXPECT_EQ(ret, CameraErrorCode::SUCCESS);
}

/*
 * Feature: Framework
 * Function: Test MetadataOutput with AddMetadataObjectTypes and RemoveMetadataObjectTypes
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test MetadataOutput with AddMetadataObjectTypes and RemoveMetadataObjectTypes
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_027, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureOutput> metadata = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(metadata, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)metadata;

    std::vector<MetadataObjectType> metadataObjectTypes = {
        MetadataObjectType::BAR_CODE_DETECTION,
        MetadataObjectType::BASE_FACE_DETECTION,
        MetadataObjectType::CAT_BODY,
        MetadataObjectType::CAT_FACE,
        MetadataObjectType::FACE,
    };
    int32_t ret = metadatOutput->AddMetadataObjectTypes(metadataObjectTypes);
    EXPECT_EQ(ret, CameraErrorCode::SESSION_NOT_CONFIG);
    ret = metadatOutput->RemoveMetadataObjectTypes(metadataObjectTypes);
    EXPECT_EQ(ret, CameraErrorCode::SESSION_NOT_CONFIG);

    metadataObjectTypes.resize(0);
    ret = metadatOutput->AddMetadataObjectTypes(metadataObjectTypes);
    EXPECT_EQ(ret, CameraErrorCode::SESSION_NOT_CONFIG);
    ret = metadatOutput->RemoveMetadataObjectTypes(metadataObjectTypes);
    EXPECT_EQ(ret, CameraErrorCode::SESSION_NOT_CONFIG);

    metadataObjectTypes.resize(0);
    metadataObjectTypes.push_back(MetadataObjectType::FACE);
    metadatOutput->session_ = nullptr;
    ret = metadatOutput->AddMetadataObjectTypes(metadataObjectTypes);
    EXPECT_EQ(ret, CameraErrorCode::SESSION_NOT_CONFIG);
    ret = metadatOutput->RemoveMetadataObjectTypes(metadataObjectTypes);
    EXPECT_EQ(ret, CameraErrorCode::SESSION_NOT_CONFIG);
}

/*
 * Feature: Framework
 * Function: Test MetadataObjectListener with OnBufferAvailable
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test MetadataObjectListener with OnBufferAvailable
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_028, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;

    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    if (camInput->GetCameraDevice()) {
        camInput->GetCameraDevice()->SetMdmCheck(false);
        camInput->GetCameraDevice()->Open();
    }

    sptr<CaptureOutput> metadata = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(metadata, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)metadata;

    metadatOutput->surface_ = IConsumerSurface::Create();
    metadatOutput->appStateCallback_ = std::make_shared<MetadataStateCallbackTest>();

    std::shared_ptr<MetadataObjectListener> listener = std::make_shared<MetadataObjectListener>(metadatOutput);
    listener->OnBufferAvailable();
    EXPECT_NE(listener, nullptr);

    metadatOutput->appStateCallback_ = nullptr;
    std::shared_ptr<MetadataObjectListener> listener_2 = std::make_shared<MetadataObjectListener>(metadatOutput);
    listener_2->OnBufferAvailable();
    EXPECT_NE(listener_2, nullptr);
}

/*
 * Feature: Framework
 * Function: Test MetadataObjectFactory with OnMetadataResult when inputDevice is not nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test MetadataObjectFactory with OnMetadataResult when inputDevice is not nullptr
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_029, TestSize.Level1)
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

    sptr<CaptureOutput> metadata = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(metadata, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)metadata;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    session->BeginConfig();
    session->AddInput(input);
    session->AddOutput(metadata);
    session->CommitConfig();
    session->Start();

    int32_t streamId = 0;
    std::shared_ptr<OHOS::Camera::CameraMetadata> result = session->GetMetadata();
    EXPECT_NE(result, nullptr);
    std::shared_ptr<MetadataObjectCallback> callback = std::make_shared<MetadataObjectCallbackTest>();
    metadatOutput->appObjectCallback_ = callback;
    metadatOutput->reportFaceResults_ = true;
    std::shared_ptr<HStreamMetadataCallbackImpl> hstreamMetadataCallbackImpl =
        std::make_shared<HStreamMetadataCallbackImpl>(metadatOutput);
    int32_t ret = hstreamMetadataCallbackImpl->OnMetadataResult(streamId, result);
    EXPECT_EQ(ret, CameraErrorCode::SUCCESS);

    metadatOutput->reportFaceResults_ = false;
    metadatOutput->reportLastFaceResults_ = false;
    std::shared_ptr<HStreamMetadataCallbackImpl> hstreamMetadataCallbackImpl_2 =
        std::make_shared<HStreamMetadataCallbackImpl>(metadatOutput);
    ret = hstreamMetadataCallbackImpl_2->OnMetadataResult(streamId, result);
    EXPECT_EQ(ret, CameraErrorCode::SUCCESS);

    input->Close();
    session->Stop();
    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test HStreamMetadataCallbackImpl with Constructor.
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Constructor for just call.
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_function_unittest_001, TestSize.Level1)
{
    std::shared_ptr<HStreamMetadataCallbackImpl> hStreamMetadataCallbackImpl =
        std::make_shared<HStreamMetadataCallbackImpl>(nullptr);
    EXPECT_EQ(hStreamMetadataCallbackImpl->innerMetadataOutput, nullptr);
}

/*
 * Feature: Framework
 * Function: Test metadataoutput with SetCapturingMetadataObjectTypes
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput when ObjectTypes is not empty
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_function_unittest_002, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> metadata = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(metadata, nullptr);
    sptr<MetadataOutput> metadataOutput = (sptr<MetadataOutput>&)metadata;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    session->BeginConfig();
    session->AddInput(input);
    session->AddOutput(metadata);
    session->CommitConfig();
    session->Start();

    metadataOutput->appStateCallback_ = std::make_shared<MetadataStateCallbackTest>();
    metadataOutput->appStateCallback_->OnError(CameraErrorCode::SERVICE_FATL_ERROR);

    input->Close();
    session->Stop();
    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test metadataoutput with SetCapturingMetadataObjectTypes
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput when ObjectTypes is not empty
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_function_unittest_003, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    ASSERT_FALSE(cameras.empty());

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> metadata = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(metadata, nullptr);
    sptr<MetadataOutput> metadataOutput = (sptr<MetadataOutput>&)metadata;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    session->BeginConfig();
    session->AddInput(input);
    session->AddOutput(metadata);
    session->CommitConfig();
    session->Start();

    metadataOutput->appObjectCallback_ = std::make_shared<MetadataObjectCallbackTest>();
    std::vector<sptr<MetadataObject>> metaObjects = {};
    metadataOutput->appObjectCallback_->OnMetadataObjectsAvailable(metaObjects);

    input->Close();
    session->Stop();
    session->Release();
    input->Release();
}

/*
 * Feature: Framework
 * Function: Test SetFocusTrackingMetaInfoCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetFocusTrackingMetaInfoCallback
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_030, TestSize.Level0)
{
    sptr<CaptureOutput> metadata = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(metadata, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)metadata;
 
    std::shared_ptr<OHOS::Camera::CameraMetadata> result = nullptr;
    FocusTrackingMetaInfo focusTrackingMetaInfo;
    metadatOutput->ProcessFocusTrackingMetaInfo(result, focusTrackingMetaInfo);
 
    std::shared_ptr<FocusTrackingMetaInfoCallback> callback = nullptr;
    metadatOutput->SetFocusTrackingMetaInfoCallback(callback);
    EXPECT_EQ(metadatOutput->focusTrackingMetaInfoCallback_, nullptr);
}
 
/*
 * Feature: Framework
 * Function: Test ProcessFocusTrackingRegion
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessFocusTrackingRegion
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_031, TestSize.Level0)
{
    sptr<CaptureOutput> metadata = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(metadata, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)metadata;
    Rect region;
    std::shared_ptr<OHOS::Camera::CameraMetadata> result = nullptr;
    EXPECT_EQ(metadatOutput->ProcessFocusTrackingRegion(result, region), false);
}

/*
 * Feature: Framework
 * Function: Test GetSupportedMetadataObjectTypes
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSupportedMetadataObjectTypes
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_032, TestSize.Level0)
{
    sptr<CaptureOutput> metadata = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(metadata, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)metadata;
    vector<MetadataObjectType>res = metadatOutput->GetSupportedMetadataObjectTypes();
    EXPECT_EQ(res.size(), 0);
}

/*
 * Feature: Framework
 * Function: Test MetadataObjectFactory with createMetadataObject when MetadataObjectType is BASE_FACE_DETECTION
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test MetadataObjectFactory with createMetadataObject when MetadataObjectType is BASE_FACE_DETECTION
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_033, TestSize.Level4)
{
    std::shared_ptr<MetadataObjectFactory> factory = std::make_shared<MetadataObjectFactory>();
    ASSERT_NE(factory, nullptr);
    factory->ResetParameters();

    MetadataObjectType type = MetadataObjectType::BASE_FACE_DETECTION;
    sptr<MetadataObject> ret = factory->createMetadataObject(type);
    EXPECT_NE(ret, nullptr);
}

/*
 * Feature: Framework
 * Function: Test metadataoutput with ProcessExternInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput with ProcessExternInfo when MetadataObjectType is BASE_FACE_DETECTION
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_033, TestSize.Level4)
{
    sptr<MetadataObjectFactory> factory = new MetadataObjectFactory();
    ASSERT_NE(factory, nullptr);
    camera_metadata_item_t metadataItem{};
    metadataItem.index = 0;
    metadataItem.item = OHOS_ABILITY_CAMERA_MODES;
    metadataItem.data_type = META_TYPE_INT32;
    metadataItem.count = 12;
    int32_t mockData[12] = {
        1,
        10, 20, 30, 40,
        50, 60, 70, 80,
        15,
        25,
        5
    };
    metadataItem.data.i32 = mockData;
    int32_t index = 0;
    MetadataObjectType type = MetadataObjectType::BASE_FACE_DETECTION;
    bool isNeedMirror = true;
    bool isNeedFlip = false;
    MetadataCommonUtils::ProcessExternInfo(*factory, metadataItem, index, type, isNeedMirror, isNeedFlip,
        RectBoxType::RECT_CAMERA);
    EXPECT_EQ(factory->pitchAngle_, 15);
}
}
}
