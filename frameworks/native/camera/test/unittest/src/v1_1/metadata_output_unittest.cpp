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

using namespace testing::ext;
using ::testing::A;
using ::testing::InSequence;
using ::testing::Mock;
using ::testing::Return;
using ::testing::_;

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;

void CameraMetadataOutputUnit::SetUpTestCase(void) {}

void CameraMetadataOutputUnit::TearDownTestCase(void) {}

void CameraMetadataOutputUnit::SetUp()
{
    cameraManager_ = CameraManager::GetInstance();
}

void CameraMetadataOutputUnit::TearDown()
{
    NativeAuthorization();
    cameraManager_ = nullptr;
}

void CameraMetadataOutputUnit::NativeAuthorization()
{
    const char *perms[2];
    perms[0] = "ohos.permission.DISTRIBUTED_DATASYNC";
    perms[1] = "ohos.permission.CAMERA";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .aclsNum = 0,
        .dcaps = NULL,
        .perms = perms,
        .acls = NULL,
        .processName = "native_camera_tdd",
        .aplStr = "system_basic",
    };
    tokenId_ = GetAccessTokenId(&infoInstance);
    uid_ = IPCSkeleton::GetCallingUid();
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid_, userId_);
    MEDIA_DEBUG_LOG("CameraMetadataOutputUnit::NativeAuthorization g_uid:%{public}d", uid_);
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

/*
 * Feature: Framework
 * Function: Test metadataoutput with SetCapturingMetadataObjectTypes
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test metadataoutput when ObjectTypes is not empty
 */
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_001, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

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
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_002, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

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
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_003, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

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
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_004, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

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
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_005, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

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
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_006, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

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
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_007, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

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
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_008, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

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
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_009, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    sptr<CaptureOutput> output = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(output, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)output;

    metadatOutput->surface_ = IConsumerSurface::Create();;
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
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_010, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

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
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_011, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

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
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_012, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

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
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_013, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> metadata = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(metadata, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)metadata;

    MetadataObjectType type = MetadataObjectType::INVALID;
    camera_metadata_item_t metadataItem;
    std::vector<sptr<MetadataObject>> metaObjects = {};
    bool isNeedMirror = true;
    bool isNeedFlip = false;
    metadatOutput->reportFaceResults_ = true;
    metadatOutput->GenerateObjects(metadataItem, type, metaObjects, isNeedMirror, isNeedFlip);
    EXPECT_EQ(metaObjects.size(), 0);

    Rect ret = metadatOutput->ProcessRectBox(1, 1, 1, 1, isNeedMirror, isNeedFlip);
    EXPECT_EQ(ret.topLeftX, 0.999999);
    EXPECT_EQ(ret.topLeftY, 0.999999);
    EXPECT_EQ(ret.width, 0);
    EXPECT_EQ(ret.height, 0);

    isNeedMirror = false;
    isNeedFlip = true;
    ret = metadatOutput->ProcessRectBox(1, 1, 1, 1, isNeedMirror, isNeedFlip);
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
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_014, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> metadata = cameraManager_->CreateMetadataOutput();
    ASSERT_NE(metadata, nullptr);
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)metadata;

    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    session->BeginConfig();
    session->AddInput(input);
    session->AddOutput(metadata);
    session->CommitConfig();
    session->Start();

    sptr<MetadataObjectFactory> factoryPtr = MetadataObjectFactory::GetInstance();
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
    metadatOutput->ProcessExternInfo(factoryPtr, metadataItem, index, type, isNeedMirror, isNeedFlip);
    EXPECT_NE(factoryPtr, nullptr);

    type = MetadataObjectType::CAT_FACE;
    metadatOutput->ProcessExternInfo(factoryPtr, metadataItem, index, type, isNeedMirror, isNeedFlip);
    EXPECT_NE(factoryPtr, nullptr);

    type = MetadataObjectType::DOG_FACE;
    metadatOutput->ProcessExternInfo(factoryPtr, metadataItem, index, type, isNeedMirror, isNeedFlip);
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
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_015, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    camInput->GetCameraDevice()->Open();

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
    auto hstreamMetadataCallbackImpl = std::make_shared<HStreamMetadataCallbackImpl>(metadatOutput);
    int32_t ret = hstreamMetadataCallbackImpl->OnMetadataResult(streamId, result);
    EXPECT_EQ(ret, CameraErrorCode::INVALID_ARGUMENT);

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
HWTEST_F(CameraMetadataOutputUnit, metadata_output_unittest_016, TestSize.Level0)
{
    auto factory = std::make_shared<MetadataObjectFactory>();
    factory->ResetParameters();
    ASSERT_NE(factory, nullptr);

    MetadataObjectType type = MetadataObjectType::HUMAN_BODY;
    sptr<MetadataObject> ret = factory->createMetadataObject(type);
    EXPECT_NE(ret, nullptr);

    type = MetadataObjectType::CAT_BODY;
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

}
}
