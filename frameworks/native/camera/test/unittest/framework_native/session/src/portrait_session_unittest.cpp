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

#include "portrait_session_unittest.h"
#include "gtest/gtest.h"
#include <cstdint>
#include <vector>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_util.h"
#include "gmock/gmock.h"
#include "hap_token_info.h"
#include "ipc_skeleton.h"
#include "metadata_utils.h"
#include "nativetoken_kit.h"
#include "surface.h"
#include "test_common.h"
#include "token_setproc.h"
#include "os_account_manager.h"
#include "sketch_wrapper.h"

using namespace testing::ext;
using ::testing::A;
using ::testing::InSequence;
using ::testing::Mock;
using ::testing::Return;
using ::testing::_;

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;
void CameraPortraitSessionUnitTest::PortraitSessionControlParams(sptr<PortraitSession> portraitSession)
{
    portraitSession->LockForControl();

    std::shared_ptr<Camera::CameraMetadata> metadata =
        portraitSession->GetInputDevice()->GetCameraDeviceInfo()->GetMetadata();
    int32_t effectAbility[2] = {0, 1};
    metadata->addEntry(OHOS_ABILITY_SCENE_PORTRAIT_EFFECT_TYPES, &effectAbility,
        sizeof(effectAbility) / sizeof(effectAbility[0]));
    portraitSession->previewProfile_.abilityId_.push_back(OHOS_ABILITY_SCENE_PORTRAIT_EFFECT_TYPES);
    std::vector<PortraitEffect> effects= portraitSession->GetSupportedPortraitEffects();
    ASSERT_TRUE(effects.size() != 0);

    if (!effects.empty()) {
        portraitSession->SetPortraitEffect(effects[0]);
    }

    uint8_t filterAbility[2] = {0, 1};
    metadata->addEntry(OHOS_ABILITY_SCENE_FILTER_TYPES, &filterAbility,
        sizeof(filterAbility) / sizeof(filterAbility[0]));
    portraitSession->previewProfile_.abilityId_.push_back(OHOS_ABILITY_SCENE_FILTER_TYPES);
    std::vector<FilterType> filterLists= portraitSession->GetSupportedFilters();
    ASSERT_TRUE(filterLists.size() != 0);

    if (!filterLists.empty()) {
        portraitSession->SetFilter(filterLists[0]);
    }

    std::shared_ptr<Camera::CameraMetadata> metadata1 = portraitSession->GetMetadata();
    uint8_t beautyAbility[5] = {OHOS_CAMERA_BEAUTY_TYPE_OFF, OHOS_CAMERA_BEAUTY_TYPE_AUTO,
                                OHOS_CAMERA_BEAUTY_TYPE_SKIN_SMOOTH, OHOS_CAMERA_BEAUTY_TYPE_FACE_SLENDER,
                                OHOS_CAMERA_BEAUTY_TYPE_SKIN_TONE};
    OHOS::Camera::DeleteCameraMetadataItem(metadata1->get(), OHOS_ABILITY_SCENE_BEAUTY_TYPES);
    metadata1->addEntry(OHOS_ABILITY_SCENE_BEAUTY_TYPES, beautyAbility,
        sizeof(beautyAbility) / sizeof(beautyAbility[0]));
    portraitSession->previewProfile_.abilityId_.push_back(OHOS_ABILITY_SCENE_BEAUTY_TYPES);
    std::vector<BeautyType> beautyLists= portraitSession->GetSupportedBeautyTypes();
    ASSERT_TRUE(beautyLists.size() != 0);

    uint8_t faceSlenderBeautyRange[2] = {2, 3};
    metadata1->addEntry(OHOS_ABILITY_BEAUTY_FACE_SLENDER_VALUES, &faceSlenderBeautyRange,
        sizeof(faceSlenderBeautyRange) / sizeof(faceSlenderBeautyRange[0]));
    std::vector<int32_t> rangeLists= portraitSession->GetSupportedBeautyRange(FACE_SLENDER);
    ASSERT_TRUE(rangeLists.size() != 0);

    if (!beautyLists.empty()) {
        portraitSession->SetBeauty(FACE_SLENDER, rangeLists[0]);
    }

    portraitSession->UnlockForControl();
    ASSERT_EQ(portraitSession->GetPortraitEffect(), effects[0]);
    ASSERT_EQ(portraitSession->GetFilter(), filterLists[0]);
    ASSERT_EQ(portraitSession->GetBeauty(FACE_SLENDER), rangeLists[0]);
}

void CameraPortraitSessionUnitTest::PortraitSessionEffectParams(sptr<PortraitSession> portraitSession)
{
    std::shared_ptr<Camera::CameraMetadata> metadata =
        portraitSession->GetInputDevice()->GetCameraDeviceInfo()->GetMetadata();
    int32_t effectAbility[2] = {0, 1};
    metadata->addEntry(OHOS_ABILITY_SCENE_PORTRAIT_EFFECT_TYPES, &effectAbility,
        sizeof(effectAbility) / sizeof(effectAbility[0]));
    portraitSession->previewProfile_.abilityId_.push_back(OHOS_ABILITY_SCENE_PORTRAIT_EFFECT_TYPES);
    std::vector<PortraitEffect> effects= portraitSession->GetSupportedPortraitEffects();
    ASSERT_TRUE(effects.size() != 0);

    if (!effects.empty()) {
        portraitSession->LockForControl();
        portraitSession->SetPortraitEffect(effects[0]);
        portraitSession->UnlockForControl();
    }
    ASSERT_EQ(portraitSession->GetPortraitEffect(), effects[0]);
}

void CameraPortraitSessionUnitTest::PortraitSessionFilterParams(sptr<PortraitSession> portraitSession)
{
    std::shared_ptr<Camera::CameraMetadata> metadata =
        portraitSession->GetInputDevice()->GetCameraDeviceInfo()->GetMetadata();
        uint8_t filterAbility[2] = {0, 1};
    metadata->addEntry(OHOS_ABILITY_SCENE_FILTER_TYPES, &filterAbility,
        sizeof(filterAbility) / sizeof(filterAbility[0]));
    portraitSession->previewProfile_.abilityId_.push_back(OHOS_ABILITY_SCENE_FILTER_TYPES);
    portraitSession->previewProfile_.abilityId_.push_back(OHOS_ABILITY_SCENE_FILTER_TYPES);
    std::vector<FilterType> filterLists= portraitSession->GetSupportedFilters();
    ASSERT_TRUE(filterLists.size() != 0);

    if (!filterLists.empty()) {
        portraitSession->LockForControl();
        portraitSession->SetFilter(filterLists[0]);
        portraitSession->UnlockForControl();
    }
    ASSERT_EQ(portraitSession->GetFilter(), filterLists[0]);
}

void CameraPortraitSessionUnitTest::PortraitSessionBeautyParams(sptr<PortraitSession> portraitSession)
{
    std::shared_ptr<Camera::CameraMetadata> metadata = portraitSession->GetMetadata();
        uint8_t beautyAbility[5] = {OHOS_CAMERA_BEAUTY_TYPE_OFF, OHOS_CAMERA_BEAUTY_TYPE_AUTO,
            OHOS_CAMERA_BEAUTY_TYPE_SKIN_SMOOTH, OHOS_CAMERA_BEAUTY_TYPE_FACE_SLENDER,
            OHOS_CAMERA_BEAUTY_TYPE_SKIN_TONE};
    OHOS::Camera::DeleteCameraMetadataItem(metadata->get(), OHOS_ABILITY_SCENE_BEAUTY_TYPES);
    metadata->addEntry(OHOS_ABILITY_SCENE_BEAUTY_TYPES, beautyAbility,
        sizeof(beautyAbility) / sizeof(beautyAbility[0]));
    portraitSession->previewProfile_.abilityId_.push_back(OHOS_ABILITY_SCENE_BEAUTY_TYPES);
    std::vector<BeautyType> beautyLists= portraitSession->GetSupportedBeautyTypes();
    ASSERT_TRUE(beautyLists.size() != 0);

    uint8_t faceSlenderBeautyRange[2] = {2, 3};
    metadata->addEntry(OHOS_ABILITY_BEAUTY_FACE_SLENDER_VALUES, &faceSlenderBeautyRange,
        sizeof(faceSlenderBeautyRange) / sizeof(faceSlenderBeautyRange[0]));
    std::vector<int32_t> rangeLists= portraitSession->GetSupportedBeautyRange(FACE_SLENDER);
    ASSERT_TRUE(rangeLists.size() != 0);

    if (!beautyLists.empty()) {
        portraitSession->LockForControl();
        portraitSession->SetBeauty(FACE_SLENDER, rangeLists[0]);
        portraitSession->UnlockForControl();
    }
    ASSERT_EQ(portraitSession->GetBeauty(FACE_SLENDER), rangeLists[0]);
}

sptr<CaptureOutput> CameraPortraitSessionUnitTest::CreatePreviewOutput()
{
    previewProfile = {};
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    if (!cameraManager_ || cameras.empty()) {
        return nullptr;
    }
    auto outputCapability = cameraManager_->GetSupportedOutputCapability(cameras[0], static_cast<int32_t>(PORTRAIT));
    if (!outputCapability) {
        return nullptr;
    }

    previewProfile = outputCapability->GetPreviewProfiles();
    if (previewProfile.empty()) {
        return nullptr;
    }

    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    if (surface == nullptr) {
        return nullptr;
    }
    return cameraManager_->CreatePreviewOutput(previewProfile[0], surface);
}

sptr<CaptureOutput> CameraPortraitSessionUnitTest::CreatePhotoOutput()
{
    photoProfile = {};
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    if (!cameraManager_ || cameras.empty()) {
        return nullptr;
    }
    auto outputCapability = cameraManager_->GetSupportedOutputCapability(cameras[0], static_cast<int32_t>(PORTRAIT));
    if (!outputCapability) {
        return nullptr;
    }

    photoProfile = outputCapability->GetPhotoProfiles();
    if (photoProfile.empty()) {
        return nullptr;
    }

    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    if (surface == nullptr) {
        return nullptr;
    }
    sptr<IBufferProducer> surfaceProducer = surface->GetProducer();
    return cameraManager_->CreatePhotoOutput(photoProfile[0], surfaceProducer);
}

void CameraPortraitSessionUnitTest::SetUpTestCase(void) {}

void CameraPortraitSessionUnitTest::TearDownTestCase(void) {}

void CameraPortraitSessionUnitTest::SetUp()
{
    NativeAuthorization();
    cameraManager_ = CameraManager::GetInstance();
}

void CameraPortraitSessionUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("CameraPortraitSessionUnitTest TearDown");
}

void CameraPortraitSessionUnitTest::NativeAuthorization()
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
    MEDIA_DEBUG_LOG("CameraPortraitSessionUnitTest::NativeAuthorization TearDown");
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

/*
 * Feature: Framework
 * Function: Test cameraManager_ and portrait session with beauty/filter/portrait effects
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameraManager_ and portrait session with beauty/filter/portrait effects
 */
HWTEST_F(CameraPortraitSessionUnitTest, portrait_session_unittest_001, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();

    SceneMode mode = PORTRAIT;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras[0]->GetMetadata();
    int32_t modeSet = static_cast<int32_t>(NORMAL);
    metadata->addEntry(OHOS_ABILITY_CAMERA_MODES, &modeSet, 1);
    std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(cameras[0]);
    ASSERT_TRUE(modes.size() != 0);

    sptr<CameraOutputCapability> ability = cameraManager_->GetSupportedOutputCapability(cameras[0], mode);
    ASSERT_NE(ability, nullptr);

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();
    sptr<CaptureSession> captureSession = cameraManager_->CreateCaptureSession(mode);
    ASSERT_NE(captureSession, nullptr);
    sptr<PortraitSession> portraitSession = nullptr;
    portraitSession = static_cast<PortraitSession *> (captureSession.GetRefPtr());
    ASSERT_NE(portraitSession, nullptr);

    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);

    int32_t ret = portraitSession->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = portraitSession->AddInput(input);
    EXPECT_EQ(ret, 0);

    sptr<CameraDevice> info = captureSession->innerInputDevice_->GetCameraDeviceInfo();
    ASSERT_NE(info, nullptr);
    info->modePreviewProfiles_.emplace(static_cast<int32_t>(PORTRAIT), previewProfile);
    info->modePhotoProfiles_.emplace(static_cast<int32_t>(PORTRAIT), photoProfile);

    ret = portraitSession->AddOutput(preview);
    EXPECT_EQ(ret, 0);

    ret = portraitSession->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    ret = portraitSession->CommitConfig();
    EXPECT_EQ(ret, 0);

    PortraitSessionControlParams(portraitSession);

    portraitSession->Release();
}

/*
 * Feature: Framework
 * Function: Test cameraManager with CreateCaptureSession and CommitConfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameraManager to CreateCaptureSession
 */
HWTEST_F(CameraPortraitSessionUnitTest, portrait_session_unittest_002, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    SceneMode mode = PORTRAIT;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras[0]->GetMetadata();
    int32_t modeSet = static_cast<int32_t>(NORMAL);
    metadata->addEntry(OHOS_ABILITY_CAMERA_MODES, &modeSet, 1);
    std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(cameras[0]);
    ASSERT_TRUE(modes.size() != 0);

    sptr<CameraOutputCapability> ability = cameraManager_->GetSupportedOutputCapability(cameras[0], mode);
    ASSERT_NE(ability, nullptr);

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);


    sptr<CaptureSession> captureSession = cameraManager_->CreateCaptureSession(mode);
    ASSERT_NE(captureSession, nullptr);
    sptr<PortraitSession> portraitSession = nullptr;
    portraitSession = static_cast<PortraitSession *> (captureSession.GetRefPtr());
    ASSERT_NE(portraitSession, nullptr);


    int32_t ret = portraitSession->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = portraitSession->AddInput(input);
    EXPECT_EQ(ret, 0);

    sptr<CameraDevice> info = captureSession->innerInputDevice_->GetCameraDeviceInfo();
    ASSERT_NE(info, nullptr);
    info->modePreviewProfiles_.emplace(static_cast<int32_t>(PORTRAIT), previewProfile);
    info->modePhotoProfiles_.emplace(static_cast<int32_t>(PORTRAIT), photoProfile);

    ret = portraitSession->AddOutput(preview);
    EXPECT_EQ(ret, 0);

    ret = portraitSession->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    ret = portraitSession->CommitConfig();
    EXPECT_EQ(ret, 0);
    portraitSession->Release();
}

/*
 * Feature: Framework
 * Function: Test GetSupportedPortraitEffects / GetPortraitEffect / SetPortraitEffect
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetPortraitEffect and SetPortraitEffect with value
 */
HWTEST_F(CameraPortraitSessionUnitTest, portrait_session_unittest_003, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    SceneMode mode = PORTRAIT;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras[0]->GetMetadata();
    int32_t modeSet = static_cast<int32_t>(NORMAL);
    metadata->addEntry(OHOS_ABILITY_CAMERA_MODES, &modeSet, 1);
    std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(cameras[0]);
    ASSERT_TRUE(modes.size() != 0);

    sptr<CameraOutputCapability> ability = cameraManager_->GetSupportedOutputCapability(cameras[0], mode);
    ASSERT_NE(ability, nullptr);

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();


    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> captureSession = cameraManager_->CreateCaptureSession(mode);
    ASSERT_NE(captureSession, nullptr);
    sptr<PortraitSession> portraitSession = nullptr;
    portraitSession = static_cast<PortraitSession *> (captureSession.GetRefPtr());
    ASSERT_NE(portraitSession, nullptr);

    int32_t ret = portraitSession->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = portraitSession->AddInput(input);
    EXPECT_EQ(ret, 0);

    sptr<CameraDevice> info = captureSession->innerInputDevice_->GetCameraDeviceInfo();
    ASSERT_NE(info, nullptr);
    info->modePreviewProfiles_.emplace(static_cast<int32_t>(PORTRAIT), previewProfile);
    info->modePhotoProfiles_.emplace(static_cast<int32_t>(PORTRAIT), photoProfile);

    ret = portraitSession->AddOutput(preview);
    EXPECT_EQ(ret, 0);

    ret = portraitSession->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    ret = portraitSession->CommitConfig();
    EXPECT_EQ(ret, 0);

    PortraitSessionEffectParams(portraitSession);

    portraitSession->Release();
}

/*
 * Feature: Framework
 * Function: Test GetSupportedFilters / GetFilter / SetFilter
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetFilter and SetFilter with value
 */
HWTEST_F(CameraPortraitSessionUnitTest, portrait_session_unittest_004, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    SceneMode mode = PORTRAIT;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras[0]->GetMetadata();
    int32_t modeSet = static_cast<int32_t>(NORMAL);
    metadata->addEntry(OHOS_ABILITY_CAMERA_MODES, &modeSet, 1);
    std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(cameras[0]);
    ASSERT_TRUE(modes.size() != 0);

    sptr<CameraOutputCapability> ability = cameraManager_->GetSupportedOutputCapability(cameras[0], mode);
    ASSERT_NE(ability, nullptr);

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> captureSession = cameraManager_->CreateCaptureSession(mode);
    ASSERT_NE(captureSession, nullptr);
    sptr<PortraitSession> portraitSession = nullptr;
    portraitSession = static_cast<PortraitSession *> (captureSession.GetRefPtr());
    ASSERT_NE(portraitSession, nullptr);

    int32_t ret = portraitSession->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = portraitSession->AddInput(input);
    EXPECT_EQ(ret, 0);

    sptr<CameraDevice> info = captureSession->innerInputDevice_->GetCameraDeviceInfo();
    ASSERT_NE(info, nullptr);
    info->modePreviewProfiles_.emplace(static_cast<int32_t>(PORTRAIT), previewProfile);
    info->modePhotoProfiles_.emplace(static_cast<int32_t>(PORTRAIT), photoProfile);

    ret = portraitSession->AddOutput(preview);
    EXPECT_EQ(ret, 0);

    ret = portraitSession->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    ret = portraitSession->CommitConfig();
    EXPECT_EQ(ret, 0);

    PortraitSessionFilterParams(portraitSession);

    portraitSession->Release();
}

/*
 * Feature: Framework
 * Function: Test GetSupportedBeautyTypes / GetSupportedBeautyRange / GetBeauty / SetBeauty
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetBeauty and SetBeauty with value
 */
HWTEST_F(CameraPortraitSessionUnitTest, portrait_session_unittest_005, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    SceneMode mode = PORTRAIT;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras[0]->GetMetadata();
    int32_t modeSet = static_cast<int32_t>(NORMAL);
    metadata->addEntry(OHOS_ABILITY_CAMERA_MODES, &modeSet, 1);
    std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(cameras[0]);
    ASSERT_TRUE(modes.size() != 0);

    sptr<CameraOutputCapability> ability = cameraManager_->GetSupportedOutputCapability(cameras[0], mode);
    ASSERT_NE(ability, nullptr);

    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();


    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);

    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);

    sptr<CaptureSession> captureSession = cameraManager_->CreateCaptureSession(mode);
    ASSERT_NE(captureSession, nullptr);
    sptr<PortraitSession> portraitSession = nullptr;
    portraitSession = static_cast<PortraitSession *> (captureSession.GetRefPtr());
    ASSERT_NE(portraitSession, nullptr);

    int32_t ret = portraitSession->BeginConfig();
    EXPECT_EQ(ret, 0);

    ret = portraitSession->AddInput(input);
    EXPECT_EQ(ret, 0);

    sptr<CameraDevice> info = captureSession->innerInputDevice_->GetCameraDeviceInfo();
    ASSERT_NE(info, nullptr);
    info->modePreviewProfiles_.emplace(static_cast<int32_t>(PORTRAIT), previewProfile);
    info->modePhotoProfiles_.emplace(static_cast<int32_t>(PORTRAIT), photoProfile);

    ret = portraitSession->AddOutput(preview);
    EXPECT_EQ(ret, 0);

    ret = portraitSession->AddOutput(photo);
    EXPECT_EQ(ret, 0);

    ret = portraitSession->CommitConfig();
    EXPECT_EQ(ret, 0);

    PortraitSessionBeautyParams(portraitSession);

    portraitSession->Release();
}

/*
 * Feature: Framework
 * Function: Test PortraitSession when output is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test PortraitSession when output is nullptr
 */
HWTEST_F(CameraPortraitSessionUnitTest, portrait_session_unittest_006, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    SceneMode mode = PORTRAIT;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras[0]->GetMetadata();
    int32_t modeSet = static_cast<int32_t>(NORMAL);
    metadata->addEntry(OHOS_ABILITY_CAMERA_MODES, &modeSet, 1);
    std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(cameras[0]);
    ASSERT_TRUE(modes.size() != 0);

    sptr<CameraOutputCapability> ability = cameraManager_->GetSupportedOutputCapability(cameras[0], mode);
    ASSERT_NE(ability, nullptr);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);

    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);
    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);
    sptr<CaptureSession> captureSession = cameraManager_->CreateCaptureSession(mode);
    ASSERT_NE(captureSession, nullptr);
    sptr<PortraitSession> portraitSession = nullptr;
    portraitSession = static_cast<PortraitSession *> (captureSession.GetRefPtr());
    ASSERT_NE(portraitSession, nullptr);
    sptr<CaptureOutput> output = nullptr;
    EXPECT_EQ(portraitSession->CanAddOutput(output), false);
    EXPECT_EQ(portraitSession->BeginConfig(), 0);
    EXPECT_EQ(portraitSession->AddInput(input), 0);
    sptr<CameraDevice> info = captureSession->innerInputDevice_->GetCameraDeviceInfo();
    ASSERT_NE(info, nullptr);
    info->modePreviewProfiles_.emplace(static_cast<int32_t>(PORTRAIT), previewProfile);
    info->modePhotoProfiles_.emplace(static_cast<int32_t>(PORTRAIT), photoProfile);
    EXPECT_EQ(portraitSession->AddOutput(preview), 0);
    EXPECT_EQ(portraitSession->AddOutput(photo), 0);
    EXPECT_EQ(portraitSession->CommitConfig(), 0);

    const float aperture = 0.1;
    EXPECT_EQ(portraitSession->CanAddOutput(output), false);
    std::vector<float> supportedVirtualApertures = {};
    std::vector<float> virtualApertures = {};
    OHOS::Camera::DeleteCameraMetadataItem(info->GetMetadata()->get(), OHOS_ABILITY_CAMERA_VIRTUAL_APERTURE_RANGE);
    OHOS::Camera::DeleteCameraMetadataItem(info->GetMetadata()->get(), OHOS_ABILITY_CAMERA_PHYSICAL_APERTURE_RANGE);
    portraitSession->GetSupportedVirtualApertures(virtualApertures);
    EXPECT_EQ(virtualApertures, supportedVirtualApertures);
    float virtualAperture = 0.0f;
    portraitSession->GetVirtualAperture(virtualAperture);
    EXPECT_EQ(virtualAperture, 0.0);
    portraitSession->SetVirtualAperture(aperture);
    std::vector<std::vector<float>> supportedPhysicalApertures;
    std::vector<std::vector<float>> physicalApertures;
    portraitSession->GetSupportedPhysicalApertures(physicalApertures);
    EXPECT_EQ(physicalApertures, supportedPhysicalApertures);
    float physicalAperture = 0.0f;
    portraitSession->GetPhysicalAperture(physicalAperture);
    EXPECT_EQ(physicalAperture, 0.0f);
    portraitSession->SetPhysicalAperture(aperture);

    portraitSession->Release();
    input->Close();
}

/*
 * Feature: Framework
 * Function: Test PortraitSession without CommitConfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test PortraitSession without CommitConfig
 */
HWTEST_F(CameraPortraitSessionUnitTest, portrait_session_unittest_007, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    SceneMode mode = PORTRAIT;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras[0]->GetMetadata();
    int32_t modeSet = static_cast<int32_t>(NORMAL);
    metadata->addEntry(OHOS_ABILITY_CAMERA_MODES, &modeSet, 1);
    std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(cameras[0]);
    ASSERT_TRUE(modes.size() != 0);
    sptr<CameraOutputCapability> ability = cameraManager_->GetSupportedOutputCapability(cameras[0], mode);
    ASSERT_NE(ability, nullptr);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);
    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);
    sptr<CaptureSession> captureSession = cameraManager_->CreateCaptureSession(mode);
    ASSERT_NE(captureSession, nullptr);
    sptr<PortraitSession> portraitSession = nullptr;
    portraitSession = static_cast<PortraitSession *> (captureSession.GetRefPtr());
    ASSERT_NE(portraitSession, nullptr);

    EXPECT_EQ(portraitSession->BeginConfig(), 0);
    EXPECT_EQ(portraitSession->AddInput(input), 0);
    sptr<CameraDevice> info = captureSession->innerInputDevice_->GetCameraDeviceInfo();
    ASSERT_NE(info, nullptr);
    info->modePreviewProfiles_.emplace(static_cast<int32_t>(PORTRAIT), previewProfile);
    info->modePhotoProfiles_.emplace(static_cast<int32_t>(PORTRAIT), photoProfile);
    EXPECT_EQ(portraitSession->AddOutput(preview), 0);
    EXPECT_EQ(portraitSession->AddOutput(photo), 0);

    const float physicalAperture = 0.1;
    const float virtualAperture = 0.1;
    std::vector<float> supportedVirtualApertures = {};
    std::vector<float> virtualApertures = {};
    OHOS::Camera::DeleteCameraMetadataItem(info->GetMetadata()->get(), OHOS_ABILITY_CAMERA_VIRTUAL_APERTURE_RANGE);
    OHOS::Camera::DeleteCameraMetadataItem(info->GetMetadata()->get(), OHOS_ABILITY_CAMERA_PHYSICAL_APERTURE_RANGE);
    portraitSession->GetSupportedVirtualApertures(virtualApertures);
    EXPECT_EQ(virtualApertures, supportedVirtualApertures);
    float virtualApertureResult = 0.0f;
    portraitSession->GetVirtualAperture(virtualApertureResult);
    EXPECT_EQ(virtualApertureResult, 0.0);
    portraitSession->SetVirtualAperture(virtualAperture);
    std::vector<std::vector<float>> supportedPhysicalApertures;
    std::vector<std::vector<float>> physicalApertures;
    portraitSession->GetSupportedPhysicalApertures(physicalApertures);
    EXPECT_EQ(physicalApertures, supportedPhysicalApertures);
    float physicalApertureResult = 0.0f;
    portraitSession->GetPhysicalAperture(physicalApertureResult);
    EXPECT_EQ(physicalApertureResult, 0.0f);
    portraitSession->SetPhysicalAperture(physicalAperture);
    portraitSession->Release();
    input->Close();
}

/*
 * Feature: Framework
 * Function: Test PortraitSession when innerInputDevice_ is nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test PortraitSession when innerInputDevice_ is nullptr
 */
HWTEST_F(CameraPortraitSessionUnitTest, portrait_session_unittest_008, TestSize.Level0)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    SceneMode mode = PORTRAIT;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = cameras[0]->GetMetadata();
    int32_t modeSet = static_cast<int32_t>(NORMAL);
    metadata->addEntry(OHOS_ABILITY_CAMERA_MODES, &modeSet, 1);
    std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(cameras[0]);
    ASSERT_TRUE(modes.size() != 0);

    sptr<CameraOutputCapability> ability = cameraManager_->GetSupportedOutputCapability(cameras[0], mode);
    ASSERT_NE(ability, nullptr);
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    ASSERT_NE(input, nullptr);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureOutput> preview = CreatePreviewOutput();
    ASSERT_NE(preview, nullptr);
    sptr<CaptureOutput> photo = CreatePhotoOutput();
    ASSERT_NE(photo, nullptr);
    sptr<CaptureSession> captureSession = cameraManager_->CreateCaptureSession(mode);
    ASSERT_NE(captureSession, nullptr);
    sptr<PortraitSession> portraitSession = nullptr;
    portraitSession = static_cast<PortraitSession *> (captureSession.GetRefPtr());
    ASSERT_NE(portraitSession, nullptr);

    EXPECT_EQ(portraitSession->BeginConfig(), 0);
    EXPECT_EQ(portraitSession->AddInput(input), 0);
    sptr<CameraDevice> info = captureSession->innerInputDevice_->GetCameraDeviceInfo();
    ASSERT_NE(info, nullptr);
    info->modePreviewProfiles_.emplace(static_cast<int32_t>(PORTRAIT), previewProfile);
    info->modePhotoProfiles_.emplace(static_cast<int32_t>(PORTRAIT), photoProfile);
    EXPECT_EQ(portraitSession->AddOutput(preview), 0);
    EXPECT_EQ(portraitSession->AddOutput(photo), 0);
    EXPECT_EQ(portraitSession->CommitConfig(), 0);

    portraitSession->innerInputDevice_ = nullptr;
    std::vector<PortraitEffect> supportedPortraitEffects = {};
    EXPECT_EQ(portraitSession->GetSupportedPortraitEffects(), supportedPortraitEffects);
    EXPECT_EQ(portraitSession->GetPortraitEffect(), PortraitEffect::OFF_EFFECT);
    std::vector<float> supportedVirtualApertures = {};
    std::vector<float> virtualApertures = {};
    portraitSession->GetSupportedVirtualApertures(virtualApertures);
    EXPECT_EQ(virtualApertures, supportedVirtualApertures);
    float virtualAperture = 0.0f;
    portraitSession->GetVirtualAperture(virtualAperture);
    EXPECT_EQ(virtualAperture, 0.0);
    std::vector<std::vector<float>> supportedPhysicalApertures;
    std::vector<std::vector<float>> physicalApertures;
    portraitSession->GetSupportedPhysicalApertures(physicalApertures);
    EXPECT_EQ(physicalApertures, supportedPhysicalApertures);
    float physicalAperture = 0.0f;
    portraitSession->GetPhysicalAperture(physicalAperture);
    EXPECT_EQ(physicalAperture, 0.0);

    portraitSession->Release();
    input->Close();
}

}
}