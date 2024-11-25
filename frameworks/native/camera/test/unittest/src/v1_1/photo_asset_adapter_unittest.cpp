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

#include "photo_asset_adapter_unittest.h"
#include "gtest/gtest.h"
#include "camera_log.h"
#include "surface.h"

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;
void PhotoAssetAdapterUnit::SetUpTestCase(void) {}

void PhotoAssetAdapterUnit::TearDownTestCase(void) {}

void PhotoAssetAdapterUnit::SetUp() {}

void PhotoAssetAdapterUnit::TearDown() {}


/*
 * Feature: Framework
 * Function: Test PhotoAssetAdapter 
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: CaseDescription: Test PhotoAssetAdapter methods when the photoAssetProxy_ is set to nullptr.
 *    - AddPhotoProxy should not change the state.
 *    - GetPhotoAssetUri should return an empty string.
 *    - GetVideoFd should return -1.
 *    - NotifyVideoSaveFinished should set photoAssetProxy_ to nullptr.
 */
HWTEST_F(PhotoAssetAdapterUnit, photo_asset_adapter_unittest_001, TestSize.Level0)
{

    int32_t cameraShotType = 0;
    int32_t uid = 1;
    std::unique_ptr<PhotoAssetAdapter> photoAssetAdapterTest = std::make_unique<PhotoAssetAdapter>(cameraShotType, uid);
    sptr<Media::PhotoProxy> photoProxy;
    photoAssetAdapterTest->photoAssetProxy_ = nullptr;
    photoAssetAdapterTest->AddPhotoProxy(photoProxy);

    string ret01 = photoAssetAdapterTest->GetPhotoAssetUri();
    string ret001 = "";
    EXPECT_EQ(ret01, ret001);

    int32_t ret02 = photoAssetAdapterTest->GetVideoFd();
    EXPECT_EQ(ret02, -1);

    photoAssetAdapterTest->NotifyVideoSaveFinished();
    ASSERT_EQ(photoAssetAdapterTest->photoAssetProxy_, nullptr);
}

/*
 * Feature: Framework
 * Function: Test PhotoAssetAdapter 
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test PhotoAssetAdapter methods when the photoAssetProxy_ is set to a valid proxy.
 *    - AddPhotoProxy should not change the state.
 *    - GetPhotoAssetUri should return an empty string.
 *    - GetVideoFd should return -1.
 *    - NotifyVideoSaveFinished should not change the state of photoAssetProxy_.
 */
HWTEST_F(PhotoAssetAdapterUnit, photo_asset_adapter_unittest_002, TestSize.Level0)
{

    int32_t cameraShotType = 0;
    int32_t uid = 1;
    std::unique_ptr<PhotoAssetAdapter> photoAssetAdapterTest = 
       std::make_unique<PhotoAssetAdapter>(cameraShotType, uid);
    EXPECT_NE(photoAssetAdapterTest, nullptr);

    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper;
    std::shared_ptr<PhotoAssetProxy> photoAssetProxy =
        std::make_shared <PhotoAssetProxy>(dataShareHelper, CameraShotType::IMAGE, 1, 1024);
    sptr<Media::PhotoProxy> photoProxy;
    photoAssetAdapterTest->photoAssetProxy_ = photoAssetProxy;
    EXPECT_NE(photoAssetAdapterTest->photoAssetProxy_, nullptr);

    photoAssetAdapterTest->AddPhotoProxy(photoProxy);
    EXPECT_NE(photoAssetAdapterTest->photoAssetProxy_, nullptr);

    string ret01 = photoAssetAdapterTest->GetPhotoAssetUri();
    string ret001 = "";
    EXPECT_EQ(ret01, ret001);

    int32_t ret02 = photoAssetAdapterTest->GetVideoFd();
    EXPECT_EQ(ret02, -1);

    photoAssetAdapterTest->NotifyVideoSaveFinished();
    EXPECT_NE(photoAssetAdapterTest->photoAssetProxy_, nullptr);
}
}
}