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

#include "camera_photo_native_unittest.h"
#include "photo_native_impl.h"
using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

void PhotoNativeUnitTest::SetUpTestCase(void) {}

void PhotoNativeUnitTest::TearDownTestCase(void) {}

void PhotoNativeUnitTest::SetUp(void) {}

void PhotoNativeUnitTest::TearDown(void) {}

/*
* Feature: Framework
* Function: Test get main image in photo native
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: Test get main image in photo native
*/
HWTEST_F(PhotoNativeUnitTest, camera_photo_native_unittest_001, TestSize.Level0)
{
    OH_PhotoNative* photoNative = new OH_PhotoNative();
    OH_ImageNative* mainImage = nullptr;
    Camera_ErrorCode ret = OH_PhotoNative_GetMainImage(photoNative, &mainImage);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PhotoNative_GetMainImage(nullptr, &mainImage);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_PhotoNative_GetMainImage(photoNative, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    std::shared_ptr<OHOS::Media::NativeImage> mainImage_ = std::make_shared<OHOS::Media::NativeImage>(nullptr, nullptr);
    photoNative->SetMainImage(mainImage_);
    ret = OH_PhotoNative_GetMainImage(photoNative, &mainImage);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(mainImage, nullptr);
    EXPECT_EQ(OH_PhotoNative_Release(photoNative), CAMERA_OK);
}

/*
* Feature: Framework
* Function: Test release in photo native
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: Test release in photo native
*/
HWTEST_F(PhotoNativeUnitTest, camera_photo_native_unittest_002, TestSize.Level0)
{
    OH_PhotoNative* photoNative = new OH_PhotoNative();
    OH_ImageNative* mainImage = nullptr;
    Camera_ErrorCode ret = OH_PhotoNative_GetMainImage(photoNative, &mainImage);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PhotoNative_GetMainImage(nullptr, &mainImage);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_PhotoNative_GetMainImage(photoNative, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_PhotoNative_Release(photoNative), CAMERA_OK);
    EXPECT_EQ(OH_PhotoNative_Release(nullptr), CAMERA_INVALID_ARGUMENT);
}

/*
* Feature: Framework
* Function: Test release in photo native
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: Test release in photo native
*/
HWTEST_F(PhotoNativeUnitTest, camera_photo_native_unittest_003, TestSize.Level0)
{
    OH_PhotoNative* photoNative = new OH_PhotoNative();
    ASSERT_NE(photoNative, nullptr);
    std::shared_ptr<OHOS::Media::NativeImage> rawImage = std::make_shared<OHOS::Media::NativeImage>(nullptr, nullptr);
    ASSERT_NE(rawImage, nullptr);
    photoNative->SetRawImage(rawImage);
    EXPECT_EQ(OH_PhotoNative_Release(photoNative), CAMERA_OK);
}
} // CameraStandard
} // OHOS