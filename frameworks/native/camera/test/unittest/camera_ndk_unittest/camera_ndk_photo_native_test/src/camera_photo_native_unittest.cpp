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
#include "auxiliary_picture.h"
#include "pixel_map.h"
#include "surface_buffer.h"
using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

namespace {
sptr<SurfaceBuffer> CreateAllocatedSurfaceBufferForAuxTest()
{
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    if (buffer == nullptr) {
        return nullptr;
    }
    BufferRequestConfig config = {
        .width = 64,
        .height = 64,
        .strideAlignment = 0x8,
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE,
        .timeout = 0,
    };
    if (buffer->Alloc(config) != GSERROR_OK) {
        return nullptr;
    }
    return buffer;
}
}

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

#ifdef CAMERA_CAPTURE_YUV
/*
* Feature: Framework
* Function: Test get uncompressed image in photo native
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: Test OH_PhotoNative_GetUncompressedImage with valid and invalid arguments
*/
HWTEST_F(PhotoNativeUnitTest, camera_photo_native_unittest_004, TestSize.Level0)
{
    OH_PhotoNative* photoNative = new OH_PhotoNative();
    OH_PictureNative* picture = nullptr;
    Camera_ErrorCode ret = OH_PhotoNative_GetUncompressedImage(photoNative, &picture);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PhotoNative_GetUncompressedImage(nullptr, &picture);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_PhotoNative_GetUncompressedImage(photoNative, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_PhotoNative_Release(photoNative), CAMERA_OK);
}
#endif

HWTEST_F(PhotoNativeUnitTest, GetAuxiliaryImage_001, TestSize.Level0)
{
    OH_PhotoNative* photoNative = new OH_PhotoNative();
    ASSERT_NE(photoNative, nullptr);
    OH_ImageNative* image = nullptr;
    EXPECT_EQ(OH_PhotoNative_GetAuxiliaryImage(nullptr, OH_CAMERA_AUXILIARY_PHOTO_TYPE_OXYGEN, &image),
        CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_PhotoNative_GetAuxiliaryImage(photoNative, OH_CAMERA_AUXILIARY_PHOTO_TYPE_OXYGEN, nullptr),
        CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_PhotoNative_GetAuxiliaryImage(photoNative, OH_CAMERA_AUXILIARY_PHOTO_TYPE_OXYGEN, &image),
        CAMERA_ERROR_PARAM_OUT_OF_RANGE);
    EXPECT_EQ(OH_PhotoNative_GetAuxiliaryImage(photoNative, OH_CAMERA_AUXILIARY_PHOTO_TYPE_PIGMENTATION, &image),
        CAMERA_ERROR_PARAM_OUT_OF_RANGE);
    EXPECT_EQ(OH_PhotoNative_GetAuxiliaryImage(photoNative, static_cast<OH_Camera_AuxiliaryPhotoType>(-1), &image),
        CAMERA_ERROR_PARAM_OUT_OF_RANGE);
    EXPECT_EQ(OH_PhotoNative_Release(photoNative), CAMERA_OK);
}

HWTEST_F(PhotoNativeUnitTest, GetAuxiliaryImage_002, TestSize.Level0)
{
    OH_PhotoNative* photoNative = new OH_PhotoNative();
    ASSERT_NE(photoNative, nullptr);
    std::shared_ptr<OHOS::Media::NativeImage> oxygenImage =
        std::make_shared<OHOS::Media::NativeImage>(nullptr, nullptr);
    ASSERT_NE(oxygenImage, nullptr);
    std::shared_ptr<OHOS::Media::NativeImage> pigmentationImage =
        std::make_shared<OHOS::Media::NativeImage>(nullptr, nullptr);
    ASSERT_NE(pigmentationImage, nullptr);
    photoNative->SetOxygenImage(oxygenImage);
    photoNative->SetPigmentationImage(pigmentationImage);
    OH_ImageNative* image = nullptr;
    EXPECT_EQ(OH_PhotoNative_GetAuxiliaryImage(photoNative, OH_CAMERA_AUXILIARY_PHOTO_TYPE_OXYGEN, &image),
        CAMERA_OK);
    EXPECT_NE(image, nullptr);
    EXPECT_EQ(OH_PhotoNative_GetAuxiliaryImage(photoNative, OH_CAMERA_AUXILIARY_PHOTO_TYPE_PIGMENTATION, &image),
        CAMERA_OK);
    EXPECT_NE(image, nullptr);
    EXPECT_EQ(OH_PhotoNative_Release(photoNative), CAMERA_OK);
}

HWTEST_F(PhotoNativeUnitTest, GetUncompressedAuxiliaryImage_001, TestSize.Level0)
{
    OH_PhotoNative* photoNative = new OH_PhotoNative();
    ASSERT_NE(photoNative, nullptr);
    OH_PictureNative* picture = nullptr;
    EXPECT_EQ(OH_PhotoNative_GetUncompressedAuxiliaryImage(nullptr,
        OH_CAMERA_AUXILIARY_PHOTO_TYPE_OXYGEN, &picture), CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_PhotoNative_GetUncompressedAuxiliaryImage(photoNative,
        OH_CAMERA_AUXILIARY_PHOTO_TYPE_OXYGEN, nullptr), CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_PhotoNative_GetUncompressedAuxiliaryImage(photoNative,
        OH_CAMERA_AUXILIARY_PHOTO_TYPE_OXYGEN, &picture), CAMERA_ERROR_PARAM_OUT_OF_RANGE);

    Media::InitializationOptions options;
    options.size.width = 8;
    options.size.height = 8;
    options.pixelFormat = Media::PixelFormat::RGBA_8888;
    std::unique_ptr<Media::PixelMap> pixelMap = Media::PixelMap::Create(options);
    ASSERT_NE(pixelMap, nullptr);
    std::shared_ptr<Media::PixelMap> sharedPixelMap = std::move(pixelMap);
    std::shared_ptr<Media::Picture> mainPicture = Media::Picture::Create(sharedPixelMap);
    ASSERT_NE(mainPicture, nullptr);
    photoNative->SetPicture(mainPicture);
    EXPECT_EQ(OH_PhotoNative_GetUncompressedAuxiliaryImage(photoNative,
        static_cast<OH_Camera_AuxiliaryPhotoType>(-1), &picture), CAMERA_ERROR_PARAM_OUT_OF_RANGE);
    EXPECT_EQ(OH_PhotoNative_GetUncompressedAuxiliaryImage(photoNative,
        OH_CAMERA_AUXILIARY_PHOTO_TYPE_OXYGEN, &picture), CAMERA_ERROR_PARAM_OUT_OF_RANGE);
    EXPECT_EQ(OH_PhotoNative_GetUncompressedAuxiliaryImage(photoNative,
        OH_CAMERA_AUXILIARY_PHOTO_TYPE_PIGMENTATION, &picture), CAMERA_ERROR_PARAM_OUT_OF_RANGE);
    EXPECT_EQ(OH_PhotoNative_Release(photoNative), CAMERA_OK);
}

HWTEST_F(PhotoNativeUnitTest, GetUncompressedAuxiliaryImage_002, TestSize.Level0)
{
    sptr<SurfaceBuffer> auxBuffer = CreateAllocatedSurfaceBufferForAuxTest();
    ASSERT_NE(auxBuffer, nullptr);
    std::unique_ptr<Media::AuxiliaryPicture> auxPicture = Media::AuxiliaryPicture::Create(
        auxBuffer, Media::AuxiliaryPictureType::OXY_MAP);
    ASSERT_NE(auxPicture, nullptr);
    std::shared_ptr<Media::AuxiliaryPicture> auxPicturePtr = std::move(auxPicture);
    Media::InitializationOptions options;
    options.size.width = 8;
    options.size.height = 8;
    options.pixelFormat = Media::PixelFormat::RGBA_8888;
    std::unique_ptr<Media::PixelMap> pixelMap = Media::PixelMap::Create(options);
    ASSERT_NE(pixelMap, nullptr);
    std::shared_ptr<Media::PixelMap> sharedPixelMap = std::move(pixelMap);
    std::shared_ptr<Media::Picture> mainPicture = Media::Picture::Create(sharedPixelMap);
    ASSERT_NE(mainPicture, nullptr);
    mainPicture->SetAuxiliaryPicture(auxPicturePtr);
    OH_PhotoNative* photoNative = new OH_PhotoNative();
    ASSERT_NE(photoNative, nullptr);
    photoNative->SetPicture(mainPicture);
    OH_PictureNative* picture = nullptr;
    EXPECT_EQ(OH_PhotoNative_GetUncompressedAuxiliaryImage(photoNative,
        OH_CAMERA_AUXILIARY_PHOTO_TYPE_OXYGEN, &picture), CAMERA_OK);
    EXPECT_NE(picture, nullptr);
    EXPECT_EQ(OH_PhotoNative_GetUncompressedAuxiliaryImage(photoNative,
        OH_CAMERA_AUXILIARY_PHOTO_TYPE_PIGMENTATION, &picture), CAMERA_ERROR_PARAM_OUT_OF_RANGE);
    EXPECT_EQ(OH_PhotoNative_Release(photoNative), CAMERA_OK);
}

HWTEST_F(PhotoNativeUnitTest, ReleasePictureAndImage_001, TestSize.Level0)
{
    EXPECT_EQ(OH_PhotoNative_ReleasePicture(nullptr), CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_PhotoNative_ReleaseImage(nullptr), CAMERA_INVALID_ARGUMENT);
}
} // CameraStandard
} // OHOS