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

#include "buffer_extra_data_impl.h"
#include "gmock/gmock.h"
#include "photo_listener_impl.h"
#include "photo_listener_impl_unittest.h"
#include "surface_buffer_impl.h"
#include "video_key_info.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

void PhotoListenerImplUnitTest::SetUpTestCase(void)
{
    SetNativeToken();
}

void PhotoListenerImplUnitTest::TearDownTestCase(void) {}

void PhotoListenerImplUnitTest::SetUp(void)
{
    InitCamera();
    photoOutput_ = CreatePhotoOutput();
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    photoListener_ = new PhotoListener(photoOutput_, surface);
    rawPhotoListener_ = new RawPhotoListener(photoOutput_, surface);
}

void PhotoListenerImplUnitTest::TearDown(void)
{
    OH_PhotoOutput_Release(photoOutput_);
    ReleaseCamera();
}
bool PhotoListenerImplUnitTest::isCalled = false;

/**
 * @tc.name  : Test GetCameraBufferExtraData API
 * @tc.number: GetCameraBufferExtraData_001
 * @tc.desc  : Test GetCameraBufferExtraData API, when extraData is empty
 */
HWTEST_F(PhotoListenerImplUnitTest, GetCameraBufferExtraData_001, TestSize.Level0)
{
    auto buffer = SurfaceBuffer::Create();
    sptr<BufferExtraData> extraData = new BufferExtraDataImpl();

    buffer->SetExtraData(extraData);

    CameraBufferExtraData cameraBfExtData = photoListener_->GetCameraBufferExtraData(buffer);
    EXPECT_EQ(cameraBfExtData.imageId, 0);
    EXPECT_EQ(cameraBfExtData.extraDataSize, 0);
    EXPECT_EQ(cameraBfExtData.deferredImageFormat, 0);
    EXPECT_EQ(cameraBfExtData.size, 0);
}

/**
 * @tc.name  : Test GetCameraBufferExtraData API
 * @tc.number: GetCameraBufferExtraData_002
 * @tc.desc  : Test GetCameraBufferExtraData API, when res == 0 && extraData.extraDataSize <= 0
 */
HWTEST_F(PhotoListenerImplUnitTest, GetCameraBufferExtraData_002, TestSize.Level0)
{
    auto buffer = SurfaceBuffer::Create();
    sptr<BufferExtraData> extraData = new BufferExtraDataImpl();
    extraData->ExtraSet(OHOS::Camera::dataSize, -1);

    buffer->SetExtraData(extraData);

    CameraBufferExtraData cameraBfExtData = photoListener_->GetCameraBufferExtraData(buffer);
    EXPECT_EQ(cameraBfExtData.imageId, 0);
    EXPECT_EQ(cameraBfExtData.extraDataSize, -1);
    EXPECT_EQ(cameraBfExtData.deferredImageFormat, 0);
    EXPECT_EQ(cameraBfExtData.size, 0);
}

/**
 * @tc.name  : Test GetCameraBufferExtraData API
 * @tc.number: GetCameraBufferExtraData_003
 * @tc.desc  : Test GetCameraBufferExtraData API, when res == 0 && extraData.extraDataSize > 0 &&
 * extraData.extraDataSize > surfaceBuffer->GetSize()
 */
HWTEST_F(PhotoListenerImplUnitTest, GetCameraBufferExtraData_003, TestSize.Level0)
{
    auto buffer = SurfaceBuffer::Create();
    sptr<BufferExtraData> extraData = new BufferExtraDataImpl();
    extraData->ExtraSet(OHOS::Camera::dataSize, 100);

    buffer->SetExtraData(extraData);
    BufferHandle* bfHandle = new BufferHandle();
    const int32_t BF_SIZE = 1;
    bfHandle->size = BF_SIZE;
    buffer->SetBufferHandle(bfHandle);

    CameraBufferExtraData cameraBfExtData = photoListener_->GetCameraBufferExtraData(buffer);
    EXPECT_EQ(cameraBfExtData.imageId, 0);
    EXPECT_EQ(cameraBfExtData.extraDataSize, 100);
    EXPECT_EQ(cameraBfExtData.deferredImageFormat, 0);
    EXPECT_EQ(cameraBfExtData.size, BF_SIZE);
}

/**
 * @tc.name  : Test GetCameraBufferExtraData API
 * @tc.number: GetCameraBufferExtraData_004
 * @tc.desc  : Test GetCameraBufferExtraData API, when res == 0 && extraData.extraDataSize > 0 &&
 * extraData.extraDataSize <= surfaceBuffer->GetSize()
 */
HWTEST_F(PhotoListenerImplUnitTest, GetCameraBufferExtraData_004, TestSize.Level0)
{
    auto buffer = SurfaceBuffer::Create();
    sptr<BufferExtraData> extraData = new BufferExtraDataImpl();
    const int32_t DATA_SIZE = 1;
    extraData->ExtraSet(OHOS::Camera::dataSize, DATA_SIZE);

    buffer->SetExtraData(extraData);
    BufferHandle* bfHandle = new BufferHandle();
    bfHandle->size = 100;
    buffer->SetBufferHandle(bfHandle);

    CameraBufferExtraData cameraBfExtData = photoListener_->GetCameraBufferExtraData(buffer);
    EXPECT_EQ(cameraBfExtData.imageId, 0);
    EXPECT_EQ(cameraBfExtData.extraDataSize, 1);
    EXPECT_EQ(cameraBfExtData.deferredImageFormat, 0);
    EXPECT_EQ(cameraBfExtData.size, DATA_SIZE);
}

/**
 * @tc.name  : Test SetPhotoAvailableCallback API
 * @tc.number: SetPhotoAvailableCallback_001
 * @tc.desc  : Test SetPhotoAvailableCallback API, when [in]callback is nullptr
 */
HWTEST_F(PhotoListenerImplUnitTest, SetPhotoAvailableCallback_001, TestSize.Level0)
{
    photoListener_->SetPhotoAvailableCallback(nullptr);
    EXPECT_EQ(photoListener_->photoCallback_, nullptr);
}

/**
 * @tc.name  : Test UnregisterPhotoAvailableCallback API
 * @tc.number: UnregisterPhotoAvailableCallback_001
 * @tc.desc  : Test UnregisterPhotoAvailableCallback API, when photoCallback_ is not nullptr && [in]callback is nullptr
 */
HWTEST_F(PhotoListenerImplUnitTest, UnregisterPhotoAvailableCallback_001, TestSize.Level0)
{
    OH_PhotoOutput_PhotoAvailable callback = [](Camera_PhotoOutput* photoOutput, OH_PhotoNative* photo) -> void {};
    ASSERT_NE(callback, nullptr);
    photoListener_->photoCallback_ = callback;
    photoListener_->UnregisterPhotoAvailableCallback(nullptr);
    EXPECT_EQ(photoListener_->photoCallback_, callback);
}

/**
 * @tc.name  : Test UnregisterPhotoAvailableCallback API
 * @tc.number: UnregisterPhotoAvailableCallback_002
 * @tc.desc  : Test UnregisterPhotoAvailableCallback API, when photoCallback_ is nullptr && [in]callback is not nullptr
 */
HWTEST_F(PhotoListenerImplUnitTest, UnregisterPhotoAvailableCallback_002, TestSize.Level0)
{
    OH_PhotoOutput_PhotoAvailable callback = [](Camera_PhotoOutput* photoOutput, OH_PhotoNative* photo) -> void {};
    ASSERT_NE(callback, nullptr);
    photoListener_->photoCallback_ = nullptr;
    photoListener_->UnregisterPhotoAvailableCallback(callback);
    EXPECT_EQ(photoListener_->photoCallback_, nullptr);
}

/**
 * @tc.name  : Test SetPhotoAssetAvailableCallback API
 * @tc.number: SetPhotoAssetAvailableCallback_001
 * @tc.desc  : Test SetPhotoAssetAvailableCallback API, when [in]callback is nullptr
 */
HWTEST_F(PhotoListenerImplUnitTest, SetPhotoAssetAvailableCallback_001, TestSize.Level0)
{
    photoListener_->SetPhotoAssetAvailableCallback(nullptr);
    EXPECT_EQ(photoListener_->photoCallback_, nullptr);
}

/**
 * @tc.name  : Test UnregisterPhotoAssetAvailableCallback API
 * @tc.number: UnregisterPhotoAssetAvailableCallback_001
 * @tc.desc  : Test UnregisterPhotoAssetAvailableCallback API, when photoCallback_ is not nullptr && [in]callback is
 * nullptr
 */
HWTEST_F(PhotoListenerImplUnitTest, UnregisterPhotoAssetAvailableCallback_001, TestSize.Level0)
{
    OH_PhotoOutput_PhotoAssetAvailable callback = [](Camera_PhotoOutput* photoOutput, OH_MediaAsset* photo) -> void {};
    ASSERT_NE(callback, nullptr);
    photoListener_->photoAssetCallback_ = callback;
    photoListener_->UnregisterPhotoAssetAvailableCallback(nullptr);
    EXPECT_EQ(photoListener_->photoAssetCallback_, callback);
}

/**
 * @tc.name  : Test UnregisterPhotoAssetAvailableCallback API
 * @tc.number: UnregisterPhotoAssetAvailableCallback_002
 * @tc.desc  : Test UnregisterPhotoAssetAvailableCallback API, when photoCallback_ is nullptr && [in]callback is not
 * nullptr
 */
HWTEST_F(PhotoListenerImplUnitTest, UnregisterPhotoAssetAvailableCallback_002, TestSize.Level0)
{
    OH_PhotoOutput_PhotoAssetAvailable callback = [](Camera_PhotoOutput* photoOutput, OH_MediaAsset* photo) -> void {};
    ASSERT_NE(callback, nullptr);
    photoListener_->photoAssetCallback_ = nullptr;
    photoListener_->UnregisterPhotoAssetAvailableCallback(callback);
    EXPECT_EQ(photoListener_->photoAssetCallback_, nullptr);
}

/**
 * @tc.name  : Test ExecutePhoto API
 * @tc.number: ExecutePhoto_001
 * @tc.desc  : Test ExecutePhoto API, when photoCallback_ != nullptr && photoOutput_ != nullptr
 */
HWTEST_F(PhotoListenerImplUnitTest, ExecutePhoto_001, TestSize.Level0)
{
    auto surBf = SurfaceBuffer::Create();
    photoListener_->photoCallback_ = [](Camera_PhotoOutput* photoOutput, OH_PhotoNative* photo) -> void {
        PhotoListenerImplUnitTest::isCalled = true;
    };
    photoListener_->ExecutePhoto(surBf, 60);
    EXPECT_TRUE(PhotoListenerImplUnitTest::isCalled);
    PhotoListenerImplUnitTest::isCalled = false;
}

/**
 * @tc.name  : Test ExecutePhoto API
 * @tc.number: ExecutePhoto_002
 * @tc.desc  : Test ExecutePhoto API, when photoCallback_ == nullptr && photoOutput_ != nullptr
 */
HWTEST_F(PhotoListenerImplUnitTest, ExecutePhoto_002, TestSize.Level0)
{
    auto surBf = SurfaceBuffer::Create();
    photoListener_->photoCallback_ = nullptr;
    photoListener_->ExecutePhoto(surBf, 60);
    EXPECT_FALSE(PhotoListenerImplUnitTest::isCalled);
}

/**
 * @tc.name  : Test RawPhotoListener API
 * @tc.number: RawPhotoListener_001
 * @tc.desc  : Test RawPhotoListener API, when bufferProcessor_ == nullptr && rawPhotoSurface != nullptr
 */
HWTEST_F(PhotoListenerImplUnitTest, RawPhotoListener_001, TestSize.Level0)
{
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    sptr<RawPhotoListener> rawPhotoListener = new RawPhotoListener(photoOutput_, surface);
    EXPECT_NE(rawPhotoListener, nullptr);
}

/**
 * @tc.name  : Test ExecuteRawPhoto API
 * @tc.number: ExecuteRawPhoto_001
 * @tc.desc  : Test ExecuteRawPhoto API, when callback_ != nullptr && photoOutput_ != nullptr
 */
HWTEST_F(PhotoListenerImplUnitTest, ExecuteRawPhoto_001, TestSize.Level0)
{
    OH_PhotoOutput_PhotoAvailable callback = [](Camera_PhotoOutput* photoOutput, OH_PhotoNative* photo) -> void {
        PhotoListenerImplUnitTest::isCalled = true;
    };
    rawPhotoListener_->SetCallback(callback);
    sptr<SurfaceBuffer> surBf = SurfaceBuffer::Create();
    rawPhotoListener_->ExecuteRawPhoto(surBf, 60);
    EXPECT_TRUE(PhotoListenerImplUnitTest::isCalled);
    PhotoListenerImplUnitTest::isCalled = false;
}

/**
 * @tc.name  : Test ExecuteRawPhoto API
 * @tc.number: ExecuteRawPhoto_002
 * @tc.desc  : Test ExecuteRawPhoto API, when callback_ == nullptr && photoOutput_ != nullptr
 */
HWTEST_F(PhotoListenerImplUnitTest, ExecuteRawPhoto_002, TestSize.Level1)
{
    rawPhotoListener_->callback_ = nullptr;
    sptr<SurfaceBuffer> surBf = SurfaceBuffer::Create();
    rawPhotoListener_->ExecuteRawPhoto(surBf, 60);
    EXPECT_FALSE(PhotoListenerImplUnitTest::isCalled);
}

/**
 * @tc.name  : Test ExecuteRawPhoto API
 * @tc.number: ExecuteRawPhoto_003
 * @tc.desc  : Test ExecuteRawPhoto API, when callback_ != nullptr && photoOutput_ == nullptr
 */
HWTEST_F(PhotoListenerImplUnitTest, ExecuteRawPhoto_003, TestSize.Level1)
{
    OH_PhotoOutput_PhotoAvailable callback = [](Camera_PhotoOutput* photoOutput, OH_PhotoNative* photo) -> void {
        PhotoListenerImplUnitTest::isCalled = true;
    };
    rawPhotoListener_->callback_ = callback;
    rawPhotoListener_->photoOutput_ = nullptr;
    sptr<SurfaceBuffer> surBf = SurfaceBuffer::Create();
    rawPhotoListener_->ExecuteRawPhoto(surBf, 60);
    EXPECT_FALSE(PhotoListenerImplUnitTest::isCalled);
}

/**
 * @tc.name  : Test ExecuteRawPhoto API
 * @tc.number: ExecuteRawPhoto_004
 * @tc.desc  : Test ExecuteRawPhoto API, when callback_ == nullptr && photoOutput_ == nullptr
 */
HWTEST_F(PhotoListenerImplUnitTest, ExecuteRawPhoto_004, TestSize.Level1)
{
    rawPhotoListener_->callback_ = nullptr;
    rawPhotoListener_->photoOutput_ = nullptr;
    sptr<SurfaceBuffer> surBf = SurfaceBuffer::Create();
    rawPhotoListener_->ExecuteRawPhoto(surBf, 60);
    EXPECT_FALSE(PhotoListenerImplUnitTest::isCalled);
}

/**
 * @tc.name  : Test SetCallback API
 * @tc.number: SetCallback_001
 * @tc.desc  : Test SetCallback API, when callback != nullptr
 */
HWTEST_F(PhotoListenerImplUnitTest, SetCallback_001, TestSize.Level0)
{
    OH_PhotoOutput_PhotoAvailable callback = [](Camera_PhotoOutput* photoOutput, OH_PhotoNative* photo) -> void {};
    rawPhotoListener_->SetCallback(callback);
    EXPECT_NE(rawPhotoListener_->callback_, nullptr);
}

/**
 * @tc.name  : Test SetCallback API
 * @tc.number: SetCallback_002
 * @tc.desc  : Test SetCallback API, when callback is nullptr
 */
HWTEST_F(PhotoListenerImplUnitTest, SetCallback_002, TestSize.Level1)
{
    rawPhotoListener_->SetCallback(nullptr);
    EXPECT_EQ(rawPhotoListener_->callback_, nullptr);
}

/**
 * @tc.name  : Test UnregisterCallback API
 * @tc.number: UnregisterCallback_001
 * @tc.desc  : Test UnregisterCallback API, when callback != nullptr && callback_ != nullptr
 */
HWTEST_F(PhotoListenerImplUnitTest, UnregisterCallback_001, TestSize.Level1)
{
    OH_PhotoOutput_PhotoAvailable callback = [](Camera_PhotoOutput* photoOutput, OH_PhotoNative* photo) -> void {};
    rawPhotoListener_->callback_ = callback;
    rawPhotoListener_->UnregisterCallback(callback);
    EXPECT_EQ(rawPhotoListener_->callback_, nullptr);
}

} // namespace CameraStandard
} // namespace OHOS