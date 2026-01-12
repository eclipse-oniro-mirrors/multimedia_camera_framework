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
#include "photo_asset_adapter.h"
#include "picture_adapter.h"
#include "dfx_report.h"
#include "camera_log.h"
#include "surface.h"
#include "media_photo_asset_proxy.h"
#include "ipc_skeleton.h"

using namespace testing::ext;
namespace OHOS {
namespace CameraStandard {

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
 *-AddPhotoProxy should not change the state.
 *-GetPhotoAssetUri should return an empty string.
 *-GetVideoFd should return -1.
 *-NotifyVideoSaveFinished should set photoAssetProxy_ to nullptr.
 */
HWTEST_F(PhotoAssetAdapterUnit, photo_asset_adapter_unittest_001, TestSize.Level0)
{
    int32_t cameraShotType = 0;
    int32_t uid = 1;
    int32_t photoCount = 1;
    std::string bundleName = "com.example.camera";
    std::unique_ptr<PhotoAssetAdapter> photoAssetAdapterTest = std::make_unique<PhotoAssetAdapter>(cameraShotType, uid,
        IPCSkeleton::GetCallingTokenID(), photoCount, bundleName);
    sptr<Media::PhotoProxy> photoProxy;
    photoAssetAdapterTest->photoAssetProxy_ = nullptr;
    photoAssetAdapterTest->AddPhotoProxy(photoProxy);

    string ret01 = photoAssetAdapterTest->GetPhotoAssetUri();
    string ret001 = "";
    EXPECT_EQ(ret01, ret001);

    auto videoTp = VideoType::ORIGIN_VIDEO;
    int32_t ret02 = photoAssetAdapterTest->GetVideoFd(videoTp);
    EXPECT_EQ(ret02, -1);

    photoAssetAdapterTest->NotifyVideoSaveFinished(videoTp);
    ASSERT_EQ(photoAssetAdapterTest->photoAssetProxy_, nullptr);
}

/*
 * Feature: Framework
 * Function: Test PhotoAssetAdapter
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test PhotoAssetAdapter methods when the photoAssetProxy_ is set to a valid proxy.
 *-AddPhotoProxy should not change the state.
 *-GetPhotoAssetUri should return an empty string.
 *-GetVideoFd should return -1.
 *-NotifyVideoSaveFinished should not change the state of photoAssetProxy_.
 */
HWTEST_F(PhotoAssetAdapterUnit, photo_asset_adapter_unittest_002, TestSize.Level0)
{
    int32_t cameraShotType = 0;
    int32_t uid = 1;
    int32_t photoCount = 1;
    std::string bundleName = "com.example.camera";
    std::unique_ptr<PhotoAssetAdapter> photoAssetAdapterTest =
        std::make_unique<PhotoAssetAdapter>(cameraShotType, uid, IPCSkeleton::GetCallingTokenID(),
        photoCount, bundleName);
    EXPECT_NE(photoAssetAdapterTest, nullptr);

    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper;
    std::shared_ptr<Media::PhotoAssetProxy> photoAssetProxy =
        std::make_shared <Media::PhotoAssetProxy>(
            dataShareHelper, Media::CameraShotType::IMAGE, 1, 1024, 1, IPCSkeleton::GetCallingTokenID());
    sptr<Media::PhotoProxy> photoProxy;
    photoAssetAdapterTest->photoAssetProxy_ = photoAssetProxy;
    EXPECT_NE(photoAssetAdapterTest->photoAssetProxy_, nullptr);

    photoAssetAdapterTest->AddPhotoProxy(photoProxy);
    EXPECT_NE(photoAssetAdapterTest->photoAssetProxy_, nullptr);

    string ret01 = photoAssetAdapterTest->GetPhotoAssetUri();
    string ret001 = "";
    EXPECT_EQ(ret01, ret001);

    auto videoTp = VideoType::ORIGIN_VIDEO;
    int32_t ret02 = photoAssetAdapterTest->GetVideoFd(videoTp);
    EXPECT_EQ(ret02, -1);

    photoAssetAdapterTest->NotifyVideoSaveFinished(videoTp);
    EXPECT_NE(photoAssetAdapterTest->photoAssetProxy_, nullptr);
}

/*
 * Feature: Framework
 * Function: Test For DFX.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test For DFX.
 */
HWTEST_F(PhotoAssetAdapterUnit, photo_asset_adapter_unittest_003, TestSize.Level0)
{
    std::unique_ptr<PictureAdapter> pictureAdapterTest =
        std::make_unique<PictureAdapter>();
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    pictureAdapterTest->Create(surfaceBuffer);
    EXPECT_EQ(surfaceBuffer, nullptr);
}
 
/*
 * Feature: Framework
 * Function: Test For DFX.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test For DFX.
 */
HWTEST_F(PhotoAssetAdapterUnit, photo_asset_adapter_unittest_004, TestSize.Level0)
{
    std::unique_ptr<PictureAdapter> pictureAdapterTest =
        std::make_unique<PictureAdapter>();
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    std::string pictureAdapterUse = "DFX::TEST";
    CameraReportUtils::GetInstance().ReportCameraCreateNullptr("DFX::TEST",
        pictureAdapterUse);
    CameraReportUtils::GetInstance().ReportCameraFalse("DFX::TEST",
        pictureAdapterUse);
    int32_t ret = 0;
    CameraReportUtils::GetInstance().ReportCameraError("DFX::TEST",
        pictureAdapterUse, ret);
    CameraReportUtils::GetInstance().ReportCameraGetNullStr("DFX::TEST",
        pictureAdapterUse);
    CameraReportUtils::GetInstance().ReportCameraFail("DFX::TEST",
        pictureAdapterUse);
    EXPECT_EQ(surfaceBuffer, nullptr);
}

#ifdef CAMERA_CAPTURE_YUV
/*
 * Feature: MediaLibraryManagerAdapter
 * Function: RegisterPhotoStateCallback / UnregisterPhotoStateCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Callback registration methods should not crash even if g_mediaLibraryManager is null.
 */
HWTEST_F(PhotoAssetAdapterUnit, media_library_manager_adapter_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("media_library_manager_adapter_test_001 Start");

    MediaLibraryManagerAdapter adapter;

    auto callback = [](int32_t state) {
        MEDIA_INFO_LOG("Photo state callback invoked: %{public}d", state);
    };

    adapter.RegisterPhotoStateCallback(callback);
    adapter.UnregisterPhotoStateCallback();

    MEDIA_INFO_LOG("media_library_manager_adapter_test_001 End");
}
#endif
}
}