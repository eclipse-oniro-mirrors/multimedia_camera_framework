/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "camera_fwk_metadata_utils_fuzzer.h"
#include "hstream_capture.h"
#include "message_parcel.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "accesstoken_kit.h"
#include "camera_metadata_info.h"
#include "metadata_utils.h"

namespace {

const int32_t LIMITSIZE = 16;

}

namespace OHOS {
namespace CameraStandard {

bool CameraFwkMetadataUtilsFuzzer::hasPermission = false;

void CameraFwkMetadataUtilsFuzzer::CheckPermission()
{
    if (!hasPermission) {
        uint64_t tokenId;
        const char *perms[0];
        perms[0] = "ohos.permission.CAMERA";
        NativeTokenInfoParams infoInstance = { .dcapsNum = 0, .permsNum = 1, .aclsNum = 0, .dcaps = NULL,
            .perms = perms, .acls = NULL, .processName = "camera_capture", .aplStr = "system_basic",
        };
        tokenId = GetAccessTokenId(&infoInstance);
        SetSelfTokenID(tokenId);
        OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
        hasPermission = true;
    }
}

void CameraFwkMetadataUtilsFuzzer::Test(uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    CheckPermission();

    MessageParcel data;
    data.WriteRawData(rawData, size);

    std::shared_ptr<OHOS::Camera::CameraMetadata> srcMetadata;
    std::shared_ptr<OHOS::Camera::CameraMetadata> dstMetadata;

    data.RewindRead(0);
    srcMetadata->addEntry(data.ReadUint32(), rawData, size);
    CameraFwkMetadataUtils::MergeMetadata(srcMetadata, dstMetadata);

    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = CameraFwkMetadataUtils::CopyMetadata(srcMetadata);

    CameraFwkMetadataUtils::LogFormatCameraMetadata(metadata);

    CameraFwkMetadataUtils::RecreateMetadata(metadata);
    
    data.RewindRead(0);
    camera_metadata_item_t item = {
        data.ReadUint32(),
        data.ReadUint32(),
        data.ReadUint32(),
        data.ReadUint32(),
    };
    camera_metadata_item_t srcItem = item;

    CameraFwkMetadataUtils::UpdateMetadataTag(srcItem, dstMetadata);
    CameraFwkMetadataUtils::DumpMetadataItemInfo(item);
    CameraFwkMetadataUtils::DumpMetadataInfo(srcMetadata);
}

} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::CameraStandard::CameraFwkMetadataUtilsFuzzer::Test(data, size);
    return 0;
}