/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "camera_napi_metadata_utils.h"

#include "camera_napi_const.h"

namespace OHOS {
namespace CameraStandard {
namespace CameraNapiMetadataUtils {

int32_t MapMetadataObjSupportedTypesEnum(MetadataObjectType nativeMetadataObjType)
{
    switch (nativeMetadataObjType) {
        case MetadataObjectType::FACE:
            return JSMetadataObjectType::FACE_DETECTION;
        case MetadataObjectType::HUMAN_BODY:
            return JSMetadataObjectType::HUMAN_BODY;
        case MetadataObjectType::CAT_FACE:
            return JSMetadataObjectType::CAT_FACE;
        case MetadataObjectType::CAT_BODY:
            return JSMetadataObjectType::CAT_BODY;
        case MetadataObjectType::DOG_FACE:
            return JSMetadataObjectType::DOG_FACE;
        case MetadataObjectType::DOG_BODY:
            return JSMetadataObjectType::DOG_BODY;
        case MetadataObjectType::SALIENT_DETECTION:
            return JSMetadataObjectType::SALIENT_DETECTION;
        case MetadataObjectType::BAR_CODE_DETECTION:
            return JSMetadataObjectType::BAR_CODE_DETECTION;
        default:
            // do nothing
            break;
    }
    return JSMetadataObjectType::INVALID;
}

MetadataObjectType MapMetadataObjSupportedTypesEnumFromJS(int32_t jsMetadataObjType)
{
    switch (jsMetadataObjType) {
        case JSMetadataObjectType::FACE_DETECTION:
            return MetadataObjectType::FACE;
        case JSMetadataObjectType::HUMAN_BODY:
            return MetadataObjectType::HUMAN_BODY;
        case JSMetadataObjectType::CAT_FACE:
            return MetadataObjectType::CAT_FACE;
        case JSMetadataObjectType::CAT_BODY:
            return MetadataObjectType::CAT_BODY;
        case JSMetadataObjectType::DOG_FACE:
            return MetadataObjectType::DOG_FACE;
        case JSMetadataObjectType::DOG_BODY:
            return MetadataObjectType::DOG_BODY;
        case JSMetadataObjectType::SALIENT_DETECTION:
            return MetadataObjectType::SALIENT_DETECTION;
        case JSMetadataObjectType::BAR_CODE_DETECTION:
            return MetadataObjectType::BAR_CODE_DETECTION;
        default:
            // do nothing
            break;
    }
    return MetadataObjectType::INVALID;
}
} // namespace CameraNapiMetadataUtils
} // namespace CameraStandard
} // namespace OHOS