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

#include "kits/native/include/camera/photo_native.h"
#include "impl/photo_native_impl.h"
#include "camera_log.h"
#include "hilog/log.h"

#ifdef __cplusplus
extern "C" {
#endif

Camera_ErrorCode OH_PhotoNative_GetMainImage(OH_PhotoNative* photo, OH_ImageNative* mainImage)
{
    CHECK_AND_RETURN_RET_LOG(photo != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, photo is null!");
    CHECK_AND_RETURN_RET_LOG(mainImage != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, main is null!");
    return photo->GetMainImage(mainImage);
}

Camera_ErrorCode OH_PhotoNative_Release(OH_PhotoNative* photo)
{
    CHECK_AND_RETURN_RET_LOG(photo != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, photo is null!");
    delete photo;
    photo = nullptr;
    return CAMERA_OK;
}

#ifdef __cplusplus
}
#endif