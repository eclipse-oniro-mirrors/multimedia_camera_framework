/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "camera_transfer_taihe.h"

#include "camera_lib_manager_taihe.h"
#include "camera_log.h"
#include "image_taihe.h"
#include "camera_input_taihe.h"
#include "photo_output_taihe.h"
#include "preview_output_taihe.h"
#include "video_output_taihe.h"
#include "metadata_output_taihe.h"
#include "video_session_taihe.h"
#include "secure_session_taihe.h"
#include "photo_session_taihe.h"
#include "photo_taihe.h"
#include "interop_js/arkts_esvalue.h"
#include "interop_js/arkts_interop_js_api.h"

using namespace Ani::Camera;
using GetCameraInputNapiFn = napi_value (*)(napi_env, sptr<OHOS::CameraStandard::CameraInput>);
using GetPhotoSessionNapiFn = napi_value (*)(napi_env, sptr<OHOS::CameraStandard::PhotoSession>);
using GetSecureCameraSessionNapiFn = napi_value (*)(napi_env, sptr<OHOS::CameraStandard::SecureCameraSession>);
using GetVideoSessionNapiFn = napi_value (*)(napi_env, sptr<OHOS::CameraStandard::VideoSession>);
using GetMetadataOutputNapiFn = napi_value (*)(napi_env, sptr<OHOS::CameraStandard::MetadataOutput>);
using GetPhotoNapiFn = napi_value (*)(napi_env, std::shared_ptr<OHOS::Media::NativeImage>, bool);
using GetPhotoOutputNapiFn = napi_value (*)(napi_env, sptr<OHOS::CameraStandard::PhotoOutput>);
using GetPreviewOutputNapiFn = napi_value (*)(napi_env, sptr<OHOS::CameraStandard::PreviewOutput>);
using GetVideoOutputNapiFn = napi_value (*)(napi_env, sptr<OHOS::CameraStandard::VideoOutput>);

using GetNativeCameraInputFn = bool (*)(void*, sptr<OHOS::CameraStandard::CameraInput>&);
using GetNativePhotoSessionFn = bool (*)(void*, sptr<OHOS::CameraStandard::CaptureSession>&);
using GetNativeSecureCameraSessionFn = bool (*)(void*, sptr<OHOS::CameraStandard::CaptureSession>&);
using GetNativeVideoSessionFn = bool (*)(void*, sptr<OHOS::CameraStandard::CaptureSession>&);
using GetNativeMetadataOutputFn = bool (*)(void*, sptr<OHOS::CameraStandard::MetadataOutput>&);
using GetNativeImageFn = bool (*)(void*, std::shared_ptr<OHOS::Media::NativeImage>&);
using GetNativePhotoOutputFn = bool (*)(void*, sptr<OHOS::CameraStandard::PhotoOutput>&);
using GetNativePreviewOutputFn = bool (*)(void*, sptr<OHOS::CameraStandard::PreviewOutput>&);
using GetNativeVideoOutputFn = bool (*)(void*, sptr<OHOS::CameraStandard::VideoOutput>&);
namespace ImageTaihe = ohos::multimedia::image::image;

namespace Ani {
namespace Camera {
std::mutex LibManager::mutex_;
std::shared_ptr<LibHandle> LibManager::instance_ = nullptr;

CameraInput CameraInputTransferStaticImpl(uintptr_t input)
{
    MEDIA_INFO_LOG("%{public}s Called", __func__);
    ani_object esValue = reinterpret_cast<ani_object>(input);
    CameraInput cameraInputTH = make_holder<CameraInputImpl, CameraInput>(nullptr);
    void *nativePtr = nullptr;
    CHECK_ERROR_RETURN_RET_LOG(!arkts_esvalue_unwrap(get_env(), esValue, &nativePtr) || nativePtr == nullptr,
        cameraInputTH, "%{public}s unwrap esValue failed", __func__);
    GetNativeCameraInputFn funcHandle = nullptr;
    CHECK_ERROR_RETURN_RET_LOG(!LibManager::GetSymbol("GetNativeCameraInput", funcHandle),
        cameraInputTH, "%{public}s Get GetNativeCameraInput symbol failed", __func__);
    sptr<OHOS::CameraStandard::CameraInput> nativeCameraInput = nullptr;
    bool ret = funcHandle(nativePtr, nativeCameraInput);
    CHECK_ERROR_RETURN_RET_LOG(!ret || nativeCameraInput == nullptr,
        cameraInputTH, "%{public}s GetNativeCameraInput failed", __func__);
    MEDIA_INFO_LOG("%{public}s End", __func__);
    return make_holder<CameraInputImpl, CameraInput>(nativeCameraInput);
}

uintptr_t CameraInputTransferDynamicImpl(weak::CameraInput input)
{
    MEDIA_INFO_LOG("%{public}s Called", __func__);
    CHECK_ERROR_RETURN_RET_LOG(input.is_error(), 0, "%{public}s input is nullptr", __func__);
    CameraInputImpl *implPtr = reinterpret_cast<CameraInputImpl*>(input->GetSpecificImplPtr());
    CHECK_ERROR_RETURN_RET_LOG(implPtr == nullptr, 0, "%{public}s implPtr is nullptr", __func__);
    napi_env jsEnv;
    CHECK_ERROR_RETURN_RET_LOG(!arkts_napi_scope_open(get_env(), &jsEnv), 0,
        "%{public}s arkts_napi_scope_open failed", __func__);
    GetCameraInputNapiFn funcHandle = nullptr;
    if (!LibManager::GetSymbol("GetCameraInputNapi", funcHandle)) {
        MEDIA_ERR_LOG("%{public}s Get GetCameraInputNapi symbol failed", __func__);
        arkts_napi_scope_close_n(jsEnv, 0, nullptr, nullptr);
        return 0;
    }
    napi_value instance = funcHandle(jsEnv, implPtr->GetCameraInput());
    if (instance == nullptr) {
        MEDIA_ERR_LOG("%{public}s Get GetCameraInputNapi symbol failed", __func__);
        arkts_napi_scope_close_n(jsEnv, 0, nullptr, nullptr);
        return 0;
    }

    uintptr_t result = 0;
    arkts_napi_scope_close_n(jsEnv, 1, &instance, reinterpret_cast<ani_ref*>(&result));
    MEDIA_INFO_LOG("%{public}s End", __func__);
    return result;
}

PhotoOutput PhotoOutputTransferStaticImpl(uintptr_t input)
{
    MEDIA_INFO_LOG("%{public}s Called", __func__);
    ani_object esValue = reinterpret_cast<ani_object>(input);
    PhotoOutput photoOutputTH = make_holder<PhotoOutputImpl, PhotoOutput>(nullptr);
    void *nativePtr = nullptr;
    CHECK_ERROR_RETURN_RET_LOG(!arkts_esvalue_unwrap(get_env(), esValue, &nativePtr) || nativePtr == nullptr,
        photoOutputTH, "%{public}s unwrap esValue failed", __func__);
    GetNativePhotoOutputFn funcHandle = nullptr;
    CHECK_ERROR_RETURN_RET_LOG(!LibManager::GetSymbol("GetNativePhotoOutput", funcHandle),
        photoOutputTH, "%{public}s Get GetNativePhotoOutput symbol failed", __func__);
    sptr<OHOS::CameraStandard::PhotoOutput> nativePhotoOutput = nullptr;
    bool ret = funcHandle(nativePtr, nativePhotoOutput);
    CHECK_ERROR_RETURN_RET_LOG(!ret || nativePhotoOutput == nullptr,
        photoOutputTH, "%{public}s GetNativePhotoOutput failed", __func__);
    MEDIA_INFO_LOG("%{public}s End", __func__);
    return make_holder<PhotoOutputImpl, PhotoOutput>(nativePhotoOutput);
}

uintptr_t PhotoOutputTransferDynamicImpl(weak::PhotoOutput input)
{
    MEDIA_INFO_LOG("%{public}s Called", __func__);
    CHECK_ERROR_RETURN_RET_LOG(input.is_error(), 0, "%{public}s input is nullptr", __func__);
    PhotoOutputImpl *implPtr =
        reinterpret_cast<PhotoOutputImpl*>(CameraOutput(PhotoOutput(input))->GetSpecificImplPtr());
    CHECK_ERROR_RETURN_RET_LOG(implPtr == nullptr, 0, "%{public}s implPtr is nullptr", __func__);
    napi_env jsEnv;
    CHECK_ERROR_RETURN_RET_LOG(!arkts_napi_scope_open(get_env(), &jsEnv), 0,
        "%{public}s arkts_napi_scope_open failed", __func__);
    GetPhotoOutputNapiFn funcHandle = nullptr;
    if (!LibManager::GetSymbol("GetPhotoOutputNapi", funcHandle)) {
        MEDIA_ERR_LOG("%{public}s Get GetPhotoOutputNapi symbol failed", __func__);
        arkts_napi_scope_close_n(jsEnv, 0, nullptr, nullptr);
        return 0;
    }
    napi_value instance = funcHandle(jsEnv, implPtr->GetPhotoOutput());
    if (instance == nullptr) {
        MEDIA_ERR_LOG("%{public}s Get GetPhotoOutputNapi symbol failed", __func__);
        arkts_napi_scope_close_n(jsEnv, 0, nullptr, nullptr);
        return 0;
    }

    uintptr_t result = 0;
    arkts_napi_scope_close_n(jsEnv, 1, &instance, reinterpret_cast<ani_ref*>(&result));
    MEDIA_INFO_LOG("%{public}s End", __func__);
    return result;
}

PreviewOutput PreviewOutputTransferStaticImpl(uintptr_t input)
{
    MEDIA_INFO_LOG("%{public}s Called", __func__);
    ani_object esValue = reinterpret_cast<ani_object>(input);
    PreviewOutput previewOutputTH = make_holder<PreviewOutputImpl, PreviewOutput>(nullptr);
    void *nativePtr = nullptr;
    CHECK_ERROR_RETURN_RET_LOG(!arkts_esvalue_unwrap(get_env(), esValue, &nativePtr) || nativePtr == nullptr,
        previewOutputTH, "%{public}s unwrap esValue failed", __func__);
    GetNativePreviewOutputFn funcHandle = nullptr;
    CHECK_ERROR_RETURN_RET_LOG(!LibManager::GetSymbol("GetNativePreviewOutput", funcHandle),
        previewOutputTH, "%{public}s Get GetNativePreviewOutput symbol failed", __func__);
    sptr<OHOS::CameraStandard::PreviewOutput> nativePreviewOutput = nullptr;
    bool ret = funcHandle(nativePtr, nativePreviewOutput);
    CHECK_ERROR_RETURN_RET_LOG(!ret || nativePreviewOutput == nullptr,
        previewOutputTH, "%{public}s GetNativePreviewOutput failed", __func__);
    MEDIA_INFO_LOG("%{public}s End", __func__);
    return make_holder<PreviewOutputImpl, PreviewOutput>(nativePreviewOutput);
}

uintptr_t PreviewOutputTransferDynamicImpl(weak::PreviewOutput input)
{
    MEDIA_INFO_LOG("%{public}s Called", __func__);
    CHECK_ERROR_RETURN_RET_LOG(input.is_error(), 0, "%{public}s input is nullptr", __func__);
    PreviewOutputImpl *implPtr =
        reinterpret_cast<PreviewOutputImpl*>(CameraOutput(PreviewOutput(input))->GetSpecificImplPtr());
    CHECK_ERROR_RETURN_RET_LOG(implPtr == nullptr, 0, "%{public}s implPtr is nullptr", __func__);
    napi_env jsEnv;
    CHECK_ERROR_RETURN_RET_LOG(!arkts_napi_scope_open(get_env(), &jsEnv), 0,
        "%{public}s arkts_napi_scope_open failed", __func__);
    GetPreviewOutputNapiFn funcHandle = nullptr;
    if (!LibManager::GetSymbol("GetPreviewOutputNapi", funcHandle)) {
        MEDIA_ERR_LOG("%{public}s Get GetPreviewOutputNapi symbol failed", __func__);
        arkts_napi_scope_close_n(jsEnv, 0, nullptr, nullptr);
        return 0;
    }
    napi_value instance = funcHandle(jsEnv, implPtr->GetPreviewOutput());
    if (instance == nullptr) {
        MEDIA_ERR_LOG("%{public}s Get GetPreviewOutputNapi symbol failed", __func__);
        arkts_napi_scope_close_n(jsEnv, 0, nullptr, nullptr);
        return 0;
    }

    uintptr_t result = 0;
    arkts_napi_scope_close_n(jsEnv, 1, &instance, reinterpret_cast<ani_ref*>(&result));
    MEDIA_INFO_LOG("%{public}s End", __func__);
    return result;
}

VideoOutput VideoOutputTransferStaticImpl(uintptr_t input)
{
    MEDIA_INFO_LOG("%{public}s Called", __func__);
    ani_object esValue = reinterpret_cast<ani_object>(input);
    VideoOutput videoOutputTH = make_holder<VideoOutputImpl, VideoOutput>(nullptr);
    void *nativePtr = nullptr;
    CHECK_ERROR_RETURN_RET_LOG(!arkts_esvalue_unwrap(get_env(), esValue, &nativePtr) || nativePtr == nullptr,
        videoOutputTH, "%{public}s unwrap esValue failed", __func__);
    GetNativeVideoOutputFn funcHandle = nullptr;
    CHECK_ERROR_RETURN_RET_LOG(!LibManager::GetSymbol("GetNativeVideoOutput", funcHandle),
        videoOutputTH, "%{public}s Get GetNativeVideoOutput symbol failed", __func__);
    sptr<OHOS::CameraStandard::VideoOutput> nativeVideoOutput = nullptr;
    bool ret = funcHandle(nativePtr, nativeVideoOutput);
    CHECK_ERROR_RETURN_RET_LOG(!ret || nativeVideoOutput == nullptr,
        videoOutputTH, "%{public}s GetNativeVideoOutput failed", __func__);
    MEDIA_INFO_LOG("%{public}s End", __func__);
    return make_holder<VideoOutputImpl, VideoOutput>(nativeVideoOutput);
}

uintptr_t VideoOutputTransferDynamicImpl(weak::VideoOutput input)
{
    MEDIA_INFO_LOG("%{public}s Called", __func__);
    CHECK_ERROR_RETURN_RET_LOG(input.is_error(), 0, "%{public}s input is nullptr", __func__);
    VideoOutputImpl *implPtr =
        reinterpret_cast<VideoOutputImpl*>(CameraOutput(VideoOutput(input))->GetSpecificImplPtr());
    CHECK_ERROR_RETURN_RET_LOG(implPtr == nullptr, 0, "%{public}s implPtr is nullptr", __func__);
    napi_env jsEnv;
    CHECK_ERROR_RETURN_RET_LOG(!arkts_napi_scope_open(get_env(), &jsEnv), 0,
        "%{public}s arkts_napi_scope_open failed", __func__);
    GetVideoOutputNapiFn funcHandle = nullptr;
    if (!LibManager::GetSymbol("GetVideoOutputNapi", funcHandle)) {
        MEDIA_ERR_LOG("%{public}s Get GetVideoOutputNapi symbol failed", __func__);
        arkts_napi_scope_close_n(jsEnv, 0, nullptr, nullptr);
        return 0;
    }
    napi_value instance = funcHandle(jsEnv, implPtr->GetVideoOutput());
    if (instance == nullptr) {
        MEDIA_ERR_LOG("%{public}s Get GetVideoOutputNapi symbol failed", __func__);
        arkts_napi_scope_close_n(jsEnv, 0, nullptr, nullptr);
        return 0;
    }

    uintptr_t result = 0;
    arkts_napi_scope_close_n(jsEnv, 1, &instance, reinterpret_cast<ani_ref*>(&result));
    MEDIA_INFO_LOG("%{public}s End", __func__);
    return result;
}

MetadataOutput MetadataOutputTransferStaticImpl(uintptr_t input)
{
    MEDIA_INFO_LOG("%{public}s Called", __func__);
    ani_object esValue = reinterpret_cast<ani_object>(input);
    MetadataOutput metadataOutputTH = make_holder<MetadataOutputImpl, MetadataOutput>(nullptr);
    void *nativePtr = nullptr;
    CHECK_ERROR_RETURN_RET_LOG(!arkts_esvalue_unwrap(get_env(), esValue, &nativePtr) || nativePtr == nullptr,
        metadataOutputTH, "%{public}s unwrap esValue failed", __func__);
    GetNativeMetadataOutputFn funcHandle = nullptr;
    CHECK_ERROR_RETURN_RET_LOG(!LibManager::GetSymbol("GetNativeMetadataOutput", funcHandle),
        metadataOutputTH, "%{public}s Get GetNativeMetadataOutput symbol failed", __func__);
    sptr<OHOS::CameraStandard::MetadataOutput> nativeMetadataOutput = nullptr;
    bool ret = funcHandle(nativePtr, nativeMetadataOutput);
    CHECK_ERROR_RETURN_RET_LOG(!ret || nativeMetadataOutput == nullptr,
        metadataOutputTH, "%{public}s GetNativeMetadataOutput failed", __func__);
    MEDIA_INFO_LOG("%{public}s End", __func__);
    return make_holder<MetadataOutputImpl, MetadataOutput>(nativeMetadataOutput);
}

uintptr_t MetadataOutputTransferDynamicImpl(weak::MetadataOutput input)
{
    MEDIA_INFO_LOG("%{public}s Called", __func__);
    CHECK_ERROR_RETURN_RET_LOG(input.is_error(), 0, "%{public}s input is nullptr", __func__);
    MetadataOutputImpl *implPtr =
        reinterpret_cast<MetadataOutputImpl*>(CameraOutput(MetadataOutput(input))->GetSpecificImplPtr());
    CHECK_ERROR_RETURN_RET_LOG(implPtr == nullptr, 0, "%{public}s implPtr is nullptr", __func__);
    napi_env jsEnv;
    CHECK_ERROR_RETURN_RET_LOG(!arkts_napi_scope_open(get_env(), &jsEnv), 0,
        "%{public}s arkts_napi_scope_open failed", __func__);
    GetMetadataOutputNapiFn funcHandle = nullptr;
    if (!LibManager::GetSymbol("GetMetadataOutputNapi", funcHandle)) {
        MEDIA_ERR_LOG("%{public}s Get GetMetadataOutputNapi symbol failed", __func__);
        arkts_napi_scope_close_n(jsEnv, 0, nullptr, nullptr);
        return 0;
    }
    napi_value instance = funcHandle(jsEnv, implPtr->GetMetadataOutput());
    if (instance == nullptr) {
        MEDIA_ERR_LOG("%{public}s Get GetMetadataOutputNapi symbol failed", __func__);
        arkts_napi_scope_close_n(jsEnv, 0, nullptr, nullptr);
        return 0;
    }

    uintptr_t result = 0;
    arkts_napi_scope_close_n(jsEnv, 1, &instance, reinterpret_cast<ani_ref*>(&result));
    MEDIA_INFO_LOG("%{public}s End", __func__);
    return result;
}

VideoSession VideoSessionTransferStaticImpl(uintptr_t input)
{
    MEDIA_INFO_LOG("%{public}s Called", __func__);
    ani_object esValue = reinterpret_cast<ani_object>(input);
    sptr<OHOS::CameraStandard::CaptureSession> sessionNullptr = nullptr;
    VideoSession videoSessionTH = make_holder<VideoSessionImpl, VideoSession>(sessionNullptr);
    void *nativePtr = nullptr;
    CHECK_ERROR_RETURN_RET_LOG(!arkts_esvalue_unwrap(get_env(), esValue, &nativePtr) || nativePtr == nullptr,
        videoSessionTH, "%{public}s unwrap esValue failed", __func__);
    GetNativeVideoSessionFn funcHandle = nullptr;
    CHECK_ERROR_RETURN_RET_LOG(!LibManager::GetSymbol("GetNativeVideoSession", funcHandle),
        videoSessionTH, "%{public}s Get GetNativeVideoSession symbol failed", __func__);
    sptr<OHOS::CameraStandard::CaptureSession> session = nullptr;
    bool ret = funcHandle(nativePtr, session);
    CHECK_ERROR_RETURN_RET_LOG(!ret || session == nullptr,
        videoSessionTH, "%{public}s GetNativeVideoSession failed", __func__);
    MEDIA_INFO_LOG("%{public}s End", __func__);
    return make_holder<VideoSessionImpl, VideoSession>(session);
}

uintptr_t VideoSessionTransferDynamicImpl(weak::VideoSession input)
{
    MEDIA_INFO_LOG("%{public}s Called", __func__);
    CHECK_ERROR_RETURN_RET_LOG(input.is_error(), 0, "%{public}s input is nullptr", __func__);
    VideoSessionImpl *implPtr =
        reinterpret_cast<VideoSessionImpl*>(input->GetSpecificImplPtr());
    CHECK_ERROR_RETURN_RET_LOG(implPtr == nullptr, 0, "%{public}s implPtr is nullptr", __func__);
    napi_env jsEnv;
    CHECK_ERROR_RETURN_RET_LOG(!arkts_napi_scope_open(get_env(), &jsEnv), 0,
        "%{public}s arkts_napi_scope_open failed", __func__);
    GetVideoSessionNapiFn funcHandle = nullptr;
    if (!LibManager::GetSymbol("GetVideoSessionNapi", funcHandle)) {
        MEDIA_ERR_LOG("%{public}s Get GetVideoSessionNapi symbol failed", __func__);
        arkts_napi_scope_close_n(jsEnv, 0, nullptr, nullptr);
        return 0;
    }
    napi_value instance = funcHandle(jsEnv, implPtr->GetVideoSession());
    if (instance == nullptr) {
        MEDIA_ERR_LOG("%{public}s Get GetVideoSessionNapi symbol failed", __func__);
        arkts_napi_scope_close_n(jsEnv, 0, nullptr, nullptr);
        return 0;
    }

    uintptr_t result = 0;
    arkts_napi_scope_close_n(jsEnv, 1, &instance, reinterpret_cast<ani_ref*>(&result));
    MEDIA_INFO_LOG("%{public}s End", __func__);
    return result;
}

SecureSession SecureSessionTransferStaticImpl(uintptr_t input)
{
    MEDIA_INFO_LOG("%{public}s Called", __func__);
    ani_object esValue = reinterpret_cast<ani_object>(input);
    sptr<OHOS::CameraStandard::CaptureSession> sessionNullptr = nullptr;
    SecureSession secureSessionTH = make_holder<SecureSessionImpl, SecureSession>(sessionNullptr);
    void *nativePtr = nullptr;
    CHECK_ERROR_RETURN_RET_LOG(!arkts_esvalue_unwrap(get_env(), esValue, &nativePtr) || nativePtr == nullptr,
        secureSessionTH, "%{public}s unwrap esValue failed", __func__);
    GetNativeSecureCameraSessionFn funcHandle = nullptr;
    CHECK_ERROR_RETURN_RET_LOG(!LibManager::GetSymbol("GetNativeSecureCameraSession", funcHandle),
        secureSessionTH, "%{public}s Get GetNativeSecureCameraSession symbol failed", __func__);
    sptr<OHOS::CameraStandard::CaptureSession> session = nullptr;
    bool ret = funcHandle(nativePtr, session);
    CHECK_ERROR_RETURN_RET_LOG(!ret || session == nullptr,
        secureSessionTH, "%{public}s GetNativeSecureCameraSession failed", __func__);
    MEDIA_INFO_LOG("%{public}s End", __func__);
    return make_holder<SecureSessionImpl, SecureSession>(session);
}

uintptr_t SecureSessionTransferDynamicImpl(weak::SecureSession input)
{
    MEDIA_INFO_LOG("%{public}s Called", __func__);
    CHECK_ERROR_RETURN_RET_LOG(input.is_error(), 0, "%{public}s input is nullptr", __func__);
    SecureSessionImpl *implPtr =
        reinterpret_cast<SecureSessionImpl*>(input->GetSpecificImplPtr());
    CHECK_ERROR_RETURN_RET_LOG(implPtr == nullptr, 0, "%{public}s implPtr is nullptr", __func__);
    napi_env jsEnv;
    CHECK_ERROR_RETURN_RET_LOG(!arkts_napi_scope_open(get_env(), &jsEnv), 0,
        "%{public}s arkts_napi_scope_open failed", __func__);
    GetSecureCameraSessionNapiFn funcHandle = nullptr;
    if (!LibManager::GetSymbol("GetSecureCameraSessionNapi", funcHandle)) {
        MEDIA_ERR_LOG("%{public}s Get GetSecureCameraSessionNapi symbol failed", __func__);
        arkts_napi_scope_close_n(jsEnv, 0, nullptr, nullptr);
        return 0;
    }
    napi_value instance = funcHandle(jsEnv, implPtr->GetSecureCameraSession());
    if (instance == nullptr) {
        MEDIA_ERR_LOG("%{public}s Get GetSecureCameraSessionNapi symbol failed", __func__);
        arkts_napi_scope_close_n(jsEnv, 0, nullptr, nullptr);
        return 0;
    }

    uintptr_t result = 0;
    arkts_napi_scope_close_n(jsEnv, 1, &instance, reinterpret_cast<ani_ref*>(&result));
    MEDIA_INFO_LOG("%{public}s End", __func__);
    return result;
}

PhotoSession PhotoSessionTransferStaticImpl(uintptr_t input)
{
    MEDIA_INFO_LOG("%{public}s Called", __func__);
    ani_object esValue = reinterpret_cast<ani_object>(input);
    sptr<OHOS::CameraStandard::CaptureSession> sessionNullptr = nullptr;
    PhotoSession photoSessionTH = make_holder<PhotoSessionImpl, PhotoSession>(sessionNullptr);
    void *nativePtr = nullptr;
    CHECK_ERROR_RETURN_RET_LOG(!arkts_esvalue_unwrap(get_env(), esValue, &nativePtr) || nativePtr == nullptr,
        photoSessionTH, "%{public}s unwrap esValue failed", __func__);
    GetNativePhotoSessionFn funcHandle = nullptr;
    CHECK_ERROR_RETURN_RET_LOG(!LibManager::GetSymbol("GetNativePhotoSession", funcHandle),
        photoSessionTH, "%{public}s Get GetNativePhotoSession symbol failed", __func__);
    sptr<OHOS::CameraStandard::CaptureSession> session = nullptr;
    bool ret = funcHandle(nativePtr, session);
    CHECK_ERROR_RETURN_RET_LOG(!ret || session == nullptr,
        photoSessionTH, "%{public}s GetNativePhotoSession failed", __func__);
    MEDIA_INFO_LOG("%{public}s End", __func__);
    return make_holder<PhotoSessionImpl, PhotoSession>(session);
}

uintptr_t PhotoSessionTransferDynamicImpl(weak::PhotoSession input)
{
    MEDIA_INFO_LOG("%{public}s Called", __func__);
    CHECK_ERROR_RETURN_RET_LOG(input.is_error(), 0, "%{public}s input is nullptr", __func__);
    PhotoSessionImpl *implPtr =
        reinterpret_cast<PhotoSessionImpl*>(input->GetSpecificImplPtr());
    CHECK_ERROR_RETURN_RET_LOG(implPtr == nullptr, 0, "%{public}s implPtr is nullptr", __func__);
    napi_env jsEnv;
    CHECK_ERROR_RETURN_RET_LOG(!arkts_napi_scope_open(get_env(), &jsEnv), 0,
        "%{public}s arkts_napi_scope_open failed", __func__);
    GetPhotoSessionNapiFn funcHandle = nullptr;
    if (!LibManager::GetSymbol("GetPhotoSessionNapi", funcHandle)) {
        MEDIA_ERR_LOG("%{public}s Get GetPhotoSessionNapi symbol failed", __func__);
        arkts_napi_scope_close_n(jsEnv, 0, nullptr, nullptr);
        return 0;
    }
    napi_value instance = funcHandle(jsEnv, implPtr->GetPhotoSession());
    if (instance == nullptr) {
        MEDIA_ERR_LOG("%{public}s Get GetPhotoSessionNapi symbol failed", __func__);
        arkts_napi_scope_close_n(jsEnv, 0, nullptr, nullptr);
        return 0;
    }

    uintptr_t result = 0;
    arkts_napi_scope_close_n(jsEnv, 1, &instance, reinterpret_cast<ani_ref*>(&result));
    MEDIA_INFO_LOG("%{public}s End", __func__);
    return result;
}

Photo PhotoTransferStaticImpl(uintptr_t input)
{
    MEDIA_INFO_LOG("%{public}s Called", __func__);
    ani_object esValue = reinterpret_cast<ani_object>(input);
    ImageTaihe::Image mainImageEmpty = make_holder<ANI::Image::ImageImpl, ImageTaihe::Image>();
    Photo photoTHEmpty = make_holder<PhotoImpl, Photo>(mainImageEmpty);
    void *nativePtr = nullptr;
    CHECK_ERROR_RETURN_RET_LOG(!arkts_esvalue_unwrap(get_env(), esValue, &nativePtr) || nativePtr == nullptr,
        photoTHEmpty, "%{public}s unwrap esValue failed", __func__);
    GetNativeImageFn funcHandle = nullptr;
    CHECK_ERROR_RETURN_RET_LOG(!LibManager::GetSymbol("GetNativeImage", funcHandle),
        photoTHEmpty, "%{public}s Get GetNativeImage symbol failed", __func__);
    std::shared_ptr<OHOS::Media::NativeImage> nativeImage = nullptr;
    bool ret = funcHandle(nativePtr, nativeImage);
    CHECK_ERROR_RETURN_RET_LOG(!ret || nativeImage == nullptr,
        photoTHEmpty, "%{public}s GetNativeImage failed", __func__);
    ImageTaihe::Image image = ANI::Image::ImageImpl::Create(nativeImage);
    CHECK_ERROR_RETURN_RET_LOG(image.is_error(), photoTHEmpty,
        "%{public}s ImageTaihe Create failed", __func__);
    MEDIA_INFO_LOG("%{public}s End", __func__);
    return make_holder<PhotoImpl, Photo>(image);
}

std::shared_ptr<OHOS::Media::NativeImage> GetNativeImageFromTH(PhotoImpl *photoImplPtr, bool &isRaw)
{
    MEDIA_INFO_LOG("%{public}s Called", __func__);
    ImageTaihe::Image mainImageTH = photoImplPtr->GetMain();
    std::shared_ptr<OHOS::Media::NativeImage> nativeMainImage = nullptr;
    if (!mainImageTH.is_error()) {
        ANI::Image::ImageImpl *mainImageImplPtr = reinterpret_cast<ANI::Image::ImageImpl*>(mainImageTH->GetImplPtr());
        if (mainImageImplPtr != nullptr) {
            nativeMainImage = mainImageImplPtr->GetIncrementalImage();
        }
    }
    optional<ImageTaihe::Image> rawImageTH = photoImplPtr->GetRaw();
    std::shared_ptr<OHOS::Media::NativeImage> nativeRawImage = nullptr;
    if (rawImageTH.has_value() && !rawImageTH.value().is_error()) {
        ANI::Image::ImageImpl *rawImageImplPtr =
            reinterpret_cast<ANI::Image::ImageImpl*>(rawImageTH.value()->GetImplPtr());
        if (rawImageImplPtr != nullptr) {
            nativeRawImage = rawImageImplPtr->GetIncrementalImage();
        }
    }

    if (nativeMainImage != nullptr) {
        isRaw = false;
        MEDIA_INFO_LOG("%{public}s End. isRaw is %{public}d", __func__, isRaw);
        return nativeMainImage;
    } else if (nativeRawImage != nullptr) {
        isRaw = true;
        MEDIA_INFO_LOG("%{public}s End. isRaw is %{public}d", __func__, isRaw);
        return nativeRawImage;
    }
    MEDIA_ERR_LOG("%{public}s mainImage and rawImage in photoTaihe are both nullptr", __func__);
    return nullptr;
}

uintptr_t PhotoTransferDynamicImpl(weak::Photo input)
{
    MEDIA_INFO_LOG("%{public}s Called", __func__);
    CHECK_ERROR_RETURN_RET_LOG(input.is_error(), 0, "%{public}s input is nullptr", __func__);
    PhotoImpl *photoImplPtr = reinterpret_cast<PhotoImpl*>(input->GetSpecificImplPtr());
    CHECK_ERROR_RETURN_RET_LOG(photoImplPtr == nullptr, 0, "%{public}s photoImplPtr is nullptr", __func__);
    bool isRaw = false;
    std::shared_ptr<OHOS::Media::NativeImage> nativeImage = GetNativeImageFromTH(photoImplPtr, isRaw);
    CHECK_ERROR_RETURN_RET_LOG(nativeImage == nullptr, 0, "%{public}s GetNativeImageFromTH failed", __func__);
    napi_env jsEnv;
    CHECK_ERROR_RETURN_RET_LOG(!arkts_napi_scope_open(get_env(), &jsEnv), 0,
        "%{public}s arkts_napi_scope_open failed", __func__);
    GetPhotoNapiFn funcHandle = nullptr;
    if (!LibManager::GetSymbol("GetPhotoNapi", funcHandle)) {
        MEDIA_ERR_LOG("%{public}s Get GetPhotoNapi symbol failed", __func__);
        arkts_napi_scope_close_n(jsEnv, 0, nullptr, nullptr);
        return 0;
    }
    napi_value instance = nullptr;
    instance = funcHandle(jsEnv, nativeImage, isRaw);
    if (instance == nullptr) {
        MEDIA_ERR_LOG("%{public}s GetPhotoNapi failed", __func__);
        arkts_napi_scope_close_n(jsEnv, 0, nullptr, nullptr);
        return 0;
    }

    uintptr_t result = 0;
    arkts_napi_scope_close_n(jsEnv, 1, &instance, reinterpret_cast<ani_ref*>(&result));
    MEDIA_INFO_LOG("%{public}s End", __func__);
    return result;
}

} // namespace Camera
} // namespace Ani

TH_EXPORT_CPP_API_CameraInputTransferStaticImpl(CameraInputTransferStaticImpl);
TH_EXPORT_CPP_API_CameraInputTransferDynamicImpl(CameraInputTransferDynamicImpl);
TH_EXPORT_CPP_API_PhotoOutputTransferStaticImpl(PhotoOutputTransferStaticImpl);
TH_EXPORT_CPP_API_PhotoOutputTransferDynamicImpl(PhotoOutputTransferDynamicImpl);
TH_EXPORT_CPP_API_PreviewOutputTransferStaticImpl(PreviewOutputTransferStaticImpl);
TH_EXPORT_CPP_API_PreviewOutputTransferDynamicImpl(PreviewOutputTransferDynamicImpl);
TH_EXPORT_CPP_API_VideoOutputTransferStaticImpl(VideoOutputTransferStaticImpl);
TH_EXPORT_CPP_API_VideoOutputTransferDynamicImpl(VideoOutputTransferDynamicImpl);
TH_EXPORT_CPP_API_MetadataOutputTransferStaticImpl(MetadataOutputTransferStaticImpl);
TH_EXPORT_CPP_API_MetadataOutputTransferDynamicImpl(MetadataOutputTransferDynamicImpl);
TH_EXPORT_CPP_API_VideoSessionTransferStaticImpl(VideoSessionTransferStaticImpl);
TH_EXPORT_CPP_API_VideoSessionTransferDynamicImpl(VideoSessionTransferDynamicImpl);
TH_EXPORT_CPP_API_SecureSessionTransferStaticImpl(SecureSessionTransferStaticImpl);
TH_EXPORT_CPP_API_SecureSessionTransferDynamicImpl(SecureSessionTransferDynamicImpl);
TH_EXPORT_CPP_API_PhotoSessionTransferStaticImpl(PhotoSessionTransferStaticImpl);
TH_EXPORT_CPP_API_PhotoSessionTransferDynamicImpl(PhotoSessionTransferDynamicImpl);
TH_EXPORT_CPP_API_PhotoTransferStaticImpl(PhotoTransferStaticImpl);
TH_EXPORT_CPP_API_PhotoTransferDynamicImpl(PhotoTransferDynamicImpl);