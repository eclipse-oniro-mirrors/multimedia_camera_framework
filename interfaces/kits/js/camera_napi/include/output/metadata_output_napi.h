/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef METADATA_OUTPUT_NAPI_H_
#define METADATA_OUTPUT_NAPI_H_

#include "input/camera_manager.h"
#include "input/camera_info.h"

#include "hilog/log.h"
#include "camera_napi_utils.h"

#include "listener_napi_base.h"

namespace OHOS {
namespace CameraStandard {
static const char CAMERA_METADATA_OUTPUT_NAPI_CLASS_NAME[] = "MetadataOutput";

class MetadataOutputCallback : public MetadataObjectCallback,
    public std::enable_shared_from_this<MetadataOutputCallback> {
public:
    explicit MetadataOutputCallback(napi_env env);
    virtual ~MetadataOutputCallback() = default;

    void OnMetadataObjectsAvailable(std::vector<sptr<MetadataObject>> metaObjects) const override;
    void SaveCallbackReference(const std::string &eventType, napi_value callback, bool isOnce);
    void RemoveCallbackRef(napi_env env, napi_value callback);
    void RemoveAllCallbacks();

private:
    void OnMetadataObjectsAvailableCallback(const std::vector<sptr<MetadataObject>> metadataObjList) const;
    std::mutex metadataOutputCbMutex_;
    napi_env env_;
    mutable std::vector<std::shared_ptr<AutoRef>> metadataOutputCbList_;
};

class MetadataStateCallbackNapi : public MetadataStateCallback,
    public std::enable_shared_from_this<MetadataStateCallbackNapi> {
public:
    explicit MetadataStateCallbackNapi(napi_env env);
    virtual ~MetadataStateCallbackNapi() = default;
    void SaveCallbackReference(const std::string &eventType, napi_value callback, bool isOnce);
    void RemoveCallbackRef(napi_env env, napi_value args);
    void RemoveAllCallbacks();
    void OnError(const int32_t errorType) const override;

private:
    void OnErrorCallback(const int32_t errorType) const;
    void OnErrorCallbackAsync(const int32_t errorType) const;
    std::mutex metadataStateCbMutex_;
    napi_env env_;
    mutable std::vector<std::shared_ptr<AutoRef>> metadataStateCbList_;
};

struct MetadataOutputCallbackInfo {
    const std::vector<sptr<MetadataObject>> info_;
    weak_ptr<const MetadataOutputCallback> listener_;
    MetadataOutputCallbackInfo(std::vector<sptr<MetadataObject>> metadataObjList,
        shared_ptr<const MetadataOutputCallback> listener)
        : info_(metadataObjList), listener_(listener) {}
};

struct MetadataStateCallbackInfo {
    int32_t errorType_;
    weak_ptr<const MetadataStateCallbackNapi> listener_;
    MetadataStateCallbackInfo(int32_t errorType, shared_ptr<const MetadataStateCallbackNapi> listener)
        : errorType_(errorType), listener_(listener) {}
};

class MetadataOutputNapi : public ListenerNapiBase{
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateMetadataOutput(napi_env env);
    MetadataOutputNapi();
    ~MetadataOutputNapi();
    sptr<MetadataOutput> GetMetadataOutput();
    static bool IsMetadataOutput(napi_env env, napi_value obj);

private:
    static void MetadataOutputNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value MetadataOutputNapiConstructor(napi_env env, napi_callback_info info);

    static napi_value GetSupportedMetadataObjectTypes(napi_env env, napi_callback_info info);
    static napi_value SetCapturingMetadataObjectTypes(napi_env env, napi_callback_info info);
    static napi_value Start(napi_env env, napi_callback_info info);
    static napi_value Stop(napi_env env, napi_callback_info info);
    static napi_value RegisterCallback(napi_env env, napi_value jsThis,
        const std::string& eventType, napi_value callback, bool isOnce) override;
    static napi_value UnregisterCallback(napi_env env, napi_value jsThis,
        const std::string& eventType, napi_value callback) override;

    static thread_local napi_ref sConstructor_;
    static thread_local sptr<MetadataOutput> sMetadataOutput_;

    napi_env env_;
    napi_ref wrapper_;
    sptr<MetadataOutput> metadataOutput_;
};

struct MetadataOutputAsyncContext : public AsyncContext {
    MetadataOutputNapi* objectInfo;
    bool bRetBool;
    bool isSupported = false;
    std::string errorMsg;
    std::vector<MetadataObjectType> SupportedMetadataObjectTypes;
    std::vector<MetadataObjectType> setSupportedMetadataObjectTypes;
    ~MetadataOutputAsyncContext()
    {
        objectInfo = nullptr;
    }
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* METADATA_OUTPUT_NAPI_H_ */
