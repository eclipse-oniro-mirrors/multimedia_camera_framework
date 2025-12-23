/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef RESOURCE_MANAGER_NAPI_H
#define RESOURCE_MANAGER_NAPI_H

#include <atomic>
#include <memory>
#include <cstdint>
#include <utility>
#include <unordered_map>
#include "napi_ref_manager.h"
#include "napi/native_api.h"

#include "resource_types.h"
#include "camera_napi_const.h"

namespace OHOS {
namespace CameraStandard {

static const std::unordered_map<std::string, int32_t> mapErrorCode = {
    {"SUCCESS", 0},
};

static const std::unordered_map<std::string, int32_t> mapResourceDownloadStatus = {
    {"IDLE", 0},
    {"COVER_DOWNLOADING", 101},
    {"COVER_DOWNLOADED", 102},
    {"COVER_NEW_VERSION_EXIST", 103},
    {"FULL_DOWNLOADING", 201},
    {"FULL_PART_DOWNLOADED", 202},
    {"FULL_DOWNLOADED", 203},
    {"FULL_NEW_VERSION_EXIST", 204},
};

static const std::unordered_map<std::string, int32_t> mapFeatureId = {
    {"FEATURE_ID_WATERMARK", 1}
};

static const std::unordered_map<std::string, int32_t> mapTypeId = {
    {"COMMON", 0},
    {"INDIVIDUALITY", 1},
    {"TIME_LIMIT", 2}
};

static const std::unordered_map<std::string, int32_t> mapTemplateId = {
    {"XSTYLE_WATERMARK", 1},
    {"ARTIST_WATERMARK_1", 2},
    {"ARTIST_WATERMARK_2", 3},
    {"NATIONAL_STYLE_WATERMARK", 4},
};

static const std::unordered_map<std::string, int32_t> mapPackageType = {
    {"COVER", 1},
    {"FULL", 2},
};

static const std::unordered_map<std::string, int32_t> mapParamType = {
    {"SWITCH", 0},
    {"SELECTOR", 1},
    {"CUSTOM", 2}
};

static const std::unordered_map<std::string, int32_t> mapSelectorOptions = {
    {"SELECTOR_OPTION_FIRST", 0},
    {"SELECTOR_OPTION_SECOND", 1},
    {"SELECTOR_OPTION_THIRD", 2},
    {"SELECTOR_OPTION_FOUR", 3},
};

static const std::unordered_map<std::string, int32_t> mapSelectorType = {
    {"IMAGE", 0},
    {"TEXT", 1},
    {"PRESET_IMAGE", 2},
};

static const std::unordered_map<std::string, int32_t> mapShapeType = {
    {"CIRCLE", 0},
    {"SQUARE", 1},
};

class ResourceManagerNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value ResourceManagerNapiConstructor(napi_env env, napi_callback_info info);
    static void ResourceManagerNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    ResourceManagerNapi();
    ~ResourceManagerNapi();
    static napi_value QueryFeatureInfo(napi_env env, napi_callback_info info);
    static napi_value RequestFeatureInfo(napi_env env, napi_callback_info info);
    static napi_value Destroy(napi_env env, napi_callback_info info);
    static napi_value PauseTask(napi_env env, napi_callback_info info);
    static napi_value ResumeTask(napi_env env, napi_callback_info info);
private:
    napi_env env_;
    static thread_local uint32_t resourceManagerNapiTaskId;
    static thread_local napi_ref sConstructor_;
    static void ParseRequestBodyParams(napi_env env, napi_value info, RequestBodyParams* requestBody);
    static void ParseCallerInfo(napi_env env, napi_value info, ReqCallerInfo* callerInfo);
    static void ParseDeletePredicates(napi_env env, napi_value info, DeletePredicates* deletePredicates);
    bool CheckFeatureId(int32_t featureId);
    bool CheckTypeId(int32_t typeId);
    bool CheckPackageType(int32_t packageType);
    bool CheckTemplateId(int32_t templateId);
    bool CheckPositionType(int32_t positionType);
};

struct ResourceManagerAsyncContext : public AsyncContext {
public:
    std::string resultUri;
    std::string errorMsg;
    bool bRetBool;
    FeatureResult featureResult = {};
    DetailFeatureResult detailFeatureResult = {};
    RequestBodyParams requestBody = {};
};

struct ProcessAsyncContext : public ResourceManagerAsyncContext {
    int32_t process;
};

struct DeleteAsyncContext : public ResourceManagerAsyncContext {
    DeletePredicates deletePredicates;
};

struct BaseAsyncContext : public AsyncContext {
public:
    std::string resultUri;
    std::string errorMsg;
    bool bRetBool;
    RequestBodyParams requestBody;
    BaseResult baseResult = {};
};
} // namespace CameraStandard
} // namespace OHOS

#endif /* RESOURCE_MANAGER_NAPI_H */