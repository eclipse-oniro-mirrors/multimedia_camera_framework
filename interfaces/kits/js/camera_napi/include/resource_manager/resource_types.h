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

#ifndef RESOURCE_TYPES_H
#define RESOURCE_TYPES_H

#include <cstdint>
#include "surface.h"

namespace OHOS {
namespace CameraStandard {
enum class FeatureId : int32_t {
    INVALID_FEATURE_ID = -1,
    FEATURE_ID_WATERMARK = 1,
};

enum class ResourceDownloadStatus : int32_t {
    INVALID_RES_DOWNLOAD_STATUS = -1,
    IDLE = 0,
    COVER_DOWNLOADING = 101,
    COVER_DOWNLOADED = 102,
    COVER_NEW_VERSION_EXIST = 103,
    FULL_DOWNLOADING = 201,
    FULL_PART_DOWNLOADED = 202,
    FULL_DOWNLOADED = 203,
    FULL_NEW_VERSION_EXIST = 204,
};

enum class TypeId : int32_t {
    INVALID_TYPE_ID = -1,
    COMMON = 0,
    INDIVIDUALITY = 1,
    TIME_LIMIT = 2,
};

enum class PackageType : int32_t {
    INVALID_PACKAGE_TYPE = -1,
    COVER = 1,
    FULL = 2,
};

enum class PositionType : int32_t {
    INVALID_POSITION_TYPE = -1,
    TEXT = 1 << 0,
    PICTURE = 1 << 1,
    COLOR = 1 << 2,
    FONT = 1 << 3,
};

struct BaseFeatureInfo {
    FeatureId featureId;
};

struct ReqCallerInfo {
    std::string bundleName;
};

struct RequestBodyParams {
    ReqCallerInfo callerInfo;
    FeatureId featureId;
    TypeId typeId;
    int32_t templateId;
    int32_t resourceId;
    PackageType packageType;
};

struct ResourceInfo {
    int32_t resourceId;
    int32_t fullResourceId;
    int32_t templateId;
    TypeId typeId;
    std::string effectiveTime;
    std::string expirationTime;
    std::string coverUriForCamera;
    std::string coverUriForPhotoGallery;
    ResourceDownloadStatus resourceDownloadStatus;
    bool isVideoSupported;
};

enum class ParamType : int32_t {
    INVALID = -1,
    SWITCH = 0,
    SELECTOR = 1,
    CUSTOM = 2,
};

enum class SelectorOptions : int32_t {
    SELECTOR_OPTION_FIRST = 0,
    SELECTOR_OPTION_SECOND = 1,
    SELECTOR_OPTION_THIRD = 2,
    SELECTOR_OPTION_FOURTH = 3,
};

enum class SelectorType : int32_t {
    IMAGE = 0,
    TEXT = 1,
    PRESET_IMAGE = 2,
};

enum class ShapeType : int32_t {
    CIRCLE = 0,
    SQUARE = 1,
};

struct Selector {
    SelectorOptions id;
    SelectorType type;
    ShapeType shapeType;
    std::vector<std::string> source;
};

struct ParamInfo {
    std::string paramId;
    std::string defaultValue;
    std::string titleText;
    ParamType type;
    std::string description;
    std::vector<Selector> selectors;
    std::string affectedField;
    bool isVideoSupported;
};

struct DetailTemplateInfo : public ResourceInfo {
    std::vector<ParamInfo> paramList;
};

struct TypeInfo {
    TypeId typeId;
    std::vector<ResourceInfo> infos;
};

struct DetailTypeInfo {
    TypeId typeId;
    std::vector<DetailTemplateInfo> infos;
};

struct BaseResult {
    int32_t resCode;
    std::string resMsg;
};

struct FeatureResult : public BaseResult {
    std::vector<TypeInfo> featureInfos;
};

struct DetailFeatureResult : public BaseResult {
    std::vector<DetailTypeInfo> featureInfos;
};

struct DeletePredicates {
    int32_t downloadedDuration;
};
}
}
#endif