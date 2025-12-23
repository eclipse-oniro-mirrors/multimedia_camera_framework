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

#ifndef FEATURE_RESULT_PARSER_H
#define FEATURE_RESULT_PARSER_H

#include <vector>
#include "js_native_api.h"
#include "napi/native_api.h"

#include "resource_types.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
class FeatureResultParser {
public:
    FeatureResultParser(napi_env env) : env_(env) {};

    template <typename T>
    napi_value WrapFeatureResult(const T& result)
    {
        napi_value callbackObj;
        napi_status status = napi_create_object(env_, &callbackObj);
        if (status != napi_ok) {
            napi_get_undefined(env_, &callbackObj);
            return callbackObj;
        }
        napi_value propValue;
        if (napi_create_int32(env_, result.resCode, &propValue) == napi_ok) {
            napi_set_named_property(env_, callbackObj, "resCode", propValue);
        }
        if (napi_create_string_utf8(env_, result.resMsg.c_str(), NAPI_AUTO_LENGTH, &propValue) == napi_ok) {
            napi_set_named_property(env_, callbackObj, "resMsg", propValue);
        }
        if (!result.featureInfos.empty()) {
            napi_value featureArray;
            status = napi_create_array(env_, &featureArray);
            if (status != napi_ok) {
                napi_get_undefined(env_, &featureArray);
                napi_set_named_property(env_, callbackObj, "featureInfos", featureArray);
                return callbackObj;
            }
            for (size_t i = 0; i < result.featureInfos.size(); ++i) {
                const auto& detailTypeInfo = result.featureInfos[i];
                napi_value detailTypeInfoObj = WrapTypeInfo(detailTypeInfo);
                napi_set_element(env_, featureArray, i, detailTypeInfoObj);
            }
            napi_set_named_property(env_, callbackObj, "featureInfos", featureArray);
        }
        return callbackObj;
    }
    napi_value WrapBaseResult(const BaseResult& baseResult);
    napi_value WrapProcess(const std::int32_t& process);

private:
    template <typename U>
    napi_value WrapTypeInfo(const U& typeInfo)
    {
        napi_value typeInfoObj;
        napi_status status = napi_create_object(env_, &typeInfoObj);
        if (status != napi_ok) {
            napi_get_undefined(env_, &typeInfoObj);
            return typeInfoObj;
        }
        napi_value propValue;
        if (napi_create_int32(env_, static_cast<int32_t>(typeInfo.typeId), &propValue) == napi_ok) {
            napi_set_named_property(env_, typeInfoObj, "typeId", propValue);
        }
        napi_value infoArray = WrapInfoArray(typeInfo.infos);
        napi_set_named_property(env_, typeInfoObj, "infos", infoArray);

        return typeInfoObj;
    }
    template <typename E>
    void WrapBaseResourceInfo(const E& info, napi_value& infoObj)
    {
        CHECK_RETURN(infoObj == nullptr);
        napi_value propValue;
        if (napi_create_int32(env_, info.resourceId, &propValue) == napi_ok) {
            napi_set_named_property(env_, infoObj, "resourceId", propValue);
        }
        if (napi_create_int32(env_, info.fullResourceId, &propValue) == napi_ok) {
            napi_set_named_property(env_, infoObj, "fullResourceId", propValue);
        }
        if (napi_create_int32(env_, info.templateId, &propValue) == napi_ok) {
            napi_set_named_property(env_, infoObj, "templateId", propValue);
        }
        if (napi_create_int32(env_, static_cast<int32_t>(info.typeId), &propValue) == napi_ok) {
            napi_set_named_property(env_, infoObj, "typeId", propValue);
        }
        if (napi_create_string_utf8(env_,
                                    info.effectiveTime.c_str(),
                                    NAPI_AUTO_LENGTH,
                                    &propValue) == napi_ok) {
            napi_set_named_property(env_, infoObj, "effectiveTime", propValue);
        }
        if (napi_create_string_utf8(env_,
                                    info.expirationTime.c_str(),
                                    NAPI_AUTO_LENGTH,
                                    &propValue) == napi_ok) {
            napi_set_named_property(env_, infoObj, "expirationTime", propValue);
        }
        if (napi_create_string_utf8(env_,
                                    info.coverUriForCamera.c_str(),
                                    NAPI_AUTO_LENGTH,
                                    &propValue) == napi_ok) {
            napi_set_named_property(env_, infoObj, "coverUriForCamera", propValue);
        }
        if (napi_create_string_utf8(env_,
                                    info.coverUriForPhotoGallery.c_str(),
                                    NAPI_AUTO_LENGTH,
                                    &propValue) == napi_ok) {
            napi_set_named_property(env_, infoObj, "coverUriForPhotoGallery", propValue);
        }
        if (napi_create_int32(env_, static_cast<int32_t>(info.resourceDownloadStatus), &propValue) == napi_ok) {
            napi_set_named_property(env_, infoObj, "resourceDownloadStatus", propValue);
        }
        if (napi_get_boolean(env_, info.isVideoSupported, &propValue) == napi_ok) {
            napi_set_named_property(env_, infoObj, "isVideoSupported", propValue);
        }
    }
    napi_value WrapInfoArray(const std::vector<ResourceInfo>& infos);
    napi_value WrapInfoArray(const std::vector<DetailTemplateInfo>& infos);
    napi_value WrapResourceInfo(const ResourceInfo& resourceInfo);
    napi_value GetUndefined();
    napi_value WrapDetailTemplateInfo(const DetailTemplateInfo& detailTemplateInfo);
    napi_value WrapParamList(const std::vector<ParamInfo>& paramList);
    napi_value WrapParamInfo(const ParamInfo& paramInfo);
    napi_value WrapSelectors(const std::vector<Selector>& selectors);
    napi_value WrapSelector(const Selector& selector);
    napi_value WrapSourceArray(const std::vector<std::string>& source);

    napi_env env_ = nullptr;
};
}
}

#endif /* RESOURCE_MANAGER_NAPI_H */