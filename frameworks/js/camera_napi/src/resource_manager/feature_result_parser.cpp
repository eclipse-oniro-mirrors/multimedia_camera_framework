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

#include "resource_manager/feature_result_parser.h"

#include <map>
#include "napi/native_api.h"

namespace OHOS {
namespace CameraStandard {
napi_value FeatureResultParser::WrapBaseResult(const BaseResult& baseResult)
{
    napi_value callbackObj;
    napi_status status = napi_create_object(env_, &callbackObj);
    if (status != napi_ok) {
        napi_get_undefined(env_, &callbackObj);
        return callbackObj;
    }
    napi_value propValue;
    if (napi_create_int32(env_, baseResult.resCode, &propValue) == napi_ok) {
        napi_set_named_property(env_, callbackObj, "resCode", propValue);
    }
    if (napi_create_string_utf8(env_, baseResult.resMsg.c_str(), NAPI_AUTO_LENGTH, &propValue) == napi_ok) {
        napi_set_named_property(env_, callbackObj, "resMsg", propValue);
    }
    return callbackObj;
}

napi_value FeatureResultParser::WrapProcess(const std::int32_t& process)
{
    napi_value propValue;
    napi_status status = napi_create_int32(env_, process, &propValue);
    if (status != napi_ok) {
        napi_get_undefined(env_, &propValue);
    }
    return propValue;
}

napi_value FeatureResultParser::WrapInfoArray(const std::vector<ResourceInfo>& infos)
{
    napi_value infoArray;
    napi_status status = napi_create_array(env_, &infoArray);
    if (status != napi_ok) {
        napi_get_undefined(env_, &infoArray);
        return infoArray;
    }
    if (infos.empty()) {
        return infoArray;
    }
    for (size_t j = 0; j < infos.size(); ++j) {
        const auto& resourceInfo = infos[j];
        napi_value resourceInfoObj = WrapResourceInfo(resourceInfo);
        napi_set_element(env_, infoArray, j, resourceInfoObj);
    }
    return infoArray;
}

napi_value FeatureResultParser::WrapInfoArray(const std::vector<DetailTemplateInfo>& infos)
{
    napi_value infoArray;
    napi_status status = napi_create_array(env_, &infoArray);
    if (status != napi_ok) {
        napi_get_undefined(env_, &infoArray);
        return infoArray;
    }
    if (infos.empty()) {
        return infoArray;
    }
    for (size_t j = 0; j < infos.size(); ++j) {
        const auto& detailTemplateInfo = infos[j];
        napi_value detailTemplateInfoObj = WrapDetailTemplateInfo(detailTemplateInfo);
        napi_set_element(env_, infoArray, j, detailTemplateInfoObj);
    }
    return infoArray;
}

napi_value FeatureResultParser::WrapResourceInfo(const ResourceInfo& resourceInfo)
{
    napi_value resourceInfoObj;
    napi_status status = napi_create_object(env_, &resourceInfoObj);
    if (status != napi_ok) {
        napi_get_undefined(env_, &resourceInfoObj);
        return resourceInfoObj;
    }
    WrapBaseResourceInfo(resourceInfo, resourceInfoObj);
    // 传入空值防止出现crash
    napi_value paramArray;
    if (napi_create_array(env_, &paramArray) == napi_ok) {
        napi_set_named_property(env_, resourceInfoObj, "paramList", paramArray);
    }
    return resourceInfoObj;
}

napi_value FeatureResultParser::WrapDetailTemplateInfo(const DetailTemplateInfo& detailTemplateInfo)
{
    napi_value detailTemplateInfoObj;
    napi_status status = napi_create_object(env_, &detailTemplateInfoObj);
    if (status != napi_ok) {
        napi_get_undefined(env_, &detailTemplateInfoObj);
        return detailTemplateInfoObj;
    }
    WrapBaseResourceInfo(detailTemplateInfo, detailTemplateInfoObj);
    napi_value paramArray = WrapParamList(detailTemplateInfo.paramList);
    napi_set_named_property(env_, detailTemplateInfoObj, "paramList", paramArray);
    return detailTemplateInfoObj;
}

napi_value FeatureResultParser::WrapParamList(const std::vector<ParamInfo>& paramList)
{
    napi_value paramArray;
    napi_status status = napi_create_array(env_, &paramArray);
    if (status != napi_ok) {
        napi_get_undefined(env_, &paramArray);
        return paramArray;
    }
    if (paramList.empty()) {
        return paramArray;
    }
    for (size_t k = 0; k < paramList.size(); ++k) {
        const auto& paramInfo = paramList[k];
        napi_value paramInfoObj = WrapParamInfo(paramInfo);
        napi_set_element(env_, paramArray, k, paramInfoObj);
    }
    return paramArray;
}

napi_value FeatureResultParser::WrapParamInfo(const ParamInfo& paramInfo)
{
    napi_value paramInfoObj;
    napi_status status = napi_create_object(env_, &paramInfoObj);
    if (status != napi_ok) {
        napi_get_undefined(env_, &paramInfoObj);
        return paramInfoObj;
    }
    napi_value propValue;
    if (napi_create_string_utf8(env_, paramInfo.paramId.c_str(), NAPI_AUTO_LENGTH, &propValue) == napi_ok) {
        napi_set_named_property(env_, paramInfoObj, "paramId", propValue);
    }
    if (napi_create_string_utf8(env_, paramInfo.defaultValue.c_str(), NAPI_AUTO_LENGTH, &propValue) == napi_ok) {
        napi_set_named_property(env_, paramInfoObj, "defaultValue", propValue);
    }
    if (napi_create_string_utf8(env_, paramInfo.titleText.c_str(), NAPI_AUTO_LENGTH, &propValue) == napi_ok) {
        napi_set_named_property(env_, paramInfoObj, "titleText", propValue);
    }
    if (napi_create_int32(env_, static_cast<int32_t>(paramInfo.type), &propValue) == napi_ok) {
        napi_set_named_property(env_, paramInfoObj, "type", propValue);
    }
    if (napi_create_string_utf8(env_, paramInfo.description.c_str(), NAPI_AUTO_LENGTH, &propValue) == napi_ok) {
        napi_set_named_property(env_, paramInfoObj, "description", propValue);
    }
    if (napi_create_string_utf8(env_, paramInfo.affectedField.c_str(), NAPI_AUTO_LENGTH, &propValue) == napi_ok) {
        napi_set_named_property(env_, paramInfoObj, "affectedField", propValue);
    }
    if (napi_get_boolean(env_, paramInfo.isVideoSupported, &propValue) == napi_ok) {
        napi_set_named_property(env_, paramInfoObj, "isVideoSupported", propValue);
    }
    napi_value selectorsArray = WrapSelectors(paramInfo.selectors);
    napi_set_named_property(env_, paramInfoObj, "selectors", selectorsArray);
    return paramInfoObj;
}

napi_value FeatureResultParser::WrapSelectors(const std::vector<Selector>& selectors)
{
    napi_value selectorsArray;
    napi_status status = napi_create_array(env_, &selectorsArray);
    if (status != napi_ok) {
        napi_get_undefined(env_, &selectorsArray);
        return selectorsArray;
    }
    if (selectors.empty()) {
        return selectorsArray;
    }
    for (size_t m = 0; m < selectors.size(); ++m) {
        const auto& selector = selectors[m];
        napi_value selectorObj = WrapSelector(selector);
        napi_set_element(env_, selectorsArray, m, selectorObj);
    }
    return selectorsArray;
}

napi_value FeatureResultParser::WrapSelector(const Selector& selector)
{
    napi_value selectorObj;
    napi_status status = napi_create_object(env_, &selectorObj);
    if (status != napi_ok) {
        napi_get_undefined(env_, &selectorObj);
        return selectorObj;
    }
    napi_value propValue;
    if (napi_create_int32(env_, static_cast<int32_t>(selector.id), &propValue) == napi_ok) {
        napi_set_named_property(env_, selectorObj, "id", propValue);
    }
    if (napi_create_int32(env_, static_cast<int32_t>(selector.type), &propValue) == napi_ok) {
        napi_set_named_property(env_, selectorObj, "type", propValue);
    }
    if (napi_create_int32(env_, static_cast<int32_t>(selector.shapeType), &propValue) == napi_ok) {
        napi_set_named_property(env_, selectorObj, "shapeType", propValue);
    }
    napi_value sourceArray = WrapSourceArray(selector.source);
    napi_set_named_property(env_, selectorObj, "source", sourceArray);
    return selectorObj;
}

napi_value FeatureResultParser::WrapSourceArray(const std::vector<std::string>& source)
{
    napi_value sourceArray;
    napi_status status = napi_create_array(env_, &sourceArray);
    if (status != napi_ok) {
        napi_get_undefined(env_, &sourceArray);
        return sourceArray;
    }
    if (source.empty()) {
        return sourceArray;
    }
    for (size_t n = 0; n < source.size(); ++n) {
        const auto& sourceTmp = source[n];
        napi_value propValue;
        napi_status status = napi_create_string_utf8(env_, sourceTmp.c_str(), NAPI_AUTO_LENGTH, &propValue);
        if (status != napi_ok) {
            napi_get_undefined(env_, &propValue);
        }
        napi_set_element(env_, sourceArray, n, propValue);
    }
    return sourceArray;
}
}
}