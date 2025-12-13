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

#include "camera_xml_parser.h"

#include <dlfcn.h>
#include <string>
#include <map>
#include <set>
#include <atomic>
#include <mutex>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include "camera_log.h"
namespace OHOS {
namespace CameraStandard {

static const int8_t SUCCESS = 0;
static const int8_t FAIL = -1;

class CameraXmlNodeInner : public CameraXmlNode {
public:
    CameraXmlNodeInner();
    CameraXmlNodeInner(const CameraXmlNodeInner &obj);
    CameraXmlNodeInner &operator=(const CameraXmlNodeInner &obj);
    ~CameraXmlNodeInner() override;

    std::shared_ptr<CameraXmlNode> GetChildrenNode() override;
    std::shared_ptr<CameraXmlNode> GetCopyNode() override;
    int32_t Config(const char *fileName, const char *encoding, int32_t options) override;
    void MoveToNext() override;
    void MoveToChildren() override;

    bool IsNodeValid() override;
    bool CompareName(const char *propName) override;
    bool IsElementNode() override;
    bool HasProp(const char *propName) override;
    int32_t GetProp(const char *propName, std::string &result) override;
    int32_t GetContent(std::string &result) override;
    std::string GetName() override;

    void FreeDoc() override;
    void FreeProp(char *propName) override;
    void CleanUpParser() override;

private:
    int32_t StrcmpXml(const xmlChar *propName1, const xmlChar *propName2);
    xmlDoc *doc_ = nullptr;
    xmlNode *curNode_ = nullptr;
};

std::shared_ptr<CameraXmlNode> CameraXmlNode::Create()
{
    return std::make_shared<CameraXmlNodeInner>();
}

std::shared_ptr<CameraXmlNode> CameraXmlNodeInner::GetChildrenNode()
{
    std::shared_ptr<CameraXmlNodeInner> copyNode = std::make_shared<CameraXmlNodeInner>(*this);
    copyNode->MoveToChildren();
    return copyNode;
}

std::shared_ptr<CameraXmlNode> CameraXmlNodeInner::GetCopyNode()
{
    return std::make_shared<CameraXmlNodeInner>(*this);
}

CameraXmlNodeInner::CameraXmlNodeInner() {}

CameraXmlNodeInner::CameraXmlNodeInner(const CameraXmlNodeInner &obj)
{
    // only the main node has doc and freedoc() when destruct
    doc_ = nullptr;
    curNode_ = obj.curNode_;
}

CameraXmlNodeInner &CameraXmlNodeInner::operator=(const CameraXmlNodeInner &obj)
{
    // only the main node has doc and freedoc() when destruct
    doc_ = nullptr;
    curNode_ = obj.curNode_;
    return *this;
}

CameraXmlNodeInner::~CameraXmlNodeInner()
{
    if (doc_ != nullptr) {
        xmlFreeDoc(doc_);
        xmlCleanupParser();
        doc_ = nullptr;
    }
    curNode_ = nullptr;
}

int32_t CameraXmlNodeInner::Config(const char *fileName, const char *encoding, int32_t options)
{
    doc_ = xmlReadFile(fileName, encoding, options);
    CHECK_RETURN_RET_ELOG(doc_ == nullptr, FAIL, "xmlReadFile failed! fileName :%{private}s", fileName);
    curNode_ = xmlDocGetRootElement(doc_);
    CHECK_RETURN_RET_ELOG(curNode_ == nullptr, FAIL, "xmlDocGetRootElement failed!");
    return SUCCESS;
}

void CameraXmlNodeInner::MoveToNext()
{
    CHECK_RETURN_ELOG(curNode_ == nullptr, "curNode_ is nullptr! Cannot MoveToNext!");
    curNode_ = curNode_->next;
}

void CameraXmlNodeInner::MoveToChildren()
{
    CHECK_RETURN_ELOG(curNode_ == nullptr, "curNode_ is nullptr! Cannot MoveToChildren!");
    curNode_ = curNode_->children;
}

bool CameraXmlNodeInner::IsNodeValid()
{
    return curNode_ != nullptr;
}

// need check curNode_ isvalid before use
bool CameraXmlNodeInner::HasProp(const char *propName)
{
    return xmlHasProp(curNode_, reinterpret_cast<const xmlChar*>(propName));
}

// need check curNode_ isvalid before use
int32_t CameraXmlNodeInner::GetProp(const char *propName, std::string &result)
{
    result = "";
    xmlChar *tempValue = xmlGetProp(curNode_, reinterpret_cast<const xmlChar*>(propName));
    CHECK_RETURN_RET_ELOG(tempValue == nullptr, FAIL, "GetProp Fail! curNode has no prop: %{public}s", propName);
    result = reinterpret_cast<char*>(tempValue);
    xmlFree(tempValue);
    return SUCCESS;
}

int32_t CameraXmlNodeInner::GetContent(std::string &result)
{
    xmlChar *tempContent = xmlNodeGetContent(curNode_);
    CHECK_RETURN_RET_ELOG(tempContent == nullptr, FAIL, "GetContent Fail!");
    result = reinterpret_cast<char*>(tempContent);
    return SUCCESS;
}

std::string CameraXmlNodeInner::GetName()
{
    CHECK_RETURN_RET_ELOG(curNode_ == nullptr, "", "curNode_ is nullptr! Cannot GetName!");
    return reinterpret_cast<char*>(const_cast<xmlChar*>(curNode_->name));
}

void CameraXmlNodeInner::FreeDoc()
{
    if (doc_ != nullptr) {
        xmlFreeDoc(doc_);
        doc_ = nullptr;
    }
}

void CameraXmlNodeInner::FreeProp(char *propName)
{
    xmlFree(reinterpret_cast<xmlChar*>(propName));
}

void CameraXmlNodeInner::CleanUpParser()
{
    xmlCleanupParser();
}

int32_t CameraXmlNodeInner::StrcmpXml(const xmlChar *propName1, const xmlChar *propName2)
{
    return xmlStrcmp(propName1, propName2);
}

bool CameraXmlNodeInner::CompareName(const char *propName)
{
    CHECK_RETURN_RET_ELOG(curNode_ == nullptr, false, "curNode_ is nullptr! Cannot CompareName!");
    return curNode_->type == XML_ELEMENT_NODE &&
        (StrcmpXml(curNode_->name, reinterpret_cast<const xmlChar*>(propName)) == 0);
}

bool CameraXmlNodeInner::IsElementNode()
{
    CHECK_RETURN_RET_ELOG(curNode_ == nullptr, false, "curNode_ is nullptr! Cannot CompareElementNode!");
    return curNode_->type == XML_ELEMENT_NODE;
}

} // namespace CameraStandard
} // namespace OHOS
