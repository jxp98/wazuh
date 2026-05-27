/*
 * Wazuh SysCollector
 * Copyright (C) 2015, Wazuh Inc.
 * January 12, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include <iostream>
#include <fstream>
#include <regex>

#include "syscollectorNormalizer.hpp"

namespace
{
std::string jsonStringValue(const nlohmann::json& value)
{
    return value.get<std::string>();
}
}

SysNormalizer::SysNormalizer(const std::string& configFile,
                             const std::string& target)
    : m_typeExclusions(getTypeValues(configFile, target, "exclusions"))
    , m_typeDictionary(getTypeValues(configFile, target, "dictionary"))
{
}

void SysNormalizer::removeExcluded(const std::string& type,
                                   nlohmann::json& data) const
{
    const auto exclusionsIt = m_typeExclusions.find(type);

    if (exclusionsIt != m_typeExclusions.cend())
    {
        for (const auto& exclusionItem : exclusionsIt->second)
        {
            try
            {
                const auto patternValue = jsonStringValue(exclusionItem["pattern"]);
                const auto fieldName = jsonStringValue(exclusionItem["field_name"]);
                std::regex pattern(patternValue);

                if (data.is_array())
                {
                    for (auto item{data.begin()}; item != data.end(); ++item)
                    {
                        const auto fieldIt = item->find(fieldName);

                        if (fieldIt != item->end() && std::regex_match(jsonStringValue(*fieldIt), pattern))
                        {
                            data.erase(item);
                        }
                    }
                }
                else
                {
                    const auto fieldIt = data.find(fieldName);

                    if (fieldIt != data.end() && std::regex_match(jsonStringValue(*fieldIt), pattern))
                    {
                        data.clear();
                    }
                }
            }
            // LCOV_EXCL_START
            catch (...)
            {}

            // LCOV_EXCL_STOP
        }
    }
}


static void normalizeItem(const nlohmann::json& dictionary,
                          nlohmann::json& item)
{
    for (const auto& dictItem : dictionary)
    {
        const auto itFindPattern = dictItem.find("find_pattern");
        const auto itFindField = dictItem.find("find_field");

        if (itFindPattern != dictItem.end() && itFindField != dictItem.end())
        {
            const auto findField = jsonStringValue(*itFindField);
            const auto findPattern = jsonStringValue(*itFindPattern);
            const auto fieldIt = item.find(findField);
            std::regex pattern(findPattern);

            if (fieldIt == item.end() ||
                    !std::regex_match(jsonStringValue(*fieldIt), pattern))
            {
                //no field in the item or no matching, we continue
                continue;
            }
        }
        else if (itFindPattern != dictItem.end() || itFindField != dictItem.end())
        {
            //we won't evaluate an incomplete item.
            continue;
        }

        const auto itReplacePattern = dictItem.find("replace_pattern");
        const auto itReplaceField = dictItem.find("replace_field");
        const auto itReplaceValue = dictItem.find("replace_value");

        if (itReplacePattern != dictItem.end() && itReplaceField != dictItem.end() && itReplaceValue != dictItem.end())
        {
            const auto replacePattern = jsonStringValue(*itReplacePattern);
            const auto replaceField = jsonStringValue(*itReplaceField);
            const auto replaceValue = jsonStringValue(*itReplaceValue);
            std::regex pattern(replacePattern);
            const auto fieldIt = item.find(replaceField);

            if (fieldIt != item.end())
            {
                *fieldIt = std::regex_replace(jsonStringValue(*fieldIt), pattern, replaceValue);
            }
        }

        const auto itAddField = dictItem.find("add_field");
        const auto itAddValue = dictItem.find("add_value");

        if (itAddField != dictItem.end() && itAddValue != dictItem.end())
        {
            item[jsonStringValue(*itAddField)] = jsonStringValue(*itAddValue);
        }
    }
}

void SysNormalizer::normalize(const std::string& type,
                              nlohmann::json& data) const
{
    const auto dictionaryIt = m_typeDictionary.find(type);

    if (dictionaryIt != m_typeDictionary.cend())
    {
        if (data.is_array())
        {
            for (auto& item : data)
            {
                normalizeItem(dictionaryIt->second, item);
            }
        }
        else
        {
            normalizeItem(dictionaryIt->second, data);
        }
    }
}

std::map<std::string, nlohmann::json> SysNormalizer::getTypeValues(const std::string& configFile,
                                                                   const std::string& target,
                                                                   const std::string& type)
{
    std::map<std::string, nlohmann::json> ret;

    try
    {
        std::ifstream config(configFile);
        nlohmann::json data;

        if (config.is_open())
        {
            const auto jsonConfigFile = nlohmann::json::parse(config);
            const auto it = jsonConfigFile.find(type);

            if (it != jsonConfigFile.end())
            {
                for (const auto& item : *it)
                {
                    if (item["target"] == target)
                    {
                        ret[jsonStringValue(item["data_type"])].push_back(item);
                    }
                }
            }
        }
    }
    catch (...)
    {
    }

    return ret;
}
