/**
 * Copyright © 2023 The Thingsboard Authors
 *
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
package org.thingsboard.gateway.extensions.opc;

import lombok.Data;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.thingsboard.gateway.extensions.opc.conf.mapping.AttributesMapping;
import org.thingsboard.gateway.extensions.opc.conf.mapping.DeviceMapping;
import org.thingsboard.gateway.extensions.common.conf.mapping.KVMapping;
import org.thingsboard.gateway.extensions.opc.conf.mapping.TimeseriesMapping;
import org.thingsboard.gateway.extensions.opc.scan.OpcUaNode;
import org.thingsboard.server.common.data.kv.*;

import java.util.*;
import java.util.stream.Collectors;

import static java.util.Comparator.comparingLong;
import static java.util.stream.Collectors.collectingAndThen;
import static java.util.stream.Collectors.toCollection;

/**
 * Created by ashvayka on 16.01.17.
 */
@Data
public class OpcUaDevice {

    Logger logger = LoggerFactory.getLogger(OpcUaDevice.class);

    private final OpcUaNode opcNode;
    private final DeviceMapping mapping;
    private final Map<String, NodeId> tagKeysMap = new HashMap<>();
    private final Map<NodeId, String> tagIdsMap = new HashMap<>();
    private final Map<String, String> tagValues = new HashMap<>();
    private final Map<NodeId, List<AttributesMapping>> attributesMap = new HashMap<>();
    private final Map<NodeId, List<TimeseriesMapping>> timeseriesMap = new HashMap<>();

    private String deviceName;
    private long scanTs;

    public Map<String, NodeId> registerTags(Map<String, NodeId> newTagMap) {
        Map<String, NodeId> newTags = new HashMap<>();
        for (Map.Entry<String, NodeId> kv : newTagMap.entrySet()) {
            NodeId old = registerTag(kv);
            if (old == null) {
                newTags.put(kv.getKey(), kv.getValue());
            }
        }
        return newTags;
    }

    private NodeId registerTag(Map.Entry<String, NodeId> kv) {
        String tag = kv.getKey();
        NodeId tagId = kv.getValue();
        mapping.getAttributes().stream()
                .filter(attr -> attr.getValue().contains(escape(tag)))
                .forEach(attr -> attributesMap.computeIfAbsent(tagId, key -> new ArrayList<>()).add(attr));
        if (attributesMap.containsKey(tagId) && attributesMap.get(tagId).size() > 0) {
            List<AttributesMapping> attributesUnique = attributesMap.get(tagId).stream().collect(collectingAndThen(
                    toCollection(() -> new TreeSet<>(Comparator.comparing(AttributesMapping::getKey).thenComparing(AttributesMapping::getValue))), ArrayList::new)
            );
            attributesMap.put(tagId, attributesUnique);
        }

        mapping.getTimeseries().stream()
                .filter(attr -> attr.getValue().contains(escape(tag)))
                .forEach(attr -> timeseriesMap.computeIfAbsent(tagId, key -> new ArrayList<>()).add(attr));
        if (timeseriesMap.containsKey(tagId)) {
            List<TimeseriesMapping> unique = timeseriesMap.get(tagId).stream().collect(collectingAndThen(
                    toCollection(() -> new TreeSet<>(Comparator.comparing(TimeseriesMapping::getKey).thenComparing(TimeseriesMapping::getValue))), ArrayList::new)
            );
            timeseriesMap.put(tagId, unique);
        }
        tagIdsMap.putIfAbsent(kv.getValue(), kv.getKey());
        return tagKeysMap.put(kv.getKey(), kv.getValue());
    }

    public String calculateDeviceName(Map<String, String> deviceNameTagValues) {
        String deviceNameTmp = mapping.getDeviceNamePattern();
        for (Map.Entry<String, String> kv : deviceNameTagValues.entrySet()) {
            deviceNameTmp = deviceNameTmp.replace(escape(kv.getKey()), kv.getValue());
        }
        this.deviceName = deviceNameTmp;

        return this.deviceName;
    }

    public void updateTag(NodeId tagId, DataValue dataValue) {
        String tag = tagIdsMap.get(tagId);
        tagValues.put(tag, dataValue.getValue().getValue().toString());
        tagValues.put(escape(tag), dataValue.getValue().getValue().toString());
    }

    public void updateScanTs() {
        scanTs = System.currentTimeMillis();
    }

    private List<AttributesMapping> getAttributesMapping(NodeId tag) {
        return attributesMap.getOrDefault(tag, Collections.emptyList());
    }

    private List<TimeseriesMapping> getTimeseriesMapping(NodeId tag) {
        return timeseriesMap.getOrDefault(tag, Collections.emptyList());
    }

    private String escape(String tag) {
        return "${" + tag + "}";
    }

    public List<KvEntry> getAffectedAttributes(NodeId tagId, DataValue dataValue) {
        List<AttributesMapping> attributes = getAttributesMapping(tagId);
        if (attributes.size() > 0) {
            return getKvEntries(attributes);
        } else {
            return Collections.emptyList();
        }
    }

    public List<TsKvEntry> getAffectedTimeseries(NodeId tagId, DataValue dataValue) {
        List<TimeseriesMapping> attributes = getTimeseriesMapping(tagId);
        if (attributes.size() > 0) {
            return getKvEntries(attributes).stream()
                    .map(kv -> new BasicTsKvEntry(dataValue.getSourceTime().getJavaTime(), kv))
                    .collect(Collectors.toList());
        } else {
            return Collections.emptyList();
        }
    }

    public NodeId getTagNodeId(String tag) {
        return tagKeysMap.get(tag);
    }

//    static long time = 0;

    private List<KvEntry> getKvEntries(List<? extends KVMapping> mappings) {
        List<KvEntry> result = new ArrayList<>();
        if (mappings == null) {
            return result;
        }
//        if (System.currentTimeMillis() - time > 1000) {
//            logger.info("mappings:{}", mappings.size());
//            logger.info("tagValues:{}", tagValues.size());
//            time = System.currentTimeMillis();
//        }
        for (KVMapping mapping : mappings) {
//            String strVal = mapping.getValue();
//            for (Map.Entry<String, String> tagKV : tagValues.entrySet()) {
//                strVal = strVal.replace(escape(tagKV.getKey()), tagKV.getValue());
//            }
            String strVal = tagValues.get(mapping.getValue());
            if (strVal == null) {
                strVal = mapping.getValue();
            }
            switch (mapping.getType().getDataType()) {
                case STRING:
                    result.add(new StringDataEntry(mapping.getKey(), strVal));
                    break;
                case BOOLEAN:
                    result.add(new BooleanDataEntry(mapping.getKey(), Boolean.valueOf(strVal)));
                    break;
                case DOUBLE:
                    result.add(new DoubleDataEntry(mapping.getKey(), Double.valueOf(strVal)));
                    break;
                case LONG:
                    result.add(new LongDataEntry(mapping.getKey(), Long.valueOf(strVal)));
                    break;
            }
        }
        return result;
    }
}
