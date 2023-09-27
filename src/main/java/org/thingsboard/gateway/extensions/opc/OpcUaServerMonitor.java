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

import lombok.extern.slf4j.Slf4j;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.sdk.client.api.config.OpcUaClientConfig;
import org.eclipse.milo.opcua.sdk.client.api.config.OpcUaClientConfigBuilder;
import org.eclipse.milo.opcua.sdk.client.api.identity.AnonymousProvider;
import org.eclipse.milo.opcua.sdk.client.api.identity.IdentityProvider;
import org.eclipse.milo.opcua.sdk.client.api.subscriptions.UaMonitoredItem;
import org.eclipse.milo.opcua.sdk.client.api.subscriptions.UaSubscription;
import org.eclipse.milo.opcua.sdk.client.nodes.UaVariableNode;
import org.eclipse.milo.opcua.stack.client.security.DefaultClientCertificateValidator;
import org.eclipse.milo.opcua.stack.core.AttributeId;
import org.eclipse.milo.opcua.stack.core.Identifiers;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.security.DefaultTrustListManager;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.types.builtin.*;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.*;
import org.eclipse.milo.opcua.stack.core.types.enumerated.*;
import org.eclipse.milo.opcua.stack.core.types.structured.*;
import org.slf4j.LoggerFactory;
import org.thingsboard.gateway.extensions.opc.conf.KeyStoreLoader;
import org.thingsboard.gateway.extensions.opc.conf.OpcUaServerConfiguration;
import org.thingsboard.gateway.extensions.opc.conf.mapping.DeviceMapping;
import org.thingsboard.gateway.extensions.opc.rpc.RpcProcessor;
import org.thingsboard.gateway.extensions.opc.scan.OpcUaNode;
import org.thingsboard.gateway.extensions.opc.util.OpcUaUtils;
import org.thingsboard.gateway.service.data.RpcCommandSubscription;
import org.thingsboard.gateway.service.gateway.GatewayService;
import org.thingsboard.gateway.util.CertificateInfo;
import org.thingsboard.gateway.util.ConfigurationTools;
import org.thingsboard.server.common.data.kv.KvEntry;
import org.thingsboard.server.common.data.kv.TsKvEntry;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;
import static org.eclipse.milo.opcua.stack.core.util.ConversionUtil.toList;

/**
 * Created by ashvayka on 16.01.17.
 */
@Slf4j
public class OpcUaServerMonitor implements OpcUaDeviceAware {

    private final GatewayService gateway;
    private final OpcUaServerConfiguration configuration;

    private OpcUaClient client;
    private UaSubscription subscription;
    private Map<NodeId, OpcUaDevice> devices;
    private Map<NodeId, List<OpcUaDevice>> devicesByTags;
    private Map<String, OpcUaDevice> devicesByName;
    private Map<Pattern, DeviceMapping> mappings;
    private ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();

    private final AtomicLong clientHandles = new AtomicLong(1L);

    private RpcProcessor rpcProcessor;
    private boolean isRemote;

    public OpcUaServerMonitor(GatewayService gateway, OpcUaServerConfiguration configuration) {
        this.gateway = gateway;
        this.configuration = configuration;
        this.devices = new HashMap<>();
        this.devicesByTags = new HashMap<>();
        this.mappings = configuration.getMapping().stream().collect(Collectors.toMap(m -> Pattern.compile(m.getDeviceNodePattern()), Function.identity()));
        this.devicesByName = new HashMap<>();
    }

    public void connect(Boolean isRemote) {
        try {
            this.isRemote = isRemote;
            log.info("Initializing OPC-UA server connection to [{}:{}]!", configuration.getHost(), configuration.getPort());

            SecurityPolicy securityPolicy = SecurityPolicy.valueOf(configuration.getSecurity());
            IdentityProvider identityProvider = configuration.getIdentity().toProvider();

            client = getOpcUaClient("opc.tcp://" + configuration.getHost() + ":" + configuration.getPort() + "/freeopcua/server/",securityPolicy);
            client.connect().get();
            // todo
            subscription = client.getSubscriptionManager().createSubscription(100.0).get();
            rpcProcessor = new RpcProcessor(gateway, client, this);

            scanForDevices();
        } catch (Exception e) {
            log.error("OPC-UA server connection failed!", e);
            throw new RuntimeException("OPC-UA server connection failed!", e);
        }
    }

    public synchronized OpcUaClient getOpcUaClient(String endpointUrl,SecurityPolicy securityPolicy) throws Exception {
        Path securityTempDir = Paths.get(System.getProperty("java.io.tmpdir"), "client", "security");
        Files.createDirectories(securityTempDir);
        if (!Files.exists(securityTempDir)) {
            throw new Exception("unable to create security dir: " + securityTempDir);
        }

        File pkiDir = securityTempDir.resolve("pki").toFile();

        LoggerFactory.getLogger(getClass())
                .info("security dir: {}", securityTempDir.toAbsolutePath());
        LoggerFactory.getLogger(getClass())
                .info("security pki dir: {}", pkiDir.getAbsolutePath());

        KeyStoreLoader loader = new KeyStoreLoader().load(securityTempDir);

        DefaultTrustListManager trustListManager = new DefaultTrustListManager(pkiDir);

        DefaultClientCertificateValidator certificateValidator =
                new DefaultClientCertificateValidator(trustListManager);

        return  OpcUaClient.create(
                endpointUrl,
                endpoints ->
                        endpoints.stream()
                                .filter(endpointFilter(securityPolicy))
                                .findFirst(),
                configBuilder ->
                        configBuilder
                                .setApplicationName(LocalizedText.english("eclipse milo opc-ua client"))
                                .setApplicationUri("urn:eclipse:milo:examples:client")
                                .setKeyPair(loader.getClientKeyPair())
                                .setCertificate(loader.getClientCertificate())
                                .setCertificateChain(loader.getClientCertificateChain())
                                .setCertificateValidator(certificateValidator)
                                .setIdentityProvider(getIdentityProvider())
                                .setRequestTimeout(uint(5000))
                                .build()
        );
    }

    private IdentityProvider getIdentityProvider() {
        return new AnonymousProvider();
    }

    private Predicate<EndpointDescription> endpointFilter(SecurityPolicy securityPolicy) {
        return e -> securityPolicy.getUri().equals(e.getSecurityPolicyUri());
    }


    public void disconnect() {
        if (client != null) {
            log.info("Disconnecting from OPC-UA server!");
            try {
                client.disconnect().get(10, TimeUnit.SECONDS);
                log.info("Disconnected from OPC-UA server!");
            } catch (InterruptedException | ExecutionException | TimeoutException e) {
                log.info("Failed to disconnect from OPC-UA server!");
            }
        }
    }

    public void scanForDevices() {
        try {
//            client.connect().get();
            long startTs = System.currentTimeMillis();
            scanForDevices(new OpcUaNode(Identifiers.RootFolder, ""));
            log.info("Device scan cycle completed in {} ms", (System.currentTimeMillis() - startTs));
            List<OpcUaDevice> deleted = devices.entrySet().stream().filter(kv -> kv.getValue().getScanTs() < startTs).map(kv -> kv.getValue()).collect(Collectors.toList());
            if (deleted.size() > 0) {
                log.info("Devices {} are no longer available", deleted);
            }
            deleted.forEach(devices::remove);
            deleted.stream().map(OpcUaDevice::getDeviceName).forEach(gateway::onDeviceDisconnect);
        } catch (Exception e) {
            log.warn("Periodic device scan failed!", e);
        }

        log.info("Scheduling next scan in {} seconds!", configuration.getScanPeriodInSeconds());
        executor.schedule(() -> {
            scanForDevices();
        }, configuration.getScanPeriodInSeconds(), TimeUnit.SECONDS);
    }

    @Override
    public OpcUaDevice getDevice(String deviceName) {
        return devicesByName.get(deviceName);
    }

    private void scanForDevices(OpcUaNode node) {
        log.trace("Scanning node: {}", node);
        // 匹配，查询收到的结果是否和配置文件能匹配，能匹配上则需要扫描此设备
        List<DeviceMapping> matchedMappings = mappings.entrySet().stream()
                .filter(mappingEntry -> mappingEntry.getKey().matcher(node.getNodeId().getIdentifier().toString()).matches())
                .map(m -> m.getValue()).collect(Collectors.toList());

        matchedMappings.forEach(m -> {
            try {
                scanDevice(node, m);
            } catch (Exception e) {
                log.error("Failed to scan device: {}", node.getName(), e);
            }
        });

        try {
            BrowseResult browseResult = client.browse(OpcUaUtils.getBrowseDescription(node.getNodeId())).get();
            List<ReferenceDescription> references = toList(browseResult.getReferences());

            for (ReferenceDescription rd : references) {
                NodeId nodeId;
                if (rd.getNodeId().isLocal()) {
                    nodeId = rd.getNodeId().toNodeId(client.getNamespaceTable()).get();
                } else {
                    log.trace("Ignoring remote node: {}", rd.getNodeId());
                    continue;
                }
                OpcUaNode childNode = new OpcUaNode(node, nodeId, rd.getBrowseName().getName());

                // recursively browse to children
                scanForDevices(childNode);
            }
        } catch (InterruptedException | ExecutionException e) {
            log.error("Browsing nodeId={} failed: {}", node, e.getMessage(), e);
//            log.error(e.getMessage());
//            if (e.getMessage().contains("Bad_Timeout") || e.getMessage().contains("time out")) {
//                log.info("{}", "请求超时，重建连接");
//                log.info("{}", "scanForDevices");
//                scanForDevices(node);
//            }
        }
    }

    private void scanDevice(OpcUaNode node, DeviceMapping m) throws Exception {
        log.debug("Scanning device node: {}", node);
        Set<String> tags = m.getAllTags();
        log.debug("Scanning node hierarchy for tags: {}", tags);
        Map<String, NodeId> tagMap = OpcUaUtils.lookupTags(client, node.getNodeId(), node.getName(), tags);
        log.debug("Scanned {} tags out of {}", tagMap.size(), tags.size());

        OpcUaDevice device;
        if (devices.containsKey(node.getNodeId())) {
            device = devices.get(node.getNodeId());
        } else {
            device = new OpcUaDevice(node, m);
            devices.put(node.getNodeId(), device);

            Map<String, NodeId> deviceNameTags = new HashMap<>();
            for (String tag : m.getDeviceNameTags()) {
                NodeId tagNode = tagMap.get(tag);
                if (tagNode == null) {
                    log.error("Not enough info to populate device id for node [{}]. Tag [{}] is missing!", node.getName(), tag);
                    throw new IllegalArgumentException("Not enough info to populate device id. Tag: [" + tag + "] is missing!");
                } else {
                    deviceNameTags.put(tag, tagNode);
                }
            }

            String deviceName = device.calculateDeviceName(readTags(deviceNameTags));
            devicesByName.put(deviceName, device);

            gateway.onDeviceConnect(deviceName, null);
            gateway.subscribe(new RpcCommandSubscription(deviceName, rpcProcessor));
        }

        device.updateScanTs();

        Map<String, NodeId> newTags = device.registerTags(tagMap);
        if (newTags.size() > 0) {
            for (NodeId tagId : newTags.values()) {
                devicesByTags.putIfAbsent(tagId, new ArrayList<>());
                devicesByTags.get(tagId).add(device);
            }
            log.debug("Going to subscribe to tags: {}", newTags);
            subscribeToTags(newTags);
        }
    }

    private void subscribeToTags(Map<String, NodeId> newTags) throws InterruptedException, ExecutionException {
        List<MonitoredItemCreateRequest> requests = new ArrayList<>();
        for (Map.Entry<String, NodeId> kv : newTags.entrySet()) {
            // subscribe to the Value attribute of the server's CurrentTime node
            ReadValueId readValueId = new ReadValueId(
                    kv.getValue(),
                    AttributeId.Value.uid(), null, QualifiedName.NULL_VALUE);
            // important: client handle must be unique per item
            UInteger clientHandle = uint(clientHandles.getAndIncrement());

            MonitoringParameters parameters = new MonitoringParameters(
                    clientHandle,
                    100.0,     // sampling interval
                    null,       // filter, null means use default
                    uint(10),   // queue size
                    true        // discard oldest
            );

            requests.add(new MonitoredItemCreateRequest(
                    readValueId, MonitoringMode.Reporting, parameters));
        }

        UaSubscription.ItemCreationCallback onItemCreated =
                (item, id) -> item.setValueConsumer(this::onSubscriptionValue);

        List<UaMonitoredItem> items = subscription.createMonitoredItems(
                TimestampsToReturn.Both,
                requests,
                onItemCreated
        ).get();

        for (UaMonitoredItem item : items) {
            if (item.getStatusCode().isGood()) {
                log.trace("Monitoring Item created for nodeId={}", item.getReadValueId().getNodeId());
            } else {
                log.warn("Failed to create item for nodeId={} (status={})",
                        item.getReadValueId().getNodeId(), item.getStatusCode());
            }
        }
    }

    static long onDeviceTelemetryTime = 0;
    static long onDeviceTelemetryCount = 0;
    static long time = System.currentTimeMillis();
    static long count = 0;

    static long delayTime = 0;
    private void onSubscriptionValue(UaMonitoredItem item, DataValue dataValue) {
        count++;
        if (System.currentTimeMillis() - time > 1000) {
            System.out.println(System.currentTimeMillis() - time);
            log.info("Subscription value received: item={}, value={}, time = {}",
                    item.getReadValueId().getNodeId(), dataValue.getValue(), dataValue.getSourceTime());
            log.info("{} ms，收到数据条数：{}", System.currentTimeMillis() - time, count);
            time = System.currentTimeMillis();
            count = 0;
        }
        long timediff = System.currentTimeMillis() - dataValue.getServerTime().getJavaTime();
        if (timediff > 1000 && System.currentTimeMillis() - delayTime > 3000) {
            log.warn("当前时间差：{}", timediff);
            delayTime = System.currentTimeMillis();
        }
        NodeId tagId = item.getReadValueId().getNodeId();
        devicesByTags.getOrDefault(tagId, Collections.emptyList()).forEach(
                device -> {
                    device.updateTag(tagId, dataValue);
                    List<KvEntry> attributes = device.getAffectedAttributes(tagId, dataValue);
                    if (attributes.size() > 0) {
                        gateway.onDeviceAttributesUpdate(device.getDeviceName(), attributes);
                    }

                    List<TsKvEntry> timeseries = device.getAffectedTimeseries(tagId, dataValue);
                    if (timeseries.size() > 0) {
                        long timeTmp = System.currentTimeMillis();
                        gateway.onDeviceTelemetry(device.getDeviceName(), timeseries);
                        onDeviceTelemetryCount = onDeviceTelemetryCount + timeseries.size();
                        onDeviceTelemetryTime = onDeviceTelemetryTime + (System.currentTimeMillis() - timeTmp);
                        if (onDeviceTelemetryCount >= 10000) {
                            log.info("{}条写入本地耗时：{}", onDeviceTelemetryCount, onDeviceTelemetryTime);
                            onDeviceTelemetryCount = 0;
                            onDeviceTelemetryTime = 0;
                        }
                        timeseries.clear();
                    }
                }
        );
    }

    private Map<String, String> readTags(Map<String, NodeId> tags) throws ExecutionException, InterruptedException, UaException {
        Map<String, DataValue> dataFutures = new HashMap<>();
        for (Map.Entry<String, NodeId> kv : tags.entrySet()) {
            UaVariableNode node = client.getAddressSpace().getVariableNode(kv.getValue());
            dataFutures.put(kv.getKey(), node.readValue());
        }

        Map<String, String> result = new HashMap<>();
        for (Map.Entry<String, DataValue> kv : dataFutures.entrySet()) {
            String tag = kv.getKey();
            DataValue value = kv.getValue();
            result.put(tag, value.getValue().getValue().toString());
        }
        return result;
    }
}
