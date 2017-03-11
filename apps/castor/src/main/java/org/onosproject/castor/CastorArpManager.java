/*
 * Copyright 2016-present Open Networking Laboratory
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
package org.onosproject.castor;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.Service;
import org.onlab.packet.ARP;
import org.onlab.packet.EthType;
import org.onlab.packet.Ethernet;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.host.HostEvent;
import org.onosproject.net.host.HostListener;
import org.onosproject.net.host.HostService;
import org.onosproject.net.intent.Key;
import org.onosproject.net.intent.MultiPointToSinglePointIntent;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.PacketService;
import org.onosproject.routing.IntentSynchronizationService;
import org.slf4j.Logger;

import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * Component for managing the ARPs.
 */

@Component(immediate = true, enabled = true)
@Service
public class CastorArpManager implements ArpService  {

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected ConnectivityManagerService connectivityManager;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected IntentSynchronizationService intentSynchronizer;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CastorStore castorStore;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected HostService hostService;

    private final HostListener hostListener = new CastorHostListener();

    private final Logger log = getLogger(getClass());
    private static final int FLOW_PRIORITY = 500;
    private static final int ARP_FLOW_PRIORITY = 50000;
    private static final MacAddress ARP_SOURCEMAC = MacAddress.valueOf("00:00:00:00:00:01");
    private static final MacAddress ARP_DEST = MacAddress.valueOf("00:00:00:00:00:00");
    private static final byte[] ZERO_MAC_ADDRESS = MacAddress.ZERO.toBytes();
    private static final IpAddress ARP_SRC = Ip4Address.valueOf("0.0.0.0");

    private ApplicationId appId;
    Optional<DeviceId> deviceID = null;

    private enum Protocol {
        ARP
    }

    private enum MessageType {
        REQUEST, REPLY
    }

    @Activate
    public void activate() {
        appId = coreService.getAppId(Castor.CASTOR_APP);
        hostService.addListener(hostListener);
        updateHosts();
        //packetService.addProcessor(processor, PacketProcessor.director(1));
        //requestPackets();
    }

    @Deactivate
    public void deactivate() {
        hostService.removeListener(hostListener);
        //withdrawIntercepts();
        //packetService.removeProcessor(processor);
        //processor = null;
    }

    private class CastorHostListener implements HostListener {

        @Override
        public void event(HostEvent event) {

            switch(event.type()) {

                case HOST_ADDED:
                    // update mac map
                    Host newHost = event.subject();

                    for (IpAddress ip : newHost.ipAddresses()) {
                        castorStore.setAddressMap(ip, newHost.mac());
                        Peer matchingPeer = getMatchingCustomerByAddress(ip);

                        if (matchingPeer != null && !matchingPeer.getl2Status()) {
                            connectivityManager.setUpL2(matchingPeer);
                        }
                    }
                    break;

                case HOST_REMOVED:
                    // do nothing for now
                case HOST_UPDATED:
                    // do nothing for now
            }

        }
    }

    /**
     * Used to update all the known host mac address into Castor Map at startup.
     */
    private void updateHosts() {

        Iterable<Host> allHosts = hostService.getHosts();

        for (Host host : allHosts) {

            for (IpAddress ip : host.ipAddresses()) {
                castorStore.setAddressMap(ip, host.mac());
            }
        }
    }

    private Peer getMatchingCustomerByAddress(IpAddress ipAddress) {

        for (Peer peer : castorStore.getCustomers()) {
            IpAddress peerAddress = IpAddress.valueOf(peer.getIpAddress());

            if(peerAddress.equals(ipAddress)) {
                return peer;
            }
        }
        return null;
    }

    @Override
    public void createArp(Peer peer) {

        Ethernet packet = null;
        packet = buildArpRequest(peer);
        ByteBuffer buf = ByteBuffer.wrap(packet.serialize());
        ConnectPoint connectPoint = ConnectPoint.deviceConnectPoint(peer.getPort());

        TrafficTreatment.Builder builder = DefaultTrafficTreatment.builder();
        builder.setOutput(connectPoint.port());
        packetService.emit(new DefaultOutboundPacket(connectPoint.deviceId(), builder.build(), buf));

    }

    /**
     * Builds the ARP request when MAC is not known.
     *
     * @param peer The Peer whose MAC is not known.
     * @return Ethernet
     */
    private Ethernet buildArpRequest(Peer peer) {
        ARP arp = new ARP();
        arp.setHardwareType(ARP.HW_TYPE_ETHERNET)
                .setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH)
                .setProtocolType(ARP.PROTO_TYPE_IP)
                .setProtocolAddressLength((byte) IpAddress.INET_BYTE_LENGTH)
                .setOpCode(ARP.OP_REQUEST);

        arp.setSenderHardwareAddress(ARP_SOURCEMAC.toBytes())
                .setSenderProtocolAddress(ARP_SRC.toOctets())
                .setTargetHardwareAddress(ZERO_MAC_ADDRESS)
                .setTargetProtocolAddress(IpAddress.valueOf(peer.getIpAddress()).toOctets());

        Ethernet ethernet = new Ethernet();
        ethernet.setEtherType(Ethernet.TYPE_ARP)
                .setDestinationMACAddress(MacAddress.BROADCAST)
                .setSourceMACAddress(ARP_SOURCEMAC)
                .setPayload(arp);
        ethernet.setPad(true);

        return ethernet;
    }

    /**
     * Gets the matching connect point corresponding to the peering IP address.
     *
     * @param target Target IP address
     * @return Connect point as a String
     */
    private String getMatchingConnectPoint(IpAddress target) {
        Set<Peer> peers = castorStore.getAllPeers();
        for (Peer peer : peers) {
            IpAddress match = IpAddress.valueOf(peer.getIpAddress());
            if (match.equals(target)) {
                return peer.getPort();
            }
        }
        return null;
    }

    /**
     * Returns the matching Peer or route server on a Connect Point.
     *
     * @param connectPoint The peering connect point.
     * @return Peer or Route Server
     */
    private Peer getMatchingPeer(ConnectPoint connectPoint) {

        for (Peer peer : castorStore.getAllPeers()) {
            if (connectPoint.equals(ConnectPoint.deviceConnectPoint(peer.getPort()))) {
                return peer;
            }
        }
        return null;
    }

    /**
     * Returns matching BGP Peer on a connect point.
     *
     * @param connectPoint The peering connect point.
     * @return The Peer
     */
    private Peer getMatchingCustomer(ConnectPoint connectPoint) {

        for (Peer peer : castorStore.getCustomers()) {
            if (connectPoint.equals(ConnectPoint.deviceConnectPoint(peer.getPort()))) {
                return peer;
            }
        }
        return null;
    }

    @Override
    public void setUpArp(Peer peer) {

        if (!castorStore.getArpIntents().isEmpty()) {
            updateExistingArpIntents(peer);
        }

        Set<ConnectPoint> ingressPorts = new HashSet<>();
        ConnectPoint egressPort = ConnectPoint.deviceConnectPoint(peer.getPort());

        for (Peer inPeer : castorStore.getAllPeers()) {
            if (!inPeer.getName().equals(peer.getName())) {
                ingressPorts.add(ConnectPoint.deviceConnectPoint(inPeer.getPort()));
            }
        }

        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchArpTpa(Ip4Address.valueOf(peer.getIpAddress()));
        selector.matchEthType(EthType.EtherType.ARP.ethType().toShort());


        TrafficTreatment treatment = DefaultTrafficTreatment.emptyTreatment();


        String arpKey = "arp-" + peer.getIpAddress();
        Key key = Key.of(arpKey, appId);

        MultiPointToSinglePointIntent intent = MultiPointToSinglePointIntent.builder()
                .appId(appId)
                .key(key)
                .selector(selector.build())
                .treatment(treatment)
                .ingressPoints(ingressPorts)
                .egressPoint(egressPort)
                .priority(ARP_FLOW_PRIORITY)
                .build();

        intentSynchronizer.submit(intent);
        castorStore.storeArpIntent(peer.getIpAddress(), intent);

    }

    private void updateExistingArpIntents(Peer peer) {

        Collection<MultiPointToSinglePointIntent> oldIntents = castorStore.getArpIntents().values();

        for (MultiPointToSinglePointIntent oldIntent : oldIntents) {

            Set<ConnectPoint> ingressPoints = oldIntent.ingressPoints();
            ConnectPoint egressPoint = oldIntent.egressPoint();

            if(ConnectPoint.deviceConnectPoint(peer.getPort()).equals(egressPoint)) {
                continue;
            }

            if (ingressPoints.add(ConnectPoint.deviceConnectPoint(peer.getPort()))) {

                MultiPointToSinglePointIntent updatedMp2pIntent =
                        MultiPointToSinglePointIntent.builder()
                                .appId(appId)
                                .key(oldIntent.key())
                                .selector(oldIntent.selector())
                                .treatment(oldIntent.treatment())
                                .ingressPoints(ingressPoints)
                                .egressPoint(egressPoint)
                                .priority(oldIntent.priority())
                                .build();

                intentSynchronizer.submit(updatedMp2pIntent);

                ConnectPoint oldConnectPoint = oldIntent.egressPoint();
                String storeKey = getMatchingAddressByConnectPoint(oldConnectPoint);
                castorStore.storeArpIntent(storeKey, updatedMp2pIntent);
            }
        }
    }

    @Override
    public void deleteArp(Peer peer) {

        intentSynchronizer.withdraw(castorStore.getArpIntents().get(peer.getIpAddress()));
        castorStore.removeArpIntent(peer.getIpAddress());
        updateArpAfterDeletion(peer);
    }

    private String getMatchingAddressByConnectPoint (ConnectPoint cp) {

        for (Peer peer : castorStore.getCustomers()) {

            if(cp.equals(ConnectPoint.deviceConnectPoint(peer.getPort()))) {
                return peer.getIpAddress();
            }
        }
        return null;

    }

    private void updateArpAfterDeletion(Peer peer) {
        Collection<MultiPointToSinglePointIntent> oldIntents = castorStore.getArpIntents().values();
        Map<String, MultiPointToSinglePointIntent> intents = new HashMap<>();

        for (MultiPointToSinglePointIntent oldIntent : oldIntents) {

            Set<ConnectPoint> ingressPoints = oldIntent.ingressPoints();
            ConnectPoint egressPoint = oldIntent.egressPoint();

            if (ingressPoints.remove(ConnectPoint.deviceConnectPoint(peer.getPort()))) {

                MultiPointToSinglePointIntent updatedMp2pIntent =
                        MultiPointToSinglePointIntent.builder()
                                .appId(appId)
                                .key(oldIntent.key())
                                .selector(oldIntent.selector())
                                .treatment(oldIntent.treatment())
                                .ingressPoints(ingressPoints)
                                .egressPoint(egressPoint)
                                .priority(oldIntent.priority())
                                .build();

                ConnectPoint oldConnectPoint = oldIntent.egressPoint();
                String storeKey = getMatchingAddressByConnectPoint(oldConnectPoint);

                intents.put(storeKey, updatedMp2pIntent);
                intentSynchronizer.submit(updatedMp2pIntent);
            }
        }
        for (String key : intents.keySet()) {
            castorStore.storeArpIntent(key, intents.get(key));
        }
    }

    @Override
    public void setArpRouteServer() {

        for (Peer server : castorStore.getServers()) {

            Set<ConnectPoint> ingressPorts = new HashSet<>();
            ConnectPoint egressPort = ConnectPoint.deviceConnectPoint(server.getPort());

            for (Peer inPeer : castorStore.getAllPeers()) {
                if (!inPeer.getName().equals(server.getName())) {
                    ingressPorts.add(ConnectPoint.deviceConnectPoint(inPeer.getPort()));
                }
            }

            TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
            selector.matchArpTpa(Ip4Address.valueOf(server.getIpAddress()));
            selector.matchEthType(EthType.EtherType.ARP.ethType().toShort());


            //TrafficTreatment treatment = DefaultTrafficTreatment.emptyTreatment();
            TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(PortNumber.CONTROLLER).build();

            String arpKey = "arp-" + server.getIpAddress();
            Key key = Key.of(arpKey, appId);

            MultiPointToSinglePointIntent intent = MultiPointToSinglePointIntent.builder()
                    .appId(appId)
                    .key(key)
                    .selector(selector.build())
                    .treatment(treatment)
                    .ingressPoints(ingressPorts)
                    .egressPoint(egressPort)
                    .priority(ARP_FLOW_PRIORITY)
                    .build();

            intentSynchronizer.submit(intent);

        }

    }
}
