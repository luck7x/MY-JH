import { urlsToClashProxies } from '../../../utils/url-to-clash.js';
import { normalizeUnifiedTemplateModel } from '../template-model.js';
import { buildSingboxDnsConfig, DNS_PROXY_GROUP, SINGBOX_CN_RULE_SET } from '../safe-dns.js';
import { getSingboxDnsRuleSet, pinRemoteRuleUrl } from '../builtin-rules-provider.js';

function sanitizeTag(value) {
    return String(value || '').trim() || 'Untitled';
}

function parsePort(port) {
    const num = Number.parseInt(String(port), 10);
    return Number.isFinite(num) ? num : undefined;
}

function buildOutbound(proxy) {
    if (!proxy || !proxy.server || !proxy.port) return null;

    const type = String(proxy.type || '').toLowerCase();
    const tag = sanitizeTag(proxy.name);
    const server = proxy.server;
    const serverPort = parsePort(proxy.port);
    if (!serverPort) return null;

    if (type === 'http' || type === 'https') {
        const outbound = {
            tag,
            type: 'http',
            server,
            server_port: serverPort,
            username: proxy.username || undefined,
            password: proxy.password || undefined,
        };
        if (type === 'https' || proxy.tls || proxy.sni || proxy.servername) {
            outbound.tls = {
                enabled: true,
                server_name: proxy.servername ?? proxy.sni ?? server,
                insecure: proxy['skip-cert-verify'] === true || proxy.skipCertVerify === true,
            };
        }
        return outbound;
    }

    if (type === 'trojan') {
        return {
            tag,
            type: 'trojan',
            server,
            server_port: serverPort,
            password: proxy.password || '',
            tls: {
                enabled: true,
                server_name: proxy.servername ?? proxy.sni ?? server,
                insecure: proxy['skip-cert-verify'] === true || proxy.skipCertVerify === true,
            },
        };
    }

    if (type === 'ss' || type === 'shadowsocks') {
        const outbound = {
            tag,
            type: 'shadowsocks',
            server,
            server_port: serverPort,
            method: proxy.cipher || 'aes-128-gcm',
            password: proxy.password || '',
        };
        // sing-box 的 Shadowsocks 出站使用 SIP003 plugin/plugin_opts；
        // `transport` 仅属于 V2Ray 传输协议，SFA 会严格拒绝它。
        const plugin = proxy.plugin || '';
        const opts = proxy['plugin-opts'] || proxy.pluginOpts || {};
        if (plugin === 'v2ray-plugin' || opts.mode === 'websocket') {
            outbound.plugin = 'v2ray-plugin';
            const pluginOptions = ['mode=websocket'];
            if (opts.host) pluginOptions.push(`host=${opts.host}`);
            if (opts.path) pluginOptions.push(`path=${opts.path}`);
            if (opts.tls || opts.mode === 'websocket-tls') pluginOptions.push('tls');
            outbound.plugin_opts = pluginOptions.join(';');
        }
        return outbound;
    }

    if (type === 'vmess') {
        const outbound = {
            tag,
            type: 'vmess',
            server,
            server_port: serverPort,
            uuid: proxy.uuid || '',
            security: proxy.cipher || 'auto',
            congestion_control: proxy['congestion-control'] || 'cubic',
            alter_id: Number.isFinite(Number(proxy.alterId)) ? Number(proxy.alterId) : 0,
        };

        const network = proxy.network || '';
        if (network === 'ws') {
            const wsOpts = proxy['ws-opts'] || proxy.wsOpts;
            outbound.transport = {
                type: 'ws',
                path: wsOpts?.path || '/',
                headers: wsOpts?.headers || {},
            };
        } else if (network === 'grpc') {
            const grpcOpts = proxy['grpc-opts'] || proxy.grpcOpts;
            outbound.transport = {
                type: 'grpc',
                service_name: grpcOpts?.['grpc-service-name'] || grpcOpts?.serviceName || 'grpc',
            };
        } else if (network === 'h2' || network === 'http') {
            const opts = proxy[`${network}-opts`] || proxy[`${network}Opts`];
            outbound.transport = {
                type: network === 'h2' ? 'h2' : 'http',
                host: opts?.host ? (Array.isArray(opts.host) ? opts.host : [opts.host]) : [],
                path: opts?.path || '/',
            };
        }

        if (proxy.tls || proxy.sni || proxy.servername) {
            outbound.tls = {
                enabled: true,
                server_name: proxy.servername ?? proxy.sni ?? server,
                insecure: proxy['skip-cert-verify'] === true || proxy.skipCertVerify === true,
            };
            if (proxy.alpn)
                outbound.tls.alpn = Array.isArray(proxy.alpn) ? proxy.alpn : [proxy.alpn];
        }
        return outbound;
    }

    if (type === 'vless') {
        const outbound = {
            tag,
            type: 'vless',
            server,
            server_port: serverPort,
            uuid: proxy.uuid || '',
        };
        if (proxy.flow) outbound.flow = proxy.flow;

        const network = proxy.network || '';
        if (network === 'ws') {
            const wsOpts = proxy['ws-opts'] || proxy.wsOpts;
            outbound.transport = {
                type: 'ws',
                path: wsOpts?.path || '/',
                headers: wsOpts?.headers || {},
            };
        } else if (network === 'grpc') {
            const grpcOpts = proxy['grpc-opts'] || proxy.grpcOpts;
            outbound.transport = {
                type: 'grpc',
                service_name: grpcOpts?.['grpc-service-name'] || grpcOpts?.serviceName || 'grpc',
            };
        } else if (network === 'httpupgrade') {
            const httpupgradeOpts = proxy['httpupgrade-opts'] || proxy.httpupgradeOpts;
            outbound.transport = {
                type: 'httpupgrade',
                path: httpupgradeOpts?.path || '/',
                host: httpupgradeOpts?.host || '',
            };
        }

        if (proxy.tls || proxy.sni || proxy.servername) {
            outbound.tls = {
                enabled: true,
                server_name: proxy.servername ?? proxy.sni ?? server,
                insecure: proxy['skip-cert-verify'] === true || proxy.skipCertVerify === true,
            };

            const fingerprint = proxy['client-fingerprint'] || proxy.clientFingerprint || proxy.fp;
            if (fingerprint) {
                outbound.tls.utls = {
                    enabled: true,
                    fingerprint: fingerprint,
                };
            }

            const realityOpts = proxy['reality-opts'] || proxy.realityOpts;
            if (realityOpts) {
                outbound.tls.reality = {
                    enabled: true,
                    public_key: realityOpts['public-key'] || realityOpts.publicKey || '',
                    short_id: realityOpts['short-id'] || realityOpts.shortId || '',
                };
                if (realityOpts['spider-x'] || realityOpts.spiderX) {
                    outbound.tls.reality.spider_x = realityOpts['spider-x'] || realityOpts.spiderX;
                }
            }
        }
        return outbound;
    }

    if (type === 'hysteria2' || type === 'hy2') {
        return {
            tag,
            type: 'hysteria2',
            server,
            server_port: serverPort,
            password: proxy.password || '',
            tls: {
                enabled: true,
                server_name: proxy.servername ?? proxy.sni ?? server,
                insecure: proxy['skip-cert-verify'] === true || proxy.skipCertVerify === true,
            },
        };
    }

    if (type === 'tuic') {
        const outbound = {
            tag,
            type: 'tuic',
            server,
            server_port: serverPort,
            uuid: proxy.uuid || '',
            password: proxy.password || '',
            tls: {
                enabled: true,
                server_name: proxy.servername ?? proxy.sni ?? server,
                insecure: proxy['skip-cert-verify'] === true || proxy.skipCertVerify === true,
            },
        };
        if (proxy.alpn) outbound.tls.alpn = Array.isArray(proxy.alpn) ? proxy.alpn : [proxy.alpn];
        const congestionControl =
            proxy['congestion-control'] || proxy['congestion-controller'] || proxy.congestion;
        if (congestionControl) outbound.congestion_control = congestionControl;
        // sing-box TUIC schema has no udp_relay_mode field.
        if (proxy['udp-over-stream'] !== undefined)
            outbound.udp_over_stream = Boolean(proxy['udp-over-stream']);
        if (proxy['zero-rtt-handshake'] !== undefined || proxy['reduce-rtt'] !== undefined) {
            outbound.zero_rtt_handshake = Boolean(
                proxy['zero-rtt-handshake'] ?? proxy['reduce-rtt']
            );
        }
        if (proxy.heartbeat) outbound.heartbeat = String(proxy.heartbeat);
        if (proxy.network) outbound.network = proxy.network;
        return outbound;
    }

    if (type === 'wireguard') {
        return {
            tag,
            type: 'wireguard',
            server,
            server_port: serverPort,
            local_address: Array.isArray(proxy.ip) ? proxy.ip : proxy.ip ? [proxy.ip] : [],
            private_key: proxy['private-key'] || '',
            peer_public_key: proxy['public-key'] || '',
            pre_shared_key: proxy['preshared-key'] || '',
        };
    }

    return null;
}

function mapGroupType(type) {
    const normalized = String(type || '').toLowerCase();
    if (normalized === 'select') return 'selector';
    if (normalized === 'url-test') return 'urltest';
    if (normalized === 'load-balance') return 'selector';
    return 'selector';
}

function buildGroupOutbounds(groups) {
    return groups.map((group) => {
        const mappedType = mapGroupType(group.type);
        const rawMembers = Array.isArray(group.members) ? group.members.filter(Boolean) : [];
        const outbound = {
            tag: sanitizeTag(group.name),
            type: mappedType,
            outbounds: ['urltest'].includes(mappedType)
                ? rawMembers.filter(
                      (member) =>
                          !['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS'].includes(
                              String(member).toUpperCase()
                          )
                  )
                : rawMembers,
        };

        if (mappedType === 'urltest') {
            outbound.url = group.options?.url || 'http://www.gstatic.com/generate_204';
            outbound.interval = `${group.options?.interval || 300}s`;
        }

        if (outbound.outbounds.length > 0) {
            outbound.default = outbound.outbounds[0];
        }

        return outbound;
    });
}

function toSingboxRuleSetUrl(rawUrl) {
    let url = pinRemoteRuleUrl(rawUrl);
    // 将 MetaCubeX .mrs 规则自动映射为 Sing-Box 专用的 @sing .srs 二进制规则集（国内 fastly.jsdelivr.net 直连）
    if (/metacubex\/meta-rules-dat/i.test(url)) {
        url = url
            .replace(/https?:\/\/[^/]+\/gh\/MetaCubeX\/meta-rules-dat@meta\//i, 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/')
            .replace(/https?:\/\/raw\.githubusercontent\.com\/MetaCubeX\/meta-rules-dat\/meta\//i, 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/')
            .replace(/\.mrs$/i, '.srs');
    }
    return url;
}

function mapRuleToSingbox(rule, ruleSetTagMap) {
    const type = String(rule.type || '').toLowerCase();
    if (type === 'rule-set') {
        const tag = ruleSetTagMap.get(rule.value);
        if (!tag) return null;
        return {
            rule_set: [tag],
            outbound: rule.policy,
        };
    }
    if (type === 'geoip') {
        const value = String(rule.value || 'cn').toLowerCase();
        return {
            rule_set: [`geoip-${value}`],
            outbound: rule.policy,
        };
    }
    if (type === 'geosite') {
        const value = String(rule.value || 'cn').toLowerCase();
        return {
            rule_set: [`geosite-${value}`],
            outbound: rule.policy,
        };
    }
    if (type === 'match' || type === 'final') {
        return {
            outbound: rule.policy,
        };
    }
    if (type === 'domain') {
        return {
            domain: [rule.value],
            outbound: rule.policy,
        };
    }
    if (type === 'domain-suffix') {
        return {
            domain_suffix: [rule.value],
            outbound: rule.policy,
        };
    }
    if (type === 'domain-keyword') {
        return {
            domain_keyword: [rule.value],
            outbound: rule.policy,
        };
    }
    if (type === 'ip-cidr' || type === 'ip-cidr6') {
        return {
            ip_cidr: [rule.value],
            outbound: rule.policy,
        };
    }
    if (type === 'process-name') {
        return {
            process_name: [rule.value],
            outbound: rule.policy,
        };
    }
    return null;
}

function detectRuleSetFormat(url) {
    const raw = String(url || '')
        .trim()
        .toLowerCase();
    if (!raw) return 'source';
    return raw.endsWith('.srs') ? 'binary' : 'source';
}

function buildRuleSets(rules, downloadDetour) {
    const remoteRuleSets = [];
    const ruleSetTagMap = new Map();
    const seenTags = new Set();
    let counter = 0;

    rules.forEach((rule) => {
        if (String(rule.type || '').toLowerCase() !== 'rule-set') return;
        if (!rule.value || !/^https?:\/\//i.test(rule.value)) return;
        if (ruleSetTagMap.has(rule.value)) return;

        const convertedUrl = toSingboxRuleSetUrl(rule.value);
        let hint = 'rs';
        try {
            const file = new URL(convertedUrl).pathname.split('/').pop() || '';
            hint = file.replace(/\.(srs|json|mrs|yaml|yml|list|txt)$/i, '').replace(/[^a-zA-Z0-9_-]/g, '_') || 'rs';
        } catch {}
        const tag = `${hint}_${counter++}`;
        ruleSetTagMap.set(rule.value, tag);
        if (!seenTags.has(tag)) {
            seenTags.add(tag);
            remoteRuleSets.push({
                tag,
                type: 'remote',
                format: detectRuleSetFormat(convertedUrl),
                url: convertedUrl,
                update_interval: '24h',
                download_detour: /jsdelivr\.net/i.test(convertedUrl) ? 'DIRECT' : downloadDetour,
            });
        }
    });

    const implicitRuleSets = [];
    rules.forEach((rule) => {
        const type = String(rule.type || '').toLowerCase();
        if (type === 'geoip' || type === 'geosite') {
            const value = String(rule.value || 'cn').toLowerCase();
            const tag = `${type}-${value}`;
            if (!seenTags.has(tag)) {
                seenTags.add(tag);
                implicitRuleSets.push({
                    tag,
                    type: 'remote',
                    format: 'binary',
                    url:
                        type === 'geoip'
                            ? `https://fastly.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/geoip-${value}.srs`
                            : `https://fastly.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-${value}.srs`,
                    update_interval: '24h',
                    download_detour: 'DIRECT',
                });
            }
        }
    });

    return { ruleSets: [...remoteRuleSets, ...implicitRuleSets], ruleSetTagMap };
}

export function renderSingboxFromTemplateModel(model, options = {}) {
    const normalizedModel = normalizeUnifiedTemplateModel(model);
    const nodeList = typeof options.nodeList === 'string' ? options.nodeList : '';
    const proxyUrls = nodeList
        .split('\n')
        .map((line) => line.trim())
        .filter((line) => line && !line.startsWith('#'));
    const proxies =
        Array.isArray(normalizedModel.proxies) && normalizedModel.proxies.length > 0
            ? normalizedModel.proxies
            : urlsToClashProxies(proxyUrls);
    const proxyOutbounds = proxies.map(buildOutbound).filter(Boolean);
    const groupOutbounds = buildGroupOutbounds(
        normalizedModel.groups.filter((g) => Array.isArray(g.members) && g.members.length > 0)
    );
    const hasDnsProxyGroup = groupOutbounds.some((g) => g.tag === DNS_PROXY_GROUP);
    const effectiveDnsProxyGroup = hasDnsProxyGroup
        ? DNS_PROXY_GROUP
        : groupOutbounds.find((g) => /节点选择|选择|proxy/i.test(g.tag))?.tag || 'DIRECT';

    const dnsRuleSet = { ...getSingboxDnsRuleSet(), download_detour: 'DIRECT' };
    const { ruleSets, ruleSetTagMap } = buildRuleSets(normalizedModel.rules, effectiveDnsProxyGroup);
    const ruleSetObjects = [
        dnsRuleSet,
        ...ruleSets.filter((ruleSet) => ruleSet.tag !== SINGBOX_CN_RULE_SET),
    ];
    const routeRules = normalizedModel.rules
        .map((rule) => mapRuleToSingbox(rule, ruleSetTagMap))
        .filter(Boolean);
    const defaultOutbound =
        normalizedModel.groups.find((group) => group.name !== DNS_PROXY_GROUP)?.name || 'DIRECT';
    const dnsConfig = buildSingboxDnsConfig(normalizedModel.settings?.customDnsOverride, {
        mode: normalizedModel.settings?.dnsMode,
        proxyGroup: effectiveDnsProxyGroup,
    });

    const config = {
        log: { level: 'info' },
        dns: dnsConfig,
        inbounds: [
            {
                type: 'tun',
                tag: 'tun-in',
                address: ['172.19.0.1/30'],
                auto_route: true,
                strict_route: true,
                stack: 'mixed',
            },
        ],
        outbounds: [
            { tag: 'DIRECT', type: 'direct' },
            { tag: 'REJECT', type: 'block' },
            ...proxyOutbounds,
            ...groupOutbounds,
        ],
        route: {
            auto_detect_interface: true,
            default_domain_resolver: dnsConfig.servers[0]?.tag || 'dns-cn-1',
            final: defaultOutbound,
            rule_set: ruleSetObjects,
            rules: routeRules,
        },
    };

    return JSON.stringify(config, null, 2) + '\n';
}
