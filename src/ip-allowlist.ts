import ipaddr from 'ipaddr.js';

export const API_KEY_CLIENT_IP_RESOLVER = Symbol('API_KEY_CLIENT_IP_RESOLVER');

export type ApiKeyClientIpResolver = (
  request: unknown,
) => string | undefined | Promise<string | undefined>;

export const defaultApiKeyClientIpResolver: ApiKeyClientIpResolver = (request) => {
  if (!request || typeof request !== 'object') {
    return undefined;
  }

  const ip = (request as Record<string, unknown>).ip;
  return typeof ip === 'string' && ip.trim() !== '' ? ip.trim() : undefined;
};

export function normalizeAllowedIpCidrs(entries: readonly string[] = []): string[] {
  return [...new Set(entries.map(normalizeAllowedIpCidr))];
}

export function isIpAllowed(
  clientIp: string | undefined,
  allowedIpCidrs: readonly string[],
): boolean {
  if (allowedIpCidrs.length === 0) {
    return true;
  }

  if (!clientIp) {
    return false;
  }

  let candidate: ipaddr.IPv4 | ipaddr.IPv6;
  try {
    candidate = ipaddr.process(clientIp.trim());
  } catch {
    return false;
  }

  return allowedIpCidrs.some((entry) => {
    try {
      const [network, prefixLength] = parseCidr(entry);
      return candidate.kind() === network.kind() && candidate.match(network, prefixLength);
    } catch {
      return false;
    }
  });
}

function normalizeAllowedIpCidr(entry: string): string {
  if (typeof entry !== 'string' || entry.trim() === '') {
    throw new Error('invalid IP allowlist entry: expected an IP address or CIDR');
  }

  try {
    const [address, prefixLength] = parseCidr(entry.trim());
    const normalized = `${address.toString()}/${prefixLength}`;
    const network =
      address.kind() === 'ipv4'
        ? ipaddr.IPv4.networkAddressFromCIDR(normalized)
        : ipaddr.IPv6.networkAddressFromCIDR(normalized);

    return `${network.toString()}/${prefixLength}`;
  } catch {
    throw new Error(`invalid IP allowlist entry: ${entry}`);
  }
}

function parseCidr(entry: string): [ipaddr.IPv4 | ipaddr.IPv6, number] {
  if (!entry.includes('/')) {
    const address = ipaddr.process(entry);
    return [address, address.kind() === 'ipv4' ? 32 : 128];
  }

  const [parsedAddress, parsedPrefixLength] = ipaddr.parseCIDR(entry);
  if (parsedAddress instanceof ipaddr.IPv6 && parsedAddress.isIPv4MappedAddress()) {
    if (parsedPrefixLength < 96) {
      throw new Error('IPv4-mapped IPv6 CIDR prefix must be at least 96');
    }

    return [parsedAddress.toIPv4Address(), parsedPrefixLength - 96];
  }

  return [parsedAddress, parsedPrefixLength];
}
