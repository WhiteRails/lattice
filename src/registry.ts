import { RegistryRecord, WhiteCertificate } from './types';
import { generateWhiteAddress } from './addressing';

export class WhiteRegistry {
  private records: Map<string, RegistryRecord> = new Map();

  /**
   * Registers a service or node in the registry.
   */
  register(params: {
    certificate: WhiteCertificate;
    certificate_chain: string[];
    accepted_capabilities: string[];
    protecting_gateways: string[];
  }): string {
    const address = generateWhiteAddress(params.certificate.public_key);

    const record: RegistryRecord = {
      address,
      public_key: params.certificate.public_key,
      certificate_chain: params.certificate_chain,
      issuer: params.certificate.issuer,
      is_revoked: false,
      accepted_capabilities: params.accepted_capabilities,
      protecting_gateways: params.protecting_gateways,
    };

    this.records.set(address, record);
    return address;
  }

  /**
   * Resolves a WhiteNet address to its registry record.
   */
  resolve(address: string): RegistryRecord | undefined {
    return this.records.get(address);
  }

  /**
   * Marks a record as revoked in the registry.
   */
  markRevoked(address: string) {
    const record = this.records.get(address);
    if (record) {
      record.is_revoked = true;
    }
  }
}
