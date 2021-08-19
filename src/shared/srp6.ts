import { createHash, Hash, randomBytes } from 'crypto';
import { BigInteger } from 'jsbn';

export interface SRP6Params {
  g: BigInteger;
  N: BigInteger;
  algorithm: string;
}

const params: SRP6Params = {
  g: new BigInteger('07', 16),
  N: new BigInteger('894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7', 16), // prettier-ignore
  algorithm: 'sha1',
};

export const bnToHex = (bn): string => {
  let hex = BigInt(bn).toString(16);
  if (hex.length % 2) {
    hex = '0' + hex;
  }
  return hex;
};

export const generateSalt = async (length = 32) => {
  return randomBytes(length);
};

const createSHA = (type: string): Hash => {
  switch (type) {
    case 'sha1':
      return createHash('sha1');
    case 'sha256':
      return createHash('sha256');
    case 'sha512':
      return createHash('sha512');
    default:
      throw new Error('Invalid hash algorithm');
  }
};

const sha = (...values: (Buffer | string)[]): Buffer => {
  const hash = createSHA(params.algorithm);

  values.forEach((value) => hash.update(value));

  return hash.digest();
};

const computePrivateKey = async (
  username: string,
  password: string,
  salt: Buffer,
): Promise<BigInteger> => {
  const h1 = sha(`${username}:${password}`.toUpperCase());
  const h2 = sha(salt, h1).reverse();

  return new BigInteger(h2.toString('hex'), 16);
};

export const computeVerifier = async (
  username: string,
  password: string,
  salt: Buffer,
): Promise<Buffer> => {
  const hash = await computePrivateKey(username, password, salt);
  const verifier = params.g.modPow(hash, params.N);

  return Buffer.from(bnToHex(verifier), 'hex').reverse();
};

export const verifyLogin = async (
  username: string,
  password: string,
  salt: Buffer,
  verifier: Buffer,
): Promise<boolean> => {
  const genVerifier = await computeVerifier(username, password, salt);
  return genVerifier.equals(verifier);
};
