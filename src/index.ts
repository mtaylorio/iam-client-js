import sodium from 'libsodium-wrappers-sumo';
import axios, { AxiosResponse } from 'axios';
import { v4 as uuidv4 } from 'uuid';


interface User {
  id: string,
  email: string | null,
  groups: string[],
  policies: string[],
  publicKeys: { description: string, key: string }[],
}


interface CreateUserResponse {
  keypair: { publicKey: Uint8Array, privateKey: Uint8Array },
  user: User,
}


export class Users {
  private iam: IAM;

  constructor(iam: IAM) {
    this.iam = iam;
  }

  async createUser(
    email: string | null = null,
    groups: string[] = [],
    policies: string[] = [],
  ): Promise<CreateUserResponse> {
    const keypair = sodium.crypto_sign_keypair();

    const publicKeys = [{
      'description': 'default',
      'key': sodium.to_base64(keypair.publicKey, sodium.base64_variants.ORIGINAL),
    }]

    const id = uuidv4();
    const user = { id, email, groups, policies, publicKeys };

    const response = await this.iam.request('POST', '/users', null, user);

    return {
      keypair,
      user: response.data,
    }
  }

  async getUser(id: string): Promise<User> {
    const response = await this.iam.request('GET', `/users/${id}`);
    return response.data;
  }

  async listUsers(offset: number = 0, limit: number = 100): Promise<User[]> {
    const query = `offset=${offset}&limit=${limit}`;
    const response = await this.iam.request('GET', '/users', query)
    return response.data;
  }
}


export default class IAM {
  private protocol: string;
  private host: string;
  private port: number | null;
  private userId: string;
  private secretKey: Uint8Array;
  private publicKey: Uint8Array;

  constructor(
    userId: string,
    secretKey: Uint8Array,
    protocol: string,
    host: string,
    port: number | null
  ) {
    this.protocol = protocol;
    this.host = host;
    this.port = port;
    this.userId = userId;
    this.secretKey = secretKey;
    this.publicKey = sodium.crypto_sign_ed25519_sk_to_pk(secretKey);
  }

  static async client(
    userId: string,
    secretKey: Uint8Array,
    protocol: string = 'https',
    host: string = 'iam.mtaylor.io',
    port: number | null = null,
  ): Promise<IAM> {
    await sodium.ready; // Wait for libsodium to be ready
    return new IAM(userId, secretKey, protocol, host, port);
  }

  async request(
    method: string,
    path: string,
    query: string | null = null,
    body: any | null = null,
  ): Promise<AxiosResponse> {
    const url = this.url(path);
    const requestId = uuidv4();
    const publicKey = sodium.to_base64(this.publicKey, sodium.base64_variants.ORIGINAL);
    const signature = this.signature(requestId, method, path, query);

    const headers = {
      'Authorization': `Signature ${signature}`,
      'X-MTaylor-IO-User-ID': this.userId,
      'X-MTaylor-IO-Request-ID': requestId,
      'X-MTaylor-IO-Public-Key': publicKey,
    };

    const response = await axios.request({
      method,
      url,
      headers,
      data: body,
    });

    return response;
  }

  signature(
    requestId: string,
    method: string,
    path: string,
    query: string | null = null,
  ): string {
    return sodium.to_base64(sodium.crypto_sign_detached(
      requestStringToSign(method, this.host, path, query, requestId),
      this.secretKey,
    ), sodium.base64_variants.ORIGINAL);
  }

  url(path: string): string {
    return [
      this.protocol,
      '://',
      this.host,
      this.port ? `:${this.port}` : '',
      path,
    ].join('');
  }
}


function requestStringToSign(
  method: string,
  host: string,
  path: string,
  query: string | null,
  requestId: string | null,
): Uint8Array {
  return sodium.from_string([
    method,
    host,
    path,
    query ? query : 'foo',
    requestId,
  ].join('\n'));
}
