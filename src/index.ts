import sodium from 'libsodium-wrappers-sumo';
import axios, { AxiosResponse } from 'axios';
import { v4 as uuidv4 } from 'uuid';


const DEFAULT_PROTOCOL = 'https';
const DEFAULT_HOST = 'iam.mtaylor.io';
const DEFAULT_PORT = null;


export const enum LoginStatus {
  PENDING = 'pending',
  GRANTED = 'granted',
  DENIED = 'denied',
}


export const LoginStatusValues = [
  LoginStatus.PENDING,
  LoginStatus.GRANTED,
  LoginStatus.DENIED,
];


export const enum Action {
  READ = 'Read',
  WRITE = 'Write',
}


export const PolicyActions = [Action.READ, Action.WRITE];


export const enum Effect {
  ALLOW = 'Allow',
  DENY = 'Deny',
}


export const PolicyEffects = [Effect.ALLOW, Effect.DENY];


export const enum SortOrder {
  ASC = 'asc',
  DESC = 'desc',
}


export const SortOrders = [SortOrder.ASC, SortOrder.DESC];


export const enum SortUsersBy {
  SORT_USERS_BY_ID = 'id',
  SORT_USERS_BY_NAME = 'name',
  SORT_USERS_BY_EMAIL = 'email',
}


export const SortUsersByValues = [
  SortUsersBy.SORT_USERS_BY_ID,
  SortUsersBy.SORT_USERS_BY_NAME,
  SortUsersBy.SORT_USERS_BY_EMAIL,
];


export const enum SortGroupsBy {
  SORT_GROUPS_BY_ID = 'id',
  SORT_GROUPS_BY_NAME = 'name',
}


export const SortGroupsByValues = [
  SortGroupsBy.SORT_GROUPS_BY_ID,
  SortGroupsBy.SORT_GROUPS_BY_NAME,
];


export const enum SortPoliciesBy {
  SORT_POLICIES_BY_ID = 'id',
  SORT_POLICIES_BY_NAME = 'name',
}


export const SortPoliciesByValues = [
  SortPoliciesBy.SORT_POLICIES_BY_ID,
  SortPoliciesBy.SORT_POLICIES_BY_NAME,
];


export interface UserIdentity {
  id: string,
  name?: string,
  email?: string,
}


export interface GroupIdentity {
  id: string,
  name?: string,
}


export interface PolicyIdentity {
  id: string,
  name?: string,
}


export interface Rule {
  action: Action,
  effect: Effect,
  resource: string,
}


export interface Policy {
  id: string,
  name: string | undefined,
  hostname: string,
  statements: Rule[],
}


export interface PolicySpec {
  name?: string,
  hostname: string,
  statements: Rule[],
}


export interface UserPublicKey {
  description: string,
  key: string,
}


export interface LoginResponse {
  id: string,
  ip: string,
  user: string,
  publicKey: UserPublicKey,
  session: CreateSession | string,
  status: LoginStatus,
}


export interface User {
  id: string,
  name: string | null,
  email: string | null,
  groups: GroupIdentity[],
  policies: PolicyIdentity[],
  publicKeys: UserPublicKey[],
}


export interface UserUpdate {
  name?: string,
  email?: string,
}


export interface Group {
  id: string,
  name: string | null,
  users: UserIdentity[],
  policies: PolicyIdentity[],
}


export interface Session {
  id: string,
  user: string,
  address: string,
  expiration: string,
}


export interface CreateSession {
  id: string,
  user: string,
  token: string,
  address: string,
  expiration: string,
}


export interface UserPublicKeysResponse {
  items: UserPublicKey[],
  limit: number,
  offset: number,
  total: number,
}


export interface LoginResponses {
  items: LoginResponse[],
  limit: number,
  offset: number,
  total: number,
}


export interface UsersResponse {
  items: UserIdentity[],
  limit: number,
  offset: number,
  total: number,
}


export interface GroupsResponse {
  items: GroupIdentity[],
  limit: number,
  offset: number,
  total: number,
}


export interface PoliciesResponse {
  items: PolicyIdentity[],
  limit: number,
  offset: number,
  total: number,
}


export interface SessionsResponse {
  items: Session[],
  limit: number,
  offset: number,
  total: number,
}


export function rule(effect: Effect, action: Action, resource: string): Rule {
  return { action, effect, resource };
}


export class Principal {
  public readonly user: User;
  public readonly publicKey: Uint8Array;
  public readonly privateKey: Uint8Array;
  public readonly publicKeyBase64: string;
  public readonly privateKeyBase64: string;

  constructor(user: User, privateKey: Uint8Array, publicKey: Uint8Array | null = null) {
    this.user = user;
    this.privateKey = privateKey;
    this.publicKey = publicKey ?
      publicKey : sodium.crypto_sign_ed25519_sk_to_pk(privateKey);
    this.publicKeyBase64 = sodium.to_base64(
      this.publicKey, sodium.base64_variants.URLSAFE);
    this.privateKeyBase64 = sodium.to_base64(
      this.privateKey, sodium.base64_variants.URLSAFE);
  }
}


export default class IAM {
  public protocol: string;
  public host: string;
  public port: number | null;

  public userId: string | null = null;
  public secretKey: Uint8Array | null = null;
  public publicKey: Uint8Array | null = null;

  public loginId: string | null = null;

  public sessionId: string | null = null;
  public sessionToken: string | null = null;
  public sessionExpires: string | null = null;
  public sessionAddress: string | null = null;
  public sessionUserId: string | null = null;

  public user: UserClient;
  public users: UsersClient;
  public logins: LoginsClient;
  public groups: GroupsClient;
  public policies: PoliciesClient;
  public sessions: SessionsClient;
  public publicKeys: PublicKeysClient;

  constructor(
    protocol: string = DEFAULT_PROTOCOL,
    host: string = DEFAULT_HOST,
    port: number | null = DEFAULT_PORT,
  ) {
    this.protocol = protocol.endsWith(':') ? protocol.slice(0, -1) : protocol;
    this.host = host;
    this.port = port;

    this.user = new UserClient(this);
    this.users = new UsersClient(this);
    this.logins = new LoginsClient(this);
    this.groups = new GroupsClient(this);
    this.policies = new PoliciesClient(this);
    this.sessions = new SessionsClient(this);
    this.publicKeys = new PublicKeysClient(this);
  }

  async login(
    userId: string,
    secretKey: Uint8Array | string | null = null,
  ): Promise<void> {
    if (secretKey === null || secretKey === '') {
      return await this.loginRequest(userId);
    } else {
      return await this.loginWithSecretKey(userId, secretKey);
    }
  }

  async loginRequest(
    userId: string,
    description: string = 'default',
  ): Promise<void> {
    await sodium.ready;

    if (!this.loginId) {
      this.loginId = uuidv4();
    }

    this.userId = userId;
    if (!this.publicKey) {
      const keypair = sodium.crypto_sign_keypair();
      this.publicKey = keypair.publicKey;
      this.secretKey = keypair.privateKey;
    }

    const id = this.loginId;
    const publicKey = {
      description,
      key: sodium.to_base64(this.publicKey, sodium.base64_variants.URLSAFE),
    };

    const loginRequest = { id, publicKey, user: userId };
    const response = await axios.post(this.url('/login'), loginRequest);

    if (response.data.status === 'granted') {
      this.sessionId = response.data.session.id;
      this.sessionToken = response.data.session.token;
      this.sessionExpires = response.data.session.expiration;
      this.sessionAddress = response.data.session.address;
      this.sessionUserId = response.data.session.user;
    }
  }

  async loginWithSecretKey(
    userId: string, secretKey: Uint8Array | string
  ): Promise<void> {
    await sodium.ready;
    const secretKeyBytes = typeof secretKey === 'string' ?
      sodium.from_base64(secretKey, sodium.base64_variants.URLSAFE) : secretKey;

    this.userId = userId;
    this.secretKey = secretKeyBytes;
    this.publicKey = sodium.crypto_sign_ed25519_sk_to_pk(secretKeyBytes);

    const response = await this.request('POST', '/user/sessions');
    this.sessionId = response.data.id;
    this.sessionToken = response.data.token;
    this.sessionExpires = response.data.expiration;
    this.sessionAddress = response.data.address;
    this.sessionUserId = response.data.user;
  }

  async logout(): Promise<void> {
    await this.request('DELETE', `/user/sessions/${this.sessionId}`);
    this.userId = null;
    this.secretKey = null;
    this.publicKey = null;
    this.sessionId = null;
    this.sessionToken = null;
    this.sessionExpires = null;
    this.sessionAddress = null;
    this.sessionUserId = null;
  }

  async refresh(
    userId: string | null = null,
    secretKey: Uint8Array | string | null = null,
    sessionId: string | null = null,
    sessionToken: string | null = null,
  ): Promise<void> {
    await sodium.ready;
    this.userId = userId ? userId : this.userId
    this.secretKey = secretKey ? typeof secretKey === 'string' ?
      sodium.from_base64(secretKey, sodium.base64_variants.URLSAFE) :
      secretKey : this.secretKey
    this.publicKey = this.secretKey ?
      sodium.crypto_sign_ed25519_sk_to_pk(this.secretKey) : null
    this.sessionId = sessionId ? sessionId : this.sessionId
    this.sessionToken = sessionToken ? sessionToken : this.sessionToken

    if (this.sessionId && this.sessionToken) {
      const refreshUrl = `/user/sessions/${this.sessionId}/refresh`
      const response = await this.request('POST', refreshUrl);
      this.sessionExpires = response.data.expiration;
      this.sessionAddress = response.data.address;
      this.sessionUserId = response.data.user;
    }
  }

  async request(
    method: string,
    path: string,
    query: string | null = null,
    body: any | null = null,
  ): Promise<AxiosResponse> {
    await sodium.ready;
    const url = this.url(path, query);
    const requestId = uuidv4();
    const publicKey = sodium.to_base64(this.publicKey, sodium.base64_variants.URLSAFE);
    const signature = this.signature(requestId, method, path, query);

    const headers = {
      'Authorization': `Signature ${signature}`,
      'X-MTaylor-IO-User-ID': this.userId,
      'X-MTaylor-IO-Request-ID': requestId,
      'X-MTaylor-IO-Public-Key': publicKey,
    };

    if (this.sessionToken) {
      headers['X-MTaylor-IO-Session-Token'] = this.sessionToken;
    }

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
      requestStringToSign(method, this.host, path, query, requestId, this.sessionToken),
      this.secretKey,
    ), sodium.base64_variants.URLSAFE);
  }

  url(path: string, query: string | null = null): string {
    return [
      this.protocol,
      '://',
      this.host,
      this.port ? `:${this.port}` : '',
      path,
      query ? query : '',
    ].join('');
  }
}


export class UserClient {
  private iam: IAM;

  constructor(iam: IAM) {
    this.iam = iam;
  }

  async getUser(): Promise<User> {
    const response = await this.iam.request('GET', '/user');
    return response.data;
  }

  async updateUser(update: UserUpdate): Promise<User> {
    const response = await this.iam.request('PUT', '/user', null, update);
    return response.data;
  }

  async deleteUser(): Promise<void> {
    await this.iam.request('DELETE', '/user');
  }

  async attachPolicy(policyId: string): Promise<void> {
    await this.iam.request('POST', `/user/policies/${policyId}`);
  }

  async detachPolicy(policyId: string): Promise<void> {
    await this.iam.request('DELETE', `/user/policies/${policyId}`);
  }
}


export class UsersClient {
  private iam: IAM;

  constructor(iam: IAM) {
    this.iam = iam;
  }

  async createUser(
    name: string | null = null,
    email: string | null = null,
    groups: string[] = [],
    policies: string[] = [],
  ): Promise<Principal> {
    const keypair = sodium.crypto_sign_keypair();

    const publicKeys = [{
      'description': 'default',
      'key': sodium.to_base64(keypair.publicKey, sodium.base64_variants.URLSAFE),
    }]

    const id = uuidv4();
    const user = { id, name, email, groups, policies, publicKeys };

    const response = await this.iam.request('POST', '/users', null, user);

    return new Principal(response.data, keypair.privateKey, keypair.publicKey);
  }

  async updateUser(id: string, update: UserUpdate): Promise<User> {
    const url = `/users/${id}`;
    const response = await this.iam.request('PUT', url, null, update);
    return response.data;
  }

  async deleteUser(id: string): Promise<void> {
    await this.iam.request('DELETE', `/users/${id}`);
  }

  async getUser(id: string): Promise<User> {
    const response = await this.iam.request('GET', `/users/${id}`);
    return response.data;
  }

  async listUsers(
    search: string | null = null,
    sortBy: SortUsersBy | null = null,
    sortOrder: SortOrder | null = null,
    offset: number | null = null,
    limit: number | null = null,
  ): Promise<UsersResponse> {
    const params = new URLSearchParams();

    if (search) {
      params.append('search', search);
    }

    if (sortBy) {
      params.append('sort', sortBy);
    }

    if (sortOrder) {
      params.append('order', sortOrder);
    }

    if (offset) {
      params.append('offset', offset.toString());
    }

    if (limit) {
      params.append('limit', limit.toString());
    }

    const queryParams = params.toString();
    const query = queryParams === '' ? null : `?${queryParams}`;
    const response = await this.iam.request('GET', '/users', query);

    return response.data;
  }

  async attachPolicy(userId: string, policyId: string): Promise<void> {
    await this.iam.request('POST', `/users/${userId}/policies/${policyId}`);
  }

  async detachPolicy(userId: string, policyId: string): Promise<void> {
    await this.iam.request('DELETE', `/users/${userId}/policies/${policyId}`);
  }
}


export class LoginsClient {
  private iam: IAM;

  constructor(iam: IAM) {
    this.iam = iam;
  }

  async getLogin(id: string, userId: string | null = null): Promise<LoginResponse> {
    const path = userId ? `/users/${userId}/login-requests/${id}` :
      `/user/login-requests/${id}`;
    const response = await this.iam.request('GET', path);
    return response.data;
  }

  async listLogins(userId: string | null = null): Promise<LoginResponses> {
    const path = userId ? `/users/${userId}/login-requests` : `/user/login-requests`;
    const response = await this.iam.request('GET', path);
    return response.data;
  }

  async denyLogin(id: string, userId: string | null = null): Promise<LoginResponse> {
    const path = userId ? `/users/${userId}/login-requests/${id}/deny` :
      `/user/login-requests/${id}/deny`;
    const response = await this.iam.request('POST', path);
    return response.data;
  }

  async grantLogin(id: string, userId: string | null = null): Promise<LoginResponse> {
    const path = userId ? `/users/${userId}/login-requests/${id}/grant` :
      `/user/login-requests/${id}/grant`;
    const response = await this.iam.request('POST', path);
    return response.data;
  }

  async deleteLogin(id: string, userId: string | null = null): Promise<void> {
    const path = userId ? `/users/${userId}/login-requests/${id}` :
      `/user/login-requests/${id}`;
    await this.iam.request('DELETE', path);
  }
}


export class PublicKeysClient {
  private iam: IAM;

  constructor(iam: IAM) {
    this.iam = iam;
  }

  async createPublicKey(
    description: string,
    key: string,
    userId: string | null = null,
  ): Promise<UserPublicKey> {
    const publicKey = { description, key };
    const path = userId ? `/users/${userId}/public-keys` : '/user/public-keys';
    const response = await this.iam.request('POST', path, null, publicKey);
    return response.data;
  }

  async deletePublicKey(
    id: string,
    userId: string | null = null,
  ): Promise<UserPublicKey> {
    const path = userId ? `/users/${userId}/public-keys/${id}` :
      `/user/public-keys/${id}`;
    const response = await this.iam.request('DELETE', path);
    return response.data;
  }

  async listPublicKeys(
    userId: string | null = null,
  ): Promise<UserPublicKeysResponse> {
    const path = userId ? `/users/${userId}/public-keys` : '/user/public-keys';
    const response = await this.iam.request('GET', path);
    return response.data;
  }

  async getPublicKey(
    id: string,
    userId: string | null = null,
  ): Promise<UserPublicKey> {
    const path = userId ? `/users/${userId}/public-keys/${id}` :
      `/user/public-keys/${id}`;
    const response = await this.iam.request('GET', path);
    return response.data;
  }
}


export class GroupsClient {
  private iam: IAM;

  constructor(iam: IAM) {
    this.iam = iam;
  }

  async createGroup(
    name: string | null = null,
    users: string[] = [],
    policies: string[] = [],
  ): Promise<Group> {
    const id = uuidv4();
    const group = { id, name, users, policies };
    const response = await this.iam.request('POST', '/groups', null, group);
    return response.data;
  }

  async deleteGroup(id: string): Promise<void> {
    await this.iam.request('DELETE', `/groups/${id}`);
  }

  async getGroup(id: string): Promise<Group> {
    const response = await this.iam.request('GET', `/groups/${id}`);
    return response.data;
  }

  async listGroups(
    search: string | null = null,
    sortBy: SortGroupsBy | null = null,
    sortOrder: SortOrder | null = null,
    offset: number | null = null,
    limit: number | null = null,
  ): Promise<GroupsResponse> {
    const params = new URLSearchParams();

    if (search) {
      params.append('search', search);
    }

    if (sortBy) {
      params.append('sort', sortBy);
    }

    if (sortOrder) {
      params.append('order', sortOrder);
    }

    if (offset !== null) {
      params.append('offset', offset.toString());
    }

    if (limit !== null) {
      params.append('limit', limit.toString());
    }

    const queryParams = params.toString();
    const query = queryParams === '' ? null : `?${queryParams}`;

    const response = await this.iam.request('GET', '/groups', query)

    return response.data;
  }

  async attachPolicy(groupId: string, policyId: string): Promise<void> {
    await this.iam.request('POST', `/groups/${groupId}/policies/${policyId}`);
  }

  async detachPolicy(groupId: string, policyId: string): Promise<void> {
    await this.iam.request('DELETE', `/groups/${groupId}/policies/${policyId}`);
  }

  async addMember(groupId: string, userId: string): Promise<void> {
    await this.iam.request('POST', `/groups/${groupId}/members/${userId}`);
  }

  async removeMember(groupId: string, userId: string): Promise<void> {
    await this.iam.request('DELETE', `/groups/${groupId}/members/${userId}`);
  }
}


export class PoliciesClient {
  private iam: IAM;

  constructor(iam: IAM) {
    this.iam = iam;
  }

  async createPolicy(spec: PolicySpec): Promise<Policy> {
    const id = uuidv4();
    const { hostname, statements } = spec;
    const policy = { id, hostname, statements };

    if (spec.name) {
      policy['name'] = spec.name;
    }

    const response = await this.iam.request('POST', '/policies', null, policy);
    return response.data;
  }

  async deletePolicy(id: string): Promise<void> {
    await this.iam.request('DELETE', `/policies/${id}`);
  }

  async getPolicy(id: string): Promise<Policy> {
    const response = await this.iam.request('GET', `/policies/${id}`);
    return response.data;
  }

  async listPolicies(
    search: string | null = null,
    sortBy: SortPoliciesBy | null = null,
    sortOrder: SortOrder | null = null,
    offset: number | null = null,
    limit: number | null = null,
  ): Promise<PoliciesResponse> {
    const params = new URLSearchParams();

    if (search) {
      params.append('search', search);
    }

    if (sortBy) {
      params.append('sort', sortBy);
    }

    if (sortOrder) {
      params.append('order', sortOrder);
    }

    if (offset !== null) {
      params.append('offset', offset.toString());
    }

    if (limit !== null) {
      params.append('limit', limit.toString());
    }

    const queryParams = params.toString();
    const query = queryParams === '' ? null : `?${queryParams}`;
    const response = await this.iam.request('GET', '/policies', query)

    return response.data;
  }
}


export class SessionsClient {
  private iam: IAM;

  constructor(iam: IAM) {
    this.iam = iam;
  }

  async createSession(
    userId: string | null = null,
  ): Promise<CreateSession> {
    const path = userId ? `/users/${userId}/sessions` : '/user/sessions';
    const response = await this.iam.request('POST', path);
    return response.data;
  }

  async listSessions(
    userId: string | null = null,
    offset: number = 0,
    limit: number = 100,
  ): Promise<SessionsResponse> {
    const query = `?offset=${offset}&limit=${limit}`;
    const path = userId ? `/users/${userId}/sessions` : '/user/sessions';
    const response = await this.iam.request('GET', path, query);
    return response.data;
  }

  async getSession(
    id: string,
    userId: string | null = null,
  ): Promise<Session> {
    const path = userId ? `/users/${userId}/sessions/${id}` : `/user/sessions/${id}`;
    const response = await this.iam.request('GET', path);
    return response.data;
  }

  async deleteSession(
    id: string,
    userId: string | null = null,
  ): Promise<void> {
    const path = userId ? `/users/${userId}/sessions/${id}` : `/user/sessions/${id}`;
    await this.iam.request('DELETE', path);
  }

  async refreshSession(
    id: string,
    userId: string | null = null,
  ): Promise<void> {
    const path = userId ? `/users/${userId}/sessions/${id}/refresh` : `/user/sessions/${id}/refresh`;
    await this.iam.request('POST', path);
  }
}


function requestStringToSign(
  method: string,
  host: string,
  path: string,
  query: string | null,
  requestId: string | null,
  sessionToken: string | null,
): Uint8Array {
  const s = [
    method,
    host,
    path,
    query ? query : '',
    requestId,
  ]

  if (sessionToken) {
    s.push(sessionToken);
  }

  return sodium.from_string(s.join('\n'));
}
