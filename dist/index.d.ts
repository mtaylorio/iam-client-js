import { AxiosResponse } from 'axios';
export declare const enum LoginStatus {
    PENDING = "pending",
    GRANTED = "granted",
    DENIED = "denied"
}
export declare const LoginStatusValues: LoginStatus[];
export declare const enum Action {
    READ = "Read",
    WRITE = "Write"
}
export declare const PolicyActions: Action[];
export declare const enum Effect {
    ALLOW = "Allow",
    DENY = "Deny"
}
export declare const PolicyEffects: Effect[];
export declare const enum SortOrder {
    ASC = "asc",
    DESC = "desc"
}
export declare const SortOrders: SortOrder[];
export declare const enum SortUsersBy {
    SORT_USERS_BY_ID = "id",
    SORT_USERS_BY_NAME = "name",
    SORT_USERS_BY_EMAIL = "email"
}
export declare const SortUsersByValues: SortUsersBy[];
export declare const enum SortGroupsBy {
    SORT_GROUPS_BY_ID = "id",
    SORT_GROUPS_BY_NAME = "name"
}
export declare const SortGroupsByValues: SortGroupsBy[];
export declare const enum SortPoliciesBy {
    SORT_POLICIES_BY_ID = "id",
    SORT_POLICIES_BY_NAME = "name"
}
export declare const SortPoliciesByValues: SortPoliciesBy[];
export declare const enum SortSessionsBy {
    SORT_SESSIONS_BY_ID = "id",
    SORT_SESSIONS_BY_USER_ID = "user_id",
    SORT_SESSIONS_BY_ADDRESS = "address",
    SORT_SESSIONS_BY_EXPIRATION = "expiration"
}
export declare const SortSessionsByValues: SortSessionsBy[];
export interface UserIdentity {
    id: string;
    name?: string;
    email?: string;
}
export interface GroupIdentity {
    id: string;
    name?: string;
}
export interface PolicyIdentity {
    id: string;
    name?: string;
}
export interface Rule {
    action: Action;
    effect: Effect;
    resource: string;
}
export interface Policy {
    id: string;
    name: string | undefined;
    hostname: string;
    statements: Rule[];
}
export interface PolicySpec {
    name?: string;
    hostname: string;
    statements: Rule[];
}
export interface UserPublicKey {
    description: string;
    key: string;
}
export interface LoginResponse {
    id: string;
    ip: string;
    user: string;
    publicKey: UserPublicKey;
    session: CreateSession | string;
    status: LoginStatus;
}
export interface User {
    id: string;
    name?: string;
    email?: string;
    groups: GroupIdentity[];
    policies: PolicyIdentity[];
    publicKeys: UserPublicKey[];
}
export interface UserUpdate {
    name?: string;
    email?: string;
}
export interface Group {
    id: string;
    name?: string;
    users: UserIdentity[];
    policies: PolicyIdentity[];
}
export interface Session {
    id: string;
    user: string;
    address: string;
    expiration: string;
}
export interface CreateSession {
    id: string;
    user: string;
    token: string;
    address: string;
    expiration: string;
}
export interface UserPublicKeysResponse {
    items: UserPublicKey[];
    limit: number;
    offset: number;
    total: number;
}
export interface LoginResponses {
    items: LoginResponse[];
    limit: number;
    offset: number;
    total: number;
}
export interface UsersResponse {
    items: UserIdentity[];
    limit: number;
    offset: number;
    total: number;
}
export interface GroupsResponse {
    items: GroupIdentity[];
    limit: number;
    offset: number;
    total: number;
}
export interface PoliciesResponse {
    items: PolicyIdentity[];
    limit: number;
    offset: number;
    total: number;
}
export interface SessionsResponse {
    items: Session[];
    limit: number;
    offset: number;
    total: number;
}
export declare function rule(effect: Effect, action: Action, resource: string): Rule;
export declare class Principal {
    readonly user: User;
    readonly publicKey: Uint8Array;
    readonly privateKey: Uint8Array;
    readonly publicKeyBase64: string;
    readonly privateKeyBase64: string;
    constructor(user: User, privateKey: Uint8Array, publicKey?: Uint8Array | null);
}
export default class IAM {
    protocol: string;
    host: string;
    port: number | null;
    userId: string | null;
    secretKey: Uint8Array | null;
    publicKey: Uint8Array | null;
    loginId: string | null;
    sessionId: string | null;
    sessionToken: string | null;
    sessionExpires: string | null;
    sessionAddress: string | null;
    sessionUserId: string | null;
    user: UserClient;
    users: UsersClient;
    logins: LoginsClient;
    groups: GroupsClient;
    policies: PoliciesClient;
    sessions: SessionsClient;
    publicKeys: PublicKeysClient;
    userSessions: UserSessionsClient;
    constructor(protocol?: string, host?: string, port?: number | null);
    login(userId: string, secretKey?: Uint8Array | string | null): Promise<void>;
    loginRequest(userId: string, description?: string): Promise<void>;
    loginWithSecretKey(userId: string, secretKey: Uint8Array | string): Promise<void>;
    logout(): Promise<void>;
    refresh(userId?: string | null, secretKey?: Uint8Array | string | null, sessionId?: string | null, sessionToken?: string | null): Promise<void>;
    request(method: string, path: string, query?: string | null, body?: any | null): Promise<AxiosResponse>;
    signature(requestId: string, method: string, path: string, query?: string | null): string;
    url(path: string, query?: string | null): string;
}
export declare class UserClient {
    private iam;
    constructor(iam: IAM);
    getUser(): Promise<User>;
    updateUser(update: UserUpdate): Promise<User>;
    deleteUser(): Promise<void>;
    attachPolicy(policyId: string): Promise<void>;
    detachPolicy(policyId: string): Promise<void>;
}
export declare class UsersClient {
    private iam;
    constructor(iam: IAM);
    createUser(name?: string | null, email?: string | null, groups?: string[], policies?: string[]): Promise<Principal>;
    updateUser(id: string, update: UserUpdate): Promise<User>;
    deleteUser(id: string): Promise<void>;
    getUser(id: string): Promise<User>;
    listUsers(search?: string | null, sortBy?: SortUsersBy | null, sortOrder?: SortOrder | null, offset?: number | null, limit?: number | null): Promise<UsersResponse>;
    attachPolicy(userId: string, policyId: string): Promise<void>;
    detachPolicy(userId: string, policyId: string): Promise<void>;
}
export declare class LoginsClient {
    private iam;
    constructor(iam: IAM);
    getLogin(id: string, userId?: string | null): Promise<LoginResponse>;
    listLogins(userId?: string | null): Promise<LoginResponses>;
    denyLogin(id: string, userId?: string | null): Promise<LoginResponse>;
    grantLogin(id: string, userId?: string | null): Promise<LoginResponse>;
    deleteLogin(id: string, userId?: string | null): Promise<void>;
}
export declare class PublicKeysClient {
    private iam;
    constructor(iam: IAM);
    createPublicKey(description: string, key: string, userId?: string | null): Promise<UserPublicKey>;
    deletePublicKey(id: string, userId?: string | null): Promise<UserPublicKey>;
    listPublicKeys(userId?: string | null): Promise<UserPublicKeysResponse>;
    getPublicKey(id: string, userId?: string | null): Promise<UserPublicKey>;
}
export declare class GroupsClient {
    private iam;
    constructor(iam: IAM);
    createGroup(name?: string | null, users?: string[], policies?: string[]): Promise<Group>;
    deleteGroup(id: string): Promise<void>;
    getGroup(id: string): Promise<Group>;
    listGroups(search?: string | null, sortBy?: SortGroupsBy | null, sortOrder?: SortOrder | null, offset?: number | null, limit?: number | null): Promise<GroupsResponse>;
    attachPolicy(groupId: string, policyId: string): Promise<void>;
    detachPolicy(groupId: string, policyId: string): Promise<void>;
    addMember(groupId: string, userId: string): Promise<void>;
    removeMember(groupId: string, userId: string): Promise<void>;
}
export declare class PoliciesClient {
    private iam;
    constructor(iam: IAM);
    createPolicy(spec: PolicySpec): Promise<Policy>;
    deletePolicy(id: string): Promise<void>;
    getPolicy(id: string): Promise<Policy>;
    listPolicies(search?: string | null, sortBy?: SortPoliciesBy | null, sortOrder?: SortOrder | null, offset?: number | null, limit?: number | null): Promise<PoliciesResponse>;
}
export declare class SessionsClient {
    private iam;
    constructor(iam: IAM);
    listSessions(search?: string | null, sortBy?: SortSessionsBy | null, sortOrder?: SortOrder | null, offset?: number | null, limit?: number | null): Promise<SessionsResponse>;
    getSession(id: string): Promise<Session>;
    deleteSession(id: string): Promise<void>;
}
export declare class UserSessionsClient {
    private iam;
    constructor(iam: IAM);
    createSession(userId?: string | null): Promise<CreateSession>;
    listSessions(userId?: string | null, offset?: number, limit?: number): Promise<SessionsResponse>;
    getSession(id: string, userId?: string | null): Promise<Session>;
    deleteSession(id: string, userId?: string | null): Promise<void>;
    refreshSession(id: string, userId?: string | null): Promise<void>;
}
